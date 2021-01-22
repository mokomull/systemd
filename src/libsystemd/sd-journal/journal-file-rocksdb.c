#include "journal-file-rocksdb.h"
#include "journal-file-rocksdb-shim.h"

#include <fcntl.h>

enum OffsetTokens {
        TOKEN_FIELD_HASH_TABLE = 0x4200000000000000,
        TOKEN_FIELD_FIRST,
        TOKEN_FIELD_NEXT,
};

static RocksdbJournalFile *journal_file_to_rocksdb(JournalFile *f) {
        return container_of(f, RocksdbJournalFile, journal_file);
}

int journal_file_rocksdb_open(
        int fd,
        const char *fname,
        int flags,
        mode_t mode,
        bool seal,
        JournalMetrics *metrics,
        JournalFile *jtemplate,
        JournalFile **ret) {

        // TODO(mmullins) open for read-only if (flags & O_ACCMODE) == O_RDONLY
        RocksdbShim *shim = journal_rocksdb_shim_open(fname);
        if (!shim)
                return -ENOMEM;

        RocksdbJournalFile *f = new (RocksdbJournalFile, 1);
        if (!f) {
                // TODO(mmullins) free shim
                return -ENOMEM;
        }

        *f = (RocksdbJournalFile){
                .journal_file = {
                        .ops = &journal_file_rocksdb_ops,
                        .writable = (flags & O_ACCMODE) != O_RDONLY,
                        .fd = -1, /* TODO(mmullins) */
                },
                // TODO(mmullins) this should probably be zero if the file is empty
                .field_hash_table = {
                        .head_hash_offset = htole64(TOKEN_FIELD_FIRST),
                },
                .shim = shim,
        };

        f->journal_file.path = strdup(fname);

        *ret = &f->journal_file;
        return 0;
}

static void journal_file_rocksdb_close(JournalFile *jf) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        size_t i;

        if (f->field_it)
                journal_rocksdb_shim_close_iterator(f->field_it);

        journal_rocksdb_shim_close(f->shim);

        for (i = 0; i < sizeof(f->cached_objects) / sizeof(f->cached_objects[0]); ++i) {
                mfree(f->cached_objects[i]);
        }

        mfree(jf->path);
}

static bool journal_file_rocksdb_rotate_suggested(JournalFile *f, uint64_t max_file_usec) {
        return false;
}

static const char header_key[] = "header";

static Header *journal_file_rocksdb_header(JournalFile *jf) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        if (!f->header_initialized) {
                const char *value;
                uint64_t size;

                if (!journal_rocksdb_shim_read(f->shim, header_key, sizeof(header_key) - 1, &value, &size)) {
                        assert(size == sizeof(f->cached_header));
                        memcpy(&f->cached_header, value, sizeof(f->cached_header));
                        free((void *) value);
                } else {
                        // TODO(mmullins) we should have a template and otherwise know whether the file is new or not
                        journal_file_init_header(&f->cached_header, NULL);
                }

                f->cached_header.field_hash_table_offset = htole64(TOKEN_FIELD_HASH_TABLE);
                f->cached_header.field_hash_table_size = htole64(sizeof(HashItem));

                f->header_initialized = true;
        }

        return &f->cached_header;
}

static void journal_file_rocksdb_sync(JournalFile *jf) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);

        assert(jf);

        (void) journal_rocksdb_shim_write(
                f->shim,
                header_key,
                sizeof(header_key) - 1,
                (const char *) &f->cached_header,
                sizeof(f->cached_header));
}

// TODO(mmullins) did I name these backwards?
#define RocksdbDataKey__contents     \
        {                            \
                uint8_t type;        \
                uint8_t flags;       \
                uint8_t reserved[6]; \
                char data[];         \
        }

typedef struct RocksdbDataKey RocksdbDataKey__contents RocksdbDataKey;
struct RocksdbDataKey__packed RocksdbDataKey__contents _packed_;
assert_cc(sizeof(struct RocksdbDataKey) == sizeof(struct RocksdbDataKey__packed));

#define RocksdbIndexKey__contents    \
        {                            \
                uint8_t type;        \
                uint8_t flags;       \
                uint8_t reserved[6]; \
                be64_t index[];      \
        }

typedef struct RocksdbIndexKey RocksdbIndexKey__contents RocksdbIndexKey;
struct RocksdbIndexKey__packed RocksdbIndexKey__contents _packed_;
assert_cc(sizeof(struct RocksdbIndexKey) == sizeof(struct RocksdbIndexKey__packed));

enum KeyType {
        INDEX_ENTRY_BY_OFFSET = 1, /* value is a full EntryObject */
        INDEX_DATA_BY_OFFSET,      /* value is the payload of the data object */
        SET_FIELD,                 /* value is empty */
        DATA_BY_CONTENTS,          /* value is the offset of the corresponding data object */
        SET_ENTRY_BY_DATA,         /* value is empty */
        SET_ENTRY_BY_SEQNUM,
        SET_ENTRY_BY_REALTIME,
        SET_ENTRY_BY_MONOTONIC,
};

static char *rocksdb_data_key_alloc(uint64_t *key_size, uint8_t type, const char *data, uint64_t data_size) {
        RocksdbDataKey *key = malloc0(offsetof(RocksdbDataKey, data[data_size]));
        if (key) {
                key->type = type;
                memcpy(key->data, data, data_size);
                *key_size = offsetof(RocksdbDataKey, data[data_size]);
        }
        return (char *) key;
}

static char *rocksdb_index_key_alloc_one(uint64_t *key_size, uint8_t type, be64_t index) {
        RocksdbIndexKey *key = malloc0(offsetof(RocksdbIndexKey, index[1]));
        if (key) {
                key->type = type;
                key->index[0] = index;
                *key_size = offsetof(RocksdbIndexKey, index[1]);
        }
        return (char *) key;
}

static char *rocksdb_index_key_alloc_two(uint64_t *key_size, uint8_t type, be64_t index1, be64_t index2) {

        RocksdbIndexKey *key = malloc0(offsetof(RocksdbIndexKey, index[2]));
        if (key) {
                key->type = type;
                key->index[0] = index1;
                key->index[1] = index2;
                *key_size = offsetof(RocksdbIndexKey, index[2]);
        }
        return (char *) key;
}

static char *rocksdb_index_key_alloc_id128(
        uint64_t *key_size, uint8_t type, sd_id128_t id, be64_t index1, be64_t index2) {

        RocksdbIndexKey *key = malloc0(offsetof(RocksdbIndexKey, index[4]));
        if (key) {
                key->type = type;
                assert_cc(sizeof(id.bytes) == 2 * sizeof(key->index[0]));
                memcpy(&key->index[0], id.bytes, sizeof(id.bytes));
                key->index[2] = index1;
                key->index[3] = index2;
                *key_size = offsetof(RocksdbIndexKey, index[4]);
        }
        return (char *) key;
}

static int journal_file_rocksdb_append_data(
        JournalFile *jf, const void *data, uint64_t size, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        const char *field_end = memchr(data, '=', size);
        const size_t field_length = field_end - (const char *) data;
        const char *previous_data;
        uint64_t previous_data_len;
        be64_t data_id;
        uint64_t offset;
        char *key;
        uint64_t key_size;
        int r;

        assert(field_end);
        key = rocksdb_data_key_alloc(&key_size, SET_FIELD, data, field_length);
        if (!key)
                return -ENOMEM;
        // TODO(mmullins) header's n_fields should agree here.
        r = journal_rocksdb_shim_write(f->shim, key, key_size, NULL, 0);
        if (r)
                return r;

        free(key);
        key = rocksdb_data_key_alloc(&key_size, DATA_BY_CONTENTS, data, size);
        if (!key)
                return -ENOMEM;
        r = journal_rocksdb_shim_read(f->shim, key, key_size, &previous_data, &previous_data_len);

        if (r == -ENOENT) {
                offset = ++f->data_id;
                data_id = htobe64(offset);
                r = journal_rocksdb_shim_write(f->shim, key, key_size, (char *) &data_id, sizeof(data_id));
                free(key);
                if (r)
                        return r;

                key = rocksdb_index_key_alloc_one(&key_size, INDEX_DATA_BY_OFFSET, data_id);
                if (!key)
                        return -ENOMEM;
                r = journal_rocksdb_shim_write(f->shim, key, key_size, data, size);
        } else if (r == 0) {
                assert(previous_data_len == sizeof(be64_t));
                memcpy(&data_id, previous_data, sizeof(data_id));
                free((char *) previous_data);
                offset = be64toh(data_id);
        } else {
                abort();
        }
        free(key);


        f->new_object = (Object){ .data = {
                                          .hash = htole64(journal_file_hash_data(jf, data, size)),
                                  } };

        if (ret)
                *ret = &f->new_object;
        if (ret_offset)
                *ret_offset = offset;

        return r;
}

static int journal_file_rocksdb_append_object(
        JournalFile *jf, ObjectType type, uint64_t size, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);

        free(f->cached_objects[type]);
        f->cached_objects[type] = malloc(size);

        f->cached_objects[type]->object = (ObjectHeader){
                .type = type,
                .size = htole64(size),
        };

        if (ret)
                *ret = f->cached_objects[type];
        if (ret_offset)
                *ret_offset = ++f->data_id;

        if (f->cached_objects[type])
                return 0;
        else
                return -ENOMEM;
}

static int journal_file_rocksdb_commit_entry(JournalFile *jf, Object *o, uint64_t offset) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        int r;
        uint64_t key_size;
        char *key = rocksdb_index_key_alloc_one(&key_size, INDEX_ENTRY_BY_OFFSET, htobe64(offset));

        assert(o->object.type == OBJECT_ENTRY);
        assert(o == f->cached_objects[OBJECT_ENTRY]);

        if (!key)
                return -ENOMEM;

        r = journal_rocksdb_shim_write(f->shim, key, key_size, (const char *) o, o->entry.object.size);
        free(key);
        if (r)
                return r;

        key = rocksdb_index_key_alloc_two(
                &key_size, SET_ENTRY_BY_SEQNUM, htobe64(o->entry.seqnum), htobe64(offset));
        if (!key)
                return -ENOMEM;
        r = journal_rocksdb_shim_write(f->shim, key, key_size, NULL, 0);
        free(key);
        if (r)
                return r;

        key = rocksdb_index_key_alloc_two(
                &key_size, SET_ENTRY_BY_REALTIME, htobe64(o->entry.realtime), htobe64(offset));
        if (!key)
                return -ENOMEM;
        r = journal_rocksdb_shim_write(f->shim, key, key_size, NULL, 0);
        free(key);
        if (r)
                return r;

        key = rocksdb_index_key_alloc_id128(
                &key_size,
                SET_ENTRY_BY_MONOTONIC,
                o->entry.boot_id,
                htobe64(o->entry.monotonic),
                htobe64(offset));
        if (!key)
                return -ENOMEM;
        r = journal_rocksdb_shim_write(f->shim, key, key_size, NULL, 0);
        free(key);

        return r;
}

static int journal_file_rocksdb_link_entry_into_array(JournalFile *f, le64_t *first, le64_t *idx, uint64_t p) {
        // the RocksDB backend doesn't need to manage its own arrays of entries, since we can make this wtith
        // a key scan later.

        // but this function IS where the header's n_entries is updated, so
        int hidx = le64toh(*idx);
        *idx = htole64(hidx + 1);
        return 0;
}

static int journal_file_rocksdb_link_entry_item(JournalFile *jf, Object *o, uint64_t offset, uint64_t i) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        int r;
        uint64_t key_size;
        char *key = rocksdb_index_key_alloc_two(
                &key_size,
                SET_ENTRY_BY_DATA,
                htobe64(le64toh(o->entry.items[i].object_offset)),
                htobe64(offset));

        if (!key)
                return -ENOMEM;

        r = journal_rocksdb_shim_write(f->shim, key, key_size, NULL, 0);

        free(key);
        return r;
}

static int journal_file_rocksdb_next_entry(
        JournalFile *jf, uint64_t p, direction_t direction, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        int r;
        const uint64_t key_size = offsetof(RocksdbIndexKey, index[1]);
        RocksdbIndexKey *key = malloc0(key_size);
        RocksdbShimIterator *it;
        const char *found_key;
        uint64_t found_size;

        if (!key)
                return -ENOMEM;

        key->type = INDEX_ENTRY_BY_OFFSET;
        if (direction == DIRECTION_DOWN) {
                key->index[0] = htobe64(p + 1);
                it = journal_rocksdb_shim_create_iterator(
                        f->shim, SEEK_FORWARD, INDEX_ENTRY_BY_OFFSET, (const char *) key, key_size);
        } else {
                if (p == 0)
                        key->index[0] = UINT64_MAX;
                else
                        key->index[0] = htobe64(p - 1);
                it = journal_rocksdb_shim_create_iterator(
                        f->shim, SEEK_REVERSE, INDEX_ENTRY_BY_OFFSET, (const char *) key, key_size);
        }

        if (!it) {
                r = -ENOMEM;
                goto out;
        }

        r = journal_rocksdb_shim_iterator_key(it, &found_key, &found_size);
        if (r == 0) {
                assert(found_size == key_size);
                memcpy(key, found_key, key_size);
                p = be64toh(key->index[0]);
                free((char *) found_key);

                if (ret_offset)
                        *ret_offset = p;
                r = journal_file_move_to_object(&f->journal_file, OBJECT_ENTRY, p, ret);
                if (r == 0)
                        r = 1; /* journal_file_next_entry returns 1 on success */
        } else if (r == -ENOENT) {
                r = 0;
        } else {
                abort();
        }
        journal_rocksdb_shim_close_iterator(it);

out:
        free(key);
        return r;
}

static int journal_file_rocksdb_next_entry_for_data(
        JournalFile *jf,
        Object *o,
        uint64_t p,
        uint64_t data_offset,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        const uint64_t key_size = offsetof(RocksdbIndexKey, index[2]);
        RocksdbIndexKey *key = malloc0(key_size);
        RocksdbShimIterator *it;
        const char *found_key;
        uint64_t found_key_size;
        int r;

        assert(p > 0 || !o);

        if (!key)
                return -ENOMEM;

        key->type = SET_ENTRY_BY_DATA;
        key->index[0] = htobe64(data_offset);
        if (direction == DIRECTION_DOWN) {
                key->index[1] = htobe64(p + 1);
                it = journal_rocksdb_shim_create_iterator(
                        f->shim, SEEK_FORWARD, SET_ENTRY_BY_DATA, (const char *) key, key_size);
        } else {
                if (p == 0)
                        key->index[1] = UINT64_MAX;
                else
                        key->index[1] = htobe64(p - 1);
                it = journal_rocksdb_shim_create_iterator(
                        f->shim, SEEK_REVERSE, SET_ENTRY_BY_DATA, (const char *) key, key_size);
        }

        free(key);

        r = journal_rocksdb_shim_iterator_key(it, &found_key, &found_key_size);
        if (r == -ENOENT)
                return 0;
        else if (r)
                return r;

        assert(found_key_size == key_size);

        key = (RocksdbIndexKey *) found_key;
        assert(key->type = SET_ENTRY_BY_DATA);

        if (be64toh(key->index[0]) == data_offset) {
                if (ret_offset)
                        *ret_offset = be64toh(key->index[1]);
                if (ret) {
                        r = journal_file_move_to_object(jf, OBJECT_ENTRY, be64toh(key->index[1]), ret);
                }
                if (r == 0)
                        r = 1; /* returns 1 on success */
        } else {
                r = 0;
        }
        journal_rocksdb_shim_close_iterator(it);

        free(key);
        return r;
}

static int journal_file_rocksdb_move_to(
        JournalFile *jf, ObjectType type, bool keep_always, uint64_t offset, uint64_t size, void **ret) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);

        assert(jf);
        assert(keep_always);

        switch (type) {
        case OBJECT_FIELD_HASH_TABLE:
                assert(offset == TOKEN_FIELD_HASH_TABLE);
                assert(size == sizeof(HashItem));
                *ret = &f->field_hash_table;
                return 1;
        default:
                return -EINVAL;
        }
}

static le64_t find_data_offset_for_field(
        RocksdbJournalFile *f, const char *needle, uint64_t needle_size, bool strictly_after) {

        int r;
        be64_t data_offset = 0;

        uint64_t data_key_size;
        const char *data_key = rocksdb_data_key_alloc(&data_key_size, DATA_BY_CONTENTS, needle, needle_size);
        if (!data_key)
                return 0;

        RocksdbShimIterator *it = journal_rocksdb_shim_create_iterator(
                f->shim, SEEK_FORWARD, DATA_BY_CONTENTS, data_key, data_key_size);
        free((void *) data_key);
        if (!it)
                return 0;

        if (strictly_after) {
                r = journal_rocksdb_shim_iterator_next(it);
                if (r)
                        goto out;
        }

        r = journal_rocksdb_shim_iterator_key(it, &data_key, &data_key_size);
        if (r)
                goto out;

        const char *found_field = data_key + offsetof(RocksdbDataKey, data[0]);
        uint64_t found_size = data_key_size - (found_field - data_key);

        const char *found_equals = memchr(found_field, '=', found_size);
        const char *needle_equals = memchr(needle, '=', needle_size);

        if (!found_equals || !needle_equals) {
                /* one or both did not have a field name */
                data_offset = 0;
        } else if ((found_equals - found_field) != (needle_equals - needle)) {
                /* the field names were different lengths */
                data_offset = 0;
        } else if (memcmp(found_field, needle, needle_equals - needle) != 0) {
                /* the field names were different */
                data_offset = 0;
        } else {
                const char *data_value;
                uint64_t data_value_size;
                r = journal_rocksdb_shim_iterator_value(it, &data_value, &data_value_size);
                if (r) {
                        data_offset = 0;
                } else {
                        assert(data_value_size == sizeof(data_offset));
                        memcpy(&data_offset, data_value, sizeof(data_offset));
                        free((void *) data_value);
                }
        }

        free((void *) data_key);
out:
        journal_rocksdb_shim_close_iterator(it);

        return htole64(be64toh(data_offset));
}

static int materialize_field_object(RocksdbJournalFile *f, const char *key, uint64_t key_size, Object **ret) {
        uint64_t payload_size = key_size - offsetof(RocksdbDataKey, data[0]);
        char *field_prefix = alloca0(payload_size + 1);

        memcpy(field_prefix, key + offsetof(RocksdbDataKey, data[0]), payload_size);
        field_prefix[payload_size] = '=';

        free(*ret);
        *ret = malloc0(offsetof(Object, field.payload[payload_size]));
        if (!*ret)
                return -ENOMEM;

        (*ret)->field.object.type = OBJECT_FIELD;
        (*ret)->field.object.size = htole64(offsetof(Object, field.payload[payload_size]));
        (*ret)->field.next_hash_offset = TOKEN_FIELD_NEXT,
        (*ret)->field.head_data_offset = find_data_offset_for_field(f, field_prefix, payload_size + 1, false);
        memcpy((*ret)->field.payload, key + offsetof(RocksdbDataKey, data[0]), payload_size);

        return 0;
}

static int materialize_data_object(RocksdbJournalFile *f, uint64_t offset, Object **ret) {
        int r;
        const char *found_data;
        uint64_t key_size, found_size;
        char *key = rocksdb_index_key_alloc_one(&key_size, INDEX_DATA_BY_OFFSET, htobe64(offset));

        if (!key)
                return -ENOMEM;
        r = journal_rocksdb_shim_read(f->shim, key, key_size, &found_data, &found_size);
        free(key);
        if (r)
                return r;

        free(*ret);
        *ret = malloc0(offsetof(DataObject, payload[found_size]));
        if (!*ret)
                return -ENOMEM;

        (*ret)->data.object.type = OBJECT_DATA;
        (*ret)->data.object.size = htole64(offsetof(DataObject, payload[found_size]));
        (*ret)->data.hash = journal_file_hash_data(&f->journal_file, found_data, found_size);
        (*ret)->data.next_field_offset = find_data_offset_for_field(f, found_data, found_size, true);
        memcpy((*ret)->data.payload, found_data, found_size);
        free((void *) found_data);

        return 0;
}

static int journal_file_rocksdb_move_to_object(JournalFile *jf, ObjectType type, uint64_t offset, Object **ret) {
        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        uint64_t key_size, value_size;
        int r;

        switch (type) {
        case OBJECT_ENTRY: {
                char *key = rocksdb_index_key_alloc_one(&key_size, INDEX_ENTRY_BY_OFFSET, htobe64(offset));
                if (!key)
                        return -ENOMEM;

                free(f->cached_objects[OBJECT_ENTRY]);
                f->cached_objects[OBJECT_ENTRY] = NULL;
                r = journal_rocksdb_shim_read(
                        f->shim, key, key_size, (const char **) &f->cached_objects[OBJECT_ENTRY], &value_size);
                free(key);
                if (r)
                        return -EINVAL;

                assert(value_size == f->cached_objects[OBJECT_ENTRY]->object.size);

                break;
        }
        case OBJECT_DATA: {
                r = materialize_data_object(f, offset, &f->cached_objects[OBJECT_DATA]);
                if (r)
                        return r;
                break;
        }
        case OBJECT_FIELD: {
                const char *key;
                assert(offset == TOKEN_FIELD_NEXT || offset == TOKEN_FIELD_FIRST);

                r = journal_rocksdb_shim_iterator_key(f->field_it, &key, &key_size);
                if (r)
                        return r;

                r = materialize_field_object(f, key, key_size, &f->cached_objects[type]);
                free((void *) key);

                if (r)
                        return r;

                break;
        }
        case OBJECT_UNUSED: {
                const char *key;

                switch (offset) {
                case TOKEN_FIELD_FIRST: {
                        const char *first_key;

                        if (f->field_it) {
                                journal_rocksdb_shim_close_iterator(f->field_it);
                                f->field_it = NULL;
                        }

                        first_key = rocksdb_data_key_alloc(&key_size, SET_FIELD, NULL, 0);
                        if (!first_key)
                                return -ENOMEM;

                        f->field_it = journal_rocksdb_shim_create_iterator(
                                f->shim, SEEK_FORWARD, SET_FIELD, first_key, key_size);
                        free((void *) first_key);

                        r = journal_rocksdb_shim_iterator_key(f->field_it, &key, &key_size);
                        if (r)
                                return r;
                        break;
                }
                case TOKEN_FIELD_NEXT:
                        assert(f->field_it);

                        r = journal_rocksdb_shim_iterator_next(f->field_it);
                        if (r)
                                return r;

                        r = journal_rocksdb_shim_iterator_key(f->field_it, &key, &key_size);
                        if (r)
                                return r;
                        break;
                default:
                        r = materialize_data_object(f, offset, &f->cached_objects[OBJECT_UNUSED]);
                        if (r)
                                return r;
                        goto out;
                }

                r = materialize_field_object(f, key, key_size, &f->cached_objects[type]);
                free((void *) key);

                if (r)
                        return r;

                break;
        }
        default:
                abort();
        }

        // TODO(mmullins) does any of the logic in _check_object() go here?

out:
        *ret = f->cached_objects[type];
        return 0;
}

static int journal_file_rocksdb_move_to_entry_by_seqnum(
        JournalFile *jf, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        uint64_t p;
        uint64_t key_size;
        char *key = rocksdb_index_key_alloc_one(&key_size, SET_ENTRY_BY_SEQNUM, htobe64(seqnum));
        const char *found_key;
        uint64_t found_size;
        RocksdbShimIterator *it;
        int r;

        if (!key)
                return -ENOMEM;

        it = journal_rocksdb_shim_create_iterator(
                f->shim,
                direction == DIRECTION_DOWN ? SEEK_FORWARD : SEEK_REVERSE,
                SET_ENTRY_BY_SEQNUM,
                key,
                key_size);
        free(key);
        if (!it)
                return -ENOMEM;

        r = journal_rocksdb_shim_iterator_key(it, &found_key, &found_size);
        journal_rocksdb_shim_close_iterator(it);

        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        assert(found_size == offsetof(RocksdbIndexKey, index[2]));

        p = be64toh(((RocksdbIndexKey *) found_key)->index[1]);
        free((void *) found_key);

        if (ret_offset)
                *ret_offset = p;

        if (ret) {
                r = journal_file_move_to_object(jf, OBJECT_ENTRY, p, ret);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int journal_file_rocksdb_move_to_entry_by_realtime(
        JournalFile *jf, uint64_t realtime, direction_t direction, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        uint64_t p;
        uint64_t key_size;
        char *key = rocksdb_index_key_alloc_one(&key_size, SET_ENTRY_BY_REALTIME, htobe64(realtime));
        const char *found_key;
        uint64_t found_size;
        RocksdbShimIterator *it;
        int r;

        if (!key)
                return -ENOMEM;

        it = journal_rocksdb_shim_create_iterator(
                f->shim,
                direction == DIRECTION_DOWN ? SEEK_FORWARD : SEEK_REVERSE,
                SET_ENTRY_BY_REALTIME,
                key,
                key_size);
        free(key);
        if (!it)
                return -ENOMEM;

        r = journal_rocksdb_shim_iterator_key(it, &found_key, &found_size);
        journal_rocksdb_shim_close_iterator(it);

        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        assert(found_size == offsetof(RocksdbIndexKey, index[2]));

        p = be64toh(((RocksdbIndexKey *) found_key)->index[1]);
        free((void *) found_key);

        if (ret_offset)
                *ret_offset = p;

        if (ret) {
                r = journal_file_move_to_object(jf, OBJECT_ENTRY, p, ret);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int journal_file_rocksdb_move_to_entry_by_monotonic(
        JournalFile *jf,
        sd_id128_t bootid,
        uint64_t monotonic,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        uint64_t p;
        uint64_t key_size;
        char *key = rocksdb_index_key_alloc_id128(
                &key_size,
                SET_ENTRY_BY_MONOTONIC,
                bootid,
                htobe64(monotonic),
                direction == DIRECTION_DOWN ? 0 : UINT64_MAX);
        const char *found_key;
        uint64_t found_size;
        sd_id128_t found_bootid;
        RocksdbShimIterator *it;
        int r;

        if (!key)
                return -ENOMEM;

        it = journal_rocksdb_shim_create_iterator(
                f->shim,
                direction == DIRECTION_DOWN ? SEEK_FORWARD : SEEK_REVERSE,
                SET_ENTRY_BY_MONOTONIC,
                key,
                key_size);
        free(key);
        if (!it)
                return -ENOMEM;

        r = journal_rocksdb_shim_iterator_key(it, &found_key, &found_size);
        journal_rocksdb_shim_close_iterator(it);

        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        assert(found_size == offsetof(RocksdbIndexKey, index[4]));

        assert_cc(sizeof(found_bootid.bytes) == 2 * sizeof(be64_t));
        memcpy(found_bootid.bytes, &((RocksdbIndexKey *) found_key)->index[0], sizeof(found_bootid.bytes));
        p = be64toh(((RocksdbIndexKey *) found_key)->index[3]);
        free((void *) found_key);

        if (!sd_id128_equal(bootid, found_bootid))
                return -ENOENT;

        if (ret_offset)
                *ret_offset = p;

        if (ret) {
                r = journal_file_move_to_object(jf, OBJECT_ENTRY, p, ret);
                if (r < 0)
                        return r;
        }

        return 1;
}


static int journal_file_rocksdb_move_to_entry_by_offset_for_data(
        JournalFile *jf,
        uint64_t data_offset,
        uint64_t p,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        // Since the RocksDB keys are ordered, the iteration through data_offset is the same logic, even if
        // the object at offset p does not exist in the data link we're looking for.

        assert(p > 0);

        // next_entry_for_data is looking for strictly greater-than (or strictly less-than), but for the
        // purposes of move_to_entry, we're happy with matching the same offset.
        if (direction == DIRECTION_DOWN)
                p--;
        else
                p++;

        return journal_file_rocksdb_next_entry_for_data(
                jf, NULL /* unused there anyway */, p, data_offset, direction, ret, ret_offset);
}

static int journal_file_rocksdb_move_to_entry_by_seqnum_for_data(
        JournalFile *f,
        uint64_t data_offset,
        uint64_t seqnum,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        int r;
        uint64_t p;

        // first find the seqnum
        r = journal_file_rocksdb_move_to_entry_by_seqnum(f, seqnum, direction, NULL, &p);
        if (r < 0)
                return r;

        // then find the next or matching position for the data
        if (direction == DIRECTION_DOWN)
                p--;
        else
                p++;

        return journal_file_rocksdb_next_entry_for_data(f, NULL, p, data_offset, direction, ret, ret_offset);
}

static int journal_file_rocksdb_move_to_entry_by_realtime_for_data(
        JournalFile *f,
        uint64_t data_offset,
        uint64_t realtime,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        int r;
        uint64_t p;

        // first find the realtime
        r = journal_file_move_to_entry_by_realtime(f, realtime, direction, NULL, &p);
        if (r < 0)
                return r;

        // then find the next matching position for the data
        if (direction == DIRECTION_DOWN)
                p--;
        else
                p++;

        return journal_file_rocksdb_next_entry_for_data(f, NULL, p, data_offset, direction, ret, ret_offset);
}

static int journal_file_rocksdb_move_to_entry_by_monotonic_for_data(
        JournalFile *f,
        uint64_t data_offset,
        sd_id128_t boot_id,
        uint64_t monotonic,
        direction_t direction,
        Object **ret,
        uint64_t *ret_offset) {

        int r;
        uint64_t p;
        Object *o;

        // first find the monotonic
        r = journal_file_move_to_entry_by_monotonic(f, boot_id, monotonic, direction, NULL, &p);
        if (r < 0)
                return r;

        // then find the next matching position for the data
        if (direction == DIRECTION_DOWN)
                p--;
        else
                p++;

        // TODO(mmullins) this assumes that corresponding boot_ids will always be in contiguous runs in the entries.
        r = journal_file_rocksdb_next_entry_for_data(f, NULL, p, data_offset, direction, &o, &p);
        if (r) {
                if (sd_id128_equal(boot_id, o->entry.boot_id)) {
                        if (ret)
                                *ret = o;
                        if (ret_offset)
                                *ret_offset = p;
                        return 1;
                }
        }

        return 0;
}

static int journal_file_rocksdb_find_data_object_with_hash(
        JournalFile *jf, const void *data, uint64_t size, uint64_t hash, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        uint64_t key_size;
        char *key = rocksdb_data_key_alloc(&key_size, DATA_BY_CONTENTS, data, size);
        uint64_t p, value_size;
        be64_t read_p;
        const char *value;
        int r;

        if (!key)
                return -ENOMEM;

        r = journal_rocksdb_shim_read(f->shim, key, key_size, &value, &value_size);
        free(key);
        if (r == -ENOENT)
                return 0;
        else if (r)
                return r;

        assert(value_size == sizeof(read_p));
        memcpy(&read_p, value, sizeof(read_p));
        free((void *) value);

        p = be64toh(read_p);
        if (ret_offset)
                *ret_offset = p;

        if (ret) {
                r = journal_file_rocksdb_move_to_object(jf, OBJECT_DATA, p, ret);
                if (r)
                        return r;
        }

        return 1;
}

static int journal_file_rocksdb_find_field_object_with_hash(
        JournalFile *jf, const void *field, uint64_t size, uint64_t hash, Object **ret, uint64_t *ret_offset) {

        RocksdbJournalFile *f = journal_file_to_rocksdb(jf);
        int r;
        const char *key;
        uint64_t key_size;

        key = rocksdb_data_key_alloc(&key_size, SET_FIELD, field, size);
        if (!key)
                return -ENOMEM;

        r = materialize_field_object(f, key, key_size, &f->cached_objects[OBJECT_FIELD]);
        free((void *) key);
        if (r)
                return r;

        if (ret)
                *ret = f->cached_objects[OBJECT_FIELD];
        if (ret_offset)
                *ret_offset = TOKEN_FIELD_FIRST;

        return 1;
}


static bool journal_file_rocksdb_check_sigbus(JournalFile *jf) {
        return false;
}

static void journal_file_rocksdb_post_change(JournalFile *jf) {
}

const JournalFileOps journal_file_rocksdb_ops = {
        .append_data = journal_file_rocksdb_append_data,
        .append_object = journal_file_rocksdb_append_object,
        .commit_entry = journal_file_rocksdb_commit_entry,
        .link_entry_into_array = journal_file_rocksdb_link_entry_into_array,
        .link_entry_item = journal_file_rocksdb_link_entry_item,
        .next_entry = journal_file_rocksdb_next_entry,
        .next_entry_for_data = journal_file_rocksdb_next_entry_for_data,
        .move_to = journal_file_rocksdb_move_to,
        .move_to_object = journal_file_rocksdb_move_to_object,
        .move_to_entry_by_seqnum = journal_file_rocksdb_move_to_entry_by_seqnum,
        .move_to_entry_by_realtime = journal_file_rocksdb_move_to_entry_by_realtime,
        .move_to_entry_by_monotonic = journal_file_rocksdb_move_to_entry_by_monotonic,
        .move_to_entry_by_offset_for_data = journal_file_rocksdb_move_to_entry_by_offset_for_data,
        .move_to_entry_by_seqnum_for_data = journal_file_rocksdb_move_to_entry_by_seqnum_for_data,
        .move_to_entry_by_realtime_for_data = journal_file_rocksdb_move_to_entry_by_realtime_for_data,
        .move_to_entry_by_monotonic_for_data = journal_file_rocksdb_move_to_entry_by_monotonic_for_data,
        .find_data_object_with_hash = journal_file_rocksdb_find_data_object_with_hash,
        .find_field_object_with_hash = journal_file_rocksdb_find_field_object_with_hash,
        .header = journal_file_rocksdb_header,
        .rotate_suggested = journal_file_rocksdb_rotate_suggested,
        .check_sigbus = journal_file_rocksdb_check_sigbus,
        .post_change = journal_file_rocksdb_post_change,
        .sync = journal_file_rocksdb_sync,
        .close = journal_file_rocksdb_close,
};
