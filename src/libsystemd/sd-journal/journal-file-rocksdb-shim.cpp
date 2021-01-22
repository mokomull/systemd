#include <rocksdb/db.h>
#include <string_view>

#include "journal-file-rocksdb-shim.h"

struct RocksdbShim {
        rocksdb::DB *db;
};

RocksdbShim *journal_rocksdb_shim_open(const char *path) {
        RocksdbShim *ret = new RocksdbShim;

        rocksdb::Options options;
        options.create_if_missing = true;

        rocksdb::Status status = rocksdb::DB::Open(options, path, &ret->db);
        if (!status.ok()) {
                delete ret;
                return nullptr;
        }
        return ret;
}

int journal_rocksdb_shim_write(
        RocksdbShim *db, const char *key, uint64_t keysize, const char *value, uint64_t valuesize) {

        rocksdb::Status s = db->db->Put(
                rocksdb::WriteOptions{}, rocksdb::Slice{ key, keysize }, rocksdb::Slice{ value, valuesize });

        if (s.ok())
                return 0;
        else
                return -EINVAL;
}

int journal_rocksdb_shim_read(
        RocksdbShim *db, const char *key, uint64_t keysize, const char **value, uint64_t *valuesize) {

        std::string output;

        rocksdb::Status s = db->db->Get(rocksdb::ReadOptions{}, rocksdb::Slice{ key, keysize }, &output);
        if (s.ok()) {
                *value = (char *) malloc(output.size());
                if (!*value)
                        return -ENOMEM;
                *valuesize = output.size();
                memcpy((char *) *value, output.data(), output.size());
                return 0;
        } else if (s.IsNotFound()) {
                return -ENOENT;
        } else {
                return -EINVAL;
        }
}

void journal_rocksdb_shim_close(RocksdbShim *db) {
        delete db->db;
        delete db;
}

struct RocksdbShimIterator {
        rocksdb::Iterator *it;
        rocksdb::Slice begin_slice, end_slice;
        char begin, end;
};

RocksdbShimIterator *journal_rocksdb_shim_create_iterator(
        RocksdbShim *db, SeekDirection dir, uint8_t type, const char *key, uint64_t size) {

        RocksdbShimIterator *ret = new RocksdbShimIterator;

        ret->begin = type;
        ret->end = type + 1;
        ret->begin_slice = rocksdb::Slice{ &ret->begin, 1 };
        ret->end_slice = rocksdb::Slice{ &ret->end, 1 };

        rocksdb::ReadOptions options;
        options.iterate_lower_bound = &ret->begin_slice;
        options.iterate_upper_bound = &ret->end_slice;

        ret->it = db->db->NewIterator(options);

        switch (dir) {
        case SEEK_FORWARD:
                ret->it->Seek(rocksdb::Slice{ key, size });
                break;
        case SEEK_REVERSE:
                ret->it->SeekForPrev(rocksdb::Slice{ key, size });
                break;
        }

        return ret;
}

int journal_rocksdb_shim_iterator_key(RocksdbShimIterator *it, const char **key, uint64_t *size) {
        rocksdb::Status s = it->it->status();

        if (it->it->Valid()) {
                rocksdb::Slice found = it->it->key();
                *key = (char *) malloc(found.size());
                if (!*key)
                        return -ENOMEM;
                *size = found.size();
                memcpy((char *) *key, found.data(), found.size());
                return 0;
        } else if (s.ok()) {
                return -ENOENT;
        } else {
                return -EINVAL;
        }
}

int journal_rocksdb_shim_iterator_value(RocksdbShimIterator *it, const char **value, uint64_t *size) {
        rocksdb::Status s = it->it->status();

        if (it->it->Valid()) {
                rocksdb::Slice found = it->it->value();
                *value = (char *) malloc(found.size());
                if (!*value)
                        return -ENOMEM;
                *size = found.size();
                memcpy((char *) *value, found.data(), found.size());
                return 0;
        } else if (s.ok()) {
                return -ENOENT;
        } else {
                return -EINVAL;
        }
}

int journal_rocksdb_shim_iterator_next(RocksdbShimIterator *it) {
        if (!it->it->Valid())
                return -EINVAL;
        it->it->Next();
        return 0;
}

void journal_rocksdb_shim_close_iterator(RocksdbShimIterator *it) {
        delete it->it;
        delete it;
}
