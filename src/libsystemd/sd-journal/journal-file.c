/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "compress.h"
#include "env-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "journal-authenticate.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-file-binary.h"
#include "journal-verify.h"
#include "lookup3.h"
#include "memory-util.h"
#include "path-util.h"
#include "random-util.h"
#include "set.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "xattr-util.h"

/* These are the lower and upper bounds if we deduce the max_use value
 * from the file system size */
#define MAX_USE_LOWER (1 * 1024 * 1024ULL)                /* 1 MiB */
#define MAX_USE_UPPER (4 * 1024 * 1024 * 1024ULL)         /* 4 GiB */

/* Those are the lower and upper bounds for the minimal use limit,
 * i.e. how much we'll use even if keep_free suggests otherwise. */
#define MIN_USE_LOW (1 * 1024 * 1024ULL)                  /* 1 MiB */
#define MIN_USE_HIGH (16 * 1024 * 1024ULL)                /* 16 MiB */

/* This is the upper bound if we deduce max_size from max_use */
#define MAX_SIZE_UPPER (128 * 1024 * 1024ULL)             /* 128 MiB */

/* This is the upper bound if we deduce the keep_free value from the
 * file system size */
#define KEEP_FREE_UPPER (4 * 1024 * 1024 * 1024ULL)       /* 4 GiB */

/* This is the keep_free value when we can't determine the system
 * size */
#define DEFAULT_KEEP_FREE (1024 * 1024ULL)                /* 1 MB */

/* This is the default maximum number of journal files to keep around. */
#define DEFAULT_N_MAX_FILES 100

/* This is the minimum journal file size */
#define JOURNAL_FILE_SIZE_MIN (512 * 1024ULL)             /* 512 KiB */

/* This may be called from a separate thread to prevent blocking the caller for the duration of fsync().
 * As a result we use atomic operations on f->offline_state for inter-thread communications with
 * journal_file_set_offline() and journal_file_set_online(). */
static void journal_file_set_offline_internal(JournalFile *f) {
        Header *header;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        for (;;) {
                switch (f->offline_state) {
                case OFFLINE_CANCEL:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_CANCEL, OFFLINE_DONE))
                                continue;
                        return;

                case OFFLINE_AGAIN_FROM_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_AGAIN_FROM_SYNCING, OFFLINE_SYNCING))
                                continue;
                        break;

                case OFFLINE_AGAIN_FROM_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_AGAIN_FROM_OFFLINING, OFFLINE_SYNCING))
                                continue;
                        break;

                case OFFLINE_SYNCING:
                        f->ops->sync(f);

                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_SYNCING, OFFLINE_OFFLINING))
                                continue;

                        header->state = f->archive ? STATE_ARCHIVED : STATE_OFFLINE;
                        f->ops->sync(f);
                        break;

                case OFFLINE_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_OFFLINING, OFFLINE_DONE))
                                continue;
                        _fallthrough_;
                case OFFLINE_DONE:
                        return;

                case OFFLINE_JOINED:
                        log_debug("OFFLINE_JOINED unexpected offline state for journal_file_set_offline_internal()");
                        return;
                }
        }
}

static void * journal_file_set_offline_thread(void *arg) {
        JournalFile *f = arg;

        (void) pthread_setname_np(pthread_self(), "journal-offline");

        journal_file_set_offline_internal(f);

        return NULL;
}

static int journal_file_set_offline_thread_join(JournalFile *f) {
        int r;

        assert(f);

        if (f->offline_state == OFFLINE_JOINED)
                return 0;

        r = pthread_join(f->offline_thread, NULL);
        if (r)
                return -r;

        f->offline_state = OFFLINE_JOINED;

        if (f->ops->check_sigbus(f))
                return -EIO;

        return 0;
}

/* Trigger a restart if the offline thread is mid-flight in a restartable state. */
static bool journal_file_set_offline_try_restart(JournalFile *f) {
        for (;;) {
                switch (f->offline_state) {
                case OFFLINE_AGAIN_FROM_SYNCING:
                case OFFLINE_AGAIN_FROM_OFFLINING:
                        return true;

                case OFFLINE_CANCEL:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_CANCEL, OFFLINE_AGAIN_FROM_SYNCING))
                                continue;
                        return true;

                case OFFLINE_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_SYNCING, OFFLINE_AGAIN_FROM_SYNCING))
                                continue;
                        return true;

                case OFFLINE_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_OFFLINING, OFFLINE_AGAIN_FROM_OFFLINING))
                                continue;
                        return true;

                default:
                        return false;
                }
        }
}

/* Sets a journal offline.
 *
 * If wait is false then an offline is dispatched in a separate thread for a
 * subsequent journal_file_set_offline() or journal_file_set_online() of the
 * same journal to synchronize with.
 *
 * If wait is true, then either an existing offline thread will be restarted
 * and joined, or if none exists the offline is simply performed in this
 * context without involving another thread.
 */
int journal_file_set_offline(JournalFile *f, bool wait) {
        Header *header;
        bool restarted;
        int r;

        assert(f);
        header = journal_file_header(f);

        if (!f->writable)
                return -EPERM;

        if (!header)
                return -EINVAL;

        /* An offlining journal is implicitly online and may modify f->header->state,
         * we must also join any potentially lingering offline thread when not online. */
        if (!journal_file_is_offlining(f) && header->state != STATE_ONLINE)
                return journal_file_set_offline_thread_join(f);

        /* Restart an in-flight offline thread and wait if needed, or join a lingering done one. */
        restarted = journal_file_set_offline_try_restart(f);
        if ((restarted && wait) || !restarted) {
                r = journal_file_set_offline_thread_join(f);
                if (r < 0)
                        return r;
        }

        if (restarted)
                return 0;

        /* Initiate a new offline. */
        f->offline_state = OFFLINE_SYNCING;

        if (wait) /* Without using a thread if waiting. */
                journal_file_set_offline_internal(f);
        else {
                sigset_t ss, saved_ss;
                int k;

                assert_se(sigfillset(&ss) >= 0);
                /* Don't block SIGBUS since the offlining thread accesses a memory mapped file.
                 * Asynchronous SIGBUS signals can safely be handled by either thread. */
                assert_se(sigdelset(&ss, SIGBUS) >= 0);

                r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
                if (r > 0)
                        return -r;

                r = pthread_create(&f->offline_thread, NULL, journal_file_set_offline_thread, f);

                k = pthread_sigmask(SIG_SETMASK, &saved_ss, NULL);
                if (r > 0) {
                        f->offline_state = OFFLINE_JOINED;
                        return -r;
                }
                if (k > 0)
                        return -k;
        }

        return 0;
}

int journal_file_set_online(JournalFile *f) {
        Header *header;
        bool wait = true;

        assert(f);

        header = journal_file_header(f);

        if (!f->writable)
                return -EPERM;

        if (!header)
                return -EINVAL;

        while (wait) {
                switch (f->offline_state) {
                case OFFLINE_JOINED:
                        /* No offline thread, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_SYNCING, OFFLINE_CANCEL))
                                continue;
                        /* Canceled syncing prior to offlining, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_AGAIN_FROM_SYNCING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_AGAIN_FROM_SYNCING, OFFLINE_CANCEL))
                                continue;
                        /* Canceled restart from syncing, no need to wait. */
                        wait = false;
                        break;

                case OFFLINE_AGAIN_FROM_OFFLINING:
                        if (!__sync_bool_compare_and_swap(&f->offline_state, OFFLINE_AGAIN_FROM_OFFLINING, OFFLINE_CANCEL))
                                continue;
                        /* Canceled restart from offlining, must wait for offlining to complete however. */
                        _fallthrough_;
                default: {
                        int r;

                        r = journal_file_set_offline_thread_join(f);
                        if (r < 0)
                                return r;

                        wait = false;
                        break;
                }
                }
        }

        if (f->ops->check_sigbus(f))
                return -EIO;

        switch (header->state) {
                case STATE_ONLINE:
                        return 0;

                case STATE_OFFLINE:
                        header->state = STATE_ONLINE;
                        f->ops->sync(f);
                        return 0;

                default:
                        return -EINVAL;
        }
}

bool journal_file_is_offlining(JournalFile *f) {
        assert(f);

        __sync_synchronize();

        if (IN_SET(f->offline_state, OFFLINE_DONE, OFFLINE_JOINED))
                return false;

        return true;
}

JournalFile* journal_file_close(JournalFile *f) {
        if (!f)
                return NULL;

#if HAVE_GCRYPT
        /* Write the final tag */
        if (f->seal && f->writable) {
                int r;

                r = journal_file_append_tag(f);
                if (r < 0)
                        log_error_errno(r, "Failed to append tag when closing journal: %m");
        }
#endif

        if (f->post_change_timer) {
                if (sd_event_source_get_enabled(f->post_change_timer, NULL) > 0)
                        journal_file_post_change(f);

                sd_event_source_disable_unref(f->post_change_timer);
        }

        journal_file_set_offline(f, true);

        f->ops->close(f);

        return mfree(f);
}

int journal_file_init_header(Header *h, JournalFile *template) {
        int r;
        Header *template_header;

        memcpy(h->signature, HEADER_SIGNATURE, 8);
        h->header_size = htole64(ALIGN64(sizeof(*h)));

        r = sd_id128_randomize(&h->file_id);
        if (r < 0)
                return r;

        if (template) {
                template_header = journal_file_header(template);
                h->seqnum_id = template_header->seqnum_id;
                h->tail_entry_seqnum = template_header->tail_entry_seqnum;
        } else
                h->seqnum_id = h->file_id;

        return 0;
}

int journal_file_refresh_header(JournalFile *f) {
        Header *header;
        int r;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        r = sd_id128_get_machine(&header->machine_id);
        if (IN_SET(r, -ENOENT, -ENOMEDIUM))
                /* We don't have a machine-id, let's continue without */
                zero(header->machine_id);
        else if (r < 0)
                return r;

        r = sd_id128_get_boot(&header->boot_id);
        if (r < 0)
                return r;

        r = journal_file_set_online(f);

        /* Sync the online state to disk */
        f->ops->sync(f);

        /* We likely just created a new file, also sync the directory this file is located in. */
        if (f->ops->sync_directory)
                f->ops->sync_directory(f);

        return r;
}

int journal_file_fstat(JournalFile *f) {
        int r;

        assert(f);
        assert(f->fd >= 0);

        if (fstat(f->fd, &f->last_stat) < 0)
                return -errno;

        f->last_stat_usec = now(CLOCK_MONOTONIC);

        /* Refuse dealing with files that aren't regular */
        r = stat_verify_regular(&f->last_stat);
        if (r < 0)
                return r;

        /* Refuse appending to files that are already deleted */
        if (f->last_stat.st_nlink <= 0)
                return -EIDRM;

        return 0;
}

static int journal_file_move_to(
                JournalFile *f,
                ObjectType type,
                bool keep_always,
                uint64_t offset,
                uint64_t size,
                void **ret) {
        return f->ops->move_to(f, type, keep_always, offset, size, ret);
}

int journal_file_move_to_object(JournalFile *f, ObjectType type, uint64_t offset, Object **ret) {
        return f->ops->move_to_object(f, type, offset, ret);
}

static uint64_t journal_file_entry_seqnum(JournalFile *f, uint64_t *seqnum) {
        Header *header;
        uint64_t r;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        r = le64toh(header->tail_entry_seqnum) + 1;

        if (seqnum) {
                /* If an external seqnum counter was passed, we update
                 * both the local and the external one, and set it to
                 * the maximum of both */

                if (*seqnum + 1 > r)
                        r = *seqnum + 1;

                *seqnum = r;
        }

        header->tail_entry_seqnum = htole64(r);

        if (header->head_entry_seqnum == 0)
                header->head_entry_seqnum = htole64(r);

        return r;
}

int journal_file_append_object(
                JournalFile *f,
                ObjectType type,
                uint64_t size,
                Object **ret,
                uint64_t *ret_offset) {
        return f->ops->append_object(f, type, size, ret, ret_offset);
}

int journal_file_map_field_hash_table(JournalFile *f) {
        uint64_t s, p;
        void *t;
        int r;
        Header *header;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        if (f->field_hash_table)
                return 0;

        p = le64toh(header->field_hash_table_offset);
        s = le64toh(header->field_hash_table_size);

        r = journal_file_move_to(f,
                                 OBJECT_FIELD_HASH_TABLE,
                                 true,
                                 p, s,
                                 &t);
        if (r < 0)
                return r;

        f->field_hash_table = t;
        return 0;
}

uint64_t journal_file_hash_data(
                JournalFile *f,
                const void *data,
                size_t sz) {

        Header *header;
        assert(f);
        assert(data || sz == 0);

        header = journal_file_header(f);

        /* We try to unify our codebase on siphash, hence new-styled journal files utilizing the keyed hash
         * function use siphash. Old journal files use the Jenkins hash. */

        if (JOURNAL_HEADER_KEYED_HASH(header))
                return siphash24(data, sz, header->file_id.bytes);

        return jenkins_hash64(data, sz);
}

int journal_file_find_field_object_with_hash(
                JournalFile *f,
                const void *field, uint64_t size, uint64_t hash,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->find_field_object_with_hash(f, field, size, hash, ret, ret_offset);
}

int journal_file_find_field_object(
                JournalFile *f,
                const void *field, uint64_t size,
                Object **ret, uint64_t *ret_offset) {

        assert(f);
        assert(field && size > 0);

        return journal_file_find_field_object_with_hash(
                        f,
                        field, size,
                        journal_file_hash_data(f, field, size),
                        ret, ret_offset);
}

int journal_file_find_data_object_with_hash(
                JournalFile *f,
                const void *data, uint64_t size, uint64_t hash,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->find_data_object_with_hash(f, data, size, hash, ret, ret_offset);
}

int journal_file_find_data_object(
                JournalFile *f,
                const void *data, uint64_t size,
                Object **ret, uint64_t *ret_offset) {

        assert(f);
        assert(data || size == 0);

        return journal_file_find_data_object_with_hash(
                        f,
                        data, size,
                        journal_file_hash_data(f, data, size),
                        ret, ret_offset);
}

bool journal_field_valid(const char *p, size_t l, bool allow_protected) {
        /* We kinda enforce POSIX syntax recommendations for
           environment variables here, but make a couple of additional
           requirements.

           http://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap08.html */

        if (l == (size_t) -1)
                l = strlen(p);

        /* No empty field names */
        if (l <= 0)
                return false;

        /* Don't allow names longer than 64 chars */
        if (l > 64)
                return false;

        /* Variables starting with an underscore are protected */
        if (!allow_protected && p[0] == '_')
                return false;

        /* Don't allow digits as first character */
        if (p[0] >= '0' && p[0] <= '9')
                return false;

        /* Only allow A-Z0-9 and '_' */
        for (const char *a = p; a < p + l; a++)
                if ((*a < 'A' || *a > 'Z') &&
                    (*a < '0' || *a > '9') &&
                    *a != '_')
                        return false;

        return true;
}

uint64_t journal_file_entry_n_items(Object *o) {
        uint64_t sz;
        assert(o);

        if (o->object.type != OBJECT_ENTRY)
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, entry.items))
                return 0;

        return (sz - offsetof(Object, entry.items)) / sizeof(EntryItem);
}

uint64_t journal_file_entry_array_n_items(Object *o) {
        uint64_t sz;

        assert(o);

        if (o->object.type != OBJECT_ENTRY_ARRAY)
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, entry_array.items))
                return 0;

        return (sz - offsetof(Object, entry_array.items)) / sizeof(uint64_t);
}

uint64_t journal_file_hash_table_n_items(Object *o) {
        uint64_t sz;

        assert(o);

        if (!IN_SET(o->object.type, OBJECT_DATA_HASH_TABLE, OBJECT_FIELD_HASH_TABLE))
                return 0;

        sz = le64toh(READ_NOW(o->object.size));
        if (sz < offsetof(Object, hash_table.items))
                return 0;

        return (sz - offsetof(Object, hash_table.items)) / sizeof(HashItem);
}

static int link_entry_into_array(JournalFile *f, le64_t *first, le64_t *idx, uint64_t p) {
        return f->ops->link_entry_into_array(f, first, idx, p);
}

static int journal_file_link_entry_item(
                JournalFile *f,
                Object *o,
                uint64_t offset,
                uint64_t i) {
        return f->ops->link_entry_item(f, o, offset, i);
}

static int journal_file_link_entry(JournalFile *f, Object *o, uint64_t offset) {
        Header *header;
        uint64_t n;
        int r;

        assert(f);
        assert(o);
        assert(offset > 0);

        header = journal_file_header(f);
        assert(header);

        if (o->object.type != OBJECT_ENTRY)
                return -EINVAL;

        __sync_synchronize();
        if (f->ops->commit_entry)
                f->ops->commit_entry(f, o, offset);

        /* Link up the entry itself */
        r = link_entry_into_array(f,
                                  &header->entry_array_offset,
                                  &header->n_entries,
                                  offset);
        if (r < 0)
                return r;

        /* log_debug("=> %s seqnr=%"PRIu64" n_entries=%"PRIu64, f->path, o->entry.seqnum, f->header->n_entries); */

        if (header->head_entry_realtime == 0)
                header->head_entry_realtime = o->entry.realtime;

        header->tail_entry_realtime = o->entry.realtime;
        header->tail_entry_monotonic = o->entry.monotonic;

        /* Link up the items */
        n = journal_file_entry_n_items(o);
        for (uint64_t i = 0; i < n; i++) {
                r = journal_file_link_entry_item(f, o, offset, i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int journal_file_append_entry_internal(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                uint64_t xor_hash,
                const EntryItem items[], unsigned n_items,
                uint64_t *seqnum,
                Object **ret, uint64_t *ret_offset) {
        Header *header;
        uint64_t np;
        uint64_t osize;
        Object *o;
        int r;

        assert(f);
        assert(items || n_items == 0);
        assert(ts);

        header = journal_file_header(f);
        assert(header);

        osize = offsetof(Object, entry.items) + (n_items * sizeof(EntryItem));

        r = journal_file_append_object(f, OBJECT_ENTRY, osize, &o, &np);
        if (r < 0)
                return r;

        o->entry.seqnum = htole64(journal_file_entry_seqnum(f, seqnum));
        memcpy_safe(o->entry.items, items, n_items * sizeof(EntryItem));
        o->entry.realtime = htole64(ts->realtime);
        o->entry.monotonic = htole64(ts->monotonic);
        o->entry.xor_hash = htole64(xor_hash);
        if (boot_id)
                header->boot_id = *boot_id;
        o->entry.boot_id = header->boot_id;

#if HAVE_GCRYPT
        r = journal_file_hmac_put_object(f, OBJECT_ENTRY, o, np);
        if (r < 0)
                return r;
#endif

        r = journal_file_link_entry(f, o, np);
        if (r < 0)
                return r;

        if (ret)
                *ret = o;

        if (ret_offset)
                *ret_offset = np;

        return 0;
}

void journal_file_post_change(JournalFile *f) {
        f->ops->post_change(f);
}

static int post_change_thunk(sd_event_source *timer, uint64_t usec, void *userdata) {
        assert(userdata);

        journal_file_post_change(userdata);

        return 1;
}

static void schedule_post_change(JournalFile *f) {
        int r;

        assert(f);
        assert(f->post_change_timer);

        r = sd_event_source_get_enabled(f->post_change_timer, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to get ftruncate timer state: %m");
                goto fail;
        }
        if (r > 0)
                return;

        r = sd_event_source_set_time_relative(f->post_change_timer, f->post_change_timer_period);
        if (r < 0) {
                log_debug_errno(r, "Failed to set time for scheduling ftruncate: %m");
                goto fail;
        }

        r = sd_event_source_set_enabled(f->post_change_timer, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_debug_errno(r, "Failed to enable scheduled ftruncate: %m");
                goto fail;
        }

        return;

fail:
        /* On failure, let's simply post the change immediately. */
        journal_file_post_change(f);
}

/* Enable coalesced change posting in a timer on the provided sd_event instance */
int journal_file_enable_post_change_timer(JournalFile *f, sd_event *e, usec_t t) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *timer = NULL;
        int r;

        assert(f);
        assert_return(!f->post_change_timer, -EINVAL);
        assert(e);
        assert(t);

        r = sd_event_add_time(e, &timer, CLOCK_MONOTONIC, 0, 0, post_change_thunk, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(timer, SD_EVENT_OFF);
        if (r < 0)
                return r;

        f->post_change_timer = TAKE_PTR(timer);
        f->post_change_timer_period = t;

        return r;
}

static int entry_item_cmp(const EntryItem *a, const EntryItem *b) {
        return CMP(le64toh(a->object_offset), le64toh(b->object_offset));
}

static int journal_file_append_data(
                JournalFile *jf,
                const void *data, uint64_t size,
                Object **ret, uint64_t *ret_offset) {
        return jf->ops->append_data(jf, data, size, ret, ret_offset);
}

int journal_file_append_entry(
                JournalFile *f,
                const dual_timestamp *ts,
                const sd_id128_t *boot_id,
                const struct iovec iovec[],
                unsigned n_iovec,
                uint64_t *seqnum,
                Object **ret, uint64_t *ret_offset) {

        Header *header;
        EntryItem *items;
        int r;
        uint64_t xor_hash = 0;
        struct dual_timestamp _ts;

        assert(f);
        assert(iovec || n_iovec == 0);

        header = journal_file_header(f);
        assert(header);

        if (ts) {
                if (!VALID_REALTIME(ts->realtime))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid realtime timestamp %" PRIu64 ", refusing entry.",
                                               ts->realtime);
                if (!VALID_MONOTONIC(ts->monotonic))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Invalid monotomic timestamp %" PRIu64 ", refusing entry.",
                                               ts->monotonic);
        } else {
                dual_timestamp_get(&_ts);
                ts = &_ts;
        }

#if HAVE_GCRYPT
        r = journal_file_maybe_append_tag(f, ts->realtime);
        if (r < 0)
                return r;
#endif

        /* alloca() can't take 0, hence let's allocate at least one */
        items = newa(EntryItem, MAX(1u, n_iovec));

        for (unsigned i = 0; i < n_iovec; i++) {
                uint64_t p;
                Object *o;

                r = journal_file_append_data(f, iovec[i].iov_base, iovec[i].iov_len, &o, &p);
                if (r < 0)
                        return r;

                /* When calculating the XOR hash field, we need to take special care if the "keyed-hash"
                 * journal file flag is on. We use the XOR hash field to quickly determine the identity of a
                 * specific record, and give records with otherwise identical position (i.e. match in seqno,
                 * timestamp, …) a stable ordering. But for that we can't have it that the hash of the
                 * objects in each file is different since they are keyed. Hence let's calculate the Jenkins
                 * hash here for that. This also has the benefit that cursors for old and new journal files
                 * are completely identical (they include the XOR hash after all). For classic Jenkins-hash
                 * files things are easier, we can just take the value from the stored record directly. */

                if (JOURNAL_HEADER_KEYED_HASH(header))
                        xor_hash ^= jenkins_hash64(iovec[i].iov_base, iovec[i].iov_len);
                else
                        xor_hash ^= le64toh(o->data.hash);

                items[i].object_offset = htole64(p);
                items[i].hash = o->data.hash;
        }

        /* Order by the position on disk, in order to improve seek
         * times for rotating media. */
        typesafe_qsort(items, n_iovec, entry_item_cmp);

        r = journal_file_append_entry_internal(f, ts, boot_id, xor_hash, items, n_iovec, seqnum, ret, ret_offset);

        /* If the memory mapping triggered a SIGBUS then we return an
         * IO error and ignore the error code passed down to us, since
         * it is very likely just an effect of a nullified replacement
         * mapping page */

        if (f->ops->check_sigbus(f))
                r = -EIO;

        if (f->post_change_timer)
                schedule_post_change(f);
        else
                journal_file_post_change(f);

        return r;
}

int journal_file_move_to_entry_by_seqnum(
                JournalFile *f,
                uint64_t seqnum,
                direction_t direction,
                Object **ret,
                uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_seqnum(f, seqnum, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_realtime(
                JournalFile *f,
                uint64_t realtime,
                direction_t direction,
                Object **ret,
                uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_realtime(f, realtime, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_monotonic(
                JournalFile *f,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret,
                uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_monotonic(f, boot_id, monotonic, direction, ret, ret_offset);
}

void journal_file_reset_location(JournalFile *f) {
        f->location_type = LOCATION_HEAD;
        f->current_offset = 0;
        f->current_seqnum = 0;
        f->current_realtime = 0;
        f->current_monotonic = 0;
        zero(f->current_boot_id);
        f->current_xor_hash = 0;
}

void journal_file_save_location(JournalFile *f, Object *o, uint64_t offset) {
        f->location_type = LOCATION_SEEK;
        f->current_offset = offset;
        f->current_seqnum = le64toh(o->entry.seqnum);
        f->current_realtime = le64toh(o->entry.realtime);
        f->current_monotonic = le64toh(o->entry.monotonic);
        f->current_boot_id = o->entry.boot_id;
        f->current_xor_hash = le64toh(o->entry.xor_hash);
}

int journal_file_compare_locations(JournalFile *af, JournalFile *bf) {
        int r;
        Header *aheader, *bheader;

        assert(af);
        assert(bf);
        assert(af->location_type == LOCATION_SEEK);
        assert(af->location_type == LOCATION_SEEK);

        aheader = journal_file_header(af);
        bheader = journal_file_header(bf);
        assert(aheader);
        assert(bheader);

        /* If contents, timestamps and seqnum match, these entries are
         * identical*/
        if (sd_id128_equal(af->current_boot_id, bf->current_boot_id) &&
            af->current_monotonic == bf->current_monotonic &&
            af->current_realtime == bf->current_realtime &&
            af->current_xor_hash == bf->current_xor_hash &&
            sd_id128_equal(aheader->seqnum_id, bheader->seqnum_id) &&
            af->current_seqnum == bf->current_seqnum)
                return 0;

        if (sd_id128_equal(aheader->seqnum_id, bheader->seqnum_id)) {

                /* If this is from the same seqnum source, compare
                 * seqnums */
                r = CMP(af->current_seqnum, bf->current_seqnum);
                if (r != 0)
                        return r;

                /* Wow! This is weird, different data but the same
                 * seqnums? Something is borked, but let's make the
                 * best of it and compare by time. */
        }

        if (sd_id128_equal(af->current_boot_id, bf->current_boot_id)) {

                /* If the boot id matches, compare monotonic time */
                r = CMP(af->current_monotonic, bf->current_monotonic);
                if (r != 0)
                        return r;
        }

        /* Otherwise, compare UTC time */
        r = CMP(af->current_realtime, bf->current_realtime);
        if (r != 0)
                return r;

        /* Finally, compare by contents */
        return CMP(af->current_xor_hash, bf->current_xor_hash);
}

int journal_file_next_entry(
                JournalFile *f,
                uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {

        return f->ops->next_entry(f, p, direction, ret, ret_offset);
}

int journal_file_next_entry_for_data(
                JournalFile *f,
                Object *o, uint64_t p,
                uint64_t data_offset,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->next_entry_for_data(f, o, p, data_offset, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_offset_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t p,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {

        return f->ops->move_to_entry_by_offset_for_data(f, data_offset, p, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_monotonic_for_data(
                JournalFile *f,
                uint64_t data_offset,
                sd_id128_t boot_id,
                uint64_t monotonic,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_monotonic_for_data(
                f, data_offset, boot_id, monotonic, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_seqnum_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t seqnum,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_seqnum_for_data(f, data_offset, seqnum, direction, ret, ret_offset);
}

int journal_file_move_to_entry_by_realtime_for_data(
                JournalFile *f,
                uint64_t data_offset,
                uint64_t realtime,
                direction_t direction,
                Object **ret, uint64_t *ret_offset) {
        return f->ops->move_to_entry_by_realtime_for_data(f, data_offset, realtime, direction, ret, ret_offset);
}

void journal_file_dump(JournalFile *f) {
        Header *header;
        Object *o;
        int r;
        uint64_t p;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        journal_file_print_header(f);

        p = le64toh(READ_NOW(header->header_size));
        while (p != 0) {
                r = journal_file_move_to_object(f, OBJECT_UNUSED, p, &o);
                if (r < 0)
                        goto fail;

                switch (o->object.type) {

                case OBJECT_UNUSED:
                        printf("Type: OBJECT_UNUSED\n");
                        break;

                case OBJECT_DATA:
                        printf("Type: OBJECT_DATA\n");
                        break;

                case OBJECT_FIELD:
                        printf("Type: OBJECT_FIELD\n");
                        break;

                case OBJECT_ENTRY:
                        printf("Type: OBJECT_ENTRY seqnum=%"PRIu64" monotonic=%"PRIu64" realtime=%"PRIu64"\n",
                               le64toh(o->entry.seqnum),
                               le64toh(o->entry.monotonic),
                               le64toh(o->entry.realtime));
                        break;

                case OBJECT_FIELD_HASH_TABLE:
                        printf("Type: OBJECT_FIELD_HASH_TABLE\n");
                        break;

                case OBJECT_DATA_HASH_TABLE:
                        printf("Type: OBJECT_DATA_HASH_TABLE\n");
                        break;

                case OBJECT_ENTRY_ARRAY:
                        printf("Type: OBJECT_ENTRY_ARRAY\n");
                        break;

                case OBJECT_TAG:
                        printf("Type: OBJECT_TAG seqnum=%"PRIu64" epoch=%"PRIu64"\n",
                               le64toh(o->tag.seqnum),
                               le64toh(o->tag.epoch));
                        break;

                default:
                        printf("Type: unknown (%i)\n", o->object.type);
                        break;
                }

                if (o->object.flags & OBJECT_COMPRESSION_MASK)
                        printf("Flags: %s\n",
                               object_compressed_to_string(o->object.flags & OBJECT_COMPRESSION_MASK));

                if (p == le64toh(header->tail_object_offset))
                        p = 0;
                else
                        p += ALIGN64(le64toh(o->object.size));
        }

        return;
fail:
        log_error("File corrupt");
}

static const char* format_timestamp_safe(char *buf, size_t l, usec_t t) {
        const char *x;

        x = format_timestamp(buf, l, t);
        if (x)
                return x;
        return " --- ";
}

void journal_file_print_header(JournalFile *f) {
        char a[SD_ID128_STRING_MAX], b[SD_ID128_STRING_MAX], c[SD_ID128_STRING_MAX], d[SD_ID128_STRING_MAX];
        char x[FORMAT_TIMESTAMP_MAX], y[FORMAT_TIMESTAMP_MAX], z[FORMAT_TIMESTAMP_MAX];
        struct stat st;
        char bytes[FORMAT_BYTES_MAX];
        Header *header;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        printf("File path: %s\n"
               "File ID: %s\n"
               "Machine ID: %s\n"
               "Boot ID: %s\n"
               "Sequential number ID: %s\n"
               "State: %s\n"
               "Compatible flags:%s%s\n"
               "Incompatible flags:%s%s%s%s%s\n"
               "Header size: %"PRIu64"\n"
               "Arena size: %"PRIu64"\n"
               "Data hash table size: %"PRIu64"\n"
               "Field hash table size: %"PRIu64"\n"
               "Rotate suggested: %s\n"
               "Head sequential number: %"PRIu64" (%"PRIx64")\n"
               "Tail sequential number: %"PRIu64" (%"PRIx64")\n"
               "Head realtime timestamp: %s (%"PRIx64")\n"
               "Tail realtime timestamp: %s (%"PRIx64")\n"
               "Tail monotonic timestamp: %s (%"PRIx64")\n"
               "Objects: %"PRIu64"\n"
               "Entry objects: %"PRIu64"\n",
               f->path,
               sd_id128_to_string(header->file_id, a),
               sd_id128_to_string(header->machine_id, b),
               sd_id128_to_string(header->boot_id, c),
               sd_id128_to_string(header->seqnum_id, d),
               header->state == STATE_OFFLINE ? "OFFLINE" :
               header->state == STATE_ONLINE ? "ONLINE" :
               header->state == STATE_ARCHIVED ? "ARCHIVED" : "UNKNOWN",
               JOURNAL_HEADER_SEALED(header) ? " SEALED" : "",
               (le32toh(header->compatible_flags) & ~HEADER_COMPATIBLE_ANY) ? " ???" : "",
               JOURNAL_HEADER_COMPRESSED_XZ(header) ? " COMPRESSED-XZ" : "",
               JOURNAL_HEADER_COMPRESSED_LZ4(header) ? " COMPRESSED-LZ4" : "",
               JOURNAL_HEADER_COMPRESSED_ZSTD(header) ? " COMPRESSED-ZSTD" : "",
               JOURNAL_HEADER_KEYED_HASH(header) ? " KEYED-HASH" : "",
               (le32toh(header->incompatible_flags) & ~HEADER_INCOMPATIBLE_ANY) ? " ???" : "",
               le64toh(header->header_size),
               le64toh(header->arena_size),
               le64toh(header->data_hash_table_size) / sizeof(HashItem),
               le64toh(header->field_hash_table_size) / sizeof(HashItem),
               yes_no(journal_file_rotate_suggested(f, 0)),
               le64toh(header->head_entry_seqnum), le64toh(header->head_entry_seqnum),
               le64toh(header->tail_entry_seqnum), le64toh(header->tail_entry_seqnum),
               format_timestamp_safe(x, sizeof(x), le64toh(header->head_entry_realtime)), le64toh(header->head_entry_realtime),
               format_timestamp_safe(y, sizeof(y), le64toh(header->tail_entry_realtime)), le64toh(header->tail_entry_realtime),
               format_timespan(z, sizeof(z), le64toh(header->tail_entry_monotonic), USEC_PER_MSEC), le64toh(header->tail_entry_monotonic),
               le64toh(header->n_objects),
               le64toh(header->n_entries));

        if (JOURNAL_HEADER_CONTAINS(header, n_data))
                printf("Data objects: %"PRIu64"\n"
                       "Data hash table fill: %.1f%%\n",
                       le64toh(header->n_data),
                       100.0 * (double) le64toh(header->n_data) / ((double) (le64toh(header->data_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(header, n_fields))
                printf("Field objects: %"PRIu64"\n"
                       "Field hash table fill: %.1f%%\n",
                       le64toh(header->n_fields),
                       100.0 * (double) le64toh(header->n_fields) / ((double) (le64toh(header->field_hash_table_size) / sizeof(HashItem))));

        if (JOURNAL_HEADER_CONTAINS(header, n_tags))
                printf("Tag objects: %"PRIu64"\n",
                       le64toh(header->n_tags));
        if (JOURNAL_HEADER_CONTAINS(header, n_entry_arrays))
                printf("Entry array objects: %"PRIu64"\n",
                       le64toh(header->n_entry_arrays));

        if (JOURNAL_HEADER_CONTAINS(header, field_hash_chain_depth))
                printf("Deepest field hash chain: %" PRIu64"\n",
                       header->field_hash_chain_depth);

        if (JOURNAL_HEADER_CONTAINS(header, data_hash_chain_depth))
                printf("Deepest data hash chain: %" PRIu64"\n",
                       header->data_hash_chain_depth);

        if (fstat(f->fd, &st) >= 0)
                printf("Disk usage: %s\n", format_bytes(bytes, sizeof(bytes), (uint64_t) st.st_blocks * 512ULL));
}

int journal_file_open(
                int fd,
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournalFile *jtemplate,
                JournalFile **ret) {
        return journal_file_open_binary(fd, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics, mmap_cache, deferred_closes, jtemplate, ret);
}

int journal_file_archive(JournalFile *f) {
        Header *header;
        _cleanup_free_ char *p = NULL;

        assert(f);

        header = journal_file_header(f);
        assert(header);

        if (!f->writable)
                return -EINVAL;

        /* Is this a journal file that was passed to us as fd? If so, we synthesized a path name for it, and we refuse
         * rotation, since we don't know the actual path, and couldn't rename the file hence. */
        if (path_startswith(f->path, "/proc/self/fd"))
                return -EINVAL;

        if (!endswith(f->path, ".journal"))
                return -EINVAL;

        if (asprintf(&p, "%.*s@" SD_ID128_FORMAT_STR "-%016"PRIx64"-%016"PRIx64".journal",
                     (int) strlen(f->path) - 8, f->path,
                     SD_ID128_FORMAT_VAL(header->seqnum_id),
                     le64toh(header->head_entry_seqnum),
                     le64toh(header->head_entry_realtime)) < 0)
                return -ENOMEM;

        /* Try to rename the file to the archived version. If the file already was deleted, we'll get ENOENT, let's
         * ignore that case. */
        if (rename(f->path, p) < 0 && errno != ENOENT)
                return -errno;

        /* Sync the rename to disk */
        (void) fsync_directory_of_file(f->fd);

        /* Set as archive so offlining commits w/state=STATE_ARCHIVED. Previously we would set old_file->header->state
         * to STATE_ARCHIVED directly here, but journal_file_set_offline() short-circuits when state != STATE_ONLINE,
         * which would result in the rotated journal never getting fsync() called before closing.  Now we simply queue
         * the archive state by setting an archive bit, leaving the state as STATE_ONLINE so proper offlining
         * occurs. */
        f->archive = true;

        /* Currently, btrfs is not very good with out write patterns and fragments heavily. Let's defrag our journal
         * files when we archive them */
        f->defrag_on_close = true;

        return 0;
}

JournalFile* journal_initiate_close(
                JournalFile *f,
                Set *deferred_closes) {

        int r;

        assert(f);

        if (deferred_closes) {

                r = set_put(deferred_closes, f);
                if (r < 0)
                        log_debug_errno(r, "Failed to add file to deferred close set, closing immediately.");
                else {
                        (void) journal_file_set_offline(f, false);
                        return NULL;
                }
        }

        return journal_file_close(f);
}

int journal_file_rotate(
                JournalFile **f,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                Set *deferred_closes) {

        JournalFile *new_file = NULL;
        int r;

        assert(f);
        assert(*f);

        r = journal_file_archive(*f);
        if (r < 0)
                return r;

        r = journal_file_open(
                        -1,
                        (*f)->path,
                        (*f)->flags,
                        (*f)->mode,
                        compress,
                        compress_threshold_bytes,
                        seal,
                        NULL,            /* metrics */
                        (*f)->mmap,
                        deferred_closes,
                        *f,              /* template */
                        &new_file);

        journal_initiate_close(*f, deferred_closes);
        *f = new_file;

        return r;
}

int journal_file_dispose(int dir_fd, const char *fname) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;

        assert(fname);

        /* Renames a journal file to *.journal~, i.e. to mark it as corrupted or otherwise uncleanly shutdown. Note that
         * this is done without looking into the file or changing any of its contents. The idea is that this is called
         * whenever something is suspicious and we want to move the file away and make clear that it is not accessed
         * for writing anymore. */

        if (!endswith(fname, ".journal"))
                return -EINVAL;

        if (asprintf(&p, "%.*s@%016" PRIx64 "-%016" PRIx64 ".journal~",
                     (int) strlen(fname) - 8, fname,
                     now(CLOCK_REALTIME),
                     random_u64()) < 0)
                return -ENOMEM;

        if (renameat(dir_fd, fname, dir_fd, p) < 0)
                return -errno;

        /* btrfs doesn't cope well with our write pattern and fragments heavily. Let's defrag all files we rotate */
        fd = openat(dir_fd, p, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW);
        if (fd < 0)
                log_debug_errno(errno, "Failed to open file for defragmentation/FS_NOCOW_FL, ignoring: %m");
        else {
                (void) chattr_fd(fd, 0, FS_NOCOW_FL, NULL);
                (void) btrfs_defrag_fd(fd);
        }

        return 0;
}

int journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournalFile *template,
                JournalFile **ret) {

        int r;

        r = journal_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics, mmap_cache,
                              deferred_closes, template, ret);
        if (!IN_SET(r,
                    -EBADMSG,           /* Corrupted */
                    -ENODATA,           /* Truncated */
                    -EHOSTDOWN,         /* Other machine */
                    -EPROTONOSUPPORT,   /* Incompatible feature */
                    -EBUSY,             /* Unclean shutdown */
                    -ESHUTDOWN,         /* Already archived */
                    -EIO,               /* IO error, including SIGBUS on mmap */
                    -EIDRM,             /* File has been deleted */
                    -ETXTBSY))          /* File is from the future */
                return r;

        if ((flags & O_ACCMODE) == O_RDONLY)
                return r;

        if (!(flags & O_CREAT))
                return r;

        if (!endswith(fname, ".journal"))
                return r;

        /* The file is corrupted. Rotate it away and try it again (but only once) */
        log_warning_errno(r, "File %s corrupted or uncleanly shut down, renaming and replacing.", fname);

        r = journal_file_dispose(AT_FDCWD, fname);
        if (r < 0)
                return r;

        return journal_file_open(-1, fname, flags, mode, compress, compress_threshold_bytes, seal, metrics, mmap_cache,
                                 deferred_closes, template, ret);
}

int journal_file_copy_entry(JournalFile *from, JournalFile *to, Object *o, uint64_t p) {
        uint64_t q, n, xor_hash = 0;
        Header *to_header;
        const sd_id128_t *boot_id;
        dual_timestamp ts;
        EntryItem *items;
        int r;

        assert(from);
        assert(to);
        assert(o);
        assert(p);

        to_header = journal_file_header(to);
        assert(to_header);

        if (!to->writable)
                return -EPERM;

        ts.monotonic = le64toh(o->entry.monotonic);
        ts.realtime = le64toh(o->entry.realtime);
        boot_id = &o->entry.boot_id;

        n = journal_file_entry_n_items(o);
        /* alloca() can't take 0, hence let's allocate at least one */
        items = newa(EntryItem, MAX(1u, n));

        for (uint64_t i = 0; i < n; i++) {
                uint64_t l, h;
                le64_t le_hash;
                size_t t;
                void *data;
                Object *u;

                q = le64toh(o->entry.items[i].object_offset);
                le_hash = o->entry.items[i].hash;

                r = journal_file_move_to_object(from, OBJECT_DATA, q, &o);
                if (r < 0)
                        return r;

                if (le_hash != o->data.hash)
                        return -EBADMSG;

                l = le64toh(READ_NOW(o->object.size));
                if (l < offsetof(Object, data.payload))
                        return -EBADMSG;

                l -= offsetof(Object, data.payload);
                t = (size_t) l;

                /* We hit the limit on 32bit machines */
                if ((uint64_t) t != l)
                        return -E2BIG;

                if (o->object.flags & OBJECT_COMPRESSION_MASK) {
#if HAVE_COMPRESSION
                        size_t rsize = 0;

                        r = decompress_blob(o->object.flags & OBJECT_COMPRESSION_MASK,
                                            o->data.payload, l, &from->compress_buffer, &from->compress_buffer_size, &rsize, 0);
                        if (r < 0)
                                return r;

                        data = from->compress_buffer;
                        l = rsize;
#else
                        return -EPROTONOSUPPORT;
#endif
                } else
                        data = o->data.payload;

                r = journal_file_append_data(to, data, l, &u, &h);
                if (r < 0)
                        return r;

                if (JOURNAL_HEADER_KEYED_HASH(to_header))
                        xor_hash ^= jenkins_hash64(data, l);
                else
                        xor_hash ^= le64toh(u->data.hash);

                items[i].object_offset = htole64(h);
                items[i].hash = u->data.hash;

                r = journal_file_move_to_object(from, OBJECT_ENTRY, p, &o);
                if (r < 0)
                        return r;
        }

        r = journal_file_append_entry_internal(to, &ts, boot_id, xor_hash, items, n,
                                               NULL, NULL, NULL);

        if (to->ops->check_sigbus(to))
                return -EIO;

        return r;
}

void journal_reset_metrics(JournalMetrics *m) {
        assert(m);

        /* Set everything to "pick automatic values". */

        *m = (JournalMetrics) {
                .min_use = (uint64_t) -1,
                .max_use = (uint64_t) -1,
                .min_size = (uint64_t) -1,
                .max_size = (uint64_t) -1,
                .keep_free = (uint64_t) -1,
                .n_max_files = (uint64_t) -1,
        };
}

void journal_default_metrics(JournalMetrics *m, int fd) {
        char a[FORMAT_BYTES_MAX], b[FORMAT_BYTES_MAX], c[FORMAT_BYTES_MAX], d[FORMAT_BYTES_MAX], e[FORMAT_BYTES_MAX];
        struct statvfs ss;
        uint64_t fs_size = 0;

        assert(m);
        assert(fd >= 0);

        if (fstatvfs(fd, &ss) >= 0)
                fs_size = ss.f_frsize * ss.f_blocks;
        else
                log_debug_errno(errno, "Failed to determine disk size: %m");

        if (m->max_use == (uint64_t) -1) {

                if (fs_size > 0)
                        m->max_use = CLAMP(PAGE_ALIGN(fs_size / 10), /* 10% of file system size */
                                           MAX_USE_LOWER, MAX_USE_UPPER);
                else
                        m->max_use = MAX_USE_LOWER;
        } else {
                m->max_use = PAGE_ALIGN(m->max_use);

                if (m->max_use != 0 && m->max_use < JOURNAL_FILE_SIZE_MIN*2)
                        m->max_use = JOURNAL_FILE_SIZE_MIN*2;
        }

        if (m->min_use == (uint64_t) -1) {
                if (fs_size > 0)
                        m->min_use = CLAMP(PAGE_ALIGN(fs_size / 50), /* 2% of file system size */
                                           MIN_USE_LOW, MIN_USE_HIGH);
                else
                        m->min_use = MIN_USE_LOW;
        }

        if (m->min_use > m->max_use)
                m->min_use = m->max_use;

        if (m->max_size == (uint64_t) -1)
                m->max_size = MIN(PAGE_ALIGN(m->max_use / 8), /* 8 chunks */
                                  MAX_SIZE_UPPER);
        else
                m->max_size = PAGE_ALIGN(m->max_size);

        if (m->max_size != 0) {
                if (m->max_size < JOURNAL_FILE_SIZE_MIN)
                        m->max_size = JOURNAL_FILE_SIZE_MIN;

                if (m->max_use != 0 && m->max_size*2 > m->max_use)
                        m->max_use = m->max_size*2;
        }

        if (m->min_size == (uint64_t) -1)
                m->min_size = JOURNAL_FILE_SIZE_MIN;
        else
                m->min_size = CLAMP(PAGE_ALIGN(m->min_size),
                                    JOURNAL_FILE_SIZE_MIN,
                                    m->max_size ?: UINT64_MAX);

        if (m->keep_free == (uint64_t) -1) {
                if (fs_size > 0)
                        m->keep_free = MIN(PAGE_ALIGN(fs_size / 20), /* 5% of file system size */
                                           KEEP_FREE_UPPER);
                else
                        m->keep_free = DEFAULT_KEEP_FREE;
        }

        if (m->n_max_files == (uint64_t) -1)
                m->n_max_files = DEFAULT_N_MAX_FILES;

        log_debug("Fixed min_use=%s max_use=%s max_size=%s min_size=%s keep_free=%s n_max_files=%" PRIu64,
                  format_bytes(a, sizeof(a), m->min_use),
                  format_bytes(b, sizeof(b), m->max_use),
                  format_bytes(c, sizeof(c), m->max_size),
                  format_bytes(d, sizeof(d), m->min_size),
                  format_bytes(e, sizeof(e), m->keep_free),
                  m->n_max_files);
}

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *from, usec_t *to) {
        Header *header;

        assert(f);
        assert(from || to);

        header = journal_file_header(f);
        assert(header);

        if (from) {
                if (header->head_entry_realtime == 0)
                        return -ENOENT;

                *from = le64toh(header->head_entry_realtime);
        }

        if (to) {
                if (header->tail_entry_realtime == 0)
                        return -ENOENT;

                *to = le64toh(header->tail_entry_realtime);
        }

        return 1;
}

int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot_id, usec_t *from, usec_t *to ){
        return f->ops->get_cutoff_monotonic_usec(f, boot_id, from, to);
}


bool journal_file_rotate_suggested(JournalFile *f, usec_t max_file_usec) {
        return f->ops->rotate_suggested(f, max_file_usec);
}
