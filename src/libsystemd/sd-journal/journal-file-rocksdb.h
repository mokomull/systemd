#pragma once

#include "journal-file-rocksdb-shim.h"
#include "journal-file.h"

extern const JournalFileOps journal_file_rocksdb_ops;

typedef struct RocksdbJournalFile {
        JournalFile journal_file;
        RocksdbShim *shim;
        Header cached_header;
        uint64_t data_id;
        Object new_object;

        Object *cached_objects[_OBJECT_TYPE_MAX];

        HashItem field_hash_table;
        RocksdbShimIterator *field_it;

        bool header_initialized : 1;
} RocksdbJournalFile;

int journal_file_rocksdb_open(
        int fd,
        const char *fname,
        int flags,
        mode_t mode,
        bool seal,
        JournalMetrics *metrics,
        JournalFile *jtemplate,
        JournalFile **ret);
