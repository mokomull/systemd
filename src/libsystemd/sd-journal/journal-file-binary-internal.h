#pragma once

#include "journal-file-binary.h"

typedef struct BinaryJournalFile {
        JournalFile journal_file;

        MMapFileDescriptor *cache_fd;

        bool compress_xz:1;
        bool compress_lz4:1;
        bool compress_zstd:1;
        bool seal:1;
        bool keyed_hash:1;

        Header *header;
        HashItem *data_hash_table;

        JournalMetrics metrics;

        OrderedHashmap *chain_cache;

        uint64_t compress_threshold_bytes;

#if HAVE_GCRYPT
        gcry_md_hd_t hmac;
        bool hmac_running;

        FSSHeader *fss_file;
        size_t fss_file_size;

        uint64_t fss_start_usec;
        uint64_t fss_interval_usec;

        void *fsprg_state;
        size_t fsprg_state_size;

        void *fsprg_seed;
        size_t fsprg_seed_size;
#endif
} BinaryJournalFile;

static inline BinaryJournalFile* journal_file_to_binary(JournalFile *f) {
        return container_of(f, BinaryJournalFile, journal_file);
}
