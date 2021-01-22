#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RocksdbShim RocksdbShim;

RocksdbShim *journal_rocksdb_shim_open(const char *name);
void journal_rocksdb_shim_close(RocksdbShim *db);
int journal_rocksdb_shim_write(
        RocksdbShim *db, const char *key, uint64_t keysize, const char *value, uint64_t valuesize);

int journal_rocksdb_shim_read(
        RocksdbShim *db, const char *key, uint64_t keysize, const char **value, uint64_t *valuesize);

typedef enum SeekDirection {
        SEEK_FORWARD,
        SEEK_REVERSE,
} SeekDirection;
typedef struct RocksdbShimIterator RocksdbShimIterator;
RocksdbShimIterator *journal_rocksdb_shim_create_iterator(
        RocksdbShim *db, SeekDirection dir, uint8_t type, const char *key, uint64_t size);
int journal_rocksdb_shim_iterator_key(RocksdbShimIterator *it, const char **key, uint64_t *size);
int journal_rocksdb_shim_iterator_value(RocksdbShimIterator *it, const char **value, uint64_t *size);
int journal_rocksdb_shim_iterator_next(RocksdbShimIterator *it);
void journal_rocksdb_shim_close_iterator(RocksdbShimIterator *it);

#ifdef __cplusplus
}
#endif