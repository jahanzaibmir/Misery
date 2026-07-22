#ifndef FILEOPS_H
#define FILEOPS_H

#include <windows.h>
#include <stdbool.h>

#include "crypto.h"

#define FILEOPS_MAX_PATH        32768
#define FILEOPS_DEFAULT_THREADS 8
#define FILEOPS_IO_CHUNK        (64*1024)

#define ENC_EXT           ".encrypted"
#define ENC_EXT_LEN       10
#define MAX_FPATH         32768
#define MAX_DEPTH         16

typedef enum {
    FILEOPS_FLAG_NONE          = 0,
    FILEOPS_FLAG_RECURSIVE     = 1 << 0,
    FILEOPS_FLAG_DRY_RUN       = 1 << 1,
    FILEOPS_FLAG_NO_DELETE     = 1 << 2,
    FILEOPS_FLAG_SECURE_DELETE = 1 << 3,
    FILEOPS_FLAG_FOLLOW_SYMLINKS = 1 << 4
} FILEOPS_FLAGS;

typedef struct {
    alignas(8) volatile LONGLONG bytesProcessed;
    alignas(8) volatile LONGLONG filesSucceeded;
    alignas(8) volatile LONGLONG filesFailed;
    DWORD lastSystemError;
    FILETIME startTime;
} FILEOPS_STATS;

typedef struct {
    WCHAR extension[16];
    DWORD threadCount;
    DWORD ioBufferSize;
    FILEOPS_FLAGS flags;
    CRYPTO_CTX *crypto_ctx;
    bool (*pfnShouldSkip)(const WCHAR* path);
    /* NEW: decryption mode flag */
    bool decryptMode;
} FILEOPS_CONFIG;

typedef struct FILEOPS_CTX FILEOPS_CTX;

FILEOPS_CTX* FileOps_CreateContext(const FILEOPS_CONFIG* config);
void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath);
void FileOps_WaitForCompletion(FILEOPS_CTX* ctx);
void FileOps_GetStats(FILEOPS_CTX* ctx, FILEOPS_STATS* outStats);
void FileOps_DestroyContext(FILEOPS_CTX* ctx);
bool FileOps_DefaultShouldSkip(const WCHAR* path);

#endif // FILEOPS_H