#ifndef FILEOPS_H
#define FILEOPS_H

#include <windows.h>
#include <stdbool.h>

/* Cryptographic constants come from crypto.h */
#include "crypto.h"

/* ============================================================
 * CONFIGURATION & CONSTANTS
 * ============================================================ */

#define FILEOPS_MAX_PATH     32768   // Support for \\?\ extended paths
#define FILEOPS_DEFAULT_THREADS 8    // Optimal for modern multi-core I/O
#define FILEOPS_IO_CHUNK    (64*1024) // 64KB aligns with NTFS cluster sizes

/* Fileops-specific constants (not crypto-related) */
#define ENC_EXT           ".encrypted"
#define ENC_EXT_LEN       10
#define MAX_FPATH         32768
#define MAX_DEPTH         16

typedef enum {
    FILEOPS_FLAG_NONE          = 0,
    FILEOPS_FLAG_RECURSIVE     = 1 << 0,
    FILEOPS_FLAG_DRY_RUN       = 1 << 1, // Log only, do not encrypt
    FILEOPS_FLAG_NO_DELETE     = 1 << 2, // Keep original files
    FILEOPS_FLAG_SECURE_DELETE = 1 << 3, // 3-pass wipe before unlink
    FILEOPS_FLAG_FOLLOW_SYMLINKS = 1 << 4
} FILEOPS_FLAGS;

/* ============================================================
 * CORE STRUCTURES (Context & Stats)
 * ============================================================ */

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
    CRYPTO_CTX *crypto_ctx;  /* CRITICAL: Pass crypto context explicitly */
    // Callback for custom skip logic
    bool (*pfnShouldSkip)(const WCHAR* path); 
} FILEOPS_CONFIG;

// Opaque context handle to prevent global state leaks
typedef struct FILEOPS_CTX FILEOPS_CTX;

/*
 * HIGH-PERFORMANCE API {from scratch by Jahanzaib Ashraf Mir}
 **/

/**
 * LIFECYCLE: Initializes a heavy-duty processing context.
 * Spawns the internal thread pool and prepares I/O completion ports.
 */
FILEOPS_CTX* FileOps_CreateContext(const FILEOPS_CONFIG* config);

/**
 * DISCOVERY: Recursively crawls the filesystem.
 * Submits discovered files to the internal high-speed work queue.
 */
void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath);

/**
 * SYNCHRONIZATION: Blocks until all queued file operations are complete.
 */
void FileOps_WaitForCompletion(FILEOPS_CTX* ctx);

/**
 * TELEMETRY: Returns an immutable snapshot of current engine performance.
 */
void FileOps_GetStats(FILEOPS_CTX* ctx, FILEOPS_STATS* outStats);

/**
 * CLEANUP: Shuts down threads and frees the context.
 */
void FileOps_DestroyContext(FILEOPS_CTX* ctx);

bool FileOps_DefaultShouldSkip(const WCHAR* path);

#endif // FILEOPS_H
