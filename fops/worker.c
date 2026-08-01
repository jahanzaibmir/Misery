// SPDX-License-Identifier: MIT
// worker.c - Worker thread lifecycle and dispatching

#include "fops_internal.h"
#include "fops_log.h"
#include <string.h>

extern void FopsProcessFileIO(FILEOPS_CTX *ctx, const char *narrowPath);

DWORD WINAPI FopsWorkerThread(LPVOID lpParam) {
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)lpParam;

    for (;;) {
        struct WorkItem *item = NULL;

        EnterCriticalSection(&ctx->queueLock);
        while (ctx->queueHead == NULL && !ctx->shutdownFlag) {
            SleepConditionVariableCS(&ctx->queueNotEmpty, &ctx->queueLock, INFINITE);
        }
        if (ctx->shutdownFlag && ctx->queueHead == NULL) {
            LeaveCriticalSection(&ctx->queueLock);
            break;
        }
        item = ctx->queueHead;
        ctx->queueHead = item->next;
        if (ctx->queueHead == NULL) ctx->queueTail = &ctx->queueHead;
        ctx->queueCount--;
        ctx->activeWorkers++;
        LeaveCriticalSection(&ctx->queueLock);

        char narrowPath[FILEOPS_MAX_PATH];
        int narrowLen = WideCharToMultiByte(CP_UTF8, 0, item->path, -1,
                                            narrowPath, sizeof(narrowPath), NULL, NULL);
        HeapFree(GetProcessHeap(), 0, item);
        item = NULL;

        if (narrowLen <= 0 || narrowLen >= (int)sizeof(narrowPath)) {
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            LeaveCriticalSection(&ctx->statsLock);
            EnterCriticalSection(&ctx->queueLock);
            ctx->activeWorkers--;
            WakeConditionVariable(&ctx->queueIdle);
            LeaveCriticalSection(&ctx->queueLock);
            continue;
        }

        FopsProcessFileIO(ctx, narrowPath);

        EnterCriticalSection(&ctx->queueLock);
        ctx->activeWorkers--;
        WakeConditionVariable(&ctx->queueIdle);
        LeaveCriticalSection(&ctx->queueLock);
    }
    return 0;
}