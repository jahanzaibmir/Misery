#include "fops_internal.h"
#include <stdlib.h>


void FopsEnqueue(FILEOPS_CTX *ctx, const WCHAR *fullPath) {
    if (!ctx || !fullPath) return;
    size_t pathBytes = (wcslen(fullPath) + 1) * sizeof(WCHAR);
    struct WorkItem *item = (struct WorkItem *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct WorkItem) + pathBytes);
    if (!item) return;
    memcpy(item->path, fullPath, pathBytes);
    item->next = NULL;
    
    EnterCriticalSection(&ctx->queueLock);
    *ctx->queueTail = item;
    ctx->queueTail = &item->next;
    ctx->queueCount++;
    WakeConditionVariable(&ctx->queueNotEmpty);
    LeaveCriticalSection(&ctx->queueLock);
}