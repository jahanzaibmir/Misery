// SPDX-License-Identifier: MIT
// fops_internal.h - Private context definitions for the Fops subsystem

#ifndef FOPS_INTERNAL_H
#define FOPS_INTERNAL_H

#include "../fileops.h"

// WorkItem structure for the queue linked list
struct WorkItem {
    struct WorkItem *next;
    WCHAR   path[];    // Flexible array member
};

// Full definition of FILEOPS_CTX (Hidden from the rest of the application)
struct FILEOPS_CTX {
    FILEOPS_CONFIG    config;
    FILEOPS_STATS     stats;
    bool              statsInitialized;
    CRITICAL_SECTION  statsLock;
    HANDLE           *threads;
    DWORD             threadCount;
    struct WorkItem  *queueHead;
    struct WorkItem **queueTail;
    LONG              queueCount;
    LONG              activeWorkers;
    CRITICAL_SECTION  queueLock;
    CONDITION_VARIABLE queueNotEmpty;
    CONDITION_VARIABLE queueIdle;
    volatile LONG     shutdownFlag;
};

#endif // FOPS_INTERNAL_H