
// fops_internal.h 
/* Author: Jahanzaib Ashraf Mir
Malware Researcher | Cybersecurity Engineer | Hacker
Copyright © 2026. All Rights Reserved.

No part of this script may be reproduced,published,
distributed, modified,or executed on any unauthorized systems,
networks, or servers, by any means or in any form,
without the prior written permission of the copyright owner.
Unauthorized use, deployment, or duplication is strictly prohibited and may result in legal action.*/

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
