#ifndef MISERY_H
#define MISERY_H

#include <windows.h>
#include <stdbool.h>

/* Version and build metadata */
#define MISERY_VERSION "3.1"
#define MISERY_BUILD_ID "20260721"

/* Global context for cross-module communication */
typedef struct {
    bool initialized;
    bool stealthMode;
    bool debugDetected;
    HANDLE hMutex;
    DWORD processID;
} MISERY_GLOBAL_CTX;

extern MISERY_GLOBAL_CTX g_misery;

/* Initialize global context */
bool Misery_InitGlobalContext(void);
void Misery_CleanupGlobalContext(void);

/* Debug detection wrapper */
bool Misery_IsDebugEnvironment(void);

/* CPU count helper */
ULONG GetActiveSystemCpuCount(void);

#endif
