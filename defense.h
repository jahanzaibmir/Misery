#pragma once
#ifndef DEFENSE_H
#define DEFENSE_H
#include <windows.h>
#include <stdbool.h>

// Anti Analysis Detection
bool DefenseCheckDebugger(void);
bool DefenseDetectAnalysisTools(void);
bool DefenseDetectVirtualMachine(void);

// Defense System Patching
bool DefensePatchETW(void);           // Disable Event Tracing for Windows 
bool DefensePatchAMSI(void);          // Bypass AMSI scanning 
bool DefensePatchWLDP(void);          // Bypass Windows Lockdown Policy 

// Runtime Hiding 
bool DefenseHideFromDebugger(void);

// Cleanup & Reporting /
void DefenseResetSecurityChecks(void);

#endif
