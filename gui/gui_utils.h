#ifndef GUI_UTILS_H
#define GUI_UTILS_H

#include "gui_types.h"

/* Update the countdown timer display */
void UpdateTimerDisplay(HWND hWnd);

/* Update the attempts counter display */
void UpdateAttemptsDisplay(HWND hWnd);

/* Delete key files from all locations, clean up crypto, close window */
void DestroyKeyAndClose(HWND hWnd);

#endif /* GUI_UTILS_H */