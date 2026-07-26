#ifndef GUI_CONTROLS_H
#define GUI_CONTROLS_H

#include "gui_types.h"

/* Subclass procedure for the key edit control (Enter → decrypt, smart paste) */
LRESULT CALLBACK KeyEditSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#endif /* GUI_CONTROLS_H */