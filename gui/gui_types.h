#ifndef GUI_TYPES_H
#define GUI_TYPES_H

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h>
#include <shlobj.h>
#include <ctype.h>


/* Colour palette                                                     */

#define CLR_BG          RGB(245, 225, 225)
#define CLR_BANNER_BG   RGB(40,   8,   8)
#define CLR_ACCENT      RGB(60, 160,  80)
#define CLR_ACCENT_DARK RGB(35, 110,  50)
#define CLR_HEADLINE    RGB(220,  80,  80)
#define CLR_WHITE       RGB(248, 248, 248)
#define CLR_CARD_BG     RGB(50,  12,  12)
#define CLR_CARD_TEXT   RGB(230, 200, 200)
#define CLR_BODY_TEXT   RGB(30,  15,  15)
#define CLR_CODE_BG     RGB(235, 252, 235)
#define CLR_DECRYPT_BG  RGB(225, 240, 225)
#define CLR_TIMER_RED   RGB(220,   0,   0)
#define CLR_TIMER_BG    RGB(60,   8,   8)
#define CLR_BTN_GREEN        RGB(40, 130,  55)
#define CLR_BTN_GREEN_HOVER  RGB(50, 155,  70)
#define CLR_BTN_GREEN_PRESS  RGB(25,  80,  35)
#define CLR_BTN_GREEN_DIS    RGB(140, 175, 140)
#define CLR_BTN_RED          RGB(200,  60,  60)
#define CLR_BTN_RED_HOVER    RGB(220,  80,  80)
#define CLR_BTN_RED_PRESS    RGB(150,  40,  40)


/* Class / window identifiers                                         */
#define WC_RANSOM   L"MiseryRansomNote"
#define WIN_TITLE   L"MISERY - Security Event"

//control id's
#define IDC_CLOSE        1001
#define IDC_DECRYPT_KEY  1002
#define IDC_DECRYPT_BTN  1003
#define IDC_STATUS       1004
#define IDC_TIMER        1005
#define IDC_ATTEMPTS     1006

/* Banner/card/decorative panel IDs */
#define IDC_BANNER_BG     2001
#define IDC_CARD_BG       2002
#define IDC_DECRYPT_PANEL 2003
#define IDC_CARD_BAR      2004


// Custom window messages                                       

#define WM_DECRYPT_DONE (WM_APP + 1)

// Limits      
#define MAX_DECRYPT_ATTEMPTS 10


/* Decrypt thread parameter                                           */
typedef struct {
    char  key[256];
    HWND  hWnd;
} DECRYPT_THREAD_PARAMS;


// Extern GDI resources
extern HBRUSH  g_hbrBanner;
extern HBRUSH  g_hbrBg;
extern HBRUSH  g_hbrCard;
extern HBRUSH  g_hbrAccent;
extern HBRUSH  g_hbrCodeBg;
extern HBRUSH  g_hbrDecryptBg;
extern HBRUSH  g_hbrTimerBg;

extern HFONT   g_hFontHead;
extern HFONT   g_hFontSub;
extern HFONT   g_hFontBody;
extern HFONT   g_hFontSmall;
extern HFONT   g_hFontMono;
extern HFONT   g_hFontName;
extern HFONT   g_hFontTimer;


// Extern state variables/
extern ULONGLONG g_timerEndFileTime;
extern int       g_decryptAttempts;
extern WNDPROC   g_OldKeyEditProc;

#endif /* GUI_TYPES_H */
