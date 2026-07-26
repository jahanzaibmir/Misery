#include "gui_controls.h"

/* g_OldKeyEditProc — saved original window proc for edit subclass */
WNDPROC g_OldKeyEditProc = NULL;

/* KeyEditSubclassProc — unchanged (full function body below) */
LRESULT CALLBACK KeyEditSubclassProc(HWND hWnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CHAR:
        if (wParam == VK_RETURN) {
            HWND hParent = GetParent(hWnd);
            if (hParent) {
                HWND hBtn = GetDlgItem(hParent, IDC_DECRYPT_BTN);
                if (hBtn && IsWindowEnabled(hBtn)) {
                    SendMessage(hParent, WM_COMMAND,
                                MAKEWPARAM(IDC_DECRYPT_BTN, BN_CLICKED),
                                (LPARAM)hBtn);
                }
            }
            return 0;
        }
        if (wParam == VK_TAB) {
            HWND hParent = GetParent(hWnd);
            if (hParent) {
                SendMessage(hParent, WM_NEXTDLGCTL, 0, 0);
            }
            return 0;
        }
        break;

    case WM_KEYDOWN:
        if (wParam == VK_RETURN && (GetKeyState(VK_CONTROL) & 0x8000)) {
            HWND hParent = GetParent(hWnd);
            if (hParent) {
                HWND hBtn = GetDlgItem(hParent, IDC_DECRYPT_BTN);
                if (hBtn && IsWindowEnabled(hBtn)) {
                    SendMessage(hParent, WM_COMMAND,
                                MAKEWPARAM(IDC_DECRYPT_BTN, BN_CLICKED),
                                (LPARAM)hBtn);
                }
            }
            return 0;
        }
        break;

    case WM_PASTE: {
        if (!OpenClipboard(hWnd)) break;
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (!hData) { CloseClipboard(); break; }

        const WCHAR *clipStr = (const WCHAR *)GlobalLock(hData);
        if (!clipStr) { CloseClipboard(); break; }

        WCHAR clean[512] = {0};
        size_t ci = 0;
        for (size_t si = 0; clipStr[si] != L'\0' && ci < 510; si++) {
            WCHAR c = clipStr[si];
            if (iswxdigit(c)) {
                clean[ci++] = towlower(c);
            }
        }
        clean[ci] = L'\0';
        GlobalUnlock(hData);
        CloseClipboard();

        DWORD selStart, selEnd;
        SendMessage(hWnd, EM_GETSEL, (WPARAM)&selStart, (LPARAM)&selEnd);
        SendMessage(hWnd, EM_SETSEL, selStart, selEnd);
        SendMessageW(hWnd, EM_REPLACESEL, TRUE, (LPARAM)clean);
        return 0;
    }

    case WM_NCDESTROY:
        SetWindowLongPtrW(hWnd, GWLP_WNDPROC, (LONG_PTR)g_OldKeyEditProc);
        break;
    }

    return CallWindowProcW(g_OldKeyEditProc, hWnd, msg, wParam, lParam);
}