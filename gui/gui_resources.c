#include "gui_resources.h"

/* ------------------------------------------------------------------ */
/* GDI resource globals                                               */
/* ------------------------------------------------------------------ */
HBRUSH  g_hbrBanner    = NULL;
HBRUSH  g_hbrBg        = NULL;
HBRUSH  g_hbrCard      = NULL;
HBRUSH  g_hbrAccent    = NULL;
HBRUSH  g_hbrCodeBg    = NULL;
HBRUSH  g_hbrDecryptBg = NULL;
HBRUSH  g_hbrTimerBg   = NULL;

HFONT   g_hFontHead    = NULL;
HFONT   g_hFontSub     = NULL;
HFONT   g_hFontBody    = NULL;
HFONT   g_hFontSmall   = NULL;
HFONT   g_hFontMono    = NULL;
HFONT   g_hFontName    = NULL;
HFONT   g_hFontTimer   = NULL;

/* ------------------------------------------------------------------ */
/* CreateResources — allocate all brushes and fonts                    */
/* ------------------------------------------------------------------ */
void CreateResources(void) {
    g_hbrBanner    = CreateSolidBrush(CLR_BANNER_BG);
    g_hbrBg        = CreateSolidBrush(CLR_BG);
    g_hbrCard      = CreateSolidBrush(CLR_CARD_BG);
    g_hbrAccent    = CreateSolidBrush(CLR_ACCENT_DARK);
    g_hbrCodeBg    = CreateSolidBrush(CLR_CODE_BG);
    g_hbrDecryptBg = CreateSolidBrush(CLR_DECRYPT_BG);
    g_hbrTimerBg   = CreateSolidBrush(CLR_TIMER_BG);

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

/* ------------------------------------------------------------------ */
/* DestroyResources — free all GDI resources                          */
/* ------------------------------------------------------------------ */
void DestroyResources(void) {
    if (g_hbrBanner)    DeleteObject(g_hbrBanner);
    if (g_hbrBg)        DeleteObject(g_hbrBg);
    if (g_hbrCard)      DeleteObject(g_hbrCard);
    if (g_hbrAccent)    DeleteObject(g_hbrAccent);
    if (g_hbrCodeBg)    DeleteObject(g_hbrCodeBg);
    if (g_hbrDecryptBg) DeleteObject(g_hbrDecryptBg);
    if (g_hbrTimerBg)   DeleteObject(g_hbrTimerBg);
    if (g_hFontHead)    DeleteObject(g_hFontHead);
    if (g_hFontSub)     DeleteObject(g_hFontSub);
    if (g_hFontBody)    DeleteObject(g_hFontBody);
    if (g_hFontSmall)   DeleteObject(g_hFontSmall);
    if (g_hFontMono)    DeleteObject(g_hFontMono);
    if (g_hFontName)    DeleteObject(g_hFontName);
    if (g_hFontTimer)   DeleteObject(g_hFontTimer);

    g_hbrBanner = g_hbrBg = g_hbrCard = g_hbrAccent = NULL;
    g_hbrCodeBg = g_hbrDecryptBg = g_hbrTimerBg = NULL;
    g_hFontHead = g_hFontSub = g_hFontBody = g_hFontSmall = NULL;
    g_hFontMono = g_hFontName = g_hFontTimer = NULL;
}