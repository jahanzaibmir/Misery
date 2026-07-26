#include "gui_decrypt.h"
#include "../misery_config.h"   /* MiseryRunDecrypt, MiseryLog, FILEOPS_STATS */

/* NormalizeKeyInput — unchanged */
int NormalizeKeyInput(const char *raw, char *outKey, size_t outSize) {
    char cleaned[512];
    size_t n = 0;
    size_t i;

    if (!raw || !outKey || outSize < 65) return 0;

    for (i = 0; raw[i] != '\0' && n < sizeof(cleaned) - 1; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (isxdigit(c)) {
            cleaned[n++] = (char)tolower(c);
        }
    }
    cleaned[n] = '\0';

    if (n == 64) {
        memcpy(outKey, cleaned, 64);
        outKey[64] = '\0';
        return 1;
    }

    if (n == 96) {
        memcpy(outKey, cleaned + 32, 64);
        outKey[64] = '\0';
        return 1;
    }

    return 0;
}

/* DecryptThreadProc — unchanged */
unsigned int __stdcall DecryptThreadProc(void *lpParam) {
    DECRYPT_THREAD_PARAMS *p = (DECRYPT_THREAD_PARAMS *)lpParam;
    FILEOPS_STATS stats = {0};
    BOOL success = FALSE;

    if (p && p->key[0] != '\0') {
        success = MiseryRunDecrypt(p->key, &stats) ? TRUE : FALSE;
    }

    if (p && p->hWnd && IsWindow(p->hWnd)) {
        PostMessage(p->hWnd, WM_DECRYPT_DONE,
                    success ? (WPARAM)stats.filesSucceeded : (WPARAM)-1,
                    success ? (LPARAM)stats.filesFailed    : 0);
    }

    if (p) free(p);
    return 0;
}