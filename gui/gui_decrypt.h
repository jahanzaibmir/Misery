#ifndef GUI_DECRYPT_H
#define GUI_DECRYPT_H

#include "gui_types.h"

/* Decrypt worker thread */
unsigned int __stdcall DecryptThreadProc(void *lpParam);

/* Normalize key input from raw text to clean 64-char hex string */
int NormalizeKeyInput(const char *raw, char *outKey, size_t outSize);

#endif /* GUI_DECRYPT_H */