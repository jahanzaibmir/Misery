#include "crypto.h"

static CRYPTO_CTX g_ctx = {0, 0};

CRYPTO_CTX *GetCryptoCtx(void) {
    return &g_ctx;
}

int InitCrypto(void) {
    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }
    if (!CryptGenKey(g_ctx.hProv, CALG_AES_256,
                     CRYPT_EXPORTABLE, &g_ctx.hKey)) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        return 0;
    }
    return 1;
}

int EncryptBuffer(CRYPTO_CTX *ctx, BYTE *iv, BYTE *buf, DWORD *encLen, DWORD bufCap) {
    /* Duplicate key so each file gets its own key state */
    HCRYPTKEY hDup = 0;
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDup))
        return 0;

    /* Set the IV on the duplicated key */
    if (!CryptSetKeyParam(hDup, KP_IV, iv, 0)) {
        CryptDestroyKey(hDup);
        return 0;
    }

    /* Encrypt in-place */
    DWORD outLen = *encLen;
    if (!CryptEncrypt(hDup, 0, TRUE, 0, buf, &outLen, bufCap)) {
        CryptDestroyKey(hDup);
        return 0;
    }
    *encLen = outLen;

    CryptDestroyKey(hDup);
    return 1;
}

void CleanupCrypto(void) {
    if (g_ctx.hKey)  { CryptDestroyKey(g_ctx.hKey);  g_ctx.hKey  = 0; }
    if (g_ctx.hProv) { CryptReleaseContext(g_ctx.hProv, 0); g_ctx.hProv = 0; }
}