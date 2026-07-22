#include "crypto.h"
#include <string.h>
#include <stdlib.h>

static CRYPTO_CTX g_ctx = { 0 };
static bool g_initialized = false;

const char *GetErrorString(CRYPTO_ERROR error) {
    static const char *err[] = {
        "Success","Invalid parameter","Memory alloc fail","Crypto init fail",
        "Key gen fail","Encryption fail","Decryption fail","MAC verify fail",
        "IV generation fail","Buffer size invalid","Not initialized",
        "MAC mismatch","HMAC computation fail","Invalid MAC length",
        "Context locked"
    };
    if (error <= CRYPTO_ERR_CONTEXT_LOCKED) return err[error];
    return "Unknown";
}

CRYPTO_CTX *GetCryptoCtx(void) { return &g_ctx; }

CRYPTO_ERROR LockContext(void) {
    if (!g_initialized) return CRYPTO_ERR_NOT_INITIALIZED;
    EnterCriticalSection(&g_ctx.csLock);
    g_ctx.locked = true;
    return CRYPTO_SUCCESS;
}
CRYPTO_ERROR UnlockContext(void) {
    if (!g_initialized) return CRYPTO_ERR_NOT_INITIALIZED;
    if (!g_ctx.locked) return CRYPTO_ERR_CRYPTO_INIT;
    g_ctx.locked = false;
    LeaveCriticalSection(&g_ctx.csLock);
    return CRYPTO_SUCCESS;
}

static CRYPTO_ERROR make_key(HCRYPTPROV hProv, const char *pw, size_t pwlen, BYTE *salt, HCRYPTKEY *hKey, HCRYPTKEY *hMacKey) {
    HCRYPTHASH hHash;
    BYTE tmpKey[AES_KEY_SIZE_256];
    DWORD klen = AES_KEY_SIZE_256;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return CRYPTO_ERR_KEY_GEN;
    CryptHashData(hHash, (BYTE*)pw, (DWORD)pwlen, 0);
    CryptHashData(hHash, salt, SALT_SIZE, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, tmpKey, &klen, 0)) { CryptDestroyHash(hHash); return CRYPTO_ERR_KEY_GEN; }
    CryptDestroyHash(hHash);
    struct {
        PUBLICKEYSTRUC hdr;
        DWORD          keylen;
        BYTE           key[AES_KEY_SIZE_256];
    } blob;
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_256;
    blob.keylen = AES_KEY_SIZE_256;
    memcpy(blob.key, tmpKey, AES_KEY_SIZE_256);
    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, hKey)) return CRYPTO_ERR_KEY_GEN;
    for (DWORD i = 0; i < AES_KEY_SIZE_256; ++i) blob.key[i] = tmpKey[i] ^ 0xAA;
    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, hMacKey)) { CryptDestroyKey(*hKey); return CRYPTO_ERR_KEY_GEN; }
    SecureZeroMemory(tmpKey, sizeof(tmpKey));
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen, BYTE *opt_salt) {
    if (!password || passwordLen == 0) return CRYPTO_ERR_INVALID_PARAM;
    if (g_initialized && g_ctx.hKey && g_ctx.hProv) return CRYPTO_SUCCESS;
    InitializeCriticalSection(&g_ctx.csLock);
    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return CRYPTO_ERR_CRYPTO_INIT;
    if (opt_salt) {
        memcpy(g_ctx.salt, opt_salt, SALT_SIZE);
    } else {
        if (!CryptGenRandom(g_ctx.hProv, SALT_SIZE, g_ctx.salt)) { CryptReleaseContext(g_ctx.hProv, 0); return CRYPTO_ERR_IV_GEN; }
    }
    if (make_key(g_ctx.hProv, password, passwordLen, g_ctx.salt, &g_ctx.hKey, &g_ctx.hHmacKey) != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        return CRYPTO_ERR_KEY_GEN;
    }
    g_ctx.locked = false;
    g_ctx.initialized = true;
    g_initialized = true;
    return CRYPTO_SUCCESS;
}

void CleanupCrypto(void) {
    if (!g_initialized) return;
    if (g_ctx.hKey) CryptDestroyKey(g_ctx.hKey);
    if (g_ctx.hHmacKey) CryptDestroyKey(g_ctx.hHmacKey);
    if (g_ctx.hProv) CryptReleaseContext(g_ctx.hProv, 0);
    DeleteCriticalSection(&g_ctx.csLock);
    SecureZeroMemory(&g_ctx, sizeof(g_ctx));
    g_initialized = false;
}

CRYPTO_ERROR EncryptBuffer(CRYPTO_CTX *ctx, const BYTE *plain, DWORD plen,
                           BYTE *cipher, DWORD *clen, DWORD cap) {
    if (!ctx || !plain || !cipher || !clen) return CRYPTO_ERR_INVALID_PARAM;
    if (plen == 0 || plen > MAX_BUFFER_SIZE) return CRYPTO_ERR_BUFFER_SIZE;
    if (!ctx->initialized || !ctx->hKey || !ctx->hHmacKey || !ctx->hProv) return CRYPTO_ERR_CRYPTO_INIT;
    CRYPTO_ERROR lerr = LockContext(); if (lerr != CRYPTO_SUCCESS) return lerr;
    BYTE iv[IV_SIZE];
    if (!CryptGenRandom(ctx->hProv, IV_SIZE, iv)) { UnlockContext(); return CRYPTO_ERR_IV_GEN; }
    DWORD padded = plen + (AES_BLOCK_SIZE - (plen % AES_BLOCK_SIZE));
    DWORD needcap = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + padded;
    if (cap < needcap) { UnlockContext(); return CRYPTO_ERR_BUFFER_SIZE; }
    memcpy(cipher, ctx->salt, SALT_SIZE);
    memcpy(cipher + SALT_SIZE, iv, IV_SIZE);
    HCRYPTKEY hDupKey=0;
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) { UnlockContext(); return CRYPTO_ERR_KEY_GEN; }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hDupKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hDupKey, KP_IV, iv, 0);
    BYTE *dst = cipher + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    memcpy(dst, plain, plen);
    if (padded > plen) SecureZeroMemory(dst+plen, padded-plen);
    DWORD ctextlen = plen;
    if (!CryptEncrypt(hDupKey,0,TRUE,0,dst,&ctextlen,padded)) {
        CryptDestroyKey(hDupKey); UnlockContext(); return CRYPTO_ERR_ENCRYPT;
    }
    CryptDestroyKey(hDupKey);

    BYTE hmacval[HMAC_SHA256_SIZE]; DWORD hvlen = HMAC_SHA256_SIZE;

    HCRYPTHASH hh=0;

    HMAC_INFO hminfo={0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) { UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE; }


    hminfo.HashAlgid = CALG_SHA_256;

    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);
 
    // Hash the HMAC slot as zeros first, then ciphertext:

    BYTE hmac_zeros[HMAC_SHA256_SIZE] ={0};
    CryptHashData(hh, cipher, SALT_SIZE + IV_SIZE, 0);
    CryptHashData(hh, hmac_zeros, HMAC_SHA256_SIZE, 0); 
    CryptHashData(hh, dst, ctextlen, 0); 

    if (!CryptGetHashParam(hh, HP_HASHVAL, hmacval, &hvlen, 0)) { CryptDestroyHash(hh); UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE; }
    CryptDestroyHash(hh);
    memcpy(cipher + SALT_SIZE + IV_SIZE, hmacval, HMAC_SHA256_SIZE);
    *clen = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + ctextlen;
    UnlockContext();
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR DecryptBuffer(CRYPTO_CTX *ctx, const BYTE *cipher, DWORD clen,
                           BYTE *plain, DWORD *plen, DWORD cap) {
    if (!ctx || !plain || !plen || !cipher || clen < (SALT_SIZE+IV_SIZE+HMAC_SHA256_SIZE+AES_BLOCK_SIZE))
        return CRYPTO_ERR_INVALID_PARAM;
    if (!ctx->initialized || !ctx->hKey || !ctx->hHmacKey || !ctx->hProv) return CRYPTO_ERR_CRYPTO_INIT;
    CRYPTO_ERROR lerr = LockContext(); if (lerr != CRYPTO_SUCCESS) return lerr;
    const BYTE *iv = cipher + SALT_SIZE;
    const BYTE *hmac = cipher + SALT_SIZE + IV_SIZE;
    const BYTE *ctext = cipher + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    DWORD ctextlen = clen - (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE);
    BYTE hmacval[HMAC_SHA256_SIZE]; DWORD hvlen = HMAC_SHA256_SIZE;
    HCRYPTHASH hh=0;
    HMAC_INFO hminfo={0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) { UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE; }
    hminfo.HashAlgid = CALG_SHA_256;
    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);

    CryptHashData(hh, cipher, SALT_SIZE + IV_SIZE, 0);
    BYTE hmac_zeros[HMAC_SHA256_SIZE] = {0};
    CryptHashData(hh, hmac_zeros, HMAC_SHA256_SIZE, 0); 
    CryptHashData(hh, ctext, ctextlen, 0);  

    if (!CryptGetHashParam(hh, HP_HASHVAL, hmacval, &hvlen, 0)) { CryptDestroyHash(hh); UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE; }
    if (memcmp(hmacval, hmac, HMAC_SHA256_SIZE) != 0) { CryptDestroyHash(hh); UnlockContext(); return CRYPTO_ERR_MAC_MISMATCH; }
    CryptDestroyHash(hh);
    HCRYPTKEY hDupKey=0;
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) { UnlockContext(); return CRYPTO_ERR_KEY_GEN; }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hDupKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hDupKey, KP_IV, (BYTE*)iv, 0);
    memcpy(plain, ctext, ctextlen); DWORD ptlen = ctextlen;
    if (!CryptDecrypt(hDupKey,0,TRUE,0,plain,&ptlen)) {
        CryptDestroyKey(hDupKey); UnlockContext(); return CRYPTO_ERR_DECRYPT;
    }
    CryptDestroyKey(hDupKey);
    *plen = ptlen;
    UnlockContext();
    return CRYPTO_SUCCESS;
}
