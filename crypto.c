#include "crypto.h"
#include <string.h>
#include <stdlib.h>

static CRYPTO_CTX g_ctx = { 0 };
static bool g_initialized = false;

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    static const char hexdig[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hexdig[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexdig[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, size_t hexLen, unsigned char *out, size_t outLen) {
    if (hexLen % 2 != 0 || hexLen / 2 > outLen) return 0;
    for (size_t i = 0; i < hexLen / 2; i++) {
        unsigned char hi = 0, lo = 0;
        char c = hex[i * 2];
        if      (c >= '0' && c <= '9') hi = (unsigned char)(c - '0');
        else if (c >= 'a' && c <= 'f') hi = (unsigned char)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') hi = (unsigned char)(c - 'A' + 10);
        else return 0;
        c = hex[i * 2 + 1];
        if      (c >= '0' && c <= '9') lo = (unsigned char)(c - '0');
        else if (c >= 'a' && c <= 'f') lo = (unsigned char)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') lo = (unsigned char)(c - 'A' + 10);
        else return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(hexLen / 2);
}

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

/*
 * FIX: Domain-separated key derivation.
 *   AES key  = SHA-256("misery-aes-key" || inputKey || salt)
 *   HMAC key = SHA-256("misery-hmac-key" || inputKey || salt)
 *
 * This ensures:
 *   - AES and HMAC keys are cryptographically independent
 *   - Knowledge of one does not reveal the other
 *   - Full 256-bit entropy from inputKey is preserved
 */
static CRYPTO_ERROR derive_keys(HCRYPTPROV hProv,
                                const BYTE *inputKey, DWORD inputLen,
                                const BYTE *salt,
                                HCRYPTKEY *hKey, HCRYPTKEY *hMacKey)
{
    HCRYPTHASH hHash = 0;
    BYTE aesKey[AES_KEY_SIZE_256];
    BYTE hmacKey[AES_KEY_SIZE_256];
    DWORD klen = AES_KEY_SIZE_256;
    CRYPTO_ERROR err = CRYPTO_SUCCESS;

    const char aesCtx[]  = "misery-aes-key";
    const char hmacCtx[] = "misery-hmac-key";

    /* --- Derive AES-256 key --- */
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptHashData(hHash, (BYTE*)aesCtx, (DWORD)strlen(aesCtx), 0);
    CryptHashData(hHash, inputKey, inputLen, 0);
    CryptHashData(hHash, salt, SALT_SIZE, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, aesKey, &klen, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptDestroyHash(hHash); hHash = 0;

    /* --- Derive HMAC-SHA256 key (separate hash chain) --- */
    klen = AES_KEY_SIZE_256;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptHashData(hHash, (BYTE*)hmacCtx, (DWORD)strlen(hmacCtx), 0);
    CryptHashData(hHash, inputKey, inputLen, 0);
    CryptHashData(hHash, salt, SALT_SIZE, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hmacKey, &klen, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptDestroyHash(hHash); hHash = 0;

    /* --- Import AES key into CryptoAPI --- */
    struct {
        PUBLICKEYSTRUC hdr;
        DWORD          keylen;
        BYTE           key[AES_KEY_SIZE_256];
    } blob;
    blob.hdr.bType      = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion   = CUR_BLOB_VERSION;
    blob.hdr.reserved   = 0;
    blob.hdr.aiKeyAlg   = CALG_AES_256;
    blob.keylen         = AES_KEY_SIZE_256;
    memcpy(blob.key, aesKey, AES_KEY_SIZE_256);

    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, hKey)) {
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }

    /* --- Import HMAC key --- */
    memcpy(blob.key, hmacKey, AES_KEY_SIZE_256);
    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, hMacKey)) {
        CryptDestroyKey(*hKey); *hKey = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }

cleanup:
    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(hmacKey, sizeof(hmacKey));
    SecureZeroMemory(blob.key, sizeof(blob.key));
    if (hHash) CryptDestroyHash(hHash);
    return err;
}

/*
 * Password-based initialisation (legacy wrapper).
 * Hashes password to a 32-byte key, then calls derive_keys().
 */
CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen, BYTE *opt_salt) {
    if (!password || passwordLen == 0) return CRYPTO_ERR_INVALID_PARAM;
    if (g_initialized && g_ctx.hKey && g_ctx.hProv) return CRYPTO_SUCCESS;

    InitializeCriticalSection(&g_ctx.csLock);

    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return CRYPTO_ERR_CRYPTO_INIT;

    if (opt_salt) {
        memcpy(g_ctx.salt, opt_salt, SALT_SIZE);
    } else {
        if (!CryptGenRandom(g_ctx.hProv, SALT_SIZE, g_ctx.salt)) {
            CryptReleaseContext(g_ctx.hProv, 0);
            return CRYPTO_ERR_IV_GEN;
        }
    }

    /* Hash password to get a 256-bit input key */
    HCRYPTHASH hHash = 0;
    BYTE pwKey[AES_KEY_SIZE_256];
    DWORD klen = AES_KEY_SIZE_256;
    CRYPTO_ERROR err = CRYPTO_SUCCESS;

    if (!CryptCreateHash(g_ctx.hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(g_ctx.hProv, 0);
        return CRYPTO_ERR_KEY_GEN;
    }
    CryptHashData(hHash, (BYTE*)password, (DWORD)passwordLen, 0);
    CryptHashData(hHash, g_ctx.salt, SALT_SIZE, 0);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, pwKey, &klen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(g_ctx.hProv, 0);
        return CRYPTO_ERR_KEY_GEN;
    }
    CryptDestroyHash(hHash);

    err = derive_keys(g_ctx.hProv, pwKey, AES_KEY_SIZE_256, g_ctx.salt,
                      &g_ctx.hKey, &g_ctx.hHmacKey);
    SecureZeroMemory(pwKey, sizeof(pwKey));

    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        return err;
    }

    g_ctx.locked      = false;
    g_ctx.initialized = true;
    g_initialized     = true;
    return CRYPTO_SUCCESS;
}

/*
 * FIX: New raw-key initialisation — uses derive_keys() directly.
 *   - salt == NULL → generates a random salt
 *   - salt != NULL → uses the provided salt (for decryption)
 */
CRYPTO_ERROR InitCryptoRaw(const BYTE *rawKey, DWORD keyLen, const BYTE *salt) {
    if (!rawKey || keyLen == 0) return CRYPTO_ERR_INVALID_PARAM;
    if (g_initialized && g_ctx.hKey && g_ctx.hProv) return CRYPTO_SUCCESS;

    InitializeCriticalSection(&g_ctx.csLock);

    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return CRYPTO_ERR_CRYPTO_INIT;

    if (salt) {
        memcpy(g_ctx.salt, salt, SALT_SIZE);
    } else {
        if (!CryptGenRandom(g_ctx.hProv, SALT_SIZE, g_ctx.salt)) {
            CryptReleaseContext(g_ctx.hProv, 0);
            return CRYPTO_ERR_IV_GEN;
        }
    }

    CRYPTO_ERROR err = derive_keys(g_ctx.hProv, rawKey, keyLen, g_ctx.salt,
                                    &g_ctx.hKey, &g_ctx.hHmacKey);
    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        return err;
    }

    g_ctx.locked      = false;
    g_ctx.initialized = true;
    g_initialized     = true;
    return CRYPTO_SUCCESS;
}

void CleanupCrypto(void) {
    if (!g_initialized) return;
    if (g_ctx.hKey)    CryptDestroyKey(g_ctx.hKey);
    if (g_ctx.hHmacKey) CryptDestroyKey(g_ctx.hHmacKey);
    if (g_ctx.hProv)   CryptReleaseContext(g_ctx.hProv, 0);
    DeleteCriticalSection(&g_ctx.csLock);
    SecureZeroMemory(&g_ctx, sizeof(g_ctx));
    g_initialized = false;
}

/* ===================================================================
 * EncryptBuffer and DecryptBuffer are unchanged from the original —
 * they use the context's hKey (AES-256-CBC) and hHmacKey (HMAC-SHA256).
 * The HMAC covers [salt || iv || zeroed-MAC-slot || ciphertext].
 * =================================================================== */

CRYPTO_ERROR EncryptBuffer(CRYPTO_CTX *ctx, const BYTE *plain, DWORD plen,
                           BYTE *cipher, DWORD *clen, DWORD cap) {
    if (!ctx || !plain || !cipher || !clen) return CRYPTO_ERR_INVALID_PARAM;
    if (plen == 0 || plen > MAX_BUFFER_SIZE) return CRYPTO_ERR_BUFFER_SIZE;
    if (!ctx->initialized || !ctx->hKey || !ctx->hHmacKey || !ctx->hProv)
        return CRYPTO_ERR_CRYPTO_INIT;

    CRYPTO_ERROR lerr = LockContext();
    if (lerr != CRYPTO_SUCCESS) return lerr;

    BYTE iv[IV_SIZE];
    if (!CryptGenRandom(ctx->hProv, IV_SIZE, iv)) {
        UnlockContext(); return CRYPTO_ERR_IV_GEN;
    }

    DWORD padded = plen + (AES_BLOCK_SIZE - (plen % AES_BLOCK_SIZE));
    DWORD needcap = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + padded;
    if (cap < needcap) { UnlockContext(); return CRYPTO_ERR_BUFFER_SIZE; }

    memcpy(cipher, ctx->salt, SALT_SIZE);
    memcpy(cipher + SALT_SIZE, iv, IV_SIZE);

    HCRYPTKEY hDupKey = 0;
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) {
        UnlockContext(); return CRYPTO_ERR_KEY_GEN;
    }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hDupKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hDupKey, KP_IV, iv, 0);

    BYTE *dst = cipher + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    memcpy(dst, plain, plen);
    if (padded > plen) SecureZeroMemory(dst + plen, padded - plen);

    DWORD ctextlen = plen;
    if (!CryptEncrypt(hDupKey, 0, TRUE, 0, dst, &ctextlen, padded)) {
        CryptDestroyKey(hDupKey); UnlockContext(); return CRYPTO_ERR_ENCRYPT;
    }
    CryptDestroyKey(hDupKey);

    /* Compute HMAC over [salt || iv || 32 zero-bytes || ciphertext] */
    BYTE hmacval[HMAC_SHA256_SIZE];
    DWORD hvlen = HMAC_SHA256_SIZE;
    HCRYPTHASH hh = 0;
    HMAC_INFO hminfo = {0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) {
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    hminfo.HashAlgid = CALG_SHA_256;
    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);

    BYTE hmac_zeros[HMAC_SHA256_SIZE] = {0};
    CryptHashData(hh, cipher, SALT_SIZE + IV_SIZE, 0);
    CryptHashData(hh, hmac_zeros, HMAC_SHA256_SIZE, 0);
    CryptHashData(hh, dst, ctextlen, 0);

    if (!CryptGetHashParam(hh, HP_HASHVAL, hmacval, &hvlen, 0)) {
        CryptDestroyHash(hh); UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    CryptDestroyHash(hh);

    memcpy(cipher + SALT_SIZE + IV_SIZE, hmacval, HMAC_SHA256_SIZE);
    *clen = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + ctextlen;
    UnlockContext();
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR DecryptBuffer(CRYPTO_CTX *ctx, const BYTE *cipher, DWORD clen,
                           BYTE *plain, DWORD *plen, DWORD cap) {
    if (!ctx || !plain || !plen || !cipher ||
        clen < (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + AES_BLOCK_SIZE))
        return CRYPTO_ERR_INVALID_PARAM;
    if (!ctx->initialized || !ctx->hKey || !ctx->hHmacKey || !ctx->hProv)
        return CRYPTO_ERR_CRYPTO_INIT;

    CRYPTO_ERROR lerr = LockContext();
    if (lerr != CRYPTO_SUCCESS) return lerr;

    const BYTE *iv     = cipher + SALT_SIZE;
    const BYTE *hmac   = cipher + SALT_SIZE + IV_SIZE;
    const BYTE *ctext  = cipher + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    DWORD ctextlen = clen - (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE);

    /* Verify HMAC first */
    BYTE hmacval[HMAC_SHA256_SIZE];
    DWORD hvlen = HMAC_SHA256_SIZE;
    HCRYPTHASH hh = 0;
    HMAC_INFO hminfo = {0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) {
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    hminfo.HashAlgid = CALG_SHA_256;
    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);

    BYTE hmac_zeros[HMAC_SHA256_SIZE] = {0};
    CryptHashData(hh, cipher, SALT_SIZE + IV_SIZE, 0);
    CryptHashData(hh, hmac_zeros, HMAC_SHA256_SIZE, 0);
    CryptHashData(hh, ctext, ctextlen, 0);

    if (!CryptGetHashParam(hh, HP_HASHVAL, hmacval, &hvlen, 0)) {
        CryptDestroyHash(hh);
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    CryptDestroyHash(hh);

    if (memcmp(hmacval, hmac, HMAC_SHA256_SIZE) != 0) {
        UnlockContext(); return CRYPTO_ERR_MAC_MISMATCH;
    }

    /* Decrypt */
    HCRYPTKEY hDupKey = 0;
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) {
        UnlockContext(); return CRYPTO_ERR_KEY_GEN;
    }
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hDupKey, KP_MODE, (BYTE*)&mode, 0);
    CryptSetKeyParam(hDupKey, KP_IV, (BYTE*)iv, 0);

    memcpy(plain, ctext, ctextlen);
    DWORD ptlen = ctextlen;
    if (!CryptDecrypt(hDupKey, 0, TRUE, 0, plain, &ptlen)) {
        CryptDestroyKey(hDupKey);
        UnlockContext(); return CRYPTO_ERR_DECRYPT;
    }
    CryptDestroyKey(hDupKey);
    *plen = ptlen;
    UnlockContext();
    return CRYPTO_SUCCESS;
}