// SPDX-License-Identifier: MIT
// cipher.c - Core AES-256-CBC encryption, decryption, and HMAC-SHA256 authentication

#include "ncrypt_internal.h"
#include <string.h>

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

    /* HMAC Calculation */
    BYTE hmacval[HMAC_SHA256_SIZE];
    DWORD hvlen = HMAC_SHA256_SIZE;
    HCRYPTHASH hh = 0;
    HMAC_INFO hminfo = {0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) {
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    hminfo.HashAlgid = CALG_SHA_256;
    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);

    /* Legacy 32-byte zero padding domain separator (Preserved for backward compatibility) */
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
                           BYTE *plain, DWORD *plen) {
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

    /* Legacy 32-byte zero padding domain separator */
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