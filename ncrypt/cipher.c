
// cipher.c

/*Author: Jahanzaib Ashraf Mir
Kashmir
CSE GRAD W/S in Cybersecurity
Malware Researcher | Cybersecurity Engineer | Hacker
Copyright © 2026. All Rights Reserved.

This educational script and software is designed
strictly for academic research and defensive analysis.
No part of this script may be reproduced, published, distributed, modified,
sold, rebranded, or executed on any unauthorized systems, networks, or servers,
by any means or in any form, without prior written permission of the copyright owner.

Unauthorized use, deployment, or duplication is strictly prohibited and may result
in severe legal action under applicable copyright and computer crime statutes.

THIS SOFTWARE IS PROVIDED "AS IS" FOR EDUCATIONAL PURPOSES ONLY.
The author assumes zero liability and no responsibility for any misuse, damage,
data loss, or illegal activity resulting from the execution of this code.
Execution against non-consenting target systems is strictly illegal.*/

#include "ncrypt_internal.h"
#include <string.h>

// Constant time comparison to prevent HMAC timing side channel attacks
static int NcryptSafeCompare(const BYTE *a, const BYTE *b, size_t len) {
    int result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result; // Returns 0 if identical, non zero if different
}

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

    //  EXPLICITLY zero the HMAC slot  The legacy HMAC calculation hashes this exact 
   
    SecureZeroMemory(cipher + SALT_SIZE + IV_SIZE, HMAC_SHA256_SIZE);

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

    /* Legacy 32 byte zero padding domain separator  */
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

    //
    BYTE hmacval[HMAC_SHA256_SIZE];
    DWORD hvlen = HMAC_SHA256_SIZE;
    HCRYPTHASH hh = 0;
    HMAC_INFO hminfo = {0};

    if (!CryptCreateHash(ctx->hProv, CALG_HMAC, ctx->hHmacKey, 0, &hh)) {
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    hminfo.HashAlgid = CALG_SHA_256;
    CryptSetHashParam(hh, HP_HMAC_INFO, (BYTE*)&hminfo, 0);

    //
    BYTE hmac_zeros[HMAC_SHA256_SIZE] = {0};
    CryptHashData(hh, cipher, SALT_SIZE + IV_SIZE, 0);
    CryptHashData(hh, hmac_zeros, HMAC_SHA256_SIZE, 0);
    CryptHashData(hh, ctext, ctextlen, 0);

    if (!CryptGetHashParam(hh, HP_HASHVAL, hmacval, &hvlen, 0)) {
        CryptDestroyHash(hh);
        UnlockContext(); return CRYPTO_ERR_HMAC_COMPUTE;
    }
    CryptDestroyHash(hh);

    //  constant time NcryptSafeCompare to prevent timing side-channels
    if (NcryptSafeCompare(hmacval, hmac, HMAC_SHA256_SIZE) != 0) {
        UnlockContext(); return CRYPTO_ERR_MAC_MISMATCH;
    }

    //
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
