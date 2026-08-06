
// context.c 

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

// Define the global state here
CRYPTO_CTX g_nctx = { 0 };
bool g_ninitialized = false;
bool g_ncs_initialized = false;

CRYPTO_CTX *GetCryptoCtx(void) { return &g_nctx; }

CRYPTO_ERROR LockContext(void) {
    if (!g_ninitialized) return CRYPTO_ERR_NOT_INITIALIZED;
    EnterCriticalSection(&g_nctx.csLock);
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR UnlockContext(void) {
    if (!g_ninitialized) return CRYPTO_ERR_NOT_INITIALIZED;
    LeaveCriticalSection(&g_nctx.csLock);
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen, BYTE *opt_salt) {
    if (!password || passwordLen == 0) return CRYPTO_ERR_INVALID_PARAM;
    if (g_ninitialized && g_nctx.hKey && g_nctx.hProv) return CRYPTO_SUCCESS;

    if (!g_ncs_initialized) {
        InitializeCriticalSection(&g_nctx.csLock);
        g_ncs_initialized = true;
    }

    if (!CryptAcquireContextA(&g_nctx.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return CRYPTO_ERR_CRYPTO_INIT;

    if (opt_salt) {
        memcpy(g_nctx.salt, opt_salt, SALT_SIZE);
    } else {
        if (!CryptGenRandom(g_nctx.hProv, SALT_SIZE, g_nctx.salt)) {
            CryptReleaseContext(g_nctx.hProv, 0);
            g_nctx.hProv = 0;
            return CRYPTO_ERR_IV_GEN;
        }
    }

    HCRYPTHASH hHash = 0;
    BYTE pwKey[AES_KEY_SIZE_256];
    DWORD klen = AES_KEY_SIZE_256;
    CRYPTO_ERROR err = CRYPTO_SUCCESS;

    if (!CryptCreateHash(g_nctx.hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
        return CRYPTO_ERR_KEY_GEN;
    }
    
    // F Check CryptHashData returns
    if (!CryptHashData(hHash, (BYTE*)password, (DWORD)passwordLen, 0) ||
        !CryptHashData(hHash, g_nctx.salt, SALT_SIZE, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
        return CRYPTO_ERR_KEY_GEN;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, pwKey, &klen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
        return CRYPTO_ERR_KEY_GEN;
    }
    CryptDestroyHash(hHash);

    err = NcryptDeriveKeys(g_nctx.hProv, pwKey, AES_KEY_SIZE_256, g_nctx.salt,
                           &g_nctx.hKey, &g_nctx.hHmacKey);
    SecureZeroMemory(pwKey, sizeof(pwKey));

    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
        return err;
    }

    g_nctx.locked      = false;
    g_nctx.initialized = true;
    g_ninitialized     = true;
    return CRYPTO_SUCCESS;
}

CRYPTO_ERROR InitCryptoRaw(const BYTE *rawKey, DWORD keyLen, const BYTE *salt) {
    if (!rawKey) return CRYPTO_ERR_INVALID_PARAM;
    if (keyLen != RAW_KEY_SIZE) return CRYPTO_ERR_INVALID_PARAM; 
    if (g_ninitialized && g_nctx.hKey && g_nctx.hProv) return CRYPTO_SUCCESS;

    if (!g_ncs_initialized) {
        InitializeCriticalSection(&g_nctx.csLock);
        g_ncs_initialized = true;
    }

    if (!CryptAcquireContextA(&g_nctx.hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return CRYPTO_ERR_CRYPTO_INIT;

    if (salt) {
        memcpy(g_nctx.salt, salt, SALT_SIZE);
    } else {
        if (!CryptGenRandom(g_nctx.hProv, SALT_SIZE, g_nctx.salt)) {
            CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
            return CRYPTO_ERR_IV_GEN;
        }
    }

    CRYPTO_ERROR err = NcryptDeriveKeys(g_nctx.hProv, rawKey, keyLen, g_nctx.salt,
                                       &g_nctx.hKey, &g_nctx.hHmacKey);
    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0;
        return err;
    }

    g_nctx.locked      = false;
    g_nctx.initialized = true;
    g_ninitialized     = true;
    return CRYPTO_SUCCESS;
}

void CleanupCrypto(void) {
    if (g_nctx.hKey)    { CryptDestroyKey(g_nctx.hKey); g_nctx.hKey = 0; }
    if (g_nctx.hHmacKey) { CryptDestroyKey(g_nctx.hHmacKey); g_nctx.hHmacKey = 0; }
    if (g_nctx.hProv)   { CryptReleaseContext(g_nctx.hProv, 0); g_nctx.hProv = 0; }

    SecureZeroMemory(g_nctx.salt, SALT_SIZE);

    if (g_ncs_initialized) {
        DeleteCriticalSection(&g_nctx.csLock);
        g_ncs_initialized = false;
    }

    SecureZeroMemory(&g_nctx, sizeof(g_nctx));
    g_ninitialized = false;
}
