/*crypto.c*/

#include "crypto.h"
#include <windows.h>
#include <wincrypt.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Static global context */
static CRYPTO_CTX g_ctx = {0};
static bool g_initialized = false;

/* Forward declarations */
static CRYPTO_ERROR SecureRandomBytes(HCRYPTPROV hProv, BYTE *buffer, DWORD size);
static CRYPTO_ERROR DeriveKeyFromPassword(HCRYPTPROV hProv, const char *password,
                                          size_t passwordLen, const BYTE *salt,
                                          HCRYPTKEY *phKey, HCRYPTKEY *phHmacKey);
static CRYPTO_ERROR ComputeHMAC(HCRYPTPROV hProv, HCRYPTKEY hHmacKey,
                               const BYTE *data, DWORD dataLen,
                               BYTE *hmacOut, DWORD hmacOutLen);
static CRYPTO_ERROR VerifyHMAC(HCRYPTPROV hProv, HCRYPTKEY hHmacKey,
                              const BYTE *data, DWORD dataLen,
                              const BYTE *expectedHmac, DWORD hmacLen);

/**
 * GetCryptoCtx - Get the global crypto context
 * Returns: Pointer to global CRYPTO_CTX structure
 */
CRYPTO_CTX *GetCryptoCtx(void) {
    return &g_ctx;
}

/**
 * GetErrorString - Convert error code to human-readable string
 * @error: CRYPTO_ERROR code
 * Returns: Pointer to error string
 */
const char *GetErrorString(CRYPTO_ERROR error) {
    switch (error) {
        case CRYPTO_SUCCESS:
            return "Success";
        case CRYPTO_ERR_INVALID_PARAM:
            return "Invalid parameter";
        case CRYPTO_ERR_MEMORY_ALLOC:
            return "Memory allocation failed";
        case CRYPTO_ERR_CRYPTO_INIT:
            return "Crypto initialization failed";
        case CRYPTO_ERR_KEY_GEN:
            return "Key generation failed";
        case CRYPTO_ERR_ENCRYPT:
            return "Encryption failed";
        case CRYPTO_ERR_DECRYPT:
            return "Decryption failed";
        case CRYPTO_ERR_MAC_VERIFY:
            return "MAC verification failed";
        case CRYPTO_ERR_IV_GEN:
            return "IV generation failed";
        case CRYPTO_ERR_BUFFER_SIZE:
            return "Buffer size invalid";
        case CRYPTO_ERR_NOT_INITIALIZED:
            return "Crypto context not initialized";
        case CRYPTO_ERR_MAC_MISMATCH:
            return "MAC mismatch - data tampered";
        case CRYPTO_ERR_HMAC_COMPUTE:
            return "HMAC computation failed";
        case CRYPTO_ERR_INVALID_MAC:
            return "Invalid MAC length";
        case CRYPTO_ERR_CONTEXT_LOCKED:
            return "Context locked by another operation";
        default:
            return "Unknown error";
    }
}

/**
 * SecureRandomBytes - Generate cryptographically secure random bytes
 * @hProv: Crypto provider handle
 * @buffer: Output buffer for random bytes
 * @size: Number of bytes to generate
 * Returns: CRYPTO_ERROR code
 */
static CRYPTO_ERROR SecureRandomBytes(HCRYPTPROV hProv, BYTE *buffer, DWORD size) {
    if (!hProv || !buffer || size == 0 || size > MAX_BUFFER_SIZE)
        return CRYPTO_ERR_INVALID_PARAM;

    if (!CryptGenRandom(hProv, size, buffer)) {
        /* Fallback: Use system RNG if CryptGenRandom fails */
        HCRYPTPROV hNewProv = 0;
        if (!CryptAcquireContextA(&hNewProv, NULL, NULL,
                                  PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return CRYPTO_ERR_IV_GEN;
        }
        
        bool bSuccess = CryptGenRandom(hNewProv, size, buffer);
        CryptReleaseContext(hNewProv, 0);
        
        if (!bSuccess)
            return CRYPTO_ERR_IV_GEN;
    }

    return CRYPTO_SUCCESS;
}

/**
 * DeriveKeyFromPassword - Derive encryption and HMAC keys from password using PBKDF2
 * @hProv: Crypto provider handle
 * @password: Password string
 * @passwordLen: Password length
 * @salt: Salt for key derivation
 * @phKey: Output encryption key handle
 * @phHmacKey: Output HMAC key handle
 * Returns: CRYPTO_ERROR code
 */
static CRYPTO_ERROR DeriveKeyFromPassword(HCRYPTPROV hProv, const char *password,
                                          size_t passwordLen, const BYTE *salt,
                                          HCRYPTKEY *phKey, HCRYPTKEY *phHmacKey) {
    if (!hProv || !password || passwordLen == 0 || passwordLen > 1024 ||
        !salt || !phKey || !phHmacKey)
        return CRYPTO_ERR_INVALID_PARAM;

    HCRYPTHASH hHash = 0;
    BYTE derivedKey[AES_KEY_SIZE_256] = {0};
    BYTE derivedHmacKey[AES_KEY_SIZE_256] = {0};
    DWORD dwKeyLen = sizeof(derivedKey);
    CRYPTO_ERROR ret = CRYPTO_SUCCESS;

    /* Create hash for PBKDF2 */
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return CRYPTO_ERR_KEY_GEN;
    }

    /* Hash the password with salt multiple times */
    for (int i = 0; i < KDF_ITERATIONS; i++) {
        if (!CryptHashData(hHash, (BYTE *)password, (DWORD)passwordLen, 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
            break;
        }
        
        if (!CryptHashData(hHash, (BYTE *)salt, SALT_SIZE, 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
            break;
        }
    }

    if (ret == CRYPTO_SUCCESS) {
        if (!CryptGetHashParam(hHash, HP_HASHVAL, derivedKey, &dwKeyLen, 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
        }
    }

    CryptDestroyHash(hHash);
    hHash = 0;

    if (ret != CRYPTO_SUCCESS)
        return ret;

    /* Create second hash for HMAC key derivation */
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        return CRYPTO_ERR_KEY_GEN;
    }

    /* Derive HMAC key */
    for (int i = 0; i < KDF_ITERATIONS / 2; i++) {
        if (!CryptHashData(hHash, (BYTE *)password, (DWORD)passwordLen, 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
            break;
        }
        
        if (!CryptHashData(hHash, derivedKey, sizeof(derivedKey), 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
            break;
        }
    }

    dwKeyLen = sizeof(derivedHmacKey);
    if (ret == CRYPTO_SUCCESS) {
        if (!CryptGetHashParam(hHash, HP_HASHVAL, derivedHmacKey, &dwKeyLen, 0)) {
            ret = CRYPTO_ERR_KEY_GEN;
        }
    }

    CryptDestroyHash(hHash);

    if (ret != CRYPTO_SUCCESS) {
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        SecureZeroMemory(derivedHmacKey, sizeof(derivedHmacKey));
        return ret;
    }

    /* Import encryption key */
    PUBLICKEYSTRUC keyBlob = {0};
    DWORD keyBlobSize = sizeof(PUBLICKEYSTRUC) + sizeof(DWORD) + AES_KEY_SIZE_256;
    BYTE *pKeyBlob = (BYTE *)malloc(keyBlobSize);
    
    if (!pKeyBlob) {
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        SecureZeroMemory(derivedHmacKey, sizeof(derivedHmacKey));
        return CRYPTO_ERR_MEMORY_ALLOC;
    }

    keyBlob.bType = PLAINTEXTKEYBLOB;
    keyBlob.bVersion = CUR_BLOB_VERSION;
    keyBlob.reserved = 0;
    keyBlob.aiKeyAlg = CALG_AES_256;

    memcpy(pKeyBlob, &keyBlob, sizeof(PUBLICKEYSTRUC));
    DWORD keyLength = AES_KEY_SIZE_256;
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC), &keyLength, sizeof(DWORD));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), derivedKey, AES_KEY_SIZE_256);

    if (!CryptImportKey(hProv, pKeyBlob, keyBlobSize, 0, 0, phKey)) {
        ret = CRYPTO_ERR_KEY_GEN;
    }

    SecureZeroMemory(pKeyBlob, keyBlobSize);
    free(pKeyBlob);

    if (ret != CRYPTO_SUCCESS) {
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        SecureZeroMemory(derivedHmacKey, sizeof(derivedHmacKey));
        return ret;
    }

    /* Import HMAC key */
    pKeyBlob = (BYTE *)malloc(keyBlobSize);
    if (!pKeyBlob) {
        CryptDestroyKey(*phKey);
        *phKey = 0;
        SecureZeroMemory(derivedKey, sizeof(derivedKey));
        SecureZeroMemory(derivedHmacKey, sizeof(derivedHmacKey));
        return CRYPTO_ERR_MEMORY_ALLOC;
    }

    memcpy(pKeyBlob, &keyBlob, sizeof(PUBLICKEYSTRUC));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC), &keyLength, sizeof(DWORD));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), derivedHmacKey, AES_KEY_SIZE_256);

    if (!CryptImportKey(hProv, pKeyBlob, keyBlobSize, 0, 0, phHmacKey)) {
        ret = CRYPTO_ERR_KEY_GEN;
    }

    SecureZeroMemory(pKeyBlob, keyBlobSize);
    free(pKeyBlob);

    SecureZeroMemory(derivedKey, sizeof(derivedKey));
    SecureZeroMemory(derivedHmacKey, sizeof(derivedHmacKey));

    return ret;
}

/**
 * ComputeHMAC - Compute HMAC-SHA256
 * @hProv: Crypto provider handle
 * @hHmacKey: HMAC key handle
 * @data: Data to authenticate
 * @dataLen: Data length
 * @hmacOut: Output HMAC buffer
 * @hmacOutLen: Output buffer size
 * Returns: CRYPTO_ERROR code
 */
static CRYPTO_ERROR ComputeHMAC(HCRYPTPROV hProv, HCRYPTKEY hHmacKey,
                               const BYTE *data, DWORD dataLen,
                               BYTE *hmacOut, DWORD hmacOutLen) {
    if (!hProv || !hHmacKey || !data || dataLen == 0 || !hmacOut || hmacOutLen < HMAC_SHA256_SIZE)
        return CRYPTO_ERR_INVALID_PARAM;

    HCRYPTHASH hHash = 0;
    DWORD dwHashLen = HMAC_SHA256_SIZE;

    if (!CryptCreateHash(hProv, CALG_HMAC, hHmacKey, 0, &hHash)) {
        return CRYPTO_ERR_HMAC_COMPUTE;
    }

    if (!CryptHashData(hHash, (BYTE *)data, dataLen, 0)) {
        CryptDestroyHash(hHash);
        return CRYPTO_ERR_HMAC_COMPUTE;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hmacOut, &dwHashLen, 0)) {
        CryptDestroyHash(hHash);
        return CRYPTO_ERR_HMAC_COMPUTE;
    }

    CryptDestroyHash(hHash);
    return CRYPTO_SUCCESS;
}

/**
 * VerifyHMAC - Verify HMAC-SHA256
 * @hProv: Crypto provider handle
 * @hHmacKey: HMAC key handle
 * @data: Data to verify
 * @dataLen: Data length
 * @expectedHmac: Expected HMAC value
 * @hmacLen: HMAC length
 * Returns: CRYPTO_ERROR code
 */
static CRYPTO_ERROR VerifyHMAC(HCRYPTPROV hProv, HCRYPTKEY hHmacKey,
                              const BYTE *data, DWORD dataLen,
                              const BYTE *expectedHmac, DWORD hmacLen) {
    if (!hProv || !hHmacKey || !data || dataLen == 0 || !expectedHmac ||
        hmacLen != HMAC_SHA256_SIZE)
        return CRYPTO_ERR_INVALID_MAC;

    BYTE computedHmac[HMAC_SHA256_SIZE] = {0};
    CRYPTO_ERROR ret = ComputeHMAC(hProv, hHmacKey, data, dataLen, computedHmac, HMAC_SHA256_SIZE);
    
    if (ret != CRYPTO_SUCCESS)
        return ret;

    /* Constant-time comparison to prevent timing attacks */
    DWORD diff = 0;
    for (DWORD i = 0; i < HMAC_SHA256_SIZE; i++) {
        diff |= (computedHmac[i] ^ expectedHmac[i]);
    }

    SecureZeroMemory(computedHmac, sizeof(computedHmac));

    if (diff != 0)
        return CRYPTO_ERR_MAC_MISMATCH;

    return CRYPTO_SUCCESS;
}

/**
 * LockContext - Lock the crypto context for exclusive use
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR LockContext(void) {
    if (!g_initialized)
        return CRYPTO_ERR_NOT_INITIALIZED;

    if (g_ctx.locked)
        return CRYPTO_ERR_CONTEXT_LOCKED;

    EnterCriticalSection(&g_ctx.csLock);
    g_ctx.locked = true;
    return CRYPTO_SUCCESS;
}

/**
 * UnlockContext - Unlock the crypto context
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR UnlockContext(void) {
    if (!g_initialized)
        return CRYPTO_ERR_NOT_INITIALIZED;

    if (!g_ctx.locked)
        return CRYPTO_ERR_CRYPTO_INIT;

    g_ctx.locked = false;
    LeaveCriticalSection(&g_ctx.csLock);
    return CRYPTO_SUCCESS;
}

/**
 * VerifyContext - Verify crypto context is properly initialized
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR VerifyContext(void) {
    if (!g_initialized)
        return CRYPTO_ERR_NOT_INITIALIZED;

    if (!g_ctx.hProv || !g_ctx.hKey || !g_ctx.hHmacKey)
        return CRYPTO_ERR_CRYPTO_INIT;

    if (!g_ctx.initialized)
        return CRYPTO_ERR_NOT_INITIALIZED;

    return CRYPTO_SUCCESS;
}

/**
 * InitCrypto - Initialize crypto system with password-based key derivation
 * @password: Password string
 * @passwordLen: Password length in bytes
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen) {
    if (!password || passwordLen == 0 || passwordLen > 1024)
        return CRYPTO_ERR_INVALID_PARAM;

    if (g_initialized && g_ctx.hKey && g_ctx.hProv) {
        /* Already initialized - prevent double initialization */
        return CRYPTO_SUCCESS;
    }

    /* Initialize critical section */
    InitializeCriticalSection(&g_ctx.csLock);

    /* Acquire crypto provider */
    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        DeleteCriticalSection(&g_ctx.csLock);
        return CRYPTO_ERR_CRYPTO_INIT;
    }

    /* Generate salt */
    CRYPTO_ERROR err = SecureRandomBytes(g_ctx.hProv, g_ctx.salt, SALT_SIZE);
    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        return err;
    }

    /* Derive keys from password */
    err = DeriveKeyFromPassword(g_ctx.hProv, password, passwordLen, g_ctx.salt,
                               &g_ctx.hKey, &g_ctx.hHmacKey);
    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        return err;
    }

    GetSystemTimeAsFileTime(&g_ctx.keyCreationTime);
    g_ctx.keyRotationCounter = 0;
    g_ctx.initialized = true;
    g_initialized = true;

    return CRYPTO_SUCCESS;
}

/**
 * InitCryptoWithKey - Initialize crypto system with raw key
 * @key: Raw encryption key (256-bit)
 * @keyLen: Key length (must be 32 bytes)
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR InitCryptoWithKey(const BYTE *key, size_t keyLen) {
    if (!key || keyLen != AES_KEY_SIZE_256)
        return CRYPTO_ERR_INVALID_PARAM;

    if (g_initialized && g_ctx.hKey && g_ctx.hProv)
        return CRYPTO_SUCCESS;

    InitializeCriticalSection(&g_ctx.csLock);

    if (!CryptAcquireContextA(&g_ctx.hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        DeleteCriticalSection(&g_ctx.csLock);
        return CRYPTO_ERR_CRYPTO_INIT;
    }

    /* Generate salt */
    CRYPTO_ERROR err = SecureRandomBytes(g_ctx.hProv, g_ctx.salt, SALT_SIZE);
    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        return err;
    }

    /* Import encryption key */
    PUBLICKEYSTRUC keyBlob = {0};
    DWORD keyBlobSize = sizeof(PUBLICKEYSTRUC) + sizeof(DWORD) + AES_KEY_SIZE_256;
    BYTE *pKeyBlob = (BYTE *)malloc(keyBlobSize);
    
    if (!pKeyBlob) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        return CRYPTO_ERR_MEMORY_ALLOC;
    }

    keyBlob.bType = PLAINTEXTKEYBLOB;
    keyBlob.bVersion = CUR_BLOB_VERSION;
    keyBlob.reserved = 0;
    keyBlob.aiKeyAlg = CALG_AES_256;

    memcpy(pKeyBlob, &keyBlob, sizeof(PUBLICKEYSTRUC));
    DWORD keyLength = AES_KEY_SIZE_256;
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC), &keyLength, sizeof(DWORD));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), key, AES_KEY_SIZE_256);

    if (!CryptImportKey(g_ctx.hProv, pKeyBlob, keyBlobSize, 0, 0, &g_ctx.hKey)) {
        err = CRYPTO_ERR_KEY_GEN;
    }

    SecureZeroMemory(pKeyBlob, keyBlobSize);
    free(pKeyBlob);

    if (err != CRYPTO_SUCCESS) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        return err;
    }

    /* Create HMAC key from derived key */
    BYTE hmacKey[AES_KEY_SIZE_256];
    for (int i = 0; i < AES_KEY_SIZE_256; i++) {
        hmacKey[i] = key[i] ^ 0xAA;
    }

    pKeyBlob = (BYTE *)malloc(keyBlobSize);
    if (!pKeyBlob) {
        CryptDestroyKey(g_ctx.hKey);
        g_ctx.hKey = 0;
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return CRYPTO_ERR_MEMORY_ALLOC;
    }

    memcpy(pKeyBlob, &keyBlob, sizeof(PUBLICKEYSTRUC));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC), &keyLength, sizeof(DWORD));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), hmacKey, AES_KEY_SIZE_256);

    if (!CryptImportKey(g_ctx.hProv, pKeyBlob, keyBlobSize, 0, 0, &g_ctx.hHmacKey)) {
        SecureZeroMemory(pKeyBlob, keyBlobSize);
        free(pKeyBlob);
        CryptDestroyKey(g_ctx.hKey);
        g_ctx.hKey = 0;
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
        DeleteCriticalSection(&g_ctx.csLock);
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        return CRYPTO_ERR_KEY_GEN;
    }

    SecureZeroMemory(pKeyBlob, keyBlobSize);
    free(pKeyBlob);
    SecureZeroMemory(hmacKey, sizeof(hmacKey));

    GetSystemTimeAsFileTime(&g_ctx.keyCreationTime);
    g_ctx.keyRotationCounter = 0;
    g_ctx.initialized = true;
    g_initialized = true;

    return CRYPTO_SUCCESS;
}

/**
 * EncryptBuffer - Encrypt plaintext with authentication
 * @ctx: Crypto context
 * @plaintext: Input plaintext
 * @plaintextLen: Plaintext length
 * @ciphertext: Output ciphertext buffer
 * @ciphertextLen: Output ciphertext length
 * @capacity: Maximum ciphertext buffer size
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR EncryptBuffer(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD plaintextLen,
                           BYTE *ciphertext, DWORD *ciphertextLen, DWORD capacity) {
    if (!ctx || !plaintext || plaintextLen == 0 || !ciphertext || !ciphertextLen)
        return CRYPTO_ERR_INVALID_PARAM;

    if (plaintextLen > MAX_BUFFER_SIZE || capacity > MAX_BUFFER_SIZE)
        return CRYPTO_ERR_BUFFER_SIZE;

    if (plaintextLen < MIN_BUFFER_SIZE)
        return CRYPTO_ERR_BUFFER_SIZE;

    CRYPTO_ERROR err = VerifyContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    err = LockContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    /* Calculate required capacity: salt(16) + iv(16) + hmac(32) + ciphertext(padded) */
    DWORD paddedLen = plaintextLen + (AES_BLOCK_SIZE - (plaintextLen % AES_BLOCK_SIZE));
    DWORD requiredCapacity = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + paddedLen;

    if (capacity < requiredCapacity) {
        UnlockContext();
        return CRYPTO_ERR_BUFFER_SIZE;
    }

    BYTE iv[IV_SIZE] = {0};
    HCRYPTKEY hDupKey = 0;

    /* Generate random IV */
    err = SecureRandomBytes(ctx->hProv, iv, IV_SIZE);
    if (err != CRYPTO_SUCCESS) {
        UnlockContext();
        SecureZeroMemory(iv, sizeof(iv));
        return err;
    }

    /* Duplicate the encryption key */
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) {
        UnlockContext();
        SecureZeroMemory(iv, sizeof(iv));
        return CRYPTO_ERR_KEY_GEN;
    }

    /* Set CBC mode */
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hDupKey, KP_MODE, (BYTE *)&mode, 0)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        SecureZeroMemory(iv, sizeof(iv));
        return CRYPTO_ERR_ENCRYPT;
    }

    /* Set IV */
    if (!CryptSetKeyParam(hDupKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        SecureZeroMemory(iv, sizeof(iv));
        return CRYPTO_ERR_ENCRYPT;
    }

    /* Prepare output buffer */
    BYTE *ciphertextData = ciphertext + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    
    /* Copy plaintext to encrypt location */
    memcpy(ciphertextData, plaintext, plaintextLen);
    
    DWORD dataLen = plaintextLen;

    /* Encrypt */
    if (!CryptEncrypt(hDupKey, 0, TRUE, 0, ciphertextData, &dataLen, 
                     capacity - SALT_SIZE - IV_SIZE - HMAC_SHA256_SIZE)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        SecureZeroMemory(iv, sizeof(iv));
        SecureZeroMemory(ciphertextData, capacity - SALT_SIZE - IV_SIZE - HMAC_SHA256_SIZE);
        return CRYPTO_ERR_ENCRYPT;
    }

    CryptDestroyKey(hDupKey);

    /* Copy salt and IV to output */
    memcpy(ciphertext, ctx->salt, SALT_SIZE);
    memcpy(ciphertext + SALT_SIZE, iv, IV_SIZE);

    SecureZeroMemory(iv, sizeof(iv));

    /* Compute HMAC over salt + iv + ciphertext */
    BYTE hmac[HMAC_SHA256_SIZE] = {0};
    DWORD hmacDataLen = SALT_SIZE + IV_SIZE + dataLen;
    err = ComputeHMAC(ctx->hProv, ctx->hHmacKey, ciphertext, hmacDataLen, hmac, HMAC_SHA256_SIZE);
    
    if (err != CRYPTO_SUCCESS) {
        UnlockContext();
        SecureZeroMemory(ciphertextData, capacity - SALT_SIZE - IV_SIZE - HMAC_SHA256_SIZE);
        SecureZeroMemory(hmac, sizeof(hmac));
        return err;
    }

    /* Copy HMAC to output */
    memcpy(ciphertext + SALT_SIZE + IV_SIZE, hmac, HMAC_SHA256_SIZE);

    *ciphertextLen = SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + dataLen;

    SecureZeroMemory(hmac, sizeof(hmac));
    UnlockContext();

    return CRYPTO_SUCCESS;
}

/**
 * DecryptBuffer - Decrypt ciphertext with authentication verification
 * @ctx: Crypto context
 * @ciphertext: Input ciphertext
 * @ciphertextLen: Ciphertext length
 * @plaintext: Output plaintext buffer
 * @plaintextLen: Output plaintext length
 * @capacity: Maximum plaintext buffer size
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR DecryptBuffer(CRYPTO_CTX *ctx, const BYTE *ciphertext, DWORD ciphertextLen,
                           BYTE *plaintext, DWORD *plaintextLen, DWORD capacity) {
    if (!ctx || !ciphertext || ciphertextLen == 0 || !plaintext || !plaintextLen)
        return CRYPTO_ERR_INVALID_PARAM;

    if (ciphertextLen < (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE + AES_BLOCK_SIZE))
        return CRYPTO_ERR_BUFFER_SIZE;

    if (ciphertextLen > MAX_BUFFER_SIZE || capacity > MAX_BUFFER_SIZE)
        return CRYPTO_ERR_BUFFER_SIZE;

    CRYPTO_ERROR err = VerifyContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    err = LockContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    /* Extract components */
    const BYTE *iv = ciphertext + SALT_SIZE;
    const BYTE *hmac = ciphertext + SALT_SIZE + IV_SIZE;
    const BYTE *ciphertextData = ciphertext + SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE;
    DWORD ciphertextDataLen = ciphertextLen - SALT_SIZE - IV_SIZE - HMAC_SHA256_SIZE;

    if (capacity < ciphertextDataLen) {
        UnlockContext();
        return CRYPTO_ERR_BUFFER_SIZE;
    }

    /* Verify HMAC first (before decrypting) */
    DWORD hmacDataLen = SALT_SIZE + IV_SIZE + ciphertextDataLen;
    err = VerifyHMAC(ctx->hProv, ctx->hHmacKey, ciphertext, hmacDataLen, hmac, HMAC_SHA256_SIZE);
    
    if (err != CRYPTO_SUCCESS) {
        UnlockContext();
        return err;
    }

    HCRYPTKEY hDupKey = 0;

    /* Duplicate the decryption key */
    if (!CryptDuplicateKey(ctx->hKey, NULL, 0, &hDupKey)) {
        UnlockContext();
        return CRYPTO_ERR_KEY_GEN;
    }

    /* Set CBC mode */
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hDupKey, KP_MODE, (BYTE *)&mode, 0)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        return CRYPTO_ERR_DECRYPT;
    }

    /* Set IV */
    if (!CryptSetKeyParam(hDupKey, KP_IV, (BYTE *)iv, 0)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        return CRYPTO_ERR_DECRYPT;
    }

    /* Copy ciphertext to plaintext buffer for decryption */
    memcpy(plaintext, ciphertextData, ciphertextDataLen);
    
    DWORD dataLen = ciphertextDataLen;

    /* Decrypt */
    if (!CryptDecrypt(hDupKey, 0, TRUE, 0, plaintext, &dataLen)) {
        CryptDestroyKey(hDupKey);
        UnlockContext();
        SecureZeroMemory(plaintext, capacity);
        return CRYPTO_ERR_DECRYPT;
    }

    CryptDestroyKey(hDupKey);
    *plaintextLen = dataLen;

    UnlockContext();
    return CRYPTO_SUCCESS;
}

/**
 * RotateKey - Rotate encryption key using password-based derivation
 * @password: New password for key derivation
 * @passwordLen: Password length
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR RotateKey(const char *password, size_t passwordLen) {
    if (!password || passwordLen == 0 || passwordLen > 1024)
        return CRYPTO_ERR_INVALID_PARAM;

    CRYPTO_ERROR err = VerifyContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    err = LockContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    /* Save old keys */
    HCRYPTKEY oldKey = g_ctx.hKey;
    HCRYPTKEY oldHmacKey = g_ctx.hHmacKey;
    BYTE oldSalt[SALT_SIZE];
    memcpy(oldSalt, g_ctx.salt, SALT_SIZE);

    /* Generate new salt */
    err = SecureRandomBytes(g_ctx.hProv, g_ctx.salt, SALT_SIZE);
    if (err != CRYPTO_SUCCESS) {
        UnlockContext();
        return err;
    }

    /* Derive new keys */
    HCRYPTKEY newKey = 0;
    HCRYPTKEY newHmacKey = 0;
    err = DeriveKeyFromPassword(g_ctx.hProv, password, passwordLen, g_ctx.salt, &newKey, &newHmacKey);
    
    if (err != CRYPTO_SUCCESS) {
        /* Restore old keys */
        memcpy(g_ctx.salt, oldSalt, SALT_SIZE);
        UnlockContext();
        return err;
    }

    /* Destroy old keys */
    CryptDestroyKey(oldKey);
    CryptDestroyKey(oldHmacKey);

    /* Update context */
    g_ctx.hKey = newKey;
    g_ctx.hHmacKey = newHmacKey;
    g_ctx.keyRotationCounter++;
    GetSystemTimeAsFileTime(&g_ctx.keyCreationTime);

    UnlockContext();
    return CRYPTO_SUCCESS;
}

/**
 * RotateKeyWithNewKey - Rotate encryption key with raw key material
 * @newKey: New 256-bit encryption key
 * @newKeyLen: Key length (must be 32 bytes)
 * Returns: CRYPTO_ERROR code
 */
CRYPTO_ERROR RotateKeyWithNewKey(const BYTE *newKey, size_t newKeyLen) {
    if (!newKey || newKeyLen != AES_KEY_SIZE_256)
        return CRYPTO_ERR_INVALID_PARAM;

    CRYPTO_ERROR err = VerifyContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    err = LockContext();
    if (err != CRYPTO_SUCCESS)
        return err;

    /* Save old keys */
    HCRYPTKEY oldKey = g_ctx.hKey;
    HCRYPTKEY oldHmacKey = g_ctx.hHmacKey;
    BYTE oldSalt[SALT_SIZE];
    memcpy(oldSalt, g_ctx.salt, SALT_SIZE);

    /* Generate new salt */
    err = SecureRandomBytes(g_ctx.hProv, g_ctx.salt, SALT_SIZE);
    if (err != CRYPTO_SUCCESS) {
        UnlockContext();
        return err;
    }

    /* Import new encryption key */
    PUBLICKEYSTRUC keyBlob = {0};
    DWORD keyBlobSize = sizeof(PUBLICKEYSTRUC) + sizeof(DWORD) + AES_KEY_SIZE_256;
    BYTE *pKeyBlob = (BYTE *)malloc(keyBlobSize);
    
    if (!pKeyBlob) {
        memcpy(g_ctx.salt, oldSalt, SALT_SIZE);
        UnlockContext();
        return CRYPTO_ERR_MEMORY_ALLOC;
    }

    keyBlob.bType = PLAINTEXTKEYBLOB;
    keyBlob.bVersion = CUR_BLOB_VERSION;
    keyBlob.reserved = 0;
    keyBlob.aiKeyAlg = CALG_AES_256;

    memcpy(pKeyBlob, &keyBlob, sizeof(PUBLICKEYSTRUC));
    DWORD keyLength = AES_KEY_SIZE_256;
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC), &keyLength, sizeof(DWORD));
    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), newKey, AES_KEY_SIZE_256);

    HCRYPTKEY hNewKey = 0;
    if (!CryptImportKey(g_ctx.hProv, pKeyBlob, keyBlobSize, 0, 0, &hNewKey)) {
        SecureZeroMemory(pKeyBlob, keyBlobSize);
        free(pKeyBlob);
        memcpy(g_ctx.salt, oldSalt, SALT_SIZE);
        UnlockContext();
        return CRYPTO_ERR_KEY_GEN;
    }

    /* Create HMAC key */
    BYTE hmacKey[AES_KEY_SIZE_256];
    for (int i = 0; i < AES_KEY_SIZE_256; i++) {
        hmacKey[i] = newKey[i] ^ 0xAA;
    }

    memcpy(pKeyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(DWORD), hmacKey, AES_KEY_SIZE_256);

    HCRYPTKEY hNewHmacKey = 0;
    if (!CryptImportKey(g_ctx.hProv, pKeyBlob, keyBlobSize, 0, 0, &hNewHmacKey)) {
        CryptDestroyKey(hNewKey);
        SecureZeroMemory(pKeyBlob, keyBlobSize);
        free(pKeyBlob);
        SecureZeroMemory(hmacKey, sizeof(hmacKey));
        memcpy(g_ctx.salt, oldSalt, SALT_SIZE);
        UnlockContext();
        return CRYPTO_ERR_KEY_GEN;
    }

    SecureZeroMemory(pKeyBlob, keyBlobSize);
    free(pKeyBlob);
    SecureZeroMemory(hmacKey, sizeof(hmacKey));

    /* Destroy old keys */
    CryptDestroyKey(oldKey);
    CryptDestroyKey(oldHmacKey);

    /* Update context */
    g_ctx.hKey = hNewKey;
    g_ctx.hHmacKey = hNewHmacKey;
    g_ctx.keyRotationCounter++;
    GetSystemTimeAsFileTime(&g_ctx.keyCreationTime);

    UnlockContext();
    return CRYPTO_SUCCESS;
}

/**
 * CleanupCrypto - Cleanup and destroy all crypto resources
 */
void CleanupCrypto(void) {
    if (!g_initialized)
        return;

    if (g_ctx.locked) {
        LeaveCriticalSection(&g_ctx.csLock);
    }

    if (g_ctx.hKey) {
        CryptDestroyKey(g_ctx.hKey);
        g_ctx.hKey = 0;
    }

    if (g_ctx.hHmacKey) {
        CryptDestroyKey(g_ctx.hHmacKey);
        g_ctx.hHmacKey = 0;
    }

    if (g_ctx.hHmac) {
        CryptDestroyHash(g_ctx.hHmac);
        g_ctx.hHmac = 0;
    }

    if (g_ctx.hProv) {
        CryptReleaseContext(g_ctx.hProv, 0);
        g_ctx.hProv = 0;
    }

    /* Securely zero salt */
    SecureZeroMemory(g_ctx.salt, SALT_SIZE);

    /* Delete critical section */
    DeleteCriticalSection(&g_ctx.csLock);

    g_ctx.initialized = false;
    g_initialized = false;

    /* Zero entire context */
    SecureZeroMemory(&g_ctx, sizeof(CRYPTO_CTX));
}
