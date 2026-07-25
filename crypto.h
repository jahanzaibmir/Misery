#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out);
int  hex_to_bytes(const char *hex, size_t hexLen, unsigned char *out, size_t outLen);

#define AES_KEY_SIZE_256 32
#define SALT_SIZE        16
#define IV_SIZE          16
#define HMAC_SHA256_SIZE 32
#define ENCRYPT_OVERHEAD (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE)
#define AES_BLOCK_SIZE   16
#define MAX_BUFFER_SIZE  (100u*1024u*1024u)
#define RAW_KEY_SIZE     32          /* 256-bit key */

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERR_INVALID_PARAM = 1,
    CRYPTO_ERR_MEMORY_ALLOC  = 2,
    CRYPTO_ERR_CRYPTO_INIT  = 3,
    CRYPTO_ERR_KEY_GEN      = 4,
    CRYPTO_ERR_ENCRYPT      = 5,
    CRYPTO_ERR_DECRYPT      = 6,
    CRYPTO_ERR_MAC_VERIFY   = 7,
    CRYPTO_ERR_IV_GEN       = 8,
    CRYPTO_ERR_BUFFER_SIZE  = 9,
    CRYPTO_ERR_NOT_INITIALIZED = 10,
    CRYPTO_ERR_MAC_MISMATCH = 11,
    CRYPTO_ERR_HMAC_COMPUTE = 12,
    CRYPTO_ERR_INVALID_MAC  = 13,
    CRYPTO_ERR_CONTEXT_LOCKED = 14
} CRYPTO_ERROR;

typedef struct {
    HCRYPTPROV      hProv;
    HCRYPTKEY       hKey;
    HCRYPTKEY       hHmacKey;
    CRITICAL_SECTION csLock;
    bool            locked;
    bool            initialized;
    BYTE            salt[SALT_SIZE];
} CRYPTO_CTX;

/* --- Initialization --- */

/* Password-based: hashes password to derive key (legacy, not used by main flow) */
CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen, BYTE *opt_salt);

/* Raw 256-bit key: uses domain-separated KDF for AES + HMAC keys (recommended) */
CRYPTO_ERROR InitCryptoRaw(const BYTE *rawKey, DWORD keyLen, const BYTE *salt);

void         CleanupCrypto(void);
CRYPTO_CTX  *GetCryptoCtx(void);
const char  *GetErrorString(CRYPTO_ERROR err);

CRYPTO_ERROR EncryptBuffer(CRYPTO_CTX *ctx, const BYTE *plaintext, DWORD plaintextLen,
                           BYTE *ciphertext, DWORD *ciphertextLen, DWORD capacity);

CRYPTO_ERROR DecryptBuffer(CRYPTO_CTX *ctx, const BYTE *ciphertext, DWORD ciphertextLen,
                           BYTE *plaintext, DWORD *plaintextLen, DWORD capacity);

#define CRYPTO_REQUIRED_CAPACITY(plainLen) ((DWORD)(plainLen)+ENCRYPT_OVERHEAD+AES_BLOCK_SIZE)

#endif