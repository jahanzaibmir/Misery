/*crypto.h*/
#pragma once
#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * ============================================================================
 * Windows CryptoAPI Wrapper - AES-256-CBC with HMAC-SHA256
 * ============================================================================
 *
 * Provides authenticated symmetric encryption using:
 *   - AES-256-CBC for confidentiality
 *   - HMAC-SHA256 for integrity (encrypt-then-MAC)
 *   - PBKDF2-style password-based key derivation (or raw key import)
 *   - Cryptographically secure random IV and salt generation
 *   - Constant-time MAC comparison (timing-attack resistant)
 *   - Thread-safe operations via CRITICAL_SECTION
 *   - Key rotation support
 *
 * Wire format produced by EncryptBuffer():
 *   [ Salt (16) | IV (16) | HMAC-SHA256 (32) | Ciphertext (N, padded to 16) ]
 *
 * Usage:
 *   1. Call InitCrypto() or InitCryptoWithKey() once at startup.
 *   2. Call EncryptBuffer() / DecryptBuffer() as needed.
 *   3. Call CleanupCrypto() at shutdown.
 *
 * Thread safety:
 *   InitCrypto / InitCryptoWithKey — NOT thread-safe; call once before
 *   spawning threads.  All other functions are thread-safe.
 * ============================================================================
 */

#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601   /* Windows 7 minimum */
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * CONSTANTS
 * ============================================================ */

/** AES block and IV size (bytes) */
#define AES_BLOCK_SIZE      16
#define IV_SIZE             16

/** AES-256 key size (bytes) */
#define AES_KEY_SIZE_256    32

/** Salt size for key derivation (bytes) */
#define SALT_SIZE           16

/** HMAC-SHA256 output size (bytes) */
#define HMAC_SHA256_SIZE    32

/**
 * Minimum required overhead added to plaintext by EncryptBuffer().
 * Output size = plaintextLen + ENCRYPT_OVERHEAD  (plus AES padding, up to
 * one extra block).  Allocate at least plaintextLen + ENCRYPT_OVERHEAD +
 * AES_BLOCK_SIZE to be safe.
 *
 *   SALT(16) + IV(16) + HMAC(32) = 64 bytes
 */
#define ENCRYPT_OVERHEAD    (SALT_SIZE + IV_SIZE + HMAC_SHA256_SIZE)

/**
 * KDF iteration count used when deriving keys from a password.
 *
 * NOTE: The current implementation is NOT a standards-compliant PBKDF2.
 * Consider replacing DeriveKeyFromPassword() with BCryptDeriveKeyPBKDF2()
 * and increasing this value to >= 100 000 for password-based keys.
 */
#define KDF_ITERATIONS      10000

/** Absolute buffer size limits */
#define MAX_BUFFER_SIZE     (100u * 1024u * 1024u)   /* 100 MB */
#define MIN_BUFFER_SIZE     1u

/* ============================================================
 * ERROR CODES
 * ============================================================ */

/**
 * CRYPTO_ERROR - Return codes for all crypto functions.
 *
 * Every function returns CRYPTO_SUCCESS (0) on success and a non-zero
 * value on failure.  Use GetErrorString() to get a human-readable
 * description.
 */
typedef enum {
    CRYPTO_SUCCESS              = 0,    /**< Operation completed successfully */
    CRYPTO_ERR_INVALID_PARAM    = 1,    /**< NULL pointer or out-of-range argument */
    CRYPTO_ERR_MEMORY_ALLOC     = 2,    /**< malloc() / HeapAlloc() returned NULL */
    CRYPTO_ERR_CRYPTO_INIT      = 3,    /**< CryptAcquireContext or CS init failed */
    CRYPTO_ERR_KEY_GEN          = 4,    /**< Key import / derivation failed */
    CRYPTO_ERR_ENCRYPT          = 5,    /**< CryptEncrypt failed */
    CRYPTO_ERR_DECRYPT          = 6,    /**< CryptDecrypt failed */
    CRYPTO_ERR_MAC_VERIFY       = 7,    /**< HMAC computation failed during verify */
    CRYPTO_ERR_IV_GEN           = 8,    /**< CryptGenRandom failed for IV/salt */
    CRYPTO_ERR_BUFFER_SIZE      = 9,    /**< Buffer too small or too large */
    CRYPTO_ERR_NOT_INITIALIZED  = 10,   /**< InitCrypto*() has not been called */
    CRYPTO_ERR_MAC_MISMATCH     = 11,   /**< HMAC mismatch — data tampered or corrupt */
    CRYPTO_ERR_HMAC_COMPUTE     = 12,   /**< HMAC computation failed during encrypt */
    CRYPTO_ERR_INVALID_MAC      = 13,   /**< Supplied MAC has wrong length */
    CRYPTO_ERR_CONTEXT_LOCKED   = 14,   /**< Context already locked by another thread */
} CRYPTO_ERROR;

/* ============================================================
 * STRUCTURES
 * ============================================================ */

/**
 * CRYPTO_CTX - Cryptographic context.
 *
 * Treat this as opaque.  Obtain the global instance via GetCryptoCtx().
 * Do NOT copy, free, or modify fields directly.
 */
typedef struct {
    HCRYPTPROV      hProv;              /**< CryptoAPI provider handle           */
    HCRYPTKEY       hKey;               /**< AES-256 encryption key handle       */
    HCRYPTKEY       hHmacKey;           /**< HMAC-SHA256 key handle              */
    HCRYPTHASH      hHmac;              /**< Reusable HMAC hash object (internal)*/
    CRITICAL_SECTION csLock;           /**< Per-context critical section        */
    bool            locked;             /**< TRUE while a crypto op is running   */
    bool            initialized;        /**< TRUE after successful Init call      */
    BYTE            salt[SALT_SIZE];    /**< Salt used for key derivation        */
    FILETIME        keyCreationTime;    /**< Timestamp of last key (rotation)    */
    DWORD           keyRotationCounter; /**< Incremented on every RotateKey call */
} CRYPTO_CTX;

/**
 * CRYPTO_STATS - Operational statistics (optional, for auditing).
 *
 * Populate via GetCryptoStats().  A non-zero tamperDetections field
 * indicates HMAC failures and possible active attacks; investigate.
 */
typedef struct {
    DWORD encryptCount;         /**< Total EncryptBuffer() calls that succeeded */
    DWORD decryptCount;         /**< Total DecryptBuffer() calls that succeeded */
    DWORD tamperDetections;     /**< CRYPTO_ERR_MAC_MISMATCH occurrences        */
    DWORD keyRotations;         /**< RotateKey / RotateKeyWithNewKey calls      */
    ULONGLONG encryptBytes;     /**< Cumulative plaintext bytes encrypted       */
    ULONGLONG decryptBytes;     /**< Cumulative plaintext bytes decrypted       */
} CRYPTO_STATS;

/* ============================================================
 * INITIALISATION / TEARDOWN
 * ============================================================ */

/**
 * InitCrypto - Initialise the global crypto context using a password.
 *
 * Derives two independent 256-bit keys (encryption + HMAC) from
 * @password and a freshly generated random salt.  Must be called once
 * before any other function.  Not thread-safe — call from a single
 * thread before spawning workers.
 *
 * @password     NUL-terminated (or binary) password; 1–1024 bytes.
 * @passwordLen  Exact byte length of @password (excluding any NUL).
 *
 * @return CRYPTO_SUCCESS, or:
 *         CRYPTO_ERR_INVALID_PARAM   — NULL / empty / too-long password
 *         CRYPTO_ERR_CRYPTO_INIT     — CryptAcquireContext failed
 *         CRYPTO_ERR_IV_GEN          — salt generation failed
 *         CRYPTO_ERR_KEY_GEN         — key derivation / import failed
 *
 * Example:
 *   const char *pw = "hunter2";
 *   if (InitCrypto(pw, strlen(pw)) != CRYPTO_SUCCESS) { ... }
 */
CRYPTO_ERROR InitCrypto(const char *password, size_t passwordLen);

/**
 * InitCryptoWithKey - Initialise the global crypto context using raw key material.
 *
 * Imports @key directly as the AES-256 encryption key.  Derives the
 * HMAC key by XOR-ing each byte with 0xAA (simple but NOT recommended
 * for high-security use — prefer InitCrypto() with a strong password
 * and proper PBKDF2).
 *
 * @key     32-byte (256-bit) raw key; must NOT be a low-entropy value.
 * @keyLen  Must equal AES_KEY_SIZE_256 (32).
 *
 * @return CRYPTO_SUCCESS, or:
 *         CRYPTO_ERR_INVALID_PARAM   — NULL key or wrong length
 *         CRYPTO_ERR_CRYPTO_INIT     — CryptAcquireContext failed
 *         CRYPTO_ERR_IV_GEN          — salt generation failed
 *         CRYPTO_ERR_KEY_GEN         — key import failed
 *         CRYPTO_ERR_MEMORY_ALLOC    — out of memory
 *
 * Example:
 *   BYTE key[AES_KEY_SIZE_256] = { ... };   // from a KMS / HSM
 *   if (InitCryptoWithKey(key, sizeof(key)) != CRYPTO_SUCCESS) { ... }
 */
CRYPTO_ERROR InitCryptoWithKey(const BYTE *key, size_t keyLen);

/**
 * CleanupCrypto - Destroy all cryptographic resources.
 *
 * Securely zeroes key material, releases CryptoAPI handles, and deletes
 * the critical section.  After this call InitCrypto*() must be called
 * again before further use.  Safe to call on an uninitialised context.
 *
 * Example:
 *   atexit(CleanupCrypto);
 */
void CleanupCrypto(void);

/* ============================================================
 * CONTEXT ACCESSORS
 * ============================================================ */

/**
 * GetCryptoCtx - Return a pointer to the global CRYPTO_CTX.
 *
 * The returned pointer is valid until CleanupCrypto() is called.
 * Never free it directly.
 *
 * @return Pointer to the global CRYPTO_CTX (never NULL).
 *
 * Example:
 *   CRYPTO_CTX *ctx = GetCryptoCtx();
 */
CRYPTO_CTX *GetCryptoCtx(void);

/**
 * VerifyContext - Assert the global context is ready for use.
 *
 * Checks that InitCrypto*() succeeded and all required handles are valid.
 * Prefer calling this at function entry rather than inspecting the struct
 * directly.
 *
 * @return CRYPTO_SUCCESS or CRYPTO_ERR_NOT_INITIALIZED / CRYPTO_ERR_CRYPTO_INIT.
 */
CRYPTO_ERROR VerifyContext(void);

/**
 * IsCryptoInitialized - Quick initialisation check.
 *
 * @return TRUE if the context is ready; FALSE otherwise.
 *
 * Example:
 *   if (!IsCryptoInitialized()) { InitCrypto(...); }
 */
BOOL IsCryptoInitialized(void);

/* ============================================================
 * LOCKING (internal — exposed for advanced use)
 * ============================================================ */

/**
 * LockContext / UnlockContext - Acquire / release the context lock.
 *
 * EncryptBuffer and DecryptBuffer call these internally.  You should
 * only call them directly if you are building higher-level primitives
 * that must hold the lock across multiple operations.
 *
 * @return CRYPTO_SUCCESS, CRYPTO_ERR_NOT_INITIALIZED, or
 *         CRYPTO_ERR_CONTEXT_LOCKED / CRYPTO_ERR_CRYPTO_INIT.
 *
 * WARNING: LockContext() has a known TOCTOU race on the `locked` flag.
 *          The underlying CRITICAL_SECTION still provides mutual
 *          exclusion; the flag is advisory only.
 */
CRYPTO_ERROR LockContext(void);
CRYPTO_ERROR UnlockContext(void);

/* ============================================================
 * ENCRYPTION / DECRYPTION
 * ============================================================ */

/**
 * EncryptBuffer - Encrypt plaintext with AES-256-CBC and authenticate with HMAC-SHA256.
 *
 * Wire format written to @ciphertext:
 *   [ Salt(16) | IV(16) | HMAC-SHA256(32) | Ciphertext(plaintextLen rounded up to 16) ]
 *
 * The HMAC covers the Salt, IV, and Ciphertext fields (encrypt-then-MAC).
 *
 * @ctx           Pointer to an initialised CRYPTO_CTX (from GetCryptoCtx()).
 * @plaintext     Input data to encrypt.
 * @plaintextLen  Length of @plaintext in bytes. Must be >= MIN_BUFFER_SIZE
 *                and <= MAX_BUFFER_SIZE.
 * @ciphertext    Output buffer.  Must not overlap with @plaintext.
 * @ciphertextLen On return: total bytes written to @ciphertext.
 * @capacity      Size of @ciphertext in bytes.
 *                Must be >= plaintextLen + ENCRYPT_OVERHEAD + AES_BLOCK_SIZE.
 *
 * @return CRYPTO_SUCCESS, or:
 *         CRYPTO_ERR_INVALID_PARAM   — any pointer is NULL
 *         CRYPTO_ERR_BUFFER_SIZE     — @plaintextLen or @capacity out of range
 *         CRYPTO_ERR_NOT_INITIALIZED — InitCrypto*() not called
 *         CRYPTO_ERR_CONTEXT_LOCKED  — context busy (concurrent call)
 *         CRYPTO_ERR_IV_GEN          — IV generation failed
 *         CRYPTO_ERR_KEY_GEN         — CryptDuplicateKey failed
 *         CRYPTO_ERR_ENCRYPT         — CryptEncrypt failed
 *         CRYPTO_ERR_HMAC_COMPUTE    — HMAC computation failed
 *
 * Example:
 *   BYTE plain[] = "Hello, world!";
 *   DWORD plainLen = (DWORD)strlen((char*)plain);
 *   DWORD outLen = 0;
 *   DWORD cap = plainLen + ENCRYPT_OVERHEAD + AES_BLOCK_SIZE;
 *   BYTE *out = malloc(cap);
 *
 *   CRYPTO_CTX *ctx = GetCryptoCtx();
 *   if (EncryptBuffer(ctx, plain, plainLen, out, &outLen, cap) != CRYPTO_SUCCESS) { ... }
 */
CRYPTO_ERROR EncryptBuffer(CRYPTO_CTX *ctx,
                            const BYTE  *plaintext,
                            DWORD        plaintextLen,
                            BYTE        *ciphertext,
                            DWORD       *ciphertextLen,
                            DWORD        capacity);

/**
 * DecryptBuffer - Verify HMAC and decrypt an EncryptBuffer() output.
 *
 * The HMAC is verified BEFORE decryption (decrypt-after-verify).
 * If CRYPTO_ERR_MAC_MISMATCH is returned, the output buffer contents
 * are zeroed and MUST NOT be trusted.
 *
 * @ctx           Pointer to an initialised CRYPTO_CTX.
 * @ciphertext    Buffer produced by EncryptBuffer().
 * @ciphertextLen Total byte length of @ciphertext (including headers).
 *                Must be >= ENCRYPT_OVERHEAD + AES_BLOCK_SIZE.
 * @plaintext     Output buffer for decrypted data.
 * @plaintextLen  On return: number of plaintext bytes written.
 * @capacity      Size of @plaintext in bytes.
 *                Must be >= ciphertextLen - ENCRYPT_OVERHEAD.
 *
 * @return CRYPTO_SUCCESS, or:
 *         CRYPTO_ERR_INVALID_PARAM   — any pointer is NULL
 *         CRYPTO_ERR_BUFFER_SIZE     — length out of valid range
 *         CRYPTO_ERR_NOT_INITIALIZED — InitCrypto*() not called
 *         CRYPTO_ERR_CONTEXT_LOCKED  — context busy
 *         CRYPTO_ERR_INVALID_MAC     — supplied MAC has wrong length
 *         CRYPTO_ERR_MAC_MISMATCH    — HMAC failed: DATA IS TAMPERED/CORRUPT
 *         CRYPTO_ERR_KEY_GEN         — CryptDuplicateKey failed
 *         CRYPTO_ERR_DECRYPT         — CryptDecrypt failed
 *
 * Security note:
 *   Always check the return value.  A CRYPTO_ERR_MAC_MISMATCH result
 *   means the ciphertext was modified; log it and treat as an attack.
 *
 * Example:
 *   DWORD plainLen = 0;
 *   BYTE plain[256] = {0};
 *   CRYPTO_ERROR err = DecryptBuffer(ctx, cipher, cipherLen,
 *                                    plain, &plainLen, sizeof(plain));
 *   if (err == CRYPTO_ERR_MAC_MISMATCH) {
 *       LogSecurityEvent("HMAC failure — possible tampering");
 *   } else if (err == CRYPTO_SUCCESS) {
 *       ProcessData(plain, plainLen);
 *   }
 */
CRYPTO_ERROR DecryptBuffer(CRYPTO_CTX *ctx,
                            const BYTE  *ciphertext,
                            DWORD        ciphertextLen,
                            BYTE        *plaintext,
                            DWORD       *plaintextLen,
                            DWORD        capacity);

/* ============================================================
 * KEY ROTATION
 * ============================================================ */

/**
 * RotateKey - Re-derive encryption and HMAC keys from a new password.
 *
 * Generates a fresh salt, derives new keys, and destroys the old keys.
 * Any ciphertext encrypted with the old keys will no longer be
 * decryptable after this call — re-encrypt data before rotating if
 * continued access is needed.
 *
 * @password     New password; 1–1024 bytes.
 * @passwordLen  Byte length of @password.
 *
 * @return CRYPTO_SUCCESS, or:
 *         CRYPTO_ERR_INVALID_PARAM   — bad password
 *         CRYPTO_ERR_NOT_INITIALIZED — context not ready
 *         CRYPTO_ERR_CONTEXT_LOCKED  — concurrent operation in progress
 *         CRYPTO_ERR_IV_GEN          — salt generation failed
 *         CRYPTO_ERR_KEY_GEN         — key derivation failed
 */
CRYPTO_ERROR RotateKey(const char *password, size_t passwordLen);

/**
 * RotateKeyWithNewKey - Replace keys with raw 256-bit key material.
 *
 * Same caveats as RotateKey() — existing ciphertext becomes inaccessible.
 * The HMAC key is derived by XOR-ing each byte of @newKey with 0xAA
 * (same weakness as InitCryptoWithKey — prefer RotateKey() for
 * password-based rotation).
 *
 * @newKey    32-byte raw key.
 * @newKeyLen Must equal AES_KEY_SIZE_256 (32).
 *
 * @return CRYPTO_SUCCESS, or same error codes as RotateKey().
 */
CRYPTO_ERROR RotateKeyWithNewKey(const BYTE *newKey, size_t newKeyLen);

/* ============================================================
 * UTILITIES
 * ============================================================ */

/**
 * GetErrorString - Convert a CRYPTO_ERROR code to a human-readable string.
 *
 * The returned pointer refers to a static string; do not free it.
 *
 * @error  Any CRYPTO_ERROR value.
 * @return Pointer to a NUL-terminated description string.
 *
 * Example:
 *   CRYPTO_ERROR err = EncryptBuffer(...);
 *   if (err != CRYPTO_SUCCESS)
 *       fprintf(stderr, "crypto error: %s\n", GetErrorString(err));
 */
const char *GetErrorString(CRYPTO_ERROR error);

/**
 * GetCryptoStats - Copy current operational statistics.
 *
 * @stats  Pointer to a caller-allocated CRYPTO_STATS to fill.
 *
 * @return CRYPTO_SUCCESS or CRYPTO_ERR_INVALID_PARAM (NULL @stats).
 *
 * Example:
 *   CRYPTO_STATS s;
 *   GetCryptoStats(&s);
 *   if (s.tamperDetections > 0)
 *       AlertSecurityTeam();
 */
CRYPTO_ERROR GetCryptoStats(CRYPTO_STATS *stats);

/**
 * ResetCryptoStats - Zero all statistics counters.
 */
void ResetCryptoStats(void);

/* ============================================================
 * CONVENIENCE MACROS
 * ============================================================ */

/**
 * CRYPTO_REQUIRED_CAPACITY(plainLen)
 *
 * Compute the minimum output buffer size needed to encrypt @plainLen bytes.
 * Add AES_BLOCK_SIZE as extra headroom for PKCS#7 padding.
 *
 * Usage:
 *   DWORD cap = CRYPTO_REQUIRED_CAPACITY(plaintextLen);
 *   BYTE *out = malloc(cap);
 */
#define CRYPTO_REQUIRED_CAPACITY(plainLen) \
    ((DWORD)(plainLen) + ENCRYPT_OVERHEAD + AES_BLOCK_SIZE)

/**
 * CRYPTO_CHECK(expr)
 *
 * Evaluate @expr (a CRYPTO_ERROR-returning call) and return the error
 * immediately if it is not CRYPTO_SUCCESS.  Useful for chaining calls.
 *
 * Usage:
 *   CRYPTO_CHECK(InitCrypto(pw, pwLen));
 *   CRYPTO_CHECK(EncryptBuffer(ctx, plain, plainLen, out, &outLen, cap));
 */
#define CRYPTO_CHECK(expr)                      \
    do {                                        \
        CRYPTO_ERROR _err = (expr);             \
        if (_err != CRYPTO_SUCCESS) return _err;\
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
