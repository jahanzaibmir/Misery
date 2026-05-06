#pragma once
#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#define AES_IV_SIZE      16
#define AES_BLOCK_SIZE   16
#define AES_PAD_HEADROOM (AES_BLOCK_SIZE * 2)

typedef struct {
    HCRYPTPROV hProv;
    HCRYPTKEY  hKey;
} CRYPTO_CTX;

/* Initialize CryptoAPI context — returns 1 on success */
int  InitCrypto(void);

/* Encrypt a buffer in-place. *encLen in/out. IV prepended to buf. */
int  EncryptBuffer(CRYPTO_CTX *ctx, BYTE *iv, BYTE *buf, DWORD *encLen, DWORD bufCap);

/* Free crypto resources */
void CleanupCrypto(void);

/* Access the global crypto context */
CRYPTO_CTX *GetCryptoCtx(void);