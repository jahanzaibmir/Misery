
#ifndef NCRYPT_INTERNAL_H
#define NCRYPT_INTERNAL_H

#include "../crypto.h"

// Global state defined in context.c
extern CRYPTO_CTX g_nctx;
extern bool g_ninitialized;
extern bool g_ncs_initialized;

// Internal KDF function defined in kdf.c
CRYPTO_ERROR NcryptDeriveKeys(HCRYPTPROV hProv,
                              const BYTE *inputKey, DWORD inputLen,
                              const BYTE *salt,
                              HCRYPTKEY *hKey, HCRYPTKEY *hMacKey);

#endif // NCRYPT_INTERNAL_H