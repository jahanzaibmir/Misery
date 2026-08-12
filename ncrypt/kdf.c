
// kdf.c 

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

CRYPTO_ERROR NcryptDeriveKeys(HCRYPTPROV hProv,
                              const BYTE *inputKey, DWORD inputLen,
                              const BYTE *salt,
                              HCRYPTKEY *hKey, HCRYPTKEY *hMacKey)
{
    HCRYPTHASH hHash = 0;
    BYTE aesKey[AES_KEY_SIZE_256];
    BYTE hmacKey[AES_KEY_SIZE_256];
    DWORD klen = AES_KEY_SIZE_256;
    CRYPTO_ERROR err = CRYPTO_SUCCESS;

    if (!inputKey) return CRYPTO_ERR_INVALID_PARAM;

    const char aesCtx[]  = "misery-aes-key";
    const char hmacCtx[] = "misery-hmac-key";

    //Derive AES-256 key
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    // Check all CryptHashData return values to prevent silent key corruption
    if (!CryptHashData(hHash, (BYTE*)aesCtx, (DWORD)strlen(aesCtx), 0) ||
        !CryptHashData(hHash, inputKey, inputLen, 0) ||
        !CryptHashData(hHash, salt, SALT_SIZE, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, aesKey, &klen, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptDestroyHash(hHash); hHash = 0;

    //Derive HMAC-SHA256 key
    klen = AES_KEY_SIZE_256;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    if (!CryptHashData(hHash, (BYTE*)hmacCtx, (DWORD)strlen(hmacCtx), 0) ||
        !CryptHashData(hHash, inputKey, inputLen, 0) ||
        !CryptHashData(hHash, salt, SALT_SIZE, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hmacKey, &klen, 0)) {
        CryptDestroyHash(hHash); hHash = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }
    CryptDestroyHash(hHash); hHash = 0;

    //Import AES key into CryptoAPI
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

    /* Import HMAC key */
    memcpy(blob.key, hmacKey, AES_KEY_SIZE_256);
    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, hMacKey)) {
        CryptDestroyKey(*hKey); *hKey = 0;
        err = CRYPTO_ERR_KEY_GEN; goto cleanup;
    }

cleanup:
    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(hmacKey, sizeof(hmacKey));
    SecureZeroMemory(&blob, sizeof(blob)); 
    if (hHash) CryptDestroyHash(hHash);
    return err;
}
