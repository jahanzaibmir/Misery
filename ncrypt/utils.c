
#include "../crypto.h"
#include <string.h>

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    if (!bytes || !out) return; 
    static const char hexdig[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hexdig[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexdig[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, size_t hexLen, unsigned char *out, size_t outLen) {
    if (!hex || !out) return 0;
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