
// utils.c

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
    // FIX: Thread-Local Storage prevents race conditions when multiple threads log errors simultaneously
    __declspec(thread) static const char *err[] = {
        "Success","Invalid parameter","Memory alloc fail","Crypto init fail",
        "Key gen fail","Encryption fail","Decryption fail","MAC verify fail",
        "IV generation fail","Buffer size invalid","Not initialized",
        "MAC mismatch","HMAC computation fail","Invalid MAC length",
        "Context locked"
    };
    if (error <= CRYPTO_ERR_CONTEXT_LOCKED) return err[error];
    return "Unknown";
}
