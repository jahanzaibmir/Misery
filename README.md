# Misery
Misery is a windows malware/future Ransomware

# Requirement

gcc

TO install gcc on windows system: Use MSYS MINGW64 SHELL and type pacman -S mingw-w64-x86_64-gcc

then add gcc to the path in powershell

# Compilation

git clone https://github.com/jahanzaibmir/Misery

cd Misery

x86_64-w64-mingw32-gcc -o misery.exe misery.c -lcrypt32 -ladvapi32 -lshlwapi -O2 -s -Os -mwindows


# About Author

Written by JAHANZAIB ASHRAF MIR
from Scratch 
