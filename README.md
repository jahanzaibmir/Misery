# Misery
Misery is a windows malware/future Ransomware

# Requirement

gcc

TO install gcc on windows system: Use MSYS MINGW64 SHELL and type pacman -S mingw-w64-x86_64-gcc

then add gcc to the path in powershell

# Compilation

git clone https://github.com/jahanzaibmir/Misery

cd Misery

make 


# About Author

Written by JAHANZAIB ASHRAF MIR
from Scratch 

## IGNORE

install choco for gcc: Set-ExecutionPolicy Bypass -Scope Process -Force; `
[System.Net.ServicePointManager]::SecurityProtocol = 3072; `
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

install gcc: choco install mingw -y
