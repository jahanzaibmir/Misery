# Misery
Misery is a modular Windows-based research project designed to simulate a high-speed ransomware infection by blending sophisticated evasion techniques with professional-grade encryption. Utilizing multi-threaded AES-256-CBC encryption to rapidly lock files while simultaneously blinding OS security features like AMSI and ETW to remain undetected. By systematically destroying backup shadows, elevating its own privileges, and establishing multi-layered persistence through registry hijacks and accessibility backdoors, Misery demonstrates how a modern payload can weaponize legitimate Windows internals to achieve total system dominance before self-deleting to frustrate forensic recovery.

### Requirement

gcc

# Compilation

git clone https://github.com/jahanzaibmir/Misery

cd Misery

make 


# About Author

Written by JAHANZAIB ASHRAF MIR
from Scratch 

#### IGNORE

install choco for gcc: Set-ExecutionPolicy Bypass -Scope Process -Force; `
[System.Net.ServicePointManager]::SecurityProtocol = 3072; `
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

install gcc: choco install mingw -y
