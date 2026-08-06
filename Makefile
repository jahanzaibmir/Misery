.RECIPEPREFIX = >

#Author: Jahanzaib Ashraf Mir
#Kashmir
#CSE GRAD W/S in Cybersecurity
#Malware Researcher | Cybersecurity Engineer | Hacker
#Copyright © 2026. All Rights Reserved.

#This educational script and software is designed
#strictly for academic research and defensive analysis.
#No part of this script may be reproduced, published, distributed, modified,
#sold, rebranded, or executed on any unauthorized systems, networks, or servers,
#by any means or in any form, without prior written permission of the copyright owner.

#Unauthorized use, deployment, or duplication is strictly prohibited and may result
#in severe legal action under applicable copyright and computer crime statutes.

#THIS SOFTWARE IS PROVIDED "AS IS" FOR EDUCATIONAL PURPOSES ONLY.
#The author assumes zero liability and no responsibility for any misuse, damage,
#data loss, or illegal activity resulting from the execution of this code.
#Execution against non-consenting target systems is strictly illegal.

# Makefile
#
# Misery is an educational project to demonstrate how Ransomware behaves
# Use in controlled environment, otherwise it may harm
# This project is created strictly for educational and research purposes

# DISCLAIMER & WARNING
# This PROJECT is part of an academic research intended solely for
# studying cyber threat behavior in controlled, isolated lab environments.
# Unauthorized deployment on production systems or without explicit permission
# is strictly prohibited and illegal under applicable cybercrime laws.

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -s -Wall -Wextra -fno-stack-protector -fvisibility=hidden -masm=intel -I.
LIBS    = -ladvapi32 -luser32 -lshell32 -lshlwapi -lntdll -lws2_32 -liphlpapi -lole32 -luuid -lbcrypt -lgdi32 -lcomctl32
SHELL   = cmd.exe
BUILD_DIR = build

# Root source files 
SRCS_ROOT   = misery.c misery_config.c defense.c security.c persistence.c utils.c

# NCrypt files
SRCS_NCRYPT = ncrypt/context.c ncrypt/kdf.c ncrypt/cipher.c ncrypt/utils.c

# fops files
SRCS_FOPS   = fops/api.c fops/queue.c fops/worker.c fops/traverse.c fops/fileio.c fops/config.c

# gui files
SRCS_GUI    = gui/gui_main.c gui/gui_resources.c gui/gui_window.c gui/gui_decrypt.c gui/gui_controls.c gui/gui_utils.c

# All source files
ALL_SRCS    = $(SRCS_ROOT) $(SRCS_NCRYPT) $(SRCS_FOPS) $(SRCS_GUI)
ALL_OBJS    = $(ALL_SRCS:.c=.o)
ALL_HEADERS = misery_config.h crypto.h fileops.h defense.h security.h persistence.h utils.h ransomnote.h \
              gui/gui_types.h gui/gui_resources.h gui/gui_window.h gui/gui_decrypt.h gui/gui_controls.h gui/gui_utils.h gui/gui_main.h

TARGET      = $(BUILD_DIR)/misery.exe

all: $(TARGET)

 $(TARGET): $(ALL_OBJS) | $(BUILD_DIR)
> $(CC) $(CFLAGS) -o $@ $(ALL_OBJS) $(LIBS)
> @echo.
> @echo Build successful: $(TARGET)
> @for %%I in ($(TARGET)) do @set /a _sz=%%~zI/1024 & call echo [+] Size: %%_sz%% KB
> @echo.

%.o: %.c $(ALL_HEADERS)
> $(CC) $(CFLAGS) -c $< -o $@

 $(BUILD_DIR):
> @mkdir "$(BUILD_DIR)"

clean:
> @echo Cleaning Ransomware
> @if exist *.o del /f /q *.o
> @if exist ncrypt\*.o del /f /q ncrypt\*.o
> @if exist fops\*.o del /f /q fops\*.o
> @if exist gui\*.o del /f /q gui\*.o
> @if exist "$(BUILD_DIR)" rmdir /s /q "$(BUILD_DIR)"
> @echo Ransomware cleaned.

.PHONY: all clean
