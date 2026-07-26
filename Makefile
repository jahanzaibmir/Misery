# Makefile
#
# Misery is an educational project to demonstrate how Ransomware behaves
# Use in controlled environment, otherwise it may harm
# This project is created strictly for educational and research purposes
# Author & Contact: Jahanzaib Ashraf Mir
# Github: @jahanzaibmir
# Instagram: @jahanzaibmir
# LinkedIn: @jahanzaibmir

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

# Root source files (in project root)
SRCS_ROOT   = misery.c misery_config.c crypto.c fileops.c defense.c security.c persistence.c utils.c

# GUI source files (in gui/ subfolder)
SRCS_GUI    = gui/gui_main.c gui/gui_resources.c gui/gui_window.c gui/gui_decrypt.c gui/gui_controls.c gui/gui_utils.c

# All source files
ALL_SRCS    = $(SRCS_ROOT) $(SRCS_GUI)
ALL_OBJS    = $(ALL_SRCS:.c=.o)
ALL_HEADERS = misery_config.h crypto.h fileops.h defense.h security.h persistence.h utils.h ransomnote.h \
              gui/gui_types.h gui/gui_resources.h gui/gui_window.h gui/gui_decrypt.h gui/gui_controls.h gui/gui_utils.h gui/gui_main.h

TARGET      = $(BUILD_DIR)/misery.exe

all: $(TARGET)

$(TARGET): $(ALL_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(ALL_OBJS) $(LIBS)
	@echo.
	@echo [+] Build successful: $(TARGET)
	@for %%I in ($(TARGET)) do @set /a _sz=%%~zI/1024 & call echo [+] Size: %%_sz%% KB
	@echo.

%.o: %.c $(ALL_HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir "$(BUILD_DIR)"

clean:
	@echo Cleaning project...
	@-del /f /q *.o 2>nul
	@-del /f /q gui\*.o 2>nul
	@-rmdir /s /q "$(BUILD_DIR)" 2>nul
	@echo Project cleaned.

.PHONY: all clean
