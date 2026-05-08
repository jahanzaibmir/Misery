# Makefile - Misery v3 (Advanced Evasion Framework)
# Cross-compiler: x86_64-w64-mingw32-gcc
# Author: Jahanzaib Ashraf Mir

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -s -Wall -fno-stack-protector -fvisibility=hidden -masm=intel
LIBS    = -ladvapi32 -luser32 -lshell32 -lshlwapi -lntdll -lws2_32 -liphlpapi -lole32 -luuid

BUILD_DIR = build

SRCS    = misery.c crypto.c fileops.c defense.c security.c persistence.c utils.c
OBJS    = $(SRCS:.c=.o)

TARGET  = $(BUILD_DIR)/misery.exe

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)
	@echo ""
	@echo "[+] Build successful: $(TARGET)"
	@echo ""

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"

clean:
	@echo Cleaning project...
	-@del /f /q *.o 2>nul
	-@if exist "$(BUILD_DIR)" rd /s /q "$(BUILD_DIR)" 2>nul
	@echo Project cleaned.

.PHONY: all clean
