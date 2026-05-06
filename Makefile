# Cross-compiler
CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -s -Wall -fno-stack-protector -fvisibility=hidden
LIBS    = -ladvapi32 -luser32 -lshell32 -lshlwapi -lntdll -lws2_32 -liphlpapi

# Folder
BUILD_DIR = build

SRCS    = misery.c crypto.c fileops.c defense.c security.c persistence.c utils.c
OBJS    = $(SRCS:.c=.o)

# Update TARGET to include the build folder
TARGET  = $(BUILD_DIR)/misery.exe

all: $(TARGET)

# Rule to link the executable
$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

# Rule to compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to create the build directory
$(BUILD_DIR):
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"

clean:
	@echo Cleaning project...
	-@del /f /q *.o 2>nul
	-@if exist "$(BUILD_DIR)" rd /s /q "$(BUILD_DIR)" 2>nul
	@echo Project cleaned.

.PHONY: all clean