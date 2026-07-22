# Makefile


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




# Cross-compiler: x86_64-w64-mingw32-gcc

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Os -s -Wall -Wextra -fno-stack-protector -fvisibility=hidden -masm=intel
LIBS    = -ladvapi32 -luser32 -lshell32 -lshlwapi -lntdll -lws2_32 -liphlpapi -lole32 -luuid -lbcrypt -lgdi32 -lcomctl32

BUILD_DIR = build

SRCS    = misery.c misery_config.c crypto.c fileops.c defense.c security.c persistence.c utils.c ransomnote.c
OBJS    = $(SRCS:.c=.o)
HEADERS = misery_config.h crypto.h fileops.h defense.h security.h persistence.h utils.h ransomnote.h

TARGET  = $(BUILD_DIR)/misery.exe

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)
	@echo ""
	@echo "[+] Build successful: $(TARGET)"
	@echo "[+] Size: $$(ls -lh $(TARGET) | awk '{print $$5}')"
	@echo ""

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p "$(BUILD_DIR)"

clean:
	@echo "Cleaning project..."
	@rm -f *.o
	@rm -rf "$(BUILD_DIR)"
	@echo "Project cleaned."

.PHONY: all clean