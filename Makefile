# Makefile for SOCKS5 Server
# Supports MinGW64/MSYS2 and Linux/Unix environments
# Static linking: libssh2 with mbedtls backend

# Project configuration
TARGET = socks5server
SRCS = main_socks5.c xpoll.c socks5_server.c ssh_tunnel.c xargs.c
HEADERS = socket_util.h socks5_server.h ssh_tunnel.h xargs.h

# mbedtls source files
MBEDTLS_DIR = mbedtls
MBEDTLS_INC = -I$(MBEDTLS_DIR)/include
MBEDTLS_SRCS = $(wildcard $(MBEDTLS_DIR)/library/*.c)
MBEDTLS_OBJS = $(addprefix $(BUILD_DIR)/mbedtls/library/, $(notdir $(MBEDTLS_SRCS:.c=.o)))

# libssh2 source files (with mbedtls backend)
LIBSSH2_DIR = libssh2
LIBSSH2_INC = -I$(LIBSSH2_DIR)/include
LIBSSH2_SRCS = $(LIBSSH2_DIR)/src/agent.c \
               $(LIBSSH2_DIR)/src/bcrypt_pbkdf.c \
               $(LIBSSH2_DIR)/src/blowfish.c \
               $(LIBSSH2_DIR)/src/chacha.c \
               $(LIBSSH2_DIR)/src/channel.c \
               $(LIBSSH2_DIR)/src/cipher-chachapoly.c \
               $(LIBSSH2_DIR)/src/comp.c \
               $(LIBSSH2_DIR)/src/crypt.c \
               $(LIBSSH2_DIR)/src/global.c \
               $(LIBSSH2_DIR)/src/hostkey.c \
               $(LIBSSH2_DIR)/src/keepalive.c \
               $(LIBSSH2_DIR)/src/kex.c \
               $(LIBSSH2_DIR)/src/knownhost.c \
               $(LIBSSH2_DIR)/src/mac.c \
               $(LIBSSH2_DIR)/src/mbedtls.c \
               $(LIBSSH2_DIR)/src/misc.c \
               $(LIBSSH2_DIR)/src/packet.c \
               $(LIBSSH2_DIR)/src/pem.c \
               $(LIBSSH2_DIR)/src/poly1305.c \
               $(LIBSSH2_DIR)/src/publickey.c \
               $(LIBSSH2_DIR)/src/scp.c \
               $(LIBSSH2_DIR)/src/session.c \
               $(LIBSSH2_DIR)/src/sftp.c \
               $(LIBSSH2_DIR)/src/transport.c \
               $(LIBSSH2_DIR)/src/userauth.c \
               $(LIBSSH2_DIR)/src/userauth_kbd_packet.c \
               $(LIBSSH2_DIR)/src/version.c
LIBSSH2_OBJS = $(addprefix $(BUILD_DIR)/libssh2/src/, $(notdir $(LIBSSH2_SRCS:.c=.o)))

# Environment detection
MINGW64 = $(shell uname -s 2>/dev/null | grep -c MINGW64)

ifeq ($(MINGW64),1)
    # MinGW64 configuration
    CC = gcc
    CFLAGS = -O2 -std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 \
            -Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces -Wno-pointer-sign \
            -s -flto -ffunction-sections -fdata-sections \
            $(MBEDTLS_INC) $(LIBSSH2_INC) \
            -DLIBSSH2_MBEDTLS -DLIBSSH2_STATIC
    LDFLAGS = -Wl,--gc-sections -Wl,--strip-all
    LIBS = -lws2_32 -lcrypt32 -lbcrypt
    TARGET_EXT = .exe
    RM = rm -f
    MKDIR = mkdir -p
    OBJ_EXT = .o
else
    # Linux/Unix configuration
    CC = gcc
    CFLAGS = -O2 -std=c11 -pthread \
            $(MBEDTLS_INC) $(LIBSSH2_INC) \
            -DLIBSSH2_MBEDTLS -DLIBSSH2_STATIC
    LDFLAGS =
    LIBS = -lpthread
    TARGET_EXT =
    RM = rm -f
    MKDIR = mkdir -p
    OBJ_EXT = .o
endif

# Build directories
BUILD_DIR = build
OBJ_FILES = $(addprefix $(BUILD_DIR)/, $(SRCS:.c=$(OBJ_EXT)))

# Default target
all: $(TARGET)$(TARGET_EXT)

# Create build directory and subdirectories
$(BUILD_DIR):
	$(MKDIR) $(BUILD_DIR)
	$(MKDIR) $(BUILD_DIR)/mbedtls/library
	$(MKDIR) $(BUILD_DIR)/libssh2/src

# Compile mbedtls source files
$(BUILD_DIR)/mbedtls/library/%.o: $(MBEDTLS_DIR)/library/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile libssh2 source files
$(BUILD_DIR)/libssh2/src/%.o: $(LIBSSH2_DIR)/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile project source files
$(BUILD_DIR)/%$(OBJ_EXT): %.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link final target with static static libraries
$(TARGET)$(TARGET_EXT): $(OBJ_FILES) $(MBEDTLS_OBJS) $(LIBSSH2_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(RM) -r $(BUILD_DIR)

# Clean build artifacts
clean:
	$(RM) $(TARGET)$(TARGET_EXT)
	$(RM) -r $(BUILD_DIR)

# Install target (optional)
install: $(TARGET)$(TARGET_EXT)
ifeq ($(MINGW64),1)
	@echo "On MinGW64, copy $(TARGET)$(TARGET_EXT) manually to desired location"
else
	cp $(TARGET)$(TARGET_EXT) /usr/local/bin/
endif

# Uninstall target (optional)
uninstall:
ifeq ($(MINGW64),1)
	@echo "On MinGW64, remove $(TARGET)$(TARGET_EXT) manually from installed location"
else
	$(RM) /usr/local/bin/$(TARGET)$(TARGET_EXT)
endif

# Debug build
debug:
	$(MAKE) CFLAGS="-std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 \
		-Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces -Wno-pointer-sign \
		-ffunction-sections -fdata-sections \
		-Imbedtls/include -Ilibssh2/include \
		-DLIBSSH2_MBEDTLS -DLIBSSH2_STATIC \
		-DDEBUG -g -O0" \
	LDFLAGS="-Wl,--gc-sections -lunwind" \
	clean all

# Release build with maximum optimization
release: CFLAGS += -O3 -DNDEBUG
release: all

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build socks5server with static libssh2/mbedtls (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build with maximum optimization"
	@echo "  install  - Install the binary"
	@echo "  uninstall- Remove the installed binary"
	@echo "  help     - Show this help message"

# Phony targets
.PHONY: all clean install uninstall debug release help

# Dependencies
main_socks5.o: socket_util.h socks5_server.h xargs.h xpoll.h
socks5_server.o: socket_util.h socks5_server.h
ssh_tunnel.o: socket_util.h ssh_tunnel.h
xpoll.o: socket_util.h xpoll.h
