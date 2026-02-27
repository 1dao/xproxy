# Makefile for SOCKS5 Proxy Server using wolfSSH/wolfSSL
# All sources compiled from source

CC = gcc
#CFLAGS = -Wall -g3 -O0 -std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 -Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces
CFLAGS = -Wall -O2 -std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 -Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces
CPPFLAGS = -I. -I./3rd/wolfssl -I./3rd/wolfssl/wolfssl -I./3rd/wolfssh -I./3rd/wolfssh/wolfssh -DWOLFSSL_USER_SETTINGS -DWOLFSSH_USER_SETTINGS -DWOLFSSH_FWD

# Detect platform and set appropriate flags/libraries
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Windows_NT)
    # Windows-specific settings
    CFLAGS += -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601
    LDFLAGS = -lws2_32 -lcrypt32 -lbcrypt -ladvapi32
    EXE = xproxy.exe
else ifeq ($(UNAME_S),Darwin)
    # macOS-specific settings
    CPPFLAGS += -D_XOPEN_SOURCE -D_DARWIN_UNLIMITED_SELECT
    LDFLAGS = -framework Security -framework CoreFoundation
    EXE = xproxy
else
    # Linux and other Unix-like systems
    LDFLAGS = -lm -lpthread
    EXE = xproxy
endif

# Object directory
OBJDIR = .objs

# Application sources
APP_SOURCES = main.c xpoll.c socks5_server.c ssh_tunnel.c xargs.c https_proxy.c xpac_server.c

# wolfCrypt sources (required for SSH crypto)
WOLFCRYPT_SOURCES = \
    3rd/wolfssl/wolfcrypt/src/asn.c \
    3rd/wolfssl/wolfcrypt/src/error.c \
    3rd/wolfssl/wolfcrypt/src/rsa.c \
    3rd/wolfssl/wolfcrypt/src/aes.c \
    3rd/wolfssl/wolfcrypt/src/des3.c \
    3rd/wolfssl/wolfcrypt/src/sha.c \
    3rd/wolfssl/wolfcrypt/src/sha256.c \
    3rd/wolfssl/wolfcrypt/src/sha512.c \
    3rd/wolfssl/wolfcrypt/src/md5.c \
    3rd/wolfssl/wolfcrypt/src/hmac.c \
    3rd/wolfssl/wolfcrypt/src/hash.c \
    3rd/wolfssl/wolfcrypt/src/coding.c \
    3rd/wolfssl/wolfcrypt/src/random.c \
    3rd/wolfssl/wolfcrypt/src/memory.c \
    3rd/wolfssl/wolfcrypt/src/ecc.c \
    3rd/wolfssl/wolfcrypt/src/dh.c \
    3rd/wolfssl/wolfcrypt/src/integer.c \
    3rd/wolfssl/wolfcrypt/src/tfm.c \
    3rd/wolfssl/wolfcrypt/src/wolfmath.c \
    3rd/wolfssl/wolfcrypt/src/signature.c \
    3rd/wolfssl/wolfcrypt/src/logging.c \
    3rd/wolfssl/wolfcrypt/src/sp_int.c \
    3rd/wolfssl/wolfcrypt/src/wc_port.c \
    3rd/wolfssl/wolfcrypt/src/kdf.c \
    3rd/wolfssl/wolfcrypt/src/wc_encrypt.c \
    3rd/wolfssl/wolfcrypt/src/pwdbased.c \
    3rd/wolfssl/wolfcrypt/src/pkcs12.c

# wolfSSH sources
WOLFSSH_SOURCES = \
    3rd/wolfssh/src/ssh.c \
    3rd/wolfssh/src/internal.c \
    3rd/wolfssh/src/io.c \
    3rd/wolfssh/src/keygen.c \
    3rd/wolfssh/src/log.c \
    3rd/wolfssh/src/port.c \
    3rd/wolfssh/src/certman.c \
    3rd/wolfssh/src/agent.c

# Object files (organized into subdirectories)
APP_OBJECTS = $(addprefix $(OBJDIR)/, $(notdir $(APP_SOURCES:.c=.o)))
WOLFCRYPT_OBJECTS = $(addprefix $(OBJDIR)/wolfssl/, $(notdir $(WOLFCRYPT_SOURCES:.c=.o)))
WOLFSSH_OBJECTS = $(addprefix $(OBJDIR)/wolfssh/, $(notdir $(WOLFSSH_SOURCES:.c=.o)))

ALL_OBJECTS = $(APP_OBJECTS) $(WOLFCRYPT_OBJECTS) $(WOLFSSH_OBJECTS)

.PHONY: all clean run

all: $(EXE)

# Create required directories
$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/wolfssl:
	mkdir -p $@

$(OBJDIR)/wolfssh:
	mkdir -p $@

# Link executable (order-only dependency on top-level build dir)
$(EXE): $(ALL_OBJECTS) | $(OBJDIR)
	@echo "Linking $(EXE)..."
	$(CC) $(ALL_OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build completed: $(EXE)"
	rm -rf $(OBJDIR)

# Pattern rules for compiling sources

# Application sources → build/*.o
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# wolfSSL sources → build/wolfssl/*.o
$(OBJDIR)/wolfssl/%.o: 3rd/wolfssl/wolfcrypt/src/%.c | $(OBJDIR)/wolfssl
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# wolfSSH sources → build/wolfssh/*.o
$(OBJDIR)/wolfssh/%.o: 3rd/wolfssh/src/%.c | $(OBJDIR)/wolfssh
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(EXE)

run: all
	./$(EXE)
