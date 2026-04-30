# Makefile for SOCKS5 Proxy Server using libssh2
# All sources compiled from source

CC = gcc
#CFLAGS = -Wall -g3 -O0 -std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 -Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces
CFLAGS = -Wall -Os -std=c11 -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 -Wno-unknown-pragmas -Wno-sign-compare -Wno-missing-braces
CPPFLAGS = -I. -I./3rd/libssh2/include -I./3rd/libssh2/src
UNAME_S := $(shell uname -s 2>/dev/null)
SIZE_CFLAGS = -ffunction-sections -fdata-sections -flto
GNU_SIZE_LDFLAGS = -flto -Wl,--gc-sections -s

# Detect platform and set appropriate flags/libraries
ifeq ($(OS),Windows_NT)
    # Native Windows (cmd.exe)
    CFLAGS += -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 $(SIZE_CFLAGS)
    CPPFLAGS += -DLIBSSH2_WINCNG
    LDFLAGS = $(GNU_SIZE_LDFLAGS) -lws2_32 -lcrypt32 -lbcrypt -ladvapi32
    EXE = xproxy.exe
else ifneq (,$(findstring NT-6,$(UNAME_S)))
    # Windows with NT in the name (includes MinGW, MSYS2, Cygwin)
    CFLAGS += -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 $(SIZE_CFLAGS)
    CPPFLAGS += -DLIBSSH2_WINCNG
    LDFLAGS = $(GNU_SIZE_LDFLAGS) -lws2_32 -lcrypt32 -lbcrypt -ladvapi32
    EXE = xproxy.exe
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    # Explicitly check for MinGW environment
    CFLAGS += -DWIN32_LEAN_AND_MEAN -DWINVER=0x0601 $(SIZE_CFLAGS)
    CPPFLAGS += -DLIBSSH2_WINCNG
    LDFLAGS = $(GNU_SIZE_LDFLAGS) -lws2_32 -lcrypt32 -lbcrypt -ladvapi32
    EXE = xproxy.exe
else ifeq ($(UNAME_S),Darwin)
    # macOS-specific settings
    CFLAGS += $(SIZE_CFLAGS)
    CPPFLAGS += -D_XOPEN_SOURCE -D_DARWIN_UNLIMITED_SELECT -DLIBSSH2_OPENSSL
    LDFLAGS = -flto -Wl,-dead_strip -lcrypto -framework Security -framework CoreFoundation
    EXE = xproxy
else
    # Linux and other Unix-like systems
    CFLAGS += $(SIZE_CFLAGS)
    CPPFLAGS += -DLIBSSH2_OPENSSL
    LDFLAGS = $(GNU_SIZE_LDFLAGS) -lm -lpthread -lcrypto
    EXE = xproxy
endif

# Object directory
OBJDIR = .objs

# Application sources
APP_SOURCES = main.c xpoll.c socks5_server.c ssh_tunnel.c xargs.c https_proxy.c xpac_server.c

# libssh2 sources
LIBSSH2_SOURCES = \
    3rd/libssh2/src/bcrypt_pbkdf.c \
    3rd/libssh2/src/chacha.c \
    3rd/libssh2/src/channel.c \
    3rd/libssh2/src/cipher-chachapoly.c \
    3rd/libssh2/src/comp.c \
    3rd/libssh2/src/crypt.c \
    3rd/libssh2/src/global.c \
    3rd/libssh2/src/hostkey.c \
    3rd/libssh2/src/keepalive.c \
    3rd/libssh2/src/kex.c \
    3rd/libssh2/src/mac.c \
    3rd/libssh2/src/misc.c \
    3rd/libssh2/src/openssl.c \
    3rd/libssh2/src/packet.c \
    3rd/libssh2/src/pem.c \
    3rd/libssh2/src/poly1305.c \
    3rd/libssh2/src/session.c \
    3rd/libssh2/src/transport.c \
    3rd/libssh2/src/userauth.c \
    3rd/libssh2/src/userauth_kbd_packet.c \
    3rd/libssh2/src/wincng.c

    # 3rd/libssh2/src/agent.c       # Pageant/ssh-agent
    # 3rd/libssh2/src/knownhost.c   # known_hosts API
    # 3rd/libssh2/src/libgcrypt.c   # 非当前 crypto backend
    # 3rd/libssh2/src/mbedtls.c     # 非当前 crypto backend
    # 3rd/libssh2/src/openssl.c     # Windows 当前走 WinCNG 时不用
    # 3rd/libssh2/src/os400qc3.c    # IBM i backend
    # 3rd/libssh2/src/publickey.c   # publickey subsystem API
    # 3rd/libssh2/src/scp.c         # SCP API
    # 3rd/libssh2/src/sftp.c        # SFTP API
    # 3rd/libssh2/src/version.c     # libssh2_version()，当前没调用

# Object files (organized into subdirectories)
APP_OBJECTS = $(addprefix $(OBJDIR)/, $(notdir $(APP_SOURCES:.c=.o)))
LIBSSH2_OBJECTS = $(addprefix $(OBJDIR)/libssh2/, $(notdir $(LIBSSH2_SOURCES:.c=.o)))

ALL_OBJECTS = $(APP_OBJECTS) $(LIBSSH2_OBJECTS)

.PHONY: all clean run

all: $(EXE)

# Create required directories
$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/libssh2:
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

# libssh2 sources → build/libssh2/*.o
$(OBJDIR)/libssh2/%.o: 3rd/libssh2/src/%.c | $(OBJDIR)/libssh2
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(EXE)

run: all
	./$(EXE)
