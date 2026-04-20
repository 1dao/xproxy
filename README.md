# PROJECT KNOWLEDGE BASE

**Generated:** Thu Feb 26 2026
**Commit:** 7ab36b03
**Branch:** (current)

## OVERVIEW

C-based multi-protocol proxy server supporting SOCKS5, HTTPS proxy, SSH tunneling, and PAC (Proxy Auto-Config). Cross-platform (Windows MinGW64 / Linux/Unix). Uses wolfssl/wolfssh for crypto/SSH.

## STRUCTURE

```
./                          # Source root (flat structure)
├── main.c                  # Entry point, signal handling
├── https_proxy.c/h        # HTTPS CONNECT proxy
├── socks5_server.c/h      # SOCKS5 server (primary)
├── socks5_client.c/h       # SOCKS5 client (outbound)
├── ssh_tunnel.c/h         # SSH port forwarding
├── xpac_server.c/h        # PAC file server
├── xpoll.c/h              # I/O multiplexing (WSAPoll/poll)
├── xargs.c/h              # CLI argument parser
├── xhash.h                # Hash table (auth users)
├── socket_util.h          # Cross-platform socket macros
├── user_settings.h        # Configuration
├── Makefile               # Build (Unix)
├── build.bat              # Build (Windows)
└── 3rd/                  # Submodules (wolfssl, wolfssh)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Build | `Makefile` / `build.bat` | Unix/Windows respectively |
| SOCKS5 server | `socks5_server.c` | Main proxy logic |
| HTTPS proxy | `https_proxy.c` | CONNECT tunnel |
| SSH tunnel | `ssh_tunnel.c` | wolfssh integration |
| PAC server | `xpac_server.c` | WPAD/PAC serving |
| Event loop | `xpoll.c` | Cross-platform poll |
| CLI args | `xargs.c` | Interactive password input |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| main | func | main.c:134 | Entry point |
| g_running | var | main.c:13 | Shutdown flag |
| signal_handler | func | main.c:16 | SIGINT/SIGSEGV |
| get_hidden_input | func | main.c:32 | Password entry |
| socks5_server_init | func | socks5_server.c | Server setup |
| socks5_server_loop | func | socks5_server.c | Event loop |
| https_proxy_handler | func | https_proxy.c | CONNECT handling |
| ssh_tunnel_connect | func | ssh_tunnel.c | SSH session |
| xpoll_init | func | xpoll.c | Poll init |
| xpoll_poll | func | xpoll.c | Event wait |
| xargs_init | func | xargs.c | Arg parsing |

## CONVENTIONS

- **Error handling**: Negative = error, NULL = failure
- **Socket types**: `SOCKET_T` macro (platform-specific)
- **Close**: `CLOSE_SOCKET()` macro
- **Memory**: malloc/free (no GC)
- **Buffers**: Fixed 256-byte typical
- **Globals**: Static vars prefixed `g_`

## ANTI-PATTERNS (THIS PROJECT)

- **Single-threaded**: No concurrency - event loop only
- **Global state**: Heavy use of `static` globals
- **Error paths**: Leaks possible on early returns
- **Fixed buffers**: No dynamic sizing - truncation risk

## UNIQUE STYLES

- **Poll abstraction**: xpoll wraps WSAPoll/poll
- **Submodule deps**: wolfssl, wolfssh via git submodules
- **Static linking**: No runtime lib dependencies
- **Interactive config**: Hidden password input (Windows/Linux)
- **Dual build**: Makefile + build.bat

## COMMANDS

```bash
make              # Release build (Unix)
make debug       # Debug build (Unix)
make clean       # Clean artifacts

build.bat        # Windows build (MSYS2/MinGW)
start.bat        # Windows start proxy
```

## NOTES

- Requires MSYS2/MinGW64 on Windows
- wolfssh + wolfssl backends
- SOCKS5 supports CONNECT only (no BIND/UDP)
- PAC server listens on port 7890 by default
- SOCKS5 Proxy listens on port 1080 by default
- HTTP Proxy listens on port 7890 by default
