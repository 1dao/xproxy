# PROJECT KNOWLEDGE BASE

**Generated:** Fri Feb 06 2026
**Commit:** Unknown
**Branch:** Unknown

## OVERVIEW
A SOCKS5 proxy server with SSH tunneling capabilities, implemented in C. Supports both Windows (MinGW64) and Linux/Unix environments with statically linked libssh2 and mbedtls libraries.

## STRUCTURE
```
./
├── libssh2/          # SSH library with mbedtls backend (submodule)
├── mbedtls/          # TLS library (submodule)
├── main_socks5.c     # Main entry point
├── socks5_server.c   # SOCKS5 server implementation
├── socks5_server.h   # SOCKS5 server header
├── ssh_tunnel.c      # SSH tunnel implementation
├── ssh_tunnel.h      # SSH tunnel header
├── xpoll.c           # I/O multiplexing (WSAPoll/poll wrapper)
├── xpoll.h           # I/O multiplexing header
├── xargs.c           # Command-line argument parser
├── xargs.h           # Command-line argument parser header
├── xhash.h           # Hash table implementation
├── socket_util.h     # Socket utilities
└── Makefile          # Build configuration
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Main entry point | main_socks5.c | Handles initialization, configuration, and event loop |
| SOCKS5 protocol | socks5_server.c/h | Handshake, authentication, request handling |
| SSH tunneling | ssh_tunnel.c/h | Session management, channel operations |
| I/O multiplexing | xpoll.c/h | WSAPoll (Windows) / poll (Unix) abstraction |
| Argument parsing | xargs.c/h | Command-line and interactive configuration |
| Hash table | xhash.h | Generic hash table implementation |
| Socket utilities | socket_util.h | Cross-platform socket macros |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| main | Function | main_socks5.c:134 | Entry point |
| socks5_server_init | Function | socks5_server.c:638 | Initialize server |
| socks5_server_handle_client | Function | socks5_server.c:442 | Handle client connections |
| ssh_tunnel_session_open | Function | ssh_tunnel.c:18 | Open SSH session |
| ssh_tunnel_channel_open | Function | ssh_tunnel.c:192 | Open direct-tcpip channel |
| xpoll_create | Function | xpoll.c:54 | Create poll loop |
| xpoll_poll | Function | xpoll.c:312 | Poll for events |
| xargs_init | Function | xargs.c:166 | Initialize argument parser |
| xargs_get | Function | xargs.c:263 | Get argument value |

## CONVENTIONS

- **Error handling**: Negative return values indicate errors, NULL for pointer failures
- **Socket API**: Cross-platform macros (SOCKET_T, CLOSE_SOCKET) in socket_util.h
- **Event callbacks**: xFileProc type for poll event handlers
- **Memory management**: Manual allocation with malloc/free
- **String handling**: Fixed-size buffers (256 bytes typical)

## ANTI-PATTERNS (THIS PROJECT)

- **Global state**: Extensive use of static globals (g_server_config, g_xpoll, g_ssh_session)
- **Error recovery**: Limited error handling, most failures terminate connections
- **Buffer management**: Fixed-size buffers may cause overflow
- **Concurrency**: Single-threaded event loop only
- **Memory leaks**: Potential leaks in error paths (e.g., socks5_handle_client_single)

## UNIQUE STYLES

- **Poll abstraction**: xpoll wrapper for WSAPoll/poll compatibility
- **SSH integration**: libssh2 with mbedtls backend, static linking
- **Interactive config**: get_hidden_input for password entry
- **Signal handling**: Interrupt and segmentation fault handlers

## COMMANDS
```bash
make              # Build release version
make debug        # Build with debug symbols
make clean        # Remove build artifacts
make install      # Install to /usr/local/bin (Unix only)
make uninstall    # Remove from /usr/local/bin (Unix only)
```

## NOTES

- Requires MinGW64/MSYS2 on Windows for compilation
- libssh2 and mbedtls are git submodules
- Static linking ensures no runtime dependencies
- Single-threaded event loop design limits scalability
- SOCKS5 supports CONNECT command only (no BIND or UDP ASSOCIATE)
