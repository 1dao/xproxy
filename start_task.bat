@echo off
REM ============================================================================
REM xproxy Windows Service Installation Script
REM ============================================================================
REM Usage:
REM   1. Run this batch file as Administrator to create a scheduled task that
REM      starts xproxy automatically on system boot
REM   2. The task runs under SYSTEM account with highest privileges
REM   3. To remove the task, run: schtasks /delete /tn "xproxy_boot" /f
REM   4. To view task status, run: schtasks /query /tn "xproxy_boot"
REM   5. To run manually: schtasks /run /tn "xproxy_boot"
REM
REM Parameters:
REM   -h  Remote SSH host IP
REM   -p  Remote SSH port
REM   -u  SSH username
REM   -P  SSH password
REM   -l  Local SOCKS5 proxy port
REM   -t  Local HTTP proxy port
REM   --pac-file  PAC configuration file path
REM
REM Log file: C:\source\ops\xproxy\xproxy.log
REM ============================================================================

echo Creating xproxy startup task...

schtasks /create /tn "xproxy_boot" /tr "cmd /c C:\source\ops\xproxy\xproxy.exe -h 216.121.173.196 -p 22 -u xxx -P password -l 1080 -t 7890 --pac-file C:\source\ops\xproxy\pac_config.txt > C:\source\ops\xproxy\xproxy.log 2>&1" /sc onstart /ru SYSTEM

if %errorlevel% equ 0 (
    echo Task created successfully!
    echo xproxy will start automatically on next system boot.
) else (
    echo Failed to create task. Make sure you are running as Administrator.
)

pause
