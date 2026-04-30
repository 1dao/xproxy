@echo off
chcp 65001 > nul
title xproxy-Build-Script (MSVC)
setlocal enabledelayedexpansion

:: 定义颜色常量
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "RESET=[0m"

:: ======================================
:: 1. 初始化 VS 编译环境
:: ======================================
echo %GREEN%[INFO]%RESET% Searching for MSVC Environment...
set "VS_VCVARS="
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\Program Files\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "C:\software\MicrosoftVisual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
) do (
    if exist %%P (
        set "VS_VCVARS=%%P"
        goto :found_vcvars
    )
)

:found_vcvars
if not defined VS_VCVARS (
    echo %RED%[ERROR]%RESET%Visual Studio vcvarsall.bat not found!
    pause
    exit /b 1
)

if "%VSCMD_ARG_TGT_ARCH%" neq "x64" (
    call %VS_VCVARS% x64
)

:: ======================================
:: 2. 配置编译参数 (Mirroring Makefile)
:: ======================================
set "OBJDIR=.obj"
set "EXE=xproxy.exe"

:: Define flags similar to Makefile
set "DEFS=/DWIN32_LEAN_AND_MEAN /DWINVER=0x0601 /D_CRT_SECURE_NO_WARNINGS /DLIBSSH2_WINCNG /DWIN32 /D_CONSOLE /D_LIB"

:: Add macro to replace strcpy with strcpy_s for security
:: set "DEFS=%DEFS% /Dstrcpy=strcpy_s /Dstrcat=strcat_s /Dsprintf=sprintf_s"
set "DEFS=%DEFS% /Dstrdup=_strdup /Dstrcasecmp=_stricmp

set "INCS=/I. /I./3rd/libssh2/include /I./3rd/libssh2/src"

:: CFLAGS (mirroring Makefile flags) - enable C11 standard for MSVC
set "BASE_CFLAGS=/nologo /TC /W3 /utf-8 /std:c11 /wd4005 /wd4996 %DEFS% %INCS%"

if "%1"=="debug" (
    set "CFLAGS=%BASE_CFLAGS% /Od /Zi /MDd /DDEBUG"
    set "LDFLAGS=/DEBUG"
) else (
    set "CFLAGS=%BASE_CFLAGS% /O1 /MD /Gy /Gw /GL"
    set "LDFLAGS=/LTCG /OPT:REF /OPT:ICF"
    :: set "CFLAGS=%BASE_CFLAGS% /O2 /MD"
    :: set "LDFLAGS="
)

:: Libraries (mirroring Makefile)
set "LIBS=ws2_32.lib crypt32.lib bcrypt.lib advapi32.lib"

:: ======================================
:: 3. Source and Object Lists (matching Makefile)
:: ======================================

:: Application sources
set "APP_SOURCES=main.c xpoll.c socks5_server.c ssh_tunnel.c xargs.c https_proxy.c xpac_server.c"

:: libssh2 sources (from Makefile)
set "LIBSSH2_SOURCES=3rd/libssh2/src/bcrypt_pbkdf.c 3rd/libssh2/src/chacha.c 3rd/libssh2/src/channel.c 3rd/libssh2/src/cipher-chachapoly.c 3rd/libssh2/src/comp.c 3rd/libssh2/src/crypt.c 3rd/libssh2/src/global.c 3rd/libssh2/src/hostkey.c 3rd/libssh2/src/keepalive.c 3rd/libssh2/src/kex.c 3rd/libssh2/src/mac.c 3rd/libssh2/src/misc.c 3rd/libssh2/src/openssl.c 3rd/libssh2/src/packet.c 3rd/libssh2/src/pem.c 3rd/libssh2/src/poly1305.c 3rd/libssh2/src/session.c 3rd/libssh2/src/transport.c 3rd/libssh2/src/userauth.c 3rd/libssh2/src/userauth_kbd_packet.c 3rd/libssh2/src/wincng.c"

:: Build object file lists similar to Makefile
set "APP_OBJECTS="
for %%F in (%APP_SOURCES%) do (
    set "APP_OBJECTS=!APP_OBJECTS! !OBJDIR!/%%~nF.obj"
)

set "LIBSSH2_OBJECTS="
for %%F in (%LIBSSH2_SOURCES%) do (
    set "NAME=%%~nF"
    set "LIBSSH2_OBJECTS=!LIBSSH2_OBJECTS! !OBJDIR!/libssh2/!NAME!.obj"
)

set "ALL_OBJECTS=!APP_OBJECTS! !LIBSSH2_OBJECTS!"

:: ======================================
:: 4. Clean Operation
:: ======================================
if "%1"=="clean" (
    if exist %OBJDIR% (
        echo %GREEN%[INFO]%RESET% Cleaning build directory...
        rmdir /S /Q %OBJDIR%
    )
    if exist %EXE% (
        del %EXE%
    )
    exit /b 0
)

:: ======================================
:: 5. Create Directories
:: ======================================
if not exist %OBJDIR% mkdir %OBJDIR%
if not exist %OBJDIR%\libssh2 mkdir %OBJDIR%\libssh2

:: ======================================
:: 6. Compile Individual Source Files
:: ======================================
echo %GREEN%[INFO]%RESET% Compiling application sources...

:: Compile each app source file individually
for %%F in (%APP_SOURCES%) do (
    set "SOURCE_FILE=%%F"
    set "OBJECT_FILE=%OBJDIR%\%%~nF.obj"
    if not exist "!OBJECT_FILE!" (
        echo %GREEN%[INFO]%RESET% Compiling !SOURCE_FILE!...
        cl %CFLAGS% /c "!SOURCE_FILE!" /Fo"!OBJECT_FILE!"
        if !ERRORLEVEL! neq 0 (
            echo %RED%[ERROR]%RESET% Failed to compile !SOURCE_FILE!
            exit /b 1
        )
    ) else (
        :: Check if source is newer than object
        for %%G in (!SOURCE_FILE!) do (
            if "%%~tG" gtr "!OBJECT_FILE!" (
                echo %GREEN%[INFO]%RESET% Re-compiling !SOURCE_FILE!...
                cl %CFLAGS% /c "!SOURCE_FILE!" /Fo"!OBJECT_FILE!"
                if !ERRORLEVEL! neq 0 (
                    echo %RED%[ERROR]%RESET% Failed to compile !SOURCE_FILE!
                    exit /b 1
                )
            )
        )
    )
)

echo %GREEN%[INFO]%RESET% Compiling libssh2 sources...

:: Compile each libssh2 source file individually
for %%F in (%LIBSSH2_SOURCES%) do (
    set "SOURCE_FILE=%%F"
    set "NAME=%%~nF"
    set "OBJECT_FILE=%OBJDIR%\libssh2\!NAME!.obj"
    if not exist "!OBJECT_FILE!" (
        echo %GREEN%[INFO]%RESET% Compiling !SOURCE_FILE!...
        cl %CFLAGS% /c "!SOURCE_FILE!" /Fo"!OBJECT_FILE!"
        if !ERRORLEVEL! neq 0 (
            echo %RED%[ERROR]%RESET% Failed to compile !SOURCE_FILE!
            exit /b 1
        )
    ) else (
        :: Check if source is newer than object
        for %%G in (!SOURCE_FILE!) do (
            if "%%~tG" gtr "!OBJECT_FILE!" (
                echo %GREEN%[INFO]%RESET% Re-compiling !SOURCE_FILE!...
                cl %CFLAGS% /c "!SOURCE_FILE!" /Fo"!OBJECT_FILE!"
                if !ERRORLEVEL! neq 0 (
                    echo %RED%[ERROR]%RESET% Failed to compile !SOURCE_FILE!
                    exit /b 1
                )
            )
        )
    )
)

:: ======================================
:: 7. Link Executable
:: ======================================
echo %GREEN%[INFO]%RESET% Linking executable %EXE%...
link /nologo %LDFLAGS% /OUT:%EXE% %ALL_OBJECTS% %LIBS%

if %ERRORLEVEL% neq 0 (
    echo %RED%[ERROR]%RESET% Link failed
    exit /b 1
)

REM 编译完成后删除.obj目录
echo %GREEN%[INFO]%RESET% Cleaning up .obj directory...
rd /S /Q !OBJDIR! 2>nul

echo %GREEN%[INFO]%RESET% %EXE% build success with C11 standard.
pause
exit /b 0
