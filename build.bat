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
set "DEFS=/DWIN32_LEAN_AND_MEAN /DWINVER=0x0601 /D_CRT_SECURE_NO_WARNINGS /DWOLFSSL_USER_SETTINGS /DWOLFSSH_USER_SETTINGS /DWOLFSSH_FWD /DWIN32 /D_CONSOLE /D_LIB"

:: Add macro to replace strcpy with strcpy_s for security
:: set "DEFS=%DEFS% /Dstrcpy=strcpy_s /Dstrcat=strcat_s /Dsprintf=sprintf_s"
set "DEFS=%DEFS% /Dstrdup=_strdup /Dstrcasecmp=_stricmp

set "INCS=/I. /I./3rd/wolfssl /I./3rd/wolfssl/wolfssl /I./3rd/wolfssh /I./3rd/wolfssh/wolfssh"

:: CFLAGS (mirroring Makefile flags)
set "BASE_CFLAGS=/nologo /TC /W3 /utf-8 /wd4005 /wd4996 %DEFS% %INCS%"

if "%1"=="debug" (
    set "CFLAGS=%BASE_CFLAGS% /Od /Zi /MDd /DDEBUG"
    set "LDFLAGS=/DEBUG"
) else (
    set "CFLAGS=%BASE_CFLAGS% /O2 /MD"
    set "LDFLAGS="
)

:: Libraries (mirroring Makefile)
set "LIBS=ws2_32.lib crypt32.lib bcrypt.lib advapi32.lib"

:: ======================================
:: 3. Source and Object Lists (matching Makefile)
:: ======================================

:: Application sources
set "APP_SOURCES=main.c xpoll.c socks5_server.c ssh_tunnel.c xargs.c https_proxy.c xpac_server.c"

:: WolfCrypt sources (from Makefile)
set "WOLFCRYPT_SOURCES=3rd/wolfssl/wolfcrypt/src/asn.c 3rd/wolfssl/wolfcrypt/src/error.c 3rd/wolfssl/wolfcrypt/src/rsa.c 3rd/wolfssl/wolfcrypt/src/aes.c 3rd/wolfssl/wolfcrypt/src/des3.c 3rd/wolfssl/wolfcrypt/src/sha.c 3rd/wolfssl/wolfcrypt/src/sha256.c 3rd/wolfssl/wolfcrypt/src/sha512.c 3rd/wolfssl/wolfcrypt/src/md5.c 3rd/wolfssl/wolfcrypt/src/hmac.c 3rd/wolfssl/wolfcrypt/src/hash.c 3rd/wolfssl/wolfcrypt/src/coding.c 3rd/wolfssl/wolfcrypt/src/random.c 3rd/wolfssl/wolfcrypt/src/memory.c 3rd/wolfssl/wolfcrypt/src/ecc.c 3rd/wolfssl/wolfcrypt/src/dh.c 3rd/wolfssl/wolfcrypt/src/integer.c 3rd/wolfssl/wolfcrypt/src/tfm.c 3rd/wolfssl/wolfcrypt/src/wolfmath.c 3rd/wolfssl/wolfcrypt/src/signature.c 3rd/wolfssl/wolfcrypt/src/logging.c 3rd/wolfssl/wolfcrypt/src/sp_int.c 3rd/wolfssl/wolfcrypt/src/wc_port.c 3rd/wolfssl/wolfcrypt/src/kdf.c 3rd/wolfssl/wolfcrypt/src/wc_encrypt.c 3rd/wolfssl/wolfcrypt/src/pwdbased.c 3rd/wolfssl/wolfcrypt/src/pkcs12.c"

:: WolfSSH sources (from Makefile)
set "WOLFSSH_SOURCES=3rd/wolfssh/src/ssh.c 3rd/wolfssh/src/internal.c 3rd/wolfssh/src/io.c 3rd/wolfssh/src/keygen.c 3rd/wolfssh/src/log.c 3rd/wolfssh/src/misc.c 3rd/wolfssh/src/port.c 3rd/wolfssh/src/certman.c 3rd/wolfssh/src/agent.c"

:: Build object file lists similar to Makefile
set "APP_OBJECTS="
for %%F in (%APP_SOURCES%) do (
    set "APP_OBJECTS=!APP_OBJECTS! !OBJDIR!/%%~nF.obj"
)

set "WOLFCRYPT_OBJECTS="
for %%F in (%WOLFCRYPT_SOURCES%) do (
    set "NAME=%%~nF"
    set "WOLFCRYPT_OBJECTS=!WOLFCRYPT_OBJECTS! !OBJDIR!/wolfssl/!NAME!.obj"
)

set "WOLFSSH_OBJECTS="
for %%F in (%WOLFSSH_SOURCES%) do (
    set "NAME=%%~nF"
    set "WOLFSSH_OBJECTS=!WOLFSSH_OBJECTS! !OBJDIR!/wolfssh/!NAME!.obj"
)

set "ALL_OBJECTS=!APP_OBJECTS! !WOLFCRYPT_OBJECTS! !WOLFSSH_OBJECTS!"

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
if not exist %OBJDIR%\wolfssl mkdir %OBJDIR%\wolfssl
if not exist %OBJDIR%\wolfssh mkdir %OBJDIR%\wolfssh

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

echo %GREEN%[INFO]%RESET% Compiling WolfCrypt sources...

:: Compile each WolfCrypt source file individually
for %%F in (%WOLFCRYPT_SOURCES%) do (
    set "SOURCE_FILE=%%F"
    set "NAME=%%~nF"
    set "OBJECT_FILE=%OBJDIR%\wolfssl\!NAME!.obj"
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

echo %GREEN%[INFO]%RESET% Compiling WolfSSH sources...

:: Compile each WolfSSH source file individually
for %%F in (%WOLFSSH_SOURCES%) do (
    set "SOURCE_FILE=%%F"
    set "NAME=%%~nF"
    set "OBJECT_FILE=%OBJDIR%\wolfssh\!NAME!.obj"
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

echo %GREEN%[INFO]%RESET% %EXE% build success.
pause
exit /b 0
