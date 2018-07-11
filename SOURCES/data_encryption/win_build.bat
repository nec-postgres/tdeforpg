SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

REM ### TDEforPG Windows builder ###
REM %1 : PostgreSQL Major Version (95 96 10 11 ...)
REM %2 : PostgreSQL Source Directory

IF NOT EXIST "tdeforpg\data_encryption.c" EXIT /B 255
IF NOT EXIST "msvc_tools\Mkvcbuild.pm.%1.diff" EXIT /B 255

FOR /F "usebackq tokens=*" %%i in (`CD`) DO SET BOOT_DIR=%%i
SET PGTDE_SRC=%BOOT_DIR%

SET MINGW_BIN=C:\MINGW\MSYS\1.0\BIN
IF NOT EXIST "%MINGW_BIN%\PATCH.EXE" EXIT /B 255

SET POSTGRES_MAJOR_VER=%1

SET PGSRC_ROOT=%2
SET PGSRC_CONTRIB=%PGSRC_ROOT%\contrib
SET PGSRC=%PGSRC_ROOT%\src\tools\msvc

REM ##### Copy suitable directory under "data_encryption" to PostgreSQL contrib
CD /D "%PGSRC_CONTRIB%"
IF EXIST data_encryption RD /Q /S data_encryption\
XCOPY /Y /F /I "%PGTDE_SRC%\tdeforpg" data_encryption
COPY /Y "%PGTDE_SRC%\msvc_tools\win32ver.rc" data_encryption\
REM ##### Windows build need Makefile to work
COPY /Y data_encryption\Makefile.in data_encryption\Makefile

REM ##### Patch Mkvcbuild.pm to build TDEforPG #####
CD /D "%PGSRC_ROOT%\src\tools\msvc"
COPY /Y Mkvcbuild.pm Mkvcbuild.pm.orig
"%MINGW_BIN%\PATCH.EXE" -p0 -i "%PGTDE_SRC%\msvc_tools\Mkvcbuild.pm.%POSTGRES_MAJOR_VER%.diff"

REM ##### Patch to pgcrypto for AES-NI #####
IF %POSTGRES_MAJOR_VER%==95 (
    CALL :patch_now
    IF NOT !ERRORLEVEL!==0 EXIT /B !ERRORLEVEL!
) ELSE IF %POSTGRES_MAJOR_VER%==96 (
    CALL :patch_now
    IF NOT !ERRORLEVEL!==0 EXIT /B !ERRORLEVEL!
)

REM ##### Delete old build #####
CD /D "%PGSRC_ROOT%"
IF EXIST Release ( RD /Q /S Release\ ) ELSE (ECHO Release directory is not found.)

REM ##### Build NOW! #####
cd /D "%PGSRC%"
CALL "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" amd64
CALL build.bat
EXIT /B %ERRORLEVEL%


:patch_now
CD /D %PGSRC_CONTRIB%\pgcrypto
COPY /Y openssl.c openssl.c.orig
COPY /Y "%PGTDE_SRC%\pgcrypto-aes-ni\openssl.c" .\
IF NOT %ERRORLEVEL%==0 EXIT /B 255

COPY /Y pgp-encrypt.c pgp-encrypt.c.orig
"%MINGW_BIN%\PATCH.EXE" -p0 -i "%PGTDE_SRC%\pgcrypto-aes-ni\pgp-encrypt.patch"
IF NOT %ERRORLEVEL%==0 EXIT /B 255
EXIT /B 0
