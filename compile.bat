@echo OFF
SET COUNTRY_CODE=%1%

:country_select
if "%COUNTRY_CODE%"=="E" goto country_ok
if "%COUNTRY_CODE%"=="A" goto country_ok

echo Please choose which version you'd like to build.
echo.
echo A) NTSC (USA)
echo E) PAL (EUR)
echo.

set /p COUNTRY_CODE=
goto country_select

:country_ok

REM Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
REM Unfortunately, we can't keep the existing path, we must delete it. This is because Borland make doesn't handle paths above a certain size, and will give the error "Command arguments too long".
CALL SDK\PSPATHS.BAT

REM Setup temp directory with copied code.
if not exist build md build
if not exist "build\Files_%COUNTRY_CODE%" md "build\Files_%COUNTRY_CODE%"
del build\burn\SLUS_005.06
del build\burn\SLES_007.04

:: Move to the source folder.
cd source

:: Make Frogger executable.
if "%COUNTRY_CODE%"=="A" make -l -N all
if "%COUNTRY_CODE%"=="E" make -l -N all
::if "%COUNTRY_CODE%"=="A" nmake /f MAKEFILE
::if "%COUNTRY_CODE%"=="E" nmake /f MAKEFILE
:: NTSC_VERSION=1 -> This can be read by the makefile in the same way 'BUG' can be. Let's add this once we're ready later.
::if "%COUNTRY_CODE%"=="A" nmake /f MAKEFILE -B NTSC_VERSION=1
:: SYSTEM.H contains the defines for things like region, etc. I think we can move that to the makefile.

:: Verify Frogger executable was made.
if errorlevel 1 goto error
if NOT EXIST main.cpe goto error

:: Convert Frogger executable to PSX-EXE.
cpe2exe main.cpe %COUNTRY_CODE% 0x801ffff0
if NOT EXIST main.exe goto error

:: Move output to burn folder.
cd ..\

:: Show SHA1 hash
echo Executable SHA1 Hash:
certutil -hashfile source\main.exe SHA1
PAUSE

:: Attempt to build the CD.
CALL buildcd.bat %COUNTRY_CODE%
if errorlevel 1 goto error

goto okay

:error
echo *** There Were Errors ***
PAUSE
SET ERRORLEVEL=1
goto :EOF

:okay
echo Success
PAUSE