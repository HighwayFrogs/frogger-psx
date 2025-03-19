@echo off
setlocal

:: Ensure we execute from the directly the script is located in.
cd /d "%~dp0"

:: This script can compile Frogger PSX in a Windows environment capable of running 32-bit applications (which as of writing is pretty much any Windows PC).
:: It takes approximately one minute on my computer to compile a full clean build.

if not exist "merge\FROGPSX.MWI" (
	echo.
	echo.
	echo In order for the game to be able to read game assets ^(3D models, textures, etc^), it needs a file called FROGPSX.MWI.
	echo Here are the steps for getting this file.
	echo.
	echo 1^) Run extractdisc.bat if you haven't already, and follow its instructions.
	echo 2^) Open FrogLord ^(Frogger Editor, Google it^)
	echo 2^) Open SLUS_005.06 ^& FROGPSX.MWD in the build^\files folder. ^(If you don't have it, go back to step 1^)
	echo 3^) In FrogLord, there is a menu bar at the top. Click on "Edit ^> Generate Source Files".
	echo 4^) Move FROGPSX.MWI from the build^\files folder into ^\merge^\.
	echo 5^) This message will go away next time you run compile.bat if you did it.
	echo.
	echo If you need further help, join the Highway Frogs discord server.
	echo.
	endlocal
	pause
	goto :EOF
)

:: Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
:: Unfortunately, we can't keep the existing path, we must delete it. This is because Borland make doesn't handle paths above a certain size, and will give the error "Command arguments too long".
CALL sdk\PSPATHS.BAT

:: Setup build folder.
if not exist build md build
if not exist build\temp md build\temp

:: Setup PsyQ SDK 4.0 Binaries.
:: DMPSX from PsyQ 4.3 is the first one I found which is win32 compatible.
:: GCC 2.6.3 / CC1PSX.EXE was compiled from scratch (as described in the document)
if exist sdk\bin\PSYLIB.EXE del sdk\bin\PSYLIB.EXE
robocopy sdk\bin\SDK4.0 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
robocopy sdk\bin\SDK4.3 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
copy sdk\bin\gcc-2.6.3\bin\win32\CC1PSX.EXE sdk\bin\ /Y /B

:: Move to the source folder.
cd source

:: Make Frogger executable.
del frogger.cpe
:: make -l -DWIN32 -N all
:: Borland Make seems to fail on Windows 11 on a pretty much fresh install. It's probably path related soooo, we're just gonna use real nmake, no reason why not to at this point.
nmake WIN32= all

:: Verify Frogger executable was made.
if not exist frogger.cpe goto error
if exist frogger.exe del frogger.exe

:: Convert Frogger executable to PSX-EXE.
cpe2exe frogger.cpe A 0x801ffff0
if not exist frogger.exe goto error

:: Copy executables to build folder.
copy /y "frogger.exe" "..\build\frogger.exe" >NUL
if exist "..\build\frogger.map" del "..\build\frogger.map" >NUL
if exist "..\build\frogger.sym" del "..\build\frogger.sym" >NUL
if exist "frogger.map" copy "frogger.map" "..\build\frogger.map" >NUL
if exist "frogger.sym" copy "frogger.sym" "..\build\frogger.sym" >NUL

:: Move back to root folder.
cd ..\

:: Show SHA1 hash
echo Executable SHA1 Hash:
certutil -hashfile build\frogger.exe SHA1
echo.
echo.

:AskToBuildCD
echo Would you like to build the .BIN/.CUE CD Image (Yes/Y/No/N)? 
set /p USER_RESPONSE=
if "%USER_RESPONSE%"=="y" goto BuildCD
if "%USER_RESPONSE%"=="Y" goto BuildCD
if "%USER_RESPONSE%"=="yes" goto BuildCD
if "%USER_RESPONSE%"=="Yes" goto BuildCD
if "%USER_RESPONSE%"=="YES" goto BuildCD
if "%USER_RESPONSE%"=="no" goto exit
if "%USER_RESPONSE%"=="No" goto exit
if "%USER_RESPONSE%"=="NO" goto exit
if "%USER_RESPONSE%"=="n" goto exit
if "%USER_RESPONSE%"=="N" goto exit
goto AskToBuildCD

:BuildCD
:: Attempt to build the CD.
call buildcd.bat A
if errorlevel 1 (
	endlocal
	goto :EOF
)

pause
goto exit

:error
echo *** There Were Errors ***
endlocal
pause

:exit