@echo OFF
setlocal
setlocal EnableDelayedExpansion

:: This script can compile Frogger PSX both with the original compiler and later ones.
:: It takes approximately one minute on my computer to compile a full clean build.

:VerifyMWI
if not exist "merge\FROGPSX.MWI" (
	ECHO.
	ECHO.
	ECHO In order for the game to be able to read game assets ^(3D models, textures, etc^), it needs a file called FROGPSX.MWI.
	ECHO Here are the steps for getting this file.
	ECHO.
	ECHO 1^) Run extractdisc.bat if you haven't already, and follow its instructions.
	ECHO 2^) Open FrogLord ^(Frogger Editor, Google it^)
	ECHO 2^) Open SLUS_005.06 ^& FROGPSX.MWD in the build^\files folder. ^(If you don't have it, go back to step 1^)
	ECHO 3^) In FrogLord, there is a menu bar at the top. Click on "Edit ^> Generate Source Files".
	ECHO 4^) Move FROGPSX.MWI from the build^\files folder into ^\merge^\.
	ECHO 5^) This message will go away next time you run compile.bat if you did it.
	ECHO.
	ECHO If you need further help, join the Highway Frogs discord server.
	ECHO.
	PAUSE
	goto :EOF
)

:: Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
:: Unfortunately, we can't keep the existing path, we must delete it. This is because Borland make doesn't handle paths above a certain size, and will give the error "Command arguments too long".
CALL SDK\PSPATHS.BAT

:: Setup build folder.
if not exist build md build
if not exist build\temp md build\temp

:: Setup PsyQ SDK 4.0 Binaries.
:: DMPSX from PsyQ 4.3 is the first one I found which is win32 compatible.
:: GCC 2.6.3 / CC1PSX.EXE was compiled from scratch (as described in the document)
IF EXIST sdk\bin\PSYLIB.EXE DEL sdk\bin\PSYLIB.EXE
IF EXIST sdk\bin\cc1-psx-263 DEL sdk\bin\cc1-psx-263
robocopy sdk\bin\SDK4.0 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
robocopy sdk\bin\SDK4.3 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
COPY sdk\bin\gcc-2.6.3\CC1PSX.EXE sdk\bin\ /Y /B

:: Move to the source folder.
cd source

:: Make Frogger executable.
DEL main.cpe
:: make -l -DWIN32 -N all
:: Borland Make seems to fail on Windows 11 on a pretty much fresh install. It's probably path related soooo, we're just gonna use real nmake, no reason why not to at this point.
nmake WIN32= all

:: Verify Frogger executable was made.
if NOT EXIST main.cpe goto error
if EXIST main.exe DEL main.exe

:: Convert Frogger executable to PSX-EXE.
cpe2exe main.cpe A 0x801ffff0
if NOT EXIST main.exe goto error

:: Move back to root folder.
cd ..\

:: Show SHA1 hash
ECHO Executable SHA1 Hash:
certutil -hashfile source\main.exe SHA1
ECHO.
ECHO.

:AskToBuildCD
ECHO Would you like to build the .BIN/.CUE CD Image (Yes/Y/No/N)? 
set /p USER_RESPONSE=
IF "%USER_RESPONSE%"=="y" GOTO BuildCD
IF "%USER_RESPONSE%"=="Y" GOTO BuildCD
IF "%USER_RESPONSE%"=="yes" GOTO BuildCD
IF "%USER_RESPONSE%"=="Yes" GOTO BuildCD
IF "%USER_RESPONSE%"=="YES" GOTO BuildCD
IF "%USER_RESPONSE%"=="no" GOTO exit
IF "%USER_RESPONSE%"=="No" GOTO exit
IF "%USER_RESPONSE%"=="NO" GOTO exit
IF "%USER_RESPONSE%"=="n" GOTO exit
IF "%USER_RESPONSE%"=="N" GOTO exit
GOTO AskToBuildCD

:BuildCD
:: Attempt to build the CD.
CALL buildcd.bat
if errorlevel 1 goto :EOF

PAUSE
goto exit

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:exit