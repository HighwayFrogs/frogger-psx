@echo OFF
setlocal
setlocal EnableDelayedExpansion

:: Startup
ECHO.
ECHO Welcome to the DOS Build Pipeline
ECHO.

:: This script can compile Frogger PSX with pipeline #2 (DOS).
:: It can build a byte-match of the game.
:: However, this script is discouraged, because it takes considerable setup. It is slow, takes considerable setup, 
:: It's also very very slow. It takes approximately 11 minutes to do a clean build on my computer, and even worse DOSBox doesn't run at full-speed if you de-select the window.
:: So, that means 11 minutes of not being able to use your PC. Sure, most builds you won't be rebuilding all files, but the other setup is just so much faster.

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

:: Setup DOSBox Path.
:: A simple SET DOSBOX=C:\Program Files\......\DOSBox.exe" can go in that file.
IF EXIST "sdk\dos\SetMyDosBoxPath.bat" CALL "sdk\dos\SetMyDosBoxPath.bat"

:CompileDos
if not exist "%DOSBOX%" (
	ECHO You probably wanted to run "compile.bat" instead of this file.
	ECHO Unless you know what you are doing, exit this and run that one instead.
	ECHO.
	ECHO.
	ECHO There is no file at the dosbox path "%DOSBOX%".
	ECHO If you do not have DOSBox, use "compile.bat" instead.
	ECHO Otherwise, please enter the full file path to DOSBox.exe:
	SET /P DOSBOX=
	goto :CompileDos
)

:: Setup PsyQ SDK 3.5 + 4.0 DOS Binaries.
:: DMPSX.EXE from PsyQ 4.0 is necessary to work with runtime libraries 4.0. Luckily, 4.0 ships with a DOS-compatible 16-bit DMPSX.EXE
:: ASPSXD.EXE from PsyQ 4.0 was determined to be the correct version, fixing a nop before gte_SetGeomScreen in MR_VIEW.C. The only other version which was known to be released at the time that can compile the code is 2.34 (PsyQ 3.5/3.6)
:: PSYLINK.EXE from PsyQ was determined by matching every symbol up to "Map_path_header. With the 3.5 linker, it was 8 bytes too early, with 4.0's linker it's just right.
:: ASMPSX.EXE from PsyQ 4.0 is necessary because the one from 3.5 doesn't support some of the syntax in mapasm.S or the MR API MR_M_ S files. We used 4.0 instead of 3.6 since everything else seems to be 4.0.
:: PSYLIB.EXE from PsyQ 4.0 since 3.5 worked, but everything else is 4.0.
IF EXIST sdk\bin\PSYLIB2.EXE DEL sdk\bin\PSYLIB2.EXE
robocopy sdk\bin\SDK3.5 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
robocopy sdk\bin\SDK4.0\DOS sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL

:: Compile files that require 2.6.3 (2.6.0 works with most files, so for now we only use 2.6.3 when we have to because of how slow it can be to wield.)
CALL :MakeDOS ENT_DES FALSE
CALL :MakeDOS FROG FALSE
CALL :MakeDOS MAPVIEW FALSE
CALL :MakeDOS MR_ANIM TRUE
CALL :MakeDOS MR_ANIM3 TRUE
CALL :MakeDOS MR_COLL TRUE
CALL :MakeDOS MR_DEBUG TRUE
CALL :MakeDOS MR_DISP TRUE
CALL :MakeDOS MR_FILE TRUE
CALL :MakeDOS MR_FRAME TRUE
CALL :MakeDOS MR_FONT TRUE
CALL :MakeDOS MR_FX TRUE
CALL :MakeDOS MR_LIGHT TRUE
CALL :MakeDOS MR_INPUT TRUE
CALL :MakeDOS MR_MATH TRUE
CALL :MakeDOS MR_MEM TRUE
CALL :MakeDOS MR_MESH TRUE
CALL :MakeDOS MR_MISC TRUE
CALL :MakeDOS MR_MOF TRUE
CALL :MakeDOS MR_OBJ TRUE
CALL :MakeDOS MR_OT TRUE
CALL :MakeDOS MR_PART TRUE
CALL :MakeDOS MR_QUAT TRUE
CALL :MakeDOS MR_SOUND TRUE
CALL :MakeDOS MR_SPLIN TRUE
CALL :MakeDOS MR_SPRT TRUE
CALL :MakeDOS MR_STAT TRUE
CALL :MakeDOS MR_VRAM TRUE

ECHO.
ECHO Compiling remaining files through makefile...
ECHO.

:: Run the dos make script through DOSBox.
IF EXIST source\frogger.cpe DEL source\frogger.cpe
:DosMake
:: The commend to run make with DOS used to be a bit simpler:
:: "%DOSBOX%" "%~dp0sdk\dos\dosmake.bat" -noautoexec -noconsole -exit
:: We mount C:\ as the root directory, but eventually we moved dosmake.bat out of the root directory to make it less confusing to someone who just downloads the repository.
:: Unfortunately, DOSBox mounts the directory a batch file as in as C:\ when you run a batch file directly. So, when we moved the location, we had to change how we called it, so it still mounts the repository root directory as C:\.

:: Runs make with DOSBox.
"%DOSBOX%" -noautoexec -noconsole ^
 -c "MOUNT C: '%~dp0'" ^
 -c "C:" ^
 -c "CALL sdk\dos\dosmake.bat" ^
 -c "exit"

:: Unfortunately, when doing a lot of compiling, sometimes DOSBox crashes.
:: The exit code seems to always be 0, so I made it create a file "BUILD\TEMP\DOS_LOCK" on start.
:: When the batch script completion, it will delete this file.
:: Running the script again will resume the build process wherever it left off, so if we see that file (DOSBox crashed), we just run it again.
IF EXIST BUILD\TEMP\DOS_LOCK GOTO :DosMake

:: Delete dosbox output.
DEL stderr.txt
DEL stdout.txt

:: Enter into the source folder.
CD source

:: Verify Frogger executable was made.
if NOT EXIST frogger.cpe goto error
if EXIST frogger.exe DEL frogger.exe

:: Convert Frogger executable to PSX-EXE.
cpe2exe frogger.cpe A 0x801ffff0
if NOT EXIST frogger.exe goto error

:: Move back to root folder.
cd ..\

:: Show SHA1 hash
ECHO Executable SHA1 Hash:
certutil -hashfile source\frogger.exe SHA1
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

goto done

:MakeDOS
SET FILE_NAME=%1
SET DOS_PATH=source\%FILE_NAME%
SET LINUX_PATH=source/%FILE_NAME%

:: If this is API code, update the paths accordingly.
IF "%2"=="TRUE" (
	SET DOS_PATH=source\API.SRC\%FILE_NAME%
	SET LINUX_PATH=source/API.SRC/%FILE_NAME%
)

:: Return if the obj already exists and was modified more recently than the source file.
IF EXIST "%DOS_PATH%.OBJ" (
	FOR /F %%i IN ('DIR /B /O:D "%DOS_PATH%.C" "%DOS_PATH%.OBJ"') DO SET NEWER_FILE=%%i
	IF /I "!NEWER_FILE!"=="%FILE_NAME%.OBJ" EXIT /b 0
)

:: Step 1) Preprocess
ECHO Preprocessing %FILE_NAME%.C
"%DOSBOX%" -noautoexec -noconsole ^
 -c "MOUNT C: '%~dp0'" ^
 -c "C:" ^
 -c "CALL sdk\dos\dospaths.bat" ^
 -c "ccpsx -E -comments-c++ -c -Wunused -Wmissing-prototypes -Wuninitialized -O3 '%DOS_PATH%.C' -o '%DOS_PATH%.P'" ^
 -c "IF ERRORLEVEL 1 PAUSE" ^
 -c "exit"

IF NOT EXIST "%DOS_PATH%.P" GOTO :error

:: Step 2) Compile the code.
ECHO Compiling %FILE_NAME%.P
sdk\bin\gcc-2.6.3\bin\win32\cc1psx.exe -quiet -version -Wunused -Wmissing-prototypes -Wuninitialized -O3 "%DOS_PATH%.P" -o "%DOS_PATH%.S"

IF NOT EXIST "%DOS_PATH%.S" GOTO :error
DEL "%DOS_PATH%.P"

:: Step 3) Assemble & DMPSXify
ECHO Assembling %FILE_NAME%.S
"%DOSBOX%" -noautoexec -noconsole ^
 -c "MOUNT C: '%~dp0'" ^
 -c "C:" ^
 -c "sdk\bin\aspsx -q '%DOS_PATH%.S' -o '%DOS_PATH%.OBJ'" ^
 -c "IF ERRORLEVEL 1 PAUSE" ^
 -c "sdk\bin\dmpsx %DOS_PATH%.OBJ -b" ^
 -c "exit"

:: Step 4) Create .LIB (If API)
IF "%2"=="TRUE" (
 ECHO Creating .LIB for %FILE_NAME%.OBJ
 "%DOSBOX%" -noautoexec -noconsole ^
  -c "MOUNT C: '%~dp0'" ^
  -c "C:" ^
  -c "sdk\bin\psylib /u '%DOS_PATH%.LIB' '%DOS_PATH%.OBJ'" ^
  -c "IF ERRORLEVEL 1 PAUSE" ^
  -c "exit"
)

:: Step 5) Cleanup
IF NOT EXIST "%DOS_PATH%.OBJ" GOTO :error
DEL "%DOS_PATH%.S"

:: Success
exit /b 0

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:done
echo Success
PAUSE

:exit