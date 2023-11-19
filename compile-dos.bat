@echo OFF
setlocal
setlocal EnableDelayedExpansion

:: Startup
ECHO.
ECHO Welcome to the DOS Build Pipeline
ECHO.

:: This script can compile Frogger PSX with pipeline #2 (DOS + WSL).
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

:EnsureWSLExists
SET USE_WSL=TRUE

:: Runs wsl (Windows Subsystem for Linux), and do a nothing operation "exit with exit code 0".
wsl.exe -- exit 0 > nul
IF ERRORLEVEL 1 (
	ECHO.
	ECHO You probably wanted to run "compile.bat" instead of this file.
	ECHO Unless you know what you are doing, exit this and run that one instead.
	ECHO.
	ECHO.
	ECHO Could not run wsl.exe ^(Windows Subsystem for Linux^)
	ECHO To build byte-matching code with the DOS pipeline, you must install WSL2.
	ECHO If you continue, a non-matching build will be made.
	ECHO.
	SET USE_WSL=FALSE
	PAUSE
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
COPY sdk\bin\gcc-2.6.3\cc1-psx-263 sdk\bin\ /Y /B

:: Compile files that require 2.6.3 (2.6.0 works with most files, so for now we only use 2.6.3 when we have to because of how slow it can be to wield.)
CALL :MakeWSL ENT_DES FALSE
CALL :MakeWSL FROG FALSE
CALL :MakeWSL MAPVIEW FALSE
CALL :MakeWSL MR_ANIM TRUE
CALL :MakeWSL MR_ANIM3 TRUE
CALL :MakeWSL MR_COLL TRUE
CALL :MakeWSL MR_DEBUG TRUE
CALL :MakeWSL MR_DISP TRUE
CALL :MakeWSL MR_FILE TRUE
CALL :MakeWSL MR_FRAME TRUE
CALL :MakeWSL MR_FONT TRUE
CALL :MakeWSL MR_FX TRUE
CALL :MakeWSL MR_LIGHT TRUE
CALL :MakeWSL MR_INPUT TRUE
CALL :MakeWSL MR_MATH TRUE
CALL :MakeWSL MR_MEM TRUE
CALL :MakeWSL MR_MESH TRUE
CALL :MakeWSL MR_MISC TRUE
CALL :MakeWSL MR_MOF TRUE
CALL :MakeWSL MR_OBJ TRUE
CALL :MakeWSL MR_OT TRUE
CALL :MakeWSL MR_PART TRUE
CALL :MakeWSL MR_QUAT TRUE
CALL :MakeWSL MR_SOUND TRUE
CALL :MakeWSL MR_SPLIN TRUE
CALL :MakeWSL MR_SPRT TRUE
CALL :MakeWSL MR_STAT TRUE
CALL :MakeWSL MR_VRAM TRUE

ECHO.
ECHO Compiling remaining files through makefile...
ECHO.

:: Run the dos make script through DOSBox.
IF EXIST source\main.cpe DEL source\main.cpe
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

goto done

:MakeWSL
SET FILE_NAME=%1
SET DOS_PATH=source\%FILE_NAME%
SET LINUX_PATH=source/%FILE_NAME%

:: Exit if WSL is not enabled.
IF /I "%USE_WSL%"=="FALSE" EXIT /b 0

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
 -c "ccpsx -E -comments-c++ -c -Wunused -Wmissing-prototypes -Wuninitialized -O3 %DOS_PATH%.C -o %DOS_PATH%.P" ^
 -c "IF ERRORLEVEL 1 PAUSE" ^
 -c "exit"

IF NOT EXIST "%DOS_PATH%.P" GOTO :error

:: Step 2) Replace CRLF line endings (\r\n) with LF line endings (\n) to make the preprocessed code compatibility with Linux tools.
wsl -- awk '{ sub("\r$", ""); print }' "%LINUX_PATH%.P" > "%LINUX_PATH%-LF.P"

:: Step 3) Compile the code.
ECHO Compiling %FILE_NAME%-LF.P
wsl -- cat "%LINUX_PATH%-LF.P" ^| ./sdk/bin/cc1-psx-263 -O3 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -quiet -mcpu=3000 -fgnu-linker -mgas -gcoff ^> "%LINUX_PATH%-LF.S"

:: Step 4) Replace LF line endings (\n) back with CRLF line endings (\r\n) so Windows & DOS can use the compiler output.
wsl -- awk '{ sub("$", "\r"); print }' "%LINUX_PATH%-LF.S" > "%LINUX_PATH%.S"
IF NOT EXIST "%DOS_PATH%.S" GOTO :error
DEL "%DOS_PATH%.P"
DEL "%DOS_PATH%-LF.P"

:: Step 5) Assemble & DMPSXify
ECHO Assembling %FILE_NAME%.S
"%DOSBOX%" -noautoexec -noconsole ^
 -c "MOUNT C: '%~dp0'" ^
 -c "C:" ^
 -c "sdk\bin\aspsx -q %DOS_PATH%.S -o %DOS_PATH%.OBJ" ^
 -c "IF ERRORLEVEL 1 PAUSE" ^
 -c "sdk\bin\dmpsx %DOS_PATH%.OBJ -b" ^
 -c "exit"

:: Step 6) Create .LIB (If API)
IF "%2"=="TRUE" (
 ECHO Creating .LIB for %FILE_NAME%.OBJ
 "%DOSBOX%" -noautoexec -noconsole ^
  -c "MOUNT C: '%~dp0'" ^
  -c "C:" ^
  -c "sdk\bin\psylib /u %DOS_PATH%.LIB %DOS_PATH%.OBJ" ^
  -c "IF ERRORLEVEL 1 PAUSE" ^
  -c "exit"
)

:: Step 7) Cleanup
IF NOT EXIST "%DOS_PATH%.OBJ" GOTO :error
DEL "%DOS_PATH%-LF.S"
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