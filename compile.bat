@echo OFF
setlocal
setlocal EnableDelayedExpansion

:: This script can compile Frogger PSX both with the original compiler and later ones.

:VerifyMWI
if not exist "merge\FROGPSX.MWI" (
	ECHO.
	ECHO.
	ECHO In order for the game to be able to read game assets ^(3D models, textures, etc^), it needs a file called FROGPSX.MWI.
	ECHO Here are the steps for fixing this problem.
	ECHO.
	ECHO 1^) Open FrogLord ^(Frogger Editor, Google it^)
	ECHO 2^) Open SLUS_005.06 ^& FROGPSX.MWD in the build^\Files_A or build\Files_E folder. ^(Created by running extractdisc.bat^).
	ECHO 3^) In FrogLord, there is a menu bar at the top. Do Edit ^> Generate .H Files.
	ECHO 4^) Move FROGPSX.MWI from the build^\Files_^* folder to ^\merge^\FROGPSX.MWI
	ECHO 5^) This warning will go away when you try to compile again if done correctly.
	ECHO.
	PAUSE
	goto :EOF
)



SET COUNTRY_CODE=%1%
:country_select
if "%COUNTRY_CODE%"=="E" goto country_ok
if "%COUNTRY_CODE%"=="A" goto country_ok
if "%COUNTRY_CODE%"=="D" goto country_ok

echo Please choose which version you'd like to build.
echo.
echo A) NTSC (USA)
echo D) NTSC (USA) (Uses DOSBox to use the exact original compiler for a byte-matching build)
echo E) PAL (EUR)
echo.

set /p COUNTRY_CODE=
goto country_select

:country_ok


:: Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
:: Unfortunately, we can't keep the existing path, we must delete it. This is because Borland make doesn't handle paths above a certain size, and will give the error "Command arguments too long".
CALL SDK\PSPATHS.BAT

:: Setup build folder.
if not exist build md build

:: Go to dos handler if we've selected DOS.
if "%COUNTRY_CODE%"=="D" goto :CompileDosBox


:CompileWindows
:: Setup PsyQ SDK 4.0 Binaries.
:: DMPSX from PsyQ 4.3 is the first one I found which is win32 compatible.
IF EXIST sdk\bin\PSYLIB.EXE DEL sdk\bin\PSYLIB.EXE
robocopy sdk\bin\SDK4.0 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
COPY sdk\bin\SDK4.3\DMPSX.EXE sdk\bin\ /Y /B

:: Move to the source folder.
cd source

:: Make Frogger executable.
if "%COUNTRY_CODE%"=="A" make -l -N all
if "%COUNTRY_CODE%"=="E" make -l -N all
goto :AfterCompile



:CompileDosBox
SET COUNTRY_CODE=A

IF EXIST SetMyDosBoxPath.bat CALL SetMyDosBoxPath.bat
if not exist "%DOSBOX%" (
	ECHO There is no file at the dosbox path "%DOSBOX%".
	ECHO Please enter the full path to DOSBox.exe: 
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

:: Run the dos make script through DOSBox.
IF EXIST source\main.cpe DEL source\main.cpe
:DosMake
"%DOSBOX%" "%~dp0dosmake.bat" -noautoexec -noconsole -exit

IF EXIST BUILD\TEMP\DOS_LOCK GOTO :DosMake

:: Delete dosbox output.
DEL stderr.txt
DEL stdout.txt

:: Enter into the source folder.
CD source

goto :AfterCompile





:AfterCompile

:: Verify Frogger executable was made.
if NOT EXIST main.cpe goto error
if EXIST main.exe DEL main.exe

:: Convert Frogger executable to PSX-EXE.
cpe2exe main.cpe %COUNTRY_CODE% 0x801ffff0
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
CALL buildcd.bat %COUNTRY_CODE%
if errorlevel 1 goto :EOF

goto done

:MakeWSL
SET FILE_NAME=%1
SET DOS_PATH=source\%FILE_NAME%
SET LINUX_PATH=source/%FILE_NAME%

IF "%2"=="TRUE" (
	SET DOS_PATH=source\API.SRC\%FILE_NAME%
	SET LINUX_PATH=source/API.SRC/%FILE_NAME%
)

:: Return if the obj already exists and was modified more recently than the source file.
IF EXIST "%DOS_PATH%.OBJ" (
	FOR /F %%i IN ('DIR /B /O:D "%DOS_PATH%.C" "%DOS_PATH%.OBJ"') DO SET NEWER_FILE=%%i
	IF "!NEWER_FILE!"=="%FILE_NAME%.OBJ" EXIT /b 0
)

:: Step 1) Preprocess
ECHO Preprocessing %FILE_NAME%.C
"%DOSBOX%" -noautoexec -noconsole ^
 -c "MOUNT C: '%~dp0'" ^
 -c "C:" ^
 -c "CALL dospaths.bat" ^
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