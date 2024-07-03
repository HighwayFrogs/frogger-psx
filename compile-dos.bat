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
	IF EXIST "sdk\dos\SetMyDosBoxPath.bat" DEL "sdk\dos\SetMyDosBoxPath.bat"
	ECHO SET DOSBOX=!DOSBOX! > "sdk\dos\SetMyDosBoxPath.bat"
	goto :CompileDos
)

:: Setup PsyQ SDK DOS Binaries.
:: DMPSX.EXE from PsyQ 4.0 is necessary to work with runtime libraries 4.0, meaning no earlier version could have been used. Luckily, 4.0 ships with a DOS-compatible 16-bit DMPSX.EXE
:: ASPSXD.EXE from PsyQ 4.0 was determined to be the correct version, fixing a nop before gte_SetGeomScreen in MR_VIEW.C. The only other version which was known to be released at the time that can compile the code is 2.34 (PsyQ 3.5/3.6) DTL-S2110 for example, is missing the -0 option added to the makefile after Build 49.
:: PSYLINK.EXE from PsyQ was determined by matching every symbol up to "Map_path_header. With the 3.5 linker, it was 8 bytes too early, with 4.0's linker it's just right. With DTL-S2110's linker, linking fails to find certain symbols.
:: ASMPSX.EXE from PsyQ 4.0 is necessary because the ones from 3.5 and DTL-S2110 dont't support some of the syntax in mapasm.S or the MR API MR_M_ S files. We used 4.0 instead of 3.6 since everything else seems to be 4.0.
:: PSYLIB.EXE from PsyQ 4.0 since 3.5 worked, but everything else is 4.0, so the original was probably also 4.0. (PSYLIB.EXE from DTL-S2110 produced an executable which differed from the retail version)
IF EXIST sdk\bin\PSYLIB2.EXE DEL sdk\bin\PSYLIB2.EXE
robocopy sdk\bin\DTL-S2110 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
robocopy sdk\bin\SDK4.0\DOS sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
IF EXIST sdk\bin\COPYING DEL sdk\bin\COPYING


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

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:done
echo Success
PAUSE

:exit