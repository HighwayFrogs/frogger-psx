@echo OFF
setlocal EnableDelayedExpansion

:: Ensure we execute from the directly the script is located in.
cd /d "%~dp0"

:: Startup
echo.
echo Welcome to the DOS Build Pipeline
echo.

:: This script can compile Frogger PSX with pipeline #2 (DOS).
:: It can build a byte-match of the game.
:: However, this script is discouraged, because it takes additional setup.
:: It's also very very slow. It takes approximately 11 minutes to do a clean build on my computer, and even worse DOSBox doesn't run at full-speed if you de-select the window.
:: In other words that's 11 minutes of not being able to use your PC. Sure, most builds you won't be rebuilding all files, but the other setup is just so much faster.

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
call sdk\PSPATHS.BAT

:: Setup build folder.
if not exist build md build
if not exist build\temp md build\temp

:: Setup DOSBox Path.
:: A simple SET DOSBOX=C:\Program Files\......\DOSBox.exe" can go in that file.
if exist "sdk\dos\SetMyDosBoxPath.bat" call "sdk\dos\SetMyDosBoxPath.bat"

:CompileDos
if not exist "%DOSBOX%" (
	echo You probably wanted to run "compile.bat" instead of this file.
	echo Unless you know what you are doing, exit this and run that one instead.
	echo.
	echo.
	echo There is no file at the dosbox path "%DOSBOX%".
	echo If you do not have DOSBox, use "compile.bat" instead.
	echo Otherwise, please enter the full file path to DOSBox.exe:
	SET /P DOSBOX=
	if exist "sdk\dos\SetMyDosBoxPath.bat" del "sdk\dos\SetMyDosBoxPath.bat"
	echo SET DOSBOX=!DOSBOX! > "sdk\dos\SetMyDosBoxPath.bat"
	goto :CompileDos
)

:: Setup PsyQ SDK DOS Binaries.
:: DMPSX.EXE from PsyQ 4.0 is necessary to work with runtime libraries 4.0, meaning no earlier version could have been used. Luckily, 4.0 ships with a DOS-compatible 16-bit DMPSX.EXE
:: ASPSXD.EXE from PsyQ 4.0 was determined to be the correct version, fixing a nop before gte_SetGeomScreen in MR_VIEW.C. The only other version which was known to be released at the time that can compile the code is 2.34 (PsyQ 3.5/3.6) DTL-S2110 for example, is missing the -0 option added to the makefile after Build 49.
:: PSYLINK.EXE from PsyQ was determined by matching every symbol up to "Map_path_header. With the 3.5 linker, it was 8 bytes too early, with 4.0's linker it's just right. With DTL-S2110's linker, linking fails to find certain symbols.
:: ASMPSX.EXE from PsyQ 4.0 is necessary because the ones from 3.5 and DTL-S2110 dont't support some of the syntax in mapasm.S or the MR API MR_M_ S files. We used 4.0 instead of 3.6 since everything else seems to be 4.0.
:: PSYLIB.EXE from PsyQ 4.0 since 3.5 worked, but everything else is 4.0, so the original was probably also 4.0. (PSYLIB.EXE from DTL-S2110 produced an executable which differed from the retail version)
if exist sdk\bin\PSYLIB2.EXE del sdk\bin\PSYLIB2.EXE
robocopy sdk\bin\DTL-S2110 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
robocopy sdk\bin\SDK4.0\DOS sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
if exist sdk\bin\COPYING del sdk\bin\COPYING

echo.
echo Compiling remaining files through makefile...
echo.

:: Run the dos make script through DOSBox.
if exist source\frogger.cpe del source\frogger.cpe
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
if exist BUILD\TEMP\DOS_LOCK goto :DosMake

:: Delete dosbox output.
del stderr.txt
del stdout.txt

:: Enter into the source folder.
cd source

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

goto done

:error
echo *** There Were Errors ***
endlocal
pause
goto :EOF

:done
echo Success
endlocal
pause

:exit