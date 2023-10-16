@echo OFF

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
IF EXIST sdk\bin\INLINE.TBL DEL sdk\bin\INLINE.TBL
IF EXIST sdk\bin\PSYLIB.EXE DEL sdk\bin\PSYLIB.EXE
robocopy sdk\bin\SDK4.0 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
COPY sdk\bin\SDK4.3\DMPSX.EXE sdk\bin\ /Y /B

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

:: DOSBox has trouble building mapasm.s for some reason. It works great with the 4.0 binaries, so perhaps that's necessary.
:: This does potentially suggest that ASMPSX.EXE was the new one in the retail game, but further investigation needs doing.
COPY sdk\bin\SDK4.0\ASMPSX.EXE sdk\bin\ /Y /B
COPY sdk\bin\SDK4.3\DMPSX.EXE sdk\bin\ /Y /B
cd source
make -l -N mapasm.obj
cd ..

:: Setup PsyQ SDK 3.5 Binaries.
robocopy sdk\bin\SDK3.5 sdk\bin\ /NJH /NJS /NFL /NS /NC /NDL
COPY sdk\bin\SDK4.0\PSYLIB2.EXE sdk\bin\ /Y /B
COPY sdk\bin\SDK4.0\DMPSX.EXE sdk\bin\ /Y /B

:: Run the dos make script through DOSBox.
del source\main.cpe
"%DOSBOX%" "%~dp0dosmake.bat" -noautoexec -noconsole -exit

:: Delete dosbox output.
DEL stderr.txt
DEL stdout.txt

:: Enter into the source folder.
CD source

goto :AfterCompile





:AfterCompile

:: Verify Frogger executable was made.
if errorlevel 1 goto error
if NOT EXIST main.cpe goto error
if EXIST main.exe DEL main.exe

:: Convert Frogger executable to PSX-EXE.
cpe2exe main.cpe %COUNTRY_CODE% 0x801ffff0
if NOT EXIST main.exe goto error

:: Move back to root folder.
cd ..\

:: Show SHA1 hash
echo Executable SHA1 Hash:
certutil -hashfile source\main.exe SHA1
PAUSE

:: Attempt to build the CD.
CALL buildcd.bat %COUNTRY_CODE%
if errorlevel 1 goto :EOF

goto okay

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:okay
echo Success
PAUSE