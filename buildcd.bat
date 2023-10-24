@echo OFF
:: Currently, only NTSC/U builds are byte-matching / supported.
SET COUNTRY_CODE=A

:: Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
CALL SDK\PSPATHS.BAT

IF NOT EXIST "build\files" (
	IF NOT EXIST "build\original\" MD "build\original"
	ECHO The disc has not been extracted with "dumpsxiso".
	ECHO Please place your Frogger CD image in the folder "build\original", and name it "Frogger.bin".
	ECHO Then run "extractdisc.bat".
	ECHO This script will work again after that.
	goto :error
)

:: Ensure game executable exists.
IF NOT EXIST "source\main.exe" (
	ECHO The game has not been compiled yet. Use "compile.bat" to compile the game.
	goto :error
)

:: Move game executable.
IF EXIST "build\files\SLUS_005.06" DEL "build\files\SLUS_005.06"
IF EXIST "build\files\SLES_007.04" DEL "build\files\SLES_007.04"
IF EXIST "build\files\SLPS013.99" DEL "build\files\SLPS013.99"
if "%COUNTRY_CODE%"=="A"  copy "source\main.exe" "build\files\SLUS_005.06"
if "%COUNTRY_CODE%"=="E"  copy "source\main.exe" "build\files\SLES_007.04"
if "%COUNTRY_CODE%"=="J"  copy "source\main.exe" "build\files\SLPS013.99"
copy source\main.map "build\files\frogger.map"
copy source\main.sym "build\files\frogger.sym"

:: Create .bin/.cue CD image.
if exist "build\Frogger.bin" del "build\Frogger.bin"
if exist "build\Frogger.cue" del "build\Frogger.cue"
sdk\bin\mkpsxiso.exe --output "build\Frogger.bin" --cuefile "build\Frogger.cue" "build\Frogger.xml"
if errorlevel 1 goto :error

goto okay

:okay
echo Success
goto :EOF

:error
echo *** There Were Errors ***
PAUSE
EXIT /B 1