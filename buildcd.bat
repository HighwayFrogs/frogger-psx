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

:: Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
CALL SDK\PSPATHS.BAT

IF NOT EXIST "build\Files_%COUNTRY_CODE%" (
	ECHO The disc is not extracted with "dumpsxiso".
	ECHO Please place your iso as either "FroggerA.bin" or "FroggerE.bin" in the root folder of the repository.
	ECHO Then run "extractdisc.bat".
	ECHO "FroggerA" corresponds to NTSC isos, and "FroggerE" corresponds to PAL isos.
	goto :error
)

:: Ensure game executable exists.
IF NOT EXIST "source\main.exe" (
	ECHO The game has not been compiled yet. Use "compile.bat" to compile the game.
	goto :error
)

:: Move game executable.
IF EXIST "build\Files_%COUNTRY_CODE%\SLUS_005.06" DEL "build\Files_%COUNTRY_CODE%\SLUS_005.06"
IF EXIST "build\Files_%COUNTRY_CODE%\SLES_007.04" DEL "build\Files_%COUNTRY_CODE%\SLES_007.04"
if "%COUNTRY_CODE%"=="A"  copy "source\main.exe" "build\Files_%COUNTRY_CODE%\SLUS_005.06"
if "%COUNTRY_CODE%"=="E"  copy "source\main.exe" "build\Files_%COUNTRY_CODE%\SLES_007.04"
copy source\main.map "build\Files_%COUNTRY_CODE%\frogger.map"
copy source\main.sym "build\Files_%COUNTRY_CODE%\frogger.sym"

:: Create .bin/.cue CD image.
if exist "build\Disc%COUNTRY_CODE%.bin" del "build\Disc%COUNTRY_CODE%.bin"
if exist "build\Disc%COUNTRY_CODE%.cue" del "build\Disc%COUNTRY_CODE%.cue"
sdk\bin\mkpsxiso.exe --output "build\Disc%COUNTRY_CODE%.bin" --cuefile "build\Disc%COUNTRY_CODE%.cue" "build\Disc%COUNTRY_CODE%.xml"
if errorlevel 1 goto :error

goto okay

:okay
echo Success
goto :EOF

:error
echo *** There Were Errors ***
PAUSE
EXIT /B 1