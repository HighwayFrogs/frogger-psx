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
IF NOT EXIST "build\Files_%COUNTRY_CODE%" (
	ECHO The disc is not extracted with "dumpsxiso".
	goto :error
)

del "build\Files_%COUNTRY_CODE%\SLUS_005.06"
del "build\Files_%COUNTRY_CODE%\SLES_007.04"
if "%COUNTRY_CODE%"=="A"  copy "source\main.exe" "build\Files_%COUNTRY_CODE%\SLUS_005.06"
if "%COUNTRY_CODE%"=="E"  copy "source\main.exe" "build\Files_%COUNTRY_CODE%\SLES_007.04"
copy source\main.map "build\Files_%COUNTRY_CODE%\frogger.map"
copy source\main.sym "build\Files_%COUNTRY_CODE%\frogger.sym"

:: Create .bin/.cue CD image.
if exist "build\Disc%COUNTRY_CODE%.bin" del "build\Disc%COUNTRY_CODE%.bin"
if exist "build\Disc%COUNTRY_CODE%.cue" del "build\Disc%COUNTRY_CODE%.cue"
mkpsxiso --output "build\Disc%COUNTRY_CODE%.bin" --cuefile "build\Disc%COUNTRY_CODE%.cue" "build\Disc%COUNTRY_CODE%.xml"
if errorlevel 1 goto :EOF

goto okay

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:okay
echo Success
PAUSE