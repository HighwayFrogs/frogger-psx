@echo OFF
SET COUNTRY_CODE=%1%

:country_select
if "%COUNTRY_CODE%"=="E" goto country_ok
if "%COUNTRY_CODE%"=="A" goto country_ok

echo Please choose which Frogger disc image you'd like to extract.
echo.
echo A) NTSC (USA)
echo E) PAL (EUROPE)
echo.

set /p COUNTRY_CODE=
goto country_select

:country_ok

IF NOT EXIST "Frogger%COUNTRY_CODE%.bin" (
	ECHO Expected to find the file "Frogger%COUNTRY_CODE%.bin" in the root folder of the repository.
	ECHO However, this file was not found.
	goto :error
)

:: Dump PSX ISO
IF NOT EXIST "build\Files_%COUNTRY_CODE%" MD "build\Files_%COUNTRY_CODE%"
SDK\bin\dumpsxiso.exe -x "build\Files_%COUNTRY_CODE%" -s "build\Disc%COUNTRY_CODE%.xml" "Frogger%COUNTRY_CODE%.bin"
if errorlevel 1 goto :error

goto okay

:okay
echo Success
PAUSE
goto :EOF

:error
echo *** There Were Errors ***
PAUSE
EXIT /B 1