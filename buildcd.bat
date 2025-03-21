@echo off
setlocal
set COUNTRY_CODE=%1%

:: Ensure we execute from the directly the script is located in.
cd /d "%~dp0"

:select_region
if "%COUNTRY_CODE%"=="A" goto :set_region_usa
if "%COUNTRY_CODE%"=="E" goto :set_region_europe
if "%COUNTRY_CODE%"=="J" goto :set_region_japan

:: Currently, only NTSC/U builds are byte-matching / supported.
:ask_region
echo Please choose which version you'd like to build.
echo.
echo A) USA (NTSC-U)
echo E) Europe (PAL)
echo J) Japan (NTSC-J)
echo.

:: Ask user.
set /p COUNTRY_CODE=
goto :select_region

:set_region_usa
set BUILD_FOLDER_NAME=NTSC-U (USA)
set CD_EXECUTABLE_FILE_NAME=SLUS_005.06
goto :post_region_set

:set_region_europe
set BUILD_FOLDER_NAME=PAL (Europe)
set CD_EXECUTABLE_FILE_NAME=SLES_007.04
goto :post_region_set

:set_region_japan
set BUILD_FOLDER_NAME=NTSC-J (Japan)
set CD_EXECUTABLE_FILE_NAME=SLPS013.99
goto :post_region_set

:post_region_set
set BUILD_FOLDER_PATH=build\%BUILD_FOLDER_NAME%
if not exist "%BUILD_FOLDER_PATH%\" md "%BUILD_FOLDER_PATH%\"

:: Dump PSX ISO if missing.
if not exist "%BUILD_FOLDER_PATH%\files" (
	:: Check that the Frogger.bin file is there.
	if not exist "%BUILD_FOLDER_PATH%\original\Frogger.bin" (
		if not exist "%BUILD_FOLDER_PATH%\original" md "%BUILD_FOLDER_PATH%\original\"
		echo.
		echo Cannot build CD image, because game files from an original Frogger PSX CD image are required first!
		echo Please place your PSX Frogger CD image in the folder "%BUILD_FOLDER_PATH%\original", and name it "Frogger.bin".
		echo Other formats such as .mdf are not supported by the 'dumpsxiso' tool and should be avoided.
		echo After doing so, run this script again, and the game files will automatically be extracted.
		goto :error
	)

	sdk\bin\mkpsxiso\win-x64\dumpsxiso.exe -x "%BUILD_FOLDER_PATH%\files" -s "%BUILD_FOLDER_PATH%\DiscTemplate.xml" "%BUILD_FOLDER_PATH%\original\Frogger.bin"
	if errorlevel 1 goto :error
)

:: Ensure game executable exists.
if not exist "build\frogger.exe" (
	echo The game has not been compiled yet. Use "compile.bat" to compile the game before running this script again.
	goto :error
)

:: Move game executable.
copy /y "build\frogger.exe" "%BUILD_FOLDER_PATH%\files\%CD_EXECUTABLE_FILE_NAME%"
if exist "%BUILD_FOLDER_PATH%\files\frogger.map" del "%BUILD_FOLDER_PATH%\files\frogger.map"
if exist "%BUILD_FOLDER_PATH%\files\frogger.sym" del "%BUILD_FOLDER_PATH%\files\frogger.sym"
if exist "build\frogger.map" copy "build\frogger.map" "%BUILD_FOLDER_PATH%\files\"
if exist "build\frogger.sym" copy "build\frogger.sym" "%BUILD_FOLDER_PATH%\files\"

:: Create .bin/.cue CD image.
if exist "%BUILD_FOLDER_PATH%\Frogger.bin" del "%BUILD_FOLDER_PATH%\Frogger.bin"
if exist "%BUILD_FOLDER_PATH%\Frogger.cue" del "%BUILD_FOLDER_PATH%\Frogger.cue"
sdk\bin\mkpsxiso\win-x64\mkpsxiso.exe --output "%BUILD_FOLDER_PATH%\Frogger.bin" --cuefile "%BUILD_FOLDER_PATH%\Frogger.cue" "%BUILD_FOLDER_PATH%\DiscTemplate.xml"
if errorlevel 1 goto :error

goto :okay

:okay
echo Success
endlocal
goto :EOF

:error
endlocal
echo *** There Were Errors ***
pause
exit /B 1
