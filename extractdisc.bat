@echo OFF

IF NOT EXIST "build\original" MD "build\original"

:: Check that the Frogger.bin file is there.
IF NOT EXIST "build\original\Frogger.bin" (
	ECHO Expected to find the PSX disc image "Frogger.bin" at the file path "build\original\Frogger.bin".  
	ECHO This is the CD image it will extract game files from, so it can build a CD image after compiling the game code.  
	ECHO However, this file was not found, please put it there and try again.  
	goto :error  
)

:: Dump PSX ISO
IF NOT EXIST "build\files" MD "build\files"
SDK\bin\dumpsxiso.exe -x "build\files" -s "build\Frogger.xml" "build\original\Frogger.bin"
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