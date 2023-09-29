@echo OFF

REM Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
REM Unfortunately, we can't keep the existing path, we must delete it. This is because Borland make doesn't handle paths above a certain size, and will give the error "Command arguments too long".
CALL SDK\PSPATHS.BAT

:: Move to the source folder.
cd source

:: Make Frogger executable.
make -l -N clean
if errorlevel 1 goto error

:: Move to the root folder.
cd ..\

goto okay

:error
echo *** There Were Errors ***
PAUSE
goto :EOF

:okay
echo Success
PAUSE