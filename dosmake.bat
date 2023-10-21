@ECHO OFF
REM This batch script can be run by DOSBox to compile the game using the correct compilers.
REM This will not work on modern Windows.

REM Create an empty file that indicates DOSBox has not exited. This lets DOSBox automatically restart if it crashes, because we'll delete it upon successful completion.
ECHO . > BUILD\TEMP\DOS_LOCK

REM Setup SDK / folder.
CALL dospaths.bat

REM Move to the source folder.
cd source

REM Make Frogger executable and handle errors.
nmake all

IF ERRORLEVEL 2 GOTO :ERROR
IF ERRORLEVEL 1 GOTO :ERROR

REM End script.
GOTO :END

:ERROR
ECHO Compilation Failure
PAUSE

:END
CD ..\
REM Must change directory before attempting to delete the lock.
DEL BUILD\TEMP\DOS_LOCK