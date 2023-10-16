@ECHO OFF
REM This batch script can be run by DOSBox to compile the game using the correct compilers.
REM This will not work on modern Windows.

REM The repository is mounted to C:\ by DOSBox.
SET BASE_PATH=C:\
SET SDK_PATH=%BASE_PATH%sdk\

REM Calling PSPATHS.BAT will replace your %PATH% with one which has access to the SDK executables for this session only.
set PATH=%SDK_PATH%bin;%PATH%


REM Set the PsyQ paths. The "vlo" path is included because DOS doesn't handle paths the way Windows does.
set PSX_PATH=%SDK_PATH%bin
set LIBRARY_PATH=%SDK_PATH%lib
set C_PLUS_INCLUDE_PATH=%BASE_PATH%include
set C_INCLUDE_PATH=%BASE_PATH%include;%BASE_PATH%vlo;
set PSYQ_PATH=%SDK_PATH%bin
set COMPILER_PATH=%SDK_PATH%bin

REM Set the folder which the compiler / preprocessor / etc will write temporary files to as the build folder, because it will default to C:\WINDOWS\TEMP, which... doesn't fly anymore.
set TMPDIR=%BASE_PATH%build\temp

REM Setup build folder.
IF NOT EXIST build MD build
IF NOT EXIST build\temp MD build\temp

REM Move to the source folder.
cd source

REM Make Frogger executable and handle errors.
nmake all

IF ERRORLEVEL 2 GOTO :ERROR
IF ERRORLEVEL 1 GOTO :ERROR

REM Move back to root folder.
CD ..\
GOTO :END

:ERROR
ECHO Compilation Failure
PAUSE

:END