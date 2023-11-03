REM ================= PSX DEVELOPMENT ENVIRONMENT VARIABLES =============
set PATH=%~dp0bin;%WINDIR%\system32;
set PSX_PATH=%~dp0bin
set LIBRARY_PATH=%~dp0lib
set C_PLUS_INCLUDE_PATH=%~dp0..\include
set C_INCLUDE_PATH=%~dp0..\include;
set PSYQ_PATH=%~dp0bin
set COMPILER_PATH=%~dp0bin

REM Setup the temp directory to put files in here.
set TMPDIR=%~dp0..\build\temp
set TEMP=%TMPDIR%
set TMP=%TMPDIR%