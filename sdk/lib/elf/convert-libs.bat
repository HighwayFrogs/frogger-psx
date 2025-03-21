@ECHO OFF
:: This script converts a folder of .LIB files (the official Psy-Q runtime libraries) from the proprietary SN Systems .LIB format to .A (ELF Archives)
:: This is necessary for building to work on Linux. This script however, is built to be run on Windows, since Psy-Q's PSYLIB2.EXE (which this script depends upon) is a Windows program.
:: It also requires WSL, with the packages installed from setup-linux.sh having been installed.
SETLOCAL EnableDelayedExpansion
CD %~dp0

:: Delete objects which can't be converted (due to the tool not supporting them)
IF EXIST NOHEAP.OBJ DEL NOHEAP.OBJ
IF EXIST NONE3.OBJ DEL NONE3.OBJ
IF EXIST 2MBYTE.OBJ DEL 2MBYTE.OBJ
IF EXIST 8MBYTE.OBJ DEL 8MBYTE.OBJ
IF EXIST AUTOPAD.OBJ DEL AUTOPAD.OBJ

:: Convert objects which are convertable.
CALL :convert-obj POWERON.OBJ
CALL :convert-obj PUTCHAR.OBJ

:: Convert libraries
CALL :convert-lib LIBAPI.LIB
CALL :convert-lib LIBC.LIB
CALL :convert-lib LIBC2.LIB
CALL :convert-lib LIBCARD.LIB
CALL :convert-lib LIBCD.LIB
CALL :convert-lib LIBCOMB.LIB
CALL :convert-lib LIBDS.LIB
CALL :convert-lib LIBETC.LIB
CALL :convert-lib LIBGPU.LIB
CALL :convert-lib LIBGS.LIB
CALL :convert-lib LIBGTE.LIB
CALL :convert-lib LIBGUN.LIB
CALL :convert-lib LIBMATH.LIB
CALL :convert-lib LIBMCRD.LIB
CALL :convert-lib LIBPRESS.LIB
CALL :convert-lib LIBSIO.LIB
CALL :convert-lib LIBSN.LIB
CALL :convert-lib LIBSND.LIB
CALL :convert-lib LIBSPU.LIB
CALL :convert-lib LIBTAP.LIB

goto :done

:convert-obj
SET OBJ_FILE=%1

:: Verify file exists
IF NOT EXIST "%OBJ_FILE%" (
	ECHO Skipping conversion of '%OBJ_FILE%' since it does not exist.
	EXIT /b 1
)

:: Generate new file name for converted object. Example: 'EVENT.OBJ' -> 'event.o'
FOR /F "tokens=* USEBACKQ" %%g IN (`wsl.exe -- echo "%OBJ_FILE%" ^^^| tr "[A-Z]" "[a-z]" ^^^| sed 's/\.obj/\.o/g'`) DO SET "O_FILE=%%g"

:: Perform conversion
IF EXIST "%O_FILE%" DEL "%O_FILE%"
ECHO Converting compiler object '%OBJ_FILE%' to '%O_FILE%'...


IF "%O_FILE%"=="snmain.o" (
	FOR /F "tokens=* USEBACKQ" %%g IN (`wsl.exe -- echo "%O_FILE%" ^^^| sed 's/\.o/\.s/g'`) DO SET "S_FILE=%%g"
	wsl.exe -- mipsel-linux-gnu-as -march=r3000 -mtune=r3000 -no-pad-sections -O1 -G8 "!S_FILE!" -o "%O_FILE%"
) ELSE (
	tools\psyq-obj-parser.exe "%OBJ_FILE%" -o "%O_FILE%" > nul
)

SET OBJ_ERROR=%ERRORLEVEL%

:: Verify success
IF "%OBJ_ERROR%" NEQ "0" (
	ECHO Failed to convert compiler object '%OBJ_FILE%' to '%O_FILE%'.
	PAUSE
	EXIT /b 1
)

:: Cleanup
DEL "%OBJ_FILE%"

:: Success
EXIT /b 0



:convert-lib
SET LIB_FILE=%1

:: Generate converted object name 'LIBAPI.LIB' -> 'libapi.a'
FOR /F "tokens=* USEBACKQ" %%g IN (`wsl.exe -- echo "%LIB_FILE%" ^^^| tr "[A-Z]" "[a-z]" ^^^| sed 's/\.lib/\.a/g'`) DO SET ELF_FILE=%%g

:: Verify .LIB file exists
IF NOT EXIST "%LIB_FILE%" (
	IF NOT EXIST "%ELF_FILE%" DO ECHO Skipping conversion of '%LIB_FILE%' since it does not exist.
	EXIT /b 1
)

:: Perform conversion
IF EXIST "%ELF_FILE%" DEL "%ELF_FILE%"
ECHO Converting library '%LIB_FILE%' to '%ELF_FILE%'...

:: Extract .lib
SET TEMP_FILE=temp.txt
IF EXIST "%NAME_TEMP_FILE%" DEL "%TEMP_FILE%"
..\..\bin\SDK4.3\PSYLIB2.EXE /x "%LIB_FILE%" > "%TEMP_FILE%"

:: Verify it exited ok
IF "%ERRORLEVEL%" NEQ "0" (
	ECHO Failed to extract '%LIB_FILE%'.
	PAUSE
	EXIT /b 1
)

:: Update the text file to include a list of objs, one per line.
:: The amount of files is too large to fit in a batch variable. By saving it to a file, we can bypass the variable size limit.
wsl.exe -- sed -i "s/Extracting module '//g" "%TEMP_FILE%"
wsl.exe -- sed -i "s/'//g" "%TEMP_FILE%"

:: Convert each .OBJ file to .O, then add them to the library.
wsl.exe -- mipsel-linux-gnu-ar -r "%ELF_FILE%"
SET DELETE_LIB=TRUE
FOR /F "tokens=*" %%A IN (%TEMP_FILE%) DO (
	CALL :convert-obj %%A
	IF "!ERRORLEVEL!"=="0" (
		IF NOT EXIST "!O_FILE!" (
			ECHO  File '!O_FILE!' was not found.
			PAUSE
			ECHO.
			FOR /F "tokens=*" %%A IN (%TEMP_FILE%) DO IF EXIST "%%A" DEL "%%A"
			DEL "%ELF_FILE%" "%TEMP_FILE%"
			EXIT /b 1
		)
		
		wsl.exe -- mipsel-linux-gnu-ar -r "%ELF_FILE%" "!O_FILE!"
		IF "!ERRORLEVEL!" NEQ "0" (
			ECHO Failed to add '!O_FILE!' to '%ELF_FILE%'.
			PAUSE
			ECHO.
			FOR /F "tokens=*" %%A IN (%TEMP_FILE%) DO IF EXIST "%%A" DEL "%%A"
			DEL "%ELF_FILE%" "!O_FILE!" "%TEMP_FILE%"
			EXIT /b 1
		)
		
		DEL "%%A" "!O_FILE!"
	) ELSE (
		DEL "%%A"
		ECHO Skipping '%%A' due to conversion failure.
		ECHO.
		SET DELETE_LIB=FALSE
	)
)

DEL "%TEMP_FILE%"

:: Verify existence of converted file.
IF NOT EXIST "%ELF_FILE%" (
	ECHO Failed to create library '%ELF_FILE%'.
	PAUSE
	EXIT /b 1
)

:: Cleanup
IF "%DELETE_LIB%"=="TRUE" DEL "%LIB_FILE%"
ECHO.

:: Success
EXIT /b 0



:done
echo Finished converting files
PAUSE

:exit