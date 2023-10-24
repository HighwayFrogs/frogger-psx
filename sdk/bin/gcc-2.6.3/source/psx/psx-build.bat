nmake /f psx-makefile cccp.exe
nmake /f psx-makefile cc1.exe
nmake /f psx-makefile stamp-objlist
cd cp
nmake /f psx-makefile compiler
cd ..
move cccp.exe cpppsx.exe
move cc1.exe cc1psx.exe
move cc1plus.exe cc1plpsx.exe
pkzip gnupsx.zip cpppsx.exe cc1psx.exe cc1plpsx.exe
echo All done!
