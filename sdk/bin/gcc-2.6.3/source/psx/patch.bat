REM Remove read-only property from directory and files
attrib -r -a .
attrib -r -a * /s


REM Setup makefile. (Disabled because it built 8086 when I tried to make it build mips...)
REM config\i386\config-nt.bat

REM Comment out the line "#include <sys/file.h>" in config\mips\mips.c
Sed -e "s/#include <sys\/file.h>/\/\/#include <sys\/file.h>/" config\mips\mips.c > config\mips\mips2.c
DEL config\mips\mips.c
MOVE config\mips\mips2.c config\mips\mips.c

REM Replace the line "#define SDB_MAX_DIM 4" with "#define SDB_MAX_DIM 6" in sdbout.c
Sed -e "s/#define SDB_MAX_DIM 4/#define SDB_MAX_DIM 6/" sdbout.c > sdbout2.c
DEL sdbout.c
MOVE sdbout2.c sdbout.c

REM Replace the line "strcpy (q, ".o")" with "strcpy (q, ".obj")" in cccp.c
Sed -e "s/strcpy (q, \".o\")/strcpy (q, \".obj\")/" cccp.c > cccp2.c
DEL cccp2.c
MOVE cccp2.c cccp.c