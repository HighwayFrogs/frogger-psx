#!/bin/bash

# This script modifies the repository to enable building in a Linux x64 environment (Or any other architecture you compile GCC for)
# This is a somewhat unusual approach, usually  you'd want one unified setup for both Windows and Linux.
# However, I wanted to keep the repository as close to the original as possible, and additionally the compilers for each system depend on different line endings.
# So, this script should do all the changes necessary to make it compileable on Linux.

# TODO: Before done.
# 1) Get a build which functions and matches outside of bss ordering.
#  - a) Fix relative $gp accessing.
#  - b) Generalize LD script as much as possible to SN Systems.
#  - c) Create build-cd.sh and make it work.
# 2) Attempt automated symbol ordering. (Python script for generating order automagically?)
# 3) Improve handwritten assembly files.
# 4) Make api.src and other folders lower-case.
# 5) Which changes did we want to apply to the windows setup?
#  - Lower-case header file names? Leaning towards yes
#  - Lower-case main source file names? Leaning towards no, but consider further.
# 6) Go through all documentation, find all TODOs. Did we byte-match on Linux? If not, make sure documentation makes this clear. If so, document how.
# 7) Move file setup from loose to setup script. [makefile, linker LD, linux/ folder]
# 8) Heavy Testing (Is it possible to have a repository which is both linux and windows compileable? Probably not locally due to CRLF reasons. But, a git repository which has linux pushed? Perhaps...)
# - Verify Full WSL (Then, see if windows build pipeline still works & that DOS pipeline still works.)
# - Verify WSL In Windows Filesystem (Then, see if windows build pipeline still works & that DOS pipeline still works.)
# - Verify standalone Windows Pipeline
# - Verify standalone DOS Pipeline

# Install required software
# vim is required to convert CR LF (\r\n) line endings to LF (\n).
# git is required for installing maspsx. (Although, a backup has been included in this repository which is known to work, and can be manually setup by just doing the steps this script does.)
# make is required to use the Linux makefile.
# gcc-mipsel-linux-gnu and binutils-mipsel-linux-gnu contain utilities for compiling MIPS programs and working with MIPS binaries. (In other words, it's how we're gonna get the executable.)
# python3 and python3-pip are required for maspsx.
echo "Installing packages..."
if [ $UID -eq 0 ]; then
	echo "Already root..."
	SUDO=""
else
	SUDO=sudo
fi

${SUDO} apt-get update && ${SUDO} apt-get install -y git vim make gcc-mipsel-linux-gnu binutils-mipsel-linux-gnu python3 python3-pip dos2unix

# The first problem with building on Linux is that the Linux file-system is case-sensitive, but Windows is not.
# The source file names are somewhat erratic in terms of upper-case / lower-case, likely because this was still when DOS was still common, which didn't even support lower-case file names.
# So, this here renames all of the relevant files to become lower-case.
# Make all file names lower-case (Unix has a case-sensitive file-system, but Windows does not. Let's use lower-case file names here.)
echo ""
echo "Forcing file-names to be lower-case..."
mv include/SYS include/sys
for f in include/*.[hH]; do mv -v "$f" "`echo $f | tr '[A-Z]' '[a-z]'`"; done
for f in include/sys/*.[hH]; do mv -v "$f" "`echo $f | tr '[A-Z]' '[a-z]'`"; done
for f in source/*.[cChHsSIi]; do mv -v "$f" "`echo $f | tr '[A-Z]' '[a-z]'`"; done
mv include/inline_c.h include/inline_c_windows.h
mv include/inline_c_linux.h include/inline_c.h

# Go into the directory, since otherwise it will try to make 'API.SRC' lower-case too.
cd source/API.SRC/
for f in *.[cChHsSIi]; do mv -v "$f" "`echo $f | tr '[A-Z]' '[a-z]'`"; done
cd ../../

# There's a weird character that sometimes makes compilation not work. I'm not sure why, since it wasn't an issue at one point. Oh well.
echo "Removing garbage 0x1A character that causes syntax errors..."
find ./source/ -iname '*.[chs]' -exec sed -i 's/\x1A//g' {} \;
# Remove random 0x8 character in ./source/API.SRC/mr_view.c
find ./source/ -iname '*.[chs]' -exec sed -i 's/\x08//g' {} \;

# Windows also uses CR LF line endings (\r\n), instead of LF line endings (\n)
# I think modern versions of GCC are capable of dealing with this, but we're using GCC from 1994 in order to get byte-matching compiler output.
# This step should only run after file renames, because it will only find lower-case extensions.
# This may be optional, especially if you git clone'd on a Linux machine, since it'll clone all the files as LF already. However, this has been kept for situations like WSL.
echo ""
echo "Converting CRLF line endings to LF..."
find ./source/ -iname '*.[chs]' | xargs dos2unix
find ./include/ -iname '*.h' | xargs dos2unix
find ./sdk/bin/gcc-2.6.3/source/linux/patches/ | xargs dos2unix
dos2unix ./sdk/bin/gcc-2.6.3/source/linux/build.sh

# Setup maspsx
# If this fails, extract sdk/bin/src/maspsx.zip to sdk/maspsx/.
# Eg: In case maspsx ever goes away or changes in a way which breaks this setup, we have a backup from when it worked.
echo ""
echo "Adding maspsx..."
git submodule add --force https://github.com/mkst/maspsx ./sdk/maspsx

# Setup gcc
chmod +x sdk/bin/gcc-2.6.3/bin/linux-x64/cc1
chmod +x sdk/bin/gcc-2.6.3/bin/linux-x64/cpp

# Replace file paths that use backslashes.
echo ""
echo "Updating source files..."
#sed -i "s/MR_VIEWPORT\*\tOption_viewport_ptr;/\/\/MR_VIEWPORT*\tOption_viewport_ptr;/g" source/select.c
sed -i 's/..\\merge\\frogpsx.h/..\/merge\/frogpsx.h/g' source/sound.c
sed -i 's/..\\vlo\\frogvram.c/..\/vlo\/frogvram.c/g' source/sprdata.c
sed -i 's/..\\vlo\\frogvram.h/..\/vlo\/frogvram.h/g' source/sprdata.h
sed -i 's/..\\merge\\frogpsx.h/..\/merge\/frogpsx.h/g' source/project.h
sed -i 's/sys\\types.h/sys\/types.h/g' source/system.h
sed -i 's/sys\\file.h/sys\/file.h/g' source/system.h
sed -i 's/api.src\/mr_all.h/API.SRC\/mr_all.h/g' source/mr_all.h
sed -i 's/..\\system.h/..\/system.h/g' source/API.SRC/mr_sys.h
sed -i 's/\/\/ Special GTE load\/save macros (not found in the normal PlayStation header files/\/* Special GTE load\/save macros (not found in the normal PlayStation header files/g' source/API.SRC/mr_sys.h
sed -i 's/\/\/ MRAcos_table access macros/\/\/ MRAcos_table access macros *\//g' source/API.SRC/mr_sys.h

# convert objects
./sdk/lib/elf/tools/psyq-obj-parser ./sdk/lib/putchar.obj -o ./sdk/lib/elf/putchar.o

# avoid double definition of "Option_viewport_ptr"
sed -i ./source/select.c 's/MR_VIEWPORT/extern MR_VIEWPORT/'

# make expects the Makefile to be named Makefile (otherwise 'make -f MAKEFILE')
mv MAKEFILE Makefile

#sdk/bin/gcc-2.6.3/bin/linux-x64/cpp -Iinclude -undef -D__GNUC__=2 -v -Wunused -Wmissing-prototypes -Wuninitialized -D__OPTIMIZE__ -lang-c -lang-c-c++-comments -Dmips -D__mips__ -D__mips -Dpsx -D__psx__ -D__psx -D__EXTENSIONS__ -D_MIPSEL -D__CHAR_UNSIGNED__ -D_LANGUAGE_C -DLANGUAGE_C source/frog.c > source/frog-preproc.c
#cat source/frog-preproc.c | sdk/bin/gcc-2.6.3/bin/linux-x64/cc1 -O3 -G0 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fgnu-linker -mgas -msoft-float -fverbose-asm -g -quiet -mcpu=3000 -gcoff -o source/frog-1.s
#cat source/frog-1.s | python3 sdk/maspsx/maspsx.py --no-macro-inc > source/frog-2.s
#mipsel-linux-gnu-as -Iinclude -march=r3000 -mtune=r3000 -no-pad-sections -O1 -G0 -o source/frog.o source/frog-2.s

echo "Setup complete, it should now be possible to build the game by running 'make'."

#mipsel-linux-gnu-ld -nostdlib --no-check-sections -o Frogger.elf \
#	source/main.o  source/project.o  source/sprdata.o  source/gamefont.o  source/mapload.o  source/mapdisp.o  source/gamesys.o  source/library.o  source/particle.o \
#    source/mapview.o  source/camera.o  source/entity.o  source/form.o  source/options.o  source/frog.o  source/grid.o  source/path.o  source/zone.o  source/collide.o  source/misc.o \
#	source/mapdebug.o  source/entlib.o  source/froguser.o  source/scripts.o  source/sound.o  source/stream.o  source/memcard.o  source/ent_des.o  source/ent_vol.o  source/ent_swp.o  \
#	source/ent_sub.o  source/ent_sky.o  source/ent_org.o  source/ent_jun.o  source/ent_gen.o  source/ent_for.o  source/ent_arn.o  source/ent_cav.o  source/formlib.o  source/hud.o  \
#	source/score.o  source/scripter.o  source/loadsave.o  source/playxa.o  source/tempopt.o  source/effects.o  source/xalist.o  source/select.o  source/model.o  source/hsview.o  \
#	source/froganim.o  source/hsinput.o  source/credits.o  source/water.o  source/pause.o  \
#	--start-group \
#	sdk/lib-elf/libgte.a sdk/lib-elf/libgpu.a sdk/lib-elf/libetc.a sdk/lib-elf/libapi.a sdk/lib-elf/libsn.a sdk/lib-elf/libc2.a sdk/lib-elf/libspu.a \
#	sdk/lib-elf/libsnd.a sdk/lib-elf/libpress.a sdk/lib-elf/libcd.a sdk/lib-elf/libds.a sdk/lib-elf/libcard.a sdk/lib-elf/libmcrd.a sdk/lib-elf/libtap.a \
#	source/API.SRC/mr_mof.o  source/API.SRC/mr_misc.o  source/API.SRC/mr_frame.o  \
#	source/API.SRC/mr_anim.o  source/API.SRC/mr_anim2.o  source/API.SRC/mr_anim3.o  \
#	source/API.SRC/mr_obj.o  source/API.SRC/mr_coll.o  source/API.SRC/mr_disp.o  \
#	source/API.SRC/mr_view.o  source/API.SRC/mr_mesh.o  source/API.SRC/mr_sprt.o  \
#	source/API.SRC/mr_light.o  source/API.SRC/mr_mem.o  source/API.SRC/mr_file.o  \
#	source/API.SRC/mr_debug.o  source/API.SRC/mr_input.o  source/API.SRC/mr_font.o  \
#	source/API.SRC/mr_quat.o  source/API.SRC/mr_fx.o  source/API.SRC/mr_pres.o  \
#	source/API.SRC/mr_part.o  source/API.SRC/mr_bin.o  source/API.SRC/mr_vram.o  \
#	source/API.SRC/mr_ot.o  source/API.SRC/mr_splin.o  source/API.SRC/mr_stat.o  \
#	source/API.SRC/mr_math.o  source/API.SRC/mr_sound.o  source/API.SRC/mr_over.o  \
#	source/API.SRC/mr_m_qua.o  source/API.SRC/mr_m_pak.o  \
#	source/API.SRC/mr_phlf3.o  source/API.SRC/mr_phlf4.o  \
#	source/API.SRC/mr_m_f3.o  source/API.SRC/mr_m_f4.o  source/API.SRC/mr_m_ft3.o  source/API.SRC/mr_m_ft4.o  \
#	source/API.SRC/mr_m_g3.o  source/API.SRC/mr_m_g4.o  source/API.SRC/mr_m_gt3.o  source/API.SRC/mr_m_gt4.o  \
#	source/API.SRC/mr_m_e3.o  source/API.SRC/mr_m_e4.o  source/API.SRC/mr_m_ge3.o  source/API.SRC/mr_m_ge4.o  \
#	--end-group \
#	source/fastram.o  source/binaries.o  source/mapasm.o
