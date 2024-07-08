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

# 1) Ensure current environment is capable of building Frogger.
# The ability to compile Frogger depends on case-sensitive file names. (Eg: We want everything to be lower-case, otherwise the preprocessor won't resolve #include statements)
# However, some file-system types (Primarily when running under Windows Subsystem for Linux) are case-insensitive, meaning the file 'TEST' is the same as a file named 'test'.
# It's probably just Windows/NTFS, but when this happens, the "mv" command fails to rename files, because Linux interfacing with the Windows file-system causes both files to be seen as the same hard link, a rename operation can't occur.
# TODO: It's been a while, and I don't recall if using some kind of bypass (Creating a replacement function for mv which renames the file to a temp file before renaming to the new target file.) would work, or if other complications occur.

# Prepare FS Case-Sensitivity Test
testFileNameUpper="FILENAME_CASE.TEST"
testFileNameLower="filename_case.test"
rm -f -- $testFileNameUpper
rm -f -- $testFileNameLower

# Run the test.
>$testFileNameUpper # Creates the empty test file.
mv $testFileNameUpper $testFileNameLower > /dev/null 2>&1
fsCaseTestResult=$?

# Cleanup test. (and shutdown if the test failed)
rm -f -- $testFileNameUpper
rm -f -- $testFileNameLower
if [ $fsCaseTestResult -ne 0 ]; then
    # This message is aimed primarily at non-technical people, which is why it's like this. The reason this won't work is explained above, since if you're reading this I assume you know what you're doing :P
    echo
    echo "The folder '$(pwd)' cannot be used to build Frogger."
    echo "This is because the file-system containing the folder is not case-sensitive."
    echo "This most likely means you are running under Windows Subsystem for Linux, or something similar."
    echo "Try cloning the repository somewhere in a non-Windows file-system."
	echo "Usually this will work in your home folder: '$HOME'"
    echo	
    exit 1
fi


# 2) Install required software
# dos2unix is required to convert CR LF (\r\n) line endings to LF (\n).
# git is required for installing maspsx. (Although, a backup has been included in this repository which is known to work, and can be manually setup by extracting it to sdk/maspsx/.)
# make is required to use the Linux makefile.
# gcc-mipsel-linux-gnu and binutils-mipsel-linux-gnu contain utilities for compiling MIPS programs and working with MIPS binaries. (In other words, it's how we're gonna get the executable.)
# python3 and python3-pip are required for maspsx.
echo "Installing packages..."
if [ $UID -eq 0 ]; then
	echo "Already running as root..."
	SUDO=""
else
	SUDO=sudo
fi

${SUDO} apt-get update && ${SUDO} apt-get install -y git make gcc-mipsel-linux-gnu binutils-mipsel-linux-gnu python3 python3-pip dos2unix


# 3) The first problem with building on Linux is that the Linux file-system is case-sensitive, but Windows is not.
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


# 4) There's a weird character that sometimes makes compilation not work. I'm not sure why, since it wasn't an issue at one point. Oh well.
echo "Removing garbage 0x1A character that causes syntax errors..."
find ./source/ -iname '*.[chs]' -exec sed -i 's/\x1A//g' {} \;
# Remove random 0x8 character in ./source/API.SRC/mr_view.c
find ./source/ -iname '*.[chs]' -exec sed -i 's/\x08//g' {} \;


# 5) Windows also uses CR LF line endings (\r\n), instead of LF line endings (\n)
# I think modern versions of GCC support CRLF line endings, but we're using GCC from 1994 in order to get byte-matching compiler output.
# This step should only run after file renames, because it will only find lower-case extensions.
# This may be optional, especially if you git clone'd on a Linux machine, since it'll clone all the files as LF already. However this has been kept for situations like WSL.
echo ""
echo "Converting CRLF line endings to LF..."
find ./source/ -iname '*.[chs]' | xargs dos2unix
find ./include/ -iname '*.h' | xargs dos2unix
find ./sdk/bin/gcc-2.6.3/source/linux/patches/ | xargs dos2unix
dos2unix ./sdk/bin/gcc-2.6.3/source/linux/build.sh


# 6) Setup maspsx
# If this fails, extract sdk/bin/src/maspsx.zip to sdk/maspsx/.
# Eg: In case maspsx ever goes away or changes in a way which breaks this setup, we have a backup from when it worked.
echo ""
echo "Adding maspsx..."
git submodule add --force https://github.com/mkst/maspsx ./sdk/maspsx


# 7) Setup gcc
chmod +x sdk/bin/gcc-2.6.3/bin/linux-x64/cc1
chmod +x sdk/bin/gcc-2.6.3/bin/linux-x64/cpp

# 8) Replace file paths that use backslashes with forward slashes.
echo ""
echo "Updating source files..."
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

# Avoid double definition of "Option_viewport_ptr". (Disabled)
# This is disabled since it seems this actually does compile/link somehow.
# We want to keep the duplicate definition since it impacts the instructions used to access Option_viewport_ptr in select.c (It will use $gp relative addressing with the double declaration, but it won't without it)
# My guess for why I originally thought I needed this is that maspsx supported very few of the scenarios we needed for Frogger when I wrote this, and maspsx might not have output assembly which allowed the same symbol declared in two objects.
#sed -i 's/MR_VIEWPORT\*\tOption_viewport_ptr;/\/\/MR_VIEWPORT*\tOption_viewport_ptr;/g' source/select.c TODO: Maybe extern it instead? Wrap it around an ifdef so it only happens for certain stuff? Dunno.

# 9) Misc Changes
# make expects the Makefile to be named Makefile (otherwise 'make -f MAKEFILE')
mv MAKEFILE Makefile

echo ""
echo "Setup complete, it should now be possible to build the game by running 'make'."
