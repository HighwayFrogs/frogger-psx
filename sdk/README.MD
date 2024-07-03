# Frogger PsyQ SDK  
If you are just trying to compile the game, this document is not the right one to read, refer to the main readme instead.  
This document details the contents of the SDK folder, where the binaries were sourced, and how the compilation process works.  
It is intended to be an aid when reading the `.bat` scripts created to compile the game.  

## The Basics
This folder contains the PSX SDK executables used to compile source code into something that runs on the PlayStation.  
In other words, this folder is mostly tools created for Sony given out to game developers so they could write code for the PlayStation.  
PsyQ is the name of this toolchain (by Psygnosis & SN Systems) for building PSX code.  
Most of the PsyQ tools were sourced from "Programmer Tool" PlayStation SDK CDs, otherwise they are specified where they came from.  

## PsyQ Version  
Frogger was built using tools mostly from PsyQ 4.0. Luckily, this version contains both 32-bit and 16-bit versions of tools, allowing for some flexibility we'll take advantage of below.  
One notable exception which was not used from PsyQ 4.0 was the compiler.  

## The Compiler
Frogger was compiled using DOS (Likely Windows 95), using 16-bit applications.  
In order to build a perfect match of the original game, the original compiler must be used. Or rather, if it doesn't it gets a bit more complicated.  
The compiler used to build Frogger (`CC1PSX.EXE`) has been identified as `GCC 2.6.3`, likely: `GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`.  
Unfortunately, the floppy containing this compiler version is rare and was not available either online or for purchase when this repository was setup.  
The workaround was to recreate this compiler's changes and apply them to the official GCC 2.6.3 source code to the best of our abilities.  
`CC1PSX.EXE` is GCC 2.6.3 compiled by me (Kneesnap), with information and source code available in the `gcc-2.6.3` folder.  
`cc1-psx-263` is GCC 2.6.3 compiled for Linux from [here](https://github.com/decompals/old-gcc) by [sonicdcer](https://github.com/sonicdcer).  
Luckily, the original compiler did eventually surface (Thank you logi26/logi1700!!!), but it ended up being a 16-bit executable. As such, it can only be used in the DOSBox build pipeline.  

## Runtime Libraries  
The runtime libraries in the `lib\` folder have been copied from PsyQ 4.0, and are the version the game was originally compiled with.  

**putchar.obj:**  
This file was probably extracted from some `.lib` file with Ghidra, then modified to closely match the data seen in the build of the game.  
Specific details have been forgotten, as it seems they were not documented. Here's my recollection of what happened.  
These are the steps:  
 - **1)** Install the [ghidra-psx-ldr](https://github.com/lab313ru/ghidra_psx_ldr) plugin installed in Ghidra.  
 - **2)** Drag the `LIBC2.LIB` file into Ghidra.  
 - **3)** It should ask what import mode you want since it has nested files. Select "File System".  
 - **4)** Right-click "PUTCHAR.OBJ", and click "Export".  
 - **5)** Modify the file with a hex editor, and replace the large existing function code with the handful of instructions seen in the actual game executable.  

## Two Build Pipelines
There are build pipelines included for compiling the game. Both are similar, but contain key differences.  

### Pipeline 1) Windows (Recommended)
This pipeline builds on Windows 10/11, and likely most earlier versions of Windows too.  
This pipeline is recommended because it is fast, works on Windows 10/11 with 32-bit executables, and is capable of building byte-matching builds.  

**Programs:**  
```
PsyQ 4.0 (Official PlayStation SDK):
 - CCPSX.EXE: Windows Version of GCC (Runs CC1PSX, ASPSX, and CPPPSX, 32-Bit)
 - CPPPSX.EXE: GNU C Preprocessor (Preprocesses .C, 32-Bit)
 - ASMPSX.EXE  v2.34: Assembler for hand-written assembly (.S -> .obj, 32-Bit)
 - ASPSX.EXE   v2.56: Assembler for C Compiler (cc1psx -> aspsx -> .obj, 32-Bit)
 - PSYLINK.EXE v2.52: PsyQ Linker (.obj -> .cpe, 32-Bit)

PsyQ 4.3 (Official PlayStation SDK):
 - DMPSX.EXE   v3.04: Ensures gte instructions work properly. (Post-processes .obj, 32-Bit)
 - PSYLIB2.EXE v2.05: PsyQ Library Maker (.obj -> .lib, 32-Bit)
 PsyQ 4.3 was the first known Programmer Tool CD to include a 32-bit version of these programs, so they were sourced from this CD.

GCC 2.6.3 (Compiler):
 - CC1PSX.EXE: GNU C Compiler 2.6.3 modified for PSX (.C -> aspsx -> .obj, 32-bit)

NMAKE:
 - NMAKE.EXE: This is the actual make program, described below.
 The program 'make', for those unfamiliar is what can read a "Makefile", which is like a recipe which usually describes how to compile code.
 In this case, nmake is the "brand" of make which was originally used in 1997 for building Frogger.
 It was obtained from Microsoft Visual C++ 4.0, obtained from https://winworldpc.com/product/visual-c/4x
```

### Pipeline 2) DOS (Not recommended)
This pipeline attempts to use the original binaries as closely as possible to compile byte-matching builds.  
Unfortunately, the original tools were 16-bit, so they can only be run in DOS, the precursor to Windows.  
While Windows XP (and other versions) were supposed to have compatibility with 16-bit programs, they crash with memory errors.  
While Windows 95/98 (built upon DOS) are capable of running these tools, the most convenient way to run them these days is with a DOS emulator, in our case [DOSBox](https://www.dosbox.com/).  
If you use this pipeline, you will need to install [DOSBox](https://www.dosbox.com/).  
This pipeline was primarily helpful for reverse engineering purposes, but fell out of favor once rhe other setup was finished.  
It is kept here because there isn't much of a need to remove it, and perhaps one day when Windows is obscure maybe this one would be easier to emulate?  
Either way don't use it for now.  

**Programs:**  
```
PsyQ 4.0 (Official PlayStation SDK):
 - These binaries are confirmed to byte-match, and are almost certainly the binaries originally used to build the game.
 - ASMPSXD.EXE  v2.34: PsyQ Assembler for hand-written assembly (.S -> .obj, 16-Bit)
 - ASPSXD.EXE   v2.56: PsyQ Assembler for C Compiler (cc1psx -> aspsx -> .obj, 16-Bit)
 - DMPSX.EXE    v3.03: Ensures gte instructions work properly. (Post-processes .obj, 16-Bit)
 - PSYLIBD.EXE  v2.07: PsyQ Library Maker (.obj -> .lib, 16-Bit)
 - PSYLINKD.EXE v2.52: PsyQ Linker (.obj -> .cpe, 16-Bit)
 
DTL-S2110 v4.04 Floppy Disk 1 (CONFIRMED WRONG VERSIONS):
 - ASMPSX.EXE  v1.32: Fails to assemble the original unmodified .S files, as it does not recognize certain opcodes.
 - ASPSX.EXE   v2.21: Does not recognize the -0 option, which was confirmed added after PSX Build 49.
 - PSYLIB.EXE  v1.07: Creates a non-matching build (compared to PSX Build 71) when used in an otherwise matching compilation setup.
 - PSYLINK.EXE v1.42: This linker version failed to find certain symbols from the SDK libraries
 
DTL-S2110 v4.04 Floppy Disk 2:
 - CC1PSX.EXE GNU C Compiler 2.6.3 (.C -> aspsx -> .obj, 16-Bit)
 - CCPSX.EXE: DOS Version of GCC (Runs CC1PSX, ASPSX, and CPPPSX, 16-Bit)
 - CPPPSX.EXE: GNU C Preprocessor (Preprocesses .C, 16-Bit)

NMAKE:
 - NMAKE.EXE: This is the actual make program, described below.
 - DOSXNT.EXE: This is apparently a "DOS Extender". (What that is is unimportant, just know it lets DOS programs get around certain limitations of DOS.)
 The program 'make', for those unfamiliar is what can read a "Makefile", which is like a recipe which usually describes how to compile code.
 In this case, nmake is the "brand" of make which was originally used in 1997 for building Frogger.
 Both of the programs here came from Microsoft Visual C++ 4.0, obtained from https://winworldpc.com/product/visual-c/4x
```

## Extra Tools
There are a few additional tools included, their purposes are described below.  

**Programs:**  
```
cpe2exe.exe:
Converts .cpe PSX executables to .exe PSX executables.
This is a a replacement to the original CPE2X.EXE from PsyQ.
I modified the code so it could work with large .cpe files, something the original could crash with.
Source code is available in the `src\` folder.

The source code to both of these programs are available at: https://github.com/Lameguy64/mkpsxiso (Licensed with GPLv2)
dumpsxiso.exe: This program extracts all of the files from a Frogger disc image, and makes a template for how to recreate the PSX iso image.
mkpsxiso.exe: This program creates PSX iso images using the templates created by dumpsxiso.exe.
```

```
This is a note for when the Linux version is ready.
### WSL (Windows Subsystem for Linux)
A Linux version of the compiler has been built from [this repository](https://github.com/decompals/old-gcc) by [sonicdcer](https://github.com/sonicdcer).  
The Linux build pipeline can be used on Windows via [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) to run the `GCC 2.6.3 CC1 (cc1-psx-263)` C compiler.  
Naturally, [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) is required for the Linux build. I used `Ubuntu 22.04.2 LTS`, but pretty much anything should work.  
```

## Linux Build Pipeline?
It should be completely possible to create a working compilation setup on Linux using free software.  
In fact, I was able to compile code, but it eventually became clear the simpler route to creating a matching setup was to use the original toolchain, especially with the original makefile, linker script, etc.  
Perhaps in the future a complete build pipeline could be finished.  


**Miscellaneous Potentially Useful Info:**  
```
cc1-psx-263 combined with the mips gcc toolchain can be used to build Frogger, as seen in the DOSBox compilation setup.
However, CR LF line endings (\r\n) used by Windows completely break GCC, since outside of Windows everyone uses LF line endings (Just \n).
So, when you start encountering segfaults and/or syntax errors while trying to preprocess or compile this code in Linux, this is usually why.

Working GCC Toolchain:
sudo apt-get install -y git make gcc-mipsel-linux-gnu g++-mipsel-linux-gnu binutils-mipsel-linux-gnu python3 python3-pip

Code Formatter:
sudo apt-get install -y  clang clang-format clang-tidy-14

Compilation Examples:

1) Convert CR LF (\r\n) line endings to LF (\n), for compatibility with Linux tools:
awk '{ sub("\r$", ""); print }' "source/FROG.C" > "source/FROG-LF.C"

2) Preprocess with modern GNU (mipsel-linux-gnu-cpp instead of cpppsx.exe):
mipsel-linux-gnu-cpp -Iinclude -undef -Wall -fno-builtin -Dmips -D__GNUC__=2 -D__OPTIMIZE__ -D__mips__ -D__mips -Dpsx -D__psx__ -D__psx -D_PSYQ -D__EXTENSIONS__ -D_MIPSEL -D_LANGUAGE_C -DLANGUAGE_C -DHACKS -DUSE_INCLUDE_ASM -lang-c source/FROG-LF.C > source/FROG-PREPROC.C
NOTE: I got an error "mipsel-linux-gnu-cpp: fatal error: cannot execute ‘cc1plus’: execvp: No such file or directory", because I didn't have "g++-mipsel-linux-gnu" installed.
This doesn't seem to produce compileable output for the old version, which is odd because in a decomp setup it compiles just fine.

3) Compile Preprocessed FROG.C GNU (& Fix the Assembly Code):
cat source/FROG-PREPROC.C | ./sdk/bin/gcc-2.6.3/cc1-psx-263 -O3 -G0 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -quiet -mcpu=3000 -fgnu-linker -mgas -gcoff > source/FROG-ASM.S

4) Update assembly with maspsx
cat source/FROG-ASM.S | python3 tools/maspsx/maspsx.py --no-macro-inc >> src/main/FROG.asm

4) Assemble with GNU Assembler/AS (mipsel-linux-gnu-as instead of aspsx.exe):
mipsel-linux-gnu-as -Iinclude -march=r3000 -mtune=r3000 -no-pad-sections -O1 -G0 src/main/FROG.asm -o src/main/FROG.o
You'll get a .o file, which is a completely different format from what aspsx.

Linker Info:
Unfortunately, I have no idea how to link the .o objects into a PSX executable from this point.
Other PSX decomp projects should probably get checked out.
You'll need to use ld of course, but I am not sure how to make a linker script that LD likes.

See the DOS pipelinecat FROG.PRE | ./sdk/bin/cc1-psx-263 -O3 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -quiet -mcpu=3000 -fgnu-linker -mgas -gcoff > FROG.S
cat src/main/FROG.PRE | ./bin/cc1-psx-263 -O3 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -quiet -mcpu=3000 -fgnu-linker -mgas -gcoff > src/main/FROG.S
aspsx.exe -q FROG.S -o FROG.OBJ


Windows Example (Build 49, NOT Retail):
ccpsx -save-temps -v -comments-c++ -c -Wunused -Wmissing-prototypes -Wuninitialized -O3 mapview.c
OR
cpppsx.exe -undef -D__GNUC__=2 -v -Wunused -Wmissing-prototypes -Wuninitialized -D__OPTIMIZE__ -lang-c -Dmips -D__mips__ -D__mips -Dpsx -D__psx__ -D__psx -D__EXTENSIONS__ -D_MIPSEL -D__CHAR_UNSIGNED__ -D_LANGUAGE_C -DLANGUAGE_C mapview.c C:/build/temp/QLJHWRNT
cc1psx.exe -quiet -version -Wunused -Wmissing-prototypes -Wuninitialized -O3 C:/build/temp/QLJHWRNT -o C:/build/temp/JFTSBZIG
aspsx.exe -q C:\build\temp\JFTSBZIG -o mapview.obj
```

## Ghidra Scripts
Ghidra was used extensively in understanding and reverse engineering the game, and there are many scripts which have been included which were helpful.  
These were used to assist in both attempting to understand the game and also to assist in making a matching build.   
Many of these were made long ago.

**Scripts:**  
```
DataTester.java: Prints the location of all data between two executables which do not match.  
FunctionGPApplier.java: Applies the hardcoded value of $gp to all functions. I forget why this was useful.
ImageNameImporter.java: Given a list of images and texture ids exported by FrogLord, apply those names to pointers in the global texture array. (Helpful for finding code which uses images, or for matching the bss section in Frogger)
ImportPsyQMap.py: Imports symbols from a .MAP file into a ghidra project. (Very useful for matching)
LevelNameImporter.java: Generates texture names by reading data from the Sel_arcade_levels symbol and SELECT.C from source code. Also outputs a copy-pastable configuration for FrogLord image names. Make sure to update the constants before running.
ParseDataTypesFromCode.java: Parses header files from a directory to try importing all the types into the ghidra project, as well as generating a decomp.me context. It probably only works with Frogger and is pretty hacky.
SignatureTester.java: Allows comparing of different ghidra programs, comparing their functions to ensure their functionID hashes match.
SoundTableExporter.java: Generates a sound table for Frogger's sound.c from the actual sound table in the executable.
VramHeaderExporter.java: Used to generate texmacro.h. For further explanation, see the documentation in the 'vlo\' folder.
```