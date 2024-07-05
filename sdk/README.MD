# Frogger PsyQ SDK  
If you are just trying to compile the game, this document is not the right one to read, refer to the main readme instead.  
This document details the contents of the SDK folder, where the binaries were sourced, and how the compilation process works.  
It is intended to be an aid when reading the `.bat` and `.sh` scripts which compile the game.  

## The Basics
This folder contains the PSX SDK executables used to compile source code into something that runs on the PlayStation.  
In other words, this folder is mostly tools created for Sony given out to game developers so they could write code for the PlayStation.  
PsyQ is the name of this toolchain (by Psygnosis & SN Systems) for building PSX code.  
Most of the PsyQ tools and libraries were sourced from "Programmer Tool" PlayStation SDK CDs.  

## PsyQ Version  
Frogger was built using tools mostly from PsyQ 4.0. Luckily, this version contains both 32-bit and 16-bit versions of tools, allowing for some flexibility we'll take advantage of below.  
One notable exception which was not used from PsyQ 4.0 was the compiler.  

## The Compiler
Frogger was compiled using DOS (Likely Windows 95), using mostly 16-bit applications.  
In order to build a perfect match of the original game, the original compiler must be used. Or rather, if it doesn't it gets a bit more complicated.  
The compiler used to build Frogger (`CC1PSX.EXE`) has been identified as `GCC 2.6.3`, likely: `GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`.  
Unfortunately, the floppy containing this compiler version is rare and [was not available either online or for purchase when this repository was setup](https://www.psxdev.net/forum/viewtopic.php?f=28&t=4122).  
The workaround was to recreate this compiler's changes and apply them to the official GCC 2.6.3 source code to the best of our abilities.  
Those recreations have compiled builds (and their source code) for both Windows and Linux available in the `gcc-2.6.3` directory.  
Luckily, the original compiler did eventually surface (Thank you logi26/logi1700!!!), but it ended up being a 16-bit executable. As such, it can only be used in the DOSBox build pipeline.  

## Runtime Libraries  
The runtime libraries in the `lib\` folder have been copied from PsyQ 4.0, and are the version the game was originally compiled with.  
For compilation on Linux systems, the normal ELF libraries are provided in `lib-elf\` folder were converted to ELF from .LIB using the `lib-elf\convert-libs.bat` script.  

**putchar.obj:**  
This object was recreated by assembling the following file with the command: `ASPSX.EXE putchar.s -o putchar.obj`.  

putchar.s:  
```gas
	.set	noat
	.set	noreorder
	.text

    .global putchar
    putchar:
		addiu      $10, $0, 0xB0
		jr         $10
		addiu      $9, $0, 0x3D
		nop
```

## Build Pipelines
There are several build pipelines included for compiling the game, each built for different reasons.  

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

GCC 2.6.3 (Compiled By Knee):
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
This pipeline was primarily helpful for reverse engineering purposes, but fell out of favor once the other setup was finished.  
It is kept here because there isn't much of a need to remove it, and perhaps one day when Windows is obscure maybe this one would be easier to emulate?  
Either way, the Windows build pipeline is magnitudes faster, doesn't crash, and works on Windows 10/11.  

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

### Pipeline 3) GNU/Linux (Fully Open Source)
At the time of writing, Windows is capable of running 32 bit applications, but there is no guarantee how long this support will last.  
While it is possible to use DOSBox or Wine on Linux to build the game, a native open source build toolchain still has its benefits.  
Given how much work was already done (compiling custom GCC, using a Linux decompilation toolchain, etc), there wasn't much work left to make a full Linux build pipeline.  
In order to use the Linux pipeline, run `./setup-linux.sh` in the repository root. Then, running `make` should build the game.  

**Programs:**  
```
GCC 2.6.3 (Modified for PlayStation):
 - Partially based on https://github.com/decompals/old-gcc/
 - CPP: GNU C Preprocessor (.C -> cc1 -> as, x64, PsyQ Equivalent: CPPPSX.EXE)
 - CC1: GNU C Compiler 2.6.3 (cpp -> as -> .o, x64, PsyQ Equivalent: CC1PSX.EXE)

Modern GCC & binutils (apt packages: gcc-mipsel-linux-gnu, binutils-mipsel-linux-gnu):
 - Modern GCC programs can be used to replace the job of some of the original PsyQ SDK, without losing byte-accuracy.
 - mipsel-linux-gnu-as: GNU Assembler (Assembly & Compiler Output -> .o, PsyQ Equivalent: ASPSX.EXE)
 - mipsel-linux-gnu-ar: Creates .A libraries from .o compiler objects. (PsyQ Equivalent: PSYLIB2.EXE)
 - mipsel-linux-gnu-ld: LD Linker (Many .o/.a files -> single .elf, PsyQ Equivalent: PSYLINK.EXE)
 - mipsel-linux-gnu-objcopy: Used to get raw data out of the .ELF (used when converting .ELF to PSX .EXE)
 - make: GNU Make (Builds the project from the makefile)

MASPSX:
 - Source Code: https://github.com/mkst/maspsx (A backup is also included in this repository)
 - Because ASPSX.EXE was a custom assembler created for the PsyQ toolchain, it had some differences from the GNU Assembler (mipsel-linux-gnu-as). It was also rather old.
 - MASPSX.EXE is a pre-processing layer that applies changes to the assembly text before it is passed to the assembler.
 - These changes modify the code so it produces the same output the original assembler did.
 - Requires python3 (apt-get install python3 python3-pip)
```

#### WSL Support (Windows Subsystem for Linux)
The Linux build pipeline can be used on Windows via [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) to run the `GCC 2.6.3 CC1 (cc1-psx-263)` C compiler.  
However, the repository should not be cloned to an NTFS file system. In other words, **DO NOT** use a path such as `/mnt/c/Users/kneesnap/projects/frogger-psx`), use somewhere in the WSL file system like `/home/kneesnap/projects/frogger-psx`.  
Naturally, [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) is required for the Linux build. I used `Ubuntu 22.04.2 LTS`, but pretty much anything should work.  

#### Problems Solved
The challenges with creating a Linux build pipeline have been documented here, with their solution.  

**1) Line Endings:**  
Linux uses LF (\n) line endings, while Windows uses CRLF (\r\n) line endings.  
The old version of GCC used by Frogger doesn't recognize CRLF line endings when run on Linux.  
Thus, when building in environments such as WSL (Windows Subsystem for Linux), syntax errors will be thrown, sometimes with a segfault.  
The solution to this was automated in `setup-linux.sh`, which will convert line endings to LF.  

**2) File Name Case Sensitivity:**  
The Windows NTFS filesystem is not case-sensitive. So, `FROG.C` will be opened if someone asks to open `frog.c`.  
However, this is not the case on Linux. Unfortunately, this is a problem for Frogger.  
All of the #include statements in its source code use fully lower-case file names, but the actual file names have varying capitalizations, meaning those files will not be found.  
This issue does not occur when running WSL on a Windows file-system due to Windows file-system rules still applying.  
The solution was to make `setup-linux.sh` rename all files to become lower-case.  

**3) Handwritten Assembly (ASMPSX.EXE):**  
Unfortunately, the original PsyQ toolchain had two assemblers, `ASPSX.EXE` and `ASMPSX.EXE`.  
While `ASPSX.EXE` is very similar to the GNU Assembler since it was used for compiler output, `ASMPSX.EXE` was meant for handwritten assembly and used a completely custom/proprietary syntax.  
There is no equivalent program for `ASMPSX.EXE`, so the decision was made to rewrite the handwritten assembly files into the GNU Assembler syntax, and just re-use the GNU Assembler.  
The converted files can be found [here](source/linux/).  

**4) Converting Libraries:**  
The official Psy-Q SDK Libraries must be included in the executable so the game code can call the functions used to interact with PSX hardware.  
Unfortunately, SN Systems made a proprietary format for their compiler objects, libraries, and executables.  
Linux tools primarily support ELF binary files, and they are incompatible with the .OBJ and .LIB files included in the PsyQ SDK.  
Luckily, it was possible to convert the files into ELF files compatible with Linux tools by creating [this batch script](/source/sdk/lib-elf/convert-libs.bat).  
The pre-converted libraries have been included, and no conversion is necessary unless you want to use another library which was not included.  

**5) Linker Script:**  
Using a custom linker script (LD) based on [this](https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/ps-exe.ld), we can create a PSX binary.  
TODO: Document this further. 
TODO: Get into the details about maspsx.
TODO: ! 

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
A checkout of this code has been included in this repository as a backup too.
dumpsxiso.exe: This program extracts all of the files from a Frogger disc image, and makes a template for how to recreate the PSX iso image.
mkpsxiso.exe: This program creates PSX iso images using the templates created by dumpsxiso.exe.
```

### Ghidra Scripts
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