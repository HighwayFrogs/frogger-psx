# Frogger PsyQ SDK  
If you are just trying to compile the game, this document is not the right one to read, refer to the main readme instead.  
This document details the contents of the SDK folder, where the binaries were sourced, and how the compilation process works.  
It is intended to be an aid when reading the `.bat` scripts created to compile the game.  

## The Basics
This folder contains the PSX SDK executables used to compile source code into something that runs on the PlayStation.  
In other words, this folder is mostly tools created for Sony given out to game developers so they could write code for the PlayStation.  
PsyQ is the name of this toolchain (by Psygnosis & SN Systems) for building PSX code.  
All of the PsyQ tools were sourced from "Programmer Tool" PlayStation SDK CDs.  

## PsyQ Version  
Frogger was built using tools mostly from PsyQ 4.0. Luckily, this version contains both 32-bit and 16-bit versions of tools, allowing for some flexibility we'll take advantage of below.  
One notable exception which was not used from PsyQ 4.0 was the compiler.  

## The Compiler
Frogger was compiled using DOS (Likely Windows 95), using 16-bit applications.  
In order to build a perfect match of the original game, the original compiler must be used. Or rather, if it doesn't it gets a bit more complicated.  
The compiler used to build Frogger (`CC1PSX.EXE`) has been identified as `GCC 2.6.3`, likely: `GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`.  
Unfortunately, the floppy containing this compiler version is rare and has not been dumped online.  
The workaround was to recreate this compiler's changes from the GCC source code as best as possible.  
`CC1PSX.EXE` is GCC 2.6.3 compiled by me (Kneesnap), with information and source code available in the `gcc-2.6.3` folder.  
`cc1-psx-263` is GCC 2.6.3 compiled for Linux from [here](https://github.com/decompals/old-gcc) by [sonicdcer](https://github.com/sonicdcer).  
Naturally, [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) is required for the Linux build. I used `Ubuntu 22.04.2 LTS`, but pretty much anything should work.  
If the original compiler ever surfaces, we can switch to using it in the DOSBox setup and remove WSL from the mix.  

## Runtime Libraries  
The runtime libraries in the `lib\` folder have been copied from PsyQ 4.0, and are the version the game was originally compiled with.  

**putchar.obj:**  
I'm trying to remember what happened here, but I think I had to extract this .obj from one of the PsyQ .lib files. I don't remember which one or how I did it.  
I may have just put the .lib into Ghidra (with the psx plugin installed) and extracted it through that. Or perhaps I used a tool from PsyQ. I don't recall.  

## Two Build Pipelines
There are build pipelines included for compiling the game. Both are similar, but contain key differences.  

### WSL (Windows Subsystem for Linux)
Because the original compiler executable is missing, a replacement was compiled [this repository](https://github.com/decompals/old-gcc) by [sonicdcer](https://github.com/sonicdcer).  
The output of this binary is a Linux binary. It may be possible to build this for Windows, but at the time of writing this was not a priority.  
Both build pipelines utilize [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) to run the `GCC 2.6.3 CC1 (cc1-psx-263)` C compiler.  
Installing WSL is optional, compilers are provided (of the wrong version) for use if WSL is missing.  

### Pipeline 1) Windows (Recommended)
This pipeline builds on Windows 10/11, and likely most earlier versions of Windows too.  
This pipeline is recommended because it is fast, works on Windows 10/11 with 32-bit executables, and is capable of building byte-matching builds.  

**Programs:**  
```
PsyQ 4.0 (Official PlayStation SDK):
 - ASMPSX.EXE: Assembler for hand-written assembly (.S -> .obj, 32-Bit)
 - ASPSX.EXE: Assembler for C Compiler (cc1psx -> aspsx -> .obj, 32-Bit)
 - CCPSX.EXE: Windows Version of GCC (Runs CC1PSX, ASPSX, and CPPPSX, 32-Bit)
 - CPPPSX.EXE: GNU C Preprocessor (Preprocesses .C, 32-Bit)
 - PSYLINK.EXE: PsyQ Linker (.obj -> .cpe, 32-Bit)

PsyQ 4.3 (Official PlayStation SDK):
 - DMPSX.EXE: Ensures gte instructions work properly. (Post-processes .obj, 32-Bit)
 - PSYLIB2.EXE: PsyQ Library Maker (.obj -> .lib, 32-Bit)
 PsyQ 4.3 was the first known Programmer Tool CD to include a 32-bit version of these programs, so they were sourced from this CD.

GCC 2.6.3 (Compiler):
 - CC1PSX.EXE: GNU C Compiler 2.6.3 modified for PSX (.C -> aspsx -> .obj, 32-bit)

Borland Make:
 - MAKE.EXE: I believe this is "Borland Make" dated 1993-12-02. https://winworldpc.com/product/borland-c/40
 I used this version of make from convenience. I had it lying around from when I made the Frogger 2 PSX compilation setup.
 Unfortunately, while Borland Make works great on 32-bit systems, trying to use it in DOSBox causes will encounter segfaults, which is why we use NMAKE in the other pipeline.
 The program 'make', for those unfamiliar is what can read a "Makefile", which is like a recipe which usually describes how to compile code.
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
PsyQ 3.5 (Official PlayStation SDK):
 - CC1PSX.EXE GNU C Compiler 2.6.0 (.C -> aspsx -> .obj, 16-Bit)
 - CCPSX.EXE: Windows Version of GCC (Runs CC1PSX, ASPSX, and CPPPSX, 16-Bit)
 - CPPPSX.EXE: GNU C Preprocessor (Preprocesses .C, 16-Bit)

PsyQ 4.0 (Official PlayStation SDK):
 - ASPSXD.EXE: PsyQ Assembler for C Compiler (cc1psx -> aspsx -> .obj, 16-Bit)
 - ASMPSXD.EXE: PsyQ Assembler for hand-written assembly (.S -> .obj, 16-Bit)
 - DMPSX.EXE: Ensures gte instructions work properly. (Post-processes .obj, 16-Bit)
 - PSYLIBD.EXE: PsyQ Library Maker (.obj -> .lib, 16-Bit)
 - PSYLINKD.EXE: PsyQ Linker (.obj -> .cpe, 16-Bit)

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

### Linux Setup?
It should be completely possible to create a working compilation setup on Linux using free software.  
In fact, I was able to compile code, but it eventually became clear the simpler route to creating a matching setup was to use the original toolchain, especially with the original makefile, linker script, etc.  
Perhaps in the future a complete build pipeline could be finished.  

**Miscellaneous Potentially Useful Info:**  
```
cc1-psx-263 combined with the mips gcc toolchain can be used to build Frogger, as seen in the DOSBox compilation setup.
However, CR LF line endings (\r\n) used by Windows completely break GCC, since outside of Windows everyone uses LF line endings (Just \n).
So, when you start encountering segfaults and/or syntax errors while trying to preprocess or compile this code in Linux, this is usually why.

Working GCC Toolchain:
sudo apt-get install -y git make gcc-mipsel-linux-gnu binutils-mipsel-linux-gnu python3 python3-pip

Code Formatter:
sudo apt-get install -y  clang clang-format clang-tidy-14
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