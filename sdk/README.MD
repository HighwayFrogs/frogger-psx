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
The compiler used to build Frogger (`CC1PSX.EXE`) has been identified as `GCC 2.6.3` aka `GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`.  
Unfortunately, the floppy containing this compiler version is rare and has not been dumped online.  
The workaround to this problem is to use `cc1-psx-263`, which is GCC 2.6.3 compiled for Linux from [here](https://github.com/decompals/old-gcc) by [sonicdcer](https://github.com/sonicdcer).  
Naturally, [Windows Subsystem for Linux](https://learn.microsoft.com/en-us/windows/wsl/install) is required. I used `Ubuntu 22.04.2 LTS`, but pretty much anything should work.  
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

### Pipeline 1) Windows
This pipeline builds on Windows 10/11, and likely most earlier 64-bit versions of Windows.  
The first setup available to build the game is built to be straightforward, however it will not create an accurate byte-match to the official executable.  
**TODO: The byte-match is actually untested since switching to 4.0 tools, it may be compatible after all. Update this section once testing has occurred.**   

**Programs:**  
```
PsyQ 4.0 (Official PlayStation SDK):
 - ASMPSX.EXE: Assembler for hand-written assembly (.S -> .obj, 32-Bit)
 - ASPSX.EXE: Assembler for C Compiler (cc1psx -> aspsx -> .obj, 32-Bit)
 - CC1PSX.EXE GNU C Compiler 2.7.2 (.C -> aspsx -> .obj,  32-Bit)
 - CCPSX.EXE: Windows Version of GCC (Runs CC1PSX, ASPSX, and CPPPSX, 32-Bit)
 - CPPPSX.EXE: GNU C Preprocessor (Preprocesses .C, 32-Bit)
 - PSYLINK.EXE: PsyQ Linker (.obj -> .cpe, 32-Bit)

PsyQ 4.3 (Official PlayStation SDK):
 - DMPSX.EXE: Ensures gte instructions work properly. (Post-processes .obj, 32-Bit)
 - PSYLIB2.EXE: PsyQ Library Maker (.obj -> .lib, 32-Bit)
 PsyQ 4.3 was the first known Programmer Tool CD to include a 32-bit version of these programs, so they were sourced from this CD.


Borland Make:
 - MAKE.EXE: I believe this is "Borland Make" dated 1993-12-02. https://winworldpc.com/product/borland-c/40
 I used this version of make from convenience. I had it lying around from when I made the Frogger 2 PSX compilation setup.
 Unfortunately, while Borland Make works great on 32-bit systems, trying to use it in DOSBox causes will encounter segfaults, which is why we use NMAKE in the other pipeline.
 The program 'make', for those unfamiliar is what can read a "Makefile", which is like a recipe which usually describes how to compile code.
```


### Pipeline 2) DOS
This pipeline attempts to use the original toolchain as closely as possible.  
Unfortunately, the original tools were 16-bit, so they can only be run in DOS, the precursor to Windows.  
While Windows XP (and other versions) were supposed to have compatibility with 16-bit programs, they crash with memory errors.  
While Windows 95/98 (built upon DOS) are capable of running these tools, the most convenient way to run them these days is with a DOS emulator, in our case [DOSBox](https://www.dosbox.com/).  
If you use this pipeline, you will need to install [DOSBox](https://www.dosbox.com/).  

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
cc1-psx-263 combined with the mips gcc toolchain can be used to build Frogger.
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
VramHeaderExporter.java: Used to generate frogvram.c. The nuance of this is described in the .bss documentation.
```

## Making an accurate .bss section
In order to get a perfectly matching executable built, all data must be ordered exactly the same in the executable.  
Unfortunately, the original assembler & linker (`ASPSX` and `PSYLINK`) have some annoying design choices, which were determined via reverse engineering.  
Both the linker and assembler use a hash table to keep track of uninitialized global variables (Stuff that goes in the .bss section).  
When it's time to write the file output, they sequentially read through the hash tables to write out their symbols to the binary.  
This means instead of using the order in which symbols are defined (how everything else works), the order of the `.bss` section is determined by the order of the symbols put into the hash table.  
And yes, because this occurs in both the assembler and linker separately, this gets quite complicated.
So, the question is what determines the order of the entries in the hash table?  

### Hash Table Order
Both hash tables while similar, have differences. It starts with the number of slots available in the hash table.  
Each hash table is a fixed-size array pointing to a linked list of bss symbols. The hash table in the assembler contains 256 slots (0-255), while the hash table in the linker contains 512 slots (0-511).  

### The Hashing Algorithm
TODO: Explain

### Testing Order Validity
The following is a checklist which can be followed to determine if two symbols are ordered in the way they would be if compiled by the linker.  
While this could be used to make a sorting algorithm, it is used here for demonstration.   

1) Compare lastLinkerHash with currLinkerHash:  
 - If previousLinkerHash > currLinkerHash, The order is incorrect
 - If previousLinkerHash < currLinkerHash, The order is correct
 - If previousLinkerHash == currLinkerHash, continue to step 2.

2) Reversed Assembler Order
The linker loads .obj files in the order which they are linked (in the linker script .LNK).  
Then, they are put into the linker hash table in the reverse order they were loaded from the .OBJ.  
So, the comparison is as follows:

TODO: !

3) Compare the assembler hash
 - If currAssemblerHash > previousAssemblerHash, The order is incorrect
 - If currAssemblerHash < previousAssemblerHash, The order is correct
 - If currAssemblerHash == previousAssemblerHash, The order is correct
 
4) 


// How exactly does the length sort work?
// It's not actually done in the linker, and it's not even explicit as previously assumed.
// For hash values under 256, we know the result of the assembler hash is the same as the linker hash on the modulo side.
// But it's slightly different still. The assembler hash doesn't consider length, while the linker hash does.
// This means if you have two strings with different lengths but a matching linker hash, the larger string will have a smaller assembler hash.
// So, this will effectively sort the strings from largest to smallest, which when read backwards by the linker, will be reversed and cause the smaller strings to be placed first.


 TODO: Explain how length sorting works.



TODO: Do we need to get the textures in the file ordered properly? Order does matter, but to be honest the output doesn't line up with what the comments suggest.