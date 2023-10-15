# Frogger PsyQ SDK  
This folder contains the PSX SDK executables used to compile source code into something that runs on the PlayStation.  
In other words, this folder is mostly tools created by Sony and given out to game developers so they could write code for the PlayStation.  
The version used to compile Frogger was PsyQ 3.5. However, PsyQ 3.5 can only be used on systems that can run 16-bit DOS programs.  
For this reason, PsyQ 4.0 (the first version which was a 32-bit application) has been chosen for most of the applications.  
For the compiler, we have chosen to use a version of GCC 2.6.3 built for Linux, as well as masmpsx. These applications require WSL to run.  
If this isn't an option, try using cc1psx.exe, and aspsx.exe from PsyQ 3.5 with DOSBox.  

**Programs:**  
```
PsyQ 4.0 (Official Sony PlayStation SDK):
ASMPSX.EXE: Assembler for hand-written assembly files (.S -> .obj)
ASPSX.EXE: Assembler for C Compiler Output (cc1psx -> aspsx -> .obj)
CC1PSX.EXE C Compiler (.C -> aspsx -> .obj)
CCPSX.EXE: Effectively GCC.EXE (Calls the preprocessor, compiler, and assembler I think)
CPPPSX.EXE: C Preprocessor (.C -> preprocessed .C)
PSYLINK.EXE: The Linker (Creates the game executable from all of the .obj compiler objects)

PsyQ 4.3 (Official Sony PlayStation SDK):
DMPSX.EXE: I forget why this exe is needed. PsyQ 4.0 only includes a 16bit version of this program, so I went for 4.3 instead.
PSYLIB2.EXE: This is a special linker which creates .lib (library) files from .obj compiler objects. PsyQ 4.0 only had PSYLIB.EXE, 4.3 was the first one I saw with PSYLIB2.EXE

Borland Make:
Borland Make is compatible with both 16 bit and 32 bit systems, which makes it preferable to nmake, since we want to support both.
MAKE.EXE: I believe this is "Borland Make" dated 1993-12-02. I nabbed this from Frogger 2's PSX compilation setup which I made earlier. I believe I got it from https://winworldpc.com/product/borland-c/40
Unfortunately, while Borland Make works great on 32-bit systems, trying to use it with the original 16-bit compilers in DOSBox causes segfaults. So NMAKE is preferred in that case.

NMAKE:
NMAKE.EXE (And the required DOSXNT.EXE to accompany it) came from Microsoft Visual C++ 4.0 at https://winworldpc.com/product/visual-c/4x
It is used as the make program for compiling under DOSBox + with the 16 bit compilers.
Originally I grabbed this from the Visual Studio '97 backup on the Frogger 2 tape at `\\BLITZONE\DATA\TeamSpirit\pcversion\DevStudio\VC\bin\NMAKE.EXE`.
But, this doesn't cut it for DOSBox since it's 32 bit only.

Misc:
cpe2exe.exe: Converts .cpe PSX executables to .exe PSX executables. I modified the code to work with arbitrarily large .cpe files. Source code in `src\`.

ISO Tools:
mkpsxiso.exe & dumpsxiso.exe: These programs are used to make and dump PSX iso images.
dumpsxiso.exe: This program extracts all of the files from a Frogger disc image, and makes a template for how to recreate the PSX iso image.
mkpsxiso.exe: This program creates PSX iso images using the templates created by dumpsxiso.exe.
The source code to both of these programs is available at: https://github.com/Lameguy64/mkpsxiso (Licensed with GPLv2)

```

## Runtime Libraries  
The runtime libraries in the `lib\` folder have been copied from PsyQ 4.0 as well.  
This time, it's because the game was using 4.0 runtime libraries, not because of any incompatiblity.  

**putchar.obj:**  
I'm trying to remember what happened here, but I think I had to extract this .obj from one of the PsyQ .lib files. I don't remember which one or how I did it.  
I may also be incorrect / misremembering.  