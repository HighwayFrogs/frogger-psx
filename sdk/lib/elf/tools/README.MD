# Psy-Q Library Conversion Tools
These tools are used by the library conversion batch script.  

**psyq-obj-converter:**  
Links: [Source Code](https://github.com/grumpycoders/pcsx-redux/blob/main/tools/psyq-obj-parser/psyq-obj-parser.cc) [Windows x64 Builds](https://distrib.app/pub/org/pcsx-redux/project/dev-win-x64) [Linux x64 Builds](https://distrib.app/pub/org/pcsx-redux/project/dev-linux-x64)  
Download: A pre-built exe is included as part of the [PCSX Redux](https://github.com/grumpycoders/pcsx-redux) emulator.  

This tool is used to convert Psy-Q .obj files into ELF files (usable with the GNU Linker).  
The .OBJ come from extracting a .LIB file, and once converted to elf, can be added to an ELF Archive (.a).  

Many thanks to Nicolas Noble from PSXDev for both making the psyq-obj-converter program, but also fixing an issue that prevented several objects from converting successfully.  

Other Resources for this format:  
 - [ghidra_psx_ldr](https://github.com/lab313ru/ghidra_psx_ldr/blob/master/src/main/java/psyq/PsyqLoader.java)
 - [psyq2elf](https://gitlab.com/jype/psyq2elf/-/blob/master/src/elf_obj.c)
 - [Technical Info](https://www.psxdev.net/forum/viewtopic.php?f=62&t=1582)