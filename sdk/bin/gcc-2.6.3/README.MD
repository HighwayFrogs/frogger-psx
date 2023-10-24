# The Compiler
The original compiler binary was a modified version of `GCC 2.6.3` (likely `GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`).  
This version has not yet surfaced online, likely because the floppy disk it was distributed on seems to be rare.  
In order to get an accurate compilation, we of course need the same compiler as the original version.  
This folder contains a build of `CC1PSX.EXE` which seems to be an accurate recreation of the original compiler, which runs on 32-bit Windows platforms.  
The compilation setup in this repository will automatically grab the compiler in this folder and use it.  
The rest of the information here is for those who want to modify the compiler or build it themselves for whatever reason.  
In accordance with the GNU GPL v2, all source code has been included, with changes applied on October 23rd of 2023.  
Any further changes are unexpected, but their dates would be accessible in the git repository commit history.  

## How was the compiler version identified?  
Trying various different versions of GCC to see which ones produced output closest to the original game binaries.  

## How it was made.  
GCC is open source, and its license require and modified versions to have available source code.  
Unfortunately, only later versions of the PsyQ Compiler were made open source.  
However, by diffing those against unmodified GCC, it was possible to find all of the changes made to build their version of GCC.  
By copying the changes onto an unmodified version of GCC 2.6.3, a build was made which appears to be accurate.  

## File List
```
cc1-psx-263: A Linux x64 build of the compiler from (https://github.com/decompals/old-gcc) by sonicdcer.
CC1PSX.EXE: The compiler itself, compatible with the PsyQ toolchain
GNU.TXT: GNU GPL V2 License
source\gcc-2.6.3.tar.bz2: Unmodified GCC 2.6.3 source code. Obtained from https://ftp.gnu.org/old-gnu/gcc/
source\GCC272S.ZIP: PsyQ Compiler Source code for GCC 2.7.2 Obtained from Runtime Library 4.6 CD DTL-S2360
source\messy-backup.zip: If there are troubles with the psx\ folder for some reason, all the pre-setup files can be copy-pasted from this zip file.
source\psx: Folder containing modified files necessary to build a PSX version of the compiler.
```

## Build Process
This process works on a Windows NT 4.0 virtual machine. No other operating systems or setups have been tested, and there is good reason to expect this to not work more recent operating systems.  
 - 1) Install Microsoft Visual C++ 4.0, or obtain msvs32s, or get a way to use this compiler through some means.  
 - 2) Extract the GCC 2.6.3 source code to a folder.  
 - 3) Drag and drop the files in the `source\psx\` folder into GCC source folder, overwriting and conflicting files.  
 - 4) Open a cmd window. If "cl.exe" is on not your path (determine by trying to run it), navigate to vcvars32.bat (from the Visual C++ install) and run it.  
 - 5) Navigate to the folder with the GCC source code.  
 - 6) Run `patch.bat`  
 - 7) Run `psx-build.bat`  
 - 8) CC1PSX.EXE should exist after compilation.  