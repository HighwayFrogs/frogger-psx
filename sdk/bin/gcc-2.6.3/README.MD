# The Compiler
The original compiler binary was likely a version of `GCC 2.6.3` modified to support the Sony PlayStation (`GNU C 2.6.3.SN.2 [AL 1.1, MM 40] Sony Playstation compiled by GNU C`).  
Originally the compiler binary wasn't available, likely because [the floppy disk it was distributed on seems to be rare](https://www.psxdev.net/forum/viewtopic.php?f=28&p=22761). But in 2024, it was shared online. (Thanks logi26/logi1700!!)  
In order to get an accurate compilation, we of course need the same compiler as the original version.  
But since the original compiler executable is a 16-bit binary, it won't run on modern Windows computers.  
This folder contains recreations of `CC1PSX.EXE` which support Windows and Linux.  
The compilation setup in this repository will automatically grab the compiler in this folder and use it.  
The rest of the information here is for those who want to modify the compiler or build it themselves for whatever reason.  
In accordance with the GNU GPL v2, all source code has been included, with changes applied on October 23rd of 2023.  
Any further changes are unexpected, but their dates would be accessible in the git repository commit history.  

## How was the compiler version identified?  
Trying various different versions of GCC to see which ones produced output closest to the original game binaries.  

## How these were made.  
GCC is open source, and its license require and modified versions to have available source code.  
Unfortunately, only later versions of the PsyQ Compiler were made open source.  
However, by diffing those against unmodified GCC, it was possible to find all of the changes made to build their version of GCC.  
Additionally, the source code to LIBSN.A included in the PlayStation Programmer Tool CDs included much of the GCC modification code.  
By copying the changes onto an unmodified version of GCC 2.6.3, a build was made which appears to be accurate.  

## Generic File List
```
source\gcc-2.6.3.tar.bz2: Original GCC 2.6.3 source code. Obtained from https://ftp.gnu.org/old-gnu/gcc/
GNU.TXT: GNU GPL V2 License
```

## Windows x86 Version
This version of `CC1PSX.EXE` has been built with the intent of using it in the PsyQ toolchain.  
As such, the usage and flags enabled by default are intended to be identical to the original.  
A 64-bit version would be nice, but seeing as the first x86_64 processor came in 2003, nearly 10 years after GCC 2.6.3's release, this would likely take quite a bit of work.  

**File List:**  
```
Binary:
bin\win32\CC1PSX.EXE: A Windows x32 build of the C compiler, made to be used in the PsyQ toolchain. (Compiled by Kneesnap, Modifications applied by Kneesnap)

Source Code:
source\win32\GCC272S.ZIP: PsyQ Compiler Source code for GCC 2.7.2 Obtained from Runtime Library 4.6 CD DTL-S2360
source\win32\messy-backup.zip: If there are troubles with the psx\ folder for some reason, all the pre-setup files can be copy-pasted from this zip file.
source\win32\psx: Folder containing modified files necessary to build a PSX version of the compiler.
```

### Build Process
This process works on a Windows NT 4.0 virtual machine.
It is recommended to use [PCEm](https://www.pcem-emulator.co.uk/).
There is good reason to expect this to not work more recent operating systems.  
NOTE: The desktop folder is located at `C:\WINNT\Profiles\Administrator\Desktop`.  
**Steps:**  
 - 1) Extract the GCC 2.6.3 source code to a folder using 7-Zip from `gcc-2.6.3.tar.bz`.  
 - 2) Drag and drop the files in the `source\psx\` folder into GCC source folder, overwriting and conflicting files.  
 - 3) Install [Microsoft Visual C++ 4.0](https://winworldpc.com/product/visual-c/4x), or use msvc32s on the virtual machine.  
 - 4) Get the GCC folder onto the virtual machine if it was setup on your host machine. (Create an ISO file and mount it with a virtual CD drive)  
 - 5) Open a cmd window. If "cl.exe" is on not your path (determine by trying to run it), navigate to vcvars32.bat (from the Visual C++ install) and run it.  
 - 6) Navigate to the GCC folder.  
 - 7) Run `patch.bat`  
 - 8) Run `psx-build.bat`  
 - 9) Shut down the VM and close PCEm. 7-Zip can now open the hard drive and extract CC1PSX.EXE.  

## Linux x64 Version
Unlike the Windows version, this version expects all the default compiler flags to be provided by the user.  
This version should be very compatible, and with minimal changes it should support pretty much any architecture.  
This is effectively an offline backup of the [old-gcc repository](https://github.com/decompals/old-gcc/).  
When combined with [maspsx](https://github.com/mkst/maspsx), it is possible to use this old version of GCC with modern GNU AS, and other modern GNU build toolchain tools.  

**File List:**  
```
Binaries:
bin\linux-x64\cc1: A Linux x64 build of the compiler (from https://github.com/decompals/old-gcc/actions/runs/6883296765?pr=19) by mkst.
bin\linux-x64\cpp: A Linux x64 build of the C preprocessor (from https://github.com/decompals/old-gcc/actions/runs/6883296765?pr=19) by mkst.

Source Code:
source/linux/build.sh: Script for building GCC.
source/linux/patches: Patches to GCC 2.6.3 to make it support the PlayStation.
```

### Build Process
Run `sh ./build.sh` in the `source/linux/` folder.  
If run under WSL, there's a good chance you'll need to manually convert the line endings of build.sh and the patches from CRLF (Windows) to LF (Unix).  