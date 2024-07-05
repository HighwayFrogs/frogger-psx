![Frogger Logo](/logo.png)
# Frogger He's Back (PlayStation)
This repository contains a modified source backup of Frogger (1997), commonly called Frogger: He's Back.  
The source backup appears to be from September 3, 1997, less than 3 weeks before the retail NTSC version.  
However, the code has been modified (via a matching decompilation project) to perfectly byte-match the retail version of the game.  
In other words, this repository can builds an exact copy of the game executable found on a playable game CD. (As in, every single byte matches exactly.)  

**Developer:** Milennium Interactive (Defunct)  
**Publisher:** Hasbro Interactive (Sorta Defunct)   

## What versions does this build?
Currently, this repository is capable of building exact matches for:  
 - `PSX Build 49 (September 3 1997)` (SHA1 Hash: `0996e989b9c9c5702b8cb02cfc157db1136b0f72`)  
 - `PSX Build 71 (Retail US / NTSC)` (SHA1 Hash: `05cbe0ece8f267970ad9c1aabca2a2a7ec6bbcd6`)  
 
NOTE: PSX Build 49 is buildable by switching to the `psx-build49` branch, which contains the code before the retail version was byte-matched.  

**PSX Version Only:**  
This contains only the PSX version code. The PC version relied upon proprietary libraries which were not included.  
If those libraries were reverse engineered (they have debug symbols), it would likely be possible to compile the PC version, or at least a prototype version.  
Unfortunately, the PC version received two months of extra development after the PSX version was complete, likely to improve network multiplayer, compatibility, performance, and to add support for low poly mode.  
None of that work is present in this backup, and not many details are know about PC version differences anyways.  
This code could be ported to PC, but such an effort has not been attempted.  

## How to compile & run?
Compilation has been verified working on Windows 10, Windows 11, and Ubuntu 22.04 LTS.  
However, it is intended to support any Windows x86, Windows x64, or Linux x64 (or any architecture GCC can be compiled for) environments.  
In-depth documentation of the different build systems can be found [here](/sdk/README.MD), but in order to just compile the game, refer to the following steps instead.  

**Windows:**  
 - 1) Install [git](https://git-scm.com/downloads) if you haven't already. The default settings are OK to accept.  
 - 2) Clone this repository by running `git clone https://github.com/HighwayFrogs/frogger-psx` in a command prompt window.  
 - 3) Follow any instructions shown by the script, re-running `compile.bat` if necessary.  
 - 4) The script will walk you through building the source code into `source\frogger.exe`.  
 - 5) Then, if desired, it will let you build a playable CD image at `build\Frogger.bin` and `build\Frogger.cue`.  

**Linux:**  
 - 1) Install [git](https://git-scm.com/downloads) if you haven't already. (Easy: `sudo apt-get install -y git`)  
 - 2) Clone this repository by running `git clone https://github.com/HighwayFrogs/frogger-psx` in a terminal session.  
 - 3) Change the active directory by running `cd frogger-psx`  
 - 4a) If using WSL (Windows Subsystem for Linux), run `vim "./setup-linux.sh" -c "set ff=unix" -c "wq"`.  
 - 4b) Run `./setup-linux.sh`, entering local system account password for sudo if necessary.  
 - 5) Now, every time you run `make` while in the `frogger-psx` directory, the source code will be compiled to `source/frogger.exe`.  
 - 6) To make a playable CD image `build/Frogger.bin`, run `./build-cd.sh` and follow the instructions.  

**NOTE:** `frogger.exe` might sound like a .exe usable in Windows, but it only will run on the PlayStation since this is the code for the PlayStation version.  

## How is this repository organized?  
As closely to the original organization used by the developers as possible.  
Many different references to file paths show that `\\Frogger\` was a folder on a network drive.  
This repository represents that `\\Frogger\` folder, and is organized in much the same way.  
The folder contained all of the game's code, assets, documents, etc in sub-folders.  
Many of these sub-folders are known / can be re-created by extracting game assets.  
Others contain unknown file paths and assets which were stored in unknown unbaked formats.  
Unfortunately, none of the unbaked/source assets have been seen, and none of the tools (such as mappy, buildwad, etc) have ever been seen.  
However, compilation and asset mods are still possible by using the [FrogLord](https://github.com/Kneesnap/FrogLord/) tool.  

## What are the options for making mods?
Use [FrogLord](https://github.com/Kneesnap/FrogLord/).  
More details will come on how to use FrogLord with this repository to create mods.  

## Disclaimer
This repository (& code) are brought to you by [Highway Frogs](https://highwayfrogs.net/) for preservation, personal, and educational purposes.  
We do not claim to hold any affiliation to the Frogger brand / license or any other related party.  
Atari Interactive (formerly Hasbro Interactive) has explicitly stated they no longer hold any rights to this game and believe it was lost in the bankruptcy. The bankruptcy filings do not list anything relating to this game in the list of assets sold.  
Because Hasbro Interactive was the owner of the game assets (source code, textures, 3D models, etc) and has denied ownership, it is believed that the contents of this repository no longer a have a legal owner.  
However, this is unknown. If there is somehow an owner, Highway Frogs is interested in purchasing all development material and the rights (excluding the likely expired license to use the Frogger brand) from the game.  

## Credits & Special Thanks
 - [Highway Frogs](https://highwayfrogs.net/) for recreating missing code and byte-matching / decompiling code from the final version    
 - [decomp.me](https://decomp.me) & Ethan for helping ensure the decompilation tools  
 - [sonicdcer](https://github.com/sonicdcer) for helping create a decomp environment, and helping match functions  
 - [pixel-stuck](https://github.com/pixel-stuck), [mono21400](https://github.com/Mc-muffin), [petrie911](https://github.com/petrie911), and potentially more who helped decomp/match functions.  
 - The [PSXDev](https://psxdev.net/) community for archiving a lot of the PSX tools necessary to do something like this.  
 - [nicolasnoble](https://github.com/nicolasnoble) for [psyq-obj-converter](https://github.com/grumpycoders/pcsx-redux/tree/main/tools/psyq-obj-parser), and other help with understanding LD scripts.  
 - [mkst](https://github.com/mkst) for [maspsx](https://github.com/mkst/maspsx), which needed work to support building this project.  