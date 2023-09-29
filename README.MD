![Frogger Logo](/logo.png)
# Frogger He's Back (PlayStation)
This repository contains a modified source backup of Frogger (1997), commonly called Frogger: He's Back.  
The source backup appears to be from September 3, 1997. However, it seems to contain changes not seen in PSX Build 50b (Closest prototype build), so the code is likely somewhere between build 50 and build 51.  
It may be close to the September 4th PC Prototype too.  
The changes applied to the code are to make it compileable, replace the missing FROG.C file, and to make byte-accurate matches to known builds.  

**Developer:** Milennium Interactive (Defunct)  
**Publisher:** Hasbro Interactive (Sorta Defunct)   

## What versions does this build?
This contains only the PSX version code. The PC version relied upon proprietary libraries which were not included.
If those libraries were reverse engineered (they have debug symbols), it would likely be possible to compile the PC version, or at least a prototype version.  
Unfortunately, the PC version received two months of extra development after the PSX version was complete, likely to improve network multiplayer, compatibility, performance, and to add support for low poly mode.  
None of that work is present in this backup, and not all the details are know about PC version differences.  

**What builds can this repository byte match?**  
 - `TBD` (Hash: `N/A`)  

## How to compile?
TBD  

## How to build a playable CD image?
TBD

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