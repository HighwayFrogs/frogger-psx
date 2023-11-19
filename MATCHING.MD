# Matching  
The source code backup was not in a usable/compileable state in the form it was obtained, but this repository builds the retail version of the game.  
This document details the steps taken to turn the source code backup from where it started to its current state.  

## 1) Compilation & Organization  
Getting the game to compile first involved getting a SDK setup. Information on how the SDK was setup is available in the [SDK Folder](/sdk/).  
Of the missing source files, [frogvram.c](/vlo/frogvram.c) and [frogvram.h](/vlo/frogvram.h) were probably the hardest, due to issues described [here](/vlo/README.MD).  
The next hardest file was [FROG.C](/source/FROG.C) which was completely missing, but re-creating using decompilation techniques.  
The only other remaining file was [frogpsx.h](/merge/frogpsx.h), which was possible to re-generate easily by using [FrogLord](https://github.com/Kneesnap/FrogLord).  
At this point, it was only a matter of tying everything together in order to make the game compile.  

## 2) Matching PSX Build 49
The first order of business was to match the closest prototype build. Luckily, we have both a prototype build (PSX Build 49) made less than 24 hours before the code backup, and another prototype build (PSX Build 50) made less than 24 hours after the code backup.  
That means we have a VERY high degree of accuracy in terms of knowing what this code backup contains.  
It was chosen to initially match PSX Build 49, since it seemed to be less work to match PSX Build 49 than PSX Build 50.  
Matching the closest build is important because it confirmed my suspicion that this code backup contained changes never seen in any build of the game, which should be disabled.  
It seems those changes are mostly performance related, and I have wrapped them in #ifdef EXPERIMENTAL.  

Here are a list of files both modified and unmodified to build PSX Build 49, from an unmodified copy of the source backup.  
**Non-Matches:**  
????-??-?? ??:?? FROG.C		(Entire file missing, byte-matched both Build 49 and Build 50)
1997-09-04 09:23 tempopt.c 	(Has some stack changes, as well as some changes which were kept in build 50)
1997-09-04 08:53 MAIN.C 	(Seems to match Build 49 but with some experimental stack changes)
1997-09-04 08:41 sound.c 	(Seems to match Build 49 but with some experimental stack changes)
1997-09-04 08:32 gamesys.C	(Seems to match Build 49 but with some experimental stack changes)
1997-09-04 08:32 mapload.C	(Seems to match Build 49 except G2 polygon code is disabled)
1997-09-04 08:31 HSView.c	(Has an extra function call to MRDisableDisplayClear)
1997-09-04 02:32 model.C	(Some experiments have been done to model loading which aren't in build 49 or 50)
1997-09-04 01:53 ent_des.c	(Seems to have changes made for build 50 from build 49)
1997-09-04 01:53 MR_VIEW.C	(This seems to include changes for build 50. For Build 49, use old\MR_VIEW.C)
1997-09-03 07:13 PARTICLE.C	(Seems to have changes made for build 50 from build 49)
```

**Matches:**  
```
1997-09-04 08:51 OPTIONS.C
1997-09-04 06:51 pause.c
1997-09-04 06:51 mapdisp.c
1997-09-04 01:41 CAMERA.C
1997-09-04 01:29 COLLIDE.C
1997-09-03 09:37 ENTLIB.C
1997-09-03 06:57 ENTITY.C
1997-09-03 06:57 ent_gen.c
1997-09-03 06:52 SELECT.C
1997-09-03 04:05 mapasm.s
1997-09-03 04:05 hsinput.c
1997-09-03 04:05 froganim.c
1997-09-03 04:05 HUD.C
1997-09-03 04:04 ent_sub.c
1997-09-03 04:04 ent_vol.c
1997-09-02 09:37 ent_jun.c
1997-09-02 09:37 ent_org.c
1997-09-02 09:37 froguser.c
1997-09-02 06:41 ent_swp.c
1997-09-01 10:34 ent_for.c
1997-09-01 10:32 score.C
1997-09-01 06:30 LIBRARY.C
1997-08-31 07:21 PLAYXA.C
1997-08-30 09:44 EFFECTS.C
1997-08-29 10:01 ent_sky.c
1997-08-29 10:01 scripter.c
1997-08-29 10:01 scripts.c
1997-08-28 10:39 STREAM.C
1997-08-28 10:58 credits.c
1997-08-28 08:21 xalist.c
1997-08-28 03:28 LoadSave.c
1997-08-23 03:31 MISC.C
1997-08-21 10:25 ent_cav.c
1997-08-20 09:55 GRID.C
1997-08-18 06:46 MEMCARD.C
1997-08-15 08:20 mapdebug.c
1997-08-14 06:18 WATER.C
1997-08-14 11:13 PATH.C
1997-07-10 00:46 MAPVIEW.C	(Needs 2.6.3)
1997-05-06 08:25 form.c
1997-05-21 08:03 ent_arn.c
1997-04-23 09:20 ZONE.C
```

## 3) Matching PSX Build 71 (Final Build)
After matching PSX Build 49, it was time to match the retail version.  
The same decompilation techniques used to match PSX Build 49 were then used again but to match PSX Build 71 instead, which was the version shipped buyable on US store shelves.  

## Misc Decomp Notes
 - Bad function signatures can cause weird behavior with function arguments. [Example](https://decomp.me/scratch/91c0Y) change MR_USHORT to MR_USHORT* in FrogReactToFallDistance's signature.
 - Register switching fixed via weird if statement `if (x) x = !x;`, an example can be seen in [FROG.C](/source/FROG.C).  
 - do {} while (0) can often fix register swaps too.