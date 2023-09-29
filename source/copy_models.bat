@ECHO OFF
echo This copies ALL models/models textures and mappy textures from
echo camsg021 to your local drive.
echo.
echo It assumes that camsg021 is connected to your PC via S:\ and that
echo your local drive is L:\
echo.
echo If this is NOT the case. Press CTRL-C to stop this batch file NOW!
echo.
pause
echo Its going to delete loads of directories - wanna press ctrl-c now?
pause

deltree /y l:\frogger\gfx\models
deltree /y l:\frogger\gfx\bmps
deltree /y l:\frogger\gfx\mappy_textures
deltree /y l:\frogger\gfx\test
md l:\frogger\gfx\models
md l:\frogger\gfx\bmps
md l:\frogger\gfx\mappy_textures
md l:\frogger\gfx\test

xcopy s:\gfx\models\*.rgb l:\frogger\gfx\models /E
xcopy s:\gfx\models\*.gif l:\frogger\gfx\models /E
xcopy s:\gfx\models\*.bmp l:\frogger\gfx\models /E
xcopy s:\gfx\models\*.x?u l:\frogger\gfx\models /E
xcopy s:\gfx\models\*.x?i l:\frogger\gfx\models /E
xcopy s:\gfx\bmps\*.*     l:\frogger\gfx\bmps /E
xcopy s:\gfx\models\null  l:\frogger\gfx\models\

xcopy s:\gfx\mappy_textures\*.* l:\frogger\gfx\mappy_textures /E
xcopy s:\gfx\mappy_textures\test\*.* l:\frogger\maps\test /E

echo Dummying up textures for level names and suchlike
copy s:\gfx\bmps\options\levelsel\cav1name.rgb l:\frogger\gfx\models\caves\cav_name1.rgb
copy s:\gfx\bmps\options\levelsel\cav3name.rgb l:\frogger\gfx\models\caves\cav_name3.rgb
copy s:\gfx\bmps\options\levelsel\cav4name.rgb l:\frogger\gfx\models\caves\cav_name4.rgb
copy s:\gfx\bmps\options\levelsel\des1name.rgb l:\frogger\gfx\models\desert\des_name1.rgb
copy s:\gfx\bmps\options\levelsel\des2name.rgb l:\frogger\gfx\models\desert\des_name2.rgb
copy s:\gfx\bmps\options\levelsel\des3name.rgb l:\frogger\gfx\models\desert\des_name3.rgb
copy s:\gfx\bmps\options\levelsel\des4name.rgb l:\frogger\gfx\models\desert\des_name4.rgb
copy s:\gfx\bmps\options\levelsel\des5name.rgb l:\frogger\gfx\models\desert\des_name5.rgb
copy s:\gfx\bmps\options\levelsel\for1name.rgb l:\frogger\gfx\models\forest\for_name1.rgb
copy s:\gfx\bmps\options\levelsel\for2name.rgb l:\frogger\gfx\models\forest\for_name2.rgb
copy s:\gfx\bmps\options\levelsel\org1name.rgb l:\frogger\gfx\models\original\org_name1.rgb
copy s:\gfx\bmps\options\levelsel\org2name.rgb l:\frogger\gfx\models\original\org_name2.rgb
copy s:\gfx\bmps\options\levelsel\org3name.rgb l:\frogger\gfx\models\original\org_name3.rgb
copy s:\gfx\bmps\options\levelsel\org4name.rgb l:\frogger\gfx\models\original\org_name4.rgb
copy s:\gfx\bmps\options\levelsel\org5name.rgb l:\frogger\gfx\models\original\org_name5.rgb
copy s:\gfx\bmps\options\levelsel\sky1name.rgb l:\frogger\gfx\models\sky\sky_name1.rgb
copy s:\gfx\bmps\options\levelsel\sky2name.rgb l:\frogger\gfx\models\sky\sky_name2.rgb
copy s:\gfx\bmps\options\levelsel\sky3name.rgb l:\frogger\gfx\models\sky\sky_name3.rgb
copy s:\gfx\bmps\options\levelsel\sky4name.rgb l:\frogger\gfx\models\sky\sky_name4.rgb
copy s:\gfx\bmps\options\levelsel\sub1name.rgb l:\frogger\gfx\models\suburbia\sub_name1.rgb
copy s:\gfx\bmps\options\levelsel\sub2name.rgb l:\frogger\gfx\models\suburbia\sub_name2.rgb
copy s:\gfx\bmps\options\levelsel\sub3name.rgb l:\frogger\gfx\models\suburbia\sub_name3.rgb
copy s:\gfx\bmps\options\levelsel\sub4name.rgb l:\frogger\gfx\models\suburbia\sub_name4.rgb
copy s:\gfx\bmps\options\levelsel\sub5name.rgb l:\frogger\gfx\models\suburbia\sub_name5.rgb
copy s:\gfx\bmps\options\levelsel\swp1name.rgb l:\frogger\gfx\models\swamp\swp_name1.rgb
copy s:\gfx\bmps\options\levelsel\swp2name.rgb l:\frogger\gfx\models\swamp\swp_name2.rgb
copy s:\gfx\bmps\options\levelsel\swp3name.rgb l:\frogger\gfx\models\swamp\swp_name3.rgb
copy s:\gfx\bmps\options\levelsel\swp4name.rgb l:\frogger\gfx\models\swamp\swp_name4.rgb
copy s:\gfx\bmps\options\levelsel\swp5name.rgb l:\frogger\gfx\models\swamp\swp_name5.rgb
copy s:\gfx\bmps\options\levelsel\vol1name.rgb l:\frogger\gfx\models\volcano\vol_name1.rgb
copy s:\gfx\bmps\options\levelsel\vol2name.rgb l:\frogger\gfx\models\volcano\vol_name2.rgb
copy s:\gfx\bmps\options\levelsel\vol3name.rgb l:\frogger\gfx\models\volcano\vol_name3.rgb

echo Copy animation h files
attrib -r l:\frogger\source\gen_frog.h
attrib -r l:\frogger\source\gnm_frog.h
attrib -r l:\frogger\source\org_baby.h

copy s:\gfx\models\generic\gen_frog.h			l:\frogger\source\gen_frog.h
copy s:\gfx\models\generic\genm_frog.h			l:\frogger\source\gnm_frog.h
copy s:\gfx\models\generic\gen_gold_frog.h              l:\frogger\source\gen_gold.h
copy s:\gfx\models\original\org_baby_frog.h		l:\frogger\source\org_baby.h
copy s:\gfx\models\suburbia\sub_snake.h                 l:\frogger\source\sub_snak.h
copy s:\gfx\models\suburbia\sub_turtle.h                l:\frogger\source\sub_turt.h



REM Copying normal models to multiplayer versions
copy l:\frogger\gfx\models\volcano\vol_swit*.* l:\frogger\gfx\models\volcano\volm_swit*.*


REM Added by kev to copy files which should no longer be used...

copy s:\gfx\models\options\opt_frog.* l:\frogger\gfx\models\options

echo.
echo.
echo                      FINISHED COPYING FILES!
echo.

