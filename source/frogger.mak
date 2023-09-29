# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101
# TARGTYPE "Win32 (x86) Static Library" 0x0104

!IF "$(CFG)" == ""
CFG=api_src - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to api_src - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "frogger - Win32 Release" && "$(CFG)" !=\
 "frogger - Win32 Debug" && "$(CFG)" != "api_src - Win32 Release" && "$(CFG)" !=\
 "api_src - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "frogger.mak" CFG="api_src - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "frogger - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "frogger - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE "api_src - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "api_src - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "api_src - Win32 Debug"

!IF  "$(CFG)" == "frogger - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "api_src - Win32 Release" "w:\frogger\frogger.exe"

CLEAN : 
	-@erase "$(INTDIR)\Camera.obj"
	-@erase "$(INTDIR)\Collide.obj"
	-@erase "$(INTDIR)\ent_arn.obj"
	-@erase "$(INTDIR)\ent_cav.obj"
	-@erase "$(INTDIR)\ent_des.obj"
	-@erase "$(INTDIR)\ent_for.obj"
	-@erase "$(INTDIR)\ent_gen.obj"
	-@erase "$(INTDIR)\ent_jun.obj"
	-@erase "$(INTDIR)\ent_org.obj"
	-@erase "$(INTDIR)\ent_sky.obj"
	-@erase "$(INTDIR)\ent_sub.obj"
	-@erase "$(INTDIR)\ent_swp.obj"
	-@erase "$(INTDIR)\ent_vol.obj"
	-@erase "$(INTDIR)\Entity.obj"
	-@erase "$(INTDIR)\Entlib.obj"
	-@erase "$(INTDIR)\Form.obj"
	-@erase "$(INTDIR)\formlib.obj"
	-@erase "$(INTDIR)\Frog.obj"
	-@erase "$(INTDIR)\Frogger.res"
	-@erase "$(INTDIR)\froguser.obj"
	-@erase "$(INTDIR)\Gamefont.obj"
	-@erase "$(INTDIR)\Gamesys.obj"
	-@erase "$(INTDIR)\Grid.obj"
	-@erase "$(INTDIR)\Hud.obj"
	-@erase "$(INTDIR)\Levelsel.obj"
	-@erase "$(INTDIR)\Library.obj"
	-@erase "$(INTDIR)\Main.obj"
	-@erase "$(INTDIR)\Mapdebug.obj"
	-@erase "$(INTDIR)\Mapdisp.obj"
	-@erase "$(INTDIR)\Mapload.obj"
	-@erase "$(INTDIR)\Mapview.obj"
	-@erase "$(INTDIR)\Misc.obj"
	-@erase "$(INTDIR)\Options.obj"
	-@erase "$(INTDIR)\Path.obj"
	-@erase "$(INTDIR)\Project.obj"
	-@erase "$(INTDIR)\score.obj"
	-@erase "$(INTDIR)\scripter.obj"
	-@erase "$(INTDIR)\scripts.obj"
	-@erase "$(INTDIR)\sound.obj"
	-@erase "$(INTDIR)\Sprdata.obj"
	-@erase "$(INTDIR)\tempopt.obj"
	-@erase "$(INTDIR)\Zone.obj"
	-@erase "w:\frogger\frogger.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/frogger.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
RSC_PROJ=/l 0x809 /fo"$(INTDIR)/Frogger.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/frogger.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /machine:I386 /out:"w:\frogger\frogger.exe"
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo\
 /subsystem:windows /incremental:no /pdb:"$(OUTDIR)/frogger.pdb" /machine:I386\
 /out:"w:\frogger\frogger.exe" 
LINK32_OBJS= \
	"$(INTDIR)\Camera.obj" \
	"$(INTDIR)\Collide.obj" \
	"$(INTDIR)\ent_arn.obj" \
	"$(INTDIR)\ent_cav.obj" \
	"$(INTDIR)\ent_des.obj" \
	"$(INTDIR)\ent_for.obj" \
	"$(INTDIR)\ent_gen.obj" \
	"$(INTDIR)\ent_jun.obj" \
	"$(INTDIR)\ent_org.obj" \
	"$(INTDIR)\ent_sky.obj" \
	"$(INTDIR)\ent_sub.obj" \
	"$(INTDIR)\ent_swp.obj" \
	"$(INTDIR)\ent_vol.obj" \
	"$(INTDIR)\Entity.obj" \
	"$(INTDIR)\Entlib.obj" \
	"$(INTDIR)\Form.obj" \
	"$(INTDIR)\formlib.obj" \
	"$(INTDIR)\Frog.obj" \
	"$(INTDIR)\Frogger.res" \
	"$(INTDIR)\froguser.obj" \
	"$(INTDIR)\Gamefont.obj" \
	"$(INTDIR)\Gamesys.obj" \
	"$(INTDIR)\Grid.obj" \
	"$(INTDIR)\Hud.obj" \
	"$(INTDIR)\Levelsel.obj" \
	"$(INTDIR)\Library.obj" \
	"$(INTDIR)\Main.obj" \
	"$(INTDIR)\Mapdebug.obj" \
	"$(INTDIR)\Mapdisp.obj" \
	"$(INTDIR)\Mapload.obj" \
	"$(INTDIR)\Mapview.obj" \
	"$(INTDIR)\Misc.obj" \
	"$(INTDIR)\Options.obj" \
	"$(INTDIR)\Path.obj" \
	"$(INTDIR)\Project.obj" \
	"$(INTDIR)\score.obj" \
	"$(INTDIR)\scripter.obj" \
	"$(INTDIR)\scripts.obj" \
	"$(INTDIR)\sound.obj" \
	"$(INTDIR)\Sprdata.obj" \
	"$(INTDIR)\tempopt.obj" \
	"$(INTDIR)\Zone.obj" \
	".\api_src\Release\api_src.lib"

"w:\frogger\frogger.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "frogger - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "frogger_"
# PROP BASE Intermediate_Dir "frogger_"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "debug2"
# PROP Intermediate_Dir "debug2"
# PROP Target_Dir ""
OUTDIR=.\debug2
INTDIR=.\debug2

ALL : "api_src - Win32 Debug" "w:\frogger\frogger.exe"

CLEAN : 
	-@erase "$(INTDIR)\Camera.obj"
	-@erase "$(INTDIR)\Collide.obj"
	-@erase "$(INTDIR)\ent_arn.obj"
	-@erase "$(INTDIR)\ent_cav.obj"
	-@erase "$(INTDIR)\ent_des.obj"
	-@erase "$(INTDIR)\ent_for.obj"
	-@erase "$(INTDIR)\ent_gen.obj"
	-@erase "$(INTDIR)\ent_jun.obj"
	-@erase "$(INTDIR)\ent_org.obj"
	-@erase "$(INTDIR)\ent_sky.obj"
	-@erase "$(INTDIR)\ent_sub.obj"
	-@erase "$(INTDIR)\ent_swp.obj"
	-@erase "$(INTDIR)\ent_vol.obj"
	-@erase "$(INTDIR)\Entity.obj"
	-@erase "$(INTDIR)\Entlib.obj"
	-@erase "$(INTDIR)\Form.obj"
	-@erase "$(INTDIR)\formlib.obj"
	-@erase "$(INTDIR)\Frog.obj"
	-@erase "$(INTDIR)\Frogger.res"
	-@erase "$(INTDIR)\froguser.obj"
	-@erase "$(INTDIR)\Gamefont.obj"
	-@erase "$(INTDIR)\Gamesys.obj"
	-@erase "$(INTDIR)\Grid.obj"
	-@erase "$(INTDIR)\Hud.obj"
	-@erase "$(INTDIR)\Levelsel.obj"
	-@erase "$(INTDIR)\Library.obj"
	-@erase "$(INTDIR)\Main.obj"
	-@erase "$(INTDIR)\Mapdebug.obj"
	-@erase "$(INTDIR)\Mapdisp.obj"
	-@erase "$(INTDIR)\Mapload.obj"
	-@erase "$(INTDIR)\Mapview.obj"
	-@erase "$(INTDIR)\Misc.obj"
	-@erase "$(INTDIR)\Options.obj"
	-@erase "$(INTDIR)\Path.obj"
	-@erase "$(INTDIR)\Project.obj"
	-@erase "$(INTDIR)\score.obj"
	-@erase "$(INTDIR)\scripter.obj"
	-@erase "$(INTDIR)\scripts.obj"
	-@erase "$(INTDIR)\sound.obj"
	-@erase "$(INTDIR)\Sprdata.obj"
	-@erase "$(INTDIR)\tempopt.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(INTDIR)\Zone.obj"
	-@erase "$(OUTDIR)\frogger.pdb"
	-@erase "w:\frogger\frogger.exe"
	-@erase "w:\frogger\frogger.ilk"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/frogger.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\debug2/
CPP_SBRS=.\.

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
RSC_PROJ=/l 0x809 /fo"$(INTDIR)/Frogger.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/frogger.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib dplay.lib dinput.lib winmm.lib dxguid.lib dsound.lib /nologo /subsystem:windows /debug /machine:I386 /out:"w:\frogger\frogger.exe"
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib dplay.lib dinput.lib\
 winmm.lib dxguid.lib dsound.lib /nologo /subsystem:windows /incremental:yes\
 /pdb:"$(OUTDIR)/frogger.pdb" /debug /machine:I386 /out:"w:\frogger\frogger.exe"\
 
LINK32_OBJS= \
	"$(INTDIR)\Camera.obj" \
	"$(INTDIR)\Collide.obj" \
	"$(INTDIR)\ent_arn.obj" \
	"$(INTDIR)\ent_cav.obj" \
	"$(INTDIR)\ent_des.obj" \
	"$(INTDIR)\ent_for.obj" \
	"$(INTDIR)\ent_gen.obj" \
	"$(INTDIR)\ent_jun.obj" \
	"$(INTDIR)\ent_org.obj" \
	"$(INTDIR)\ent_sky.obj" \
	"$(INTDIR)\ent_sub.obj" \
	"$(INTDIR)\ent_swp.obj" \
	"$(INTDIR)\ent_vol.obj" \
	"$(INTDIR)\Entity.obj" \
	"$(INTDIR)\Entlib.obj" \
	"$(INTDIR)\Form.obj" \
	"$(INTDIR)\formlib.obj" \
	"$(INTDIR)\Frog.obj" \
	"$(INTDIR)\Frogger.res" \
	"$(INTDIR)\froguser.obj" \
	"$(INTDIR)\Gamefont.obj" \
	"$(INTDIR)\Gamesys.obj" \
	"$(INTDIR)\Grid.obj" \
	"$(INTDIR)\Hud.obj" \
	"$(INTDIR)\Levelsel.obj" \
	"$(INTDIR)\Library.obj" \
	"$(INTDIR)\Main.obj" \
	"$(INTDIR)\Mapdebug.obj" \
	"$(INTDIR)\Mapdisp.obj" \
	"$(INTDIR)\Mapload.obj" \
	"$(INTDIR)\Mapview.obj" \
	"$(INTDIR)\Misc.obj" \
	"$(INTDIR)\Options.obj" \
	"$(INTDIR)\Path.obj" \
	"$(INTDIR)\Project.obj" \
	"$(INTDIR)\score.obj" \
	"$(INTDIR)\scripter.obj" \
	"$(INTDIR)\scripts.obj" \
	"$(INTDIR)\sound.obj" \
	"$(INTDIR)\Sprdata.obj" \
	"$(INTDIR)\tempopt.obj" \
	"$(INTDIR)\Zone.obj" \
	".\api_src\api_src_\api_src.lib"

"w:\frogger\frogger.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "api_src - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "api_src\Release"
# PROP BASE Intermediate_Dir "api_src\Release"
# PROP BASE Target_Dir "api_src"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "api_src\Release"
# PROP Intermediate_Dir "api_src\Release"
# PROP Target_Dir "api_src"
OUTDIR=.\api_src\Release
INTDIR=.\api_src\Release

ALL : "$(OUTDIR)\api_src.lib"

CLEAN : 
	-@erase "$(INTDIR)\mr_anim.obj"
	-@erase "$(INTDIR)\Mr_anim2.obj"
	-@erase "$(INTDIR)\mr_c_pak.obj"
	-@erase "$(INTDIR)\Mr_coll.obj"
	-@erase "$(INTDIR)\Mr_debug.obj"
	-@erase "$(INTDIR)\Mr_disp.obj"
	-@erase "$(INTDIR)\Mr_file.obj"
	-@erase "$(INTDIR)\Mr_font.obj"
	-@erase "$(INTDIR)\Mr_frame.obj"
	-@erase "$(INTDIR)\Mr_fx.obj"
	-@erase "$(INTDIR)\Mr_Geom.obj"
	-@erase "$(INTDIR)\Mr_gte.obj"
	-@erase "$(INTDIR)\mr_input.obj"
	-@erase "$(INTDIR)\Mr_light.obj"
	-@erase "$(INTDIR)\Mr_math.obj"
	-@erase "$(INTDIR)\Mr_mem.obj"
	-@erase "$(INTDIR)\Mr_mesh.obj"
	-@erase "$(INTDIR)\Mr_misc.obj"
	-@erase "$(INTDIR)\Mr_mof.obj"
	-@erase "$(INTDIR)\Mr_obj.obj"
	-@erase "$(INTDIR)\Mr_ot.obj"
	-@erase "$(INTDIR)\Mr_p_e3.obj"
	-@erase "$(INTDIR)\Mr_p_e4.obj"
	-@erase "$(INTDIR)\Mr_p_f3.obj"
	-@erase "$(INTDIR)\Mr_p_f4.obj"
	-@erase "$(INTDIR)\Mr_p_ft3.obj"
	-@erase "$(INTDIR)\Mr_p_ft4.obj"
	-@erase "$(INTDIR)\Mr_p_g3.obj"
	-@erase "$(INTDIR)\Mr_p_g4.obj"
	-@erase "$(INTDIR)\Mr_p_gt3.obj"
	-@erase "$(INTDIR)\Mr_p_gt4.obj"
	-@erase "$(INTDIR)\Mr_part.obj"
	-@erase "$(INTDIR)\Mr_phlf3.obj"
	-@erase "$(INTDIR)\Mr_phlf4.obj"
	-@erase "$(INTDIR)\Mr_pres.obj"
	-@erase "$(INTDIR)\Mr_quat.obj"
	-@erase "$(INTDIR)\mr_sound.obj"
	-@erase "$(INTDIR)\Mr_splin.obj"
	-@erase "$(INTDIR)\Mr_sprt.obj"
	-@erase "$(INTDIR)\Mr_stat.obj"
	-@erase "$(INTDIR)\Mr_view.obj"
	-@erase "$(INTDIR)\Mr_vram.obj"
	-@erase "$(INTDIR)\mr_windows.obj"
	-@erase "$(OUTDIR)\api_src.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/api_src.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\api_src\Release/
CPP_SBRS=.\.

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/api_src.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/api_src.lib" 
LIB32_OBJS= \
	"$(INTDIR)\mr_anim.obj" \
	"$(INTDIR)\Mr_anim2.obj" \
	"$(INTDIR)\mr_c_pak.obj" \
	"$(INTDIR)\Mr_coll.obj" \
	"$(INTDIR)\Mr_debug.obj" \
	"$(INTDIR)\Mr_disp.obj" \
	"$(INTDIR)\Mr_file.obj" \
	"$(INTDIR)\Mr_font.obj" \
	"$(INTDIR)\Mr_frame.obj" \
	"$(INTDIR)\Mr_fx.obj" \
	"$(INTDIR)\Mr_Geom.obj" \
	"$(INTDIR)\Mr_gte.obj" \
	"$(INTDIR)\mr_input.obj" \
	"$(INTDIR)\Mr_light.obj" \
	"$(INTDIR)\Mr_math.obj" \
	"$(INTDIR)\Mr_mem.obj" \
	"$(INTDIR)\Mr_mesh.obj" \
	"$(INTDIR)\Mr_misc.obj" \
	"$(INTDIR)\Mr_mof.obj" \
	"$(INTDIR)\Mr_obj.obj" \
	"$(INTDIR)\Mr_ot.obj" \
	"$(INTDIR)\Mr_p_e3.obj" \
	"$(INTDIR)\Mr_p_e4.obj" \
	"$(INTDIR)\Mr_p_f3.obj" \
	"$(INTDIR)\Mr_p_f4.obj" \
	"$(INTDIR)\Mr_p_ft3.obj" \
	"$(INTDIR)\Mr_p_ft4.obj" \
	"$(INTDIR)\Mr_p_g3.obj" \
	"$(INTDIR)\Mr_p_g4.obj" \
	"$(INTDIR)\Mr_p_gt3.obj" \
	"$(INTDIR)\Mr_p_gt4.obj" \
	"$(INTDIR)\Mr_part.obj" \
	"$(INTDIR)\Mr_phlf3.obj" \
	"$(INTDIR)\Mr_phlf4.obj" \
	"$(INTDIR)\Mr_pres.obj" \
	"$(INTDIR)\Mr_quat.obj" \
	"$(INTDIR)\mr_sound.obj" \
	"$(INTDIR)\Mr_splin.obj" \
	"$(INTDIR)\Mr_sprt.obj" \
	"$(INTDIR)\Mr_stat.obj" \
	"$(INTDIR)\Mr_view.obj" \
	"$(INTDIR)\Mr_vram.obj" \
	"$(INTDIR)\mr_windows.obj"

"$(OUTDIR)\api_src.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "api_src\api_src_"
# PROP BASE Intermediate_Dir "api_src\api_src_"
# PROP BASE Target_Dir "api_src"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "api_src\api_src_"
# PROP Intermediate_Dir "api_src\api_src_"
# PROP Target_Dir "api_src"
OUTDIR=.\api_src\api_src_
INTDIR=.\api_src\api_src_

ALL : "$(OUTDIR)\api_src.lib"

CLEAN : 
	-@erase "$(INTDIR)\mr_anim.obj"
	-@erase "$(INTDIR)\Mr_anim2.obj"
	-@erase "$(INTDIR)\mr_c_pak.obj"
	-@erase "$(INTDIR)\Mr_coll.obj"
	-@erase "$(INTDIR)\Mr_debug.obj"
	-@erase "$(INTDIR)\Mr_disp.obj"
	-@erase "$(INTDIR)\Mr_file.obj"
	-@erase "$(INTDIR)\Mr_font.obj"
	-@erase "$(INTDIR)\Mr_frame.obj"
	-@erase "$(INTDIR)\Mr_fx.obj"
	-@erase "$(INTDIR)\Mr_Geom.obj"
	-@erase "$(INTDIR)\Mr_gte.obj"
	-@erase "$(INTDIR)\mr_input.obj"
	-@erase "$(INTDIR)\Mr_light.obj"
	-@erase "$(INTDIR)\Mr_math.obj"
	-@erase "$(INTDIR)\Mr_mem.obj"
	-@erase "$(INTDIR)\Mr_mesh.obj"
	-@erase "$(INTDIR)\Mr_misc.obj"
	-@erase "$(INTDIR)\Mr_mof.obj"
	-@erase "$(INTDIR)\Mr_obj.obj"
	-@erase "$(INTDIR)\Mr_ot.obj"
	-@erase "$(INTDIR)\Mr_p_e3.obj"
	-@erase "$(INTDIR)\Mr_p_e4.obj"
	-@erase "$(INTDIR)\Mr_p_f3.obj"
	-@erase "$(INTDIR)\Mr_p_f4.obj"
	-@erase "$(INTDIR)\Mr_p_ft3.obj"
	-@erase "$(INTDIR)\Mr_p_ft4.obj"
	-@erase "$(INTDIR)\Mr_p_g3.obj"
	-@erase "$(INTDIR)\Mr_p_g4.obj"
	-@erase "$(INTDIR)\Mr_p_gt3.obj"
	-@erase "$(INTDIR)\Mr_p_gt4.obj"
	-@erase "$(INTDIR)\Mr_part.obj"
	-@erase "$(INTDIR)\Mr_phlf3.obj"
	-@erase "$(INTDIR)\Mr_phlf4.obj"
	-@erase "$(INTDIR)\Mr_pres.obj"
	-@erase "$(INTDIR)\Mr_quat.obj"
	-@erase "$(INTDIR)\mr_sound.obj"
	-@erase "$(INTDIR)\Mr_splin.obj"
	-@erase "$(INTDIR)\Mr_sprt.obj"
	-@erase "$(INTDIR)\Mr_stat.obj"
	-@erase "$(INTDIR)\Mr_view.obj"
	-@erase "$(INTDIR)\Mr_vram.obj"
	-@erase "$(INTDIR)\mr_windows.obj"
	-@erase "$(OUTDIR)\api_src.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MLd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/api_src.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\api_src\api_src_/
CPP_SBRS=.\.

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/api_src.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/api_src.lib" 
LIB32_OBJS= \
	"$(INTDIR)\mr_anim.obj" \
	"$(INTDIR)\Mr_anim2.obj" \
	"$(INTDIR)\mr_c_pak.obj" \
	"$(INTDIR)\Mr_coll.obj" \
	"$(INTDIR)\Mr_debug.obj" \
	"$(INTDIR)\Mr_disp.obj" \
	"$(INTDIR)\Mr_file.obj" \
	"$(INTDIR)\Mr_font.obj" \
	"$(INTDIR)\Mr_frame.obj" \
	"$(INTDIR)\Mr_fx.obj" \
	"$(INTDIR)\Mr_Geom.obj" \
	"$(INTDIR)\Mr_gte.obj" \
	"$(INTDIR)\mr_input.obj" \
	"$(INTDIR)\Mr_light.obj" \
	"$(INTDIR)\Mr_math.obj" \
	"$(INTDIR)\Mr_mem.obj" \
	"$(INTDIR)\Mr_mesh.obj" \
	"$(INTDIR)\Mr_misc.obj" \
	"$(INTDIR)\Mr_mof.obj" \
	"$(INTDIR)\Mr_obj.obj" \
	"$(INTDIR)\Mr_ot.obj" \
	"$(INTDIR)\Mr_p_e3.obj" \
	"$(INTDIR)\Mr_p_e4.obj" \
	"$(INTDIR)\Mr_p_f3.obj" \
	"$(INTDIR)\Mr_p_f4.obj" \
	"$(INTDIR)\Mr_p_ft3.obj" \
	"$(INTDIR)\Mr_p_ft4.obj" \
	"$(INTDIR)\Mr_p_g3.obj" \
	"$(INTDIR)\Mr_p_g4.obj" \
	"$(INTDIR)\Mr_p_gt3.obj" \
	"$(INTDIR)\Mr_p_gt4.obj" \
	"$(INTDIR)\Mr_part.obj" \
	"$(INTDIR)\Mr_phlf3.obj" \
	"$(INTDIR)\Mr_phlf4.obj" \
	"$(INTDIR)\Mr_pres.obj" \
	"$(INTDIR)\Mr_quat.obj" \
	"$(INTDIR)\mr_sound.obj" \
	"$(INTDIR)\Mr_splin.obj" \
	"$(INTDIR)\Mr_sprt.obj" \
	"$(INTDIR)\Mr_stat.obj" \
	"$(INTDIR)\Mr_view.obj" \
	"$(INTDIR)\Mr_vram.obj" \
	"$(INTDIR)\mr_windows.obj"

"$(OUTDIR)\api_src.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 

################################################################################
# Begin Target

# Name "frogger - Win32 Release"
# Name "frogger - Win32 Debug"

!IF  "$(CFG)" == "frogger - Win32 Release"

!ELSEIF  "$(CFG)" == "frogger - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\Camera.c
DEP_CPP_CAMER=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Camera.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Camera.obj" : $(SOURCE) $(DEP_CPP_CAMER) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Collide.c
DEP_CPP_COLLI=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Camera.h"\
	".\Collide.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\sound.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Collide.obj" : $(SOURCE) $(DEP_CPP_COLLI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Entity.c
DEP_CPP_ENTIT=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamefont.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdebug.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Misc.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\scripter.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Entity.obj" : $(SOURCE) $(DEP_CPP_ENTIT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Form.c
DEP_CPP_FORM_=\
	".\Form.h"\
	".\formlib.H"\
	".\Mr_all.h"\
	
NODEP_CPP_FORM_=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Form.obj" : $(SOURCE) $(DEP_CPP_FORM_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Frog.c
DEP_CPP_FROG_=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Camera.h"\
	".\Collide.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\froguser.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\score.H"\
	".\sound.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Frog.obj" : $(SOURCE) $(DEP_CPP_FROG_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Gamefont.c
DEP_CPP_GAMEF=\
	"..\vlo\frogvram.h"\
	".\Gamefont.h"\
	".\Mr_all.h"\
	".\Sprdata.h"\
	
NODEP_CPP_GAMEF=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Gamefont.obj" : $(SOURCE) $(DEP_CPP_GAMEF) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Gamesys.c
DEP_CPP_GAMES=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Camera.h"\
	".\Collide.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\froguser.h"\
	".\Gamefont.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdebug.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\sound.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\xalist.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Gamesys.obj" : $(SOURCE) $(DEP_CPP_GAMES) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Grid.c
DEP_CPP_GRID_=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Grid.obj" : $(SOURCE) $(DEP_CPP_GRID_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Library.c
DEP_CPP_LIBRA=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Library.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Library.obj" : $(SOURCE) $(DEP_CPP_LIBRA) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Main.c
DEP_CPP_MAIN_=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\sound.h"\
	".\Sprdata.h"\
	".\stream.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Main.obj" : $(SOURCE) $(DEP_CPP_MAIN_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mapdebug.c
DEP_CPP_MAPDE=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Gamefont.h"\
	".\Grid.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdebug.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\Zone.h"\
	
NODEP_CPP_MAPDE=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Mapdebug.obj" : $(SOURCE) $(DEP_CPP_MAPDE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mapdisp.c
DEP_CPP_MAPDI=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamefont.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdebug.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mapdisp.obj" : $(SOURCE) $(DEP_CPP_MAPDI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mapload.c
DEP_CPP_MAPLO=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Collide.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mapload.obj" : $(SOURCE) $(DEP_CPP_MAPLO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Mapview.c
DEP_CPP_MAPVI=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Gamesys.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapview.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	
NODEP_CPP_MAPVI=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Mapview.obj" : $(SOURCE) $(DEP_CPP_MAPVI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Misc.c
DEP_CPP_MISC_=\
	".\Misc.h"\
	".\Mr_all.h"\
	
NODEP_CPP_MISC_=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Misc.obj" : $(SOURCE) $(DEP_CPP_MISC_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Options.c
DEP_CPP_OPTIO=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Levelsel.h"\
	".\Mr_all.h"\
	".\Options.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\tempopt.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Options.obj" : $(SOURCE) $(DEP_CPP_OPTIO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Path.c
DEP_CPP_PATH_=\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Library.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Path.obj" : $(SOURCE) $(DEP_CPP_PATH_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Project.c
DEP_CPP_PROJE=\
	"..\merge\frogpsx.h"\
	".\Binaries.h"\
	".\Mr_all.h"\
	".\Project.h"\
	
NODEP_CPP_PROJE=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Project.obj" : $(SOURCE) $(DEP_CPP_PROJE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Sprdata.c
DEP_CPP_SPRDA=\
	"..\vlo\frogvram.c"\
	"..\vlo\frogvram.h"\
	".\Mr_all.h"\
	".\Sprdata.h"\
	
NODEP_CPP_SPRDA=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Sprdata.obj" : $(SOURCE) $(DEP_CPP_SPRDA) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Zone.c
DEP_CPP_ZONE_=\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Library.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Zone.h"\
	
NODEP_CPP_ZONE_=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\Zone.obj" : $(SOURCE) $(DEP_CPP_ZONE_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Frogger.rc
DEP_RSC_FROGG=\
	"..\merge\Frogpsx.mwi"\
	".\api_bin\Acos_le.dat"\
	

"$(INTDIR)\Frogger.res" : $(SOURCE) $(DEP_RSC_FROGG) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Project Dependency

# Project_Dep_Name "api_src"

!IF  "$(CFG)" == "frogger - Win32 Release"

"api_src - Win32 Release" : 
   $(MAKE) /$(MAKEFLAGS) /F ".\frogger.mak" CFG="api_src - Win32 Release" 

!ELSEIF  "$(CFG)" == "frogger - Win32 Debug"

"api_src - Win32 Debug" : 
   $(MAKE) /$(MAKEFLAGS) /F ".\frogger.mak" CFG="api_src - Win32 Debug" 

!ENDIF 

# End Project Dependency
################################################################################
# Begin Source File

SOURCE=.\Entlib.c
DEP_CPP_ENTLI=\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\ent_arn.h"\
	".\ent_cav.h"\
	".\ent_des.h"\
	".\ent_for.h"\
	".\ent_gen.h"\
	".\ent_jun.h"\
	".\ent_org.h"\
	".\ent_sky.h"\
	".\ent_sub.h"\
	".\ent_swp.h"\
	".\ent_vol.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Mr_all.h"\
	".\Path.h"\
	".\scripts.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Entlib.obj" : $(SOURCE) $(DEP_CPP_ENTLI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\sound.c
DEP_CPP_SOUND=\
	"..\merge\frogpsx.h"\
	".\Mr_all.h"\
	".\sound.h"\
	
NODEP_CPP_SOUND=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\sound.obj" : $(SOURCE) $(DEP_CPP_SOUND) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_des.c
DEP_CPP_ENT_D=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\Binaries.h"\
	".\ent_des.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Gamesys.h"\
	".\Library.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\sound.h"\
	".\Sprdata.h"\
	".\Zone.h"\
	
NODEP_CPP_ENT_D=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_des.obj" : $(SOURCE) $(DEP_CPP_ENT_D) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_vol.c
DEP_CPP_ENT_V=\
	".\ent_vol.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_V=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_vol.obj" : $(SOURCE) $(DEP_CPP_ENT_V) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_cav.c
DEP_CPP_ENT_C=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\ent_cav.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Mr_all.h"\
	".\Path.h"\
	".\scripter.h"\
	".\scripts.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\ent_cav.obj" : $(SOURCE) $(DEP_CPP_ENT_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_for.c
DEP_CPP_ENT_F=\
	".\ent_for.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_F=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_for.obj" : $(SOURCE) $(DEP_CPP_ENT_F) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_gen.c
DEP_CPP_ENT_G=\
	".\ent_gen.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_G=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_gen.obj" : $(SOURCE) $(DEP_CPP_ENT_G) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_jun.c
DEP_CPP_ENT_J=\
	".\ent_jun.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_J=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_jun.obj" : $(SOURCE) $(DEP_CPP_ENT_J) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_org.c
DEP_CPP_ENT_O=\
	".\ent_org.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_O=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_org.obj" : $(SOURCE) $(DEP_CPP_ENT_O) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_sky.c
DEP_CPP_ENT_S=\
	".\ent_sky.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_S=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_sky.obj" : $(SOURCE) $(DEP_CPP_ENT_S) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_sub.c
DEP_CPP_ENT_SU=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\ent_sub.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Mr_all.h"\
	".\Path.h"\
	".\scripter.h"\
	".\scripts.h"\
	".\sound.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\ent_sub.obj" : $(SOURCE) $(DEP_CPP_ENT_SU) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_swp.c
DEP_CPP_ENT_SW=\
	".\ent_swp.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_SW=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_swp.obj" : $(SOURCE) $(DEP_CPP_ENT_SW) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ent_arn.c
DEP_CPP_ENT_A=\
	".\ent_arn.h"\
	".\Mr_all.h"\
	
NODEP_CPP_ENT_A=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\ent_arn.obj" : $(SOURCE) $(DEP_CPP_ENT_A) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\formlib.C
DEP_CPP_FORML=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\scripts.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\formlib.obj" : $(SOURCE) $(DEP_CPP_FORML) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Levelsel.c
DEP_CPP_LEVEL=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Levelsel.h"\
	".\Mr_all.h"\
	".\Options.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\tempopt.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Levelsel.obj" : $(SOURCE) $(DEP_CPP_LEVEL) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\score.C
DEP_CPP_SCORE=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\score.H"\
	".\Sprdata.h"\
	".\Zone.h"\
	
NODEP_CPP_SCORE=\
	".\api_src\Mr_all.h"\
	

"$(INTDIR)\score.obj" : $(SOURCE) $(DEP_CPP_SCORE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\Hud.c
DEP_CPP_HUD_C=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Gamesys.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Hud.obj" : $(SOURCE) $(DEP_CPP_HUD_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\scripter.c
DEP_CPP_SCRIP=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Entlib.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\scripter.h"\
	".\scripts.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\scripter.obj" : $(SOURCE) $(DEP_CPP_SCRIP) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\scripts.c
DEP_CPP_SCRIPT=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\ent_cav.h"\
	".\ent_sub.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\scripter.h"\
	".\scripts.h"\
	".\sound.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\scripts.obj" : $(SOURCE) $(DEP_CPP_SCRIPT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\froguser.C
DEP_CPP_FROGU=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Entity.h"\
	".\Form.h"\
	".\formlib.H"\
	".\Frog.h"\
	".\Grid.h"\
	".\Hud.h"\
	".\Library.h"\
	".\Main.h"\
	".\Mapdisp.h"\
	".\Mapload.h"\
	".\Mr_all.h"\
	".\Path.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\winsys.h"\
	".\Zone.h"\
	{$(INCLUDE)}"\dinput.h"\
	
NODEP_CPP_FROGU=\
	".\froguser.h"\
	

"$(INTDIR)\froguser.obj" : $(SOURCE) $(DEP_CPP_FROGU) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\tempopt.c
DEP_CPP_TEMPO=\
	"..\merge\frogpsx.h"\
	"..\vlo\frogvram.h"\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\Binaries.h"\
	".\Gamefont.h"\
	".\Gamesys.h"\
	".\Levelsel.h"\
	".\Main.h"\
	".\Mr_all.h"\
	".\Options.h"\
	".\Project.h"\
	".\Sprdata.h"\
	".\tempopt.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\tempopt.obj" : $(SOURCE) $(DEP_CPP_TEMPO) "$(INTDIR)"


# End Source File
# End Target
################################################################################
# Begin Target

# Name "api_src - Win32 Release"
# Name "api_src - Win32 Debug"

!IF  "$(CFG)" == "api_src - Win32 Release"

!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\api_src\mr_windows.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_WI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_windows.obj" : $(SOURCE) $(DEP_CPP_MR_WI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_WI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_windows.obj" : $(SOURCE) $(DEP_CPP_MR_WI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_anim2.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_AN=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_anim2.obj" : $(SOURCE) $(DEP_CPP_MR_AN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_AN=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_anim2.obj" : $(SOURCE) $(DEP_CPP_MR_AN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\mr_c_pak.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_C_=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_c_pak.obj" : $(SOURCE) $(DEP_CPP_MR_C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_C_=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_c_pak.obj" : $(SOURCE) $(DEP_CPP_MR_C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_coll.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_CO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_coll.obj" : $(SOURCE) $(DEP_CPP_MR_CO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_CO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_coll.obj" : $(SOURCE) $(DEP_CPP_MR_CO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_debug.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_DE=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_debug.obj" : $(SOURCE) $(DEP_CPP_MR_DE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_DE=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_debug.obj" : $(SOURCE) $(DEP_CPP_MR_DE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_disp.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_DI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_disp.obj" : $(SOURCE) $(DEP_CPP_MR_DI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_DI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_disp.obj" : $(SOURCE) $(DEP_CPP_MR_DI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_file.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_FI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_file.obj" : $(SOURCE) $(DEP_CPP_MR_FI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_FI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_file.obj" : $(SOURCE) $(DEP_CPP_MR_FI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_font.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_FO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_font.obj" : $(SOURCE) $(DEP_CPP_MR_FO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_FO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_font.obj" : $(SOURCE) $(DEP_CPP_MR_FO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_frame.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_FR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_frame.obj" : $(SOURCE) $(DEP_CPP_MR_FR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_FR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_frame.obj" : $(SOURCE) $(DEP_CPP_MR_FR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_fx.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_FX=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_fx.obj" : $(SOURCE) $(DEP_CPP_MR_FX) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_FX=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_fx.obj" : $(SOURCE) $(DEP_CPP_MR_FX) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_Geom.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_GE=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_Geom.obj" : $(SOURCE) $(DEP_CPP_MR_GE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_GE=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_Geom.obj" : $(SOURCE) $(DEP_CPP_MR_GE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_gte.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_GT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_gte.obj" : $(SOURCE) $(DEP_CPP_MR_GT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_GT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_gte.obj" : $(SOURCE) $(DEP_CPP_MR_GT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\mr_input.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_IN=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_input.obj" : $(SOURCE) $(DEP_CPP_MR_IN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_IN=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_input.obj" : $(SOURCE) $(DEP_CPP_MR_IN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_light.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_LI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_light.obj" : $(SOURCE) $(DEP_CPP_MR_LI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_LI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_light.obj" : $(SOURCE) $(DEP_CPP_MR_LI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_math.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_MA=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_math.obj" : $(SOURCE) $(DEP_CPP_MR_MA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_MA=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_math.obj" : $(SOURCE) $(DEP_CPP_MR_MA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_mem.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_ME=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mem.obj" : $(SOURCE) $(DEP_CPP_MR_ME) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_ME=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mem.obj" : $(SOURCE) $(DEP_CPP_MR_ME) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_mesh.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_MES=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mesh.obj" : $(SOURCE) $(DEP_CPP_MR_MES) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_MES=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mesh.obj" : $(SOURCE) $(DEP_CPP_MR_MES) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_misc.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_MI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_misc.obj" : $(SOURCE) $(DEP_CPP_MR_MI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_MI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_misc.obj" : $(SOURCE) $(DEP_CPP_MR_MI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_mof.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_MO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mof.obj" : $(SOURCE) $(DEP_CPP_MR_MO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_MO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_mof.obj" : $(SOURCE) $(DEP_CPP_MR_MO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_obj.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_OB=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_obj.obj" : $(SOURCE) $(DEP_CPP_MR_OB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_OB=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_obj.obj" : $(SOURCE) $(DEP_CPP_MR_OB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_ot.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_OT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_ot.obj" : $(SOURCE) $(DEP_CPP_MR_OT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_OT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_ot.obj" : $(SOURCE) $(DEP_CPP_MR_OT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_e3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_e3.obj" : $(SOURCE) $(DEP_CPP_MR_P_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_e3.obj" : $(SOURCE) $(DEP_CPP_MR_P_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_e4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_E=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_e4.obj" : $(SOURCE) $(DEP_CPP_MR_P_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_E=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_e4.obj" : $(SOURCE) $(DEP_CPP_MR_P_E) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_f3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_F=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_f3.obj" : $(SOURCE) $(DEP_CPP_MR_P_F) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_F=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_f3.obj" : $(SOURCE) $(DEP_CPP_MR_P_F) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_f4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_F4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_f4.obj" : $(SOURCE) $(DEP_CPP_MR_P_F4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_F4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_f4.obj" : $(SOURCE) $(DEP_CPP_MR_P_F4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_ft3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_FT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_ft3.obj" : $(SOURCE) $(DEP_CPP_MR_P_FT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_FT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_ft3.obj" : $(SOURCE) $(DEP_CPP_MR_P_FT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_ft4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_FT4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_ft4.obj" : $(SOURCE) $(DEP_CPP_MR_P_FT4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_FT4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_ft4.obj" : $(SOURCE) $(DEP_CPP_MR_P_FT4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_g3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_G=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_g3.obj" : $(SOURCE) $(DEP_CPP_MR_P_G) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_G=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_g3.obj" : $(SOURCE) $(DEP_CPP_MR_P_G) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_g4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_G4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_g4.obj" : $(SOURCE) $(DEP_CPP_MR_P_G4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_G4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_g4.obj" : $(SOURCE) $(DEP_CPP_MR_P_G4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_gt3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_GT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_gt3.obj" : $(SOURCE) $(DEP_CPP_MR_P_GT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_GT=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_gt3.obj" : $(SOURCE) $(DEP_CPP_MR_P_GT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_p_gt4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_P_GT4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_gt4.obj" : $(SOURCE) $(DEP_CPP_MR_P_GT4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_P_GT4=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_p_gt4.obj" : $(SOURCE) $(DEP_CPP_MR_P_GT4) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_part.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_PA=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_part.obj" : $(SOURCE) $(DEP_CPP_MR_PA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_PA=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_part.obj" : $(SOURCE) $(DEP_CPP_MR_PA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_phlf3.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_PH=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_phlf3.obj" : $(SOURCE) $(DEP_CPP_MR_PH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_PH=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_phlf3.obj" : $(SOURCE) $(DEP_CPP_MR_PH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_phlf4.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_PHL=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_phlf4.obj" : $(SOURCE) $(DEP_CPP_MR_PHL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_PHL=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_phlf4.obj" : $(SOURCE) $(DEP_CPP_MR_PHL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_pres.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_PR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_pres.obj" : $(SOURCE) $(DEP_CPP_MR_PR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_PR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_pres.obj" : $(SOURCE) $(DEP_CPP_MR_PR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_quat.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_QU=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_quat.obj" : $(SOURCE) $(DEP_CPP_MR_QU) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_QU=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_quat.obj" : $(SOURCE) $(DEP_CPP_MR_QU) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_splin.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_SP=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_splin.obj" : $(SOURCE) $(DEP_CPP_MR_SP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_SP=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_splin.obj" : $(SOURCE) $(DEP_CPP_MR_SP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_sprt.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_SPR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_sprt.obj" : $(SOURCE) $(DEP_CPP_MR_SPR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_SPR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_sprt.obj" : $(SOURCE) $(DEP_CPP_MR_SPR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_stat.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_ST=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_stat.obj" : $(SOURCE) $(DEP_CPP_MR_ST) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_ST=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_stat.obj" : $(SOURCE) $(DEP_CPP_MR_ST) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_view.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_VI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_view.obj" : $(SOURCE) $(DEP_CPP_MR_VI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_VI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_view.obj" : $(SOURCE) $(DEP_CPP_MR_VI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\Mr_vram.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_VR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_vram.obj" : $(SOURCE) $(DEP_CPP_MR_VR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_VR=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\Mr_vram.obj" : $(SOURCE) $(DEP_CPP_MR_VR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\mr_anim.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_ANI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_anim.obj" : $(SOURCE) $(DEP_CPP_MR_ANI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_ANI=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_anim.obj" : $(SOURCE) $(DEP_CPP_MR_ANI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\api_src\mr_sound.c

!IF  "$(CFG)" == "api_src - Win32 Release"

DEP_CPP_MR_SO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_sound.obj" : $(SOURCE) $(DEP_CPP_MR_SO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "api_src - Win32 Debug"

DEP_CPP_MR_SO=\
	".\api_src\..\system.h"\
	".\api_src\Mr_all.h"\
	".\api_src\mr_anim.h"\
	".\api_src\Mr_anim2.h"\
	".\api_src\Mr_coll.h"\
	".\api_src\Mr_debug.h"\
	".\api_src\Mr_disp.h"\
	".\api_src\Mr_file.h"\
	".\api_src\Mr_font.h"\
	".\api_src\Mr_frame.h"\
	".\api_src\Mr_fx.h"\
	".\api_src\Mr_Geom.h"\
	".\api_src\mr_gte.h"\
	".\api_src\mr_input.h"\
	".\api_src\Mr_light.h"\
	".\api_src\Mr_math.h"\
	".\api_src\Mr_mem.h"\
	".\api_src\Mr_mesh.h"\
	".\api_src\Mr_misc.h"\
	".\api_src\Mr_mof.h"\
	".\api_src\Mr_obj.h"\
	".\api_src\Mr_ot.h"\
	".\api_src\Mr_part.h"\
	".\api_src\Mr_poly.h"\
	".\api_src\Mr_pres.h"\
	".\api_src\Mr_quat.h"\
	".\api_src\mr_scanc.h"\
	".\api_src\Mr_sound.h"\
	".\api_src\Mr_splin.h"\
	".\api_src\Mr_sprt.h"\
	".\api_src\Mr_stat.h"\
	".\api_src\Mr_sys.h"\
	".\api_src\Mr_view.h"\
	".\api_src\Mr_vram.h"\
	".\api_src\mr_windows.h"\
	".\winsys.h"\
	{$(INCLUDE)}"\dinput.h"\
	

"$(INTDIR)\mr_sound.obj" : $(SOURCE) $(DEP_CPP_MR_SO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
