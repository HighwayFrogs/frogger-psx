#//
#// Linux Makefile for Frogger (PlayStation Version)
#// -------------------------------------------
#// Created by Kneesnap for Linux-compatible compilation, with GCC.
#// Thanks Dezgeg for figuring out the final steps needed to byte-match the executable.
#//
#// Intended for use with GNU make, but may support other versions of make.
#// This completely removes the original build toolchain (PsyQ SDK Tools) in favor of open source replacements.
#// Incredibly, it is still capable of a byte-matching compilation, despite even the hashing behavior specific to the original assembler/linker for the bss section.
#// This has been done by having a bss.s which manually enforces the order of all the symbols in the bss section, and likewise sbss.s for the sbss section.
#//

.SECONDEXPANSION:
.SECONDARY:

#//-------------------------------------------------------------------------------------------
#// Directories

SDK_DIR			:= sdk
GAME_SRC_DIR	:= source
ASM_SRC_DIR		:= $(GAME_SRC_DIR)/linux
API_SRC_DIR		:= $(GAME_SRC_DIR)/API.SRC
INCLUDE_DIR		:= include
OUTPUT_BASE		:= frogger
OUTPUT_EXE		:= $(OUTPUT_BASE).exe
OUTPUT_MAP		:= $(OUTPUT_BASE).map

#//-------------------------------------------------------------------------------------------
#// Compiler options and flags

GCC				:= sdk/bin/gcc-2.6.3/bin/linux-x64/
INCLUDE			:= include
CROSS			:= mipsel-linux-gnu-
AR				:= $(CROSS)ar
AS				:= $(CROSS)as
LD				:= $(CROSS)ld
OBJCOPY			:= $(CROSS)objcopy
AS_FLAGS		+= -I$(INCLUDE) -march=r3000 -mtune=r3000 -no-pad-sections -O1 -G0
CPP_FLAGS		+= -I$(INCLUDE) -undef -Wunused -Wmissing-prototypes -Wuninitialized -lang-c -lang-c-c++-comments
CPP_FLAGS		+= -Dmips -D__GNUC__=2 -D__OPTIMIZE__ -D__mips__ -D__mips -Dpsx -D__psx__ -D__psx -D_PSYQ -D__EXTENSIONS__ -D_MIPSEL -D_LANGUAGE_C -DLANGUAGE_C -D__CHAR_UNSIGNED__ -DBUILDING_ON_LINUX

LD_SCRIPT		:= frogger.ld
LD_FLAGS		:= -nostdlib -G8 -T $(LD_SCRIPT) -o $(OUTPUT_EXE) -Map $(OUTPUT_MAP)

# 'make MODERN_GCC=1'
#ifdef MODERN_GCC
#CC1			:= $(shell $(CROSS)gcc -print-prog-name=cc1)
#CPP			:= $(CROSS)cpp
#CC_FLAGS		+= -O3 -G0 -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -march=r3000 -gcoff -version -quiet
#CC_FLAGS		+= -imultiarch mipsel-linux-gnu -mel -march=mips32r2 -mfpxx -mllsc -mno-lxc1-sxc1 -mno-madd4 -mips32r2 -mno-shared -mabi=32 -fstack-protector-strong -o /dev/stdout
#else
CC1				:= $(GCC)cc1
CPP				:= $(GCC)cpp
CC_FLAGS		+= -O3 -G8 -mgpopt -funsigned-char -w -fpeephole -ffunction-cse -fpcc-struct-return -fcommon -fverbose-asm -msoft-float -g -fgnu-linker -mgas -gcoff -quiet
#endif

#//-------------------------------------------------------------------------------------------
#// Tooling

MAKE		:= make
PYTHON		:= python3
MASPSX_DIR	:= $(SDK_DIR)/maspsx
MASPSX_APP	:= $(MASPSX_DIR)/maspsx.py
MASPSX		:= $(PYTHON) $(MASPSX_APP) --aspsx-version=2.56 --dont-force-G0 -G8 --use-comm-section

#//-------------------------------------------------------------------------------------------
#// Objects

GAME_OBJ_C_LIST =	main.o		sprdata.o	project.o	gamefont.o	stream.o	\
					formlib.o	gamesys.o	mapload.o	mapdisp.o	library.o	\
					mapview.o	camera.o	entity.o	form.o		options.o	\
					frog.o		grid.o		path.o		zone.o		collide.o	\
					misc.o		mapdebug.o	entlib.o	scripts.o	scripter.o	\
					playxa.o	sound.o		memcard.o	ent_des.o	ent_swp.o	\
					ent_sub.o	ent_sky.o	ent_org.o	ent_jun.o	ent_gen.o	\
					ent_for.o	ent_cav.o	ent_arn.o	ent_vol.o	hud.o		\
					score.o		froguser.o	tempopt.o	effects.o	xalist.o	\
					select.o	model.o		hsview.o	froganim.o	hsinput.o	\
					credits.o	loadsave.o	particle.o	water.o		pause.o

GAME_OBJ_S_LIST = snmain.o sbss.o bss.o fastram.o  binaries.o mapasm.o

API_OBJ_C_LIST = mr_anim.o  mr_anim2.o mr_anim3.o            mr_coll.o  \
                 mr_debug.o mr_disp.o  mr_file.o  mr_font.o  mr_frame.o \
                 mr_fx.o    mr_input.o mr_light.o mr_math.o  mr_mem.o   \
                 mr_mesh.o                        mr_misc.o  mr_mof.o   \
				 mr_obj.o   mr_ot.o    mr_over.o  mr_part.o  mr_pres.o  \
				 mr_sound.o mr_splin.o mr_sprt.o  mr_stat.o  mr_view.o  \
				 mr_vram.o  mr_phlf3.o mr_phlf4.o mr_quat.o

API_OBJ_S_LIST = mr_m_f3.o  mr_m_f4.o  mr_m_ft3.o mr_m_ft4.o \
                 mr_m_g3.o  mr_m_g4.o  mr_m_gt3.o mr_m_gt4.o \
				 mr_m_e3.o  mr_m_e4.o  mr_m_ge3.o mr_m_ge4.o \
				 mr_m_qua.o mr_m_pak.o mr_bin.o

OBJECTS		+=	$(patsubst %, $(GAME_SRC_DIR)/%, $(GAME_OBJ_C_LIST))
OBJECTS		+=	$(patsubst %, $(API_SRC_DIR)/%, $(API_OBJ_C_LIST))
OBJECTS		+=	$(patsubst %, $(API_SRC_DIR)/%, $(API_OBJ_S_LIST))
OBJECTS		+=	$(patsubst %, $(GAME_SRC_DIR)/%, $(GAME_OBJ_S_LIST))
#$(info Objects are $(OBJECTS))

LIBRARIES	+=	$(patsubst %.o, $(API_SRC_DIR)/%.a, $(API_OBJ_C_LIST))
LIBRARIES	+=	$(patsubst %.o, $(API_SRC_DIR)/%.a, $(API_OBJ_S_LIST))
#$(info Libraries are $(LIBRARIES))

LINK_ORDER = \
	source/main.o		source/fastram.o	source/sprdata.o	source/project.o	source/gamefont.o	\
	source/binaries.o	source/stream.o		source/formlib.o	source/gamesys.o	source/mapload.o	\
	source/mapdisp.o	source/library.o	source/mapview.o	source/camera.o		source/entity.o		\
	source/form.o		source/options.o 	source/frog.o		source/grid.o		source/path.o		\
	source/zone.o		source/collide.o	source/misc.o		source/mapdebug.o	source/entlib.o		\
	source/scripts.o	source/scripter.o	source/playxa.o		source/sound.o		source/memcard.o	\
	source/ent_des.o	source/ent_swp.o	source/ent_sub.o	source/ent_sky.o	source/ent_org.o	\
	source/ent_jun.o	source/ent_gen.o	source/ent_for.o	source/ent_cav.o	source/ent_arn.o	\
	source/ent_vol.o	source/hud.o		source/score.o		source/froguser.o	source/tempopt.o	\
	source/effects.o	source/xalist.o		source/select.o		source/model.o		source/hsview.o		\
	source/froganim.o	source/hsinput.o	source/credits.o	source/loadsave.o	source/mapasm.o		\
	source/particle.o	source/water.o		source/pause.o  \
	sdk/lib/elf/putchar.o \
	source/API.SRC/mr_mof.a		source/API.SRC/mr_misc.a	source/API.SRC/mr_frame.a	\
	source/API.SRC/mr_anim.a	source/API.SRC/mr_anim2.a	source/API.SRC/mr_anim3.a	\
	source/API.SRC/mr_obj.a		source/API.SRC/mr_coll.a	source/API.SRC/mr_disp.a	\
	source/API.SRC/mr_view.a	source/API.SRC/mr_mesh.a	source/API.SRC/mr_sprt.a	\
	source/API.SRC/mr_light.a	source/API.SRC/mr_mem.a		source/API.SRC/mr_file.a	\
	source/API.SRC/mr_debug.a	source/API.SRC/mr_input.a	source/API.SRC/mr_font.a	\
	source/API.SRC/mr_fx.a		source/API.SRC/mr_pres.a	\
	source/API.SRC/mr_part.a	source/API.SRC/mr_bin.a		source/API.SRC/mr_vram.a	\
	source/API.SRC/mr_ot.a		source/API.SRC/mr_splin.a	source/API.SRC/mr_stat.a	\
	source/API.SRC/mr_math.a	source/API.SRC/mr_sound.a	source/API.SRC/mr_over.a	\
	source/API.SRC/mr_m_qua.a	source/API.SRC/mr_quat.a	source/API.SRC/mr_m_pak.a	\
	source/API.SRC/mr_phlf3.a	source/API.SRC/mr_phlf4.a	\
	source/API.SRC/mr_m_f3.a	source/API.SRC/mr_m_f4.a	\
	source/API.SRC/mr_m_ft3.a	source/API.SRC/mr_m_ft4.a	\
	source/API.SRC/mr_m_g3.a	source/API.SRC/mr_m_g4.a	\
	source/API.SRC/mr_m_gt3.a	source/API.SRC/mr_m_gt4.a	\
	source/API.SRC/mr_m_e3.a	source/API.SRC/mr_m_e4.a	\
	source/API.SRC/mr_m_ge3.a	source/API.SRC/mr_m_ge4.a	\
	sdk/lib/elf/extracted/libgte.a/geo_00.o \
	sdk/lib/elf/extracted/libgte.a/sincos.o \
	sdk/lib/elf/extracted/libgte.a/geo_01.o \
	sdk/lib/elf/extracted/libgte.a/fog_02.o \
	sdk/lib/elf/extracted/libgte.a/msc00.o \
	sdk/lib/elf/extracted/libgte.a/msc01.o \
	sdk/lib/elf/extracted/libgte.a/sqrtbl.o \
	sdk/lib/elf/extracted/libgte.a/msc02.o \
	sdk/lib/elf/extracted/libgte.a/mtx_000.o \
	sdk/lib/elf/extracted/libgte.a/mtx_004.o \
	sdk/lib/elf/extracted/libgte.a/mtx_005.o \
	sdk/lib/elf/extracted/libgte.a/mtx_03.o \
	sdk/lib/elf/extracted/libgte.a/mtx_04.o \
	sdk/lib/elf/extracted/libgte.a/mtx_05.o \
	sdk/lib/elf/extracted/libgte.a/mtx_06.o \
	sdk/lib/elf/extracted/libgte.a/reg03.o \
	sdk/lib/elf/extracted/libgte.a/smp_00.o \
	sdk/lib/elf/extracted/libgte.a/fgo_00.o \
	sdk/lib/elf/extracted/libgte.a/cstbl.o \
	sdk/lib/elf/extracted/libgte.a/fgo_01.o \
	sdk/lib/elf/extracted/libgte.a/patchgte.o \
	sdk/lib/elf/extracted/libgte.a/trr.o \
	sdk/lib/elf/extracted/libgpu.a/sys.o \
	sdk/lib/elf/extracted/libetc.a/vsync.o \
	sdk/lib/elf/extracted/libetc.a/intr.o \
	sdk/lib/elf/extracted/libetc.a/intr_vb.o \
	sdk/lib/elf/extracted/libetc.a/intr_dma.o \
	sdk/lib/elf/extracted/libetc.a/vmode.o \
	sdk/lib/elf/extracted/libapi.a/c68.o \
	sdk/lib/elf/extracted/libapi.a/c73.o \
	sdk/lib/elf/extracted/libapi.a/c112.o \
	sdk/lib/elf/extracted/libapi.a/c114.o \
	sdk/lib/elf/extracted/libapi.a/a08.o \
	sdk/lib/elf/extracted/libapi.a/a11.o \
	sdk/lib/elf/extracted/libapi.a/a12.o \
	sdk/lib/elf/extracted/libapi.a/a23.o \
	sdk/lib/elf/extracted/libapi.a/a24.o \
	sdk/lib/elf/extracted/libapi.a/a25.o \
	sdk/lib/elf/extracted/libapi.a/a36.o \
	sdk/lib/elf/extracted/libapi.a/a37.o \
	sdk/lib/elf/extracted/libapi.a/a39.o \
	sdk/lib/elf/extracted/libapi.a/a50.o \
	sdk/lib/elf/extracted/libapi.a/a52.o \
	sdk/lib/elf/extracted/libapi.a/a53.o \
	sdk/lib/elf/extracted/libapi.a/a54.o \
	sdk/lib/elf/extracted/libapi.a/a65.o \
	sdk/lib/elf/extracted/libapi.a/a66.o \
	sdk/lib/elf/extracted/libapi.a/a67.o \
	sdk/lib/elf/extracted/libapi.a/a69.o \
	sdk/lib/elf/extracted/libapi.a/a91.o \
	sdk/lib/elf/extracted/libapi.a/l10.o \
	sdk/lib/elf/extracted/libsn.a/open.o \
	sdk/lib/elf/extracted/libsn.a/close.o \
	sdk/lib/elf/extracted/libsn.a/lseek.o \
	sdk/lib/elf/extracted/libsn.a/creat.o \
	source/snmain.o \
	sdk/lib/elf/extracted/libapi.a/c57.o \
	sdk/lib/elf/extracted/libsn.a/read.o \
	sdk/lib/elf/extracted/libsn.a/snread.o \
	sdk/lib/elf/extracted/libsn.a/write.o \
	sdk/lib/elf/extracted/libsn.a/snwrite.o \
	sdk/lib/elf/extracted/libc2.a/memcpy.o \
	sdk/lib/elf/extracted/libc2.a/memset.o \
	sdk/lib/elf/extracted/libc2.a/rand.o \
	sdk/lib/elf/extracted/libc2.a/strcat.o \
	sdk/lib/elf/extracted/libc2.a/strcmp.o \
	sdk/lib/elf/extracted/libc2.a/strcpy.o \
	sdk/lib/elf/extracted/libc2.a/strlen.o \
	sdk/lib/elf/extracted/libc2.a/printf.o \
	sdk/lib/elf/extracted/libc2.a/prnt.o \
	sdk/lib/elf/extracted/libc2.a/ctype.o \
	sdk/lib/elf/extracted/libc2.a/memchr.o \
	sdk/lib/elf/extracted/libc2.a/puts.o \
	sdk/lib/elf/extracted/libc2.a/setjmp.o \
	sdk/lib/elf/extracted/libspu.a/s_i.o \
	sdk/lib/elf/extracted/libspu.a/s_ini.o \
	sdk/lib/elf/extracted/libspu.a/spu.o \
	sdk/lib/elf/extracted/libspu.a/s_m.o \
	sdk/lib/elf/extracted/libspu.a/s_rmp.o \
	sdk/lib/elf/extracted/libapi.a/a07.o \
	sdk/lib/elf/extracted/libspu.a/s_dcb.o \
	sdk/lib/elf/extracted/libspu.a/sr_gaks.o \
	sdk/lib/elf/extracted/libsnd.a/ssinit_c.o \
	sdk/lib/elf/extracted/libsnd.a/ssinit.o \
	sdk/lib/elf/extracted/libsnd.a/sssattr.o \
	sdk/lib/elf/extracted/libspu.a/s_sca.o \
	sdk/lib/elf/extracted/libsnd.a/sssmv.o \
	sdk/lib/elf/extracted/libsnd.a/ssstart.o \
	sdk/lib/elf/extracted/libapi.a/counter.o \
	sdk/lib/elf/extracted/libsnd.a/sscall.o \
	sdk/lib/elf/extracted/libsnd.a/cres.o \
	sdk/lib/elf/extracted/libsnd.a/decres.o \
	sdk/lib/elf/extracted/libsnd.a/pause.o \
	sdk/lib/elf/extracted/libsnd.a/play.o \
	sdk/lib/elf/extracted/libsnd.a/midiread.o \
	sdk/lib/elf/extracted/libsnd.a/miditime.o \
	sdk/lib/elf/extracted/libsnd.a/next.o \
	sdk/lib/elf/extracted/libsnd.a/replay.o \
	sdk/lib/elf/extracted/libsnd.a/ssstop.o \
	sdk/lib/elf/extracted/libsnd.a/sssv.o \
	sdk/lib/elf/extracted/libsnd.a/sstick.o \
	sdk/lib/elf/extracted/libsnd.a/tempo.o \
	sdk/lib/elf/extracted/libsnd.a/ut_cadsr.o \
	sdk/lib/elf/extracted/libsnd.a/ut_cp.o \
	sdk/lib/elf/extracted/libsnd.a/ut_keyv.o \
	sdk/lib/elf/extracted/libsnd.a/ut_pb.o \
	sdk/lib/elf/extracted/libsnd.a/ut_roff.o \
	sdk/lib/elf/extracted/libspu.a/s_sr.o \
	sdk/lib/elf/extracted/libspu.a/s_m_util.o \
	sdk/lib/elf/extracted/libsnd.a/ut_vvol.o \
	sdk/lib/elf/extracted/libsnd.a/vm_aloc2.o \
	sdk/lib/elf/extracted/libsnd.a/vm_doff.o \
	sdk/lib/elf/extracted/libsnd.a/vm_f.o \
	sdk/lib/elf/extracted/libspu.a/s_snv.o \
	sdk/lib/elf/extracted/libspu.a/s_sav.o \
	sdk/lib/elf/extracted/libsnd.a/vm_init.o \
	sdk/lib/elf/extracted/libspu.a/s_m_init.o \
	sdk/lib/elf/extracted/libspu.a/s_it.o \
	sdk/lib/elf/extracted/libsnd.a/vm_n2p.o \
	sdk/lib/elf/extracted/libsnd.a/vm_no1.o \
	sdk/lib/elf/extracted/libsnd.a/vm_nowof.o \
	sdk/lib/elf/extracted/libsnd.a/vm_nowon.o \
	sdk/lib/elf/extracted/libsnd.a/vm_pb.o \
	sdk/lib/elf/extracted/libsnd.a/vm_seq.o \
	sdk/lib/elf/extracted/libsnd.a/vm_vsu.o \
	sdk/lib/elf/extracted/libsnd.a/vs_vab.o \
	sdk/lib/elf/extracted/libspu.a/s_m_f.o \
	sdk/lib/elf/extracted/libspu.a/s_m_int.o \
	sdk/lib/elf/extracted/libsnd.a/vs_vh.o \
	sdk/lib/elf/extracted/libspu.a/s_m_m.o \
	sdk/lib/elf/extracted/libsnd.a/vs_vtb.o \
	sdk/lib/elf/extracted/libspu.a/s_w.o \
	sdk/lib/elf/extracted/libspu.a/s_stsa.o \
	sdk/lib/elf/extracted/libspu.a/s_stm.o \
	sdk/lib/elf/extracted/libsnd.a/vs_vtc.o \
	sdk/lib/elf/extracted/libspu.a/s_itc.o \
	sdk/lib/elf/extracted/libpress.a/libpress.o \
	sdk/lib/elf/extracted/libpress.a/vlc_c.o \
	sdk/lib/elf/extracted/libpress.a/build.o \
	sdk/lib/elf/extracted/libcd.a/cdrom.o \
	sdk/lib/elf/extracted/libcd.a/event.o \
	sdk/lib/elf/extracted/libcd.a/sys.o \
	sdk/lib/elf/extracted/libcd.a/bios.o \
	sdk/lib/elf/extracted/libcd.a/iso9660.o \
	sdk/lib/elf/extracted/libc2.a/strncmp.o \
	sdk/lib/elf/extracted/libcd.a/cdread.o \
	sdk/lib/elf/extracted/libcd.a/cdread2.o \
	sdk/lib/elf/extracted/libcd.a/c_002.o \
	sdk/lib/elf/extracted/libcd.a/c_003.o \
	sdk/lib/elf/extracted/libcd.a/c_004.o \
	sdk/lib/elf/extracted/libcd.a/c_005.o \
	sdk/lib/elf/extracted/libcd.a/c_007.o \
	sdk/lib/elf/extracted/libcd.a/c_008.o \
	sdk/lib/elf/extracted/libcd.a/c_009.o \
	sdk/lib/elf/extracted/libcd.a/c_010.o \
	sdk/lib/elf/extracted/libcd.a/c_011.o \
	sdk/lib/elf/extracted/libds.a/dscb.o \
	sdk/lib/elf/extracted/libcard.a/c171.o \
	sdk/lib/elf/extracted/libcard.a/c172.o \
	sdk/lib/elf/extracted/libcard.a/card.o \
	sdk/lib/elf/extracted/libcard.a/a78.o \
	sdk/lib/elf/extracted/libcard.a/a80.o \
	sdk/lib/elf/extracted/libcard.a/init.o \
	sdk/lib/elf/extracted/libapi.a/pad.o \
	sdk/lib/elf/extracted/libapi.a/a18.o \
	sdk/lib/elf/extracted/libapi.a/a19.o \
	sdk/lib/elf/extracted/libapi.a/a20.o \
	sdk/lib/elf/extracted/libapi.a/a21.o \
	sdk/lib/elf/extracted/libapi.a/l02.o \
	sdk/lib/elf/extracted/libapi.a/l03.o \
	sdk/lib/elf/extracted/libapi.a/patch.o \
	sdk/lib/elf/extracted/libapi.a/sendpad.o \
	sdk/lib/elf/extracted/libapi.a/chclrpad.o \
	sdk/lib/elf/extracted/libcard.a/a74.o \
	sdk/lib/elf/extracted/libcard.a/a75.o \
	sdk/lib/elf/extracted/libcard.a/a76.o \
	sdk/lib/elf/extracted/libcard.a/end.o \
	sdk/lib/elf/extracted/libtap.a/tap.o \
	sdk/lib/elf/extracted/libapi.a/a22.o \
	sdk/lib/elf/extracted/libc2.a/bzero.o \
	sdk/lib/elf/extracted/libsnd.a/vm_g.o \
	source/sbss.o \
	source/bss.o \
	--no-gc-sections

#//-------------------------------------------------------------------------------------------
#// Makefile interface routines (build all, run project, debug project)

all: $(OUTPUT_EXE)

$(MASPSX_APP):
	$(error maspsx was not found! '$(MASPSX_APP)')

# Build game source files
$(GAME_SRC_DIR)/%.o: $(GAME_SRC_DIR)/%.c $(MASPSX_APP)
	$(info )
	$(info ----- Compiling $@ -----)
	$(CPP) $(CPP_FLAGS) $< | $(CC1) $(CC_FLAGS) | $(MASPSX) | $(AS) $(AS_FLAGS) -o $@

# Build game handwritten assembly files.
$(GAME_SRC_DIR)/%.o: $(ASM_SRC_DIR)/%.s
	$(info )
	$(info ----- Assembling $@ -----)
	$(AS) -I$(ASM_SRC_DIR) $(AS_FLAGS) -o $@ $<

# Build API source files
$(API_SRC_DIR)/%.o: $(API_SRC_DIR)/%.c $(MASPSX_APP)
	$(info )
	$(info ----- Compiling $@ -----)
	$(CPP) $(CPP_FLAGS) $< | $(CC1) $(CC_FLAGS) | $(MASPSX) | $(AS) $(AS_FLAGS) -o $@

# Build API handwritten assembly files
$(API_SRC_DIR)/%.o: $(ASM_SRC_DIR)/%.s
	$(info )
	$(info ----- Assembling $@ -----)
	$(AS) -I$(ASM_SRC_DIR) $(AS_FLAGS) -o $@ $<

# Build API Libraries (Using libraries will cause objects which are fully unused to be skipped when linking)
$(API_SRC_DIR)/%.a: $(API_SRC_DIR)/%.o
	$(info )
	$(info ----- Creating library $@ -----)
	$(AR) -rs $@ $<

clean:
	rm -f -- $(OUTPUT_EXE)
	rm -f -- $(OUTPUT_MAP)
	rm -f -- $(GAME_SRC_DIR)/*.o
	rm -f -- $(API_SRC_DIR)/*.o
	rm -f -- $(API_SRC_DIR)/*.a

# This links the PSX EXE from all the objects & libraries.
$(OUTPUT_EXE): $(OBJECTS) $(LIBRARIES)
	$(info )
	$(info ----- Linking -----)
	@$(LD) $(LD_FLAGS) $(LINK_ORDER)

# We cannot use $(info message) here, because the info function is evaluated with all the variables. This evaluation occurs before any shell commands are run, including the command to build the executable, thus it would print an outdated SHA-1 hash, or potentially even fail.
	@echo "Build Success, SHA1: $$(sha1sum $(OUTPUT_EXE))"
	@echo ""

# Phony (Targets which are not treated as file names.)
.PHONY: all, clean
