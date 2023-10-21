//---------------------------------------------------------------------------
//
//	SOUND.C
//
//		Definitions for sound data
//
//---------------------------------------------------------------------------

#include "mr_all.h"
#include "..\merge\frogpsx.h"
#include "sound.h"
#include "project.h"
#include "gamesys.h"
#include "frog.h"
#include "froguser.h"
#include "entity.h"
#include "tempopt.h"

MRSND_VAB_INFO		gVABInfo[]=
{
	{RES_GENERIC_VH,	RES_GENERIC_VB,		-1},
	{RES_CAVES_VH,		RES_CAVES_VB,		-1},
	{RES_DESERT_VH,		RES_DESERT_VB,		-1},
	{RES_FOREST_VH,		RES_FOREST_VB,		-1},
	{RES_JUNGLE_VH,		RES_JUNGLE_VB,		-1},
	{RES_ORIGINAL_VH,	RES_ORIGINAL_VB,	-1},
	{-1,				-1,					-1},			// This level was removed, but is still needed for ordering.
	{RES_SWAMP_VH,		RES_SWAMP_VB,		-1},
	{RES_SKY_VH,		RES_SKY_VB,			-1},
	{RES_SUBURBIA_VH,	RES_SUBURBIA_VB,	-1},
	{RES_INDUST_VH,		RES_INDUST_VB,		-1},
	{RES_SELECT_VH,		RES_SELECT_VB,		-1},

	
	// temp by martin... appologies if i checked it in by accident
//	{RES_CAVES_VH,		RES_CAVES_VB,		-1},
//	{RES_JUNGLE_VH,		RES_JUNGLE_VB,		-1},
	
	{-1,					-1,				-1}
};

MRSND_GROUP_INFO	gGroupInfo[]=
{
	0,	4,			// FROGGER
	5,  21,			// ENTITY

	22,	23,			// UNKNOWN.

// Select
	0,	23,			// Select ( all at once )

	-1,	-1
};

// Split by theme.
MRSND_SAMPLE_INFO	gSampleInfo[]=
{	
	//									GENERIC SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	0,	0,	 60,   60,	 0,	100,	 NULL},		// GEN_FLY_BUZZ
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	1,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_DROWN1
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	2,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_DROWN2
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	3,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_CROAK
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	4,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_FALL1
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	5,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_FLY_GULP
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	6,	0,	 58,   60,	 0,	120,	 NULL},		// GEN_FROG_HOP
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	7,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_HOP_SUPER
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	8,	0,	 72,   60,	 0,	127,	 NULL},		// MUSIC_LEVEL_COMPLETE
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	9,	0,	 60,   60,	 0,	127,	 NULL},		// MUSIC_TARGET_COMPLETE
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	10,	0,	 72,   60,	 0,	127,	 NULL},		// MUSIC_TIMEOUT
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	11,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_ENTITY_DIVE1
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	12,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_HIT_GROUND
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	13,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_SPLAT
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	14,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_THUD
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	15,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_SPLASH1
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	16,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_BABY_FROG
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	17,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_EXPLODE
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	18,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_GOLD_FROG_CROAK
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_ENTITY,	19,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_SPLASH2
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	20,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_SLURP
	{MRSNDVF_LOOPED,VAB_GENERIC,SFX_GROUP_ENTITY,	21,	0,	 60,   60,	 0,	100,	 NULL},		// GEN_FLY_BUZZ02,
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	22,	0,	 48,   60,	 0,	126,	 NULL},		// MUSIC_GOLD_COMPLETE
	{MRSNDVF_LOOPED,VAB_GENERIC,SFX_GROUP_FROGGER,	23,	0,	 60,   60,	 0,	120,	 NULL},		// MUSIC_DRUMLOAD
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	24,	0,	 72,   60,	 0,	126,	 NULL},		// GEN_CLOCK_TICK
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	25,	0,	 72,   60,	 0,	126,	 NULL},		// GEN_CLOCK_TOCK
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	26,	0,	 72,   60,	 0,	120,	 NULL},		// GEN_EXTRA_LIFE
	// These's are the same samples as above, only used for different things.
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	6,	0,	 64,   60,	 0,	126,	 NULL},		// GEN_BABY_FROG_HOP
	{MRSNDVF_REPEAT,VAB_GENERIC,SFX_GROUP_FROGGER,	3,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_CROAK_REPEAT  
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	12,	0,	 60,   60,   0, 120,	 NULL},		// GEN_FROG_COLL_STACK
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	12,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_STUNNED
	{MRSNDVF_SINGLE,VAB_GENERIC,SFX_GROUP_FROGGER,	5,	0,	 60,   60,	 0,	120,	 NULL},		// GEN_FROG_SCARED

	// 									CAVES SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		0,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_BAT
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		1,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_FIREFLY
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		2,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_LAVADROP_BUBBLE
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		3,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_LAVADROP_FLOORHIT
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,	    4,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_ROCKFALLFLOOR
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		5,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_ROPEBRIDGE01
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		6,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_ROPEBRIDGE02
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,	    7,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_SLIME
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,	    8,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_SNAIL_MOVE
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,		9,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_SNAIL_SLIME
	{MRSNDVF_LOOPED,VAB_CAVES,SFX_GROUP_ENTITY,	   10,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_SPIDER
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,	   11,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_VAMP_BAT
	{MRSNDVF_LOOPED,VAB_CAVES,SFX_GROUP_ENTITY,	   12,	0,	 60,   60,	 0,	100,	 NULL},		// CAV_GLOW_WORM
	{MRSNDVF_SINGLE,VAB_CAVES,SFX_GROUP_ENTITY,	   13,	0,	 60,   60,	 0,	120,	 NULL},		// CAV_FROG_SLIDE

	// 									DESERT SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	0,	0,	 60,   60,	 0,	120,	 NULL},		// DES_BISON (CALL)
	{MRSNDVF_LOOPED,VAB_DESERT,SFX_GROUP_ENTITY,	1,	0,	 60,   60,	 0,	126,	 NULL},		// DES_BISON_NOISE
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	2,	0,	 60,   60,	 0,	120,	 NULL},		// DES_CRACK
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	3,	0,	 60,   60,	 0,	120,	 NULL},		// DES_EARTHQUAKE
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	4,	0,	 60,   60,	 0,	120,	 NULL},		// DES_ROCK_BOUNCE
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	5,	0,	 60,   60,	 0,	120,	 NULL},		// DES_ROCK_BREAK
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	6,	0,	 60,   60,	 0,	120,	 NULL},		// DES_ROCK_ROLL
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY, 	7,	0,	 60,   60,	 0,	120,	 NULL},		// DES_HOLE01
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY, 	8,	0,	 60,   60,	 0,	120,	 NULL},		// DES_HOLE02
	{MRSNDVF_LOOPED,VAB_DESERT,SFX_GROUP_ENTITY,	9,	0,	 48,   60,	 0,	120,	 NULL},		// DES_LIZARD
	{MRSNDVF_LOOPED,VAB_DESERT,SFX_GROUP_ENTITY, 	10,	0,	 60,   60,	 0,	120,	 NULL},		// DES_SALAMANDER
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY, 	11,	0,	 60,   60,	 0,	120,	 NULL},		// DES_SANDSTORM
	{MRSNDVF_LOOPED,VAB_DESERT,SFX_GROUP_ENTITY, 	12,	0,	 60,   60,	 0,	126,	 NULL},		// DES_SNAKE_HISS
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY, 	13,	0,	 60,   60,	 0,	126,	 NULL},		// DES_SNAKE_RATTLE
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	14,	0,	 60,   60,	 0,	120,	 NULL},		// DES_VULTURE
	{MRSNDVF_LOOPED,VAB_DESERT,SFX_GROUP_ENTITY,	15,	0,	 60,   60,	 0,	120,	 NULL},		// DES_TUMBLEWEED
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	16,	0,	 60,   60,	 0,	120,	 NULL},		// DES_CROCODILE_SNAP
	{MRSNDVF_SINGLE,VAB_DESERT,SFX_GROUP_ENTITY,	17,	0,	 60,   60,	 0,	120,	 NULL},		// DES_CROCODILE_MUNCH

	// 									FOREST SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_LOOPED,VAB_FOREST,SFX_GROUP_ENTITY,	0,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_BEE_BUZZ
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	1,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_BEE_STING
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	2,	0,	 60,   60,	 0,	126,	 NULL},		// FOR_BRANCH_SNAP
	{MRSNDVF_LOOPED,VAB_FOREST,SFX_GROUP_ENTITY,	3,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_RIVER
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY, 	4,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_OWL01
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY, 	5,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_OWL02
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	6,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_SQUIRREL
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	7,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_BIRD_WING
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	8,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_BIRD_WING_FRENZIED
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	9,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_SWAN_CALL
	{MRSNDVF_SINGLE,VAB_FOREST,SFX_GROUP_ENTITY,	10,	0,	 60,   60,	 0,	120,	 NULL},		// FOR_SWAN_CALL_FRENZIED


	// 									JUNGLE SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	0,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BIRD_CALL
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	1,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BIRD_CALL_FRENIZED
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	2,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BIRD_WING
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	3,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BIRD_WING_FRENIZED
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	4,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BITE
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	5,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_BITE_SWALLOW
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	6,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_FROG_CROC_MUNCH
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	7,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_FROG_CROC_SNAP
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	8,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_HIPPO
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	9,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_MONKEY_CHAT
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	10,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_MONKEY_SCREAM
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	11,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_RHINO_GROWL
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	12,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_SCORPION
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	13,	0,	 60,   60,	 0,	120,	 NULL},		// JUN_WATER_NOISE
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	14,	0,	 60,   60,	 0,	120,	 NULL},		// OUT_FROG_EXPLODE
	{MRSNDVF_LOOPED,VAB_JUNGLE,SFX_GROUP_ENTITY,	15,	0,	 56,   60,	 0,	120,	 NULL},		// OUT_STONE_RUMBLE_REPEAT
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	16,	0,	 60,   60,	 0,	120,	 NULL},		// OUT_STONE_RUMBLE
	{MRSNDVF_SINGLE,VAB_JUNGLE,SFX_GROUP_ENTITY,	7,	0,	 72,   60,	 0,	120,	 NULL},		// JUN_PLANT_SNAP

	// 									ORIGINAL SFX.
	//																	  	  VOL			
	// FLAGS       		VAB   		GROUP         	 PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY,    0,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_BULLDOZER_HORN
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY,    1,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_BULLDOZER_HORN02
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY,    2,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_CAR_HORN01
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY,    3,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_CAR_HORN02
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY,	  4,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_CROCODILE_SNAP
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_FROGGER,   5,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_FROG_CROC_MUNCH
	{MRSNDVF_LOOPED,VAB_ORIGINAL,SFX_GROUP_ENTITY, 	  6,	0,	 68,   60,	 0,	90,		 NULL},		// ORG_ROAD_NOISE
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY, 	  7,	0,	 60,   60,	 0,	100,	 NULL},		// ORG_SNAKE_HISS
	{MRSNDVF_LOOPED,VAB_ORIGINAL,SFX_GROUP_ENTITY, 	  8,	0,	 60,   60,	 0,	90,		 NULL},		// ORG_WATER_NOISE
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY, 	  9,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_LORRY_HORN01
	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_ENTITY, 	 10,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_LORRY_HORN02

	// 									SWAMP SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,		0,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_CRUSHER
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_FROGGER,   	1,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_NUCLEAR_BARREL_EXPLODE
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,		2,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_NUCLEAR_BARREL_GEIGER
 	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_FROGGER,   	3,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_HOLLOW_THUD
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,		4,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_RAT
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,  	5,	0,	 60,   60,	 0,	50,		 NULL},		// SWP_STAT_FLUME
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,  	6,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_STAT_MARSH
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,  	7,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_STAT_PIPE_HOLE
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,  	8,	0,	 60,   60,	 0,	100, 	 NULL},		// SWP_STAT_WEIR
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY,  	9,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_ACID_DRIP
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	10,	0,	 60,   60,	 0,	50,	 	 NULL},		// SWP_WATERNOISE
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	11,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_SLIPPING
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	12,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_BIRD_WING
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	13,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_BIRD_WING_FRENZIED
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	14,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_PELICAN_CALL
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	15,	0,	 60,   60,	 0,	120,	 NULL},		// SWP_PELICAN_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SWAMP,SFX_GROUP_ENTITY, 	16,	0,	 60,   60,	 0,	127,	 NULL},		// SWP_SNAIL_MOVE

	// 									SKY SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	   0,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_BIPLANE1
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	   1,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_BIPLANE_BANNER1
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	   2,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_PELICAN_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,     3,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_PELICAN_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	   4,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_BIRD_WING
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,     5,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_BIRD_WING_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	   6,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_CROw_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,     7,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_CROW_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,      8,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_SEAGULL_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,	   9,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_SEAGULL_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  10,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_GOOSE_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,	  11,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_GOOSE_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,	  12,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_BIRD_SMALL1
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  13,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_FLOCKING1
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  14,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_HAWK_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  15,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_HAWK_DIVE
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,    16,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_HELICOPTER_FROG_KILL
	{MRSNDVF_REPEAT,VAB_SKY,SFX_GROUP_ENTITY,	  17,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_HELICOPTER_NOISE
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,    18,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_HELIUM_BALLOON_POP
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  19,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_JET1
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,     20,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_JET3
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY, 	  21,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_DUCK_CALL
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,    22,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_DUCK_CALL_FRENZIED
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_ENTITY,	  23,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_RUBBER_BALLOON_FART
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_FROGGER,    24,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_RUBBER_BALLOON_SQUEAK
	{MRSNDVF_SINGLE,VAB_SKY,SFX_GROUP_UNKNOWN,    25,	0,	 60,   60,	 0,	120,	 NULL},		// SKY_WIND

	// 									SUBURBIA SFX.
	//																	  VOL			
	// FLAGS       		VAB   		   GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY,     0,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_CAR_HORN01
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY,     1,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_CAR_HORN02
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY,     2,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_DOG_BARK
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_FROGGER,    3,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_DOG_EAT
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY,     4,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_DOG_GROWL
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_FROGGER,	   5,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_FROG_MOWED
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	   6,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_LORRY_HORN01
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	   7,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_LORRY_HORN02
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	   8,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_MOWER
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	   9,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_SWAN_CALL
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	  10,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_PELICAN_WING
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	  11,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_SNAKE_HISS
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	  12,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_WATER_NOISE
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	  13,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_ROAD_NOISE
	{MRSNDVF_SINGLE,VAB_SUBURBIA,SFX_GROUP_ENTITY, 	  14,	0,	 60,   60,	 0,	120,	 NULL},		// SUB_PELICAN_CALL


	// 									INDUSTRIAL SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         	  PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   0,	0,	 60,   60,	 0,	120,	 NULL},		// IND_CHAIN
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   1,	0,	 60,   60,	 0,	120,	 NULL},		// IND_COGS
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   2,	0,	 60,   60,	 0,	120,	 NULL},		// IND_HYDRAULIC
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   3,	0,	 60,   60,	 0,	120,	 NULL},		// IND_LAVA
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   4,	0,	 60,   60,	 0,	120,	 NULL},		// IND_METAL_SMASH
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   5,	0,	 60,   60,	 0,	120,	 NULL},		// IND_PLATFORM_FALLING
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   6,	0,	 60,   60,	 0,	120,	 NULL},		// IND_STREAM_JET3
	{MRSNDVF_SINGLE,VAB_INDUSTRIAL,SFX_GROUP_ENTITY,   7,	0,	 60,   60,	 0,	120,	 NULL},		// IND_SWITCH

	// 									SELECT SFX.
	//																	  VOL			
	// FLAGS       		VAB   		GROUP         PROG TONE	PITCH P MOD	MIN MAX  NAME
	{MRSNDVF_SINGLE,VAB_SELECT,SFX_GROUP_SELECT,	0,	0,	 60,   60,	 0,	120,	 NULL},		// SEL_CANCEL
	{MRSNDVF_SINGLE,VAB_SELECT,SFX_GROUP_SELECT,	1,	0,	 60,   60,	 0,	120,	 NULL},		// SEL_HI_SCORE_COUNT
	{MRSNDVF_SINGLE,VAB_SELECT,SFX_GROUP_SELECT,	2,	0,	 60,   60,	 0,	120,	 NULL},		// SEL_HI_SCORE_COUNT0
	{MRSNDVF_SINGLE,VAB_SELECT,SFX_GROUP_SELECT,	3,	0,	 60,   60,	 0,	120,	 NULL},		// SEL_SCORE_FINISH
	{MRSNDVF_SINGLE,VAB_SELECT,SFX_GROUP_SELECT,	0,	0,	 60,   60,	 0,	120,	 NULL},		// SEL_SPLASH


	{NULL,			0,0,					0,	0, 		0, 		0,		0,  0,		NULL},
};

#ifdef	MR_DEBUG
	MR_LONG	current_sfx = 0;
#endif

/******************************************************************************
*%%%% TestSoundEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	TestSoundEffects(MR_VOID)
*
*	FUNCTION	Allows to scan through VAB playing each SFX.
*
*	L1	-	Decreases SFX number. (To Play)
*	R1	-	Increase SFX number. (To Play)
*	L2  - 	Play's current SFX.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Gary Richards	Created.
*
*%%%**************************************************************************/
MR_VOID	TestSoundEffects(MR_VOID)
{
#ifdef	MR_DEBUG

		// Check the current SFX.
		if (MR_CHECK_PAD_PRESSED(4,FRR_LEFT_1))
		{
			if (current_sfx > 0)
				current_sfx--;
		}

		if (MR_CHECK_PAD_PRESSED(4,FRR_RIGHT_1))
			current_sfx++;

		if (MR_CHECK_PAD_PRESSED(4,FRR_LEFT_2))
			MRSNDPlaySound((current_sfx+SFX_SUB_CAR_HORN01), NULL, 0, 0);
#endif
};

/******************************************************************************
*%%%% InitialiseVab
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseVab(MR_VOID)
*
*	FUNCTION	Loads the level specific VAB file for the theme.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Gary Richards	Created.
*
*%%%**************************************************************************/
MR_VOID	InitialiseVab(MR_VOID)
{
#ifdef PSX
#ifdef EXPERIMENTAL
	MR_ULONG	saved_sp;


	saved_sp = SetSp(saved_stack);
#endif
#endif

#ifdef MR_API_SOUND
	MRLoadResource(gVABInfo[Game_map_theme].va_vh_resource_id);
	MRProcessResource(gVABInfo[Game_map_theme].va_vh_resource_id);
	MRLoadResource(gVABInfo[Game_map_theme].va_vb_resource_id);
	MRProcessResource(gVABInfo[Game_map_theme].va_vb_resource_id);
	MRSNDOpenVab(Game_map_theme, TRUE);
	
	// Remove the body once sitting in SRAM.
	MRUnloadResource(gVABInfo[Game_map_theme].va_vb_resource_id);
#endif

#ifdef PSX
#ifdef EXPERIMENTAL
	SetSp(saved_sp);
#endif
#endif
}

/******************************************************************************
*%%%% PlaySoundDistance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlaySoundDistance(SFX,
										  distance)
*
*	FUNCTION	Plays sound effect IF Frogger is within distance.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	Gary Richards	Created.
*
*%%%**************************************************************************/
MR_VOID	PlaySoundDistance(LIVE_ENTITY* live_entity, MR_LONG sfx, MR_LONG distance)
{
	FROG*		frog;
	MR_USHORT	frog_index;
	MR_LONG		closest_distance;
	MR_SVEC		svec;
	MR_SVEC		svec_offset;
	MR_LONG		value;

	// search for all 4 possible frogs
	frog_index			= 0;
	closest_distance	= 9999999;

	// To stop play SFX when collecting checkpoint in single player mode.
	if (Game_total_players <= 1)
		{
		switch(Frogs[0].fr_mode)
			{
			case FROG_MODE_HIT_CHECKPOINT:
			case FROGUSER_MODE_CHECKPOINT_COLLECTED:
				return;
				break;
			}
		}

	// No new SFX if game is OVER.
	if (Game_over_no_new_sound)
		return;

	while (frog_index < 4)
		{
		frog = &Frogs[frog_index++];

		// is frog active?
		if (frog->fr_flags & FROG_ACTIVE)
			{
			// Adjust the position of the entity collision point.
			//switch(script[3])
			//	{
				//-------------------------------------------------------------------
			//	case ENTSCR_COORD_X:
					svec_offset.vx = 0;		//script[4];
					svec_offset.vy = 0;
					svec_offset.vz = 0;
			//		break;
				//-------------------------------------------------------------------
			//	case ENTSCR_COORD_Y:
			//		svec_offset.vx = 0;
			//		svec_offset.vy = script[4];
			//		svec_offset.vz = 0;
			//		break;
				//-------------------------------------------------------------------
			//	case ENTSCR_COORD_Z:
			//		svec_offset.vx = 0;
			//		svec_offset.vy = 0;
			//		svec_offset.vz = script[4];
			//		break;
				//-------------------------------------------------------------------
			//	}

			MRApplyMatrixSVEC(live_entity->le_lwtrans, (MR_SVEC*)&svec_offset.vx, (MR_SVEC*)&svec_offset.vx);
			svec_offset.vx += live_entity->le_lwtrans->t[0];
			svec_offset.vy += live_entity->le_lwtrans->t[1];
			svec_offset.vz += live_entity->le_lwtrans->t[2];

			svec.vx = frog->fr_lwtrans->t[0] - svec_offset.vx;
			svec.vy = frog->fr_lwtrans->t[1] - svec_offset.vy;
			svec.vz = frog->fr_lwtrans->t[2] - svec_offset.vz;

			closest_distance = MIN(closest_distance, MR_SVEC_MOD(&svec));
			}
		}

	value = MR_SQRT(closest_distance);
	if (distance > MR_SQRT(closest_distance))
		MRSNDPlaySound(sfx, NULL, 0, 0);

}

/******************************************************************************
*%%%% PlayMovingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayMovingSound(live_entity,
*					   					sfx,
*					   				  	min_radius,
*					   					max_radius)
*
*	FUNCTION	Creates and plays a moving sound. Create as a Frogger Wrapper for the API.
*
*	INPUT		live_entity	-	Live_entity to attach sound to.
*				sfx			-	Sample to play.
*				min_radius	-	OverRide for the min default radius.
*				max_radius	-	OverRide for the max default radius.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Gary Richards	Created.
*
*%%%**************************************************************************/
MR_VOID	PlayMovingSound(LIVE_ENTITY* live_entity, MR_LONG sfx, MR_LONG min, MR_LONG max)
{
	// To stop play SFX when collecting checkpoint in single player mode.
	if (Game_total_players <= 1)
		{
		switch(Frogs[0].fr_mode)
			{
			case FROG_MODE_HIT_CHECKPOINT:
			case FROGUSER_MODE_CHECKPOINT_COLLECTED:
				return;
				break;
			}
		}

	// No new SFX if game is OVER.
	if (Game_over_no_new_sound)
		return;
	
	if (live_entity->le_moving_sound == NULL)
		{
		(MRSND_MOVING_SOUND*)live_entity->le_moving_sound =
								 	MRSNDCreateMovingSound(	(MR_VEC*)live_entity->le_lwtrans->t, 
															(MR_VEC*)live_entity->le_lwtrans->t,
															(MR_SHORT)sfx,
															(MRSND_MOVING_SOUND**)&live_entity->le_moving_sound);
		if (live_entity->le_moving_sound)
			{
#ifdef	MOVING_SOUND_DEBUG
			// For testing we write the unique_id to the min radius for easy debugging.
			((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_min_radius = live_entity->le_entity->en_unique_id;	//min;
#else
			// Let see if we need to over-write the default MIN radius.
	 		if (min != -1)
				((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_min_radius = min;
#endif

			if (max != -1)
				((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_max_radius = max;
			} 
		}
}

/******************************************************************************
*%%%% KillMovingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillMovingSound(live_entity)
*
*	FUNCTION	Kills a moving sound. Created as a Frogger Wrapper for the API.
*
*	INPUT		live_entity	-	Live_entity which has attach sound. (Or NOT)
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Gary Richards	Created.
*
*%%%**************************************************************************/
MR_VOID	KillMovingSound(LIVE_ENTITY* live_entity)
{
	// Check to make sure that there is a moving sound to kill
	if (live_entity->le_moving_sound != NULL)
		MRSNDKillMovingSound(live_entity->le_moving_sound);
}

// A list of pitches to play the level_complete and the target_complete music.

MR_LONG	MusicPitchTable[60][2]=
{
// ------------------------------------------------------------
	12,	 0,				// Caves 1
	15,	 3,				// Caves 2
	12,	 0,				// Caves 1
	15,	 3,				// Caves 2
	12,	 0,				// Caves 1
	15,	 3,				// Caves 2
// ------------------------------------------------------------
	12,	 0,				// Desert 2
	15,	 3,				// Desert 1
	12,	 0,				// Desert 2
	12,	 0,				// Desert 2
	15,	 3,				// Desert 1
	15,	 3,				// Desert 1
// ------------------------------------------------------------
	12,	 0,				// Forest 2
	10,	-2,				// Forest 1
	12,	 0,				// Forest 2
	10,	-2,				// Forest 1
	12,	 0,				// Forest 2
	10,	-2,				// Forest 1
// ------------------------------------------------------------
	15,	 3,				// Jungle 1
	15,	 3,				// Jungle 1
	15,	 3,				// Jungle 1
	15,	 3,				// Jungle 1
	15,	 3,				// Jungle 1
	15,	 3,				// Jungle 1
// ------------------------------------------------------------
	11,	-1,				// Original 1
	11,	-1,				// Original 1
	11,	-1,				// Original 2
	11,	-1,				// Original 2
	11,	-1,				// Original 2
	11,	-1,				// Original 1
// ------------------------------------------------------------
	0,	 0,				// Ruins
	0,	 0,				// Ruins
	0,	 0,				// Ruins
	0,	 0,				// Ruins
	0,	 0,				// Ruins
	0,	 0,				// Ruins
// ------------------------------------------------------------
	8,	-4,				// Swamp 2
	8,	-4,				// Swamp 2
	8,	-4,				// Swamp 1
	8,	-4,				// Swamp 2
	8,	-4,				// Swamp 1
	8,	-4,				// Swamp 1
// ------------------------------------------------------------
	10,	-2,				// Sky 2
	10,	-2,				// Sky 1
	10,	-2,				// Sky 2
	10,	-2,				// Sky 2
	10,	-2,				// Sky 1
	10,	-2,				// Sky 1
// ------------------------------------------------------------
	10,	-2,				// Suburbia 1
	12,	 0,				// Suburbia 2
	12,	 0,				// Suburbia 2
	10,	-2,				// Suburbia 1
	12,	 0,				// Suburbia 2
	12,	 0,				// Suburbia 2
// ------------------------------------------------------------
	15,	 3,				// Industrial 2
	 9,	-3,				// Industrial 1
	15,	 3,				// Industrial 2
	 9,	-3,				// Industrial 1
	15,	 3,				// Industrial 2
	 9,	-3,				// Industrial 1
// ------------------------------------------------------------
};
