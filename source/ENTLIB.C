/******************************************************************************
*%%%% entlib.c
*------------------------------------------------------------------------------
*
*	Specific entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	23.04.97	Tim Closs		Created
*	02.04.97	Martin Kift		Added new entity library variable, for size
*								of runtime structure. Also scripting code.
*	12.05.97	Martin Kift		Removed scripting id (moved to form library)
*
*%%%**************************************************************************/


// Include entity files here
#include "entlib.h"
#include "entity.h"
#include "ent_all.h"
#include "scripts.h"

//-----------------------------------------------------------------------------
// Entity library
//-----------------------------------------------------------------------------

ENTITY_BOOK	Entity_library[] =
	{
		{
		// ENTITY_TYPE_STATIC
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_STATIC,
		NULL,
		},
		{
		// ENTITY_TYPE_MOVING
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		NULL,
		},
		{
		// ENTITY_TYPE_CHECKPOINT
		ENTSTRGenCreateCheckPoint,
		ENTSTRGenUpdateCheckPoint,
		ENTSTRGenKillCheckPoint,
		ENTITY_BOOK_STATIC,
		NULL,
		},
		{
		// ENTITY_TYPE_DES_FALLING_ROCK
		ENTSTRDesCreateFallingRock,
		ENTSTRDesUpdateFallingRock,
		ENTSTRDesKillFallingRock,
		ENTITY_BOOK_IMMORTAL,
		sizeof(DESERT_RT_FALLING_ROCK),
		},
		{
		// ENTITY_TYPE_DES_EARTHQUAKE
		NULL,
		NULL,
		NULL,
		ENTITY_BOOK_IMMORTAL,
		sizeof(DESERT_RT_FALLING_ROCK),
		},
		{
		// ENTITY_TYPE_DES_THERMAL
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(DESERT_RT_THERMAL),
		},
		{
		// ENTITY_TYPE_DYNAMIC
		ENTSTRCreateDynamicMOF,
		NULL,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_CAV_WEB
		NULL,
		NULL,
		NULL,
		ENTITY_BOOK_STATIC,
		sizeof(CAV_RT_WEB),
		},
		{
		// ENTITY_TYPE_CAV_SPIDER
		NULL,
		NULL,
		NULL,
		ENTITY_BOOK_IMMORTAL,
		sizeof(CAV_RT_SPIDER),
		},
		{
		// ENTITY_TYPE_CAV_FROGGER_LIGHT
		ENTSTRCavCreateFroggerLight,
		ENTSTRCavUpdateFroggerLight,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(CAVES_RT_FROG_LIGHT),
		},
		{
		// ENTITY_TYPE_ORG_LOG_SNAKE,
		ENTSTROrgCreateLogSnake,
		ENTSTROrgUpdateLogSnake,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(ORG_RT_LOG_SNAKE),
		},
		{
		// ENTITY_TYPE_BONUS_FLY
		ENTSTRGenCreateBonusFly,
		ENTSTRGenUpdateBonusFly,
		ENTSTRGenKillBonusFly,
		ENTITY_BOOK_STATIC | ENTITY_BOOK_TONGUEABLE,
		NULL,
		},
		{
		// ENTITY_TYPE_SUB_TURTLE
		ENTSTRSubCreateTurtle,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		NULL,
		},
		{
		// ENTITY_TYPE_SWP_SQUIRT
		ENTSTRSwpCreateSquirt,
		ENTSTRSwpUpdateSquirt,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(SWAMP_RT_SQUIRT),
		},
		{
		// ENTITY_TYPE_SWP_CRUSHER
		ENTSTRSwpCreateCrusher,
		ENTSTRSwpUpdateCrusher,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(SWAMP_RT_CRUSHER),
		},
		{
		// ENTITY_TYPE_TRIGGER
		ENTSTRCreateTrigger,
		ENTSTRUpdateTrigger,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(ENTSTR_RT_TRIGGER),
		},
		{
		// ENTITY_TYPE_ORG_BABY_FROG
		ENTSTROrgCreateBabyFrog,
		ENTSTROrgUpdateBabyFrog,
		ENTSTROrgKillBabyFrog,
		ENTITY_BOOK_IMMORTAL,
		sizeof(ORG_RT_BABY_FROG),
		},
		{
		// ENTITY_TYPE_DES_SNAKE
		ENTSTRDesCreateSnake,
		ENTSTRDesUpdateSnake,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(DESERT_RT_SNAKE),
		},
		{
		// ENTITY_TYPE_ORG_BEAVER
		ENTSTROrgCreateBeaver,
		ENTSTROrgUpdateBeaver,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER | ENTITY_BOOK_IMMORTAL,
		sizeof(ORG_RT_BEAVER),
		},
		{
		// ENTITY_TYPE_DES_VULTURE
		ENTSTRDesCreateVulture,
		ENTSTRDesUpdateVulture,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(DESERT_RT_VULTURE),
		},
		{
		// ENTITY_TYPE_ORG_FLY
		ENTSTROrgCreateBonusFly,
		ENTSTROrgUpdateBonusFly,
		ENTSTROrgKillBonusFly,
		ENTITY_BOOK_IMMORTAL | ENTITY_BOOK_TONGUEABLE,
		sizeof(ORG_RT_BONUS_FLY),
		},
		{
		// ENTITY_TYPE_ORG_CROC_HEAD
		ENTSTROrgCreateCrocHead,
		ENTSTROrgUpdateCrocHead,
		ENTSTROrgKillCrocHead,
		ENTITY_BOOK_IMMORTAL,
		sizeof(ORG_RT_CROC_HEAD),
		},
		{
		// ENTITY_TYPE_FOR_HIVE
		ENTSTRForCreateHive,
		ENTSTRForUpdateHive,
		ENTSTRForKillHive,
		ENTITY_BOOK_IMMORTAL,
		sizeof(FOREST_RT_HIVE),
		},
		{
		// ENTITY_TYPE_SWP_PRESS
		ENTSTRSwpCreatePress,
		ENTSTRSwpUpdatePress,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(SWAMP_RT_PRESS),
		},
		{
		// ENTITY_TYPE_CAV_FAT_FIRE_FLY
		ENTSTRCavCreateFatFireFly,
		ENTSTRCavUpdateFatFireFly,
		ENTSTRCavKillFatFireFly,
		ENTITY_BOOK_STATIC | ENTITY_BOOK_TONGUEABLE,
		NULL,
		},
		{
		// ENTITY_TYPE_DES_CROC_HEAD
		ENTSTRDesCreateCrocHead,
		ENTSTRDesUpdateCrocHead,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(DES_RT_CROC_HEAD),
		}, 
		{
		// ENTITY_TYPE_MULTIPOINT
		ENTSTRGenCreateMultiPoint,
		NULL,
		ENTSTRGenKillMultiPoint,
		ENTITY_BOOK_STATIC,
		NULL,
		},
		{
		// ENTITY_TYPE_SUB_DOG
		ENTSTRSubCreateDog,
		ENTSTRSubUpdateDog,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(SUBURBIA_RT_DOG),
		},
		{
		// ENTITY_TYPE_DES_CRACK
		ENTSTRDesCreateCrack,
		ENTSTRDesUpdateCrack,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(DES_RT_CRACK),
		},
		{
		// ENTITY_TYPE_CAV_RACE_SNAIL
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		8,
		},
		{
		// ENTITY_TYPE_SWAYING_BRANCH
		ENTSTRCreateDynamicMOF,
		NULL,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(FOREST_RT_SWAYING_BRANCH),
		},
		{
		// ENTITY_TYPE_BREAKING_BRANCH
		ENTSTRForCreateBreakingBranch,
		ENTSTRForUpdateBreakingBranch,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(FOREST_RT_BREAKING_BRANCH)
		},
		{
		// ENTITY_TYPE_SQUIRREL
		ENTSTRForCreateSquirrel,
		ENTSTRForUpdateSquirrel,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER|ENTITY_BOOK_IMMORTAL,
		sizeof(FOREST_RT_SQUIRREL),
		},
		{
		// ENTITY_TYPE_HEDGEHOG
		ENTSTRForCreateHedgehog,
		ENTSTRForUpdateHedgehog,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(FOREST_RT_HEDGEHOG),
		},
		{
		// ENTITY_TYPE_MOVING_PLATFORM
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingPlatformMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER|ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_MOVING_TONGUEABLE
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER | ENTITY_BOOK_TONGUEABLE,
		NULL,
		},
		{
		// ENTITY_TYPE_FIREFLY
		ENTSTRCreateMovingSprite,
		ENTSTRUpdateMovingMOF,				// Although this IS a sprite, we can use this function to move.
		ENTSTRKillMovingSprite,
		ENTITY_BOOK_PATH_RUNNER | ENTITY_BOOK_TONGUEABLE | ENTITY_BOOK_XZ_PARALLEL_TO_CAMERA,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_PLANT
		ENTSTRJunCreatePlant,
		ENTSTRJunUpdatePlant,				
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(JUN_RT_PLANT),
		},
		{
		// ENTITY_TYPE_DES_ROLLING_ROCK
		ENTSTRDesCreateRollingRock,
		ENTSTRDesUpdateRollingRock,				
		ENTSTRDesKillRollingRock,
		ENTITY_BOOK_PATH_RUNNER | ENTITY_BOOK_IMMORTAL,
		sizeof(DESERT_RT_ROLLING_ROCK),
		},

		{
		// ENTITY_TYPE_JUN_ROPE_BRIDGE
		ENTSTRJunCreateRopeBridge,
		ENTSTRJunUpdateRopeBridge,				
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(JUN_RT_ROPE_BRIDGE),
		},
		{
		// ENTITY_TYPE_JUN_HIPPO
		ENTSTRJunCreateHippo,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		NULL,
		},
		{
		// ENTITY_TYPE_VOL_FALLING_PLATFORM
		ENTSTRVolCreateFallingPlatform,
		ENTSTRVolUpdateFallingPlatform,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(DES_RT_CRACK),
		},
		{
		// ENTITY_TYPE_DES_TUMBLE_WEED
		ENTSTRDesCreateTumbleWeed,
		ENTSTRDesUpdateTumbleWeed,
		ENTSTRDesKillTumbleWeed,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(DESERT_RT_TUMBLE_WEED),
		},
		{
		// ENTITY_TYPE_GEN_TOP_LEFT
		ENTSTRGenCreateTopLeft,
		NULL,
		NULL,
		ENTITY_BOOK_STATIC | ENTITY_BOOK_IMMORTAL,
		0,
		},
		{
		// ENTITY_TYPE_GEN_BOTTOM_RIGHT
		ENTSTRGenCreateBottomRight,
		NULL,
		NULL,
		ENTITY_BOOK_STATIC | ENTITY_BOOK_IMMORTAL,
		0,
		},
		{
		// ENTITY_TYPE_GEN_GOLD_FROG
		ENTSTRGenCreateGoldFrog,
		ENTSTRGenUpdateGoldFrog,
		ENTSTRGenKillGoldFrog,
		ENTITY_BOOK_IMMORTAL,
		sizeof(GEN_RT_GOLD_FROG),
		},
		{
		// ENTITY_TYPE_SWP_RAT
		ENTSTRSwpCreateRat,
		ENTSTRSwpUpdateRat,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(SWAMP_RT_RAT),
		},
		{
		// ENTITY_TYPE_VOL_COLOUR_SWITCH
		ENTSTRVolCreateColourTrigger,
		ENTSTRVolUpdateColourTrigger,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		sizeof(VOL_RT_COLOUR_TRIGGER),
		},
		{
		// ENTITY_TYPE_JUN_OUTRO_DOOR
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_STATUE
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_PLINTH
		ENTSTRJunCreatePlinth,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_GOLD_FROG
		ENTSTRJunCreateGoldFrog,
		ENTSTRJunUpdateGoldFrog,
		ENTSTRJunKillGoldFrog,
		ENTITY_BOOK_IMMORTAL,
		sizeof (JUN_OUTRO_RT_GOLD_FROG),
		},
		{
		// ENTITY_TYPE_JUN_STONE_FROG
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_OUTRO
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_SWP_SLUG
		ENTSTRSwpCreateSlug,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER|ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_BOUNCY_MUSHROOM
		ENTSTRJunCreateBouncyMushroom,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_STATIC,
		NULL,
		},
		{
		// ENTITY_TYPE_SUB_LAWNMOWER
		ENTSTRSubCreateLawnmower,
		ENTSTRSubUpdateLawnmower,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		sizeof(SUB_RT_LAWNMOWER),
		},
		{
		// ENTITY_TYPE_NUCLEAR_BARREL
		ENTSTRCreateMovingMOF,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER|ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_JUN_SCORPION
		ENTSTRJunCreateScorpion,
		ENTSTRUpdateMovingMOF,
		ENTSTRKillMovingMOF,
		ENTITY_BOOK_PATH_RUNNER,
		NULL,
		},
		{
		// ENTITY_TYPE_STATIC_NOISE
		ENTSTRCreateStationaryMOF,
		NULL,
		ENTSTRKillStationaryMOF,
		ENTITY_BOOK_STATIC|ENTITY_BOOK_IMMORTAL,
		NULL,
		},
		{
		// ENTITY_TYPE_SWP_STAT_WEIR
		ENTSTRSwpCreateWeir,
		NULL,
		ENTSTRKillDynamicMOF,
		ENTITY_BOOK_STATIC|ENTITY_BOOK_IMMORTAL,
		NULL,
		},
};
