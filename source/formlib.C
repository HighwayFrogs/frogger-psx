/******************************************************************************
*%%%% formlib.c
*------------------------------------------------------------------------------
*
*	Specific forms
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	06.05.97	Tim Closs		Created
*	08.05.97	Martin Kift		Added dummy entry to all blank form lists, and
*								moved all the suburbia entities over to the
*								suburbia theme, out of the volcano theme :/
*	12.05.97	Martin Kift		Changed scripts from ptr to id
*
*%%%**************************************************************************/

#include "formlib.h"
#include "entity.h"
#include "entlib.h"
#include "project.h"
#include "scripts.h"
#include "ent_all.h"
#include "collide.h"
//-----------------------------------------------------------------------------
// Form library
//-----------------------------------------------------------------------------

//----------
// THEME_GEN
//----------
FORM_BOOK	Form_library_gen[] =
	{
		{
		// gen_checkpoint_1
		ENTITY_TYPE_CHECKPOINT,
		PROJECT_MAX_THEME_MOFS + 0,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_checkpoint_2
		ENTITY_TYPE_CHECKPOINT,
		PROJECT_MAX_THEME_MOFS + 1,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_checkpoint_3
		ENTITY_TYPE_CHECKPOINT,
		PROJECT_MAX_THEME_MOFS + 2,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_checkpoint_4
		ENTITY_TYPE_CHECKPOINT,
		PROJECT_MAX_THEME_MOFS + 3,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_checkpoint_5
		ENTITY_TYPE_CHECKPOINT,
		PROJECT_MAX_THEME_MOFS + 4,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_bonus_score
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 5,
		},
		{
		// gen_bonus_time
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 6,
		},
		{
		// gen_bonus_life
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 7,
		},
		{
		// gen_bonus_frog
		ENTITY_TYPE_STATIC,
		NULL,
		},
		{
		// gen_bonus_fly_gre
		ENTITY_TYPE_BONUS_FLY,
		NULL,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL | GAME_RESET_CHECKPOINT_COLLECTED | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		100,
		},
		{
		// gen_ladyFrog
		ENTITY_TYPE_STATIC,
		NULL,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_multipoint_1
		ENTITY_TYPE_MULTIPOINT,
		PROJECT_MAX_THEME_MOFS + 8,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_multipoint_2
		ENTITY_TYPE_MULTIPOINT,
		PROJECT_MAX_THEME_MOFS + 9,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_multipoint_3
		ENTITY_TYPE_MULTIPOINT,
		PROJECT_MAX_THEME_MOFS + 10,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_multipoint_4
		ENTITY_TYPE_MULTIPOINT,
		PROJECT_MAX_THEME_MOFS + 11,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_multipoint_5
		ENTITY_TYPE_MULTIPOINT,
		PROJECT_MAX_THEME_MOFS + 12,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_stat_col_block
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 13,
		NULL,
		NULL,		//FORM_BOOK_FLAG_NO_MODEL,
		&GenBlockCollPrimCallback,
		},
		{
		// gen_stat_death_block
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 14,	
		NULL,
		//FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// gen_topleft
		ENTITY_TYPE_GEN_TOP_LEFT,
		PROJECT_MAX_THEME_MOFS + 13,
		NULL,
		},
		{
		// gen_bottomright
		ENTITY_TYPE_GEN_BOTTOM_RIGHT,
		PROJECT_MAX_THEME_MOFS + 13,
		NULL,
		},
		{
		// gen_gold_frog
		ENTITY_TYPE_GEN_GOLD_FROG,
		PROJECT_MAX_THEME_MOFS + 15,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// gen_stat_water_fall_block
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 13,
		NULL,
		NULL,		//FORM_BOOK_FLAG_NO_MODEL,
		&GenBlockWaterFallCollPrimCallback,
		},
		{
		// gen_stat_fall_block
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 13,
		NULL,
		NULL,		//FORM_BOOK_FLAG_NO_MODEL,
		&GenBlockFallCollPrimCallback,
		},
	};

//----------
// THEME_CAV
//----------
FORM_BOOK	Form_library_cav[] =
	{
		{
		// cav_glowworm
		ENTITY_TYPE_STATIC,
		0,
		},
		{
		// cav_firefly
		ENTITY_TYPE_FIREFLY,
		0,
		0,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		0,
		0,
		0,
		&CavFireFlyCallBack,
		},
		{
		// cav_spider
		ENTITY_TYPE_MOVING,			//CAV_SPIDER,
		0,
		SCRIPT_CAV_SPIDER,
		FORM_BOOK_THICK_FORM,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// cav_bat
		ENTITY_TYPE_MOVING,
		1,
		SCRIPT_CAV_BAT,
		},
		{
		// cav_rockfallfloor
		ENTITY_TYPE_STATIC,
		2,
		SCRIPT_CAV_ROCKFALLFLOOR_WAITING,
		NULL,
		},
		{
		// cav_rockblock
		ENTITY_TYPE_STATIC,
		3,
		},
		{
		// cav_ropebridge
		ENTITY_TYPE_STATIC,
		4,
		},
		{
		// cav_froggerlight
		ENTITY_TYPE_CAV_FROGGER_LIGHT,
		0,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// cav_stat_cobweb
		ENTITY_TYPE_STATIC,
		5,
		//NULL,
		//NULL,
		//CavBounceWebCallback,
		},
		{
		// cav_vamp_bat
		ENTITY_TYPE_MOVING,
		6,
		SCRIPT_CAV_VAMP_BAT,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// cav_stat_stonebridge
		ENTITY_TYPE_STATIC,
		7,
		},
		{
		// cav_stat_crystals
		ENTITY_TYPE_STATIC,
		8,
		},
		{
		// cav_bat_flock
		ENTITY_TYPE_STATIC,
		9,
		},
		{
		// cav_lavadrop
		ENTITY_TYPE_STATIC,
		0,
		},
		{
		// cav_snail
		ENTITY_TYPE_STATIC,
		10,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// cav_slime
		ENTITY_TYPE_STATIC,
		11,
		},
		{
		// cav_stat_rockblock2
		ENTITY_TYPE_STATIC,
		12,
		},
		{
		// cav_stat_webwall
		ENTITY_TYPE_STATIC,
		13,
		NULL,
		NULL,
		&CavBounceWebCallback,
		},
		{
		// cav_fat_fire_fly
		ENTITY_TYPE_CAV_FAT_FIRE_FLY,
		NULL,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// cav_racesnail
		ENTITY_TYPE_MOVING,
		14,
		},
	};

//----------
// THEME_DES
//----------
FORM_BOOK	Form_library_des[] =
	{
		{
		// des_vulture"
		ENTITY_TYPE_DES_VULTURE,
		0+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{	
		// des_lizard
		ENTITY_TYPE_MOVING,
		1+DESERT_WAD_OFFSET,
		SCRIPT_DES_LIZARD,
		FORM_BOOK_THICK_FORM,
		NULL,
		0,
		FORM_DEATH_FLOP
		},
		{
		// des_stat_ballcactus
		ENTITY_TYPE_STATIC,
		2+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_stat_cactus
		ENTITY_TYPE_STATIC,
		3+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_snake
		ENTITY_TYPE_DES_SNAKE,
		4+DESERT_WAD_OFFSET,
		SCRIPT_DES_SNAKE,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_tumbleweed
		ENTITY_TYPE_DES_TUMBLE_WEED,
		5+DESERT_WAD_OFFSET,
		},
		{
		// des_falling_rock
		ENTITY_TYPE_DES_FALLING_ROCK,
		6+DESERT_WAD_OFFSET,
		SCRIPT_DES_FALLING_ROCK,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// des_earthquake
		ENTITY_TYPE_DES_EARTH_QUAKE,
		0+DESERT_WAD_OFFSET,
		},
		{
		// des_hole1
		ENTITY_TYPE_STATIC,
		7+DESERT_WAD_OFFSET,
		},
		{
		// des_hole2
		ENTITY_TYPE_STATIC,
		8+DESERT_WAD_OFFSET,
		},
		{
		// des_crack
		ENTITY_TYPE_DES_CRACK,
		9+DESERT_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// des_beetle
		ENTITY_TYPE_MOVING,
		10+DESERT_WAD_OFFSET,
		SCRIPT_DES_BEETLE,
		0,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_bison
		ENTITY_TYPE_MOVING,
		11+DESERT_WAD_OFFSET,
		SCRIPT_DES_BISON,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// des_thermal
		ENTITY_TYPE_DES_THERMAL,
		12+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_rockform
		ENTITY_TYPE_STATIC,
		13+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_arch
		ENTITY_TYPE_STATIC,
		14+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_rocks
		ENTITY_TYPE_STATIC,
		15+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_rocks2
		ENTITY_TYPE_STATIC,
		16+DESERT_WAD_OFFSET,
		},
		{
		// des_bisoncloud
		ENTITY_TYPE_STATIC,
		17+DESERT_WAD_OFFSET,
		},
		{
		// des_salamander
		ENTITY_TYPE_STATIC,
		18+DESERT_WAD_OFFSET,
		SCRIPT_DES_SALAMANDER,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_stat_cliffbranch
		ENTITY_TYPE_STATIC,
		19+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_cowskull
		ENTITY_TYPE_STATIC,
		20+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_ballcactus2
		ENTITY_TYPE_STATIC,
		21+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_stat_cactus2
		ENTITY_TYPE_STATIC,
		22+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP
		},
		{
		// des_stat_cliffbranch2
		ENTITY_TYPE_STATIC,
		23+DESERT_WAD_OFFSET,
		},
		{
		// des_stat_bones
		ENTITY_TYPE_STATIC,
		24+DESERT_WAD_OFFSET,
		},
		{
		// des_fall_rockroll
		ENTITY_TYPE_STATIC,
		25+DESERT_WAD_OFFSET,
		},
		{
		// des_bisonnoise
		ENTITY_TYPE_STATIC,
		1+DESERT_WAD_OFFSET,
		NULL,	
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// des_bird1
		ENTITY_TYPE_MOVING,
		26+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_bird2
		ENTITY_TYPE_MOVING,
		27+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_stat_cactus3
		ENTITY_TYPE_STATIC,
		28+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_stat_ballcactus3
		ENTITY_TYPE_STATIC,
		29+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_stat_ballcactus4
		ENTITY_TYPE_STATIC,
		30+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_stat_cactus4
		ENTITY_TYPE_STATIC,
		31+DESERT_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// des_lizard_noise
		ENTITY_TYPE_STATIC,
		1+DESERT_WAD_OFFSET,
		0,							//SCRIPT_DES_LIZARD_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		0,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_butterfly
		ENTITY_TYPE_MOVING_TONGUEABLE,
		32+DESERT_WAD_OFFSET,
		0,
		0,
		0,
		NULL,
		NULL,
		&GenButterFlyCallBack,
		},
		{
		// des_crochead
		ENTITY_TYPE_DES_CROC_HEAD,
		33+DESERT_WAD_OFFSET,
		0,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// des_rollingrock
		ENTITY_TYPE_DES_ROLLING_ROCK,
		6+DESERT_WAD_OFFSET,
		NULL,//SCRIPT_DES_ROLLING_ROCK,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
	};

//----------
// THEME_FOR
//----------
FORM_BOOK	Form_library_for[] =
	{
		{
		// for_woodpecker
		ENTITY_TYPE_STATIC,
		0,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// for_jay
		ENTITY_TYPE_MOVING,
		1,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// for_fallingleaves
		ENTITY_TYPE_STATIC,
		2,
		},
		{
		// for_swayingbranch
		ENTITY_TYPE_FOR_SWAYING_BRANCH,
		3,
		NULL,
		FORM_BOOK_FROG_NO_ROTATION_SNAPPING | FORM_BOOK_FROG_NO_ENTITY_ANGLE,
		},
		{
		// for_squirrel
		ENTITY_TYPE_FOR_SQUIRREL,
		4,
		SCRIPT_FOR_SQUIRREL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// for_owl
		ENTITY_TYPE_MOVING,
		5,
		SCRIPT_FOR_OWL,
		},
		{
		// for_swarm
		ENTITY_TYPE_STATIC,
		6,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// for_hive
		ENTITY_TYPE_FOR_HIVE,
		7,
		},
		{
		// for_stat_brachtfungi
		ENTITY_TYPE_STATIC,
		8,
		},
		{
		// for_stat_treestump
		ENTITY_TYPE_STATIC,
		9,
		},
		{
		// for_stat_bigtree
		ENTITY_TYPE_STATIC,
		10,
		},
		{
		// for_breakingbranch
		ENTITY_TYPE_FOR_BREAKING_BRANCH,
		11,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// for_stat_safebranch
		ENTITY_TYPE_STATIC,
		12,
		},
		{
		// for_stat_treestump2
		ENTITY_TYPE_STATIC,
		13,
		},
		{
		// for_stat_treestump3
		ENTITY_TYPE_STATIC,
		14,
		},
		{
		// for_stat_breakingbranch
		ENTITY_TYPE_STATIC,
		15,
		},
		{
		// for_stat_bush
		ENTITY_TYPE_STATIC,
		16,
		},
		{
		// for_stat_smalltree
		ENTITY_TYPE_STATIC,
		17,
		},
		{
		// for_stat_safebranch2
		ENTITY_TYPE_STATIC,
		18,
		},
		{
		// for_stat_toadstool
		ENTITY_TYPE_STATIC,
		19,
		},
		{
		// for_stat_mushroom
		ENTITY_TYPE_STATIC,
		20,
		},
		{
		// for_stat_deadbranch
		ENTITY_TYPE_STATIC,
		21,
		},
		{
		// for_stat_fallentree
		ENTITY_TYPE_STATIC,
		22,
		},
		{
		// for_stat_smalltree2
		ENTITY_TYPE_STATIC,
		23,
		},
		{
		// for_stat_smalltree3
		ENTITY_TYPE_STATIC,
		24,
		},
		{
		// for_stat_swayingbranch
		ENTITY_TYPE_FOR_SWAYING_BRANCH,
		25,
		},
		{
		// for_stat_treetop
		ENTITY_TYPE_STATIC,
		26,
		},
		{
		// for_stat_brachtfungi2
		ENTITY_TYPE_STATIC,
		27,
		},
		{
		// for_stat_brachtfungi3
		ENTITY_TYPE_STATIC,
		28,
		},
		{
		// for_stat_brachtfungi4
		ENTITY_TYPE_STATIC,
		29,
		},
		{
		// for_hedgehog
		ENTITY_TYPE_FOR_HEDGEHOG,
		30,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// for_swan
		ENTITY_TYPE_MOVING,
		31,
		SCRIPT_FOR_SWAN,
		},
		{
		// for_stat_orchid
		ENTITY_TYPE_STATIC,
		32,
		},
		{
		// for_stat_daisy
		ENTITY_TYPE_STATIC,
		33,
		},
		{
		// for_leaf
		ENTITY_TYPE_MOVING,
		34,
		},
		{
		// for_stat_treestump1
		ENTITY_TYPE_STATIC,
		0,					// Not in vorg, since its only EVER part of the landscape!
		},
		{
		// for_river_noise
		ENTITY_TYPE_STATIC,
		PROJECT_MAX_THEME_MOFS + 14,	// Uses the Gen Block.
		SCRIPT_FOR_RIVER_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
	};

//----------
// THEME_JUN
//----------
FORM_BOOK	Form_library_jun[] =
	{
		{
		// arn_falling_tree
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		NULL,
		},
		{
		// arn_scorpion
		ENTITY_TYPE_MOVING,
		0+JUNGLE_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// arn_stat_boulder
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_dog
		ENTITY_TYPE_STATIC,
		1+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_dog2
		ENTITY_TYPE_STATIC,
		2+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_falltreestump
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_frog
		ENTITY_TYPE_STATIC,
		3+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_rock
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_rocks
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_rocks2
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// arn_stat_stump
		ENTITY_TYPE_STATIC,
		0+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_bird
		ENTITY_TYPE_MOVING,
		4+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_bird1
		ENTITY_TYPE_MOVING,
		5+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_bird2
		ENTITY_TYPE_MOVING,
		6+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_boar
		ENTITY_TYPE_MOVING,
		7+JUNGLE_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// jun_butterfly
        ENTITY_TYPE_MOVING_TONGUEABLE,
		8+JUNGLE_WAD_OFFSET,
		0,
		0,
		0,
		NULL,
		NULL,
		&GenButterFlyCallBack,
		},
		{
		// jun_dragonfly
        ENTITY_TYPE_MOVING,
		9+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_eel
		ENTITY_TYPE_MOVING,
		10+JUNGLE_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// jun_flamingo
		ENTITY_TYPE_MOVING,
		11+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_humbird
		ENTITY_TYPE_MOVING,
		12+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_monkey
		ENTITY_TYPE_MOVING,
		13+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_MONKEY,
		},
		{
		// jun_parrot
		ENTITY_TYPE_MOVING,
		14+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_parrot2
		ENTITY_TYPE_MOVING,
		15+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_parrot3
		ENTITY_TYPE_MOVING,
		16+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_pocupine
		ENTITY_TYPE_MOVING,
		17+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_plant
		ENTITY_TYPE_JUN_PLANT,
		18+JUNGLE_WAD_OFFSET,
		0,
		FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_RESET_ON_CHECKPOINT,
		},
		{
		// jun_piranha
		ENTITY_TYPE_MOVING,
		19+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_PIRANAHA,
		},
		{
		// jun_rhino
		ENTITY_TYPE_MOVING,
		20+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_RHINO,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// jun_scorpion
		ENTITY_TYPE_JUN_SCORPION,
		0+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_SCORPION,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// jun_stat_treecoc2
		ENTITY_TYPE_STATIC,
		21+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_tree2
		ENTITY_TYPE_STATIC,
		22+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_treecoc
		ENTITY_TYPE_STATIC,
		23+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_sunflower
		ENTITY_TYPE_STATIC,
		24+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_tree
		ENTITY_TYPE_STATIC,
		25+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_treefat2
		ENTITY_TYPE_STATIC,
		26+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_treefat
		ENTITY_TYPE_STATIC,
		27+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_tree4
		ENTITY_TYPE_STATIC,
		28+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_tree3
		ENTITY_TYPE_STATIC,
		29+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_flower
		ENTITY_TYPE_STATIC,
		30+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_flower2
		ENTITY_TYPE_STATIC,
		31+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_flower3
		ENTITY_TYPE_STATIC,
		32+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_flower4
		ENTITY_TYPE_STATIC,
		33+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_stat_orchid
		ENTITY_TYPE_STATIC,
		34+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_toucan
		ENTITY_TYPE_MOVING,
		35+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_turtle
		ENTITY_TYPE_MOVING,
		36+JUNGLE_WAD_OFFSET,
		0,
		FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_RESET_ON_CHECKPOINT,
		},
		{
		// jun_log
		ENTITY_TYPE_MOVING,
		37+JUNGLE_WAD_OFFSET,
		0,
		FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_RESET_ON_CHECKPOINT,
		},
		{
		// jun_ropebridge
		ENTITY_TYPE_JUN_ROPE_BRIDGE,
		38+JUNGLE_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_UNIT_FORM,
		},
		{
		// jun_crocodile
		ENTITY_TYPE_MOVING,
		39+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_CROCODILE,
		FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_RESET_ON_CHECKPOINT,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// jun_hippo
		ENTITY_TYPE_JUN_HIPPO,
		40+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_HIPPO,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// jun_crack
		ENTITY_TYPE_DES_CRACK,
		41+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_bananatree
		ENTITY_TYPE_STATIC,
		42+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_pineappletree
		ENTITY_TYPE_STATIC,
		43+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_FLOATING_TREE,
		},
		{
		// jun_overhang
		ENTITY_TYPE_STATIC,
		44+JUNGLE_WAD_OFFSET,
		SCRIPT_JUN_FLOATING_TREE,
		},
		{
		// jun_floatingtrees
		ENTITY_TYPE_MOVING,
		45+JUNGLE_WAD_OFFSET,		// no model at the moment, use turtle
		SCRIPT_JUN_FLOATING_TREE,
		FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_RESET_ON_CHECKPOINT,
		},
		{
		// jun_ropebridge2
		ENTITY_TYPE_JUN_ROPE_BRIDGE,
		46+JUNGLE_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// jun_stat_palm
		ENTITY_TYPE_STATIC,
		47+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_bouncy_mush
		ENTITY_TYPE_JUN_BOUNCY_MUSHROOM,
		48+JUNGLE_WAD_OFFSET,
		},
		{
		// jun_water_noise
		ENTITY_TYPE_STATIC,
		NULL,
		SCRIPT_JUN_WATER_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// JUN_OUTRO
		ENTITY_TYPE_JUN_OUTRO,		
		NULL,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// JUN_OUTRO_DOOR
		ENTITY_TYPE_JUN_OUTRO_DOOR,
		49+JUNGLE_WAD_OFFSET,
		NULL,
		NULL,
		&SwpCrusherCallback,
		},
		{
		// JUN_OUTRO_STATUE
		ENTITY_TYPE_JUN_STATUE,
		NULL,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// JUN_OUTRO_PLINTH
		ENTITY_TYPE_JUN_PLINTH,
		50+JUNGLE_WAD_OFFSET,	
		},
		{
		// JUN_OUTRO_GOLD_DOOR
		ENTITY_TYPE_JUN_OUTRO_DOOR,
		49+JUNGLE_WAD_OFFSET,				// set to bridge graphic
		NULL,
		NULL,
		&SwpCrusherCallback,
		},
		{
		// JUN_OUTRO_GOLD_FROG
		ENTITY_TYPE_JUN_GOLD_FROG,
		PROJECT_MAX_THEME_MOFS + 15,		// Gold frog from generic
		},
		{
		// JUN_STONE_FROG
		ENTITY_TYPE_JUN_STONE_FROG,
		51+JUNGLE_WAD_OFFSET
		},
		{
		// JUN_LOG3
		ENTITY_TYPE_MOVING,
		52+JUNGLE_WAD_OFFSET,
		NULL,
		},
	};

//----------
// THEME_ORG
//----------
FORM_BOOK	Form_library_org[] =
	{
		{
		// org_bull_dozer
		ENTITY_TYPE_MOVING,
		0,
		SCRIPT_ORG_BULL_DOZER,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_car_blue
		ENTITY_TYPE_MOVING,
		1,
		SCRIPT_ORG_CAR_BLUE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_car_purple
		ENTITY_TYPE_MOVING,
		2,
		SCRIPT_ORG_CAR_PURPLE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_log_small
		ENTITY_TYPE_MOVING,
		3,
		SCRIPT_LOG_SPLASH,
		FORM_BOOK_FROG_NO_CENTRING_Z | FORM_BOOK_THICK_FORM,
		},
		{
		// org_log_medium
		ENTITY_TYPE_MOVING,
		4,
		SCRIPT_LOG_SPLASH,
		FORM_BOOK_FROG_NO_CENTRING_Z | FORM_BOOK_THICK_FORM,
		},
		{
		// org_log_large
		ENTITY_TYPE_MOVING,
		5,
		SCRIPT_LOG_SPLASH,
		FORM_BOOK_FROG_NO_CENTRING_Z | FORM_BOOK_THICK_FORM,
		},
		{
		// org_snake
		ENTITY_TYPE_MOVING,
		6,
		SCRIPT_ORG_SNAKE,
		FORM_BOOK_THICK_FORM,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// org_lorry
		ENTITY_TYPE_MOVING,
		7,
		SCRIPT_ORG_LORRY,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_truck_green
		ENTITY_TYPE_MOVING,
		8,
		SCRIPT_ORG_TRUCK,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_truck_red
		ENTITY_TYPE_MOVING,
		9,
		SCRIPT_ORG_TRUCK,
		NULL,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_crocodile
		ENTITY_TYPE_MOVING,
		10,
		SCRIPT_ORG_CROCODILE,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// org_home_frog
		ENTITY_TYPE_STATIC,
		10,
		},
		{
		// org_fly
		ENTITY_TYPE_ORG_FLY,
		12,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		NULL,
		NULL,
		NULL,
		&OrgFlyCallBack,
		},
		{
		// org_beaver
		ENTITY_TYPE_ORG_BEAVER,
		13,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// org_babyfrog
		ENTITY_TYPE_ORG_BABY_FROG,
		14,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// org_crochead
		ENTITY_TYPE_ORG_CROC_HEAD,
		15,
		NULL,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// org_logsnake
		ENTITY_TYPE_ORG_LOG_SNAKE,
		6,								// but still gets output in the wad file as NULL.
		0,
		0,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// org_roadnoise
		ENTITY_TYPE_STATIC_NOISE,
		0,
		SCRIPT_ORG_ROAD_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{						   
		// org_rivernoise
		ENTITY_TYPE_STATIC_NOISE,
		0,
		SCRIPT_ORG_WATER_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// org_turtle
		ENTITY_TYPE_SUB_TURTLE,
		16,
		SCRIPT_TURTLE,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH
		},
		{
		// org_turtle2
		ENTITY_TYPE_SUB_TURTLE,
		17,
		SCRIPT_TURTLE,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH
		},
		{
		// org_turtle3
		ENTITY_TYPE_SUB_TURTLE,
		18,
		SCRIPT_TURTLE,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH
		},
		{
		// org_stat_nettles
		ENTITY_TYPE_STATIC,
		19,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP
		},
		{
		// org_car_orange
		ENTITY_TYPE_MOVING,
		20,
		SCRIPT_ORG_CAR_PURPLE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// org_gold_frog
		ENTITY_TYPE_ORG_BABY_FROG,
		PROJECT_MAX_THEME_MOFS + 15,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
	};

//----------
// THEME_ARN
//----------
//FORM_BOOK	Form_library_arn[] =
//	{
//		{
//		// arn_stat_dog
//		ENTITY_TYPE_STATIC,
//		0,
//		},
//		{
//		// arn_stat_dog2
//		ENTITY_TYPE_STATIC,
//		1,
//		},
//		{
//		// arn_stat_frog
//		ENTITY_TYPE_STATIC,
//		2,
//		},
//	};

//----------
// THEME_SWP
//----------
FORM_BOOK	Form_library_swp[] =
	{
		{
		// swp_oil_drum
		ENTITY_TYPE_MOVING,
		0,
		SCRIPT_SWP_OIL_DRUM,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// swp_box
		ENTITY_TYPE_STATIC,
		1,
		SCRIPT_SWP_PALLET,
		FORM_BOOK_THICK_FORM,
		},
		{
		// swp_rat
		ENTITY_TYPE_SWP_RAT,
		2,
		SCRIPT_SWP_RAT,
		0,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// swp_stat_mound
		ENTITY_TYPE_STATIC,
		0,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// swp_stat_sunkcar
		ENTITY_TYPE_STATIC,
		3,
		SCRIPT_SWP_SUNKCAR,
		},
		{
		// swp_newspaper
		ENTITY_TYPE_MOVING,
		4,
		SCRIPT_SWP_PALLET,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// swp_newspaper_torn
		ENTITY_TYPE_STATIC,
		5,
		NULL,
		FORM_BOOK_THICK_FORM,
		},
		{
		// swp_stat_pipe
		ENTITY_TYPE_STATIC,
		6,
		SCRIPT_SWP_STAT_PIPE,
		},
		{
		// swp_stat_flume
		ENTITY_TYPE_STATIC,
		0,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// swp_racoon
		ENTITY_TYPE_MOVING,
		7,
		SCRIPT_SWP_RACCOON,
		0,
		NULL,
		0,
		//FORM_DEATH_FLOP,
		},
		{
		// swp_stat_deadtree
		ENTITY_TYPE_STATIC,
		8,
		},
		{
		// swp_stat_deadtree1
		ENTITY_TYPE_STATIC,
		9,
		},
		{
		// swp_stat_log
		ENTITY_TYPE_STATIC,
		10,
		},
		{
		// swp_stat_litter
		ENTITY_TYPE_STATIC,
		11,
		NULL,
		FORM_BOOK_THICK_FORM,
		},
		{
		// swp_stat_litter2
		ENTITY_TYPE_STATIC,
		12,
		NULL,
		FORM_BOOK_THICK_FORM,
		},
		{
		// swp_pallet
		ENTITY_TYPE_MOVING,
		13,
		SCRIPT_SWP_PALLET,
		FORM_BOOK_THICK_FORM,
		},
		{
		// swp_oil
		ENTITY_TYPE_MOVING,
		14,
		},
		{
		// swp_waste_barrel
		ENTITY_TYPE_MOVING,
		15,
		NULL,
		},
		{
		// swp_nuclear_barrel
		ENTITY_TYPE_NUCLEAR_BARREL,
		16,
		SCRIPT_SWP_NUCLEAR_BARLLEL_WAITING,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// swp_stat_pipe_str
		ENTITY_TYPE_STATIC,
		17,
		SCRIPT_SWP_STAT_PIPE,
		},
		{
		// swp_st_pipe_big_str
		ENTITY_TYPE_STATIC,
		18,
		SCRIPT_SWP_STAT_PIPE_BIG_STR,
		},
		{
		// swp_stat_pipe_hole
		ENTITY_TYPE_STATIC,
		19,
		SCRIPT_SWP_STAT_PIPE_HOLE,
		},
		{
		// swp_stat_marsh
		ENTITY_TYPE_STATIC,
		20,
		},
		{
		// swp_crusher
		ENTITY_TYPE_SWP_CRUSHER,
		21,
		NULL,
		FORM_BOOK_THICK_FORM,
		&SwpCrusherCallback,
		NULL,
		FORM_DEATH_SQUISHED,
		},
		{
		// swp_stat_weir
		ENTITY_TYPE_SWP_STAT_WEIR,
		22,
		SCRIPT_SWP_WEIR_ROTATE,
		},
		{
		// swp_squirt
		ENTITY_TYPE_SWP_SQUIRT,
		23,
		},
		{
		// swp_stat_pipe_curved
		ENTITY_TYPE_STATIC,
		24,
		SCRIPT_SWP_STAT_PIPE,
		},
		{
		// swp_st_pipe_big_curve
		ENTITY_TYPE_STATIC,
		25,
		SCRIPT_SWP_STAT_PIPE_BIG_STR,
		},
		{
		// swp_stat_pipe_small_str
		ENTITY_TYPE_STATIC,
		26,
		SCRIPT_SWP_STAT_PIPE,
		},
		{
		// swp_stat_pipe_small_cur
		ENTITY_TYPE_STATIC,
		27,
		SCRIPT_SWP_STAT_PIPE,
		},
		{
		// swp_slug
		ENTITY_TYPE_SWP_SLUG,
		28,
		SCRIPT_SWP_SNAIL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// swp_mutant_fish
		ENTITY_TYPE_MOVING,
		29,
		SCRIPT_SWP_MUTANT_FISH,
		0,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// swp_stat_waste_barrel
		ENTITY_TYPE_DYNAMIC,
		30,	
		SCRIPT_SWP_BOBBING_WASTE_BARREL,
		},
		{
		// swp_pipe_mesh
		ENTITY_TYPE_STATIC,
		31,
		},
		{
		// swp_stat_fridge
		ENTITY_TYPE_STATIC,
		32,
		},
		{
		// swp_stat_tyre
		ENTITY_TYPE_STATIC,
		33,
		},
		{
		// swp_chemical_barrel
		ENTITY_TYPE_MOVING,
		30,
		},
		{
		// swp_crusher2
		ENTITY_TYPE_SWP_CRUSHER,
		34,
		NULL,
		FORM_BOOK_THICK_FORM,
		&SwpCrusherCallback,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// swp_press
		ENTITY_TYPE_SWP_PRESS,
		35,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// swp_bird1
		ENTITY_TYPE_MOVING,
		36,
		SCRIPT_SWP_PELICAN,
		},
		{						   
		// swp_water_noise
		ENTITY_TYPE_STATIC_NOISE,
		0,
		SCRIPT_SWP_WATER_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		// swp_weir_noise
		{
		ENTITY_TYPE_STATIC_NOISE,
		0,
		SCRIPT_SWP_WEIR_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		// swp_recycle_bin_noise
		{
		ENTITY_TYPE_STATIC_NOISE,
		0,
		SCRIPT_SWP_RECYCLE_BIN_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
	};

//----------
// THEME_SKY
//----------
FORM_BOOK	Form_library_sky[] =
	{
		{
		// sky_jet1
		ENTITY_TYPE_MOVING,
		0,
		SCRIPT_SKY_JET1,
		},
		{
		// sky_jet3
		ENTITY_TYPE_MOVING,
		1,
		SCRIPT_SKY_JET3,
		},
		{
		// sky_biplane1
		ENTITY_TYPE_MOVING,
		2,
		SCRIPT_SKY_BIPLANE,
		},
		{
		// sky_biplane2
		ENTITY_TYPE_MOVING,
		3,
		SCRIPT_SKY_BIPLANE,
		},
		{
		// sky_helicopter
		ENTITY_TYPE_DYNAMIC,
		4,
		SCRIPT_SKY_HELICOPTER,
		NULL,
		NULL,
		0,
		FORM_DEATH_POP,
		},
		{
		// sky_bird1
		ENTITY_TYPE_MOVING,
		5,
		SCRIPT_SKY_BIRD1_1,
		},
		{
		// sky_bird2
		ENTITY_TYPE_MOVING,
		6,
		SCRIPT_SKY_BIRD2_1,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// sky_bird3
		ENTITY_TYPE_MOVING,
		7,
		SCRIPT_SKY_BIRD3_1,
		},
		{
		// sky_bird4
		ENTITY_TYPE_MOVING,
		8,
		SCRIPT_SKY_BIRD4_1,
		},
		{
		// sky_little_bird
		ENTITY_TYPE_MOVING,
		9,
		SCRIPT_SKY_BIRD4_1,
		},
		{
		// sky_popping_bird
		ENTITY_TYPE_MOVING,
		10,
		SCRIPT_SKY_BIRD4_1,
		},
		{
		// sky_rubber_balloon1
		ENTITY_TYPE_DYNAMIC,
		11,
		SCRIPT_SKY_RUBBER_BALLOON_WAITING,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_rubber_balloon2
		ENTITY_TYPE_DYNAMIC,
		12,
		SCRIPT_SKY_RUBBER_BALLOON_WAITING,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_helium_balloon3
		ENTITY_TYPE_DYNAMIC,
		13,
		SCRIPT_SKY_HELIUM_BALLOON_WAITING,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_biplane_banner1
		ENTITY_TYPE_STATIC,
		14,
		},
		{
		// sky_cloud_platform1
		ENTITY_TYPE_STATIC,
		0,
		NULL,
		FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// sky_cloud1
		ENTITY_TYPE_STATIC,
		15,
		},
		{
		// sky_cloud2
		ENTITY_TYPE_STATIC,
		16,
		},
		{
		// sky_cloud3
		ENTITY_TYPE_STATIC,
		17,
		},
		{
		// sky_hawk
		ENTITY_TYPE_DYNAMIC,
		18,
		SCRIPT_SKY_BIRD,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// sky_birdhawk
		ENTITY_TYPE_DYNAMIC,
		19,
		SCRIPT_SKY_BIRD,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_tornado_object
		ENTITY_TYPE_MOVING,
		20,
		},
		{
		// sky_flocking_bird
		ENTITY_TYPE_MOVING,
		21,
		},
		{
		// sky_bird_small
		ENTITY_TYPE_MOVING,
		22,
		},
		{
		// sky_cld_patch
		ENTITY_TYPE_STATIC,
		23,
		},
		{
		// sky_cloudplatform
		ENTITY_TYPE_MOVING,
		15,
		SCRIPT_SKY_CLOUDPLATFORM,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_squadron,
		ENTITY_TYPE_MOVING_PLATFORM,
		24,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sky_froggers_magical_popping_balloon,
		ENTITY_TYPE_TRIGGER,
		25,
		SCRIPT_SKY_MAGICAL_POPPING_BALLOON,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		TriggerEntityCallback,
		},
	};

//----------
// THEME_SUB
//----------
FORM_BOOK	Form_library_sub[] =
	{
		{
		// sub_log
		ENTITY_TYPE_MOVING,
		0,
		SCRIPT_LOG_SPLASH,
		},
		{
		// sub_turtle
		ENTITY_TYPE_MOVING,
		1,
		SCRIPT_TURTLE,
		},
		{
		// sub_stat_big_fence
		ENTITY_TYPE_STATIC,
		2,
		},
		{
		// sub_stat_small_fence
		ENTITY_TYPE_STATIC,
		3,
		},
		{
		// sub_stat_small_flowers
		ENTITY_TYPE_STATIC,
		4,
		},
		{
		// sub_stat_big_flowers
		ENTITY_TYPE_STATIC,
		5,
		},
		{
		// sub_stat_small_jetty
		ENTITY_TYPE_STATIC,
		6,
		},
		{
		// sub_stat_dog_kennel
		ENTITY_TYPE_STATIC,
		7,
		},
		{
		// sub_stat_tunnel
		ENTITY_TYPE_STATIC,
		8,
		},
		{
		// sub_stat_lilly
		ENTITY_TYPE_STATIC,
		9,
		},
		{
		// sub_lillypad
		ENTITY_TYPE_DYNAMIC,
		10,
		SCRIPT_SUB_LILLY_PAD,
		FORM_BOOK_FROG_NO_ROTATION_SNAPPING | FORM_BOOK_FROG_NO_ENTITY_ANGLE | FORM_BOOK_THICK_FORM,
		},
		{
		// sub_hedgehog
		ENTITY_TYPE_MOVING,
		11,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// sub_stat_start_jetty - $km - Acutally references the lillypad model
		ENTITY_TYPE_STATIC,
		10,
		},
		{
		// sub_stat_fence_post
		ENTITY_TYPE_STATIC,
		12,
		},
		{
		// sub_truck
		ENTITY_TYPE_MOVING,
		13,
		SCRIPT_SUB_TRUCK,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// sub_car
		ENTITY_TYPE_MOVING,
		14,
		SCRIPT_SUB_CAR_BLUE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// sub_lorry
		ENTITY_TYPE_MOVING,
		15,
		SCRIPT_SUB_LORRY,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// sub_peddleboat
		ENTITY_TYPE_MOVING,
		16,
		},
		{
		// sub_swan
		ENTITY_TYPE_MOVING,
		17,
		SCRIPT_SUB_SWAN,
		},
		{
		// sub_lawn_mower
		ENTITY_TYPE_SUB_LAWNMOWER,
		18,
		0,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_MOWED,
		},
		{
		// sub_dog
		ENTITY_TYPE_SUB_DOG,
		19,
		0,
		0,
		NULL,
		0,
		FORM_DEATH_BITTEN,
		},
		{
		// sub_stat_dandylion
		ENTITY_TYPE_STATIC,
		20,
		},
		{
		// sub_stat_stone
		ENTITY_TYPE_STATIC,
		21,
		},
		{
		// sub_stat_rocks
		ENTITY_TYPE_STATIC,
		22,
		},
		{
		// sub_stat_stopsign
		ENTITY_TYPE_STATIC,
		23,
		},
		{
		// sub_stat_bullrush
		ENTITY_TYPE_STATIC,
		24,
		},
		{
		// sub_stat_tlight
		ENTITY_TYPE_STATIC,
		25,
		},
		{
		// sub_stat_grass
		ENTITY_TYPE_STATIC,
		26,
		},
		{
		// sub_fish
		ENTITY_TYPE_MOVING,
		27,
		0,
		0,
		NULL,
		0,
		FORM_DEATH_DROWN,
		},
		{
		// sub_fish3
		ENTITY_TYPE_MOVING,
		28,
		0,
		0,
		NULL,
		0,
		FORM_DEATH_DROWN,
		},
		{
		// sub_butterfly
		ENTITY_TYPE_MOVING_TONGUEABLE,
		29,
		0,
		0,
		0,
		0,
		0,
		&GenButterFlyCallBack,
		},
		{
		// sub_lawnmowernoise
		ENTITY_TYPE_DYNAMIC,							// Which is an immortal MATRIX.
		30,	// dummy, no MOF
		0,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// sub_butterfly2
		ENTITY_TYPE_MOVING_TONGUEABLE,
		30,
		0,
		0,
		0,
		0,
		0,
		&GenButterFlyCallBack,
		},
		{
		// sub_butterfly3
		ENTITY_TYPE_MOVING_TONGUEABLE,
		31,
		0,
		0,
		0,
		0,
		0,
		&GenButterFlyCallBack,
		},
		{
		// sub_stat_bullrush2
		ENTITY_TYPE_STATIC,
		32,
		},
		{
		// sub_stat_daisy
		ENTITY_TYPE_STATIC,
		33,
		},
		{
		// sub_stat_weed
		ENTITY_TYPE_STATIC,
		34,
		},
		{
		// sub_stat_weed2
		ENTITY_TYPE_STATIC,
		35,
		},
		{
		// sub_stat_weed3
		ENTITY_TYPE_STATIC,
		36,
		},
		{
		// sub_stat_treefat
		ENTITY_TYPE_STATIC,
		37,
		},
		{
		// sub_stat_treefat2
		ENTITY_TYPE_STATIC,
		38,
		},
		{
		// sub_stat_orchid
		ENTITY_TYPE_STATIC,
		39,
		},
		{
		// sub_stat_tree
		ENTITY_TYPE_STATIC,
		40,
		},
		{
		// sub_stat_tree2
		ENTITY_TYPE_STATIC,
		41,
		},
		{
		// sub_stat_tree3
		ENTITY_TYPE_STATIC,
		42,
		},
		{
		// sub_stat_tree4
		ENTITY_TYPE_STATIC,
		43,
		},
		{
		// sub_stat_shed
		ENTITY_TYPE_STATIC,
		44,
		},
		{
		// sub_bird4
		ENTITY_TYPE_MOVING,
		45,
		SCRIPT_SUB_PELICAN,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sub_snake
		ENTITY_TYPE_MOVING,
		46,
		SCRIPT_SUB_SNAKE,
		0,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// sub_crocodile
		ENTITY_TYPE_MOVING,
		47,
		SCRIPT_ORG_CROCODILE,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// sub_small_bird
		ENTITY_TYPE_MOVING,
		48,
		SCRIPT_SUB_SMALL_BIRD,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sub_log3
		ENTITY_TYPE_MOVING,
		49,
		},
		{
		// sub_cloud_platform
		ENTITY_TYPE_MOVING,
		50,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// sub_road_noise
		ENTITY_TYPE_STATIC_NOISE,
		15,
		SCRIPT_SUB_ROAD_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{						   
		// sub_water_noise
		ENTITY_TYPE_STATIC_NOISE,
		23,
		SCRIPT_SUB_WATER_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// sub_car_blue
		ENTITY_TYPE_MOVING,
		51,
		SCRIPT_SUB_CAR_BLUE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// sub_car_purple
		ENTITY_TYPE_MOVING,
		52,
		SCRIPT_SUB_CAR_BLUE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// sub_car_blue
		ENTITY_TYPE_MOVING,
		53,
		SCRIPT_SUB_CAR_BLUE,
		0,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
	};

//----------
// THEME_VOL
//----------
FORM_BOOK	Form_library_vol[] =
	{
		{
		// vol_buring_log
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_treetops
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_fireballs.
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		NULL,
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// vol_splash
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_spurt_platforms
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_black_lava
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_ash_gyser
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_crack
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_bubbleup
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_tops_explosions
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_tree_fall_burn
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_trapped_animal1
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_trapped_animal2
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_debris1
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_debris2
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_stat_treestump
		ENTITY_TYPE_STATIC,
		0+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_stat_rocks
		ENTITY_TYPE_STATIC,
		1+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_stat_rocks2
		ENTITY_TYPE_STATIC,
		2+VOLCANO_WAD_OFFSET,
		},
		{
		// vol_switch
		ENTITY_TYPE_TRIGGER,
		3+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		TriggerEntityCallback,
		},
		{
		// vol_platform1
		ENTITY_TYPE_MOVING,
		4+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// vol_platform2
		ENTITY_TYPE_MOVING_PLATFORM,
		5+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// vol_falling_platform (21)
		ENTITY_TYPE_VOL_FALLING_PLATFORM,
		6+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_THICK_FORM | FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH | FORM_BOOK_THICK_FORM,
		},
		{
		// vol_mechanism,
		ENTITY_TYPE_DYNAMIC,
		7+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_MECHANISM,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// vol_furnace_platform,
		ENTITY_TYPE_DYNAMIC,
		8+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_FURNACE_PLATFORM,
		},
		{
		// vol_lava_spray
		ENTITY_TYPE_MOVING,
		9+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_LAVA_SPRAY, 
		NULL,
		NULL,
		0,
		FORM_DEATH_FLOP,
		},
		{
		// vol_spinner,
		ENTITY_TYPE_MOVING,
		10+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_SPINNER,
		FORM_BOOK_THICK_FORM,
		NULL,
		0,
		FORM_DEATH_SQUISHED,
		},
		{
		// vol_colour_trigger
		ENTITY_TYPE_VOL_COLOUR_SWITCH,
		3+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		VolColourTriggerEntityCallback,
		},
		{
		// vol_cog_noise
		ENTITY_TYPE_STATIC,
		11+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_COG_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
		{
		// vol_platform3
		ENTITY_TYPE_MOVING_PLATFORM,
		12+VOLCANO_WAD_OFFSET,
		NULL,
		FORM_BOOK_RESET_ON_CHECKPOINT | FORM_BOOK_RESET_ON_FROG_DEATH,
		},
		{
		// vol_lava_noise
		ENTITY_TYPE_STATIC,
		10+VOLCANO_WAD_OFFSET,
		SCRIPT_VOL_LAVA_NOISE,
		FORM_BOOK_FLAG_NO_COLOUR_FADE | FORM_BOOK_FLAG_NO_MODEL,
		},
	};
