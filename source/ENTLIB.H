/******************************************************************************
*%%%% entlib.h
*------------------------------------------------------------------------------
*
*	Specific entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	23.04.97	Tim Closs		Created
*	30.04.97	Martin Kift		Added an 'immortal entity' 
*	02.04.97	Martin Kift		Added new entity library variable, for size
*								of runtime structure. Also scripting code.
*	12.05.97	Martin Kift		Removed scripting id (moved to form library)
*
*%%%**************************************************************************/

#ifndef	__ENTLIB_H
#define	__ENTLIB_H

#include "mr_all.h"
#include "entity.h"
#include "sprdata.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Entity library flags
#define	ENTITY_BOOK_PATH_RUNNER				(1<<0)		// create a PATH_RUNNER for the entity at map resolve time
#define ENTITY_BOOK_IMMORTAL				(1<<1)		// entity that refuses to die when offscreen... please don't overuse
#define ENTITY_BOOK_USE_SCRIPT				(1<<2)		// use script file (supplied by library) to control entity
#define ENTITY_BOOK_STATIC					(1<<3)		// never unlink from MAP_GROUP list
#define ENTITY_BOOK_TONGUEABLE				(1<<4)		// targettable with TONGUE
#define ENTITY_BOOK_FROG_NO_ALIGN			(1<<5)		// frog is not aligned to entity when landing on it
#define	ENTITY_BOOK_XZ_PARALLEL_TO_CAMERA	(1<<6)		// for 3D sprites: create matrix XZ parallel to camera local XY

// These are in same order as Entity_library
enum	{
		ENTITY_TYPE_STATIC,
		ENTITY_TYPE_MOVING,
		ENTITY_TYPE_CHECKPOINT,
		ENTITY_TYPE_DES_FALLING_ROCK,
		ENTITY_TYPE_DES_EARTH_QUAKE,
		ENTITY_TYPE_DES_THERMAL,
		ENTITY_TYPE_DYNAMIC,
		ENTITY_TYPE_CAV_WEB,
		ENTITY_TYPE_CAV_SPIDER,
		ENTITY_TYPE_CAV_FROGGER_LIGHT,
		ENTITY_TYPE_ORG_LOG_SNAKE,
		ENTITY_TYPE_BONUS_FLY,
		ENTITY_TYPE_SUB_TURTLE,
		ENTITY_TYPE_SWP_SQUIRT,
		ENTITY_TYPE_SWP_CRUSHER,
		ENTITY_TYPE_TRIGGER,
		ENTITY_TYPE_ORG_BABY_FROG,
		ENTITY_TYPE_DES_SNAKE,
		ENTITY_TYPE_ORG_BEAVER,
		ENTITY_TYPE_DES_VULTURE,
		ENTITY_TYPE_ORG_FLY,
		ENTITY_TYPE_ORG_CROC_HEAD,
		ENTITY_TYPE_FOR_HIVE,
		ENTITY_TYPE_SWP_PRESS,
		ENTITY_TYPE_CAV_FAT_FIRE_FLY,
		ENTITY_TYPE_DES_CROC_HEAD,
		ENTITY_TYPE_MULTIPOINT,
		ENTITY_TYPE_SUB_DOG,
		ENTITY_TYPE_DES_CRACK,
		ENTITY_TYPE_CAV_RACE_SNAIL,
		ENTITY_TYPE_FOR_FALLING_LEAF,
		ENTITY_TYPE_FOR_SWAYING_BRANCH,
		ENTITY_TYPE_FOR_BREAKING_BRANCH,
		ENTITY_TYPE_FOR_SQUIRREL,
		ENTITY_TYPE_FOR_HEDGEHOG,
		ENTITY_TYPE_MOVING_PLATFORM,
		ENTITY_TYPE_MOVING_TONGUEABLE,
		ENTITY_TYPE_FIREFLY,
		ENTITY_TYPE_JUN_PLANT,
		ENTITY_TYPE_DES_ROLLING_ROCK,
		ENTITY_TYPE_JUN_ROPE_BRIDGE,
		ENTITY_TYPE_JUN_HIPPO,
		ENTITY_TYPE_VOL_FALLING_PLATFORM,
		ENTITY_TYPE_DES_TUMBLE_WEED,
		ENTITY_TYPE_GEN_TOP_LEFT,
		ENTITY_TYPE_GEN_BOTTOM_RIGHT,
		ENTITY_TYPE_GEN_GOLD_FROG,
		ENTITY_TYPE_SWP_RAT,
		ENTITY_TYPE_VOL_COLOUR_SWITCH,
		ENTITY_TYPE_JUN_OUTRO_DOOR,
		ENTITY_TYPE_JUN_STATUE,
		ENTITY_TYPE_JUN_PLINTH,
		ENTITY_TYPE_JUN_GOLD_FROG,
		ENTITY_TYPE_JUN_STONE_FROG,
		ENTITY_TYPE_JUN_OUTRO,
		ENTITY_TYPE_SWP_SLUG,
		ENTITY_TYPE_JUN_BOUNCY_MUSHROOM,
		ENTITY_TYPE_SUB_LAWNMOWER,
		ENTITY_TYPE_NUCLEAR_BARREL,
		};

// Entity trigger types
enum	{
		ENTITY_TYPE_TRIGGER_FREEZE,
		ENTITY_TYPE_TRIGGER_REVERSE,
		ENTITY_TYPE_TRIGGER_START,
		ENTITY_TYPE_TRIGGER_BEGIN,
		};


#define	ENTITY_TYPE_TRIGGER_MAX_IDS		(10)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__entity_book		ENTITY_BOOK;

// Entity specific structures
typedef	struct	__entstr_static		ENTSTR_STATIC;
typedef	struct	__entstr_moving		ENTSTR_MOVING;
typedef	struct	__entstr_dynamic	ENTSTR_DYNAMIC;
typedef	struct	__entstr_trigger	ENTSTR_TRIGGER;
typedef	struct	__entstr_rt_trigger	ENTSTR_RT_TRIGGER;
typedef	struct	__entstr_butterfly	ENTSTR_BUTTERFLY;

struct	__entity_book
	{
	MR_VOID		(*eb_callback_create)(LIVE_ENTITY*);	// create callback
	MR_VOID		(*eb_callback_update)(LIVE_ENTITY*);	// update callback
	MR_VOID		(*eb_callback_kill)(LIVE_ENTITY*);		// kill callback
	MR_ULONG	eb_flags;								// entity flags
	MR_ULONG	eb_runtime_data_size;					// Runtime structure size required

	};	// ENTITY_BOOK


// Entity specific structures
struct	__entstr_static
	{
	MR_MAT			et_matrix;

	};	// ENTSTR_STATIC

// Entity specific structures
struct	__entstr_dynamic
	{
	MR_MAT			et_matrix;

	};	// ENTSTR_DYNAMIC


struct	__entstr_moving
	{
	PATH_INFO		et_path_info;						// standard path setup info

	};	// ENTSTR_MOVING

struct __entstr_trigger
	{
	MR_MAT		et_matrix;
	MR_ULONG	et_type;
	MR_SHORT	et_unique_ids[ENTITY_TYPE_TRIGGER_MAX_IDS];
	MR_ULONG	et_frame_count;
	};	// ENTSTR_TRIGGER

struct __entstr_rt_trigger
	{
	MR_ULONG	et_frame_count;
	MR_BOOL		et_first_time;
	};	// ENTSTR_RT_TRIGGER

struct	__entstr_butterfly
	{
	PATH_INFO		et_path_info;						// standard path setup info
	MR_USHORT		et_type;							// Score type for Butterfly.
	MR_USHORT		et_pad;
	};	// ENTSTR_BUTTERFLY

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	ENTITY_BOOK	Entity_library[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------



#endif	//__ENTLIB_H

