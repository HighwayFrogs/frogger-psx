/******************************************************************************
*%%%% library.h
*------------------------------------------------------------------------------
*
*	Libraries of books for various subjects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__LIBRARY_H
#define	__LIBRARY_H

#include "mr_all.h"
#include "entity.h"
#include "formlib.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	MAX_LEVELS_PER_WORLD		(6)
#define	MAX_THEMES					(10)

// These are in same order as Map_library
enum	{
		LEVEL_CAVES1,
		LEVEL_CAVES2,
		LEVEL_CAVES3,
		LEVEL_CAVES4,
		LEVEL_CAVES5,
		LEVEL_CAVES_MULTI_PLAYER,

		LEVEL_DESERT1,
		LEVEL_DESERT2,
		LEVEL_DESERT3,
		LEVEL_DESERT4,
		LEVEL_DESERT5,
		LEVEL_DESERT_MULTI_PLAYER,

		LEVEL_FOREST1,
		LEVEL_FOREST2,
		LEVEL_FOREST3,
		LEVEL_FOREST4,
		LEVEL_FOREST5,
		LEVEL_FOREST_MULTI_PLAYER,

		LEVEL_JUNGLE1,
		LEVEL_JUNGLE2,
		LEVEL_JUNGLE3,
		LEVEL_JUNGLE4,
		LEVEL_JUNGLE5,
		LEVEL_JUNGLE_MULTI_PLAYER,

		LEVEL_ORIGINAL1,
		LEVEL_ORIGINAL2,
		LEVEL_ORIGINAL3,
		LEVEL_ORIGINAL4,
		LEVEL_ORIGINAL5,
		LEVEL_ORIGINAL_MULTI_PLAYER,

		LEVEL_RUINS1,
		LEVEL_RUINS2,
		LEVEL_RUINS3,
		LEVEL_RUINS4,
		LEVEL_RUINS5,
		LEVEL_RUINS_MULTI_PLAYER,

		LEVEL_SWAMP1,
		LEVEL_SWAMP2,
		LEVEL_SWAMP3,
		LEVEL_SWAMP4,
		LEVEL_SWAMP5,
		LEVEL_SWAMP_MULTI_PLAYER,

		LEVEL_SKY1,
		LEVEL_SKY2,
		LEVEL_SKY3,
		LEVEL_SKY4,
		LEVEL_SKY5,
		LEVEL_SKY_MULTI_PLAYER,

		LEVEL_SUBURBIA1,
		LEVEL_SUBURBIA2,
		LEVEL_SUBURBIA3,
		LEVEL_SUBURBIA4,
		LEVEL_SUBURBIA5,
		LEVEL_SUBURBIA_MULTI_PLAYER,

		LEVEL_VOLCANO1,
		LEVEL_VOLCANO2,
		LEVEL_VOLCANO3,
		LEVEL_VOLCANO4,
		LEVEL_VOLCANO5,
		LEVEL_VOLCANO_MULTI_PLAYER,

		LEVEL_ISLAND,				// THIS IS THE FIRST TEST MAP. (HERE FOR TIM!!!)
		LEVEL_QB,					// THIS IS THE FIRST TEST MAP. (HERE FOR TIM!!!)
	};

// Map book flags

#define	MAP_BOOK_FLAG_CAVE_LIGHT	(1<<0)			// use cave lights

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__map_book			MAP_BOOK;
typedef	struct	__theme_book		THEME_BOOK;

struct	__map_book
	{
	MR_ULONG	mb_map_res_id;			// resource id of MAP file
	MR_USHORT*	mb_texture_remap;		// texture remap array
	MR_ULONG	mb_flags;				// special flags for each map
	MR_TEXTURE*	mb_env_texture_ptr;		// Ptr to this themes environment bitmap
#ifdef MR_DEBUG
#ifdef WIN95
	char*		mb_map_name;			// map name, for dbug purposes only, allows mappers to load in maps from files
#endif
#endif
	MR_ULONG	mb_model_wad_res_id;	// resource id of model WAD file (Level Based.)
	};	// MAP_BOOK


struct	__theme_book
	{
	MR_ULONG	tb_full_model_wad_res_id;	// resource id of model WAD file (FULL)
	FORM_BOOK*	tb_form_library;			// ptr to Form_library_???
	MR_ULONG	tb_vlo_res_id;				// resource id of VLO file
	MR_LONG		tb_death_height;			// frog dies below this height
	MR_ULONG	tb_multi_model_wad_res_id;	// resource id of model WAD file (FULL)
	MR_ULONG	tb_multi_vlo_res_id;		// resource id of VLO file
	};	// THEME_BOOK


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MAP_BOOK	Map_library[];
extern	THEME_BOOK	Theme_library[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------



#endif		//__LIBRARY_H

