/******************************************************************************
*%%%% mapdebug.h
*------------------------------------------------------------------------------
*
*	Map Debug stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef	__MAPDEBUG_H
#define	__MAPDEBUG_H

#include "mr_all.h"
#include "gamefont.h"
#include "form.h"
#include "mapdisp.h"
#include "zone.h"
#include "grid.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	MAP_DEBUG_SCALE_INCREMENT			(0x80)
#define	MAP_DEBUG_SCALE_INITIAL				(0x1800)

#define	MAP_DEBUG_GRID_START_X				(256)
#define	MAP_DEBUG_GRID_START_Y				(128)
#define	MAP_DEBUG_GRID_CELL_SIZE			(3)

#ifdef PSX
#define	MAP_DEBUG_OPTION_X					(24)
#define	MAP_DEBUG_OPTION_Y					(72)
#define	MAP_DEBUG_OPTION_WIDTH				(212)
#define	MAP_DEBUG_OPTION_TITLE_HEIGHT		(9)
#define	MAP_DEBUG_OPTION_MAIN_HEIGHT		(25+(11*6))
#define	MAP_DEBUG_SHOW_MAX_LINES	 		(3)
#define	MAP_DEBUG_SHOW_TEXT_X		 		(296 - 10 * 6)
#define	MAP_DEBUG_SHOW_TEXT_Y		 		(48)
#define	MAP_DEBUG_SHOW_TEXT_W		 		(256)
#define	MAP_DEBUG_SHOW_TEXT_H		 		(256)
#define	MAP_DEBUG_SHOW_TEXT_MAX_CHARS		(100)
#else
#define	MAP_DEBUG_OPTION_X					(24)
#define	MAP_DEBUG_OPTION_Y					(72)
#define	MAP_DEBUG_OPTION_WIDTH				(212)
#define	MAP_DEBUG_OPTION_TITLE_HEIGHT		(9)
#define	MAP_DEBUG_OPTION_MAIN_HEIGHT		(25+(11*6))
#define	MAP_DEBUG_SHOW_MAX_LINES	 		(7)
#define	MAP_DEBUG_SHOW_TEXT_X		 		(600 - 15 * 6)
#define	MAP_DEBUG_SHOW_TEXT_Y		 		(48)
#define	MAP_DEBUG_SHOW_TEXT_W		 		(256)
#define	MAP_DEBUG_SHOW_TEXT_H		 		(256)
#define	MAP_DEBUG_SHOW_TEXT_MAX_CHARS		(200)
#endif

enum	{
		MOPTLINE_END,
		MOPTLINE_ROOT,
		MOPTLINE_SUB,
		};

enum	{
		MAP_OPTLINE_DISPLAY_MAP_GROUP_GRID,
		MAP_OPTLINE_DISPLAY_ACTIVE_GROUPS_ON_GRID,
		MAP_OPTLINE_DISPLAY_CURRENT_GROUP_ON_GRID,
		MAP_OPTLINE_CUSTOM_GRID_SCALE,

		MAP_OPTLINE_SHOW_MAP_POLY_COUNT,
		MAP_OPTLINE_SHOW_LIVE_PATH_ENT_COUNT,
		MAP_OPTLINE_SHOW_LIVE_STAT_ENT_COUNT,
		MAP_OPTLINE_SHOW_LIVE_PATH_ENT_POLY_COUNT,
		MAP_OPTLINE_SHOW_LIVE_STAT_ENT_POLY_COUNT,

#ifdef WIN95
		MAP_OPTLINE_SHOW_FRAME_RATE,
		MAP_OPTLINE_SHOW_FRAME_COUNT,
#endif
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __map_debug_optline	MAP_DEBUG_OPTLINE;

struct	__map_debug_optline
		{
		MR_ULONG		mo_type;
		MR_BOOL			mo_initial_state;
		MR_STRPTR		mo_text;
		MR_BOOL			mo_current_state;
		MR_TEXT_AREA*	mo_text_area;

		};	//MAP_DEBUG_OPTLINE

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	GET_MAP_DEBUG_OPTION_STATE(a)	Map_debug_optlines[(a)].mo_current_state

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_BOOL		Map_debug_options_show;

// MR_LONGs for debug variables go here
extern	MR_LONG		Map_debug_land_polys;
extern	MR_LONG		Map_debug_poly_groups;

extern	MR_LONG		Map_debug_live_path_ents;
extern	MR_LONG		Map_debug_live_stat_ents;
extern	MR_LONG		Map_debug_live_path_ent_polys;
extern	MR_LONG		Map_debug_live_stat_ent_polys;

#ifdef WIN95
extern	MR_LONG		Map_debug_frame_rate;
#endif

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

// Debug display stuff
extern	MR_VOID		InitialiseMapDebugDisplay(MR_VOID);
extern	MR_VOID		KillMapDebugDisplay(MR_VOID);
extern	MR_VOID		UpdateMapDebugDisplay(MR_VOID);
extern	MR_VOID		BuildMapDebugGroups(MR_VOID);
extern	MR_VOID		BuildMapDebugShowText(MR_VOID);
extern	MR_VOID		DrawMapDebugLine(MR_SVEC*, MR_SVEC*, MR_ULONG);

// Other debug functions
extern	MR_VOID		MapDebugDisplayGridFlags(MR_ULONG, MR_ULONG);
extern	MR_VOID		MapDebugDisplayForm(FORM*, MR_MAT*);
extern	MR_VOID		MapDebugDisplayMapGroup(MAP_GROUP*);
extern	MR_VOID		MapDebugDisplayZoneRegion(ZONE_REGION*);
extern	MR_VOID		MapDebugDisplayGridSquare(GRID_SQUARE*);
extern	MR_VOID		MapDebugDisplayGridCoord(MR_LONG, MR_LONG);
extern	MR_VOID		MapDebugDisplayGrid(MR_LONG, MR_LONG, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID		MapDebugDisplayFormBoundingSphere(LIVE_ENTITY*);
extern	MR_VOID		MapDebugDisplayPath(PATH*);


#endif	//__MAPDEBUG_H

