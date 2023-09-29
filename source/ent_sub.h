/******************************************************************************
*%%%% ent_sub.h
*------------------------------------------------------------------------------
*
*	This is used to hold all the structures/defines etc for the suburbia entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	18.12.96	Martin Kift		Created
*	18.04.97	Gary Richards	Update ALL functions/structures to conform to standard
*	24.04.97	Gary Richards	Added to the new Frogger code.
*	06.05.97	Martin Kift		Moved about everything to scripts
*
*%%%**************************************************************************/

#ifndef __ENT_SUB_H
#define __ENT_SUB_H

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum {
	SUB_TURTLE_DIVING,
	SUB_TURTLE_NOTDIVING,
	};

enum {
	SUB_DOG_WAITING,
	SUB_DOG_WALKING,
	SUB_DOG_FALLING,
	SUB_DOG_BITING,
	};

#define	SUB_DOG_BARK_DISTANCE	1024

enum	{
		SUB_LAWNMOWER_MOWING,
		SUB_LAWNMOWER_CHOPPING,
		SUB_LAWNMOWER_DO_NOTHING,
		};

typedef struct __suburbia_turtle		SUBURBIA_TURTLE;
typedef	struct __suburbia_rt_dog		SUBURBIA_RT_DOG;
typedef	struct __suburbia_dog			SUBURBIA_DOG;
typedef struct __sub_rt_lawnmower		SUB_RT_LAWNMOWER;

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

struct	__suburbia_turtle
	{
	PATH_INFO		st_path_info;						
	MR_ULONG		st_dive_delay;
	MR_ULONG		st_rise_delay;
	MR_ULONG		st_turtle_type;
	};	// SUBURBIA_TURTLE

struct __suburbia_rt_dog
	{
	PATH_INFO	do_path_info;			// Standard path setup info
	MR_ULONG	do_current_wait;		// How long to go before we move.
	MR_ULONG	do_state;				// What are we doing??
	MR_ULONG	do_bite_count;			// Time remaining in bite animation
	};	// SUBURBIA_RT_DOG

struct	__suburbia_dog
	{
	PATH_INFO		do_path_info;				
	MR_ULONG		do_wait_delay;		
	};	// suburbia_dog

struct	__sub_rt_lawnmower
	{
	MR_ULONG	lm_state;				// Current mode of operation
	};	// SUB_RT_LAWNMOWER

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_sub_lawn_mower[];
extern	MR_LONG		script_sub_lawn_mower_kill_frogger[];
extern	MR_LONG		script_sub_swan[];
extern	MR_LONG		script_sub_swan_sfx[];
extern	MR_LONG		script_sub_lilly_pad[];
extern	MR_LONG		script_sub_car_blue[];
extern	MR_LONG		script_sub_car_blue_sfx[];
extern	MR_LONG		script_sub_lorry[];
extern	MR_LONG		script_sub_lorry_sfx[];
extern	MR_LONG		script_sub_truck[];
extern	MR_LONG		script_sub_truck_sfx[];
extern	MR_LONG		script_sub_snake[];
extern	MR_LONG		script_sub_road_noise[];
extern	MR_LONG		script_sub_water_noise[];
extern	MR_LONG		script_sub_small_bird[];
extern	MR_LONG		script_sub_snake_turn[];
extern	MR_LONG		script_sub_pelican[];
extern	MR_LONG		script_sub_pelican_call_sfx[];

extern	MR_VOID		ENTSTRSubCreateTurtle(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBDiveColourChange(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSubLillyPad(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRSubCreateDog(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSubUpdateDog(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRSubCreateLawnmower(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSubUpdateLawnmower(LIVE_ENTITY*);

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------


#endif //__ENT_SUB_H
