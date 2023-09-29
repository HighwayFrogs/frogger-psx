/******************************************************************************
*%%%% suburbia.h
*------------------------------------------------------------------------------
*
*	This is used to hold all the structures/defines etc for the suburbia entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	18.12.96	Martin Kift		Created
*	18.04.97	Gary Richards	Update ALL functions/structures to conform to standard
*	24.04.97	Gary Richards	Added to the new Frogger code.
*
*%%%**************************************************************************/

#ifndef __suburbia_h
#define __suburbia_h

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------
//
// Turtle - Spline based entity
//

#define SUB_TURTLE_DIVE_HEIGHT	(128 << WORLD_SHIFT)

enum
	{
	SUB_ANIM_TURTLE_SWIMMING,				// on top of the water, waiting for dive to commense.
	SUB_ANIM_TURTLE_DIVING,					// Diving under the water.
	};

enum
	{
	SUB_ACTION_TURTLE_SWIMMING,				// on top of the water, waiting for dive to commense.
	SUB_ACTION_TURTLE_DIVING,				// Diving under the water.
	SUB_ACTION_TURTLE_UNDERWATER_SWIMMING,	// Swimming under water, waiting for rise to commense
	SUB_ACTION_TURTLE_RISING,				// Rising back to the top
	};

//
// Crocodile - spline based
//

enum
	{
	ORG_ACTION_CROCODILE_SWIMMING,			// swimming
	ORG_ACTION_CROCODILE_SNAPPING,			// Snapping mouth
	};

//
// Swan - spline based
//

enum					
	{							
	SUB_ACTION_SWAN_SWIMMING,
	SUB_ACTION_SWAN_START_FLAP,
	SUB_ACTION_SWAN_FLAPPING,
	SUB_ACTION_SWAN_STOP_FLAP,
	};

enum					
	{							
	SUB_ANIM_SWAN_SWIMMING,
	SUB_ANIM_SWAN_FLAPPING,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef	struct __suburbia_turtle		SUBURBIA_TURTLE;
typedef struct __suburbia_rt_turtle		SUBURBIA_RT_TURTLE;
typedef	struct __original_crocodile		ORIGINAL_CROCODILE;
typedef struct __original_rt_crocodile	ORIGINAL_RT_CROCODILE;
typedef	struct __suburbia_swan			SUBURBIA_SWAN;
typedef struct __suburbia_rt_swan		SUBURBIA_RT_SWAN;

// Turtle Map specific structure.
struct	__suburbia_turtle
	{
	PATH_INFO		tu_path_info;			// standard path setup info

	MR_SHORT		tu_dive_delay;			// delay before turtles dive
											// or -1 if none-diving variety ;)
	MR_SHORT		tu_rise_delay;			// delay before turtles rise

	MR_SHORT		tu_dive_speed;			// Speed at which the Turtle Dives.
	MR_SHORT		tu_rise_speed;			// Speed at which the Turtle Rises.

	};	// SUBURBIA_TURTLE

// Turtle RunTime structure.
struct __suburbia_rt_turtle
	{
	MR_USHORT		tu_dive_count;			// Diving count!
	MR_LONG			tu_dive_height;			// Diving Height (Y offset to base of spline)
	MR_BYTE			tu_state;				// State (action)
	MR_BYTE			tu_pad;		
	};	// SUBURBIA_RT_TURTLE


//
// Crocodile - spline based
//

struct __original_crocodile
	{
	MR_USHORT		cd_open_mouth_delay;	// Delay before opening mouth
	MR_USHORT		cd_pad;					// pad
	};	// ORIGINAL_CROCODILE


struct __original_rt_crocodile
	{
	MR_USHORT		cd_delay;				// Delay (opening mouth) counter
	MR_USHORT		cd_action;				// Action of croc (opening/closing mouth)
	};	// ORIGINAL_RT_CROCODILE

//
// Swan - spline based
//

struct __suburbia_swan
	{
	MR_USHORT		sw_spline_delay;		// Delay at BOTH ends of the spline. GCR
	MR_SHORT		sw_swimming_time;		// Moving along normally. (-1 prevents flapping.)
	MR_SHORT		sw_flap_think_time;		// 
	MR_SHORT		sw_flapping_time;		// 
	};	// SUBURBIA_SWAN

struct __suburbia_rt_swan
	{
	MR_LONG			sw_voice_id;			// voice id
	MR_SHORT		sw_flap_delay;			// Delay until NEXT state.
	MR_SHORT		sw_action;				// current action
	MRSND_MOVING_SOUND*	sw_moving_sound;	// ptr to moving sound pointer.
	};	// SUBURBIA_RT_SWAN


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	ENTSTRSubCreateTurtle(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubUpdateTurtle(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubKillTurtle(LIVE_ENTITY*);

extern	MR_VOID	ENTSTROrgCreateCrocodile(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateCrocodile(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgKillCrocodile(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRSubCreateSwan(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubUpdateSwan(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubKillSwan(LIVE_ENTITY*);

// These's are tmep.
extern	MR_VOID	ENTSTRSubUpdateCar(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubUpdateLorry(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateSnake(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSubUpdateLawnMower(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRSkyUpdateBird1(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateTruckRed(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateCarPurple(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateSwan(LIVE_ENTITY*);

#endif //__suburbia