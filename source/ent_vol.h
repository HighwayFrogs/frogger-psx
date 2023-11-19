/******************************************************************************
*%%%% ent_vol.h
*------------------------------------------------------------------------------
*
*	Header file for the Volcano level.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

#ifndef	__ENT_VOL_H
#define	__ENT_VOL_H

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define VOL_COLOUR_TRIGGER_MAX_IDS			(10)

// Entity trigger types
enum	{
		VOL_TYPE_TRIGGER_FREEZE,
		VOL_TYPE_TRIGGER_REVERSE,
		VOL_TYPE_TRIGGER_START,
		};

// Entity trigger initial movement.
enum	{
		VOL_INITIAL_MOVEMENT_MOVING,
		VOL_INITIAL_MOVEMENT_STOPPED,
		};

// Switch flags
#define	VOL_SWITCH_FLAG_FIRST_TIME			(1<<0)
#define	VOL_SWITCH_FLAG_NO_FROG_CONTACT		(1<<1)

// Switch states (same for all switch types)
enum	{
		VOL_SWITCH_ON_DOWN,
		VOL_SWITCH_ON_UP,
		VOL_SWITCH_OFF_DOWN,
		VOL_SWITCH_OFF_UP,
		};

// Switch actions
enum	{
		VOL_SWITCH_ACTION_DOWN,
		VOL_SWITCH_ACTION_UP,
		};

#define	VOL_SWITCH_FORBID_TIME					6


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__vol_colour_trigger		VOL_COLOUR_TRIGGER;
typedef	struct	__vol_rt_colour_trigger		VOL_RT_COLOUR_TRIGGER;
typedef	struct	__vol_triggered_platform	VOL_TRIGGERED_PLATFORM;

struct __vol_colour_trigger
	{
	MR_MAT		ct_matrix;
	MR_USHORT	ct_type;
	MR_USHORT	ct_colour;
	MR_SHORT	ct_unique_ids[VOL_COLOUR_TRIGGER_MAX_IDS];
	MR_ULONG	ct_frame_count;

	};	// VOL_COLOUR_TRIGGER


struct __vol_rt_colour_trigger
	{
	MR_ULONG	ct_forbid_timer;
	MR_ULONG	ct_flags;
	MR_LONG		ct_state;

	};	// VOL_RT_COLOUR_TRIGGER


struct	__vol_triggered_platform
	{
	PATH_INFO		vt_path_info;						
	MR_ULONG		vt_initial_movement;			// Is it moving or stopped??

	};	// VOL_TRIGGERED_PLATFORM

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_vol_mechanism[];
extern	MR_LONG		script_vol_cog_noise[];
extern	MR_LONG		script_vol_lava_noise[];
extern	MR_LONG		script_vol_spinner[];
extern	MR_LONG		script_vol_furnace_platform[];
extern	MR_LONG		script_vol_lava_spray[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		ScriptCBVolMechanism(LIVE_ENTITY* live_entity);
extern	MR_VOID		ENTSTRVolCreateFallingPlatform(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRVolUpdateFallingPlatform(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRVolCreateColourTrigger(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRVolUpdateColourTrigger(LIVE_ENTITY*);
extern	MR_VOID 	VolColourTriggerEntityCallback(MR_VOID*, MR_VOID*, MR_VOID*);

#endif	//__ENT_VOL_H
