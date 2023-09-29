/******************************************************************************
*%%%% ent_swp.h
*------------------------------------------------------------------------------
*
*	Swamp header file
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Martin Kift		Created
*	24.05.97	Martin Kift		Added squirts and crushers
*
*%%%**************************************************************************/

#ifndef	__ENT_SWP_H
#define	__ENT_SWP_H

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------


typedef struct __swamp_squirt			SWAMP_SQUIRT;
typedef struct __swamp_rt_squirt		SWAMP_RT_SQUIRT;
typedef struct __swamp_crusher			SWAMP_CRUSHER;
typedef struct __swamp_rt_crusher		SWAMP_RT_CRUSHER;
typedef struct __swamp_press			SWAMP_PRESS;
typedef struct __swamp_rt_press			SWAMP_RT_PRESS;
typedef struct __swamp_rat				SWAMP_RAT;
typedef struct __swamp_rt_rat			SWAMP_RT_RAT;
typedef struct __swamp_slug				SWAMP_SLUG;

enum	{
		// Actions for slug
		SWAMP_SLUG_ANIM_NORMAL,
		SWAMP_SLUG_ANIM_CURVY,
		};

enum	{
		SWAMP_SLUG_MOTION_TYPE_NORMAL,
		SWAMP_SLUG_MOTION_TYPE_CURVY,
		};

enum {
	// squirt action enum list
	SWAMP_SQUIRT_WAITING,
	SWAMP_SQUIRT_FALL_PREPARE,
	SWAMP_SQUIRT_FALLING,
	};

enum {
	// squirt (potential anim enum list
	SWAMP_SQUIRT_ANIM_NORMAL,
	SWAMP_SQUIRT_ANIM_FALLING,
	SWAMP_SQUIRT_ANIM_SQUASHED,
	};


#define SWAMP_CRUSHER_IN		0
#define SWAMP_CRUSHER_OUT		1

enum {
	SWAMP_CRUSHER_NORTH,
	SWAMP_CRUSHER_EAST,
	SWAMP_CRUSHER_SOUTH,
	SWAMP_CRUSHER_WEST,

	SWAMP_CRUSHER_WAITING,
	SWAMP_CRUSHER_CRUSHING,
	};

#define SWAMP_PRESS_MOVING_UP		0
#define SWAMP_PRESS_MOVING_DOWN		1

enum {
	SWAMP_PRESS_UP,
	SWAMP_PRESS_DOWN,

	SWAMP_PRESS_WAITING,
	SWAMP_PRESS_CRUSHING,
	};

#define	SWP_PRESS_DISTANCE	 (1024)
#define	SWP_SQUIRT_DISTANCE  (1536)

enum	{
		SWAMP_RAT_MODE_INIT_FIRST_JUMP,
		SWAMP_RAT_MODE_JUMP1,
		SWAMP_RAT_MODE_INIT_ROLL,
		SWAMP_RAT_MODE_ROLL,
		SWAMP_RAT_MODE_RUN,
		SWAMP_RAT_MODE_JUMP2,
		SWAMP_RAT_MODE_RESTART,
		};

enum	{
		SWAMP_RAT_ANIM_RUN,
		SWAMP_RAT_ANIM_JUMP,
		SWAMP_RAT_ANIM_ROLL,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

struct __swamp_squirt
	{	
	MR_MAT		sq_matrix;			// Placement matrix
	MR_SHORT	sq_time_delay;		// Once off delay 
	MR_SHORT	sq_drop_time;		// Time to reach Target.
	MR_SVEC		sq_target;			// Place where the drip is going to end up.
	};	// SWAMP_SQUIRT

struct __swamp_rt_squirt
	{ 
	MR_VEC		sq_velocity;		// The amount we should move every frame.
	MR_VEC		sq_position;		// Current position
 	MR_SHORT	sq_curr_time;		// Current time
	MR_BYTE		sq_action;			// current action
	MR_BYTE		sq_anim;			// Current anim
	};	// SWAMP_RT_SQUIRT

struct __swamp_crusher
	{	
	MR_MAT		cr_matrix;			// Placement matrix
	MR_SHORT	cr_speed;			// Speed of movement
	MR_SHORT	cr_distance;		// Distance moved
	MR_SHORT	cr_direction;		// Direction to move in
	MR_SHORT	cr_delay;			// Once only delay
	};	// SWAMP_CRUSHER

struct __swamp_rt_crusher
	{ 
	MR_USHORT	cr_direction;		// Curr direction
	MR_USHORT	cr_time;			// Curr time
	MR_USHORT	cr_action;			// Curr acion
	MR_USHORT	cr_pad;				// pad
	};	// SWAMP_RT_CRUSHER

struct __swamp_press
	{	
	MR_MAT		pr_matrix;			// Placement matrix
	MR_SHORT	pr_speed;			// Speed of movement
	MR_SHORT	pr_distance;		// Distance moved
	MR_SHORT	pr_direction;		// Direction to move in
	MR_SHORT	pr_delay;			// Once only delay
	};	// SWAMP_PRESS

struct __swamp_rt_press
	{ 
	MR_USHORT	pr_direction;		// Curr direction
	MR_USHORT	pr_time;			// Curr time
	MR_USHORT	pr_action;			// Curr acion
	MR_USHORT	pr_pad;				// pad
	};	// SWAMP_RT_PRESS

struct __swamp_rat
	{	
	MR_MAT		ra_matrix;			// Placement matrix
	MR_SHORT	ra_speed;			// Speed of movement
	MR_SHORT	ra_pad;				// Pad
	MR_SVEC		ra_start_target;	// Target to start from
	MR_SVEC		ra_start_run_target;
	MR_SVEC		ra_end_run_target;
	MR_SVEC		ra_end_target;
	};	// SWAMP_RAT

struct __swamp_rt_rat
	{ 
	MR_USHORT	ra_mode;			// Current mode of operation
	MR_USHORT	ra_count;			// Temp count
	MR_LONG		ra_speed;			// Speed per frame

	MR_LONG		ra_prev_y;			// Previous y position

	MR_LONG		ra_jump1_time;
	MR_LONG		ra_run_time;
	MR_LONG		ra_jump2_time;

	MR_LONG		ra_jump1_dist;		// XZ distance of first jump
	MR_LONG		ra_jump2_dist;		// XZ distance of second jump

	MR_LONG		ra_jump1_sin_movement;
	MR_LONG		ra_jump2_sin_movement;

	MR_LONG		ra_jump1_sin_pos;
	MR_LONG		ra_jump2_sin_pos;

	MR_VEC		ra_jump1_vel;
	MR_VEC		ra_run_vel;
	MR_VEC		ra_jump2_vel;

	MR_VEC		ra_pos;

	};	// SWAMP_RT_RAT

struct	__swamp_slug
	{
	PATH_INFO		sl_path_info;
	MR_ULONG		sl_motion_type;
	};	// swamp_slug

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_swp_nuclear_barrel_ejecting[];
extern	MR_LONG		script_swp_nuclear_barrel_waiting[];
extern	MR_LONG		script_swp_waste_barrel_spinning[];
extern	MR_LONG		script_swp_waste_barrel_waiting[];
extern	MR_LONG		script_swp_bobbing_waste_barrel[];
extern	MR_LONG		script_swp_oil_drum[]; 
extern	MR_LONG		script_swp_pallet[]; 
extern	MR_LONG		script_swp_sunkcar[]; 
extern	MR_LONG		script_swp_stat_pipe[]; 
extern	MR_LONG		script_swp_stat_pipe_big_str[]; 
extern	MR_LONG		script_swp_stat_pipe_hole[]; 
extern	MR_LONG		script_swp_water_noise[];
extern	MR_LONG		script_swp_rat[];
extern	MR_LONG		script_swp_rat_sfx[];
extern	MR_LONG		script_swp_mutant_fish[];
extern	MR_LONG		script_swp_raccoon[];
extern	MR_LONG		script_swp_snail[];
extern	MR_LONG		script_swp_pelican[];
extern	MR_LONG		script_swp_pelican_call_sfx[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		ENTSTRSwpCreateSquirt(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpUpdateSquirt(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpCreateCrusher(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpUpdateCrusher(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpOilDrum(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpPallet(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpSunkCar(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpStatPipe(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpStatPipeBigStr(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpMutantFish(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpCreatePress(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpUpdatePress(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpCreateRat(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpUpdateRat(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpRaccoon(LIVE_ENTITY*);
extern	MR_VOID		ScriptCBSwpPelicanCall(LIVE_ENTITY*);

extern	MR_VOID		SwpCrusherCallback(MR_VOID*, MR_VOID*, MR_VOID*);

extern	MR_VOID		ENTSTRSwpCreateSlug(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpUpdateSlug(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRSwpKillSlug(LIVE_ENTITY*);

#endif	//__ENT_SWP_H
