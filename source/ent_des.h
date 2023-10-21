/******************************************************************************
*%%%% ent_des.h
*------------------------------------------------------------------------------
*
*	This is used to hold all the structures/defines etc for the desert entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	28.04.97	Martin Kift		Created
*	07.07.97	Tim Closs		Revised for new shadows.
*								Added ENTSTRDesFallingRockCalculateInitialVelocity()
*								Added DES_ROCK_RADIUS, DESERT_FALLING_ROCK_TARGETS_RESOLVED
*	18.07.97	Martin Kift		Rewrote rock tumbling code
*
*%%%**************************************************************************/

#ifndef __DES_ENT_H
#define __DES_ENT_H

#include "mr_all.h"
#include "entity.h"
#include "effects.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

//
// Falling rock - dynamic entity
//
enum 
	{
	DES_C_ACTION_FALLING_ROCK_CHECKING,
	DES_C_ACTION_FALLING_ROCK_DELAY,
	DES_C_ACTION_FALLING_ROCK_START,
	DES_C_ACTION_FALLING_ROCK_TARGETS,
	DES_C_ACTION_FALLING_ROCK_EXPLODE,
	DES_C_ACTION_FALLING_ROCK_EXPLODING,
	};

#define	DES_FALL_ROCKROLL		(1)			// Used to change position within the buildwad file.

#define DES_ROCK_RADIUS						(0x80)
//
// Desert EarthQuake.
//

#define DES_C_MAX_ENT_UNPAUSED_BY_QUAKE		(10)

enum 
	{
	DES_C_ACTION_EARTH_QUAKE_STARTING,
	DES_C_ACTION_EARTH_QUAKE_WAITING,
	DES_C_ACTION_EARTH_QUAKE_SHAKING,
	DES_C_ACTION_EARTH_QUAKE_RAMPING_DOWN,
	DES_C_ACTION_EARTH_QUAKE_STOPPED,
	};

//
// Tumble weeds
//
#define DES_C_TUMBLE_WEED_SLOW				(15)		// Slow down in 15 frames.

enum
	{
	DES_C_ACTION_TUMBLE_WEED_START,
	DES_C_ACTION_TUMBLE_WEED_MOVING,
	DES_C_ACTION_TUMBLE_WEED_ACCELERATING,
	DES_C_ACTION_TUMBLE_WEED_SLOWING
	};

//
// Snake Animations.
//

enum
	{
	DES_ANIM_SNAKE_NORMAL,
	DES_ANIM_SNAKE_BITE,
	DES_ANIM_SNAKE_TURNING,
	DES_ANIM_SNAKE_RATTLE,
	};

#define	DES_SNAKE_RATTLE_RANGE	(512)
#define DES_SNAKE_BITE_RANGE	(256)

//
// Vulture Animations.
//

enum
	{
	DES_ANIM_VULTURE_NORMAL,
	DES_ANIM_VULTURE_SWOOP,
	};

// Desert Croc Head

enum
	{
	DES_CROCHEAD_PAUSE3,
	DES_CROCHEAD_RISE,
	DES_CROCHEAD_PAUSE1,
	DES_CROCHEAD_SNAP,
	DES_CROCHEAD_PAUSE2,
	DES_CROCHEAD_FALL,
	};

// Desert Crack

enum
	{
	DES_CRACK_WAITING_FOR_HITS,
	DES_CRACK_WAITING_TO_FALL,
	DES_CRACK_FALLING,
	};

#define	DES_CRACK_NUM_ANIM_TEXTURES	(3)

enum
	{	
	DES_ROLLING_ROCK_ROLLING,
	DES_ROLLING_ROCK_EXPLODING,
	};


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef	struct __desert_falling_rock			DESERT_FALLING_ROCK;
typedef struct __desert_rt_falling_rock			DESERT_RT_FALLING_ROCK;
typedef struct __desert_falling_rock_targets	DESERT_FALLING_ROCK_TARGETS;
typedef struct __desert_thermal					DESERT_THERMAL;
typedef struct __desert_rt_thermal				DESERT_RT_THERMAL;
typedef struct __desert_rt_snake				DESERT_RT_SNAKE;
typedef struct __desert_rt_vulture				DESERT_RT_VULTURE;
typedef struct __des_croc_head					DES_CROC_HEAD;
typedef struct __des_rt_croc_head				DES_RT_CROC_HEAD;
typedef	struct __des_rt_crack					DES_RT_CRACK;
typedef	struct __des_crack						DES_CRACK;
typedef struct __desert_rt_rolling_rock			DESERT_RT_ROLLING_ROCK;
typedef struct __desert_rt_tumble_weed			DESERT_RT_TUMBLE_WEED;

//
// Desert Falling Rocks.
//
#define	DESERT_FALLING_ROCK_TARGETS_RESOLVED	(1<<0)	// target SVECs have been projected down onto landscape

struct __desert_falling_rock_targets
	{
	MR_SVEC							fr_target;			// Target position
	MR_USHORT						fr_time;			// Time to reach target
	MR_USHORT						fr_pad;				// Pad

	}; // DESERT_FALLING_ROCK_TARGETS


struct __desert_falling_rock
	{	
	MR_MAT							fr_matrix;			// matrix of entity
	DESERT_FALLING_ROCK_TARGETS		fr_targets[12];		// Array of 12 target positions and times
	MR_USHORT						fr_delay;			// Delay until rock starts moving.
	MR_UBYTE						fr_num_bounces;		// Number of bounces
	MR_UBYTE						fr_pad[1];			// Pad
	MR_LONG							fr_flags;			// eg. DESERT_FALLING_ROCK_TARGETS_RESOLVED
	MR_LONG							fr_entity_sound;	// Does this rock have an SFX??

	};	// DESERT_FALLING_ROCK


struct __desert_rt_falling_rock
	{
	MR_VEC							fr_position;		// Position backup
	MR_VEC							fr_velocity;		// Velocity backup
	MR_VOID*						fr_anim_rock;		// Rock Animation
	MR_VOID*						fr_api_insts[4];	// ptr to API mesh instance ( as returned by MRAddObjectToViewport )
	EFFECT*							fr_shadow;			// falling rock shadow
	MR_LONG							fr_grid_x;			// Current grid X
	MR_LONG							fr_grid_z;			// Current grid Z
	MR_MAT							fr_rot_matrix;		// Rotation Matrix
	MR_LONG							fr_rotation;		// Rotation
	MR_SVEC							fr_rot_svec;		// svec
	MR_USHORT						fr_curr_time;		// Curr time counter
	MR_BYTE							fr_state;			// Current state
	MR_BYTE							fr_curr_bounces;	// Current bounce
	};	// DESERT_RT_FALLING_ROCK

struct __desert_rt_rolling_rock
	{
	MR_VOID*						rr_anim_rock;		// Rock Animation
	MR_VOID*						rr_api_insts[4];	// ptr to API mesh instance ( as returned by MRAddObjectToViewport )
	MR_LONG							rr_rotation;		// Roll rotation X
	MR_LONG							rr_mode;			// Current mode
	MR_MAT							rr_matrix;			// matrix for entity (can't use parent's, its a path runner)
	};	// DESERT_RT_FALLING_ROCK

struct __desert_rt_tumble_weed
	{
	MR_LONG							tw_rotation;		// Roll rotation X
	MR_VEC							tw_velocity;		// Velocity (of jumping)
	MR_LONG							tw_count;			// Count
	EFFECT*							tw_shadow;			// falling rock shadow
	MR_LONG							tw_height;			
	};	// DESERT_RT_TUMBLE_WEED

//
// Desert thermal
//

struct __desert_thermal
	{	
	MR_USHORT				tw_rotate_time;			// Time to rotate 360
	MR_USHORT				tw_pad;
	};	// DESERT_THERMAL

struct __desert_rt_thermal
	{
	PATH_INFO				tw_path_info;			// Standard path setup info
	MR_USHORT				tw_rotate_step;			// Current time
	MR_USHORT				tw_pad;					// Pad
	MR_SVEC					tw_rotation;			// Current rotation
	};	// DESERT_RT_THERMAL

//
// Desert Snake (Only run time!)
//

struct __desert_rt_snake
	{
	PATH_INFO				sn_path_info;			// Standard path setup info
	MR_BOOL					sn_request_anim;		// Waiting to start new animation.
	MR_USHORT				sn_requested_anim;		// The animation we are waiting for.
	MR_USHORT				sn_frame_count;			// Used to tell when the turn animation is finishing,
	};	// DESERT_RT_SNAKE

//
// Desert Vulture (Only run time!)
//

struct __desert_rt_vulture
	{
	PATH_INFO				vu_path_info;			// Standard path setup info
	MR_BOOL					vu_request_anim;		// Waiting to start new animation.
	MR_USHORT				vu_requested_anim;		// The animation we are waiting for.
	MR_USHORT				vu_pad;
	};	// DESERT_RT_VULTURE

//
// CrocHead
//

struct __des_croc_head
	{
	MR_MAT			ch_matrix;					// Matrix of entity
	MR_USHORT		ch_rise_height;				// Height to rise to
	MR_USHORT		ch_rise_speed;				// Speed at which to rise
	MR_USHORT		ch_snap_delay;				// Time before snapping
	MR_USHORT		ch_pause_delay;				// Time before falling
	MR_USHORT		ch_snap_or_not_to_snap;		// Flag, specifing whether to snap or not
	MR_USHORT		ch_submerged_delay;			// Time before rising
	};	// DES_CROC_HEAD

struct __des_rt_croc_head
	{
	MR_USHORT		ch_rt_mode;					// Mode of operation
	MR_USHORT		ch_rt_start_position;		// Start y height
	MR_ULONG		ch_rt_wait_count;			// Time waiting for
	MR_BOOL			ch_rt_deadly;				// Head deadly status
	};	// DES_RT_CROC_HEAD

struct __des_rt_crack
	{
	MR_USHORT		cr_current_wait;			// Before it falls.
	MR_UBYTE		cr_state;					// What are we doing??
	MR_UBYTE		cr_num_hits;				// How many times have we been hit??
#ifndef BUILD_49
	MR_LONG			cr_vel_y;					// y velocity (16:16)
	MR_LONG			cr_y;						// y position (16:16)
#endif
	};	// DES_RT_CRACK

struct	__des_crack
	{
	MR_MAT			cr_matrix;			// Matrix of entity
	MR_USHORT		cr_fall_delay;		// Time before the crack opens.	
	MR_USHORT		cr_hops_before;		// Number of time it can be landed before it triggers.
	};	// DES_CRACK

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG	script_des_vulture[];
extern	MR_LONG	script_des_vulture_sfx[];
extern	MR_LONG	script_des_bison[];
extern	MR_LONG	script_des_bison_sfx[];
extern	MR_LONG	script_des_rolling_rock[];
extern	MR_LONG	script_des_beetle[];
extern	MR_LONG	script_des_lizard[];
extern	MR_LONG script_des_salamander[];
extern	MR_LONG	script_des_snake[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	ENTSTRDesCreateFallingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateFallingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesKillFallingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesFallingRockCalculateInitialVelocity(LIVE_ENTITY*, DESERT_FALLING_ROCK*, DESERT_RT_FALLING_ROCK*);

extern	MR_VOID ENTSTRDesCreateThermal(LIVE_ENTITY*);
extern	MR_VOID ENTSTRDesUpdateThermal(LIVE_ENTITY*);

extern	MR_VOID ENTSTRDesCreateSnake(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateSnake(LIVE_ENTITY*);

extern	MR_VOID ENTSTRDesCreateVulture(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateVulture(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRDesCreateShadow(LIVE_ENTITY*, DESERT_RT_FALLING_ROCK*);

extern	MR_VOID ENTSTRDesCreateCrocHead(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateCrocHead(LIVE_ENTITY*);

extern	MR_VOID ENTSTRDesCreateCrack(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateCrack(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRDesCreateRollingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateRollingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesKillRollingRock(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRDesCreateTumbleWeed(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateTumbleWeed(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesKillTumbleWeed(LIVE_ENTITY*);

#endif //__DES_ENT_H
