/******************************************************************************
*%%%% frog.h
*------------------------------------------------------------------------------
*
*	Frog control
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.04.97	Dean Ashton		Created
*	15.05.97	Martin Kift		Added and moved around frog jump flags
*	05.06.97	Martin Kift		Added animation structs.
*	08.07.97	Tim Closs		Added FROG_JUMPUP_SMALL_DY_EXTENDED
*
*%%%**************************************************************************/

#ifndef	__FROG_H
#define	__FROG_H

#include "mr_all.h"
#include "project.h"
#include "main.h"
#include "grid.h"
#include "zone.h"
#include "hud.h"
#include "effects.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compilation
#define	FROG_START_IN_LINE								// start multiple players in line
//#define	FROG_DISPLAY_HILITES						// display hilite vertices on frog models
#define	FROG_LOCAL_OT								// use local OT for frog
//#define	FROG_NO_DISPLAY									// hide frog model
//#define	FROG_INFINITE_LIVES

// Debug start position
//#define	FROG_DEBUG_START_X					9
//#define	FROG_DEBUG_START_Z					18
//#define	FROG_DEBUG_START_ON_ENTITY			1836

// Movement
#define	FROG_JUMP_DISTANCE					0x1000000	// standard jump distance (16.16)
#define	FROG_JUMP_DOWN_DISTANCE				0x100		// maximum smooth jump down distance
#define	FROG_MAX_Y_VELOCITY					0x300000	// maximum y velocity (16.16)
#define	FROG_CENTRING_SPEED					0x0f		// speed for centring to a grid square
#define	FROG_CENTRING_ANIMATION_TOLERANCE	0x60		// min distance from grid square centre to request centring animation
#define	FROG_FREEFALL_ANIMATION_DISTANCE	0//0x80		// freefall distance before animation kicks in

#define	FROG_JUMP_TIME						6			// standard jump duration
#define	FROG_QUICK_JUMP_TIME				3			// Half the standard jump.
#define	FROG_SUPERJUMP_TIME					15			// SuperJump duration

// Collision
#define	FROG_COLLIDE_RADIUS					80			// collision radius of frog
#define	FROG_COLLIDE_RADIUS2				MR_SQR(FROG_COLLIDE_RADIUS)

#define	FROG_COLLIDE_FROG_Y_OFFSET			100			// REMOVE FROM ENTITY SPECIFIC CODE!

#define	FROG_STACK_CENTRE_OFFSET			50			// offset from frog origin to radial collision origin
#define	FROG_STACK_MASTER_RADIUS			100			// collision radius
#define	FROG_STACK_COLLISION_HEIGHT 		200			// master above slave max y distance for collision
#define	FROG_STACK_SQUASH_TIME				8			// duration of squash bounce
#define	FROG_STACK_MASTER_OFFSET_MAX		100			// offset from frog slave to frog master (max)
#define	FROG_STACK_MASTER_OFFSET_MIN		50			// offset from frog slave to frog master (min)

// Death
#ifdef	FROG_INFINITE_LIVES
#define	FROG_START_LIVES					0x7fff
#else
#define	FROG_START_LIVES					3			// lives in bank at start of game
#endif

#define	FROG_MAX_LIVES						10			// Max lives Frogger can have
#define	FROG_DEATH_TIME						70			// death time
#define	FROG_POLY_PIECE_POP_DURATION		32			// duration of popping frog effect

// Frog flags
#define	FROG_ACTIVE							(1<<0)		// update frog
#define	FROG_JUMP_TO_ENTITY					(1<<1)		// frog is jumping towards an entity
#define	FROG_ON_ENTITY						(1<<2)		// frog is on an entity
#define	FROG_MUST_DIE						(1<<3)		// frog will be killed
#define	FROG_JUMP_FROM_ENTITY				(1<<4)		// frog is jumping from an entity (to entity, land or nothing)
#define	FROG_SUPERJUMP						(1<<5)		// frog is jumping with SuperJump
#define	FROG_JUMP_TO_LAND					(1<<6)		// frog is jumping to land
#define	FROG_FREEFALL						(1<<7)		// frog is in freefall
#define	FROG_FORCEDJUMP						(1<<8)		// frog is jumping with ForcedJump. This flag may be unnecessary!
#define	FROG_SCALING_UP						(1<<9)		// frog is scaling up
#define	FROG_SCALING_DOWN					(1<<10)		// frog is scaling down
#define FROG_CONTROL_ACTIVE					(1<<11)		// frog is active, but has no control. Used on death before restart.
#define FROG_IS_NETWORK						(1<<12)		// win95 only. If the frog is playing (ACTIVE) and on a remote machine.
#define FROG_FREEFALL_NO_ANIMATION			(1<<13)		// frog is in freefall, but has not yet played freefall animation
#define FROG_JUMP_ON_SPOT					(1<<14)		// frog is jumping on the spot
#define FROG_JUST_BOUNCED					(1<<15)		// frog just bounced
#define FROG_JUMP_FROM_COLLPRIM				(1<<16)		// frog has just hit a collprim (this will be removed soon $mk)

#define FROG_ENTER_SCORE					(1<<17)		// enter frog score in high score table
#define FROG_ENTER_ARCADE_TIME				(1<<18)		// enter frog time in aracde time table
#define FROG_ENTER_RACE_SCORE				(1<<19)		// enter frog score in race score table

#define FROG_DO_NOT_UPDATE_CAMERA_ZONES		(1<<20)		// dont update camera zones... hacky I know

// Frog jump types
#define	FROG_JUMP_SUPER						(1<<0)		// frog should do a super jump
#define	FROG_JUMP_FORCED					(1<<1)		// frog should do a forced jump, which overrides any height restrictions

#define	FROG_LANDED_ON_LAND_CLEAR_MASK		(FROG_ON_ENTITY | FROG_JUMP_TO_ENTITY | FROG_JUMP_FROM_ENTITY | FROG_SUPERJUMP | FROG_JUMP_TO_LAND | FROG_FREEFALL | FROG_FORCEDJUMP | FROG_JUMP_FROM_COLLPRIM | FROG_JUMP_ON_SPOT)
#define	FROG_LANDED_ON_ENTITY_CLEAR_MASK	(FROG_JUMP_TO_ENTITY | FROG_JUMP_FROM_ENTITY | FROG_SUPERJUMP | FROG_JUMP_TO_LAND | FROG_FREEFALL | FROG_FORCEDJUMP | FROG_JUMP_FROM_COLLPRIM | FROG_JUMP_ON_SPOT)

// Frog movement callback return flags
#define	FROG_MOVEMENT_CALLBACK_UPDATE_POS		(1<<0)	// update frog positional info
#define	FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS	(1<<1)	// update frog old positional info
#define	FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS	(1<<2)	// react with returned grid flags
#define	FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX	(1<<3)	// update frog matrix

// Frog croak times
#define	FROG_CROAK_INFLATE_TIME					6
#define	FROG_CROAK_HOLD_TIME					4
#define	FROG_CROAK_DEFLATE_TIME					6
#define	FROG_CROAK_MAX_SCALE					0x1000
#define	FROG_CROAK_MIN_SCALE					0x200
#define	FROG_CROAK_TARGET_RADIUS2				MR_SQR(16 * 0x100)	// 16 grid squares is max echo distance

// Input flags
#define	FROG_DIRECTION_NO_INPUT					0x80
#define	FROG_DIRECTION_CAMERA_CLOCKWISE			0x40
#define	FROG_DIRECTION_CAMERA_ANTICLOCKWISE		0x20
#define	FROG_DIRECTION_TONGUE					0x10
#define	FROG_DIRECTION_SUPER_JUMP				0x08
#define	FROG_DIRECTION_UNUSED					0x04	// Currently unused
#define	FROG_DIRECTION_RESERVED_2				0x02	// Used for direction
#define	FROG_DIRECTION_RESERVED_1				0x01	// Used for direction

// Misc
#define MAX_BUFFERED_KEYS						1
#define	FROG_BASE_COLOUR_FADE_SHIFT				1		// Amount of fade per frame for frog base colour!!!
#define	FROG_GLOBAL_OT_OFFSET					-0x30
//#define	FROG_GLOBAL_OT_OFFSET					-0x40	// changed from -0x30 by Tim, 26/08/97 
#define	FROG_POPPING_FIXED_OT					2		// pop and particle effect added at front of OT

// PowerUp Flags.
#define	FROG_POWERUP_SUPER_TONGUE				(1<<0)	// switches super tongue.
#define FROG_POWERUP_QUICK_JUMP					(1<<1)	// switches quick jump.
#define	FROG_POWERUP_AUTO_HOP					(1<<2)	// switches auto hop.
#define	FROG_POWERUP_TIMER_SPEED				(1<<3)	// switches timer speed. (Ramp)
#define	FROG_POWERUP_SUPER_LIGHT				(1<<4)	// switches the super light

// PowerUp Time Limits.
#define	POWERUP_AUTO_HOP_TIME					300		// Time the Auto Hop last.
#define	POWERUP_SUPER_TONGUE_TIME				450		// Time the Super Tongue last.
#define	POWERUP_QUICK_JUMP_TIME					240		// Time the Quick Jump last.

// Frog modes
enum	{
		FROG_MODE_STATIONARY,
		FROG_MODE_JUMPING,
		FROG_MODE_DYING,
		FROG_MODE_WAIT_FOR_CAMERA,
		FROG_MODE_HIT_CHECKPOINT,
		FROG_MODE_CENTRING,
		FROG_MODE_STUNNED,
		FROG_MODE_STACK_MASTER,
		FROG_MODE_NO_CONTROL,
		
		// Frog user modes start here
		FROG_MODE_USER = 0x100,
		};

// Jump heights, fall heights and stuff
#define	FROG_JUMPUP_SMALL_DY					0x0c8	// <= this can be made with normal hop
#define	FROG_JUMPUP_SMALL_DY_EXTENDED			0x0ff	// <= this can be made with normal hop if GRID_SQUARE_EXTEND_HOP_HEIGHT is set

#define	FROG_JUMPUP_LARGE_DY					0x1c0	// <= this can be made with SuperJump
#define	FROG_JUMPUP_FORCED_DY					0x7fff	// <= this can be made with Forced Jump (supposed to be infinite)

#define	FROG_FREEFALL_SAFE_HEIGHT				0x200	// <= this, and frog is OK
#define	FROG_FREEFALL_STUN_HEIGHT				0x400	// <= this, and frog is stunned (else frog dies)
#define	FROG_FREEFALL_STUN_TIME					45		// duration of stun

// Tongue defines
#define FROG_TONGUE_ALLOWANCE_HEIGHT			(200)	// Height allowance for tongueing entities

// General
#define FROG_DROP_HEIGHT						(400<<16)	// Height from which frog is dropped at start of level
#define FROG_MULTIPLAYER_HIT_CHECKPOINT_DELAY	(3*30)		// Time player has to wait (in multiplayer mode) before he can restart after hitting a checkpoint
#define	FROG_PERFECT_JUMPS_BEFORE_ROLL			(3)			// Number of perfect jumps (-1 since its buffered) before a roll happens

// Frog croak modes
enum	{
		FROG_CROAK_NONE,
		FROG_CROAK_INFLATE,
		FROG_CROAK_HOLD,
		FROG_CROAK_DEFLATE,
		};

// Frog IDs
enum	{
		FROG_ID_0,
		FROG_ID_1,
		FROG_ID_2,
		FROG_ID_3,
		FROG_MAX_FROGS,
		};

// Frog directions
enum	{
		FROG_DIRECTION_N,
		FROG_DIRECTION_E,
		FROG_DIRECTION_S,
		FROG_DIRECTION_W,
		};
	

// Frog hilite vertex indices
enum	{
		FROG_HILITE_VERTEX_TONGUE,
		FROG_HILITE_VERTEX_TRAIL_LEFT,
		FROG_HILITE_VERTEX_TRAIL_RIGHT,
		};


enum	{
		 FROG_ANIMATION_AUTOHOP,
		 FROG_ANIMATION_BACKFLIP,
		 FROG_ANIMATION_SQUISHED,
		 FROG_ANIMATION_WAIT1,
		 FROG_ANIMATION_TIMEOUT,
		 FROG_ANIMATION_STRUGGLE,
		 FROG_ANIMATION_FALLING,
		 FROG_ANIMATION_TRIGGER,
		 FROG_ANIMATION_DROWN,
		 FROG_ANIMATION_COMPLETE,
		 FROG_ANIMATION_BITTEN,
		 FROG_ANIMATION_FREEFALL,
		 FROG_ANIMATION_FLOP,
		 FROG_ANIMATION_OUCH,
		 FROG_ANIMATION_PANT,
		 FROG_ANIMATION_ROLL,
		 FROG_ANIMATION_HOP,
		 FROG_ANIMATION_SUPERJUMP,
		 FROG_ANIMATION_PANT2,
		 FROG_ANIMATION_WAIT3,
		 FROG_ANIMATION_SUPERHOP,
		 FROG_ANIMATION_WAIT2,
		 FROG_ANIMATION_SLIP,
		 FROG_ANIMATION_POP,
		 FROG_ANIMATION_SLIPRIGHT,
		 FROG_ANIMATION_SLIPLEFT,
		 FROG_ANIMATION_CRASH,
		 FROG_ANIMATION_PHEW,
		 FROG_ANIMATION_LOOKDOWN,
		 FROG_ANIMATION_LOOKUP,
		 FROG_ANIMATION_LOOKLEFT,
		 FROG_ANIMATION_LOOKRIGHT,
		 FROG_ANIMATION_DANCE,
		 FROG_ANIMATION_MOWN,
		 FROG_ANIMATION_ROLL_REPEATING,

		 FROG_ANIMATION_MAX,
	};


// Frog texture animations
enum	{
		FROG_TEX_ANIMATION_EYE_BLINK,
		FROG_TEX_ANIMATION_MAX,	// delimiter
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __frog					FROG;
typedef struct __frog_animation_data	FROG_ANIMATION_DATA;
typedef struct __frog_anim_info			FROG_ANIM_INFO;
typedef struct __frog_anim				FROG_ANIM;
typedef struct __frog_tex_anim_info		FROG_TEX_ANIM_INFO;
typedef struct __frog_tex_anim			FROG_TEX_ANIM;
typedef struct __frog_player_data		FROG_PLAYER_DATA;
typedef struct __frog_control_method	FROG_CONTROL_METHOD;

//
// Following is a array structure, used to equate an enum of actions to 
// a script to play and flags to control the playback
//
struct	__frog_anim
		{
		MR_LONG*		fa_script;							// Ptr to script to run
		MR_LONG*		fa_script_multiplayer;				// Ptr to script to run (when in multiplayer mode)
		MR_USHORT		fa_flags;							// Animation flags (such as QUEUE, INTERUPT, etc)
		MR_USHORT		fa_pad;								// Pad
		};	// FROG_ANIM

//
// Following is a runtime structure, stored off frog, for animation information and
// script handling...
//
struct	__frog_anim_info
		{
		MR_LONG			fi_flags;							// eg. FROG_ANIM_INFO_ACTIVE
		MR_LONG			fi_type;							// current script type (see enum list of frog anim equates (in frog.h))
		MR_LONG*		fi_script;							// ptr to current script action
	
		MR_LONG			fi_queue_flags;						// eg. FROG_ANIM_INFO_ACTIVE
		MR_LONG			fi_queue_type;						// queued script type
		MR_LONG*		fi_queue_script;					// queued script ptr
	
		MR_LONG			fi_previous_flags;					// eg. FROG_ANIM_INFO_ACTIVE
		MR_LONG			fi_previous_type;					// previous script type
		MR_LONG*		fi_previous_script;					// previous queued script ptr
		
		MR_LONG*		fi_script_loop_start;				// start of loop
		MR_LONG*		fi_script_loop_end;					// end of loop
		MR_LONG*		fi_script_loop_start_previous;		// start of previous loop (for gosubs)
		MR_LONG*		fi_script_loop_end_previous;		// end of previous loop (for gosubs)
	
		MR_LONG			fi_timer;							// Timer
		MR_LONG			fi_anim_timer;						// Timer for handling delayed anim's
		};	// FROG_ANIM_INFO

//
// Following is a array structure, used to equate an enum of actions to 
// a texture anim script to play and flags to control the playback
//
struct	__frog_tex_anim
		{
		MR_LONG*		ta_script;							// Ptr to script to run
		MR_USHORT		ta_flags;							// Animation flags (such as QUEUE, INTERUPT, etc)
		MR_USHORT		ta_pad;								// Pad
		};	// FROG_TEX_ANIM

//
// Following is a runtime structure, stored off frog, for texture animation information and
// script handling...
//
struct	__frog_tex_anim_info
		{
		MR_LONG			ti_flags;							// eg. FROG_TEX_ANIM_INFO_ACTIVE
		MR_LONG			ti_type;							// current script type (see enum list of frog anim equates (in frog.h))
		MR_LONG*		ti_script;							// ptr to current script action
	
		MR_LONG			ti_queue_flags;						// eg. FROG_TEX_ANIM_INFO_ACTIVE
		MR_LONG			ti_queue_type;						// queued script type
		MR_LONG*		ti_queue_script;					// queued script ptr
	
		MR_LONG			ti_previous_flags;					// eg. FROG_TEX_ANIM_INFO_ACTIVE
		MR_LONG			ti_previous_type;					// previous script type
		MR_LONG*		ti_previous_script;					// previous queued script ptr
		
		MR_LONG*		ti_script_loop_start;				// start of loop
		MR_LONG*		ti_script_loop_end;					// end of loop
		MR_LONG*		ti_script_loop_start_previous;		// start of previous loop (for gosubs)
		MR_LONG*		ti_script_loop_end_previous;		// end of previous loop (for gosubs)

		MR_LONG			ti_timer;							// Timer
		};	// FROG_TEX_ANIM_INFO


struct	__frog
		{
		MR_ULONG		fr_flags;				// eg. FROG_ACTIVE
		MR_ULONG		fr_mode;				// eg. FROG_MODE_STATIONARY
		MR_ULONG		fr_frog_id;				// unique frog ID (0..3)
		MR_ULONG		fr_direction;			// eg. FROG_DIRECTION_UP
		MR_ULONG		fr_input_id;			// controller ID
		FROG_CONTROL_METHOD* fr_control_method;	// current control method being used
	
		// Looping SFX.
		MR_LONG			fr_voice_id;			// Used to Store the voice for the slipping SFX.
		MR_LONG			fr_current_sfx;			// Current SFX playing.

		// Current position
		MR_LONG			fr_grid_x;				// current or destination grid x coord
		MR_LONG			fr_grid_z;				// current or destination grid z coord
		GRID_SQUARE*	fr_grid_square;			// current or destination grid square
		MR_LONG			fr_y;					// current or destination world y coord
		MR_VEC			fr_pos;					// current world pos (16.16)												

		// Old position
		MR_LONG			fr_old_grid_x;			// current or previous grid x coord
		MR_LONG			fr_old_grid_z;			// current or previous grid z coord
		GRID_SQUARE*	fr_old_grid_square;		// current or previous grid square
		MR_LONG			fr_old_y;		   		// current or previous world y coord
		MR_VEC			fr_old_pos;				// previous world pos (16.16)												

		// Start position
		MR_LONG			fr_start_grid_x;		// Start position grid_x, useful for resets
		MR_LONG			fr_start_grid_z;		// Start position grid_z, useful for resets

		// Movement
		MR_LONG			fr_count;				// counts down to 0 for jump
		MR_LONG			fr_death_count;			// death countdown timer
		MR_VEC			fr_velocity;			// add to fr_pos each frame (16.16)
		MR_SVEC			fr_target_pos;			// if jumping, target position

		MR_MAT*			fr_lwtrans;				// ptr to lw transform
		MR_MAT			fr_matrix;				// space for lw transform
		MR_VOID*		fr_api_item;			// ptr to API item (MR_OBJECT* or MR_ANIM_ENV*)
		MR_VOID*		fr_api_insts[4];		// ptr to API instances (MR_MESH_INST* or MR_ANIM_ENV_INST*)
		MR_LONG			fr_no_input_timer;		// counter for counting up no-input time
		MR_LONG			fr_buffered_key[MAX_BUFFERED_KEYS];		// Buffered keyboard storage
		MR_LONG			fr_num_buffered_keys;					// Current number of buffered key inputs stored
		MR_LONG			fr_buffered_input_count;				// Buffered input counter, used to measure how fast the player is hammering the buttons
		MR_OT*			fr_ot[4];				// pointer to the Frog's OT. (One for each ViewPort)
		
		// Bouncing (level initialisation)
		MR_LONG			fr_target_y;			// target Y position whilst bouncing at level start

		// Zone
		ZONE*			fr_cam_zone;			// current frog camera zone (if any)
		ZONE_REGION*	fr_cam_zone_region;		// current frog camera zone region (if any)

		// On entity
		ENTITY*			fr_entity;				// entity frog is on (if any)
		MR_VEC			fr_entity_ofs;			// offset from entity to frog, in entity frame (16.16)
		MR_LONG			fr_entity_angle;		// 0..3 according to direction on entity that UP will take us
		MR_LONG			fr_entity_grid_x;		// current or previous entity grid x coord
		MR_LONG			fr_entity_grid_z;		// current or previous entity grid z coord
		MR_MAT			fr_entity_transform;	// (this) * (current entity M) = (current frog M)
		ENTITY*			fr_forbid_entity;		// forbid collision with this (if non-NULL)
		
		// HUD and scores
		HUD_ITEM*		fr_hud_script;			// ptr to HUD script (or NULL)
		MR_LONG			fr_score;				// current score
		MR_ULONG		fr_old_score;			// old score
		MR_ULONG		fr_prev_score;			// score at end of last level ( used for calculating race mode scores on level by level basis )
		MR_LONG			fr_lives;				// current lives in the bank
		MR_ULONG		fr_life_bonus_score;	// Score at which next live bonus is awarded

		// Multiplayer stats
		MR_ULONG		fr_multi_games_won;		// Number of multiplayer games won
		MR_ULONG		fr_multi_games_lost;	// Number of multiplayer games lost

		// Effects
		EFFECT*			fr_shadow;				// frog shadow
		EFFECT*			fr_tongue;				// tongue
		EFFECT*			fr_trail;				// jump trail

		// Effects (separate from effects system)
		MR_VOID*		fr_particle_api_item;	// ptr to api item for particles
		MR_LONG			fr_particle_flags;		// particle flags

		// Scaling
		MR_LONG			fr_scale_up_time;		// time to scale up to max_scale
		MR_LONG			fr_scale_down_time;		// time to scale down to min_scale
		MR_LONG			fr_scale_timer;			// scaling timer
		MR_LONG			fr_max_scale;			// max scale to scale up to
		MR_LONG			fr_scale;				// current scale

		// User-mode
		MR_ULONG		fr_previous_key;		// Previous key pressed (if any)
		MR_ULONG		fr_current_key;			// Current key pressed (if any)
		MR_ULONG		fr_user_count;			// User count
		MR_VOID*		fr_user_data1;			// User data 1
		MR_VOID*		fr_user_data2;			// User data 2
		MR_SVEC			fr_user_target;			// Where we are moving Frogger to.
		MR_VEC			fr_user_source;			// Where Frogger came from.
		MR_VEC			fr_user_current;		// Current offset for the camera.
		MR_ULONG		fr_user_flags;			// What are we doing.
		MR_USHORT		fr_user_speed;			// Current moving speed.
		MR_USHORT		fr_user_acceleration;	// Current moving Acceleration.
		MR_USHORT		fr_user_timer;			// Time to wait at target.

		// Animations
		FROG_ANIM_INFO		fr_anim_info;		// animation info structure
		FROG_TEX_ANIM_INFO	fr_tex_anim_info;	// texture animation info structure
		MR_ULONG			fr_death_equate;	// death anim type (if dying)

		// Croak
		MR_ULONG		fr_croak_mode;			// eg. FROG_CROAK_NONE
		MR_ULONG		fr_croak_timer;			// counts down to 0 in each mode
		MR_ULONG		fr_croak_scale;			// real scale to apply to part transform
		MR_ULONG		fr_croak_radius_min;	// radius extender for light
		MR_ULONG		fr_croak_radius_max;	// radius extender for light
		MR_ULONG		fr_croak_rate;			// rate of croak which is applied to lights
		MR_MAT			fr_croak_scale_matrix;	// used as imported transform

		// Power Ups
		MR_ULONG		fr_powerup_flags;		// Have we any powerups active?
		MR_USHORT		fr_auto_hop_timer;		// Time until Auto-hop runs out.
		MR_USHORT		fr_super_tongue_timer;	// Time until Super-tongue runs out.
		MR_USHORT		fr_quick_jump_timer;	// Time until Quick-jump runs out.
		MR_USHORT		fr_powerup_pad;
		
		// Stacking
		FROG*			fr_stack_master;		// non-NULL if frog has a master
		FROG*			fr_stack_slave;			// non-NULL if frog has a slave
		MR_MAT			fr_stack_mod_matrix;	// (matrix)*(frog slave lwtrans) = (frog master lwtrans)
		MR_LONG			fr_stack_count;			// used to calculate squash offsets

		// Popping
		POLY_PIECE_POP*	fr_poly_piece_pop;		// frog popping control structure (alloc'ed with POLY_PIECE_DYNAMIC structures)

		// Rubbish :/
		MR_LONG			fr_old_direction;		// Old direction
		};	// FROG


struct __frog_player_data
		{
		MR_ULONG		fp_player_id;			// player id (0 to 3)
		MR_ULONG		fp_port_id;				// id of the port the frog is playing on
#ifdef WIN95
		MR_ULONG		fp_is_local;			// is this a local of network frog? (win95 only)
#endif
		
		// more data to be added soon


		}; // FROG_PLAYER_DATA

struct __frog_control_method
		{

		MR_ULONG		fc_up_control;
		MR_ULONG		fc_right_control;
		MR_ULONG		fc_down_control;
		MR_ULONG		fc_left_control;

		MR_ULONG		fc_camera_clockwise_control;
		MR_ULONG		fc_camera_anticlockwise_control;

		MR_ULONG		fc_tongue_control;
		MR_ULONG		fc_superjump_control;
		MR_ULONG		fc_repeat_control;
		MR_ULONG		fc_croak_control;

		};	// FROG_CONTROL_METHOD

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

// FROG_FALL is now a function in frog.c!

#define	FROG_KILL_PARTICLE_EFFECT(a)														\
		if ((a)->fr_particle_api_item)														\
			{																				\
			((MR_OBJECT*)(a)->fr_particle_api_item)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;	\
			(a)->fr_particle_api_item = NULL;												\
			}																				\

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	FROG				Frogs[];
extern	MR_ULONG			Frog_current_control_methods[];
extern	MR_VEC				Frog_fixed_vectors[];
extern	MR_LONG				Frog_input_ports[];
extern	FROG_PLAYER_DATA	Frog_player_data[];
extern	MR_BOOL				Frog_cave_light_special;
extern	MR_SVEC*			Frog_jump_shadow_offsets[];
extern	MR_TEXTURE*			Frog_jump_shadow_textures[];
extern	MR_MAT				Frog_splash_matrix;

#ifdef WIN95
extern	MR_ULONG			Frog_local_id;						
extern	FROG*				Frog_local_ptr;							
#endif


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			InitialiseFrogs(MR_VOID);
extern	FROG*			CreateFrog(MR_ULONG, MR_ULONG, MR_ULONG, MR_ULONG);
extern	MR_VOID			KillFrog(FROG*);
extern	MR_VOID			UpdateFrogs(MR_VOID);
extern	MR_VOID			ControlFrog(FROG*);
extern	MR_VOID			MoveFrog(FROG*);
extern	MR_VOID			ResetFrog(FROG*, MR_LONG, MR_LONG, MR_ULONG);
extern	MR_VOID			UpdateFrogPositionalInfo(FROG*);
extern	MR_VOID			UpdateFrogOldPositionalInfo(FROG*);
extern	MR_VOID			SetFrogUserMode(FROG*, MR_ULONG);
extern	MR_VOID			JumpFrog(FROG*, MR_LONG, MR_ULONG, MR_LONG, MR_LONG);
extern	MR_VOID			FrogLandedOnLand(FROG*);
extern	MR_VOID			UpdateFrogEffects(FROG*);
extern	ENTITY*			FrogGetNearestTongueTarget(FROG*);
extern	MR_BOOL 		FrogCheckTongueTargetVisibility(FROG*, LIVE_ENTITY*);
extern	MR_VOID			UpdateFrogMatrix(FROG*);
extern	MR_VOID			FrogSetScaling(FROG*, MR_LONG, MR_LONG,	MR_LONG);
extern	MR_VOID			FrogCollectCheckPoint(FROG*, ENTITY*);
extern	MR_VOID			FrogCollectGoldFrog(FROG*, ENTITY*);
extern	MR_VOID			FrogUpdateCroak(FROG*);
extern	ENTITY*			FrogGetNearestCheckpoint(FROG*);
extern	MR_VOID			FrogKill(FROG*, MR_ULONG, MR_VEC*);
extern	MR_VOID			UpdateFrogBaseColour(FROG*);
extern	MR_VOID			UpdateFrogStackMaster(FROG*, FROG*);
extern	MR_VOID			FrogReactToFallDistance(FROG*, MR_LONG, MR_USHORT);
extern	MR_VOID			JumpFrogOnSpot(FROG*, MR_LONG);
extern	MR_VOID			FrogInitCustomAmbient(FROG*);
extern	MR_VOID			SetFrogScaleColours(FROG*, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID			UpdateFrogCameraZone(FROG*);
extern	MR_VOID			FROG_FALL(FROG*);

// Poly piece popping
extern	MR_VOID			FrogStartPolyPiecePop(FROG*);

// Control callbacks
extern	MR_VOID			FrogModeControlStationary(FROG*, MR_ULONG);
extern	MR_VOID			FrogModeControlJumping(FROG*, MR_ULONG);

// Movement callbacks
extern	MR_ULONG		FrogModeMovementStationary(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementJumping(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementDying(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementHitCheckpoint(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_VOID			FrogUpdateFreefall(FROG*);
extern	MR_ULONG		FrogModeMovementCentring(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementStunned(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementLevelStartBounce(FROG*, MR_ULONG, MR_ULONG*);
extern	MR_ULONG		FrogModeMovementLevelStartComeToRest(FROG*, MR_ULONG, MR_ULONG*);

// PowerUp Functions.
extern	MR_VOID			UpdateFrogPowerUps(FROG*);
extern	MR_VOID			RemoveAllFrogsFromDisplay(MR_VOID);
extern	MR_VOID			FrogPlayLoopingSound(FROG*, MR_LONG);
extern	MR_VOID			FrogKillLoopingSound(FROG*);

#endif		//__FROG_H

