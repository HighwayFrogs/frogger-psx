/******************************************************************************
*%%%% ent_org.h
*------------------------------------------------------------------------------
*
*	Header file for original theme entities.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_ORG_H
#define	__ENT_ORG_H

#include "mr_all.h"
#include "entity.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum {
	ORG_C_ACTION_SNAKE_BITING,
	ORG_C_ACTION_SNAKE_SLITHERING,
	};

enum {
	ORG_BABY_FROG_SEARCHING,
	ORG_BABY_FROG_ON_ENTITY,
	ORG_BABY_FROG_JUMPING,
	ORG_BABY_FROG_ON_FROG,
	ORG_BABY_FROG_NOTHING,
	ORG_BABY_FROG_WAIT_TO_SEARCH_AGAIN,
	};

#define ORG_BABY_FROG_JUMP_DELAY			(30)
#define ORG_GOLD_BABY_FROG_FORM_ID			(24)
#define ORG_BABY_FROG_SEARCH_BEFORE_LAND	(2)

enum {
	ORG_BEAVER_SWIMMING,							// Swimming through water
	ORG_BEAVER_WAITING_FIRSTLOG,					// Waiting for a log to pass underneath
	ORG_BEAVER_WAITING_FIRSTLOGEND,					// Found a log, now waiting til its out of view
	ORG_BEAVER_WAITING_GAP,							// Counting the gap before something else comes along
	ORG_BEAVER_WAITING_TO_FINISH_BITE,				// Wait for beaver to finish bite
	ORG_BEAVER_SWIMMING_ENDPAUSE					// Hit log we are following, pausing before restarting
};

#define	ORG_BEAVER_CHECK_PAUSE		(30)			// Pause (time) before checking for moving entities
#define	ORG_BEAVER_KILL_DISTANCE	(262)			// Distance beaver must be from frog to kill it
#define ORG_BEAVER_DIVE_COUNT		(60)			// Dive timer
#define ORG_BEAVER_DIVE_SPEED		(256/60)		// Dive speed

enum	{
		ORG_ACTION_BEAVER_SWIM,
		ORG_ACTION_BEAVER_BITE,
		};

enum	{
		ORG_BONUS_FLY_WAITING,
		ORG_BONUS_FLY_APPEARED,
		ORG_BONUS_FLY_EATEN,
		};

#define	ORG_BONUS_FLY_OT_OFFSET				(0)
#define	ORG_BONUS_FLY_APPEAR_TIME			(60)
#define	ORG_BONUS_FLY_DISAPPEAR_TIME		(120)
#define	ORG_BONUS_FLY_EATEN_TIME			(120)
#define	ORG_BONUS_FLY_VALUE					(1000)

enum	{
		ORG_CROC_HEAD_WAITING,
		ORG_CROC_HEAD_APPEARING,
		ORG_CROC_HEAD_APPEARED,
		};

#define	ORG_CROC_HEAD_APPEAR_TIME			(60)
#define	ORG_CROC_HEAD_APPEARING_TIME		(60)
#define	ORG_CROC_HEAD_DISAPPEAR_TIME		(120)
#define	ORG_CROC_HEAD_FRAMES				(20)

// Animation list for crocodile
enum
	{
	ORG_ACTION_CROCODILE_SWIMMING,			// swimming
	ORG_ACTION_CROCODILE_SNAPPING,			// Snapping mouth
	};

// Flags for baby frog
#define	ORG_BABY_FROG_HOME_FLAG				(1<<0)
#define	ORG_BABY_FROG_DEAD_FLAG				(1<<1)

// Animation list for turtle
enum
	{
	ACTION_TURTLE_SWIMMING,
	ACTION_TURTLE_DIVING,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef	struct __org_log_snake_data		ORG_LOG_SNAKE_DATA;
typedef	struct __org_rt_log_snake		ORG_RT_LOG_SNAKE;
typedef	struct __org_baby_frog_data		ORG_BABY_FROG_DATA;
typedef	struct __org_rt_baby_frog		ORG_RT_BABY_FROG;
typedef	struct __org_beaver_data		ORG_BEAVER_DATA;
typedef	struct __org_rt_beaver			ORG_RT_BEAVER;
typedef	struct __org_bonus_fly			ORG_BONUS_FLY;
typedef	struct	__org_rt_bonus_fly		ORG_RT_BONUS_FLY;
typedef	struct __org_croc_head			ORG_CROC_HEAD;
typedef	struct	__org_rt_croc_head		ORG_RT_CROC_HEAD;

struct __org_log_snake_data
	{
	MR_MAT					ls_matrix;				// matrix
	MR_SHORT				ls_unique_log_id;		// Unique id of log to sit on
	MR_USHORT				ls_speed;				// Speed of movement
	};		// ORG_LOG_SNAKE_DATA

struct __org_rt_log_snake
	{
	ENTITY*					ls_log_entity;			// Ptr to parent entity
	MR_SVEC					ls_offset;				// Offset of snake from centre of log
	MR_SHORT				ls_movement_range;		// Range of movement (basically length of parent)
	MR_USHORT				ls_pad;					// pad
	MR_UBYTE				ls_direction;			// Direction of movement
	MR_UBYTE				ls_action;				// Current action, moving or biting
	};		// ORG_RT_LOG_SNAKE

struct __org_baby_frog_data
	{
	MR_MAT					bf_matrix;				// Not really required.
	MR_SHORT				bf_unique_log_id;		// Unique id of the log (parent) frog will stand on
	MR_SHORT				bf_value;				// Points awarded when collected
	};		// ORG_BABY_FROG_DATA

struct __org_rt_baby_frog
	{
	ENTITY*					bf_entity;				// Needs to be resolved at update time
	MR_VOID*				bf_frog;				// Pointer to frog, if standing on it.
	MR_VEC					bf_entity_ofs;			// offset from entity to frog, in entity frame (16.16)
	MR_LONG					bf_entity_angle;		// 0..3 according to direction on entity that UP will take us
	MR_LONG					bf_entity_grid_x;		// current or previous entity grid x coord
	MR_LONG					bf_entity_grid_z;		// current or previous entity grid z coord
	MR_MAT					bf_entity_transform;	// (this) * (current entity M) = (current frog M)
	MR_VEC					bf_target_pos;			// Target position
	MR_VEC					bf_velocity;			// Velocity of frog as it jumps
	MR_VEC					bf_pos;					// Current position
	MR_ULONG				bf_croak_mode;			// eg. FROG_CROAK_NONE
	MR_ULONG				bf_croak_timer;			// counts down to 0 in each mode
	MR_ULONG				bf_croak_scale;			// real scale to apply to part transform
	MR_MAT					bf_croak_scale_matrix;	// Baby frog croak scale matrix
	MR_ULONG				bf_jump_time_count;		// Take left in current jump
	MR_ULONG				bf_flags;				// General flags ( ie got home score )
	MR_USHORT				bf_delay;				// Delay before jumping
	MR_USHORT				bf_count;				// JUmp count
	MR_USHORT				bf_direction;			// Direction of movement
	MR_UBYTE				bf_mode;				// Baby frog mode
	MR_UBYTE				bf_search_count;		// Baby frog mode
	};		// ORG_BABY_FROG

struct __org_beaver_data
	{
	PATH_INFO				bv_path_info;			// Standard path setup info
	MR_SHORT				bv_delay;				// Delay before following entity
	MR_SHORT				bv_pad;
	};		// ORG_BEAVER_DATA

struct __org_rt_beaver
	{
	ENTITY*					bv_follow_entity;			// Ptr to entity that beaver is following
	MR_USHORT				bv_delay;					// Delay (for following)
	MR_USHORT				bv_curr_movement;			// Current movement 
	MR_USHORT				bv_wait;					// Wait count
	MR_USHORT				bv_dive_offset;				// pad
	};		// ORG_RT_BEAVER

struct	__org_bonus_fly
	{
	MR_MAT			bf_matrix;
	MR_USHORT		bf_type;
	MR_USHORT		bf_pad;
	};	// ORG_BONUS_FLY

struct	__org_rt_bonus_fly
	{
	MR_LONG			bf_timer;
	MR_LONG			bf_mode;
	MR_ULONG		bf_checkpoint_id;
	};	// ORG_RT_BONUS_FLY

struct	__org_croc_head
	{
	MR_MAT			ch_matrix;
	MR_USHORT		ch_type;
	MR_USHORT		ch_pad;
	};	// ORG_BONUS_FLY

struct	__org_rt_croc_head
	{
	MR_LONG			ch_timer;
	MR_LONG			ch_mode;
	MR_LONG			ch_checkpoint_id;
	MR_ULONG		ch_snd_timer;
	};	// ORG_RT_BONUS_FLY

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_org_car_blue[];
extern	MR_LONG		script_org_car_blue_sfx[];
extern	MR_LONG		script_org_car_purple[];
extern  MR_LONG		script_org_car_purple_sfx[];
extern	MR_LONG		script_org_lorry[];
extern	MR_LONG		script_org_lorry_sfx[];
extern	MR_LONG		script_org_snake[];
extern	MR_LONG		script_org_truck[];
extern	MR_LONG		script_org_truck_sfx[];
extern  MR_LONG		script_org_bull_dozer[];
extern	MR_LONG		script_org_bull_dozer_sfx[];
extern	MR_LONG		script_log_splash[];

extern	MR_LONG		script_org_crocodile[];
extern	MR_LONG		script_org_bonus_fly_collected[];
extern	MR_LONG		script_org_bonus_fly[];
extern	MR_LONG		script_org_road_noise[];
extern	MR_LONG		script_org_water_noise[];
extern	MR_LONG		script_turtle[];
extern	MR_LONG		script_turtle_no_dive[];
extern	MR_LONG		script_org_turtle_swim[];

extern	MR_SVEC		Org_baby_frog_directions[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID ENTSTROrgCreateLogSnake(LIVE_ENTITY*);
extern	MR_VOID ENTSTROrgUpdateLogSnake(LIVE_ENTITY*);
extern	MR_VOID ENTSTROrgKillLogSnake(LIVE_ENTITY*);
extern	MR_VOID ENTSTROrgCreateBabyFrog(LIVE_ENTITY*);
extern	MR_VOID ENTSTROrgUpdateBabyFrog(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBFrogTrafficSplat(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBLogSplash(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBHitTurtle(LIVE_ENTITY*);
extern	ENTITY*	OrgCollideEntityWithPathEntities(LIVE_ENTITY*, PATH*);
extern	MR_VOID	ENTSTROrgUpdateBeaver(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgCreateBeaver(LIVE_ENTITY*);

extern	MR_VOID	ENTSTROrgKillBonusFly(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgUpdateBonusFly(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgCreateBonusFly(LIVE_ENTITY*);

extern	MR_VOID	ENTSTROrgUpdateCrocHead(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgCreateCrocHead(LIVE_ENTITY*);
extern	MR_VOID	ENTSTROrgKillCrocHead(LIVE_ENTITY*);

extern	MR_BOOL	ENTSTROrgChooseRandomCheckPoint(LIVE_ENTITY*, MR_ULONG*, MR_SVEC*);
extern	MR_VOID	ENTSTROrgResetCrocHead(LIVE_ENTITY*, ENTITY*, ORG_RT_CROC_HEAD*);

#endif	//__ENT_ORG_H
