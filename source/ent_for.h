/******************************************************************************
*%%%% ent_for.h
*------------------------------------------------------------------------------
*
*	Forest header file
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_FOR_H
#define	__ENT_FOR_H

#include "mr_all.h"
#include "entity.h"
#include "collide.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Hive - matrix based
enum {
	FOR_ACTION_HIVE_WAITING,
	FOR_ACTION_HIVE_SWARM_CHASING,
	FOR_ACTION_HIVE_SWARM_MILLING,
	FOR_ACTION_HIVE_SWARM_RETURNING,
};

#define	FOR_HIVE_CRITICAL_DISTANCE	(3 * 256)					    
#define FOR_HIVE_INTEREST_TIME		(2 * 30)			// 2 Seconds before they lose interest.
#define	FOREST_MAX_VIS_ENTITIES		(3)					// Check for max of 3 entities
#define	FOR_SWARM_ANGLE_SPEED		0x200				// angular speed of swarm buzzing

enum 	{
		FOREST_SQUIRREL_RUNNING,
		FOREST_SQUIRREL_TURNING,
		};

enum 	{
		FOREST_HEDGEHOG_RUNNING,
		FOREST_HEDGEHOG_PREPARE_TO_ROLL,
		FOREST_HEDGEHOG_ROLLING,
		FOREST_HEDGEHOG_PREPARE_TO_RUN,
		};

enum	{
		FOREST_BRANCH_OK,
		FOREST_BRANCH_BREAKING,
		FOREST_BRANCH_BROKEN,
		FOREST_BRANCH_STILL,
		};	

#define FOR_NUM_OFFSETS						(10)
#define FOR_NUM_SWARM_SPRITES				(3)
#define FOR_NUM_SWARM_SPRITES_MULTIPLAYER	(1)
#define	FOR_SWARM_SIN_SPEED					(7)
#define	FOR_SWARM_SHIFT						(9)
#define	FOR_SWARM_CENTER_PITCH				(72)
#define	FOR_SWARM_PITCH_MOD					(8)

enum	{
		FOREST_SWAY_BRANCH_WAITING,
		FOREST_SWAY_BRANCH_SWAYING,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __forest_hive				FOREST_HIVE;
typedef struct __forest_rt_hive				FOREST_RT_HIVE;
typedef struct __forest_rt_swarm			FOREST_RT_SWARM;
typedef struct __forest_falling_leaf		FOREST_FALLING_LEAF;
typedef struct __forest_rt_falling_leaf		FOREST_RT_FALLING_LEAF;
typedef struct __forest_swaying_branch		FOREST_SWAYING_BRANCH;
typedef struct __forest_rt_swaying_branch	FOREST_RT_SWAYING_BRANCH;
typedef struct __forest_breaking_branch		FOREST_BREAKING_BRANCH;
typedef struct __forest_rt_breaking_branch	FOREST_RT_BREAKING_BRANCH;
typedef struct __forest_hedgehog			FOREST_HEDGEHOG;
typedef struct __forest_rt_hedgehog			FOREST_RT_HEDGEHOG;
typedef struct __forest_squirrel			FOREST_SQUIRREL;
typedef struct __forest_rt_squirrel			FOREST_RT_SQUIRREL;

struct __forest_rt_swarm
	{
	MR_VOID*				sw_frog;				// Ptr to frog being chased (void* to avoid header include probs)
	MR_VOID*				sw_api_item0;			// Ptr to PGEN
	MR_VOID*				sw_api_insts[4];		// Ptr to api insts
	MR_LONG					sw_voice_id;			// Voice id
	MR_LONG					sw_speed;				// Speed at which swarm moves
	MR_ULONG				sw_delay;				// Delay count
	MR_MAT					sw_matrix;				// Matrix
	MR_SVEC					sw_positions[FOR_NUM_SWARM_SPRITES];
//	MR_ULONG				sw_curr_offset[FOR_NUM_SWARM_SPRITES];
//	MR_VEC*					sw_offset_table[FOR_NUM_SWARM_SPRITES];
	MR_LONG					sw_ofs_angle[FOR_NUM_SWARM_SPRITES];

	};	//FOREST_RT_SWARM

struct __forest_hive
	{	
	MR_MAT					hv_matrix;				// matrix of entity
	MR_LONG					hv_release_distance;	// How close does Frogger get before swarm comes out.
	MR_LONG					hv_swarm_speed;			// How fast when released?
	};	//FOREST_HIVE

struct __forest_rt_hive
	{
	FOREST_RT_SWARM			hv_swarm;				// swarm entity when its released
	MR_LONG					hv_voice_id;			// Voice id
	MR_USHORT				hv_state;				// State
	MR_USHORT				hv_pad;					// Pad
	};	//FOREST_RT_HIVE

struct __forest_falling_leaf
	{	
	MR_MAT					fl_matrix;				// matrix of entity
	MR_USHORT				fl_fall_speed;			// Falling speed (path based)
	MR_USHORT				fl_sway_duration;		// Time take to sway from side to side
	MR_USHORT				fl_sway_angle;			// Angle leaf sways through
	MR_USHORT				fl_pad;					// Pad
	};	// FOREST_FALLING_LEAF

struct __forest_rt_falling_leaf
	{
	MR_SHORT				fl_curr_displacement;	// Current displacement from center
	MR_USHORT				fl_curr_dir;			// Current direction (of rotation)
	MR_USHORT				fl_speed;				// Speed
	MR_USHORT				fl_angle_divider;		// Angle divider
	};	// FOREST_RT_FALLING_LEAF


struct __forest_swaying_branch
	{	
	MR_MAT					sb_matrix;				// matrix of entity
	MR_USHORT				sb_sway_angle;			// Angle of sway
	MR_USHORT				sb_sway_duration;		// Duration of sway
	MR_USHORT				sb_once_off_delay;		// Once of delay
	MR_USHORT				sb_pad;					// Pad
	};	// FOREST_SWAYING_BRANCH

struct __forest_rt_swaying_branch
	{
	MR_SHORT				sb_curr_displace;		// Current displacement from center
	MR_USHORT				sb_curr_dir;			// Current movement (sway) direction
	MR_USHORT				sb_speed;				// Speed of rotation
	MR_USHORT				sb_angle_divider;		// Angle divider...
	MR_USHORT				sb_timer;				// Timer
	MR_USHORT				sb_mode;				// Mode
	MR_VEC					sb_rotation;			// Rotation
	};	// FOREST_RT_SWAYING_BRANCH

struct __forest_breaking_branch
	{	
	MR_MAT					bb_matrix;				// matrix of entity
	MR_USHORT				bb_break_delay;			// Delay before break happens
	MR_USHORT				bb_fall_speed;			// Falling speed
	};	// FOREST_BREAKING_BRANCH

struct __forest_rt_breaking_branch
	{
	MR_USHORT				bb_break_count;			// Count before break happens
	MR_USHORT				bb_action;				// Current action (ok or breaking)
	MR_LONG					bb_voice_id;			// Voice id
	MR_SVEC					bb_rot;					// rotation of falling branch
	MR_LONG					bb_fall_height;			// Fall height
	MR_LONG					bb_fall_speed;			// Fall speed
	};	// FOREST_RT_BREAKING_BRANCH


struct __forest_squirrel
	{
	PATH_INFO				sq_path_info;			// Standard path setup info
	MR_LONG					sq_turn_duration;		// Time taken to turn at end of path
	};	// FOREST_SQUIRREL


struct __forest_rt_squirrel
	{
	MR_USHORT				sq_animation_delay;		// animation delay (precalced at create time)
	MR_USHORT				sq_action;				// current action
	};		// FG_SQUIRREL

struct __forest_hedgehog
	{
	PATH_INFO				hh_path_info;			// Standard path setup info
	MR_USHORT				hh_run_time;			// Time to run
	MR_USHORT				hh_roll_time;			// Roll time
	MR_USHORT				hh_run_speed;			// Run speed
	MR_USHORT				hh_roll_speed;			// Roll speed
	};	// FOREST_HEDGEHOG


struct __forest_rt_hedgehog
	{
	MR_USHORT				hh_action;				// current action
	MR_USHORT				hh_count;				// counter to actions
	};		// FG_HEDGEHOG

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define FOREST_HEDGEHOG_START_RUNNING(a, b, c)													\
		LiveEntitySetAction(a, FOREST_HEDGEHOG_RUNNING);										\
		(b)->hh_action								= FOREST_HEDGEHOG_RUNNING;					\
		(b)->hh_count								= (c)->hh_run_time;							\
		(a)->le_entity->en_path_runner->pr_speed 	= (c)->hh_run_speed;						\

#define FOREST_HEDGEHOG_START_ROLLING(a, b, c)													\
		LiveEntitySetAction(a, FOREST_HEDGEHOG_ROLLING);										\
		(b)->hh_action								= FOREST_HEDGEHOG_ROLLING;					\
		(b)->hh_count								= (c)->hh_roll_time;						\
		(a)->le_entity->en_path_runner->pr_speed 	= (c)->hh_roll_speed;						\

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern MR_ULONG					Forest_swarm_animlist[];
extern MR_ULONG					Forest_swarm_collide_forms[];
extern COLL_VISIBILITY_INFO		Forest_swarm_vis_info;
extern COLL_VISIBILITY_DATA		Forest_swarm_vis_data[];
extern MR_VEC					Forest_swarm_offsets1[];
extern MR_VEC					Forest_swarm_offsets2[];
extern MR_LONG					script_for_squirrel[];
extern MR_LONG					script_for_squirrel_sfx[];
extern MR_LONG					script_for_owl[];
extern MR_LONG					script_for_owl_sfx[];
extern MR_LONG					script_for_river_noise[];
extern MR_LONG					script_for_swan[];
extern MR_LONG					script_for_swan_sfx[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	ENTSTRForCreateHive(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateHive(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForKillHive(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRForCreateFallingLeaf(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateFallingLeaf(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRForCreateSwayingBranch(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateSwayingBranch(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRForCreateBreakingBranch(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateBreakingBranch(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRForCreateHedgehog(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateHedgehog(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRForCreateSquirrel(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForUpdateSquirrel(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRForKillSquirrel(LIVE_ENTITY*);

extern	MR_VOID ENTSTRHiveResetSwarm(FOREST_RT_HIVE*, LIVE_ENTITY*);

#endif	//__ENT_FOR_H
