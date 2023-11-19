/******************************************************************************
*%%%% ent_jun.h
*------------------------------------------------------------------------------
*
*	Jungle entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_JUN_H
#define	__ENT_JUN_H

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum	{
		JUN_PLANT_WAITING,
		JUN_PLANT_WAITING_TO_SNAP,
		JUN_PLANT_SNAPPING,
		JUN_PLANT_DELAY_AFTER_SNAPPING,
		};

#define	JUN_PLANT_HIT_DISTANCE						(256+100)		// 50 + plus one grid square
#define GAME_END_GOLD_FROG_DELAY					(30)
#define GAME_END_MAX_PLINTHS						(8)
#define GAME_END_MAX_PLINTH_RAISE_TIME				(2*30)
#define GAME_END_MAX_PLINTH_RAISE_DISTANCE			(256*2)
#define GAME_END_MAX_GOLD_FROG_JUMPS				(13)
#define GAME_END_PLINTH_TIME_FROG_SWITCH			(GAME_END_MAX_PLINTH_RAISE_TIME>>1)
#define GAME_END_PLINTH_TIME_FROG_SWITCH_PARTICLE	((GAME_END_MAX_PLINTH_RAISE_TIME>>1)+15)
#define GAME_END_FIRST_DOOR_TARGET					(0)
#define GAME_END_LAST_DOOR_TARGET					(9)


enum	{											
		JUN_ROPE_BRIDGE_WAITING_FOR_HITS,
		JUN_ROPE_BRIDGE_WAITING_TO_FALL,
		JUN_ROPE_BRIDGE_FALLING,
		};

// The following are FORM ID's 
#define	JUN_OUTRO						(58)
#define	JUN_OUTRO_DOOR					(59)
#define	JUN_OUTRO_STATUE				(60)
#define	JUN_OUTRO_PLINTH				(61)
#define	JUN_OUTRO_GOLD_DOOR				(62)
#define	JUN_OUTRO_GOLD_FROG				(63)
#define JUN_OUTRO_STONE_FROG			(64)

// Following is gold frog statue id (0->7 are plinth gold frog id's)
#define JUN_GOLD_FROG_STATUE_ID			(8)
#define JUN_STONE_FROG_STATUE_ID		(8)

enum	{
		JUN_GOLD_FROG_SITTING,
		JUN_GOLD_FROG_JUMPING,
		};

#define GAME_OUTRO_FADE_DURATION		(60)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct	__jun_plant						JUN_PLANT;
typedef struct	__jun_rt_plant					JUN_RT_PLANT;
typedef	struct	__jun_rt_rope_bridge			JUN_RT_ROPE_BRIDGE;
typedef	struct	__jun_rope_bridge				JUN_ROPE_BRIDGE;
typedef struct	__jun_outro_targets				JUN_OUTRO_TARGETS;
typedef struct	__jun_outro_entity				JUN_OUTRO_ENTITY;
typedef struct	__jun_outro_frogplinth_data		JUN_OUTRO_FROGPLINTH_DATA;
typedef struct	__jun_outro_data				JUN_OUTRO_DATA;
typedef struct	__jun_outro_rt_gold_frog		JUN_OUTRO_RT_GOLD_FROG;

struct __jun_plant
	{
	MR_MAT			jp_matrix;				// matrix of entity
	MR_SHORT		jp_snap_time;			// time taken to snap to frogger
	MR_SHORT		jp_snap_delay;			// delay before resnapping
	};	// JUN_PLANT

struct __jun_rt_plant
	{
	MR_SHORT		jp_mode;				// plant mode (snapping, delaying, etc)
	MR_SHORT		jp_timer;				// timer
	MR_LONG			jp_snap_timer;			// snap cooldown
	};	// JUN_RT_PLANT

struct	__jun_rope_bridge
	{
	MR_MAT			rb_matrix;				// Matrix of entity
	MR_USHORT		rb_fall_delay;			// Time before the crack opens.	
	MR_USHORT		rb_hops_before;			// Number of time it can be landed before it triggers.
	};	// JUN_ROPE_BRIDGE

struct __jun_rt_rope_bridge
	{
	MR_USHORT		rb_current_wait;		// Before it falls.
	MR_UBYTE		rb_state;				// What are we doing??
	MR_UBYTE		rb_num_hits;			// How many times have we been hit??
	};	// JUN_RT_ROPE_BRIDGE

struct __jun_outro_targets
	{
	MR_SVEC					ot_target;			// Target position
	MR_ULONG				ot_time;			// Time to reach target
	}; // JUN_OUTRO_TARGETS

struct	__jun_outro_entity
	{
	MR_MAT					oe_matrix;
	JUN_OUTRO_TARGETS		oe_targets[11];
	}; // JUN_OUTRO_ENTITY

struct __jun_outro_data
	{
	MR_ULONG				od_mode;					// mode 
	ENTITY*					od_entity;					// controller entity 
	LIVE_ENTITY*			od_live_entity;				// secondary live_entities which are controlled on screen for effects
	LIVE_ENTITY*			od_live_entity1;			// secondary live_entities which are controlled on screen for effects
	LIVE_ENTITY*			od_live_entity2;			// secondary live_entities which are controlled on screen for effects
	MR_VEC					od_velocity;				// velocity to move camera etc
	MR_VEC					od_target;					// Target position
	MR_VEC					od_position;				// Current position
	MR_LONG					od_counter;					// Counter
	MR_LONG					od_plinth;					// Plinth counter
	MR_OBJECT*				od_effect;					// Special effects
	MR_VOID*				od_pop;						// Pop effect
	}; // JUN_OUTRO_DATA

struct __jun_outro_frogplinth_data
	{
	MR_MAT					op_matrix;					// Matrix of entity
	MR_LONG					op_id;
	}; // JUN_OUTRO_FROGPLINTH_DATA

struct __jun_outro_rt_gold_frog
	{
	MR_SHORT				op_mode;					// Jumping or whatever
	MR_SHORT				op_counter;					// Jump counter
	MR_VEC					op_velocity;				// Velocity
	MR_VEC					op_target;					// Target position
	MR_LONG					op_direction;				// Direction
	MR_OBJECT*				op_object;
	}; // JUN_OUTRO_RT_GOLD_FROG

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_jun_floating_tree_moving[];
extern	MR_LONG		script_jun_floating_tree[];
extern	MR_LONG		script_jun_hippo[];
extern	MR_LONG		script_jun_hippo_no_dive[];
extern	MR_LONG		script_jun_water_noise[];
extern	MR_LONG		script_jun_monkey[];\
extern	MR_LONG		script_jun_monkey_sfx[];
extern	MR_LONG		script_jun_monkey_scream_sfx[];
extern	MR_LONG		script_jun_crocodile[];
extern	MR_LONG		script_jun_hippo_sfx[];
extern	MR_LONG		script_jun_scorpion[];
extern	MR_LONG		script_jun_rhino[];
extern	MR_LONG		script_jun_rhino_sfx[];
extern	MR_LONG		script_jun_piranaha[];

extern	MR_LONG		Jun_outro_frog_jumps[13];
extern	MR_LONG		Jun_outro_gold_frog_jumps[9][13];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			ENTSTRJunCreatePlant(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunUpdatePlant(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreateRopeBridge(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunUpdateRopeBridge(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreateHippo(LIVE_ENTITY*);
extern	MR_VOID			ScriptCBJunHippoDive(LIVE_ENTITY*);
extern	MR_VOID			ScriptCBJunHippoHit(LIVE_ENTITY*);
extern	MR_VOID			ScriptCBJunPiranaha(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreateGoldFrog(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunUpdateGoldFrog(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunKillGoldFrog(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreatePlinth(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreateStatue(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunUpdateStatue(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunKillStatue(LIVE_ENTITY*);
						
extern	MR_VOID			ENTSTRJunCreateOutroDoor(LIVE_ENTITY*);

extern	MR_VOID			JunJumpGoldFrog(LIVE_ENTITY*, MR_LONG, MR_LONG);
extern	LIVE_ENTITY*	JunFindEntity(MR_LONG, MR_LONG);

extern	MR_VOID			ENTSTRJunCreateBouncyMushroom(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunUpdateBouncyMushroom(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRJunKillBouncyMushroom(LIVE_ENTITY*);

extern	MR_VOID			ENTSTRJunCreateScorpion(LIVE_ENTITY*);

#endif	//__ENT_JUN_H
