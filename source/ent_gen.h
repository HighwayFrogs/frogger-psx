/******************************************************************************
*%%%% ent_gen.h
*------------------------------------------------------------------------------
*
*	General Create/Update/Kill Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	19.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_GEN_H
#define	__ENT_GEN_H

#include "mr_all.h"
#include "entity.h"
#include "frog.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Bonus fly animlist types.
enum	{
		GEN_FLY_10,	   
		GEN_FLY_25,
		GEN_FLY_50,
		GEN_FLY_100,
		GEN_FLY_200,
		GEN_FLY_500,
		GEN_FLY_1000,
		GEN_FLY_5000,
		GEN_GLOW_WORM,	   
		GEN_FAT_FIRE_FLY,
		GEN_FLY_MIN,	   
		GEN_FLY_MED,
		GEN_FLY_MAX,
		GEN_BLACK0_FLY,	   
		GEN_BLACK1_FLY,	   
		GEN_EXTRA_LIFE,	   
		GEN_SUPER_TONGUE, 
		GEN_QUICK_JUMP,   
		GEN_AUTO_HOP,	   
		};

// Bonus fly defines
#define	GEN_BONUS_FLY_OT_OFFSET				0

// Used to control the gen_fly_buzz.
#define	GEN_FLY_SIN_SPEED		(8)
#define	GEN_FLY_SHIFT			(8)
#define	GEN_FLY_CENTER_PITCH	(64)
#define	GEN_FLY_PITCH_MOD		(8)

											
// Check point defines						
#define GEN_CHECKPOINT_1					(1<<0)
#define GEN_CHECKPOINT_2					(1<<1)
#define GEN_CHECKPOINT_3					(1<<2)
#define GEN_CHECKPOINT_4					(1<<3)
#define GEN_CHECKPOINT_5					(1<<4)
#define GEN_CHECKPOINT_NO_HUD_UPDATE		(1<<5)											

#define GEN_ALL_CHECKPOINTS					(GEN_CHECKPOINT_1 | GEN_CHECKPOINT_2 | GEN_CHECKPOINT_3 | GEN_CHECKPOINT_4 | GEN_CHECKPOINT_5)
#define GEN_MAX_CHECKPOINTS					(5)

// Check point flags
#define GEN_CHECKPOINT_IS_COVERED			(1<<0)			// Check point already covered by another entity

// Gold frog defines						
#define GEN_GOLD_FROG_1						(1<<0)
#define GEN_GOLD_FROG_2						(1<<0)
#define GEN_GOLD_FROG_3						(1<<0)
#define GEN_GOLD_FROG_4						(1<<0)
#define GEN_GOLD_FROG_5						(1<<0)
#define GEN_GOLD_FROG_6						(1<<0)
#define GEN_GOLD_FROG_7						(1<<0)
#define GEN_GOLD_FROG_8						(1<<0)

#define GEN_ALL_GOLD_FROGS					(GEN_GOLD_FROG_1 | GEN_GOLD_FROG_2 | GEN_GOLD_FROG_3 | GEN_GOLD_FROG_4 | GEN_GOLD_FROG_5 | GEN_GOLD_FROG_6 | GEN_GOLD_FROG_7 | GEN_GOLD_FROG_8)

// Modes of operation for Checkpoints
enum
	{
	CHECKPOINT_MODE_WAITING,
	CHECKPOINT_MODE_INFLATE,
	CHECKPOINT_MODE_DEFLATE,
	CHECKPOINT_MODE_JUMP,
	};

// Gold frog
enum 
	{
	GEN_GOLD_FROG_WAITING,
	GEN_GOLD_FROG_JUMPING,
	GEN_GOLD_FROG_FINISHED,
	};

#define	GEN_GOLD_FROG_JUMP_SPEED			(-256)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__gen_checkpoint		GEN_CHECKPOINT;
typedef	struct	__gen_bonus_fly			GEN_BONUS_FLY;
typedef	struct	__gen_checkpoint_data	GEN_CHECKPOINT_DATA;
typedef	struct	__gen_gold_frog_data	GEN_GOLD_FROG_DATA;
typedef	struct	__gen_gold_frog			GEN_GOLD_FROG;
typedef	struct	__gen_rt_gold_frog		GEN_RT_GOLD_FROG;

struct	__gen_checkpoint
	{
	MR_MAT			cp_matrix;
	MR_USHORT		cp_id;
	MR_USHORT		cp_pad;
	};	// GEN_CHECKPOINT


struct __gen_checkpoint_data
	{
	MR_LONG			cp_flags;					// Various flags
	MR_LONG			cp_frog_collected_id;		// Id of frog that hit checkpoint
	MR_SVEC			cp_position;				// Position of check point in world
	MR_ULONG		cp_time;					// Time taken to get to check point
	ENTITY*			cp_entity;					// Ptr to check point entity
	MR_ULONG		cp_user_data;				// User data, used by entities for various purposes
	MR_ULONG		cp_croak_mode;				// eg. FROG_CROAK_NONE
	MR_ULONG		cp_croak_timer;				// counts down to 0 in each mode

	};	// GEN_CHECKPOINT_DATA


struct __gen_gold_frog_data
	{
	MR_LONG			gf_flags;					// Various flags
	MR_LONG			gf_frog_collected_id;		// Id of frog that hit checkpoint (probably not needed)
	MR_SVEC			gf_position;				// Position of check point in world
	MR_ULONG		gf_time;					// Time taken to get to check point
	ENTITY*			gf_entity;					// Ptr to check point entity
	MR_ULONG		gf_user_data;				// User data, used by entities for various purposes
	MR_ULONG		gf_croak_mode;				// eg. FROG_CROAK_NONE
	MR_ULONG		gf_croak_timer;				// counts down to 0 in each mode
	};	// GEN_GOLD_FROG_DATA


struct	__gen_bonus_fly
	{
	MR_MAT			bf_matrix;
	MR_USHORT		bf_type;
	MR_USHORT		bf_pad;

	};	// GEN_BONUS_FLY

struct	__gen_gold_frog
	{
	MR_MAT			cp_matrix;
	};	// GEN_GOLD_FROG


struct __gen_rt_gold_frog
	{
	MR_LONG			gf_mode;					// Gold frog mode (see enum list)
	MR_VOID*		gf_hud_script;				// ptr to HUD script (or NULL), used for fancy effects
	MR_VOID*		gf_api_item;				// Glow particle effect
	MR_VOID*		gf_api_insts[4];			// 
	};

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_TEXTURE**			Pickup_data[];
extern	MR_ULONG				Bonus_fly_scores[];
extern	MR_ULONG				Checkpoints;
extern	MR_ULONG				Checkpoint_last_collected;
extern	GEN_CHECKPOINT_DATA		Checkpoint_data[];
extern	MR_ULONG				Gold_frogs;				// Gold frogs collected in all games (saved to cart)
extern	MR_ULONG				Gold_frogs_current;		// Gold frogs collected in current game (flushed on game-start)
extern	MR_ULONG				Gold_frogs_zone;		// Gold frogs collected in current game-zone (flushed on game-start)
extern	GEN_GOLD_FROG_DATA		Gold_frog_data;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID 	InitialiseCheckPoints(MR_VOID);

extern	MR_VOID		ENTSTRGenCreateBonusFly(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenUpdateBonusFly(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenKillBonusFly(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRGenCreateCheckPoint(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenUpdateCheckPoint(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenKillCheckPoint(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRGenCreateMultiPoint(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenUpdateMultiPoint(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenKillMultiPoint(LIVE_ENTITY*);

extern	MR_VOID		GenBlockCollPrimCallback(MR_VOID*, MR_VOID*, MR_VOID*);
extern	MR_VOID		GenButterFlyCallBack(MR_VOID*, MR_VOID*, MR_VOID*);
extern	MR_VOID 	GenBlockWaterFallCollPrimCallback(MR_VOID*, MR_VOID*, MR_VOID*);
extern	MR_VOID 	GenBlockFallCollPrimCallback(MR_VOID*, MR_VOID*, MR_VOID*);

extern	MR_VOID		ENTSTRGenCreateTopLeft(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenCreateBottomRight(LIVE_ENTITY*);

extern	MR_VOID		ENTSTRGenCreateGoldFrog(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenUpdateGoldFrog(LIVE_ENTITY*);
extern	MR_VOID		ENTSTRGenKillGoldFrog(LIVE_ENTITY*);

#endif	//__ENT_GEN_H
