/******************************************************************************
*%%%% hud.h
*------------------------------------------------------------------------------
*
*	In-game overlay stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__HUD_H
#define	__HUD_H

#include "mr_all.h"
#include "gamesys.h"


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// HUD_ITEM types
enum	{
		HUD_ITEM_NULL,
		HUD_ITEM_SCORE,
		HUD_ITEM_TIMER,
		HUD_ITEM_HELP,
		HUD_ITEM_CHECKPOINTS,
		HUD_ITEM_LIVES,
		HUD_ITEM_LEVEL_START_GATHER,
		HUD_ITEM_LEVEL_START_TIMER,
		HUD_ITEM_LEVEL_START_SCATTER,
		HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT,
		HUD_ITEM_TRIGGER_RETURN_CHECKPOINT,
		HUD_ITEM_BITMAP,
		HUD_ITEM_LEVEL_BONUS,
		HUD_ITEM_EMPTY,
		HUD_ITEM_LEVEL_TIME,
		HUD_ITEM_GOLD_FROG,
		};

// HUD_ITEM_HELP types
enum	{
		HUD_ITEM_HELP_SUPERJUMP,
		HUD_ITEM_HELP_TONGUE,
		HUD_ITEM_HELP_CROAK,
		HUD_ITEM_HELP_COLLISION_ON,
		HUD_ITEM_HELP_COLLISION_OFF,
		HUD_ITEM_HELP_TIMER_ON,
		HUD_ITEM_HELP_TIMER_OFF,
		HUD_ITEM_HELP_INFINITE_LIVES_ON,
		HUD_ITEM_HELP_INFINITE_LIVES_OFF,
		HUD_ITEM_HELP_POLYGON_WARNING,
		HUD_ITEM_HELP_ALL_LEVELS_OPEN,
		HUD_ITEM_HELP_ALL_ZONES_OPEN,
		HUD_ITEM_HELP_COLLECT_CHECKPOINT,
		HUD_ITEM_HELP_COLLECT_GOLDFROG,
		HUD_ITEM_HELP_SUPER_TONGUE,
		HUD_ITEM_HELP_AUTO_HOP,
		HUD_ITEM_HELP_QUICK_JUMP,
		HUD_ITEM_HELP_SUPER_LIGHT,
		HUD_ITEM_HELP_LOSE_TIME,
		HUD_ITEM_HELP_TOTAL,
		};

// Moving HUD modes
enum	{
		HUD_ITEM_ANIM_DELAY,
		HUD_ITEM_ANIM_UPDATE,
		HUD_ITEM_ANIM_FINISHED,
		};

enum	{
		HUD_ITEM_BONUS_COUNT_UP,
		HUD_ITEM_BONUS_COUNT_ADD,
		};

// HUD_ITEM flags
#define	HUD_ITEM_FLIPPED								(1<<0)
#define	HUD_ITEM_FADE_UP								(1<<1)
#define	HUD_ITEM_HOLD									(1<<2)
#define	HUD_ITEM_FADE_DOWN								(1<<3)
#define	HUD_ITEM_PREDELAY								(1<<4)
#define	HUD_ITEM_REBUILD								(1<<5)
#define HUD_ITEM_FINISHED								(1<<6)
#define HUD_ITEM_NO_UPDATE								(1<<7)

// HUD_ITEM defines
#define	HUD_ITEM_FADE_DURATION							16
#define	HUD_ITEM_HOLD_DURATION							24

#define	HUD_ITEM_SCORE_LIFETIME							60
#define	HUD_ITEM_HELP_WIDTH								160

#define	HUD_ITEM_TIMER_WIDTH							120
#define	HUD_ITEM_TIMER_HEIGHT							8
#define	HUD_ITEM_TIMER_MAX_TIME							(75 * 30)		// max timer bar time in frames
#define	HUD_ITEM_TIMER_DIGIT_TIME						10				// time (seconds) at which digits appear

#define	HUD_ITEM_LIVES_MAX_ICONS						5				// maximum lives icons
#define	HUD_ITEM_LIVES_BIG_VALUE						3				// big icon is worth n small icons

#define	HUD_MAX_BONUS_DIGITS							5				// Max digits in BONUS points hud item

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

typedef struct	__hud_item					HUD_ITEM;
typedef struct __hud_checkpoint_anim_info	HUD_CHECKPOINT_ANIM_INFO;


struct	__hud_item
	{
	MR_USHORT	hi_type;		// eg. HUD_ITEM_SCORE
	MR_SHORT	hi_x;			// of top left of item within viewport
	MR_SHORT	hi_y;			// of top left of item within viewport
	MR_USHORT	hi_flags;		// eg. HUD_ITEM_FLIPPED
	MR_USHORT	hi_timer;		//
	MR_VOID*	hi_extra;		// eg. algorithm canvas
	MR_TEXTURE*	hi_texture;		// ptr to texture to use
	MR_UBYTE*	hi_polys[2];	// double-buffered specific poly ptrs
	MR_VOID*	hi_api_0;		// eg. MR_OBJECT* or MR_TEXT_AREA*
	MR_VOID*	hi_api_1;		// eg. MR_OBJECT* or MR_TEXT_AREA*
	MR_VOID*	hi_api_2;		// eg. MR_OBJECT* or MR_TEXT_AREA*
	};	// HUD_ITEM

struct __hud_checkpoint_anim_info
	{
	MR_SHORT	hc_start_x;			// start x (top left of item within viewport)
	MR_SHORT	hc_start_y;			// start y
	MR_LONG		hc_velocity_x;		// velocity x
	MR_LONG		hc_velocity_y;		// velocity y
	MR_SHORT	hc_timer;			// frames to add velocity
	MR_SHORT	hc_initial_delay;	// delay before moving
	MR_SHORT	hc_anim_timer;		// Timer for complex anim/movements
	MR_SHORT	hc_mode;			// Current mode
	MR_LONG		hc_pos_x;			// pos x
	MR_LONG		hc_pos_y;			// pos y
	}; // HUD_CHECKPOINT_ANIM_INFO

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------

extern	MR_USHORT					Hud_item_help_flags[SYSTEM_MAX_VIEWPORTS][HUD_ITEM_HELP_TOTAL];
extern	MR_ULONG					Hud_bonus_score;

extern	MR_UBYTE					Hud_digits[10];

extern	MR_TEXTURE*					Hud_timer_images[];
extern	MR_TEXTURE*					Hud_score_images[];

extern	MR_ULONG*					Hud_checkpoint_animlists[];
extern	HUD_CHECKPOINT_ANIM_INFO	Hud_checkpoint_anim_gather[];
extern	HUD_CHECKPOINT_ANIM_INFO	Hud_checkpoint_anim_split[];
extern	HUD_ITEM					HUD_script_start_level[];
extern	HUD_ITEM					HUD_script_trigger_collected[];
extern	HUD_ITEM					HUD_script_gold_frog[];


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			InitialiseHUD(MR_VOID);
extern	MR_VOID			DeinitialiseHUD(MR_VOID);
extern	MR_VOID			StartHUD(MR_VOID);
extern	MR_VOID			UpdateHUD(MR_VOID);

extern	HUD_ITEM*		SetupHUDScript(HUD_ITEM*, MR_ULONG);
extern	MR_VOID			UpdateHUDScript(HUD_ITEM*, MR_ULONG);
extern	MR_VOID			ResetHUDScript(HUD_ITEM*);
extern	MR_VOID			KillHUDScript(HUD_ITEM*);

// This function probably doesn't have a prototype defined in the original, since functions that call it treat the last argument as a MR_LONG (the default type used if there is no prototype)
//extern	MR_VOID			DisplayHUDHelp(MR_ULONG, MR_ULONG, MR_BOOL, MR_USHORT);

extern	MR_VOID			HUDGetDigits(MR_ULONG, MR_ULONG*, MR_ULONG*, MR_ULONG*);

extern	MR_VOID			InitialiseMultiplayerHUDbackgrounds(MR_VOID);
extern	MR_VOID			DeinitialiseMultiplayerHUDbackgrounds(MR_VOID);
extern	MR_VOID			UpdateMultiplayerHUDbackgrounds(MR_VOID);

#endif	//__HUD_H

















