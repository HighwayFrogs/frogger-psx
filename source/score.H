/******************************************************************************
*%%%% score.h
*------------------------------------------------------------------------------
*
*	Score stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__SCORE_H
#define	__SCORE_H

#include "mr_all.h"
#include "frog.h"


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Score equates
enum	{
		SCORE_5,
		SCORE_10,
		SCORE_25,
		SCORE_50,
		SCORE_75,
		SCORE_100,
		SCORE_150,
		SCORE_200,
		SCORE_250,
		SCORE_500,
		SCORE_1000,
		SCORE_5000,

		LIGHT_5,				
		LIGHT_8,				
		ADD_SUPER_LIGHT,

		TIME_MIN,				
		TIME_MED,
		TIME_MAX,

		REDUCE_SCORE_100,		

		ADD_TIMER_SPEED,

		ADD_EXTRA_LIFE,
		ADD_SUPER_TONGUE,
		ADD_QUICK_JUMP,
		ADD_AUTO_HOP,
		};

#define	SCORE_SPRITE_LIFETIME				30

// Score flags
#define	SCORE_FLAG_SCORE				(1<<0)		// this gives us points
#define	SCORE_FLAG_LIGHT				(1<<1)		// this gives us light
#define SCORE_FLAG_TIME					(1<<2)		// this gives us time.
#define SCORE_FLAG_REDUCE_SCORE			(1<<3)		// remove this from score.
#define	SCORE_FLAG_ADD_EXTRA_LIFE		(1<<4)		// this gives us an extra life.
#define	SCORE_FLAG_POWERUP				(1<<5)		// this enables the POWERUP passed

// Score defines
#define	FROG_LIFE_AWARD_SCORE			(10000)	// Points needed before an extra life is awarded
#define	FROG_TIMER_BONUS_SCORE			(100)	// Points for each second left at the end of the level.

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

typedef	struct	__score_sprite	SCORE_SPRITE;
typedef	struct	__score_book	SCORE_BOOK;

struct	__score_sprite
	{
	SCORE_SPRITE*	ss_next;
	SCORE_SPRITE*	ss_prev;
	MR_2DSPRITE*	ss_2dsprite;				// ptr to created API sprite
	MR_LONG			ss_x;						// fractional screen x
	MR_LONG			ss_y;						// fractional screen y
	MR_LONG			ss_vx;						// fractional screen x vel
	MR_LONG			ss_vy;						// fractional screen y vel
	MR_XY			ss_xy;						// actual MR_XY structure for API sprite
	MR_USHORT		ss_timer;					// counts down to 0
	MR_USHORT		ss_pad;
	MR_CVEC			ss_colour;					// start colour of sprite

	};		// SCORE_SPRITE

struct	__score_book
	{
	MR_ULONG		sb_value;					// actual score value
	MR_TEXTURE*		sb_texture;					// texture
	MR_ULONG		sb_flags;					// flags

	};		// SCORE_BOOK


//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

#define	ADD_FROG_SCORE(a, b) \
		(a)->fr_old_score	= (a)->fr_score, \
		(a)->fr_score 		+= (b), \
		((a)->fr_hud_script + HUD_ITEM_SCORE - 1)->hi_flags |= HUD_ITEM_REBUILD

#define ADD_FROG_LIGHT(a,b) \
		Map_light_max_r2	+= ((b)->sb_value<<16), \
		Map_light_min_r2	+= ((b)->sb_value<<16)

#define ADD_FROG_TIME(a,b) 	\
		Game_map_timer		+= (b)

// IMPORTANT WARNING.. $mk 
// Only call the following macro in single player mode!
#define ADD_FROG_EXTRA_LIFE(a,b) \
		(a)->fr_lives 		+= (b), \
		((a)->fr_hud_script + HUD_ITEM_LIVES - 1)->hi_flags |= HUD_ITEM_REBUILD

#define ADD_FROG_POWERUP(a,b) \
		(a)->fr_powerup_flags		|= (b)

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			InitialiseScoreSprites(MR_VOID);
extern	SCORE_SPRITE*	CreateScoreSprite(MR_SHORT,	MR_SHORT, MR_TEXTURE*, MR_VIEWPORT*);
extern	MR_VOID			UpdateScoreSprites(MR_VOID);
extern	SCORE_SPRITE*	AddFrogScore(FROG*, MR_ULONG, MR_MAT*);
extern	MR_VOID			AddFrogPoints(FROG*, MR_LONG);

#endif	//__SCORE_H



