/******************************************************************************
*%%%% froganim.h
*------------------------------------------------------------------------------
*
*	Frog animation code and equates
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__FROGANIM_H
#define	__FROGANIM_H

#include "mr_all.h"
#include "frog.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------
//#define	FROG_TEX_ANIMATION

// FROG_ANIM_INFO flags
#define	FROG_ANIM_ACTIVE				(1<<0)		// Script is active
#define	FROG_ANIM_QUEUE					(1<<1)		// Script should queue itself and not interupt current script
#define	FROG_ANIM_BIN_IF_ANIM_PLAYING	(1<<2)		// Script should bin itself if an animation is playing (except pant)
#define	FROG_ANIM_OVERRIDE_PREV_ANIM	(1<<3)		// Script over override immediately any script playing
#define	FROG_ANIM_RESTORE_AFTER			(1<<4)		// When overridden, this script should back itself up to come back later
#define	FROG_ANIM_DO_NOT_OVERRIDE		(1<<5)		// When running, this script cannot be overridden until anim system is reinit'ed... useful for death anims

// Frog animation types
enum	{
		FROG_ANIM_TYPE_NORMAL,						// Normal animation (movement and suchlike)
		FROG_ANIM_TYPE_TEXTURE,						// Texture animation
		};

// Animation playback types
enum	{	
		FROGSCR_PLAYBACK_ONCE,
		FROGSCR_PLAYBACK_REPEATING,
		};

enum	{
		// Return types from script commands
		FROGSCR_RETURN_CONTINUE,					// Continue to the next command in the frog
		FROGSCR_RETURN_BREAK,						// Stop processing of commands for the frog
		FROGSCR_RETURN_END,							// End processing of scripts for the frog
		};


// Normal anim script command id's
enum	{
		FROGSCR_PLAY_ANIM,
		FROGSCR_SETLOOP,
		FROGSCR_ENDLOOP,
		FROGSCR_END,
		FROGSCR_HOLD,
		FROGSCR_WAIT_ANIM_FINISHED,
		FROGSCR_PLAY_SCRIPT_IF,
		FROGSCR_SET_TIMER,
		FROGSCR_WAIT_UNTIL_TIMER
		};

#ifdef FROG_TEX_ANIMATION
// Texture anim script command id's
enum	{
		FROGTEXSCR_PLAY_ANIM,
		FROGTEXSCR_SETLOOP,
		FROGTEXSCR_ENDLOOP,
		FROGTEXSCR_END,
		FROGTEXSCR_HOLD,
		FROGTEXSCR_WAIT_ANIM_FINISHED,
		FROGTEXSCR_PLAY_SCRIPT_IF,
		FROGTEXSCR_SET_TIMER,
		FROGTEXSCR_WAIT_UNTIL_TIMER,
		FROGTEXSCR_STOP_ANIM,
		};
#endif

// Conditional defines
enum	{
		FROGSCR_CONDITION_NO_INPUT,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct	froganim_play_anim			FROGANIM_PLAY_ANIM;
typedef struct	froganim_play_anim_if		FROGANIM_PLAY_ANIM_IF;
typedef struct	frogtexanim_play_anim		FROGTEXANIM_PLAY_ANIM;

struct	froganim_play_anim
	{
	MR_LONG		pa_play_back_type;
	MR_LONG		pa_delay_timer;
	MR_LONG		pa_action;
	}; //FROGANIM_PLAY_ANIM

struct	froganim_play_anim_if
	{
	MR_LONG		pai_condition;
	MR_LONG		pai_variable1;
	MR_LONG		pai_variable2;
	MR_LONG		pai_script_ids[4];
	}; //FROGANIM_PLAY_ANIM_IF

struct	frogtexanim_play_anim
	{
	MR_LONG		pa_play_back_type;
	MR_LONG		pa_action;
	}; //FROGANIM_PLAY_ANIM

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define FROG_ANIM_CLEAR_QUEUE(info)									\
				(info)->fi_queue_flags	= 0;						\
				(info)->fi_queue_type	= -1;						\
				(info)->fi_queue_script	= NULL;

#define FROG_ANIM_SET_QUEUE(info, equate, flags, script)			\
				(info)->fi_queue_flags	= flags;					\
				(info)->fi_queue_type	= equate;					\
				(info)->fi_queue_script	= script;

#define FROG_ANIM_APPLY_QUEUE(info, script)							\
				(info)->fi_flags		= (info)->fi_queue_flags;	\
				(info)->fi_type			= (info)->fi_queue_type;	\
				(info)->fi_script		= script;					

#define FROG_ANIM_CLEAR_PREVIOUS(info)								\
				(info)->fi_previous_flags	= 0;					\
				(info)->fi_previous_type	= -1;					\
				(info)->fi_previous_script	= NULL;

#define FROG_ANIM_SET_PREVIOUS(info)								\
				(info)->fi_previous_flags	= (info)->fi_flags;		\
				(info)->fi_previous_type	= (info)->fi_type;		\
				(info)->fi_previous_script	= (info)->fi_script;		

#define FROG_ANIM_APPLY_PREVIOUS(info, script)						\
				(info)->fi_flags		= (info)->fi_previous_flags;\
				(info)->fi_type			= (info)->fi_previous_type;	\
				(info)->fi_script		= script;			
			
#define FROG_ANIM_SET_SCRIPT(info, equate, anim, script)			\
				(info)->fi_flags	= anim->fa_flags;				\
				(info)->fi_type		= equate;						\
				(info)->fi_script	= script;
		
#ifdef FROG_TEX_ANIMATION

#define FROG_TEX_ANIM_CLEAR_QUEUE(info)								\
				(info)->ti_queue_flags	= 0;						\
				(info)->ti_queue_type	= -1;						\
				(info)->ti_queue_script	= NULL;

#define FROG_TEX_ANIM_SET_QUEUE(info, equate, anim)					\
				(info)->ti_queue_flags	= anim->ta_flags;			\
				(info)->ti_queue_type	= equate;					\
				(info)->ti_queue_script	= anim->ta_script;

#define FROG_TEX_ANIM_APPLY_QUEUE(info, anim)						\
				(info)->ti_flags		= (info)->ti_queue_flags;	\
				(info)->ti_type			= (info)->ti_queue_type;	\
				(info)->ti_script		= (anim)->ta_script;		\

#define FROG_TEX_ANIM_CLEAR_PREVIOUS(info)							\
				(info)->ti_previous_flags	= 0;					\
				(info)->ti_previous_type	= -1;					\
				(info)->ti_previous_script	= NULL;

#define FROG_TEX_ANIM_SET_PREVIOUS(info)							\
				(info)->ti_previous_flags	= (info)->ti_flags;		\
				(info)->ti_previous_type	= (info)->ti_type;		\
				(info)->ti_previous_script	= (info)->ti_script;		

#define FROG_TEX_ANIM_APPLY_PREVIOUS(info, anim)						\
				(info)->ti_flags		= (info)->ti_previous_flags;	\
				(info)->ti_type			= (info)->ti_previous_type;		\
				(info)->ti_script		= (anim)->ta_script;			
					
#define FROG_TEX_ANIM_SET_SCRIPT(info, equate, anim)			\
				(info)->ti_flags	= anim->ta_flags;			\
				(info)->ti_type		= equate;					\
				(info)->ti_script	= anim->ta_script;
#endif

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		(*Frog_animation_script_commands[])(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_ULONG	Frog_animation_script_command_lengths[];
extern	MR_LONG		(*Frog_tex_animation_script_commands[])(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_ULONG	Frog_tex_animation_script_command_lengths[];

extern	MR_LONG		froganim_scr_autohop[];
extern	MR_LONG		froganim_scr_backflip[];

extern	MR_LONG		froganim_scr_wait1[];
extern	MR_LONG		froganim_scr_wait2[];
extern	MR_LONG		froganim_scr_wait3[];
extern	MR_LONG		froganim_scr_wait4[];
extern	MR_LONG		froganim_scr_hop[];
extern	MR_LONG		froganim_scr_start_jump[];
extern	MR_LONG		froganim_scr_end_jump[];
extern	MR_LONG		froganim_scr_squished[];
extern	MR_LONG		froganim_scr_die_on_back[];
extern	MR_LONG		froganim_scr_timeout[];
extern	MR_LONG		froganim_scr_swim[];
extern	MR_LONG		froganim_scr_struggle[];
extern	MR_LONG		froganim_scr_freefall[];
extern	MR_LONG		froganim_scr_falling[];
extern	MR_LONG		froganim_scr_wait[];
extern	MR_LONG		froganim_scr_trigger[];
extern	MR_LONG		froganim_scr_drown[];
extern	MR_LONG		froganim_scr_complete[];
extern	MR_LONG		froganim_scr_bitten[];
extern	MR_LONG		froganim_scr_freefall[];
extern	MR_LONG		froganim_scr_flop[];
extern	MR_LONG		froganim_scr_ouch[];
extern	MR_LONG		froganim_scr_pant[];
extern	MR_LONG		froganim_scr_swimpant[];
extern	MR_LONG		froganim_scr_superjump[];
extern	MR_LONG		froganim_scr_superhop[];
extern	MR_LONG		froganim_scr_superstart[];
extern	MR_LONG		froganim_scr_roll[];
extern	MR_LONG		froganim_scr_start1[];
extern	MR_LONG		froganim_scr_leapfrog[];
extern	MR_LONG		froganim_scr_lcartwheel[];
extern	MR_LONG		froganim_scr_rcartwheel[];
extern	MR_LONG		froganim_scr_roll[];
extern	MR_LONG		froganim_scr_leapfrog[];
extern	MR_LONG		froganim_scr_slip[];
extern	MR_LONG		froganim_scr_pant2[];
extern	MR_LONG		froganim_scr_death[];
extern	MR_LONG		froganim_scr_slipright[];
extern	MR_LONG		froganim_scr_slipleft[];
extern	MR_LONG		froganim_scr_hopleft[];
extern	MR_LONG		froganim_scr_hopright[];
extern	MR_LONG		froganim_scr_crash[];
extern	MR_LONG		froganim_scr_pop[];
extern	MR_LONG		froganim_scr_roll_repeating[];

extern	MR_LONG		froganim_scr_pipeslip[];
extern	MR_LONG		froganim_scr_phew[];
extern	MR_LONG		froganim_scr_bounce[];
extern	MR_LONG		froganim_scr_sink[];
extern	MR_LONG		froganim_scr_left[];
extern	MR_LONG		froganim_scr_right[];
extern	MR_LONG		froganim_scr_lookdown[];
extern	MR_LONG		froganim_scr_lookup[];
extern	MR_LONG		froganim_scr_lookleft[];
extern	MR_LONG		froganim_scr_lookright[];
extern	MR_LONG		froganim_scr_dance[];
extern	MR_LONG		froganim_scr_mown[];

// multiplayer frog scripts
extern	MR_LONG		froganim_m_scr_hop[];
extern	MR_LONG		froganim_m_scr_pant[];
extern	MR_LONG		froganim_m_scr_superjump[];

// texture animation scripts
extern	MR_LONG		frogtexanim_scr_none[];
extern	MR_LONG		frogtexanim_scr_eye_blink[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			FrogRequestAnimation(FROG*, MR_ULONG, MR_ULONG, MR_ULONG);
extern	MR_VOID			FrogInitialiseAnimation(FROG*, MR_ULONG, MR_ULONG);
extern	MR_VOID			UpdateFrogAnimationScripts(MR_VOID);

extern	MR_LONG			FROGSCR_PLAY_ANIM_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_SETLOOP_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_ENDLOOP_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_END_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_HOLD_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_SET_TIMER_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_WAIT_UNTIL_TIMER_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_WAIT_ANIM_FINISHED_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGSCR_PLAY_SCRIPT_IF_command(FROG*, FROG_ANIM_INFO*, MR_LONG*);

extern	MR_LONG			FROGTEXSCR_PLAY_ANIM_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_SETLOOP_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_ENDLOOP_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_END_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_HOLD_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_SET_TIMER_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_WAIT_UNTIL_TIMER_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_WAIT_ANIM_FINISHED_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_PLAY_SCRIPT_IF_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);
extern	MR_LONG			FROGTEXSCR_STOP_ANIM_command(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*);

#endif //__FROGANIM_H
