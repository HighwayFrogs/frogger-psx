/******************************************************************************
*%%%% froganim.c
*------------------------------------------------------------------------------
*
*	Frog animation control, used for normal anims and texture anims
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	04.05.97	Martin Kift		Created
*	18.06.97	Martin Kift		Added texture anims
*
*%%%**************************************************************************/

#include "froganim.h"
#include "gamesys.h"
#include "ent_all.h"
#include "frog.h"
#include "gen_frog.h"
#include "gnm_frog.h"

MR_LONG		Frog_script_if_counter = 0;


//-----------------------------------------------------------------------------
// Main animation script lookup table
//-----------------------------------------------------------------------------
FROG_ANIM	FrogAnimScripts[] = {
		{
		//FROG_ANIMATION_AUTOHOP
		&froganim_scr_autohop[0],
		&froganim_m_scr_hop[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_BACKFLIP
		&froganim_scr_backflip[0],
		&froganim_m_scr_hop[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_SQUISHED
		&froganim_scr_squished[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM|FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_WAIT1
		&froganim_scr_wait1[0],
		NULL,
		FROG_ANIM_QUEUE,
		},
		{
		//FROG_ANIMATION_TIMEOUT
		&froganim_scr_timeout[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM|FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_STRUGGLE
		&froganim_scr_struggle[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_FALLING
		&froganim_scr_falling[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_TRIGGER
		&froganim_scr_trigger[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_DROWN
		&froganim_scr_drown[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM|FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_COMPLETE
		&froganim_scr_complete[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_BITTEN
		&froganim_scr_bitten[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM|FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_FREEFALL
		&froganim_scr_freefall[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_FLOP
		&froganim_scr_flop[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM|FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_OUCH
		&froganim_scr_ouch[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_PANT
		&froganim_scr_pant[0],
		&froganim_m_scr_pant[0],
		FROG_ANIM_QUEUE | FROG_ANIM_RESTORE_AFTER,
		},
		{
		//FROG_ANIMATION_ROLL
		&froganim_scr_roll[0],
		&froganim_m_scr_hop[0],		// Multiplayer has no roll, hence do multiplayer HOP instead
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_HOP
		&froganim_scr_hop[0],
		&froganim_m_scr_hop[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_SUPERJUMP
		&froganim_scr_superjump[0],
		&froganim_m_scr_superjump[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_PANT2
		&froganim_scr_pant2[0],
		NULL,
		FROG_ANIM_QUEUE | FROG_ANIM_RESTORE_AFTER,
		},
		{
		//FROG_ANIMATION_WAIT3
		&froganim_scr_wait3[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_SUPERHOP
		&froganim_scr_superhop[0],
		&froganim_m_scr_superjump[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_WAIT2
		&froganim_scr_wait2[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_SLIP
		&froganim_scr_slip[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_POP
		&froganim_scr_pop[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM | FROG_ANIM_DO_NOT_OVERRIDE,
		},
		{
		//FROG_ANIMATION_SLIPRIGHT
		&froganim_scr_slipright[0],
		NULL,
		FROG_ANIM_BIN_IF_ANIM_PLAYING,
		},
		{
		//FROG_ANIMATION_SLIPLEFT
		&froganim_scr_slipleft[0],
		NULL,
		FROG_ANIM_BIN_IF_ANIM_PLAYING,
		},
		{
		//FROG_ANIMATION_CRASH
		&froganim_scr_crash[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_PHEW
		&froganim_scr_phew[0],
		NULL,
		FROG_ANIM_QUEUE,
		//FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_LOOKDOWN
		&froganim_scr_lookdown[0],
		NULL,
		FROG_ANIM_QUEUE,
		},
		{
		//FROG_ANIMATION_LOOKUP
		&froganim_scr_lookup[0],
		NULL,
		FROG_ANIM_QUEUE,
		},
		{
		//FROG_ANIMATION_LOOKLEFT
		&froganim_scr_lookleft[0],
		NULL,
		FROG_ANIM_QUEUE,
		},
		{
		//FROG_ANIMATION_LOOKRIGHT
		&froganim_scr_lookright[0],
		NULL,
		FROG_ANIM_QUEUE,
		},
		{
		//FROG_ANIMATION_DANCE
		&froganim_scr_dance[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_MOWN
		&froganim_scr_mown[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
		{
		//FROG_ANIMATION_ROLL_REPEATING
		&froganim_scr_roll_repeating[0],
		NULL,
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
	};

#ifdef FROG_TEX_ANIMATION
//-----------------------------------------------------------------------------
// Texture animation script lookup table
//-----------------------------------------------------------------------------
FROG_TEX_ANIM	FrogTexAnimScripts[] = {
		{
		//FROG_TEX_ANIMATION_NONE
		&frogtexanim_scr_none[0],
		FROG_ANIM_QUEUE | FROG_ANIM_RESTORE_AFTER,
		},
		{
		//FROG_TEX_ANIMATION_EYE_BLINK
		&frogtexanim_scr_eye_blink[0],
		FROG_ANIM_OVERRIDE_PREV_ANIM,
		},
	};
#endif

//------------------------------------------------------------------------------------------------
// Script command function pointers
//------------------------------------------------------------------------------------------------
MR_LONG (*Frog_animation_script_commands[])(FROG*, FROG_ANIM_INFO*, MR_LONG*) =
	{
	FROGSCR_PLAY_ANIM_command,
	FROGSCR_SETLOOP_command,
	FROGSCR_ENDLOOP_command,
	FROGSCR_END_command,
	FROGSCR_HOLD_command,
	FROGSCR_WAIT_ANIM_FINISHED_command,
	FROGSCR_PLAY_SCRIPT_IF_command,
	FROGSCR_SET_TIMER_command,
	FROGSCR_WAIT_UNTIL_TIMER_command,
	};

//------------------------------------------------------------------------------------------------
// Script command lengths. This is used for script loops and suchlike
//------------------------------------------------------------------------------------------------
MR_ULONG	Frog_animation_script_command_lengths[] =	// INCLUDING the token itself
	{
	4,			//FROGSCR_PLAY_ANIM
	1,			//FROGSCR_SETLOOP
	1,			//FROGSCR_ENDLOOP
	1,			//FROGSCR_END
	1,			//FROGSCR_HOLD
	1,			//FROGSCR_WAIT_ANIM_FINISHED
	8,			//FROGSCR_PLAY_SCRIPT_IF
	2,			//FROGSCR_SET_TIMER
	2,			//FROGSCR_WAIT_UNTIL_TIMER
	};


//------------------------------------------------------------------------------------------------
// autohop script
//
MR_LONG		froganim_scr_autohop[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_AUTOHOP,	
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Wait1 script
//
MR_LONG		froganim_scr_wait1[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_WAIT1,	
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Wait2 script
//
MR_LONG		froganim_scr_wait2[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_WAIT2,	
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Wait3 script
//
MR_LONG		froganim_scr_wait3[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_WAIT3,	
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Hop script
//
MR_LONG		froganim_scr_hop[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_HOP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Hop script (multiplayer frogs)
//
MR_LONG		froganim_m_scr_hop[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,		0, GENM_FROG_HOP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};


//------------------------------------------------------------------------------------------------
// Back flip script
//
MR_LONG		froganim_scr_backflip[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_BACKFLIP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// POP script
//
MR_LONG		froganim_scr_pop[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_POP,
//	FROGSCR_WAIT_ANIM_FINISHED,
//	FROGSCR_END,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Squished flip script
//
MR_LONG		froganim_scr_squished[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_SQUISHED,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
//time out script
//
MR_LONG		froganim_scr_timeout[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_TIMEOUT,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

			
//------------------------------------------------------------------------------------------------
// Struggle script
//
MR_LONG		froganim_scr_struggle[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_REPEATING,		0, GEN_FROG_STRUGGLE,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};
				
//------------------------------------------------------------------------------------------------
// freefall script
//
MR_LONG		froganim_scr_free_fall[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_REPEATING,		8, GEN_FROG_FREEFALL,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// falling script
//
MR_LONG		froganim_scr_falling[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_REPEATING,		8, GEN_FROG_FALLING,
	FROGSCR_HOLD,
	};
					
//------------------------------------------------------------------------------------------------
// Trigger script
//
MR_LONG		froganim_scr_trigger[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_TRIGGER,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Drown script
//
MR_LONG		froganim_scr_drown[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_DROWN,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Complete script
//
MR_LONG		froganim_scr_complete[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_COMPLETE,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// bitten script
//
MR_LONG		froganim_scr_bitten[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_BITTEN,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Freefall script
//
MR_LONG		froganim_scr_freefall[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_REPEATING,		5, GEN_FROG_FREEFALL,
//	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Flop script
//
MR_LONG		froganim_scr_flop[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_FLOP,
	FROGSCR_WAIT_ANIM_FINISHED,
//	FROGSCR_END,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Ouch script
//
MR_LONG		froganim_scr_ouch[] =
	{
	FROGSCR_PLAY_ANIM,		FROGSCR_PLAYBACK_ONCE,			0, GEN_FROG_OUCH,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Pant script
//
MR_LONG		froganim_scr_pant[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_REPEATING,	0, GEN_FROG_PANT,
	FROGSCR_SETLOOP,
		FROGSCR_PLAY_SCRIPT_IF,		FROGSCR_CONDITION_NO_INPUT,	30, 0,		FROG_ANIMATION_LOOKLEFT,
																			FROG_ANIMATION_LOOKRIGHT,
																			FROG_ANIMATION_LOOKUP,
																			FROG_ANIMATION_LOOKDOWN,
	FROGSCR_ENDLOOP,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Pant2 script
//
MR_LONG		froganim_scr_pant2[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_REPEATING,	0, GEN_FROG_PANT2,
	FROGSCR_SETLOOP,
		FROGSCR_PLAY_SCRIPT_IF,		FROGSCR_CONDITION_NO_INPUT,	30, 0,		FROG_ANIMATION_LOOKLEFT,
																			FROG_ANIMATION_LOOKRIGHT,
																			FROG_ANIMATION_LOOKUP,
																			FROG_ANIMATION_LOOKDOWN,
	FROGSCR_ENDLOOP,
	FROGSCR_END,
	};
//------------------------------------------------------------------------------------------------
// Pant script (multiplayer frogs)
//
MR_LONG		froganim_m_scr_pant[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GENM_FROG_SIT,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Super jump script
//
MR_LONG		froganim_scr_superjump[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_SUPERJUMP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Super jump (multiplayer) script
//
MR_LONG		froganim_m_scr_superjump[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,		0, GENM_FROG_SUPERJUMP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Super hop script
//
MR_LONG		froganim_scr_superhop[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_SUPERHOP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Roll frog  script
//
MR_LONG		froganim_scr_roll[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,		0, GEN_FROG_ROLL,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Roll frog  script
//
MR_LONG		froganim_scr_roll_repeating[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_REPEATING,		0, GEN_FROG_ROLL,
	FROGSCR_HOLD,
	};

//------------------------------------------------------------------------------------------------
// Slip frog  script
//
MR_LONG		froganim_scr_slip[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_SLIP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};
		
//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_SLIPRIGHT script
//
MR_LONG		froganim_scr_slipright[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_SLIPRIGHT,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_SLIPLEFT script
//
MR_LONG		froganim_scr_slipleft[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_SLIPLEFT,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_CRASH script
//
MR_LONG		froganim_scr_crash[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_CRASH,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_PHEW script
//
MR_LONG		froganim_scr_phew[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_PHEW,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_LOOKDOWN script
//
MR_LONG		froganim_scr_lookdown[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_LOOKDOWN,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_LOOKUP script
//
MR_LONG		froganim_scr_lookup[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_LOOKUP,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_LOOKLEFT script
//
MR_LONG		froganim_scr_lookleft[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_LOOKLEFT,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_LOOKRIGHT script
//
MR_LONG		froganim_scr_lookright[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_LOOKRIGHT,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_DANCE script
//
MR_LONG		froganim_scr_dance[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_DANCE,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_END,
	};

//------------------------------------------------------------------------------------------------
// FROG_ANIMATION_MOWN script
//
MR_LONG		froganim_scr_mown[] =
	{
	FROGSCR_PLAY_ANIM,				FROGSCR_PLAYBACK_ONCE,	0, GEN_FROG_MOWN,
	FROGSCR_WAIT_ANIM_FINISHED,
	FROGSCR_HOLD,
	};

#ifdef FROG_TEX_ANIMATION

//------------------------------------------------------------------------------------------------
// Script command function pointers
//------------------------------------------------------------------------------------------------
MR_LONG (*Frog_tex_animation_script_commands[])(FROG*, FROG_TEX_ANIM_INFO*, MR_LONG*) =
	{
	FROGTEXSCR_PLAY_ANIM_command,
	FROGTEXSCR_SETLOOP_command,
	FROGTEXSCR_ENDLOOP_command,
	FROGTEXSCR_END_command,
	FROGTEXSCR_HOLD_command,
	FROGTEXSCR_WAIT_ANIM_FINISHED_command,
	FROGTEXSCR_PLAY_SCRIPT_IF_command,
	FROGTEXSCR_SET_TIMER_command,
	FROGTEXSCR_WAIT_UNTIL_TIMER_command,
	FROGTEXSCR_STOP_ANIM_command,
	};

//------------------------------------------------------------------------------------------------
// Script command lengths. This is used for script loops and suchlike
//------------------------------------------------------------------------------------------------
MR_ULONG	Frog_texture_animation_script_command_lengths[] =	// INCLUDING the token itself
	{
	3,			//FROGTEXSCR_PLAY_ANIM
	1,			//FROGTEXSCR_SETLOOP
	1,			//FROGTEXSCR_ENDLOOP
	1,			//FROGTEXSCR_END
	1,			//FROGTEXSCR_HOLD
	1,			//FROGTEXSCR_WAIT_ANIM_FINISHED
	5,			//FROGTEXSCR_PLAY_SCRIPT_IF
	2,			//FROGTEXSCR_SET_TIMER
	2,			//FROGTEXSCR_WAIT_UNTIL_TIMER
	1,			//FROGTEXSCR_STOP_ANIM
	};

//------------------------------------------------------------------------------------------------
// No texture anim
//
MR_LONG		frogtexanim_scr_none[] =
	{
	FROGTEXSCR_STOP_ANIM,			
	FROGTEXSCR_END,
	};

//------------------------------------------------------------------------------------------------
// Eye blink texture anim
//
MR_LONG		frogtexanim_scr_eye_blink[] =
	{
	FROGTEXSCR_PLAY_ANIM,			FROGSCR_PLAYBACK_ONCE,			GEN_FROG_SUPERJUMP,
	FROGTEXSCR_END,
	};
#endif


/******************************************************************************
*%%%% FrogInitialiseAnimation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FrogInitialiseAnimation(FROG*		frog,
*										MR_ULONG	anim_equate,
*										MR_ULONG	anim_type)
*
*	FUNCTION	This function initialises the animation structure, for both
*				normal and texture animation.
*
*	INPUTS		frog			-	ptr to FROG
*				anim_equate		-	animation equate (see enum and structs in 
*									froganim.h)
*				anim_type		-	anim type (is normal or texture animation)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID FrogInitialiseAnimation(	FROG*		frog,
									MR_ULONG	anim_equate,
									MR_ULONG	anim_type)
{
	FROG_ANIM*			anim;
	MR_LONG*			script;

#ifdef FROG_TEX_ANIMATION
    FROG_TEX_ANIM*      tex_anim;
#endif

	// what type of animation was requested?
	if (anim_type == FROG_ANIM_TYPE_NORMAL)
		{
		// Get requested animation structure
		MR_ASSERT (anim_equate < FROG_ANIMATION_MAX);
		anim = &FrogAnimScripts[anim_equate];

		// Work out which script we are looking at, maybe different in single or
		// multiplayer, may even be NULL
		if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS)
			script = anim->fa_script_multiplayer;
		else
			script = anim->fa_script;

		// If the script is NULL, then return now
		if (script)
			{
			// Copy across flags and script ptr
			FROG_ANIM_SET_SCRIPT(&frog->fr_anim_info, anim_equate, anim, script);
			FROG_ANIM_CLEAR_PREVIOUS(&frog->fr_anim_info);
			FROG_ANIM_CLEAR_QUEUE(&frog->fr_anim_info);
			}
		}
#ifdef FROG_TEX_ANIMATION
	else
		{
		// If in multiplayer mode, ignore texture animation
		if (Game_total_players == 1)
			{
			// Get requested animation structure
			MR_ASSERT (anim_equate < FROG_TEX_ANIMATION_MAX);
			tex_anim = &FrogTexAnimScripts[anim_equate];
		
			// Copy across flags and script ptr
			FROG_TEX_ANIM_SET_SCRIPT(&frog->fr_tex_anim_info, anim_equate, tex_anim);
			FROG_TEX_ANIM_CLEAR_PREVIOUS(&frog->fr_tex_anim_info);
			FROG_TEX_ANIM_CLEAR_QUEUE(&frog->fr_tex_anim_info);
			}
		}

#endif
}


/******************************************************************************
*%%%% FrogRequestAnimation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FrogRequestAnimation(	FROG*		frog,
*										MR_ULONG	anim_equate,
*										MR_ULONG	anim_type,
*										MR_ULONG	anim_request_local)
*
*	FUNCTION	This function requests that an animation be played, and is called
*				from a multitude of different places within frogger. 
*
*	NOTES		Asking for an animation to be played and actually getting that
*				animtion played are two different things, it all depends on what
*				previous animation was playing, whether that animation requires
*				no interuptions until its finished, etc.
*
*	INPUTS		frog				-	ptr to FROG
*				anim_equate			-	animation equate (see enum and structs in 
*										froganim.h)
*				anim_type			-	anim type (is normal or texture animation)
*				anim_request_local	-	(win95 only) set to 0 when local call, else 1
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID FrogRequestAnimation(	FROG*		frog,
								MR_ULONG	anim_equate,
								MR_ULONG	anim_type,
								MR_ULONG	anim_request_local)
{
	FROG_ANIM*			anim;
	FROG_ANIM_INFO*		info;
	MR_LONG*			script;
#ifdef FROG_TEX_ANIMATION
	FROG_TEX_ANIM*		tex_anim;
	FROG_TEX_ANIM_INFO*	tex_info;
#endif

	// what type of animation was requested?
	if (anim_type == FROG_ANIM_TYPE_NORMAL)
		{
		// Get requested animation structure
		MR_ASSERT (anim_equate < FROG_ANIMATION_MAX);
		anim	= &FrogAnimScripts[anim_equate];
		info	= &frog->fr_anim_info;

		// Work out which script we are looking at, maybe different in single or
		// multiplayer, may even be NULL
		if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS)
			script = anim->fa_script_multiplayer;
		else
			script = anim->fa_script;

		// If the script is NULL, then return now
		if (!script)
			return;

		// If current script has the FROG_ANIM_DO_NOT_OVERRIDE flag, then ignore this anim request,
		// since we ain't gonna play it
		if (info->fi_flags & FROG_ANIM_DO_NOT_OVERRIDE)
			return;

		// Firstly check (since script may get overridden) that current script wants to back itself
		// up, and become re-active after current script is finished
		if (info->fi_flags & FROG_ANIM_RESTORE_AFTER)
			{
			FROG_ANIM_SET_PREVIOUS(info);
			}

		// Look at requested animation, and decide on whether it can be played, queued, or whatever.
		if (anim->fa_flags & FROG_ANIM_QUEUE)
			{
			// We have a request to queue after the present animation. BUT, if the current
			// anim is a delayed start anim, we should but in immediately...
			if (frog->fr_anim_info.fi_anim_timer)
				{
				// Override any current animation with the requested one
				FROG_ANIM_SET_SCRIPT(info, anim_equate, anim, script);
				}
			else
				{
				// QUEUE up the animation to play when the current one has finished playing
				FROG_ANIM_SET_QUEUE(info, anim_equate, anim->fa_flags, script);
				}
			// reset timer
			frog->fr_anim_info.fi_anim_timer = 0;
			}
		else
		if (anim->fa_flags & FROG_ANIM_BIN_IF_ANIM_PLAYING)
			{
			// If theres any animation playing (apart from the pant anim which is
			// consider NO animation for the frog) then forget this animation request
			if (info->fi_type == FROG_ANIMATION_PANT)
				{
				// its ok to proceed with the requested animation
				FROG_ANIM_SET_QUEUE(info, anim_equate, anim->fa_flags, script);

				// reset timer
				frog->fr_anim_info.fi_anim_timer = 0;
				}
			}
		else
		if (anim->fa_flags & FROG_ANIM_OVERRIDE_PREV_ANIM)
			{
			// Override any current animation with the requested one
			FROG_ANIM_SET_SCRIPT(info, anim_equate, anim, script);

			// clear any queued anims, they are redundent now
			FROG_ANIM_CLEAR_QUEUE(&frog->fr_anim_info);

			// reset timer
			frog->fr_anim_info.fi_anim_timer = 0;
			}
		}
#ifdef FROG_TEX_ANIMATION
	else
		{
		// Must be a texture animation...
		// Get requested animation structure
		MR_ASSERT (anim_equate < FROG_TEX_ANIMATION_MAX);
		tex_anim	= &FrogTexAnimScripts[anim_equate];
		tex_info	= &frog->fr_tex_anim_info;

		// Firstly check (since script may get overridden) that current script wants to back itself
		// up, and become re-active after current script is finished
		if (tex_info->ti_flags & FROG_ANIM_RESTORE_AFTER)
			{
			FROG_TEX_ANIM_SET_PREVIOUS(tex_info);
			}

		// Look at requested animation, and decide on whether it can be played, queued, or whatever.
		if (tex_anim->ta_flags & FROG_ANIM_QUEUE)
			{
			// QUEUE up the animation to play when the current one has finished playing
			FROG_TEX_ANIM_SET_QUEUE(tex_info, anim_equate, tex_anim);
			}
		else
		if (tex_anim->ta_flags & FROG_ANIM_BIN_IF_ANIM_PLAYING)
			{
			// its ok to proceed with the requested animation
			FROG_TEX_ANIM_SET_QUEUE(tex_info, anim_equate, tex_anim);
			}
		else
		if (tex_anim->ta_flags & FROG_ANIM_OVERRIDE_PREV_ANIM)
			{
			// Override any current animation with the requested one
			FROG_TEX_ANIM_SET_SCRIPT(tex_info, anim_equate, tex_anim);
			}
		}
#endif

#ifdef WIN95
	// update network is running, and this is not a network request already
	if	(
		(Game_is_network) &&
		(anim_request_local) && 
		(frog == Frog_local_ptr)
		)
		{
		SendFrogData(FRNET_FROG_FLAG_ANIM, frog, anim_equate, anim_type, frog->fr_flags);			
		}
#endif // WIn95
}


/******************************************************************************
*%%%% UpdateFrogAnimationScripts
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogAnimationScripts(MR_VOID)
*
*	FUNCTION	Modify animation scripts
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Martin Kift		Rewritten to include scripts and other code
*
*%%%**************************************************************************/

MR_VOID	UpdateFrogAnimationScripts(MR_VOID)
{
	FROG*					frog;
	MR_LONG					loop;
	MR_ANIM_ENV*			env;
	MR_LONG					ret;
	FROG_ANIM*				anim;
	FROG_ANIM_INFO*			info;
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;
	MR_LONG					cel, total_cel;
	MR_LONG*				script;
#ifdef FROG_TEX_ANIMATION
	FROG_TEX_ANIM*			tex_anim;
	FROG_TEX_ANIM_INFO*		tex_info;
#endif

	frog	= Frogs;
	loop	= Game_total_players;
	while(loop--)
		{
		env = frog->fr_api_item;

		if (Game_total_players == 1)
			{
			env_sing		= env->ae_extra.ae_extra_env_single;
			cel				= env_sing->ae_cel_number;
			total_cel		= env_sing->ae_total_cels;

			// Always force LW transforms to be rebuilt
			env_sing->ae_last_cel_number	= -1;
			}
		else
			{
			env_flipbook	= env->ae_extra.ae_extra_env_flipbook;
			cel				= env_flipbook->ae_cel_number;
			total_cel		= env_flipbook->ae_total_cels;
			}
script_rerun:;
		// Update the normal script for this frog
		if	(info = &frog->fr_anim_info)
			{
			// Parse script
			ret = FROGSCR_RETURN_CONTINUE;
			while (ret == FROGSCR_RETURN_CONTINUE)
				{
				ret = (Frog_animation_script_commands[info->fi_script[0]])(frog, info, info->fi_script + 1);
				}

			// check if theres a queued script waiting to come in, and previous anim has finished
			if (info->fi_queue_type != -1)
				{
				if (cel >= total_cel-1)
					{
					// play new script
					anim = &FrogAnimScripts[info->fi_queue_type];

					// Work out which script we are looking at, maybe different in single or
					// multiplayer, may even be NULL
					if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS)
						script = anim->fa_script_multiplayer;
					else
						script = anim->fa_script;

					// If the script is NULL, then return now
					if (script)
						{
						FROG_ANIM_APPLY_QUEUE(info, script);
						FROG_ANIM_CLEAR_QUEUE(info);

						// after having setup the script, we really need to rerun this script,
						// otherwise we'll be out of sync (playing a frame twice)
						goto script_rerun;
						}
					}
				}


			// Consider action on leaving script
			switch (ret)		
				{
				case FROGSCR_RETURN_BREAK:
					break;

				case FROGSCR_RETURN_END:
					// Is there a backed up script?
					if (info->fi_previous_type != -1)
						{
						anim = &FrogAnimScripts[info->fi_previous_type];

						// Work out which script we are looking at, maybe different in single or
						// multiplayer, may even be NULL
						if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS)
							script = anim->fa_script_multiplayer;
						else
							script = anim->fa_script;

						// If the script is NULL, then return now
						if (script)
							{
							FROG_ANIM_APPLY_PREVIOUS(info, script);
							FROG_ANIM_CLEAR_PREVIOUS(info);

							// after having setup the script, we really need to rerun this script,
							// otherwise we'll be out of sync (playing a frame twice)
							goto script_rerun;
							}
						}
					break;
				}

			// update timer
			info->fi_timer++;
			}

#ifdef FROG_TEX_ANIMATION
		// Update the texture script for this frog
		if	(tex_info = &frog->fr_tex_anim_info)
			{
			// Parse script (if one exists)
			if (tex_info->ti_script)
				{
				ret = FROGSCR_RETURN_CONTINUE;
				while (ret == FROGSCR_RETURN_CONTINUE)
					{
					ret = (Frog_tex_animation_script_commands[tex_info->ti_script[0]])(frog, tex_info, tex_info->ti_script + 1);
					}

				// check if theres a queued script waiting to come in, and previous anim has finished
				if (tex_info->ti_queue_type != -1)
					{
					// play new script
					tex_anim = &FrogTexAnimScripts[tex_info->ti_queue_type];
					FROG_TEX_ANIM_APPLY_QUEUE(tex_info, tex_anim);
					FROG_TEX_ANIM_CLEAR_QUEUE(tex_info);
					}

				// Consider action on leaving script
				switch (ret)		
					{
					case FROGSCR_RETURN_BREAK:
						break;

					case FROGSCR_RETURN_END:
						// Is there a backed up script?
						if (tex_info->ti_previous_type != -1)
							{
							tex_anim = &FrogTexAnimScripts[tex_info->ti_previous_type];
							FROG_TEX_ANIM_APPLY_PREVIOUS(tex_info, tex_anim);
							FROG_TEX_ANIM_CLEAR_PREVIOUS(tex_info);
							}
						break;
					}

				// update timer
				tex_info->ti_timer++;
				}
			}
#endif

		// move to next frog
		frog++;
		}
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_PLAY_ANIM_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	FROGANIM_PLAY_ANIM*	play_anim;

	play_anim = (FROGANIM_PLAY_ANIM*)script;

	// Has a delay timer been requested for this playback of animation?
	if (play_anim->pa_delay_timer != 0)
		{
		// Is an animation delay already in operation? If so then we need to process this command in a
		// different way
		if (frog_anim_info->fi_anim_timer)
			{
			if (--frog_anim_info->fi_anim_timer)
				{
				// Delay timer is not zero, return now and continue on this command for a while
				frog_anim_info->fi_script = script-1;
				return FROGSCR_RETURN_BREAK;
				}
			else 
				goto play_anim;
			}
		else
			{
			frog_anim_info->fi_anim_timer = play_anim->pa_delay_timer;
			frog_anim_info->fi_script = script-1;
			return FROGSCR_RETURN_BREAK;
			}
		}

play_anim:;
	if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS)
		MRAnimEnvSingleSetAction((MR_ANIM_ENV*)frog->fr_api_item, (MR_SHORT)play_anim->pa_action);
	else
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)frog->fr_api_item, (MR_SHORT)play_anim->pa_action);

	// look at playback mode
	switch (play_anim->pa_play_back_type)
		{
		case FROGSCR_PLAYBACK_ONCE:
			((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags |= (MR_ANIM_ENV_DEFAULT_FLAGS | MR_ANIM_ENV_ONE_SHOT);
			break;

		case FROGSCR_PLAYBACK_REPEATING:
			((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags |= MR_ANIM_ENV_DEFAULT_FLAGS;
			((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
			break;
		}

	// Clear anim timer, so it works on successive calls
	frog_anim_info->fi_anim_timer = 0;

	frog_anim_info->fi_script = (MR_LONG*)((MR_UBYTE*)script + sizeof (FROGANIM_PLAY_ANIM));
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_SETLOOP_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	frog_anim_info->fi_script_loop_start	= script;
	frog_anim_info->fi_script				= script;

	// Find next ENTSCR_ENDLOOP command
	while (script[0] != FROGSCR_ENDLOOP)
		script += Frog_animation_script_command_lengths[script[0]];

	frog_anim_info->fi_script_loop_end 	= script;
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_ENDLOOP_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	MR_ASSERT(frog_anim_info->fi_script_loop_start);
	frog_anim_info->fi_script	= frog_anim_info->fi_script_loop_start;
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_END_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	return FROGSCR_RETURN_END;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_HOLD_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	// Hack of the gods... if we were playing a one shot and its reached the last frame,
	// set ae_last_cel_number to -1 so the matrix is updated
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;


	env_sing = NULL;
	if (((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags & MR_ANIM_ENV_ONE_SHOT)
		{
		if (Game_total_players == 1)
			{
			env_sing = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_single;
			if (env_sing->ae_cel_number >= env_sing->ae_total_cels-1)
				env_sing->ae_last_cel_number = -1;
			}
		else
			{
			env_flipbook = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_flipbook;
			if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
				env_flipbook->ae_last_cel_number = -1;
			}
		}
	
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_SET_TIMER_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	frog_anim_info->fi_timer	= script[0];
	
	// move to next command
	frog_anim_info->fi_script	= script + 1;
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGSCR_WAIT_UNTIL_TIMER_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	if (frog_anim_info->fi_timer >= script[0])
		{
		frog_anim_info->fi_script = script + 1;
		return FROGSCR_RETURN_CONTINUE;
		}
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
// This function waits til the animation is finished
//
MR_LONG	FROGSCR_WAIT_ANIM_FINISHED_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;

	if (Game_total_players == 1)
		{
		env_sing = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_single;
		if (env_sing->ae_cel_number >= env_sing->ae_total_cels-1)
			{
			frog_anim_info->fi_script = script;
			return FROGSCR_RETURN_CONTINUE;
			}
		}
	else
		{
		env_flipbook = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_flipbook;
		if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
			{
			frog_anim_info->fi_script = script;
			return FROGSCR_RETURN_CONTINUE;
			}
		}

	// animation still playing
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
// This function branches to another script, but on a condition
// Match: https://decomp.me/scratch/QXCFw (By Kneesnap) 12-11-23
//
MR_LONG	FROGSCR_PLAY_SCRIPT_IF_command(FROG* frog, FROG_ANIM_INFO* frog_anim_info, MR_LONG* script)
{
	FROGANIM_PLAY_ANIM_IF*	play_anim_if;
	MR_LONG					random;
	MR_LONG					script_id;

	// Setup the action
	play_anim_if = (FROGANIM_PLAY_ANIM_IF*)script;

	switch (play_anim_if->pai_condition)
		{
		case FROGSCR_CONDITION_NO_INPUT:
			if (frog->fr_no_input_timer >= play_anim_if->pai_variable1)
				{
				// script is destined to play one of 4 scripts, so pick one
				random		= rand()&3;
				script_id	= play_anim_if->pai_script_ids[random];

				MR_ASSERT (script_id < FROG_ANIMATION_MAX);

				// bodge to play a different WAIT on Industrial and Jungle.
				// Not a great way of doing it, but the system was never designed to 
				// do this type of sort!
				if ((Game_map_theme == THEME_JUN) || (Game_map_theme == THEME_VOL))
					{
					// For a change.
					if (Frog_script_if_counter++ == 4)
						{
						// Play a different wait for the Industrial & Jungle.
						FrogRequestAnimation(frog, FROG_ANIMATION_PHEW, 0, 0);

						// reset no input counter
						Frog_script_if_counter = 0;
						frog->fr_no_input_timer = 0;
						}
					else
						{
						// Play requested script
						FrogRequestAnimation(frog, script_id, 0, 0);

						// reset no input counter
						frog->fr_no_input_timer = 0;
						}
					}
				else
					{
					// Play requested script
					FrogRequestAnimation(frog, script_id, 0, 0);

					// reset no input counter
					frog->fr_no_input_timer = 0;
					}
				}
			break;
		}

	frog_anim_info->fi_script = (MR_LONG*)((MR_UBYTE*)script + sizeof (FROGANIM_PLAY_ANIM_IF));
	return FROGSCR_RETURN_CONTINUE;
}

#ifdef FROG_TEX_ANIMATION

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_PLAY_ANIM_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	anim_info->ti_script = (MR_LONG*)((MR_UBYTE*)script + sizeof (FROGTEXANIM_PLAY_ANIM));
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_SETLOOP_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	anim_info->ti_script_loop_start		= script;
	anim_info->ti_script				= script;

	// Find next ENTSCR_ENDLOOP command
	while (script[0] != FROGSCR_ENDLOOP)
		script += Frog_texture_animation_script_command_lengths[script[0]];

	anim_info->ti_script_loop_end 		= script;
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_ENDLOOP_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	MR_ASSERT(anim_info->ti_script_loop_start);
	anim_info->ti_script = anim_info->ti_script_loop_start;
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_END_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	return FROGSCR_RETURN_END;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_HOLD_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_SET_TIMER_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	anim_info->ti_timer	= script[0];
	
	// move to next command
	anim_info->ti_script = script + 1;
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	FROGTEXSCR_WAIT_UNTIL_TIMER_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
	if (anim_info->ti_timer >= script[0])
		{
		anim_info->ti_script = script + 1;
		return FROGSCR_RETURN_CONTINUE;
		}
	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
// This function waits til the animation is finished
//
MR_LONG	FROGTEXSCR_WAIT_ANIM_FINISHED_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
		// animation finished, so return continue
		anim_info->ti_script = script;
		return FROGSCR_RETURN_CONTINUE;

	// animation still playing
//	return FROGSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
// This function branches to another script, but on a condition
//
MR_LONG	FROGTEXSCR_PLAY_SCRIPT_IF_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
/*	FROGANIM_PLAY_ANIM_IF*	play_anim_if;
	FROG_TEX_ANIM*			tex_anim;

	// Setup the action
	play_anim_if = (FROGANIM_PLAY_ANIM_IF*)script;

	switch (play_anim_if->pai_condition)
		{
		case FROGSCR_CONDITION_NO_INPUT:
			if (frog->fr_no_input_timer >= play_anim_if->pai_variable1)
				{
				// Play requested script
				FrogRequestAnimation(frog, play_anim_if->pai_script_ids[0], FROG_ANIM_TYPE_TEXTURE, 0);

				// reset no input counter
				frog->fr_no_input_timer = 0;
				}
			break;
		}
*/
	anim_info->ti_script = (MR_LONG*)((MR_UBYTE*)script + sizeof (FROGANIM_PLAY_ANIM_IF));
	return FROGSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
// This function stops all texture animations in their tracks (or maybe at the end of the 
// current update, depends on what we need ultimately)
//
MR_LONG	FROGTEXSCR_STOP_ANIM_command(FROG* frog, FROG_TEX_ANIM_INFO* anim_info, MR_LONG* script)
{
/*
	MR_MESH*						mesh_ptr;
	MR_ANIM_MESH*					amesh_ptr;
	MR_ANIM_ENV*					env;
	MR_ANIM_ENV_SINGLE*				env_sing;
	MR_ANIM_ENV_MULTIPLE*			env_mult;
	MR_MOF*							mof_ptr;
	MR_ULONG						i, polys, parts, pp;//, anim_entries;
	MR_MESH_ANIMATED_POLY*			anim_poly;
	MR_PART_POLY_ANIM*				part_poly;
	MR_PART*						part_ptr;
//	MR_PART_POLY_ANIMLIST_ENTRY*	anim_entry;	
	MR_BOOL							finished_all_textures;

	// set bool flag to TRUE. If any texture anims are left unfinished on this pass of the STOP_ANIM
	// command, the script anim is left on this STOP_ANIM command until next game frame, and so on
	// until all anims are finished. If any anims are unfinished, the flag FALSE and the script command
	// cannot end until future frames...
	finished_all_textures = FALSE;

	env = (MR_ANIM_ENV*)frog->fr_api_item;

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		env_mult 	= env->ae_extra.ae_extra_env_multiple;
		mof_ptr 	= env->ae_header->ah_static_files[env_mult->ae_models[amesh_ptr->am_model_no]->am_static_model];
		}
	else
		{
		env_sing 	= env->ae_extra.ae_extra_env_single;
		mof_ptr 	= env->ae_header->ah_static_files[env_sing->ae_model->am_static_model];
		}

	polys 		= mesh_ptr->me_num_animated_polys;
	anim_poly	= mesh_ptr->me_animated_polys;
	parts 		= mof_ptr->mm_extra;
	part_ptr 	= (MR_PART*)(mof_ptr + 1);

	while(parts--)
		{
		if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
			{
			// MR_PART has some animated polys
			pp 			= *(MR_ULONG*)(part_ptr->mp_pad0);
			part_poly	= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);
			while(pp--)
				{
				// mark poly as paused if its reached the last frame.
				if (!(anim_poly->ma_flags & MR_MESH_ANIMATED_POLY_PAUSED))
					{
					// Reached last frame?
					if (anim_poly->ma_animlist_entry == 0)
						anim_poly->ma_flags |= MR_MESH_ANIMATED_POLY_PAUSED;
					else
						finished_all_textures = FALSE;
					}
				anim_poly++;
				part_poly++;
				polys--;
				}
			}
		part_ptr++;
		}

	// Have we finished all texture anims?
	if (finished_all_textures)
		{*/
		anim_info->ti_script = script;
		return FROGSCR_RETURN_CONTINUE;
		/*}
	else
		{
		anim_info->ti_script = script-1;
		return FROGSCR_RETURN_BREAK;
		}*/
}
#endif

