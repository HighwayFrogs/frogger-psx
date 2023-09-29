/******************************************************************************
*%%%% hud.c
*------------------------------------------------------------------------------
*
*	In-game overlay stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	08.05.97	Tim Closs		Created
*	11.06.97	Martin Kift		Linked up colours of checkpoints with in game
*	05.07.97	Martin Kift		Added lots of new in game HUD specials
*	05.08.97	Martin Kift		Added F4 backgrounds to scores
*
*%%%**************************************************************************/

#include "hud.h"
#include "gamesys.h"
#include "frog.h"
#include "ent_all.h"
#include "froganim.h"
#include "score.h"
#include "select.h"
#include "sound.h"
#include "tempopt.h"

#ifdef WIN95
#pragma warning (disable : 4761)
#endif

// HUD script info structures
HUD_CHECKPOINT_ANIM_INFO	Hud_checkpoint_anim_gather[] = 
	{
		// check point 1
		{	
		(SYSTEM_DISPLAY_WIDTH>>1)-80,											// x
		(SYSTEM_DISPLAY_HEIGHT>>1)+40,											// y
		(16 - ((SYSTEM_DISPLAY_WIDTH>>1)-80)<<16)/30,							// x vel
#ifdef PSX_MODE_PAL
		(SYSTEM_DISPLAY_HEIGHT - 32 - 6 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#else
		(SYSTEM_DISPLAY_HEIGHT - 32 - 12 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#endif
		30,																		// time (100+20 / 4)
		5,																		// delay before moving
		0,																		// Timer for complex anim/movements
		},
		// check point 2
		{	
		(SYSTEM_DISPLAY_WIDTH/2)-40,											// x
		(SYSTEM_DISPLAY_HEIGHT>>1)+40,											// y
		(32 - ((SYSTEM_DISPLAY_WIDTH>>1)-40)<<16)/30,							// x vel
#ifdef PSX_MODE_PAL
		(SYSTEM_DISPLAY_HEIGHT - 32 - 6 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#else
		(SYSTEM_DISPLAY_HEIGHT - 32 - 12 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#endif
		30,																		// time (100+20 / 4)
		10,																		// delay before moving
		0,																		// Timer for complex anim/movements
		},
		// check point 3
		{	
		(SYSTEM_DISPLAY_WIDTH/2),												// x
		(SYSTEM_DISPLAY_HEIGHT>>1)+40,											// y
		(48 - ((SYSTEM_DISPLAY_WIDTH>>1))<<16)/30,								// x vel
#ifdef PSX_MODE_PAL
		(SYSTEM_DISPLAY_HEIGHT - 32 - 6 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#else
		(SYSTEM_DISPLAY_HEIGHT - 32 - 12 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#endif
		30,																		// time (100+20 / 4)
		15,																		// delay before moving
		0,																		// Timer for complex anim/movements
		},
		// check point 4
		{	
		(SYSTEM_DISPLAY_WIDTH/2)+40,											// x
		(SYSTEM_DISPLAY_HEIGHT>>1)+40,											// y
		(64 - ((SYSTEM_DISPLAY_WIDTH>>1)+40)<<16)/30,							// x vel
#ifdef PSX_MODE_PAL
		(SYSTEM_DISPLAY_HEIGHT - 32 - 6 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#else
		(SYSTEM_DISPLAY_HEIGHT - 32 - 12 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#endif
		30,																		// time (100+20 / 4)
		20,																		// delay before moving
		0,																		// Timer for complex anim/movements
		},
		// check point 5
		{	
		(SYSTEM_DISPLAY_WIDTH/2)+80,											// x
		(SYSTEM_DISPLAY_HEIGHT>>1)+40,											// y
		(80 - ((SYSTEM_DISPLAY_WIDTH>>1)+80)<<16)/30,							// x vel
#ifdef PSX_MODE_PAL
		(SYSTEM_DISPLAY_HEIGHT - 32 - 6 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#else
		(SYSTEM_DISPLAY_HEIGHT - 32 - 12 - ((SYSTEM_DISPLAY_HEIGHT>>1)+40)<<16)/30,	// y vel
#endif
		30,																		// time (100+20 / 4)
		25,																		// delay before moving
		0,																		// Timer for complex anim/movements
		},
	};

HUD_CHECKPOINT_ANIM_INFO	Hud_checkpoint_anim_split[] = 
	{
		// check point 1
		{	
		16,										// x
#ifdef PSX_MODE_PAL
		SYSTEM_DISPLAY_HEIGHT - 32 - 6,				// y
#else
		SYSTEM_DISPLAY_HEIGHT - 32 - 12,				// y
#endif
		0,										// x vel
		2<<16,									// y vel
		20,										// time (100+20 / 4)
		5,										// delay before moving
		0,										// Timer for complex anim/movements
		},
		// check point 2
		{	
		32,										// x
#ifdef PSX_MODE_PAL
		SYSTEM_DISPLAY_HEIGHT - 32 - 6,				// y
#else
		SYSTEM_DISPLAY_HEIGHT - 32 - 12,				// y
#endif
		0,										// x vel
		2<<16,									// y vel
		20,										// time (100+20 / 4)
		10,										// delay before moving
		0,										// Timer for complex anim/movements
		},
		// check point 3
		{		
		48,										// x
#ifdef PSX_MODE_PAL
		SYSTEM_DISPLAY_HEIGHT - 32 - 6,				// y
#else
		SYSTEM_DISPLAY_HEIGHT - 32 - 12,				// y
#endif
		0,										// x vel
		2<<16,									// y vel
		20,										// time (100+20 / 4)
		15,										// delay before moving
		0,										// Timer for complex anim/movements
		},
		// check point 4
		{	
		64,										// x
#ifdef PSX_MODE_PAL
		SYSTEM_DISPLAY_HEIGHT - 32 - 6,				// y
#else
		SYSTEM_DISPLAY_HEIGHT - 32 - 12,				// y
#endif
		0,										// x vel
		2<<16,									// y vel
		20,										// time (100+20 / 4)
		20,										// delay before moving
		0,										// Timer for complex anim/movements
		},
		// check point 5
		{	
		80,										// x
#ifdef PSX_MODE_PAL
		SYSTEM_DISPLAY_HEIGHT - 32 - 6,				// y
#else
		SYSTEM_DISPLAY_HEIGHT - 32 - 12,				// y
#endif
		0,										// x vel
		2<<16,									// y vel
		20,										// time (100+20 / 4)
		25,										// delay before moving
		0,										// Timer for complex anim/movements
		},
	};

// HUD script info structures
HUD_CHECKPOINT_ANIM_INFO	Hud_single_checkpoint_collect_anim[] = 
	{
		{	
		0,										// x
		0,										// y
		0,										// x vel
		0,										// y vel
		0,										// time (100+20 / 4)
		0,										// delay before moving
		0,										// Timer for complex anim/movements
		},
	};

// HUD script info structures
HUD_CHECKPOINT_ANIM_INFO	Hud_single_checkpoint_return_anim[] = 
	{
		{	
		0,										// x
		0,										// y
		0,										// x vel
		0,										// y vel
		0,										// time (100+20 / 4)
		0,										// delay before moving
		0,										// Timer for complex anim/movements
		},
	};

// HUD bonus score add anim
HUD_CHECKPOINT_ANIM_INFO	Hud_bonus_add_anim[] = 
	{
		{	
		(SYSTEM_DISPLAY_WIDTH/2),				// x
		(SYSTEM_DISPLAY_HEIGHT/2),				// y
		((SYSTEM_DISPLAY_WIDTH/2)<<16)/10,		// x vel
		((SYSTEM_DISPLAY_HEIGHT/2)<<16)/10,		// y vel
		30,										// time (100+20 / 4)
		0,										// delay before moving
		0,										// Timer for complex anim/movements
		},
	};

// HUD script info structures
HUD_CHECKPOINT_ANIM_INFO	Hud_gold_frog_collect_anim[] = 
	{
		{	
		0,										// x
		0,										// y
		0,										// x vel
		0,										// y vel
		0,										// time (100+20 / 4)
		0,										// delay before moving
		0,										// Timer for complex anim/movements
		},
	};

// HUD scripts
HUD_ITEM	HUD_script_one_viewport_player_1[] =
	{
		{	HUD_ITEM_SCORE,
			SYSTEM_DISPLAY_WIDTH 	- 16 - 48,
			16,
		},
		{	HUD_ITEM_TIMER,
			(SYSTEM_DISPLAY_WIDTH 	- HUD_ITEM_TIMER_WIDTH) / 2,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - HUD_ITEM_TIMER_HEIGHT - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - HUD_ITEM_TIMER_HEIGHT - 12,
#endif
		},
		{	HUD_ITEM_HELP,
			(SYSTEM_DISPLAY_WIDTH 	- HUD_ITEM_HELP_WIDTH) / 2,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 8 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 8 - 12,
#endif
		},
		{	HUD_ITEM_CHECKPOINTS,
			16,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 12,
#endif
		},
		{	HUD_ITEM_LIVES,
			SYSTEM_DISPLAY_WIDTH 	- 16,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 12,
#endif
			HUD_ITEM_FLIPPED,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_two_viewports_player_1[] =
	{
		{	HUD_ITEM_SCORE,
			16,
			16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			(SYSTEM_DISPLAY_WIDTH / 4) - (HUD_ITEM_HELP_WIDTH / 2),
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 12,
#endif
		},
		{	HUD_ITEM_CHECKPOINTS,
			16,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 12,
#endif
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_two_viewports_player_2[] =
	{
		{	HUD_ITEM_SCORE,
			SYSTEM_DISPLAY_WIDTH 	- 16 - 48,
			16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			((SYSTEM_DISPLAY_WIDTH * 3) / 4) - (HUD_ITEM_HELP_WIDTH / 2),
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 8 - 12,
#endif
		},
		{	HUD_ITEM_CHECKPOINTS,
			SYSTEM_DISPLAY_WIDTH 	- 16,
#ifdef PSX_MODE_PAL
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 6,
#else
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16 - 12,
#endif
			HUD_ITEM_FLIPPED,
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_four_viewports_player_1[] =
	{
		{	HUD_ITEM_SCORE,
			16,
			16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			(SYSTEM_DISPLAY_WIDTH / 4) - (HUD_ITEM_HELP_WIDTH / 2),
			(SYSTEM_DISPLAY_HEIGHT / 2) - 24,
		},
		{	HUD_ITEM_CHECKPOINTS,
			16,
			(SYSTEM_DISPLAY_HEIGHT / 2)	- 16 - 16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_four_viewports_player_2[] =
	{
		{	HUD_ITEM_SCORE,
			SYSTEM_DISPLAY_WIDTH 	- 16 - 48,
			16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			((SYSTEM_DISPLAY_WIDTH * 3) / 4) - (HUD_ITEM_HELP_WIDTH / 2),
			(SYSTEM_DISPLAY_HEIGHT / 2) - 24,
		},
		{	HUD_ITEM_CHECKPOINTS,
			SYSTEM_DISPLAY_WIDTH 	- 16,
			(SYSTEM_DISPLAY_HEIGHT / 2)	- 16 - 16,
			HUD_ITEM_FLIPPED,
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_four_viewports_player_3[] =
	{
		{	HUD_ITEM_SCORE,
			16,
			(SYSTEM_DISPLAY_HEIGHT / 2) + 16,
			16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			(SYSTEM_DISPLAY_WIDTH / 4) - (HUD_ITEM_HELP_WIDTH / 2),
			SYSTEM_DISPLAY_HEIGHT - 24,
		},
		{	HUD_ITEM_CHECKPOINTS,
			16,
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_four_viewports_player_4[] =
	{
		{	HUD_ITEM_SCORE,
			SYSTEM_DISPLAY_WIDTH 	- 16 - 48,
			(SYSTEM_DISPLAY_HEIGHT / 2) + 16,
		},
		{	HUD_ITEM_EMPTY,
		},
		{	HUD_ITEM_HELP,
			((SYSTEM_DISPLAY_WIDTH * 3) / 4) - (HUD_ITEM_HELP_WIDTH / 2),
			SYSTEM_DISPLAY_HEIGHT - 24,
		},
		{	HUD_ITEM_CHECKPOINTS,
			SYSTEM_DISPLAY_WIDTH 	- 16,
			SYSTEM_DISPLAY_HEIGHT 	- 16 - 16,
			HUD_ITEM_FLIPPED,
		},
		{	HUD_ITEM_EMPTY,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_start_level[] =
	{
		{	HUD_ITEM_LEVEL_START_GATHER,
			0,
			0,
			0,
			0,
			&Hud_checkpoint_anim_gather,
		},
		{	HUD_ITEM_LEVEL_START_SCATTER,
			0,
			0,
			0,
			0,
			&Hud_checkpoint_anim_split,
		},
		{
			HUD_ITEM_LEVEL_START_TIMER,
			(SYSTEM_DISPLAY_WIDTH 	- HUD_ITEM_TIMER_WIDTH) / 2,
#ifdef PSX_MODE_PAL
			(SYSTEM_DISPLAY_HEIGHT 	- 16 - 6 - HUD_ITEM_TIMER_HEIGHT),
#else
			(SYSTEM_DISPLAY_HEIGHT 	- 16 - 12 - HUD_ITEM_TIMER_HEIGHT),
#endif
		},
		{
			HUD_ITEM_BITMAP,
			((SYSTEM_DISPLAY_WIDTH>>1)+5),
#ifdef PSX_MODE_PAL
			(SYSTEM_DISPLAY_HEIGHT - 6 - HUD_ITEM_TIMER_HEIGHT - 64),
#else
			(SYSTEM_DISPLAY_HEIGHT - 12 - HUD_ITEM_TIMER_HEIGHT - 64),
#endif
			0,
			0,
			NULL,
			&im_hop_to_it,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_trigger_collected[] =
	{
		{	HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT,
			0,
			0,
			0,
			0,
			&Hud_single_checkpoint_collect_anim,
		},
		{
			HUD_ITEM_LEVEL_TIME,
			((SYSTEM_DISPLAY_WIDTH	- HUD_ITEM_TIMER_WIDTH) >> 1),
			((SYSTEM_DISPLAY_HEIGHT - HUD_ITEM_TIMER_HEIGHT) >> 1) - 15,
		},
		{
			HUD_ITEM_BITMAP,
			(SYSTEM_DISPLAY_WIDTH>>1) - 60,
			(SYSTEM_DISPLAY_HEIGHT>>1) + 8,
			0,
			0,
			NULL,
			&im_bonus,
		},
		{
			HUD_ITEM_LEVEL_BONUS,
			(SYSTEM_DISPLAY_WIDTH  - HUD_ITEM_TIMER_WIDTH) >> 1,
			((SYSTEM_DISPLAY_HEIGHT - HUD_ITEM_TIMER_HEIGHT) >> 1) + 10,
			0, 
			0,
			&Hud_bonus_add_anim,
		},
		{	HUD_ITEM_TRIGGER_RETURN_CHECKPOINT,
			0,
			0,
			0,
			0,
			&Hud_single_checkpoint_return_anim,
		},
		{NULL},
	};

HUD_ITEM	HUD_script_gold_frog[] =
	{
		{	HUD_ITEM_GOLD_FROG,
			0,
			0,
			0, 
			0,
			&Hud_gold_frog_collect_anim,

		},
		{NULL},
	};

MR_LONG		Hud_build_text_digits[3];

MR_UBYTE	Hud_digits[10];

MR_STRPTR	text_hud_score_words_right[]		= {"%jr%w UP",	(MR_STRPTR)&Hud_build_text_digits[0], (MR_STRPTR)1, NULL};
MR_STRPTR	text_hud_score_digits_right[]		= {"%jr%w",	  	(MR_STRPTR)&Hud_build_text_digits[0], (MR_STRPTR)6, NULL};
MR_STRPTR	text_hud_score_words_left[]			= {"%w UP",   	(MR_STRPTR)&Hud_build_text_digits[0], (MR_STRPTR)1, NULL};
MR_STRPTR	text_hud_score_digits_left[]		= {"%lw",	  	(MR_STRPTR)&Hud_build_text_digits[0], (MR_STRPTR)6, NULL};

// Help messages (in different languages)
MR_STRPTR	text_help_superjump[]				= {"%jcSUPERJUMP", NULL};
MR_STRPTR	text_help_tongue[]					= {"%jcTONGUE", NULL};
MR_STRPTR	text_help_croak[]					= {"%jcCROAK", NULL};

MR_STRPTR	text_help_superjump_i[]				= {"%jcSUPER SALTO", NULL};
MR_STRPTR	text_help_tongue_i[]				= {"%jcLINGUA", NULL};
MR_STRPTR	text_help_croak_i[]					= {"%jcGRACIDA", NULL};

MR_STRPTR	text_help_superjump_g[]				= {"%jcSUPER-SPRUNG", NULL};
MR_STRPTR	text_help_tongue_g[]				= {"%jcQUAK", NULL};
MR_STRPTR	text_help_croak_g[]					= {"%jcZUNGE", NULL};

MR_STRPTR	text_help_superjump_f[]				= {"%jcSUPER SAUT", NULL};
MR_STRPTR	text_help_tongue_f[]				= {"%jcLANGUE", NULL};
MR_STRPTR	text_help_croak_f[]					= {"%jcCOASSEMENT", NULL};

MR_STRPTR	text_help_superjump_s[]				= {"%jcSUPERSALTO", NULL};
MR_STRPTR	text_help_tongue_s[]				= {"%jcLENGUA", NULL};
MR_STRPTR	text_help_croak_s[]					= {"%jcCROAR", NULL};

// Cheats
MR_STRPTR	text_help_collision_on[]			= {"%jcCOLLISION ON", NULL};
MR_STRPTR	text_help_collision_off[]			= {"%jcCOLLISION OFF", NULL};
MR_STRPTR	text_help_timer_on[]				= {"%jcTIMER ON", NULL};
MR_STRPTR	text_help_timer_off[]				= {"%jcTIMER OFF", NULL};
MR_STRPTR	text_help_infinite_lives_on[]		= {"%jcINFINITE LIVES ON", NULL};
MR_STRPTR	text_help_infinite_lives_off[]		= {"%jcINFINITE LIVES OFF", NULL};
MR_STRPTR	text_help_polygon_warning[]			= {"%jcTOO MANY POLYGONS", NULL};
MR_STRPTR	text_help_all_levels_open[]			= {"%jcALL LEVELS OPEN", NULL};
MR_STRPTR	text_help_collect_checkpoint[]		= {"%jcCHECKPOINTS COLLECTED", NULL};
MR_STRPTR	text_help_collect_goldfrog[]		= {"%jcGOLDFROG COLLECTED", NULL};

MR_STRPTR*	Hud_item_help_messages[HUD_ITEM_HELP_TOTAL][MAX_NUM_LANGUAGES] =
	{
		{text_help_superjump,			text_help_superjump_i,			text_help_superjump_g,			text_help_superjump_f,			text_help_superjump_s},
		{text_help_tongue,				text_help_tongue_i,				text_help_tongue_g,				text_help_tongue_f,				text_help_tongue_s},
		{text_help_croak,				text_help_croak_i,				text_help_croak_g,				text_help_croak_f,				text_help_croak_s},
		{text_help_collision_on,		text_help_collision_on,			text_help_collision_on,			text_help_collision_on,			text_help_collision_on},
		{text_help_collision_off,		text_help_collision_off,		text_help_collision_off,		text_help_collision_off,		text_help_collision_off},
		{text_help_timer_on,			text_help_timer_on,				text_help_timer_on,				text_help_timer_on,				text_help_timer_on},
		{text_help_timer_off,			text_help_timer_off,			text_help_timer_off,			text_help_timer_off,			text_help_timer_off},
		{text_help_infinite_lives_on,	text_help_infinite_lives_on,	text_help_infinite_lives_on,	text_help_infinite_lives_on,	text_help_infinite_lives_on},
		{text_help_infinite_lives_off,	text_help_infinite_lives_off,	text_help_infinite_lives_off,	text_help_infinite_lives_off,	text_help_infinite_lives_off},
		{text_help_polygon_warning,		text_help_polygon_warning,		text_help_polygon_warning,		text_help_polygon_warning,		text_help_polygon_warning},
		{text_help_all_levels_open,		text_help_all_levels_open,		text_help_all_levels_open,		text_help_all_levels_open,		text_help_all_levels_open},
		{text_help_collect_checkpoint,	text_help_collect_checkpoint,	text_help_collect_checkpoint,	text_help_collect_checkpoint,	text_help_collect_checkpoint},
		{text_help_collect_goldfrog,	text_help_collect_goldfrog,		text_help_collect_goldfrog,		text_help_collect_goldfrog,		text_help_collect_goldfrog},	
	};


MR_TEXTURE*	Hud_timer_images[] =
	{
	&im_32x32_0,
	&im_32x32_1,
	&im_32x32_2,
	&im_32x32_3,
	&im_32x32_4,
	&im_32x32_5,
	&im_32x32_6,
	&im_32x32_7,
	&im_32x32_8,
	&im_32x32_9,
	&im_32x32_colon,
	};

// Score images
MR_TEXTURE*	Hud_score_images[] =
	{
	&im_med_0,
	&im_med_1,
	&im_med_2,
	&im_med_3,
	&im_med_4,
	&im_med_5,
	&im_med_6,
	&im_med_7,
	&im_med_8,
	&im_med_9,
	};

// Checkpoint animlists

// Green frog
MR_ULONG	Animlist_hud_checkpoint_1[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog1_6,
	MR_SPRT_LOOPBACK
	};

// Orange frog
MR_ULONG	Animlist_hud_checkpoint_2[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog2_6,
	MR_SPRT_LOOPBACK
	};

// Purple frog
MR_ULONG	Animlist_hud_checkpoint_3[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog3_6,
	MR_SPRT_LOOPBACK
	};

// Cyan frog
MR_ULONG	Animlist_hud_checkpoint_4[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog4_6,
	MR_SPRT_LOOPBACK
	};

// Red frog
MR_ULONG	Animlist_hud_checkpoint_5[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfrog5_6,
	MR_SPRT_LOOPBACK
	};

// Red frog
MR_ULONG	Animlist_hud_gold_frog[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_6,
	MR_SPRT_LOOPBACK
	};


MR_ULONG*	Hud_checkpoint_animlists[] =
	{
	Animlist_hud_checkpoint_1,
	Animlist_hud_checkpoint_2,
	Animlist_hud_checkpoint_3,
	Animlist_hud_checkpoint_4,
	Animlist_hud_checkpoint_5,
	};

// Multiplayer Checkpoint animlists

// Green flag
MR_ULONG	Animlist_hud_checkpoint_multiplayer_1[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag1_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag1_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag1_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag1_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag1_4,
	MR_SPRT_LOOPBACK
	};

// Orange flag
MR_ULONG	Animlist_hud_checkpoint_multiplayer_2[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag2_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag2_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag2_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag2_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag2_4,
	MR_SPRT_LOOPBACK
	};

// Purple flag
MR_ULONG	Animlist_hud_checkpoint_multiplayer_3[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag3_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag3_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag3_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag3_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag3_4,
	MR_SPRT_LOOPBACK
	};

// Cyan flag
MR_ULONG	Animlist_hud_checkpoint_multiplayer_4[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag4_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag4_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag4_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag4_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag4_4,
	MR_SPRT_LOOPBACK
	};

// Red flag
MR_ULONG	Animlist_hud_checkpoint_multiplayer_5[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag5_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag5_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag5_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag5_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_flag5_4,
	MR_SPRT_LOOPBACK
	};

MR_ULONG*	Hud_checkpoint_multiplayer_animlists[] =
	{
	Animlist_hud_checkpoint_multiplayer_1,
	Animlist_hud_checkpoint_multiplayer_2,
	Animlist_hud_checkpoint_multiplayer_3,
	Animlist_hud_checkpoint_multiplayer_4,
	Animlist_hud_checkpoint_multiplayer_5,
	};

// Lives animlists
MR_ULONG	Animlist_hud_lives_icon_small[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lifes1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lifes2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lifes3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lifes4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lifes5,
	MR_SPRT_LOOPBACK
	};

MR_ULONG	Animlist_hud_lives_icon_big[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lives_bg1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lives_bg2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lives_bg3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lives_bg4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_lives_bg5,
	MR_SPRT_LOOPBACK
	};


MR_CVEC	Hud_font_colours[] = 
		{
			{0x80,0x80,0x80},		// MR_FONT_COLOUR_WHITE
			{0x01,0x01,0x01},		// MR_FONT_COLOUR_BLACK
			{0x80,0x00,0x00},		// MR_FONT_COLOUR_RED
			{0x00,0x80,0x00},		// MR_FONT_COLOUR_GREEN
			{0x00,0x00,0x80},		// MR_FONT_COLOUR_BLUE
			{0x00,0x80,0x80},		// MR_FONT_COLOUR_CYAN
			{0x80,0x00,0x80},		// MR_FONT_COLOUR_MAGENTA
			{0x80,0x80,0x00},		// MR_FONT_COLOUR_YELLOW
			{0xa0,0x60,0x20},		// MR_FONT_COLOUR_BROWN
			{0x50,0x50,0x50},		// MR_FONT_COLOUR_GREY
			{0x30,0x30,0x30},		// MR_FONT_COLOUR_DARK_GREY
			{0x20,0x20,0x50},		// MR_FONT_COLOUR_DARK_BLUE
			{0x01,0x01,0x01},		// MR_FONT_COLOUR_NEAR_BLACK
			{0xff,0x64,0x00},		// MR_FONT_COLOUR_CADMIUM
			{0x80,0x50,0x10},		// MR_FONT_COLOUR_ORANGE
		};



MR_USHORT	Hud_item_help_flags[SYSTEM_MAX_VIEWPORTS][HUD_ITEM_HELP_TOTAL];
MR_ULONG	Hud_bonus_score;

POLY_F4*	Hud_score_background_f[SYSTEM_MAX_VIEWPORTS][2];
POLY_FT3*	Hud_score_background_ft[SYSTEM_MAX_VIEWPORTS][2];

/******************************************************************************
*%%%% InitialiseHUD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseHUD(MR_VOID)
*
*	FUNCTION	Set up HUD and HUD scripts, setting ptrs in FROGs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*	04.07.97	Martin Kift		Added score f4 backgrounds
*
*%%%**************************************************************************/

MR_VOID	InitialiseHUD(MR_VOID)
{
	MR_ULONG	i;
	
	// Alloc space for background polys behind scores
	Hud_score_background_f[0][0] = MRAllocMem(sizeof(POLY_F4) * 2 * Game_total_viewports, "HUD score background polys");
	Hud_score_background_f[0][1] = Hud_score_background_f[0][0] + 1;
	for (i = 1; i < Game_total_viewports; i++)
		{
		Hud_score_background_f[i][0] = Hud_score_background_f[i - 1][1] + 1;
		Hud_score_background_f[i][1] = Hud_score_background_f[i][0] + 1;
		}
	Hud_score_background_ft[0][0] = MRAllocMem(sizeof(POLY_FT3) * 2 * Game_total_viewports, "HUD score background polys");
	Hud_score_background_ft[0][1] = Hud_score_background_ft[0][0] + 1;
	for (i = 1; i < Game_total_viewports; i++)
		{
		Hud_score_background_ft[i][0] = Hud_score_background_ft[i - 1][1] + 1;
		Hud_score_background_ft[i][1] = Hud_score_background_ft[i][0] + 1;
		}

	// Set API to point at our Font Table.
	MRSetFontColourTable(Hud_font_colours);
	MR_COPY32(Hud_font_colours[MR_FONT_COLOUR_GREY + 0], Game_border_colours[0]);
	MR_COPY32(Hud_font_colours[MR_FONT_COLOUR_GREY + 1], Game_border_colours[1]);
	MR_COPY32(Hud_font_colours[MR_FONT_COLOUR_GREY + 2], Game_border_colours[2]);
	MR_COPY32(Hud_font_colours[MR_FONT_COLOUR_GREY + 3], Game_border_colours[3]);

	// Initialise game hud
	switch(Game_total_viewports)
		{
		//----------------------------------------------------------------------
		case 1:
			// 1 viewport, 1 player
			ResetHUDScript(HUD_script_one_viewport_player_1);
			Frogs[0].fr_hud_script = SetupHUDScript(HUD_script_one_viewport_player_1, 0);
			break;
		//----------------------------------------------------------------------
		case 2:
			// 2 viewports, 2 players
			ResetHUDScript(HUD_script_two_viewports_player_1);
			ResetHUDScript(HUD_script_two_viewports_player_2);

			Frogs[0].fr_hud_script = SetupHUDScript(HUD_script_two_viewports_player_1, 0);
			Frogs[1].fr_hud_script = SetupHUDScript(HUD_script_two_viewports_player_2, 1);
			break;
		//----------------------------------------------------------------------
		case 4:
			// (3 or 4) viewports, (3 or 4) players
			ResetHUDScript(HUD_script_four_viewports_player_4);
			Frogs[3].fr_hud_script = SetupHUDScript(HUD_script_four_viewports_player_4, 3);

		case 3:
			ResetHUDScript(HUD_script_four_viewports_player_1);
			ResetHUDScript(HUD_script_four_viewports_player_2);
			ResetHUDScript(HUD_script_four_viewports_player_3);
			Frogs[0].fr_hud_script = SetupHUDScript(HUD_script_four_viewports_player_1, 0);
			Frogs[1].fr_hud_script = SetupHUDScript(HUD_script_four_viewports_player_2, 1);
			Frogs[2].fr_hud_script = SetupHUDScript(HUD_script_four_viewports_player_3, 2);
			break;
		//----------------------------------------------------------------------
		}
	

	// Reset HUD_ITEM_HELP flags
	MR_CLEAR(Hud_item_help_flags);
}

/******************************************************************************
*%%%% DeinitialiseHUD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeinitialiseHUD(MR_VOID)
*
*	FUNCTION	Kill HUDs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.06.97	William Bell	Created
*	11.08.97	Gary Richards	Added code to free the background sprite alloc.
*
*%%%**************************************************************************/

MR_VOID DeinitialiseHUD(MR_VOID)
{

	switch(Game_total_viewports)
		{
		//----------------------------------------------------------------------
		case 1:
			KillHUDScript(Frogs[0].fr_hud_script);
			break;
		//----------------------------------------------------------------------
		case 2:
			KillHUDScript(Frogs[0].fr_hud_script);
			KillHUDScript(Frogs[1].fr_hud_script);
			break;
		//----------------------------------------------------------------------
		case 4:
			KillHUDScript(Frogs[3].fr_hud_script);

		case 3:
			KillHUDScript(Frogs[0].fr_hud_script);
			KillHUDScript(Frogs[1].fr_hud_script);
			KillHUDScript(Frogs[2].fr_hud_script);
			break;
		//----------------------------------------------------------------------
		}

	// Free Alloc space for background polys behind scores
	MRFreeMem(Hud_score_background_f[0][0]);
	MRFreeMem(Hud_score_background_ft[0][0]);
}

/******************************************************************************
*%%%% StartHUD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	StartHUD(MR_VOID)
*
*	FUNCTION	Start HUD for this frame
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	StartHUD(MR_VOID)
{
}


/******************************************************************************
*%%%% UpdateHUD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateHUD(MR_VOID)
*
*	FUNCTION	Updates the hud for any players
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdateHUD(MR_VOID)
{
	MR_ULONG		i;
	MR_VIEWPORT*	vp;


	vp = Game_viewporth;
	for (i = 0; i < Game_total_players; i++)
		{
		if (Frogs[i].fr_hud_script)
			{
			UpdateHUDScript(Frogs[i].fr_hud_script, i);
			}

		// Add viewport borders at back of overlay viewport (for multiplayer)
#ifdef GAME_VIEWPORT_BORDERS
		if (Game_total_players > 1)
			{
			addPrim(vp->vp_work_ot + vp->vp_ot_size - 1, &Game_viewport_borders[i][MRFrame_index][0]);
			addPrim(vp->vp_work_ot + vp->vp_ot_size - 1, &Game_viewport_borders[i][MRFrame_index][1]);
			}
#endif
		}
}


/******************************************************************************
*%%%% UpdateHUDScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateHUDScript(
*						HUD_ITEM*	item,
*						MR_ULONG	id)
*
*	FUNCTION	Update items in a HUD script
*
*	INPUTS		item	-	ptr to first HUD_ITEM in script array
*				id		-	player id (0..3)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*	11.06.97	Martin Kift		Tinkered with checkpoint hud code.
*	05.07.97	Martin Kift		Added new checkpoint anim code (for level init)
*	14.08.97	Gary Richards	Added Tick 'n' Tock for timer count down.
*
*%%%**************************************************************************/

MR_VOID	UpdateHUDScript(	HUD_ITEM*	item,
							MR_ULONG	id)
{
	MR_TEXTURE*					texture;
	FROG*						frog;
	MR_LONG						d, i, j, k;
	MR_2DSPRITE**				sprite_pptr;
	POLY_FT3*					poly_ft3;
	POLY_F4*					poly_f4;
	POLY_G4*					poly_g4;
	MR_2DSPRITE*				sprite_ptr;
	HUD_CHECKPOINT_ANIM_INFO*	checkpoint_anim_info;
	MR_BOOL						finished_flag;
	MR_LONG						digit_a, digit_b, digit_c;
	MR_LONG						temp_map_timer;
	MRSND_VOLUME				game_timer_vol;

	MR_ASSERT(item);

	frog 		= &Frogs[id];

	while(item->hi_type)
		{
		if (!(item->hi_flags & HUD_ITEM_NO_UPDATE))
			{
			texture = item->hi_texture;
			switch(item->hi_type)
				{
				//--------------------------------------------------------------------
				case HUD_ITEM_SCORE:
					if (Game_flags & GAME_FLAG_HUD_SCORE)
						{	
						if (item->hi_flags & HUD_ITEM_REBUILD)
							{
							if ( Sel_mode == SEL_MODE_ARCADE )
								{
								// Rebuild digit text
								item->hi_flags &= ~HUD_ITEM_REBUILD;
								Hud_build_text_digits[0] = frog->fr_score;
			
								// If multi-player, score text is colour of frog
								if (Game_total_viewports > 1)
									j = MR_FONT_COLOUR_GREY + Frog_player_data[id].fp_player_id;
								else
									j = MR_FONT_COLOUR_WHITE;

								if 	(
									(Game_total_viewports > 1) &&
									(!(id & 1))
									)
									// Left justify score
									MRBuildText(item->hi_api_1, text_hud_score_digits_left,		j);
								else						
									// Right justify score
									MRBuildText(item->hi_api_1, text_hud_score_digits_right,	j);
								}
							}
							addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - 1, Hud_score_background_f[id][MRFrame_index]);
							addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - 1, Hud_score_background_ft[id][MRFrame_index]);
						}
					break;	
				//--------------------------------------------------------------------
				case HUD_ITEM_TIMER:
					if (Game_flags & GAME_FLAG_HUD_TIMER)
						{	
						// Update digits
						d = (Game_map_timer + 29) / 30;
						// Don't show digits during "time bonus"
						if ( (d <= HUD_ITEM_TIMER_DIGIT_TIME) && !(Game_mode & GAME_MODE_SINGLE_TRIGGER_COLLECTED) )
							{
							// Display digits
							MRChangeSprite(item->hi_api_0, Hud_timer_images[d / 10]);
							MRChangeSprite(item->hi_api_1, Hud_timer_images[d % 10]);
							((MR_SP_CORE*)item->hi_api_0)->sc_flags &= ~MR_SPF_NO_DISPLAY;
							((MR_SP_CORE*)item->hi_api_1)->sc_flags &= ~MR_SPF_NO_DISPLAY;

							// Colour digits
							d = (Game_map_timer % 30) * 3;
							((MR_SP_CORE*)item->hi_api_0)->sc_base_colour.r = d;
							((MR_SP_CORE*)item->hi_api_1)->sc_base_colour.r = d;
							// Wait for game to start.
							if (!Game_start_timer)
								{
							// Play Sound Effects of Clock ticking down.
							if (Game_map_timer <= 300)					// Less than 10 seconds.
								{
								// Start TimeOut music with 2 seconds to go.
								if (Game_map_timer == 55)
									MRSNDPlaySound(SFX_MUSIC_TIMEOUT, NULL, 0, 0);

								temp_map_timer = Game_map_timer / 15;	// Only Div once.
	
								game_timer_vol.left  = (127 - (temp_map_timer << 2));
								game_timer_vol.right = (127 - (temp_map_timer << 2));
								// Check for a change in time.
								if (temp_map_timer != Game_last_map_timer)
									{
									if (temp_map_timer & 1)
										{
										MRSNDPlaySound(SFX_GEN_CLOCK_TICK, NULL, 0, 0);
										}
									else
										{
										if (temp_map_timer)
											{
											MRSNDPlaySound(SFX_GEN_CLOCK_TOCK, NULL, 0, 0);
											}
										}
									// So we only get one sound/half second.
									Game_last_map_timer = temp_map_timer;
									}
								}
								}
							}
						else
							{
							((MR_SP_CORE*)item->hi_api_0)->sc_flags |= MR_SPF_NO_DISPLAY;
							((MR_SP_CORE*)item->hi_api_1)->sc_flags |= MR_SPF_NO_DISPLAY;
							}

						// Render bar
						poly_ft3 	= (POLY_FT3*)item->hi_polys[MRFrame_index];
						poly_f4 	= (POLY_F4*)(poly_ft3 + 1);
						addPrim(Game_viewporth->vp_work_ot + 1, poly_f4);
						addPrim(Game_viewporth->vp_work_ot + 1, poly_ft3);

						poly_ft3 	= (POLY_FT3*)(poly_f4 + 1);
						poly_g4 	= (POLY_G4*)(poly_ft3 + 1);
						addPrim(Game_viewporth->vp_work_ot + 1, poly_ft3);
						addPrim(Game_viewporth->vp_work_ot + 1, poly_g4);

						// Alter bar coords/colours
						poly_g4->x1 = item->hi_x + 1 + (((HUD_ITEM_TIMER_WIDTH - 2) * Game_map_timer) / HUD_ITEM_TIMER_MAX_TIME);
						poly_g4->x3 = poly_g4->x1;
						d			= ((0xc0 * Game_map_timer) / HUD_ITEM_TIMER_MAX_TIME);
						poly_g4->g1 = d + 0x20;
						poly_g4->g3 = d + 0x20;
						poly_g4->r1 = (0xc0 - d) + 0x20;
						poly_g4->r3 = (0xc0 - d) + 0x20;

						// Has time limit reached zero, if so request anim
//						if ( Game_map_timer == 0 )
//							FrogRequestAnimation(frog, FROG_ANIMATION_TIMEOUT, 0, 0);
						}
					break;
				//--------------------------------------------------------------------
				case HUD_ITEM_HELP:
					if (Game_flags & GAME_FLAG_HUD_HELP)
						{	
						if (item->hi_flags & HUD_ITEM_FADE_UP)
							{
							((MR_TEXT_AREA*)item->hi_api_0)->ta_display = TRUE;
							MRSetTextColour(item->hi_api_0, MRFrame_index, ((HUD_ITEM_FADE_DURATION - item->hi_timer) << 3) * 0x010101);
							if (item->hi_api_1)
								{
								((MR_TEXT_AREA*)item->hi_api_1)->ta_display = TRUE;
								MRSetTextColour(item->hi_api_1, MRFrame_index, ((HUD_ITEM_FADE_DURATION - item->hi_timer) << 3) * 0x010101);
								}
							if (!(--item->hi_timer))
								{
								item->hi_flags &= ~HUD_ITEM_FADE_UP;
								item->hi_flags |= HUD_ITEM_HOLD;
								item->hi_timer	= HUD_ITEM_HOLD_DURATION;
								}
							}
						else
						if (item->hi_flags & HUD_ITEM_FADE_DOWN)
							{
							MRSetTextColour(item->hi_api_0, MRFrame_index, ((item->hi_timer) << 3) * 0x010101);
							if (item->hi_api_1)
								MRSetTextColour(item->hi_api_1, MRFrame_index, ((item->hi_timer) << 3) * 0x010101);
							if (!(--item->hi_timer))
								{
								item->hi_flags &= ~HUD_ITEM_FADE_DOWN;
								((MR_TEXT_AREA*)item->hi_api_0)->ta_display = FALSE;
								if (item->hi_api_1)
									((MR_TEXT_AREA*)item->hi_api_1)->ta_display = FALSE;
								}
							}
						else
						if (item->hi_flags & HUD_ITEM_HOLD)
							{
							if (item->hi_timer > HUD_ITEM_HOLD_DURATION - 2)
								{
								MRSetTextColour(item->hi_api_0, MRFrame_index, (HUD_ITEM_FADE_DURATION << 3) * 0x010101);
								if (item->hi_api_1)
									MRSetTextColour(item->hi_api_1, MRFrame_index, (HUD_ITEM_FADE_DURATION << 3) * 0x010101);
								}
							if (!(--item->hi_timer))
								{
								item->hi_flags &= ~HUD_ITEM_HOLD;
								item->hi_flags |= HUD_ITEM_FADE_DOWN;
								item->hi_timer	= HUD_ITEM_FADE_DURATION;
								}
							}				
						else
						if (item->hi_flags & HUD_ITEM_PREDELAY)
							{
							if (!(--item->hi_timer))
								{
								item->hi_flags &= ~HUD_ITEM_PREDELAY;
								item->hi_flags |= HUD_ITEM_FADE_UP;
								item->hi_timer	= HUD_ITEM_FADE_DURATION;
								}				
							}
						}
					break;	
				//--------------------------------------------------------------------
				case HUD_ITEM_CHECKPOINTS:
					if (Game_flags & GAME_FLAG_HUD_CHECKPOINTS)
						{
						d = item->hi_x;
						for (i = 0; i < GEN_MAX_CHECKPOINTS; i++)
							{
							sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0 + i;

							if	(
								(Checkpoint_data[i].cp_frog_collected_id == (MR_LONG)id) &&
								!(Checkpoint_data[i].cp_flags & GEN_CHECKPOINT_NO_HUD_UPDATE)
								)
								{
								if (item->hi_flags & HUD_ITEM_FLIPPED)
									d -= 16;
	
								((MR_SP_CORE*)(*sprite_pptr))->sc_flags &= ~MR_SPF_NO_DISPLAY;
								((MR_2DSPRITE*)(*sprite_pptr))->sp_pos.x = d;

								if (!(item->hi_flags & HUD_ITEM_FLIPPED))
									d += 16;
								}
							else
								{
								((MR_SP_CORE*)(*sprite_pptr))->sc_flags |= MR_SPF_NO_DISPLAY;
								}
							sprite_pptr++;
							}
						}
					break;
				//--------------------------------------------------------------------
				case HUD_ITEM_LIVES:
					if (Game_flags & GAME_FLAG_HUD_LIVES)
						{
						if (item->hi_flags & HUD_ITEM_REBUILD)
							{
							item->hi_flags &= ~HUD_ITEM_REBUILD;

							sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
							d			= item->hi_x;

							// Only display up to FROG_MAX_LIVES, even if we have more
							k = MAX(0,frog->fr_lives-1);
							if (k = MIN(FROG_MAX_LIVES, k))
								{
								i =  (k - 1) / HUD_ITEM_LIVES_BIG_VALUE;		// number of big icons
								j = ((k - 1) % HUD_ITEM_LIVES_BIG_VALUE) + 1;	// number of small icons
								}
							else
								{
								i = 0;
								j = 0;
								}

							k = HUD_ITEM_LIVES_MAX_ICONS - (i + j);
							MR_ASSERT(k >= 0);

							// Big icons
							while(i--)
								{
								((MR_SP_CORE*)(*sprite_pptr))->sc_flags &= ~MR_SPF_NO_DISPLAY;

								if (item->hi_flags & HUD_ITEM_FLIPPED)
									d -= 30;

								if ( ((MR_SP_CORE*)(*sprite_pptr))->sc_alist_addr != (MR_LONG*)&Animlist_hud_lives_icon_big[0] )
									MRChangeSprite(*sprite_pptr, Animlist_hud_lives_icon_big);
								((MR_2DSPRITE*)(*sprite_pptr))->sp_pos.x = d;
								((MR_2DSPRITE*)(*sprite_pptr))->sp_pos.y = item->hi_y - 14 - 18;

								if (!(item->hi_flags & HUD_ITEM_FLIPPED))
									d += 30;

								sprite_pptr++;
								}

							// Small icons
							d			= item->hi_x;
							while(j--)
								{
								((MR_SP_CORE*)(*sprite_pptr))->sc_flags &= ~MR_SPF_NO_DISPLAY;

								if (item->hi_flags & HUD_ITEM_FLIPPED)
									d -= 24;

								if ( ((MR_SP_CORE*)(*sprite_pptr))->sc_alist_addr != (MR_LONG*)&Animlist_hud_lives_icon_small[0] )
									MRChangeSprite(*sprite_pptr, Animlist_hud_lives_icon_small);
								((MR_2DSPRITE*)(*sprite_pptr))->sp_pos.x = d;
								((MR_2DSPRITE*)(*sprite_pptr))->sp_pos.y = item->hi_y - 14;

								if (!(item->hi_flags & HUD_ITEM_FLIPPED))
									d += 24;

								sprite_pptr++;
								}

							// Turned unused icons off
							while(k--)
								{
								((MR_SP_CORE*)(*sprite_pptr))->sc_flags |= MR_SPF_NO_DISPLAY;
								sprite_pptr++;
								}
							}
						}
					break;
				//--------------------------------------------------------------------
				case HUD_ITEM_LEVEL_START_GATHER:
				case HUD_ITEM_LEVEL_START_SCATTER:
					finished_flag			= TRUE;
					checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;

					for (i = 0; i < GEN_MAX_CHECKPOINTS; i++)
						{
						sprite_pptr			= (MR_2DSPRITE**)item->hi_api_0 + i;
						sprite_ptr			= (MR_2DSPRITE*)(*sprite_pptr);

						switch (checkpoint_anim_info->hc_mode)
							{
							case HUD_ITEM_ANIM_DELAY:
								// has sprite has not delay period
								if (!(checkpoint_anim_info->hc_anim_timer--))
									{
									checkpoint_anim_info->hc_anim_timer = checkpoint_anim_info->hc_timer;
									checkpoint_anim_info->hc_mode		= HUD_ITEM_ANIM_UPDATE;
									}
								((MR_SP_CORE*)sprite_ptr)->sc_flags	&= ~MR_SPF_NO_DISPLAY;
								finished_flag = FALSE;
								break;

							case HUD_ITEM_ANIM_UPDATE:
								((MR_SP_CORE*)sprite_ptr)->sc_flags	&= ~MR_SPF_NO_DISPLAY;

								// has sprite has not reached it's destination, update
								if (checkpoint_anim_info->hc_anim_timer--)
									{
									checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
									checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
									sprite_ptr->sp_pos.x			= checkpoint_anim_info->hc_pos_x>>16;
									sprite_ptr->sp_pos.y			= checkpoint_anim_info->hc_pos_y>>16;
									finished_flag					= FALSE;
									}
								else
									checkpoint_anim_info->hc_mode		= HUD_ITEM_ANIM_FINISHED;
								break;

							case HUD_ITEM_ANIM_FINISHED:
								break;
							}
						sprite_pptr++;
						checkpoint_anim_info++;
						}
						
					// if all sprites have finished moving, mark this item as no update
					// and move on to the next one
					if	(finished_flag)
						{
						for (i = 0; i < GEN_MAX_CHECKPOINTS; i++)
							{
							sprite_pptr		= (MR_2DSPRITE**)item->hi_api_0 + i;
							((MR_SP_CORE*)*sprite_pptr)->sc_flags	|= MR_SPF_NO_DISPLAY;
							}
						item->hi_flags |= (HUD_ITEM_NO_UPDATE|HUD_ITEM_FINISHED);

						// dependent on which we are in, switch on/off any following HUDS
						// (this is hard coded at the moment)
						if (item->hi_type == HUD_ITEM_LEVEL_START_GATHER)
							{
							// turn on following item(s)
							(item+1)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							(item+2)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							(item+3)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							}
						}
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_LEVEL_START_TIMER:
					((MR_SP_CORE*)item->hi_api_0)->sc_flags &= ~MR_SPF_NO_DISPLAY;
					((MR_SP_CORE*)item->hi_api_1)->sc_flags &= ~MR_SPF_NO_DISPLAY;

					if (Game_map_timer > (MR_LONG)(Game_map_time * 30))
						{
						item->hi_flags |= (HUD_ITEM_NO_UPDATE|HUD_ITEM_FINISHED);
						Game_map_timer = (Game_map_time * 30);
						}
					else
						Game_map_timer += 30;
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_LEVEL_TIME:
					((MR_SP_CORE*)item->hi_api_0)->sc_flags &= ~MR_SPF_NO_DISPLAY;
					((MR_SP_CORE*)item->hi_api_1)->sc_flags &= ~MR_SPF_NO_DISPLAY;
					item->hi_flags |= (HUD_ITEM_FINISHED);
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT:
					checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;
					sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;

					// has sprite has not reached it's destination, update
					((MR_SP_CORE*)sprite_ptr)->sc_flags	&= ~MR_SPF_NO_DISPLAY;

					// is timer still valid?
					if (checkpoint_anim_info->hc_timer)
						{
						// Have we pressed fire to skip ?
						if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
							{
							FROG_CLEAR_PAD_PRESSED(Frog_input_ports[0], FR_GO);

							// set timer to 1, which make make the timer stop later this frame
							while (checkpoint_anim_info->hc_timer > 1)
								{
								checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
								checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
								checkpoint_anim_info->hc_timer--;
								}
							}

						checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
						checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
						sprite_ptr->sp_pos.x			= checkpoint_anim_info->hc_pos_x>>16;
						sprite_ptr->sp_pos.y			= checkpoint_anim_info->hc_pos_y>>16;

						if (!(--checkpoint_anim_info->hc_timer))
							{
							((MR_SP_CORE*)sprite_ptr)->sc_flags	|= MR_SPF_NO_DISPLAY;
							item->hi_flags |= HUD_ITEM_FINISHED;

							// turn on next item(s)
							(item+1)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							(item+2)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							(item+3)->hi_flags &= ~HUD_ITEM_NO_UPDATE;
							}
						}
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_TRIGGER_RETURN_CHECKPOINT:
					checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;
					sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;

					((MR_SP_CORE*)sprite_ptr)->sc_flags	&= ~MR_SPF_NO_DISPLAY;

					// TURN OFF THE COLLECT CHECKPOINT (currently hard coded!)
					(item-4)->hi_flags |= (HUD_ITEM_NO_UPDATE);

					// has sprite has not reached it's destination, update
					if (checkpoint_anim_info->hc_timer)
						{
						// Have we pressed fire to skip ?
						if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
							{
							FROG_CLEAR_PAD_PRESSED(Frog_input_ports[0], FR_GO);

							// set timer to 1, which make make the timer stop later this frame
							while (checkpoint_anim_info->hc_timer > 1)
								{
								checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
								checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
								checkpoint_anim_info->hc_timer--;
								}
							}

						checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
						checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
						sprite_ptr->sp_pos.x			= checkpoint_anim_info->hc_pos_x>>16;
						sprite_ptr->sp_pos.y			= checkpoint_anim_info->hc_pos_y>>16;

						if (!(--checkpoint_anim_info->hc_timer))
							{
							((MR_SP_CORE*)sprite_ptr)->sc_flags	|= MR_SPF_NO_DISPLAY;
							item->hi_flags |= (HUD_ITEM_NO_UPDATE|HUD_ITEM_FINISHED);
							}
						}
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_BITMAP:
					sprite_ptr								= (MR_2DSPRITE*)item->hi_api_0;
					((MR_SP_CORE*)sprite_ptr)->sc_flags		&= ~MR_SPF_NO_DISPLAY;
					item->hi_flags |= HUD_ITEM_FINISHED;
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_LEVEL_BONUS:
					// Count down the timer (for time left in game, adding FROG_TIMER_BONUS_SCORE
					// to the bonus score for every second left)

					sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
					sprite_pptr += (HUD_MAX_BONUS_DIGITS-1);

					// Have we pressed fire to skip ?
					if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
						{
						FROG_CLEAR_PAD_PRESSED(Frog_input_ports[0], FR_GO);

						// Yes ... end
						item->hi_timer = HUD_ITEM_BONUS_COUNT_ADD;

						// Add on remaing score
						while (Game_map_timer)
							{
							if ( (Game_map_timer-30) < 0 )
								{
								Game_map_timer = 0;
								}
							else
								{
								Game_map_timer -= 30;
								Hud_bonus_score += FROG_TIMER_BONUS_SCORE;
								}
							}
							HUDGetDigits(Hud_bonus_score, &digit_a, &digit_b, &digit_c);
							for (i=0; i<HUD_MAX_BONUS_DIGITS; i++)
								{
								MRChangeSprite(*sprite_pptr, Hud_score_images[Hud_digits[9-i]]);
								((MR_SP_CORE*)*sprite_pptr--)->sc_flags &= ~MR_SPF_NO_DISPLAY;
								}
						}

					switch (item->hi_timer)
						{
						case HUD_ITEM_BONUS_COUNT_UP:
							if (Game_map_timer)
								{
								if ((Game_map_timer - 30) < 0)
									{
									Game_map_timer = 0;
									break;
									}

								// dec game timer
								Game_map_timer -= 10;
								if ((Game_map_timer % 30) == 0)
									Hud_bonus_score += FROG_TIMER_BONUS_SCORE;

								// Play SFX for each digit.
								MRSNDPlaySound(SFX_GEN_CLOCK_TICK, NULL, 0, 0);

								HUDGetDigits(Hud_bonus_score, &digit_a, &digit_b, &digit_c);
								for (i=0; i<HUD_MAX_BONUS_DIGITS; i++)
									{
									MRChangeSprite(*sprite_pptr, Hud_score_images[Hud_digits[9-i]]);
									((MR_SP_CORE*)*sprite_pptr--)->sc_flags &= ~MR_SPF_NO_DISPLAY;
									}
								}
							else
								item->hi_timer = HUD_ITEM_BONUS_COUNT_ADD;
							break;

						case HUD_ITEM_BONUS_COUNT_ADD:
							// Add to score
							AddFrogPoints(&Frogs[0], Hud_bonus_score);
										   	
							item->hi_flags		|= (HUD_ITEM_FINISHED | HUD_ITEM_NO_UPDATE);
							(item+1)->hi_flags	&= ~HUD_ITEM_NO_UPDATE;
							(item-3)->hi_flags	|= HUD_ITEM_NO_UPDATE;
							break;
						}
					// Missing break ???
					break;

				//--------------------------------------------------------------------
				case HUD_ITEM_GOLD_FROG:
					checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;
					sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;

					if (checkpoint_anim_info->hc_timer)
						{
						checkpoint_anim_info->hc_pos_x += checkpoint_anim_info->hc_velocity_x;
						checkpoint_anim_info->hc_pos_y += checkpoint_anim_info->hc_velocity_y;
						sprite_ptr->sp_pos.x			= checkpoint_anim_info->hc_pos_x>>16;
						sprite_ptr->sp_pos.y			= checkpoint_anim_info->hc_pos_y>>16;
						checkpoint_anim_info->hc_timer--;
						}
					break;
				}
			}	
		item++;
		}
}


/******************************************************************************
*%%%% ResetHUDScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetHUDScript(
*						HUD_ITEM*	item)
*
*	FUNCTION	Reset a HUD script (clear ptrs)
*
*	INPUTS		item	-	ptr to first item
*
*	NOTES		This does NOT free memory or API items already set in the script
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResetHUDScript(HUD_ITEM*	item)
{
	MR_ASSERT(item);


	while(item->hi_type)
		{
		item->hi_api_0		= NULL;
		item->hi_api_1		= NULL;
		item->hi_extra		= NULL;
		item->hi_polys[0]	= NULL;
		item->hi_polys[1]	= NULL;
		item->hi_timer		= 0;
		item++;
		}
}


/******************************************************************************
*%%%% SetupHUDScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	HUD_ITEM*	item =	SetupHUDScript(
*									HUD_ITEM*	item,
*									MR_ULONG	id)
*
*	FUNCTION	Setup a HUD script
*
*	INPUTS		item	-	ptr to first item
*				id		-	player id (0..3)
*
*	RESULT		item	-	ptr to first item
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

HUD_ITEM*	SetupHUDScript(	HUD_ITEM*	item,
							MR_ULONG	id)
{
	HUD_ITEM*					start_item;
	HUD_ITEM*					item_loop;
	MR_TEXTURE*					texture;
	FROG*						frog;
	MR_2DSPRITE**				sprite_pptr;
	MR_2DSPRITE*				sprite_ptr;
	POLY_FT3*					poly_ft3;
	POLY_F4*					poly_f4;
	POLY_G4*					poly_g4;
	HUD_CHECKPOINT_ANIM_INFO*	checkpoint_anim_info;
	MR_LONG						j, d;

	MR_ASSERT(item);

	frog		= &Frogs[id];
	start_item 	= item;

	while(item->hi_type)
		{
		texture = item->hi_texture;
		switch(item->hi_type)
			{
			//--------------------------------------------------------------------
			case HUD_ITEM_SCORE:
				if (Game_flags & GAME_FLAG_HUD_SCORE)
					{
					item->hi_flags 	|= HUD_ITEM_REBUILD;
					item->hi_api_0	= MRAllocateTextArea(NULL, Game_font_infos[GAME_FONT_STANDARD], Game_viewporth, 20, item->hi_x, item->hi_y, 		48, 8);
					item->hi_api_1	= MRAllocateTextArea(NULL, Game_font_infos[GAME_FONT_STANDARD],	Game_viewporth, 20, item->hi_x, item->hi_y + 8, 	48, 8);
					((MR_TEXT_AREA*)item->hi_api_0)->ta_display = TRUE;
					((MR_TEXT_AREA*)item->hi_api_1)->ta_display = TRUE;
	
					Hud_build_text_digits[0] = id + 1;
					// If multi-player, score text is colour of frog
					if (Game_total_viewports > 1)
						j = MR_FONT_COLOUR_GREY + Frog_player_data[id].fp_player_id;
					else
						j = MR_FONT_COLOUR_WHITE;
	
					if 	(
						(Game_total_viewports > 1) &&
						(!(id & 1))
						)
						// Left justify score
						MRBuildText(item->hi_api_0, text_hud_score_words_left,	j);
					else
						// Right justify score
						MRBuildText(item->hi_api_0, text_hud_score_words_right,	j);

					// setup background polys for scores
					for (j = 0; j < 2; j++)
						{
						setPolyF4(Hud_score_background_f[id][j]);
						setRGB0(Hud_score_background_f[id][j], 0x40, 0x40, 0x40);
						setSemiTrans(Hud_score_background_f[id][j], 1);

						Hud_score_background_f[id][j]->x0 = item->hi_x - 5;
						Hud_score_background_f[id][j]->y0 = item->hi_y - 5;
						Hud_score_background_f[id][j]->x1 = item->hi_x + 48 + 5;
						Hud_score_background_f[id][j]->y1 = Hud_score_background_f[id][j]->y0;
						Hud_score_background_f[id][j]->x2 = Hud_score_background_f[id][j]->x0;
						Hud_score_background_f[id][j]->y2 = item->hi_y + 16 + 5;
						Hud_score_background_f[id][j]->x3 = Hud_score_background_f[id][j]->x1;
						Hud_score_background_f[id][j]->y3 = Hud_score_background_f[id][j]->y2;

						SetupABRChangeFT3(Hud_score_background_ft[id][j], 2);
						}
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_TIMER:
				if (Game_flags & GAME_FLAG_HUD_TIMER)
					{
					// Set up digits
					item->hi_api_0	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH / 2) - 32, item->hi_y - 34, Game_viewporth, &im_32x32_0, NULL);
					item->hi_api_1	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH / 2) -  0, item->hi_y - 34, Game_viewporth, &im_32x32_0, NULL);
					((MR_SP_CORE*)item->hi_api_0)->sc_base_colour.r = 0x00;
					((MR_SP_CORE*)item->hi_api_0)->sc_base_colour.g = 0x00;
					((MR_SP_CORE*)item->hi_api_0)->sc_base_colour.b = 0x00;
					((MR_SP_CORE*)item->hi_api_1)->sc_base_colour.r = 0x00;
					((MR_SP_CORE*)item->hi_api_1)->sc_base_colour.g = 0x00;
					((MR_SP_CORE*)item->hi_api_1)->sc_base_colour.b = 0x00;

					// Set up bar
					j 					= (sizeof(POLY_FT3) * 2) + sizeof(POLY_F4) + sizeof(POLY_G4);
					item->hi_polys[0] 	= MRAllocMem(j * 2, "HUD TIMER BAR POLYS");
					item->hi_polys[1] 	= item->hi_polys[0] + j;
					poly_ft3			= (POLY_FT3*)item->hi_polys[0];
					for (j = 0; j < 2; j++)
						{
						// ABR change for F4 (subtractive)
						SetupABRChangeFT3(poly_ft3, 2);

						// F4 (dark bar)
						poly_f4			= (POLY_F4*)(poly_ft3 + 1);
						setPolyF4(poly_f4);
						setSemiTrans(poly_f4, 1);
						setRGB0(poly_f4, 0x40, 0x40, 0x40);
						poly_f4->x0		= item->hi_x;
						poly_f4->x1		= item->hi_x + HUD_ITEM_TIMER_WIDTH;
						poly_f4->x2		= item->hi_x;
						poly_f4->x3		= item->hi_x + HUD_ITEM_TIMER_WIDTH;
						poly_f4->y0		= item->hi_y;
						poly_f4->y1		= item->hi_y;
						poly_f4->y2		= item->hi_y + HUD_ITEM_TIMER_HEIGHT;
						poly_f4->y3		= item->hi_y + HUD_ITEM_TIMER_HEIGHT;

						// ABR change for G4 (additive)
						poly_ft3		= (POLY_FT3*)(poly_f4 + 1);
						SetupABRChangeFT3(poly_ft3, 1);		

						// G4 (coloured bar)
						poly_g4			= (POLY_G4*)(poly_ft3 + 1);
						setPolyG4(poly_g4);
//						setSemiTrans(poly_g4, 1);
						setRGB0(poly_g4, 0xe0, 0x20, 0x20);
						setRGB2(poly_g4, 0xe0, 0x20, 0x20);
						setRGB1(poly_g4, 0x20, 0xe0, 0x20);
						setRGB3(poly_g4, 0x20, 0xe0, 0x20);
						poly_g4->x0		= item->hi_x + 1;
						poly_g4->x1		= item->hi_x + HUD_ITEM_TIMER_WIDTH - 1;
						poly_g4->x2		= item->hi_x + 1;
						poly_g4->x3		= item->hi_x + HUD_ITEM_TIMER_WIDTH - 1;
						poly_g4->y0		= item->hi_y + 1;
						poly_g4->y1		= item->hi_y + 1;
						poly_g4->y2		= item->hi_y + HUD_ITEM_TIMER_HEIGHT - 1;
						poly_g4->y3		= item->hi_y + HUD_ITEM_TIMER_HEIGHT - 1;

						poly_ft3		= (POLY_FT3*)(poly_g4 + 1);
						}
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_HELP:
				if (Game_flags & GAME_FLAG_HUD_HELP)
					{
					item->hi_api_0	= MRAllocateTextArea(NULL, Game_font_infos[GAME_FONT_STANDARD],	Game_viewporth, 20, item->hi_x, item->hi_y, HUD_ITEM_HELP_WIDTH, 24);
					item->hi_api_1	= NULL;
					((MR_TEXT_AREA*)item->hi_api_0)->ta_display = FALSE;
					MRSetTextTranslucency(item->hi_api_0, 0, 1);
					MRSetTextTranslucency(item->hi_api_0, 1, 1);
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_CHECKPOINTS:
				if (Game_flags & GAME_FLAG_HUD_CHECKPOINTS)
					{
					item->hi_api_0	= MRAllocMem(sizeof(MR_2DSPRITE*) * GEN_MAX_CHECKPOINTS, "HUD CHECKPOINT 2DSPRITE PTRS");

					sprite_pptr		= (MR_2DSPRITE**)item->hi_api_0;
					for (j = 0; j < GEN_MAX_CHECKPOINTS; j++)
						{
						if ( Sel_mode == SEL_MODE_ARCADE )
							{
							*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
															item->hi_y,
															Game_viewporth,
															Hud_checkpoint_animlists[j],
															NULL);
							}
						else
							{
							*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
															item->hi_y,
															Game_viewporth,
															Hud_checkpoint_multiplayer_animlists[j],
															NULL);
							}

						// setup start position

						sprite_pptr++;
						}
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_LIVES:
				if (Game_flags & GAME_FLAG_HUD_LIVES)
					{
					item->hi_api_0	= MRAllocMem(sizeof(MR_2DSPRITE*) * HUD_ITEM_LIVES_MAX_ICONS, "HUD LIVES 2DSPRITE PTRS");

					sprite_pptr		= (MR_2DSPRITE**)item->hi_api_0;
					for (j = 0; j < HUD_ITEM_LIVES_MAX_ICONS; j++)
						{
						*sprite_pptr = MRCreate2DSprite(0, 0,		// get rewritten
														Game_viewporth,
														Animlist_hud_lives_icon_small,
														NULL);
						sprite_pptr++;
						}
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_START_GATHER:
				item->hi_api_0			= MRAllocMem(sizeof(MR_2DSPRITE*) * GEN_MAX_CHECKPOINTS, "HUD CHECKPOINT 2DSPRITE PTRS");
				sprite_pptr				= (MR_2DSPRITE**)item->hi_api_0;
				checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;
				
				for (j = 0; j < GEN_MAX_CHECKPOINTS; j++)
					{
					if ( Sel_mode == SEL_MODE_ARCADE )
						{
						*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
														item->hi_y,
														Game_viewporth,
														Hud_checkpoint_animlists[j],
														NULL);
						}
					else
						{
						*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
														item->hi_y,
														Game_viewporth,
														Hud_checkpoint_multiplayer_animlists[j],
														NULL);
						}

					sprite_ptr				= (MR_2DSPRITE*)*sprite_pptr;
					sprite_ptr->sp_pos.x	= checkpoint_anim_info->hc_start_x;
					sprite_ptr->sp_pos.y	= checkpoint_anim_info->hc_start_y;

					// set up variables inside the structure, ready to execute
					checkpoint_anim_info->hc_anim_timer = checkpoint_anim_info->hc_initial_delay;
					checkpoint_anim_info->hc_mode		= HUD_ITEM_ANIM_DELAY;
					checkpoint_anim_info->hc_pos_x		= checkpoint_anim_info->hc_start_x << 16;
					checkpoint_anim_info->hc_pos_y		= checkpoint_anim_info->hc_start_y << 16;

					sprite_pptr++;
					checkpoint_anim_info++;
					}

				// make sure finished flag is not set
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags &= ~HUD_ITEM_NO_UPDATE;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_START_TIMER:
				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;

				// Set up digits
				item->hi_api_0	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH / 2) - 32, item->hi_y - 34, Game_viewporth, &im_32x32_0, NULL);
				item->hi_api_1	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH / 2) -  0, item->hi_y - 34, Game_viewporth, &im_32x32_0, NULL);

				// Update digits
				d = (Game_map_timer + 29) / 30;

				// Display digits
				MRChangeSprite(item->hi_api_0, Hud_timer_images[d / 10]);
				MRChangeSprite(item->hi_api_1, Hud_timer_images[d % 10]);

				((MR_SP_CORE*)item->hi_api_0)->sc_flags |= MR_SPF_NO_DISPLAY;
				((MR_SP_CORE*)item->hi_api_1)->sc_flags |= MR_SPF_NO_DISPLAY;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_TIME:
				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;

				// Set up digits
				item->hi_api_0	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH>>1), item->hi_y, Game_viewporth, &im_32x32_0, NULL);
				item->hi_api_1	= MRCreate2DSprite(item->hi_x + (HUD_ITEM_TIMER_WIDTH>>1) + 16, item->hi_y, Game_viewporth, &im_32x32_0, NULL);

				// Update digits
				d = ((Game_map_time*30) - Game_map_timer)/30;

				// Display digits
				MRChangeSprite(item->hi_api_0, Hud_score_images[d / 10]);
				MRChangeSprite(item->hi_api_1, Hud_score_images[d % 10]);

				((MR_SP_CORE*)item->hi_api_0)->sc_flags |= MR_SPF_NO_DISPLAY;
				((MR_SP_CORE*)item->hi_api_1)->sc_flags |= MR_SPF_NO_DISPLAY;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_START_SCATTER:
				item->hi_api_0			= MRAllocMem(sizeof(MR_2DSPRITE*) * GEN_MAX_CHECKPOINTS, "HUD CHECKPOINT 2DSPRITE PTRS");
				sprite_pptr				= (MR_2DSPRITE**)item->hi_api_0;
				checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;

				for (j = 0; j < GEN_MAX_CHECKPOINTS; j++)
					{
					if ( Sel_mode == SEL_MODE_ARCADE )
						{
						*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
														item->hi_y,
														Game_viewporth,
														Hud_checkpoint_animlists[j],
														NULL);
						}
					else
						{
						*sprite_pptr = MRCreate2DSprite(0,			// gets rewritten
														item->hi_y,
														Game_viewporth,
														Hud_checkpoint_multiplayer_animlists[j],
														NULL);
						}

					sprite_ptr								= (MR_2DSPRITE*)*sprite_pptr;
					sprite_ptr->sp_pos.x					= checkpoint_anim_info->hc_start_x;
					sprite_ptr->sp_pos.y					= checkpoint_anim_info->hc_start_y;
					((MR_SP_CORE*)*sprite_pptr)->sc_flags	|= MR_SPF_NO_DISPLAY;

					// set up variables inside the structure, ready to execute
					checkpoint_anim_info->hc_anim_timer = 0;
					checkpoint_anim_info->hc_mode		= HUD_ITEM_ANIM_DELAY;
					checkpoint_anim_info->hc_pos_x		= checkpoint_anim_info->hc_start_x << 16;
					checkpoint_anim_info->hc_pos_y		= checkpoint_anim_info->hc_start_y << 16;

					sprite_pptr++;
					checkpoint_anim_info++;
					}

				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT:
				if ( Sel_mode == SEL_MODE_ARCADE )
					{
					item->hi_api_0			= MRCreate2DSprite(	0,					// gets rewritten
																0,					// gets rewritten
																Game_viewporth,
																Hud_checkpoint_animlists[Checkpoint_last_collected],
																NULL);
					}
				else
					{
					item->hi_api_0			= MRCreate2DSprite(	0,					// gets rewritten
																0,					// gets rewritten
																Game_viewporth,
																Hud_checkpoint_multiplayer_animlists[Checkpoint_last_collected],
																NULL);
					}

				sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;
				checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;

				// Work out where the check point is, and where it needs to go
				checkpoint_anim_info->hc_start_x		= (SYSTEM_DISPLAY_WIDTH>>1)-70;
				checkpoint_anim_info->hc_start_y		= -20;
				checkpoint_anim_info->hc_timer			= 31;
				checkpoint_anim_info->hc_velocity_x		= 0;
				checkpoint_anim_info->hc_velocity_y		= (((SYSTEM_DISPLAY_HEIGHT>>1) - 25 - checkpoint_anim_info->hc_start_y)<<16) / 30;
				checkpoint_anim_info->hc_pos_x			= checkpoint_anim_info->hc_start_x << 16;
				checkpoint_anim_info->hc_pos_y			= checkpoint_anim_info->hc_start_y << 16;
				checkpoint_anim_info->hc_anim_timer		= 0;
				checkpoint_anim_info->hc_mode			= HUD_ITEM_ANIM_DELAY;

				// Are we in single player ?
				if (Sel_mode != SEL_MODE_ARCADE)
					{
					// No ... turn off the checkpoint entity ( static )
					if	(
						(Checkpoint_data[Checkpoint_last_collected].cp_entity) &&
						(Checkpoint_data[Checkpoint_last_collected].cp_entity->en_live_entity)
						)
						{
						((MR_OBJECT*)Checkpoint_data[Checkpoint_last_collected].cp_entity->en_live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
						}
					}

				// Set up sprite
				sprite_ptr->sp_pos.x					= checkpoint_anim_info->hc_start_x;
				sprite_ptr->sp_pos.y					= checkpoint_anim_info->hc_start_y;
				((MR_SP_CORE*)sprite_ptr)->sc_flags		|= MR_SPF_NO_DISPLAY;

				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags &= ~HUD_ITEM_NO_UPDATE;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_TRIGGER_RETURN_CHECKPOINT:
				// find the COLLECT_CHECKPOINT sprite
				item_loop = start_item;
				while (item_loop->hi_type)
					{
					if (item_loop->hi_type == HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT)
						{
						item->hi_api_0 = item_loop->hi_api_0;
						break;
						}
					item_loop++;
					}

				sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;
				checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;

				// Work out where (in x and y) the checkpoint needs to zoom too
				d = 16;
				for (j=0; j<(MR_LONG)Checkpoint_last_collected; j++)
					{
					if (Checkpoint_data[j].cp_frog_collected_id == (MR_LONG)id)
						d += 16;
					}
				
				checkpoint_anim_info->hc_start_x		= ((SYSTEM_DISPLAY_WIDTH>>1)-70);
				checkpoint_anim_info->hc_start_y		= (SYSTEM_DISPLAY_HEIGHT>>1)-25;
				checkpoint_anim_info->hc_timer			= 31;
				checkpoint_anim_info->hc_velocity_x		= ((d - checkpoint_anim_info->hc_start_x)<<16) / 30;
#ifdef PSX_MODE_PAL
				checkpoint_anim_info->hc_velocity_y		= ((SYSTEM_DISPLAY_HEIGHT -32-6 - checkpoint_anim_info->hc_start_y)<<16) / 30;
#else
				checkpoint_anim_info->hc_velocity_y		= ((SYSTEM_DISPLAY_HEIGHT -32-12 - checkpoint_anim_info->hc_start_y)<<16) / 30;
#endif
				checkpoint_anim_info->hc_pos_x			= checkpoint_anim_info->hc_start_x << 16;
				checkpoint_anim_info->hc_pos_y			= checkpoint_anim_info->hc_start_y << 16;
				checkpoint_anim_info->hc_anim_timer		= 0;
				checkpoint_anim_info->hc_mode			= HUD_ITEM_ANIM_DELAY;

				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_BITMAP:
				item->hi_api_0	= MRCreate2DSprite(	item->hi_x - (item->hi_texture->te_w>>1),
													item->hi_y,
													Game_viewporth,
													item->hi_texture,
													NULL);


				// Set up sprite
				((MR_SP_CORE*)item->hi_api_0)->sc_flags	|= MR_SPF_NO_DISPLAY;

				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_BONUS:
				// Init bonus score
				Hud_bonus_score = 0;

				// Even off Game_map_timer
				while 
					(
					(Game_map_timer) &&
					((Game_map_timer % 30) != 0)
					)
					{
					Game_map_timer--;
					}

				// make sure finished flag is not set, and its marked as no_update
				item->hi_flags &= ~HUD_ITEM_FINISHED;
				item->hi_flags |= HUD_ITEM_NO_UPDATE;

				// reuse hi_timer for general mode
				item->hi_timer		= HUD_ITEM_BONUS_COUNT_UP;
				item->hi_api_0		= MRAllocMem(sizeof(MR_2DSPRITE*) * HUD_MAX_BONUS_DIGITS, "HUD BONUS POINTS 2DSPRITE PTRS");
				sprite_pptr			= (MR_2DSPRITE**)item->hi_api_0;

				d = item->hi_x + (HUD_ITEM_TIMER_WIDTH>>1);

				for (j = 0; j < HUD_MAX_BONUS_DIGITS; j++)
					{
					*sprite_pptr = MRCreate2DSprite(d,
													item->hi_y,
													Game_viewporth,
													&im_32x32_0,
													NULL);
					((MR_SP_CORE*)*sprite_pptr)->sc_flags	|= MR_SPF_NO_DISPLAY;

					// push x position along for next digit
					d += 16;

					sprite_pptr++;
					}
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_GOLD_FROG:
				item->hi_api_0			= MRCreate2DSprite(	0,					// gets rewritten
															0,					// gets rewritten
															Game_viewporth,
															Animlist_hud_gold_frog,
															NULL);
				sprite_ptr				= (MR_2DSPRITE*)item->hi_api_0;
				checkpoint_anim_info	= (HUD_CHECKPOINT_ANIM_INFO*)item->hi_extra;

				// has gold frog been collected?
				if (!(Gold_frogs & (1<<Game_map_theme)))
					{
					// Work out where the check point is, and where it needs to go
					checkpoint_anim_info->hc_start_x		= 16 + (16*6);
					checkpoint_anim_info->hc_start_y		= -20;
					checkpoint_anim_info->hc_timer			= 30;
					checkpoint_anim_info->hc_velocity_x		= 0;
#ifdef PSX_MODE_PAL
					checkpoint_anim_info->hc_velocity_y		= (((SYSTEM_DISPLAY_HEIGHT-32-6) - checkpoint_anim_info->hc_start_y)<<16) / 30;
#else
					checkpoint_anim_info->hc_velocity_y		= (((SYSTEM_DISPLAY_HEIGHT-32-12) - checkpoint_anim_info->hc_start_y)<<16) / 30;
#endif
					}
				else
					{
					checkpoint_anim_info->hc_start_x		= 16 + (16*6);
					checkpoint_anim_info->hc_start_y		= (SYSTEM_DISPLAY_HEIGHT-32);
					checkpoint_anim_info->hc_timer			= 0;
					checkpoint_anim_info->hc_velocity_x		= 0;
					checkpoint_anim_info->hc_velocity_y		= 0;
					}
				checkpoint_anim_info->hc_pos_x			= checkpoint_anim_info->hc_start_x << 16;
				checkpoint_anim_info->hc_pos_y			= checkpoint_anim_info->hc_start_y << 16;

				// Set up sprite
				sprite_ptr->sp_pos.x	= checkpoint_anim_info->hc_start_x;
				sprite_ptr->sp_pos.y	= checkpoint_anim_info->hc_start_y;
				item->hi_flags			|= HUD_ITEM_NO_UPDATE;
				break;
			}
		item++;
		}

	return(start_item);
}


/******************************************************************************
*%%%% KillHUDScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillHUDScript(
*						HUD_ITEM*	item)
*
*	FUNCTION	Kill a HUD script (free allocated memory)
*
*	INPUTS		item	-	ptr to first item
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillHUDScript(HUD_ITEM*	item)
{
	MR_2DSPRITE**	sprite_pptr;
	MR_LONG			j;


	MR_ASSERT(item);

	while(item->hi_type)
		{
		switch(item->hi_type)
			{
			//--------------------------------------------------------------------
			case HUD_ITEM_SCORE:
				if (Game_flags & GAME_FLAG_HUD_SCORE)
					{
					MRFreeTextAreaPhysically(item->hi_api_0);
					MRFreeTextAreaPhysically(item->hi_api_1);
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_TIMER:
				if (Game_flags & GAME_FLAG_HUD_TIMER)
					{
					MRKill2DSprite(item->hi_api_0);
					MRKill2DSprite(item->hi_api_1);
					MRFreeMem(item->hi_polys[0]);
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_HELP:
				if (Game_flags & GAME_FLAG_HUD_HELP)
					MRFreeTextAreaPhysically(item->hi_api_0);
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_CHECKPOINTS:
				if (Game_flags & GAME_FLAG_HUD_CHECKPOINTS)
					{
					sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
					for (j = 0; j < GEN_MAX_CHECKPOINTS; j++)
						{
						MRKill2DSprite(*sprite_pptr);
						sprite_pptr++;
						}
					MRFreeMem(item->hi_api_0);
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_LIVES:
				if (Game_flags & GAME_FLAG_HUD_LIVES)
					{
					sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
					for (j = 0; j < HUD_ITEM_LIVES_MAX_ICONS; j++)
						{
						MRKill2DSprite(*sprite_pptr);
						sprite_pptr++;
						}
					MRFreeMem(item->hi_api_0);
					}
				break;
			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_START_GATHER:
			case HUD_ITEM_LEVEL_START_SCATTER:
				sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
				for (j = 0; j < GEN_MAX_CHECKPOINTS; j++)
					{
					MRKill2DSprite(*sprite_pptr);
					sprite_pptr++;
					}
				MRFreeMem(item->hi_api_0);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_START_TIMER:
				MRKill2DSprite(item->hi_api_0);
				MRKill2DSprite(item->hi_api_1);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_TIME:
				MRKill2DSprite(item->hi_api_0);
				MRKill2DSprite(item->hi_api_1);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_TRIGGER_COLLECT_CHECKPOINT:
				MRKill2DSprite(item->hi_api_0);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_TRIGGER_RETURN_CHECKPOINT:
				//MRKill2DSprite(item->hi_api_0);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_BITMAP:
				MRKill2DSprite(item->hi_api_0);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_LEVEL_BONUS:
				sprite_pptr	= (MR_2DSPRITE**)item->hi_api_0;
				for (j = 0; j < HUD_MAX_BONUS_DIGITS; j++)
					{
					MRKill2DSprite(*sprite_pptr);
					sprite_pptr++;
					}
				MRFreeMem(item->hi_api_0);
				break;

			//--------------------------------------------------------------------
			case HUD_ITEM_GOLD_FROG:
				MRKill2DSprite(item->hi_api_0);
				break;
			}
		item++;
 		}
}


/******************************************************************************
*%%%% DisplayHUDHelp
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DisplayHUDHelp(
*						MR_ULONG	frog_id,
*						MR_ULONG	help_id)
*
*	FUNCTION	Check the flag for a help item, and if 0, try and display it
*
*	INPUTS		frog_id	-	id of frog
*				help_id	-	help item id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	DisplayHUDHelp(	MR_ULONG	frog_id,
				   		MR_ULONG	help_id)
{							
	HUD_ITEM*	hud_item;
	FROG*		frog;


	if 	(
		(!(Hud_item_help_flags[frog_id][help_id])) &&
		(Game_flags & GAME_FLAG_HUD_HELP)
		)
		{
		frog 		= &Frogs[frog_id];		
		hud_item 	= frog->fr_hud_script + HUD_ITEM_HELP - 1;
		if	(((MR_TEXT_AREA*)hud_item->hi_api_0)->ta_display == FALSE)
			{
			// Display help message
			MRBuildText(hud_item->hi_api_0, Hud_item_help_messages[help_id][Game_language], MR_FONT_COLOUR_WHITE);
			hud_item->hi_timer						= HUD_ITEM_FADE_DURATION;
			hud_item->hi_flags						|= HUD_ITEM_FADE_UP;
			Hud_item_help_flags[frog_id][help_id] 	= 1;
			}
		}
}

/******************************************************************************
*%%%% HUDGetDigits
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HUDGetDigits(	MR_ULONG	value,
*										MR_ULONG*	digit_a,
*										MR_ULONG*	digit_b,
*										MR_ULONG*	digit_c)
*
*	FUNCTION	Takes a value, and returns in the supplied params the digits that
*				make up the number, eg 203 return '2', '0' and '3', and 40
*				returns '0', '4' and '0'.
*
*	INPUTS		value		-	number to convert
*				digit_a		-	digit 'a' filled in by this function
*				digit_b		-	digit 'b' filled in by this function
*				digit_c		-	digit 'c' filled in by this function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Martin Kift		Created
*	21.07.97	William Bell	Rewritten to allow more than 3 digits
*
*%%%**************************************************************************/

MR_VOID	HUDGetDigits(	MR_ULONG	value,
						MR_ULONG*	digit_a,
						MR_ULONG*	digit_b,
						MR_ULONG*	digit_c)
{


	// Locals
	MR_UBYTE*			digit_ptr;
	MR_ULONG			loop_counter;
	MR_ULONG			remainder;

	// Set pointer
	digit_ptr = &Hud_digits[9];

	// Loop once for each digit
	for(loop_counter=0;loop_counter<10;loop_counter++)
		{

		// Get right most digit
		remainder = value % 10;

		// Store right most digit
		*digit_ptr = (MR_UBYTE)remainder;

		// Move value down
		value = value / 10;

		// Move pointer back
		digit_ptr--;

		}

}


/******************************************************************************
*%%%% InitialiseMultiplayerHUDbackgrounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseMultiplayerHUDbackgrounds(MR_VOID)
*
*	FUNCTION	Initialises background sprites for multiplayer mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID InitialiseMultiplayerHUDbackgrounds(MR_VOID)
{
	// If in multiplayer mode, create sprites for backgrounds (4 for all potential viewports)
	// Initialise game hud
	switch (Game_total_viewports)
		{
		//----------------------------------------------------------------------
		case 2:
			// 2 viewports, 2 players
			Game_multiplayer_no_player[0] =	MRCreate2DSprite(
								(Game_display_width/4) - (im_multback.te_w/2),
								(Game_display_height/2) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);
			((MR_SP_CORE*)Game_multiplayer_no_player[0])->sc_flags	|= MR_SPF_NO_DISPLAY;

			Game_multiplayer_no_player[1] =	MRCreate2DSprite(
								((Game_display_width*3)/4) - (im_multback.te_w/2),
								(Game_display_height/2) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);
			((MR_SP_CORE*)Game_multiplayer_no_player[1])->sc_flags	|= MR_SPF_NO_DISPLAY;
			break;
		//----------------------------------------------------------------------
		case 3:
		case 4:
			// player 1
			Game_multiplayer_no_player[0] =	MRCreate2DSprite(
								(Game_display_width/4) - (im_multback.te_w/2),
								(Game_display_height/4) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);
			((MR_SP_CORE*)Game_multiplayer_no_player[0])->sc_flags	|= MR_SPF_NO_DISPLAY;

			// player 2
			Game_multiplayer_no_player[1] =	MRCreate2DSprite(
								((Game_display_width*3)/4) - (im_multback.te_w/2),
								(Game_display_height/4) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);
			((MR_SP_CORE*)Game_multiplayer_no_player[1])->sc_flags	|= MR_SPF_NO_DISPLAY;

			// player 3
			Game_multiplayer_no_player[2] =	MRCreate2DSprite(
								(Game_display_width/4) - (im_multback.te_w/2),
								((Game_display_height*3)/4) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);
			((MR_SP_CORE*)Game_multiplayer_no_player[2])->sc_flags	|= MR_SPF_NO_DISPLAY;

			// player 4
			Game_multiplayer_no_player[3] =	MRCreate2DSprite(
								((Game_display_width*3)/4) - (im_multback.te_w/2),
								((Game_display_height*3)/4) - (im_multback.te_h/2),
								Game_viewporth,
								&im_multback,
								NULL);

			if (Game_total_viewports == 4)
				((MR_SP_CORE*)Game_multiplayer_no_player[3])->sc_flags	|= MR_SPF_NO_DISPLAY;
			break;
		//----------------------------------------------------------------------
		}
}

/******************************************************************************
*%%%% UpdateMultiplayerHUDbackgrounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateMultiplayerHUDbackgrounds(MR_VOID)
*
*	FUNCTION	Updates background sprites for multiplayer mode (well the blatting
*				black tiles anyway to clear the viewports)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID UpdateMultiplayerHUDbackgrounds(MR_VOID)
{
//	MR_LONG	i;
//	TILE*	tile;
//
//	// If in multiplayer mode, create sprites for backgrounds (4 for all potential viewports)
//	// Initialise game hud. Note that this can only happen in 3/4 player mode... in 2 player
//	// mode there must always be a winner from 5 checkpoints!
//	switch (Game_total_viewports)
//		{
//		case 3:
//		case 4:
//			for (i=0; i<Game_total_viewports; i++)
//				{
//				// If the viewports are turned off, add the clear tile to the HUD
//				if (Game_viewports[i]->vp_flags & MR_VP_NO_DISPLAY)
//					{
//					tile		= &Game_clear_tiles[i][MRFrame_index];
//					tile->x0	+= Game_viewports[i]->vp_disp_inf.x;
//					tile->y0	+= Game_viewports[i]->vp_disp_inf.y;
//					addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - 1, tile);
//					}
//				}
//			break;
//		}
}


/******************************************************************************
*%%%% DeinitialiseMultiplayerHUDbackgrounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeinitialiseMultiplayerHUDbackgrounds(MR_VOID)
*
*	FUNCTION	Initialises background sprites for multiplayer mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID DeinitialiseMultiplayerHUDbackgrounds(MR_VOID)
{
	MR_LONG		i;

	switch (Game_total_viewports)
		{
		case 2:
			for (i=0; i<2; i++)
				MRKill2DSprite(Game_multiplayer_no_player[i]);
			break;

		case 3:
		case 4:
			for (i=0; i<4; i++)
				MRKill2DSprite(Game_multiplayer_no_player[i]);
			break;
		}
}

#ifdef WIN95
#pragma warning (default : 4761)
#endif
