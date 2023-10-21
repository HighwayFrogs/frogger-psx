/******************************************************************************
*%%%% hsview.c
*------------------------------------------------------------------------------
*
*	High score table viewer.  Based on Dean's level select.
*
*	Arcade mode ( sorted on total level time ) ( 3 entries per level ) -
*		Name	Total Level Time	Time to Trigger 1 2 3 4 5	Score
*
*	Race mode ( sorted on score ) ( 3 entries per level ) -
*		Name	Score
*
*	Main high score ( sorted on score ) ( 10 entries ) -
*		Name	Score
*
*
*	Lots of seperate functionality
*		1.1 Scroll across high scores
*		1.2 Show level stack stuff and allow main high scores
*
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.06.97	William Bell	Created
*
*%%%**************************************************************************/

#include "hsview.h"
#include "select.h"
#include "project.h"
#include "sprdata.h"
#include "options.h"
#include "tempopt.h"
#include "gamefont.h"
#include "gamesys.h"
#include "hsinput.h"
#include "sound.h"
#include "gen_frog.h"
#include "frog.h"
#include "camera.h"
#include "main.h"
#include "misc.h"
#include "model.h"
#include "hsinput.h"

#include "library.h"

#ifdef WIN95
#pragma warning (disable : 4761)
#endif


MR_ULONG		High_score_splash_animlist[]=
	{
	MR_SPRT_SETSPEED,	3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim5,
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x606060,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x404040,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x202020,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_KILL
	};

MR_USHORT		High_score_log_animated_poly_indices[] =
	{
	56, 48, 40, 8, 16, 24, 32, 0
	};

MR_MAT*			High_score_matrices;
POLY_FT4*		High_score_view_water_prim_ptrs[2];
POLY_FT4*		High_score_view_riverbed_prim_ptrs[2];

// Extra models
MR_MAT*			High_score_view_extras_matrix_ptr[HIGH_SCORE_VIEW_NUM_EXTRAS];
MR_OBJECT*		High_score_view_extras_object_ptr[HIGH_SCORE_VIEW_NUM_EXTRAS];
MR_ULONG		High_score_view_extras_resource_id[] =
	{
	RES_OPT_STAT_BULLRUSH_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_LILLY_XMR,

	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_BULLRUSH_XMR,
	};

MR_LONG			High_score_view_extras_coords[] =
	{
	-0x400, -0x580,
	-0x280, -0x700,
	 0x300, -0x600,
	-0x240,  0x700,
	 0x200,  0x740,
	};

// Stuff flying on/off screen
MR_LONG			High_score_view_flyoff_counter;
MR_LONG			High_score_view_flyon_counter;
MR_LONG			High_score_view_delayed_request;

MR_SVEC*		High_score_view_water_points_ptr;
MR_SVEC*		High_score_view_riverbed_points_ptr;

MR_ULONG		New_high_score_operation_mode 		= HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT;
MR_ULONG		High_score_operation_mode 			= HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT;
MR_ULONG		High_score_camera_operation_mode 	= HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC;

// Scratch
MR_ULONG		High_score_view_mode;

// High score numbers
MR_MOF*			High_score_view_number_model_ptr[10];
MR_MAT*			High_score_view_number_matrix_ptr[10];
MR_OBJECT*		High_score_view_number_object_ptr[10];
MR_ANIM_ENV*	High_score_view_number_anim_env_ptr[10];

// High score initials
MR_MOF*			High_score_view_initials_model_ptr[30];
MR_MAT*			High_score_view_initials_matrix_ptr[30];
MR_OBJECT*		High_score_view_initials_object_ptr[30];
MR_MESH_INST*	High_score_view_initials_inst_ptr[30];

// High score Frog
MR_ANIM_HEADER*		High_score_view_frog_anim_model_ptr;
MR_MAT*				High_score_view_frog_anim_matrix_ptr;
MR_ANIM_ENV*		High_score_view_frog_anim_env_ptr;
MR_MAT				High_score_view_frog_sack_scale_matrix;

// High score logs
MR_MOF*				High_score_view_log_model_ptr[10];
MR_MAT*				High_score_view_log_matrix_ptr[10];
MR_OBJECT*			High_score_view_log_object_ptr[10];
MR_MESH_INST*		High_score_view_log_inst_ptr[10];

MR_ULONG	High_score_view_water_prim_colours[2] =
	{
	0x00406060,	// surface
	0x00303030	// riverbed
	};

MR_2DSPRITE*			HSView_arrow_sprite_ptr[2];

MR_BOOL					HSView_automatic_flag = FALSE;

MR_USHORT				Frog_time_data[5];
HIGH_SCORE_ENTRY		Frog_score_data[60][4];			// Data as comes from the frog during play

HIGH_SCORE_ENTRY		Game_high_score[10] =
	{
	// Initials			Score
	{'T','I','M',0,	    250000},
	{'M','K','Z'+1,0,	225000},
	{'M','Z'+1,'B',0,	200000},
	{'G','C','R',0,		175000},
	{'J','A','S',0,		150000},
	{'B','Z'+1,'S',0,	125000},
	{'W','I','L',0,		100000},
	{'J','O','N',0,		75000},
	{'D','A','Z',0,		50000},
#ifdef DEBUG
	{'A','L','Z'+1,0,	  200},
#else
	{'A','L','Z'+1,0,	25000},
#endif
	};

HIGH_SCORE_ENTRY		Level_high_scores[60][3]=
	{
	{
		// Initials		Score	Time 1		Time 2		Time 3		Time 4		Time 5
// CAVES 1
#ifdef DEBUG
		{'A','A','A',0,	  10,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#else
		{'K','E','V',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#endif
		{'S','U','E',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'D','A','V',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// CAVES 2
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// CAVES 3 (unused)
		{'E','I','L',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'W','I','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'G','A','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// CAVES 4
		{'D','A','Z',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','A','R',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'T','O','M',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// CAVES 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// CAVES M (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT 1
		{'L','O','R',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','N','D',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','L','N',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT 2
		{'M','A','R',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','U','A',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','H','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT 3
		{'B','L','A',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'X','Y','P',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','A','D',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT 4
		{'B','A','R',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','I','M',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'N','A','T',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT 5
		{'N','I','C',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','I','M',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','O','N',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// DESERT M (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST 1
		{'S','A','M',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','H','A',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'N','I','C',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST 2
		{'L','I','S',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'G','O','R',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'P','E','T',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST 3 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST 4 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// FOREST M
		{'A','G','E',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'T','I','N',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','A','S',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE 1
		{'L','I','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','T','V',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'D','E','N',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE 2 (unused)
		{'W','E','L',0,	00100,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'L','D','O',0,	11111,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'N','E',' ',0,	00100,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE 3 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE 4 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// JUNGLE M
		{'B','A','R',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'E','L','V',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'B','U','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL 1
		{'B','O','B',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','U','R',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','A','M',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL 2
		{'B','E','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'O','S',' ',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'T','A','M',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL 3
		{'M','A','T',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','I','K',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'J','U','L',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL 4
		{'T','I','M',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'E','L','S',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','O','L',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL 5
		{'G','I','L',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'B','O','Y',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'K','A','T',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// ORIGINAL M
#ifdef DEBUG
		{'A','A','A',0,	  10,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#else
		{'G','O','T',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#endif
		{'M','I','T',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'R','I','L',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS 1 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS 2 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS 3 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS 4 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// RUINS M (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER 1
		{'P','A','U',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'H','A','Y',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'D','A','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER 2
		{'S','O','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','I','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','Y','B',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER 3
		{'B','E','A',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','T','W',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','R','S',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER 4
		{'M','E','D',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'I','E','V',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'I','L',' ',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER 5
		{'T','O','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','L','V',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','N','D',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SEWER M (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY 1
		{'D','O','W',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'N','A','D',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'T','I','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY 2
		{'N','I','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'D','E','R',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'R','O','N',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY 3
		{'H','O','L',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'B','E','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'R','I','C',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY 4
		{'B','R','O',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','C','T',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'E','V','A',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SKY M (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA 1
		{'D','O','U',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','U','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'K','I','F',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA 2
		{'S','A','U',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'P','O','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','R','C',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA 3
		{'L','E','V',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','L','S',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','U','L',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA 4
		{'L','L','O',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','U','L',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'B','U','T',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA 5
		{'O','S','W',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'A','R','N',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'C','A','V',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// SUBURBIA M
#ifdef DEBUG
		{'A','A','A',0,	  10,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#else
		{'S','U','B',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
#endif
		{'D','E','S',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','W','P',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL 1
		{'J','U','N',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'O','R','G',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'S','K','Y',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL 2
		{'V','O','L',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'I','N','D',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'L','A','R',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL 3
		{'F','O','R',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','A','P',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'X','M','O',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL 4 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL 5 (unused)
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
		{'B','U','G',0,	9999,	(60*12)+34,	(60*0)+0,	(60*0)+0,	(60*0)+0,	(60*0)+0},
	},
	{
		// Initials		Score	Time1		Time 2		Time 3		Time 4		Time 5
// INDUSTRIAL M
		{'C','H','I',0,	4000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'M','P','S',0,	2000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
		{'O','U','T',0,	1000,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0,	(60*1)+0},
	},

	};

MR_ULONG	HSView_counter;

// Store for current status of level select stack
MR_ULONG	Stack_status_flags_store[10*6];

/******************************************************************************
*%%%% HSViewStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewStartup(MR_VOID)
*
*	FUNCTION	Initalise high score view.  Which is based on Dean's level select.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	William Bell	Created
*	04.08.97	Gary Richards	Changed to used GEN instead of GENM,
*
*%%%**************************************************************************/

MR_VOID	HSViewStartup(MR_VOID)
{
//	SEL_LEVEL_INFO*	level_ptr;

	// Load options resources
	LoadOptionsResources();

	// Load GEN wad for frogs
	LoadGenericWad(0);

	// According to required mode of high score view operation do ...
	switch ( High_score_operation_mode )
		{
		// Main high scores initialise ------------------------------
		case HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES:
		
			// Initialise for "scrolly" high score view
			HSInitialiseScrollyHighScore();

			// Did we come here from the show hiscores screen?
			if (High_score_camera_operation_mode == HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC)
				{
				// Yes ... set up camera for static view
				MR_SET_SVEC(&Cameras[0].ca_current_source_ofs,
							OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_X,
							OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_Y,
							OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_Z);
			
				MR_SET_SVEC(&Cameras[0].ca_current_target_ofs,
							OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_X,
							OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_Y,
							OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_Z);
				}

			// Initialise ---------------------------------------

			// Set display clear colour
			MRSetDisplayClearColour(0x00,0x00,0x00);

			// Set update mode
			High_score_view_mode = HIGH_SCORE_VIEW_INIT_MODE;

			break;

		// Level select initialise ----------------------------------
		case HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT:

			// Dean:	You need to add calls here to select.c functions that will return/set 
			//			Sel_<xxx>_level_ptr to an appropriate Game_map-style equate.

			// Set start position
			Sel_arcade_level_ptr	= SelectGetLevelPointer(LEVEL_ORIGINAL1);
			Sel_race_level_ptr		= SelectGetLevelPointer(LEVEL_ORIGINAL_MULTI_PLAYER);

			// $da: Start of butchering

			// Store current status of level select stack
//			HSViewStoreStackStatus();
		
			// Enable all arcade levels 
//			level_ptr	= Sel_arcade_levels;
//			while (level_ptr->li_library_id != -1)
//				{
//				level_ptr->li_flags = SEL_LF_SELECTABLE;
//				level_ptr++;
//				}
			
			// Enable all race levels 
//			level_ptr	= Sel_race_levels;
//			while (level_ptr->li_library_id != -1)
//				{
//				level_ptr->li_flags = SEL_LF_SELECTABLE;
//				level_ptr++;
//				}
			
			// $da: End

			// Initialise level select ( ready for use to view highscores )
			SelectLevelStartup();

			if	(
				(From_options == TRUE) ||
				(HSView_automatic_flag 	== TRUE)
				)
				{
				// We are showing a level stack - init tiled background
				SelectLevelCreateBG();
				}
			break;
		}

	// Did we come from options ( ie are we in high score view mode )
	if (From_options == TRUE)
		{
		// Yes ... create sprites at side of screen
		HSView_arrow_sprite_ptr[0] = MRCreate2DSprite(32,(Game_display_height>>1)-16,Option_viewport_ptr,&im_opt_arrow,NULL);
		HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_HORIZONTAL_FLIP;
		HSView_arrow_sprite_ptr[1] = MRCreate2DSprite(Game_display_width-64,(Game_display_height>>1)-16,Option_viewport_ptr,&im_opt_arrow,NULL);

		// Are we showing logs?
		if (High_score_operation_mode == HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES)
			{
			// Yes ... blank left sprite ( 0 )
			HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			}
		else
			{
			// Are we showing race stack?
//			if ( Sel_mode == SEL_MODE_RACE )
//				{
				// Yes ... blank right sprite ( 1 )
				HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//				}
			}
		}

	// Set auto view count
	HSView_counter = HIGH_SCORE_AFTER_INPUT_DURATION;
}


/******************************************************************************
*%%%% HSViewShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewShutdown(MR_VOID)
*
*	FUNCTION	Shut down high score view.  Which is based on Dean's level select.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HSViewShutdown(MR_VOID)
{

	// According to required mode of high score view operation do ...
	switch ( High_score_operation_mode )
		{

		// Main high scores initialise ------------------------------
		case HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES:

			// Reset display clear colour
			MRSetDisplayClearColour(0x00,0x00,0x00);

			// Shut down scrolly high scores
			HSDeinitialiseScrollyHighScore();
			break;

		// Level select initialise ----------------------------------
		case HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT:

			// Shutdown level select ( as used to view highscores )
			SelectLevelShutdown();
			SelectLevelKillBG();

			// Restore status of level select stack
//			HSViewRestoreStackStatus();

			break;
		}

	// Did we come from options ( ie are we in high score view mode )
	if ( From_options == TRUE)
		{
		// Yes ... kill sprites at side of screen
		MRKill2DSprite(HSView_arrow_sprite_ptr[0]);
		MRKill2DSprite(HSView_arrow_sprite_ptr[1]);
		}

	OptionKill3DSprites();

	// Reset mode
	High_score_operation_mode 	= New_high_score_operation_mode;
	HSView_automatic_flag 		= FALSE;
}


/******************************************************************************
*%%%% HSViewUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewUpdate(MR_VOID)
*
*	FUNCTION	Update high score view.  Which is based on Dean's level select.
*
*	NOTES		Based very much on Dean's SelectLevelUpdate.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HSViewUpdate(MR_VOID)
{

	// Did we come from options ?
	if ( From_options == FALSE )
		{
		// No ... viewing after hiscore input
		if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
			{
			// Yes ... exit now
			Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
			OptionsCameraSnapToMain();
			// Hide level name
			Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			}
		}

	// According to required mode of high score view operation do ...
	switch ( High_score_operation_mode )
		{
		// Main high scores initialise ------------------------------
		case HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES:

			HSUpdateScrollyHighScores();

			// Did we come from options page ?
			if ( From_options == TRUE )
				{
				// Yes ... did we push right ?
				if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], MRIP_RIGHT))
					{
					// Yes ... play sound
					MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

					// Yes ... go on to arcade view
					Sel_mode 						= SEL_MODE_ARCADE;
					Option_page_request 			= OPTIONS_PAGE_HIGH_SCORE_VIEW;
					New_high_score_operation_mode 	= HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT;

					// Stop showing arrows
					HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
					HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
					}
				else
				// Did we push triangle ?
				if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE))
					{
					// DMA: We're leaving the level selection screen, but we didn't select a level
					//		I suggest you replace the 'OPTIONS_PAGE_EXIT' with an appropriate return page identifier.
					// Yes ... play sound
					MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
					Sel_requested_play 	= FALSE;

					// Go back to options
					Option_page_request = OPTIONS_PAGE_OPTIONS;
					OptionsCameraSnapToOptions();

					// Stop showing arrows
					HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
					HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
					}
				}
			else
				{
				// No (we are in view from end of game)
				if (!HSView_counter--)
//				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
					{
					// Go back to main options
					Sel_requested_play	= FALSE;
					Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
	
					// Ensure camera starts where it should
					High_score_view_delayed_request	= NULL;
					OptionsCameraSnapToMain();
					}
				}

			break;

		// Level select initialise ----------------------------------
		case HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT:

			// Are we in automatic mode ?
			if ( HSView_automatic_flag == FALSE )
				{
				// No ... 
				//
				// Allow player to move up and down stack
				SelectUpdateLevelSlide();
				SelectLevelUpdateBG();
				
				// According to mode of operation do ...
				switch (Sel_game_mode)
					{
					// Selecting a level ...
					case SEL_GAME_MODE_SELECTING:
						// Update selecting
						HSViewUpdate_MODE_SELECTING_manual();
						break;

					// Showing level info ...
					case SEL_GAME_MODE_SHOW_LEVEL_INFO:
						// Update viewing info
						HSViewUpdate_MODE_SHOW_LEVEL_INFO_manual();
						break;
					}
				}
			else
				{
				// Yes ... 

				// Allow player to move up and down stack
				SelectUpdateLevelSlide();
				SelectLevelUpdateBG();

				// According to mode of operation do ...
				switch (Sel_game_mode)
					{
					// Selecting a level ...
					case SEL_GAME_MODE_SELECTING:
						// Update selecting
						HSViewUpdate_MODE_SELECTING_automatic();
						break;

					// Showing level info ...
					case SEL_GAME_MODE_SHOW_LEVEL_INFO:
						// Update viewing info
						HSViewUpdate_MODE_SHOW_LEVEL_INFO_automatic();
						break;
					}
				}
			break;
		}

	// Did we come from options ( ie are we in high score view )
	if ( From_options == TRUE )
		{
		// Glow arrow sprites
		HSView_arrow_sprite_ptr[0]->sp_core.sc_base_colour.r = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		HSView_arrow_sprite_ptr[0]->sp_core.sc_base_colour.g = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		HSView_arrow_sprite_ptr[0]->sp_core.sc_base_colour.b = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		HSView_arrow_sprite_ptr[1]->sp_core.sc_base_colour.r = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		HSView_arrow_sprite_ptr[1]->sp_core.sc_base_colour.g = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		HSView_arrow_sprite_ptr[1]->sp_core.sc_base_colour.b = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		}
}


/******************************************************************************
*%%%% HSViewUpdate_MODE_SELECTING_automatic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewUpdate_MODE_SELECTING_automatic(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SELECTING'
*
*	NOTES		Based very much on Dean's SelectUpdate_MODE_SELECTING.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*	03.06.97	William Bell	Re-created as HSViewUpdate_MODE_SELECTING.
*
*%%%**************************************************************************/

MR_VOID	HSViewUpdate_MODE_SELECTING_automatic(MR_VOID)
{
	SEL_LEVEL_INFO*	level_ptr;
	MR_BOOL			next_level_flag;
	MR_TEXTURE*		texture;


	// High score on first level ?
	if ( ( New_high_scores[LEVEL_ORIGINAL1] == 1 ) || ( New_high_scores[LEVEL_ORIGINAL_MULTI_PLAYER] == 1 ) )
		{
			// Yes ... invalidate data
			New_high_scores[LEVEL_ORIGINAL1] = 0;
			New_high_scores[LEVEL_ORIGINAL_MULTI_PLAYER] = 0;
		}
	else
		{
		// Find a level with a new high score
		next_level_flag = FALSE;
		do
			{
			// Get next level
			next_level_flag = SelectFindTarget(SEL_FIND_NEXT);

			// Any more levels ?
			if ( next_level_flag == FALSE )
				{
				// No ... hide level name
				Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
				// Did we get a high high score ?
				if ( New_high_score == 1 )
					{
					// Yes ... show main high scores
					New_high_score_operation_mode 		= HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES;
					High_score_camera_operation_mode 	= HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC;
					Option_page_request 				= OPTIONS_PAGE_HIGH_SCORE_VIEW;
					}
				else
					{
					// No ... go back to main options
					Sel_requested_play	= FALSE;
					Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
					}
				return;
				}

			// Set level not found
			next_level_flag = FALSE;

			// Is this a level with a new high score ?
			if ( New_high_scores[Sel_work_level_ptr->li_library_id] == 1 )
				{
				// Yes ... flag level found
				next_level_flag = TRUE;
				}

			} while ( next_level_flag == FALSE );

		// Set camera position to target position
		Sel_camera_y						= Sel_target_y;
		Sel_camera_frame->fr_matrix.t[1]	= Sel_camera_y;
		}

	// Yes ... play sound
	MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

	// Download "world" VLO
	MRAllocPackedResource(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]);
	MRProcessVLO(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id],MR_GET_RESOURCE_ADDR(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]));
	MRFreePackedResource(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]);

	// Spin out level
	level_ptr 				= Sel_work_level_ptr;
	level_ptr->li_current_z = SEL_LEVEL_SLIDE_DIST;
	Sel_game_mode 			= SEL_GAME_MODE_SHOW_LEVEL_INFO;
	SelectEnableSpinMOF(level_ptr);

	MRChangeSprite(Sel_level_title, level_ptr->li_level_name_texture);
	
	texture = Options_text_textures[OPTION_TEXT_SELECT2][Game_language];
	MRChangeSprite(Sel_user_prompt, texture);
	Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;

	// Are we in arcade mode ?
	if ( Sel_mode == SEL_MODE_ARCADE )
		{
		// Yes ... build arcade table for display
		HighScoreBuildArcadeTimeTable(level_ptr->li_library_id,3);
		}
	else
		{
		// No ... build race table for display
		HighScoreBuildRaceScoreTable(level_ptr->li_library_id,3);
		}

	// Print high scores
	MRBuildText(Sel_score_line[0], Sel_hiscore_text[0], MR_FONT_COLOUR_WHITE);
	MRBuildText(Sel_score_line[1], Sel_hiscore_text[1], MR_FONT_COLOUR_WHITE);
	MRBuildText(Sel_score_line[2], Sel_hiscore_text[2], MR_FONT_COLOUR_WHITE);

	HSView_counter = HIGH_SCORE_VIEW_LEVEL_DURATION;
}


/******************************************************************************
*%%%% HSViewUpdate_MODE_SHOW_LEVEL_INFO_automatic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewUpdate_MODE_SHOW_LEVEL_INFO_automatic(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SHOW_LEVEL_INFO'
*
*	NOTES		Based very much on Dean's SelectUpdate_MODE_SHOW_LEVEL_INFO.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*	03.06.97	William Bell	Re-created as HSViewUpdate_MODE_SHOW_LEVEL_INFO
*
*%%%**************************************************************************/

MR_VOID	HSViewUpdate_MODE_SHOW_LEVEL_INFO_automatic(MR_VOID)
{
	MR_VEC		local_x;
	MR_VEC		local_y;
	MR_VEC		local_z;
	MR_TEXTURE*	texture;


	if ((Sel_spin_mode == SEL_SPIN_OUT) || (Sel_spin_mode == SEL_SPIN_IN))
		{
		SelectUpdateInterpolation();

		if (Sel_spin_mode == SEL_SPIN_OUT)
			{
			Sel_spin_time++;
			if (Sel_spin_time > Sel_spin_max_time)
				{
				// DMA: You could put a sound here for when the spinning mof is at its 2d-like target position
				//		and all hi-scores are in place.
				Sel_spin_time = Sel_spin_max_time;
				Sel_spin_mode = SEL_SPIN_HOLD;
				}
			}
		else
			{
			Sel_spin_time--;
			if (Sel_spin_time < 0)
				{
				// DMA: You could put a sound here for when the spinning mof has returned to its rest position

				Sel_game_mode = SEL_GAME_MODE_SELECTING;
				SelectDisableSpinMOF();

				texture = Options_text_textures[OPTION_TEXT_SELECT1][Game_language];
				MRChangeSprite(Sel_user_prompt, texture);
				Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;
				}
			}

		// Update spinning levels position
		Sel_spin_frame->fr_matrix.t[0] = Sel_temp_pos.vx;
		Sel_spin_frame->fr_matrix.t[1] = Sel_temp_pos.vy;
		Sel_spin_frame->fr_matrix.t[2] = Sel_temp_pos.vz;

		// Update spinning levels rotation
		MRNormaliseVEC(&Sel_temp_vec_y, &local_y);
		MROuterProduct12(&local_y, &Sel_temp_vec_roll, &local_x);
		MRNormaliseVEC(&local_x, &local_x);
		MROuterProduct12(&local_x, &local_y, &local_z);

		Sel_spin_frame->fr_matrix.m[0][0] = local_x.vx;
		Sel_spin_frame->fr_matrix.m[1][0] = local_x.vy;
		Sel_spin_frame->fr_matrix.m[2][0] = local_x.vz;

		Sel_spin_frame->fr_matrix.m[0][1] = local_y.vx;
		Sel_spin_frame->fr_matrix.m[1][1] = local_y.vy;
		Sel_spin_frame->fr_matrix.m[2][1] = local_y.vz;

		Sel_spin_frame->fr_matrix.m[0][2] = local_z.vx;
		Sel_spin_frame->fr_matrix.m[1][2] = local_z.vy;
		Sel_spin_frame->fr_matrix.m[2][2] = local_z.vz;

		// Update score/level name positions
		Sel_level_title->sp_pos.x	= Sel_status_temp_x + (SEL_STATUS_WIDTH >> 1) - (Sel_level_title->sp_image_buf[0]->te_w >> 1);

		Sel_score_line[0]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[1]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[2]->ta_box_x	= Sel_status_temp_x;
		}
	else
//	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
	if (!HSView_counter--)
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
		// Back to level stack
		Sel_spin_mode = SEL_SPIN_IN;
		}

}

/******************************************************************************
*%%%% HSViewUpdate_MODE_SELECTING_manual
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewUpdate_MODE_SELECTING_manual(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SELECTING'
*
*	NOTES		Based very much on Dean's SelectUpdate_MODE_SELECTING.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*	03.06.97	William Bell	Re-created as HSViewUpdate_MODE_SELECTING.
*
*%%%**************************************************************************/

MR_VOID	HSViewUpdate_MODE_SELECTING_manual(MR_VOID)
{
	MR_BOOL			reached_target;
	SEL_LEVEL_INFO*	level_ptr;
	MR_TEXTURE*		texture;


	// Update camera position/acceleration/velocity, and move into matrix
	Sel_camera_vel 	+= Sel_camera_acc;

	if (Sel_camera_vel > SEL_CAMERA_MAX_VEL)
		Sel_camera_vel = SEL_CAMERA_MAX_VEL;

	if (Sel_camera_vel < -SEL_CAMERA_MAX_VEL)
		Sel_camera_vel = -SEL_CAMERA_MAX_VEL;

	Sel_camera_y	+= Sel_camera_vel;

	// Decide whether we've reached our target this frame...
	reached_target = FALSE;
	if (Sel_camera_flag & SEL_CAMERA_GOING_DOWN)
		{
		if ((Sel_camera_frame->fr_matrix.t[1] <= Sel_target_y) && (Sel_camera_y >= Sel_target_y))
			reached_target = TRUE;
		}
	else
	if (Sel_camera_flag & SEL_CAMERA_GOING_UP)
		{
		if ((Sel_camera_frame->fr_matrix.t[1] >= Sel_target_y) && (Sel_camera_y <= Sel_target_y))
			reached_target = TRUE;
		}
	else
	if (Sel_camera_flag == SEL_CAMERA_STATIONARY)
		reached_target = TRUE;

	Sel_camera_frame->fr_matrix.t[1] = Sel_camera_y;

	if (Sel_camera_flag & SEL_CAMERA_STATIONARY)
		{
		if (MR_CHECK_PAD_HELD(Frog_input_ports[0], MRIP_DOWN))
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
			if (SelectFindTarget(SEL_FIND_NEXT) == TRUE)
				{
				Sel_camera_flag = SEL_CAMERA_GOING_DOWN;
				Sel_camera_acc	= SEL_CAMERA_ACC;
				reached_target = FALSE;
				}
			else
				{
				// DMA: No target below us.. perhaps a sound effect here?
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				}
			}
		else
		if (MR_CHECK_PAD_HELD(Frog_input_ports[0], MRIP_UP))
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
			if (SelectFindTarget(SEL_FIND_PREV) == TRUE)
				{
				Sel_camera_flag = SEL_CAMERA_GOING_UP;
				Sel_camera_acc	= -SEL_CAMERA_ACC;
				reached_target = FALSE;
				}
			else
				{
				// DMA: No target above us.. perhaps a sound effect here?
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				}
			}
		else
//		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], MRIP_RIGHT))
//			{
//			if ( Sel_mode == SEL_MODE_ARCADE )
//				{
//				// Yes ... play sound
//				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
//				Sel_mode = SEL_MODE_RACE;
//				Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;
//				// Stop showing arrows
//				HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//				HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//				}
//			}
//		else
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], MRIP_LEFT))
			{
			if ( Sel_mode == SEL_MODE_ARCADE )
				{
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

				New_high_score_operation_mode = HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES;
				Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;

				// Stop showing arrows
				HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
				HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
				}
//			else if ( Sel_mode == SEL_MODE_RACE )
//				{
//				// Yes ... play sound
//				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
//				Sel_mode = SEL_MODE_ARCADE;
//				Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;
//
//				// Stop showing arrows
//				HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//				HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//				}
			}
		else
		if	(MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
			{
			level_ptr = Sel_work_level_ptr;
			if (level_ptr->li_current_z == SEL_LEVEL_SLIDE_DIST)
				{
				// DMA: We have selected a fully extended selectable level.. do something here maybe?
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

				// Download "world" VLO
				MRAllocPackedResource(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]);
				MRProcessVLO(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id],MR_GET_RESOURCE_ADDR(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]));
				MRFreePackedResource(Sel_vlo_res_id[Sel_work_level_ptr->li_world_id]);

				Sel_game_mode = SEL_GAME_MODE_SHOW_LEVEL_INFO;
				SelectEnableSpinMOF(level_ptr);
				MRChangeSprite(Sel_level_title, level_ptr->li_level_name_texture);

				texture = Options_text_textures[OPTION_TEXT_SELECT3][Game_language];
				MRChangeSprite(Sel_user_prompt, texture);
				Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;

				// Are we in arcade mode ?
				if ( Sel_mode == SEL_MODE_ARCADE )
					{
					// Yes ... build arcade table for display
					HighScoreBuildArcadeTimeTable(level_ptr->li_library_id,3);
					}
				else
					{
					// No ... build race table for display
					HighScoreBuildRaceScoreTable(level_ptr->li_library_id,3);
					}

				// Display first three entries of high score table
				MRBuildText(Sel_score_line[0], Sel_hiscore_text[0], MR_FONT_COLOUR_WHITE);
				MRBuildText(Sel_score_line[1], Sel_hiscore_text[1], MR_FONT_COLOUR_WHITE);
				MRBuildText(Sel_score_line[2], Sel_hiscore_text[2], MR_FONT_COLOUR_WHITE);
				return;
				}
			}
		else
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE))
			{
			// DMA: We're leaving the level selection screen, but we didn't select a level
			//		I suggest you replace the 'OPTIONS_PAGE_EXIT' with an appropriate return page identifier.
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
			Sel_requested_play = FALSE;

			// Go back to options
			Option_page_request = OPTIONS_PAGE_OPTIONS;
			OptionsCameraSnapToOptions();

			// Stop showing arrows
			HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			}
		}

	if (Sel_camera_flag == SEL_CAMERA_GOING_DOWN)
		{
		if ((!MR_CHECK_PAD_HELD(Frog_input_ports[0], MRIP_DOWN)))
			{
			Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		else
		if (reached_target == TRUE)
			{
			if (SelectFindTarget(SEL_FIND_NEXT))
				reached_target = FALSE;
			else
				Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		}

	if (Sel_camera_flag == SEL_CAMERA_GOING_UP)
		{
		if ((!MR_CHECK_PAD_HELD(Frog_input_ports[0], MRIP_UP)))
			{
			Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		else
		if (reached_target == TRUE)
			{
			if (SelectFindTarget(SEL_FIND_PREV))
				reached_target = FALSE;
			else
				Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		}


	if ((Sel_camera_flag & SEL_CAMERA_STOPPING) && (reached_target == TRUE))
		{
		Sel_camera_acc	= 0;
		Sel_camera_vel	= 0;
		Sel_camera_flag = SEL_CAMERA_STATIONARY;
		Sel_camera_y	= Sel_target_y;
		Sel_camera_frame->fr_matrix.t[1] = Sel_camera_y;
		}

}

/******************************************************************************
*%%%% HSViewUpdate_MODE_SHOW_LEVEL_INFO_manual
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewUpdate_MODE_SHOW_LEVEL_INFO_manual(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SHOW_LEVEL_INFO'
*
*	NOTES		Based very much on Dean's SelectUpdate_MODE_SHOW_LEVEL_INFO.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*	03.06.97	William Bell	Re-created as HSViewUpdate_MODE_SHOW_LEVEL_INFO
*
*%%%**************************************************************************/

MR_VOID	HSViewUpdate_MODE_SHOW_LEVEL_INFO_manual(MR_VOID)
{
	MR_VEC		local_x;
	MR_VEC		local_y;
	MR_VEC		local_z;
	MR_TEXTURE*	texture;


	if ((Sel_spin_mode == SEL_SPIN_OUT) || (Sel_spin_mode == SEL_SPIN_IN))
		{
		SelectUpdateInterpolation();

		if (Sel_spin_mode == SEL_SPIN_OUT)
			{
			Sel_spin_time++;
			if (Sel_spin_time > Sel_spin_max_time)
				{
				// DMA: You could put a sound here for when the spinning mof is at its 2d-like target position
				//		and all hi-scores are in place.
				Sel_spin_time = Sel_spin_max_time;
				Sel_spin_mode = SEL_SPIN_HOLD;
				}
			}
		else
			{
			Sel_spin_time--;
			if (Sel_spin_time < 0)
				{
				// DMA: You could put a sound here for when the spinning mof has returned to its rest position

				Sel_game_mode = SEL_GAME_MODE_SELECTING;
				SelectDisableSpinMOF();
				texture = Options_text_textures[OPTION_TEXT_SELECT1][Game_language];
				MRChangeSprite(Sel_user_prompt, texture);
				Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;
				}
			}

		// Update spinning levels position
		Sel_spin_frame->fr_matrix.t[0] = Sel_temp_pos.vx;
		Sel_spin_frame->fr_matrix.t[1] = Sel_temp_pos.vy;
		Sel_spin_frame->fr_matrix.t[2] = Sel_temp_pos.vz;

		// Update spinning levels rotation
		MRNormaliseVEC(&Sel_temp_vec_y, &local_y);
		MROuterProduct12(&local_y, &Sel_temp_vec_roll, &local_x);
		MRNormaliseVEC(&local_x, &local_x);
		MROuterProduct12(&local_x, &local_y, &local_z);

		Sel_spin_frame->fr_matrix.m[0][0] = local_x.vx;
		Sel_spin_frame->fr_matrix.m[1][0] = local_x.vy;
		Sel_spin_frame->fr_matrix.m[2][0] = local_x.vz;

		Sel_spin_frame->fr_matrix.m[0][1] = local_y.vx;
		Sel_spin_frame->fr_matrix.m[1][1] = local_y.vy;
		Sel_spin_frame->fr_matrix.m[2][1] = local_y.vz;

		Sel_spin_frame->fr_matrix.m[0][2] = local_z.vx;
		Sel_spin_frame->fr_matrix.m[1][2] = local_z.vy;
		Sel_spin_frame->fr_matrix.m[2][2] = local_z.vz;

		// Update score/level name positions
		Sel_level_title->sp_pos.x	= Sel_status_temp_x + (SEL_STATUS_WIDTH >> 1) - (Sel_level_title->sp_image_buf[0]->te_w >> 1);

		Sel_score_line[0]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[1]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[2]->ta_box_x	= Sel_status_temp_x;
		}
	else
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE))
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
		// Back to level stack
		Sel_spin_mode = SEL_SPIN_IN;
		}
	else
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], MRIP_LEFT))
		{
		if ( Sel_mode == SEL_MODE_ARCADE )
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

			New_high_score_operation_mode = HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES;
			Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;

			// Stop showing arrows
			HSView_arrow_sprite_ptr[0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			HSView_arrow_sprite_ptr[1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

			// Hide level name
			Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

			}
		}

}

/******************************************************************************
*%%%% HighScoreBuildArcadeTimeTable
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreBuildArcadeTimeTable(MR_ULONG hiscore_table_number,
*												MR_LONG num_entries);
*
*	FUNCTION	Builds this levels high score table into the static MR_STRPTRs
*				used to build the text.
*
*	INPUTS		hiscore_table_number		- The number of the table to display
*
*				num_entries					- The number of entries to build
*
*	NOTES		Arcade mode ( sorted on total level time ) ( 3 entries per level ) -
*				Name	Total Level Time	Time to Checkpoint 1 2 3 4 5	Score
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreBuildArcadeTimeTable(MR_ULONG hiscore_table_number,MR_ULONG num_entries)
{
	MR_ULONG			entry_count;
	MR_UBYTE*			text_ptr;
	HIGH_SCORE_ENTRY*	hs_entry_ptr;
	MR_ULONG			minutes;
	MR_ULONG			seconds;
	MR_ULONG			score;
	MR_ULONG			count;
	MR_ULONG			total_time;

	// Is this jungle 2 ?
	if ( hiscore_table_number == LEVEL_JUNGLE2 )
		{
		// Yes ... no it isn't!
		hiscore_table_number = LEVEL_JUNGLE1;
		}

	// Get pointer to arcade high score entry
	hs_entry_ptr = &Level_high_scores[hiscore_table_number][0];

	// Assert if building too many entries
	MR_ASSERT(num_entries < 4);

	// Loop once for each entry in high score table
	for(entry_count = 0; entry_count < num_entries; entry_count++)
		{
		// Get pointer to text
		text_ptr = *Sel_hiscore_text[entry_count];

		// Blank text
		for(count = 3; count < 21; count++)
			*(text_ptr+count) = ' ';

		// Set initials
		*(text_ptr+3) = hs_entry_ptr->he_initials[0];
		*(text_ptr+4) = hs_entry_ptr->he_initials[1];
		*(text_ptr+5) = hs_entry_ptr->he_initials[2];

		// Calculate time in minutes and seconds
		total_time = hs_entry_ptr->he_time_to_checkpoint[0] +
						hs_entry_ptr->he_time_to_checkpoint[1] +
						hs_entry_ptr->he_time_to_checkpoint[2] +
						hs_entry_ptr->he_time_to_checkpoint[3] +
						hs_entry_ptr->he_time_to_checkpoint[4];
		seconds = total_time % 60;
		minutes = total_time / 60;

		// Time out of range ?
		if ( minutes > 99 )
			{
			// Yes ... set to max
			minutes = 99;
			seconds = 59;
			}

		// Set seconds and minutes
//		*(text_ptr+11) = (seconds % 10) + 48;
//		*(text_ptr+10) = (seconds / 10) + 48;
//		*(text_ptr+9) = ':';
//		*(text_ptr+8) = (minutes % 10) + 48;
//		*(text_ptr+7) = (minutes / 10) + 48;

		*(text_ptr+21) = (seconds % 10) + 48;
		*(text_ptr+20) = (seconds / 10) + 48;
		*(text_ptr+19) = ':';
		*(text_ptr+18) = (minutes % 10) + 48;
		*(text_ptr+17) = (minutes / 10) + 48;

		// Display time to each checkpoint

		// Get total score
		score = hs_entry_ptr->he_score;

		// Loop once for each digit in score
		count = 8;
		while(count--)
			{
			// Set current score digit
//			*(text_ptr+13+count) = (score % 10) + 48;
			*(text_ptr+7+count) = (score % 10) + 48;
			// Adjust total score
			score /= 10;
			};

		// Blank leading zeros from score ( leaving last one - in case score is actually zero )
		for(count=0;count<7;count++)
			{
			// Leading zero ?
//			if ( *(text_ptr+13+count) == '0' )
			if ( *(text_ptr+7+count) == '0' )
				{
				// Yes ... space out zero
//				*(text_ptr+13+count) = ' ';
				*(text_ptr+7+count) = ' ';
				}
			else
				{
				// No ... break loop
				break;
				}
			}

		// Inc pointer to next high score entry
		hs_entry_ptr++;

		}

}

/******************************************************************************
*%%%% HighScoreBuildRaceScoreTable
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreBuildRaceScoreTable(MR_ULONG hiscore_table_number,
*												MR_LONG num_entries);
*
*	FUNCTION	Builds this levels high score table into the static MR_STRPTRs
*				used to build the text.
*
*	INPUTS		hiscore_table_number		- The number of the table to display
*
*				num_entries					- The number of entries to build
*
*	NOTES		Racde mode ( sorted on score ) ( 3 entries per level ) -
*				Name	Score
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreBuildRaceScoreTable(MR_ULONG hiscore_table_number,MR_ULONG num_entries)
{
	MR_ULONG			entry_count;
	MR_UBYTE*			text_ptr;
	HIGH_SCORE_ENTRY*	hs_entry_ptr;
//	MR_ULONG			score;
	MR_ULONG			count;

	// Get pointer to race high score entry
	hs_entry_ptr = &Level_high_scores[hiscore_table_number][0];

	// Assert if building too many entries
	MR_ASSERT(num_entries < 4);

	// Loop once for each entry in high score table
	for(entry_count = 0; entry_count < num_entries; entry_count++)
		{
		// Get pointer to text
		text_ptr = *Sel_hiscore_text[entry_count];

		// Blank text
		for(count = 3; count < 22; count++)
			*(text_ptr+count) = ' ';

		// Set initials
/*		*(text_ptr+6) = hs_entry_ptr->he_initials[0];
		*(text_ptr+7) = hs_entry_ptr->he_initials[1];
		*(text_ptr+8) = hs_entry_ptr->he_initials[2];

		// Get total score
		score = hs_entry_ptr->he_score;

		// Loop once for each digit in score
		count = 8;
		while(count--)
			{
			// Set current score digit
			*(text_ptr+10+count) = (score % 10) + 48;
			// Adjust total score
			score /= 10;
			};

		// Blank leading zeros from score ( leaving last one - in case score is actaully zero )
		for(count=0;count<7;count++)
			{
			// Leading zero ?
			if ( *(text_ptr+10+count) == '0' )
				{
				// Yes ... space out zero
				*(text_ptr+10+count) = ' ';
				}
			else
				{
				// No ... break loop
				break;
				}
			}
*/
		// Inc pointer to next high score entry
		hs_entry_ptr++;
		}
}

#if 0

/******************************************************************************
*%%%% HighScoreBuildScoreTable
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreBuildScoreTable(MR_ULONG num_entries);
*
*	FUNCTION	Builds the global high score table into the static MR_STRPTRs
*				used to build the text.
*
*	INPUTS		num_entries					- The number of entries to build
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreBuildScoreTable(MR_ULONG num_entries)
{

	// Locals
	MR_ULONG			entry_count;
	MR_UBYTE*			text_ptr;
	HIGH_SCORE_ENTRY*	hs_entry_ptr;
	MR_ULONG			score;
	MR_ULONG			count;

	// Get pointer to high score table
	hs_entry_ptr = &Game_high_score[0];

	// Loop once for each entry in high score table
	for(entry_count=0;entry_count<num_entries;entry_count++)
		{

		// Get pointer to text
		text_ptr = *Sel_hiscore_text[entry_count];

		// Set initials
		*(text_ptr+3) = hs_entry_ptr->he_initials[0];
		*(text_ptr+4) = hs_entry_ptr->he_initials[1];
		*(text_ptr+5) = hs_entry_ptr->he_initials[2];

		// Blank seconds and minutes
		*(text_ptr+11) = ' ';
		*(text_ptr+10) = ' ';
		*(text_ptr+9) = ' ';
		*(text_ptr+8) = ' ';
		*(text_ptr+7) = ' ';

		// Get total score
		score = hs_entry_ptr->he_score;

		// Loop once for each digit in score
		count = 8;
		while(count--)
			{
			// Set current score digit
			*(text_ptr+14+count) = (score % 10) + 48;
			// Adjust total score
			score /= 10;
			};

		// Blank leading zeros from score ( leaving last one - in case score is actaully zero )
		for(count=0;count<7;count++)
			{
			// Leading zero ?
			if ( *(text_ptr+14+count) == '0' )
				{
				// Yes ... space out zero
				*(text_ptr+14+count) = ' ';
				}
			else
				{
				// No ... break loop
				break;
				}
			}

		// Inc pointer to next high score entry
		hs_entry_ptr++;

		}
}
#endif


/******************************************************************************
*%%%% HSInitialiseWater
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSInitialiseWater(
*						MR_TEXTURE*	surface_texture,
*						MR_TEXTURE*	bed_texture)
*
*	FUNCTION	Initalise water and river bed for options screens.
*
*	INPUTS		surface_texture	-	ptr to surface texture
*				bed_texture		-	ptr to bed texture
*
*	NOTES		Water surface is 8x8 array of FT4
*				Riverbed is 8x8 array of FT4
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSInitialiseWater(	MR_TEXTURE*	surface_texture,
							MR_TEXTURE*	bed_texture)
{
//	POLY_G4*	poly_g4;
	POLY_FT4*	poly_ft4;
	MR_LONG		i, j, k;
	MR_TEXTURE*	texture;
	MR_SVEC*	svec_ptr;


	// Set background colour
	MRSetDisplayClearColour(0, 0, 0);

//	// Set up sky prims
//	poly_g4 = High_score_view_sky_prims;
//	for (k = 0; k < 2; k++)
//		{
//		setPolyG4(poly_g4);
//		poly_g4->x0 = 0;
//		poly_g4->x1 = Game_display_width;
//		poly_g4->x2 = 0;
//		poly_g4->x3 = Game_display_width;
//		poly_g4->y0 = 0;
//		poly_g4->y1 = 0;
//		poly_g4->y2 = Game_display_height / 7;
//		poly_g4->y3 = Game_display_height / 7;
//		setRGB0(poly_g4, 0x40, 0x40, 0xa0);
//		setRGB1(poly_g4, 0x40, 0x40, 0xa0);
//		setRGB2(poly_g4, 0x00, 0x00, 0x20);
//		setRGB3(poly_g4, 0x00, 0x00, 0x20);
//		poly_g4++;
//		}

	// Allocate vertices
	i										= (HIGH_SCORE_VIEW_WATER_X_NUM + 1) * (HIGH_SCORE_VIEW_WATER_Z_NUM + 1);
	High_score_view_water_points_ptr 		= MRAllocMem(sizeof(MR_SVEC) * i,	"HS water points");
	i										= (HIGH_SCORE_VIEW_RIVERBED_X_NUM + 1) * (HIGH_SCORE_VIEW_RIVERBED_Z_NUM + 1);
	High_score_view_riverbed_points_ptr 	= MRAllocMem(sizeof(MR_SVEC) *i,	"HS riverbed points");

	// Create water surface
	i										= HIGH_SCORE_VIEW_WATER_X_NUM * HIGH_SCORE_VIEW_WATER_Z_NUM;
	High_score_view_water_prim_ptrs[0] 		= MRAllocMem(sizeof(POLY_FT4) * i * 2, "HS water prims");
	High_score_view_water_prim_ptrs[1] 		= High_score_view_water_prim_ptrs[0] + i;

	poly_ft4 	= High_score_view_water_prim_ptrs[0];
	texture		= surface_texture;

#ifdef WIN95
	// This sets ABR value 1.. useful for when someone forgets to set up Vorg correctly :/
	texture->te_tpage_id |= (1<<8);
#endif

	for (k = 0; k < 2; k++)
		{
		for (j = 0; j < HIGH_SCORE_VIEW_WATER_Z_NUM; j++)
			{
			for (i = 0; i < HIGH_SCORE_VIEW_WATER_X_NUM; i++)
				{
				MR_COPY32(poly_ft4->r0, High_score_view_water_prim_colours[0]);
				setPolyFT4(poly_ft4);
				setSemiTrans(poly_ft4, 1);

				// Map single texture across whole poly mesh
				poly_ft4->u0 = texture->te_u0 + ((texture->te_w * (i + 0)) / HIGH_SCORE_VIEW_WATER_X_NUM);
				poly_ft4->u1 = texture->te_u0 + ((texture->te_w * (i + 1)) / HIGH_SCORE_VIEW_WATER_X_NUM);
				poly_ft4->u2 = texture->te_u0 + ((texture->te_w * (i + 0)) / HIGH_SCORE_VIEW_WATER_X_NUM);
				poly_ft4->u3 = texture->te_u0 + ((texture->te_w * (i + 1)) / HIGH_SCORE_VIEW_WATER_X_NUM);
				poly_ft4->v0 = texture->te_v0 + ((texture->te_h * (j + 0)) / HIGH_SCORE_VIEW_WATER_Z_NUM);
				poly_ft4->v1 = texture->te_v0 + ((texture->te_h * (j + 0)) / HIGH_SCORE_VIEW_WATER_Z_NUM);
				poly_ft4->v2 = texture->te_v0 + ((texture->te_h * (j + 1)) / HIGH_SCORE_VIEW_WATER_Z_NUM);
				poly_ft4->v3 = texture->te_v0 + ((texture->te_h * (j + 1)) / HIGH_SCORE_VIEW_WATER_Z_NUM);

				poly_ft4->tpage = texture->te_tpage_id;
#ifdef	PSX
				poly_ft4->clut	= texture->te_clut_id;
#endif
				poly_ft4++;
				}
			}
		}

	// Initialise water positions
	svec_ptr = High_score_view_water_points_ptr;
	for (j = 0; j < HIGH_SCORE_VIEW_WATER_Z_NUM + 1; j++)
		{
		for (i = 0; i < HIGH_SCORE_VIEW_WATER_X_NUM + 1; i++)
			{
			svec_ptr->vx = -((HIGH_SCORE_VIEW_WATER_X_LEN * HIGH_SCORE_VIEW_WATER_X_NUM) / 2) + (i * HIGH_SCORE_VIEW_WATER_X_LEN);
			svec_ptr->vy = 0;
			svec_ptr->vz =  ((HIGH_SCORE_VIEW_WATER_Z_LEN * HIGH_SCORE_VIEW_WATER_Z_NUM) / 2) - (j * HIGH_SCORE_VIEW_WATER_Z_LEN);
			svec_ptr++;
			}
		}	

	// Create riverbed
	i										= HIGH_SCORE_VIEW_RIVERBED_X_NUM * HIGH_SCORE_VIEW_RIVERBED_Z_NUM;
	High_score_view_riverbed_prim_ptrs[0] 	= MRAllocMem(sizeof(POLY_FT4) * i * 2, "HS riverbed prims");
	High_score_view_riverbed_prim_ptrs[1] 	= High_score_view_riverbed_prim_ptrs[0] + i;

	poly_ft4 	= High_score_view_riverbed_prim_ptrs[0];
	texture		= bed_texture;

	for (k = 0; k < 2; k++)
		{
		for (j = 0; j < HIGH_SCORE_VIEW_RIVERBED_Z_NUM; j++)
			{
			for (i = 0; i < HIGH_SCORE_VIEW_RIVERBED_X_NUM; i++)
				{
				MR_COPY32(poly_ft4->r0, High_score_view_water_prim_colours[1]);
				setPolyFT4(poly_ft4);

				// Map texture onto each poly
				if (j & 1)
					{
					MR_COPY16(poly_ft4->u0, texture->te_u0);
					MR_COPY16(poly_ft4->u1, texture->te_u1);
					MR_COPY16(poly_ft4->u2, texture->te_u2);
					MR_COPY16(poly_ft4->u3, texture->te_u3);
					}	
				else
					{
					MR_COPY16(poly_ft4->u2, texture->te_u0);
					MR_COPY16(poly_ft4->u3, texture->te_u1);
					MR_COPY16(poly_ft4->u0, texture->te_u2);
					MR_COPY16(poly_ft4->u1, texture->te_u3);
					}
				poly_ft4->tpage = texture->te_tpage_id;
#ifdef PSX
				poly_ft4->clut 	= texture->te_clut_id;
#endif
				poly_ft4++;
				}
			}
		}

	// Initialise riverbed positions
	svec_ptr = High_score_view_riverbed_points_ptr;
	for (j = 0; j < HIGH_SCORE_VIEW_RIVERBED_Z_NUM + 1; j++)
		{
		for (i = 0; i < HIGH_SCORE_VIEW_RIVERBED_X_NUM + 1; i++)
			{
			svec_ptr->vx = -((HIGH_SCORE_VIEW_RIVERBED_X_LEN * HIGH_SCORE_VIEW_RIVERBED_X_NUM) / 2) + (i * HIGH_SCORE_VIEW_RIVERBED_X_LEN);
			svec_ptr->vy = 0;
			svec_ptr->vz =  ((HIGH_SCORE_VIEW_RIVERBED_Z_LEN * HIGH_SCORE_VIEW_RIVERBED_Z_NUM) / 2) - (j * HIGH_SCORE_VIEW_RIVERBED_Z_LEN);
			svec_ptr++;
			}
		}	
}


/******************************************************************************
*%%%% HSUpdateWater
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSUpdateWater(MR_VOID)
*
*	FUNCTION	Update water and river bed for options screens.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSUpdateWater(MR_VOID)
{
	MR_LONG		i, j, t, tx, tz, d;
	POLY_FT4*	poly_ft4;
	MR_SVEC		rot;
	MR_SVEC*	svec_ptr[4];


	// Apply wave deltas to vertex y
	svec_ptr[0]	= &High_score_view_water_points_ptr[0];
	t			= Option_viewport_ptr->vp_frame_count;

	for (j = 0; j <= HIGH_SCORE_VIEW_WATER_Z_NUM; j++)
		{
		for (i = 0; i <= HIGH_SCORE_VIEW_WATER_X_NUM; i++)
			{
			tx 				= ((i * HIGH_SCORE_VIEW_WAVE_PERIOD_X) / HIGH_SCORE_VIEW_WATER_X_NUM) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_X);
			tz 				= ((j * HIGH_SCORE_VIEW_WAVE_PERIOD_Z) / HIGH_SCORE_VIEW_WATER_Z_NUM) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_Z);
			d				= ((rsin(tx) * HIGH_SCORE_VIEW_WAVE_AMP_X) + (rsin(tz) * HIGH_SCORE_VIEW_WAVE_AMP_Z)) >> 12;
			svec_ptr[0]->vy = d;
			svec_ptr[0]++;
			}
		}

	// Set up rotation matrix
	MRSetActiveViewport(Option_viewport_ptr);
	rot.vx = -Option_viewport_ptr->vp_render_matrix.t[0];
	rot.vy = -Option_viewport_ptr->vp_render_matrix.t[1];
	rot.vz = -Option_viewport_ptr->vp_render_matrix.t[2];
	gte_SetRotMatrix(&Option_viewport_ptr->vp_render_matrix);
	MRApplyRotMatrix(&rot, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);

	// Render riverbed
	svec_ptr[0]	= &High_score_view_riverbed_points_ptr[0];
	svec_ptr[1]	= &High_score_view_riverbed_points_ptr[1];
	svec_ptr[2]	= &High_score_view_riverbed_points_ptr[HIGH_SCORE_VIEW_RIVERBED_X_NUM + 1];
	svec_ptr[3]	= &High_score_view_riverbed_points_ptr[HIGH_SCORE_VIEW_RIVERBED_X_NUM + 2];
	poly_ft4 	= High_score_view_riverbed_prim_ptrs[MRFrame_index];

	for (j = 0; j < HIGH_SCORE_VIEW_RIVERBED_Z_NUM; j++)
		{
		for (i = 0; i < HIGH_SCORE_VIEW_RIVERBED_X_NUM; i++)
			{
			gte_ldv3(svec_ptr[0], svec_ptr[1], svec_ptr[2]);
			gte_rtpt();
			svec_ptr[0]++;
			svec_ptr[1]++;
			svec_ptr[2]++;
			gte_stsxy3(	(MR_LONG*)&poly_ft4->x0,
						(MR_LONG*)&poly_ft4->x1,
						(MR_LONG*)&poly_ft4->x2);
			gte_ldv0(svec_ptr[3]);
			gte_rtps();
			svec_ptr[3]++;
			gte_stsxy(	(MR_LONG*)&poly_ft4->x3);

			addPrim(Option_viewport_ptr->vp_work_ot + Option_viewport_ptr->vp_ot_size - 1, poly_ft4);
			poly_ft4++;
			}
		svec_ptr[0]++;
		svec_ptr[1]++;
		svec_ptr[2]++;
		svec_ptr[3]++;
		}

	// Render water
	svec_ptr[0]	= &High_score_view_water_points_ptr[0];
	svec_ptr[1]	= &High_score_view_water_points_ptr[1];
	svec_ptr[2]	= &High_score_view_water_points_ptr[HIGH_SCORE_VIEW_WATER_X_NUM + 1];
	svec_ptr[3]	= &High_score_view_water_points_ptr[HIGH_SCORE_VIEW_WATER_X_NUM + 2];
	poly_ft4 	= High_score_view_water_prim_ptrs[MRFrame_index];

	for (j = 0; j < HIGH_SCORE_VIEW_WATER_Z_NUM; j++)
		{
		for (i = 0; i < HIGH_SCORE_VIEW_WATER_X_NUM; i++)
			{
			gte_ldv3(svec_ptr[0], svec_ptr[1], svec_ptr[2]);
			gte_rtpt();
			svec_ptr[0]++;
			svec_ptr[1]++;
			svec_ptr[2]++;
			gte_stsxy3(	(MR_LONG*)&poly_ft4->x0,
						(MR_LONG*)&poly_ft4->x1,
						(MR_LONG*)&poly_ft4->x2);
			gte_ldv0(svec_ptr[3]);
			gte_rtps();
			svec_ptr[3]++;
			gte_stsxy(	(MR_LONG*)&poly_ft4->x3);

			addPrim(Option_viewport_ptr->vp_work_ot + Option_viewport_ptr->vp_ot_size - 3, poly_ft4);
			poly_ft4++;
			}
		svec_ptr[0]++;
		svec_ptr[1]++;
		svec_ptr[2]++;
		svec_ptr[3]++;
		}

	// Render sky
//	addPrim(Option_viewport_ptr->vp_work_ot + Option_viewport_ptr->vp_ot_size - 1, &High_score_view_sky_prims[MRFrame_index]);
}


/******************************************************************************
*%%%% HSDeinitialiseWater
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSDeinitialiseWater(MR_VOID)
*
*	FUNCTION	Deinitalise water and river bed for options screens.  Remove fish
*				model.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSDeinitialiseWater(MR_VOID)
{
	// Flag prims to be free'd
	InitialisePrimFree((MR_UBYTE*)High_score_view_water_prim_ptrs[0]);
	InitialisePrimFree((MR_UBYTE*)High_score_view_riverbed_prim_ptrs[0]);

	// Free other buffers
	MRFreeMem(High_score_view_water_points_ptr);
	MRFreeMem(High_score_view_riverbed_points_ptr);
}

	
/******************************************************************************
*%%%% HSInitialiseScrollyHighScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSInitialiseScrollyHighScore(MR_VOID)
*
*	FUNCTION	Initialisation for scrolly high score table.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSInitialiseScrollyHighScore(MR_VOID)
{
	MR_LONG		i, j, k, l;
	MR_ULONG	score_digit;
	MR_ULONG	log_score;
	MR_ULONG	power;
	FROG*		frog;
	MR_MESH*	mesh_ptr;


	// Allocate memory for all matrices
	// (1 frog, 10 numbers, 30 letters, 10 logs)
	High_score_matrices = MRAllocMem(sizeof(MR_MAT) * (1 + 10 + 30 + 10 + HIGH_SCORE_VIEW_NUM_EXTRAS), "HS matrices");

	High_score_view_frog_anim_matrix_ptr 		= High_score_matrices;
	for (k = 0; k < 10; k++)	
		High_score_view_number_matrix_ptr[k] 	= High_score_matrices + 1 + k;
	for (k = 0; k < 30; k++)	
		High_score_view_initials_matrix_ptr[k] 	= High_score_matrices + 11 + k;
	for (k = 0; k < 10; k++)	
		High_score_view_log_matrix_ptr[k] 		= High_score_matrices + 41 + k;
	for (k = 0; k < HIGH_SCORE_VIEW_NUM_EXTRAS; k++)	
		High_score_view_extras_matrix_ptr[k]	= High_score_matrices + 51 + k;

	// Create extras
	for (i = 0; i < HIGH_SCORE_VIEW_NUM_EXTRAS; i++)
		{
		MR_INIT_MAT(High_score_view_extras_matrix_ptr[i]);
		High_score_view_extras_matrix_ptr[i]->t[0] 	= High_score_view_extras_coords[(i << 1) + 0];
		High_score_view_extras_matrix_ptr[i]->t[1] 	= OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_extras_matrix_ptr[i]->t[2] 	= High_score_view_extras_coords[(i << 1) + 1];
		High_score_view_extras_object_ptr[i] 		= MRCreateMesh(MR_GET_RESOURCE_ADDR(High_score_view_extras_resource_id[i]), (MR_FRAME*)High_score_view_extras_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_view_extras_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Create numbers down left hand side (1 at bottom, 10 at top)
	//
	// Loop once for each number
	for (i = 0; i < 10; i++)
		{
		// Create stuff for each model
		MR_INIT_MAT(High_score_view_number_matrix_ptr[i]);
		High_score_view_number_matrix_ptr[i]->t[0] 	= -0x480;
		High_score_view_number_matrix_ptr[i]->t[1] 	= OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_number_matrix_ptr[i]->t[2] 	= (-9 * 0x80) + (i * 0x100);

		High_score_view_number_anim_env_ptr[i] 		= MRAnimEnvFlipbookCreateWhole(	MR_GET_RESOURCE_ADDR(RES_OPT_TURTLE_XMR),
																					MR_OBJ_STATIC,
																					(MR_FRAME*)High_score_view_number_matrix_ptr[i]);
		MRAnimEnvFlipbookSetAction(High_score_view_number_anim_env_ptr[i], 0);
		MRAnimAddEnvToViewport(High_score_view_number_anim_env_ptr[i], Option_viewport_ptr, 0);

		// Turn off animated textures, and set correct animated textures
		mesh_ptr 			= High_score_view_number_anim_env_ptr[i]->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh;
		mesh_ptr->me_flags 	|= MR_MESH_PAUSE_ANIMATED_POLYS;

		for (j = 0; j < 12; j++)
			MRMeshAnimatedPolySetCel(mesh_ptr, j, 9-i);
		}

	// Create Frog ready to jump up numbers
	//
	// Get address of Frog model in memory
	High_score_view_frog_anim_model_ptr = MR_GET_RESOURCE_ADDR(RES_GEN_FROG_XAR);

	// Assert if Frog model currently not in memory
	MR_ASSERT(High_score_view_frog_anim_model_ptr!=NULL);

	MR_INIT_MAT(High_score_view_frog_anim_matrix_ptr);

	// Create frogs and add to viewport
	High_score_view_frog_anim_env_ptr = MRAnimEnvSingleCreateWhole(High_score_view_frog_anim_model_ptr, 0, MR_OBJ_STATIC, (MR_FRAME*)High_score_view_frog_anim_matrix_ptr);

	// Try and make the Frog anim a ONE SHOT.
	High_score_view_frog_anim_env_ptr->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

	// Set a default animation action
	MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_WAIT2);
	High_score_view_frog_anim_env_ptr->ae_update_period = 2;

	// Scale croak sack down
	MRAnimEnvSingleCreateLWTransforms(High_score_view_frog_anim_env_ptr);
	MRAnimEnvSingleSetPartFlags(High_score_view_frog_anim_env_ptr, THROAT, MR_ANIM_PART_TRANSFORM_PART_SPACE);
	MRAnimEnvSingleSetImportedTransform(High_score_view_frog_anim_env_ptr, THROAT, &High_score_view_frog_sack_scale_matrix);
	MR_INIT_MAT(&High_score_view_frog_sack_scale_matrix);
	High_score_view_frog_sack_scale_matrix.m[0][0] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[1][1] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[2][2] = FROG_CROAK_MIN_SCALE;

	// Attach to game viewports
	MRAnimAddEnvToViewport(High_score_view_frog_anim_env_ptr,Option_viewport_ptr,0);
	
	// Use Frogs[0] to store info about frog jumping along numbers
	frog		   		= &Frogs[0];
	frog->fr_lwtrans 	= High_score_view_frog_anim_matrix_ptr;
	frog->fr_grid_z		= 0;												// lilly that frog is on
	frog->fr_mode 		= FROG_MODE_STATIONARY;								// wait before jumping
	frog->fr_count		= HIGH_SCORE_VIEW_FROG_WAIT_TIME;					// time before jumping
	frog->fr_pos.vx		= High_score_view_number_matrix_ptr[0]->t[0] << 16;
	frog->fr_pos.vy		= High_score_view_number_matrix_ptr[0]->t[1] << 16;
	frog->fr_pos.vz		= High_score_view_number_matrix_ptr[0]->t[2] << 16;
	frog->fr_direction 	= FROG_DIRECTION_N;

	// Create shadow for frog
	frog->fr_shadow 			= CreateShadow(Frog_jump_shadow_textures[0], frog->fr_lwtrans, Frog_jump_shadow_offsets[0]);
	frog->fr_shadow->ef_flags	|= EFFECT_STATIC;
	frog->fr_shadow->ef_flags	&= ~EFFECT_KILL_WHEN_FINISHED;

	// Create lillies for initials (remember score 1, highest, is at bottom)
	//
	// Loop once for each initial
	for (i = 0; i < 30; i++)
		{
		if (Game_high_score[i / 3].he_initials[i % 3] == '.')
			{
			// Get address of '.' model in memory
			High_score_view_initials_model_ptr[i] = MR_GET_RESOURCE_ADDR(High_score_input_letters_resource_id[26]);
			}
		else
		if (Game_high_score[i / 3].he_initials[i % 3] == ' ')
			{
			// Get address of ' ' model in memory
			High_score_view_initials_model_ptr[i] = MR_GET_RESOURCE_ADDR(High_score_input_letters_resource_id[27]);
			}
		else
			{
			// No ... get address of letter in memory
			High_score_view_initials_model_ptr[i] = MR_GET_RESOURCE_ADDR(High_score_input_letters_resource_id[Game_high_score[i / 3].he_initials[i % 3]- 'A']);
			}

		// Assert if letter not currently in memory
		MR_ASSERT(High_score_view_initials_model_ptr[i]!=NULL);

		MR_INIT_MAT(High_score_view_initials_matrix_ptr[i]);
		High_score_view_initials_matrix_ptr[i]->t[0] = -0x300 + ((i % 3) * 0x100);
		High_score_view_initials_matrix_ptr[i]->t[1] = OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_initials_matrix_ptr[i]->t[2] = (-9 * 0x80) + ((9-(i / 3)) * 0x100);

		// Create stuff for each model
		High_score_view_initials_object_ptr[i]	= MRCreateMesh(High_score_view_initials_model_ptr[i], (MR_FRAME*)High_score_view_initials_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		High_score_view_initials_inst_ptr[i] 	= MRAddObjectToViewport(High_score_view_initials_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Create logs for scores
	//
	// Loop once for each log
	for (i = 0; i < 10; i++)
		{
		// Get address of number in memory
		High_score_view_log_model_ptr[i] = MR_GET_RESOURCE_ADDR(RES_HI_LOG_XMR);

		// Assert if letter not currently in memory
		MR_ASSERT(High_score_view_log_model_ptr[i]!=NULL);

		MR_INIT_MAT(High_score_view_initials_matrix_ptr[i]);
		High_score_view_log_matrix_ptr[i]->t[0] = 0x280;
		High_score_view_log_matrix_ptr[i]->t[1] = OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_log_matrix_ptr[i]->t[2] = (-9 * 0x80) + ((9-i) * 0x100);

		// Create model
		High_score_view_log_object_ptr[i] = MRCreateMesh(High_score_view_log_model_ptr[i], (MR_FRAME*)High_score_view_log_matrix_ptr[i], MR_OBJ_STATIC, NULL);

		// Run through all digit texture polys, setting 'no animation' flag
		High_score_view_log_object_ptr[i]->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_PAUSE_ANIMATED_POLYS;

		// Add object to viewport
		High_score_view_log_inst_ptr[i] = MRAddObjectToViewport(High_score_view_log_object_ptr[i], Option_viewport_ptr, 0);

		// Set correct digit textures
		log_score 	= Game_high_score[i].he_score;
		l			= 0;
		for (j = 0; j < 8; j++)
			{
			score_digit = log_score;
			k			= 7 - j;
			power		= 1;
			while(k--)
				power *= 10;
			score_digit /= power;
			log_score = log_score - (score_digit * power);
			
			if	(
				(score_digit == 0) &&
				(l == 0) &&
				(j < 7)
				)
				// Leading space
				score_digit = 10;
			else
				l = 1;

			for (k = 0; k < 8; k++)
				MRMeshAnimatedPolySetCel(High_score_view_log_object_ptr[i]->ob_extra.ob_extra_mesh, High_score_log_animated_poly_indices[j] + k, score_digit);
			}
		}

	// Update mesh instances animated polys for logs
	MRFrame_index ^= 1;
	MRUpdateViewportMeshInstancesAnimatedPolys(Option_viewport_ptr);
	MRFrame_index ^= 1;
	MRUpdateViewportMeshInstancesAnimatedPolys(Option_viewport_ptr);
	for (i = 0; i < 10; i++)
		{
		High_score_view_log_object_ptr[i]->ob_extra.ob_extra_mesh->me_flags &= ~MR_MESH_ANIMATED_POLYS;
		High_score_view_number_anim_env_ptr[i]->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_flags &= ~MR_MESH_ANIMATED_POLYS;
		}

	High_score_view_flyon_counter 	= OPTIONS_CAMERA_FLYON_TIME;
	High_score_view_delayed_request	= NULL;

	HSUpdateScrollyCamera();
	MRUpdateFrames();
	MRUpdateViewportRenderMatrices();

#ifdef EXPERIMENTAL
	MRDisableDisplayClear();
#endif
}


/******************************************************************************
*%%%% HSDeinitialiseScrollyHighScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSDeinitialiseScrollyHighScore(MR_VOID)
*
*	FUNCTION	Deinitialisation for scrolly high score table.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSDeinitialiseScrollyHighScore(MR_VOID)
{
	MR_LONG	i;


	// Free allocated matrices
	MRFreeMem(High_score_matrices);

	// Destroy all number models
	for (i = 0; i < 10; i++)
		MRAnimEnvDestroyByDisplay(High_score_view_number_anim_env_ptr[i]);

	// Destroy all initial models
	for (i = 0; i < 30; i++)
		High_score_view_initials_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all log models
	for (i = 0; i < 10; i++)
		High_score_view_log_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all extra models
	for (i = 0; i < HIGH_SCORE_VIEW_NUM_EXTRAS; i++)
		High_score_view_extras_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy frog and shadow
	MRAnimEnvDestroyByDisplay(High_score_view_frog_anim_env_ptr);
	if (Frogs[0].fr_shadow)
		Frogs[0].fr_shadow->ef_kill_timer = 2;

#ifdef EXPERIMENTAL
	MREnableDisplayClear();
#endif
}


/******************************************************************************
*%%%% HSUpdateScrollyHighScores
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSUpdateScrollyHighScores(MR_VOID)
*
*	FUNCTION	Update scrolly high scores screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSUpdateScrollyHighScores(MR_VOID)
{
	EFFECT*		effect;
	SHADOW*		shadow;
	MR_LONG		i;
	MR_LONG		cos, sin;
	MR_MAT		transform;


	// Move camera
	if 	(
		(High_score_camera_operation_mode == HIGH_SCORE_CAMERA_OPERATION_MODE_SCROLLY) &&
		(!High_score_view_flyoff_counter)
		)
		{
		if (!High_score_view_flyon_counter)
			{
			Cameras[0].ca_current_source_ofs.vz = (Frogs[0].fr_lwtrans->t[2] + 1152) + OPTIONS_CAMERA_MAIN_SOURCE_OFS_Z;
			Cameras[0].ca_current_target_ofs.vz = (Frogs[0].fr_lwtrans->t[2] + 1152) + OPTIONS_CAMERA_MAIN_TARGET_OFS_Z;
			}
		}
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();

	// Update flying on/off
	HSUpdateFlying();

	// Set up scale matrix to enlarge all models
	MRScale_matrix.m[0][0] = 0x1300;
	MRScale_matrix.m[1][1] = 0x1300;
	MRScale_matrix.m[2][2] = 0x1300;

	// Apply wave deltas to lillies y
	HSProjectMatricesOntoWaterSurface(High_score_view_initials_matrix_ptr[0], 30, &MRScale_matrix);

	// Apply wave deltas to numbers
	HSProjectMatricesOntoWaterSurface(High_score_view_number_matrix_ptr[0], 10, &MRScale_matrix);

	// Apply wave deltas to extras
	HSProjectMatricesOntoWaterSurface(High_score_view_extras_matrix_ptr[0], HIGH_SCORE_VIEW_NUM_EXTRAS, &MRScale_matrix);

	// Apply wave deltas to logs
	//
	// Set up local X rotation
	cos = rcos(0x500);
	sin = rsin(0x500);
	MRRot_matrix_X.m[1][1] =  cos;
	MRRot_matrix_X.m[1][2] = -sin;
	MRRot_matrix_X.m[2][1] =  sin;
	MRRot_matrix_X.m[2][2] =  cos;

	// Logs aren't scaled up so much in local X
	MRScale_matrix.m[0][0] = 0x1200;
	MRMulMatrixABC(&MRScale_matrix, &MRRot_matrix_X, &transform);
	HSProjectMatricesOntoWaterSurface(High_score_view_log_matrix_ptr[0], 10, &transform);

	// Is camera scrolly (ie. are we in options menu, or viewing table after hiscore input) ?
	if (High_score_camera_operation_mode == HIGH_SCORE_CAMERA_OPERATION_MODE_SCROLLY)
		{
		HSUpdateFrog();
		UpdateEffects();

		// UpdateEffects has set y of shadow vertices to frog y... we want to project them onto the water
		if (effect = Frogs[0].fr_shadow)
			{
			shadow = effect->ef_extra;
			for (i = 0; i < 4; i++)						
				shadow->sh_corners[0][i].vy = HSGetWaterSurfaceInfoFromXZ(shadow->sh_corners[0][i].vx, shadow->sh_corners[0][i].vz, NULL, NULL);
			}
		}
	else
		{
		High_score_view_frog_anim_env_ptr->ae_flags &= ~MR_ANIM_ENV_DISPLAY;
		if (effect = Frogs[0].fr_shadow)
			effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
		}
}


/******************************************************************************
*%%%% HSUpdateScrollyCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSUpdateScrollyCamera(MR_VOID)
*
*	FUNCTION	Update the high score scrolly camera using the acceleration 
*				code written by Kev.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSUpdateScrollyCamera(MR_VOID)
{
	CAMERA*	camera;

	
	camera 					= &Cameras[0];
	camera->ca_mode 		= CAMERA_MODE_FIXED_SWEEP;
	camera->ca_move_timer 	= MAX(1, camera->ca_move_timer);
	UpdateCamera(camera);
}


/******************************************************************************
*%%%% HSGetWaterSurfaceInfoFromXZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	y =	HSGetWaterSurfaceInfoFromXZ(
*							MR_LONG	x,
*							MR_LONG	z,
*							MR_VEC*	x_slope,
*							MR_VEC*	z_slope)
*
*	FUNCTION	From world x,z coord, get water surface height y and slope of
*				surface in direction of world x and z axes
*
*	INPUTS		x		-	world x coord
*				z		-	world z coord
*				x_slope	-	ptr to MR_VEC to store x slope
*				z_slope	-	ptr to MR_VEC to store z slope
*
*	RESULT		y		-	height of surface
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	HSGetWaterSurfaceInfoFromXZ(MR_LONG	x,
									MR_LONG	z,
									MR_VEC*	x_slope,
									MR_VEC*	z_slope)
{
	MR_LONG	dx, dz;
	MR_LONG	t, tx, tz, y, tx2, tz2, y2;


	dx 	= x - High_score_view_water_points_ptr[0].vx;
	dz 	= High_score_view_water_points_ptr[0].vz - z;

	t	= Option_viewport_ptr->vp_frame_count;
	tx	= ((dx * HIGH_SCORE_VIEW_WAVE_PERIOD_X) / (HIGH_SCORE_VIEW_WATER_X_NUM * HIGH_SCORE_VIEW_WATER_X_LEN)) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_X);
	tz	= ((dz * HIGH_SCORE_VIEW_WAVE_PERIOD_Z) / (HIGH_SCORE_VIEW_WATER_Z_NUM * HIGH_SCORE_VIEW_WATER_Z_LEN)) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_Z);

	y	= ((rsin(tx) * HIGH_SCORE_VIEW_WAVE_AMP_X) + (rsin(tz) * HIGH_SCORE_VIEW_WAVE_AMP_Z)) >> 12;

	if (x_slope)
		{
		tx2 = (((dx + 0x100) * HIGH_SCORE_VIEW_WAVE_PERIOD_X) / (HIGH_SCORE_VIEW_WATER_X_NUM * HIGH_SCORE_VIEW_WATER_X_LEN)) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_X);
		y2	= ((rsin(tx2) * HIGH_SCORE_VIEW_WAVE_AMP_X) + (rsin(tz) * HIGH_SCORE_VIEW_WAVE_AMP_Z)) >> 12;
		x_slope->vx = 0x100;
		x_slope->vy = y2 - y;

		x_slope->vz = 0;
		MRNormaliseVEC(x_slope, x_slope);
		}
	if (z_slope)
		{
		tz2	= (((dz + 0x100) * HIGH_SCORE_VIEW_WAVE_PERIOD_Z) / (HIGH_SCORE_VIEW_WATER_Z_NUM * HIGH_SCORE_VIEW_WATER_Z_LEN)) + (t * HIGH_SCORE_VIEW_WAVE_FREQ_Z);
		y2	= ((rsin(tx) * HIGH_SCORE_VIEW_WAVE_AMP_X) + (rsin(tz2) * HIGH_SCORE_VIEW_WAVE_AMP_Z)) >> 12;
		z_slope->vz = 0x100;
		z_slope->vy = y2 - y;

		z_slope->vx = 0;
		MRNormaliseVEC(z_slope, z_slope);
		}
	return(y);
}


/******************************************************************************
*%%%% HSProjectMatricesOntoWaterSurface
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSProjectMatricesOntoWaterSurface(
*						MR_MAT*	matrix_ptr,
*						MR_LONG	num_matrices,
*						MR_MAT*	transform)
*
*	FUNCTION	Project an array of matrices onto the water surface
*
*	INPUTS		matrix_ptr		-	ptr to array of MR_MAT
*				num_matrcies	-	number in array
*				transform		-	possible extra transform
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	HSProjectMatricesOntoWaterSurface(	MR_MAT*	matrix_ptr,
											MR_LONG	num_matrices,
											MR_MAT*	transform)
{
	MR_VEC	vec_x, vec_y, vec_z;
	MR_LONG	h;


	while(num_matrices--)
		{
		h = HSGetWaterSurfaceInfoFromXZ(matrix_ptr->t[0], matrix_ptr->t[2], &vec_x, &vec_z);

		if (High_score_view_flyon_counter)
			{
			// Stuff flying off
			matrix_ptr->t[1] += OPTIONS_CAMERA_FLYON_SPEED;
			if (matrix_ptr->t[1] >= h)
				{
				// Hit water
				matrix_ptr->t[1] = h;
				}
			}
		if (High_score_view_flyoff_counter)
			{
			// Stuff flying off
			if (matrix_ptr->t[0] < 0)
				matrix_ptr->t[0] -= OPTIONS_CAMERA_FLYOFF_SPEED;
			else
				matrix_ptr->t[0] += OPTIONS_CAMERA_FLYOFF_SPEED;
			}			

		if (!High_score_view_flyon_counter)
			matrix_ptr->t[1] = h;

		MROuterProduct12(&vec_z, &vec_x, &vec_y);
		MRNormaliseVEC(&vec_y, &vec_y);
		MROuterProduct12(&vec_x, &vec_y, &vec_z);
		WriteAxesAsMatrix(matrix_ptr, &vec_x, &vec_y, &vec_z);
		if (transform)
			MRMulMatrixABB(transform, matrix_ptr);
		matrix_ptr++;
		}
}


/******************************************************************************
*%%%% HSUpdateFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSUpdateFrog(MR_VOID)
*
*	FUNCTION	Move the frog around the number pads
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	HSUpdateFrog(MR_VOID)
{
	FROG*		frog;
	MR_MAT		matrix;
	MR_LONG		i, dy;
	MR_OBJECT*	object_ptr;
	EFFECT*		effect;
	SHADOW*		shadow;


	frog = &Frogs[0];
	switch(frog->fr_mode)
		{
		//--------------------------------------------------------------------
		case FROG_MODE_STATIONARY:
			// Get y coord from current pad
			frog->fr_pos.vy	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1] << 16;

			// Count down before jumping
			if (!(--frog->fr_count))
				{
				if (frog->fr_grid_z == 9)
					frog->fr_direction = FROG_DIRECTION_S;
				else
				if (frog->fr_grid_z == 0)
					frog->fr_direction = FROG_DIRECTION_N;

				if (frog->fr_direction == FROG_DIRECTION_N)
					frog->fr_grid_z++;
				else
					frog->fr_grid_z--;

				frog->fr_mode			= FROG_MODE_JUMPING;
				frog->fr_count			= HIGH_SCORE_VIEW_FROG_JUMP_TIME;

				// Calculate target pos
				frog->fr_target_pos.vx 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[0];
				frog->fr_target_pos.vy 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1];
				frog->fr_target_pos.vz 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[2];

				frog->fr_y				= frog->fr_pos.vy;
				frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
				frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

				MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_HOP);
				// Play effect when jumping.
				MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
				}
			
			// Get rotation from current pad (scaled up)
			MR_COPY_MAT(frog->fr_lwtrans, High_score_view_number_matrix_ptr[frog->fr_grid_z]);
			MRScale_matrix.m[0][0] = 0x1400;
			MRScale_matrix.m[1][1] = 0x1400;
			MRScale_matrix.m[2][2] = 0x1400;
			MRMulMatrixABB(&MRScale_matrix, frog->fr_lwtrans);
						
			if (frog->fr_direction == FROG_DIRECTION_S)
				{
				MR_INIT_MAT(&matrix);
				matrix.m[0][0] = -0x1000;
				matrix.m[0][2] =  0;
				matrix.m[2][0] =  0;
				matrix.m[2][2] = -0x1000;
				MRMulMatrixABB(&matrix, frog->fr_lwtrans);
				}
			break;
		//--------------------------------------------------------------------
		case FROG_MODE_JUMPING:
			// Handle jump
			//
			// Move fr_y in a line from source to target: actual y is parabola offset from this
			frog->fr_target_pos.vy 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1];
			frog->fr_y 				+= ((frog->fr_target_pos.vy << 16) - frog->fr_y) / frog->fr_count;

			dy						= (-8 << 16)  * (MR_SQR(HIGH_SCORE_VIEW_FROG_JUMP_TIME >> 1) - MR_SQR(frog->fr_count - (HIGH_SCORE_VIEW_FROG_JUMP_TIME >> 1)));
			frog->fr_pos.vy 		= frog->fr_y + dy;

			frog->fr_pos.vx 		+= frog->fr_velocity.vx;
			frog->fr_pos.vz 		+= frog->fr_velocity.vz;

			if (!(--frog->fr_count))
				{
				// Jump complete
				frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
				frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
				frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

				frog->fr_mode	= FROG_MODE_STATIONARY;
				frog->fr_count	= HIGH_SCORE_VIEW_FROG_WAIT_TIME;
				MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_WAIT1);

				// Create splash sprite
				object_ptr = MRCreate3DSprite((MR_FRAME*)High_score_view_number_matrix_ptr[frog->fr_grid_z], MR_OBJ_STATIC, High_score_splash_animlist);
				MRAddObjectToViewport(object_ptr, Option_viewport_ptr, NULL);

				object_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
				object_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x8;
				object_ptr->ob_extra.ob_extra_sp_core->sc_scale		= 10 << 16;

				// Play effect when landing
				MRSNDPlaySound(SFX_GEN_FROG_SPLASH1, NULL, 0, 0);
				}
			else
				{
				}
			break;
		//--------------------------------------------------------------------
		}

	if (High_score_view_flyoff_counter)
		{
		frog->fr_pos.vx 		-= (OPTIONS_CAMERA_FLYOFF_SPEED << 16);
		frog->fr_target_pos.vx 	-= OPTIONS_CAMERA_FLYOFF_SPEED;
		}
	
	// Get frog position/rotation
	frog->fr_lwtrans->t[0] 	= frog->fr_pos.vx >> 16;
	frog->fr_lwtrans->t[1] 	= (frog->fr_pos.vy >> 16)-64;
	frog->fr_lwtrans->t[2] 	= frog->fr_pos.vz >> 16;

	// Force anim code to rebuild LW transforms
	High_score_view_frog_anim_env_ptr->ae_extra.ae_extra_env_single->ae_last_cel_number = -1;

	// Update shadow
	if (effect = frog->fr_shadow)
		{
		// Update sh_texture and sh_offsets
		if (High_score_view_flyon_counter)
			effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
		else
			{
			effect->ef_flags &= ~(EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
			shadow = effect->ef_extra;

			if (frog->fr_mode == FROG_MODE_JUMPING)
				{
				i = ((HIGH_SCORE_VIEW_FROG_JUMP_TIME - frog->fr_count) * 6) / HIGH_SCORE_VIEW_FROG_JUMP_TIME;
				i = MAX(0, MIN(5, i));
				}
			else
				{
				i = 0;
				}
			shadow->sh_offsets 	= Frog_jump_shadow_offsets[i];
			shadow->sh_texture	= Frog_jump_shadow_textures[i];
			}
		}
}


/******************************************************************************
*%%%% HSUpdateFlying
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSUpdateFlying(MR_VOID)
*
*	FUNCTION	Update counters for stuff flying on/off screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	HSUpdateFlying(MR_VOID)
{
	if (High_score_view_flyon_counter)
		High_score_view_flyon_counter--;

	if (High_score_view_flyoff_counter)
		{
		if (!(--High_score_view_flyoff_counter))
			Option_page_request = High_score_view_delayed_request;
		}
}

/******************************************************************************
*%%%% HSViewStoreStackStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewStoreStackStatus(MR_VOID)
*
*	FUNCTION	Store the current status flags for the level stack.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSViewStoreStackStatus(MR_VOID)
{

	// Locals
	MR_ULONG		i;
	SEL_LEVEL_INFO*	level_ptr;

	// Store status of all arcade levels
	level_ptr	= Sel_arcade_levels;
	i = 0;
	while (level_ptr->li_library_id != -1)
		{
		Stack_status_flags_store[i] = level_ptr->li_flags;
		level_ptr++;
		i++;
		}

}

/******************************************************************************
*%%%% HSViewRestoreStackStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSViewRestoreStackStatus(MR_VOID)
*
*	FUNCTION	Restore the status flags for the level stack.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HSViewRestoreStackStatus(MR_VOID)
{

	// Locals
	MR_ULONG		i;
	SEL_LEVEL_INFO*	level_ptr;

	// Store status of all arcade levels
	level_ptr	= Sel_arcade_levels;
	i = 0;
	while (level_ptr->li_library_id != -1)
		{
		level_ptr->li_flags = Stack_status_flags_store[i];
		level_ptr++;
		i++;
		}

}

#ifdef WIN95
#pragma warning (default : 4761)
#endif

