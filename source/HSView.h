/******************************************************************************
*%%%% hsview.h
*------------------------------------------------------------------------------
*
*	High score table viewer.  Based on Dean's level select.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.06.97	William Bell	Created
*
*%%%**************************************************************************/

#ifndef	__HSVIEW_H
#define	__HSVIEW_H

#include "mr_all.h"
#include "options.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum	{
		HIGH_SCORE_VIEW_INIT_MODE,
		HIGH_SCORE_VIEW_MOVE_FROG_MODE,
		HIGH_SCORE_VIEW_END_MODE,
		};

enum	{
		HIGH_SCORE_OPERATION_MODE_SCROLLY_HIGH_SCORES,
		HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT,
		};

enum	{
		HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC,
		HIGH_SCORE_CAMERA_OPERATION_MODE_SCROLLY,
		};

#define		HIGH_SCORE_AFTER_INPUT_DURATION			(4 * 30)	// duration of display after hiscore input
#define		HIGH_SCORE_VIEW_LEVEL_DURATION			(3 * 30)	// duration of automatic view of level info

#define		HIGH_SCORE_VIEW_PERSPECTIVE				0x100
#define		HIGH_SCORE_VIEW_WAVE_AMP_X				0x40	// amplitude of x sin wave
#define		HIGH_SCORE_VIEW_WAVE_AMP_Z				0x50	// amplitude of z sin wave
#define		HIGH_SCORE_VIEW_WAVE_FREQ_X				0x60	// frequency of x sin wave
#define		HIGH_SCORE_VIEW_WAVE_FREQ_Z				0x80	// frequency of z sin wave
#define		HIGH_SCORE_VIEW_WAVE_PERIOD_X			0x2000	// total period across surface x
#define		HIGH_SCORE_VIEW_WAVE_PERIOD_Z			0x2000	// total period across surface z

// Water surface
#define		HIGH_SCORE_VIEW_WATER_X_NUM				14
#define		HIGH_SCORE_VIEW_WATER_Z_NUM				16
#define		HIGH_SCORE_VIEW_WATER_X_LEN				0x240
#define		HIGH_SCORE_VIEW_WATER_Z_LEN				0x240

// Riverbed
#define		HIGH_SCORE_VIEW_RIVERBED_X_NUM			14
#define		HIGH_SCORE_VIEW_RIVERBED_Z_NUM			16
#define		HIGH_SCORE_VIEW_RIVERBED_X_LEN			0x240
#define		HIGH_SCORE_VIEW_RIVERBED_Z_LEN			0x240

// Frog jumping
#define		HIGH_SCORE_VIEW_FROG_WAIT_TIME			18
#define		HIGH_SCORE_VIEW_FROG_JUMP_TIME			12

// Extras
#define		HIGH_SCORE_VIEW_NUM_EXTRAS				5

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __high_score_entry		HIGH_SCORE_ENTRY;

struct __high_score_entry
	{
	MR_UBYTE			he_initials[4];				// Player's initials
	MR_ULONG			he_score;					// Score
	MR_USHORT			he_time_to_checkpoint[5];	// Time taken to checkpoint

	};	// HIGH_SCORE_ENTRY

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_USHORT				Frog_time_data[5];
extern	HIGH_SCORE_ENTRY		Frog_score_data[60][4];
extern	HIGH_SCORE_ENTRY		Game_high_score[10];
extern	HIGH_SCORE_ENTRY		Level_high_scores[60][3];
extern	MR_BOOL					HSView_automatic_flag;
extern	MR_ULONG				High_score_operation_mode;

extern	MR_ULONG				High_score_camera_operation_mode;
extern	MR_ULONG				High_score_view_mode;

extern	MR_LONG					High_score_view_flyoff_counter;
extern	MR_LONG					High_score_view_flyon_counter;
extern	MR_LONG					High_score_view_delayed_request;

extern	MR_MAT*					High_score_matrices;
extern	MR_MOF*					High_score_view_number_model_ptr[];
extern	MR_MAT*					High_score_view_number_matrix_ptr[];
extern	MR_OBJECT*				High_score_view_number_object_ptr[];
extern	MR_MAT*					High_score_view_initials_matrix_ptr[];
extern	MR_OBJECT*				High_score_view_initials_object_ptr[];
extern	MR_MAT*					High_score_view_log_matrix_ptr[];
extern	MR_OBJECT*				High_score_view_log_object_ptr[];
extern	MR_ANIM_HEADER*			High_score_view_frog_anim_model_ptr;
extern	MR_MAT*					High_score_view_frog_anim_matrix_ptr;
extern	MR_ANIM_ENV*			High_score_view_frog_anim_env_ptr;
extern	MR_MAT					High_score_view_frog_sack_scale_matrix;

extern	MR_ULONG				High_score_splash_animlist[];
extern	MR_USHORT				High_score_log_animated_poly_indices[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		HSViewStartup(MR_VOID);
extern	MR_VOID		HSViewShutdown(MR_VOID);
extern	MR_VOID		HSViewUpdate(MR_VOID);

extern	MR_VOID		HSViewUpdate_MODE_SELECTING_automatic(MR_VOID);
extern	MR_VOID		HSViewUpdate_MODE_SHOW_LEVEL_INFO_automatic(MR_VOID);

extern	MR_VOID		HSViewUpdate_MODE_SELECTING_manual(MR_VOID);
extern	MR_VOID		HSViewUpdate_MODE_SHOW_LEVEL_INFO_manual(MR_VOID);

extern	MR_VOID 	HighScoreBuildArcadeTimeTable(MR_ULONG, MR_ULONG);
extern	MR_VOID 	HighScoreBuildRaceScoreTable(MR_ULONG, MR_ULONG);

extern	MR_VOID		HSUpdateLogs(MR_VOID);
extern	MR_VOID		HSInitialiseWater(MR_TEXTURE*, MR_TEXTURE*);
extern	MR_VOID		HSUpdateWater(MR_VOID);
extern	MR_VOID		HSDeinitialiseWater(MR_VOID);

extern	MR_VOID		HSInitialiseScrollyHighScore(MR_VOID);
extern	MR_VOID		HSDeinitialiseScrollyHighScore(MR_VOID);

//extern	MR_VOID		HSInitialiseScrollyScrollyCamera(MR_VOID);
//extern	MR_VOID		HSInitialiseScrollyStaticCamera(MR_VOID);

extern	MR_VOID		HSUpdateScrollyHighScores(MR_VOID);
extern	MR_VOID		HSUpdateScrollyCamera(MR_VOID);
extern	MR_LONG		HSGetWaterSurfaceInfoFromXZ(MR_LONG, MR_LONG, MR_VEC*, MR_VEC*);
extern	MR_VOID		HSProjectMatricesOntoWaterSurface(MR_MAT*, MR_LONG, MR_MAT*);
extern	MR_VOID		HSUpdateFrog(MR_VOID);
extern	MR_VOID		HSUpdateFlying(MR_VOID);

extern	MR_VOID		HSViewStoreStackStatus(MR_VOID);
extern	MR_VOID		HSViewRestoreStackStatus(MR_VOID);

#endif	//__HSVIEW_H
