/******************************************************************************
*%%%% hsinput.c
*------------------------------------------------------------------------------
*
*	High score input and maintainence.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

#include "hsinput.h"
#include "project.h"
#include "sprdata.h"
#include "options.h"
#include "tempopt.h"
#include "gamefont.h"
#include "gamesys.h"
#include "hsview.h"
#include "frog.h"
#include "select.h"
#include "sound.h"
#include "model.h"
#include "camera.h"
#include "particle.h"
#include "pause.h"
#include "gnm_frog.h"
	
#ifdef WIN95
#pragma warning (disable : 4761)
#pragma warning (disable : 4018)
#endif

MR_BOOL				High_high_score;			// New global high score ( for this player )
MR_BOOL				High_level_score;			// New high score for this level ( race or arcade level ) ( for this player )

MR_UBYTE			New_high_score;				// New high score has been achieved ( for any player )
MR_UBYTE			New_high_scores[60];		// Levels that a new high score has been achieved on ( for any player )

// Extra models
MR_MAT*				High_score_input_extras_matrix_ptr[HIGH_SCORE_INPUT_NUM_EXTRAS];
MR_OBJECT*			High_score_input_extras_object_ptr[HIGH_SCORE_INPUT_NUM_EXTRAS];
MR_ULONG			High_score_input_extras_resource_id[] =
	{
	RES_OPT_STAT_BULLRUSH_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_BULLRUSH_XMR,
	RES_OPT_STAT_BULLRUSH_XMR,
	};

MR_LONG				High_score_input_extras_coords[] =
	{
	-0x400, -0x040,
	-0x280, -0x200,
	 0x480, -0x240,
	 0x400, -0x080,
	 0x240, -0x300,
	-0x300, -0x380,
	};

MR_MAT*				High_score_input_letters_matrix_ptr[30];
MR_OBJECT*			High_score_input_letters_object_ptr[30];
MR_MAT*				High_score_input_initials_matrix_ptr[4 * 3];
MR_OBJECT*			High_score_input_initials_object_ptr[4 * 3];

// High score input frogs
MR_MAT*				High_score_input_frog_anim_matrix_ptr[4];
MR_ANIM_ENV*		High_score_input_frog_anim_env_ptr[4];

MR_ULONG			High_score_input_letters_resource_id[] =
	{
	RES_HI_A_XMR,
	RES_HI_B_XMR,
	RES_HI_C_XMR,
	RES_HI_D_XMR,
	RES_HI_E_XMR,
	RES_HI_F_XMR,
	RES_HI_G_XMR,
	RES_HI_H_XMR,
	RES_HI_I_XMR,
	RES_HI_J_XMR,
	RES_HI_K_XMR,
	RES_HI_L_XMR,
	RES_HI_M_XMR,
	RES_HI_N_XMR,
	RES_HI_O_XMR,
	RES_HI_P_XMR,
	RES_HI_Q_XMR,
	RES_HI_R_XMR,
	RES_HI_S_XMR,
	RES_HI_T_XMR,
	RES_HI_U_XMR,
	RES_HI_V_XMR,
	RES_HI_W_XMR,
	RES_HI_X_XMR,
	RES_HI_Y_XMR,
	RES_HI_Z_XMR,
	RES_HI_DOT_XMR,
	RES_OPT_LILLYPAD_BLANK_XMR,
	RES_HI_BACK_XMR,
	RES_HI_END_XMR,
	};

MR_LONG				High_score_input_initials[4][HIGH_SCORE_NUM_INITIALS];	// initials stored
MR_LONG				High_score_input_initial_pos[4];						// current initial waiting to be entered
HSI_LILY_INFO		High_score_input_lily_infos[4];							// for turning lilies

MR_LONG				High_score_input_frog_num;								// frog id, used by some functions

MR_BOOL				Any_high_score;

/******************************************************************************
*%%%% HighScoreInitialiseData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreInitialiseData(MR_VOID)
*
*	FUNCTION	Initialisation code for High Score data.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreInitialiseData(MR_VOID)
{

	// Locals
	MR_ULONG		loop_counter_1;
	MR_ULONG		loop_counter_2;

	// Loop once for each player
	for(loop_counter_2=0;loop_counter_2<4;loop_counter_2++)
		{
		// Loop once for each level
		for(loop_counter_1=0;loop_counter_1<60;loop_counter_1++)
			{
			// Zero data
			Frog_score_data[loop_counter_1][loop_counter_2].he_initials[0] = 'A';
			Frog_score_data[loop_counter_1][loop_counter_2].he_initials[1] = 'A';
			Frog_score_data[loop_counter_1][loop_counter_2].he_initials[2] = 'A';

			Frog_score_data[loop_counter_1][loop_counter_2].he_score = 0;

			Frog_score_data[loop_counter_1][loop_counter_2].he_time_to_checkpoint[0] = 0;
			Frog_score_data[loop_counter_1][loop_counter_2].he_time_to_checkpoint[1] = 0;
			Frog_score_data[loop_counter_1][loop_counter_2].he_time_to_checkpoint[2] = 0;
			Frog_score_data[loop_counter_1][loop_counter_2].he_time_to_checkpoint[3] = 0;
			Frog_score_data[loop_counter_1][loop_counter_2].he_time_to_checkpoint[4] = 0;
			}
		}
}


/******************************************************************************
*%%%% HighScoreInputStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreInputStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for High Score Input screen.  Sets up text
*				for displaying.  Initialise players initials.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	23.06.97	Martin Kift		Changed port data structure
*
*%%%**************************************************************************/

MR_VOID	HighScoreInputStartup(MR_VOID)
{
	MR_ULONG	i, j, k;
	FROG*		frog;
	MR_LONG*	long_ptr;


	// Consider whether any frog has anything to enter
	Any_high_score = FALSE;

	// Bail if we quit the game
	if (Game_paused_selection == HIDDEN_MENU_QUIT_GAME)
		{
		Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
		return;
		}

	for (i = 0; i < Game_total_players; i++)
		{
		frog = &Frogs[i];
		if (HighScoreCheckScore(frog->fr_score) == TRUE)
			{
			frog->fr_flags |= FROG_ENTER_SCORE;
			Any_high_score = TRUE;
			}
		if (Sel_mode == SEL_MODE_ARCADE)
			{
			if (HighScoreCheckAllArcadeTimes(i) == TRUE)
				{
			 	frog->fr_flags |= FROG_ENTER_ARCADE_TIME;
				Any_high_score = TRUE;
				}
			}
		else
			{
			if (HighScoreCheckAllRaceScores(i) == TRUE)
				{		
				frog->fr_flags |= FROG_ENTER_RACE_SCORE;
				Any_high_score = TRUE;
				}
			}
		}

	// If no high score to be entered, bail to main options
	if (Any_high_score == FALSE)
		{
		Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
		return;
		}

	// Load options resources
	LoadOptionsResources();

	// Load GENM wad for frogs
	LoadGenericWad(1);

	// Initialise high score input display
	//
	// Allocate memory for all matrices
	// (30 letters, 4 frogs, 12 initials, extras)
	High_score_matrices = MRAllocMem(sizeof(MR_MAT) * (30 + 4 + 12 + HIGH_SCORE_INPUT_NUM_EXTRAS), "HS matrices");

	for (k = 0; k < 30; k++)	
		High_score_input_letters_matrix_ptr[k] 		= High_score_matrices + k;

	for (k = 0; k < 4; k++)	
		High_score_input_frog_anim_matrix_ptr[k]	= High_score_matrices + 30 + k;

	for (k = 0; k < 12; k++)	
		High_score_input_initials_matrix_ptr[k] 	= High_score_matrices + 30 + 4 + k;

	for (k = 0; k < HIGH_SCORE_INPUT_NUM_EXTRAS; k++)	
		High_score_input_extras_matrix_ptr[k]		= High_score_matrices + 30 + 4 + 12 + k;

	// Create extras
	for (i = 0; i < HIGH_SCORE_INPUT_NUM_EXTRAS; i++)
		{
		MR_INIT_MAT(High_score_input_extras_matrix_ptr[i]);
		High_score_input_extras_matrix_ptr[i]->t[0]	= High_score_input_extras_coords[(i << 1) + 0];
		High_score_input_extras_matrix_ptr[i]->t[2]	= High_score_input_extras_coords[(i << 1) + 1];
		High_score_input_extras_object_ptr[i] 		= MRCreateMesh(MR_GET_RESOURCE_ADDR(High_score_input_extras_resource_id[i]), (MR_FRAME*)High_score_input_extras_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_input_extras_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Create letter grid
	for (i = 0; i < 30; i++)
		{
		// Create stuff for each model
		MR_INIT_MAT(High_score_input_letters_matrix_ptr[i]);
		High_score_input_letters_matrix_ptr[i]->t[0] 	= ((i % 10) * 0x100) - 0x480;
		High_score_input_letters_matrix_ptr[i]->t[2] 	= (3 - (i / 10)) * 0x100;
		High_score_input_letters_object_ptr[i]			= MRCreateMesh(MR_GET_RESOURCE_ADDR(High_score_input_letters_resource_id[i]), (MR_FRAME*)High_score_input_letters_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_input_letters_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Create Frogs ready to jump up numbers
	for (i = 0; i < Game_total_players; i++)
		{
		High_score_input_frog_num = i;

		MR_INIT_MAT(High_score_input_frog_anim_matrix_ptr[i]);
	
		// Create frog and add to viewport
		High_score_input_frog_anim_env_ptr[i] = MRAnimEnvFlipbookCreateWhole(Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0 + i], MR_OBJ_STATIC, (MR_FRAME*)High_score_input_frog_anim_matrix_ptr[i]);
	
		// Set a default animation action of zero, default behaviour so to speak
//		MRAnimEnvFlipbookSetAction(High_score_input_frog_anim_env_ptr[i], 0);
//		MRAnimEnvFlipbookSetCel(High_score_input_frog_anim_env_ptr[i], 5);
		MRAnimEnvFlipbookSetAction(High_score_input_frog_anim_env_ptr[i], GENM_FROG_SIT);
		MRAnimEnvFlipbookSetCel(High_score_input_frog_anim_env_ptr[i], 0);

		High_score_input_frog_anim_env_ptr[i]->ae_update_period = 2;
		High_score_input_frog_anim_env_ptr[i]->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
	
		// Use Frogs[0] to store info about frog jumping along numbers
		frog		   			= &Frogs[i];
		frog->fr_lwtrans 		= High_score_input_frog_anim_matrix_ptr[i];
		frog->fr_frog_id		= i;
		frog->fr_api_item		= High_score_input_frog_anim_env_ptr[i];
		frog->fr_api_insts[0] 	= MRAnimAddEnvToViewport(High_score_input_frog_anim_env_ptr[i], Option_viewport_ptr, 0);

		frog->fr_grid_x			= 4 + (i & 1);
		frog->fr_grid_z			= 1 + (i >> 1);
		frog->fr_direction 		= (i & 2) + 1;

		frog->fr_count			= 0;
		j						= (frog->fr_grid_z * 10) + frog->fr_grid_x;
		frog->fr_pos.vx			= High_score_input_letters_matrix_ptr[j]->t[0] << 16;
		frog->fr_pos.vy			= High_score_input_letters_matrix_ptr[j]->t[1] << 16;
		frog->fr_pos.vz			= High_score_input_letters_matrix_ptr[j]->t[2] << 16;
	
		// Create shadow for frog
		Game_total_viewports		= 1;
		Game_viewports[0]			= Option_viewport_ptr;
		frog->fr_shadow 			= CreateShadow(Frog_jump_shadow_textures[0], frog->fr_lwtrans, Frog_jump_shadow_offsets[0]);
		frog->fr_shadow->ef_flags	|= EFFECT_STATIC;
		frog->fr_shadow->ef_flags	&= ~EFFECT_KILL_WHEN_FINISHED;

		// Frog popping
		frog->fr_poly_piece_pop							= MRAllocMem(sizeof(POLY_PIECE_POP) + (sizeof(POLY_PIECE_DYNAMIC) * Frog_model_pieces_polys), "FROG POLY PIECE POP");
		frog->fr_poly_piece_pop->pp_mof					= Frog_model_pieces_mof;
		frog->fr_poly_piece_pop->pp_numpolys 			= Frog_model_pieces_polys;
		frog->fr_poly_piece_pop->pp_timer				= 0;
		frog->fr_poly_piece_pop->pp_lwtrans				= frog->fr_lwtrans;
		frog->fr_poly_piece_pop->pp_poly_pieces			= Frog_model_pieces;
		frog->fr_poly_piece_pop->pp_poly_piece_dynamics	= (POLY_PIECE_DYNAMIC*)(frog->fr_poly_piece_pop	+ 1);

//		if (HighScoreCheckScore(frog->fr_score) == TRUE)
//			{
//			frog->fr_flags |= FROG_ENTER_SCORE;
//			any_high_score = TRUE;
//			}
//		if (Sel_mode == SEL_MODE_ARCADE)
//			{
//			if (HighScoreCheckAllArcadeTimes(i) == TRUE)
//				{
//			 	frog->fr_flags |= FROG_ENTER_ARCADE_TIME;
//				any_high_score = TRUE;
//				}
//			}
//		else
//			{
//			if (HighScoreCheckAllRaceScores(i) == TRUE)
//				{		
//				frog->fr_flags |= FROG_ENTER_RACE_SCORE;
//				any_high_score = TRUE;
//				}
//			}

		if (frog->fr_flags & (FROG_ENTER_SCORE | FROG_ENTER_ARCADE_TIME | FROG_ENTER_RACE_SCORE))
			// Allow frog to enter initials
			frog->fr_mode = FROG_MODE_STATIONARY;
		else
			// Forbid frog to enter initials
			frog->fr_mode = FROG_MODE_STUNNED;
		}
	
	// Create lillies for initials (3 for each frog)
	for (j = 0; j < Game_total_players; j++)
		{
		for (i = 0; i < 3; i++)
			{
			k = (j * 3) + i;
			MR_INIT_MAT(High_score_input_initials_matrix_ptr[k]);
			High_score_input_initials_matrix_ptr[k]->t[0] = (i * 0x100) - 0x100;
			High_score_input_initials_matrix_ptr[k]->t[2] = (j * -0x100) - 0x80;
	
			// Create stuff for each model
			High_score_input_initials_object_ptr[k] = MRCreateMesh(MR_GET_RESOURCE_ADDR(RES_OPT_LILLYPAD_BLANK_XMR), (MR_FRAME*)High_score_input_initials_matrix_ptr[k], MR_OBJ_STATIC, NULL);
			MRAddObjectToViewport(High_score_input_initials_object_ptr[k], Option_viewport_ptr, 0);
			}
		// Reset lily infos
		High_score_input_lily_infos[j].hs_object	= NULL;
		High_score_input_lily_infos[j].hs_angle		= 0;
		High_score_input_lily_infos[j].hs_new_mof	= NULL;
		}

	// Set up camera
	HSInputInitialiseCamera();

	// Initialise high score values, flags, etc.
	//
	// Clear table (flag no levels as having a new high score)
#ifndef DEBUG
	for(i = 0; i < 60; i++)
		New_high_scores[i] = 0;
#endif

	// Clear flag (flag as no player having a new high score)
	New_high_score = 0;

	// Initialise position in player name
	High_score_input_initial_pos[0] = 0;
	High_score_input_initial_pos[1] = 0;
	High_score_input_initial_pos[2] = 0;
	High_score_input_initial_pos[3] = 0;

	// Initialise initials to spaces
	long_ptr 	= &High_score_input_initials[0][0];
	i			= 4 * HIGH_SCORE_NUM_INITIALS;
	while(i--)
		*long_ptr++ = ' ';

	// If no high score to be entered, bail to main options
//	if (any_high_score == FALSE)
//		{
//		Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
//		return;
//		}
}


/******************************************************************************
*%%%% HighScoreInputUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreInputUpdate(MR_VOID)
*
*	FUNCTION	Update code for High Score Input screen.  Automatically skips if
*				the player does not have a new high score.  Pressing left or right
*				cycles through the selections available.  Then fire will select
*				the selection and place it in to the current initial.  Once all
*				initials are full, END will be automatically selected.  As soon
*				as END is selected this input will go on the next player.  When
*				all player's have finished this will exit.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	23.06.97	Martin Kift		Changed port data structure
*
*%%%**************************************************************************/

MR_VOID	HighScoreInputUpdate(MR_VOID)
{
	MR_LONG			i, cos, sin;
	EFFECT*			effect;
	SHADOW*			shadow;
	HSI_LILY_INFO*	lily_info;
	MR_MAT**		matrix_pptr;

	// Did anybody get a high score ?
	if (Any_high_score == FALSE)
		// No ... exit now
		return;

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();

	// Set up scale matrix to enlarge all models
	MRScale_matrix.m[0][0] = 0x1300;
	MRScale_matrix.m[1][1] = 0x1300;
	MRScale_matrix.m[2][2] = 0x1300;

	// Apply wave deltas to letters
	HSProjectMatricesOntoWaterSurface(High_score_input_letters_matrix_ptr[0], 30, &MRScale_matrix);

	// Apply wave deltas to initials
	matrix_pptr = High_score_input_initials_matrix_ptr;
	i			= Game_total_players * 3;
	while(i--)
		{
		MR_COPY_MAT(*matrix_pptr, &MRScale_matrix);
		(*matrix_pptr)->t[1] = HSGetWaterSurfaceInfoFromXZ((*matrix_pptr)->t[0], (*matrix_pptr)->t[2], NULL, NULL);
		matrix_pptr++;
		}
																														
	for (i = 0; i < Game_total_players; i++)
		{
		lily_info = &High_score_input_lily_infos[i];
		if (lily_info->hs_new_mof)
			{
			// Rotate initials matrix about local Z
			cos = rcos(lily_info->hs_angle);
			sin = rsin(lily_info->hs_angle);
			MRRot_matrix_Z.m[0][0] =  cos;
			MRRot_matrix_Z.m[0][1] =  sin;
			MRRot_matrix_Z.m[1][0] = -sin;
			MRRot_matrix_Z.m[1][1] =  cos;
			MRMulMatrixABB(&MRRot_matrix_Z, (MR_MAT*)lily_info->hs_object->ob_frame);
			}
		}

	// Apply wave deltas to extras
	HSProjectMatricesOntoWaterSurface(High_score_input_extras_matrix_ptr[0], HIGH_SCORE_INPUT_NUM_EXTRAS, &MRScale_matrix);

	// Move frog
	for (i = 0; i < Game_total_players; i++)
		HSInputUpdateFrog(&Frogs[i]);

	UpdateEffects();

	for (i = 0; i < Game_total_players; i++)
		{
		// UpdateEffects has set y of shadow vertices to frog y... we want to project them onto the water
		if (effect = Frogs[i].fr_shadow)
			{
			shadow = effect->ef_extra;
			for (i = 0; i < 4; i++)						
				shadow->sh_corners[0][i].vy = HSGetWaterSurfaceInfoFromXZ(shadow->sh_corners[0][i].vx, shadow->sh_corners[0][i].vz, NULL, NULL);
			}
		}

	// Check if all frogs have entered initials
	for (i = 0; i < Game_total_players; i++)
		{
		if	(
			(Frogs[i].fr_mode != FROG_MODE_STUNNED) ||
			(Frogs[i].fr_poly_piece_pop->pp_timer > 0)
			)
			// This frog hasn't quite finished
			return;
		}

	// All frogs have entered initials
	//
	// Store names/scores in tables
	for (i = 0; i < Game_total_players; i++)
		{
		High_score_input_frog_num = i;

		if (Frogs[i].fr_flags & FROG_ENTER_SCORE)
			HighScoreEnterScore(Frogs[i].fr_score);

		if (Frogs[i].fr_flags & FROG_ENTER_ARCADE_TIME)
			HighScoreAddAllArcadeTimes(i);

		if (Frogs[i].fr_flags & FROG_ENTER_RACE_SCORE)
			HighScoreAddAllRaceScores(i);
		}

	// Go on to high score view
	Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;

	// Operate in automatic mode
	HSView_automatic_flag 				= TRUE;
	High_score_operation_mode 			= HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT;
	High_score_camera_operation_mode 	= HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC;
	From_options 						= FALSE;
}


/******************************************************************************
*%%%% HighScoreInputShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreInputShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for High Score Input screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HighScoreInputShutdown(MR_VOID)
{
	MR_ULONG	i;

	// Did any body get a high score ?
	if (Any_high_score == FALSE)
		// No ... exit now
		return;

	// Free allocated matrices
	MRFreeMem(High_score_matrices);

	// Destroy all letter models
	for (i = 0; i < 30; i++)
		High_score_input_letters_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all initials models
	for (i = 0; i < Game_total_players * 3; i++)
		High_score_input_initials_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all extra models
	for (i = 0; i < HIGH_SCORE_INPUT_NUM_EXTRAS; i++)
		High_score_input_extras_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy frogs and shadows and poly pops
	for (i = 0; i < Game_total_players; i++)
		{
		MRAnimEnvDestroyByDisplay(High_score_input_frog_anim_env_ptr[i]);
		if (Frogs[i].fr_shadow)
			Frogs[i].fr_shadow->ef_kill_timer = 2;

		if (Frogs[i].fr_poly_piece_pop)
			{
			MRFreeMem(Frogs[i].fr_poly_piece_pop);
			Frogs[i].fr_poly_piece_pop = NULL;
			}
		}
}


/******************************************************************************
*%%%% HighScoreCheckScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	HighScoreCheckScore(MR_ULONG score)
*
*	FUNCTION	This function checks the score against the entries in the game high
*				score table.
*
*	INPUTS		score						- Score to enter in to table
*
*	RESULT		MR_BOOL						- State of score in table, TRUE - score fits
*											  in table, FALSE - score too low!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL HighScoreCheckScore(MR_ULONG score)
{
	MR_ULONG	loop_counter;


	// Loop once for each entry in high score table
	for(loop_counter=0;loop_counter<10;loop_counter++)
		{
		// Is score greater than current entry ?
		if ( Game_high_score[loop_counter].he_score < score )
			{
			// Yes ... return high score fits in table
			return TRUE;
			}
		}

	// No, score too low
	return FALSE;

}

/******************************************************************************
*%%%% HighScoreCheckArcadeTime
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	HighScoreCheckArcadeTime(MR_ULONG high_score_table_number,
*											MR_ULONG time)
*
*	FUNCTION	This function checks the time against the entries in the level high
*				score table.
*
*	INPUTS		high_score_table_number		- Number of the table to enter the score
*												in.
*
*				time						- Time to enter in to table
*
*	RESULT		MR_BOOL						- State of time in table, TRUE - time fits
*											  in table, FALSE - time too low!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL HighScoreCheckArcadeTime(MR_ULONG high_score_table_number,MR_ULONG time)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_ULONG		total_time;

	// $da: Changed, because we're making high_score_table_number the same as Game_map,
	//		so be careful to ensure that the order of Arcade_high_scores array is _EXACTLY_
	//		the same as the main library layout. No gaps, missus. Or it'll barf. 

	// Loop once for each entry in high score table
	for(loop_counter=0;loop_counter<3;loop_counter++)
		{

		// Calculate level time ( sum of time for each checkpoint )
//		total_time = Level_high_scores[high_score_table_number][loop_counter].he_time_to_checkpoint[0] +
//						Level_high_scores[high_score_table_number][loop_counter].he_time_to_checkpoint[1] +
//						Level_high_scores[high_score_table_number][loop_counter].he_time_to_checkpoint[2] +
//						Level_high_scores[high_score_table_number][loop_counter].he_time_to_checkpoint[3] +
//						Level_high_scores[high_score_table_number][loop_counter].he_time_to_checkpoint[4];
		total_time = Level_high_scores[high_score_table_number][loop_counter].he_score;

		// Is time greater than current entry ?
		if ( total_time < time )
			{
			// Yes ... return time fits in table
			return TRUE;
			}

		}

	// No, time too low
	return FALSE;

}

/******************************************************************************
*%%%% HighScoreCheckRaceScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	HighScoreCheckRaceScore(MR_ULONG high_score_table_number,
*											MR_ULONG score)
*
*	FUNCTION	This function checks the score against the entries in the level high
*				score table.
*
*	INPUTS		high_score_table_number		- Number of the table to enter the score
*												in.
*
*				score						- Score to enter in to table
*
*	RESULT		MR_BOOL						- State of score in table, TRUE - score fits
*											  in table, FALSE - score too low!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL HighScoreCheckRaceScore(MR_ULONG high_score_table_number,MR_ULONG score)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_ULONG		high_score;


	// $da: Changed, because we're making high_score_table_number the same as Game_map,
	//		so be careful to ensure that the order of Race_high_scores array is _EXACTLY_
	//		the same as the main library layout. No gaps, missus. Or it'll barf.

	// Loop once for each entry in high score table
	for(loop_counter=0;loop_counter<3;loop_counter++)
		{

		// Get score
		high_score = Level_high_scores[high_score_table_number][loop_counter].he_score;

		// Is score greater than current entry ?
		if ( high_score < score )
			{
			// Yes ... return score fits in table
			return TRUE;
			}

		}

	// No, score too low
	return FALSE;

}

/******************************************************************************
*%%%% HighScoreEnterScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreEnterScore(MR_ULONG score)
*
*	FUNCTION	Enter the initials with the score in to the game high score table.
*
*	INPUTS		score			- score to enter into table
*
*	NOTES		This routine will just return if the name doesn't fit into the high
*				score table.  Also this function should only called from within the
*				HSInput system, and not externally.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreEnterScore(MR_ULONG score)
{

	// Locals
	MR_LONG			loop_counter_1;
	MR_LONG			loop_counter_2;

	// Loop once for each entry in table
	for(loop_counter_1=0;loop_counter_1<10;loop_counter_1++)
		{
		// Is this score less than entrants score ?
		if ( Game_high_score[loop_counter_1].he_score < score )
			// Yes ... store position
			break;
		}

	// Are we in table ?
	if ( loop_counter_1 == 10 )
		{
		// No ... stop now
		return;
		}

	// Enter at bottom of table ?
	if ( loop_counter_1 != 9 )
		{
		// No ... loop once for each remaining entry in table
		loop_counter_2 = 9;
		do
			{

			// Dec count
			loop_counter_2--;

			// Move entry down
			Game_high_score[loop_counter_2+1].he_initials[0] = Game_high_score[loop_counter_2].he_initials[0];
			Game_high_score[loop_counter_2+1].he_initials[1] = Game_high_score[loop_counter_2].he_initials[1];
			Game_high_score[loop_counter_2+1].he_initials[2] = Game_high_score[loop_counter_2].he_initials[2];
			Game_high_score[loop_counter_2+1].he_score = Game_high_score[loop_counter_2].he_score;

			} while ( loop_counter_2!=loop_counter_1 );
		}

	// Enter new entry at position
	Game_high_score[loop_counter_1].he_initials[0] = High_score_input_initials[High_score_input_frog_num][0];
	Game_high_score[loop_counter_1].he_initials[1] = High_score_input_initials[High_score_input_frog_num][1];
	Game_high_score[loop_counter_1].he_initials[2] = High_score_input_initials[High_score_input_frog_num][2];
	Game_high_score[loop_counter_1].he_score = score;

	// Flag as having a new high score
	New_high_score = 1;

}

/******************************************************************************
*%%%% HighScoreEnterArcadeTime
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreEnterArcadeTime(MR_ULONG level_number,
*													MR_ULONG time)
*
*	FUNCTION	Inserts entry into arcade level high score table.
*
*	INPUTS		level_number			- Number of high score table to insert
*										  entry in to.
*				time					- Time to calculate position at which to
*										  insert entry
*
*	NOTES		This routine will just return if the time doesn't fit into the high
*				score table.  Also this routine should only be called from within the
*				HSInput system, and not externally.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreEnterArcadeTime(MR_ULONG level_number,MR_ULONG time)
{

	// Locals
	MR_LONG			loop_counter_1;
	MR_LONG			loop_counter_2;
	MR_ULONG		total_time;

	// $da: Changed, because we're making high_score_table_number the same as Game_map,
	//		so be careful to ensure that the order of Arcade_high_scores array is _EXACTLY_
	//		the same as the main library layout. No gaps, missus. Or it'll barf.


	// Loop once for each entry in table
	for(loop_counter_1=0;loop_counter_1<3;loop_counter_1++)
		{

		// Calculate total time
//		total_time = Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[0] +
//						Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[1] +
//						Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[2] +
//						Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[3] +
//						Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[4];

		total_time = Level_high_scores[level_number][loop_counter_1].he_score;

		// Is this time greater than entrants time ?
		if ( total_time < time )
			// Yes ... store position
			break;
		}

	// Are we in table ?
	if ( loop_counter_1 == 3 )
		{
		// No ... stop now
		return;
		}

	// Enter at bottom of table ?
	if ( loop_counter_1 != 2 )
		{
		// No ... loop once for each remaining entry in table
		loop_counter_2 = 2;
		do
			{

			// Dec count
			loop_counter_2--;

			// Move entry down
			Level_high_scores[level_number][loop_counter_2+1].he_initials[0] = Level_high_scores[level_number][loop_counter_2].he_initials[0];
			Level_high_scores[level_number][loop_counter_2+1].he_initials[1] = Level_high_scores[level_number][loop_counter_2].he_initials[1];
			Level_high_scores[level_number][loop_counter_2+1].he_initials[2] = Level_high_scores[level_number][loop_counter_2].he_initials[2];
			Level_high_scores[level_number][loop_counter_2+1].he_score = Level_high_scores[level_number][loop_counter_2].he_score;
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[0] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[0];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[1] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[1];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[2] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[2];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[3] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[3];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[4] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[4];

			} while ( loop_counter_2!=loop_counter_1 );
		}

	// Enter new entry at position
	Level_high_scores[level_number][loop_counter_1].he_initials[0] = High_score_input_initials[High_score_input_frog_num][0];
	Level_high_scores[level_number][loop_counter_1].he_initials[1] = High_score_input_initials[High_score_input_frog_num][1];
	Level_high_scores[level_number][loop_counter_1].he_initials[2] = High_score_input_initials[High_score_input_frog_num][2];
//	Level_high_scores[level_number][loop_counter_1].he_score = Frogs[0].fr_score;
	Level_high_scores[level_number][loop_counter_1].he_score = Frog_score_data[level_number][0].he_score;

	// $da: Changed to index Frog_score_data using non-mangled level id
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[0] = Frog_score_data[level_number][0].he_time_to_checkpoint[0];
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[1] = Frog_score_data[level_number][0].he_time_to_checkpoint[1];
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[2] = Frog_score_data[level_number][0].he_time_to_checkpoint[2];
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[3] = Frog_score_data[level_number][0].he_time_to_checkpoint[3];
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[4] = Frog_score_data[level_number][0].he_time_to_checkpoint[4];

	// Flag level as having a new high score
	New_high_scores[level_number] = 1;

}

/******************************************************************************
*%%%% HighScoreEnterRaceScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreEnterRaceScore(MR_ULONG level_number,
*											MR_ULONG score)
*
*	FUNCTION	Inserts entry into race level high score table.
*
*	INPUTS		level_number			- Number of high score table to insert
*										  entry in to.
*				score					- Score to calculate position at which to
*										  insert entry
*
*	NOTES		If the score is not good enough for the table, then this function
*				will just return.  Also this function can only be called from within
*				the HSInput system, and not externally.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreEnterRaceScore(MR_ULONG level_number,MR_ULONG score)
{

	// Locals
	MR_LONG			loop_counter_1;
	MR_LONG			loop_counter_2;
	MR_ULONG		high_score;

	// $da: Changed, because we're making high_score_table_number the same as Game_map,
	//		so be careful to ensure that the order of Race_high_scores array is _EXACTLY_
	//		the same as the main library layout. No gaps, missus. Or it'll barf.

	// Loop once for each entry in table
	for(loop_counter_1=0;loop_counter_1<3;loop_counter_1++)
		{

		// Get score
		high_score = Level_high_scores[level_number][loop_counter_1].he_score;

		// Is this score less than entrants score ?
		if ( score > high_score )
			// Yes ... store position
			break;

		}

	// Are we in table ?
	if ( loop_counter_1 == 3 )
		{
		// No ... stop now
		return;
		}

	// Enter at bottom of table ?
	if ( loop_counter_1 != 2 )
		{
		// No ... loop once for each remaining entry in table
		loop_counter_2 = 2;
		do
			{

			// Dec count
			loop_counter_2--;

			// Move entry down
			Level_high_scores[level_number][loop_counter_2+1].he_initials[0] = Level_high_scores[level_number][loop_counter_2].he_initials[0];
			Level_high_scores[level_number][loop_counter_2+1].he_initials[1] = Level_high_scores[level_number][loop_counter_2].he_initials[1];
			Level_high_scores[level_number][loop_counter_2+1].he_initials[2] = Level_high_scores[level_number][loop_counter_2].he_initials[2];
			Level_high_scores[level_number][loop_counter_2+1].he_score = Level_high_scores[level_number][loop_counter_2].he_score;
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[0] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[0];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[1] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[1];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[2] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[2];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[3] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[3];
			Level_high_scores[level_number][loop_counter_2+1].he_time_to_checkpoint[4] = Level_high_scores[level_number][loop_counter_2].he_time_to_checkpoint[4];

			} while ( loop_counter_2!=loop_counter_1 );
		}

	// Enter new entry at position
	Level_high_scores[level_number][loop_counter_1].he_initials[0] = High_score_input_initials[High_score_input_frog_num][0];
	Level_high_scores[level_number][loop_counter_1].he_initials[1] = High_score_input_initials[High_score_input_frog_num][1];
	Level_high_scores[level_number][loop_counter_1].he_initials[2] = High_score_input_initials[High_score_input_frog_num][2];
	Level_high_scores[level_number][loop_counter_1].he_score = score;
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[0] = 0;
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[1] = 0;
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[2] = 0;
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[3] = 0;
	Level_high_scores[level_number][loop_counter_1].he_time_to_checkpoint[4] = 0;

	// Flag level as having a new high score
	New_high_scores[level_number] = 1;

}

/******************************************************************************
*%%%% HighScoreCheckAllArcadeTimes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	HighScoreCheckAllArcadeTimes(MR_ULONG frog_num)
*
*	FUNCTION	Checks if this player has achieved a new high score in any of the
*				arcade high score tables.
*
*	INPUTS		frog_num				- Number of frog who may have achieved a
*										  new high score
*
*	RETURN		MR_BOOL					- TRUE - if player fits in any arcade high score table
*										  FALSE - if player doesn't fit in any arcade high score table
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL HighScoreCheckAllArcadeTimes(MR_ULONG frog_num)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_ULONG		total_time;
	MR_BOOL			high_score;

	// Loop once for each arcade level
	for(loop_counter=0;loop_counter<60;loop_counter++)
		{

		// Have we recorded a time for this level ?
		if ( Frog_score_data[loop_counter][frog_num].he_initials[0] == 'Z' )
			{

			// Yes ... calculate time to complete level
//			total_time = Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0];
			total_time = Frog_score_data[loop_counter][frog_num].he_score;

			// Check this level's high score
			high_score = HighScoreCheckArcadeTime(loop_counter,total_time);

			// Did this player get a new high score ?
			if ( high_score )
				// Yes ... return TRUE
				return TRUE;

			}
		}

	// Return false
	return FALSE;

}

/******************************************************************************
*%%%% HighScoreCheckAllRaceScores
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	HighScoreCheckAllRaceScores(MR_ULONG frog_num)
*
*	FUNCTION	Checks if this player has achieved a new high score in any of the
*				race high score tables.
*
*	INPUTS		frog_num				- Number of frog who may have achieved a
*										  new high score
*
*	RETURN		MR_BOOL					- TRUE - if player fits in any race high score table
*										  FALSE - if player doesn't fit in any race high score table
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL HighScoreCheckAllRaceScores(MR_ULONG frog_num)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_BOOL			high_score;

	// Loop once for each race level
	for(loop_counter=0;loop_counter<10;loop_counter++)
		{

		// Have we recorded a score for this level ?
		if ( Frog_score_data[(loop_counter*6)+5][frog_num].he_initials[0] == 'Z' )
			{

			// Yes ... check this level's high score
			high_score = HighScoreCheckRaceScore((loop_counter*6)+5,Frog_score_data[loop_counter][frog_num].he_score);

			// Did this player get a new high score ?
			if ( high_score )
				// Yes ... return TRUE
				return TRUE;

			}
		}

	// Return false
	return FALSE;

}

/******************************************************************************
*%%%% HighScoreAddAllArcadeTimes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreAddAllArcadeTimes(MR_ULONG frog_num)
*
*	FUNCTION	Adds the player's initials and times to all the high score tables
*				that the player has achieved a new high score in.
*
*	INPUTS		frog_num				- Number of frog who may have achieved a
*										  new high score
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreAddAllArcadeTimes(MR_ULONG frog_num)
{

	// Locals
	MR_ULONG		loop_counter;
//	MR_ULONG		total_time;

	// Loop once for each high score table
	for(loop_counter=0;loop_counter<60;loop_counter++)
		{

		// Has frog achieved a time for this level ?
		if ( Frog_score_data[loop_counter][frog_num].he_initials[0] == 'Z' )
			{

			// Yes ... calculate time
//			total_time = Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[0] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[1] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[2] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[3] +
//							Frog_score_data[loop_counter][frog_num].he_time_to_checkpoint[4];

			// Attempt to enter it into high score table
//			HighScoreEnterArcadeTime(loop_counter,total_time);
			HighScoreEnterArcadeTime(loop_counter,Frog_score_data[loop_counter][frog_num].he_score);
			}
		}
}


/******************************************************************************
*%%%% HighScoreAddAllRaceScores
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HighScoreAddAllRaceScores(MR_ULONG frog_num)
*
*	FUNCTION	Adds the player's initials and scores to all the high score tables
*				that the player has achieved a new high score in.
*
*	INPUTS		frog_num				- Number of frog who may have achieved a
*										  new high score
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID HighScoreAddAllRaceScores(MR_ULONG frog_num)
{

	// Locals
	MR_ULONG		loop_counter;

	// Loop once for each high score table
	for(loop_counter=0;loop_counter<10;loop_counter++)
		{
		// Has frog achieved a score for this level ?
		if ( Frog_score_data[(loop_counter*6)+5][frog_num].he_initials[0] == 'Z' )
			{
			// Yes ... attempt to enter it into high score table
			HighScoreEnterRaceScore((loop_counter*6)+5,Frog_score_data[(loop_counter*6)+5][frog_num].he_score);
			}
		}
}


/******************************************************************************
*%%%% HSInputInitialiseCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSInputInitialiseCamera(MR_VOID)
*
*	FUNCTION	Initialise "scrolly" camera to view all at once.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID HSInputInitialiseCamera(MR_VOID)
{
	CAMERA*	camera;


	Option_viewport_ptr->vp_camera 		= Option_camera_ptr;
	Option_viewport_ptr->vp_perspective = HIGH_SCORE_VIEW_PERSPECTIVE;
	camera 								= &Cameras[0];
	InitialiseCamera(camera, Option_viewport_ptr);

	// Offsets for static view (all hiscores)
	MR_SET_SVEC(&camera->ca_current_source_ofs,
				HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_X,
				HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_Y,
				HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_Z);

	MR_SET_SVEC(&camera->ca_current_target_ofs,
				HIGH_SCORE_INPUT_STATIC_TARGET_OFS_X,
				HIGH_SCORE_INPUT_STATIC_TARGET_OFS_Y,
				HIGH_SCORE_INPUT_STATIC_TARGET_OFS_Z);

	// Duration of scroll (none)
	camera->ca_move_timer 		= 0;
	camera->ca_offset_origin	= &Null_vector;
}


/******************************************************************************
*%%%% HSInputUpdateFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HSInputUpdateFrog(
*						FROG*	frog)
*
*	FUNCTION	Move the frog around the number pads
*
*	INPUTS		frog	-	ptr to FROG to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	HSInputUpdateFrog(FROG*	frog)
{
	MR_LONG			i, dy, letter;
	MR_OBJECT*		object_ptr;
	EFFECT*			effect;
	SHADOW*			shadow;
	MR_BOOL			jump;
	MR_LONG			cos, sin;
	MR_LONG			old_x, old_z;
	MR_OBJECT*		object;
	HSI_LILY_INFO*	lily_info;


	letter = (frog->fr_grid_z * 10) + frog->fr_grid_x;
	switch(frog->fr_mode)
		{
		//--------------------------------------------------------------------
		case FROG_MODE_STATIONARY:
			// Get y coord from current pad
			frog->fr_pos.vy	= High_score_input_letters_matrix_ptr[letter]->t[1] << 16;
			jump			= FALSE;
			old_x			= frog->fr_grid_x;
			old_z			= frog->fr_grid_z;
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_UP)) &&
				(frog->fr_grid_z > 0)
				)
				{
				// Jump up
				frog->fr_direction = FROG_DIRECTION_N;
				frog->fr_grid_z--;
				jump = TRUE;
				}
			else
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_DOWN)) &&
				(frog->fr_grid_z < 2)
				)
				{
				// Jump down
				frog->fr_direction = FROG_DIRECTION_S;
				frog->fr_grid_z++;
				jump = TRUE;
				}
			else
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_LEFT)) &&
				(frog->fr_grid_x > 0)
				)
				{
				// Jump left
				frog->fr_direction = FROG_DIRECTION_W;
				frog->fr_grid_x--;
				jump = TRUE;
				}
			else
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_RIGHT)) &&
				(frog->fr_grid_x < 9)
				)
				{
				// Jump right
				frog->fr_direction = FROG_DIRECTION_E;
				frog->fr_grid_x++;
				jump = TRUE;
				}
			else
			if	(
				(High_score_input_lily_infos[frog->fr_frog_id].hs_new_mof == NULL) &&
				(MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_GO))
				)
				{
				// Selected letter
				if (letter == HIGH_SCORE_INPUT_LETTER_RUB)
					{
					// Erase last character
					if (High_score_input_initial_pos[frog->fr_frog_id])
						{
#ifdef PSX
						MRSNDPlaySound(SFX_SEL_SPLASH, NULL, 0, 0);
#else
						MRSNDPlaySound(SFX_SEL_HI_SCORE_COUNT, NULL, 0, 0);
#endif
						High_score_input_initial_pos[frog->fr_frog_id]--;

						// Set up lily to turn and show new letter
						High_score_input_lily_infos[frog->fr_frog_id].hs_initial_index 	= (frog->fr_frog_id * 3) + High_score_input_initial_pos[frog->fr_frog_id];
						High_score_input_lily_infos[frog->fr_frog_id].hs_object			= High_score_input_initials_object_ptr[High_score_input_lily_infos[frog->fr_frog_id].hs_initial_index];
						High_score_input_lily_infos[frog->fr_frog_id].hs_angle			= 0;
						High_score_input_lily_infos[frog->fr_frog_id].hs_new_mof		= MR_GET_RESOURCE_ADDR(RES_OPT_LILLYPAD_BLANK_XMR);
						}
					}
				else
				if (letter == HIGH_SCORE_INPUT_LETTER_END)
					{
					// End hiscore input - explode frog
#ifdef PSX
					MRSNDPlaySound(SFX_SEL_SPLASH, NULL, 0, 0);
#else
					MRSNDPlaySound(SFX_SEL_HI_SCORE_COUNT, NULL, 0, 0);
#endif
					if (frog->fr_poly_piece_pop)
						{
						FrogStartPolyPiecePop(frog);
						object = MRCreatePgen(&PGIN_frog_pop_explosion, (MR_FRAME*)frog->fr_poly_piece_pop->pp_lwtrans, MR_OBJ_STATIC, NULL);
						object->ob_extra.ob_extra_pgen->pg_user_data_2 = Frog_pop_explosion_colours[frog->fr_frog_id];
						MRAddObjectToViewport(object, Option_viewport_ptr, NULL);
						frog->fr_mode =	FROG_MODE_STUNNED;
						frog->fr_shadow->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
						}
					}
				else
					{
					// Enter letter
					if (High_score_input_initial_pos[frog->fr_frog_id] < 3)
						{
#ifdef PSX
						MRSNDPlaySound(SFX_SEL_SPLASH, NULL, 0, 0);
#else
						MRSNDPlaySound(SFX_SEL_HI_SCORE_COUNT, NULL, 0, 0);
#endif
						if (letter < 26)
							// Letter
							High_score_input_initials[frog->fr_frog_id][High_score_input_initial_pos[frog->fr_frog_id]] = letter + 'A';
						else
						if (letter == 26)
							// Dot
							High_score_input_initials[frog->fr_frog_id][High_score_input_initial_pos[frog->fr_frog_id]] = '.';
						else
						if (letter == 27)
							// Space
							High_score_input_initials[frog->fr_frog_id][High_score_input_initial_pos[frog->fr_frog_id]] = ' ';

						// Set up lily to turn and show new letter
						High_score_input_lily_infos[frog->fr_frog_id].hs_initial_index 	= (frog->fr_frog_id * 3) + High_score_input_initial_pos[frog->fr_frog_id];
						High_score_input_lily_infos[frog->fr_frog_id].hs_object			= High_score_input_initials_object_ptr[High_score_input_lily_infos[frog->fr_frog_id].hs_initial_index];
						High_score_input_lily_infos[frog->fr_frog_id].hs_angle			= 0;
						High_score_input_lily_infos[frog->fr_frog_id].hs_new_mof		= MR_GET_RESOURCE_ADDR(High_score_input_letters_resource_id[letter]);						// Set up lily to turn and show new letter

						High_score_input_initial_pos[frog->fr_frog_id]++;
						}
					}
				}

			if (jump == TRUE)			
				{
				// Check we're not trying to jump to an occupied iliy
				for (i = 0; i < Game_total_players; i++)
					{
					if	(
						(i != frog->fr_frog_id) &&
						(Frogs[i].fr_mode != FROG_MODE_STUNNED) &&
						(Frogs[i].fr_grid_x == frog->fr_grid_x) &&
						(Frogs[i].fr_grid_z == frog->fr_grid_z)
						)
						{
						// Forbid jump
						frog->fr_grid_x = old_x;
						frog->fr_grid_z = old_z;
						goto after_jump;
						}
					}

				MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
				frog->fr_mode			= FROG_MODE_JUMPING;
				frog->fr_count			= HIGH_SCORE_INPUT_FROG_JUMP_TIME;

				// Calculate target pos
				letter 					= (frog->fr_grid_z * 10) + frog->fr_grid_x;
				frog->fr_target_pos.vx 	= High_score_input_letters_matrix_ptr[letter]->t[0];
				frog->fr_target_pos.vy 	= High_score_input_letters_matrix_ptr[letter]->t[1];
				frog->fr_target_pos.vz 	= High_score_input_letters_matrix_ptr[letter]->t[2];

				frog->fr_y				= frog->fr_pos.vy;
				frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
				frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

//				MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)frog->fr_api_item, 0);
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)frog->fr_api_item, GENM_FROG_HOP);
				MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)frog->fr_api_item, 0);
				}

		after_jump:;
			// Get rotation from current pad (scaled up)
			MR_COPY_MAT(frog->fr_lwtrans, High_score_input_letters_matrix_ptr[letter]);
			MRScale_matrix.m[0][0] = 0x1400;
			MRScale_matrix.m[1][1] = 0x1400;
			MRScale_matrix.m[2][2] = 0x1400;
			MRMulMatrixABB(&MRScale_matrix, frog->fr_lwtrans);
						
			cos = rcos(frog->fr_direction * 0x400);
			sin = rsin(frog->fr_direction * 0x400);
			MRRot_matrix_Y.m[0][0] =  cos;
			MRRot_matrix_Y.m[0][2] =  sin;
			MRRot_matrix_Y.m[2][0] = -sin;
			MRRot_matrix_Y.m[2][2] =  cos;
			MRMulMatrixABB(&MRRot_matrix_Y, frog->fr_lwtrans);
			break;
		//--------------------------------------------------------------------
		case FROG_MODE_JUMPING:
			// Handle jump
			//
			// Move fr_y in a line from source to target: actual y is parabola offset from this
			frog->fr_target_pos.vy 	= High_score_input_letters_matrix_ptr[letter]->t[1];
			frog->fr_y 				+= ((frog->fr_target_pos.vy << 16) - frog->fr_y) / frog->fr_count;

			dy						= (-8 << 16)  * (MR_SQR(HIGH_SCORE_INPUT_FROG_JUMP_TIME >> 1) - MR_SQR(frog->fr_count - (HIGH_SCORE_INPUT_FROG_JUMP_TIME >> 1)));
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

				// Create splash sprite
				object_ptr = MRCreate3DSprite((MR_FRAME*)High_score_input_letters_matrix_ptr[letter], MR_OBJ_STATIC, High_score_splash_animlist);
				MRAddObjectToViewport(object_ptr, Option_viewport_ptr, NULL);

				object_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
				object_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x8;
				object_ptr->ob_extra.ob_extra_sp_core->sc_scale		= 10 << 16;

				// setup anim
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)frog->fr_api_item, GENM_FROG_SIT);
				MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)frog->fr_api_item, 0);
				}
			break;
		//--------------------------------------------------------------------
		}

	// Get frog position/rotation
	frog->fr_lwtrans->t[0] 	= frog->fr_pos.vx >> 16;
	frog->fr_lwtrans->t[1] 	= frog->fr_pos.vy >> 16;
	frog->fr_lwtrans->t[2] 	= frog->fr_pos.vz >> 16;

	// Update shadow
	if (effect = frog->fr_shadow)
		{
		// Update sh_texture and sh_offsets
		shadow = effect->ef_extra;
		if (frog->fr_mode == FROG_MODE_JUMPING)
			{
			i = ((HIGH_SCORE_INPUT_FROG_JUMP_TIME - frog->fr_count) * 6) / HIGH_SCORE_INPUT_FROG_JUMP_TIME;
			i = MAX(0, MIN(5, i));
			}
		else
			{
			i = 0;
			}
		shadow->sh_offsets 	= Frog_jump_shadow_offsets[i];
		shadow->sh_texture	= Frog_jump_shadow_textures[i];
		}

	// Poly piece pop
	if	(
		(frog->fr_poly_piece_pop) &&
		(frog->fr_poly_piece_pop->pp_timer)
		)
		{
		UpdatePolyPiecePop(frog->fr_poly_piece_pop);
		RenderPolyPiecePop(frog->fr_poly_piece_pop, ((MR_ANIM_ENV_INST*)frog->fr_api_insts[0])->ae_mesh_insts[0], 0);
		}		

	// Update turning lily
	lily_info = &High_score_input_lily_infos[frog->fr_frog_id];
	if (lily_info->hs_new_mof)
		{
		lily_info->hs_angle += 0x100;
		if (lily_info->hs_angle == 0x500)
			{
			// Kill current mesh and create a new one
			lily_info->hs_object->ob_flags 	|= MR_OBJ_DESTROY_BY_DISPLAY;
			lily_info->hs_object			= MRCreateMesh(lily_info->hs_new_mof, lily_info->hs_object->ob_frame, MR_OBJ_STATIC, NULL);

			High_score_input_initials_object_ptr[lily_info->hs_initial_index] = lily_info->hs_object;
			MRAddObjectToViewport(lily_info->hs_object, Option_viewport_ptr, NULL);

			lily_info->hs_angle				= -0x300;
			}
		else
		if (lily_info->hs_angle == 0)
			{
			// Done - reset lily info
			lily_info->hs_new_mof			= NULL;
			}
		}
}




#ifdef WIN95
#pragma warning (default : 4761)
#pragma warning (default : 4018)
#endif
