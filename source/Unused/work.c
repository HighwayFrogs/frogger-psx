
MR_UBYTE	High_score_input_initials[4][HIGH_SCORE_NUM_INITIALS];

MR_UBYTE	High_score_input_mode;
MR_ULONG	High_score_wait_count;

MR_BOOL		High_high_score;
MR_BOOL		High_level_score;

MR_MOF*		High_score_selectable_letter_model_ptr[HIGH_SCORE_NUM_SELECTABLE_LETTERS];
MR_FRAME*	High_score_selectable_letter_frame_ptr[HIGH_SCORE_NUM_SELECTABLE_LETTERS];
MR_OBJECT*	High_score_selectable_letter_object_ptr[HIGH_SCORE_NUM_SELECTABLE_LETTERS];
MR_MESH_INST*	High_score_selectable_letter_inst_ptr[HIGH_SCORE_NUM_SELECTABLE_LETTERS];

MR_MOF*		High_score_initial_model_ptr[HIGH_SCORE_NUM_INITIALS];
MR_FRAME*	High_score_initial_frame_ptr[HIGH_SCORE_NUM_INITIALS];
MR_OBJECT*	High_score_initial_object_ptr[HIGH_SCORE_NUM_INITIALS];
MR_MESH_INST*	High_score_initial_inst_ptr[HIGH_SCORE_NUM_INITIALS];

MR_*		High_score_frog_anim_model_ptr;
MR_FRAME*	High_score_frog_anim_frame_ptr;
MR_ANIMENV*	High_score_frog_anim_env_ptr;
MR_*		High_score_frog_anim_inst_ptr;

MR_ULONG		High_score_ripple_display_list[]	=
{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_hs_ripple6,
	MR_SPRT_KILL
};

//---------------------------------------------------------------------------
//
//---------------------------------------------------------------------------

MR_VOID HighScoreInputStartup(MR_VOID)
{

	// Locals
	MR_ULONG		loop_counter;

// Create Selectable Letter Models ------------------------------------------

	// Loop once for each selectable letter
	for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_SELECTABLE_LETTERS;loop_counter++)
		{
		// Get address of letter in memory
		High_score_selectable_letter_model_ptr[loop_counter] = MR_GET_RESOURCE_ADDR();
		// Assert if letter not currently in memory
		MR_ASSERT(High_score_selectable_letter_model_ptr[loop_counter]!=NULL);
		// Create a frame for each model
		High_score_selectable_letter_frame_ptr[loop_counter] = MRCreateFrame(&MRNull_vec,&MRNull_svec,0);
		// Create model
		High_score_selectable_letter_object_ptr[loop_counter] = MRCreateObject(MR_OBJTYPE_STATIC_MESH,High_score_selectable_letter_frame_ptr[loop_counter],0,High_score_selectable_letter_model_ptr[loop_counter]);
		// Flag object as currently not displayable
		High_score_selectable_letter_object_ptr[loop_counter]->ob_flags |= MR_OBJ_NO_DISPLAY;
		// Add object to viewport
		High_score_selectable_letter_inst_ptr[loop_counter] = MRAddObjectToViewport(High_score_selectable_letter_object_ptr[loop_counter],Option_viewport_ptr,0);
		}

// Create Selected Letter Models --------------------------------------------

	// Loop once for each initial
	for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_INITIALS;loop_counter++)
		{
		// Get address of letter in memory
		High_score_initial_model_ptr[loop_counter] = MR_GET_RESOURCE_ADDR();
		// Assert if letter not currently in memory
		MR_ASSERT(High_score_initial_model_ptr[loop_counter]!=NULL);
		// Create a frame for each model
		High_score_initial_frame_ptr[loop_counter] = MRCreateFrame(&MRNull_vec,&MRNull_svec,0);
		// Create model
		High_score_initial_object_ptr[loop_counter] = MRCreateObject(MR_OBJTYPE_STATIC_MESH,High_score_initial_frame_ptr[loop_counter],0,High_score_initial_model_ptr[loop_counter]);
		// Flag object as currently not displayable
		High_score_initial_object_ptr[loop_counter]->ob_flags |= MR_OBJ_NO_DISPLAY;
		// Add object to viewport
		High_score_initial_inst_ptr[loop_counter] = MRAddObjectToViewport(High_score_initial_object_ptr[loop_counter],Option_viewport_ptr,0);
		}

// Create Frog Model --------------------------------------------------------

// Flag frog as current invisible

	// Get address of Frog model in memory
	High_score_frog_anim_model_ptr = MR_GET_RESOURCE_ADDR();

	// Assert if Frog model currently not in memory
	MR_ASSERT(High_score_frog_anim_model_ptr!=NULL);

	// Create frame for Frog model
	High_score_frog_anim_frame_ptr = MRCreateFrame(&MRNull_vec,&MRNull_svec,0);

	// Create frogs and add to viewport
	High_score_frog_anim_env_ptr = MRAnimEnvSingleCreateWhole(High_score_frog_anim_model_ptr,0,/*MR_OBJ_STATIC*/0,High_score_frog_anim_frame_ptr);

	// Try and make the Frog anim a ONE SHOT.
	High_score_frog_anim_env_ptr->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

	// Set a default animation action of zero, default behaviour so to speak
	MRAnimEnvSingleSetAction(High_score_frog_anim_env_ptr, 0);

	// Attach to game viewports
	High_score_frog_anim_inst_ptr = MRAnimAddEnvToViewport(High_score_frog_anim_env_ptr,Option_viewport_ptr,0);

// Initialise ---------------------------------------------------------------

	// Initialise mode of operation
	High_score_input_mode = HIGH_SCORE_INPUT_MODE_INPUT;

	// Initialise wait count
	High_score_wait_count = 0;

	// Initialise first frog
	High_score_frog_num = 0;

}

//---------------------------------------------------------------------------
//
//---------------------------------------------------------------------------


MR_VOID HighScoreInputUpdate(MR_VOID)
{

	// Locals
	MR_ULONG	loop_counter;
	MR_SVEC		rot;

	// According to high score input mode do ...
	switch ( High_score_input_mode )
		{

		//-----------------------------------------------------------
		case HIGH_SCORE_INPUT_MODE_INIT:

			// Initialise high score input stuff
			High_score_input_pos = 13;
			High_score_initial_pos = 0;

			// Initialise input
			for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_INITIALS;loop_counter++)
				High_score_input_initials[High_score_frog_num][loop_counter] = 0;

			// Initialise player as not good enough
			High_high_score = FALSE;
			High_level_score = FALSE;

			// Check if this frog has got a new game high score ( when in arcade, unused frog's score should be initialised to 0 )
			High_high_score = HighScoreCheckScore(Frogs[High_score_frog_num].fr_score);			// Score

			// Are we in arcade mode ?
			if ( Sel_mode == SEL_MODE_ARCADE )
				{
				// Yes ... has this frog achieved a new fastest time for a certain level
				High_level_score = HighScoreCheckAllArcadeTimes(High_score_frog_num);
				}
			else
				{
				// No ... has this Frog achieved a new high score for a certain level
				High_level_score = HighScoreCheckAllRaceScores(High_score_frog_num);
				}

			// Should this frog enter his name ?
			if ( (High_high_score == TRUE) || (High_level_score == TRUE) )
				{
				// Yes ... go on to input
// Position selectable letters at correct starting positions
// Flag selectable letters as displayable
// Position initials at correct starting positions
// Flag initials as displayable
// Position frog at correct starting position
// Flag frog as displayable
				HSInput_mode = HIGH_SCORE_INPUT_MODE_INPUT;
				}
			else
				{
				// No ... go on to next frog
				HSInput_mode = HIGH_SCORE_INPUT_MODE_NEXT_FROG;
				}

			break;

		//-----------------------------------------------------------
		// Wait for new input before moving ...
		case HIGH_SCORE_INPUT_MODE_INPUT:

			// Did we press right ?
			if ( MR_CHECK_PAD_PRESSED(Frog_selected_input_ports[HSInput_frog_num],FRR_RIGHT) )
				{
				// Yes ... are we at right edge ?
				if ( High_score_input_pos < (HIGH_SCORE_NUM_SELECTABLE_LETTERS-1) )
					{
					// No ... switch mode to scroll right
					High_score_input_mode = HIGH_SCORE_INPUT_MODE_SCROLL_RIGHT;
					// Trigger frog jumping animation
					MRAnimEnvSingleSetAction(High_score_frog_anim_env_ptr, 0);
					// Cause frog to face right
					rot.vx = 0;
					rot.vy = 1024;
					rot.vz = 0;
					MRRotMatrix(&rot,High_score_frog_anim_frame_ptr->fr_matrix);
					// Reset wait count
					High_score_wait_count = 0;
					}
				}

			// Did we press left ?
			if ( MR_CHECK_PAD_PRESSED(Frog_selected_input_ports[HSInput_frog_num],FRR_LEFT) )
				{
				// Yes ... are we at left edge ?
				if ( High_score_input_pos > 0 )
					{
					// No ... switch mode to scroll left
					High_score_input_mode = HIGH_SCORE_INPUT_MODE_SCROLL_LEFT;
					// Trigger jumping animation
					MRAnimEnvSingleSetAction(High_score_frog_anim_env_ptr, 0);
					// Cause frog to face left
					rot.vx = 0;
					rot.vy = 3072;
					rot.vz = 0;
					MRRotMatrix(&rot,High_score_frog_anim_frame_ptr->fr_matrix);
					// Reset wait count
					High_score_wait_count = 0;
					}
				}

			// Did we press fire ?
			if ( MR_CHECK_PAD_PRESSED(Frog_selected_input_ports[HSInput_frog_num],FRR_CROSS) )
				{
				// Yes ... go to selection
				High_score_input_mode = HIGH_SCORE_INPUT_MODE_SELECT;
				// Trigger backflip animation
				MRAnimEnvSingleSetAction(High_score_frog_anim_env_ptr, 1);
				// Reset wait count
				High_score_wait_count = 0;
				}
			break;

		//-----------------------------------------------------------
		// Move frog to right by moving lillypads left ...
		case HIGH_SCORE_INPUT_MODE_SCROLL_RIGHT:

			// Move lillypads left
			for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_SELECTABLE_LETTERS;loop_counter++)
				{
				// Update x position of lillypad
				High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] -= 10;

		       		// Has lillypad come on right ?
				if ( High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] < HIGH_SCORE_MAX_X_POS )
					{
					// Yes ... start displaying lillypad
					High_score_selectable_letter_object_ptr[loop_counter]->ob_flags &= ~MR_OBJ_NO_DISPLAY;
					}

				// Has lillypad gone off left ?
				if ( High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] < HIGH_SCORE_MIN_X_POS )
					{
					// Yes ... stop displaying lillypad
					High_score_selectable_letter_object_ptr[loop_counter]->ob_flags |= MR_OBJ_NO_DISPLAY;
					}

				}

			// Inc wait count
			High_score_wait_count++;

			// Have we reached end of wait ?
			if ( High_score_wait_count == HIGH_SCORE_NUM_FROG_JUMP_FRAMES )
				{
				// Yes ... trigger splash animation
				High_score_ripple_sprite_ptr[0] = MRCreate2DSprite(192,120,Option_viewport_ptr,&im_hiscore_back,NULL);
				High_score_ripple_sprite_ptr[0]->sp_core.sc_ot_offset = 100;
				// Yes ... go back to waiting for input
				High_score_input_mode = HIGH_SCORE_INPUT_MODE_INPUT;
				// Move cursor position right
				High_score_input_pos++;
				}

			break;

		//-----------------------------------------------------------
		// Move frog to left by moving lillypads right ...
		case HIGH_SCORE_INPUT_MODE_SCROLL_LEFT:

			// Move lillypads right
			for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_SELECTABLE_LETTERS;loop_counter++)
				{
				// Update x position of lillypad
				High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] += 10;

				// Has lilly come on left ?
				if ( High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] > HIGH_SCORE_MIN_X_POS )
					{
					// Yes ... start displaying lillypad
					High_score_selectable_letter_object_ptr[loop_counter].ob_flags &= ~MR_OBJ_NO_DISPLAY;
					}
				// Has lilly go off right ?
				if ( High_score_selectable_letter_frame_ptr[loop_counter]->fr_matrix.t[0] > HIGH_SCORE_MAX_X_POS )
					{
					// Yes ... stop displaying lillypad
					High_score_selectable_letter_object_ptr[loop_counter].ob_flags |= MR_OBJ_NO_DISPLAY;
					}
				}

			// Inc wait count
			High_score_wait_count++;

			// Have we reached end of wait ?
			if ( High_score_wait_count == HIGH_SCORE_NUM_FROG_JUMP_FRAMES )
				{
				// Yes ... trigger splash animation
				High_score_ripple_sprite_ptr[0] = MRCreate2DSprite(192,120,Option_viewport_ptr,&im_hiscore_back,NULL);
				High_score_ripple_sprite_ptr[0]->sp_core.sc_ot_offset = 100;
				// Yes ... go back to waiting for input
				High_score_input_mode = HIGH_SCORE_INPUT_MODE_INPUT;
				// Move cursor position left
				High_score_input_pos--;
				}

			break;

		//-----------------------------------------------------------
		// Select current thing ...
		case HIGH_SCORE_INPUT_MODE_SELECT:

			// Inc wait count
			High_score_wait_count++;

			// Have we reached end of wait ?
			if ( High_score_wait_count == HIGH_SCORE_NUM_FROG_BACKFLIP_FRAMES )
				{
				// Yes ... trigger splash animation
				High_score_ripple_sprite_ptr[0] = MRCreate2DSprite(192,120,Option_viewport_ptr,&im_hiscore_back,NULL);
				High_score_ripple_sprite_ptr[0]->sp_core.sc_ot_offset = 100;

				// Yes ... depending on type of letter do...
				if ( High_score_input_pos == HIGH_SCORE_RUB )
					{
					// Rub
					High_score_input_initials[High_score_input_frog_num][High_score_initial_pos] = 26;

					// Are we still on first character ?
					if ( High_score_initial_pos )
						{
						// No ... move cursor back
						High_score_initial_pos--;
						}
					}
				else if ( High_score_input_pos == HIGH_SCORE_END )
					{
					// End ... enter high score
					High_score_input_mode = HIGH_SCORE_INPUT_MODE_ENTER_HISCORE;
					}
				else
					{
					// Set letter
					High_score_input_initials[High_score_input_frog_num][High_score_initial_pos] = High_score_input_pos;
					// Reset wait count
					High_score_wait_count = 0;
					// Go on to waiting for letter animation
					High_score_input_mode = HIGH_SCORE_INPUT_MODE_LETTER_ANIM_PART1;
					}
				}

			break;

		//-----------------------------------------------------------
		// Wait for letter to spin ...
		case HIGH_SCORE_INPUT_MODE_LETTER_ANIM_PART1:

// Animate current initial spinning half way round

			// Inc wait count
			High_score_wait_count++;

			// End of wait count ?
			if( High_score_wait_count == )
				{
				// Yes ... spin rest of way
				High_score_input_mode = HIGH_SCORE_INPUT_MODE_LETTER_ANIM_PART2;
				// Reset wait count
				High_score_wait_count = 0;
				}
			break;

		// Stop displaying old initial, start displaying new one and wait for spin to finish ...
		case HIGH_SCORE_INPUT_MODE_LETTER_ANIM_PART2:

// First time in kill old initial and create new one
// Spin new initial

			// Inc wait count
			High_score_wait_count++;

			// End of wait count ?
			if ( High_score_wait_count == )
				{
				// Yes ... go back to input
				High_score_input_mode = HIGH_SCORE_INPUT_MODE_INPUT;
				}

			break;

		//-----------------------------------------------------------
		case HIGH_SCORE_INPUT_MODE_ENTER_HISCORE:

// Flag selectable letters as not displayable
// Flag initials as not displayable
// Flag frog as not displayable

			// Was a new game based high score achieved ?
			if ( High_high_score )
				{
				// Yes ... add frog to game high score
				HighScoreEnterScore(Frogs[High_score_frog_num].fr_score);		// Score
				}

			// Was a new level based high score achieved ?
			if ( High_level_score )
				{
				// Yes ... add frog to relevant high score tables
				if ( Sel_mode == SEL_MODE_ARCADE )
					{
					// Yes ... add player to relevant arcade high score table
					HighScoreAddAllArcadeTimes(High_score_frog_num);
					}
				else
					{
					// No ... add player to relevant race high score table
					HighScoreAddAllRaceScores(High_score_frog_num);
					}
				}

			// Go on to next frog
			High_score_input_mode = HIGH_SCORE_INPUT_NEXT_FROG;

			break;

		//-----------------------------------------------------------
		case HIGH_SCORE_INPUT_NEXT_FROG:

			// Go on to next frog
			High_score_frog_num++;

			// All frogs finished ?
			if ( High_score_frog_num != 4 )
				{
				// No ... go back to initialise
				High_score_input_mode = HIGH_SCORE_INPUT_INIT;
				}
			else
				{
				// Yes ... exit
				High_score_input_mode = HIGH_SCORE_INPUT_END;
				}

			break;

		//-----------------------------------------------------------
		case HIGH_SCORE_INPUT_END:

			// Deinitialise

			// Go on to high score view
			Option_page_request = OPTIONS_PAGE_HIGH_SCORE_VIEW;

			// Operate in automatic mode
			HSView_automatic_flag = TRUE;

			break;

		}
}

//---------------------------------------------------------------------------
//
//---------------------------------------------------------------------------

MR_VOID HighScoreInputShutdown(MR_VOID)
{

	// Locals
	MR_ULONG	loop_counter;

	// Destroy all selectable letter models
	for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_SELECTABLE_LETTERS;loop_counter++)
		{
		// Destroy object and frame
		High_score_selectable_letter_object_ptr[loop_counter]->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
		}

	// Destroy all initial models
	for(loop_counter=0;loop_counter<HIGH_SCORE_NUM_INITIALS;loop_counter++)
		{
		// Destroy initials
		High_score_initial_object_ptr[loop_counter]->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
		}

	// Destroy frog
	MRAnimEnvDestroyByDisplay(High_score_frog_anim_env_ptr);


}

