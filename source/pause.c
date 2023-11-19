/******************************************************************************
*%%%% pause.c
*------------------------------------------------------------------------------
*
*	All stuff to do with pausing the game.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

#include "pause.h"
#include "frog.h"
#include "tempopt.h"
#include "entity.h"
#include "options.h"
#include "playxa.h"
#include "sound.h"
#include "select.h"
#include "hsinput.h"
#include "ent_gen.h"

// Pause mode
MR_2DSPRITE*	Game_paused_insert_pad_sprite_ptr = NULL;
MR_2DSPRITE*	Game_paused_pause_sprite_ptr 	  = NULL;
MR_2DSPRITE*	Game_paused_continue_sprite_ptr   = NULL;
MR_2DSPRITE*	Game_paused_quit_sprite_ptr       = NULL;
MR_2DSPRITE*	Game_paused_quit_yes_sprite_ptr   = NULL;
MR_2DSPRITE*	Game_paused_quit_no_sprite_ptr    = NULL;
MR_ULONG		Game_paused_selection;
MR_BOOL			Game_paused_finish;
MR_LONG			Game_paused_player 				  = -1;						// Cos only the player that paused can un-pause.
MR_ULONG		Pause_mode 						  = PAUSE_MODE_NO_PAUSE;	// Mode of pause operation
POLY_F4			Pause_poly[2];
POLY_FT3		Pause_poly2[2];
MR_UBYTE		Pause_volume;
MR_LONG			Pause_hidden_menu_mode 			  = HIDDEN_MENU_WAITING;	// Mode of Hidden Menu.
MR_LONG			Pause_hidden_selection			  = 0;
MR_LONG			Pause_hidden_quit_selection		  = HIDDEN_MENU_QUIT_NO;

MR_LONG			Select_mode						  = SELECT_MODE_WAITING;
MR_LONG			Game_select_player 				  = -1;		
MR_LONG			Select_timer					  = 2 * (FRAMES_PER_SECOND >> 2);

MR_USHORT		Cached_states[8];

/******************************************************************************
*%%%% GameSelectReset
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameSelectReset(MR_VOID)
*
*	FUNCTION	Handle in game select reset mode.
*	MATCH		https://decomp.me/scratch/61XAM	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created.
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/
MR_VOID GameSelectReset(MR_VOID)
{
 	// Locals
	FROG*			frog;
	MR_LONG			loop;
				
	// Make sure all Frogs get a chance to Reset.
	frog	= &Frogs[0];
	loop	= Game_total_players;
	
	switch (Select_mode)
		{
		// --------------------------------------------------------
		case SELECT_MODE_WAITING:
			while(loop--)
			{
			// Has Select Been Pressed.
			if ( MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_SELECT) )
				{
				Select_mode = SELECT_MODE_INIT;
				// Store the player number that PAUSED the Game.
				Game_select_player = frog->fr_input_id;
				// Can we have 1 second on the clock please?
				Select_timer = FRAMES_PER_SECOND;
				}
			frog++;											   
			}
			break;
		// --------------------------------------------------------
		case SELECT_MODE_INIT:
			// Is select still being pressed??
			if ( MR_CHECK_PAD_HELD(Game_select_player, FRR_SELECT) )
				{
				// If so wait for START to be pressed.
				if ( MR_CHECK_PAD_PRESSED(Game_select_player, FRR_START) )
					{
					Select_mode = SELECT_MODE_COUNTING;
					// Need an audio response for this too.
					MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
					}
				}
			else
				{
				// Select is not being held, so reset select reset.
				Select_mode = SELECT_MODE_WAITING;
				}
			break;
		// --------------------------------------------------------
		case SELECT_MODE_COUNTING:
			// Is select still being pressed??
			if ( MR_CHECK_PAD_HELD(Game_select_player, FRR_SELECT) && MR_CHECK_PAD_HELD(Game_select_player, FRR_START) )
				{
				// Wait for timer to get to zero.
				if (Select_timer-- == 0)
					{
					Option_page_request = OPTIONS_PAGE_GAME_OVER;
					Option_number = 2;
					}
				}
			else
				{
				// Select is not being held, so reset select reset.
				Select_mode = SELECT_MODE_WAITING;
				}
			break;
		// --------------------------------------------------------
		}
}

/******************************************************************************
*%%%% GamePause
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GamePause(MR_VOID)
*
*	FUNCTION	Handle in game pause mode.
*	MATCH		https://decomp.me/scratch/aRo6w	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	William Bell	Created
*	14.08.97	Gary Richards	Re-wrote to conform to SONY standards.
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/
MR_VOID GamePause(MR_VOID)
{
 	// Locals
	MR_ULONG		loop_counter;
	POLY_F4*		poly_f4;
	MR_TEXTURE*		texture;
	FROG*			frog;
	MR_LONG			loop;
	MR_ULONG		i;
				
	// According to mode do ...
	switch ( Pause_mode )
		{

		//-------------------------------------------------------------------
		// Non pause ...
		case PAUSE_MODE_NO_PAUSE:
			// Can't pause while the game is in START-UP Mode.
			if	(
				(!Game_start_timer) &&
				(!(Game_flags & GAME_FLAG_NO_PAUSE_ALLOWED))
				)
				{
				// Make sure all Frogs get a chance to PAUSE.
				frog	= &Frogs[0];
				loop	= Game_total_players;
			
				while(loop--)
					{
					// Did we press Start, without holding Select.
					if ((frog->fr_flags & FROG_ACTIVE) && 
						(MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_START)) &&
						(!(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_SELECT))))
						{
//						MRShowMem("GamePause");

						// Yes ... flag game as paused
						Game_flags |= GAME_FLAG_PAUSED;
				   		// Go on to pause init
						Pause_mode = PAUSE_MODE_INIT;
						// Store the player number that PAUSED the Game.
						Game_paused_player = frog->fr_input_id;
						// Kill any effects that may be playing.
						MRSNDKillAllSounds();		// And hope they come back when we un-pause.
						// Audio response to the button press.
						MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
						}
						frog++;
					}
				}
			break;

		//-------------------------------------------------------------------
		// Initialise ...
		case PAUSE_MODE_INIT:
			GamePauseCreateFadePoly();

			// Create "paused" sprite
			texture = Options_text_textures[OPTION_TEXT_PAUSED][Game_language];
			Game_paused_pause_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),Game_display_height>>1,Option_viewport_ptr,texture,NULL);
 
 			// Initialise selection to first
			Game_paused_selection = 0;
			// Go on to fade down
			Pause_mode = PAUSE_MODE_FADE_DOWN;
			// Initial sound volume defaults.
			Pause_volume = Sound_volume;
			OptionClearSpcores();
			Option_spcore_ptrs[1] = NULL;
			Option_spcore_ptrs[0] = (MR_SP_CORE*)Game_paused_pause_sprite_ptr;
			Option_spcore_index   = Game_paused_selection;		// So pause flashes at start.

#ifdef	PSX_ENABLE_XA
#ifdef PSX
			// Pause music
			XAControl(XACOM_PAUSE,0);
#else
#endif
#endif
			break;

		//-------------------------------------------------------------------
		// Fade down ...
		case PAUSE_MODE_FADE_DOWN:

			// Fade down semi-trans poly
			poly_f4 = &Pause_poly[0];

			// Loop once for each poly
			for(loop_counter=0;loop_counter<2;loop_counter++)
				{
				// Set poly base colour
				poly_f4->r0 += 0x10;
				poly_f4->g0 += 0x10;
				poly_f4->b0 += 0x10;
				// Next prim
				poly_f4++;
				}

			// Reduce the Volume of the SFX.
			if (Pause_volume < 1)
				Pause_volume = 0;	
			else
				Pause_volume--;	

			// Turn off the Auto_Volume within the API.
			LiveEntityChangeVolume(Pause_volume, FALSE);

			// End of fade ?
			if ( Pause_poly[0].r0 == 0x80 )
				{
				// Yes ... go on to main pause
				Pause_mode = PAUSE_MODE_MENU;
				}

			GamePauseAddPrim();
			break;

		//-------------------------------------------------------------------
		// Menu ...
		case PAUSE_MODE_MENU:
			// Using 'Game_paused_player' cos only the person that paused has control.

			// Start Pressed to Un-Paused.
			if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_START) )
				{
				// Continue game
				Game_paused_selection = 0;
				Pause_mode = PAUSE_MODE_KILL_SPRITES;
				// Audio response to the button press.
				MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
				}
			else
				{
				if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_GREEN) && Pause_hidden_menu_mode)
					{
					DeInitialiseHiddenMenu();
					Option_spcore_index = 0;
					}

				if (Sel_mode == SEL_MODE_ARCADE)
					{
					// Check for any cheat mode presses.
					GameCheatModeCheck();
					}

				

				// Display Hidden Menu, according to mode set.
				switch ( Pause_hidden_menu_mode )
					{
					// ------------------------------------------------------------------------------------
					case HIDDEN_MENU_WAITING:
						// If Select is pressed in PAUSE Mode display hidden Menu allowing a reset to title.
						// Start Pressed to Un-Paused.
						if ( MR_CHECK_PAD_RELEASED(Game_paused_player,FRR_SELECT) )
							{
							InitialiseHiddenMenu();
							MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
							}
						break;
					// ------------------------------------------------------------------------------------
					case HIDDEN_MENU_CONTINUE:
						if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_DOWN) )
							{
							// Yes ... last selection ?
							if ( Pause_hidden_selection < (MAX_HIDDEN_MENU_ITEMS - 1) )
								{
								Pause_hidden_selection++;	// Down one.
								// Audio response to the button press.
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								}
							}

						if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_UP) )
							{
							// Check we are NOT at the Top.
							if ( Pause_hidden_selection > 0 )
								{
								Pause_hidden_selection--;		// Up one.
								// Audio response to the button press.
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								}
							}
	
						if ( MR_CHECK_PAD_RELEASED(Game_paused_player,FRR_CROSS) )
							{
							// Act on currently selected menu options.
							switch (Pause_hidden_selection)
								{
								// ------------------------------------------------
								// Continue back to game.
								case HIDDEN_MENU_CONTINUE_SELECTED:
									Game_paused_selection = HIDDEN_MENU_CONTINUE_SELECTED;
									Pause_mode = PAUSE_MODE_KILL_SPRITES;
									// Audio response to the button press.
									MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
									break;
								// ------------------------------------------------
								case HIDDEN_MENU_QUIT_SELECTED:
									// Off to display YES/NO.
									Pause_hidden_menu_mode = HIDDEN_MENU_QUIT;
									InitialiseHiddenQuitMenu();
									// Audio response to the button press.
									MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
									break;
								// ------------------------------------------------
								}
							}
						// Display the new sprite 'n' things.
						Option_spcore_index   = ( Pause_hidden_selection + 1);		// So continue/quit flashes.
						break;
					// ------------------------------------------------------------------------------------									
					case HIDDEN_MENU_QUIT:
						if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_LEFT) )
							{
							// Yes ... last selection ?
							if ( Pause_hidden_quit_selection < (MAX_HIDDEN_MENU_QUIT_ITEMS - 1) )
								{
								Pause_hidden_quit_selection++;	// Down one.
								// Audio response to the button press.
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								}
							}
	
						if ( MR_CHECK_PAD_PRESSED(Game_paused_player,FRR_RIGHT) )
							{
							// Check we are NOT at the Top.
							if ( Pause_hidden_quit_selection > 0 )
								{
								Pause_hidden_quit_selection--;		// Up one.
								// Audio response to the button press.
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								}
							}
	
						if ( MR_CHECK_PAD_RELEASED(Game_paused_player,FRR_CROSS) )
							{
							// Act on currently selected menu options.
							switch (Pause_hidden_quit_selection)
								{
								// ------------------------------------------------
								// Quit NO back to game.
								case HIDDEN_MENU_QUIT_NO:
									Game_paused_selection = HIDDEN_MENU_CONTINUE_SELECTED;
									Pause_mode = PAUSE_MODE_KILL_SPRITES;
									// Audio response to the button press.
									MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
									break;
								// ------------------------------------------------
								case HIDDEN_MENU_QUIT_YES:
									// Quit the Game..... GAME OVER!
									Game_paused_selection = HIDDEN_MENU_QUIT_SELECTED;

									// Set option number ( in case we are in multiplayer mode )
									Option_number = 2;

									// Flag all hiscores as invalid
									New_high_score = 0;
									for(i = 0; i < 60; i++)
										{
										New_high_scores[i] = 0;
										}

									// Audio response to the button press.
									MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);

									// Kill sprites and get out now
									MRKill2DSprite(Game_paused_pause_sprite_ptr);
									Game_paused_pause_sprite_ptr = NULL;
									XAControl(XACOM_RESUME, 0);
									OptionClearSpcores();
									DeInitialiseHiddenMenu();
									Pause_mode = PAUSE_MODE_DEINIT;
									break;
								// ------------------------------------------------
								}
							}
						// Display the new sprite 'n' things.
						Option_spcore_index   = ( Pause_hidden_quit_selection + 3);		// So yes/no flashes.
						break;
					// ------------------------------------------------------------------------------------									
					}
				}

			GamePauseAddPrim();
			OptionUpdateSpcores();
			break;

		//-------------------------------------------------------------------
		// Kill Sprites BEFORE fading up.
		case PAUSE_MODE_KILL_SPRITES:
			// Kill "paused" sprite
			MRKill2DSprite(Game_paused_pause_sprite_ptr);
			Game_paused_pause_sprite_ptr = NULL;
			// Kill any hidden Menu Sprites that may be left around.
			DeInitialiseHiddenMenu();
			// Go on to next mode.
			Pause_mode = PAUSE_MODE_FADE_UP;
			// Add Poly to avoid flickering.
			GamePauseAddPrim();
			OptionClearSpcores();
#ifdef	PSX_ENABLE_XA
#ifdef PSX
			// Resume music
			XAControl(XACOM_RESUME,0);
#endif
#endif
			break;

		//-------------------------------------------------------------------
		// Fade up ...
		case PAUSE_MODE_FADE_UP:

			// Fade up screen
			poly_f4 = &Pause_poly[0];
			// Loop once for each poly
			for(loop_counter=0;loop_counter<2;loop_counter++)
				{
				// Set poly base colour
				poly_f4->r0 -= 0x10;
				poly_f4->g0 -= 0x10;
				poly_f4->b0 -= 0x10;
				// Next prim
				poly_f4++;
				}

			// Fade up sound volume
			if (Pause_volume >= Sound_volume)
				Pause_volume = Sound_volume;	
			else
				Pause_volume++;	

			// Turn off the Auto_Volume within the API.
			LiveEntityChangeVolume(Pause_volume, TRUE);

			// End of fade ?
			if ( Pause_poly[0].r0 == 0x00 )
				{
				// Yes ... go on to deinit
				Pause_mode = PAUSE_MODE_DEINIT;
				}

			GamePauseAddPrim();
			break;

		//-------------------------------------------------------------------
		// Deinitialise ...
		case PAUSE_MODE_DEINIT:

			// Did user select quit ?
			if (Game_paused_selection == HIDDEN_MENU_QUIT_SELECTED)
				{
				// Quit to GAME OVER.
				Option_page_request 	= OPTIONS_PAGE_GAME_OVER;
				Game_paused_selection 	= HIDDEN_MENU_QUIT_GAME;

				// Loop around any active frogs.
				frog	= &Frogs[0];
				loop	= Game_total_players;
		
				while(loop--)
					{
					frog->fr_flags &= ~FROG_CONTROL_ACTIVE;		// Remove control from players.
					frog++;									
					}
				}
			else
				Game_paused_selection = 0;

			// Flag game as unpaused
			Game_flags &= ~GAME_FLAG_PAUSED;
			// Reset pause mode
			Pause_mode = PAUSE_MODE_NO_PAUSE;
			// Reset the player that paused the game.
			Game_paused_player = -1;
			GamePauseAddPrim();
			break;
		}
}

// Cheat sequences
MR_ULONG		Sequence[] =
#ifndef	PSX_MASTER
	{ FRR_CIRCLE, FRR_CIRCLE, FRR_TRIANGLE, FRR_SQUARE, FR_ANY_BUTTON, -1 };
#else
	{ FRR_RIGHT,	FRR_SQUARE,	FRR_TRIANGLE,	FRR_SQUARE,	FRR_TRIANGLE,	-2,
	  FRR_RIGHT_1,	FRR_LEFT_1,	FRR_RIGHT_1,	FRR_LEFT_1, 				-3,
	  FRR_TRIANGLE,	FRR_SQUARE,								 				-4,
	  -1 };
#endif

MR_ULONG*		c_ptr = Sequence;

/******************************************************************************
*%%%% InitialiseHiddenMenu
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseHiddenMenu(MR_VOID)
*
*	FUNCTION	does excally what is says in the title.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/
MR_VOID	InitialiseHiddenMenu(MR_VOID)
{
	MR_TEXTURE*	texture;

	// Create "Continue" sprite
	texture = Options_text_textures[OPTION_TEXT_BIG_CONTINUE][Game_language];
	Game_paused_continue_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)+32,Option_viewport_ptr,texture,NULL);

	// Create "Quit" sprite
	texture = Options_text_textures[OPTION_TEXT_QUIT][Game_language];
	Game_paused_quit_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)+48,Option_viewport_ptr,texture,NULL);

	Pause_hidden_menu_mode = HIDDEN_MENU_CONTINUE;
	Pause_hidden_selection = HIDDEN_MENU_CONTINUE_SELECTED;
	Option_spcore_ptrs[1] = (MR_SP_CORE*)Game_paused_continue_sprite_ptr;
	Option_spcore_ptrs[2] = (MR_SP_CORE*)Game_paused_quit_sprite_ptr;
	Option_spcore_ptrs[3] = NULL;
}


/******************************************************************************
*%%%% InitialiseHiddenQuitMenu
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseHiddenQuitMenu(MR_VOID)
*
*	FUNCTION	does excally what is says in the title.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/
MR_VOID	InitialiseHiddenQuitMenu(MR_VOID)
{
	MR_TEXTURE*	texture;

	// Create "Yes" sprite
	texture = Options_text_textures[OPTION_TEXT_YES][Game_language];
	Game_paused_quit_yes_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1)+48,(Game_display_height>>1)+64,Option_viewport_ptr,texture,NULL);

	// Create "No" sprite
	texture = Options_text_textures[OPTION_TEXT_NO][Game_language];
	Game_paused_quit_no_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1)-48,(Game_display_height>>1)+64,Option_viewport_ptr,texture,NULL);

	Pause_hidden_quit_selection	= HIDDEN_MENU_QUIT_NO;
	Option_spcore_ptrs[3] = (MR_SP_CORE*)Game_paused_quit_yes_sprite_ptr;
	Option_spcore_ptrs[4] = (MR_SP_CORE*)Game_paused_quit_no_sprite_ptr;
	Option_spcore_ptrs[5] = NULL;
}

/******************************************************************************
*%%%% DeInitialiseHiddenMenu
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeInitialiseHiddenMenu(MR_VOID)
*
*	FUNCTION	does excally what is says in the title.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID	DeInitialiseHiddenMenu(MR_VOID)
{
	// Destory "continue" sprite
	if (Game_paused_continue_sprite_ptr != NULL)
		{
		MRKill2DSprite(Game_paused_continue_sprite_ptr);
		Game_paused_continue_sprite_ptr = NULL;
		}

	// Destory "quit" sprite
	if (Game_paused_quit_sprite_ptr != NULL)
		{
		MRKill2DSprite(Game_paused_quit_sprite_ptr);
		Game_paused_quit_sprite_ptr = NULL;
		}

	// Destory "quit yes" sprite
	if (Game_paused_quit_yes_sprite_ptr != NULL)
		{
		MRKill2DSprite(Game_paused_quit_yes_sprite_ptr);
		Game_paused_quit_yes_sprite_ptr = NULL;
		}

	// Destory "quit no" sprite
	if (Game_paused_quit_no_sprite_ptr != NULL)
		{
		MRKill2DSprite(Game_paused_quit_no_sprite_ptr);
		Game_paused_quit_no_sprite_ptr = NULL;
		}

	Pause_hidden_menu_mode = HIDDEN_MENU_WAITING;
}

/******************************************************************************
*%%%% UpdateControllerInputFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateControllerInputFlags(MR_VOID)
*
*	FUNCTION	Used to update the controller input flags
*	MATCH		https://decomp.me/scratch/w5Vx6	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.08.97	Gary Richards	Created
*	10.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID UpdateControllerInputFlags(MR_VOID)
{
    MR_ULONG i;

    for (i=0; i<8; i++)
        Cached_states[i] = MRInput[i].in_flags;
}

/******************************************************************************
*%%%% CheckJoyPadStillPresent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CheckJoyPadStillPresent(MR_VOID)
*
*	FUNCTION	Used to check that no joypads have been removed, if so throws the 
*				game into Pause Mode.
*
*	MATCH		https://decomp.me/scratch/TWMJQ	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.08.97	Gary Richards	Created
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	CheckJoyPadStillPresent(MR_VOID)
{
	FROG*		frog;
	MR_LONG		loop;
	MR_TEXTURE*	texture;
	MR_BOOL		show_warning;

	// Handle control and movement
	frog	= &Frogs[0];
	loop	= Game_total_players;
	texture	= NULL;		

	show_warning = FALSE;
	while(loop--)
		{
		// Check to see if the current controller has been removed
		if (MRInput[frog->fr_input_id].in_flags != Cached_states[frog->fr_input_id])
			{

			// Someone unplugged their controller
			show_warning = TRUE;

			// Check that game is not ALREADY pause.
			if (!(Game_flags & GAME_FLAG_PAUSED))
				{
				// Flag game as paused
				Game_flags |= GAME_FLAG_PAUSED;
				// Go on to pause init
				Pause_mode = PAUSE_MODE_INIT;
				// Store the player number that Un-plugged.
				Game_paused_player = frog->fr_input_id;
				}
			}
		frog++;
		}

	if (show_warning == TRUE)
		{
		if (Game_paused_insert_pad_sprite_ptr == NULL)
			{
			texture = Options_text_textures[OPTION_TEXT_INSERT_PAD][Game_language];
			Game_paused_insert_pad_sprite_ptr = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w >> 1),
																 (Game_display_height>>1)-48,
																 Option_viewport_ptr,
																 texture,
																 NULL);
			}
		}
	else
		{
		// Kill "insert_pad" sprite
		if (Game_paused_insert_pad_sprite_ptr != NULL)
			{
			MRKill2DSprite(Game_paused_insert_pad_sprite_ptr);
			Game_paused_insert_pad_sprite_ptr = NULL;
			}
		}
	
}

/******************************************************************************
*%%%% GamePauseAddPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GamePauseAddPrim(MR_VOID)
*
*	FUNCTION	Used to add the fade prims to the viewport for pause mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID GamePauseAddPrim(MR_VOID)
{
	// Add prims to display
	addPrim(Option_viewport_ptr->vp_work_ot + 2, &Pause_poly[MRFrame_index]);
	addPrim(Option_viewport_ptr->vp_work_ot + 2, &Pause_poly2[MRFrame_index]);
}


/******************************************************************************
*%%%% GamePauseCreateFadePoly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GamePauseCreateFadePoly(MR_VOID)
*
*	FUNCTION	Creates the Fade poly for the PAUSE mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID GamePauseCreateFadePoly(MR_VOID)
{
	MR_LONG		i;
	POLY_F4*	poly_f4;


	poly_f4 = &Pause_poly[0];
	for (i = 0; i < 2; i++)
		{
		// Set poly code
		setPolyF4(poly_f4);
		setSemiTrans(poly_f4, 1);

		// Set poly position
		poly_f4->x0 = 0;
		poly_f4->y0 = 0;
		poly_f4->x1 = Game_display_width;
		poly_f4->y1 = 0;
		poly_f4->x2 = 0;
		poly_f4->y2 = Game_display_height;
		poly_f4->x3 = Game_display_width;
		poly_f4->y3 = Game_display_height;

		// Set poly base colour
		poly_f4->r0 = 0x00;
		poly_f4->g0 = 0x00;
		poly_f4->b0 = 0x00;
		poly_f4++;
		}

	SetupABRChangeFT3(&Pause_poly2[0], 2);
	SetupABRChangeFT3(&Pause_poly2[1], 2);
}

/******************************************************************************
*%%%% GameCheatModeCheck(MR_VOID)
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCheatModeCheck(MR_VOID)
*
*	FUNCTION	Searches for Cheat Mode and acts occordling.
*
*	MATCH		https://decomp.me/scratch/G3U0W	(By Kneesnap & Gillou68310)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.08.97	Gary Richards	Created
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID GameCheatModeCheck(MR_VOID)
{

	// Check too see if ANY buttons where pressed.
	if (!MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_ANY_BUTTON))
		return;

	if ((*c_ptr == -2) || (*c_ptr == -3) || (*c_ptr == -4))
		{
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_CROSS) && (*c_ptr == -2))
			{ 
			GameCheatModeToggleInfiniteLives();
			c_ptr = Sequence;
			return;
			}
		else if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_CIRCLE) && (*c_ptr == -3))
			{
			GameCheatModeUnlockAllZones();
			c_ptr = Sequence;
			return;
			}
		else if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN) && (*c_ptr == -4))
			{
			GameCheatModeUnlockAllLevels();
			c_ptr = Sequence;
			return;
			}
		
		c_ptr++;
		}

	// A button was pressed, check to see if it's one we want.
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], *c_ptr))
		c_ptr++;
	else
		{
		// Not one we want, so reset the sequence.
		c_ptr = Sequence;
		}
}

/******************************************************************************
*%%%% GameCheatModeToggleInfiniteLives(MR_VOID)
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCheatModeToggleInfiniteLives(MR_VOID)
*
*	FUNCTION	Toggles the infinite lives cheat.
*
*	MATCH		https://decomp.me/scratch/1ZwiO	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID GameCheatModeToggleInfiniteLives(MR_VOID)
{
	MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
	if (Cheat_infinite_lives_toggle == TRUE)
		{
		DisplayHUDHelp(0, HUD_ITEM_HELP_INFINITE_LIVES_OFF, 0, TRUE);
		Hud_item_help_flags[0][HUD_ITEM_HELP_INFINITE_LIVES_OFF] = 0;
		Cheat_infinite_lives_toggle = FALSE;
		}
	else
		{
		DisplayHUDHelp(0, HUD_ITEM_HELP_INFINITE_LIVES_ON, 0, TRUE);
		Hud_item_help_flags[0][HUD_ITEM_HELP_INFINITE_LIVES_ON] = 0;
		Cheat_infinite_lives_toggle = TRUE;
		}
}

/******************************************************************************
*%%%% GameCheatModeUnlockAllZones(MR_VOID)
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCheatModeUnlockAllZones(MR_VOID)
*
*	FUNCTION	Unlocks all zones on the level stack.
*
*	MATCH		https://decomp.me/scratch/2Dqo3	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID GameCheatModeUnlockAllZones(MR_VOID)
{
	MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
	DisplayHUDHelp(0, HUD_ITEM_HELP_ALL_ZONES_OPEN, 0, TRUE);

	// Unlock cave
	SelectSetLevelFlags(LEVEL_CAVES1, (SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE));
	GameCheatModeUnlockLevelZone(LEVEL_CAVES3);
	GameCheatModeUnlockLevelZone(LEVEL_CAVES4);

	// Unlock sky
	SelectSetLevelFlags(LEVEL_SKY1, (SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE));
	GameCheatModeUnlockLevelZone(LEVEL_SKY2);
	GameCheatModeUnlockLevelZone(LEVEL_SKY3);
	GameCheatModeUnlockLevelZone(LEVEL_SKY4);

	// Unlock sewer
	SelectSetLevelFlags(LEVEL_SWAMP1, (SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE));
	GameCheatModeUnlockLevelZone(LEVEL_SWAMP2);
	GameCheatModeUnlockLevelZone(LEVEL_SWAMP3);
	GameCheatModeUnlockLevelZone(LEVEL_SWAMP4);
	GameCheatModeUnlockLevelZone(LEVEL_SWAMP5);

	// Unlock desert
	SelectSetLevelFlags(LEVEL_DESERT1, (SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE));
	GameCheatModeUnlockLevelZone(LEVEL_DESERT2);
	GameCheatModeUnlockLevelZone(LEVEL_DESERT3);
	GameCheatModeUnlockLevelZone(LEVEL_DESERT4);
	GameCheatModeUnlockLevelZone(LEVEL_DESERT5);

	// Unlock jungle
	SelectSetLevelFlags(LEVEL_JUNGLE1, (SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE));
}

/******************************************************************************
*%%%% GameCheatModeUnlockAllLevels(MR_VOID)
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCheatModeUnlockAllLevels(MR_VOID)
*
*	FUNCTION	Unlocks all levels on the level stack.
*
*	MATCH		https://decomp.me/scratch/p7fQ1	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID GameCheatModeUnlockAllLevels(MR_VOID)
{
	SEL_LEVEL_INFO* sel_level_info_ptr;

	// Show info and play sound
	MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
	DisplayHUDHelp(0, HUD_ITEM_HELP_ALL_LEVELS_OPEN, 0, TRUE);

	// Unlock levels
	sel_level_info_ptr = Sel_arcade_levels;
	while (sel_level_info_ptr->li_library_id != -1)
		{
		SelectSetLevelFlags(sel_level_info_ptr->li_library_id, SelectGetLevelFlags(sel_level_info_ptr->li_library_id) | SEL_LF_ZONEACCESSIBLE | SEL_LF_SELECTABLE);
		sel_level_info_ptr++;
		}
}

/******************************************************************************
*%%%% GameModeCheatUnlockLevelZone(MR_ULONG)
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCheatModeUnlockLevelZone(
											MR_ULONG	level_id)
*
*	FUNCTION	Marks a level as having its zone unlocked.
*
*	MATCH		https://decomp.me/scratch/jaaYv	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID GameCheatModeUnlockLevelZone(MR_ULONG level_id)
{
	if (!(SelectGetLevelFlags(level_id) & SEL_LF_SELECTABLE))
		SelectSetLevelFlags(level_id, SEL_LF_ZONEACCESSIBLE);
}
													  
