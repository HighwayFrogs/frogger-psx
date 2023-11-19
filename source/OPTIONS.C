/******************************************************************************
*%%%% options.c
*------------------------------------------------------------------------------
*
*	Options Processing
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#include "options.h"
#include "sprdata.h"
#include "project.h"
#include "tempopt.h"
#include "select.h"
#include "gamesys.h"
#include "hsview.h"
#include "hsinput.h"
#include "credits.h"
#include "loadsave.h"
#include "main.h"
#include "sound.h"
#include "ent_gen.h"


OPTION_PAGE		Option_page_info[] =
				{
				{NULL,								NULL,								NULL },
				{VersionStartup,					VersionUpdate,						VersionShutdown},
#ifdef PSX
				{AntiPiracyStartup,					AntiPiracyUpdate,					AntiPiracyShutdown},
#endif
				{NULL,								HasbroLogoUpdate,					NULL},
				{NULL,								MillenniumLogoUpdate,				NULL},
				{LanguageSelectionStartup,			LanguageSelectionUpdate,			LanguageSelectionShutdown},
				{CheckStartup,						CheckUpdate,						CheckShutdown},
				{IntroStartup,						IntroUpdate,						NULL},
				{MainOptionsStartup,				MainOptionsUpdate,					MainOptionsShutdown},
				{OptionsStartup,					OptionsUpdate,						OptionsShutdown},
#ifdef WIN95
				{MultiplayerModeOptionsStartup,		MultiplayerModeOptionsUpdate,		MultiplayerModeOptionsShutdown},
				{NetworkTypeOptionsStartup,			NetworkTypeOptionsUpdate,			NetworkTypeOptionsShutdown},
				{NetworkHostOptionsStartup,			NetworkHostOptionsUpdate,			NetworkHostOptionsShutdown},
				{NetworkPlayOptionsStartup,			NetworkPlayOptionsUpdate,			NetworkPlayOptionsShutdown},
#endif
				{FrogSelectionStartup,				FrogSelectionUpdate,				FrogSelectionShutdown},
//				{FrogSelectionStartup,				FrogSelectionNetworkUpdate,			FrogSelectionShutdown},

				{SelectLevelStartup,				SelectLevelUpdate,					SelectLevelShutdown},
				{NULL,								ContinueUpdate,						ContinueShutdown},
				{GameOverStartup,					GameOverUpdate,						GameOverShutdown},
				{NULL,								OutroUpdate,						NULL},
				{CreditsStartup,					CreditsUpdate,						CreditsShutdown},
				{HighScoreInputStartup,				HighScoreInputUpdate,				HighScoreInputShutdown},
				{HSViewStartup,						HSViewUpdate,						HSViewShutdown},
				{SaveStartup,						SaveUpdate,							SaveShutdown},
				{LoadStartup,						LoadUpdate,							LoadShutdown},
#ifdef PSX		// PSX Specific code ----------------------------------------
				{RedefinePSXButtonsStartup,			RedefinePSXButtonsUpdate,			RedefinePSXButtonsShutdown},
#else			// WIN95 Specific code --------------------------------------
				{ChooseWINControllerStartup,		ChooseWINControllerUpdate,			ChooseWINControllerShutdown},
#endif			// PSX
				{GameStart,							GameMainloop,						NULL},
				{LevelCompleteStartup,				LevelCompleteUpdate,				LevelCompleteShutdown},
				{ShowWaterStartup,					ShowWaterUpdate,					ShowWaterShutdown},
				{PlayAgainStartup,					PlayAgainUpdate,					PlayAgainShutdown},
				};

MR_LONG			Option_page_current;
MR_LONG			Option_page_request;

MR_VIEWPORT*	Option_viewport_ptr;
MR_FRAME*		Option_camera_ptr;

MR_LONG			Option_level_number = OPTION_MIN_LEVEL;

PRIM_PACKET		Option_prim_packets[OPTION_NUM_PRIM_PACKETS];

MR_SP_CORE*		Option_spcore_ptrs[OPTION_MAX_SPCORES + 1];
MR_LONG			Option_spcore_index;
MR_LONG			Option_spcore_value;


/******************************************************************************
*%%%% OptionStart
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionStart(MR_VOID)
*
*	FUNCTION	Main entry point for Frogger options screens. After creation
*				of the required viewports, this routine passes control to
*				a page-based system of callbacks (controlling options page
*				initialisation, main loop functionality, and shutdown).
*	MATCH		https://decomp.me/scratch/uyNFW (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Dean Ashton		Created
*	26.08.97	Gary Richards	Moved start-up code to CreateOptionsAfterStream.
*	30.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_BOOL	OptionStart(MR_VOID)
{
	MR_LONG vsync_mode;
	CreateOptionsAfterStream();
	
	Option_page_request 	= NULL;

	do 	{
		// Process page startup callback
#ifdef OPTIONS_SHOW_MEM
		MRShowMem(NULL);
#endif
		OptionClearSpcores();
		if (Option_page_info[Option_page_current].op_callback_startup)
			(Option_page_info[Option_page_current].op_callback_startup)();

		while (Option_page_request == NULL)
			{
#ifdef PSX
//			FASTSTACK;
#endif
#ifdef WIN95	
			MRClearAllViewportOTs();
#else			
			DrawSync(0);
			if (Game_total_players >= 3) {
				vsync_mode = 2;
				if (Option_page_current == 0x15)
					vsync_mode = 3;
			} else {
				vsync_mode = 2;
			}
			VSync(vsync_mode);
	  
			MRSwapDisplay();
#endif			
			// Free any prims left over
			FreePrims();

			// Read input and sound
			MRReadInput();
			MRSNDUpdateSound();

#ifdef PSX_ENABLE_XA
#ifdef PSX
			XAUpdate();
#endif
#endif	// PSX_ENABLE_XA

#ifdef DEBUG
			MRStartGatso();
#endif
			// Process page update callback
			if (Option_page_info[Option_page_current].op_callback_update)
				(Option_page_info[Option_page_current].op_callback_update)();

			// Update glowing options sprites
			OptionUpdateSpcores();

			if (Game_running == FALSE)
				{
				MRUpdateFrames();
				MRUpdateObjects();
				MRAnimUpdateEnvironments();
				MRUpdateMeshesAnimatedPolys();
				MRUpdateViewportRenderMatrices();
				}

			MRUpdateViewport2DSpriteAnims(Option_viewport_ptr);
			MRRenderViewport(Option_viewport_ptr);
			MRUpdateViewportMeshInstancesAnimatedPolys(Option_viewport_ptr);
			RenderEffects();
#ifdef PSX
#ifdef DEBUG
			MRStopGatso();
			ProgressMonitor();
#endif
#endif

#ifdef WIN95	//-win95 specific---------------------------------------------
			MRSwapDisplay();
			MRProcessWindowsMessages(NULL);				

			if (MR_KEY_DOWN(MRIK_ESCAPE))
				Option_page_request = OPTIONS_PAGE_EXIT;

			// Network code
			if (MNIsNetGameRunning())
				MNReceiveMessages();
#endif			//-end of specific code---------------------------------------
#ifdef PSX
//			SLOWSTACK;
#endif
			}

		// Process page shutdown callback
		if (Option_page_info[Option_page_current].op_callback_shutdown)
			(Option_page_info[Option_page_current].op_callback_shutdown)();

		Option_page_current = Option_page_request;
		Option_page_request = NULL;

		} while (Option_page_current != OPTIONS_PAGE_EXIT);

	KillOptionsTextSprites();
	MRKillViewport(Option_viewport_ptr);
	return TRUE;
}

/******************************************************************************
*%%%% FreePrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FreePrims(MR_VOID)
*
*	FUNCTION	Free memory used to hold prims after count has reached zero.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	FreePrims(MR_VOID)
{

	// Locals
	MR_ULONG		i;
	PRIM_PACKET*	packet_ptr;

	// Set up count
	i = OPTION_NUM_PRIM_PACKETS;

	// Get pointer to first packet
	packet_ptr = &Option_prim_packets[0];

	// Loop once for each prim packet
	while ( i -- )
		{
		// Is this packet active ?
		if ( packet_ptr->pp_flags & PRIM_PACKET_FLAG_ACTIVE )
			{
			// Yes ... dec count
			packet_ptr->pp_count--;
			// Has count reach 0 ?
			if ( !packet_ptr->pp_count )
				{
				// Yes ... free memory
				MRFreeMem(packet_ptr->pp_prim_adr);
				// Flag packet as inactive
				packet_ptr->pp_flags = 0;
				}
			}
		// Next packet
		packet_ptr++;
		}

}

/******************************************************************************
*%%%% InitialisePrimFree
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialisePrimFree(MR_UBYTE* prim_adr)
*
*	FUNCTION	Set up a free of prims.
*
*	INPUTS		prim_adr		- Pointer to prim block to free.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID InitialisePrimFree(MR_UBYTE* prim_adr)
{

	// Locals
	MR_ULONG		i;
	PRIM_PACKET*	packet_ptr;

	MR_ASSERT(prim_adr);

	// Get pointer to first packet
	packet_ptr = &Option_prim_packets[0];

	// Initialise count
	i = 0;

	// Loop once for each packet
	while ( (packet_ptr->pp_flags & PRIM_PACKET_FLAG_ACTIVE) && (i < OPTION_NUM_PRIM_PACKETS) )
		{
		// Inc count
		i++;
		// Next packet
		packet_ptr++;
		}

	// Assert if no free packets remaining
	MR_ASSERT(i!=OPTION_NUM_PRIM_PACKETS);

	// Initialise packet
	packet_ptr->pp_flags = PRIM_PACKET_FLAG_ACTIVE;
	packet_ptr->pp_prim_adr = prim_adr;
	packet_ptr->pp_count = 3;

}


/******************************************************************************
*%%%% ClearOptions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ClearOptions(MR_VOID)
*
*	FUNCTION	Unload options resources, clear viewport OTs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ClearOptions(MR_VOID)
{
//	MRClearViewportOT(Option_viewport_ptr);
	UnloadOptionsResources();
}


/******************************************************************************
*%%%% OptionClearSpcores
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionClearSpcores(MR_VOID)
*
*	FUNCTION	Clear out all MR_SP_CORE*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionClearSpcores(MR_VOID)
{
	MR_SP_CORE**	spcore_pptr;
	MR_LONG			i;


	spcore_pptr = Option_spcore_ptrs;
	i			= OPTION_MAX_SPCORES + 1;
	while(i--)
		*spcore_pptr++ = NULL;		

	Option_spcore_index = 0;		// selected index
	Option_spcore_value = 0x60;		// brightness
}


/******************************************************************************
*%%%% OptionUpdateSpcores
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionUpdateSpcores(MR_VOID)
*
*	FUNCTION	Update all MR_SP_CORE*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionUpdateSpcores(MR_VOID)
{
	MR_SP_CORE**	spcore_pptr;
	MR_SP_CORE*		spcore;
	MR_LONG			v;


	spcore_pptr = Option_spcore_ptrs;
	while(spcore = *spcore_pptr)
		{
		v = Option_spcore_value;
		spcore->sc_base_colour.r = v;
		spcore->sc_base_colour.g = v;
		spcore->sc_base_colour.b = v;
		spcore_pptr++;
		}

	if (Option_spcore_index >= 0)
		{
		// Glow
		v 		= (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
		spcore 	= Option_spcore_ptrs[Option_spcore_index];

		// $mk must check its VALID!!!
		if (spcore)
			{
			spcore->sc_base_colour.r = v;
			spcore->sc_base_colour.g = v;
			spcore->sc_base_colour.b = v;
			}
		}
}

/******************************************************************************
*%%%% CreateOptionsAfterStream
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreateOptionsAfterStream(MR_VOID)
*
*	FUNCTION	Restores the viewports etc after it has been killed by the stream.
*	MATCH		https://decomp.me/scratch/dxG2c (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.08.97	Gary Richards	Created
*	30.10.23	Kneesnap		Byte-matched to PSX Build 71. (Retail NTSC Build)
*
*%%%**************************************************************************/
MR_VOID CreateOptionsAfterStream(MR_VOID)
{
	MR_VEC		vec;
	MR_OBJECT*	light0;
	MR_OBJECT*	light1;
	MR_FRAME*	frame1;

	Option_viewport_ptr = MRCreateViewport(NULL, NULL, MR_VP_SIZE_4096, 1);
	MRSetViewportViewDistance(Option_viewport_ptr, MR_VP_VIEWDIST_32768);

	// Create camera for options to stop windows from crashing
	MR_SET_VEC(&vec, 0, 0, -2144);
	Option_camera_ptr = MRCreateFrame(&vec, &Null_svector, 0);
	MRPointMatrixAtVector(&Option_camera_ptr->fr_matrix, &Null_vector, &Game_y_axis_pos);
	MRSetViewportCamera(Option_viewport_ptr, Option_camera_ptr);

	// Set up API lights for options pages
	light0 = MRCreateLight(MR_LIGHT_TYPE_AMBIENT, 0x606060, NULL, MR_OBJ_STATIC);
	MRAddObjectToViewport(light0, Option_viewport_ptr, NULL);

	MR_SET_VEC(&vec, 0x800, -0x1000, -0x1000);
	frame1 = MRCreateFrame(&vec, &Null_svector, 0);
	MRPointMatrixAtVector(&frame1->fr_matrix, &Null_vector, &Game_y_axis_pos);
	light1 = MRCreateLight(MR_LIGHT_TYPE_PARALLEL, 0xa0a0c0, frame1, NULL);
	light1->ob_flags |= MR_OBJ_KILL_FRAME_WITH_OBJECT;
	MRAddObjectToViewport(light1, Option_viewport_ptr, NULL);

	SetupOptionTextSprites();
	Game_total_viewports	= 1;
	Game_viewports[0] 		= Option_viewport_ptr;

	InitialiseOptionsCamera();
	HSUpdateScrollyCamera();
}

/******************************************************************************
*%%%% KillOptionsForStream
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillOptionsForStream(MR_VOID)
*
*	FUNCTION	Kill all the viewports etc in order to create a 24bit screen
*				so that the streams look nicer.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.08.97	Gary Richards	Created
*	30.10.23	Kneesnap		Byte-matched to PSX Build 71. (Retail NTSC Build)
*
*%%%**************************************************************************/

MR_VOID	KillOptionsForStream(MR_VOID)
{
	// Kill option text sprites
	KillOptionsTextSprites();
	
	// Remove the Active Viewport.
	MRKillViewport(Option_viewport_ptr);
	Option_viewport_ptr = NULL;

	// Kill the camera frames and 
	MRKillFrame(Option_camera_ptr);
	Option_camera_ptr = NULL;

	// Kill the Display.
	MRKillDisplay();
}


/******************************************************************************
*%%%% OptionKill3DSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionKill3DSprites(MR_VOID)
*
*	FUNCTION	Kill all API 3D sprites
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionKill3DSprites(MR_VOID)
{
	MR_OBJECT*	object_ptr;


	object_ptr = MRObject_root_ptr;
 	while(object_ptr = object_ptr->ob_next_node)
		{
		if (object_ptr->ob_type == MR_OBJTYPE_3DSPRITE)
			object_ptr->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
}

/******************************************************************************
*%%%% SetupOptionTextSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetupOptionTextSprites(MR_VOID)
*
*	FUNCTION	Sets up most of the options text sprites
*	MATCH		https://decomp.me/scratch/dIJW3	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID SetupOptionTextSprites(MR_VOID)
{
	MR_LONG			i, y;
	MR_2DSPRITE**	sprite_pptr;
	MR_TEXTURE*		texture;

	// Setup basic text graphics
	Sel_level_title = MRCreate2DSprite(0, 0, Option_viewport_ptr, &im_opt_start, NULL);
	MakeSpriteInvisible(Sel_level_title);
	Sel_loading_sprite_ptr = MRCreate2DSprite(0, 0, Option_viewport_ptr, &im_opt_race, NULL);
	MakeSpriteInvisible(Sel_loading_sprite_ptr);
	
	// Create hud checkpoint graphics
	y	= (Game_display_height>>1) - 70;
	for (i=0; i<GEN_MAX_CHECKPOINTS; i++)
		{
		Level_complete.Level_complete_checkpoints[i]	= MRCreate2DSprite((Game_display_width>>1)-105, y, Option_viewport_ptr, Hud_checkpoint_animlists[i], NULL);
		MakeSpriteInvisible(Level_complete.Level_complete_checkpoints[i]);
		y += 20;
		}

	// Create hud checkpoint time graphics
	y			= (Game_display_height>>1) - 70;
	for (i=0; i<GEN_MAX_CHECKPOINTS; i++)
		{
		Level_complete.Level_complete_checkpoint_time[i] = MRAllocMem(sizeof(MR_2DSPRITE*) * 3, "CHKPOINT PTR");
		sprite_pptr		= (MR_2DSPRITE**)Level_complete.Level_complete_checkpoint_time[i];

		MakeSpriteInvisible(*sprite_pptr++	= MRCreate2DSprite(	(Game_display_width>>1) -84, y, Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL));
		MakeSpriteInvisible(*sprite_pptr++	= MRCreate2DSprite(	(Game_display_width>>1) -68, y, Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL));
		texture = Options_text_textures[OPTION_TEXT_SEC][Game_language];
		MakeSpriteInvisible(*sprite_pptr++	= MRCreate2DSprite(	(Game_display_width>>1) -52, y, Option_viewport_ptr, texture, NULL));
		y += 20;
		}
	
	Level_complete.Level_complete_total_time_text = MRCreate2DSprite((Game_display_width >> 1)-16, (Game_display_height>>1)-60, Option_viewport_ptr, Options_text_textures[OPTION_TEXT_TOTAL_TIME][Game_language], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_time_text);
	
	Level_complete.Level_complete_total_time[0] = MRCreate2DSprite((Game_display_width>>1)+10, (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[7]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_time[0]);
	
	Level_complete.Level_complete_total_time[1] = MRCreate2DSprite((Game_display_width>>1)+26, (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_time[1]);
	
	Level_complete.Level_complete_total_time[2] = MRCreate2DSprite((Game_display_width>>1)+42, (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_time[2]);

	texture = Options_text_textures[OPTION_TEXT_SEC][Game_language];
	Level_complete.Level_complete_total_time[3] = MRCreate2DSprite((Game_display_width>>1)+58, (Game_display_height>>1)-40, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_time[3]);

	Level_complete.Level_complete_total_score_text = MRCreate2DSprite((Game_display_width>>1)-26, (Game_display_height>>1)-15, Option_viewport_ptr, Options_text_textures[OPTION_TEXT_TOTAL_SCORE][Game_language], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score_text);
	
	Level_complete.Level_complete_total_score[0] = MRCreate2DSprite((Game_display_width>>1)-10, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[4]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[0]);
	
	Level_complete.Level_complete_total_score[1] = MRCreate2DSprite((Game_display_width>>1)+6, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[5]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[1]);
	
	Level_complete.Level_complete_total_score[2] = MRCreate2DSprite((Game_display_width>>1)+22, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[6]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[2]);
	
	Level_complete.Level_complete_total_score[3] = MRCreate2DSprite((Game_display_width>>1)+38, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[7]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[3]);
	
	Level_complete.Level_complete_total_score[4] = MRCreate2DSprite((Game_display_width>>1)+54, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[4]);
	
	Level_complete.Level_complete_total_score[5] = MRCreate2DSprite((Game_display_width>>1)+70, (Game_display_height>>1)+5, Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_total_score[5]);

	texture = Options_text_textures[OPTION_TEXT_PRESS_FIRE][Game_language];
	Level_complete.Level_complete_next_level_des = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (((Game_display_height & 0xffff)-50) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_next_level_des);
	
	texture = Options_text_textures[OPTION_TEXT_PRESS_FIRE][Game_language];
	Level_complete.Level_complete_press_fire = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (((Game_display_height & 0xffff)-32) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_press_fire);

	Level_complete.Level_complete_next_level_text = MRCreate2DSprite(Game_display_width>>1, (((Game_display_height & 0xffff)-70) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_next_level_text);
	
	Level_complete.Level_complete_golden_frog = MRCreate2DSprite((Game_display_width>>1)-105, (Game_display_height>>1)+30, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_golden_frog);

	Level_complete.Level_complete_press_tri = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (((Game_display_height & 0xffff)-30) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Level_complete.Level_complete_press_tri);

	texture = Options_text_textures[OPTION_TEXT_START][Game_language];
	Start_ptr = MRCreate2DSprite((Game_display_width - texture->te_w)>>1, Game_display_height, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Start_ptr);

	texture = Options_text_textures[OPTION_TEXT_RACE][Game_language];
	Race_ptr = MRCreate2DSprite((Game_display_width - texture->te_w)>>1, (((Game_display_height & 0xffff)+16) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Race_ptr);

	texture = Options_text_textures[OPTION_TEXT_OPTIONS][Game_language];
	Options_ptr = MRCreate2DSprite((Game_display_width - texture->te_w)>>1, (((Game_display_height & 0xffff)+32) << 16) >> 16, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Options_ptr);
	
	texture = Options_text_textures[OPTION_TEXT_GAMEOVER][Game_language];
	Gameover_title_sprite_ptr = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (Game_display_height>>1) - (texture->te_h>>1), Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Gameover_title_sprite_ptr);
	
	SetupMultiplayerGameOverTextSprites();
}

/******************************************************************************
*%%%% SetupMultiplayerGameOverTextSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetupMultiplayerGameOverTextSprites(MR_VOID)
*
*	FUNCTION	Sets up most of the text sprites used for multiplayer game over displays
*	MATCH		https://decomp.me/scratch/rH51H (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID SetupMultiplayerGameOverTextSprites(MR_VOID)
{
	MR_LONG i;
	MR_TEXTURE* texture;
	

	// Loop once for each viewport
	for (i=0; i<4; i++)
		{
		// Create "PLAYED"/"WON"/"LOST" text headers 
		texture = Options_text_textures[OPTION_TEXT_PLAYED][Game_language]; // Previously Game_over[i]->go_played_text
		Game_over_Multiplayer_played_text[i] = MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x - ((texture->te_w>>1)+30), Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-20, Option_viewport_ptr, texture, NULL);
		MakeSpriteInvisible(Game_over_Multiplayer_played_text[i]);
		
		texture = Options_text_textures[OPTION_TEXT_WON][Game_language]; // Previously Game_over[i]->go_won_text	
		Game_over_Multiplayer_won_text[i] = MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x - ((texture->te_w>>1)+30), Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y, Option_viewport_ptr, texture, NULL);
		MakeSpriteInvisible(Game_over_Multiplayer_won_text[i]);
		
		texture = Options_text_textures[OPTION_TEXT_LOST][Game_language]; // Previously Game_over[i]->go_lost_text
		Game_over_Multiplayer_lost_text[i] = MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x - ((texture->te_w>>1)+30), Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y+20, Option_viewport_ptr, texture, NULL);
		MakeSpriteInvisible(Game_over_Multiplayer_lost_text[i]);
		}
	
	texture = Options_text_textures[OPTION_TEXT_PLAY_AGAIN][Game_language];
	Playagain_pa_sprite_ptr = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (Game_display_height>>1)-24, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Playagain_pa_sprite_ptr);
	
	texture = Options_text_textures[OPTION_TEXT_CHOOSE_COURSE][Game_language];
	Playagain_cc_sprite_ptr = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (Game_display_height>>1)-8, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Playagain_cc_sprite_ptr);
	
	texture = Options_text_textures[OPTION_TEXT_EXIT][Game_language];
	Playagain_ex_sprite_ptr = MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), (Game_display_height>>1)+8, Option_viewport_ptr, texture, NULL);
	MakeSpriteInvisible(Playagain_ex_sprite_ptr);
}


/******************************************************************************
*%%%% KillOptionsTextSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillOptionsTextSprites(MR_VOID)
*
*	FUNCTION	Kills most of the active options text sprites
*	MATCH		https://decomp.me/scratch/ra6Fx	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID KillOptionsTextSprites(MR_VOID)
{
	MR_LONG i;
	MR_2DSPRITE** sprite_pptr;

	// Kill loading text sprites
	MRKill2DSprite(Sel_level_title);
	MRKill2DSprite(Sel_loading_sprite_ptr);

	// Kill checkpoint text sprites
	for (i=0; i<5; i++)
		MRKill2DSprite(Level_complete.Level_complete_checkpoints[i]);

	// Kill complete checkpoint time text sprites
	for (i=0; i<5; i++)
		{
		sprite_pptr = Level_complete.Level_complete_checkpoint_time[i];
		MRKill2DSprite(*sprite_pptr++);
		MRKill2DSprite(*sprite_pptr++);
		MRKill2DSprite(*sprite_pptr++);
		MRFreeMem(Level_complete.Level_complete_checkpoint_time[i]);
		}
	
	// Kill total text sprites
	MRKill2DSprite(Level_complete.Level_complete_total_time_text);
	MRKill2DSprite(Level_complete.Level_complete_total_score_text);

	// Kill total time text sprites
	for (i=0; i<4; i++)
		MRKill2DSprite(Level_complete.Level_complete_total_time[i]);

	// Kill total score text sprites
	for (i=0; i<6; i++)
		MRKill2DSprite(Level_complete.Level_complete_total_score[i]);

	// Kill remaining text sprites
	MRKill2DSprite(Level_complete.Level_complete_golden_frog);
	MRKill2DSprite(Level_complete.Level_complete_press_fire);
	MRKill2DSprite(Level_complete.Level_complete_next_level_des);
	MRKill2DSprite(Level_complete.Level_complete_press_tri);
	MRKill2DSprite(Level_complete.Level_complete_next_level_text);
	MRKill2DSprite(Start_ptr);
	MRKill2DSprite(Race_ptr);
	MRKill2DSprite(Options_ptr);
	MRKill2DSprite(Gameover_title_sprite_ptr);

	// Kill game over sprites
	KillGameOverTextSprites();
}


/******************************************************************************
*%%%% KillGameOverTextSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillGameOverTextSprites(MR_VOID)
*
*	FUNCTION	Kills most of the active options text sprites
*	MATCH		https://decomp.me/scratch/EbL2E (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID KillGameOverTextSprites(MR_VOID)
{
	MR_LONG i;

	// Kill game over result text sprites
	for (i=0; i<4; i++)
		{
		MRKill2DSprite(Game_over_Multiplayer_played_text[i]);
		MRKill2DSprite(Game_over_Multiplayer_won_text[i]);
		MRKill2DSprite(Game_over_Multiplayer_lost_text[i]);
		}

	// Kill game over action text sprites
	MRKill2DSprite(Playagain_pa_sprite_ptr);
	MRKill2DSprite(Playagain_cc_sprite_ptr);
	MRKill2DSprite(Playagain_ex_sprite_ptr);
}

/******************************************************************************
*%%%% UpdateSpriteDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateSpriteDisplay(
*											MR_2DSPRITE*	sprite,
*											MR_TEXTURE*		texture,
*											MR_SHORT		x,
*											MR_SHORT		y)
*
*	FUNCTION	Updates the provided sprite.
*	MATCH		https://decomp.me/scratch/DHu9s (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID UpdateSpriteDisplay(MR_2DSPRITE *sprite, MR_TEXTURE *texture, MR_SHORT x, MR_SHORT y)
{
    MRChangeSprite(sprite, texture);
    sprite->sp_pos.x = x;
    sprite->sp_pos.y = y;
    sprite->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
}

/******************************************************************************
*%%%% MakeSpriteVisible
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MakeSpriteVisible(
*										MR_2DSPRITE*	sprite)
*
*	FUNCTION	Updates the provided sprite.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID MakeSpriteVisible(MR_2DSPRITE *sprite)
{
    sprite->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
}


/******************************************************************************
*%%%% MakeSpriteInvisible
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MakeSpriteInvisible(
*									MR_2DSPRITE*	sprite)
*
*	FUNCTION	Updates the provided sprite.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.10.23	Kneesnap		Byte-matching decompilation from PSX Build 71 (Retail NTSC).
*
*%%%**************************************************************************/

MR_VOID MakeSpriteInvisible(MR_2DSPRITE *sprite)
{
    sprite->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
}


