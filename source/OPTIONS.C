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


OPTION_PAGE		Option_page_info[] =
				{
				{NULL,								NULL,								NULL },
				{VersionStartup,					VersionUpdate,						VersionShutdown},
#ifdef PSX
				{AntiPiracyStartup,					AntiPiracyUpdate,					AntiPiracyShutdown},
#endif
				{HasbroLogoStartup,					HasbroLogoUpdate,					HasbroLogoShutdown},
				{MillenniumLogoStartup,				MillenniumLogoUpdate,				MillenniumLogoShutdown},
				{LanguageSelectionStartup,			LanguageSelectionUpdate,			LanguageSelectionShutdown},
				{CheckStartup,						CheckUpdate,						CheckShutdown},
				{IntroStartup,						IntroUpdate,						IntroShutdown},
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
				{ContinueStartup,					ContinueUpdate,						ContinueShutdown},
				{GameOverStartup,					GameOverUpdate,						GameOverShutdown},
				{OutroStartup,						OutroUpdate,						OutroShutdown},
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
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Dean Ashton		Created
*	26.08.97	Gary Richards	Moved start-up code to CreateOptionsAfterStream.
*
*%%%**************************************************************************/

MR_BOOL	OptionStart(MR_VOID)
{
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
			VSync(2);
			MRSwapDisplay();
#endif			
			// Free any prims left over
			FreePrims();

			// Read input and sound
			MRReadInput();
			GameUpdateControllers();
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

	MRKill2DSprite(Sel_level_title);
	MRKill2DSprite(Sel_loading_sprite_ptr);

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
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.08.97	Gary Richards	Created
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

	// Create loading sprites ready for use!
	Sel_level_title	= MRCreate2DSprite(0, 0, Option_viewport_ptr, &im_opt_start, NULL);
	Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
	Sel_loading_sprite_ptr = MRCreate2DSprite(0, 0, Option_viewport_ptr, &im_opt_race, NULL);
	Sel_loading_sprite_ptr->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

	Game_total_viewports	= 1;
	Game_viewports[0] 		= Option_viewport_ptr;

	InitialiseOptionsCamera();
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
*
*%%%**************************************************************************/

MR_VOID	KillOptionsForStream(MR_VOID)
{
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
