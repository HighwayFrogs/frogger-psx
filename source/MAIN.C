/******************************************************************************
*%%%% main.c
*------------------------------------------------------------------------------
*
*	Frogger Project (PlayStation)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	10.04.97	Dean Ashton		Created
*	28.04.97	Martin Kift		Added lots of windows code
*	01.05.97	Martin Kift		Had to ifdef out the 'stream.h' include call
*	08.05.97	Martin Kift		Moved most of the init win95 code over into
*								main(), alongside the psx code.Easier to update.
*	20.06.97	Martin Kift		Added win95 network code.
*
*%%%**************************************************************************/

#include "main.h"
#include "gamesys.h"
#include "library.h"
#include "mapview.h"
#include "frog.h"
#include "path.h"
#include "sound.h"
#include "options.h"
#ifdef PSX
#include "stream.h"
#endif
#include "select.h"
#include "gamefont.h"
#include "model.h"
#include "tempopt.h"
#include "hsinput.h"


//---- System RAM and Stack definitions --------

#ifdef PSX_RELEASE
MR_ULONG	_ramsize 	= 0x00200000;				// 2Mb of Main RAM (as in consumer machine)
#else
MR_ULONG	_ramsize 	= 0x00262c00;				// 3Mb of Main RAM (for debug)
#endif

MR_ULONG	_stacksize 	= 0x02000;					// 8k Stack should be plenty!			


//---- Globals, other bits of stuff --------
					
MR_VEC		Null_vector 	= {0,0,0};
MR_SVEC		Null_svector	= {0,0,0,0};
													 
MR_STRPTR			Version_text[4][25]=
	{
#ifdef PSX
	{"%jcFROGGER",NULL},
	{"%jcCOMPILED: 12:19",NULL},
#ifdef BUILD_49
	{"%jcBUILD: 49",NULL},
#else
	{"%jcBUILD: 50",NULL},
#endif
	{"%jc03/09/97",NULL},
#else
	{"%jcFROGGER WINDOWS",NULL},
	{"%jcCOMPILED: 14:00",NULL},
	{"%jcBUILD: 2",NULL},
	{"%jc06/08/97",NULL},
#endif
	};

#ifdef WIN95
MR_BOOL				Main_load_specific_level = FALSE;		// Load a specific level requested?
MR_LONG				Main_load_number_players = 1;			// Load with a specific number of players
MR_TIMER_EVENT*		Main_frame_rate_timer;					// Pointer to timer
volatile MR_LONG	Main_frame_count=0;						// Number of frames processed
volatile MR_LONG	Main_global_frame_count=0;				// Global frame count

char				Main_cmd_line[255];						// Command line
MR_DISP_DATA*		Main_display_data;						// Data about main display

char				Main_win95_cd_drive;					// CD Drive id
#ifdef MR_DEBUG
MR_LONG				Main_screen_resolution;			// Requested screen res
MR_BOOL				Main_screen_clear;				// Screen Clear Flag
MR_LONG				Main_screen_widths[] = 
							{ 640, 512, 640, 320, 320 };
MR_LONG				Main_screen_heights[] = 
							{ 480, 384, 400, 240, 200 };

#endif	// MR_DEBUG
#endif	// WIN95

MR_BOOL				Cheat_control_toggle 		= FALSE;	// Are we in cheat mode or not.
MR_BOOL				Cheat_collision_toggle 		= FALSE;	// Is collision bypass cheat ON ?????
MR_BOOL				Cheat_time_toggle			= FALSE;	// Time limit running ??
MR_BOOL				Cheat_infinite_lives_toggle = FALSE;	// Infinite lives on ??

/******************************************************************************
*%%%% main
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	main(MR_VOID)
*
*	FUNCTION	Startup function for project
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.04.94	Dean Ashton		Created
*	08.05.95	Martin Kift		On the request of Tim, I've moved all the 
*								main windows code into here, on IFDEF's obviously
*
*%%%**************************************************************************/

MR_VOID	main(MR_VOID)
{			
#ifdef WIN95	//-windows specific code-------------------------------------------------------
	MR_ULONG	count;
	
	InitialiseWIN95();								// Perform machine initialisation 
#else			//-psx specific code-----------------------------------------------------------
	ResetGraph(0);
	InitialisePSX();		 						// Perform machine initialisation 

	// Print initial RAM information
	printf("----------------\n");
	printf("Code: %ld Kb\n", (__textlen/1024));
	printf("Data: %ld Kb\n", (__datalen/1024));
  	printf(" Bss: %ld Kb\n", (__bsslen/1024));
	printf("Heap: %ld Kb\n", (__heapsize/1024));
#ifdef BUILD_49
	printf("Version: 49\n");
#else
	printf("Version: 50\n");
#endif
	printf("----------------\n");
#endif			//-end of specific code--------------------------------------------------------

#ifdef PSX
#ifdef EXPERIMENTAL
	FASTSTACK;
#endif
#endif
#ifdef MR_API_SOUND
	MRSNDInit(&gVABInfo[0],&gGroupInfo[0],&gSampleInfo[0]);
#endif

	// Load the fixed stuff
	MRSetTextureList(bmp_pointers);
	MRSetDefaultFont(&std_font);

#ifdef WIN95	//-windows specific code-------------------------------------------------------
	// Under windows, need to create the display BEFORE loading any graphics/wads

	// Read command line, to handle map loading (amongst other things)
	ProcessCmdLine((MR_UBYTE*)Main_cmd_line);

	if (MR_FAILURE == MRCreateDisplay())
		exit(0);

	Game_display_width 	= MRDisplay_ptr->di_disp_data->dd_width;	// Width of screen
	Game_display_height	= MRDisplay_ptr->di_disp_data->dd_height;	// Height of screen

#ifdef MR_DEBUG
	if (Main_screen_clear)
		MRDisableDisplayClear();
#endif			//-end of specific code--------------------------------------------------------
#endif

//#ifdef	MR_GATSO
	// Load in fixed vram stuff for the GATSO Font??
	MRLoadResource(RES_FIXE_VRAM_VLO);
	MRProcessResource(RES_FIXE_VRAM_VLO);
	MRUnloadResource(RES_FIXE_VRAM_VLO);
//#endif

	// Load in and init gatso
	MRSetGatsoImage(&im_gatso);
	MRInitialiseGatso();

	// Initialise game flags
	Game_flags 		= GAME_FLAG_HUD_SCORE | GAME_FLAG_HUD_TIMER | GAME_FLAG_HUD_HELP | GAME_FLAG_SCORE_SPRITES | GAME_FLAG_HUD_CHECKPOINTS | GAME_FLAG_HUD_LIVES;

	// Do a cold initialise of the game variables (probably overridden by game load from card)
	GameColdInitialise();

	// Initialise language (set on boot-up anyway)
	Game_language 	= GAME_LANGUAGE_ENGLISH;

#ifdef PSX		//-psx specific code-----------------------------------------------------------
	// Setup display
	Game_display_width 	= SYSTEM_DISPLAY_WIDTH;
	Game_display_height = SYSTEM_DISPLAY_HEIGHT;

	// Create display for psx
	MRCreateDisplay(SYSTEM_DISPLAY_MODE);
#endif			//-end of specific code--------------------------------------------------------

	// Initialise level flags, etc.
	SelectLevelInit();
	// Setup Effect pointers etc.....
	InitialiseEffects();

#ifdef MR_API_SOUND
	// Start/play/end game
	//
	
#ifdef EXPERIMENTAL
	// Load the GENERIC SFX (Theses stay loaded all the time,until the game is quit!!)
	// Moved so that they load while the ANTI-PIRACY is on screen.
	Game_map_theme = 0;
	InitialiseVab();
#endif

	// Set sound and CD volumes from options variables
	MRSNDSetVolumeLevel(MRSND_FX_VOLUME, (127 * Sound_volume) / OPTIONS_SOUND_STAGES);
	MRSNDSetVolumeLevel(MRSND_CD_VOLUME, (127 * Music_volume) / OPTIONS_SOUND_STAGES);
#endif

#ifdef PSX		//-psx specific code-----------------------------------------------------------
#ifdef FROG_OPTIONS
	// On PSX begin with anti piracy logo!!!
	MRSetDefaultFont(&std_font);

#ifndef EXPERIMENTAL
	Option_page_current = OPTIONS_PAGE_ANTI_PIRACY;
#else
	Option_page_current = OPTIONS_PAGE_MAIN_OPTIONS;
#endif

#ifdef DEBUG
	// Hiscore view
	//Option_page_current = OPTIONS_PAGE_MAIN_OPTIONS;
	Main_options_status	= MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT;

	// Hiscore input
//	Game_total_players		= 1;
//	Frogs[0].fr_input_id	= MR_INPUT_PORT_0;
//	Frogs[0].fr_score		= 10000;
//	Frogs[1].fr_input_id	= MR_INPUT_PORT_1;
//	Frogs[1].fr_score		= 20000;
//	Frogs[2].fr_input_id	= MR_INPUT_PORT_0;
//	Frogs[3].fr_input_id	= MR_INPUT_PORT_1;
//	Option_page_current 	= OPTIONS_PAGE_HIGH_SCORE_INPUT;
//	Sel_mode 				= SEL_MODE_RACE;
//	New_high_scores[0]		= 1;
//	New_high_scores[1]		= 1;
//	New_high_scores[3]		= 1;
//	New_high_scores[23]		= 1;

	// Options
//	Option_page_current = OPTIONS_PAGE_OPTIONS;
#endif

	// Do whole game ( as option pages )	
	OptionStart();
#else
//	Game_map = LEVEL_QB;
//	Game_map = LEVEL_ISLAND;
//	Game_map = LEVEL_ATTACK;
//	Game_map = LEVEL_SWAMP5;
	Game_map = LEVEL_SUBURBIA1;
//	Game_map = LEVEL_SUBURBIA_MULTI_PLAYER;
//	Game_map = LEVEL_FOREST_MULTI_PLAYER;
//	Game_map = LEVEL_ORIGINAL1;
//	Game_map = LEVEL_SKY1;
//	Game_map = LEVEL_CAVES1;
//	Game_map = LEVEL_DESERT2;
//	Game_map = LEVEL_VOLCANO2;
//	Game_map = LEVEL_FOREST2;
//	Game_map = LEVEL_JUNGLE1;
//	Game_map = LEVEL_VOLCANO3;

	Game_total_viewports 	= 1;
	Game_total_players 		= 1;
	Option_page_current 	= OPTIONS_PAGE_GAME;

	GameInitialise();
	OptionStart();
#endif
#endif			//-end of specific code--------------------------------------------------------

#ifdef WIN95	//-windows specific code------------------------------------------------
	// On PSX begin with anti piracy logo!!!
	MRSetDefaultFont(&std_font);

	if (!Main_load_specific_level)
		{
		Option_page_current		= OPTIONS_PAGE_VERSION;
		}
	else
		{
		Game_total_viewports 	= Main_load_number_players;
		Game_total_players 		= Main_load_number_players;

		Option_page_current 	= OPTIONS_PAGE_GAME;

		for (count=0; count<4; count++)
			{
			Frog_player_data[count].fp_is_local = 1;
			Frog_player_data[count].fp_port_id	= count;
			}
		GameInitialise();
		}

	OptionStart();
#endif			//-end of specific code--------------------------------------------------------

#ifdef MR_API_SOUND
	// UnLoad the GENERIC SFX 
	MRSNDCloseVab(VAB_GENERIC);
	MRUnloadResource(gVABInfo[VAB_GENERIC].va_vh_resource_id);
#endif

	// Memory check
	MRCheckMem();
	MRShowMem(NULL);

	// Note, don't put any psx code to cleanup api, such as MRDeinitMem() without wrapping
	// it up inside a PSX define, since the windows code does its own cleanup inside WinMain()
}

#ifdef PSX

/******************************************************************************
*%%%% InitialisePSX
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialisePSX(MR_VOID)
*
*	FUNCTION	Performs PlayStation hardware initialisation.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	InitialisePSX(VOID)
{
	stack_safety = 0xBEEFBABE;

	ResetCallback();						// Initialise PlayStation callback mechanisms

	SpuInit();								// Initialise SPU (stops reverb bug in PlayStation ROM)

	ResetGraph(0);							// Cold-start the GPU, turning the display off.
//	SetGraphDebug(0);						// Disable GPU debug
	SetGraphDebug(1);						

	InitGeom();								// Initialise the GTE

// Only install exception handler for non-release build

#ifdef	PSX_RELEASE
#ifndef	PSX_MASTER
    MRExceptionInstall(MR_EXCEPTION_AUTO_INSTALL);
#endif
#endif

	// This was changed because we are runnning out of memory. $gr
	MRInitMem(__heapbase, __heapsize-(10*1024));		// Initialise a memory heap (everything except 10k)

	// File System initialisation

#ifdef	PSX_CD_INIT
	CdInit();
	CdSetDebug(0);
#endif

#ifndef	PSX_RELEASE
	PCinit();
#endif

#ifdef	PSX_CD_LOAD
	MRInitialiseResources("FROGPSX.MWD", frogpsx_mwi, RES_FROGPSX_DIRECTORY, RES_NUMBER_OF_RESOURCES);
#else
	MRInitialiseResources(NULL, frogpsx_mwi, RES_FROGPSX_DIRECTORY, RES_NUMBER_OF_RESOURCES);
#endif

	MRSetFileProcess(FR_FTYPE_STD,		NULL);
	MRSetFileProcess(FR_FTYPE_VLO,	 	FRFileProcess_VLO);
	MRSetFileProcess(FR_FTYPE_MOF,	 	FRFileProcess_MOF);
	MRSetFileProcess(FR_FTYPE_MAPMOF, 	FRFileProcess_MAPMOF);
	MRSetFileProcess(FR_FTYPE_SPU, 		NULL);
	MRSetFileProcess(FR_FTYPE_DEMODATA,	NULL);

//---- 
// Do not change the order of functions between the '----' markers

	MRInitialiseInput(FRInput_default_map);			// Initialise controllers

#ifdef	PSX_CARD
	Card_init();				 					// Initialise card
#endif 

	ChangeClearPAD(0);								// Re-enable VBlank processing

//----

	// General initialisation
	MRInitialiseCallbacks();		
	MRInitialise();

	// XA Audio/Stream subsystem initialisation
#ifdef	PSX_ENABLE_XA					
	XAInitialise();
#endif

}
												 
												  
/******************************************************************************
*%%%% ProgressMonitor
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ProgressMonitor(MR_VOID)
*
*	FUNCTION	When called each game frame, this function provides debugging
*				functions such as slow-down, screen grab, VRAM dump and 
*				memory status.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	ProgressMonitor(MR_VOID)
{
#ifdef DEBUG

	MR_BOOL	paused = TRUE;

	return;

	if (MR_CHECK_PAD_HELD(0,MRIP_SELECT))
		{
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		VSync(0);
		}

	if (MR_CHECK_PAD_PRESSED(0,MRIP_START))
		{
		//	Pressed start...
		while (paused == TRUE)
			{
			// Grab the screen if 'Select' is pressed
			if (MR_CHECK_PAD_PRESSED(0,MRIP_SELECT))
				{
			 	MRDebugGrabScreen();
				}

			// Dump current memory status if green triangle is pressed
			if (MR_CHECK_PAD_PRESSED(0,MRIP_GREEN))
				{
			 	MRShowMem(NULL);
				MRShowMemNameSummary(NULL);
				}		 
	
			// Show VRAM if blue cross is pressed
			if (MR_CHECK_PAD_PRESSED(0,MRIP_BLUE))
				{
			 	MRDebugShowVram();
				}

			VSync(0);
			MRReadInput();

			if (MR_CHECK_PAD_PRESSED(0,MRIP_START))
				{
				paused = FALSE;
				}
			}
		}

#endif
}


/******************************************************************************
*%%%% TestModel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	TestModel(MR_VOID)
*
*	FUNCTION	Static model test function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	TestModel(MR_VOID)
{
#ifdef	DEBUG
	MR_OBJECT*		light;
	MR_OBJECT*		object;
	MR_MESH*		mesh;
	MR_FRAME*		frame;
	MR_FRAME*		meshframe0;
	MR_FRAME*		meshframe1;
	MR_MOF*			mof;
	MR_VEC			vec;
	MR_SVEC			svec;
	MR_VIEWPORT*	viewport0;
	MR_MESH_INST*	mesh_inst;


	MRSetDisplayClearColour(0x20,0x20,0x40);

	// Set up viewport
	viewport0	= MRCreateViewport(NULL, NULL, MR_VP_SIZE_1024, 0);
	vec.vx 		= 0;
	vec.vy 		= 0;
	vec.vz 		= -1000;
	frame 		= MRCreateFrame(&vec, &Null_svector, NULL);
	MRSetViewportCamera(viewport0, frame);

	//	Set up lights
	light = MRCreateLight(MR_LIGHT_TYPE_AMBIENT, 0x505050, NULL, MR_OBJ_STATIC);
	MRAddObjectToViewport(light, viewport0, NULL);

	setVector(&svec, 0x800, -0x600, 0);
	frame = MRCreateFrame(&Null_vector, &svec, NULL);
	light = MRCreateLight(MR_LIGHT_TYPE_PARALLEL, 0xf0f0f0, frame, NULL);
	MRAddObjectToViewport(light, viewport0, NULL);

	// Create stationary object
	MR_SET_VEC(&vec,  0, 0, 0);
	MR_SET_SVEC(&svec,  0, 0, 0);
	meshframe0 			= MRCreateFrame(&vec, &svec, NULL);

	// Get model
	MRLoadResource(Theme_library[THEME_ORG].tb_full_model_wad_res_id);
	MRProcessResource(Theme_library[THEME_ORG].tb_full_model_wad_res_id);
	mof					= MR_GET_RESOURCE_ADDR(RES_ORG_LOG_SMALL_XMR);

	object 				= MRCreateMesh(mof, meshframe0, NULL, NULL);
	mesh_inst			= MRAddObjectToViewport(object, viewport0, NULL);
	MRCalculateMOFDimensions(mof, &vec);

	mesh				= object->ob_extra.ob_extra_mesh;
	mesh->me_flags		|= MR_MESH_DEBUG_DISPLAY_PART_BBOX;
	mesh->me_flags		|= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;

	meshframe1			= MRCreateFrame(&vec, &Null_svector, NULL);

	MRDebugInitialiseDisplay();

//------------
//	Mainloop
	
	while(1)
		{
		DrawSync(0);
		VSync(0);
		MRSwapDisplay();
		MRReadInput();
		MRDebugStartDisplay();

		// Input
		if (MR_CHECK_PAD_HELD(0,FR_LEFT))
			{
			meshframe0->fr_rotation.vy += 0x200000;
			meshframe1->fr_rotation.vy += 0x200000;
			}
		if (MR_CHECK_PAD_HELD(0,FR_RIGHT))
			{
			meshframe0->fr_rotation.vy -= 0x200000;
			meshframe1->fr_rotation.vy -= 0x200000;
			}
		if (MR_CHECK_PAD_HELD(0,FR_UP))
			{
			meshframe0->fr_rotation.vx -= 0x200000;
			meshframe1->fr_rotation.vx -= 0x200000;
			}
		if (MR_CHECK_PAD_HELD(0,FR_DOWN))
			{
			meshframe0->fr_rotation.vx += 0x200000;
			meshframe1->fr_rotation.vx += 0x200000;
			}
		meshframe0->fr_flags |= MR_FRAME_REBUILD;
		meshframe1->fr_flags |= MR_FRAME_REBUILD;

		if (MR_CHECK_PAD_HELD(0,FRR_PINK))
			viewport0->vp_camera->fr_matrix.t[2] += 0x20;
		if (MR_CHECK_PAD_HELD(0,FRR_RED))
			viewport0->vp_camera->fr_matrix.t[2] -= 0x20;

		FASTSTACK;
		MRUpdateFrames();
		MRUpdateObjects();
		MRUpdateViewportRenderMatrices();
		MRRenderViewport(viewport0);
		SLOWSTACK;

		ProgressMonitor();
		}
#endif	// DEBUG
}
#endif	//PSX


#ifdef WIN95

/*******************************************************************************
*	ProcessCmdLine
*-------------------------------------------------------------------------------
*
*	FUNCTION	MR_VOID ProcessCmdLine(MR_UBYTE *CmdLine)
*
*	SYNOPSIS	Processes the command line for windows frogger
*
*	INPUTS		Command line string ptr
*
*	NOTES		None.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Martin Kift		Created
*
*******************************************************************************/

MR_VOID ProcessCmdLine(MR_UBYTE *CmdLine)
{
	MR_UBYTE	Command;					// Temp store for command
	char		theme[10];
	char		map[10];
	char*		ptr;
	MR_ULONG	mapnum;
	MR_ULONG	themenum;

#ifdef MR_DEBUG
	Main_screen_resolution	= 0;
	Main_screen_clear		= FALSE;
#endif

	// Loop until end of line
	do
		{
		// Skip to whitespace and then past it to next command
		while (*CmdLine != ' ' && *CmdLine != '\t' && *CmdLine != '\0'
				&& *CmdLine != '-' && *CmdLine != '\\' && *CmdLine != '/')
			CmdLine++;
		while (*CmdLine == ' ' || *CmdLine == '\t')
			CmdLine++;

		// End of line ?
		if ('\0' == *CmdLine)
			return;

		// New param ???
		if (*CmdLine == '-' || *CmdLine == '\\' || *CmdLine == '/')
			{
			// Yes ... get command & point to next character
			Command = *++CmdLine;
			CmdLine++;

			// ensure that its upper case
			Command = toupper(Command);
			
			// Depending on command do ...
			switch( Command )
				{
				// Load in a level ...
				case 'M':
					// Need to separate out theme and map number
					ptr = &theme[0];
					while (*CmdLine && *CmdLine != ',')
						*ptr++ = *CmdLine++;
					*ptr = '\0';

					ptr = &map[0];
					CmdLine++;
					while (*CmdLine && *CmdLine != ' ')
						*ptr++ = *CmdLine++;
					*ptr = '\0';

					// turn into numbers
					themenum = GetNumber(&theme[0]) - 1;
					mapnum = GetNumber(&map[0]) - 1;

					// check numbers
					MR_ASSERTMSG((themenum>=0 && themenum<=9), "Theme number should be value of 1->10");
					MR_ASSERTMSG((mapnum>=0 && mapnum<=5), "Map number should be value of 1->6");

					// work out actual game map number
					Game_map = (themenum*6) + mapnum;

					Main_load_specific_level = TRUE;
					break;

#ifdef MR_DEBUG
				// Screen res
				case 'R':
					// Need to separate out theme and map number
					ptr = &theme[0];
					while (*CmdLine && *CmdLine != ',')
						*ptr++ = *CmdLine++;
					*ptr = '\0';

					Main_screen_resolution = GetNumber(&theme[0]);
					if (Main_screen_resolution < 0 || Main_screen_resolution  > 5)
						Main_screen_resolution = 0;
					break;

				// Screen clear
				case 'C':
					Main_screen_clear = TRUE;
					break;

				// multiplayer	
				case 'P':
					// Need to separate out theme and map number
					ptr = &theme[0];
					while (*CmdLine && *CmdLine != ',')
						*ptr++ = *CmdLine++;
					*ptr = '\0';

					// turn into numbers
					Main_load_number_players = GetNumber(&theme[0]);
					if (Main_load_number_players <= 0 || Main_load_number_players>4)
						Main_load_number_players = 1;
					break;

#endif
				}
			} 
		else
			return;
		} while (*CmdLine != '\0');
}

/*******************************************************************************
*	GetNumber
*-------------------------------------------------------------------------------
*
*	FUNCTION	MR_ULONG GetNumber(MR_UBYTE *String)
*
*	SYNOPSIS	main windows callback fucntion
*
*	INPUTS		Converts the passed ASCII number into a ulong
*
*	RESULT		ULONG number, zero on failure
*
*	NOTES		None.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	xx.xx.96	Kevin Mullard	Created
*	24.04.97	Martin Kift		Recoded
*
*******************************************************************************/

MR_ULONG GetNumber(MR_UBYTE *InString)
{
	MR_LONG		Index;
	MR_LONG		Multiplier;
	MR_UBYTE	c;
	MR_ULONG	Number;
	MR_UBYTE	String[256];

	Index = 0;
	Multiplier = 1;
	Number = 0;

	// Copy the string up till the next white space or null
	while(*InString != '\0' && *InString != ' ' && *InString !='\t')
	{
		String[Index++] = *InString++;
	}
	
	// If there are no numbers return default value, else work out the number
	while(--Index >= 0)
	{
		c = (String[Index]) - '0';
		
		// zero the digit if its invalid
		if(c < 0 || c > 9)
			c = 0;

		Number += c * Multiplier;
		Multiplier *= 10;
	}

	return Number;
}

/******************************************************************************
*%%%% InitialiseWIN95
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseWIN95(MR_VOID)
*
*	FUNCTION	Performs PlayStation hardware initialisation.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseWIN95(VOID)
{
	MRInitGeom();				// Init PC Geom
	MRInitMem(10192000);			// Initialise a memory heap 

#ifdef	WIN95_CD_LOAD
	MRInitialiseResources("FROGPSX.MWD", NULL, IDR_MWI1, "MWI", RES_FROGPSX_DIRECTORY, RES_NUMBER_OF_RESOURCES);
#else
	MRInitialiseResources(NULL, NULL, IDR_MWI1, "MWI", RES_FROGPSX_DIRECTORY, RES_NUMBER_OF_RESOURCES);
#endif

	// Setup API resource handling callbacks
	MRSetFileProcess(FR_FTYPE_STD,		NULL);
	MRSetFileProcess(FR_FTYPE_VLO,	 	FRFileProcess_VLO);
	MRSetFileProcess(FR_FTYPE_MOF,	 	FRFileProcess_MOF);
	MRSetFileProcess(FR_FTYPE_MAPMOF, 	FRFileProcess_MAPMOF);
	MRSetFileProcess(FR_FTYPE_SPU, 		NULL);
	MRSetFileProcess(FR_FTYPE_DEMODATA,	NULL);

	// General initialisation
	MRInitialiseInput();			// Init controllers
	MRInitialiseCallbacks();		// Init callbacks
	MRInitialise();					// General init
	MRInitialiseWindowsTimers();	// Init timers

	MRRemapInput(0, &FRInput_default_map[0], &FRInput_default_key_map1[0]);
	MRRemapInput(1, &FRInput_default_map[0], &FRInput_default_key_map2[0]);
	MRRemapInput(2, &FRInput_default_map[0], &FRInput_default_key_map3[0]);
	MRRemapInput(3, &FRInput_default_map[0], &FRInput_default_key_map4[0]);

	// Create a timer to count every 30 frames
	Main_frame_rate_timer = MRCreateTimer(1000/LOGIC_CALLS_PER_SEC,(LPTIMECALLBACK)(FrameRateTimerCallBack));
	MR_ASSERT (Main_frame_rate_timer);
}

/******************************************************************************
*%%%% FrameRateTimerCallBack
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrameRateTimerCallBack(	UINT hWnd,
*												UINT uMsg,
*												DWORD idEvent,
*												DWORD dwTime,
*												DWORD dwThree)
*
*	FUNCTION	Timer callback for windows
*
*	INPUTS		Obvious
*
*	NOTES		Callback routine for frame rate timer.  This function is called 
*				30 times a second to increament a frame count.  This frame 
*				count is used by the main logic to calculate the number of 
*				frames necessary to process to keep the game at a constant 
*				frame rate.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID CALLBACK FrameRateTimerCallBack(	UINT hWnd, 
											UINT uMsg, 
											DWORD idEvent, 
											DWORD dwTime,
											DWORD dwThree)
{
	// Inc global frame rate
	Main_frame_count++;
}

/*******************************************************************************
*	WinMain
*-------------------------------------------------------------------------------
*
*	FUNCTION	int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
*												LPSTR lpCmdLine, int nCmdShow)
*
*	SYNOPSIS	Windows winmain function...  This will call the psx main() 
*				function, such that the code remains pretty standard.
*
*	INPUTS		Obvious
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Martin Kift		Created
*	08.05.97	Martin Kift		Moved most of the code across to main()
*
*******************************************************************************/

int WINAPI	WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// Open up windows
	if(MR_FAILURE == MROpenWindows(NULL, hInstance))		
		return(0);

	// Detect and setup the cd drive
	Main_win95_cd_drive = MRDetectCD("FROGGER");

	// Try initialising the cd audio, if cd is present
	if (Main_win95_cd_drive)
		MCOpenCDAudio(Main_win95_cd_drive);	

	// copy the command line over into global data, for later access
	strcpy(Main_cmd_line, lpCmdLine);

	// Call the general main function, to do all the work
	main();

	// Cleanup and exit
	MRDeinitialiseWindowsTimers();
	MRKillDisplay();
	MRDeinitialiseResources();
	MRDeinitialiseInput();
	MRDeinitMem();
	MRDeinitialise();

	// Close down the cd audio
	if (Main_win95_cd_drive)
		MCCloseCDAudio();

	// The following line must exist
	return (MRCloseWindows());								
}

#endif // WIN95

