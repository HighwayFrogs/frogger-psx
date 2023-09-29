/******************************************************************************
*%%%% gamesys.c
*------------------------------------------------------------------------------
*
*	All game system variables
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "gamesys.h"
#include "mapdisp.h"
#include "main.h"
#include "project.h"
#include "mapview.h"
#include "camera.h"
#include "grid.h"
#include "frog.h"
#include "froganim.h"
#include "froguser.h"
#include "mapdebug.h"
#include "collide.h"
#include "gamefont.h"
#ifdef PSX
#include "sound.h"
#endif
#include "xalist.h"
#include "effects.h"
#include "ent_gen.h"
#include "model.h"
#include "options.h"
#include "mapload.h"
#include "tempopt.h"
#include "score.h"
#include "frog.h"
#include "select.h"
#include "playxa.h"
#include "water.h"
#include "ent_jun.h"
#include "particle.h"
#include "hud.h"
#include "gen_gold.h"
#include "pause.h"
#include "hsview.h"

#ifdef WIN95
#include "cdaudio.h"
#include "sound.h"
#pragma warning (disable : 4761)
#endif

// Viewports
MR_VIEWPORT*	Game_viewport0;					// player 1 viewport
MR_VIEWPORT*	Game_viewport1;					// player 2 viewport
MR_VIEWPORT*	Game_viewport2;					// player 3 viewport
MR_VIEWPORT*	Game_viewport3;					// player 4 viewport
MR_VIEWPORT*	Game_viewporth;					// HUD viewport
MR_VIEWPORT*	Game_viewportc;					// clearing viewport
MR_VIEWPORT*	Game_viewports[5];				// NULL terminated ptrs to player viewports
												
#ifdef GAME_CLEAR_USING_TILES
TILE			Game_clear_tiles[2];			// tiles for clearing viewports
#endif
#ifdef GAME_VIEWPORT_BORDERS
LINE_F3			Game_viewport_borders[4][2][2];	// lines around viewport edges
#endif

MR_ULONG		Game_border_colours[] =
	{
	0x00a000,	// GREEN
	0xa000a0,	// MAGENTA
	0x00a0a0,	// YELLOW
	0xa0a000,	// CYAN
	};	

// System
MR_VEC			Game_x_axis_pos 	= { 0x1000, 0, 0};
MR_VEC			Game_x_axis_neg 	= {-0x1000, 0, 0};
MR_VEC			Game_y_axis_pos 	= {0,  0x1000, 0};
MR_VEC			Game_y_axis_neg 	= {0, -0x1000, 0};
MR_VEC			Game_z_axis_pos 	= {0, 0,  0x1000};
MR_VEC			Game_z_axis_neg 	= {0, 0, -0x1000};

// Display
MR_CVEC			Game_back_colour[60]	= 
{
	{0, 0, 0},		// Caves
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Desert
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Forest
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Jungle
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Original
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Ruins
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Swamp
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Sky
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Suburbia
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Volcano
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

	{0, 0, 0},		// Dummy!!!
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},

};

MR_LONG			Game_perspective;
MR_LONG			Game_display_width;
MR_LONG			Game_display_height;

// Main game
MR_BOOL			Game_running;
MR_ULONG		Game_timer;						// reset to 0 at start of game
MR_ULONG		Game_flags;						// various game flags
MR_ULONG		Game_start_timer;				// counts down to 0, then game starts
MR_LONG			Game_map_timer;					// max time for this level - counts down to 0
MR_LONG			Game_last_map_timer;			// Used to control the sounds for the timer.
MR_FRAC16		Game_map_timer_speed;			// These are used to ramp the time limit up/down
MR_FRAC16		Game_map_timer_frac;			// for when a Time Bonus Fly is picked up.
MR_UBYTE		Game_map_timer_flags;			// 
MR_ULONG		Game_map_time;					// max time for this level
MR_ULONG		Game_reset_flags;				// game reset flags (such as resetting due to frog death)
HUD_ITEM*		Game_hud_script;				// ptr to HUD script (or NULL), used for fancy effects
MR_LONG			Game_continues_left;			// Number of continues left?

#ifdef WIN95
MR_BOOL			Game_is_network;				// is network (and multiplayer of course). Win95 only
MR_BOOL			Game_is_waiting_for_sync;		// in network mode, we have to wait for sync messages before doing a frame
#endif													

// Game mode
MR_ULONG		Game_mode;						// Game mode (init -> play -> deinit, etc)
MR_VOID*		Game_mode_data;					// Data needed for some modes
														
// Game options											
MR_ULONG		Game_map;						// current map index (from library.h)
MR_ULONG		Game_map_theme;					// eg. THEME_SUB
MR_ULONG		Game_total_players;				// 1..4
MR_ULONG		Game_total_viewports;			// 1..4
												
// Game modes (debug and cheat stuff)			
MR_ULONG		Game_cheat_mode;				// Cheat mode
MR_ULONG		Game_debug_mode;				// Debug mode
														
// Fonts
MR_FONT_INFO*	Game_font_infos[] =
	{
	&debug_font,
	&std_font,
	};

// Demo mode
MR_TEXT_AREA*	Recording_demo_text_area;
MR_STRPTR		Recording_demo_text[]						=	{"%jcRECORDING DEMO",NULL};

// "Time out!" 
MR_ULONG		Time_out_message_count = TIME_OUT_MESSAGE_LEN;
MR_ULONG		Animlist_time_out[] =
				{
				MR_SPRT_SETSPEED,	4,
				MR_SPRT_SETCOUNT,	0,
				MR_SPRT_SETIMAGE,	(MR_ULONG)&im_timeout,
				MR_SPRT_SETIMAGE,	(MR_ULONG)&im_timeout,
				MR_SPRT_SETIMAGE,	(MR_ULONG)&im_timeout,
				MR_SPRT_SETIMAGE,	(MR_ULONG)&im_timeout,
				MR_SPRT_SETIMAGE,	(MR_ULONG)&im_timeout,
				MR_SPRT_KILL
				};

// Background transparent polys
POLY_F4			Game_prim_f[2];
POLY_FT3		Game_prim_ft[2];

// Multiplayer background graphic data (sprite ptrs and positions on screen)
MR_2DSPRITE*	Game_multiplayer_no_player[4];

// Table for text positions at end of multiplayer game
MR_XY	Multiplayer_end_of_game_text_pos[4][4]=
		{
			// 1 Player game
			{
				{0,0},	{0,0},	{0,0},	{0,0}
			},
			// 2 Player game
			{
				{0,0},	{0,0},	{0,0},	{0,0}
			},
			// 3 Player game
			{
				{0,0},	{0,0},	{0,0},	{0,0}
			},
			// 4 Player game
			{
				{0,0},	{0,0},	{0,0},	{0,0}
			}
		};

// Used for ASync Loading.
MR_LONG	Game_start_mode = GAME_START_INIT;


// Multiplayer 
GAME_OVER_MULTIPLAYER*		Game_over[4];

//------------------------------------------------------------------------------------------------
// Game mainloop setup functions	- called from GameMainLoop()
//------------------------------------------------------------------------------------------------
MR_VOID (*Game_mainloop_setup_functions[])(MR_VOID) =
	{	
	NULL,												// Single - Level is starting (bouncing frogs, hud, etc)
	GameMainloopSingleTriggerCollectedSetup,			// Single - Trigger collected
	NULL,												// Single - Level has been failed
	GameMainloopSingleFrogDiedSetup,					// Single - Frog (single player) has died
	NULL,												// Single - Level complete
	NULL,												// Multiplayer - Start level
	NULL,												// Multiplayer - Trigger collected
	NULL,												// Multiplayer - Level has been failed
	NULL,												// Multiplayer - All frogs died
	GameMainloopMultiCompleteSetup,						// Multiplayer - Level complete

	NULL,												// Level is playing
	NULL,												// Level is starting (simple fast start)

	GameMainloopEndOfGameSetup,							// GAME_MODE_END_OF_GAME
	GameMainloopEndOfMultiplayerGameSetup,				// GAME_MODE_END_OF_MULTIPLAYER_GAME
	};

//------------------------------------------------------------------------------------------------
// Game mainloop update functions	- called from GameMainLoop()
//------------------------------------------------------------------------------------------------
MR_VOID (*Game_mainloop_update_functions[])(MR_VOID) =
	{
	GameMainloopSingleStartUpdate,						// Single - Level is starting (bouncing frogs, hud, etc)
	GameMainloopSingleTriggerCollectedUpdate,			// Single - Trigger collected
	GameMainloopSingleFailedUpdate,						// Single - Level has been failed
	GameMainloopSingleFrogDiedUpdate,					// Single - Frog (single player) has died
	GameMainloopSingleCompleteUpdate,					// Single - Level complete
	GameMainloopMultiStartUpdate,						// Multiplayer - Start level
	GameMainloopMultiTriggerCollectedUpdate,			// Multiplayer - Trigger collected
	GameMainloopMultiFailedUpdate,						// Multiplayer - Level has been failed
	GameMainloopMultiFrogDiedUpdate,					// Multiplayer - All frogs died
	GameMainloopMultiCompleteUpdate,					// Multiplayer - Level complete

	GameMainloopPlayUpdate,								// Level is playing
	GameMainloopFastStartUpdate,						// Level is starting (simple fast start)

	GameMainloopEndOfGameUpdate,						// GAME_MODE_END_OF_GAME
	GameMainloopEndOfMultiplayerGameUpdate,				// GAME_MODE_END_OF_MULTIPLAYER_GAME
	};


//-----------------------------------------------------------------------------
//	Test timings
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// 	15.04.97, old desert map, y = -7000, looking straight down, 147 poly groups, 1176 polys
//
//										CALC	RENDER
// 	CreateMapViewList()					4
//	CreateMapGroups()					8
//	RenderMap()							154		276

//-----------------------------------------------------------------------------
// 	08.05.97, test island: frog animation takes ages! 4 viewport, first view, calc time for 4 MRRenderViewport()
//
//										CALC
// with frog animating					181
// with frog static						97

/******************************************************************************
*%%%% GameInitialise
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameInitialise(MR_VOID)
*
*	FUNCTION	Initialises main game (called once only when entering a game).
*				Its main task is to initialise frog structures (such as scores)
*				which cannot be done in CreateFrog, since this is called every
*				level.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameInitialise(MR_VOID)
{
	MR_ULONG	loop;

	for (loop=0; loop<4; loop++)
		{
		Frogs[loop].fr_lives			= FROG_START_LIVES;
		Frogs[loop].fr_score			= 0;
		Frogs[loop].fr_old_score		= 0;
		Frogs[loop].fr_prev_score		= 0;
		Frogs[loop].fr_life_bonus_score	= FROG_LIFE_AWARD_SCORE;
		}

	// Flush current-game counter for gold frogs
	Gold_frogs_current	= 0;
	Gold_frogs_zone		= 0;
}

/******************************************************************************
*%%%% GameColdInitialise
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameColdInitialise(MR_VOID)
*
*	FUNCTION	This is a single called function to initialise data, such as
*				gold frogs collected... The data set here COULD be overridden
*				by loading in a previous game. Because of the nature of this
*				function, I suggest its only called once from main(), way
*				before going into the options code.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameColdInitialise(MR_VOID)
{
	// Init gold frogs (save data variable)
	Gold_frogs = 0;

	// Other things to come later...
}

/******************************************************************************
*%%%% GameStart
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	GameStart(MR_VOID)
*
*	FUNCTION	starts main game (called as a once off when entering a level)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameStart(MR_VOID)
{
	SEL_LEVEL_INFO*		arcade_level_ptr;
	MR_ULONG			game_mode;

#ifdef WIN95
	// Initialise synced of all network machines (win95 only)
	if (MNIsNetGameRunning())
		Game_is_network	= TRUE;				// Set network flag, very important!
	else
		Game_is_network	= FALSE;			// Clear network flag, very important!
#endif

	// Set important game vars
	Game_reset_flags	= 0;
	Game_perspective	= 0x100;

	// set backgroun clear colour
	MRSetDisplayClearColour(Game_back_colour[Game_map].r, Game_back_colour[Game_map].g, Game_back_colour[Game_map].b);
	
	// Clear options
	ClearOptions();

	// Start the loading Tune. (After Select Vab has been unloaded)
	MRSNDPlaySound(	SFX_MUSIC_DRUMLOAD, NULL, 0, 0);

	// Load correct generic wad (if not already loaded)
	if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS)
		LoadGenericWad(1);
	else
		LoadGenericWad(0);

	// Create viewports
	GameCreateViewports();
#ifdef GAME_CLEAR_USING_TILES
	MRDisableDisplayClear();
#endif

	// Initialise effects (map creation may need them)
	//InitialiseEffects(); This should only be called ONCE.

	// Initialise path runners - must be done before map is resolved
	InitialisePathRunners();

	// Initialise entities
	InitialiseLiveEntities();

	// Load level map
	Map_mof_index = 0;
   	InitialiseMap();

//	HideAllEntitiesExcept(1984);
//	MRShowMemSummary(NULL);

	GameSetViewportsPerspective();
	InitialiseCheckPoints();

	// Initialise map display and view
	InitialiseMapDisplay();
	InitialiseMapView();

	// Initialise grid
	InitialiseGrid();

	// Initialise lights
	CreateMapLights();

	// Initialise HUD and scores
	InitialiseHUD();
	InitialiseScoreSprites();
	InitialiseMultiplayerHUDbackgrounds();

	// Are we in demo mode ?
	if ( Game_flags & GAME_FLAG_DEMO_RUNNING )
		{
		// Yes ... reset map start position
		Map_general_header->gh_start_x = Demo_data_ptr/*s[Num_demo_levels_seen]*/->dd_start_grid_x;
		Map_general_header->gh_start_z = Demo_data_ptr/*s[Num_demo_levels_seen]*/->dd_start_grid_z;
		}

	// Initialise frogs
	InitialiseFrogs();	

	// Must be after InitialiseFrogs (camera->ca_origin_offset set to point to frog origin)
	InitialiseCameras();

	// Initialise Map Debug display
	InitialiseMapDebugDisplay();

	// CD stuff
#ifdef	PSX_ENABLE_XA

#ifdef PSX
	XAStartup();
	// Get ID (zero based) of the music track you want to play
	PlayLevelMusic(Game_xa_tunes[Game_map]);		
#else
	if (Main_win95_cd_drive)
		MCPlayLoopingTrack(Game_xa_tunes[Game_map]);
#endif	// PSX

#endif	// PSX_ENABLE_XA

	// Flag game as currently running, and setup various game flags
	Game_running		= TRUE;
	Game_cheat_mode		= FALSE;
	Game_debug_mode		= FALSE;
	Game_hud_script		= NULL;

	// Kill loading sprite
//	if ( Sel_loading_sprite_ptr )
//		{
//		MRKill2DSprite(Sel_loading_sprite_ptr);
//		Sel_loading_sprite_ptr = NULL;
//		}

	// Kill level name
//	if ( Sel_level_title )
//		{
//		MRKill2DSprite(Sel_level_title);
//		Sel_level_title = NULL;
//		}

	// Flag loading sprites as no display!
	Sel_loading_sprite_ptr->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
	Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

#ifdef WIN95
	// reset frame rate counter to zero
	Main_frame_count = 0;

	// Set game as not having to wait for a sync, this will run the first frame,
	// and then wait on the 2nd
	Game_is_waiting_for_sync = FALSE;
#endif

	// If in multiplayer mode, start in a normal boring way, else start in fancy way
	if (Game_total_players == 1)
		{
		game_mode = GAME_MODE_SINGLE_START;

		// if we are playing jungle 2, then no need for fancy starts, go straight to outro mode,
		// else goto single_start mode
		if (Game_map_theme == THEME_JUN)
			{
			arcade_level_ptr = Sel_arcade_levels;
			while (arcade_level_ptr->li_library_id != -1)
				{
				if (arcade_level_ptr->li_library_id == LEVEL_JUNGLE2)
					{
					game_mode = GAME_MODE_END_OF_GAME;
					break;
					}
				arcade_level_ptr++;
				}
			}

		// setup game mode and start level
		SetGameMainloopMode(game_mode);		
		LevelStart(game_mode);
		}
	else
		{
		SetGameMainloopMode(GAME_MODE_MULTI_START);			
		LevelStart(GAME_MODE_MULTI_START);
		}
	// Kill SFX of loading sample.
	MRSNDKillAllSounds();

	// turn on pause (default for in game)
	Game_flags &= ~GAME_FLAG_NO_PAUSE_ALLOWED;

	// Set up pause polys - these 2 lines ARE necessary: please don't delete them!
	GamePauseCreateFadePoly();
	Game_paused_selection = 0;
}

/******************************************************************************
*%%%% GameEnd
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameEnd(MR_VOID)
*
*	FUNCTION	End main game
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	26.06.97	Martin Kift		Added win95 network code to shut things down neatly
*
*%%%**************************************************************************/

MR_VOID	GameEnd(MR_VOID)
{
	MR_ULONG		loop_counter;
	
#ifdef PSX_ENABLE_XA
#ifdef PSX
	XAShutdown();
#else
	if (Main_win95_cd_drive)
		MCStop();
#endif //PSX
#endif //PSX_ENABLE_XA

	// Kill all live entities
	KillAllLiveEntities();

	// Kill all path runners
	KillAllPathRunners();

	// Stop all sound effects before we release the VABs
	MRSNDKillAllMovingSounds();
	MRSNDKillAllSounds();
	
	// Close the Vab.
	MRSNDCloseVab(Game_map_theme);

#ifdef MR_API_SOUND
	// Remove the Header From Main RAM.
	MRUnloadResource(gVABInfo[Game_map_theme].va_vh_resource_id);
#endif

	// Deinitialise HUD
	DeinitialiseHUD();
	DeinitialiseMultiplayerHUDbackgrounds();

	// Kill debug display
	KillMapDebugDisplay();

	// Kill map display
	DeinitialiseMapDisplay();

	// Loop once for each Frog
	for(loop_counter=0;loop_counter<Game_total_players;loop_counter++)
		{
		// Kill frog
		KillFrog(&Frogs[loop_counter]);
		}

	// Kill viewports
	GameKillViewports();

	// Kill All effects (This is OK, cos the viewports have been killed)
	KillAllEffects();

#ifdef GAME_CLEAR_USING_TILES
	MREnableDisplayClear();
#endif

	// Kill map lights frames
	KillMapLightsFrames();

#ifdef PSX
	// Unload level MAP
	MRUnloadResource(Map_book->mb_map_res_id);
#endif

	// under win95, and debug mode, the maps are loaded directly (the one from the wad
	// file is ignored), so the memory used needs to be freed
#ifdef WIN95
#ifdef MR_DEBUG
	 MRFreeMem(map_memory);
#else
	// Unload level MAP
	MRUnloadResource(Map_book->mb_map_res_id);
#endif
#endif

	// Unload theme model WAD
	MRUnloadResource(Map_book->mb_model_wad_res_id);

	// Free memory allocated during InitialiseMap
	MRFreeMem(Map_group_entity_roots);

	// Remove any PolyGroups that may be left over.					
	FreeAllPolyGroups();

#ifdef WIN95
	// In windows, if we have just played a network game, we need to close it all down.
	if (Game_is_network)
		{
		MNClose();									
		Game_is_network	= FALSE;			
		}
#endif

	// Clear any camera shakes
	ResetCameras();

	Game_running	= FALSE;

}

/******************************************************************************
*%%%% LevelStart
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelStart(MR_ULONG	Game_mode)
*
*	FUNCTION	Start a level (game must have been previously initialised using
*				GameStart())
*
*	PARAMS		Game_mode		-	Mode of game as it starts (first start, 
*									restart after trigger, etc).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	LevelStart(MR_ULONG game_mode)
{
	MR_ULONG		count;
	FROG*			frog;
	MR_ULONG		i;
	ENTITY*			entity;
	LIVE_ENTITY*	live_entity;
	ENTITY**		entity_pptr;

	// Reset frogs
	frog	= Frogs;
	count	= Game_total_players;
	while (count--)
		{
		ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, game_mode);
		UpdateFrogCameraZone(frog);
		frog++;
		}

	// Reset sky scrolly background
	MR_CLEAR_VEC(&Sky_drift_position);
	MR_CLEAR_VEC(&Sky_drift_velocity);
	MR_CLEAR_VEC(&Sky_drift_acceleration);

	// $wb - Start displaying all necessary objects ( after being flagged as no display by LevelEnd() )
	// Loop once for each entity
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		*entity_pptr 	= (ENTITY*)(*entity_pptr);
		entity			= *entity_pptr;
		// Should this entity be displayed ?
		if ( !(entity->en_flags & ENTITY_NO_DISPLAY) )
			{
			// Yes ... get pointer to live entity
			live_entity = entity->en_live_entity;
			// Is it a valid pointer to a live entity
			if ( live_entity != NULL )
				{
				// Yes ... is there a valid API pointer ?
				if ( live_entity->le_api_item0 != NULL )
					{
					// Yes ... is it animated ?
					if ( live_entity->le_flags & LIVE_ENTITY_ANIMATED )
						{
						// Yes ... flipbook ?
						if ( live_entity->le_flags & LIVE_ENTITY_FLIPBOOK )
							{
							// Yes ... display flipbook
							((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
							}
						else
							{
							// No ... display animation
							((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_single->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
							}
						}
					else
						{
						// No ... display static
						((MR_OBJECT*)live_entity->le_api_item0)->ob_flags &= ~MR_OBJ_NO_DISPLAY;
						}
					}
				}
			}
		// Next entity
		entity_pptr++;
		}

	// reset up Game_flags, etc
	Game_map_time			= Map_general_header->gh_trigger_timers[0];
	Game_map_timer			= Game_map_time * 30;
	Game_map_timer_speed 	= 1 << 16;							// Cos it's a Fraction.
	Game_map_timer_frac		= 0;
	Game_map_timer_flags 	= GAME_TIMER_FLAGS_COUNT_UP;

	// Set up start timer based on the type of start
	switch (game_mode)
		{
		case GAME_MODE_SINGLE_START:
			Game_start_timer = GAME_START_TIME_SLOW;
			break;
		case GAME_MODE_SINGLE_TRIGGER_COLLECTED:
		case GAME_MODE_SINGLE_FROG_DIED:
		case GAME_MODE_MULTI_START:
		case GAME_MODE_MULTI_TRIGGER_COLLECTED:
		case GAME_MODE_MULTI_FROG_DIED:
		case GAME_MODE_LEVEL_FAST_START:
		case GAME_MODE_LEVEL_PLAY:
		default:
			Game_start_timer = GAME_START_TIME_FAST;
			break;
		}

	// Reset cameras
	ResetCameras();

	// Now do stuff to ensure that on the first call to GameMainloop(), we will in a 
	// position to generate a valid game view
	UpdateCameras();
	MRUpdateFrames();

}


/******************************************************************************
*%%%% LevelEnd
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelEnd(MR_VOID)
*
*	FUNCTION	End a level (wait for a while to flush everything)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*	22.07.97	Gary Richards	Added code to remove frog/3d sprites from display.
*
*%%%**************************************************************************/

MR_VOID	LevelEnd(MR_VOID)
{
	MR_OBJECT*		object_ptr = MRObject_root_ptr;

	// Turn off Frog, so it's not displayed on screen.
	RemoveAllFrogsFromDisplay();

	// $wb - Fixed bug that leaves some entities behind on screen after death
	// Remove ALL objects from display
	while(object_ptr = object_ptr->ob_next_node)
		{
			object_ptr->ob_flags |= MR_OBJ_NO_DISPLAY;
		}

	// Reset entities 
	ResetEntities();

	// Reset game reset flags
	Game_reset_flags = 0;

	// Clear GPU, etc
	GameClearRender();
}


/******************************************************************************
*%%%% GameCreateViewports
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameCreateViewports(MR_VOID)
*
*	FUNCTION	Set up game viewports
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	08.05.97	Tim Closs		Altered for multi-viewport
*
*%%%**************************************************************************/

MR_VOID	GameCreateViewports(MR_VOID)
{
	MR_RECT		vp_rect;
	MR_LONG		i, j;
#ifdef GAME_CLEAR_USING_TILES
	TILE*		tile;
#endif
#ifdef GAME_VIEWPORT_BORDERS
	MR_LONG		x0, x1, y0, y1;
	LINE_F3*	line_f3;
#endif

	
	Game_viewport0 = NULL;
	Game_viewport1 = NULL;
	Game_viewport2 = NULL;
	Game_viewport3 = NULL;

#ifdef GAME_CLEAR_USING_TILES
	// Set up clearing viewport first (so it appears behind)
	Game_viewportc 					= MRCreateViewport(NULL, NULL, MR_VP_SIZE_4, 4);
	Game_viewportc->vp_camera 		= NULL;
	Game_viewportc->vp_perspective	= Game_perspective;
	tile = Game_clear_tiles;
	for (j = 0; j < 2; j++)
		{
		MR_SET32(tile->r0, 0);
		setTile(tile);			
		tile->x0 = 0;
		tile->y0 = 0;
		tile->w = Game_display_width;
		tile->h	= Game_display_height;
		tile++;
		}
#endif

	switch(Game_total_viewports)
		{
		//-----------------------------------------------------------------------
		case 1:
			// Single viewport
			Game_viewport0 					= MRCreateViewport(NULL, NULL, SYSTEM_VIEWPORT_OT_SIZE_1P, 3);
			Game_viewport0->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport0->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport0, SYSTEM_VIEWPORT_VIEWDIST);
			break;
		//-----------------------------------------------------------------------
		case 2:
			// Double viewport
			setRECT(&vp_rect, 0, 0, (Game_display_width / 2) - 1, Game_display_height);
			Game_viewport0 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_2P, 3);
			Game_viewport0->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport0->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport0, SYSTEM_VIEWPORT_VIEWDIST);
			Game_viewport0->vp_aspect_matrix.m[0][0] = 0x1000;
			Game_viewport0->vp_flags 		|= MR_VP_NO_ASPECT;
	
			setRECT(&vp_rect, (Game_display_width / 2) + 1, 0, (Game_display_width / 2) - 1, Game_display_height);
			Game_viewport1 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_2P, 3);
			Game_viewport1->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport1->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport1, SYSTEM_VIEWPORT_VIEWDIST);
			Game_viewport1->vp_aspect_matrix.m[0][0] = 0x1000;
			Game_viewport1->vp_flags 		|= MR_VP_NO_ASPECT;
			break;
		//-----------------------------------------------------------------------
		case 4:
			// Quadruple viewport
			setRECT(&vp_rect, (Game_display_width / 2) + 1, (Game_display_height / 2) + 1, (Game_display_width / 2) - 1, (Game_display_height / 2) - 1);
			Game_viewport3 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_4P, 3);
			Game_viewport3->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport3->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport3, SYSTEM_VIEWPORT_VIEWDIST);

		case 3:
			// Triple viewport
			setRECT(&vp_rect, 0, 0, (Game_display_width / 2) - 1, (Game_display_height / 2) - 1);
			Game_viewport0 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_4P, 3);
			Game_viewport0->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport0->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport0, SYSTEM_VIEWPORT_VIEWDIST);

			setRECT(&vp_rect, (Game_display_width / 2) + 1, 0, (Game_display_width / 2) - 1, (Game_display_height / 2) - 1);
			Game_viewport1 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_4P, 3);
			Game_viewport1->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport1->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport1, SYSTEM_VIEWPORT_VIEWDIST);

			setRECT(&vp_rect, 0, (Game_display_height / 2) + 1, (Game_display_width / 2) - 1, (Game_display_height / 2) - 1);
			Game_viewport2 					= MRCreateViewport(&vp_rect, NULL, SYSTEM_VIEWPORT_OT_SIZE_4P, 3);
			Game_viewport2->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
			Game_viewport2->vp_perspective	= Game_perspective;
			MRSetViewportViewDistance(Game_viewport2, SYSTEM_VIEWPORT_VIEWDIST);
			break;
		//-----------------------------------------------------------------------
		}

	// Set up hud viewport last (so it appears in front)
	Game_viewporth 					= MRCreateViewport(NULL, NULL, /*MR_VP_SIZE_4*/SYSTEM_VIEWPORT_OT_SIZE_2P, 2);
	Game_viewporth->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);
	Game_viewporth->vp_perspective	= Game_perspective;
	MRSetViewportViewDistance(Game_viewporth, MR_VP_VIEWDIST_8192);
	
	Game_viewports[0]				= Game_viewport0;
	Game_viewports[1] 				= Game_viewport1;
	Game_viewports[2] 				= Game_viewport2;
	Game_viewports[3] 				= Game_viewport3;
	Game_viewports[4] 				= NULL;

	// Set up clearing tiles/borders
	for (i = 0; i < Game_total_viewports; i++)
		{
#ifdef GAME_VIEWPORT_BORDERS
		line_f3 = Game_viewport_borders[i][0];
		x0		= Game_viewports[i]->vp_disp_inf.x - (i & 1);
		y0		= Game_viewports[i]->vp_disp_inf.y - (i >> 1);
		x1		= Game_viewports[i]->vp_disp_inf.w + x0;
		y1		= Game_viewports[i]->vp_disp_inf.h + y0;
		if (Game_total_viewports <= 2)
			y1--;
			
		for (j = 0; j < 2; j++)
			{
			MR_COPY32(line_f3->r0, Game_border_colours[Frog_player_data[i].fp_player_id]);
			setLineF3(line_f3);
			line_f3->x0 = x0;
			line_f3->x1 = x1;
			line_f3->x2 = x1;
			line_f3->y0 = y0;
			line_f3->y1 = y0;
			line_f3->y2 = y1;
			line_f3++;
			MR_COPY32(line_f3->r0, Game_border_colours[Frog_player_data[i].fp_player_id]);
			setLineF3(line_f3);
			line_f3->x0 = x0;
			line_f3->x1 = x0;
			line_f3->x2 = x1;
			line_f3->y0 = y0;
			line_f3->y1 = y1;
			line_f3->y2 = y1;
			line_f3++;
			}
#endif
		}
}


/******************************************************************************
*%%%% GameSetViewportsPerspective
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameSetViewportsPerspective(MR_VOID)
*
*	FUNCTION	Sets all viewports vp_perspective from Game_perspective
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameSetViewportsPerspective(MR_VOID)
{
	MR_ULONG		i;


	for (i = 0; i < Game_total_viewports; i++)
		Game_viewports[i]->vp_perspective = Game_perspective;
}


/******************************************************************************
*%%%% GameKillViewports
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameKillViewports(MR_VOID)
*
*	FUNCTION	Kill game viewports
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	07.08.97	Gary Richards	Added code to clear VP pointers once they have
*								been kill.
*	02.09.97	Gary Richards 	Added code to remove the ClearTile viewport.
*
*%%%**************************************************************************/

MR_VOID	GameKillViewports(MR_VOID)
{
	if (Game_viewport0)
		{
		MRKillFrame(Game_viewport0->vp_camera);
		MRKillViewport(Game_viewport0);
		Game_viewport0	  = NULL;					
		Game_viewports[0] = NULL;
		}

	if (Game_viewport1)
		{
		MRKillFrame(Game_viewport1->vp_camera);
		MRKillViewport(Game_viewport1);
		Game_viewport1    = NULL;	
		Game_viewports[1] = NULL;				
		}

	if (Game_viewport2)
		{
		MRKillFrame(Game_viewport2->vp_camera);
		MRKillViewport(Game_viewport2);
		Game_viewport2 	  = NULL;					
		Game_viewports[2] = NULL;
		}

	if (Game_viewport3)
		{
		MRKillFrame(Game_viewport3->vp_camera);
		MRKillViewport(Game_viewport3);
		Game_viewport3 	  = NULL;					
		Game_viewports[3] = NULL;
		}

	if (Game_viewporth)
		{
		MRKillFrame(Game_viewporth->vp_camera);
		MRKillViewport(Game_viewporth);
		Game_viewporth = NULL;					
		}

#ifdef GAME_CLEAR_USING_TILES
	// Set up clearing viewport first (so it appears behind)
	if (Game_viewportc)
		{
		MRKillViewport(Game_viewportc);
		Game_viewportc = NULL;
		}
#endif

}


/******************************************************************************
*%%%% GameAddObjectToViewports
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameAddObjectToViewports(
*						MR_OBJECT*	object)
*
*	FUNCTION	Add object to all game viewports
*
*	INPUTS		object	-	ptr to object to add
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameAddObjectToViewports(MR_OBJECT*	object)
{
	MR_ULONG		i;
	MR_VIEWPORT**	vp_pptr;
  
	vp_pptr 	= Game_viewports;
	i			= Game_total_viewports;
	while(i--)
		{
		MRAddObjectToViewport(object, *vp_pptr, NULL);
		vp_pptr++;
		}
}


/******************************************************************************
*%%%% GameAddObjectToViewportsStoreInstances
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameAddObjectToViewportsStoreInstances(
*						MR_OBJECT*		object,
*						MR_MESH_INST**	inst_pptr)
*
*	FUNCTION	Add object to all game viewports, store instance ptrs
*
*	INPUTS		object		-	ptr to object to add
*				inst_pptr	-	ptr to array of 4 MR_MESH_INST*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameAddObjectToViewportsStoreInstances(	MR_OBJECT*		object,
												MR_MESH_INST**	inst_pptr)
{
	MR_ULONG		i;
	MR_VIEWPORT**	vp_pptr;


	vp_pptr 	= Game_viewports;
	i			= Game_total_viewports;
	while(i--)
		{
		*inst_pptr = MRAddObjectToViewport(object, *vp_pptr, NULL);
		vp_pptr++;
		inst_pptr++;
		}
}


/******************************************************************************
*%%%% GameAddAnimEnvToViewports
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameAddAnimEnvToViewports(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Add anim env to all game viewports
*
*	INPUTS		env	-	ptr to MR_ANIM_ENV to add
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameAddAnimEnvToViewports(MR_ANIM_ENV*	env)
{
	MR_ULONG		i;
	MR_VIEWPORT**	vp_pptr;


	vp_pptr 	= Game_viewports;
	i			= Game_total_viewports;
	while(i--)
		{
		MRAnimAddEnvToViewport(env, *vp_pptr, NULL);
		vp_pptr++;
		}
}


/******************************************************************************
*%%%% GameAddAnimEnvToViewportsStoreInstances
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameAddAnimEnvToViewportsStoreInstances(
*						MR_ANIM_ENV*		env,
*						MR_ANIM_ENV_INST**	inst_pptr)
*
*	FUNCTION	Add anim env to all game viewports, store instance ptrs
*
*	INPUTS		env			-	ptr to env to add
*				inst_pptr	-	ptr to array of 4 MR_ANIM_ENV_INST*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameAddAnimEnvToViewportsStoreInstances(	MR_ANIM_ENV*		object,
													MR_ANIM_ENV_INST**	inst_pptr)
{
	MR_ULONG		i;
	MR_VIEWPORT**	vp_pptr;


	vp_pptr 	= Game_viewports;
	i			= Game_total_viewports;
	while(i--)
		{
		*inst_pptr = MRAnimAddEnvToViewport(object, *vp_pptr, NULL);
		vp_pptr++;
		inst_pptr++;
		}
}


/******************************************************************************
*%%%% GameUpdateLogic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameUpdateLogic(MR_VOID)
*
*	FUNCTION	Game logic main loop, runs everything important to the game logic.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*	18.06.97	William Bell	Added pause mode stuff
*	23.06.97	Martin Kift		Added win95 network sync stuff
*
*%%%**************************************************************************/

MR_VOID	GameUpdateLogic(MR_VOID)
{
	MR_ULONG	i;

#ifdef WIN95
	// Inc the global frame rate counter, this is very important since it allows
	// us to keep track on which frame we are on.
	Main_global_frame_count++;
#endif

	// Is game paused ?
	if ( !(Game_flags & GAME_FLAG_PAUSED) )
		{
		// No ... process logic
		UnlinkEntities();
		UpdatePathRunners();
		UpdateLiveEntities();
		LinkEntities();
		UpdateFrogs();
		UpdateCameras();

		MRUpdateFrames();
		MRUpdateObjects();

		UpdateFrogAnimationScripts();
		MRAnimUpdateEnvironments();
		MRUpdateMeshesAnimatedPolys();
		MapUpdateAnimatedPolys();
		MRUpdateViewport2DSpriteAnims(Game_viewporth);

		MRUpdateViewportRenderMatrices();

		UpdateScoreSprites();
		UpdateEffects();

		if (Map_wibble_water.ww_vertices_ptr)
			WaterWibbleVertices(Map_wibble_water.ww_vertices_ptr, Map_wibble_water.ww_num_vertices);
		}

	for (i = 0; i < Game_total_viewports; i++)
		CreateMapViewList(i);
	for (i = 0; i < Game_total_viewports; i++)
		CreateMapGroups(i);

	// Are we paused ?
	if ( !(Game_flags & GAME_FLAG_PAUSED) )
		// No ... do sky landscape
		UpdateSkyLand();

	// Are we playing back ?
	if ( Game_flags & GAME_FLAG_DEMO_RUNNING )
		{
		// Yes: decrease demo timer
		if (Demo_time > 0)
			Demo_time--;
		}
}


/******************************************************************************
*%%%% GameUpdateDebug
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	GameUpdateDebug(MR_VOID)
*
*	FUNCTION	Game mainloop for debug code
*
*	RESULTS		TRUE if debug options is showing, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.06.97	Martin Kift		Created
*	10.06.97	Gary Richards	Updated so that L1 + R1 toggle cheat mode.
*	18.08.97	Gary Richards	Remove Cheat Stuff, cos it's going in the game.
*
*%%%**************************************************************************/

MR_BOOL GameUpdateDebug(MR_VOID)
{
	MR_ULONG		i;

#ifdef	MR_DEBUG_DISPLAY
#ifdef	GAME_USE_MAPDEBUG_MENU
	// Debug screen
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_START))
		{
		Map_debug_options_show = (Map_debug_options_show) ? FALSE : TRUE;
		}
#endif
#endif

	// Look at map debug show flag, if on, need to render enough to keep system happy
	if (Map_debug_options_show == TRUE)
		{
#ifdef WIN95
		MRReadInput();
#endif
		for (i = 0; i < Game_total_viewports; i++)
			{
			CreateMapViewList(i);
			CreateMapGroups(i);
			}
		for (i = 0; i < Game_total_viewports; i++)
			{
			MRRenderViewport(Game_viewports[i]);
			RenderMap(i);
			}

		UpdateHUD();
		MRRenderViewport(Game_viewporth);
		}

	UpdateMapDebugDisplay();

	// This remains the default viewport for all debug display code
	MRSetActiveViewport(Game_viewport0);

#ifdef PSX
#ifndef	PSX_RELEASE
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_LEFT_1) && MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_RIGHT_1))
		Cheat_control_toggle = TRUE;
	else
		Cheat_control_toggle = FALSE;
#endif
#endif
	return TRUE;
}


/******************************************************************************
*%%%% GameMainloop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloop(MR_VOID)
*
*	FUNCTION	Game mainloop
*
*	NOTES		On the pc we need to lock the frame rate, so here goes a nastyish 
*				piece of code. Note that this code goes around the logic part of 
*				this main game loop and not the render part, which is allowed to 
*				go at whatever speed it can manage!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Added lots of WIN95 code... sorry for all the
*								#ifdef's, I've tried to minimise them, but the
*								constant framerate code makes it a bit messy! :/
*	30.05.97	William Bell	Removed loop stuff, so that this routine is now
*								one frame only.  Needed for demo mode.  Also removed
*								stuff handled by options loop, such as DrawSync etc.
*	09.05.97	Martin Kift		Restructured and tidied up
*	11.06.97	Gary Richards	Added new Joypad control systems. 
*	18.06.97	William Bell	Added pause mode stuff
*	05.07.07	Martin Kift		Moved bulk to GameMainLoopPlay
*
*%%%**************************************************************************/

MR_VOID	GameMainloop(MR_VOID)
{
	MR_ULONG		i;
	FROG*			frog;
	MR_LONG			counter;			// Number of logic frames to process

#ifdef WIN95
	// We need to wait at this point (its virtually the start of a frame, as near
	// as dammit) for all machines to be happy that they are on this frame of the
	// game. So init and wait for a sync message on this frame
	if (Game_is_network)
		GameNetworkSync();
#endif

#ifdef GAME_PAUSABLE
	// Are we in demo mode ?
	if (!(Game_flags & GAME_FLAG_DEMO_RUNNING))
		{
		// Are we in hud intro ?
		if ( !Game_hud_script )
			{
			// No ... check for all important JoyPads.
			CheckJoyPadStillPresent();
			// Do pause stuff
			GamePause();
			// Select reset stuff.
			GameSelectReset();
			}
		}

#endif	// GAME_PAUSEABLE

	MRDebugStartDisplay();

#ifdef PSX	
//	MRStartGatso();
//	FASTSTACK;
#endif		

	MRSetActiveViewport(Game_viewport0);
	StartHUD();

  	if (Game_running == TRUE)
		{
#ifdef DEBUG
		// Update debug (panel) display
		GameUpdateDebug();
#endif
		// If no debug panel, run game
		if (Map_debug_options_show == FALSE)
			{
#ifdef PSX	//-psx specific code-----------------------------------------------------------
			GameUpdateLogic();					// Update main game logic
#else		//-windows specific code-------------------------------------------------------
			GameUpdateWin95();

			if (!Game_is_network)
				{
				// Copy frame rate to local version
				counter = Main_frame_count;

				// Are there any logic frames to do ?
				if (0 == counter)
					{
					while (0 == Main_frame_count);
					counter = Main_frame_count;
					}
		
				Main_frame_count = 0;

				// If we're going really slowly, slow the game down rather than making it hugely jerky
				// But don't do this in network mode, it'll cause even more problems
				if (counter > MAX_LOGIC_LOOPS_PER_RENDER)
					counter = MAX_LOGIC_LOOPS_PER_RENDER;

#ifdef MR_DEBUG
				Map_debug_frame_rate = 30 / counter;
#endif

				// Do first frame of game update. There will always be a frame to do
				GameUpdateLogic();

				// if there are any more frames needed, do them now. We need to recall
				// update input and sound, since these are separate from the main logic update
				while (--counter)
					{
					MRReadInput();
					MRSNDUpdateSound();
					GameUpdateLogic();					// Update main game logic
					}
				}
			else
				GameUpdateLogic();						// Update main game logic

#endif		//-end of specific code--------------------------------------------------------

			// Update HUD left to last since it does rendering
			UpdateHUD();

			// Render specific frog effects. There is only one at the moment (the multiplayer explosion),
			// and if any more arrive that need to go here, I'll move the lot out to a separate function.
			frog	= Frogs;
			counter = Game_total_players;
			while (counter--)
				{
				if	(
					(frog->fr_poly_piece_pop) &&
					(frog->fr_poly_piece_pop->pp_timer)
					)
					{
					for (i = 0; i < Game_total_viewports; i++)
						RenderPolyPiecePop(frog->fr_poly_piece_pop, ((MR_ANIM_ENV_INST*)frog->fr_api_insts[i])->ae_mesh_insts[0], i);
					}
				frog++;
				}	

			// Render
#ifdef GAME_CLEAR_USING_TILES
			addPrim(Game_viewportc->vp_work_ot, &Game_clear_tiles[MRFrame_index]);
			MRRenderViewport(Game_viewportc);
#endif
			for (i = 0; i < Game_total_viewports; i++)
				{
				MRRenderViewport(Game_viewports[i]);
				MRUpdateViewportMeshInstancesAnimatedPolys(Game_viewports[i]);
				}
			for (i = 0; i < Game_total_viewports; i++)
				{
				MRSetActiveViewport(Game_viewports[i]);
				RenderMap(i);
				}

			UpdateMultiplayerHUDbackgrounds();
			MRRenderViewport(Game_viewporth);

#ifdef DEBUG
			// This remains the default viewport for all debug display code
			MRSetActiveViewport(Game_viewport0);
#endif

			// count down start timer
			if (Game_start_timer)
  				Game_start_timer--;

			// Call game main loop callback
			if (Game_mode < GAME_MODE_MAX)
				{
				if (Game_mainloop_update_functions[Game_mode])
					(Game_mainloop_update_functions[Game_mode])();
				}
			}
		}

#ifdef PSX	
//	SLOWSTACK;
	MRGetMemoryStats();
//	MRStopGatso();
//	ProgressMonitor();
#endif		
}

/******************************************************************************
*%%%% GameMainloopPlayUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopPlayUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop play update function
*
*	NOTES		On the pc we need to lock the frame rate, so here goes a nastyish 
*				piece of code. Note that this code goes around the logic part of 
*				this main game loop and not the render part, which is allowed to 
*				go at whatever speed it can manage!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopPlayUpdate(MR_VOID)
{
	// If not paused, handle timer update
	if (!(Game_flags & GAME_FLAG_PAUSED))
		{
		Game_timer++;

#ifdef GAME_TIMER_DECREASE
		// Are we in arcade mode ?
		if ( Sel_mode == SEL_MODE_ARCADE )
			{
			// Yes ... only Decrease timer IF timer cheat is OFF
			if (Cheat_time_toggle == FALSE)
				{
				if (Game_map_timer)
					{
			  		Game_map_timer -=  ( Game_map_timer_speed >> 16 );

					// Check to make sure the timer never goes below zero.
					if (Game_map_timer <= 0)
						Game_map_timer = 0;
					}
				}
			}
#endif	// GAME_TIMER_DECREASE
		}
	
	// Check end of level conditions
	GameCheckStatus();

// Only on a Dev Kit.
#ifndef	PSX_RELEASE
#ifdef	PSX
#ifdef	GAME_ALLOW_RECORDING
	// Recording demo ?
	if ( Recording_demo == TRUE )
		{
		// Yes ... has demo finished ?
		if ( ++Demo_time == (MAX_DEMO_TIME-1) )
			{
			// Yes ... stop recording
			Recording_demo = FALSE;

			// Complete number of frames
			Demo_data.dd_num_frames = Demo_time;

			// Save data
			MRSaveFile(&Demo_file_name[Game_map][0],(MR_ULONG*)&Demo_data,sizeof(DEMO_DATA));

			// Change background colour
			MRSetDisplayClearColour(0x00,0x00,0x00);

			// Free text area used to inform user of "recording" status
			MRFreeTextArea(Recording_demo_text_area);
			}
		else
			{
			// No ... inform user "demo recording"
			MRBuildText(Recording_demo_text_area,Recording_demo_text,MR_FONT_COLOUR_WHITE);
			}
		}

	// Was start recording demo pressed ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_LEFT_2 ) )
		{
		// Yes ... is demo already recording ?
		if ( Recording_demo == FALSE )
			{
			// No ... set up ready for start recording demo mode
			Demo_data_input_ptr = &Demo_data.dd_input_data[0];
			Demo_time = 0;
			Recording_demo = TRUE;

			// Store frog position
			Demo_data.dd_start_grid_x = Frogs[0].fr_grid_x;
			Demo_data.dd_start_grid_z = Frogs[0].fr_grid_z;
				
			// Reset entities to start position
			Map_general_header->gh_start_x = Demo_data.dd_start_grid_x;
			Map_general_header->gh_start_z = Demo_data.dd_start_grid_z;
//			SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);

			Frogs[0].fr_start_grid_x = Map_general_header->gh_start_x;
			Frogs[0].fr_start_grid_z = Map_general_header->gh_start_z;

			LevelEnd();
			LevelStart(GAME_MODE_LEVEL_FAST_START);

			// Change background colour
			MRSetDisplayClearColour(0xFF,0xFF,0xFF);

			// Allocate text area to inform user of "recording" status
			Recording_demo_text_area = MRAllocateTextArea(NULL, &std_font, Game_viewporth, 100, 0, (Game_display_height>>1)-70, Game_display_width, 16);
			}
		}

	// Was stop recording demo pressed ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_RIGHT_2 ) )
		{
		// Yes ... is demo recording ?
		if ( Recording_demo == TRUE )
			{
			// Yes ... stop recording
			Recording_demo = FALSE;
	
			// Complete number of frames
			Demo_data.dd_num_frames = Demo_time;

			// Save data
			MRSaveFile(&Demo_file_name[Game_map][0],(MR_ULONG*)&Demo_data,sizeof(DEMO_DATA));
			
			// Change background colour
			MRSetDisplayClearColour(0x00,0x00,0x00);

			// Free text area used to inform user of "recording" status
			MRFreeTextArea(Recording_demo_text_area);
			}
		}

#endif	// GAME_ALLOW_RECORDING
#endif	// PSX
#endif	// PSX_RELEASE
}

/******************************************************************************
*%%%% GameCheckStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG status =	GameCheckStatus(MR_VOID)
*
*	FUNCTION	Checks the status of the current game, to see if check points
*				have all been reached, time limit has alapsed, etc.
*	
*	NOTES		This function sets a game flag which indicates how the game
*				is reseting. This can be used for a multitude of purposes.

*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.04.97	Martin Kift		Created
*	09.06.97	Martin Kift		Made game flags a global resource.
*
*%%%**************************************************************************/

MR_VOID GameCheckStatus(MR_VOID)
{
	MR_ULONG	frog_index;
	MR_BOOL		frogs_left;
	FROG*		frog;
	MR_TEXTURE*	texture;

	// Are we in demo mode ?
	if ( !(Game_flags & GAME_FLAG_DEMO_RUNNING) )
		{
		// No ... check points
		if (Checkpoints == GEN_ALL_CHECKPOINTS)
			{
			// Go on to level complete
			if (Game_total_players == 1)
				SetGameMainloopMode(GAME_MODE_SINGLE_COMPLETE);
			else
				SetGameMainloopMode(GAME_MODE_MULTI_COMPLETE);

			// this overrides all other concerns, so return NOW
			return;
			}

		// Game flow timer
		if (!Game_map_timer)
			{
			// Mark frogs as inactive...
			frog_index	= Game_total_players;
			frog		= &Frogs[0];
			while (frog_index--)
				{
				frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
				frog++;
				}

			// Only have to check Frogs[0] is not jumping
			if (Frogs[0].fr_mode != FROG_MODE_JUMPING)
				{
				// Are we displaying message ?
				if ( Time_out_message_count )
					{
					// Yes ... first time in ?
					if ( Time_out_message_count == (TIME_OUT_MESSAGE_LEN-1) ) 
						{
						// Yes ... create sprite saying "TIME OUT"
						texture = Options_text_textures[OPTION_TEXT_TIMEOUT][Game_language];
						Animlist_time_out[5] = (MR_ULONG)texture;
						Animlist_time_out[7] = (MR_ULONG)texture;
						Animlist_time_out[9] = (MR_ULONG)texture;
						Animlist_time_out[11] = (MR_ULONG)texture;
						Animlist_time_out[13] = (MR_ULONG)texture;
						MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)-(texture->te_h>>1),Game_viewporth,&Animlist_time_out[0],NULL);
	
						// Kill off frogs
						frog_index	= Game_total_players;
						frog		= &Frogs[0];
						while (frog_index--)
							{
							FrogKill(frog, FROG_ANIMATION_TIMEOUT, NULL);
							frog++;
							}
						}
	
					// Dec count
					Time_out_message_count--;
					}
				else
					{
					// No ... reset message count
					Time_out_message_count = TIME_OUT_MESSAGE_LEN;
	
					Game_reset_flags |= GAME_RESET_TIME_OUT;
					
					// set of a 'frog died' restart, and play a tune
					if (Game_total_players == 1)
						SetGameMainloopMode(GAME_MODE_SINGLE_FROG_DIED);
					else
						SetGameMainloopMode(GAME_MODE_MULTI_FROG_DIED);
	
					// instead of returning here, we should let continue to below, where the
					// game checks to see if any frogs are left... the game will go to game over
					// if this isn't the game, rather than frog died
					}
				}
			}

		// Check all frog active flags, if one has died, return END
		frog_index	= Game_total_players;
		frog		= Frogs;
		frogs_left	= FALSE;
		while (frog_index--)
			{
			if (frog->fr_flags & FROG_ACTIVE)
				{
				frogs_left = TRUE;
				break;
				}
			frog++;
			}

		if (frogs_left == FALSE)
			{
			Game_reset_flags |= GAME_RESET_FROGS_DEAD;
			Option_page_request = OPTIONS_PAGE_GAME_OVER;
			}
		}
}

#ifdef WIN95

/******************************************************************************
*%%%% GameUpdateWin95
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameUpdateWin95(MR_VOID)
*
*	FUNCTION	Allows user to set caps of the display, and play with screen
*				dimensions.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameUpdateWin95(MR_VOID)
{
	static MR_ULONG ulCaps = 0;
	static MR_LONG	width = 640;
	static MR_LONG	height = 480;
	static MR_LONG	last_key = 0;			// Last key pressed
	static MR_ULONG	curr_tpage = 0;
	static MR_ULONG	ul = 0;

	#define GAME_KEY_PRINT_SCREEN			(1<<0)
	#define GAME_KEY_COLLISION				(1<<1)
	#define GAME_KEY_CHEAT					(1<<2)
	#define GAME_KEY_TIME					(1<<3)
	#define GAME_KEY_LIVES					(1<<4)
	#define GAME_KEY_VRAM					(1<<5)
	#define GAME_KEY_VRAM_PLUS				(1<<6)
	#define GAME_KEY_VRAM_MINUS				(1<<7)
	#define GAME_KEY_CAPS_FILTER			(1<<8)
	#define GAME_KEY_CAPS_PERSPEC			(1<<9)
	#define GAME_KEY_CHECKPOINTS			(1<<10)

	if (MR_KEY_DOWN(MRIK_F1))
		{
		if (!(last_key & GAME_KEY_CAPS_FILTER))
			{
			last_key |=  GAME_KEY_CAPS_FILTER;

			if (ul & MR_RENDERSTATE_FILTER)
				{
				ul &= ~MR_RENDERSTATE_FILTER;
				MRSetRenderCaps(MR_RENDERSTATE_FILTER, 0);
				}
			else
				{
				ul |= MR_RENDERSTATE_FILTER;
				MRSetRenderCaps(MR_RENDERSTATE_FILTER, 1);
				}
			}
		}
	else
		last_key &=  ~GAME_KEY_CAPS_FILTER;

	if (MR_KEY_DOWN(MRIK_F2))
		{
		if (!(last_key & GAME_KEY_CAPS_PERSPEC))
			{
			last_key |=  GAME_KEY_CAPS_PERSPEC;

			if (ul & MR_RENDERSTATE_PERSPECTIVE)
				{
				ul &= ~MR_RENDERSTATE_PERSPECTIVE;
				MRSetRenderCaps(MR_RENDERSTATE_PERSPECTIVE, 0);
				}
			else
				{
				ul |= MR_RENDERSTATE_PERSPECTIVE;
				MRSetRenderCaps(MR_RENDERSTATE_PERSPECTIVE, 1);
				}
			}
		}
	else
		last_key &=  ~GAME_KEY_CAPS_PERSPEC;


	// debug break just in case
	if (MR_KEY_DOWN(MRIK_V))
		{
		last_key |= GAME_KEY_VRAM;
		MRDebugDisplayTPage(NULL, curr_tpage);

		if (MR_KEY_DOWN(MRIK_N))
			{
			if (!(last_key & GAME_KEY_VRAM_PLUS))
				{
				last_key |= GAME_KEY_VRAM_PLUS;
				curr_tpage++;
				if (curr_tpage >= 14)
					curr_tpage = 0;
				}
			}
		else
			last_key &= ~GAME_KEY_VRAM_PLUS;

		if (MR_KEY_DOWN(MRIK_B))
			{
			if (!(last_key & GAME_KEY_VRAM_MINUS))
				{
				last_key |= GAME_KEY_VRAM_MINUS;
				if (curr_tpage == 0)
					curr_tpage = 13;
				else
					curr_tpage--;
				}
			}
		else
			last_key &= ~GAME_KEY_VRAM_MINUS;
		}
	else
		last_key &= ~GAME_KEY_VRAM;

	if (MR_KEY_DOWN(MRIK_F5))
		{
		if (!(last_key & GAME_KEY_CHECKPOINTS))
			{
			last_key |=  GAME_KEY_CHECKPOINTS;

			Checkpoints |= (1<<0);
			Checkpoints |= (1<<1);
			Checkpoints |= (1<<2);
			Checkpoints |= (1<<3);
			Checkpoints |= (1<<4);
			}
		}
	else
		last_key &=  ~GAME_KEY_CHECKPOINTS;

	// show vram
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;

	// Has debug key been pressed?
	if (MR_KEY_DOWN(MRIK_LALT))
		{
		// Print screen?
		if (MR_KEY_DOWN(MRIK_S))
			{
			MRDebugGrabScreen();
			last_key |= GAME_KEY_PRINT_SCREEN;
			}
		else
			last_key &= ~GAME_KEY_PRINT_SCREEN;
		}

	if (MR_KEY_DOWN(MRIK_LALT))
		{
		Cheat_control_toggle = TRUE;
		MRSetDisplayClearColour(0x88,0x00,0x88);			// Purple for CHEAT MODE.
		}
	else
		{
		Cheat_control_toggle = FALSE;

		// Only turn background back, IF collision mode off.
		if (Cheat_collision_toggle == FALSE)
			MRSetDisplayClearColour(Game_back_colour[Game_map].r, Game_back_colour[Game_map].g, Game_back_colour[Game_map].b);
		}	

	// We are in CHEAT MODE, so lets processes these controls.
	if (Cheat_control_toggle == TRUE)
		{
		// Toggle Collision ON/OFF. Death collision with entities is OFF when the screen is RED.
		if (MR_KEY_DOWN(MRIK_C))
			{
			if (!(last_key & GAME_KEY_COLLISION))
				{
				if (Cheat_collision_toggle == TRUE)
					{
					DisplayHUDHelp(0, HUD_ITEM_HELP_COLLISION_ON);
					Hud_item_help_flags[0][HUD_ITEM_HELP_COLLISION_ON] 	= 0;
					Cheat_collision_toggle = FALSE;								// Collision Cheat OFF
					MRSetDisplayClearColour(0xFF,0x00,0x00);					// Red screen on.
					}
				else
					{
					DisplayHUDHelp(0, HUD_ITEM_HELP_COLLISION_OFF);
					Hud_item_help_flags[0][HUD_ITEM_HELP_COLLISION_OFF] 	= 0;
					Cheat_collision_toggle = TRUE;			// Collision Cheat ON.
					MRSetDisplayClearColour(Game_back_colour[Game_map].r, Game_back_colour[Game_map].g, Game_back_colour[Game_map].b);
					}
				last_key |= GAME_KEY_COLLISION;
				}
			}
		else
			last_key &= ~GAME_KEY_COLLISION;


		// Toggle Time ON/OFF.
		if (MR_KEY_DOWN(MRIK_T))
			{
			if (!(last_key & GAME_KEY_TIME))
				{
				if (Cheat_time_toggle == TRUE)
					{
					DisplayHUDHelp(0, HUD_ITEM_HELP_TIMER_ON);
					Hud_item_help_flags[0][HUD_ITEM_HELP_TIMER_ON] = 0;
					Cheat_time_toggle = FALSE;				// Time Cheat OFF.
					}
				else
					{
					DisplayHUDHelp(0, HUD_ITEM_HELP_TIMER_OFF);
					Hud_item_help_flags[0][HUD_ITEM_HELP_TIMER_OFF]	= 0;
					Cheat_time_toggle = TRUE;				// Time Cheat ON.
					}
				last_key |= GAME_KEY_TIME;
				}
			}
		else
			last_key &= ~GAME_KEY_TIME;

		// Toggle Infinite lives ON/OFF.
		if (MR_KEY_DOWN(MRIK_L))
			{
			if (!(last_key & GAME_KEY_LIVES))
				{
				if (Cheat_infinite_lives_toggle == TRUE)
					{
					DisplayHUDHelp(0, HUD_ITEM_HELP_INFINITE_LIVES_ON);					
					Hud_item_help_flags[0][HUD_ITEM_HELP_INFINITE_LIVES_ON]	= 0;
					Cheat_infinite_lives_toggle = FALSE;		// Infinite Cheat OFF.
					}
				else
					{															
					DisplayHUDHelp(0, HUD_ITEM_HELP_INFINITE_LIVES_OFF);					
					Hud_item_help_flags[0][HUD_ITEM_HELP_INFINITE_LIVES_OFF] = 0;
					Cheat_infinite_lives_toggle = TRUE;			// Infinite Cheat ON.
					}
				last_key |= GAME_KEY_LIVES;
				}
			}
		else
			last_key &= ~GAME_KEY_LIVES;
		}

	// screen sizes
	if (MR_KEY_DOWN(MRIK_SUBTRACT))
	{
		MR_RECT		des;
	
		if (width>320)
		{
			width	-= 4;
			height	= (width*480)/640;

			des.w	= width;
			des.h	= height;
			des.x = (640 - width)>>1;
			des.y = (480 - height)>>1;

			MRChangeViewport(Game_viewport0, &des);
		}

	}

	if (MR_KEY_DOWN(MRIK_ADD))
		{
		MR_RECT des;
	
		if (width<640)
			{
			width += 4;
			height = (width*480)/640;

			des.w = width;
			des.h = height;
			des.x = (640 - width)>>1;
			des.y = (480 - height)>>1;

			MRChangeViewport(Game_viewport0, &des);
			}
		}
}


/******************************************************************************
*%%%% GameNetworkSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameNetworkSync(MR_VOID)
*
*	FUNCTION	Network update (specific to Win95). It waits for sync messages
*				from all machines, responds to game specific network msgs, etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameNetworkSync(MR_VOID)
{
	// Kick off a new sync, ready for next frame
	InitialiseSync();
	SendFrameSync();

	// are we waiting for a sync message?
	while (WaitingForSync)
		{
		MNReceiveMessages();
		MRProcessWindowsMessages(NULL);				

		// debug break just in case
		if (MR_KEY_DOWN(MRIK_ESCAPE))
			{
			Option_page_request = OPTIONS_PAGE_EXIT;
			return;
			}
		}

	// check for restart request flag, and do a sync
	if (Game_flags & GAME_FLAG_RESTART_GAME)
		{
		Game_flags &= ~GAME_FLAG_RESTART_GAME;
		if (Game_is_network)
			{
			InitialiseSync();
			;//GameRestartLevel();
			SendSync();
			}
		else
			{
			;//GameRestartLevel();
			}
		}
}


#endif // win95




/******************************************************************************
*%%%% GameMainloopSingleStartUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleStartUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop SINGLE START update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleStartUpdate(MR_VOID)
{
	HUD_ITEM*		item;
	MR_BOOL			finished;

#ifdef GAME_SHOW_SEQUENCES
	// this code only works (and was only designed to work) in single player mode
	MR_ASSERT (Game_total_players == 1);

	// Wait until the a frog (I think one will do) has bounced once, and enter
	// start HUD update
	if (Frogs[0].fr_flags & FROG_JUST_BOUNCED)
		{
		// Create HUD script, but don't execute it yet
		if (!Game_hud_script)
			{
			// Set start texture
			HUD_script_start_level[3].hi_texture = Options_text_textures[OPTION_TEXT_HOP_TO_IT+rand()%6][Game_language];
			Game_hud_script		= SetupHUDScript(HUD_script_start_level, 0);
			Game_map_timer		= (30*6);		// start count up on 6 sec (stops system getting confused)
			}
		// if we haven't already, we need to initialise our HUD script(s)
		if (Game_hud_script)
			{
			UpdateHUDScript(Game_hud_script, 0);

			// We need to wait until the HUD has finished its current script
			finished	= TRUE;
			item		= Game_hud_script;
			while(item->hi_type)
				{
				if (!(item->hi_flags & HUD_ITEM_FINISHED))
					finished = FALSE;
				item++;
				}

			if (finished)
				{
				// Set main loop into level play mode
				SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);
				KillHUDScript(Game_hud_script);
				Game_hud_script = NULL;

				// mark frogs as stationary so they can move
				// try and stop frog bouncing
				Frogs[0].fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
				}
			}
		}

#else //GAME_SHOW_SEQUENCES
	frog		= Frogs;
	frog_number	= Game_total_players;

	while (frog_number--)
		{
		frog->fr_mode	= FROG_MODE_STATIONARY;
		frog++;
		}

	// Set main loop into level play mode
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);
#endif


}

/******************************************************************************
*%%%% GameMainloopMultiStartUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiStartUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop MULTI START update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopMultiStartUpdate(MR_VOID)
{
	// Set main loop into level play mode
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);
}

/******************************************************************************
*%%%% GameMainloopSingleTriggerCollectedSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleTriggerCollectedSetup(MR_VOID)
*
*	FUNCTION	Game mainloop TRIGGER COLLECTED setup function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleTriggerCollectedSetup(MR_VOID)
{
#ifdef GAME_SHOW_SEQUENCES
	FROG*	frog;

	frog = Frogs;

	// this code only works (and was only designed to work) in single player mode
	MR_ASSERT (Game_total_players == 1);

	// No ... start checkpoint animation
	FrogRequestAnimation(frog, FROG_ANIMATION_TRIGGER, 0, 0);

	// init background polys
	InitTransparentPolyBackground((Game_display_width>>1)-100, (Game_display_height>>1)-30, 200, 60);
#endif //GAME_SHOW_SEQUENCES
}

/******************************************************************************
*%%%% GameMainloopSingleTriggerCollectedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleTriggerCollectedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop TRIGGER COLLECTED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleTriggerCollectedUpdate(MR_VOID)
{
#ifdef GAME_SHOW_SEQUENCES
	FROG*			frog;
	MR_BOOL			finished;
	HUD_ITEM*		item;
	ENTITY*			checkpoint;
	MR_BOOL			pop_fin;
	MR_TEXTURE*		texture;
	POLY_PIECE_POP* pop;

	frog = Frogs;

	// this code only works (and was only designed to work) in single player mode
	MR_ASSERT (Game_total_players == 1);

	// Make checkpoint hit explode, and start script straight away boss!
	checkpoint	= Checkpoint_data[Checkpoint_last_collected].cp_entity;
	MR_ASSERT (checkpoint->en_live_entity);

	// if effect hasn't been created, create it now
	if (checkpoint->en_live_entity->le_effect == NULL)
		{
		LiveEntityInitPop(checkpoint->en_live_entity);
		LiveEntityStartPolyPiecePop(checkpoint->en_live_entity);
		}

	pop_fin = TRUE;

	// see if pop has finished
	if (checkpoint->en_live_entity->le_effect)
		{
		pop = (POLY_PIECE_POP*)checkpoint->en_live_entity->le_effect;
		if (pop->pp_timer)
			pop_fin = FALSE;
		}

	// wait until camera zooms, and set off frog
	if 	(
		(!(Cameras[frog->fr_frog_id].ca_move_timer)) &&
		(!(Cameras[frog->fr_frog_id].ca_twist_counter))
		)
		{
		// Wait for pop to end.
		if (pop_fin == TRUE)
			{
			if (!Game_hud_script)
				{
				// Change BONUS sprite
				texture = Options_text_textures[OPTION_TEXT_BONUS][Game_language];
				HUD_script_trigger_collected[2].hi_texture = texture;
				Game_hud_script	= SetupHUDScript(HUD_script_trigger_collected, 0);
				}

			// update background polys
			UpdateTransparentPolyBackground();

			// update hud scrip
			UpdateHUDScript(Game_hud_script, 0);
			
			// We need to wait until the HUD has finished its current script
			finished	= TRUE;
			item		= HUD_script_trigger_collected;
			while(item->hi_type)
				{
				if (!(item->hi_flags & HUD_ITEM_FINISHED))
					finished = FALSE;
				item++;
				}

			if (finished)
				{
				KillHUDScript(Game_hud_script);
				Game_hud_script = NULL;

				// Turn back on the hud frog
				Checkpoint_data[Checkpoint_last_collected].cp_flags &= ~GEN_CHECKPOINT_NO_HUD_UPDATE;

				// Have we collected all check points? If so, go to level complete screen... else
				// restart level so player can continue...
				if (Checkpoints != GEN_ALL_CHECKPOINTS)
					{
					// Continue to next check point
					Game_reset_flags |= GAME_RESET_CHECKPOINT_COLLECTED;

					// Free poly piece
					LiveEntityFreePop(checkpoint->en_live_entity);

					// close down current level, and then start a fresh
					LevelEnd();
					LevelStart(GAME_MODE_LEVEL_PLAY);

					// start game (straight in there)
					SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		
					}
				else
					{
					// Free poly piece
					LiveEntityFreePop(checkpoint->en_live_entity);

					// Go to level complete/zone complete screen
					SetGameMainloopMode(GAME_MODE_SINGLE_COMPLETE);
					}
				}
			}
		}
#else				
	// close down current level, and then start a fresh
	LevelEnd();
	LevelStart();
#endif
}

/******************************************************************************
*%%%% GameMainloopMultiTriggerCollectedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiTriggerCollectedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop MULTIPLAYER TRIGGER COLLECTED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopMultiTriggerCollectedUpdate(MR_VOID)
{
	MR_ULONG	frog_index;
	FROG*		frog;
	MR_BOOL		camera_finished;

	frog				= Frogs;
	frog_index			= 4;
	camera_finished		= TRUE;

	while (frog_index--)
		{
		if	(
			(frog->fr_flags & FROG_ACTIVE) && 
			(frog->fr_flags & FROG_CONTROL_ACTIVE)
			)
			{
			// wait until camera zooms end for all frogs
			if 	(
				(Cameras[frog->fr_frog_id].ca_move_timer) || 
				(Cameras[frog->fr_frog_id].ca_twist_counter)
				)
				{
				camera_finished = FALSE;
				}
			}
		frog++;
		}

	if (camera_finished)
		{
		// set reset flags
		Game_reset_flags |= GAME_RESET_CHECKPOINT_COLLECTED;

		// Turn back on the hud frog
		Checkpoint_data[Checkpoint_last_collected].cp_flags &= ~GEN_CHECKPOINT_NO_HUD_UPDATE;

		// close down current level, and then start a fresh
		LevelEnd();
		LevelStart(GAME_MODE_LEVEL_PLAY);

		// start game (straight in there)
		SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		
		}
}

/******************************************************************************
*%%%% GameMainloopSingleFailedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleFailedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop LEVEL FAILED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleFailedUpdate(MR_VOID)
{
	// close down current level, and then start a fresh
	LevelEnd();

	// Exit with the level over flag
	Option_page_request = OPTIONS_PAGE_CONTINUE;
}


/******************************************************************************
*%%%% GameMainloopMultiFailedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiFailedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop MULTIPLAYER LEVEL FAILED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopMultiFailedUpdate(MR_VOID)
{
	// start game (straight in there)
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		

	// close down current level, and then start a fresh
	LevelEnd();
	LevelStart(GAME_MODE_LEVEL_PLAY);
}

/******************************************************************************
*%%%% GameMainloopSingleFrogDiedSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleFrogDiedSetup(MR_VOID)
*
*	FUNCTION	Game mainloop FROG DIED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleFrogDiedSetup(MR_VOID)
{
	// Check to see if current frog has lost ALL of its lives. If
	// so, jump into level failed 
	if (Frogs[0].fr_lives == 0)
		{
		SetGameMainloopMode(GAME_MODE_SINGLE_FAILED);
		}
}

/******************************************************************************
*%%%% GameMainloopSingleFrogDiedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleFrogDiedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop FROG DIED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleFrogDiedUpdate(MR_VOID)
{
#ifdef GAME_SHOW_SEQUENCES
	// this code only works (and was only designed to work) in single player mode
	MR_ASSERT (Game_total_players == 1);

	// set reset type flag
	Game_reset_flags |= GAME_RESET_FROGS_DEAD;

	LevelEnd();
	LevelStart(GAME_MODE_LEVEL_PLAY);
#else
	// close down current level, and then start a fresh
	LevelEnd();
	LevelStart();
#endif
	// start game (straight in there)
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		
}

/******************************************************************************
*%%%% GameMainloopMultiFrogDiedUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiFrogDiedUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop MULTIPLAYER FROG DIED update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopMultiFrogDiedUpdate(MR_VOID)
{
	// close down current level, and then start a fresh
	LevelEnd();
	LevelStart(GAME_MODE_LEVEL_PLAY);

	// start game (straight in there)
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		
}

/******************************************************************************
*%%%% GameMainloopSingleCompleteUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopSingleCompleteUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop LEVEL COMPLETE update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopSingleCompleteUpdate(MR_VOID)
{
	// wait for frog to finish current anim
	MR_ANIM_ENV_SINGLE*	env_sing;

	env_sing = ((MR_ANIM_ENV*)Frogs[0].fr_api_item)->ae_extra.ae_extra_env_single;
	
	if (env_sing->ae_cel_number >= env_sing->ae_total_cels-1)
		{
		// If we are playing the jungle, then we have no level to go to, and should now
		// play the end of level sequence.. else, close down current level and go to
		// level complete options page
		if (Game_map_theme == THEME_JUN)
			{
			SetGameMainloopMode(GAME_MODE_END_OF_GAME);
			}
		else
			{
			LevelEnd();
			Option_page_request = OPTIONS_PAGE_LEVEL_COMPLETE;
			}

		// Tot up scores, mess with hi score table, etc.
		
		// Has a score already been recorded for this level ?
		if ( Frog_score_data[Game_map][0].he_initials[0] == 'Z' )
			{
			// Yes ... does this score beat your best ?
			if ( Frog_score_data[Game_map][0].he_score < (Frogs[0].fr_score - Frogs[0].fr_prev_score) )
				{
				// Yes ... enter this score
				Frog_score_data[Game_map][0].he_score = Frogs[0].fr_score - Frogs[0].fr_prev_score;
				// Store these times
				Frog_score_data[Game_map][0].he_time_to_checkpoint[0] = Frog_time_data[0];
				Frog_score_data[Game_map][0].he_time_to_checkpoint[1] = Frog_time_data[1];
				Frog_score_data[Game_map][0].he_time_to_checkpoint[2] = Frog_time_data[2];
				Frog_score_data[Game_map][0].he_time_to_checkpoint[3] = Frog_time_data[3];
				Frog_score_data[Game_map][0].he_time_to_checkpoint[4] = Frog_time_data[4];
				}
			}
		else
			{
			// No ... set time to trigger data as valid
			Frog_score_data[Game_map][0].he_initials[0] = 'Z';

			// Store score for this level
			Frog_score_data[Game_map][0].he_score = Frogs[0].fr_score - Frogs[0].fr_prev_score;
			// Store times
			Frog_score_data[Game_map][0].he_time_to_checkpoint[0] = Frog_time_data[0];
			Frog_score_data[Game_map][0].he_time_to_checkpoint[1] = Frog_time_data[1];
			Frog_score_data[Game_map][0].he_time_to_checkpoint[2] = Frog_time_data[2];
			Frog_score_data[Game_map][0].he_time_to_checkpoint[3] = Frog_time_data[3];
			Frog_score_data[Game_map][0].he_time_to_checkpoint[4] = Frog_time_data[4];
			}

		// Set score achieved at end of this level
		Frogs[0].fr_prev_score = Frogs[0].fr_score;
		}
}


/******************************************************************************
*%%%% GameMainloopFastStartUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopFastStartUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop LEVEL COMPLETE update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopFastStartUpdate(MR_VOID)
{
	// close down current level, and then start a fresh
	LevelEnd();
	LevelStart(GAME_MODE_LEVEL_PLAY);

	// start game (straight in there)
	SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);		
}

/******************************************************************************
*%%%% GameMainloopMultiCompleteSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiCompleteSetup(MR_VOID)
*
*	FUNCTION	Game mainloop LEVEL COMPLETE setup function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopMultiCompleteSetup(MR_VOID)
{
	GAME_MULTI_COMPLETE*	multi;
	MR_LONG					i, j;
	MR_LONG					num_winning_frogs, max_checkpoints, checkpoint_count[4];
	MR_LONG					winning_order[4], order_number, curr_check;
	MR_BOOL					found;

	// init data
	Game_mode	= GAME_MODE_MULTIPLAYER_CAMERA;

	// turn off pause
	Game_flags	|= GAME_FLAG_NO_PAUSE_ALLOWED;

	// Mark all frogs as no-control whilst effects are done.
	for (i=0; i<Game_total_players; i++)
		Frogs[i].fr_flags &= ~FROG_CONTROL_ACTIVE;

	// alloc data needed
	Game_mode_data	= MRAllocMem(sizeof(GAME_MULTI_COMPLETE), "GAME_MULTI_COMPLETE");
	multi			= (GAME_MULTI_COMPLETE*)Game_mode_data;

	// create sprites and other stuff needed
	for (i=0; i<Game_total_viewports; i++)
		{
		multi->gm_numbers[i]					= MRCreate2DSprite(0, 0, Game_viewporth, &im_32x32_0, NULL);
		multi->gm_numbers[i]->sp_core.sc_scale	= 0 << 16;
		}

	// setup winning order
	GameGetMultiplayerFrogCheckpointData(checkpoint_count, &max_checkpoints, &num_winning_frogs);

	order_number = 1;
	curr_check	 = max_checkpoints;

	for (i=0; i<4; i++)
		winning_order[i] = 0;

	for (j=0; j<4; j++)
		{
		found = FALSE;
		for (i=0; i<4; i++)
			{
			if (checkpoint_count[i] == curr_check)
				{
				winning_order[i]	= order_number;
				checkpoint_count[i]	= -1;
				found				= TRUE;
				}
			}
		
		if (found == TRUE)
			order_number++;
		curr_check--;
		}

	// setup right number bitmaps for the viewports
	for (i=0; i<Game_total_viewports; i++)
		{
		MRChangeSprite(multi->gm_numbers[i], Hud_timer_images[winning_order[i]]);
		multi->gm_data[i].gm_mode		= GAME_MODE_MULTIPLAYER_DATA_DELAY;
		multi->gm_data[i].gm_counter	= winning_order[i] * 15;
		}

	switch (Game_total_viewports)
		{
		case 2:
			multi->gm_data[0].gm_pos.x = Game_display_width>>2;
			multi->gm_data[0].gm_pos.y = Game_display_height>>1;
			multi->gm_data[1].gm_pos.x = (Game_display_width>>2)*3;
			multi->gm_data[1].gm_pos.y = Game_display_height>>1;
			break;
		case 3:
		case 4:
			multi->gm_data[0].gm_pos.x = Game_display_width>>2;
			multi->gm_data[0].gm_pos.y = Game_display_height>>2;
			multi->gm_data[1].gm_pos.x = (Game_display_width>>2)*3;
			multi->gm_data[1].gm_pos.y = Game_display_height>>2;
			multi->gm_data[2].gm_pos.x = Game_display_width>>2;
			multi->gm_data[2].gm_pos.y = (Game_display_height>>2)*3;
			multi->gm_data[3].gm_pos.x = (Game_display_width>>2)*3;
			multi->gm_data[3].gm_pos.y = (Game_display_height>>2)*3;
			break;
		}

	multi->gm_mode = GAME_MODE_MULTIPLAYER_NUMBER_ZOOM;

	// if number of winnning frogs is 1, then play music
	if (num_winning_frogs == 1)
		MRSNDPlaySound(SFX_MUSIC_LEVEL_COMPLETE,NULL,0,0);
}

  
/******************************************************************************
*%%%% GameMainloopMultiCompleteUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopMultiCompleteUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop LEVEL COMPLETE update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameMainloopMultiCompleteUpdate(MR_VOID)
{
	MR_ULONG				frog_index;
	FROG*					frog;
	MR_ULONG				i, j;
	MR_LONG					max_checkpoints, checkpoint_count[4];
	MR_LONG					num_winning_frogs;
	GEN_CHECKPOINT_DATA*	data;
	MR_BOOL					marked_check;
	MR_BOOL					finished;
	GAME_MULTI_COMPLETE*	multi;

	multi = (GAME_MULTI_COMPLETE*)Game_mode_data;

	// switch on game mode to create flow
	switch (multi->gm_mode)
		{
		//----------------------------------------------------------------------------
		// GAME_MODE_MULTIPLAYER_CAMERA - wait for camera to zoom
		case GAME_MODE_MULTIPLAYER_CAMERA:
			frog				= Frogs;
			frog_index			= 4;
			finished			= TRUE;

			while (frog_index--)
				{
				if	(
					(frog->fr_flags & FROG_ACTIVE) && 
					(frog->fr_flags & FROG_CONTROL_ACTIVE)
					)
					{
					// wait until camera zooms end for all frogs
					if 	(
						(Cameras[frog->fr_frog_id].ca_move_timer) || 
						(Cameras[frog->fr_frog_id].ca_twist_counter)
						)
						{
						finished = FALSE;
						}
					}
				frog++;
				}

			if (finished)
				multi->gm_mode = GAME_MODE_MULTIPLAYER_NUMBER_ZOOM;
			break;

		//----------------------------------------------------------------------------
		// GAME_MODE_MULTIPLAYER_NUMBER_ZOOM - do number zoom
		case GAME_MODE_MULTIPLAYER_NUMBER_ZOOM:

			finished = TRUE;

			for (i=0; i<Game_total_viewports; i++)
				{
				switch (multi->gm_data[i].gm_mode)
					{
					//----------------------------------------------------------------
					case GAME_MODE_MULTIPLAYER_DATA_DELAY:
						if (!(multi->gm_data[i].gm_counter--))
							{
							multi->gm_data[i].gm_mode		= GAME_MODE_MULTIPLAYER_DATA_MOVE;
							multi->gm_data[i].gm_counter	= 30;
							}
						finished = FALSE;
						break;

					//----------------------------------------------------------------
					case GAME_MODE_MULTIPLAYER_DATA_MOVE:
						if (!(multi->gm_data[i].gm_counter--))
							multi->gm_data[i].gm_mode = GAME_MODE_MULTIPLAYER_DATA_END;
						else
							{
							multi->gm_numbers[i]->sp_core.sc_scale += (1<<12);

							// recalc position
							multi->gm_numbers[i]->sp_pos.x = multi->gm_data[i].gm_pos.x - (((Hud_timer_images[0]->te_w>>1) * multi->gm_numbers[i]->sp_core.sc_scale) / (1<<16));
							multi->gm_numbers[i]->sp_pos.y = multi->gm_data[i].gm_pos.y - (((Hud_timer_images[0]->te_h>>1) * multi->gm_numbers[i]->sp_core.sc_scale) / (1<<16));
							}
						finished = FALSE;
						break;

					//----------------------------------------------------------------
					case GAME_MODE_MULTIPLAYER_DATA_END:
						break;
					}
				}

			if (finished == TRUE)
				{
				multi->gm_mode		= GAME_MODE_MULTIPLAYER_NUMBER_ZOOM_WAIT;
				multi->gm_counter	= 30;
				}
			break;

		//----------------------------------------------------------------------------
		// GAME_MODE_MULTIPLAYER_NUMBER_ZOOM_START - init number zoom
		case GAME_MODE_MULTIPLAYER_NUMBER_ZOOM_WAIT:
			if (!(multi->gm_counter--))
				multi->gm_mode = GAME_MODE_MULTIPLAYER_STAT_SCREEN;
			break;

		//----------------------------------------------------------------------------
		// GAME_MODE_MULTIPLAYER_NUMBER_ZOOM_START - init number zoom
		case GAME_MODE_MULTIPLAYER_STAT_SCREEN:
			// turn on pause (default for in game)
			Game_flags &= ~GAME_FLAG_NO_PAUSE_ALLOWED;

			// Look through all checkpoints. If there was no clear winner in the 
			// number of checkpoints collected, then we need to restart the frogs 
			// in first place on a random check point to find an overall winner
			GameGetMultiplayerFrogCheckpointData(checkpoint_count, &max_checkpoints, &num_winning_frogs);

			if (num_winning_frogs == 1)
				{
				SetGameMainloopMode(GAME_MODE_END_OF_MULTIPLAYER_GAME);
				}
			else
				{
				// we have more than one winning frog.. reset game so that these frogs
				// can replay on a checkpoint that a different frog collected...
				frog			= Frogs;
				marked_check	= FALSE;	

				for (i=0; i<4; i++)
					{
					if (checkpoint_count[i] != max_checkpoints)
						{
						// remoce control flag and mark as invisible
						frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
						frog->fr_flags &= ~FROG_ACTIVE;

						// use this checkpoint as one to go for...
						if (marked_check == FALSE)
							{
							data = Checkpoint_data;
							for (j=0; j<GEN_MAX_CHECKPOINTS; j++)
								{
								if	(
									(data->cp_frog_collected_id != -1) && 
									(data->cp_frog_collected_id == frog->fr_frog_id)
									)
									{
									marked_check				= TRUE;
									data->cp_frog_collected_id	= -1;
									Checkpoints					&= ~(1<<j);
									break;
									}
								data++;
								}
							}

						// Show the no-play bitmap, and mark viewport as no-display
						((MR_SP_CORE*)Game_multiplayer_no_player[frog->fr_frog_id])->sc_flags &= ~MR_SPF_NO_DISPLAY;
						Game_viewports[frog->fr_frog_id]->vp_flags |= MR_VP_NO_DISPLAY;
						}
					else
						{
						// Reset
						ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, GAME_MODE_LEVEL_FAST_START);
						ResetCamera(&Cameras[frog->fr_frog_id]);
						SetGameMainloopMode(GAME_MODE_LEVEL_PLAY);
						}
					frog++;
					}
				}

			// clean up
			for (i=0; i<Game_total_viewports; i++)
				MRKill2DSprite(multi->gm_numbers[i]);
			MRFreeMem(Game_mode_data);
			break;
		}
}


		// Tot up scores.. currently commented out since scores are probably being trashed... until
		// of course they change their minds, and then change it back again, and so on...
//		for(loop_counter=0;loop_counter<Game_total_players;loop_counter++)
//			{
//			// Have we already recorded a score for this level ?
//			if ( Frog_score_data[Game_map][loop_counter].he_initials[0] == 'Z' )
//				{
//				// Yes ... is this new score better ?
//				if ( Frog_score_data[Game_map][loop_counter].he_score < Frogs[loop_counter].fr_score - Frogs[loop_counter].fr_prev_score )
//					// Yes ... store this new score ( current score - score at end of last level )
//					Frog_score_data[Game_map][loop_counter].he_score = Frogs[loop_counter].fr_score - Frogs[loop_counter].fr_prev_score;
//				}
//			else
//				{
//				// No ... store score for this level ( current score - score at end of last level )
//				Frog_score_data[Game_map][loop_counter].he_score = Frogs[loop_counter].fr_score - Frogs[loop_counter].fr_prev_score;
//				// Flag score as valid high score data
//				Frog_score_data[Game_map][loop_counter].he_initials[0] = 'Z';
//				}
//			// Set score achieved at end of this level
//			Frogs[loop_counter].fr_prev_score = Frogs[loop_counter].fr_score;
//			}



/******************************************************************************
*%%%% GameMainloopEndOfGameSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopEndOfGameSetup(MR_VOID)
*
*	FUNCTION	Game end... fancy screen etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopEndOfGameSetup(MR_VOID)
{
	LIVE_ENTITY*		live_entity;
	JUN_OUTRO_ENTITY*	outro_entity;
	MR_LONG				x, z;
	JUN_OUTRO_DATA*		Outro_data;
	SEL_LEVEL_INFO*		arcade_level_ptr;

	// Alloc mem for the data needed
	Game_mode_data			= MRAllocMem(sizeof(JUN_OUTRO_DATA), "Game outro data");
	Outro_data				= (JUN_OUTRO_DATA*)Game_mode_data;

	// set end of game into first mode
	Outro_data->od_mode		= GAME_END_SEQUENCE_CAMERA_TO_DOOR;

	// Get pointer to our controller entity
	live_entity = GetNextLiveEntityOfType(NULL, JUN_OUTRO);
	MR_ASSERTMSG (live_entity, "You need an outro entity for this final map!");
	Outro_data->od_entity	= live_entity->le_entity;
	Outro_data->od_effect	= NULL;
	Outro_data->od_pop		= NULL;

	// Cut to correct camera position
	outro_entity			= (JUN_OUTRO_ENTITY*)(Outro_data->od_entity + 1);

	// If we are playing level jungle 2, then we don't bother with the camera and outro
	// door stuff, just move to past it
	arcade_level_ptr = Sel_arcade_levels;
	while (arcade_level_ptr->li_library_id != -1)
		{
		if (arcade_level_ptr->li_library_id == LEVEL_JUNGLE2)
			{
			Outro_data->od_mode	= GAME_END_SEQUENCE_WAITING_FROG_HIT_STATUE;
			return;
			}
		arcade_level_ptr++;
		}

	// Level is non-jungle2, setup for jungle1
	Outro_data->od_mode		= GAME_END_SEQUENCE_CAMERA_TO_DOOR;
	Outro_data->od_counter	= 60;

	MR_VEC_EQUALS_SVEC(&Outro_data->od_position, &outro_entity->oe_targets[0].ot_target);
	Cameras[0].ca_offset_origin = &Outro_data->od_position;

	// Update camera zones
	x = GET_GRID_X_FROM_WORLD_X(Outro_data->od_position.vx);
	z = GET_GRID_Z_FROM_WORLD_Z(Outro_data->od_position.vz);
	CheckCoordsInZones(x, z, ZONE_TYPE_CAMERA, &Frogs[0].fr_cam_zone, &Frogs[0].fr_cam_zone_region);

	// detach camera from frog, and mark frog as having no control for a bit
	Frogs[0].fr_flags &= ~FROG_CONTROL_ACTIVE;
	Frogs[0].fr_flags |= FROG_DO_NOT_UPDATE_CAMERA_ZONES;
}


/******************************************************************************
*%%%% GameHasThemeBeenCompleted
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL GameHasThemeBeenCompleted(MR_LONG Game_map)
*
*	FUNCTION	Checks to see if theme has been completed, based on the requested
*				theme index.
*
*	INPUTS		Game_map		- Game map (in zone)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL GameHasThemeBeenCompleted(MR_LONG theme)
{
	SEL_LEVEL_INFO*		level_ptr;

	level_ptr = Sel_arcade_levels;
	
	// find ptr to first map in requested theme
	while (level_ptr->li_library_id != -1)
		{
		if (level_ptr->li_theme_no == theme)
			break;
		level_ptr++;
		}

	// double check for valid ptrs
	MR_ASSERT (level_ptr->li_library_id != -1);

	// Walk through all levels in this theme. checking to see if
	// level has been finished...
	while	
		(
		(level_ptr->li_library_id != -1) &&
		(level_ptr->li_theme_no == theme)
		)
		{
		// if this level is not complete, return FALSE now
		if (!(level_ptr->li_flags & SEL_LF_COMPLETED))
			return FALSE;
		level_ptr++;
		}

	// got here, so theme must be complete
	return (TRUE);
}


/******************************************************************************
*%%%% GameMainloopEndOfGameUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopEndOfGameUpdate(MR_VOID)
*
*	FUNCTION	Game end... fancy screen etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameMainloopEndOfGameUpdate(MR_VOID)
{
	LIVE_ENTITY*				live_entity1;
	LIVE_ENTITY*				live_entity2;
	JUN_OUTRO_ENTITY*			outro_entity;
//	MR_SVEC						svec;
	MR_LONG						x, z, i;
	JUN_OUTRO_RT_GOLD_FROG*		frog;
	SEL_LEVEL_INFO*				arcade_level_ptr;
	JUN_OUTRO_DATA*				outro_data;
	POLY_F4*					poly_f4;

	outro_data		= (JUN_OUTRO_DATA*)Game_mode_data;
	outro_entity	= (JUN_OUTRO_ENTITY*)(outro_data->od_entity + 1);

	switch (outro_data->od_mode)
		{
		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_CAMERA_TO_DOOR:
			// Wait for defined period of time, then goto next mode
			if (!(outro_data->od_counter--))
				outro_data->od_mode = GAME_END_SEQUENCE_OPEN_DOOR;
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_OPEN_DOOR:
			// Find the door, and the unpause it (it should have paused)
			outro_data->od_live_entity	= GetNextLiveEntityOfType(NULL, JUN_OUTRO_DOOR);
			MR_ASSERTMSG (outro_data->od_live_entity, "You need an outro door for this final map!");

			// Go to next mode
			outro_data->od_mode			= GAME_END_SEQUENCE_WAITING_DOOR_OPEN;
			outro_data->od_counter		= 60;

			// Play SFX for door opening.
			PlayMovingSound(outro_data->od_live_entity, SFX_OUT_STONE_RUMBLE, 4096, 8192);

			// Shake camera for duration of the animation
			ShakeCamera(&Cameras[0], 0x40, 60, 0x8000);
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_WAITING_DOOR_OPEN:
			if (!(outro_data->od_counter--))
				{
				// Door has opened, reset game on this level, so that the frog can make his
				// way back to open doors.. we should always remain in this game mode!
				outro_data->od_mode = GAME_END_SEQUENCE_WAITING_FROG_HIT_STATUE;

				// Find central stone frog and remember live entity
				outro_data->od_live_entity = JunFindEntity(JUN_OUTRO_STONE_FROG, GAME_END_MAX_PLINTHS);
				MR_ASSERTMSG (outro_data->od_live_entity, "You need a central (id of 8) stone frog for this final map!");

				// restart level, lie about the reset type
				Game_reset_flags = FORM_BOOK_RESET_ON_CHECKPOINT;
				LevelEnd();
				LevelStart(GAME_MODE_LEVEL_PLAY);
				}
			else
				{
				outro_data->od_live_entity->le_lwtrans->t[1] -= 10;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_WAITING_FROG_HIT_STATUE:
			// Find central stone frog and remember live entity
			outro_data->od_live_entity = JunFindEntity(JUN_OUTRO_STONE_FROG, GAME_END_MAX_PLINTHS);
			MR_ASSERTMSG (outro_data->od_live_entity, "You need a central (id of 8) stone frog for this final map!");

			// wait for frog to hit statue
			if (outro_data->od_live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				Frogs[0].fr_flags &= ~FROG_CONTROL_ACTIVE;
				Frogs[0].fr_flags |= FROG_DO_NOT_UPDATE_CAMERA_ZONES;

				// Bounce frog back to where it came from
				Frogs[0].fr_lwtrans->t[1]	= outro_data->od_live_entity->le_lwtrans->t[1];
				Frogs[0].fr_pos.vy			= outro_data->od_live_entity->le_lwtrans->t[1]<<16;
				JumpFrog(&Frogs[0], FROG_DIRECTION_S, FROG_JUMP_FORCED, 1, 6);

				// frog has hit us, move on
				outro_data->od_mode		= GAME_END_SEQUENCE_GOLD_FROG_APPEAR;

				// Find our stone & gold frog(s), and make them disappear/appear
				// respectively, probably with particle effect
				live_entity1 = JunFindEntity(JUN_OUTRO_STONE_FROG, JUN_STONE_FROG_STATUE_ID);
				MR_ASSERT (live_entity1);

				// Make disappear for the time being, do effect later
				MR_ASSERT (!(live_entity1->le_flags & LIVE_ENTITY_ANIMATED));
				((MR_OBJECT*)live_entity1->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;

				live_entity2 = JunFindEntity(JUN_OUTRO_GOLD_FROG, JUN_GOLD_FROG_STATUE_ID);
				MR_ASSERT (live_entity2);

				// Make appear for the time being, do effect later
				MR_ASSERT (live_entity2->le_flags & LIVE_ENTITY_ANIMATED);
				MR_ASSERT (live_entity2->le_flags & LIVE_ENTITY_FLIPBOOK);
				((MR_ANIM_ENV*)live_entity2->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
				((MR_ANIM_ENV*)live_entity2->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;
				LiveEntitySetAction(live_entity2, GEN_GOLD_FROG_EXCITED);

				// set up timer
				outro_data->od_counter	= GAME_END_GOLD_FROG_DELAY;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_GOLD_FROG_APPEAR:
			// Gold frog is appearing, and its doing its own wierd and wonderful
			// stuff, so just carry on... wait for defined time
			if (!(outro_data->od_counter--))
				{
				// Go to next mode
				outro_data->od_mode		= GAME_END_SEQUENCE_NEXT_PLINTH;
				outro_data->od_plinth	= -1;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_NEXT_PLINTH:
			// Go to next plinth
			outro_data->od_plinth++;

			// Last plinth?
			if (outro_data->od_plinth >= GAME_END_MAX_PLINTHS)
				{
				// all collected, goto ...
				outro_data->od_mode	= GAME_END_SEQUENCE_ALL_PLINTHS_RAISED;
				}
			else
				{
				outro_data->od_mode	= GAME_END_SEQUENCE_PLINTH_CAMERA_MOVE;

				// get pointer to this plinth, and move camera to this plinth
				live_entity1 = JunFindEntity(JUN_OUTRO_PLINTH, outro_data->od_plinth);
				MR_ASSERT (live_entity1);

				// setup target & position, and speed so we get there
				outro_data->od_live_entity		= live_entity1;
				outro_data->od_counter			= 30;
				MR_VEC_EQUALS_SVEC(&outro_data->od_target, &outro_entity->oe_targets[outro_data->od_plinth+1].ot_target);
				MR_COPY_VEC(&outro_data->od_position, Cameras[0].ca_offset_origin);
				Cameras[0].ca_offset_origin		= &outro_data->od_position;

				outro_data->od_velocity.vx	= ((outro_data->od_target.vx - outro_data->od_position.vx) << 16) / outro_data->od_counter;
				outro_data->od_velocity.vy	= ((outro_data->od_target.vy - outro_data->od_position.vy) << 16) / outro_data->od_counter;
				outro_data->od_velocity.vz	= ((outro_data->od_target.vz - outro_data->od_position.vz) << 16) / outro_data->od_counter;

				// Get pointers to the plinths stone and gold frogs, in case we need them
				outro_data->od_live_entity1 = JunFindEntity(JUN_OUTRO_STONE_FROG, outro_data->od_plinth);
				outro_data->od_live_entity2 = JunFindEntity(JUN_OUTRO_GOLD_FROG, outro_data->od_plinth);
				MR_ASSERT (outro_data->od_live_entity1);
				MR_ASSERT (outro_data->od_live_entity2);
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_PLINTH_CAMERA_MOVE:
			// move camera until timer has counter down
			if (!(outro_data->od_counter--))
				{
				// Camera has reached target, lock it and move to RAISE PLINTH mode
				MR_COPY_VEC(&outro_data->od_position, &outro_data->od_target);
				
				// Update camera zones
				x = GET_GRID_X_FROM_WORLD_X(outro_data->od_position.vx);
				z = GET_GRID_Z_FROM_WORLD_Z(outro_data->od_position.vz);
				CheckCoordsInZones(x, z, ZONE_TYPE_CAMERA, &Frogs[0].fr_cam_zone, &Frogs[0].fr_cam_zone_region);
				Frogs[0].fr_flags |= FROG_DO_NOT_UPDATE_CAMERA_ZONES;

				outro_data->od_mode			= GAME_END_SEQUENCE_PLINTH_RAISE;
				outro_data->od_counter		= GAME_END_MAX_PLINTH_RAISE_TIME;

				// Play SFX for each Gold Frog.
				MRSNDPlaySound(SFX_OUT_STONE_RUMBLE, NULL, 0, 0);

				// Shake camera for duration of the plinth raise
				ShakeCamera(&Cameras[0], 0x20, GAME_END_MAX_PLINTH_RAISE_TIME, 0x8000);

				// Calc velocity for moving plinth
				outro_data->od_velocity.vx = 0;
				outro_data->od_velocity.vy = -(GAME_END_MAX_PLINTH_RAISE_DISTANCE / GAME_END_MAX_PLINTH_RAISE_TIME) << 16;
				outro_data->od_velocity.vz = 0;
				}
			else
				{
				// move camera
				outro_data->od_position.vx += (outro_data->od_velocity.vx >> 16);
				outro_data->od_position.vy += (outro_data->od_velocity.vy >> 16);
				outro_data->od_position.vz += (outro_data->od_velocity.vz >> 16);
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_PLINTH_RAISE:
			// Raise the required plinth up, until counter is zero
			MR_ASSERT (outro_data->od_live_entity);

			// If the zone for this plinth hasn't been completed, then we SHOULD NOT raise
			// then plinth at all, break out early...
/*
#ifndef GAME_GOLD_FROG_CHEAT
			if (!GameHasThemeBeenCompleted(Game_map_theme))
				{
				// Goto to next plinth
				outro_data->od_mode = GAME_END_SEQUENCE_NEXT_PLINTH;
				break;
				}
#endif
*/
/*
			// If counter is down to set number, need to look to see if we should generate particle effect
			if (outro_data->od_counter == GAME_END_PLINTH_TIME_FROG_SWITCH_PARTICLE)
				{
				// Have we collected this gold frog?
#ifndef GAME_GOLD_FROG_CHEAT
				if (Gold_frogs & outro_data->od_plinth)
#endif
					{
					// Create particle effect
					MR_SET_SVEC(&svec, 0, 0, 0);
					outro_data->od_effect 	= MRCreatePgen(	&PGIN_stone_to_gold_frog,
															(MR_FRAME*)outro_data->od_live_entity1->le_lwtrans,
														  	MR_OBJ_STATIC,
															&svec);
					outro_data->od_effect->ob_extra.ob_extra_pgen->pg_owner = outro_data->od_live_entity1->le_lwtrans;
	
					// Add object to viewport(s)
					GameAddObjectToViewports(outro_data->od_effect);
					}
				}
*/

			// If counter is down to set number, need to look to see if we should switch on the gold frog
			if (outro_data->od_counter == GAME_END_PLINTH_TIME_FROG_SWITCH)
				{
				// Have we collected this gold frog?
#ifndef GAME_GOLD_FROG_CHEAT
				if (Gold_frogs & outro_data->od_plinth)
#endif
					{
					// Create pop for stone frog
					LiveEntityInitPop(outro_data->od_live_entity1);
					LiveEntityStartPolyPiecePop(outro_data->od_live_entity1);

					// Play SFX for each Gold Frog.
					MRSNDPlaySound(SFX_OUT_FROG_EXPLODE, NULL, 0, 0);
					
					// Make gold frog appear, not playing anim
					MR_ASSERT (outro_data->od_live_entity2->le_flags & (LIVE_ENTITY_ANIMATED|LIVE_ENTITY_FLIPBOOK));
					((MR_ANIM_ENV*)outro_data->od_live_entity2->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;
					((MR_ANIM_ENV*)outro_data->od_live_entity2->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
					LiveEntitySetAction(outro_data->od_live_entity2, GEN_GOLD_FROG_EXCITED);
					}
				}

			if (!(outro_data->od_counter--))
				{
				// Goto to next plinth
				outro_data->od_mode = GAME_END_SEQUENCE_NEXT_PLINTH;

				// Kill off particle effect
				if (outro_data->od_effect)
					{
					outro_data->od_effect->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
					outro_data->od_effect  = NULL;
					}

				// Kill off pop effect
				if (outro_data->od_pop)
					{
					MRFreeMem(outro_data->od_pop);
					outro_data->od_pop = NULL;
					}

				}
			else
				{
				// Raise up plinth, gold and stone frog
				outro_data->od_live_entity->le_lwtrans->t[0] += (outro_data->od_velocity.vx >> 16);
				outro_data->od_live_entity->le_lwtrans->t[1] += (outro_data->od_velocity.vy >> 16);
				outro_data->od_live_entity->le_lwtrans->t[2] += (outro_data->od_velocity.vz >> 16);
				outro_data->od_live_entity1->le_lwtrans->t[0] += (outro_data->od_velocity.vx >> 16);
				outro_data->od_live_entity1->le_lwtrans->t[1] += (outro_data->od_velocity.vy >> 16);
				outro_data->od_live_entity1->le_lwtrans->t[2] += (outro_data->od_velocity.vz >> 16);
				outro_data->od_live_entity2->le_lwtrans->t[0] += (outro_data->od_velocity.vx >> 16);
				outro_data->od_live_entity2->le_lwtrans->t[1] += (outro_data->od_velocity.vy >> 16);
				outro_data->od_live_entity2->le_lwtrans->t[2] += (outro_data->od_velocity.vz >> 16);
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_ALL_PLINTHS_RAISED:
			// All plinths are raised... were all gold frogs collected? If so, goto door's open 
			// and gold frogs leap out mode
#ifndef GAME_GOLD_FROG_CHEAT
			if (Gold_frogs == GEN_ALL_GOLD_FROGS)
#else
			if (1)
#endif
				{
				outro_data->od_mode	= GAME_END_SEQUENCE_FINAL_CAMERA_POS;
				}
			else
				{
				// goto credits screen... By order of the management
				outro_data->od_counter		= 60;
				outro_data->od_mode			= GAME_END_SEQUENCE_FADE_SCREEN;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_FINAL_CAMERA_POS:
			outro_data->od_mode			= GAME_END_SEQUENCE_FINAL_CAMERA_POS_MOVE;
			outro_data->od_counter		= outro_entity->oe_targets[outro_data->od_plinth+1].ot_time;

			MR_VEC_EQUALS_SVEC(&outro_data->od_target, &outro_entity->oe_targets[GAME_END_LAST_DOOR_TARGET].ot_target);
			MR_COPY_VEC(&outro_data->od_position, Cameras[0].ca_offset_origin);
			Cameras[0].ca_offset_origin		= &outro_data->od_position;

			// Update camera zones
			x = GET_GRID_X_FROM_WORLD_X(outro_data->od_position.vx);
			z = GET_GRID_Z_FROM_WORLD_Z(outro_data->od_position.vz);
			CheckCoordsInZones(x, z, ZONE_TYPE_CAMERA, &Frogs[0].fr_cam_zone, &Frogs[0].fr_cam_zone_region);

			outro_data->od_velocity.vx	= ((outro_data->od_target.vx - outro_data->od_position.vx) << 16) / outro_data->od_counter;
			outro_data->od_velocity.vy	= ((outro_data->od_target.vy - outro_data->od_position.vy) << 16) / outro_data->od_counter;
			outro_data->od_velocity.vz	= ((outro_data->od_target.vz - outro_data->od_position.vz) << 16) / outro_data->od_counter;
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_FINAL_CAMERA_POS_MOVE:
			// move camera until timer has counter down
			if (!(outro_data->od_counter--))
				{
				// Camera has reached target, start the door anim
				outro_data->od_mode			= GAME_END_SEQUENCE_WAITING_EXIT_DOOR_OPEN;
				outro_data->od_live_entity	= JunFindEntity(JUN_OUTRO_GOLD_DOOR, -1);
				outro_data->od_counter		= 60;

				ShakeCamera(&Cameras[0], 0x40, outro_data->od_counter, 0x8000);
				}
			else
				{
				// move camera
				outro_data->od_position.vx += (outro_data->od_velocity.vx >> 16);
				outro_data->od_position.vy += (outro_data->od_velocity.vy >> 16);
				outro_data->od_position.vz += (outro_data->od_velocity.vz >> 16);
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_WAITING_EXIT_DOOR_OPEN:
			if (!(outro_data->od_counter--))
				{
				// Door has opened, go into mode where each gold frog jumps from the level
				// through the door, in turn..
				outro_data->od_mode		= GAME_END_SEQUENCE_NEXT_GOLD_FROGS_EXITING;
				outro_data->od_plinth	= -1;
				}
			else
				outro_data->od_live_entity->le_lwtrans->t[1] -= 10;
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_NEXT_GOLD_FROGS_EXITING:
			// Go to next plinth/frog
			outro_data->od_plinth++;

			// Last plinth?
			if (outro_data->od_plinth >= (GAME_END_MAX_PLINTHS+1))
				{
				// all collected, goto frog_jump_frog_level mode
				outro_data->od_mode		= GAME_END_SEQUENCE_FROG_EXITING;
				outro_data->od_counter	= 0;
				}
			else
				{
				outro_data->od_mode	= GAME_END_SEQUENCE_GOLD_FROG_JUMP_THR_DOOR;

				live_entity1 = JunFindEntity(JUN_OUTRO_GOLD_FROG, outro_data->od_plinth);
				MR_ASSERT (live_entity1);

				// setup target & position, and speed so we get there
				outro_data->od_live_entity	= live_entity1;
				outro_entity				= (JUN_OUTRO_ENTITY*)(outro_data->od_entity + 1);
				outro_data->od_counter		= 0;
				}
			break;


		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_GOLD_FROG_JUMP_THR_DOOR:
			// Jump frog until end, or -1 is found
			if (outro_data->od_counter < GAME_END_MAX_GOLD_FROG_JUMPS)
				{
				// jump in required direction, only if frog has finished jumping
				frog = (JUN_OUTRO_RT_GOLD_FROG*)outro_data->od_live_entity->le_specific;
				if (frog->op_mode == JUN_GOLD_FROG_SITTING)
					{
					// if run out of jumps, stop now
					if (Jun_outro_gold_frog_jumps[outro_data->od_plinth][outro_data->od_counter] == -1)
						outro_data->od_mode = GAME_END_SEQUENCE_NEXT_GOLD_FROGS_EXITING;

					JunJumpGoldFrog(outro_data->od_live_entity, Jun_outro_gold_frog_jumps[outro_data->od_plinth][outro_data->od_counter]);
					outro_data->od_counter++;
					}
				}
			else
				{
				outro_data->od_mode = GAME_END_SEQUENCE_NEXT_GOLD_FROGS_EXITING;
				((MR_ANIM_ENV*)outro_data->od_live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_FROG_EXITING:
			// Jump frog until end, or -1 is found
			if (outro_data->od_counter < GAME_END_MAX_GOLD_FROG_JUMPS)
				{
				//
				if (Jun_outro_frog_jumps[outro_data->od_counter] == -1)
					{
					outro_data->od_mode			= GAME_END_SEQUENCE_FADE_SCREEN;
					outro_data->od_counter		= 60;
					}
				if (Frogs[0].fr_mode == FROG_MODE_STATIONARY)
					{
					// if run out of jumps, stop now
					if (Jun_outro_frog_jumps[outro_data->od_counter] == -1)
						outro_data->od_mode = GAME_END_SEQUENCE_FADE_SCREEN;

					// jump in required direction
					JumpFrog(&Frogs[0], Jun_outro_frog_jumps[outro_data->od_counter], NULL, 1, 6);
					outro_data->od_counter++;
					}
				}
			else
				{
				outro_data->od_mode			= GAME_END_SEQUENCE_FADE_SCREEN;
				outro_data->od_counter		= 60;
				}
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_FADE_SCREEN:
			// Fade screen over 2 second, and GAME OVER sprite up in same time
			if (!(outro_data->od_counter--))
				outro_data->od_mode	= GAME_END_SEQUENCE_END;

			i 			= MIN(0xff, ((GAME_OUTRO_FADE_DURATION - outro_data->od_counter) * 0xff) / 30);
			poly_f4 	= &Pause_poly[MRFrame_index];
			poly_f4->r0 = i;
			poly_f4->g0 = i;
			poly_f4->b0 = i;
			GamePauseAddPrim();
			break;

		//---------------------------------------------------------------------
		case GAME_END_SEQUENCE_END:
			// If all gold frogs are collected, goto FMV
#ifndef GAME_GOLD_FROG_CHEAT
			if (Gold_frogs == GEN_ALL_GOLD_FROGS)
				Option_page_request = OPTIONS_PAGE_OUTRO;
			else
				Option_page_request = OPTIONS_PAGE_CREDITS;
#else
			Option_page_request = OPTIONS_PAGE_OUTRO;
#endif

			// free alloced memory and close everything down
			MRFreeMem(Game_mode_data);
			LevelEnd();
			GameEnd();

			// Hack the level stack data to point jungle 1 to jungle 2.... WIll told me to do it,
			// honest guv, on my life...
			arcade_level_ptr = Sel_arcade_levels;
			while (arcade_level_ptr->li_library_id != -1)
				{
				if (arcade_level_ptr->li_library_id == LEVEL_JUNGLE1)
					{
					arcade_level_ptr->li_library_id = LEVEL_JUNGLE2;
					break;
					}
				arcade_level_ptr++;
				}
			break;
		}
}


/******************************************************************************
*%%%% GameMainloopEndOfMultiplayerGameSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopEndOfMultiplayerGameSetup(MR_VOID)
*
*	FUNCTION	Game mainloop END OF MULTIPLAYER GAME setup function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameMainloopEndOfMultiplayerGameSetup(MR_VOID)
{
	MR_ULONG				i, j;
	GEN_CHECKPOINT_DATA*	data;
	MR_BOOL					winner[4];
	MR_ULONG				checks[4];
	MR_TEXTURE*				texture;

	// Initialise number of check points collected
	for (i=0; i<4; i++)
		{
		checks[i] = 0;
		winner[i] = FALSE;
		}

	// Loop once for each check point
	data 	= Checkpoint_data;
	j 		= GEN_MAX_CHECKPOINTS;
	while(j--)
		{
		// it is possible to get here without all checkpoints being collected, so check for -1
		if (data->cp_frog_collected_id != -1)
			checks[data->cp_frog_collected_id]++;
		data++;
		}

	// Work out who won
	if ( (checks[0] > checks[1]) && (checks[0] > checks[2]) && (checks[0] > checks[3]) )
		winner[0] = TRUE;
	if ( (checks[1] > checks[0]) && (checks[1] > checks[2]) && (checks[1] > checks[3]) )
		winner[1] = TRUE;
	if ( (checks[2] > checks[0]) && (checks[2] > checks[1]) && (checks[2] > checks[3]) )
		winner[2] = TRUE;
	if ( (checks[3] > checks[0]) && (checks[3] > checks[1]) && (checks[3] > checks[2]) )
		winner[3] = TRUE;

	// Update Frog data
	for(i=0;i<Game_total_viewports;i++)
		{
		// Yes ... did this Frog win ?
		if ( winner[i] == TRUE )
			{
			// Yes ... inc number of games won
			Frogs[i].fr_multi_games_won++;
			}
		else
			{
			// No ... inc number of games lost
			Frogs[i].fr_multi_games_lost++;
			}
		}

	// Set up display positions
	switch (Game_total_viewports)
		{
		case 2:	// Two player game ...

			// Set up player one's positions
			Multiplayer_end_of_game_text_pos[1][0].x = Game_display_width>>2;
			Multiplayer_end_of_game_text_pos[1][0].y = Game_display_height>>1;

			// Set up player two's positions
			Multiplayer_end_of_game_text_pos[1][1].x = (Game_display_width>>2)*3;
			Multiplayer_end_of_game_text_pos[1][1].y = Game_display_height>>1;

			break;

		case 3:		// Three player game ...
			// Set up player one's positions
			Multiplayer_end_of_game_text_pos[2][0].x = Game_display_width>>2;
			Multiplayer_end_of_game_text_pos[2][0].y = Game_display_height>>2;

			// Set up player two's positions
			Multiplayer_end_of_game_text_pos[2][1].x = (Game_display_width>>2)*3;
			Multiplayer_end_of_game_text_pos[2][1].y = Game_display_height>>2;

			// Set up player three's positions
			Multiplayer_end_of_game_text_pos[2][2].x = Game_display_width>>2;
			Multiplayer_end_of_game_text_pos[2][2].y = (Game_display_height>>2)*3;

			break;

		case 4:		// Four player game ...
			// Set up player one's positions
			Multiplayer_end_of_game_text_pos[3][0].x = Game_display_width>>2;
			Multiplayer_end_of_game_text_pos[3][0].y = Game_display_height>>2;

			// Set up player two's positions
			Multiplayer_end_of_game_text_pos[3][1].x = (Game_display_width>>2)*3;
			Multiplayer_end_of_game_text_pos[3][1].y = Game_display_height>>2;

			// Set up player three's positions
			Multiplayer_end_of_game_text_pos[3][2].x = Game_display_width>>2;
			Multiplayer_end_of_game_text_pos[3][2].y = (Game_display_height>>2)*3;

			// Set up player four's positions
			Multiplayer_end_of_game_text_pos[3][3].x = (Game_display_width>>2)*3;
			Multiplayer_end_of_game_text_pos[3][3].y = (Game_display_height>>2)*3;
			break;

		default:
			// should be 2, 3 or 4 players in multiplayer mode
			MR_ASSERT(0);
			break;
		}

	// Loop once for each viewport
	for (i=0; i<Game_total_viewports; i++)
		{
		// Allocate structure for game over info
		Game_over[i]	= (GAME_OVER_MULTIPLAYER*)MRAllocMem(sizeof(GAME_OVER_MULTIPLAYER), "game over multiplayer");

		// Initialise semi trans prims
		for (j=0; j<2; j++)
			{
			setPolyF4(&Game_over[i]->go_prim_f[j]);
			setRGB0(&Game_over[i]->go_prim_f[j], 0x40, 0x40, 0x40);
			setSemiTrans(&Game_over[i]->go_prim_f[j], 1);

			Game_over[i]->go_prim_f[j].x0 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x - (Game_display_width>>2);	
			Game_over[i]->go_prim_f[j].y0 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y - (Game_display_height>>2);
			Game_over[i]->go_prim_f[j].x1 =	Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x + (Game_display_width>>2);	
			Game_over[i]->go_prim_f[j].y1 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y - (Game_display_height>>2);
			Game_over[i]->go_prim_f[j].x2 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x - (Game_display_width>>2);	
			Game_over[i]->go_prim_f[j].y2 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y + (Game_display_height>>2);
			Game_over[i]->go_prim_f[j].x3 =	Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x + (Game_display_width>>2);	
			Game_over[i]->go_prim_f[j].y3 = Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y + (Game_display_height>>2);
			}

		for (j=0; j<2; j++)
			{
			setPolyFT3(&Game_over[i]->go_prim_ft[j]);
			//setSemiTrans(&Game_over[i]->go_prim_ft[j], 1);
			setXY3(&Game_over[i]->go_prim_ft[j], -1,-1,-1,-1,-1,-1);
#ifdef PSX
			Game_over[i]->go_prim_ft[j].tpage = defTPage(0,0,2);
#else
			Game_over[i]->go_prim_ft[j].tpage = 0;
#endif
			}

		// Creat "PLAYED"/"WON"/"LOST" text headers 
		texture = Options_text_textures[OPTION_TEXT_PLAYED][Game_language];
		Game_over[i]->go_played_text	= MRCreate2DSprite((Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x-30)-(texture->te_w>>1),	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-20,	
															Game_viewporth,
															texture,
															NULL);
		texture = Options_text_textures[OPTION_TEXT_WON][Game_language];
		Game_over[i]->go_won_text		= MRCreate2DSprite((Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x-30)-(texture->te_w>>1),	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y,
															Game_viewporth,
															texture,
															NULL);
		texture = Options_text_textures[OPTION_TEXT_LOST][Game_language];
		Game_over[i]->go_lost_text		= MRCreate2DSprite((Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x-30)-(texture->te_w>>1),	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y+20,
															Game_viewporth,
															texture,
															NULL);
		// Display number of games played
		HUDGetDigits(Frogs[i].fr_multi_games_won + Frogs[i].fr_multi_games_lost, NULL, NULL, NULL);
		Game_over[i]->go_played_number[0]	= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+20,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-21,	
															Game_viewporth,
															Hud_score_images[Hud_digits[8]],
															NULL);
		Game_over[i]->go_played_number[1]	= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+36,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-21,
															Game_viewporth,
															Hud_score_images[Hud_digits[9]],
															NULL);

		// Display number of games won
		HUDGetDigits(Frogs[i].fr_multi_games_won, NULL, NULL, NULL);
		Game_over[i]->go_won_number[0]		= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+20,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-1,	
															Game_viewporth,
															Hud_score_images[Hud_digits[8]],
															NULL);
		Game_over[i]->go_won_number[1]		= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+36,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y-1,	
															Game_viewporth,
															Hud_score_images[Hud_digits[9]],
															NULL);

		// Display number of games lost
		HUDGetDigits(Frogs[i].fr_multi_games_lost, NULL, NULL, NULL);
		Game_over[i]->go_lost_number[0]	= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+20,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y+19,	
															Game_viewporth,
															Hud_score_images[Hud_digits[8]],
															NULL);
		Game_over[i]->go_lost_number[1]	= MRCreate2DSprite(Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].x+36,	
															Multiplayer_end_of_game_text_pos[Game_total_viewports-1][i].y+19,	
															Game_viewporth,
															Hud_score_images[Hud_digits[9]],
															NULL);
		}
	
	// Remove control from frogs..
	for (i=0; i<Game_total_players; i++)
		{
		Frogs[i].fr_flags &= ~FROG_CONTROL_ACTIVE;
		Frogs[i].fr_flags &= ~FROG_ACTIVE;
		}

	// turn off pause (default for in game)
	Game_flags |= GAME_FLAG_NO_PAUSE_ALLOWED;
}

/******************************************************************************
*%%%% GameMainloopEndOfMultiplayerGameUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMainloopEndOfMultiplayerGameUpdate(MR_VOID)
*
*	FUNCTION	Game mainloop END OF MULTIPLAYER GAME update function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameMainloopEndOfMultiplayerGameUpdate(MR_VOID)
{
	MR_ULONG		i,j;
	MR_BOOL			exit_flag;

	// Loop once for each viewport
	for (i=0; i<Game_total_viewports; i++)
		{
		// Show subtractive polys
		addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - (i+1), &Game_over[i]->go_prim_f[MRFrame_index]);
		addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - (i+1), &Game_over[i]->go_prim_ft[MRFrame_index]);
		}

	// Flag exit as not pressed
	exit_flag = FALSE;

	// Loop once for each frog
	for(i=0;i<Game_total_players;i++)
		{
		// Did this player press exit ?
		if ( MR_CHECK_PAD_PRESSED(Frogs[i].fr_input_id, FR_GO) )
			{
			// Yes ... flag exit
			exit_flag = TRUE;
			}
		}

	// Was exit selected ?
	if (exit_flag)
		{

		// Yes ... loop once for each viewport
		for (i=0; i<Game_total_viewports; i++)
			{
			// Remove sprites
			MRKill2DSprite(Game_over[i]->go_played_text);
			MRKill2DSprite(Game_over[i]->go_won_text);
			MRKill2DSprite(Game_over[i]->go_lost_text);

			for (j=0; j<2; j++)
				{
				MRKill2DSprite(Game_over[i]->go_played_number[j]);
				MRKill2DSprite(Game_over[i]->go_won_number[j]);
				MRKill2DSprite(Game_over[i]->go_lost_number[j]);
				}

			// Free memory for game over data
			InitialisePrimFree((MR_UBYTE*)Game_over[i]);
			}

		// Go on to play again screen
		Option_page_request = OPTIONS_PAGE_PLAY_AGAIN;

		// turn on pause (default for in game)
		Game_flags &= ~GAME_FLAG_NO_PAUSE_ALLOWED;
		}
}

/******************************************************************************
*%%%% SetGameMainloopMode
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetGameMainloopMode(
*						MR_ULONG game_mainloop_mode)
*
*	FUNCTION	Sets the game into the requested mainloop mode.
*
*	PARAMS		game_mainloop_mode	-	game mode
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SetGameMainloopMode(MR_ULONG game_mainloop_mode)
{
	MR_ASSERT (game_mainloop_mode < GAME_MODE_MAX);

	// Call setup callback
	if 	(Game_mainloop_setup_functions[game_mainloop_mode])
	   	(Game_mainloop_setup_functions[game_mainloop_mode])();

	// Set frog mode
	Game_mode = game_mainloop_mode;
}

/******************************************************************************
*%%%% GameClearRender
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameClearRender(MR_VOID)
*
*	FUNCTION	Game goes into loop, calling MRSwapDisplay (waiting for a while 
*				to flush everything)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	GameClearRender(MR_VOID)
{
	MR_LONG		i;
#ifdef	PSX
	MR_LONG		j;
#endif

	i = 4;

	// Go into a wait state for a few frames, to clear the render buffer and suchlike
#ifdef WIN95
	while (i--)
		{
		if (MRDraw_valid == 0)
			MRClearAllViewportOTs();
		MRSwapDisplay();
		MRClearAllViewportOTs();
		}
#else	// PSX
	DrawSync(0);
	while (i--)
		{
	 	//VSync(2);
		//MRSwapDisplay();
		for (j = 0; j < Game_total_viewports; j++)
			{
			MRRenderViewport(Game_viewports[j]);
		 	MRClearViewportOT(Game_viewports[j]);
			}
		}
#endif
}


/******************************************************************************
*%%%% GameUpdateControllers
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameUpdateControllers(MR_VOID)
*
*	FUNCTION	Writes controller IDs back to Frog_input_ports[]
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GameUpdateControllers(MR_VOID)
{
#ifdef	PSX
	// There are 3 cases:
	//
	// No multitap: 		players 0..1 are MR_INPUT_PORT_0..1
	// Multitap in port 1:	players 0..3 are MR_INPUT_PORT_0_0..3
	// Multitap in port 2:	players 0..3 are MR_INPUT_PORT_1_0..3
	if (MR_IS_CONTROLLER_TYPE(MR_INPUT_PORT_0, MRIF_TYPE_TAP))
		{
		// Multitap in port 1
		Frog_input_ports[0] = MR_INPUT_PORT_0_0;
		Frog_input_ports[1] = MR_INPUT_PORT_0_1;
		Frog_input_ports[2] = MR_INPUT_PORT_0_2;
		Frog_input_ports[3] = MR_INPUT_PORT_0_3;
		}
	else
	if (MR_IS_CONTROLLER_TYPE(MR_INPUT_PORT_1, MRIF_TYPE_TAP))
		{
		// Multitap in port 2
		Frog_input_ports[0] = MR_INPUT_PORT_1_0;
		Frog_input_ports[1] = MR_INPUT_PORT_1_1;
		Frog_input_ports[2] = MR_INPUT_PORT_1_2;
		Frog_input_ports[3] = MR_INPUT_PORT_1_3;
		}
	else
		{
		// No multitap
		Frog_input_ports[0] = MR_INPUT_PORT_0;
		Frog_input_ports[1] = MR_INPUT_PORT_1;
		Frog_input_ports[2] = -1;
		Frog_input_ports[3] = -1;
		}
#endif
}

/******************************************************************************
*%%%% InitTransparentPolyBackground
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitTransparentPolyBackground(
*						MR_LONG		x,
*						MR_LONG		y,
*						MR_LONG		w,
*						MR_LONG		h)
*
*	FUNCTION	Init's polys for transparent background
*
*	INPUTS		x		- x pos
*				y		- y pos
*				w		- width
*				h		- height
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	InitTransparentPolyBackground(	MR_LONG		x,
										MR_LONG		y,
										MR_LONG		w,
										MR_LONG		h)
{
	MR_LONG		j;

	// Initialise semi trans prims
	for (j=0; j<2; j++)
		{
		setPolyF4(&Game_prim_f[j]);
		setRGB0(&Game_prim_f[j], 0x60, 0x60, 0x60);
		setSemiTrans(&Game_prim_f[j], 1);

		Game_prim_f[j].x0 = x;
		Game_prim_f[j].y0 = y;
		Game_prim_f[j].x1 = x + w;
		Game_prim_f[j].y1 = y;
		Game_prim_f[j].x2 = x;
		Game_prim_f[j].y2 = y + h;
		Game_prim_f[j].x3 = x + w;
		Game_prim_f[j].y3 = y + h;
		}

	for (j=0; j<2; j++)
		{
		setPolyFT3(&Game_prim_ft[j]);
		setXY3(&Game_prim_ft[j], -1,-1,-1,-1,-1,-1);

#ifdef PSX
		Game_prim_ft[j].tpage = defTPage(0,0,2);
#else
		Game_prim_ft[j].tpage = 0;
#endif
		}
}


/******************************************************************************
*%%%% UpdateTransparentPolyBackground
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateTransparentPolyBackground(MR_VOID)
*
*	FUNCTION	Updates polys for transparent background
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	UpdateTransparentPolyBackground(MR_VOID)
{
	// Show subtractive polys
	addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - 1, &Game_prim_f[MRFrame_index]);
	addPrim(Game_viewporth->vp_work_ot + Game_viewporth->vp_ot_size - 1, &Game_prim_ft[MRFrame_index]);
}


/******************************************************************************
*%%%% GameGetMultiplayerFrogCheckpointData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameGetMultiplayerFrogCheckpointData(MR_VOID)
*
*	FUNCTION	Counts checkpoints collected in multiplayer, plus max number
*				of checkpoints collected by any frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameGetMultiplayerFrogCheckpointData(	MR_LONG*	checkpoint_count,
												MR_LONG*	max_checkpoints,
												MR_LONG*	num_winning_frogs)
{
	MR_LONG					i;
	GEN_CHECKPOINT_DATA*	data;

	for (i=0; i<4; i++)
		checkpoint_count[i] = 0;

	data 	= Checkpoint_data;
	i 		= GEN_MAX_CHECKPOINTS;

	while (i--)
		{
		if (data->cp_frog_collected_id != -1)
			(*(checkpoint_count + data->cp_frog_collected_id))++;
		data++;
		}

	// work out max number of checkpoints collected by any frog
	*max_checkpoints = 0;
	for (i=0; i<4; i++)
		*max_checkpoints = MAX(*max_checkpoints, *(checkpoint_count + i));

	// Has more than one frog collected this number?
	*num_winning_frogs = 0;
	for (i=0; i<4; i++)
		{
		if (*(checkpoint_count + i) == *max_checkpoints)
			(*num_winning_frogs)++;
		}
}

#ifdef WIN95
#pragma warning (default : 4761)
#endif // win95
