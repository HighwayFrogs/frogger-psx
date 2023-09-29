/******************************************************************************
*%%%% gamesys.h
*------------------------------------------------------------------------------
*
*	All game system variables
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__GAMESYS_H
#define	__GAMESYS_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
#define	GAME_PAUSABLE
#define	GAME_SHOW_SEQUENCES
#define	GAME_TIMER_DECREASE
#define	GAME_CLEAR_USING_TILES
//#define	GAME_VIEWPORT_BORDERS

#ifndef PSX_RELEASE
//#define 	GAME_GOLD_FROG_CHEAT
#endif	

//#define	GAME_ALLOW_RECORDING
//#define	GAME_USE_MAPDEBUG_MENU
//#define	GAME_TIMS_BODGED_COMPILE


// Gravity
#define	SYSTEM_GRAVITY					0x100000	//	world units per frame per frame (16.16)

// Display
#define	SYSTEM_PERSPECTIVE				192

// The following should be a temporary IFDEF, the code shouldn't rely on defines for screen
// sizes since the PC can and will have a flexible screen resolution system
#ifdef PSX 
	#define	SYSTEM_DISPLAY_MODE				MR_SCREEN_STANDARD_368
	#define	SYSTEM_DISPLAY_WIDTH			368

	#ifdef	PSX_MODE_NTSC
		#define	SYSTEM_DISPLAY_HEIGHT			240
	#else
		#define	SYSTEM_DISPLAY_HEIGHT			256
	#endif
#else
	#define	SYSTEM_DISPLAY_WIDTH			640
	#define	SYSTEM_DISPLAY_HEIGHT			480
#endif

// Viewports
#define	SYSTEM_MAX_VIEWPORTS			4
#define	SYSTEM_VIEWPORT_VIEWDIST		MR_VP_VIEWDIST_8192
#define	SYSTEM_VIEWPORT_OT_SIZE_1P		MR_VP_SIZE_4096
#define	SYSTEM_VIEWPORT_OT_SIZE_2P		MR_VP_SIZE_4096
#define	SYSTEM_VIEWPORT_OT_SIZE_4P		MR_VP_SIZE_2048

// Graphical themes
enum	{
		THEME_GEN,
		THEME_CAV,
		THEME_DES,
		THEME_FOR,
		THEME_JUN,
		THEME_ORG,
		THEME_ARN,
		THEME_SWP,
		THEME_SKY,
		THEME_SUB,
		THEME_VOL,

		THEME_TIT,
		THEME_HUD,
		THEME_FRG,
		};

// The following enum table gives the various modes that the main game loop
// can be in. This is separate from what state the options loop is in.
enum	{
		GAME_MODE_SINGLE_START,								// Single - Level is starting (bouncing frogs, hud, etc)
		GAME_MODE_SINGLE_TRIGGER_COLLECTED,					// Single - Trigger collected
		GAME_MODE_SINGLE_FAILED,							// Single - Level has been failed
		GAME_MODE_SINGLE_FROG_DIED,							// Single - Frog (single player) has died
		GAME_MODE_SINGLE_COMPLETE,							// Single - Level complete
		GAME_MODE_MULTI_START,								// Multiplayer - Start level
		GAME_MODE_MULTI_TRIGGER_COLLECTED,					// Multiplayer - Trigger collected
		GAME_MODE_MULTI_FAILED,								// Multiplayer - Level has been failed
		GAME_MODE_MULTI_FROG_DIED,							// Multiplayer - All frogs died
		GAME_MODE_MULTI_COMPLETE,							// Multiplayer - Level complete

		GAME_MODE_LEVEL_PLAY,								// Level is playing
		GAME_MODE_LEVEL_FAST_START,							// Level is starting (simple fast start)

		GAME_MODE_END_OF_GAME,								// End of game
		GAME_MODE_END_OF_MULTIPLAYER_GAME,					// End of multiplayer game/level
		GAME_MODE_MAX,										// Delimit
		};

// Game defines
#define	GAME_START_TIME_SLOW					(4*30)		// duration to hold camera on frog before panning out
#define	GAME_START_TIME_FAST					(30)		// duration to hold camera on frog before panning out
#define	GAME_MAX_HIGH_POLY_PLAYERS				1			// number of players in game with high poly frog models
#define	GAME_MAX_HUD_SCRIPTS					3			// max HUD scripts that can be run at once

// Score based defines
#define	GAME_BONUS_SCORE_PER_SECOND_LEFT		(10)		// points awarded per second left

// Game flags
#define	GAME_FLAG_HUD_SCORE						(1<<0)		// display score as part of HUD
#define	GAME_FLAG_HUD_TIMER						(1<<1)		// display timer as part of HUD
#define	GAME_FLAG_HUD_HELP						(1<<2)		// display help as part of HUD
#define	GAME_FLAG_HUD_CHECKPOINTS				(1<<3)		// display checkpoints as part of HUD
#define	GAME_FLAG_HUD_LIVES						(1<<4)		// display lives as part of HUD
												
#define	GAME_FLAG_PAUSED						(1<<8)		// game is paused
#define	GAME_FLAG_SCORE_SPRITES					(1<<9)		// display scores as small sprites

#define GAME_FLAG_DEMO_RUNNING					(1<<10)		// demo playback is currently running

#define GAME_FLAG_SYNCED_FROGS					(1<<11)		// win95 only, network mode, all frogs synced
#define	GAME_FLAG_RESTART_GAME					(1<<12)		// win95 only, requests a restart level
#define	GAME_FLAG_GEN_WAD_LOADED				(1<<13)		// GEN wad loaded
#define	GAME_FLAG_GENM_WAD_LOADED				(1<<14)		// GENM wad loaded

#define GAME_FLAG_NO_PAUSE_ALLOWED				(1<<15)		// Is paused allowed at the moment?

// Game flow flags, end of level detection, etc.
#define GAME_RESET_ALL_CHECKPOINTS_COLLECTED	(1<<0)		// all check points collected (by one or more frogs)
#define GAME_RESET_CHECKPOINT_COLLECTED			(1<<1)		// a single check points collected (by one or more frogs)
#define GAME_RESET_TIME_OUT						(1<<2)		// time run out for current level
#define	GAME_RESET_FROGS_DEAD					(1<<3)		// all frogs dead

// Game Timer Limit ramp defines...
#define	GAME_TIMER_FLAGS_COUNT_UP				(1<<0)
#define	GAME_TIMER_FLAGS_COUNT_DOWN				(1<<1)
#define	GAME_TIMER_FRAC							(3276)		// (1<<16)/20. Change by .1 every frame.
#define	GAME_TIMER_FRAC_LIMIT					(65536)		// (1<<16) Stop adding when we get to this value.
#define	GAME_TIMER_DEFAULT						(65536)		// (1<<16) Normally reduce by 1.

// Number of continues.
#define	GAME_CONTINUES							(3)			// Get to continue 3 times before it quits.

// When the Increase Timer Speed Powerup is collected. The Speed of the timer increases by
// GAME_TIMER_FRAC every frame, until it reaches GAME_TIMER_FRAC_LIMIT, when it starts to
// decrease by GAME_TIMER_FRAC until the Timer Speed reaches GAME_TIMER_DEFAULT. $gr

// Fonts
enum	{
		GAME_FONT_DEBUG,
		GAME_FONT_STANDARD,
		};

#ifdef WIN95
	#define	MAX_LOGIC_LOOPS_PER_RENDER		3		
	#define	LOGIC_CALLS_PER_SEC				30		
#endif

// Pause mode operation definitions
enum		{
			PAUSE_MODE_NO_PAUSE,
			PAUSE_MODE_INIT,
			PAUSE_MODE_FADE_DOWN,
			PAUSE_MODE_MENU,
			PAUSE_MODE_KILL_SPRITES,
			PAUSE_MODE_FADE_UP,
			PAUSE_MODE_DEINIT,
			};

// Time out
#define		TIME_OUT_MESSAGE_LEN			30*2

// ASync Loading.
enum
	{
	GAME_START_INIT,
	GAME_START_RUNNING,
	GAME_START_FINISHED,
	};

#define	GAME_OVER_MULTIPLAYER_OVERLAY_WIDTH		(140)
#define	GAME_OVER_MULTIPLAYER_OVERLAY_HEIGHT	(100)

enum	{
		GAME_END_SEQUENCE_CAMERA_TO_DOOR,
		GAME_END_SEQUENCE_OPEN_DOOR,
		GAME_END_SEQUENCE_WAITING_DOOR_OPEN,
		GAME_END_SEQUENCE_WAITING_FROG_HIT_STATUE,
		GAME_END_SEQUENCE_GOLD_FROG_APPEAR,
		GAME_END_SEQUENCE_NEXT_PLINTH,
		GAME_END_SEQUENCE_PLINTH_CAMERA_MOVE,
		GAME_END_SEQUENCE_PLINTH_RAISE,
		GAME_END_SEQUENCE_ALL_PLINTHS_RAISED,
		GAME_END_SEQUENCE_OPEN_EXIT_DOOR,
		GAME_END_SEQUENCE_WAITING_EXIT_DOOR_OPEN,
		GAME_END_SEQUENCE_NEXT_GOLD_FROGS_EXITING,
		GAME_END_SEQUENCE_FINAL_CAMERA_POS,
		GAME_END_SEQUENCE_FINAL_CAMERA_POS_MOVE,
		GAME_END_SEQUENCE_GOLD_FROG_JUMP_THR_DOOR,
		GAME_END_SEQUENCE_FROG_EXITING,
		GAME_END_SEQUENCE_FADE_SCREEN,
		GAME_END_SEQUENCE_END,
		};

enum	{
		GAME_MODE_MULTIPLAYER_CAMERA,
		GAME_MODE_MULTIPLAYER_NUMBER_ZOOM,
		GAME_MODE_MULTIPLAYER_NUMBER_ZOOM_WAIT,
		GAME_MODE_MULTIPLAYER_STAT_SCREEN,
		};

enum	{
		GAME_MODE_MULTIPLAYER_DATA_DELAY,
		GAME_MODE_MULTIPLAYER_DATA_MOVE,
		GAME_MODE_MULTIPLAYER_DATA_END,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __game_multi_complete			GAME_MULTI_COMPLETE;
typedef struct __game_multi_complete_data		GAME_MULTI_COMPLETE_DATA;
typedef struct __game_over_multiplayer			GAME_OVER_MULTIPLAYER;

struct __game_over_multiplayer
	{
	MR_2DSPRITE*				go_played_text;
	MR_2DSPRITE*				go_won_text;
	MR_2DSPRITE*				go_lost_text;
	MR_VOID*					go_played_number[2];
	MR_VOID*					go_won_number[2];
	MR_VOID*					go_lost_number[2];
	POLY_F4						go_prim_f[2];
	POLY_FT3					go_prim_ft[2];
	};	//GAME_OVER_MULTIPLAYER

struct __game_multi_complete_data
	{
	MR_LONG						gm_mode;
	MR_LONG						gm_counter;
	MR_XY						gm_pos;
	};

struct __game_multi_complete
	{
	MR_LONG						gm_mode;
	MR_2DSPRITE*				gm_numbers[4];
	GAME_MULTI_COMPLETE_DATA	gm_data[4];
	MR_LONG						gm_counter;
	};

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

// Viewports
extern	MR_VIEWPORT*	Game_viewport0;
extern	MR_VIEWPORT*	Game_viewport1;
extern	MR_VIEWPORT*	Game_viewport2;
extern	MR_VIEWPORT*	Game_viewport3;
extern	MR_VIEWPORT*	Game_viewporth;
extern	MR_VIEWPORT*	Game_viewportc;
extern	MR_VIEWPORT*	Game_viewports[];
extern	TILE			Game_clear_tiles[2];
extern	LINE_F3			Game_viewport_borders[4][2][2];
extern	MR_ULONG		Game_border_colours[];
extern	MR_2DSPRITE*	Game_multiplayer_no_player[4];

// Display
extern	MR_LONG			Game_perspective;
extern	MR_LONG			Game_display_width;
extern	MR_LONG			Game_display_height;
extern	MR_CVEC			Game_back_colour[];
extern	MR_ULONG		Game_border_colours[];

// System
extern	MR_VEC			Game_x_axis_pos;
extern	MR_VEC			Game_x_axis_neg;
extern	MR_VEC			Game_y_axis_pos;
extern	MR_VEC			Game_y_axis_neg;
extern	MR_VEC			Game_z_axis_pos;
extern	MR_VEC			Game_z_axis_neg;

// Main game
extern	MR_ULONG		Game_mode;						
extern	MR_BOOL			Game_running;
extern	MR_ULONG		Game_timer;
extern	MR_ULONG		Game_flags;
extern	MR_ULONG		Game_start_timer;
extern	MR_FRAC16		Game_map_timer_speed;
extern	MR_FRAC16		Game_map_timer_frac;
extern	MR_UBYTE		Game_map_timer_flags;
extern	MR_LONG			Game_map_timer;
extern	MR_LONG			Game_last_map_timer;
extern	MR_ULONG		Game_map_time;
extern	MR_ULONG		Game_reset_flags;
extern	MR_LONG			Game_continues_left;
#ifdef WIN95
extern	MR_BOOL			Game_is_network;		
#endif

// Stuff
extern	MR_ULONG		Game_mode;					
extern	MR_VOID*		Game_mode_data;				

// Game options
extern	MR_ULONG		Game_map;
extern	MR_ULONG		Game_map_theme;
extern	MR_ULONG		Game_total_players;
extern	MR_ULONG		Game_total_viewports;

// Fonts
extern	MR_FONT_INFO*	Game_font_infos[];

// mainloop callbacks
extern	MR_VOID			(*Game_mainloop_setup_functions[])(MR_VOID);
extern	MR_VOID			(*Game_mainloop_update_functions[])(MR_VOID);

// ASync loading.
extern	MR_LONG			Game_start_mode;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			GameColdInitialise(MR_VOID);
extern	MR_VOID			GameInitialise(MR_VOID);
extern	MR_VOID			GameStart(MR_VOID);
extern	MR_VOID			GameEnd(MR_VOID);
extern	MR_VOID			LevelStart(MR_ULONG);
extern	MR_VOID			LevelEnd(MR_VOID);

extern	MR_VOID			GameCreateViewports(MR_VOID);
extern	MR_VOID			GameKillViewports(MR_VOID);
extern	MR_VOID			GameStartLevel(MR_VOID);
extern	MR_VOID			GameUpdateLogic(MR_VOID);

// Main loop controller function and child functions
extern	MR_VOID			GameMainloop(MR_VOID);
extern	MR_VOID			SetGameMainloopMode(MR_ULONG);

extern	MR_VOID			GameMainloopSingleTriggerCollectedSetup(MR_VOID);
extern	MR_VOID			GameMainloopSingleFrogDiedSetup(MR_VOID);

extern	MR_VOID			GameMainloopSingleStartUpdate(MR_VOID);				
extern	MR_VOID			GameMainloopSingleTriggerCollectedUpdate(MR_VOID);		
extern	MR_VOID			GameMainloopSingleFailedUpdate(MR_VOID);
extern	MR_VOID			GameMainloopSingleFrogDiedUpdate(MR_VOID);		
extern	MR_VOID			GameMainloopSingleCompleteUpdate(MR_VOID);		
extern	MR_VOID			GameMainloopMultiStartUpdate(MR_VOID);			
extern	MR_VOID			GameMainloopMultiTriggerCollectedUpdate(MR_VOID);
extern	MR_VOID			GameMainloopMultiFailedUpdate(MR_VOID);
extern	MR_VOID			GameMainloopMultiFrogDiedUpdate(MR_VOID);			
extern	MR_VOID			GameMainloopMultiCompleteSetup(MR_VOID);
extern	MR_VOID			GameMainloopMultiCompleteUpdate(MR_VOID);					
extern	MR_VOID			GameMainloopPlayUpdate(MR_VOID);							
extern	MR_VOID			GameMainloopFastStartUpdate(MR_VOID);					
extern	MR_VOID			GameMainloopEndOfGameSetup(MR_VOID);
extern	MR_VOID			GameMainloopEndOfGameUpdate(MR_VOID);
extern	MR_VOID			GameMainloopEndOfMultiplayerGameSetup(MR_VOID);
extern	MR_VOID			GameMainloopEndOfMultiplayerGameUpdate(MR_VOID);

extern	MR_VOID			GameAddObjectToViewports(MR_OBJECT*);
extern	MR_VOID			GameAddAnimEnvToViewports(MR_ANIM_ENV*);
extern	MR_VOID			GameAddObjectToViewportsStoreInstances(MR_OBJECT*, MR_MESH_INST**);
extern	MR_VOID			GameAddAnimEnvToViewportsStoreInstances(MR_ANIM_ENV*, MR_ANIM_ENV_INST**);

extern	MR_VOID			GameSetViewportsPerspective(MR_VOID);
extern	MR_VOID			GameCheckStatus(MR_VOID);
extern	MR_BOOL			GameUpdateDebug(MR_VOID);
extern	MR_VOID			GameClearRender(MR_VOID);

#ifdef WIN95
extern	MR_VOID			GameUpdateWin95(MR_VOID);
extern	MR_VOID			GameNetworkSync(MR_VOID);
#endif

extern	MR_BOOL			GameHasThemeBeenCompleted(MR_LONG);
extern	MR_VOID			GameUpdateControllers(MR_VOID);

extern	MR_VOID			InitTransparentPolyBackground(MR_LONG, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID			UpdateTransparentPolyBackground(MR_VOID);
extern	MR_VOID			GameGetMultiplayerFrogCheckpointData(MR_LONG*, MR_LONG*, MR_LONG*);

#endif		//__GAMESYS_H

