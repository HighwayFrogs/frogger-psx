/******************************************************************************
*%%%% tempopt.h
*------------------------------------------------------------------------------
*
*	Header file for temp options routines
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

#ifndef	__TEMPOPT_H
#define	__TEMPOPT_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	ANTI_PIRACY_TIME					30*1					// Number of frames anti-piracy on screen for
#define	MAX_DEMO_TIME						30*60					// The most number of frames, demo mode can ever last for

#ifdef	PSX_RELEASE
#define	SCORE_TIME							30*27					// Timeout for main menu scrolly hiscores
#else
#define	SCORE_TIME							30*6					// Timeout for main menu scrolly hiscores
#endif

#define MAIN_MENU_Y_OFFSET					80						// offset from bottom of screen to top of main menu

#define NUM_OPTION_TICKS					31						// Number of ticks or frames per unit

#define NUM_MAIN_OPTIONS_OPTIONS			3						// Number of "main options" options
#define NUM_OPTIONS_OPTIONS					9						// Number of "option" options

#define	NUM_CONTINUE_UNITS					9						// Number of units until continue over
#define	NUM_CONTINUE_TICKS					NUM_OPTION_TICKS		// Number of ticks or frames per unit

#define	NUM_GAME_OVER_UNITS					2						// Number of units until game over over (used by level complete)
#define	NUM_GAME_OVER_TICKS					NUM_OPTION_TICKS		// Number of ticks or frames per unit (used by level complete)
#define	GAME_OVER_DURATION					(30 * 4)				// Duration of game over (from start of fade)
#define	GAME_OVER_PREDELAY					(30 * 2)				// Duration of game over (before start of fade)

#define	MAX_NUM_HIGH_SCORE_INITIALS			3						// Maximum number of initials the player can enter
#define	MAX_NUM_HIGH_SCORE_CHARACTERS		29						// Maximum number of letters the player can choose from ( A..Z / SPACE / RUB / ENTER )
#define	HIGH_SCORE_SPACE					26						// Position of RUB in letter selection
#define	HIGH_SCORE_RUB						27						// Position of RUB in letter selection
#define	HIGH_SCORE_END						28						// Position of END in letter selection

#define	NUM_HIGH_SCORE_ENTRIES_PER_TABLE	10						// Number of names per table
#define	NUM_HIGH_SCORE_TABLES				5						// Total number of high score tables

#define	SINGLE_PLAYER_HIGH_SCORE_STACK		0						// Number of single player high score stack
#define	MULTI_PLAYER_HIGH_SCORE_STACK		1						// Number of multi player high score stack

#define	MAX_HIGH_SCORE_TABLES				50						// Total number of high score tables ( one for each level )

//#define	MAX_NUM_DEMO_LEVELS					8						// Define the number of demo levels

#define	FROG_SELECTION_PLAYER1_MASTER			(1<<0)				// Warning - These four flags must be consecutive
#define	FROG_SELECTION_PLAYER2_MASTER			(1<<1)
#define	FROG_SELECTION_PLAYER3_MASTER			(1<<2)
#define	FROG_SELECTION_PLAYER4_MASTER			(1<<3)

#define	FROG_SELECTION_PLAYER1_JOINED			(1<<4)				// Warning - These four flags must be consecutive
#define	FROG_SELECTION_PLAYER2_JOINED			(1<<5)
#define	FROG_SELECTION_PLAYER3_JOINED			(1<<6)
#define	FROG_SELECTION_PLAYER4_JOINED			(1<<7)

#define	FROG_SELECTION_PLAYER1_FROG_SELECTED	(1<<8)				// Warning - These four flags must be consecutive
#define	FROG_SELECTION_PLAYER2_FROG_SELECTED	(1<<9)
#define	FROG_SELECTION_PLAYER3_FROG_SELECTED	(1<<10)
#define	FROG_SELECTION_PLAYER4_FROG_SELECTED	(1<<11)

#define	FROG_SELECTION_PLAYER1_COWERING			(1<<12)				// Warning - These four flags must be consecutive
#define	FROG_SELECTION_PLAYER2_COWERING			(1<<13)
#define	FROG_SELECTION_PLAYER3_COWERING			(1<<14)
#define	FROG_SELECTION_PLAYER4_COWERING			(1<<15)

#define	FROG_SELECTION_PLAYER1_GROWLING			(1<<16)				// Warning - These four flags must be consecutive
#define	FROG_SELECTION_PLAYER2_GROWLING			(1<<17)
#define	FROG_SELECTION_PLAYER3_GROWLING			(1<<18)
#define	FROG_SELECTION_PLAYER4_GROWLING			(1<<19)

#define	FROG_SELECTION_MASTER_WANTED			(1<<20)
#define	FROG_SELECTION_NO_MASTER				(1<<21)

#define	FROG_SELECTION_ALL_MASTERS				( FROG_SELECTION_PLAYER1_MASTER | FROG_SELECTION_PLAYER2_MASTER | FROG_SELECTION_PLAYER3_MASTER | FROG_SELECTION_PLAYER4_MASTER )

#define	NUM_FRAMES_COWERING_ANIMATION			30*10
#define	NUM_FRAMES_GROWLING_ANIMATION			30*10

// Following are input (selection) request flags
#define	FROG_REQUEST_PLAYER1_JOINING			(1<<0)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_JOINING			(1<<1)				
#define	FROG_REQUEST_PLAYER3_JOINING			(1<<2)				
#define	FROG_REQUEST_PLAYER4_JOINING			(1<<3)				
#define	FROG_REQUEST_PLAYER1_FROG_SELECTED		(1<<4)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_FROG_SELECTED		(1<<5)			
#define	FROG_REQUEST_PLAYER3_FROG_SELECTED		(1<<6)			
#define	FROG_REQUEST_PLAYER4_FROG_SELECTED		(1<<7)			
#define	FROG_REQUEST_PLAYER1_COWERING			(1<<8)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_COWERING			(1<<9)			
#define	FROG_REQUEST_PLAYER3_COWERING			(1<<10)			
#define	FROG_REQUEST_PLAYER4_COWERING			(1<<11)			
#define	FROG_REQUEST_PLAYER1_GROWLING			(1<<12)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_GROWLING			(1<<13)			
#define	FROG_REQUEST_PLAYER3_GROWLING			(1<<14)			
#define	FROG_REQUEST_PLAYER4_GROWLING			(1<<15)			
#define	FROG_REQUEST_PLAYER1_INCFROG			(1<<16)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_INCFROG			(1<<17)				
#define	FROG_REQUEST_PLAYER3_INCFROG			(1<<18)				
#define	FROG_REQUEST_PLAYER4_INCFROG			(1<<19)				
#define	FROG_REQUEST_PLAYER1_DECFROG			(1<<20)				// Warning - These four flags must be consecutive
#define	FROG_REQUEST_PLAYER2_DECFROG			(1<<21)			
#define	FROG_REQUEST_PLAYER3_DECFROG			(1<<22)			
#define	FROG_REQUEST_PLAYER4_DECFROG			(1<<23)			
#define FROG_REQUEST_START_GAME					(1<<24)				// Master player has requested a START GAME

#define	MAX_SELECTABLE_FROGS					5

enum
	{
	DEMO_LOADING_INIT,
	DEMO_LOADING_DEMO_LOADING,
	DEMO_LOADING_GAME_START,
	DEMO_LOADING_LEVEL_START,
	};

enum
	{
	MAIN_OPTIONS_STATUS_DEMO_INIT,
	MAIN_OPTIONS_STATUS_DEMO_MAIN,
	MAIN_OPTIONS_STATUS_DEMO_FADE_OUT,
	MAIN_OPTIONS_STATUS_DEMO_FINISH,
	MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT,
	MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_MAIN,
	MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_FINISH,
	};

enum
	{
	OPTION_MULTIPLAYER_MODE_LOCAL,
	OPTION_MULTIPLAYER_MODE_NETWORK,
	};

#define	OPTION_NETWORK_TYPE_MAX_ENTRIES		(10)
#define	OPTION_NETWORK_TYPE_MAX_CHARS		(500)

#define	OPTION_NETWORK_HOST_MAX_ENTRIES		(10)
#define	OPTION_NETWORK_HOST_MAX_CHARS		(500)

#define	OPTION_NETWORK_PLAY_MAX_ENTRIES		(4)
#define	OPTION_NETWORK_PLAY_MAX_CHARS		(100)

enum
	{
	OPTION_UPDATE_MODE_MAIN,
	OPTION_UPDATE_MODE_LANG_INIT,
	OPTION_UPDATE_MODE_LANG_SCROLL_ON,
	OPTION_UPDATE_MODE_LANG_MAIN,
	OPTION_UPDATE_MODE_LANG_SCROLL_OFF,
	OPTION_UPDATE_MODE_LANG_DEINIT,
	};

// Languages
enum
	{
	GAME_LANGUAGE_ENGLISH,
	GAME_LANGUAGE_ITALIAN,
	GAME_LANGUAGE_GERMAN,
	GAME_LANGUAGE_FRENCH,
	GAME_LANGUAGE_SPANISH,
	};

// Text texture defines
enum
	{
	OPTION_TEXT_NEXT,			
	OPTION_TEXT_PAUSED,			
	OPTION_TEXT_PRESS_FIRE,		
	OPTION_TEXT_QUIT,			
	OPTION_TEXT_TOTAL_SCORE,	
	OPTION_TEXT_TOTAL_TIME,		
	OPTION_TEXT_MEM_MESSAGE,	
	OPTION_TEXT_LOST,			
	OPTION_TEXT_PLAYED,			
	OPTION_TEXT_WON,			
	OPTION_TEXT_SELECT1,		
	OPTION_TEXT_SELECT2,		
	OPTION_TEXT_SELECT3,		
	OPTION_TEXT_SELECT4,
	OPTION_TEXT_SELECT5,
	OPTION_TEXT_LOADING,		
	OPTION_TEXT_INSERT_PAD,		
	OPTION_TEXT_START,			
	OPTION_TEXT_OPTIONS,		
	OPTION_TEXT_RACE,			
	OPTION_TEXT_YES,			
	OPTION_TEXT_NO,				
	OPTION_TEXT_GAMEOVER,		
	OPTION_TEXT_CTRL_CONFIG,	
	OPTION_TEXT_EXIT,			
	OPTION_TEXT_LOAD_HS,		
	OPTION_TEXT_LOAD_HS_SM,		
	OPTION_TEXT_SAVE_HS,		
	OPTION_TEXT_LOAD_OK,		
	OPTION_TEXT_NO_CARD,		
	OPTION_TEXT_NO_DATA,		
	OPTION_TEXT_NO_SPACE,		
	OPTION_TEXT_FORMAT2,		
	OPTION_TEXT_OVERWRITE,		
	OPTION_TEXT_RETURN,			
	OPTION_TEXT_SAVE_OK,		
	OPTION_TEXT_SELECT_CARD,	
	OPTION_TEXT_ZONE_COMPLETE,	
	OPTION_TEXT_SAVE_FAILED,	
	OPTION_TEXT_FORMAT_FAILED,	
	OPTION_TEXT_UNFORMATTED,	
	OPTION_TEXT_LOAD_FAILED,	
	OPTION_TEXT_HOP_TO_IT,		
	OPTION_TEXT_GO_FROGGER,		
	OPTION_TEXT_GO,				
	OPTION_TEXT_GO_GET_EM,		
	OPTION_TEXT_JUMP_TO_IT,		
	OPTION_TEXT_CROAK,			
	OPTION_TEXT_SELECT_LEVEL,	
	OPTION_TEXT_VIEW_HISCORES,	
	OPTION_TEXT_PLAY_AGAIN,		
	OPTION_TEXT_CHOOSE_COURSE,	
	OPTION_TEXT_START_RACE,		
	OPTION_TEXT_CHECK_SAVE,
	OPTION_TEXT_TIMEOUT,
	OPTION_TEXT_BONUS,
	OPTION_TEXT_BIG_CONTINUE,
	OPTION_TEXT_SKIP_HI_SCORE,
	OPTION_TEXT_NOW_SAVING,
	OPTION_TEXT_NOW_LOADING,
	OPTION_TEXT_NOW_FORMATTING,
	OPTION_TEXT_NOW_CHECKING,

	OPTION_TEXT_TOTAL
	};

#define		OPTIONS_NUM_OPTIONS				7			// Current number of options
#define		OPTIONS_NUM_EXTRAS				7			// number of extra models
#define		OPTIONS_SOUND_STAGES			8			// number of stages on sound fx/music bars

// These have been changed because our MUSIC is louder than SFX. $gr
#define		OPTION_START_MUSIC_VALUE		3			// start value for music
#define		OPTION_START_SOUND_VALUE		5			// start value for sound

enum
	{
	OPTIONS_EXIT_OPTION,
	OPTIONS_VIEW_HIGH_SCORES_OPTION,
	OPTIONS_LOAD_HS_OPTION,
	OPTIONS_SAVE_HS_OPTION,
	OPTIONS_CTRL_CONFIG_OPTION,
	OPTIONS_MUSIC_OPTION,
	OPTIONS_FX_OPTION,
	};

#define		MAX_NUM_LANGUAGES		5			// Number of languages to show
#define		FLAG_X_GAP				64			// Spacing between the beginning of one flag and the beginning of the next
#define		FLAG_MOVEMENT_SPEED		10			// Speed at which to move flags per frame
#define		FIRST_FLAG_X_POSITION	32			// Move flags on screen until first flag reaches this x position
#define		LAST_FLAG_X_POSITION	-128		// Move flags off screen until last flag is at this x position

enum
	{
	OPTIONS_LANGUAGE_MODE_SCROLL_ON,
	OPTIONS_LANGUAGE_MODE_SELECTION,
	OPTIONS_LANGUAGE_MODE_SCROLL_OFF,
	};

// Number of pads
#define		MAX_NUM_PADS			4

// Number of different pad configurations
#define		MAX_NUM_PAD_CONFIGS		4

// Offset for main options page (START, RACE, OPTIONS)
#define		OPTIONS_CAMERA_MAIN_SOURCE_OFS_X		0
#define		OPTIONS_CAMERA_MAIN_SOURCE_OFS_Y		-2500
#define		OPTIONS_CAMERA_MAIN_SOURCE_OFS_Z		-1280
#define		OPTIONS_CAMERA_MAIN_TARGET_OFS_X		0
#define		OPTIONS_CAMERA_MAIN_TARGET_OFS_Y		1024
#define		OPTIONS_CAMERA_MAIN_TARGET_OFS_Z		-800

// Offset for options menu (EXIT, etc)
#define		OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_X		-1200
#define		OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Y		-2000
#define		OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Z		-1800
#define		OPTIONS_CAMERA_OPTIONS_TARGET_OFS_X		300
#define		OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Y		1000
#define		OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Z		500

// Offset for overall hiscore screen
#define		OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_X	0
#define		OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_Y	-3200
#define		OPTIONS_CAMERA_HS_STATIC_SOURCE_OFS_Z	-200
#define		OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_X	0
#define		OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_Y	1024
#define		OPTIONS_CAMERA_HS_STATIC_TARGET_OFS_Z	50

// Camera move stuff
#define		OPTIONS_CAMERA_FLYOFF_TIME				10
#define		OPTIONS_CAMERA_FLYOFF_SPEED				0x100
#define		OPTIONS_CAMERA_FLYON_TIME				10
#define		OPTIONS_CAMERA_FLYON_SPEED				0xa0
#define		OPTIONS_CAMERA_FLYON_HEIGHT				-((OPTIONS_CAMERA_FLYON_TIME + 0) * OPTIONS_CAMERA_FLYON_SPEED) 

#define		OPTIONS_CAMERA_SCROLL_TIME				60		// to scroll through high scores

#define		OPTIONS_CAMERA_MOVE_TIME 				(OPTIONS_CAMERA_FLYOFF_TIME + OPTIONS_CAMERA_FLYON_TIME)

// Main menu cloud
#define		OPTIONS_CLOUD_BORDER					8


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __option_demo_level		OPTION_DEMO_LEVEL;
typedef struct __frog_selection			FROG_SELECTION;
typedef struct __demo_data				DEMO_DATA;
typedef struct __opt_level_complete		OPT_LEVEL_COMPLETE;

struct __option_demo_level
	{
	MR_LONG			dl_world_number;
	MR_LONG			dl_level_number;

	};	// OPTION_DEMO_LEVEL


struct __frog_selection
	{
	MR_SVEC				fs_rot;				// Rotation of Frog
	MR_ULONG			fs_current_frog;	// Number of current Frog selected

	};	// FROG_SELECTION


struct __demo_data
	{
	MR_ULONG			dd_num_frames;							// Number of frames of data
	MR_ULONG			dd_start_grid_x;						// X Position of frog
	MR_ULONG			dd_start_grid_z;						// Z Position of frog
	MR_UBYTE			dd_input_data[MAX_DEMO_TIME];			// Player input ( button presses )

	};	// DEMO_DATA


// Added by martin, for level select screen
struct __opt_level_complete
	{
	MR_2DSPRITE*		Level_complete_title_sprite_ptr;	// Pointer to 2D sprite
	MR_2DSPRITE*		Level_complete_checkpoints[5];
	MR_VOID*			Level_complete_checkpoint_time[5];
	MR_2DSPRITE*		Level_complete_total_time_text;
	MR_2DSPRITE*		Level_complete_total_time[4];
	MR_2DSPRITE*		Level_complete_total_score_text;
	MR_2DSPRITE*		Level_complete_total_score[5];
	MR_BOOL				Level_complete_next_level;
	MR_2DSPRITE*		Level_complete_next_level_text;
	MR_2DSPRITE*		Level_complete_next_level_des;
	MR_2DSPRITE*		Level_complete_press_fire;
	MR_2DSPRITE*		Level_complete_press_tri;
	MR_2DSPRITE*		Level_complete_golden_frog;
	POLY_F4				Level_complete_prim_f[2];
	POLY_FT3			Level_complete_prim_ft[2];
	}; // OPT_LEVEL_COMPLETE

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_USHORT		Main_options_status;					// Status of operation for main options screen

extern	MR_ULONG		Game_language;							// Current language
extern	MR_ULONG		Opt_resource_files[];					// Language Resource file to load.

extern	MR_UBYTE		Music_volume;
extern	MR_UBYTE		Sound_volume;

extern	MR_TEXT_AREA*	Option_load_text_area[];
extern	MR_TEXT_AREA*	Option_save_text_area[];
extern	MR_TEXT_AREA*	Option_format_text_area[];

extern	DEMO_DATA		Demo_data;								// Actual demo data
extern	MR_BOOL			Recording_demo;							// Flag recording demo
extern	MR_BYTE*		Demo_data_input_ptr;					// Ptr to demo mode input data
extern	MR_LONG			Demo_time;								// Time demo to last for
extern	MR_UBYTE		Demo_file_name[60][16];					// File names for demo modes
//extern	DEMO_DATA*		Demo_data_ptrs[];
extern	DEMO_DATA*		Demo_data_ptr;

extern	MR_ULONG		Frog_selection_master_flags;			// Frog selection flags
extern	MR_ULONG		Frog_selection_network_request_flags;	// Network frog selection flags
extern	MR_ULONG		Frog_selection_master_player_id;		// Multiplayer network master player id
extern	MR_ULONG		Frog_selection_request_flags;			// Frog selection request flags

extern	MR_BOOL			From_options;

extern	MR_TEXTURE*		Options_text_textures[OPTION_TEXT_TOTAL][MAX_NUM_LANGUAGES];

#ifdef WIN95
extern	MR_TEXT_AREA*	Option_network_type_text_area[OPTION_NETWORK_TYPE_MAX_ENTRIES];
extern	MR_STRPTR		Option_network_type_text_buff[OPTION_NETWORK_TYPE_MAX_ENTRIES][70];
extern	MR_STRPTR		Option_network_type_text_tag;
extern	MR_ULONG		Option_network_type_number_providers;
extern	MR_ULONG		Option_network_type_selected_provider;

extern	MR_TEXT_AREA*	Option_network_host_text_area[OPTION_NETWORK_HOST_MAX_ENTRIES];
extern	MR_STRPTR		Option_network_host_text_buff[OPTION_NETWORK_HOST_MAX_ENTRIES][70];
extern	MR_STRPTR		Option_network_host_text_tag;
extern	MR_ULONG		Option_network_host_number_providers;
extern	MR_ULONG		Option_network_host_selected_provider;

extern	MR_TEXT_AREA*	Option_network_play_text_area[OPTION_NETWORK_PLAY_MAX_ENTRIES];
extern	MR_STRPTR		Option_network_play_text_buff[OPTION_NETWORK_PLAY_MAX_ENTRIES][70];
extern	MR_STRPTR		Option_network_play_text_tag;
extern	MR_ULONG		Option_network_play_number_players;
#endif

extern	MR_ULONG		Num_demo_levels_seen;
extern	MR_BOOL			Options_music_playing;

extern	MR_ULONG		Option_number;					// Number of option currently selected
extern	MR_BOOL			Game_demo_loading;
extern	MR_BOOL			Game_over_no_new_sound;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		VersionStartup(MR_VOID);
extern	MR_VOID		VersionUpdate(MR_VOID);
extern	MR_VOID		VersionShutdown(MR_VOID);

#ifdef PSX		// PSX Specific code ----------------------------------------
extern	MR_VOID		AntiPiracyStartup(MR_VOID);
extern	MR_VOID		AntiPiracyUpdate(MR_VOID);
extern	MR_VOID		AntiPiracyShutdown(MR_VOID);
#endif	// PSX

extern	MR_VOID		HasbroLogoStartup(MR_VOID);
extern	MR_VOID		HasbroLogoUpdate(MR_VOID);
extern	MR_VOID		HasbroLogoShutdown(MR_VOID);

extern	MR_VOID		MillenniumLogoStartup(MR_VOID);
extern	MR_VOID		MillenniumLogoUpdate(MR_VOID);
extern	MR_VOID		MillenniumLogoShutdown(MR_VOID);

extern	MR_VOID		IntroStartup(MR_VOID);
extern	MR_VOID		IntroUpdate(MR_VOID);
extern	MR_VOID		IntroShutdown(MR_VOID);

extern	MR_VOID		MainOptionsStartup(MR_VOID);
extern	MR_VOID		MainOptionsUpdate(MR_VOID);
extern	MR_VOID		MainOptionsShutdown(MR_VOID);
extern	MR_VOID		OptionsUpdateAPI(MR_VOID);

#ifdef WIN95
extern	MR_VOID		MultiplayerModeOptionsStartup(MR_VOID);
extern	MR_VOID		MultiplayerModeOptionsUpdate(MR_VOID);
extern	MR_VOID		MultiplayerModeOptionsShutdown(MR_VOID);

extern	MR_VOID		NetworkTypeOptionsStartup(MR_VOID);
extern	MR_VOID		NetworkTypeOptionsUpdate(MR_VOID);
extern	MR_VOID		NetworkTypeOptionsShutdown(MR_VOID);

extern	MR_VOID		NetworkHostOptionsStartup(MR_VOID);
extern	MR_VOID		NetworkHostOptionsUpdate(MR_VOID);
extern	MR_VOID		NetworkHostOptionsShutdown(MR_VOID);

extern	MR_VOID		NetworkPlayOptionsStartup(MR_VOID);
extern	MR_VOID		NetworkPlayOptionsUpdate(MR_VOID);
extern	MR_VOID		NetworkPlayOptionsShutdown(MR_VOID);
#endif

extern	MR_VOID		OptionsStartup(MR_VOID);
extern	MR_VOID		OptionsSetupVolumeLogAnimatedPolys(MR_MESH*, MR_LONG);
extern	MR_VOID		OptionsUpdate(MR_VOID);
extern	MR_VOID		OptionsUpdateFrog(MR_VOID);
extern	MR_VOID		OptionsShutdown(MR_VOID);

extern	MR_VOID		FrogSelectionStartup(MR_VOID);
extern	MR_VOID		FrogSelectionUpdate(MR_VOID);
extern	MR_VOID		FrogSelectionShutdown(MR_VOID);
extern	MR_VOID		FrogSelectionCreateFrog(MR_LONG, MR_LONG);

extern	MR_VOID		FrogSelectionReadInput(MR_VOID);
extern	MR_VOID		FrogSelectionNetworkUpdate(MR_VOID);

extern	MR_VOID		ContinueStartup(MR_VOID);
extern	MR_VOID		ContinueUpdate(MR_VOID);
extern	MR_VOID		ContinueShutdown(MR_VOID);

extern	MR_VOID		GameOverStartup(MR_VOID);
extern	MR_VOID		GameOverUpdate(MR_VOID);
extern	MR_VOID		GameOverShutdown(MR_VOID);

extern	MR_VOID		OutroStartup(MR_VOID);
extern	MR_VOID		OutroUpdate(MR_VOID);
extern	MR_VOID		OutroShutdown(MR_VOID);

extern	MR_VOID		LanguageSelectionStartup(MR_VOID);
extern	MR_VOID		LanguageSelectionUpdate(MR_VOID);
extern	MR_VOID		LanguageSelectionShutdown(MR_VOID);

#ifdef PSX		// PSX Specific code ----------------------------------------
extern	MR_VOID		RedefinePSXButtonsStartup(MR_VOID);
extern	MR_VOID		RedefinePSXButtonsUpdate(MR_VOID);
extern	MR_VOID		RedefinePSXButtonsShutdown(MR_VOID);
#else			// Windows Specific code ------------------------------------
extern	MR_VOID		ChooseWINControllerStartup(MR_VOID);
extern	MR_VOID		ChooseWINControllerUpdate(MR_VOID);
extern	MR_VOID		ChooseWINControllerShutdown(MR_VOID);
#endif			// PSX

extern	MR_VOID		LevelCompleteStartup(MR_VOID);
extern	MR_VOID		LevelCompleteUpdate(MR_VOID);
extern	MR_VOID		LevelCompleteShutdown(MR_VOID);

extern	MR_VOID		OptUpdateGame(MR_VOID);
extern	MR_VOID 	OptionsTidyMemory(MR_BOOL);

extern	MR_VOID		LoadOptionsResources(MR_VOID);
extern	MR_VOID		UnloadOptionsResources(MR_VOID);
extern	MR_VOID		InitialiseOptionsCamera(MR_VOID);
extern	MR_VOID		OptionsCameraMoveToMain(MR_VOID);
extern	MR_VOID		OptionsCameraSnapToMain(MR_VOID);
extern	MR_VOID		OptionsCameraMoveToOptions(MR_VOID);
extern	MR_VOID		OptionsCameraSnapToOptions(MR_VOID);

extern	MR_VOID		ShowWaterStartup(MR_VOID);
extern	MR_VOID		ShowWaterUpdate(MR_VOID);
extern	MR_VOID		ShowWaterShutdown(MR_VOID);

extern	MR_VOID		PlayAgainStartup(MR_VOID);
extern	MR_VOID		PlayAgainUpdate(MR_VOID);
extern	MR_VOID		PlayAgainShutdown(MR_VOID);

extern	MR_VOID		PlayOptionsMusic(MR_VOID);
extern	MR_VOID		ShutdownOptionsMusic(MR_VOID);

extern	MR_VOID		SwitchOffOptionsMenu(MR_VOID);
extern	MR_VOID		SwitchOnOptionsMenu(MR_VOID);

#endif	//__TEMPOPT_H
