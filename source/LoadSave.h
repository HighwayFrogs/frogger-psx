/******************************************************************************
*%%%% loadsave.h
*------------------------------------------------------------------------------
*
*	Header file for memory card \ registry routines
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	07.07.97	William Bell	Created
*
*%%%**************************************************************************/

#ifndef	__LOADSAVE_H
#define	__LOADSAVE_H 

#include "mr_all.h"
#include "hsview.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Maximum number of selections
#define	MAX_NUM_SELECTIONS				10

// Spin rate for memory card models
#define	LOADSAVE_CARD_ROTATION_RATE		0x80

// Modes of operation for load
enum
	{
	LS_LOAD_MODE_INIT_INIT,
	LS_LOAD_MODE_INIT_WAIT,
	LS_LOAD_MODE_INIT_CHECK,
	LS_LOAD_MODE_INIT_UPDATE,
	LS_LOAD_MODE_SURE_INIT,
	LS_LOAD_MODE_SURE_UPDATE,
	LS_LOAD_MODE_SURE_DEINIT,
	LS_LOAD_MODE_SELECT_CARD_INIT,
	LS_LOAD_MODE_SELECT_CARD_UPDATE,
	LS_LOAD_MODE_SELECT_CARD_DEINIT,
	LS_LOAD_MODE_LOAD_INIT,
	LS_LOAD_MODE_LOAD_WAIT,
	LS_LOAD_MODE_LOAD,
	LS_LOAD_MODE_NO_SAVES_INIT,
	LS_LOAD_MODE_NO_SAVES_UPDATE,
	LS_LOAD_MODE_SUCCESS_INIT,
	LS_LOAD_MODE_SUCCESS_UPDATE,
	LS_LOAD_MODE_FAILURE_INIT,
	LS_LOAD_MODE_FAILURE_UPDATE,
	LS_LOAD_MODE_NO_CARD_PRESENT_INIT,
	LS_LOAD_MODE_NO_CARD_PRESENT_UPDATE,
	LS_LOAD_MODE_NO_CARD_INIT,
	LS_LOAD_MODE_NO_CARD_UPDATE,
	LS_LOAD_MODE_NO_GAME_INIT,
	LS_LOAD_MODE_NO_GAME_UPDATE,
	LS_LOAD_MODE_UNFORMATTED_INIT,
	LS_LOAD_MODE_UNFORMATTED_UPDATE,
	LS_LOAD_MODE_EXIT,
	};

// Modes of operation for save
enum
	{
	LS_SAVE_MODE_INIT_INIT,
	LS_SAVE_MODE_INIT_WAIT,
	LS_SAVE_MODE_INIT_CHECK,
	LS_SAVE_MODE_SURE_INIT,
	LS_SAVE_MODE_SURE_UPDATE,
	LS_SAVE_MODE_SURE_DEINIT,
	LS_SAVE_MODE_SELECT_CARD_INIT,
	LS_SAVE_MODE_SELECT_CARD_UPDATE,
	LS_SAVE_MODE_SELECT_CARD_DEINIT,
	LS_SAVE_MODE_SAVE_INIT,
	LS_SAVE_MODE_SAVE_WAIT,
	LS_SAVE_MODE_SAVE,
	LS_SAVE_MODE_OVERWRITE_INIT,
	LS_SAVE_MODE_OVERWRITE_UPDATE,
	LS_SAVE_MODE_FORMAT_INIT,
	LS_SAVE_MODE_FORMAT_UPDATE,
	LS_SAVE_MODE_FORMAT_MESSAGE_INIT,
	LS_SAVE_MODE_FORMAT_WAIT,
	LS_SAVE_MODE_FORMAT_DEINIT,
	LS_SAVE_MODE_NO_CARDS_INIT,
	LS_SAVE_MODE_NO_CARDS_UPDATE,
	LS_SAVE_MODE_CARD_FULL_INIT,
	LS_SAVE_MODE_CARD_FULL_UPDATE,
	LS_SAVE_MODE_SUCCESS_INIT,
	LS_SAVE_MODE_SUCCESS_UPDATE,
	LS_SAVE_MODE_NO_CARD_INIT,
	LS_SAVE_MODE_NO_CARD_UPDATE,
	LS_SAVE_MODE_SAVE_ERROR_INIT,
	LS_SAVE_MODE_SAVE_ERROR_UPDATE,
	LS_SAVE_MODE_FORMAT_ERROR_INIT,
	LS_SAVE_MODE_FORMAT_ERROR_UPDATE,
	LS_SAVE_MODE_EXIT,
	};

// Modes of operation for check saves screen
enum
	{
	LS_CHECK_MODE_INIT_INIT,
	LS_CHECK_MODE_INIT_WAIT,
	LS_CHECK_MODE_INIT_CHECK,
	LS_CHECK_MODE_INIT_UPDATE,
	LS_CHECK_INFO,
	LS_CHECK_MODE_SURE_INIT,
	LS_CHECK_MODE_SURE_UPDATE,
	LS_CHECK_MODE_SURE_DEINIT,
	LS_CHECK_MODE_SELECT_CARD_INIT,
	LS_CHECK_MODE_SELECT_CARD_UPDATE,
	LS_CHECK_MODE_SELECT_CARD_DEINIT,
	LS_CHECK_MODE_LOAD_INIT,
	LS_CHECK_MODE_LOAD_WAIT,
	LS_CHECK_MODE_LOAD,
	LS_CHECK_MODE_SUCCESS_INIT,
	LS_CHECK_MODE_SUCCESS_UPDATE,
	LS_CHECK_MODE_FULL_INIT,
	LS_CHECK_MODE_FULL_UPDATE,
	LS_CHECK_MODE_FAILURE_INIT,
	LS_CHECK_MODE_FAILURE_UPDATE,
	LS_CHECK_MODE_NO_CARD_INIT,
	LS_CHECK_MODE_NO_CARD_UPDATE,
	LS_CHECK_MODE_NO_GAME_INIT,
	LS_CHECK_MODE_NO_GAME_UPDATE,
	LS_CHECK_MODE_UNFORMATTED_INIT,
	LS_CHECK_MODE_UNFORMATTED_UPDATE,
	LS_CHECK_MODE_EXIT,
	};

// Modes of operation for selection screen
enum
	{
	LS_SELECT_MODE_INIT,
	LS_SELECT_MODE_INPUT,
	LS_SELECT_MODE_EXIT,
	};

// Directions of operation for selection screen
enum
	{
	LS_SELECT_DIR_LEFT_AND_RIGHT,
	LS_SELECT_DIR_UP_AND_DOWN,
	LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT,
	};

// Modes of operation for message screen
enum
	{
	LS_MESSAGE_MODE_INIT,
	LS_MESSAGE_MODE_WAIT,
	LS_MESSAGE_MODE_EXIT,
	};

#if 0

// Load modes
enum
	{
	LOAD_STATUS_LOAD,
	LOAD_STATUS_CHOOSE_GAME_INIT,
	LOAD_STATUS_CHOOSE_GAME_MAIN,
	LOAD_STATUS_CHOOSE_GAME_END,
	LOAD_STATUS_REPORT,
	LOAD_STATUS_WAIT,
	};

// Save modes
enum
	{
	SAVE_STATUS_INIT,
	SAVE_STATUS_NO_CARDS,
	SAVE_STATUS_CHOOSE_GAME_INIT,
	SAVE_STATUS_CHOOSE_GAME_MAIN,
	SAVE_STATUS_CHOOSE_GAME_END,
	SAVE_STATUS_SAVE_0,
	SAVE_STATUS_SAVE_1,
	SAVE_STATUS_FORMAT_0_INIT,
	SAVE_STATUS_FORMAT_0_MAIN,
	SAVE_STATUS_FORMAT_0_END,
	SAVE_STATUS_FORMAT_1_INIT,
	SAVE_STATUS_FORMAT_1_MAIN,
	SAVE_STATUS_FORMAT_1_END,
	SAVE_STATUS_FINISH,
	};

// Read modes
enum
	{
	READ_STATUS_INIT,
	READ_STATUS_CHOOSE_GAME_INIT,
	READ_STATUS_CHOOSE_GAME_MAIN,
	READ_STATUS_CHOOSE_GAME_END,
	READ_STATUS_LOAD_0,
	READ_STATUS_LOAD_1,
	READ_STATUS_FINISH,
	};

#endif

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __control_options		CONTROL_OPTIONS;

struct __control_options
	{

	MR_USHORT			co_music_volume;					// Current music volume setting
	MR_USHORT			co_sound_volume;					// Current sound volume setting
	MR_USHORT			co_language;						// Selected Language

#ifdef WIN95	// Windows specific options ---------------------------------

	MR_USHORT			co_device_id[4];					// Device of choice
	MR_USHORT			co_hop_up[4];						// up hop
	MR_USHORT			co_hop_down[4]; 					// down hop
	MR_USHORT			co_hop_left[4]; 					// left hop
	MR_USHORT			co_hop_right[4];					// right hop
	MR_USHORT			co_croak[4];						// croak
	MR_USHORT			co_super_tongue[4];					// super tongue
	MR_USHORT			co_super_jump[4];					// super jump
	MR_USHORT			co_rotate_left[4];					// rotate camera left 90 degrees
	MR_USHORT			co_rotate_right[4];					// rotate camera right 90 degrees

#else			// PSX specific options -------------------------------------

	MR_USHORT			co_pad0_control_config;				// Control config for pad 0
	MR_USHORT			co_pad1_control_config;				// Control config for pad 1
	MR_USHORT			co_pad2_control_config;				// Control config for pad 2
	MR_USHORT			co_pad3_control_config;				// Control config for pad 3

#endif			// WIN95

	MR_ULONG			co_selectable_levels[60];			// Currently accessible levels
	MR_ULONG			co_number_of_golden_frogs;			// Number of golden frogs collected

	HIGH_SCORE_ENTRY	co_game_high_score[10];				// Main high scores
	HIGH_SCORE_ENTRY	co_level_high_scores[60][3];		// Arcade high scores

	};	// CONTROL_OPTIONS

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

#ifdef WIN95	// Windows specific code ------------------------------------
extern	MR_VOID		OptionsGetRegistryStatus(MR_VOID);
extern	MR_VOID		OptionsCloseRegistry(MR_VOID);
#else			// PSX Specific code ----------------------------------------
extern	MR_VOID		OptionsGetCardStatus(MR_VOID);
#endif	// WIN95

#ifdef	WIN95	// Windows specific code ------------------------------------
extern	MR_VOID		OptionsSaveSaveData(MR_VOID);
#else			// PSX Specific code ----------------------------------------
extern	MR_BOOL		OptionsCheckCardFull(MR_ULONG);
extern	MR_ULONG	OptionsFormatCard(MR_ULONG);
extern	MR_ULONG	OptionsSaveSaveData(MR_ULONG);
#endif			// WIN95

#ifdef	WIN95	// Windows specific code ------------------------------------
extern	MR_VOID		OptionsLoadSaveData(MR_VOID);
#else			// PSX Specific code ----------------------------------------
extern	MR_ULONG	OptionsLoadSaveData(MR_ULONG);
#endif			// WIN95
extern	MR_ULONG	OptionsLoadSaveDataHeader(MR_ULONG);

extern	MR_VOID		SaveStartup(MR_VOID);
extern	MR_VOID		SaveUpdate(MR_VOID);
extern	MR_VOID		SaveShutdown(MR_VOID);

extern	MR_VOID		LoadStartup(MR_VOID);
extern	MR_VOID		LoadUpdate(MR_VOID);
extern	MR_VOID		LoadShutdown(MR_VOID);

extern	MR_VOID		CheckStartup(MR_VOID);
extern	MR_VOID		CheckUpdate(MR_VOID);
extern	MR_VOID		CheckShutdown(MR_VOID);

extern	MR_VOID		LSSelect(MR_VOID);
extern	MR_VOID		LSMessage(MR_VOID);

#ifdef PSX
extern	MR_VOID 	LSCreateMemoryCards(MR_VOID);
extern	MR_VOID 	LSUpdateMemoryCards(MR_VOID);
extern	MR_VOID 	LSKillMemoryCards(MR_VOID);
#endif

extern	MR_VOID		DecodeSaveData(MR_VOID);
extern	MR_VOID		DecodeSaveDataHeader(MR_VOID);
extern	MR_VOID		EncodeSaveData(MR_VOID);

#endif	//__LOADSAVE_H
