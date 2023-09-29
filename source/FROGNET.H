/******************************************************************************
*%%%% frognet.h
*------------------------------------------------------------------------------
*
*	Header file for frog net code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef		__FROGNET_H
#define		__FROGNET_H

#include	"mr_all.h"

#ifdef WIN95
#include	<windowsx.h>
#include	"cdaudio.h"
#include	"netplay.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	MAX_SYNC_WAIT_TIME					(30*120)
#define	MAX_NUMBER_REQUESTS					(5)

// frogger flags (for sending data)
#define		FRNET_FROG_FLAG_POS				(1<<0)
#define		FRNET_FROG_FLAG_ANIM			(1<<1)
#define		FRNET_FROG_FLAG_FLAGS			(1<<2)

// Frogger specific messages
enum{
		FRNET_MSG_BASE = MNM_USER+1,

		// following are generic msgs
		FRNET_MSG_SYNC,
		FRNET_MSG_SYNC_OK,
		
		// following are options screens messages
		FRNET_MSG_OPTIONS_FROG_SELECT,
		FRNET_MSG_OPTIONS_START_GAME,
		FRNET_MSG_OPTIONS_LEVEL_SELECT_UPDATE,
		FRNET_MSG_OPTIONS_GOTO_FROG_SELECT,

		// Following are game msgs
		FRNET_MSG_GAME_READY_TO_START,
		FRNET_MSG_GAME_FROG_DATA,
		FRNET_MSG_GAME_RESTART,
		FRNET_MSG_GAME_FRAME_COUNT_SYNC,

		// trailer
		FRNET_MSG_LAST_MESSAGE
} FRNET_MESSAGES;


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __frnet_generic					FRNET_GENERIC;
typedef struct __frnet_game_frog_data			FRNET_GAME_FROG_DATA;
typedef struct __frnet_options_frog_select		FRNET_OPTIONS_FROG_SELECT;
typedef struct __frnet_options_start_game		FRNET_OPTIONS_START_GAME;
typedef struct __frnet_game_ready_to_start		FRNET_GAME_READY_TO_START;
typedef struct __frnet_sync						FRNET_SYNC;
typedef struct __frnet_game_frame_sync			FRNET_GAME_FRAME_SYNC;


struct __frnet_generic
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;
};	// FRNET_GENERIC

struct __frnet_game_frog_data
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;

	MR_UBYTE	flags;
	MR_UBYTE	anim_equate;
	MR_UBYTE	anim_type;
	MR_MAT		matrix;
	MR_ULONG	frog_flags;
};	// FRNET_GAME_FROG_DATA

struct __frnet_options_frog_select
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;

    MR_ULONG	master_flags;
};	// FRNET_OPTIONS_FROG_SELECT

struct __frnet_game_ready_to_start
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;
};	// FRNET_GAME_READY_TO_START

struct __frnet_options_start_game
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;

	MR_LONG		world;					// World (theme) number
	MR_LONG		level;					// Level number
};	// FRNET_OPTIONS_START_GAME

struct __frnet_sync
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;
};	// FRNET_SYNC

struct __frnet_game_frame_sync
{
    MR_UBYTE	type;
	UINT		msg;
	MR_UBYTE	player_number;
	MR_UBYTE	size;

	MR_ULONG	frame;
};	// FRNET_GAME_FRAME_SYNC

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	volatile	MR_ULONG	CurrentPlayersSynced;
extern	volatile	MR_ULONG	PlayerSyncData[4];
extern	volatile	MR_BOOL		WaitingForSync;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern 	MR_VOID		GameMessageHandlerCallBack(FRNET_GENERIC, DWORD, DPID, DPID);

// Following are sending msg functions
extern	MR_VOID		SendFrogData(MR_ULONG, MR_VOID*, MR_ULONG, MR_ULONG, MR_ULONG);
extern	MR_VOID		SendOptionsFrogSelect(MR_ULONG);
extern	MR_VOID		SendOptionsStartGame(MR_ULONG, MR_ULONG);
extern	MR_VOID		SendGameReadyToStart(MR_VOID);
extern	MR_VOID		SendSync(MR_VOID);
extern	MR_VOID		SendFrameSync(MR_VOID);
extern	MR_VOID		SendSyncOk(MR_VOID);

// Following are generic functions
extern	MR_VOID		InitialiseSync(MR_VOID);
extern	MR_BOOL		CheckForNetworkSync(MR_VOID);
extern	MR_VOID		InitAndWaitForSync(MR_ULONG	mode);
extern	MR_VOID		SendGenericMessage(MR_ULONG);
extern	MR_VOID		WaitForNetworkSync(MR_VOID);
extern	MR_VOID		InitialiseSyncAndWaitForFrame(MR_VOID);

#endif // WIN95
#endif // __FROGNET_H
