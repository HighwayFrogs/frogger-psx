/******************************************************************************
*%%%% frogcard.h
*------------------------------------------------------------------------------
*
*	Specific Frogger Memory Card Functions.
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	26.3.97		Gary Richards	Created
*
*%%%**************************************************************************/

#ifndef	__FROGCARD_H
#define	__FROGCARD_H

#include	"system.h"

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	SAVEGAME_BUFFER_SIZE					(6 * 1024)
#define	SAVE_GAME_VERSION	(2)			// Every time the structure changes. Increment this number.

// Switch for the save game control loop.
enum {SAVE_GAME_WAITING	= 0,			// Doing nothing.
	  SAVE_GAME_CHECKING_FOR_CARDS,		// Checking for any cards plugged in.
	  SAVE_GAME_CHECKING_STATE_OF_SELECTED_CARD,	// Does exactly what it says in the label.
	  SAVE_GAME_FORMAT_CARD,
	  SAVE_GAME_OVERWRITE_GAME,
	  SAVE_GAME_TO_SELECTED_CARD,		// Does exactly what it says in the label.
	 };

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------


extern	MR_VOID		vSGInit(MR_VOID);
extern  MR_BOOL		xSaveFroggerData(MR_VOID);
extern  MR_BOOL		xSaveGameDataToCard(MR_BYTE);

extern	MR_ULONG*	Compile_savegame(MR_VOID);
extern	MR_BOOL		Uncompile_savegame(MR_ULONG*);

#endif	//_FROGCARD_H


