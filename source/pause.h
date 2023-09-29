/******************************************************************************
*%%%% pause.h
*------------------------------------------------------------------------------
*
*	All stuff to do with pausing the game.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

#ifndef	__PAUSE_H
#define	__PAUSE_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum
	{
	HIDDEN_MENU_WAITING,
	HIDDEN_MENU_CONTINUE,
	HIDDEN_MENU_QUIT,
	};

enum
	{
	HIDDEN_MENU_QUIT_YES,
	HIDDEN_MENU_QUIT_NO,
	MAX_HIDDEN_MENU_QUIT_ITEMS,
	};

#define	HIDDEN_MENU_QUIT_GAME	0xff

enum
	{
	HIDDEN_MENU_CONTINUE_SELECTED,
	HIDDEN_MENU_QUIT_SELECTED,
	MAX_HIDDEN_MENU_ITEMS,
	};

enum
	{
	SELECT_MODE_WAITING,
	SELECT_MODE_INIT,
	SELECT_MODE_COUNTING,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	POLY_F4			Pause_poly[];
extern	POLY_FT3		Pause_poly2[];
extern	MR_ULONG		Game_paused_selection;


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			GamePause(MR_VOID);
extern	MR_VOID			InitialiseHiddenMenu(MR_VOID);
extern	MR_VOID			DeInitialiseHiddenMenu(MR_VOID);
extern	MR_VOID			CheckJoyPadStillPresent(MR_VOID);
extern	MR_VOID 		GamePauseAddPrim(MR_VOID);
extern	MR_VOID 		GamePauseCreateFadePoly(MR_VOID);
extern	MR_VOID			InitialiseHiddenQuitMenu(MR_VOID);
extern	MR_VOID 		GameSelectReset(MR_VOID);
extern	MR_VOID 		GameCheatModeCheck(MR_VOID);

#endif		//__PAUSE_H

