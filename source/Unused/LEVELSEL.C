/******************************************************************************
*%%%% levelsel.c
*------------------------------------------------------------------------------
*
*	Routines for management of level selection
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	06.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#include "mr_all.h"
#include "levelsel.h"
#include "options.h"
#include "project.h"


/******************************************************************************
*%%%% LevelSelectStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelSelectStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Level Select screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	LevelSelectStartup(MR_VOID)
{
	MRSetDisplayClearColour(0x40,0x40,0x80);

	

}

/******************************************************************************
*%%%% LevelSelectUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelSelectUpdate(MR_VOID)
*
*	FUNCTION	Update code for Level Select screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	LevelSelectUpdate(MR_VOID)
{
	if (MR_CHECK_PAD_PRESSED(MR_INPUT_PORT_0, FRR_CROSS))
		{
		Option_page_request = OPTIONS_PAGE_EXIT;
		}
}

/******************************************************************************
*%%%% LevelSelectShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelSelectShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Level Select screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	LevelSelectShutdown(MR_VOID)
{
	MRSetDisplayClearColour(0x00,0x00,0x00);
}


