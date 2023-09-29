/******************************************************************************
*%%%% levelsel.h
*------------------------------------------------------------------------------
*
*	Header file for level selection routines
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	06.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef	__LEVELSEL_H
#define	__LEVELSEL_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	WORLD_BOX_HEIGHT	(0x100)
#define	WORLD_BOX_WIDTH		(0x100)
#define	WORLD_BOX_DEPTH		(0x100)


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__world_info	WORLD_INFO;
typedef	struct	__level_info	LEVEL_INFO;

struct	__world_info
		{
		MR_ULONG	wi_flags;			// Flags (such as completion status, unlock status etc)
		LEVEL_INFO*	wi_level[6];		// Pointers to level structures, which hold times/scores/initials/flags
		};	// WORLD_INFO

struct	__level_info
		{
		MR_ULONG	li_flags;
							
		MR_MAT		li_matrix;
		};	// LEVEL_INFO

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		LevelSelectStartup(MR_VOID);
extern	MR_VOID		LevelSelectUpdate(MR_VOID);
extern	MR_VOID		LevelSelectShutdown(MR_VOID);

#endif	//__LEVELSEL_H

