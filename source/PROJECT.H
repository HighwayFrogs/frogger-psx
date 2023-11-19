/******************************************************************************
*%%%% project.h
*------------------------------------------------------------------------------
*
*	Project specific things that the API needs..
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	11.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef		__PROJECT_H
#define		__PROJECT_H

#include	"mr_all.h"
#include	"binaries.h"
#include	"..\merge\frogpsx.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Internal control defines
#ifdef PSX
#define	FRR_LEFT				(1<<0)
#define	FRR_RIGHT				(1<<1)
#define	FRR_UP					(1<<2)
#define	FRR_DOWN				(1<<3)		
#define	FRR_BLUE				(1<<4)		
#define	FRR_START				(1<<5)		
#define	FRR_SELECT				(1<<6)		
#define	FRR_PINK				(1<<7)	
#define	FRR_RED					(1<<8)		
#define	FRR_GREEN				(1<<9)		
#define	FRR_LEFT_1				(1<<10)		
#define	FRR_LEFT_2				(1<<11)		
#define	FRR_RIGHT_1				(1<<12)		
#define	FRR_RIGHT_2				(1<<13)
#define	FRR_UNUSED_14			(1<<14)		
#define	FRR_UNUSED_15			(1<<15)		
#else
#define FRR_LEFT				MRIPD_LEFT
#define	FRR_RIGHT				MRIPD_RIGHT
#define	FRR_UP					MRIPD_UP
#define	FRR_DOWN				MRIPD_DOWN
#define	FRR_BLUE				MRIPD_FIRE1
#define	FRR_PINK				MRIPD_FIRE2
#define	FRR_RED					MRIPD_FIRE3
#define	FRR_GREEN				MRIPD_FIRE4
#define	FRR_LEFT_2				MRIPD_FIRE5
#define	FRR_RIGHT_2				MRIPD_FIRE6
#define	FRR_LEFT_1				MRIPD_FIRE7
#define	FRR_RIGHT_1				MRIPD_FIRE8
#define	FRR_START				MRIPD_FIRE9
#define	FRR_SELECT				MRIPD_FIRE10
#endif

#define	FRR_SQUARE				(FRR_PINK)
#define	FRR_CROSS				(FRR_BLUE)
#define	FRR_CIRCLE				(FRR_RED)
#define	FRR_TRIANGLE			(FRR_GREEN)
					  
#define	FR_ANY_BUTTON			(0xffff)

// Game-type control defines
#define	FR_LEFT					FRR_LEFT
#define	FR_RIGHT				FRR_RIGHT
#define	FR_UP					FRR_UP
#define	FR_DOWN					FRR_DOWN
#define	FR_REPEAT				FRR_BLUE
#define	FR_START				FRR_START
#define	FR_SELECT				FRR_SELECT
#define	FR_SUPERJUMP			FRR_BLUE
#define	FR_TONGUE				FRR_PINK
#define	FR_CROAK				FRR_RED
#define	FR_GO					(FRR_BLUE | FRR_START)  // for Sony guidelines

#ifdef	PSX_RELEASE
// On Demo recording on a Gold Disk.
#define	FR_CAMERA_CLOCKWISE		FRR_LEFT_1|FRR_LEFT_2
#define	FR_CAMERA_ANTICLOCKWISE	FRR_RIGHT_1|FRR_RIGHT_2
#else
// Only 1 in debug, cos L2,R2 are used to record demo modes.
#define	FR_CAMERA_CLOCKWISE		FRR_LEFT_1
#define	FR_CAMERA_ANTICLOCKWISE	FRR_RIGHT_1
#endif

// File loading stuff
#define	PROJECT_MAX_THEME_MOFS	128
#define	PROJECT_MAX_GEN_MOFS	64


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	FROG_CLEAR_PAD_PRESSED(port, action)	( MRInput[(port)].in_pad_down &= ~(action) )

#ifdef WIN95
#define	MRGetAsyncStatus			DummyGetAsyncStatus
#define	MRLoadResourceAsync			MRLoadResource
#endif

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_MOF*			Map_mof_ptrs[];
extern	MR_ULONG		Map_mof_index;

#ifdef PSX
extern	MR_USHORT		FRInput_default_map[];		// Default joypad configuration
#else
extern	MR_ULONG		FRInput_default_map[];		// Default joypad configuration
extern	MR_ULONG		FRInput_default_key_map1[];
extern	MR_ULONG		FRInput_default_key_map2[];
extern	MR_ULONG		FRInput_default_key_map3[];
extern	MR_ULONG		FRInput_default_key_map4[];
#endif

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_BOOL			FRFileProcess_VLO(MR_ULONG, MR_ULONG*, MR_ULONG);
extern	MR_BOOL			FRFileProcess_MOF(MR_ULONG, MR_ULONG*, MR_ULONG);
extern	MR_BOOL			FRFileProcess_MAPMOF(MR_ULONG, MR_ULONG*, MR_ULONG);
extern	MR_LONG			DummyGetAsyncStatus(MR_LONG);

#endif		//__PROJECT_H
