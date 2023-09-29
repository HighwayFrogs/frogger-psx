/******************************************************************************
*%%%% system.h
*------------------------------------------------------------------------------
*
*	Primary system include file. The build options are before the included
*	file list just to make the current options clearer.
*
*	CHANGED		PROGRAMMER		REASON
*  	------  	----------  	------
*	24.5.96		Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef		__SYSTEM_H					
#define		__SYSTEM_H 

#define MR_APPLICATION_REGISTRY_KEY "Hasbro\\Frogger"

#ifdef		__psx						// Supplied by the PlayStation Compiler.
#define		PSX
#else
#define		WIN95
#endif

#ifdef		PSX

// Build Options

#define		PSX_RELEASE
//#define		PSX_MASTER

#define		PSX_MODE_NTSC
//#define		PSX_MODE_PAL

#ifdef		PSX_RELEASE
#define		PSX_CD_LOAD
#define		PSX_ENABLE_XA
#define		PSX_SOUND
#define		PSX_CD_STREAMS
#define		PSX_CARD
#else
#define		DEBUG
#define		PSX_CARD
//#define		PSX_ENABLE_XA
//#define		PSX_CD_LOAD
//#define		PSX_CD_STREAMS
#define		PSX_API_DEBUG
#define		PSX_SOUND
#endif

// Set up our own Default sound volumes.
#define	MRSND_DEFAULT_FX_VOL						(120)
#define	MRSND_DEFAULT_CD_VOL						(72)

// Use API sound?
#ifdef		PSX_SOUND
#define		MR_API_SOUND
#endif

#define		MR_KEEP_SYSTEM_RAND
#define		MR_KEEP_SYSTEM_RSIN
#define		MR_KEEP_SYSTEM_RCOS

// API Debugging options
#ifdef		PSX_API_DEBUG
#define		MR_DEBUG
#define		MR_DEBUG_DISPLAY

#define		MR_GATSO_SHOW_CALC
#define		MR_GATSO_SHOW_DRAW
#define		MR_GATSO_SHOW_USED
#define		MR_GATSO_SHOW_FREE
//#define		MR_GATSO_SHOW_MIN_FREE
//#define		MR_GATSO_SHOW_MAX_FREE
//#define		MR_GATSO_SHOW_MIN_MAX_FREE
//#define		MR_GATSO_EXPECTED_FREE_RAM	(700)

#define		MR_MEM_DEBUG
//#define		MR_MEM_FULL_DEBUG
#define		MR_MEM_TORTURE
#define		MR_USE_ASSERTS
//#define		MR_SHOW_MOF_INFO
#endif

// Machine territory-related equates

#ifdef		PSX_MODE_NTSC
#define		FRAMES_PER_SECOND		(60)
#define		MR_MODE_NTSC
#else
#define		FRAMES_PER_SECOND		(50)
#define		MR_MODE_PAL
#endif

// Project specific 
#define		MR_FILE_RAMDRIVE		"E:"

//-----------------------------------------------------------------------------
// Include files 

#include	<sys\types.h>
#include 	<sys\file.h>
#include 	<r3000.h>
#include 	<asm.h>
#include	<kernel.h>
#include 	<libetc.h>
#include 	<libgte.h>
#include 	<libgpu.h>
#include	<libpress.h>
//#include 	<libgs.h>	
#include 	<libsn.h>
#include 	<libspu.h>
#include	<libsnd.h>
#include	<libcd.h>
#include	<inline_c.h>
#include	<gtemac.h>

//------------------------------------------------------------------------------------------------
// Turn on CD subsystem initialisation if it's needed

#ifdef	PSX_CD_LOAD				// If we're CD loading we need a CdInit();
#ifndef	PSX_CD_INIT
#define	PSX_CD_INIT
#endif
#endif

#ifdef	PSX_ENABLE_XA			// If we're playing streams or XA audio, we need a CdInit();
#ifndef	PSX_CD_INIT
#define	PSX_CD_INIT
#endif
#endif

#ifdef	PSX_CD_STREAMS			// If we're playing streams or XA audio, we need a CdInit();
#ifndef	PSX_CD_INIT
#define	PSX_CD_INIT
#endif
#endif

//------------------------------------------------------------------------------------------------
// Handy definitions 

#define	PSX		 												//	Platform specifier... for plot code

#define	TRUE					0xffffffff
#define	FALSE					0x00000000
#define	DLONG_ALIGNED			__attribute__ ((aligned(8)))
#define	LONG_ALIGNED			__attribute__ ((aligned(4)))
#define	WORD_ALIGNED			__attribute__ ((aligned(4)))
#define	SHORT_ALIGNED			__attribute__ ((aligned(2)))


//------------------------------------------------------------------------------------------------
// Patch the incorrect definition of abs() declared in abs.h, so it works properly... 

#undef	abs
#define	abs(x)					(((x)<0) ? -(x) : (x))

//------------------------------------------------------------------------------------------------
// Type definitions

typedef	void					VOID;
typedef	unsigned	long*		MEM;
typedef	unsigned	long		BOOL;
typedef	unsigned	long		ULONG;
typedef	signed		long		LONG;
typedef	unsigned	char*		STRPTR;
typedef	unsigned	char		UBYTE;
typedef	unsigned	char		TEXT;
typedef	signed		char		BYTE;
typedef	signed		short		SHORT;
typedef	unsigned	short		USHORT;
typedef	signed		int			INT;
typedef	unsigned	int	  		UINT;

//------------------------------------------------------------------------------------------------
//	Macros for common operations. 

#ifndef	NULL					// Everyone needs a NULL
#define	NULL	0
#endif

#ifndef	MIN						// Everyone needs a MIN
#define	MIN(a,b) 				(((a)<(b))?(a):(b))
#endif

#ifndef	MAX						// Everyone needs a MAX too..
#define	MAX(a,b) 				(((a)>(b))?(a):(b))
#endif

#ifndef	CLEAR						// And this is nice as well...
#define	CLEAR(item)				memset(&item, 0, sizeof(item))
#endif

#ifndef	MAKE_ID
#define	MAKE_ID(a,b,c,d) 		((a<<24)|(b<<16)|(c<<8)|(d<<0))
#endif

#define	COPYLONG(a,b)			(*(LONG*)(&a) = *(LONG*)(&b))
#define	COPYSHORT(a,b)			(*(SHORT*)(&a) = *(SHORT*)(&b))
#define	SETLONG(a,b)			(*(LONG*)(&a) = b)
#define	SETSHORT(a,b)			(*(SHORT*)(&a) = b)

#define	SQUARED_DIST(a,b)		((a[0]-b[0])>>2)*((a[0]-b[0])>>2)+((a[1]-b[1])>>2)*((a[1]-b[1])>>2)+((a[2]-b[2])>>2)*((a[2]-b[2])>>2)
#define	SQUARED_XZ_DIST(a,b)	((a[0]-b[0])>>2)*((a[0]-b[0])>>2)+((a[2]-b[2])>>2)*((a[2]-b[2])>>2)
#define	SQUARED_X_DIST(a,b) 	((a[0]-b[0])>>2)*((a[0]-b[0])>>2)
#define	SQR(a)					((a)*(a))

#define	COPYMATRIX(a,b)			*(LONG*)&((a).m[0][0]) = *(LONG*)&((b).m[0][0]), \
								*(LONG*)&((a).m[0][2]) = *(LONG*)&((b).m[0][2]), \
								*(LONG*)&((a).m[1][1]) = *(LONG*)&((b).m[1][1]), \
								*(LONG*)&((a).m[2][0]) = *(LONG*)&((b).m[2][0]), \
								(a).m[2][2] = (b).m[2][2]

#define	RGBL(a,b,c)				(((a)<<16) + ((b)<<8) + (c))


//------------------------------------------------------------------------------------------------
// References, defines and macros to enable stack placement on PlayStation D-Cache
 
extern	ULONG				saved_stack;
extern	ULONG				stack_safety;
 
#define	FASTSTACK			saved_stack=SetSp(0x1f8003ec)
#define	SLOWSTACK			SetSp(saved_stack)


//------------------------------------------------------------------------------------------------
//	DEBUG FUNCTION ADDRESS LIST HANDLER - For use in emergencies only!

extern	LONG*				routine_list[];
extern	LONG				routine_list_index;

#ifdef	PSX_DEBUG
#define	ROUTINE(function)	routine_list[routine_list_index] = (LONG *)(function), \
						 	routine_list_index = (routine_list_index + 1)&0x07
#else
#define	ROUTINE
#endif

// Override API defines
#define	MR_DEBUG_MAX_TILES				512
#define	MR_GATSO_X_POS					296
#define	MR_INPUT_USE_MULTITAP
#define	MR_GATSO_Y_POS					160

#endif
#ifdef	WIN95
#include "winsys.h"
#endif


#endif	//__SYSTEM_H

