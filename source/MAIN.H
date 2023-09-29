/******************************************************************************
*%%%% main.h
*------------------------------------------------------------------------------
*
*	Header file for root file in Frogger Project
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	10.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef		__MAIN_H
#define		__MAIN_H

#include	"mr_all.h"
#include	"project.h"
#include	"sprdata.h"

#ifdef WIN95
#include	"frognet.h"
#endif

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_ULONG			__textlen;
extern	MR_ULONG			__bsslen;
extern	MR_ULONG			__datalen;
extern	MR_ULONG			__heapsize;
extern	MR_ULONG*			__heapbase;

extern 	MR_VEC				Null_vector;
extern 	MR_SVEC				Null_svector;
extern	MR_STRPTR			Version_text[4][25];

#ifdef WIN95
extern 	volatile MR_LONG	Main_frame_count;				// Number of frames processed
extern 	volatile MR_LONG	Main_global_frame_count;		// Number of frames processed
extern 	char				szCmdLine[];					// Command line
extern	MR_DISP_DATA*		Main_display_data;				// Data about main display
extern	char				Main_win95_cd_drive;					// CD Drive id

#ifdef MR_DEBUG
extern	MR_LONG				Main_screen_resolution;			
extern	MR_BOOL				Main_screen_clear;	
extern	MR_LONG				Main_screen_widths[];
extern	MR_LONG				Main_screen_heights[];
#endif // MR_DEBUG

#endif // WIN95

extern	MR_BOOL				Cheat_control_toggle;
extern	MR_BOOL				Cheat_collision_toggle;
extern	MR_BOOL				Cheat_time_toggle;
extern	MR_BOOL				Cheat_infinite_lives_toggle;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern 	MR_VOID				main(MR_VOID);
extern	MR_VOID				TestModel(MR_VOID);

#ifdef PSX
extern 	MR_VOID				InitialisePSX(MR_VOID);
extern 	MR_VOID				ProgressMonitor(MR_VOID);
#endif	// PSX

#ifdef WIN95
extern 	int WINAPI			WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
extern 	MR_VOID				InitialiseWIN95(VOID);
extern 	MR_ULONG			GetNumber(MR_UBYTE *InString);
extern 	MR_VOID				ProcessCmdLine(MR_UBYTE *CmdLine);
extern 	MR_VOID	CALLBACK	FrameRateTimerCallBack(UINT hWnd, UINT uMsg, DWORD idEvent, DWORD dwTime,DWORD dwThree);
#endif	// WIN95


#endif	//__MAIN_H
