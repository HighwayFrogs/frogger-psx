/******************************************************************************
*%%%% mr_disp.h
*------------------------------------------------------------------------------
*
*	New header file for mr_disp.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	12.02.97	Dean Ashton		Lots of defines added for extra gatso stuff
*	21.07.97	Dean Ashton		Added prototypes for MRChangeDisplay()
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_display		MR_DISPLAY;
typedef	struct	__mr_disp_data		MR_DISP_DATA;
typedef	struct	__mr_gatso_info		MR_GATSO_INFO;
typedef	struct	__mr_gatso_data		MR_GATSO_DATA;

#else
#ifndef	__MR_DISP_H
#define	__MR_DISP_H

// Perform basic validation on MR_GATSO_SHOW_<xxx> flags

#ifdef	MR_GATSO_SHOW_CALC
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_DRAW
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_USED
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_FREE
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_MIN_FREE
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_MAX_FREE
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif

#ifdef	MR_GATSO_SHOW_MIN_MAX_FREE
#ifndef	MR_GATSO
#define	MR_GATSO
#endif
#endif


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Flags for display

#define	MR_DI_ACTIVE				(1<<0)
#define	MR_DI_VISIBLE				(1<<1)

// Display database identifiers

#define	MR_DD_NTSC					(1<<0)			// Display mode is NTSC		
#define	MR_DD_PAL					(1<<1)			// Display mode is PAL
#define	MR_DD_INTERLACE				(1<<2)			// Display mode is INTERLACE
#define	MR_DD_TRUECOLOUR			(1<<3)			// Display mode is TRUECOLOUR

enum		{
			MR_SCREEN_STANDARD_256,							// 256 pixels wide, non-interlace, 16-bit
			MR_SCREEN_STANDARD_320,							// 320 pixels wide, non-interlace, 16-bit
			MR_SCREEN_STANDARD_368,							// 368 pixels wide, non-interlace, 16-bit
			MR_SCREEN_STANDARD_512,							// 512 pixels wide, non-interlace, 16-bit
			MR_SCREEN_STANDARD_640,							// 640 pixels wide, non-interlace, 16-bit

			MR_SCREEN_INTERLACE_256,						// 256 pixels wide, interlaced, 16-bit
			MR_SCREEN_INTERLACE_320,						// 320 pixels wide, interlaced, 16-bit
			MR_SCREEN_INTERLACE_368,						// 368 pixels wide, interlaced, 16-bit
			MR_SCREEN_INTERLACE_512,						// 512 pixels wide, interlaced, 16-bit
			MR_SCREEN_INTERLACE_640,						// 640 pixels wide, interlaced, 16-bit

			MR_SCREEN_TRUECOLOUR_STANDARD_256,				// 256 pixels wide, non-interlace, 24-bit
			MR_SCREEN_TRUECOLOUR_STANDARD_320,				// 320 pixels wide, non-interlace, 24-bit
			MR_SCREEN_TRUECOLOUR_STANDARD_368,				// 368 pixels wide, non-interlace, 24-bit
			MR_SCREEN_TRUECOLOUR_STANDARD_512,				// 512 pixels wide, non-interlace, 24-bit
			MR_SCREEN_TRUECOLOUR_STANDARD_640,				// 640 pixels wide, non-interlace, 24-bit

			MR_SCREEN_TRUECOLOUR_INTERLACE_256,				// 256 pixels wide, interlaced, 24-bit
			MR_SCREEN_TRUECOLOUR_INTERLACE_320,				// 320 pixels wide, interlaced, 24-bit
			MR_SCREEN_TRUECOLOUR_INTERLACE_368,				// 368 pixels wide, interlaced, 24-bit
			MR_SCREEN_TRUECOLOUR_INTERLACE_512,				// 512 pixels wide, interlaced, 24-bit
			MR_SCREEN_TRUECOLOUR_INTERLACE_640,				// 640 pixels wide, interlaced, 24-bit

			MR_SCREEN_MODE_PAL_BASE,						// If MR_MODE_PAL, then mode = mode + MR_SCREEN_MODE_PAL_BASE
			};

// Screen centering values

#define	MR_DISP_DEFAULT_X_POS		(0)
#define	MR_DISP_DEFAULT_Y_POS		(0)

#define	MR_DISP_MIN_X_POS			(-8)
#define	MR_DISP_MIN_Y_POS			(0)

#define	MR_DISP_MAX_X_POS			(16)
#define	MR_DISP_MAX_Y_POS			(16)

// Gatso definitions

#define	MR_GATSO_NUM_DIGITS			(4)
#define	MR_GATSO_ITEM_SPRITE_COUNT	(MR_GATSO_NUM_DIGITS+2)		// Room for Item/Separator/Digits

#define	MR_GATSO_OT_LEN				(4)							// Number of OT slots for gatso
#ifndef	MR_GATSO_X_POS
#define	MR_GATSO_X_POS				(24)						// X position for character gatso display
#endif
#ifndef	MR_GATSO_Y_POS
#define	MR_GATSO_Y_POS				(24)						// Y position for character gatso display
#endif
#ifndef	MR_GATSO_EXPECTED_FREE_RAM
#define	MR_GATSO_EXPECTED_FREE_RAM	(1024)
#endif
#ifndef	MR_GATSO_MEM_PERSISTENCE
#define	MR_GATSO_MEM_PERSISTENCE	(1024)
#endif
//#define	MR_GATSO_PROFILE									// use MRStartGatsoProfile etc.
//#define	MR_GATSO_PEAK										// Uncomment for peak readings

enum		{													// Enumerated types to use as index into
			MR_GATSO_CH_0,										// the MRGatso_info[] array.
			MR_GATSO_CH_1,
			MR_GATSO_CH_2,
			MR_GATSO_CH_3,
			MR_GATSO_CH_4,
			MR_GATSO_CH_5,
			MR_GATSO_CH_6,
			MR_GATSO_CH_7,
			MR_GATSO_CH_8,
			MR_GATSO_CH_9,
			MR_GATSO_CH_SEPARATOR,
			MR_GATSO_CH_HYPHEN,

			MR_GATSO_CH_CALC,
			MR_GATSO_CH_DRAW,
			MR_GATSO_CH_USED,
			MR_GATSO_CH_FREE,
			MR_GATSO_CH_MIN_FREE,
			MR_GATSO_CH_MAX_FREE,
			MR_GATSO_CH_MIN_MAX_FREE,

			MR_GATSO_CH_BLANK,
			};


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_display
		{
		MR_ULONG		di_flags;					// Miscellaneous flags
		MR_ULONG		di_video_flags;				// Used to hold the current video mode flags
		MR_RECT			di_screen[2];				// VRAM positions/sizes of both screens
		DRAWENV			di_drawenv[2];				// Used to generate DR_ENV structures for buffering
		DISPENV			di_dispenv[2];				// Used to generate DR_MODE structures for buffering

		#ifdef			MR_GATSO
		DR_ENV			di_gatso_dr_env[2];	  						// Used to set ofs/clip/tpage for gatso
		MR_ULONG		di_gatso_ot_0[MR_GATSO_OT_LEN];				// Double buffered gatso ordering table
		MR_ULONG		di_gatso_ot_1[MR_GATSO_OT_LEN];				// Double buffered gatso ordering table
		MR_ULONG*		di_gatso_ot_ptr[2];	  						// Pointers to gatso ordering tables
		#endif	

		};		// MR_DISPLAY


struct	__mr_disp_data
		{
		MR_USHORT		dd_width;					// Width of screen
		MR_USHORT		dd_height;					// Height of screen
		MR_USHORT		dd_buffer_x0;				// Position of first screen in VRAM
		MR_USHORT		dd_buffer_y0;
		MR_USHORT		dd_buffer_x1;				// Position of second screen in VRAM
		MR_USHORT		dd_buffer_y1;
		MR_ULONG		dd_flags;			  		// Flags (Interlaced/Pal/24-bit etc)

		};		// MR_DISP_DATA;


#ifdef	MR_GATSO
struct	__mr_gatso_info
		{
		MR_UBYTE		gi_u;
		MR_UBYTE		gi_v;
		MR_UBYTE		gi_w;
		MR_UBYTE		gi_h;

		};		// MR_GATSO_INFO;

struct	__mr_gatso_data
		{
		MR_BYTE*		gd_setup_ptr;
		MR_VOID*		gd_prim_ptr;

		};		// MR_GATSO_DATA;

#endif

//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_ULONG 		MRFrame_number;
extern	MR_ULONG*		MRUser_pc;
extern	MR_ULONG 		MRFrame_index;
extern	MR_DISPLAY		MRDisplay;
extern	MR_DISPLAY*		MRDisplay_ptr;
extern	MR_SHORT		MRDisplay_pos_x;
extern	MR_SHORT		MRDisplay_pos_y;


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			MRInitialiseCallbacks(MR_VOID);
extern	MR_VOID			MRVBlankCallback(MR_VOID);
extern	MR_VOID			MRRenderCallback(MR_VOID);

extern	MR_VOID			MRDisablePollhost(MR_VOID);
extern	MR_VOID			MREnablePollhost(MR_VOID);

extern	MR_VOID			MRSetGatsoImage(MR_TEXTURE*);

extern	MR_VOID			MRCreateDisplay(MR_ULONG);
extern	MR_VOID			MRChangeDisplay(MR_ULONG);
extern	MR_VOID			MRKillDisplay(MR_VOID);
extern	MR_VOID			MRSwapDisplay(MR_VOID);
extern	MR_VOID			MRHideDisplay(MR_VOID);
extern	MR_VOID			MRShowDisplay(MR_VOID);
extern	MR_VOID			MRClearDisplay(MR_VOID);

extern	MR_VOID			MRClearViewportOT(MR_VIEWPORT *);
extern	MR_BOOL			MREnableDisplayClear(MR_VOID);
extern	MR_BOOL			MRDisableDisplayClear(MR_VOID);
extern	MR_VOID			MRSetDisplayClearColour(MR_UBYTE, MR_UBYTE, MR_UBYTE);
extern	MR_VOID			MRSetDisplayPosition(MR_SHORT, MR_SHORT);

extern	MR_VOID			MRInitialiseGatso(MR_VOID);
extern	MR_VOID			MRResetGatso(MR_VOID);
extern	MR_VOID			MRStartGatso(MR_VOID);
extern	MR_VOID			MRStopGatso(MR_VOID);
extern	MR_VOID			MRStartGatsoProfile(MR_VOID);
extern	MR_VOID			MRStopGatsoProfile(MR_VOID);
extern	MR_VOID			MRCalculateGatso(MR_VOID);

extern	MR_VOID			MRSetGatsoItemValue(MR_LONG, SPRT*, MR_CVEC*);

extern	MR_VOID			MRSetGatsoDisplayStatus(MR_BOOL);

#endif	//__MR_DISP_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
