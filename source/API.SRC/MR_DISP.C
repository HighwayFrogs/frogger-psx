/******************************************************************************
*%%%% mr_disp.c
*------------------------------------------------------------------------------
*
*	Display handling code (includes display swapping routines)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96 	Dean Ashton		Created
*	11.06.96 	Dean Ashton		Corrected bugs in MR_ASSERT calls.
*	12.06.96 	Dean Ashton		Added MRDisablePollhost/MREnablePollhost calls
*	19.06.96 	Dean Ashton		Modified MRDisplay_database to help create 
*			 					abstract screen types (not related to TV system)
*			 					and also changed MRCreateDisplay to utilise this.
*	19.06.96 	Dean Ashton		Added MRSetDisplayPosition() to move CRTC display
*			 					around on output device. 
*	02.09.96 	Dean Ashton		Changed MRCreateDisplay().
*	29.10.96 	Dean Ashton		Added support for 368-pixel wide 
*	12.02.97 	Dean Ashton		Changed gatso handling quite substantially
*	17.03.97 	Dean Ashton		Made gatso display switchable
*	17.06.97	Dean Ashton		Added support for 24-bit displays
*	18.07.97	Dean Ashton		Added display resolution change support
*
*%%%**************************************************************************/

#include	"mr_all.h"

MR_ULONG	 	MRFrame_number;				// Current frame number (increases from zero)
MR_LONG			MRCalc_time;				// Used to hold calculation time
MR_LONG			MRCalc_peak; 				// Peak calc time
MR_LONG			MRProf_time;				// Used to hold calculation time
MR_LONG			MRRender_time;				// Used to hold the rendering time
MR_LONG			MRRender_peak;				// Peak render time
	
MR_ULONG*		MRUser_pc;					// Pointer to user PC, for getting back from interrupts

MR_SHORT		MRDisplay_pos_x = MR_DISP_DEFAULT_X_POS;
MR_SHORT		MRDisplay_pos_y = MR_DISP_DEFAULT_Y_POS;

MR_DISPLAY		MRDisplay;
MR_DISPLAY*		MRDisplay_ptr = &MRDisplay;

#ifdef MR_DEBUG
MR_BOOL			MRPollhost_allowed = TRUE;	// Turn any pollhost() call off on a switch
#endif


#ifdef MR_GATSO
MR_BOOL			MRGatso_display;
MR_TEXTURE*		MRGatso_image_ptr;			// Pointer to gatso image (48x16 image)
MR_GATSO_INFO	MRGatso_info[] =
					{
	
					// u   v   w   h
					{	0,	 0,  6,  6 },	// 0
					{	6,	 0,  6,  6 },	// 1
					{ 12,	 0,  6,  6 },	// 2
					{ 18,	 0,  6,  6 },	// 3
					{ 24,	 0,  6,  6 },	// 4
					{	0,	 6,  6,  6 },	// 5
					{	6,	 6,  6,  6 },	// 6
					{ 12,	 6,  6,  6 },	// 7
					{ 18,	 6,  6,  6 },	// 8
					{ 24,	 6,  6,  6 },	// 9
	
					{ 30,	 6,  6,  6 },	// :
					{ 30,	 0,  6,  6 },	// -
	
					{  0,	12, 24,  6 },	// CALC
					{  0,	18, 24,  6 },	// DRAW
					{ 24,	12, 24,  6 },	// USED
					{ 24,	18, 24,  6 },	// FREE
					{  0,	24, 24,  6 },	// MIN FREE
					{ 24,	24, 24,  6 },	// MAX FREE
					{  0,	30, 24,  6 },	// MIN MAX FREE

					{ 24,	30,  6,  6 },	// BLANK
	
					};

#ifdef	MR_GATSO_SHOW_CALC
MR_BYTE		MRGatso_calc_setup[] = 
								{
								MR_GATSO_CH_CALC,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_calc_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];		
#endif

#ifdef	MR_GATSO_SHOW_DRAW
MR_BYTE		MRGatso_draw_setup[] = 
								{
								MR_GATSO_CH_DRAW,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_draw_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];	
#endif

#ifdef	MR_GATSO_SHOW_USED
MR_BYTE		MRGatso_used_setup[] = 
								{
								MR_GATSO_CH_USED,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_used_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];	
MR_CVEC		MRGatso_used_red	 = {0x80,0x00,0x00,0x64};
MR_CVEC		MRGatso_used_white = {0x80,0x80,0x80,0x64};
#endif

#ifdef	MR_GATSO_SHOW_FREE
MR_BYTE		MRGatso_free_setup[] = 
								{
								MR_GATSO_CH_FREE,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_free_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];	
#endif

#ifdef	MR_GATSO_SHOW_MIN_FREE
MR_BYTE		MRGatso_min_free_setup[] = 
								{
								MR_GATSO_CH_MIN_FREE,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_min_free_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];	
#endif

#ifdef	MR_GATSO_SHOW_MAX_FREE
MR_BYTE		MRGatso_max_free_setup[] = 
								{
								MR_GATSO_CH_MAX_FREE,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_max_free_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];	
#endif		

#ifdef	MR_GATSO_SHOW_MIN_MAX_FREE
MR_BYTE		MRGatso_min_max_free_setup[] = 
								{	
								MR_GATSO_CH_MIN_MAX_FREE,
								MR_GATSO_CH_SEPARATOR,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								MR_GATSO_CH_HYPHEN,
								-1
								};
SPRT		MRGatso_min_max_free_prims[2][MR_GATSO_ITEM_SPRITE_COUNT];
#endif


MR_GATSO_DATA MRGatso_data[] = 
					{
#ifdef	MR_GATSO_SHOW_CALC
					{&MRGatso_calc_setup[0], &MRGatso_calc_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_DRAW
					{&MRGatso_draw_setup[0], &MRGatso_draw_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_USED
					{&MRGatso_used_setup[0], &MRGatso_used_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_FREE
					{&MRGatso_free_setup[0], &MRGatso_free_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_MIN_FREE
					{&MRGatso_min_free_setup[0], &MRGatso_min_free_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_MAX_FREE
					{&MRGatso_max_free_setup[0], &MRGatso_max_free_prims[0][0]},
#endif

#ifdef	MR_GATSO_SHOW_MIN_MAX_FREE
					{&MRGatso_min_max_free_setup[0], &MRGatso_min_max_free_prims[0][0]},
#endif
					{NULL, NULL},
					};


#endif

// Display Database
																																  
MR_DISP_DATA	MRScreen_modes[] =
	{
	//    W,  H, X0, Y0, X1, Y1, Flags

		{256,240,  0,  0,  0,240, MR_DD_NTSC					},			// 256x240x16 (NTSC)
		{320,240,  0,  0,  0,240, MR_DD_NTSC					},			// 320x240x16 (NTSC)
		{368,240,  0,  0,  0,240, MR_DD_NTSC					},			// 368x240x16 (NTSC)
		{512,240,  0,  0,  0,240, MR_DD_NTSC					},			// 512x240x16 (NTSC)
		{640,240,  0,  0,  0,240, MR_DD_NTSC					},			// 640x240x16 (NTSC)

		{256,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_INTERLACE	},			// 256x240x16 (Interlaced NTSC)
		{320,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_INTERLACE	},			// 320x480x16 (Interlaced NTSC)
		{368,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_INTERLACE	},			// 368x480x16 (Interlaced NTSC)
		{512,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_INTERLACE	},			// 512x480x16 (Interlaced NTSC)
		{640,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_INTERLACE	},			// 640x480x16 (Interlaced NTSC)


		{256,240,  0,  0,  0,240, MR_DD_NTSC | MR_DD_TRUECOLOUR						},	// 256x240x24 (NTSC)
		{320,240,  0,  0,  0,240, MR_DD_NTSC | MR_DD_TRUECOLOUR						},	// 320x240x24 (NTSC)
		{368,240,  0,  0,  0,240, MR_DD_NTSC | MR_DD_TRUECOLOUR						},	// 368x240x24 (NTSC)
		{512,240,  0,  0,  0,240, MR_DD_NTSC | MR_DD_TRUECOLOUR						},	// 512x240x24 (NTSC)
		{640,240,  0,  0,  0,240, MR_DD_NTSC | MR_DD_TRUECOLOUR						},	// 640x240x24 (NTSC)

		{256,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	// 256x240x24 (Interlaced NTSC)
		{320,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	// 320x480x24 (Interlaced NTSC)
		{368,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	// 368x480x24 (Interlaced NTSC)
		{512,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	// 512x480x24 (Interlaced NTSC)
		{640,480,  0,  0,  0,  0, MR_DD_NTSC | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	// 640x480x24 (Interlaced NTSC)

		// ---

		{256,256,  0,  0,  0,256, MR_DD_PAL  					}, 			// 256x256x16 (PAL)
		{320,256,  0,  0,  0,256, MR_DD_PAL  					}, 			// 320x256x16 (PAL)
		{368,256,  0,  0,  0,256, MR_DD_PAL  					}, 			// 368x256x16 (PAL)
		{512,256,  0,  0,  0,256, MR_DD_PAL  					}, 			// 512x256x16 (PAL)
		{640,256,  0,  0,  0,256, MR_DD_PAL  					}, 			// 640x256x16 (PAL)

		{256,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_INTERLACE	},			// 256x512x16 (Interlaced PAL)
		{320,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_INTERLACE	},			// 320x512x16 (Interlaced PAL)
		{368,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_INTERLACE	},			// 368x512x16 (Interlaced PAL)
		{512,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_INTERLACE	},			// 512x512x16 (Interlaced PAL)
		{640,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_INTERLACE	},			// 640x512x16 (Interlaced PAL)

		{256,256,  0,  0,  0,256, MR_DD_PAL | MR_DD_TRUECOLOUR   					}, 	 // 256x256x24 (PAL)
		{320,256,  0,  0,  0,256, MR_DD_PAL | MR_DD_TRUECOLOUR  					}, 	 // 320x256x24 (PAL)
		{368,256,  0,  0,  0,256, MR_DD_PAL | MR_DD_TRUECOLOUR  					}, 	 // 368x256x24 (PAL)
		{512,256,  0,  0,  0,256, MR_DD_PAL | MR_DD_TRUECOLOUR  					}, 	 // 512x256x24 (PAL)
		{640,256,  0,  0,  0,256, MR_DD_PAL | MR_DD_TRUECOLOUR  					}, 	 // 640x256x24 (PAL)

		{256,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	 // 256x512x24 (Interlaced PAL)
		{320,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	 // 320x512x24 (Interlaced PAL)
		{368,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	 // 368x512x24 (Interlaced PAL)
		{512,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	 // 512x512x24 (Interlaced PAL)
		{640,512,  0,  0,  0,512, MR_DD_PAL | MR_DD_TRUECOLOUR | MR_DD_INTERLACE	},	 // 640x512x24 (Interlaced PAL)


	};

/******************************************************************************
*%%%% MRInitialiseCallbacks
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseCallbacks(MR_VOID);
*
*	FUNCTION	Sets up vertical blank/rendering callbacks
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseCallbacks(MR_VOID)
{
	struct ToT*		ic_tot;	
	struct TCBH*	ic_tcbh;
	struct TCB*		ic_tcb;
	
#ifdef	MR_GATSO
#ifdef	MR_GATSO_SHOW_DRAW
	MR_ULONG			hbl_event;
#endif
#endif	

	// Setup a counter interrupt for drawing completion, and a frame interrupt
	// for the development system (and a general frame counter). 
	EnterCriticalSection();

	VSyncCallback(&MRVBlankCallback);	

#ifdef	MR_GATSO
#ifdef	MR_GATSO_SHOW_DRAW
	hbl_event = OpenEvent(RCntCNT1, EvSpINT, EvMdNOINTR, NULL);
	EnableEvent(hbl_event);
	SetRCnt(RCntCNT1, 2000, RCntMdINTR);
	DrawSyncCallback(&MRRenderCallback);
#endif
#endif

	ExitCriticalSection();

	// Point a variable at the current tasks EPc address
	ic_tot		= (struct ToT*)0x100;
	ic_tcbh		= (struct TCBH*)((ic_tot+1)->head);
	ic_tcb		= (struct TCB*)(ic_tcbh->entry);
	MRUser_pc	= (MR_ULONG *)&ic_tcb->reg[R_EPC];

	// Clear gatso/general variables
	MRFrame_number	= 0;
	MRCalc_time		= -1;
	MRRender_time	= -1;
	MRCalc_peak		= -1;
	MRRender_peak	= -1;
}


/******************************************************************************
*%%%% MRVBlankCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRVBlankCallback(MR_VOID);
*
*	FUNCTION	Contains processing that should happen every VBlank.
*
*	NOTES		This function is called from an interrupt, and as such
*				it should be exited very quickly..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRVBlankCallback(MR_VOID)
{
	MRFrame_number++;
	
#ifdef	MR_DEBUG
	if (MRPollhost_allowed)
		pollhost();
#endif
}


/******************************************************************************
*%%%% MRVRenderCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRenderCallback(MR_VOID);
*
*	FUNCTION	Contains processing that happens when all rendering is complete
*
*	NOTES		This function is called from an interrupt, and as such
*				it should be exited very quickly..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRenderCallback(MR_VOID)
{
#ifdef	MR_GATSO
#ifdef	MR_GATSO_SHOW_DRAW
	if (MRRender_time == 0)
		{
		MRRender_time = GetRCnt(RCntCNT1);

#ifdef	MR_GATSO_PEAK
		MRRender_peak = MAX(MRRender_peak, MRRender_time);
		MRRender_time = MRRender_peak;
#endif
		}
#endif
#endif
}


/******************************************************************************
*%%%% MRDisablePollhost
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDisablePollhost(MR_VOID);
*
*	FUNCTION	This function disables any pollhost() calls within the current
*				Vertical Blank callback routine, to ensure we do not interrupt
*				the memory card operations.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRDisablePollhost(MR_VOID)
{
#ifdef	MR_DEBUG
	MRPollhost_allowed = FALSE;
#endif
}


/******************************************************************************
*%%%% MREnablePollhost
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MREnablePollhost(MR_VOID);
*
*	FUNCTION	This function enables any pollhost() calls within the current
*				Vertical Blank callback routine. See MRDisablePollhost() for
*				an explanation
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MREnablePollhost(MR_VOID)
{
#ifdef	MR_DEBUG
	MRPollhost_allowed = TRUE;
#endif
}


/******************************************************************************
*%%%% MRSetGatsoImage
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetGatsoImage(
*							MR_TEXTURE*	gatso_image);
*
*	FUNCTION	Sets the current gatso image pointer. Without this, use of the
*				gatso for timing purposes is not allowed.
*
*	INPUTS		gatso_image		-		Pointer to a valid MR_TEXTURE structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetGatsoImage(MR_TEXTURE* gatso_image)
{
#ifdef	MR_GATSO
	MR_ASSERT(gatso_image != NULL);
	MRGatso_image_ptr = gatso_image;
#endif
}


/******************************************************************************
*%%%% MRCreateDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCreateDisplay(
*						MR_ULONG	disp_id);
*						
*	FUNCTION	Initialises the video display, using the 'disp_id' parameter to
*				index into the display database to obtain the relevant parameters.
*
*	INPUTS		disp_id		-		Screen mode ID (index into 'disp_dbase')
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	28.05.96	Dean Ashton		Moved display database into API internals
*	18.06.96	Dean Ashton		Added assert to check for active display
*	19.06.96	Dean Ashton		Added abstracted TV standard support
*	02.09.96	Dean Ashton		Fixed NTSC/PAL handling in MRCreateDisplay
*	17.06.96	Dean Ashton		Added 24-bit display handling
*
*%%%**************************************************************************/

MR_VOID	MRCreateDisplay(MR_ULONG disp_id)
{
	MR_DISP_DATA*	disp_data;

#ifdef	MR_GATSO
	DRAWENV			work_env;
#endif

#ifdef	MR_GATSO	
	MR_ASSERT(MRGatso_image_ptr != NULL);
#endif

	// There can be no display currently active 
	MR_ASSERT(!(MRDisplay_ptr->di_flags & MR_DI_ACTIVE));

	// Point to correct screen mode based on currently defined TV system.
#ifdef	MR_MODE_PAL
	disp_id	=	disp_id + MR_SCREEN_MODE_PAL_BASE;
#endif
	disp_data = &MRScreen_modes[disp_id];


	// Set the DISPENV information for each buffer
	setDefDispEnv(&MRDisplay_ptr->di_dispenv[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height); 
	setDefDispEnv(&MRDisplay_ptr->di_dispenv[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height);

	// Set the DRAWENV information for each buffer, taking into account that the display width needs scaling for 24-bit displays
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		{
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[0], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, ((disp_data->dd_width*3)/2), disp_data->dd_height);
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[1], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, ((disp_data->dd_width*3)/2), disp_data->dd_height);
		}
	else
		{
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[0], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height);
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[1], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height);
		}

	
	// Set display positions for screen mode type (NTSC or PAL)
	if (disp_data->dd_flags & MR_DD_NTSC)
		{
		MRDisplay_ptr->di_dispenv[0].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[1].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y;

		}
	else
	if (disp_data->dd_flags & MR_DD_PAL)
		{
		MRDisplay_ptr->di_dispenv[0].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[1].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y + 16;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y + 16;
		MRDisplay_ptr->di_dispenv[0].screen.h = 256;
		MRDisplay_ptr->di_dispenv[1].screen.h = 256;
		}

	// Set video mode, if it's different to the current mode
	if ((disp_data->dd_flags & MR_DD_NTSC) && (!(MRDisplay_ptr->di_video_flags & MR_DD_NTSC)))
		SetVideoMode(MODE_NTSC);
	else
	if ((disp_data->dd_flags & MR_DD_PAL) && (!(MRDisplay_ptr->di_video_flags & MR_DD_PAL)))
		SetVideoMode(MODE_PAL);

	// Update current displays video flags
	MRDisplay_ptr->di_video_flags = disp_data->dd_flags;

	// Set the screen position information
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		{
		setRECT(&MRDisplay_ptr->di_screen[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, (disp_data->dd_width*3)/2, disp_data->dd_height); 
		setRECT(&MRDisplay_ptr->di_screen[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, (disp_data->dd_width*3)/2, disp_data->dd_height); 
		}
	else
		{
		setRECT(&MRDisplay_ptr->di_screen[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height); 
		setRECT(&MRDisplay_ptr->di_screen[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height); 
		}

	// Set Interlace if required
	if (disp_data->dd_flags & MR_DD_INTERLACE)
		MRDisplay_ptr->di_dispenv[0].isinter = MRDisplay_ptr->di_dispenv[1].isinter = 1;
	else
		MRDisplay_ptr->di_dispenv[0].isinter = MRDisplay_ptr->di_dispenv[1].isinter = 0; 

	// Set 24-bit colour if required
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		MRDisplay_ptr->di_dispenv[0].isrgb24 = MRDisplay_ptr->di_dispenv[1].isrgb24 = 1;
	else
		MRDisplay_ptr->di_dispenv[0].isrgb24 = MRDisplay_ptr->di_dispenv[1].isrgb24 = 0;

	// If the gatso is enabled, initialise the draw environment for it
#ifdef	MR_GATSO

	// Initialise DR_ENV structures to give gatso full-screen access, and initialise OT's
	setDefDrawEnv(&work_env, disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height);
	work_env.tpage = MRGatso_image_ptr->te_tpage_id;	
	SetDrawEnv(&MRDisplay_ptr->di_gatso_dr_env[0],&work_env);
	ClearOTagR(MRDisplay_ptr->di_gatso_ot_0, MR_GATSO_OT_LEN);

	setDefDrawEnv(&work_env, disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height);
	work_env.tpage = MRGatso_image_ptr->te_tpage_id;	
	SetDrawEnv(&MRDisplay_ptr->di_gatso_dr_env[1],&work_env);
	ClearOTagR(MRDisplay_ptr->di_gatso_ot_1, MR_GATSO_OT_LEN);
													  
	// Set ordering table pointers
	MRDisplay_ptr->di_gatso_ot_ptr[0] = MRDisplay_ptr->di_gatso_ot_0;
	MRDisplay_ptr->di_gatso_ot_ptr[1] = MRDisplay_ptr->di_gatso_ot_1;

#endif

	// Set initial flags for display (these need to be set before supporting routines are called)
	MRDisplay_ptr->di_flags = MR_DI_ACTIVE;

	// Default to clearing the display to black (this does NOT clear VRAM!)
	MREnableDisplayClear();
	MRSetDisplayClearColour(0x00,0x00,0x00);

	// Register the new drawing environment
	MRFrame_index = 0;

	PutDrawEnv(&MRDisplay_ptr->di_drawenv[MRFrame_index]);
	PutDispEnv(&MRDisplay_ptr->di_dispenv[MRFrame_index]);

	// Clear VRAM here, with the clearing colour
	MRClearDisplay();

	// Enable CRTC display
	MRShowDisplay();
	
}


/******************************************************************************
*%%%% MRChangeDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRChangeDisplay(
*						MR_ULONG	disp_id);
*						
*	FUNCTION	Changes the current video mode, leaving display clip stuff well
*				along.
*
*	INPUTS		disp_id		-		Screen mode ID (index into 'disp_dbase')
*
*	NOTE		This routine does NOT modify the clip regions associated with
*				viewports, or modify aspect matrix scaling either. If you want
*				to correct these things, you should call MRChangeViewport().
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.07.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRChangeDisplay(MR_ULONG disp_id)
{
	MR_DISP_DATA*	disp_data;
	MR_ULONG		disp_isbg;
	MR_ULONG		disp_isvisible;
	MR_UBYTE		disp_bg_r;
	MR_UBYTE		disp_bg_g;
	MR_UBYTE		disp_bg_b;

	// There has to be a display currently active 
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);


	// Clear old display areas, and all viewport OT's...
	MRClearDisplay();

	// Point to correct screen mode based on currently defined TV system.
#ifdef	MR_MODE_PAL
	disp_id	=	disp_id + MR_SCREEN_MODE_PAL_BASE;
#endif
	disp_data = &MRScreen_modes[disp_id];

	// We can't move to a truecolour/24-bit display..
	MR_ASSERT(!(disp_data->dd_flags & MR_DD_TRUECOLOUR));

	// Save the current screen clearing state, visibility state, and background colour
	disp_isbg		= MRDisplay_ptr->di_drawenv[0].isbg;
	disp_isvisible	= MRDisplay_ptr->di_flags & MR_DI_VISIBLE; 
	disp_bg_r		= MRDisplay_ptr->di_drawenv[0].r0;
	disp_bg_g		= MRDisplay_ptr->di_drawenv[0].g0;
	disp_bg_b		= MRDisplay_ptr->di_drawenv[0].b0;

	// Set the DISPENV information for each buffer
	setDefDispEnv(&MRDisplay_ptr->di_dispenv[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height); 
	setDefDispEnv(&MRDisplay_ptr->di_dispenv[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height);

	// Set the DRAWENV information for each buffer, taking into account that the display width needs scaling for 24-bit displays
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		{
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[0], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, ((disp_data->dd_width*3)/2), disp_data->dd_height);
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[1], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, ((disp_data->dd_width*3)/2), disp_data->dd_height);
		}
	else
		{
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[0], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height);
		setDefDrawEnv(&MRDisplay_ptr->di_drawenv[1], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height);
		}
	
	// Set display positions for screen mode type (NTSC or PAL)
	if (disp_data->dd_flags & MR_DD_NTSC)
		{
		MRDisplay_ptr->di_dispenv[0].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[1].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y;

		}
	else
	if (disp_data->dd_flags & MR_DD_PAL)
		{
		MRDisplay_ptr->di_dispenv[0].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[1].screen.x = MRDisplay_pos_x;
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y + 16;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y + 16;
		MRDisplay_ptr->di_dispenv[0].screen.h = 256;
		MRDisplay_ptr->di_dispenv[1].screen.h = 256;
		}

	// Update current displays video flags
	MRDisplay_ptr->di_video_flags = disp_data->dd_flags;

	// Set the screen position information
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		{
		setRECT(&MRDisplay_ptr->di_screen[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, (disp_data->dd_width*3)/2, disp_data->dd_height); 
		setRECT(&MRDisplay_ptr->di_screen[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, (disp_data->dd_width*3)/2, disp_data->dd_height); 
		}
	else
		{
		setRECT(&MRDisplay_ptr->di_screen[0], disp_data->dd_buffer_x0, disp_data->dd_buffer_y0, disp_data->dd_width, disp_data->dd_height); 
		setRECT(&MRDisplay_ptr->di_screen[1], disp_data->dd_buffer_x1, disp_data->dd_buffer_y1, disp_data->dd_width, disp_data->dd_height); 
		}

	// Set Interlace if required
	if (disp_data->dd_flags & MR_DD_INTERLACE)
		MRDisplay_ptr->di_dispenv[0].isinter = MRDisplay_ptr->di_dispenv[1].isinter = 1;
	else
		MRDisplay_ptr->di_dispenv[0].isinter = MRDisplay_ptr->di_dispenv[1].isinter = 0; 

	// Set 24-bit colour if required
	if (disp_data->dd_flags & MR_DD_TRUECOLOUR)
		MRDisplay_ptr->di_dispenv[0].isrgb24 = MRDisplay_ptr->di_dispenv[1].isrgb24 = 1;
	else
		MRDisplay_ptr->di_dispenv[0].isrgb24 = MRDisplay_ptr->di_dispenv[1].isrgb24 = 0;

	// Restore screen clearing status
	MRDisplay_ptr->di_drawenv[0].isbg = MRDisplay_ptr->di_drawenv[1].isbg = disp_isbg;

	// Restore screen visibility status
	if (disp_isvisible)
		{
		MRDisplay_ptr->di_flags |= MR_DI_VISIBLE;
		}

	// Restore screen clearing colour
	MRDisplay_ptr->di_drawenv[0].r0 = MRDisplay_ptr->di_drawenv[1].r0 = disp_bg_r;
	MRDisplay_ptr->di_drawenv[0].g0 = MRDisplay_ptr->di_drawenv[1].g0 = disp_bg_g;
	MRDisplay_ptr->di_drawenv[0].b0 = MRDisplay_ptr->di_drawenv[1].b0 = disp_bg_b;

	// Clear new display areas, and all viewport OT's...
	MRClearDisplay();

}


/******************************************************************************
*%%%% MRKillDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillDisplay(MR_VOID);
*
*	FUNCTION	Shuts down the display mechanisms. Specifically, this routine
*				hides the display, kills all viewports (which in turn kills
*				instances), and clears the ordering tables.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*
*%%%**************************************************************************/

MR_VOID	MRKillDisplay(MR_VOID)
{
	MR_VIEWPORT*	vp = MRViewport_root_ptr;

	// There has to be an active display for us to kill
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);
	
	DrawSync(0);
	MRHideDisplay();

	MRDisplay_ptr->di_flags = NULL;

	// Physically kill all viewports (memory for mesh instance polys and viewport ordering tables
	// is freed immediately)
	while(vp->vp_next_node)
		{
		MRKillViewport(vp->vp_next_node);
		}
}


/******************************************************************************
*%%%% MRSwapDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSwapDisplay(MR_VOID);
*
*	FUNCTION	Swaps the display buffers, finalises the gatso, and then starts
*				drawing the linked viewport ordering tables. The OT's are all
*				queued by the PlayStation hardware, executing sequentially.
*
*	NOTES		This should be typically called after a DrawSync(0), and a 
*				VSync(n) call..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*	10.12.96	Dean Ashton		Fixed screwy rendering gatso
*	16.06.97	Dean Ashton		Only gatso for 16-bit displays
*
*%%%**************************************************************************/

MR_VOID	MRSwapDisplay(MR_VOID)
{
	MR_ULONG		work_index;
	MR_ULONG		disp_index;

	MR_VIEWPORT*	viewport_ptr = MRViewport_root_ptr;

	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	// Recalculate Gatso primitives if necessary
#ifdef	MR_GATSO
	MRCalculateGatso();
#ifdef	MR_GATSO_SHOW_DRAW
	ResetRCnt(RCntCNT1);
#endif
#endif

	// Change the frame buffer index
	disp_index = MRFrame_index;								// The index to the OT that will be drawn 
	work_index = MRFrame_index = MRFrame_index ^ 0x01;	

	//	Register the new buffers (this can also cause the screen to be cleared)
	PutDrawEnv(&MRDisplay_ptr->di_drawenv[work_index]);
	PutDispEnv(&MRDisplay_ptr->di_dispenv[work_index]);

#ifdef	MR_GATSO
	MRCalc_time		= 0;
	MRRender_time	= 0;
#endif

	// Loop through all Viewports, queuing an OT draw for each one
	while (viewport_ptr = viewport_ptr->vp_next_node)
		{
		// Update the MR_VPCHANGE primitive if necessary
		if (viewport_ptr->vp_disp_change[disp_index].vc_flags & MR_VP_CHANGE_POS)
			{
			SetDrawArea(&viewport_ptr->vp_disp_change[disp_index].vc_change_clip, &viewport_ptr->vp_draw_areas[disp_index]);
			SetDrawOffset(&viewport_ptr->vp_disp_change[disp_index].vc_change_offset, (MR_USHORT*)&viewport_ptr->vp_draw_ofs[disp_index]);
			viewport_ptr->vp_disp_change[disp_index].vc_flags &= ~MR_VP_CHANGE_POS;		// Clear change request
			}
	
		// Only draw this viewports OT if it's visible
		if (!(viewport_ptr->vp_flags & MR_VP_NO_DISPLAY))		
			{
			// Add the MR_VPCHANGE primitive to the ordering table
			addPrim(viewport_ptr->vp_ot[disp_index]+viewport_ptr->vp_ot_size-1, 
					 &viewport_ptr->vp_disp_change[disp_index].vc_change_clip);

			addPrim(viewport_ptr->vp_ot[disp_index]+viewport_ptr->vp_ot_size-1, 
					 &viewport_ptr->vp_disp_change[disp_index].vc_change_offset);

			// Queue a request to render the primitives for this ViewPort (it's a reverse OT)
			DrawOTag(viewport_ptr->vp_ot[disp_index]+viewport_ptr->vp_ot_size - 1);
			}

		// Clear the old ordering table for this viewport (always!)
		ClearOTagR(viewport_ptr->vp_ot[work_index],viewport_ptr->vp_ot_size);

		// Set the viewports work OT pointer
		viewport_ptr->vp_work_ot = viewport_ptr->vp_ot[MRFrame_index];

		// If this viewport is the default viewport, then update the default viewport OT too
		if (viewport_ptr == MRDefault_vp)
			MRDefault_vp_ot = viewport_ptr->vp_work_ot;

		}

	// Clear any local OTs
	MRClearOTs(work_index);

	// Render a gatso last, if required
#ifdef	MR_GATSO
	if ((MRGatso_display == TRUE) && (!(MRDisplay_ptr->di_video_flags & MR_DD_TRUECOLOUR)))
		{
		DrawOTag(MRDisplay_ptr->di_gatso_ot_ptr[disp_index]+MR_GATSO_OT_LEN-1);
		}
	ClearOTagR(MRDisplay_ptr->di_gatso_ot_ptr[work_index], MR_GATSO_OT_LEN);
#endif

}


/******************************************************************************
*%%%% MRHideDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRHideDisplay(MR_VOID);
*
*	FUNCTION	Turns off the display, flagging the display structure so that
*				it isn't turned on again on subsequent MRSwapDisplay() calls
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRHideDisplay(MR_VOID)
{
	
	// Turn the display off
	VSync(0);
	SetDispMask(0);

	// Flag it in the display flags
	MRDisplay_ptr->di_flags &= ~MR_DI_VISIBLE;

}


/******************************************************************************
*%%%% MRShowDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShowDisplay(MR_VOID);
*
*	FUNCTION	Turns on the display.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRShowDisplay(MR_VOID)
{
	
	// Turn the display on
	VSync(0);
	SetDispMask(1);
	

	// Flag it in the display flags
	MRDisplay_ptr->di_flags |= MR_DI_VISIBLE;

}

							   
/******************************************************************************
*%%%% MRClearDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRClearDisplay(MR_VOID);
*
*	FUNCTION	Waits for current drawing to complete, then loops through all 
*				viewports clearing their ordering tables. It also clears the
*				gatso ordering tables, and finally clears the screen buffers
*				with the current background colour.
*
*	NOTES		This could take up to 3/60ths of a second to execute, due to 
*				the VSync() waits required for interlace support.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*
*%%%**************************************************************************/

MR_VOID	MRClearDisplay(MR_VOID)
{
	MR_VIEWPORT*	viewport_ptr = MRViewport_root_ptr;

	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	// Wait for all drawing to be complete
	DrawSync(0);

	// Clear all viewport ordering tables
	while (viewport_ptr = viewport_ptr->vp_next_node)
		{
		ClearOTagR(viewport_ptr->vp_ot[0],viewport_ptr->vp_ot_size);
		ClearOTagR(viewport_ptr->vp_ot[1],viewport_ptr->vp_ot_size);
		}

	// Clear Gatso ordering tables
#ifdef	MR_GATSO
	ClearOTagR(MRDisplay_ptr->di_gatso_ot_ptr[0], MR_GATSO_OT_LEN);
	ClearOTagR(MRDisplay_ptr->di_gatso_ot_ptr[1], MR_GATSO_OT_LEN);
#endif

	// Clear display areas (with chosen background colour)
	// The VSync(0) between the clears is incase we're using an interlace screen
	// because we need to make sure both fields are cleared.
	VSync(0);
	ClearImage(&MRDisplay_ptr->di_screen[0], 
					MRDisplay_ptr->di_drawenv[0].r0,
					MRDisplay_ptr->di_drawenv[0].g0,
					MRDisplay_ptr->di_drawenv[0].b0);

	DrawSync(0);

	VSync(0);			
	ClearImage(&MRDisplay_ptr->di_screen[1], 
					MRDisplay_ptr->di_drawenv[1].r0,
					MRDisplay_ptr->di_drawenv[1].g0,
					MRDisplay_ptr->di_drawenv[1].b0);

	DrawSync(0);

}


/******************************************************************************
*%%%% MRClearViewportOT
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRClearViewportOT(
*						MR_VIEWPORT*	viewport_ptr);
*
*	FUNCTION	Clears the specified viewport's Ordering Tables (both of them).
*
*	NOTES		This routine waits for drawing to be completed before proceeding
*				(if we don't do this then the GPU can stall while rendering a
*				corrupt primitive list).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRClearViewportOT(MR_VIEWPORT *viewport_ptr)
{
	MR_ASSERT(viewport_ptr != NULL);

	DrawSync(0);
	
	ClearOTagR(viewport_ptr->vp_ot[0],viewport_ptr->vp_ot_size);
	ClearOTagR(viewport_ptr->vp_ot[1],viewport_ptr->vp_ot_size);
}


/******************************************************************************
*%%%% MREnableDisplayClear
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	old_clear =	MREnableDisplayClear(MR_VOID);
*
*	FUNCTION	Enables automatic display clearing (handled by GPU when buffer
*				is changed).
*
*	RESULT		old_clear	-	Old clearing status
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*
*%%%**************************************************************************/

MR_BOOL	MREnableDisplayClear(MR_VOID)
{
	MR_BOOL	old_clear;

	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	if (MRDisplay_ptr->di_drawenv[0].isbg == 1)
		old_clear = TRUE;
	else
		old_clear = FALSE;

	MRDisplay_ptr->di_drawenv[0].isbg = MRDisplay_ptr->di_drawenv[1].isbg = 1;

	return(old_clear);
}


/******************************************************************************
*%%%% MRDisableDisplayClear
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	old_clear =	MRDisableDisplayClear(MR_VOID);
*
*	FUNCTION	Disables automatic display clearing (handled by GPU when buffer
*				is changed).
*
*	RESULT		old_clear	-	Old clearing status
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*
*%%%**************************************************************************/

MR_BOOL	MRDisableDisplayClear(MR_VOID)
{
	MR_BOOL	old_clear;

	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	if (MRDisplay_ptr->di_drawenv[0].isbg == 1)
		old_clear = TRUE;
	else
		old_clear = FALSE;

	MRDisplay_ptr->di_drawenv[0].isbg = MRDisplay_ptr->di_drawenv[1].isbg = 0;

	return(old_clear);
}


/******************************************************************************
*%%%% MRSetDisplayClearColour
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetDisplayClearColour(
*						MR_UBYTE	red,
*						MR_UBYTE	green,
*						MR_UBYTE	blue);
*
*	FUNCTION	Sets the display clearing colour, for when automatic display
*				clearing is enabled.
*
*	INPUTS		red			-	Red component of clearing colour
*				green		-	Green component of clearing colour
*				blue 		-	Blue component of clearing colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added assert to check for active display
*
*%%%**************************************************************************/

MR_VOID	MRSetDisplayClearColour(MR_UBYTE red,
								MR_UBYTE green,
								MR_UBYTE blue)
{
	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	setRGB0(&MRDisplay_ptr->di_drawenv[0], red, green, blue);
	setRGB0(&MRDisplay_ptr->di_drawenv[1], red, green, blue);
}


/******************************************************************************
*%%%% MRSetDisplayPosition
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetDisplayPosition(
*						MR_SHORT	dp_x,
*						MR_SHORT	dp_y);	
*
*	FUNCTION	Sets the display position. This is purely a display hardware 
*				thing, and in no way affects the coordinates of any viewports.
*				This function is just so the user can position the screen to 
*				stop any clipping by their video output device.
*				clearing is enabled.
*
*	INPUTS		dp_x		-		Display X position (CRTC coordinates)
*				dp_y		-		Display Y position (CRTC coordinates)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetDisplayPosition(	MR_SHORT	dp_x,
								MR_SHORT	dp_y)
{
	// There has to be an active display
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	// Range X/Y position
	if (dp_x > MR_DISP_MAX_X_POS)
		dp_x = MR_DISP_MAX_X_POS;
	if (dp_x < MR_DISP_MIN_X_POS)
		dp_x = MR_DISP_MIN_X_POS;
	if (dp_y > MR_DISP_MAX_Y_POS)
		dp_y = MR_DISP_MAX_Y_POS;
	if (dp_y < MR_DISP_MIN_Y_POS)
		dp_y = MR_DISP_MIN_Y_POS;

	MRDisplay_pos_x = dp_x;
	MRDisplay_pos_y = dp_y;

	// Set display position in both dispenv's
	MRDisplay_ptr->di_dispenv[0].screen.x = MRDisplay_pos_x;
	MRDisplay_ptr->di_dispenv[1].screen.x = MRDisplay_pos_x;

	if (MRDisplay_ptr->di_video_flags & MR_DD_NTSC)
		{
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y;
		}
	else
		{
		MRDisplay_ptr->di_dispenv[0].screen.y = MRDisplay_pos_y + 16;
		MRDisplay_ptr->di_dispenv[1].screen.y = MRDisplay_pos_y + 16;
		}
}


/******************************************************************************
*%%%% MRInitialiseGatso
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseGatso(MR_VOID);
*
*	FUNCTION	Turns on the display.
*
*	NOTES		Initialises any callbacks required for gatso timing, and also
*				sets up the primitives that will be used to render information.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseGatso(MR_VOID)
{
#ifdef	MR_GATSO

	MR_GATSO_DATA*	data_ptr  	= &MRGatso_data[0];
	MR_LONG			item_xpos 	= MR_GATSO_X_POS;
	MR_LONG			item_ypos 	= MR_GATSO_Y_POS;
	MR_LONG			loop;
	MR_LONG			work_xpos;
	MR_LONG			setup_idx;

	MR_BYTE*		setup_ptr;
	SPRT			(*sprt_ptr)[MR_GATSO_ITEM_SPRITE_COUNT];

	while(data_ptr->gd_setup_ptr)
		{
		setup_ptr	= data_ptr->gd_setup_ptr;
		sprt_ptr	= data_ptr->gd_prim_ptr;

		for (loop = 0; loop < 2; loop++)
			{
			setup_idx = 0;
			work_xpos = item_xpos + 0;
	
			for (setup_idx = 0; setup_idx < MR_GATSO_ITEM_SPRITE_COUNT; setup_idx++)
				{
				setSprt(&sprt_ptr[loop][setup_idx]);
				setRGB0(&sprt_ptr[loop][setup_idx], 0x80, 0x80, 0x80);
				sprt_ptr[loop][setup_idx].clut	= MRGatso_image_ptr->te_clut_id;
				sprt_ptr[loop][setup_idx].x0	= work_xpos;
				sprt_ptr[loop][setup_idx].y0	= item_ypos;
				sprt_ptr[loop][setup_idx].u0	= MRGatso_info[setup_ptr[setup_idx]].gi_u + MRGatso_image_ptr->te_u0;
				sprt_ptr[loop][setup_idx].v0	= MRGatso_info[setup_ptr[setup_idx]].gi_v + MRGatso_image_ptr->te_v0;
				sprt_ptr[loop][setup_idx].w		= MRGatso_info[setup_ptr[setup_idx]].gi_w;
				sprt_ptr[loop][setup_idx].h		= MRGatso_info[setup_ptr[setup_idx]].gi_h;
	
				work_xpos += MRGatso_info[setup_ptr[setup_idx]].gi_w;
	
				// Make sure all primitives for this section are concatenated
				if (setup_idx < (MR_GATSO_ITEM_SPRITE_COUNT-1))
					catPrim(&sprt_ptr[loop][setup_idx],&sprt_ptr[loop][setup_idx+1]);
				}
			}
		item_ypos += MRGatso_info[setup_ptr[0]].gi_h;

		data_ptr++;
		}

	// Flag that we want to see the gatso..
	MRGatso_display = TRUE;

#endif
}


/******************************************************************************
*%%%% MRResetGatso
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResetGatso(MR_VOID);
*
*	FUNCTION	Resets internal gatso counters.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRResetGatso(MR_VOID)
{
#ifdef	MR_GATSO
	
	MRCalc_time		= 0;
	MRRender_time	= 0;
	MRCalc_peak		= 0;
	MRRender_peak	= 0;

#endif
}


/******************************************************************************
*%%%% MRStartGatso
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStartGatso(MR_VOID);
*
*	FUNCTION	Starts CPU timing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRStartGatso(MR_VOID)
{
#ifdef	MR_GATSO
	
	MRCalc_time = GetRCnt(RCntCNT1);

#endif
}


/******************************************************************************
*%%%% MRStopGatso
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStopGatso(MR_VOID);
*
*	FUNCTION	Stops CPU timing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRStopGatso(MR_VOID)
{
#ifdef	MR_GATSO

	MRCalc_time = GetRCnt(RCntCNT1) - MRCalc_time;

#ifdef	MR_GATSO_PEAK
	MRCalc_peak = MAX(MRCalc_peak, MRCalc_time);
	MRCalc_time = MRCalc_peak;
#endif
#endif
}


/******************************************************************************
*%%%% MRStartGatsoProfile
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStartGatso(MR_VOID);
*
*	FUNCTION	Starts CPU timing (profile version).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRStartGatsoProfile(MR_VOID)
{
#ifdef	MR_GATSO
	#ifdef	MR_GATSO_PROFILE
	
	MRProf_time = GetRCnt(RCntCNT1);

	#endif
#endif
}


/******************************************************************************
*%%%% MRStopGatsoProfile
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStopGatso(MR_VOID);
*
*	FUNCTION	Stop CPU timing (profile version).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRStopGatsoProfile(MR_VOID)
{
#ifdef	MR_GATSO
	#ifdef	MR_GATSO_PROFILE

	MRCalc_time += GetRCnt(RCntCNT1) - MRProf_time;

	#endif
#endif
}


/******************************************************************************
*%%%% MRCalculateGatso
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateGatso(MR_VOID); 
*
*	FUNCTION	Calculates primitives for gatso display, adding them to the
*				custom gatso ordering table
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID MRCalculateGatso(MR_VOID)
{
#ifdef	MR_GATSO

#ifdef	MR_MEM_DEBUG
#ifdef	MR_GATSO_SHOW_USED
	MR_CVEC*	colour = NULL;
#endif
	MR_BOOL	memstats_valid = FALSE;
#endif

#ifdef	MR_MEM_DEBUG
	//if (MRFrame_number >  MRMem_status.ms_check_frame_count + MR_GATSO_MEM_PERSISTENCE)
	//	memstats_valid = FALSE;
	//else
		// I WANT THE MEMORY ON ALL THE TIME. $gcr.
		memstats_valid = TRUE;
#endif

#ifdef	MR_GATSO_SHOW_CALC
	MRSetGatsoItemValue(MRCalc_time, &MRGatso_calc_prims[MRFrame_index][0], NULL);
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_calc_prims[MRFrame_index][0],
			&MRGatso_calc_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_DRAW
	MRSetGatsoItemValue(MRRender_time, &MRGatso_draw_prims[MRFrame_index][0], NULL);
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_draw_prims[MRFrame_index][0],
			&MRGatso_draw_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_USED
#ifdef	MR_MEM_DEBUG
	if (memstats_valid)
		{
		if ((MRMem_status.ms_used_memory>>10) > MR_GATSO_EXPECTED_FREE_RAM)
			colour = &MRGatso_used_red;
		else
			colour = &MRGatso_used_white;	
		MRSetGatsoItemValue(MRMem_status.ms_used_memory>>10, &MRGatso_used_prims[MRFrame_index][0], colour);
		}
	else
		{
		MRSetGatsoItemValue(-1, &MRGatso_used_prims[MRFrame_index][0], NULL);
		}		
#else
	MRSetGatsoItemValue(-1, &MRGatso_used_prims[MRFrame_index][0], NULL);
#endif
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_used_prims[MRFrame_index][0],
			&MRGatso_used_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_FREE
#ifdef	MR_MEM_DEBUG
	if (memstats_valid)
		{
		MRSetGatsoItemValue(MRMem_status.ms_available_memory>>10, &MRGatso_free_prims[MRFrame_index][0], NULL);
		}
	else
		{
		MRSetGatsoItemValue(-1, &MRGatso_free_prims[MRFrame_index][0], NULL);
		}
#else										  
	MRSetGatsoItemValue(-1, &MRGatso_free_prims[MRFrame_index][0], NULL);
#endif
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_free_prims[MRFrame_index][0],
			&MRGatso_free_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_MIN_FREE
#ifdef	MR_MEM_DEBUG
	if (memstats_valid)
		{
		MRSetGatsoItemValue(MRMem_status.ms_lowest_free>>10, &MRGatso_min_free_prims[MRFrame_index][0], NULL);
		}
	else
		{
		MRSetGatsoItemValue(-1, &MRGatso_min_free_prims[MRFrame_index][0], NULL);
		}
#else
	MRSetGatsoItemValue(-1, &MRGatso_min_free_prims[MRFrame_index][0], NULL);
#endif
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_min_free_prims[MRFrame_index][0],
			&MRGatso_min_free_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_MAX_FREE
#ifdef	MR_MEM_DEBUG
	if (memstats_valid)
		{
		MRSetGatsoItemValue(MRMem_status.ms_largest_block>>10, &MRGatso_max_free_prims[MRFrame_index][0], NULL);
		}
	else
		{
		MRSetGatsoItemValue(-1, &MRGatso_max_free_prims[MRFrame_index][0], NULL);
		}
#else
	MRSetGatsoItemValue(-1, &MRGatso_max_free_prims[MRFrame_index][0], NULL);
#endif
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_max_free_prims[MRFrame_index][0],
			&MRGatso_max_free_prims[MRFrame_index][5]);
#endif

#ifdef	MR_GATSO_SHOW_MIN_MAX_FREE
#ifdef	MR_MEM_DEBUG
	if (memstats_valid)
		{
		MRSetGatsoItemValue(MRMem_status.ms_lowest_largest_free>>10, &MRGatso_min_max_free_prims[MRFrame_index][0], NULL);
		}
	else
		{
		MRSetGatsoItemValue(-1, &MRGatso_min_max_free_prims[MRFrame_index][0], NULL);
		}
#else
	MRSetGatsoItemValue(-1, &MRGatso_min_max_free_prims[MRFrame_index][0], NULL);
#endif
	addPrims(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index],
			&MRGatso_min_max_free_prims[MRFrame_index][0],
			&MRGatso_min_max_free_prims[MRFrame_index][5]);
#endif

	// Add the DR_ENV structure. This is rendered before the gatso primitives, but lets
	// us render to the entire screen.
	//										  
	// NOTE: Look! Notice how we're adding the DR_ENV for the _NEXT_ frame. This is because
	// when the DrawOTag() request gets processed, we're on another frame...
																												 
	addPrim(MRDisplay_ptr->di_gatso_ot_ptr[MRFrame_index]+MR_GATSO_OT_LEN-1, &MRDisplay_ptr->di_gatso_dr_env[MRFrame_index ^ 0x01]);

#endif
}


/******************************************************************************
*%%%% MRSetGatsoItemValue
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetGatsoItemValue(MR_LONG	value,
*											SPRT*	prim_ptr);
*
*	FUNCTION	Sets digits for a specific gatso information line. Specifically,
*				'prim_ptr' points to the lead address of the sprites forming an
*				information line. Because the format of this line is known (ie 
*				it consists of a title image, a separator, and 4 digits) we 
*				can process the digit U/V sprite coordinates directly.
*
*	INPUTS		value		-	Value to display in line. Clips at '9999', but
*								if '-1' is passed to this function, the displayed
*								value is '----'.
*				prim_ptr	-	Pointer to the lead address of this frames gatso
*								information sprite array.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.02.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetGatsoItemValue(MR_LONG value, SPRT* prim_ptr, MR_CVEC* colour)
{
#ifdef	MR_GATSO
	MR_GATSO_INFO*	info_ptr;
	SPRT*			sprt_nums;
	MR_BOOL			clear_flag;
	MR_LONG			loop;
	MR_LONG			temp_value;

	// Point 'sprt_nums' to the last digit in item setup 
	sprt_nums	= prim_ptr + (MR_GATSO_ITEM_SPRITE_COUNT-1);	

	// If we have a value, max out value at 9999	
	if (value > 0)
		value = MIN(9999,value);

	// Set a flag to say that we want to clear the characters..
	if (value < 0)
		clear_flag = TRUE;
	else
		clear_flag = FALSE;

	for (loop = 0; loop < MR_GATSO_NUM_DIGITS; loop++)
		{

		// If we're wanting to clear the digits, we point to the hyphen character in our gatso image
		if (clear_flag == TRUE)
			{
			info_ptr = &MRGatso_info[MR_GATSO_CH_HYPHEN];
			}
		else
			{
#ifdef	MR_GATSO_LEADING_ZEROS
			temp_value	= value % 10;
#else
			if ((loop > 0) && (value == 0))
				{
				temp_value = MR_GATSO_CH_BLANK;
				}
			else
				{
				temp_value	= value % 10;
				}
#endif
			info_ptr 	= &MRGatso_info[temp_value];
			value		= value / 10;
			}
		
		// Set the digit's U/V coordinates to the required character. This is making the assumption that
		// the size and position of the digits for a gatso display remain constant.
		setUV0(sprt_nums, 
				(MRGatso_image_ptr->te_u0 + info_ptr->gi_u),
				(MRGatso_image_ptr->te_v0 + info_ptr->gi_v));
		
		if (colour != NULL)
			MR_COPY32(sprt_nums->r0, *colour);
	
		sprt_nums--;
		}
#endif
}


/******************************************************************************
*%%%% MRSetGatsoDisplayStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetGatsoDisplayStatus(MR_BOOL display);
*
*	FUNCTION	Changes gatso display status.
*
*	INPUTS		display		-	TRUE if we want to show it, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetGatsoDisplayStatus(MR_BOOL display)
{
#ifdef	MR_GATSO
 	MRGatso_display = display;
#endif
}

