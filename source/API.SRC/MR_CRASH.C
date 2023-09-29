/******************************************************************************
*%%%% mr_crash.c
*------------------------------------------------------------------------------
*
*	PlayStation Exception Handler (C Support Routines)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	28.07.97	Dean Ashton		Created, based on work (C)1996 Visual Sciences
*
*%%%**************************************************************************/

#include	"mr_all.h"


MR_STRPTR	MREx_exception_types[] =							
			{
			"External Interrupt",							// 00
			"TLB Modification Exception",					// 01
			"TLB Miss (Load or Fetch)",						// 02
			"TLB Miss (Store)",				 				// 03
			"Address Error Exception (Load or Fetch)",		// 04
			"Address Error Exception (Store)",		  		// 05
			"Bus Error (Fetch)",					  		// 06
			"Bus Error (Load or Store)",			  		// 07
			"Syscall",								  		// 08
			"BreakPoint",							  		// 09
			"Reserved Instruction",							// 10
			"Coprocessor Unusable",							// 11
			"Arithmetic Overflow",					  		// 12
			"Unknown Exception",					  		// 13
			"Unknown Exception",					  		// 14
			"Unknown Exception"								// 15
			};

MR_CVEC		MREx_colours[] = 
			{
			{ 0x80, 0x80, 0x80 },							// Unused
			{ 0x60, 0x60, 0x60 },							// Numbers (grey)
			{ 0x80, 0x70, 0x00 },							// Registers (yellow)
			{ 0x80, 0x80, 0x80 },							// Titles (white)
			{ 0xf0, 0x50, 0x30 },							// Misc. Orange/Red
			};			

DISPENV		MREx_dispenv;									// Display/Drawing environments
DRAWENV		MREx_drawenv;

MR_ULONG	MREx_cause;
MR_ULONG	MREx_pc;
MR_ULONG	MREx_type;

RECT		MREx_bg;										// Rectangle for clearing screen

MR_TEXT		MREx_work[128];									// Room for text expansion
MR_TEXT		MREx_user[128];									// Room for user error text

SPRT		MREx_sprt;

MR_SHORT	MREx_text_x;
MR_SHORT	MREx_text_y;

/******************************************************************************
*%%%% MRExceptionInstall
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRExceptionInstall(MR_BOOL	force_install);
*
*	FUNCTION	Installs an exception handler into the R3000 vector chain by
*				calling a lower-level ASM routine. 
*
*	INPUTS		force_install	-		If TRUE, the exception handler is 
*										installed regardless of the machine
*										being run on. If FALSE, and the 
*										project isn't being run on a recognised
*										development station, the exception
*										handler will also be installed.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRExceptionInstall(MR_BOOL force_install)
{
	MREx_text_ptr	= NULL;
	MREx_force		= force_install;
	MREx_installed	= FALSE;

	MRExceptionInstallASM();
}


/******************************************************************************
*%%%% MRExceptionShow
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRExceptionShow(MR_VOID);
*
*	FUNCTION	Internally called by exception handler to display
*				current machine status.											
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID MRExceptionShow(MR_VOID)
{
	MR_TIM4_HEADER*	tim4 = (MR_TIM4_HEADER*)&MREx_font;

	// Initialise graphics subsystem
	ResetGraph(0);
	SetGraphDebug(0);

	// Load font clut to VRAM
	setRECT(&MREx_bg,	(tim4->tim_clutxy & 0xffff),
						(tim4->tim_clutxy >> 16),
						(tim4->tim_clutw & 0xffff),
						1);
	LoadImage(&MREx_bg, (MR_ULONG*)&tim4->tim_clut[0]);
	DrawSync(0);

	// Load font pixel data to VRAM
	setRECT(&MREx_bg,	(tim4->tim_pixelxy & 0xffff),
						(tim4->tim_pixelxy >> 16),
						(tim4->tim_pixelwh & 0xffff),
						(tim4->tim_pixelwh >> 16));
	LoadImage(&MREx_bg, (MR_ULONG*)&tim4->tim_pixel[0]);
	DrawSync(0);

	// Initialise our sprite
	setSprt(&MREx_sprt);
	setRGB0(&MREx_sprt, 0x80, 0x80, 0x80);
	MREx_sprt.clut = getClut(640, 256);
	MREx_sprt.w = MREx_sprt.h = 6;

	// Set up our display/drawing area at (0,0) with dimensions of 320*240, and set our sprite tpage
	setDefDrawEnv(&MREx_drawenv, 0, 0, 368, 240);
	setDefDispEnv(&MREx_dispenv, 0, 0, 368, 240);

	MREx_drawenv.tpage = getTPage(0, 0, 640, 0);	

#ifdef	MR_MODE_PAL
	MREx_dispenv.screen.y = 16;
	MREx_dispenv.screen.h = 256;
#endif

	setRECT(&MREx_bg,0,0,368,240);
	ClearImage(&MREx_bg, 0x30, 0x00, 0x70);
	PutDrawEnv(&MREx_drawenv);
	PutDispEnv(&MREx_dispenv);
	DrawSync(0);

	MREx_cause	=	MREx_registers.ex_ca;
	MREx_pc		=	MREx_registers.ex_epc;
	MREx_type	=	MREx_cause & 0x1f;
	
	MREx_text_x = 	0;
	MREx_text_y = 	0;

	MRExceptionPrint("\n\n\n\n\n\n\n               \x04PlayStation Exception Handler\n\n\n");

	if (MREx_text_ptr == NULL)
		{
		sprintf(MREx_work, "\n   \x02Type : \x01%s\n", MREx_exception_types[MREx_type]);
		MRExceptionPrint(MREx_work);
		}
	else
		{
		sprintf(MREx_work, "\n   \x02Info : \x01%s\n", MREx_text_ptr);
		MRExceptionPrint(MREx_work);
		}

	sprintf(MREx_work, "\n   \x02PC   : \x01%08x", MREx_pc);
	MRExceptionPrint(MREx_work);

	//	Check the Type....	

	if((MREx_cause & 0x80000000) == 0x80000000)
	{
		MRExceptionPrint(" in branch delay slot.\n\n");
	}
	else
	{
		MRExceptionPrint("\n\n");
	}

	MRExceptionPrint("\n   \x03Registers:\n\n");
	sprintf(MREx_work, "  \x02 zr:\x01%08x\x02  t0:\x01%08x\x02  s0:\x01%08x\x02  t8:\x01%08x\x02\n", MREx_registers.ex_zero, MREx_registers.ex_t0, MREx_registers.ex_s0, MREx_registers.ex_t8);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 at:\x01%08x\x02  t1:\x01%08x\x02  s1:\x01%08x\x02  t9:\x01%08x\x02\n", MREx_registers.ex_at,   MREx_registers.ex_t1, MREx_registers.ex_s1, MREx_registers.ex_t9);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 v0:\x01%08x\x02  t2:\x01%08x\x02  s2:\x01%08x\x02  k0:\x01%08x\x02\n", MREx_registers.ex_v0,   MREx_registers.ex_t2, MREx_registers.ex_s2, MREx_registers.ex_k0);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 v1:\x01%08x\x02  t3:\x01%08x\x02  s3:\x01%08x\x02  k1:\x01%08x\x02\n", MREx_registers.ex_v1,   MREx_registers.ex_t3, MREx_registers.ex_s3, MREx_registers.ex_k1);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 a0:\x01%08x\x02  t4:\x01%08x\x02  s4:\x01%08x\x02  gp:\x01%08x\x02\n", MREx_registers.ex_a0,   MREx_registers.ex_t4, MREx_registers.ex_s4, MREx_registers.ex_gp);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 a1:\x01%08x\x02  t5:\x01%08x\x02  s5:\x01%08x\x02  sp:\x01%08x\x02\n", MREx_registers.ex_a1,   MREx_registers.ex_t5, MREx_registers.ex_s5, MREx_registers.ex_sp);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 a2:\x01%08x\x02  t6:\x01%08x\x02  s6:\x01%08x\x02  fp:\x01%08x\x02\n", MREx_registers.ex_a2,   MREx_registers.ex_t6, MREx_registers.ex_s6, MREx_registers.ex_fp);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 a3:\x01%08x\x02  t7:\x01%08x\x02  s7:\x01%08x\x02  ra:\x01%08x\x02\n", MREx_registers.ex_a3,   MREx_registers.ex_t7, MREx_registers.ex_s7, MREx_registers.ex_ra);
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "\n");
	MRExceptionPrint(MREx_work);
	sprintf(MREx_work, "  \x02 hi:\x01%08x\x02  lo:\x01%08x\x02  sr:\x01%08x\x02  ca:\x01%08x\x02\n", MREx_registers.ex_hi,   MREx_registers.ex_lo, MREx_registers.ex_sr, MREx_registers.ex_ca);
	MRExceptionPrint(MREx_work);

	// Output the text to screen and make sure the screen is displayed
	DrawSync(0);	
	VSync(0);
	SetDispMask(1);			   
	
	// Loop forever
	while(1);

}

MR_VOID	MRExceptionPrint(MR_STRPTR txt)
{
	MR_USHORT	widx;

	while(*txt != '\0')
		{
		if (*txt <= '\x05')
			{
			setRGB0(&MREx_sprt, MREx_colours[*txt].r, MREx_colours[*txt].g, MREx_colours[*txt].b);
			}
		else
		if (*txt == '\n')
			{
			MREx_text_x = 6*3;
			MREx_text_y += 6;
			}
		else
			{
			widx = (*txt) - 32;
			MREx_sprt.x0 = MREx_text_x;
			MREx_sprt.y0 = MREx_text_y;
			MREx_sprt.u0 = (widx % 32) * 6;
			MREx_sprt.v0 = (widx / 32) * 6;
			DrawPrim(&MREx_sprt);
			MREx_text_x += 6;
			DrawSync(0);
			}
		txt++;
		}		
}
