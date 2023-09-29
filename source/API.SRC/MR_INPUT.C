/******************************************************************************
*%%%% mr_input.c
*------------------------------------------------------------------------------
*
*	Input handling routines
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	22.01.97	Dean Ashton		Analog and Multitap support!
*	07.05.97	Dean Ashton		New L3 and R3 buttons on Analog pad supported
*
*%%%**************************************************************************/

#include	"mr_all.h"


// Globals

MR_INPUT_PACKET	MRInput_buffer[2];	  		// Room for packets from port 0 (Left) and port 1 (Right)
MR_INPUT   		MRInput[8];					// One MR_INPUT structure per port (assuming two multitaps

// Default controller mapping

MR_USHORT	MRInput_default_map[MR_MAX_INPUT_ACTIONS+1] =
				{
				// PlayStation H/W				Name			Alternate Name

				MR_IPPSX_LEFT,				// MRIP_LEFT	/	<none>
				MR_IPPSX_RIGHT,				// MRIP_RIGHT	/	<none>
				MR_IPPSX_UP,				// MRIP_UP		/	<none>
				MR_IPPSX_DOWN,				// MRIP_DOWN	/	<none>

				MR_IPPSX_TRIANGLE,			// MRIP_GREEN	/	MRIP_TRIANGLE
				MR_IPPSX_CROSS,				// MRIP_BLUE	/	MRIP_CROSS
				MR_IPPSX_SQUARE,			// MRIP_PINK	/	MRIP_SQUARE
				MR_IPPSX_CIRCLE,			// MRIP_RED		/	MRIP_CIRCLE

				MR_IPPSX_L1,				// MRIP_L1		/	MRIP_LEFT_1
				MR_IPPSX_L2,				// MRIP_L2		/	MRIP_LEFT_2
				MR_IPPSX_R1,				// MRIP_R1		/	MRIP_RIGHT_1
				MR_IPPSX_R2,				// MRIP_R2		/	MRIP_RIGHT_2

				MR_IPPSX_START,				// MRIP_START	/	<none>
				MR_IPPSX_SELECT,			// MRIP_SELECT	/	<none>

				MR_IPPSX_L3,				// MRIP_L3		/	<none>
				MR_IPPSX_R3,				// MRIP_R3		/	<none>

				NULL						// List terminator
				};


// Simple mouse routine variables (Private)
MR_LONG		MRMouse_pminx;
MR_LONG		MRMouse_pminy;
MR_LONG		MRMouse_pmaxx;
MR_LONG		MRMouse_pmaxy;
MR_USHORT	MRMouse_dx;
MR_USHORT	MRMouse_dy;
MR_LONG		MRMouse_px;
MR_LONG		MRMouse_py;

// Simple mouse routine variables (Public)
MR_LONG		MRMouse_x;
MR_LONG		MRMouse_y;
MR_USHORT	MRMouse_up_buttons;
MR_USHORT	MRMouse_down_buttons;
MR_USHORT	MRMouse_new_buttons;	
MR_USHORT	MRMouse_old_buttons;
MR_USHORT	MRMouse_delta_buttons;


/******************************************************************************
*%%%% MRInitialiseInput
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseInput(
*						MR_USHORT*	remap);
*
*	FUNCTION	Initialises the data areas associated with controller reading,
*				and starts a VBlank-driven hardware read of the controller
*				ports into the internal buffers.
*
*	INPUTS		remap		-		Pointer to a valid remap table, or NULL
*									to use the default remap table, which only
*									supports UP/DOWN/LEFT/RIGHT/FIRE/PAUSE.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseInput(MR_USHORT* remap)
{
	MR_USHORT	loop;

	// Clear Buffer areas
	MR_CLEAR(MRInput_buffer);
	MR_CLEAR(MRInput);

	// Set default button remapping table for all inputs
	for (loop = 0; loop < 8; loop++)
		{
				
		MRInput[loop].in_analog_calibrate_lx = 128;
		MRInput[loop].in_analog_calibrate_ly = 128;
		MRInput[loop].in_analog_calibrate_rx = 128;
		MRInput[loop].in_analog_calibrate_ry = 128;

		if (remap == NULL)
			MRInput[loop].in_pad_remap = MRInput_default_map;
		else
			MRInput[loop].in_pad_remap = remap;
		}

	// Initialise the controller ports 
#ifdef	MR_INPUT_USE_MULTITAP
	InitTAP((MR_BYTE*)&MRInput_buffer[0], MR_MAX_INPUT_BYTES, (MR_BYTE*)&MRInput_buffer[1], MR_MAX_INPUT_BYTES);
	VSync(0);
	StartTAP();
	VSync(0);
#else
	InitPAD((MR_BYTE*)&MRInput_buffer[0], MR_MAX_INPUT_BYTES, (MR_BYTE*)&MRInput_buffer[1], MR_MAX_INPUT_BYTES);
	VSync(0);
	StartPAD();
	VSync(0);
#endif


}


/******************************************************************************
*%%%% MRRemapInput
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemapInput(
*						MR_USHORT	port,
*						MR_USHORT*	remap);
*
*	FUNCTION	Changes the remapping table for a given controller port. This
*				clears all buffered keypress information too.
*
*	INPUTS		port		-	Port number (currently 0 or 1)
*				remap		-	Pointer to a valid remapping table, or
*							 	NULL to use internal default table.
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	29.03.97	Dean Ashton		Preserves flags (saying what's in the port)
*								Doesn't clear both MRInput structures anymore.
*
*%%%**************************************************************************/

MR_VOID	MRRemapInput(	MR_USHORT	port,
						MR_USHORT*	remap)
{
	MR_USHORT	flag_backup;

	// Clear all input buffer keypresses (but leave the type alone!)
	flag_backup = MRInput[port].in_flags;
	MR_CLEAR(MRInput[port]);
	MRInput[port].in_flags = flag_backup;

	if (remap == NULL)
		MRInput[port].in_pad_remap = MRInput_default_map;
	else
		MRInput[port].in_pad_remap = remap;
}


/******************************************************************************
*%%%% MRReadInput
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRReadInput(MR_VOID)
*
*	FUNCTION	Interrogates the internal buffers associated with each controller
*				port, processing the received packets and storing filtered input
*				in other user-accessible structures.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRReadInput(MR_VOID)
{
	MR_INPUT_PACKET*	packet;
	MR_INPUT*			input;
	MR_BOOL				clear_tap;															 
	MR_USHORT			loop;
	
	for (loop = 0; loop < 2; loop++)
		{
		// Set pointers to commonly used structures
		packet		= &MRInput_buffer[loop];
		input		= &MRInput[loop * 4];		// Maximum of 4 controllers for each input buffer
		clear_tap	= FALSE;

		if (packet->ip_status == 0x00)			// If there's a device, and it transmitted ok.
			{
			switch (packet->ip_format >> 4)		// Device type is in top 4 bits
				{
				case	MR_INPUT_TYPE_TAP:
					// Process each input packet on the multitap, and pass in a flag_combine of MR_IF_TYPE_TAP so we can
					// identify that the controllers are on a multitap.
					MRReadInputCore(input+0, (MR_INPUT_PACKET*)&packet->ip_data.ip_tap.it_tapdata[0] , MRIF_TYPE_TAP);
					MRReadInputCore(input+1, (MR_INPUT_PACKET*)&packet->ip_data.ip_tap.it_tapdata[1] , MRIF_TYPE_TAP);
					MRReadInputCore(input+2, (MR_INPUT_PACKET*)&packet->ip_data.ip_tap.it_tapdata[2] , MRIF_TYPE_TAP);
					MRReadInputCore(input+3, (MR_INPUT_PACKET*)&packet->ip_data.ip_tap.it_tapdata[3] , MRIF_TYPE_TAP);
					break;

				default:
					// Process input packet for single controller in port, and clear multitap-related types
					MRReadInputCore(input+0, packet, NULL);
					MRClearInput(input+1);
					MRClearInput(input+2);
					MRClearInput(input+3);
					break;
				}
			}
		else
			{
			MRClearInput(input+0);
			MRClearInput(input+1);
			MRClearInput(input+2);
			MRClearInput(input+3);
			}
		}
}



/******************************************************************************
*%%%% MRReadInputCore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRReadInputCore(MR_INPUT*			input,
*										MR_INPUT_PACKET*	packet,
*										MR_ULONG			flag_combine);
*
*	FUNCTION	Interrogates an input packet, filling out the appropriate
*				MR_INPUT, based on the received controller information.
*
*	INPUTS		input			-	Pointer to a MR_INPUT structure to fill out.
*				packet			-	Pointer to a MR_INPUT_PACKET with raw input data
*				flag_combine	-	Value to be bitwise-OR'd with the type. This is
*									so we can flag all controllers off a multitap as
*									actually being so..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.01.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRReadInputCore(MR_INPUT* input, MR_INPUT_PACKET* packet, MR_ULONG flag_combine)
{
	MR_USHORT*		pad_remap;
	MR_USHORT*		pad_fixed;	
	MR_USHORT		pad_bitcount;
	MR_USHORT		button_raw;
	MR_SHORT		analog_val;

	if (packet->ip_status == 0x00)			// If there's a device, and it transmitted ok.
		{
		switch (packet->ip_format >> 4)		// Device type is in top 4 bits
			{
		//	--- PlayStation Pad ---
			case	MR_INPUT_TYPE_PAD:
				input->in_flags	= MRIF_TYPE_PAD | flag_combine;
				pad_remap			= input->in_pad_remap;		// Point to remap table for this device
				pad_fixed			= MRInput_default_map;		// Point to fixed table for buttons
				input->in_pad_old	= input->in_pad_new;		// Keep old bits, for deltas etc etc					

				// Obtain newly pressed (and remapped) bits
				button_raw = ~packet->ip_data.ip_pad;			// Read raw bits. Invert state (1=Pressed)
				input->in_pad_new = 0;

				// Add remapped button bits
				pad_bitcount = 0;
				while (*pad_remap)									// NULL terminates remap list
					{
					if (*pad_remap & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_remap++;
					}

				// Add fixed button bits
				pad_bitcount = 16;
				while (*pad_fixed)									// NULL terminates remap list
					{
					if (*pad_fixed & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_fixed++;
					}

				// Construct pad variables
				input->in_pad_delta	= input->in_pad_new ^ input->in_pad_old;
				input->in_pad_up	= input->in_pad_old & input->in_pad_delta;
				input->in_pad_down	= input->in_pad_new & input->in_pad_delta;
				break;

		//	--- PlayStation Mouse ---
			case	MR_INPUT_TYPE_MOUSE:
				input->in_flags		= MRIF_TYPE_MOUSE | flag_combine;
				input->in_mbutt_old	= input->in_mbutt_new;
				button_raw			= (~packet->ip_data.ip_mouse.im_buttons)&0x0c00;	// Change state, mask bits

				// Construct new mouse button variables
				input->in_mbutt_new		= button_raw;
				input->in_mbutt_delta	= input->in_mbutt_new ^ input->in_mbutt_old;	
				input->in_mbutt_up		= input->in_mbutt_old & input->in_mbutt_delta;
				input->in_mbutt_down	= input->in_mbutt_new & input->in_mbutt_delta;
				input->in_mouse_xoffset	= packet->ip_data.ip_mouse.im_xoffset;
				input->in_mouse_yoffset	= packet->ip_data.ip_mouse.im_yoffset;
					
				break;	

		// --- Namco NegCon ---
			case	MR_INPUT_TYPE_NEGCON:
				MRClearInput(input);
				input->in_flags	= MRIF_TYPE_NEGCON | flag_combine;
				break;

		// --- PlayStation Analog Stick ---
			case	MR_INPUT_TYPE_ANALOG_STICK:
				input->in_flags 	= MRIF_TYPE_ANALOG_STICK;
				pad_remap 			= input->in_pad_remap;		// Point to remap table for this device
				pad_fixed			= MRInput_default_map;		// Point to fixed table for buttons
				input->in_pad_old 	= input->in_pad_new;			// Keep old bits, for deltas etc etc					

				// Obtain newly pressed (and remapped) bits
				button_raw = ~packet->ip_data.ip_pad;			// Read raw bits. Invert state (1=Pressed)
				input->in_pad_new = 0;
			
				// Add remapped button bits
				pad_bitcount = 0;
				while (*pad_remap)									// NULL terminates remap list
					{
					if (*pad_remap & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_remap++;
					}

				// Add fixed button bits
				pad_bitcount = 16;
				while (*pad_fixed)									// NULL terminates remap list
					{
					if (*pad_fixed & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_fixed++;
					}


				// Construct pad variables
				input->in_pad_delta	= input->in_pad_new ^ input->in_pad_old;
				input->in_pad_up	= input->in_pad_old & input->in_pad_delta;
				input->in_pad_down	= input->in_pad_new & input->in_pad_delta;

				// Set analog values
				input->in_analog_lx	= packet->ip_data.ip_analog_pad.ic_left_x;
				input->in_analog_ly	= packet->ip_data.ip_analog_pad.ic_left_y;
				input->in_analog_rx	= packet->ip_data.ip_analog_pad.ic_right_x;
				input->in_analog_ry	= packet->ip_data.ip_analog_pad.ic_right_y;

				// Set calibrated analog values
				analog_val = (input->in_analog_lx - (unsigned)input->in_analog_calibrate_lx);
				input->in_analog_clx = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_ly - (unsigned)input->in_analog_calibrate_ly);
				input->in_analog_cly = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_rx - (unsigned)input->in_analog_calibrate_rx);
				input->in_analog_crx = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_ry - (unsigned)input->in_analog_calibrate_ry);
				input->in_analog_cry = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));

				break;

		// --- PlayStation Analog Pad ---
			case	MR_INPUT_TYPE_ANALOG_PAD:
				input->in_flags 	= MRIF_TYPE_ANALOG_PAD;
				pad_remap			= input->in_pad_remap;		// Point to remap table for this device
				pad_fixed			= MRInput_default_map;		// Point to fixed table for buttons
				input->in_pad_old 	= input->in_pad_new;			// Keep old bits, for deltas etc etc					

				// Obtain newly pressed (and remapped) bits
				button_raw = ~packet->ip_data.ip_pad;			// Read raw bits. Invert state (1=Pressed)
				input->in_pad_new = 0;

				// Add remapped button bits
				pad_bitcount = 0;
				while (*pad_remap)									// NULL terminates remap list
					{
					if (*pad_remap & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_remap++;
					}

				// Add fixed button bits
				pad_bitcount = 16;
				while (*pad_fixed)									// NULL terminates remap list
					{
					if (*pad_fixed & button_raw)				
						input->in_pad_new |= (1<<pad_bitcount);
					pad_bitcount++;
					pad_fixed++;
					}

				// Construct pad variables
				input->in_pad_delta	= input->in_pad_new ^ input->in_pad_old;
				input->in_pad_up	= input->in_pad_old & input->in_pad_delta;
				input->in_pad_down	= input->in_pad_new & input->in_pad_delta;

				// Set analog values
				input->in_analog_lx	= packet->ip_data.ip_analog_pad.ic_left_x;
				input->in_analog_ly	= packet->ip_data.ip_analog_pad.ic_left_y;
				input->in_analog_rx	= packet->ip_data.ip_analog_pad.ic_right_x;
				input->in_analog_ry	= packet->ip_data.ip_analog_pad.ic_right_y;

				// Set calibrated analog values
				analog_val = (input->in_analog_lx - (unsigned)input->in_analog_calibrate_lx);
				input->in_analog_clx = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_ly - (unsigned)input->in_analog_calibrate_ly);
				input->in_analog_cly = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_rx - (unsigned)input->in_analog_calibrate_rx);
				input->in_analog_crx = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));
				analog_val = (input->in_analog_ry - (unsigned)input->in_analog_calibrate_ry);
				input->in_analog_cry = MAX(-MR_IANALOG_TOLERANCE, MIN((signed)analog_val, MR_IANALOG_TOLERANCE));

				break;

		// --- Unknown controller ---
			default:
				MRClearInput(input);
				input->in_flags 	= MRIF_TYPE_NONE | flag_combine;
				break;
			}
		}
	else
		{
		MRClearInput(input);
		input->in_flags |= flag_combine;
		}
}

/******************************************************************************
*%%%% MRClearInput
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRClearInput(MR_INPUT* input)
*
*	FUNCTION	General function to completely clear a MR_INPUT structure. Used
*				to wipe old data out should the controller be removed/damaged.
*
*	INPUTS		input		-	Pointer to a MR_INPUT structure
*
*	NOTES		This function is for internal use only, and does NOT clear the
*				calibration values for analog pads..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.01.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRClearInput(MR_INPUT* input)
{
	input->in_flags			= MRIF_TYPE_NONE;
	input->in_pad_up 		= 0;
	input->in_pad_down		= 0;
	input->in_pad_new		= 0;
	input->in_pad_old		= 0;
	input->in_pad_delta		= 0;

	input->in_analog_lx		= 0;
	input->in_analog_ly		= 0;
	input->in_analog_rx		= 0;
	input->in_analog_ry		= 0;

	input->in_analog_clx	= 0;
	input->in_analog_cly	= 0;
	input->in_analog_crx	= 0;
	input->in_analog_cry	= 0;

	input->in_mbutt_up		= 0;
	input->in_mbutt_down	= 0;
	input->in_mbutt_new		= 0;
	input->in_mbutt_old		= 0;
	input->in_mbutt_delta	= 0;
	input->in_mouse_xoffset = 0;
	input->in_mouse_yoffset = 0;
}


/******************************************************************************
*%%%% MRAnalogCalibrate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnalogCalibrate(MR_LONG port)
*
*	FUNCTION	Sets calibration values for analog controller reading.
*
*	INPUTS		port 		-	Port number (0->7)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.01.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnalogCalibrate(MR_LONG port)
{
	MRInput[port].in_analog_calibrate_lx = MRInput[port].in_analog_lx;
	MRInput[port].in_analog_calibrate_ly = MRInput[port].in_analog_ly;
	MRInput[port].in_analog_calibrate_rx = MRInput[port].in_analog_rx;
	MRInput[port].in_analog_calibrate_ry = MRInput[port].in_analog_ry;
}


/******************************************************************************
*%%%% SimpleMouse routines (Preliminary)
*------------------------------------------------------------------------------
* Example of use:
*
*		MRInitialiseInput();	  	// Start input handler
*		MRSetMouse(0,0);		  	// Give mouse an initial coordinate
*		MRSenseMouse(3,3);		  	// Change sensitivity values
*		MRRangeMouse(0,320,0,240);	// Clip to a 320x240 screen
*											
*		VSync(0);					// Give the handler time to read controllers
*		MRReadInput();				// Process controller buffers
*		MRMouseRead(0);				// Read any mouse events from port 0
*
*		printf("Mouse is at (%d,%d)\n", MRMouse_x, MRMouse_y);
*
*
*%%%**************************************************************************/


/******************************************************************************
*%%%% MRRangeMouse
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRangeMouse(
*						MR_LONG	minx,
*						MR_LONG	maxx,
*						MR_LONG	miny,
*						MR_LONG	maxx);
*
*	FUNCTION	Sets limits on returned MRMouse_x and MRMouse_y coordinates.
*
*	INPUTS		minx		-		Minimum X value for MRMouse_x
*				maxx		-		Maximum X value for MRMouse_x
*				miny		-		Minimum Y value for MRMouse_y
*				maxy		-		Maximum Y value for MRMouse_y
*
*	NOTES		Remember, MRSenseMouse() must be called first. Look at the
*				code, man.. it's using the sensitivity values..!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRangeMouse(MR_LONG minx, MR_LONG maxx, MR_LONG miny, MR_LONG maxy)
{
	MR_ASSERT(MRMouse_dx != 0);			// These are set up by MRSenseMouse()
	MR_ASSERT(MRMouse_dy != 0);			
	
	MRMouse_pminx = minx*MRMouse_dx;
	MRMouse_pmaxx = maxx*MRMouse_dx;
	MRMouse_pminy = miny*MRMouse_dy;
	MRMouse_pmaxy = maxx*MRMouse_dy;

}


/******************************************************************************
*%%%% MRSenseMouse
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSenseMouse(
*						MR_ULONG	x_sense,
*						MR_ULONG	y_sense);
*
*	FUNCTION	Used to set scaling values to enable differing levels of 
*				mouse sensitivity.
*
*	INPUTS		x_sense		-			X scaling value (typically 2 or 3)
*				y_sense		-			Y scaling value (typically 2 or 3)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSenseMouse(MR_ULONG x_sense, MR_ULONG y_sense)
{
	MRMouse_dx = x_sense;
	MRMouse_dy = y_sense;
}
												 

/******************************************************************************
*%%%% MRSetMouse
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetMouse(
*						MR_ULONG	x_pos,
*						MR_ULONG	y_pos);
*
*	FUNCTION	Used to set the mouse position to an absolute X/Y coordinate
*				within the area defined by MRRangeMouse(). As this function
*				uses the mouse scaling values, it's important that MRSenseMouse()
*				and MRRangeMouse() have been called.
*
*	INPUTS		x_pos			-			Absolute Y position within ranged area
*				y_pos			-			Absolute Y position within ranged area
*
*	NOTES		The X/Y coordinate is not clipped to the range area until the 
*				next call of the MRMouseRead() function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetMouse(	MR_ULONG x_pos,
					MR_ULONG y_pos)
{
	MRMouse_px	= x_pos*MRMouse_dx;
	MRMouse_py	= y_pos*MRMouse_dy;
}


/******************************************************************************
*%%%% MRMouseRead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMouseRead(
*						MR_ULONG	port);
*
*	FUNCTION	Reads interpreted mouse data from the specified controller port
*				buffer, and translates it into debounced mouse button presses
*				and an absolute X/Y coordinate for the mouse, based on the 
*				current range area.
*
*	INPUTS		port		-	Controller port to read from (0 or 1)
*
*	NOTES		If the specified controller port doesn't contain a mouse, then
*				the mouse coordinates and mouse button status will remain 
*				unchanged. And although this function doesn't return anything,
*				it's useful to know that the two global variables MRMouse_x 
*				and MRMouse_y hold the ranged X/Y coordinates for the mouse 
*				after this call. The MRMouse_<x>_buttons variables hold the
*				button press information.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRMouseRead(MR_ULONG port)
{
	MRMouse_px += MRInput[port].in_mouse_xoffset;
	MRMouse_py += MRInput[port].in_mouse_yoffset;

	if (MRMouse_px > MRMouse_pmaxx)
		MRMouse_px = MRMouse_pmaxx;
	else
	if (MRMouse_px < MRMouse_pminx)
		MRMouse_px = MRMouse_pminx;

	if (MRMouse_py > MRMouse_pmaxy)
		MRMouse_py = MRMouse_pmaxy;
	else
	if (MRMouse_py < MRMouse_pminy)
		MRMouse_py = MRMouse_pminy;

	MRMouse_x = MRMouse_px/MRMouse_dx;
	MRMouse_y = MRMouse_py/MRMouse_dy;

	MRMouse_up_buttons		= MRInput[port].in_mbutt_up;
	MRMouse_down_buttons	= MRInput[port].in_mbutt_down;
	MRMouse_new_buttons		= MRInput[port].in_mbutt_new;
	MRMouse_old_buttons		= MRInput[port].in_mbutt_old;
	MRMouse_delta_buttons	= MRInput[port].in_mbutt_delta;

}
