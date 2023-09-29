/******************************************************************************
*%%%% mr_input.h
*------------------------------------------------------------------------------
*
*	Header for mr_input.c
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	07.05.97	Dean Ashton		Added support for L3 and R3 on Analog pad
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

typedef	MR_USHORT							MR_IPACKET_PAD;  			// Data from Standard Controller
typedef	struct	__mr_ipacket_mouse  		MR_IPACKET_MOUSE;			// Data from PlayStation Mouse
typedef	struct	__mr_ipacket_negcon			MR_IPACKET_NEGCON;			// Data from Namco Negcon
typedef	struct	__mr_ipacket_analog_stick	MR_IPACKET_ANALOG_STICK;	// Data from PlayStation Analog Joystick
typedef	struct	__mr_ipacket_analog_pad		MR_IPACKET_ANALOG_PAD;		// Data from PlayStation Analog Pad
typedef	struct	__mr_ipacket_tapdata		MR_IPACKET_TAPDATA;			// Data from a single MultiTap port
typedef	struct	__mr_ipacket_tap			MR_IPACKET_TAP;				// Data from MultiTap
typedef	struct	__mr_ipacket_packet			MR_INPUT_PACKET;			// Main input packet
typedef	struct	__mr_input					MR_INPUT;					// Main input structure

#else
#ifndef	__MR_INPUT_H
#define	__MR_INPUT_H


//-----------------------------------------------------------------------------
// General defines
//-----------------------------------------------------------------------------

#define	MR_MAX_INPUTS			(2)	 				// Number of controllers 
#define	MR_MAX_INPUT_ACTIONS	(16)	 			// Number of assigned actions per controller

//-----------------------------------------------------------------------------
// Defines for recognising different controller types

#define	MR_INPUT_TYPE_MOUSE			(1)
#define	MR_INPUT_TYPE_NEGCON		(2)
#define	MR_INPUT_TYPE_PAD			(4)
#define	MR_INPUT_TYPE_ANALOG_STICK	(5)
#define	MR_INPUT_TYPE_ANALOG_PAD	(7)
#define	MR_INPUT_TYPE_TAP			(8)

#define	MRIF_TYPE_NONE				(1<<0)
#define	MRIF_TYPE_UNKNOWN			(1<<1)
#define	MRIF_TYPE_PAD				(1<<2)
#define	MRIF_TYPE_MOUSE				(1<<3)
#define	MRIF_TYPE_NEGCON			(1<<4)
#define	MRIF_TYPE_ANALOG_STICK		(1<<5)
#define	MRIF_TYPE_ANALOG_PAD		(1<<6)
#define	MRIF_TYPE_TAP				(1<<7)	


//-----------------------------------------------------------------------------
// Defines for port names

#define	MR_INPUT_PORT_0_0			(0)
#define	MR_INPUT_PORT_0_1			(1)
#define	MR_INPUT_PORT_0_2			(2)
#define	MR_INPUT_PORT_0_3			(3)

#define	MR_INPUT_PORT_1_0			(4)
#define	MR_INPUT_PORT_1_1			(5)
#define	MR_INPUT_PORT_1_2			(6)
#define	MR_INPUT_PORT_1_3			(7)

#define	MR_INPUT_PORT_0				MR_INPUT_PORT_0_0
#define	MR_INPUT_PORT_1				MR_INPUT_PORT_1_0

//-----------------------------------------------------------------------------
// Button defines for MR_IPACKET_PAD 

#define	MR_IPPSX_LEFT			(0x0080)		
#define	MR_IPPSX_RIGHT			(0x0020)
#define	MR_IPPSX_UP				(0x0010)
#define	MR_IPPSX_DOWN			(0x0040)

#define	MR_IPPSX_TRIANGLE		(0x1000)
#define	MR_IPPSX_CROSS			(0x4000)
#define	MR_IPPSX_SQUARE			(0x8000)
#define	MR_IPPSX_CIRCLE			(0x2000)

#define	MR_IPPSX_L1				(0x0400)
#define	MR_IPPSX_L2				(0x0100)
#define	MR_IPPSX_R1				(0x0800)
#define	MR_IPPSX_R2				(0x0200)
	
#define	MR_IPPSX_SELECT			(0x0001)
#define	MR_IPPSX_L3				(0x0002)
#define	MR_IPPSX_R3				(0x0004)
#define	MR_IPPSX_START			(0x0008)

//-----------------------------------------------------------------------------
// Defines for default internal remapping table access

#define	MRIPD_LEFT				(1<<0)
#define	MRIPD_RIGHT				(1<<1)
#define	MRIPD_UP				(1<<2)
#define	MRIPD_DOWN				(1<<3)		

#define	MRIPD_TRIANGLE			(1<<4)		
#define	MRIPD_CROSS				(1<<5)		
#define	MRIPD_SQUARE			(1<<6)		
#define	MRIPD_CIRCLE			(1<<7)		

#define	MRIPD_L1				(1<<8)		
#define	MRIPD_L2				(1<<9)		
#define	MRIPD_R1				(1<<10)		
#define	MRIPD_R2				(1<<11)		

#define	MRIPD_START				(1<<12)		
#define	MRIPD_SELECT			(1<<13)	

#define	MRIPD_L3				(1<<14)
#define	MRIPD_R3				(1<<15)	

#define	MRIPD_GREEN				MRIPD_TRIANGLE
#define	MRIPD_BLUE				MRIPD_CROSS
#define	MRIPD_PINK				MRIPD_SQUARE
#define	MRIPD_RED				MRIPD_CIRCLE

//-----------------------------------------------------------------------------
// Defines for non-remapped button access

#define	MRIP_LEFT				(1<<16)
#define	MRIP_RIGHT				(1<<17)
#define	MRIP_UP					(1<<18)
#define	MRIP_DOWN				(1<<19)		

#define	MRIP_TRIANGLE			(1<<20)		
#define	MRIP_CROSS				(1<<21)		
#define	MRIP_SQUARE				(1<<22)		
#define	MRIP_CIRCLE				(1<<23)		

#define	MRIP_L1					(1<<24)		
#define	MRIP_L2					(1<<25)		
#define	MRIP_R1					(1<<26)		
#define	MRIP_R2					(1<<27)		

#define	MRIP_START				(1<<28)		
#define	MRIP_SELECT				(1<<29)		

#define	MRIP_L3					(1<<30)
#define	MRIP_R3					(1<<31)	

#define	MRIP_GREEN				MRIP_TRIANGLE
#define	MRIP_BLUE				MRIP_CROSS
#define	MRIP_PINK				MRIP_SQUARE
#define	MRIP_RED				MRIP_CIRCLE



//-----------------------------------------------------------------------------
// Button defines for MR_IPACKET_MOUSE

#define	MR_IMPSX_BUTTON_L		(0x0800)		
#define	MR_IMPSX_BUTTON_R		(0x0400)


//-----------------------------------------------------------------------------
// Defines for MR_IPACKET_ANALOG_STICK/ANALOG_PAD

#define	MR_IANALOG_TOLERANCE	110

//*************************************************
// NOTE: Needs finishing for other controller types
//*************************************************

//-----------------------------------------------------------------------------
// General packet related stuff

#define	MR_ISIZE_PAD			(2) 				// Defines for the number of bytes
#define	MR_ISIZE_MOUSE			(4)					// returned for each controller packet type.
#define	MR_ISIZE_NEGCON			(6)
#define	MR_ISIZE_ANALOG			(6)
#define	MR_ISIZE_TAP			(32)

#define	MR_MAX_INPUT_BYTES		(34)				// Largest possible size of MR_INPUT_PACKET



//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

struct	__mr_ipacket_mouse  						// Data from PlayStation Mouse
		{
		MR_USHORT	im_buttons;
		MR_BYTE		im_xoffset;
		MR_BYTE		im_yoffset;

		};	// MR_IPACKET_MOUSE

// ----

struct	__mr_ipacket_negcon 						// Data from Namco Negcon
		{
		MR_USHORT	in_buttons;
		MR_BYTE		in_twist;
		MR_BYTE		in_buttonI;
		MR_BYTE		in_buttonII;
		MR_BYTE		in_topleft;

		};	// MR_IPACKET_NEGCON

// ----

struct	__mr_ipacket_analog_stick					// Data from PlayStation Analog Joystick
		{
		MR_USHORT	ia_buttons;
		MR_BYTE		ia_right_x;
		MR_BYTE		ia_right_y;
		MR_BYTE		ia_left_x;
		MR_BYTE		ia_left_y;

		};	// MR_IPACKET_ANALOG_STICK

// ----

struct	__mr_ipacket_analog_pad						// Data from PlayStation Analog Pad
		{
		MR_USHORT	ic_buttons;
		MR_BYTE		ic_right_x;
		MR_BYTE		ic_right_y;
		MR_BYTE		ic_left_x;
		MR_BYTE		ic_left_y;

		};	// MR_IPACKET_ANALOG_PAD

// ----

struct	__mr_ipacket_tapdata						// Data from a single MultiTap port
		{
		MR_BYTE		id_status;
		MR_BYTE		id_format;
		union
			{
			MR_IPACKET_PAD			id_pad;
			MR_IPACKET_NEGCON		id_negcon;
			MR_IPACKET_ANALOG_STICK	id_analog_stick;
			MR_IPACKET_ANALOG_PAD	id_analog_pad;
			} id_data;

		};	// MR_IPACKET_TAPDATA

// ----

struct	__mr_ipacket_tap								// Data from MultiTap
		{
		MR_IPACKET_TAPDATA	it_tapdata[4];
		};	// MR_IPACKET_TAP
	
// ----

struct	__mr_ipacket_packet								// Main input packet
		{
		MR_UBYTE		ip_status;
		MR_UBYTE		ip_format;
		union
			{
			MR_IPACKET_PAD			ip_pad;				// Standard controller
			MR_IPACKET_MOUSE		ip_mouse;			// Mouse
			MR_IPACKET_NEGCON		ip_negcon;			// Namco Negcon
			MR_IPACKET_ANALOG_STICK	ip_analog_stick;	// Analog Joystick
			MR_IPACKET_ANALOG_PAD	ip_analog_pad;		// Analog Pad
			MR_IPACKET_TAP			ip_tap;				// 4-way Multi-Tap
			} ip_data;

		};	// MR_INPUT_PACKET

// ----

struct	__mr_input
		{
		MR_USHORT	in_flags;							// Stuff for pad and general button access
		MR_ULONG	in_pad_up;
		MR_ULONG	in_pad_down;
		MR_ULONG	in_pad_new;
		MR_ULONG	in_pad_old;
		MR_ULONG	in_pad_delta;
		MR_USHORT*	in_pad_remap;

		MR_LONG		in_analog_calibrate_lx;
		MR_LONG		in_analog_calibrate_ly;

		MR_LONG		in_analog_calibrate_rx;
		MR_LONG		in_analog_calibrate_ry;

		MR_UBYTE	in_analog_lx;						// Stuff for analog pad (left and right X/Y's)
		MR_UBYTE	in_analog_ly;
		MR_UBYTE	in_analog_rx;
		MR_UBYTE	in_analog_ry;
		
		MR_BYTE		in_analog_clx;						// Stuff for analog pad (left and right X/Y's, calibrated)
		MR_BYTE		in_analog_cly;
		MR_BYTE		in_analog_crx;
		MR_BYTE		in_analog_cry;

		MR_USHORT	in_mbutt_up;						// Stuff for mouse
		MR_USHORT	in_mbutt_down;
		MR_USHORT	in_mbutt_new;
		MR_USHORT	in_mbutt_old;
		MR_USHORT	in_mbutt_delta;
		MR_BYTE		in_mouse_xoffset;
		MR_BYTE		in_mouse_yoffset;
		
		};	// MR_INPUT


//-----------------------------------------------------------------------------
// Macros
//-----------------------------------------------------------------------------

#define	MR_IS_CONTROLLER_TYPE(port, type)	(MRInput[(port)].in_flags & (type))

#define	MR_CHECK_PAD_PRESSED(port,action)	(MRInput[(port)].in_pad_down & (action))
#define	MR_CHECK_PAD_RELEASED(port,action)	(MRInput[(port)].in_pad_up & (action))
#define	MR_CHECK_PAD_HELD(port,action)		(MRInput[(port)].in_pad_new & (action))

#define	MR_GET_LEFT_RAW_ANALOG_X(port)		(MRInput[(port)].in_analog_lx)
#define	MR_GET_LEFT_RAW_ANALOG_Y(port)		(MRInput[(port)].in_analog_ly)
#define	MR_GET_RIGHT_RAW_ANALOG_X(port)		(MRInput[(port)].in_analog_rx)
#define	MR_GET_RIGHT_RAW_ANALOG_Y(port)		(MRInput[(port)].in_analog_ry)

#define	MR_GET_LEFT_ANALOG_X(port)			(MRInput[(port)].in_analog_clx)
#define	MR_GET_LEFT_ANALOG_Y(port)			(MRInput[(port)].in_analog_cly)
#define	MR_GET_RIGHT_ANALOG_X(port)			(MRInput[(port)].in_analog_crx)
#define	MR_GET_RIGHT_ANALOG_Y(port)			(MRInput[(port)].in_analog_cry)

//-----------------------------------------------------------------------------
// Externals
//-----------------------------------------------------------------------------

extern	MR_INPUT	MRInput[];
extern	MR_LONG		MRMouse_x;
extern	MR_LONG		MRMouse_y;
extern	MR_USHORT	MRMouse_up_buttons;
extern	MR_USHORT	MRMouse_down_buttons;
extern	MR_USHORT	MRMouse_new_buttons;	
extern	MR_USHORT	MRMouse_old_buttons;
extern	MR_USHORT	MRMouse_delta_buttons;

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	MRInitialiseInput(MR_USHORT *);									
extern	MR_VOID	MRRemapInput(MR_USHORT, MR_USHORT *);							
extern	MR_VOID	MRReadInput(MR_VOID);												
extern	MR_VOID	MRReadInputCore(MR_INPUT*, MR_INPUT_PACKET*, MR_ULONG);	
extern	MR_VOID	MRClearInput(MR_INPUT*);

extern	MR_VOID	MRAnalogCalibrate(MR_LONG port);

extern	MR_VOID	MRRangeMouse(MR_LONG x0, MR_LONG x1, MR_LONG y0, MR_LONG y1);
extern	MR_VOID	MRSenseMouse(MR_ULONG x, MR_ULONG y);
extern	MR_VOID	MRSetMouse(MR_ULONG x, MR_ULONG y);
extern	MR_VOID	MRMouseRead(MR_ULONG port);

#endif	//__MR_INPUT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

