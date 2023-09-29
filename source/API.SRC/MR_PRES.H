/******************************************************************************
*%%%% mr_pres.h
*------------------------------------------------------------------------------
*
*	Header for presentation handling code (BETA)
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	20.05.96 	Tim Closs		Created
*	04.11.96 	Tim Closs		MRRenderPres() now takes viewport input
*								MRInputPres() now takes controller id input
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//-----------------------------------------------------------------------------
// Typedefs
//-----------------------------------------------------------------------------

typedef	struct __mr_presitem		MR_PRESITEM;
typedef	struct __mr_presoption		MR_PRESOPTION;
typedef	struct __mr_prespage		MR_PRESPAGE;

#else
#ifndef	__MR_PRES_H
#define	__MR_PRES_H

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

#define	MR_PS_MAX_OPTIONS					16			// per page
#define	MR_PS_MAX_PAGES						16

// MR_PRESITEM flags
#define	MR_PS_ITEM_OWNS_TEXT				(1<<0)

// MR_PRESOPTION flags
#define	MR_PS_OPTION_TOP					(1<<0)
#define	MR_PS_OPTION_BOTTOM					(1<<1)

// Script commands
enum	{
		MR_PS_END,
		MR_PS_BITMAP,
		MR_PS_MARGIN,
		MR_PS_ITEM,
		MR_PS_OPTIONS,
		MR_PS_OPTION_MOVE_CALLBACKS,
		};

// Item types
enum	{
		MR_PS_ITEMTYPE_TEXT,
		MR_PS_ITEMTYPE_BOX,
		MR_PS_ITEMTYPE_2DSPRITE,
		MR_PS_ITEMTYPE_3DSPRITE,
		MR_PS_ITEMTYPE_OUTLINE,
		};

// Justification types
enum	{
		MR_PS_JUST_LEFT,
		MR_PS_JUST_CENTRE,
		MR_PS_JUST_RIGHT,
		};

// Option column directions
enum	{
		MR_PS_HORIZONTAL,
		MR_PS_VERTICAL,
		};
	
// Option types
enum	{
		MR_PS_OPTIONTYPE_FIXED_CALLBACK,
		MR_PS_OPTIONTYPE_WALK,
		MR_PS_OPTIONTYPE_CYCLE,
		MR_PS_OPTIONTYPE_FIXED_SWITCH,
		};	


//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

struct __mr_presitem
	{
	struct __mr_presitem*	pi_next_node;	// next node
	struct __mr_presitem*	pi_prev_node;	// prev node
	MR_SHORT				pi_x;			// x (pixels)
	MR_SHORT				pi_y;			// y (pixels)
	MR_USHORT				pi_w;			// w (pixels)
	MR_USHORT				pi_h;			// h (pixels)
	MR_SHORT				pi_xspeed;		// xspeed (ppf)
	MR_SHORT				pi_yspeed;		// yspeed (ppf)
	MR_SHORT				pi_xdest;		// x destintation (pixels)
	MR_SHORT				pi_ydest;		// y destintation (pixels)
	MR_UBYTE				pi_flags;		// flags eg. MR_PS_ITEM_OWNS_TEXT
	MR_UBYTE				pi_type;		// type eg. MR_PS_ITEMTYPE_TEXT
	MR_SHORT				pi_timer;		// timer
	MR_VOID*				pi_ptr0;		// ptr0 (eg. cast to MR_TEXT_AREA*)
	MR_VOID*				pi_ptr1;		// ptr1
	MR_ULONG*				pi_prims[2];	// pointer to allocated prim memory
	MR_CVEC					pi_colour;		// r,g,b
		
	};	// MR_PRESITEM


struct	__mr_presoption
	{
	MR_USHORT		po_type;		  			// eg. MR_PS_OPTIONTYPE_WALK
	MR_USHORT		po_flags;		  			// eg. MR_PS_OPTION_TOP
	MR_LONG*		po_text_list;	  			// pointer to NULL, <text, .. ,text>, NULL
	MR_LONG*		po_variable;	  			// pointer to variable
	MR_PRESITEM*	po_presitem;	  			// ...associated with option
	MR_VOID			(*po_callback)(MR_VOID);	// pointer to selection callback

	};	// MR_PRESOPTION


struct	__mr_prespage
	{
	MR_LONG*		pp_script;					// pointer to page setup script
	MR_LONG			pp_def_option;				// default MRPresoption_index for this page

	};	// MR_PRESPAGE


//-----------------------------------------------------------------------------
// Externs
//-----------------------------------------------------------------------------

extern	MR_PRESPAGE		MRPrespages[];
extern	MR_USHORT		MRPrespage_index;

extern	MR_VOID			(*MRPresoption_move_callback)(MR_VOID);
extern	MR_PRESITEM*	MRPresoption_move_presitem;
extern	MR_PRESITEM*	MRPresitem_ptr;

extern	MR_PRESOPTION	MRPresoptions[];
extern	MR_USHORT		MRPresoption_index;
extern	MR_USHORT		MRPresoption_timer;


//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			MRInitialisePresentation(MR_VOID);
extern	MR_VOID			MRSetupPresentation(MR_LONG*, MR_VIEWPORT*);
extern	MR_LONG*		MRCreatePresitemFromScriptLine(MR_LONG*);
extern	MR_SHORT		MRPresGetJustifiedX(MR_USHORT, MR_USHORT w, MR_SHORT);
extern	MR_PRESITEM*	MRCreatePresitem(MR_USHORT type);

extern	MR_VOID			MRKillAllPresitems(MR_VOID);
extern	MR_VOID			MRKillAllPresitemsPhysically(MR_VOID);
extern	MR_VOID			MRKillPresitem(MR_PRESITEM* pi_ptr);

extern	MR_VOID			MRInputPres(MR_USHORT);
extern	MR_VOID			MRUpdatePres(MR_VOID);
extern	MR_VOID			MRRenderPres(MR_VIEWPORT*);

extern	MR_VOID			MRHideTextPresitems(MR_VOID);
extern	MR_VOID			MRShowTextPresitems(MR_VOID);

#endif	//__MR_PRES_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS











