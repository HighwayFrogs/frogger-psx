/******************************************************************************
*%%%% formlib.h
*------------------------------------------------------------------------------
*
*	Specific forms
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	06.04.97	Tim Closs		Created
*	14.05.97	Martin Kift		Added square radius and collision callback to 
*								form_book structure
*	02.07.97	Martin Kift		Added functionality for thick forms
*
*%%%**************************************************************************/

#ifndef	__FORMLIB_H
#define	__FORMLIB_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	FORM_ID_GENERAL						0x8000		// flag set in ENTITY->en_form_id if a general form

// FORM_BOOK flags
#define FORM_BOOK_FLAG_NO_MODEL				(1<<0)		// Is form a sprite, and therefore no subject to collprim collision and suchlike
#define	FORM_BOOK_FROG_NO_ROTATION_SNAPPING	(1<<1)		// frog rotation is not snapped when landing on this form (eg. lily pads)
#define	FORM_BOOK_FROG_NO_ENTITY_ANGLE		(1<<2)		// no entity angle is calculated (eg. lily pads)
#define FORM_BOOK_RESET_ON_CHECKPOINT		(1<<3)		// Entity is NOT reset if the frog collects a check point
#define FORM_BOOK_RESET_ON_FROG_DEATH		(1<<4)		// Entity is NOT reset if the frog dies
#define FORM_BOOK_THICK_FORM				(1<<5)		// Thick form (form applies beyond bottom of model to some arbitary large value)
#define	FORM_BOOK_FROG_NO_CENTRING_X		(1<<6)		// no centring along entity X axis (unless at end of FORM)
#define	FORM_BOOK_FROG_NO_CENTRING_Z		(1<<7)		// no centring along entity Z axis (unless at end of FORM)
#define	FORM_BOOK_FLAG_NO_COLOUR_FADE		(1<<8)		// For sprites and turns off the Colour Scaling. (Mainly used for Cave Levels.)
#define FORM_BOOK_UNIT_FORM					(1<<9)		// Depth of form is forced to 256 units


// These are used to as an offset from the top of the wad file for each theme. So we can have
// models not included in the map, but needed in the code, included in the wad file and still
// us EASEWAD to create the script. Using an offset means that when we add extra models to the
// top of the file, we don't have to renumber the whole of formlib, just change the define. $gr

#define	CAVES_WAD_OFFSET		(0)
#define	DESERT_WAD_OFFSET		(2)			// For the Fall/Rolling Rocks.
#define	FOREST_WAD_OFFSET		(0)
#define	JUNGLE_WAD_OFFSET		(8)			// For the 8 plinths.
#define	ORIGINAL_WAD_OFFSET		(0)
#define	SWAMP_WAD_OFFSET		(0)
#define	SKY_WAD_OFFSET			(0)
#define	SUBURBIA_WAD_OFFSET		(0)
#define	VOLCANO_WAD_OFFSET		(8)			// For the 8 switches.

enum
	{
	FORM_DEATH_SQUISHED,
	FORM_DEATH_DIE_ON_BACK,
	FORM_DEATH_DROWN,
	FORM_DEATH_BITTEN,
	FORM_DEATH_FLOP,
	FORM_DEATH_POP,
	FORM_DEATH_CRASH,
	FORM_DEATH_MOWED,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__form_book		FORM_BOOK;

struct	__form_book
	{
	MR_ULONG	fb_entity_type;										// index into global Entity_library
	MR_ULONG	fb_mof_id;											// index into theme model WAD
	MR_LONG		fb_script;											// script id to run (or NULL if no script)
	MR_ULONG	fb_flags;											// form flags
	MR_VOID		(*fb_collprim_react)(MR_VOID*, MR_VOID*, MR_VOID*);	// formbased collision callback function
	MR_LONG		fb_radius2;											// squared radius of bounding box (static or anim)
	MR_ULONG	fb_type_of_death;									// type of death required by this form ( 0 .. ? )
	MR_VOID		(*fb_bonus_callback)(MR_VOID*, MR_VOID*, MR_VOID*);	// formbased bonus callback function
	};	// FORM_BOOK

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	FORM_BOOK	Form_library_gen[];
extern	FORM_BOOK	Form_library_cav[];
extern	FORM_BOOK	Form_library_des[];
extern	FORM_BOOK	Form_library_for[];
extern	FORM_BOOK	Form_library_jun[];
extern	FORM_BOOK	Form_library_org[];
//extern	FORM_BOOK	Form_library_arn[];
extern	FORM_BOOK	Form_library_swp[];
extern	FORM_BOOK	Form_library_sky[];
extern	FORM_BOOK	Form_library_sub[];
extern	FORM_BOOK	Form_library_vol[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------



#endif	//__FORMLIB_H

