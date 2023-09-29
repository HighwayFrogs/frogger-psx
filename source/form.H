/******************************************************************************
*%%%% form.h
*------------------------------------------------------------------------------
*
*	General form handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__FORM_H
#define	__FORM_H

#include "mr_all.h"
#include "formlib.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// FORM_DATA height types
enum	{
		FORM_DATA_HEIGHT_TYPE_GRID,			// single height for grid
		FORM_DATA_HEIGHT_TYPE_SQUARE,		// height per grid square
		FORM_DATA_HEIGHT_TYPE_VERTEX,		// height per vertex
		};		


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__form				FORM;
typedef	struct	__form_data			FORM_DATA;


struct	__form
	{
	MR_USHORT	fo_numformdatas;	// number of FORM_DATAs to follow
	MR_SHORT	fo_max_y;
	MR_SHORT	fo_xnum;			// number of grid squares in local x
	MR_SHORT	fo_znum;			// number of grid squares in local z
	MR_SHORT	fo_xofs;			// offset of bottom left or grid from form entity origin
	MR_SHORT	fo_zofs;			// offset of bottom left or grid from form entity origin

	MR_ULONG	fo_formdata_ptrs;	// cast the address of this to FORM_DATA** (array of ptrs to structures)

	};	// FORM;


struct	__form_data
	{
	MR_USHORT	fd_height_type;		// eg. FORM_DATA_HEIGHT_TYPE_GRID
	MR_SHORT	fd_height;	   		// ..if single height for grid
	MR_USHORT*	fd_grid_squares;	// ptr to array of (xnum * znum) MR_USHORT flags
	MR_SHORT*	fd_heights;			// (according to fd_height_type)

	};	// FORM_DATA



//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	FORM_BOOK*	Form_library_ptrs[];
extern	FORM_BOOK*	Form_libraries[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		InitialiseFormLibrary(MR_VOID);



#endif		//__FORM_H

