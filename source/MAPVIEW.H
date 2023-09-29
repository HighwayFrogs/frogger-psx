/******************************************************************************
*%%%% mapview.h
*------------------------------------------------------------------------------
*
*	Calculate the viewing region.  Store a (-1) terminated list of map group
*	indices
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__MAPVIEW_H
#define	__MAPVIEW_H

#include "mr_all.h"
#include "mapdisp.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	MAP_VIEW_DRAW_PROJECTION
//#define	MAP_VIEW_DRAW_PICTURE

// Defines
#define	MAP_VIEW_QUAD_BORDER_WIDTH		768


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	GET_MAPGROUP_X_FROM_WORLD_X(a) \
		(((a) - Map_view_basepoint.vx) / Map_view_xlen)

#define	GET_MAPGROUP_Z_FROM_WORLD_Z(a) \
		(((a) - Map_view_basepoint.vz) / Map_view_zlen)


//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_SVEC		Map_view_basepoint;
extern	MR_LONG		Map_view_xlen;
extern	MR_LONG		Map_view_zlen;
extern	MR_LONG		Map_view_xnum;
extern	MR_LONG		Map_view_znum;
extern	POLY_F4		Map_view_debug_polys[2][MAP_MAX_POLY_GROUPS];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		InitialiseMapView(MR_VOID);
extern	MR_VOID		CreateMapViewList(MR_ULONG);
extern	MR_VOID		MapViewDrawPixel(MR_LONG, MR_LONG);
extern	MR_VOID		MapViewDrawLine(MR_LONG, MR_LONG, MR_LONG, MR_LONG);

// Debug
extern	MR_VOID		MapViewTest(MR_VOID);
extern	MR_VOID		RenderMapViewDebugDisplay(MR_VOID);
extern	MR_VOID		MapViewDrawPicture(MR_VOID);


#endif		//__MAPVIEW_H

