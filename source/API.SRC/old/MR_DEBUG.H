/******************************************************************************
*%%%% mr_debug.h
*------------------------------------------------------------------------------
*
*	Header file for mr_debug.c
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	09.10.96	Tim Closs		MRGrabScreen 	becomes MRDebugGrabScreen
*								MRShowVram		becomes MRDebugShowVram
*								Functions and data added for debug display,
*								enclosed by #ifdef MR_DEBUG_DISPLAY
*	01.11.96	Tim Closs		Added MRDebugPlot2DWorldSplineMatrix()
*	28.01.97	Tim Closs		MRDebugPlotCollPrim() - swapped inputs
*								MRDebugPlotBoundingBox() - added colour input
*								Added:
*								MRDebugPlotHiliteVertices()
*								MRDebugPlotHilitePrims()
*								MR_DEBUG_DISPLAY_HILITE_VERTICES_COLOUR
*								MR_DEBUG_DISPLAY_HILITE_PRIMS_COLOUR
*	18.04.97	Dean Ashton		Added MRDebugPlot2DWorldPolyF4();
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_grab_tim						MR_GRAB_TIM;

#else
#ifndef	__MR_DEBUG_H
#define	__MR_DEBUG_H

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

#define	MR_DEBUG_MOVE_SPEED							8

#ifndef	MR_DEBUG_MAX_TILES
#define	MR_DEBUG_MAX_TILES							512
#endif
#ifndef	MR_DEBUG_MAX_LINES
#define	MR_DEBUG_MAX_LINES							1024
#endif

#define	MR_DEBUG_DISPLAY_BBOX_COLOUR				0x000080		// standard bounding box display colour
#define	MR_DEBUG_DISPLAY_COLLPRIM_COLOUR			0x800080		// standard collprim display colour
#define	MR_DEBUG_DISPLAY_HILITE_VERTICES_COLOUR		0xf0f0f0		// standard hilite vertex display colour
#define	MR_DEBUG_DISPLAY_HILITE_PRIMS_COLOUR		0xffffff		// standard hilite prim display colour


//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

struct __mr_grab_tim
		{
		MR_ULONG	st_id;
		MR_ULONG	st_flag;
		MR_ULONG	st_bnum;
		MR_ULONG	st_dxy;
		MR_ULONG	st_hw;
		MR_USHORT	st_data[0];

		}; // MR_GRAB_TIM


//-----------------------------------------------------------------------------
// Externs
//-----------------------------------------------------------------------------

extern	MR_USHORT	MRRendered_meshes;
extern	MR_USHORT	MRListed_meshes;
extern	MR_USHORT	MRDebug_tile_otz;
extern	MR_USHORT	MRDebug_line_otz;

extern	TILE		MRDebug_tiles[2][MR_DEBUG_MAX_TILES];
extern	LINE_F2		MRDebug_lines[2][MR_DEBUG_MAX_LINES];
extern	TILE*		MRDebug_tile_ptr;
extern	LINE_F2*	MRDebug_line_ptr;


//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		MRDebugShowVram(MR_VOID);
extern	MR_VOID		MRDebugGrabScreen(MR_VOID);

// MR_DEBUG_DISPLAY stuff
//
// General
extern	MR_VOID		MRDebugInitialiseDisplay(MR_VOID);
extern	MR_VOID		MRDebugStartDisplay(MR_VOID);

// 3D
extern	MR_VOID		MRDebugPlotCollPrim(MR_COLLPRIM*, MR_MAT*, MR_SVEC*, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldPoint(MR_SVEC*, MR_ULONG, MR_USHORT);
extern	MR_VOID		MRDebugPlotWorldPointVEC(MR_VEC*, MR_ULONG, MR_USHORT);
extern	MR_VOID		MRDebugPlotWorldSplineHermite(MR_SPLINE_HERMITE*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldSplineBezier(MR_SPLINE_BEZIER*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldBspline(MR_SPLINE_BEZIER*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldSplineMatrix(MR_SPLINE_MATRIX*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlotBoundingBox(MR_BBOX*, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldLine(MR_SVEC*, MR_SVEC*, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldLineVEC(MR_VEC*, MR_VEC*, MR_ULONG);
extern	MR_VOID		MRDebugPlotHiliteVertices(MR_PART*, MR_ULONG);
extern	MR_VOID		MRDebugPlotHilitePrims(MR_MOF*, MR_USHORT, MR_MESH_INST*, MR_ULONG);
extern	MR_VOID		MRDebugPlotWorldPolyF4(MR_SVEC*, POLY_F4*);

// 2D
extern	MR_VOID		MRDebugSet2DScale(MR_LONG);
extern	MR_VOID		MRDebugPlot2DWorldPoint(MR_SVEC*, MR_ULONG, MR_USHORT);
extern	MR_VOID		MRDebugPlot2DWorldLine(MR_SVEC*, MR_SVEC*, MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldAxes(MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldCircle(MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldSplineMatrix(MR_SPLINE_MATRIX*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldBspline(MR_BSPLINE*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldSplineBezierArray(MR_SPLINE_BEZIER_ARRAY*, MR_USHORT, MR_ULONG);
extern	MR_VOID		MRDebugPlot2DWorldBsplineControlPoints(MR_BSPLINE*, MR_ULONG, MR_USHORT);
extern	MR_VOID		MRDebugPlot2DWorldBezierControlPoints(MR_SPLINE_BEZIER*, MR_ULONG, MR_USHORT);
extern	MR_VOID		MRDebugPlot2DWorldSplineBezierArrayControlPoints(MR_SPLINE_BEZIER_ARRAY*, MR_ULONG,	MR_USHORT);
extern	MR_VOID		MRDebugPlot2DWorldPolyF4(MR_SVEC*, POLY_F4*);

#endif	//__MR_DEBUG_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
