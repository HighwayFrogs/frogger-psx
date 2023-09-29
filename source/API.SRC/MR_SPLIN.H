/******************************************************************************
*%%%% mr_splin.h
*------------------------------------------------------------------------------
*
*	Functions for handling parametric cubic curves
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	05.08.96	Tim Closs		Created
*	23.09.96	Tim Closs		Increased MR_SPLINE_PARAM accuracy
*	26.09.96	Dean Ashton		Made MR_SPLINE_<x>_SHIFT defines overridable
*	01.11.96	Tim Closs		Added MRCalculateSplineHermitePointDirectly()
*								MRCalculateSplineBezierPointDirectly()
*								MRCalculateBsplinePointDirectly()
*								Added MR_SPLINE_T2_SHIFT define (overridable)
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//-----------------------------------------------------------------------------------------------

typedef	struct	__mr_spline_hermite			MR_SPLINE_HERMITE;
typedef	struct	__mr_spline_bezier			MR_SPLINE_BEZIER;
typedef	struct	__mr_spline_matrix			MR_SPLINE_MATRIX;
typedef	struct	__mr_bspline				MR_BSPLINE;
typedef	struct	__mr_spline_bezier_array	MR_SPLINE_BEZIER_ARRAY;

#else
#ifndef	__MR_SPLIN_H
#define	__MR_SPLIN_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#ifndef	MR_SPLINE_WORLD_SHIFT
#define	MR_SPLINE_WORLD_SHIFT				3	// shift world coords down by this to fit into calculation size
#endif

#ifndef	MR_SPLINE_PARAM_SHIFT
#define	MR_SPLINE_PARAM_SHIFT				11	// fixed point for parameter t ("ONE" = ( 1<< MR_SPLINE_PARAM_SHIFT))
#endif

#ifndef	MR_SPLINE_T2_SHIFT
#define	MR_SPLINE_T2_SHIFT					3	// shift applied to (t*t) before it is used
#endif

#define	MR_SPLINE_PARAM_ONE					(1 << MR_SPLINE_PARAM_SHIFT)

// NOTE:	 MR_SPLINE_PARAM_SHIFT must be greater than MR_SPLINE_WORLD_SHIFT

// Spline flags
#define	MR_SPLINE_MULTIPLE_MATRICES			(1<<0)


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_spline_hermite
	{
	MR_SVEC				sh_p1;				// start point
	MR_SVEC				sh_p4;				// end point
	MR_VEC				sh_r1;				// start tangent
	MR_VEC				sh_r4;				// end tangent
	
	};	// MR_SPLINE_HERMITE


struct	__mr_spline_bezier
	{
	MR_SVEC				sb_p1;				// start point
	MR_SVEC				sb_p2;				// control point (generates start tangent)
	MR_SVEC				sb_p3;				// control point (generates end tangent)
	MR_SVEC				sb_p4;				// end point
					
	};	// MR_SPLINE_BEZIER


struct	__mr_spline_matrix
	{
	MR_LONG				sm_m[4][3];			// spline coefficient matrix

	};	// MR_SPLINE_MATRIX

	
struct	__mr_bspline
	{
	MR_USHORT			bs_numpoints;		// number of control points
	MR_USHORT			bs_numsegments;		// number of segments (points - 3)
	MR_USHORT			bs_flags;			// eg. MR_SPLINE_MULTIPLE_MATRICES
	MR_SHORT			bs_matrix_index;	// segment index of matrix currently evaluated (if only using one matrix)
	MR_SVEC*			bs_points;			// ptr to start of array of control points (size is number of points)
	MR_SPLINE_MATRIX*	bs_matrices;		// ptr to start of array of coefficient matrices (size is numsegments, or 1)

	};	// MR_BSPLINE


struct	__mr_spline_bezier_array
	{
	MR_USHORT			sb_numbeziers;		// number of bezier splines in array
	MR_USHORT			sb_flags;			// eg. MR_SPLINE_MULTIPLE_MATRICES
	MR_SHORT			sb_matrix_index;	// segment index of matrix currently evaluated (if only using one matrix)
	MR_USHORT			sb_pad;
	MR_SPLINE_BEZIER*	sb_beziers;			// ptr to start of array of bezier splines
	MR_SPLINE_MATRIX*	sb_matrices;		// ptr to start of array of coefficient matrices (size is numbeziers, or 1)

	};	// MR_SPLINE_BEZIER_ARRRAY


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID					MRCalculateSplineHermiteMatrix(MR_SPLINE_HERMITE*, MR_SPLINE_MATRIX*);
extern	MR_VOID					MRCalculateSplineBezierMatrix(MR_SPLINE_BEZIER*, MR_SPLINE_MATRIX*);

extern	MR_VOID					MRCalculateSplinePoint(MR_SPLINE_MATRIX*, MR_LONG, MR_SVEC*);
extern	MR_VOID					MRCalculateSplineTangent(MR_SPLINE_MATRIX*, MR_LONG, MR_VEC*);
extern	MR_VOID					MRCalculateSplineTangentNormalised(MR_SPLINE_MATRIX*, MR_LONG, MR_VEC*);
extern	MR_VOID					MRCalculateSplineSecondDerivative(MR_SPLINE_MATRIX*, MR_LONG, MR_VEC*);
extern	MR_VOID					MRCalculateSplineHermitePointDirectly(MR_SPLINE_HERMITE*, MR_LONG, MR_SVEC*);
extern	MR_VOID					MRCalculateSplineBezierPointDirectly(MR_SPLINE_BEZIER*, MR_LONG, MR_SVEC*);

// Bspline stuff
extern	MR_BSPLINE*				MRCreateBspline(MR_USHORT, MR_SVEC*, MR_USHORT);
extern	MR_VOID					MRKillBspline(MR_BSPLINE*);
extern	MR_VOID					MRCalculateEntireBspline(MR_BSPLINE*);
extern	MR_VOID					MRCalculateBsplineMatrix(MR_SPLINE_BEZIER*, MR_SPLINE_MATRIX*);
extern	MR_VOID					MRCalculateBsplinePoint(MR_BSPLINE*, MR_LONG t, MR_SVEC* point);
extern	MR_VOID					MRCalculateBsplinePointDirectly(MR_SPLINE_BEZIER*, MR_LONG, MR_SVEC*);

// Bezier array stuff
extern	MR_SPLINE_BEZIER_ARRAY*	MRCreateSplineBezierArray(MR_USHORT, MR_SPLINE_BEZIER*, MR_USHORT);
extern	MR_VOID					MRCalculateEntireSplineBezierArray(MR_SPLINE_BEZIER_ARRAY*);
extern	MR_VOID					MRCalculateSplineBezierArrayPoint(MR_SPLINE_BEZIER_ARRAY*, MR_LONG, MR_SVEC*);


#endif	//__MR_SPLIN_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
