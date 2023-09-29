/******************************************************************************
*%%%% mr_splin.h
*------------------------------------------------------------------------------
*
*	Functions for handling parametric cubic curves
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	05.08.96 	Tim Closs		Created
*	23.09.96 	Tim Closs		Changed shifts in MRCalculateSplinePoint to allow
*			 					greater spline parameter resolution
*	23.10.96 	Tim Closs		Optimised MRCalculateSplineHermiteMatrix() and
*			 					MRCalculateSplineBezierMatrix()
*	01.11.96 	Tim Closs		Added MRCalculateSplineHermitePointDirectly()
*			 					MRCalculateSplineBezierPointDirectly()
*			 					MRCalculateBsplinePointDirectly()
*	31.01.97 	Tim Closs		Changed MRCreateBSpline() to accept flags
*			 					Changed MRCalculateBsplinePoint() to accept flags
*			 					Added	MRCreateSplineBezierArray()
*			 							MRCalculateEntireSplineBezierArray()
*			 							MRCalculateSplineBezierArrayPoint()
*
*%%%**************************************************************************/

#include	"mr_all.h"


/******************************************************************************
*%%%% MRCalculateSplineHermiteMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_VOID	MRCalculateSplineHermiteMatrix(
*			 			MR_SPLINE_HERMITE*	spline,
*			 			MR_SPLINE_MATRIX*	matrix)
*
*	FUNCTION	Generates the 4x3 coefficient matrix from the hermite boundary
*				conditions
*
*	INPUTS		spline	-	ptr to boundary conditions structure
*				matrix	-	ptr to coefficient matrix to be filled out
*
*	RESULT		none
*
*	NOTES		See Computer Graphics, Foley-Van Dam, p. 484, (11.19)
*				Multiplies:	0
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*	23.10.96	Tim Closs		Optimised to use no multiplies
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineHermiteMatrix(	MR_SPLINE_HERMITE*	spline,
										MR_SPLINE_MATRIX*	matrix)
{
	MR_SVEC	u, v;
	MR_VEC	U, V;


	u.vx = spline->sh_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sh_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sh_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = spline->sh_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	v.vy = spline->sh_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	v.vz = spline->sh_p4.vz >> MR_SPLINE_WORLD_SHIFT;

	U.vx = spline->sh_r1.vx >> MR_SPLINE_WORLD_SHIFT;
	U.vy = spline->sh_r1.vy >> MR_SPLINE_WORLD_SHIFT;
	U.vz = spline->sh_r1.vz >> MR_SPLINE_WORLD_SHIFT;

	V.vx = spline->sh_r4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sh_r4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sh_r4.vz >> MR_SPLINE_WORLD_SHIFT;

	matrix->sm_m[0][0] = (2*u.vx) - (2*v.vx) + (U.vx) + (V.vx);
	matrix->sm_m[0][1] = (2*u.vy) - (2*v.vy) + (U.vy) + (V.vy);
	matrix->sm_m[0][2] = (2*u.vz) - (2*v.vz) + (U.vz) + (V.vz);

//	matrix->sm_m[1][0] =-(3*u.vx) + (3*v.vx) - (2*U.vx) - (V.vx);
//	matrix->sm_m[1][1] =-(3*u.vy) + (3*v.vy) - (2*U.vy) - (V.vy);
//	matrix->sm_m[1][2] =-(3*u.vz) + (3*v.vz) - (2*U.vz) - (V.vz);

	// New version using no multiplies
	matrix->sm_m[1][0] = (-matrix->sm_m[0][0]) - u.vx + v.vx - U.vx;
	matrix->sm_m[1][1] = (-matrix->sm_m[0][1]) - u.vy + v.vy - U.vy;
	matrix->sm_m[1][2] = (-matrix->sm_m[0][2]) - u.vz + v.vz - U.vz;

	matrix->sm_m[2][0] = (U.vx);
	matrix->sm_m[2][1] = (U.vy);
	matrix->sm_m[2][2] = (U.vz);

	matrix->sm_m[3][0] = (u.vx);
	matrix->sm_m[3][1] = (u.vy);
	matrix->sm_m[3][2] = (u.vz);
}


/******************************************************************************
*%%%% MRCalculateSplineBezierMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineBezierMatrix(
*						MR_SPLINE_BEZIER*		spline,
*						MR_SPLINE_MATRIX*		matrix)
*
*	FUNCTION	Generates the 4x3 coefficient matrix from the bezier boundary
*				conditions
*
*	INPUTS		spline	-	ptr to boundary conditions structure
*				matrix	-	ptr to coefficient matrix to be filled out
*
*	RESULT		none
*
*	NOTES		See Computer Graphics, Foley-Van Dam, p. 489, (11.28)
*				Multiplies:	9
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*	23.10.96	Tim Closs		Optimised to use no multiplies
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineBezierMatrix(	MR_SPLINE_BEZIER*	spline,
										MR_SPLINE_MATRIX*	matrix)
{
	MR_SVEC	u, v, U, V;


	u.vx = spline->sb_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sb_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sb_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = (spline->sb_p2.vx >> MR_SPLINE_WORLD_SHIFT) * 3;
	v.vy = (spline->sb_p2.vy >> MR_SPLINE_WORLD_SHIFT) * 3;
	v.vz = (spline->sb_p2.vz >> MR_SPLINE_WORLD_SHIFT) * 3;

	U.vx = (spline->sb_p3.vx >> MR_SPLINE_WORLD_SHIFT) * 3;
	U.vy = (spline->sb_p3.vy >> MR_SPLINE_WORLD_SHIFT) * 3;
	U.vz = (spline->sb_p3.vz >> MR_SPLINE_WORLD_SHIFT) * 3;

	V.vx = spline->sb_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sb_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sb_p4.vz >> MR_SPLINE_WORLD_SHIFT;

//	matrix->sm_m[0][0] =-(u.vx) + (3*v.vx) - (3*U.vx) + (V.vx);
//	matrix->sm_m[0][1] =-(u.vy) + (3*v.vy) - (3*U.vy) + (V.vy);
//	matrix->sm_m[0][2] =-(u.vz) + (3*v.vz) - (3*U.vz) + (V.vz);
//
//	matrix->sm_m[1][0] = (3*u.vx) - (6*v.vx) + (3*U.vx);
//	matrix->sm_m[1][1] = (3*u.vy) - (6*v.vy) + (3*U.vy);
//	matrix->sm_m[1][2] = (3*u.vz) - (6*v.vz) + (3*U.vz);
//
//	matrix->sm_m[2][0] =-(3*u.vx) + (3*v.vx);
//	matrix->sm_m[2][1] =-(3*u.vy) + (3*v.vy);
//	matrix->sm_m[2][2] =-(3*u.vz) + (3*v.vz);
//
//	matrix->sm_m[3][0] = (u.vx);
//	matrix->sm_m[3][1] = (u.vy);
//	matrix->sm_m[3][2] = (u.vz);

	// Optimised
	matrix->sm_m[0][0] =-(u.vx) + (v.vx) - (U.vx) + (V.vx);
	matrix->sm_m[0][1] =-(u.vy) + (v.vy) - (U.vy) + (V.vy);
	matrix->sm_m[0][2] =-(u.vz) + (v.vz) - (U.vz) + (V.vz);

	matrix->sm_m[3][0] = (u.vx);
	matrix->sm_m[3][1] = (u.vy);
	matrix->sm_m[3][2] = (u.vz);

	u.vx *= 3;
	u.vy *= 3;
	u.vz *= 3;
	matrix->sm_m[1][0] = (u.vx) - (2*v.vx) + (U.vx);
	matrix->sm_m[1][1] = (u.vy) - (2*v.vy) + (U.vy);
	matrix->sm_m[1][2] = (u.vz) - (2*v.vz) + (U.vz);

	matrix->sm_m[2][0] =-(u.vx) + (v.vx);
	matrix->sm_m[2][1] =-(u.vy) + (v.vy);
	matrix->sm_m[2][2] =-(u.vz) + (v.vz);
}


/******************************************************************************
*%%%% MRCalculateBsplineMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateBsplineMatrix(
*						MR_SPLINE_BEZIER*		spline,
*						MR_SPLINE_MATRIX*		matrix)
*
*	FUNCTION	Generates the 4x3 coefficient matrix from the bezier boundary
*				conditions
*
*	INPUTS		spline	-	ptr to boundary conditions structure
*				matrix	-	ptr to coefficient matrix to be filled out
*
*	RESULT		none
*
*	NOTES		See Computer Graphics, Foley-Van Dam, p. 493, (11.34)
*				Divides: 6
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateBsplineMatrix(	MR_SPLINE_BEZIER*	spline,
									MR_SPLINE_MATRIX*	matrix)
{
	MR_SVEC	u, v, U, V;


	u.vx = spline->sb_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sb_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sb_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = spline->sb_p2.vx >> MR_SPLINE_WORLD_SHIFT;
	v.vy = spline->sb_p2.vy >> MR_SPLINE_WORLD_SHIFT;
	v.vz = spline->sb_p2.vz >> MR_SPLINE_WORLD_SHIFT;

	U.vx = spline->sb_p3.vx >> MR_SPLINE_WORLD_SHIFT;
	U.vy = spline->sb_p3.vy >> MR_SPLINE_WORLD_SHIFT;
	U.vz = spline->sb_p3.vz >> MR_SPLINE_WORLD_SHIFT;

	V.vx = spline->sb_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sb_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sb_p4.vz >> MR_SPLINE_WORLD_SHIFT;

	matrix->sm_m[0][0] = ((-u.vx + V.vx) / 6) + ((v.vx - U.vx) >> 1);
	matrix->sm_m[0][1] = ((-u.vy + V.vy) / 6) + ((v.vy - U.vy) >> 1);
	matrix->sm_m[0][2] = ((-u.vz + V.vz) / 6) + ((v.vz - U.vz) >> 1);

	matrix->sm_m[1][0] = ((u.vx + U.vx) >> 1) - v.vx;
	matrix->sm_m[1][1] = ((u.vy + U.vy) >> 1) - v.vy;
	matrix->sm_m[1][2] = ((u.vz + U.vz) >> 1) - v.vz;

	matrix->sm_m[2][0] = ((-u.vx + U.vx) >> 1);
	matrix->sm_m[2][1] = ((-u.vy + U.vy) >> 1);
	matrix->sm_m[2][2] = ((-u.vz + U.vz) >> 1);

	matrix->sm_m[3][0] = (u.vx + (v.vx << 2) + U.vx) / 6;
	matrix->sm_m[3][1] = (u.vy + (v.vy << 2) + U.vy) / 6;
	matrix->sm_m[3][2] = (u.vz + (v.vz << 2) + U.vz) / 6;
}


/******************************************************************************
*%%%% MRCreateBspline
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BSPLINE*	bspline =	MRCreateBspline(
*										MR_USHORT	numpoints,
*										MR_SVEC*	points,
*										MR_USHORT	flags)
*
*	FUNCTION	Set up a MR_BSPLINE structure (allocated)
*
*	INPUTS		numpoints	-	number of control points in the bspline
*				points		-	ptr to array of these control points
*				flags		-	eg. MR_SPLINE_MULTIPLE_MATRICES
*
*	RESULT		bspline		-	ptr to the MR_BSPLINE set up 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*	31.01.97	Tim Closs		Changed to accept flags field
*
*%%%**************************************************************************/

MR_BSPLINE*	MRCreateBspline(MR_USHORT	numpoints,
					   		MR_SVEC*	points,
					   		MR_USHORT	flags)
{
	MR_BSPLINE*	bspline;
	MR_USHORT  	numsegments;
	MR_USHORT  	nummatrices;
	

	MR_ASSERT(numpoints >= 4);
	MR_ASSERT(points);

	numsegments	= numpoints - 3;
	if (flags & MR_SPLINE_MULTIPLE_MATRICES)
		nummatrices = numsegments;
	else
		nummatrices = 1;
		
	bspline						= MRAllocMem(sizeof(MR_BSPLINE) + (sizeof(MR_SPLINE_MATRIX) * nummatrices), "MR_BSPLI");
	bspline->bs_numpoints 		= numpoints;
	bspline->bs_numsegments 	= numsegments;
	bspline->bs_flags			= flags;
	bspline->bs_matrix_index	= -1;
	bspline->bs_points 			= points;
	bspline->bs_matrices		= (MR_SPLINE_MATRIX*)(((MR_UBYTE*)bspline) + sizeof(MR_BSPLINE));

	if (flags & MR_SPLINE_MULTIPLE_MATRICES)
		{
		MRCalculateEntireBspline(bspline);
		}

	return(bspline);
}


/******************************************************************************
*%%%% MRCreateSplineBezierArray
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_SPLINE_BEZIER_ARRAY*	array	=	MRCreateSplineBezierArray(
*													MR_USHORT			numbeziers,
*													MR_SPLINE_BEZIER*	beziers,
*													MR_USHORT			flags)
*
*	FUNCTION	Set up a MR_SPLINE_BEZIER_ARRAY structure (allocated)
*
*	INPUTS		numbeziers	-	number of beziers in the array
*				beziers		-	ptr to array of these beziers
*				flags		-	eg. MR_SPLINE_MULTIPLE_MATRICES
*
*	RESULT		array		-	ptr to the structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_SPLINE_BEZIER_ARRAY*	MRCreateSplineBezierArray(	MR_USHORT			numbeziers,
													MR_SPLINE_BEZIER*	beziers,
													MR_USHORT			flags)
{
	MR_SPLINE_BEZIER_ARRAY*	array;
	MR_USHORT  				nummatrices;
	

	MR_ASSERT(beziers);

	if (flags & MR_SPLINE_MULTIPLE_MATRICES)
		nummatrices = numbeziers;
	else
		nummatrices = 1;
		
	array					= MRAllocMem(sizeof(MR_SPLINE_BEZIER_ARRAY) + (sizeof(MR_SPLINE_MATRIX) * nummatrices), "MR_SPLBA");
	array->sb_numbeziers	= numbeziers;
	array->sb_flags			= flags;
	array->sb_matrix_index	= -1;
	array->sb_beziers		= beziers;
	array->sb_matrices		= (MR_SPLINE_MATRIX*)(((MR_UBYTE*)array) + sizeof(MR_SPLINE_BEZIER_ARRAY));

	if (flags & MR_SPLINE_MULTIPLE_MATRICES)
		{
		MRCalculateEntireSplineBezierArray(array);
		}

	return(array);
}


/******************************************************************************
*%%%% MRCalculateEntireBspline
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateEntireBspline(
*						MR_BSPLINE* bspline)
*
*	FUNCTION	Calculate a coefficient matrix (allocated) for each segment
*
*	INPUTS		bspline		-	ptr to MR_BSPLINE structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateEntireBspline(MR_BSPLINE* bspline)
{
	MR_USHORT			numsegments;
	MR_SPLINE_MATRIX*	matrix;
	MR_SVEC*			points;


	numsegments = bspline->bs_numsegments;
	matrix		= bspline->bs_matrices;	
	points		= bspline->bs_points;

	while(numsegments--)
		{
		MRCalculateBsplineMatrix((MR_SPLINE_BEZIER*)points, matrix);
		points++;
		matrix++;
		}	
}


/******************************************************************************
*%%%% MRCalculateEntireSplineBezierArray
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateEntireSplineBezierArray(
*						MR_SPLINE_BEZIER_ARRAY* array)
*
*	FUNCTION	Calculate a coefficient matrix (allocated) for each bezier
*
*	INPUTS		array	-	ptr to MR_SPLINE_BEZIER_ARRAY structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateEntireSplineBezierArray(MR_SPLINE_BEZIER_ARRAY* array)
{
	MR_USHORT			numbeziers;
	MR_SPLINE_MATRIX*	matrix;
	MR_SPLINE_BEZIER*	bezier;


	numbeziers	= array->sb_numbeziers;
	matrix		= array->sb_matrices;	
	bezier		= array->sb_beziers;

	while(numbeziers--)
		{
		MRCalculateSplineBezierMatrix(bezier, matrix);
		bezier++;
		matrix++;
		}	
}


/******************************************************************************
*%%%% MRCalculateSplinePoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplinePoint(
*						MR_SPLINE_MATRIX*	matrix,
*						MR_LONG				t,
*						MR_SVEC*			point)
*
*	FUNCTION	Calculates the point on a spline at parameter t
*
*	INPUTS		matrix		-	ptr to spline coefficient matrix
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to point to fill
*
*	RESULT		none
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*				Multiplies:	11
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplinePoint(	MR_SPLINE_MATRIX*	matrix,
								MR_LONG				t,
								MR_SVEC*			point)
{
	MR_LONG	t2 = ( t*t) >> MR_SPLINE_T2_SHIFT;
	MR_LONG	t3 = (t2*t) >> MR_SPLINE_PARAM_SHIFT;


	point->vx = ((t3 * matrix->sm_m[0][0])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				((t2 * matrix->sm_m[1][0])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(( t * matrix->sm_m[2][0])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) +
				((matrix->sm_m[3][0]) << MR_SPLINE_WORLD_SHIFT);
	point->vy = ((t3 * matrix->sm_m[0][1])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				((t2 * matrix->sm_m[1][1])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(( t * matrix->sm_m[2][1])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) +
				((matrix->sm_m[3][1]) << MR_SPLINE_WORLD_SHIFT);
	point->vz = ((t3 * matrix->sm_m[0][2])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				((t2 * matrix->sm_m[1][2])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(( t * matrix->sm_m[2][2])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) +
				((matrix->sm_m[3][2]) << MR_SPLINE_WORLD_SHIFT);
}


/******************************************************************************
*%%%% MRCalculateSplineTangent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineTangent(
*						MR_SPLINE_MATRIX*	matrix,
*						MR_LONG				t,
*						MR_VEC*				tangent)
*
*	FUNCTION	Calculates the tangent to a spline at parameter t
*
*	INPUTS		matrix		-	ptr to spline coefficient matrix
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to tangent
*
*	RESULT		none
*
*	NOTES		Multiplies:	8
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineTangent(	MR_SPLINE_MATRIX*	matrix,
									MR_LONG				t,
									MR_VEC*				tangent)
{
	MR_LONG	t2;
	
	t2 = (3*t*t) >> MR_SPLINE_T2_SHIFT;

	tangent->vx =	((t2 * matrix->sm_m[0][0])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
					((t * matrix->sm_m[1][0])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
					(matrix->sm_m[2][0]<<MR_SPLINE_WORLD_SHIFT);
	tangent->vy =	((t2 * matrix->sm_m[0][1])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
					((t * matrix->sm_m[1][1])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
					(matrix->sm_m[2][1]<<MR_SPLINE_WORLD_SHIFT);
	tangent->vz = 	((t2 * matrix->sm_m[0][2])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
					((t * matrix->sm_m[1][2])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
					(matrix->sm_m[2][2]<<MR_SPLINE_WORLD_SHIFT);
}


/******************************************************************************
*%%%% MRCalculateSplineTangentNormalised
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineTangentNormalised(
*						MR_SPLINE_MATRIX*	matrix,
*						MR_LONG				t,
*						MR_VEC*				tangent)
*
*	FUNCTION	Calculates the normalised tangent to a spline at parameter t
*
*	INPUTS		matrix		-	ptr to spline coefficient matrix
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to tangent
*
*	RESULT		none
*
*	NOTES		Multiplies:	8
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineTangentNormalised(	MR_SPLINE_MATRIX*	matrix,
											MR_LONG				t,
											MR_VEC*				tangent)
{
	MR_LONG	t2;
	MR_VEC	vec;

	
	t2 = (3*t*t) >> MR_SPLINE_T2_SHIFT;

	vec.vx =	((t2 * matrix->sm_m[0][0])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
			 	((t * matrix->sm_m[1][0])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
				(matrix->sm_m[2][0]<<MR_SPLINE_WORLD_SHIFT);
	vec.vy =	((t2 * matrix->sm_m[0][1])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				((t * matrix->sm_m[1][1])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
				(matrix->sm_m[2][1]<<MR_SPLINE_WORLD_SHIFT);
	vec.vz =	((t2 * matrix->sm_m[0][2])>>(MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
  				((t * matrix->sm_m[1][2])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT-1)) +
				(matrix->sm_m[2][2]<<MR_SPLINE_WORLD_SHIFT);

	vec.vx >>= 4;
	vec.vy >>= 4;
	vec.vz >>= 4;

	// vec entries are shifted down by (MR_SPLINE_WORLD_SHIFT + 1) so VectorNormal can handle it
	MRNormaliseVEC(&vec, tangent);
}


/******************************************************************************
*%%%% MRCalculateSplineSecondDerivative
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineSecondDerivative(
*						MR_SPLINE_MATRIX*	matrix,
*						MR_LONG				t,
*						MR_VEC*				vec)
*
*	FUNCTION	Calculates the 2nd derivative to a spline at parameter t
*
*	INPUTS		matrix	-	ptr to spline coefficient matrix
*				t		-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				vec		-	ptr to vec to fill with result
*
*	RESULT		none
*
*	NOTES		Multiplies:	4
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineSecondDerivative(	MR_SPLINE_MATRIX*	matrix,
											MR_LONG				t,
											MR_VEC*				vec)
{
	t *= 6;
	vec->vx = ((t * matrix->sm_m[0][0])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) + (matrix->sm_m[1][0]<<(MR_SPLINE_WORLD_SHIFT+1));
	vec->vy = ((t * matrix->sm_m[0][1])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) + (matrix->sm_m[1][1]<<(MR_SPLINE_WORLD_SHIFT+1));
	vec->vz = ((t * matrix->sm_m[0][2])>>(MR_SPLINE_PARAM_SHIFT-MR_SPLINE_WORLD_SHIFT)) + (matrix->sm_m[1][2]<<(MR_SPLINE_WORLD_SHIFT+1));
}


/******************************************************************************
*%%%% MRCalculateBsplinePoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateBsplinePoint(
*						MR_BSPLINE*	bspline,
*						MR_LONG		t,
*						MR_SVEC*	point)
*
*	FUNCTION	Calculates the point on a spline at parameter t
*
*	INPUTS		bspline		-	ptr to MR_BSPLINE
*				t			-	value of spline parameter
*								(0 <= t <= ((1 << MR_SPLINE_PARAM_SHIFT) * number of segments))
*				point		-	ptr to point to fill
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateBsplinePoint(MR_BSPLINE*	bspline,
								MR_LONG		t,
								MR_SVEC*	point)
{
	MR_USHORT	segment;
	MR_LONG		st;


	// Work out segment and fractional param
	segment	= t >> MR_SPLINE_PARAM_SHIFT;
	st		= t & (MR_SPLINE_PARAM_ONE - 1);

	if (bspline->bs_flags & MR_SPLINE_MULTIPLE_MATRICES)
		{
		// We have already calculated a matrix for each set of 4 points, so just read the point
		MRCalculateSplinePoint(bspline->bs_matrices + segment, st, point);
		}
	else
		{
		// We may need to calculate a new matrix
		if (segment != bspline->bs_matrix_index)
			{
			MRCalculateBsplineMatrix((MR_SPLINE_BEZIER*)(bspline->bs_points + segment), bspline->bs_matrices);
			bspline->bs_matrix_index = segment;
			}
		MRCalculateSplinePoint(bspline->bs_matrices, st, point);
		}
}


/******************************************************************************
*%%%% MRCalculateSplineBezierArrayPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineBezierArrayPoint(
*						MR_SPLINE_BEZIER_ARRAY*	array,
*						MR_LONG					t,
*						MR_SVEC*				point)
*
*	FUNCTION	Calculates the point on a spline at parameter t
*
*	INPUTS		array	-	ptr to MR_SPLINE_BEZIER_ARRAY
*				t		-	value of spline parameter
*							(0 <= t <= ((1 << MR_SPLINE_PARAM_SHIFT) * number of beziers))
*				point	-	ptr to point to fill
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineBezierArrayPoint(	MR_SPLINE_BEZIER_ARRAY*	array,
											MR_LONG					t,
											MR_SVEC*				point)
{
	MR_USHORT	bezier;
	MR_LONG		st;


	// Work out segment and fractional param
	bezier	= t >> MR_SPLINE_PARAM_SHIFT;
	st		= t & (MR_SPLINE_PARAM_ONE - 1);

	if (array->sb_flags & MR_SPLINE_MULTIPLE_MATRICES)
		{
		// We have already calculated a matrix for each set of 4 points, so just read the point
		MRCalculateSplinePoint(array->sb_matrices + bezier, st, point);
		}
	else
		{
		// We may need to calculate a new matrix
		if (bezier != array->sb_matrix_index)
			{
			MRCalculateSplineBezierMatrix(array->sb_beziers + bezier, array->sb_matrices);
			array->sb_matrix_index = bezier;
			}
		MRCalculateSplinePoint(array->sb_matrices, st, point);
		}
}


/******************************************************************************
*%%%% MRCalculateSplineHermitePointDirectly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineHermitePointDirectly(
*						MR_SPLINE_HERMITE*	spline,
*						MR_LONG				t,
*						MR_SVEC*			point)
*
*	FUNCTION	Calculates the point on a spline at parameter t directly (uses no
*				coefficient matrix)
*
*	INPUTS		spline		-	ptr to spline control data
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to point to fill
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*				Multiplies:	9
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineHermitePointDirectly(	MR_SPLINE_HERMITE*	spline,
   												MR_LONG				t,
   												MR_SVEC*			point)
{
	MR_LONG	a, b, c, d;
	MR_SVEC	u, v;
	MR_VEC	U, V;


	MR_ASSERT(spline);
	MR_ASSERT(point);

	u.vx = spline->sh_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sh_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sh_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = spline->sh_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	v.vy = spline->sh_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	v.vz = spline->sh_p4.vz >> MR_SPLINE_WORLD_SHIFT;

	U.vx = spline->sh_r1.vx >> MR_SPLINE_WORLD_SHIFT;
	U.vy = spline->sh_r1.vy >> MR_SPLINE_WORLD_SHIFT;
	U.vz = spline->sh_r1.vz >> MR_SPLINE_WORLD_SHIFT;

	V.vx = spline->sh_r4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sh_r4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sh_r4.vz >> MR_SPLINE_WORLD_SHIFT;

	// Want ((at + b)t + c)t + d
	a = (2*u.vx) - (2*v.vx) + (U.vx) + (V.vx);
	b = -a - u.vx + v.vx - U.vx;
	c = (U.vx);
	d = (u.vx);

	point->vx = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = (2*u.vy) - (2*v.vy) + (U.vy) + (V.vy);
	b = -a - u.vy + v.vy - U.vy;
	c = (U.vy);
	d = (u.vy);

	point->vy = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = (2*u.vz) - (2*v.vz) + (U.vz) + (V.vz);
	b = -a - u.vz + v.vz - U.vz;
	c = (U.vz);
	d = (u.vz);

	point->vz = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);
}


/******************************************************************************
*%%%% MRCalculateSplineBezierPointDirectly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateSplineBezierPointDirectly(
*						MR_SPLINE_BEZIER*	spline,
*						MR_LONG				t,
*						MR_SVEC*			point)
*
*	FUNCTION	Calculates the point on a spline at parameter t directly (uses no
*				coefficient matrix)
*
*	INPUTS		spline		-	ptr to spline control data
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to point to fill
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*				Multiplies:	18
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateSplineBezierPointDirectly(	MR_SPLINE_BEZIER*	spline,
												MR_LONG				t,
												MR_SVEC*			point)
{
	MR_LONG	a, b, c, d;
	MR_SVEC	u, v;
	MR_VEC	U, V;


	MR_ASSERT(spline);
	MR_ASSERT(point);

	u.vx = spline->sb_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sb_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sb_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = (spline->sb_p2.vx >> MR_SPLINE_WORLD_SHIFT) * 3;
	v.vy = (spline->sb_p2.vy >> MR_SPLINE_WORLD_SHIFT) * 3;
	v.vz = (spline->sb_p2.vz >> MR_SPLINE_WORLD_SHIFT) * 3;

	U.vx = (spline->sb_p3.vx >> MR_SPLINE_WORLD_SHIFT) * 3;
	U.vy = (spline->sb_p3.vy >> MR_SPLINE_WORLD_SHIFT) * 3;
	U.vz = (spline->sb_p3.vz >> MR_SPLINE_WORLD_SHIFT) * 3;

	V.vx = spline->sb_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sb_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sb_p4.vz >> MR_SPLINE_WORLD_SHIFT;

	// Want ((at + b)t + c)t + d
	a = -(u.vx) + (v.vx) - (U.vx) + (V.vx);
	d = (u.vx);
	u.vx *= 3;
	b = (u.vx) - (2*v.vx) + (U.vx);
	c = -(u.vx) + (v.vx);

	point->vx = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = -(u.vy) + (v.vy) - (U.vy) + (V.vy);
	d = (u.vy);
	u.vy *= 3;
	b = (u.vy) - (2*v.vy) + (U.vy);
	c = -(u.vy) + (v.vy);

	point->vy = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = -(u.vz) + (v.vz) - (U.vz) + (V.vz);
	d = (u.vz);
	u.vz *= 3;
	b = (u.vz) - (2*v.vz) + (U.vz);
	c = -(u.vz) + (v.vz);

	point->vz = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);
}


/******************************************************************************
*%%%% MRCalculateBsplinePointDirectly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateBsplinePointDirectly(
*						MR_SPLINE_BEZIER*	spline,
*						MR_LONG				t,
*						MR_SVEC*			point)
*
*	FUNCTION	Calculates the point on a spline at parameter t directly (uses no
*				coefficient matrix)
*
*	INPUTS		spline		-	ptr to spline control data
*				t			-	value of spline parameter (0 <= t <= (1 << MR_SPLINE_PARAM_SHIFT))
*				point		-	ptr to point to fill
*
*	NOTES		The points read off will be in a "world" of radius 0x1000 units.
*				These are scaled to a "world" of 0x8000 units.
*				Multiplies:	9
*				Divides:	6
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateBsplinePointDirectly(MR_SPLINE_BEZIER*	spline,
										MR_LONG				t,
										MR_SVEC*			point)
{
	MR_LONG	a, b, c, d;
	MR_SVEC	u, v;
	MR_VEC	U, V;


	MR_ASSERT(spline);
	MR_ASSERT(point);

	u.vx = spline->sb_p1.vx >> MR_SPLINE_WORLD_SHIFT;
	u.vy = spline->sb_p1.vy >> MR_SPLINE_WORLD_SHIFT;
	u.vz = spline->sb_p1.vz >> MR_SPLINE_WORLD_SHIFT;

	v.vx = spline->sb_p2.vx >> MR_SPLINE_WORLD_SHIFT;
	v.vy = spline->sb_p2.vy >> MR_SPLINE_WORLD_SHIFT;
	v.vz = spline->sb_p2.vz >> MR_SPLINE_WORLD_SHIFT;

	U.vx = spline->sb_p3.vx >> MR_SPLINE_WORLD_SHIFT;
	U.vy = spline->sb_p3.vy >> MR_SPLINE_WORLD_SHIFT;
	U.vz = spline->sb_p3.vz >> MR_SPLINE_WORLD_SHIFT;

	V.vx = spline->sb_p4.vx >> MR_SPLINE_WORLD_SHIFT;
	V.vy = spline->sb_p4.vy >> MR_SPLINE_WORLD_SHIFT;
	V.vz = spline->sb_p4.vz >> MR_SPLINE_WORLD_SHIFT;

	// Want ((at + b)t + c)t + d
	a = ((-u.vx + V.vx) / 6) + ((v.vx - U.vx) >> 1);
	b = ((u.vx + U.vx) >> 1) - v.vx;
	c = ((-u.vx + U.vx) >> 1);
	d = (u.vx + (v.vx << 2) + U.vx) / 6;

	point->vx = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = ((-u.vy + V.vy) / 6) + ((v.vy - U.vy) >> 1);
	b = ((u.vy + U.vy) >> 1) - v.vy;
	c = ((-u.vy + U.vy) >> 1);
	d = (u.vy + (v.vy << 2) + U.vy) / 6;

	point->vy = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);

	a = ((-u.vz + V.vz) / 6) + ((v.vz - U.vz) >> 1);
	b = ((u.vz + U.vz) >> 1) - v.vz;
	c = ((-u.vz + U.vz) >> 1);
	d = (u.vz + (v.vz << 2) + U.vz) / 6;

	point->vz = ((((((((a * t) + (b << MR_SPLINE_PARAM_SHIFT)) >> MR_SPLINE_T2_SHIFT) * t) + (c << (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_T2_SHIFT))) >> MR_SPLINE_PARAM_SHIFT) * t) >> (MR_SPLINE_PARAM_SHIFT*2-MR_SPLINE_WORLD_SHIFT-MR_SPLINE_T2_SHIFT)) +
				(d << MR_SPLINE_WORLD_SHIFT);
}
