/******************************************************************************
*%%%% mr_math.c
*------------------------------------------------------------------------------
*
*	Maths functions
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	11.10.96	Tim Closs		Created
*	04.04.97	Dean Ashton		Added MRGenerateYXMatrixFromZColumn and 
*								MRGenerateMatrixFromZAxisAndZYPlane (moved from
*								mr_misc.*)
*
*%%%**************************************************************************/

#include	"mr_all.h"

/******************************************************************************
*%%%% MRIntersectInfiniteLineInfiniteLine2D
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	MRIntersectInfiniteLineInfiniteLine2D(
*						MR_SVEC*	p0,
*						MR_SVEC*	a0,
*						MR_SVEC*	p1,
*						MR_SVEC*	a1,
*						MR_SVEC*	result);
*
*	FUNCTION	Find intersection of two infinite lines in XY plane
*
*	INPUTS		p0			-	start pt 	of line 0
*				a0			-	direction 	of line 0
*				p1			-	start pt 	of line 1
*				a1			-	direction 	of line 1
*				result		-	intersection point (if any)
*
*	RESULT		TRUE if intersecting (not parallel), else FALSE
*
*	NOTES		If TRUE, result holds the intersection point
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_BOOL	MRIntersectInfiniteLineInfiniteLine2D(	MR_SVEC*	p0,
												MR_SVEC*	a0,
												MR_SVEC*	p1,
												MR_SVEC*	a1,
												MR_SVEC*	result)
{
	MR_LONG	n, d;

	// Test for intersection on line 0
	n	= (a1->vy * (p1->vx - p0->vx)) - (a1->vx * (p1->vy - p0->vy));
	d	= (a0->vx * a1->vy) - (a0->vy * a1->vx);

	// Intersection on line 0 if (0 <= (n/d) <= 1)
	if (
		(n == 0) ||
		((n < 0) && (d < 0) && (n >= d)) ||
		((n > 0) && (d > 0) && (n <= d))
		)
		{
		n = (n / (d >> 12));
		result->vx = p0->vx + ((a0->vx * n) >> 12);
		result->vy = p0->vy + ((a0->vy * n) >> 12);
		return(TRUE);	
		}

	// Test for intersection on line 1
	n	= (a0->vy * (p0->vx - p1->vx)) - (a0->vx * (p0->vy - p1->vy));
	d	= -d;

	// Intersection on line 1 if (0 <= (n/d) <= 1)
	if (
		(n == 0) ||
		((n < 0) && (d < 0) && (n >= d)) ||
		((n > 0) && (d > 0) && (n <= d))
		)
		{
		n = (n / (d >> 12));
		result->vx = p1->vx + ((a1->vx * n) >> 12);
		result->vy = p1->vy + ((a1->vy * n) >> 12);
		return(TRUE);	
		}
	return(FALSE);
}


/******************************************************************************
*%%%% MRIntersectInfiniteLineFiniteLine2D
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	MRIntersectInfiniteLineFiniteLine2D(
*						MR_SVEC*	p0,
*						MR_SVEC*	a0,
*						MR_SVEC*	p1,
*						MR_SVEC*	a1,
*						MR_SVEC*	result);
*
*	FUNCTION	Find intersection of infinite, finite lines in XY plane
*
*	INPUTS		p0			-	start pt 	of line 0
*				a0			-	direction 	of line 0
*				p1			-	start pt 	of line 1
*				a1			-	direction 	of line 1
*				result		-	intersection point (if any)
*
*	RESULT		TRUE if intersecting (not parallel), else FALSE
*
*	NOTES		If TRUE, result holds the intersection point
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_BOOL	MRIntersectInfiniteLineFiniteLine2D(MR_SVEC*	p0,
											MR_SVEC*	a0,
											MR_SVEC*	p1,
											MR_SVEC*	a1,
											MR_SVEC*	result)
{
	MR_LONG	n, d;


	// Test for intersection on line 1 (finite line)
	n	= (a0->vy * (p0->vx - p1->vx)) - (a0->vx * (p0->vy - p1->vy));
	d	= (a1->vx * a0->vy) - (a1->vy * a0->vx);

	// Intersection on line 1 if (0 <= (n/d) <= 1)
	if (
		(n == 0) ||
		((n < 0) && (d < 0) && (n >= d)) ||
		((n > 0) && (d > 0) && (n <= d))
		)
		{
		n = (n / (d >> 12));
		result->vx = p1->vx + ((a1->vx * n) >> 12);
		result->vy = p1->vy + ((a1->vy * n) >> 12);
		return(TRUE);	
		}
	return(FALSE);
}


/******************************************************************************
*%%%% MRIntersectFiniteLineFiniteLine2D
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	MRIntersectFiniteLineFiniteLine2D(
*						MR_SVEC*	p0,
*						MR_SVEC*	a0,
*						MR_SVEC*	p1,
*						MR_SVEC*	a1,
*						MR_SVEC*	result);
*
*	FUNCTION	Find intersection of two finite lines in XY plane
*
*	INPUTS		p0			-	start pt 	of line 0
*				a0			-	direction 	of line 0
*				p1			-	start pt 	of line 1
*				a1			-	direction 	of line 1
*				result		-	intersection point (if any)
*
*	RESULT		TRUE if intersecting (not parallel), else FALSE
*
*	NOTES		If TRUE, result holds the intersection point
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_BOOL	MRIntersectFiniteLineFiniteLine2D(	MR_SVEC*	p0,
									 		MR_SVEC*	a0,
									 		MR_SVEC*	p1,
									 		MR_SVEC*	a1,
									 		MR_SVEC*	result)
{
	MR_LONG	n, d;


	// Test for intersection on line 0
	n	= (a1->vy * (p1->vx - p0->vx)) - (a1->vx * (p1->vy - p0->vy));
	d	= (a0->vx * a1->vy) - (a0->vy * a1->vx);

	// Intersection on line 0 if (0 <= (n/d) <= 1)
	if (
		(n == 0) ||
		((n < 0) && (d < 0) && (n >= d)) ||
		((n > 0) && (d > 0) && (n <= d))
		)
		{
		// Test for intersection on line 1
		n	= (a0->vy * (p0->vx - p1->vx)) - (a0->vx * (p0->vy - p1->vy));
		d	= -d;

		// Intersection on line 1 if (0 <= (n/d) <= 1)
		if (
			(n == 0) ||
			((n < 0) && (d < 0) && (n >= d)) ||
			((n > 0) && (d > 0) && (n <= d))
			)
			{
			n = (n / (d >> 12));
			result->vx = p1->vx + ((a1->vx * n) >> 12);
			result->vy = p1->vy + ((a1->vy * n) >> 12);
			return(TRUE);	
			}
		}
	return(FALSE);
}


/******************************************************************************
*%%%% MRAngleBetweenLines
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	angle =	MRAngleBetweenLines(
*								MR_SVEC*	v0,
*								MR_SVEC*	v1);
*
*	FUNCTION	Returns the angle between two lines
*
*	INPUTS		v0		-	1st line vector
*				v1		-	2nd line vector
*
*	RESULT		angle	-	angle in the range 0x000..0x800 (0 to 180 degrees)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	MRAngleBetweenLines(MR_SVEC* v0,
							MR_SVEC* v1)
{
	MR_LONG	d, a;
	MR_VEC	n0, n1;


	MR_VEC_EQUALS_SVEC(&n0, v0);
	MR_VEC_EQUALS_SVEC(&n1, v1);
	MRNormaliseVEC(&n0, &n0);
	MRNormaliseVEC(&n1, &n1);
	
	d	= MR_VEC_DOT_VEC(&n0 ,&n1);
	a	= MAX(-4096, MIN(4095, d >> 12)) + 4096;
	a	= MRAcos_table[a];

	return(a);	
}


/******************************************************************************
*%%%% MRGenerateYXMatrixFromZColumn
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRGenerateYXMatrixFromZColumn(
*						MR_MAT*	matrix);
*
*	FUNCTION	Takes the direction of the Z column within the matrix, and then
*				changes the matrix into a rotation matrix which is assuming YX 
*				rotation only.
*
*	INPUTS		matrix		-		Pointer to a valid MR_MAT structure
*
*	NOTES		Why doesn't this output to a different matrix?
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRGenerateYXMatrixFromZColumn(MR_MAT* matrix)
{
	LONG	denom;

	SHORT	x;
	SHORT	y;
	SHORT	z;

	MR_ASSERT(matrix != NULL);

	x = matrix->m[0][2];
	y = matrix->m[1][2];
	z = matrix->m[2][2];

	if (denom = MR_SQRT(MR_SQR(x) + MR_SQR(z)))
		{
		matrix->m[0][0] = ((z << 18) / denom) >> 6;
		matrix->m[0][1] = ((-x*y << 6) / denom) >> 6;
		matrix->m[1][0] = 0;
		matrix->m[1][1] = denom;
		matrix->m[2][0] = ((-x << 18) / denom) >> 6;
		matrix->m[2][1] = ((-y*z << 6) / denom) >> 6; 
		}
	else
		{
		if (y > 0)
			{
			// cos theta = 0, sin theta < 0, so theta = -90
			matrix->m[0][0] = 0;
			matrix->m[0][1] = -0x1000;
			matrix->m[1][0] = 0;
			matrix->m[1][1] = 0;
			matrix->m[2][0] = 0x1000;
			matrix->m[2][1] = 0;
			}
		else
			{
			// cos theta = 0, sin theta > 0, so theta = +90
			matrix->m[0][0] = 0;
			matrix->m[0][1] = 0x1000;
			matrix->m[1][0] = 0;
			matrix->m[1][1] = 0;
			matrix->m[2][0] = -0x1000;
			matrix->m[2][1] = 0;
			}
		}
}


/******************************************************************************
*%%%% MRGenerateMatrixFromZAxisAndZYPlane
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRGenerateMatrixFromZAxisAndZYPlane(
*						MR_MAT* matrix,
*						MR_VEC* z,
*						MR_VEC* y)
*
*	FUNCTION	Generates a square matrix.  Z column is z axis.  X column is outer
*				product of Z, Y axes.  Y column is then outer product of Z, X axes
*
*	INPUTS		matrix	-	ptr to matrix to generate
*				z		-	ptr to z direction
*				y		-	ptr to y direction
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRGenerateMatrixFromZAxisAndZYPlane(MR_MAT* matrix,
											MR_VEC* z,
											MR_VEC* y)
{
	MR_VEC	nx, ny;

	MROuterProduct12(y, z, &nx);
	// y, z not nec. perp, so need to normalise result
	matrix->m[0][2] = z->vx;
	matrix->m[1][2] = z->vy;
	matrix->m[2][2] = z->vz;

	MRNormaliseVEC(&nx, &nx);

	MROuterProduct12(z, &nx, &ny);

	matrix->m[0][0] = nx.vx;
	matrix->m[1][0] = nx.vy;
	matrix->m[2][0] = nx.vz;
	matrix->m[0][1] = ny.vx;
	matrix->m[1][1] = ny.vy;
	matrix->m[2][1] = ny.vz;
}









									 
