/******************************************************************************
*%%%% misc.c
*------------------------------------------------------------------------------
*
*	Miscellaneous geometry functions, etc
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "misc.h"
#include "gamesys.h"


/******************************************************************************
*%%%% WriteAxesAsMatrix
*------------------------------------------------------------------------------
* 
*	SYNOPSIS	MR_VOID	WriteAxesAsMatrix(
*						MR_MAT*	matrix,
*						MR_VEC*	axis_x,
*						MR_VEC*	axis_y,
*						MR_VEC*	axis_z)
*
*	FUNCTION	Write the columns of a matrix from 3 vectors
*
*	INPUTS		matrix	-	matrix to write
*				axis_x	-	local x axis
*				axis_y	-	local y axis
*				axis_z	-	local z axis
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	WriteAxesAsMatrix(	MR_MAT*	matrix,
							MR_VEC*	axis_x,
							MR_VEC*	axis_y,
							MR_VEC*	axis_z)
{
	matrix->m[0][0] = axis_x->vx;
	matrix->m[1][0] = axis_x->vy;
	matrix->m[2][0] = axis_x->vz;
	matrix->m[0][1] = axis_y->vx;
	matrix->m[1][1] = axis_y->vy;
	matrix->m[2][1] = axis_y->vz;
	matrix->m[0][2] = axis_z->vx;
	matrix->m[1][2] = axis_z->vy;
	matrix->m[2][2] = axis_z->vz;
}


/******************************************************************************
*%%%% GetWorldYQuadrantFromMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG quadrant =	GetWorldYQuadrantFromMatrix(
*									MR_MAT*	matrix)
*
*	FUNCTION	Calculate the quadrant in the XZ plane of a matrix
*
*	INPUTS		matrix		-	to get quadrant from
*
*	RESULT		quadrant	-	0..3
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	GetWorldYQuadrantFromMatrix(MR_MAT*	matrix)
{
	MR_ASSERT(matrix);


	if (abs(matrix->m[2][2]) > abs(matrix->m[0][2]))
		{
		if (matrix->m[2][2] > 0)
			{
			return(0);
			}
		else
			{
			return(2);
			}
		}
	else
		{
		if (matrix->m[0][2] > 0)
			{
			return(1);
			}
		else
			{
			return(3);
			}
		}
}


/******************************************************************************
*%%%% SetMatrixToWorldYQuadrant
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	quadrant =	SetMatrixToWorldYQuadrant(
*									MR_MAT*	matrix)
*
*	FUNCTION	Calculate the quadrant in the XZ plane of a matrix, and set
*				the matrix to a Y rotation of that quadrant
*
*	INPUTS		matrix		-	to get quadrant from
*
*	RESULT		quadrant	-	0..3
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	SetMatrixToWorldYQuadrant(MR_MAT*	matrix)
{
	MR_LONG	i, cos, sin;


	i 				= GetWorldYQuadrantFromMatrix(matrix);
	cos				= rcos(i * 0x400);
	sin				= rsin(i * 0x400);
	matrix->m[0][0] = cos;
	matrix->m[0][1] = 0;
	matrix->m[0][2] = sin;
	matrix->m[1][0] = 0;
	matrix->m[1][1] = 0x1000;
	matrix->m[1][2] = 0;
	matrix->m[2][0] = -sin;
	matrix->m[2][1] = 0;
	matrix->m[2][2] = cos;
}


/******************************************************************************
*%%%% ProjectMatrixOntoWorldXZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ProjectMatrixOntoWorldXZ(
*						MR_MAT*	matrix,
*						MR_MAT*	result)
*
*	FUNCTION	Project a rotation matrix into a rotation about world Y
*
*	INPUTS		matrix	-	ptr to matrix to project
*				result	-	ptr to result matrix
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ProjectMatrixOntoWorldXZ(	MR_MAT*	matrix,
									MR_MAT*	result)
{
	MR_VEC	vec_z, vec_x;

	
	vec_z.vx = matrix->m[0][2];
	vec_z.vy = 0;
	vec_z.vz = matrix->m[2][2];
	MRNormaliseVEC(&vec_z, &vec_z);
	MROuterProduct12(&Game_y_axis_pos, &vec_z, &vec_x);		
	MRNormaliseVEC(&vec_x, &vec_x);
	WriteAxesAsMatrix(result, &vec_x, &Game_y_axis_pos, &vec_z);
}
				
	
