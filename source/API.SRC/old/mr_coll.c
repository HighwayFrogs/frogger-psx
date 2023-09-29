/******************************************************************************
*%%%% mr_coll.c
*------------------------------------------------------------------------------
*
*	Basic collision routines 
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Tim Closs		Created
*	09.07.96	Tim Closs		MRPointToFrustrumCollision now returns OR of
*								flags. MRPointToFrustrumCollisionNoXY was named
*								wrongly in header.
*	15.07.96	Tim Closs		Changed 'MRReturnNormalToIntersectionPlane...' to
*								'MRReflectVectorInIntersectionPlane...' and added
*								MR_COLL_UNSTABLE equate (0xBABE)
*	26.07.96	Tim Closs		OuterProduct0 changed to MROuterProduct
*	25.09.96	Tim Closs		Removed MRColl_matrix_ptr from fastram
*								Added MRColl_lw_ptr and new cp_matrix functionality
*								to allow collprims not aligned to frame axes.  All
*								functions now accept static frames.  Functions which
*								check against lists now bail out if they fail on
*								a collprim flagged as MR_COLL_BOUNDING
*	10.10.96	Tim Closs		MRCheckCollPrimWithWorldPoint() now accepts frame input
*								MRCheckCollPrimsWithWorldPointAndFrame() renamed to
*								MRCheckCollPrimsWithWorldPoint()
*								MRReflectVectorInIntersectionPlane() now accepts frame input,
*								renamed to MRReflectVectorInCollPrim()
*								MRReflectVectorInIntersectionPlaneAndFrame() removed
*								Added	MRCheckBoundingBoxWithWorldPoint()
*								Added	MRReflectVectorInBoundingBox()
*								Many bugs fixed!
*	04.12.96	Tim Closs		MRReflectVectorInCollPrim now accepts reflection
*								normal ptr.  Returned reflection normal and
*								reflected vector now both point AWAY from the prim
*	14.01.97	Tim Closs		Fixed bug in MRCheckBoundingBoxWithWorldPoint()
*	05.02.97	Tim Closs		Fixed TransposeMatrix bug in
*								MRCheckCollPrim(s)WithWorldPoint()
*								Fixed reflection direction bug in 
*								MRReflectVectorInCollPrim()
*	12.02.97	Tim Closs		MRCheckCollPrimWithWorldPoint() REWRITEEN
*								MRCheckBoundingBoxWithWorldPoint() REWRITEEN
*								Added MRCollisionCheck()
*	13.02.97	Tim Closs		MRCheckCollPrimWithWorldPoint() - fixed return(TRUE) bug
*	11.03.97	Tim Closs		Added support for MR_COLLCHECK_C_POINT
*								MRCollisionCheck() now writes out mc_c_item_a/b
*								Removed:
*								MRCheckCollPrimsWithWorldPoint()
*								MRReflectVectorInCollPrim()
*								MRPointToFrustrumCollision()
*								MRPointToFrustrumCollisionNoXY()
*								MRReflectVectorInBoundingBox()
*	13.03.97	Tim Closs		Functions now respect collision face flags
*	14.03.97	Tim Closs		References to MRApplyRotMatrix(VEC) now MUST
*								have set up the rotation matrix explicitly with
*								gte_SetRotMatrix()
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix in
*								MRCheckCollPrimWithWorldPoint() and
*								MRCheckBoundingBoxWithWorldPoint()
*	20.03.97	Tim Closs		MRCheckCollPrimWithWorldPoint() now sets
*								MR_COLLCHECK_C_NO_OUTPUT if both ends of
*								line are inside volume (or relative motion is 0)
*	11.04.97	Tim Closs		Fixed hilites in multiple parts bug in
*								MRCollisionCheck()
*	10.06.97	Dean Ashton		Added support for MR_COLL_DISABLED flag
*	25.06.97	Tim Closs		MRCollisionCheck() - added support for MR_ANIM_ENV_FLIPBOOK
*								
*%%%**************************************************************************/

#include "mr_all.h"


MR_MAT*	MRColl_lw_ptr;
MR_MAT*	MRColl_matrix_ptr;

MR_MAT	MRColl_transmatrix;
MR_SVEC	MRColl_transpt;


/******************************************************************************
*%%%% MRCreateCollPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_COLLPRIM coll_ptr =	MRCreateCollPrim(
*										MR_USHORT	type,
*										MR_USHORT	flags,
*										MR_FRAME*	frame,
*										MR_MAT*		matrix);	
*
*	FUNCTION	Creates and initialises a collision primitive for use by the 
*				specified object/frame.
*
*	INPUTS		type		-	Collision type (eg. Cylinder)
*				flags		-	Eg. deadly
*				frame		-	Pointer to MR_FRAME to place collision
*							 	volume in
*				object		-	Pointer to MR_OBJECT which owns the
*							 	created collision primitive
*
*	RESULT		coll_ptr	-	Pointer to created collision primitive
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	25.09.96	Tim Closs		4th parameter is now cp_matrix.  cp_object set up
*								as NULL
*
*%%%**************************************************************************/

MR_COLLPRIM* MRCreateCollPrim(	MR_USHORT	type,
								MR_USHORT	flags,
								MR_FRAME*	frame,
								MR_MAT*		matrix)
{
	MR_COLLPRIM*	coll_ptr;

	MR_ASSERT(frame != NULL);
	MR_ASSERT(matrix != NULL);

	coll_ptr 			= MRAllocMem(sizeof(MR_COLLPRIM), "COLLPRIM");

	coll_ptr->cp_type	= type;
	coll_ptr->cp_flags	= flags;
	coll_ptr->cp_frame	= frame;
	coll_ptr->cp_object	= NULL;
	coll_ptr->cp_matrix	= matrix;

	MR_CLEAR_SVEC(&coll_ptr->cp_offset);

	return(coll_ptr);
}


/******************************************************************************
*%%%% MRKillCollPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillCollPrim(
*						MR_COLLPRIM*	coll_ptr);
*
*	FUNCTION	Destroys a collision primitive
*
*	INPUTS		coll_ptr	-	Pointer to a valid MR_COLLPRIM structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillCollPrim(MR_COLLPRIM* coll_ptr)
{
	MR_ASSERT(coll_ptr != NULL);
	
	MRFreeMem(coll_ptr);
}


/******************************************************************************
*%%%% MRCheckCollPrimWithWorldPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	collided =	MRCheckCollPrimWithWorldPoint(
*									MR_COLLPRIM*	coll,
*									MR_SVEC*			point,
*									MR_MAT*			matrix,	
*									MR_COLLCHECK*	collcheck)
*
*	FUNCTION	Checks if a world point is inside a collision volume
*
*	INPUTS		coll 		-	ptr to a valid collision primitive
*				point		-	ptr to an MR_SVEC containing the points
*					 			position within the world
*				matrix		-	NULL if using collprim's cp_frame, else ptr to
*					 			LW transform for collprim
*				collcheck	-	if non-NULL, this is used to store various results
*
*	RESULT		collided	-	TRUE if in collision, else FALSE
*
*	NOTES		This has been optimised in the following ways: the function only
*				calculates the global transpose matrix if the collprim points to
*				matrix different from the previous one.  The function only
*				recalculates the transformed point if this is the case also.
*				However, the function always adds the collprim offset to the
*				transformed point.
*
*				MR_COLL_STATIC is only relevant if we are NOT specifying our own
*				LW transform for the collprim
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	25.09.96	Tim Closs		Now accepts cp_matrix
*	10.10.96	Tim Closs		Now accepts frame pointer
*	05.02.97	Tim Closs		Fixed TransposeMatrix bug
*	11.02.97	Tim Closs		Now takes matrix, collcheck inputs
*	13.02.97	Tim Closs		Fixed return(TRUE) bug
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix
*	20.03.97	Tim Closs		Now sets MR_COLLCHECK_C_NO_OUTPUT if both ends of
*								line are inside volume (or relative motion is 0)
*	10.06.97	Dean Ashton		Added support for MR_COLL_DISABLED flag
*
*%%%**************************************************************************/

MR_BOOL	MRCheckCollPrimWithWorldPoint(	MR_COLLPRIM* 	coll,
										MR_SVEC* 		point,
										MR_MAT*			matrix,	
										MR_COLLCHECK*	collcheck)
{
	MR_VEC		transpt;	// will become point in collprim's frame
	MR_MAT*		lw_ptr;
	MR_VEC		a, o, p;
	MR_LONG		dot, l;
	MR_LONG		av, tv, l2, index;
	MR_USHORT	cv;
	MR_LONG*	av_ptr;
	MR_LONG*	tv_ptr;
	MR_SVEC		svec;
	MR_MAT		transpose;


	MR_ASSERT(coll);
	MR_ASSERT(point);

	// If collision primitive is disabled, then bail.
	if (coll->cp_flags & MR_COLL_DISABLED)
		return(FALSE);

	if (matrix)
		lw_ptr = matrix;
	else
		{
		MR_ASSERT(coll->cp_frame);
		if (coll->cp_flags & MR_COLL_STATIC)
			lw_ptr = (MR_MAT*)coll->cp_frame;
		else
			lw_ptr = &coll->cp_frame->fr_lw_transform;
		}

	// Get pointers to cp_frame (A) and cp_matrix (B).  If either of these have changed since the last
	// collision check, we need to rebuild the MRColl_transmatrix, which is BtAt (B transpose A transpose) which
	// is (AB)t (AB transpose).
	if (coll->cp_type == MR_COLLPRIM_SPHERE)
		{
		if (MRColl_lw_ptr	!= lw_ptr)
			{
			MRColl_lw_ptr = lw_ptr;
			MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
			}
		}
	else
	if (
		(MRColl_lw_ptr 		!= lw_ptr) ||
		(MRColl_matrix_ptr	!= coll->cp_matrix)
		)
		{
		MRColl_lw_ptr = lw_ptr;
		if (MRColl_matrix_ptr = coll->cp_matrix)
			{
			MRMulMatrixABC(MRColl_lw_ptr, MRColl_matrix_ptr, &MRTemp_matrix);
			MRTransposeMatrix(&MRTemp_matrix, &MRColl_transmatrix);
			}
		else
			MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
		}
	
	// MRColl_transmatrix will now transform a point in the world into the collprim's axes
	//
	// Note that the cp_offset vector is always specified in the axes of the frame
	MRApplyMatrix(MRColl_lw_ptr, &coll->cp_offset, &transpt);
	MRColl_transpt.vx = point->vx - MRColl_lw_ptr->t[0] - transpt.vx;
	MRColl_transpt.vy = point->vy - MRColl_lw_ptr->t[1] - transpt.vy;
	MRColl_transpt.vz = point->vz - MRColl_lw_ptr->t[2] - transpt.vz;
	gte_SetRotMatrix(&MRColl_transmatrix);
	MRApplyRotMatrix(&MRColl_transpt, &transpt);

	switch(coll->cp_type)
		{
		case MR_COLLPRIM_SPHERE:
			if (MR_VEC_MOD_SQR(&transpt) < coll->cp_radius2)
				{
				// Collision with sphere.  Store results
				if (collcheck)
					{
					if (collcheck->mc_c_flags & MR_COLLCHECK_C_FACE)
						{
						// If the relative_motion vector is zero, bail our because we won't be able to find an intersection face
						if (!(collcheck->mc_relative_motion.vx | collcheck->mc_relative_motion.vy | collcheck->mc_relative_motion.vz))
							goto collision_no_output;

						MRTransposeMatrix(&MRColl_transmatrix, &transpose);

						collcheck->mc_c_face = MR_COLLPRIM_FACE_SPHERE;
						if (
							(collcheck->mc_c_flags & MR_COLLCHECK_C_POINT) ||
							(collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
							)
							{
							// Calculate intersection point on sphere surface
							a.vx	= collcheck->mc_relative_motion.vx - MRColl_transpt.vx;
							a.vy	= collcheck->mc_relative_motion.vy - MRColl_transpt.vy;
							a.vz	= collcheck->mc_relative_motion.vz - MRColl_transpt.vz;
							// a is vector from old point to sphere origin
							l 		= MR_VEC_MOD_SQR(&a);
							if (l < coll->cp_radius2)
								{
								// Whoops! Start AND end point of line are inside sphere - bail out
								goto collision_no_output;
								}							
							MR_VEC_EQUALS_SVEC(&o, &collcheck->mc_relative_motion);
							MRNormaliseVEC(&o, &o);
							dot	= MR_VEC_DOT_VEC(&o, &a) >> 8;	// needs further >> 4 in future reference
							tv		= MR_SQR(dot) >> 8;
							dot	>>= 4;
							tv		= coll->cp_radius2 - (l - tv);
							tv		= MR_SQRT(tv);
							// Calculate intersection point
							p.vx = point->vx - collcheck->mc_relative_motion.vx + (((dot - tv) * o.vx) >> 12);
							p.vy = point->vy - collcheck->mc_relative_motion.vy + (((dot - tv) * o.vy) >> 12);
							p.vz = point->vz - collcheck->mc_relative_motion.vz + (((dot - tv) * o.vz) >> 12);
							if (collcheck->mc_c_flags & MR_COLLCHECK_C_POINT)
								{
								MR_SVEC_EQUALS_VEC(&collcheck->mc_c_point, &p);
								}
							if (collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
								{
								// This becomes reflection normal
								transpt.vx = p.vx + MRColl_transpt.vx - point->vx;
								transpt.vy = p.vy + MRColl_transpt.vy - point->vy;
								transpt.vz = p.vz + MRColl_transpt.vz - point->vz;
								MRNormaliseVECToSVEC(&transpt, &svec);
								gte_SetRotMatrix(&MRColl_transmatrix);
								MRApplyRotMatrix(&svec, &transpt);

								// Calculate reflection normal
								MRApplyRotMatrix(&collcheck->mc_relative_motion, &a);
								dot 		= MR_VEC_DOT_VEC(&a, &transpt) >> 11;
								svec.vx 	= a.vx - ((dot * transpt.vx) >> 12);
								svec.vy 	= a.vy - ((dot * transpt.vy) >> 12);
								svec.vz 	= a.vz - ((dot * transpt.vz) >> 12);
								gte_SetRotMatrix(&transpose);
								MRApplyRotMatrix(&svec,	&collcheck->mc_c_reflection_vector);
								MR_SVEC_EQUALS_VEC(&svec, &transpt);
								MRApplyRotMatrix(&svec,	&collcheck->mc_c_reflection_normal);
								}
							}
						}
					}
				return(TRUE);
				}
			else
				return(FALSE);
			break;

		case MR_COLLPRIM_CYLINDER_X:
		case MR_COLLPRIM_CYLINDER_Y:
		case MR_COLLPRIM_CYLINDER_Z:
			tv_ptr	= ((MR_LONG*)&transpt) + (coll->cp_type - MR_COLLPRIM_CYLINDER_X);
			tv 		= *tv_ptr;
			*tv_ptr	= 0;
			cv 		= ((MR_USHORT*)&coll->cp_xlen)[coll->cp_type - MR_COLLPRIM_CYLINDER_X];

			if (
				(MR_VEC_MOD_SQR(&transpt) < coll->cp_radius2) &&
				(abs(tv) < cv)
				)
				{
				// Collision with cylinder.  Store results
				if (collcheck)
					{
					if (collcheck->mc_c_flags & MR_COLLCHECK_C_FACE)
						{
						// If the relative_motion vector is zero, bail our because we won't be able to find an intersection face
						if (!(collcheck->mc_relative_motion.vx | collcheck->mc_relative_motion.vy | collcheck->mc_relative_motion.vz))
							goto collision_no_output;

						MRApplyRotMatrix(&collcheck->mc_relative_motion, &a);
						MRApplyRotMatrix(&MRColl_transpt, &transpt);
						MR_SUB_VEC(&transpt, &a);

						MRTransposeMatrix(&MRColl_transmatrix, &transpose);

						// transpt is now the OLD point in collprim coords
						av_ptr 	= ((MR_LONG*)&a) + (coll->cp_type - MR_COLLPRIM_CYLINDER_X);
						av		= *av_ptr;
						tv 		= *tv_ptr;
						*tv_ptr	= 0;
						if (
							((!(coll->cp_flags & MR_COLL_NO_FACE_END_NEG)) &&
							((av < 0)&&((tv + cv) >= 0)&&((tv + cv) < -av)) ||		// -ve normal (NEG face)
							((av > 0)&&((tv + cv) <= 0)&&((tv + cv) > -av))
							) ||
							((!(coll->cp_flags & MR_COLL_NO_FACE_END_POS)) &&
							((av > 0)&&((cv - tv) >= 0)&&((cv - tv) < av)) ||		// +ve normal (POS face)
							((av < 0)&&((cv - tv) <= 0)&&((cv - tv) > av))
							)
							)
							// Intersection with finite line and infinite end plane: check against (circular) face bounds
							{
							if (tv > 0)
								l = ((tv - cv) << 12) / -av;
							else
								l = ((tv + cv) << 12) / -av;
			
							*av_ptr = 0;
							if (MR_SQR(transpt.vx + ((l * a.vx) >> 12)) + MR_SQR(transpt.vy + ((l * a.vy) >> 12)) + MR_SQR(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_radius2)
								{
								// Collided with end face
								if (tv > 0)
									dot = 0;
								else
									dot = 1;

								collcheck->mc_c_face = MR_COLLPRIM_FACE_CYLINDER_X_POS + l + ((coll->cp_type - MR_COLLPRIM_CYLINDER_X) << 1);

								if (collcheck->mc_c_flags & MR_COLLCHECK_C_POINT)
									{
									svec.vx = transpt.vx + ((l * a.vx) >> 12);
									svec.vy = transpt.vy + ((l * a.vy) >> 12);
									svec.vz = transpt.vz + ((l * a.vz) >> 12);
									((MR_SHORT*)&svec.vx)[coll->cp_type - MR_COLLPRIM_CYLINDER_X] = cv - (2 * cv * dot);
									MRApplyMatrix(&transpose, &svec, &o);
									collcheck->mc_c_point.vx = o.vx - MRColl_transpt.vx + point->vx;
									collcheck->mc_c_point.vy = o.vy - MRColl_transpt.vy + point->vy;
									collcheck->mc_c_point.vz = o.vz - MRColl_transpt.vz + point->vz;
									}
								if (collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
									{
									MR_CLEAR_VEC(&transpt);
									((MR_LONG*)&transpt)[coll->cp_type - MR_COLLPRIM_CYLINDER_X] =  0x1000 - (dot * 0x2000);
									*av_ptr = -av;
									goto cylinder_rotate_outputs;
									}
								break;
								}
							}
			
						// Collided with circular surface
						if	(coll->cp_flags & MR_COLL_NO_FACE_SURFACE)
							goto collision_no_output;

						collcheck->mc_c_face = MR_COLLPRIM_FACE_CYLINDER_CIRCLE;

						if (
							(collcheck->mc_c_flags & MR_COLLCHECK_C_POINT) ||
							(collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
							)
							{
							// No collision occurred with end faces

							// Calculate intersection point on circular surface
							svec.vx = collcheck->mc_relative_motion.vx - MRColl_transpt.vx;
							svec.vy = collcheck->mc_relative_motion.vy - MRColl_transpt.vy;
							svec.vz = collcheck->mc_relative_motion.vz - MRColl_transpt.vz;
							// svec is vector from old point to cylinder axis IN COLLPRIM FRAME
							gte_SetRotMatrix(&MRColl_transmatrix);
							MRApplyRotMatrix(&svec, &a);
							av			= *av_ptr;
							*av_ptr 	= 0;
							l 			= MR_VEC_MOD_SQR(&a);
							if (l < coll->cp_radius2)
								{
								// Whoops! Start AND end point of line are inside cylinder radius - bail out
								goto collision_no_output;
								}							

							MRApplyRotMatrix(&collcheck->mc_relative_motion, &o);
							((MR_LONG*)&o)[coll->cp_type - MR_COLLPRIM_CYLINDER_X] = 0;
							l2			= MR_VEC_MOD_SQR(&o);
							MRNormaliseVEC(&o, &o);
							// o is unit vector from old point to new IN COLLPRIM FRAME

							dot		= MR_VEC_DOT_VEC(&o, &a) >> 10;	// needs further >>2 in future reference
							tv		= MR_SQR(dot) >> 4;
							dot		>>= 2;
							tv		= coll->cp_radius2 - (l - tv);
							tv		= MR_SQRT(tv);

							// Calculate intersection point IN COLLPRIM FRAME
							// (dot - tv) is length along projected line to travel
							MRApplyRotMatrix(&collcheck->mc_relative_motion, &o);
							l2			= MR_SQRT(l2);
							*av_ptr		= av;
							svec.vx 	= -a.vx + (((dot - tv) * o.vx) / l2);
							svec.vy 	= -a.vy + (((dot - tv) * o.vy) / l2);
							svec.vz 	= -a.vz + (((dot - tv) * o.vz) / l2);
							  		  
							if (collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
								{
								// Intersection point becomes reflection normal
								MR_VEC_EQUALS_SVEC(&transpt, &svec);
								*tv_ptr = 0;
								MRNormaliseVEC(&transpt, &transpt);

								// Calculate reflection vector
								MRApplyMatrix(&MRColl_transmatrix, &collcheck->mc_relative_motion, &a);
								dot 	= MR_VEC_DOT_VEC(&a, &transpt) >> 11;
								a.vx 	= a.vx - ((dot * transpt.vx) >> 12);
								a.vy 	= a.vy - ((dot * transpt.vy) >> 12);
								a.vz 	= a.vz - ((dot * transpt.vz) >> 12);
								}
							if (collcheck->mc_c_flags & MR_COLLCHECK_C_POINT)
								{
								gte_SetRotMatrix(&transpose);
								MRApplyRotMatrix(&svec, &p);
								collcheck->mc_c_point.vx = p.vx - MRColl_transpt.vx + point->vx;
								collcheck->mc_c_point.vy = p.vy - MRColl_transpt.vy + point->vy;
								collcheck->mc_c_point.vz = p.vz - MRColl_transpt.vz + point->vz;
								}

						cylinder_rotate_outputs:
							gte_SetRotMatrix(&transpose);
							MR_SVEC_EQUALS_VEC(&svec, &a);
							MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_vector);
							MR_SVEC_EQUALS_VEC(&svec, &transpt);
							MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_normal);
							}
						}
					}	
				return(TRUE);
				}
			else
				return(FALSE);
			break;
			
		case MR_COLLPRIM_CUBOID:
			if (
				(abs(transpt.vx) < coll->cp_xlen) &&
				(abs(transpt.vy) < coll->cp_ylen) &&
				(abs(transpt.vz) < coll->cp_zlen)
				)
				{
				// Collision with cuboid.  Store results
				if (collcheck)
					{
					if (collcheck->mc_c_flags & MR_COLLCHECK_C_FACE)
						{
						// If the relative_motion vector is zero, bail our because we won't be able to find an intersection face
						if (!(collcheck->mc_relative_motion.vx | collcheck->mc_relative_motion.vy | collcheck->mc_relative_motion.vz))
							goto collision_no_output;

						MRApplyRotMatrix(&collcheck->mc_relative_motion, &a);
						MR_SUB_VEC(&transpt, &a);
						// transpt is now the OLD point in collprim coords

						MRTransposeMatrix(&MRColl_transmatrix, &transpose);

						// Try each of 6 faces in turn
						o.vx = -coll->cp_xlen;
						o.vy = -coll->cp_ylen;
						o.vz = -coll->cp_zlen;
						// o is one corner of cuboid - try normals in -ve x,y,z resp:
						//
						// 1. normal c = (-1,0,0)	k = c dot o = -o.vx
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_X_NEG)) &&
							((a.vx < 0)&&((transpt.vx - o.vx) >= 0)&&((transpt.vx - o.vx) < -a.vx)) ||
							((a.vx > 0)&&((transpt.vx - o.vx) <= 0)&&((transpt.vx - o.vx) > -a.vx))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vx - o.vx) << 12) / -a.vx;
							if (
								(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen) &&
								(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
								)
								{
								index	= 0;			// X face
								l2		= 1;			// -ve
								goto cuboid_collision;
								}
							}
						// 2. normal c = (0,-1,0)	k = c dot o = -o.vy
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_Y_NEG)) &&
							((a.vy < 0)&&((transpt.vy - o.vy) >= 0)&&((transpt.vy - o.vy) < -a.vy)) ||
							((a.vy > 0)&&((transpt.vy - o.vy) <= 0)&&((transpt.vy - o.vy) > -a.vy))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vy - o.vy) << 12) / -a.vy;
							if (
								(abs(transpt.vx + ((l * a.vx) >> 12)) <= coll->cp_xlen) &&
								(abs(transpt.vz + ((l * a.vz) >> 12)) <= coll->cp_zlen)
								)
								{
								index	= 1;			// Y face
								l2		= 1;			// -ve
								goto cuboid_collision;
								}
							}
						// 3. normal c = (0,0,-1)	k = c dot o = -o.vz
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_Z_NEG)) &&
							((a.vz < 0)&&((transpt.vz - o.vz) >= 0)&&((transpt.vz - o.vz) < -a.vz)) ||
							((a.vz > 0)&&((transpt.vz - o.vz) <= 0)&&((transpt.vz - o.vz) > -a.vz))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vz - o.vz) << 12) / -a.vz;
							if (
								(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
								(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen)
								)
								{
								index	= 2;			// Z face
								l2		= 1;			// -ve
								goto cuboid_collision;	
								}
							}
						o.vx = coll->cp_xlen;
						o.vy = coll->cp_ylen;
						o.vz = coll->cp_zlen;
						// o is opposite corner of cuboid - try normals in +ve x,y,z resp:
						// 4. normal c = (+1,0,0)	k = c dot o = +o.vx
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_X_POS)) &&
							((a.vx > 0)&&((o.vx - transpt.vx) >= 0)&&((o.vx - transpt.vx) < a.vx)) ||
							((a.vx < 0)&&((o.vx - transpt.vx) <= 0)&&((o.vx - transpt.vx) > a.vx))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vx - o.vx) << 12) / -a.vx;
							if (
								(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen) &&
								(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
								)
								{
								index	= 0;			// X face
								l2		= 0;			// +ve
								goto cuboid_collision;
								}
							}
						// 5. normal c = (0,+1,0)	k = c dot o = +o.vy
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_Y_POS)) &&
							((a.vy > 0)&&((o.vy - transpt.vy) >= 0)&&((o.vy - transpt.vy) < a.vy)) ||
							((a.vy < 0)&&((o.vy - transpt.vy) <= 0)&&((o.vy - transpt.vy) > a.vy))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vy - o.vy) << 12) / -a.vy;
							if (
								(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
								(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
								)
								{
								index	= 1;			// Y face
								l2		= 0;			// +ve
								goto cuboid_collision;
								}
							}
						// 6. normal c = (0,0,+1)	k = c dot o = +o.vz
						if ((!(coll->cp_flags & MR_COLL_NO_FACE_Z_POS)) &&
							((a.vz > 0)&&((o.vz - transpt.vz) >= 0)&&((o.vz - transpt.vz) < a.vz)) ||
							((a.vz < 0)&&((o.vz - transpt.vz) <= 0)&&((o.vz - transpt.vz) > a.vz))
							)
							{
							// Intersection with finite line and infinite plane: check against face bounds
							l = ((transpt.vz - o.vz) << 12) / -a.vz;
							if (
								(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
								(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen)
								)
								{
								index	= 2;			// Z face
								l2		= 0;			// +ve
								goto cuboid_collision;
								}
							}
						goto collision_no_output;
		
					cuboid_collision:
						// Write collision face
						collcheck->mc_c_face = MR_COLLPRIM_FACE_CUBOID_X_POS + (index << 1) - l2;

						// Calculate intersection point
						if (collcheck->mc_c_flags & MR_COLLCHECK_C_POINT)
							{
							svec.vx = transpt.vx + ((l * a.vx) >> 12);
							svec.vy = transpt.vy + ((l * a.vy) >> 12);
							svec.vz = transpt.vz + ((l * a.vz) >> 12);
							// svec is intersection point in collprim frame
							gte_SetRotMatrix(&transpose);
							MRApplyRotMatrix(&svec, &o);
							collcheck->mc_c_point.vx = o.vx - MRColl_transpt.vx + point->vx;
							collcheck->mc_c_point.vy = o.vy - MRColl_transpt.vy + point->vy;
							collcheck->mc_c_point.vz = o.vz - MRColl_transpt.vz + point->vz;
							}

						if (collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
							{
							// Reflect vector
							((MR_LONG*)&a)[index] = -((MR_LONG*)&a)[index];

							// Set normal
							MR_CLEAR_VEC(&transpt);
							((MR_LONG*)&transpt)[index] = 0x1000 - (0x2000 * l2);

							// Rotate vectors back into world
							gte_SetRotMatrix(&transpose);
							MR_SVEC_EQUALS_VEC(&svec, &a);
							MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_vector);
							MR_SVEC_EQUALS_VEC(&svec, &transpt);
							MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_normal);
							}
						}
					}
				return(TRUE);
				}
			else
				return(FALSE);
			break;

		default:
			MR_ASSERTMSG(FALSE, "Unrecognised collprim type");
			break;	
		}	

	// Point is inside volume, but we asked for output information which could not be calculated
	collision_no_output:;
	collcheck->mc_c_flags |= MR_COLLCHECK_C_NO_OUTPUT;
	return(TRUE);
}


///******************************************************************************
//*%%%% MRCheckCollPrimsWithWorldPoint
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS		MR_COLLPRIM* coll_ptr =	MRCheckCollPrimsWithWorldPoint(
//*													MR_COLLPRIM*	coll,
//*													MR_SVEC*			point,
//*													MR_FRAME*		frame)	
//*
//*	FUNCTION		Checks if a world point is inside any collision volumes in a
//*					sequence. Frame is specified on input: if non-NULL, frame pointer inside
//*					interrogated MR_COLLPRIMs is ignored.
//*
//*	INPUTS		coll			-			Pointer to a valid collision primitive
//*					point			-			Pointer to an MR_SVEC containing the points
//*												position within the world
//*					frame			-			NULL if using cp_frame, else frame to use
//*												with interrogated MR_COLLPRIMs
//*
//*	RESULT		coll_ptr		-			Pointer to primitive if in collision, else
//*												returns NULL
//*
//*	NOTES			This has been optimised in the following ways: the function only
//*					calculates the global transpose matrix if the collprim points to
//*					matrix different from the previous one.  The function only
//*					recalculates the transformed point if this is the case also.
//*					However, the function always adds the collprim offset to the
//*					transformed point.
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	15.05.96		Tim Closs		Created
//*	25.09.96		Tim Closs		Now accepts cp_matrix and MR_COLL_BOUNDING and
//*										static frames
//*	10.10.96		Tim Closs		Now accepts NULL frame pointer
//*	05.02.97		Tim Closs		Fixed TransposeMatrix bug
//*
//*%%%**************************************************************************/
//
//MR_COLLPRIM* MRCheckCollPrimsWithWorldPoint(	MR_COLLPRIM*	coll,
//														  	MR_SVEC*			point,
//														  	MR_FRAME*		frame)
//{
//	MR_SVEC		transpt;	// will become point in collprim's frame
//	MR_MAT*		lw_ptr;
//	MR_FRAME*	newframe;
//
//
//	MR_ASSERT(coll != NULL);
//	MR_ASSERT(point != NULL);
//
//	do {
//		// Get pointers to cp_frame (A) and cp_matrix (B).  If either of these have changed since the last
//		// collision check, we need to rebuild the MRColl_transmatrix, which is BtAt (B transpose A transpose) which
//		// is (AB)t (AB transpose).
//		if (frame == NULL)
//			newframe = coll->cp_frame;
//		else
//			newframe = frame;
//
//		if (coll->cp_flags & MR_COLL_STATIC)
//			lw_ptr = (MR_MAT*)newframe;
//		else
//			lw_ptr = &newframe->fr_lw_transform;
//	
//		if (coll->cp_type == MR_COLLPRIM_SPHERE)
//			{
//			if (MRColl_lw_ptr	!= lw_ptr)
//				{
//				MRColl_lw_ptr = lw_ptr;
//				MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
//				}																					
//			}
//		else
//		if (
//			(MRColl_lw_ptr 		!= lw_ptr) ||
//			(MRColl_matrix_ptr 	!= coll->cp_matrix)
//			)
//			{
//			MRColl_lw_ptr = lw_ptr;
//			if (MRColl_matrix_ptr = coll->cp_matrix)
//				{
//				MRMulMatrixABC(MRColl_lw_ptr, MRColl_matrix_ptr, &MRTemp_matrix);
//				MRTransposeMatrix(&MRTemp_matrix, &MRColl_transmatrix);
//				}
//			else
//				MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
//			}
//	
//		// MRColl_transmatrix will now transform a point in the world into the collprim's axes
//		//
//		// Note that the cp_offset vector is always specified in the axes of the frame
//		MRApplyMatrixSVEC(MRColl_lw_ptr, &coll->cp_offset, &transpt);
//		MRColl_transpt.vx = point->vx - MRColl_lw_ptr->t[0] - transpt.vx;
//		MRColl_transpt.vy = point->vy - MRColl_lw_ptr->t[1] - transpt.vy;	  	
//		MRColl_transpt.vz = point->vz - MRColl_lw_ptr->t[2] - transpt.vz;	  	
//		MRApplyMatrixSVEC(&MRColl_transmatrix, &MRColl_transpt, &transpt);
//
//		switch(coll->cp_type)
//			{
//			case MR_COLLPRIM_SPHERE:
//				if (MR_VEC_MODULUS(transpt) < coll->cp_radius2)
//					{
//					if (!(coll->cp_flags & MR_COLL_BOUNDING))
//						return(coll);
//					}
//				break;
//			
//			case MR_COLLPRIM_CYLINDER_X:
//				if (
//					(MR_SQR(transpt.vy) + MR_SQR(transpt.vz) < coll->cp_radius2) &&
//					(abs(transpt.vx) < coll->cp_xlen)
//					)
//					{
//					if (!(coll->cp_flags & MR_COLL_BOUNDING))
//						return(coll);
//					}
//				break;
//			
//			case MR_COLLPRIM_CYLINDER_Y:
//				if (
//					(MR_SQR(transpt.vx) + MR_SQR(transpt.vz) < coll->cp_radius2) &&
//					(abs(transpt.vy) < coll->cp_ylen)
//					)
//					{
//					if (!(coll->cp_flags & MR_COLL_BOUNDING))
//						return(coll);
//					}
//				break;
//
//			case MR_COLLPRIM_CYLINDER_Z:
//				if (
//					(MR_SQR(transpt.vx) + MR_SQR(transpt.vy) < coll->cp_radius2) &&
//					(abs(transpt.vz) < coll->cp_zlen)
//					)
//					{
//					if (!(coll->cp_flags & MR_COLL_BOUNDING))
//						return(coll);
//					}
//				break;
//			
//			case MR_COLLPRIM_CUBOID:
//				if (
//					(abs(transpt.vx) < coll->cp_xlen) &&
//					(abs(transpt.vy) < coll->cp_ylen) &&
//					(abs(transpt.vz) < coll->cp_zlen)
//					)
//					{
//					if (!(coll->cp_flags & MR_COLL_BOUNDING))
//						return(coll);
//					}
//				break;
//			}
//		} while(!(coll++->cp_flags & (MR_COLL_LAST_IN_LIST | MR_COLL_BOUNDING)));
//
//	return(NULL);
//}
//
//
///******************************************************************************
//*%%%% MRReflectVectorInCollPrim
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS		MR_VOID	MRReflectVectorInCollPrim(
//*								MR_COLLPRIM*	coll,
//*								MR_SVEC*			p,
//*								MR_SVEC*			q,
//*								MR_VEC*			n,
//*								MR_VEC*			r,
//*								MR_FRAME*		frame);
//*
//*	FUNCTION		Assuming point 'q' is in collision with the primitive, this 
//*					routine works out which plane of the primitive is in intersection
//*					with the line 'pq', and returns pq reflected about the normal to
//*					that plane.
//*
//*	INPUTS		coll			-			Pointer to a valid collision primitive
//*					p				-			Line start point
//*					q				-			Line end point
//*					n				-			ptr to MR_VEC to store reflection normal
//*					r				-			ptr to MR_VEC to store reflected vector
//*					frame			-			If NULL, use coll->cp_frame, else override
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	15.05.96		Tim Closs		Created
//*	15.07.96		Tim Closs		Changed from "MRReturnNormal..."
//*	25.09.96		Tim Closs		Now accepts cp_matrix
//*	10.10.96		Tim Closs		Now accepts frame pointer
//*	04.12.96		Tim Closs		Now accepts reflection normal ptr.  Returned
//*										reflection normal and reflected vector now both
//*										point AWAY from the prim
//*	23.01.97		Dean Ashton		Fixed to make transpt always used as a MR_VEC
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRReflectVectorInCollPrim(	MR_COLLPRIM* 	coll,
//											 	MR_SVEC*			p,
//											 	MR_SVEC*			q,
//											 	MR_VEC*			n,
//											 	MR_VEC*			r,
//											 	MR_FRAME*		frame)
//{
//	// Pass in p as new point (the one we have just used in the point collision check) and q
//	// as old point
//	MR_VEC		a, transpt;
//	MR_SVEC		o, as;
//	MR_LONG		dot, l;
//	MR_MAT*		lw_ptr;
//	MR_LONG		av, tv;
//	MR_USHORT	cv;
//	MR_LONG*		av_ptr;
//	MR_LONG*		tv_ptr;
//
//
//	MR_ASSERT(coll != NULL);
//	MR_ASSERT(p != NULL);
//	MR_ASSERT(q != NULL);
//	MR_ASSERT(n != NULL);
//	MR_ASSERT(r != NULL);
//
//	as.vx = q->vx - p->vx;
//	as.vy = q->vy - p->vy;
//	as.vz = q->vz - p->vz;
//
//	// Get pointers to cp_frame (A) and cp_matrix (B).  If either of these have changed since the last
//	// collision check, we need to rebuild the MRColl_transmatrix, which is BtAt (B transpose A transpose) which
//	// is (AB)t (AB transpose).
//	if (frame == NULL)
//		frame = coll->cp_frame;
//
//	if (coll->cp_flags & MR_COLL_STATIC)
//		lw_ptr = (MR_MAT*)frame;
//	else
//		lw_ptr = &frame->fr_lw_transform;
//
//	if (coll->cp_type == MR_COLLPRIM_SPHERE)
//		{
//		if (MRColl_lw_ptr	!= lw_ptr)
//			{
//			MRColl_lw_ptr = lw_ptr;
//			MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
//			}
//		}
//	else
//	if (
//		(MRColl_lw_ptr 		!= lw_ptr) ||
//		(MRColl_matrix_ptr 	!= coll->cp_matrix)
//		)
//		{
//		MRColl_lw_ptr = lw_ptr;
//		if (MRColl_matrix_ptr = coll->cp_matrix)
//			{
//			MRMulMatrixABC(MRColl_lw_ptr, MRColl_matrix_ptr, &MRTemp_matrix);
//			MRTransposeMatrix(&MRTemp_matrix, &MRColl_transmatrix);
//			}
//		else
//			MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
//		}
//
//	MRApplyMatrix(MRColl_lw_ptr, &coll->cp_offset, &transpt);
//	MRColl_transpt.vx = p->vx - MRColl_lw_ptr->t[0] - transpt.vx;
//	MRColl_transpt.vy = p->vy - MRColl_lw_ptr->t[1] - transpt.vy;
//	MRColl_transpt.vz = p->vz - MRColl_lw_ptr->t[2] - transpt.vz;
//	MRApplyMatrix(&MRColl_transmatrix, &MRColl_transpt, &transpt);
//	MRApplyRotMatrix(&as, &a);
//
//	// transpt, a are now vectors p, (q-p) in the primitive's frame.  Work in this frame...
//
//	switch(coll->cp_type)
//		{
//		case MR_COLLPRIM_SPHERE:
//			// transpt gives the normal to the sphere at collision... should use this to find 
//			// reflection vector
//			MRNormaliseVEC(&transpt, &transpt);
//			dot 	= MR_VEC_DOT_VEC(&a, &transpt) >> 11;
//			a.vx 	= a.vx - ((dot * transpt.vx) >> 12);
//			a.vy 	= a.vy - ((dot * transpt.vy) >> 12);
//			a.vz 	= a.vz - ((dot * transpt.vz) >> 12);
//			MR_COPY_VEC(n, &transpt);
//			break;
//
//		case MR_COLLPRIM_CYLINDER_X:
//		case MR_COLLPRIM_CYLINDER_Y:
//		case MR_COLLPRIM_CYLINDER_Z:
//			av_ptr 	= ((MR_LONG*)&a) + (coll->cp_type - MR_COLLPRIM_CYLINDER_X);
//			av			= *av_ptr;
//			tv_ptr	= ((MR_LONG*)&transpt) + (coll->cp_type - MR_COLLPRIM_CYLINDER_X);
//			tv 		= *tv_ptr;
//			cv 		= ((MR_USHORT*)&coll->cp_xlen)[coll->cp_type - MR_COLLPRIM_CYLINDER_X];
//
//			if ((
//				((av < 0)&&((tv + cv) >= 0)&&((tv + cv) < -av)) ||
//				((av > 0)&&((tv + cv) <= 0)&&((tv + cv) > -av))
//				) ||
//				(
//				((av > 0)&&((cv - tv) >= 0)&&((cv - tv) < av)) ||
//				((av < 0)&&((cv - tv) <= 0)&&((cv - tv) > av))
//				))
//				// Intersection with finite line and infinite end plane: check against (circular) face bounds
//				{
//				if (tv > 0)
//					l = ((tv - cv) << 12) / -av;
//				else
//					l = ((tv + cv) << 12) / -av;
//
//				*tv_ptr = 0;
//				*av_ptr = 0;
//				
//				if (MR_SQR(transpt.vx + ((l * a.vx) >> 12)) + MR_SQR(transpt.vy + ((l * a.vy) >> 12)) + MR_SQR(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_radius2)
//					{
//					*av_ptr = -av;
//
//					// Calculate reflection normal
//					MR_CLEAR_VEC(n);
//					if (tv > 0)
//						((MR_LONG*)n)[coll->cp_type - MR_COLLPRIM_CYLINDER_X] =  0x1000;
//					else
//						((MR_LONG*)n)[coll->cp_type - MR_COLLPRIM_CYLINDER_X] = -0x1000;
//					break;
//					}
//				}
//
//			// Calculate reflection vector... normal is transpt projected onto YZ plane
//			*av_ptr 	= av;
//			*tv_ptr 	= 0;
//			MRNormaliseVEC(&transpt, &transpt);
//			dot 	= MR_VEC_DOT_VEC(&a, &transpt) >> 11;
//			a.vx 	= a.vx - ((dot * transpt.vx) >> 12);
//			a.vy 	= a.vy - ((dot * transpt.vy) >> 12);
//			a.vz 	= a.vz - ((dot * transpt.vz) >> 12);
//			MR_COPY_VEC(n, &transpt);
//			break;
//
//		case MR_COLLPRIM_CUBOID:
//			// Try each of 6 faces in turn
//			o.vx = -coll->cp_xlen;
//			o.vy = -coll->cp_ylen;
//			o.vz = -coll->cp_zlen;
//			// o is one corner of cuboid - try normals in -ve x,y,z resp:
//			//
//			// 1. normal c = (-1,0,0)	k = c dot o = -o.vx
//			if (
//				((a.vx < 0)&&((transpt.vx - o.vx) >= 0)&&((transpt.vx - o.vx) < -a.vx)) ||
//				((a.vx > 0)&&((transpt.vx - o.vx) <= 0)&&((transpt.vx - o.vx) > -a.vx))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vx - o.vx) << 12) / -a.vx;
//				if (
//					(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen) &&
//					(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
//					)
//					{
//					a.vx = -a.vx;
//					MR_SET_VEC(n, -0x1000, 0, 0);
//					break;
//					}
//				}
//			// 2. normal c = (0,-1,0)	k = c dot o = -o.vy
//			if (
//				((a.vy < 0)&&((transpt.vy - o.vy) >= 0)&&((transpt.vy - o.vy) < -a.vy)) ||
//				((a.vy > 0)&&((transpt.vy - o.vy) <= 0)&&((transpt.vy - o.vy) > -a.vy))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vy - o.vy) << 12) / -a.vy;
//				if (
//					(abs(transpt.vx + ((l * a.vx) >> 12)) <= coll->cp_xlen) &&
//					(abs(transpt.vz + ((l * a.vz) >> 12)) <= coll->cp_zlen)
//					)
//					{
//					a.vy = -a.vy;
//					MR_SET_VEC(n, 0, -0x1000, 0);
//					break;
//					}
//				}
//			// 3. normal c = (0,0,-1)	k = c dot o = -o.vz
//			if (
//				((a.vz < 0)&&((transpt.vz - o.vz) >= 0)&&((transpt.vz - o.vz) < -a.vz)) ||
//				((a.vz > 0)&&((transpt.vz - o.vz) <= 0)&&((transpt.vz - o.vz) > -a.vz))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vz - o.vz) << 12) / -a.vz;
//				if (
//					(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
//					(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen)
//					)
//					{
//					a.vz = -a.vz;
//					MR_SET_VEC(n, 0, 0, -0x1000);
//					break;
//					}
//				}
//			o.vx = coll->cp_xlen;
//			o.vy = coll->cp_ylen;
//			o.vz = coll->cp_zlen;
//			// o is opposite corner of cuboid - try normals in +ve x,y,z resp:
//			// 4. normal c = (+1,0,0)	k = c dot o = +o.vx
//			if (
//				((a.vx > 0)&&((o.vx - transpt.vx) >= 0)&&((o.vx - transpt.vx) < a.vx)) ||
//				((a.vx < 0)&&((o.vx - transpt.vx) <= 0)&&((o.vx - transpt.vx) > a.vx))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vx - o.vx) << 12) / -a.vx;
//				if (
//					(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen) &&
//					(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
//					)
//					{
//					a.vx = -a.vx;
//					MR_SET_VEC(n, 0x1000, 0, 0);
//					break;
//					}
//				}
//			// 5. normal c = (0,+1,0)	k = c dot o = +o.vy
//			if (
//				((a.vy > 0)&&((o.vy - transpt.vy) >= 0)&&((o.vy - transpt.vy) < a.vy)) ||
//				((a.vy < 0)&&((o.vy - transpt.vy) <= 0)&&((o.vy - transpt.vy) > a.vy))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vy - o.vy) << 12) / -a.vy;
//				if (
//					(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
//					(abs(transpt.vz + ((l * a.vz) >> 12)) < coll->cp_zlen)
//					)
//					{
//					a.vy = -a.vy;
//					MR_SET_VEC(n, 0, 0x1000, 0);
//					break;
//					}
//				}
//			// 6. normal c = (0,0,+1)	k = c dot o = +o.vz
//			if (
//				((a.vz > 0)&&((o.vz - transpt.vz) >= 0)&&((o.vz - transpt.vz) < a.vz)) ||
//				((a.vz < 0)&&((o.vz - transpt.vz) <= 0)&&((o.vz - transpt.vz) > a.vz))
//				)
//				{
//				// Intersection with finite line and infinite plane: check against face bounds
//				l = ((transpt.vz - o.vz) << 12) / -a.vz;
//				if (
//					(abs(transpt.vx + ((l * a.vx) >> 12)) < coll->cp_xlen) &&
//					(abs(transpt.vy + ((l * a.vy) >> 12)) < coll->cp_ylen)
//					)
//					{
//					a.vz = -a.vz;
//					MR_SET_VEC(n, 0, 0, 0x1000);
//					break;
//					}
//				}
//		// If we got here, we failed to find a plane which the line intersected with
//		// Likelihood is 'a' will be 0...
//		n->vx = MR_COLL_UNSTABLE;
//		MR_CLEAR_VEC(r);
//		return;
//		}	
//
//	// Put reflection normal and reflected vector back into world coords
//	MRApplyTransposeMatrixVEC(&MRColl_transmatrix,  n, n);
//	MRApplyTransposeMatrixVEC(&MRColl_transmatrix, &a, r);
//}
//
//
///******************************************************************************
//*%%%% MRPointToFrustrumCollision
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS		MR_ULONG result =	MRPointToFrustrumCollision(
//*											MR_VEC*	fx,
//*											MR_VEC*	fy,
//*											MR_VEC*	fz,
//*											MR_VEC*	p);
//*
//*	FUNCTION		Checks to see whether or not point p is within the semi-infinite
//*					frustrum defined by aces fx,fy,fz.
//*
//*	INPUTS		fx			-			Direction of x axis of frustrum in world
//*					fy			-			Direction of y axis of frustrum in world
//*					fz			-			Direction of z axis of frustrum in world
//*
//*	RESULT		result	-			0 if inside frustrum, or else MR_PLANE_XY or 
//*											equivalend according to first plane found.
//*
//*	NOTES			We assume fx,fy,fz are ordered as a right handed system (eg x to
//*					the right, y down, z into screen)
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	15.05.96		Tim Closs		Created
//*	09.07.96		Tim Closs		Now returns OR of flags, rather than first found
//*
//*%%%**************************************************************************/
//
//MR_ULONG	MRPointToFrustrumCollision(MR_VEC* fx,
//												MR_VEC* fy,
//												MR_VEC* fz,
//												MR_VEC* p)
//{
//	MR_VEC	norm;
//	MR_ULONG	result = NULL;
//
//
//	MROuterProduct12(fx, fy, &norm);
//	if (MR_VEC_DOT_VEC(&norm, p) > 0)
//		result |= MR_PLANE_XY;
//
//	MROuterProduct12(fy, fz, &norm);
//	if (MR_VEC_DOT_VEC(&norm, p) > 0)
//		result |= MR_PLANE_YZ;
//
//	MROuterProduct12(fz, fx, &norm);
//	if (MR_VEC_DOT_VEC(&norm, p) > 0)
//		result |= MR_PLANE_ZX;
//
//	return(result);
//}
//
///******************************************************************************
//*%%%% MRPointToFrustrumCollisionNoXY
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS		MR_ULONG result =	MRPointToFrustrumCollisionNoXY(
//*											MR_VEC*	fx,
//*											MR_VEC*	fy,
//*											MR_VEC*	fz,
//*											MR_VEC*	p);
//*
//*	FUNCTION		Checks to see whether or not point p is within the semi-infinite
//*					frustrum defined by aces fx,fy,fz. This routine does not check
//*					if the point is the correct size of the fx/fy plane, and OR's
//*					the results from other plane checks.
//*
//*	INPUTS		fx			-			Direction of x axis of frustrum in world
//*					fy			-			Direction of y axis of frustrum in world
//*					fz			-			Direction of z axis of frustrum in world
//*
//*	RESULT		result	-			0 if inside frustrum, or else MR_PLANE_XY or 
//*											equivalent according to first plane found.
//*
//*	NOTES			We assume fx,fy,fz are ordered as a right handed system (eg x to
//*					the right, y down, z into screen)
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	15.05.96		Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_ULONG	MRPointToFrustrumCollisionNoXY(MR_VEC* fx, MR_VEC* fy, MR_VEC* fz, MR_VEC* p)
//{
//	MR_VEC	norm;
//	MR_ULONG	result = NULL;
//
//
//	MROuterProduct12(fy, fz, &norm);
//	if (MR_VEC_DOT_VEC(&norm, p) < 0)
//		result |= MR_PLANE_YZ;
//
//	MROuterProduct12(fz, fx, &norm);
//	if (MR_VEC_DOT_VEC(&norm, p) < 0)
//		result |= MR_PLANE_ZX;
//
//	return(result);
//}


/******************************************************************************
*%%%% MRCheckBoundingBoxWithWorldPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	MRCheckBoundingBoxWithWorldPoint(
*						MR_BBOX*			bbox,
*						MR_SVEC*			point,
*						MR_MAT*			matrix,
*						MR_COLLCHECK*	collcheck)
*
*	FUNCTION	Checks to see if a point (in the world) is within a bounding box
*
*	INPUTS		bbox 		-	ptr to bounding box (in OpenInventor ordering)
*				point		-	ptr to point (in world)
*				matrix		-	ptr to LW transform for bbox
*				collcheck	-	if non-NULL, this is used to store various results
*
*	RESULT		TRUE if in collision, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*	14.01.97	Tim Closs		Fixed bug
*	14.01.97	Tim Closs		Fixed bug
*	11.02.97	Tim Closs		Now takes matrix, collcheck inputs
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix
*
*%%%**************************************************************************/

MR_BOOL	MRCheckBoundingBoxWithWorldPoint(	MR_BBOX*		bbox,
											MR_SVEC*		point,
											MR_MAT*			matrix,
											MR_COLLCHECK*	collcheck)
{
	MR_VEC		transpt, a, ov;
	MR_SVEC*	o;
	MR_LONG		l, l2, index;
	MR_SVEC		svec;
	MR_MAT		transpose;
		  	

	MR_ASSERT(bbox);
	MR_ASSERT(point);

	if (matrix == NULL)
		matrix = &MRId_matrix;

	if (MRColl_lw_ptr	!= matrix)
		{
		MRColl_lw_ptr = matrix;
		MRTransposeMatrix(MRColl_lw_ptr, &MRColl_transmatrix);
		}

	MRColl_transpt.vx = point->vx - MRColl_lw_ptr->t[0];
	MRColl_transpt.vy = point->vy - MRColl_lw_ptr->t[1];
	MRColl_transpt.vz = point->vz - MRColl_lw_ptr->t[2];
	gte_SetRotMatrix(&MRColl_transmatrix);
	MRApplyRotMatrix(&MRColl_transpt, &transpt);

	// MRColl_transmatrix will now transform a point in the world into the collprim's axes
	//
	// transpt is point in bounding box frame
	if (
		(transpt.vx > bbox->mb_verts[0].vx) && (transpt.vx < bbox->mb_verts[4].vx) &&	
		(transpt.vy > bbox->mb_verts[0].vy) && (transpt.vy < bbox->mb_verts[2].vy) &&	
		(transpt.vz > bbox->mb_verts[0].vz) && (transpt.vz < bbox->mb_verts[1].vz)
		)
		{
		// Collision.  Store outputs
		if (collcheck)
			{
			if (collcheck->mc_c_flags & MR_COLLCHECK_C_FACE)
				{
				// If the relative_motion vector is zero, bail our because we won't be able to find an intersection face
				if (!(collcheck->mc_relative_motion.vx | collcheck->mc_relative_motion.vy | collcheck->mc_relative_motion.vz))
					goto collision_no_output;

				MRApplyRotMatrix(&collcheck->mc_relative_motion, &a);
				MR_SUB_VEC(&transpt, &a);
				// transpt is now the OLD point in collprim coords

				MRTransposeMatrix(&MRColl_transmatrix, &transpose);

				// Try each of 6 faces in turn
				o = &bbox->mb_verts[0];
				// o is one corner of cuboid - try normals in -ve x,y,z resp:
				//
				// 1. normal c = (-1,0,0)	k = c dot o = -o->vx
				if (
					((a.vx < 0)&&((transpt.vx - o->vx) >= 0)&&((transpt.vx - o->vx) < -a.vx)) ||
					((a.vx > 0)&&((transpt.vx - o->vx) <= 0)&&((transpt.vx - o->vx) > -a.vx))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vx - o->vx) << 12) / -a.vx;
					if (
						((transpt.vy + ((l * a.vy) >> 12)) > o->vy) &&
						((transpt.vy + ((l * a.vy) >> 12)) < bbox->mb_verts[2].vy) &&
						((transpt.vz + ((l * a.vz) >> 12)) > o->vz) &&
						((transpt.vz + ((l * a.vz) >> 12)) < bbox->mb_verts[1].vz)
						)
						{
						index	= 0;			// X face
						l2		= 1;			// -ve
						goto bbox_collision;
						}
					}
				// 2. normal c = (0,-1,0)	k = c dot o = -o->vy
				if (
					((a.vy < 0)&&((transpt.vy - o->vy) >= 0)&&((transpt.vy - o->vy) < -a.vy)) ||
					((a.vy > 0)&&((transpt.vy - o->vy) <= 0)&&((transpt.vy - o->vy) > -a.vy))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vy - o->vy) << 12) / -a.vy;
					if (
						((transpt.vx + ((l * a.vx) >> 12)) > o->vx) &&
						((transpt.vx + ((l * a.vx) >> 12)) < bbox->mb_verts[4].vx) &&
						((transpt.vz + ((l * a.vz) >> 12)) > o->vz) &&
						((transpt.vz + ((l * a.vz) >> 12)) < bbox->mb_verts[1].vz)
						)
						{
						index	= 1;			// Y face
						l2		= 1;			// -ve
						goto bbox_collision;
						}
					}
				// 3. normal c = (0,0,-1)	k = c dot o = -o->vz
				if (
					((a.vz < 0)&&((transpt.vz - o->vz) >= 0)&&((transpt.vz - o->vz) < -a.vz)) ||
					((a.vz > 0)&&((transpt.vz - o->vz) <= 0)&&((transpt.vz - o->vz) > -a.vz))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vz - o->vz) << 12) / -a.vz;
					if (
						((transpt.vy + ((l * a.vy) >> 12)) > o->vy) &&
						((transpt.vy + ((l * a.vy) >> 12)) < bbox->mb_verts[2].vy) &&
						((transpt.vx + ((l * a.vx) >> 12)) > o->vx) &&
						((transpt.vx + ((l * a.vx) >> 12)) < bbox->mb_verts[4].vx)
						)
						{
						index	= 2;			// Z face
						l2		= 1;			// -ve
						goto bbox_collision;	
						}
					}

				o = &bbox->mb_verts[7];
				// o is opposite corner of cuboid - try normals in +ve x,y,z resp:
				//
				// 4. normal c = (+1,0,0)	k = c dot o = +o->vx
				if (
					((a.vx > 0)&&((o->vx - transpt.vx) >= 0)&&((o->vx - transpt.vx) < a.vx)) ||
					((a.vx < 0)&&((o->vx - transpt.vx) <= 0)&&((o->vx - transpt.vx) > a.vx))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vx - o->vx) << 12) / -a.vx;
					if (
						((transpt.vy + ((l * a.vy) >> 12)) > bbox->mb_verts[5].vy) &&
						((transpt.vy + ((l * a.vy) >> 12)) < o->vy) &&
						((transpt.vz + ((l * a.vz) >> 12)) > bbox->mb_verts[6].vz) &&
						((transpt.vz + ((l * a.vz) >> 12)) < o->vz)
						)
						{
						index	= 0;			// X face
						l2		= 0;			// +ve
						goto bbox_collision;
						}
					}
				// 5. normal c = (0,+1,0)	k = c dot o = +o->vy
				if (
					((a.vy > 0)&&((o->vy - transpt.vy) >= 0)&&((o->vy - transpt.vy) < a.vy)) ||
					((a.vy < 0)&&((o->vy - transpt.vy) <= 0)&&((o->vy - transpt.vy) > a.vy))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vy - o->vy) << 12) / -a.vy;
					if (
						((transpt.vx + ((l * a.vx) >> 12)) > bbox->mb_verts[3].vx) &&
						((transpt.vx + ((l * a.vx) >> 12)) < o->vx) &&
						((transpt.vz + ((l * a.vz) >> 12)) > bbox->mb_verts[6].vz) &&
						((transpt.vz + ((l * a.vz) >> 12)) < o->vz)
						)
						{
						index	= 1;			// Y face
						l2		= 0;			// +ve
						goto bbox_collision;
						}
					}
				// 6. normal c = (0,0,+1)	k = c dot o = +o->vz
				if (
					((a.vz > 0)&&((o->vz - transpt.vz) >= 0)&&((o->vz - transpt.vz) < a.vz)) ||
					((a.vz < 0)&&((o->vz - transpt.vz) <= 0)&&((o->vz - transpt.vz) > a.vz))
					)
					{
					// Intersection with finite line and infinite plane: check against face bounds
					l = ((transpt.vz - o->vz) << 12) / -a.vz;
					if (
						((transpt.vy + ((l * a.vy) >> 12)) > bbox->mb_verts[5].vy) &&
						((transpt.vy + ((l * a.vy) >> 12)) < o->vy) &&
						((transpt.vx + ((l * a.vx) >> 12)) > bbox->mb_verts[3].vx) &&
						((transpt.vx + ((l * a.vx) >> 12)) < o->vx)
						)
						{
						index	= 2;			// Z face
						l2		= 0;			// +ve
						goto bbox_collision;
						}
					}
				goto collision_no_output;
		
			bbox_collision:
				// Write collision face
				collcheck->mc_c_face = MR_COLLPRIM_FACE_CUBOID_X_POS + (index << 1) - l2;

				// Calculate intersection point
				if (collcheck->mc_c_flags & MR_COLLCHECK_C_POINT)
					{
					ov.vx = transpt.vx + ((l * a.vx) >> 12);
					ov.vy = transpt.vy + ((l * a.vy) >> 12);
					ov.vz = transpt.vz + ((l * a.vz) >> 12);
					MR_SVEC_EQUALS_VEC(&collcheck->mc_c_point, &ov);
					}

				if (collcheck->mc_c_flags & MR_COLLCHECK_C_REFLECTION)
					{
					// Reflect vector
					((MR_LONG*)&a)[index] = -((MR_LONG*)&a)[index];

					// Set normal
					MR_CLEAR_VEC(&transpt);
					((MR_LONG*)&transpt)[index] = 0x1000 - (0x2000 * l2);

					// Rotate vectors back into world
					gte_SetRotMatrix(&transpose);
					MR_SVEC_EQUALS_VEC(&svec, &a);
					MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_vector);
					MR_SVEC_EQUALS_VEC(&svec, &transpt);
					MRApplyRotMatrix(&svec, &collcheck->mc_c_reflection_normal);
					}
				}
			}
		return(TRUE);
		}
	else
		return(FALSE);

	// Point is inside volume, but we asked for output information which could not be calculated
	collision_no_output:;
	collcheck->mc_c_flags |= MR_COLLCHECK_C_NO_OUTPUT;
	return(TRUE);
}


///******************************************************************************
//*%%%% MRReflectVectorInBoundingBox
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS		MR_VOID	MRReflectVectorInBoundingBox(
//*								MR_SVEC*		vert_ptr,
//*								MR_SVEC*		p,
//*								MR_SVEC*		q,
//*								MR_VEC*		n,
//*								MR_MAT*		lw_transform);
//*
//*	FUNCTION		Assuming point 'q' is in collision with the primitive, this 
//*					routine works out which plane of the bounding box is in intersection
//*					with the line 'pq', and returns pq reflected about the normal to
//*					that plane.
//*
//*	INPUTS		vert_ptr			-	Ptr to 8 bounding vertices (in OpenInventor ordering)
//*					p					-	Line start point
//*					q					-	Line end point
//*					n					-	Address of an MR_VEC in which we will
//*											return the reflected vector
//*					lw_transform	-	ptr to a transform which takes the bounding box from
//*											its local space to the world
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	10.10.96		Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRReflectVectorInBoundingBox(	MR_SVEC*		vert_ptr,
//													MR_SVEC*		p,
//													MR_SVEC*		q,
//													MR_VEC*		n,
//													MR_MAT*		lw_transform)
//{
//	MR_SVEC		transpt, as;
//	MR_VEC		vec, a;
//	MR_SVEC*		o;
//	MR_MAT		transpose;
//	MR_LONG		l;
//
//
//	MR_ASSERT(vert_ptr 		!= NULL);
//	MR_ASSERT(p		 			!= NULL);
//	MR_ASSERT(q		 			!= NULL);
//	MR_ASSERT(n		 			!= NULL);
//	MR_ASSERT(lw_transform 	!= NULL);
//
//
//	as.vx = q->vx - p->vx;
//	as.vy = q->vy - p->vy;
//	as.vz = q->vz - p->vz;
//
//	transpt.vx = p->vx - lw_transform->t[0];
//	transpt.vy = p->vy - lw_transform->t[1];
//	transpt.vz = p->vz - lw_transform->t[2];
//	MRTransposeMatrix(lw_transform, &transpose);
//	MRApplyMatrix(&transpose, &transpt, &vec);
//	MRApplyRotMatrix(&as, &a);
//	
//	// vec is point in bounding box frame
//	//	
//	// Try each of 6 faces in turn
//
//	o = vert_ptr + 0;
//	// o is one corner of cuboid - try normals in -ve x,y,z resp:
//	//
//	// 1. normal c = (-1,0,0)	k = c dot o = -o->vx
//	if (
//		((a.vx < 0)&&((vec.vx - o->vx) >= 0)&&((vec.vx - o->vx) <= -a.vx)) ||
//		((a.vx > 0)&&((vec.vx - o->vx) <= 0)&&((vec.vx - o->vx) >= -a.vx))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vx - o->vx) << 12) / -a.vx;
//		if (
//			((vec.vy + ((l * a.vy) >> 12)) >= o->vy) &&
//			((vec.vy + ((l * a.vy) >> 12)) <= (vert_ptr + 2)->vy) &&
//			((vec.vz + ((l * a.vz) >> 12)) >= o->vz) &&
//			((vec.vz + ((l * a.vz) >> 12)) <= (vert_ptr + 1)->vz)
//			)
//			{
//			a.vx = -a.vx;
//			goto done;
//			}
//		}
//	// 2. normal c = (0,-1,0)	k = c dot o = -o->vy
//	if (
//		((a.vy < 0)&&((vec.vy - o->vy) >= 0)&&((vec.vy - o->vy) <= -a.vy)) ||
//		((a.vy > 0)&&((vec.vy - o->vy) <= 0)&&((vec.vy - o->vy) >= -a.vy))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vy - o->vy) << 12) / -a.vy;
//		if (
//			((vec.vx + ((l * a.vx) >> 12)) >= o->vx) &&
//			((vec.vx + ((l * a.vx) >> 12)) <= (vert_ptr + 4)->vx) &&
//			((vec.vz + ((l * a.vz) >> 12)) >= o->vz) &&
//			((vec.vz + ((l * a.vz) >> 12)) <= (vert_ptr + 1)->vz)
//			)
//			{
//			a.vy = -a.vy;
//			goto done;
//			}
//		}
//	// 3. normal c = (0,0,-1)	k = c dot o = -o->vz
//	if (
//		((a.vz < 0)&&((vec.vz - o->vz) >= 0)&&((vec.vz - o->vz) <= -a.vz)) ||
//		((a.vz > 0)&&((vec.vz - o->vz) <= 0)&&((vec.vz - o->vz) >= -a.vz))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vz - o->vz) << 12) / -a.vz;
//		if (
//			((vec.vy + ((l * a.vy) >> 12)) >= o->vy) &&
//			((vec.vy + ((l * a.vy) >> 12)) <= (vert_ptr + 2)->vy) &&
//			((vec.vx + ((l * a.vx) >> 12)) >= o->vx) &&
//			((vec.vx + ((l * a.vx) >> 12)) <= (vert_ptr + 4)->vx)
//			)
//			{
//			a.vz = -a.vz;
//			goto done;
//			}
//		}
//	o = vert_ptr + 7;
//	// o is opposite corner of cuboid - try normals in +ve x,y,z resp:
//	//
//	// 4. normal c = (+1,0,0)	k = c dot o = +o->vx
//	if (
//		((a.vx > 0)&&((o->vx - vec.vx) >= 0)&&((o->vx - vec.vx) <= a.vx)) ||
//		((a.vx < 0)&&((o->vx - vec.vx) <= 0)&&((o->vx - vec.vx) >= a.vx))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vx - o->vx) << 12) / -a.vx;
//		if (
//			((vec.vy + ((l * a.vy) >> 12)) >= (vert_ptr + 5)->vy) &&
//			((vec.vy + ((l * a.vy) >> 12)) <= o->vy) &&
//			((vec.vz + ((l * a.vz) >> 12)) >= (vert_ptr + 6)->vz) &&
//			((vec.vz + ((l * a.vz) >> 12)) <= o->vz)
//			)
//			{
//			a.vx = -a.vx;
//			goto done;
//			}
//		}
//	// 5. normal c = (0,+1,0)	k = c dot o = +o->vy
//	if (
//		((a.vy > 0)&&((o->vy - vec.vy) >= 0)&&((o->vy - vec.vy) <= a.vy)) ||
//		((a.vy < 0)&&((o->vy - vec.vy) <= 0)&&((o->vy - vec.vy) >= a.vy))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vy - o->vy) << 12) / -a.vy;
//		if (
//			((vec.vx + ((l * a.vx) >> 12)) >= (vert_ptr + 3)->vx) &&
//			((vec.vx + ((l * a.vx) >> 12)) <= o->vx) &&
//			((vec.vz + ((l * a.vz) >> 12)) >= (vert_ptr + 6)->vz) &&
//			((vec.vz + ((l * a.vz) >> 12)) <= o->vz)
//			)
//			{
//			a.vy = -a.vy;
//			goto done;
//			}
//		}
//	// 6. normal c = (0,0,+1)	k = c dot o = +o->vz
//	if (
//		((a.vz > 0)&&((o->vz - vec.vz) >= 0)&&((o->vz - vec.vz) <= a.vz)) ||
//		((a.vz < 0)&&((o->vz - vec.vz) <= 0)&&((o->vz - vec.vz) >= a.vz))
//		)
//		{
//		// Intersection with finite line and infinite plane: check against face bounds
//		l = ((vec.vz - o->vz) << 12) / -a.vz;
//		if (
//			((vec.vy + ((l * a.vy) >> 12)) >= (vert_ptr + 5)->vy) &&
//			((vec.vy + ((l * a.vy) >> 12)) <= o->vy) &&
//			((vec.vx + ((l * a.vx) >> 12)) >= (vert_ptr + 3)->vx) &&
//			((vec.vx + ((l * a.vx) >> 12)) <= o->vx)
//			)
//			{
//			a.vz = -a.vz;
//			goto done;
//			}
//		}
//
//	// If we got here, we failed to find a plane which the line intersected with
//	// Likelihood is 'a' will be 0...
//	n->vx = MR_COLL_UNSTABLE;
//	return;
//
//	done:
//	MRApplyMatrixVEC(lw_transform, &a, n);
//}


/******************************************************************************
*%%%% MRResetCollisionPointers
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResetCollisionPointers(MR_VOID)
*
*	FUNCTION	Reset collision ptrs used to reduce collision matrix ops
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRResetCollisionPointers(MR_VOID)
{
	MRColl_lw_ptr	 	= NULL;
	MRColl_matrix_ptr	= NULL;
}


/******************************************************************************
*%%%% MRCollisionCheck
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	result =	MRCollisionCheck(
*									MR_COLLCHECK*	collcheck,
*									MR_ULONG		flags_a,
*									MR_ULONG		flags_b,
*									MR_ULONG		flags_c)
*
*	FUNCTION	High level point-prim collision function
*
*	INPUTS		collcheck	-	ptr to MR_COLLCHECK structure holding detailed
*								info about what items to check
*				flags_a		-	what to do with inputs a
*				flags_b		-	what to do with inputs b
*				flags_c		-	what to do with outputs c
*
*	RESULT		result		-	TRUE if in collision, else FALSE
*
*	NOTES		Checks points (inputs a) against volumes (inputs b) and stores
*				results (outputs c)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.02.97	Tim Closs		Created
*	11.04.97	Tim Closs		Fixed hilites in multiple parts bug
*	25.06.97	Tim Closs		Added support for MR_ANIM_ENV_FLIPBOOK
*
*%%%**************************************************************************/

MR_BOOL	MRCollisionCheck(	MR_COLLCHECK*	collcheck,
							MR_ULONG		flags_a,
							MR_ULONG		flags_b,
							MR_ULONG		flags_c)
{
	MR_HILITE*			a_hilite = NULL;
	MR_SVEC*			a_svec	= NULL;
	MR_USHORT			a_items;
	MR_MAT*				a_matrix;
	MR_SVEC				a_world_svec;
	MR_PART*			a_part;
	MR_OBJECT*			a_object;
	MR_MOF*				a_mof;
	MR_ANIM_ENV*		a_anim_env = NULL;
	MR_USHORT			a_parts;

	MR_USHORT			b_items;
	MR_USHORT			b_parts;
	MR_COLLPRIM*		b_collprim;
	MR_BBOX*			b_bbox;
	MR_MAT*				b_matrix;
	MR_FRAME*			b_frame;
	MR_PART*			b_part;
	MR_OBJECT*			b_object;
	MR_MOF*				b_mof = NULL;
	MR_ANIM_ENV*		b_anim_env;

	MR_USHORT			b_stored_parts;
	MR_PART*			b_stored_part;
	MR_MAT*				b_stored_matrix;

	
	MR_ASSERT(collcheck);

	// Store output flags, as these are required by the low-level functions
	collcheck->mc_c_flags = flags_c;

	// Input (a) must be a MR_SVEC or MR_HILITE array
	if (flags_a & MR_COLLCHECK_A_ALL_PARTS)
		{
		// Check hilites for all parts
		}
	else
	if (flags_a & MR_COLLCHECK_A_SVEC)
		a_svec = collcheck->mc_a_item;
	else
	if	(flags_a & MR_COLLCHECK_A_HILITE)
		a_hilite = collcheck->mc_a_item;
	else
		return(FALSE);

	// Get matrix for frame item a is in (if any)
	a_matrix	= NULL;
	a_object	= NULL;
	a_mof		= NULL;
	a_parts		= 1;
	a_part 		= NULL;
	if (collcheck->mc_a_owner)
		{
		if (flags_a & MR_COLLCHECK_A_OWNER_STATIC_MESH)
			{
			a_object	= collcheck->mc_a_owner;
			a_mof		= a_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr;
			}
		else
		if (flags_a & MR_COLLCHECK_A_OWNER_FRAME)
			a_matrix	= &((MR_FRAME*)collcheck->mc_a_owner)->fr_lw_transform;
		else
		if (flags_a & MR_COLLCHECK_A_OWNER_MATRIX)
			a_matrix	= (MR_MAT*)collcheck->mc_a_owner;
		else
		if (flags_a & MR_COLLCHECK_A_OWNER_ANIM_ENV)
			{
			a_anim_env = collcheck->mc_a_owner;
			if (a_anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
				{
				a_object = a_anim_env->ae_extra.ae_extra_env_multiple->ae_objects[collcheck->mc_a_owner_model];
				a_mof 	= a_anim_env->ae_header->ah_static_files[a_anim_env->ae_model_set->am_models[collcheck->mc_a_owner_model].am_static_model];
				if (a_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
					a_matrix = a_anim_env->ae_extra.ae_extra_env_multiple->ae_lw_transforms[collcheck->mc_a_owner_model];
				}		
			else
			if (a_anim_env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
				{
				a_object = a_anim_env->ae_extra.ae_extra_env_flipbook->ae_object;
				a_mof 	= (MR_MOF*)a_anim_env->ae_header;
				}
			else
				{
				a_object = a_anim_env->ae_extra.ae_extra_env_single->ae_object;
				a_mof 	= a_anim_env->ae_header->ah_static_files[a_anim_env->ae_model_set->am_models[0].am_static_model];
				if (a_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
					a_matrix = a_anim_env->ae_extra.ae_extra_env_single->ae_lw_transforms;
				}
			}
		if (a_object)
			{
			if (!a_matrix)
				{
				if (a_object->ob_flags & MR_OBJ_STATIC)
					a_matrix	= (MR_MAT*)a_object->ob_frame;
				else
					a_matrix	= &a_object->ob_frame->fr_lw_transform;
				}
	
			a_part = (MR_PART*)(a_mof + 1);
			if (flags_a & MR_COLLCHECK_A_ALL_PARTS)
				a_parts = a_mof->mm_extra;
			else
				{
				a_part += collcheck->mc_a_owner_part;
				if ((a_anim_env) && (a_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS))
					a_matrix += collcheck->mc_a_owner_part;
				}
			}
		}
	
	// Do any set up for (b) we can do outside of loop (a)
	//
	// Get matrix for frame item b is in (if any)
	b_matrix 	= NULL;
	b_frame		= NULL;
	b_object	= NULL;
	b_parts		= 1;
	b_part		= NULL;
	b_anim_env	= NULL;

	if (flags_b & MR_COLLCHECK_B_OWNER_STATIC_MESH)
		{
		b_object	= collcheck->mc_b_owner;
		b_mof 		= b_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr;
		}
	else
	if (flags_b & MR_COLLCHECK_B_OWNER_FRAME)
		{
		b_frame		= collcheck->mc_b_owner;
		b_matrix	= &b_frame->fr_lw_transform;
		}
	else
	if (flags_b & MR_COLLCHECK_B_OWNER_MATRIX)
		b_matrix	= (MR_MAT*)collcheck->mc_b_owner;
	else
	if (flags_b & MR_COLLCHECK_B_OWNER_ANIM_ENV)
		{
		b_anim_env = collcheck->mc_b_owner;
		if (b_anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
			{
			b_object	= b_anim_env->ae_extra.ae_extra_env_multiple->ae_objects[collcheck->mc_b_owner_model];
			b_mof 		= b_anim_env->ae_header->ah_static_files[b_anim_env->ae_model_set->am_models[collcheck->mc_b_owner_model].am_static_model];
			if (b_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
				b_matrix = b_anim_env->ae_extra.ae_extra_env_multiple->ae_lw_transforms[collcheck->mc_b_owner_model];
			}
		else
		if (b_anim_env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
			{
			b_object = b_anim_env->ae_extra.ae_extra_env_flipbook->ae_object;
			b_mof 	= (MR_MOF*)b_anim_env->ae_header;
			}
		else
			{
			b_object	= b_anim_env->ae_extra.ae_extra_env_single->ae_object;
			b_mof 		= b_anim_env->ae_header->ah_static_files[b_anim_env->ae_model_set->am_models[0].am_static_model];
			if (b_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
				b_matrix = b_anim_env->ae_extra.ae_extra_env_single->ae_lw_transforms;
			}
		}
	if (b_object)
		{
		if (!b_matrix)
			{
			if (b_object->ob_flags & MR_OBJ_STATIC)
				b_matrix	= (MR_MAT*)b_object->ob_frame;
			else
				b_matrix	= &b_object->ob_frame->fr_lw_transform;
			}

		b_part = (MR_PART*)(b_mof + 1);
		if (flags_b & MR_COLLCHECK_B_ALL_PARTS)
			b_parts = b_mof->mm_extra;
		else
			{
			b_part += collcheck->mc_b_owner_part;
			if ((b_anim_env) && (b_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS))
				b_matrix += collcheck->mc_b_owner_part;
			}
		}

	b_stored_part 	= b_part;
	b_stored_parts 	= b_parts;
	b_stored_matrix = b_matrix;

	// Run through array of items (a), calculating points in world and calling low-level check
	while(a_parts--)
		{
		// Run through MR_PARTs (if any)
		if (a_object)
			{
			if (flags_a & MR_COLLCHECK_A_HILITE)
				{
				if (!(a_hilite = a_part->mp_hilite_ptr))
					// No hilites in this part
					goto next_part_a;
				}
			}
		if (a_part)
			// If a part is specified (either by ..OWNER_STATIC_MESH or ..OWNER_ANIM_ENV, get number of hilites from MR_PART
			a_items = a_part->mp_hilites;
		else
			// Else number of hilites must have been specified explicitly
			a_items = collcheck->mc_a_size;
		
		while(a_items--)
			{
			if (flags_a & MR_COLLCHECK_A_HILITE)
				{
				MR_ASSERT(a_hilite->mh_flags & MR_HILITE_VERTEX);
				a_svec = (MR_SVEC*)a_hilite->mh_target_ptr;
				a_hilite++;
				}
			if (a_matrix)
				{
				// Hilite or svec needs LW transform applied
				MRApplyMatrixSVEC(a_matrix, a_svec, &a_world_svec);
				a_world_svec.vx += a_matrix->t[0];
				a_world_svec.vy += a_matrix->t[1];
				a_world_svec.vz += a_matrix->t[2];
				}
			else
				{
				MR_COPY_SVEC(&a_world_svec, a_svec);
				}
			if (flags_a & MR_COLLCHECK_A_SVEC)
				a_svec++;
	
			// a_world_svec is point in world to check against.  Now run through volumes (b)
			b_items 	= collcheck->mc_b_size;
			b_collprim 	= NULL;
			b_bbox 		= NULL;
			b_part 		= b_stored_part;
			b_parts 	= b_stored_parts;
			b_matrix 	= b_stored_matrix;

			if (flags_b & MR_COLLCHECK_B_COLLPRIM_SPECIFIC)
				b_collprim = collcheck->mc_b_item;
			else
			if (flags_b & MR_COLLCHECK_B_BBOX_SPECIFIC)
				b_bbox = collcheck->mc_b_item;
	
			while(b_parts--)
				{
				// Run through MR_PARTs (if any)
				if (b_object)
					{
					if (flags_b & MR_COLLCHECK_B_COLLPRIM)
						{
						if (b_collprim = b_part->mp_collprim_ptr)
							{
							// The list is terminated by MR_COLL_LAST_IN_LIST (so set b_items to infinite)
							b_items = 0xffff;
							}
						else
							{
							// There are no collprims in this MR_PART
							goto next_part_b;
							}
						}
					else
					if (flags_b & MR_COLLCHECK_B_PART_BBOX)
						{
						if (b_bbox = b_part->mp_partcel_ptr->mp_bbox_ptr)
							b_items = 1;
						else
							{
							// There is no MR_BBOX in this MR_PART
							goto next_part_b;
							}
						}
	
					// If (b_anim_env) and NO lw transforms then calculate part transform here
					if	((b_anim_env) && 
						(!(b_anim_env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)) &&
						(!(b_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS))
						)
						{
						MR_ASSERTMSG(NULL, "Cannot collision check against environment without storing lw transforms");
						}
					}
				else
					{
					if (flags_b & MR_COLLCHECK_B_COLLPRIM_SPECIFIC)
						b_collprim = collcheck->mc_b_item;
					else
					if (flags_b & MR_COLLCHECK_B_BBOX_SPECIFIC)
						b_bbox = collcheck->mc_b_item;
					}
	
				// Run through volumes (b)
				while(b_items--)
					{
					if (b_collprim)
						{
						// b_matrix is only non-NULL if MR_COLLCHECK_B_OWNER_FRAME or MR_COLLCHECK_B_OWNER_MATRIX or env with lw transforms
						if (MRCheckCollPrimWithWorldPoint(b_collprim, &a_world_svec, b_matrix, collcheck))
							{
							collcheck->mc_c_item_b = b_collprim;
							goto collision;
							}
						if (b_collprim->cp_flags & MR_COLL_LAST_IN_LIST)
							{
							// Collprim list has been terminated
							goto next_item_a;
							}
						b_collprim++;
						}
					else
					if (b_bbox)
						{
						// b_matrix is only non-NULL if MR_COLLCHECK_B_OWNER_FRAME or MR_COLLCHECK_B_OWNER_MATRIX or env with lw transforms
						if (MRCheckBoundingBoxWithWorldPoint(b_bbox, &a_world_svec, b_matrix, collcheck))
							{
							collcheck->mc_c_item_b = b_bbox;
							goto collision;
							}
						b_bbox++;
						}
					}
				next_part_b:
				if (b_part)	
					b_part++;
				if ((b_anim_env) && (b_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS))
					b_matrix++;
				}
			next_item_a:
			}
		next_part_a:
		if (a_part)	
			a_part++;
		if ((a_anim_env) && (a_anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS))
			a_matrix++;
		}
	return(FALSE);

	collision:
	// Write outputs (note that the low-level collision functions will have written
	// COLLPRIM_FACE, COLLISION_POINT and REFLECTION_VECTOR if necessary)
	//
	// mc_c_item_b has already been written
	//
	// Write mc_c_item_a (note items have already been incremented)
	if (flags_a & MR_COLLCHECK_A_HILITE)
		collcheck->mc_c_item_a = a_hilite - 1;
	else
		collcheck->mc_c_item_a = a_svec - 1;

	collcheck->mc_c_item_a_index = (collcheck->mc_a_size - 1 - a_items);
	collcheck->mc_c_item_b_index = (collcheck->mc_b_size - 1 - b_items);

	return(TRUE);
}
