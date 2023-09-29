/******************************************************************************
*%%%% mr_frame.c
*------------------------------------------------------------------------------
*
*	Frame handling routines
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	26.07.96	Tim Closs		Changed MRPointMatrixAtMatrix to
*								MRPointMatrixAtVector for more generality
*	30.07.96	Dean Ashton		Removed MRUpdateFrame(), and changed 
*								MRUpdateFrames().
*	02.09.96	Tim Closs		MRPointMatrixAtVector now takes y param, and calls
*								MRGenerateMatrixFromZAxisAndZYPlane()
*	27.09.96	Dean Ashton		Removed callback from MRCreateFrame() parameters
*	06.01.97	Tim Closs		MRUpdateFrames() - fixed bug in LW calculation
*								MRUpdateFrameLWTransform() - fixed bug in calculation
*								of LW translation
*	21.01.97	Tim Closs		Added MRChangeFrameParent()
*	06.02.97	Tim Closs		Added #ifdef MR_MEMFIXED.. global
*								MRCreate/KillFrame() now handle MR_FRAME_MEMFIXED
*	12.02.97	Tim Closs		MRUpdateFrames() now handles MR_FRAME_REBUILT_LAST_FRAME
*	18.02.97	Dean Ashton		Removed MRKillFrameAtAddress, and added support for
*								MR_FRAME_AT_ADDRESS flag instead.
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix in
*								MRUpdateFrameLWTransform() and
*								MRChangeFrameParent()
*
*%%%**************************************************************************/

#include "mr_all.h"


MR_FRAME		MRFrame_root;
MR_FRAME*		MRFrame_root_ptr;
MR_USHORT		MRNumber_of_frames;


#ifdef MR_MEMFIXED_FRAME
MR_MEMFIXED*	MRMemfixed_frame;
#endif


/******************************************************************************
*%%%% MRCreateFrame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_FRAME* frame_ptr =	MRCreateFrame(
*										MR_VEC*		pos,
*										MR_SVEC*	rot,
*										MR_FRAME*	parent);
*
*	FUNCTION	Creates and initialises an MR_FRAME.
*
*	INPUTS		pos			-	Pointer to MR_VEC holding position to copy
*		 		rot			-	Pointer to MR_SVEC holding angles to copy
*		 		parent		-	Pointer to parent frame (NULL for world)
*
*	RESULT		frame_ptr	-	Pointer to frame if successful, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	27.09.96	Dean Ashton		Removed callback parameter.. it was useless.
*
*%%%**************************************************************************/

MR_FRAME*	MRCreateFrame(	MR_VEC*		pos,
							MR_SVEC*	rot,
							MR_FRAME*	parent)
{
	MR_FRAME*	frame_ptr;

	MR_ASSERT(pos != NULL);
	MR_ASSERT(rot != NULL);

	// Link new frame into list
#ifdef MR_MEMFIXED_FRAME
	if (MRMemfixed_frame)
		{
		frame_ptr 				= MRAllocMemfixed(MRMemfixed_frame);
		frame_ptr->fr_flags 	= MR_FRAME_MEMFIXED;
		}
	else
#endif
		{
		frame_ptr 				= MRAllocMem(sizeof(MR_FRAME), "MR_FRAME");
		frame_ptr->fr_flags 	= NULL;
		}

	if (frame_ptr->fr_next_node = MRFrame_root_ptr->fr_next_node)
		MRFrame_root_ptr->fr_next_node->fr_prev_node = frame_ptr;

	MRFrame_root_ptr->fr_next_node = frame_ptr;
	frame_ptr->fr_prev_node = MRFrame_root_ptr;

	MRNumber_of_frames++;

	// Generate MR_MAT and MR_VEC for frame
	MRRotMatrix(rot, &frame_ptr->fr_matrix);
	frame_ptr->fr_matrix.t[0] = pos->vx;
	frame_ptr->fr_matrix.t[1] = pos->vy;
	frame_ptr->fr_matrix.t[2] = pos->vz;

	// Set up parent
	frame_ptr->fr_parent = parent;

	// Initialise frame movement entries
	frame_ptr->fr_rotation.vx = rot->vx << MR_FP_VEC;
	frame_ptr->fr_rotation.vy = rot->vy << MR_FP_VEC;
	frame_ptr->fr_rotation.vz = rot->vz << MR_FP_VEC;

	frame_ptr->fr_velocity.vx = 0;
	frame_ptr->fr_velocity.vy = 0;
	frame_ptr->fr_velocity.vz = 0;

	frame_ptr->fr_angvel.vx = 0;
	frame_ptr->fr_angvel.vy = 0;
	frame_ptr->fr_angvel.vz = 0;
		
	// Initialise count
	frame_ptr->fr_count = 0;

	// Calculate LW transform
	MRUpdateFrameLWTransform(frame_ptr);
	
	return(frame_ptr);
}


/******************************************************************************
*%%%% MRCreateFrameAtAddress
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_FRAME* frame_ptr =	MRCreateFrameAtAddress(
*										MR_VEC*		pos,
*										MR_SVEC* 	rot,
*										MR_FRAME*	parent,
*										MR_ULONG*	mem);
*
*	FUNCTION	Creates and initialises an MR_FRAME at a fixed address
*
*	INPUTS		pos			-	Pointer to MR_VEC holding position to copy
*				rot			-	Pointer to MR_SVEC holding angles to copy
*				parent		-	Pointer to parent frame (NULL for world)
*				mem			-	Address to create the frame at.
*
*	RESULT		frame_ptr	-	Pointer to frame if successful, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_FRAME*	MRCreateFrameAtAddress(	MR_VEC*		pos,
							 		MR_SVEC*	rot,
							 		MR_FRAME*	parent,
							 		MR_ULONG*	mem)
{
	MR_FRAME*	frame_ptr;

	MR_ASSERT(mem != NULL);

	frame_ptr = (MR_FRAME*)mem;

	// Link new frame into list
	if (frame_ptr->fr_next_node = MRFrame_root_ptr->fr_next_node)
		MRFrame_root_ptr->fr_next_node->fr_prev_node = frame_ptr;

	MRFrame_root_ptr->fr_next_node = frame_ptr;
	frame_ptr->fr_prev_node = MRFrame_root_ptr;

	MRNumber_of_frames++;

	// Generate MR_MAT and MR_VEC for frame
	MRRotMatrix(rot, &frame_ptr->fr_matrix);
	frame_ptr->fr_matrix.t[0] = pos->vx;
	frame_ptr->fr_matrix.t[1] = pos->vy;
	frame_ptr->fr_matrix.t[2] = pos->vz;

	// Set up parent
	frame_ptr->fr_parent 			= parent;

	// Initialise frame movement entries
	frame_ptr->fr_rotation.vx = rot->vx << MR_FP_VEC;
	frame_ptr->fr_rotation.vy = rot->vy << MR_FP_VEC;
	frame_ptr->fr_rotation.vz = rot->vz << MR_FP_VEC;

	frame_ptr->fr_velocity.vx = 0;
	frame_ptr->fr_velocity.vy = 0;
	frame_ptr->fr_velocity.vz = 0;

	frame_ptr->fr_angvel.vx = 0;
	frame_ptr->fr_angvel.vy = 0;
	frame_ptr->fr_angvel.vz = 0;
		
	// Initialise flags and count
	frame_ptr->fr_flags = MR_FRAME_AT_ADDRESS;
	frame_ptr->fr_count = 0;

	// Calculate LW transform
	MRUpdateFrameLWTransform(frame_ptr);
	
	return(frame_ptr);
}


/******************************************************************************
*%%%% MRKillFrame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillFrame(
*						MR_FRAME*	frame);
*
*	FUNCTION	Kills a MR_FRAME structure.
*
*	INPUTS		frame	-		Pointer to the frame to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	13.02.97	Dean Ashton		Added check so you can't kill a frame if it's
*								got an outstanding reference.
*	18.02.97	Dean Ashton		Changed to handle frames created with 
*								MRCreateFrameAtAddress();
*
*%%%**************************************************************************/

MR_VOID	MRKillFrame(MR_FRAME* frame)
{
	MR_ASSERT(frame != NULL);

	MR_ASSERT(frame->fr_count == 0);
	
	// Remove structure from linked list
	frame->fr_prev_node->fr_next_node = frame->fr_next_node;
	if	(frame->fr_next_node)
		frame->fr_next_node->fr_prev_node = frame->fr_prev_node;

#ifdef MR_MEMFIXED_FRAME
	if (frame->fr_flags & MR_FRAME_MEMFIXED)
		MRFreeMemfixed(MRMemfixed_frame, frame);
	else
#endif

	// Free structure memory if we're a dynamically allocated frame
	if (!(frame->fr_flags & MR_FRAME_AT_ADDRESS))
		MRFreeMem(frame);

	// Decrease count
	MRNumber_of_frames--;
}


/******************************************************************************
*%%%% MRUpdateFrames
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateFrames(MR_VOID)
*				
*	FUNCTION	Updates all frames in our linked frame list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	30.07.96	Dean Ashton		Optimised routine, and changed to perform a 
*								pass to update fr_matrix, and a pass to update
*								fr_lw_transform for effective parent/child 
*								handling.
*	06.01.97	Tim Closs		Fixed bug in LW calculation: lineage is now
*								stacked to ensure correct calculation ordering
*	12.02.97	Tim Closs		Now handles MR_FRAME_REBUILT_LAST_FRAME
*
*%%%**************************************************************************/

MR_VOID	MRUpdateFrames(MR_VOID)
{
	register MR_FRAME*	frame_ptr;
	MR_SVEC				frame_svec;
	MR_FRAME*			frame_stack[MR_FRAME_MAX_GENERATIONS];
	MR_FRAME*			parent_ptr;
	MR_FRAME**			frame_stack_ptr;


	frame_ptr = MRFrame_root_ptr;
	while(frame_ptr = frame_ptr->fr_next_node)
		{
		frame_ptr->fr_flags &= ~MR_FRAME_REBUILT_LAST_FRAME;
		if (!(frame_ptr->fr_flags & MR_FRAME_NO_UPDATE))
			{
			// Update frame MR_MAT translation from velocity
			frame_ptr->fr_matrix.t[0] += (frame_ptr->fr_velocity.vx >> MR_FP_VEC);
			frame_ptr->fr_matrix.t[1] += (frame_ptr->fr_velocity.vy >> MR_FP_VEC);
			frame_ptr->fr_matrix.t[2] += (frame_ptr->fr_velocity.vz >> MR_FP_VEC);

			// Update frame angles if necessary
			if ((frame_ptr->fr_angvel.vx) || (frame_ptr->fr_angvel.vy) || (frame_ptr->fr_angvel.vz))
				{
				frame_ptr->fr_rotation.vx += frame_ptr->fr_angvel.vx;
				frame_ptr->fr_rotation.vy += frame_ptr->fr_angvel.vy;
				frame_ptr->fr_rotation.vz += frame_ptr->fr_angvel.vz;

				frame_ptr->fr_flags |= MR_FRAME_REBUILD;
				}

			// Rebuild frame MR_MAT if necessary
			if (frame_ptr->fr_flags & MR_FRAME_REBUILD)
				{
				frame_svec.vx = frame_ptr->fr_rotation.vx >> MR_FP_VEC;
				frame_svec.vy = frame_ptr->fr_rotation.vy >> MR_FP_VEC;
				frame_svec.vz = frame_ptr->fr_rotation.vz >> MR_FP_VEC;
		
				MRRotMatrix(&frame_svec, &frame_ptr->fr_matrix);
	
				frame_ptr->fr_flags &= ~MR_FRAME_REBUILD;
				frame_ptr->fr_flags |= MR_FRAME_REBUILT_LAST_FRAME;
				}
			}
		frame_ptr->fr_flags &= ~MR_FRAME_LW_CALCULATED;
		}

	frame_ptr = MRFrame_root_ptr;
	while(frame_ptr = frame_ptr->fr_next_node)
		{
		if (!(frame_ptr->fr_flags & MR_FRAME_NO_UPDATE))
			{
			// Calculate LW transform for this frame
 			// Step up parent tree, stacking parents whose LWs must be calculated before this one
			frame_stack_ptr = frame_stack;

			// Start in such a way that frame itself is stacked, if LW not already calculated
			parent_ptr = frame_ptr;
			while(parent_ptr)
				{
				if (!(parent_ptr->fr_flags & MR_FRAME_LW_CALCULATED))
					{
					// Stack frame
					MR_ASSERT(frame_stack_ptr < frame_stack + MR_FRAME_MAX_GENERATIONS);
					*frame_stack_ptr = parent_ptr;
					frame_stack_ptr++;
					}
				parent_ptr = parent_ptr->fr_parent;
				}
			// Now pull parent ptr off stack, and calculated LWs
			while(frame_stack_ptr > frame_stack)
				{
				frame_stack_ptr--;
				MRUpdateFrameLWTransform(*frame_stack_ptr);
				(*frame_stack_ptr)->fr_flags |= MR_FRAME_LW_CALCULATED;
				}
			}
		else
			frame_ptr->fr_flags &= ~MR_FRAME_NO_UPDATE;
		}
}

	
/******************************************************************************
*%%%% MRUpdateFrameLWTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateFrameLWTransform(
*						MR_FRAME*	frame);
*
*	FUNCTION	Calculates a frames Local->World transformation matrix
*
*	INPUTS		frame	-		Pointer to the frame to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	06.01.97	Tim Closs		Fixed bug in calculation of LW translation
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix
*
*%%%**************************************************************************/

MR_VOID	MRUpdateFrameLWTransform(MR_FRAME* frame)
{
	MR_FRAME*	framepc;
	MR_VEC		vec;
	MR_SVEC		svec;

	
	MR_ASSERT(frame != NULL);

	// Calculate frame's LW transform
	MR_COPY_MAT(&frame->fr_lw_transform, &frame->fr_matrix);
	MR_CLEAR_VEC(frame->fr_lw_transform.t);

	framepc = frame;

	// Step up the frame heirachy, modifying fr_lw_transform:
	while (framepc->fr_parent)
		{
		// Frame has a parent
		MR_SVEC_EQUALS_VEC(&svec, (MR_VEC*)framepc->fr_matrix.t);
		MRApplyMatrix(&framepc->fr_parent->fr_lw_transform, &svec, &vec);
		MR_ADD_VEC(frame->fr_lw_transform.t, &vec);

		MRMulMatrixABB(&framepc->fr_parent->fr_matrix, &frame->fr_lw_transform);
		framepc = framepc->fr_parent;
		}

	MR_ADD_VEC(frame->fr_lw_transform.t, framepc->fr_matrix.t);
}
	

/******************************************************************************
*%%%% MRInitialiseFrame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseFrame(
*						MR_FRAME*	frame);
*
*	FUNCTION	Initialise an existing frame structure to be linked to the world
*
*	INPUTS		frame		-	Pointer to the frame to initialise
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseFrame(MR_FRAME* frame)
{
	MR_ASSERT(frame != NULL);

	MR_INIT_MAT(&frame->fr_matrix);
	MR_INIT_MAT(&frame->fr_lw_transform);

	MR_CLEAR_VEC(frame->fr_matrix.t);
	MR_CLEAR_VEC(&frame->fr_rotation);
	MR_CLEAR_VEC(&frame->fr_velocity);
	MR_CLEAR_VEC(&frame->fr_angvel);

	frame->fr_flags = 0;
}


/******************************************************************************
*%%%% MRPointMatrixAtVector
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRPointMatrixAtVector(
*						MR_MAT*	mat,
*						MR_VEC*	vec,
*						MR_VEC*	y);
*
*	FUNCTION	Point matrix at vector
*
*	INPUTS		mat		-		matrix to point
*				vec		-		position to point at
*				y		-		other vector used to generate ZY plane for roll
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	02.09.96	Tim Closs		Now takes y param, and calls
*								MRGenerateMatrixFromZAxisAndZYPlane()
*
*%%%**************************************************************************/

MR_VOID	MRPointMatrixAtVector(	MR_MAT*	mat,
								MR_VEC*	vec,
								MR_VEC*	y)
{
	MR_VEC	d;

	MR_ASSERT(mat != NULL);
	MR_ASSERT(vec != NULL);

	MR_SUB_VEC_ABC(vec, mat->t, &d);
	MRNormaliseVEC(&d, &d);
	MRGenerateMatrixFromZAxisAndZYPlane(mat, &d, y);
}


/******************************************************************************
*%%%% MRChangeFrameParent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRChangeFrameParent(
*						MR_FRAME*	frame,
*						MR_FRAME*	parent)
*
*	FUNCTION	Change a frame's parent, and update fr_matrix as required
*
*	INPUTS		frame		-	frame whose parent we wish to change
*				parent		-	ptr to new parent frame (or NULL)
*
*	NOTES		This only changes fr_matrix, NOT fr_lw_transform.  fr_lw_transform
*				can be updated by calling MRUpdateFrameLWTransform(), or waiting for
*				the next call to MRUpdateFrames().
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.01.97	Tim Closs		Created
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix
*
*%%%**************************************************************************/

MR_VOID	MRChangeFrameParent(MR_FRAME*	frame,
							MR_FRAME*	parent)
{
	MR_MAT	matrix;
	MR_SVEC	svec;


	MR_ASSERT(frame);
	
	if (frame->fr_parent)
		{
		// Frame currently has a parent
		if (parent)
			{
			// Move to a new parent
			MRTransposeMatrix(&parent->fr_lw_transform, &matrix);
			MRMulMatrixABC(&matrix, &frame->fr_lw_transform, &frame->fr_matrix);

			MR_SUB_VEC_ABC(frame->fr_lw_transform.t, parent->fr_lw_transform.t, frame->fr_matrix.t);
			MR_SVEC_EQUALS_VEC(&svec, (MR_VEC*)frame->fr_matrix.t);
			MRApplyMatrix(&matrix, &svec, (MR_VEC*)frame->fr_matrix.t);
			}
		else
			{
			// Move to no parent
			MR_COPY_MAT(&frame->fr_matrix, &frame->fr_lw_transform);
			MR_COPY_VEC(frame->fr_matrix.t, frame->fr_lw_transform.t);
			}
		}
	else
		{
		// Frame currently has no parent
		if (parent)
			{
			// Move to a parent
			MRTransposeMatrix(&parent->fr_lw_transform, &matrix);
			MRMulMatrixABC(&matrix, &frame->fr_lw_transform, &frame->fr_matrix);

			MR_SUB_VEC_ABC(frame->fr_lw_transform.t, parent->fr_lw_transform.t, frame->fr_matrix.t);
			MR_SVEC_EQUALS_VEC(&svec, (MR_VEC*)frame->fr_matrix.t);
			MRApplyMatrix(&matrix, &svec, (MR_VEC*)frame->fr_matrix.t);
			}
		}

	frame->fr_parent = parent;
}
