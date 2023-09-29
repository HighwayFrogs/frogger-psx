/******************************************************************************
*%%%% mr_ot.c
*------------------------------------------------------------------------------
*
*	Object (Mesh) Ordering Tables. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	12.09.96	Dean Ashton		Created
*	07.10.96	Tim Closs		Added	MRKillAllOTs()
*	09.07.96	Dean Ashton		Added bias initialisation for OT positioning
*
*%%%**************************************************************************/

#include	"mr_all.h"


MR_OT			MROT_root;
MR_OT*			MROT_root_ptr;
MR_USHORT		MRNumber_of_OTs;


/******************************************************************************
*%%%% MRCreateOT
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OT* ot_ptr =	MRCreateOT(
*								MR_USHORT	otshift,
*								MR_USHORT	otzshift,
*								MR_FRAME*	otframe);
*
*	FUNCTION	Creates a local ordering table suitable for use by mesh instances
*				(both animating and static).
*
*	INPUTS		otshift		-	Defines the size of the local ordering table
*				otzshift	-	User-defined shift value (used to make the
*							 	mesh instances using the ordering table fit
*							 	within the local ordering table
*				otframe		-	Pointer to a frame that defines where the 
*							 	local ordering table will be located in the
*							 	main viewport ordering table. Normally this
*							 	is the frame of the object using the local 
*							 	table.
*
*	RESULT		ot_ptr		-	Pointer to an allocated MR_OT structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.09.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_OT*	MRCreateOT(MR_USHORT otshift, MR_USHORT otzshift, MR_FRAME* otframe)
{
	MR_OT*	ot_ptr;
	
	// Validate parameters
	MR_ASSERT(otshift != NULL);
	MR_ASSERT(otframe != NULL);
																					  
	// Link new OT into list												  
	ot_ptr = MRAllocMem(sizeof(MR_OT) + ((1<<otshift)* 2 * sizeof(MR_ULONG)), "MR_OT");

	if (ot_ptr->ot_next_node = MROT_root_ptr->ot_next_node)
		MROT_root_ptr->ot_next_node->ot_prev_node = ot_ptr;

	MROT_root_ptr->ot_next_node = ot_ptr;
	ot_ptr->ot_prev_node = MROT_root_ptr;

	MRNumber_of_OTs++;

	// Setup MR_OT structure
	ot_ptr->ot_shift			= otshift;
	ot_ptr->ot_zshift			= otzshift;
	ot_ptr->ot_frame			= otframe;
	ot_ptr->ot_flags			= NULL;
	ot_ptr->ot_global_ot_offset	= 0;
	MR_CLEAR_SVEC(&ot_ptr->ot_frame_offset);

	ot_ptr->ot_ot[0] = (MR_ULONG*)(((MR_UBYTE*)ot_ptr) + sizeof(MR_OT));
	ot_ptr->ot_ot[1] = (MR_ULONG*)(((MR_UBYTE*)ot_ptr) + sizeof(MR_OT) + ((1<<otshift) * sizeof(MR_ULONG)));

	ClearOTagR(ot_ptr->ot_ot[0],(1<<ot_ptr->ot_shift));
	ClearOTagR(ot_ptr->ot_ot[1],(1<<ot_ptr->ot_shift));

	return(ot_ptr);
}


/******************************************************************************
*%%%% MRKillOT
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillOT( MR_OT* ot_ptr);
*
*	FUNCTION	Used to kill a previously allocated MR_OT structure (and free
*				all associated memory)
*
*	INPUTS		ot_ptr		-	Pointer to a valid MR_OT structure
*
*	NOTES		If you use this function while it is still in use (by the GPU 
*				for rendering, or by a mesh instance for calculation) then 
*				your code will barf. Therefore it's a good idea to create your
*				local OT prior to your main loop, run your main loop with the
*				relevant objects using the local OT, stop your main loop, kill
*				your viewport, and then kill the OT.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.09.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillOT(MR_OT* ot_ptr)
{
	MR_ASSERT(ot_ptr != NULL);

	// Remove structure from linked list
	ot_ptr->ot_prev_node->ot_next_node = ot_ptr->ot_next_node;
	if	(ot_ptr->ot_next_node)
		ot_ptr->ot_next_node->ot_prev_node = ot_ptr->ot_prev_node;

	// Free structure memory
	MRFreeMem(ot_ptr);

	// Decrease count
	MRNumber_of_OTs--;
}


/******************************************************************************
*%%%% MRClearOTs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRClearOTs(MR_USHORT frame_index)
*
*	FUNCTION	This routine runs through all local ordering tables, clearing
*				the appropriate work ordering table for use later in the frame.
*
*	INPUTS		frame_index	-	The OT index we should be clearing.
*
*	NOTES		This should only be called from MRSwapDisplay(). As such, it's
*				not designed for use by game code. The frame_index is actually
*				passed down from MRSwapDisplay() to ensure that the correct
*				index is cleared.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.09.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRClearOTs(MR_USHORT frame_index)
{
	register MR_OT*	ot_ptr;

	ot_ptr = MROT_root_ptr;
	while(ot_ptr = ot_ptr->ot_next_node)
		{
		ot_ptr->ot_flags &= ~MR_OT_ADDED_TO_GLOBAL;
		ClearOTagR(ot_ptr->ot_ot[frame_index], (1 << ot_ptr->ot_shift));
		}
}


/******************************************************************************
*%%%% MRKillAllOTs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillAllOTs(MR_VOID)
*
*	FUNCTION	Kills all local OTs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillAllOTs(MR_VOID)
{
	while(MROT_root_ptr->ot_next_node)
		MRKillOT(MROT_root_ptr->ot_next_node);
}


/******************************************************************************
*%%%% MRCalculateOTInfoFromMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateOTInfoFromMOF(
*						MR_MOF*	mof_ptr,
*						MR_OT*	ot_ptr)
*
*	FUNCTION	Uses a static or animating MOF to calculate the zshift and
*				frame_offset entries in a MR_OT
*
*	INPUTS		mof_ptr		-	ptr to MR_MOF 	(static or animating)
*				ot_ptr 		-	ptr to MR_OT	(in which this MOF will sit)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateOTInfoFromMOF(	MR_MOF*	mof_ptr,
									MR_OT*	ot_ptr)
{
	MR_VEC	max_vec, min_vec;
	MR_LONG	lx, ly, lz, l, s;


	MR_ASSERT(mof_ptr);
	MR_ASSERT(ot_ptr);

	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		{
		// If we are checking an animation, just check the first static MOF in the file
		mof_ptr	= *(((MR_ANIM_HEADER*)mof_ptr)->ah_static_files);
		}

	MRCalculateMOFVertexExtremes(mof_ptr, &max_vec, &min_vec);	

	// Place frame offset in middle of vertex extreme bounding box
	ot_ptr->ot_frame_offset.vx = (max_vec.vx + min_vec.vx) >> 1;
	ot_ptr->ot_frame_offset.vy = (max_vec.vy + min_vec.vy) >> 1;
	ot_ptr->ot_frame_offset.vz = (max_vec.vz + min_vec.vz) >> 1;

	// Calculate smallest zshift which will fit these vertex extremes into the OT size
	lx = max_vec.vx - min_vec.vx;
	ly = max_vec.vy - min_vec.vy;
	lz = max_vec.vz - min_vec.vz;
	l	= MAX(MAX(lx, ly), lz);
	s	= 0;	

	while((l >> s) >= (1 << ot_ptr->ot_shift))
		s++;

	ot_ptr->ot_zshift = s;
}

