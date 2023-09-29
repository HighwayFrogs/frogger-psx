enum
{
	FROG_HILITE_SPLASH,				// Splash hilite type!!!
};

#define	FROG_MAX_NUM_3D_SPRITES		10

/******************************************************************************
*%%%% CreateLiveEntity3DSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG CreateLiveEntity3DSprites(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function creates splash effects at the points denoted by
*				highlights of the correct type
*
*	INPUTS		live_entity			-	ptr to live entity to create 3d sprites for
*
*	RESULT		The number of 3d sprites created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_ULONG CreateLiveEntity3DSprites(LIVE_ENTITY* live_entity)
{

	// Locals
	MR_MOF*			mof_ptr;
	MR_PART*		part_ptr;
	MR_HILITE*		hilite_ptr;
	MR_USHORT		num_hilites = 0;
	MR_ULONG		num_sprites = 0;
	MR_ULONG		loop_counter;
	MR_ULONG*		sprite_ptrs;
	MR_OBJECT*		sprite_object_ptrs[FROG_MAX_NUM_3D_SPRITES];
	MR_FRAME*		frame_ptr;
	MR_VEC*			sprite_position_ptrs[FROG_MAX_NUM_3D_SPRITES];
	MR_SVEC			rot = {0,0,0};
	MR_VEC			temp_vec;

	// Get pointer to hilites
	mof_ptr = Map_mof_ptrs[Map_form_ptrs[live_entity->le_entity->en_form_id]->fo_mof_id];
	part_ptr = mof_ptr + sizeof(MR_MOF);
	num_hilites = part_ptr->mp_hilites;
	hilite_ptr = part_ptr->mp_hilite_ptr;

	// Are there any highlights ?
	if ( num_hilites )
		{
		// Yes ... loop once for each highlight
		for(loop_counter=0;loop_counter<num_hilites;loop_counter++)
			{
			// Is this hilite of the splash type ?
			if ( hilite_ptr->mh_type == FROG_HILITE_SPLASH )
				{
				// Yes ... assert if too many sprites attempted to be allocated!!!
				MR_ASSERT(num_sprites != FROG_MAX_NUM_3D_SPRITES);

				// Create a frame
				frame_ptr = MRCreateFrame(&live_entity->le_lwtrans->t[0],&rot,NULL);

				// Create a 3D sprite for this highlight
				sprite_object_ptrs[num_sprites] = MRCreate3DSprite(frame_ptr,0,&im_gatso);

				// Store pointer to MR_VEC
				sprite_position_ptrs[num_sprites] = hilite_ptr->mh_target_ptr;

				// Apply orientation to this sprite
				MR_COPY_MAT(&sprite_frame_ptrs[num_sprites]->fr_matrix,live_entity->le_lwtrans);

				// Apply object orientation to sprite position
				MRApplyMatrixVEC(live_entity->le_lwtrans,sprite_position_ptrs[num_sprites],&temp_vec);

				// Add on entity position to sprite position
				MR_ADD_VEC(&temp_vec,&live_entity->le_lwtrans->t[0]);

				// Store sprite position
				MR_COPY_VEC(&frame_ptr->fr_matrix.t[0],&temp_vec);

				// Inc number of sprites allocated
				num_sprites++;
				}
			// Inc hilite pointer
			hilite_ptr++;
			}
		}

	// Did we allocate any sprites ?
	if ( num_sprites )
		{
		// Yes ... allocate chunk of memory equal to number of pointers plus an extra to store the number of sprites
		live_entity->le_sprite_ptrs = MRAlloMem(4+(num_sprites*8),"3D_SPRT");

		// Get pointer to sprite pointers
		sprite_ptrs = live_entity->le_sprite_ptrs;

		// Complete number field
		*sprite_ptrs++ = num_sprites;

		// Loop once for each sprite we allocated
		for(loop_counter=0;loop_counter<num_sprites;loop_counter++)
		{
			// Store sprite object pointer
			*sprite_ptrs++ = (MR_ULONG*)sprite_object_ptrs[loop_counter];

			// Store sprite vertex pointer
			*sprite_ptrs++ = (MR_ULONG*)sprite_position_ptrs[num_sprites];
		}

	// Return the number of sprites allocated
	return num_sprites;

}
			
/******************************************************************************
*%%%% UpdateLiveEntity3DSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateLiveEntity3DSprites(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function updates the splash effects
*
*	INPUTS		live_entity			-	ptr to live entity to update 3d sprites for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID UpdateLiveEntity3DSprites(LIVE_ENTITY* live_entity)
{

	// Locals
	MR_ULONG*		sprite_ptrs;
	MR_ULONG		num_sprites;
	MR_ULONG		loop_counter;
	MR_VEC*			vec_ptr;
	MR_OBJECT*		object_ptr;
	MR_FRAME*		frame_ptr;
	MR_VEC			temp_vec;

	// Are there any 3D sprites for this entity ?
	if ( live_entity->le_sprite_ptrs != NULL )
		{
		// Yes ... get pointer to sprite data
		sprite_ptrs = live_entity->le_sprite_ptrs;

		// Get number of sprites
		num_sprites = *sprite_ptrs++;

		// Loop once for each 3D sprite
		for(loop_counter=0;loop_counter<num_sprites;loop_counter++)
			{

			// Get base position of sprite
			vec_ptr = *sprite_ptrs++;

			// Get pointer to sprite object
			object_ptr = *sprite_ptr++;

			// Get pointer to sprite frame
			frame_ptr = *sprite_ptr++;

			// Apply entities orientation to sprite position
			MRApplyMatrixVEC(live_entity->le_lwtrans,vec_ptr,vec_ptr,&temp_vec);

			// Copy entities orientation in to sprites orientation
			MR_COPY_MAT(&frame_ptr->fr_matrix,live_entity->le_lwtrans);

			// Add on entities position to sprites position
			MR_ADD_VEC(&temp_vec,&live_entity->le_lwtrans->t[0]);

			// Set sprites position
			MR_COPY_VEC(&frame_ptr->fr_matrix.t[0],&temp_vec);

			}
		}

}

/******************************************************************************
*%%%% KillLiveEntity3DSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID KillLiveEntity3DSprites(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function kills any 3D sprites allocated by CreateLiveEntity3DSprites
*
*	INPUTS		live_entity			-	ptr to live entity to create 3d sprites for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID KillLiveEntity3DSprites(LIVE_ENTITY* live_entity)
{

	// Locals
	MR_ULONG*		sprite_ptrs;
	MR_ULONG		num_sprites;
	MR_ULONG		loop_counter;

	// Are there any 3D sprites for this entity ?
	if ( live_entity->le_sprite_ptrs != NULL )
		{ 
		// Yes ... get pointer to sprite object ptrs
		sprite_ptrs = live_entity->le_sprite_ptrs;

		// Get number of sprites
		num_sprites = *sprite_ptrs++;

		// Loop once for each 3D sprite
		for(loop_counter=0;loop_counter<num_sprites;loop_counter++)
			{
			// Kill sprite
			((MR_OBJECT*)sprite_ptrs)->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;

			// Next sprite ( skip MR_OBJECT* and MR_VEC* )!!!
			sprite_ptrs++;
			sprite_ptrs++;
			}
		}

	// Free memory we grabbed during the create
	MRFreeMem(live_entity->le_sprite_ptrs);

	// Invalidate pointer
	live_entity->le_sprite_ptrs = NULL;

}

