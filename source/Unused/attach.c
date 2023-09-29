// Anim lists
MR_ULONG		gulSplashDisplayList[]=
{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash3,
	MR_SPRT_RESTART
};

MR_ULONG		gulWakeDisplayList[]=
{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake4,
	MR_SPRT_RESTART
};

/******************************************************************************
*%%%% CreateLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG CreateLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function creates special effects at the points denoted by
*				hilites of the correct type
*
*	INPUTS		live_entity			-	ptr to live entity to create special effect for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID CreateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{

 	// Locals
	MR_ULONG		num_effects;						// Number of effects we have created for this model
	MR_ULONG		loop_counter;						// Temp loop count
	MR_ULONG		loop_counter_2;						// Temp loop count
	ENTITY_SPECIAL*	special_ptr;						// Pointer to special effects
	ENTITY_SPECIAL	specials[MAX_NUM_SPECIAL_EFFECTS];	// Temp store for special effects
	MR_ULONG		i;									// Temp while count
	MR_FRAME*		frame_ptr;							// Temp pointer to frame used to create sprites etc

//	MR_MOF*			mof_ptr;
//	MR_ANIM_HEADER*	anim_header_ptr;
//	MR_PART*		part_ptr;
//	MR_HILITE*		hilite_ptr;
//	MR_ULONG*		sprite_ptrs;
//	MR_OBJECT*		sprite_object_ptrs[FROG_MAX_NUM_3D_SPRITES];
//	MR_SVEC* 		sprite_position_ptrs[FROG_MAX_NUM_3D_SPRITES];
//	MR_SVEC			rot;
//	MR_SVEC			temp_svec;
//	MR_USHORT		num_static_mofs;
//	MR_ANIM_ENV*	sprite_anim_env_ptr;
//	MR_ULONG		sprite_parts[FROG_MAX_NUM_3D_SPRITES];

	// Initialise
	i = 0;
	num_effects = 0;
	MR_CLEAR_SVEC(&rot);

	// Get pointer to mof
	mof_ptr = Map_mof_ptrs[ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_mof_id];

	// Is MOF animated ?
	if ( MR_MOF_ANIMATED == ( mof_ptr->mm_flags & MR_MOF_ANIMATED ) )
		{
		// Yes ... get pointer to anim header
		anim_header_ptr = (MR_ANIM_HEADER*)mof_ptr;

		// Get number of static mofs
		num_static_mofs = anim_header_ptr->ah_no_of_static_files;

		// Assert if more than one static mof ( currently not coded for more than 1 )!!!
		MR_ASSERT(num_static_mofs == 1);

		// Get pointer to mof
		mof_ptr = *anim_header_ptr->ah_static_files;

		// Store pointer to anim env
		sprite_anim_env_ptr = (MR_ANIM_ENV*)live_entity->le_api_item0;
		}
	else
		{
		// No ... clear pointer to anim env
		sprite_anim_env_ptr = NULL;
		}

	// Get pointer to first part
	part_ptr = (MR_PART*)(mof_ptr + 1);

	// Loop once for each part of mof
	for(loop_counter_2=0;loop_counter_2<mof_ptr->mm_extra;loop_counter_2++)
		{

		// Get hilite info
		i = part_ptr->mp_hilites;
		hilite_ptr = part_ptr->mp_hilite_ptr;

		// Are there any highlights ?
		if ( i )
			{

			// Yes ... loop once for each highlight
			while ( i-- )
				{

				// Assert if too many effects attempted to be allocated!!!
				MR_ASSERT(num_effects != MAX_NUM_SPECIAL_EFFECTS);

				// According to hilite type do ...
				switch ( hilite_ptr->mh_type )
					{

					// Reserved ...
					case HILITE_TYPE_COLLISION:
						break;

					// 3D sprite ...
					case HILITE_TYPE_SPLASH:
					case HILITE_TYPE_WAKE:

						// Set hilite type
						specials[num_effects].es_type = ENTITY_SPECIAL_TYPE_SPRITE;

						// Store part number
						specials[num_effects].es_part_index = loop_counter_2;

						// Store pointer to MR_SVEC
						specials[num_effects].es_vertex = (MR_SVEC*)hilite_ptr->mh_target_ptr;

						// Create a frame
						frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);

						// Create a 3D sprite for this highlight
						if ( hilite_ptr->mh_type == HILITE_TYPE_SPLASH )
							(MR_OBJECT*)specials[num_effects].es_api_item = MRCreate3DSprite(frame_ptr,0,&gulSplashDisplayList);
						else
							(MR_OBJECT*)specials[num_effects].es_api_item = MRCreate3DSprite(frame_ptr,0,&gulWakeDisplayList);

						// Add object to viewport(s)
						for (loop_counter=0;loop_counter<Game_total_viewports;loop_counter++)
							specials[num_effects].es_api_insts[loop_counter] = MRAddObjectToViewport((MR_OBJECT*)specials[num_effects].es_api_item,Game_viewports[loop_counter],0);

						// Inc number of effects
						num_effects++;

						break;

//					// Splash ...
//					case FROG_HILITE_SPLASH:
//						// Yes ... assert if too many sprites attempted to be allocated!!!
//						MR_ASSERT(num_effects != FROG_MAX_NUM_3D_SPRITES);
//
//						// Create a frame
//						frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);
//
//						// Create a 3D sprite for this highlight
//						sprite_object_ptrs[num_effects] = MRCreate3DSprite(frame_ptr,0,&gulSplashDisplayList);
//
//						// Add object to viewport
//						MRAddObjectToViewport(sprite_object_ptrs[num_effects],Game_viewport0,0);
//
//						// Store part number
//						sprite_parts[num_effects] = loop_counter_2;
//
//						// Store pointer to MR_SVEC
//						sprite_position_ptrs[num_effects] = (MR_SVEC*)hilite_ptr->mh_target_ptr;
//
//						// Apply object orientation to sprite position
//						MRApplyMatrixSVEC(live_entity->le_lwtrans,sprite_position_ptrs[num_effects],&temp_svec);
//
//						// Re-orient sprite ( to be flat ) and apply entities orientation
//						rot.vx = 3072;
//						rot.vy = 0;
//						rot.vz = 0;
//						MRRotMatrix(&rot,&frame_ptr->fr_matrix);
//						MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);
//
//						// Add on entity position to sprite position and store sprite position
//						frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
//						frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
//						frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];
//
//						// Inc number of sprites allocated
//						num_effects++;
//
//						break;
//					
//					// Wake ...
//					case FROG_HILITE_WAKE:
//						// Yes ... assert if too many sprites attempted to be allocated!!!
//						MR_ASSERT(num_effects != FROG_MAX_NUM_3D_SPRITES);
//
//						// Create a frame
//						frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);
//
//						// Create a 3D sprite for this highlight
//						sprite_object_ptrs[num_effects] = MRCreate3DSprite(frame_ptr,0,&gulWakeDisplayList);
//
//						// Add object to viewport
//						MRAddObjectToViewport(sprite_object_ptrs[num_effects],Game_viewport0,0);
//
//						// Store part number
//						sprite_parts[num_effects] = loop_counter_2;
//
//						// Store pointer to MR_VEC
//						sprite_position_ptrs[num_effects] = (MR_SVEC*)hilite_ptr->mh_target_ptr;
//
//						// Apply object orientation to sprite position
//						MRApplyMatrixSVEC(live_entity->le_lwtrans,sprite_position_ptrs[num_effects],&temp_svec);
//
//						// Re-orient sprite ( to be flat ) and apply entities orientation
//						rot.vx = 3072;
//						rot.vy = 0;
//						rot.vz = 0;
//						MRRotMatrix(&rot,&frame_ptr->fr_matrix);
//						MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);
//
//						// Add on entity position to sprite position and store sprite position
//						frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
//						frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
//						frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];
//
//						// Inc number of sprites allocated
//						num_effects++;
//
//						break;

					// Particle fountain ...
					case HILITE_TYPE_PARTICLE:
						break;

					// Mesh ...
					case HILITE_TYPE_MESH:
						break;

					// Animated mesh ...
					case HILITE_TYPE_ANIM:
						break;

					// Other ...
					default :

						// Assert if we encounter an unknown type of hilite!
						MR_ASSERT(0);

						break;

					}

				// Inc hilite pointer
				hilite_ptr++;

				};
			}
		// Next part
		part_ptr++;
		}

	// Did we allocate any effects ?
	if ( num_effects )
		{
		// Yes ... allocate chunk of memory equal to number of effects
		live_entity->le_numspecials = num_effects;
		live_entity->le_specials = (MR_ULONG*)MRAllocMem(sizeof(ENTITY_SPECIAL)*num_effects,"ENTITY SPECIALS");

		// Set up temp pointer
		special_ptr = live_entity->le_specials;

		// Loop once for each effect we allocated
		for(loop_counter=0;loop_counter<num_effects;loop_counter++)
			{
			// Copy special data
			memcpy(special_ptr,&specials[loop_counter],sizeof(ENTITY_SPECIAL));

			// Inc pointer
			special_ptr++;
			}
		}
	else
		{
		// No ... blank entity data
		live_entity->le_numspecials = 0;
		live_entity->le_specials = NULL;
		}

}
			
/******************************************************************************
*%%%% UpdateLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function updates the special effects
*
*	INPUTS		live_entity			-	ptr to live entity to update special effects for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID UpdateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY_SPECIAL*	special_ptr;		// Ptr to entity specials
	MR_ULONG		i;					// While count
	MR_SVEC			temp_svec;			// Temp svec
	MR_FRAME*		frame_ptr;			// Ptr to API frame

//	MR_ULONG*		sprite_ptrs;
//	MR_SVEC			rot;
//	MR_MAT			mat;
//	MR_ANIM_ENV*	anim_env_ptr;
//	MR_ULONG		part_num;

	// Are there any effects for this entity ?
	if ( live_entity->le_numspecials )
		{
		// Yes ... get pointer to effects data
		special_ptr = live_entity->le_specials;

		// Get number of effects
		i = live_entity->le_numspecials;

		// Loop once for each effect
		while ( i-- )
			{

			// According to type of effect do ...
			switch(special_ptr->es_type)
				{

				// 3D sprite ...
				case ENTITY_SPECIAL_TYPE_SPRITE:

//					// Get anim env pointer
//					anim_env_ptr = (MR_ANIM_ENV*)*sprite_ptrs++;
//
//					// Get number of part
//					part_num = (MR_ULONG)special_ptr->es_part_index;

					// Get pointer to sprite frame
					frame_ptr = ((MR_OBJECT*)special_ptr->es_api_item)->ob_frame;

					// Initialise temp svec ( offset of sprite from entity base point )
					MR_COPY_SVEC(&temp_svec,special_ptr->es_vertex);

					// Apply entities orientation to sprite position
					MRApplyMatrixSVEC(live_entity->le_lwtrans,&temp_svec,&temp_svec);

					// Re-orient sprite ( to be flat ) and apply entities orientation
					rot.vx = 3072;
					rot.vy = 0;
					rot.vz = 0;
					MRRotMatrix(&rot,&frame_ptr->fr_matrix);
					MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);

					// Add on entities position to sprites position
					frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
					frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
					frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];

//					// Is there a valid anim env pointer ?
//					if ( anim_env_ptr )
//						{
//						// Get part's transform matrix
//						MRAnimEnvGetPartTransform(anim_env_ptr,&mat,0,part_num);
//						MRApplyMatrixVEC(live_entity->le_lwtrans,(MR_VEC*)&mat.t,(MR_VEC*)&mat.t);
//						// Apply translation to sprite
//						MR_ADD_VEC(&frame_ptr->fr_matrix.t[0],&mat.t[0]);
//						}

					break;

				// Particle generator ...
				case ENTITY_SPECIAL_TYPE_PARTICLE:
					break;

				// Mesh ...
				case ENTITY_SPECIAL_TYPE_MESH:
					break;

				// Animating mesh ...
				case ENTITY_SPECIAL_TYPE_ANIM:
					break;

				// Unkown type ...
				default:

					// Assert if we have encountered an unknown special type
					MR_ASSERT(0);

					break;
				}

			// Next effect
			special_ptr++;

			};
		}

}

/******************************************************************************
*%%%% KillLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID KillLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function kills any special effects allocated by CreateLiveEntitySpecialEffects
*
*	INPUTS		live_entity			-	ptr to live entity that had special effects created for it
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID KillLiveEntitySpecials(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY_SPECIAL*	special_ptr;
	MR_ULONG		i;

	// Are there any effects for this entity ?
	if ( live_entity->le_numspecials )
		{ 

		// Yes ... get pointer to sprite object ptrs
		special_ptr = live_entity->le_specials;

		// Get number of effects
		i = live_entity->le_numspecials;

		// Loop once for each effect
		while ( i-- )
			{

			// According to type of effect do ...
			switch ( special_ptr->es_type )
				{

				// 3D Sprites ...
				case ENTITY_SPECIAL_TYPE_SPRITE:
					// Kill sprite
					((MR_OBJECT*)special_ptr->es_api_item)->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
					break;

				// Particle generator ...
				case ENTITY_SPECIAL_TYPE_PARTICLE:
					break;

				// Mesh ...
				case ENTITY_SPECIAL_TYPE_MESH:
					break;

				// Animated mesh ...
				case ENTITY_SPECIAL_TYPE_ANIM:
					break;

				}

			// Next effect
			special_ptr++;

			};

		// Free memory we grabbed during the create
		MRFreeMem(live_entity->le_specials);

		// Invalidate pointer and number
		live_entity->le_specials = NULL;
		live_entity->le_numspecials = 0;

		}

}
