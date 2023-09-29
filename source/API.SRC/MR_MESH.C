/******************************************************************************
*%%%%	mr_mesh.c
*------------------------------------------------------------------------------
*
*	Mesh handling functions
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96	Dean Ashton		Created
*	28.05.96	Tim Closs		MRCreateMesh
*	19.06.96	Tim Closs		MOF2 changes: Updated MRDisplayMeshInstance
*								(now takes model, cel params also)
*	01.08.96	Tim Closs		In MRCreateMesh, removed MR_ASSERT(frame != NULL)
*								to allow static meshes
*	08.08.96	Tim Closs		MRCreateMesh handles anims
*	20.08.96	Dean Ashton		Moved static model related functions to mr_stat.c
*	15.10.96	Tim Closs		MRCreateMesh() - animation handling altered
*	08.11.96	Tim Closs		MRCreateMesh() - model change distances now set
*								up to defaults
*	06.06.97	Tim Closs		Added stuff for animated polys.  New functions:
*								MRCreateMeshAnimatedPolys()
*								MRUpdateMeshAnimatedPolys()
*								MRUpdateMeshesAnimatedPolys()
*								MRUpdateViewportMeshInstancesAnimatedPolys()
*								MRMeshAnimatedPolyPause()
*								MRMeshAnimatedPolySetCel()
*								MRMeshAnimatedPolysSetCels()
*	02.07.97	Dean Ashton		Changed MRUpdateMeshesAnimatedPolys() to not
*								update objects that are dying..
*	18.07.97	Tim Closs		Fixed bugs in:
*								MRUpdateMeshesAnimatedPolys()
*								MRUpdateViewportMeshInstancesAnimatedPolys()
*
*%%%**************************************************************************/

#include "mr_all.h"



/******************************************************************************
*%%%% MRCreateMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT* object_ptr = MRCreateMesh(
*										MR_MOF*		mof_ptr,
*										MR_FRAME*	frame,
*										MR_USHORT	obj_flags,
*										MR_USHORT	mesh_flags)
*
*	FUNCTION	Creates and initialises a MR_MESH structure
*
*	INPUTS		mof_ptr		-	Pointer to mesh data
*				frame		-	Frame for mesh to occupy
*				obj_flags	-	MR_OBJECT flags
*				mesh_flags	-	MR_MESH flags
*
*	RESULT		object_ptr	-	Pointer to created object, or NULL.
*
*	NOTES		Prototypes for movement/display callback need to be defined!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	28.05.96	Tim Closs		Removed callbacks and pass in flags instead
*	01.08.96	Tim Closs		Removed MR_ASSERT(frame != NULL) to allow static
*								frame meshes
*	08.08.96	Tim Closs		Handles anims
*	15.10.96	Tim Closs		Animation handling altered
*	08.11.96	Tim Closs		Model change distances now set up to defaults
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreateMesh(	MR_MOF*		mof_ptr,
							MR_FRAME*	frame,
							MR_USHORT	obj_flags,
							MR_USHORT	mesh_flags)
{
	MR_OBJECT*		object_ptr;
	MR_MESH*		mesh_ptr;
	MR_STATIC_MESH*	smesh_ptr;
	MR_ANIM_MESH*	amesh_ptr;
	MR_USHORT		i;


	MR_ASSERT(mof_ptr != NULL);

	if (mesh_flags & MR_MESH_ANIMATED)
		object_ptr = MRCreateObject(MR_OBJTYPE_ANIM_MESH, frame, obj_flags, mof_ptr);
	else		
		object_ptr = MRCreateObject(MR_OBJTYPE_STATIC_MESH, frame, obj_flags, mof_ptr);

	// Set callbacks
	object_ptr->ob_move_callback = NULL;
	object_ptr->ob_disp_callback = NULL;

	// Default is to accept some lighting
	object_ptr->ob_flags |= (MR_OBJ_ACCEPT_LIGHTS_AMBIENT |
			  				 MR_OBJ_ACCEPT_LIGHTS_PARALLEL |
			  				 MR_OBJ_ACCEPT_LIGHTS_POINT);

	// Successfully created object structure
	mesh_ptr 					= object_ptr->ob_extra.ob_extra_mesh;
	mesh_ptr->me_flags			= mesh_flags;
	mesh_ptr->me_clip_distance	= 0x7fff;

	if (mof_ptr->mm_flags & MR_MOF_ANIMATED_POLYS)
		{
		// Set up MR_MESH_ANIMATED_POLY structures
		MRCreateMeshAnimatedPolys(mesh_ptr, mof_ptr);
		}

	if (mesh_flags & MR_MESH_ANIMATED)
		{
		// Animated mesh
		amesh_ptr					= mesh_ptr->me_extra.me_extra_anim_mesh;
		amesh_ptr->am_environment	= NULL;
		amesh_ptr->am_model_no		= 0;
		}
	else
		{
		// Static mesh
		smesh_ptr				= mesh_ptr->me_extra.me_extra_static_mesh;
		smesh_ptr->sm_mof_ptr	= mof_ptr;
		smesh_ptr->sm_part		= 0;
		smesh_ptr->sm_partcel	= 0;

		// Write default model change distances
		for (i = 0; i < MR_MESH_MAX_CHANGE_DISTS; i++)
			smesh_ptr->sm_mod_change_dists[i] = 0x7fffffff;
		}

	return(object_ptr);
}


/******************************************************************************
*%%%% MRKillMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillMesh(
*						MR_OBJECT*	mesh);
*
*	FUNCTION	Kills a mesh.
*
*	INPUTS		mesh		-	Pointer to mesh object to destroy
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillMesh(MR_OBJECT* mesh)
{
	MR_ASSERT(mesh != NULL);

	MRKillObject(mesh);
}	

/******************************************************************************
*%%%% MRDestroyMeshByDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDestroyMeshByDisplay(
*						MR_OBJECT*	object);
*
*	FUNCTION	Sets up a mesh object to be destroyed safely during the display
*				processing. All instances of the mesh will be deleted.
*
*	INPUTS		object		-	Pointer to mesh to destroy
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDestroyMeshByDisplay(MR_OBJECT* object)
{
	object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
}


/******************************************************************************
*%%%% MRCreateMeshAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCreateMeshAnimatedPolys(
*						MR_MESH*	mesh_ptr,
*						MR_MOF*		mof_ptr)
*
*	FUNCTION	Set up an array of MR_MESH_ANIMATED_POLY structures
*				(already allocated)
*
*	INPUTS		mesh_ptr	-	ptr to MR_MESH
*				mof_ptr		-	ptr to MR_MOF
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCreateMeshAnimatedPolys(	MR_MESH*	mesh_ptr,
									MR_MOF*		mof_ptr)
{
	MR_MESH_ANIMATED_POLY*	anim_poly;
	MR_ULONG				polys, part, pp;
	MR_PART_POLY_ANIM*		part_poly;
	MR_PART*				part_ptr;


	MR_ASSERT(mof_ptr->mm_flags & MR_MOF_ANIMATED_POLYS);

	polys		= mesh_ptr->me_num_animated_polys;
	anim_poly 	= mesh_ptr->me_animated_polys;
	part_ptr	= (MR_PART*)(mof_ptr + 1);

	for (part = 0; part < mof_ptr->mm_extra; part++)
		{
		if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
			{
			// MR_PART has some animated polys
			pp			= *(MR_ULONG*)(part_ptr->mp_pad0);
			part_poly	= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);

			// Set up pp animated polys
			while(pp--)
				{
//				anim_poly->ma_poly_offset		= MRPartGetPrimOffsetFromPointer(mof_ptr, part, part_poly->mp_mprim_ptr); 
				anim_poly->ma_flags				= NULL;
				anim_poly->ma_animlist_entry	= 0;
				anim_poly->ma_duration			= 0;
				anim_poly++;
				part_poly++;
				}
			}
		part_ptr++;
		}	

	mesh_ptr->me_flags 				|= MR_MESH_ANIMATED_POLYS;
	mesh_ptr->me_animation_period 	= 1;
	mesh_ptr->me_animation_timer 	= 0;
}


/******************************************************************************
*%%%% MRUpdateMeshesAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateMeshesAnimatedPolys(MR_VOID)
*
*	FUNCTION	Update all MR_MESH_ANIMATED_POLYs attached to MR_MESHes
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*	02.07.97	Dean Ashton		Changed to not update objects that are dying..
*
*%%%**************************************************************************/

MR_VOID	MRUpdateMeshesAnimatedPolys(MR_VOID)
{
	MR_OBJECT*	object_ptr;
	MR_MESH*	mesh_ptr;


	object_ptr = MRObject_root_ptr;
	while(object_ptr = object_ptr->ob_next_node)
		{
		if	(
			(!(object_ptr->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)) &&
				(
				(object_ptr->ob_type == MR_OBJTYPE_STATIC_MESH) ||
				(object_ptr->ob_type == MR_OBJTYPE_ANIM_MESH)
				)
			)
			{
			mesh_ptr = object_ptr->ob_extra.ob_extra_mesh;
			if 	(
				(mesh_ptr->me_flags & MR_MESH_ANIMATED_POLYS) &&
				(!(mesh_ptr->me_flags & MR_MESH_PAUSE_ANIMATED_POLYS))
				)
				{	
				MRUpdateMeshAnimatedPolys(object_ptr->ob_extra.ob_extra_mesh);
				}
			}
		}
}


/******************************************************************************
*%%%% MRUpdateMeshAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateMeshAnimatedPolys(
*						ME_MESH*	mesh_ptr)
*
*	FUNCTION	Update all MR_MESH_ANIMATED_POLYs attached to a MR_MESH
*
*	INPUT		mesh_ptr	-	ptr to MR_MESH
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRUpdateMeshAnimatedPolys(MR_MESH*	mesh_ptr)
{
	MR_ANIM_MESH*					amesh_ptr;
	MR_ANIM_ENV*					env;
	MR_ANIM_ENV_SINGLE*				env_sing;
	MR_ANIM_ENV_MULTIPLE*			env_mult;
	MR_MOF*							mof_ptr;
	MR_ULONG						polys, parts, pp, anim_entries;
	MR_MESH_ANIMATED_POLY*			anim_poly;
	MR_PART_POLY_ANIM*				part_poly;
	MR_PART*						part_ptr;
	MR_PART_POLY_ANIMLIST_ENTRY*	anim_entry;	


	// Update animation counter
	if (++mesh_ptr->me_animation_timer >= mesh_ptr->me_animation_period)
		{
		mesh_ptr->me_animation_timer = 0;


		// Get pointer to MR_MOF
		if	(mesh_ptr->me_flags & MR_MESH_ANIMATED)
			{
			// Animated mesh
			amesh_ptr	= mesh_ptr->me_extra.me_extra_anim_mesh;
			env			= amesh_ptr->am_environment;
	
			if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
				{
				env_mult 	= env->ae_extra.ae_extra_env_multiple;
				mof_ptr 	= env->ae_header->ah_static_files[env_mult->ae_models[amesh_ptr->am_model_no]->am_static_model];
				}
			else
				{
				env_sing 	= env->ae_extra.ae_extra_env_single;
				mof_ptr 	= env->ae_header->ah_static_files[env_sing->ae_model->am_static_model];
				}
			}
		else
			{
			// Static mesh
			mof_ptr			= mesh_ptr->me_extra.me_extra_static_mesh->sm_mof_ptr;
			}
	
		polys 		= mesh_ptr->me_num_animated_polys;
		anim_poly	= mesh_ptr->me_animated_polys;
		parts 		= mof_ptr->mm_extra;
		part_ptr 	= (MR_PART*)(mof_ptr + 1);
	
		while(parts--)
			{
			if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
				{
				// MR_PART has some animated polys
				pp 			= *(MR_ULONG*)(part_ptr->mp_pad0);
				part_poly	= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);
				while(pp--)
					{
					if (!(anim_poly->ma_flags & MR_MESH_ANIMATED_POLY_PAUSED))
						{
						anim_entries 	= *part_poly->mp_animlist;

						MR_ASSERT(anim_poly->ma_animlist_entry < anim_entries);

						anim_entry 		= ((MR_PART_POLY_ANIMLIST_ENTRY*)(part_poly->mp_animlist + 1)) + anim_poly->ma_animlist_entry;
		
						// Increase MR_MESH_ANIMATED_POLY counter, and consider moving to next anim_entry
						if (++anim_poly->ma_duration >= anim_entry->mp_duration)
							{
							// Move to next anim_entry
							anim_poly->ma_duration = 0;
							if (++anim_poly->ma_animlist_entry >= anim_entries)
								{
								// Restart anim
								anim_poly->ma_animlist_entry = 0;
								}
							}
						}
					anim_poly++;
					part_poly++;
					polys--;
					}
				}
			part_ptr++;
			}
		MR_ASSERTMSG(polys == 0, "Error: number of MR_MESH_ANIMATED_POLYs did not match with number in MR_MOF");
		}
}


/******************************************************************************
*%%%% MRUpdateViewportMeshInstancesAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateViewportMeshInstancesAnimatedPolys(
*						MR_VIEWPORT*	vp)
*
*	FUNCTION	Write to any animated polys for MR_MESH_INSTs in a viewport
*
*	INPUT		vp	-	ptr to MR_VIEWPORT
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*	18.07.97	Tim Closs		Fixed bug: now looks at mesh object flags
*								MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY
*
*%%%**************************************************************************/

MR_VOID	MRUpdateViewportMeshInstancesAnimatedPolys(MR_VIEWPORT*	vp)
{
	MR_MESH*						mesh_ptr;
	MR_MESH_INST*					mesh_inst;
	MR_ANIM_MESH*					amesh_ptr;
	MR_ANIM_ENV*					env;
	MR_ANIM_ENV_SINGLE*				env_sing;
	MR_ANIM_ENV_MULTIPLE*			env_mult;
	MR_MOF*							mof_ptr;
	MR_ULONG						polys, part, pp;
	MR_MESH_ANIMATED_POLY*			anim_poly;
	MR_PART_POLY_ANIM*				part_poly;
	MR_PART*						part_ptr;
	MR_PART_POLY_ANIMLIST_ENTRY*	anim_entry;	
	MR_UBYTE*						poly;
	MR_ULONG*						mprim;
	MR_TEXTURE*						text_ptr;


	mesh_inst = vp->vp_mesh_root_ptr;
	while(mesh_inst = mesh_inst->mi_next_node)
		{

		if	(
			(!(mesh_inst->mi_kill_timer)) &&
			(!(mesh_inst->mi_object->ob_flags & (MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY)))
			)
			{
			mesh_ptr = mesh_inst->mi_object->ob_extra.ob_extra_mesh;
			if (mesh_ptr->me_flags & MR_MESH_ANIMATED_POLYS)
				{
				if (mesh_inst->mi_flags | MR_MESH_INST_DISPLAYED_LAST_FRAME)
					{
					// Mesh has animated polys, and instance was displayed last frame
					//
					// Get pointer to MR_MOF
					if	(mesh_ptr->me_flags & MR_MESH_ANIMATED)
						{
						// Animated mesh
						amesh_ptr	= mesh_ptr->me_extra.me_extra_anim_mesh;
						env			= amesh_ptr->am_environment;
				
						if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
							{
							env_mult 	= env->ae_extra.ae_extra_env_multiple;
							mof_ptr 	= env->ae_header->ah_static_files[env_mult->ae_models[amesh_ptr->am_model_no]->am_static_model];
							}
						else
							{
							env_sing 	= env->ae_extra.ae_extra_env_single;
							mof_ptr 	= env->ae_header->ah_static_files[env_sing->ae_model->am_static_model];
							}
						}
					else
						{
						// Static mesh
						mof_ptr			= mesh_ptr->me_extra.me_extra_static_mesh->sm_mof_ptr;
						}
				
					polys 		= mesh_ptr->me_num_animated_polys;
					anim_poly	= mesh_ptr->me_animated_polys;
					part_ptr 	= (MR_PART*)(mof_ptr + 1);
				
					for (part = 0; part < mof_ptr->mm_extra; part++)
						{
						if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
							{
							// MR_PART has some animated polys
							pp 			= *(MR_ULONG*)(part_ptr->mp_pad0);
							part_poly	= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);
							while(pp--)
								{
								anim_entry 	= ((MR_PART_POLY_ANIMLIST_ENTRY*)(part_poly->mp_animlist + 1)) + anim_poly->ma_animlist_entry;
								text_ptr	= MRTexture_list_ptr[anim_entry->mp_image_id];
								poly		= ((MR_UBYTE*)mesh_inst->mi_prims[part]) + (part_ptr->mp_buff_size * MRFrame_index) + part_poly->mp_poly_offset;
								mprim		= part_poly->mp_mprim_ptr;
				
								// Write tpage, clut and UVs from MR_TEXTURE to poly
								// Note that UV coords 2,3 are swapped (as in MRPresetPartPrims)
								switch(part_poly->mp_mprim_type)
									{
									case MR_MPRIMID_FT3:
										((POLY_FT3*)poly)->tpage 	= text_ptr->te_tpage_id;
										((POLY_FT3*)poly)->clut		= text_ptr->te_clut_id;
										((POLY_FT3*)poly)->u0		= text_ptr->te_u0 + ((MR_MPRIM_FT3*)mprim)->mp_u0;
										((POLY_FT3*)poly)->v0		= text_ptr->te_v0 + ((MR_MPRIM_FT3*)mprim)->mp_v0;
										((POLY_FT3*)poly)->u1		= text_ptr->te_u0 + ((MR_MPRIM_FT3*)mprim)->mp_u1;
										((POLY_FT3*)poly)->v1		= text_ptr->te_v0 + ((MR_MPRIM_FT3*)mprim)->mp_v1;
										((POLY_FT3*)poly)->u2		= text_ptr->te_u0 + ((MR_MPRIM_FT3*)mprim)->mp_u2;
										((POLY_FT3*)poly)->v2		= text_ptr->te_v0 + ((MR_MPRIM_FT3*)mprim)->mp_v2;
										break;
	
									case MR_MPRIMID_FT4:
										((POLY_FT4*)poly)->tpage 	= text_ptr->te_tpage_id;
										((POLY_FT4*)poly)->clut		= text_ptr->te_clut_id;
										((POLY_FT4*)poly)->u0		= text_ptr->te_u0 + ((MR_MPRIM_FT4*)mprim)->mp_u0;
										((POLY_FT4*)poly)->v0		= text_ptr->te_v0 + ((MR_MPRIM_FT4*)mprim)->mp_v0;
										((POLY_FT4*)poly)->u1		= text_ptr->te_u0 + ((MR_MPRIM_FT4*)mprim)->mp_u1;
										((POLY_FT4*)poly)->v1		= text_ptr->te_v0 + ((MR_MPRIM_FT4*)mprim)->mp_v1;
										((POLY_FT4*)poly)->u2		= text_ptr->te_u0 + ((MR_MPRIM_FT4*)mprim)->mp_u3;
										((POLY_FT4*)poly)->v2		= text_ptr->te_v0 + ((MR_MPRIM_FT4*)mprim)->mp_v3;
										((POLY_FT4*)poly)->u3		= text_ptr->te_u0 + ((MR_MPRIM_FT4*)mprim)->mp_u2;
										((POLY_FT4*)poly)->v3		= text_ptr->te_v0 + ((MR_MPRIM_FT4*)mprim)->mp_v2;
										break;
	
									case MR_MPRIMID_GT3:
										((POLY_GT3*)poly)->tpage 	= text_ptr->te_tpage_id;
										((POLY_GT3*)poly)->clut		= text_ptr->te_clut_id;
										((POLY_GT3*)poly)->u0		= text_ptr->te_u0 + ((MR_MPRIM_GT3*)mprim)->mp_u0;
										((POLY_GT3*)poly)->v0		= text_ptr->te_v0 + ((MR_MPRIM_GT3*)mprim)->mp_v0;
										((POLY_GT3*)poly)->u1		= text_ptr->te_u0 + ((MR_MPRIM_GT3*)mprim)->mp_u1;
										((POLY_GT3*)poly)->v1		= text_ptr->te_v0 + ((MR_MPRIM_GT3*)mprim)->mp_v1;
										((POLY_GT3*)poly)->u2		= text_ptr->te_u0 + ((MR_MPRIM_GT3*)mprim)->mp_u2;
										((POLY_GT3*)poly)->v2		= text_ptr->te_v0 + ((MR_MPRIM_GT3*)mprim)->mp_v2;
										break;		   
	
									case MR_MPRIMID_GT4:
										((POLY_GT4*)poly)->tpage 	= text_ptr->te_tpage_id;
										((POLY_GT4*)poly)->clut		= text_ptr->te_clut_id;
										((POLY_GT4*)poly)->u0		= text_ptr->te_u0 + ((MR_MPRIM_GT4*)mprim)->mp_u0;
										((POLY_GT4*)poly)->v0		= text_ptr->te_v0 + ((MR_MPRIM_GT4*)mprim)->mp_v0;
										((POLY_GT4*)poly)->u1		= text_ptr->te_u0 + ((MR_MPRIM_GT4*)mprim)->mp_u1;
										((POLY_GT4*)poly)->v1		= text_ptr->te_v0 + ((MR_MPRIM_GT4*)mprim)->mp_v1;
										((POLY_GT4*)poly)->u2		= text_ptr->te_u0 + ((MR_MPRIM_GT4*)mprim)->mp_u3;
										((POLY_GT4*)poly)->v2		= text_ptr->te_v0 + ((MR_MPRIM_GT4*)mprim)->mp_v3;
										((POLY_GT4*)poly)->u3		= text_ptr->te_u0 + ((MR_MPRIM_GT4*)mprim)->mp_u2;
										((POLY_GT4*)poly)->v3		= text_ptr->te_v0 + ((MR_MPRIM_GT4*)mprim)->mp_v2;
										break;
									}
	
								anim_poly++;
								part_poly++;
								polys--;
								}
							}
						part_ptr++;
						}
					MR_ASSERTMSG(polys == 0, "Error: number of MR_MESH_ANIMATED_POLYs did not match with number in MR_MOF");
					}
				}
			}
		}
}


/******************************************************************************
*%%%% MRMeshAnimatedPolyPause
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMeshAnimatedPolyPause(
*						MR_MESH*	mesh_ptr,
*						MR_ULONG	poly_index)
*
*	FUNCTION	Pause a specific animated poly within a MR_MESH
*
*	INPUTS		mesh_ptr	-	ptr to MR_MESH
*				poly_index	-	index of animated poly (0 = first animated poly)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMeshAnimatedPolyPause(	MR_MESH*	mesh_ptr,
									MR_ULONG	poly_index)
{
	MR_ASSERT(mesh_ptr);
	MR_ASSERT(poly_index < mesh_ptr->me_num_animated_polys);

	mesh_ptr->me_animated_polys[poly_index].ma_flags |= MR_MESH_ANIMATED_POLY_PAUSED;
}


/******************************************************************************
*%%%% MRMeshAnimatedPolySetCel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMeshAnimatedPolySetCel(
*						MR_MESH*	mesh_ptr,
*						MR_ULONG	poly_index,
*						MR_ULONG	cel_index)
*
*	FUNCTION	Set the animated cel of a specific animated poly within a MR_MESH
*
*	INPUTS		mesh_ptr	-	ptr to MR_MESH
*				poly_index	-	index of animated poly (0 = first animated poly)
*				cel_index	-	index of cel within poly's animlist
*
*	NOTE		For speed, this does NOT check if the cel_index is in range.
*				If it is not,  MRUpdateMeshAnimatedPolys() will assert
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMeshAnimatedPolySetCel(	MR_MESH*	mesh_ptr,
									MR_ULONG	poly_index,
									MR_ULONG	cel_index)
{
	MR_ASSERT(mesh_ptr);
	MR_ASSERT(poly_index < mesh_ptr->me_num_animated_polys);

	mesh_ptr->me_animated_polys[poly_index].ma_animlist_entry = cel_index;
}


/******************************************************************************
*%%%% MRMeshAnimatedPolysSetCels
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMeshAnimatedPolysSetCels(
*						MR_MESH*	mesh_ptr,
*						MR_ULONG	cel_index)
*
*	FUNCTION	Set the animated cel of all animated polys within a MR_MESH
*
*	INPUTS		mesh_ptr	-	ptr to MR_MESH
*				cel_index	-	index of cel within poly's animlist
*
*	NOTE		For speed, this does NOT check if the cel_index is in range.
*				If it is not,  MRUpdateMeshAnimatedPolys() will assert
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMeshAnimatedPolysSetCels(	MR_MESH*	mesh_ptr,
									MR_ULONG	cel_index)
{
	MR_MESH_ANIMATED_POLY*	anim_poly;
	MR_ULONG				p;

	
	MR_ASSERT(mesh_ptr);

	p			= mesh_ptr->me_num_animated_polys;
	anim_poly 	= mesh_ptr->me_animated_polys;
	while(p--)
		{
		anim_poly->ma_animlist_entry = cel_index;
		anim_poly++;
		}	
}


