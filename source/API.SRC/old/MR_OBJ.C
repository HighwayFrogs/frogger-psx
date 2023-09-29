/******************************************************************************
*%%%% mr_obj.c
*------------------------------------------------------------------------------
*
*	Object routines
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	28.05.96	Dean Ashton		Changes to MRCreateObject 
*	12.06.96	Tim Closs		Changes to MRKillObject
*	20.11.96	Tim Closs		MRKillObject(): object's frame's fr_count decreased:
*				   				killing off frame altered accordingly
*	06.02.97	Tim Closs		Added new #ifdef MR_MEMFIXED_.. globals
*	13.02.97	Dean Ashton		MRKillObject() now kills lights.. and also checks
*				   				that objects don't have any outstanding instances
*				   				hanging around.
*	14.02.97	Tim Closs		MRCreateObject() now handles MR_PF_NO_GEOMETRY
*	19.02.97	Dean Ashton		Added MRAttachFrameToObject() and 
*				   				MRDetachFrameFromObject()...
*	06.06.97	Tim Closs		MRCreateObject() - last input changed to MR_VOID*
*								Added support for animated polys
*
*%%%**************************************************************************/

#include "mr_all.h"


MR_OBJECT		MRObject_root;
MR_OBJECT*		MRObject_root_ptr;
MR_USHORT		MRNumber_of_objects;

#ifdef MR_MEMFIXED_3DSPRITE
MR_MEMFIXED*	MRMemfixed_3dsprite;
#endif
#ifdef MR_MEMFIXED_PGEN
MR_MEMFIXED*	MRMemfixed_pgen;
#endif
#ifdef MR_MEMFIXED_STATIC_MESH
MR_MEMFIXED*	MRMemfixed_static_mesh;
#endif


/******************************************************************************
*%%%% MRCreateObject
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT*	object_ptr =	MRCreateObject(
*											MR_USHORT	type,
*											MR_FRAME*	frame,
*											MR_ULONG	flags,
*											MR_VOID*	user_0);
*
*	FUNCTION	Create and initialise an MR_OBJECT structure
*
*	INPUTS		type		-	Object type
*				frame		-	Frame to occupy
*				flags		-	Flags
*				user_0		-	User data
*
*	RESULT		object_ptr	-	Pointer to object if successful, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	21.05.96	Tim Closs		Changed prototype to include flags, removed
*					  			user_1 field. This is to allow objects without 
*					  			proper frames (they will point to matrix, and
*					  			be flagged as MR_OBJ_STATIC.)
*	28.05.96	Dean Ashton		If MR_OBJ_STATIC isn't set, then frame must point
*					  			to a valid (non-null) frame. If OBJ_STATIC, and
*					  			the frame is null, then we point to an internal
*					  			identity matrix.
*	06.02.97	Tim Closs		Handles MR_OBJ_MEMFIXED
*	14.02.97	Tim Closs		Now handles MR_PF_NO_GEOMETRY
*	06.06.97	Tim Closs		Last input changed to MR_VOID*
*								Added support for animated polys
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreateObject(	MR_USHORT	type,
							MR_FRAME*	frame,
							MR_USHORT	flags,
							MR_VOID* 	user_0)
{
	MR_OBJECT*		object_ptr = NULL;
	MR_LONG			pg_geom_size = NULL;
	MR_LONG			pg_max_part;
	MR_PGEN_INIT*	pgen_init;
	MR_MESH*		mesh_ptr;
	MR_ULONG		i;

								
	// If frame is NULL, then it has to be flagged as MR_OBJ_STATIC, and it will
	// be replaced with the address of the identity matrix within the API. 
	if (flags & MR_OBJ_STATIC)
		{
		if (frame == NULL)
			frame = (MR_FRAME*)&MRId_matrix;
		}
	else
		{
		MR_ASSERT(frame != NULL);
		frame->fr_count++;
		}


	// Allocate memory for MR_OBJECT and additional structure (eg. MR_MESH)
	switch(type)
		{
		case MR_OBJTYPE_LIGHT:
			object_ptr = (MR_OBJECT*)MRAllocMem(sizeof(MR_OBJECT) + sizeof(MR_LIGHT), "MROBJ_LI");
			break;

		case MR_OBJTYPE_STATIC_MESH:
#ifdef MR_MEMFIXED_STATIC_MESH
			if ((MRMemfixed_static_mesh) && (flags & MR_OBJ_MEMFIXED))
				object_ptr 		= MRAllocMemfixed(MRMemfixed_static_mesh);
			else
#endif
				{
				i				= MRCalculateMOFAnimatedPolys((MR_MOF*)user_0);
				object_ptr 		= (MR_OBJECT*)MRAllocMem(sizeof(MR_OBJECT) + sizeof(MR_MESH) + (i * sizeof(MR_MESH_ANIMATED_POLY)) + sizeof(MR_STATIC_MESH), "MR OBJECT STATIC MESH");
				}
			mesh_ptr			= (MR_MESH*)(((MR_UBYTE*)object_ptr) + sizeof(MR_OBJECT));
			mesh_ptr->me_extra 	= (MR_VOID*)(((MR_UBYTE*)mesh_ptr) + sizeof(MR_MESH));
			mesh_ptr->me_num_animated_polys = i;
			mesh_ptr->me_animated_polys 	= (MR_MESH_ANIMATED_POLY*)(((MR_UBYTE*)mesh_ptr->me_extra.me_extra_void) + sizeof(MR_STATIC_MESH));
			break;

		case MR_OBJTYPE_ANIM_MESH:
			i					= MRCalculateMOFAnimatedPolys((MR_MOF*)user_0);
			object_ptr 			= (MR_OBJECT*)MRAllocMem(sizeof(MR_OBJECT) + sizeof(MR_MESH) + (i * sizeof(MR_MESH_ANIMATED_POLY)) + sizeof(MR_ANIM_MESH), "MR OBJECT ANIM MESH");
			mesh_ptr			= (MR_MESH*)(((MR_UBYTE*)object_ptr) + sizeof(MR_OBJECT));
			mesh_ptr->me_extra 	= (MR_VOID*)(((MR_UBYTE*)mesh_ptr) + sizeof(MR_MESH));
			mesh_ptr->me_num_animated_polys = i;
			mesh_ptr->me_animated_polys 	= (MR_MESH_ANIMATED_POLY*)(((MR_UBYTE*)mesh_ptr->me_extra.me_extra_void) + sizeof(MR_ANIM_MESH));
			break;

		case MR_OBJTYPE_3DSPRITE:
#ifdef MR_MEMFIXED_3DSPRITE
			if ((MRMemfixed_3dsprite) && (flags & MR_OBJ_MEMFIXED))
				object_ptr 		= MRAllocMemfixed(MRMemfixed_3dsprite);
			else
#endif
			object_ptr 			= MRAllocMem(sizeof(MR_OBJECT) + sizeof(MR_3DSPRITE), "MROBJ_SP");
			break;

		case MR_OBJTYPE_PGEN:
#ifdef MR_MEMFIXED_PGEN
			if ((MRMemfixed_pgen) && (flags & MR_OBJ_MEMFIXED))
				object_ptr 		= MRAllocMemfixed(MRMemfixed_pgen);
			else
#endif
				{
				pgen_init = (MR_PGEN_INIT*)user_0;						// Set pointer to initialiser
			
				if (!(pgen_init->pgi_flags & MR_PF_NO_GEOMETRY))
					{
					pg_max_part = pgen_init->pgi_max_particles;

					switch(pgen_init->pgi_type)
						{
						case	MR_PTYPE_POINT:
							pg_geom_size = pg_max_part * sizeof(MR_PTYPE_POINT_GEOM);
						break;
			
						case	MR_PTYPE_3D:
							pg_geom_size = pg_max_part * sizeof(MR_PTYPE_3D_GEOM);
							break;
		
						case	MR_PTYPE_2D:
							pg_geom_size = pg_max_part * sizeof(MR_PTYPE_2D_GEOM);
							break;
		
						default:	  
							MR_ASSERT(FALSE);
							break;
						}
					}
				else
					{
					// No geometry allocated for this particle generator
					pg_geom_size = 0;
					MR_ASSERT(pgen_init->pgi_geom_init_callback == NULL);
					}

				object_ptr = (MR_OBJECT*)MRAllocMem(sizeof(MR_OBJECT) + sizeof(MR_PGEN) + pg_geom_size, "MROBJ_PGN");
				}
			break;

		}
	object_ptr->ob_extra = (MR_VOID*)(((MR_UBYTE*)object_ptr) + sizeof(MR_OBJECT));

	// Link new object into list
	if (object_ptr->ob_next_node = MRObject_root_ptr->ob_next_node)
		MRObject_root_ptr->ob_next_node->ob_prev_node = object_ptr;

	MRObject_root_ptr->ob_next_node = object_ptr;
	object_ptr->ob_prev_node = MRObject_root_ptr;

	MRNumber_of_objects++;

	// Initialise object structure	
	object_ptr->ob_type				= type;
	object_ptr->ob_flags 			= flags;
	object_ptr->ob_vp_inst_count	= 0;

	// Set up object to point to frame.
	object_ptr->ob_frame = frame;
	MR_CLEAR_SVEC(&object_ptr->ob_offset);
	object_ptr->ob_owner = NULL;

	object_ptr->ob_move_callback = NULL;
	object_ptr->ob_disp_callback = NULL;
	object_ptr->ob_dest_callback = NULL;

	return(object_ptr);
}


/******************************************************************************
*%%%% MRKillObject
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillObject(
*						MR_OBJECT*	object);
*
*	FUNCTION	Kill an MR_OBJECT
*
*	INPUTS		object		-	Pointer to the object to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
* 	14.06.96	Dean Ashton		Added automatic frame kill ability.
*	20.11.96	Tim Closs		Object's frame's fr_count decreased: killing of
*								frame altered accordingly
*	06.02.97	Tim Closs		Handles MR_OBJ_MEMFIXED
*	13.02.97	Dean Ashton		Added memory release code for MR_OBJTYPE_LIGHT
*								Added check to make sure objects are killed only
*								when all instances are removed.
*	18.02.97	Tim Closs		MRKillObject() - fixed bug which was ignoring
*								MR_OBJTYPE_ANIM_MESHes
*
*%%%**************************************************************************/

MR_VOID	MRKillObject(MR_OBJECT* object)
{																 
	MR_ASSERT(object != NULL);

	MR_ASSERT(object->ob_vp_inst_count == 0);

	// Remove structure from linked list
	object->ob_prev_node->ob_next_node = object->ob_next_node;
	if	(object->ob_next_node)
		object->ob_next_node->ob_prev_node = object->ob_prev_node;

	// Decrease count
	MRNumber_of_objects--;

	// Call destroy callback (if any)
	if (object->ob_dest_callback)
		(object->ob_dest_callback)(object);

	if (!(object->ob_flags & MR_OBJ_STATIC))
		{
		// We have a problem if the object's frame has a ref count of 0
		MR_ASSERT(object->ob_frame != NULL);
		MR_ASSERT(object->ob_frame->fr_count != 0);
		object->ob_frame->fr_count--;
		
		// Kill object's frame if required
		if (
			(object->ob_flags & MR_OBJ_KILL_FRAME_WITH_OBJECT) &&
			(object->ob_frame->fr_count == 0)
			)
			{
			MRKillFrame(object->ob_frame);
			}
		}

	// Free memory or fixed memory slot
	switch(object->ob_type)
		{
		case MR_OBJTYPE_3DSPRITE:
#ifdef MR_MEMFIXED_3DSPRITE
			if ((MRMemfixed_3dsprite) && (object->ob_flags & MR_OBJ_MEMFIXED))
				MRFreeMemfixed(MRMemfixed_3dsprite, object);
			else
#endif
			MRFreeMem(object);
			break;

		case MR_OBJTYPE_PGEN:
#ifdef MR_MEMFIXED_PGEN
			if ((MRMemfixed_pgen) && (object->ob_flags & MR_OBJ_MEMFIXED))
				MRFreeMemfixed(MRMemfixed_pgen, object);
			else
#endif
			MRFreeMem(object);
			break;

		case MR_OBJTYPE_STATIC_MESH:
#ifdef MR_MEMFIXED_STATIC_MESH
			if ((MRMemfixed_static_mesh) && (object->ob_flags & MR_OBJ_MEMFIXED))
				MRFreeMemfixed(MRMemfixed_static_mesh, object);
			else
#endif
			MRFreeMem(object);
			break;

		case MR_OBJTYPE_ANIM_MESH:
			MRFreeMem(object);
			break;

		case MR_OBJTYPE_LIGHT:
			MRFreeMem(object);
			break;
		}
}


/******************************************************************************
*%%%% MRUpdateObjects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateObjects(MR_VOID);
*
*	FUNCTION	Update all objects in the linked object link
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRUpdateObjects(MR_VOID)
{
	MR_OBJECT*	object_ptr = MRObject_root_ptr;

	while(object_ptr = object_ptr->ob_next_node)
		{
		if (object_ptr->ob_type == MR_OBJTYPE_3DSPRITE)
			MRProcessSpriteAnim(object_ptr->ob_extra.ob_extra_sp_core);

		// Call movement callback
		if (object_ptr->ob_move_callback)
			(object_ptr->ob_move_callback)(object_ptr);
		}
}


/******************************************************************************
*%%%% MRAttachFrameToObject
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAttachFrameToObject(	MR_OBJECT*	object,
*												MR_FRAME*	frame);
*
*	FUNCTION	Attaches a frame to an object, correctly modifying the frame
*				reference counters.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.02.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRAttachFrameToObject(MR_OBJECT* object, MR_FRAME* frame)
{
	MR_ASSERT(object);
	MR_ASSERT(frame);

	// We can't attach to an object if the object has a frame already
	MR_ASSERT(object->ob_frame == NULL);

	object->ob_frame = frame;
	frame->fr_count++;
}


/******************************************************************************
*%%%% MRDetachFrameFramObject
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_FRAME* frame =	MRDetachFrameFromObject(MR_OBJECT*	object);
*
*	FUNCTION	Detaches a frame from an object, correctly modifying the frame
*				reference counters.
*
*	INPUTS		object		-	Object to detach frame from.
*		
*	RESULT		frame			-	Pointer to the frame detached from the object.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.02.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_FRAME*	MRDetachFrameFromObject(MR_OBJECT* object)
{
	MR_FRAME*	frame;

	MR_ASSERT(object);

	// We can't detach from an object if the object is marked as MR_OBJ_STATIC
	MR_ASSERT(!(object->ob_flags & MR_OBJ_STATIC));

	// We can't detach from an object if the object hasn't got a frame
	MR_ASSERT(object->ob_frame != NULL);

	frame = object->ob_frame;
	frame->fr_count--;

	object->ob_frame = NULL;
	object->ob_flags |= MR_OBJ_STATIC;

	return(frame);	
}




