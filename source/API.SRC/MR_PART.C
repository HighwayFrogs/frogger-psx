/******************************************************************************
*%%%%	mr_part.c
*------------------------------------------------------------------------------
*
*	Basic particle control code
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	24.09.96	Tim Closs		MRCreatePgen now clears out new pg_owner field
*	06.02.97	Tim Closs		Added MRCreateMemfixedWithInstsPgen()
*	18.02.97	Tim Closs		MRCreatePgen() - fixed bug when MR_PF_NO_GEOMETRY was set
*	20.02.97	Tim Closs		MRCreatePgen() - NULL frame now permitted
*	11.04.97	Dean Ashton		Added facility for PGEN initialisers to allocate
*								a specific amount of memory for transient user
*								data, and automatic release of said allocated
*								memory.
*
*%%%**************************************************************************/

#include	"mr_all.h"


/******************************************************************************
*%%%% MRCreatePgen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT object_ptr =	MRCreatePgen(
*										MR_PGEN_INIT*	cp_init,
*										MR_FRAME*		cp_frame,
*										MR_ULONG*		cp_obj_flags,
*										MR_SVEC* 		cp_offset);
*
*	FUNCTION	Creates a particle generator control object linked to the
*				specified frame (or static matrix, if cp_obj_flags is set to
*				MR_OBJ_STATIC). If cp_offset is non-NULL, then the particle
*				generator is offset from the frame by the desired amount in X,
*				Y and Z.
*
*	INPUTS		cp_init			-	Pointer to a particle generator init
*								 	structure.
*				cp_frame		-	Pointer to the frame containing the world
*								 	position/rotation of the generator, or NULL
*								 	if the generator is linked to the world.
*				cp_obj_flags	-	Flags for object creation (typically NULL, 
*									or MR_OBJ_STATIC).		
*				cp_offset		-	Offset from cp_frame, or NULL.
*
*	RESULT		object_ptr		-	Pointer to created particle generator
*								 	object.
*
*	NOTES		Currently this routine asserts that cp_frame is non-NULL. This
*				is because the current implementation of MRCreateObject does
*				not handle NULL frame pointers.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	21.05.96	Dean Ashton		Added cp_obj_flags, to enable use of static
*								matrix as frame for the generator.
*	24.09.96	Tim Closs		Now clears out new pg_owner field
*	18.02.97	Tim Closs		Fixed bug when MR_PF_NO_GEOMETRY was set
*	20.02.97	Tim Closs		NULL frame now permitted
*	11.04.97	Dean Ashton		Added init of pg_user_data_ptr.
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreatePgen(	MR_PGEN_INIT*	cp_init,
							MR_FRAME* 		cp_frame,
							MR_ULONG		cp_obj_flags,
							MR_SVEC*		cp_offset)
{
	MR_OBJECT*				object;
	MR_PGEN*				pgen;
	MR_PTYPE_POINT_GEOM*	cp_point_geom;
	MR_PTYPE_2D_GEOM*		cp_2d_geom;
	MR_PTYPE_3D_GEOM*		cp_3d_geom;
	MR_LONG					max_part;

	MR_ASSERT(cp_init != NULL);


	// Create the object associated with the MR_PGEN
	object = MRCreateObject(MR_OBJTYPE_PGEN, cp_frame, cp_obj_flags, cp_init);

	// Set the particle information pointer and the PGEN update callback
	pgen 						= object->ob_extra.ob_extra_pgen;
	pgen->pg_particle_info 		= (MR_VOID*)(pgen + 1);
	object->ob_move_callback 	= cp_init->pgi_move_callback;

	pgen->pg_type				= cp_init->pgi_type;
	pgen->pg_flags				= cp_init->pgi_flags;
	pgen->pg_prim_size			= (MR_USHORT)cp_init->pgi_prim_size;
	pgen->pg_geom_init_callback	= cp_init->pgi_geom_init_callback;
	pgen->pg_prim_init_callback	= cp_init->pgi_prim_init_callback;
	pgen->pg_move_callback		= cp_init->pgi_move_callback;
	pgen->pg_disp_callback		= cp_init->pgi_disp_callback;
	pgen->pg_gravity			= cp_init->pgi_gravity;
	pgen->pg_max_particles		= cp_init->pgi_max_particles;
	pgen->pg_generator_life		= cp_init->pgi_generator_life;
	pgen->pg_particle_min_life	= cp_init->pgi_particle_min_life;
	pgen->pg_particle_max_life	= cp_init->pgi_particle_max_life;
	pgen->pg_user_data_1		= cp_init->pgi_user_data_1;
	pgen->pg_user_data_2		= cp_init->pgi_user_data_2;
	pgen->pg_next_particle		= NULL;
	pgen->pg_owner				= NULL;
	pgen->pg_user_data_ptr		= NULL;

	if (cp_offset == NULL)
		MR_COPY_SVEC(&pgen->pg_offset, &MRNull_svec);
	else
		MR_COPY_SVEC(&pgen->pg_offset, cp_offset);

	if (!(pgen->pg_flags & MR_PF_NO_GEOMETRY))
		{
		// Initialise the geometry as much as we can...
		max_part = pgen->pg_max_particles;
	
		switch(cp_init->pgi_type)	
			{
			case	MR_PTYPE_POINT:
				cp_point_geom	= (MR_PTYPE_POINT_GEOM*)pgen->pg_particle_info;
				while(max_part--) 
					{
					cp_point_geom->pt_lifetime = 0;
					cp_point_geom++;
					}
				break;
			
			case	MR_PTYPE_3D:
				cp_3d_geom		= (MR_PTYPE_3D_GEOM*)pgen->pg_particle_info;
																								  	
				while(max_part--) 
					{
					cp_3d_geom->pt_lifetime = 0;
					cp_3d_geom++;
					}
				break;
		
			case	MR_PTYPE_2D:
				cp_2d_geom 		= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
		
				while(max_part--) 
					{
					cp_2d_geom->pt_lifetime = 0;
					cp_2d_geom++;
					}
				break;
		
			default:
				MR_ASSERT(FALSE);
				break;
			}
		// Call our creation callback, passing the address of this particular MR_PGEN as a parameter
		// This 'creation' routine should generate the initial list of geometry data.
		if (cp_init->pgi_geom_init_callback != NULL)
			(cp_init->pgi_geom_init_callback)(object);
		}

	// Leave, returning a pointer to our new object
	return(object);
}


/******************************************************************************
*%%%% MRKillPgen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillPgen(
*						MR_OBJECT*	pgen);
*
*	FUNCTION	Starts processing that will destroy all particle instances,
*				and safely kill the object once the GPU primitives have been
*				finished with.
*
*	INPUTS		pgen		-	Pointer to a particle generator object
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillPgen(MR_OBJECT* pgen)
{
	MR_ASSERT(pgen != NULL);

	if (pgen->ob_extra.ob_extra_pgen->pg_user_data_ptr)
		MRFreeMem(pgen->ob_extra.ob_extra_pgen->pg_user_data_ptr);

	MRKillObject(pgen);
}


/******************************************************************************
*%%%% MRShutdownPgen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShutdownPgen(
*						MR_OBJECT*	pgen);
*
*	FUNCTION	Sets the specified generator so it doesn't generate any more
*				particles... when all existing particles have disappeared, then
*				the generator will be killed
*
*	INPUTS		pgen		-	Pointer to a particle generator object
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRShutdownPgen(MR_OBJECT* object)
{
	MR_PGEN*	pgen;

	MR_ASSERT(object != NULL);

	pgen = object->ob_extra.ob_extra_pgen;
	pgen->pg_generator_life = 0;
	pgen->pg_flags 			|= MR_PF_CLOSING_DOWN;
}


/******************************************************************************
*%%%% MRShutdownPgenNow
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShutdownPgenNow(
*						MR_OBJECT*	pgen);
*
*	FUNCTION	Sets the specified generator so it doesn't generate any more
*				particles... and starts the destruction of the generator
*				the generator will be killed
*
*	INPUTS		pgen	-		Pointer to a particle generator object
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRShutdownPgenNow(MR_OBJECT* object)
{
	MR_PGEN*	pgen;

	MR_ASSERT(object != NULL);

	pgen = object->ob_extra.ob_extra_pgen;
	pgen->pg_generator_life = 0;
	pgen->pg_flags 			|= MR_PF_CLOSING_DOWN;
	pgen->pg_flags 			|= MR_PF_INACTIVE;
	object->ob_flags 	 	|= MR_OBJ_DESTROY_BY_DISPLAY;
}


/******************************************************************************
*%%%% MRCreateMemfixedWithInstsPgen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT*	object =	MRCreateMemfixedWithInstsPgen
*										MR_PGEN_INIT*	init,
*										MR_FRAME* 		frame,
*										MR_ULONG		obj_flags,
*										MR_VIEWPORT**	viewports);
*
*	FUNCTION	Calls MRCreatePgen, then creates viewport instances in fixed
*				memory
*
*	INPUTS		init		-	ptr to a particle generator init
*							 	structure.
*				frame		-	ptr to the frame containing the world
*								position/rotation of the generator, or NULL
*								if the generator is linked to the world.
*				obj_flags	-	flags for object creation (typically NULL, 
*								or MR_OBJ_STATIC).		
*				viewports	-	ptr to NULL-terminated list of viewports to
*								instance into
*
*	RESULT		object		-	ptr to created particle generator object
*
*	NOTES		This passes in MRNull_svec as the particle generator offset:
*				this should be filled in by the code afterwards
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreateMemfixedWithInstsPgen(	MR_PGEN_INIT*	init,
											MR_FRAME* 		frame,
											MR_ULONG		obj_flags,
											MR_VIEWPORT**	viewports)
{
#ifdef MR_MEMFIXED_PGEN
	MR_OBJECT*	 	object;
	MR_PGEN_INST*	pgeninst_ptr;
	MR_PGEN_INST*	pgeninst_root_ptr;
	MR_VIEWPORT**	vp_pptr;
	MR_VIEWPORT*	vp;


	MR_ASSERT(frame);
	MR_ASSERT(viewports);
	
	// Create object from fixed memory
	object 			= MRCreatePgen(init, frame, obj_flags | MR_OBJ_MEMFIXED | MR_OBJ_MEMFIXED_WITH_INSTS, &MRNull_svec);

	// Set up instances and link them into viewports
	pgeninst_ptr	= (MR_PGEN_INST*)(((MR_UBYTE*)object) + MRMemfixed_pgen->mm_obj_size);
	vp_pptr			= viewports;
	while(vp = *vp_pptr++)
		{
		pgeninst_root_ptr = vp->vp_pgen_root_ptr;
		if (pgeninst_ptr->pi_next_node = pgeninst_root_ptr->pi_next_node)
			pgeninst_root_ptr->pi_next_node->pi_prev_node = pgeninst_ptr;
	
		pgeninst_root_ptr->pi_next_node	= pgeninst_ptr;
		pgeninst_ptr->pi_prev_node 		= pgeninst_root_ptr;
		pgeninst_ptr->pi_object			= object;
		pgeninst_ptr->pi_kill_timer		= 0;
		object->ob_vp_inst_count++;

		// Call the primitive initialisation routine
		MR_ASSERT(((MR_PGEN*)object->ob_extra)->pg_prim_init_callback != NULL);
		(((MR_PGEN*)object->ob_extra)->pg_prim_init_callback)(pgeninst_ptr);

		pgeninst_ptr = (MR_PGEN_INST*)(((MR_UBYTE*)pgeninst_ptr) + MRMemfixed_pgen->mm_inst_size);
		}
	return(object);
#else
	return(NULL);
#endif
}

