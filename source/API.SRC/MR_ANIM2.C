/******************************************************************************
*%%%% mr_anim2.c
*------------------------------------------------------------------------------
*
*	Functions for handling multiple environments
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	24.03.97	Tim Closs		Created
*	11.06.97	Dean Ashton		Fixed bug in MRAnimEnvMultipleSetImportedTransform()
*								where matrix_pptr was incorrectly used after being
*								incremented.
*
*%%%**************************************************************************/

#include "mr_all.h"


/******************************************************************************
*%%%% MRAnimEnvMultipleCreate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvMultipleCreate(MR_VOID)
*
*	FUNCTION	Allocates space for and initialises a multiple anim environmenet
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	10.11.96	Tim Closs		Clears off some MULTIPLE stuff
*	17.01.97	Tim Closs		Sets vp_inst_count and model_set_ptr
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvMultipleCreate(MR_VOID)
{
	MR_ANIM_ENV* env;

	env	= MRAllocMem(sizeof(MR_ANIM_ENV) + sizeof(MR_ANIM_ENV_MULTIPLE), "MRAN_ENV");

	env->ae_prev_node 			= NULL;
	env->ae_next_node 			= NULL;
	env->ae_flags				= (MR_ANIM_ENV_IS_MULTIPLE | MR_ANIM_ENV_DEFAULT_FLAGS);
	env->ae_special_flags		= NULL;
	env->ae_update_count		= 0;
	env->ae_update_period		= 1;
	env->ae_vp_inst_count		= 0;
	env->ae_header				= NULL;
	env->ae_model_set			= NULL;
	env->ae_extra.ae_extra_void	= (MR_VOID*)((MR_UBYTE*)env) + sizeof(MR_ANIM_ENV);

	// Set up MULTIPLE stuff
	env->ae_extra.ae_extra_env_multiple->ae_parts_flags 		= NULL;
	env->ae_extra.ae_extra_env_multiple->ae_events				= NULL;
	env->ae_extra.ae_extra_env_multiple->ae_lw_transforms		= NULL;
	env->ae_extra.ae_extra_env_multiple->ae_imported_transforms	= NULL;
	env->ae_extra.ae_extra_env_multiple->ae_parameters			= NULL;
	env->ae_extra.ae_extra_env_multiple->ae_user_struct			= NULL;

	MRNumber_of_anim_envs++;
	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleInit(
*						MR_ANIM_ENV* 	env,
*						MR_ANIM_HEADER*	anim,
*						MR_USHORT	 	model_set,
*						MR_USHORT	 	n)
*
*	FUNCTION	Initialises a multiple anim environment to receive precisely n models
*				from a particular model set
*
*	INPUTS		env			-	ptr to environment to initialise
*				anim		-	ptr to animation file to initialise from
*				model_set	-	index of model set to load from
*				n			-	number of models to receive
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	01.17.96	Tim Closs		Handles model_set input.  Makes no allocation
*								for lw_transforms or event_list
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleInit(	MR_ANIM_ENV*	env,
								MR_ANIM_HEADER*	anim,
								MR_USHORT		model_set,
								MR_USHORT		n)
{
	// The following arrays must be allocated.  Each has n entries (of varying size):
	//
	// ae_models
	// ae_objects
	// ae_cel_number
	// ae_action_number
	// ae_last_cel_number
	// ae_last_action_number
	// ae_total_cels
	// ae_transforms
	// ae_no_of_transforms
	// ae_model_order
	// ae_parts_flags
	// ae_imported_transforms
	//
	//	This allocation is done in a single block, starting with ae_models, so can be
	// freed with MRFreeMem(env_mult->ae_models);


	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				size, i;
	MR_USHORT				offsets[12];
	MR_ANIM_MODEL**			model_pptr;
	MR_OBJECT**				object_pptr;
	MR_SHORT*				cel_num_ptr;
	MR_MAT34**				transform_pptr;
	MR_SHORT**				num_transform_pptr;
	MR_UBYTE*				model_order_ptr;
	MR_UBYTE**				part_flags_pptr;
	MR_MAT***				transform_ppptr;


	MR_ASSERT(env);
	MR_ASSERT(anim);
	MR_ASSERT(env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE);	
	MR_ASSERT(model_set < anim->ah_no_of_model_sets);

	env->ae_header		= anim;
	env->ae_model_set	= &anim->ah_model_sets[model_set];

	env_mult 			= env->ae_extra.ae_extra_env_multiple;

	size				= 0;
	offsets[0]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_ANIM_MODEL*))));		// ae_models
	offsets[1]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_OBJECT*))));			// ae_objects
	offsets[2]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT))));				// ae_cel_number
	offsets[3]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT))));				// ae_action_number
	offsets[4]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT))));				// ae_last_cel_number
	offsets[5]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT))));				// ae_last_action_number
	offsets[6]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT))));				// ae_total_cels
	offsets[7]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_MAT34*))));				// ae_transforms
	offsets[8]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_SHORT*))));				// ae_no_of_transforms
	offsets[9]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_UBYTE))));				// ae_model_order
	offsets[10]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_UBYTE*))));				// ae_parts_flags
	offsets[11]			= (size += MR_WORD_ALIGN(n * (sizeof(MR_MAT34**))));			// ae_imported_transforms

	env_mult->ae_models = MRAllocMem(size, "MULTXTRA");

	env_mult->ae_objects				= (MR_OBJECT**)		(((MR_UBYTE*)env_mult->ae_models) + offsets[0]);
	env_mult->ae_cel_number				= (MR_SHORT*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[1]);
	env_mult->ae_action_number			= (MR_SHORT*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[2]);
	env_mult->ae_last_cel_number		= (MR_SHORT*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[3]);
	env_mult->ae_last_action_number		= (MR_SHORT*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[4]);
	env_mult->ae_total_cels				= (MR_SHORT*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[5]);
	env_mult->ae_transforms				= (MR_MAT34**) 		(((MR_UBYTE*)env_mult->ae_models) + offsets[6]);
	env_mult->ae_no_of_transforms		= (MR_SHORT**) 		(((MR_UBYTE*)env_mult->ae_models) + offsets[7]);
	env_mult->ae_model_order			= (MR_UBYTE*)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[8]);
	env_mult->ae_parts_flags			= (MR_UBYTE**) 		(((MR_UBYTE*)env_mult->ae_models) + offsets[9]);
	env_mult->ae_imported_transforms	= (MR_MAT***)  		(((MR_UBYTE*)env_mult->ae_models) + offsets[10]);

	// Initialise ae_models
	model_pptr	= env_mult->ae_models;
	i			= n;
	while(i--)
		*model_pptr++ = NULL;

	// Initialise ae_objects
	object_pptr	= env_mult->ae_objects;
	i			= n;
	while(i--)
		*object_pptr++ = NULL;

	// Initialise ae_no_of_models
	env_mult->ae_no_of_models = n;

	// Initialise these 5 (MUST be consecutive):
	// ae_cel_number
	// ae_action_number
	// ae_last_cel_number
	// ae_last_action_number
	// ae_total_cels
	cel_num_ptr	= env_mult->ae_cel_number;
	i			= n * 5;
	while(i--)
		*cel_num_ptr++ = -1;

	// Initialise ae_transforms
	transform_pptr	= env_mult->ae_transforms;
	i				= n;
	while(i--)
		*transform_pptr++ = NULL;

	// Initialise ae_no_of_transforms
	num_transform_pptr	= env_mult->ae_no_of_transforms;
	i					= n;
	while(i--)
		*num_transform_pptr++ = NULL;

	// Initialise ae_model_order
	model_order_ptr	= env_mult->ae_model_order;
	i				= n;
	while(i--)
		*model_order_ptr++ = 0;

	// Initialise ae_parts_flags
	part_flags_pptr	= env_mult->ae_parts_flags;
	i				= n;
	while(i--)
		*part_flags_pptr++ = NULL;

	// Initialise ae_imported_transforms
	transform_ppptr	= env_mult->ae_imported_transforms;
	i				= n;
	while(i--)
		*transform_ppptr++ = NULL;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleAddModel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleAddModel(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		model)
*
*	FUNCTION	Adds a model to a multiple environment
*
*	INPUTS		env			-	ptr to multiple environment
*				model		-	index of model within model set
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	17.01.97	Tim Closs		Removed model_set input
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleAddModel(	MR_ANIM_ENV*	env,
									MR_USHORT		model)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_MODEL**			model_pptr;
	MR_ANIM_MODEL*			model_ptr;
	MR_USHORT				n;


	MR_ASSERT(env);
	MR_ASSERT(env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE);	

	env_mult	= env->ae_extra.ae_extra_env_multiple;

	// We find the first free model entry in the environment by looking for a NULL model pointer
	model_pptr	= env_mult->ae_models;
	for (n = 0; n < env_mult->ae_no_of_models; n++)
		{
		if (*model_pptr == NULL)
			{
			// Found free model entry within required size
			model_ptr = &env->ae_model_set->am_models[model];

			if (env->ae_flags & MR_ANIM_ENV_DISPLAY_LIMITED_PARTS)
				{
				// Want to allocate an extra array of bytes of size the number of parts in model
				MR_ASSERT(env_mult->ae_parts_flags[n] == NULL);
				env_mult->ae_parts_flags[n]	= MRAllocMem(MR_WORD_ALIGN(model_ptr->am_no_of_parts), "PARTFLGS");
				}

			env_mult->ae_models[n]	= model_ptr;
			return;
			}
		model_pptr++;
		}

	// If we got here, we failed to find a free model entry in the multiple environment
	MR_ASSERTMSG(NULL, "Failed to find free slot within multiple environment");
}


/******************************************************************************
*%%%% MRAnimEnvMultipleEndInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleEndInit(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Does any tidying up after all models have been added to a 
*				multiple environment
*
*	INPUTS		env			-	ptr to multiple environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleEndInit(MR_ANIM_ENV*	env)
{
	MR_ASSERT(env);

	// Nothing to do until constraints implemented
}


/******************************************************************************
*%%%% MRAnimEnvMultipleLoad
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleLoad(
*						MR_ANIM_ENV*	env,
*						MR_ANIM_HEADER*	anim,
*						MR_USHORT		model_set)
*
*	FUNCTION	Take all models from a model set and load them into a
*				multiple environment
*
*	INPUTS		env			-	ptr to empty environment structure
*				anim		-	ptr to MR_MOF (animation file)
*				model_set	-	index of model set within animation file
*
*	RESULT		TRUE if successful, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleLoad(	MR_ANIM_ENV*	env,
								MR_ANIM_HEADER*	anim,
								MR_USHORT		model_set)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_MODEL_SET*		model_set_ptr;
	MR_USHORT				n, i;


	MR_ASSERT(env);
	MR_ASSERT(anim);
	MR_ASSERT(model_set < anim->ah_no_of_model_sets);
	
	env_mult 		= env->ae_extra.ae_extra_env_multiple;
	model_set_ptr	= &anim->ah_model_sets[model_set];
	n				= model_set_ptr->am_no_of_models;

	MRAnimEnvMultipleInit(env, anim, model_set, n);
	for (i = 0; i < n; i++)
		{
		MRAnimEnvMultipleAddModel(env, i);
		}
}


/******************************************************************************
*%%%% MRAnimEnvMultipleCreateWhole
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvMultipleCreateWhole(
*										MR_ANIM_HEADER*	anim,
*										MR_USHORT		model_set,
*										MR_USHORT		obj_flags,
*										MR_FRAME*		frame)
*
*	INPUTS		anim		-	ptr to MR_MOF (animation file)
*				model_set	-	index of model set within animation file
*				obj_flags	-	flags for MR_OBJECT of type MR_MESH
*				frame		-	ptr to frame
*
*	FUNCTION	Allocates space for and initialises a multiple environment, then
*				loads a model set into it, creates a mesh and links the environment
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvMultipleCreateWhole(	MR_ANIM_HEADER*	anim,
											 	MR_USHORT		model_set,
											 	MR_USHORT		obj_flags,
											 	MR_FRAME*		frame)
{
	MR_ANIM_ENV*	env;
	
	MR_ASSERT(anim);
	MR_ASSERT(frame);

	env = MRAnimEnvMultipleCreate();
	MRAnimEnvMultipleLoad(env, anim, model_set);
	MRAnimEnvCreateMeshes(env, frame, obj_flags);
	MRAnimLinkEnv(env);

	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE	flags	=	MRAnimEnvMultipleSetPartFlags(
*							   			MR_ANIM_ENV*	env,
*							   			MR_USHORT		model,
*							   			MR_USHORT		part,
*							   			MR_UBYTE		mask)
*
*	FUNCTION	Sets all bits set in the mask
*							
*	INPUTS		env			-	ptr to environment (multiple)
*				model		-	index of model within environment
*				part		-	index of part within model
*				mask		-	bits to set
*
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Handles allocations
*	17.02.97	Tim Closs		Now handles MR_ANIM_PART_REDUNDANT
*
*%%%**************************************************************************/

MR_UBYTE	MRAnimEnvMultipleSetPartFlags(	MR_ANIM_ENV*	env,
						  					MR_USHORT		model,
		  									MR_USHORT		part,
		  									MR_UBYTE		mask)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				b;
	MR_UBYTE*				byte_ptr;


	MR_ASSERT(env);

	env_mult	= env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);

	if ((mask & MR_ANIM_PART_REDUNDANT) && (env->ae_vp_inst_count))
		MR_ASSERTMSG(NULL, "Cannot set MR_ANIM_PART_REDUNDANT after environment has been instanced");

	if (env_mult->ae_parts_flags[model] == NULL)
		{
		// Parts flags do not exist for this model - make allocation
		b	 			   				= MR_WORD_ALIGN(env_mult->ae_models[model]->am_no_of_parts);
		env_mult->ae_parts_flags[model] = MRAllocMem(b, "PARTFLGS");
		byte_ptr						= (MR_UBYTE*)env_mult->ae_parts_flags[model];
		while(b--)
			*byte_ptr++ = MR_ANIM_PART_DISPLAY;
		}

	env_mult->ae_parts_flags[model][part] |= mask;
	return(env_mult->ae_parts_flags[model][part]);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleClearPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE	flags	=	MRAnimEnvMultipleClearPartFlags(
*										MR_ANIM_ENV*	env,
*										MR_USHORT		model,
*										MR_USHORT		part,
*										MR_UBYTE		mask)
*
*	FUNCTION	Clears all bits set in the mask
*
*	INPUTS		env			-	ptr to environment (single)
*				model		-	index of model within environment
*				part		-	index of part within model
*				mask		-	bits to clear
*							
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Handles allocations
*	17.02.97	Tim Closs		Now handles MR_ANIM_PART_REDUNDANT
*
*%%%**************************************************************************/

MR_UBYTE	MRAnimEnvMultipleClearPartFlags(MR_ANIM_ENV*	env,
							  				MR_USHORT		model,
		  									MR_USHORT		part,
		  									MR_UBYTE		mask)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT 				b;
	MR_UBYTE* 				byte_ptr;


	MR_ASSERT(env);

	if (mask & MR_ANIM_PART_REDUNDANT)
		MR_ASSERTMSG(NULL, "It is illegal to clear this part flag");

	env_mult	= env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);

	if (env_mult->ae_parts_flags[model] == NULL)
		{
		// Parts flags do not exist for this model - make allocation
		b	  							= MR_WORD_ALIGN(env_mult->ae_models[model]->am_no_of_parts);
		env_mult->ae_parts_flags[model]	= MRAllocMem(b, "PARTFLGS");
		byte_ptr					   	= (MR_UBYTE*)env_mult->ae_parts_flags[model];
		while(b--)
			*byte_ptr++ = MR_ANIM_PART_DISPLAY;
		}

	env_mult->ae_parts_flags[model][part] &= ~mask;
	return(env_mult->ae_parts_flags[model][part]);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleGetPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE	flags	=	MRAnimEnvMultipleGetPartFlags(
*						  				MR_ANIM_ENV*	env,
*						  				MR_USHORT		part)
*
*	FUNCTION	Get the part flags
*
*	INPUTS		env			-	ptr to environment (single)
*				model		-	index of model within environment
*				part		-	index of part within model
*
*	RESULT		flags		-	part flags
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_UBYTE	MRAnimEnvMultipleGetPartFlags(	MR_ANIM_ENV*	env,
						  					MR_USHORT		model,
						  					MR_USHORT		part)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);
	MR_ASSERT(env_mult->ae_parts_flags[model]);

	return(env_mult->ae_parts_flags[model][part]);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleDeletePartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_VOID	MRAnimEnvMultipleDeletePartFlags(
*			 			MR_ANIM_ENV*		env)
*
*	FUNCTION 	Frees any parts flags allocations
*
*	INPUTS		env			-	ptr to multiple environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleDeletePartFlags(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT					model;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	for (model = 0; model < env_mult->ae_no_of_models; model++)
		{
		if (env_mult->ae_parts_flags[model])
			{
			MRFreeMem(env_mult->ae_parts_flags[model]);
			env_mult->ae_parts_flags[model] = NULL;
			}
		}

	env->ae_special_flags &= ~(MR_ANIM_ENV_DISPLAY_LIMITED_PARTS | MR_ANIM_ENV_IMPORTED_TRANSFORMS);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleCreateLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MAT**	matrix_pptr	=	MRAnimEnvMultipleCreateLWTransforms(
*											MR_ANIM_ENV*	env)
*
*	FUNCTION	Allocates space for one LW transform per part, and returns
*				pointer to block of matrix ptrs (one per model)
*
*	INPUTS		env			-	ptr to multiple environment
*
*	RESULT		matrix_pptr	-	ptr to block of matrix ptrs (one per model)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_MAT**	MRAnimEnvMultipleCreateLWTransforms(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_MAT**				matrix_pptr;
	MR_MAT*					transform_ptr;
	MR_ANIM_MODEL**			model_pptr;
	MR_USHORT				m, b;


	MR_ASSERT(env);

	env_mult	= env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(env_mult->ae_lw_transforms == NULL);

	// Count total parts in environment
	model_pptr	= env_mult->ae_models;
	m			= env_mult->ae_no_of_models;
	b			= 0;
	while(m--)
		{
		b += (*model_pptr)->am_no_of_parts;
		model_pptr++;
		}

	matrix_pptr					= MRAllocMem((sizeof(MR_MAT) * b) + (sizeof(MR_MAT*) * env_mult->ae_no_of_models), "LW_TRANS");
	env_mult->ae_lw_transforms	= matrix_pptr;
	transform_ptr				= (MR_MAT*)(((MR_UBYTE*)matrix_pptr) + (sizeof(MR_MAT*) * env_mult->ae_no_of_models));

	model_pptr	= env_mult->ae_models;
	for (m = 0; m < env_mult->ae_no_of_models; m++)
		{
		env_mult->ae_lw_transforms[m] = transform_ptr;
		transform_ptr += (*model_pptr)->am_no_of_parts;
		model_pptr++;
		}

	env->ae_special_flags |= MR_ANIM_ENV_STORE_LW_TRANSFORMS;
	return(env_mult->ae_lw_transforms);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleDeleteLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleDeleteLWTransforms(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Frees space used by LW transforms
*
*	INPUTS		env			-	ptr to multiple environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleDeleteLWTransforms(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(env_mult->ae_lw_transforms);
	MRFreeMem(env_mult->ae_lw_transforms);
	env_mult->ae_lw_transforms = NULL;
	env->ae_special_flags &= ~MR_ANIM_ENV_STORE_LW_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleSetImportedTransform(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		model,
*						MR_USHORT		part,
*						MR_MAT*			transform)
*
*	FUNCTION	Sets a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to multiple environment
*			 	model 		-	index of model within environment
*			 	part  		-	index of part within model
*			 	transform	-	pointer to transform to import
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.01.97 	Tim Closs		Created
*	17.01.97 	Tim Closs		Handles allocations
*	11.06.97	Dean Ashton		Fixed bug where matrix_pptr was incorrectly
*								used after being incremented
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetImportedTransform(	MR_ANIM_ENV*	env,
												MR_USHORT		model,
												MR_USHORT		part,
												MR_MAT*			transform)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				b;
	MR_MAT**				matrix_pptr;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);

	if (env_mult->ae_imported_transforms[model] == NULL)
		{
		// Imported transform ptrs do not exist for this model - make allocation
		b				= env_mult->ae_models[model]->am_no_of_parts;
		matrix_pptr	= MRAllocMem(sizeof(MR_MAT*) * b, "IM_TRANS");
		env_mult->ae_imported_transforms[model] = matrix_pptr;

		while(b--)
			*matrix_pptr++ = NULL;
		}

	env_mult->ae_imported_transforms[model][part] = transform;
	env->ae_special_flags |= MR_ANIM_ENV_IMPORTED_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleClearImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_VOID	MRAnimEnvMultipleClearImportedTransform(
*			 			MR_ANIM_ENV*	env,
*			 			MR_USHORT		model,
*			 			MR_USHORT		part)
*
*	FUNCTION 	Clear a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to multiple environment
*			 	model		-	index of model within environment
*			 	part 		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleClearImportedTransform(MR_ANIM_ENV*	env,
					 							MR_USHORT		model,
												MR_USHORT		part)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);
	MR_ASSERT(env_mult->ae_imported_transforms[model]);

	env_mult->ae_imported_transforms[model][part] = NULL;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleGetImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MAT*	matrix	=	MRAnimEnvMultipleGetImportedTransform(
*									MR_ANIM_ENV*	env,
*									MR_USHORT		model,
*									MR_USHORT		part)
*
*	FUNCTION	Returns a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to single environment
*			 	model		- 	index of model within environment
*			 	part		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_MAT*	MRAnimEnvMultipleGetImportedTransform(	MR_ANIM_ENV*	env,
												MR_USHORT		model,
												MR_USHORT		part)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);
	MR_ASSERT(part < env_mult->ae_models[model]->am_no_of_parts);
	MR_ASSERT(env_mult->ae_imported_transforms[model]);

	return(env_mult->ae_imported_transforms[model][part]);
}


/******************************************************************************
*%%%% MRAnimEnvMultipleDeleteImportedTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS  	MR_VOID	MRAnimEnvMultipleDeleteImportedTransforms(
*			  			MR_ANIM_ENV*	env)
*
*	FUNCTION  	Frees space used by imported transforms
*
*	INPUTS		env	-	ptr to multiple environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97  	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleDeleteImportedTransforms(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT 				model;


	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	for (model = 0; model < env_mult->ae_no_of_models; model++)
		{
		if (env_mult->ae_imported_transforms[model])
			{
			MRFreeMem(env_mult->ae_imported_transforms[model]);
			env_mult->ae_imported_transforms[model] = NULL;
			}
		}

	env->ae_special_flags &= ~MR_ANIM_ENV_IMPORTED_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetAction
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_VOID	MRAnimEnvMultipleSetAction(
*			 			MR_ANIM_ENV*	env,
*			 			MR_USHORT		model)
*			 			MR_SHORT		action)
*
*	FUNCTION 	Change the action of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (multiple)
*			 	model		-	index of model within environment
*			 	action		-	action number (-1 for no action)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetAction(	MR_ANIM_ENV*	env,
									MR_USHORT		model,
									MR_SHORT		action)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;

	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;
	
	if (action == -1)
		{
		// Turn model off
		env_mult->ae_action_number[model] 	= -1;
		env_mult->ae_total_cels[model]		= -1;
		env_mult->ae_cel_number[model]		= -1;
		}
	else
		{
		MR_ASSERTMSG(action < env_mult->ae_models[model]->am_cel_set->ac_no_of_cels_structures, "Action number too big");
		env_mult->ae_action_number[model] 	= action;
		env_mult->ae_total_cels[model]		= env_mult->ae_models[model]->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels;
		env_mult->ae_cel_number[model] 		= -1;
		}
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetActionAll
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleSetActionAll(
*						MR_ANIM_ENV*	env,
*						MR_SHORT   		action)
*
*	FUNCTION	Change the action of all models within an environment
*
*	INPUTS		env			-	ptr to animation environment (multiple)
*				action		-	action number (-1 for no action)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetActionAll(	MR_ANIM_ENV*	env,
								   		MR_SHORT		action)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				model;
	
	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;
	
	if (action == -1)
		{
		// Turn models off
		for (model = 0; model < env_mult->ae_no_of_models; model++)
			{
			env_mult->ae_action_number[model] 	= -1;
			env_mult->ae_total_cels[model]		= -1;
			env_mult->ae_cel_number[model]		= -1;
			}
		}
	else
		{
		// All models use the same cel set, so we can ASSERT using the cel set of model 0
		MR_ASSERTMSG(action < env_mult->ae_models[0]->am_cel_set->ac_no_of_cels_structures, "Action number too big");

		for (model = 0; model < env_mult->ae_no_of_models; model++)
			{
			env_mult->ae_action_number[model] 	= action;
			env_mult->ae_total_cels[model]		= env_mult->ae_models[model]->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels;
			env_mult->ae_cel_number[model] 		= -1;
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetCel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleSetCel(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		model)
*						MR_SHORT		cel)
*
*	FUNCTION	Change the cel of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (multiple)
*			 	model		-	index of model within environment
*			 	cel			-	cel number (-1 for no cel)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetCel(MR_ANIM_ENV*	env,
								MR_USHORT		model,
								MR_SHORT		cel)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	
	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	if (cel == -1)
		{
		// Turn model off
		env_mult->ae_cel_number[model] = -1;
		}
	else
		{
		MR_ASSERTMSG(cel < env_mult->ae_models[model]->am_cel_set->ac_cels.ac_cels[env_mult->ae_action_number[model]].ac_no_of_virtual_cels, "Cel number too big");
		env_mult->ae_cel_number[model] = cel;
		}
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetCelAll
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleSetCelAll(
*						MR_ANIM_ENV*	env,
*						MR_SHORT		cel)
*
*	FUNCTION	Change the cel of all models within an environment
*
*	INPUTS		env			-	ptr to animation environment (multiple)
*				cel			-	cel number (-1 for no cel)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetCelAll(	MR_ANIM_ENV*	env,
									MR_SHORT		cel)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				model;

	
	MR_ASSERT(env);

	env_mult = env->ae_extra.ae_extra_env_multiple;

	if (cel == -1)
		{
		// Turn models off
		for (model = 0; model < env_mult->ae_no_of_models; model++)
			env_mult->ae_cel_number[model] = -1;
		}
	else
		{
		for (model = 0; model < env_mult->ae_no_of_models; model++)
			{
			MR_ASSERTMSG(cel < env_mult->ae_models[model]->am_cel_set->ac_cels.ac_cels[env_mult->ae_action_number[model]].ac_no_of_virtual_cels, "Cel number too big");
			env_mult->ae_cel_number[model] = cel;
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvMultipleSetEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleSetEvent(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		model,
*						MR_USHORT		action,
*						MR_USHORT		cel,
*						MR_UBYTE		event_callback,
*						MR_UBYTE		user_param)
*
*	FUNCTION	Set an event at a particular model, action, cel.  Make memory
*				allocations if necessary
*
*	INPUTS		env				-	ptr to environment (multiple)
*				model			-	index of model within environment
*				action			-	action of event
*				cel				-	cel of event
*				event_callback	-	event id
*				user_param		-	event user param
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleSetEvent(	MR_ANIM_ENV*	env,
									MR_USHORT		model,
									MR_USHORT		action,
									MR_USHORT		cel,
									MR_UBYTE		event_callback,
									MR_UBYTE		user_param)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				i, j, k;


	MR_ASSERT(env);

	MR_ASSERTMSG(action < env->ae_model_set->am_cel_set->ac_no_of_cels_structures, "Action number too big");
	MR_ASSERTMSG(cel    < env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels, "Cel number too big");

	env_mult = env->ae_extra.ae_extra_env_multiple;

	MR_ASSERT(model < env_mult->ae_no_of_models);

	if (env_mult->ae_events == NULL)
		{
		// Allocate one MR_ANIM_EVENT** per model
		i					= env_mult->ae_no_of_models;
		env_mult->ae_events	= MRAllocMem(i * sizeof(MR_ANIM_EVENT**), "MOD_EVNT");
		for (j = 0; j < i; j++)
			env_mult->ae_events[j] = NULL;
		}

	if (env_mult->ae_events[model] == NULL)
		{
		// Allocate one MR_ANIM_EVENT* per action
		i							= env->ae_model_set->am_cel_set->ac_no_of_cels_structures;
		env_mult->ae_events[model]	= MRAllocMem(i * sizeof(MR_ANIM_EVENT*), "ACT_EVNT");
		for (j = 0; j < i; j++)
			env_mult->ae_events[model][j] = NULL;
		}

	if (env_mult->ae_events[model][action] == NULL)
		{
		// Allocate one MR_ANIM_EVENT per (virtual) cel
		k									= env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels;
		env_mult->ae_events[model][action]	= MRAllocMem(k * sizeof(MR_ANIM_EVENT), "CEL_EVNT");
		for (j = 0; j < k; j++)
			MR_SET16(env_mult->ae_events[model][action][j], MR_ANIM_EVENT_EMPTY);
		}

	// Write the event
	env_mult->ae_events[model][action][cel].ae_event_callback	= event_callback;
	env_mult->ae_events[model][action][cel].ae_user_param		= user_param;

	env->ae_special_flags |= MR_ANIM_ENV_EVENT_LIST_ACTIVE;
}


/******************************************************************************
*%%%% MRAnimEnvMultipleClearEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvMultipleClearEvent(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		model,
*						MR_USHORT		action,
*						MR_USHORT		cel)
*
*	FUNCTION	Clear an event at a particular model, action, cel
*
*	INPUTS		env			-	ptr to environment (multiple)
*				model		-	index of model within environment
*				action		-	action of event
*				cel			-	cel of event
*							
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvMultipleClearEvent(	MR_ANIM_ENV*	env,
										MR_USHORT		model,
										MR_USHORT		action,
										MR_USHORT		cel)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;


	MR_ASSERT(env);

	MR_ASSERTMSG(action < env->ae_model_set->am_cel_set->ac_no_of_cels_structures, "Action number too big");
	MR_ASSERTMSG(cel    < env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels, "Cel number too big");

	env_mult = env->ae_extra.ae_extra_env_multiple;

	if (env_mult->ae_events)
		{
		// Model level ptrs exist
		if (env_mult->ae_events[model])
			{
			// Action level ptrs exist for this model
			if (env_mult->ae_events[model][action])
				{
				// Cel level ptrs exist for this model, action
				MR_SET16(env_mult->ae_events[model][action][cel], MR_ANIM_EVENT_EMPTY);
				}
			}
		}
}


