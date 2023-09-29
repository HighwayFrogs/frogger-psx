/******************************************************************************
*%%%% mr_light.c
*------------------------------------------------------------------------------
*
*	Routines associated with API lighting
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	28.05.96	Dean Ashton		Changed callback in MRCreateLight to flags instead
*
*%%%**************************************************************************/

#include "mr_all.h"


/******************************************************************************
*%%%% MRCreateLight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT* object_ptr = MRCreateLight(
*										MR_USHORT	type,
*										MR_ULONG	colour,
*										MR_FRAME*	frame,
*										MR_USHORT	flags)
*
*	FUNCTION	Creates and initialises an MR_LIGHT
*
*	INPUTS		type		-	Light type
*				colour		-	BbGgRr format colour value
*				frame		-	Frame occupied by the MR_LIGHT
*				flags		-	Flags for object creation
*
*	RESULT		object_ptr	-	Pointer to object if successful, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	28.05.96	Dean Ashton		Changed callback param to flags... added NULL
*								handling
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreateLight(	MR_ULONG 	type,
							MR_ULONG 	colour,
							MR_FRAME*	frame,
							MR_USHORT	flags)
{
	MR_OBJECT*	object_ptr;
	MR_LIGHT*	light_ptr;

	if (object_ptr = MRCreateObject(MR_OBJTYPE_LIGHT, frame, flags, NULL))
		{

		// Successfully created object structure
		light_ptr = object_ptr->ob_extra.ob_extra_light;

		light_ptr->li_type	= type;
		light_ptr->li_flags	= 0;

		// Set 3 colour components (and alpha)
		MR_SET32(light_ptr->li_colour.r, colour);

		return(object_ptr);
		}
	else
		return(NULL);
}


/******************************************************************************
*%%%% MRKillLight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillLight(
*						MR_OBJECT*	light);
*
*	FUNCTION	Kills a light previously created with MRCreateLight();
*
*	INPUTS		light		-	Pointer to the light object to destroy
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillLight(MR_OBJECT* light)
{
	MR_ASSERT(light != NULL);
	MRKillObject(light);
}	


/******************************************************************************
*%%%% MRUpdateViewportColourMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateViewportColourMatrix(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Recalculates the colour matrix for the specified viewport.
*
*	INPUTS		viewport	-	Pointer to a valid MR_VIEWPORT structure
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.96	Tim Closs		Created
*	28.05.96	Dean Ashton		Added default handling for ambient lights
*
*%%%**************************************************************************/

MR_VOID	MRUpdateViewportColourMatrix(MR_VIEWPORT* viewport)
{
	MR_LIGHT_INST*	light_inst;
	MR_USHORT		i;
	MR_LIGHT*		light_ptr;

	MR_ASSERT(viewport != NULL);

	light_inst = viewport->vp_light_root_ptr;

	i = 0;

	while	((light_inst = light_inst->li_next_node) && (i < 3))
		// Ignore any lights beyond 3 which require matrix space
		{
		light_ptr = (light_inst->li_object->ob_extra.ob_extra_light);

		switch(light_ptr->li_type)
			{
			case MR_LIGHT_TYPE_PARALLEL:
			case MR_LIGHT_TYPE_POINT:
				viewport->vp_colour_matrix.m[0][i] = light_ptr->li_colour.r << 4;
				viewport->vp_colour_matrix.m[1][i] = light_ptr->li_colour.g << 4;
				viewport->vp_colour_matrix.m[2][i] = light_ptr->li_colour.b << 4;
				i++;
				break;

			case MR_LIGHT_TYPE_AMBIENT:
				break;
		
			default:
				MR_ASSERT(FALSE);
			}
		}
	while(i < 3)
		{
		viewport->vp_colour_matrix.m[0][i] = 0;
		viewport->vp_colour_matrix.m[1][i] = 0;
		viewport->vp_colour_matrix.m[2][i] = 0;
		i++;
		}		
}


/******************************************************************************
*%%%% MRUpdateViewportLightMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateViewportLightMatrix(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Recalculates the light matrix for the specified viewport.
*
*	INPUTS		viewport	-	Pointer to a valid MR_VIEWPORT structure
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.96	Tim Closs		Created
*	28.05.96	Dean Ashton		Added default handling for ambient lights
*	31.07.97	Dean Ashton		Changed to only recalculate light matrix
*
*%%%**************************************************************************/

MR_VOID	MRUpdateViewportLightMatrix(MR_VIEWPORT* viewport)
{
	MR_LIGHT_INST*	light_inst;
	MR_USHORT		i;
	MR_LIGHT*		light_ptr;

	MR_ASSERT(viewport != NULL);	

	light_inst = viewport->vp_light_root_ptr;

	i = 0;
	while	((light_inst = light_inst->li_next_node) && (i < 3))
		// Ignore any lights beyond 3 which require matrix space
		{
		light_ptr = (light_inst->li_object->ob_extra.ob_extra_light);

		switch(light_ptr->li_type)
			{
			case MR_LIGHT_TYPE_PARALLEL:
				// Copy direction of z axis of light object's frame into ROW of light matrix
				viewport->vp_light_matrix.m[i][0] = light_inst->li_object->ob_frame->fr_lw_transform.m[0][2];
				viewport->vp_light_matrix.m[i][1] = light_inst->li_object->ob_frame->fr_lw_transform.m[1][2];
				viewport->vp_light_matrix.m[i][2] = light_inst->li_object->ob_frame->fr_lw_transform.m[2][2];
				i++;
				break;
	
			case MR_LIGHT_TYPE_POINT:
				// If there are point lights in the viewport, we can't build that ROW of the light
				// matrix (since it depends on mesh position)
				i++;
				break;

			case MR_LIGHT_TYPE_AMBIENT:
				break;

			default:
				MR_ASSERT(FALSE);
			}
		}
}


/******************************************************************************
*%%%% MRCalculateCustomInstanceLights
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateCustomInstanceLights(
*						MR_OBJECT*	object,
*						MR_ULONG 	light_flags,
*						MR_CVEC* 	colour_scale,
*						MR_CVEC* 	custom_ambient);
*
*	FUNCTION	Recalculates (as necessary) the light matrix, colour matrix, and
*				ambient/back colour for a given objects display in a viewport.
*				Typically this is called for objects accepting pointlights, where
*				the light matrix has to be updated each frame, and also where the
*				object is requiring a non-standard lighting requirement (such as 
*				not requiring ambient, not requiring parallel, or requiring a 
*				colour scale)
*
*	INPUTS		object			-	Object being instanced in a viewport
*				light_flags		-	Indicates what colour scaling is to take place
*				colour_scale	-	A colour vector representing R/G/B scaling
*									values (where 0x80 is no change)
*				custom_ambient	-	A colour vector representing an overriding 
*									ambient (or base) colour. 
*
*	RESULT		lights_modified -	Bitfield containing flags that let caller know
*									what lighting things we've modified.
*
*	NOTES		Uses current viewport pointer (MRVp_ptr) to get a handle to the
*		 		required viewport.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Dean Ashton		Created
*	11.03.97	Dean Ashton		Changed to use MR_VEC_MOD_SQR
*
*%%%**************************************************************************/

MR_ULONG	MRCalculateCustomInstanceLights(MR_OBJECT*	object,
											MR_ULONG 	light_flags,
											MR_CVEC* 	colour_scale,
											MR_CVEC* 	custom_ambient)
{
	MR_LIGHT_INST*	light_inst;						
	MR_USHORT	  	i;
	MR_LONG		  	light_strength;
	MR_LIGHT*	  	light_ptr;
	MR_MAT*		  	matrix;
	MR_VEC		  	troffset;
	MR_MAT*			object_lw;
	MR_MAT*			light_lw;
	MR_ULONG		lights_modified = NULL;

	MR_ASSERT(object != NULL);

	light_inst	= MRVp_ptr->vp_light_root_ptr;
	matrix		= MRLight_matrix_ptr;
	i 			= 0;

	// Only re-build the light matrix if we've got pointlights, or no parallel lights
	
	if ( ((MRVp_ptr->vp_pointlights) && (object->ob_flags & MR_OBJ_ACCEPT_LIGHTS_POINT)) ||
			(!(object->ob_flags & MR_OBJ_ACCEPT_LIGHTS_PARALLEL)))
		{
		// Get a handle to the matrix representing this objects position
		if (object->ob_flags & MR_OBJ_STATIC)
			object_lw = (MR_MAT*)object->ob_frame;
		else
			object_lw = &object->ob_frame->fr_lw_transform;
	
		// Scan through light instances
		while	((light_inst = light_inst->li_next_node) && (i < 3))	// Ignore any lights beyond 3 which require matrix space
			{
			light_ptr = (light_inst->li_object->ob_extra.ob_extra_light);
	
			if (object->ob_flags & light_ptr->li_type)
				{
				// Object accepts this type of lighting
				switch(light_ptr->li_type)
					{
					case MR_LIGHT_TYPE_AMBIENT:
						// Ambient - nothing to do.. yet.
						break;
	
					case MR_LIGHT_TYPE_PARALLEL:
						// Copy direction of z axis of light object's frame into ROW of light matrix
						if (light_inst->li_object->ob_flags & MR_OBJ_STATIC)
							light_lw = (MR_MAT*)light_inst->li_object->ob_frame;
						else
							light_lw = &light_inst->li_object->ob_frame->fr_lw_transform;
	
						matrix->m[i][0] = light_lw->m[0][2];
						matrix->m[i][1] = light_lw->m[1][2];
						matrix->m[i][2] = light_lw->m[2][2];
						i++;
						break;
	
					case MR_LIGHT_TYPE_POINT:
						// Direction of light is MR_VEC from light origin to object
						if (light_inst->li_object->ob_flags & MR_OBJ_STATIC)
							light_lw = (MR_MAT*)light_inst->li_object->ob_frame;
						else
							light_lw = &light_inst->li_object->ob_frame->fr_lw_transform;
	
						MRApplyMatrix(	&object->ob_frame->fr_lw_transform,
											&object->ob_offset,
											&troffset);
				
						troffset.vx = (troffset.vx + object_lw->t[0] - light_lw->t[0]) >> 4;
						troffset.vy = (troffset.vy + object_lw->t[1] - light_lw->t[1]) >> 4;
						troffset.vz = (troffset.vz + object_lw->t[2] - light_lw->t[2]) >> 4;
						
						light_strength = MR_VEC_MOD_SQR(&troffset);
						light_strength = ((light_strength - (light_ptr->li_falloff_min >> 8)) << 8);
						light_strength /= (MR_LONG)((light_ptr->li_falloff_max - light_ptr->li_falloff_min) >> 8);
						light_strength = 4096 - (light_strength << 4);
						light_strength = MIN(4096, MAX(0, light_strength));
	
						MRNormaliseVEC(&troffset, &troffset);
						matrix->m[i][0] = (troffset.vx * light_strength) >> 12;
						matrix->m[i][1] = (troffset.vy * light_strength) >> 12;
						matrix->m[i][2] = (troffset.vz * light_strength) >> 12;
						i++;
						break;
	
					default:
						MR_ASSERT(FALSE);
					}
				}
			else
				{
				// Object does not accept this type of lighting
				if (light_ptr->li_type & (MR_LIGHT_TYPE_PARALLEL | MR_LIGHT_TYPE_POINT))
					{
					// Space allocated in colour matrix for this light, so pad out with 0
					matrix->m[i][0] = 0;
					matrix->m[i][1] = 0;
					matrix->m[i][2] = 0;
					i++;
					}
				}
			}
		}
	else
		{
		MR_COPY_MAT(&MRLight_matrix, &MRVp_ptr->vp_light_matrix);
		}

	// Ambient processing
	if (!(object->ob_flags & MR_OBJ_ACCEPT_LIGHTS_AMBIENT))									// No ambient required
		{					  	
		gte_SetBackColor(	0,
							0,
							0);
		lights_modified |= MR_CHANGED_AMBIENT_COLOUR;
		}
	else
	if ((light_flags & MR_INST_USE_CUSTOM_AMBIENT) && (!(light_flags & MR_INST_USE_SCALED_COLOURS)))
		{
		gte_SetBackColor(	custom_ambient->r,
							custom_ambient->g,
							custom_ambient->b);
		lights_modified |= MR_CHANGED_AMBIENT_COLOUR;
		}

	// Colour matrix scaling
	if (light_flags & MR_INST_USE_SCALED_COLOURS)				// We want to scale the colour matrix too.
		{
		MR_CLEAR_MAT(&MRTemp_matrix);

		MRTemp_matrix.m[0][0] = colour_scale->r << 5;			// Set up the MR_CVEC as a scaling matrix
		MRTemp_matrix.m[1][1] = colour_scale->g << 5;
		MRTemp_matrix.m[2][2] = colour_scale->b << 5;

		MRMulMatrixABA(&MRTemp_matrix, &MRVp_ptr->vp_colour_matrix);

		gte_SetColorMatrix(&MRTemp_matrix);

		if (object->ob_flags & MR_OBJ_ACCEPT_LIGHTS_AMBIENT)
			{
			if (light_flags & MR_INST_USE_CUSTOM_AMBIENT)
				{
				gte_SetBackColor(	(custom_ambient->r * colour_scale->r)>>7,
									(custom_ambient->g * colour_scale->g)>>7,
									(custom_ambient->b * colour_scale->b)>>7);
				}
			else
				{
				gte_SetBackColor(	(MRVp_ptr->vp_back_colour.r * colour_scale->r)>>7,
									(MRVp_ptr->vp_back_colour.g * colour_scale->g)>>7,
									(MRVp_ptr->vp_back_colour.b * colour_scale->b)>>7);
				}
			lights_modified |= MR_CHANGED_AMBIENT_COLOUR;
			}

		lights_modified |= MR_CHANGED_COLOUR_MATRIX;
		}		
	
	return(lights_modified);
}
