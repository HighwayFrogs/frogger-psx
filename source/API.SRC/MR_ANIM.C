/******************************************************************************
*%%%% mr_anim.c
*------------------------------------------------------------------------------
*
*	Functions for handling animated MOFs
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	07.08.96	Tim Closs		Created
*	15.10.96	Tim Closs		Added basic environment and event handling
*	21.10.96	Dean Ashton		Applied Local OT bugfix to display code.
*	21.10.96	Tim Closs		Added MRAnimSetAction(), MRAnimSetCel()
*	23.10.96	Tim Closs		New prim types supported in MRAnimDisplayMeshInstance:
*									MR_MPRIMID_HLF3, MR_MPRIMID_HLF4
*									MR_ANIM_MODEL->am_static_model is now an index into
*									MR_ANIM_HEADER->ah_static_files
*	31.10.96	Tim Closs		MRAnimDisplayMeshInstance now sets
*								MR_MESH_INST_DISPLAYED_LAST_FRAME only if mesh
*								rendered (on screen and in OT)
*								Added MRAnimAddEnvToViewport()
*	20.11.96	Tim Closs		Altered all animation functions, added low level
*								functions
*	10.12.96	Tim Closs		MRAnimCreateEnvSingle/Multiple and 
*								MRAnimLoadEnvSingle altered subtly
*	17.12.96	Tim Closs		Fixed double add object bug in MRAnimAddEnvToViewport
*	10.01.97	Tim Closs		MRAnimCreateEnvSingle/MultipleEntirely changed to
*								MRAnimCreateWholeEnvSingle/Multiple
*								Added:
*									MRAnimEnvUpdateLWTransforms()
*									MRAnimEnvSetFlags()
*									MRAnimEnvClearFlags()
*									MRAnimEnvGetFlags()
*									MRAnimEnvSetSpecialFlags()
*									MRAnimEnvClearSpecialFlags()
*									MRAnimEnvGetSpecialFlags()
*	14.01.97	Tim Closs		MRAnimKillEnv() now deallocates memory properly
*								Added:
*									MRAnimEnvSingleSetPartFlags()
*									MRAnimEnvSingleClearPartFlags()
*									MRAnimEnvSingleGetPartFlags()
*									MRAnimEnvMultipleSetPartFlags()
*									MRAnimEnvMultipleClearPartFlags()
*									MRAnimEnvMultipleGetPartFlags()
*									MRAnimEnvSingleSetImportedTransform()
*									MRAnimEnvSingleClearImportedTransform()
*									MRAnimEnvMultipleSetImportedTransform()
*									MRAnimEnvMultipleClearImportedTransform()
*									MRAnimRemoveEnvInstanceFromViewport()
*									MRAnimEnvDestroyByDisplay()
*								Added support for type '1' files (byte transforms)
*								MRAnimKillEnv() no longer touches associated meshes
*	15.01.97	Tim Closs		Added:
*				   					MRAnimEnvSingleGetImportedTransform()
*				   					MRAnimEnvMultipleGetImportedTransform()
*				   					MRAnimEnvSingleSetAction()
*				   					MRAnimEnvSingleSetCel()
*				   					MRAnimEnvMultipleSetAction()
*				   					MRAnimEnvMultipleSetCel()
*				   					MRAnimEnvMultipleSetActionAll()
*				   					MRAnimEnvMultipleSetCelAll()
*				   				Removed:
*				   					MRAnimSetAction()
*				   					MRAnimSetCel()
*				   					MRAnimKillEnvInst()
*	17.01.97	Tim Closs		Renamed and added so much stuff I can't be bothered
*					  			to detail it
*	20.01.97	Tim Closs		Added all events functions
*	22.01.97	Tim Closs		Added support for MR_ANIM_ENV_NOT_ACTIVE and
*					  			MR_ANIM_ENV_ONE_SHOT_AND_KILL
*					  			Added MRAnimRemoveEnvInstanceFromViewportPhysically()
*	24.01.97	Tim Closs		Changed handling of MRCheckBoundingBoxOnScreen() result
*				Dean Ashton		Removed MRAnimUnresolveMOFTextures()
*	05.02.97	Dean Ashton		Modified display code to use new lighting code
*	10.02.97	Tim Closs		MRAnimEnvGetPartTransform() now handles compressed
*		 			  			and byte transforms
*					  			Fixed transform increment bug in MRAnimDisplayMeshInstance()
*					  			and MRAnimEnvUpdateLWTransforms()
*					  			Added MRAnimEnvUpdateModelLWTransforms()
*	12.02.97	Tim Closs		Altered debug display calls in MRAnimDisplayMeshInstance()
*					  			MRAnimEnvUpdateLWTransforms() now rebuilds if
*					  			MR_FRAME_REBUILT_LAST_FRAME set for the environment's MR_FRAME
*	13.02.97	Tim Closs		MRAnimRemoveEnvInstanceFromViewportPhysically() now kills
*					  			component meshes and mesh instances
*					  			MRAnimKillEnv() no longer flags component meshes as
*					  			MR_OBJ_DESTROY_BY_DISPLAY
*	17.02.97	Tim Closs		Added support for MR_ANIM_PART_REDUNDANT
*	13.03.97	Tim Closs		MRAnimDisplayMeshInstance() - fixed collprim display bug
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix in
*					  			MRAnimCalculatePartTransform()
*	18.03.97	Tim Closs		Anim file transforms now MUST be indexed (else
*					  			code will assert).  Added support for MR_QUATB_TRANS
*					  			transforms
*	19.03.97	Tim Closs		Created MR_ANIM_CPT_PARAMS structure for passing
*										parameters into MRAnimCalculatePartTransform().
*								Altered:
*										MRAnimEnvUpdateLWTransforms()
*										MRAnimEnvUpdateModelLWTransforms()
*										MRAnimCalculatePartTransform()
*										MRAnimDisplayMeshInstance()
*	24.03.97	Tim Closs		MRAnimEnvGetPartTransform() updated to use
*								MRAnimCalculatePartTransform().
*								Removed all Multiple specific functions to mr_anim2
*	03.04.97	Dean Ashton		Changed MRAnimEnvGetPartTransform() to accept a pointer
*								to a MR_MAT to store result in..
*	07.04.97	Dean Ashton		MRAnimDisplayMeshInstance() now respects
*								MR_MESH_IGNORE_BBOX and MR_MESH_CHECK_BBOX_USING_EDGES
*	02.06.97	Dean Ashton		MRAnimDisplayMeshInstance() now handles local ordering
*								tables without frames (using MR_MAT's instead)
*								Fixed bug in MRAnimDisplayMeshInstance() where colour
*								matrix could be modified, but not restored afterwards.
*	04.06.97	Dean Ashton		Removal of an animation environment instance from a 
*								viewport now requests appropriate removal of mesh
*								instances too.
*	11.06.97	Dean Ashton		Fixed bug in MRAnimEnvSingleSetImportedTransform()
*								where matrix_pptr was incorrectly used after being
*								incremented.
*	12.06.97 	Tim Closs		MRAnimEnvSingleSetImportedTransform() - fixed bug
*								MRAnimCalculatePartTransform():
*								MR_ANIM_FILE_ID_NORMAL				(16bit matrix)
*								MR_ANIM_FILE_ID_BYTE_TRANSFORMS		(8bit matrix)
*								MR_ANIM_FILE_ID_QUATB_TRANSFORMS	(8bit quaternion)	
*								MR_ANIM_FILE_ID_QUAT_TRANSFORMS		(16bit quaternion)
*								For quaternion transforms, MR_ANIM_CELS flag 
*								MR_ANIM_CELS_VIRTUAL_INTERPOLATION indicates virtual cel list is
*								interpreted as (prev actual cel index, next actual cel index, interpolation param)
*	13.06.97	Dean Ashton		Added support for MR_MRPRIM_GE3/MR_MRPRIM_GE4
*			 	Tim Closs		MRAnimCalculatePartTransform():
*								Added support for scaled transform types:
*								MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS		(8bit quaternion, scaled)
*								MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS		(16bit quaternion, scaled)
*	18.06.97 	Tim Closs		Added support for MR_ANIM_ENV_FLIPBOOK
*	04.07.97	Dean Ashton		Fixed bug to do with env mapping in MRAnimDisplayMeshInstance();
*	09.07.97	Dean Ashton		Added OT biasing with ot_global_ot_offset in display code
*	16.07.97	Dean Ashton		Made changes to deal with new model types, where frames start at 0 instead
*								of 1.
*	23.07.97	Dean Ashton		Applied Tim's bugfix to MRAnimUpdateEnvironments() where update period
*								greater than 1 broke code when action was changed.
*	30.07.97	Dean Ashton		Fixed bug where tsize wasn't being correctly setup for
*								non-interpolated quaternion animations in MRAnimCalculatePartTransform()
*	13.08.97	Tim Closs		Changed MRAnimUpdateEnvironments() to not access MOF for flipbook 
*								animations that are being destroyed.
*	20.08.97	Dean Ashton		Added support for MR_OT_FORCE_BACK in MRAnimDisplayMeshInstance()
*	03.09.97	Dean Ashton		Fixed bug in MRAnimRemoveMeshInstancePhysically 
*								where environment was being killed multiple times
*								if the routine was called with some mesh instances
*								having kill timer set. 
*
*%%%**************************************************************************/

#include "mr_all.h"

MR_ANIM_ENV			MRAnim_env_root;
MR_ANIM_ENV*		MRAnim_env_root_ptr;
MR_USHORT			MRNumber_of_anim_envs;
MR_ANIM_EVENT_LIST*	MRAnim_event_list;
MR_MAT				MRAnim_temp_matrix;

// Compile flags
//#define	MR_ANIM_COMPILE_IDENTITY_TRANSFORM		// all parts use identity transform (debug)


/******************************************************************************
*%%%% MRAnimResolveMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimResolveMOF(
*						MR_MOF* mof_ptr);
*
*	FUNCTION	Resolves all offsets and sizes within a MOF. 
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	07.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimResolveMOF(MR_MOF* mof_ptr)
{
	MR_ANIM_HEADER*			anim_ptr;
	MR_USHORT				i, j, k;
	MR_MOF**				mof_pptr;
	MR_ANIM_MODEL_SET*		model_set_ptr;
	MR_ANIM_MODEL*			model_ptr;
	MR_ANIM_CEL_SET*		cel_set_ptr;
	MR_ANIM_CELS*			cel_ptr;
	MR_ANIM_CELS_PARTS*		cel_part_ptr;
	MR_ANIM_BBOX_SET* 		bbox_set_ptr;
	MR_ANIM_BBOXES*			abbox_ptr;
	MR_ANIM_COMMON_DATA*	common_data;


	MR_ASSERT(mof_ptr != NULL);
	if (mof_ptr->mm_flags & MR_MOF_OFFSETS_RESOLVED)
		return;

	//-------------------------------------------------------------------------
	// Resolve MR_ANIM_HEADER ptrs		
	//-------------------------------------------------------------------------
	anim_ptr	= (MR_ANIM_HEADER*)mof_ptr;

	MR_ASSERTMSG(anim_ptr->ah_flags & MR_MOF_ANIM_TRANSFORMS_INDEXED, "Transforms MUST be indexed - in this file they are not");

	anim_ptr->ah_model_sets		= (MR_ANIM_MODEL_SET*)((MR_ULONG)anim_ptr + (MR_ULONG)anim_ptr->ah_model_sets);
	anim_ptr->ah_common_data	= (MR_ANIM_COMMON_DATA*)((MR_ULONG)anim_ptr + (MR_ULONG)anim_ptr->ah_common_data);
	anim_ptr->ah_static_files	= (MR_MOF**)((MR_ULONG)anim_ptr + (MR_ULONG)anim_ptr->ah_static_files);

	//-------------------------------------------------------------------------
	// Resolve the array of ptrs to static files, and resolve the static files themselves
	//-------------------------------------------------------------------------
	mof_pptr	= anim_ptr->ah_static_files;
	i			= anim_ptr->ah_no_of_static_files;
	while(i--)
		{
		*mof_pptr = (MR_MOF*)((MR_ULONG)anim_ptr + (MR_ULONG)*mof_pptr);
		MRStaticResolveMOF(*mof_pptr);
		mof_pptr++;
		}	

	// Set the _RESOLVED bits in the MR_ANIM_HEADER flags (they have already been set in the individual static MOFs)
	anim_ptr->ah_flags |= (MR_MOF_OFFSETS_RESOLVED | MR_MOF_SIZES_RESOLVED);

	//-------------------------------------------------------------------------
	// Resolve ptrs in MR_ANIM_MODEL_SETs
	//-------------------------------------------------------------------------
	model_set_ptr 	= anim_ptr->ah_model_sets;
	i				= anim_ptr->ah_no_of_model_sets;
	while(i--)
		{
		// Resolve models
		if (model_set_ptr->am_models)
			{
			model_set_ptr->am_models	= (MR_ANIM_MODEL*)((MR_ULONG)anim_ptr + (MR_ULONG)model_set_ptr->am_models);
			model_ptr					= model_set_ptr->am_models;
			j		 					= model_set_ptr->am_no_of_models;
			while(j--)
				{
				if (model_ptr->am_cel_set)
					model_ptr->am_cel_set		= (MR_ANIM_CEL_SET*)((MR_ULONG)anim_ptr + (MR_ULONG)model_ptr->am_cel_set);

				if (model_ptr->am_static_bbox)
					// This is a model-wide bounding box, and should enclose all cels in the model				
					model_ptr->am_static_bbox	= (MR_BBOX*)((MR_ULONG)anim_ptr + (MR_ULONG)model_ptr->am_static_bbox);

				if (model_ptr->am_bbox_set)
					model_ptr->am_bbox_set		= (MR_ANIM_BBOX_SET*)((MR_ULONG)anim_ptr + (MR_ULONG)model_ptr->am_bbox_set);

				if (model_ptr->am_constraint)
					model_ptr->am_constraint 	= (MR_ANIM_CONSTRAINT*)((MR_ULONG)anim_ptr + (MR_ULONG)model_ptr->am_constraint);

				model_ptr++;
				}
			}

		// Resolve cel sets
		if (model_set_ptr->am_cel_set)
			{	
			// Resolve ptrs in all the MR_ANIM_CEL_SETs
			model_set_ptr->am_cel_set	= (MR_ANIM_CEL_SET*)((MR_ULONG)anim_ptr + (MR_ULONG)model_set_ptr->am_cel_set);
			cel_set_ptr					= model_set_ptr->am_cel_set;
			j		  					= model_set_ptr->am_no_of_cel_sets;
			while(j--)
				{
				cel_set_ptr->ac_cels.ac_cels	= (MR_ANIM_CELS*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_set_ptr->ac_cels.ac_cels);

				// Within the cel set, resolve ptrs in MR_ANIM_CELS or MR_ANIM_CELS_PARTS
				k = cel_set_ptr->ac_no_of_cels_structures;

				if (anim_ptr->ah_flags & MR_MOF_ANIM_INDEXED_TRANSFORMS_IN_PARTS)
					{
					// THIS IS NEVER THE CASE!
					cel_part_ptr = cel_set_ptr->ac_cels.ac_cels_parts;
					while(k--)
						{
						cel_part_ptr->ac_rotations 		= (MR_USHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_part_ptr->ac_rotations);
						cel_part_ptr->ac_translations	= (MR_USHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_part_ptr->ac_translations);
						cel_part_ptr->ac_cel_numbers 	= (MR_USHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_part_ptr->ac_cel_numbers);
						cel_part_ptr++;
						}
					}
				else
					{
					// THIS IS ALWAYS THE CASE!
					cel_ptr = cel_set_ptr->ac_cels.ac_cels;
					while(k--)
						{
						cel_ptr->ac_transforms.ac_indices = (MR_SHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_ptr->ac_transforms.ac_indices);
						cel_ptr->ac_cel_numbers = (MR_USHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)cel_ptr->ac_cel_numbers);
						cel_ptr++;
						}
					}
				cel_set_ptr++;
				}	
			}

		// Resolve bounding boxes
		if (model_set_ptr->am_bbox_sets)
			{
			// Resolve ptrs in the model MR_ANIM_BBOX_SET
			model_set_ptr->am_bbox_sets	= (MR_ANIM_BBOX_SET*)((MR_ULONG)anim_ptr + (MR_ULONG)model_set_ptr->am_bbox_sets);
			bbox_set_ptr				= model_set_ptr->am_bbox_sets;
			j							= model_set_ptr->am_no_of_bbox_sets;
			while(j--)
				{
				if (bbox_set_ptr->ab_bboxes)
					{
					bbox_set_ptr->ab_bboxes = (MR_ANIM_BBOXES*)((MR_ULONG)anim_ptr + (MR_ULONG)bbox_set_ptr->ab_bboxes);
					abbox_ptr = bbox_set_ptr->ab_bboxes;

					// Resolve ptrs in MR_ANIM_BBOXES structures (it doesn't matter about pointer types in unions, so long as
					// they get resolved)
					abbox_ptr->ab_bboxes.ab_indices = (MR_SHORT*)((MR_ULONG)anim_ptr + (MR_ULONG)(abbox_ptr->ab_bboxes.ab_indices));
					}
				bbox_set_ptr++;
				}
			}
		model_set_ptr++;
		}

	//-------------------------------------------------------------------------
	// Resolve MR_ANIM_COMMON_DATA structure
	//-------------------------------------------------------------------------
	common_data 	= anim_ptr->ah_common_data;
	if (common_data->ac_flags & MR_ANIM_COMMON_TRANSFORMS_PRESENT)
		common_data->ac_transforms		= (MR_MAT34*)((MR_ULONG)anim_ptr + (MR_ULONG)common_data->ac_transforms);

	if (common_data->ac_flags & MR_ANIM_COMMON_ROTATIONS_PRESENT)
		common_data->ac_rotations 		= (MR_MAT34*)((MR_ULONG)anim_ptr + (MR_ULONG)common_data->ac_rotations);

	if (common_data->ac_flags & MR_ANIM_COMMON_TRANSLATIONS_PRESENT)
		common_data->ac_translations	= (MR_VEC*)((MR_ULONG)anim_ptr + (MR_ULONG)common_data->ac_translations);

	if (common_data->ac_flags & MR_ANIM_COMMON_BBOXES_PRESENT)
		common_data->ac_bboxes			= (MR_BBOX*)((MR_ULONG)anim_ptr + (MR_ULONG)common_data->ac_bboxes);

	// Debug breakpoint line
	model_set_ptr++;
}


/******************************************************************************
*%%%% MRAnimPatchMOFTranslucency
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimPatchMOFTranslucency(
*						MR_MOF* mof_ptr,
*						MR_BOOL	add_trans);
*
*	FUNCTION	Patches textured MR_MPRIM's in the specified MOF (animating)
*				to enable/disable translucent processing depending on
*				MR_TEXTURE translucency flags.
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*				add_trans	-	TRUE to add translucency where necessary,
*								else FALSE to remove it.
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	18.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimPatchMOFTranslucency(MR_MOF* mof_ptr, MR_BOOL add_trans)
{
	MR_MOF**		mof_pptr;
	MR_ANIM_HEADER*	anim_ptr;
	MR_USHORT		i;

	MR_ASSERT(mof_ptr != NULL);
	MR_ASSERT(mof_ptr->mm_flags & MR_MOF_OFFSETS_RESOLVED);

	anim_ptr	= (MR_ANIM_HEADER*)mof_ptr;
	mof_pptr	= anim_ptr->ah_static_files;
	i			= anim_ptr->ah_no_of_static_files;
	while(i--)
		{
		MRStaticPatchMOFTranslucency(*mof_pptr, add_trans);
		mof_pptr++;
		}	
}


/******************************************************************************
*%%%% MRAnimDisplayMeshInstance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimDisplayMeshInstance(
*						MR_MESH_INST*	mesh_inst_ptr,
*						MR_VIEWPORT*	viewport)
*
*	FUNCTION	Display a frame of an animating mesh instance
*
*	INPUTS		mesh_inst_ptr	-	ptr to mesh instance
*				viewport		-	ptr to viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.08.96	Tim Closs		Created
*	21.10.96	Dean Ashton		Applied Local OT bugfix
*	31.10.96	Tim Closs		Now sets MR_MESH_INST_DISPLAYED_LAST_FRAME only if
*								mesh rendered (on screen and in OT)
*	20.11.96	Tim Closs		Now takes just 2 inputs
*	10.02.97	Tim Closs		Fixed transform increment bug
*	12.02.97	Tim Closs		Altered debug display calls
*	17.02.97	Tim Closs		Now handles MR_ANIM_PART_REDUNDANT
*	13.03.97	Tim Closs		Fixed collprim display bug
*	18.03.97	Tim Closs		Anim file transforms now MUST be indexed (else
*								code will assert).  Added support for MR_QUATB_TRANS
*								transforms
*	04.04.97	Dean Ashton		Fixed bug where lw_transform wasn't set properly..
*	07.04.97	Dean Ashton		MRAnimDisplayMeshInstance() now respects
*								MR_MESH_IGNORE_BBOX and MR_MESH_CHECK_BBOX_USING_EDGES
*	02.06.97	Dean Ashton		Moved custom light modifications to remove possibility
*								of failed colour matrix reset, and also modified local
*								ordering table code to handle objects without frames.
*	13.06.97	Dean Ashton		Added support for MR_MRPRIM_GE3/MR_MRPRIM_GE4
*	04.07.97	Dean Ashton		Fixed bug to do with env mapping.
*	09.07.97	Dean Ashton		Added OT biasing with ot_global_ot_offset
*	16.07.97	Dean Ashton		Handles new models with frames starting at zero
*	20.08.97	Dean Ashton		At the request of Tim, it's now possible for animations
*								with local OT's to be inserted at the back of the global
*								OT.
*	13.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	MRAnimDisplayMeshInstance(	MR_MESH_INST*	mesh_inst_ptr,
									MR_VIEWPORT*	viewport)
{
	MR_OBJECT*				object_ptr;
	MR_MESH*				mesh_ptr;
	MR_ANIM_MESH*			amesh_ptr;
	MR_ANIM_HEADER*			anim_ptr;
	MR_ANIM_COMMON_DATA*	common_data;
	MR_ANIM_MODEL*			model_ptr;
	MR_ANIM_CELS*			cels_ptr;
	MR_ANIM_ENV*			anim_env;
	MR_ANIM_ENV_SINGLE*		anim_env_sing = NULL;
	MR_ANIM_ENV_MULTIPLE*	anim_env_mult = NULL;
	MR_UBYTE*				parts_flags;
	MR_ANIM_CPT_PARAMS		params;

	MR_SHORT				actual_cel, virtual_cel, parts;
	MR_MAT*					owner_transform;
	MR_MAT*					lw_transform;
	MR_VOID*				part_transform;

	MR_PART*				part_ptr;
	MR_SVEC*				vert_ptr;
	MR_BBOX*				bbox_ptr;
	MR_SVEC*				norm_ptr;
	MR_ULONG*				prim_ptr;
	MR_ULONG				prims;
	MR_ULONG*				mem;
	MR_SHORT				i, type, p, mult_model = NULL;
	MR_USHORT				prim_set;
	MR_FRAME*				camera_frame;
	MR_MAT*					temp_matrix_ptr;
	MR_MESH_PARAM			mesh_param;
	MR_SVEC					dm_svec;
	MR_VEC					dm_vec0;
	MR_BOOL					dm_light_dpq;
	MR_ULONG				dm_lights_modified;
	MR_ULONG				render_flags;

#ifdef	MR_DEBUG_DISPLAY
	MR_COLLPRIM*			collprim;
#endif

	// Stuff for bounding box check
	MR_ULONG				dm_long;


	MR_ASSERT(mesh_inst_ptr != NULL);
	MR_ASSERT(viewport != NULL); 

	object_ptr		= mesh_inst_ptr->mi_object;
	mesh_ptr		= object_ptr->ob_extra.ob_extra_mesh;
	amesh_ptr		= mesh_ptr->me_extra.me_extra_anim_mesh;
	anim_env		= amesh_ptr->am_environment;
	part_transform	= NULL;

	if (
		(!(anim_env->ae_flags & MR_ANIM_ENV_DISPLAY)) ||
		(anim_env->ae_flags & MR_ANIM_ENV_NOT_ACTIVE)
		)
		{
		// Environment display flag cleared, or environment not active
		return;
		}

	anim_ptr		= anim_env->ae_header;

	if (anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		anim_env_mult	= anim_env->ae_extra.ae_extra_env_multiple;
		mult_model		= amesh_ptr->am_model_no;
		model_ptr		= anim_env_mult->ae_models[mult_model];
		if (anim_env_mult->ae_action_number[mult_model] >= 0)
			cels_ptr 	= &model_ptr->am_cel_set->ac_cels.ac_cels[anim_env_mult->ae_action_number[mult_model]];
		else
			return;
		if ((virtual_cel = anim_env_mult->ae_cel_number[mult_model]) < 0)
			return;
		}
	else
		{
		anim_env_sing	= anim_env->ae_extra.ae_extra_env_single;
		model_ptr		= anim_env_sing->ae_model;
		if (anim_env_sing->ae_action_number >= 0)
			cels_ptr 	= &model_ptr->am_cel_set->ac_cels.ac_cels[anim_env_sing->ae_action_number];
		else
			return;
		if ((virtual_cel = anim_env_sing->ae_cel_number) < 0)
			return;
		}

	common_data		= (MR_ANIM_COMMON_DATA*)anim_ptr->ah_common_data;
	camera_frame	= viewport->vp_camera;
	dm_light_dpq	= ((object_ptr->ob_flags & MR_OBJ_ACCEPT_DPQ) && (MRVp_fog_near_distance));



	// Viewtrans is now the LW transform for the MR_OBJECT.  We will use this as a base transform, on top of which we must
	// add the transforms for individual parts of the anim

	// Actual cel index is got from frame number and virtual cel index table
	if (((MR_UBYTE*)anim_env->ae_header)[0] == MR_ANIM_FILE_START_FRAME_AT_ZERO)
		actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel];				// New models have frames starting at zero 
	else
		actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel] - 1;			// Old models have frames starting at 1

	parts		= cels_ptr->ac_no_of_parts;

	// If LW transforms have already been calculated for the parts, then 'transform' will run through the list of LW
	// transforms, NOT the list of transforms in the animation file
	if (anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
		{
		// LW transforms are always of type MR_MAT
		if (anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
			part_transform = anim_env_mult->ae_lw_transforms[mult_model];
		else
			part_transform = anim_env_sing->ae_lw_transforms;
		}

	// Set up object base transform: we need to do this for OT calcs and model-wide bounding box stuff
	if (object_ptr->ob_flags & MR_OBJ_STATIC)
		temp_matrix_ptr = (MR_MAT*)object_ptr->ob_frame;
	else
		temp_matrix_ptr = &object_ptr->ob_frame->fr_lw_transform;

	if (MRWorldtrans_ptr != temp_matrix_ptr)
		{
		MRWorldtrans_ptr = temp_matrix_ptr;
		MRMulMatrixABC(&viewport->vp_render_matrix, MRWorldtrans_ptr, MRViewtrans_ptr);
		}
	MRApplyMatrix(MRWorldtrans_ptr, &object_ptr->ob_offset, &dm_vec0);
	dm_svec.vx = MRWorldtrans_ptr->t[0] + dm_vec0.vx - viewport->vp_render_matrix.t[0];
	dm_svec.vy = MRWorldtrans_ptr->t[1] + dm_vec0.vy - viewport->vp_render_matrix.t[1];
	dm_svec.vz = MRWorldtrans_ptr->t[2] + dm_vec0.vz - viewport->vp_render_matrix.t[2];
	MRApplyMatrix(&viewport->vp_render_matrix, &dm_svec, (MR_VEC*)MRViewtrans_ptr->t);
		 
	// Set up GTE matrix and offset
	gte_SetRotMatrix(MRViewtrans_ptr);
	gte_SetTransMatrix(MRViewtrans_ptr);

	// Check mesh origin z is inside clip distance
	gte_ldv0(&MRNull_svec);
	gte_rtps();
	gte_stsz(&dm_long);
	if (dm_long > mesh_ptr->me_clip_distance)
		{
		// Mesh origin is beyond clip distance, so bail
		return;
		}

	// If frame-wide bounding box exists, check this and bail if off screen
	if (model_ptr->am_flags & MR_ANIM_PERCEL_BBOXES_INCLUDED)
		{
		bbox_ptr = &model_ptr->am_bbox_set->ab_bboxes->ab_bboxes.ab_bboxes[actual_cel];
		if (MRCheckBoundingBoxOnScreen(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
			{
			// Bin model!
			return;
			}
		// If mesh origin z beyond view distance, bail:
		if ((dm_long >> MRVp_otz_shift) >= MRVp_ot_size)
			return;

#ifdef MR_DEBUG_DISPLAY
		if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_ANIM_PERCEL_BBOX)
			{
			// Anim model has a frame-wide bounding box
			MRDebugPlotBoundingBox(&model_ptr->am_bbox_set->ab_bboxes->ab_bboxes.ab_bboxes[actual_cel], MR_DEBUG_DISPLAY_BBOX_COLOUR);
			}			
#endif
		}
	else
	// If model-wide bounding box exists, check this and bail if off screen
	if (model_ptr->am_flags & MR_ANIM_GLOBAL_BBOXES_INCLUDED)
		{
		bbox_ptr = model_ptr->am_static_bbox;
		if (MRCheckBoundingBoxOnScreen(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
			{
			// Bin model!
			return;
			}
		// If mesh origin z beyond view distance, bail:
		if ((dm_long >> MRVp_otz_shift) >= MRVp_ot_size)
			return;

#ifdef MR_DEBUG_DISPLAY
		if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_ANIM_GLOBAL_BBOX)
			{
			// Anim model has a static (model-wide) bounding box
			MRDebugPlotBoundingBox(bbox_ptr, MR_DEBUG_DISPLAY_BBOX_COLOUR);
			}			
#endif
		}

	// Do OT calcs
	if (mesh_inst_ptr->mi_ot != NULL) 
		{
		// Only calculate the view origin Z if it's not been calculated already this frame
		if (!(mesh_inst_ptr->mi_ot->ot_flags & MR_OT_ADDED_TO_GLOBAL))
			{
			gte_ldv0(&mesh_inst_ptr->mi_ot->ot_frame_offset);

			if (mesh_inst_ptr->mi_ot->ot_frame != object_ptr->ob_frame)
				{
				if (object_ptr->ob_flags & MR_OBJ_STATIC)
					MRWorldtrans_ptr = (MR_MAT*)object_ptr->ob_frame;
				else
					MRWorldtrans_ptr = &mesh_inst_ptr->mi_ot->ot_frame->fr_lw_transform;

				MRMulMatrixABC(&viewport->vp_render_matrix, MRWorldtrans_ptr, &MRTemp_matrix);
				dm_svec.vx = MRWorldtrans_ptr->t[0] - viewport->vp_render_matrix.t[0];
				dm_svec.vy = MRWorldtrans_ptr->t[1] - viewport->vp_render_matrix.t[1];
				dm_svec.vz = MRWorldtrans_ptr->t[2] - viewport->vp_render_matrix.t[2];
				MRApplyMatrix(&viewport->vp_render_matrix, &dm_svec, (MR_VEC*)MRTemp_matrix.t);
		 
				// Set up GTE matrix and offset
				gte_SetRotMatrix(&MRTemp_matrix);
				gte_SetTransMatrix(&MRTemp_matrix);
				gte_rtps();
				gte_stlvnl2(&mesh_inst_ptr->mi_ot->ot_view_origin_z);
				}
			else
				{
				gte_rtps();

				// Pull out non-limited SSZ from MAC3.  We don't know why, but MAC3 seems to be signed 16 bit, so wraps from 32767 to
				// -32768.  This means that we don't need to limit the max positive value (if it wraps to large negative, the model
				// will be clipped by the p_ot_clip value set below).
				gte_stlvnl2(&mesh_inst_ptr->mi_ot->ot_view_origin_z);
				}
			mesh_inst_ptr->mi_ot->ot_view_origin_z += mesh_inst_ptr->mi_ot->ot_global_ot_offset;
			}

		mesh_param.p_work_ot			= mesh_inst_ptr->mi_ot->ot_ot[MRFrame_index];
		mesh_param.p_otz_shift			= mesh_inst_ptr->mi_ot->ot_zshift;
		mesh_param.p_ot_size			= (1 << mesh_inst_ptr->mi_ot->ot_shift);
		mesh_param.p_ot_view_origin_z	= mesh_inst_ptr->mi_ot->ot_view_origin_z;
	
		// Do we need to add the local OT to the back of the global OT?		
		if (mesh_inst_ptr->mi_ot->ot_flags & MR_OT_FORCE_BACK)
			{
			i = MRVp_ot_size - 1;
			}
		else
			{
			// If we are about to add the local OT into the global OT at a position less than the global MR_OT_NEAR_CLIP, or greater
			// than the global OT size, then bail
			i = mesh_param.p_ot_view_origin_z >> MRVp_otz_shift;
			if ((i < MR_OT_NEAR_CLIP) || (i >= MRVp_ot_size))
				return;
			}

		mesh_param.p_ot_otz_delta		= (-mesh_param.p_ot_view_origin_z >> mesh_param.p_otz_shift) + (mesh_param.p_ot_size >> 1);

		// Decide what we want our min OT check to be
		if (((-mesh_param.p_ot_otz_delta << mesh_param.p_otz_shift) >> MRVp_otz_shift) <= MR_OT_NEAR_CLIP)
			{
			mesh_param.p_ot_clip		= ((MR_OT_NEAR_CLIP << MRVp_otz_shift) >> mesh_param.p_otz_shift) + mesh_param.p_ot_otz_delta;
			}
		else
			mesh_param.p_ot_clip		= 0;

		// Also, add local OT to global OT at (mesh_param.p_ot_view_origin_z >> MRVp_otz_shift)
		// (only if this local OT has not already been added)
		if (!(mesh_inst_ptr->mi_ot->ot_flags & MR_OT_ADDED_TO_GLOBAL))
			{
			// Flag local OT that it has been added to global OT
			mesh_inst_ptr->mi_ot->ot_flags |= MR_OT_ADDED_TO_GLOBAL;
	
			// Add local OT
			addPrims(MRVp_work_ot + i,
						mesh_param.p_work_ot + mesh_param.p_ot_size - 1,
						mesh_param.p_work_ot);
			}
		}
	else
		{
		mesh_param.p_work_ot				= MRVp_work_ot;
		mesh_param.p_otz_shift				= MRVp_otz_shift;
		mesh_param.p_ot_size				= MRVp_ot_size;
		mesh_param.p_ot_clip				= MR_OT_NEAR_CLIP;
		mesh_param.p_ot_view_origin_z		= 0;
		mesh_param.p_ot_otz_delta			= 0;
		}		

	// Now step through parts and transforms together

	// Set up vert_ptr, norm_ptr, prim_ptr
	part_ptr 	= (MR_PART*)(((MR_UBYTE*)(anim_ptr->ah_static_files[model_ptr->am_static_model])) + sizeof(MR_MOF));

	// Set flag saying this mesh instance was displayed
	mesh_inst_ptr->mi_flags |= MR_MESH_INST_DISPLAYED_LAST_FRAME;

	render_flags = mesh_inst_ptr->mi_flags & MR_MESH_INST_SPECIAL_RENDER_MASK;
		
	parts_flags = NULL;
	if (anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		if (anim_env_mult->ae_parts_flags)
			parts_flags = anim_env_mult->ae_parts_flags[mult_model];
		}
	else
		parts_flags = anim_env_sing->ae_parts_flags;

	//---------------------------------------------------------------------------------------------

	// If we:
	//		a. Have to scale the colour matrix, or have a custom ambient
	//		b.	Don't want an ambient colour
	//		c.	Don't want parallel lights	
	//		d. Are accepting pointlights, and there are some in the viewport
	//
	// Then:
	//		Recalculate the lighting matrix, and perhaps the ambient colour too..
	//
	//	Else:
	//		Use the viewport lighting matrix

	if (
		(mesh_inst_ptr->mi_light_flags & MR_INST_MODIFIED_LIGHT_MASK) ||
			(!(object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_AMBIENT)) || 
			(!(object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_PARALLEL)) ||
			((viewport->vp_pointlights) && (object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_POINT))
		)
		{
		dm_lights_modified = MRCalculateCustomInstanceLights(	object_ptr,
					 											mesh_inst_ptr->mi_light_flags,
					 											&mesh_inst_ptr->mi_colour_scale,
					 											&mesh_inst_ptr->mi_custom_ambient);
		}
	else
		{
		MR_COPY_MAT(&MRLight_matrix, &viewport->vp_light_matrix);
		dm_lights_modified = NULL;
		}

	//---------------------------------------------------------------------------------------------

	//---------------------------------------------------------------------------
	// Display each part
	//---------------------------------------------------------------------------
	prim_set = 0;
	for (p = 0; p < parts; p++)
		{
		// Check to see if we can skip this part
		if (parts_flags)
			{
			// Skip if part redundant
			if (parts_flags[p] & MR_ANIM_PART_REDUNDANT)
				{
				prim_set--;
				goto next_part;
				}

			// Skip if part hidden
			if (
				(anim_env->ae_special_flags & MR_ANIM_ENV_DISPLAY_LIMITED_PARTS) &&
				(!(parts_flags[p] & MR_ANIM_PART_DISPLAY))
				)
				goto next_part;
			}

		vert_ptr	= part_ptr->mp_partcel_ptr[0].mp_vert_ptr;
		bbox_ptr	= part_ptr->mp_partcel_ptr[0].mp_bbox_ptr;
		norm_ptr	= part_ptr->mp_partcel_ptr[0].mp_norm_ptr;
		prim_ptr	= part_ptr->mp_prim_ptr;
		prims	  	= part_ptr->mp_prims;
		mem	  		= mesh_inst_ptr->mi_prims[prim_set] + ((part_ptr->mp_buff_size >> 2) * MRFrame_index);

#ifdef MR_ANIM_COMPILE_IDENTITY_TRANSFORM
		part_transform = (MR_MAT*)&MRId_matrix;
#endif

		// Get view transform for the part.  The LW transform may already have been calculated
		if (anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
			{
			lw_transform	= (MR_MAT*)part_transform;
			MRMulMatrixABC(&viewport->vp_render_matrix, lw_transform, MRViewtrans_ptr);
			dm_svec.vx 		= lw_transform->t[0] - viewport->vp_render_matrix.t[0];
			dm_svec.vy 		= lw_transform->t[1] - viewport->vp_render_matrix.t[1];
			dm_svec.vz 		= lw_transform->t[2] - viewport->vp_render_matrix.t[2];
			}
		else
			{
			// We must build the transform
			if (object_ptr->ob_flags & MR_OBJ_STATIC)
				owner_transform = (MR_MAT*)object_ptr->ob_frame;
			else
				owner_transform = &object_ptr->ob_frame->fr_lw_transform;
														  
			// The following calculates the model->world transform for the part
			// temp_matrix_ptr points to the transformed matrix after calculation
			// MRTemp_svec is the transformed translation
			params.ac_cels_ptr 	= cels_ptr;
			params.ac_model		= mult_model;
			params.ac_part		= p;
			params.ac_cel 		= virtual_cel;
			temp_matrix_ptr		= MRAnimCalculatePartTransform(anim_env, &params);

			lw_transform   		= &MRAnim_temp_matrix;
			MRMulMatrixABC(owner_transform, temp_matrix_ptr, lw_transform);

			// Now build the new transform
			MRApplyMatrix(owner_transform, &MRTemp_svec, (MR_VEC*)lw_transform->t);
			MR_ADD_VEC((MR_VEC*)lw_transform->t, (MR_VEC*)owner_transform->t);

			MRMulMatrixABC(&viewport->vp_render_matrix, lw_transform, MRViewtrans_ptr);
			dm_svec.vx = lw_transform->t[0] - viewport->vp_render_matrix.t[0];
			dm_svec.vy = lw_transform->t[1] - viewport->vp_render_matrix.t[1];
			dm_svec.vz = lw_transform->t[2] - viewport->vp_render_matrix.t[2];
			}

		// Set MRWorldtrans_ptr to the parts local->world transform, 'cos it's used in environment mapping routines.
		MRWorldtrans_ptr = lw_transform;

		// Note:
		//
		//	lw_transform now points to a MR_MAT for the rotation and translation of the part in the world
		// dm_svec is the vector from the camera to the origin of the part

		MRApplyMatrix(&viewport->vp_render_matrix, &dm_svec, (MR_VEC*)MRViewtrans_ptr->t);
		// Note: this currently has not supported an offset in the MR_OBJECT!!!

		gte_SetRotMatrix(MRViewtrans_ptr);
		gte_SetTransMatrix(MRViewtrans_ptr);

		// Do part-wide bounding box clipping
		if (
			(!(mesh_ptr->me_flags & MR_MESH_IGNORE_BBOX)) &&
			(bbox_ptr)
			)
			{
			// Check bounding box
			if (mesh_ptr->me_flags & MR_MESH_CHECK_BBOX_USING_EDGES)
				{
				if (MRCheckBoundingBoxOnScreenUsingEdges(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
					goto next_part;
				}
			else
				{
				if (MRCheckBoundingBoxOnScreen(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
					goto next_part;
				}

			// If mesh origin z beyond view distance, bail:
			if ((dm_long >> MRVp_otz_shift) >= MRVp_ot_size)
				goto next_part;
			}

#ifdef MR_DEBUG_DISPLAY
		// Debug: display part-wide bounding box
		if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_PART_BBOX)
			MRDebugPlotBoundingBox(bbox_ptr, MR_DEBUG_DISPLAY_BBOX_COLOUR);

		// Debug: display collision primitives
		if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_COLLPRIMS)
			{
			if (collprim = part_ptr->mp_collprim_ptr)
				{	
				do {
					MRDebugPlotCollPrim(collprim, lw_transform, NULL, MR_DEBUG_DISPLAY_COLLPRIM_COLOUR);
	
					} while(!(collprim++->cp_flags & MR_COLL_LAST_IN_LIST));
				}
			// Non-aligned collprims change the current rotation matrix
			gte_SetRotMatrix(MRViewtrans_ptr);
			gte_SetTransMatrix(MRViewtrans_ptr);
			}
	
		// Debug: display hilite vertices
		if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_HILITE_VERTICES)
			MRDebugPlotHiliteVertices(part_ptr, MR_DEBUG_DISPLAY_HILITE_VERTICES_COLOUR);
#endif

		// Set up light matrix: this is always the LAST thing we do.
		// At this point, MRLight_matrix either contains custom or viewport light matrix
		MRMulMatrixABC(&MRLight_matrix, lw_transform, &MRTemp_matrix);
		gte_SetLightMatrix(&MRTemp_matrix);
  
		// Lighting code performs matrix multiplication, which destroys the GTE rotation matrix
		gte_SetRotMatrix(MRViewtrans_ptr);
		gte_SetTransMatrix(MRViewtrans_ptr);

		// Calculate the prims
		while(prims)
			{
			type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
			i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
			prim_ptr++;
			switch(type)
				{
	  			//---------------------------------------------------------------------------------------
				case MR_MPRIMID_F3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_F3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
	  			case MR_MPRIMID_F4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_F4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_FT3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_FT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_FT4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_FT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_G3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_G3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_G4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_G4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_GT3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_GT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_GT4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_GT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_E3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_E3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_E4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_E4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_GE3:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_GE3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_GE4:
					mesh_param.p_prims = prims;
					if (!render_flags)
						MRDisplayMeshPolys_GE4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_HLF3:
					mesh_param.p_prims = prims;
					MRDisplayMeshPolys_HLF3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				case MR_MPRIMID_HLF4:
					mesh_param.p_prims = prims;
					MRDisplayMeshPolys_HLF4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
					mem			=	mesh_param.p_mem_ptr;
					prim_ptr 	=	mesh_param.p_prim_ptr;	
					prims		=	mesh_param.p_prims;
					break;
				//---------------------------------------------------------------------------------------
				}
			}
	next_part:
		// Move on to next part
		part_ptr++;
		prim_set++;

		if (anim_env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
			((MR_MAT*)part_transform)++;
		}

	// If we've overwritten the colour matrix for this mesh, set it back to the viewport colour matrix
	if (dm_lights_modified & MR_CHANGED_COLOUR_MATRIX)
		gte_SetColorMatrix(&viewport->vp_colour_matrix);

	// If we've modified the ambient colour for this mesh, set it back to the viewport colour matrix
	if (dm_lights_modified & MR_CHANGED_AMBIENT_COLOUR)
		gte_SetBackColor(viewport->vp_back_colour.r, viewport->vp_back_colour.g, viewport->vp_back_colour.b);
}


/******************************************************************************
*%%%% MRAnimResolveMOFTextures
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimResolveMOFTextures(
*						MR_MOF* mof_ptr);
*
*	FUNCTION	Resolves a models UV texture coordinates to correctly represent
*				the appropriate textures UV coordinates in VRAM before Vorg 
*				processing (model UV's will be as set on initial load)
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*	NOTE		Assumes MOFs have already had offsets resolved to absolute
*				addresses
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	09.09.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimResolveMOFTextures(MR_MOF* mof_ptr)
{
	MR_ANIM_HEADER*		anim_ptr;
	MR_USHORT			i;
	MR_MOF** 			mof_pptr;


	anim_ptr	= (MR_ANIM_HEADER*)mof_ptr;

	// Run through static MOFs, resolving textures for each
	mof_pptr	= anim_ptr->ah_static_files;
	i			= anim_ptr->ah_no_of_static_files;
	while(i--)
		{
		MRStaticResolveMOFTextures(*mof_pptr);
		mof_pptr++;
		}	
}


/******************************************************************************
*%%%% MRAnimEnvSingleCreate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvSingleCreate(MR_VOID)
*
*	FUNCTION	Allocates space for and initialises a single anim environmenet
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	10.11.96	Tim Closs		Clears off some SINGLE stuff
*	17.01.97	Tim Closs		Sets vp_inst_count and model_set_ptr
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvSingleCreate(MR_VOID)
{
	MR_ANIM_ENV*			env;

	env	= MRAllocMem(sizeof(MR_ANIM_ENV) + sizeof(MR_ANIM_ENV_SINGLE), "MRAN_ENV");

	env->ae_prev_node 			= NULL;
	env->ae_next_node 			= NULL;
	env->ae_flags				= MR_ANIM_ENV_DEFAULT_FLAGS;
	env->ae_special_flags		= NULL;
	env->ae_update_count		= 0;
	env->ae_update_period		= 1;
	env->ae_vp_inst_count		= 0;
	env->ae_header				= NULL;
	env->ae_model_set			= NULL;
	env->ae_extra.ae_extra_void	= (MR_VOID*)((MR_UBYTE*)env) + sizeof(MR_ANIM_ENV);

	// Set up SINGLE stuff
	env->ae_extra.ae_extra_env_single->ae_cel_number 			= -1;
	env->ae_extra.ae_extra_env_single->ae_action_number 			= -1;
	env->ae_extra.ae_extra_env_single->ae_last_cel_number 		= -1;
	env->ae_extra.ae_extra_env_single->ae_last_action_number 	= -1;
	env->ae_extra.ae_extra_env_single->ae_total_cels			 	= -1;

	env->ae_extra.ae_extra_env_single->ae_parts_flags			= NULL;
	env->ae_extra.ae_extra_env_single->ae_events					= NULL;
	env->ae_extra.ae_extra_env_single->ae_lw_transforms			= NULL;
	env->ae_extra.ae_extra_env_single->ae_imported_transforms	= NULL;
	env->ae_extra.ae_extra_env_single->ae_parameters				= NULL;
	env->ae_extra.ae_extra_env_single->ae_user_struct			= NULL;

	MRNumber_of_anim_envs++;
	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvSingleLoad
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleLoad(
*						MR_ANIM_ENV*	env,
*						MR_ANIM_HEADER*	anim,
*						MR_USHORT		model_set,
*						MR_USHORT		model)
*
*	FUNCTION	Take a model from a model set and load in into a single environment
*
*	INPUTS		env			-	ptr to empty environment structure
*				anim 		-	ptr to MR_MOF (animation file)
*				model_set	-	index of model set within animation file
*				model		-	index of model within model set
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	10.11.96	Tim Closs		Part flags stuff changed slightly
*	17.01.97	Tim Closs		Now returns void, sets ae_model_set
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleLoad(MR_ANIM_ENV*  	env,
							MR_ANIM_HEADER*	anim,
							MR_USHORT	  	model_set,
							MR_USHORT	  	model)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	MR_ANIM_MODEL*		model_ptr;
	MR_ANIM_MODEL_SET*	model_set_ptr;


	MR_ASSERT(env);
	MR_ASSERT(anim);
	MR_ASSERT(model_set < anim->ah_no_of_model_sets);
	
	env_sing 		= env->ae_extra.ae_extra_env_single;
	model_set_ptr	= &anim->ah_model_sets[model_set];
	model_ptr		= &model_set_ptr->am_models[model];

	// Initialise structure
	env->ae_header		= anim;
	env->ae_model_set	= model_set_ptr;
	env_sing->ae_model	= model_ptr;
	env_sing->ae_object	= NULL;
	env_sing->ae_events	= NULL;
}

/******************************************************************************
*%%%% MRAnimEnvCreateMeshes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvCreateMeshes(
*						MR_ANIM_ENV*	env,
*						MR_FRAME*		frame,
*						MR_USHORT		obj_flags)
*
*	FUNCTION	Create the mesh(es) required for an animation environment
*
*	INPUTS		env			-	ptr to environment
*				frame 		-	ptr to frame
*				obj_flags	-	flags for MR_OBJECT of type MR_MESH
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvCreateMeshes(	MR_ANIM_ENV*	env,
					  			MR_FRAME*		frame,
								MR_USHORT		obj_flags)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_USHORT				n;


	MR_ASSERT(env);
	MR_ASSERT(frame);

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Create meshes for multiple environment
		env_mult = env->ae_extra.ae_extra_env_multiple;
		for (n = 0; n < env_mult->ae_no_of_models; n++)
			{
			if (env_mult->ae_models[n] != NULL)
				{
				// Model in this slot
				env_mult->ae_objects[n] = MRCreateMesh(	env->ae_header->ah_static_files[env_mult->ae_models[n]->am_static_model],
														frame,
														obj_flags,
														MR_MESH_ANIMATED);

				// Make sure mesh object points back to environment
				env_mult->ae_objects[n]->ob_owner.ob_owner_anim_env = env;

				// Set up MR_ANIM_MESH to point to this environment (MR_MESH_ANIM_ENV_MULTIPLE is NOT set in mesh flags)
				env_mult->ae_objects[n]->ob_extra.ob_extra_mesh->me_extra.me_extra_anim_mesh->am_environment 	= env;
				env_mult->ae_objects[n]->ob_extra.ob_extra_mesh->me_extra.me_extra_anim_mesh->am_model_no		= n;
				}
			}
		}
	else
	if (env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
		{
		// Create mesh for flipbook environment
		env_flip = env->ae_extra.ae_extra_env_flipbook;
		env_flip->ae_object = MRCreateMesh(	(MR_MOF*)env->ae_header,
											frame,
											obj_flags,
											MR_MESH_FLIPBOOK);

		// Make sure mesh object points back to environment
		env_flip->ae_object->ob_owner.ob_owner_anim_env = env;
		}
	else
		{
		// Create mesh for single environment
		env_sing = env->ae_extra.ae_extra_env_single;
		env_sing->ae_object = MRCreateMesh(	env->ae_header->ah_static_files[env_sing->ae_model->am_static_model],
											frame,
											obj_flags,
											MR_MESH_ANIMATED);

		// Make sure mesh object points back to environment
		env_sing->ae_object->ob_owner.ob_owner_anim_env = env;

		// Set up MR_ANIM_MESH to point to this environment (MR_MESH_ANIM_ENV_MULTIPLE is NOT set in mesh flags)
		env_sing->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_anim_mesh->am_environment 	= env;
		env_sing->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_anim_mesh->am_model_no		= 0;
		}
}

/******************************************************************************
*%%%% MRAnimLinkEnv
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimLinkEnv(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Link an animation environment into the linked list
*
*	INPUTS		env			-	ptr to environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimLinkEnv(MR_ANIM_ENV*	env)
{
 	MR_ASSERT(env);

	if (env->ae_next_node = MRAnim_env_root_ptr->ae_next_node)
		MRAnim_env_root_ptr->ae_next_node->ae_prev_node = env;

	MRAnim_env_root_ptr->ae_next_node = env;
	env->ae_prev_node = MRAnim_env_root_ptr;
}	


/******************************************************************************
*%%%% MRAnimUnlinkEnv
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimUnlinkEnv(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Unlink an animation environment from the linked list
*
*	INPUTS		env			-	ptr to environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimUnlinkEnv(MR_ANIM_ENV* env)
{
 	MR_ASSERT(env);

	env->ae_prev_node->ae_next_node = env->ae_next_node;
	if	(env->ae_next_node)
		env->ae_next_node->ae_prev_node = env->ae_prev_node;
}	

			
/******************************************************************************
*%%%% MRAnimKillEnv
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimKillEnv(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Kills an animation environment (frees all structure memory).
*				Note this does NOT set associated meshes to
*				MR_OBJ_DESTROY_BY_DISPLAY
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.10.96	Tim Closs		Created
*	14.01.97	Tim Closs		Now deallocates memory properly.  Does not touch
*								associated meshes
*	13.02.97	Tim Closs		No longer flags component meshes as
*								MR_OBJ_DESTROY_BY_DISPLAY
*
*%%%**************************************************************************/

MR_VOID	MRAnimKillEnv(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				m;


	MR_ASSERT(env);

	// Remove structure from linked list (if necessary)
	if (env->ae_prev_node)
		{
		env->ae_prev_node->ae_next_node = env->ae_next_node;
		if	(env->ae_next_node)
			env->ae_next_node->ae_prev_node = env->ae_prev_node;
		}

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Kill multiple environment
		env_mult = env->ae_extra.ae_extra_env_multiple;

		// Do environment type-specific memory freeing
		if (env_mult->ae_lw_transforms)
			MRFreeMem(env_mult->ae_lw_transforms);

		for (m = 0; m < env_mult->ae_no_of_models; m++)
			{
			if (env_mult->ae_parts_flags[m])
				MRFreeMem(env_mult->ae_parts_flags[m]);

			if (env_mult->ae_imported_transforms[m])
				MRFreeMem(env_mult->ae_imported_transforms[m]);
			}

		// Free main multiple block
		if (env_mult->ae_models)
			MRFreeMem(env_mult->ae_models);
		}
	else
		{
		// Kill single environment
		env_sing = env->ae_extra.ae_extra_env_single;

		// Do environment type-specific memory freeing
		if (env->ae_special_flags & (MR_ANIM_ENV_DISPLAY_LIMITED_PARTS | MR_ANIM_ENV_IMPORTED_TRANSFORMS))
			{
			if (env_sing->ae_parts_flags)
				MRFreeMem(env_sing->ae_parts_flags);
			}
		if (env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
			{
			if (env_sing->ae_lw_transforms)
				MRFreeMem(env_sing->ae_lw_transforms);
			}
		if (env->ae_special_flags & MR_ANIM_ENV_IMPORTED_TRANSFORMS)
			{
			if (env_sing->ae_imported_transforms)
				MRFreeMem(env_sing->ae_imported_transforms);
			}
		}

	// Decrease count
	MRNumber_of_anim_envs--;

	// Free structure memory
	MRFreeMem(env);
}

/******************************************************************************
*%%%% MRAnimUpdateEnvironments
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimUpdateEnvironments(MR_VOID)
*
*	FUNCTION	Update all single and multiple anim environments
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.10.96	Tim Closs		Created
*	23.07.97	Tim Closs		Fixed bug where update_period > 1 was arsing
*								when an action was changed
*	13.08.97	Tim Closs		Changed to not access MOF for flipbook 
*								animations that are being destroyed.
*
*%%%**************************************************************************/

MR_VOID	MRAnimUpdateEnvironments(MR_VOID)
{
	MR_ANIM_ENV*			env_ptr;
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_SHORT				n;
	MR_ANIM_MODEL*			model_ptr;
	MR_SHORT*				cel_number_ptr;
	MR_SHORT*				total_cels_ptr;
	MR_STATIC_MESH*			static_mesh;
	MR_PART_FLIPBOOK*		flipbook;


	cel_number_ptr	= NULL;
	total_cels_ptr	= NULL;
	env_ptr 		= MRAnim_env_root_ptr;
	while(env_ptr	= env_ptr->ae_next_node)
		{
		//-----------------------------------------------------------------------
		// Handle stepping (increase of virtual frame number)
		//-----------------------------------------------------------------------
		if (!(env_ptr->ae_flags & (MR_ANIM_ENV_NOT_ACTIVE | MR_ANIM_ENV_DESTROY_BY_DISPLAY)))
			{
			if (env_ptr->ae_flags & MR_ANIM_ENV_STEP)
				{
				n			= 0;
				env_mult	= env_ptr->ae_extra.ae_extra_env_multiple;
	
				while(n >= 0)
					{
					// This loop handles single and multiple updates
					if (env_ptr->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
						{
						// Multiple environment
						if (
							(n == env_mult->ae_no_of_models) ||
							((model_ptr = env_mult->ae_models[n]) == NULL)
							)
							{
							break;
							}
		
						if (env_mult->ae_action_number[n] >= 0)
							{
							cel_number_ptr		= &env_mult->ae_cel_number[n];
							total_cels_ptr		= &env_mult->ae_total_cels[n];
							n++;
							}
						else
							{
							n++;
							goto step_next_model;
							}
						}
					else
					if (env_ptr->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
						{
						// Flipbook environment
						env_flip	= env_ptr->ae_extra.ae_extra_env_flipbook;
						n  			= -1;
	
						if (env_flip->ae_action_number >= 0)
							{
							cel_number_ptr		= &env_flip->ae_cel_number;
							total_cels_ptr		= &env_flip->ae_total_cels;
							}
						else
							goto step_next_model;
						}
					else
						{
						// Single environment
						env_sing	= env_ptr->ae_extra.ae_extra_env_single;
						n 			= -1;
	
						if (env_sing->ae_action_number >= 0)
							{
							cel_number_ptr		= &env_sing->ae_cel_number;
							total_cels_ptr		= &env_sing->ae_total_cels;
							}
						else
							goto step_next_model;
						}
	
					env_ptr->ae_update_count++;
					if	(
						(env_ptr->ae_update_count >= env_ptr->ae_update_period) ||
						(*cel_number_ptr == -1)
						)
						{
						// Core update
						env_ptr->ae_update_count = 0;
						(*cel_number_ptr)++;
	
						// Check for reaching end of action
						if (*cel_number_ptr >= *total_cels_ptr)
							{
							// Reached end of anim
							if (env_ptr->ae_flags & MR_ANIM_ENV_ONE_SHOT_AND_KILL)
								{
								// Kill whole environment
								MRAnimEnvDestroyByDisplay(env_ptr);
								goto step_next_env;
								}
							else
							if (env_ptr->ae_flags & MR_ANIM_ENV_ONE_SHOT)
								(*cel_number_ptr)--;
							else
								(*cel_number_ptr) = 0;
							}
						// End of core update
						}
					step_next_model:
					}
				}
			if (env_ptr->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
				{
				// Write exact MR_PARTCEL index to MR_STATIC_MESH
				env_flip				= env_ptr->ae_extra.ae_extra_env_flipbook;
				static_mesh 			= env_ptr->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh;
				flipbook				= (MR_PART_FLIPBOOK*)((MR_PART*)(((MR_MOF*)env_ptr->ae_header) + 1))->mp_pad1;
				static_mesh->sm_partcel = (((MR_PART_FLIPBOOK_ACTION*)(flipbook + 1)) + env_flip->ae_action_number)->mp_partcel_index + env_flip->ae_cel_number;
				}
			}
		step_next_env:
		}

	env_ptr 		= MRAnim_env_root_ptr;
	while(env_ptr	= env_ptr->ae_next_node)
		{
		//-----------------------------------------------------------------------
		// Handle update (calculation of part lw transforms)
		//-----------------------------------------------------------------------
		if (
			(env_ptr->ae_flags & MR_ANIM_ENV_UPDATE) &&
			(!(env_ptr->ae_flags & (MR_ANIM_ENV_NOT_ACTIVE | MR_ANIM_ENV_DESTROY_BY_DISPLAY)))
			)
			{
			MRAnimEnvUpdateLWTransforms(env_ptr);
			}
		}

	env_ptr 		= MRAnim_env_root_ptr;
	while(env_ptr	= env_ptr->ae_next_node)
		{
		//-----------------------------------------------------------------------
		// Handle user callback
		//-----------------------------------------------------------------------
		if (
			(env_ptr->ae_special_flags & MR_ANIM_ENV_USER_CALLBACK_ACTIVE) &&
			(!(env_ptr->ae_flags & (MR_ANIM_ENV_NOT_ACTIVE | MR_ANIM_ENV_DESTROY_BY_DISPLAY)))
			)
			{
			(env_ptr->ae_user_callback)(env_ptr);
			}
		}

	env_ptr 		= MRAnim_env_root_ptr;
	while(env_ptr	= env_ptr->ae_next_node)
		{
		//-----------------------------------------------------------------------
		// Handle events
		//-----------------------------------------------------------------------
		if (
			(env_ptr->ae_special_flags & MR_ANIM_ENV_EVENT_LIST_ACTIVE) &&
			(!(env_ptr->ae_flags & (MR_ANIM_ENV_NOT_ACTIVE | MR_ANIM_ENV_DESTROY_BY_DISPLAY)))
			)
			{
			MRAnimEnvCheckEvents(env_ptr);
			}
		}
}


/******************************************************************************
*%%%% MRAnimAddEnvToViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV_INST*	env_inst = 	MRAnimAddEnvToViewport(
*												MR_ANIM_ENV*	env,
*												MR_VIEWPORT*	vp,
*												MR_USHORT		flags)
*
*	FUNCTION	Adds an animation environment to a viewport.  Returns back a
*				pointer to the MR_MESH_INST created.
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*				vp			-	ptr to viewport
*				flags		-	flags
*
*	RESULT		env_inst	-	ptr to MR_ANIM_ENV_INST structure
*
*	NOTES		Flags currently suported:
*					MR_USE_VP_LIGHT_MATRIX
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.10.96	Tim Closs		Created
*	17.12.96	Tim Closs		Fixed double add object bug!
*
*%%%**************************************************************************/

MR_ANIM_ENV_INST*	MRAnimAddEnvToViewport(	MR_ANIM_ENV*	env,
											MR_VIEWPORT*	vp,
											MR_USHORT		flags)
{				
	MR_ANIM_ENV_INST*		env_inst;
	MR_ANIM_ENV_INST*		env_root;
	MR_UBYTE				m;
	MR_OBJECT**				object_pptr;
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_MESH_INST**			mesh_inst_pptr;


	MR_ASSERT(env);
	MR_ASSERT(vp);
	
	env_sing = NULL;
	env_mult = NULL;

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Add multiple environment to viewport
		env_mult		= env->ae_extra.ae_extra_env_multiple;
		object_pptr 	= env_mult->ae_objects;
		m				= env_mult->ae_no_of_models;

		// Allocate and set up structure
		env_inst					= MRAllocMem(sizeof(MR_ANIM_ENV_INST) + (sizeof(MR_MESH_INST*) * m), "MRANENVI");
		env_inst->ae_environment	= env;
		env_inst->ae_viewport		= vp;
		env_inst->ae_models			= m;
		env_inst->ae_mesh_insts		= (MR_MESH_INST**)(((MR_UBYTE*)env_inst) + sizeof(MR_ANIM_ENV_INST));

		// Add models to viewport, storing MR_MESH_INST* along the way
		mesh_inst_pptr				= env_inst->ae_mesh_insts;
		while(m--)
			{
			// Add rest of models
			*mesh_inst_pptr			= MRAddObjectToViewport(*object_pptr, vp, flags);
			object_pptr++;
			mesh_inst_pptr++;
			}
		}
	else
		{

		// Add single/flipbook environment to viewport

		// Allocate and set up structure
		env_inst					= MRAllocMem(sizeof(MR_ANIM_ENV_INST) + sizeof(MR_MESH_INST*), "MRANENVI");
		env_inst->ae_environment	= env;
		env_inst->ae_viewport		= vp;
		env_inst->ae_models			= 1;
		env_inst->ae_mesh_insts		= (MR_MESH_INST**)(((MR_UBYTE*)env_inst) + sizeof(MR_ANIM_ENV_INST));

		// Add model to viewport, storing MR_MESH_INST* along the way
		if (env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
			*env_inst->ae_mesh_insts	= MRAddObjectToViewport(env->ae_extra.ae_extra_env_flipbook->ae_object, vp, flags);
		else			
			*env_inst->ae_mesh_insts	= MRAddObjectToViewport(env->ae_extra.ae_extra_env_single->ae_object, vp, flags);
		}	

	// Increase environment instance count
	env->ae_vp_inst_count++;

	// Link instance into list
	env_root = vp->vp_env_root_ptr;
	if (env_inst->ae_next_node = env_root->ae_next_node)
		env_root->ae_next_node->ae_prev_node = env_inst;
	env_root->ae_next_node 	= env_inst;
	env_inst->ae_prev_node 	= env_root;

	env_inst->ae_kill_timer	= 0;

	return(env_inst);
}


/******************************************************************************
*%%%% MRAnimEnvSingleCreateWhole
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_ENV*	env = 	MRAnimEnvSingleCreateWhole(
*										MR_ANIM_HEADER*	anim,
*										MR_USHORT		model_set,
*										MR_USHORT		obj_flags,
*										MR_FRAME*		frame,
*
*	INPUTS		anim 		-	ptr to MR_MOF (animation file)
*				model_set	-	index of model set within animation file
*				obj_flags	-	flags for MR_OBJECT of type MR_MESH
*				frame		-	ptr to frame
*
*	FUNCTION	Allocates space for and initialises a single anim environment, then
*				loads a model into it (the frst in the set), creates a mesh and
*				links the environment
*
*	RESULT		env			-	ptr to environment, or NULL if failed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.11.96	Tim Closs		Created
*	10.01.97	Tim Closs		Changed name and removed model input
*
*%%%**************************************************************************/

MR_ANIM_ENV*	MRAnimEnvSingleCreateWhole(	MR_ANIM_HEADER*	anim,
				  						  	MR_USHORT 		model_set,
				  						  	MR_USHORT 		obj_flags,
				  						  	MR_FRAME* 		frame)
{
	MR_ANIM_ENV*	env;
	
	MR_ASSERT(anim);
	MR_ASSERT(frame);

	env = MRAnimEnvSingleCreate();
	MRAnimEnvSingleLoad(env, anim, model_set, 0);
	MRAnimEnvCreateMeshes(env, frame, obj_flags);
	MRAnimLinkEnv(env);

	return(env);
}


/******************************************************************************
*%%%% MRAnimEnvGetPartTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	=	MRAnimEnvGetPartTransform(
*							MR_ANIM_ENV*	env,
*							MR_MAT*			mat,
*							MR_USHORT		model,
*							MR_USHORT		part)
*
*	FUNCTION	Finds the transform for a part of a model in an environment
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*				mat			-	ptr to MR_MAT to hold transform data
*				model		-	index of model within environment (ignored for single)
*				part		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.12.96	Tim Closs		Created
*	10.02.97	Tim Closs		Now handles compressed and byte transforms
*	24.03.97	Tim Closs		Updated to use MRAnimCalculatePartTransform()
*	03.04.97	Dean Ashton		Changed to accept pointer to matrix, instead of
*								returning a pointer to what could potentially be
*								pointing to MRTemp_matrix..
*	16.04.97	Dean Ashton		Fixed bug where matrix was being copied from
*								MRTemp_matrix, not 'transform' (breaking when using
*								normal-format matrices).
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvGetPartTransform(	MR_ANIM_ENV*	env,
									MR_MAT*			mat,
		 							MR_USHORT		model,
		 							MR_USHORT		part)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_MODEL*			model_ptr;
	MR_MAT34*	  			transform;
	MR_ANIM_CPT_PARAMS		params;

	
	MR_ASSERT(env);
	
	env_sing = NULL;
	env_mult = NULL;

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Multiple environment
		env_mult		= env->ae_extra.ae_extra_env_multiple;
		model_ptr	= env_mult->ae_models[model];
		MR_ASSERT(model_ptr);
		MR_ASSERT(env_mult->ae_action_number[model] >= 0);
		MR_ASSERT(env_mult->ae_cel_number[model] >= 0);

		params.ac_cels_ptr 	= &model_ptr->am_cel_set->ac_cels.ac_cels[env_mult->ae_action_number[model]];
		params.ac_model		= model;
		params.ac_part		= part;
		params.ac_cel 		= env_mult->ae_cel_number[model];
		}
	else
		{
		// Single environment
		env_sing	= env->ae_extra.ae_extra_env_single;
		model_ptr	= env_sing->ae_model;
		MR_ASSERT(model_ptr);
		MR_ASSERT(env_sing->ae_action_number >= 0);
		MR_ASSERT(env_sing->ae_cel_number >= 0);

		params.ac_cels_ptr 	= &model_ptr->am_cel_set->ac_cels.ac_cels[env_sing->ae_action_number];
		params.ac_model		= NULL;
		params.ac_part		= part;
		params.ac_cel		= env_sing->ae_cel_number;
		}	

	transform = (MR_MAT34*)MRAnimCalculatePartTransform(env, &params);

	// Put stuff in output matrix
	MR_COPY_MAT(mat, transform);
	MR_VEC_EQUALS_SVEC(&mat->t[0], &MRTemp_svec);
}


/******************************************************************************
*%%%% MRAnimEnvUpdateLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvUpdateLWTransforms(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Calculates and stores LW transforms for all parts in an
*				environment, but ONLY if required (ie. if we have a different
*				action or actual cel number to last time)
*
*	INPUTS		env			-	ptr to environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Check for different action or actual cel
*	10.02.97	Tim Closs		Fixed transform increment bug
*	12.02.97	Tim Closs		Now rebuilds if MR_FRAME_REBUILT_LAST_FRAME set
*								for the environment's MR_FRAME
*	16.07.97	Dean Ashton		Handles new models with frames starting at zero
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvUpdateLWTransforms(MR_ANIM_ENV* env)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_CELS*			cels_ptr;
	MR_USHORT				virtual_cel;
	MR_USHORT				actual_cel;
	MR_USHORT				model;
	MR_OBJECT*				object;
	MR_OBJECT**				object_pptr;
	MR_ANIM_MODEL**			model_pptr;

	
	MR_ASSERT(env);
	
	env_sing = NULL;
	env_mult = NULL;

	if (env->ae_special_flags & MR_ANIM_ENV_STORE_LW_TRANSFORMS)
		{
		if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
			{
			// Multiple environment
			env_mult	= env->ae_extra.ae_extra_env_multiple;
			MR_ASSERT(env_mult->ae_lw_transforms);
			model_pptr	= env_mult->ae_models;
			object_pptr	= env_mult->ae_objects;

			for (model = 0; model < env_mult->ae_no_of_models; model++)
				{
				// Check if we need to generate transforms for this model
				if (
					(env_mult->ae_action_number[model] < 0) ||
					(env_mult->ae_cel_number[model] < 0)
					)
					goto next_model;
			
				cels_ptr	= &(*model_pptr)->am_cel_set->ac_cels.ac_cels[env_mult->ae_action_number[model]];
				virtual_cel = env_mult->ae_cel_number[model];

				// Actual cel index is got from frame number and virtual cel index table
				if (((MR_UBYTE*)env->ae_header)[0] == MR_ANIM_FILE_START_FRAME_AT_ZERO)
					actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel];		// New models have frames starting at zero
				else
					actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel] - 1;	// Old models have frames starting at 1

				// cel is actual cel number, so is ae_last_cel_number
				if (
					(env_mult->ae_action_number[model] == env_mult->ae_last_action_number[model]) &&
					(actual_cel == env_mult->ae_last_cel_number[model]) &&
					(((*object_pptr)->ob_flags & MR_OBJ_STATIC) || (!((*object_pptr)->ob_frame->fr_flags & MR_FRAME_REBUILT_LAST_FRAME)))
					)
					{
					// Same action and actual cel as last time, so no new transforms to generate
					goto next_model;
					}
	
				// Write new last_ indices
				env_mult->ae_last_action_number[model]	= env_mult->ae_action_number[model];
				env_mult->ae_last_cel_number[model]		= actual_cel;

				object = *object_pptr;

				// Set up view transform
				if (object->ob_flags & MR_OBJ_STATIC)
					MRWorldtrans_ptr = (MR_MAT*)object->ob_frame;
				else
					MRWorldtrans_ptr = &object->ob_frame->fr_lw_transform;

				MRAnimEnvUpdateModelLWTransforms(env, cels_ptr, virtual_cel, model);

			next_model:
				model_pptr++;
				object_pptr++;
				}
			}
		else
			{
			// Single environment
			env_sing	= env->ae_extra.ae_extra_env_single;
			MR_ASSERT(env_sing->ae_lw_transforms);
			object		= env_sing->ae_object;

			// Check if we need to generate transforms for this model
			if (
				(env_sing->ae_action_number < 0) ||
				(env_sing->ae_cel_number < 0)
				)
				goto end_single;

			cels_ptr	= &env_sing->ae_model->am_cel_set->ac_cels.ac_cels[env_sing->ae_action_number];

			virtual_cel	= env_sing->ae_cel_number;

			// Actual cel index is got from frame number and virtual cel index table
			if (((MR_UBYTE*)env->ae_header)[0] == MR_ANIM_FILE_START_FRAME_AT_ZERO)
				actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel];		// New models have frames starting at zero
			else
				actual_cel	= cels_ptr->ac_cel_numbers[virtual_cel] - 1;	// Old models have frames starting at 1

			// cel is actual cel number, so is ae_last_cel_number
			if (
				(env_sing->ae_action_number == env_sing->ae_last_action_number) &&
				(actual_cel == env_sing->ae_last_cel_number) &&
				((object->ob_flags & MR_OBJ_STATIC) || (!(object->ob_frame->fr_flags & MR_FRAME_REBUILT_LAST_FRAME)))
				)
				{
				// Same action and actual cel as last time, so no new transforms to generate
				goto end_single;
				}

			// Write new last_ indices
			env_sing->ae_last_action_number	= env_sing->ae_action_number;
			env_sing->ae_last_cel_number 	= actual_cel;
	
			// Set up view transform
			if (object->ob_flags & MR_OBJ_STATIC)
				MRWorldtrans_ptr = (MR_MAT*)object->ob_frame;
			else
				MRWorldtrans_ptr = &object->ob_frame->fr_lw_transform;

			MRAnimEnvUpdateModelLWTransforms(env, cels_ptr, virtual_cel, 0);

		end_single:
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvUpdateModelLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvUpdateModelLWTransforms(
*						MR_ANIM_ENV*	env,
*						MR_ANIM_CELS*	cels_ptr,
*						MR_USHORT		virtual_cel,
*						MR_USHORT		model)
*
*	FUNCTION	Calculate the LW transforms for a model in an environment
*				(called from MRAnimEnvUpdateLWTransforms)
*
*	INPUTS		env			-	ptr to animation environment
*				cels_ptr	-	ptr to MR_ANIM_CELS for model
*				virtual_cel	-	virtual cel index
*				model		-	index of model (if MR_ANIM_ENV_MULTIPLE)
*
*	NOTES		MRWorldtrans_ptr has been pointed to the model->world transform
*				Also, if a part is MR_ANIM_PART_REDUNDANT, memory has still been
*				allocated for that part's transform, but it is never calculated
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.02.97	Tim Closs		Created
*	17.02.97	Tim Closs		Now handles MR_ANIM_PART_REDUNDANT
*	18.03.97	Tim Closs		Anim file transforms now MUST be indexed (else
*								code will assert).  Added support for MR_QUATB_TRANS
*								transforms
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvUpdateModelLWTransforms(	MR_ANIM_ENV*	env,
											MR_ANIM_CELS*	cels_ptr,
											MR_USHORT		virtual_cel,
											MR_USHORT		model)
{
	MR_USHORT		 	parts, p;
	MR_MAT*			 	temp_matrix_ptr;
	MR_VEC				vec;
	MR_UBYTE*			parts_flags;
	MR_MAT*				lw_transform;
	MR_ANIM_CPT_PARAMS	params;


	MR_ASSERT(env);
	MR_ASSERT(cels_ptr);

	parts 		= cels_ptr->ac_no_of_parts;
	parts_flags	= NULL;

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		lw_transform 	= env->ae_extra.ae_extra_env_multiple->ae_lw_transforms[model];
		if (env->ae_extra.ae_extra_env_multiple->ae_parts_flags)
			parts_flags = env->ae_extra.ae_extra_env_multiple->ae_parts_flags[model];
		}
	else
		{
		lw_transform 	= env->ae_extra.ae_extra_env_single->ae_lw_transforms;
		parts_flags 	= env->ae_extra.ae_extra_env_single->ae_parts_flags;
		}

	for (p = 0; p < parts; p++)
		{
		// Calculate LW transform
		//
		// Get pointer to transform (indexed)

		// Check to see if we can skip this part
		if (parts_flags)
			{
			// Skip if part redundant
			if (parts_flags[p] & MR_ANIM_PART_REDUNDANT)
				goto next_part;
			}

		// The following calculates the part's transform
		// temp_matrix_ptr points to the transformed matrix after calculation,
		// MRTemp_svec is the transformed translation
		params.ac_cels_ptr 	= cels_ptr;
		params.ac_model		= model;
		params.ac_part		= p;
		params.ac_cel		= virtual_cel;
		temp_matrix_ptr 	= MRAnimCalculatePartTransform(env, &params);

		MRMulMatrixABC(MRWorldtrans_ptr, temp_matrix_ptr, lw_transform);
		MRApplyMatrix(MRWorldtrans_ptr, &MRTemp_svec, &vec);
		lw_transform->t[0] = vec.vx + MRWorldtrans_ptr->t[0];
		lw_transform->t[1] = vec.vy + MRWorldtrans_ptr->t[1];
		lw_transform->t[2] = vec.vz + MRWorldtrans_ptr->t[2];

	next_part:
		lw_transform++;
		}
}


/******************************************************************************
*%%%% MRAnimEnvSetFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	flags	=	MRAnimEnvSetFlags(
*										MR_ANIM_ENV*	env,
*										MR_USHORT		mask)
*
*	FUNCTION	Sets all bits set in the mask
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvSetFlags(	MR_ANIM_ENV*	env,
								MR_USHORT		mask)
{
	MR_ASSERT(env);

	env->ae_flags |= mask;
	return(env->ae_flags);
}


/******************************************************************************
*%%%% MRAnimEnvClearFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	flags	=	MRAnimEnvClearFlags(
*										MR_ANIM_ENV*	env,
*										MR_USHORT		mask)
*
*	FUNCTION	Clears all bits set in the mask
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvClearFlags(	MR_ANIM_ENV*	env,
									MR_USHORT		mask)
{
	MR_ASSERT(env);

	env->ae_flags &= ~mask;
	return(env->ae_flags);
}


/******************************************************************************
*%%%% MRAnimEnvGetFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	flags	=	MRAnimEnvGetFlags(
*										MR_ANIM_ENV*	env)
*
*	FUNCTION	Returns the environment flags
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvGetFlags(MR_ANIM_ENV*	env)
{
	MR_ASSERT(env);

	return(env->ae_flags);
}


/******************************************************************************
*%%%% MRAnimEnvSetSpecialFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	flags	=	MRAnimEnvSetSpecialFlags(
*										MR_ANIM_ENV*	env,
*										MR_USHORT		mask)
*
*	FUNCTION	Sets all bits set in the mask
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Now no longer does any allocation!
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvSetSpecialFlags(	MR_ANIM_ENV*	env,
										MR_USHORT		mask)
{
	MR_ASSERT(env);
	
	env->ae_special_flags |= mask;
	return(env->ae_special_flags);
}


/******************************************************************************
*%%%% MRAnimEnvClearSpecialFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	flags	=	MRAnimEnvClearSpecialFlags(
*										MR_ANIM_ENV*	env,
*										MR_USHORT		mask)
*
*	FUNCTION	Clears all bits set in the mask
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	new flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Now no longer does any deallocation!
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvClearSpecialFlags(	MR_ANIM_ENV*	env,
										MR_USHORT		mask)
{
	MR_ASSERT(env);

	env->ae_special_flags &= ~mask;
	return(env->ae_special_flags);
}


/******************************************************************************
*%%%% MRAnimEnvGetSpecialFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_USHORT	flags	=	MRAnimEnvGetSpecialFlags(
*			 							MR_ANIM_ENV*	env)
*
*	FUNCTION 	Returns the environment special flags
*
*	INPUTS		env			-	ptr to environment
*
*	RESULT		flags		-	flags field
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRAnimEnvGetSpecialFlags(MR_ANIM_ENV*	env)
{
	MR_ASSERT(env);

	return(env->ae_special_flags);
}


/******************************************************************************
*%%%% MRAnimEnvSingleSetPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE flags	=	MRAnimEnvSingleSetPartFlags(
*							  	 	MR_ANIM_ENV*	env,
*							  	 	MR_USHORT		part,
*							  	 	MR_UBYTE		mask)
*
*	FUNCTION	Sets all bits set in the mask.  Allocates the parts_flags if
*				necessary
*
*	INPUTS		env			-	ptr to environment (single)
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

MR_UBYTE	MRAnimEnvSingleSetPartFlags(	MR_ANIM_ENV*	env,
		  		  							MR_USHORT		part,
		  		  							MR_UBYTE		mask)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	MR_USHORT			b;
	MR_UBYTE*			byte_ptr;

	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);

	if ((mask & MR_ANIM_PART_REDUNDANT) && (env->ae_vp_inst_count))
		MR_ASSERTMSG(NULL, "Cannot set MR_ANIM_PART_REDUNDANT after environment has been instanced");

	if (env_sing->ae_parts_flags == NULL)
		{
		// Parts flags do not exist - make allocation
		b		  					= MR_WORD_ALIGN(env_sing->ae_model->am_no_of_parts);
		env_sing->ae_parts_flags 	= MRAllocMem(b, "PARTFLGS");
		byte_ptr  					= (MR_UBYTE*)env_sing->ae_parts_flags;
		while(b--)
			*byte_ptr++ = MR_ANIM_PART_DISPLAY;
		}

	env_sing->ae_parts_flags[part] |= mask;
	return(env_sing->ae_parts_flags[part]);
}


/******************************************************************************
*%%%% MRAnimEnvSingleClearPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE	flags	=	MRAnimEnvSingleClearPartFlags(
*						  				MR_ANIM_ENV*	env,
*						  				MR_USHORT		part,
*						  				MR_UBYTE		mask)
*
*	FUNCTION	Clears all bits set in the mask
*
*	INPUTS		env			-	ptr to environment (single)
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

MR_UBYTE	MRAnimEnvSingleClearPartFlags(	MR_ANIM_ENV*	env,
		  									MR_USHORT		part,
		  									MR_UBYTE		mask)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	MR_USHORT			b;
	MR_UBYTE*			byte_ptr;


	MR_ASSERT(env);

	if (mask & MR_ANIM_PART_REDUNDANT)
		MR_ASSERTMSG(NULL, "It is illegal to clear this part flag");

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);

	if (env_sing->ae_parts_flags == NULL)
		{
		// Parts flags do not exist - make allocation
		b		  					= MR_WORD_ALIGN(env_sing->ae_model->am_no_of_parts);
		env_sing->ae_parts_flags 	= MRAllocMem(b, "PARTFLGS");
		byte_ptr  					= (MR_UBYTE*)env_sing->ae_parts_flags;
		while(b--)
			*byte_ptr++ = MR_ANIM_PART_DISPLAY;
		}

	env_sing->ae_parts_flags[part] &= ~mask;
	return(env_sing->ae_parts_flags[part]);
}


/******************************************************************************
*%%%% MRAnimEnvSingleGetPartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_UBYTE	flags	=	MRAnimEnvSingleGetPartFlags(
*						  				MR_ANIM_ENV*	env,
*						  				MR_USHORT		part)
*
*	FUNCTION	Get the part flags
*
*	INPUTS		env			-	ptr to environment (single)
*				part		-	index of part within model
*
*	RESULT		flags		-	part flags
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_UBYTE	MRAnimEnvSingleGetPartFlags(MR_ANIM_ENV*	env,
						  				MR_USHORT		part)
{
	MR_ANIM_ENV_SINGLE*	env_sing;

	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);
	MR_ASSERT(env_sing->ae_parts_flags);

	return(env_sing->ae_parts_flags[part]);
}


/******************************************************************************
*%%%% MRAnimEnvSingleDeletePartFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleDeletePartFlags(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Frees any parts flags allocations
*
*	INPUTS		env			-	ptr to single environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleDeletePartFlags(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*	env_sing;


	MR_ASSERT(env);

	env_sing = env->ae_extra.ae_extra_env_single;

	if (env_sing->ae_parts_flags)
		{
		MRFreeMem(env_sing->ae_parts_flags);
		env_sing->ae_parts_flags = NULL;
		}
	
	env->ae_special_flags &= ~(MR_ANIM_ENV_DISPLAY_LIMITED_PARTS | MR_ANIM_ENV_IMPORTED_TRANSFORMS);
}


/******************************************************************************
*%%%% MRAnimEnvSingleCreateLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MAT*	matrix	=	MRAnimEnvSingleCreateLWTransforms(
*									MR_ANIM_ENV*	env)
*
*	FUNCTION	Allocates space for one LW transform per part, and returns
*				pointer to first transform
*
*	INPUTS		env			-	ptr to single environment
*
*	RESULT		matrix		-	ptr to first matrix
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_MAT*	MRAnimEnvSingleCreateLWTransforms(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*	env_sing;

	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(env_sing->ae_lw_transforms == NULL);

	env_sing->ae_lw_transforms = MRAllocMem(sizeof(MR_MAT) * env_sing->ae_model->am_no_of_parts, "LW_TRANS");

	env->ae_special_flags |= MR_ANIM_ENV_STORE_LW_TRANSFORMS;
	return(env_sing->ae_lw_transforms);
}


/******************************************************************************
*%%%% MRAnimEnvSingleDeleteLWTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleDeleteLWTransforms(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Frees space used by LW transforms
*
*	INPUTS		env			-	ptr to single environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleDeleteLWTransforms(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*	env_sing;

	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(env_sing->ae_lw_transforms);
	MRFreeMem(env_sing->ae_lw_transforms);
	env_sing->ae_lw_transforms = NULL;
	env->ae_special_flags &= ~MR_ANIM_ENV_STORE_LW_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimEnvSingleSetImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleSetImportedTransform(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		part,
*						MR_MAT*			transform)
*
*	FUNCTION	Sets a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to single environment
*				part		-	index of part within model
*				transform	-	pointer to transform to import
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.01.97	Tim Closs		Created
*	17.01.97	Tim Closs		Handles allocation
*	11.06.97	Dean Ashton		Fixed bug where matrix_pptr was incorrectly
*								used after being incremented
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleSetImportedTransform(MR_ANIM_ENV*	env,
											MR_USHORT		part,
											MR_MAT*			transform)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	MR_USHORT			b;
	MR_MAT**			matrix_pptr;


	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);

	if (env_sing->ae_imported_transforms == NULL)
		{
		// Imported transform ptrs do not exist - make allocation
		b				= env_sing->ae_model->am_no_of_parts;
		matrix_pptr	= MRAllocMem(sizeof(MR_MAT*) * b, "IM_TRANS");
		env_sing->ae_imported_transforms = matrix_pptr;

		while(b--)
			*matrix_pptr++ = NULL;
		}

	env_sing->ae_imported_transforms[part] = transform;
	env->ae_special_flags |= MR_ANIM_ENV_IMPORTED_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimEnvSingleClearImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleClearImportedTransform(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		part)
*
*	FUNCTION	Clear a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to single environment
*				part		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleClearImportedTransform(	MR_ANIM_ENV*	env,
												MR_USHORT		part)
{
	MR_ANIM_ENV_SINGLE*	env_sing;


	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(env_sing->ae_imported_transforms);
	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);

	env_sing->ae_imported_transforms[part] = NULL;
}


/******************************************************************************
*%%%% MRAnimEnvSingleGetImportedTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MAT*	matrix	=	MRAnimEnvSingleGetImportedTransform(
*				 					MR_ANIM_ENV*	env,
*				 					MR_USHORT		part)
*
*	FUNCTION	Returns a pointer to an imported transform for a part
*
*	INPUTS		env			-	pointer to single environment
*				part		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_MAT*	MRAnimEnvSingleGetImportedTransform(MR_ANIM_ENV*	env,
											MR_USHORT		part)
{
	MR_ANIM_ENV_SINGLE*	env_sing;


	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(env_sing->ae_imported_transforms);
	MR_ASSERT(part < env_sing->ae_model->am_no_of_parts);

	return(env_sing->ae_imported_transforms[part]);
}


/******************************************************************************
*%%%% MRAnimEnvSingleDeleteImportedTransforms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleDeleteImportedTransforms(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Frees space used by imported transforms
*
*	INPUTS		env			-	ptr to single environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleDeleteImportedTransforms(MR_ANIM_ENV* env)
{
	MR_ANIM_ENV_SINGLE*	env_sing;


	MR_ASSERT(env);

	env_sing	= env->ae_extra.ae_extra_env_single;

	MR_ASSERT(env_sing->ae_imported_transforms);
	MRFreeMem(env_sing->ae_imported_transforms);
	env_sing->ae_imported_transforms = NULL;
	env->ae_special_flags &= ~MR_ANIM_ENV_IMPORTED_TRANSFORMS;
}


/******************************************************************************
*%%%% MRAnimCalculatePartTransform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MAT*	matrix	= 	MRAnimCalculatePartTransform(
*									MR_ANIM_ENV*		env,
*									MR_ANIM_CPT_PARAMS*	params)
*
*	FUNCTION	Calculate the model->world transform for a part, including
*				imported transforms
*
*	INPUTS		env			-	ptr to environment
*				params		-	ptr to structure containing all the info we need
*								to calculate the transform
*
*	RESULT		matrix		-	ptr to transformed rotation
*
*	NOTES		MRTemp_svec always hold transformed translation
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.01.97	Tim Closs		Created
*	17.03.97	Tim Closs		Changed MRApplyMatrixVEC to MRApplyMatrix
*	18.03.97	Tim Closs		Changed transform input to MR_VOID*
*								Anim file transforms now MUST be indexed (else
*								code will assert).  Added support for MR_QUATB_TRANS
*								transforms
*	12.06.97	Tim Closs		New transform formats:
*								MR_ANIM_FILE_ID_NORMAL				(16bit matrix)
*								MR_ANIM_FILE_ID_BYTE_TRANSFORMS		(8bit matrix)
*								MR_ANIM_FILE_ID_QUATB_TRANSFORMS	(8bit quaternion)	
*								MR_ANIM_FILE_ID_QUAT_TRANSFORMS		(16bit quaternion)
*								For quaternion transforms, MR_ANIM_CELS flag 
*								MR_ANIM_CELS_VIRTUAL_INTERPOLATION indicates virtual cel list is
*								interpreted as (prev actual cel index, next actual cel index, interpolation param)
*	16.07.97	Dean Ashton		Handles new models with frames starting at zero
*	30.07.97	Dean Ashton		Fixed bug where tsize wasn't being correctly setup for
*								non-interpolated quaternion animations
*
*%%%**************************************************************************/

MR_MAT*	MRAnimCalculatePartTransform(	MR_ANIM_ENV*		env,
										MR_ANIM_CPT_PARAMS*	params)
{
	MR_MAT*			imported_part_transform;
	MR_MAT*			imported_model_transform;
	MR_MAT*			matrix;
	MR_MAT34*		mat34 = NULL;
	MR_VEC			vec;
	MR_VOID*	 	part_transform;
	MR_USHORT		parts, model, part, t, actual_cel;
	MR_USHORT*		index_ptr;
	MR_QUAT			quat;
	MR_QUAT_TRANS*	quat_prev;
	MR_QUAT_TRANS*	quat_next;
	MR_QUATB_TRANS*	quatb_prev;
	MR_QUATB_TRANS*	quatb_next;
	MR_ANIM_CELS*	cels_ptr;
	MR_UBYTE		file_type;
	MR_LONG			scale_x, scale_y, scale_z, sp, sn, tsize = 0;
	static MR_LONG	trans_sizes[] =
		{
		sizeof(MR_MAT34),
		sizeof(MR_MAT34B),
		sizeof(MR_QUATB_TRANS),
		sizeof(MR_QUAT_TRANS),
		sizeof(MR_QUATB_SCALE_TRANS),
		sizeof(MR_QUAT_SCALE_TRANS),
		};

	model		= params->ac_model;
	part		= params->ac_part;
	cels_ptr	= params->ac_cels_ptr;
	parts 		= cels_ptr->ac_no_of_parts;

	// Actual cel index is got from frame number and virtual cel index table
	if (((MR_UBYTE*)env->ae_header)[0] == MR_ANIM_FILE_START_FRAME_AT_ZERO)
		actual_cel	= cels_ptr->ac_cel_numbers[params->ac_cel];				// New models have frames starting at zero
	else
		actual_cel	= cels_ptr->ac_cel_numbers[params->ac_cel] - 1;			// Old models have frames starting at 1

	switch(file_type = ((MR_UBYTE*)env->ae_header)[1])
		{
		//-----------------------------------------------------------------------
		case MR_ANIM_FILE_ID_QUAT_TRANSFORMS:
		case MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS:

			// Find size of transform. 
			tsize = trans_sizes[file_type - MR_ANIM_FILE_ID_NORMAL];

			// Rotation is short quaternion, translation is 3 shorts
			if (cels_ptr->ac_flags & MR_ANIM_CELS_VIRTUAL_INTERPOLATION)
				{
				index_ptr	= cels_ptr->ac_cel_numbers + (params->ac_cel * 3);

				// index_ptr points to a group of 3 MR_USHORTs (prev actual cel index, next actual cel index, interpolation param)
				quat_prev 	= (MR_QUAT_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(index_ptr[0] * parts) + part]) * tsize));
				quat_next 	= (MR_QUAT_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(index_ptr[1] * parts) + part]) * tsize));

				t			= index_ptr[2];	
				MR_INTERPOLATE_QUAT_TO_QUAT(&quat_prev->q, &quat_next->q, &quat, t);
				MR_QUAT_TO_MAT(&quat, (MR_MAT*)&MRTemp_matrix);
	
				// Consider applying scaling
				if (file_type == MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS)
					{
					if 	(
						(((MR_QUAT_SCALE_TRANS*)quat_prev)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING) ||
						(((MR_QUAT_SCALE_TRANS*)quat_next)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING)
						)
						{
						// Get interpolated scaling values
						sp		= ((MR_QUAT_SCALE_TRANS*)quat_prev)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUAT_SCALE_TRANS*)quat_next)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_x = ((sp * (0x1000 - t)) + (sn * t)) >> 12;
						sp		= ((MR_QUAT_SCALE_TRANS*)quat_prev)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUAT_SCALE_TRANS*)quat_next)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_y = ((sp * (0x1000 - t)) + (sn * t)) >> 12;
						sp		= ((MR_QUAT_SCALE_TRANS*)quat_prev)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUAT_SCALE_TRANS*)quat_next)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_z = ((sp * (0x1000 - t)) + (sn * t)) >> 12;
						MR_SCALE_MATRIX(&MRTemp_matrix, scale_x, scale_y, scale_z);
						}
					}
				// Interpolate translation
				((MR_MAT34*)&MRTemp_matrix)->t[0]	= ((quat_prev->t[0] * (0x1000 - t)) + (quat_next->t[0] * t)) >> 12;
				((MR_MAT34*)&MRTemp_matrix)->t[1]	= ((quat_prev->t[1] * (0x1000 - t)) + (quat_next->t[1] * t)) >> 12;
				((MR_MAT34*)&MRTemp_matrix)->t[2]	= ((quat_prev->t[2] * (0x1000 - t)) + (quat_next->t[2] * t)) >> 12;
				}
			else
				{
				// Convert quaternion to matrix
				part_transform	= (MR_QUAT_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(actual_cel * parts) + part]) * tsize));
				MR_QUAT_TO_MAT(&((MR_QUAT_TRANS*)part_transform)->q, &MRTemp_matrix);
	
				// Consider applying scaling
				if	(
					(file_type == MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS) &&
					(((MR_QUAT_SCALE_TRANS*)part_transform)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING)
					)
					{
					// Get scale values
					scale_x	= ((MR_QUAT_SCALE_TRANS*)part_transform)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					scale_y	= ((MR_QUAT_SCALE_TRANS*)part_transform)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					scale_z	= ((MR_QUAT_SCALE_TRANS*)part_transform)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					MR_SCALE_MATRIX(&MRTemp_matrix, scale_x, scale_y, scale_z);
					}	
				// Copy translation
				((MR_MAT34*)&MRTemp_matrix)->t[0]	= ((MR_QUAT_TRANS*)part_transform)->t[0];
				((MR_MAT34*)&MRTemp_matrix)->t[1]	= ((MR_QUAT_TRANS*)part_transform)->t[1];
				((MR_MAT34*)&MRTemp_matrix)->t[2]	= ((MR_QUAT_TRANS*)part_transform)->t[2];
				}

			mat34 = (MR_MAT34*)&MRTemp_matrix;
			break;
		//-----------------------------------------------------------------------
		case MR_ANIM_FILE_ID_QUATB_TRANSFORMS:
		case MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS:

			// Find size of transform. 
			tsize = trans_sizes[file_type - MR_ANIM_FILE_ID_NORMAL];

			// Rotation is byte quaternion, translation is 3 shorts
			if (cels_ptr->ac_flags & MR_ANIM_CELS_VIRTUAL_INTERPOLATION)
				{
				index_ptr	= cels_ptr->ac_cel_numbers + (params->ac_cel * 3);
	
				// index_ptr points to a group of 3 MR_USHORTs (prev actual cel index, next actual cel index, interpolation param)
				quatb_prev 	= (MR_QUATB_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(index_ptr[0] * parts) + part]) * tsize));
				quatb_next 	= (MR_QUATB_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(index_ptr[1] * parts) + part]) * tsize));
				t			= index_ptr[2];	
				MR_INTERPOLATE_QUATB_TO_MAT(&quatb_prev->q, &quatb_next->q, (MR_MAT*)&MRTemp_matrix, t);
	
				// Consider applying scaling
				if (file_type == MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS)
					{
					if 	(
						(((MR_QUATB_SCALE_TRANS*)quatb_prev)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING) ||
						(((MR_QUATB_SCALE_TRANS*)quatb_next)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING)
						)
						{
						// Get interpolated scaling values
						sp		= ((MR_QUATB_SCALE_TRANS*)quatb_prev)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUATB_SCALE_TRANS*)quatb_next)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_x = ((sp * (0x1000 - t)) + (sn * t)) >> 12;
						sp		= ((MR_QUATB_SCALE_TRANS*)quatb_prev)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUATB_SCALE_TRANS*)quatb_next)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_y = ((sp * (0x1000 - t)) + (sn * t)) >> 12;
						sp		= ((MR_QUATB_SCALE_TRANS*)quatb_prev)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						sn		= ((MR_QUATB_SCALE_TRANS*)quatb_next)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
						scale_z = ((sp * (0x1000 - t)) + (sn * t)) >> 12;

						// NOTE: MR_SCALE_MATRIX currently trashes the 10th MR_SHORT in the structure (which is t[0] for a 
						// MR_MAT34)
						MR_SCALE_MATRIX(&MRTemp_matrix, scale_x, scale_y, scale_z);
						}
					}
				// Interpolate translation
				((MR_MAT34*)&MRTemp_matrix)->t[0]	= ((quatb_prev->t[0] * (0x1000 - t)) + (quatb_next->t[0] * t)) >> 12;
				((MR_MAT34*)&MRTemp_matrix)->t[1]	= ((quatb_prev->t[1] * (0x1000 - t)) + (quatb_next->t[1] * t)) >> 12;
				((MR_MAT34*)&MRTemp_matrix)->t[2]	= ((quatb_prev->t[2] * (0x1000 - t)) + (quatb_next->t[2] * t)) >> 12;
				}
			else
				{
				// Convert quaternion to matrix
				part_transform = (MR_QUATB_TRANS*)(((MR_UBYTE*)env->ae_header->ah_common_data->ac_transforms) + ((cels_ptr->ac_transforms.ac_indices[(actual_cel * parts) + part]) * tsize));
				MR_QUATB_TO_MAT(&((MR_QUATB_TRANS*)part_transform)->q, &MRTemp_matrix);
	
				// Consider applying scaling
				if	(
					(file_type == MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS) &&
					(((MR_QUATB_SCALE_TRANS*)part_transform)->flags & MR_QUAT_SCALE_TRANS_USE_SCALING)
					)
					{
					// Get scale values
					scale_x	= ((MR_QUATB_SCALE_TRANS*)part_transform)->s[0] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					scale_y	= ((MR_QUATB_SCALE_TRANS*)part_transform)->s[1] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					scale_z	= ((MR_QUATB_SCALE_TRANS*)part_transform)->s[2] << (12 - MR_QUAT_SCALE_TRANS_FIXED_POINT);
					MR_SCALE_MATRIX(&MRTemp_matrix, scale_x, scale_y, scale_z);
					}	
				// Copy translation
				((MR_MAT34*)&MRTemp_matrix)->t[0]	= ((MR_QUATB_TRANS*)part_transform)->t[0];
				((MR_MAT34*)&MRTemp_matrix)->t[1]	= ((MR_QUATB_TRANS*)part_transform)->t[1];
				((MR_MAT34*)&MRTemp_matrix)->t[2]	= ((MR_QUATB_TRANS*)part_transform)->t[2];
				}
			mat34 = (MR_MAT34*)&MRTemp_matrix;
			break;
		//-----------------------------------------------------------------------
		case MR_ANIM_FILE_ID_BYTE_TRANSFORMS:
			// Rotation is byte matrix, translation is 3 shorts
			//
			// Expand 8bit entries to 16bit entries
			part_transform = (MR_MAT34B*)env->ae_header->ah_common_data->ac_transforms + (cels_ptr->ac_transforms.ac_indices[(actual_cel * parts) + part]);
			MRTemp_matrix.m[0][0]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[0][0]) << 5;
			MRTemp_matrix.m[0][1]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[0][1]) << 5;
			MRTemp_matrix.m[0][2]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[0][2]) << 5;
			MRTemp_matrix.m[1][0]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[1][0]) << 5;
			MRTemp_matrix.m[1][1]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[1][1]) << 5;
			MRTemp_matrix.m[1][2]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[1][2]) << 5;
			MRTemp_matrix.m[2][0]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[2][0]) << 5;
			MRTemp_matrix.m[2][1]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[2][1]) << 5;
			MRTemp_matrix.m[2][2]	= ((MR_SHORT)((MR_MAT34B*)part_transform)->m[2][2]) << 5;
	
			// Copy translation
			((MR_MAT34*)&MRTemp_matrix)->t[0]	= ((MR_MAT34B*)part_transform)->t[0];
			((MR_MAT34*)&MRTemp_matrix)->t[1]	= ((MR_MAT34B*)part_transform)->t[1];
			((MR_MAT34*)&MRTemp_matrix)->t[2]	= ((MR_MAT34B*)part_transform)->t[2];
			mat34 								= (MR_MAT34*)&MRTemp_matrix;
			break;
		//-----------------------------------------------------------------------
		case MR_ANIM_FILE_ID_NORMAL:
			// Rotation is short matrix, translation is 3 shorts
			part_transform = (MR_MAT34*)env->ae_header->ah_common_data->ac_transforms + (cels_ptr->ac_transforms.ac_indices[(actual_cel * parts) + part]);
			mat34 = part_transform;
			break;
		}

	// mat34 now points to a valid MR_MAT34
	
	// Handle imported transform
	imported_part_transform	 	= NULL;
	imported_model_transform	= NULL;

	if (env->ae_special_flags & MR_ANIM_ENV_IMPORTED_TRANSFORMS)
		{
		if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
			{
			if (env->ae_extra.ae_extra_env_multiple->ae_imported_transforms[model])
				{
				// This model has imported transform ptrs, so MUST have parts flags
				MR_ASSERT(env->ae_extra.ae_extra_env_multiple->ae_parts_flags[model]);

				if (env->ae_extra.ae_extra_env_multiple->ae_imported_transforms[model][part])
					{
					if (env->ae_extra.ae_extra_env_multiple->ae_parts_flags[model][part] & MR_ANIM_PART_TRANSFORM_PART_SPACE)
						imported_part_transform = env->ae_extra.ae_extra_env_multiple->ae_imported_transforms[model][part];
					else
					if (env->ae_extra.ae_extra_env_multiple->ae_parts_flags[model][part] & MR_ANIM_PART_TRANSFORM_MODEL_SPACE)
						imported_model_transform = env->ae_extra.ae_extra_env_multiple->ae_imported_transforms[model][part];
					}
				}
			}			
		else
			{
			if (env->ae_extra.ae_extra_env_single->ae_imported_transforms)
				{
				// This model has imported transform ptrs, so MUST have parts flags
				MR_ASSERT(env->ae_extra.ae_extra_env_single->ae_parts_flags);

				if (env->ae_extra.ae_extra_env_single->ae_imported_transforms[part])
					{
					if (env->ae_extra.ae_extra_env_single->ae_parts_flags[part] & MR_ANIM_PART_TRANSFORM_PART_SPACE)
						imported_part_transform = env->ae_extra.ae_extra_env_single->ae_imported_transforms[part];
					else
					if (env->ae_extra.ae_extra_env_single->ae_parts_flags[part] & MR_ANIM_PART_TRANSFORM_MODEL_SPACE)
						imported_model_transform = env->ae_extra.ae_extra_env_single->ae_imported_transforms[part];
					}
				}
			}			
		}

	if (imported_part_transform)
		{
		MRMulMatrixABC((MR_MAT*)mat34, imported_part_transform, &MRTemp_matrix);
		MR_SVEC_EQUALS_VEC(&MRTemp_svec, (MR_VEC*)imported_part_transform->t);
		MRApplyMatrix((MR_MAT*)mat34, &MRTemp_svec, &vec);
		matrix 		  	= &MRTemp_matrix;
		MRTemp_svec.vx	= vec.vx + mat34->t[0];
		MRTemp_svec.vy	= vec.vy + mat34->t[1];
		MRTemp_svec.vz	= vec.vz + mat34->t[2];
		}
	else
	if (imported_model_transform)
		{
		MRMulMatrixABC(imported_model_transform, (MR_MAT*)mat34, &MRTemp_matrix);
		matrix		  	= &MRTemp_matrix;
		MRTemp_svec.vx	= imported_model_transform->t[0] + mat34->t[0];
		MRTemp_svec.vy	= imported_model_transform->t[1] + mat34->t[1];
		MRTemp_svec.vz	= imported_model_transform->t[2] + mat34->t[2];
		}
	else
		{
		matrix		  	= (MR_MAT*)mat34;
		MRTemp_svec.vx	= mat34->t[0];
		MRTemp_svec.vy	= mat34->t[1];
		MRTemp_svec.vz	= mat34->t[2];
		}

	// BODGE to test scaling code
//	MR_INIT_MAT(&MRTemp_matrix);	
//	MRTemp_matrix.m[0][0] 	= (params->ac_cel << 12) / cels_ptr->ac_no_of_virtual_cels;
//	MRTemp_matrix.m[1][1] 	= (params->ac_cel << 12) / cels_ptr->ac_no_of_virtual_cels;
//	MRTemp_matrix.m[2][2] 	= (params->ac_cel << 12) / cels_ptr->ac_no_of_virtual_cels;
//	MRTemp_svec.vx			= 0x60;
//	MRTemp_svec.vy			= 0;
//	MRTemp_svec.vz			= 0x60;
//	matrix		  			= (MR_MAT*)mat34;
	// BODGE to test scaling code

	return(matrix);
}
	

/******************************************************************************
*%%%% MRAnimRemoveEnvInstanceFromViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimRemoveEnvInstanceFromViewport(
*						MR_ANIM_ENV_INST*	env_inst,
*						MR_VIEWPORT*		viewport);
*
*	FUNCTION	Removes an instance of an environment from the specified viewport
*
*	INPUTS		env_inst	-	ptr to valid MR_ANIM_ENV_INST structure
*				viewport	-	ptr to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.01.97	Tim Closs		Created
*	04.06.97	Dean Ashton		Changed to request removal of mesh instances too
*
*%%%**************************************************************************/

MR_VOID	MRAnimRemoveEnvInstanceFromViewport(MR_ANIM_ENV_INST*	env_inst,
											MR_VIEWPORT*		viewport)
{
	MR_LONG	model;

	MR_ASSERT(env_inst);
	MR_ASSERT(viewport);

	env_inst->ae_environment->ae_vp_inst_count--;
	env_inst->ae_kill_timer = 2;

	// For each model in the environment, signal a removal of the instance data from the viewport
	for (model = 0; model < env_inst->ae_models; model++)
		MRRemoveMeshInstanceFromViewport(env_inst->ae_mesh_insts[model], viewport);
}


/******************************************************************************
*%%%% MRAnimRemoveEnvInstanceFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimRemoveEnvInstanceFromViewportPhysically(
*						MR_ANIM_ENV_INST*	env_inst,
*						MR_VIEWPORT*		viewport);
*
*	FUNCTION	Removes an instance of an environment from the specified viewport
*				immediately
*
*	INPUTS		env_inst	-	ptr to valid MR_ANIM_ENV_INST structure
*				viewport	-	ptr to the MR_VIEWPORT to remove from
*
*	NOTE		This does not destroy any MR_MESH structures
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.01.97	Tim Closs		Created
*	13.02.97	Tim Closs		Now kills component meshes and mesh instances
*	03.09.97	Dean Ashton		Fixed bug where environment was being killed
*								multiple times if the routine was called with
*								some mesh instances having kill timer set.
*
*%%%**************************************************************************/

MR_VOID	MRAnimRemoveEnvInstanceFromViewportPhysically(	MR_ANIM_ENV_INST*	env_inst,
												  		MR_VIEWPORT*		viewport)
{
	MR_USHORT	model;


	MR_ASSERT(env_inst != NULL);
	MR_ASSERT(viewport != NULL);

	// Remove instance from viewport's env instance list
	env_inst->ae_prev_node->ae_next_node = env_inst->ae_next_node;
	if	(env_inst->ae_next_node)
		env_inst->ae_next_node->ae_prev_node = env_inst->ae_prev_node;

	// For each model in the environment, physically remove the mesh inst from the viewport
	for (model = 0; model < env_inst->ae_models; model++)
		{
		// Note that when the last instance of a mesh is removed, the mesh object is killed
		MRRemoveMeshInstanceFromViewportPhysically(env_inst->ae_mesh_insts[model], viewport);
		}

	// Kill the env if there are no more instances hanging around... but don't kill the environment
	// for instances that are in the process of being killed. Y'see, the MR_ANIM_ENV will have been
	// killed in a prior MRRenderViewport()
	if (env_inst->ae_kill_timer == 0)
		{
		if (!(--env_inst->ae_environment->ae_vp_inst_count))
			MRAnimKillEnv(env_inst->ae_environment);
		}

	// Free memory for instance structure
	MRFreeMem(env_inst);
}


/******************************************************************************
*%%%% MRAnimEnvDestroyByDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvDestroyByDisplay(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Flags an environment as MR_ANIM_ENV_DESTROY_BY_DISPLAY and all
*				associated meshes as MR_OBJ_DESTROY_BY_DISPLAY for tidy removal
*
*	INPUTS		env			-	ptr to environment
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvDestroyByDisplay(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				m;

	MR_ASSERT(env);

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Multiple environment
		env_mult = env->ae_extra.ae_extra_env_multiple;

		for (m = 0; m < env_mult->ae_no_of_models; m++)
			env_mult->ae_objects[m]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
	else
	if (env->ae_flags & MR_ANIM_ENV_IS_FLIPBOOK)
		{
		// Flipbook environment
		env->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
	else
		{
		// Single environment
		env->ae_extra.ae_extra_env_single->ae_object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}

	env->ae_flags |= MR_ANIM_ENV_DESTROY_BY_DISPLAY;
}


/******************************************************************************
*%%%% MRAnimEnvSingleSetAction
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleSetAction(
*						MR_ANIM_ENV*	env,
*						MR_SHORT		action)
*
*	FUNCTION	Change the action of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (single)
*				action		-	action number (-1 for no action)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleSetAction(	MR_ANIM_ENV*	env,
									MR_SHORT		action)
{
	MR_ANIM_ENV_SINGLE*	env_sing;

	
	MR_ASSERT(env);

	env_sing = env->ae_extra.ae_extra_env_single;
	
	if (action == -1)
		{
		// Turn model off
		env_sing->ae_action_number	= -1;
		env_sing->ae_total_cels		= -1;
		env_sing->ae_cel_number		= -1;
		}
	else
		{
		MR_ASSERTMSG(action < env_sing->ae_model->am_cel_set->ac_no_of_cels_structures, "Action number too big");
		env_sing->ae_action_number	= action;
		env_sing->ae_total_cels		= env_sing->ae_model->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels;
		env_sing->ae_cel_number 	= -1;
		}
}


/******************************************************************************
*%%%% MRAnimEnvSingleSetCel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleSetCel(
*						MR_ANIM_ENV*	env,
*						MR_SHORT		cel)
*
*	FUNCTION	Change the cel of a model within an environment
*
*	INPUTS		env			-	ptr to animation environment (single)
*				cel			-	cel number (-1 for no cel)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleSetCel(	MR_ANIM_ENV*	env,
								MR_SHORT		cel)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	
	MR_ASSERT(env);

	env_sing = env->ae_extra.ae_extra_env_single;
	
	if (cel == -1)
		{
		// Turn model off
		env_sing->ae_cel_number = -1;
		}
	else
		{
		MR_ASSERTMSG(cel < env_sing->ae_model->am_cel_set->ac_cels.ac_cels[env_sing->ae_action_number].ac_no_of_virtual_cels, "Cel number too big");
		env_sing->ae_cel_number = cel;
		}
}


/******************************************************************************
*%%%% MRAnimCreateEventList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_EVENT_LIST*	list =	MRAnimCreateEventList(
*											MR_USHORT	size)
*
*	FUNCTION	Allocates and initialises an event list
*
*	INPUTS		size		-	size of list (maximum 256)
*
*	RESULT		list		-	ptr to list allocated
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ANIM_EVENT_LIST*	MRAnimCreateEventList(MR_USHORT	size)
{
	MR_ANIM_EVENT_LIST*	list;


	MR_ASSERT(size >    0);
	MR_ASSERT(size <= 256);


	list				= MRAllocMem(sizeof(MR_ANIM_EVENT_LIST) + (size * sizeof(MR_LONG*)), "EVNTLIST");

	list->ae_size		= size;
	list->ae_event_list	= (MR_VOID*)(((MR_UBYTE*)list) + sizeof(MR_ANIM_EVENT_LIST));

	// Set up rest of structure and clear all event ptrs
	MRAnimClearEventList(list);

	MRAnim_event_list	= list;
	return(list);
}


/******************************************************************************
*%%%% MRAnimSetEventList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ANIM_EVENT_LIST*	old_list =	MRAnimSetEventList(
*												MR_ANIM_EVENT_LIST*	new_list)
*
*	FUNCTION	Sets the global event list ptr
*
*	INPUTS		new_list	-	new list ptr
*
*	RESULT		old_list	-	old list ptr
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ANIM_EVENT_LIST*	MRAnimSetEventList(MR_ANIM_EVENT_LIST*	new_list)
{
	MR_ANIM_EVENT_LIST*	old_list;


	MR_ASSERT(new_list);

	old_list			= MRAnim_event_list;
	MRAnim_event_list	= new_list;
	
	return(old_list);
}


/******************************************************************************
*%%%% MRAnimClearEventList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimClearEventList(
*						MR_ANIM_EVENT_LIST*	list)
*
*	FUNCTION	Clears an event list
*
*	INPUTS		list		-	ptr to list to clear
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimClearEventList(MR_ANIM_EVENT_LIST*	list)
{
	MR_USHORT	i;


	MR_ASSERT(list);

	list->ae_mode		= MR_ANIM_EVENT_MODE_STANDARD;
	list->ae_allocated	= 0;
	list->ae_next		= 0;

	// Set all function ptrs to NULL
	for (i = 0; i < list->ae_size; i++)
		list->ae_event_list[i] = NULL;
}


/******************************************************************************
*%%%% MRAnimKillEventList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimKillEventList(
*						MR_ANIM_EVENT_LIST*	list)
*
*	FUNCTION	Kills an event list
*
*	INPUTS		list		-	ptr to list to clear
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimKillEventList(MR_ANIM_EVENT_LIST*	list)
{
	MR_ASSERT(list);

	MRFreeMem(list);
}


/******************************************************************************
*%%%% MRAnimAllocEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	MRAnimAllocEvent(
*							MR_LONG (*event)(MR_ANIM_EVENT, MR_VOID*))
*
*	FUNCTION	Place an event in the global event list
*
*	INPUTS		event		-	ptr to event function to place
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG	MRAnimAllocEvent(MR_LONG (*event)(MR_ANIM_EVENT, MR_VOID*))
{
	MR_ULONG	i, j;


	MR_ASSERT(event);
	MR_ASSERT(MRAnim_event_list->ae_allocated < MRAnim_event_list->ae_size);

	switch(MRAnim_event_list->ae_mode)
		{
		//----------------------------------------------------------------------
		case MR_ANIM_EVENT_MODE_STANDARD:
			// Allocate next entry in list
			if (MRAnim_event_list->ae_next == MRAnim_event_list->ae_size)
				{
				MRAnim_event_list->ae_mode = MR_ANIM_EVENT_MODE_SEARCH;
				goto search;
				}
			MRAnim_event_list->ae_event_list[MRAnim_event_list->ae_next] = event;
			MRAnim_event_list->ae_allocated++;
			return(MRAnim_event_list->ae_next++);

			break;
		//----------------------------------------------------------------------
		case MR_ANIM_EVENT_MODE_SEARCH:
		search:
			// Search for a free entry
			i = MRAnim_event_list->ae_size;
			j = MRAnim_event_list->ae_next;
			while(i--)
				{
				if (MRAnim_event_list->ae_event_list[j] == NULL)
					{
					// Found free slot
					MRAnim_event_list->ae_event_list[j] = event;
					MRAnim_event_list->ae_allocated++;
					return(j);
					}
				if (++j == MRAnim_event_list->ae_size)
					j = 0;
				}

			break;
		//----------------------------------------------------------------------
		}
}


/******************************************************************************
*%%%% MRAnimFreeEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimFreeEvent(
*						MR_ULONG	event)
*
*	FUNCTION	Frees the specified event
*
*	INPUTS		event		-	index of event to free
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimFreeEvent(MR_ULONG	event)
{
	MR_ASSERT(event < MRAnim_event_list->ae_size);
	MR_ASSERT(MRAnim_event_list->ae_event_list[event] != NULL);

	MRAnim_event_list->ae_event_list[event] = NULL;
	MRAnim_event_list->ae_allocated--;
	
	if (MRAnim_event_list->ae_mode == MR_ANIM_EVENT_MODE_SEARCH)
		MRAnim_event_list->ae_next = event;
}


/******************************************************************************
*%%%% MRAnimEventCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	result =	MRAnimEventCallback(
*									MR_ANIM_EVENT	event)
*
*	FUNCTION	Call an event callback
*
*	INPUTS		event		-	MR_ANIM_EVENT structure to pass in
*
*	RESULT		result		-	result passed back from callback
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	MRAnimEventCallback(MR_ANIM_EVENT event)
{
	MR_LONG	result;


	MR_ASSERT(event.ae_event_callback < MRAnim_event_list->ae_size);
	MR_ASSERT(MRAnim_event_list->ae_event_list[event.ae_event_callback]);

	result = (MRAnim_event_list->ae_event_list[event.ae_event_callback])(event, NULL);
	return(result);
}


/******************************************************************************
*%%%% MRAnimEnvEventCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_LONG	result =	MRAnimEnvEventCallback(
*											MR_ANIM_EVENT	event,
*											MR_ANIM_ENV*	env)
*
*	FUNCTION		Call an event callback with an environment
*
*	INPUTS		event		-	MR_ANIM_EVENT structure to pass in
*					env		-	ptr to environment
*
*	RESULT		result	-	result passed back from callback
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97		Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	MRAnimEnvEventCallback(	MR_ANIM_EVENT	event,
											MR_ANIM_ENV*	env)
{
	MR_LONG	result;


	MR_ASSERT(env);
	MR_ASSERT(event.ae_event_callback < MRAnim_event_list->ae_size);
	MR_ASSERT(MRAnim_event_list->ae_event_list[event.ae_event_callback]);

	result = (MRAnim_event_list->ae_event_list[event.ae_event_callback])(event, env);
	return(result);
}


/******************************************************************************
*%%%% MRAnimEnvSingleSetEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleSetEvent(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		action,
*						MR_USHORT		cel,
*						MR_UBYTE		event_callback,
*						MR_UBYTE		user_param)
*
*	FUNCTION	Set an event at a particular action, cel.  Make memory allocations
*				if necessary
*
*	INPUTS		env				-	ptr to environment (single)
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

MR_VOID	MRAnimEnvSingleSetEvent(MR_ANIM_ENV*	env,
								MR_USHORT		action,
								MR_USHORT		cel,
								MR_UBYTE		event_callback,
								MR_UBYTE		user_param)
{
	MR_ANIM_ENV_SINGLE*	env_sing;
	MR_USHORT			i, j, k;


	MR_ASSERT(env);

	MR_ASSERTMSG(action < env->ae_model_set->am_cel_set->ac_no_of_cels_structures, "Action number too big");
	MR_ASSERTMSG(cel    < env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels, "Cel number too big");

	env_sing = env->ae_extra.ae_extra_env_single;

	if (env_sing->ae_events == NULL)
		{
		// Allocate one MR_ANIM_EVENT* per action
		i							= env->ae_model_set->am_cel_set->ac_no_of_cels_structures;
		env_sing->ae_events	= MRAllocMem(i * sizeof(MR_ANIM_EVENT*), "ACT_EVNT");
		for (j = 0; j < i; j++)
			env_sing->ae_events[j] = NULL;
		}

	if (env_sing->ae_events[action] == NULL)
		{
		// Allocate one MR_ANIM_EVENT per (virtual) cel
		k										= env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels;
		env_sing->ae_events[action]	= MRAllocMem(k * sizeof(MR_ANIM_EVENT), "CEL_EVNT");
		for (j = 0; j < k; j++)
			MR_SET16(env_sing->ae_events[action][j], MR_ANIM_EVENT_EMPTY);
		}

	// Write the event
	env_sing->ae_events[action][cel].ae_event_callback	= event_callback;
	env_sing->ae_events[action][cel].ae_user_param		= user_param;

	env->ae_special_flags |= MR_ANIM_ENV_EVENT_LIST_ACTIVE;
}


/******************************************************************************
*%%%% MRAnimEnvCheckEvents
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvCheckEvents(
*						MR_ANIM_ENV*	env)
*								
*	FUNCTION	Check and activate events for an environment
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvCheckEvents(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_ANIM_EVENT*			event_ptr;
	MR_USHORT				model;


	MR_ASSERT(env);

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Multiple environment
		env_mult	= env->ae_extra.ae_extra_env_multiple;

		if (env_mult->ae_events)
			{
			// Model level ptrs exist.  Run through each model
			for (model = 0; model < env_mult->ae_no_of_models; model++)
				{
				if (env_mult->ae_events[model])
					{
					// Action level ptrs exist for this model
					if (env_mult->ae_cel_number[model] >= 0)
						{
						if (env_mult->ae_events[model][env_mult->ae_action_number[model]])
							{
							// Cel level ptr exists for current action for this model, action
							if (*(MR_USHORT*)&env_mult->ae_events[model][env_mult->ae_action_number[model]][env_mult->ae_cel_number[model]] != MR_ANIM_EVENT_EMPTY)
								{
								// Non-empty event for this model, action, cel
								event_ptr 	= &env_mult->ae_events[model][env_mult->ae_action_number[model]][env_mult->ae_cel_number[model]];
			
								// Call event
								MR_ASSERT(MRAnim_event_list->ae_event_list[event_ptr->ae_event_callback]);
								(MRAnim_event_list->ae_event_list[event_ptr->ae_event_callback])(*event_ptr, env);
						 		}
							}
						}
					}
				}
			}
		}
	else
		{
		// Single environment
		env_sing	= env->ae_extra.ae_extra_env_single;

		if (env_sing->ae_cel_number >= 0)
			{
			if (env_sing->ae_events)
				{
				// Action level ptrs exist
				if (env_sing->ae_events[env_sing->ae_action_number])
					{
					// Cel level ptr exists for current action
					if (*(MR_USHORT*)&env_sing->ae_events[env_sing->ae_action_number][env_sing->ae_cel_number] != MR_ANIM_EVENT_EMPTY)
						{
						// Non-empty event for this action, cel
						event_ptr 	= &env_sing->ae_events[env_sing->ae_action_number][env_sing->ae_cel_number];
	
						// Call event
						MR_ASSERT(MRAnim_event_list->ae_event_list[event_ptr->ae_event_callback]);
						(MRAnim_event_list->ae_event_list[event_ptr->ae_event_callback])(*event_ptr, env);
						}
					}
				}
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvSingleClearEvent
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvSingleClearEvent(
*						MR_ANIM_ENV*	env,
*						MR_USHORT		action,
*						MR_USHORT		cel)
*
*	FUNCTION	Clear an event at a particular action, cel
*
*	INPUTS		env			-	ptr to environment (single)
*				action		-	action of event
*				cel			-	cel of event
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvSingleClearEvent(	MR_ANIM_ENV*	env,
									MR_USHORT		action,
									MR_USHORT		cel)
{
	MR_ANIM_ENV_SINGLE*	env_sing;


	MR_ASSERT(env);

	MR_ASSERTMSG(action < env->ae_model_set->am_cel_set->ac_no_of_cels_structures, "Action number too big");
	MR_ASSERTMSG(cel    < env->ae_model_set->am_cel_set->ac_cels.ac_cels[action].ac_no_of_virtual_cels, "Cel number too big");

	env_sing = env->ae_extra.ae_extra_env_single;

	if (env_sing->ae_events)
		{
		// Action level ptrs exist
		if (env_sing->ae_events[action])
			{
			// Cel level ptrs exist for this action
			MR_SET16(env_sing->ae_events[action][cel], MR_ANIM_EVENT_EMPTY);
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvCleanEvents
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAnimEnvCleanEvents(
*						MR_ANIM_ENV*	env)
*
*	FUNCTION	Clean up any empty events structures
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvCleanEvents(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				model, a, c;
	MR_BOOL	 				cel_event = FALSE;
	MR_BOOL	 				action_event;
	MR_BOOL	 				model_event;


	MR_ASSERT(env);

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Multiple environment
		env_mult	= env->ae_extra.ae_extra_env_multiple;

		if (env_mult->ae_events)
			{
			// Model level ptrs exist.  Run through each model
			model_event = FALSE;
			for (model = 0; model < env_mult->ae_no_of_models; model++)
				{
				action_event = FALSE;
				if (env_mult->ae_events[model])
					{
					// Action level ptrs exist for this model
					for (a = 0; a < env->ae_model_set->am_cel_set->ac_no_of_cels_structures; a++)
						{
						if (env_mult->ae_events[model][a])
							{
							// Run through all the virtual cels for this model, action
							cel_event = FALSE;
							for (c = 0; c < env->ae_model_set->am_cel_set->ac_cels.ac_cels[a].ac_no_of_virtual_cels; c++)
								{
								if (*(MR_USHORT*)&env_mult->ae_events[model][a][c] != MR_ANIM_EVENT_EMPTY)
									{
									// Found a non-empty event for this model, action
									cel_event 		= TRUE;
									action_event 	= TRUE;
									model_event 	= TRUE;
									break;
									}
								}
							if (cel_event == FALSE)
								{
								// No non-empty events for this model, action - free memory
								MRFreeMem(env_mult->ae_events[model][a]);
								env_mult->ae_events[model][a] = NULL;
								}
							}
						}
					if (cel_event == FALSE)
						{
						// No non-empty events for ANY action in this model - free memory
						MRFreeMem(env_mult->ae_events[model]);
						env_mult->ae_events[model] = NULL;
						}
					}
				}
			if (model_event == FALSE)
				{
				// No non-empty events for ANY action in ANY model - free memory
				MRFreeMem(env_mult->ae_events);
				env_mult->ae_events = NULL;
				}
			}
		}
	else
		{
		// Single environment
		env_sing	= env->ae_extra.ae_extra_env_single;

		action_event = FALSE;
		if (env_sing->ae_events)
			{
			// Action level ptrs exist
			for (a = 0; a < env->ae_model_set->am_cel_set->ac_no_of_cels_structures; a++)
				{
				if (env_sing->ae_events[a])
					{
					// Run through all the virtual cels for this action
					cel_event = FALSE;
					for (c = 0; c < env->ae_model_set->am_cel_set->ac_cels.ac_cels[a].ac_no_of_virtual_cels; c++)
						{
						if (*(MR_USHORT*)&env_sing->ae_events[a][c] != MR_ANIM_EVENT_EMPTY)
							{
							// Found a non-empty event for this action
							cel_event 		= TRUE;
							action_event 	= TRUE;
							break;
							}
						}
					if (cel_event == FALSE)
						{
						// No non-empty events for this action - free memory
						MRFreeMem(env_sing->ae_events[a]);
						env_sing->ae_events[a] = NULL;
						}
					}
				}
			if (cel_event == FALSE)
				{
				// No non-empty events for ANY action - free memory
				MRFreeMem(env_sing->ae_events);
				env_sing->ae_events = NULL;
				}
			}
		}
}


/******************************************************************************
*%%%% MRAnimEnvDeleteEvents
*------------------------------------------------------------------------------
*
*	SYNOPSIS  	MR_VOID	MRAnimEnvDeleteEvents(
*			  			MR_ANIM_ENV*	env)
*
*	FUNCTION  	Delete the entire event structure for an environment
*
*	INPUTS		env			-	ptr to environment (single or multiple)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRAnimEnvDeleteEvents(MR_ANIM_ENV*	env)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_MULTIPLE*	env_mult;
	MR_USHORT				model, a;


	MR_ASSERT(env);

	if (env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
		{
		// Multiple environment
		env_mult	= env->ae_extra.ae_extra_env_multiple;

		if (env_mult->ae_events)
			{
			for (model = 0; model < env_mult->ae_no_of_models; model++)
				{
				if (env_mult->ae_events[model])
					{
					// Action level ptrs exist for this model
					for (a = 0; a < env->ae_model_set->am_cel_set->ac_no_of_cels_structures; a++)
						{
						if (env_mult->ae_events[model][a])
							MRFreeMem(env_mult->ae_events[model][a]);
						}
					MRFreeMem(env_mult->ae_events[model]);
					env_mult->ae_events[model] = NULL;
					}
				}
			MRFreeMem(env_mult->ae_events);
			env_mult->ae_events = NULL;
			}
		}
	else
		{
		// Single environment
		env_sing	= env->ae_extra.ae_extra_env_single;

		if (env_sing->ae_events)
			{
			// Action level ptrs exist
			for (a = 0; a < env->ae_model_set->am_cel_set->ac_no_of_cels_structures; a++)
				{
				if (env_sing->ae_events[a])
					MRFreeMem(env_sing->ae_events[a]);
				}
			MRFreeMem(env_sing->ae_events);
			env_sing->ae_events = NULL;
			}
		}

	env->ae_special_flags &= ~MR_ANIM_ENV_EVENT_LIST_ACTIVE;
}
