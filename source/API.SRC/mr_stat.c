/******************************************************************************
*%%%% mr_stat.c
*------------------------------------------------------------------------------
*
*	Functions for handling static MOFs
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	20.08.96	Dean Ashton		Created
*	21.10.96	Dean Ashton		Applied Local OT bugfix to display code
*	23.10.96	Tim Closs		New prim types supported in MRStaticDisplayMeshInstance:
*								MR_MPRIMID_HLF3, MR_MPRIMID_HLF4
*	31.10.96	Tim Closs		MRStaticDisplayMeshInstance now sets
*								MR_MESH_INST_DISPLAYED_LAST_FRAME only if mesh
*								rendered (on screen and in OT)
*	28.01.97	Tim Closs		Changed MRStaticResolveMOF() to resolve MR_HILITEs
*								Changed MRStaticDisplayMeshInstance() to display
*								debug hilites
*	05.02.97	Tim Closs		MRStaticDisplayMeshInstance() now restores rotation
*								matrix if displaying debug collprims
*				Dean Ashton		Changed display to use simplified lighting calls
*	12.02.97	Tim Closs		Altered debug display calls in MRStaticDisplayMeshInstance()
*	01.04.97	Dean Ashton		MRStaticDisplayMeshInstance() now calls specialised render
*								functions when necessary
*	07.04.97	Dean Ashton		MRStaticDisplayMeshInstance() now respects
*								MR_MESH_IGNORE_BBOX and MR_MESH_CHECK_BBOX_USING_EDGES
*	02.06.97	Dean Ashton		MRStaticDisplayMeshInstance() now handles local ordering
*								tables without frames (ie using MR_MAT's)
*	13.06.97	Dean Ashton		Added support for MR_MRPRIM_GE3/MR_MRPRIM_GE4 throughout
*
*	06.06.97	Tim Closs		Added support for animated polys in
*								MRStaticResolveMOF()
*								MRStaticResolveMOFTextures()
*	18.06.97	Tim Closs		Added support for flipbooks in
*								MRStaticResolveMOF()
*								In MRStaticDisplayMeshInstance(), MR_MESH_SPECIFY_MODEL_AND_CEL
*								changed to MR_MESH_FLIPBOOK.
*								model, cel inputs renamed to part, partcel
*	09.07.97	Dean Ashton		Added OT biasing with ot_global_ot_offset in display code
*	10.07.97	Dean Ashton		Added model size display under MR_SHOW_MOF_INFO
*								conditions.
*	20.08.97	Dean Ashton		Added support for MR_OT_FORCE_BACK flag
*
**%%%**************************************************************************/

#include	"mr_all.h"


// Notes:
//
// OpenInventor bounding box vertices are grouped in the following way:
//
//	0--------1
//	|		 |
//	|	4----+---5
//	|	|	 |	 |
//	|	|	 |	 |
//	|	|	 |	 |
//	2---+----3	 |
//		|	 	 |
//		6--------7
//
// ie. each top and bottom quad orderings are in 'PSX format'.  This is
// the order in which the 8 vertices appear in all MOF bounding boxes.




/******************************************************************************
*%%%% MRStaticResolveMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStaticResolveMOF(
*						MR_MOF* mof_ptr);
*
*	FUNCTION	Resolves all offsets and sizes within a MOF. 
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	14.05.96	Tim Closs		Created
*	20.06.96	Tim Closs		Modified for MOF2
*	20.08.96	Dean Ashton		Name changed to match animation code style
*	07.10.96	Tim Closs		In MRStaticDisplayMeshInstance, fixed bug in model
*								changing loop, and allowed specification of z
*								distance beyond which nothing is displayed
*	06.06.97	Tim Closs		Added support for animated polys
*	18.06.97	Tim Closs		Added support for flipbooks
*	10.07.97	Dean Ashton		Added model size display under MR_SHOW_MOF_INFO
*
*%%%**************************************************************************/

MR_VOID	MRStaticResolveMOF(MR_MOF* mof_ptr)
{
	MR_ULONG					i, c;
	MR_PART*					part_ptr;
	MR_PARTCEL*					partcel_ptr;
	MR_COLLPRIM*				collprim_ptr;
	MR_HILITE*					hilite_ptr;
	MR_PART_POLY_ANIM*			part_poly;
	MR_ULONG*					mprim;
	MR_PART_FLIPBOOK*			flipbook;
	MR_PART_FLIPBOOK_ACTION*	flipbook_action;

#ifdef	MR_SHOW_MOF_INFO
	MR_ULONG		polys, collprims, hilites, vertices;
	MR_LONG			res_id;
	MR_LONG			res_size;
	MR_STRPTR		res_name;
#endif


	MR_ASSERT(mof_ptr != NULL);

#ifdef	MR_SHOW_MOF_INFO
	polys 			= 0;
	collprims		= 0;
	hilites			= 0;
	vertices		= 0;
#endif

	if (!(mof_ptr->mm_flags & MR_MOF_OFFSETS_RESOLVED))
		{
		// Resolve the section pointers from offsets to absolute (for each model in the MOF)
		part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

		for (i = 0; i < mof_ptr->mm_extra; i++)
			{
			// Resolve MR_PART ptrs
			part_ptr->mp_partcel_ptr	= (MR_PARTCEL*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_partcel_ptr);
			part_ptr->mp_prim_ptr 		= (MR_ULONG*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_prim_ptr);

			// Now, for each MR_PARTCEL in the MR_PART, resolve ptrs
			partcel_ptr = part_ptr->mp_partcel_ptr;			
			for (c = 0; c < part_ptr->mp_partcels; c++)
				{
				partcel_ptr->mp_vert_ptr = (MR_SVEC*)((MR_ULONG)mof_ptr + (MR_ULONG)partcel_ptr->mp_vert_ptr);
				partcel_ptr->mp_norm_ptr = (MR_SVEC*)((MR_ULONG)mof_ptr + (MR_ULONG)partcel_ptr->mp_norm_ptr);

				if (partcel_ptr->mp_bbox_ptr)
					partcel_ptr->mp_bbox_ptr = (MR_BBOX*)((MR_ULONG)mof_ptr + (MR_ULONG)partcel_ptr->mp_bbox_ptr);

				partcel_ptr++;
				}

			// Resolve MR_HILITE ptr, and any ptrs within MR_HILITEs
			if (part_ptr->mp_hilite_ptr)
				{
				part_ptr->mp_hilite_ptr = (MR_HILITE*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_hilite_ptr);
				hilite_ptr		 		= part_ptr->mp_hilite_ptr;
				c				 		= part_ptr->mp_hilites;
				while(c--)
					{
					if (hilite_ptr->mh_flags & MR_HILITE_VERTEX)
						{
						// Hilite is an index within vertex block
						hilite_ptr->mh_target_ptr	= (MR_ULONG*)(part_ptr->mp_partcel_ptr->mp_vert_ptr + hilite_ptr->mh_index);
						hilite_ptr->mh_prim_ofs		= 0;
						}
					else
					if (hilite_ptr->mh_flags & MR_HILITE_PRIM)
						{
						// Hilite is an index within primitive block
						hilite_ptr->mh_target_ptr 	= MRPartGetPrim(mof_ptr, i, hilite_ptr->mh_index);
						hilite_ptr->mh_prim_ofs		= MRPartGetPrimOffset(mof_ptr, i, hilite_ptr->mh_index);
						}
					hilite_ptr++;
					}
				}

			// Resolve MR_MAT ptr
			if (part_ptr->mp_matrix_ptr)
				part_ptr->mp_matrix_ptr = (MR_MAT*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_matrix_ptr);

			// Resolve MR_COLLPRIM ptr, and any MR_MAT ptrs within those collprims
			if (part_ptr->mp_collprim_ptr)
				{
				part_ptr->mp_collprim_ptr 	= (MR_COLLPRIM*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_collprim_ptr);
				collprim_ptr 	 			= part_ptr->mp_collprim_ptr;
				do	{
					if ((MR_LONG)collprim_ptr->cp_matrix == -1)
						collprim_ptr->cp_matrix = NULL;
					else
						collprim_ptr->cp_matrix = part_ptr->mp_matrix_ptr + ((MR_LONG)collprim_ptr->cp_matrix);

#ifdef	MR_SHOW_MOF_INFO
					collprims++;
#endif
					} while(!(collprim_ptr++->cp_flags & MR_COLL_LAST_IN_LIST));
				}

#ifdef	MR_SHOW_MOF_INFO
			polys		+= part_ptr->mp_prims;
			vertices	+= part_ptr->mp_verts;
			hilites		+= part_ptr->mp_hilites;
#endif
			part_ptr++;
			}

		// If MOF has animated polys, resolve prim offsets (UVs are resolved in MRStaticResolveMOFTextures)
		if (mof_ptr->mm_flags & MR_MOF_ANIMATED_POLYS)
			{
			part_ptr	= (MR_PART*)(mof_ptr + 1);
		
			for (i = 0; i < mof_ptr->mm_extra; i++)
				{
				if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
					{
					// MR_PART has some animated polys
					part_ptr->mp_pad0	= (MR_VOID*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_pad0);
					part_poly			= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);
					c					= *(MR_ULONG*)(part_ptr->mp_pad0);
		
					// There are c animated polys to resolve
					while(c--)
						{
						// Calculate offset of poly within primitive buffer
						part_poly->mp_poly_offset	= MRPartGetPrimOffset(mof_ptr, i, (MR_ULONG)part_poly->mp_mprim_ptr);

						// Resolve ptr to MR_MPRIM within MOF prim block
						mprim 				   		= MRPartGetPrim(mof_ptr, i, (MR_ULONG)part_poly->mp_mprim_ptr);
						part_poly->mp_mprim_ptr		= mprim;
						
						part_poly->mp_animlist 		= (MR_ULONG*)((MR_ULONG)mof_ptr + (MR_ULONG)part_poly->mp_animlist);
						part_poly++;
						}
					}
				part_ptr++;
				}	
			}

		// If MOF is a flipbook file, resolve offsets in associated structures
		if (mof_ptr->mm_flags & MR_MOF_FLIPBOOK)
			{
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			for (i = 0; i < mof_ptr->mm_extra; i++)
				{
				part_ptr->mp_pad1	= (MR_VOID*)((MR_ULONG)mof_ptr + (MR_ULONG)part_ptr->mp_pad1);
				flipbook			= (MR_PART_FLIPBOOK*)part_ptr->mp_pad1;
				flipbook_action		= (MR_PART_FLIPBOOK_ACTION*)(flipbook + 1);
				c					= flipbook->mp_numactions;
				while(c--)
					{
					// Nothing to resolve here!
					}
				part_ptr++;
				}
			}	

		mof_ptr->mm_flags |= MR_MOF_OFFSETS_RESOLVED;
		}

	if (!(mof_ptr->mm_flags & MR_MOF_SIZES_RESOLVED))
		{
		// Calculate the prim buffer size (for each MR_PART in the MR_MOF)
		part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

		for (i = 0; i < mof_ptr->mm_extra; i++)
			{
			part_ptr->mp_buff_size = MRCalculatePartPrimSize(part_ptr);
			part_ptr++;
			}
		mof_ptr->mm_flags |= MR_MOF_SIZES_RESOLVED;
		}

	// Write the prim codes into the prims in the MOF
	part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

	for (i = 0; i < mof_ptr->mm_extra; i++)
		{
		MRWritePartPrimCodes(part_ptr, FALSE);
		part_ptr++;
		}

#ifdef	MR_SHOW_MOF_INFO
	res_id = MRGetResourceIDFromAddress(mof_ptr);
	if (res_id != -1)
		{
		res_name = MR_GET_RESOURCE_NAME(res_id);
		res_size = MR_GET_RESOURCE_SIZE(res_id);
		
		if ((MR_LONG)res_name != -1)
			{
			MRPrintf(	"MRResolveMOF - Parts:%3ld  Prims:%5ld  Verts:%5ld  Colls:%3ld  Hilites:%3ld  Size:%7ld (%s)\n",
		 		mof_ptr->mm_extra, polys, vertices, collprims, hilites, res_size, res_name);
			}
		else
			{
			MRPrintf(	"MRResolveMOF - Parts:%3ld  Prims:%5ld  Verts:%5ld  Colls:%3ld  Hilites:%3ld  Size:%7ld (NO NAME)\n",
				mof_ptr->mm_extra, polys, vertices, collprims, hilites, res_size);                           
			}
		}
	else
		{
			MRPrintf(	"MRResolveMOF - Parts:%3ld  Prims:%5ld  Verts:%5ld  Colls:%3ld  Hilites:%3ld  Size: N/A   (NO ID AVAILABLE)\n",
			mof_ptr->mm_extra, polys, vertices, collprims, hilites);
		}

#endif
}


/******************************************************************************
*%%%% MRStaticResolveMOFTextures
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStaticResolveMOFTextures(
*						MR_MOF*	mof_ptr);
*
*	FUNCTION	Resolves a models UV texture coordinates to correctly represent
*				the appropriate textures UV coordinates in VRAM after Vorg
*				processing. 
*
*	INPUTS		mof_ptr		-	Pointer to a valid MOF (static type)
*
*	NOTES		This acts on STATIC MOF files only!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.08.96	Dean Ashton		Created
*	19.08.96	Dean Ashton		Changed name to clarify MOF type this acts on.
*
*%%%**************************************************************************/

MR_VOID	MRStaticResolveMOFTextures(MR_MOF* mof_ptr)
{
	MR_PART*			part_ptr;	
	MR_USHORT			mod_loop;
	MR_USHORT			prims;
	MR_ULONG*			prim_ptr;
	MR_USHORT			i, type;
	MR_TEXTURE*			text_ptr;	
	MR_PART_POLY_ANIM*	part_poly;

	MR_ASSERT(mof_ptr);
	MR_ASSERT(MRTexture_list_ptr != NULL);
	MR_ASSERT((mof_ptr->mm_flags & MR_MOF_OFFSETS_RESOLVED));		// Pointers must be resolved
	MR_ASSERT(!(mof_ptr->mm_flags & MR_MOF_TEXTURES_RESOLVED));		// UV's must not be resolved

	mof_ptr->mm_flags |= MR_MOF_TEXTURES_RESOLVED;		

	part_ptr = (MR_PART*)(((MR_BYTE*)mof_ptr + sizeof(MR_MOF)));

	for (mod_loop = 0; mod_loop < mof_ptr->mm_extra; mod_loop++)
		{
		prims		= part_ptr->mp_prims;
		prim_ptr	= part_ptr->mp_prim_ptr;

		while	(prims)
			{
			type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
			i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
			prim_ptr++;
		
			switch (type)
				{
				case MR_MPRIMID_F3:
					prim_ptr += ((sizeof(MR_MPRIM_F3) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
	
				case MR_MPRIMID_F4:
					prim_ptr += ((sizeof(MR_MPRIM_F4) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
									  
				case MR_MPRIMID_FT3:
					while (i--)
						{
						// Set up texture coords
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_FT3*)prim_ptr)->mp_image_id];
						((MR_MPRIM_FT3*)prim_ptr)->mp_tpage_id = text_ptr->te_tpage_id;
						((MR_MPRIM_FT3*)prim_ptr)->mp_clut_id = text_ptr->te_clut_id;
						((MR_MPRIM_FT3*)prim_ptr)->mp_u0 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_u0 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v0 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_v0 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_u1 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_u1 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v1 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_v1 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_u2 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_u2 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v2 = ((((MR_MPRIM_FT3*)prim_ptr)->mp_v2 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT3*)prim_ptr)++;
						prims--;
						}
					break;
		
				case MR_MPRIMID_FT4:
					while (i--)
						{
						// Set up texture coords
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_FT4*)prim_ptr)->mp_image_id];
						((MR_MPRIM_FT4*)prim_ptr)->mp_tpage_id = text_ptr->te_tpage_id;
						((MR_MPRIM_FT4*)prim_ptr)->mp_clut_id = text_ptr->te_clut_id;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u0 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_u0 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v0 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_v0 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u1 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_u1 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v1 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_v1 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u2 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_u2 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v2 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_v2 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u3 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_u3 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v3 = ((((MR_MPRIM_FT4*)prim_ptr)->mp_v3 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)++;
						prims--;
						}
					break;
		
				case MR_MPRIMID_G3:
					prim_ptr += ((sizeof(MR_MPRIM_G3) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
	
				case MR_MPRIMID_G4:
					prim_ptr += ((sizeof(MR_MPRIM_G4) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
		
				case MR_MPRIMID_GT3:
					while (i--)
						{
						// Set up texture coords
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_GT3*)prim_ptr)->mp_image_id];
						((MR_MPRIM_GT3*)prim_ptr)->mp_tpage_id = text_ptr->te_tpage_id;
						((MR_MPRIM_GT3*)prim_ptr)->mp_clut_id = text_ptr->te_clut_id;
						((MR_MPRIM_GT3*)prim_ptr)->mp_u0 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_u0 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v0 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_v0 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_u1 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_u1 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v1 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_v1 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_u2 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_u2 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v2 = ((((MR_MPRIM_GT3*)prim_ptr)->mp_v2 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT3*)prim_ptr)++;
						prims--;
						}
					break;
		
				case MR_MPRIMID_GT4:
					while (i--)
						{
						// Set up texture coords
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_GT4*)prim_ptr)->mp_image_id];
						((MR_MPRIM_GT4*)prim_ptr)->mp_tpage_id = text_ptr->te_tpage_id;
						((MR_MPRIM_GT4*)prim_ptr)->mp_clut_id = text_ptr->te_clut_id;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u0 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_u0 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v0 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_v0 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u1 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_u1 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v1 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_v1 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u2 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_u2 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v2 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_v2 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u3 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_u3 * text_ptr->te_w)/255) + text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v3 = ((((MR_MPRIM_GT4*)prim_ptr)->mp_v3 * text_ptr->te_h)/255) + text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)++;
						prims--;
						}
					break;
	
				case MR_MPRIMID_E3:
					prim_ptr += ((sizeof(MR_MPRIM_E3) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
	
				case MR_MPRIMID_E4:
					prim_ptr += ((sizeof(MR_MPRIM_E4) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;

				case MR_MPRIMID_GE3:
					prim_ptr += ((sizeof(MR_MPRIM_GE3) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;
	
				case MR_MPRIMID_GE4:
					prim_ptr += ((sizeof(MR_MPRIM_GE4) * i)/sizeof(MR_ULONG));
					prims -= i;
					break;

				}
			}

		if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
			{	
			// MR_PART has some animated polys
			i			= *(MR_ULONG*)(part_ptr->mp_pad0);
			part_poly	= (MR_PART_POLY_ANIM*)(((MR_ULONG*)(part_ptr->mp_pad0)) + 1);

			// There are c animated polys to resolve
			while(i--)
				{
				// Resolve UVs in MR_MPRIM (which are now absolute VRAM coords) to additive offsets from MR_TEXTURE top left							
				prim_ptr = part_poly->mp_mprim_ptr;

//				text_ptr = MRTexture_list_ptr[((MR_PART_POLY_ANIMLIST_ENTRY*)(part_poly->mp_animlist + 1))->mp_image_id];
				switch(part_poly->mp_mprim_type)
					{
					case MR_MPRIMID_FT3:
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_FT3*)prim_ptr)->mp_image_id];
						((MR_MPRIM_FT3*)prim_ptr)->mp_u0 -= text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v0 -= text_ptr->te_v0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_u1 -= text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v1 -= text_ptr->te_v0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_u2 -= text_ptr->te_u0;
						((MR_MPRIM_FT3*)prim_ptr)->mp_v2 -= text_ptr->te_v0;
						break;

					case MR_MPRIMID_FT4:
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_FT4*)prim_ptr)->mp_image_id];
						((MR_MPRIM_FT4*)prim_ptr)->mp_u0 -= text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v0 -= text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u1 -= text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v1 -= text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u2 -= text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v2 -= text_ptr->te_v0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_u3 -= text_ptr->te_u0;
						((MR_MPRIM_FT4*)prim_ptr)->mp_v3 -= text_ptr->te_v0;
						break;

					case MR_MPRIMID_GT3:
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_GT3*)prim_ptr)->mp_image_id];
						((MR_MPRIM_GT3*)prim_ptr)->mp_u0 -= text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v0 -= text_ptr->te_v0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_u1 -= text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v1 -= text_ptr->te_v0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_u2 -= text_ptr->te_u0;
						((MR_MPRIM_GT3*)prim_ptr)->mp_v2 -= text_ptr->te_v0;
						break;

					case MR_MPRIMID_GT4:
						text_ptr = MRTexture_list_ptr[((MR_MPRIM_GT4*)prim_ptr)->mp_image_id];
						((MR_MPRIM_GT4*)prim_ptr)->mp_u0 -= text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v0 -= text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u1 -= text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v1 -= text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u2 -= text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v2 -= text_ptr->te_v0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_u3 -= text_ptr->te_u0;
						((MR_MPRIM_GT4*)prim_ptr)->mp_v3 -= text_ptr->te_v0;
						break;
					}
				part_poly++;
				}
			}

		part_ptr++;
		}
}


/******************************************************************************
*%%%% MRStaticPatchMOFTranslucency
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStaticPatchMOFTranslucency(
*						MR_MOF* mof_ptr,
*						MR_BOOL	add_trans);
*
*	FUNCTION	Patches textured MR_MPRIM's in the specified MOF (static)
*				to enable/disable translucent processing depending on MR_TEXTURE
*				translucency flags.
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

MR_VOID	MRStaticPatchMOFTranslucency(MR_MOF* mof_ptr, MR_BOOL add_trans)
{
	MR_PART*		part_ptr;
	MR_USHORT		i;

	MR_ASSERT(mof_ptr != NULL);
	MR_ASSERT(mof_ptr->mm_flags & MR_MOF_OFFSETS_RESOLVED);

	// Write the prim codes into the prims in the MOF
	part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

	for (i = 0; i < mof_ptr->mm_extra; i++)
		{
		MRWritePartPrimCodes(part_ptr, add_trans);
		part_ptr++;
		}
}


/******************************************************************************
*%%%% MRStaticDisplayMeshInstance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRStaticDisplayMeshInstance(
*						MR_MESH_INST*	mesh_inst_ptr,
*						MR_VIEWPORT*	viewport,
*						MR_UBYTE		part,
*						MR_UBYTE		partcel);
*
*	FUNCTION	Calculate polygon coordinates and other rendering-related 
*				values for the primitives of a part within a mesh.
*
*	INPUTS		mesh_inst_ptr	-	ptr to an instance of a mesh object
*				viewport  		-	ptr to the viewport to render into
*				part	  		-	index of MR_PART within MOF
*				partcel			-	index of MR_PARTCEL within MR_PART
*
*	NOTES		part, partcel are only used if the mesh is flagged as
*				MR_MESH_FLIPBOOK.
*
*				This function only displays STATIC MODELS.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	19.06.96	Tim Closs		Changed for MOF2
*	20.08.96	Dean Ashton		Changed name to match mr_anim equivalents.
*	07.10.96	Tim Closs		Fixed bug in model changing loop, and allowed specification
*								of z distance beyond which nothing is displayed
*	21.10.96	Dean Ashton		Applied Local OT bugfix
*	31.10.96	Tim Closs		Now sets MR_MESH_INST_DISPLAYED_LAST_FRAME only if
*								mesh rendered (on screen and in OT)
*	12.02.97	Tim Closs		Altered debug display calls
*	01.04.97	Dean Ashton		Added calls to specialised rendering functions based on
*								mesh instance flags
*	07.04.97	Dean Ashton		MRStaticDisplayMeshInstance() now respects
*								MR_MESH_IGNORE_BBOX and MR_MESH_CHECK_BBOX_USING_EDGES
*	13.06.97	Dean Ashton		Added support for MR_MRPRIM_GE3/MR_MRPRIM_GE4
*	18.06.97	Tim Closs		MR_MESH_SPECIFY_MODEL_AND_CEL changed to MR_MESH_FLIPBOOK
*								model, cel inputs renamed to part, partcel
*	09.07.97	Dean Ashton		Added OT biasing with ot_global_ot_offset
*	20.08.97	Dean Ashton		Added support for MR_OT_FORCE_BACK flag
*
*%%%**************************************************************************/

MR_VOID	MRStaticDisplayMeshInstance(MR_MESH_INST*	mesh_inst_ptr,
									MR_VIEWPORT*	viewport,
									MR_UBYTE		part,
									MR_UBYTE		partcel)
{
	MR_OBJECT*			object_ptr;
	MR_MESH*			mesh_ptr;
	MR_STATIC_MESH*		smesh_ptr;
	MR_PART*			part_ptr;
	MR_SVEC*			vert_ptr;
	MR_SVEC*			norm_ptr;
	MR_ULONG*			prim_ptr;
	MR_ULONG			prims;
	MR_ULONG*			mem;
	MR_SHORT			i, type;
	MR_FRAME*			camera_frame;
	MR_MAT*				temp_matrix_ptr;
	MR_MESH_PARAM		mesh_param;
  	MR_ULONG			dm_long;
	MR_SVEC				dm_svec;
	MR_VEC				dm_vec0;
	MR_ULONG			dm_lights_modified;
	MR_BOOL				dm_light_dpq;
	MR_BBOX*			bbox_ptr;
	MR_ULONG			render_flags;

#ifdef	MR_DEBUG_DISPLAY
	MR_COLLPRIM*		collprim;
#endif


	MR_ASSERT(mesh_inst_ptr != NULL);
	MR_ASSERT(viewport != NULL); 

	object_ptr		= mesh_inst_ptr->mi_object;
	mesh_ptr		= object_ptr->ob_extra.ob_extra_mesh;
	smesh_ptr		= mesh_ptr->me_extra.me_extra_static_mesh;
	camera_frame	= viewport->vp_camera;
	dm_light_dpq	= ((object_ptr->ob_flags & MR_OBJ_ACCEPT_DPQ) && (MRVp_fog_near_distance));

	if (object_ptr->ob_flags & MR_OBJ_STATIC)
		temp_matrix_ptr = (MR_MAT*)object_ptr->ob_frame;
	else
		temp_matrix_ptr = &object_ptr->ob_frame->fr_lw_transform;

	if (MRWorldtrans_ptr != temp_matrix_ptr)
		{
		// Assuming the camera matrix.m is the same as when this function was last called,
		// we only need to update the view matrix.m if the worldtrans matrix.m is different...
		// this makes a significant speed difference!
		MRWorldtrans_ptr = temp_matrix_ptr;
		MRMulMatrixABC(&viewport->vp_render_matrix, MRWorldtrans_ptr, MRViewtrans_ptr);
		}

	MRApplyMatrix(MRWorldtrans_ptr, &object_ptr->ob_offset, &dm_vec0);

	dm_svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] + (MR_SHORT)dm_vec0.vx - (MR_SHORT)viewport->vp_render_matrix.t[0];
	dm_svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] + (MR_SHORT)dm_vec0.vy - (MR_SHORT)viewport->vp_render_matrix.t[1];
	dm_svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] + (MR_SHORT)dm_vec0.vz - (MR_SHORT)viewport->vp_render_matrix.t[2];
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

	// Work out which part in static file to use
	if (!(mesh_ptr->me_flags & MR_MESH_FLIPBOOK))
		{
		// Which model from MOF? dm_long holds view z (not OTZ) of mesh frame origin
		partcel = 0;
		part	= 0;

		while (dm_long > smesh_ptr->sm_mod_change_dists[part])
			{
			part++;
			if	(part >= mesh_inst_ptr->mi_mof_models)
				{
				// Model is further than the distance beyond which we have no more parts to display: so return
				return;
				}			
			}
		}
	part_ptr = ((MR_PART*)(smesh_ptr->sm_mof_ptr + 1)) + part;

	// Do bounding box clipping
	bbox_ptr = part_ptr->mp_partcel_ptr[partcel].mp_bbox_ptr;
	if (
		(!(mesh_ptr->me_flags & MR_MESH_IGNORE_BBOX)) &&
		(bbox_ptr)
		)
		{
		// Check bounding box
		if (mesh_ptr->me_flags & MR_MESH_CHECK_BBOX_USING_EDGES)
			{
			if (MRCheckBoundingBoxOnScreenUsingEdges(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
				return;
			}
		else
			{
			if (MRCheckBoundingBoxOnScreen(bbox_ptr->mb_verts, &dm_long) == MR_BBOX_DISPLAY_NO_VERTICES)
				return;
			}
		// If mesh origin z beyond view distance, bail:
		if ((dm_long >> MRVp_otz_shift) >= MRVp_ot_size)
			return;
		}

#ifdef MR_DEBUG_DISPLAY
	// Debug: display static bounding box
	if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_PART_BBOX)
		MRDebugPlotBoundingBox(bbox_ptr, MR_DEBUG_DISPLAY_BBOX_COLOUR);

	// Debug: display collision primitives
	if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_COLLPRIMS)
		{
		if (collprim = part_ptr->mp_collprim_ptr)
			{	
			do {
				MRDebugPlotCollPrim(collprim, MRWorldtrans_ptr, &object_ptr->ob_offset, MR_DEBUG_DISPLAY_COLLPRIM_COLOUR);

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
				dm_svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] - (MR_SHORT)viewport->vp_render_matrix.t[0];
				dm_svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] - (MR_SHORT)viewport->vp_render_matrix.t[1];
				dm_svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] - (MR_SHORT)viewport->vp_render_matrix.t[2];
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

	// So this is what we now want to do with poly otz:
	//
	// shift down by mesh_param.p_otz_shift
	// add mesh_param.p_ot_otz_delta

#ifdef PSX_DEBUG
	MRRendered_meshes++;
#endif

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
		MRMULMATRIXABC(&MRLight_matrix, MRWorldtrans_ptr, &MRLight_matrix);
		gte_SetLightMatrix(&MRLight_matrix);
		}
	else
		{
		MRMULMATRIXABC(&viewport->vp_light_matrix, MRWorldtrans_ptr, &MRLight_matrix);
		gte_SetLightMatrix(&MRLight_matrix);
		dm_lights_modified = NULL;
		}

	//---------------------------------------------------------------------------------------------

	// Lighting code performs matrix multiplication, which destroys the GTE rotation matrix
	gte_SetRotMatrix(MRViewtrans_ptr);
	gte_SetTransMatrix(MRViewtrans_ptr);

	// Set up vert_ptr, norm_ptr, prim_ptr, prims, mem
	// ...depending on which model from the MOF we are displaying
	mem 		= mesh_inst_ptr->mi_prims[part] + ((part_ptr->mp_buff_size >> 2) * MRFrame_index);

	vert_ptr 	= part_ptr->mp_partcel_ptr[partcel].mp_vert_ptr;
	norm_ptr 	= part_ptr->mp_partcel_ptr[partcel].mp_norm_ptr;
	prim_ptr	= part_ptr->mp_prim_ptr;
	prims		= part_ptr->mp_prims;
	
	// Set flag saying this mesh instance was displayed
	mesh_inst_ptr->mi_flags |= MR_MESH_INST_DISPLAYED_LAST_FRAME;

	render_flags = mesh_inst_ptr->mi_flags & MR_MESH_INST_SPECIAL_RENDER_MASK;

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
				else
					MRSpecialDisplayMeshPolys_F3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
  			case MR_MPRIMID_F4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_F4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_F4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_FT3:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_FT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else		
					MRSpecialDisplayMeshPolys_FT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_FT4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_FT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_FT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_G3:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_G3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_G3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_G4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_G4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_G4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_GT3:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_GT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_GT3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_GT4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_GT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_GT4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_E3:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_E3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_E3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_E4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_E4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_E4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_GE3:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_GE3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_GE3(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
				mem			=	mesh_param.p_mem_ptr;
				prim_ptr 	=	mesh_param.p_prim_ptr;	
				prims		=	mesh_param.p_prims;
				break;
			//---------------------------------------------------------------------------------------
			case MR_MPRIMID_GE4:
				mesh_param.p_prims = prims;
				if (!render_flags)
					MRDisplayMeshPolys_GE4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq);
				else
					MRSpecialDisplayMeshPolys_GE4(vert_ptr, norm_ptr, prim_ptr, mem, &mesh_param, dm_light_dpq, render_flags);
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

	// If we've overwritten the colour matrix for this mesh, set it back to the viewport colour matrix
	if (dm_lights_modified & MR_CHANGED_COLOUR_MATRIX)
		gte_SetColorMatrix(&viewport->vp_colour_matrix);

	// If we've modified the ambient colour for this mesh, set it back to the viewport colour matrix
	if (dm_lights_modified & MR_CHANGED_AMBIENT_COLOUR)
		gte_SetBackColor(viewport->vp_back_colour.r, viewport->vp_back_colour.g, viewport->vp_back_colour.b);


	// Debug: display hilite primitives (this must be done after polys are added, because it writes to poly colours)
	if (mesh_ptr->me_flags & MR_MESH_DEBUG_DISPLAY_HILITE_PRIMS)
		MRDebugPlotHilitePrims(smesh_ptr->sm_mof_ptr, part, mesh_inst_ptr, MR_DEBUG_DISPLAY_HILITE_PRIMS_COLOUR);
}

