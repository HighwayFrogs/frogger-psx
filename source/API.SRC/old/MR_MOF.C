/******************************************************************************
*%%%% mr_mof.c
*------------------------------------------------------------------------------
*
*	General MOF(PlayStation Format) manipulation and initialisation routines
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	14.05.96	Tim Closs		Created
*	29.05.96	Dean Ashton		Removed excess castings.
*	19.06.96	Tim Closs		MOF2 changes: Added Prim_type_gpu_xy_offsets[]
*								Updated MRResolveMOF
*								Updated MRCreateMOFFromMOF
*								Updated MRScaleMOF
*								Updated MRWriteMODPrimCodes
*	02.08.96	Tim Closs		Removed flags field from MRCreateMOFFromMOF
*								Added MRRotateMOF
*								All MOF manipulation functions now assume ptrs are
*								absolute
*	02.08.96	Tim Closs		In MRPresetMODPrims, all texture info now copied
*								directly from MR_MPRIMs (rather than MR_TEXTUREs)
*	05.08.96	Dean Ashton		Added MRResolveMOFTextures/MRUnresolveMOFTextures
*								for application of VORG texture offsets.
*	08.08.96	Tim Closs		Added "duplicate" input (FALSE for anims) in
*								MRPresetMODPrims
*	20.08.96	Dean Ashton		Moved static mof functions to mr_stat.c, and added
*								calls to animating mof functions.
*								Renamed Prim_<xxx> variables to MRPrim_<xxx>
*	11.09.96	Tim Closs		Added	MRCalculateMOFDimensions
*	09.10.96	Tim Closs		MRScaleMOF now handles animated MOFs
*	10.10.96	Tim Closs		Added MRCheckBoundingBoxOnScreen()
*	23.10.96	Tim Closs		New prim types supported:
*								MR_MPRIMID_HLF3, MR_MPRIMID_HLF4
*								Added	MRCreateWireframeMOF() and 
*								MRStaticCreateWireframeMOF()
*								MRCalculateMOFDimensions() changed to call
*								new function MRCalculateMOFVertexExtremes()
*	31.10.96	Tim Closs		MRCheckBoundingBoxOnScreen changed to accept
*								origin_otz input and write out otz of origin 
*	24.01.97	Tim Closs		MRCheckBoundingBoxOnScreen() changed to return
*								flags field
*	28.01.97	Tim Closs		Added:
*								MRPartGetPrim()
*								MRPartGetPrimOffset()
*								MRGetNumberOfHilites()
*								MRGetFirstHilite()
*								MRFillHiliteSVECArray()
*								MRFillHiliteSVECPointerArray()
*	18.02.97	Tim Closs		MR(Static)CreateWireframeMOF() now handle
*								MR_MOF_WIREFRAME_MONOCHROME
*	26.02.97	Tim Closs		MRStaticCreateWireframeMOF() now supports the
*								full new MR_PART structure!
*	07.04.97	Dean Ashton		Fixed bug in MRCheckBoundingBoxOnScreen()
*	13.06.97	Dean Ashton		Support for new MR_MPRIM_GE3/GE4 primitives	
*								MRWritePartPrimCodes() can modify translucency
*								flags on request for translucent textures.
*	06.06.97	Tim Closs		Added support for animated polys.  New functions:
*								MRPartGetPrimOffsetFromPointer()
*								MRCalculateMOFAnimatedPolys()
*
*%%%**************************************************************************/

#include "mr_all.h"


MR_USHORT	MRPrim_type_gpu_sizes[] =		// in bytes!!!
				{
				sizeof(POLY_F3),							// MR_MPRIM_F3
				sizeof(POLY_F4),							// MR_MPRIM_F4
				sizeof(POLY_FT3),							// MR_MPRIM_FT3
				sizeof(POLY_FT4),							// MR_MPRIM_FT4
				sizeof(POLY_G3),							// MR_MPRIM_G3
				sizeof(POLY_G4),							// MR_MPRIM_G4
				sizeof(POLY_GT3),							// MR_MPRIM_GT3
				sizeof(POLY_GT4),							// MR_MPRIM_GT4
				sizeof(POLY_FT3),							// MR_MPRIM_E3
				sizeof(POLY_FT4),							// MR_MPRIM_E4
				sizeof(LINE_F2),							// MR_MPRIM_LF2
				sizeof(LINE_F3),							// MR_MPRIM_LF3
				sizeof(LINE_F4) + sizeof(POLY_F3),			// MR_MPRIM_HLF3
				(sizeof(LINE_F3) * 2) + sizeof(POLY_F4),	// MR_MPRIM_HLF4
				sizeof(POLY_GT3),							// MR_MPRIM_GE3
				sizeof(POLY_GT4),							// MR_MPRIM_GE4
					};

MR_USHORT	MRPrim_type_mod_sizes[] =			// in longwords
				{
				sizeof(MR_MPRIM_F3) >> 2,			// MR_MPRIM_F3
				sizeof(MR_MPRIM_F4) >> 2,			// MR_MPRIM_F4
				sizeof(MR_MPRIM_FT3) >> 2,			// MR_MPRIM_FT3
				sizeof(MR_MPRIM_FT4) >> 2,			// MR_MPRIM_FT4
				sizeof(MR_MPRIM_G3) >> 2,			// MR_MPRIM_G3
				sizeof(MR_MPRIM_G4) >> 2,			// MR_MPRIM_G4
				sizeof(MR_MPRIM_GT3) >> 2,			// MR_MPRIM_GT3
				sizeof(MR_MPRIM_GT4) >> 2,			// MR_MPRIM_GT4
				sizeof(MR_MPRIM_E3) >> 2,			// MR_MPRIM_E3
				sizeof(MR_MPRIM_E4) >> 2,			// MR_MPRIM_E4
				sizeof(MR_MPRIM_LF2) >> 2,			// MR_MPRIM_LF2
				sizeof(MR_MPRIM_LF3) >> 2,			// MR_MPRIM_LF3
				sizeof(MR_MPRIM_HLF3) >> 2,			// MR_MPRIM_HLF3
				sizeof(MR_MPRIM_HLF4) >> 2,			// MR_MPRIM_HLF4
				sizeof(MR_MPRIM_GE3) >> 2,			// MR_MPRIM_GE3
				sizeof(MR_MPRIM_GE4) >> 2,			// MR_MPRIM_GE4
				};

MR_USHORT	MRPrim_type_gpu_codes[] =
				{
				0x20,								// MR_MPRIM_F3 		uses POLY_F3
				0x28,								// MR_MPRIM_F4 		uses POLY_F4
				0x24,								// MR_MPRIM_FT3 	uses POLY_FT3
				0x2c,								// MR_MPRIM_FT4 	uses POLY_FT4
				0x30,								// MR_MPRIM_G3 		uses POLY_G3
				0x38,								// MR_MPRIM_G4 		uses POLY_G4
				0x34,								// MR_MPRIM_GT3 	uses POLY_GT3
				0x3c,								// MR_MPRIM_GT4 	uses POLY_GT4
				0x24,								// MR_MPRIM_E3 		uses POLY_FT3
				0x2c,								// MR_MPRIM_E4 		uses POLY_FT4
				0x40,								// MR_MPRIM_LF2		uses LINE_F2
				0x48,								// MR_MPRIM_LF3		uses LINE_F3
				0x4c,								// MR_MPRIM_HLF3	uses LINE_F4
				0x48,								// MR_MPRIM_HLF4	uses LINE_F3
				0x34,								// MR_MPRIM_GE3 	uses POLY_GT3
				0x3c,								// MR_MPRIM_GE4 	uses POLY_GT4
				};

MR_USHORT	MRPrim_type_gpu_xy_offsets[] =			// in bytes!!!
				{
				4,
				4,
				8,
				8,
				8,
				8,
				12,
				12,
				};

MR_TEXTURE** 	MRTexture_list_ptr;					// Pointer to texture list
												
MR_TEXTURE*		MREnv_strip;						// New! MR_TEXTURE!


/******************************************************************************
*%%%% MRSetEnvMap
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetEnvMap(
*						MR_TEXTURE* envmap_image);
*
*	FUNCTION	Sets the current environment map source image. 
*
*	INPUTS		envmap_image	-	Pointer to a valid MR_TEXTURE structure
*
*	NOTES		The current environment map image pointer is only used when 
*				creating the hardware specific primitives. If the texture is
*				changed during the lifetime of an environment mapped part,
*				the changes will not be applied to it. This needs resolving.
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetEnvMap(MR_TEXTURE* envmap_image)
{
	MR_ASSERT(envmap_image != NULL);

	MREnv_strip = envmap_image;
}

/******************************************************************************
*%%%% MRSetTextureList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetTextureList(
*						MR_TEXTURE* envmap_image);
*
*	FUNCTION	Sets the current texture list.
*
*	INPUTS		texture_list	-	Pointer to a valid MR_TEXTURE list
*
*	NOTES		No validation is possible on the contents of the list. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetTextureList(MR_TEXTURE** texture_list)
{
	MR_ASSERT(texture_list != NULL);

	MRTexture_list_ptr = texture_list;
}


/******************************************************************************
*%%%% MRResolveMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResolveMOF(
*						MR_MOF* mof_ptr);
*
*	FUNCTION	Resolves all offsets and sizes within a MOF. This routine 
*				identifies the MOF type, and calls type-specific routines to 
*				perform MOF resolving. 
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	16.05.96	Dean Ashton		Created
*	20.08.96	Dean Ashton		Changed to call mr_stat/mr_anim functions
*
*%%%**************************************************************************/

MR_VOID	MRResolveMOF(MR_MOF* mof_ptr)
{
	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		MRAnimResolveMOF(mof_ptr);
	else
		MRStaticResolveMOF(mof_ptr);
}

/******************************************************************************
*%%%% MRResolveMOFTextures
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResolveMOFTextures(
*						MR_MOF* mof_ptr);
*
*	FUNCTION	Resolves a parts UV texture coordinates to correctly 
*				represent VORG VRAM placement of texture data. This routine
*				identifies the MOF type, and calls type-specific routines to 
*				perform MOF texture resolving. 
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*
*	CHANGED		PROGRAMMER		REASON						
*	-------		----------		------
*	19.08.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRResolveMOFTextures(MR_MOF* mof_ptr)
{
	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		MRAnimResolveMOFTextures(mof_ptr);
	else
		MRStaticResolveMOFTextures(mof_ptr);
}



/******************************************************************************
*%%%% MRPatchMOFTranslucency
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRPatchMOFTranslucency(
*						MR_MOF* mof_ptr,
*						MR_BOOL	add_trans);
*
*	FUNCTION	Patches textured MR_MPRIM's in the specified MOF (whether
*				animating or static) to enable/disable translucent processing
*				depending on MR_TEXTURE translucency flags.
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

MR_VOID	MRPatchMOFTranslucency(MR_MOF* mof_ptr, MR_BOOL add_trans)
{
	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		{
		MRAnimPatchMOFTranslucency(mof_ptr, add_trans);
		}
	else
		{
		MRStaticPatchMOFTranslucency(mof_ptr, add_trans);
		}
}


/******************************************************************************
*%%%% MRCalculatePartPrimSize
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG size =	MRCalculatePartPrimSize(
*								MR_PART* 		part_ptr);
*
*	FUNCTION	Calculates the size of a single set of primitives for the
*				part. As this routine is called from MRResolveMOF(), we 
*				assume that the part pointers are absolute.
*
*	INPUTS		part_ptr	-	Pointer to a valid MR_PART structure
*
*	RESULT		size		-	Size of primitive set (in bytes)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG	MRCalculatePartPrimSize(MR_PART* part_ptr)
{
	MR_ULONG	prims;
	MR_ULONG*	prim_ptr;
	MR_USHORT	i, type;
	MR_ULONG	size = 0;

	MR_ASSERT(part_ptr != NULL);

	prims 		= part_ptr->mp_prims;
	prim_ptr 	= part_ptr->mp_prim_ptr;			// we assume this pointer is now absolute

	while(prims)
		{
		type		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
		i			= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
		prim_ptr++;
		size 		+= (i * MRPrim_type_gpu_sizes[type]);		// these sizes are in bytes
		prim_ptr	+= (i * MRPrim_type_mod_sizes[type]);		// these sizes are in longwords
		prims 		-= i;
		}

	return(size);
}


/******************************************************************************
*%%%% MRWritePartPrimCodes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRWritePartPrimCodes(
*						MR_PART* 		part_ptr,
*						MR_BOOL			process_translucency)
*
*	FUNCTION	Fills in the 'cd' element of the MR_CVEC at the end of each
*				MR_MPRIM_<xx> structure within a part. The 'cd' element holds
*				the raw PlayStation primitive code, which identifies a polygon
*				type to the hardware. As this routine is called from
*				MRResolveMOF(), we assume that the part primitive pointers are
*				now absolute. This routine also performs a dual function in that
*				it can add/remove translucency enable bits into the primitive code
*				for each textured MR_MPRIM that has uses a MR_TEXTURE with the
*				appropriate translucency enable bit set.
*
*	INPUTS		part_ptr				-	Pointer to a valid MR_PART structure
*				process_translucency	-	TRUE if we want to modify the prims
*											to be translucent if the corresponding
*											MR_TEXTURE is flagged as translucenct
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	23.10.96	Tim Closs		New prim types supported:
*								MR_MPRIMID_LF2, MR_MPRIMID_HLF3,
*								MR_MPRIMID_HLF3, MR_MPRIMID_HLF4
*	18.06.97	Dean Ashton		Added translucency processing
*
*%%%**************************************************************************/

MR_VOID	MRWritePartPrimCodes(MR_PART* part_ptr, MR_BOOL process_translucency)
{
	MR_ULONG	prims;
	MR_ULONG*	prim_ptr;
	MR_USHORT	i, type;


	prims 		= part_ptr->mp_prims;
	prim_ptr 	= part_ptr->mp_prim_ptr;			// we assume this pointer is now absolute

	while(prims)
		{
		type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
		prim_ptr++;

		while (i--)
			{
			prim_ptr += MRPrim_type_mod_sizes[type];		// these sizes are in longwords

			switch(type)
				{
				case MR_MPRIMID_F3:
				case MR_MPRIMID_F4:
				case MR_MPRIMID_G3:
				case MR_MPRIMID_G4:
				case MR_MPRIMID_E3:
				case MR_MPRIMID_E4:
				case MR_MPRIMID_LF2:
				case MR_MPRIMID_LF3:
				case MR_MPRIMID_HLF3:
				case MR_MPRIMID_HLF4:
				case MR_MPRIMID_GE3:
				case MR_MPRIMID_GE4:

					// cd b g r is always last 32bit in prim
					*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type];
					break;

				case MR_MPRIMID_FT3:
					if (process_translucency && (MRTexture_list_ptr[(((MR_MPRIM_FT3*)prim_ptr) - 1)->mp_image_id]->te_flags & MR_SPIF_TRANSLUCENT))
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type] | 0x2;
					else
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type];
					break;

				case MR_MPRIMID_FT4:
					if (process_translucency && (MRTexture_list_ptr[(((MR_MPRIM_FT4*)prim_ptr) - 1)->mp_image_id]->te_flags & MR_SPIF_TRANSLUCENT))
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type] | 0x2;
					else
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type];
					break;

				case MR_MPRIMID_GT3:
					if (process_translucency && (MRTexture_list_ptr[(((MR_MPRIM_GT3*)prim_ptr) - 1)->mp_image_id]->te_flags & MR_SPIF_TRANSLUCENT))
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type] | 0x2;
					else
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type];
					break;

				case MR_MPRIMID_GT4:
					if (process_translucency && (MRTexture_list_ptr[(((MR_MPRIM_GT4*)prim_ptr) - 1)->mp_image_id]->te_flags & MR_SPIF_TRANSLUCENT))
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type] | 0x2;
					else
						*(((MR_BYTE*)prim_ptr) - 1) = MRPrim_type_gpu_codes[type];
					break;
				}
			prims--;
			}
		}
}


/******************************************************************************
*%%%% MRPresetPartPrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG size	=	MRPresetPartPrims(
*									MR_PART* 	part_ptr,
*									MR_ULONG*	mem,
*									MR_BOOL		duplicate);
*
*	FUNCTION	Creates a double buffered primitive set (PlayStation format) in 
*				pre-allocated memory for a part. 
*
*	INPUTS		part_ptr	-	Pointer to a valid MR_PART structure
*				mem			-	Pointer to previously allocated memory
*				duplicate	-	TRUE if we want to make another copy of the
*							 	data after the first (used for setting up
*							 	static meshes only)
*
*	RESULT		size		-	Length of one primitive buffer (in bytes)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	02.08.96	Tim Closs		All texture info now copied directly from MR_MPRIMs
*	08.08.96	Tim Closs		Added "duplicate" input (FALSE for anims)
*	23.10.96	Tim Closs		New prim types supported:
*								MR_MPRIMID_HLF3, MR_MPRIMID_HLF4
*
*%%%**************************************************************************/

MR_LONG	MRPresetPartPrims(	MR_PART*	part_ptr, 
							MR_ULONG*	mem,
							MR_BOOL		duplicate)
{
	MR_ULONG	prims;
	MR_ULONG*	prim_ptr;
	MR_USHORT	i, type;
	MR_ULONG*	org_mem;


	MR_ASSERT(part_ptr != NULL);
	MR_ASSERT(mem != NULL);

	prims 		=	part_ptr->mp_prims;
	prim_ptr	=	part_ptr->mp_prim_ptr;			// we assume this pointer is now absolute
	org_mem		=	mem;

	while(prims)
		{
		type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
		prim_ptr++;

		switch(type)
			{
			case MR_MPRIMID_F3:
				while (i--)
					{
					setPolyF3((POLY_F3*)mem);
					((POLY_F3*)mem)++;
					((MR_MPRIM_F3*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_F4:
				while (i--)
					{
					setPolyF4((POLY_F4*)mem);
					((POLY_F4*)mem)++;
					((MR_MPRIM_F4*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_FT3:
				while (i--)
					{
					setPolyFT3((POLY_FT3*)mem);
					// Set up texture coords
					MR_COPY32(((POLY_FT3*)mem)->u0, ((MR_MPRIM_FT3*)prim_ptr)->mp_u0);
					MR_COPY32(((POLY_FT3*)mem)->u1, ((MR_MPRIM_FT3*)prim_ptr)->mp_u1);
					MR_COPY16(((POLY_FT3*)mem)->u2, ((MR_MPRIM_FT3*)prim_ptr)->mp_u2);
					((POLY_FT3*)mem)++;
					((MR_MPRIM_FT3*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_FT4:
				while (i--)
					{
					setPolyFT4((POLY_FT4*)mem);

					// Set up texture coords
					MR_COPY32(((POLY_FT4*)mem)->u0, ((MR_MPRIM_FT4*)prim_ptr)->mp_u0);
					MR_COPY32(((POLY_FT4*)mem)->u1, ((MR_MPRIM_FT4*)prim_ptr)->mp_u1);
					MR_COPY16(((POLY_FT4*)mem)->u3, ((MR_MPRIM_FT4*)prim_ptr)->mp_u2);
					MR_COPY16(((POLY_FT4*)mem)->u2, ((MR_MPRIM_FT4*)prim_ptr)->mp_u3);
					((POLY_FT4*)mem)++;
					((MR_MPRIM_FT4*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_G3:
				while (i--)
					{
					setPolyG3((POLY_G3*)mem);
					((POLY_G3*)mem)++;
					((MR_MPRIM_G3*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_G4:
				while (i--)
					{
					setPolyG4((POLY_G4*)mem);
					((POLY_G4*)mem)++;
					((MR_MPRIM_G4*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_GT3:
				while (i--)
					{
					setPolyGT3((POLY_GT3*)mem);
					// Set up texture coords
					MR_COPY32(((POLY_GT3*)mem)->u0, ((MR_MPRIM_GT3*)prim_ptr)->mp_u0);
					MR_COPY32(((POLY_GT3*)mem)->u1, ((MR_MPRIM_GT3*)prim_ptr)->mp_u1);
					MR_COPY16(((POLY_GT3*)mem)->u2, ((MR_MPRIM_GT3*)prim_ptr)->mp_u2);
					((POLY_GT3*)mem)++;
					((MR_MPRIM_GT3*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_GT4:
				while (i--)
					{
					setPolyGT4((POLY_GT4*)mem);
					// Set up texture coords
					MR_COPY32(((POLY_GT4*)mem)->u0, ((MR_MPRIM_GT4*)prim_ptr)->mp_u0);
					MR_COPY32(((POLY_GT4*)mem)->u1, ((MR_MPRIM_GT4*)prim_ptr)->mp_u1);
					MR_COPY16(((POLY_GT4*)mem)->u3, ((MR_MPRIM_GT4*)prim_ptr)->mp_u2);
					MR_COPY16(((POLY_GT4*)mem)->u2, ((MR_MPRIM_GT4*)prim_ptr)->mp_u3);
					((POLY_GT4*)mem)++;
					((MR_MPRIM_GT4*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_E3:
				while (i--)
					{
					setPolyFT3((POLY_FT3*)mem);
					// Set up texture coords
					((POLY_FT3*)mem)->tpage	= MREnv_strip->te_tpage_id;
					((POLY_FT3*)mem)->clut	= MREnv_strip->te_clut_id;
					((POLY_FT3*)mem)++;
					((MR_MPRIM_E3*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_E4:
				while (i--)
					{
					setPolyFT4((POLY_FT4*)mem);
					// Set up texture coords
					((POLY_FT4*)mem)->tpage	= MREnv_strip->te_tpage_id;
					((POLY_FT4*)mem)->clut	= MREnv_strip->te_clut_id;
					((POLY_FT4*)mem)++;
					((MR_MPRIM_E4*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_GE3:
				while (i--)
					{
					setPolyGT3((POLY_GT3*)mem);
					// Set up texture coords
					((POLY_GT3*)mem)->tpage	= MREnv_strip->te_tpage_id;
					((POLY_GT3*)mem)->clut	= MREnv_strip->te_clut_id;
					((POLY_GT3*)mem)++;
					((MR_MPRIM_GE3*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_GE4:
				while (i--)
					{
					setPolyGT4((POLY_GT4*)mem);
					// Set up texture coords
					((POLY_GT4*)mem)->tpage	= MREnv_strip->te_tpage_id;
					((POLY_GT4*)mem)->clut	= MREnv_strip->te_clut_id;
					((POLY_GT4*)mem)++;
					((MR_MPRIM_GE4*)prim_ptr)++;
					prims--;
					}
				break;

			case MR_MPRIMID_HLF3:
				while (i--)
					{
//					CatPrim((LINE_F4*)mem, ((LINE_F4*)mem) + 1);
					setLineF4((LINE_F4*)mem);
					MR_COPY32(((LINE_F4*)mem)->r0, ((MR_MPRIM_HLF3*)prim_ptr)->mp_cvec.r);
					((LINE_F4*)mem)++;
					setPolyF3((POLY_F3*)mem);
					setRGB0((POLY_F3*)mem, 0x00, 0x00, 0x00);
					((POLY_F3*)mem)++;
					((MR_MPRIM_HLF3*)prim_ptr)++;
					prims--;
					}
				break;
	
			case MR_MPRIMID_HLF4:
				while (i--)
					{
//					CatPrim((LINE_F3*)mem, ((LINE_F3*)mem) + 1);
//					CatPrim(((LINE_F3*)mem + 1), ((LINE_F3*)mem) + 2);
					setLineF3((LINE_F3*)mem);
					MR_COPY32(((LINE_F3*)mem)->r0, ((MR_MPRIM_HLF4*)prim_ptr)->mp_cvec.r);
					((LINE_F3*)mem)++;
					setLineF3((LINE_F3*)mem);
					MR_COPY32(((LINE_F3*)mem)->r0, ((MR_MPRIM_HLF4*)prim_ptr)->mp_cvec.r);
					((LINE_F3*)mem)++;
					setPolyF4((POLY_F4*)mem);
					setRGB0((POLY_F4*)mem, 0x00, 0x00, 0x00);
					((POLY_F4*)mem)++;
					((MR_MPRIM_HLF4*)prim_ptr)++;
					prims--;
					}
				break;
			}
		}

	if (duplicate == TRUE)
		{
		// We have now set up all the polys for one buffer... now duplicate the memory we have set up
		// for use as the second buffer
		i = mem - org_mem;										// size of 1st buffer in 32bit words

		while(i--)
			*mem++ = *org_mem++;
		}

	return((mem - org_mem) << 2);
}


/******************************************************************************
*%%%% MRScaleMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRScaleMOF(
*						MR_MOF* 		mof_ptr,
*						MR_SHORT		scale);
*
*	FUNCTION	Scales the vertices and bounding box used by the specified
*				MOF.
*
*	INPUTS		mof_ptr		-	Pointer to a valid MR_MOF structure
*				scale		-	Scaling value (4096 == 1:1)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	20.06.96	Tim Closs		Modified for MOF2
*	01.08.96	Tim Closs		Now assumes pointers are absolute
*	09.10.96	Tim Closs		Now handles animated MOFs
*
*%%%**************************************************************************/

MR_VOID	MRScaleMOF(	MR_MOF* 	mof_ptr,
					MR_SHORT scale)
{
	MR_USHORT				v, c, i, s;
	MR_PART*				part_ptr;
	MR_PARTCEL*				partcel_ptr;
	MR_SVEC*				vert_ptr;
	MR_MOF**				mof_pptr;
	MR_ANIM_HEADER*			anim_ptr;
	MR_ANIM_COMMON_DATA*	common_data;
	MR_MAT34*				transform;
	MR_VEC*					translation;
	MR_BBOX*				bbox;


	MR_ASSERT(mof_ptr != NULL);

	// Set up scale matrix	
	MRScale_matrix.m[0][0] = scale;
	MRScale_matrix.m[1][1] = scale;
	MRScale_matrix.m[2][2] = scale;

	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		{
		// MOF is an animation.  We must scale the translation part of all transforms, then scale all static files
		anim_ptr		= (MR_ANIM_HEADER*)mof_ptr;
		common_data = anim_ptr->ah_common_data;

		// Scale transforms
		if (common_data->ac_flags & MR_ANIM_COMMON_TRANSFORMS_PRESENT)
			{
			v 			= common_data->ac_no_of_transforms;
			transform 	= common_data->ac_transforms;
			while(v--)
				{
				transform->t[0] = (transform->t[0] * scale) >> 12;
				transform->t[1] = (transform->t[1] * scale) >> 12;
				transform->t[2] = (transform->t[2] * scale) >> 12;
				transform++;
				}
			}
		// Scale translations
		if (common_data->ac_flags & MR_ANIM_COMMON_TRANSLATIONS_PRESENT)
			{
			v 			= common_data->ac_no_of_translations;
			translation	= common_data->ac_translations;
			while(v--)
				{
				translation->vx = (translation->vx * scale) >> 12;
				translation->vy = (translation->vy * scale) >> 12;
				translation->vz = (translation->vz * scale) >> 12;
				translation++;
				}
			}
		// Scale bounding boxes (NOTE: we are assuming ALL bouding boxes used by the anim file are in the common data block!)
		if (common_data->ac_flags & MR_ANIM_COMMON_BBOXES_PRESENT)
			{
			v 		= common_data->ac_no_of_bboxes;
			bbox	= common_data->ac_bboxes;
			while(v--)
				{
				s			= 8;
				vert_ptr	= bbox->mb_verts;
				while(s--)
					{
					vert_ptr->vx = (vert_ptr->vx * scale) >> 12;
					vert_ptr->vy = (vert_ptr->vy * scale) >> 12;
					vert_ptr->vz = (vert_ptr->vz * scale) >> 12;
					vert_ptr++;
					}
				bbox++;
				}
			}

		// Scale static files
		mof_pptr	= anim_ptr->ah_static_files;
		s			= anim_ptr->ah_no_of_static_files;
		}	
	else	
		{
		// Scale single static file
		mof_pptr	= &mof_ptr;
		s			= 1;
		}	
	
	while(s--)
		{
		// Scale all parts (parts) in static file
		part_ptr = (MR_PART*)(((MR_UBYTE*)*mof_pptr) + sizeof(MR_MOF));

		// Scale vertices
		// Note that all ptrs ARE NOW ABSOLUTE
		for (i = 0; i < (*mof_pptr)->mm_extra; i++)
			{
			partcel_ptr = part_ptr->mp_partcel_ptr;

			for (c = 0; c < part_ptr->mp_partcels; c++)
				{
				// Scale main vertex block
				vert_ptr = partcel_ptr->mp_vert_ptr;
				v = part_ptr->mp_verts;

				while(v--)
					{
					MRApplyMatrixSVEC(&MRScale_matrix, vert_ptr, vert_ptr);
					vert_ptr++;
					}

				// Scale bounding vertices... WE ASSUME THESE ARE NOT IN THE ABOVE BLOCK
				if (partcel_ptr->mp_bbox_ptr)
					{
					vert_ptr = partcel_ptr->mp_bbox_ptr->mb_verts;
					v 			= 8;
					while(v--)
						{
						MRApplyMatrixSVEC(&MRScale_matrix, vert_ptr, vert_ptr);
						vert_ptr++;
						}	
					}
				partcel_ptr++;
				}
			part_ptr++;
			}
		mof_pptr++;
		}
}


/******************************************************************************
*%%%% MRRotateMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS   	MR_VOID	MRRotateMOF(
*			   			MR_MOF* 	mof_ptr,
*			   			MR_MAT*		matrix);
*
*	FUNCTION   	Rotates the vertices and normals in a MOF
*
*	INPUTS		mof_ptr		-	ptr to a valid MR_MOF structure
*			   	matrix		-	ptr to rotation matrix
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.08.96   	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRRotateMOF(MR_MOF* mof_ptr,
			   		MR_MAT*	matrix)
{
	MR_USHORT	v, c, i;
	MR_PART*	part_ptr;
	MR_PARTCEL*	partcel_ptr;
	MR_SVEC*   	vert_ptr;

	MR_ASSERT(mof_ptr != NULL);

	part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

	// Scale vertices in copy
	//
	// Note that all ptrs ARE NOW ABSOLUTE
	for (i = 0; i < mof_ptr->mm_extra; i++)
		{
		partcel_ptr = part_ptr->mp_partcel_ptr;

		for (c = 0; c < part_ptr->mp_partcels; c++)
			{
			// Scale main vertex block
			vert_ptr	= partcel_ptr->mp_vert_ptr;
			v 			= part_ptr->mp_verts;
			while(v--)
				{
				MRApplyMatrixSVEC(matrix, vert_ptr, vert_ptr);
				vert_ptr++;
				}

			// Scale main normal block
			vert_ptr	= partcel_ptr->mp_norm_ptr;
			v 			= part_ptr->mp_norms;
			while(v--)
				{
				MRApplyMatrixSVEC(matrix, vert_ptr, vert_ptr);
				vert_ptr++;
				}

			// Scale bounding vertices... WE ASSUME THESE ARE NOT IN THE ABOVE BLOCK
			if (partcel_ptr->mp_bbox_ptr)
				{
				vert_ptr	= partcel_ptr->mp_bbox_ptr->mb_verts;
				v 			= 8;
				while(v--)
					{
					MRApplyMatrixSVEC(matrix, vert_ptr, vert_ptr);
					vert_ptr++;
					}	
				}
			partcel_ptr++;
			}
		part_ptr++;
		}
}


/******************************************************************************
*%%%% MRCalculateMOFDimensions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateMOFDimensions(
*						MR_MOF*	mof_ptr,
*						MR_VEC*	bounds)
*
*	FUNCTION	For a static ir animating MOF, calculate coordinate limits of
*				vertices (ie. max x, min x, max y, etc...) and fill out a vector
*				with the dimensions of the bounding box (ie. max x - min x, etc.)
*
*	INPUTS		mof_ptr		-	ptr to mof
*				bounds		-	ptr to vector to fill out with bounds	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.09.96	Tim Closs		Created
*	23.10.96	Tim Closs		Changed to call MRCalculateMOFVertexExtremes
*
*%%%**************************************************************************/

MR_VOID	MRCalculateMOFDimensions(	MR_MOF*	mof_ptr,
									MR_VEC*	bounds)
{
	MR_VEC	max_vec, min_vec;

	MR_ASSERT(mof_ptr);
	MR_ASSERT(bounds);
	
	if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
		{
		// If we are checking an animation, just check the first static MOF in the file
		mof_ptr	= *(((MR_ANIM_HEADER*)mof_ptr)->ah_static_files);
		}

	MRCalculateMOFVertexExtremes(mof_ptr, &max_vec, &min_vec);

	// Place width, height, depth in vector
	bounds->vx = max_vec.vx - min_vec.vx;
	bounds->vy = max_vec.vy - min_vec.vy;
	bounds->vz = max_vec.vz - min_vec.vz;
}


/******************************************************************************
*%%%% MRCalculateMOFVertexExtremes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCalculateMOFVertexExtremes(
*						MR_MOF*	mof_ptr,
*						MR_VEC*	max_vec,
*						MR_VEC*	min_vec)
*
*	FUNCTION	For a static MOF, calculate coordinate limits of
*				vertices (ie. max x, min x, max y, etc...)
*
*	INPUTS		mof_ptr		-	ptr to mof
*				max_vec		-	ptr to MR_VEC to store coordinate maxima
*				min_vec		-	ptr to MR_VEC to store coordinate minima
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRCalculateMOFVertexExtremes(	MR_MOF*	mof_ptr,
										MR_VEC*	max_vec,
										MR_VEC*	min_vec)
{
	MR_PART*		part_ptr;
	MR_PARTCEL*		partcel_ptr;
	MR_SVEC*		vert_ptr;
	MR_USHORT		v, c, i;


	MR_ASSERT(mof_ptr != NULL);
	MR_ASSERT(max_vec != NULL);
	MR_ASSERT(min_vec != NULL);

	max_vec->vx = -0x8000;
	min_vec->vx =  0x7fff;
	max_vec->vy = -0x8000;
	min_vec->vy =  0x7fff;
	max_vec->vz = -0x8000;
	min_vec->vz =  0x7fff;

	// MOF is assumed to be static
	part_ptr = (MR_PART*)(((MR_UBYTE*)mof_ptr) + sizeof(MR_MOF));

	// Run through each part
	for (i = 0; i < mof_ptr->mm_extra; i++)
		{
		partcel_ptr = part_ptr->mp_partcel_ptr;

		// Run through each cel
		for (c = 0; c < part_ptr->mp_partcels; c++)
			{
			// Run through vertex block
			vert_ptr = partcel_ptr->mp_vert_ptr;
			v 			= part_ptr->mp_verts;
			while(v--)
				{
				min_vec->vx = MIN(min_vec->vx, vert_ptr->vx);
				max_vec->vx = MAX(max_vec->vx, vert_ptr->vx);
				min_vec->vy = MIN(min_vec->vy, vert_ptr->vy);
				max_vec->vy = MAX(max_vec->vy, vert_ptr->vy);
				min_vec->vz = MIN(min_vec->vz, vert_ptr->vz);
				max_vec->vz = MAX(max_vec->vz, vert_ptr->vz);

				vert_ptr++;
				}
			partcel_ptr++;
			}
		part_ptr++;
		}
}


/******************************************************************************
*%%%% MRCheckBoundingBoxOnScreen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	flags =	MRCheckBoundingBoxOnScreen(
*									MR_SVEC*		vert_ptr,
*									MR_ULONG*	origin_otz)
*
*	FUNCTION	Assuming RotMatrix and TransMatrix are set up, rotates 8
*				points and returns flags according to which are on screen.  Also
*				store the OTZ of the frame origin
*
*	INPUTS		vert_ptr		-	ptr to 8 bounding vertices in OpenInventor ordering
*				origin_otz		-	ptr to where to store otz of origin
*
*	RESULT		flags			-  eg. MR_BBOX_DISPLAY_ALL_VERTICES
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*	31.10.96	Tim Closs		Changed to accept origin_otz input and write out
*						  		otz of origin 
*	24.01.97	Tim Closs		Changed to return flags field
*	07.04.97	Dean Ashton		Fixed bug..
*
*%%%**************************************************************************/

MR_ULONG	MRCheckBoundingBoxOnScreen(	MR_SVEC*	vert_ptr,
										MR_ULONG*	origin_otz)
{
	MR_SHORT	coords[3][2];
	MR_ULONG	flags, v, t, bit;
	MR_SHORT*	coord_ptr;
	MR_SVEC		origin_svec;
	MR_SVEC*	work_vert_ptr;

	MR_ASSERT(vert_ptr);
	MR_ASSERT(origin_otz);

	work_vert_ptr = vert_ptr;

	flags = NULL;
	bit	= 1;			// First bit position in our flags longword
	v 		= 3;
	while(v--)
		{
		gte_ldv0(vert_ptr);
		vert_ptr++;
		gte_ldv1(vert_ptr);
		vert_ptr++;

		if (v == 0)
			{
			origin_svec.vx = (work_vert_ptr[0].vx + work_vert_ptr[7].vx) >> 1;
			origin_svec.vy = (work_vert_ptr[0].vy + work_vert_ptr[7].vy) >> 1;
			origin_svec.vz = (work_vert_ptr[0].vz + work_vert_ptr[7].vz) >> 1;
			gte_ldv2(&origin_svec);
			}
		else
			{
			gte_ldv2(vert_ptr);
			vert_ptr++;
			}

		gte_rtpt();
		coord_ptr 	= coords[0];
		t 			= 3;

		gte_stsxy0((MR_LONG*)coords[0]);	// xy of pt 0
		gte_stsxy1((MR_LONG*)coords[1]);	// xy of pt 1

		if (v == 0)
			{
			gte_stsz(origin_otz);
			}

		gte_stsxy2((MR_LONG*)coords[2]);	// xy of pt 2

		while(t--)
			{
			if ((coord_ptr[0] >= 0) && (coord_ptr[0] < MRVp_disp_w) && (coord_ptr[1] >= 0) && (coord_ptr[1] < MRVp_disp_h))
				flags |= bit;

			bit <<= 1;
			coord_ptr += 2;
			}
		}

	if (flags == 0)
		return(MR_BBOX_DISPLAY_NO_VERTICES);
	else
	if (flags == 0xff)
		return(MR_BBOX_DISPLAY_ALL_VERTICES);			
	else
		return(MR_BBOX_DISPLAY_SOME_VERTICES);


	return(flags);
}

/******************************************************************************
*%%%% MRCheckBoundingBoxOnScreenUsingEdges
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	flags =	MRCheckBoundingBoxOnScreenUsingEdges(
*									MR_SVEC*		vert_ptr,
*									MR_ULONG*	origin_otz)
*
*	FUNCTION	Rotates bounding box and uses transformed points to perform edge
*				detection to determine whether the mesh box is visible.
*
*	INPUTS		vert_ptr		-	ptr to 8 bounding vertices in OpenInventor ordering
*				origin_otz	-	ptr to where to store otz of origin
*
*	RESULT		flags			-  eg. MR_BBOX_DISPLAY_ALL_VERTICES
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.04.97	Dean Ashton		Creared
*
*%%%**************************************************************************/

MR_ULONG MRCheckBoundingBoxOnScreenUsingEdges(MR_SVEC* vert_ptr, MR_ULONG* origin_otz)
{
	MR_SHORT	coords[16];
	MR_ULONG	v, t;
	MR_SHORT*	coord_ptr;
	MR_LONG		edge, total;

	MR_ASSERT(vert_ptr);
	MR_ASSERT(origin_otz);

	v 			= 3;
	coord_ptr	= coords;

	// rotate all the points
	while(v--)
		{
		gte_ldv0(vert_ptr);
		vert_ptr++;

		gte_ldv1(vert_ptr);
		vert_ptr++;

		if(v == 0)
			{
			gte_ldv2(&MRNull_svec);
			}
		else
			{
			gte_ldv2(vert_ptr);
			vert_ptr++;
			}

		// rotate 
		gte_rtpt();

		gte_stsxy0((MR_LONG*)coord_ptr);	
		coord_ptr += 2;

		gte_stsxy1((MR_LONG*)coord_ptr);	
		coord_ptr += 2;

		if(v == 0)
			{
			gte_stsz(origin_otz);
			}
		else
			{
			gte_stsxy2((MR_LONG*)coord_ptr);	
			coord_ptr +=2;
			}
		}
	
	// now check the edges
	total = 0;

	// now check points with left edge
	edge		= 0;
	coord_ptr	= coords;
	for(t=8; t; t--)
		{
		edge += (*coord_ptr >= 0);
		coord_ptr += 2;
		}
	if(!edge)
		return(MR_BBOX_DISPLAY_NO_VERTICES);
	total += edge;

	// now check points with right edge
	edge		= 0;
	coord_ptr	= coords;
	for(t=8; t; t--)
		{
		edge += (*coord_ptr < MRVp_disp_w);
		coord_ptr +=2 ;
		}
	if(!edge)
		return(MR_BBOX_DISPLAY_NO_VERTICES);
	total += edge;

	// now check points with top edge
	edge		= 0;
	coord_ptr	= &coords[1];
	for(t=8; t; t--)
		{
		edge += (*coord_ptr >= 0);
		coord_ptr +=2;
		}
	if(!edge)
		return(MR_BBOX_DISPLAY_NO_VERTICES);
	total += edge;

	// now check points with bottom edge
	edge		= 0;
	coord_ptr	= &coords[1];
	for(t=8; t; t--)
		{
		edge += (*coord_ptr <= MRVp_disp_h);
		coord_ptr += 2;
		}
	if(!edge)
		return(MR_BBOX_DISPLAY_NO_VERTICES);
	total += edge;

	// Check for on screen
	if(total == 32)
		return(MR_BBOX_DISPLAY_ALL_VERTICES);
	else
		return(MR_BBOX_DISPLAY_SOME_VERTICES);	
}

  
/******************************************************************************
*%%%% MRCreateWireframeMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MOF*	dmof	=	MRCreateWireframeMOF(
*									MR_MOF*		smof,
*									MR_USHORT	flags,
*									MR_ULONG	colour)
*
*	FUNCTION	Create a wireframe MOF from an ordinary MOF.
*				Flags determine which primitives are used
*
*	INPUTS		smof		-	ptr to source MOF
*				flags		-	determine which primitive types are used
*				colour		-	if MR_MOF_WIREFRAME_MONOCHROME, use this colour
*
*	RESULT		dmof		-	ptr to static MOF created
*
*	NOTES		Flags currently supported:
*				MR_MOF_WIREFRAME_MONOCHROME
*
*				If the MOF is animated, a new static MOF is created for each
*				static MOF in the animation file.  A new MR_ANIM_HEADER is
*				created, along with a list of pointers to the new static MOFs,
*				and a pointer to MR_ANIM_HEADER is returned.				
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.10.96	Tim Closs		Created
*	22.10.96	Tim Closs		Now handles anim files
*	18.02.97	Tim Closs		Now handles MR_MOF_WIREFRAME_MONOCHROME
*
*%%%**************************************************************************/

MR_MOF*	MRCreateWireframeMOF(	MR_MOF*		smof,
							  	MR_USHORT	flags,
								MR_ULONG	colour)
{
	MR_ANIM_HEADER*		anim;
	MR_ANIM_HEADER*		danim;
	MR_USHORT			i;

	MR_ASSERT(smof);

	if (smof->mm_flags & MR_MOF_ANIMATED)
		{
		// MOF is an animation
		anim 	= (MR_ANIM_HEADER*)smof;
		danim	= MRAllocMem(sizeof(MR_ANIM_HEADER) + (sizeof(MR_MOF*) * anim->ah_no_of_static_files), "ANIMHEAD");	

		danim->ah_id					= anim->ah_id;
		danim->ah_length				= anim->ah_length;
		danim->ah_flags					= anim->ah_flags;
		danim->ah_no_of_model_sets		= anim->ah_no_of_model_sets;
		danim->ah_no_of_static_files	= anim->ah_no_of_static_files;
		danim->ah_model_sets			= anim->ah_model_sets;
		danim->ah_common_data			= anim->ah_common_data;
		danim->ah_static_files			= (MR_MOF**)(((MR_UBYTE*)danim) + sizeof(MR_ANIM_HEADER));

		for (i = 0; i < anim->ah_no_of_static_files; i++)
			{
			danim->ah_static_files[i] = MRStaticCreateWireframeMOF(anim->ah_static_files[i], flags, colour);
			}
		return((MR_MOF*)danim);
		}
	else
		{
		return(MRStaticCreateWireframeMOF(smof, flags, colour));
		}
}


/******************************************************************************
*%%%% MRStaticCreateWireframeMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MOF*	dmof	=	MRStaticCreateWireframeMOF(
*									MR_MOF*		smof,
*									MR_USHORT	flags,
*									MR_ULONG	colour)
*
*	FUNCTION	Create a wireframe static MOF from an ordinary static MOF.
*				Flags determine which primitives are used
*
*	INPUTS		smof		-	ptr to source MOF
*				flags		-	determine which primitive types are used
*				colour	-	if MR_MOF_WIREFRAME_MONOCHROME, use this colour
*
*	RESULT		dmof		-	ptr to static MOF created
*
*	NOTES		Flags currently supported:
*				MR_MOF_WIREFRAME_MONOCHROME
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.10.96	Tim Closs		Created
*	18.02.97	Tim Closs		Now handles MR_MOF_WIREFRAME_MONOCHROME
*	26.02.97	Tim Closs		Now supports the full new MR_PART structure!
*
*%%%**************************************************************************/

MR_MOF*	MRStaticCreateWireframeMOF(	MR_MOF*		smof,
									MR_USHORT	flags,
									MR_ULONG	colour)
{
	MR_PART*	part_ptr;
	MR_PART*	dpart_ptr;
	MR_USHORT	size, models, prims, i, j, type;
	MR_ULONG*	prim_ptr;
	MR_MOF*		dmof;
	MR_ULONG*	dprim_ptr;


	MR_ASSERT(smof);

	size 		= sizeof(MR_MOF);
	models		= smof->mm_extra;
	part_ptr	= (MR_PART*)(((MR_UBYTE*)smof) + sizeof(MR_MOF));

	while(models--)
		{
		size 		+= sizeof(MR_PART);
		prims		= part_ptr->mp_prims;
		prim_ptr	= part_ptr->mp_prim_ptr;

		while(prims)
			{
			type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
			i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
			prim_ptr++;
		
			switch(type)
				{
				case MR_MPRIMID_F3:
				case MR_MPRIMID_FT3:
				case MR_MPRIMID_G3:
				case MR_MPRIMID_GT3:
				case MR_MPRIMID_E3:
				case MR_MPRIMID_GE3:
					size += (i * sizeof(MR_MPRIM_HLF3)) + 4;
					break;
				
				case MR_MPRIMID_F4:
				case MR_MPRIMID_FT4:
				case MR_MPRIMID_G4:
				case MR_MPRIMID_GT4:
				case MR_MPRIMID_E4:
				case MR_MPRIMID_GE4:
					size += (i * sizeof(MR_MPRIM_HLF4)) + 4;
					break;
				}
			prims 	-= i;
			prim_ptr += (i * MRPrim_type_mod_sizes[type]);
			}
		part_ptr++;
		}

	// size is now the size in bytes of the MR_MOF, MR_PARTs, and the new primitive buffers (ie. the total size of the new MOF)
	dmof 		= MRAllocMem(size, "MR_MOF");	

	// Copy MR_MOF structure
	dmof->mm_id 	= smof->mm_id;
	dmof->mm_length	= size;
	dmof->mm_flags	= smof->mm_flags;
	dmof->mm_extra	= smof->mm_extra;

	models			= smof->mm_extra;
	part_ptr		= (MR_PART*)(((MR_UBYTE*)smof) + sizeof(MR_MOF));
	dpart_ptr		= (MR_PART*)(((MR_UBYTE*)dmof) + sizeof(MR_MOF));
	dprim_ptr		= (MR_ULONG*)(((MR_UBYTE*)dpart_ptr) + (models * sizeof(MR_PART)));

	while(models--)
		{
		// Copy MR_PART structure
		dpart_ptr->mp_flags			= part_ptr->mp_flags;
		dpart_ptr->mp_partcels		= part_ptr->mp_partcels;
		dpart_ptr->mp_verts			= part_ptr->mp_verts;
		dpart_ptr->mp_norms			= part_ptr->mp_norms;
		dpart_ptr->mp_prims			= part_ptr->mp_prims;
		dpart_ptr->mp_hilites		= part_ptr->mp_hilites;
		dpart_ptr->mp_partcel_ptr	= part_ptr->mp_partcel_ptr;
		dpart_ptr->mp_prim_ptr		= dprim_ptr;
		dpart_ptr->mp_hilite_ptr	= part_ptr->mp_hilite_ptr;
		dpart_ptr->mp_buff_size		= NULL;
		dpart_ptr->mp_collprim_ptr	= part_ptr->mp_collprim_ptr;
		dpart_ptr->mp_matrix_ptr	= part_ptr->mp_matrix_ptr;
		dpart_ptr->mp_pad0			= part_ptr->mp_pad0;
		dpart_ptr->mp_pad1			= part_ptr->mp_pad1;

		prims			= part_ptr->mp_prims;
		prim_ptr		= part_ptr->mp_prim_ptr;

		while(prims)
			{
			type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
			i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
			j		= i;
			prim_ptr++;
				
			switch(type)
				{
				case MR_MPRIMID_F3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_F3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_F3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_F3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_F3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_F3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_FT3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_FT3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_FT3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_FT3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_FT3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_FT3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_G3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_G3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_G3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_G3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_G3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_G3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_GT3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_GT3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_GT3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_GT3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_GT3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_GT3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;
				
				case MR_MPRIMID_E3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_E3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_E3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_E3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_E3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_E3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;
			
				case MR_MPRIMID_GE3:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF3;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p0 = ((MR_MPRIM_GE3*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p1 = ((MR_MPRIM_GE3*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF3*)dprim_ptr)->mp_p2 = ((MR_MPRIM_GE3*)prim_ptr)->mp_p2;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF3*)dprim_ptr)->mp_cvec, ((MR_MPRIM_GE3*)prim_ptr)->mp_cvec);
						((MR_MPRIM_GE3*)prim_ptr)++;
						((MR_MPRIM_HLF3*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_F4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_F4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_F4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_F4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_F4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_F4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_F4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_FT4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_FT4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_FT4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_FT4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_FT4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_FT4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_FT4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_G4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_G4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_G4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_G4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_G4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_G4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_G4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_GT4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_GT4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_GT4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_GT4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_GT4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_GT4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_GT4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_E4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_E4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_E4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_E4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_E4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_E4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_E4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				case MR_MPRIMID_GE4:
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_count	= i;
					((MR_MPRIM_HEADER*)dprim_ptr)->mm_type	= MR_MPRIMID_HLF4;
					dprim_ptr++;
					while(i--)
						{
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p0 = ((MR_MPRIM_GE4*)prim_ptr)->mp_p0;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p1 = ((MR_MPRIM_GE4*)prim_ptr)->mp_p1;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p2 = ((MR_MPRIM_GE4*)prim_ptr)->mp_p2;
						((MR_MPRIM_HLF4*)dprim_ptr)->mp_p3 = ((MR_MPRIM_GE4*)prim_ptr)->mp_p3;
						if (flags & MR_MOF_WIREFRAME_MONOCHROME)
							MR_SET32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, colour);
						else
							MR_COPY32(((MR_MPRIM_HLF4*)dprim_ptr)->mp_cvec, ((MR_MPRIM_GE4*)prim_ptr)->mp_cvec);
						((MR_MPRIM_GE4*)prim_ptr)++;
						((MR_MPRIM_HLF4*)dprim_ptr)++;
						}
					break;

				}
			prims -= j;
			}
		part_ptr++;
		dpart_ptr++;
		}

	// Resolve new MOF buffer sizes and prim codes
	dmof->mm_flags &= ~MR_MOF_SIZES_RESOLVED;
	MRStaticResolveMOF(dmof);

	dmof->mm_flags |= MR_MOF_WIREFRAME;
	dmof->mm_flags |= (flags & MR_MOF_WIREFRAME_MONOCHROME);
	return(dmof);
}


/******************************************************************************
*%%%% MRPartGetPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG*	prim =	MRPartGetPrim(
*									MR_MOF*		mof,
*									MR_USHORT	part,
*									MR_USHORT	index)
*
*	FUNCTION	Locate the nth primtive in a part of a static MOF
*
*	INPUTS		mof		-	ptr to static MOF file
*				part	-	index of part within MOF
*				index	-	index of primitive within part (n)
*
*	RESULT		prim	-	ptr to nth prim
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG*	MRPartGetPrim(	MR_MOF*		mof,
							MR_USHORT	part,
							MR_USHORT	index)
{
	MR_ULONG*	prim;
	MR_PART*	part_ptr;
	MR_USHORT	type, i;
	MR_LONG		n;


	MR_ASSERT(mof);
	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	MR_ASSERT(index < part_ptr->mp_prims);

	prim	= part_ptr->mp_prim_ptr;
	n 		= index;
	while(n >= 0)
		{
		type	= ((MR_MPRIM_HEADER*)prim)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim)->mm_count;
		prim++;
		if (i > n)
			{
			// Our prim is within this block
			prim	+= MRPrim_type_mod_sizes[type] * n;		// these sizes are in longwords
			return(prim);			
			}
		else
			{
			prim	+= MRPrim_type_mod_sizes[type] * i;		// these sizes are in longwords
			n 		-= i;
			}
		}

	// Failed to find primitive
	MR_ASSERT(NULL);
}


/******************************************************************************
*%%%% MRPartGetPrimOffset
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	offset =	MRPartGetPrimOffset(
*										MR_MOF*		mof,
*										MR_USHORT	part,
*										MR_USHORT	index)
*
*	FUNCTION	Calculate the poly buffer offset of the nth primtive in a part
*				of a static MOF
*
*	INPUTS		mof			-	ptr to static MOF file
*				part 		-	index of part within MOF
*				index		-	index of primitive within part (n)
*
*	RESULT		offset		-	offset of this prim's poly within poly buffer
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG	MRPartGetPrimOffset(	MR_MOF*		mof,
									MR_USHORT	part,
									MR_USHORT	index)
{
	MR_ULONG*	prim;
	MR_PART*	part_ptr;
	MR_LONG		type, i;
	MR_LONG		n, offset;


	MR_ASSERT(mof);
	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	MR_ASSERT(index < part_ptr->mp_prims);

	prim		= part_ptr->mp_prim_ptr;
	n 			= index;
	offset	=	0;
	while(n >= 0)
		{
		type	= ((MR_MPRIM_HEADER*)prim)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim)->mm_count;
		prim++;
		if (i > n)
			{
			// Our prim is within this block
			prim	+= MRPrim_type_mod_sizes[type] * n;		// these sizes are in longwords
			offset	+=	MRPrim_type_gpu_sizes[type] * n;	// these sizes are in bytes
			return(offset);			
			}
		else
			{
			prim	+= MRPrim_type_mod_sizes[type] * i;		// these sizes are in longwords
			offset	+=	MRPrim_type_gpu_sizes[type] * i;	// these sizes are in bytes
			n 		-= i;
			}
		}

	// Failed to find primitive
	MR_ASSERT(NULL);
}


/******************************************************************************
*%%%% MRPartGetPrimOffsetFromPointer
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	offset =	MRPartGetPrimOffsetFromPointer(
*										MR_MOF*		mof,
*										MR_USHORT	part,
*										MR_ULONG*	mprim)
*
*	FUNCTION	Calculate the poly buffer offset of the nth primtive in a part
*				of a static MOF - MR_MPRIM is specified as a ptr
*
*	INPUTS		mof			-	ptr to static MOF file
*				part 		-	index of part within MOF
*				mprim		-	ptr to MR_MPRIM
*
*	RESULT		offset		-	offset of this prim's poly within poly buffer
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG	MRPartGetPrimOffsetFromPointer(	MR_MOF*		mof,
											MR_USHORT	part,
											MR_ULONG*	mprim)
{
	MR_ULONG*	prim;
	MR_PART*	part_ptr;
	MR_ULONG	type, i;
	MR_LONG		polys, offset, d;


	MR_ASSERT(mof);
	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	prim	= part_ptr->mp_prim_ptr;
	polys	= part_ptr->mp_prims;
	offset	= 0;

	while(polys > 0)
		{
		type	= ((MR_MPRIM_HEADER*)prim)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim)->mm_count;
		prim++;

		if (mprim < (prim + (MRPrim_type_mod_sizes[type] * i)))
			{
			// Our prim is within this block
			d 		= (mprim - prim) / MRPrim_type_mod_sizes[type];
			offset	+= MRPrim_type_gpu_sizes[type] * d;
			return(offset);			
			}
		else
			{
			prim	+= MRPrim_type_mod_sizes[type] * i;		// these sizes are in longwords
			offset	+= MRPrim_type_gpu_sizes[type] * i;		// these sizes are in bytes
			}

		polys -= i;
		}

	// Failed to find primitive
	MR_ASSERT(NULL);
}


/******************************************************************************
*%%%% MRGetNumberOfHilites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	hilites =	MRGetNumberOfHilites(
*										MR_MOF*	mof,
*										MR_LONG	part)
*										MR_LONG	type)
*
*	FUNCTION	Return the number of hilites of specific type in a part of a MOF
*
*	INPUTS		mof 		-	ptr to static MOF file
*				part		-	index of part within file (or -ve for all parts)
*				type		-	type of hilite (or -ve for all types)
*
*	RESULT		hilites	-	number of hilites
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRGetNumberOfHilites(	MR_MOF*	mof,
									MR_LONG	part,
									MR_LONG	type)
{
	MR_PART*	part_ptr;
	MR_HILITE*	hilite_ptr;
	MR_USHORT	i, c, p;


	MR_ASSERT(mof);

	// Let p be number of parts to search
	if (part < 0)
		{
		part 	= 0;
		p		= mof->mm_extra;
		}
	else
		p		= 0;

	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	c = 0;
	while(p--)
		{
		if (type < 0)
			c += part_ptr->mp_hilites;
		else
			{
			// Count hilites of specified type
			hilite_ptr 	= part_ptr->mp_hilite_ptr;
			i			= part_ptr->mp_hilites;
			while(i--)
				{
				if (hilite_ptr->mh_type == type)
					c++;

				hilite_ptr++;
				}
			}
		part_ptr++;
		}

	return(c);
}


/******************************************************************************
*%%%% MRGetFirstHilite
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_HILITE*	hilite =	MRGetFirstHilite(
*			 						 	MR_MOF*	mof,
*			 						 	MR_LONG	part)
*			 						 	MR_LONG	type)
*
*	FUNCTION 	Return a pointer to the first of hilites of specific type in
*			 	a part of a MOF
*
*	INPUTS		mof 		-	ptr to static MOF file
*			 	part		-	index of part within file (or -ve for all parts)
*			 	type		-	type of hilite (or -ve for all types)
*
*	RESULT		hilite		-	ptr to first hilite (or NULL if none found)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97 	Tim Closs		Created
*
*%%%**************************************************************************/

MR_HILITE*	MRGetFirstHilite(	MR_MOF*	mof,
							 	MR_LONG	part,
								MR_LONG	type)
{
	MR_PART*	part_ptr;
	MR_HILITE*	hilite_ptr;
	MR_USHORT	i, p;


	MR_ASSERT(mof);

	// Let p be number of parts to search
	if (part < 0)
		{
		part 	= 0;
		p		= mof->mm_extra;
		}
	else
		p		= 0;

	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	while(p--)
		{
		if (type < 0)
			return(part_ptr->mp_hilite_ptr);
		else
			{
			// Find first hilite of specified type
			hilite_ptr 	= part_ptr->mp_hilite_ptr;
			i			= part_ptr->mp_hilites;
			while(i--)
				{
				if (hilite_ptr->mh_type == type)
					return(hilite_ptr);

				hilite_ptr++;
				}
			}
		part_ptr++;
		}

	return(NULL);
}


/******************************************************************************
*%%%% MRFillHiliteSVECArray
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	hilites =	MRFillHiliteSVECArray(
*								 		MR_MOF*		mof,
*								 		MR_LONG		part,
*								 		MR_LONG		type,
*								 		MR_SVEC*	array)
*
*	FUNCTION	Fill out an array of SVECs from MOF hilites
*
*	INPUTS		mof 		-	ptr to static MOF file
*				part		-	index of part within file (or -ve for all parts)
*				type		-	type of hilite (or -ve for all types)
*				array		-	ptr to array to fill
*
*	RESULT		hilites		-	number of hilites found (entries filled)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRFillHiliteSVECArray(	MR_MOF*		mof,
								 	MR_LONG		part,
								 	MR_LONG		type,
								 	MR_SVEC*	array)
{
	MR_PART*	part_ptr;
	MR_HILITE*	hilite_ptr;
	MR_USHORT	i, c, p;


	MR_ASSERT(mof);
	MR_ASSERT(array);

	// Let p be number of parts to search
	if (part < 0)
		{
		part 	= 0;
		p		= mof->mm_extra;
		}
	else
		p		= 0;
	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	c = 0;
	while(p--)
		{
		hilite_ptr 	= part_ptr->mp_hilite_ptr;
		i			= part_ptr->mp_hilites;
		while(i--)
			{
			if ((type < 0) || (hilite_ptr->mh_type == type))
				{
				MR_COPY_SVEC(array, (MR_SVEC*)hilite_ptr->mh_target_ptr);
				array++;
				c++;
				}
			hilite_ptr++;
			}
		part_ptr++;
		}

	return(c);
}


/******************************************************************************
*%%%% MRFillHiliteSVECPointerArray
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_USHORT	hilites =	MRFillHiliteSVECPointerArray(
*								 		MR_MOF*		mof,
*								 		MR_LONG		part)
*								 		MR_LONG		type)
*								 		MR_SVEC**	array)
*
*	FUNCTION	Fill out an array of SVEC pointers from MOF hilites
*
*	INPUTS		mof 		-	ptr to static MOF file
*				part		-	index of part within file (or -ve for all parts)
*				type		-	type of hilite (or -ve for all types)
*				array		-	ptr to array to fill
*
*	RESULT		hilites		-	number of hilites found (entries filled)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_USHORT	MRFillHiliteSVECPointerArray(	MR_MOF*		mof,
								 			MR_LONG		part,
								 			MR_LONG		type,
								 			MR_SVEC**	array)
{
	MR_PART*	part_ptr;
	MR_HILITE*	hilite_ptr;
	MR_USHORT	i, c, p;


	MR_ASSERT(mof);
	MR_ASSERT(array);

	// Let p be number of parts to search
	if (part < 0)
		{
		part 	= 0;
		p		= mof->mm_extra;
		}
	else
		p		= 0;

	MR_ASSERT(part < mof->mm_extra);

	part_ptr = ((MR_PART*)(mof + 1)) + part;

	c = 0;
	while(p--)
		{
		hilite_ptr 	= part_ptr->mp_hilite_ptr;
		i			= part_ptr->mp_hilites;
		while(i--)
			{
			if ((type < 0) || (hilite_ptr->mh_type == type))
				{
				*array = (MR_SVEC*)hilite_ptr->mh_target_ptr;
				array++;
				c++;
				}
			hilite_ptr++;
			}
		part_ptr++;
		}

	return(c);
}


/******************************************************************************
*%%%% MRCalculateMOFAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG polys =	MRCalculateMOFAnimatedPolys(
*									MR_MOF*	mof_ptr)
*
*	FUNCTION	Add up the total number of animated polys in all MR_PARTs
*
*	INPUTS		mof_ptr		-	ptr to mof
*
*	RESULT		polys		-	total animated polys
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_ULONG	MRCalculateMOFAnimatedPolys(MR_MOF*	mof_ptr)
{
	MR_PART*	part_ptr;
	MR_ULONG	p, i;


	MR_ASSERT(mof_ptr);

	// MOF is assumed to be static
	part_ptr 	= (MR_PART*)(mof_ptr + 1);
	p			= 0;

	// Run through each part
	i = mof_ptr->mm_extra;
	while(i--)
		{
		if (part_ptr->mp_flags & MR_PART_ANIMATED_POLYS)
			p += *(MR_ULONG*)(part_ptr->mp_pad0);

		part_ptr++;
		}

	return(p);
}

