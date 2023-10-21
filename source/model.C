/******************************************************************************
*%%%% model.c
*------------------------------------------------------------------------------
*
*	Dummy models
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "model.h"
#include "project.h"
#include "gamesys.h"
#include "library.h"


#ifdef WIN95
#pragma warning (disable : 4245)
#endif

MR_MOF*			Model_MOF_ptrs[MODEL_MAX_MOFS];
POLY_PIECE*		Frog_model_pieces;
MR_MOF*			Frog_model_pieces_mof;
MR_LONG			Frog_model_pieces_polys;


#if 0
// Test MOF (FT4 cube)
MR_ULONG	Model_MOF_cube_ft4[] =
	{
	// MR_MOF
	NULL,					// 0
	(64 * 4) + (6 * sizeof(MR_MPRIM_FT4)),
	NULL,					// 2
	1,						// 3
	
	// MR_PART
	0 + (1 << 16),		// 4
	8 + (4 << 16),		// 5
	6 + (0 << 16),		// 6
	15 * 4,				// 7
	63 * 4,				// 8
	NULL,					// 9
	NULL,					// 10
	NULL,					// 11
	NULL,					// 12
	NULL,					// 13
	NULL,					// 14

	// MR_PARTCEL
	19 * 4,				// 15
	35 * 4,				// 16
	47 * 4,				// 17
	NULL,					// 18

	// vertex block
	0xff00ff00, 0x00000100,	// 19
	0xff000100, 0x00000100,	// 21		  	
	0xff000100, 0x0000ff00,	// 23
	0xff00ff00, 0x0000ff00,	// 25
	0x0000ff00, 0x00000100,	// 27
	0x00000100, 0x00000100,	// 29
	0x00000100, 0x0000ff00,	// 31
	0x0000ff00, 0x0000ff00,	// 33

	// normal block
	0x10000000, 0x00000000,	// 35
	0xf0000000, 0x00000000,	// 37
	0x00000000, 0x00001000,	// 39
	0x00000000, 0x0000f000,	// 41
	0x00001000, 0x00000000,	// 43
	0x0000f000, 0x00000000,	// 45

	// bounds block
	0xff00ff00, 0x00000100,	// 47
	0xff000100, 0x00000100,	// 49
	0xff000100, 0x0000ff00,	// 51
	0xff00ff00, 0x0000ff00,	// 53
	0x0000ff00, 0x00000100,	// 55
	0x00000100, 0x00000100,	// 57
	0x00000100, 0x0000ff00,	// 59
	0x0000ff00, 0x0000ff00,	// 61

	// prim block
	MR_MPRIMID_FT4 + (6 << 16),		// 63
	0 + (1 << 16),					// 64
	2 + (3 << 16),									
	0 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										

	5 + (4 << 16),									
	7 + (6 << 16),									
	1 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										

	3 + (2 << 16),									
	6 + (7 << 16),									
	2 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										

	1 + (0 << 16),									
	4 + (5 << 16),									
	3 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										

	0 + (3 << 16),									
	7 + (4 << 16),									
	4 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										

	2 + (1 << 16),									
	5 + (6 << 16),									
	5 + (MODEL_TEXTURE_INDEX << 16),									
	  0 + (  0 << 8) + ( 0 << 16),					
	255 + (  0 << 8) + ( 0 << 16),					
	255 + (255 << 8) + ( 0 << 16) + (255 << 24),	
	0x00808080,										
	};

// Test MOF (E4 cube)
MR_ULONG	Model_MOF_cube_e4[] =
	{
	// MR_MOF
	NULL,					// 0
	(80 * 4) + (6 * sizeof(MR_MPRIM_E4)),
	NULL,					// 2
	1,						// 3
	
	// MR_PART
	0 + ( 1 << 16),	// 4
	8 + (12 << 16),	// 5
	6 + ( 0 << 16),	// 6
	15 * 4,				// 7
	79 * 4,				// 8
	NULL,					// 9
	NULL,					// 10
	NULL,					// 11
	NULL,					// 12
	NULL,					// 13
	NULL,					// 14

	// MR_PARTCEL
	19 * 4,				// 15
	35 * 4,				// 16
	63 * 4,				// 17
	NULL,					// 18

	// vertex block
	0xff00ff00, 0x00000100,	// 19
	0xff000100, 0x00000100,	//	21		  	
	0xff000100, 0x0000ff00,	//	23
	0xff00ff00, 0x0000ff00,	// 25
	0x0000ff00, 0x00000100,	// 27
	0x00000100, 0x00000100,	// 29
	0x00000100, 0x0000ff00,	// 31
	0x0000ff00, 0x0000ff00,	// 33

	// normal block
	0x093c093c, 0x0000f6c4,	// 35
	0x093cf6c4, 0x0000f6c4,	// 37
	0x093cf6c4, 0x0000093c,	// 39
	0x093c093c, 0x0000093c,	// 41
	0xf6c4093c, 0x0000f6c4,	// 43
	0xf6c4f6c4, 0x0000f6c4,	// 45
	0xf6c4f6c4, 0x0000093c,	// 47
	0xf6c4093c, 0x0000093c,	// 49

	0x10000000, 0x00000000,	// 51
	0xf0000000, 0x00000000,	// 53
	0x00000000, 0x00001000,	// 55
	0x00000000, 0x0000f000,	// 57
	0x00001000, 0x00000000,	// 59
	0x0000f000, 0x00000000,	// 61

	// bounds block
	0xff00ff00, 0x00000100,	// 63
	0xff000100, 0x00000100,	// 65
	0xff000100, 0x0000ff00,	// 67
	0xff00ff00, 0x0000ff00,	// 69
	0x0000ff00, 0x00000100,	// 71
	0x00000100, 0x00000100,	// 73
	0x00000100, 0x0000ff00,	// 75
	0x0000ff00, 0x0000ff00,	// 77

	// prim block
	MR_MPRIMID_E4 + (6 << 16),				// 79

	0 + (1 << 16),								// 80
	2 + (3 << 16),									
	0 + (1 << 16),								
	2 + (3 << 16),									
	8,
	0x00808080,										

	5 + (4 << 16),									
	7 + (6 << 16),									
	5 + (4 << 16),									
	7 + (6 << 16),									
	9,
	0x00808080,										

	3 + (2 << 16),									
	6 + (7 << 16),									
	3 + (2 << 16),									
	6 + (7 << 16),									
	10,
	0x00808080,										

	1 + (0 << 16),									
	4 + (5 << 16),									
	1 + (0 << 16),									
	4 + (5 << 16),									
	11,
	0x00808080,										

	0 + (3 << 16),									
	7 + (4 << 16),									
	0 + (3 << 16),									
	7 + (4 << 16),									
	12,
	0x00808080,										

	2 + (1 << 16),									
	5 + (6 << 16),									
	2 + (1 << 16),									
	5 + (6 << 16),									
	13,
	0x00808080,										
	};
#endif

#ifdef WIN95
#pragma warning (default : 4245)
#endif


/******************************************************************************
*%%%% InitialiseModels
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseModels(
*						MR_LONG	mode)
*
*	FUNCTION	Fix up models, strip out hilites, etc.  Called once after
*				the resource is loaded
*
*	INPUTS		mode	-	0 for GEN, 1 for GENM
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*	01.07.97	Tim Closs		Changed to accept mode input
*
*%%%**************************************************************************/

MR_VOID	InitialiseModels(MR_LONG mode)
{
	MR_ANIM_HEADER*	anim0;
	MR_ANIM_HEADER*	anim1;
	MR_LONG			i, p;
	MR_MOF*			mof_ptr;
	MR_PART*		part_ptr;
	MR_PART*		part_ptr2;


#if 0
	// Resolve dummy MOFs
	MRResolveMOF((MR_MOF*)Model_MOF_cube_ft4);
	MRResolveMOFTextures((MR_MOF*)Model_MOF_cube_ft4);
	MRScaleMOF((MR_MOF*)Model_MOF_cube_ft4, 0x0600);

	MRResolveMOF((MR_MOF*)Model_MOF_cube_e4);
	MRScaleMOF((MR_MOF*)Model_MOF_cube_e4, 0x0600);

	// Set up MOF ptrs
	Model_MOF_ptrs[MODEL_MOF_CUBE_FT4]	= (MR_MOF*)Model_MOF_cube_ft4;
	Model_MOF_ptrs[MODEL_MOF_CUBE_E4]	= (MR_MOF*)Model_MOF_cube_e4;
#endif

	if (mode == 0)
		{
		Model_MOF_ptrs[MODEL_MOF_FROG_ANIMATIONS]	= MR_GET_RESOURCE_ADDR(RES_GEN_FROG_XAR);
		Model_MOF_ptrs[MODEL_MOF_FROG_STATIC_0]		= NULL;
	
		// For each frog model, construct a new MR_ANIM_HEADER, which contains a pointer to the correct XMR MOF
		anim1 = (MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_ANIMATIONS];
		Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0] = (MR_MOF*)anim1;

		// High poly frogs for players 1,2,3 are only needed if options resource is loaded
		if (MR_GET_RESOURCE_ADDR(RES_OPTIONS_WAD))
			{
			Model_MOF_ptrs[MODEL_MOF_FROG_STATIC_1]	= MR_GET_RESOURCE_ADDR(RES_GEN_FROG2_XMR);
			Model_MOF_ptrs[MODEL_MOF_FROG_STATIC_2]	= MR_GET_RESOURCE_ADDR(RES_GEN_FROG3_XMR);
			Model_MOF_ptrs[MODEL_MOF_FROG_STATIC_3]	= MR_GET_RESOURCE_ADDR(RES_GEN_FROG4_XMR);	  	

			for (i = 1; i < 4; i++)
				{
				Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + i] = MRAllocMem(sizeof(MR_ANIM_HEADER) + sizeof(MR_MOF*), "FROG ANIM HEADER CONSTRUCTION");
				anim0 							= (MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + i];
				anim0->ah_id 					= anim1->ah_id;
				anim0->ah_length				= anim1->ah_length;
				anim0->ah_flags 				= anim1->ah_flags;
				anim0->ah_no_of_model_sets		= anim1->ah_no_of_model_sets;
				anim0->ah_no_of_static_files	= 1;
				anim0->ah_model_sets			= anim1->ah_model_sets;
				anim0->ah_common_data			= anim1->ah_common_data;
				anim0->ah_static_files			= (MR_MOF**)(anim0 + 1);
				anim0->ah_static_files[0]		= Model_MOF_ptrs[MODEL_MOF_FROG_STATIC_0 + i];
				}
			}
		else
			{
			Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_1] = NULL;
			Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_2] = NULL;
			Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_3] = NULL;
			}

		// Resolve flipbook checkpoint MOFs
		Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_0]	= MR_GET_RESOURCE_ADDR(RES_GEN_CHECKPOINT_1_XMR);
		Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_1]	= MR_GET_RESOURCE_ADDR(RES_GEN_CHECKPOINT_2_XMR);
		Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_2]	= MR_GET_RESOURCE_ADDR(RES_GEN_CHECKPOINT_3_XMR);
		Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_3]	= MR_GET_RESOURCE_ADDR(RES_GEN_CHECKPOINT_4_XMR);
		Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_4]	= MR_GET_RESOURCE_ADDR(RES_GEN_CHECKPOINT_5_XMR);

		for (i = 1; i < 5; i++)
			{
			mof_ptr 	= Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_0];
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			part_ptr2	= (MR_PART*)(((MR_UBYTE*)part_ptr) + ((MR_UBYTE*)Model_MOF_ptrs[MODEL_MOF_CHECKPOINT_FLIPBOOK_0 + i] - (MR_UBYTE*)mof_ptr));
			p			= mof_ptr->mm_extra;

			while(p--)
				{
				part_ptr2->mp_partcel_ptr	= part_ptr->mp_partcel_ptr;
				part_ptr2->mp_hilite_ptr 	= part_ptr->mp_hilite_ptr;
				part_ptr2->mp_collprim_ptr 	= part_ptr->mp_collprim_ptr;
				part_ptr2->mp_matrix_ptr 	= part_ptr->mp_matrix_ptr;
				part_ptr2->mp_pad0			= part_ptr->mp_pad0;
				part_ptr2->mp_pad1			= part_ptr->mp_pad1;
				part_ptr++;
				part_ptr2++;
				}
			}
		}
	else
		{
		// Resolve flipbook frog MOFs
		Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0]	= MR_GET_RESOURCE_ADDR(RES_GENM_FROG_XMR);
		Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_1]	= MR_GET_RESOURCE_ADDR(RES_GENM_FROG2_XMR);
		Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_2]	= MR_GET_RESOURCE_ADDR(RES_GENM_FROG3_XMR);
		Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_3]	= MR_GET_RESOURCE_ADDR(RES_GENM_FROG4_XMR);

		for (i = 1; i < 4; i++)
			{
			mof_ptr 	= Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0];
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			part_ptr2	= (MR_PART*)(((MR_UBYTE*)part_ptr) + ((MR_UBYTE*)Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0 + i] - (MR_UBYTE*)mof_ptr));
			p			= mof_ptr->mm_extra;

			while(p--)
				{
				part_ptr2->mp_partcel_ptr	= part_ptr->mp_partcel_ptr;
				part_ptr2->mp_hilite_ptr 	= part_ptr->mp_hilite_ptr;
				part_ptr2->mp_collprim_ptr 	= part_ptr->mp_collprim_ptr;
				part_ptr2->mp_matrix_ptr 	= part_ptr->mp_matrix_ptr;
				part_ptr2->mp_pad0			= part_ptr->mp_pad0;
				part_ptr2->mp_pad1			= part_ptr->mp_pad1;
				part_ptr++;
				part_ptr2++;
				}
			}

		// Resolve flipbook multiplayer checkpoint MOFs
		Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_0]	= MR_GET_RESOURCE_ADDR(RES_GENM_MULTIPOINT_1_XMR);
		Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_1]	= MR_GET_RESOURCE_ADDR(RES_GENM_MULTIPOINT_2_XMR);
		Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_2]	= MR_GET_RESOURCE_ADDR(RES_GENM_MULTIPOINT_3_XMR);
		Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_3]	= MR_GET_RESOURCE_ADDR(RES_GENM_MULTIPOINT_4_XMR);
		Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_4]	= MR_GET_RESOURCE_ADDR(RES_GENM_MULTIPOINT_5_XMR);

		for (i = 1; i < 5; i++)
			{
			mof_ptr 	= Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_0];
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			part_ptr2	= (MR_PART*)(((MR_UBYTE*)part_ptr) + ((MR_UBYTE*)Model_MOF_ptrs[MODEL_MOF_MULTIPOINT_FLIPBOOK_0 + i] - (MR_UBYTE*)mof_ptr));
			p			= mof_ptr->mm_extra;

			while(p--)
				{
				part_ptr2->mp_partcel_ptr	= part_ptr->mp_partcel_ptr;
				part_ptr2->mp_hilite_ptr 	= part_ptr->mp_hilite_ptr;
				part_ptr2->mp_collprim_ptr 	= part_ptr->mp_collprim_ptr;
				part_ptr2->mp_matrix_ptr 	= part_ptr->mp_matrix_ptr;
				part_ptr2->mp_pad0			= part_ptr->mp_pad0;
				part_ptr2->mp_pad1			= part_ptr->mp_pad1;
				part_ptr++;
				part_ptr2++;
				}
			}

		// Set up exploding mesh stuff
		Frog_model_pieces 		= CreateMeshPolyPieces(Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0]);
		Frog_model_pieces_mof 	= Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0];
		Frog_model_pieces_polys = ((MR_PART*)(Model_MOF_ptrs[MODEL_MOF_FROG_FLIPBOOK_0] + 1))->mp_prims;
		}
}


/******************************************************************************
*%%%% DeinitialiseModels
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeinitialiseModels(
*						MR_LONG	mode)
*
*	FUNCTION	Free allocated memory
*
*	INPUTS		mode	-	0 for GEN, 1 for GENM
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Tim Closs		Created
*	01.07.97	Tim Closs		Changed to accept mode input
*
*%%%**************************************************************************/

MR_VOID	DeinitialiseModels(MR_LONG mode)
{
	MR_ULONG		i;

	if (mode == 0)
		{
		// Free allocated MR_ANIM_HEADERs
		for (i = 1; i < 4; i++)
			{
			if (Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + i])
				{
				MRFreeMem(Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + i]);
				Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + i] = NULL;
				}
			}
		}
	else
		{
		// Free allocated POLY_PIECEs
		MRFreeMem(Frog_model_pieces);
		}
}


/******************************************************************************
*%%%% LoadGenericWad
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LoadGenericWad(
*						MR_LONG	mode)
*
*	FUNCTION	Load and process gen/genm wad
*
*	INPUTS		mode	-	0 for GEN, 1 for GENM
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	LoadGenericWad(MR_LONG	mode)
{
	Map_mof_index = PROJECT_MAX_THEME_MOFS;

	if (mode)
		{
		// GENM
		if (Game_flags & GAME_FLAG_GEN_WAD_LOADED)
			{
			MRUnloadResource(Theme_library[THEME_GEN].tb_full_model_wad_res_id);
			DeinitialiseModels(0);
			Game_flags &= ~GAME_FLAG_GEN_WAD_LOADED;
			}
		if (!(Game_flags & GAME_FLAG_GENM_WAD_LOADED))
			{
			MRLoadResource(Theme_library[THEME_GEN].tb_multi_model_wad_res_id);
			MRProcessResource(Theme_library[THEME_GEN].tb_multi_model_wad_res_id);
			InitialiseModels(1);
			Game_flags |= GAME_FLAG_GENM_WAD_LOADED;
			}
		}
	else
		{
		// GEN
		if (Game_flags & GAME_FLAG_GENM_WAD_LOADED)
			{
			MRUnloadResource(Theme_library[THEME_GEN].tb_multi_model_wad_res_id);
#ifdef EXPERIMENTAL
			DeinitialiseModels(1);
#else
			MRFreeMem(Frog_model_pieces);
#endif
			Game_flags &= ~GAME_FLAG_GENM_WAD_LOADED;
			}
		if (!(Game_flags & GAME_FLAG_GEN_WAD_LOADED))
			{
			MRLoadResource(Theme_library[THEME_GEN].tb_full_model_wad_res_id);
			MRProcessResource(Theme_library[THEME_GEN].tb_full_model_wad_res_id);	
#ifdef BUILD_49
			InitialiseModels(0);
			Game_flags |= GAME_FLAG_GEN_WAD_LOADED;
#endif
			}

#ifndef BUILD_49
		// Need to do this every time, because the player 1,2,3 frogs are in options wad, which may have been reloaded
		// to a different place
		DeinitialiseModels(0);
		InitialiseModels(0);
		Game_flags |= GAME_FLAG_GEN_WAD_LOADED;
#endif
		}
}
