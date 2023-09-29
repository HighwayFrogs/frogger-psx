/******************************************************************************
*%%%% mr_misc.c
*------------------------------------------------------------------------------
*
*	Initialisation routines for API usage, some of the more esoteric light
*	handling, and other general routines. It also declares common data, such as
*	general vectors, svectors and colour vectors
*
*	The lighting routines should be moved to mr_light.c as soon as possible.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	14.05.96	Dean Ashton		Created
*	28.05.96	Dean Ashton		Added default handling for ambient lights
*	21.06.96	Dean Ashton		Added multiple initialisation check
*	25.06.96	Tim Closs		Fixed bug in MRUpdateMeshInstanceLightMatrix,
*								MRUpdate3DSpriteInstanceLightMatrix
*	22.07.96	Dean Ashton		Changed to fully clear VRAM in MRInitialise()
*	02.09.96	Tim Closs		Created MRGenerateMatrixFromZAxisAndZYPlane
*	13.09.96	Dean Ashton		Added new list initialisation to MRInitialise()
*	25.09.96	Tim Closs		MRInitialise now resets new collision variables
*								MRColl_lw_ptr and MRColl_matrix_ptr
*	15.10.96	Tim Closs		MRInitialise sets up animation stuff
*	13.02.97	Dean Ashton		MRInitialise clears MRVp_ptr (used by debug code)
*	04.04.97	Dean Ashton		Moved MRGenerateYXMatrixFromZColumn and 
*								MRGenerateMatrixFromZAxisAndZYPlane to mr_math.c
*
*%%%**************************************************************************/


#include "mr_all.h"

MR_MAT			MRScale_matrix;
MR_MAT			MRRot_matrix_X;
MR_MAT			MRRot_matrix_Y;
MR_MAT			MRRot_matrix_Z;
MR_MAT			MRId_matrix;

MR_CVEC			MRCvec_ft3 = {0x80, 0x80, 0x80, 0x24};
MR_CVEC			MRCvec_ft4 = {0x80, 0x80, 0x80, 0x2c};
MR_CVEC			MRCvec_gt3 = {0x80, 0x80, 0x80, 0x34};
MR_CVEC			MRCvec_gt4 = {0x80, 0x80, 0x80, 0x3c};

MR_VEC			MRNull_vec 	= {0,0,0};
MR_SVEC			MRNull_svec	= {0,0,0};

MR_BOOL			MRInitialise_called = FALSE;


/******************************************************************************
*%%%% MRInitialise
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialise(MR_VOID);
*
*	FUNCTION	General initialisation code.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.96	Tim Closs		Created
*	21.06.96	Dean Ashton		Added multiple initialisation check
*	22.07.96	Dean Ashton		Changed to fully clear VRAM on debug builds
*	13.09.96	Dean Ashton		Added initialise of OT table
*	25.09.96	Tim Closs		Now resets new collision variables MRColl_lw_ptr
*								and MRColl_matrix_ptr
*	13.02.97	Dean Ashton		Clears MRVp_ptr..
*
*%%%**************************************************************************/

MR_VOID	MRInitialise(MR_VOID)
{
#ifdef	MR_DEBUG
	MR_RECT	vram_rect;
#endif

	// We'll stop double initialise calls
	MR_ASSERTMSG((MRInitialise_called == FALSE), "MRInitialise already called");

	// Print a revision header
	MRPrintf("\n%s\n\n", MR_API_VERSION);

	MRInitialise_called = TRUE;

	//	Do stuff for frame table
	MRFrame_root_ptr = &MRFrame_root;
	MRFrame_root_ptr->fr_next_node = NULL;
	MRFrame_root_ptr->fr_prev_node = NULL;
	MRNumber_of_frames = 0;

	//	Do stuff for object table
	MRObject_root_ptr = &MRObject_root;
	MRObject_root_ptr->ob_next_node = NULL;
	MRObject_root_ptr->ob_prev_node = NULL;
	MRNumber_of_objects = 0;

	//	Do stuff for OT table
	MROT_root_ptr = &MROT_root;
	MROT_root_ptr->ot_next_node = NULL;
	MROT_root_ptr->ot_prev_node = NULL;
	MRNumber_of_OTs = 0;

	//	Do stuff for viewport table
	MRViewport_root_ptr = &MRViewport_root;
	MRViewport_root_ptr->vp_next_node = NULL;
	MRViewport_root_ptr->vp_prev_node = NULL;
	MRNumber_of_viewports = 0;

	//	Do stuff for animation environment table
	MRAnim_env_root_ptr = &MRAnim_env_root;
	MRAnim_env_root_ptr->ae_next_node = NULL;
	MRAnim_env_root_ptr->ae_prev_node = NULL;
	MRNumber_of_anim_envs 	= 0;
	MRAnim_event_list 		= NULL;

	// Initialise MRScale_matrix (non-diag entries are never touched)
	MR_INIT_MAT(&MRScale_matrix);
	MR_CLEAR_VEC(MRScale_matrix.t);

	// Initialise MRRot matrices
	MR_INIT_MAT(&MRRot_matrix_X);
	MR_INIT_MAT(&MRRot_matrix_Y);
	MR_INIT_MAT(&MRRot_matrix_Z);
	MR_INIT_MAT(&MRId_matrix);
	MR_CLEAR_VEC(MRId_matrix.t);

	// Initialise (fastram) viewtrans ptr and other stuff
	MRDefault_vp 			= NULL;
	MRDefault_vp_ot		= NULL;

	MRVp_ptr					= NULL;

	MRViewtrans_ptr		= &MRViewtrans;
	MRWorldtrans_ptr		= NULL;
	MRLight_matrix_ptr 	= &MRLight_matrix;
	MRColl_lw_ptr 			= NULL;
	MRColl_matrix_ptr 	= NULL;

	MREnv_strip				= NULL;

#ifdef MR_MEMFIXED_3DSPRITE
	MRMemfixed_3dsprite		= NULL;
#endif
#ifdef MR_MEMFIXED_PGEN
	MRMemfixed_pgen			= NULL;
#endif
#ifdef MR_MEMFIXED_STATIC_MESH
	MRMemfixed_static_mesh	= NULL;
#endif
#ifdef MR_MEMFIXED_FRAME
	MRMemfixed_frame			= NULL;
#endif

#ifdef	MR_DEBUG
	setRECT(&vram_rect, 0, 0, 1024, 512);
	ClearImage(&vram_rect, 0x60, 0x60, 0x30);
	DrawSync(0);
	setRECT(&vram_rect, 992, 0, 32, 512);
	ClearImage(&vram_rect, 0x60, 0x60, 0x30);
	DrawSync(0);
	setRECT(&vram_rect, 0, 511, 1024, 1);
	ClearImage(&vram_rect, 0x60, 0x60, 0x30);
	DrawSync(0);	
#endif	

	// Now we set the GTE C2_ZSF3 and C2_ZSF4 registers so that
	// AVSZ3 and AVSZ4 (and also the LIBGTE AverageZ3/AverageZ4 routines)
	// return the _real_ average. Not a quarter of it (which is the
	// default behaviour). This means our MRVp_otz_shift is valid for all
	// GTE 'Z' values

	__asm__ volatile ( "ctc2 %0, $29" : : "r" (4096/3));
	__asm__ volatile ( "ctc2 %0, $30" : : "r" (4096/4));

}


