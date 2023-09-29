/******************************************************************************
*%%%% mr_phlf3.c
*------------------------------------------------------------------------------
*
*	Polygon rendering routines (mesh based), for hidden line flat triangles
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	22.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

#include	"mr_all.h"


/******************************************************************************
*%%%% MRDisplayMeshPolys_HLF3
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDisplayMeshPolys_HLF3(
*						MR_SVEC*			vert_ptr,
*						MR_SVEC*			norm_ptr,
*						MR_ULONG*		prim_ptr,
*						MR_ULONG*		mem_ptrm
*						MR_MESH_PARAM*	param_ptr,
*						MR_BOOL			light_dpq);
*
*	FUNCTION	Performs high-speed geometry calculations for a block of
*				MR_MPRIM_HLF3 (flat shaded triangle) primitives.
*
*	INPUTS		vert_ptr	-	Pointer to vertex block
*				norm_ptr	-	Pointer to normal block
*				prim_ptr	-	Pointer to MR_MPRIM_HLF3 block
*				mem_ptr		-	Pointer to primitive buffer memory
*				param_ptr	-	Pointer to mesh parameter block
*				light_dpq	-	TRUE 	:	Lighting with depth queuing
*							 	FALSE	:	Lighting without depth queuing
*
*	NOTES		This routine is only called from MRDisplayMeshInstance(), which
*				is where the MR_MESH_PARAM block is set up.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDisplayMeshPolys_HLF3(MR_SVEC* 		vert_ptr,
								MR_SVEC* 		norm_ptr,
								MR_ULONG*		prim_ptr,
								MR_ULONG*		mem_ptr,
								MR_MESH_PARAM* 	param_ptr,
								MR_BOOL 		light_dpq)
{
	register	MR_ULONG*	work_ot		= param_ptr->p_work_ot;
	register	MR_LONG		otz_shift	= param_ptr->p_otz_shift;
	register	MR_LONG		ot_size		= param_ptr->p_ot_size;
	register	MR_LONG		ot_clip		= param_ptr->p_ot_clip;
	register	MR_LONG		prim_count;

	// Fetch number of primitives in this block
	prim_count = ((MR_MPRIM_HEADER*)(prim_ptr - 1))->mm_count;

	// Pre-fetch the first set of vertex pointers
	param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr)->mp_p0;
	param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr)->mp_p1;
	param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr)->mp_p2;

	// Process every polygon in turn
	while (prim_count--)
		{
		// Load first 3 vertices into the GTE 
		gte_ldv3(param_ptr->p_v0, param_ptr->p_v1, param_ptr->p_v2);

		// Rotate the first three points
		gte_rtpt();
		param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr+1)->mp_p0;	// Fetch next vertices
		param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr+1)->mp_p1;	// while in gte_rtpt()
		param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_HLF3*)prim_ptr+1)->mp_p2;	// delay slot
		
		// Normal clip first three points
		gte_nclip();
//		gte_ldrgb(&((MR_MPRIM_HLF3*)prim_ptr)->mp_cvec);						// Load RGB in delay slot
		gte_stopz(&(param_ptr->p_nclip_result));
		
		if ((param_ptr->p_nclip_result) <= 0)										// If first triangle is invisible
			goto next_poly;																// skip this primitive 

	//---------------
		gte_avsz3();
		gte_stotz(&param_ptr->p_poly_otz);

		param_ptr->p_poly_otz = (param_ptr->p_poly_otz >> otz_shift) + param_ptr->p_ot_otz_delta;

		if (
			(param_ptr->p_poly_otz >= ot_clip) &&
			(param_ptr->p_poly_otz < ot_size)
			)
			{
			gte_stsxy3_f3((POLY_F3*)(((MR_UBYTE*)mem_ptr) + sizeof(LINE_F4)));
			MR_COPY32(((LINE_F4*)(((MR_UBYTE*)mem_ptr)))->x0, ((POLY_F3*)(((MR_UBYTE*)mem_ptr) + sizeof(LINE_F4)))->x0);
			MR_COPY32(((LINE_F4*)(((MR_UBYTE*)mem_ptr)))->x1, ((POLY_F3*)(((MR_UBYTE*)mem_ptr) + sizeof(LINE_F4)))->x1);
			MR_COPY32(((LINE_F4*)(((MR_UBYTE*)mem_ptr)))->x2, ((POLY_F3*)(((MR_UBYTE*)mem_ptr) + sizeof(LINE_F4)))->x2);
			MR_COPY32(((LINE_F4*)(((MR_UBYTE*)mem_ptr)))->x3, ((POLY_F3*)(((MR_UBYTE*)mem_ptr) + sizeof(LINE_F4)))->x0);

			addPrim(work_ot + param_ptr->p_poly_otz, (LINE_F4*)mem_ptr);
			addPrim(work_ot + param_ptr->p_poly_otz, ((LINE_F4*)mem_ptr) + 1);

//			addPrims(work_ot + param_ptr->p_poly_otz,
//						(LINE_F4*)mem_ptr,
//						((LINE_F4*)mem_ptr) + 1);
			}

	//---------------
	next_poly:
			mem_ptr += (sizeof(LINE_F4) + sizeof(POLY_F3)) >> 2;
			((MR_MPRIM_HLF3*)prim_ptr)++;
			param_ptr->p_prims--;
		}
	
	// Place register based address arguments into param block for retrieval/setting by caller
	param_ptr->p_mem_ptr	= mem_ptr;
	param_ptr->p_prim_ptr	= prim_ptr;
}


