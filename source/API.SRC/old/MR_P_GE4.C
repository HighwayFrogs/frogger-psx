/******************************************************************************
*%%%% mr_p_ge4.c
*------------------------------------------------------------------------------
*
*	Polygon rendering routines (mesh based), for gouraud/environment mapped quads
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/


#include	"mr_all.h"


/******************************************************************************
*%%%% MRDisplayMeshPolys_GE4
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDisplayMeshPolys_GE4(
*						MR_SVEC*		vert_ptr,
*						MR_SVEC*		norm_ptr,
*						MR_ULONG*		prim_ptr,
*						MR_ULONG*		mem_ptrm
*						MR_MESH_PARAM*	param_ptr,
*						MR_BOOL			light_dpq);
*
*	FUNCTION	Performs high-speed geometry calculations for a block of
*				MR_MPRIM_GE4 (gouraud/environment mapped quad) primitives.
*
*	INPUTS		vert_ptr	-	Pointer to vertex block
*				norm_ptr	-	Pointer to normal block
*				prim_ptr	-	Pointer to MR_MPRIM_GE4 block
*				mem_ptr		-	Pointer to primitive buffer memory
*				param_ptr	-	Pointer to mesh parameter block
*				light_dpq	-	TRUE 	:	Lighting with depth queuing
*								FALSE	:	Lighting without depth queuing
*
*	NOTES		This routine is only called from MRDisplayMeshInstance(), which
*				is where the MR_MESH_PARAM block is set up.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRDisplayMeshPolys_GE4(	MR_SVEC* 	  	vert_ptr,
								MR_SVEC* 	  	norm_ptr,
							 	MR_ULONG*	  	prim_ptr,
							 	MR_ULONG*	  	mem_ptr,
							 	MR_MESH_PARAM*	param_ptr,
							 	MR_BOOL 		light_dpq)
{
	register	MR_ULONG*	work_ot		= param_ptr->p_work_ot;
	register	MR_LONG		otz_shift	= param_ptr->p_otz_shift;
	register	MR_LONG		ot_size		= param_ptr->p_ot_size;
	register	MR_LONG		ot_clip		= param_ptr->p_ot_clip;
	register	MR_LONG		disp_h		= MRVp_disp_h;
	register	MR_LONG		prim_count;

	MR_VEC		work_vector;
	MR_SHORT	uofs, vofs;

	// We need an environment map defined
	MR_ASSERT(MREnv_strip);

	// Fetch number of primitives in this block
	prim_count = ((MR_MPRIM_HEADER*)(prim_ptr - 1))->mm_count;

	// Precalculate uofs/vofs
	uofs = 64 + MREnv_strip->te_u0;
	vofs = 64 + MREnv_strip->te_v0;

	// Pre-fetch the first set of vertex pointers
	param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_p0;
	param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_p1;
	param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_p2;
	param_ptr->p_v3 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_p3;

	// Process every polygon in turn
	while (prim_count--)
		{
		// Load first 3 vertices into the GTE 
		gte_ldv3(param_ptr->p_v0, param_ptr->p_v1, param_ptr->p_v3);

		// Rotate the first three points
		gte_rtpt();
		param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr+1)->mp_p0;	// Fetch next vertices
		param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr+1)->mp_p1;	// while in gte_rtpt()
		param_ptr->p_v3 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr+1)->mp_p3;	// delay slot
		
		// Normal clip first three points
		gte_nclip();
		gte_ldv0(param_ptr->p_v2);													// Load 4th vertex in delay slot
		gte_stopz(&(param_ptr->p_nclip_result));

		// Store the screen XY coordinates for vertex 0 (as they will be pushed out of FIFO by vertex 4)
		gte_stsxy0((MR_LONG*)&((POLY_GT4*)mem_ptr)->x0);

		// Rotate the fourth point (and perform operations in delay slot)
		gte_rtps();
		gte_ldrgb(&((MR_MPRIM_GE4*)prim_ptr)->mp_cvec);						// Load poly-variable RGB in delay slot
		param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_GE4*)prim_ptr+1)->mp_p2;	// Fetch next vertex in delay slot
		if ((param_ptr->p_nclip_result) > 0)								// If first triangle is visible
			goto visible_poly;												// we don't need second nclip 

		// If the first triangle is clipped, we normal clip the second one. If both invisible, we ignore polygon
		// Note that the condition of nclip is reversed, as the points are in the FIFO in reverse order
		gte_nclip();
		gte_stopz(&(param_ptr->p_nclip_result));
		if ((param_ptr->p_nclip_result) >= 0)
			goto next_poly;	

	//---------------
	visible_poly:
		gte_avsz4();
		gte_stotz(&param_ptr->p_poly_otz);

		param_ptr->p_poly_otz = (param_ptr->p_poly_otz >> otz_shift) + param_ptr->p_ot_otz_delta;

		if (
			(param_ptr->p_poly_otz >= ot_clip) &&
			(param_ptr->p_poly_otz < ot_size)
			)
			{
			gte_stsxy3(	(MR_LONG*)&((POLY_GT4*)mem_ptr)->x1,
							(MR_LONG*)&((POLY_GT4*)mem_ptr)->x2,
							(MR_LONG*)&((POLY_GT4*)mem_ptr)->x3);
	
			if (
				(((((POLY_GT4*)mem_ptr)->y0 >= 0) ||
				  (((POLY_GT4*)mem_ptr)->y1 >= 0) ||
				  (((POLY_GT4*)mem_ptr)->y2 >= 0) ||
				  (((POLY_GT4*)mem_ptr)->y3 >= 0)) &&
				 ((((POLY_GT4*)mem_ptr)->y0 < disp_h) ||
				  (((POLY_GT4*)mem_ptr)->y1 < disp_h) ||
				  (((POLY_GT4*)mem_ptr)->y2 < disp_h) ||
				  (((POLY_GT4*)mem_ptr)->y3 < disp_h)))
				)
				{
				gte_SetRotMatrix(MRWorldtrans_ptr);

// --- This is what the code really does ---
//
//				gte_ApplyRotMatrix(norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en0), &work_vector);
//				MR_SET16(((POLY_GT4*)mem_ptr)->u0, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
//
//				gte_ApplyRotMatrix(norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en1), &work_vector);
//				MR_SET16(((POLY_GT4*)mem_ptr)->u1, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
//
//				gte_ApplyRotMatrix(norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en2), &work_vector);
//				MR_SET16(((POLY_GT4*)mem_ptr)->u3, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
//
//				gte_ApplyRotMatrix(norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en3), &work_vector);
//				MR_SET16(((POLY_GT4*)mem_ptr)->u2, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
//
// --- End of code

				param_ptr->p_n0 = norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en0);	// Calc en0 address
				gte_ldv0(param_ptr->p_n0);										 	// Load into V0(GTE)
				gte_rtv0();														 	// Rotate en0
				param_ptr->p_n0 = norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en1);	// Precalc en1 address (delay slot)
				gte_stlvnl(&work_vector);										 	// Store output

				gte_ldv0(param_ptr->p_n0);															
				gte_rtv0();																				// Rotate en1
				MR_SET16(((POLY_GT4*)mem_ptr)->u0, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
				param_ptr->p_n0 = norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en2);
				gte_stlvnl(&work_vector);

				gte_ldv0(param_ptr->p_n0);
				gte_rtv0();					 															// Rotate en2
				MR_SET16(((POLY_GT4*)mem_ptr)->u1, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
				param_ptr->p_n0 = norm_ptr + (((MR_MPRIM_GE4*)prim_ptr)->mp_en3);
				gte_stlvnl(&work_vector);				

				gte_ldv0(param_ptr->p_n0);
				gte_rtv0();											 									// Rotate en3
				MR_SET16(((POLY_GT4*)mem_ptr)->u3, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));
				gte_stlvnl(&work_vector);				
				MR_SET16(((POLY_GT4*)mem_ptr)->u2, (work_vector.vx >> 6) + uofs + (((-work_vector.vy >> 6) + vofs) << 8));

				gte_SetRotMatrix(MRViewtrans_ptr);

				gte_ldv3((norm_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_n0),
							(norm_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_n1),
							(norm_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_n3));
	
				if (light_dpq)
					{
					gte_ncdt();
					addPrim(work_ot + param_ptr->p_poly_otz, mem_ptr);
					gte_ldv0(norm_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_n2);
					gte_strgb3_gt4((POLY_GT4*)mem_ptr);
					gte_ncds();
					}
				else
					{
					gte_ncct();
					addPrim(work_ot + param_ptr->p_poly_otz, mem_ptr);
					gte_ldv0(norm_ptr + ((MR_MPRIM_GE4*)prim_ptr)->mp_n2);
					gte_strgb3_gt4((POLY_GT4*)mem_ptr);
					gte_nccs();
					}
	
				gte_strgb((MR_CVEC*)&((POLY_GT4*)mem_ptr)->r3);
				}
			}

	//---------------
	next_poly:
			((POLY_GT4*)mem_ptr)++;
			((MR_MPRIM_GE4*)prim_ptr)++;
			param_ptr->p_prims--;
		}
	
	// Place register based address arguments into param block for retrieval/setting by caller
	param_ptr->p_mem_ptr	= mem_ptr;
	param_ptr->p_prim_ptr	= prim_ptr;

}

