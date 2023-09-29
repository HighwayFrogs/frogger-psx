/******************************************************************************
*%%%% mr_s_gt3.c
*------------------------------------------------------------------------------
*
*	Polygon rendering routines (mesh based), for gouraud textured triangles
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	26.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/


#include	"mr_all.h"


/******************************************************************************
*%%%% MRSpecialDisplayMeshPolys_GT3
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSpecialDisplayMeshPolys_GT3(
*						MR_SVEC*		vert_ptr,
*						MR_SVEC*		norm_ptr,
*						MR_ULONG*		prim_ptr,
*						MR_ULONG*		mem_ptrm
*						MR_MESH_PARAM*	param_ptr,
*						MR_BOOL			light_dpq,
*						MR_ULONG		flags);
*
*	FUNCTION	Performs high-speed geometry calculations for a block of
*				MR_MPRIM_GT3 (gouraud textured triangles) primitives.
*
*	INPUTS		vert_ptr	-	Pointer to vertex block
*				norm_ptr	-	Pointer to normal block
*				prim_ptr	-	Pointer to MR_MPRIM_GT3 block
*				mem_ptr		-	Pointer to primitive buffer memory
*				param_ptr	-	Pointer to mesh parameter block
*				light_dpq	-	TRUE 	:	Lighting with depth queuing
*								FALSE	:	Lighting without depth queuing
*				flags		-	Special rendering override flags
*
*	NOTES		This routine is only called from MRDisplayMeshInstance(), which
*				is where the MR_MESH_PARAM block is set up.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSpecialDisplayMeshPolys_GT3(	MR_SVEC* 		vert_ptr,
									 	MR_SVEC* 		norm_ptr,
									 	MR_ULONG*		prim_ptr,
									 	MR_ULONG*		mem_ptr,
									 	MR_MESH_PARAM*	param_ptr,
									 	MR_BOOL 		light_dpq,
										MR_ULONG		flags)
{											
	register	MR_ULONG*	work_ot		= param_ptr->p_work_ot;
	register	MR_LONG		otz_shift	= param_ptr->p_otz_shift;
	register	MR_LONG		ot_size		= param_ptr->p_ot_size;
	register	MR_LONG		ot_clip		= param_ptr->p_ot_clip;
	register	MR_LONG		disp_h		= MRVp_disp_h;
	register	MR_LONG		prim_count;
	MR_CVEC					work_cvec;
	MR_SVEC					work_svec[3];

	// Fetch number of primitives in this block
	prim_count = ((MR_MPRIM_HEADER*)(prim_ptr - 1))->mm_count;

	// Pre-fetch the first set of vertex pointers
	param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_p0;
	param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_p1;
	param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_p2;

	// Process every polygon in turn
	while (prim_count--)
		{
		// Load first 3 vertices into the GTE 
		gte_ldv3(param_ptr->p_v0, param_ptr->p_v1, param_ptr->p_v2);

		// Rotate the first three points
		gte_rtpt();
		param_ptr->p_v0 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr+1)->mp_p0;	// Fetch next vertices
		param_ptr->p_v1 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr+1)->mp_p1;	// while in gte_rtpt()
		param_ptr->p_v2 = vert_ptr + ((MR_MPRIM_GT3*)prim_ptr+1)->mp_p2;	// delay slot
		
		// Normal clip first three points
		gte_nclip();
		MR_COPY32(work_cvec, ((MR_MPRIM_GT3*)prim_ptr)->mp_cvec);
		if (flags & MR_MESH_INST_TRANSLUCENT_MASK)								
			work_cvec.cd = work_cvec.cd | 0x02;										// This could be an absolute write?
		gte_ldrgb(&work_cvec);															// Load RGB in delay slot
		gte_stopz(&(param_ptr->p_nclip_result));
		
		// Normal clip if required
		if ((!(flags & MR_MESH_INST_IGNORE_NCLIP)) && (param_ptr->p_nclip_result <= 0))
			goto next_poly;															

	//---------------
		gte_avsz3();
		gte_stotz(&param_ptr->p_poly_otz);

		param_ptr->p_poly_otz = (param_ptr->p_poly_otz >> otz_shift) + param_ptr->p_ot_otz_delta;

		if (
			(param_ptr->p_poly_otz >= ot_clip) &&
			(param_ptr->p_poly_otz < ot_size)
			)
			{
			gte_stsxy3_gt3((POLY_GT3*)mem_ptr);

			if (
				(((((POLY_GT3*)mem_ptr)->y0 >= 0) ||
				  (((POLY_GT3*)mem_ptr)->y1 >= 0) ||
				  (((POLY_GT3*)mem_ptr)->y2 >= 0)) &&
				 ((((POLY_GT3*)mem_ptr)->y0 < disp_h) ||
				  (((POLY_GT3*)mem_ptr)->y1 < disp_h) ||
				  (((POLY_GT3*)mem_ptr)->y2 < disp_h)))
				)

				{

				if (!(flags & MR_MESH_INST_NO_LIGHTING))								// We want lighting?
					{
					if ((flags & MR_MESH_INST_IGNORE_NCLIP) && (flags & MR_MESH_INST_FIX_NCLIP_NORMALS) && (param_ptr->p_nclip_result <= 0))
						{
						work_svec[0].vx = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n0)->vx;					
						work_svec[0].vy = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n0)->vy;					
						work_svec[0].vz = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n0)->vz;					
						work_svec[1].vx = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n1)->vx;					
						work_svec[1].vy = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n1)->vy;					
						work_svec[1].vz = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n1)->vz;					
						work_svec[2].vx = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n2)->vx;					
						work_svec[2].vy = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n2)->vy;					
						work_svec[2].vz = -(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n2)->vz;					
						gte_ldv3(&work_svec[0], &work_svec[1], &work_svec[2]);
						}
					else
						{
						gte_ldv3((norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n0),
									(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n1),
									(norm_ptr + ((MR_MPRIM_GT3*)prim_ptr)->mp_n2));
						}

					if (light_dpq)
						{
						gte_ncdt();
						}
					else
						{
						gte_ncct();
						}
					gte_strgb3_gt3((POLY_GT3*)mem_ptr);
					}
				else
					{
					MR_COPY32(((POLY_GT3*)mem_ptr)->r0, work_cvec);
					MR_COPY32(((POLY_GT3*)mem_ptr)->r1, work_cvec);
					MR_COPY32(((POLY_GT3*)mem_ptr)->r2, work_cvec);
					}
	
				addPrim(work_ot + param_ptr->p_poly_otz, mem_ptr);
				}	
			}
	//---------------
	next_poly:
			((POLY_GT3*)mem_ptr)++;
			((MR_MPRIM_GT3*)prim_ptr)++;
			param_ptr->p_prims--;
		}
	
	// Place register based address arguments into param block for retrieval/setting by caller
	param_ptr->p_mem_ptr	= mem_ptr;
	param_ptr->p_prim_ptr	= prim_ptr;

}
