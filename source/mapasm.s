;/******************************************************************************
;/*%%%% mapasm.s
;/*------------------------------------------------------------------------------
;/*
;/*	Polygon rendering routines for Frogger (PlayStation)
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------  	----------  		------
;/*	03.07.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

		section	.text	

		xdef	MapRenderQuadsASM
		xdef	MapRenderTrisASM
		
		include	"mapasm.i"	
			
		xref	MRFrame_index
		xref	MRVp_work_ot
		xref	MRVp_otz_shift
		xref	MRVp_ot_size
		xref	MRTemp_svec

		xref	Map_light_min_r2
		xref	Map_light_max_r2
		xref	Map_vertices
		xref	Map_debug_land_polys


;/******************************************************************************
;/*%%%% MapRenderQuadsASM
;/*------------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MapRenderQuadsASM(
;/*				POLY_NODE*		poly_node,
;/*				MAP_RENDER_PARAMS*	params);
;/*
;/*	FUNCTION	Runs through all poly nodes, rotates polys, and adds them
;/*			to the viewport OT after texture mashing.
;/*
;/*	INPUTS		poly_node	-    (a0) Root node of quad list to process
;/*			params		-    (a1) Pointer to quad rendering info
;/*
;/*	NOTES		This function performs equivalent processing to that found
;/*			in mapdisp.c (MapRenderQuads)
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	03.07.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

;	a0	-	pointer to current polygon node
;	a1	-	pointer to rendering param block
;	a2	-	current prim pointer
;	a3	-	OT position 
;
;	v0	-	poly
;	v1	-	npolys
;
;	t0	-	
;	t1	-	
;	t2	-	
;	t3	-	
;	t4	-	
;	t5	-	
;	t6	-	
;	t7	-	
;	t8	-	
;	t9	-	
;
;	s0	-	current prim pointer x0 address
;	s1	-	current prim pointer x1 address
;	s2	-	current prim pointer x2 address
;	s3	-	current prim pointer x3 address
;	s4	-	pvert[0]
;	s5	-	pvert[1]	
;	s6	-	pvert[2]
;	s7	-	pvert[3]
;	s8	-	Map_vertices


MapRenderQuadsASM:

.stack_saved_registers:
		addiu	sp, sp, -sizeof_MAPASM_STACK		; Create a stack frame
		sw	s0, MAPASM_STACK_s0(sp)	  		; Save registers on the stack
		sw	s1, MAPASM_STACK_s1(sp)			
		sw	s2, MAPASM_STACK_s2(sp)			
		sw	s3, MAPASM_STACK_s3(sp)			
		sw	s4, MAPASM_STACK_s4(sp)			
		sw	s5, MAPASM_STACK_s5(sp)			
		sw	s6, MAPASM_STACK_s6(sp)			
		sw	s7, MAPASM_STACK_s7(sp)			
		sw	s8, MAPASM_STACK_s8(sp)			
								

.init:								
		lw	t0, MRP_prim_size(a1)			
		lui	t1, $00ff
		sra	t0, t0, 2
		ori	t1, t1, $ffff				; t1 = $ffffff
		addiu	t0, t0, -1
		sll	t0, t0, 24				; t0 = (GPU primitive size << 24)
		sw	t1, MAPASM_STACK_ot_and_mask(sp)
		sw	t0, MAPASM_STACK_ot_or_mask(sp)

		lui	s8, (Map_vertices>>16)	
		ori	s8, s8, (Map_vertices&$ffff)
		lw	s8, 0(s8)				; s8 = Contents of Map_vertices (pointer to MR_SVEC array)

		lui	t1, (MRVp_work_ot>>16)			; Read and cache the OT pointer, OT size, and OT shift
		lui	t2, (MRVp_ot_size>>16)
		lui	t3, (MRVp_otz_shift>>16)
		lui	t4, (MRTemp_svec>>16)
		ori	t1, t1, (MRVp_work_ot&$ffff)
		ori	t2, t2, (MRVp_ot_size&$ffff)
		ori	t3, t3, (MRVp_otz_shift&$ffff)
		ori	t4, t4, (MRTemp_svec&$ffff)
		lw	t1, 0(t1)
		lh	t2, 0(t2)
		lh	t3, 0(t3)
		sw	t1, MAPASM_STACK_work_ot(sp)
		sw	t2, MAPASM_STACK_ot_size(sp)
		sw	t3, MAPASM_STACK_otz_shift(sp)
		sw	t4, MAPASM_STACK_temp_svec_ptr(sp)							
								
		lw	t1, MRP_prim_flags(a1)	      		
		nop
		andi	t1, t1, MAP_RENDER_FLAGS_LIT
		beq	t1, zero, .fetch_next_node
		add	a3, zero, zero				; // DELAY: light_factor = NULL
								
		lui	t0, 128					; t0 = (128<<16)
								
		lui	t1, (Map_light_min_r2>>16)	
		ori	t1, t1, (Map_light_min_r2&$ffff)
		lw	t2, 0(t1)				; t2 = *Map_light_min_r2

		lui	t1, (Map_light_max_r2>>16)	
		ori	t1, t1, (Map_light_max_r2&$ffff)
		lw	t3, 0(t1)				; t3 = *Map_light_max_r2

		sw	t2, MAPASM_STACK_light_min(sp)
		sw	t3, MAPASM_STACK_light_max(sp)
		
		sub	t1, t3, t2				; t1 = Map_light_max_r2 - Map_light_min_r2
			  					
		divu	t0, t1					; start divide of t0 (128<<16) by t1 (Map_light_max_r2 - Map_light_min_r2)
		nop						
		mflo	t0					; t3 = (128<<16) / (Map_light_max_r2 - Map_light_min_r2)
		sw	t0, MAPASM_STACK_light_factor(sp)	


.fetch_next_node:
		lw	a0, PN_next(a0)				; poly_node = poly_node->pn_next
		lui	t0, (MRFrame_index>>16)			; Fetch first part of MRFrame_index address
		beq	a0, zero, .exit				; leave if we haven't any poly nodes
		ori	t0, t0, (MRFrame_index&$ffff)		; t0 = address of MRFrame_index
		lw	t1, 0(t0)				; t1 = MRFrame_index
		addi	t2, a0, PN_prims			; t2 points to poly_node->pn_prims
		sll	t1, t1, 2				; Turn MRFrame_index into longword offset
		add	t2, t2, t1				; t2 now points to poly_node->pn_prims[0] or poly_node->pn_prims[1]
		lw	a2, 0(t2)				; a2 now points to appropriate primitive buffer

		lw	v1, PN_numpolys(a0)			; v1 = numpoly
		lw	v0, PN_map_polys(a0)			; v0 = poly
		beq	v1, zero, .fetch_next_node
		nop

		;// Set s0, s1, s2 and s3 to appropriate addresses within primitive

		lw	s0, MRP_prim_x0_ofs(a1)			; s0 = mr_prim_x0_ofs
		lw	t0, MRP_prim_coord_ofs(a1)		; load t0 with offset between each x position in prim
		addu	s0, s0, a2				; s0 = address of x0 in primitive
		add	s1, s0, t0				; s1 = s0 + mr_prim_coord_ofs
		add	s2, s1, t0				; s2 = s1 + mr_prim_coord_ofs
		add	s3, s2, t0				; s3 = s2 + mr_prim_coord_ofs	

		    
		lhu	s4, 0+MF4_vertices(v0)			; t0 = poly->mp_vertices[0]			
		lhu	s5, 2+MF4_vertices(v0)			; t1 = poly->mp_vertices[1]			
		lhu	s6, 4+MF4_vertices(v0)			; t2 = poly->mp_vertices[2]			
		lhu	s7, 6+MF4_vertices(v0)			; t3 = poly->mp_vertices[3]			

		sll	s4, s4, 3				; Turn next vertex 0 index into a MR_SVEC offset
		sll	s5, s5, 3				; Turn next vertex 1 index into a MR_SVEC offset
		sll	s6, s6, 3				; Turn next vertex 2 index into a MR_SVEC offset
		sll	s7, s7, 3				; Turn next vertex 3 index into a MR_SVEC offset

		add	s4, s8, s4				; s4 = address of vertex 0
		add	s5, s8, s5				; s5 = address of vertex 1
		add	s6, s8, s6				; s6 = address of vertex 2
		add	s7, s8, s7				; s7 = address of vertex 3

.process_next_polygon:

.check_for_lit:
		lw	t0, MRP_prim_flags(a1)	      		
		nop
		andi	t1, t0, MAP_RENDER_FLAGS_LIT
		beq	t1, zero, .check_for_textured
		nop

		;// Start of lighting code

		lh	t3, SVEC_vx+MRP_frog_svec(a1)		; Must NOT trash t3/t4/t5
		lh	t4, SVEC_vy+MRP_frog_svec(a1)		; and must keep t6/t7/t8/t9 holding rgb[0/1/2/3]'s
		lh	t5, SVEC_vz+MRP_frog_svec(a1)

		;// ------ VERTEX 0 -------
	
		lh	t0, SVEC_vx(s4)	
		lh	t1, SVEC_vy(s4)
		lh	t2, SVEC_vz(s4)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop
		bge	t0, t1, .check_max_light_0
		lui	t6, $0080
		beq	zero, zero, .have_light_0
		ori	t6, t6, 0x8080				
.check_max_light_0:
		blt	t0, t2, .calc_light_0
		add	t6, zero, zero
		beq	zero, zero, .have_light_0
		nop

.calc_light_0:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t6					; t6 = rgb[0]

.have_light_0:
		;// ------ End of VERTEX 0 ------

		;// ------ VERTEX 1 -------
	
		lh	t0, SVEC_vx(s5)	
		lh	t1, SVEC_vy(s5)
		lh	t2, SVEC_vz(s5)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop
		bge	t0, t1, .check_max_light_1
		lui	t7, $0080
		beq	zero, zero, .have_light_1
		ori	t7, t7, 0x8080				
.check_max_light_1:
		blt	t0, t2, .calc_light_1
		add	t7, zero, zero
		beq	zero, zero, .have_light_1
		nop

.calc_light_1:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t7					; t7 = rgb[1]

.have_light_1:
		;// ------ End of VERTEX 1 ------

		;// ------ VERTEX 2 -------
	
		lh	t0, SVEC_vx(s6)	
		lh	t1, SVEC_vy(s6)
		lh	t2, SVEC_vz(s6)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop		
		bge	t0, t1, .check_max_light_2
		lui	t8, $0080
		beq	zero, zero, .have_light_2
		ori	t8, t8, 0x8080				
.check_max_light_2:
		blt	t0, t2, .calc_light_2
		add	t8, zero, zero
		beq	zero, zero, .have_light_2
		nop

.calc_light_2:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t8					; t8 = rgb[2]

.have_light_2:
		;// ------ End of VERTEX 2 ------

		;// ------ VERTEX 3 -------
	
		lh	t0, SVEC_vx(s7)	
		lh	t1, SVEC_vy(s7)
		lh	t2, SVEC_vz(s7)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop
		bge	t0, t1, .check_max_light_3
		lui	t9, $0080
		beq	zero, zero, .have_light_3
		ori	t9, t9, 0x8080				
.check_max_light_3:
		blt	t0, t2, .calc_light_3
		add	t9, zero, zero
		beq	zero, zero, .have_light_3
		nop

.calc_light_3:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t9					; t9 = rgb[0]

.have_light_3:
		;// ------ End of VERTEX 3 ------

		sb	t6, -4(s0)
		sra	t6, t6, 8
		sw	t7, -4(s1)
		sb	t6, -3(s0)
		sra	t6, t6, 8
		sw	t8, -4(s2)
		sb	t6, -2(s0)
		sw	t9, -4(s3)


		;// End of lighting code


.check_for_textured:					
		lw	t0, MRP_prim_flags(a1)	      		
		add	a3, zero, zero				; OT(a3) position clear
		andi	t0, t0, MAP_RENDER_FLAGS_TEXTURED
		beq	t0, zero, .do_rotates
		lhu	t1, MFT4_flags(v0)			; // DELAY: Fetch mp_flags
		nop
		andi	t2, t1, MAP_POLY_ENVMAP
		beq	t2, zero, .check_for_max_ot

		;// Start of ENVMAP stuff
		lw	t0, MAPASM_STACK_temp_svec_ptr(sp)	; // DELAY: Get address of MRTemp_svec
		nop
		lh	t3, SVEC_vx(t0)
		lh	t5, SVEC_vz(t0)
		lh	t2, SVEC_vx(s4)
		lh	t4, SVEC_vz(s4)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s0)
		sb	t4, 5(s0)
	
		lh	t2, SVEC_vx(s5)
		lh	t4, SVEC_vz(s5)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s1)
		sb	t4, 5(s1)
		
		lh	t2, SVEC_vx(s6)
		lh	t4, SVEC_vz(s6)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s2)
		sb	t4, 5(s2)

		lh	t2, SVEC_vx(s7)
		lh	t4, SVEC_vz(s7)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s3)
		sb	t4, 5(s3)

		lw	t3, MAPASM_STACK_ot_size(sp)
		beq	zero, zero, .maybe_update_textures
		addi	a3, t3, -2				; // DELAY: a3 (ot) = MRVp_ot_size - 2
		;// End of ENVMAP stuff

.check_for_max_ot:						; t1 is assumed to still have mp_flags in it.
		andi	t2, t1, MAP_POLY_MAX_OT		
		beq	t2, zero, .maybe_update_textures
		lw	t3, MAPASM_STACK_ot_size(sp)
		nop
		addi	a3, t3, -1				; a3 (ot) = MRVp_ot_size - 1

.maybe_update_textures:						; t1 is assumed to still have mp_flags in it.
		andi	t2, t1, (MAP_POLY_ANIM_TEXTURE|MAP_POLY_ANIM_UV)
		beq	t2, zero, .do_rotates
		nop
		   
		lw	t0, MFT4_u0(v0)				; copy u0/v0/clut into prim
		lw	t1, MFT4_u1(v0)				; copy u1/v1/tpage into prim
		lhu	t2, MFT4_u2(v0)				; copy u2/v2 into prim
		lhu	t3, MFT4_u3(v0)				; copy u3/v3 into prim
		sw	t0, 4(s0)
		sw	t1, 4(s1)
		sh	t2, 4(s2)
		sh	t3, 4(s3)

.do_rotates:
		lwc2	C2_VXY0, SVEC_vx(s4)			; Load vector 0 from vertex 0
		lwc2	C2_VZ0, SVEC_vz(s4)		
		lwc2	C2_VXY1, SVEC_vx(s5)			; Load vector 1 from vertex 1
		lwc2	C2_VZ1, SVEC_vz(s5)			
		lwc2	C2_VXY2, SVEC_vx(s6)			; Load vector 2 from vertex 2
		lwc2	C2_VZ2, SVEC_vz(s6)			
		lw	t0, MRP_poly_size(a1)			; Fetch polygon size
		nop
		RTPT
		add	v0, v0, t0				; // DELAY: Increment polygon pointer accordingly	

		lhu	s4, 0+MF4_vertices(v0)			; // DELAY: s4 = poly->mp_vertices[0]			
		lhu	s5, 2+MF4_vertices(v0)			; // DELAY: s5 = poly->mp_vertices[1]			
		lhu	s6, 4+MF4_vertices(v0)			; // DELAY: s6 = poly->mp_vertices[2]			

		sll	s4, s4, 3				; // DELAY: Turn next vertex 0 index into a MR_SVEC offset
		sll	s5, s5, 3				; // DELAY: Turn next vertex 1 index into a MR_SVEC offset
		sll	s6, s6, 3				; // DELAY: Turn next vertex 2 index into a MR_SVEC offset

		add	s4, s8, s4				; // DELAY: s4 = address of vertex 0
		add	s5, s8, s5				; // DELAY: s5 = address of vertex 1
		add	s6, s8, s6				; // DELAY: s6 = address of vertex 2
		
		NCLIP

		lwc2	C2_VXY0, SVEC_vx(s7)			; // DELAY: Load vector 0 from vertex 3 (in NCLIP delay slots)
		lwc2	C2_VZ0, SVEC_vz(s7)			; // DELAY: 

		mfc2	t0, C2_MAC0				; Get first NCLIP result

		swc2	C2_SXY0, 0(s0)				; Store XY0, as it will be pushed out of fifo by vertex 3
		
		RTPS
		
		lhu	s7, 6+MF4_vertices(v0)			; // DELAY: s7 = poly->mp_vertices[3]			
		nop
		sll	s7, s7, 3				; // DELAY: Turn next vertex 3 index into a MR_SVEC offset

		bgtz	t0, .visible_poly
		add	s7, s8, s7				; // DELAY: s7 = address of vertex 3
				
		NCLIP
		mfc2	t0, C2_MAC0
		nop
		bgez	t0, .next_poly
		nop

.visible_poly:
		swc2	C2_SXY0,0(s1)				; Store XY coordinates for vertex 1
		swc2	C2_SXY1,0(s2)				; Store XY coordinates for vertex 2
		swc2	C2_SXY2,0(s3)				; Store XY coordinates for vertex 3

		bne	zero, a3, .add_prim			; Fixed OT position (at the back, normally) so skip max Z stuff
		ori	t2, zero, MAP_POLY_CLIP_OTZ		; DELAY

		;// t9 = MAX(C2_SZ0, C2_SZ1)
;//		opt	at-
;//		mfc2	t0, C2_SZ0
;//		mfc2	t1, C2_SZ1
;//		nop
;//		slt	at, t1, t0
;//		beq	at, zero, .check_z_pair_1		; If t1 >= t0
;//		addu	t9, t1, zero				; move t1 to t9 while evaluating branch
;//		addu	t0, t0, zero				; Branch not taken, so t1 < t0
;//		opt	at+
;//	
;//.check_z_pair_1:
;//		;// t1 = MAX(t9, C2_SZ2)
;//		opt	at-
;//		mfc2	t0, C2_SZ2
;//		nop
;//		slt	at, t9, t0
;//		beq	at, zero, .check_z_pair_2		; If t9 >= t0
;//		addu	t1, t9, zero				; move t9 to t1 while evaluating branch
;//		addu	t1, t0, zero				; Branch not taken, so t9 < t0
;//		opt	at+
;//		
;//.check_z_pair_2:
;//		;// a3 = MAX(t1, C2_SZ3)
;//		opt	at-
;//		mfc2	t0, C2_SZ3
;//		nop		
;//		slt	at, t0, t1
;//		beq	at, zero, .we_have_maximum_z		; If t0 >= t1
;//		addu	a3, t0, zero				; move t0 to a3 while evaluating branch
;//		addu	a3, t1, zero				; Branch not taken, so a3 < t1
;//		opt	at+
;//
;//.we_have_maximum_z:						; Note: At this point, a3 holds maximum OT position

		AVSZ4						; Average the SZ0/SZ1/SZ2/SZ3 points in the FIFO
		mfc2	a3,C2_OTZ				; Fetch OTZ
		lw	t1, MAPASM_STACK_otz_shift(sp)
		ble	a3, t2, .next_poly			; OTZ <= MAP_POLY_CLIP_OTZ
		lw	t0, MAPASM_STACK_ot_size(sp)		; // DELAY: Load ot size for free...
		
		srav	a3, a3, t1				; Shift OT into range
		addi	a3, a3, MAP_POLY_OT_OFFSET		; Add poly offset

.check_for_ot_in_range:
		bge	a3, t0, .next_poly			; otz > OT size, so bail..

; a2 = prim address 
; a3 = ot position

.add_prim:
		lw	t2, MAPASM_STACK_ot_or_mask(sp)		; // DELAY: t2 holds OT 'or' mask
		lw	t1, MAPASM_STACK_ot_and_mask(sp)	; t1 holds OT 'and' mask
		lw	t0, MAPASM_STACK_work_ot(sp)		; // DELAY: t0 holds OT pointer		

		opt 	at-					; We need AT register
		and	t9,a2,t1				; And low 24-bits of primitive address
		sll	a3,a3,2					; Turn OT position into 32-bit OT offset
		add	a3,a3,t0				; a3 now points to ordering table entry
		lw	at,0(a3)				; Fetch current OT entry contents
		sw	t9,0(a3)				; Point OT entry to our current prim
		or	at,at,t2						
		sw	at,0(t9)
		opt	at+

;//-------- Optionally increment polygon count here? -------- 

.next_poly:
		lw	t0, MRP_prim_size(a1)			; Fetch primitive size
		add	v1, v1, -1;				; Decrement number of polys left in this node
		add	s0, s0, t0				; Increment to point to next x0
		add	s1, s1, t0				; Increment to point to next x1
		add	s2, s2, t0				; Increment to point to next x2
		add	s3, s3, t0				; Increment to point to next x3
		bgtz	v1, .process_next_polygon		; If we've prims left in this node, go and deal with them
		add	a2, a2, t0				; // DELAY: Increment primitive pointer
		beq	zero, zero, .fetch_next_node		; All polygons for this node processed.. go get next node
		nop

.exit:							
		lw	s0, MAPASM_STACK_s0(sp)	  		; Restore registers from stack
		lw	s1, MAPASM_STACK_s1(sp)
		lw	s2, MAPASM_STACK_s2(sp)
		lw	s3, MAPASM_STACK_s3(sp)
		lw	s4, MAPASM_STACK_s4(sp)
		lw	s5, MAPASM_STACK_s5(sp)
		lw	s6, MAPASM_STACK_s6(sp)
		lw	s7, MAPASM_STACK_s7(sp)
		lw	s8, MAPASM_STACK_s8(sp)
		jr	ra
		addiu	sp, sp, sizeof_MAPASM_STACK




;/******************************************************************************
;/*%%%% MapRenderTrisASM
;/*------------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MapRenderTrisASM(
;/*				POLY_NODE*		poly_node,
;/*				MAP_RENDER_PARAMS*	params);
;/*
;/*	FUNCTION	Runs through all poly nodes, rotates polys, and adds them
;/*			to the viewport OT after texture mashing.
;/*
;/*	INPUTS		poly_node	-    (a0) Root node of tri list to process
;/*			params		-    (a1) Pointer to tri rendering info
;/*
;/*	NOTES		This function performs equivalent processing to that found
;/*			in mapdisp.c (MapRenderTris)
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	03.07.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

;	a0	-	pointer to current polygon node
;	a1	-	pointer to rendering param block
;	a2	-	current prim pointer
;	a3	-	OT position 
;
;	v0	-	poly
;	v1	-	npolys
;
;	t0	-	
;	t1	-	
;	t2	-	
;	t3	-	
;	t4	-	
;	t5	-	
;	t6	-	
;	t7	-	
;	t8	-	
;	t9	-	
;
;	s0	-	current prim pointer x0 address
;	s1	-	current prim pointer x1 address
;	s2	-	current prim pointer x2 address
;	s3	-	
;	s4	-	pvert[0]
;	s5	-	pvert[1]	
;	s6	-	pvert[2]
;	s7	-	
;	s8	-	Map_vertices


MapRenderTrisASM:

.stack_saved_registers:
		addiu	sp, sp, -sizeof_MAPASM_STACK		; Create a stack frame
		sw	s0, MAPASM_STACK_s0(sp)	  		; Save registers on the stack
		sw	s1, MAPASM_STACK_s1(sp)			
		sw	s2, MAPASM_STACK_s2(sp)			
		sw	s3, MAPASM_STACK_s3(sp)			
		sw	s4, MAPASM_STACK_s4(sp)			
		sw	s5, MAPASM_STACK_s5(sp)			
		sw	s6, MAPASM_STACK_s6(sp)			
		sw	s7, MAPASM_STACK_s7(sp)			
		sw	s8, MAPASM_STACK_s8(sp)			
								

.init:								
		lw	t0, MRP_prim_size(a1)			
		lui	t1, $00ff
		sra	t0, t0, 2
		ori	t1, t1, $ffff				; t1 = $ffffff
		addiu	t0, t0, -1
		sll	t0, t0, 24				; t0 = (GPU primitive size << 24)
		sw	t1, MAPASM_STACK_ot_and_mask(sp)
		sw	t0, MAPASM_STACK_ot_or_mask(sp)

		lui	s8, (Map_vertices>>16)	
		ori	s8, s8, (Map_vertices&$ffff)
		lw	s8, 0(s8)				; s8 = Contents of Map_vertices (pointer to MR_SVEC array)

		lui	t1, (MRVp_work_ot>>16)			; Read and cache the OT pointer, OT size, and OT shift
		lui	t2, (MRVp_ot_size>>16)
		lui	t3, (MRVp_otz_shift>>16)
		lui	t4, (MRTemp_svec>>16)
		ori	t1, t1, (MRVp_work_ot&$ffff)
		ori	t2, t2, (MRVp_ot_size&$ffff)
		ori	t3, t3, (MRVp_otz_shift&$ffff)
		ori	t4, t4, (MRTemp_svec&$ffff)
		lw	t1, 0(t1)
		lh	t2, 0(t2)
		lh	t3, 0(t3)
		sw	t1, MAPASM_STACK_work_ot(sp)
		sw	t2, MAPASM_STACK_ot_size(sp)
		sw	t3, MAPASM_STACK_otz_shift(sp)
		sw	t4, MAPASM_STACK_temp_svec_ptr(sp)							
								
		lw	t1, MRP_prim_flags(a1)	      		
		nop
		andi	t1, t1, MAP_RENDER_FLAGS_LIT
		beq	t1, zero, .fetch_next_node
		add	a3, zero, zero				; // DELAY: light_factor = NULL
								
		lui	t0, 128					; t0 = (128<<16)
								
		lui	t1, (Map_light_min_r2>>16)	
		ori	t1, t1, (Map_light_min_r2&$ffff)
		lw	t2, 0(t1)				; t2 = *Map_light_min_r2

		lui	t1, (Map_light_max_r2>>16)	
		ori	t1, t1, (Map_light_max_r2&$ffff)
		lw	t3, 0(t1)				; t3 = *Map_light_max_r2

		sw	t2, MAPASM_STACK_light_min(sp)
		sw	t3, MAPASM_STACK_light_max(sp)
		
		sub	t1, t3, t2				; t1 = Map_light_max_r2 - Map_light_min_r2
			  					
		divu	t0, t1					; start divide of t0 (128<<16) by t1 (Map_light_max_r2 - Map_light_min_r2)
		nop						
		mflo	t0					; t3 = (128<<16) / (Map_light_max_r2 - Map_light_min_r2)
		sw	t0, MAPASM_STACK_light_factor(sp)	


.fetch_next_node:
		lw	a0, PN_next(a0)				; poly_node = poly_node->pn_next
		lui	t0, (MRFrame_index>>16)			; Fetch first part of MRFrame_index address
		beq	a0, zero, .exit				; leave if we haven't any poly nodes
		ori	t0, t0, (MRFrame_index&$ffff)		; t0 = address of MRFrame_index
		lw	t1, 0(t0)				; t1 = MRFrame_index
		addi	t2, a0, PN_prims			; t2 points to poly_node->pn_prims
		sll	t1, t1, 2				; Turn MRFrame_index into longword offset
		add	t2, t2, t1				; t2 now points to poly_node->pn_prims[0] or poly_node->pn_prims[1]
		lw	a2, 0(t2)				; a2 now points to appropriate primitive buffer

		lw	v1, PN_numpolys(a0)			; v1 = numpoly
		lw	v0, PN_map_polys(a0)			; v0 = poly
		beq	v1, zero, .fetch_next_node
		nop

		;// Set s0, s1, and s2 to appropriate addresses within primitive

		lw	s0, MRP_prim_x0_ofs(a1)			; s0 = mr_prim_x0_ofs
		lw	t0, MRP_prim_coord_ofs(a1)		; load t0 with offset between each x position in prim
		addu	s0, s0, a2				; s0 = address of x0 in primitive
		add	s1, s0, t0				; s1 = s0 + mr_prim_coord_ofs
		add	s2, s1, t0				; s2 = s1 + mr_prim_coord_ofs

		    
		lhu	s4, 0+MF4_vertices(v0)			; t0 = poly->mp_vertices[0]			
		lhu	s5, 2+MF4_vertices(v0)			; t1 = poly->mp_vertices[1]			
		lhu	s6, 4+MF4_vertices(v0)			; t2 = poly->mp_vertices[2]			

		sll	s4, s4, 3				; Turn next vertex 0 index into a MR_SVEC offset
		sll	s5, s5, 3				; Turn next vertex 1 index into a MR_SVEC offset
		sll	s6, s6, 3				; Turn next vertex 2 index into a MR_SVEC offset

		add	s4, s8, s4				; s4 = address of vertex 0
		add	s5, s8, s5				; s5 = address of vertex 1
		add	s6, s8, s6				; s6 = address of vertex 2

.process_next_polygon:

.check_for_lit:
		lw	t0, MRP_prim_flags(a1)	      		
		nop
		andi	t1, t0, MAP_RENDER_FLAGS_LIT
		beq	t1, zero, .check_for_textured
		nop

		;// Start of lighting code

		lh	t3, SVEC_vx+MRP_frog_svec(a1)		; Must NOT trash t3/t4/t5
		lh	t4, SVEC_vy+MRP_frog_svec(a1)		; and must keep t6/t7/t8/t9 holding rgb[0/1/2/3]'s
		lh	t5, SVEC_vz+MRP_frog_svec(a1)

		;// ------ VERTEX 0 -------
	
		lh	t0, SVEC_vx(s4)	
		lh	t1, SVEC_vy(s4)
		lh	t2, SVEC_vz(s4)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop
		bge	t0, t1, .check_max_light_0
		lui	t6, $0080
		beq	zero, zero, .have_light_0
		ori	t6, t6, 0x8080				
.check_max_light_0:
		blt	t0, t2, .calc_light_0
		add	t6, zero, zero
		beq	zero, zero, .have_light_0
		nop

.calc_light_0:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t6					; t6 = rgb[0]

.have_light_0:
		;// ------ End of VERTEX 0 ------

		;// ------ VERTEX 1 -------
	
		lh	t0, SVEC_vx(s5)	
		lh	t1, SVEC_vy(s5)
		lh	t2, SVEC_vz(s5)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop
		bge	t0, t1, .check_max_light_1
		lui	t7, $0080
		beq	zero, zero, .have_light_1
		ori	t7, t7, 0x8080				
.check_max_light_1:
		blt	t0, t2, .calc_light_1
		add	t7, zero, zero
		beq	zero, zero, .have_light_1
		nop

.calc_light_1:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t7					; t7 = rgb[1]

.have_light_1:
		;// ------ End of VERTEX 1 ------

		;// ------ VERTEX 2 -------
	
		lh	t0, SVEC_vx(s6)	
		lh	t1, SVEC_vy(s6)
		lh	t2, SVEC_vz(s6)
		sub	t0, t0, t3				; t0 = diff.vx
		sub	t1, t1, t4				; t1 = diff.vy
		sub	t2, t2, t5				; t2 = diff.vz
		andi	t0, t0, $ffff				
		sll	t1, t1, 16				
		andi	t2, t2, $ffff			
		or	t0, t0, t1				; t0 = (diff.vy << 16) | (diff.vx)
		ctc2	t2, C2_L13L21			
		ctc2	t0, C2_L11L12			
		mtc2	t2, C2_VZ0
		mtc2	t0, C2_VXY0
		nop					
		nop					
		MVMVA	0,1,0,3,0 				; Multiply vertex 0 by row of light matrix we're playing with
		lw	t1, MAPASM_STACK_light_min(sp)		; // DELAY: Fetch light min
		lw	t2, MAPASM_STACK_light_max(sp)		; // DELAY: Fetch light max
		mfc2	t0, C2_MAC1				; t0 = (diff.vx*diff.vx)+(diff.vy*diff.vy)+(diff.vz*diff.vz)
		nop		
		bge	t0, t1, .check_max_light_2
		lui	t8, $0080
		beq	zero, zero, .have_light_2
		ori	t8, t8, 0x8080				
.check_max_light_2:
		blt	t0, t2, .calc_light_2
		add	t8, zero, zero
		beq	zero, zero, .have_light_2
		nop

.calc_light_2:
		sub	t0, t0, t1				; t0 = dist[v] - Map_light_min_r2
		lw	t2, MAPASM_STACK_light_factor(sp)	; t2 = light_factor
		ori	t1, zero, $80				; t1 = 0x80
		mult	t0, t2
		nop
		mflo	t0					; t0 = light_factor * (dist[v] - Map_light_min_r2)
		lui	t2, $0001
		sra	t0, t0, 16
		ori	t2, t2, $0101
		sub	t1, t1, t0
		mult	t1, t2
		nop
		mflo	t8					; t8 = rgb[2]

.have_light_2:
		;// ------ End of VERTEX 2 ------

		sb	t6, -4(s0)
		sra	t6, t6, 8
		sw	t7, -4(s1)
		sb	t6, -3(s0)
		sra	t6, t6, 8
		sw	t8, -4(s2)
		sb	t6, -2(s0)

		;// End of lighting code


.check_for_textured:					
		lw	t0, MRP_prim_flags(a1)	      		
		add	a3, zero, zero				; OT(a3) position clear
		andi	t0, t0, MAP_RENDER_FLAGS_TEXTURED
		beq	t0, zero, .do_rotates
		lhu	t1, MFT4_flags(v0)			; // DELAY: Fetch mp_flags
		nop
		andi	t2, t1, MAP_POLY_ENVMAP
		beq	t2, zero, .check_for_max_ot

		;// Start of ENVMAP stuff
		lw	t0, MAPASM_STACK_temp_svec_ptr(sp)	; // DELAY: Get address of MRTemp_svec
		nop
		lh	t3, SVEC_vx(t0)
		lh	t5, SVEC_vz(t0)
		lh	t2, SVEC_vx(s4)
		lh	t4, SVEC_vz(s4)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s0)
		sb	t4, 5(s0)
	
		lh	t2, SVEC_vx(s5)
		lh	t4, SVEC_vz(s5)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s1)
		sb	t4, 5(s1)
		
		lh	t2, SVEC_vx(s6)
		lh	t4, SVEC_vz(s6)
		add	t2, t2, t3
		add	t4, t4, t5
		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
		addi	t2, t2, 128
		addi	t4, t4, 128
		sb	t2, 4(s2)
		sb	t4, 5(s2)

;//		lh	t2, SVEC_vx(s7)
;//		lh	t4, SVEC_vz(s7)
;//		add	t2, t2, t3
;//		add	t4, t4, t5
;//		sra	t2, t2, MAP_POLY_ENVMAP_SHIFT
;//		sra	t4, t4, MAP_POLY_ENVMAP_SHIFT
;//		addi	t2, t2, 128
;//		addi	t4, t4, 128
;//		sb	t2, 4(s3)
;//		sb	t4, 5(s3)

		lw	t3, MAPASM_STACK_ot_size(sp)
		beq	zero, zero, .maybe_update_textures
		addi	a3, t3, -2				; // DELAY: a3 (ot) = MRVp_ot_size - 2
		;// End of ENVMAP stuff


.check_for_max_ot:						; t1 is assumed to still have mp_flags in it
		andi	t2, t1, MAP_POLY_MAX_OT		
		beq	t2, zero, .maybe_update_textures
		lw	t3, MAPASM_STACK_ot_size(sp)
		nop
		addi	a3, t3, -1				; a3 (ot) = MRVp_ot_size - 1

.maybe_update_textures:						; t1 is assumed to still have mp_flags in it.
		andi	t2, t1, (MAP_POLY_ANIM_TEXTURE|MAP_POLY_ANIM_UV)
		beq	t2, zero, .do_rotates
		nop
		   
		lw	t0, MFT4_u0(v0)				; copy u0/v0/clut into prim
		lw	t1, MFT4_u1(v0)				; copy u1/v1/tpage into prim
		lhu	t2, MFT4_u2(v0)				; copy u2/v2 into prim
		sw	t0, 4(s0)
		sw	t1, 4(s1)
		sh	t2, 4(s2)

.do_rotates:
		lwc2	C2_VXY0, SVEC_vx(s4)			; Load vector 0 from vertex 0
		lwc2	C2_VZ0, SVEC_vz(s4)		
		lwc2	C2_VXY1, SVEC_vx(s5)			; Load vector 1 from vertex 1
		lwc2	C2_VZ1, SVEC_vz(s5)			
		lwc2	C2_VXY2, SVEC_vx(s6)			; Load vector 2 from vertex 2
		lwc2	C2_VZ2, SVEC_vz(s6)			
		lw	t0, MRP_poly_size(a1)			; Fetch polygon size
		nop
		RTPT
		add	v0, v0, t0				; // DELAY: Increment polygon pointer accordingly	

		lhu	s4, 0+MF4_vertices(v0)			; // DELAY: s4 = poly->mp_vertices[0]			
		lhu	s5, 2+MF4_vertices(v0)			; // DELAY: s5 = poly->mp_vertices[1]			
		lhu	s6, 4+MF4_vertices(v0)			; // DELAY: s6 = poly->mp_vertices[2]			

		sll	s4, s4, 3				; // DELAY: Turn next vertex 0 index into a MR_SVEC offset
		sll	s5, s5, 3				; // DELAY: Turn next vertex 1 index into a MR_SVEC offset
		sll	s6, s6, 3				; // DELAY: Turn next vertex 2 index into a MR_SVEC offset

		add	s4, s8, s4				; // DELAY: s4 = address of vertex 0
		add	s5, s8, s5				; // DELAY: s5 = address of vertex 1
		add	s6, s8, s6				; // DELAY: s6 = address of vertex 2
		
		NCLIP

		mfc2	t0, C2_MAC0				; Get first NCLIP result
		nop
		blez	t0, .next_poly
		nop

.visible_poly:
		swc2	C2_SXY0,0(s0)				; Store XY coordinates for vertex 0
		swc2	C2_SXY1,0(s1)				; Store XY coordinates for vertex 1
		swc2	C2_SXY2,0(s2)				; Store XY coordinates for vertex 2

		bne	zero, a3, .add_prim			; Fixed OT position (at the back, normally) so skip max Z stuff
		ori	t2, zero, MAP_POLY_CLIP_OTZ		; DELAY

;//		;// t9 = MAX(C2_SZ1, C2_SZ2)
;//		opt	at-
;//		mfc2	t0, C2_SZ1
;//		mfc2	t1, C2_SZ2
;//		nop
;//		slt	at, t1, t0
;//		beq	at, zero, .check_z_pair_1		; If t1 >= t0
;//		addu	t9, t1, zero				; move t1 to t9 while evaluating branch
;//		addu	t0, t0, zero				; Branch not taken, so t1 < t0
;//		opt	at+
;//	
;//.check_z_pair_1:
;//		;// t1 = MAX(t9, C2_SZ3)
;//		opt	at-
;//		mfc2	t0, C2_SZ3
;//		nop
;//		slt	at, t9, t0
;//		beq	at, zero, .we_have_maximum_z		; If t9 >= t0
;//		addu	a3, t9, zero				; move t9 to a3 while evaluating branch
;//		addu	a3, t0, zero				; Branch not taken, so t9 < t0
;//		opt	at+
;//		
;//.we_have_maximum_z:						; Note: At this point, a3 holds maximum OT position

		AVSZ3						; Average the SZ0/SZ1/SZ2 points in the FIFO
		mfc2	a3,C2_OTZ				; Fetch OTZ
		lw	t1, MAPASM_STACK_otz_shift(sp)
		ble	a3, t2, .next_poly			; OTZ <= MAP_POLY_CLIP_OTZ
		lw	t0, MAPASM_STACK_ot_size(sp)		; // DELAY: Load ot size for free...
		
		srav	a3, a3, t1				; Shift OT into range
		addi	a3, a3, MAP_POLY_OT_OFFSET		; Add poly offset

.check_for_ot_in_range:
		bge	a3, t0, .next_poly			; otz > OT size, so bail..

; a2 = prim address 
; a3 = ot position

.add_prim:
		lw	t2, MAPASM_STACK_ot_or_mask(sp)		; // DELAY: t2 holds OT 'or' mask
		lw	t1, MAPASM_STACK_ot_and_mask(sp)	; t1 holds OT 'and' mask
		lw	t0, MAPASM_STACK_work_ot(sp)		; // DELAY: t0 holds OT pointer		

		opt 	at-					; We need AT register
		and	t9,a2,t1				; And low 24-bits of primitive address
		sll	a3,a3,2					; Turn OT position into 32-bit OT offset
		add	a3,a3,t0				; a3 now points to ordering table entry
		lw	at,0(a3)				; Fetch current OT entry contents
		sw	t9,0(a3)				; Point OT entry to our current prim
		or	at,at,t2						
		sw	at,0(t9)
		opt	at+

;//-------- Optionally increment polygon count here? -------- 

.next_poly:
		lw	t0, MRP_prim_size(a1)			; Fetch primitive size
		add	v1, v1, -1;				; Decrement number of polys left in this node
		add	s0, s0, t0				; Increment to point to next x0
		add	s1, s1, t0				; Increment to point to next x1
		add	s2, s2, t0				; Increment to point to next x2
		bgtz	v1, .process_next_polygon		; If we've prims left in this node, go and deal with them
		add	a2, a2, t0				; // DELAY: Increment primitive pointer
		beq	zero, zero, .fetch_next_node		; All polygons for this node processed.. go get next node
		nop

.exit:							
		lw	s0, MAPASM_STACK_s0(sp)	  		; Restore registers from stack
		lw	s1, MAPASM_STACK_s1(sp)
		lw	s2, MAPASM_STACK_s2(sp)
		lw	s3, MAPASM_STACK_s3(sp)
		lw	s4, MAPASM_STACK_s4(sp)
		lw	s5, MAPASM_STACK_s5(sp)
		lw	s6, MAPASM_STACK_s6(sp)
		lw	s7, MAPASM_STACK_s7(sp)
		lw	s8, MAPASM_STACK_s8(sp)
		jr	ra
		addiu	sp, sp, sizeof_MAPASM_STACK

		end

