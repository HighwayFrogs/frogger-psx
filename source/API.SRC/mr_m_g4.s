;/******************************************************************************
;/*%%%% mr_m_g4.s
;/*------------------------------------------------------------------------------
;/*
;/*	Polygon rendering routines for gouraud shaded quadrilateral groups
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------  	----------  		------
;/*	18.09.96	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

		section	.text	

		xdef	MRDisplayMeshPolys_G4
 
		include	"mr_m_hdr.i"	

;/******************************************************************************
;/*%%%% MRDisplayMeshPolys_G4
;/*------------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MRDisplayMeshPolys_G4(
;/*				MR_SVEC*	vert_ptr,
;/*				MR_SVEC*	norm_ptr,
;/*				MR_ULONG*	prim_ptr,
;/*				MR_ULONG*	mem_ptr,
;/*				MR_MESH_PARAM*	param_ptr,
;/*				MR_BOOL		light_dpq);
;/*
;/*	FUNCTION	Performs high-speed geometry calculations for a block of
;/*			MR_MPRIM_G4 primitives (gouraud shaded quadrilaterals).
;/*
;/*	INPUTS		vert_ptr	-    (a0) Pointer to vertex block
;/*			norm_ptr	-    (a1) Pointer to normal block
;/*			prim_ptr	-    (a2) Pointer to MR_MPRIM_G4 block	
;/*			mem_ptr		-    (a3) Pointer to primitive buffer memory
;/*			param_ptr	- $10(sp) Pointer to mesh parameter block	
;/*			light_dpq	- $14(sp) TRUE if using depth queuing
;/*
;/*	NOTES		This function performs equivalent processing to that found
;/*			in mr_p_g4.c, with the exception that this doesn't clip
;/*			to the display.
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	18.9.96		Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

;// Register usage
;
;a0 = vertex ptr
;a1 = normal ptr
;a2 = mprim ptr
;a3 = mem ptr
;
;v0 = param block ptr
;v1 = depth queueing flag
;
;t0 = temp for vertex 0
;t1 = temp for vertex 1
;t2 = temp for vertex 2
;t3 = temp for vertex 3
;
;t4 = temp for normal 0 
;t5 = temp for normal 1 
;t6 = temp for normal 2 
;t7 = temp for normal 3 
;
;t8 = work
;t9 = work
;
;s0 = ot pointer
;s1 = otz shift
;s2 = ot size
;s3 = ot clip
;s4 = otz delta
;s5 = primitive count

;s6 = ot 'and' mask
;s7 = ot 'or' mask

;s8 = model primitive count 

;// ---------------------------------------------------------------------------------------------

MRDisplayMeshPolys_G4:

.initialise:
		lw	v0,$10(sp)			; Get param_ptr
		lw	v1,$14(sp)			; Get light_dpq 

.stack_saved_registers:
		addiu	sp, sp, -sizeof_MESH_STACK     	; Create a stack frame
		sw	s0, MESH_STACK_s0(sp)		; Save registers on the stack
		sw	s1, MESH_STACK_s1(sp)
		sw	s2, MESH_STACK_s2(sp)
		sw	s3, MESH_STACK_s3(sp)
		sw	s4, MESH_STACK_s4(sp)
		sw	s5, MESH_STACK_s5(sp)
		sw	s6, MESH_STACK_s6(sp)
		sw	s7, MESH_STACK_s7(sp)
		sw	s8, MESH_STACK_s8(sp)
			  
.calculate_common_registers
		lw	s0,MP_work_ot(v0)
		lh	s1,MP_otz_shift(v0)
		lw	s2,MP_ot_size(v0)
		lw	s3,MP_ot_clip(v0)
		lh	s4,MP_ot_otz_delta(v0)

.calculate_loop_iterations:				
		addi	s5,a2,-4			; s5 points to previous word in prim block
		lw	s5,0(s5)			; Fetch word containing primitive count
		nop					
		sra	s5,s5,16			; High word contains count, so shift down
				
.calculate_addprim_masks:				
		lui	s6,$00ff			; s6 = $00ffffff	  
		ori	s6,s6,$ffff			
		lui	s7,primsize_PG4<<8		; s7 = primitive packet length in upper 8 bits

.calculate_model_primitive_count:
		lw	s8,MP_prims(v0)
							
.precalculate_first_vertices:				
		lh	t0,MPG4_p0(a2)			; Fetch mp_p0
		lh	t1,MPG4_p1(a2)			; Fetch mp_p1
		lh	t2,MPG4_p2(a2)			; Fetch mp_p2
		lh	t3,MPG4_p3(a2)			; Fetch mp_p3
							
		sll	t0,t0,3				; Turn mp_p0 index into SVECTOR offset
		sll	t1,t1,3				; Turn mp_p1 index into SVECTOR offset
		sll	t2,t2,3				; Turn mp_p2 index into SVECTOR offset
		sll	t3,t3,3				; Turn mp_p3 index into SVECTOR offset
 							
		add	t0,t0,a0			; t0 = vertex 0 address		
		add	t1,t1,a0			; t1 = vertex 1 address		
		add	t2,t2,a0			; t2 = vertex 2 address		
		add	t3,t3,a0			; t3 = vertex 3 address		
							
.process_next_polygon					
		lwc2	C2_VXY0,SVEC_vx(t0)		; Load vector 0 from vertex 0
		lwc2	C2_VZ0,SVEC_vz(t0)
		lwc2	C2_VXY1,SVEC_vx(t1)		; Load vector 1 from vertex 1
		lwc2	C2_VZ1,SVEC_vz(t1)		
		lwc2	C2_VXY2,SVEC_vx(t3)		; Load vector 2 from vertex 3
		lwc2	C2_VZ2,SVEC_vz(t3)		
		add	t8,a2,sizeof_MPG4		; //DELAY: t8 points to next MR_MPRIM_G4 structure
		nop
		RTPT					; Rotate 3 vertices
							
.precalculate_next_vertices:				
		lh	t0,MPG4_p0(t8)			; Fetch next mp_p0
		lh	t1,MPG4_p1(t8)			; Fetch next mp_p1
		lh	t3,MPG4_p3(t8)			; Fetch next mp_p3
							
		sll	t0,t0,3				; Turn next mp_p0 index into SVECTOR offset
		sll	t1,t1,3				; Turn next mp_p1 index into SVECTOR offset
		sll	t3,t3,3				; Turn next mp_p3 index into SVECTOR offset
							
		add	t0,t0,a0			; t0 = next vertex 0 address
		add	t1,t1,a0			; t1 = next vertex 1 address
		add	t3,t3,a0			; t3 = next vertex 3 address
							
.normal_clip:						
		NCLIP					; NCLIP coordinates in SXY FIFO 
					  
		lwc2	C2_VXY0,SVEC_vx(t2)		; Load vector 0 from vertex 2 (in delay slots)
		lwc2	C2_VZ0,SVEC_vz(t2)
		
		mfc2	t9,C2_MAC0			; Fetch first NCLIP result
		swc2	C2_SXY0,PG4_x0(a3)		; Store XY0, as it will be pushed out of fifo by vertex 2
;		nop					; NOPS not needed as there are 2 instructions between load and RTPS				
;		nop
		RTPS					; Rotate vertex 2

		lwc2	C2_RGB,MPG4_cvec(a2)		; //DELAY: Load RGB in RTPS delay slot

		lh	t2,MPG4_p2(t8)			; Fetch next mp_p2
		nop 
		sll	t2,t2,3				; Turn mp_p2 index into SVECTOR offset


		bgtz	t9,.process_poly		; NCLIP result > 0 means we want this polygon
		add	t2,t2,a0			; //DELAY: t2 = vertex 2 address

		NCLIP					; First triangle failed NCLIP, so we do the second
		mfc2	t9,C2_MAC0			; one. If that fails also, then we bin the polygon
		nop					; (Note that failure is >= 0, as FIFO points are in a screwy order)
		bgez	t9,.next_poly
		nop

.process_poly:
		AVSZ4					; Average the SZ0/SZ1/SZ2/SZ3 points in the FIFO
		lh	t4,MPG4_n0(a2)			; //DELAY: Fetch mp_n0
		mfc2	t8,C2_OTZ			; Fetch OTZ
		sll	t4,t4,3				; //DELAY: Turn mp_n0 index into SVECTOR offset
		srav	t8,t8,s1			; Shift down OTZ
		add	t8,t8,s4			; Add OTZ delta

.clip_polygon:	
		blt	t8,s3,.next_poly		; If t8 < s2, bail (near clip)
		add	t4,t4,a1			; //DELAY: t4 = normal 0 address (always executed in branch slot)
		bge	t8,s2,.next_poly		; If t8 >= s2, bail (far clip)
		lh	t5,MPG4_n1(a2)			; //DELAY: Fetch mp_n1 (always executed in branch slot)

		lh	t7,MPG4_n3(a2)			; Fetch mp_n3

		swc2	C2_SXY0,PG4_x1(a3)		; Store XY coordinates for each remaining vertex
		swc2	C2_SXY1,PG4_x2(a3)
		swc2	C2_SXY2,PG4_x3(a3)

		sll	t5,t5,3				; Turn mp_n1 index into SVECTOR offset
		sll	t7,t7,3				; Turn mp_n3 index into SVECTOR offset

		add	t5,t5,a1			; t5 = normal 1 address
		add	t7,t7,a1			; t7 = normal 3 address

		lwc2	C2_VXY0,SVEC_vx(t4)		; Load vector 0 from normal 0
		lwc2	C2_VZ0,SVEC_vz(t4)
		lwc2	C2_VXY1,SVEC_vx(t5)		; Load vector 1 from normal 1
		lwc2	C2_VZ1,SVEC_vz(t5)
		lwc2	C2_VXY2,SVEC_vx(t7)		; Load vector 2 from normal 3
		lwc2	C2_VZ2,SVEC_vz(t7)
	
		beq	zero,v1,.lighting_no_dpq	; If light_dpq == FALSE, then no depth queuing
		nop

.lighting_dpq:
		NCDT

		lh	t6,MPG4_n2(a2)			; Fetch mp_n2

		opt	at-
		and	t9,a3,s6			; And low 24-bits of primitive address
		sll	t8,t8,2				; Turn OT position into 32-bit OT offset
		add	t8,t8,s0			; t8 now points to ordering table entry
		lw	at,0(t8)			; Fetch current OT entry contents
		sw	t9,0(t8)			; Point OT entry to our current POLY_G4
		or	at,at,s7			
		sw	at,0(t9)			 					   
		opt	at+

		sll	t6,t6,3				; Turn mp_n2 index into SVECTOR offset
		add	t6,t6,a1			; t6 = normal 2 address

		swc2	C2_RGB0,PG4_rgb0(a3)		; Store RGB 0 (we need to stall NCDT in order to safely load new vertex 0)							

		lwc2	C2_VXY0,SVEC_vx(t6)		; Load vector 0 from normal 2
		lwc2	C2_VZ0,SVEC_vz(t6)

		swc2	C2_RGB1,PG4_rgb1(a3)		; Store RGB 1							
		swc2	C2_RGB2,PG4_rgb2(a3)		; Store RGB 2						

;		nop					; NOPS not needed as there are 2 instructions between load and RTPS				
;		nop
		NCDS
		
		beq	zero,zero,.store_final_rgb
		nop

.lighting_no_dpq:
		NCCT

		lh	t6,MPG4_n2(a2)			; Fetch mp_n2

		opt	at-
		and	t9,a3,s6			; And low 24-bits of primitive address
		sll	t8,t8,2				; Turn OT position into 32-bit OT offset
		add	t8,t8,s0			; t8 now points to ordering table entry
		lw	at,0(t8)			; Fetch current OT entry contents
		sw	t9,0(t8)			; Point OT entry to our current POLY_G4
		or	at,at,s7			 
		sw	at,0(t9)			 
		opt	at+

		sll	t6,t6,3				; Turn mp_n2 index into SVECTOR offset
		add	t6,t6,a1			; t6 = normal 2 address

		swc2	C2_RGB0,PG4_rgb0(a3)		; Store RGB 0 (we need to stall NCCT in order to safely load new vertex 0)							

		lwc2	C2_VXY0,SVEC_vx(t6)		; Load vector 0 from normal 2
		lwc2	C2_VZ0,SVEC_vz(t6)

		swc2	C2_RGB1,PG4_rgb1(a3)		; Store RGB 1							
		swc2	C2_RGB2,PG4_rgb2(a3)		; Store RGB 2						
		
;		nop					; NOPS not needed as there are 2 instructions between load and RTPS				
;		nop
		NCCS
		nop

.store_final_rgb:
		swc2	C2_RGB2,PG4_rgb3(a3)		; Store RGB							

.next_poly:						
		addi	s5,s5,-1			; Decrement primitive count
		addi	a2,a2,sizeof_MPG4		; Point to next MR_MPRIM_G4
		addi	a3,a3,sizeof_PG4		; Point to next POLY_G4
		bgtz	s5,.process_next_polygon	; If we've got to do more, then loop back
		addi	s8,s8,-1			; Adjust model primitive count in branch delay
							
.exit:				     			
		sw	a3,MP_mem_ptr(v0)		; Update p_mem_ptr in parameter block
		sw	a2,MP_prim_ptr(v0)		; Update p_prim_ptr in parameter block
		sw	s8,MP_prims(v0)			; Update p_prims in parameter block

		lw	s0, MESH_STACK_s0(sp)		; Restore registers from stack
		lw	s1, MESH_STACK_s1(sp)
		lw	s2, MESH_STACK_s2(sp)
		lw	s3, MESH_STACK_s3(sp)
		lw	s4, MESH_STACK_s4(sp)
		lw	s5, MESH_STACK_s5(sp)
		lw	s6, MESH_STACK_s6(sp)
		lw	s7, MESH_STACK_s7(sp)
		lw	s8, MESH_STACK_s8(sp)
		jr	ra
		addiu	sp, sp, sizeof_MESH_STACK

		end					



