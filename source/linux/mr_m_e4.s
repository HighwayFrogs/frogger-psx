#/******************************************************************************
#/*%%%% mr_m_e4.s
#/*------------------------------------------------------------------------------
#/*
#/*	Polygon rendering routines for environment mapped quadrilateral groups
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	13.06.97	Dean Ashton		Created
#/*	??.11.23	Kneesnap		Created GNU Assembler version
#/*	20.03.25	Kneesnap		Improved GNU Assembler version readibility
#/*
#/*%%%**************************************************************************/

.include		"mr_m_hdr.i"

.set noat      # allow manual use of $at
.set noreorder # don't insert nops after branches

#/******************************************************************************
#/*%%%% MRDisplayMeshPolys_E4
#/*------------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRDisplayMeshPolys_E4(
#/*				MR_SVEC*	vert_ptr,
#/*				MR_SVEC*	norm_ptr,
#/*				MR_ULONG*	prim_ptr,
#/*				MR_ULONG*	mem_ptr,
#/*				MR_MESH_PARAM*	param_ptr,
#/*				MR_BOOL		light_dpq);
#/*
#/*	FUNCTION	Performs high-speed geometry calculations for a block of
#/*			MR_MPRIM_E4 primitives (env mapped quadrilaterals).
#/*
#/*	INPUTS		vert_ptr	-    (a0) Pointer to vertex block
#/*			norm_ptr	-    (a1) Pointer to normal block
#/*			prim_ptr	-    (a2) Pointer to MR_MPRIM_E4 block	
#/*			mem_ptr		-    (a3) Pointer to primitive buffer memory
#/*			param_ptr	- $10(sp) Pointer to mesh parameter block	
#/*			light_dpq	- $14(sp) TRUE if using depth queuing
#/*
#/*	NOTES		This function performs equivalent processing to that found
#/*			in mr_p_e4.c, with the exception that this doesn't clip
#/*			to the display.
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	18.9.96		Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

#// Register usage
#
#a0 = vertex ptr
#a1 = normal ptr
#a2 = mprim ptr
#a3 = mem ptr
#
#v0 = param block ptr
#v1 = depth queueing flag
#
#t0 = temp for vertex 0
#t1 = temp for vertex 1
#t2 = temp for vertex 2
#t3 = temp for vertex 3
#
#t4 = work
#t5 = work
#t6 = work
#t7 = work
#t8 = work
#t9 = work
#
#s0 = ot pointer
#s1 = otz shift
#s2 = ot size
#s3 = ot clip
#s4 = otz delta
#s5 = primitive count

#s6 = ot 'and' mask (stacked, and fetched again after u/v offset calculations
#s7 = ot 'or' mask

#s8 = model primitive count 

# ---------------------------------------------------------------------------------------------
glabel MRDisplayMeshPolys_E4
	lw         $v0, 0x10($sp) # Get param_ptr
	lw         $v1, 0x14($sp) # Get light_dpq

.Lstack_saved_registers:
	addiu      $sp, $sp, -sizeof_MESH_ENVSTACK # Create a stack frame
	sw         $s0, MESH_ENVSTACK_s0($sp) #  registers on the stack
	sw         $s1, MESH_ENVSTACK_s1($sp)
	sw         $s2, MESH_ENVSTACK_s2($sp)
	sw         $s3, MESH_ENVSTACK_s3($sp)
	sw         $s4, MESH_ENVSTACK_s4($sp)
	sw         $s5, MESH_ENVSTACK_s5($sp)
	sw         $s6, MESH_ENVSTACK_s6($sp)
	sw         $s7, MESH_ENVSTACK_s7($sp)
	sw         $s8, MESH_ENVSTACK_s8($sp)

.Lcalculate_common_registers:
	lw         $s0, MP_work_ot($v0)
	lh         $s1, MP_otz_shift($v0)
	lw         $s2, MP_ot_size($v0)
	lw         $s3, MP_ot_clip($v0)
	lh         $s4, MP_ot_otz_delta($v0)

.Lcalculate_loop_iterations:
	addi       $s5, $a2, -4 # s5 points to previous word in prim block
	lw         $s5, 0($s5) # Fetch word containing primitive count
	nop
	sra        $s5, $s5, 16 # High word contains count, so shift down

.Lcalculate_addprim_masks:
	lui        $s6, (0xFFFFFF >> 16) # s6 = $00ffffff	
	ori        $s6, $s6, %lo(0xFFFFFF)
	lui        $s7, primsize_PFT4 << 8 # s7 = primitive packet length in upper 8 bits

	sw         $s6, MESH_ENVSTACK_ot_and($sp) # We have to save s6 and s7, because we need the
	sw         $s7, MESH_ENVSTACK_ot_or($sp) # registers later on for environment mapping calcs.

.Lcalculate_uofs_vofs:
	lui        $t9, %hi(MREnv_strip) # Environment map image should be 129x129 with
	lui        $at, 0
	addu       $at, $at, $t9
	lw         $t5, %lo(MREnv_strip)($at) # pixel edge duplication enabled.
	nop
	lbu        $s6, TEX_u0($t5)
	lbu        $s7, TEX_v0($t5)
	addiu      $s6, $s6, 64
	addiu      $s7, $s7, 64
	sw         $s6, MESH_ENVSTACK_uofs($sp)
	sw         $s7, MESH_ENVSTACK_vofs($sp)

.Lcalculate_model_primitive_count:
	lw         $s8, MP_prims($v0)

.Lprecalculate_first_vertices:
	lh         $t0, MPE4_p0($a2) # Fetch mp_p0
	lh         $t1, MPE4_p1($a2) # Fetch mp_p1
	lh         $t2, MPE4_p2($a2) # Fetch mp_p2
	lh         $t3, MPE4_p3($a2) # Fetch mp_p3

	sll        $t0, $t0, 3 # Turn mp_p0 index into SVECTOR offset
	sll        $t1, $t1, 3 # Turn mp_p1 index into SVECTOR offset
	sll        $t2, $t2, 3 # Turn mp_p2 index into SVECTOR offset
	sll        $t3, $t3, 3 # Turn mp_p3 index into SVECTOR offset

	add        $t0, $t0, $a0 # t0 = vertex 0 address
	add        $t1, $t1, $a0 # t1 = vertex 1 address
	add        $t2, $t2, $a0 # t2 = vertex 2 address
	add        $t3, $t3, $a0 # t3 = vertex 3 address

.Lprocess_next_polygon:
	lwc2       C2_VXY0, SVEC_vx($t0) # Load vector 0 from vertex 0
	lwc2       C2_VZ0, SVEC_vz($t0)
	lwc2       C2_VXY1, SVEC_vx($t1) # Load vector 1 from vertex 1
	lwc2       C2_VZ1, SVEC_vz($t1)
	lwc2       C2_VXY2, SVEC_vx($t3) # Load vector 2 from vertex 3
	lwc2       C2_VZ2, SVEC_vz($t3)
	addi       $t8, $a2, sizeof_MPE4 # DELAY: t8 points to next MR_MPRIM_E4 structure
	nop
	RTPT       # Rotate 3 vertices

.Lprecalculate_next_vertices:
	lh         $t0, MPE4_p0($t8) # Fetch next mp_p0
	lh         $t1, MPE4_p1($t8) # Fetch next mp_p1
	lh         $t3, MPE4_p3($t8) # Fetch next mp_p3

	sll        $t0, $t0, 3 # Turn next mp_p0 index into SVECTOR offset
	sll        $t1, $t1, 3 # Turn next mp_p1 index into SVECTOR offset
	sll        $t3, $t3, 3 # Turn next mp_p3 index into SVECTOR offset

	add        $t0, $t0, $a0 # t0 = next vertex 0 address
	add        $t1, $t1, $a0 # t1 = next vertex 1 address
	add        $t3, $t3, $a0 # t3 = next vertex 3 address

.Lnormal_clip:
	NCLIP      # NCLIP coordinates in SXY FIFO 
	lwc2       C2_VXY0, SVEC_vx($t2) # Load vector 0 from vertex 2 (in delay slots)
	lwc2       C2_VZ0, SVEC_vz($t2)

	mfc2       $t9, C2_MAC0 # Fetch first NCLIP result

	swc2       C2_SXY0, PFT4_x0($a3) # Store XY0, as it will be pushed out of fifo by vertex 2
	RTPS       # Rotate vertex 2

	lwc2       C2_RGB, MPE4_cvec($a2) # DELAY: Load RGB in RTPS delay slots

	lh         $t2, MPE4_p2($t8) # Fetch next mp_p2
	nop
	sll        $t2, $t2, 3 # Turn mp_p2 index into SVECTOR offset

	bgtz       $t9, .Lprocess_poly # NCLIP result > 0 means we want this polygon
	add        $t2, $t2, $a0 # DELAY: t2 = vertex 2 address

	NCLIP      # First triangle failed NCLIP, so we do the second
	mfc2       $t9, C2_MAC0 # one. If that fails also, then we bin the polygon
	nop        # (Note that failure is >= 0, as FIFO points are in a screwy order)
	bgez       $t9, .Lnext_poly
	nop

.Lprocess_poly:
	AVSZ4      # Average the SZ0/SZ1/SZ2/SZ3 points in the FIFO
	lh         $t4, MPE4_en0($a2) # DELAY: Fetch mp_en0
	mfc2       $t8, C2_OTZ # Fetch OTZ
	sll        $t4, $t4, 3 # DELAY: Turn mp_en0 index into SVECTOR offset
	srav       $t8, $t8, $s1 # Shift down OTZ
	add        $t8, $t8, $s4 # Add OTZ delta

.Lclip_polygon:
	slt        $at, $t8, $s3
	bnez       $at, .Lnext_poly # If t8 < s2, bail (near clip)
	add        $t4, $t4, $a1 # DELAY: t4 = normal 0 address
	slt        $at, $t8, $s2
	beqz       $at, .Lnext_poly # If t8 >= s2, bail (far clip)
	nop

	swc2       C2_SXY0, PFT4_x1($a3) # Store XY coordinates for each remaining vertex
	swc2       C2_SXY1, PFT4_x2($a3)
	swc2       C2_SXY2, PFT4_x3($a3)

		# --- Start of environment mapping code ---
	lui        $t9, %hi(MRWorldtrans_ptr) # Set GTE rotation matrix to that pointed at by MRWorldtrans_ptr
	lui        $at, 0
	addu       $at, $at, $t9
	lw         $t5, %lo(MRWorldtrans_ptr)($at)
	nop
	lw         $t6, MAT_r11r12($t5)
	lw         $t7, MAT_r13r21($t5)
	ctc2       $t6, C2_R11R12
	ctc2       $t7, C2_R13R21
	lw         $t6, MAT_r22r23($t5)
	lw         $t7, MAT_r31r32($t5)
	lw         $t9, MAT_r33pad($t5)
	ctc2       $t6, C2_R22R23
	ctc2       $t7, C2_R31R32
	ctc2       $t9, C2_R33

	# Handle normal 0
	lwc2       C2_VXY0, SVEC_vx($t4) # Load vector 0 from normal 0
	lwc2       C2_VZ0, SVEC_vz($t4)
	lw         $s6, MESH_ENVSTACK_uofs($sp) # DELAY: Fetch 'uofs'
	lw         $s7, MESH_ENVSTACK_vofs($sp) # DELAY: Fetch 'vofs'
	MVMVA      1, 0, 0, 3, 0 # Equivalent of a RotTrans of vector 0

	lh         $t4, MPE4_en1($a2) # DELAY: Fetch mp_en1
	nop        # DELAY:
	sll        $t4, $t4, 3 # DELAY: Turn mp_en1 index into SVECTOR offset
	add        $t4, $t4, $a1 # DELAY: t4 = normal 1 address

	lwc2       $2, SVEC_vx($t4) # DELAY: Load vector 1 from normal 1
	lwc2       $3, SVEC_vz($t4) # DELAY: while we're processing using vector 0.

	mfc2       $t5, C2_MAC1 # Fetch vx
	nop
	sra        $t5, $t5, 6 # Equiv. vx>>6
	add        $t5, $t5, $s6 # Add 'uofs' (is in bits 0-7)

	mfc2       $t6, C2_MAC2 # Fetch vy
	nop
	sub        $t6, $zero, $t6 # Negate it
	sra        $t6, $t6, 6 # Equiv. vy>>6
	add        $t6, $t6, $s7 # Add 'vofs'
	sll        $t6, $t6, 8 # Shift into bits 8-15
	add        $t5, $t6, $t5 # Now t5 = ((vx>>6)+uofs) + ((-vy>>6)+vofs)<<8))
	sh         $t5, PFT4_u0($a3) # Store new u0/v0 in polygon (low 16-bits of t5)

	# Handle normal 1
	MVMVA      1, 0, 1, 3, 0 # Equivalent of a RotTrans of vector 1

	lh         $t4, MPE4_en2($a2) # DELAY: Fetch mp_en2
	nop        # DELAY:
	sll        $t4, $t4, 3 # DELAY: Turn mp_en2 index into SVECTOR offset
	add        $t4, $t4, $a1 # DELAY: t4 = normal 2 address

	lwc2       C2_VXY0, SVEC_vx($t4) # DELAY: Load vector 0 from normal 2
	lwc2       C2_VZ0, SVEC_vz($t4) # DELAY: While we're processing using vector 1

	mfc2       $t5, C2_MAC1 # Fetch vx
	nop
	sra        $t5, $t5, 6 # Equiv. vx>>6
	add        $t5, $t5, $s6 # Add 'uofs' (is in bits 0-7)

	mfc2       $t6, C2_MAC2 # Fetch vy
	nop
	sub        $t6, $zero, $t6 # Negate it
	sra        $t6, $t6, 6 # Equiv. vy>>6
	add        $t6, $t6, $s7 # Add 'vofs'
	sll        $t6, $t6, 8 # Shift into bits 8-15
	add        $t5, $t6, $t5 # Now t5 = ((vx>>6)+uofs) + ((-vy>>6)+vofs)<<8))
	sh         $t5, PFT4_u1($a3) # Store new u1/v1 in polygon (low 16-bits of t5)

	# Handle normal 2
	MVMVA      1, 0, 0, 3, 0 # Equivalent of a RotTrans of vector 0

	lh         $t4, MPE4_en3($a2) # DELAY: Fetch mp_en3
	nop        # DELAY:
	sll        $t4, $t4, 3 # DELAY: Turn mp_en3 index into SVECTOR offset
	add        $t4, $t4, $a1 # DELAY: t4 = normal 3 address

	lwc2       C2_VXY1, SVEC_vx($t4) # DELAY: Load vector 1 from normal 3
	lwc2       C2_VZ1, SVEC_vz($t4) # DELAY: while we're processing using vector 0

	mfc2       $t5, C2_MAC1 # Fetch vx
	nop
	sra        $t5, $t5, 6 # Equiv. vx>>6
	add        $t5, $t5, $s6 # Add 'uofs' (is in bits 0-7)

	mfc2       $t6, C2_MAC2 # Fetch vy
	nop
	sub        $t6, $zero, $t6 # Negate it
	sra        $t6, $t6, 6 # Equiv. vy>>6
	add        $t6, $t6, $s7 # Add 'vofs'
	sll        $t6, $t6, 8 # Shift into bits 8-15
	add        $t5, $t6, $t5 # Now t5 = ((vx>>6)+uofs) + ((-vy>>6)+vofs)<<8))
	sh         $t5, PFT4_u3($a3) # Store new u3/v3 in polygon (low 16-bits of t5)

	# Handle normal 3
	MVMVA      1, 0, 1, 3, 0 # Equivalent of a RotTrans of vector 1

	lh         $t4, MPE4_n0($a2) # DELAY: Fetch mp_n0 (for lighting)
	nop        # DELAY:
	sll        $t4, $t4, 3 # DELAY: Turn mp_n0 index into SVECTOR offset
	add        $t4, $t4, $a1 # DELAY: t4 = normal 0 address

	lwc2       C2_VXY0, SVEC_vx($t4) # DELAY: Load vector 0 from normal 0
	lwc2       C2_VZ0, SVEC_vz($t4) # DELAY: for lighting after envmap processing

	mfc2       $t5, C2_MAC1 # Fetch vx
	nop
	sra        $t5, $t5, 6 # Equiv. vx>>6
	add        $t5, $t5, $s6 # Add 'uofs' (is in bits 0-7)

	mfc2       $t6, C2_MAC2 # Fetch vy
	nop
	sub        $t6, $zero, $t6 # Negate it
	sra        $t6, $t6, 6 # Equiv. vy>>6
	add        $t6, $t6, $s7 # Add 'vofs'
	sll        $t6, $t6, 8 # Shift into bits 8-15
	add        $t5, $t6, $t5 # Now t5 = ((vx>>6)+uofs) + ((-vy>>6)+vofs)<<8))
	sh         $t5, PFT4_u2($a3) # Store new u2/v2 in polygon (low 16-bits of t5)

	# Restore rotation matrix
	lui        $t9, %hi(MRViewtrans_ptr) # Set GTE rotation matrix to that pointer at by MRViewtrans_ptr
	lui        $at, 0
	addu       $at, $at, $t9
	lw         $t5, %lo(MRViewtrans_ptr)($at)
	nop
	lw         $t6, MAT_r11r12($t5)
	lw         $t7, MAT_r13r21($t5)
	ctc2       $t6, C2_R11R12
	ctc2       $t7, C2_R13R21
	lw         $t6, MAT_r22r23($t5)
	lw         $t7, MAT_r31r32($t5)
	lw         $t9, MAT_r33pad($t5)
	ctc2       $t6, C2_R22R23
	ctc2       $t7, C2_R31R32
	ctc2       $t9, C2_R33
	# --- End of environment mapping code ---

	beq        $zero, $v1, .Llightning_no_dpq # If light_dpq == FALSE, then no depth queuing
	nop

.Llightning_dpq:
	NCDS
	b          .Ladd_polygon
	nop

.Llightning_no_dpq:
	NCCS

.Ladd_polygon:
	lw         $s6, MESH_ENVSTACK_ot_and($sp)
	lw         $s7, MESH_ENVSTACK_ot_or($sp)

	and        $t9, $a3, $s6 # low 24-bits of primitive address
	sll        $t8, $t8, 2 # Turn OT position into 32-bit OT offset
	add        $t8, $t8, $s0 # t8 now points to ordering table entry
	lw         $at, 0($t8) # Fetch current OT entry contents
	sw         $t9, 0($t8) # Point OT entry to our current POLY_FT4
	or         $at, $at, $s7
	sw         $at, 0($t9)

	swc2       C2_RGB2, PFT4_rgb($a3) # Store RGB

.Lnext_poly:
	addi       $s5, $s5, -1 # Decrement primitive count
	addi       $a2, $a2, sizeof_MPE4 # Point to next MR_MPRIM_E4
	addi       $a3, $a3, sizeof_PFT4 # Point to next POLY_FT4
	bgtz       $s5, .Lprocess_next_polygon # If we've got to do more, then loop back
	addi      $s8, $s8, -1 # Adjust model primitive count in branch delay

.Lexit:
	sw         $a3, MP_mem_ptr($v0) # Update p_mem_ptr in parameter block
	sw         $a2, MP_prim_ptr($v0) # Update p_prim_ptr in parameter block
	sw         $s8, MP_prims($v0) # Update p_prims in parameter block

	lw         $s0, MESH_ENVSTACK_s0($sp) # Restore registers from stack
	lw         $s1, MESH_ENVSTACK_s1($sp)
	lw         $s2, MESH_ENVSTACK_s2($sp)
	lw         $s3, MESH_ENVSTACK_s3($sp)
	lw         $s4, MESH_ENVSTACK_s4($sp)
	lw         $s5, MESH_ENVSTACK_s5($sp)
	lw         $s6, MESH_ENVSTACK_s6($sp)
	lw         $s7, MESH_ENVSTACK_s7($sp)
	lw         $s8, MESH_ENVSTACK_s8($sp)
	jr         $ra
	addiu      $sp, $sp, sizeof_MESH_ENVSTACK
