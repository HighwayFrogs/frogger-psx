#;/******************************************************************************
#;/*%%%% mapasm.s
#;/*------------------------------------------------------------------------------
#;/*
#;/*	Polygon rendering routines for Frogger (PlayStation)
#;/*
#;/*	CHANGED		PROGRAMMER		REASON
#;/*	-------  	----------  	------
#;/*	03.07.97	Dean Ashton		Created
#;/*	XX.12.23	Kneesnap		Converted to GNU AS Syntax
#;/*
#;/*%%%**************************************************************************/

.include "macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

#/******************************************************************************
#/*%%%% MapRenderQuadsASM
#/*------------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MapRenderQuadsASM(
#/*				POLY_NODE*		poly_node,
#/*				MAP_RENDER_PARAMS*	params);
#/*
#/*	FUNCTION	Runs through all poly nodes, rotates polys, and adds them
#/*			to the viewport OT after texture mashing.
#/*
#/*	INPUTS		poly_node	-    (a0) Root node of quad list to process
#/*			params		-    (a1) Pointer to quad rendering info
#/*
#/*	NOTES		This function performs equivalent processing to that found
#/*			in mapdisp.c (MapRenderQuads)
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	03.07.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

#	a0	-	pointer to current polygon node
#	a1	-	pointer to rendering param block
#	a2	-	current prim pointer
#	a3	-	OT position 
#
#	v0	-	poly
#	v1	-	npolys
#
#	t0	-	
#	t1	-	
#	t2	-	
#	t3	-	
#	t4	-	
#	t5	-	
#	t6	-	
#	t7	-	
#	t8	-	
#	t9	-	
#
#	s0	-	current prim pointer x0 address
#	s1	-	current prim pointer x1 address
#	s2	-	current prim pointer x2 address
#	s3	-	current prim pointer x3 address
#	s4	-	pvert[0]
#	s5	-	pvert[1]	
#	s6	-	pvert[2]
#	s7	-	pvert[3]
#	s8	-	Map_vertices

# Handwritten function
func MapRenderQuadsASM
	addiu      $sp, $sp, -0x60  # Create a stack frame
	sw         $s0, 0x10($sp)   # Save registers on the stack
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	sw         $s3, 0x1C($sp)
	sw         $s4, 0x20($sp)
	sw         $s5, 0x24($sp)
	sw         $s6, 0x28($sp)
	sw         $s7, 0x2C($sp)
	sw         $fp, 0x30($sp)

	lw         $t0, 0x4($a1)
	lui        $t1, (0xFFFFFF >> 16)
	sra        $t0, $t0, 2
	ori        $t1, $t1, (0xFFFFFF & 0xFFFF)
	addiu      $t0, $t0, -0x1
	sll        $t0, $t0, 24
	sw         $t1, 0x54($sp)
	sw         $t0, 0x58($sp)
	lui        $fp, %hi(Map_vertices)
	ori        $fp, $fp, %lo(Map_vertices)
	lw         $fp, 0x0($fp)
	lui        $t1, %hi(MRVp_work_ot)
	lui        $t2, %hi(MRVp_ot_size)
	lui        $t3, %hi(MRVp_otz_shift)
	lui        $t4, %hi(MRTemp_svec)
	ori        $t1, $t1, %lo(MRVp_work_ot)
	ori        $t2, $t2, %lo(MRVp_ot_size)
	ori        $t3, $t3, %lo(MRVp_otz_shift)
	ori        $t4, $t4, %lo(MRTemp_svec)
	lw         $t1, 0x0($t1)
	lh         $t2, 0x0($t2)
	lh         $t3, 0x0($t3)
	sw         $t1, 0x48($sp)
	sw         $t2, 0x4C($sp)
	sw         $t3, 0x50($sp)
	sw         $t4, 0x5C($sp)
	lw         $t1, 0xC($a1)
	nop
	andi       $t1, $t1, 0x4
	beqz       $t1, .L80059BB4
	add        $a3, $zero, $zero # handwritten instruction
	lui        $t0, 0x80
	lui        $t1, %hi(Map_light_min_r2)
	ori        $t1, $t1, %lo(Map_light_min_r2)
	lw         $t2, 0x0($t1)
	lui        $t1, %hi(Map_light_max_r2)
	ori        $t1, $t1, %lo(Map_light_max_r2)
	lw         $t3, 0x0($t1)
	sw         $t2, 0x40($sp)
	sw         $t3, 0x44($sp)
	sub        $t1, $t3, $t2 # handwritten instruction
	divu       $zero, $t0, $t1
	nop
	mflo       $t0
	sw         $t0, 0x3C($sp)
.L80059BB4:
	lw         $a0, 0x0($a0)
	lui        $t0, %hi(MRFrame_index)
	beqz       $a0, .L8005A164
	ori        $t0, $t0, %lo(MRFrame_index)
	lw         $t1, 0x0($t0)
	addi       $t2, $a0, 0x10 # handwritten instruction
	sll        $t1, $t1, 2
	add        $t2, $t2, $t1 # handwritten instruction
	lw         $a2, 0x0($t2)
	lw         $v1, 0x8($a0)
	lw         $v0, 0xC($a0)
	beqz       $v1, .L80059BB4
	nop
	lw         $s0, 0x10($a1)
	lw         $t0, 0x8($a1)
	addu       $s0, $s0, $a2
	add        $s1, $s0, $t0 # handwritten instruction
	add        $s2, $s1, $t0 # handwritten instruction
	add        $s3, $s2, $t0 # handwritten instruction
	lhu        $s4, 0x0($v0)
	lhu        $s5, 0x2($v0)
	lhu        $s6, 0x4($v0)
	lhu        $s7, 0x6($v0)
	sll        $s4, $s4, 3
	sll        $s5, $s5, 3
	sll        $s6, $s6, 3
	sll        $s7, $s7, 3
	add        $s4, $fp, $s4 # handwritten instruction
	add        $s5, $fp, $s5 # handwritten instruction
	add        $s6, $fp, $s6 # handwritten instruction
	add        $s7, $fp, $s7 # handwritten instruction
.L80059C30:
	lw         $t0, 0xC($a1)
	nop
	andi       $t1, $t0, 0x4
	beqz       $t1, .L80059F30
	nop
	lh         $t3, 0x14($a1)
	lh         $t4, 0x16($a1)
	lh         $t5, 0x18($a1)
	lh         $t0, 0x0($s4)
	lh         $t1, 0x2($s4)
	lh         $t2, 0x4($s4)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L80059CB8
	lui        $t6, (0x808080 >> 16)
	b          .L80059D00
	ori        $t6, $t6, (0x808080 & 0xFFFF)
.L80059CB8:
	slt        $at, $t0, $t2
	bnez       $at, .L80059CCC
	add        $t6, $zero, $zero # handwritten instruction
	b          .L80059D00
	nop
.L80059CCC:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t6
.L80059D00:
	lh         $t0, 0x0($s5)
	lh         $t1, 0x2($s5)
	lh         $t2, 0x4($s5)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L80059D68
	lui        $t7, (0x808080 >> 16)
	b          .L80059DB0
	ori        $t7, $t7, (0x808080 & 0xFFFF)
.L80059D68:
	slt        $at, $t0, $t2
	bnez       $at, .L80059D7C
	add        $t7, $zero, $zero # handwritten instruction
	b          .L80059DB0
	nop
.L80059D7C:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t7
.L80059DB0:
	lh         $t0, 0x0($s6)
	lh         $t1, 0x2($s6)
	lh         $t2, 0x4($s6)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L80059E18
	lui        $t8, (0x808080 >> 16)
	b          .L80059E60
	ori        $t8, $t8, (0x808080 & 0xFFFF)
.L80059E18:
	slt        $at, $t0, $t2
	bnez       $at, .L80059E2C
	add        $t8, $zero, $zero # handwritten instruction
	b          .L80059E60
	nop
.L80059E2C:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t8
.L80059E60:
	lh         $t0, 0x0($s7)
	lh         $t1, 0x2($s7)
	lh         $t2, 0x4($s7)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L80059EC8
	lui        $t9, (0x808080 >> 16)
	b          .L80059F10
	ori        $t9, $t9, (0x808080 & 0xFFFF)
.L80059EC8:
	slt        $at, $t0, $t2
	bnez       $at, .L80059EDC
	add        $t9, $zero, $zero # handwritten instruction
	b          .L80059F10
	nop
.L80059EDC:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t9
.L80059F10:
	sb         $t6, -0x4($s0)
	sra        $t6, $t6, 8
	sw         $t7, -0x4($s1)
	sb         $t6, -0x3($s0)
	sra        $t6, $t6, 8
	sw         $t8, -0x4($s2)
	sb         $t6, -0x2($s0)
	sw         $t9, -0x4($s3)
.L80059F30:
	lw         $t0, 0xC($a1)
	add        $a3, $zero, $zero # handwritten instruction
	andi       $t0, $t0, 0x1
	beqz       $t0, .L8005A04C
	lhu        $t1, 0x8($v0)
	nop
	andi       $t2, $t1, 0x2
	beqz       $t2, .L8005A00C
	lw         $t0, 0x5C($sp)
	nop
	lh         $t3, 0x0($t0)
	lh         $t5, 0x4($t0)
	lh         $t2, 0x0($s4)
	lh         $t4, 0x4($s4)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s0)
	sb         $t4, 0x5($s0)
	lh         $t2, 0x0($s5)
	lh         $t4, 0x4($s5)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s1)
	sb         $t4, 0x5($s1)
	lh         $t2, 0x0($s6)
	lh         $t4, 0x4($s6)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s2)
	sb         $t4, 0x5($s2)
	lh         $t2, 0x0($s7)
	lh         $t4, 0x4($s7)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s3)
	sb         $t4, 0x5($s3)
	lw         $t3, 0x4C($sp)
	b          .L8005A020
	addi       $a3, $t3, -0x2 # handwritten instruction
.L8005A00C:
	andi       $t2, $t1, 0x4
	beqz       $t2, .L8005A020
	lw         $t3, 0x4C($sp)
	nop
	addi       $a3, $t3, -0x1 # handwritten instruction
.L8005A020:
	andi       $t2, $t1, 0x18
	beqz       $t2, .L8005A04C
	nop
	lw         $t0, 0xC($v0)
	lw         $t1, 0x10($v0)
	lhu        $t2, 0x14($v0)
	lhu        $t3, 0x16($v0)
	sw         $t0, 0x4($s0)
	sw         $t1, 0x4($s1)
	sh         $t2, 0x4($s2)
	sh         $t3, 0x4($s3)
.L8005A04C:
	lwc2       $0, 0x0($s4)
	lwc2       $1, 0x4($s4)
	lwc2       $2, 0x0($s5)
	lwc2       $3, 0x4($s5)
	lwc2       $4, 0x0($s6)
	lwc2       $5, 0x4($s6)
	lw         $t0, 0x0($a1)
	nop
	RTPT
	add        $v0, $v0, $t0 # handwritten instruction
	lhu        $s4, 0x0($v0)
	lhu        $s5, 0x2($v0)
	lhu        $s6, 0x4($v0)
	sll        $s4, $s4, 3
	sll        $s5, $s5, 3
	sll        $s6, $s6, 3
	add        $s4, $fp, $s4 # handwritten instruction
	add        $s5, $fp, $s5 # handwritten instruction
	add        $s6, $fp, $s6 # handwritten instruction
	NCLIP
	lwc2       $0, 0x0($s7)
	lwc2       $1, 0x4($s7)
	mfc2       $t0, $24 # handwritten instruction
	swc2       $12, 0x0($s0)
	RTPS
	lhu        $s7, 0x6($v0)
	nop
	sll        $s7, $s7, 3
	bgtz       $t0, .L8005A0D8
	add        $s7, $fp, $s7 # handwritten instruction
	NCLIP
	mfc2       $t0, $24 # handwritten instruction
	nop
	bgez       $t0, .L8005A13C
	nop
.L8005A0D8:
	swc2       $12, 0x0($s1)
	swc2       $13, 0x0($s2)
	swc2       $14, 0x0($s3)
	bne        $zero, $a3, .L8005A114
	ori        $t2, $zero, 0x10
	AVSZ4
	mfc2       $a3, $7 # handwritten instruction
	lw         $t1, 0x50($sp)
	slt        $at, $t2, $a3
	beqz       $at, .L8005A13C
	lw         $t0, 0x4C($sp)
	srav       $a3, $a3, $t1
	addi       $a3, $a3, 0x40 # handwritten instruction
	slt        $at, $a3, $t0
	beqz       $at, .L8005A13C
.L8005A114:
	lw         $t2, 0x58($sp)
	lw         $t1, 0x54($sp)
	lw         $t0, 0x48($sp)
	and        $t9, $a2, $t1
	sll        $a3, $a3, 2
	add        $a3, $a3, $t0 # handwritten instruction
	lw         $at, 0x0($a3)
	sw         $t9, 0x0($a3)
	or         $at, $at, $t2
	sw         $at, 0x0($t9)
.L8005A13C:
	lw         $t0, 0x4($a1)
	addi       $v1, $v1, -0x1 # handwritten instruction
	add        $s0, $s0, $t0 # handwritten instruction
	add        $s1, $s1, $t0 # handwritten instruction
	add        $s2, $s2, $t0 # handwritten instruction
	add        $s3, $s3, $t0 # handwritten instruction
	bgtz       $v1, .L80059C30
	add        $a2, $a2, $t0 # handwritten instruction
	b          .L80059BB4
	nop
.L8005A164:
	lw         $s0, 0x10($sp)
	lw         $s1, 0x14($sp)
	lw         $s2, 0x18($sp)
	lw         $s3, 0x1C($sp)
	lw         $s4, 0x20($sp)
	lw         $s5, 0x24($sp)
	lw         $s6, 0x28($sp)
	lw         $s7, 0x2C($sp)
	lw         $fp, 0x30($sp)
	jr         $ra
	addiu      $sp, $sp, 0x60

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
func MapRenderTrisASM
	addiu      $sp, $sp, -0x60
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	sw         $s3, 0x1C($sp)
	sw         $s4, 0x20($sp)
	sw         $s5, 0x24($sp)
	sw         $s6, 0x28($sp)
	sw         $s7, 0x2C($sp)
	sw         $fp, 0x30($sp)
	lw         $t0, 0x4($a1)
	lui        $t1, (0xFFFFFF >> 16)
	sra        $t0, $t0, 2
	ori        $t1, $t1, (0xFFFFFF & 0xFFFF)
	addiu      $t0, $t0, -0x1
	sll        $t0, $t0, 24
	sw         $t1, 0x54($sp)
	sw         $t0, 0x58($sp)
	lui        $fp, %hi(Map_vertices)
	ori        $fp, $fp, %lo(Map_vertices)
	lw         $fp, 0x0($fp)
	lui        $t1, %hi(MRVp_work_ot)
	lui        $t2, %hi(MRVp_ot_size)
	lui        $t3, %hi(MRVp_otz_shift)
	lui        $t4, %hi(MRTemp_svec)
	ori        $t1, $t1, %lo(MRVp_work_ot)
	ori        $t2, $t2, %lo(MRVp_ot_size)
	ori        $t3, $t3, %lo(MRVp_otz_shift)
	ori        $t4, $t4, %lo(MRTemp_svec)
	lw         $t1, 0x0($t1)
	lh         $t2, 0x0($t2)
	lh         $t3, 0x0($t3)
	sw         $t1, 0x48($sp)
	sw         $t2, 0x4C($sp)
	sw         $t3, 0x50($sp)
	sw         $t4, 0x5C($sp)
	lw         $t1, 0xC($a1)
	nop
	andi       $t1, $t1, 0x4
	beqz       $t1, .L8005A26C
	add        $a3, $zero, $zero # handwritten instruction
	lui        $t0, 0x80
	lui        $t1, %hi(Map_light_min_r2)
	ori        $t1, $t1, %lo(Map_light_min_r2)
	lw         $t2, 0x0($t1)
	lui        $t1, %hi(Map_light_max_r2)
	ori        $t1, $t1, %lo(Map_light_max_r2)
	lw         $t3, 0x0($t1)
	sw         $t2, 0x40($sp)
	sw         $t3, 0x44($sp)
	sub        $t1, $t3, $t2 # handwritten instruction
	divu       $zero, $t0, $t1
	nop
	mflo       $t0
	sw         $t0, 0x3C($sp)
.L8005A26C:
	lw         $a0, 0x0($a0)
	lui        $t0, %hi(MRFrame_index)
	beqz       $a0, .L8005A6F8
	ori        $t0, $t0, %lo(MRFrame_index)
	lw         $t1, 0x0($t0)
	addi       $t2, $a0, 0x10 # handwritten instruction
	sll        $t1, $t1, 2
	add        $t2, $t2, $t1 # handwritten instruction
	lw         $a2, 0x0($t2)
	lw         $v1, 0x8($a0)
	lw         $v0, 0xC($a0)
	beqz       $v1, .L8005A26C
	nop
	lw         $s0, 0x10($a1)
	lw         $t0, 0x8($a1)
	addu       $s0, $s0, $a2
	add        $s1, $s0, $t0 # handwritten instruction
	add        $s2, $s1, $t0 # handwritten instruction
	lhu        $s4, 0x0($v0)
	lhu        $s5, 0x2($v0)
	lhu        $s6, 0x4($v0)
	sll        $s4, $s4, 3
	sll        $s5, $s5, 3
	sll        $s6, $s6, 3
	add        $s4, $fp, $s4 # handwritten instruction
	add        $s5, $fp, $s5 # handwritten instruction
	add        $s6, $fp, $s6 # handwritten instruction
.L8005A2D8:
	lw         $t0, 0xC($a1)
	nop
	andi       $t1, $t0, 0x4
	beqz       $t1, .L8005A524
	nop
	lh         $t3, 0x14($a1)
	lh         $t4, 0x16($a1)
	lh         $t5, 0x18($a1)
	lh         $t0, 0x0($s4)
	lh         $t1, 0x2($s4)
	lh         $t2, 0x4($s4)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L8005A360
	lui        $t6, (0x808080 >> 16)
	b          .L8005A3A8
	ori        $t6, $t6, (0x808080 & 0xFFFF)
.L8005A360:
	slt        $at, $t0, $t2
	bnez       $at, .L8005A374
	add       $t6, $zero, $zero # handwritten instruction
	b          .L8005A3A8
	nop
.L8005A374:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t6
.L8005A3A8:
	lh         $t0, 0x0($s5)
	lh         $t1, 0x2($s5)
	lh         $t2, 0x4($s5)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L8005A410
	lui        $t7, (0x808080 >> 16)
	b          .L8005A458
	ori        $t7, $t7, (0x808080 & 0xFFFF)
.L8005A410:
	slt        $at, $t0, $t2
	bnez       $at, .L8005A424
	add        $t7, $zero, $zero # handwritten instruction
	b          .L8005A458
	nop
.L8005A424:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t7
.L8005A458:
	lh         $t0, 0x0($s6)
	lh         $t1, 0x2($s6)
	lh         $t2, 0x4($s6)
	sub        $t0, $t0, $t3 # handwritten instruction
	sub        $t1, $t1, $t4 # handwritten instruction
	sub        $t2, $t2, $t5 # handwritten instruction
	andi       $t0, $t0, 0xFFFF
	sll        $t1, $t1, 16
	andi       $t2, $t2, 0xFFFF
	or         $t0, $t0, $t1
	ctc2       $t2, $9 # handwritten instruction
	ctc2       $t0, $8 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	mtc2       $t0, $0 # handwritten instruction
	nop
	nop
	MVMVA      0, 1, 0, 3, 0
	lw         $t1, 0x40($sp)
	lw         $t2, 0x44($sp)
	mfc2       $t0, $25 # handwritten instruction
	nop
	slt        $at, $t0, $t1
	beqz       $at, .L8005A4C0
	lui        $t8, (0x808080 >> 16)
	b          .L8005A508
	ori        $t8, $t8, (0x808080 & 0xFFFF)
.L8005A4C0:
	slt        $at, $t0, $t2
	bnez       $at, .L8005A4D4
	add        $t8, $zero, $zero # handwritten instruction
	b          .L8005A508
	nop
.L8005A4D4:
	sub        $t0, $t0, $t1 # handwritten instruction
	lw         $t2, 0x3C($sp)
	ori        $t1, $zero, 0x80
	mult       $t0, $t2
	nop
	mflo       $t0
	lui        $t2, (0x10101 >> 16)
	sra        $t0, $t0, 16
	ori        $t2, $t2, (0x10101 & 0xFFFF)
	sub        $t1, $t1, $t0 # handwritten instruction
	mult       $t1, $t2
	nop
	mflo       $t8
.L8005A508:
	sb         $t6, -0x4($s0)
	sra        $t6, $t6, 8
	sw         $t7, -0x4($s1)
	sb         $t6, -0x3($s0)
	sra        $t6, $t6, 8
	sw         $t8, -0x4($s2)
	sb         $t6, -0x2($s0)
.L8005A524:
	lw         $t0, 0xC($a1)
	add        $a3, $zero, $zero # handwritten instruction
	andi       $t0, $t0, 0x1
	beqz       $t0, .L8005A610
	lhu        $t1, 0x8($v0)
	nop
	andi       $t2, $t1, 0x2
	beqz       $t2, .L8005A5D8
	lw         $t0, 0x5C($sp)
	nop
	lh         $t3, 0x0($t0)
	lh         $t5, 0x4($t0)
	lh         $t2, 0x0($s4)
	lh         $t4, 0x4($s4)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s0)
	sb         $t4, 0x5($s0)
	lh         $t2, 0x0($s5)
	lh         $t4, 0x4($s5)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s1)
	sb         $t4, 0x5($s1)
	lh         $t2, 0x0($s6)
	lh         $t4, 0x4($s6)
	add        $t2, $t2, $t3 # handwritten instruction
	add        $t4, $t4, $t5 # handwritten instruction
	sra        $t2, $t2, 5
	sra        $t4, $t4, 5
	addi       $t2, $t2, 0x80 # handwritten instruction
	addi       $t4, $t4, 0x80 # handwritten instruction
	sb         $t2, 0x4($s2)
	sb         $t4, 0x5($s2)
	lw         $t3, 0x4C($sp)
	b          .L8005A5EC
	addi       $a3, $t3, -0x2 # handwritten instruction
.L8005A5D8:
	andi       $t2, $t1, 0x4
	beqz       $t2, .L8005A5EC
	lw         $t3, 0x4C($sp)
	nop
	addi       $a3, $t3, -0x1 # handwritten instruction
.L8005A5EC:
	andi       $t2, $t1, 0x18
	beqz       $t2, .L8005A610
	nop
	lw         $t0, 0xC($v0)
	lw         $t1, 0x10($v0)
	lhu        $t2, 0x14($v0)
	sw         $t0, 0x4($s0)
	sw         $t1, 0x4($s1)
	sh         $t2, 0x4($s2)
.L8005A610:
	lwc2       $0, 0x0($s4)
	lwc2       $1, 0x4($s4)
	lwc2       $2, 0x0($s5)
	lwc2       $3, 0x4($s5)
	lwc2       $4, 0x0($s6)
	lwc2       $5, 0x4($s6)
	lw         $t0, 0x0($a1)
	nop
	RTPT
	add        $v0, $v0, $t0 # handwritten instruction
	lhu        $s4, 0x0($v0)
	lhu        $s5, 0x2($v0)
	lhu        $s6, 0x4($v0)
	sll        $s4, $s4, 3
	sll        $s5, $s5, 3
	sll        $s6, $s6, 3
	add        $s4, $fp, $s4 # handwritten instruction
	add        $s5, $fp, $s5 # handwritten instruction
	add        $s6, $fp, $s6 # handwritten instruction
	NCLIP
	mfc2       $t0, $24 # handwritten instruction
	nop
	blez       $t0, .L8005A6D4
	nop
	swc2       $12, 0x0($s0)
	swc2       $13, 0x0($s1)
	swc2       $14, 0x0($s2)
	bne        $zero, $a3, .L8005A6AC
	ori        $t2, $zero, 0x10
	AVSZ3
	mfc2       $a3, $7 # handwritten instruction
	lw         $t1, 0x50($sp)
	slt        $at, $t2, $a3
	beqz       $at, .L8005A6D4
	lw         $t0, 0x4C($sp)
	srav       $a3, $a3, $t1
	addi       $a3, $a3, 0x40 # handwritten instruction
	slt        $at, $a3, $t0
	beqz       $at, .L8005A6D4
.L8005A6AC:
	lw         $t2, 0x58($sp)
	lw         $t1, 0x54($sp)
	lw         $t0, 0x48($sp)
	and        $t9, $a2, $t1
	sll        $a3, $a3, 2
	add        $a3, $a3, $t0 # handwritten instruction
	lw         $at, 0x0($a3)
	sw         $t9, 0x0($a3)
	or         $at, $at, $t2
	sw         $at, 0x0($t9)
.L8005A6D4:
	lw         $t0, 0x4($a1)
	addi       $v1, $v1, -0x1 # handwritten instruction
	add        $s0, $s0, $t0 # handwritten instruction
	add        $s1, $s1, $t0 # handwritten instruction
	add        $s2, $s2, $t0 # handwritten instruction
	bgtz       $v1, .L8005A2D8
	add        $a2, $a2, $t0 # handwritten instruction
	b          .L8005A26C
	nop
.L8005A6F8:
	lw         $s0, 0x10($sp)
	lw         $s1, 0x14($sp)
	lw         $s2, 0x18($sp)
	lw         $s3, 0x1C($sp)
	lw         $s4, 0x20($sp)
	lw         $s5, 0x24($sp)
	lw         $s6, 0x28($sp)
	lw         $s7, 0x2C($sp)
	lw         $fp, 0x30($sp)
	jr         $ra
	addiu     $sp, $sp, 0x60
