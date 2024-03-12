#/******************************************************************************
#/*%%%% mr_m_qua.s
#/*-----------------------------------------------------------------------------
#/*
#/*	Quaternion Functions (MIPS Versions)
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	20.03.97	Dean Ashton		Created
#/*	12.06.97	Tim Closs		MRInterpolateQuaternionsASM() no longer assumes
#/*						MR_QUAT is long-aligned
#/*						(due to existence of MR_QUAT_TRANS structure)
#/*	23.23.11	Kneesnap		Ported to GNU AS Syntax
#/*
#/*%%%**************************************************************************/

		.include	"macro.inc"
		.text

#/******************************************************************************
#/*%%%% MRQuaternionToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRQuaternionToMatrixASM(
#/*				MR_QUAT*	q,
#/*				MR_MAT*		m);
#/*
#/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
#/*
#/*	INPUTS		q	- (a0)	Pointer to quaternion (1.3.12 format)
#/*			m	- (a1)	Pointer to matrix to fill in
#/*
#/*	NOTES		Be careful when modifying this routine, it's pipelined to
#/*			hell, and uses an odd register layout (effectively trashing
#/*			one of the input argument pointers).
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	21.03.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRQuaternionToMatrixASM
	addiu      $sp, $sp, -0x1C
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	lh         $v0, 0x0($a0)
	lh         $v1, 0x2($a0)
	lh         $at, 0x4($a0)
	lh         $a0, 0x6($a0)
	sll        $s1, $at, 1
	mtc2       $v0, $9 # handwritten instruction
	mtc2       $v1, $10 # handwritten instruction
	mtc2       $at, $11 # handwritten instruction
	mtc2       $s1, $8 # handwritten instruction
	sll        $s0, $v1, 1
	sll        $s2, $a0, 1
	GPF        0
	mult       $v0, $s0
	mfc2       $t1, $25 # handwritten instruction
	mfc2       $t4, $26 # handwritten instruction
	mfc2       $t6, $27 # handwritten instruction
	mtc2       $s2, $8 # handwritten instruction
	mtc2       $v0, $9 # handwritten instruction
	mtc2       $v1, $10 # handwritten instruction
	mtc2       $at, $11 # handwritten instruction
	mflo       $t0
	addi       $at, $zero, 0x1000 # handwritten instruction
	GPF        0
	mult       $v1, $s0
	mfc2       $t2, $25 # handwritten instruction
	mflo       $t3
	mfc2       $t5, $26 # handwritten instruction
	add        $a3, $t3, $t6 # handwritten instruction
	mult       $a0, $s2
	mfc2       $t7, $27 # handwritten instruction
	mflo       $t8
	sra        $a3, $a3, 12
	sub        $a3, $at, $a3 # handwritten instruction
	sh         $a3, 0x10($a1)
	add        $a2, $t6, $t8 # handwritten instruction
	add        $a3, $t4, $t2 # handwritten instruction
	sra        $a2, $a2, 12
	sra        $a3, $a3, 12
	sub        $a2, $at, $a2 # handwritten instruction
	sh         $a3, 0x2($a1)
	sh         $a2, 0x0($a1)
	sub        $a3, $t5, $t1 # handwritten instruction
	sub        $a2, $t4, $t2 # handwritten instruction
	sra        $a3, $a3, 12
	sra        $a2, $a2, 12
	sh         $a3, 0x4($a1)
	sh         $a2, 0x6($a1)
	add        $a3, $t3, $t8 # handwritten instruction
	add        $a2, $t7, $t0 # handwritten instruction
	sra        $a3, $a3, 12
	sra        $a2, $a2, 12
	sub        $a3, $at, $a3 # handwritten instruction
	sh         $a2, 0xA($a1)
	sh         $a3, 0x8($a1)
	add        $a3, $t5, $t1 # handwritten instruction
	sub        $a2, $t7, $t0 # handwritten instruction
	sra        $a3, $a3, 12
	sra        $a2, $a2, 12
	sh         $a3, 0xC($a1)
	sh         $a2, 0xE($a1)
	lw         $s0, 0x10($sp)
	lw         $s1, 0x14($sp)
	lw         $s2, 0x18($sp)
	jr         $ra
	addiu     $sp, $sp, 0x1C


#/******************************************************************************
#/*%%%% MRQuaternionBToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRQuaternionBToMatrixASM(
#/*				MR_QUATB*	q,
#/*				MR_MAT*		m);
#/*
#/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
#/*
#/*	INPUTS		q	- (a0)	Pointer to quaternion (1.1.6 format)
#/*			m	- (a1)	Pointer to matrix to fill in
#/*
#/*	NOTES		Be careful when modifying this routine, it's pipelined to
#/*			hell, and uses an odd register layout (effectively trashing
#/*			one of the input argument pointers). Is pretty much the
#/*			same as MRQuaternionToMatrixASM.
#/*		
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	21.03.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRQuaternionBToMatrixASM
	addiu      $sp, $sp, -0x1C
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	lb         $v0, 0x0($a0)
	lb         $v1, 0x1($a0)
	lb         $at, 0x2($a0)
	lb         $a0, 0x3($a0)
	sll        $s1, $at, 1
	mtc2       $v0, $9 # handwritten instruction
	mtc2       $v1, $10 # handwritten instruction
	mtc2       $at, $11 # handwritten instruction
	mtc2       $s1, $8 # handwritten instruction
	sll        $s0, $v1, 1
	sll        $s2, $a0, 1
	GPF        0
	mult       $v0, $s0
	mfc2       $t1, $25 # handwritten instruction
	mfc2       $t4, $26 # handwritten instruction
	mfc2       $t6, $27 # handwritten instruction
	mtc2       $s2, $8 # handwritten instruction
	mtc2       $v0, $9 # handwritten instruction
	mtc2       $v1, $10 # handwritten instruction
	mtc2       $at, $11 # handwritten instruction
	mflo       $t0
	addi       $at, $zero, 0x1000 # handwritten instruction
	GPF        0
	mult       $v1, $s0
	mfc2       $t2, $25 # handwritten instruction
	mflo       $t3
	mfc2       $t5, $26 # handwritten instruction
	add        $a3, $t3, $t6 # handwritten instruction
	mult       $a0, $s2
	mfc2       $t7, $27 # handwritten instruction
	mflo       $t8
	sub        $a3, $at, $a3 # handwritten instruction
	sh         $a3, 0x10($a1)
	add        $a2, $t6, $t8 # handwritten instruction
	add        $a3, $t4, $t2 # handwritten instruction
	sub        $a2, $at, $a2 # handwritten instruction
	sh         $a3, 0x2($a1)
	sh         $a2, 0x0($a1)
	sub        $a3, $t5, $t1 # handwritten instruction
	sub        $a2, $t4, $t2 # handwritten instruction
	sh         $a3, 0x4($a1)
	sh         $a2, 0x6($a1)
	add        $a3, $t3, $t8 # handwritten instruction
	add        $a2, $t7, $t0 # handwritten instruction
	sub        $a3, $at, $a3 # handwritten instruction
	sh         $a2, 0xA($a1)
	sh         $a3, 0x8($a1)
	add        $a3, $t5, $t1 # handwritten instruction
	sub        $a2, $t7, $t0 # handwritten instruction
	sh         $a3, 0xC($a1)
	sh         $a2, 0xE($a1)
	lw         $s0, 0x10($sp)
	lw         $s1, 0x14($sp)
	lw         $s2, 0x18($sp)
	jr         $ra
	addiu     $sp, $sp, 0x1C


#/******************************************************************************
#/*%%%% MRInterpolateQuaternionsASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsASM(
#/*				MR_QUAT*	startq,
#/*				MR_QUAT*	endq,
#/*				MR_QUAT*	destq,
#/*				MR_USHORT	t);
#/*
#/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
#/*
#/*	INPUTS		startq	- (a0)	Start quaternion
#/*			endq	- (a1)	End quaternion
#/*			destq	- (a2)	Destination quaternion (output)
#/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
#/*
#/*	CHANGED		PROGRAMMER	REASON
#/*	-------		----------	------
#/*	17.05.96	Tim Closs	Created
#/*	21.03.97	Dean Ashton	MIPS/GTE Conversion
#/*	12.06.97	Tim Closs	No longer assumes MR_QUAT is long-aligned
#/*			       		(due to existence of MR_QUAT_TRANS structure)
#/*
#/*%%%**************************************************************************/

# a0	-	Pointer to startq	(initial)
# a1	-	Pointer to endq		(initial)
# a2	-	Pointer to destq	(initial)
# a3	-	t			(initial)
#
# s0	-	bflip
# s1	-	cosomega
# s2	-	omega
# s3	-	sinomega
#
# s4	-	Pointer to startq
# s5	-	Pointer to endq
# s6	-	Pointer to destq
# s7	-	Safe work
#
# s8	-	startscale
#

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRInterpolateQuaternionsASM
	addiu      $sp, $sp, -0x38
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	sw         $s3, 0x1C($sp)
	sw         $s4, 0x20($sp)
	sw         $s5, 0x24($sp)
	sw         $s6, 0x28($sp)
	sw         $s7, 0x2C($sp)
	sw         $fp, 0x30($sp)
	sw         $ra, 0x34($sp)
	bnez       $a3, .L80079FBC
	lh        $t0, 0x0($a0)
	lh         $t1, 0x2($a0)
	lh         $t2, 0x4($a0)
	lh         $t3, 0x6($a0)
	sh         $t0, 0x0($a2)
	sh         $t1, 0x2($a2)
	sh         $t2, 0x4($a2)
	b          .L8007A18C
	sh        $t3, 0x6($a2)
.L80079FBC:
	add        $s4, $a0, $zero # handwritten instruction
	add        $s5, $a1, $zero # handwritten instruction
	add        $s6, $a2, $zero # handwritten instruction
	lhu        $t0, 0x0($a0)
	lhu        $t1, 0x2($a0)
	lhu        $t2, 0x4($a0)
	sll        $t1, $t1, 16
	or         $t0, $t0, $t1
	ctc2       $t0, $0 # handwritten instruction
	ctc2       $t2, $1 # handwritten instruction
	lhu        $t0, 0x0($a1)
	lhu        $t1, 0x2($a1)
	lhu        $t2, 0x4($a1)
	sll        $t1, $t1, 16
	or         $t0, $t0, $t1
	mtc2       $t0, $0 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	lh         $t0, 0x6($a0)
	lh         $t1, 0x6($a1)
	MVMVA      0, 0, 0, 3, 0
	mult       $t0, $t1
	mfc2       $t2, $25 # handwritten instruction
	mflo       $t5
	add        $t0, $t5, $t2 # handwritten instruction
	sra        $s1, $t0, 12
	ori        $t9, $zero, 0x1000
	bgez       $s1, .L8007A034
	or        $s0, $zero, $zero
	sub        $s1, $zero, $s1 # handwritten instruction
	ori        $s0, $zero, 0x1
.L8007A034:
	sub        $t0, $t9, $s1 # handwritten instruction
	addi       $t0, $t9, -0x1 # handwritten instruction
	bltz       $t0, .L8007A0F0
	sub       $fp, $t9, $s7 # handwritten instruction
	slti       $at, $s1, 0x1000
	bnez       $at, .L8007A054
	or        $v0, $s1, $zero
	addi       $v0, $zero, 0x1000 # handwritten instruction
.L8007A054:
	slti       $at, $v0, -0x1000
	beqz       $at, .L8007A064
	or        $s1, $v0, $zero
	addi       $s1, $zero, -0x1000 # handwritten instruction
.L8007A064:
	addi       $t1, $s1, 0x1000 # handwritten instruction
	lui        $t2, %hi(MRAcos_table)
	sll        $t1, $t1, 1
	ori        $t2, $t2, %lo(MRAcos_table)
	add        $t2, $t2, $t1 # handwritten instruction
	lh         $s2, 0x0($t2)
	lui        $t3, %hi(rcossin_tbl)
	addiu      $t3, $t3, %lo(rcossin_tbl)
	sll        $t4, $s2, 2
	add        $t4, $t4, $t3 # handwritten instruction
	lw         $t5, 0x0($t4)
	nop
	sll        $t5, $t5, 16
	sra        $s3, $t5, 16
	mult       $a3, $s2
	nop
	mflo       $s7
	sra        $s7, $s7, 12
	sll        $t4, $s7, 2
	add        $t4, $t4, $t3 # handwritten instruction
	lw         $t5, 0x0($t4)
	nop
	sll        $t4, $t5, 16
	sra        $v0, $t4, 4
	div        $zero, $v0, $s3
	mflo       $s3
	sra        $v1, $t5, 16
	nop
	mult       $s1, $s3
	addi       $t0, $s3, 0x0 # handwritten instruction
	mflo       $t1
	sra        $t1, $t1, 12
	sub        $fp, $v1, $t1 # handwritten instruction
	b          .L8007A0F4
	lw        $ra, 0x34($sp)
.L8007A0F0:
	or         $t0, $a3, $zero
.L8007A0F4:
	bnez       $s0, .L8007A100
	sub       $t0, $zero, $t0 # handwritten instruction
	sub        $t0, $zero, $t0 # handwritten instruction
.L8007A100:
	lh         $t1, 0x0($s5)
	lh         $t2, 0x2($s5)
	lh         $t3, 0x4($s5)
	mtc2       $t0, $8 # handwritten instruction
	mtc2       $t1, $9 # handwritten instruction
	mtc2       $t2, $10 # handwritten instruction
	mtc2       $t3, $11 # handwritten instruction
	lh         $t4, 0x6($s5)
	nop
	GPF        0
	mult       $t0, $t4
	lh         $t1, 0x0($s4)
	lh         $t2, 0x2($s4)
	lh         $t3, 0x4($s4)
	mtc2       $fp, $8 # handwritten instruction
	mtc2       $t1, $9 # handwritten instruction
	mtc2       $t2, $10 # handwritten instruction
	mtc2       $t3, $11 # handwritten instruction
	mflo       $t0
	lh         $t4, 0x6($s4)
	GPL        0
	mult       $fp, $t4
	mfc2       $t1, $25 # handwritten instruction
	mfc2       $t2, $26 # handwritten instruction
	mflo       $t4
	mfc2       $t3, $27 # handwritten instruction
	add        $t4, $t0, $t4 # handwritten instruction
	sra        $t1, $t1, 12
	sra        $t2, $t2, 12
	sra        $t3, $t3, 12
	sra        $t4, $t4, 12
	sh         $t1, 0x0($s6)
	sh         $t2, 0x2($s6)
	sh         $t3, 0x4($s6)
	sh         $t4, 0x6($s6)
.L8007A18C:
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
	addiu     $sp, $sp, 0x38



#/******************************************************************************
#/*%%%% MRInterpolateQuaternionsBToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsBToMatrixASM(
#/*				MR_QUATB*	startq,
#/*				MR_QUATB*	endq,
#/*				MR_MAT*		matrix,
#/*				MR_USHORT	t);
#/*
#/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
#/*
#/*	INPUTS		startq	- (a0)	Start quaternion
#/*			endq	- (a1)	End quaternion
#/*			matrix	- (a2)	Destination matrix (output)
#/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	19.03.97	Tim Closs		Created
#/*	21.03.97	Dean Ashton		MIPS/GTE Conversion
#/*
#/*%%%**************************************************************************/

# a0	-	Pointer to startq	(initial)
# a1	-	Pointer to endq		(initial)
# a2	-	Pointer to matrix	(initial)
# a3	-	t			(initial)
#
# s0	-	bflip
# s1	-	cosomega
# s2	-	omega
# s3	-	sinomega
#
# s4	-	Pointer to startq
# s5	-	Pointer to endq
# s6	-	Pointer to matrix
# s7	-	Safe work
#
# s8	-	startscale

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRInterpolateQuaternionsBToMatrixASM
	addiu      $sp, $sp, -0x40
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	sw         $s3, 0x1C($sp)
	sw         $s4, 0x20($sp)
	sw         $s5, 0x24($sp)
	sw         $s6, 0x28($sp)
	sw         $s7, 0x2C($sp)
	sw         $fp, 0x30($sp)
	sw         $ra, 0x34($sp)
	add        $s4, $a0, $zero # handwritten instruction
	add        $s5, $a1, $zero # handwritten instruction
	add        $s6, $a2, $zero # handwritten instruction
	bnez       $a3, .L8007A204
	nop
	jal        MRQuaternionBToMatrixASM
	add       $a1, $s6, $zero # handwritten instruction
	b          .L8007A3F8
.L8007A204:
	lb        $t0, 0x0($s4)
	lb         $t1, 0x1($s4)
	lb         $t2, 0x2($s4)
	sll        $t0, $t0, 16
	sll        $t1, $t1, 16
	srl        $t0, $t0, 16
	or         $t0, $t0, $t1
	ctc2       $t0, $0 # handwritten instruction
	ctc2       $t2, $1 # handwritten instruction
	lb         $t0, 0x0($s5)
	lb         $t1, 0x1($s5)
	lb         $t2, 0x2($s5)
	sll        $t0, $t0, 16
	sll        $t1, $t1, 16
	srl        $t0, $t0, 16
	or         $t0, $t0, $t1
	mtc2       $t0, $0 # handwritten instruction
	mtc2       $t2, $1 # handwritten instruction
	lb         $t0, 0x3($s4)
	lb         $t1, 0x3($s5)
	MVMVA      0, 0, 0, 3, 0
	mult       $t0, $t1
	mfc2       $t2, $25 # handwritten instruction
	mflo       $t5
	add        $s1, $t5, $t2 # handwritten instruction
	ori        $t9, $zero, 0x1000
	bgez       $s1, .L8007A27C
	or        $s0, $zero, $zero
	sub        $s1, $zero, $s1 # handwritten instruction
	ori        $s0, $zero, 0x1
.L8007A27C:
	sub        $t0, $t9, $s1 # handwritten instruction
	addi       $t0, $t9, -0x1 # handwritten instruction
	bltz       $t0, .L8007A338
	sub       $fp, $t9, $s7 # handwritten instruction
	slti       $at, $s1, 0x1000
	bnez       $at, .L8007A29C
	or        $v0, $s1, $zero
	addi       $v0, $zero, 0x1000 # handwritten instruction
.L8007A29C:
	slti       $at, $v0, -0x1000
	beqz       $at, .L8007A2AC
	or        $s1, $v0, $zero
	addi       $s1, $zero, -0x1000 # handwritten instruction
.L8007A2AC:
	addi       $t1, $s1, 0x1000 # handwritten instruction
	lui        $t2, %hi(MRAcos_table)
	sll        $t1, $t1, 1
	ori        $t2, $t2, %lo(MRAcos_table)
	add        $t2, $t2, $t1 # handwritten instruction
	lh         $s2, 0x0($t2)
	lui        $t3, %hi(rcossin_tbl)
	addiu      $t3, $t3, %lo(rcossin_tbl)
	sll        $t4, $s2, 2
	add        $t4, $t4, $t3 # handwritten instruction
	lw         $t5, 0x0($t4)
	nop
	sll        $t5, $t5, 16
	sra        $s3, $t5, 16
	mult       $a3, $s2
	nop
	mflo       $s7
	sra        $s7, $s7, 12
	sll        $t4, $s7, 2
	add        $t4, $t4, $t3 # handwritten instruction
	lw         $t5, 0x0($t4)
	nop
	sll        $t4, $t5, 16
	sra        $v0, $t4, 4
	div        $zero, $v0, $s3
	mflo       $s3
	sra        $v1, $t5, 16
	nop
	mult       $s1, $s3
	addi       $t0, $s3, 0x0 # handwritten instruction
	mflo       $t1
	sra        $t1, $t1, 12
	sub        $fp, $v1, $t1 # handwritten instruction
	b          .L8007A33C
	nop
.L8007A338:
	or         $t0, $a3, $zero
.L8007A33C:
	bnez       $s0, .L8007A348
	sub       $t0, $zero, $t0 # handwritten instruction
	sub        $t0, $zero, $t0 # handwritten instruction
.L8007A348:
	lb         $t1, 0x0($s5)
	lb         $t2, 0x1($s5)
	lb         $t3, 0x2($s5)
	mtc2       $t0, $8 # handwritten instruction
	mtc2       $t1, $9 # handwritten instruction
	mtc2       $t2, $10 # handwritten instruction
	mtc2       $t3, $11 # handwritten instruction
	lb         $t4, 0x3($s5)
	nop
	GPF        0
	mult       $t0, $t4
	lb         $t1, 0x0($s4)
	lb         $t2, 0x1($s4)
	lb         $t3, 0x2($s4)
	mtc2       $fp, $8 # handwritten instruction
	mtc2       $t1, $9 # handwritten instruction
	mtc2       $t2, $10 # handwritten instruction
	mtc2       $t3, $11 # handwritten instruction
	mflo       $t0
	lb         $t4, 0x3($s4)
	GPL        0
	mult       $fp, $t4
	mfc2       $t1, $25 # handwritten instruction
	mfc2       $t2, $26 # handwritten instruction
	mflo       $t4
	mfc2       $t3, $27 # handwritten instruction
	add        $t4, $t0, $t4 # handwritten instruction
	sra        $t1, $t1, 6
	sra        $t2, $t2, 6
	sra        $t3, $t3, 6
	sra        $t4, $t4, 6
	addiu      $s0, $sp, 0x38
	sh         $t1, 0x0($s0)
	sh         $t2, 0x2($s0)
	sh         $t3, 0x4($s0)
	sh         $t4, 0x6($s0)
	beqz       $t0, .L8007A3F0
	addi      $a0, $s0, 0x0 # handwritten instruction
	addi       $a1, $a0, 0x0 # handwritten instruction
	jal        MRNormaliseQuaternion
	addi      $a2, $zero, 0x1000 # handwritten instruction
	addi       $a0, $s0, 0x0 # handwritten instruction
.L8007A3F0:
	jal        MRQuaternionToMatrixASM
	addi      $a1, $s6, 0x0 # handwritten instruction
.L8007A3F8:
	lw         $ra, 0x34($sp)
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
	addiu     $sp, $sp, 0x40
