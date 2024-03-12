.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_E3
	lw         $v0, 0x10($sp)
	lw         $v1, 0x14($sp)
	addiu      $sp, $sp, -0x44
	sw         $s0, 0x10($sp)
	sw         $s1, 0x14($sp)
	sw         $s2, 0x18($sp)
	sw         $s3, 0x1C($sp)
	sw         $s4, 0x20($sp)
	sw         $s5, 0x24($sp)
	sw         $s6, 0x28($sp)
	sw         $s7, 0x2C($sp)
	sw         $fp, 0x30($sp)
	lw         $s0, 0x20($v0)
	lh         $s1, 0x24($v0)
	lw         $s2, 0x28($v0)
	lw         $s3, 0x2C($v0)
	lh         $s4, 0x26($v0)
	addi       $s5, $a2, -0x4 # handwritten instruction
	lw         $s5, 0x0($s5)
	nop
	sra        $s5, $s5, 16
	lui        $s6, (0xFFFFFF >> 16)
	ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
	lui        $s7, (0x7000000 >> 16)
	sw         $s6, 0x34($sp)
	sw         $s7, 0x38($sp)
	lui        $t9, %hi(MREnv_strip)
	lui        $at, 0
	addu       $at, $at, $t9
	lw         $t5, %lo(MREnv_strip)($t9)
	nop
	lbu        $s6, 0x4($t5)
	lbu        $s7, 0x5($t5)
	addiu      $s6, $s6, 0x40
	addiu      $s7, $s7, 0x40
	sw         $s6, 0x3C($sp)
	sw         $s7, 0x40($sp)
	lw         $fp, 0x44($v0)
	lh         $t0, 0x0($a2)
	lh         $t1, 0x2($a2)
	lh         $t2, 0x4($a2)
	sll        $t0, $t0, 3
	sll        $t1, $t1, 3
	sll        $t2, $t2, 3
	add        $t0, $t0, $a0 # handwritten instruction
	add        $t1, $t1, $a0 # handwritten instruction
	add        $t2, $t2, $a0 # handwritten instruction
.L8007CA9C:
	lwc2       $0, 0x0($t0)
	lwc2       $1, 0x4($t0)
	lwc2       $2, 0x0($t1)
	lwc2       $3, 0x4($t1)
	lwc2       $4, 0x0($t2)
	lwc2       $5, 0x4($t2)
	addi       $t8, $a2, 0x14 # handwritten instruction
	nop
	RTPT
	lh         $t0, 0x0($t8)
	lh         $t1, 0x2($t8)
	lh         $t2, 0x4($t8)
	sll        $t0, $t0, 3
	sll        $t1, $t1, 3
	sll        $t2, $t2, 3
	add        $t0, $t0, $a0 # handwritten instruction
	add        $t1, $t1, $a0 # handwritten instruction
	add        $t2, $t2, $a0 # handwritten instruction
	NCLIP
	lwc2       $6, 0x10($a2)
	mfc2       $t8, $24 # handwritten instruction
	nop
	blez       $t8, .L8007CCE4
	nop
	AVSZ3
	lh         $t4, 0x6($a2)
	mfc2       $t8, $7 # handwritten instruction
	sll        $t4, $t4, 3
	srav       $t8, $t8, $s1
	add        $t8, $t8, $s4 # handwritten instruction
	slt        $at, $t8, $s3
	bnez       $at, .L8007CCE4
	add       $t4, $t4, $a1 # handwritten instruction
	slt        $at, $t8, $s2
	beqz       $at, .L8007CCE4
	nop
	swc2       $12, 0x8($a3)
	swc2       $13, 0x10($a3)
	swc2       $14, 0x18($a3)
	lui        $t9, (0x1F800000 >> 16)
	lui        $at, (0x38 >> 16)
	addu       $at, $at, $t9
	lw         $t5, (0x38 & 0xFFFF)($at)
	nop
	lw         $t6, 0x0($t5)
	lw         $t7, 0x4($t5)
	ctc2       $t6, $0 # handwritten instruction
	ctc2       $t7, $1 # handwritten instruction
	lw         $t6, 0x8($t5)
	lw         $t7, 0xC($t5)
	lw         $t9, 0x10($t5)
	ctc2       $t6, $2 # handwritten instruction
	ctc2       $t7, $3 # handwritten instruction
	ctc2       $t9, $4 # handwritten instruction
	lwc2       $0, 0x0($t4)
	lwc2       $1, 0x4($t4)
	lw         $s6, 0x3C($sp)
	lw         $s7, 0x40($sp)
	MVMVA      1, 0, 0, 3, 0
	lh         $t4, 0x8($a2)
	nop
	sll        $t4, $t4, 3
	add        $t4, $t4, $a1 # handwritten instruction
	lwc2       $2, 0x0($t4)
	lwc2       $3, 0x4($t4)
	mfc2       $t5, $25 # handwritten instruction
	nop
	sra        $t5, $t5, 6
	add        $t5, $t5, $s6 # handwritten instruction
	mfc2       $t6, $26 # handwritten instruction
	nop
	sub        $t6, $zero, $t6 # handwritten instruction
	sra        $t6, $t6, 6
	add        $t6, $t6, $s7 # handwritten instruction
	sll        $t6, $t6, 8
	add        $t5, $t6, $t5 # handwritten instruction
	sh         $t5, 0xC($a3)
	MVMVA      1, 0, 1, 3, 0
	lh         $t4, 0xA($a2)
	nop
	sll        $t4, $t4, 3
	add        $t4, $t4, $a1 # handwritten instruction
	lwc2       $4, 0x0($t4)
	lwc2       $5, 0x4($t4)
	mfc2       $t5, $25 # handwritten instruction
	nop
	sra        $t5, $t5, 6
	add        $t5, $t5, $s6 # handwritten instruction
	mfc2       $t6, $26 # handwritten instruction
	nop
	sub        $t6, $zero, $t6 # handwritten instruction
	sra        $t6, $t6, 6
	add        $t6, $t6, $s7 # handwritten instruction
	sll        $t6, $t6, 8
	add        $t5, $t6, $t5 # handwritten instruction
	sh         $t5, 0x14($a3)
	MVMVA      1, 0, 2, 3, 0
	lh         $t4, 0xC($a2)
	nop
	sll        $t4, $t4, 3
	add        $t4, $t4, $a1 # handwritten instruction
	lwc2       $0, 0x0($t4)
	lwc2       $1, 0x4($t4)
	mfc2       $t5, $25 # handwritten instruction
	nop
	sra        $t5, $t5, 6
	add        $t5, $t5, $s6 # handwritten instruction
	mfc2       $t6, $26 # handwritten instruction
	nop
	sub        $t6, $zero, $t6 # handwritten instruction
	sra        $t6, $t6, 6
	add        $t6, $t6, $s7 # handwritten instruction
	sll        $t6, $t6, 8
	add        $t5, $t6, $t5 # handwritten instruction
	sh         $t5, 0x1C($a3)
	lui        $t9, (0x1F800000 >> 16)
	lui        $at, (0x34 >> 16)
	addu       $at, $at, $t9
	lw         $t5, (0x34 & 0xFFFF)($at)
	nop
	lw         $t6, 0x0($t5)
	lw         $t7, 0x4($t5)
	ctc2       $t6, $0 # handwritten instruction
	ctc2       $t7, $1 # handwritten instruction
	lw         $t6, 0x8($t5)
	lw         $t7, 0xC($t5)
	lw         $t9, 0x10($t5)
	ctc2       $t6, $2 # handwritten instruction
	ctc2       $t7, $3 # handwritten instruction
	ctc2       $t9, $4 # handwritten instruction
	beq        $zero, $v1, .L8007CCB8
	nop
	NCDS
	b          .L8007CCBC
	nop
.L8007CCB8:
	NCCS
.L8007CCBC:
	lw         $s6, 0x34($sp)
	lw         $s7, 0x38($sp)
	and        $t9, $a3, $s6
	sll        $t8, $t8, 2
	add        $t8, $t8, $s0 # handwritten instruction
	lw         $at, 0x0($t8)
	sw         $t9, 0x0($t8)
	or         $at, $at, $s7
	sw         $at, 0x0($t9)
	swc2       $22, 0x4($a3)
.L8007CCE4:
	addi       $a2, $a2, 0x14 # handwritten instruction
	addi       $a3, $a3, 0x20 # handwritten instruction
	addi       $s5, $s5, -0x1 # handwritten instruction
	bgtz       $s5, .L8007CA9C
	addi      $fp, $fp, -0x1 # handwritten instruction
	sw         $a3, 0x3C($v0)
	sw         $a2, 0x40($v0)
	sw         $fp, 0x44($v0)
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
	addiu     $sp, $sp, 0x44
