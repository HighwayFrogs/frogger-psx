.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_GT3
	lw         $v0, 0x10($sp)
	lw         $v1, 0x14($sp)
	addiu      $sp, $sp, -0x34
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
	lui        $s7, (0x9000000 >> 16)
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
.L8007C618:
	lwc2       $0, 0x0($t0)
	lwc2       $1, 0x4($t0)
	lwc2       $2, 0x0($t1)
	lwc2       $3, 0x4($t1)
	lwc2       $4, 0x0($t2)
	lwc2       $5, 0x4($t2)
	addi       $t8, $a2, 0x1C # handwritten instruction
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
	lwc2       $6, 0x18($a2)
	mfc2       $t8, $24 # handwritten instruction
	nop
	blez       $t8, .L8007C720
	nop
	AVSZ3
	lh         $t4, 0x6($a2)
	mfc2       $t8, $7 # handwritten instruction
	sll        $t4, $t4, 3
	srav       $t8, $t8, $s1
	add        $t8, $t8, $s4 # handwritten instruction
	slt        $at, $t8, $s3
	bnez       $at, .L8007C720
	add       $t4, $t4, $a1 # handwritten instruction
	slt        $at, $t8, $s2
	beqz       $at, .L8007C720
	lh        $t5, 0x8($a2)
	lh         $t6, 0xA($a2)
	swc2       $12, 0x8($a3)
	swc2       $13, 0x14($a3)
	swc2       $14, 0x20($a3)
	sll        $t5, $t5, 3
	sll        $t6, $t6, 3
	add        $t5, $t5, $a1 # handwritten instruction
	add        $t6, $t6, $a1 # handwritten instruction
	lwc2       $0, 0x0($t4)
	lwc2       $1, 0x4($t4)
	lwc2       $2, 0x0($t5)
	lwc2       $3, 0x4($t5)
	lwc2       $4, 0x0($t6)
	lwc2       $5, 0x4($t6)
	beq        $zero, $v1, .L8007C6F4
	nop
	NCDT
	b          .L8007C6F8
	nop
.L8007C6F4:
	NCCT
.L8007C6F8:
	and        $t9, $a3, $s6
	sll        $t8, $t8, 2
	add        $t8, $t8, $s0 # handwritten instruction
	lw         $at, 0x0($t8)
	sw         $t9, 0x0($t8)
	or         $at, $at, $s7
	sw         $at, 0x0($t9)
	swc2       $20, 0x4($a3)
	swc2       $21, 0x10($a3)
	swc2       $22, 0x1C($a3)
.L8007C720:
	addi       $a2, $a2, 0x1C # handwritten instruction
	addi       $a3, $a3, 0x28 # handwritten instruction
	addi       $s5, $s5, -0x1 # handwritten instruction
	bgtz       $s5, .L8007C618
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
	addiu     $sp, $sp, 0x34
