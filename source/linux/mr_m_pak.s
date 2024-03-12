.include		"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRPPDecrunchBuffer
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
	lw         $t4, 0x0($a0)
	lui        $t5, (0x30325050 >> 16)
	ori        $t5, $t5, (0x30325050 & 0xFFFF)
	bne        $t4, $t5, .L8007B45C
	ori       $v0, $zero, 0x0
	lui        $t0, %hi(MRTemp_matrix)
	ori        $t0, $t0, %lo(MRTemp_matrix)
	lw         $t4, 0x4($a0)
	lui        $t1, %hi(MRPP_rev_table)
	sw         $t4, 0x0($t0)
	ori        $t1, $t1, %lo(MRPP_rev_table)
	addu       $a0, $a0, $a2
	addiu      $a0, $a0, -0x4
	lbu        $t5, 0x1($a0)
	lbu        $t4, 0x2($a0)
	lbu        $t6, 0x0($a0)
	sll        $t5, $t5, 8
	sll        $t6, $t6, 16
	or         $t4, $t4, $t5
	or         $t4, $t4, $t6
	or         $t2, $zero, $zero
	or         $t3, $zero, $zero
	ori        $s3, $zero, 0x3
	ori        $s4, $zero, 0x4
	ori        $s5, $zero, 0x7
	ori        $s6, $zero, 0xFF
	lbu        $v1, 0x3($a0)
	addu       $a3, $a1, $t4
	or         $v0, $zero, $zero
.L8007ADA0:
	beq        $zero, $v1, .L8007AE38
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007ADD4
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007ADA0
	or        $v1, $zero, $zero
.L8007ADD4:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007ADA0
	or        $t3, $t3, $s2
.L8007AE38:
	ori        $v1, $zero, 0x1
	or         $v0, $zero, $zero
.L8007AE40:
	beq        $zero, $v1, .L8007AED8
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007AE74
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007AE40
	or        $v1, $zero, $zero
.L8007AE74:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007AE40
	or        $t3, $t3, $s2
.L8007AED8:
	bnez       $v0, .L8007B040
	or        $t7, $zero, $zero
.L8007AEE0:
	ori        $v1, $zero, 0x2
	or         $v0, $zero, $zero
.L8007AEE8:
	beq        $zero, $v1, .L8007AF80
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007AF1C
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007AEE8
	or        $v1, $zero, $zero
.L8007AF1C:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007AEE8
	or        $t3, $t3, $s2
.L8007AF80:
	addu       $t7, $t7, $v0
	beq        $v0, $s3, .L8007AEE0
.L8007AF88:
	ori       $v1, $zero, 0x8
	or         $v0, $zero, $zero
.L8007AF90:
	beq        $zero, $v1, .L8007B028
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007AFC4
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007AF90
	or        $v1, $zero, $zero
.L8007AFC4:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007AF90
	or        $t3, $t3, $s2
.L8007B028:
	addi       $a3, $a3, -0x1 # handwritten instruction
	addi       $t7, $t7, -0x1 # handwritten instruction
	bgez       $t7, .L8007AF88
	sb        $v0, 0x0($a3)
	slt        $at, $a1, $a3
	beqz       $at, .L8007B458
.L8007B040:
	ori       $v1, $zero, 0x2
	or         $v0, $zero, $zero
.L8007B048:
	beq        $zero, $v1, .L8007B0E0
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B07C
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B048
	or        $v1, $zero, $zero
.L8007B07C:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B048
	or        $t3, $t3, $s2
.L8007B0E0:
	addiu      $t7, $v0, 0x1
	addu       $t4, $t0, $v0
	lbu        $t9, 0x0($t4)
	bne        $t7, $s4, .L8007B394
	ori       $v1, $zero, 0x1
	or         $v0, $zero, $zero
.L8007B0F8:
	beq        $zero, $v1, .L8007B190
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B12C
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B0F8
	or        $v1, $zero, $zero
.L8007B12C:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B0F8
	or        $t3, $t3, $s2
.L8007B190:
	bnez       $v0, .L8007B23C
	or        $v1, $zero, $s5
	or         $v0, $zero, $zero
.L8007B19C:
	beq        $zero, $v1, .L8007B234
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B1D0
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B19C
	or        $v1, $zero, $zero
.L8007B1D0:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B19C
	or        $t3, $t3, $s2
.L8007B234:
	b          .L8007B2E0
	or        $t6, $zero, $v0
.L8007B23C:
	or         $v1, $zero, $t9
	or         $v0, $zero, $zero
.L8007B244:
	beq        $zero, $v1, .L8007B2DC
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B278
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B244
	or        $v1, $zero, $zero
.L8007B278:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B244
	or        $t3, $t3, $s2
.L8007B2DC:
	or         $t6, $zero, $v0
.L8007B2E0:
	ori        $v1, $zero, 0x3
	or         $v0, $zero, $zero
.L8007B2E8:
	beq        $zero, $v1, .L8007B380
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B31C
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B2E8
	or        $v1, $zero, $zero
.L8007B31C:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B2E8
	or        $t3, $t3, $s2
.L8007B380:
	addu       $t7, $t7, $v0
	beq        $v0, $s5, .L8007B2E0
	nop
	b          .L8007B438
	nop
.L8007B394:
	or         $v1, $zero, $t9
	or         $v0, $zero, $zero
.L8007B39C:
	beq        $zero, $v1, .L8007B434
	nop
	slt        $at, $v1, $t2
	beqz       $at, .L8007B3D0
	ori       $s0, $zero, 0x20
	sllv       $v0, $v0, $v1
	sub        $t2, $t2, $v1 # handwritten instruction
	sub        $s0, $s0, $v1 # handwritten instruction
	srlv       $s2, $t3, $s0
	sllv       $t3, $t3, $v1
	or         $v0, $v0, $s2
	b          .L8007B39C
	or        $v1, $zero, $zero
.L8007B3D0:
	sub        $s0, $s0, $t2 # handwritten instruction
	addiu      $a0, $a0, -0x4
	srlv       $v0, $t3, $s0
	lbu        $s0, 0x0($a0)
	sub        $v1, $v1, $t2 # handwritten instruction
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x1($a0)
	or         $t3, $zero, $s2
	addu       $s1, $t1, $s0
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x2($a0)
	sll        $s2, $s2, 8
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	lbu        $s0, 0x3($a0)
	sll        $s2, $s2, 16
	addu       $s1, $t1, $s0
	or         $t3, $t3, $s2
	lbu        $s2, 0x0($s1)
	ori        $t2, $zero, 0x20
	sll        $s2, $s2, 24
	b          .L8007B39C
	or        $t3, $t3, $s2
.L8007B434:
	or         $t6, $zero, $v0
.L8007B438:
	addu       $t4, $a3, $t6
	lbu        $t5, 0x0($t4)
	addi       $t7, $t7, -0x1 # handwritten instruction
	sb         $t5, -0x1($a3)
	bgez       $t7, .L8007B438
	addiu     $a3, $a3, -0x1
	slt        $at, $a1, $a3
	bnez       $at, .L8007AE38
.L8007B458:
	ori       $v0, $zero, 0x1
.L8007B45C:
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
