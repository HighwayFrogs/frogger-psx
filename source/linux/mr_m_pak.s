.include		"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRPPDecrunchBuffer
/* 6B504 8007AD04 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6B508 8007AD08 1000B0AF */  sw         $s0, 0x10($sp)
/* 6B50C 8007AD0C 1400B1AF */  sw         $s1, 0x14($sp)
/* 6B510 8007AD10 1800B2AF */  sw         $s2, 0x18($sp)
/* 6B514 8007AD14 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6B518 8007AD18 2000B4AF */  sw         $s4, 0x20($sp)
/* 6B51C 8007AD1C 2400B5AF */  sw         $s5, 0x24($sp)
/* 6B520 8007AD20 2800B6AF */  sw         $s6, 0x28($sp)
/* 6B524 8007AD24 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6B528 8007AD28 3000BEAF */  sw         $fp, 0x30($sp)
/* 6B52C 8007AD2C 00008C8C */  lw         $t4, 0x0($a0)
/* 6B530 8007AD30 32300D3C */  lui        $t5, (0x30325050 >> 16)
/* 6B534 8007AD34 5050AD35 */  ori        $t5, $t5, (0x30325050 & 0xFFFF)
/* 6B538 8007AD38 C8018D15 */  bne        $t4, $t5, .L8007B45C
/* 6B53C 8007AD3C 00000234 */   ori       $v0, $zero, 0x0
/* 6B540 8007AD40 801F083C */  lui        $t0, %hi(MRTemp_matrix)
/* 6B544 8007AD44 60000835 */  ori        $t0, $t0, %lo(MRTemp_matrix)
/* 6B548 8007AD48 04008C8C */  lw         $t4, 0x4($a0)
/* 6B54C 8007AD4C 0C80093C */  lui        $t1, %hi(MRPP_rev_table)
/* 6B550 8007AD50 00000CAD */  sw         $t4, 0x0($t0)
/* 6B554 8007AD54 F0062935 */  ori        $t1, $t1, %lo(MRPP_rev_table)
/* 6B558 8007AD58 21208600 */  addu       $a0, $a0, $a2
/* 6B55C 8007AD5C FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B560 8007AD60 01008D90 */  lbu        $t5, 0x1($a0)
/* 6B564 8007AD64 02008C90 */  lbu        $t4, 0x2($a0)
/* 6B568 8007AD68 00008E90 */  lbu        $t6, 0x0($a0)
/* 6B56C 8007AD6C 006A0D00 */  sll        $t5, $t5, 8
/* 6B570 8007AD70 00740E00 */  sll        $t6, $t6, 16
/* 6B574 8007AD74 25608D01 */  or         $t4, $t4, $t5
/* 6B578 8007AD78 25608E01 */  or         $t4, $t4, $t6
/* 6B57C 8007AD7C 25500000 */  or         $t2, $zero, $zero
/* 6B580 8007AD80 25580000 */  or         $t3, $zero, $zero
/* 6B584 8007AD84 03001334 */  ori        $s3, $zero, 0x3
/* 6B588 8007AD88 04001434 */  ori        $s4, $zero, 0x4
/* 6B58C 8007AD8C 07001534 */  ori        $s5, $zero, 0x7
/* 6B590 8007AD90 FF001634 */  ori        $s6, $zero, 0xFF
/* 6B594 8007AD94 03008390 */  lbu        $v1, 0x3($a0)
/* 6B598 8007AD98 2138AC00 */  addu       $a3, $a1, $t4
/* 6B59C 8007AD9C 25100000 */  or         $v0, $zero, $zero
.L8007ADA0:
/* 6B5A0 8007ADA0 25000310 */  beq        $zero, $v1, .L8007AE38
/* 6B5A4 8007ADA4 00000000 */   nop
/* 6B5A8 8007ADA8 2A086A00 */  slt        $at, $v1, $t2
/* 6B5AC 8007ADAC 09002010 */  beqz       $at, .L8007ADD4
/* 6B5B0 8007ADB0 20001034 */   ori       $s0, $zero, 0x20
/* 6B5B4 8007ADB4 04106200 */  sllv       $v0, $v0, $v1
/* 6B5B8 8007ADB8 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B5BC 8007ADBC 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B5C0 8007ADC0 06900B02 */  srlv       $s2, $t3, $s0
/* 6B5C4 8007ADC4 04586B00 */  sllv       $t3, $t3, $v1
/* 6B5C8 8007ADC8 25105200 */  or         $v0, $v0, $s2
/* 6B5CC 8007ADCC F4FF0010 */  b          .L8007ADA0
/* 6B5D0 8007ADD0 25180000 */   or        $v1, $zero, $zero
.L8007ADD4:
/* 6B5D4 8007ADD4 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B5D8 8007ADD8 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B5DC 8007ADDC 06100B02 */  srlv       $v0, $t3, $s0
/* 6B5E0 8007ADE0 00009090 */  lbu        $s0, 0x0($a0)
/* 6B5E4 8007ADE4 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B5E8 8007ADE8 21883001 */  addu       $s1, $t1, $s0
/* 6B5EC 8007ADEC 00003292 */  lbu        $s2, 0x0($s1)
/* 6B5F0 8007ADF0 01009090 */  lbu        $s0, 0x1($a0)
/* 6B5F4 8007ADF4 25581200 */  or         $t3, $zero, $s2
/* 6B5F8 8007ADF8 21883001 */  addu       $s1, $t1, $s0
/* 6B5FC 8007ADFC 00003292 */  lbu        $s2, 0x0($s1)
/* 6B600 8007AE00 02009090 */  lbu        $s0, 0x2($a0)
/* 6B604 8007AE04 00921200 */  sll        $s2, $s2, 8
/* 6B608 8007AE08 21883001 */  addu       $s1, $t1, $s0
/* 6B60C 8007AE0C 25587201 */  or         $t3, $t3, $s2
/* 6B610 8007AE10 00003292 */  lbu        $s2, 0x0($s1)
/* 6B614 8007AE14 03009090 */  lbu        $s0, 0x3($a0)
/* 6B618 8007AE18 00941200 */  sll        $s2, $s2, 16
/* 6B61C 8007AE1C 21883001 */  addu       $s1, $t1, $s0
/* 6B620 8007AE20 25587201 */  or         $t3, $t3, $s2
/* 6B624 8007AE24 00003292 */  lbu        $s2, 0x0($s1)
/* 6B628 8007AE28 20000A34 */  ori        $t2, $zero, 0x20
/* 6B62C 8007AE2C 00961200 */  sll        $s2, $s2, 24
/* 6B630 8007AE30 DBFF0010 */  b          .L8007ADA0
/* 6B634 8007AE34 25587201 */   or        $t3, $t3, $s2
.L8007AE38:
/* 6B638 8007AE38 01000334 */  ori        $v1, $zero, 0x1
/* 6B63C 8007AE3C 25100000 */  or         $v0, $zero, $zero
.L8007AE40:
/* 6B640 8007AE40 25000310 */  beq        $zero, $v1, .L8007AED8
/* 6B644 8007AE44 00000000 */   nop
/* 6B648 8007AE48 2A086A00 */  slt        $at, $v1, $t2
/* 6B64C 8007AE4C 09002010 */  beqz       $at, .L8007AE74
/* 6B650 8007AE50 20001034 */   ori       $s0, $zero, 0x20
/* 6B654 8007AE54 04106200 */  sllv       $v0, $v0, $v1
/* 6B658 8007AE58 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B65C 8007AE5C 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B660 8007AE60 06900B02 */  srlv       $s2, $t3, $s0
/* 6B664 8007AE64 04586B00 */  sllv       $t3, $t3, $v1
/* 6B668 8007AE68 25105200 */  or         $v0, $v0, $s2
/* 6B66C 8007AE6C F4FF0010 */  b          .L8007AE40
/* 6B670 8007AE70 25180000 */   or        $v1, $zero, $zero
.L8007AE74:
/* 6B674 8007AE74 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B678 8007AE78 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B67C 8007AE7C 06100B02 */  srlv       $v0, $t3, $s0
/* 6B680 8007AE80 00009090 */  lbu        $s0, 0x0($a0)
/* 6B684 8007AE84 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B688 8007AE88 21883001 */  addu       $s1, $t1, $s0
/* 6B68C 8007AE8C 00003292 */  lbu        $s2, 0x0($s1)
/* 6B690 8007AE90 01009090 */  lbu        $s0, 0x1($a0)
/* 6B694 8007AE94 25581200 */  or         $t3, $zero, $s2
/* 6B698 8007AE98 21883001 */  addu       $s1, $t1, $s0
/* 6B69C 8007AE9C 00003292 */  lbu        $s2, 0x0($s1)
/* 6B6A0 8007AEA0 02009090 */  lbu        $s0, 0x2($a0)
/* 6B6A4 8007AEA4 00921200 */  sll        $s2, $s2, 8
/* 6B6A8 8007AEA8 21883001 */  addu       $s1, $t1, $s0
/* 6B6AC 8007AEAC 25587201 */  or         $t3, $t3, $s2
/* 6B6B0 8007AEB0 00003292 */  lbu        $s2, 0x0($s1)
/* 6B6B4 8007AEB4 03009090 */  lbu        $s0, 0x3($a0)
/* 6B6B8 8007AEB8 00941200 */  sll        $s2, $s2, 16
/* 6B6BC 8007AEBC 21883001 */  addu       $s1, $t1, $s0
/* 6B6C0 8007AEC0 25587201 */  or         $t3, $t3, $s2
/* 6B6C4 8007AEC4 00003292 */  lbu        $s2, 0x0($s1)
/* 6B6C8 8007AEC8 20000A34 */  ori        $t2, $zero, 0x20
/* 6B6CC 8007AECC 00961200 */  sll        $s2, $s2, 24
/* 6B6D0 8007AED0 DBFF0010 */  b          .L8007AE40
/* 6B6D4 8007AED4 25587201 */   or        $t3, $t3, $s2
.L8007AED8:
/* 6B6D8 8007AED8 59004014 */  bnez       $v0, .L8007B040
/* 6B6DC 8007AEDC 25780000 */   or        $t7, $zero, $zero
.L8007AEE0:
/* 6B6E0 8007AEE0 02000334 */  ori        $v1, $zero, 0x2
/* 6B6E4 8007AEE4 25100000 */  or         $v0, $zero, $zero
.L8007AEE8:
/* 6B6E8 8007AEE8 25000310 */  beq        $zero, $v1, .L8007AF80
/* 6B6EC 8007AEEC 00000000 */   nop
/* 6B6F0 8007AEF0 2A086A00 */  slt        $at, $v1, $t2
/* 6B6F4 8007AEF4 09002010 */  beqz       $at, .L8007AF1C
/* 6B6F8 8007AEF8 20001034 */   ori       $s0, $zero, 0x20
/* 6B6FC 8007AEFC 04106200 */  sllv       $v0, $v0, $v1
/* 6B700 8007AF00 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B704 8007AF04 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B708 8007AF08 06900B02 */  srlv       $s2, $t3, $s0
/* 6B70C 8007AF0C 04586B00 */  sllv       $t3, $t3, $v1
/* 6B710 8007AF10 25105200 */  or         $v0, $v0, $s2
/* 6B714 8007AF14 F4FF0010 */  b          .L8007AEE8
/* 6B718 8007AF18 25180000 */   or        $v1, $zero, $zero
.L8007AF1C:
/* 6B71C 8007AF1C 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B720 8007AF20 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B724 8007AF24 06100B02 */  srlv       $v0, $t3, $s0
/* 6B728 8007AF28 00009090 */  lbu        $s0, 0x0($a0)
/* 6B72C 8007AF2C 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B730 8007AF30 21883001 */  addu       $s1, $t1, $s0
/* 6B734 8007AF34 00003292 */  lbu        $s2, 0x0($s1)
/* 6B738 8007AF38 01009090 */  lbu        $s0, 0x1($a0)
/* 6B73C 8007AF3C 25581200 */  or         $t3, $zero, $s2
/* 6B740 8007AF40 21883001 */  addu       $s1, $t1, $s0
/* 6B744 8007AF44 00003292 */  lbu        $s2, 0x0($s1)
/* 6B748 8007AF48 02009090 */  lbu        $s0, 0x2($a0)
/* 6B74C 8007AF4C 00921200 */  sll        $s2, $s2, 8
/* 6B750 8007AF50 21883001 */  addu       $s1, $t1, $s0
/* 6B754 8007AF54 25587201 */  or         $t3, $t3, $s2
/* 6B758 8007AF58 00003292 */  lbu        $s2, 0x0($s1)
/* 6B75C 8007AF5C 03009090 */  lbu        $s0, 0x3($a0)
/* 6B760 8007AF60 00941200 */  sll        $s2, $s2, 16
/* 6B764 8007AF64 21883001 */  addu       $s1, $t1, $s0
/* 6B768 8007AF68 25587201 */  or         $t3, $t3, $s2
/* 6B76C 8007AF6C 00003292 */  lbu        $s2, 0x0($s1)
/* 6B770 8007AF70 20000A34 */  ori        $t2, $zero, 0x20
/* 6B774 8007AF74 00961200 */  sll        $s2, $s2, 24
/* 6B778 8007AF78 DBFF0010 */  b          .L8007AEE8
/* 6B77C 8007AF7C 25587201 */   or        $t3, $t3, $s2
.L8007AF80:
/* 6B780 8007AF80 2178E201 */  addu       $t7, $t7, $v0
/* 6B784 8007AF84 D6FF5310 */  beq        $v0, $s3, .L8007AEE0
.L8007AF88:
/* 6B788 8007AF88 08000334 */   ori       $v1, $zero, 0x8
/* 6B78C 8007AF8C 25100000 */  or         $v0, $zero, $zero
.L8007AF90:
/* 6B790 8007AF90 25000310 */  beq        $zero, $v1, .L8007B028
/* 6B794 8007AF94 00000000 */   nop
/* 6B798 8007AF98 2A086A00 */  slt        $at, $v1, $t2
/* 6B79C 8007AF9C 09002010 */  beqz       $at, .L8007AFC4
/* 6B7A0 8007AFA0 20001034 */   ori       $s0, $zero, 0x20
/* 6B7A4 8007AFA4 04106200 */  sllv       $v0, $v0, $v1
/* 6B7A8 8007AFA8 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B7AC 8007AFAC 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B7B0 8007AFB0 06900B02 */  srlv       $s2, $t3, $s0
/* 6B7B4 8007AFB4 04586B00 */  sllv       $t3, $t3, $v1
/* 6B7B8 8007AFB8 25105200 */  or         $v0, $v0, $s2
/* 6B7BC 8007AFBC F4FF0010 */  b          .L8007AF90
/* 6B7C0 8007AFC0 25180000 */   or        $v1, $zero, $zero
.L8007AFC4:
/* 6B7C4 8007AFC4 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B7C8 8007AFC8 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B7CC 8007AFCC 06100B02 */  srlv       $v0, $t3, $s0
/* 6B7D0 8007AFD0 00009090 */  lbu        $s0, 0x0($a0)
/* 6B7D4 8007AFD4 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B7D8 8007AFD8 21883001 */  addu       $s1, $t1, $s0
/* 6B7DC 8007AFDC 00003292 */  lbu        $s2, 0x0($s1)
/* 6B7E0 8007AFE0 01009090 */  lbu        $s0, 0x1($a0)
/* 6B7E4 8007AFE4 25581200 */  or         $t3, $zero, $s2
/* 6B7E8 8007AFE8 21883001 */  addu       $s1, $t1, $s0
/* 6B7EC 8007AFEC 00003292 */  lbu        $s2, 0x0($s1)
/* 6B7F0 8007AFF0 02009090 */  lbu        $s0, 0x2($a0)
/* 6B7F4 8007AFF4 00921200 */  sll        $s2, $s2, 8
/* 6B7F8 8007AFF8 21883001 */  addu       $s1, $t1, $s0
/* 6B7FC 8007AFFC 25587201 */  or         $t3, $t3, $s2
/* 6B800 8007B000 00003292 */  lbu        $s2, 0x0($s1)
/* 6B804 8007B004 03009090 */  lbu        $s0, 0x3($a0)
/* 6B808 8007B008 00941200 */  sll        $s2, $s2, 16
/* 6B80C 8007B00C 21883001 */  addu       $s1, $t1, $s0
/* 6B810 8007B010 25587201 */  or         $t3, $t3, $s2
/* 6B814 8007B014 00003292 */  lbu        $s2, 0x0($s1)
/* 6B818 8007B018 20000A34 */  ori        $t2, $zero, 0x20
/* 6B81C 8007B01C 00961200 */  sll        $s2, $s2, 24
/* 6B820 8007B020 DBFF0010 */  b          .L8007AF90
/* 6B824 8007B024 25587201 */   or        $t3, $t3, $s2
.L8007B028:
/* 6B828 8007B028 FFFFE720 */  addi       $a3, $a3, -0x1 # handwritten instruction
/* 6B82C 8007B02C FFFFEF21 */  addi       $t7, $t7, -0x1 # handwritten instruction
/* 6B830 8007B030 D5FFE105 */  bgez       $t7, .L8007AF88
/* 6B834 8007B034 0000E2A0 */   sb        $v0, 0x0($a3)
/* 6B838 8007B038 2A08A700 */  slt        $at, $a1, $a3
/* 6B83C 8007B03C 06012010 */  beqz       $at, .L8007B458
.L8007B040:
/* 6B840 8007B040 02000334 */   ori       $v1, $zero, 0x2
/* 6B844 8007B044 25100000 */  or         $v0, $zero, $zero
.L8007B048:
/* 6B848 8007B048 25000310 */  beq        $zero, $v1, .L8007B0E0
/* 6B84C 8007B04C 00000000 */   nop
/* 6B850 8007B050 2A086A00 */  slt        $at, $v1, $t2
/* 6B854 8007B054 09002010 */  beqz       $at, .L8007B07C
/* 6B858 8007B058 20001034 */   ori       $s0, $zero, 0x20
/* 6B85C 8007B05C 04106200 */  sllv       $v0, $v0, $v1
/* 6B860 8007B060 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B864 8007B064 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B868 8007B068 06900B02 */  srlv       $s2, $t3, $s0
/* 6B86C 8007B06C 04586B00 */  sllv       $t3, $t3, $v1
/* 6B870 8007B070 25105200 */  or         $v0, $v0, $s2
/* 6B874 8007B074 F4FF0010 */  b          .L8007B048
/* 6B878 8007B078 25180000 */   or        $v1, $zero, $zero
.L8007B07C:
/* 6B87C 8007B07C 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B880 8007B080 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B884 8007B084 06100B02 */  srlv       $v0, $t3, $s0
/* 6B888 8007B088 00009090 */  lbu        $s0, 0x0($a0)
/* 6B88C 8007B08C 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B890 8007B090 21883001 */  addu       $s1, $t1, $s0
/* 6B894 8007B094 00003292 */  lbu        $s2, 0x0($s1)
/* 6B898 8007B098 01009090 */  lbu        $s0, 0x1($a0)
/* 6B89C 8007B09C 25581200 */  or         $t3, $zero, $s2
/* 6B8A0 8007B0A0 21883001 */  addu       $s1, $t1, $s0
/* 6B8A4 8007B0A4 00003292 */  lbu        $s2, 0x0($s1)
/* 6B8A8 8007B0A8 02009090 */  lbu        $s0, 0x2($a0)
/* 6B8AC 8007B0AC 00921200 */  sll        $s2, $s2, 8
/* 6B8B0 8007B0B0 21883001 */  addu       $s1, $t1, $s0
/* 6B8B4 8007B0B4 25587201 */  or         $t3, $t3, $s2
/* 6B8B8 8007B0B8 00003292 */  lbu        $s2, 0x0($s1)
/* 6B8BC 8007B0BC 03009090 */  lbu        $s0, 0x3($a0)
/* 6B8C0 8007B0C0 00941200 */  sll        $s2, $s2, 16
/* 6B8C4 8007B0C4 21883001 */  addu       $s1, $t1, $s0
/* 6B8C8 8007B0C8 25587201 */  or         $t3, $t3, $s2
/* 6B8CC 8007B0CC 00003292 */  lbu        $s2, 0x0($s1)
/* 6B8D0 8007B0D0 20000A34 */  ori        $t2, $zero, 0x20
/* 6B8D4 8007B0D4 00961200 */  sll        $s2, $s2, 24
/* 6B8D8 8007B0D8 DBFF0010 */  b          .L8007B048
/* 6B8DC 8007B0DC 25587201 */   or        $t3, $t3, $s2
.L8007B0E0:
/* 6B8E0 8007B0E0 01004F24 */  addiu      $t7, $v0, 0x1
/* 6B8E4 8007B0E4 21600201 */  addu       $t4, $t0, $v0
/* 6B8E8 8007B0E8 00009991 */  lbu        $t9, 0x0($t4)
/* 6B8EC 8007B0EC A900F415 */  bne        $t7, $s4, .L8007B394
/* 6B8F0 8007B0F0 01000334 */   ori       $v1, $zero, 0x1
/* 6B8F4 8007B0F4 25100000 */  or         $v0, $zero, $zero
.L8007B0F8:
/* 6B8F8 8007B0F8 25000310 */  beq        $zero, $v1, .L8007B190
/* 6B8FC 8007B0FC 00000000 */   nop
/* 6B900 8007B100 2A086A00 */  slt        $at, $v1, $t2
/* 6B904 8007B104 09002010 */  beqz       $at, .L8007B12C
/* 6B908 8007B108 20001034 */   ori       $s0, $zero, 0x20
/* 6B90C 8007B10C 04106200 */  sllv       $v0, $v0, $v1
/* 6B910 8007B110 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B914 8007B114 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B918 8007B118 06900B02 */  srlv       $s2, $t3, $s0
/* 6B91C 8007B11C 04586B00 */  sllv       $t3, $t3, $v1
/* 6B920 8007B120 25105200 */  or         $v0, $v0, $s2
/* 6B924 8007B124 F4FF0010 */  b          .L8007B0F8
/* 6B928 8007B128 25180000 */   or        $v1, $zero, $zero
.L8007B12C:
/* 6B92C 8007B12C 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B930 8007B130 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B934 8007B134 06100B02 */  srlv       $v0, $t3, $s0
/* 6B938 8007B138 00009090 */  lbu        $s0, 0x0($a0)
/* 6B93C 8007B13C 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B940 8007B140 21883001 */  addu       $s1, $t1, $s0
/* 6B944 8007B144 00003292 */  lbu        $s2, 0x0($s1)
/* 6B948 8007B148 01009090 */  lbu        $s0, 0x1($a0)
/* 6B94C 8007B14C 25581200 */  or         $t3, $zero, $s2
/* 6B950 8007B150 21883001 */  addu       $s1, $t1, $s0
/* 6B954 8007B154 00003292 */  lbu        $s2, 0x0($s1)
/* 6B958 8007B158 02009090 */  lbu        $s0, 0x2($a0)
/* 6B95C 8007B15C 00921200 */  sll        $s2, $s2, 8
/* 6B960 8007B160 21883001 */  addu       $s1, $t1, $s0
/* 6B964 8007B164 25587201 */  or         $t3, $t3, $s2
/* 6B968 8007B168 00003292 */  lbu        $s2, 0x0($s1)
/* 6B96C 8007B16C 03009090 */  lbu        $s0, 0x3($a0)
/* 6B970 8007B170 00941200 */  sll        $s2, $s2, 16
/* 6B974 8007B174 21883001 */  addu       $s1, $t1, $s0
/* 6B978 8007B178 25587201 */  or         $t3, $t3, $s2
/* 6B97C 8007B17C 00003292 */  lbu        $s2, 0x0($s1)
/* 6B980 8007B180 20000A34 */  ori        $t2, $zero, 0x20
/* 6B984 8007B184 00961200 */  sll        $s2, $s2, 24
/* 6B988 8007B188 DBFF0010 */  b          .L8007B0F8
/* 6B98C 8007B18C 25587201 */   or        $t3, $t3, $s2
.L8007B190:
/* 6B990 8007B190 2A004014 */  bnez       $v0, .L8007B23C
/* 6B994 8007B194 25181500 */   or        $v1, $zero, $s5
/* 6B998 8007B198 25100000 */  or         $v0, $zero, $zero
.L8007B19C:
/* 6B99C 8007B19C 25000310 */  beq        $zero, $v1, .L8007B234
/* 6B9A0 8007B1A0 00000000 */   nop
/* 6B9A4 8007B1A4 2A086A00 */  slt        $at, $v1, $t2
/* 6B9A8 8007B1A8 09002010 */  beqz       $at, .L8007B1D0
/* 6B9AC 8007B1AC 20001034 */   ori       $s0, $zero, 0x20
/* 6B9B0 8007B1B0 04106200 */  sllv       $v0, $v0, $v1
/* 6B9B4 8007B1B4 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6B9B8 8007B1B8 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6B9BC 8007B1BC 06900B02 */  srlv       $s2, $t3, $s0
/* 6B9C0 8007B1C0 04586B00 */  sllv       $t3, $t3, $v1
/* 6B9C4 8007B1C4 25105200 */  or         $v0, $v0, $s2
/* 6B9C8 8007B1C8 F4FF0010 */  b          .L8007B19C
/* 6B9CC 8007B1CC 25180000 */   or        $v1, $zero, $zero
.L8007B1D0:
/* 6B9D0 8007B1D0 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6B9D4 8007B1D4 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6B9D8 8007B1D8 06100B02 */  srlv       $v0, $t3, $s0
/* 6B9DC 8007B1DC 00009090 */  lbu        $s0, 0x0($a0)
/* 6B9E0 8007B1E0 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6B9E4 8007B1E4 21883001 */  addu       $s1, $t1, $s0
/* 6B9E8 8007B1E8 00003292 */  lbu        $s2, 0x0($s1)
/* 6B9EC 8007B1EC 01009090 */  lbu        $s0, 0x1($a0)
/* 6B9F0 8007B1F0 25581200 */  or         $t3, $zero, $s2
/* 6B9F4 8007B1F4 21883001 */  addu       $s1, $t1, $s0
/* 6B9F8 8007B1F8 00003292 */  lbu        $s2, 0x0($s1)
/* 6B9FC 8007B1FC 02009090 */  lbu        $s0, 0x2($a0)
/* 6BA00 8007B200 00921200 */  sll        $s2, $s2, 8
/* 6BA04 8007B204 21883001 */  addu       $s1, $t1, $s0
/* 6BA08 8007B208 25587201 */  or         $t3, $t3, $s2
/* 6BA0C 8007B20C 00003292 */  lbu        $s2, 0x0($s1)
/* 6BA10 8007B210 03009090 */  lbu        $s0, 0x3($a0)
/* 6BA14 8007B214 00941200 */  sll        $s2, $s2, 16
/* 6BA18 8007B218 21883001 */  addu       $s1, $t1, $s0
/* 6BA1C 8007B21C 25587201 */  or         $t3, $t3, $s2
/* 6BA20 8007B220 00003292 */  lbu        $s2, 0x0($s1)
/* 6BA24 8007B224 20000A34 */  ori        $t2, $zero, 0x20
/* 6BA28 8007B228 00961200 */  sll        $s2, $s2, 24
/* 6BA2C 8007B22C DBFF0010 */  b          .L8007B19C
/* 6BA30 8007B230 25587201 */   or        $t3, $t3, $s2
.L8007B234:
/* 6BA34 8007B234 2A000010 */  b          .L8007B2E0
/* 6BA38 8007B238 25700200 */   or        $t6, $zero, $v0
.L8007B23C:
/* 6BA3C 8007B23C 25181900 */  or         $v1, $zero, $t9
/* 6BA40 8007B240 25100000 */  or         $v0, $zero, $zero
.L8007B244:
/* 6BA44 8007B244 25000310 */  beq        $zero, $v1, .L8007B2DC
/* 6BA48 8007B248 00000000 */   nop
/* 6BA4C 8007B24C 2A086A00 */  slt        $at, $v1, $t2
/* 6BA50 8007B250 09002010 */  beqz       $at, .L8007B278
/* 6BA54 8007B254 20001034 */   ori       $s0, $zero, 0x20
/* 6BA58 8007B258 04106200 */  sllv       $v0, $v0, $v1
/* 6BA5C 8007B25C 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6BA60 8007B260 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6BA64 8007B264 06900B02 */  srlv       $s2, $t3, $s0
/* 6BA68 8007B268 04586B00 */  sllv       $t3, $t3, $v1
/* 6BA6C 8007B26C 25105200 */  or         $v0, $v0, $s2
/* 6BA70 8007B270 F4FF0010 */  b          .L8007B244
/* 6BA74 8007B274 25180000 */   or        $v1, $zero, $zero
.L8007B278:
/* 6BA78 8007B278 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6BA7C 8007B27C FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6BA80 8007B280 06100B02 */  srlv       $v0, $t3, $s0
/* 6BA84 8007B284 00009090 */  lbu        $s0, 0x0($a0)
/* 6BA88 8007B288 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6BA8C 8007B28C 21883001 */  addu       $s1, $t1, $s0
/* 6BA90 8007B290 00003292 */  lbu        $s2, 0x0($s1)
/* 6BA94 8007B294 01009090 */  lbu        $s0, 0x1($a0)
/* 6BA98 8007B298 25581200 */  or         $t3, $zero, $s2
/* 6BA9C 8007B29C 21883001 */  addu       $s1, $t1, $s0
/* 6BAA0 8007B2A0 00003292 */  lbu        $s2, 0x0($s1)
/* 6BAA4 8007B2A4 02009090 */  lbu        $s0, 0x2($a0)
/* 6BAA8 8007B2A8 00921200 */  sll        $s2, $s2, 8
/* 6BAAC 8007B2AC 21883001 */  addu       $s1, $t1, $s0
/* 6BAB0 8007B2B0 25587201 */  or         $t3, $t3, $s2
/* 6BAB4 8007B2B4 00003292 */  lbu        $s2, 0x0($s1)
/* 6BAB8 8007B2B8 03009090 */  lbu        $s0, 0x3($a0)
/* 6BABC 8007B2BC 00941200 */  sll        $s2, $s2, 16
/* 6BAC0 8007B2C0 21883001 */  addu       $s1, $t1, $s0
/* 6BAC4 8007B2C4 25587201 */  or         $t3, $t3, $s2
/* 6BAC8 8007B2C8 00003292 */  lbu        $s2, 0x0($s1)
/* 6BACC 8007B2CC 20000A34 */  ori        $t2, $zero, 0x20
/* 6BAD0 8007B2D0 00961200 */  sll        $s2, $s2, 24
/* 6BAD4 8007B2D4 DBFF0010 */  b          .L8007B244
/* 6BAD8 8007B2D8 25587201 */   or        $t3, $t3, $s2
.L8007B2DC:
/* 6BADC 8007B2DC 25700200 */  or         $t6, $zero, $v0
.L8007B2E0:
/* 6BAE0 8007B2E0 03000334 */  ori        $v1, $zero, 0x3
/* 6BAE4 8007B2E4 25100000 */  or         $v0, $zero, $zero
.L8007B2E8:
/* 6BAE8 8007B2E8 25000310 */  beq        $zero, $v1, .L8007B380
/* 6BAEC 8007B2EC 00000000 */   nop
/* 6BAF0 8007B2F0 2A086A00 */  slt        $at, $v1, $t2
/* 6BAF4 8007B2F4 09002010 */  beqz       $at, .L8007B31C
/* 6BAF8 8007B2F8 20001034 */   ori       $s0, $zero, 0x20
/* 6BAFC 8007B2FC 04106200 */  sllv       $v0, $v0, $v1
/* 6BB00 8007B300 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6BB04 8007B304 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6BB08 8007B308 06900B02 */  srlv       $s2, $t3, $s0
/* 6BB0C 8007B30C 04586B00 */  sllv       $t3, $t3, $v1
/* 6BB10 8007B310 25105200 */  or         $v0, $v0, $s2
/* 6BB14 8007B314 F4FF0010 */  b          .L8007B2E8
/* 6BB18 8007B318 25180000 */   or        $v1, $zero, $zero
.L8007B31C:
/* 6BB1C 8007B31C 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6BB20 8007B320 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6BB24 8007B324 06100B02 */  srlv       $v0, $t3, $s0
/* 6BB28 8007B328 00009090 */  lbu        $s0, 0x0($a0)
/* 6BB2C 8007B32C 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6BB30 8007B330 21883001 */  addu       $s1, $t1, $s0
/* 6BB34 8007B334 00003292 */  lbu        $s2, 0x0($s1)
/* 6BB38 8007B338 01009090 */  lbu        $s0, 0x1($a0)
/* 6BB3C 8007B33C 25581200 */  or         $t3, $zero, $s2
/* 6BB40 8007B340 21883001 */  addu       $s1, $t1, $s0
/* 6BB44 8007B344 00003292 */  lbu        $s2, 0x0($s1)
/* 6BB48 8007B348 02009090 */  lbu        $s0, 0x2($a0)
/* 6BB4C 8007B34C 00921200 */  sll        $s2, $s2, 8
/* 6BB50 8007B350 21883001 */  addu       $s1, $t1, $s0
/* 6BB54 8007B354 25587201 */  or         $t3, $t3, $s2
/* 6BB58 8007B358 00003292 */  lbu        $s2, 0x0($s1)
/* 6BB5C 8007B35C 03009090 */  lbu        $s0, 0x3($a0)
/* 6BB60 8007B360 00941200 */  sll        $s2, $s2, 16
/* 6BB64 8007B364 21883001 */  addu       $s1, $t1, $s0
/* 6BB68 8007B368 25587201 */  or         $t3, $t3, $s2
/* 6BB6C 8007B36C 00003292 */  lbu        $s2, 0x0($s1)
/* 6BB70 8007B370 20000A34 */  ori        $t2, $zero, 0x20
/* 6BB74 8007B374 00961200 */  sll        $s2, $s2, 24
/* 6BB78 8007B378 DBFF0010 */  b          .L8007B2E8
/* 6BB7C 8007B37C 25587201 */   or        $t3, $t3, $s2
.L8007B380:
/* 6BB80 8007B380 2178E201 */  addu       $t7, $t7, $v0
/* 6BB84 8007B384 D6FF5510 */  beq        $v0, $s5, .L8007B2E0
/* 6BB88 8007B388 00000000 */   nop
/* 6BB8C 8007B38C 2A000010 */  b          .L8007B438
/* 6BB90 8007B390 00000000 */   nop
.L8007B394:
/* 6BB94 8007B394 25181900 */  or         $v1, $zero, $t9
/* 6BB98 8007B398 25100000 */  or         $v0, $zero, $zero
.L8007B39C:
/* 6BB9C 8007B39C 25000310 */  beq        $zero, $v1, .L8007B434
/* 6BBA0 8007B3A0 00000000 */   nop
/* 6BBA4 8007B3A4 2A086A00 */  slt        $at, $v1, $t2
/* 6BBA8 8007B3A8 09002010 */  beqz       $at, .L8007B3D0
/* 6BBAC 8007B3AC 20001034 */   ori       $s0, $zero, 0x20
/* 6BBB0 8007B3B0 04106200 */  sllv       $v0, $v0, $v1
/* 6BBB4 8007B3B4 22504301 */  sub        $t2, $t2, $v1 # handwritten instruction
/* 6BBB8 8007B3B8 22800302 */  sub        $s0, $s0, $v1 # handwritten instruction
/* 6BBBC 8007B3BC 06900B02 */  srlv       $s2, $t3, $s0
/* 6BBC0 8007B3C0 04586B00 */  sllv       $t3, $t3, $v1
/* 6BBC4 8007B3C4 25105200 */  or         $v0, $v0, $s2
/* 6BBC8 8007B3C8 F4FF0010 */  b          .L8007B39C
/* 6BBCC 8007B3CC 25180000 */   or        $v1, $zero, $zero
.L8007B3D0:
/* 6BBD0 8007B3D0 22800A02 */  sub        $s0, $s0, $t2 # handwritten instruction
/* 6BBD4 8007B3D4 FCFF8424 */  addiu      $a0, $a0, -0x4
/* 6BBD8 8007B3D8 06100B02 */  srlv       $v0, $t3, $s0
/* 6BBDC 8007B3DC 00009090 */  lbu        $s0, 0x0($a0)
/* 6BBE0 8007B3E0 22186A00 */  sub        $v1, $v1, $t2 # handwritten instruction
/* 6BBE4 8007B3E4 21883001 */  addu       $s1, $t1, $s0
/* 6BBE8 8007B3E8 00003292 */  lbu        $s2, 0x0($s1)
/* 6BBEC 8007B3EC 01009090 */  lbu        $s0, 0x1($a0)
/* 6BBF0 8007B3F0 25581200 */  or         $t3, $zero, $s2
/* 6BBF4 8007B3F4 21883001 */  addu       $s1, $t1, $s0
/* 6BBF8 8007B3F8 00003292 */  lbu        $s2, 0x0($s1)
/* 6BBFC 8007B3FC 02009090 */  lbu        $s0, 0x2($a0)
/* 6BC00 8007B400 00921200 */  sll        $s2, $s2, 8
/* 6BC04 8007B404 21883001 */  addu       $s1, $t1, $s0
/* 6BC08 8007B408 25587201 */  or         $t3, $t3, $s2
/* 6BC0C 8007B40C 00003292 */  lbu        $s2, 0x0($s1)
/* 6BC10 8007B410 03009090 */  lbu        $s0, 0x3($a0)
/* 6BC14 8007B414 00941200 */  sll        $s2, $s2, 16
/* 6BC18 8007B418 21883001 */  addu       $s1, $t1, $s0
/* 6BC1C 8007B41C 25587201 */  or         $t3, $t3, $s2
/* 6BC20 8007B420 00003292 */  lbu        $s2, 0x0($s1)
/* 6BC24 8007B424 20000A34 */  ori        $t2, $zero, 0x20
/* 6BC28 8007B428 00961200 */  sll        $s2, $s2, 24
/* 6BC2C 8007B42C DBFF0010 */  b          .L8007B39C
/* 6BC30 8007B430 25587201 */   or        $t3, $t3, $s2
.L8007B434:
/* 6BC34 8007B434 25700200 */  or         $t6, $zero, $v0
.L8007B438:
/* 6BC38 8007B438 2160EE00 */  addu       $t4, $a3, $t6
/* 6BC3C 8007B43C 00008D91 */  lbu        $t5, 0x0($t4)
/* 6BC40 8007B440 FFFFEF21 */  addi       $t7, $t7, -0x1 # handwritten instruction
/* 6BC44 8007B444 FFFFEDA0 */  sb         $t5, -0x1($a3)
/* 6BC48 8007B448 FBFFE105 */  bgez       $t7, .L8007B438
/* 6BC4C 8007B44C FFFFE724 */   addiu     $a3, $a3, -0x1
/* 6BC50 8007B450 2A08A700 */  slt        $at, $a1, $a3
/* 6BC54 8007B454 78FE2014 */  bnez       $at, .L8007AE38
.L8007B458:
/* 6BC58 8007B458 01000234 */   ori       $v0, $zero, 0x1
.L8007B45C:
/* 6BC5C 8007B45C 1000B08F */  lw         $s0, 0x10($sp)
/* 6BC60 8007B460 1400B18F */  lw         $s1, 0x14($sp)
/* 6BC64 8007B464 1800B28F */  lw         $s2, 0x18($sp)
/* 6BC68 8007B468 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6BC6C 8007B46C 2000B48F */  lw         $s4, 0x20($sp)
/* 6BC70 8007B470 2400B58F */  lw         $s5, 0x24($sp)
/* 6BC74 8007B474 2800B68F */  lw         $s6, 0x28($sp)
/* 6BC78 8007B478 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6BC7C 8007B47C 3000BE8F */  lw         $fp, 0x30($sp)
/* 6BC80 8007B480 0800E003 */  jr         $ra
/* 6BC84 8007B484 3400BD27 */   addiu     $sp, $sp, 0x34
