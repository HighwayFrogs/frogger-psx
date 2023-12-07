.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_G4
/* 6CB1C 8007C31C 1000A28F */  lw         $v0, 0x10($sp)
/* 6CB20 8007C320 1400A38F */  lw         $v1, 0x14($sp)
/* 6CB24 8007C324 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6CB28 8007C328 1000B0AF */  sw         $s0, 0x10($sp)
/* 6CB2C 8007C32C 1400B1AF */  sw         $s1, 0x14($sp)
/* 6CB30 8007C330 1800B2AF */  sw         $s2, 0x18($sp)
/* 6CB34 8007C334 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6CB38 8007C338 2000B4AF */  sw         $s4, 0x20($sp)
/* 6CB3C 8007C33C 2400B5AF */  sw         $s5, 0x24($sp)
/* 6CB40 8007C340 2800B6AF */  sw         $s6, 0x28($sp)
/* 6CB44 8007C344 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6CB48 8007C348 3000BEAF */  sw         $fp, 0x30($sp)
/* 6CB4C 8007C34C 2000508C */  lw         $s0, 0x20($v0)
/* 6CB50 8007C350 24005184 */  lh         $s1, 0x24($v0)
/* 6CB54 8007C354 2800528C */  lw         $s2, 0x28($v0)
/* 6CB58 8007C358 2C00538C */  lw         $s3, 0x2C($v0)
/* 6CB5C 8007C35C 26005484 */  lh         $s4, 0x26($v0)
/* 6CB60 8007C360 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6CB64 8007C364 0000B58E */  lw         $s5, 0x0($s5)
/* 6CB68 8007C368 00000000 */  nop
/* 6CB6C 8007C36C 03AC1500 */  sra        $s5, $s5, 16
/* 6CB70 8007C370 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6CB74 8007C374 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6CB78 8007C378 0008173C */  lui        $s7, (0x8000000 >> 16)
/* 6CB7C 8007C37C 44005E8C */  lw         $fp, 0x44($v0)
/* 6CB80 8007C380 0000C884 */  lh         $t0, 0x0($a2)
/* 6CB84 8007C384 0200C984 */  lh         $t1, 0x2($a2)
/* 6CB88 8007C388 0400CA84 */  lh         $t2, 0x4($a2)
/* 6CB8C 8007C38C 0600CB84 */  lh         $t3, 0x6($a2)
/* 6CB90 8007C390 C0400800 */  sll        $t0, $t0, 3
/* 6CB94 8007C394 C0480900 */  sll        $t1, $t1, 3
/* 6CB98 8007C398 C0500A00 */  sll        $t2, $t2, 3
/* 6CB9C 8007C39C C0580B00 */  sll        $t3, $t3, 3
/* 6CBA0 8007C3A0 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CBA4 8007C3A4 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CBA8 8007C3A8 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6CBAC 8007C3AC 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007C3B0:
/* 6CBB0 8007C3B0 000000C9 */  lwc2       $0, 0x0($t0)
/* 6CBB4 8007C3B4 040001C9 */  lwc2       $1, 0x4($t0)
/* 6CBB8 8007C3B8 000022C9 */  lwc2       $2, 0x0($t1)
/* 6CBBC 8007C3BC 040023C9 */  lwc2       $3, 0x4($t1)
/* 6CBC0 8007C3C0 000064C9 */  lwc2       $4, 0x0($t3)
/* 6CBC4 8007C3C4 040065C9 */  lwc2       $5, 0x4($t3)
/* 6CBC8 8007C3C8 1400D820 */  addi       $t8, $a2, 0x14 # handwritten instruction
/* 6CBCC 8007C3CC 00000000 */  nop
/* 6CBD0 8007C3D0 3000284A */  RTPT
/* 6CBD4 8007C3D4 00000887 */  lh         $t0, 0x0($t8)
/* 6CBD8 8007C3D8 02000987 */  lh         $t1, 0x2($t8)
/* 6CBDC 8007C3DC 06000B87 */  lh         $t3, 0x6($t8)
/* 6CBE0 8007C3E0 C0400800 */  sll        $t0, $t0, 3
/* 6CBE4 8007C3E4 C0480900 */  sll        $t1, $t1, 3
/* 6CBE8 8007C3E8 C0580B00 */  sll        $t3, $t3, 3
/* 6CBEC 8007C3EC 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CBF0 8007C3F0 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CBF4 8007C3F4 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6CBF8 8007C3F8 0600404B */  NCLIP
/* 6CBFC 8007C3FC 000040C9 */  lwc2       $0, 0x0($t2)
/* 6CC00 8007C400 040041C9 */  lwc2       $1, 0x4($t2)
/* 6CC04 8007C404 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6CC08 8007C408 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6CC0C 8007C40C 0100184A */  RTPS
/* 6CC10 8007C410 1000C6C8 */  lwc2       $6, 0x10($a2)
/* 6CC14 8007C414 04000A87 */  lh         $t2, 0x4($t8)
/* 6CC18 8007C418 00000000 */  nop
/* 6CC1C 8007C41C C0500A00 */  sll        $t2, $t2, 3
/* 6CC20 8007C420 0600201F */  bgtz       $t9, .L8007C43C
/* 6CC24 8007C424 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6CC28 8007C428 0600404B */  NCLIP
/* 6CC2C 8007C42C 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6CC30 8007C430 00000000 */  nop
/* 6CC34 8007C434 43002107 */  bgez       $t9, .L8007C544
/* 6CC38 8007C438 00000000 */   nop
.L8007C43C:
/* 6CC3C 8007C43C 2E00684B */  AVSZ4
/* 6CC40 8007C440 0800CC84 */  lh         $t4, 0x8($a2)
/* 6CC44 8007C444 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6CC48 8007C448 C0600C00 */  sll        $t4, $t4, 3
/* 6CC4C 8007C44C 07C03802 */  srav       $t8, $t8, $s1
/* 6CC50 8007C450 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6CC54 8007C454 2A081303 */  slt        $at, $t8, $s3
/* 6CC58 8007C458 3A002014 */  bnez       $at, .L8007C544
/* 6CC5C 8007C45C 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6CC60 8007C460 2A081203 */  slt        $at, $t8, $s2
/* 6CC64 8007C464 37002010 */  beqz       $at, .L8007C544
/* 6CC68 8007C468 0A00CD84 */   lh        $t5, 0xA($a2)
/* 6CC6C 8007C46C 0E00CF84 */  lh         $t7, 0xE($a2)
/* 6CC70 8007C470 1000ECE8 */  swc2       $12, 0x10($a3)
/* 6CC74 8007C474 1800EDE8 */  swc2       $13, 0x18($a3)
/* 6CC78 8007C478 2000EEE8 */  swc2       $14, 0x20($a3)
/* 6CC7C 8007C47C C0680D00 */  sll        $t5, $t5, 3
/* 6CC80 8007C480 C0780F00 */  sll        $t7, $t7, 3
/* 6CC84 8007C484 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6CC88 8007C488 2078E501 */  add        $t7, $t7, $a1 # handwritten instruction
/* 6CC8C 8007C48C 000080C9 */  lwc2       $0, 0x0($t4)
/* 6CC90 8007C490 040081C9 */  lwc2       $1, 0x4($t4)
/* 6CC94 8007C494 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6CC98 8007C498 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6CC9C 8007C49C 0000E4C9 */  lwc2       $4, 0x0($t7)
/* 6CCA0 8007C4A0 0400E5C9 */  lwc2       $5, 0x4($t7)
/* 6CCA4 8007C4A4 14000310 */  beq        $zero, $v1, .L8007C4F8
/* 6CCA8 8007C4A8 00000000 */   nop
/* 6CCAC 8007C4AC 1604F84A */  NCDT
/* 6CCB0 8007C4B0 0C00CE84 */  lh         $t6, 0xC($a2)
/* 6CCB4 8007C4B4 24C8F600 */  and        $t9, $a3, $s6
/* 6CCB8 8007C4B8 80C01800 */  sll        $t8, $t8, 2
/* 6CCBC 8007C4BC 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6CCC0 8007C4C0 0000018F */  lw         $at, 0x0($t8)
/* 6CCC4 8007C4C4 000019AF */  sw         $t9, 0x0($t8)
/* 6CCC8 8007C4C8 25083700 */  or         $at, $at, $s7
/* 6CCCC 8007C4CC 000021AF */  sw         $at, 0x0($t9)
/* 6CCD0 8007C4D0 C0700E00 */  sll        $t6, $t6, 3
/* 6CCD4 8007C4D4 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6CCD8 8007C4D8 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6CCDC 8007C4DC 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6CCE0 8007C4E0 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6CCE4 8007C4E4 0C00F5E8 */  swc2       $21, 0xC($a3)
/* 6CCE8 8007C4E8 1400F6E8 */  swc2       $22, 0x14($a3)
/* 6CCEC 8007C4EC 1304E84A */  NCDS
/* 6CCF0 8007C4F0 13000010 */  b          .L8007C540
/* 6CCF4 8007C4F4 00000000 */   nop
.L8007C4F8:
/* 6CCF8 8007C4F8 3F04184B */  NCCT
/* 6CCFC 8007C4FC 0C00CE84 */  lh         $t6, 0xC($a2)
/* 6CD00 8007C500 24C8F600 */  and        $t9, $a3, $s6
/* 6CD04 8007C504 80C01800 */  sll        $t8, $t8, 2
/* 6CD08 8007C508 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6CD0C 8007C50C 0000018F */  lw         $at, 0x0($t8)
/* 6CD10 8007C510 000019AF */  sw         $t9, 0x0($t8)
/* 6CD14 8007C514 25083700 */  or         $at, $at, $s7
/* 6CD18 8007C518 000021AF */  sw         $at, 0x0($t9)
/* 6CD1C 8007C51C C0700E00 */  sll        $t6, $t6, 3
/* 6CD20 8007C520 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6CD24 8007C524 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6CD28 8007C528 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6CD2C 8007C52C 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6CD30 8007C530 0C00F5E8 */  swc2       $21, 0xC($a3)
/* 6CD34 8007C534 1400F6E8 */  swc2       $22, 0x14($a3)
/* 6CD38 8007C538 1B04084B */  NCCS
/* 6CD3C 8007C53C 00000000 */  nop
.L8007C540:
/* 6CD40 8007C540 1C00F6E8 */  swc2       $22, 0x1C($a3)
.L8007C544:
/* 6CD44 8007C544 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6CD48 8007C548 1400C620 */  addi       $a2, $a2, 0x14 # handwritten instruction
/* 6CD4C 8007C54C 2400E720 */  addi       $a3, $a3, 0x24 # handwritten instruction
/* 6CD50 8007C550 97FFA01E */  bgtz       $s5, .L8007C3B0
/* 6CD54 8007C554 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6CD58 8007C558 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6CD5C 8007C55C 400046AC */  sw         $a2, 0x40($v0)
/* 6CD60 8007C560 44005EAC */  sw         $fp, 0x44($v0)
/* 6CD64 8007C564 1000B08F */  lw         $s0, 0x10($sp)
/* 6CD68 8007C568 1400B18F */  lw         $s1, 0x14($sp)
/* 6CD6C 8007C56C 1800B28F */  lw         $s2, 0x18($sp)
/* 6CD70 8007C570 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6CD74 8007C574 2000B48F */  lw         $s4, 0x20($sp)
/* 6CD78 8007C578 2400B58F */  lw         $s5, 0x24($sp)
/* 6CD7C 8007C57C 2800B68F */  lw         $s6, 0x28($sp)
/* 6CD80 8007C580 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6CD84 8007C584 3000BE8F */  lw         $fp, 0x30($sp)
/* 6CD88 8007C588 0800E003 */  jr         $ra
/* 6CD8C 8007C58C 3400BD27 */   addiu     $sp, $sp, 0x34
