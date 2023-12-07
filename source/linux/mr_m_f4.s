.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_F4
/* 6C3C0 8007BBC0 1000A28F */  lw         $v0, 0x10($sp)
/* 6C3C4 8007BBC4 1400A38F */  lw         $v1, 0x14($sp)
/* 6C3C8 8007BBC8 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6C3CC 8007BBCC 1000B0AF */  sw         $s0, 0x10($sp)
/* 6C3D0 8007BBD0 1400B1AF */  sw         $s1, 0x14($sp)
/* 6C3D4 8007BBD4 1800B2AF */  sw         $s2, 0x18($sp)
/* 6C3D8 8007BBD8 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6C3DC 8007BBDC 2000B4AF */  sw         $s4, 0x20($sp)
/* 6C3E0 8007BBE0 2400B5AF */  sw         $s5, 0x24($sp)
/* 6C3E4 8007BBE4 2800B6AF */  sw         $s6, 0x28($sp)
/* 6C3E8 8007BBE8 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6C3EC 8007BBEC 3000BEAF */  sw         $fp, 0x30($sp)
/* 6C3F0 8007BBF0 2000508C */  lw         $s0, 0x20($v0)
/* 6C3F4 8007BBF4 24005184 */  lh         $s1, 0x24($v0)
/* 6C3F8 8007BBF8 2800528C */  lw         $s2, 0x28($v0)
/* 6C3FC 8007BBFC 2C00538C */  lw         $s3, 0x2C($v0)
/* 6C400 8007BC00 26005484 */  lh         $s4, 0x26($v0)
/* 6C404 8007BC04 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6C408 8007BC08 0000B58E */  lw         $s5, 0x0($s5)
/* 6C40C 8007BC0C 00000000 */  nop
/* 6C410 8007BC10 03AC1500 */  sra        $s5, $s5, 16
/* 6C414 8007BC14 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6C418 8007BC18 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6C41C 8007BC1C 0005173C */  lui        $s7, (0x5000000 >> 16)
/* 6C420 8007BC20 44005E8C */  lw         $fp, 0x44($v0)
/* 6C424 8007BC24 0000C884 */  lh         $t0, 0x0($a2)
/* 6C428 8007BC28 0200C984 */  lh         $t1, 0x2($a2)
/* 6C42C 8007BC2C 0400CA84 */  lh         $t2, 0x4($a2)
/* 6C430 8007BC30 0600CB84 */  lh         $t3, 0x6($a2)
/* 6C434 8007BC34 C0400800 */  sll        $t0, $t0, 3
/* 6C438 8007BC38 C0480900 */  sll        $t1, $t1, 3
/* 6C43C 8007BC3C C0500A00 */  sll        $t2, $t2, 3
/* 6C440 8007BC40 C0580B00 */  sll        $t3, $t3, 3
/* 6C444 8007BC44 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C448 8007BC48 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C44C 8007BC4C 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6C450 8007BC50 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007BC54:
/* 6C454 8007BC54 000000C9 */  lwc2       $0, 0x0($t0)
/* 6C458 8007BC58 040001C9 */  lwc2       $1, 0x4($t0)
/* 6C45C 8007BC5C 000022C9 */  lwc2       $2, 0x0($t1)
/* 6C460 8007BC60 040023C9 */  lwc2       $3, 0x4($t1)
/* 6C464 8007BC64 000064C9 */  lwc2       $4, 0x0($t3)
/* 6C468 8007BC68 040065C9 */  lwc2       $5, 0x4($t3)
/* 6C46C 8007BC6C 1000D820 */  addi       $t8, $a2, 0x10 # handwritten instruction
/* 6C470 8007BC70 00000000 */  nop
/* 6C474 8007BC74 3000284A */  RTPT
/* 6C478 8007BC78 00000887 */  lh         $t0, 0x0($t8)
/* 6C47C 8007BC7C 02000987 */  lh         $t1, 0x2($t8)
/* 6C480 8007BC80 06000B87 */  lh         $t3, 0x6($t8)
/* 6C484 8007BC84 C0400800 */  sll        $t0, $t0, 3
/* 6C488 8007BC88 C0480900 */  sll        $t1, $t1, 3
/* 6C48C 8007BC8C C0580B00 */  sll        $t3, $t3, 3
/* 6C490 8007BC90 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C494 8007BC94 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C498 8007BC98 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6C49C 8007BC9C 0600404B */  NCLIP
/* 6C4A0 8007BCA0 000040C9 */  lwc2       $0, 0x0($t2)
/* 6C4A4 8007BCA4 040041C9 */  lwc2       $1, 0x4($t2)
/* 6C4A8 8007BCA8 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6C4AC 8007BCAC 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6C4B0 8007BCB0 0100184A */  RTPS
/* 6C4B4 8007BCB4 0C00C6C8 */  lwc2       $6, 0xC($a2)
/* 6C4B8 8007BCB8 04000A87 */  lh         $t2, 0x4($t8)
/* 6C4BC 8007BCBC 00000000 */  nop
/* 6C4C0 8007BCC0 C0500A00 */  sll        $t2, $t2, 3
/* 6C4C4 8007BCC4 0600201F */  bgtz       $t9, .L8007BCE0
/* 6C4C8 8007BCC8 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6C4CC 8007BCCC 0600404B */  NCLIP
/* 6C4D0 8007BCD0 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6C4D4 8007BCD4 00000000 */  nop
/* 6C4D8 8007BCD8 20002107 */  bgez       $t9, .L8007BD5C
/* 6C4DC 8007BCDC 00000000 */   nop
.L8007BCE0:
/* 6C4E0 8007BCE0 2E00684B */  AVSZ4
/* 6C4E4 8007BCE4 0800CC84 */  lh         $t4, 0x8($a2)
/* 6C4E8 8007BCE8 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6C4EC 8007BCEC C0600C00 */  sll        $t4, $t4, 3
/* 6C4F0 8007BCF0 07C03802 */  srav       $t8, $t8, $s1
/* 6C4F4 8007BCF4 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6C4F8 8007BCF8 2A081303 */  slt        $at, $t8, $s3
/* 6C4FC 8007BCFC 17002014 */  bnez       $at, .L8007BD5C
/* 6C500 8007BD00 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6C504 8007BD04 2A081203 */  slt        $at, $t8, $s2
/* 6C508 8007BD08 14002010 */  beqz       $at, .L8007BD5C
/* 6C50C 8007BD0C 00000000 */   nop
/* 6C510 8007BD10 0C00ECE8 */  swc2       $12, 0xC($a3)
/* 6C514 8007BD14 1000EDE8 */  swc2       $13, 0x10($a3)
/* 6C518 8007BD18 1400EEE8 */  swc2       $14, 0x14($a3)
/* 6C51C 8007BD1C 000080C9 */  lwc2       $0, 0x0($t4)
/* 6C520 8007BD20 040081C9 */  lwc2       $1, 0x4($t4)
/* 6C524 8007BD24 04000310 */  beq        $zero, $v1, .L8007BD38
/* 6C528 8007BD28 00000000 */   nop
/* 6C52C 8007BD2C 1304E84A */  NCDS
/* 6C530 8007BD30 02000010 */  b          .L8007BD3C
/* 6C534 8007BD34 00000000 */   nop
.L8007BD38:
/* 6C538 8007BD38 1B04084B */  NCCS
.L8007BD3C:
/* 6C53C 8007BD3C 24C8F600 */  and        $t9, $a3, $s6
/* 6C540 8007BD40 80C01800 */  sll        $t8, $t8, 2
/* 6C544 8007BD44 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6C548 8007BD48 0000018F */  lw         $at, 0x0($t8)
/* 6C54C 8007BD4C 000019AF */  sw         $t9, 0x0($t8)
/* 6C550 8007BD50 25083700 */  or         $at, $at, $s7
/* 6C554 8007BD54 000021AF */  sw         $at, 0x0($t9)
/* 6C558 8007BD58 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007BD5C:
/* 6C55C 8007BD5C FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6C560 8007BD60 1000C620 */  addi       $a2, $a2, 0x10 # handwritten instruction
/* 6C564 8007BD64 1800E720 */  addi       $a3, $a3, 0x18 # handwritten instruction
/* 6C568 8007BD68 BAFFA01E */  bgtz       $s5, .L8007BC54
/* 6C56C 8007BD6C FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6C570 8007BD70 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6C574 8007BD74 400046AC */  sw         $a2, 0x40($v0)
/* 6C578 8007BD78 44005EAC */  sw         $fp, 0x44($v0)
/* 6C57C 8007BD7C 1000B08F */  lw         $s0, 0x10($sp)
/* 6C580 8007BD80 1400B18F */  lw         $s1, 0x14($sp)
/* 6C584 8007BD84 1800B28F */  lw         $s2, 0x18($sp)
/* 6C588 8007BD88 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6C58C 8007BD8C 2000B48F */  lw         $s4, 0x20($sp)
/* 6C590 8007BD90 2400B58F */  lw         $s5, 0x24($sp)
/* 6C594 8007BD94 2800B68F */  lw         $s6, 0x28($sp)
/* 6C598 8007BD98 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6C59C 8007BD9C 3000BE8F */  lw         $fp, 0x30($sp)
/* 6C5A0 8007BDA0 0800E003 */  jr         $ra
/* 6C5A4 8007BDA4 3400BD27 */   addiu     $sp, $sp, 0x34
