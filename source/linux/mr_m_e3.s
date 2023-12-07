.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_E3
/* 6D1E0 8007C9E0 1000A28F */  lw         $v0, 0x10($sp)
/* 6D1E4 8007C9E4 1400A38F */  lw         $v1, 0x14($sp)
/* 6D1E8 8007C9E8 BCFFBD27 */  addiu      $sp, $sp, -0x44
/* 6D1EC 8007C9EC 1000B0AF */  sw         $s0, 0x10($sp)
/* 6D1F0 8007C9F0 1400B1AF */  sw         $s1, 0x14($sp)
/* 6D1F4 8007C9F4 1800B2AF */  sw         $s2, 0x18($sp)
/* 6D1F8 8007C9F8 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6D1FC 8007C9FC 2000B4AF */  sw         $s4, 0x20($sp)
/* 6D200 8007CA00 2400B5AF */  sw         $s5, 0x24($sp)
/* 6D204 8007CA04 2800B6AF */  sw         $s6, 0x28($sp)
/* 6D208 8007CA08 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6D20C 8007CA0C 3000BEAF */  sw         $fp, 0x30($sp)
/* 6D210 8007CA10 2000508C */  lw         $s0, 0x20($v0)
/* 6D214 8007CA14 24005184 */  lh         $s1, 0x24($v0)
/* 6D218 8007CA18 2800528C */  lw         $s2, 0x28($v0)
/* 6D21C 8007CA1C 2C00538C */  lw         $s3, 0x2C($v0)
/* 6D220 8007CA20 26005484 */  lh         $s4, 0x26($v0)
/* 6D224 8007CA24 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6D228 8007CA28 0000B58E */  lw         $s5, 0x0($s5)
/* 6D22C 8007CA2C 00000000 */  nop
/* 6D230 8007CA30 03AC1500 */  sra        $s5, $s5, 16
/* 6D234 8007CA34 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6D238 8007CA38 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6D23C 8007CA3C 0007173C */  lui        $s7, (0x7000000 >> 16)
/* 6D240 8007CA40 3400B6AF */  sw         $s6, 0x34($sp)
/* 6D244 8007CA44 3800B7AF */  sw         $s7, 0x38($sp)
/* 6D248 8007CA48 0B80193C */  lui        $t9, %hi(MREnv_strip)
/* 6D24C 8007CA4C 0000013C */  lui        $at, 0
/* 6D250 8007CA50 21083900 */  addu       $at, $at, $t9
/* 6D254 8007CA54 603A2D8C */  lw         $t5, %lo(MREnv_strip)($t9)
/* 6D258 8007CA58 00000000 */  nop
/* 6D25C 8007CA5C 0400B691 */  lbu        $s6, 0x4($t5)
/* 6D260 8007CA60 0500B791 */  lbu        $s7, 0x5($t5)
/* 6D264 8007CA64 4000D626 */  addiu      $s6, $s6, 0x40
/* 6D268 8007CA68 4000F726 */  addiu      $s7, $s7, 0x40
/* 6D26C 8007CA6C 3C00B6AF */  sw         $s6, 0x3C($sp)
/* 6D270 8007CA70 4000B7AF */  sw         $s7, 0x40($sp)
/* 6D274 8007CA74 44005E8C */  lw         $fp, 0x44($v0)
/* 6D278 8007CA78 0000C884 */  lh         $t0, 0x0($a2)
/* 6D27C 8007CA7C 0200C984 */  lh         $t1, 0x2($a2)
/* 6D280 8007CA80 0400CA84 */  lh         $t2, 0x4($a2)
/* 6D284 8007CA84 C0400800 */  sll        $t0, $t0, 3
/* 6D288 8007CA88 C0480900 */  sll        $t1, $t1, 3
/* 6D28C 8007CA8C C0500A00 */  sll        $t2, $t2, 3
/* 6D290 8007CA90 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D294 8007CA94 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D298 8007CA98 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007CA9C:
/* 6D29C 8007CA9C 000000C9 */  lwc2       $0, 0x0($t0)
/* 6D2A0 8007CAA0 040001C9 */  lwc2       $1, 0x4($t0)
/* 6D2A4 8007CAA4 000022C9 */  lwc2       $2, 0x0($t1)
/* 6D2A8 8007CAA8 040023C9 */  lwc2       $3, 0x4($t1)
/* 6D2AC 8007CAAC 000044C9 */  lwc2       $4, 0x0($t2)
/* 6D2B0 8007CAB0 040045C9 */  lwc2       $5, 0x4($t2)
/* 6D2B4 8007CAB4 1400D820 */  addi       $t8, $a2, 0x14 # handwritten instruction
/* 6D2B8 8007CAB8 00000000 */  nop
/* 6D2BC 8007CABC 3000284A */  RTPT
/* 6D2C0 8007CAC0 00000887 */  lh         $t0, 0x0($t8)
/* 6D2C4 8007CAC4 02000987 */  lh         $t1, 0x2($t8)
/* 6D2C8 8007CAC8 04000A87 */  lh         $t2, 0x4($t8)
/* 6D2CC 8007CACC C0400800 */  sll        $t0, $t0, 3
/* 6D2D0 8007CAD0 C0480900 */  sll        $t1, $t1, 3
/* 6D2D4 8007CAD4 C0500A00 */  sll        $t2, $t2, 3
/* 6D2D8 8007CAD8 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D2DC 8007CADC 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D2E0 8007CAE0 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6D2E4 8007CAE4 0600404B */  NCLIP
/* 6D2E8 8007CAE8 1000C6C8 */  lwc2       $6, 0x10($a2)
/* 6D2EC 8007CAEC 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6D2F0 8007CAF0 00000000 */  nop
/* 6D2F4 8007CAF4 7B00001B */  blez       $t8, .L8007CCE4
/* 6D2F8 8007CAF8 00000000 */   nop
/* 6D2FC 8007CAFC 2D00584B */  AVSZ3
/* 6D300 8007CB00 0600CC84 */  lh         $t4, 0x6($a2)
/* 6D304 8007CB04 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6D308 8007CB08 C0600C00 */  sll        $t4, $t4, 3
/* 6D30C 8007CB0C 07C03802 */  srav       $t8, $t8, $s1
/* 6D310 8007CB10 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6D314 8007CB14 2A081303 */  slt        $at, $t8, $s3
/* 6D318 8007CB18 72002014 */  bnez       $at, .L8007CCE4
/* 6D31C 8007CB1C 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6D320 8007CB20 2A081203 */  slt        $at, $t8, $s2
/* 6D324 8007CB24 6F002010 */  beqz       $at, .L8007CCE4
/* 6D328 8007CB28 00000000 */   nop
/* 6D32C 8007CB2C 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6D330 8007CB30 1000EDE8 */  swc2       $13, 0x10($a3)
/* 6D334 8007CB34 1800EEE8 */  swc2       $14, 0x18($a3)
/* 6D338 8007CB38 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6D33C 8007CB3C 0000013C */  lui        $at, (0x38 >> 16)
/* 6D340 8007CB40 21083900 */  addu       $at, $at, $t9
/* 6D344 8007CB44 38002D8C */  lw         $t5, (0x38 & 0xFFFF)($at)
/* 6D348 8007CB48 00000000 */  nop
/* 6D34C 8007CB4C 0000AE8D */  lw         $t6, 0x0($t5)
/* 6D350 8007CB50 0400AF8D */  lw         $t7, 0x4($t5)
/* 6D354 8007CB54 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6D358 8007CB58 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6D35C 8007CB5C 0800AE8D */  lw         $t6, 0x8($t5)
/* 6D360 8007CB60 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6D364 8007CB64 1000B98D */  lw         $t9, 0x10($t5)
/* 6D368 8007CB68 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6D36C 8007CB6C 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6D370 8007CB70 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6D374 8007CB74 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D378 8007CB78 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D37C 8007CB7C 3C00B68F */  lw         $s6, 0x3C($sp)
/* 6D380 8007CB80 4000B78F */  lw         $s7, 0x40($sp)
/* 6D384 8007CB84 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6D388 8007CB88 0800CC84 */  lh         $t4, 0x8($a2)
/* 6D38C 8007CB8C 00000000 */  nop
/* 6D390 8007CB90 C0600C00 */  sll        $t4, $t4, 3
/* 6D394 8007CB94 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D398 8007CB98 000082C9 */  lwc2       $2, 0x0($t4)
/* 6D39C 8007CB9C 040083C9 */  lwc2       $3, 0x4($t4)
/* 6D3A0 8007CBA0 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D3A4 8007CBA4 00000000 */  nop
/* 6D3A8 8007CBA8 83690D00 */  sra        $t5, $t5, 6
/* 6D3AC 8007CBAC 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D3B0 8007CBB0 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D3B4 8007CBB4 00000000 */  nop
/* 6D3B8 8007CBB8 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D3BC 8007CBBC 83710E00 */  sra        $t6, $t6, 6
/* 6D3C0 8007CBC0 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D3C4 8007CBC4 00720E00 */  sll        $t6, $t6, 8
/* 6D3C8 8007CBC8 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D3CC 8007CBCC 0C00EDA4 */  sh         $t5, 0xC($a3)
/* 6D3D0 8007CBD0 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6D3D4 8007CBD4 0A00CC84 */  lh         $t4, 0xA($a2)
/* 6D3D8 8007CBD8 00000000 */  nop
/* 6D3DC 8007CBDC C0600C00 */  sll        $t4, $t4, 3
/* 6D3E0 8007CBE0 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D3E4 8007CBE4 000084C9 */  lwc2       $4, 0x0($t4)
/* 6D3E8 8007CBE8 040085C9 */  lwc2       $5, 0x4($t4)
/* 6D3EC 8007CBEC 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D3F0 8007CBF0 00000000 */  nop
/* 6D3F4 8007CBF4 83690D00 */  sra        $t5, $t5, 6
/* 6D3F8 8007CBF8 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D3FC 8007CBFC 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D400 8007CC00 00000000 */  nop
/* 6D404 8007CC04 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D408 8007CC08 83710E00 */  sra        $t6, $t6, 6
/* 6D40C 8007CC0C 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D410 8007CC10 00720E00 */  sll        $t6, $t6, 8
/* 6D414 8007CC14 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D418 8007CC18 1400EDA4 */  sh         $t5, 0x14($a3)
/* 6D41C 8007CC1C 1260494A */  MVMVA      1, 0, 2, 3, 0
/* 6D420 8007CC20 0C00CC84 */  lh         $t4, 0xC($a2)
/* 6D424 8007CC24 00000000 */  nop
/* 6D428 8007CC28 C0600C00 */  sll        $t4, $t4, 3
/* 6D42C 8007CC2C 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D430 8007CC30 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D434 8007CC34 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D438 8007CC38 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D43C 8007CC3C 00000000 */  nop
/* 6D440 8007CC40 83690D00 */  sra        $t5, $t5, 6
/* 6D444 8007CC44 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D448 8007CC48 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D44C 8007CC4C 00000000 */  nop
/* 6D450 8007CC50 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D454 8007CC54 83710E00 */  sra        $t6, $t6, 6
/* 6D458 8007CC58 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D45C 8007CC5C 00720E00 */  sll        $t6, $t6, 8
/* 6D460 8007CC60 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D464 8007CC64 1C00EDA4 */  sh         $t5, 0x1C($a3)
/* 6D468 8007CC68 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6D46C 8007CC6C 0000013C */  lui        $at, (0x34 >> 16)
/* 6D470 8007CC70 21083900 */  addu       $at, $at, $t9
/* 6D474 8007CC74 34002D8C */  lw         $t5, (0x34 & 0xFFFF)($at)
/* 6D478 8007CC78 00000000 */  nop
/* 6D47C 8007CC7C 0000AE8D */  lw         $t6, 0x0($t5)
/* 6D480 8007CC80 0400AF8D */  lw         $t7, 0x4($t5)
/* 6D484 8007CC84 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6D488 8007CC88 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6D48C 8007CC8C 0800AE8D */  lw         $t6, 0x8($t5)
/* 6D490 8007CC90 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6D494 8007CC94 1000B98D */  lw         $t9, 0x10($t5)
/* 6D498 8007CC98 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6D49C 8007CC9C 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6D4A0 8007CCA0 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6D4A4 8007CCA4 04000310 */  beq        $zero, $v1, .L8007CCB8
/* 6D4A8 8007CCA8 00000000 */   nop
/* 6D4AC 8007CCAC 1304E84A */  NCDS
/* 6D4B0 8007CCB0 02000010 */  b          .L8007CCBC
/* 6D4B4 8007CCB4 00000000 */   nop
.L8007CCB8:
/* 6D4B8 8007CCB8 1B04084B */  NCCS
.L8007CCBC:
/* 6D4BC 8007CCBC 3400B68F */  lw         $s6, 0x34($sp)
/* 6D4C0 8007CCC0 3800B78F */  lw         $s7, 0x38($sp)
/* 6D4C4 8007CCC4 24C8F600 */  and        $t9, $a3, $s6
/* 6D4C8 8007CCC8 80C01800 */  sll        $t8, $t8, 2
/* 6D4CC 8007CCCC 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6D4D0 8007CCD0 0000018F */  lw         $at, 0x0($t8)
/* 6D4D4 8007CCD4 000019AF */  sw         $t9, 0x0($t8)
/* 6D4D8 8007CCD8 25083700 */  or         $at, $at, $s7
/* 6D4DC 8007CCDC 000021AF */  sw         $at, 0x0($t9)
/* 6D4E0 8007CCE0 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007CCE4:
/* 6D4E4 8007CCE4 1400C620 */  addi       $a2, $a2, 0x14 # handwritten instruction
/* 6D4E8 8007CCE8 2000E720 */  addi       $a3, $a3, 0x20 # handwritten instruction
/* 6D4EC 8007CCEC FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6D4F0 8007CCF0 6AFFA01E */  bgtz       $s5, .L8007CA9C
/* 6D4F4 8007CCF4 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6D4F8 8007CCF8 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6D4FC 8007CCFC 400046AC */  sw         $a2, 0x40($v0)
/* 6D500 8007CD00 44005EAC */  sw         $fp, 0x44($v0)
/* 6D504 8007CD04 1000B08F */  lw         $s0, 0x10($sp)
/* 6D508 8007CD08 1400B18F */  lw         $s1, 0x14($sp)
/* 6D50C 8007CD0C 1800B28F */  lw         $s2, 0x18($sp)
/* 6D510 8007CD10 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6D514 8007CD14 2000B48F */  lw         $s4, 0x20($sp)
/* 6D518 8007CD18 2400B58F */  lw         $s5, 0x24($sp)
/* 6D51C 8007CD1C 2800B68F */  lw         $s6, 0x28($sp)
/* 6D520 8007CD20 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6D524 8007CD24 3000BE8F */  lw         $fp, 0x30($sp)
/* 6D528 8007CD28 0800E003 */  jr         $ra
/* 6D52C 8007CD2C 4400BD27 */   addiu     $sp, $sp, 0x44
