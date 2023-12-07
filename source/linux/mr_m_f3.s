.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_F3
/* 6C210 8007BA10 1000A28F */  lw         $v0, 0x10($sp)
/* 6C214 8007BA14 1400A38F */  lw         $v1, 0x14($sp)
/* 6C218 8007BA18 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6C21C 8007BA1C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6C220 8007BA20 1400B1AF */  sw         $s1, 0x14($sp)
/* 6C224 8007BA24 1800B2AF */  sw         $s2, 0x18($sp)
/* 6C228 8007BA28 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6C22C 8007BA2C 2000B4AF */  sw         $s4, 0x20($sp)
/* 6C230 8007BA30 2400B5AF */  sw         $s5, 0x24($sp)
/* 6C234 8007BA34 2800B6AF */  sw         $s6, 0x28($sp)
/* 6C238 8007BA38 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6C23C 8007BA3C 3000BEAF */  sw         $fp, 0x30($sp)
/* 6C240 8007BA40 2000508C */  lw         $s0, 0x20($v0)
/* 6C244 8007BA44 24005184 */  lh         $s1, 0x24($v0)
/* 6C248 8007BA48 2800528C */  lw         $s2, 0x28($v0)
/* 6C24C 8007BA4C 2C00538C */  lw         $s3, 0x2C($v0)
/* 6C250 8007BA50 26005484 */  lh         $s4, 0x26($v0)
/* 6C254 8007BA54 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6C258 8007BA58 0000B58E */  lw         $s5, 0x0($s5)
/* 6C25C 8007BA5C 00000000 */  nop
/* 6C260 8007BA60 03AC1500 */  sra        $s5, $s5, 16
/* 6C264 8007BA64 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6C268 8007BA68 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6C26C 8007BA6C 0004173C */  lui        $s7, (0x4000000 >> 16)
/* 6C270 8007BA70 44005E8C */  lw         $fp, 0x44($v0)
/* 6C274 8007BA74 0000C884 */  lh         $t0, 0x0($a2)
/* 6C278 8007BA78 0200C984 */  lh         $t1, 0x2($a2)
/* 6C27C 8007BA7C 0400CA84 */  lh         $t2, 0x4($a2)
/* 6C280 8007BA80 C0400800 */  sll        $t0, $t0, 3
/* 6C284 8007BA84 C0480900 */  sll        $t1, $t1, 3
/* 6C288 8007BA88 C0500A00 */  sll        $t2, $t2, 3
/* 6C28C 8007BA8C 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C290 8007BA90 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C294 8007BA94 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007BA98:
/* 6C298 8007BA98 000000C9 */  lwc2       $0, 0x0($t0)
/* 6C29C 8007BA9C 040001C9 */  lwc2       $1, 0x4($t0)
/* 6C2A0 8007BAA0 000022C9 */  lwc2       $2, 0x0($t1)
/* 6C2A4 8007BAA4 040023C9 */  lwc2       $3, 0x4($t1)
/* 6C2A8 8007BAA8 000044C9 */  lwc2       $4, 0x0($t2)
/* 6C2AC 8007BAAC 040045C9 */  lwc2       $5, 0x4($t2)
/* 6C2B0 8007BAB0 0C00D820 */  addi       $t8, $a2, 0xC # handwritten instruction
/* 6C2B4 8007BAB4 00000000 */  nop
/* 6C2B8 8007BAB8 3000284A */  RTPT
/* 6C2BC 8007BABC 00000887 */  lh         $t0, 0x0($t8)
/* 6C2C0 8007BAC0 02000987 */  lh         $t1, 0x2($t8)
/* 6C2C4 8007BAC4 04000A87 */  lh         $t2, 0x4($t8)
/* 6C2C8 8007BAC8 C0400800 */  sll        $t0, $t0, 3
/* 6C2CC 8007BACC C0480900 */  sll        $t1, $t1, 3
/* 6C2D0 8007BAD0 C0500A00 */  sll        $t2, $t2, 3
/* 6C2D4 8007BAD4 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C2D8 8007BAD8 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C2DC 8007BADC 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6C2E0 8007BAE0 0600404B */  NCLIP
/* 6C2E4 8007BAE4 0800C6C8 */  lwc2       $6, 0x8($a2)
/* 6C2E8 8007BAE8 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6C2EC 8007BAEC 00000000 */  nop
/* 6C2F0 8007BAF0 2000001B */  blez       $t8, .L8007BB74
/* 6C2F4 8007BAF4 00000000 */   nop
/* 6C2F8 8007BAF8 2D00584B */  AVSZ3
/* 6C2FC 8007BAFC 0600CC84 */  lh         $t4, 0x6($a2)
/* 6C300 8007BB00 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6C304 8007BB04 C0600C00 */  sll        $t4, $t4, 3
/* 6C308 8007BB08 07C03802 */  srav       $t8, $t8, $s1
/* 6C30C 8007BB0C 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6C310 8007BB10 2A081303 */  slt        $at, $t8, $s3
/* 6C314 8007BB14 17002014 */  bnez       $at, .L8007BB74
/* 6C318 8007BB18 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6C31C 8007BB1C 2A081203 */  slt        $at, $t8, $s2
/* 6C320 8007BB20 14002010 */  beqz       $at, .L8007BB74
/* 6C324 8007BB24 00000000 */   nop
/* 6C328 8007BB28 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6C32C 8007BB2C 0C00EDE8 */  swc2       $13, 0xC($a3)
/* 6C330 8007BB30 1000EEE8 */  swc2       $14, 0x10($a3)
/* 6C334 8007BB34 000080C9 */  lwc2       $0, 0x0($t4)
/* 6C338 8007BB38 040081C9 */  lwc2       $1, 0x4($t4)
/* 6C33C 8007BB3C 04000310 */  beq        $zero, $v1, .L8007BB50
/* 6C340 8007BB40 00000000 */   nop
/* 6C344 8007BB44 1304E84A */  NCDS
/* 6C348 8007BB48 02000010 */  b          .L8007BB54
/* 6C34C 8007BB4C 00000000 */   nop
.L8007BB50:
/* 6C350 8007BB50 1B04084B */  NCCS
.L8007BB54:
/* 6C354 8007BB54 24C8F600 */  and        $t9, $a3, $s6
/* 6C358 8007BB58 80C01800 */  sll        $t8, $t8, 2
/* 6C35C 8007BB5C 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6C360 8007BB60 0000018F */  lw         $at, 0x0($t8)
/* 6C364 8007BB64 000019AF */  sw         $t9, 0x0($t8)
/* 6C368 8007BB68 25083700 */  or         $at, $at, $s7
/* 6C36C 8007BB6C 000021AF */  sw         $at, 0x0($t9)
/* 6C370 8007BB70 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007BB74:
/* 6C374 8007BB74 0C00C620 */  addi       $a2, $a2, 0xC # handwritten instruction
/* 6C378 8007BB78 1400E720 */  addi       $a3, $a3, 0x14 # handwritten instruction
/* 6C37C 8007BB7C FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6C380 8007BB80 C5FFA01E */  bgtz       $s5, .L8007BA98
/* 6C384 8007BB84 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6C388 8007BB88 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6C38C 8007BB8C 400046AC */  sw         $a2, 0x40($v0)
/* 6C390 8007BB90 44005EAC */  sw         $fp, 0x44($v0)
/* 6C394 8007BB94 1000B08F */  lw         $s0, 0x10($sp)
/* 6C398 8007BB98 1400B18F */  lw         $s1, 0x14($sp)
/* 6C39C 8007BB9C 1800B28F */  lw         $s2, 0x18($sp)
/* 6C3A0 8007BBA0 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6C3A4 8007BBA4 2000B48F */  lw         $s4, 0x20($sp)
/* 6C3A8 8007BBA8 2400B58F */  lw         $s5, 0x24($sp)
/* 6C3AC 8007BBAC 2800B68F */  lw         $s6, 0x28($sp)
/* 6C3B0 8007BBB0 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6C3B4 8007BBB4 3000BE8F */  lw         $fp, 0x30($sp)
/* 6C3B8 8007BBB8 0800E003 */  jr         $ra
/* 6C3BC 8007BBBC 3400BD27 */   addiu     $sp, $sp, 0x34
