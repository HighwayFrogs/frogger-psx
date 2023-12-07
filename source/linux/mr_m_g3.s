.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_G3
/* 6C940 8007C140 1000A28F */  lw         $v0, 0x10($sp)
/* 6C944 8007C144 1400A38F */  lw         $v1, 0x14($sp)
/* 6C948 8007C148 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6C94C 8007C14C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6C950 8007C150 1400B1AF */  sw         $s1, 0x14($sp)
/* 6C954 8007C154 1800B2AF */  sw         $s2, 0x18($sp)
/* 6C958 8007C158 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6C95C 8007C15C 2000B4AF */  sw         $s4, 0x20($sp)
/* 6C960 8007C160 2400B5AF */  sw         $s5, 0x24($sp)
/* 6C964 8007C164 2800B6AF */  sw         $s6, 0x28($sp)
/* 6C968 8007C168 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6C96C 8007C16C 3000BEAF */  sw         $fp, 0x30($sp)
/* 6C970 8007C170 2000508C */  lw         $s0, 0x20($v0)
/* 6C974 8007C174 24005184 */  lh         $s1, 0x24($v0)
/* 6C978 8007C178 2800528C */  lw         $s2, 0x28($v0)
/* 6C97C 8007C17C 2C00538C */  lw         $s3, 0x2C($v0)
/* 6C980 8007C180 26005484 */  lh         $s4, 0x26($v0)
/* 6C984 8007C184 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6C988 8007C188 0000B58E */  lw         $s5, 0x0($s5)
/* 6C98C 8007C18C 00000000 */  nop
/* 6C990 8007C190 03AC1500 */  sra        $s5, $s5, 16
/* 6C994 8007C194 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6C998 8007C198 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6C99C 8007C19C 0006173C */  lui        $s7, (0x6000000 >> 16)
/* 6C9A0 8007C1A0 44005E8C */  lw         $fp, 0x44($v0)
/* 6C9A4 8007C1A4 0000C884 */  lh         $t0, 0x0($a2)
/* 6C9A8 8007C1A8 0200C984 */  lh         $t1, 0x2($a2)
/* 6C9AC 8007C1AC 0400CA84 */  lh         $t2, 0x4($a2)
/* 6C9B0 8007C1B0 C0400800 */  sll        $t0, $t0, 3
/* 6C9B4 8007C1B4 C0480900 */  sll        $t1, $t1, 3
/* 6C9B8 8007C1B8 C0500A00 */  sll        $t2, $t2, 3
/* 6C9BC 8007C1BC 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C9C0 8007C1C0 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C9C4 8007C1C4 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007C1C8:
/* 6C9C8 8007C1C8 000000C9 */  lwc2       $0, 0x0($t0)
/* 6C9CC 8007C1CC 040001C9 */  lwc2       $1, 0x4($t0)
/* 6C9D0 8007C1D0 000022C9 */  lwc2       $2, 0x0($t1)
/* 6C9D4 8007C1D4 040023C9 */  lwc2       $3, 0x4($t1)
/* 6C9D8 8007C1D8 000044C9 */  lwc2       $4, 0x0($t2)
/* 6C9DC 8007C1DC 040045C9 */  lwc2       $5, 0x4($t2)
/* 6C9E0 8007C1E0 1000D820 */  addi       $t8, $a2, 0x10 # handwritten instruction
/* 6C9E4 8007C1E4 00000000 */  nop
/* 6C9E8 8007C1E8 3000284A */  RTPT
/* 6C9EC 8007C1EC 00000887 */  lh         $t0, 0x0($t8)
/* 6C9F0 8007C1F0 02000987 */  lh         $t1, 0x2($t8)
/* 6C9F4 8007C1F4 04000A87 */  lh         $t2, 0x4($t8)
/* 6C9F8 8007C1F8 C0400800 */  sll        $t0, $t0, 3
/* 6C9FC 8007C1FC C0480900 */  sll        $t1, $t1, 3
/* 6CA00 8007C200 C0500A00 */  sll        $t2, $t2, 3
/* 6CA04 8007C204 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CA08 8007C208 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CA0C 8007C20C 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6CA10 8007C210 0600404B */  NCLIP
/* 6CA14 8007C214 0C00C6C8 */  lwc2       $6, 0xC($a2)
/* 6CA18 8007C218 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6CA1C 8007C21C 00000000 */  nop
/* 6CA20 8007C220 2B00001B */  blez       $t8, .L8007C2D0
/* 6CA24 8007C224 00000000 */   nop
/* 6CA28 8007C228 2D00584B */  AVSZ3
/* 6CA2C 8007C22C 0600CC84 */  lh         $t4, 0x6($a2)
/* 6CA30 8007C230 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6CA34 8007C234 C0600C00 */  sll        $t4, $t4, 3
/* 6CA38 8007C238 07C03802 */  srav       $t8, $t8, $s1
/* 6CA3C 8007C23C 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6CA40 8007C240 2A081303 */  slt        $at, $t8, $s3
/* 6CA44 8007C244 22002014 */  bnez       $at, .L8007C2D0
/* 6CA48 8007C248 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6CA4C 8007C24C 2A081203 */  slt        $at, $t8, $s2
/* 6CA50 8007C250 1F002010 */  beqz       $at, .L8007C2D0
/* 6CA54 8007C254 0800CD84 */   lh        $t5, 0x8($a2)
/* 6CA58 8007C258 0A00CE84 */  lh         $t6, 0xA($a2)
/* 6CA5C 8007C25C 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6CA60 8007C260 1000EDE8 */  swc2       $13, 0x10($a3)
/* 6CA64 8007C264 1800EEE8 */  swc2       $14, 0x18($a3)
/* 6CA68 8007C268 C0680D00 */  sll        $t5, $t5, 3
/* 6CA6C 8007C26C C0700E00 */  sll        $t6, $t6, 3
/* 6CA70 8007C270 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6CA74 8007C274 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6CA78 8007C278 000080C9 */  lwc2       $0, 0x0($t4)
/* 6CA7C 8007C27C 040081C9 */  lwc2       $1, 0x4($t4)
/* 6CA80 8007C280 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6CA84 8007C284 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6CA88 8007C288 0000C4C9 */  lwc2       $4, 0x0($t6)
/* 6CA8C 8007C28C 0400C5C9 */  lwc2       $5, 0x4($t6)
/* 6CA90 8007C290 04000310 */  beq        $zero, $v1, .L8007C2A4
/* 6CA94 8007C294 00000000 */   nop
/* 6CA98 8007C298 1604F84A */  NCDT
/* 6CA9C 8007C29C 02000010 */  b          .L8007C2A8
/* 6CAA0 8007C2A0 00000000 */   nop
.L8007C2A4:
/* 6CAA4 8007C2A4 3F04184B */  NCCT
.L8007C2A8:
/* 6CAA8 8007C2A8 24C8F600 */  and        $t9, $a3, $s6
/* 6CAAC 8007C2AC 80C01800 */  sll        $t8, $t8, 2
/* 6CAB0 8007C2B0 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6CAB4 8007C2B4 0000018F */  lw         $at, 0x0($t8)
/* 6CAB8 8007C2B8 000019AF */  sw         $t9, 0x0($t8)
/* 6CABC 8007C2BC 25083700 */  or         $at, $at, $s7
/* 6CAC0 8007C2C0 000021AF */  sw         $at, 0x0($t9)
/* 6CAC4 8007C2C4 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6CAC8 8007C2C8 0C00F5E8 */  swc2       $21, 0xC($a3)
/* 6CACC 8007C2CC 1400F6E8 */  swc2       $22, 0x14($a3)
.L8007C2D0:
/* 6CAD0 8007C2D0 1000C620 */  addi       $a2, $a2, 0x10 # handwritten instruction
/* 6CAD4 8007C2D4 1C00E720 */  addi       $a3, $a3, 0x1C # handwritten instruction
/* 6CAD8 8007C2D8 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6CADC 8007C2DC BAFFA01E */  bgtz       $s5, .L8007C1C8
/* 6CAE0 8007C2E0 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6CAE4 8007C2E4 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6CAE8 8007C2E8 400046AC */  sw         $a2, 0x40($v0)
/* 6CAEC 8007C2EC 44005EAC */  sw         $fp, 0x44($v0)
/* 6CAF0 8007C2F0 1000B08F */  lw         $s0, 0x10($sp)
/* 6CAF4 8007C2F4 1400B18F */  lw         $s1, 0x14($sp)
/* 6CAF8 8007C2F8 1800B28F */  lw         $s2, 0x18($sp)
/* 6CAFC 8007C2FC 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6CB00 8007C300 2000B48F */  lw         $s4, 0x20($sp)
/* 6CB04 8007C304 2400B58F */  lw         $s5, 0x24($sp)
/* 6CB08 8007C308 2800B68F */  lw         $s6, 0x28($sp)
/* 6CB0C 8007C30C 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6CB10 8007C310 3000BE8F */  lw         $fp, 0x30($sp)
/* 6CB14 8007C314 0800E003 */  jr         $ra
/* 6CB18 8007C318 3400BD27 */   addiu     $sp, $sp, 0x34
