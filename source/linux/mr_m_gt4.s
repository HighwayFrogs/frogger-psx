.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_GT4
/* 6CF6C 8007C76C 1000A28F */  lw         $v0, 0x10($sp)
/* 6CF70 8007C770 1400A38F */  lw         $v1, 0x14($sp)
/* 6CF74 8007C774 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6CF78 8007C778 1000B0AF */  sw         $s0, 0x10($sp)
/* 6CF7C 8007C77C 1400B1AF */  sw         $s1, 0x14($sp)
/* 6CF80 8007C780 1800B2AF */  sw         $s2, 0x18($sp)
/* 6CF84 8007C784 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6CF88 8007C788 2000B4AF */  sw         $s4, 0x20($sp)
/* 6CF8C 8007C78C 2400B5AF */  sw         $s5, 0x24($sp)
/* 6CF90 8007C790 2800B6AF */  sw         $s6, 0x28($sp)
/* 6CF94 8007C794 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6CF98 8007C798 3000BEAF */  sw         $fp, 0x30($sp)
/* 6CF9C 8007C79C 2000508C */  lw         $s0, 0x20($v0)
/* 6CFA0 8007C7A0 24005184 */  lh         $s1, 0x24($v0)
/* 6CFA4 8007C7A4 2800528C */  lw         $s2, 0x28($v0)
/* 6CFA8 8007C7A8 2C00538C */  lw         $s3, 0x2C($v0)
/* 6CFAC 8007C7AC 26005484 */  lh         $s4, 0x26($v0)
/* 6CFB0 8007C7B0 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6CFB4 8007C7B4 0000B58E */  lw         $s5, 0x0($s5)
/* 6CFB8 8007C7B8 00000000 */  nop
/* 6CFBC 8007C7BC 03AC1500 */  sra        $s5, $s5, 16
/* 6CFC0 8007C7C0 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6CFC4 8007C7C4 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6CFC8 8007C7C8 000C173C */  lui        $s7, (0xC000000 >> 16)
/* 6CFCC 8007C7CC 44005E8C */  lw         $fp, 0x44($v0)
/* 6CFD0 8007C7D0 0000C884 */  lh         $t0, 0x0($a2)
/* 6CFD4 8007C7D4 0200C984 */  lh         $t1, 0x2($a2)
/* 6CFD8 8007C7D8 0400CA84 */  lh         $t2, 0x4($a2)
/* 6CFDC 8007C7DC 0600CB84 */  lh         $t3, 0x6($a2)
/* 6CFE0 8007C7E0 C0400800 */  sll        $t0, $t0, 3
/* 6CFE4 8007C7E4 C0480900 */  sll        $t1, $t1, 3
/* 6CFE8 8007C7E8 C0500A00 */  sll        $t2, $t2, 3
/* 6CFEC 8007C7EC C0580B00 */  sll        $t3, $t3, 3
/* 6CFF0 8007C7F0 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CFF4 8007C7F4 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CFF8 8007C7F8 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6CFFC 8007C7FC 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007C800:
/* 6D000 8007C800 000000C9 */  lwc2       $0, 0x0($t0)
/* 6D004 8007C804 040001C9 */  lwc2       $1, 0x4($t0)
/* 6D008 8007C808 000022C9 */  lwc2       $2, 0x0($t1)
/* 6D00C 8007C80C 040023C9 */  lwc2       $3, 0x4($t1)
/* 6D010 8007C810 000064C9 */  lwc2       $4, 0x0($t3)
/* 6D014 8007C814 040065C9 */  lwc2       $5, 0x4($t3)
/* 6D018 8007C818 2400D820 */  addi       $t8, $a2, 0x24 # handwritten instruction
/* 6D01C 8007C81C 00000000 */  nop
/* 6D020 8007C820 3000284A */  RTPT
/* 6D024 8007C824 00000887 */  lh         $t0, 0x0($t8)
/* 6D028 8007C828 02000987 */  lh         $t1, 0x2($t8)
/* 6D02C 8007C82C 06000B87 */  lh         $t3, 0x6($t8)
/* 6D030 8007C830 C0400800 */  sll        $t0, $t0, 3
/* 6D034 8007C834 C0480900 */  sll        $t1, $t1, 3
/* 6D038 8007C838 C0580B00 */  sll        $t3, $t3, 3
/* 6D03C 8007C83C 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D040 8007C840 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D044 8007C844 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6D048 8007C848 0600404B */  NCLIP
/* 6D04C 8007C84C 000040C9 */  lwc2       $0, 0x0($t2)
/* 6D050 8007C850 040041C9 */  lwc2       $1, 0x4($t2)
/* 6D054 8007C854 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6D058 8007C858 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6D05C 8007C85C 0100184A */  RTPS
/* 6D060 8007C860 2000C6C8 */  lwc2       $6, 0x20($a2)
/* 6D064 8007C864 04000A87 */  lh         $t2, 0x4($t8)
/* 6D068 8007C868 00000000 */  nop
/* 6D06C 8007C86C C0500A00 */  sll        $t2, $t2, 3
/* 6D070 8007C870 0600201F */  bgtz       $t9, .L8007C88C
/* 6D074 8007C874 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6D078 8007C878 0600404B */  NCLIP
/* 6D07C 8007C87C 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6D080 8007C880 00000000 */  nop
/* 6D084 8007C884 43002107 */  bgez       $t9, .L8007C994
/* 6D088 8007C888 00000000 */   nop
.L8007C88C:
/* 6D08C 8007C88C 2E00684B */  AVSZ4
/* 6D090 8007C890 0800CC84 */  lh         $t4, 0x8($a2)
/* 6D094 8007C894 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6D098 8007C898 C0600C00 */  sll        $t4, $t4, 3
/* 6D09C 8007C89C 07C03802 */  srav       $t8, $t8, $s1
/* 6D0A0 8007C8A0 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6D0A4 8007C8A4 2A081303 */  slt        $at, $t8, $s3
/* 6D0A8 8007C8A8 3A002014 */  bnez       $at, .L8007C994
/* 6D0AC 8007C8AC 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6D0B0 8007C8B0 2A081203 */  slt        $at, $t8, $s2
/* 6D0B4 8007C8B4 37002010 */  beqz       $at, .L8007C994
/* 6D0B8 8007C8B8 0A00CD84 */   lh        $t5, 0xA($a2)
/* 6D0BC 8007C8BC 0E00CF84 */  lh         $t7, 0xE($a2)
/* 6D0C0 8007C8C0 1400ECE8 */  swc2       $12, 0x14($a3)
/* 6D0C4 8007C8C4 2000EDE8 */  swc2       $13, 0x20($a3)
/* 6D0C8 8007C8C8 2C00EEE8 */  swc2       $14, 0x2C($a3)
/* 6D0CC 8007C8CC C0680D00 */  sll        $t5, $t5, 3
/* 6D0D0 8007C8D0 C0780F00 */  sll        $t7, $t7, 3
/* 6D0D4 8007C8D4 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6D0D8 8007C8D8 2078E501 */  add        $t7, $t7, $a1 # handwritten instruction
/* 6D0DC 8007C8DC 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D0E0 8007C8E0 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D0E4 8007C8E4 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6D0E8 8007C8E8 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6D0EC 8007C8EC 0000E4C9 */  lwc2       $4, 0x0($t7)
/* 6D0F0 8007C8F0 0400E5C9 */  lwc2       $5, 0x4($t7)
/* 6D0F4 8007C8F4 14000310 */  beq        $zero, $v1, .L8007C948
/* 6D0F8 8007C8F8 00000000 */   nop
/* 6D0FC 8007C8FC 1604F84A */  NCDT
/* 6D100 8007C900 0C00CE84 */  lh         $t6, 0xC($a2)
/* 6D104 8007C904 24C8F600 */  and        $t9, $a3, $s6
/* 6D108 8007C908 80C01800 */  sll        $t8, $t8, 2
/* 6D10C 8007C90C 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6D110 8007C910 0000018F */  lw         $at, 0x0($t8)
/* 6D114 8007C914 000019AF */  sw         $t9, 0x0($t8)
/* 6D118 8007C918 25083700 */  or         $at, $at, $s7
/* 6D11C 8007C91C 000021AF */  sw         $at, 0x0($t9)
/* 6D120 8007C920 C0700E00 */  sll        $t6, $t6, 3
/* 6D124 8007C924 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6D128 8007C928 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6D12C 8007C92C 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6D130 8007C930 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6D134 8007C934 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6D138 8007C938 1C00F6E8 */  swc2       $22, 0x1C($a3)
/* 6D13C 8007C93C 1304E84A */  NCDS
/* 6D140 8007C940 13000010 */  b          .L8007C990
/* 6D144 8007C944 00000000 */   nop
.L8007C948:
/* 6D148 8007C948 3F04184B */  NCCT
/* 6D14C 8007C94C 0C00CE84 */  lh         $t6, 0xC($a2)
/* 6D150 8007C950 24C8F600 */  and        $t9, $a3, $s6
/* 6D154 8007C954 80C01800 */  sll        $t8, $t8, 2
/* 6D158 8007C958 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6D15C 8007C95C 0000018F */  lw         $at, 0x0($t8)
/* 6D160 8007C960 000019AF */  sw         $t9, 0x0($t8)
/* 6D164 8007C964 25083700 */  or         $at, $at, $s7
/* 6D168 8007C968 000021AF */  sw         $at, 0x0($t9)
/* 6D16C 8007C96C C0700E00 */  sll        $t6, $t6, 3
/* 6D170 8007C970 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6D174 8007C974 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6D178 8007C978 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6D17C 8007C97C 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6D180 8007C980 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6D184 8007C984 1C00F6E8 */  swc2       $22, 0x1C($a3)
/* 6D188 8007C988 1B04084B */  NCCS
/* 6D18C 8007C98C 00000000 */  nop
.L8007C990:
/* 6D190 8007C990 2800F6E8 */  swc2       $22, 0x28($a3)
.L8007C994:
/* 6D194 8007C994 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6D198 8007C998 2400C620 */  addi       $a2, $a2, 0x24 # handwritten instruction
/* 6D19C 8007C99C 3400E720 */  addi       $a3, $a3, 0x34 # handwritten instruction
/* 6D1A0 8007C9A0 97FFA01E */  bgtz       $s5, .L8007C800
/* 6D1A4 8007C9A4 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6D1A8 8007C9A8 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6D1AC 8007C9AC 400046AC */  sw         $a2, 0x40($v0)
/* 6D1B0 8007C9B0 44005EAC */  sw         $fp, 0x44($v0)
/* 6D1B4 8007C9B4 1000B08F */  lw         $s0, 0x10($sp)
/* 6D1B8 8007C9B8 1400B18F */  lw         $s1, 0x14($sp)
/* 6D1BC 8007C9BC 1800B28F */  lw         $s2, 0x18($sp)
/* 6D1C0 8007C9C0 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6D1C4 8007C9C4 2000B48F */  lw         $s4, 0x20($sp)
/* 6D1C8 8007C9C8 2400B58F */  lw         $s5, 0x24($sp)
/* 6D1CC 8007C9CC 2800B68F */  lw         $s6, 0x28($sp)
/* 6D1D0 8007C9D0 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6D1D4 8007C9D4 3000BE8F */  lw         $fp, 0x30($sp)
/* 6D1D8 8007C9D8 0800E003 */  jr         $ra
/* 6D1DC 8007C9DC 3400BD27 */   addiu     $sp, $sp, 0x34
