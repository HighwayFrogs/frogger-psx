.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_FT4
/* 6C758 8007BF58 1000A28F */  lw         $v0, 0x10($sp)
/* 6C75C 8007BF5C 1400A38F */  lw         $v1, 0x14($sp)
/* 6C760 8007BF60 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6C764 8007BF64 1000B0AF */  sw         $s0, 0x10($sp)
/* 6C768 8007BF68 1400B1AF */  sw         $s1, 0x14($sp)
/* 6C76C 8007BF6C 1800B2AF */  sw         $s2, 0x18($sp)
/* 6C770 8007BF70 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6C774 8007BF74 2000B4AF */  sw         $s4, 0x20($sp)
/* 6C778 8007BF78 2400B5AF */  sw         $s5, 0x24($sp)
/* 6C77C 8007BF7C 2800B6AF */  sw         $s6, 0x28($sp)
/* 6C780 8007BF80 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6C784 8007BF84 3000BEAF */  sw         $fp, 0x30($sp)
/* 6C788 8007BF88 2000508C */  lw         $s0, 0x20($v0)
/* 6C78C 8007BF8C 24005184 */  lh         $s1, 0x24($v0)
/* 6C790 8007BF90 2800528C */  lw         $s2, 0x28($v0)
/* 6C794 8007BF94 2C00538C */  lw         $s3, 0x2C($v0)
/* 6C798 8007BF98 26005484 */  lh         $s4, 0x26($v0)
/* 6C79C 8007BF9C FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6C7A0 8007BFA0 0000B58E */  lw         $s5, 0x0($s5)
/* 6C7A4 8007BFA4 00000000 */  nop
/* 6C7A8 8007BFA8 03AC1500 */  sra        $s5, $s5, 16
/* 6C7AC 8007BFAC FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6C7B0 8007BFB0 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6C7B4 8007BFB4 0009173C */  lui        $s7, (0x9000000 >> 16)
/* 6C7B8 8007BFB8 44005E8C */  lw         $fp, 0x44($v0)
/* 6C7BC 8007BFBC 0000C884 */  lh         $t0, 0x0($a2)
/* 6C7C0 8007BFC0 0200C984 */  lh         $t1, 0x2($a2)
/* 6C7C4 8007BFC4 0400CA84 */  lh         $t2, 0x4($a2)
/* 6C7C8 8007BFC8 0600CB84 */  lh         $t3, 0x6($a2)
/* 6C7CC 8007BFCC C0400800 */  sll        $t0, $t0, 3
/* 6C7D0 8007BFD0 C0480900 */  sll        $t1, $t1, 3
/* 6C7D4 8007BFD4 C0500A00 */  sll        $t2, $t2, 3
/* 6C7D8 8007BFD8 C0580B00 */  sll        $t3, $t3, 3
/* 6C7DC 8007BFDC 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C7E0 8007BFE0 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C7E4 8007BFE4 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6C7E8 8007BFE8 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007BFEC:
/* 6C7EC 8007BFEC 000000C9 */  lwc2       $0, 0x0($t0)
/* 6C7F0 8007BFF0 040001C9 */  lwc2       $1, 0x4($t0)
/* 6C7F4 8007BFF4 000022C9 */  lwc2       $2, 0x0($t1)
/* 6C7F8 8007BFF8 040023C9 */  lwc2       $3, 0x4($t1)
/* 6C7FC 8007BFFC 000064C9 */  lwc2       $4, 0x0($t3)
/* 6C800 8007C000 040065C9 */  lwc2       $5, 0x4($t3)
/* 6C804 8007C004 1C00D820 */  addi       $t8, $a2, 0x1C # handwritten instruction
/* 6C808 8007C008 00000000 */  nop
/* 6C80C 8007C00C 3000284A */  RTPT
/* 6C810 8007C010 00000887 */  lh         $t0, 0x0($t8)
/* 6C814 8007C014 02000987 */  lh         $t1, 0x2($t8)
/* 6C818 8007C018 06000B87 */  lh         $t3, 0x6($t8)
/* 6C81C 8007C01C C0400800 */  sll        $t0, $t0, 3
/* 6C820 8007C020 C0480900 */  sll        $t1, $t1, 3
/* 6C824 8007C024 C0580B00 */  sll        $t3, $t3, 3
/* 6C828 8007C028 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C82C 8007C02C 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C830 8007C030 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6C834 8007C034 0600404B */  NCLIP
/* 6C838 8007C038 000040C9 */  lwc2       $0, 0x0($t2)
/* 6C83C 8007C03C 040041C9 */  lwc2       $1, 0x4($t2)
/* 6C840 8007C040 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6C844 8007C044 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6C848 8007C048 0100184A */  RTPS
/* 6C84C 8007C04C 1800C6C8 */  lwc2       $6, 0x18($a2)
/* 6C850 8007C050 04000A87 */  lh         $t2, 0x4($t8)
/* 6C854 8007C054 00000000 */  nop
/* 6C858 8007C058 C0500A00 */  sll        $t2, $t2, 3
/* 6C85C 8007C05C 0600201F */  bgtz       $t9, .L8007C078
/* 6C860 8007C060 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6C864 8007C064 0600404B */  NCLIP
/* 6C868 8007C068 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6C86C 8007C06C 00000000 */  nop
/* 6C870 8007C070 20002107 */  bgez       $t9, .L8007C0F4
/* 6C874 8007C074 00000000 */   nop
.L8007C078:
/* 6C878 8007C078 2E00684B */  AVSZ4
/* 6C87C 8007C07C 0800CC84 */  lh         $t4, 0x8($a2)
/* 6C880 8007C080 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6C884 8007C084 C0600C00 */  sll        $t4, $t4, 3
/* 6C888 8007C088 07C03802 */  srav       $t8, $t8, $s1
/* 6C88C 8007C08C 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6C890 8007C090 2A081303 */  slt        $at, $t8, $s3
/* 6C894 8007C094 17002014 */  bnez       $at, .L8007C0F4
/* 6C898 8007C098 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6C89C 8007C09C 2A081203 */  slt        $at, $t8, $s2
/* 6C8A0 8007C0A0 14002010 */  beqz       $at, .L8007C0F4
/* 6C8A4 8007C0A4 00000000 */   nop
/* 6C8A8 8007C0A8 1000ECE8 */  swc2       $12, 0x10($a3)
/* 6C8AC 8007C0AC 1800EDE8 */  swc2       $13, 0x18($a3)
/* 6C8B0 8007C0B0 2000EEE8 */  swc2       $14, 0x20($a3)
/* 6C8B4 8007C0B4 000080C9 */  lwc2       $0, 0x0($t4)
/* 6C8B8 8007C0B8 040081C9 */  lwc2       $1, 0x4($t4)
/* 6C8BC 8007C0BC 04000310 */  beq        $zero, $v1, .L8007C0D0
/* 6C8C0 8007C0C0 00000000 */   nop
/* 6C8C4 8007C0C4 1304E84A */  NCDS
/* 6C8C8 8007C0C8 02000010 */  b          .L8007C0D4
/* 6C8CC 8007C0CC 00000000 */   nop
.L8007C0D0:
/* 6C8D0 8007C0D0 1B04084B */  NCCS
.L8007C0D4:
/* 6C8D4 8007C0D4 24C8F600 */  and        $t9, $a3, $s6
/* 6C8D8 8007C0D8 80C01800 */  sll        $t8, $t8, 2
/* 6C8DC 8007C0DC 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6C8E0 8007C0E0 0000018F */  lw         $at, 0x0($t8)
/* 6C8E4 8007C0E4 000019AF */  sw         $t9, 0x0($t8)
/* 6C8E8 8007C0E8 25083700 */  or         $at, $at, $s7
/* 6C8EC 8007C0EC 000021AF */  sw         $at, 0x0($t9)
/* 6C8F0 8007C0F0 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007C0F4:
/* 6C8F4 8007C0F4 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6C8F8 8007C0F8 1C00C620 */  addi       $a2, $a2, 0x1C # handwritten instruction
/* 6C8FC 8007C0FC 2800E720 */  addi       $a3, $a3, 0x28 # handwritten instruction
/* 6C900 8007C100 BAFFA01E */  bgtz       $s5, .L8007BFEC
/* 6C904 8007C104 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6C908 8007C108 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6C90C 8007C10C 400046AC */  sw         $a2, 0x40($v0)
/* 6C910 8007C110 44005EAC */  sw         $fp, 0x44($v0)
/* 6C914 8007C114 1000B08F */  lw         $s0, 0x10($sp)
/* 6C918 8007C118 1400B18F */  lw         $s1, 0x14($sp)
/* 6C91C 8007C11C 1800B28F */  lw         $s2, 0x18($sp)
/* 6C920 8007C120 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6C924 8007C124 2000B48F */  lw         $s4, 0x20($sp)
/* 6C928 8007C128 2400B58F */  lw         $s5, 0x24($sp)
/* 6C92C 8007C12C 2800B68F */  lw         $s6, 0x28($sp)
/* 6C930 8007C130 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6C934 8007C134 3000BE8F */  lw         $fp, 0x30($sp)
/* 6C938 8007C138 0800E003 */  jr         $ra
/* 6C93C 8007C13C 3400BD27 */   addiu     $sp, $sp, 0x34
