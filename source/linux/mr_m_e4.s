.include		"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_E4
/* 6D530 8007CD30 1000A28F */  lw         $v0, 0x10($sp)
/* 6D534 8007CD34 1400A38F */  lw         $v1, 0x14($sp)
/* 6D538 8007CD38 BCFFBD27 */  addiu      $sp, $sp, -0x44
/* 6D53C 8007CD3C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6D540 8007CD40 1400B1AF */  sw         $s1, 0x14($sp)
/* 6D544 8007CD44 1800B2AF */  sw         $s2, 0x18($sp)
/* 6D548 8007CD48 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6D54C 8007CD4C 2000B4AF */  sw         $s4, 0x20($sp)
/* 6D550 8007CD50 2400B5AF */  sw         $s5, 0x24($sp)
/* 6D554 8007CD54 2800B6AF */  sw         $s6, 0x28($sp)
/* 6D558 8007CD58 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6D55C 8007CD5C 3000BEAF */  sw         $fp, 0x30($sp)
/* 6D560 8007CD60 2000508C */  lw         $s0, 0x20($v0)
/* 6D564 8007CD64 24005184 */  lh         $s1, 0x24($v0)
/* 6D568 8007CD68 2800528C */  lw         $s2, 0x28($v0)
/* 6D56C 8007CD6C 2C00538C */  lw         $s3, 0x2C($v0)
/* 6D570 8007CD70 26005484 */  lh         $s4, 0x26($v0)
/* 6D574 8007CD74 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6D578 8007CD78 0000B58E */  lw         $s5, 0x0($s5)
/* 6D57C 8007CD7C 00000000 */  nop
/* 6D580 8007CD80 03AC1500 */  sra        $s5, $s5, 16
/* 6D584 8007CD84 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6D588 8007CD88 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6D58C 8007CD8C 0009173C */  lui        $s7, (0x9000000 >> 16)
/* 6D590 8007CD90 3400B6AF */  sw         $s6, 0x34($sp)
/* 6D594 8007CD94 3800B7AF */  sw         $s7, 0x38($sp)
/* 6D598 8007CD98 0B80193C */  lui        $t9, %hi(MREnv_strip)
/* 6D59C 8007CD9C 0000013C */  lui        $at, 0
/* 6D5A0 8007CDA0 21083900 */  addu       $at, $at, $t9
/* 6D5A4 8007CDA4 603A2D8C */  lw         $t5, %lo(MREnv_strip)($at)
/* 6D5A8 8007CDA8 00000000 */  nop
/* 6D5AC 8007CDAC 0400B691 */  lbu        $s6, 0x4($t5)
/* 6D5B0 8007CDB0 0500B791 */  lbu        $s7, 0x5($t5)
/* 6D5B4 8007CDB4 4000D626 */  addiu      $s6, $s6, 0x40
/* 6D5B8 8007CDB8 4000F726 */  addiu      $s7, $s7, 0x40
/* 6D5BC 8007CDBC 3C00B6AF */  sw         $s6, 0x3C($sp)
/* 6D5C0 8007CDC0 4000B7AF */  sw         $s7, 0x40($sp)
/* 6D5C4 8007CDC4 44005E8C */  lw         $fp, 0x44($v0)
/* 6D5C8 8007CDC8 0000C884 */  lh         $t0, 0x0($a2)
/* 6D5CC 8007CDCC 0200C984 */  lh         $t1, 0x2($a2)
/* 6D5D0 8007CDD0 0400CA84 */  lh         $t2, 0x4($a2)
/* 6D5D4 8007CDD4 0600CB84 */  lh         $t3, 0x6($a2)
/* 6D5D8 8007CDD8 C0400800 */  sll        $t0, $t0, 3
/* 6D5DC 8007CDDC C0480900 */  sll        $t1, $t1, 3
/* 6D5E0 8007CDE0 C0500A00 */  sll        $t2, $t2, 3
/* 6D5E4 8007CDE4 C0580B00 */  sll        $t3, $t3, 3
/* 6D5E8 8007CDE8 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D5EC 8007CDEC 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D5F0 8007CDF0 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6D5F4 8007CDF4 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007CDF8:
/* 6D5F8 8007CDF8 000000C9 */  lwc2       $0, 0x0($t0)
/* 6D5FC 8007CDFC 040001C9 */  lwc2       $1, 0x4($t0)
/* 6D600 8007CE00 000022C9 */  lwc2       $2, 0x0($t1)
/* 6D604 8007CE04 040023C9 */  lwc2       $3, 0x4($t1)
/* 6D608 8007CE08 000064C9 */  lwc2       $4, 0x0($t3)
/* 6D60C 8007CE0C 040065C9 */  lwc2       $5, 0x4($t3)
/* 6D610 8007CE10 1800D820 */  addi       $t8, $a2, 0x18 # handwritten instruction
/* 6D614 8007CE14 00000000 */  nop
/* 6D618 8007CE18 3000284A */  RTPT
/* 6D61C 8007CE1C 00000887 */  lh         $t0, 0x0($t8)
/* 6D620 8007CE20 02000987 */  lh         $t1, 0x2($t8)
/* 6D624 8007CE24 06000B87 */  lh         $t3, 0x6($t8)
/* 6D628 8007CE28 C0400800 */  sll        $t0, $t0, 3
/* 6D62C 8007CE2C C0480900 */  sll        $t1, $t1, 3
/* 6D630 8007CE30 C0580B00 */  sll        $t3, $t3, 3
/* 6D634 8007CE34 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D638 8007CE38 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D63C 8007CE3C 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6D640 8007CE40 0600404B */  NCLIP
/* 6D644 8007CE44 000040C9 */  lwc2       $0, 0x0($t2)
/* 6D648 8007CE48 040041C9 */  lwc2       $1, 0x4($t2)
/* 6D64C 8007CE4C 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6D650 8007CE50 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6D654 8007CE54 0100184A */  RTPS
/* 6D658 8007CE58 1400C6C8 */  lwc2       $6, 0x14($a2)
/* 6D65C 8007CE5C 04000A87 */  lh         $t2, 0x4($t8)
/* 6D660 8007CE60 00000000 */  nop
/* 6D664 8007CE64 C0500A00 */  sll        $t2, $t2, 3
/* 6D668 8007CE68 0600201F */  bgtz       $t9, .L8007CE84
/* 6D66C 8007CE6C 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6D670 8007CE70 0600404B */  NCLIP
/* 6D674 8007CE74 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6D678 8007CE78 00000000 */  nop
/* 6D67C 8007CE7C 8E002107 */  bgez       $t9, .L8007D0B8
/* 6D680 8007CE80 00000000 */   nop
.L8007CE84:
/* 6D684 8007CE84 2E00684B */  AVSZ4
/* 6D688 8007CE88 0800CC84 */  lh         $t4, 0x8($a2)
/* 6D68C 8007CE8C 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6D690 8007CE90 C0600C00 */  sll        $t4, $t4, 3
/* 6D694 8007CE94 07C03802 */  srav       $t8, $t8, $s1
/* 6D698 8007CE98 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6D69C 8007CE9C 2A081303 */  slt        $at, $t8, $s3
/* 6D6A0 8007CEA0 85002014 */  bnez       $at, .L8007D0B8
/* 6D6A4 8007CEA4 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6D6A8 8007CEA8 2A081203 */  slt        $at, $t8, $s2
/* 6D6AC 8007CEAC 82002010 */  beqz       $at, .L8007D0B8
/* 6D6B0 8007CEB0 00000000 */   nop
/* 6D6B4 8007CEB4 1000ECE8 */  swc2       $12, 0x10($a3)
/* 6D6B8 8007CEB8 1800EDE8 */  swc2       $13, 0x18($a3)
/* 6D6BC 8007CEBC 2000EEE8 */  swc2       $14, 0x20($a3)
/* 6D6C0 8007CEC0 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6D6C4 8007CEC4 0000013C */  lui        $at, (0x38 >> 16)
/* 6D6C8 8007CEC8 21083900 */  addu       $at, $at, $t9
/* 6D6CC 8007CECC 38002D8C */  lw         $t5, (0x38 & 0xFFFF)($at)
/* 6D6D0 8007CED0 00000000 */  nop
/* 6D6D4 8007CED4 0000AE8D */  lw         $t6, 0x0($t5)
/* 6D6D8 8007CED8 0400AF8D */  lw         $t7, 0x4($t5)
/* 6D6DC 8007CEDC 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6D6E0 8007CEE0 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6D6E4 8007CEE4 0800AE8D */  lw         $t6, 0x8($t5)
/* 6D6E8 8007CEE8 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6D6EC 8007CEEC 1000B98D */  lw         $t9, 0x10($t5)
/* 6D6F0 8007CEF0 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6D6F4 8007CEF4 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6D6F8 8007CEF8 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6D6FC 8007CEFC 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D700 8007CF00 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D704 8007CF04 3C00B68F */  lw         $s6, 0x3C($sp)
/* 6D708 8007CF08 4000B78F */  lw         $s7, 0x40($sp)
/* 6D70C 8007CF0C 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6D710 8007CF10 0A00CC84 */  lh         $t4, 0xA($a2)
/* 6D714 8007CF14 00000000 */  nop
/* 6D718 8007CF18 C0600C00 */  sll        $t4, $t4, 3
/* 6D71C 8007CF1C 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D720 8007CF20 000082C9 */  lwc2       $2, 0x0($t4)
/* 6D724 8007CF24 040083C9 */  lwc2       $3, 0x4($t4)
/* 6D728 8007CF28 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D72C 8007CF2C 00000000 */  nop
/* 6D730 8007CF30 83690D00 */  sra        $t5, $t5, 6
/* 6D734 8007CF34 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D738 8007CF38 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D73C 8007CF3C 00000000 */  nop
/* 6D740 8007CF40 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D744 8007CF44 83710E00 */  sra        $t6, $t6, 6
/* 6D748 8007CF48 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D74C 8007CF4C 00720E00 */  sll        $t6, $t6, 8
/* 6D750 8007CF50 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D754 8007CF54 0C00EDA4 */  sh         $t5, 0xC($a3)
/* 6D758 8007CF58 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6D75C 8007CF5C 0C00CC84 */  lh         $t4, 0xC($a2)
/* 6D760 8007CF60 00000000 */  nop
/* 6D764 8007CF64 C0600C00 */  sll        $t4, $t4, 3
/* 6D768 8007CF68 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D76C 8007CF6C 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D770 8007CF70 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D774 8007CF74 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D778 8007CF78 00000000 */  nop
/* 6D77C 8007CF7C 83690D00 */  sra        $t5, $t5, 6
/* 6D780 8007CF80 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D784 8007CF84 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D788 8007CF88 00000000 */  nop
/* 6D78C 8007CF8C 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D790 8007CF90 83710E00 */  sra        $t6, $t6, 6
/* 6D794 8007CF94 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D798 8007CF98 00720E00 */  sll        $t6, $t6, 8
/* 6D79C 8007CF9C 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D7A0 8007CFA0 1400EDA4 */  sh         $t5, 0x14($a3)
/* 6D7A4 8007CFA4 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6D7A8 8007CFA8 0E00CC84 */  lh         $t4, 0xE($a2)
/* 6D7AC 8007CFAC 00000000 */  nop
/* 6D7B0 8007CFB0 C0600C00 */  sll        $t4, $t4, 3
/* 6D7B4 8007CFB4 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D7B8 8007CFB8 000082C9 */  lwc2       $2, 0x0($t4)
/* 6D7BC 8007CFBC 040083C9 */  lwc2       $3, 0x4($t4)
/* 6D7C0 8007CFC0 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D7C4 8007CFC4 00000000 */  nop
/* 6D7C8 8007CFC8 83690D00 */  sra        $t5, $t5, 6
/* 6D7CC 8007CFCC 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D7D0 8007CFD0 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D7D4 8007CFD4 00000000 */  nop
/* 6D7D8 8007CFD8 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D7DC 8007CFDC 83710E00 */  sra        $t6, $t6, 6
/* 6D7E0 8007CFE0 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D7E4 8007CFE4 00720E00 */  sll        $t6, $t6, 8
/* 6D7E8 8007CFE8 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D7EC 8007CFEC 2400EDA4 */  sh         $t5, 0x24($a3)
/* 6D7F0 8007CFF0 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6D7F4 8007CFF4 1000CC84 */  lh         $t4, 0x10($a2)
/* 6D7F8 8007CFF8 00000000 */  nop
/* 6D7FC 8007CFFC C0600C00 */  sll        $t4, $t4, 3
/* 6D800 8007D000 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6D804 8007D004 000080C9 */  lwc2       $0, 0x0($t4)
/* 6D808 8007D008 040081C9 */  lwc2       $1, 0x4($t4)
/* 6D80C 8007D00C 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6D810 8007D010 00000000 */  nop
/* 6D814 8007D014 83690D00 */  sra        $t5, $t5, 6
/* 6D818 8007D018 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6D81C 8007D01C 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6D820 8007D020 00000000 */  nop
/* 6D824 8007D024 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6D828 8007D028 83710E00 */  sra        $t6, $t6, 6
/* 6D82C 8007D02C 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6D830 8007D030 00720E00 */  sll        $t6, $t6, 8
/* 6D834 8007D034 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6D838 8007D038 1C00EDA4 */  sh         $t5, 0x1C($a3)
/* 6D83C 8007D03C 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6D840 8007D040 0000013C */  lui        $at, (0x34 >> 16)
/* 6D844 8007D044 21083900 */  addu       $at, $at, $t9
/* 6D848 8007D048 34002D8C */  lw         $t5, (0x34 & 0xFFFF)($at)
/* 6D84C 8007D04C 00000000 */  nop
/* 6D850 8007D050 0000AE8D */  lw         $t6, 0x0($t5)
/* 6D854 8007D054 0400AF8D */  lw         $t7, 0x4($t5)
/* 6D858 8007D058 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6D85C 8007D05C 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6D860 8007D060 0800AE8D */  lw         $t6, 0x8($t5)
/* 6D864 8007D064 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6D868 8007D068 1000B98D */  lw         $t9, 0x10($t5)
/* 6D86C 8007D06C 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6D870 8007D070 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6D874 8007D074 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6D878 8007D078 04000310 */  beq        $zero, $v1, .L8007D08C
/* 6D87C 8007D07C 00000000 */   nop
/* 6D880 8007D080 1304E84A */  NCDS
/* 6D884 8007D084 02000010 */  b          .L8007D090
/* 6D888 8007D088 00000000 */   nop
.L8007D08C:
/* 6D88C 8007D08C 1B04084B */  NCCS
.L8007D090:
/* 6D890 8007D090 3400B68F */  lw         $s6, 0x34($sp)
/* 6D894 8007D094 3800B78F */  lw         $s7, 0x38($sp)
/* 6D898 8007D098 24C8F600 */  and        $t9, $a3, $s6
/* 6D89C 8007D09C 80C01800 */  sll        $t8, $t8, 2
/* 6D8A0 8007D0A0 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6D8A4 8007D0A4 0000018F */  lw         $at, 0x0($t8)
/* 6D8A8 8007D0A8 000019AF */  sw         $t9, 0x0($t8)
/* 6D8AC 8007D0AC 25083700 */  or         $at, $at, $s7
/* 6D8B0 8007D0B0 000021AF */  sw         $at, 0x0($t9)
/* 6D8B4 8007D0B4 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007D0B8:
/* 6D8B8 8007D0B8 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6D8BC 8007D0BC 1800C620 */  addi       $a2, $a2, 0x18 # handwritten instruction
/* 6D8C0 8007D0C0 2800E720 */  addi       $a3, $a3, 0x28 # handwritten instruction
/* 6D8C4 8007D0C4 4CFFA01E */  bgtz       $s5, .L8007CDF8
/* 6D8C8 8007D0C8 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6D8CC 8007D0CC 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6D8D0 8007D0D0 400046AC */  sw         $a2, 0x40($v0)
/* 6D8D4 8007D0D4 44005EAC */  sw         $fp, 0x44($v0)
/* 6D8D8 8007D0D8 1000B08F */  lw         $s0, 0x10($sp)
/* 6D8DC 8007D0DC 1400B18F */  lw         $s1, 0x14($sp)
/* 6D8E0 8007D0E0 1800B28F */  lw         $s2, 0x18($sp)
/* 6D8E4 8007D0E4 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6D8E8 8007D0E8 2000B48F */  lw         $s4, 0x20($sp)
/* 6D8EC 8007D0EC 2400B58F */  lw         $s5, 0x24($sp)
/* 6D8F0 8007D0F0 2800B68F */  lw         $s6, 0x28($sp)
/* 6D8F4 8007D0F4 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6D8F8 8007D0F8 3000BE8F */  lw         $fp, 0x30($sp)
/* 6D8FC 8007D0FC 0800E003 */  jr         $ra
/* 6D900 8007D100 4400BD27 */   addiu     $sp, $sp, 0x44
