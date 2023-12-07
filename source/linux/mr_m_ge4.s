.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_GE4
/* 6DC84 8007D484 1000A28F */  lw         $v0, 0x10($sp)
/* 6DC88 8007D488 1400A38F */  lw         $v1, 0x14($sp)
/* 6DC8C 8007D48C BCFFBD27 */  addiu      $sp, $sp, -0x44
/* 6DC90 8007D490 1000B0AF */  sw         $s0, 0x10($sp)
/* 6DC94 8007D494 1400B1AF */  sw         $s1, 0x14($sp)
/* 6DC98 8007D498 1800B2AF */  sw         $s2, 0x18($sp)
/* 6DC9C 8007D49C 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6DCA0 8007D4A0 2000B4AF */  sw         $s4, 0x20($sp)
/* 6DCA4 8007D4A4 2400B5AF */  sw         $s5, 0x24($sp)
/* 6DCA8 8007D4A8 2800B6AF */  sw         $s6, 0x28($sp)
/* 6DCAC 8007D4AC 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6DCB0 8007D4B0 3000BEAF */  sw         $fp, 0x30($sp)
/* 6DCB4 8007D4B4 2000508C */  lw         $s0, 0x20($v0)
/* 6DCB8 8007D4B8 24005184 */  lh         $s1, 0x24($v0)
/* 6DCBC 8007D4BC 2800528C */  lw         $s2, 0x28($v0)
/* 6DCC0 8007D4C0 2C00538C */  lw         $s3, 0x2C($v0)
/* 6DCC4 8007D4C4 26005484 */  lh         $s4, 0x26($v0)
/* 6DCC8 8007D4C8 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6DCCC 8007D4CC 0000B58E */  lw         $s5, 0x0($s5)
/* 6DCD0 8007D4D0 00000000 */  nop
/* 6DCD4 8007D4D4 03AC1500 */  sra        $s5, $s5, 16
/* 6DCD8 8007D4D8 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6DCDC 8007D4DC FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6DCE0 8007D4E0 000C173C */  lui        $s7, (0xC000000 >> 16)
/* 6DCE4 8007D4E4 3400B6AF */  sw         $s6, 0x34($sp)
/* 6DCE8 8007D4E8 3800B7AF */  sw         $s7, 0x38($sp)
/* 6DCEC 8007D4EC 0B80193C */  lui        $t9, %hi(MREnv_strip)
/* 6DCF0 8007D4F0 0000013C */  lui        $at, 0
/* 6DCF4 8007D4F4 21083900 */  addu       $at, $at, $t9
/* 6DCF8 8007D4F8 603A2D8C */  lw         $t5, %lo(MREnv_strip)($at)
/* 6DCFC 8007D4FC 00000000 */  nop
/* 6DD00 8007D500 0400B691 */  lbu        $s6, 0x4($t5)
/* 6DD04 8007D504 0500B791 */  lbu        $s7, 0x5($t5)
/* 6DD08 8007D508 4000D626 */  addiu      $s6, $s6, 0x40
/* 6DD0C 8007D50C 4000F726 */  addiu      $s7, $s7, 0x40
/* 6DD10 8007D510 3C00B6AF */  sw         $s6, 0x3C($sp)
/* 6DD14 8007D514 4000B7AF */  sw         $s7, 0x40($sp)
/* 6DD18 8007D518 44005E8C */  lw         $fp, 0x44($v0)
/* 6DD1C 8007D51C 0000C884 */  lh         $t0, 0x0($a2)
/* 6DD20 8007D520 0200C984 */  lh         $t1, 0x2($a2)
/* 6DD24 8007D524 0400CA84 */  lh         $t2, 0x4($a2)
/* 6DD28 8007D528 0600CB84 */  lh         $t3, 0x6($a2)
/* 6DD2C 8007D52C C0400800 */  sll        $t0, $t0, 3
/* 6DD30 8007D530 C0480900 */  sll        $t1, $t1, 3
/* 6DD34 8007D534 C0500A00 */  sll        $t2, $t2, 3
/* 6DD38 8007D538 C0580B00 */  sll        $t3, $t3, 3
/* 6DD3C 8007D53C 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6DD40 8007D540 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6DD44 8007D544 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6DD48 8007D548 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
.L8007D54C:
/* 6DD4C 8007D54C 000000C9 */  lwc2       $0, 0x0($t0)
/* 6DD50 8007D550 040001C9 */  lwc2       $1, 0x4($t0)
/* 6DD54 8007D554 000022C9 */  lwc2       $2, 0x0($t1)
/* 6DD58 8007D558 040023C9 */  lwc2       $3, 0x4($t1)
/* 6DD5C 8007D55C 000064C9 */  lwc2       $4, 0x0($t3)
/* 6DD60 8007D560 040065C9 */  lwc2       $5, 0x4($t3)
/* 6DD64 8007D564 1C00D820 */  addi       $t8, $a2, 0x1C # handwritten instruction
/* 6DD68 8007D568 00000000 */  nop
/* 6DD6C 8007D56C 3000284A */  RTPT
/* 6DD70 8007D570 00000887 */  lh         $t0, 0x0($t8)
/* 6DD74 8007D574 02000987 */  lh         $t1, 0x2($t8)
/* 6DD78 8007D578 06000B87 */  lh         $t3, 0x6($t8)
/* 6DD7C 8007D57C C0400800 */  sll        $t0, $t0, 3
/* 6DD80 8007D580 C0480900 */  sll        $t1, $t1, 3
/* 6DD84 8007D584 C0580B00 */  sll        $t3, $t3, 3
/* 6DD88 8007D588 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6DD8C 8007D58C 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6DD90 8007D590 20586401 */  add        $t3, $t3, $a0 # handwritten instruction
/* 6DD94 8007D594 0600404B */  NCLIP
/* 6DD98 8007D598 000040C9 */  lwc2       $0, 0x0($t2)
/* 6DD9C 8007D59C 040041C9 */  lwc2       $1, 0x4($t2)
/* 6DDA0 8007D5A0 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6DDA4 8007D5A4 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6DDA8 8007D5A8 0100184A */  RTPS
/* 6DDAC 8007D5AC 1800C6C8 */  lwc2       $6, 0x18($a2)
/* 6DDB0 8007D5B0 04000A87 */  lh         $t2, 0x4($t8)
/* 6DDB4 8007D5B4 00000000 */  nop
/* 6DDB8 8007D5B8 C0500A00 */  sll        $t2, $t2, 3
/* 6DDBC 8007D5BC 0600201F */  bgtz       $t9, .L8007D5D8
/* 6DDC0 8007D5C0 20504401 */   add       $t2, $t2, $a0 # handwritten instruction
/* 6DDC4 8007D5C4 0600404B */  NCLIP
/* 6DDC8 8007D5C8 00C01948 */  mfc2       $t9, $24 # handwritten instruction
/* 6DDCC 8007D5CC 00000000 */  nop
/* 6DDD0 8007D5D0 B2002107 */  bgez       $t9, .L8007D89C
/* 6DDD4 8007D5D4 00000000 */   nop
.L8007D5D8:
/* 6DDD8 8007D5D8 2E00684B */  AVSZ4
/* 6DDDC 8007D5DC 0800CC84 */  lh         $t4, 0x8($a2)
/* 6DDE0 8007D5E0 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6DDE4 8007D5E4 C0600C00 */  sll        $t4, $t4, 3
/* 6DDE8 8007D5E8 07C03802 */  srav       $t8, $t8, $s1
/* 6DDEC 8007D5EC 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6DDF0 8007D5F0 2A081303 */  slt        $at, $t8, $s3
/* 6DDF4 8007D5F4 A9002014 */  bnez       $at, .L8007D89C
/* 6DDF8 8007D5F8 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6DDFC 8007D5FC 2A081203 */  slt        $at, $t8, $s2
/* 6DE00 8007D600 A6002010 */  beqz       $at, .L8007D89C
/* 6DE04 8007D604 00000000 */   nop
/* 6DE08 8007D608 1400ECE8 */  swc2       $12, 0x14($a3)
/* 6DE0C 8007D60C 2000EDE8 */  swc2       $13, 0x20($a3)
/* 6DE10 8007D610 2C00EEE8 */  swc2       $14, 0x2C($a3)
/* 6DE14 8007D614 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6DE18 8007D618 0000013C */  lui        $at, (0x38 >> 16)
/* 6DE1C 8007D61C 21083900 */  addu       $at, $at, $t9
/* 6DE20 8007D620 38002D8C */  lw         $t5, (0x38 & 0xFFFF)($at)
/* 6DE24 8007D624 00000000 */  nop
/* 6DE28 8007D628 0000AE8D */  lw         $t6, 0x0($t5)
/* 6DE2C 8007D62C 0400AF8D */  lw         $t7, 0x4($t5)
/* 6DE30 8007D630 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6DE34 8007D634 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6DE38 8007D638 0800AE8D */  lw         $t6, 0x8($t5)
/* 6DE3C 8007D63C 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6DE40 8007D640 1000B98D */  lw         $t9, 0x10($t5)
/* 6DE44 8007D644 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6DE48 8007D648 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6DE4C 8007D64C 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6DE50 8007D650 000080C9 */  lwc2       $0, 0x0($t4)
/* 6DE54 8007D654 040081C9 */  lwc2       $1, 0x4($t4)
/* 6DE58 8007D658 3C00B68F */  lw         $s6, 0x3C($sp)
/* 6DE5C 8007D65C 4000B78F */  lw         $s7, 0x40($sp)
/* 6DE60 8007D660 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6DE64 8007D664 0A00CC84 */  lh         $t4, 0xA($a2)
/* 6DE68 8007D668 00000000 */  nop
/* 6DE6C 8007D66C C0600C00 */  sll        $t4, $t4, 3
/* 6DE70 8007D670 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DE74 8007D674 000082C9 */  lwc2       $2, 0x0($t4)
/* 6DE78 8007D678 040083C9 */  lwc2       $3, 0x4($t4)
/* 6DE7C 8007D67C 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DE80 8007D680 00000000 */  nop
/* 6DE84 8007D684 83690D00 */  sra        $t5, $t5, 6
/* 6DE88 8007D688 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DE8C 8007D68C 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DE90 8007D690 00000000 */  nop
/* 6DE94 8007D694 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DE98 8007D698 83710E00 */  sra        $t6, $t6, 6
/* 6DE9C 8007D69C 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DEA0 8007D6A0 00720E00 */  sll        $t6, $t6, 8
/* 6DEA4 8007D6A4 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DEA8 8007D6A8 0C00EDA4 */  sh         $t5, 0xC($a3)
/* 6DEAC 8007D6AC 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6DEB0 8007D6B0 0C00CC84 */  lh         $t4, 0xC($a2)
/* 6DEB4 8007D6B4 00000000 */  nop
/* 6DEB8 8007D6B8 C0600C00 */  sll        $t4, $t4, 3
/* 6DEBC 8007D6BC 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DEC0 8007D6C0 000080C9 */  lwc2       $0, 0x0($t4)
/* 6DEC4 8007D6C4 040081C9 */  lwc2       $1, 0x4($t4)
/* 6DEC8 8007D6C8 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DECC 8007D6CC 00000000 */  nop
/* 6DED0 8007D6D0 83690D00 */  sra        $t5, $t5, 6
/* 6DED4 8007D6D4 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DED8 8007D6D8 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DEDC 8007D6DC 00000000 */  nop
/* 6DEE0 8007D6E0 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DEE4 8007D6E4 83710E00 */  sra        $t6, $t6, 6
/* 6DEE8 8007D6E8 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DEEC 8007D6EC 00720E00 */  sll        $t6, $t6, 8
/* 6DEF0 8007D6F0 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DEF4 8007D6F4 1800EDA4 */  sh         $t5, 0x18($a3)
/* 6DEF8 8007D6F8 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6DEFC 8007D6FC 0E00CC84 */  lh         $t4, 0xE($a2)
/* 6DF00 8007D700 00000000 */  nop
/* 6DF04 8007D704 C0600C00 */  sll        $t4, $t4, 3
/* 6DF08 8007D708 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DF0C 8007D70C 000082C9 */  lwc2       $2, 0x0($t4)
/* 6DF10 8007D710 040083C9 */  lwc2       $3, 0x4($t4)
/* 6DF14 8007D714 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DF18 8007D718 00000000 */  nop
/* 6DF1C 8007D71C 83690D00 */  sra        $t5, $t5, 6
/* 6DF20 8007D720 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DF24 8007D724 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DF28 8007D728 00000000 */  nop
/* 6DF2C 8007D72C 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DF30 8007D730 83710E00 */  sra        $t6, $t6, 6
/* 6DF34 8007D734 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DF38 8007D738 00720E00 */  sll        $t6, $t6, 8
/* 6DF3C 8007D73C 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DF40 8007D740 3000EDA4 */  sh         $t5, 0x30($a3)
/* 6DF44 8007D744 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6DF48 8007D748 1000CC84 */  lh         $t4, 0x10($a2)
/* 6DF4C 8007D74C 00000000 */  nop
/* 6DF50 8007D750 C0600C00 */  sll        $t4, $t4, 3
/* 6DF54 8007D754 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DF58 8007D758 000080C9 */  lwc2       $0, 0x0($t4)
/* 6DF5C 8007D75C 040081C9 */  lwc2       $1, 0x4($t4)
/* 6DF60 8007D760 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DF64 8007D764 00000000 */  nop
/* 6DF68 8007D768 83690D00 */  sra        $t5, $t5, 6
/* 6DF6C 8007D76C 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DF70 8007D770 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DF74 8007D774 00000000 */  nop
/* 6DF78 8007D778 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DF7C 8007D77C 83710E00 */  sra        $t6, $t6, 6
/* 6DF80 8007D780 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DF84 8007D784 00720E00 */  sll        $t6, $t6, 8
/* 6DF88 8007D788 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DF8C 8007D78C 2400EDA4 */  sh         $t5, 0x24($a3)
/* 6DF90 8007D790 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6DF94 8007D794 0000013C */  lui        $at, (0x34 >> 16)
/* 6DF98 8007D798 21083900 */  addu       $at, $at, $t9
/* 6DF9C 8007D79C 34002D8C */  lw         $t5, (0x34 & 0xFFFF)($at)
/* 6DFA0 8007D7A0 00000000 */  nop
/* 6DFA4 8007D7A4 0000AE8D */  lw         $t6, 0x0($t5)
/* 6DFA8 8007D7A8 0400AF8D */  lw         $t7, 0x4($t5)
/* 6DFAC 8007D7AC 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6DFB0 8007D7B0 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6DFB4 8007D7B4 0800AE8D */  lw         $t6, 0x8($t5)
/* 6DFB8 8007D7B8 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6DFBC 8007D7BC 1000B98D */  lw         $t9, 0x10($t5)
/* 6DFC0 8007D7C0 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6DFC4 8007D7C4 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6DFC8 8007D7C8 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6DFCC 8007D7CC 0A00CD84 */  lh         $t5, 0xA($a2)
/* 6DFD0 8007D7D0 0E00CF84 */  lh         $t7, 0xE($a2)
/* 6DFD4 8007D7D4 C0680D00 */  sll        $t5, $t5, 3
/* 6DFD8 8007D7D8 C0780F00 */  sll        $t7, $t7, 3
/* 6DFDC 8007D7DC 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6DFE0 8007D7E0 2078E501 */  add        $t7, $t7, $a1 # handwritten instruction
/* 6DFE4 8007D7E4 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6DFE8 8007D7E8 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6DFEC 8007D7EC 0000E4C9 */  lwc2       $4, 0x0($t7)
/* 6DFF0 8007D7F0 0400E5C9 */  lwc2       $5, 0x4($t7)
/* 6DFF4 8007D7F4 3400B68F */  lw         $s6, 0x34($sp)
/* 6DFF8 8007D7F8 3800B78F */  lw         $s7, 0x38($sp)
/* 6DFFC 8007D7FC 14000310 */  beq        $zero, $v1, .L8007D850
/* 6E000 8007D800 00000000 */   nop
/* 6E004 8007D804 1604F84A */  NCDT
/* 6E008 8007D808 1400CE84 */  lh         $t6, 0x14($a2)
/* 6E00C 8007D80C 24C8F600 */  and        $t9, $a3, $s6
/* 6E010 8007D810 80C01800 */  sll        $t8, $t8, 2
/* 6E014 8007D814 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6E018 8007D818 0000018F */  lw         $at, 0x0($t8)
/* 6E01C 8007D81C 000019AF */  sw         $t9, 0x0($t8)
/* 6E020 8007D820 25083700 */  or         $at, $at, $s7
/* 6E024 8007D824 000021AF */  sw         $at, 0x0($t9)
/* 6E028 8007D828 C0700E00 */  sll        $t6, $t6, 3
/* 6E02C 8007D82C 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6E030 8007D830 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6E034 8007D834 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6E038 8007D838 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6E03C 8007D83C 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6E040 8007D840 1C00F6E8 */  swc2       $22, 0x1C($a3)
/* 6E044 8007D844 1304E84A */  NCDS
/* 6E048 8007D848 13000010 */  b          .L8007D898
/* 6E04C 8007D84C 00000000 */   nop
.L8007D850:
/* 6E050 8007D850 3F04184B */  NCCT
/* 6E054 8007D854 1400CE84 */  lh         $t6, 0x14($a2)
/* 6E058 8007D858 24C8F600 */  and        $t9, $a3, $s6
/* 6E05C 8007D85C 80C01800 */  sll        $t8, $t8, 2
/* 6E060 8007D860 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6E064 8007D864 0000018F */  lw         $at, 0x0($t8)
/* 6E068 8007D868 000019AF */  sw         $t9, 0x0($t8)
/* 6E06C 8007D86C 25083700 */  or         $at, $at, $s7
/* 6E070 8007D870 000021AF */  sw         $at, 0x0($t9)
/* 6E074 8007D874 C0700E00 */  sll        $t6, $t6, 3
/* 6E078 8007D878 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6E07C 8007D87C 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6E080 8007D880 0000C0C9 */  lwc2       $0, 0x0($t6)
/* 6E084 8007D884 0400C1C9 */  lwc2       $1, 0x4($t6)
/* 6E088 8007D888 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6E08C 8007D88C 1C00F6E8 */  swc2       $22, 0x1C($a3)
/* 6E090 8007D890 1B04084B */  NCCS
/* 6E094 8007D894 00000000 */  nop
.L8007D898:
/* 6E098 8007D898 2800F6E8 */  swc2       $22, 0x28($a3)
.L8007D89C:
/* 6E09C 8007D89C FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6E0A0 8007D8A0 1C00C620 */  addi       $a2, $a2, 0x1C # handwritten instruction
/* 6E0A4 8007D8A4 3400E720 */  addi       $a3, $a3, 0x34 # handwritten instruction
/* 6E0A8 8007D8A8 28FFA01E */  bgtz       $s5, .L8007D54C
/* 6E0AC 8007D8AC FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6E0B0 8007D8B0 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6E0B4 8007D8B4 400046AC */  sw         $a2, 0x40($v0)
/* 6E0B8 8007D8B8 44005EAC */  sw         $fp, 0x44($v0)
/* 6E0BC 8007D8BC 1000B08F */  lw         $s0, 0x10($sp)
/* 6E0C0 8007D8C0 1400B18F */  lw         $s1, 0x14($sp)
/* 6E0C4 8007D8C4 1800B28F */  lw         $s2, 0x18($sp)
/* 6E0C8 8007D8C8 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6E0CC 8007D8CC 2000B48F */  lw         $s4, 0x20($sp)
/* 6E0D0 8007D8D0 2400B58F */  lw         $s5, 0x24($sp)
/* 6E0D4 8007D8D4 2800B68F */  lw         $s6, 0x28($sp)
/* 6E0D8 8007D8D8 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6E0DC 8007D8DC 3000BE8F */  lw         $fp, 0x30($sp)
/* 6E0E0 8007D8E0 0800E003 */  jr         $ra
/* 6E0E4 8007D8E4 4400BD27 */   addiu     $sp, $sp, 0x44
