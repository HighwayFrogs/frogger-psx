.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_GT3
/* 6CD90 8007C590 1000A28F */  lw         $v0, 0x10($sp)
/* 6CD94 8007C594 1400A38F */  lw         $v1, 0x14($sp)
/* 6CD98 8007C598 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6CD9C 8007C59C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6CDA0 8007C5A0 1400B1AF */  sw         $s1, 0x14($sp)
/* 6CDA4 8007C5A4 1800B2AF */  sw         $s2, 0x18($sp)
/* 6CDA8 8007C5A8 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6CDAC 8007C5AC 2000B4AF */  sw         $s4, 0x20($sp)
/* 6CDB0 8007C5B0 2400B5AF */  sw         $s5, 0x24($sp)
/* 6CDB4 8007C5B4 2800B6AF */  sw         $s6, 0x28($sp)
/* 6CDB8 8007C5B8 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6CDBC 8007C5BC 3000BEAF */  sw         $fp, 0x30($sp)
/* 6CDC0 8007C5C0 2000508C */  lw         $s0, 0x20($v0)
/* 6CDC4 8007C5C4 24005184 */  lh         $s1, 0x24($v0)
/* 6CDC8 8007C5C8 2800528C */  lw         $s2, 0x28($v0)
/* 6CDCC 8007C5CC 2C00538C */  lw         $s3, 0x2C($v0)
/* 6CDD0 8007C5D0 26005484 */  lh         $s4, 0x26($v0)
/* 6CDD4 8007C5D4 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6CDD8 8007C5D8 0000B58E */  lw         $s5, 0x0($s5)
/* 6CDDC 8007C5DC 00000000 */  nop
/* 6CDE0 8007C5E0 03AC1500 */  sra        $s5, $s5, 16
/* 6CDE4 8007C5E4 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6CDE8 8007C5E8 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6CDEC 8007C5EC 0009173C */  lui        $s7, (0x9000000 >> 16)
/* 6CDF0 8007C5F0 44005E8C */  lw         $fp, 0x44($v0)
/* 6CDF4 8007C5F4 0000C884 */  lh         $t0, 0x0($a2)
/* 6CDF8 8007C5F8 0200C984 */  lh         $t1, 0x2($a2)
/* 6CDFC 8007C5FC 0400CA84 */  lh         $t2, 0x4($a2)
/* 6CE00 8007C600 C0400800 */  sll        $t0, $t0, 3
/* 6CE04 8007C604 C0480900 */  sll        $t1, $t1, 3
/* 6CE08 8007C608 C0500A00 */  sll        $t2, $t2, 3
/* 6CE0C 8007C60C 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CE10 8007C610 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CE14 8007C614 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007C618:
/* 6CE18 8007C618 000000C9 */  lwc2       $0, 0x0($t0)
/* 6CE1C 8007C61C 040001C9 */  lwc2       $1, 0x4($t0)
/* 6CE20 8007C620 000022C9 */  lwc2       $2, 0x0($t1)
/* 6CE24 8007C624 040023C9 */  lwc2       $3, 0x4($t1)
/* 6CE28 8007C628 000044C9 */  lwc2       $4, 0x0($t2)
/* 6CE2C 8007C62C 040045C9 */  lwc2       $5, 0x4($t2)
/* 6CE30 8007C630 1C00D820 */  addi       $t8, $a2, 0x1C # handwritten instruction
/* 6CE34 8007C634 00000000 */  nop
/* 6CE38 8007C638 3000284A */  RTPT
/* 6CE3C 8007C63C 00000887 */  lh         $t0, 0x0($t8)
/* 6CE40 8007C640 02000987 */  lh         $t1, 0x2($t8)
/* 6CE44 8007C644 04000A87 */  lh         $t2, 0x4($t8)
/* 6CE48 8007C648 C0400800 */  sll        $t0, $t0, 3
/* 6CE4C 8007C64C C0480900 */  sll        $t1, $t1, 3
/* 6CE50 8007C650 C0500A00 */  sll        $t2, $t2, 3
/* 6CE54 8007C654 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6CE58 8007C658 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6CE5C 8007C65C 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6CE60 8007C660 0600404B */  NCLIP
/* 6CE64 8007C664 1800C6C8 */  lwc2       $6, 0x18($a2)
/* 6CE68 8007C668 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6CE6C 8007C66C 00000000 */  nop
/* 6CE70 8007C670 2B00001B */  blez       $t8, .L8007C720
/* 6CE74 8007C674 00000000 */   nop
/* 6CE78 8007C678 2D00584B */  AVSZ3
/* 6CE7C 8007C67C 0600CC84 */  lh         $t4, 0x6($a2)
/* 6CE80 8007C680 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6CE84 8007C684 C0600C00 */  sll        $t4, $t4, 3
/* 6CE88 8007C688 07C03802 */  srav       $t8, $t8, $s1
/* 6CE8C 8007C68C 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6CE90 8007C690 2A081303 */  slt        $at, $t8, $s3
/* 6CE94 8007C694 22002014 */  bnez       $at, .L8007C720
/* 6CE98 8007C698 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6CE9C 8007C69C 2A081203 */  slt        $at, $t8, $s2
/* 6CEA0 8007C6A0 1F002010 */  beqz       $at, .L8007C720
/* 6CEA4 8007C6A4 0800CD84 */   lh        $t5, 0x8($a2)
/* 6CEA8 8007C6A8 0A00CE84 */  lh         $t6, 0xA($a2)
/* 6CEAC 8007C6AC 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6CEB0 8007C6B0 1400EDE8 */  swc2       $13, 0x14($a3)
/* 6CEB4 8007C6B4 2000EEE8 */  swc2       $14, 0x20($a3)
/* 6CEB8 8007C6B8 C0680D00 */  sll        $t5, $t5, 3
/* 6CEBC 8007C6BC C0700E00 */  sll        $t6, $t6, 3
/* 6CEC0 8007C6C0 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6CEC4 8007C6C4 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6CEC8 8007C6C8 000080C9 */  lwc2       $0, 0x0($t4)
/* 6CECC 8007C6CC 040081C9 */  lwc2       $1, 0x4($t4)
/* 6CED0 8007C6D0 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6CED4 8007C6D4 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6CED8 8007C6D8 0000C4C9 */  lwc2       $4, 0x0($t6)
/* 6CEDC 8007C6DC 0400C5C9 */  lwc2       $5, 0x4($t6)
/* 6CEE0 8007C6E0 04000310 */  beq        $zero, $v1, .L8007C6F4
/* 6CEE4 8007C6E4 00000000 */   nop
/* 6CEE8 8007C6E8 1604F84A */  NCDT
/* 6CEEC 8007C6EC 02000010 */  b          .L8007C6F8
/* 6CEF0 8007C6F0 00000000 */   nop
.L8007C6F4:
/* 6CEF4 8007C6F4 3F04184B */  NCCT
.L8007C6F8:
/* 6CEF8 8007C6F8 24C8F600 */  and        $t9, $a3, $s6
/* 6CEFC 8007C6FC 80C01800 */  sll        $t8, $t8, 2
/* 6CF00 8007C700 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6CF04 8007C704 0000018F */  lw         $at, 0x0($t8)
/* 6CF08 8007C708 000019AF */  sw         $t9, 0x0($t8)
/* 6CF0C 8007C70C 25083700 */  or         $at, $at, $s7
/* 6CF10 8007C710 000021AF */  sw         $at, 0x0($t9)
/* 6CF14 8007C714 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6CF18 8007C718 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6CF1C 8007C71C 1C00F6E8 */  swc2       $22, 0x1C($a3)
.L8007C720:
/* 6CF20 8007C720 1C00C620 */  addi       $a2, $a2, 0x1C # handwritten instruction
/* 6CF24 8007C724 2800E720 */  addi       $a3, $a3, 0x28 # handwritten instruction
/* 6CF28 8007C728 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6CF2C 8007C72C BAFFA01E */  bgtz       $s5, .L8007C618
/* 6CF30 8007C730 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6CF34 8007C734 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6CF38 8007C738 400046AC */  sw         $a2, 0x40($v0)
/* 6CF3C 8007C73C 44005EAC */  sw         $fp, 0x44($v0)
/* 6CF40 8007C740 1000B08F */  lw         $s0, 0x10($sp)
/* 6CF44 8007C744 1400B18F */  lw         $s1, 0x14($sp)
/* 6CF48 8007C748 1800B28F */  lw         $s2, 0x18($sp)
/* 6CF4C 8007C74C 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6CF50 8007C750 2000B48F */  lw         $s4, 0x20($sp)
/* 6CF54 8007C754 2400B58F */  lw         $s5, 0x24($sp)
/* 6CF58 8007C758 2800B68F */  lw         $s6, 0x28($sp)
/* 6CF5C 8007C75C 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6CF60 8007C760 3000BE8F */  lw         $fp, 0x30($sp)
/* 6CF64 8007C764 0800E003 */  jr         $ra
/* 6CF68 8007C768 3400BD27 */   addiu     $sp, $sp, 0x34
