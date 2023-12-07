.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_FT3
/* 6C5A8 8007BDA8 1000A28F */  lw         $v0, 0x10($sp)
/* 6C5AC 8007BDAC 1400A38F */  lw         $v1, 0x14($sp)
/* 6C5B0 8007BDB0 CCFFBD27 */  addiu      $sp, $sp, -0x34
/* 6C5B4 8007BDB4 1000B0AF */  sw         $s0, 0x10($sp)
/* 6C5B8 8007BDB8 1400B1AF */  sw         $s1, 0x14($sp)
/* 6C5BC 8007BDBC 1800B2AF */  sw         $s2, 0x18($sp)
/* 6C5C0 8007BDC0 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6C5C4 8007BDC4 2000B4AF */  sw         $s4, 0x20($sp)
/* 6C5C8 8007BDC8 2400B5AF */  sw         $s5, 0x24($sp)
/* 6C5CC 8007BDCC 2800B6AF */  sw         $s6, 0x28($sp)
/* 6C5D0 8007BDD0 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6C5D4 8007BDD4 3000BEAF */  sw         $fp, 0x30($sp)
/* 6C5D8 8007BDD8 2000508C */  lw         $s0, 0x20($v0)
/* 6C5DC 8007BDDC 24005184 */  lh         $s1, 0x24($v0)
/* 6C5E0 8007BDE0 2800528C */  lw         $s2, 0x28($v0)
/* 6C5E4 8007BDE4 2C00538C */  lw         $s3, 0x2C($v0)
/* 6C5E8 8007BDE8 26005484 */  lh         $s4, 0x26($v0)
/* 6C5EC 8007BDEC FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6C5F0 8007BDF0 0000B58E */  lw         $s5, 0x0($s5)
/* 6C5F4 8007BDF4 00000000 */  nop
/* 6C5F8 8007BDF8 03AC1500 */  sra        $s5, $s5, 16
/* 6C5FC 8007BDFC FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6C600 8007BE00 FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6C604 8007BE04 0007173C */  lui        $s7, (0x7000000 >> 16)
/* 6C608 8007BE08 44005E8C */  lw         $fp, 0x44($v0)
/* 6C60C 8007BE0C 0000C884 */  lh         $t0, 0x0($a2)
/* 6C610 8007BE10 0200C984 */  lh         $t1, 0x2($a2)
/* 6C614 8007BE14 0400CA84 */  lh         $t2, 0x4($a2)
/* 6C618 8007BE18 C0400800 */  sll        $t0, $t0, 3
/* 6C61C 8007BE1C C0480900 */  sll        $t1, $t1, 3
/* 6C620 8007BE20 C0500A00 */  sll        $t2, $t2, 3
/* 6C624 8007BE24 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C628 8007BE28 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C62C 8007BE2C 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007BE30:
/* 6C630 8007BE30 000000C9 */  lwc2       $0, 0x0($t0)
/* 6C634 8007BE34 040001C9 */  lwc2       $1, 0x4($t0)
/* 6C638 8007BE38 000022C9 */  lwc2       $2, 0x0($t1)
/* 6C63C 8007BE3C 040023C9 */  lwc2       $3, 0x4($t1)
/* 6C640 8007BE40 000044C9 */  lwc2       $4, 0x0($t2)
/* 6C644 8007BE44 040045C9 */  lwc2       $5, 0x4($t2)
/* 6C648 8007BE48 1800D820 */  addi       $t8, $a2, 0x18 # handwritten instruction
/* 6C64C 8007BE4C 00000000 */  nop
/* 6C650 8007BE50 3000284A */  RTPT
/* 6C654 8007BE54 00000887 */  lh         $t0, 0x0($t8)
/* 6C658 8007BE58 02000987 */  lh         $t1, 0x2($t8)
/* 6C65C 8007BE5C 04000A87 */  lh         $t2, 0x4($t8)
/* 6C660 8007BE60 C0400800 */  sll        $t0, $t0, 3
/* 6C664 8007BE64 C0480900 */  sll        $t1, $t1, 3
/* 6C668 8007BE68 C0500A00 */  sll        $t2, $t2, 3
/* 6C66C 8007BE6C 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6C670 8007BE70 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6C674 8007BE74 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6C678 8007BE78 0600404B */  NCLIP
/* 6C67C 8007BE7C 1400C6C8 */  lwc2       $6, 0x14($a2)
/* 6C680 8007BE80 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6C684 8007BE84 00000000 */  nop
/* 6C688 8007BE88 2000001B */  blez       $t8, .L8007BF0C
/* 6C68C 8007BE8C 00000000 */   nop
/* 6C690 8007BE90 2D00584B */  AVSZ3
/* 6C694 8007BE94 0600CC84 */  lh         $t4, 0x6($a2)
/* 6C698 8007BE98 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6C69C 8007BE9C C0600C00 */  sll        $t4, $t4, 3
/* 6C6A0 8007BEA0 07C03802 */  srav       $t8, $t8, $s1
/* 6C6A4 8007BEA4 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6C6A8 8007BEA8 2A081303 */  slt        $at, $t8, $s3
/* 6C6AC 8007BEAC 17002014 */  bnez       $at, .L8007BF0C
/* 6C6B0 8007BEB0 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6C6B4 8007BEB4 2A081203 */  slt        $at, $t8, $s2
/* 6C6B8 8007BEB8 14002010 */  beqz       $at, .L8007BF0C
/* 6C6BC 8007BEBC 00000000 */   nop
/* 6C6C0 8007BEC0 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6C6C4 8007BEC4 1000EDE8 */  swc2       $13, 0x10($a3)
/* 6C6C8 8007BEC8 1800EEE8 */  swc2       $14, 0x18($a3)
/* 6C6CC 8007BECC 000080C9 */  lwc2       $0, 0x0($t4)
/* 6C6D0 8007BED0 040081C9 */  lwc2       $1, 0x4($t4)
/* 6C6D4 8007BED4 04000310 */  beq        $zero, $v1, .L8007BEE8
/* 6C6D8 8007BED8 00000000 */   nop
/* 6C6DC 8007BEDC 1304E84A */  NCDS
/* 6C6E0 8007BEE0 02000010 */  b          .L8007BEEC
/* 6C6E4 8007BEE4 00000000 */   nop
.L8007BEE8:
/* 6C6E8 8007BEE8 1B04084B */  NCCS
.L8007BEEC:
/* 6C6EC 8007BEEC 24C8F600 */  and        $t9, $a3, $s6
/* 6C6F0 8007BEF0 80C01800 */  sll        $t8, $t8, 2
/* 6C6F4 8007BEF4 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6C6F8 8007BEF8 0000018F */  lw         $at, 0x0($t8)
/* 6C6FC 8007BEFC 000019AF */  sw         $t9, 0x0($t8)
/* 6C700 8007BF00 25083700 */  or         $at, $at, $s7
/* 6C704 8007BF04 000021AF */  sw         $at, 0x0($t9)
/* 6C708 8007BF08 0400F6E8 */  swc2       $22, 0x4($a3)
.L8007BF0C:
/* 6C70C 8007BF0C 1800C620 */  addi       $a2, $a2, 0x18 # handwritten instruction
/* 6C710 8007BF10 2000E720 */  addi       $a3, $a3, 0x20 # handwritten instruction
/* 6C714 8007BF14 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6C718 8007BF18 C5FFA01E */  bgtz       $s5, .L8007BE30
/* 6C71C 8007BF1C FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6C720 8007BF20 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6C724 8007BF24 400046AC */  sw         $a2, 0x40($v0)
/* 6C728 8007BF28 44005EAC */  sw         $fp, 0x44($v0)
/* 6C72C 8007BF2C 1000B08F */  lw         $s0, 0x10($sp)
/* 6C730 8007BF30 1400B18F */  lw         $s1, 0x14($sp)
/* 6C734 8007BF34 1800B28F */  lw         $s2, 0x18($sp)
/* 6C738 8007BF38 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6C73C 8007BF3C 2000B48F */  lw         $s4, 0x20($sp)
/* 6C740 8007BF40 2400B58F */  lw         $s5, 0x24($sp)
/* 6C744 8007BF44 2800B68F */  lw         $s6, 0x28($sp)
/* 6C748 8007BF48 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6C74C 8007BF4C 3000BE8F */  lw         $fp, 0x30($sp)
/* 6C750 8007BF50 0800E003 */  jr         $ra
/* 6C754 8007BF54 3400BD27 */   addiu     $sp, $sp, 0x34
