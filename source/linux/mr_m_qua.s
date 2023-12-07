#/******************************************************************************
#/*%%%% mr_m_qua.s
#/*-----------------------------------------------------------------------------
#/*
#/*	Quaternion Functions (MIPS Versions)
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	20.03.97	Dean Ashton		Created
#/*	12.06.97	Tim Closs		MRInterpolateQuaternionsASM() no longer assumes
#/*						MR_QUAT is long-aligned
#/*						(due to existence of MR_QUAT_TRANS structure)
#/*	23.23.11	Kneesnap		Ported to GNU AS Syntax
#/*
#/*%%%**************************************************************************/

		.include	"macro.inc"
		.text

#/******************************************************************************
#/*%%%% MRQuaternionToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRQuaternionToMatrixASM(
#/*				MR_QUAT*	q,
#/*				MR_MAT*		m);
#/*
#/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
#/*
#/*	INPUTS		q	- (a0)	Pointer to quaternion (1.3.12 format)
#/*			m	- (a1)	Pointer to matrix to fill in
#/*
#/*	NOTES		Be careful when modifying this routine, it's pipelined to
#/*			hell, and uses an odd register layout (effectively trashing
#/*			one of the input argument pointers).
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	21.03.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRQuaternionToMatrixASM
/* 6A564 80079D64 E4FFBD27 */  addiu      $sp, $sp, -0x1C
/* 6A568 80079D68 1000B0AF */  sw         $s0, 0x10($sp)
/* 6A56C 80079D6C 1400B1AF */  sw         $s1, 0x14($sp)
/* 6A570 80079D70 1800B2AF */  sw         $s2, 0x18($sp)
/* 6A574 80079D74 00008284 */  lh         $v0, 0x0($a0)
/* 6A578 80079D78 02008384 */  lh         $v1, 0x2($a0)
/* 6A57C 80079D7C 04008184 */  lh         $at, 0x4($a0)
/* 6A580 80079D80 06008484 */  lh         $a0, 0x6($a0)
/* 6A584 80079D84 40880100 */  sll        $s1, $at, 1
/* 6A588 80079D88 00488248 */  mtc2       $v0, $9 # handwritten instruction
/* 6A58C 80079D8C 00508348 */  mtc2       $v1, $10 # handwritten instruction
/* 6A590 80079D90 00588148 */  mtc2       $at, $11 # handwritten instruction
/* 6A594 80079D94 00409148 */  mtc2       $s1, $8 # handwritten instruction
/* 6A598 80079D98 40800300 */  sll        $s0, $v1, 1
/* 6A59C 80079D9C 40900400 */  sll        $s2, $a0, 1
/* 6A5A0 80079DA0 3D00904B */  GPF        0
/* 6A5A4 80079DA4 18005000 */  mult       $v0, $s0
/* 6A5A8 80079DA8 00C80948 */  mfc2       $t1, $25 # handwritten instruction
/* 6A5AC 80079DAC 00D00C48 */  mfc2       $t4, $26 # handwritten instruction
/* 6A5B0 80079DB0 00D80E48 */  mfc2       $t6, $27 # handwritten instruction
/* 6A5B4 80079DB4 00409248 */  mtc2       $s2, $8 # handwritten instruction
/* 6A5B8 80079DB8 00488248 */  mtc2       $v0, $9 # handwritten instruction
/* 6A5BC 80079DBC 00508348 */  mtc2       $v1, $10 # handwritten instruction
/* 6A5C0 80079DC0 00588148 */  mtc2       $at, $11 # handwritten instruction
/* 6A5C4 80079DC4 12400000 */  mflo       $t0
/* 6A5C8 80079DC8 00100120 */  addi       $at, $zero, 0x1000 # handwritten instruction
/* 6A5CC 80079DCC 3D00904B */  GPF        0
/* 6A5D0 80079DD0 18007000 */  mult       $v1, $s0
/* 6A5D4 80079DD4 00C80A48 */  mfc2       $t2, $25 # handwritten instruction
/* 6A5D8 80079DD8 12580000 */  mflo       $t3
/* 6A5DC 80079DDC 00D00D48 */  mfc2       $t5, $26 # handwritten instruction
/* 6A5E0 80079DE0 20386E01 */  add        $a3, $t3, $t6 # handwritten instruction
/* 6A5E4 80079DE4 18009200 */  mult       $a0, $s2
/* 6A5E8 80079DE8 00D80F48 */  mfc2       $t7, $27 # handwritten instruction
/* 6A5EC 80079DEC 12C00000 */  mflo       $t8
/* 6A5F0 80079DF0 033B0700 */  sra        $a3, $a3, 12
/* 6A5F4 80079DF4 22382700 */  sub        $a3, $at, $a3 # handwritten instruction
/* 6A5F8 80079DF8 1000A7A4 */  sh         $a3, 0x10($a1)
/* 6A5FC 80079DFC 2030D801 */  add        $a2, $t6, $t8 # handwritten instruction
/* 6A600 80079E00 20388A01 */  add        $a3, $t4, $t2 # handwritten instruction
/* 6A604 80079E04 03330600 */  sra        $a2, $a2, 12
/* 6A608 80079E08 033B0700 */  sra        $a3, $a3, 12
/* 6A60C 80079E0C 22302600 */  sub        $a2, $at, $a2 # handwritten instruction
/* 6A610 80079E10 0200A7A4 */  sh         $a3, 0x2($a1)
/* 6A614 80079E14 0000A6A4 */  sh         $a2, 0x0($a1)
/* 6A618 80079E18 2238A901 */  sub        $a3, $t5, $t1 # handwritten instruction
/* 6A61C 80079E1C 22308A01 */  sub        $a2, $t4, $t2 # handwritten instruction
/* 6A620 80079E20 033B0700 */  sra        $a3, $a3, 12
/* 6A624 80079E24 03330600 */  sra        $a2, $a2, 12
/* 6A628 80079E28 0400A7A4 */  sh         $a3, 0x4($a1)
/* 6A62C 80079E2C 0600A6A4 */  sh         $a2, 0x6($a1)
/* 6A630 80079E30 20387801 */  add        $a3, $t3, $t8 # handwritten instruction
/* 6A634 80079E34 2030E801 */  add        $a2, $t7, $t0 # handwritten instruction
/* 6A638 80079E38 033B0700 */  sra        $a3, $a3, 12
/* 6A63C 80079E3C 03330600 */  sra        $a2, $a2, 12
/* 6A640 80079E40 22382700 */  sub        $a3, $at, $a3 # handwritten instruction
/* 6A644 80079E44 0A00A6A4 */  sh         $a2, 0xA($a1)
/* 6A648 80079E48 0800A7A4 */  sh         $a3, 0x8($a1)
/* 6A64C 80079E4C 2038A901 */  add        $a3, $t5, $t1 # handwritten instruction
/* 6A650 80079E50 2230E801 */  sub        $a2, $t7, $t0 # handwritten instruction
/* 6A654 80079E54 033B0700 */  sra        $a3, $a3, 12
/* 6A658 80079E58 03330600 */  sra        $a2, $a2, 12
/* 6A65C 80079E5C 0C00A7A4 */  sh         $a3, 0xC($a1)
/* 6A660 80079E60 0E00A6A4 */  sh         $a2, 0xE($a1)
/* 6A664 80079E64 1000B08F */  lw         $s0, 0x10($sp)
/* 6A668 80079E68 1400B18F */  lw         $s1, 0x14($sp)
/* 6A66C 80079E6C 1800B28F */  lw         $s2, 0x18($sp)
/* 6A670 80079E70 0800E003 */  jr         $ra
/* 6A674 80079E74 1C00BD27 */   addiu     $sp, $sp, 0x1C


#/******************************************************************************
#/*%%%% MRQuaternionBToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRQuaternionBToMatrixASM(
#/*				MR_QUATB*	q,
#/*				MR_MAT*		m);
#/*
#/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
#/*
#/*	INPUTS		q	- (a0)	Pointer to quaternion (1.1.6 format)
#/*			m	- (a1)	Pointer to matrix to fill in
#/*
#/*	NOTES		Be careful when modifying this routine, it's pipelined to
#/*			hell, and uses an odd register layout (effectively trashing
#/*			one of the input argument pointers). Is pretty much the
#/*			same as MRQuaternionToMatrixASM.
#/*		
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	21.03.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRQuaternionBToMatrixASM
/* 6A678 80079E78 E4FFBD27 */  addiu      $sp, $sp, -0x1C
/* 6A67C 80079E7C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6A680 80079E80 1400B1AF */  sw         $s1, 0x14($sp)
/* 6A684 80079E84 1800B2AF */  sw         $s2, 0x18($sp)
/* 6A688 80079E88 00008280 */  lb         $v0, 0x0($a0)
/* 6A68C 80079E8C 01008380 */  lb         $v1, 0x1($a0)
/* 6A690 80079E90 02008180 */  lb         $at, 0x2($a0)
/* 6A694 80079E94 03008480 */  lb         $a0, 0x3($a0)
/* 6A698 80079E98 40880100 */  sll        $s1, $at, 1
/* 6A69C 80079E9C 00488248 */  mtc2       $v0, $9 # handwritten instruction
/* 6A6A0 80079EA0 00508348 */  mtc2       $v1, $10 # handwritten instruction
/* 6A6A4 80079EA4 00588148 */  mtc2       $at, $11 # handwritten instruction
/* 6A6A8 80079EA8 00409148 */  mtc2       $s1, $8 # handwritten instruction
/* 6A6AC 80079EAC 40800300 */  sll        $s0, $v1, 1
/* 6A6B0 80079EB0 40900400 */  sll        $s2, $a0, 1
/* 6A6B4 80079EB4 3D00904B */  GPF        0
/* 6A6B8 80079EB8 18005000 */  mult       $v0, $s0
/* 6A6BC 80079EBC 00C80948 */  mfc2       $t1, $25 # handwritten instruction
/* 6A6C0 80079EC0 00D00C48 */  mfc2       $t4, $26 # handwritten instruction
/* 6A6C4 80079EC4 00D80E48 */  mfc2       $t6, $27 # handwritten instruction
/* 6A6C8 80079EC8 00409248 */  mtc2       $s2, $8 # handwritten instruction
/* 6A6CC 80079ECC 00488248 */  mtc2       $v0, $9 # handwritten instruction
/* 6A6D0 80079ED0 00508348 */  mtc2       $v1, $10 # handwritten instruction
/* 6A6D4 80079ED4 00588148 */  mtc2       $at, $11 # handwritten instruction
/* 6A6D8 80079ED8 12400000 */  mflo       $t0
/* 6A6DC 80079EDC 00100120 */  addi       $at, $zero, 0x1000 # handwritten instruction
/* 6A6E0 80079EE0 3D00904B */  GPF        0
/* 6A6E4 80079EE4 18007000 */  mult       $v1, $s0
/* 6A6E8 80079EE8 00C80A48 */  mfc2       $t2, $25 # handwritten instruction
/* 6A6EC 80079EEC 12580000 */  mflo       $t3
/* 6A6F0 80079EF0 00D00D48 */  mfc2       $t5, $26 # handwritten instruction
/* 6A6F4 80079EF4 20386E01 */  add        $a3, $t3, $t6 # handwritten instruction
/* 6A6F8 80079EF8 18009200 */  mult       $a0, $s2
/* 6A6FC 80079EFC 00D80F48 */  mfc2       $t7, $27 # handwritten instruction
/* 6A700 80079F00 12C00000 */  mflo       $t8
/* 6A704 80079F04 22382700 */  sub        $a3, $at, $a3 # handwritten instruction
/* 6A708 80079F08 1000A7A4 */  sh         $a3, 0x10($a1)
/* 6A70C 80079F0C 2030D801 */  add        $a2, $t6, $t8 # handwritten instruction
/* 6A710 80079F10 20388A01 */  add        $a3, $t4, $t2 # handwritten instruction
/* 6A714 80079F14 22302600 */  sub        $a2, $at, $a2 # handwritten instruction
/* 6A718 80079F18 0200A7A4 */  sh         $a3, 0x2($a1)
/* 6A71C 80079F1C 0000A6A4 */  sh         $a2, 0x0($a1)
/* 6A720 80079F20 2238A901 */  sub        $a3, $t5, $t1 # handwritten instruction
/* 6A724 80079F24 22308A01 */  sub        $a2, $t4, $t2 # handwritten instruction
/* 6A728 80079F28 0400A7A4 */  sh         $a3, 0x4($a1)
/* 6A72C 80079F2C 0600A6A4 */  sh         $a2, 0x6($a1)
/* 6A730 80079F30 20387801 */  add        $a3, $t3, $t8 # handwritten instruction
/* 6A734 80079F34 2030E801 */  add        $a2, $t7, $t0 # handwritten instruction
/* 6A738 80079F38 22382700 */  sub        $a3, $at, $a3 # handwritten instruction
/* 6A73C 80079F3C 0A00A6A4 */  sh         $a2, 0xA($a1)
/* 6A740 80079F40 0800A7A4 */  sh         $a3, 0x8($a1)
/* 6A744 80079F44 2038A901 */  add        $a3, $t5, $t1 # handwritten instruction
/* 6A748 80079F48 2230E801 */  sub        $a2, $t7, $t0 # handwritten instruction
/* 6A74C 80079F4C 0C00A7A4 */  sh         $a3, 0xC($a1)
/* 6A750 80079F50 0E00A6A4 */  sh         $a2, 0xE($a1)
/* 6A754 80079F54 1000B08F */  lw         $s0, 0x10($sp)
/* 6A758 80079F58 1400B18F */  lw         $s1, 0x14($sp)
/* 6A75C 80079F5C 1800B28F */  lw         $s2, 0x18($sp)
/* 6A760 80079F60 0800E003 */  jr         $ra
/* 6A764 80079F64 1C00BD27 */   addiu     $sp, $sp, 0x1C


#/******************************************************************************
#/*%%%% MRInterpolateQuaternionsASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsASM(
#/*				MR_QUAT*	startq,
#/*				MR_QUAT*	endq,
#/*				MR_QUAT*	destq,
#/*				MR_USHORT	t);
#/*
#/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
#/*
#/*	INPUTS		startq	- (a0)	Start quaternion
#/*			endq	- (a1)	End quaternion
#/*			destq	- (a2)	Destination quaternion (output)
#/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
#/*
#/*	CHANGED		PROGRAMMER	REASON
#/*	-------		----------	------
#/*	17.05.96	Tim Closs	Created
#/*	21.03.97	Dean Ashton	MIPS/GTE Conversion
#/*	12.06.97	Tim Closs	No longer assumes MR_QUAT is long-aligned
#/*			       		(due to existence of MR_QUAT_TRANS structure)
#/*
#/*%%%**************************************************************************/

# a0	-	Pointer to startq	(initial)
# a1	-	Pointer to endq		(initial)
# a2	-	Pointer to destq	(initial)
# a3	-	t			(initial)
#
# s0	-	bflip
# s1	-	cosomega
# s2	-	omega
# s3	-	sinomega
#
# s4	-	Pointer to startq
# s5	-	Pointer to endq
# s6	-	Pointer to destq
# s7	-	Safe work
#
# s8	-	startscale
#

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRInterpolateQuaternionsASM
/* 6A768 80079F68 C8FFBD27 */  addiu      $sp, $sp, -0x38
/* 6A76C 80079F6C 1000B0AF */  sw         $s0, 0x10($sp)
/* 6A770 80079F70 1400B1AF */  sw         $s1, 0x14($sp)
/* 6A774 80079F74 1800B2AF */  sw         $s2, 0x18($sp)
/* 6A778 80079F78 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6A77C 80079F7C 2000B4AF */  sw         $s4, 0x20($sp)
/* 6A780 80079F80 2400B5AF */  sw         $s5, 0x24($sp)
/* 6A784 80079F84 2800B6AF */  sw         $s6, 0x28($sp)
/* 6A788 80079F88 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6A78C 80079F8C 3000BEAF */  sw         $fp, 0x30($sp)
/* 6A790 80079F90 3400BFAF */  sw         $ra, 0x34($sp)
/* 6A794 80079F94 0900E014 */  bnez       $a3, .L80079FBC
/* 6A798 80079F98 00008884 */   lh        $t0, 0x0($a0)
/* 6A79C 80079F9C 02008984 */  lh         $t1, 0x2($a0)
/* 6A7A0 80079FA0 04008A84 */  lh         $t2, 0x4($a0)
/* 6A7A4 80079FA4 06008B84 */  lh         $t3, 0x6($a0)
/* 6A7A8 80079FA8 0000C8A4 */  sh         $t0, 0x0($a2)
/* 6A7AC 80079FAC 0200C9A4 */  sh         $t1, 0x2($a2)
/* 6A7B0 80079FB0 0400CAA4 */  sh         $t2, 0x4($a2)
/* 6A7B4 80079FB4 75000010 */  b          .L8007A18C
/* 6A7B8 80079FB8 0600CBA4 */   sh        $t3, 0x6($a2)
.L80079FBC:
/* 6A7BC 80079FBC 20A08000 */  add        $s4, $a0, $zero # handwritten instruction
/* 6A7C0 80079FC0 20A8A000 */  add        $s5, $a1, $zero # handwritten instruction
/* 6A7C4 80079FC4 20B0C000 */  add        $s6, $a2, $zero # handwritten instruction
/* 6A7C8 80079FC8 00008894 */  lhu        $t0, 0x0($a0)
/* 6A7CC 80079FCC 02008994 */  lhu        $t1, 0x2($a0)
/* 6A7D0 80079FD0 04008A94 */  lhu        $t2, 0x4($a0)
/* 6A7D4 80079FD4 004C0900 */  sll        $t1, $t1, 16
/* 6A7D8 80079FD8 25400901 */  or         $t0, $t0, $t1
/* 6A7DC 80079FDC 0000C848 */  ctc2       $t0, $0 # handwritten instruction
/* 6A7E0 80079FE0 0008CA48 */  ctc2       $t2, $1 # handwritten instruction
/* 6A7E4 80079FE4 0000A894 */  lhu        $t0, 0x0($a1)
/* 6A7E8 80079FE8 0200A994 */  lhu        $t1, 0x2($a1)
/* 6A7EC 80079FEC 0400AA94 */  lhu        $t2, 0x4($a1)
/* 6A7F0 80079FF0 004C0900 */  sll        $t1, $t1, 16
/* 6A7F4 80079FF4 25400901 */  or         $t0, $t0, $t1
/* 6A7F8 80079FF8 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 6A7FC 80079FFC 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 6A800 8007A000 06008884 */  lh         $t0, 0x6($a0)
/* 6A804 8007A004 0600A984 */  lh         $t1, 0x6($a1)
/* 6A808 8007A008 1260404A */  MVMVA      0, 0, 0, 3, 0
/* 6A80C 8007A00C 18000901 */  mult       $t0, $t1
/* 6A810 8007A010 00C80A48 */  mfc2       $t2, $25 # handwritten instruction
/* 6A814 8007A014 12680000 */  mflo       $t5
/* 6A818 8007A018 2040AA01 */  add        $t0, $t5, $t2 # handwritten instruction
/* 6A81C 8007A01C 038B0800 */  sra        $s1, $t0, 12
/* 6A820 8007A020 00101934 */  ori        $t9, $zero, 0x1000
/* 6A824 8007A024 03002106 */  bgez       $s1, .L8007A034
/* 6A828 8007A028 25800000 */   or        $s0, $zero, $zero
/* 6A82C 8007A02C 22881100 */  sub        $s1, $zero, $s1 # handwritten instruction
/* 6A830 8007A030 01001034 */  ori        $s0, $zero, 0x1
.L8007A034:
/* 6A834 8007A034 22403103 */  sub        $t0, $t9, $s1 # handwritten instruction
/* 6A838 8007A038 FFFF2823 */  addi       $t0, $t9, -0x1 # handwritten instruction
/* 6A83C 8007A03C 2C000005 */  bltz       $t0, .L8007A0F0
/* 6A840 8007A040 22F03703 */   sub       $fp, $t9, $s7 # handwritten instruction
/* 6A844 8007A044 0010212A */  slti       $at, $s1, 0x1000
/* 6A848 8007A048 02002014 */  bnez       $at, .L8007A054
/* 6A84C 8007A04C 25102002 */   or        $v0, $s1, $zero
/* 6A850 8007A050 00100220 */  addi       $v0, $zero, 0x1000 # handwritten instruction
.L8007A054:
/* 6A854 8007A054 00F04128 */  slti       $at, $v0, -0x1000
/* 6A858 8007A058 02002010 */  beqz       $at, .L8007A064
/* 6A85C 8007A05C 25884000 */   or        $s1, $v0, $zero
/* 6A860 8007A060 00F01120 */  addi       $s1, $zero, -0x1000 # handwritten instruction
.L8007A064:
/* 6A864 8007A064 00102922 */  addi       $t1, $s1, 0x1000 # handwritten instruction
/* 6A868 8007A068 0A800A3C */  lui        $t2, %hi(MRAcos_table)
/* 6A86C 8007A06C 40480900 */  sll        $t1, $t1, 1
/* 6A870 8007A070 20724A35 */  ori        $t2, $t2, %lo(MRAcos_table)
/* 6A874 8007A074 20504901 */  add        $t2, $t2, $t1 # handwritten instruction
/* 6A878 8007A078 00005285 */  lh         $s2, 0x0($t2)
/* 6A87C 8007A07C 0B800B3C */  lui        $t3, %hi(rcossin_tbl)
/* 6A880 8007A080 CCC46B25 */  addiu      $t3, $t3, %lo(rcossin_tbl)
/* 6A884 8007A084 80601200 */  sll        $t4, $s2, 2
/* 6A888 8007A088 20608B01 */  add        $t4, $t4, $t3 # handwritten instruction
/* 6A88C 8007A08C 00008D8D */  lw         $t5, 0x0($t4)
/* 6A890 8007A090 00000000 */  nop
/* 6A894 8007A094 006C0D00 */  sll        $t5, $t5, 16
/* 6A898 8007A098 039C0D00 */  sra        $s3, $t5, 16
/* 6A89C 8007A09C 1800F200 */  mult       $a3, $s2
/* 6A8A0 8007A0A0 00000000 */  nop
/* 6A8A4 8007A0A4 12B80000 */  mflo       $s7
/* 6A8A8 8007A0A8 03BB1700 */  sra        $s7, $s7, 12
/* 6A8AC 8007A0AC 80601700 */  sll        $t4, $s7, 2
/* 6A8B0 8007A0B0 20608B01 */  add        $t4, $t4, $t3 # handwritten instruction
/* 6A8B4 8007A0B4 00008D8D */  lw         $t5, 0x0($t4)
/* 6A8B8 8007A0B8 00000000 */  nop
/* 6A8BC 8007A0BC 00640D00 */  sll        $t4, $t5, 16
/* 6A8C0 8007A0C0 03110C00 */  sra        $v0, $t4, 4
/* 6A8C4 8007A0C4 1A005300 */  div        $zero, $v0, $s3
/* 6A8C8 8007A0C8 12980000 */  mflo       $s3
/* 6A8CC 8007A0CC 031C0D00 */  sra        $v1, $t5, 16
/* 6A8D0 8007A0D0 00000000 */  nop
/* 6A8D4 8007A0D4 18003302 */  mult       $s1, $s3
/* 6A8D8 8007A0D8 00006822 */  addi       $t0, $s3, 0x0 # handwritten instruction
/* 6A8DC 8007A0DC 12480000 */  mflo       $t1
/* 6A8E0 8007A0E0 034B0900 */  sra        $t1, $t1, 12
/* 6A8E4 8007A0E4 22F06900 */  sub        $fp, $v1, $t1 # handwritten instruction
/* 6A8E8 8007A0E8 02000010 */  b          .L8007A0F4
/* 6A8EC 8007A0EC 3400BF8F */   lw        $ra, 0x34($sp)
.L8007A0F0:
/* 6A8F0 8007A0F0 2540E000 */  or         $t0, $a3, $zero
.L8007A0F4:
/* 6A8F4 8007A0F4 02000016 */  bnez       $s0, .L8007A100
/* 6A8F8 8007A0F8 22400800 */   sub       $t0, $zero, $t0 # handwritten instruction
/* 6A8FC 8007A0FC 22400800 */  sub        $t0, $zero, $t0 # handwritten instruction
.L8007A100:
/* 6A900 8007A100 0000A986 */  lh         $t1, 0x0($s5)
/* 6A904 8007A104 0200AA86 */  lh         $t2, 0x2($s5)
/* 6A908 8007A108 0400AB86 */  lh         $t3, 0x4($s5)
/* 6A90C 8007A10C 00408848 */  mtc2       $t0, $8 # handwritten instruction
/* 6A910 8007A110 00488948 */  mtc2       $t1, $9 # handwritten instruction
/* 6A914 8007A114 00508A48 */  mtc2       $t2, $10 # handwritten instruction
/* 6A918 8007A118 00588B48 */  mtc2       $t3, $11 # handwritten instruction
/* 6A91C 8007A11C 0600AC86 */  lh         $t4, 0x6($s5)
/* 6A920 8007A120 00000000 */  nop
/* 6A924 8007A124 3D00904B */  GPF        0
/* 6A928 8007A128 18000C01 */  mult       $t0, $t4
/* 6A92C 8007A12C 00008986 */  lh         $t1, 0x0($s4)
/* 6A930 8007A130 02008A86 */  lh         $t2, 0x2($s4)
/* 6A934 8007A134 04008B86 */  lh         $t3, 0x4($s4)
/* 6A938 8007A138 00409E48 */  mtc2       $fp, $8 # handwritten instruction
/* 6A93C 8007A13C 00488948 */  mtc2       $t1, $9 # handwritten instruction
/* 6A940 8007A140 00508A48 */  mtc2       $t2, $10 # handwritten instruction
/* 6A944 8007A144 00588B48 */  mtc2       $t3, $11 # handwritten instruction
/* 6A948 8007A148 12400000 */  mflo       $t0
/* 6A94C 8007A14C 06008C86 */  lh         $t4, 0x6($s4)
/* 6A950 8007A150 3E00A04B */  GPL        0
/* 6A954 8007A154 1800CC03 */  mult       $fp, $t4
/* 6A958 8007A158 00C80948 */  mfc2       $t1, $25 # handwritten instruction
/* 6A95C 8007A15C 00D00A48 */  mfc2       $t2, $26 # handwritten instruction
/* 6A960 8007A160 12600000 */  mflo       $t4
/* 6A964 8007A164 00D80B48 */  mfc2       $t3, $27 # handwritten instruction
/* 6A968 8007A168 20600C01 */  add        $t4, $t0, $t4 # handwritten instruction
/* 6A96C 8007A16C 034B0900 */  sra        $t1, $t1, 12
/* 6A970 8007A170 03530A00 */  sra        $t2, $t2, 12
/* 6A974 8007A174 035B0B00 */  sra        $t3, $t3, 12
/* 6A978 8007A178 03630C00 */  sra        $t4, $t4, 12
/* 6A97C 8007A17C 0000C9A6 */  sh         $t1, 0x0($s6)
/* 6A980 8007A180 0200CAA6 */  sh         $t2, 0x2($s6)
/* 6A984 8007A184 0400CBA6 */  sh         $t3, 0x4($s6)
/* 6A988 8007A188 0600CCA6 */  sh         $t4, 0x6($s6)
.L8007A18C:
/* 6A98C 8007A18C 1000B08F */  lw         $s0, 0x10($sp)
/* 6A990 8007A190 1400B18F */  lw         $s1, 0x14($sp)
/* 6A994 8007A194 1800B28F */  lw         $s2, 0x18($sp)
/* 6A998 8007A198 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6A99C 8007A19C 2000B48F */  lw         $s4, 0x20($sp)
/* 6A9A0 8007A1A0 2400B58F */  lw         $s5, 0x24($sp)
/* 6A9A4 8007A1A4 2800B68F */  lw         $s6, 0x28($sp)
/* 6A9A8 8007A1A8 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6A9AC 8007A1AC 3000BE8F */  lw         $fp, 0x30($sp)
/* 6A9B0 8007A1B0 0800E003 */  jr         $ra
/* 6A9B4 8007A1B4 3800BD27 */   addiu     $sp, $sp, 0x38



#/******************************************************************************
#/*%%%% MRInterpolateQuaternionsBToMatrixASM
#/*-----------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsBToMatrixASM(
#/*				MR_QUATB*	startq,
#/*				MR_QUATB*	endq,
#/*				MR_MAT*		matrix,
#/*				MR_USHORT	t);
#/*
#/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
#/*
#/*	INPUTS		startq	- (a0)	Start quaternion
#/*			endq	- (a1)	End quaternion
#/*			matrix	- (a2)	Destination matrix (output)
#/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	19.03.97	Tim Closs		Created
#/*	21.03.97	Dean Ashton		MIPS/GTE Conversion
#/*
#/*%%%**************************************************************************/

# a0	-	Pointer to startq	(initial)
# a1	-	Pointer to endq		(initial)
# a2	-	Pointer to matrix	(initial)
# a3	-	t			(initial)
#
# s0	-	bflip
# s1	-	cosomega
# s2	-	omega
# s3	-	sinomega
#
# s4	-	Pointer to startq
# s5	-	Pointer to endq
# s6	-	Pointer to matrix
# s7	-	Safe work
#
# s8	-	startscale

.set noat      /* allow manual use of $at */
.set noreorder /* dont insert nops after branches */

# Handwritten function
glabel MRInterpolateQuaternionsBToMatrixASM
/* 6A9B8 8007A1B8 C0FFBD27 */  addiu      $sp, $sp, -0x40
/* 6A9BC 8007A1BC 1000B0AF */  sw         $s0, 0x10($sp)
/* 6A9C0 8007A1C0 1400B1AF */  sw         $s1, 0x14($sp)
/* 6A9C4 8007A1C4 1800B2AF */  sw         $s2, 0x18($sp)
/* 6A9C8 8007A1C8 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6A9CC 8007A1CC 2000B4AF */  sw         $s4, 0x20($sp)
/* 6A9D0 8007A1D0 2400B5AF */  sw         $s5, 0x24($sp)
/* 6A9D4 8007A1D4 2800B6AF */  sw         $s6, 0x28($sp)
/* 6A9D8 8007A1D8 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6A9DC 8007A1DC 3000BEAF */  sw         $fp, 0x30($sp)
/* 6A9E0 8007A1E0 3400BFAF */  sw         $ra, 0x34($sp)
/* 6A9E4 8007A1E4 20A08000 */  add        $s4, $a0, $zero # handwritten instruction
/* 6A9E8 8007A1E8 20A8A000 */  add        $s5, $a1, $zero # handwritten instruction
/* 6A9EC 8007A1EC 20B0C000 */  add        $s6, $a2, $zero # handwritten instruction
/* 6A9F0 8007A1F0 0400E014 */  bnez       $a3, .L8007A204
/* 6A9F4 8007A1F4 00000000 */   nop
/* 6A9F8 8007A1F8 9EE7010C */  jal        MRQuaternionBToMatrixASM
/* 6A9FC 8007A1FC 2028C002 */   add       $a1, $s6, $zero # handwritten instruction
/* 6AA00 8007A200 7D000010 */  b          .L8007A3F8
.L8007A204:
/* 6AA04 8007A204 00008882 */   lb        $t0, 0x0($s4)
/* 6AA08 8007A208 01008982 */  lb         $t1, 0x1($s4)
/* 6AA0C 8007A20C 02008A82 */  lb         $t2, 0x2($s4)
/* 6AA10 8007A210 00440800 */  sll        $t0, $t0, 16
/* 6AA14 8007A214 004C0900 */  sll        $t1, $t1, 16
/* 6AA18 8007A218 02440800 */  srl        $t0, $t0, 16
/* 6AA1C 8007A21C 25400901 */  or         $t0, $t0, $t1
/* 6AA20 8007A220 0000C848 */  ctc2       $t0, $0 # handwritten instruction
/* 6AA24 8007A224 0008CA48 */  ctc2       $t2, $1 # handwritten instruction
/* 6AA28 8007A228 0000A882 */  lb         $t0, 0x0($s5)
/* 6AA2C 8007A22C 0100A982 */  lb         $t1, 0x1($s5)
/* 6AA30 8007A230 0200AA82 */  lb         $t2, 0x2($s5)
/* 6AA34 8007A234 00440800 */  sll        $t0, $t0, 16
/* 6AA38 8007A238 004C0900 */  sll        $t1, $t1, 16
/* 6AA3C 8007A23C 02440800 */  srl        $t0, $t0, 16
/* 6AA40 8007A240 25400901 */  or         $t0, $t0, $t1
/* 6AA44 8007A244 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 6AA48 8007A248 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 6AA4C 8007A24C 03008882 */  lb         $t0, 0x3($s4)
/* 6AA50 8007A250 0300A982 */  lb         $t1, 0x3($s5)
/* 6AA54 8007A254 1260404A */  MVMVA      0, 0, 0, 3, 0
/* 6AA58 8007A258 18000901 */  mult       $t0, $t1
/* 6AA5C 8007A25C 00C80A48 */  mfc2       $t2, $25 # handwritten instruction
/* 6AA60 8007A260 12680000 */  mflo       $t5
/* 6AA64 8007A264 2088AA01 */  add        $s1, $t5, $t2 # handwritten instruction
/* 6AA68 8007A268 00101934 */  ori        $t9, $zero, 0x1000
/* 6AA6C 8007A26C 03002106 */  bgez       $s1, .L8007A27C
/* 6AA70 8007A270 25800000 */   or        $s0, $zero, $zero
/* 6AA74 8007A274 22881100 */  sub        $s1, $zero, $s1 # handwritten instruction
/* 6AA78 8007A278 01001034 */  ori        $s0, $zero, 0x1
.L8007A27C:
/* 6AA7C 8007A27C 22403103 */  sub        $t0, $t9, $s1 # handwritten instruction
/* 6AA80 8007A280 FFFF2823 */  addi       $t0, $t9, -0x1 # handwritten instruction
/* 6AA84 8007A284 2C000005 */  bltz       $t0, .L8007A338
/* 6AA88 8007A288 22F03703 */   sub       $fp, $t9, $s7 # handwritten instruction
/* 6AA8C 8007A28C 0010212A */  slti       $at, $s1, 0x1000
/* 6AA90 8007A290 02002014 */  bnez       $at, .L8007A29C
/* 6AA94 8007A294 25102002 */   or        $v0, $s1, $zero
/* 6AA98 8007A298 00100220 */  addi       $v0, $zero, 0x1000 # handwritten instruction
.L8007A29C:
/* 6AA9C 8007A29C 00F04128 */  slti       $at, $v0, -0x1000
/* 6AAA0 8007A2A0 02002010 */  beqz       $at, .L8007A2AC
/* 6AAA4 8007A2A4 25884000 */   or        $s1, $v0, $zero
/* 6AAA8 8007A2A8 00F01120 */  addi       $s1, $zero, -0x1000 # handwritten instruction
.L8007A2AC:
/* 6AAAC 8007A2AC 00102922 */  addi       $t1, $s1, 0x1000 # handwritten instruction
/* 6AAB0 8007A2B0 0A800A3C */  lui        $t2, %hi(MRAcos_table)
/* 6AAB4 8007A2B4 40480900 */  sll        $t1, $t1, 1
/* 6AAB8 8007A2B8 20724A35 */  ori        $t2, $t2, %lo(MRAcos_table)
/* 6AABC 8007A2BC 20504901 */  add        $t2, $t2, $t1 # handwritten instruction
/* 6AAC0 8007A2C0 00005285 */  lh         $s2, 0x0($t2)
/* 6AAC4 8007A2C4 0B800B3C */  lui        $t3, %hi(rcossin_tbl)
/* 6AAC8 8007A2C8 CCC46B25 */  addiu      $t3, $t3, %lo(rcossin_tbl)
/* 6AACC 8007A2CC 80601200 */  sll        $t4, $s2, 2
/* 6AAD0 8007A2D0 20608B01 */  add        $t4, $t4, $t3 # handwritten instruction
/* 6AAD4 8007A2D4 00008D8D */  lw         $t5, 0x0($t4)
/* 6AAD8 8007A2D8 00000000 */  nop
/* 6AADC 8007A2DC 006C0D00 */  sll        $t5, $t5, 16
/* 6AAE0 8007A2E0 039C0D00 */  sra        $s3, $t5, 16
/* 6AAE4 8007A2E4 1800F200 */  mult       $a3, $s2
/* 6AAE8 8007A2E8 00000000 */  nop
/* 6AAEC 8007A2EC 12B80000 */  mflo       $s7
/* 6AAF0 8007A2F0 03BB1700 */  sra        $s7, $s7, 12
/* 6AAF4 8007A2F4 80601700 */  sll        $t4, $s7, 2
/* 6AAF8 8007A2F8 20608B01 */  add        $t4, $t4, $t3 # handwritten instruction
/* 6AAFC 8007A2FC 00008D8D */  lw         $t5, 0x0($t4)
/* 6AB00 8007A300 00000000 */  nop
/* 6AB04 8007A304 00640D00 */  sll        $t4, $t5, 16
/* 6AB08 8007A308 03110C00 */  sra        $v0, $t4, 4
/* 6AB0C 8007A30C 1A005300 */  div        $zero, $v0, $s3
/* 6AB10 8007A310 12980000 */  mflo       $s3
/* 6AB14 8007A314 031C0D00 */  sra        $v1, $t5, 16
/* 6AB18 8007A318 00000000 */  nop
/* 6AB1C 8007A31C 18003302 */  mult       $s1, $s3
/* 6AB20 8007A320 00006822 */  addi       $t0, $s3, 0x0 # handwritten instruction
/* 6AB24 8007A324 12480000 */  mflo       $t1
/* 6AB28 8007A328 034B0900 */  sra        $t1, $t1, 12
/* 6AB2C 8007A32C 22F06900 */  sub        $fp, $v1, $t1 # handwritten instruction
/* 6AB30 8007A330 02000010 */  b          .L8007A33C
/* 6AB34 8007A334 00000000 */   nop
.L8007A338:
/* 6AB38 8007A338 2540E000 */  or         $t0, $a3, $zero
.L8007A33C:
/* 6AB3C 8007A33C 02000016 */  bnez       $s0, .L8007A348
/* 6AB40 8007A340 22400800 */   sub       $t0, $zero, $t0 # handwritten instruction
/* 6AB44 8007A344 22400800 */  sub        $t0, $zero, $t0 # handwritten instruction
.L8007A348:
/* 6AB48 8007A348 0000A982 */  lb         $t1, 0x0($s5)
/* 6AB4C 8007A34C 0100AA82 */  lb         $t2, 0x1($s5)
/* 6AB50 8007A350 0200AB82 */  lb         $t3, 0x2($s5)
/* 6AB54 8007A354 00408848 */  mtc2       $t0, $8 # handwritten instruction
/* 6AB58 8007A358 00488948 */  mtc2       $t1, $9 # handwritten instruction
/* 6AB5C 8007A35C 00508A48 */  mtc2       $t2, $10 # handwritten instruction
/* 6AB60 8007A360 00588B48 */  mtc2       $t3, $11 # handwritten instruction
/* 6AB64 8007A364 0300AC82 */  lb         $t4, 0x3($s5)
/* 6AB68 8007A368 00000000 */  nop
/* 6AB6C 8007A36C 3D00904B */  GPF        0
/* 6AB70 8007A370 18000C01 */  mult       $t0, $t4
/* 6AB74 8007A374 00008982 */  lb         $t1, 0x0($s4)
/* 6AB78 8007A378 01008A82 */  lb         $t2, 0x1($s4)
/* 6AB7C 8007A37C 02008B82 */  lb         $t3, 0x2($s4)
/* 6AB80 8007A380 00409E48 */  mtc2       $fp, $8 # handwritten instruction
/* 6AB84 8007A384 00488948 */  mtc2       $t1, $9 # handwritten instruction
/* 6AB88 8007A388 00508A48 */  mtc2       $t2, $10 # handwritten instruction
/* 6AB8C 8007A38C 00588B48 */  mtc2       $t3, $11 # handwritten instruction
/* 6AB90 8007A390 12400000 */  mflo       $t0
/* 6AB94 8007A394 03008C82 */  lb         $t4, 0x3($s4)
/* 6AB98 8007A398 3E00A04B */  GPL        0
/* 6AB9C 8007A39C 1800CC03 */  mult       $fp, $t4
/* 6ABA0 8007A3A0 00C80948 */  mfc2       $t1, $25 # handwritten instruction
/* 6ABA4 8007A3A4 00D00A48 */  mfc2       $t2, $26 # handwritten instruction
/* 6ABA8 8007A3A8 12600000 */  mflo       $t4
/* 6ABAC 8007A3AC 00D80B48 */  mfc2       $t3, $27 # handwritten instruction
/* 6ABB0 8007A3B0 20600C01 */  add        $t4, $t0, $t4 # handwritten instruction
/* 6ABB4 8007A3B4 83490900 */  sra        $t1, $t1, 6
/* 6ABB8 8007A3B8 83510A00 */  sra        $t2, $t2, 6
/* 6ABBC 8007A3BC 83590B00 */  sra        $t3, $t3, 6
/* 6ABC0 8007A3C0 83610C00 */  sra        $t4, $t4, 6
/* 6ABC4 8007A3C4 3800B027 */  addiu      $s0, $sp, 0x38
/* 6ABC8 8007A3C8 000009A6 */  sh         $t1, 0x0($s0)
/* 6ABCC 8007A3CC 02000AA6 */  sh         $t2, 0x2($s0)
/* 6ABD0 8007A3D0 04000BA6 */  sh         $t3, 0x4($s0)
/* 6ABD4 8007A3D4 06000CA6 */  sh         $t4, 0x6($s0)
/* 6ABD8 8007A3D8 05000011 */  beqz       $t0, .L8007A3F0
/* 6ABDC 8007A3DC 00000422 */   addi      $a0, $s0, 0x0 # handwritten instruction
/* 6ABE0 8007A3E0 00008520 */  addi       $a1, $a0, 0x0 # handwritten instruction
/* 6ABE4 8007A3E4 D5E9010C */  jal        MRNormaliseQuaternion
/* 6ABE8 8007A3E8 00100620 */   addi      $a2, $zero, 0x1000 # handwritten instruction
/* 6ABEC 8007A3EC 00000422 */  addi       $a0, $s0, 0x0 # handwritten instruction
.L8007A3F0:
/* 6ABF0 8007A3F0 59E7010C */  jal        MRQuaternionToMatrixASM
/* 6ABF4 8007A3F4 0000C522 */   addi      $a1, $s6, 0x0 # handwritten instruction
.L8007A3F8:
/* 6ABF8 8007A3F8 3400BF8F */  lw         $ra, 0x34($sp)
/* 6ABFC 8007A3FC 1000B08F */  lw         $s0, 0x10($sp)
/* 6AC00 8007A400 1400B18F */  lw         $s1, 0x14($sp)
/* 6AC04 8007A404 1800B28F */  lw         $s2, 0x18($sp)
/* 6AC08 8007A408 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6AC0C 8007A40C 2000B48F */  lw         $s4, 0x20($sp)
/* 6AC10 8007A410 2400B58F */  lw         $s5, 0x24($sp)
/* 6AC14 8007A414 2800B68F */  lw         $s6, 0x28($sp)
/* 6AC18 8007A418 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6AC1C 8007A41C 3000BE8F */  lw         $fp, 0x30($sp)
/* 6AC20 8007A420 0800E003 */  jr         $ra
/* 6AC24 8007A424 4000BD27 */   addiu     $sp, $sp, 0x40
