.include "macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MapRenderQuadsASM
/* 4A2D8 80059AD8 A0FFBD27 */  addiu      $sp, $sp, -0x60
/* 4A2DC 80059ADC 1000B0AF */  sw         $s0, 0x10($sp)
/* 4A2E0 80059AE0 1400B1AF */  sw         $s1, 0x14($sp)
/* 4A2E4 80059AE4 1800B2AF */  sw         $s2, 0x18($sp)
/* 4A2E8 80059AE8 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 4A2EC 80059AEC 2000B4AF */  sw         $s4, 0x20($sp)
/* 4A2F0 80059AF0 2400B5AF */  sw         $s5, 0x24($sp)
/* 4A2F4 80059AF4 2800B6AF */  sw         $s6, 0x28($sp)
/* 4A2F8 80059AF8 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 4A2FC 80059AFC 3000BEAF */  sw         $fp, 0x30($sp)
/* 4A300 80059B00 0400A88C */  lw         $t0, 0x4($a1)
/* 4A304 80059B04 FF00093C */  lui        $t1, (0xFFFFFF >> 16)
/* 4A308 80059B08 83400800 */  sra        $t0, $t0, 2
/* 4A30C 80059B0C FFFF2935 */  ori        $t1, $t1, (0xFFFFFF & 0xFFFF)
/* 4A310 80059B10 FFFF0825 */  addiu      $t0, $t0, -0x1
/* 4A314 80059B14 00460800 */  sll        $t0, $t0, 24
/* 4A318 80059B18 5400A9AF */  sw         $t1, 0x54($sp)
/* 4A31C 80059B1C 5800A8AF */  sw         $t0, 0x58($sp)
/* 4A320 80059B20 0B801E3C */  lui        $fp, %hi(Map_vertices)
/* 4A324 80059B24 A03BDE37 */  ori        $fp, $fp, %lo(Map_vertices)
/* 4A328 80059B28 0000DE8F */  lw         $fp, 0x0($fp)
/* 4A32C 80059B2C 801F093C */  lui        $t1, %hi(MRVp_work_ot)
/* 4A330 80059B30 801F0A3C */  lui        $t2, %hi(MRVp_ot_size)
/* 4A334 80059B34 801F0B3C */  lui        $t3, %hi(MRVp_otz_shift)
/* 4A338 80059B38 801F0C3C */  lui        $t4, %hi(MRTemp_svec)
/* 4A33C 80059B3C 9C002935 */  ori        $t1, $t1, %lo(MRVp_work_ot)
/* 4A340 80059B40 8E004A35 */  ori        $t2, $t2, %lo(MRVp_ot_size)
/* 4A344 80059B44 8C006B35 */  ori        $t3, $t3, %lo(MRVp_otz_shift)
/* 4A348 80059B48 80008C35 */  ori        $t4, $t4, %lo(MRTemp_svec)
/* 4A34C 80059B4C 0000298D */  lw         $t1, 0x0($t1)
/* 4A350 80059B50 00004A85 */  lh         $t2, 0x0($t2)
/* 4A354 80059B54 00006B85 */  lh         $t3, 0x0($t3)
/* 4A358 80059B58 4800A9AF */  sw         $t1, 0x48($sp)
/* 4A35C 80059B5C 4C00AAAF */  sw         $t2, 0x4C($sp)
/* 4A360 80059B60 5000ABAF */  sw         $t3, 0x50($sp)
/* 4A364 80059B64 5C00ACAF */  sw         $t4, 0x5C($sp)
/* 4A368 80059B68 0C00A98C */  lw         $t1, 0xC($a1)
/* 4A36C 80059B6C 00000000 */  nop
/* 4A370 80059B70 04002931 */  andi       $t1, $t1, 0x4
/* 4A374 80059B74 0F002011 */  beqz       $t1, .L80059BB4
/* 4A378 80059B78 20380000 */   add       $a3, $zero, $zero # handwritten instruction
/* 4A37C 80059B7C 8000083C */  lui        $t0, 0x80
/* 4A380 80059B80 0B80093C */  lui        $t1, %hi(Map_light_min_r2)
/* 4A384 80059B84 F8392935 */  ori        $t1, $t1, %lo(Map_light_min_r2)
/* 4A388 80059B88 00002A8D */  lw         $t2, 0x0($t1)
/* 4A38C 80059B8C 0B80093C */  lui        $t1, %hi(Map_light_max_r2)
/* 4A390 80059B90 FC392935 */  ori        $t1, $t1, %lo(Map_light_max_r2)
/* 4A394 80059B94 00002B8D */  lw         $t3, 0x0($t1)
/* 4A398 80059B98 4000AAAF */  sw         $t2, 0x40($sp)
/* 4A39C 80059B9C 4400ABAF */  sw         $t3, 0x44($sp)
/* 4A3A0 80059BA0 22486A01 */  sub        $t1, $t3, $t2 # handwritten instruction
/* 4A3A4 80059BA4 1B000901 */  divu       $zero, $t0, $t1
/* 4A3A8 80059BA8 00000000 */  nop
/* 4A3AC 80059BAC 12400000 */  mflo       $t0
/* 4A3B0 80059BB0 3C00A8AF */  sw         $t0, 0x3C($sp)
.L80059BB4:
/* 4A3B4 80059BB4 0000848C */  lw         $a0, 0x0($a0)
/* 4A3B8 80059BB8 801F083C */  lui        $t0, (0x1F800004 >> 16)
/* 4A3BC 80059BBC 69018010 */  beqz       $a0, .L8005A164
/* 4A3C0 80059BC0 04000835 */   ori       $t0, $t0, (0x1F800004 & 0xFFFF)
/* 4A3C4 80059BC4 0000098D */  lw         $t1, 0x0($t0)
/* 4A3C8 80059BC8 10008A20 */  addi       $t2, $a0, 0x10 # handwritten instruction
/* 4A3CC 80059BCC 80480900 */  sll        $t1, $t1, 2
/* 4A3D0 80059BD0 20504901 */  add        $t2, $t2, $t1 # handwritten instruction
/* 4A3D4 80059BD4 0000468D */  lw         $a2, 0x0($t2)
/* 4A3D8 80059BD8 0800838C */  lw         $v1, 0x8($a0)
/* 4A3DC 80059BDC 0C00828C */  lw         $v0, 0xC($a0)
/* 4A3E0 80059BE0 F4FF6010 */  beqz       $v1, .L80059BB4
/* 4A3E4 80059BE4 00000000 */   nop
/* 4A3E8 80059BE8 1000B08C */  lw         $s0, 0x10($a1)
/* 4A3EC 80059BEC 0800A88C */  lw         $t0, 0x8($a1)
/* 4A3F0 80059BF0 21800602 */  addu       $s0, $s0, $a2
/* 4A3F4 80059BF4 20880802 */  add        $s1, $s0, $t0 # handwritten instruction
/* 4A3F8 80059BF8 20902802 */  add        $s2, $s1, $t0 # handwritten instruction
/* 4A3FC 80059BFC 20984802 */  add        $s3, $s2, $t0 # handwritten instruction
/* 4A400 80059C00 00005494 */  lhu        $s4, 0x0($v0)
/* 4A404 80059C04 02005594 */  lhu        $s5, 0x2($v0)
/* 4A408 80059C08 04005694 */  lhu        $s6, 0x4($v0)
/* 4A40C 80059C0C 06005794 */  lhu        $s7, 0x6($v0)
/* 4A410 80059C10 C0A01400 */  sll        $s4, $s4, 3
/* 4A414 80059C14 C0A81500 */  sll        $s5, $s5, 3
/* 4A418 80059C18 C0B01600 */  sll        $s6, $s6, 3
/* 4A41C 80059C1C C0B81700 */  sll        $s7, $s7, 3
/* 4A420 80059C20 20A0D403 */  add        $s4, $fp, $s4 # handwritten instruction
/* 4A424 80059C24 20A8D503 */  add        $s5, $fp, $s5 # handwritten instruction
/* 4A428 80059C28 20B0D603 */  add        $s6, $fp, $s6 # handwritten instruction
/* 4A42C 80059C2C 20B8D703 */  add        $s7, $fp, $s7 # handwritten instruction
.L80059C30:
/* 4A430 80059C30 0C00A88C */  lw         $t0, 0xC($a1)
/* 4A434 80059C34 00000000 */  nop
/* 4A438 80059C38 04000931 */  andi       $t1, $t0, 0x4
/* 4A43C 80059C3C BC002011 */  beqz       $t1, .L80059F30
/* 4A440 80059C40 00000000 */   nop
/* 4A444 80059C44 1400AB84 */  lh         $t3, 0x14($a1)
/* 4A448 80059C48 1600AC84 */  lh         $t4, 0x16($a1)
/* 4A44C 80059C4C 1800AD84 */  lh         $t5, 0x18($a1)
/* 4A450 80059C50 00008886 */  lh         $t0, 0x0($s4)
/* 4A454 80059C54 02008986 */  lh         $t1, 0x2($s4)
/* 4A458 80059C58 04008A86 */  lh         $t2, 0x4($s4)
/* 4A45C 80059C5C 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4A460 80059C60 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4A464 80059C64 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4A468 80059C68 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4A46C 80059C6C 004C0900 */  sll        $t1, $t1, 16
/* 4A470 80059C70 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4A474 80059C74 25400901 */  or         $t0, $t0, $t1
/* 4A478 80059C78 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4A47C 80059C7C 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4A480 80059C80 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4A484 80059C84 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4A488 80059C88 00000000 */  nop
/* 4A48C 80059C8C 00000000 */  nop
/* 4A490 80059C90 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4A494 80059C94 4000A98F */  lw         $t1, 0x40($sp)
/* 4A498 80059C98 4400AA8F */  lw         $t2, 0x44($sp)
/* 4A49C 80059C9C 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4A4A0 80059CA0 00000000 */  nop
/* 4A4A4 80059CA4 2A080901 */  slt        $at, $t0, $t1
/* 4A4A8 80059CA8 03002010 */  beqz       $at, .L80059CB8
/* 4A4AC 80059CAC 80000E3C */   lui       $t6, (0x808080 >> 16)
/* 4A4B0 80059CB0 13000010 */  b          .L80059D00
/* 4A4B4 80059CB4 8080CE35 */   ori       $t6, $t6, (0x808080 & 0xFFFF)
.L80059CB8:
/* 4A4B8 80059CB8 2A080A01 */  slt        $at, $t0, $t2
/* 4A4BC 80059CBC 03002014 */  bnez       $at, .L80059CCC
/* 4A4C0 80059CC0 20700000 */   add       $t6, $zero, $zero # handwritten instruction
/* 4A4C4 80059CC4 0E000010 */  b          .L80059D00
/* 4A4C8 80059CC8 00000000 */   nop
.L80059CCC:
/* 4A4CC 80059CCC 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4A4D0 80059CD0 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4A4D4 80059CD4 80000934 */  ori        $t1, $zero, 0x80
/* 4A4D8 80059CD8 18000A01 */  mult       $t0, $t2
/* 4A4DC 80059CDC 00000000 */  nop
/* 4A4E0 80059CE0 12400000 */  mflo       $t0
/* 4A4E4 80059CE4 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4A4E8 80059CE8 03440800 */  sra        $t0, $t0, 16
/* 4A4EC 80059CEC 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4A4F0 80059CF0 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4A4F4 80059CF4 18002A01 */  mult       $t1, $t2
/* 4A4F8 80059CF8 00000000 */  nop
/* 4A4FC 80059CFC 12700000 */  mflo       $t6
.L80059D00:
/* 4A500 80059D00 0000A886 */  lh         $t0, 0x0($s5)
/* 4A504 80059D04 0200A986 */  lh         $t1, 0x2($s5)
/* 4A508 80059D08 0400AA86 */  lh         $t2, 0x4($s5)
/* 4A50C 80059D0C 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4A510 80059D10 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4A514 80059D14 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4A518 80059D18 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4A51C 80059D1C 004C0900 */  sll        $t1, $t1, 16
/* 4A520 80059D20 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4A524 80059D24 25400901 */  or         $t0, $t0, $t1
/* 4A528 80059D28 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4A52C 80059D2C 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4A530 80059D30 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4A534 80059D34 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4A538 80059D38 00000000 */  nop
/* 4A53C 80059D3C 00000000 */  nop
/* 4A540 80059D40 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4A544 80059D44 4000A98F */  lw         $t1, 0x40($sp)
/* 4A548 80059D48 4400AA8F */  lw         $t2, 0x44($sp)
/* 4A54C 80059D4C 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4A550 80059D50 00000000 */  nop
/* 4A554 80059D54 2A080901 */  slt        $at, $t0, $t1
/* 4A558 80059D58 03002010 */  beqz       $at, .L80059D68
/* 4A55C 80059D5C 80000F3C */   lui       $t7, (0x808080 >> 16)
/* 4A560 80059D60 13000010 */  b          .L80059DB0
/* 4A564 80059D64 8080EF35 */   ori       $t7, $t7, (0x808080 & 0xFFFF)
.L80059D68:
/* 4A568 80059D68 2A080A01 */  slt        $at, $t0, $t2
/* 4A56C 80059D6C 03002014 */  bnez       $at, .L80059D7C
/* 4A570 80059D70 20780000 */   add       $t7, $zero, $zero # handwritten instruction
/* 4A574 80059D74 0E000010 */  b          .L80059DB0
/* 4A578 80059D78 00000000 */   nop
.L80059D7C:
/* 4A57C 80059D7C 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4A580 80059D80 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4A584 80059D84 80000934 */  ori        $t1, $zero, 0x80
/* 4A588 80059D88 18000A01 */  mult       $t0, $t2
/* 4A58C 80059D8C 00000000 */  nop
/* 4A590 80059D90 12400000 */  mflo       $t0
/* 4A594 80059D94 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4A598 80059D98 03440800 */  sra        $t0, $t0, 16
/* 4A59C 80059D9C 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4A5A0 80059DA0 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4A5A4 80059DA4 18002A01 */  mult       $t1, $t2
/* 4A5A8 80059DA8 00000000 */  nop
/* 4A5AC 80059DAC 12780000 */  mflo       $t7
.L80059DB0:
/* 4A5B0 80059DB0 0000C886 */  lh         $t0, 0x0($s6)
/* 4A5B4 80059DB4 0200C986 */  lh         $t1, 0x2($s6)
/* 4A5B8 80059DB8 0400CA86 */  lh         $t2, 0x4($s6)
/* 4A5BC 80059DBC 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4A5C0 80059DC0 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4A5C4 80059DC4 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4A5C8 80059DC8 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4A5CC 80059DCC 004C0900 */  sll        $t1, $t1, 16
/* 4A5D0 80059DD0 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4A5D4 80059DD4 25400901 */  or         $t0, $t0, $t1
/* 4A5D8 80059DD8 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4A5DC 80059DDC 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4A5E0 80059DE0 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4A5E4 80059DE4 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4A5E8 80059DE8 00000000 */  nop
/* 4A5EC 80059DEC 00000000 */  nop
/* 4A5F0 80059DF0 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4A5F4 80059DF4 4000A98F */  lw         $t1, 0x40($sp)
/* 4A5F8 80059DF8 4400AA8F */  lw         $t2, 0x44($sp)
/* 4A5FC 80059DFC 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4A600 80059E00 00000000 */  nop
/* 4A604 80059E04 2A080901 */  slt        $at, $t0, $t1
/* 4A608 80059E08 03002010 */  beqz       $at, .L80059E18
/* 4A60C 80059E0C 8000183C */   lui       $t8, (0x808080 >> 16)
/* 4A610 80059E10 13000010 */  b          .L80059E60
/* 4A614 80059E14 80801837 */   ori       $t8, $t8, (0x808080 & 0xFFFF)
.L80059E18:
/* 4A618 80059E18 2A080A01 */  slt        $at, $t0, $t2
/* 4A61C 80059E1C 03002014 */  bnez       $at, .L80059E2C
/* 4A620 80059E20 20C00000 */   add       $t8, $zero, $zero # handwritten instruction
/* 4A624 80059E24 0E000010 */  b          .L80059E60
/* 4A628 80059E28 00000000 */   nop
.L80059E2C:
/* 4A62C 80059E2C 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4A630 80059E30 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4A634 80059E34 80000934 */  ori        $t1, $zero, 0x80
/* 4A638 80059E38 18000A01 */  mult       $t0, $t2
/* 4A63C 80059E3C 00000000 */  nop
/* 4A640 80059E40 12400000 */  mflo       $t0
/* 4A644 80059E44 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4A648 80059E48 03440800 */  sra        $t0, $t0, 16
/* 4A64C 80059E4C 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4A650 80059E50 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4A654 80059E54 18002A01 */  mult       $t1, $t2
/* 4A658 80059E58 00000000 */  nop
/* 4A65C 80059E5C 12C00000 */  mflo       $t8
.L80059E60:
/* 4A660 80059E60 0000E886 */  lh         $t0, 0x0($s7)
/* 4A664 80059E64 0200E986 */  lh         $t1, 0x2($s7)
/* 4A668 80059E68 0400EA86 */  lh         $t2, 0x4($s7)
/* 4A66C 80059E6C 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4A670 80059E70 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4A674 80059E74 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4A678 80059E78 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4A67C 80059E7C 004C0900 */  sll        $t1, $t1, 16
/* 4A680 80059E80 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4A684 80059E84 25400901 */  or         $t0, $t0, $t1
/* 4A688 80059E88 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4A68C 80059E8C 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4A690 80059E90 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4A694 80059E94 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4A698 80059E98 00000000 */  nop
/* 4A69C 80059E9C 00000000 */  nop
/* 4A6A0 80059EA0 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4A6A4 80059EA4 4000A98F */  lw         $t1, 0x40($sp)
/* 4A6A8 80059EA8 4400AA8F */  lw         $t2, 0x44($sp)
/* 4A6AC 80059EAC 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4A6B0 80059EB0 00000000 */  nop
/* 4A6B4 80059EB4 2A080901 */  slt        $at, $t0, $t1
/* 4A6B8 80059EB8 03002010 */  beqz       $at, .L80059EC8
/* 4A6BC 80059EBC 8000193C */   lui       $t9, (0x808080 >> 16)
/* 4A6C0 80059EC0 13000010 */  b          .L80059F10
/* 4A6C4 80059EC4 80803937 */   ori       $t9, $t9, (0x808080 & 0xFFFF)
.L80059EC8:
/* 4A6C8 80059EC8 2A080A01 */  slt        $at, $t0, $t2
/* 4A6CC 80059ECC 03002014 */  bnez       $at, .L80059EDC
/* 4A6D0 80059ED0 20C80000 */   add       $t9, $zero, $zero # handwritten instruction
/* 4A6D4 80059ED4 0E000010 */  b          .L80059F10
/* 4A6D8 80059ED8 00000000 */   nop
.L80059EDC:
/* 4A6DC 80059EDC 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4A6E0 80059EE0 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4A6E4 80059EE4 80000934 */  ori        $t1, $zero, 0x80
/* 4A6E8 80059EE8 18000A01 */  mult       $t0, $t2
/* 4A6EC 80059EEC 00000000 */  nop
/* 4A6F0 80059EF0 12400000 */  mflo       $t0
/* 4A6F4 80059EF4 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4A6F8 80059EF8 03440800 */  sra        $t0, $t0, 16
/* 4A6FC 80059EFC 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4A700 80059F00 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4A704 80059F04 18002A01 */  mult       $t1, $t2
/* 4A708 80059F08 00000000 */  nop
/* 4A70C 80059F0C 12C80000 */  mflo       $t9
.L80059F10:
/* 4A710 80059F10 FCFF0EA2 */  sb         $t6, -0x4($s0)
/* 4A714 80059F14 03720E00 */  sra        $t6, $t6, 8
/* 4A718 80059F18 FCFF2FAE */  sw         $t7, -0x4($s1)
/* 4A71C 80059F1C FDFF0EA2 */  sb         $t6, -0x3($s0)
/* 4A720 80059F20 03720E00 */  sra        $t6, $t6, 8
/* 4A724 80059F24 FCFF58AE */  sw         $t8, -0x4($s2)
/* 4A728 80059F28 FEFF0EA2 */  sb         $t6, -0x2($s0)
/* 4A72C 80059F2C FCFF79AE */  sw         $t9, -0x4($s3)
.L80059F30:
/* 4A730 80059F30 0C00A88C */  lw         $t0, 0xC($a1)
/* 4A734 80059F34 20380000 */  add        $a3, $zero, $zero # handwritten instruction
/* 4A738 80059F38 01000831 */  andi       $t0, $t0, 0x1
/* 4A73C 80059F3C 43000011 */  beqz       $t0, .L8005A04C
/* 4A740 80059F40 08004994 */   lhu       $t1, 0x8($v0)
/* 4A744 80059F44 00000000 */  nop
/* 4A748 80059F48 02002A31 */  andi       $t2, $t1, 0x2
/* 4A74C 80059F4C 2F004011 */  beqz       $t2, .L8005A00C
/* 4A750 80059F50 5C00A88F */   lw        $t0, 0x5C($sp)
/* 4A754 80059F54 00000000 */  nop
/* 4A758 80059F58 00000B85 */  lh         $t3, 0x0($t0)
/* 4A75C 80059F5C 04000D85 */  lh         $t5, 0x4($t0)
/* 4A760 80059F60 00008A86 */  lh         $t2, 0x0($s4)
/* 4A764 80059F64 04008C86 */  lh         $t4, 0x4($s4)
/* 4A768 80059F68 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4A76C 80059F6C 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4A770 80059F70 43510A00 */  sra        $t2, $t2, 5
/* 4A774 80059F74 43610C00 */  sra        $t4, $t4, 5
/* 4A778 80059F78 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4A77C 80059F7C 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4A780 80059F80 04000AA2 */  sb         $t2, 0x4($s0)
/* 4A784 80059F84 05000CA2 */  sb         $t4, 0x5($s0)
/* 4A788 80059F88 0000AA86 */  lh         $t2, 0x0($s5)
/* 4A78C 80059F8C 0400AC86 */  lh         $t4, 0x4($s5)
/* 4A790 80059F90 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4A794 80059F94 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4A798 80059F98 43510A00 */  sra        $t2, $t2, 5
/* 4A79C 80059F9C 43610C00 */  sra        $t4, $t4, 5
/* 4A7A0 80059FA0 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4A7A4 80059FA4 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4A7A8 80059FA8 04002AA2 */  sb         $t2, 0x4($s1)
/* 4A7AC 80059FAC 05002CA2 */  sb         $t4, 0x5($s1)
/* 4A7B0 80059FB0 0000CA86 */  lh         $t2, 0x0($s6)
/* 4A7B4 80059FB4 0400CC86 */  lh         $t4, 0x4($s6)
/* 4A7B8 80059FB8 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4A7BC 80059FBC 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4A7C0 80059FC0 43510A00 */  sra        $t2, $t2, 5
/* 4A7C4 80059FC4 43610C00 */  sra        $t4, $t4, 5
/* 4A7C8 80059FC8 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4A7CC 80059FCC 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4A7D0 80059FD0 04004AA2 */  sb         $t2, 0x4($s2)
/* 4A7D4 80059FD4 05004CA2 */  sb         $t4, 0x5($s2)
/* 4A7D8 80059FD8 0000EA86 */  lh         $t2, 0x0($s7)
/* 4A7DC 80059FDC 0400EC86 */  lh         $t4, 0x4($s7)
/* 4A7E0 80059FE0 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4A7E4 80059FE4 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4A7E8 80059FE8 43510A00 */  sra        $t2, $t2, 5
/* 4A7EC 80059FEC 43610C00 */  sra        $t4, $t4, 5
/* 4A7F0 80059FF0 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4A7F4 80059FF4 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4A7F8 80059FF8 04006AA2 */  sb         $t2, 0x4($s3)
/* 4A7FC 80059FFC 05006CA2 */  sb         $t4, 0x5($s3)
/* 4A800 8005A000 4C00AB8F */  lw         $t3, 0x4C($sp)
/* 4A804 8005A004 06000010 */  b          .L8005A020
/* 4A808 8005A008 FEFF6721 */   addi      $a3, $t3, -0x2 # handwritten instruction
.L8005A00C:
/* 4A80C 8005A00C 04002A31 */  andi       $t2, $t1, 0x4
/* 4A810 8005A010 03004011 */  beqz       $t2, .L8005A020
/* 4A814 8005A014 4C00AB8F */   lw        $t3, 0x4C($sp)
/* 4A818 8005A018 00000000 */  nop
/* 4A81C 8005A01C FFFF6721 */  addi       $a3, $t3, -0x1 # handwritten instruction
.L8005A020:
/* 4A820 8005A020 18002A31 */  andi       $t2, $t1, 0x18
/* 4A824 8005A024 09004011 */  beqz       $t2, .L8005A04C
/* 4A828 8005A028 00000000 */   nop
/* 4A82C 8005A02C 0C00488C */  lw         $t0, 0xC($v0)
/* 4A830 8005A030 1000498C */  lw         $t1, 0x10($v0)
/* 4A834 8005A034 14004A94 */  lhu        $t2, 0x14($v0)
/* 4A838 8005A038 16004B94 */  lhu        $t3, 0x16($v0)
/* 4A83C 8005A03C 040008AE */  sw         $t0, 0x4($s0)
/* 4A840 8005A040 040029AE */  sw         $t1, 0x4($s1)
/* 4A844 8005A044 04004AA6 */  sh         $t2, 0x4($s2)
/* 4A848 8005A048 04006BA6 */  sh         $t3, 0x4($s3)
.L8005A04C:
/* 4A84C 8005A04C 000080CA */  lwc2       $0, 0x0($s4)
/* 4A850 8005A050 040081CA */  lwc2       $1, 0x4($s4)
/* 4A854 8005A054 0000A2CA */  lwc2       $2, 0x0($s5)
/* 4A858 8005A058 0400A3CA */  lwc2       $3, 0x4($s5)
/* 4A85C 8005A05C 0000C4CA */  lwc2       $4, 0x0($s6)
/* 4A860 8005A060 0400C5CA */  lwc2       $5, 0x4($s6)
/* 4A864 8005A064 0000A88C */  lw         $t0, 0x0($a1)
/* 4A868 8005A068 00000000 */  nop
/* 4A86C 8005A06C 3000284A */  RTPT
/* 4A870 8005A070 20104800 */  add        $v0, $v0, $t0 # handwritten instruction
/* 4A874 8005A074 00005494 */  lhu        $s4, 0x0($v0)
/* 4A878 8005A078 02005594 */  lhu        $s5, 0x2($v0)
/* 4A87C 8005A07C 04005694 */  lhu        $s6, 0x4($v0)
/* 4A880 8005A080 C0A01400 */  sll        $s4, $s4, 3
/* 4A884 8005A084 C0A81500 */  sll        $s5, $s5, 3
/* 4A888 8005A088 C0B01600 */  sll        $s6, $s6, 3
/* 4A88C 8005A08C 20A0D403 */  add        $s4, $fp, $s4 # handwritten instruction
/* 4A890 8005A090 20A8D503 */  add        $s5, $fp, $s5 # handwritten instruction
/* 4A894 8005A094 20B0D603 */  add        $s6, $fp, $s6 # handwritten instruction
/* 4A898 8005A098 0600404B */  NCLIP
/* 4A89C 8005A09C 0000E0CA */  lwc2       $0, 0x0($s7)
/* 4A8A0 8005A0A0 0400E1CA */  lwc2       $1, 0x4($s7)
/* 4A8A4 8005A0A4 00C00848 */  mfc2       $t0, $24 # handwritten instruction
/* 4A8A8 8005A0A8 00000CEA */  swc2       $12, 0x0($s0)
/* 4A8AC 8005A0AC 0100184A */  RTPS
/* 4A8B0 8005A0B0 06005794 */  lhu        $s7, 0x6($v0)
/* 4A8B4 8005A0B4 00000000 */  nop
/* 4A8B8 8005A0B8 C0B81700 */  sll        $s7, $s7, 3
/* 4A8BC 8005A0BC 0600001D */  bgtz       $t0, .L8005A0D8
/* 4A8C0 8005A0C0 20B8D703 */   add       $s7, $fp, $s7 # handwritten instruction
/* 4A8C4 8005A0C4 0600404B */  NCLIP
/* 4A8C8 8005A0C8 00C00848 */  mfc2       $t0, $24 # handwritten instruction
/* 4A8CC 8005A0CC 00000000 */  nop
/* 4A8D0 8005A0D0 1A000105 */  bgez       $t0, .L8005A13C
/* 4A8D4 8005A0D4 00000000 */   nop
.L8005A0D8:
/* 4A8D8 8005A0D8 00002CEA */  swc2       $12, 0x0($s1)
/* 4A8DC 8005A0DC 00004DEA */  swc2       $13, 0x0($s2)
/* 4A8E0 8005A0E0 00006EEA */  swc2       $14, 0x0($s3)
/* 4A8E4 8005A0E4 0B000714 */  bne        $zero, $a3, .L8005A114
/* 4A8E8 8005A0E8 10000A34 */   ori       $t2, $zero, 0x10
/* 4A8EC 8005A0EC 2E00684B */  AVSZ4
/* 4A8F0 8005A0F0 00380748 */  mfc2       $a3, $7 # handwritten instruction
/* 4A8F4 8005A0F4 5000A98F */  lw         $t1, 0x50($sp)
/* 4A8F8 8005A0F8 2A084701 */  slt        $at, $t2, $a3
/* 4A8FC 8005A0FC 0F002010 */  beqz       $at, .L8005A13C
/* 4A900 8005A100 4C00A88F */   lw        $t0, 0x4C($sp)
/* 4A904 8005A104 07382701 */  srav       $a3, $a3, $t1
/* 4A908 8005A108 4000E720 */  addi       $a3, $a3, 0x40 # handwritten instruction
/* 4A90C 8005A10C 2A08E800 */  slt        $at, $a3, $t0
/* 4A910 8005A110 0A002010 */  beqz       $at, .L8005A13C
.L8005A114:
/* 4A914 8005A114 5800AA8F */   lw        $t2, 0x58($sp)
/* 4A918 8005A118 5400A98F */  lw         $t1, 0x54($sp)
/* 4A91C 8005A11C 4800A88F */  lw         $t0, 0x48($sp)
/* 4A920 8005A120 24C8C900 */  and        $t9, $a2, $t1
/* 4A924 8005A124 80380700 */  sll        $a3, $a3, 2
/* 4A928 8005A128 2038E800 */  add        $a3, $a3, $t0 # handwritten instruction
/* 4A92C 8005A12C 0000E18C */  lw         $at, 0x0($a3)
/* 4A930 8005A130 0000F9AC */  sw         $t9, 0x0($a3)
/* 4A934 8005A134 25082A00 */  or         $at, $at, $t2
/* 4A938 8005A138 000021AF */  sw         $at, 0x0($t9)
.L8005A13C:
/* 4A93C 8005A13C 0400A88C */  lw         $t0, 0x4($a1)
/* 4A940 8005A140 FFFF6320 */  addi       $v1, $v1, -0x1 # handwritten instruction
/* 4A944 8005A144 20800802 */  add        $s0, $s0, $t0 # handwritten instruction
/* 4A948 8005A148 20882802 */  add        $s1, $s1, $t0 # handwritten instruction
/* 4A94C 8005A14C 20904802 */  add        $s2, $s2, $t0 # handwritten instruction
/* 4A950 8005A150 20986802 */  add        $s3, $s3, $t0 # handwritten instruction
/* 4A954 8005A154 B6FE601C */  bgtz       $v1, .L80059C30
/* 4A958 8005A158 2030C800 */   add       $a2, $a2, $t0 # handwritten instruction
/* 4A95C 8005A15C 95FE0010 */  b          .L80059BB4
/* 4A960 8005A160 00000000 */   nop
.L8005A164:
/* 4A964 8005A164 1000B08F */  lw         $s0, 0x10($sp)
/* 4A968 8005A168 1400B18F */  lw         $s1, 0x14($sp)
/* 4A96C 8005A16C 1800B28F */  lw         $s2, 0x18($sp)
/* 4A970 8005A170 1C00B38F */  lw         $s3, 0x1C($sp)
/* 4A974 8005A174 2000B48F */  lw         $s4, 0x20($sp)
/* 4A978 8005A178 2400B58F */  lw         $s5, 0x24($sp)
/* 4A97C 8005A17C 2800B68F */  lw         $s6, 0x28($sp)
/* 4A980 8005A180 2C00B78F */  lw         $s7, 0x2C($sp)
/* 4A984 8005A184 3000BE8F */  lw         $fp, 0x30($sp)
/* 4A988 8005A188 0800E003 */  jr         $ra
/* 4A98C 8005A18C 6000BD27 */   addiu     $sp, $sp, 0x60

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MapRenderTrisASM
/* 4A990 8005A190 A0FFBD27 */  addiu      $sp, $sp, -0x60
/* 4A994 8005A194 1000B0AF */  sw         $s0, 0x10($sp)
/* 4A998 8005A198 1400B1AF */  sw         $s1, 0x14($sp)
/* 4A99C 8005A19C 1800B2AF */  sw         $s2, 0x18($sp)
/* 4A9A0 8005A1A0 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 4A9A4 8005A1A4 2000B4AF */  sw         $s4, 0x20($sp)
/* 4A9A8 8005A1A8 2400B5AF */  sw         $s5, 0x24($sp)
/* 4A9AC 8005A1AC 2800B6AF */  sw         $s6, 0x28($sp)
/* 4A9B0 8005A1B0 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 4A9B4 8005A1B4 3000BEAF */  sw         $fp, 0x30($sp)
/* 4A9B8 8005A1B8 0400A88C */  lw         $t0, 0x4($a1)
/* 4A9BC 8005A1BC FF00093C */  lui        $t1, (0xFFFFFF >> 16)
/* 4A9C0 8005A1C0 83400800 */  sra        $t0, $t0, 2
/* 4A9C4 8005A1C4 FFFF2935 */  ori        $t1, $t1, (0xFFFFFF & 0xFFFF)
/* 4A9C8 8005A1C8 FFFF0825 */  addiu      $t0, $t0, -0x1
/* 4A9CC 8005A1CC 00460800 */  sll        $t0, $t0, 24
/* 4A9D0 8005A1D0 5400A9AF */  sw         $t1, 0x54($sp)
/* 4A9D4 8005A1D4 5800A8AF */  sw         $t0, 0x58($sp)
/* 4A9D8 8005A1D8 0B801E3C */  lui        $fp, %hi(Map_vertices)
/* 4A9DC 8005A1DC A03BDE37 */  ori        $fp, $fp, %lo(Map_vertices)
/* 4A9E0 8005A1E0 0000DE8F */  lw         $fp, 0x0($fp)
/* 4A9E4 8005A1E4 801F093C */  lui        $t1, %hi(MRVp_work_ot)
/* 4A9E8 8005A1E8 801F0A3C */  lui        $t2, %hi(MRVp_ot_size)
/* 4A9EC 8005A1EC 801F0B3C */  lui        $t3, %hi(MRVp_otz_shift)
/* 4A9F0 8005A1F0 801F0C3C */  lui        $t4, %hi(MRTemp_svec)
/* 4A9F4 8005A1F4 9C002935 */  ori        $t1, $t1, %lo(MRVp_work_ot)
/* 4A9F8 8005A1F8 8E004A35 */  ori        $t2, $t2, %lo(MRVp_ot_size)
/* 4A9FC 8005A1FC 8C006B35 */  ori        $t3, $t3, %lo(MRVp_otz_shift)
/* 4AA00 8005A200 80008C35 */  ori        $t4, $t4, %lo(MRTemp_svec)
/* 4AA04 8005A204 0000298D */  lw         $t1, 0x0($t1)
/* 4AA08 8005A208 00004A85 */  lh         $t2, 0x0($t2)
/* 4AA0C 8005A20C 00006B85 */  lh         $t3, 0x0($t3)
/* 4AA10 8005A210 4800A9AF */  sw         $t1, 0x48($sp)
/* 4AA14 8005A214 4C00AAAF */  sw         $t2, 0x4C($sp)
/* 4AA18 8005A218 5000ABAF */  sw         $t3, 0x50($sp)
/* 4AA1C 8005A21C 5C00ACAF */  sw         $t4, 0x5C($sp)
/* 4AA20 8005A220 0C00A98C */  lw         $t1, 0xC($a1)
/* 4AA24 8005A224 00000000 */  nop
/* 4AA28 8005A228 04002931 */  andi       $t1, $t1, 0x4
/* 4AA2C 8005A22C 0F002011 */  beqz       $t1, .L8005A26C
/* 4AA30 8005A230 20380000 */   add       $a3, $zero, $zero # handwritten instruction
/* 4AA34 8005A234 8000083C */  lui        $t0, 0x80
/* 4AA38 8005A238 0B80093C */  lui        $t1, %hi(Map_light_min_r2)
/* 4AA3C 8005A23C F8392935 */  ori        $t1, $t1, %lo(Map_light_min_r2)
/* 4AA40 8005A240 00002A8D */  lw         $t2, 0x0($t1)
/* 4AA44 8005A244 0B80093C */  lui        $t1, %hi(Map_light_max_r2)
/* 4AA48 8005A248 FC392935 */  ori        $t1, $t1, %lo(Map_light_max_r2)
/* 4AA4C 8005A24C 00002B8D */  lw         $t3, 0x0($t1)
/* 4AA50 8005A250 4000AAAF */  sw         $t2, 0x40($sp)
/* 4AA54 8005A254 4400ABAF */  sw         $t3, 0x44($sp)
/* 4AA58 8005A258 22486A01 */  sub        $t1, $t3, $t2 # handwritten instruction
/* 4AA5C 8005A25C 1B000901 */  divu       $zero, $t0, $t1
/* 4AA60 8005A260 00000000 */  nop
/* 4AA64 8005A264 12400000 */  mflo       $t0
/* 4AA68 8005A268 3C00A8AF */  sw         $t0, 0x3C($sp)
.L8005A26C:
/* 4AA6C 8005A26C 0000848C */  lw         $a0, 0x0($a0)
/* 4AA70 8005A270 801F083C */  lui        $t0, (0x1F800004 >> 16)
/* 4AA74 8005A274 20018010 */  beqz       $a0, .L8005A6F8
/* 4AA78 8005A278 04000835 */   ori       $t0, $t0, (0x1F800004 & 0xFFFF)
/* 4AA7C 8005A27C 0000098D */  lw         $t1, 0x0($t0)
/* 4AA80 8005A280 10008A20 */  addi       $t2, $a0, 0x10 # handwritten instruction
/* 4AA84 8005A284 80480900 */  sll        $t1, $t1, 2
/* 4AA88 8005A288 20504901 */  add        $t2, $t2, $t1 # handwritten instruction
/* 4AA8C 8005A28C 0000468D */  lw         $a2, 0x0($t2)
/* 4AA90 8005A290 0800838C */  lw         $v1, 0x8($a0)
/* 4AA94 8005A294 0C00828C */  lw         $v0, 0xC($a0)
/* 4AA98 8005A298 F4FF6010 */  beqz       $v1, .L8005A26C
/* 4AA9C 8005A29C 00000000 */   nop
/* 4AAA0 8005A2A0 1000B08C */  lw         $s0, 0x10($a1)
/* 4AAA4 8005A2A4 0800A88C */  lw         $t0, 0x8($a1)
/* 4AAA8 8005A2A8 21800602 */  addu       $s0, $s0, $a2
/* 4AAAC 8005A2AC 20880802 */  add        $s1, $s0, $t0 # handwritten instruction
/* 4AAB0 8005A2B0 20902802 */  add        $s2, $s1, $t0 # handwritten instruction
/* 4AAB4 8005A2B4 00005494 */  lhu        $s4, 0x0($v0)
/* 4AAB8 8005A2B8 02005594 */  lhu        $s5, 0x2($v0)
/* 4AABC 8005A2BC 04005694 */  lhu        $s6, 0x4($v0)
/* 4AAC0 8005A2C0 C0A01400 */  sll        $s4, $s4, 3
/* 4AAC4 8005A2C4 C0A81500 */  sll        $s5, $s5, 3
/* 4AAC8 8005A2C8 C0B01600 */  sll        $s6, $s6, 3
/* 4AACC 8005A2CC 20A0D403 */  add        $s4, $fp, $s4 # handwritten instruction
/* 4AAD0 8005A2D0 20A8D503 */  add        $s5, $fp, $s5 # handwritten instruction
/* 4AAD4 8005A2D4 20B0D603 */  add        $s6, $fp, $s6 # handwritten instruction
.L8005A2D8:
/* 4AAD8 8005A2D8 0C00A88C */  lw         $t0, 0xC($a1)
/* 4AADC 8005A2DC 00000000 */  nop
/* 4AAE0 8005A2E0 04000931 */  andi       $t1, $t0, 0x4
/* 4AAE4 8005A2E4 8F002011 */  beqz       $t1, .L8005A524
/* 4AAE8 8005A2E8 00000000 */   nop
/* 4AAEC 8005A2EC 1400AB84 */  lh         $t3, 0x14($a1)
/* 4AAF0 8005A2F0 1600AC84 */  lh         $t4, 0x16($a1)
/* 4AAF4 8005A2F4 1800AD84 */  lh         $t5, 0x18($a1)
/* 4AAF8 8005A2F8 00008886 */  lh         $t0, 0x0($s4)
/* 4AAFC 8005A2FC 02008986 */  lh         $t1, 0x2($s4)
/* 4AB00 8005A300 04008A86 */  lh         $t2, 0x4($s4)
/* 4AB04 8005A304 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4AB08 8005A308 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4AB0C 8005A30C 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4AB10 8005A310 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4AB14 8005A314 004C0900 */  sll        $t1, $t1, 16
/* 4AB18 8005A318 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4AB1C 8005A31C 25400901 */  or         $t0, $t0, $t1
/* 4AB20 8005A320 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4AB24 8005A324 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4AB28 8005A328 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4AB2C 8005A32C 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4AB30 8005A330 00000000 */  nop
/* 4AB34 8005A334 00000000 */  nop
/* 4AB38 8005A338 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4AB3C 8005A33C 4000A98F */  lw         $t1, 0x40($sp)
/* 4AB40 8005A340 4400AA8F */  lw         $t2, 0x44($sp)
/* 4AB44 8005A344 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4AB48 8005A348 00000000 */  nop
/* 4AB4C 8005A34C 2A080901 */  slt        $at, $t0, $t1
/* 4AB50 8005A350 03002010 */  beqz       $at, .L8005A360
/* 4AB54 8005A354 80000E3C */   lui       $t6, (0x808080 >> 16)
/* 4AB58 8005A358 13000010 */  b          .L8005A3A8
/* 4AB5C 8005A35C 8080CE35 */   ori       $t6, $t6, (0x808080 & 0xFFFF)
.L8005A360:
/* 4AB60 8005A360 2A080A01 */  slt        $at, $t0, $t2
/* 4AB64 8005A364 03002014 */  bnez       $at, .L8005A374
/* 4AB68 8005A368 20700000 */   add       $t6, $zero, $zero # handwritten instruction
/* 4AB6C 8005A36C 0E000010 */  b          .L8005A3A8
/* 4AB70 8005A370 00000000 */   nop
.L8005A374:
/* 4AB74 8005A374 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4AB78 8005A378 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4AB7C 8005A37C 80000934 */  ori        $t1, $zero, 0x80
/* 4AB80 8005A380 18000A01 */  mult       $t0, $t2
/* 4AB84 8005A384 00000000 */  nop
/* 4AB88 8005A388 12400000 */  mflo       $t0
/* 4AB8C 8005A38C 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4AB90 8005A390 03440800 */  sra        $t0, $t0, 16
/* 4AB94 8005A394 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4AB98 8005A398 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4AB9C 8005A39C 18002A01 */  mult       $t1, $t2
/* 4ABA0 8005A3A0 00000000 */  nop
/* 4ABA4 8005A3A4 12700000 */  mflo       $t6
.L8005A3A8:
/* 4ABA8 8005A3A8 0000A886 */  lh         $t0, 0x0($s5)
/* 4ABAC 8005A3AC 0200A986 */  lh         $t1, 0x2($s5)
/* 4ABB0 8005A3B0 0400AA86 */  lh         $t2, 0x4($s5)
/* 4ABB4 8005A3B4 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4ABB8 8005A3B8 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4ABBC 8005A3BC 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4ABC0 8005A3C0 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4ABC4 8005A3C4 004C0900 */  sll        $t1, $t1, 16
/* 4ABC8 8005A3C8 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4ABCC 8005A3CC 25400901 */  or         $t0, $t0, $t1
/* 4ABD0 8005A3D0 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4ABD4 8005A3D4 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4ABD8 8005A3D8 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4ABDC 8005A3DC 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4ABE0 8005A3E0 00000000 */  nop
/* 4ABE4 8005A3E4 00000000 */  nop
/* 4ABE8 8005A3E8 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4ABEC 8005A3EC 4000A98F */  lw         $t1, 0x40($sp)
/* 4ABF0 8005A3F0 4400AA8F */  lw         $t2, 0x44($sp)
/* 4ABF4 8005A3F4 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4ABF8 8005A3F8 00000000 */  nop
/* 4ABFC 8005A3FC 2A080901 */  slt        $at, $t0, $t1
/* 4AC00 8005A400 03002010 */  beqz       $at, .L8005A410
/* 4AC04 8005A404 80000F3C */   lui       $t7, (0x808080 >> 16)
/* 4AC08 8005A408 13000010 */  b          .L8005A458
/* 4AC0C 8005A40C 8080EF35 */   ori       $t7, $t7, (0x808080 & 0xFFFF)
.L8005A410:
/* 4AC10 8005A410 2A080A01 */  slt        $at, $t0, $t2
/* 4AC14 8005A414 03002014 */  bnez       $at, .L8005A424
/* 4AC18 8005A418 20780000 */   add       $t7, $zero, $zero # handwritten instruction
/* 4AC1C 8005A41C 0E000010 */  b          .L8005A458
/* 4AC20 8005A420 00000000 */   nop
.L8005A424:
/* 4AC24 8005A424 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4AC28 8005A428 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4AC2C 8005A42C 80000934 */  ori        $t1, $zero, 0x80
/* 4AC30 8005A430 18000A01 */  mult       $t0, $t2
/* 4AC34 8005A434 00000000 */  nop
/* 4AC38 8005A438 12400000 */  mflo       $t0
/* 4AC3C 8005A43C 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4AC40 8005A440 03440800 */  sra        $t0, $t0, 16
/* 4AC44 8005A444 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4AC48 8005A448 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4AC4C 8005A44C 18002A01 */  mult       $t1, $t2
/* 4AC50 8005A450 00000000 */  nop
/* 4AC54 8005A454 12780000 */  mflo       $t7
.L8005A458:
/* 4AC58 8005A458 0000C886 */  lh         $t0, 0x0($s6)
/* 4AC5C 8005A45C 0200C986 */  lh         $t1, 0x2($s6)
/* 4AC60 8005A460 0400CA86 */  lh         $t2, 0x4($s6)
/* 4AC64 8005A464 22400B01 */  sub        $t0, $t0, $t3 # handwritten instruction
/* 4AC68 8005A468 22482C01 */  sub        $t1, $t1, $t4 # handwritten instruction
/* 4AC6C 8005A46C 22504D01 */  sub        $t2, $t2, $t5 # handwritten instruction
/* 4AC70 8005A470 FFFF0831 */  andi       $t0, $t0, 0xFFFF
/* 4AC74 8005A474 004C0900 */  sll        $t1, $t1, 16
/* 4AC78 8005A478 FFFF4A31 */  andi       $t2, $t2, 0xFFFF
/* 4AC7C 8005A47C 25400901 */  or         $t0, $t0, $t1
/* 4AC80 8005A480 0048CA48 */  ctc2       $t2, $9 # handwritten instruction
/* 4AC84 8005A484 0040C848 */  ctc2       $t0, $8 # handwritten instruction
/* 4AC88 8005A488 00088A48 */  mtc2       $t2, $1 # handwritten instruction
/* 4AC8C 8005A48C 00008848 */  mtc2       $t0, $0 # handwritten instruction
/* 4AC90 8005A490 00000000 */  nop
/* 4AC94 8005A494 00000000 */  nop
/* 4AC98 8005A498 1260424A */  MVMVA      0, 1, 0, 3, 0
/* 4AC9C 8005A49C 4000A98F */  lw         $t1, 0x40($sp)
/* 4ACA0 8005A4A0 4400AA8F */  lw         $t2, 0x44($sp)
/* 4ACA4 8005A4A4 00C80848 */  mfc2       $t0, $25 # handwritten instruction
/* 4ACA8 8005A4A8 00000000 */  nop
/* 4ACAC 8005A4AC 2A080901 */  slt        $at, $t0, $t1
/* 4ACB0 8005A4B0 03002010 */  beqz       $at, .L8005A4C0
/* 4ACB4 8005A4B4 8000183C */   lui       $t8, (0x808080 >> 16)
/* 4ACB8 8005A4B8 13000010 */  b          .L8005A508
/* 4ACBC 8005A4BC 80801837 */   ori       $t8, $t8, (0x808080 & 0xFFFF)
.L8005A4C0:
/* 4ACC0 8005A4C0 2A080A01 */  slt        $at, $t0, $t2
/* 4ACC4 8005A4C4 03002014 */  bnez       $at, .L8005A4D4
/* 4ACC8 8005A4C8 20C00000 */   add       $t8, $zero, $zero # handwritten instruction
/* 4ACCC 8005A4CC 0E000010 */  b          .L8005A508
/* 4ACD0 8005A4D0 00000000 */   nop
.L8005A4D4:
/* 4ACD4 8005A4D4 22400901 */  sub        $t0, $t0, $t1 # handwritten instruction
/* 4ACD8 8005A4D8 3C00AA8F */  lw         $t2, 0x3C($sp)
/* 4ACDC 8005A4DC 80000934 */  ori        $t1, $zero, 0x80
/* 4ACE0 8005A4E0 18000A01 */  mult       $t0, $t2
/* 4ACE4 8005A4E4 00000000 */  nop
/* 4ACE8 8005A4E8 12400000 */  mflo       $t0
/* 4ACEC 8005A4EC 01000A3C */  lui        $t2, (0x10101 >> 16)
/* 4ACF0 8005A4F0 03440800 */  sra        $t0, $t0, 16
/* 4ACF4 8005A4F4 01014A35 */  ori        $t2, $t2, (0x10101 & 0xFFFF)
/* 4ACF8 8005A4F8 22482801 */  sub        $t1, $t1, $t0 # handwritten instruction
/* 4ACFC 8005A4FC 18002A01 */  mult       $t1, $t2
/* 4AD00 8005A500 00000000 */  nop
/* 4AD04 8005A504 12C00000 */  mflo       $t8
.L8005A508:
/* 4AD08 8005A508 FCFF0EA2 */  sb         $t6, -0x4($s0)
/* 4AD0C 8005A50C 03720E00 */  sra        $t6, $t6, 8
/* 4AD10 8005A510 FCFF2FAE */  sw         $t7, -0x4($s1)
/* 4AD14 8005A514 FDFF0EA2 */  sb         $t6, -0x3($s0)
/* 4AD18 8005A518 03720E00 */  sra        $t6, $t6, 8
/* 4AD1C 8005A51C FCFF58AE */  sw         $t8, -0x4($s2)
/* 4AD20 8005A520 FEFF0EA2 */  sb         $t6, -0x2($s0)
.L8005A524:
/* 4AD24 8005A524 0C00A88C */  lw         $t0, 0xC($a1)
/* 4AD28 8005A528 20380000 */  add        $a3, $zero, $zero # handwritten instruction
/* 4AD2C 8005A52C 01000831 */  andi       $t0, $t0, 0x1
/* 4AD30 8005A530 37000011 */  beqz       $t0, .L8005A610
/* 4AD34 8005A534 08004994 */   lhu       $t1, 0x8($v0)
/* 4AD38 8005A538 00000000 */  nop
/* 4AD3C 8005A53C 02002A31 */  andi       $t2, $t1, 0x2
/* 4AD40 8005A540 25004011 */  beqz       $t2, .L8005A5D8
/* 4AD44 8005A544 5C00A88F */   lw        $t0, 0x5C($sp)
/* 4AD48 8005A548 00000000 */  nop
/* 4AD4C 8005A54C 00000B85 */  lh         $t3, 0x0($t0)
/* 4AD50 8005A550 04000D85 */  lh         $t5, 0x4($t0)
/* 4AD54 8005A554 00008A86 */  lh         $t2, 0x0($s4)
/* 4AD58 8005A558 04008C86 */  lh         $t4, 0x4($s4)
/* 4AD5C 8005A55C 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4AD60 8005A560 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4AD64 8005A564 43510A00 */  sra        $t2, $t2, 5
/* 4AD68 8005A568 43610C00 */  sra        $t4, $t4, 5
/* 4AD6C 8005A56C 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4AD70 8005A570 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4AD74 8005A574 04000AA2 */  sb         $t2, 0x4($s0)
/* 4AD78 8005A578 05000CA2 */  sb         $t4, 0x5($s0)
/* 4AD7C 8005A57C 0000AA86 */  lh         $t2, 0x0($s5)
/* 4AD80 8005A580 0400AC86 */  lh         $t4, 0x4($s5)
/* 4AD84 8005A584 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4AD88 8005A588 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4AD8C 8005A58C 43510A00 */  sra        $t2, $t2, 5
/* 4AD90 8005A590 43610C00 */  sra        $t4, $t4, 5
/* 4AD94 8005A594 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4AD98 8005A598 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4AD9C 8005A59C 04002AA2 */  sb         $t2, 0x4($s1)
/* 4ADA0 8005A5A0 05002CA2 */  sb         $t4, 0x5($s1)
/* 4ADA4 8005A5A4 0000CA86 */  lh         $t2, 0x0($s6)
/* 4ADA8 8005A5A8 0400CC86 */  lh         $t4, 0x4($s6)
/* 4ADAC 8005A5AC 20504B01 */  add        $t2, $t2, $t3 # handwritten instruction
/* 4ADB0 8005A5B0 20608D01 */  add        $t4, $t4, $t5 # handwritten instruction
/* 4ADB4 8005A5B4 43510A00 */  sra        $t2, $t2, 5
/* 4ADB8 8005A5B8 43610C00 */  sra        $t4, $t4, 5
/* 4ADBC 8005A5BC 80004A21 */  addi       $t2, $t2, 0x80 # handwritten instruction
/* 4ADC0 8005A5C0 80008C21 */  addi       $t4, $t4, 0x80 # handwritten instruction
/* 4ADC4 8005A5C4 04004AA2 */  sb         $t2, 0x4($s2)
/* 4ADC8 8005A5C8 05004CA2 */  sb         $t4, 0x5($s2)
/* 4ADCC 8005A5CC 4C00AB8F */  lw         $t3, 0x4C($sp)
/* 4ADD0 8005A5D0 06000010 */  b          .L8005A5EC
/* 4ADD4 8005A5D4 FEFF6721 */   addi      $a3, $t3, -0x2 # handwritten instruction
.L8005A5D8:
/* 4ADD8 8005A5D8 04002A31 */  andi       $t2, $t1, 0x4
/* 4ADDC 8005A5DC 03004011 */  beqz       $t2, .L8005A5EC
/* 4ADE0 8005A5E0 4C00AB8F */   lw        $t3, 0x4C($sp)
/* 4ADE4 8005A5E4 00000000 */  nop
/* 4ADE8 8005A5E8 FFFF6721 */  addi       $a3, $t3, -0x1 # handwritten instruction
.L8005A5EC:
/* 4ADEC 8005A5EC 18002A31 */  andi       $t2, $t1, 0x18
/* 4ADF0 8005A5F0 07004011 */  beqz       $t2, .L8005A610
/* 4ADF4 8005A5F4 00000000 */   nop
/* 4ADF8 8005A5F8 0C00488C */  lw         $t0, 0xC($v0)
/* 4ADFC 8005A5FC 1000498C */  lw         $t1, 0x10($v0)
/* 4AE00 8005A600 14004A94 */  lhu        $t2, 0x14($v0)
/* 4AE04 8005A604 040008AE */  sw         $t0, 0x4($s0)
/* 4AE08 8005A608 040029AE */  sw         $t1, 0x4($s1)
/* 4AE0C 8005A60C 04004AA6 */  sh         $t2, 0x4($s2)
.L8005A610:
/* 4AE10 8005A610 000080CA */  lwc2       $0, 0x0($s4)
/* 4AE14 8005A614 040081CA */  lwc2       $1, 0x4($s4)
/* 4AE18 8005A618 0000A2CA */  lwc2       $2, 0x0($s5)
/* 4AE1C 8005A61C 0400A3CA */  lwc2       $3, 0x4($s5)
/* 4AE20 8005A620 0000C4CA */  lwc2       $4, 0x0($s6)
/* 4AE24 8005A624 0400C5CA */  lwc2       $5, 0x4($s6)
/* 4AE28 8005A628 0000A88C */  lw         $t0, 0x0($a1)
/* 4AE2C 8005A62C 00000000 */  nop
/* 4AE30 8005A630 3000284A */  RTPT
/* 4AE34 8005A634 20104800 */  add        $v0, $v0, $t0 # handwritten instruction
/* 4AE38 8005A638 00005494 */  lhu        $s4, 0x0($v0)
/* 4AE3C 8005A63C 02005594 */  lhu        $s5, 0x2($v0)
/* 4AE40 8005A640 04005694 */  lhu        $s6, 0x4($v0)
/* 4AE44 8005A644 C0A01400 */  sll        $s4, $s4, 3
/* 4AE48 8005A648 C0A81500 */  sll        $s5, $s5, 3
/* 4AE4C 8005A64C C0B01600 */  sll        $s6, $s6, 3
/* 4AE50 8005A650 20A0D403 */  add        $s4, $fp, $s4 # handwritten instruction
/* 4AE54 8005A654 20A8D503 */  add        $s5, $fp, $s5 # handwritten instruction
/* 4AE58 8005A658 20B0D603 */  add        $s6, $fp, $s6 # handwritten instruction
/* 4AE5C 8005A65C 0600404B */  NCLIP
/* 4AE60 8005A660 00C00848 */  mfc2       $t0, $24 # handwritten instruction
/* 4AE64 8005A664 00000000 */  nop
/* 4AE68 8005A668 1A000019 */  blez       $t0, .L8005A6D4
/* 4AE6C 8005A66C 00000000 */   nop
/* 4AE70 8005A670 00000CEA */  swc2       $12, 0x0($s0)
/* 4AE74 8005A674 00002DEA */  swc2       $13, 0x0($s1)
/* 4AE78 8005A678 00004EEA */  swc2       $14, 0x0($s2)
/* 4AE7C 8005A67C 0B000714 */  bne        $zero, $a3, .L8005A6AC
/* 4AE80 8005A680 10000A34 */   ori       $t2, $zero, 0x10
/* 4AE84 8005A684 2D00584B */  AVSZ3
/* 4AE88 8005A688 00380748 */  mfc2       $a3, $7 # handwritten instruction
/* 4AE8C 8005A68C 5000A98F */  lw         $t1, 0x50($sp)
/* 4AE90 8005A690 2A084701 */  slt        $at, $t2, $a3
/* 4AE94 8005A694 0F002010 */  beqz       $at, .L8005A6D4
/* 4AE98 8005A698 4C00A88F */   lw        $t0, 0x4C($sp)
/* 4AE9C 8005A69C 07382701 */  srav       $a3, $a3, $t1
/* 4AEA0 8005A6A0 4000E720 */  addi       $a3, $a3, 0x40 # handwritten instruction
/* 4AEA4 8005A6A4 2A08E800 */  slt        $at, $a3, $t0
/* 4AEA8 8005A6A8 0A002010 */  beqz       $at, .L8005A6D4
.L8005A6AC:
/* 4AEAC 8005A6AC 5800AA8F */   lw        $t2, 0x58($sp)
/* 4AEB0 8005A6B0 5400A98F */  lw         $t1, 0x54($sp)
/* 4AEB4 8005A6B4 4800A88F */  lw         $t0, 0x48($sp)
/* 4AEB8 8005A6B8 24C8C900 */  and        $t9, $a2, $t1
/* 4AEBC 8005A6BC 80380700 */  sll        $a3, $a3, 2
/* 4AEC0 8005A6C0 2038E800 */  add        $a3, $a3, $t0 # handwritten instruction
/* 4AEC4 8005A6C4 0000E18C */  lw         $at, 0x0($a3)
/* 4AEC8 8005A6C8 0000F9AC */  sw         $t9, 0x0($a3)
/* 4AECC 8005A6CC 25082A00 */  or         $at, $at, $t2
/* 4AED0 8005A6D0 000021AF */  sw         $at, 0x0($t9)
.L8005A6D4:
/* 4AED4 8005A6D4 0400A88C */  lw         $t0, 0x4($a1)
/* 4AED8 8005A6D8 FFFF6320 */  addi       $v1, $v1, -0x1 # handwritten instruction
/* 4AEDC 8005A6DC 20800802 */  add        $s0, $s0, $t0 # handwritten instruction
/* 4AEE0 8005A6E0 20882802 */  add        $s1, $s1, $t0 # handwritten instruction
/* 4AEE4 8005A6E4 20904802 */  add        $s2, $s2, $t0 # handwritten instruction
/* 4AEE8 8005A6E8 FBFE601C */  bgtz       $v1, .L8005A2D8
/* 4AEEC 8005A6EC 2030C800 */   add       $a2, $a2, $t0 # handwritten instruction
/* 4AEF0 8005A6F0 DEFE0010 */  b          .L8005A26C
/* 4AEF4 8005A6F4 00000000 */   nop
.L8005A6F8:
/* 4AEF8 8005A6F8 1000B08F */  lw         $s0, 0x10($sp)
/* 4AEFC 8005A6FC 1400B18F */  lw         $s1, 0x14($sp)
/* 4AF00 8005A700 1800B28F */  lw         $s2, 0x18($sp)
/* 4AF04 8005A704 1C00B38F */  lw         $s3, 0x1C($sp)
/* 4AF08 8005A708 2000B48F */  lw         $s4, 0x20($sp)
/* 4AF0C 8005A70C 2400B58F */  lw         $s5, 0x24($sp)
/* 4AF10 8005A710 2800B68F */  lw         $s6, 0x28($sp)
/* 4AF14 8005A714 2C00B78F */  lw         $s7, 0x2C($sp)
/* 4AF18 8005A718 3000BE8F */  lw         $fp, 0x30($sp)
/* 4AF1C 8005A71C 0800E003 */  jr         $ra
/* 4AF20 8005A720 6000BD27 */   addiu     $sp, $sp, 0x60
