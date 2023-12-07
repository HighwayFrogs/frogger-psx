.include	"macro.inc"

.set noat      /* allow manual use of $at */
.set noreorder /* don't insert nops after branches */

# Handwritten function
glabel MRDisplayMeshPolys_GE3
/* 6D904 8007D104 1000A28F */  lw         $v0, 0x10($sp)
/* 6D908 8007D108 1400A38F */  lw         $v1, 0x14($sp)
/* 6D90C 8007D10C BCFFBD27 */  addiu      $sp, $sp, -0x44
/* 6D910 8007D110 1000B0AF */  sw         $s0, 0x10($sp)
/* 6D914 8007D114 1400B1AF */  sw         $s1, 0x14($sp)
/* 6D918 8007D118 1800B2AF */  sw         $s2, 0x18($sp)
/* 6D91C 8007D11C 1C00B3AF */  sw         $s3, 0x1C($sp)
/* 6D920 8007D120 2000B4AF */  sw         $s4, 0x20($sp)
/* 6D924 8007D124 2400B5AF */  sw         $s5, 0x24($sp)
/* 6D928 8007D128 2800B6AF */  sw         $s6, 0x28($sp)
/* 6D92C 8007D12C 2C00B7AF */  sw         $s7, 0x2C($sp)
/* 6D930 8007D130 3000BEAF */  sw         $fp, 0x30($sp)
/* 6D934 8007D134 2000508C */  lw         $s0, 0x20($v0)
/* 6D938 8007D138 24005184 */  lh         $s1, 0x24($v0)
/* 6D93C 8007D13C 2800528C */  lw         $s2, 0x28($v0)
/* 6D940 8007D140 2C00538C */  lw         $s3, 0x2C($v0)
/* 6D944 8007D144 26005484 */  lh         $s4, 0x26($v0)
/* 6D948 8007D148 FCFFD520 */  addi       $s5, $a2, -0x4 # handwritten instruction
/* 6D94C 8007D14C 0000B58E */  lw         $s5, 0x0($s5)
/* 6D950 8007D150 00000000 */  nop
/* 6D954 8007D154 03AC1500 */  sra        $s5, $s5, 16
/* 6D958 8007D158 FF00163C */  lui        $s6, (0xFFFFFF >> 16)
/* 6D95C 8007D15C FFFFD636 */  ori        $s6, $s6, (0xFFFFFF & 0xFFFF)
/* 6D960 8007D160 0009173C */  lui        $s7, (0x9000000 >> 16)
/* 6D964 8007D164 3400B6AF */  sw         $s6, 0x34($sp)
/* 6D968 8007D168 3800B7AF */  sw         $s7, 0x38($sp)
/* 6D96C 8007D16C 0B80193C */  lui        $t9, %hi(MREnv_strip)
/* 6D970 8007D170 0000013C */  lui        $at, 0
/* 6D974 8007D174 21083900 */  addu       $at, $at, $t9
/* 6D978 8007D178 603A2D8C */  lw         $t5, %lo(MREnv_strip)($at)
/* 6D97C 8007D17C 00000000 */  nop
/* 6D980 8007D180 0400B691 */  lbu        $s6, 0x4($t5)
/* 6D984 8007D184 0500B791 */  lbu        $s7, 0x5($t5)
/* 6D988 8007D188 4000D626 */  addiu      $s6, $s6, 0x40
/* 6D98C 8007D18C 4000F726 */  addiu      $s7, $s7, 0x40
/* 6D990 8007D190 3C00B6AF */  sw         $s6, 0x3C($sp)
/* 6D994 8007D194 4000B7AF */  sw         $s7, 0x40($sp)
/* 6D998 8007D198 44005E8C */  lw         $fp, 0x44($v0)
/* 6D99C 8007D19C 0000C884 */  lh         $t0, 0x0($a2)
/* 6D9A0 8007D1A0 0200C984 */  lh         $t1, 0x2($a2)
/* 6D9A4 8007D1A4 0400CA84 */  lh         $t2, 0x4($a2)
/* 6D9A8 8007D1A8 C0400800 */  sll        $t0, $t0, 3
/* 6D9AC 8007D1AC C0480900 */  sll        $t1, $t1, 3
/* 6D9B0 8007D1B0 C0500A00 */  sll        $t2, $t2, 3
/* 6D9B4 8007D1B4 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6D9B8 8007D1B8 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6D9BC 8007D1BC 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
.L8007D1C0:
/* 6D9C0 8007D1C0 000000C9 */  lwc2       $0, 0x0($t0)
/* 6D9C4 8007D1C4 040001C9 */  lwc2       $1, 0x4($t0)
/* 6D9C8 8007D1C8 000022C9 */  lwc2       $2, 0x0($t1)
/* 6D9CC 8007D1CC 040023C9 */  lwc2       $3, 0x4($t1)
/* 6D9D0 8007D1D0 000044C9 */  lwc2       $4, 0x0($t2)
/* 6D9D4 8007D1D4 040045C9 */  lwc2       $5, 0x4($t2)
/* 6D9D8 8007D1D8 1800D820 */  addi       $t8, $a2, 0x18 # handwritten instruction
/* 6D9DC 8007D1DC 00000000 */  nop
/* 6D9E0 8007D1E0 3000284A */  RTPT
/* 6D9E4 8007D1E4 00000887 */  lh         $t0, 0x0($t8)
/* 6D9E8 8007D1E8 02000987 */  lh         $t1, 0x2($t8)
/* 6D9EC 8007D1EC 04000A87 */  lh         $t2, 0x4($t8)
/* 6D9F0 8007D1F0 C0400800 */  sll        $t0, $t0, 3
/* 6D9F4 8007D1F4 C0480900 */  sll        $t1, $t1, 3
/* 6D9F8 8007D1F8 C0500A00 */  sll        $t2, $t2, 3
/* 6D9FC 8007D1FC 20400401 */  add        $t0, $t0, $a0 # handwritten instruction
/* 6DA00 8007D200 20482401 */  add        $t1, $t1, $a0 # handwritten instruction
/* 6DA04 8007D204 20504401 */  add        $t2, $t2, $a0 # handwritten instruction
/* 6DA08 8007D208 0600404B */  NCLIP
/* 6DA0C 8007D20C 1400C6C8 */  lwc2       $6, 0x14($a2)
/* 6DA10 8007D210 00C01848 */  mfc2       $t8, $24 # handwritten instruction
/* 6DA14 8007D214 00000000 */  nop
/* 6DA18 8007D218 8700001B */  blez       $t8, .L8007D438
/* 6DA1C 8007D21C 00000000 */   nop
/* 6DA20 8007D220 2D00584B */  AVSZ3
/* 6DA24 8007D224 0600CC84 */  lh         $t4, 0x6($a2)
/* 6DA28 8007D228 00381848 */  mfc2       $t8, $7 # handwritten instruction
/* 6DA2C 8007D22C C0600C00 */  sll        $t4, $t4, 3
/* 6DA30 8007D230 07C03802 */  srav       $t8, $t8, $s1
/* 6DA34 8007D234 20C01403 */  add        $t8, $t8, $s4 # handwritten instruction
/* 6DA38 8007D238 2A081303 */  slt        $at, $t8, $s3
/* 6DA3C 8007D23C 7E002014 */  bnez       $at, .L8007D438
/* 6DA40 8007D240 20608501 */   add       $t4, $t4, $a1 # handwritten instruction
/* 6DA44 8007D244 2A081203 */  slt        $at, $t8, $s2
/* 6DA48 8007D248 7B002010 */  beqz       $at, .L8007D438
/* 6DA4C 8007D24C 00000000 */   nop
/* 6DA50 8007D250 0800ECE8 */  swc2       $12, 0x8($a3)
/* 6DA54 8007D254 1400EDE8 */  swc2       $13, 0x14($a3)
/* 6DA58 8007D258 2000EEE8 */  swc2       $14, 0x20($a3)
/* 6DA5C 8007D25C 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6DA60 8007D260 0000013C */  lui        $at, (0x38 >> 16)
/* 6DA64 8007D264 21083900 */  addu       $at, $at, $t9
/* 6DA68 8007D268 38002D8C */  lw         $t5, (0x38 & 0xFFFF)($at)
/* 6DA6C 8007D26C 00000000 */  nop
/* 6DA70 8007D270 0000AE8D */  lw         $t6, 0x0($t5)
/* 6DA74 8007D274 0400AF8D */  lw         $t7, 0x4($t5)
/* 6DA78 8007D278 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6DA7C 8007D27C 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6DA80 8007D280 0800AE8D */  lw         $t6, 0x8($t5)
/* 6DA84 8007D284 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6DA88 8007D288 1000B98D */  lw         $t9, 0x10($t5)
/* 6DA8C 8007D28C 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6DA90 8007D290 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6DA94 8007D294 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6DA98 8007D298 000080C9 */  lwc2       $0, 0x0($t4)
/* 6DA9C 8007D29C 040081C9 */  lwc2       $1, 0x4($t4)
/* 6DAA0 8007D2A0 3C00B68F */  lw         $s6, 0x3C($sp)
/* 6DAA4 8007D2A4 4000B78F */  lw         $s7, 0x40($sp)
/* 6DAA8 8007D2A8 1260484A */  MVMVA      1, 0, 0, 3, 0
/* 6DAAC 8007D2AC 0800CC84 */  lh         $t4, 0x8($a2)
/* 6DAB0 8007D2B0 00000000 */  nop
/* 6DAB4 8007D2B4 C0600C00 */  sll        $t4, $t4, 3
/* 6DAB8 8007D2B8 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DABC 8007D2BC 000082C9 */  lwc2       $2, 0x0($t4)
/* 6DAC0 8007D2C0 040083C9 */  lwc2       $3, 0x4($t4)
/* 6DAC4 8007D2C4 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DAC8 8007D2C8 00000000 */  nop
/* 6DACC 8007D2CC 83690D00 */  sra        $t5, $t5, 6
/* 6DAD0 8007D2D0 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DAD4 8007D2D4 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DAD8 8007D2D8 00000000 */  nop
/* 6DADC 8007D2DC 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DAE0 8007D2E0 83710E00 */  sra        $t6, $t6, 6
/* 6DAE4 8007D2E4 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DAE8 8007D2E8 00720E00 */  sll        $t6, $t6, 8
/* 6DAEC 8007D2EC 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DAF0 8007D2F0 0C00EDA4 */  sh         $t5, 0xC($a3)
/* 6DAF4 8007D2F4 12E0484A */  MVMVA      1, 0, 1, 3, 0
/* 6DAF8 8007D2F8 0A00CC84 */  lh         $t4, 0xA($a2)
/* 6DAFC 8007D2FC 00000000 */  nop
/* 6DB00 8007D300 C0600C00 */  sll        $t4, $t4, 3
/* 6DB04 8007D304 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DB08 8007D308 000084C9 */  lwc2       $4, 0x0($t4)
/* 6DB0C 8007D30C 040085C9 */  lwc2       $5, 0x4($t4)
/* 6DB10 8007D310 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DB14 8007D314 00000000 */  nop
/* 6DB18 8007D318 83690D00 */  sra        $t5, $t5, 6
/* 6DB1C 8007D31C 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DB20 8007D320 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DB24 8007D324 00000000 */  nop
/* 6DB28 8007D328 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DB2C 8007D32C 83710E00 */  sra        $t6, $t6, 6
/* 6DB30 8007D330 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DB34 8007D334 00720E00 */  sll        $t6, $t6, 8
/* 6DB38 8007D338 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DB3C 8007D33C 1800EDA4 */  sh         $t5, 0x18($a3)
/* 6DB40 8007D340 1260494A */  MVMVA      1, 0, 2, 3, 0
/* 6DB44 8007D344 0C00CC84 */  lh         $t4, 0xC($a2)
/* 6DB48 8007D348 00000000 */  nop
/* 6DB4C 8007D34C C0600C00 */  sll        $t4, $t4, 3
/* 6DB50 8007D350 20608501 */  add        $t4, $t4, $a1 # handwritten instruction
/* 6DB54 8007D354 000080C9 */  lwc2       $0, 0x0($t4)
/* 6DB58 8007D358 040081C9 */  lwc2       $1, 0x4($t4)
/* 6DB5C 8007D35C 00C80D48 */  mfc2       $t5, $25 # handwritten instruction
/* 6DB60 8007D360 00000000 */  nop
/* 6DB64 8007D364 83690D00 */  sra        $t5, $t5, 6
/* 6DB68 8007D368 2068B601 */  add        $t5, $t5, $s6 # handwritten instruction
/* 6DB6C 8007D36C 00D00E48 */  mfc2       $t6, $26 # handwritten instruction
/* 6DB70 8007D370 00000000 */  nop
/* 6DB74 8007D374 22700E00 */  sub        $t6, $zero, $t6 # handwritten instruction
/* 6DB78 8007D378 83710E00 */  sra        $t6, $t6, 6
/* 6DB7C 8007D37C 2070D701 */  add        $t6, $t6, $s7 # handwritten instruction
/* 6DB80 8007D380 00720E00 */  sll        $t6, $t6, 8
/* 6DB84 8007D384 2068CD01 */  add        $t5, $t6, $t5 # handwritten instruction
/* 6DB88 8007D388 2400EDA4 */  sh         $t5, 0x24($a3)
/* 6DB8C 8007D38C 801F193C */  lui        $t9, (0x1F800000 >> 16)
/* 6DB90 8007D390 0000013C */  lui        $at, (0x34 >> 16)
/* 6DB94 8007D394 21083900 */  addu       $at, $at, $t9
/* 6DB98 8007D398 34002D8C */  lw         $t5, (0x34 & 0xFFFF)($at)
/* 6DB9C 8007D39C 00000000 */  nop
/* 6DBA0 8007D3A0 0000AE8D */  lw         $t6, 0x0($t5)
/* 6DBA4 8007D3A4 0400AF8D */  lw         $t7, 0x4($t5)
/* 6DBA8 8007D3A8 0000CE48 */  ctc2       $t6, $0 # handwritten instruction
/* 6DBAC 8007D3AC 0008CF48 */  ctc2       $t7, $1 # handwritten instruction
/* 6DBB0 8007D3B0 0800AE8D */  lw         $t6, 0x8($t5)
/* 6DBB4 8007D3B4 0C00AF8D */  lw         $t7, 0xC($t5)
/* 6DBB8 8007D3B8 1000B98D */  lw         $t9, 0x10($t5)
/* 6DBBC 8007D3BC 0010CE48 */  ctc2       $t6, $2 # handwritten instruction
/* 6DBC0 8007D3C0 0018CF48 */  ctc2       $t7, $3 # handwritten instruction
/* 6DBC4 8007D3C4 0020D948 */  ctc2       $t9, $4 # handwritten instruction
/* 6DBC8 8007D3C8 0E00CD84 */  lh         $t5, 0xE($a2)
/* 6DBCC 8007D3CC 1000CE84 */  lh         $t6, 0x10($a2)
/* 6DBD0 8007D3D0 C0680D00 */  sll        $t5, $t5, 3
/* 6DBD4 8007D3D4 C0700E00 */  sll        $t6, $t6, 3
/* 6DBD8 8007D3D8 2068A501 */  add        $t5, $t5, $a1 # handwritten instruction
/* 6DBDC 8007D3DC 2070C501 */  add        $t6, $t6, $a1 # handwritten instruction
/* 6DBE0 8007D3E0 0000A2C9 */  lwc2       $2, 0x0($t5)
/* 6DBE4 8007D3E4 0400A3C9 */  lwc2       $3, 0x4($t5)
/* 6DBE8 8007D3E8 0000C4C9 */  lwc2       $4, 0x0($t6)
/* 6DBEC 8007D3EC 0400C5C9 */  lwc2       $5, 0x4($t6)
/* 6DBF0 8007D3F0 04000310 */  beq        $zero, $v1, .L8007D404
/* 6DBF4 8007D3F4 00000000 */   nop
/* 6DBF8 8007D3F8 1604F84A */  NCDT
/* 6DBFC 8007D3FC 02000010 */  b          .L8007D408
/* 6DC00 8007D400 00000000 */   nop
.L8007D404:
/* 6DC04 8007D404 3F04184B */  NCCT
.L8007D408:
/* 6DC08 8007D408 3400B68F */  lw         $s6, 0x34($sp)
/* 6DC0C 8007D40C 3800B78F */  lw         $s7, 0x38($sp)
/* 6DC10 8007D410 24C8F600 */  and        $t9, $a3, $s6
/* 6DC14 8007D414 80C01800 */  sll        $t8, $t8, 2
/* 6DC18 8007D418 20C01003 */  add        $t8, $t8, $s0 # handwritten instruction
/* 6DC1C 8007D41C 0000018F */  lw         $at, 0x0($t8)
/* 6DC20 8007D420 000019AF */  sw         $t9, 0x0($t8)
/* 6DC24 8007D424 25083700 */  or         $at, $at, $s7
/* 6DC28 8007D428 000021AF */  sw         $at, 0x0($t9)
/* 6DC2C 8007D42C 0400F4E8 */  swc2       $20, 0x4($a3)
/* 6DC30 8007D430 1000F5E8 */  swc2       $21, 0x10($a3)
/* 6DC34 8007D434 1C00F6E8 */  swc2       $22, 0x1C($a3)
.L8007D438:
/* 6DC38 8007D438 1800C620 */  addi       $a2, $a2, 0x18 # handwritten instruction
/* 6DC3C 8007D43C 2800E720 */  addi       $a3, $a3, 0x28 # handwritten instruction
/* 6DC40 8007D440 FFFFB522 */  addi       $s5, $s5, -0x1 # handwritten instruction
/* 6DC44 8007D444 5EFFA01E */  bgtz       $s5, .L8007D1C0
/* 6DC48 8007D448 FFFFDE23 */   addi      $fp, $fp, -0x1 # handwritten instruction
/* 6DC4C 8007D44C 3C0047AC */  sw         $a3, 0x3C($v0)
/* 6DC50 8007D450 400046AC */  sw         $a2, 0x40($v0)
/* 6DC54 8007D454 44005EAC */  sw         $fp, 0x44($v0)
/* 6DC58 8007D458 1000B08F */  lw         $s0, 0x10($sp)
/* 6DC5C 8007D45C 1400B18F */  lw         $s1, 0x14($sp)
/* 6DC60 8007D460 1800B28F */  lw         $s2, 0x18($sp)
/* 6DC64 8007D464 1C00B38F */  lw         $s3, 0x1C($sp)
/* 6DC68 8007D468 2000B48F */  lw         $s4, 0x20($sp)
/* 6DC6C 8007D46C 2400B58F */  lw         $s5, 0x24($sp)
/* 6DC70 8007D470 2800B68F */  lw         $s6, 0x28($sp)
/* 6DC74 8007D474 2C00B78F */  lw         $s7, 0x2C($sp)
/* 6DC78 8007D478 3000BE8F */  lw         $fp, 0x30($sp)
/* 6DC7C 8007D47C 0800E003 */  jr         $ra
/* 6DC80 8007D480 4400BD27 */   addiu     $sp, $sp, 0x44
