#	SN Systems replacement for main module
#	in API lib, ported to GNU AS Syntax

	.set	noreorder
	.set	noat
	
# Defines
	.global __start
	.global __SN_ENTRY_POINT
	.global __main
	.global __do_global_dtors
	.global __heapbase
	.global __heapsize
	.global __text
	.global __textlen
	.global __data
	.global __datalen
	.global __bss
	.global __bsslen

# Imports:
	.global InitHeap

#
# This is the program entry point.
# 1) Clear program BSS section to zero
# 2) Set stack and heap
# 3) Call user entry point i.e. main()
# 4) Jmp back to downloader stub (should be call exit() or something?)
#
# Note:	default ram size is 8 Megabytes
#	default stack size is 32K
#	stack position is top of RAM
#	heap is all of RAM from end of prog to lowest stack addr
#
# Use can override these settings by declaring suitable values
# for these variables in his C code module along with main().
# e.g.
#	_stacksize=0x00002000; /* set 8K stack */
#	  _ramsize=0x00100000; /* and 1MB ram  */
#
# If user does not specify override values for these variables
# by defining them as unsigned int then the default values will
# be loaded from the SNDEF module in LIBSN.LIB
#
# Note that:
# 1) if the user does not override the _stacksize and _ramsize vars then
# the defaults can still be accessed if declared as external unsigned int
#
# 2) other external unsigned ints which can be referenced are:-
#
#	external unsigned int __heapbase,__heapsize
#	external insigned int __text,__textlen
#	external unsigned int __data,__datalen
#	external unsigned int __bss,__bsslen
#
# These latter variables should be treated as READ ONLY.
# (You can of course declare them as pointers if you prefer).

	.section .text

__start:
__SN_ENTRY_POINT:
	lui        $v0, %hi(__sbss_start)
	addiu      $v0, $v0, %lo(__sbss_start)
	lui        $v1, %hi(__bss_end)
	addiu      $v1, $v1, %lo(__bss_end)

.Lclrit:
	sw         $zero, 0x0($v0)
	addiu      $v0, $v0, 0x4
	sltu       $at, $v0, $v1
	bnez       $at, .Lclrit
	nop
	
# This was the old way to set ram-top. Read mem config from DIP switches.
#
#	DIPSW	equ	$1F802040	;byte, read only
#	lui	a0,DIPSW>>16
#	lb	v0,DIPSW&$FFFF(a0)	;read dip settings
#	nop
#	andi	v0,v0,%00110000	;mem size in bits 4 & 5
#	srl	v0,v0,2
#	la	a0,MemSizes
#	addu	a0,a0,v0
#	lw	v0,0(a0)	;put stack at top of RAM
#	nop
	
	lui        $v0, %hi(_ramsize) # this is the new way; because there are no switches on new hardware.
	lw         $v0, %lo(_ramsize)($v0)
	nop

	addi       $v0, $v0, -0x8 # but leave room for two parameters
	lui        $t0, %hi(0x80000004) # (mem seg for kernel cached RAM)
	or         $sp, $v0, $t0 # set stack in kseg0

	lui        $a0, %hi(__bss_end) # a0 = heap base
	addiu      $a0, $a0, %lo(__bss_end)
	sll        $a0, $a0, 3
	srl        $a0, $a0, 3 # remove mem seg bits
	lui        $v1, %hi(_stacksize)
	lw         $v1, %lo(_stacksize)($v1)
	nop
	subu       $a1, $v0, $v1 # calc a1 = top of heap
	subu       $a1, $a1, $a0 # -heap base, => a1 = size of heap
	lui        $at, %hi(__heapsize)
	sw         $a1, %lo(__heapsize)($at)
	or         $a0, $a0, $t0 # heap in kseg0

	lui        $at, %hi(__heapbase)
	sw         $a0, %lo(__heapbase)($at)

	lui        $at, %hi(__ra_temp)
	sw         $ra, %lo(__ra_temp)($at)
	la         $gp, _gp
	addu       $fp, $sp, $zero
	jal        InitHeap
	addi       $a0, $a0, %lo(0x80000004) # don't know why they do this.

	lui        $ra, %hi(__ra_temp)
	lw         $ra, %lo(__ra_temp)($ra)
	nop

	jal        main
	nop

# Will fall through here if main() returns. Fall into debugger stub.
	break      0, 1 # for want of something better

#
# main() will call this before doing user code. Init other stuff here.
#

__main:
	lui        $t0, %hi(__initialised)
	lw         $t0, %lo(__initialised)($t0)
	addiu      $sp, $sp, -0x10

	sw         $s0, 0x4($sp)
	sw         $s1, 0x8($sp)
	sw         $ra, 0xC($sp)

	bnez       $t0, .Lexit
	ori        $t0, $zero, 0x1

	lui        $at, %hi(__initialised)
	sw         $t0, %lo(__initialised)($at)

	lui        $s0, %hi(__ctors_start)
	addiu      $s0, $s0, %lo(__ctors_start)
	lui        $s1, %hi(__ctors_count)
	addiu      $s1, $s1, %lo(__ctors_count)
	beqz       $s1, .Lexit
	nop

.Lloop: # loop for all C++ global constructors
	lw         $t0, 0x0($s0)
	addiu      $s0, $s0, 0x4

	jalr       $t0 # call C++ constructor
	addiu     $s1, $s1, -0x1

	bnez       $s1, .Lloop
	nop

.Lexit:
	lw         $ra, 0xC($sp)
	lw         $s1, 0x8($sp)
	lw         $s0, 0x4($sp)

	addiu      $sp, $sp, 0x10

	jr         $ra
	nop

__do_global_dtors:
	lui        $t0, %hi(__initialised)
	lw         $t0, %lo(__initialised)($t0)

	addiu      $sp, $sp, -0x10

	sw         $s0, 0x4($sp)
	sw         $s1, 0x8($sp)
	sw         $ra, 0xC($sp)

	beqz       $t0, .Lexit2
	nop

	lui        $s0, %hi(__dtors_start)
	addiu      $s0, $s0, %lo(__dtors_start)
	lui        $s1, %hi(__dtors_count)
	addiu      $s1, $s1, %lo(__dtors_count)
	beqz       $s1, .Lexit2
	nop

.Lloop2:
	lw         $t0, 0x0($s0)

	addiu      $s0, $s0, 0x4
	jalr       $t0
	addiu     $s1, $s1, -0x1

	bnez       $s1, .Lloop2
	nop

.Lexit2:
	lw         $ra, 0xC($sp)
	lw         $s1, 0x8($sp)
	lw         $s0, 0x4($sp)

	addiu      $sp, $sp, 0x10

	jr         $ra
	nop


	.section .data

__initialised:
	.word 0
__heapbase:
	.word 0
__heapsize:
	.word 0

__text:
	.word __text_start
__textlen:
	.word __text_len
__data:
	.word __data_start
__datalen:
	.word __data_len
__bss:
	.word __bss_start
__bsslen:
	.word __bss_len

	.section .sbss
__ra_temp:
        .space 4,0

