#/******************************************************************************
#/*%%%% mr_m_pak.s
#/*------------------------------------------------------------------------------
#/*
#/*	MIPS Decompression code
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	18.09.96	Dean Ashton		Created
#/*	??.11.23	Kneesnap		Ported to GNU AS Syntax
#/*	19.03.25	Kneesnap		Improved GNU Assembler version readibility
#/*
#/*%%%**************************************************************************/

.include "macro.inc"
.include "mr_m_pak.i"

.set noat      # allow manual use of $at
.set noreorder # don't insert nops after branches

#/******************************************************************************
#/*%%%% MRPPDecrunchBuffer
#/*------------------------------------------------------------------------------
#/*
#/*	SYNOPSIS	MR_ULONG status	(v0) =	MRPPDecrunchBuffer(
#/*					 	MR_UBYTE*	source,
#/*						MR_UBYTE*	dest,
#/*						MR_ULONG	packed_length);
#/*
#/*	FUNCTION	Decompresses a block of previously compressed data. This routine
#/*			should allow you to decompress over the source area, so
#/*			theoretically dest could be 'source+8'. In practise, I guess a
#/*			32-byte margin is safer. Time will probably tell...
#/*
#/*	INPUTS		source		- (a0) Pointer to start of compressed data
#/*			dest  		- (a1) Pointer to start of destination area
#/*			packed_length	- (a2) Length of compressed file
#/*
#/*	RESULT		status		- MR_PPDECRUNCH_ERROR if not compressed
#/*					  or MR_PPDECRUNCH_OK if all went well...
#/*			     
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------		----------		------
#/*	04.03.97	Dean Ashton		Created
#/*
#/*%%%**************************************************************************/

#// Notes here
#// ---------------------------------------------------------------------------------------------
#
# a0	-	Pointer to start of source data
# a1	-	Pointer to start of destination area
# a2	-	Length of compressed data in bytes
# a3	-	Work destination pointer
#
# v0	-	Output from MRPPGetBits equivalent or return code (MR_PPDECRUNCH_ERROR/MR_PPDECRUNCH_OK)
# v1	-	Input to MRPPGetBits equivalent
#
# t0	-	Address of offset table (actually at MRTemp_matrix) 
# t1	-	Address of MRPP_rev_table
# t2	-	MRPP_counter equivalent
# t3	-	MRPP_shift_in equivalent
#
# t4	-	work register
# t5	-	work register
# t6	-	offset equivalent
# t7	-	bytes equivalent
# t8	-	to_add equivalent
# t9	-	n_bits equivalent
#
# s0	-	MRPPGetBits() work register
# s1	-	MRPPGetBits() work register
# s2	-	MRPPGetBits() work register
# s3	-	work register (holds constant 3) - for compares
# s4	-	work register (holds constant 4) - for compares
# s5	-	work register (holds constant 7) - for compares
# s6	-	work register (holds constant 0xff) - for masking
# s7	-	work register
# s8	-	work register


glabel MRPPDecrunchBuffer
	addiu      $sp, $sp, -sizeof_MR_PP_STACK # Create a stack frame
	sw         $s0, MR_PP_STACK_s0($sp) # Save registers on the stack
	sw         $s1, MR_PP_STACK_s1($sp)
	sw         $s2, MR_PP_STACK_s2($sp)
	sw         $s3, MR_PP_STACK_s3($sp)
	sw         $s4, MR_PP_STACK_s4($sp)
	sw         $s5, MR_PP_STACK_s5($sp)
	sw         $s6, MR_PP_STACK_s6($sp)
	sw         $s7, MR_PP_STACK_s7($sp)
	sw         $s8, MR_PP_STACK_s8($sp)

.Linitialise:
	lw         $t4, 0($a0) # t4 holds identifier longword from source
	lui        $t5, %hi(MR_PP_IDENT_WORD) # Load 'PP20' into t5
	ori        $t5, $t5, %lo(MR_PP_IDENT_WORD)
	bne        $t4, $t5, .Lexit # If not a PP file, then bail.
	ori        $v0, $zero, MR_PPDECRUNCH_ERROR # DELAY: Load error code in delay slot..

	lui        $t0, %hi(MRTemp_matrix)
	ori        $t0, $t0, %lo(MRTemp_matrix) # v1 points to MRPP_rev_table

	lw         $t4, 4($a0) # Load the offset sizes while a0 still points to source
	lui        $t1, %hi(MRPP_rev_table) # Start to construct pointer to MRPP_rev_table
	sw         $t4, 0($t0) # and store in our temporary area (actually first 32-bits of MRTemp_matrix)
	ori        $t1, $t1, %lo(MRPP_rev_table) # v1 points to MRPP_rev_table (finish construction)

	addu       $a0, $a0, $a2 # a0 = source + packed length - 4
	addiu      $a0, $a0, -4
	lbu        $t5, 1($a0) # Fetch source_ptr[1]
	lbu        $t4, 2($a0) # Fetch source_ptr[2]
	lbu        $t6, 0($a0) # Fetch source_ptr[0]
	sll        $t5, $t5, 8 # shift up source_ptr[1] by 8
	sll        $t6, $t6, 16 # shift up source_ptr[0] by 16
	or         $t4, $t4, $t5
	or         $t4, $t4, $t6 # unpacked_length = (source_ptr[0]<<16) | (source_ptr[1]<<8) | (source_ptr[0])

	or         $t2, $zero, $zero # t2 (MRPP_counter) = 0
	or         $t3, $zero, $zero # t3 (MRPP_shift_in) = 0

	ori        $s3, $zero, 3 # s3 holds constant 3
	ori        $s4, $zero, 4 # s4 holds constant 4
	ori        $s5, $zero, 7 # s5 holds constant 7
	ori        $s6, $zero, 255 # s6 holds constant 0xff

	lbu        $v1, 3($a0) # v1 holds number of bits to skip
	addu       $a3, $a1, $t4 # a3 = dest + unpacked_length
	
	mr_pp_readbits # Read 'v1' bits, put result into v0

.Lmain_loop:
	ori        $v1, $zero, 0x1 # v1 = 1
	mr_pp_readbits # Read 1 bit into v0

	bnez       $v0, .Ldecode_copy # Not zero, then we need to decode what to to copy
	or        $t7, $zero, $zero # DELAY: bytes = 0

#//---------------------------------------------------------------------------------------------------
.Lget_source_count:
	ori        $v1, $zero, 2 # v1 = 2 (this will always override the load with 8 in later delay)
	mr_pp_readbits # MRPPGetBits(2)
	addu       $t7, $t7, $v0 # bytes += MRPPGetBits(2)
	beq        $v0, $s3, .Lget_source_count # if result of MRPPGetBits(2) was 3, then loop back

.Lcopy_s_bytes:
	ori       $v1, $zero, 8 # DELAY: v1 = 8
	mr_pp_readbits
	addi       $a3, $a3, -1 # dest_ptr = dest_ptr - 1;
	addi       $t7, $t7, -1 # bytes = bytes - 1;
	bgez       $t7, .Lcopy_s_bytes
	sb         $v0, 0($a3) # DELAY: store byte

	slt        $at, $a1, $a3
	beqz       $at, .Lclosedown # dest_ptr <= dest, so return OK

#---------------------------------------------------------------------------------------------------
.Ldecode_copy:
	ori        $v1, $zero, 2 # DELAY: v1 = 2 (in ble's delay slot!)
	mr_pp_readbits # Read 2 bits into v0
	addiu      $t7, $v0, 1 # bytes = idx + 1

	addu       $t4, $t0, $v0 # t4 = offset table + idx
	lbu        $t9, 0($t4) # n_bits = offset_sizes[idx]
	bne        $t7, $s4, .Lsmall_length # bytes != 4?
	ori        $v1, $zero, 1 # DELAY: v1 = 1 in delay slot

.Llarge_length:
	mr_pp_readbits # Read 1 bit into v0
	bnez       $v0, .Lfetch_n_bits
	or         $v1, $zero, $s5 # v1 = 7

	mr_pp_readbits # Read 7 bits into v0
	b          .Ladd_bits
	or         $t6, $zero, $v0 # DELAY: offset = MRPPGetBits(7)	

.Lfetch_n_bits:
	or         $v1, $zero, $t9 # v1 = n_bits
	mr_pp_readbits
	or         $t6, $zero, $v0 # offset = MRPPGetBits(n_bits)
	
.Ladd_bits:
	ori        $v1, $zero, 3 # v1 = 3
	mr_pp_readbits
	addu       $t7, $t7, $v0 # bytes += MRPPGetBits(3)
	beq        $v0, $s5, .Ladd_bits # if result of MRPPGetBits(3) was 7, then loop back
	nop
	b          .Lcopy_data
	nop

.Lsmall_length:
	or         $v1, $zero, $t9 # v1 = n_bits
	mr_pp_readbits
	or         $t6, $zero, $v0 # offset = MRPPGetBits(n_bits)	

#---------------------------------------------------------------------------------------------------
.Lcopy_data:
	addu       $t4, $a3, $t6 # t4 = &dest_ptr[offset]
	lbu        $t5, 0($t4) # t5 = dest_ptr[offset]
	addi       $t7, $t7, -1 # bytes = bytes - 1
	sb         $t5, -1($a3) # dest_ptr[-1] = dest_ptr[offset]
	bgez       $t7, .Lcopy_data
	addiu     $a3, $a3, -1 # dest_ptr--
	slt        $at, $a1, $a3
	bnez       $at, .Lmain_loop # dest_ptr > dest, so loop back

.Lclosedown:
	ori       $v0, $zero, MR_PPDECRUNCH_OK # Load success code for return to caller (delay of bgt)

.Lexit:
	lw         $s0, MR_PP_STACK_s0($sp) # Restore registers from stack
	lw         $s1, MR_PP_STACK_s1($sp)
	lw         $s2, MR_PP_STACK_s2($sp)
	lw         $s3, MR_PP_STACK_s3($sp)
	lw         $s4, MR_PP_STACK_s4($sp)
	lw         $s5, MR_PP_STACK_s5($sp)
	lw         $s6, MR_PP_STACK_s6($sp)
	lw         $s7, MR_PP_STACK_s7($sp)
	lw         $s8, MR_PP_STACK_s8($sp)
	jr         $ra
	addiu      $sp, $sp, sizeof_MR_PP_STACK
