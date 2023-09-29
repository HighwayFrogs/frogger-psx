;/******************************************************************************
;/*%%%% mr_m_pak.i
;/*------------------------------------------------------------------------------
;/*
;/*	Header file for MIPS assembler decompression routines
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------  	----------  	------
;/*	08.03.97	Dean Ashton	Created
;/*	
;/*%%%**************************************************************************/

MR_PPDECRUNCH_ERROR	equ	0
MR_PPDECRUNCH_OK	equ	1

MR_PP_IDENT_WORD	equ	(("P"<<0)+("P"<<8)+("2"<<16)+("0"<<24))

			rsreset
MR_PP_STACK_arg_0	rw	1
MR_PP_STACK_arg_1	rw	1
MR_PP_STACK_arg_2	rw	1
MR_PP_STACK_arg_3	rw	1

MR_PP_STACK_s0		rw	1
MR_PP_STACK_s1		rw	1
MR_PP_STACK_s2		rw	1
MR_PP_STACK_s3		rw	1
MR_PP_STACK_s4		rw	1
MR_PP_STACK_s5		rw	1
MR_PP_STACK_s6		rw	1
MR_PP_STACK_s7		rw	1
MR_PP_STACK_s8		rw	1 

sizeof_MR_PP_STACK	rb	0

;// Handy macro for reading bits - trashes s0, s1 and s2...

MR_PP_READBITS		macro

			or	v0, zero, zero			

.bit_loop\@		beq	zero, v1, .bit_exit\@		;// No bits
			nop
			ble	t2, v1, .bit_fetch\@
			ori	s0, zero, 32			;// DELAY: s0 = 32 (needed in both cases)
			
			;// We have enough bits in current byte to satisfy fetch request
			
			sll	v0, v0, v1			; result <<= num
			sub	t2, t2, v1			; MRPP_counter -= num
			sub	s0, s0, v1			; s0 = 32 - num
			srlv	s2, t3, s0			; s2 = (MRPP_shift_in >> (32-num))
			sllv	t3, t3, v1			; MRPP_shift_in <<= num
			or	v0, v0, s2			; result = result | (MRPP_shift_in >> (32-num))			
			beq	zero, zero, .bit_loop\@
			or	v1, zero, zero			;// DELAY: Clear requested bit counter to exit loop

.bit_fetch\@		
			;// We have to use all available bits, and then fetch a new byte and loop back

			sub	s0, s0, t2			; s0 = 3 - MRPP_counter
			addiu	a0, a0, -4			; Decrement MRPP_source_ptr by 4 bytes
			srlv	v0, t3, s0			; v0 = (MRPP_shift_in >> (32-MRPP_counter))

			;// One optimisation we've made here is to fetch 4 bytes at a time, and construct an
			;// appropriately formatted 32-bit value. Once the compressor is changed to write 
			;// data in a per-byte bitswapped format, this can just be a single read.. possibly.

			lbu	s0, 0(a0)			 
			sub	v1, v1, t2			; //DELAY : num =-= MRPP_counter;
			addu	s1, t1, s0			 
			lbu	s2, 0(s1)			; s2 holds bit reversed 0(a0)
		
			lbu	s0, 1(a0)			 
			or	t3, zero, s2			; t3 contains 1 byte in place 
			addu	s1, t1, s0			 
			lbu	s2, 0(s1)			; s2 holds bit reversed 1(a0)

			lbu	s0, 2(a0)			 
			sll	s2, s2, 8			; bit reversed 1(a0) << 8
			addu	s1, t1, s0			 
			or	t3, t3, s2			; t3 contains 2 bytes in place
			lbu	s2, 0(s1)			; s2 holds bit reversed 2(a0)
	
			lbu	s0, 3(a0)			 
			sll	s2, s2, 16			; bit reversed 2(a0) << 16
			addu	s1, t1, s0			 
			or	t3, t3, s2			; t3 contains 3 bytes in place
			lbu	s2, 0(s1)			; s3 holds bit reversed 3(a0)

			ori	t2, zero, 32			; Set MRPP_counter to 32 in delay slot

			sll	s2, s2, 24			; bit reversed 3(a0) << 24

			beq	zero, zero, .bit_loop\@
			or	t3, t3, s2			;// DELAY: Final construct of MRPP_shift_bits in delay slot			
.bit_exit\@
			;// v0 now holds result bits
			endm
