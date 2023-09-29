;/******************************************************************************
;/*%%%% mr_m_cra.s
;/*-----------------------------------------------------------------------------
;/*
;/*	PlayStation Exception Handler
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------  	----------  	------
;/*	28.07.97	Dean Ashton	Created
;/*
;/*%%%**************************************************************************/

	    	rsreset
MREX_ZERO   	rw	1
MREX_AT	    	rw	1
MREX_V0	    	rw	1
MREX_V1	    	rw	1
MREX_A0	    	rw	1
MREX_A1	    	rw	1
MREX_A2	    	rw	1
MREX_A3	    	rw	1
MREX_T0	    	rw	1
MREX_T1	    	rw	1
MREX_T2	    	rw	1
MREX_T3	    	rw	1
MREX_T4	    	rw	1
MREX_T5	    	rw	1
MREX_T6	    	rw	1
MREX_T7	    	rw	1
MREX_S0	    	rw	1
MREX_S1	    	rw	1
MREX_S2	    	rw	1
MREX_S3	    	rw	1
MREX_S4	    	rw	1
MREX_S5	    	rw	1
MREX_S6	    	rw	1
MREX_S7	    	rw	1
MREX_T8	    	rw	1
MREX_T9	    	rw	1
MREX_K0	    	rw	1
MREX_K1	    	rw	1
MREX_GP	    	rw	1
MREX_SP	    	rw	1
MREX_FP	    	rw	1
MREX_RA	    	rw	1
MREX_HI	    	rw	1
MREX_LO	    	rw	1
MREX_SR	    	rw	1
MREX_CA	    	rw	1
MREX_EPC    	rw	1
MREX_OLDVEC1	rw	1
MREX_OLDVEC2	rw	1
MREX_OLDVEC3	rw	1
MREX_OLDVEC4	rw	1
sizeof_MREX 	rb	0

		section	.text

		xdef	MRExceptionInstallASM
		xdef	MREx_registers
		xdef	MREx_force
		xdef	MREx_installed
		xdef	MREx_text_ptr
		xdef	MREx_font

		xref	MRExceptionShow
		
		opt	at-

MRExceptionInstallASM:
;		mfc0	v0, SR			; Get Status Register
		dw	$40026000
		andi	at, zero, $fffc		; Mask
		and	at, at, v0		; Interrupts Off
;		mtc0	at, SR
		dw 	$40816000
		nop				; Load/Store are undefined around mtc0 so
		nop				; leave an extra nop just in case...

		la	k0, MREx_registers

		addiu	t1, zero, $80		; Address of Interrupt Vector
		nop
		lw 	t2, (t1)		; Get Old Vector

		la	a0, MREx_force		; Point to our force variable
		lw	t0, 0(a0)		; Get MREx_force_patch BOOL
		nop
		bnez	t0, .patch_vector	; If TRUE then force installation
		nop			
	
		;// Check for DTL-H2000 development system

		lui	t3, $3c1a		; DTL-H2000 has interrupt vector holding $3C1A1FA0
		addiu	t3, t3, $1fa0
		nop
		subu	t3, t3, t2
		beqz	t3, .sn_installed	; Running on a DTL-H2000, so don't install our handler
		nop

		;// Check for DTL-H2500 development system

		lui	t3, $3c1a		; DTL-H2500 has interrupt vector holding $3C1A1FC2
		addiu	t3, t3, $1fc2
		nop
		subu	t3, t3, t2
		beqz	t3, .sn_installed	; Running on a DTL-H2500, so don't install our handler
		nop

.patch_vector:				
		lw	t0, 4(t1)
		lw	t3, 8(t1)
		lw	t4, 12(t1)
		sw	t2, MREX_OLDVEC1(k0)	; Store old vectors
		sw	t0, MREX_OLDVEC2(k0)
		sw	t3, MREX_OLDVEC3(k0)
		sw	t4, MREX_OLDVEC4(k0)
		la	k0, .exception_jump
		lw	t0, 0(k0)
		lw	t2, 4(k0)
		lw	t3, 8(k0)
		lw	t4, 12(k0)
		sw	t0, 0(t1)
		sw	t2, 4(t1)
		sw	t3, 8(t1)
		sw	t4, 12(t1)

		la	a0, MREx_installed	
		li	a1, $ffffffff
		sw	a1,0(a0)		
		nop

.sn_installed:
;		mtc0	v0,SR			; Restore Interrupt State
		dw	$40826000
		nop
		nop
		jr	ra			; And Return
		nop

.exception_jump:
		la	k0, .exception_run_new_handler
		jr	k0
		nop

;
;	The Actual Handler.
;

	
.exception_run_new_handler:
		la	k0, MREx_registers	; Get Save Area
		nop
		sw	at, MREX_AT(k0)		; Save 'at'... etc
		sw	v0, MREX_V0(k0)
;		mfc0	at, Cause
		dw	$40016800			

		ori	v0,zero,%1110011111110	; Pass External Interrupt and Syscall to OS
						; Trap the Rest...
		srl	at, at, 2
		andi	at, at, $1f		; Mask off bits...
		srlv	v0, v0, at
		andi	v0, v0, 1
		beqz 	v0, .run_old_handler	; Run the original OS interrupt handler
		nop


.real_exception:

; --- Save all the normal registers

		sw	zero, MREX_ZERO(k0)
		sw	v1, MREX_V1(k0)
		sw	a0, MREX_A0(k0)
		sw	a1, MREX_A1(k0)
		sw	a2, MREX_A2(k0)
		sw	a3, MREX_A3(k0)
		sw	t0, MREX_T0(k0)
		sw	t1, MREX_T1(k0)
		sw	t2, MREX_T2(k0)
		sw	t3, MREX_T3(k0)
		sw	t4, MREX_T4(k0)
		sw	t5, MREX_T5(k0)
		sw	t6, MREX_T6(k0)
		sw	t7, MREX_T7(k0)
		sw	s0, MREX_S0(k0)
		sw	s1, MREX_S1(k0)
		sw	s2, MREX_S2(k0)
		sw	s3, MREX_S3(k0)
		sw	s4, MREX_S4(k0)
		sw	s5, MREX_S5(k0)
		sw	s6, MREX_S6(k0)
		sw	s7, MREX_S7(k0)
		sw	t8, MREX_T8(k0)
		sw	t9, MREX_T9(k0)
		sw	k0, MREX_K0(k0)	
		sw	k1, MREX_K1(k0)
		sw	gp, MREX_GP(k0)
		sw	sp, MREX_SP(k0)
		sw	fp, MREX_FP(k0)
		sw	ra, MREX_RA(k0)
		mfhi	v0
		sw	v0, MREX_HI(k0)
		mflo	v0
		sw	v0, MREX_LO(k0)

;// Get status and cause registers and store them

;		mfc0	v0,SR
		dw	$40026000
		nop
		nop
		sw	v0, MREX_SR(k0)
		sw	at, MREX_CA(k0)


;// Get exception program counter and store it

;		mfc0	v0,EPC	   	
		dw	$40027000
		nop
		nop
		sw	v0, MREX_EPC(k0)


;// Call 'C' routine to display our exception details (after setting stack)

		la	v0,$801ffff8		; Point to top of 2Mb RAM
		or	sp,zero,v0		; Make it our stack pointer

		la	k0, MRExceptionShow
		jr	k0
		nop


;// Call the OS Exception Handler (for callbacks etc etc)

.run_old_handler:
		lw	at, MREX_AT(k0)		; Restore Regs...
		lw	v0, MREX_V0(k0)
					     
		addiu	k0, k0, MREX_OLDVEC1	; Call OS exception handler
		jr	k0
		nop
	

;// Declare data.	

	  	cnop	0,4
MREx_font	incbin	"..\API.BIN\CRASHFNT.TIM"	; Exception handler font (image to (640,0), clut to (640,256))

		cnop	0,4
MREx_force	dsw	1				; Set to true to always install
MREx_installed	dsw	1				; 0 if not installed, else -1.
MREx_text_ptr	dsw	1				; Pointer to some text
MREx_registers	dsb	sizeof_MREX			; The Register Save Area.

		end
			
