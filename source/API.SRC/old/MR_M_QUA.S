;/******************************************************************************
;/*%%%% mr_m_qua.s
;/*-----------------------------------------------------------------------------
;/*
;/*	Quaternion Functions (MIPS Versions)
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------  	----------  	------
;/*	20.03.97	Dean Ashton	Created
;/*	12.06.97	Tim Closs	MRInterpolateQuaternionsASM() no longer assumes
;/*					MR_QUAT is long-aligned
;/*					(due to existence of MR_QUAT_TRANS structure)
;/*
;/*%%%**************************************************************************/
	
		section	.text	
	
		include	"mr_m_qua.i"

		xref	MRAcos_table
		xref	rsin
		xref	rcos
		xref	SquareRoot0
		
		xref	MRNormaliseQuaternion

		xdef	MRQuaternionToMatrixASM
		xdef	MRQuaternionBToMatrixASM
		xdef	MRInterpolateQuaternionsASM
		xdef	MRInterpolateQuaternionsBToMatrixASM


;/******************************************************************************
;/*%%%% MRQuaternionToMatrixASM
;/*-----------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MRQuaternionToMatrixASM(
;/*				MR_QUAT*	q,
;/*				MR_MAT*		m);
;/*
;/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
;/*
;/*	INPUTS		q	- (a0)	Pointer to quaternion (1.3.12 format)
;/*			m	- (a1)	Pointer to matrix to fill in
;/*
;/*	NOTES		Be careful when modifying this routine, it's pipelined to
;/*			hell, and uses an odd register layout (effectively trashing
;/*			one of the input argument pointers).
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	21.03.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

MRQuaternionToMatrixASM:
		addiu	sp, sp, -sizeof_MRQUATM_STACK
		sw	s0, MRQUATM_STACK_s0(sp)	
		sw	s1, MRQUATM_STACK_s1(sp)	
		sw	s2, MRQUATM_STACK_s2(sp)	

		opt 	at-

		;//--------------------------

		lh	qc, 0(a0)			; s0 = q->c
		lh	qx, 2(a0)			; s1 = q->x
		lh	qy, 4(a0)			; s2 = q->y
		lh	qz, 6(a0)			; s3 = q->z	// WARNING: THIS IS TRASHING ARGUMENT POINTER IN A0
		
		sll	ys, qy, 1			; s5 = 'ys'

		mtc2	qc, C2_IR1		
		mtc2	qx, C2_IR2		
		mtc2	qy, C2_IR3		
		mtc2	ys, C2_IR0			; Multiplier is 'ys'
		sll	xs, qx, 1			; // LOAD DELAY: s4 = xs
		sll	zs, qz, 1			; // LOAD DELAY: s6 = zs
		GPF	0
		
		mult	qc,xs	  			; // DELAY:
	
		mfc2	wy, C2_MAC1
		mfc2	xy, C2_MAC2
		mfc2	yy, C2_MAC3
		
		mtc2	zs, C2_IR0			; Multiplier is 'zs'
		mtc2	qc, C2_IR1		
		mtc2	qx, C2_IR2		
		mtc2	qy, C2_IR3		
		mflo	wx				; // LOAD DELAY:
		add	at, zero, $1000			; // LOAD DELAY:
		GPF	0

		mult	qx,xs				; // DELAY:
		mfc2	wz, C2_MAC1			; // MULTIPLY DELAY:
		mflo	xx

		mfc2	xz, C2_MAC2			; Need 2 instructions between mflo and next mult
		add	a3, xx, yy			; so we can schedule one of the matrix writes

		mult	qz,zs
		mfc2	yz, C2_MAC3			; // MULTIPLY DELAY
		mflo	zz

		sra	a3, a3, 12
		sub	a3, at, a3
		sh	a3, 16(a1)			; m[2][2] = 0x1000 - ((xx + yy) >> 12)
	
		add	a2, yy, zz
		add	a3, xy, wz
		sra	a2, a2, 12
		sra	a3, a3, 12
		sub	a2, at, a2
		sh	a3, 2(a1)			; m[0][1] = (xy + wz) >> 12
		sh	a2, 0(a1)			; m[0][0] = 0x1000 - ((yy + zz) >> 12)

		sub	a3, xz, wy
		sub	a2, xy, wz
		sra	a3, a3, 12
		sra	a2, a2, 12
		sh	a3, 4(a1)			; m[0][2] = (xz - wy) >> 12
		sh	a2, 6(a1)			; m[1][0] = (xy + wz) >> 12
				
		add	a3, xx, zz
		add	a2, yz, wx
		sra	a3, a3, 12
		sra	a2, a2, 12
		sub	a3, at, a3
		sh	a2, 10(a1)			; m[1][2] = (yz + wx) >> 12
		sh	a3, 8(a1)			; m[1][1] = 0x1000 - ((xx + zz) >> 12)
		
		add	a3, xz, wy
		sub	a2, yz, wx
		sra	a3, a3, 12
		sra	a2, a2, 12
		sh	a3, 12(a1)			; m[2][0] = (xz + wy) >> 12
		sh	a2, 14(a1)			; m[2][1] = (yz - wx) >> 12	

		;//--------------------------

		opt	at+

		lw	s0, MRQUATM_STACK_s0(sp)
		lw	s1, MRQUATM_STACK_s1(sp)
		lw	s2, MRQUATM_STACK_s2(sp)
		jr	ra
		addiu	sp, sp, sizeof_MRQUATM_STACK


;/******************************************************************************
;/*%%%% MRQuaternionBToMatrixASM
;/*-----------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MRQuaternionBToMatrixASM(
;/*				MR_QUATB*	q,
;/*				MR_MAT*		m);
;/*
;/*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
;/*
;/*	INPUTS		q	- (a0)	Pointer to quaternion (1.1.6 format)
;/*			m	- (a1)	Pointer to matrix to fill in
;/*
;/*	NOTES		Be careful when modifying this routine, it's pipelined to
;/*			hell, and uses an odd register layout (effectively trashing
;/*			one of the input argument pointers). Is pretty much the
;/*			same as MRQuaternionToMatrixASM.
;/*		
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	21.03.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/

MRQuaternionBToMatrixASM:
		addiu	sp, sp, -sizeof_MRQUATM_STACK
		sw	s0, MRQUATM_STACK_s0(sp)	
		sw	s1, MRQUATM_STACK_s1(sp)	
		sw	s2, MRQUATM_STACK_s2(sp)	

		opt 	at-

		;//--------------------------

		lb	qc, 0(a0)			; s0 = q->c
		lb	qx, 1(a0)			; s1 = q->x
		lb	qy, 2(a0)			; s2 = q->y
		lb	qz, 3(a0)			; s3 = q->z	// WARNING: THIS IS TRASHING ARGUMENT POINTER IN A0
		
		sll	ys, qy, 1			; s5 = 'ys'

		mtc2	qc, C2_IR1		
		mtc2	qx, C2_IR2		
		mtc2	qy, C2_IR3		
		mtc2	ys, C2_IR0			; Multiplier is 'ys'
		sll	xs, qx, 1			; // LOAD DELAY: s4 = xs
		sll	zs, qz, 1			; // LOAD DELAY: s6 = zs
		GPF	0
		
		mult	qc,xs	  			; // DELAY:
	
		mfc2	wy, C2_MAC1
		mfc2	xy, C2_MAC2
		mfc2	yy, C2_MAC3
		
		mtc2	zs, C2_IR0			; Multiplier is 'zs'
		mtc2	qc, C2_IR1		
		mtc2	qx, C2_IR2		
		mtc2	qy, C2_IR3		
		mflo	wx				; // LOAD DELAY:
		add	at, zero, $1000			; // LOAD DELAY:
		GPF	0

		mult	qx,xs				; // DELAY:
		mfc2	wz, C2_MAC1			; // MULTIPLY DELAY:
		mflo	xx

		mfc2	xz, C2_MAC2			; Need 2 instructions between mflo and next mult
		add	a3, xx, yy			; so we can schedule one of the matrix writes

		mult	qz,zs
		mfc2	yz, C2_MAC3			; // MULTIPLY DELAY
		mflo	zz

		sub	a3, at, a3
		sh	a3, 16(a1)			; m[2][2] = 0x1000 - ((xx + yy) >> 12)
	
		add	a2, yy, zz
		add	a3, xy, wz
		sub	a2, at, a2
		sh	a3, 2(a1)			; m[0][1] = (xy + wz)
		sh	a2, 0(a1)			; m[0][0] = 0x1000 - (yy + zz)

		sub	a3, xz, wy
		sub	a2, xy, wz
		sh	a3, 4(a1)			; m[0][2] = (xz - wy)
		sh	a2, 6(a1)			; m[1][0] = (xy + wz)
				
		add	a3, xx, zz
		add	a2, yz, wx
		sub	a3, at, a3
		sh	a2, 10(a1)			; m[1][2] = (yz + wx)
		sh	a3, 8(a1)			; m[1][1] = 0x1000 - (xx + zz)
		
		add	a3, xz, wy
		sub	a2, yz, wx
		sh	a3, 12(a1)			; m[2][0] = (xz + wy)
		sh	a2, 14(a1)			; m[2][1] = (yz - wx)	

		;//--------------------------

		opt	at+

		lw	s0, MRQUATM_STACK_s0(sp)
		lw	s1, MRQUATM_STACK_s1(sp)
		lw	s2, MRQUATM_STACK_s2(sp)
		jr	ra
		addiu	sp, sp, sizeof_MRQUATM_STACK



;/******************************************************************************
;/*%%%% MRInterpolateQuaternionsASM
;/*-----------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsASM(
;/*				MR_QUAT*	startq,
;/*				MR_QUAT*	endq,
;/*				MR_QUAT*	destq,
;/*				MR_USHORT	t);
;/*
;/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
;/*
;/*	INPUTS		startq	- (a0)	Start quaternion
;/*			endq	- (a1)	End quaternion
;/*			destq	- (a2)	Destination quaternion (output)
;/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------		----------	------
;/*	17.05.96	Tim Closs	Created
;/*	21.03.97	Dean Ashton	MIPS/GTE Conversion
;/*	12.06.97	Tim Closs	No longer assumes MR_QUAT is long-aligned
;/*			       		(due to existence of MR_QUAT_TRANS structure)
;/*
;/*%%%**************************************************************************/

; a0	-	Pointer to startq	(initial)
; a1	-	Pointer to endq		(initial)
; a2	-	Pointer to destq	(initial)
; a3	-	t			(initial)
;
; s0	-	bflip
; s1	-	cosomega
; s2	-	omega
; s3	-	sinomega
;
; s4	-	Pointer to startq
; s5	-	Pointer to endq
; s6	-	Pointer to destq
; s7	-	Safe work
;
; s8	-	startscale
;

MRInterpolateQuaternionsASM:

		addiu	sp, sp, -sizeof_MRIQUAT_STACK
		sw	s0, MRIQUAT_STACK_s0(sp)	
		sw	s1, MRIQUAT_STACK_s1(sp)	
		sw	s2, MRIQUAT_STACK_s2(sp)	
		sw	s3, MRIQUAT_STACK_s3(sp)	
		sw	s4, MRIQUAT_STACK_s4(sp)	
		sw	s5, MRIQUAT_STACK_s5(sp)	
		sw	s6, MRIQUAT_STACK_s6(sp)	
		sw	s7, MRIQUAT_STACK_s7(sp)	
		sw	s8, MRIQUAT_STACK_s8(sp)	
		sw	ra, MRIQUAT_STACK_ra(sp)	

		;// ---------------------------------

		opt 	at-

		bnez	a3, .not_zero_interpolation
		lh	t0, 0(a0)
		lh	t1, 2(a0)
		lh	t2, 4(a0)
		lh	t3, 6(a0)
		sh	t0, 0(a2)
		sh	t1, 2(a2)
		sh	t2, 4(a2)
		beqz	zero, .exit_routine	
		sh	t3, 6(a2)

.not_zero_interpolation:
		add	s4, a0, zero			; s4 = Pointer to startq
		add	s5, a1, zero			; s5 = Pointer to endq
		add	s6, a2, zero			; s6 = Pointer to destq

		lhu	t0, 0(a0)
		lhu	t1, 2(a0)
		lhu	t2, 4(a0)
		sll	t1, t1, 16
		or	t0, t0, t1
		ctc2	t0, C2_R11R12
		ctc2	t2, C2_R13R21

		lhu	t0, 0(a1)
		lhu	t1, 2(a1)
		lhu	t2, 4(a1)
		sll	t1, t1, 16
		or	t0, t0, t1
		mtc2	t0, C2_VXY0
		mtc2	t2, C2_VZ0

		lh	t0, 6(a0)			; Load startq->z 
		lh	t1, 6(a1)			; Load endq->z

		MVMVA	0,0,0,3,0			; Perform (startq->c * endq->c), (startq->x * endq->x) and (startq->y * endq->y)
	
		mult	t0, t1				; Perform (startq->z * endq->z)

		mfc2	t2, C2_MAC1			; t2 = (startq->c * endq->c) + (startq->x * endq->x) + (startq->y * endq->y)
		mflo	t5				; t5 = (startq->z * endq->z)

		add	t0, t5, t2				 
		sra	s1, t0, 12			; cosomega = (t2 + t3 + t4 + t5) >> 12

		ori	t9, zero, $1000			; t9 = 0x1000

		bgez	s1, .not_neg_cosomega
		or	s0, zero, zero			; // DELAY: bflip = FALSE
		sub	s1, zero, s1			; cosomega = -cosomega
		ori	s0, zero, 1			; bflip = TRUE

.not_neg_cosomega:
		sub	t0, t9, s1			; t0 = 0x1000 - cosomega
		subi	t0, t9, MR_QUAT_EPSILON		; t0 = (0x1000 - cosomega) - MR_QUAT_EPSILON
		bltz	t0, .close_ends
		sub	s8, t9, s7			; // DELAY: startscale = 0x1000 - t 			

		;// if (0x1000 - cosomega) > MR_QUAT_EPSILON)


.more_1000:
		slti	at, s1, $1000			; // DELAY: Check MIN(0x1000, cosomega)
		bnez	at, .less_1000			; at non-zero, so s1 < $1000. v0 = s1 in delay
		or	v0, s1, zero		
		addi	v0, zero, $1000			; at was zero (ie s1 >= $1000), so v0 = $1000..

.less_1000:
		slti	at, v0, -$1000
		beq	at, zero, .find_omega		; at zero (v0 >= -$1000), so cosomega = v0 (using delay slot)
		or	s1, v0, zero   				
		addi	s1, zero, -$1000		; at non-zero (ie v0 < -$1000) so set cosomega to -$1000

.find_omega:

		addi	t1, s1, $1000			; omega = MR_ACOS_RAW(cosomega)
		lui	t2, (MRAcos_table>>16)
		sll	t1, t1, 1
		ori	t2, t2, (MRAcos_table&$ffff)
		add	t2, t2, t1			; t2 now points to MRAcos_table[cosomega]
		lh	s2, 0(t2)			; s2 (omega) = MRAcos_table[cosomega]

		;// Start of suspiciously bad code

		jal	rsin	      			; go get rsin(omega)
		add	a0, zero, s2

		mult	a3, s2				; start (t * omega)
		add	s3, zero, v0			; sinomega = rsin(omega)
		mflo	s7				; s7 = (t * omega)
		sra	s7, s7, 12			; s7 = (t * omega) >> 12

		jal	rsin				; rsin(s7)
		add	a0, zero, s7			; // DELAY: Load function arguments

		sll	v0, v0, 12			; v0 = rsin(to) << 12
		div	v0, s3				; (rsin(to) << 12) / sinomega
		add	a0, zero, s7
		mflo	s3				; s3 (overridden sinomega) = end (temporary!)
		jal	rcos	    			; rcos(s7)
		nop
		mult	s1, s3				; At this point, v0 holds rcos(to), s1 holds cosomega, s3 holds end
		add	t0, s3, 0			; t0 holds endscale
		mflo	t1				; t1 = (cosomega * end)

		sra	t1, t1, 12			; t1 = (cosomega * end) >> 12
		sub	s8, v0, t1			; s8 holds startscale : rcos(to) - ((cosomega * end) >> 12)

		;// End of suspiciously bad code

		beq	zero, zero, .check_bflip
		lw	ra, MRIQUAT_STACK_ra(sp)	; Put our return address back
			
.close_ends:	
		or	t0, a3, zero			; endscale = t (a3 not corrupt, no function call happened)
		
.check_bflip:
		bnez	s0, .bflip
		sub	t0, zero, t0			; endscale = -endscale
		sub	t0, zero, t0			; endscale = -endscale (here if we don't want negate, in which case we invert again) 

.bflip:		
		lh	t1, 0(s5)			; t1 = endq->c
		lh	t2, 2(s5)			; t2 = endq->x
		lh	t3, 4(s5)			; t3 = endq->y
		mtc2	t0, C2_IR0			; t0 = endscale
		mtc2	t1, C2_IR1
		mtc2	t2, C2_IR2
		mtc2	t3, C2_IR3
		lh	t4, 6(s5)			; t4 = endq->z		
		nop
		GPF	0				; IR1 = (endq->c * endscale), IR2 = (endq->x * endscale), IR3 = (endq->y * endscale)
		mult	t0, t4				; Start (endq->z * endscale)

		lh	t1, 0(s4)			; t1 = startq->c
		lh	t2, 2(s4)			; t2 = startq->x
		lh	t3, 4(s4)			; t3 = startq->y
		mtc2	s8, C2_IR0			; s8 = startscale
		mtc2	t1, C2_IR1
		mtc2	t2, C2_IR2
		mtc2	t3, C2_IR3
		mflo	t0				; t0 = (endq->z * endscale)
		lh	t4, 6(s4)
		GPL	0	  			; IR1=(C2_MAC1+(startq->c*startscale)), IR2=(C2_MAC2+(startq->x*startscale)), IR3=(C2_MAC+(startq->y*startscale))
		mult	s8, t4				; Start (startq->z * startscale)
		
		mfc2	t1, C2_MAC1
		mfc2	t2, C2_MAC2
		mflo	t4				; t4 = (startq->z * startscale)
		mfc2	t3, C2_MAC3
		add	t4, t0, t4
		sra	t1, t1, 12			; t1 = ((startq->c * startscale) + (endq->c * endscale)) >> 12
		sra	t2, t2, 12			; t2 = ((startq->x * startscale) + (endq->x * endscale)) >> 12
		sra	t3, t3, 12			; t3 = ((startq->y * startscale) + (endq->y * endscale)) >> 12
		sra	t4, t4, 12			; t4 = ((startq->z * startscale) + (endq->z * endscale)) >> 12
	
		sh	t1, 0(s6)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 12	
		sh	t2, 2(s6)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 12	
		sh	t3, 4(s6)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 12	
		sh	t4, 6(s6)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 12	

		opt	at+
		
		;// ---------------------------------

.exit_routine:
		lw	s0, MRIQUAT_STACK_s0(sp)
		lw	s1, MRIQUAT_STACK_s1(sp)
		lw	s2, MRIQUAT_STACK_s2(sp)
		lw	s3, MRIQUAT_STACK_s3(sp)
		lw	s4, MRIQUAT_STACK_s4(sp)
		lw	s5, MRIQUAT_STACK_s5(sp)
		lw	s6, MRIQUAT_STACK_s6(sp)
		lw	s7, MRIQUAT_STACK_s7(sp)
		lw	s8, MRIQUAT_STACK_s8(sp)
		jr	ra
		addiu	sp, sp, sizeof_MRIQUAT_STACK



;/******************************************************************************
;/*%%%% MRInterpolateQuaternionsBToMatrixASM
;/*-----------------------------------------------------------------------------
;/*
;/*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsBToMatrixASM(
;/*				MR_QUATB*	startq,
;/*				MR_QUATB*	endq,
;/*				MR_MAT*		matrix,
;/*				MR_USHORT	t);
;/*
;/*	FUNCTION	Spherical linear interpolation of two unit quaternions.
;/*
;/*	INPUTS		startq	- (a0)	Start quaternion
;/*			endq	- (a1)	End quaternion
;/*			matrix	- (a2)	Destination matrix (output)
;/*			t	- (a3)	Interpolation value (0..1, 1 is 0x1000)
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------		----------		------
;/*	19.03.97	Tim Closs		Created
;/*	21.03.97	Dean Ashton		MIPS/GTE Conversion
;/*
;/*%%%**************************************************************************/

; a0	-	Pointer to startq	(initial)
; a1	-	Pointer to endq		(initial)
; a2	-	Pointer to matrix	(initial)
; a3	-	t			(initial)
;
; s0	-	bflip
; s1	-	cosomega
; s2	-	omega
; s3	-	sinomega
;
; s4	-	Pointer to startq
; s5	-	Pointer to endq
; s6	-	Pointer to matrix
; s7	-	Safe work
;
; s8	-	startscale

MRInterpolateQuaternionsBToMatrixASM:

		addiu	sp, sp, -sizeof_MRIQUATBM_STACK
		sw	s0, MRIQUATBM_STACK_s0(sp)	
		sw	s1, MRIQUATBM_STACK_s1(sp)	
		sw	s2, MRIQUATBM_STACK_s2(sp)	
		sw	s3, MRIQUATBM_STACK_s3(sp)	
		sw	s4, MRIQUATBM_STACK_s4(sp)	
		sw	s5, MRIQUATBM_STACK_s5(sp)	
		sw	s6, MRIQUATBM_STACK_s6(sp)	
		sw	s7, MRIQUATBM_STACK_s7(sp)	
		sw	s8, MRIQUATBM_STACK_s8(sp)	
		sw	ra, MRIQUATBM_STACK_ra(sp)	

		;// ---------------------------------

		opt 	at-

		add	s4, a0, zero			; s4 = Pointer to startq
		add	s5, a1, zero			; s5 = Pointer to endq
		add	s6, a2, zero			; s6 = Pointer to matrix

.check_for_quick_set
		bnez	a3, .process_quat		; t = 0, so do a MR_QUATB_TO_MAT(startq, matrix)
		nop
		jal	MRQuaternionBToMatrixASM
		add	a1, s6, zero
		beqz	zero, .exit_routine

.process_quat:
		lb	t0, 0(s4)			; t0 = startq->c (is in delay of previous beqz)
		lb	t1, 1(s4)			; t1 = startq->x
		lb	t2, 2(s4)			; t2 = startq->y
		sll	t0, t0, 16			
		sll	t1, t1, 16
		srl	t0, t0, 16
		or	t0, t0, t1			; t1 = (startq->x << 16) | startq->c
		ctc2	t0, C2_R11R12
		ctc2	t2, C2_R13R21
	
		lb	t0, 0(s5)			; t0 = endq->c
		lb	t1, 1(s5)			; t1 = endq->x
		lb	t2, 2(s5)			; t2 = endq->y
		sll	t0, t0, 16
		sll	t1, t1, 16
		srl	t0, t0, 16
		or	t0, t0, t1			; t0 = (endq->x << 16) | endq->c
		mtc2	t0, C2_VXY0
		mtc2	t2, C2_VZ0
		
		lb	t0, 3(s4)			; Load startq->z 
		lb	t1, 3(s5)			; Load endq->z

		MVMVA	0,0,0,3,0			; Perform (startq->c * endq->c), (startq->x * endq->x) and (startq->y * endq->y)
	
		mult	t0, t1				; Perform (startq->z * endq->z)

		mfc2	t2, C2_MAC1			; t2 = (startq->c * endq->c) + (startq->x * endq->x) + (startq->y * endq->y)
		mflo	t5				; t5 = (startq->z * endq->z)

		add	s1, t5, t2			; cosomega = (t2 + t3 + t4 + t5) 

		ori	t9, zero, $1000			; t9 = 0x1000
						 
		bgez	s1, .not_neg_cosomega
		or	s0, zero, zero			; // DELAY: bflip = FALSE
		sub	s1, zero, s1			; cosomega = -cosomega
		ori	s0, zero, 1			; bflip = TRUE

.not_neg_cosomega:
		sub	t0, t9, s1			; t0 = 0x1000 - cosomega
		subi	t0, t9, MR_QUAT_EPSILON		; t0 = (0x1000 - cosomega) - MR_QUAT_EPSILON
		bltz	t0, .close_ends
		sub	s8, t9, s7			; // DELAY: startscale = 0x1000 - t 			

		;// if (0x1000 - cosomega) > MR_QUAT_EPSILON)


.more_1000:
		slti	at, s1, $1000			; // DELAY: Check MIN(0x1000, cosomega)
		bnez	at, .less_1000			; at non-zero, so s1 < $1000. v0 = s1 in delay
		or	v0, s1, zero
		addi	v0, zero, $1000			; at was zero (ie s1 >= $1000), so v0 = $1000..

.less_1000:
		slti	at, v0, -$1000
		beq	at, zero, .find_omega		; at zero (v0 >= -$1000), so cosomega = v0 (using delay slot)
		or	s1, v0, zero   			
		addi	s1, zero, -$1000		; at non-zero (ie v0 < -$1000) so set cosomega to -$1000

.find_omega:
		addi	t1, s1, $1000			; omega = MR_ACOS_RAW(cosomega)
		lui	t2, (MRAcos_table>>16)
		sll	t1, t1, 1
		ori	t2, t2, (MRAcos_table&$ffff)
		add	t2, t2, t1			; t2 now points to MRAcos_table[cosomega]
		lh	s2, 0(t2)			; s2 (omega) = MRAcos_table[cosomega]

		;// Start of suspiciously bad code

		jal	rsin	      			; go get rsin(omega)
		add	a0, zero, s2

		mult	a3, s2				; start (t * omega)
		add	s3, zero, v0			; sinomega = rsin(omega)
		mflo	s7				; s7 = (t * omega)
		sra	s7, s7, 12			; s7 = (t * omega) >> 12

		jal	rsin				; rsin(s7)
		add	a0, zero, s7			; // DELAY: Load function arguments

		sll	v0, v0, 12			; v0 = rsin(to) << 12
		div	v0, s3				; (rsin(to) << 12) / sinomega
		add	a0, zero, s7
		mflo	s3				; s3 (overridden sinomega) = end (temporary!)
		jal	rcos	    			; rcos(s7)
		nop
		mult	s1, s3				; At this point, v0 holds rcos(to), s1 holds cosomega, s3 holds end
		add	t0, s3, 0			; t0 holds endscale
		mflo	t1				; t1 = (cosomega * end)

		sra	t1, t1, 12			; t1 = (cosomega * end) >> 12
		sub	s8, v0, t1			; s8 holds startscale : rcos(to) - ((cosomega * end) >> 12)

		;// End of suspiciously bad code

		beq	zero, zero, .check_bflip
		nop
			
.close_ends:	
		or	t0, a3, zero			; endscale = t (a3 not corrupt, no function call happened)
		
.check_bflip:
		bnez	s0, .bflip
		sub	t0, zero, t0			; endscale = -endscale
		sub	t0, zero, t0			; endscale = -endscale (here if we don't want negate, in which case we invert again) 

.bflip:		
		lb	t1, 0(s5)			; t1 = endq->c
		lb	t2, 1(s5)			; t2 = endq->x
		lb	t3, 2(s5)			; t3 = endq->y
		mtc2	t0, C2_IR0			; t0 = endscale
		mtc2	t1, C2_IR1
		mtc2	t2, C2_IR2
		mtc2	t3, C2_IR3
		lb	t4, 3(s5)			; t4 = endq->z		
		nop
		GPF	0				; IR1 = (endq->c * endscale), IR2 = (endq->x * endscale), IR3 = (endq->y * endscale)
		mult	t0, t4				; Start (endq->z * endscale)

		lb	t1, 0(s4)			; t1 = startq->c
		lb	t2, 1(s4)			; t2 = startq->x
		lb	t3, 2(s4)			; t3 = startq->y
		mtc2	s8, C2_IR0			; s8 = startscale
		mtc2	t1, C2_IR1
		mtc2	t2, C2_IR2
		mtc2	t3, C2_IR3
		mflo	t0				; t0 = (endq->z * endscale)
		lb	t4, 3(s4)
		GPL	0	  			; IR1=(C2_MAC1+(startq->c*startscale)), IR2=(C2_MAC2+(startq->x*startscale)), IR3=(C2_MAC+(startq->y*startscale))
		mult	s8, t4				; Start (startq->z * startscale)
		
		mfc2	t1, C2_MAC1
		mfc2	t2, C2_MAC2
		mflo	t4				; t4 = (startq->z * startscale)
		mfc2	t3, C2_MAC3
		add	t4, t0, t4
		sra	t1, t1, 6			; t1 = ((startq->c * startscale) + (endq->c * endscale)) >> 6
		sra	t2, t2, 6			; t2 = ((startq->x * startscale) + (endq->x * endscale)) >> 6
		sra	t3, t3, 6			; t3 = ((startq->y * startscale) + (endq->y * endscale)) >> 6
		sra	t4, t4, 6			; t4 = ((startq->z * startscale) + (endq->z * endscale)) >> 6
	
		addiu	s0, sp, MRIQUATBM_STACK_dquat	; a0 points to destquat
		
		sh	t1, 0(s0)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 6
		sh	t2, 2(s0)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 6
		sh	t3, 4(s0)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 6
		sh	t4, 6(s0)			; destq->c = ((startq->c * startscale) + (endq->c * endscale)) >> 6

		beqz	t0, .turn_to_matrix		; t0 still holds endscale..
		add	a0, s0, 0			; // DELAY: a0 points to destquat
		add	a1, a0, 0			; a1 = a0 = destquat
		jal	MRNormaliseQuaternion
		addi	a2, zero, $1000			; // DELAY: a2 = $1000
		add	a0, s0, 0			; Reset a0 to destquat (could have been trashed by MRNormaliseQuaternion)

.turn_to_matrix:
		jal	MRQuaternionToMatrixASM
		add	a1, s6, 0			; // DELAY: s6 = matrix
	
		opt	at+
		
		;// ---------------------------------

.exit_routine:
		lw	ra, MRIQUATBM_STACK_ra(sp)	; Put our return address back
		lw	s0, MRIQUATBM_STACK_s0(sp)
		lw	s1, MRIQUATBM_STACK_s1(sp)
		lw	s2, MRIQUATBM_STACK_s2(sp)
		lw	s3, MRIQUATBM_STACK_s3(sp)
		lw	s4, MRIQUATBM_STACK_s4(sp)
		lw	s5, MRIQUATBM_STACK_s5(sp)
		lw	s6, MRIQUATBM_STACK_s6(sp)
		lw	s7, MRIQUATBM_STACK_s7(sp)
		lw	s8, MRIQUATBM_STACK_s8(sp)
		jr	ra
		addiu	sp, sp, sizeof_MRIQUATBM_STACK

