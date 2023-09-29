;/******************************************************************************
;/*%%%% mr_mips.s
;/*------------------------------------------------------------------------------
;/*
;/*	General purpose routines
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------  	----------  		------
;/*	20.03.97	Dean Ashton		Created
;/*
;/*%%%**************************************************************************/
	
		section	.text	
	
		include	"gtereg.h"

		xdef	MRQuaternionToMatrixASM
	
			rsreset
QUAT_STACK_arg_0	rw	1
QUAT_STACK_arg_1	rw	1
QUAT_STACK_arg_2	rw	1
QUAT_STACK_arg_3	rw	1
QUAT_STACK_s0		rw	1
QUAT_STACK_s1		rw	1
QUAT_STACK_s2		rw	1
sizeof_QUAT_STACK	rb	0

		opt	at-
qc		equr	v0
qx		equr	v1
qy		equr	at
qz		equr	a0
		opt	at+

xs		equr	s0
ys		equr	s1
zs		equr	s2

wx		equr	t0
wy		equr	t1
wz		equr	t2
xx		equr	t3
xy		equr	t4
xz		equr	t5
yy		equr	t6
yz		equr	t7
zz		equr	t8

MRQuaternionToMatrixASM:
		addiu	sp, sp, -sizeof_QUAT_STACK
		sw	s0, QUAT_STACK_s0(sp)	
		sw	s1, QUAT_STACK_s1(sp)	
		sw	s2, QUAT_STACK_s2(sp)	

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

		lw	s0, QUAT_STACK_s0(sp)
		lw	s1, QUAT_STACK_s1(sp)
		lw	s2, QUAT_STACK_s2(sp)
		jr	ra
		addiu	sp, sp, sizeof_QUAT_STACK

		end
	
