;/******************************************************************************
;/*%%%% mr_m_hdr.i
;/*------------------------------------------------------------------------------
;/*
;/*	Header file for MIPS assembler polygon rendering modules.
;/*
;/*	CHANGED		PROGRAMMER		REASON
;/*	-------  	----------  	------
;/*	18.9.96		Dean Ashton		Created
;/*	
;/*%%%**************************************************************************/

		include	"gtereg.h"

MR_QUAT_EPSILON		equ	1

;//-------------------------------------------------------------------------------------------
;// Register equates and stack layout for MRQuaternionToMatrixASM and MRQuaternionBToMatrixASM

			rsreset
MRQUATM_STACK_arg_0	rw	1
MRQUATM_STACK_arg_1	rw	1
MRQUATM_STACK_arg_2	rw	1
MRQUATM_STACK_arg_3	rw	1
MRQUATM_STACK_s0   	rw	1
MRQUATM_STACK_s1   	rw	1
MRQUATM_STACK_s2   	rw	1
sizeof_MRQUATM_STACK	rb	0

			opt	at-
qc			equr	v0
qx			equr	v1
qy			equr	at
qz			equr	a0
			opt	at+

xs			equr	s0
ys			equr	s1
zs			equr	s2

wx			equr	t0
wy			equr	t1
wz			equr	t2
xx			equr	t3
xy			equr	t4
xz			equr	t5
yy			equr	t6
yz			equr	t7
zz			equr	t8


;//------------------------------------------------------------------
;// Register equates and stack layout for MRInterpolateQuaternionsASM

			rsreset
MRIQUAT_STACK_arg_0	rw	1
MRIQUAT_STACK_arg_1	rw	1
MRIQUAT_STACK_arg_2	rw	1
MRIQUAT_STACK_arg_3	rw	1
MRIQUAT_STACK_s0   	rw	1
MRIQUAT_STACK_s1   	rw	1
MRIQUAT_STACK_s2   	rw	1
MRIQUAT_STACK_s3   	rw	1
MRIQUAT_STACK_s4   	rw	1
MRIQUAT_STACK_s5   	rw	1
MRIQUAT_STACK_s6   	rw	1
MRIQUAT_STACK_s7   	rw	1
MRIQUAT_STACK_s8   	rw	1
MRIQUAT_STACK_ra   	rw	1
sizeof_MRIQUAT_STACK	rb	0


;//---------------------------------------------------------------------------
;// Register equates and stack layout for MRInterpolateQuaternionsBToMatrixASM

			rsreset
MRIQUATBM_STACK_arg_0	rw	1
MRIQUATBM_STACK_arg_1	rw	1
MRIQUATBM_STACK_arg_2	rw	1
MRIQUATBM_STACK_arg_3	rw	1
MRIQUATBM_STACK_s0   	rw	1
MRIQUATBM_STACK_s1   	rw	1
MRIQUATBM_STACK_s2   	rw	1
MRIQUATBM_STACK_s3   	rw	1
MRIQUATBM_STACK_s4   	rw	1
MRIQUATBM_STACK_s5   	rw	1
MRIQUATBM_STACK_s6   	rw	1
MRIQUATBM_STACK_s7   	rw	1
MRIQUATBM_STACK_s8   	rw	1
MRIQUATBM_STACK_ra   	rw	1
MRIQUATBM_STACK_dquat	rh	4
sizeof_MRIQUATBM_STACK	rb	0


