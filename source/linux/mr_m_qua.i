#/******************************************************************************
#/*%%%% mr_m_qua.i
#/*------------------------------------------------------------------------------
#/*
#/*	Header file for MIPS assembler polygon rendering modules.
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	18.9.96		Dean Ashton		Created
#/*	19.3.25		Kneesnap		Converted to GNU Assembler Syntax
#/*	
#/*%%%**************************************************************************/

.include "macro.inc"
.include "utils.i"

.set MR_QUAT_EPSILON, 1

#-------------------------------------------------------------------------------------------
# Register equates and stack layout for MRQuaternionToMatrixASM and MRQuaternionBToMatrixASM

new_struct
struct_entry MRQUATM_STACK_arg_0, 4
struct_entry MRQUATM_STACK_arg_1, 4
struct_entry MRQUATM_STACK_arg_2, 4
struct_entry MRQUATM_STACK_arg_3, 4
struct_entry MRQUATM_STACK_s0, 4
struct_entry MRQUATM_STACK_s1, 4
struct_entry MRQUATM_STACK_s2, 4
struct_entry sizeof_MRQUATM_STACK, 0

.set qc, $2 # v0
.set qx, $3 # v1
.set qy, $1 # at
.set qz, $4 # a0

.set xs, $16 # s0
.set ys, $17 # s1
.set zs, $18 # s2

.set wx, $8 # t0
.set wy, $9 # t1
.set wz, $10 # t2
.set xx, $11 # t3
.set xy, $12 # t4
.set xz, $13 # t5
.set yy, $14 # t6
.set yz, $15 # t7
.set zz, $24 # t8


#------------------------------------------------------------------
# Register equates and stack layout for MRQuaternionToMatrixASM
new_struct
struct_entry QUAT_STACK_arg_0, 4
struct_entry QUAT_STACK_arg_1, 4
struct_entry QUAT_STACK_arg_2, 4
struct_entry QUAT_STACK_arg_3, 4
struct_entry QUAT_STACK_s0, 4
struct_entry QUAT_STACK_s1, 4
struct_entry QUAT_STACK_s2, 4
struct_entry sizeof_QUAT_STACK, 0


#------------------------------------------------------------------
# Register equates and stack layout for MRInterpolateQuaternionsASM

new_struct
struct_entry MRIQUAT_STACK_arg_0, 4
struct_entry MRIQUAT_STACK_arg_1, 4
struct_entry MRIQUAT_STACK_arg_2, 4
struct_entry MRIQUAT_STACK_arg_3, 4
struct_entry MRIQUAT_STACK_s0, 4
struct_entry MRIQUAT_STACK_s1, 4
struct_entry MRIQUAT_STACK_s2, 4
struct_entry MRIQUAT_STACK_s3, 4
struct_entry MRIQUAT_STACK_s4, 4
struct_entry MRIQUAT_STACK_s5, 4
struct_entry MRIQUAT_STACK_s6, 4
struct_entry MRIQUAT_STACK_s7, 4
struct_entry MRIQUAT_STACK_s8, 4
struct_entry MRIQUAT_STACK_ra, 4
struct_entry sizeof_MRIQUAT_STACK, 0


#---------------------------------------------------------------------------
# Register equates and stack layout for MRInterpolateQuaternionsBToMatrixASM

new_struct
struct_entry MRIQUATBM_STACK_arg_0, 4
struct_entry MRIQUATBM_STACK_arg_1, 4
struct_entry MRIQUATBM_STACK_arg_2, 4
struct_entry MRIQUATBM_STACK_arg_3, 4
struct_entry MRIQUATBM_STACK_s0, 4
struct_entry MRIQUATBM_STACK_s1, 4
struct_entry MRIQUATBM_STACK_s2, 4
struct_entry MRIQUATBM_STACK_s3, 4
struct_entry MRIQUATBM_STACK_s4, 4
struct_entry MRIQUATBM_STACK_s5, 4
struct_entry MRIQUATBM_STACK_s6, 4
struct_entry MRIQUATBM_STACK_s7, 4
struct_entry MRIQUATBM_STACK_s8, 4
struct_entry MRIQUATBM_STACK_ra, 4
struct_entry MRIQUATBM_STACK_dquat, 8
struct_entry sizeof_MRIQUATBM_STACK, 0

