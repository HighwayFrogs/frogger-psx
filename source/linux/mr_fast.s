#///******************************************************************************
#//*%%%% mr_fast.s
#//*------------------------------------------------------------------------------
#//*
#//*	Used to hold API variables that reside in the PlayStation D-Cache, which
#//*	is a 1Kbyte memory mapped area at 0x1f800000. 
#//*
#//*	NOTE:	This file is included into the projects 'fastram.s'. Using this 
#//*		method, the main project has access to fastram, the API has access
#//*		to fastram, and the API use of fastram is hidden from the project.
#//*
#//*	CHANGED		PROGRAMMER		REASON
#//*	-------		----------		------
#//*	30.05.96	Dean Ashton		Created
#//*	25.09.96	Tim Closs		Removed MRColl_matrix_ptr
#//*	13.12.96	Dean Ashton		Added MRVp_ptr
#//*	11.03.97	Dean Ashton		Removed MRFast_frame, added MRFast_long
#//*	23.22.11	Kneesnap		Ported to GNU AS Syntax
#//*
#//*%%%**************************************************************************/

	# MR_ULONG
	.global MRFrame_index
MRFrame_index:
	.space	4

	# MR_VIEWPORT*
	.global MRDefault_vp
MRDefault_vp:
	.space	4

	# MR_ULONG*
	.global MRDefault_vp_ot
MRDefault_vp_ot:
	.space	4

	# MR_LONG
	.global MRFast_long
MRFast_long:
	.space	4

	# MR_MAT
	.global MRViewtrans
MRViewtrans:
	.space	32

	# MR_MAT*
	.global MRViewtrans_ptr
MRViewtrans_ptr:
	.space	4

	# MR_MAT*
	.global MRWorldtrans_ptr
MRWorldtrans_ptr:
	.space	4

	# MR_MAT
	.global MRLight_matrix
MRLight_matrix:
	.space	32

	# MR_MAT*
	.global MRLight_matrix_ptr
MRLight_matrix_ptr:
	.space	4

	# MR_MAT
	.global MRTemp_matrix
MRTemp_matrix:
	.space	32

	# MR_SVEC
	.global MRTemp_svec
MRTemp_svec:
	.space	8

	# MR_VIEWPORT*
	.global MRVp_ptr
MRVp_ptr:
	.space	4

	# MR_USHORT
	.global MRVp_otz_shift
MRVp_otz_shift:
	.space	2

	# MR_USHORT
	.global MRVp_ot_size
MRVp_ot_size:
	.space	2

	# MR_ULONG
	.global MRVp_fog_near_distance
MRVp_fog_near_distance:
	.space	4

	# MR_ULONG
	.global MRVp_fog_far_distance
MRVp_fog_far_distance:
	.space	4

	# MR_USHORT
	.global MRVp_disp_w
MRVp_disp_w:
	.space	2

	# MR_USHORT
	.global MRVp_disp_h
MRVp_disp_h:
	.space	2

	# MR_ULONG*
	.global MRVp_work_ot
MRVp_work_ot:
	.space	4
