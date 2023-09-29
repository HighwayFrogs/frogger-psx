/******************************************************************************
*%%%% mr_fast.h
*------------------------------------------------------------------------------
*
*	Variables placed on PlayStation Data Cache (1k Memory Mapped)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.06.96	Dean Ashton		Created
*	25.09.96	Tim Closs		Removed MRColl_matrix_ptr
*	13.12.96	Dean Ashton		Added MRVp_ptr
*	11.03.97	Dean Ashton		Removed MRFast_frame, added MRFast_long
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
// Typedefs
//------------------------------------------------------------------------------------------------

#else
#ifndef	__MR_FAST_H
#define	__MR_FAST_H

//------------------------------------------------------------------------------------------------
// Externs
//------------------------------------------------------------------------------------------------

extern	MR_ULONG		MRFrame_index;

extern	MR_VIEWPORT*	MRDefault_vp;
extern	MR_ULONG*		MRDefault_vp_ot;

extern	MR_LONG			MRFast_long;

extern	MR_MAT			MRViewtrans;
extern	MR_MAT*			MRViewtrans_ptr;
extern	MR_MAT*			MRWorldtrans_ptr;

extern	MR_MAT			MRLight_matrix;
extern	MR_MAT*			MRLight_matrix_ptr;

extern	MR_MAT			MRTemp_matrix;
extern	MR_SVEC			MRTemp_svec;

extern	MR_VIEWPORT*	MRVp_ptr;
extern	MR_USHORT		MRVp_otz_shift;
extern	MR_USHORT		MRVp_ot_size;
extern	MR_USHORT		MRVp_disp_w;
extern	MR_USHORT		MRVp_disp_h;
extern	MR_ULONG		MRVp_fog_near_distance;
extern	MR_ULONG		MRVp_fog_far_distance;
extern	MR_ULONG*		MRVp_work_ot;

#endif	//__MR_FAST_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS









