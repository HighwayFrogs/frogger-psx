;///******************************************************************************
;//*%%%% filename.ext
;//*------------------------------------------------------------------------------
;//*
;//*	Used to hold API variables that reside in the PlayStation D-Cache, which
;//*	is a 1Kbyte memory mapped area at 0x1f800000. 
;//*
;//*	NOTE:	This file is included into the projects 'fastram.s'. Using this 
;//*		method, the main project has access to fastram, the API has access
;//*		to fastram, and the API use of fastram is hidden from the project.
;//*
;//*	CHANGED		PROGRAMMER	REASON
;//*	-------  	----------  	------
;//*	30.05.96	Dean Ashton	Created
;//*	25.09.96	Tim Closs	Removed MRColl_matrix_ptr
;//*	13.12.96	Dean Ashton	Added MRVp_ptr
;//*	11.03.97	Dean Ashton	Removed MRFast_frame, added MRFast_long
;//*
;//*%%%**************************************************************************/


MRFrame_index		rw	1		; MR_ULONG

MRDefault_vp		rw	1		; MR_VIEWPORT*
MRDefault_vp_ot		rw	1		; MR_ULONG*

MRFast_long		rw	1		; MR_LONG

MRViewtrans		rw	8		; MR_MAT		
MRViewtrans_ptr		rw	1		; MR_MAT*		
MRWorldtrans_ptr	rw	1		; MR_MAT*		
      
MRLight_matrix		rw	8		; MR_MAT	
MRLight_matrix_ptr	rw	1		; MR_MAT*		

MRTemp_matrix		rw	8		; MR_MAT
MRTemp_svec		rw	2		; MR_SVEC

MRVp_ptr		rw	1		; MR_VIEWPORT*
MRVp_otz_shift		rh	1		; MR_USHORT		
MRVp_ot_size		rh	1		; MR_USHORT		
MRVp_fog_near_distance	rw	1		; MR_ULONG
MRVp_fog_far_distance	rw	1		; MR_ULONG
MRVp_disp_w		rh	1		; MR_USHORT
MRVp_disp_h		rh	1		; MR_USHORT
MRVp_work_ot		rw	1		; MR_ULONG*		



