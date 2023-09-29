/******************************************************************************
*%%%% mr_misc.h
*------------------------------------------------------------------------------
*
*	Header file for mr_misc.c
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	14.05.96	Tim Closs		Created
*	02.09.96	Tim Closs		Created MRGenerateMatrixFromZAxisAndZYPlane
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//-----------------------------------------------------------------------------
// Typedefs
//-----------------------------------------------------------------------------

#else
#ifndef	__MR_MISC_H
#define	__MR_MISC_H

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Externals
//-----------------------------------------------------------------------------

extern	MR_MAT			MRScale_matrix;
extern	MR_MAT			MRRot_matrix_X;
extern	MR_MAT			MRRot_matrix_Y;
extern	MR_MAT			MRRot_matrix_Z;
extern	MR_MAT			MRId_matrix;

extern	MR_CVEC			MRCvec_ft3;
extern	MR_CVEC			MRCvec_ft4;
extern	MR_CVEC			MRCvec_gt3;
extern	MR_CVEC			MRCvec_gt4;

extern	MR_VEC			MRNull_vec;
extern	MR_SVEC			MRNull_svec;

volatile extern	MR_LONG		MRRnd_seed;

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			MRInitialise(MR_VOID);

#endif	//__MR_MISC_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS










