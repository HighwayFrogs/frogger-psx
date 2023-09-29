/******************************************************************************
*%%%% mr_math.h
*------------------------------------------------------------------------------
*
*	Maths functions
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	11.10.96	Tim Closs		Created
*	11.03.97	Dean Ashton		Added prototypes for MR<x>Modulus<Squared>
*	04.04.97	Dean Ashton		Added MRGenerateYXMatrixFromZColumn and 
*					 			MRGenerateMatrixFromZAxisAndZYPlane
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

#else
#ifndef	__MR_MATH_H
#define	__MR_MATH_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_PLANE_XY	 				(1<<0)	// indicates the XY plane
#define	MR_PLANE_YZ	 				(1<<1)	// indicates the YZ plane
#define	MR_PLANE_ZX	 				(1<<2)	// indicates the ZX plane

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_BOOL		MRIntersectInfiniteLineInfiniteLine2D(MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*);
extern	MR_BOOL		MRIntersectInfiniteLineFiniteLine2D(MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*);
extern	MR_BOOL		MRIntersectFiniteLineFiniteLine2D(MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*, MR_SVEC*);
extern	MR_LONG		MRAngleBetweenLines(MR_SVEC*, MR_SVEC*);

extern	MR_VOID		MRGenerateYXMatrixFromZColumn(MR_MAT*);
extern	MR_VOID		MRGenerateMatrixFromZAxisAndZYPlane(MR_MAT*, MR_VEC*, MR_VEC*);

#endif	//__MR_MATH_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
















									
