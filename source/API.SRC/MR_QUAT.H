/******************************************************************************
*%%%%	mr_quat.h
*------------------------------------------------------------------------------
*
*	Header file for API Quaternion routines
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96	Tim Closs		Created
*	17.03.97	Tim Closs		Removed MRMulQuaternionByEulers..() functions
*								Added MR_QUATB structure
*								Added MRQuaternionBToMatrix()
*								MRMatrixToQuaternionB()
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
// Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_quat		MR_QUAT;
typedef	struct	__mr_quatb		MR_QUATB;

#else
#ifndef	__MR_QUAT_H
#define	__MR_QUAT_H

//------------------------------------------------------------------------------------------------
// Defines
//------------------------------------------------------------------------------------------------

#define	MR_GTE_QUAT_SPEEDUPS		// This enables GTE implementation on PlayStation

#ifdef	MR_GTE_QUAT_SPEEDUPS
#define	MR_QUAT_TO_MAT(q,m)			   			MRQuaternionToMatrixASM(q,m)
#define	MR_QUATB_TO_MAT(q,m)		   			MRQuaternionBToMatrixASM(q,m)
#define	MR_INTERPOLATE_QUAT_TO_QUAT(s,e,d,t)	MRInterpolateQuaternionsASM(s,e,d,t)
#define	MR_INTERPOLATE_QUATB_TO_MAT(s,e,m,t)	MRInterpolateQuaternionsBToMatrixASM(s,e,m,t)
#else
#define	MR_QUAT_TO_MAT(q,m)			   			MRQuaternionToMatrix(q,m)
#define	MR_QUATB_TO_MAT(q,m)		   			MRQuaternionBToMatrix(q,m)
#define	MR_INTERPOLATE_QUAT_TO_QUAT(s,e,d,t)	MRInterpolateQuaternions(s,e,d,t)
#define	MR_INTERPOLATE_QUATB_TO_MAT(s,e,m,t)	MRInterpolateQuaternionsBToMatrix(s,e,m,t)
#endif

#define	MR_QUAT_EPSILON			1

//------------------------------------------------------------------------------------------------
// Structures
//------------------------------------------------------------------------------------------------

struct	__mr_quat
	{
	MR_SHORT	c;		// real
	MR_SHORT	x;		// pure i cpt
	MR_SHORT	y;		// pure j cpt
	MR_SHORT	z;		// pure k cpt

	};	//	MR_QUAT	// all elements 1.3.12 format


struct	__mr_quatb
	{
	MR_BYTE	c;		// real
	MR_BYTE	x;		// pure i cpt
	MR_BYTE	y;		// pure j cpt
	MR_BYTE	z;		// pure k cpt

	};	//	MR_QUATB	// all elements 1.1.6 format


//------------------------------------------------------------------------------------------------
// Externs
//------------------------------------------------------------------------------------------------

extern			MR_SHORT	MRAcos_table[];			// arccos table (input -4096..4096)


//------------------------------------------------------------------------------------------------
// Prototypes
//------------------------------------------------------------------------------------------------

extern			MR_VOID	MRQuaternionToMatrix(MR_QUAT*, MR_MAT*);
extern			MR_VOID	MRMatrixToQuaternion(MR_MAT*, MR_QUAT*);
extern			MR_VOID	MRMulQuaternionABC(MR_QUAT*, MR_QUAT*, MR_QUAT*);
extern			MR_VOID	MRNormaliseQuaternion(MR_QUAT*, MR_QUAT*, MR_USHORT);
extern			MR_VOID	MREulersToQuaternion(MR_QUAT*, MR_SHORT, MR_SHORT, MR_SHORT);
extern			MR_VOID	MRInterpolateQuaternions(MR_QUAT*, MR_QUAT*, MR_QUAT*, MR_USHORT);

// MR_QUATB functions
extern			MR_VOID	MRQuaternionBToMatrix(MR_QUATB*, MR_MAT*);
extern			MR_VOID	MRMatrixToQuaternionB(MR_MAT*, MR_QUATB*);
extern			MR_VOID	MRInterpolateQuaternionsBToMatrix(MR_QUATB*,	MR_QUATB*, MR_MAT*, MR_USHORT);

// Assembler routine prototypes
extern			MR_VOID	MRQuaternionToMatrixASM(MR_QUAT*, MR_MAT*);
extern			MR_VOID	MRQuaternionBToMatrixASM(MR_QUATB*, MR_MAT*);
extern			MR_VOID	MRInterpolateQuaternionsASM(MR_QUAT*, MR_QUAT*, MR_QUAT*, MR_USHORT);
extern			MR_VOID	MRInterpolateQuaternionsBToMatrixASM(MR_QUATB*,	MR_QUATB*, MR_MAT*, MR_USHORT);
extern			MR_VOID	MRNormaliseQuaternionASM(MR_QUAT*, MR_QUAT*, MR_USHORT);

#endif	//__MR_QUAT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS












