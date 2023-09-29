/******************************************************************************
*%%%% mr_sys.h
*------------------------------------------------------------------------------
*
*	Header file for Millennium API, declaring API data types, and also some
*	macros that remove the need for direct PlayStation macros (as defined in
*	"system.h")
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	06.06.96	Tim Closs		Added a couple of macros and Fixed point types
*	19.06.96	Tim Closs		Added _ADD_(S)VEC_ABC, _SUB_(S)VEC_ABC macros
*	19.06.96	Tim Closs		Corrected MRNormaliseSVEC to
*								MRNormaliseVECToSVEC
*	26.07.96	Tim Closs		Added MRApplyRotMatrixVEC 		(ApplyRotMatrixLV)
*								Added MROuterProduct			(OuterProduct0)
*								Added MROuterProduct12			(OuterProduct12)
*								Added MRApplyTransposeMatrix	(ApplyTransposeMatrix)
*								Added MRApplyTransposeMatrixVEC	(ApplyTransposeMatrixLV)
*	11.09.96	Dean Ashton		Added MR_FRAC8/UFRAC8, MR_FAILURE/SUCCESS, MR_FP_PI/PI2
*					 			and MRPrint for PC compatibility.
*	10.10.96	Tim Closs		Added MR_SVEC_MODULUS macro
*	12.02.97	Tim Closs		Moved MR_BBOX from mr_mof.h
*	14.02.97	Tim Closs		Supports MR_BIG_ENDIAN
*	11.03.97	Dean Ashton		Changed MR_VEC_MODULUS macro names...
*	13.06.97	Tim Closs		Added MR_SCALE_MATRIX macro.  This scales row 0
*								by x, row 1 by y, row 2 by z.  Needs optimisation for PC
*								and PSX
*
*%%%**************************************************************************/

#ifndef	__MR_SYS_H
#define	__MR_SYS_H

#include	"..\system.h"					// PSX system file


// Defines

#define		MR_API_VERSION		"Millennium API Version 1.32 (c)1997 Millennium Interactive Ltd"

#define		MR_FP_VEC			(16)			// number of fractional bits in some MR_VEC entry uses
#define		MR_FP_MAT			(12)			// number of fractional bits in MR_MAT entries

#define		MR_FP_PI			(1<<(MR_FP_MAT-1))
#define		MR_FP_PI2			(1<<MR_FP_MAT)

#define		MR_FAILURE			(FALSE)
#define		MR_SUCCESS			(TRUE)

#define		MRPrintf			printf

// Variable definitions
typedef		BYTE				MR_BYTE;
typedef		UBYTE				MR_UBYTE;
typedef		SHORT				MR_SHORT;
typedef		USHORT				MR_USHORT;
typedef		LONG				MR_LONG;
typedef		ULONG				MR_ULONG;
#define		MR_LONG64			long long
#define		MR_ULONG64			unsigned long long

typedef		VOID				MR_VOID;
typedef		BOOL				MR_BOOL;
typedef		STRPTR				MR_STRPTR;
typedef		TEXT				MR_TEXT;

// Fixed width variable definitions
typedef		BYTE				MR_8;
typedef		SHORT				MR_16;
typedef		LONG				MR_32;

// Fixed point variables
typedef		LONG				MR_FRAC8;
typedef		LONG				MR_FRAC12;
typedef		LONG				MR_FRAC16;
typedef		ULONG				MR_UFRAC8;
typedef		ULONG				MR_UFRAC12;
typedef		ULONG				MR_UFRAC16;

// API structure definitions
typedef		VECTOR				MR_VEC;
typedef		SVECTOR				MR_SVEC;
typedef		MATRIX				MR_MAT;
typedef		CVECTOR				MR_CVEC;
typedef		RECT				MR_RECT;
typedef		struct	__mr_xy		MR_XY;
typedef		struct	__mr_link	MR_LINK;
typedef  	struct 	__mr_bbox	MR_BBOX;
typedef  	struct 	__mr_mat33	MR_MAT33;

// Structures
struct	__mr_xy
	{
	MR_SHORT		x;
	MR_SHORT		y;

	};		// MR_XY


struct	__mr_link
	{
	MR_LINK*		ml_next;
	MR_LINK*		ml_prev;			

	};		// MR_LINK


struct	__mr_bbox
	{
	MR_SVEC		mb_verts[8];

	};		//	MR_BBOX


struct	__mr_mat33
	{
	MR_SHORT		m[3][3];
	MR_SHORT		pad;

	};		//	MR_MAT33


// Macros
#define		MR_MAKE_ID(a,b,c,d)	(((a)<<24)|((b)<<16)|((c)<<8)|((d)<<0))

#define		MR_CLEAR(item)		(memset(&item, 0, sizeof(item)))

#define		MR_SET8(a, b)		(*(MR_BYTE*)(&a)	= b)
#define		MR_SET16(a, b)		(*(MR_SHORT*)(&a) 	= b)
#define		MR_SET32(a, b)		(*(MR_LONG*)(&a)	= b)
#define		MR_COPY8(a, b)		(*(MR_BYTE*)(&a)	= *(MR_BYTE*)(&b))
#define		MR_COPY16(a, b)		(*(MR_SHORT*)(&a)	= *(MR_SHORT*)(&b))
#define		MR_COPY32(a, b)		(*(MR_LONG*)(&a)	= *(MR_LONG*)(&b))

#define		MR_SQR(a)			((a) * (a))
#define		MR_SQRT				SquareRoot0

#define		MR_SET_VEC(v,x,y,z)		setVector(v,x,y,z)
#define		MR_SET_SVEC(v,x,y,z)	setVector(v,x,y,z)

#define		MR_COPY_MAT(a, b) \
				*(((MR_LONG*)(a)) + 0) = *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) = *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(a)) + 2) = *(((MR_LONG*)(b)) + 2), \
				*(((MR_LONG*)(a)) + 3) = *(((MR_LONG*)(b)) + 3), \
				*(((MR_SHORT*)(a)) + 8) = *(((MR_SHORT*)(b)) + 8)

#define		MR_CLEAR_VEC(a) \
				*(((MR_LONG*)(a)) + 0) = 0, \
				*(((MR_LONG*)(a)) + 1) = 0, \
				*(((MR_LONG*)(a)) + 2) = 0

#define		MR_CLEAR_SVEC(a) \
				*((MR_LONG*)(a)) = 0, \
				*(((MR_SHORT*)(a)) + 2) = 0

#define		MR_CLEAR_MAT(a) \
				*(((MR_LONG*)(a)) + 0) = 0, \
				*(((MR_LONG*)(a)) + 1) = 0, \
				*(((MR_LONG*)(a)) + 2) = 0, \
				*(((MR_LONG*)(a)) + 3) = 0, \
				*(((MR_SHORT*)(a)) + 8) = 0

#ifdef MR_BIG_ENDIAN
#define		MR_INIT_MAT(a) \
				*(((MR_LONG*)(a)) + 0) = 0x10000000, \
				*(((MR_LONG*)(a)) + 1) = 0x00000000, \
				*(((MR_LONG*)(a)) + 2) = 0x10000000, \
				*(((MR_LONG*)(a)) + 3) = 0x00000000, \
				*(((MR_SHORT*)(a)) + 8) = 0x1000
#else
#define		MR_INIT_MAT(a) \
				*(((MR_LONG*)(a)) + 0) = 0x00001000, \
				*(((MR_LONG*)(a)) + 1) = 0x00000000, \
				*(((MR_LONG*)(a)) + 2) = 0x00001000, \
				*(((MR_LONG*)(a)) + 3) = 0x00000000, \
				*(((MR_SHORT*)(a)) + 8) = 0x1000
#endif

#define		MR_COPY_VEC(a, b) \
				*(((MR_LONG*)(a)) + 0) = *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) = *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(a)) + 2) = *(((MR_LONG*)(b)) + 2)

#define		MR_COPY_QUAT(a, b) \
				*(((MR_LONG*)(a)) + 0) = *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) = *(((MR_LONG*)(b)) + 1)

#define		MR_COPY_SVEC(a, b) \
				*(((MR_LONG*)(a)) + 0) = *(((MR_LONG*)(b)) + 0), \
				*(((MR_SHORT*)(a)) + 2) = *(((MR_SHORT*)(b)) + 2)

#define		MR_ADD_VEC(a, b) \
				*(((MR_LONG*)(a)) + 0) += *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) += *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(a)) + 2) += *(((MR_LONG*)(b)) + 2)
					
#define		MR_SUB_VEC(a, b) \
				*(((MR_LONG*)(a)) + 0) -= *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) -= *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(a)) + 2) -= *(((MR_LONG*)(b)) + 2)
				
#define		MR_ADD_SVEC(a, b) \
				*(((MR_SHORT*)(a)) + 0) += *(((MR_SHORT*)(b)) + 0), \
				*(((MR_SHORT*)(a)) + 1) += *(((MR_SHORT*)(b)) + 1), \
				*(((MR_SHORT*)(a)) + 2) += *(((MR_SHORT*)(b)) + 2)
				
#define		MR_SUB_SVEC(a, b) \
				*(((MR_SHORT*)(a)) + 0) -= *(((MR_SHORT*)(b)) + 0), \
				*(((MR_SHORT*)(a)) + 1) -= *(((MR_SHORT*)(b)) + 1), \
				*(((MR_SHORT*)(a)) + 2) -= *(((MR_SHORT*)(b)) + 2)

#define		MR_VEC_MOD_SQR(a) \
				((a)->vx*(a)->vx + (a)->vy*(a)->vy +(a)->vz*(a)->vz)

#define		MR_VEC_MOD(a) \
				(MR_SQRT((a)->vx*(a)->vx + (a)->vy*(a)->vy +(a)->vz*(a)->vz))

#define		MR_SVEC_MOD_SQR(a)	MR_VEC_MOD_SQR(a)

#define		MR_SVEC_MOD(a)		MR_VEC_MOD(a)

#define		MR_SVEC_DOT_SVEC(a, b) \
				(((MR_SHORT*)(a))[0] * ((MR_SHORT*)(b))[0] + ((MR_SHORT*)(a))[1] * ((MR_SHORT*)(b))[1] + ((MR_SHORT*)(a))[2] * ((MR_SHORT*)(b))[2])

#define		MR_VEC_DOT_VEC(a, b) \
				(((MR_LONG*)(a))[0] * ((MR_LONG*)(b))[0] + ((MR_LONG*)(a))[1] * ((MR_LONG*)(b))[1] + ((MR_LONG*)(a))[2] * ((MR_LONG*)(b))[2])

#define		MR_SVEC_DOT_VEC(a, b) \
				(((MR_SHORT*)(a))[0] * ((MR_LONG*)(b))[0] + ((MR_SHORT*)(a))[1] * ((MR_LONG*)(b))[1] + ((MR_SHORT*)(a))[2] * ((MR_LONG*)(b))[2])

#define		MR_ADD_VEC_ABC(a, b, c) \
				*(((MR_LONG*)(c)) + 0) = *(((MR_LONG*)(a)) + 0) + *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(c)) + 1) = *(((MR_LONG*)(a)) + 1) + *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(c)) + 2) = *(((MR_LONG*)(a)) + 2) + *(((MR_LONG*)(b)) + 2)

#define		MR_SUB_VEC_ABC(a, b, c) \
				*(((MR_LONG*)(c)) + 0) = *(((MR_LONG*)(a)) + 0) - *(((MR_LONG*)(b)) + 0), \
				*(((MR_LONG*)(c)) + 1) = *(((MR_LONG*)(a)) + 1) - *(((MR_LONG*)(b)) + 1), \
				*(((MR_LONG*)(c)) + 2) = *(((MR_LONG*)(a)) + 2) - *(((MR_LONG*)(b)) + 2)

#define		MR_ADD_SVEC_ABC(a, b, c) \
				*(((MR_SHORT*)(c)) + 0) = *(((MR_SHORT*)(a)) + 0) + *(((MR_SHORT*)(b)) + 0), \
				*(((MR_SHORT*)(c)) + 1) = *(((MR_SHORT*)(a)) + 1) + *(((MR_SHORT*)(b)) + 1), \
				*(((MR_SHORT*)(c)) + 2) = *(((MR_SHORT*)(a)) + 2) + *(((MR_SHORT*)(b)) + 2)

#define		MR_SUB_SVEC_ABC(a, b, c) \
				*(((MR_SHORT*)(c)) + 0) = *(((MR_SHORT*)(a)) + 0) - *(((MR_SHORT*)(b)) + 0), \
				*(((MR_SHORT*)(c)) + 1) = *(((MR_SHORT*)(a)) + 1) - *(((MR_SHORT*)(b)) + 1), \
				*(((MR_SHORT*)(c)) + 2) = *(((MR_SHORT*)(a)) + 2) - *(((MR_SHORT*)(b)) + 2)

#define		MR_SVEC_EQUALS_VEC(a, b) \
				*(((MR_SHORT*)(a)) + 0) = *(((MR_LONG*)(b)) + 0), \
				*(((MR_SHORT*)(a)) + 1) = *(((MR_LONG*)(b)) + 1), \
				*(((MR_SHORT*)(a)) + 2) = *(((MR_LONG*)(b)) + 2)

#define		MR_VEC_EQUALS_SVEC(a, b) \
				*(((MR_LONG*)(a)) + 0) = *(((MR_SHORT*)(b)) + 0), \
				*(((MR_LONG*)(a)) + 1) = *(((MR_SHORT*)(b)) + 1), \
				*(((MR_LONG*)(a)) + 2) = *(((MR_SHORT*)(b)) + 2)

#define		MR_SCALE_MATRIX(a, b, c, d) \
				MRScale_matrix.m[0][0] = (b), \
				MRScale_matrix.m[1][1] = (c), \
				MRScale_matrix.m[2][2] = (d), \
				MRMulMatrixABB(&MRScale_matrix, (a))

// Special GTE load/save macros (not found in the normal PlayStation header files
#define		gte_stdq(r0, r1) __asm__ volatile ( \
				"cfc2 $12, $27;" \
				"cfc2 $13, $28;" \
				"sw   $12, 0(%0);" \
				"sw   $13, 0(%1)" \
				: \
				: "r"(r0), "r"(r1) \
				: "$12", "$13", "memory")

// GTE instruction macros (with nops)
#define		gte_mvmva(sf,mx,v,cv,lm)  gte_mvmva_core(0x000013bf | ((sf)<<25) | ((mx)<<23) | ((v)<<21) | ((cv)<<19) | ((lm)<<18))
#define		gte_mvmva_core( r0 ) __asm__ volatile ( \
				"nop;" \
				"nop;" \
				".word %0" \
				: \
				: "g"( r0 ) )

// GTE instruction macros (without any extra nops) for more precise control of CPU cycles
#define		gte_mvmva_b(sf,mx,v,cv,lm)  gte_mvmva_core_b(0x000013bf | ((sf)<<25) | ((mx)<<23) | ((v)<<21) | ((cv)<<19) | ((lm)<<18))
#define		gte_mvmva_core_b( r0 ) __asm__ volatile ( \
				".word %0" \
				: \
				: "g"( r0 ) )


// MRAcos_table access macros
#define		MR_ACOS_RAW(a) \
				MRAcos_table[(a) + 0x1000]

#define		MR_ACOS(a) \
				MRAcos_table[MIN(MAX((a), -0x1000), 0x1000) + 0x1000]


// Special overrides for PC filesystem functions provided in LIBSN.H, to enable a DDX version with no code changes

#ifdef		MR_USE_DDX_FILESYSTEM
#undef		pollhost
#define		pollhost()		DDXpollhost()
#define		PCopen(a,b,c)	DDXopen((a),(b))
#define		PCcreat			DDXcreate
#define		PClseek			DDXlseek
#define		PCread			DDXread
#define		PCwrite			DDXwrite
#define		PCclose			DDXclose
#define		PCinit			DDXinit
#endif			


// The following macros were written as API abstractions of PSX GTE macros or functions
#define		MRApplyMatrix				ApplyMatrix				// matrix.svec	=	vec
#define		MRApplyRotMatrix			ApplyRotMatrix			// (rotm).svec	=	vec
#define		MRApplyRotMatrixVEC			ApplyRotMatrixLV		//	(rotm).vec	=	vec
#define		MRApplyMatrixSVEC			ApplyMatrixSV			// matrix.svec	=	svec
#define		MRApplyMatrixVEC 			ApplyMatrixLV			// matrix.vec	=	vec
#define		MRTransposeMatrix			TransposeMatrix
#define		MRApplyTransposeMatrixVEC	ApplyTransposeMatrixLV
#define		MRMulMatrixABC				MulMatrix0
#define		MRMulMatrixABA				MulMatrix
#define		MRMulMatrixABB				MulMatrix2
#define		MRRotMatrix					RotMatrix
#define		MRRotMatrixX				RotMatrixX
#define		MRRotMatrixY				RotMatrixY
#define		MRRotMatrixZ				RotMatrixZ
#define		MRRotTransPers				RotTransPers
#define		MRNormaliseVEC				VectorNormal
#define		MRNormaliseVECToSVEC		VectorNormalS
#define		MROuterProduct				OuterProduct0
#define		MROuterProduct12			OuterProduct12

#define		MRAPPLYMATRIX				gte_ApplyMatrix
#define		MRAPPLYROTMATRIX			gte_ApplyRotMatrix
#define		MRMULMATRIXABC				gte_MulMatrix0

#endif	// __MR_SYS_H














