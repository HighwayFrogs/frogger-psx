/******************************************************************************
*%%%% filename.h
*------------------------------------------------------------------------------
*
*	<Description>
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	xx.xx.97	<Name>			Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//-----------------------------------------------------------------------------
//	Typedefs
//-----------------------------------------------------------------------------

typedef struct __mr_exregisters	MR_EXREGISTERS;
typedef	struct __mr_tim4_header MR_TIM4_HEADER;

#else
#ifndef	__MR_CRASH_H
#define	__MR_CRASH_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	MR_EXCEPTION_FORCE_INSTALL	(TRUE)
#define	MR_EXCEPTION_AUTO_INSTALL	(FALSE)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

struct	__mr_exregisters
		{
		MR_ULONG	ex_zero;
		MR_ULONG	ex_at;
		MR_ULONG	ex_v0;
		MR_ULONG	ex_v1;
		MR_ULONG	ex_a0;
		MR_ULONG	ex_a1;
		MR_ULONG	ex_a2;
		MR_ULONG	ex_a3;
		MR_ULONG	ex_t0;
		MR_ULONG	ex_t1;
		MR_ULONG	ex_t2;
		MR_ULONG	ex_t3;
		MR_ULONG	ex_t4;
		MR_ULONG	ex_t5;
		MR_ULONG	ex_t6;
		MR_ULONG	ex_t7;
		MR_ULONG	ex_s0;
		MR_ULONG	ex_s1;
		MR_ULONG	ex_s2;
		MR_ULONG	ex_s3;
		MR_ULONG	ex_s4;
		MR_ULONG	ex_s5;
		MR_ULONG	ex_s6;
		MR_ULONG	ex_s7;
		MR_ULONG	ex_t8;
		MR_ULONG	ex_t9;
		MR_ULONG	ex_k0;
		MR_ULONG	ex_k1;
		MR_ULONG	ex_gp;
		MR_ULONG	ex_sp;
		MR_ULONG	ex_fp;
		MR_ULONG	ex_ra;
		MR_ULONG	ex_hi;
		MR_ULONG	ex_lo;
		MR_ULONG	ex_sr;
		MR_ULONG	ex_ca;
		MR_ULONG	ex_epc;
		};		// MR_EXREGISTERS;

struct	__mr_tim4_header
		{
		MR_ULONG	tim_id;
		MR_ULONG	tim_flags;
		MR_ULONG	tim_clutbnum;
		MR_ULONG	tim_clutxy;
		MR_ULONG	tim_clutw;
		MR_USHORT	tim_clut[16];
		MR_ULONG	tim_pixelbnum;
		MR_ULONG	tim_pixelxy;
		MR_ULONG	tim_pixelwh;
		MR_ULONG	tim_pixel[1];
		};		// MR_TIM4_HEADER	

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#ifdef	MR_USE_ASSERTS
#define	MR_ASSERT(f) \
			if (f) \
				{} \
			else \
				{ \
				sprintf(MREx_user, "Assert: %s (%s, %u)", __FUNCTION__, __FILE__, __LINE__); \
				MREx_text_ptr = MREx_user; \
				if (MREx_installed) \
					{asm(".word 0x4e000000");} \
				else \
					{ \
					printf("%s\n",MREx_user); \
					while(1) \
						{ \
						pollhost(); \
						} \
					} \
				}

#define	MR_ASSERTMSG(f,str) \
			if (f) \
				{} \
			else \
				{ \
				sprintf(MREx_user, "Assert: %s (%s, %u) : %s", __FUNCTION__, __FILE__, __LINE__, str); \
				MREx_text_ptr = MREx_user; \
				if (MREx_installed) \
					{asm(".word 0x4e000000");} \
				else \
					{ \
					printf("%s\n",MREx_user); \
					while(1) \
						{ \
						pollhost(); \
						} \
					} \
				}
#else
#define	MR_ASSERT(f)
#define	MR_ASSERTMSG(f,str)
#endif

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_EXREGISTERS	MREx_registers;		// Register array (defined in mr_m_cra.s)
extern	MR_BOOL			MREx_force;			// TRUE if we forced an install of handler
extern	MR_BOOL			MREx_installed;		// TRUE if we took over the vector
extern	MR_STRPTR		MREx_text_ptr;		// Pointer to text for information line
extern	MR_TEXT			MREx_user[];		// Room for user error text
extern	MR_ULONG		MREx_font[];		// Font (defined in mr_m_cra.s)

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	MRExceptionInstall(MR_BOOL);
extern	MR_VOID MRExceptionShow(MR_VOID);
extern	MR_VOID	MRExceptionPrint(MR_STRPTR txt);

#endif	//__MR_CRASH_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS



