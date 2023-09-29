/******************************************************************************
*%%%% water.h
*------------------------------------------------------------------------------
*
*	Water handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__WATER_H
#define	__WATER_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define		WATER_SIN_OFFSET_TABLE_SHIFT			5
#define		WATER_SIN_OFFSET_TABLE_SIZE				(1<<WATER_SIN_OFFSET_TABLE_SHIFT)
#define		WATER_SIN_OFFSET_TABLE_SCALE_SHIFT		9			
#define		WATER_SIN_OFFSET_TABLE_SPEED			1
#define		WATER_SIN_OFFSET_TABLE_COS_OFFSET		(WATER_SIN_OFFSET_TABLE_SIZE>>2)	// quarter of table

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

// structures
typedef struct __fg_pgen_extra
{
	MR_SP_CORE	fpg_sp_core;							// sp_core used for animation (handled by anim code)
	MR_TEXTURE	*fpg_sp_buf[2];							// buffers to store texture pointers

} FG_PGEN_EXTRA;

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern 	MR_VOID		WaterInitialiseSinOffsetsTable(MR_VOID);
extern 	MR_VOID		WaterWibbleVertices(MR_SVEC**, MR_LONG);
extern 	MR_VOID		WaterGetSinCosOffsets(MR_SHORT*, MR_SHORT*);
extern	MR_OBJECT* 	WaterCreateSurfaceIndication(MR_VIEWPORT*, MR_VOID*	);


#endif
