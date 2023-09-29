/******************************************************************************
*%%%% binaries.h
*------------------------------------------------------------------------------
*
*	Binary data that's linked into the project via 'binaries.s' needs external
*	references to be made available. This is what this file is...
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	28.5.96		Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef		__BINARIES_H
#define		__BINARIES_H

#include	"mr_all.h"

extern		MR_RESINFO	frogpsx_mwi[];			// MWI reference, actually in Binaries.s
extern		MR_USHORT	card_image[];

#endif		//__BINARIES_H
