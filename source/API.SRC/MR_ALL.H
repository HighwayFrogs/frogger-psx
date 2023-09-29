/******************************************************************************
*%%%% mr_all.h
*------------------------------------------------------------------------------
*
*	General header for Millennium API development. Access to API functions and
*	data structures can only happen through the inclusion of this header file.
*	As such, all projects wishing to use the API in a module must include this
*	header file in the module header.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	14.05.96	Dean Ashton		Created
*	20.08.96	Dean Ashton		Added mr_stat.h and mr_anim.h
*
*%%%**************************************************************************/

#ifndef		__MR_ALL_H
#define		__MR_ALL_H

// Include root system file
#include	"mr_sys.h"

#define		__MR_ONLY_INCLUDE_TYPEDEFS
#include	"mr_inc.h"
#undef		__MR_ONLY_INCLUDE_TYPEDEFS

#include	"mr_inc.h"

#endif	//	__MR_ALL_H


