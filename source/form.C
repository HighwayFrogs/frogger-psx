/******************************************************************************
*%%%% form.h
*------------------------------------------------------------------------------
*
*	General form handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "form.h"
#include "formlib.h"


FORM_BOOK*	Form_library_ptrs[2];	// [0] points to Form_library_???, [1] points to Form_library_gen

//FORM_BOOK*	Form_libraries[] =
//	{
//	Form_library_gen,
//	Form_library_cav,
//	Form_library_des,
//	Form_library_for,
//	Form_library_jun,
//	Form_library_org,
//	Form_library_arn,
//	Form_library_swp,
//	Form_library_sky,
//	Form_library_sub,
//	Form_library_vol,
//	};
//
//
///******************************************************************************
//*%%%% InitialiseFormLibrary
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	InitialiseFormLibrary(MR_VOID)
//*
//*	FUNCTION	Set up Form_library_ptrs
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	06.05.97	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	InitialiseFormLibrary(MR_VOID)
//{
//	Form_library_ptrs[0] = Form_libraries[THEME_GEN];
//	Form_library_ptrs[1] = Form_libraries[Game_map_theme];
//}

