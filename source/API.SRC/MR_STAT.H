/******************************************************************************
*%%%% mr_stat.h
*------------------------------------------------------------------------------
*
*	Functions for handling static MOFs
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	20.08.96	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

#else
#ifndef	__MR_STAT_H
#define	__MR_STAT_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID				MRStaticResolveMOF(MR_MOF*);
extern	MR_VOID				MRStaticResolveMOFTextures(MR_MOF*);
extern	MR_VOID				MRStaticUnresolveMOFTextures(MR_MOF*);
extern	MR_VOID				MRStaticPatchMOFTranslucency(MR_MOF*, MR_BOOL);
extern	MR_VOID				MRStaticDisplayMeshInstance(MR_MESH_INST*, MR_VIEWPORT*, MR_UBYTE, MR_UBYTE);

#endif	//__MR_STAT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS










