/******************************************************************************
*%%%% mr_anim2.h
*------------------------------------------------------------------------------
*
*	Functions for handling multiple environments
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	24.03.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

#else
#ifndef	__MR_ANIM2_H
#define	__MR_ANIM2_H

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

// Multiple environment
extern	MR_ANIM_ENV*		MRAnimEnvMultipleCreate(MR_VOID);
extern	MR_VOID				MRAnimEnvMultipleLoad(MR_ANIM_ENV*, MR_ANIM_HEADER*, MR_USHORT);
extern	MR_ANIM_ENV*		MRAnimEnvMultipleCreateWhole(MR_ANIM_HEADER*, MR_USHORT, MR_USHORT, MR_FRAME*);
extern	MR_VOID				MRAnimEnvMultipleInit(MR_ANIM_ENV*,	MR_ANIM_HEADER*, MR_USHORT, MR_USHORT);
extern	MR_VOID				MRAnimEnvMultipleEndInit(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvMultipleAddModel(MR_ANIM_ENV*, MR_USHORT);
extern	MR_UBYTE			MRAnimEnvMultipleSetPartFlags(MR_ANIM_ENV*, MR_USHORT, MR_USHORT,	MR_UBYTE);
extern	MR_UBYTE			MRAnimEnvMultipleClearPartFlags(MR_ANIM_ENV*, MR_USHORT, MR_USHORT, MR_UBYTE);
extern	MR_UBYTE			MRAnimEnvMultipleGetPartFlags(MR_ANIM_ENV*, MR_USHORT, MR_USHORT);
extern	MR_VOID				MRAnimEnvMultipleDeletePartFlags(MR_ANIM_ENV*);
extern	MR_MAT**			MRAnimEnvMultipleCreateLWTransforms(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvMultipleDeleteLWTransforms(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvMultipleSetImportedTransform(MR_ANIM_ENV*, MR_USHORT, MR_USHORT, MR_MAT*);
extern	MR_VOID				MRAnimEnvMultipleClearImportedTransform(MR_ANIM_ENV*, MR_USHORT, MR_USHORT);
extern	MR_MAT*				MRAnimEnvMultipleGetImportedTransform(MR_ANIM_ENV*, MR_USHORT,	MR_USHORT);
extern	MR_VOID				MRAnimEnvMultipleDeleteImportedTransforms(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvMultipleSetAction(MR_ANIM_ENV*, MR_USHORT, MR_SHORT);
extern	MR_VOID				MRAnimEnvMultipleSetActionAll(MR_ANIM_ENV*, MR_SHORT);
extern	MR_VOID				MRAnimEnvMultipleSetCel(MR_ANIM_ENV*, MR_USHORT, MR_SHORT);
extern	MR_VOID				MRAnimEnvMultipleSetCelAll(MR_ANIM_ENV*, MR_SHORT);

// Events
extern	MR_VOID				MRAnimEnvMultipleSetEvent(MR_ANIM_ENV*, MR_USHORT, MR_USHORT, MR_USHORT, MR_UBYTE, MR_UBYTE);
extern	MR_VOID				MRAnimEnvMultipleClearEvent(MR_ANIM_ENV*, MR_USHORT, MR_USHORT, MR_USHORT);

#endif	//__MR_ANIM2_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS 
