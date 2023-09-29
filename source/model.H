/******************************************************************************
*%%%% model.h
*------------------------------------------------------------------------------
*
*	Dummy models
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__MODEL_H
#define	__MODEL_H

#include "mr_all.h"
#include "effects.h"


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MODEL_MAX_MOFS				32			// max MOFs we want to store ptrs to for reference in code
#define	MODEL_TEXTURE_INDEX			(14 - 7)	// cube texture for debug


// MOF names
enum	{
		MODEL_MOF_CUBE_FT4,
		MODEL_MOF_CUBE_E4,

		MODEL_MOF_FROG_ANIMATIONS,
		MODEL_MOF_FROG_STATIC_0,				// this is contained in the .XMR
		MODEL_MOF_FROG_STATIC_1,
		MODEL_MOF_FROG_STATIC_2,
		MODEL_MOF_FROG_STATIC_3,
		MODEL_MOF_FROG_CONSTRUCTION_0,			// this simply points to the .XMR
		MODEL_MOF_FROG_CONSTRUCTION_1,
		MODEL_MOF_FROG_CONSTRUCTION_2,
		MODEL_MOF_FROG_CONSTRUCTION_3,
		MODEL_MOF_FROG_FLIPBOOK_0,				// contains vertex blocks
		MODEL_MOF_FROG_FLIPBOOK_1,				// ..resolved to point to vertex blocks in FLIPBOOK_0
		MODEL_MOF_FROG_FLIPBOOK_2,
		MODEL_MOF_FROG_FLIPBOOK_3,
		MODEL_MOF_CHECKPOINT_FLIPBOOK_0,		// contains vertex blocks
		MODEL_MOF_CHECKPOINT_FLIPBOOK_1,		// ..resolved to point to vertex blocks in FLIPBOOK_0
		MODEL_MOF_CHECKPOINT_FLIPBOOK_2,
		MODEL_MOF_CHECKPOINT_FLIPBOOK_3,
		MODEL_MOF_CHECKPOINT_FLIPBOOK_4,
		MODEL_MOF_MULTIPOINT_FLIPBOOK_0,		// contains vertex blocks
		MODEL_MOF_MULTIPOINT_FLIPBOOK_1,		// ..resolved to point to vertex blocks in FLIPBOOK_0
		MODEL_MOF_MULTIPOINT_FLIPBOOK_2,
		MODEL_MOF_MULTIPOINT_FLIPBOOK_3,
		MODEL_MOF_MULTIPOINT_FLIPBOOK_4,
		};

// Frog hilite types
enum	{
		MODEL_FROG_HILITE_COLLISION,
		MODEL_FROG_HILITE_SPLASH,
		MODEL_FROG_HILITE_WAKE,
		MODEL_FROG_HILITE_TRAIL_LEFT,
		MODEL_FROG_HILITE_TRAIL_RIGHT,
		};

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------

extern	MR_ULONG	Model_MOF_cube_ft4[];
extern	MR_ULONG	Model_MOF_cube_e4[];

extern	MR_MOF*		Model_MOF_ptrs[];
extern	POLY_PIECE*	Frog_model_pieces;
extern	MR_MOF*	   	Frog_model_pieces_mof;
extern	MR_LONG	   	Frog_model_pieces_polys;


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID		InitialiseModels(MR_LONG);
extern	MR_VOID		DeinitialiseModels(MR_LONG);
extern	MR_VOID		LoadGenericWad(MR_LONG);


#endif	//__MODEL_H



