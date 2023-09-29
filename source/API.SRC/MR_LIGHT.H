/******************************************************************************
*%%%% mr_light.h
*------------------------------------------------------------------------------
*
*	New header file for mr_light.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_light				MR_LIGHT;
typedef	struct	__mr_light_inst			MR_LIGHT_INST;

#else
#ifndef	__MR_LIGHT_H
#define	__MR_LIGHT_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Light type bit definitions  (same as the flags which allow meshes to accept these light types)
#define	MR_LIGHT_TYPE_AMBIENT 			(1<<0)
#define	MR_LIGHT_TYPE_PARALLEL			(1<<1)
#define	MR_LIGHT_TYPE_POINT				(1<<2)

#define	MR_LIGHT_CHANGED_COLOURS		(1<<8)
#define	MR_LIGHT_CHANGED_DIRECTION		(1<<9)

// Return flag values for MRCalculateCustomInstanceLights()
#define	MR_CHANGED_COLOUR_MATRIX		(1<<0)	
#define	MR_CHANGED_AMBIENT_COLOUR		(1<<1)

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_light
		{
		MR_USHORT		li_type;  				// eg. MR_LIGTYPE_PARALLEL
		MR_USHORT		li_flags;
		MR_CVEC			li_colour;				// r, g, b
		MR_ULONG		li_falloff_min;			// squared distance below which POINT is specified colour
		MR_ULONG		li_falloff_max;			// squared distance above which POINT has no effect
	
		};		// MR_LIGHT


struct	__mr_light_inst
		{
		MR_LIGHT_INST*	li_next_node;			// ptr to next in linked list
		MR_LIGHT_INST*	li_prev_node;			// ptr to previous in linked list
		MR_OBJECT*		li_object;	 			// ptr to object we are instancing	

		};		// MR_LIGHT_INST


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_OBJECT*	MRCreateLight(MR_ULONG, MR_ULONG, MR_FRAME*, MR_USHORT);
extern	MR_VOID	  	MRKillLight(MR_OBJECT*);

extern	MR_VOID	  	MRUpdateViewportColourMatrix(MR_VIEWPORT*);
extern	MR_VOID	  	MRUpdateViewportLightMatrix(MR_VIEWPORT*);

extern	MR_ULONG  	MRCalculateCustomInstanceLights(MR_OBJECT*, MR_ULONG, MR_CVEC*, MR_CVEC*);

#endif	//__MR_LIGHT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
