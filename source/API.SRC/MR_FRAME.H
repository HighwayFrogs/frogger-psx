/******************************************************************************
*%%%% mr_frame.h
*------------------------------------------------------------------------------
*
*	New header file for mr_frame.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	21.01.97	Tim Closs		Added MRChangeFrameParent()
*	12.02.97	Tim Closs		Added MR_FRAME_REBUILT_LAST_FRAME
*	18.02.97	Dean Ashton		Added MR_FRAME_AT_ADDRESS, and removed 
*								prototype for MRKillFrameAtAddress()
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_frame				MR_FRAME;

#else
#ifndef	__MR_FRAME_H
#define	__MR_FRAME_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Maximum number of generations in a frame hierarchy
#define	MR_FRAME_MAX_GENERATIONS				8

// Bits for frame structure flags
#define	MR_FRAME_REBUILD   						(1<<0)
#define	MR_FRAME_NO_UPDATE						(1<<1)
#define	MR_FRAME_TRANSLATE						(1<<2)
#define	MR_FRAME_LW_CALCULATED					(1<<3)
#define	MR_FRAME_REBUILT_LAST_FRAME				(1<<4)


#define	MR_FRAME_MEMFIXED						(1<<10)		// frame is in fixed memory
#define	MR_FRAME_AT_ADDRESS						(1<<11)		// frame was created at a fixed address

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_frame
		{
		struct __mr_frame*	fr_next_node;				// pointer to next frame in linked list
		struct __mr_frame*	fr_prev_node;				// pointer to previous frame in linked list
	
		MR_USHORT	 		fr_flags;
		MR_SHORT	 		fr_count; 					// reference count of things pointing to this frame
		MR_MAT		 		fr_matrix;					// 3x3 rotation matrix (m) and translation vector (t)
		struct __mr_frame*	fr_parent;					// pointer to parent frame (NULL = world)
	
		MR_VEC		 		fr_rotation;				// frame vector of angles	(16.16 on PSX)
		MR_VEC		 		fr_velocity;				// frame velocity				(16.16 on PSX)
		MR_VEC		 		fr_angvel;					// frame angular velocity	(16.16 on PSX)

		MR_MAT		 	 	fr_lw_transform;			// LW transform for this frame (identical to fr_matrix
														// if fr_parent is NULL)
		};		// MR_FRAME


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_FRAME			MRFrame_root;
extern	MR_FRAME*			MRFrame_root_ptr;
extern	MR_USHORT			MRNumber_of_frames;

#ifdef MR_MEMFIXED_FRAME
extern	MR_MEMFIXED*		MRMemfixed_frame;
#endif

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_FRAME*		MRCreateFrame(MR_VEC*, MR_SVEC*, MR_FRAME*);
extern	MR_VOID			MRKillFrame(MR_FRAME*);
extern	MR_VOID			MRUpdateFrames(MR_VOID);
extern	MR_VOID			MRUpdateFrameLWTransform(MR_FRAME*);
extern	MR_VOID			MRInitialiseFrame(MR_FRAME*);
extern	MR_FRAME*		MRCreateFrameAtAddress(MR_VEC*, MR_SVEC*, MR_FRAME*, MR_ULONG* mem);
extern	MR_VOID			MRPointMatrixAtVector(MR_MAT*, MR_VEC*, MR_VEC*);
extern	MR_VOID			MRChangeFrameParent(MR_FRAME*, MR_FRAME*);

#endif	//__MR_FRAME_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

