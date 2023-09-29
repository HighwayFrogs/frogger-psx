/******************************************************************************
*%%%% mr_ot.h
*------------------------------------------------------------------------------
*
*	New header file for mr_ot.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	09.07.96	Tim Closs		Added bias for OT positioning
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
// Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_ot					MR_OT;

#else
#ifndef	__MR_OT_H
#define	__MR_OT_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#ifndef	MR_OT_NEAR_CLIP
#define	MR_OT_NEAR_CLIP	   				(2)			// minimum OT position for API 3D polys
#endif

#define	MR_OT_ADDED_TO_GLOBAL			(1<<0)		// local OT has been added to global this frame

//------------------------------------------------------------------------------------------------
//	Structure
//------------------------------------------------------------------------------------------------

struct	__mr_ot
 		{
 		struct __mr_ot*		ot_prev_node;
 		struct __mr_ot*		ot_next_node;
 
		MR_ULONG			ot_flags;
		MR_USHORT			ot_shift;
		MR_USHORT			ot_zshift;
		MR_LONG				ot_view_origin_z;
		MR_FRAME*			ot_frame;
		MR_SVEC				ot_frame_offset;
		MR_ULONG*			ot_ot[2];
		MR_LONG				ot_global_ot_offset;	// bias where we wedge into the global OT (+/-32767)
	
		};		// MR_OT


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_OT		MROT_root;
extern	MR_OT*		MROT_root_ptr;
extern	MR_USHORT	MRNumber_of_OTs;


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_OT*		MRCreateOT(MR_USHORT, MR_USHORT, MR_FRAME*);
extern	MR_VOID		MRKillOT(MR_OT*);
extern	MR_VOID		MRClearOTs(MR_USHORT);
extern	MR_VOID		MRRenderOTs(MR_USHORT);
extern	MR_VOID		MRKillAllOTs(MR_VOID);
extern	MR_VOID		MRCalculateOTInfoFromMOF(MR_MOF*, MR_OT*);

#endif	//__MR_OT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
