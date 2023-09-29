/******************************************************************************
*%%%% mr_obj.h
*------------------------------------------------------------------------------
*
*	New header file for mr_obj.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	06.02.97	Tim Closs		Added:
*									#define	MR_OBJ_MEMFIXED
*									#define	MR_OBJ_MEMFIXED_WITH_INSTS
*									Externs of #ifdef MR_MEMFIXED.. globals
*	19.02.97	Dean Ashton		Added prototypes for MRAttachFrameToObject() and
*								MRDetachFrameFromObject();
*	19.06.96	Dean Ashton		Last param to MRCreateObject() changed to MR_VOID*
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_object				MR_OBJECT;

#else
#ifndef	__MR_OBJ_H
#define	__MR_OBJ_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Object types
enum		{
			MR_OBJTYPE_STATIC_MESH,
			MR_OBJTYPE_ANIM_MESH,
			MR_OBJTYPE_LIGHT,
			MR_OBJTYPE_3DSPRITE,
			MR_OBJTYPE_PGEN
			};

// Note! These are the same as mr_light.h defines. DO NOT CHANGE!
#define	MR_OBJ_ACCEPT_LIGHTS_AMBIENT  		(1<<0)
#define	MR_OBJ_ACCEPT_LIGHTS_PARALLEL  		(1<<1)
#define	MR_OBJ_ACCEPT_LIGHTS_POINT			(1<<2)
#define	MR_OBJ_ACCEPT_LIGHTS_MASK			(MR_OBJ_ACCEPT_LIGHTS_AMBIENT | MR_OBJ_ACCEPT_LIGHTS_PARALLEL | MR_OBJ_ACCEPT_LIGHTS_POINT)

#define	MR_OBJ_ACCEPT_DPQ					(1<<5)					// First 5 bits are for lights
#define	MR_OBJ_NO_DISPLAY					(1<<6)
#define	MR_OBJ_STATIC						(1<<7)					// object uses a static frame
#define	MR_OBJ_DESTROY_BY_DISPLAY			(1<<8)					// as we display an instance, reduce obj count, destroy when 0
#define	MR_OBJ_KILL_FRAME_WITH_OBJECT		(1<<9)

#define	MR_OBJ_MEMFIXED						(1<<10)					// object is in fixed memory
#define	MR_OBJ_MEMFIXED_WITH_INSTS			(1<<11)					// object is in fixed memory with instances


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_object
		{
		struct __mr_object*	ob_next_node;							// pointer to next object in linked list
		struct __mr_object*	ob_prev_node;							// pointer to previous object in linked list
	
		MR_USHORT	 		ob_type;								// 0 => inactive
		MR_USHORT	 		ob_flags;
	
		MR_FRAME*	 		ob_frame;								// pointer to object's coord frame
		MR_SVEC		 		ob_offset;								// offset of object's origin from frame's origin
	
		MR_LONG		 		ob_vp_inst_count;						// reference count of instances of this object
		MR_VOID		 		(*ob_move_callback)(MR_OBJECT*);		// movement callback function (or NULL)
		MR_VOID		 	 	(*ob_disp_callback)(MR_OBJECT*);		// display callback function (or NULL)
		MR_VOID		 		(*ob_dest_callback)(MR_OBJECT*);		// destroy callback function (or NULL)

		union
			{														// pointer to an owner of some kind
			MR_VOID* 		ob_owner_void;								
			MR_ANIM_ENV*	ob_owner_anim_env;
			} ob_owner;

		union 	
			{
			MR_VOID*		ob_extra_void;
			MR_MESH*		ob_extra_mesh;
			MR_LIGHT*		ob_extra_light;
			MR_PGEN*		ob_extra_pgen;
			MR_SP_CORE*		ob_extra_sp_core;
			MR_3DSPRITE*	ob_extra_3dsprite;
			} ob_extra;
	
		};		// MR_OBJECT


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_OBJECT			MRObject_root;
extern	MR_OBJECT*			MRObject_root_ptr;
extern	MR_USHORT			MRNumber_of_objects;

#ifdef MR_MEMFIXED_3DSPRITE
extern	MR_MEMFIXED*		MRMemfixed_3dsprite;
#endif
#ifdef MR_MEMFIXED_PGEN
extern	MR_MEMFIXED*		MRMemfixed_pgen;
#endif
#ifdef MR_MEMFIXED_STATIC_MESH
extern	MR_MEMFIXED*		MRMemfixed_static_mesh;
#endif


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_OBJECT*		MRCreateObject(MR_USHORT, MR_FRAME*, MR_USHORT, MR_VOID*);
extern	MR_VOID			MRKillObject(MR_OBJECT*);
extern	MR_VOID			MRUpdateObjects(MR_VOID);

extern	MR_VOID			MRAttachFrameToObject(MR_OBJECT*, MR_FRAME*);
extern	MR_FRAME*		MRDetachFrameFromObject(MR_OBJECT*);

#endif	//__MR_OBJ_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

