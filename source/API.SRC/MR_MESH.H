/******************************************************************************
*%%%% mr_mesh.h
*------------------------------------------------------------------------------
*
*	New header file for mr_mesh.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	28.01.97	Tim Closs		Added MR_MESH_DEBUG_DISPLAY_HILITE_VERTICES,
*						  		MR_MESH_DEBUG_DISPLAY_HILITE_PRIMS
*	31.01.97	Dean Ashton		Removed mi_light_matrix/mi_light_matrix_ptr
*						  		from MR_MESH_INST
*	07.04.97	Dean Ashton		Added MR_MESH_IGNORE_BBOX and 
*						  		MR_MESH_CHECK_BBOX_USING_EDGES defines.	
*	06.06.97	Tim Closs		Added stuff for animated polys.  New functions:
*								MRCreateMeshAnimatedPolys()
*								MRUpdateMeshAnimatedPolys()
*								MRUpdateMeshesAnimatedPolys()
*								MRUpdateViewportMeshInstancesAnimatedPolys()
*								MRMeshAnimatedPolyPause()
*								MRMeshAnimatedPolySetCel()
*								MRMeshAnimatedPolysSetCels()
*								Altered and extended MR_MESH structure
*								Added MR_MESH_ANIMATED_POLY structure
*								Add new flags:
*								MR_MESH_ANIMATED_POLYS
*								MR_MESH_PAUSE_ANIMATED_POLYS
*								MR_MESH_ANIMATED_POLY_PAUSED
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_mesh					MR_MESH;
typedef	struct	__mr_static_mesh			MR_STATIC_MESH;
typedef	struct	__mr_mesh_inst				MR_MESH_INST;
typedef	struct	__mr_mesh_param				MR_MESH_PARAM;
typedef	struct	__mr_mesh_animated_poly		MR_MESH_ANIMATED_POLY;

#else
#ifndef	__MR_MESH_H
#define	__MR_MESH_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_MESH_MAX_CHANGE_DISTS				(4)		// maximum change distances set in a mesh

// Mesh flags
#define	MR_MESH_ANIMATED						(1<<0)	// MR_MESH extension is MR_ANIM_MESH, not MR_STATIC_MESH (used by anim files only)
#define	MR_MESH_FLIPBOOK						(1<<1)	// (static) mesh is displayed by specifying part and partcel (flipbook)
#define	MR_MESH_ANIM_ENV_MULTIPLE				(1<<2)	// (animated) mesh created from a multiple environment
#define	MR_MESH_IGNORE_BBOX						(1<<3)	// don't check the bounding box for display status
#define	MR_MESH_CHECK_BBOX_USING_EDGES			(1<<4)	// check the display state of the bbox using edges 
#define	MR_MESH_ANIMATED_POLYS					(1<<5)	// mesh contains some animated textured polys
#define	MR_MESH_PAUSE_ANIMATED_POLYS			(1<<6)	// don't update animlist stuff for animated textured polys

// Mesh debug flags (in same flags field)
#define	MR_MESH_DEBUG_DISPLAY_PART_BBOX			(1<<8)	// display part bounding box (static model or anim part)
#define	MR_MESH_DEBUG_DISPLAY_ANIM_GLOBAL_BBOX	(1<<9)	// display anim-wide bounding box (for animations only)
#define	MR_MESH_DEBUG_DISPLAY_ANIM_PERCEL_BBOX	(1<<10)	// display cel-wide bounding box (for animations only)
#define	MR_MESH_DEBUG_DISPLAY_COLLPRIMS			(1<<11)	// display collprims in MOF file
#define	MR_MESH_DEBUG_DISPLAY_HILITE_VERTICES	(1<<12)	// display MR_HILITEs of type MR_HILITE_VERTEX
#define	MR_MESH_DEBUG_DISPLAY_HILITE_PRIMS		(1<<13)	// display MR_HILITEs of type MR_HILITE_PRIM

// Mesh reserved flags (reserved for use by user code)
#define	MR_MESH_RESERVED_FLAG_0					(1<<16)
#define	MR_MESH_RESERVED_FLAG_1					(1<<17)
#define	MR_MESH_RESERVED_FLAG_2					(1<<18)
#define	MR_MESH_RESERVED_FLAG_3					(1<<19)

// Mesh instance flags
#define	MR_MESH_INST_DISPLAYED_LAST_FRAME		(1<<0)	// MR_MESH_INST was rendered last frame

#define	MR_MESH_INST_IGNORE_NCLIP				(1<<1)
#define	MR_MESH_INST_FIX_NCLIP_NORMALS			(1<<2)
#define	MR_MESH_INST_TRANSLUCENT				(1<<3)
#define	MR_MESH_INST_FORCE_TRANSLUCENT			(1<<4)
#define	MR_MESH_INST_NO_LIGHTING				(1<<5)

#define	MR_MESH_INST_SPECIAL_RENDER_MASK		(MR_MESH_INST_IGNORE_NCLIP | \
												 MR_MESH_INST_FIX_NCLIP_NORMALS | \
												 MR_MESH_INST_TRANSLUCENT | \
												 MR_MESH_INST_FORCE_TRANSLUCENT | \
												 MR_MESH_INST_NO_LIGHTING)

#define	MR_MESH_INST_TRANSLUCENT_MASK			(MR_MESH_INST_TRANSLUCENT | MR_MESH_INST_FORCE_TRANSLUCENT)

// Mesh animated poly flags
#define	MR_MESH_ANIMATED_POLY_PAUSED			(1<<0)	// animated poly cel number not updated


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_mesh_animated_poly
		{
		MR_USHORT	ma_flags;							// eg. MR_MESH_ANIMATED_POLY_PAUSE
		MR_USHORT	ma_animlist_entry;					// index of MR_PART_POLY_ANIMLIST_ENTRY to reference
		MR_USHORT	ma_duration;						// counts up, then move to next animlist entry
		MR_USHORT	ma_pad;

		};		// MR_MESH_ANIMATED_POLY


struct	__mr_mesh
		{
		MR_ULONG				me_flags;				// mesh specific flags

		union
			{
			MR_VOID*			me_extra_void;
			MR_STATIC_MESH*		me_extra_static_mesh;
			MR_ANIM_MESH*		me_extra_anim_mesh;
			} me_extra;

		MR_USHORT				me_clip_distance;		// distance beyond which mesh is not displayed
		MR_USHORT				me_num_animated_polys;	// number of animated polys in mesh
		MR_MESH_ANIMATED_POLY*	me_animated_polys;		// ptr to array of MR_MESH_ANIMATED_POLYs (1-1 corr. with array in MOF)
		MR_USHORT				me_animation_period;	// #game cycles before cels updated (default 1)
		MR_USHORT				me_animation_timer;		// counts up to period


		};		// MR_MESH


struct	__mr_static_mesh
		{
		MR_USHORT			sm_part;					// mesh MR_PART to display
		MR_USHORT			sm_partcel;					// part MR_PARTCEL to display
		MR_MOF* 			sm_mof_ptr;					// ptr to mesh's MOF
		MR_ULONG			sm_mod_change_dists[MR_MESH_MAX_CHANGE_DISTS];
														// view z at which we change from mod n to mod (n+1)

		};		// MR_STATIC_MESH


struct	__mr_mesh_inst
		{
		MR_MESH_INST*		mi_next_node;				// ptr to next in linked list
		MR_MESH_INST*		mi_prev_node;				// ptr to previous in linked list
		MR_OBJECT*			mi_object;					// ptr to object we are instancing	
		MR_USHORT			mi_kill_timer;				// mesh instance kill timer
		MR_USHORT			mi_flags;					// eg. MR_MESH_INST_DISPLAYED_LAST_FRAME
		MR_CVEC				mi_colour_scale;			// used to scale colour matrix and applicable ambient colour (optional)
		MR_CVEC				mi_custom_ambient;			// custom ambient colour (optional)
		MR_ULONG**			mi_prims;					// ptr to array of prim buffer pointers
		MR_USHORT			mi_mof_models;				// total number of mof models in the mesh
		MR_USHORT			mi_light_flags;				// Special lighting flags (shared with 3d sprites)
		MR_OT*				mi_ot;						// Pointer to object ordering table (NULL == Use Viewport)
		
		union
			{
			MR_VOID*		mi_extra_void;		
			} mi_extra;
	
		// Note: memory directly after this structure is allocated for prim buffer pointers: one for each MR_PART in the static
		// MOF

		};		// MR_MESH_INST

struct	__mr_mesh_param
		{
		MR_SVEC*			p_v0;
		MR_SVEC*			p_v1;
		MR_SVEC*			p_v2;
		MR_SVEC*			p_v3;

		MR_SVEC*			p_n0;
		MR_SVEC*			p_n1;
		MR_SVEC*			p_n2;
		MR_SVEC*			p_n3;

		MR_ULONG*			p_work_ot;
		MR_USHORT			p_otz_shift;
		MR_SHORT			p_ot_otz_delta;
		MR_ULONG			p_ot_size;
		MR_LONG				p_ot_clip;
		MR_LONG				p_ot_view_origin_z;

		MR_LONG				p_nclip_result;
		MR_LONG				p_poly_otz;
				
		MR_ULONG*			p_mem_ptr;
		MR_ULONG*			p_prim_ptr;
		MR_ULONG			p_prims;

		};		//	MR_MESH_PARAM;


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_OBJECT*		MRCreateMesh(MR_MOF*, MR_FRAME*, MR_USHORT, MR_USHORT);
extern	MR_VOID			MRKillMesh(MR_OBJECT*);
extern	MR_VOID			MRDestroyMeshByDisplay(MR_OBJECT*);

// Animated polys
extern	MR_VOID			MRCreateMeshAnimatedPolys(MR_MESH*, MR_MOF*);
extern	MR_VOID			MRUpdateMeshAnimatedPolys(MR_MESH*);
extern	MR_VOID			MRUpdateMeshesAnimatedPolys(MR_VOID);
extern	MR_VOID			MRUpdateViewportMeshInstancesAnimatedPolys(MR_VIEWPORT*);
extern	MR_VOID			MRMeshAnimatedPolyPause(MR_MESH*, MR_ULONG);
extern	MR_VOID			MRMeshAnimatedPolySetCel(MR_MESH*, MR_ULONG, MR_ULONG);
extern	MR_VOID			MRMeshAnimatedPolysSetCels(MR_MESH*, MR_ULONG);

// Render code
extern	MR_VOID			MRDisplayMeshPolys_F3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_F4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_FT3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_FT4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_G3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_G4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_GT3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_GT4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_E3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_E4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_GE3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_GE4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_HLF3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);
extern	MR_VOID			MRDisplayMeshPolys_HLF4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL);

// Special Render code
extern	MR_VOID			MRSpecialDisplayMeshPolys_F3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_F4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_FT3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_FT4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_G3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_G4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_GT3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_GT4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_E3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_E4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_GE3(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);
extern	MR_VOID			MRSpecialDisplayMeshPolys_GE4(MR_SVEC*, MR_SVEC*, MR_ULONG*, MR_ULONG*, MR_MESH_PARAM*, MR_BOOL, MR_ULONG);

#endif	//__MR_MESH_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

