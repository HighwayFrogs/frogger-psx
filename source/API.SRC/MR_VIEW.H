/******************************************************************************
*%%%% mr_view.h
*------------------------------------------------------------------------------
*
*	New header file for mr_view.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	14.01.97	Tim Closs		MR_VIEWPORT now has linked list of environment
*								instances hanging off it
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_vpoffset				MR_VPOFFSET;
typedef	struct	__mr_vpchange				MR_VPCHANGE;
typedef	struct	__mr_viewport				MR_VIEWPORT;

#else
#ifndef	__MR_VIEW_H
#define	__MR_VIEW_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_VP_LIGHTS_MOVING					(1<<0) 		// lights in VP may be moving
#define	MR_VP_CHANGE_POS  					(1<<1)		// Indicates an update to the MR_VP_CHANGE prim
#define	MR_VP_NO_DISPLAY  					(1<<2)		// Don't/Do display the viewport
#define	MR_VP_ABS_VRAM	  					(1<<3)		// Viewport coordinates are in VRAM
#define	MR_VP_EFFECT_OVER 					(1<<4)		// An effect process has finished
#define	MR_VP_NO_ASPECT						(1<<5)		// vp_aspect_matrix is I

#define	MR_VP_REBUILD_LIGHT_MATRIX			(1<<6)		// Set when we add/remove parallel lights
#define	MR_VP_REBUILD_COLOUR_MATRIX			(1<<7)		// Set when we add/remove parallel/point lights

#define	MR_VP_SIZE_4096						(12)			// Ordering table lengths
#define	MR_VP_SIZE_2048						(11)
#define	MR_VP_SIZE_1024						(10)
#define	MR_VP_SIZE_512						(9)
#define	MR_VP_SIZE_256						(8)
#define	MR_VP_SIZE_128						(7)
#define	MR_VP_SIZE_64						(6)
#define	MR_VP_SIZE_32						(5)
#define	MR_VP_SIZE_16						(4)
#define	MR_VP_SIZE_8						(3)
#define	MR_VP_SIZE_4						(2)

#define	MR_VP_VIEWDIST_32768				(0)
#define	MR_VP_VIEWDIST_16384				(1)
#define	MR_VP_VIEWDIST_8192					(2)
#define	MR_VP_VIEWDIST_4096					(3)
#define	MR_VP_VIEWDIST_2048					(4)
#define	MR_VP_VIEWDIST_1024					(5)
#define	MR_VP_VIEWDIST_512					(6)

#define	MR_VP_VIEWDIST_DEFAULT				(MR_VP_VIEWDIST_16384)


#define	MR_INST_USE_CUSTOM_AMBIENT			(1<<0)
#define	MR_INST_USE_SCALED_COLOURS			(1<<1)
#define	MR_INST_MODIFIED_LIGHT_MASK			(MR_INST_USE_CUSTOM_AMBIENT | MR_INST_USE_SCALED_COLOURS)

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_vpoffset
		{
		MR_SHORT				off_x;						// Drawing offset X component
		MR_SHORT				off_y;						// Drawing offset Y component
	
		};		// MR_VPOFFSET


struct	__mr_vpchange
		{
		DR_AREA					vc_change_clip;				// Change clip region for ViewPort
		DR_OFFSET				vc_change_offset;			// Change drawing offset for ViewPort
		MR_ULONG				vc_flags;		 			// Flags
	
		};		//	MR_VPCHANGE


struct	__mr_viewport
		{
		struct __mr_viewport*	vp_next_node;				// ptr to next in linked list
		struct __mr_viewport*	vp_prev_node;				// ptr to previous in linked list
	
		MR_USHORT				vp_flags;					// Flags
		MR_USHORT				vp_frame_count;				// Counts up by 1 each time viewport is rendered
		MR_RECT					vp_disp_inf;				// Position and dimensions of ViewPort region
		MR_RECT					vp_draw_areas[2];			// Room for DR_AREA source information
		MR_VPOFFSET				vp_draw_ofs[2];				// Room for DR_OFFSET source information (2 shorts!)
		MR_USHORT				vp_geom_x;					// 3D geometry offset (usually centre of above region)
		MR_USHORT				vp_geom_y;					// 3D geometry offset (usually centre of above region)
	
		MR_VPCHANGE				vp_disp_change[2];			// Display change primitive for PlayStation 
 
		MR_USHORT				vp_ot_size;					// Size of the ordering table
		MR_USHORT				vp_ot_size_bits;			// vp_ot_size = 1<<vp_ot_size_bits;
		MR_USHORT				vp_otz_shift;				// Shift to get polygons to fit into OT
		MR_USHORT				vp_view_distance;			// View distance (default is 16384, set by MRSetViewportViewDistance)

		MR_ULONG*				vp_ot[2];					// pointer to allocated OT memory
		MR_ULONG*				vp_work_ot;					// pointer to OT pointer being built
	
		MR_FRAME*				vp_camera;					// camera frame
		MR_MAT					vp_aspect_matrix;			// aspect ratio matrix to apply to camera lw transform (normally I)
		MR_MAT					vp_render_matrix;			// result of (aspect * camera lw)
		MR_USHORT				vp_perspective;				// perspective constant
		MR_USHORT				vp_priority;				// Priority of viewport (0=Highest priority)

		// NOTE: These are only ever referenced for initial next/prev nodes!
		// 		As such, you should _NOT_ use any other fields for initial access
		MR_LINK					vp_text_area_root;			// text area root	
		MR_LINK					vp_mesh_root;				// mesh instance root
		MR_LINK					vp_light_root;				// light instance root
		MR_LINK					vp_pgen_root;				// particle generator root
		MR_LINK					vp_3dsprite_root;			// 3d sprite instance root
		MR_LINK					vp_2dsprite_root;			// 2d sprite root (list is NOT instanced)
		MR_LINK					vp_env_root;				// animation environment root

		// NOTE: These pointers are actually to the above MR_LINK structures.
		//			They're declared as MR_VOID* to stop over-excessive casting,
		//			although some will be needed.
		MR_VOID*				vp_text_area_root_ptr;		// pointer to first instance of a text area to display
		MR_VOID*				vp_mesh_root_ptr;			// pointer to first instance of a mesh to display	
		MR_VOID*				vp_light_root_ptr;			// pointer to first instance of a light to display	
		MR_VOID*				vp_pgen_root_ptr;			// pointer to first instance of a particle generator to display
		MR_VOID*				vp_3dsprite_root_ptr;		// pointer to first instance of a 3d sprite to display
		MR_VOID*				vp_2dsprite_root_ptr;		// pointer to first 2d sprite to display
		MR_VOID*				vp_env_root_ptr;			// pointer to first animation environment

		MR_USHORT				vp_instances;				// number of meshes, lights and 3d sprites instanced
		MR_USHORT				vp_pointlights;				// number of point lights instanced
	
		MR_CVEC	 				vp_fog_colour;				// r,g,b to fade to
		MR_ULONG 				vp_fog_near_dist;			// Fog near distance (0 means no fog active)
		MR_ULONG 				vp_fog_far_dist;			// Fog far distance (defaults to 100.. needed for 
	
		MR_MAT	 				vp_light_matrix;			// light matrix (vpinsts pointing to this will be
															// quicker to light)
		MR_MAT	 				vp_colour_matrix;			// light colour matrix
		MR_CVEC	 				vp_back_colour;				// ambient colour
		MR_EFFECT				vp_effect;					// Room for effect stuff
	
		};		// MR_VIEWPORT


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_VIEWPORT		MRViewport_root;
extern	MR_VIEWPORT*	MRViewport_root_ptr;
extern	MR_USHORT		MRNumber_of_viewports;


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VIEWPORT*	MRCreateViewport(MR_RECT*, MR_RECT*, MR_USHORT, MR_USHORT);
extern	MR_VOID			MRKillViewport(MR_VIEWPORT*);
extern	MR_VOID			MRKillViewportPhysically(MR_VIEWPORT*);
extern	MR_VOID			MRRenderViewport(MR_VIEWPORT*);
extern	MR_BOOL			MRSetViewportCamera(MR_VIEWPORT*,MR_FRAME*);
extern	MR_VOID			MRSetDefaultViewport(MR_VIEWPORT*);
extern	MR_VOID*		MRAddObjectToViewport(MR_OBJECT*, MR_VIEWPORT*, MR_USHORT);

extern	MR_BOOL			MRRemoveObjectFromViewport(MR_OBJECT*, MR_VIEWPORT*);
extern	MR_VOID			MRRemoveMeshInstanceFromViewport(MR_MESH_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemoveMeshInstanceFromViewportPhysically(MR_MESH_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemoveLightInstanceFromViewportPhysically(MR_LIGHT_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemoveAllLightInstancesFromViewportPhysically(MR_VIEWPORT*);
extern	MR_VOID			MRRemove3DSpriteInstanceFromViewport(MR_3DSPRITE_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemove3DSpriteInstanceFromViewportPhysically(MR_3DSPRITE_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemovePgenInstanceFromViewport(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemovePgenInstanceFromViewportPhysically(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			MRRemove2DSpriteFromViewportPhysically(MR_2DSPRITE*, MR_VIEWPORT*);
extern	MR_VOID			MRRemoveTextAreaFromViewportPhysically(MR_TEXT_AREA*, MR_VIEWPORT*);

extern	MR_VOID			MRMoveViewport(MR_VIEWPORT*, MR_SHORT, MR_SHORT);
extern	MR_VOID			MRMoveViewportAbs(MR_VIEWPORT*, MR_RECT*, MR_RECT*);
extern	MR_VOID			MRChangeViewport(MR_VIEWPORT*, MR_RECT*);

extern	MR_VOID			MRSetViewportAspect(MR_VIEWPORT*, MR_MAT*);
extern	MR_VOID			MRResetViewportAspect(MR_VIEWPORT*);
extern	MR_VOID			MRUpdateViewportRenderMatrices(MR_VOID);
extern	MR_VOID			MRUpdateViewport2DSpriteAnims(MR_VIEWPORT*);
extern	MR_VOID			MRSetActiveViewport(MR_VIEWPORT*);
extern	MR_BOOL			MRSetViewportFogColour(MR_VIEWPORT*, MR_UBYTE, MR_UBYTE, MR_UBYTE);
extern	MR_BOOL			MRSetViewportFogDistances(MR_VIEWPORT*, MR_ULONG, MR_ULONG);
extern	MR_VOID			MRSetViewportViewDistance(MR_VIEWPORT*, MR_USHORT);


#endif	//__MR_VIEW_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

