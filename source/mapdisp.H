/******************************************************************************
*%%%% mapdisp.h
*------------------------------------------------------------------------------
*
*	Map display
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Added variable to __map_render_params
*	20.05.97	William Bell	Extern'd lighting variables for use by frog light entity.
*
*%%%**************************************************************************/

#ifndef	__MAPDISP_H
#define	__MAPDISP_H

#include "mr_all.h"
#include "entity.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	MAP_WIREFRAME_EXTENSION
#define	MAP_WATER_WIBBLE
#define	MAP_TEXTURE_ANIMATION
#ifdef	PSX
#define	MAP_USE_ASM										// Only PlayStation uses MIPS terrain code
#endif

// Map display limits
#define	MAP_MAX_POLY_GROUPS				128				// Was 256 $gr Changed by Tim.
#define	MAP_MAX_POLYS_RENDERED			2500
#define	MAP_MAX_GRID_ROWS				64

// OT stuff
#define	MAP_POLY_OT_OFFSET				64
#define	MAP_POLY_CLIP_OTZ				16
#define	MAP_POLY_MAX_OT_OFFSET			1
#define	MAP_POLY_ENVMAP_OFFSET			2

// Render flags
#define	MAP_RENDER_FLAGS_TEXTURED		(1<<0)
#define	MAP_RENDER_FLAGS_GOURAUD		(1<<1)
#define	MAP_RENDER_FLAGS_LIT			(1<<2)

// Poly flags
#define	MAP_POLY_SEMITRANS				(1<<0)			// do a setSemiTrans on the poly
#define	MAP_POLY_ENVMAP					(1<<1)			// use camera->poly environment indexing
#define	MAP_POLY_MAX_OT					(1<<2)			// add poly at very back of OT
#define	MAP_POLY_ANIM_UV				(1<<3)			// poly has an associated MAP_ANIM using UV animation
#define	MAP_POLY_ANIM_TEXTURE			(1<<4)			// poly has an associated MAP_ANIM using cel list animation

// Wireframe extension
#define	MAP_WIREFRAME_NUM_LINES			5				// number of lines per edge of MAP_GROUP
#define	MAP_WIREFRAME_LINE_LENGTH		0x300			// length of lines
#define	MAP_WIREFRAME_CORNER_NUM_LINES	3				// number of lines in each direction at corner

// Map poly types
enum	{
		POLY_ID_F3,
		POLY_ID_F4,
		POLY_ID_FT3,
		POLY_ID_FT4,
		POLY_ID_G3,
		POLY_ID_G4,
		POLY_ID_GT3,
		POLY_ID_GT4,
		POLY_ID_G2,

		POLY_ID_LAST,
		};

// Light defines
enum	{	
		LIGHT_TYPE_DUMMY,
		LIGHT_TYPE_STATIC,
		LIGHT_TYPE_ENTITY,
		};

// MAP_ANIM flags
#define	MAP_ANIM_UV						(1<<0)			// MAP_ANIM uses UV animation
#define	MAP_ANIM_TEXTURE				(1<<1)			// MAP_ANIM uses cel list animation

// Sky land stuff
#define	SKY_LAND_GRIDLEN				0x400
#define	SKY_LAND_HEIGHT					0x1800
#define	SKY_MAX_DRIFT					0xb00
#define	SKY_MAX_DRIFT_POSITION			0x10000000


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__map_f3				MAP_F3;
typedef	struct	__map_ft3				MAP_FT3;
typedef	struct	__map_g3				MAP_G3;
typedef	struct	__map_gt3				MAP_GT3;
typedef	struct	__map_f4				MAP_F4;
typedef	struct	__map_ft4				MAP_FT4;
typedef	struct	__map_g4				MAP_G4;
typedef	struct	__map_gt4				MAP_GT4;
typedef	struct	__map_g2				MAP_G2;
typedef	struct	__map_group				MAP_GROUP;
typedef	struct	__poly_group			POLY_GROUP;
typedef	struct	__poly_node				POLY_NODE;
typedef	struct	__map_render_params		MAP_RENDER_PARAMS;
typedef	struct	__light					LIGHT;
typedef	struct	__sky_land_header		SKY_LAND_HEADER;
typedef	struct	__map_anim				MAP_ANIM;
typedef	struct	__map_uv_info			MAP_UV_INFO;
typedef	struct	__map_wibble_water		MAP_WIBBLE_WATER;

struct __map_f3
	{
	MR_USHORT	mp_vertices[3];
	MR_USHORT	mp_pad;
	MR_CVEC	 	mp_rgb0;

	};	// MAP_F3 	(12 bytes)


struct __map_f4
	{
	MR_USHORT	mp_vertices[4];
	MR_CVEC	 	mp_rgb0;

	};	// MAP_F4	(12 bytes)


struct __map_g3
	{
	MR_USHORT	mp_vertices[3];
	MR_USHORT	mp_pad;
	MR_CVEC	 	mp_rgb0;
	MR_CVEC	 	mp_rgb1;
	MR_CVEC	 	mp_rgb2;

	};	// MAP_G3	(20 bytes)


struct __map_g4
	{
	MR_USHORT	mp_vertices[4];
	MR_CVEC	 	mp_rgb0;
	MR_CVEC	 	mp_rgb1;
	MR_CVEC	 	mp_rgb2;
	MR_CVEC	 	mp_rgb3;

	};	// MAP_G4	(24 bytes)


struct __map_g2							// this is set up when a MAP_GROUP on the edge of the world is created
	{
	MR_USHORT	mp_vertices[2];
	MR_CVEC	 	mp_rgb0;
	MR_CVEC	 	mp_rgb1;

	};	// MAP_G2


struct __map_ft3
	{
	MR_USHORT	mp_vertices[3];
	MR_USHORT	mp_pad0;
	MR_USHORT	mp_flags;
	MR_USHORT	mp_pad1;
	MR_UBYTE	mp_u0;
	MR_UBYTE	mp_v0;
	MR_USHORT	mp_clut_id;
	MR_UBYTE	mp_u1;
	MR_UBYTE	mp_v1;
	MR_USHORT	mp_tpage_id;
	MR_UBYTE	mp_u2;
	MR_UBYTE	mp_v2;
	MR_USHORT	mp_pad2;
	MR_CVEC	 	mp_rgb0;

	};	// MAP_FT3	(28 bytes)


struct __map_ft4
	{
	MR_USHORT	mp_vertices[4];
	MR_USHORT	mp_flags;
	MR_USHORT	mp_pad0;
	MR_UBYTE	mp_u0;
	MR_UBYTE	mp_v0;
	MR_USHORT	mp_clut_id;
	MR_UBYTE	mp_u1;
	MR_UBYTE	mp_v1;
	MR_USHORT	mp_tpage_id;
	MR_UBYTE	mp_u2;
	MR_UBYTE	mp_v2;
	MR_UBYTE	mp_u3;
	MR_UBYTE	mp_v3;
	MR_CVEC	 	mp_rgb0;

	};	// MAP_FT4	(28 bytes)


struct __map_gt3
	{
	MR_USHORT	mp_vertices[3];
	MR_USHORT	mp_pad0;
	MR_USHORT	mp_flags;
	MR_USHORT	mp_pad1;
	MR_UBYTE	mp_u0;
	MR_UBYTE	mp_v0;
	MR_USHORT	mp_clut_id;
	MR_UBYTE	mp_u1;
	MR_UBYTE	mp_v1;
	MR_USHORT	mp_tpage_id;
	MR_UBYTE	mp_u2;
	MR_UBYTE	mp_v2;
	MR_USHORT	mp_pad2;
	MR_CVEC	 	mp_rgb0;
	MR_CVEC	 	mp_rgb1;
	MR_CVEC	 	mp_rgb2;

	};	// MAP_GT3	(36 bytes)


struct __map_gt4
	{
	MR_USHORT	mp_vertices[4];
	MR_USHORT	mp_flags;
	MR_USHORT	mp_pad1;
	MR_UBYTE	mp_u0;
	MR_UBYTE	mp_v0;
	MR_USHORT	mp_clut_id;
	MR_UBYTE	mp_u1;
	MR_UBYTE	mp_v1;
	MR_USHORT	mp_tpage_id;
	MR_UBYTE	mp_u2;
	MR_UBYTE	mp_v2;
	MR_UBYTE	mp_u3;
	MR_UBYTE	mp_v3;
	MR_CVEC	 	mp_rgb0;
	MR_CVEC	 	mp_rgb1;
	MR_CVEC	 	mp_rgb2;
	MR_CVEC	 	mp_rgb3;

	};	// MAP_GT4	(40 bytes)


struct	__map_group
	{
	MR_UBYTE		mg_num_f3;			// number of f3 polys
	MR_UBYTE		mg_num_f4;			// number of f4 polys
	MR_UBYTE		mg_num_ft3;			// number of ft3 polys
	MR_UBYTE		mg_num_ft4;			// number of ft4 polys
	MR_UBYTE		mg_num_g3;			// number of g3 polys
	MR_UBYTE		mg_num_g4;			// number of g4 polys
	MR_UBYTE		mg_num_gt3;			// number of gt3 polys
	MR_UBYTE		mg_num_gt4;			// number of gt4 polys
	MR_UBYTE		mg_num_g2;			// number of g2 polys
	MR_UBYTE		mg_pad0[3];
	MAP_F3*			mg_f3_list;			// ptr (offset) to map poly list
	MAP_F4*			mg_f4_list;			// ptr (offset) to map poly list
	MAP_FT3*		mg_ft3_list;		// ptr (offset) to map poly list
	MAP_FT4*		mg_ft4_list;		// ptr (offset) to map poly list
	MAP_G3*			mg_g3_list;			// ptr (offset) to map poly list
	MAP_G4*			mg_g4_list;			// ptr (offset) to map poly list
	MAP_GT3*		mg_gt3_list;		// ptr (offset) to map poly list
	MAP_GT4*		mg_gt4_list;		// ptr (offset) to map poly list
	MAP_G2*			mg_g2_list;			// ptr (offset) to map poly list
	MR_SHORT*		mg_static_indices;	// ptr (offset) to index list of static entities (or NULL)

	POLY_GROUP*		mg_poly_group[4];	// POLY_GROUP created, or NULL for each viewport
	ENTITY*			mg_entity_root_ptr;	// linked list of entities which project over this MAP_GROUP

	};	// MAP_GROUP


struct	__poly_node
	{
  	POLY_NODE*	pn_next;			// standard linked list entries
	POLY_NODE*	pn_prev;
	MR_ULONG	pn_numpolys;		// number of polys pointed to
	MR_UBYTE*	pn_map_polys;		// ptr to array of map polys, eg. MAP_FT4
	MR_UBYTE*	pn_prims[2];		// double buffered primitives

	};	// POLY_NODE


struct	__poly_group
	{
	MAP_GROUP*	pg_map_group;		// pointer to map group which created this poly group
	MR_USHORT	pg_timer;			// if 2, display... else don't display, free when 0
	MR_USHORT	pg_flags;			
	POLY_NODE	pg_polys_f3;
	POLY_NODE	pg_polys_f4;
	POLY_NODE	pg_polys_ft3;
	POLY_NODE	pg_polys_ft4;
	POLY_NODE	pg_polys_g3;
	POLY_NODE	pg_polys_g4;
	POLY_NODE	pg_polys_gt3;
	POLY_NODE	pg_polys_gt4;
#ifdef MAP_WIREFRAME_EXTENSION
	POLY_NODE	pg_polys_g2;		// wireframe extension of world
#endif
	MR_UBYTE*	pg_prims[2];		// allocated in one block

	};	// POLY_GROUP


struct	__map_render_params
	{
	MR_ULONG	mr_poly_size;			// size of our map poly struct (eg. MAP_FT4)
	MR_ULONG	mr_prim_size;			// size of PSX prim (eg sizeof(POLY_FT4))
	MR_ULONG	mr_prim_coord_ofs;		// gap in bytes between x0 and x1 (same for x1..x2, x2..x3)
	MR_ULONG	mr_prim_flags;			// eg. MAP_RENDER_FLAGS_TEXTURED
	MR_ULONG	mr_prim_x0_ofs;			// Added by Martin, offset to x0 in structure
	MR_SVEC		mr_frog_svec;			// Added by Dean (used to pass world position of frog into render code)

#ifdef WIN95
	MR_ULONG	mr_prim_z_coord_ofs;	// gap in bytes between z0 and z1 (same for z1..z2, z2..z3)
	MR_ULONG	mr_prim_z0_ofs;			// offset to z0 in structure
#endif
	};	// MAP_RENDER_PARAMS


struct	__light
	{
	MR_UBYTE	li_type; 		
	MR_UBYTE	li_priority;
	MR_USHORT	li_parent_id;
	MR_UBYTE	li_api_type;		// API light type
	MR_UBYTE	li_pad[3];
	MR_ULONG	li_colour;			// BbGgRr
	MR_SVEC		li_position;
	MR_SVEC		li_direction;
	MR_USHORT	li_attribute_0;
	MR_USHORT	li_attribute_1;
	MR_FRAME*	li_frame;			// ptr to API frame
	MR_OBJECT*	li_object;			// ptr to API object

	};	// LIGHT


struct	__sky_land_header
	{
	MR_USHORT	sl_xnum;			// number of grid squares in x
	MR_USHORT	sl_znum;			// number of grid squares in z

	};	// SKY_LAND_HEADER


struct	__map_anim
	{
	// UV stuff
	MR_UBYTE		ma_du;				// delta u to add to offset each frame
	MR_UBYTE		ma_dv;				// delta v to add to offset each frame
	MR_USHORT		ma_uv_duration;		// number of frames before resetting
	MR_UBYTE		ma_ofs_u;			// current u offset    (mappy outputs 0)
	MR_UBYTE		ma_ofs_v;			// current v offset    (mappy outputs 0)
	MR_USHORT 		ma_uv_count;		// current frame count (mappy outputs 0)

	// TEXTURE stuff
	MR_USHORT		ma_numcels;			// number of cels in animlist
	MR_USHORT		ma_current_cel;		// current cel (mappy outputs 0)
	MR_USHORT*		ma_cel_list;		// offset (ptr) to array of indices into
	MR_USHORT		ma_cel_period;		// number of frames before resetting
	MR_USHORT 		ma_cel_count;		// current frame count (mappy outputs 0)

	// General stuff
	MR_USHORT		ma_flags;			// eg. MAP_ANIM_UV, MAP_ANIM_TEXTURE
	MR_USHORT		ma_numpolys;
	MR_TEXTURE*		ma_texture;			// always points to the MR_TEXTURE used by the poly(s)
	MAP_UV_INFO*	ma_map_uv_info;		// ptr to array of UV info structures (1 for each poly)

	};	// MAP_ANIM


struct	__map_uv_info
	{
	MR_VOID*		mu_map_poly;		// ptr to single map poly
	MR_UBYTE		mu_u0;				// original UV coords (mappy outputs as 0).  Copied at load time from the
	MR_UBYTE		mu_v0;				// map poly, and resolved to absolute offsets from top left of texture in VRAM
	MR_UBYTE		mu_u1;
	MR_UBYTE		mu_v1;
	MR_UBYTE		mu_u2;
	MR_UBYTE		mu_v2;
	MR_UBYTE		mu_u3;
	MR_UBYTE		mu_v3;

	};	// MAP_UV_INFO


struct __map_wibble_water
	{
	MR_LONG		ww_num_vertices;
	MR_SVEC**	ww_vertices_ptr;
	};	// MAP_WIBBLE_WATER


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_SHORT			Map_group_view_list[][MAP_MAX_POLY_GROUPS + 1];
extern	MR_ULONG			Map_light_max_r2;
extern	MR_ULONG			Map_light_min_r2;
extern	MR_ULONG			Map_prim_type_sizes[];
extern	MR_ULONG			Map_prim_type_codes[];
extern	MAP_WIBBLE_WATER	Map_wibble_water;
extern	MR_VEC				Sky_drift_position;
extern	MR_VEC				Sky_drift_velocity;
extern	MR_VEC				Sky_drift_acceleration;


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		InitialiseMapDisplay(MR_VOID);
extern	MR_VOID		DeinitialiseMapDisplay(MR_VOID);
extern	POLY_GROUP*	FindFreePolyGroup(MR_ULONG);
extern	MR_LONG		ExpandMapGroup(MR_SHORT, MR_ULONG, MR_LONG);
extern	MR_VOID		CreateMapGroups(MR_ULONG);
extern	MR_VOID		RenderMap(MR_ULONG);
extern	MR_VOID		FreeAllPolyGroups(MR_VOID);

extern	MR_VOID		MapRenderTris(POLY_NODE*, MAP_RENDER_PARAMS*);
extern	MR_VOID		MapRenderQuads(POLY_NODE*, MAP_RENDER_PARAMS*);
extern	MR_VOID		MapRenderG2s(POLY_NODE*);

extern	MR_VOID		MapRenderTrisASM(POLY_NODE*, MAP_RENDER_PARAMS*);
extern	MR_VOID		MapRenderQuadsASM(POLY_NODE*, MAP_RENDER_PARAMS*);

extern	MR_VOID		CreateMapLights(MR_VOID);
extern	MR_VOID 	KillMapLightsFrames(MR_VOID);
extern	MR_VOID		RenderSkyLand(MR_ULONG);
extern	MR_VOID		UpdateSkyLand(MR_VOID);
extern	MR_VOID		MapCreateWireframeLines(MR_VOID);
extern	MR_VOID		MapCreateWireframeLinesMapgroupCorner(MR_LONG, MR_LONG, MR_LONG, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID		MapCreateWireframeLinesMapgroupEdge(MR_LONG, MR_LONG, MR_LONG, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID		MapUpdateAnimatedPolys(MR_VOID);


#endif		//_MAPDISP_H
