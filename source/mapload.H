/******************************************************************************
*%%%% mapload.h
*------------------------------------------------------------------------------
*
*	Map loading and resolving
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__MAPLOAD_H
#define	__MAPLOAD_H

#include "mr_all.h"
#include "library.h"
#include "entity.h"
#include "form.h"
#include "mapdisp.h"
#include "zone.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
#define MAPLOAD_INSERT_MODEL_HILITES

// Defines
#define	MAPLOAD_MOF_RADIUS_EXTEND		(100)

#define	MAP_WATER_HEIGHT_TOLERANCE		(50)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

// Map structures
typedef	struct	__map_header			MAP_HEADER;
typedef struct	__graphical_header		GRAPHICAL_HEADER;
typedef	struct	__vertex_header			VERTEX_HEADER;
typedef	struct	__entity_header			ENTITY_HEADER;
typedef	struct	__form_header			FORM_HEADER;
typedef	struct	__light_header			LIGHT_HEADER;
typedef	struct	__path_header			PATH_HEADER;
typedef	struct	__zone_header			ZONE_HEADER;

typedef struct	__general_header		GENERAL_HEADER;
typedef struct	__grid_header			GRID_HEADER;
typedef struct	__group_header			GROUP_HEADER;
typedef struct	__poly_header			POLY_HEADER;
typedef struct	__anim_header			ANIM_HEADER;

typedef struct  __level_header			LEVEL_HEADER;

struct	__map_header
	{
	MR_ULONG			mh_id;					// "FROG"            	
	MR_ULONG			mh_file_length;			// Length of File in Bytes
	MR_ULONG			mh_version;				// Version Detail
	MR_UBYTE			mh_name[64];			// Level Name/Annotation String

	// Offsets to data packets
	GENERAL_HEADER*		mh_general_header;
	GRAPHICAL_HEADER*	mh_graphical_header;
	FORM_HEADER*		mh_form_header;
	ENTITY_HEADER*		mh_entity_header;
	ZONE_HEADER*		mh_zone_header;
	PATH_HEADER*		mh_path_header;

	};	// MAP_HEADER

// The following data is all located in the entities 'LevelHeader' structure...
struct  __level_header
	{
	MR_SHORT		gh_frog_red;
	MR_SHORT		gh_frog_green;
	MR_SHORT		gh_frog_blue;
	MR_SHORT		gh_frog_pad;
	};

struct	__general_header
	{
	MR_ULONG		gh_id;					// "GENE"
	MR_USHORT		gh_start_x;				// level start x grid coord
	MR_USHORT		gh_start_z;				// level start z grid coord
	MR_USHORT		gh_rotation;			// level start rotation (eg. FROG_DIRECTION_N)
	MR_USHORT		gh_theme;				// eg. THEME_SUB
					
	MR_USHORT		gh_trigger_timers[5];	// max times to reach triggers
	MR_USHORT		gh_perspective;			// map perspective constant
					
	MR_SVEC			gh_default_camera_source_ofs;
	MR_SVEC			gh_default_camera_target_ofs;

	// level header stuff follows (see struct above)
	LEVEL_HEADER	gh_level_header;
	};	// GENERAL_HEADER


struct	__graphical_header
	{
	MR_ULONG		gh_id;				// "GRMP"
	LIGHT_HEADER*	gh_light_header;
	GROUP_HEADER*	gh_group_header;
	POLY_HEADER*	gh_poly_header;
	VERTEX_HEADER*	gh_vertex_header;
	GRID_HEADER*	gh_grid_header;
	ANIM_HEADER*	gh_anim_header;

	};	// GRAPHICAL_HEADER


struct	__grid_header
	{
	MR_ULONG		gh_id;				// "GRID"
	MR_USHORT		gh_xnum;			// number of grid squares in x
	MR_USHORT		gh_znum;			// number of grid squares in z
	MR_USHORT		gh_xlen;			// x length of grid square
	MR_USHORT		gh_zlen;			// z length of grid square

	};	// GRID_HEADER


struct	__group_header
	{
	MR_ULONG		gh_id;				// "GROU"
	MR_SVEC			gh_basepoint;		// bottom left of map group grid
	MR_USHORT		gh_xnum;			// number of groups in x
	MR_USHORT		gh_znum;			// number of groups in z
	MR_USHORT		gh_xlen;			// x length of group
	MR_USHORT		gh_zlen;			// z length of group

	};	// GROUP_HEADER


struct	__poly_header
	{
	MR_ULONG		ph_id;				// "POLY"
	MR_USHORT		ph_num_f3;			// number of f3 polys
	MR_USHORT		ph_num_f4;			// number of f4 polys
	MR_USHORT		ph_num_ft3;			// number of ft3 polys
	MR_USHORT		ph_num_ft4;			// number of ft4 polys
	MR_USHORT		ph_num_g3;			// number of g3 polys
	MR_USHORT		ph_num_g4;			// number of g4 polys
	MR_USHORT		ph_num_gt3;			// number of gt3 polys
	MR_USHORT		ph_num_gt4;			// number of gt4 polys
	MR_USHORT		ph_num_g2;			// number of g2 polys
	MR_USHORT		ph_pad0;
	MAP_F3*			ph_f3_list;			// ptr (offset) to map poly list
	MAP_F4*			ph_f4_list;			// ptr (offset) to map poly list
	MAP_FT3*		ph_ft3_list;		// ptr (offset) to map poly list
	MAP_FT4*		ph_ft4_list;		// ptr (offset) to map poly list
	MAP_G3*			ph_g3_list;			// ptr (offset) to map poly list
	MAP_G4*			ph_g4_list;			// ptr (offset) to map poly list
	MAP_GT3*		ph_gt3_list;		// ptr (offset) to map poly list
	MAP_GT4*		ph_gt4_list;		// ptr (offset) to map poly list
	MAP_G2*			ph_g2_list;			// ptr (offset) to map poly list

	};	// POLY_HEADER


struct	__vertex_header
	{
	MR_ULONG	vh_id;				// "VRTX"
	MR_USHORT	vh_numverts;		// number of vertices in map
	MR_USHORT	vh_pad;

	};	// VERTEX HEADER


struct	__entity_header
	{
	MR_ULONG	eh_id;				// "EMTP"
	MR_ULONG	eh_packet_length;
	MR_USHORT	eh_numentities;		// number of entities in map
	MR_USHORT	eh_pad;

	};	// ENTITY_HEADER


struct	__form_header
	{
	MR_ULONG	fh_id;				// "FORM"
	MR_USHORT	fh_numforms;		// number of forms in map
	MR_USHORT	fh_pad;

	};	// FORM_HEADER


struct	__light_header
	{
	MR_ULONG	lh_id;				// "LITE"
	MR_ULONG	lh_numlights;		// number of lights in map

	};	// LIGHT_HEADER


struct	__path_header
	{
	MR_ULONG	ph_id;				// "PATH"
	MR_ULONG	ph_numpaths;		// number of paths in map

	};	// PATH_HEADER


struct	__zone_header
	{
	MR_ULONG	zh_id;				// "ZONE"
	MR_ULONG	zh_numzones;		// number of zones in map

	};	// ZONE_HEADER


struct	__anim_header
	{
	MR_ULONG	ah_id;				// "ANIM"
	MR_ULONG	ah_nummapanims;		// number of MAP_ANIMs in map
	MAP_ANIM*	ah_mapanims;		// offset (ptr) to array of MAP_ANIMs

	};	// ANIM_HEADER


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	ENTITY*				Map_group_entity_roots;
extern	MAP_HEADER*			Map_header;
extern	GRAPHICAL_HEADER*	Map_graphical_header;
extern	GENERAL_HEADER*		Map_general_header;
extern	GROUP_HEADER*		Map_group_header;
extern	GRID_HEADER*		Map_grid_header;
extern	MR_ULONG			Map_numgroups;
extern	MAP_GROUP*			Map_groups;
extern	MR_SVEC*			Map_vertices;
extern	MR_SVEC				Map_vertex_min;
extern	MR_SVEC				Map_vertex_max;
extern	MAP_BOOK*			Map_book;

extern	ENTITY_HEADER*		Map_entity_header;
extern	ENTITY**			Map_entity_ptrs;

extern	FORM_HEADER*		Map_form_header;
extern	FORM**				Map_form_ptrs;

extern	PATH_HEADER*		Map_path_header;
extern	PATH**				Map_path_ptrs;

extern	ZONE_HEADER*		Map_zone_header;
extern	ZONE**				Map_zone_ptrs;

extern	LIGHT_HEADER*		Map_light_header;
extern	LIGHT*				Map_lights;

extern	ANIM_HEADER*		Map_anim_header;
extern	MAP_ANIM*			Map_anims;

#ifdef WIN95
#ifdef MR_DEBUG
extern	MR_VOID*			map_memory;
#endif
#endif

extern	MR_LONG				Map_water_height;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		InitialiseMap(MR_VOID);
extern	MR_VOID		ResolveMapPolys(MR_VOID);
extern	MR_VOID		ResolveMapEntities(MR_VOID);
extern	MR_VOID		ResolveMapPaths(MR_VOID);
extern	MR_VOID		ResolveMapForms(MR_VOID);
extern	MR_VOID		ResolveMapAnims(MR_VOID);
extern	MR_VOID		ResolveMapAnimMapPolys(MR_VOID);
extern	MR_VOID		MapCalculateVertexLimits(MR_VOID);

extern	MR_VOID		MapCreateWibbleWater(MR_VOID);
extern	MR_VOID		MapCleanUpWibbleWater(MR_VOID);
extern	MR_VOID		MapVerticesSort(MR_SVEC**, MR_SVEC**, MR_LONG64*, MR_LONG64*);
extern	MR_VOID		MapVertexSwap(MR_SVEC**, MR_SVEC**, MR_LONG64*, MR_LONG64*);
extern	MR_VOID		AddVertex(MR_LONG*, MR_SHORT*, MR_LONG*);


#endif		//__MAPLOAD_H


