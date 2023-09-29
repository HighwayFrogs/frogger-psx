/******************************************************************************
*%%%% mapload.c
*------------------------------------------------------------------------------
*
*	Map loading and resolving
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*	30.04.97	Martin Kift		Added some win95 debug code for map loading
*	02.07.97	Martin Kift		Added functionality for thick forms
*	25.07.97	Martin Kift		Added water code.
*	12.08.97	Tim Closs		ResolveMapEntities() - fixed bugs in calculation
*								of form book radius2
*
*%%%**************************************************************************/
					      
#include "mapload.h"
#include "mapdisp.h"
#include "mapview.h"
#include "gamesys.h"
#include "project.h"
#include "library.h"
#include "sprdata.h"
#include "main.h"
#include "grid.h"
#include "zone.h"
#include "path.h"
#include "entlib.h"
#include "collide.h"
#include "entity.h"
#include "sound.h"

// Ptrs to headers/sections in map file
MAP_HEADER*			Map_header;
MAP_BOOK*			Map_book;

// Graphical map stuff
GRAPHICAL_HEADER*	Map_graphical_header;
GENERAL_HEADER*		Map_general_header;
GROUP_HEADER*		Map_group_header;
GRID_HEADER*		Map_grid_header;
MR_ULONG			Map_numgroups;
MAP_GROUP*			Map_groups;
MR_SVEC*			Map_vertices;

// Map vertex limits
MR_SVEC				Map_vertex_min;
MR_SVEC				Map_vertex_max;

// Entities
ENTITY_HEADER*		Map_entity_header;
ENTITY**			Map_entity_ptrs;
ENTITY*				Map_group_entity_roots;

// Forms
FORM_HEADER*		Map_form_header;
FORM**				Map_form_ptrs;

// Paths
PATH_HEADER*		Map_path_header;
PATH**				Map_path_ptrs;

// Zones
ZONE_HEADER*		Map_zone_header;
ZONE**				Map_zone_ptrs;

// Lights
LIGHT_HEADER*		Map_light_header;
LIGHT*				Map_lights;

// Animated polys
ANIM_HEADER*		Map_anim_header;
MAP_ANIM*			Map_anims;

#ifdef WIN95
#ifdef MR_DEBUG
MR_VOID*			map_memory;
#endif
#endif

#ifdef MAPLOAD_INSERT_MODEL_HILITES
MR_HILITE			Map_model_hilites[] =
	{
		{
		HILITE_TYPE_PARTICLE_EXHAUST,
		MR_HILITE_VERTEX,
		1, NULL, NULL,
		},
	};
#endif

MR_LONG		Map_water_height;

/******************************************************************************
*%%%% InitialiseMap
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseMap(MR_VOID)
*
*	FUNCTION	Set up global ptrs, do resolving, etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	30.04.97	Martin Kift		Added some win95 debug code for map loading
*	11.07.97	Gary Richards	Added code for WAD/Level.
*
*%%%**************************************************************************/

MR_VOID	InitialiseMap(MR_VOID)
{
	MAP_GROUP*		map_group;
	MR_ULONG  		i, ofs, m;
	ZONE**			zone_pptr;
	GRID_SQUARE*	grid_square;
	GRID_STACK*		grid_stack;

#ifdef WIN95
#ifdef MR_DEBUG
	int				fh = -1;
	MR_ULONG		filesize;
#endif
#endif

	Map_book 		= &Map_library[Game_map];

	// Note from Martin:
	//
	// The playstation gets its maps from the level wad (which is where the pc will ultimately
	// get them too!). But for debug purposes, the pc version needs to load in the map directly
	// using the file system, alloc mem for the map of course, and patch in the map pointer to
	// here. This allows the mappers to work with maps directly and not have to build wad files

#ifdef PSX
	// Load and process map
	MRLoadResource(Map_book->mb_map_res_id);
	MRProcessResource(Map_book->mb_map_res_id);

	// MAP_HEADER: resolve offsets to ptrs
	Map_header 	= MR_GET_RESOURCE_ADDR(Map_book->mb_map_res_id);
	ofs			= (MR_ULONG)Map_header;
#endif


#ifdef WIN95
#ifndef MR_DEBUG
	// Load and process map
	MRLoadResource(Map_book->mb_map_res_id);
	MRProcessResource(Map_book->mb_map_res_id);

	// MAP_HEADER: resolve offsets to ptrs
	Map_header 	= MR_GET_RESOURCE_ADDR(Map_book->mb_map_res_id);
	ofs			= (MR_ULONG)Map_header;
#else

	// open mapfile and copy it into memory
	if ( (fh = open(Map_book->mb_map_name, O_RDONLY|O_BINARY)) == -1)
		MR_ASSERTMSG(0, "Illegal map name, please check your command line");

	filesize = lseek(fh,0,SEEK_END);
	lseek(fh, 0, SEEK_SET);
	map_memory = MRAllocMem(filesize, "win95 frogger map");
	read(fh, (MR_UBYTE*)map_memory, filesize);
	close(fh);

	// MAP_HEADER: resolve offsets to ptrs, pointing at map loaded in directly!
	Map_header 	= (MAP_HEADER*)map_memory;
	ofs			= (MR_ULONG)Map_header;

#endif // MR_DEBUG
#endif // WIN95

	Map_header->mh_general_header 				= (GENERAL_HEADER*)		(((MR_UBYTE*)Map_header->mh_general_header) 				+ ofs);
	Map_header->mh_graphical_header 			= (GRAPHICAL_HEADER*)	(((MR_UBYTE*)Map_header->mh_graphical_header) 				+ ofs);
	Map_header->mh_form_header 					= (FORM_HEADER*)		(((MR_UBYTE*)Map_header->mh_form_header) 					+ ofs);
	Map_header->mh_entity_header 				= (ENTITY_HEADER*)		(((MR_UBYTE*)Map_header->mh_entity_header) 					+ ofs);
	Map_header->mh_zone_header 					= (ZONE_HEADER*)		(((MR_UBYTE*)Map_header->mh_zone_header)					+ ofs);
	Map_header->mh_path_header 					= (PATH_HEADER*)		(((MR_UBYTE*)Map_header->mh_path_header)					+ ofs);
														
	// GRAPHICAL_HEADER: resolve offsets to ptrs
	Map_graphical_header = (GRAPHICAL_HEADER*)Map_header->mh_graphical_header;
	Map_graphical_header->gh_light_header		= (LIGHT_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_light_header) 		+ ofs);
	Map_graphical_header->gh_group_header		= (GROUP_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_group_header) 		+ ofs);
	Map_graphical_header->gh_poly_header		= (POLY_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_poly_header) 			+ ofs);
	Map_graphical_header->gh_vertex_header		= (VERTEX_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_vertex_header) 		+ ofs);
	Map_graphical_header->gh_grid_header		= (GRID_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_grid_header) 			+ ofs);
	Map_graphical_header->gh_anim_header		= (ANIM_HEADER*)		(((MR_UBYTE*)Map_graphical_header->gh_anim_header) 			+ ofs);

	// GENERAL_HEADER: store globals
	Map_general_header 		= (GENERAL_HEADER*)Map_header->mh_general_header;
	//Game_perspective		= Map_general_header->gh_perspective;

	Game_map_theme			= Map_general_header->gh_theme;
	Form_library_ptrs[0]	= Theme_library[Game_map_theme].tb_form_library;
	Form_library_ptrs[1]	= Theme_library[THEME_GEN].tb_form_library;

	// Initialise Vab. (Has to be loaded before the map steals the memory.)
	InitialiseVab();

	// Check to see if we are playing a single VIEWPORT game.
	
	if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS)
		{
		// Load/process/unload theme VLO. (Single-Player Files.)
		MRLoadResource(Theme_library[Game_map_theme].tb_vlo_res_id);	   
		MRProcessResource(Theme_library[Game_map_theme].tb_vlo_res_id);			
		MRUnloadResource(Theme_library[Game_map_theme].tb_vlo_res_id);
		}
	else
		{
		// Load/process/unload theme VLO. (Multi-Player Files.)
		MRLoadResource(Theme_library[Game_map_theme].tb_multi_vlo_res_id);	   
		MRProcessResource(Theme_library[Game_map_theme].tb_multi_vlo_res_id);			
		MRUnloadResource(Theme_library[Game_map_theme].tb_multi_vlo_res_id);
		}
	
	// Load and process theme model WAD. (These are now Level based.)
	MRLoadResource(Map_book->mb_model_wad_res_id);
	MRProcessResource(Map_book->mb_model_wad_res_id);

	// GROUP_HEADER: store globals
	Map_group_header = (GROUP_HEADER*)Map_graphical_header->gh_group_header;
	MR_COPY_SVEC(&Map_view_basepoint, &Map_group_header->gh_basepoint);
	Map_view_xlen	= Map_group_header->gh_xlen;
	Map_view_zlen	= Map_group_header->gh_zlen;
	Map_view_xnum	= Map_group_header->gh_xnum;
	Map_view_znum	= Map_group_header->gh_znum;

	// Run through all MAP_GROUPS
	Map_groups 		= (MAP_GROUP*)(Map_group_header + 1);
	Map_numgroups	= Map_view_xnum * Map_view_znum;
	map_group		= Map_groups;
	i				= Map_numgroups;

	// Allocate memory for MAP_GROUP entity root ptrs
	Map_group_entity_roots = MRAllocMem(sizeof(ENTITY) * i, "ENTITY ROOT");

	while(i--)
		{
		// MAP_GROUP: resolve offsets to ptrs
		map_group->mg_f3_list 			= (MAP_F3*)		(((MR_UBYTE*)map_group->mg_f3_list) 		+ ofs);
		map_group->mg_f4_list 			= (MAP_F4*)		(((MR_UBYTE*)map_group->mg_f4_list) 		+ ofs);
		map_group->mg_ft3_list 			= (MAP_FT3*)	(((MR_UBYTE*)map_group->mg_ft3_list) 		+ ofs);
		map_group->mg_ft4_list 			= (MAP_FT4*)	(((MR_UBYTE*)map_group->mg_ft4_list) 		+ ofs);
		map_group->mg_g3_list 			= (MAP_G3*)		(((MR_UBYTE*)map_group->mg_g3_list) 		+ ofs);
		map_group->mg_g4_list 			= (MAP_G4*)		(((MR_UBYTE*)map_group->mg_g4_list) 		+ ofs);
		map_group->mg_gt3_list 			= (MAP_GT3*)	(((MR_UBYTE*)map_group->mg_gt3_list) 		+ ofs);
		map_group->mg_gt4_list 			= (MAP_GT4*)	(((MR_UBYTE*)map_group->mg_gt4_list) 		+ ofs);
												   	
//		if (map_group->mg_static_indices)
//			map_group->mg_static_indices = (MR_SHORT*)	(((MR_UBYTE*)map_group->mg_static_indices) 	+ ofs);
//
//		map_group->mg_num_g2			= NULL;
//		map_group->mg_g2_list			= NULL;

		map_group->mg_poly_group[0]		= NULL;
		map_group->mg_poly_group[1]		= NULL;
		map_group->mg_poly_group[2]		= NULL;
		map_group->mg_poly_group[3]		= NULL;

		map_group->mg_entity_root_ptr 	= Map_group_entity_roots + i;

		(Map_group_entity_roots + i)->en_next = NULL;
		(Map_group_entity_roots + i)->en_prev = NULL;
		map_group++;
		}

	// GRID_HEADER: store globals
	Map_grid_header = (GRID_HEADER*)Map_graphical_header->gh_grid_header;
	Grid_xnum 		= Map_grid_header->gh_xnum;
	Grid_znum 		= Map_grid_header->gh_znum;
	Grid_xlen 		= Map_grid_header->gh_xlen;
	Grid_zlen 		= Map_grid_header->gh_zlen;
	Grid_xshift		= 8;
	Grid_zshift 	= 8;
	Grid_base_x		= -(Grid_xlen * Grid_xnum) >> 1;
	Grid_base_z		= -(Grid_zlen * Grid_znum) >> 1;
	Grid_stacks 	= (GRID_STACK*)(Map_grid_header + 1);
	Grid_squares 	= (GRID_SQUARE*)(Grid_stacks + (Grid_xnum * Grid_znum));

	// Initialise fade positions to max limits
	MR_SET_SVEC(&Fade_top_left_pos,-32767,0,32767);
	MR_SET_SVEC(&Fade_bottom_right_pos,32767,0,-32767);

	// Run through all GRID_STACKs, finding maximum GRID_SQUARE index
	i 			= (Grid_xnum * Grid_znum);
	m			= 0;
	grid_stack	= Grid_stacks;
	while(i--)
		{
		m = MAX(m, (grid_stack->gs_index + grid_stack->gs_numsquares));
		grid_stack++;
		}

	// Run through all GRID_SQUAREs, resolving offsets to ptrs
	grid_square	= Grid_squares;
	while(m--)
		{
		grid_square->gs_map_poly = (MAP_F4*)(((MR_UBYTE*)grid_square->gs_map_poly) + ofs);
		grid_square++;
		}

	// VERTEX CHUNK:
	Map_vertices = (MR_SVEC*)(Map_graphical_header->gh_vertex_header + 1);
	MapCalculateVertexLimits();

	// FORM HEADER:
	Map_form_header = Map_header->mh_form_header;
	Map_form_ptrs	= (FORM**)(Map_form_header + 1);

	// Resolve form offsets, etc
	ResolveMapForms();

	// ZONE HEADER:
	Map_zone_header = Map_header->mh_zone_header;
	Map_zone_ptrs	= (ZONE**)(Map_zone_header + 1);

	// Resolve zone offsets to ptrs
	zone_pptr 	= Map_zone_ptrs;
	i			= Map_zone_header->zh_numzones;
	while(i--)
		{
		*zone_pptr 						= (ZONE*)((MR_ULONG)(*zone_pptr) + ofs);
		if ((*zone_pptr)->zo_numregions)
			(*zone_pptr)->zo_regions 	= (ZONE_REGION*)(((MR_ULONG)(*zone_pptr)->zo_regions) + ofs);
		zone_pptr++;
		}

	// LIGHT HEADER:
	Map_light_header 	= Map_graphical_header->gh_light_header;
	Map_lights			= (LIGHT*)(Map_graphical_header->gh_light_header + 1);

	// Resolve MAP_ANIMs and map polys
	ResolveMapAnimMapPolys();			// Resolve stuff in map polys linked to MAP_ANIMs
	ResolveMapPolys();					// Resolve uv, tpage, clut stuff in map polys
	ResolveMapAnims();					// Resolve MAP_ANIMs

	// PATH HEADER:
	Map_path_header 	= Map_header->mh_path_header;
	Map_path_ptrs		= (PATH**)(Map_path_header + 1);

	// Resolve path offsets to ptrs, etc.
	ResolveMapPaths();

	// This should be last, because it will rely on other things being sorted
	//
	// ENTITY HEADER:
	Map_entity_header 	= Map_header->mh_entity_header;
	Map_entity_ptrs		= (ENTITY**)(Map_entity_header + 1);

	// set up the environment mapped tetxure (if specced) so that the API works properly
	if (Map_library[Game_map].mb_env_texture_ptr)
		{
		MRSetEnvMap(Map_library[Game_map].mb_env_texture_ptr);
		}

	// Resolve entity offsets to ptrs, etc.
	ResolveMapEntities();

#ifdef MAPLOAD_INSERT_MODEL_HILITES
	{
	// BODGE! Put test hilite on org_truck_red
	MR_MOF*		mof_ptr;


	if ((Game_map_theme == THEME_ORG) && (Game_map != 29))
		{
		mof_ptr = MR_GET_RESOURCE_ADDR(RES_ORG_TRUCK_RED_XMR);
		((MR_PART*)(mof_ptr + 1))->mp_hilites 		= 1;
		((MR_PART*)(mof_ptr + 1))->mp_hilite_ptr 	= &Map_model_hilites[0];
		Map_model_hilites[0].mh_target_ptr			= (MR_ULONG*)&((MR_PART*)(mof_ptr + 1))->mp_partcel_ptr->mp_vert_ptr[Map_model_hilites[0].mh_index];
		((MR_SVEC*)Map_model_hilites[0].mh_target_ptr)->vx += 0x20;
	
		mof_ptr = MR_GET_RESOURCE_ADDR(RES_ORG_CAR_BLUE_XMR);
		((MR_PART*)(mof_ptr + 1))->mp_hilites 		= 1;
		((MR_PART*)(mof_ptr + 1))->mp_hilite_ptr 	= &Map_model_hilites[0];
	
		mof_ptr = MR_GET_RESOURCE_ADDR(RES_ORG_CAR_PURPLE_XMR);
		((MR_PART*)(mof_ptr + 1))->mp_hilites 		= 1;
		((MR_PART*)(mof_ptr + 1))->mp_hilite_ptr 	= &Map_model_hilites[0];
	
		mof_ptr = MR_GET_RESOURCE_ADDR(RES_ORG_LORRY_XMR);
		((MR_PART*)(mof_ptr + 1))->mp_hilites 		= 1;
		((MR_PART*)(mof_ptr + 1))->mp_hilite_ptr 	= &Map_model_hilites[0];
		}
	}
#endif
}


/******************************************************************************
*%%%% ResolveMapPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapPolys(MR_VOID)
*
*	FUNCTION	Resolve UVs, etc. in map polys
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	23.06.97	Tim Closs		Changed to use POLY_HEADER block.  Writes
*								GPU codes back to rgb0.cd for PSX
*
*%%%**************************************************************************/

MR_VOID	ResolveMapPolys(MR_VOID)
{
	MAP_F3*		map_f3;
	MAP_F4*		map_f4;
	MAP_FT3*	map_ft3;
	MAP_FT4*	map_ft4;
	MAP_G3*		map_g3;
	MAP_G4*		map_g4;
	MAP_GT3*	map_gt3;
	MAP_GT4*	map_gt4;
//	MAP_G2*		map_g2;
	MR_LONG		i, ofs;
	MR_TEXTURE*	texture;


	ofs	= (MR_ULONG)Map_header;
	if (i = Map_graphical_header->gh_poly_header->ph_num_f3)
		{
		Map_graphical_header->gh_poly_header->ph_f3_list = (MAP_F3*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_f3_list) + ofs);
		map_f3 = Map_graphical_header->gh_poly_header->ph_f3_list;
		while(i--)
			{
			map_f3->mp_rgb0.cd = Map_prim_type_codes[POLY_ID_F3];
			map_f3++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_f4)
		{
		Map_graphical_header->gh_poly_header->ph_f4_list = (MAP_F4*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_f4_list) + ofs);
		map_f4 = Map_graphical_header->gh_poly_header->ph_f4_list;
		while(i--)
			{
			map_f4->mp_rgb0.cd = Map_prim_type_codes[POLY_ID_F4];
			map_f4++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_g3)
		{
		Map_graphical_header->gh_poly_header->ph_g3_list = (MAP_G3*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_g3_list) + ofs);
		map_g3 = Map_graphical_header->gh_poly_header->ph_g3_list;
		while(i--)
			{
			map_g3->mp_rgb0.cd = Map_prim_type_codes[POLY_ID_G3];
			map_g3++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_g4)
		{
		Map_graphical_header->gh_poly_header->ph_g4_list = (MAP_G4*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_g4_list) + ofs);
		map_g4 = Map_graphical_header->gh_poly_header->ph_g4_list;
		while(i--)
			{
			map_g4->mp_rgb0.cd = Map_prim_type_codes[POLY_ID_G4];
			map_g4++;
			}
		}
//	if (i = Map_graphical_header->gh_poly_header->ph_num_g2)
//		{
//		Map_graphical_header->gh_poly_header->ph_g2_list = (MAP_G2*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_g2_list) + ofs);
//		map_g2 = Map_graphical_header->gh_poly_header->ph_g2_list;
//		while(i--)
//			{
//			map_g2->mp_rgb0.cd = Map_prim_type_codes[POLY_ID_G2];
//			map_g2++;
//			}
//		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_ft3)
		{
		Map_graphical_header->gh_poly_header->ph_ft3_list = (MAP_FT3*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_ft3_list) + ofs);
		map_ft3 = Map_graphical_header->gh_poly_header->ph_ft3_list;
		while(i--)
			{
			map_ft3->mp_rgb0.cd 	= Map_prim_type_codes[POLY_ID_FT3];

			// Resolve texture index to absolute index
			map_ft3->mp_tpage_id 	= Map_book->mb_texture_remap[map_ft3->mp_tpage_id];
			texture 				= bmp_pointers[map_ft3->mp_tpage_id];
			map_ft3->mp_tpage_id 	= texture->te_tpage_id;
#ifdef PSX
			map_ft3->mp_clut_id 	= texture->te_clut_id;
#endif				
			// Resolve to absolute VRAM offsets
			map_ft3->mp_u0 = (texture->te_w * map_ft3->mp_u0) / 0xff; 
			map_ft3->mp_u1 = (texture->te_w * map_ft3->mp_u1) / 0xff; 
			map_ft3->mp_u2 = (texture->te_w * map_ft3->mp_u2) / 0xff; 
			map_ft3->mp_v0 = (texture->te_h * map_ft3->mp_v0) / 0xff; 
			map_ft3->mp_v1 = (texture->te_h * map_ft3->mp_v1) / 0xff; 
			map_ft3->mp_v2 = (texture->te_h * map_ft3->mp_v2) / 0xff; 
			if (!(map_ft3->mp_flags & (MAP_POLY_ANIM_UV | MAP_POLY_ANIM_TEXTURE)))
				{
				// Resolve to absolute VRAM coords
				map_ft3->mp_u0 += texture->te_u0;
				map_ft3->mp_u1 += texture->te_u0;
				map_ft3->mp_u2 += texture->te_u0;
				map_ft3->mp_v0 += texture->te_v0;
				map_ft3->mp_v1 += texture->te_v0;
				map_ft3->mp_v2 += texture->te_v0;
				}
			map_ft3++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_ft4)
		{
		Map_graphical_header->gh_poly_header->ph_ft4_list = (MAP_FT4*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_ft4_list) + ofs);
		map_ft4 = Map_graphical_header->gh_poly_header->ph_ft4_list;
		while(i--)
			{
			map_ft4->mp_rgb0.cd 	= Map_prim_type_codes[POLY_ID_FT4];

			// Resolve texture index to absolute index
			map_ft4->mp_tpage_id 	= Map_book->mb_texture_remap[map_ft4->mp_tpage_id];
			texture 			 	= bmp_pointers[map_ft4->mp_tpage_id];
			map_ft4->mp_tpage_id 	= texture->te_tpage_id;
#ifdef PSX
			map_ft4->mp_clut_id		= texture->te_clut_id;
#endif				
			// Resolve to absolute VRAM offsets
			map_ft4->mp_u0 = (texture->te_w * map_ft4->mp_u0) / 0xff; 
			map_ft4->mp_u1 = (texture->te_w * map_ft4->mp_u1) / 0xff; 
			map_ft4->mp_u2 = (texture->te_w * map_ft4->mp_u2) / 0xff; 
			map_ft4->mp_u3 = (texture->te_w * map_ft4->mp_u3) / 0xff; 
			map_ft4->mp_v0 = (texture->te_h * map_ft4->mp_v0) / 0xff; 
			map_ft4->mp_v1 = (texture->te_h * map_ft4->mp_v1) / 0xff; 
			map_ft4->mp_v2 = (texture->te_h * map_ft4->mp_v2) / 0xff; 
			map_ft4->mp_v3 = (texture->te_h * map_ft4->mp_v3) / 0xff; 
			if (!(map_ft4->mp_flags & (MAP_POLY_ANIM_UV | MAP_POLY_ANIM_TEXTURE)))
				{
				// Resolve to absolute VRAM coords
				map_ft4->mp_u0 += texture->te_u0;
				map_ft4->mp_u1 += texture->te_u0;
				map_ft4->mp_u2 += texture->te_u0;
				map_ft4->mp_u3 += texture->te_u0;
				map_ft4->mp_v0 += texture->te_v0;
				map_ft4->mp_v1 += texture->te_v0;
				map_ft4->mp_v2 += texture->te_v0;
				map_ft4->mp_v3 += texture->te_v0;
				}
			map_ft4++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_gt3)
		{
		Map_graphical_header->gh_poly_header->ph_gt3_list = (MAP_GT3*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_gt3_list) + ofs);
		map_gt3 = Map_graphical_header->gh_poly_header->ph_gt3_list;
		while(i--)
			{
			map_gt3->mp_rgb0.cd 	= Map_prim_type_codes[POLY_ID_GT3];

			// Resolve texture index to absolute index
			map_gt3->mp_tpage_id 	= Map_book->mb_texture_remap[map_gt3->mp_tpage_id];
			texture 				= bmp_pointers[map_gt3->mp_tpage_id];
			map_gt3->mp_tpage_id 	= texture->te_tpage_id;
#ifdef PSX
			map_gt3->mp_clut_id 	= texture->te_clut_id;
#endif				
			// Resolve to absolute VRAM offsets
			map_gt3->mp_u0 = (texture->te_w * map_gt3->mp_u0) / 0xff; 
			map_gt3->mp_u1 = (texture->te_w * map_gt3->mp_u1) / 0xff; 
			map_gt3->mp_u2 = (texture->te_w * map_gt3->mp_u2) / 0xff; 
			map_gt3->mp_v0 = (texture->te_h * map_gt3->mp_v0) / 0xff; 
			map_gt3->mp_v1 = (texture->te_h * map_gt3->mp_v1) / 0xff; 
			map_gt3->mp_v2 = (texture->te_h * map_gt3->mp_v2) / 0xff; 
			if (!(map_gt3->mp_flags & (MAP_POLY_ANIM_UV | MAP_POLY_ANIM_TEXTURE)))
				{
				// Resolve to absolute VRAM coords
				map_gt3->mp_u0 += texture->te_u0;
				map_gt3->mp_u1 += texture->te_u0;
				map_gt3->mp_u2 += texture->te_u0;
				map_gt3->mp_v0 += texture->te_v0;
				map_gt3->mp_v1 += texture->te_v0;
				map_gt3->mp_v2 += texture->te_v0;
				}
			map_gt3++;
			}
		}	
	if (i = Map_graphical_header->gh_poly_header->ph_num_gt4)
		{
		Map_graphical_header->gh_poly_header->ph_gt4_list = (MAP_GT4*)(((MR_UBYTE*)Map_graphical_header->gh_poly_header->ph_gt4_list) + ofs);
		map_gt4 = Map_graphical_header->gh_poly_header->ph_gt4_list;
		while(i--)
			{
			map_gt4->mp_rgb0.cd 	= Map_prim_type_codes[POLY_ID_GT4];

			// Resolve texture index to absolute index
			map_gt4->mp_tpage_id 	= Map_book->mb_texture_remap[map_gt4->mp_tpage_id];
			texture 				= bmp_pointers[map_gt4->mp_tpage_id];
			map_gt4->mp_tpage_id 	= texture->te_tpage_id;
#ifdef PSX
			map_gt4->mp_clut_id 	= texture->te_clut_id;
#endif				
			// Resolve to absolute VRAM offsets
			map_gt4->mp_u0 = (texture->te_w * map_gt4->mp_u0) / 0xff; 
			map_gt4->mp_u1 = (texture->te_w * map_gt4->mp_u1) / 0xff; 
			map_gt4->mp_u2 = (texture->te_w * map_gt4->mp_u2) / 0xff; 
			map_gt4->mp_u3 = (texture->te_w * map_gt4->mp_u3) / 0xff; 
			map_gt4->mp_v0 = (texture->te_h * map_gt4->mp_v0) / 0xff; 
			map_gt4->mp_v1 = (texture->te_h * map_gt4->mp_v1) / 0xff; 
			map_gt4->mp_v2 = (texture->te_h * map_gt4->mp_v2) / 0xff; 
			map_gt4->mp_v3 = (texture->te_h * map_gt4->mp_v3) / 0xff; 
			if (!(map_gt4->mp_flags & (MAP_POLY_ANIM_UV | MAP_POLY_ANIM_TEXTURE)))
				{
				// Resolve to absolute VRAM coords
				map_gt4->mp_u0 += texture->te_u0;
				map_gt4->mp_u1 += texture->te_u0;
				map_gt4->mp_u2 += texture->te_u0;
				map_gt4->mp_u3 += texture->te_u0;
				map_gt4->mp_v0 += texture->te_v0;
				map_gt4->mp_v1 += texture->te_v0;
				map_gt4->mp_v2 += texture->te_v0;
				map_gt4->mp_v3 += texture->te_v0;
				}
			map_gt4++;
			}
		}	
}


/******************************************************************************
*%%%% ResolveMapEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapEntities(MR_VOID)
*
*	FUNCTION	Resolve offsets, create PATH_RUNNERs etc
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	30.04.97	Martin Kift		Added code to support 'immortal' entities
*	17.05.97	Martin Kift		Added code to calculated spherical collprim for
*								entities.
*	29.05.97	Gary Richards	Removed the en_flag clear, as mappy now supplies 
*								the flag data.
*	16.06.96	Martin Kift		Added entity flags respect when creating path runners
*	02.07.97	Martin Kift		Added functionality for thick forms
*	11.07.97	Gary Richards	Check to make sure we have all the models we need.
*	08.08.97	Gary Richards	Added a check for NO_MODEL flag from the form book.
*	12.08.97	Tim Closs		Fixed bugs in calculation of form book radius2
*
*%%%**************************************************************************/

MR_VOID	ResolveMapEntities(MR_VOID)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	ENTITY_BOOK*	entity_book;
	MR_ULONG		i, ofs;
	PATH_INFO*		path_info;
	FORM_BOOK*		form_book;
	MR_MOF*			mof;
	MR_BBOX*		bbox;
	MR_PART*		part;
	MR_PARTCEL*		part_cel;
	MR_ULONG		num_parts, num_part_cels;
	MR_ULONG		count, r;
	MR_COLLPRIM*	coll_prim;
	MR_ULONG		distance;

	// Resolve entity offsets to ptrs
	ofs			= (MR_ULONG)Map_header;
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		*entity_pptr 	= (ENTITY*)((MR_ULONG)(*entity_pptr) + ofs);
		entity			= *entity_pptr;
		entity_book		= ENTITY_GET_ENTITY_BOOK(entity);

		if (entity_book->eb_flags & ENTITY_BOOK_PATH_RUNNER)
			{
			// Create a PATH_RUNNER for the entity
			path_info	= (PATH_INFO*)(entity + 1);

			MR_ASSERT(entity->en_path_runner == NULL);
			entity->en_path_runner = CreatePathRunner(	Map_path_ptrs[path_info->pi_path_id],
														path_info->pi_segment_id,
														path_info->pi_segment_dist);

			entity->en_path_runner->pr_speed = path_info->pi_speed;
			entity->en_path_runner->pr_flags |= path_info->pi_motion_type;

			// Look at the entity flag (really the no movement flag) and if its set, 
			// mark the path runner as paused too
			if (entity->en_flags & ENTITY_NO_MOVEMENT)
				entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
			else
				entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
			}

		// Immortal entities need to be created now, and not when they are just on screen
		if (entity_book->eb_flags & ENTITY_BOOK_IMMORTAL)
			CreateLiveEntity(entity);

		// Write FORM maximum y from model bounding box, which can be overridden by the FORM_BOOK_THICK_FORM
		// formlib flag
		form_book	= ENTITY_GET_FORM_BOOK(entity);
		mof		 	= Map_mof_ptrs[form_book->fb_mof_id];

		// Check too see if the model is loaded.
		if (mof != NULL)
			{
			if (form_book->fb_flags & FORM_BOOK_THICK_FORM)
				{
				// make max y to some arbitary large value
				Map_form_ptrs[entity->en_form_grid_id]->fo_max_y = 0x7fff;
				}
			else
			if (form_book->fb_flags & FORM_BOOK_UNIT_FORM)
				{
				// make max y 256 units
				Map_form_ptrs[entity->en_form_grid_id]->fo_max_y = 0x100;
				}
			else
				{
				if (mof->mm_flags & MR_MOF_ANIMATED)
					{
					// Use animation global bounding box
					MR_ASSERT(((MR_ANIM_HEADER*)mof)->ah_model_sets->am_models->am_flags & MR_ANIM_GLOBAL_BBOXES_INCLUDED);
					bbox = ((MR_ANIM_HEADER*)mof)->ah_model_sets->am_models->am_static_bbox;
					}
				else
					{
					// Use bounding box of 1st part
					bbox = ((MR_PART*)(mof + 1))->mp_partcel_ptr->mp_bbox_ptr;
					}
				Map_form_ptrs[entity->en_form_grid_id]->fo_max_y = bbox->mb_verts[7].vy;
				}
	
			// Work out the spherical bounding box for this entities MOF, and store the
			// result in the FORM_BOOK... This code only runs if the radius is zero, 
			// this stops doing the same calculation over and over, and respects radius's
			// entered explicitly into the formbook
			if (form_book->fb_radius2 == 0)
				{
				if (mof->mm_flags & MR_MOF_ANIMATED)
					{
					// Use animation global bounding box
					MR_ASSERT(((MR_ANIM_HEADER*)mof)->ah_model_sets->am_models->am_flags & MR_ANIM_GLOBAL_BBOXES_INCLUDED);
					bbox = ((MR_ANIM_HEADER*)mof)->ah_model_sets->am_models->am_static_bbox;
	
					// walk through each part of the bounding box, storing MAX radius2
					count = 8;
					while (count--)
						{
//						form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vx));
//						form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vy));
//						form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vz));
						form_book->fb_radius2 = MAX(form_book->fb_radius2, MR_SVEC_MOD_SQR(&bbox->mb_verts[count]));
						}
					}
				else
					{
					// Use static MOF bounding box
					part 		= (MR_PART*)(mof + 1);
					num_parts 	= mof->mm_extra;
	
					// loop around for each part that exists in the model
					while (num_parts--)
						{
						part_cel		= part->mp_partcel_ptr;
						num_part_cels	= part->mp_partcels;
	
						// loop around for each part_cel
						while (num_part_cels--)
							{
							if (bbox = part_cel->mp_bbox_ptr)
								{
								// walk through each part of the bounding box, storing MAX radius2
								count = 8;
								while (count--)
									{
//									form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vx));
//									form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vy));
//									form_book->fb_radius2 = MAX (form_book->fb_radius2, abs(bbox->mb_verts[count].vz));
									form_book->fb_radius2 = MAX(form_book->fb_radius2, MR_SVEC_MOD_SQR(&bbox->mb_verts[count]));
									}
								}
							part_cel++;
							}
						part++;
						}
					}
	
				// Now rescan the entity and take into account any collprims contained within... if the collprim
				// stretches beyond the bounds of the bounding box, we need to take account of that too.
				if (!(mof->mm_flags & MR_MOF_ANIMATED))
					{
					part 		= (MR_PART*)(mof + 1);
					num_parts 	= mof->mm_extra;
	
					// loop around for each part that exists in the model
					while (num_parts--)
						{
						if (coll_prim = part->mp_collprim_ptr)
							{
//							// work out max offset
//							distance = MAX(coll_prim->cp_offset.vx, MAX(coll_prim->cp_offset.vy, coll_prim->cp_offset.vz));
//	
//							switch (coll_prim->cp_type)
//								{
//								case MR_COLLPRIM_CUBOID:
//									distance += MAX(coll_prim->cp_xlen, MAX(coll_prim->cp_ylen, coll_prim->cp_zlen));
//									if (distance > (MR_ULONG)form_book->fb_radius2)
//										form_book->fb_radius2 = distance;
//									break;
//	
//								case MR_COLLPRIM_CYLINDER_X:
//								case MR_COLLPRIM_CYLINDER_Y:
//								case MR_COLLPRIM_CYLINDER_Z:
//									// not using cylinders
//									MR_ASSERT (0);
//									break;
//	
//								case MR_COLLPRIM_SPHERE:
//									distance += MR_SQRT(coll_prim->cp_radius2);
//									if (distance > (MR_ULONG)form_book->fb_radius2)
//										form_book->fb_radius2 = distance;
//									break;
//								}

							do	{
								distance 	= MR_SVEC_MOD_SQR(&coll_prim->cp_offset);
								r			= 0;
								switch (coll_prim->cp_type)
									{
									case MR_COLLPRIM_CUBOID:
										r = MR_SQR(coll_prim->cp_xlen) + MR_SQR(coll_prim->cp_ylen) + MR_SQR(coll_prim->cp_zlen);
										break;
									case MR_COLLPRIM_CYLINDER_X:
										r = MR_SQR(coll_prim->cp_xlen) + coll_prim->cp_radius2;
										break;
									case MR_COLLPRIM_CYLINDER_Y:
										r = MR_SQR(coll_prim->cp_ylen) + coll_prim->cp_radius2;
										break;
									case MR_COLLPRIM_CYLINDER_Z:
										r = MR_SQR(coll_prim->cp_zlen) + coll_prim->cp_radius2;
										break;
									case MR_COLLPRIM_SPHERE:
										r = coll_prim->cp_radius2;
										break;
									}
								form_book->fb_radius2 = MAX(form_book->fb_radius2, distance + r);
											
								} while(!(coll_prim++->cp_flags & MR_COLL_LAST_IN_LIST));
							}
						part++;
						}
					}
				// Add in pre-defined addition value, to extend radius of sphere slightly, and square
				// the value to make sure radius is the square of!
				form_book->fb_radius2 += MAPLOAD_MOF_RADIUS_EXTEND;
				}	
			else
				{
				// Form library already contains squared collision radius
				}
			}
#ifdef	MR_DEBUG
		else
			{
			if (! (form_book->fb_flags & FORM_BOOK_FLAG_NO_MODEL) )
				printf("We have a model (%d) that is being displayed, not loaded in WAD file.\n",form_book->fb_mof_id);
			}
#endif

		// Clear out MAP_GROUP links
		entity->en_next = NULL;
		entity->en_prev = NULL;

		// If ENTITY_STATIC, link into list
		if (entity_book->eb_flags & ENTITY_BOOK_STATIC)
			EntityLinkToMapGroup(entity, (MR_VEC*)((MR_MAT*)(entity + 1))->t);

		entity_pptr++;
		}
}
	

/******************************************************************************
*%%%% ResolveMapPaths
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapPaths(MR_VOID)
*
*	FUNCTION	Resolve offsets, etc
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResolveMapPaths(MR_VOID)
{
	PATH**			path_pptr;
	PATH_SEGMENT**	segment_pptr;
	PATH*			path;
	MR_ULONG		i, s, ofs;


	// Resolve path offsets to ptrs
	ofs			= (MR_ULONG)Map_header;
	path_pptr 	= Map_path_ptrs;
	i			= Map_path_header->ph_numpaths;
	while(i--)
		{
		*path_pptr 			= (PATH*)((MR_ULONG)(*path_pptr) + ofs);
		path				= *path_pptr;

		if (path->pa_entity_indices)
			path->pa_entity_indices = (MR_SHORT*)((MR_ULONG)(path->pa_entity_indices) + ofs);

		segment_pptr		= (PATH_SEGMENT**)&path->pa_segment_ptrs;			
		s					= path->pa_numsegments;
		while(s--)
			{
			*segment_pptr	= (PATH_SEGMENT*)((MR_ULONG)(*segment_pptr) + ofs);
			segment_pptr++;
			}
		path_pptr++;
		}
}
	

/******************************************************************************
*%%%% ResolveMapForms
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapForms(MR_VOID)
*
*	FUNCTION	Resolve offsets, etc
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResolveMapForms(MR_VOID)
{
	FORM**			form_pptr;
	FORM*			form;
	FORM_DATA**		form_data_pptr;
	FORM_DATA*		form_data;
	MR_ULONG		i, j, ofs;


	// Resolve form offsets to ptrs
	ofs			= (MR_ULONG)Map_header;
	form_pptr 	= Map_form_ptrs;
	i			= Map_form_header->fh_numforms;
	while(i--)
		{
		*form_pptr 			= (FORM*)((MR_ULONG)(*form_pptr) + ofs);
		form				= *form_pptr;

		form_data_pptr		= (FORM_DATA**)&form->fo_formdata_ptrs;
		j					= form->fo_numformdatas;
		while(j--)
			{
			*form_data_pptr	= (FORM_DATA*)((MR_ULONG)(*form_data_pptr) + ofs);

			// Resolve FORM_DATA
			form_data					= *form_data_pptr;
			form_data->fd_grid_squares 	= (MR_USHORT*)	(((MR_ULONG)form_data->fd_grid_squares) + ofs);
			form_data->fd_heights		= (MR_SHORT*)	(((MR_ULONG)form_data->fd_heights) 		+ ofs);

			form_data_pptr++;
			}
		form_pptr++;
		}
}


/******************************************************************************
*%%%% MapCalculateVertexLimits
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCalculateVertexLimits(MR_VOID)
*
*	FUNCTION	Run through all vertices in the map, getting min and max coords
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapCalculateVertexLimits(MR_VOID)
{
	MR_SVEC*	vertex;
	MR_LONG		i;


	vertex 	= Map_vertices;	
	i		= Map_graphical_header->gh_vertex_header->vh_numverts;
	MR_SET_SVEC(&Map_vertex_min, 0x7fff, 0x7fff, 0x7fff);
	MR_SET_SVEC(&Map_vertex_max, 0x8000, 0x8000, 0x8000);
	
	while(i--)
		{
		Map_vertex_min.vx = MIN(Map_vertex_min.vx, vertex->vx);
		Map_vertex_min.vy = MIN(Map_vertex_min.vy, vertex->vy);
		Map_vertex_min.vz = MIN(Map_vertex_min.vz, vertex->vz);

		Map_vertex_max.vx = MAX(Map_vertex_max.vx, vertex->vx);
		Map_vertex_max.vy = MAX(Map_vertex_max.vy, vertex->vy);
		Map_vertex_max.vz = MAX(Map_vertex_max.vz, vertex->vz);

		vertex++;
		}
}


/******************************************************************************
*%%%% ResolveMapAnims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapAnims(MR_VOID)
*
*	FUNCTION	Resolve ANIM_HEADER and MAP_ANIM structures
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResolveMapAnims(MR_VOID)
{
#ifdef MAP_TEXTURE_ANIMATION
	MR_LONG			ofs, i, c;
	MAP_ANIM*		map_anim;
	MAP_UV_INFO*	map_uv_info;
	MR_USHORT*		index_ptr;


	// This MUST be called AFTER ResolveMapPolys(), so that the uvs in the map polys are absolute offsets from the top left
	// of the texture

	Map_anim_header = Map_graphical_header->gh_anim_header;
	ofs				= (MR_ULONG)Map_header;

	if (i = Map_anim_header->ah_nummapanims)
		{
		Map_anims	= Map_anim_header->ah_mapanims;
		map_anim	= Map_anims;
		while(i--)
			{
			if (map_anim->ma_flags & MAP_ANIM_TEXTURE)
				{
				// Resolve cel list to global texture indices
				map_anim->ma_cel_list 	= (MR_USHORT*)(((MR_UBYTE*)map_anim->ma_cel_list) + ofs);
				index_ptr				= map_anim->ma_cel_list;
				if ((*index_ptr) & 0x8000)
					{
					// Cel list has already been resolved
					}
				else
					{
					// Resolve each cel index to a global texture index
					c = map_anim->ma_numcels;
					while(c--)
						{
						*index_ptr = Map_book->mb_texture_remap[*index_ptr];
						index_ptr++;
						}
	
					// Flag first cel index to say that list has been resolved
					*map_anim->ma_cel_list |= 0x8000;
					}
				}

			// Run through all MAP_UV_INFO structures
			c 			= map_anim->ma_numpolys;
			map_uv_info	= map_anim->ma_map_uv_info;
			while(c--)
				{			
				// Store absolute offsets from top left of texture in VRAM
				map_uv_info->mu_u0	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u0;
				map_uv_info->mu_v0	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v0;
				map_uv_info->mu_u1	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u1;
				map_uv_info->mu_v1	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v1;
				map_uv_info->mu_u2	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u2;
				map_uv_info->mu_v2	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v2;
				map_uv_info->mu_u3	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u3;
				map_uv_info->mu_v3	= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v3;
				map_uv_info++;
				}
			map_anim++;
			}

		// Now run through all cel lists, resetting bit in first cel index
		i 			= Map_anim_header->ah_nummapanims;
		map_anim	= Map_anims;
		while(i--)
			{
			if (map_anim->ma_flags & MAP_ANIM_TEXTURE)
				*map_anim->ma_cel_list &= ~0x8000;

			map_anim++;
			}
		}
#endif
}


/******************************************************************************
*%%%% ResolveMapAnimMapPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResolveMapAnimMapPolys(MR_VOID)
*
*	FUNCTION	Resolve stuff in map polys linked to MAP_ANIMs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResolveMapAnimMapPolys(MR_VOID)
{
#ifdef MAP_TEXTURE_ANIMATION
	MR_LONG			ofs, i, c, t;
	MAP_ANIM*		map_anim;
	MAP_UV_INFO*	map_uv_info;


	// This MUST be called BEFORE ResolveMapPolys()
	Map_anim_header = Map_graphical_header->gh_anim_header;
	ofs				= (MR_ULONG)Map_header;

	if (i = Map_anim_header->ah_nummapanims)
		{
		Map_anim_header->ah_mapanims 	= (MAP_ANIM*)(((MR_UBYTE*)Map_anim_header->ah_mapanims)	+ ofs);
		Map_anims						= Map_anim_header->ah_mapanims;
		map_anim						= Map_anims;

		while(i--)
			{
			map_anim->ma_map_uv_info	= (MAP_UV_INFO*)(((MR_UBYTE*)map_anim->ma_map_uv_info) + ofs);
			map_uv_info 				= map_anim->ma_map_uv_info;
			c							= map_anim->ma_numpolys;
			while(c--)
				{
				map_uv_info->mu_map_poly = ((MR_UBYTE*)map_uv_info->mu_map_poly) + ofs;

				if (map_anim->ma_flags & MAP_ANIM_UV)
					((MAP_FT4*)map_uv_info->mu_map_poly)->mp_flags |= MAP_POLY_ANIM_UV;

				if (map_anim->ma_flags & MAP_ANIM_TEXTURE)
					((MAP_FT4*)map_uv_info->mu_map_poly)->mp_flags |= MAP_POLY_ANIM_TEXTURE;

				// Write MR_TEXTURE* back to MAP_ANIM.. we need this if the MAP_ANIM is using UV animation but no texture
				// animation
				t						= ((MAP_FT4*)map_uv_info->mu_map_poly)->mp_tpage_id;
				map_anim->ma_texture 	= bmp_pointers[Map_book->mb_texture_remap[t]];

				map_uv_info++;
				}
			map_anim++;
			}
		}
#endif
}

/******************************************************************************
*%%%% AddVertex
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	AddVertex(	MR_LONG*	vertices,
*									MR_LONG*	add_vertices,
*									MR_LONG*	count)
*
*	FUNCTION	Set up map water wibble structures, so they can be wibbled to
*				create a water wibble effect.
*
*	PARAMS		vertices		- ptr to vertex list to add to
*				add_vertices	- ptr to 4 vertices index to add
*				count			- number of vertices currently in list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*	07.08.97	Martin Kift		Rewrote to be faster
*
*%%%**************************************************************************/

MR_VOID	AddVertex(MR_LONG* vertices, MR_SHORT* add_vertices, MR_LONG* count)
{
#ifdef MAP_WATER_WIBBLE
	MR_LONG*	vertex_ptr;
	MR_SHORT*	add_vertex_ptr;
	MR_LONG		add_vertex_counter;
	MR_LONG		vertex_counter;

	add_vertex_ptr		= add_vertices;
	add_vertex_counter	= 4;

	// Loop through the 4 vertices pass into this function
	while (add_vertex_counter--)
		{
		// reset ptrs, and loop through all vertices, to see if already added
		vertex_ptr		= vertices;
		vertex_counter	= *count;
		
		while (vertex_counter--)
			{
			if (*add_vertex_ptr == *vertex_ptr)
				goto add_vertex_next;
			vertex_ptr++;
			}
		
		// vertex is a new one, add it and up the count
		*vertex_ptr = *add_vertex_ptr;
		(*count)++;

add_vertex_next:;
		// next add-vertex
		add_vertex_ptr++;
		}

#endif //MAP_WATER_WIBBLE
}

/******************************************************************************
*%%%% MapCreateWibbleWater
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCreateWibbleWater(MR_VOID)
*
*	FUNCTION	Set up map water wibble structures, so they can be wibbled to
*				create a water wibble effect.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*	28.07.97	Gary Richards	Fixed leak.
*
*%%%**************************************************************************/

MR_VOID	MapCreateWibbleWater(MR_VOID)
{
#ifdef MAP_WATER_WIBBLE
	MAP_FT4*	map_ft4;
	MAP_GT4*	map_gt4;
	MR_LONG		i, num_vertices, actual_vertices;
	MR_SVEC**	vertices_pptr;
	MR_LONG*	vertices;
	MR_LONG*	vertices_l_ptr;
	MR_SVEC**	v_buffer;
	MR_SVEC**	v_buffer_pptr;
	MR_LONG		count;
	MR_LONG64*	distances;
	MR_LONG64*	distances_ptr;

	count				= 0;

	// Set default water level.. its important to set it to something very low, since this figure
	// is used to change the frog base colours to turn him blue... although only in single player
	// mode
	Map_water_height	= 1000;	

	// Walk through polys to find our env map ones, which will dictate the water height for this level

	// clear everything
	Map_wibble_water.ww_num_vertices	= 0;
	Map_wibble_water.ww_vertices_ptr	= NULL;

	// Go through once, building up count of each poly type (well the textured ones anyway, since
	// these are the only ones which can be applied as MAX_OT, hence water river bed textures)
	if (i = Map_graphical_header->gh_poly_header->ph_num_ft4)
		{
		map_ft4 = Map_graphical_header->gh_poly_header->ph_ft4_list;
		while(i--)
			{
			if (map_ft4->mp_flags & MAP_POLY_ENVMAP)
				{
				Map_water_height = ((MR_SVEC*)Map_vertices + map_ft4->mp_vertices[0])->vy;
				break;
				}
			map_ft4++;
			}
		}

	// Go through once, building up count of each poly type (well the textured ones anyway, since
	// these are the only ones which can be applied as MAX_OT, hence water river bed textures)
	if (i = Map_graphical_header->gh_poly_header->ph_num_ft4)
		{
		map_ft4 = Map_graphical_header->gh_poly_header->ph_ft4_list;
		while(i--)
			{
			if (map_ft4->mp_flags & MAP_POLY_MAX_OT)
				Map_wibble_water.ww_num_vertices += 4;

			map_ft4++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_gt4)
		{
		map_gt4 = Map_graphical_header->gh_poly_header->ph_gt4_list;
		while(i--)
			{
			if (map_gt4->mp_flags & MAP_POLY_MAX_OT)
				Map_wibble_water.ww_num_vertices += 4;
			map_gt4++;
			}
		}	

	// Get poly numbers
	vertices		= (MR_LONG*)MRAllocMem(Map_wibble_water.ww_num_vertices * sizeof (MR_LONG), "Water wibble vertices buffer");
	num_vertices	= 0;

	// Copy all vertices out into the alloc'ed work buffer
	if (i = Map_graphical_header->gh_poly_header->ph_num_ft4)
		{
		map_ft4 = Map_graphical_header->gh_poly_header->ph_ft4_list;
		while(i--)
			{
			if (map_ft4->mp_flags & MAP_POLY_MAX_OT)
				AddVertex(vertices, map_ft4->mp_vertices, &num_vertices);
			map_ft4++;
			}
		}
	if (i = Map_graphical_header->gh_poly_header->ph_num_gt4)
		{
		map_gt4 = Map_graphical_header->gh_poly_header->ph_gt4_list;
		while(i--)
			{
			if (map_gt4->mp_flags & MAP_POLY_MAX_OT)
				AddVertex(vertices, map_gt4->mp_vertices, &num_vertices);
			map_gt4++;
			}
		}	

	// If we have water poly's, sort them out
	if (!num_vertices)
		{
		// Drop out before freeing memory
		MRFreeMem(vertices);					
		return;
		}

	// We now have a count of how many we have, so allocate a work buffer where all the points can be
	// added, sorted, and dropped if they are above or on the water surface...
	v_buffer		= (MR_SVEC**)MRAllocMem(num_vertices * sizeof (MR_SVEC*), "Water wibble vertices");
	v_buffer_pptr	= v_buffer;

	// Alloc buffer for where distances are stored
	distances		= (MR_LONG64*)MRAllocMem(num_vertices * sizeof (MR_LONG64), "Water wibble distances");
	distances_ptr	= distances;		

	// Add all vertices (SVEC's) into memory, working out max distance as we do it
	i				= num_vertices;
	vertices_l_ptr	= vertices;
	actual_vertices = 0;

	while (i--)
		{
		*v_buffer_pptr	= Map_vertices + *vertices_l_ptr;

		if ((*v_buffer_pptr)->vy > (Map_water_height + MAP_WATER_HEIGHT_TOLERANCE))
			{
			*distances_ptr	= (*v_buffer_pptr)->vx + ((MR_LONG64)(*v_buffer_pptr)->vz << 16);
			v_buffer_pptr++;
			distances_ptr++;
			actual_vertices++;
			}
		vertices_l_ptr++;
		}

	// We now have an ACTUAL count of how many we have, so allocate the memory needed for the points
	Map_wibble_water.ww_vertices_ptr	= (MR_SVEC**)MRAllocMem(actual_vertices * sizeof (MR_SVEC*), "Water wibble vertices");
	vertices_pptr						= Map_wibble_water.ww_vertices_ptr;
	v_buffer_pptr						= v_buffer;
	count								= actual_vertices;

	// copy all points across
	while (count--)
		{
		*vertices_pptr = *v_buffer_pptr;
		vertices_pptr++;
		v_buffer_pptr++;
		}

	// update vertex counter in structure
	Map_wibble_water.ww_num_vertices = actual_vertices;

	// Free buffer vertices
	MRFreeMem(v_buffer);
/*
	// Now we are ready to sort the list... joy
	MapVerticesSort(	Map_wibble_water.ww_vertices_ptr, 
						Map_wibble_water.ww_vertices_ptr + actual_vertices - 1,
						distances, 
						distances + actual_vertices - 1);
*/	
	// Free long ptr vertex memory, not needed anymore
	MRFreeMem(vertices);
	MRFreeMem(distances);
#endif //MAP_WATER_WIBBLE
}

/******************************************************************************
*%%%% MapCleanUpWibbleWater
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCleanUpWibbleWater(MR_VOID)
*
*	FUNCTION	Cleanmap water wibble memory, etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	MapCleanUpWibbleWater(MR_VOID)
{
#ifdef MAP_WATER_WIBBLE
	// If memory was allocated, remove it now
	if (Map_wibble_water.ww_vertices_ptr)
		{
		MRFreeMem(Map_wibble_water.ww_vertices_ptr);
		Map_wibble_water.ww_vertices_ptr = NULL;
		}
#endif MAP_WATER_WIBBLE
}



/******************************************************************************
*%%%% MapVertexSwap
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapVerticesSort(
*						MR_SVEC**	left_vertex_pptr,
*						MR_SVEC**	right_vertex_pptr, 
*						MR_LONG64*	left_distance_ptr,
*						MR_LONG64*	right_distance_ptr)
*
*	FUNCTION	Swaps vertices (and associated distances)
*
*	INPUTS		left_vertex_pptr	- ptr to 1st of 2 vertices to swap
*				right_vertex_pptr	- ptr to 2nd of 2 vertices to swap
*				left_distance_ptr	- ptr to 1st of 2 distances to swap
*				right_distance_ptr	- ptr to 2nd of 2 distances to swap
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID MapVertexSwap(MR_SVEC**		left_vertex_pptr, 
					  MR_SVEC**		right_vertex_pptr, 
					  MR_LONG64*	left_distance_ptr,
					  MR_LONG64*	right_distance_ptr)
{
	MR_SVEC*	vertex;
	MR_LONG64	distance;

	vertex				= *left_vertex_pptr;
	*left_vertex_pptr	= *right_vertex_pptr;
	*right_vertex_pptr	= vertex;

	distance			= *left_distance_ptr;
	*left_distance_ptr	= *right_distance_ptr;
	*right_distance_ptr	= distance;
}

/******************************************************************************
*%%%% MapVerticesSort
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapVerticesSort(
*						MR_SVEC**	first_vertex_pptr, 
*						MR_SVEC**	last_vertex_pptr, 
*						MR_LONG64*	first_distances_ptr, 
*						MR_LONG64*	last_distances_ptr)
*
*	FUNCTION	Performs a sort routine on an array of vertices, based on
*				an associated array of distances from the bottom left of
*				the map. Effectively sorts vertices into rows and columns.
*
*	INPUTS		first_vertex_pptr	- ptr to first vertex to sort
*				last_vertex_pptr	- ptr to last vertex to sort
*				first_distances_ptr	- ptr to first (associated) distance to sort
*				last_distances_ptr	- ptr to last (associated) distance to sort
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.08.97	Martin Kift		Created
*
*%%%**************************************************************************/
	
MR_VOID MapVerticesSort(	MR_SVEC**	first_vertex_pptr, 
							MR_SVEC**	last_vertex_pptr, 
							MR_LONG64*	first_distances_ptr, 
							MR_LONG64*	last_distances_ptr)
{
	MR_LONG		diff;
	MR_SVEC**	left_vertex_pptr;
	MR_SVEC**	right_vertex_pptr;
	MR_LONG64*	left_distances_ptr;
	MR_LONG64*	right_distances_ptr;
	MR_LONG64	pivot_distance;

	left_vertex_pptr	= first_vertex_pptr;
	right_vertex_pptr	= last_vertex_pptr;
	left_distances_ptr	= first_distances_ptr;
	right_distances_ptr	= last_distances_ptr;

	// choose a pivot ptr somewhere in the middle
	diff				= (right_vertex_pptr - left_vertex_pptr) >> 1;
	pivot_distance		= *(left_distances_ptr + diff);

	// partition the array of ptrs into two smaller partitions each of
	// which can be sorted in turn
	while (left_vertex_pptr <= right_vertex_pptr)
		{
		// move forward, find first/next ptr in partition which has short distance
		while (*left_distances_ptr < pivot_distance)
			{
			left_vertex_pptr++;
			left_distances_ptr++;
			}

		// move backwards, find first/next ptr in partition which has greater distance
		while (*right_distances_ptr > pivot_distance)
			{
			right_vertex_pptr--;
			right_distances_ptr--;
			}

		// if left ptr > right ptr then array has been partitioned, otherwise out of order, 
		// so swap them and move ptrs on by one.
		if (left_vertex_pptr <= right_vertex_pptr)
			{
			MapVertexSwap(left_vertex_pptr, right_vertex_pptr, left_distances_ptr, right_distances_ptr);
			left_vertex_pptr++;
			right_vertex_pptr--;
			left_distances_ptr++;
			right_distances_ptr--;
			}
		}

	if (first_vertex_pptr < right_vertex_pptr)
		MapVerticesSort(first_vertex_pptr, right_vertex_pptr, first_distances_ptr, right_distances_ptr);
	
	if (left_vertex_pptr < last_vertex_pptr)
		MapVerticesSort(left_vertex_pptr, last_vertex_pptr, left_distances_ptr, last_distances_ptr);

}
