/******************************************************************************
*%%%% mapdisp.c
*------------------------------------------------------------------------------
*
*	Map display
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Rewrote small part of prim code
*	25.07.97	Martin Kift		Added water code.
*	28.07.97	Martin Kift		Changed the poly_groups and Poly_root_nodes
*								to alloc'ed arrays, which saves lots of space
*								in single player mode
*
*%%%**************************************************************************/

#include "mapdisp.h"
#include "mapview.h"
#include "mapload.h"
#include "main.h"
#include "gamesys.h"
#include "frog.h"
#include "mapdebug.h"
#include "library.h"
#include "camera.h"
#include "water.h"

// Map group creation indices
MR_SHORT		Map_group_view_list[SYSTEM_MAX_VIEWPORTS][MAP_MAX_POLY_GROUPS + 1];

// Poly groups
POLY_GROUP*		Poly_groups[SYSTEM_MAX_VIEWPORTS];
POLY_NODE*		Poly_root_nodes[SYSTEM_MAX_VIEWPORTS];

// Light pool
MR_ULONG		Map_light_max_r2;
MR_ULONG		Map_light_min_r2;

// Platform prim type sizes
MR_ULONG		Map_prim_type_sizes[] =
	{
	sizeof(POLY_F3),
	sizeof(POLY_F4),
	sizeof(POLY_FT3),
	sizeof(POLY_FT4),
	sizeof(POLY_G3),
	sizeof(POLY_G4),
	sizeof(POLY_GT3),
	sizeof(POLY_GT4),
	sizeof(LINE_G2),
	};

// Platform prim type codes
MR_ULONG		Map_prim_type_codes[] =
	{
	0x20,
	0x28,
	0x24,
	0x2c,
	0x30,
	0x38,
	0x34,
	0x3c,
	0x50,
	};

// Sky land stuff
SKY_LAND_HEADER*	Sky_land_header;							// ptr to heaader structure for sky land
MR_USHORT*			Sky_land_texture_ids;						// ptr to array of texture indices for sky land
MR_SVEC*			Sky_land_vertices;							// ptr to array of vertices for sky land
POLY_FT4*			Sky_land_polys[SYSTEM_MAX_VIEWPORTS][2];	// polys for quads in each viewport
MR_VEC				Sky_drift_position;
MR_VEC				Sky_drift_velocity;
MR_VEC				Sky_drift_acceleration;
MR_ULONG			Sky_land_base_colours[] =
	{
	0x606060,	// LOONEY BALLOONS
	0x302010,	// AIRSHOW ANTICS
	0x406070,	// LOONIER BALLOONS
	0x304070,	// TIME FLIES
	};


#ifdef MAP_WIREFRAME_EXTENSION
MR_CVEC				Map_wireframe_line_colours[MAP_WIREFRAME_CORNER_NUM_LINES + 1];
#endif

#ifdef MAP_WATER_WIBBLE
// Water wibbling
MAP_WIBBLE_WATER	Map_wibble_water;
#endif


/******************************************************************************
*%%%% InitialiseMapDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseMapDisplay(MR_VOID)
*
*	FUNCTION	Initialise map display stuff
*
*	MATCH		https://decomp.me/scratch/RLYIK	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	02.05.97	Martin Kift		PC'er'fied
*	20.06.97	Gary Richards	Took out the 'Set Light pools' sets cause they
*								are not needed. (They screw-up the caves light.)
*	28.07.97	Martin Kift		Added poly group memory alloc code
*	16.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	InitialiseMapDisplay(MR_VOID)
{
	MR_ULONG	i, j, k, v;
	POLY_GROUP*	poly_group;
	POLY_NODE*	poly_node;
	MR_SVEC*	svec_ptr;
	POLY_FT4*	poly_ft4;
	MR_TEXTURE*	texture;
	MR_USHORT*	index_ptr;


	// Allocate space for the poly groups
	Poly_groups[0] = MRAllocMem(sizeof(POLY_GROUP) * MAP_MAX_POLY_GROUPS * Game_total_viewports, "Map poly groups");
	for (i = 1; i < Game_total_viewports; i++)
		Poly_groups[i] = Poly_groups[i - 1] + MAP_MAX_POLY_GROUPS;

	// Set up POLY_GROUPs
 	poly_group 	= Poly_groups[0];
 	i 			= MAP_MAX_POLY_GROUPS * Game_total_viewports;
	while(i--)
		{
		poly_group->pg_map_group	= NULL;
		poly_group->pg_timer 		= 0;
		poly_group++;
		}

#ifdef DEBUG
	Map_debug_poly_groups			= 0;
#endif

	// Allocate space for the poly nodes
	Poly_root_nodes[0] = MRAllocMem(sizeof(POLY_NODE) * POLY_ID_LAST * Game_total_viewports, "Map poly nodes");
	for (i = 1; i < Game_total_viewports; i++)
		Poly_root_nodes[i] = Poly_root_nodes[i - 1] + POLY_ID_LAST;

	// Set up POLY_NODEs
 	poly_node 	= Poly_root_nodes[0];
 	i 			= POLY_ID_LAST * Game_total_viewports;
	while(i--)
		{
		poly_node->pn_next = NULL;
		poly_node++;
		}

	if (Game_map_theme == THEME_SKY)
		{
		// Load and process sky land map
		MRLoadResource(RES_SKY_LAND_MAP);
		MRProcessResource(RES_SKY_LAND_MAP);

 		Sky_land_header 		= MR_GET_RESOURCE_ADDR(RES_SKY_LAND_MAP);
		Sky_land_texture_ids 	= (MR_USHORT*)(Sky_land_header + 1);
		Sky_land_vertices		= MRAllocMem(sizeof(MR_SVEC) * (Sky_land_header->sl_xnum + 1) * (Sky_land_header->sl_znum + 1), "SKY LAND VERTICES");
		MR_CLEAR_VEC(&Sky_drift_position);
		MR_CLEAR_VEC(&Sky_drift_velocity);
		MR_CLEAR_VEC(&Sky_drift_acceleration);
	
		i						= Sky_land_header->sl_xnum * Sky_land_header->sl_znum;
		Sky_land_polys[0][0]	= MRAllocMem(sizeof(POLY_FT4) * i * 2 * Game_total_viewports, "SKY LAND QUADS");
		Sky_land_polys[0][1]	= Sky_land_polys[0][0] + i;
		for (j = 1; j < Game_total_viewports; j++)
			{
			Sky_land_polys[j][0] = Sky_land_polys[j - 1][1] + i;
			Sky_land_polys[j][1] = Sky_land_polys[j][0] + i;
			}

		// Set up sky land polys
		poly_ft4 = Sky_land_polys[0][0];
		for (v = 0; v < Game_total_viewports; v++)
			{
			for (k = 0; k < 2; k++)
				{
				index_ptr = Sky_land_texture_ids;
				for (j = 0; j < Sky_land_header->sl_znum; j++)
					{
					for (i = 0; i < Sky_land_header->sl_xnum; i++)
						{
						texture = bmp_pointers[txl_sky_land[(*index_ptr) & 0x3fff]];

						// AIRSHOW ANTICS land is darker
						MR_SET32(poly_ft4->r0, Sky_land_base_colours[Game_map - LEVEL_SKY1]);
						setPolyFT4(poly_ft4);

						switch(((*index_ptr) & 0xc000) >> 14)
							{
							case 0:
								MR_COPY16(poly_ft4->u0, texture->te_u0);
								MR_COPY16(poly_ft4->u1, texture->te_u1);
								MR_COPY16(poly_ft4->u2, texture->te_u2);
								MR_COPY16(poly_ft4->u3, texture->te_u3);
								break;
							case 1:
								MR_COPY16(poly_ft4->u0, texture->te_u2);
								MR_COPY16(poly_ft4->u1, texture->te_u0);
								MR_COPY16(poly_ft4->u2, texture->te_u3);
								MR_COPY16(poly_ft4->u3, texture->te_u1);
								break;
							case 2:
								MR_COPY16(poly_ft4->u0, texture->te_u3);
								MR_COPY16(poly_ft4->u1, texture->te_u2);
								MR_COPY16(poly_ft4->u2, texture->te_u1);
								MR_COPY16(poly_ft4->u3, texture->te_u0);
								break;
							case 3:
								MR_COPY16(poly_ft4->u0, texture->te_u1);
								MR_COPY16(poly_ft4->u1, texture->te_u3);
								MR_COPY16(poly_ft4->u2, texture->te_u0);
								MR_COPY16(poly_ft4->u3, texture->te_u2);
								break;
							}								
#ifdef PSX
						poly_ft4->clut 	= texture->te_clut_id;
#endif
						poly_ft4->tpage = texture->te_tpage_id;
						index_ptr++;

						if	(!(
							(j == (Sky_land_header->sl_znum - 1)) &&
							(i == (Sky_land_header->sl_xnum - 1))
							))
							catPrim(poly_ft4, poly_ft4 + 1);

						poly_ft4++;
						}
					}
				}
			}	
		
		// Set up sky land vertices
		svec_ptr = Sky_land_vertices;
		for (j = 0; j <= Sky_land_header->sl_znum; j++)
			{
			for (i = 0; i <= Sky_land_header->sl_xnum; i++)
				{
				svec_ptr->vx	= (i * SKY_LAND_GRIDLEN) - (Sky_land_header->sl_xnum * SKY_LAND_GRIDLEN / 2);
				svec_ptr->vy	= SKY_LAND_HEIGHT;
				svec_ptr->vz	= (j * SKY_LAND_GRIDLEN) - (Sky_land_header->sl_znum * SKY_LAND_GRIDLEN / 2);
				svec_ptr++;
				}
			}
		}

	// Set the cave light to max, if playing cave multi-player.
	if (Game_map == LEVEL_CAVES_MULTI_PLAYER)
		{
		Map_light_max_r2 = (128 << 16);
		Map_light_min_r2 = (128 << 16);
		}

	// Wireframe lines
	MapCreateWireframeLines();

	// Wibbling water effect
	MapCreateWibbleWater();
	WaterInitialiseSinOffsetsTable();
}


/******************************************************************************
*%%%% DeinitialiseMapDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeinitialiseMapDisplay(MR_VOID)
*
*	FUNCTION	Deinitialise map display stuff
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	DeinitialiseMapDisplay(MR_VOID)
{
#ifdef MAP_WIREFRAME_EXTENSION
	MAP_GROUP*	map_group;
	MR_LONG		i;
#endif

	// Free stuff for sky land if necessary
	if (Game_map_theme == THEME_SKY)
		{
		MRFreeMem(Sky_land_vertices);
		MRFreeMem(Sky_land_polys[0][0]);
		MRUnloadResource(RES_SKY_LAND_MAP);
		}

#ifdef MAP_WIREFRAME_EXTENSION
	// Free memory for wireframe lines
	map_group 	= Map_groups;
	i 			= Map_view_xnum * Map_view_znum;
	while(i--)
		{
		if (map_group->mg_g2_list)
			MRFreeMem(map_group->mg_g2_list);

		map_group++;
		}
#endif

	// Wibbling water effect
	MapCleanUpWibbleWater();
}


/******************************************************************************
*%%%% FindFreePolyGroup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	POLY_GROUP*	pgroup =	FindFreePolyGroup(
*										MR_ULONG	vp_id)
*
*	FUNCTION	Find a free POLY_GROUP for a given viewport
*
*	INPUTS		MR_ULONG	vp_id	-	viewport id
*
*	RESULT		pgroup	-	ptr to free POLY_GROUP, or NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

POLY_GROUP*	FindFreePolyGroup(MR_ULONG	vp_id)
{
	MR_ULONG	i;
	POLY_GROUP*	poly_group;


	poly_group 	= Poly_groups[vp_id];
 	i 			= MAP_MAX_POLY_GROUPS;
	while(i--)
		{
		if (!poly_group->pg_map_group)
			// Free POLY_GROUP found
			return(poly_group);
		
		poly_group++;
		}

	// No free POLY_GROUP found
	return(NULL);
}


/******************************************************************************
*%%%% ExpandMapGroup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	polys =	ExpandMapGroup(
*								MR_SHORT		index,
*								MR_ULONG		vp_id,
*								MR_LONG			poly_count)
*
*	FUNCTION	Create the poly groups for a map group
*
*	INPUTS		index		-	index of MAP_GROUP within map file
*				vp_id		-	viewport id
*				poly_count	-	max polys left to use up this frame
*
*	RESULT		polys		-	max polys left after calling this function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/


MR_LONG	ExpandMapGroup(	MR_SHORT	index,
			  			MR_ULONG	vp_id,
			  			MR_LONG		poly_count)
{
	MAP_GROUP*		map_group;
	POLY_GROUP*		poly_group;
	MR_ULONG		total_polys;
	MR_ULONG		prim_bufflen;
	MR_ULONG		npolys;
	MR_UBYTE*		prims0;
	MR_UBYTE*		prims1;
	MR_UBYTE*		mpoly;
	ENTITY*			entity;
	MR_VIEWPORT*	vp;
	POLY_NODE*		poly_root_nodes;


	MR_ASSERT(index >= 0);
	MR_ASSERT(index < (Map_view_xnum * Map_view_znum));

	map_group 		= Map_groups + index;
	vp				= Game_viewports[vp_id];
	poly_root_nodes	= Poly_root_nodes[vp_id];

	//-------------------------------------------------------------------------
	// Entity stuff
	//-------------------------------------------------------------------------
	entity = map_group->mg_entity_root_ptr;
	while(entity = entity->en_next)
		{
		// Is entity LIVE?
		if (entity->en_live_entity)
			{
			if (entity->en_flags & ENTITY_HIDDEN)
				// Keep destroy flag
				{
				}
			else
				// Clear destroy flag
				{
				entity->en_live_entity->le_flags &= ~LIVE_ENTITY_DESTROY;
				}					
			}
		else
			{
			// No: create LIVE_ENTITY
			if (!(entity->en_flags & ENTITY_HIDDEN))
				CreateLiveEntity(entity);
			}
		}

	//-------------------------------------------------------------------------
	// Poly mesh stuff
	//-------------------------------------------------------------------------
	total_polys	= map_group->mg_num_f3	+
				  map_group->mg_num_f4 	+
				  map_group->mg_num_ft3 +
				  map_group->mg_num_ft4 +
				  map_group->mg_num_g3 	+
				  map_group->mg_num_g4 	+
				  map_group->mg_num_gt3 +
#ifdef MAP_WIREFRAME_EXTENSION
				  map_group->mg_num_gt4 +
				  map_group->mg_num_g2;
#else
				  map_group->mg_num_gt4;
#endif

 	if (poly_group = map_group->mg_poly_group[vp_id])
		{
		// map_group->mg_poly_group is non-null, so POLY_GROUP has already been set up... so nothing to do
 		if (poly_group->pg_timer < 2)
			return(poly_count - total_polys);

 		poly_group->pg_timer = 3;
		}
	else
		{
		if (!(total_polys))
			{
			// If map_group->mg_npolys == 0, MAP_GROUP is empty, so nothing to do
			poly_group = NULL;
			return(poly_count);
			}
		if (!(poly_group = FindFreePolyGroup(vp_id)))
			{
			// No free poly group
			return(poly_count);
			}
		if (total_polys > poly_count)
			{
			// Too many polys in this map group
			return(poly_count);
			}

#ifdef DEBUG
		Map_debug_poly_groups++;
#endif
		map_group->mg_poly_group[vp_id]	= poly_group;
 		poly_group->pg_map_group 		= map_group;
 		poly_group->pg_timer			= 3;

		prim_bufflen =	(sizeof(POLY_F3)  	* map_group->mg_num_f3) 	+
						(sizeof(POLY_F4)  	* map_group->mg_num_f4) 	+
						(sizeof(POLY_FT3) 	* map_group->mg_num_ft3) 	+
						(sizeof(POLY_FT4) 	* map_group->mg_num_ft4) 	+
						(sizeof(POLY_G3) 	* map_group->mg_num_g3) 	+
						(sizeof(POLY_G4) 	* map_group->mg_num_g4) 	+
						(sizeof(POLY_GT3) 	* map_group->mg_num_gt3) 	+
#ifdef MAP_WIREFRAME_EXTENSION
						(sizeof(POLY_GT4) 	* map_group->mg_num_gt4)	+
						(sizeof(LINE_G2) 	* map_group->mg_num_g2);
#else
						(sizeof(POLY_GT4) 	* map_group->mg_num_gt4);
#endif

		// Allocated space for prims
		poly_group->pg_flags	= NULL;
		poly_group->pg_prims[0]	= MRAllocMem(prim_bufflen << 1, "POLY_GROUP_PRIMS");
		poly_group->pg_prims[1]	= poly_group->pg_prims[0] + prim_bufflen;
	
		// The following pointers increase through the PSX prim buffers for this POLY_GROUP as polys of different types are set
		//	up... before the first poly of a new type is set up, these pointers are set up in the POLY_NODEs
		prims0 = poly_group->pg_prims[0];
		prims1 = poly_group->pg_prims[1];

		//-----------
		// Build f3s
		//-----------
		if (poly_group->pg_polys_f3.pn_numpolys = map_group->mg_num_f3)
			{
			mpoly = (MR_UBYTE*)map_group->mg_f3_list;

			// Link polys
			if (poly_group->pg_polys_f3.pn_next		= poly_root_nodes[POLY_ID_F3].pn_next)
				poly_root_nodes[POLY_ID_F3].pn_next->pn_prev = &poly_group->pg_polys_f3;
			poly_root_nodes[POLY_ID_F3].pn_next		= &poly_group->pg_polys_f3;
			poly_group->pg_polys_f3.pn_prev			= &poly_root_nodes[POLY_ID_F3];
			poly_group->pg_polys_f3.pn_prims[0]		= prims0;
			poly_group->pg_polys_f3.pn_prims[1]		= prims1;
			poly_group->pg_polys_f3.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_f3.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_F3*)prims0)->r0, ((MAP_F3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_F3*)prims1)->r0, ((MAP_F3*)mpoly)->mp_rgb0);
#ifdef WIN95
				setPolyF3((POLY_F3*)prims0);
				setPolyF3((POLY_F3*)prims1);
#else
				setlen(prims0, 4);
				setlen(prims1, 4);
#endif
				((POLY_F3*)prims0)++;
				((POLY_F3*)prims1)++;
				((MAP_F3*)mpoly)++;
				}
			}
		//-----------
		// Build f4s
		//-----------
		if (poly_group->pg_polys_f4.pn_numpolys = map_group->mg_num_f4)
			{
			mpoly = (MR_UBYTE*)map_group->mg_f4_list;

			// Link polys
			if (poly_group->pg_polys_f4.pn_next		= poly_root_nodes[POLY_ID_F4].pn_next)
				poly_root_nodes[POLY_ID_F4].pn_next->pn_prev = &poly_group->pg_polys_f4;
			poly_root_nodes[POLY_ID_F4].pn_next		= &poly_group->pg_polys_f4;
			poly_group->pg_polys_f4.pn_prev			= &poly_root_nodes[POLY_ID_F4];
			poly_group->pg_polys_f4.pn_prims[0]		= prims0;
			poly_group->pg_polys_f4.pn_prims[1]		= prims1;
			poly_group->pg_polys_f4.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_f4.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_F4*)prims0)->r0, ((MAP_F4*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_F4*)prims1)->r0, ((MAP_F4*)mpoly)->mp_rgb0);
#ifdef WIN95
				setPolyF4((POLY_F4*)prims0);
				setPolyF4((POLY_F4*)prims1);
#else
				setlen(prims0, 5);
				setlen(prims1, 5);
#endif
				((POLY_F4*)prims0)++;
				((POLY_F4*)prims1)++;
				((MAP_F4*)mpoly)++;
				}
			}
		//-----------
		// Build ft3s
		//-----------
		if (poly_group->pg_polys_ft3.pn_numpolys = map_group->mg_num_ft3)
			{
			mpoly = (MR_UBYTE*)map_group->mg_ft3_list;

			// Link polys
			if (poly_group->pg_polys_ft3.pn_next	= poly_root_nodes[POLY_ID_FT3].pn_next)
				poly_root_nodes[POLY_ID_FT3].pn_next->pn_prev = &poly_group->pg_polys_ft3;
			poly_root_nodes[POLY_ID_FT3].pn_next	= &poly_group->pg_polys_ft3;
			poly_group->pg_polys_ft3.pn_prev		= &poly_root_nodes[POLY_ID_FT3];
			poly_group->pg_polys_ft3.pn_prims[0]	= prims0;
			poly_group->pg_polys_ft3.pn_prims[1]	= prims1;
			poly_group->pg_polys_ft3.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_ft3.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_FT3*)prims0)->r0, ((MAP_FT3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_FT3*)prims1)->r0, ((MAP_FT3*)mpoly)->mp_rgb0);
#ifdef WIN95
				setPolyFT3((POLY_FT3*)prims0);
				setPolyFT3((POLY_FT3*)prims1);
#else
				setlen(prims0, 7);
				setlen(prims1, 7);
#endif
				if (((MAP_FT3*)mpoly)->mp_flags & MAP_POLY_SEMITRANS)
					{		
					setSemiTrans((POLY_FT3*)prims0, 1);
					setSemiTrans((POLY_FT3*)prims1, 1);
					}
#ifdef PSX
				MR_COPY32(((POLY_FT3*)prims0)->u0, ((MAP_FT3*)mpoly)->mp_u0);
				MR_COPY32(((POLY_FT3*)prims0)->u1, ((MAP_FT3*)mpoly)->mp_u1);
				MR_COPY32(((POLY_FT3*)prims1)->u0, ((MAP_FT3*)mpoly)->mp_u0);
				MR_COPY32(((POLY_FT3*)prims1)->u1, ((MAP_FT3*)mpoly)->mp_u1);
#else
				MR_COPY16(((POLY_FT3*)prims0)->u0, ((MAP_FT3*)mpoly)->mp_u0);
				MR_COPY16(((POLY_FT3*)prims0)->u1, ((MAP_FT3*)mpoly)->mp_u1);
				((POLY_FT3*)prims0)->tpage = ((MAP_FT3*)mpoly)->mp_tpage_id;
				MR_COPY16(((POLY_FT3*)prims1)->u0, ((MAP_FT3*)mpoly)->mp_u0);
				MR_COPY16(((POLY_FT3*)prims1)->u1, ((MAP_FT3*)mpoly)->mp_u1);
				((POLY_FT3*)prims1)->tpage = ((MAP_FT3*)mpoly)->mp_tpage_id;
#endif
				MR_COPY16(((POLY_FT3*)prims0)->u2, ((MAP_FT3*)mpoly)->mp_u2);
				MR_COPY16(((POLY_FT3*)prims1)->u2, ((MAP_FT3*)mpoly)->mp_u2);

				((POLY_FT3*)prims0)++;
				((POLY_FT3*)prims1)++;
				((MAP_FT3*)mpoly)++;
				}
			}
		//-----------
		// Build ft4s
		//-----------
		if (poly_group->pg_polys_ft4.pn_numpolys = map_group->mg_num_ft4)
			{
			mpoly = (MR_UBYTE*)map_group->mg_ft4_list;

			// Link polys
			if (poly_group->pg_polys_ft4.pn_next	= poly_root_nodes[POLY_ID_FT4].pn_next)
				poly_root_nodes[POLY_ID_FT4].pn_next->pn_prev = &poly_group->pg_polys_ft4;
			poly_root_nodes[POLY_ID_FT4].pn_next	= &poly_group->pg_polys_ft4;
			poly_group->pg_polys_ft4.pn_prev		= &poly_root_nodes[POLY_ID_FT4];
			poly_group->pg_polys_ft4.pn_prims[0]	= prims0;
			poly_group->pg_polys_ft4.pn_prims[1]	= prims1;
			poly_group->pg_polys_ft4.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_ft4.pn_numpolys;
			while(npolys--)
				{
//				if (((MAP_FT4*)mpoly)->mp_flags & MAP_POLY_ENVMAP)
//					{
//					MR_SET32(((POLY_FT4*)prims0)->r0, 0x2e306060);
//					MR_SET32(((POLY_FT4*)prims1)->r0, 0x2e306060);
//					}
//				else
					{
					MR_COPY32(((POLY_FT4*)prims0)->r0, ((MAP_FT4*)mpoly)->mp_rgb0);
					MR_COPY32(((POLY_FT4*)prims1)->r0, ((MAP_FT4*)mpoly)->mp_rgb0);
					}
#ifdef WIN95
				setPolyFT4((POLY_FT4*)prims0);
				setPolyFT4((POLY_FT4*)prims1);
#else
				setlen(prims0, 9);
				setlen(prims1, 9);
#endif
				if (((MAP_FT4*)mpoly)->mp_flags & MAP_POLY_SEMITRANS)
					{		
					setSemiTrans((POLY_FT4*)prims0, 1);
					setSemiTrans((POLY_FT4*)prims1, 1);
					}
#ifdef PSX
				MR_COPY32(((POLY_FT4*)prims0)->u0, ((MAP_FT4*)mpoly)->mp_u0);
				MR_COPY32(((POLY_FT4*)prims0)->u1, ((MAP_FT4*)mpoly)->mp_u1);
				MR_COPY32(((POLY_FT4*)prims1)->u0, ((MAP_FT4*)mpoly)->mp_u0);
				MR_COPY32(((POLY_FT4*)prims1)->u1, ((MAP_FT4*)mpoly)->mp_u1);
#else
				MR_COPY16(((POLY_FT4*)prims0)->u0, ((MAP_FT4*)mpoly)->mp_u0);
				MR_COPY16(((POLY_FT4*)prims0)->u1, ((MAP_FT4*)mpoly)->mp_u1);
				((POLY_FT4*)prims0)->tpage = ((MAP_FT4*)mpoly)->mp_tpage_id;
				MR_COPY16(((POLY_FT4*)prims1)->u0, ((MAP_FT4*)mpoly)->mp_u0);
				MR_COPY16(((POLY_FT4*)prims1)->u1, ((MAP_FT4*)mpoly)->mp_u1);
				((POLY_FT4*)prims1)->tpage = ((MAP_FT4*)mpoly)->mp_tpage_id;
#endif
				MR_COPY16(((POLY_FT4*)prims0)->u2, ((MAP_FT4*)mpoly)->mp_u2);
				MR_COPY16(((POLY_FT4*)prims0)->u3, ((MAP_FT4*)mpoly)->mp_u3);
				MR_COPY16(((POLY_FT4*)prims1)->u2, ((MAP_FT4*)mpoly)->mp_u2);
				MR_COPY16(((POLY_FT4*)prims1)->u3, ((MAP_FT4*)mpoly)->mp_u3);

				((POLY_FT4*)prims0)++;
				((POLY_FT4*)prims1)++;
				((MAP_FT4*)mpoly)++;
				}
			}
		//-----------
		// Build g3s
		//-----------
		if (poly_group->pg_polys_g3.pn_numpolys = map_group->mg_num_g3)
			{
			mpoly = (MR_UBYTE*)map_group->mg_g3_list;

			// Link polys
			if (poly_group->pg_polys_g3.pn_next		= poly_root_nodes[POLY_ID_G3].pn_next)
				poly_root_nodes[POLY_ID_G3].pn_next->pn_prev = &poly_group->pg_polys_g3;
			poly_root_nodes[POLY_ID_G3].pn_next		= &poly_group->pg_polys_g3;
			poly_group->pg_polys_g3.pn_prev			= &poly_root_nodes[POLY_ID_G3];
			poly_group->pg_polys_g3.pn_prims[0]		= prims0;
			poly_group->pg_polys_g3.pn_prims[1]		= prims1;
			poly_group->pg_polys_g3.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_g3.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_G3*)prims0)->r0, ((MAP_G3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_G3*)prims1)->r0, ((MAP_G3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_G3*)prims0)->r1, ((MAP_G3*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_G3*)prims1)->r1, ((MAP_G3*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_G3*)prims0)->r2, ((MAP_G3*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_G3*)prims1)->r2, ((MAP_G3*)mpoly)->mp_rgb2);
#ifdef WIN95
				setPolyG3((POLY_G3*)prims0);
				setPolyG3((POLY_G3*)prims1);
#else
				setlen(prims0, 6);
				setlen(prims1, 6);
#endif
				((POLY_G3*)prims0)++;
				((POLY_G3*)prims1)++;
				((MAP_G3*)mpoly)++;
				}
			}
		//-----------
		// Build g4s
		//-----------
		if (poly_group->pg_polys_g4.pn_numpolys = map_group->mg_num_g4)
			{
			mpoly = (MR_UBYTE*)map_group->mg_g4_list;

			// Link polys
			if (poly_group->pg_polys_g4.pn_next		= poly_root_nodes[POLY_ID_G4].pn_next)
				poly_root_nodes[POLY_ID_G4].pn_next->pn_prev = &poly_group->pg_polys_g4;
			poly_root_nodes[POLY_ID_G4].pn_next		= &poly_group->pg_polys_g4;
			poly_group->pg_polys_g4.pn_prev			= &poly_root_nodes[POLY_ID_G4];
			poly_group->pg_polys_g4.pn_prims[0]		= prims0;
			poly_group->pg_polys_g4.pn_prims[1]		= prims1;
			poly_group->pg_polys_g4.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_g4.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_G4*)prims0)->r0, ((MAP_G4*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_G4*)prims1)->r0, ((MAP_G4*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_G4*)prims0)->r1, ((MAP_G4*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_G4*)prims1)->r1, ((MAP_G4*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_G4*)prims0)->r2, ((MAP_G4*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_G4*)prims1)->r2, ((MAP_G4*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_G4*)prims0)->r3, ((MAP_G4*)mpoly)->mp_rgb3);
				MR_COPY32(((POLY_G4*)prims1)->r3, ((MAP_G4*)mpoly)->mp_rgb3);
#ifdef WIN95
				setPolyG4((POLY_G4*)prims0);
				setPolyG4((POLY_G4*)prims1);
#else
				setlen(prims0, 8);
				setlen(prims1, 8);
#endif
				((POLY_G4*)prims0)++;
				((POLY_G4*)prims1)++;
				((MAP_G4*)mpoly)++;
				}
			}
		//-----------
		// Build gt3s
		//-----------
		if (poly_group->pg_polys_gt3.pn_numpolys = map_group->mg_num_gt3)
			{
			mpoly = (MR_UBYTE*)map_group->mg_gt3_list;

			// Link polys
			if (poly_group->pg_polys_gt3.pn_next	= poly_root_nodes[POLY_ID_GT3].pn_next)
				poly_root_nodes[POLY_ID_GT3].pn_next->pn_prev = &poly_group->pg_polys_gt3;
			poly_root_nodes[POLY_ID_GT3].pn_next	= &poly_group->pg_polys_gt3;
			poly_group->pg_polys_gt3.pn_prev		= &poly_root_nodes[POLY_ID_GT3];
			poly_group->pg_polys_gt3.pn_prims[0]	= prims0;
			poly_group->pg_polys_gt3.pn_prims[1]	= prims1;
			poly_group->pg_polys_gt3.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_gt3.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_GT3*)prims0)->r0, ((MAP_GT3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_GT3*)prims1)->r0, ((MAP_GT3*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_GT3*)prims0)->r1, ((MAP_GT3*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_GT3*)prims1)->r1, ((MAP_GT3*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_GT3*)prims0)->r2, ((MAP_GT3*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_GT3*)prims1)->r2, ((MAP_GT3*)mpoly)->mp_rgb2);
#ifdef WIN95
				setPolyGT3((POLY_GT3*)prims0);
				setPolyGT3((POLY_GT3*)prims1);
#else
				setlen(prims0, 9);
				setlen(prims1, 9);
#endif
				if (((MAP_GT3*)mpoly)->mp_flags & MAP_POLY_SEMITRANS)
					{		
					setSemiTrans((POLY_GT3*)prims0, 1);
					setSemiTrans((POLY_GT3*)prims1, 1);		
					}
#ifdef PSX
				MR_COPY32(((POLY_GT3*)prims0)->u0, ((MAP_GT3*)mpoly)->mp_u0);
				MR_COPY32(((POLY_GT3*)prims0)->u1, ((MAP_GT3*)mpoly)->mp_u1);
				MR_COPY32(((POLY_GT3*)prims1)->u0, ((MAP_GT3*)mpoly)->mp_u0);
				MR_COPY32(((POLY_GT3*)prims1)->u1, ((MAP_GT3*)mpoly)->mp_u1);
#else
				MR_COPY16(((POLY_GT3*)prims0)->u0, ((MAP_GT3*)mpoly)->mp_u0);
				MR_COPY16(((POLY_GT3*)prims0)->u1, ((MAP_GT3*)mpoly)->mp_u1);
				((POLY_GT3*)prims0)->tpage = ((MAP_GT3*)mpoly)->mp_tpage_id;
				MR_COPY16(((POLY_GT3*)prims1)->u0, ((MAP_GT3*)mpoly)->mp_u0);
				MR_COPY16(((POLY_GT3*)prims1)->u1, ((MAP_GT3*)mpoly)->mp_u1);
				((POLY_GT3*)prims1)->tpage = ((MAP_GT3*)mpoly)->mp_tpage_id;
#endif
				MR_COPY16(((POLY_GT3*)prims0)->u2, ((MAP_GT3*)mpoly)->mp_u2);
				MR_COPY16(((POLY_GT3*)prims1)->u2, ((MAP_GT3*)mpoly)->mp_u2);

				((POLY_GT3*)prims0)++;
				((POLY_GT3*)prims1)++;
				((MAP_GT3*)mpoly)++;
				}
			}
		//-----------
		// Build gt4s
		//-----------
		if (poly_group->pg_polys_gt4.pn_numpolys = map_group->mg_num_gt4)
			{
			mpoly = (MR_UBYTE*)map_group->mg_gt4_list;

			// Link polys
			if (poly_group->pg_polys_gt4.pn_next	= poly_root_nodes[POLY_ID_GT4].pn_next)
				poly_root_nodes[POLY_ID_GT4].pn_next->pn_prev = &poly_group->pg_polys_gt4;
			poly_root_nodes[POLY_ID_GT4].pn_next	= &poly_group->pg_polys_gt4;
			poly_group->pg_polys_gt4.pn_prev		= &poly_root_nodes[POLY_ID_GT4];
			poly_group->pg_polys_gt4.pn_prims[0]	= prims0;
			poly_group->pg_polys_gt4.pn_prims[1]	= prims1;
			poly_group->pg_polys_gt4.pn_map_polys	= mpoly;

			// Set up polys
			npolys = poly_group->pg_polys_gt4.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((POLY_GT4*)prims0)->r0, ((MAP_GT4*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_GT4*)prims1)->r0, ((MAP_GT4*)mpoly)->mp_rgb0);
				MR_COPY32(((POLY_GT4*)prims0)->r1, ((MAP_GT4*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_GT4*)prims1)->r1, ((MAP_GT4*)mpoly)->mp_rgb1);
				MR_COPY32(((POLY_GT4*)prims0)->r2, ((MAP_GT4*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_GT4*)prims1)->r2, ((MAP_GT4*)mpoly)->mp_rgb2);
				MR_COPY32(((POLY_GT4*)prims0)->r3, ((MAP_GT4*)mpoly)->mp_rgb3);
				MR_COPY32(((POLY_GT4*)prims1)->r3, ((MAP_GT4*)mpoly)->mp_rgb3);
#ifdef WIN95
				setPolyGT4((POLY_GT4*)prims0);
				setPolyGT4((POLY_GT4*)prims1);
#else
				setlen(prims0, 12);
				setlen(prims1, 12);
#endif
				if (((MAP_GT4*)mpoly)->mp_flags & MAP_POLY_SEMITRANS)
					{		
					setSemiTrans((POLY_GT4*)prims0, 1);
					setSemiTrans((POLY_GT4*)prims1, 1);	
					}
#ifdef PSX
				MR_COPY32(((POLY_GT4*)prims0)->u0, ((MAP_GT4*)mpoly)->mp_u0);
				MR_COPY32(((POLY_GT4*)prims0)->u1, ((MAP_GT4*)mpoly)->mp_u1);
				MR_COPY32(((POLY_GT4*)prims1)->u0, ((MAP_GT4*)mpoly)->mp_u0);
				MR_COPY32(((POLY_GT4*)prims1)->u1, ((MAP_GT4*)mpoly)->mp_u1);
#else
				MR_COPY16(((POLY_GT4*)prims0)->u0, ((MAP_GT4*)mpoly)->mp_u0);
				MR_COPY16(((POLY_GT4*)prims0)->u1, ((MAP_GT4*)mpoly)->mp_u1);
				((POLY_GT4*)prims0)->tpage = ((MAP_GT4*)mpoly)->mp_tpage_id;
				MR_COPY16(((POLY_GT4*)prims1)->u0, ((MAP_GT4*)mpoly)->mp_u0);
				MR_COPY16(((POLY_GT4*)prims1)->u1, ((MAP_GT4*)mpoly)->mp_u1);
				((POLY_GT4*)prims1)->tpage = ((MAP_GT4*)mpoly)->mp_tpage_id;
#endif
				MR_COPY16(((POLY_GT4*)prims0)->u2, ((MAP_GT4*)mpoly)->mp_u2);
				MR_COPY16(((POLY_GT4*)prims0)->u3, ((MAP_GT4*)mpoly)->mp_u3);
				MR_COPY16(((POLY_GT4*)prims1)->u2, ((MAP_GT4*)mpoly)->mp_u2);
				MR_COPY16(((POLY_GT4*)prims1)->u3, ((MAP_GT4*)mpoly)->mp_u3);

				((POLY_GT4*)prims0)++;
				((POLY_GT4*)prims1)++;
				((MAP_GT4*)mpoly)++;
				}
			}

#ifdef MAP_WIREFRAME_EXTENSION
		if (poly_group->pg_polys_g2.pn_numpolys = map_group->mg_num_g2)
			{
			// There are some wireframe lines to create
			mpoly = (MR_UBYTE*)map_group->mg_g2_list;

			// Link polys
			if (poly_group->pg_polys_g2.pn_next		= poly_root_nodes[POLY_ID_G2].pn_next)
				poly_root_nodes[POLY_ID_G2].pn_next->pn_prev = &poly_group->pg_polys_g2;
			poly_root_nodes[POLY_ID_G2].pn_next		= &poly_group->pg_polys_g2;
			poly_group->pg_polys_g2.pn_prev			= &poly_root_nodes[POLY_ID_G2];
			poly_group->pg_polys_g2.pn_prims[0]		= prims0;
			poly_group->pg_polys_g2.pn_prims[1]		= prims1;
			poly_group->pg_polys_g2.pn_map_polys	= mpoly;

			npolys = poly_group->pg_polys_g2.pn_numpolys;
			while(npolys--)
				{
				MR_COPY32(((LINE_G2*)prims0)->r0, ((MAP_G2*)mpoly)->mp_rgb0);
				MR_COPY32(((LINE_G2*)prims1)->r0, ((MAP_G2*)mpoly)->mp_rgb0);
				MR_COPY32(((LINE_G2*)prims0)->r1, ((MAP_G2*)mpoly)->mp_rgb1);
				MR_COPY32(((LINE_G2*)prims1)->r1, ((MAP_G2*)mpoly)->mp_rgb1);
#ifdef WIN95
				setLineG2((LINE_G2*)prims0);
				setLineG2((LINE_G2*)prims1);
#else
				setlen(prims0, 4);
				setlen(prims1, 4);
#endif
				((LINE_G2*)prims0)++;
				((LINE_G2*)prims1)++;
				((MAP_G2*)mpoly)++;
				}
			}
#endif

		// Check we built exactly the right area of memory
		MR_ASSERT(prims0 == poly_group->pg_prims[0] + prim_bufflen);
		}

	return(poly_count - total_polys);
}


/******************************************************************************
*%%%% CreateMapGroups
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreateMapGroups(
*						MR_ULONG	vp_id)
*
*	FUNCTION	Create MAP_GROUPs from list of map group indices
*
*	INPUTS		vp_id		-	viewport id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	CreateMapGroups(MR_ULONG	vp_id)
{
	MR_SHORT*		index;
	MR_LONG			poly_count;
	MR_VIEWPORT*	vp;


	vp			= Game_viewports[vp_id];
	index  		= Map_group_view_list[vp_id];
	poly_count	= MAP_MAX_POLYS_RENDERED;

	while((*index >= 0) && (poly_count > 0))
		{
		poly_count = ExpandMapGroup(*index, vp_id, poly_count);
		index++;
		}
}


/******************************************************************************
*%%%% RenderMap
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderMap(
*						MR_ULONG	vp_id)
*
*	FUNCTION	Render polys in map
*
*	INPUTS		vp_id		-	viewport id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Added new offset to MAP_RENDER_PARAMS, which is
*								offset to X0 in struct, which differs from PSX 
*								to WIN95 :/
*%%%**************************************************************************/

MR_VOID	RenderMap(MR_ULONG	vp_id)
{
	POLY_GROUP*			poly_group;
	POLY_NODE*			pn_node;
	MR_ULONG			ngroups;
	MAP_RENDER_PARAMS	prp_block;
	MAP_RENDER_PARAMS*	params;
	MR_VIEWPORT*		vp;
	POLY_NODE*			poly_root_nodes;


	vp				= Game_viewports[vp_id];
	poly_root_nodes	= Poly_root_nodes[vp_id];
 	poly_group		= Poly_groups[vp_id];
	ngroups   		= MAP_MAX_POLY_GROUPS;
	params 	  		= &prp_block;

#ifdef DEBUG
	Map_debug_land_polys	= 0;
#endif

	// Set up camera, accounting for aspect... map is a huge model sitting in world... must apply aspect to rotation matrix
	// AND camera offset vector
	MRTemp_svec.vx = -vp->vp_render_matrix.t[0];
	MRTemp_svec.vy = -vp->vp_render_matrix.t[1];
	MRTemp_svec.vz = -vp->vp_render_matrix.t[2];

	// Set up GTE matrix and offset
	gte_SetRotMatrix(&vp->vp_render_matrix);
	MRApplyRotMatrix(&MRTemp_svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);

	while(ngroups--)
		{
		switch (poly_group->pg_timer)
			{
			case 3:
				// Poly group was added last frame
				poly_group->pg_timer--;
				break;

			case 2:
				// Remove POLY_NODEs from linked list
				if ((pn_node = &poly_group->pg_polys_f3)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_f4)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_ft3)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_ft4)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_g3)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_g4)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_gt3)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
				if ((pn_node = &poly_group->pg_polys_gt4)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
#ifdef	MAP_WIREFRAME_EXTENSION
				if ((pn_node = &poly_group->pg_polys_g2)->pn_numpolys)
					{
					pn_node->pn_prev->pn_next = pn_node->pn_next;
					if (pn_node->pn_next)
						pn_node->pn_next->pn_prev = pn_node->pn_prev;
					}
#endif
				poly_group->pg_timer--;
				break;

			case 1:
				poly_group->pg_map_group->mg_poly_group[vp_id] 	= NULL;
				poly_group->pg_map_group 						= NULL;
				MRFreeMem(poly_group->pg_prims[0]);

				poly_group->pg_timer--;
#ifdef DEBUG
				Map_debug_poly_groups--;
#endif
				break;
			}
		poly_group++;
		}

	// DEAN:	Changed to pass frog_svec into render code, because otherwise the ASM
	//			versions of the code would have to duplicate the (huge) FROG structure
	params->mr_frog_svec.vx		= Frogs[0].fr_lwtrans->t[0];
	params->mr_frog_svec.vy		= Frogs[0].fr_lwtrans->t[1];
	params->mr_frog_svec.vz		= Frogs[0].fr_lwtrans->t[2];

	// Render F3s
	params->mr_poly_size 		= sizeof(MAP_F3);	
	params->mr_prim_size 		= sizeof(POLY_F3);
	params->mr_prim_coord_ofs	= 4;
	params->mr_prim_flags		= 0;

#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 12;
	params->mr_prim_z0_ofs		= 24;		// Z!!!
	params->mr_prim_z_coord_ofs	= 2;		// Z!!!
#endif

	if (poly_root_nodes[POLY_ID_F3].pn_next)
#ifdef MAP_USE_ASM
		MapRenderTrisASM(&poly_root_nodes[POLY_ID_F3], params);
#else
		MapRenderTris(&poly_root_nodes[POLY_ID_F3], params);
#endif

	// Render FT3s
	params->mr_poly_size 		= sizeof(MAP_FT3);	
	params->mr_prim_size 		= sizeof(POLY_FT3);
	params->mr_prim_coord_ofs	= 8;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_TEXTURED;
#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 16;
	params->mr_prim_z0_ofs		= 22;		// Z!!!
	params->mr_prim_z_coord_ofs	= 8;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderTrisASM(&poly_root_nodes[POLY_ID_FT3], params);
#else
	MapRenderTris(&poly_root_nodes[POLY_ID_FT3], params);
#endif

	// Render G3s
	params->mr_poly_size 		= sizeof(MAP_G3);	
	params->mr_prim_size 		= sizeof(POLY_G3);
	params->mr_prim_coord_ofs	= 8;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_GOURAUD;

	if ( Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT )
		// Yes ... set cave light
		params->mr_prim_flags	|= MAP_RENDER_FLAGS_LIT;

#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 12;
	params->mr_prim_z0_ofs		= 32;		// Z!!!
	params->mr_prim_z_coord_ofs	= 2;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderTrisASM(&poly_root_nodes[POLY_ID_G3], params);
#else
	MapRenderTris(&poly_root_nodes[POLY_ID_G3], params);
#endif

	// Render GT3s
	params->mr_poly_size 		= sizeof(MAP_GT3);	
	params->mr_prim_size 		= sizeof(POLY_GT3);
	params->mr_prim_coord_ofs	= 12;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_GOURAUD | MAP_RENDER_FLAGS_TEXTURED;

// $wb - Does map book say we want to use cave light ?
	if ( Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT )
		// Yes ... set cave light
		params->mr_prim_flags	|= MAP_RENDER_FLAGS_LIT;

#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 16;
	params->mr_prim_z0_ofs		= 22;		// Z!!!
	params->mr_prim_z_coord_ofs	= 12;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderTrisASM(&poly_root_nodes[POLY_ID_GT3], params);
#else
	MapRenderTris(&poly_root_nodes[POLY_ID_GT3], params);
#endif

	// Render F4s
	params->mr_poly_size 		= sizeof(MAP_F4);	
	params->mr_prim_size 		= sizeof(POLY_F4);
	params->mr_prim_coord_ofs	= 4;
	params->mr_prim_flags		= 0;
#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 12;
	params->mr_prim_z0_ofs		= 28;		// Z!!!
	params->mr_prim_z_coord_ofs	= 2;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderQuadsASM(&poly_root_nodes[POLY_ID_F4], params);
#else
	MapRenderQuads(&poly_root_nodes[POLY_ID_F4], params);
#endif

	// Render FT4s
	params->mr_poly_size 		= sizeof(MAP_FT4);	
	params->mr_prim_size 		= sizeof(POLY_FT4);
	params->mr_prim_coord_ofs	= 8;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_TEXTURED;
#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 16;
	params->mr_prim_z0_ofs		= 22;		// Z!!!
	params->mr_prim_z_coord_ofs	= 8;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderQuadsASM(&poly_root_nodes[POLY_ID_FT4], params);
#else
	MapRenderQuads(&poly_root_nodes[POLY_ID_FT4], params);
#endif
	
	// Render G4s
	params->mr_poly_size 		= sizeof(MAP_G4);	
	params->mr_prim_size 		= sizeof(POLY_G4);
	params->mr_prim_coord_ofs	= 8;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_GOURAUD;

// $wb - Does map book say we want to use cave light ?
	if ( Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT )
		// Yes ... set cave light
		params->mr_prim_flags	|= MAP_RENDER_FLAGS_LIT;

#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 12;
	params->mr_prim_z0_ofs		= 40;		// Z!!!
	params->mr_prim_z_coord_ofs	= 2;		// Z!!!
#endif
#ifdef MAP_USE_ASM
	MapRenderQuadsASM(&poly_root_nodes[POLY_ID_G4], params);
#else
	MapRenderQuads(&poly_root_nodes[POLY_ID_G4], params);
#endif

	// Render GT4s
	params->mr_poly_size 		= sizeof(MAP_GT4);	
	params->mr_prim_size 		= sizeof(POLY_GT4);
	params->mr_prim_coord_ofs	= 12;
	params->mr_prim_flags		= MAP_RENDER_FLAGS_GOURAUD | MAP_RENDER_FLAGS_TEXTURED;

// $wb - Does map book say we want to use cave light ?
	if ( Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT )
		// Yes ... set cave light
		params->mr_prim_flags	|= MAP_RENDER_FLAGS_LIT;

#ifdef PSX	//-psx specific code-------------------------------------------------------
	params->mr_prim_x0_ofs		= 8;
#else		//-win95 specific code-----------------------------------------------------
	params->mr_prim_x0_ofs		= 16;
	params->mr_prim_z0_ofs		= 22;		// Z!!!
	params->mr_prim_z_coord_ofs	= 12;		// Z!!!
#endif

#ifdef MAP_USE_ASM
	MapRenderQuadsASM(&poly_root_nodes[POLY_ID_GT4], params);
#else
	MapRenderQuads(&poly_root_nodes[POLY_ID_GT4], params);
#endif

#ifdef MAP_WIREFRAME_EXTENSION
	// Render G2s (wireframe extension)
	MapRenderG2s(&poly_root_nodes[POLY_ID_G2]);

	MapDebugDisplayMapGroup(&Map_groups[0]);
	MapDebugDisplayMapGroup(&Map_groups[4]);
#endif

	if (Game_map_theme == THEME_SKY)
		RenderSkyLand(vp_id);
}


/******************************************************************************
*%%%% FreeAllPolyGroups
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FreeAllPolyGroups
*
*	FUNCTION	Frees all the poly groups (and resets map group/poly group
*				pointers)
*
*	NOTES		Make sure none of the allocated polys are in the OT!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	FreeAllPolyGroups(MR_VOID)
{
	POLY_GROUP*	poly_group;
	POLY_NODE*	poly_node;
	MR_ULONG	i;


	poly_group	= Poly_groups[0];
	i 			= MAP_MAX_POLY_GROUPS * Game_total_viewports;
	while(i--)
		{
		if (poly_group->pg_map_group)
			{
			poly_group->pg_map_group->mg_poly_group[0]	= NULL;
			poly_group->pg_map_group->mg_poly_group[1]	= NULL;
			poly_group->pg_map_group->mg_poly_group[2]	= NULL;
			poly_group->pg_map_group->mg_poly_group[3]	= NULL;
			poly_group->pg_map_group 			   		= NULL;
			poly_group->pg_timer 				   		= 0;
			MRFreeMem(poly_group->pg_prims[0]);
			}
		poly_group++;
		}

	// Set up POLY_NODEs
 	poly_node 	= Poly_root_nodes[0];
 	i 			= 8 * Game_total_viewports;
	while(i--)
		{
		poly_node->pn_next = NULL;
		poly_node++;
		}

	// cleanup alloced map polys
	MRFreeMem(Poly_groups[0]);

	// cleanup alloced map polys nodes
	MRFreeMem(Poly_root_nodes[0]);

#ifdef DEBUG
	Map_debug_poly_groups = 0;
#endif
}


/******************************************************************************
*%%%% MapRenderQuads
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapRenderQuads(
*						POLY_NODE*			poly_node,
*						MAP_RENDER_PARAMS*	params)
*
*	FUNCTION	Run through all nodes, rotate polys and add to viewport OT.
*
*	INPUTS		poly_node	-	root node of quad list to process
*				params		-	ptr to quad info block
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Changed code to remove offset of '8' to x0 in 
*								poly structure, and use supplied offset instead.
*
*%%%**************************************************************************/

MR_VOID	MapRenderQuads(	POLY_NODE*			poly_node,
						MAP_RENDER_PARAMS*	params)
{
#ifndef	MAP_USE_ASM
	MR_UBYTE*	prim;		// ptr to display primitives
	MR_UBYTE*	poly;		// ptr to map polys
	MR_SVEC*	pvert[4];	// ptrs to quad vertices
	MR_ULONG	npolys;
	MR_SVEC		diff_svec;
	MR_LONG		dist[4];
	MR_ULONG	rgb[4];
	MR_LONG		u, v;
	MR_LONG		light_factor;
	MR_LONG		otz;
	MR_LONG		nclip;
	MR_ULONG	prim_offset_x0;
	MR_ULONG	prim_offset_x1;
	MR_ULONG	prim_offset_x2;
	MR_ULONG	prim_offset_x3;
#ifdef WIN95
	MR_ULONG	prim_offset_z0;
	MR_ULONG	prim_offset_z1;
	MR_ULONG	prim_offset_z2;
	MR_ULONG	prim_offset_z3;
	MR_LONG		poly_z[4];
#endif
	MR_VEC		vec;

	prim_offset_x0	= params->mr_prim_x0_ofs;
	prim_offset_x1	= prim_offset_x0 + params->mr_prim_coord_ofs;
	prim_offset_x2	= prim_offset_x1 + params->mr_prim_coord_ofs;
	prim_offset_x3	= prim_offset_x2 + params->mr_prim_coord_ofs;
	vec.vy 			= 0;

#ifdef WIN95
	prim_offset_z0	= params->mr_prim_z0_ofs;
	prim_offset_z1	= prim_offset_z0 + params->mr_prim_z_coord_ofs;
	prim_offset_z2	= prim_offset_z1 + params->mr_prim_z_coord_ofs;
	prim_offset_z3	= prim_offset_z2 + params->mr_prim_z_coord_ofs;
#endif

	if (params->mr_prim_flags & MAP_RENDER_FLAGS_LIT)
		{
		// Calculate amount light drops off across distance between min and max radius
		light_factor = (128 << 16) / (Map_light_max_r2 - Map_light_min_r2);
		}
	else
		light_factor = NULL;

	// Do all nodes
	while(poly_node = poly_node->pn_next)
		{
		prim	= poly_node->pn_prims[MRFrame_index];
		poly	= poly_node->pn_map_polys;
		npolys	= poly_node->pn_numpolys;

		// Get pointer to vertices (all types have mp_vertices[4] in same place)
		for (v = 0; v < 4; v++)
			pvert[v] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[v];

		// Do all quads in node
		while(npolys--)
			{
			// Calculate lighting if necessary
			if (params->mr_prim_flags & MAP_RENDER_FLAGS_LIT)
				{
				// For each vertex, rgb is proportional to squared distance from frog
				for (v = 0; v < 4; v++)
					{
					MR_SUB_SVEC_ABC(pvert[v], &params->mr_frog_svec, &diff_svec);
					dist[v] = MR_SVEC_MOD_SQR(&diff_svec);

					if (dist[v] < Map_light_min_r2)
						rgb[v] = 0x808080;
					else
					if (dist[v] > Map_light_max_r2)
						rgb[v] = 0x000000;
					else
					rgb[v] = (0x80 - ((light_factor * (dist[v] - Map_light_min_r2)) >> 16)) * 0x010101;
					}

				// Copy to rgb0 (don't overwrite poly code)
				*(prim + prim_offset_x0 - 4) =  ((MR_UBYTE*)&rgb[0])[0];
				*(prim + prim_offset_x0 - 3) =  ((MR_UBYTE*)&rgb[0])[1];
				*(prim + prim_offset_x0 - 2) =  ((MR_UBYTE*)&rgb[0])[2];

				// Copy to rgb1,2,3
				MR_COPY32(*(prim + prim_offset_x1 - 4), rgb[1]);
				MR_COPY32(*(prim + prim_offset_x2 - 4), rgb[2]);
				MR_COPY32(*(prim + prim_offset_x3 - 4), rgb[3]);
				}

			otz	= 0;
			if (params->mr_prim_flags & MAP_RENDER_FLAGS_TEXTURED)
				{
				if (((MAP_FT4*)poly)->mp_flags & MAP_POLY_ENVMAP)
					{
					// Textured poly with ENVMAP - calculate UVs
					// MRTemp_svec is -(world coord of camera)
					// Texture is assumed to be 254x254 with DupAll, so centre of texture is assumed to be (128, 128)
					u = 128;
					v = 128;
					vec.vx = (pvert[0]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[0]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x0)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x0)[5] = (vec.vz >> 5) + v;
					vec.vx = (pvert[1]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[1]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x1)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x1)[5] = (vec.vz >> 5) + v;
					vec.vx = (pvert[2]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[2]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x2)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x2)[5] = (vec.vz >> 5) + v;
					vec.vx = (pvert[3]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[3]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x3)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x3)[5] = (vec.vz >> 5) + v;
					otz = MRVp_ot_size - MAP_POLY_ENVMAP_OFFSET;
					}
				else
				if (((MAP_FT4*)poly)->mp_flags & MAP_POLY_MAX_OT)
					otz = MRVp_ot_size - MAP_POLY_MAX_OT_OFFSET;

				if (((MAP_FT4*)poly)->mp_flags & (MAP_POLY_ANIM_TEXTURE | MAP_POLY_ANIM_UV))
					{
#ifdef WIN95
					MR_COPY16(*(prim + prim_offset_x0 + 4), ((MAP_FT4*)poly)->mp_u0);
					MR_COPY16(*(prim + prim_offset_x1 + 4), ((MAP_FT4*)poly)->mp_u1);
					MR_COPY16(*(prim + 8), ((MAP_FT4*)poly)->mp_tpage_id);				// tpage is always here for PC prims
#else
					MR_COPY32(*(prim + prim_offset_x0 + 4), ((MAP_FT4*)poly)->mp_u0);
					MR_COPY32(*(prim + prim_offset_x1 + 4), ((MAP_FT4*)poly)->mp_u1);
#endif
					MR_COPY16(*(prim + prim_offset_x2 + 4), ((MAP_FT4*)poly)->mp_u2);
					MR_COPY16(*(prim + prim_offset_x3 + 4), ((MAP_FT4*)poly)->mp_u3);
					}
				}

			// Standard quad rotation/nclip code
			gte_ldv3(pvert[0], pvert[1], pvert[2]);
			gte_rtpt();

			poly += params->mr_poly_size;
			pvert[0] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[0];
			pvert[1] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[1];
			pvert[2] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[2];

			gte_nclip();
			gte_stsxy0((MR_LONG*)(prim + prim_offset_x0));
			gte_ldv0(pvert[3]);
			gte_stopz(&nclip);

			gte_rtps();
			pvert[3] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[3];
			if (nclip > 0)
				goto visible_poly;

			gte_nclip();
			gte_stopz(&nclip);
			if (nclip >= 0)
				goto next_poly;

		visible_poly:;
			gte_stsxy3(	(MR_LONG*)(prim + prim_offset_x1),
						(MR_LONG*)(prim + prim_offset_x2),
						(MR_LONG*)(prim + prim_offset_x3));
#ifdef WIN95
			gte_stsz4(&poly_z[0], &poly_z[1], &poly_z[2], &poly_z[3]);
			*(MR_USHORT*)(prim + prim_offset_z0) = (MR_USHORT)poly_z[0];
			*(MR_USHORT*)(prim + prim_offset_z1) = (MR_USHORT)poly_z[1];
			*(MR_USHORT*)(prim + prim_offset_z2) = (MR_USHORT)poly_z[2];
			*(MR_USHORT*)(prim + prim_offset_z3) = (MR_USHORT)poly_z[3];
#endif

			if (!otz)
				{
				gte_avsz4();
				gte_stotz(&otz);

				if (otz <= MAP_POLY_CLIP_OTZ)
					goto next_poly;

				otz >>= MRVp_otz_shift;
 				otz += MAP_POLY_OT_OFFSET;

				if (otz >= MRVp_ot_size)
					goto next_poly;
				}

			// Add primitive
			addPrim(MRVp_work_ot + otz, prim);
#ifdef DEBUG
			Map_debug_land_polys++;
#endif
		next_poly:;
			// Next poly
			prim += params->mr_prim_size;
			}
		// Next node
		}
#endif // MAP_USE_ASM
}


/******************************************************************************
*%%%% MapRenderTris
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapRenderTris(
*						POLY_NODE*			poly_node,
*						MAP_RENDER_PARAMS*	params)
*
*	FUNCTION	Run through all nodes, rotate polys and add to viewport OT.
*
*	INPUTS		poly_node	-	root node of tri list to process
*				params		-	ptr to tri info block
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Changed code to remove offset of '8' to x0 in 
*								poly structure, and use supplied offset instead.
*%%%**************************************************************************/

MR_VOID	MapRenderTris(	POLY_NODE*			poly_node,
						MAP_RENDER_PARAMS*	params)
{
#ifndef	MAP_USE_ASM
	MR_UBYTE*	prim;		// ptr to display primitives
	MR_UBYTE*	poly;		// ptr to map polys
	MR_SVEC*	pvert[3];	// ptrs to tri vertices
	MR_ULONG	npolys;
	MR_SVEC		diff_svec;
	MR_LONG		dist[3];
	MR_ULONG	rgb[3];
	MR_LONG		u, v;
	MR_LONG		light_factor;
	MR_LONG		otz, nclip;
	MR_ULONG	prim_offset_x0;
	MR_ULONG	prim_offset_x1;
	MR_ULONG	prim_offset_x2;
#ifdef WIN95
	MR_ULONG	prim_offset_z0;
	MR_ULONG	prim_offset_z1;
	MR_ULONG	prim_offset_z2;
	MR_ULONG	prim_offset_z3;
	MR_LONG		poly_z[4];
#endif
	MR_VEC		vec;


	prim_offset_x0	= params->mr_prim_x0_ofs;
	prim_offset_x1	= prim_offset_x0 + params->mr_prim_coord_ofs;
	prim_offset_x2	= prim_offset_x1 + params->mr_prim_coord_ofs;

#ifdef WIN95
	prim_offset_z0	= params->mr_prim_z0_ofs;
	prim_offset_z1	= prim_offset_z0 + params->mr_prim_z_coord_ofs;
	prim_offset_z2	= prim_offset_z1 + params->mr_prim_z_coord_ofs;
	prim_offset_z3	= prim_offset_z2 + params->mr_prim_z_coord_ofs;
#endif

	if (params->mr_prim_flags & MAP_RENDER_FLAGS_LIT)
		{
		// Calculate amount light drops off across distance between min and max radius
		light_factor = (128 << 16) / (Map_light_max_r2 - Map_light_min_r2);
		}
	else
		light_factor = NULL;

	// Do all nodes
	while(poly_node = poly_node->pn_next)
		{
		prim	= poly_node->pn_prims[MRFrame_index];
		poly	= poly_node->pn_map_polys;
		npolys	= poly_node->pn_numpolys;

		// Get pointer to vertices (all types have mp_vertices[4] in same place)
		for (v = 0; v < 3; v++)
			pvert[v] = Map_vertices + ((MAP_F3*)poly)->mp_vertices[v];

		// Do all quads in node
		while(npolys--)
			{
			// Calculate lighting if necessary
			if (params->mr_prim_flags & MAP_RENDER_FLAGS_LIT)
				{
				// For each vertex, rgb is proportional to squared distance from frog
				for (v = 0; v < 3; v++)
					{
					MR_SUB_SVEC_ABC(pvert[v], &params->mr_frog_svec, &diff_svec);
					dist[v] = MR_SVEC_MOD_SQR(&diff_svec);

					if (dist[v] < Map_light_min_r2)
						rgb[v] = 0x808080;
					else
					if (dist[v] > Map_light_max_r2)
						rgb[v] = 0x000000;
					else
					rgb[v] = (0x80 - ((light_factor * (dist[v] - Map_light_min_r2)) >> 16)) * 0x010101;
					}

				// Copy to rgb0 (don't overwrite poly code)
				*(prim + prim_offset_x0 - 4) =  ((MR_UBYTE*)&rgb[0])[0];
				*(prim + prim_offset_x0 - 3) =  ((MR_UBYTE*)&rgb[0])[1];
				*(prim + prim_offset_x0 - 2) =  ((MR_UBYTE*)&rgb[0])[2];

				// Copy to rgb1,2
				MR_COPY32(*(prim + prim_offset_x1 - 4), rgb[1]);
				MR_COPY32(*(prim + prim_offset_x2 - 4), rgb[2]);
				}

			otz	= 0;
			if (params->mr_prim_flags & MAP_RENDER_FLAGS_TEXTURED)
				{
				if (((MAP_FT3*)poly)->mp_flags & MAP_POLY_ENVMAP)
					{
					// Textured poly with ENVMAP - calculate UVs
					// MRTemp_svec is -(world coord of camera)
					// Texture is assumed to be 254x254 with DupAll, so centre of texture is assumed to be (128, 128)
					u = 128;
					v = 128;
					vec.vx = (pvert[0]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[0]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x0)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x0)[5] = (vec.vz >> 5) + v;
					vec.vx = (pvert[1]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[1]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x1)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x1)[5] = (vec.vz >> 5) + v;
					vec.vx = (pvert[2]->vx + MRTemp_svec.vx);
					vec.vz = (pvert[2]->vz + MRTemp_svec.vz);
					(prim + prim_offset_x2)[4] = (vec.vx >> 5) + u;
					(prim + prim_offset_x2)[5] = (vec.vz >> 5) + v;
					otz = MRVp_ot_size - MAP_POLY_ENVMAP_OFFSET;
					}
				else
				if (((MAP_FT3*)poly)->mp_flags & MAP_POLY_MAX_OT)
					otz = MRVp_ot_size - MAP_POLY_MAX_OT_OFFSET;

				if (((MAP_FT3*)poly)->mp_flags & (MAP_POLY_ANIM_TEXTURE | MAP_POLY_ANIM_UV))
					{
#ifdef WIN95
					MR_COPY16(*(prim + prim_offset_x0 + 4), ((MAP_FT3*)poly)->mp_u0);
					MR_COPY16(*(prim + prim_offset_x1 + 4), ((MAP_FT3*)poly)->mp_u1);
					MR_COPY16(*(prim + 8), ((MAP_FT3*)poly)->mp_tpage_id);				// tpage is always here for PC prims
#else
					MR_COPY32(*(prim + prim_offset_x0 + 4), ((MAP_FT3*)poly)->mp_u0);
					MR_COPY32(*(prim + prim_offset_x1 + 4), ((MAP_FT3*)poly)->mp_u1);
#endif
					MR_COPY16(*(prim + prim_offset_x2 + 4), ((MAP_FT3*)poly)->mp_u2);
					}
				}

			// Standard tri rotation/nclip code
			gte_ldv3(pvert[0], pvert[1], pvert[2]);
			gte_rtpt();

			poly += params->mr_poly_size;
			for (v = 0; v < 3; v++)
				pvert[v] = Map_vertices + ((MAP_F4*)poly)->mp_vertices[v];

			gte_nclip();
			gte_stopz(&nclip);
			if (nclip <= 0)
				goto next_poly;

			gte_stsxy3(	(MR_LONG*)(prim + prim_offset_x0),
						(MR_LONG*)(prim + prim_offset_x1),
						(MR_LONG*)(prim + prim_offset_x2));

#ifdef WIN95
			gte_stsz3(&poly_z[0], &poly_z[1], &poly_z[2]);
			*(MR_USHORT*)(prim + prim_offset_z0) = (MR_USHORT)poly_z[0];
			*(MR_USHORT*)(prim + prim_offset_z1) = (MR_USHORT)poly_z[1];
			*(MR_USHORT*)(prim + prim_offset_z2) = (MR_USHORT)poly_z[2];
#endif

			if (!otz)
				{
				gte_avsz3();
				gte_stotz(&otz);

				if (otz <= MAP_POLY_CLIP_OTZ)
					goto next_poly;

				otz >>= MRVp_otz_shift;
 				otz += MAP_POLY_OT_OFFSET;

				if (otz >= MRVp_ot_size)
					goto next_poly;
				}

			// Add primitive
			addPrim(MRVp_work_ot + otz, prim);
#ifdef DEBUG
			Map_debug_land_polys++;
#endif
		next_poly:;
			// Next poly
			prim += params->mr_prim_size;
			}
		// Next node
		}
#endif // MAP_USE_ASM
}


/******************************************************************************
*%%%% CreateMapLights
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreateMapLights(MR_VOID)
*
*	FUNCTION	Create lights from the map
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	CreateMapLights(MR_VOID)
{
	LIGHT*		light;
	MR_ULONG	i, flags;
	MR_VEC		vec;
	MR_BOOL		new_light;
	

	i 		= Map_light_header->lh_numlights;
	light	= Map_lights;
	while(i--)
		{
		new_light 	= FALSE;
		flags 		= NULL;
		switch(light->li_type)
			{
			//-----------------------------------------------------------------
			case LIGHT_TYPE_DUMMY:
				break;
			//-----------------------------------------------------------------
			case LIGHT_TYPE_STATIC:
				if (light->li_api_type == MR_LIGHT_TYPE_PARALLEL)
					{					
					light->li_frame = MRCreateFrame(&Null_vector, &Null_svector, NULL);
					MR_VEC_EQUALS_SVEC(&vec, &light->li_direction);
					MRNormaliseVEC(&vec, &vec);
					light->li_frame->fr_matrix.m[0][2] = vec.vx;
					light->li_frame->fr_matrix.m[1][2] = vec.vy;
					light->li_frame->fr_matrix.m[2][2] = vec.vz;
					MRGenerateYXMatrixFromZColumn(&light->li_frame->fr_matrix);
					MR_COPY_MAT( &light->li_frame->fr_lw_transform.m[0][0] ,&light->li_frame->fr_matrix.m[0][0] );
					new_light = TRUE;
					}
				else
				if (light->li_api_type == MR_LIGHT_TYPE_AMBIENT)
					{
					light->li_frame = NULL;
					flags 			= MR_OBJ_STATIC;
					new_light 		= TRUE;
					}
				break;
			//-----------------------------------------------------------------
			case LIGHT_TYPE_ENTITY:
				break;
			//-----------------------------------------------------------------
			}

		if (new_light == TRUE)
			{
			light->li_object = MRCreateLight(light->li_api_type, light->li_colour, light->li_frame, flags);
			GameAddObjectToViewports(light->li_object);
			}

		light++;
		}
}

/******************************************************************************
*%%%% KillMapLightsFrames
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillMapLightsFrames(MR_VOID)
*
*	FUNCTION	Kills the frames of lights created from the map
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID KillMapLightsFrames(MR_VOID)
{

	LIGHT*		light;
	MR_ULONG	i;

	i 		= Map_light_header->lh_numlights;
	light	= Map_lights;

	while(i--)
		{
		if (light->li_frame)
			{
			MRKillFrame(light->li_frame);
			}
		light++;
		}

}


/******************************************************************************
*%%%% RenderSkyLand
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderSkyLand(
*						MR_ULONG	vp_id)
*
*	FUNCTION	Render polys in sky land map
*
*	INPUTS		vp_id		-	viewport id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	RenderSkyLand(MR_ULONG	vp_id)
{
	MR_SVEC			svec;
	MR_ULONG		x, z;
	MR_SVEC*		vertex_0;
	MR_SVEC*		vertex_1;
	MR_SVEC*		vertex_2;
	MR_SVEC*		vertex_3;
	POLY_FT4*		poly_ft4;
	MR_VIEWPORT*	vp;


	vp		= Game_viewports[vp_id];

	// Position is Sky_drift_position
	svec.vx = (Sky_drift_position.vx >> 16);
	svec.vy = (Sky_drift_position.vy >> 16);
	svec.vz = (Sky_drift_position.vz >> 16);

	// Rotation is camera rotation
	gte_SetRotMatrix(&vp->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);

	vertex_0 	= Sky_land_vertices + (Sky_land_header->sl_xnum + 1);
	vertex_1 	= Sky_land_vertices + (Sky_land_header->sl_xnum + 1) + 1;
	vertex_2 	= Sky_land_vertices;
	vertex_3 	= Sky_land_vertices + 1;
	poly_ft4	= Sky_land_polys[vp_id][MRFrame_index];

	addPrims(vp->vp_work_ot + vp->vp_ot_size - 1, poly_ft4, poly_ft4 + (Sky_land_header->sl_znum * Sky_land_header->sl_xnum) - 1);

	// Run through each quad
	for (z = 0; z < Sky_land_header->sl_znum; z++)
		{
		for (x = 0; x < Sky_land_header->sl_xnum; x++)
			{
			gte_ldv3(vertex_0, vertex_1, vertex_2);
			gte_rtpt();
			vertex_0++;
			vertex_1++;
			vertex_2++;
			gte_stsxy3(	(MR_LONG*)&poly_ft4->x0,
						(MR_LONG*)&poly_ft4->x1,
						(MR_LONG*)&poly_ft4->x2);
			gte_ldv0(vertex_3);
			gte_rtps();
			vertex_3++;
			gte_stsxy((MR_LONG*)&poly_ft4->x3);

			poly_ft4++;
			}
		vertex_0++;
		vertex_1++;
		vertex_2++;
		vertex_3++;
		}
}


/******************************************************************************
*%%%% UpdateSkyLand
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateSkyLand(MR_VOID)
*
*	FUNCTION	Update sky drift
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdateSkyLand(MR_VOID)
{
	if (Game_map_theme == THEME_SKY)
		{
		if (!(Game_timer & 0x7f))
			{
			// New drift acceleration
			if 	(
				((Sky_drift_position.vx >> 16) >  SKY_MAX_DRIFT) ||
				((Sky_drift_position.vx >> 16) < -SKY_MAX_DRIFT) ||
				((Sky_drift_position.vz >> 16) >  SKY_MAX_DRIFT) ||
				((Sky_drift_position.vz >> 16) < -SKY_MAX_DRIFT)
				)
				{
				Sky_drift_acceleration.vx = -Sky_drift_position.vx >> 16;
				Sky_drift_acceleration.vy = -Sky_drift_position.vy >> 16;
				Sky_drift_acceleration.vz = -Sky_drift_position.vz >> 16;
				}
			else
				{
				Sky_drift_acceleration.vx = rand() & 0x3ff;
				Sky_drift_acceleration.vy = 0;
				Sky_drift_acceleration.vz = rand() & 0x3ff;
				}
			MRNormaliseVEC(&Sky_drift_acceleration, &Sky_drift_acceleration);
			Sky_drift_acceleration.vx <<= 3;
			Sky_drift_acceleration.vy <<= 3;
			Sky_drift_acceleration.vz <<= 3;
			}
		else
		if ((Game_timer & 0xff) < 0x60)
			{
			// Accelerate
			MR_ADD_VEC(&Sky_drift_velocity, &Sky_drift_acceleration);
			}
		else
			{
			// Decelerate
			Sky_drift_velocity.vx = (Sky_drift_velocity.vx >> 5) * 31;
			Sky_drift_velocity.vy = (Sky_drift_velocity.vy >> 5) * 31;
			Sky_drift_velocity.vz = (Sky_drift_velocity.vz >> 5) * 31;
			}
	
		MR_ADD_VEC(&Sky_drift_position, &Sky_drift_velocity);
		}

	// Bound drift position
	Sky_drift_position.vx = MIN(SKY_MAX_DRIFT_POSITION, MAX(-SKY_MAX_DRIFT_POSITION, Sky_drift_position.vx));
	Sky_drift_position.vz = MIN(SKY_MAX_DRIFT_POSITION, MAX(-SKY_MAX_DRIFT_POSITION, Sky_drift_position.vz));
}


/******************************************************************************
*%%%% MapCreateWireframeLines
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCreateWireframeLines(MR_VOID)
*
*	FUNCTION	Set up MAP_G2 structures, and point MAP_GROUPs to them
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapCreateWireframeLines(MR_VOID)
{
#ifdef MAP_WIREFRAME_EXTENSION
	MR_LONG	i;


	// Calculate colours
	for (i = 0; i <= MAP_WIREFRAME_CORNER_NUM_LINES; i++)
		{
		Map_wireframe_line_colours[i].r = ((0xa0 * (MAP_WIREFRAME_CORNER_NUM_LINES - i)) + (Game_back_colour[Game_map].r * i)) / MAP_WIREFRAME_CORNER_NUM_LINES;
		Map_wireframe_line_colours[i].g = ((0xa0 * (MAP_WIREFRAME_CORNER_NUM_LINES - i)) + (Game_back_colour[Game_map].g * i)) / MAP_WIREFRAME_CORNER_NUM_LINES;
		Map_wireframe_line_colours[i].b = ((0xa0 * (MAP_WIREFRAME_CORNER_NUM_LINES - i)) + (Game_back_colour[Game_map].b * i)) / MAP_WIREFRAME_CORNER_NUM_LINES;
		}

	// Create MAP_G2 and link them to MAP_GROUPs
	MapCreateWireframeLinesMapgroupCorner(Map_vertex_min.vx, Map_vertex_max.vz, 0, 0, -MAP_WIREFRAME_LINE_LENGTH,  MAP_WIREFRAME_LINE_LENGTH);
	MapCreateWireframeLinesMapgroupCorner(Map_vertex_max.vx, Map_vertex_max.vz, 0, 0,  MAP_WIREFRAME_LINE_LENGTH,  MAP_WIREFRAME_LINE_LENGTH);
	MapCreateWireframeLinesMapgroupCorner(Map_vertex_max.vx, Map_vertex_min.vz, 0, 0,  MAP_WIREFRAME_LINE_LENGTH, -MAP_WIREFRAME_LINE_LENGTH);
	MapCreateWireframeLinesMapgroupCorner(Map_vertex_min.vx, Map_vertex_min.vz, 0, 0, -MAP_WIREFRAME_LINE_LENGTH, -MAP_WIREFRAME_LINE_LENGTH);

	MapCreateWireframeLinesMapgroupEdge(Map_vertex_min.vx, Map_vertex_min.vz, 0, 0,  1,  0);
//	MapCreateWireframeLinesMapgroupEdge(Map_vertex_min.vx, Map_vertex_min.vz, 0, 0,  0,  1);
//	MapCreateWireframeLinesMapgroupEdge(Map_vertex_max.vx, Map_vertex_max.vz, 0, 0, -1,  0);
//	MapCreateWireframeLinesMapgroupEdge(Map_vertex_max.vx, Map_vertex_max.vz, 0, 0,  0, -1);
#endif
}


/******************************************************************************
*%%%% MapCreateWireframeLinesMapgroupCorner
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCreateWireframeLinesMapgroupCorner(
*						MR_LONG	x,
*						MR_LONG	z,
*						MR_LONG	gdx,
*						MR_LONG	gdz,
*						MR_LONG	wdx,
*						MR_LONG	wdz)
*
*	FUNCTION	Set up MAP_G2 structures, and point MAP_GROUPs to them for
*				all MAP_GROUPs at a corner of the map
*
*	INPUTS		x 	- start world x coord
*				z 	- start world z coord
*				gdx	- map group dx
*				gdz	- map group dz
*				wdx	- direction of line
*				wdz	- direction of line
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapCreateWireframeLinesMapgroupCorner(	MR_LONG	x,
												MR_LONG	z,
												MR_LONG	gdx,
												MR_LONG	gdz,
												MR_LONG	wdx,
												MR_LONG	wdz)
{
#ifdef MAP_WIREFRAME_EXTENSION
	MR_LONG			wx, wz, mx, mz;
	MR_LONG			i, tpolys;
	MR_SVEC			svec0;
	MR_SVEC			svec1;
	MAP_GROUP*		map_group;
	MAP_G2*			map_g2;


	// Get map group coords of point
	mx			= (x - Map_view_basepoint.vx) / Map_view_xlen;
	mz			= (z - Map_view_basepoint.vz) / Map_view_zlen;
	mx			+= gdx;
	mz			+= gdz;
	map_group	= Map_groups + (mz * Map_view_xnum) + mx;
	wx			= (mx * Map_view_xlen) + Map_view_basepoint.vx;
	wz			= (mz * Map_view_zlen) + Map_view_basepoint.vz;

	while (!map_group->mg_g2_list)
		{
		// Allocate space for MAP_G2s
		tpolys 					= MAP_WIREFRAME_CORNER_NUM_LINES << 1;
		map_group->mg_num_g2 	= tpolys;
		map_group->mg_g2_list 	= MRAllocMem(sizeof(MAP_G2) * tpolys, "MAP_G2");
		map_g2					= map_group->mg_g2_list;

		// Write horizontal lines
		svec0.vx 	= wx;
		svec0.vy 	= Map_vertex_max.vy;
		svec0.vz 	= wz;
		svec1.vx 	= svec0.vx + wdx;
		svec1.vy 	= svec0.vy;
		svec1.vz 	= svec0.vz;
		for (i = 0; i < MAP_WIREFRAME_CORNER_NUM_LINES; i++)
			{
			MR_COPY_SVEC(&map_g2->mp_vertices[0], &svec0);
			MR_COPY_SVEC(&map_g2->mp_vertices[1], &svec1);
			if (wdz > 0)
				{
				svec0.vz += Grid_zlen;
				svec1.vz += Grid_zlen;
				}
			else
				{
				svec0.vz -= Grid_zlen;
				svec1.vz -= Grid_zlen;
				}

			MR_COPY32(map_g2->mp_rgb0, Map_wireframe_line_colours[i]);
			MR_COPY32(map_g2->mp_rgb1, Map_wireframe_line_colours[MAP_WIREFRAME_CORNER_NUM_LINES]);
			map_g2++;
			}

		// Write vertical lines
		svec0.vx 	= wx;
		svec0.vy 	= Map_vertex_max.vy;
		svec0.vz 	= wz;
		svec1.vx 	= svec0.vx;
		svec1.vy 	= svec0.vy;
		svec1.vz 	= svec0.vz + wdz;
		for (i = 0; i < MAP_WIREFRAME_CORNER_NUM_LINES; i++)
			{
			MR_COPY_SVEC(&map_g2->mp_vertices[0], &svec0);
			MR_COPY_SVEC(&map_g2->mp_vertices[1], &svec1);
			if (wdx > 0)
				{
				svec0.vx += Grid_xlen;
				svec1.vx += Grid_xlen;
				}
			else
				{
				svec0.vx -= Grid_xlen;
				svec1.vx -= Grid_xlen;
				}

			MR_COPY32(map_g2->mp_rgb0, Map_wireframe_line_colours[i]);
			MR_COPY32(map_g2->mp_rgb1, Map_wireframe_line_colours[MAP_WIREFRAME_CORNER_NUM_LINES]);
			map_g2++;
			}
		}
#endif
}


/******************************************************************************
*%%%% MapCreateWireframeLinesMapgroupEdge
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapCreateWireframeLinesMapgroupEdge(
*						MR_LONG	x,
*						MR_LONG	z,
*						MR_LONG	gdx,
*						MR_LONG	gdz,
*						MR_LONG	wdx,
*						MR_LONG	wdz)
*
*	FUNCTION	Set up MAP_G2 structures, and point MAP_GROUPs to them for
*				all MAP_GROUPs along an edge of the map
*
*	INPUTS		x 	- start world x coord
*				z 	- start world z coord
*				gdx	- in grid squares
*				gdz	- in grid squares
*				wdx	- direction of line
*				wdz	- direction of line
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapCreateWireframeLinesMapgroupEdge(	MR_LONG	x,
												MR_LONG	z,
												MR_LONG	gdx,
												MR_LONG	gdz,
												MR_LONG	wdx,
												MR_LONG	wdz)
{
#ifdef MAP_WIREFRAME_EXTENSION
	MR_LONG			gx, gz, wx, wz, mx, mz;
	MR_LONG			i, tpolys;
	MR_LONG			dx, dz, lx, lz, mdx, mdz;
	MR_SVEC			svec0;
	MR_SVEC			svec1;
	MAP_GROUP*		map_group;
	MAP_G2*			map_g2;


	// Calculate line draw gaps and lengths
	if (wdx > 0)
		{
		dx 	=  Grid_xlen;
		dz 	= -Grid_zlen;
		lx 	=  MAP_WIREFRAME_LINE_LENGTH;
		lz 	= -MAP_WIREFRAME_LINE_LENGTH;
		mdx = 0;
		mdz = Map_view_zlen;
		}
	else
	if (wdx < 0)
		{
		dx 	=  Grid_xlen;
		dz 	=  Grid_zlen;
		lx 	=  MAP_WIREFRAME_LINE_LENGTH;
		lz 	=  0;
		mdx = 0;
		mdz = 0;
		}
	else
	if (wdz > 0)
		{
		dx 	= -Grid_xlen;
		dz 	=  Grid_zlen;
		lx 	= -MAP_WIREFRAME_LINE_LENGTH;
		lz 	=  MAP_WIREFRAME_LINE_LENGTH;
		mdx = Map_view_xlen;
		mdz = 0;
		}
	else
		{
		dx 	=  Grid_xlen;
		dz 	= -Grid_zlen;
		lx 	=  MAP_WIREFRAME_LINE_LENGTH;
		lz 	= -MAP_WIREFRAME_LINE_LENGTH;
		mdx = 0;
		mdz = Map_view_zlen;
		}

	// Get grid coords of point
	gx			= GET_GRID_X_FROM_WORLD_X(x) + gdx;
	gz			= GET_GRID_Z_FROM_WORLD_Z(z) + gdz;

	wx 			= (gx << 8) + Grid_base_x;
	wz 			= (gz << 8) + Grid_base_z;
	mx			= (wx - Map_view_basepoint.vx) / Map_view_xlen;
	mz			= (wz - Map_view_basepoint.vz) / Map_view_zlen;

	// Move to adjacent map group
	mx 			+= wdx;
	mz 			+= wdz;
	map_group	= Map_groups + (mz * Map_view_xnum) + mx;
	wx			= (mx * Map_view_xlen) + Map_view_basepoint.vx;
	wz			= (mz * Map_view_zlen) + Map_view_basepoint.vz;

	while (!map_group->mg_g2_list)
		{
		// Allocate space for MAP_G2s
		tpolys 					= MAP_WIREFRAME_CORNER_NUM_LINES << 1;
		map_group->mg_num_g2 	= tpolys;
		map_group->mg_g2_list 	= MRAllocMem(sizeof(MAP_G2) * tpolys, "MAP_G2");
		map_g2					= map_group->mg_g2_list;

		// Write horizontal lines
		svec0.vx 	= wx + mdx;
		svec0.vy 	= Map_vertex_max.vy;
		svec0.vz 	= wz + mdz;
		svec1.vx 	= svec0.vx + lx;
		svec1.vy 	= svec0.vy;
		svec1.vz 	= svec0.vz;
		for (i = 0; i < MAP_WIREFRAME_CORNER_NUM_LINES; i++)
			{
			MR_COPY_SVEC(&map_g2->mp_vertices[0], &svec0);
			MR_COPY_SVEC(&map_g2->mp_vertices[1], &svec1);
			svec0.vz += dz;
			svec1.vz += dz;

			MR_SET32(map_g2->mp_rgb0, 0x808080);
			MR_SET32(map_g2->mp_rgb1, 0x808080);
			map_g2++;
			}

		// Write vertical lines
		svec0.vx 	= wx + mdx;
		svec0.vy 	= Map_vertex_max.vy;
		svec0.vz 	= wz + mdz;
		svec1.vx 	= svec0.vx;
		svec1.vy 	= svec0.vy;
		svec1.vz 	= svec0.vz + lz;
		for (i = 0; i < MAP_WIREFRAME_CORNER_NUM_LINES; i++)
			{
			MR_COPY_SVEC(&map_g2->mp_vertices[0], &svec0);
			MR_COPY_SVEC(&map_g2->mp_vertices[1], &svec1);
			svec0.vx += dx;
			svec1.vx += dx;

			MR_SET32(map_g2->mp_rgb0, 0x808080);
			MR_SET32(map_g2->mp_rgb1, 0x808080);
			map_g2++;
			}

		// Move to adjacent map group
		mx 			+= wdx;
		mz 			+= wdz;
		map_group	= Map_groups + (mz * Map_view_xnum) + mx;
		}
#endif
}


/******************************************************************************
*%%%% MapRenderG2s
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapRenderG2s(
*						POLY_NODE*	poly_node)
*
*	FUNCTION	Run through all nodes, rotate lines and add to viewport OT.
*
*	INPUTS		poly_node	-	root node of tri list to process
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapRenderG2s(POLY_NODE*	poly_node)
{
	MAP_G2*		map_g2;
	LINE_G2*	line_g2;
	MR_SVEC*	pvert[2];
	MR_ULONG	npolys;
	MR_LONG		dummy;


	// Do all nodes
	while(poly_node = poly_node->pn_next)
		{
		line_g2	= (LINE_G2*)poly_node->pn_prims[MRFrame_index];
		map_g2	= (MAP_G2*)poly_node->pn_map_polys;
		npolys	= poly_node->pn_numpolys;

		// Get pointer to vertices (all types have mp_vertices[4] in same place)
		pvert[0] = Map_vertices + map_g2->mp_vertices[0];
		pvert[1] = Map_vertices + map_g2->mp_vertices[1];

		// Look at next poly
		map_g2++;

		// Do all quads in node
		while(npolys--)
			{
			// Calculate lighting if necessary
			gte_ldv3(pvert[0], pvert[1], &Null_svector);
			gte_rtpt();

			pvert[0] = Map_vertices + map_g2->mp_vertices[0];
			pvert[1] = Map_vertices + map_g2->mp_vertices[1];

			gte_stsxy3(	(MR_LONG*)&line_g2->x0,
						(MR_LONG*)&line_g2->x1,
						&dummy);

			addPrim(MRVp_work_ot + MRVp_ot_size - 1, line_g2);

			// Next poly
			map_g2++;
			line_g2++;
			}
		// Next node
		}
}


/******************************************************************************
*%%%% MapUpdateAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapUpdateAnimatedPolys(MR_VOID)
*
*	FUNCTION	Update all MAP_ANIM and associated map poly structures
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Tim Closs		Created
*	19.08.97	Tim Closs		Made much, much, much, much, MUCH faster
*
*%%%**************************************************************************/

MR_VOID	MapUpdateAnimatedPolys(MR_VOID)
{
#ifdef MAP_TEXTURE_ANIMATION
	MR_LONG			i, c;
	MR_UBYTE		bu, bv;
	MAP_ANIM*		map_anim;
	MAP_UV_INFO*	map_uv_info;
#ifdef PSX
	MR_USHORT		us;
	MR_ULONG		ul;
#endif

	map_anim	= Map_anims;
	i 			= Map_anim_header->ah_nummapanims;
	while(i--)
		{
		if (map_anim->ma_flags & MAP_ANIM_UV)
			{
			if (++map_anim->ma_uv_count == map_anim->ma_uv_duration)
				{
//				map_anim->ma_uv_count 	= 0;
//				map_anim->ma_ofs_u		= 0;
//				map_anim->ma_ofs_v		= 0;
				MR_SET32(map_anim->ma_ofs_u, 0);
				}
			else
				{
//				map_anim->ma_ofs_u		+= map_anim->ma_du;
//				map_anim->ma_ofs_v		+= map_anim->ma_dv;
				*(MR_USHORT*)&map_anim->ma_ofs_u += *(MR_USHORT*)&map_anim->ma_du;
				}
			}

		if (map_anim->ma_flags & MAP_ANIM_TEXTURE)
			{
			if (++map_anim->ma_cel_count >= map_anim->ma_cel_period)
				{
				// Go to next cel in list
				map_anim->ma_cel_count = 0;

				if (++map_anim->ma_current_cel == map_anim->ma_numcels)
					map_anim->ma_current_cel = 0;

				map_anim->ma_texture = bmp_pointers[map_anim->ma_cel_list[map_anim->ma_current_cel]];
				}
			}

		map_uv_info = map_anim->ma_map_uv_info;
		c			= map_anim->ma_numpolys;
		if (c)
			{
			MR_ASSERT(map_anim->ma_texture);
			bu = map_anim->ma_texture->te_u0 + map_anim->ma_ofs_u;
			bv = map_anim->ma_texture->te_v0 + map_anim->ma_ofs_v;
			while(c--)
				{
				// Write new UVs back to map poly
#ifdef PSX
				us = bu + (bv << 8);
				*(MR_USHORT*)&((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u0 = *(MR_USHORT*)&map_uv_info->mu_u0 + us;
				*(MR_USHORT*)&((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u1 = *(MR_USHORT*)&map_uv_info->mu_u1 + us;
	
				ul = us + (us << 16);
				*(MR_ULONG*)&((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u2 = *(MR_ULONG*)&map_uv_info->mu_u2 + ul;
#else
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u0 = map_uv_info->mu_u0 + bu;
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v0 = map_uv_info->mu_v0 + bv;
	
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u1 = map_uv_info->mu_u1 + bu;
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v1 = map_uv_info->mu_v1 + bv;
	
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u2 = map_uv_info->mu_u2 + bu;
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v2 = map_uv_info->mu_v2 + bv;
	
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_u3 = map_uv_info->mu_u3 + bu;
				((MAP_FT4*)map_uv_info->mu_map_poly)->mp_v3 = map_uv_info->mu_v3 + bv;
#endif
				if (map_anim->ma_flags & MAP_ANIM_TEXTURE)
					{
					// Copy new tpage and clut
#ifdef PSX
					((MAP_FT4*)map_uv_info->mu_map_poly)->mp_clut_id 	= map_anim->ma_texture->te_clut_id;
#endif
					((MAP_FT4*)map_uv_info->mu_map_poly)->mp_tpage_id 	= map_anim->ma_texture->te_tpage_id;
					}
				map_uv_info++;
				}
			}
		map_anim++;
		}
#endif
}

