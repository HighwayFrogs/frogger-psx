/******************************************************************************
*%%%% mapview.c
*------------------------------------------------------------------------------
*
*	Calculate the viewing region.  Store a (-1) terminated list of map group
*	indices
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "mapview.h"
#include "mapdisp.h"
#include "gamesys.h"
#include "main.h"
#include "camera.h"

#ifdef WIN95
#pragma warning (disable : 4761)
#endif

MR_SVEC		Map_view_basepoint;
MR_LONG		Map_view_xlen;
MR_LONG		Map_view_zlen;
MR_LONG		Map_view_xnum;
MR_LONG		Map_view_znum;

// Used in view region calc
MR_SVEC		Map_view_plane_svecs[SYSTEM_MAX_VIEWPORTS][4];	// in camera coords
MR_VEC		Map_view_plane_vecs[4];							// in world coords
MR_VEC		Map_view_plane_intersect[5];					// intersections in world of view volume with XZ plane (Y = 0)

MR_LONG		Map_view_region_minx[MAP_MAX_GRID_ROWS];
MR_LONG		Map_view_region_maxx[MAP_MAX_GRID_ROWS];


/******************************************************************************
*%%%% InitialiseMapView
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseMapView(MR_VOID)
*
*	FUNCTION	Initialise map display stuff
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.04.97	Tim Closs		Created
*	30.05.97	Tim Closs		Fixed sizes for all viewport numbers
*	03.07.97	Tim Closs		Fixed sizes for all viewports.. again
*
*%%%**************************************************************************/

MR_VOID	InitialiseMapView(MR_VOID)
{
	MR_ULONG	i, w, h;
	MR_RECT*	rect;


	for (i = 0; i < Game_total_viewports; i++)
		{
		rect = &Game_viewports[i]->vp_disp_inf;

		// Note that these values are irrespective of the screen resolution: if we go to hi-res, we don't suddenly
		// want to pull in more of the world!
		if (Game_total_viewports == 2)
			{
			w = 80;
			h = 120;
			}
		else
			{
			w = 160;
			h = 120;
			}
			
		// Set view plane corners in camera coords
		MR_SET_SVEC(&Map_view_plane_svecs[i][1], -w, -h, Game_perspective);
		MR_SET_SVEC(&Map_view_plane_svecs[i][2],  w, -h, Game_perspective);
		MR_SET_SVEC(&Map_view_plane_svecs[i][3],  w,  h, Game_perspective);
		MR_SET_SVEC(&Map_view_plane_svecs[i][0], -w,  h, Game_perspective);
		}

	for (i = 0; i < 5; i++)
		Map_view_plane_intersect[i].vy = 0;
}


/******************************************************************************
*%%%% CreateMapViewList
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreateMapViewList(
*						MR_ULONG	vp_id)
*
*	FUNCTION	Create terminated list of map group indices
*	MATCH		https://decomp.me/scratch/hXlus	(By Kneesnap)
*
*	INPUTS		vp_id		-	viewport id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*	30.10.23	Kneesnap		Byte-matched this function as seen in PSX Build 71 (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	CreateMapViewList(MR_ULONG	vp_id)
{
	MR_MAT*			cam_matrix;
	MR_LONG			l, i;
	MR_VEC			vec, vec2;
	MR_LONG			count, x, z;
	MR_LONG			minx, maxx, minz, maxz;
	MR_SHORT*		index;
	MR_VEC			intergrid[5];
	MR_VIEWPORT*	vp;


	vp			= Game_viewports[vp_id];
	index 		= Map_group_view_list[vp_id];
	cam_matrix 	= Cameras[vp_id].ca_matrix;

	// Calculate viewplane corners in world
	gte_SetRotMatrix(cam_matrix);
	for (i = 0; i < 4; i++)
		{
		MRApplyRotMatrix(&Map_view_plane_svecs[vp_id][i], &Map_view_plane_vecs[i]);
		MR_ADD_VEC(&Map_view_plane_vecs[i], (MR_VEC*)cam_matrix->t);
		}

	// Find intersection points of volume lines with XZ plane (Y = 0)
	for (i = 0; i < 4; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_vecs[i], (MR_VEC*)cam_matrix->t, &vec);

		if (vec.vy <= 0)
			{
			// Line is parallel to or pointing away from XZ plane: force intersection to lie on circle in XZ plane, centred
			// on camera, or large radius (r = 0x4000)
			vec.vy = 0;
			MRNormaliseVEC(&vec, &vec);
			Map_view_plane_intersect[i].vx = cam_matrix->t[0] + (vec.vx << 2);
			Map_view_plane_intersect[i].vz = cam_matrix->t[2] + (vec.vz << 2);
			}
		else
			{
			l = (-cam_matrix->t[1] << 8) / vec.vy;

			// Note that the intersection points can be outside of MR_SVEC range
			Map_view_plane_intersect[i].vx = cam_matrix->t[0] + ((l * vec.vx) >> 8);
			Map_view_plane_intersect[i].vz = cam_matrix->t[2] + ((l * vec.vz) >> 8);
			}
		}

	// intersect[4] is projected camera origin
	Map_view_plane_intersect[4].vx = cam_matrix->t[0];
	Map_view_plane_intersect[4].vz = cam_matrix->t[2];

#ifdef	MAP_VIEW_DRAW_PROJECTION
	// Display projected quad
	for (i = 0; i < 5; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_intersect[(i + 1) % 5], &Map_view_plane_intersect[i], &vec);
		MRDebugPlotWorldLineVEC(&Map_view_plane_intersect[i], &vec, 0x000080);
		}
#endif

	// Border code:
	//
	// Because polys may be linked to map groups which they are not wholly within, and because entitys are linked to map
	// groups according to projected origin (so can spread into another group), we expand the projected area as follows:
	// Calculate average of projected points 0..3  Push points 0..3 out from this average by a fixed distance
	vec.vx = (Map_view_plane_intersect[0].vx + Map_view_plane_intersect[1].vx + Map_view_plane_intersect[2].vx + Map_view_plane_intersect[3].vx) >> 2;
	vec.vz = (Map_view_plane_intersect[0].vz + Map_view_plane_intersect[1].vz + Map_view_plane_intersect[2].vz + Map_view_plane_intersect[3].vz) >> 2;
	for (i = 0; i < 4; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_intersect[i], &vec, &vec2);
		MRNormaliseVEC(&vec2, &vec2);
		Map_view_plane_intersect[i].vx += (vec2.vx * MAP_VIEW_QUAD_BORDER_WIDTH) >> 12;
		Map_view_plane_intersect[i].vz += (vec2.vz * MAP_VIEW_QUAD_BORDER_WIDTH) >> 12;
		}	

	// Clear row buffers
	for (i = 0; i < Map_view_znum; i++)
		{
		Map_view_region_minx[i]	= 0x7fffffff;
		Map_view_region_maxx[i] = -0x7fffffff;
		}

	// Convert intersect[i].vx/vz to grid coords
	for (i = 0; i < 5; i++)
		{
		intergrid[i].vx = (Map_view_plane_intersect[i].vx - Map_view_basepoint.vx);
		intergrid[i].vz = (Map_view_plane_intersect[i].vz - Map_view_basepoint.vz);
		}

	MapViewDrawLine(intergrid[0].vx, intergrid[0].vz, intergrid[1].vx, intergrid[1].vz);
	MapViewDrawLine(intergrid[1].vx, intergrid[1].vz, intergrid[2].vx, intergrid[2].vz);
	MapViewDrawLine(intergrid[2].vx, intergrid[2].vz, intergrid[3].vx, intergrid[3].vz);
	MapViewDrawLine(intergrid[3].vx, intergrid[3].vz, intergrid[4].vx, intergrid[4].vz);
	MapViewDrawLine(intergrid[4].vx, intergrid[4].vz, intergrid[0].vx, intergrid[0].vz);
	MapViewDrawLine(intergrid[3].vx, intergrid[3].vz, intergrid[0].vx, intergrid[0].vz);

	for (i = 0; i < 5; i++)
		{
		intergrid[i].vx /= Map_view_xlen;
		intergrid[i].vz /= Map_view_zlen;
		}
	
	// Now run from z = minz to z = maxz, filling grid squares between ..view_region_minx[z] and ..view_region_maxx[z]
	count 	= 0;
	vec.vy	= 0;
	minz 	= MIN(MIN(MIN(MIN(intergrid[0].vz, intergrid[1].vz), intergrid[2].vz), intergrid[3].vz), intergrid[4].vz);
	maxz 	= MAX(MAX(MAX(MAX(intergrid[0].vz, intergrid[1].vz), intergrid[2].vz), intergrid[3].vz), intergrid[4].vz);
	minz	= MAX(0, minz);
	maxz	= MIN((MR_LONG)(Map_view_znum - 1), maxz);

	for (z = minz; z <= maxz; z++)
		{
		minx = MAX(0, Map_view_region_minx[z]);
		maxx = MIN((MR_LONG)(Map_view_xnum - 1), Map_view_region_maxx[z]);
		
		for (x = minx; x <= maxx; x++)
			{
			// Write MAP_GROUP index
			*index = (z * Map_view_xnum) + x;
			MR_ASSERT((*index) >= 0);
			MR_ASSERT((*index) < (Map_view_xnum * Map_view_znum));

			index++;

			if (++count >= MAP_MAX_POLY_GROUPS)
				goto end_list;
			}
		}

	end_list:;

	// Write terminator
	*index = -1;

	MapViewDrawPicture();
}


/******************************************************************************
*%%%% RenderMapViewDebugDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderMapViewDebugDisplay(MR_VOID)
*
*	FUNCTION	Display map view region in debug viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef DEBUG
#ifdef SYSTEM_DISPLAY_DEBUG_VIEWPORT
MR_VOID	RenderMapViewDebugDisplay(MR_VOID)
{
	MR_LONG		i, x, z;
	MR_VEC		vec, vec2;
	MR_MAT*		cam_matrix;
	POLY_F4*	poly_f4;
	MR_SHORT*	index;
	MR_SVEC		corners[4];
	

	cam_matrix = Cameras[0].ca_matrix;

	// Display viewplane
	for (i = 0; i < 4; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_vecs[(i + 1) & 3], &Map_view_plane_vecs[i], &vec);
		MRDebugPlotWorldLineVEC(&Map_view_plane_vecs[i], &vec, 0x808000);
		}
	// Display lines from camera to intersection with XZ plane
	for (i = 0; i < 4; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_intersect[i], (MR_VEC*)cam_matrix->t, &vec);
		MRDebugPlotWorldLineVEC((MR_VEC*)cam_matrix->t, &vec, 0x000080);
		}
	// Display active MAP_GROUPs
	poly_f4 = Map_view_debug_polys[MRFrame_index];
	index 	= Map_group_view_list;
	while(*index >= 0)
		{
		i = *index;				// active MAP_GROUP index
		x = i % Map_view_xnum;
		z = i / Map_view_xnum;
		MR_SET_SVEC(&corners[0], ((x + 0) * Map_view_xlen) + Map_view_basepoint.vx, 0, ((z + 1) * Map_view_zlen) + Map_view_basepoint.vz);
		MR_SET_SVEC(&corners[1], ((x + 1) * Map_view_xlen) + Map_view_basepoint.vx, 0, ((z + 1) * Map_view_zlen) + Map_view_basepoint.vz);
		MR_SET_SVEC(&corners[2], ((x + 0) * Map_view_xlen) + Map_view_basepoint.vx, 0, ((z + 0) * Map_view_zlen) + Map_view_basepoint.vz);
		MR_SET_SVEC(&corners[3], ((x + 1) * Map_view_xlen) + Map_view_basepoint.vx, 0, ((z + 0) * Map_view_zlen) + Map_view_basepoint.vz);
		MRDebugPlotWorldPolyF4(corners, poly_f4);
		poly_f4++;
		index++;
		}

	// Display XZ grid
	MR_SET_VEC(&vec2, 0, 0, (Map_view_znum * Map_view_zlen));
	for (i = 0; i <= Map_view_xnum; i++)
		{
		MR_SET_VEC(&vec, Map_view_basepoint.vx + (i * Map_view_xlen), 0, Map_view_basepoint.vz);
		MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
		}
	MR_SET_VEC(&vec2, (Map_view_xnum * Map_view_xlen), 0, 0);
	for (i = 0; i <= Map_view_znum; i++)
		{
		MR_SET_VEC(&vec, Map_view_basepoint.vx, 0, Map_view_basepoint.vz + (i * Map_view_zlen));
		MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
		}
}
#endif
#endif

#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% MapViewDrawPixel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapViewDrawPixel(
*						MR_LONG	x,
*						MR_LONG	y)
*
*	FUNCTION	Draws an imaginary pixel by storing the min and max x coords in arrays
*
*	INPUTS		x	-	x coord of point
*				y	-	y coord of point
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*	30.10.23	Kneesnap		Disabled to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	MapViewDrawPixel(	MR_LONG	x,
									MR_LONG	y)
{
	if ((y < 0) || (y >= Map_view_znum))
		return;

	Map_view_region_minx[y] = MIN(x, Map_view_region_minx[y]);
	Map_view_region_maxx[y] = MAX(x, Map_view_region_maxx[y]);
}
#endif


/******************************************************************************
*%%%% MapViewDrawLine
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapViewDrawLine(
*						MR_LONG	x0,
*						MR_LONG	z0,
*						MR_LONG	x1,
*						MR_LONG	z1)
*
*	FUNCTION	Draws an imaginary line between (x0,z0) and (x1,z1), storing
*				the min and max x coords in arrays
*
*	INPUTS		x0	-	x coord of point 0
*				z0	-	z coord of point 0
*				x1	-	x coord of point 1
*				z1	-	z coord of point 1
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*
*%%%**************************************************************************/
//
MR_VOID	MapViewDrawLine(MR_LONG	x0,
								MR_LONG	z0,
								MR_LONG	x1,
								MR_LONG	z1)
//{
//	MR_LONG	stepx, stepy;
//	MR_LONG	stepdx, stepdy;
//	MR_LONG	b, c, h, l, t, x, y;
//
//
//	x = x0;
//	y = z0;
//	MapViewDrawPixel(x, y);
//
//	stepx	= 1;
//	stepy	= 1;
//	
//	t = x1 - x0;
//	if (t <= 0)
//		{
//		// x1 <= x0
//		stepx	= -1;
//		t		= -t;
//		}
//	b = t;		// b holds no. of steps in x
//
//	t = z1 - z0;
//	if (t <= 0)
//		{
//		// z1 <= z0
//		stepy	= -1;
//		t		= -t;
//		}
//	c = t;		// c holds no. of steps in y
//
//	// Check line isn't a point
//	if (!(b | c))
//		return;
//
//	// Store dirn of diag step
//	stepdx = stepx;
//	stepdy = stepy;
//
//	if (b <= c)
//		{
//		stepx 	= 0;
//		c 		= b;
//		b 		= t;
//		}
//	else
//		stepy 	= 0;
//
//
//	// V/H step is in stepx/stepy
//	//
//	// b >= c.  The routine now takes (b - c) straight steps and (c) diagonal ones.
//	h = b;
//	l = b >> 1;
//	while(h)
//		{
//		l += c;
//		if (l >= b)
//			{
//			// Diag step
//			l -= b;
//			x += stepdx;
//			y += stepdy;
//			}
//		else
//			{
//			x += stepx;
//			y += stepy;
//			}
//		MapViewDrawPixel(x, y);
//		h--;
//		}
//}

// New version: gets ALL pixels which line passes through
{
	MR_LONG	mz, mz1;
	MR_LONG	tx, tz;
	MR_LONG	minx, maxx;


	minx 	= x0 / Map_view_xlen;
	maxx 	= minx;
	mz		= z0 / Map_view_zlen;
	mz1		= z1 / Map_view_zlen;
	tx		= x0;
	tz		= z0;

	if (z1 > z0)
		tz = ((tz / Map_view_zlen) * Map_view_zlen) + Map_view_zlen;
	else
	if (z1 < z0)
		tz = ((tz / Map_view_zlen) * Map_view_zlen);

	while(mz != mz1)
		{
		if	(
			(mz >= 0) &&
			(mz < Map_view_znum)
			)
			{
			if (z1 > z0)
				{
				// Look for line between (nz, z1) above nz
				if (tz >= z1)
					break;
				}
			else
			if (z1 < z0)
				{
				// Look for line between (nz, z1) below nz
				if (tz <= z1)
					break;
				}
		
			// Get intersection world x
//			tx = (((tz - z0) * (x1 - x0)) / (z1 - z0)) + x0;

			// Note: (tz - z0) and (x1 - x0) can both be larger than +/- 60000...
			if (abs(z1 - z0) >= 0x10)
				tx = ((((tz - z0) >> 2) * ((x1 - x0) >> 2)) / ((z1 - z0) >> 4)) + x0;
			else
				tx = (z0 + z1) >> 1;

			if (x1 >= x0)
				{
				maxx = tx / Map_view_xlen;
				Map_view_region_minx[mz] = MIN(minx, Map_view_region_minx[mz]);
				Map_view_region_maxx[mz] = MAX(maxx, Map_view_region_maxx[mz]);
				minx = maxx;
				}
			else
				{
				minx = tx / Map_view_xlen;
				Map_view_region_minx[mz] = MIN(minx, Map_view_region_minx[mz]);
				Map_view_region_maxx[mz] = MAX(maxx, Map_view_region_maxx[mz]);
				maxx = minx;	
				}
			}
		else
			{
			if	(
				(mz < 0) &&
				(z1 <= z0)
				)
				return;
			if	(
				(mz >= Map_view_znum) &&
				(z1 >= z0)
				)
				return;
			}
	
		if (z1 > z0)
			{
			mz++;
			tz += Map_view_zlen;
			}
		else
			{
			mz--;
			tz -= Map_view_zlen;
			}
		}

	if	(
		(mz >= 0) &&
		(mz < Map_view_znum)
		)
		{
		if (x1 >= x0)
			{
			maxx = x1 / Map_view_xlen;
			Map_view_region_minx[mz] = MIN(minx, Map_view_region_minx[mz]);
			Map_view_region_maxx[mz] = MAX(maxx, Map_view_region_maxx[mz]);
			}
		else
			{
			minx = x1 / Map_view_xlen;
			Map_view_region_minx[mz] = MIN(minx, Map_view_region_minx[mz]);
			Map_view_region_maxx[mz] = MAX(maxx, Map_view_region_maxx[mz]);
			}
		}
}


/******************************************************************************
*%%%% MapViewDrawPicture
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapViewDrawPicture(MR_VOID)
*
*	FUNCTION	Display view projection as 3D diagram
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapViewDrawPicture(MR_VOID)
{
#ifdef MAP_VIEW_DRAW_PICTURE
	MR_VEC		roll;
	MR_MAT*		camera;
	MR_LONG		i;
	MR_VEC		vec, vec2;
	MR_SHORT*	index;


	// Set up viewport camera
	MR_SET_VEC(&roll, 0, 0x1000, 0);
	MR_SET_VEC((MR_VEC*)Game_viewporth->vp_camera->fr_matrix.t, 0x800, -12000, -0x800);
	MRPointMatrixAtVector(&Game_viewporth->vp_camera->fr_matrix, &Null_vector, &roll);

	MRSetActiveViewport(Game_viewporth);
	camera = Cameras[0].ca_matrix;

	// Display camera dot
	MRDebugPlotWorldPointVEC((MR_VEC*)camera->t, 0x808080, 3);

	// Display projected quad
	for (i = 0; i < 5; i++)
		{
		MR_SUB_VEC_ABC(&Map_view_plane_intersect[(i + 1) % 5], &Map_view_plane_intersect[i], &vec);
		MRDebugPlotWorldLineVEC(&Map_view_plane_intersect[i], &vec, 0x000080);
		}

	// Display XZ grid
	MR_SET_VEC(&vec2, 0, 0, (Map_view_znum * Map_view_zlen));
	for (i = 0; i <= Map_view_xnum; i++)
		{
		MR_SET_VEC(&vec, Map_view_basepoint.vx + (i * Map_view_xlen), 0, Map_view_basepoint.vz);
		MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
		}
	MR_SET_VEC(&vec2, (Map_view_xnum * Map_view_xlen), 0, 0);
	for (i = 0; i <= Map_view_znum; i++)
		{
		MR_SET_VEC(&vec, Map_view_basepoint.vx, 0, Map_view_basepoint.vz + (i * Map_view_zlen));
		MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
		}

	// Display dots for created groups
	index  	= Map_group_view_list[0];
	vec.vy	= 0;
	while(*index >= 0)
		{
		vec.vx = (((*index) % Map_view_znum) * Map_view_xlen) + Map_view_basepoint.vx + (Map_view_xlen >> 1);
		vec.vz = (((*index) / Map_view_znum) * Map_view_zlen) + Map_view_basepoint.vz + (Map_view_zlen >> 1);
		MRDebugPlotWorldPointVEC(&vec, 0x00a000, 3);
		index++;
		}
#endif
}


/******************************************************************************
*%%%% MapViewTest
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapViewTest(MR_VOID)
*
*	FUNCTION	Test function to display view region calculation
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef DEBUG
MR_VOID	MapViewTest(MR_VOID)
{
	MR_LONG		i;
	MR_VEC		roll, vec, vec2;
	MR_MAT		camera;
	MR_SVEC		vpc_svecs[4];	// view plane corners in camera frame
	MR_VEC		vpc_vecs[4];	// view plane corners in world
	MR_ULONG	perspective;	
	MR_VEC		intersect[5];
	MR_LONG		l;
	MR_LONG		minz, maxz, minx, maxx;
	MR_LONG		x, z, count;


	MRDebugInitialiseDisplay();

	MR_SET_SVEC(&Map_view_basepoint, -0x1000, 0, -0x1000);
	Map_view_xlen	= 768;
	Map_view_zlen	= 768;
	Map_view_xnum	= 16;
	Map_view_znum	= 16;
	perspective 	= 160;	

	// Set up viewport camera
	MR_SET_VEC(&roll, 0, 0x1000, 0);
	MR_SET_VEC((MR_VEC*)Game_viewport0->vp_camera->fr_matrix.t, 0x800, -7000, -0x800);
	MRPointMatrixAtVector(&Game_viewport0->vp_camera->fr_matrix, &Null_vector, &roll);

	// Set up calc camera
	MR_SET_VEC((MR_VEC*)camera.t, -0x800, -4000, -0x800);
	MRPointMatrixAtVector(&camera, &Null_vector, &roll);
	
	while(1)
		{
#ifdef PSX
		DrawSync(0);
		VSync(0);
		MRSwapDisplay();
#endif
		MRDebugStartDisplay();
		MRReadInput();
		MRUpdateObjects();
		MRUpdateFrames();
		MRUpdateViewportRenderMatrices();
  
//		MRStartGatso();
		//---------------------------------------------------------------------------
		// Calculate and display region
		//---------------------------------------------------------------------------

		// Set view plane corners in camera coords
		MR_SET_SVEC(&vpc_svecs[1], -SYSTEM_DISPLAY_WIDTH / 2, -SYSTEM_DISPLAY_HEIGHT / 2, perspective);
		MR_SET_SVEC(&vpc_svecs[2],  SYSTEM_DISPLAY_WIDTH / 2, -SYSTEM_DISPLAY_HEIGHT / 2, perspective);
		MR_SET_SVEC(&vpc_svecs[3],  SYSTEM_DISPLAY_WIDTH / 2,  SYSTEM_DISPLAY_HEIGHT / 2, perspective);
		MR_SET_SVEC(&vpc_svecs[0], -SYSTEM_DISPLAY_WIDTH / 2,  SYSTEM_DISPLAY_HEIGHT / 2, perspective);

		// Display camera dot
		MRDebugPlotWorldPointVEC((MR_VEC*)camera.t, 0x808080, 3);

		// Display viewplane
		gte_SetRotMatrix(&camera);
		for (i = 0; i < 4; i++)
			{
			MRApplyRotMatrix(&vpc_svecs[i], &vpc_vecs[i]);
			MR_ADD_VEC(&vpc_vecs[i], (MR_VEC*)camera.t);
			}
		for (i = 0; i < 4; i++)
			{
			MR_SUB_VEC_ABC(&vpc_vecs[(i + 1) & 3], &vpc_vecs[i], &vec);
			MRDebugPlotWorldLineVEC(&vpc_vecs[i], &vec, 0x808000);
			}

		// Find intersection points of volume lines with XZ plane (Y = 0)
		for (i = 0; i < 4; i++)
			{
			MR_SUB_VEC_ABC(&vpc_vecs[i], (MR_VEC*)camera.t, &vec);

			// vec is vector from camera to view plane corner. Modify this if the angle between this line and the XZ plane
			// is too small (ie. if we think the intersection point will be wildly outside the map area)
			l = MR_SQR(vec.vx) + MR_SQR(vec.vz);
			if (l > (MR_SQR(vec.vy) * 8))
				{
				// Modify
				vec.vy = MR_SQRT(l / 8);
				}

			l = (-camera.t[1] << 8) / vec.vy;

			// Note that the intersection points can be outside of MR_SVEC range
			intersect[i].vx = camera.t[0] + ((l * vec.vx) >> 8);
			intersect[i].vy = 0;
			intersect[i].vz = camera.t[2] + ((l * vec.vz) >> 8);
			MRDebugPlotWorldPointVEC(&intersect[i], 0xa0a0a0, 3);
			}

		// intersect[4] is projected camera origin
		intersect[4].vx = camera.t[0];
		intersect[4].vy = 0;
		intersect[4].vz = camera.t[2];

		// Display lines from camera throught viewplane corners
		for (i = 0; i < 4; i++)
			{
			MR_SUB_VEC_ABC(&intersect[i], (MR_VEC*)camera.t, &vec);
			MRDebugPlotWorldLineVEC((MR_VEC*)camera.t, &vec, 0x404040);
			}

		// Display projected quad
		for (i = 0; i < 5; i++)
			{
			MR_SUB_VEC_ABC(&intersect[(i + 1) % 5], &intersect[i], &vec);
			MRDebugPlotWorldLineVEC(&intersect[i], &vec, 0x000080);
			}

		// Clear row buffers
		for (i = 0; i < Map_view_znum; i++)
			{
			Map_view_region_minx[i]	= 0x7fffffff;
			Map_view_region_maxx[i] = -0x7fffffff;
			}

		for (i = 0; i < 5; i++)
			{
			intersect[i].vx -= Map_view_basepoint.vx;
			intersect[i].vz -= Map_view_basepoint.vz;
			}

		for (i = 0; i < 5; i++)
			MapViewDrawLine(intersect[i].vx, intersect[i].vz, intersect[(i + 1) % 5].vx, intersect[(i + 1) % 5].vz);

		for (i = 0; i < 5; i++)
			{
			intersect[i].vx /= Map_view_xlen;
			intersect[i].vz /= Map_view_zlen;
			}

		// Now run from z = minz to z = maxz, filling grid squares between ..view_region_minx[z] and ..view_region_maxx[z]
		count 	= 0;
		vec.vy	= 0;
		minz 	= MIN(MIN(MIN(MIN(intersect[0].vz, intersect[1].vz), intersect[2].vz), intersect[3].vz), intersect[4].vz);
		maxz 	= MAX(MAX(MAX(MAX(intersect[0].vz, intersect[1].vz), intersect[2].vz), intersect[3].vz), intersect[4].vz);
		minz	= MAX(0, minz);
		maxz	= MIN(Map_view_znum - 1, maxz);

		for (z = minz; z <= maxz; z++)
			{
			minx = MAX(0,	 				Map_view_region_minx[z]);
			maxx = MIN(Map_view_xnum - 1, 	Map_view_region_maxx[z]);
			
			for (x = minx; x <= maxx; x++)
				{
				vec.vx = (x * Map_view_xlen) + Map_view_basepoint.vx + (Map_view_xlen >> 1);
				vec.vz = (z * Map_view_xlen) + Map_view_basepoint.vz + (Map_view_zlen >> 1);
				MRDebugPlotWorldPointVEC(&vec, 0x00a000, 3);
				if (++count >= MAP_MAX_POLY_GROUPS)
					goto display_grid;
				}
			}

	display_grid:;

		// Display XZ grid
		MR_SET_VEC(&vec2, 0, 0, (Map_view_znum * Map_view_zlen));
		for (i = 0; i <= Map_view_xnum; i++)
			{
			MR_SET_VEC(&vec, Map_view_basepoint.vx + (i * Map_view_xlen), 0, Map_view_basepoint.vz);
			MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
			}
		MR_SET_VEC(&vec2, (Map_view_xnum * Map_view_xlen), 0, 0);
		for (i = 0; i <= Map_view_znum; i++)
			{
			MR_SET_VEC(&vec, Map_view_basepoint.vx, 0, Map_view_basepoint.vz + (i * Map_view_zlen));
			MRDebugPlotWorldLineVEC(&vec, &vec2, 0x004000);
			}
//		MRStopGatso();
	
		//---------------------------------------------------------------------------
		// Allow movement
		//---------------------------------------------------------------------------
		// Move camera
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_LEFT))
			camera.t[0] -= 0x20;
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_RIGHT))
			camera.t[0] += 0x20;
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_UP))
			camera.t[2] += 0x20;
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_DOWN))
			camera.t[2] -= 0x20;
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_GREEN))
			camera.t[1] -= 0x20;
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_BLUE))
			camera.t[1] += 0x20;
		MRPointMatrixAtVector(&camera, &Null_vector, &roll);

		// Change perspective
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_PINK))
			perspective = MAX(  0x8, perspective - 4);
		if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, FRR_RED))
			perspective = MIN(0x200, perspective + 4);

		MRRenderViewport(Game_viewport0);

#ifdef WIN95	//-win95 specific code---------------------------------------------------------
		MRSwapDisplay();
#endif			//-end of specific code--------------------------------------------------------

		}
}
#endif

#ifdef WIN95
#pragma warning (default : 4761)
#endif
