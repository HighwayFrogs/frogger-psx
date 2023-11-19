/******************************************************************************
*%%%% grid.c
*------------------------------------------------------------------------------
*
*	Grid handling functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "grid.h"
#include "frog.h"



MR_LONG			Grid_base_x;				// x coord of bottom left of grid
MR_LONG			Grid_base_z;				// z coord of bottom left of grid
MR_LONG			Grid_xnum;					// number of grid squares in x (even)
MR_LONG			Grid_znum;					// number of grid squares in z (even)
MR_LONG			Grid_xshift;				// (1 << Grid_xshift) = x length of grid square
MR_LONG			Grid_zshift;				// (1 << Grid_zshift) = z length of grid square
MR_LONG			Grid_xlen;					// x length of grid square
MR_LONG			Grid_zlen;					// z length of grid square

GRID_STACK*		Grid_stacks;				// ptr to array of (xnum * znum) GRID_STACKs
GRID_SQUARE*	Grid_squares;				// ptr to array of GRID_SQUAREs

//MR_LONG			Grid_square_offsets[4];		// offset between adjacent grid squares
	

/******************************************************************************
*%%%% InitialiseGrid
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseGrid(MR_VOID)
*
*	FUNCTION	Initialise the grid (the 'board' on which the game is played)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseGrid(MR_VOID)
{
}


/******************************************************************************
*%%%% GetGridStack
*------------------------------------------------------------------------------
*
*	SYNOPSIS	GRID_STACK*	grid_stack =	GetGridStack(
*											MR_LONG	x,
*											MR_LONG	z)
*
*	FUNCTION	Returns a pointer to the GRID_STACK structure at coords (x,z)
*
*	INPUTS		x			-	x grid coord
*				z			-	z grid coord
*
*	RESULT		grid_stack	-	ptr to GRID_STACK
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

GRID_STACK*	GetGridStack(	MR_LONG	x,
							MR_LONG	z)
{
	MR_ASSERT(x >= 0);
	MR_ASSERT(x < Grid_xnum);
	MR_ASSERT(z >= 0);
	MR_ASSERT(z < Grid_znum);

	return(Grid_stacks + (z * Grid_xnum) + x);
}


/******************************************************************************
*%%%% GetGridSquareCentre
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridSquareCentre(
*						GRID_SQUARE*	grid_square,
*						MR_SVEC*		coord)
*
*	FUNCTION	Calculate the world coord of the centre of a grid square
*
*	INPUTS		grid_square	-	ptr to GRID_SQUARE
*				coord		-	ptr to MR_SVEC to store coord
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.04.97	Tim Closs		Created
*	20.08.97	Martin Kift		Changed calc of x and z to use all poly
*								vertices, to cope with tris and quads.
*
*%%%**************************************************************************/

MR_VOID	GetGridSquareCentre(GRID_SQUARE*	grid_square,
							MR_SVEC*		coord)
{
	coord->vx = (	Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vx +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vx +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vx +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vx) >> 2;
	coord->vz = (	Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vz +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vz +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vz +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vz) >> 2;

	coord->vx = (GET_GRID_X_FROM_WORLD_X(coord->vx) << 8) + 0x80 + Grid_base_x;
	coord->vz = (GET_GRID_Z_FROM_WORLD_Z(coord->vz) << 8) + 0x80 + Grid_base_z;

	coord->vy = (	Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy +
					Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy) >> 2;
}


/******************************************************************************
*%%%% GetGridSquareHeight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	y =	GetGridSquareHeight(
*							GRID_SQUARE*	grid_square)
*
*	FUNCTION	Calculate the average y of grid square vertices
*
*	INPUTS		grid_square	-	ptr to GRID_SQUARE
*
*	RESULT		y			-	height
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	GetGridSquareHeight(GRID_SQUARE*	grid_square)
{
	MR_LONG	y;


	y = (	Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy +
			Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy +
			Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy +
			Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy) >> 2;

	return(y);
}


#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% GetGridSquareNormals
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridSquareNormals(
*						GRID_SQUARE*	grid_square,
*						MR_VEC*			normal0,
*						MR_VEC*			normal1)
*
*	FUNCTION	Calculate the normals from the two effective tris making up a 
*				grid square
*
*	INPUTS		grid_square	-	ptr to GRID_SQUARE
*				normal0		-	where to store normal 0
*				normal1		-	where to store normal 1
*
*	NOTES		Returned normals are normalised (length 0x1000)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	02.11.23	Kneesnap		Disabled as part of an effort to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	GetGridSquareNormals(	GRID_SQUARE*	grid_square,
										MR_VEC*			normal0,
										MR_VEC*			normal1)
{
	MR_VEC		edge0;
	MR_VEC		edge1;
	MR_SVEC*	map_poly_v0;
	MR_SVEC*	map_poly_v1;
	MR_SVEC*	map_poly_v2;
	MR_SVEC*	map_poly_v3;


	// The vertices of the associated map poly are in PSX format, ie:
	//
	// vertex 0		- top left		(min x, max z)
	// vertex 1		- top right		(max x, max z)
	// vertex 2		- bottom left 	(min x, min z)
	// vertex 3		- botom right	(max x, min z)

	map_poly_v0 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[0]];
	map_poly_v1 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[1]];
	map_poly_v2 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[2]];
	map_poly_v3 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[3]];

	edge0.vx 	= map_poly_v1->vx - map_poly_v0->vx;
	edge0.vy 	= map_poly_v1->vy - map_poly_v0->vy;
	edge0.vz 	= map_poly_v1->vz - map_poly_v0->vz;
	edge1.vx 	= map_poly_v2->vx - map_poly_v0->vx;
	edge1.vy 	= map_poly_v2->vy - map_poly_v0->vy;
	edge1.vz 	= map_poly_v2->vz - map_poly_v0->vz;

	// Entries of edge? are now typically 0x100
	MROuterProduct(&edge0, &edge1, normal0);
	if	(
		(normal0->vx) ||
		(normal0->vy) ||
		(normal0->vz)
		)
		MRNormaliseVEC(normal0, normal0);
	else
		MR_CLEAR_VEC(normal0);

	edge0.vx 	= map_poly_v1->vx - map_poly_v3->vx;
	edge0.vy 	= map_poly_v1->vy - map_poly_v3->vy;
	edge0.vz 	= map_poly_v1->vz - map_poly_v3->vz;
	edge1.vx 	= map_poly_v2->vx - map_poly_v3->vx;
	edge1.vy 	= map_poly_v2->vy - map_poly_v3->vy;
	edge1.vz 	= map_poly_v2->vz - map_poly_v3->vz;

	// Entries of edge? are now typically 0x100
	MROuterProduct(&edge0, &edge1, normal1);
	if	(
		(normal1->vx) ||
		(normal1->vy) ||
		(normal1->vz)
		)
		MRNormaliseVEC(normal1, normal1);
	else
		MR_CLEAR_VEC(normal1);
	MRNormaliseVEC(normal1, normal1);
}
#endif

/******************************************************************************
*%%%% GetGridSquareAverageNormal
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridSquareAverageNormal(
*						GRID_SQUARE*	grid_square,
*						MR_VEC*			normal)
*
*	FUNCTION	Calculate the average or the normals from the two effective
*				tris making up a grid square
*
*	INPUTS		grid_square	-	ptr to GRID_SQUARE
*				normal		-	where to store normal
*
*	NOTES		Returned normal is normalised (length 0x1000)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GetGridSquareAverageNormal(	GRID_SQUARE*	grid_square,
									MR_VEC*			normal)
{
	MR_VEC		edge0;
	MR_VEC		edge1;
	MR_VEC		normal0;
	MR_VEC		normal1;
	MR_SVEC*	map_poly_v0;
	MR_SVEC*	map_poly_v1;
	MR_SVEC*	map_poly_v2;
	MR_SVEC*	map_poly_v3;


	// The vertices of the associated map poly are in PSX format, ie:
	//
	// vertex 0		- top left		(min x, max z)
	// vertex 1		- top right		(max x, max z)
	// vertex 2		- bottom left 	(min x, min z)
	// vertex 3		- botom right	(max x, min z)

	map_poly_v0 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[0]];
	map_poly_v1 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[1]];
	map_poly_v2 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[2]];
	map_poly_v3 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[3]];

	edge0.vx 	= (map_poly_v1->vx - map_poly_v0->vx) << 4;
	edge0.vy 	= (map_poly_v1->vy - map_poly_v0->vy) << 4;
	edge0.vz 	= (map_poly_v1->vz - map_poly_v0->vz) << 4;
	edge1.vx 	= (map_poly_v2->vx - map_poly_v0->vx) << 4;
	edge1.vy 	= (map_poly_v2->vy - map_poly_v0->vy) << 4;
	edge1.vz 	= (map_poly_v2->vz - map_poly_v0->vz) << 4;

	// Entries of edge? are now typically 0x1000
	MROuterProduct12(&edge1, &edge0, &normal0);

	edge0.vx 	= (map_poly_v1->vx - map_poly_v3->vx) << 4;
	edge0.vy 	= (map_poly_v1->vy - map_poly_v3->vy) << 4;
	edge0.vz 	= (map_poly_v1->vz - map_poly_v3->vz) << 4;
	edge1.vx 	= (map_poly_v2->vx - map_poly_v3->vx) << 4;
	edge1.vy 	= (map_poly_v2->vy - map_poly_v3->vy) << 4;
	edge1.vz 	= (map_poly_v2->vz - map_poly_v3->vz) << 4;

	// Entries of edge? are now typically 0x1000
	//
	// If the GRID_SQUARE points to a MAP_POLY which is a tri, edge1 will be 0, and we just want normal0
	if	(
		(edge1.vx) ||
		(edge1.vy) ||
		(edge1.vz)
		)
		{
		MRNormaliseVEC(&normal0, &normal0);
		MROuterProduct12(&edge0, &edge1, &normal1);
		MRNormaliseVEC(&normal1, &normal1);
		normal->vx = (normal0.vx + normal1.vx) >> 1;
		normal->vy = (normal0.vy + normal1.vy) >> 1;		
		normal->vz = (normal0.vz + normal1.vz) >> 1;		
		MRNormaliseVEC(normal, normal);
		}
	else
		{
		MRNormaliseVEC(&normal0, normal);
		}
}

#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% GetHeightFromWorldXZAndGridSquare
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	y =	GetHeightFromWorldXZAndGridSquare(
*							MR_LONG			x,
*							MR_LONG			z,
*							GRID_SQUARE*	grid_square)
*
*	FUNCTION	Project world XZ onto extension of plane(s) defined by a 
*				GRID_SQUARE
*
*	INPUTS		x			-	world x
*				z			-	world z
*				grid_square	-	ptr to GRID_SQUARE
*
*	RESULT		y			-	world y
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Tim Closs		Created
*	02.11.23	Kneesnap		Disabled as part of an effort to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_LONG	GetHeightFromWorldXZAndGridSquare(	MR_LONG			x,
											MR_LONG			z,
											GRID_SQUARE*	grid_square)
{
	MR_LONG	y;
	MR_LONG	dx;
	MR_LONG	dz;
	MR_LONG	map_poly_y0;
	MR_LONG	map_poly_y1;
	MR_LONG	map_poly_y2;
	MR_LONG	map_poly_y3;


	MR_ASSERT(grid_square);

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx = x & 0xff;	
	dz = z & 0xff;	
	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz			= 0x100 - dz;
		y			= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx			= 0x100 - dx;
		y			= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		}

	return(y);
}


/******************************************************************************
*%%%% GetHeightFromWorldXZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	y =	GetHeightFromWorldXZ(
*							MR_LONG	x,
*							MR_LONG	z)
*
*	FUNCTION	Project world XZ onto extension of plane(s) defined by the
*				first GRID_SQUARE in the GRID_STACK
*
*	INPUTS		x	-	world x
*				z	-	world z
*
*	RESULT		y	-	world y
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Tim Closs		Created
*	02.11.23	Kneesnap		Disabled as part of an effort to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_LONG	GetHeightFromWorldXZ(	MR_LONG	x,
								MR_LONG	z)
{
	MR_LONG			y;
	MR_LONG			dx;
	MR_LONG			dz;
	MR_LONG			gx;
	MR_LONG			gz;
	MR_LONG			map_poly_y0;
	MR_LONG			map_poly_y1;
	MR_LONG			map_poly_y2;
	MR_LONG			map_poly_y3;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;


	gx 			= GET_GRID_X_FROM_WORLD_X(x);
	gz 			= GET_GRID_Z_FROM_WORLD_Z(z);
	grid_stack 	= Grid_stacks + (gz * Grid_xnum) + gx;
	MR_ASSERT(grid_stack->gs_numsquares);
	grid_square = Grid_squares + grid_stack->gs_index;

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx = x & 0xff;	
	dz = z & 0xff;	
	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz			= 0x100 - dz;
		y			= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx			= 0x100 - dx;
		y			= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		}

	return(y);
}
#endif


/******************************************************************************
*%%%% GetHeightFromWorldXYZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	height =	GetHeightFromWorldXYZ(
*									MR_LONG			x,
*									MR_LONG			y,
*									MR_LONG			z,
*									GRID_SQUARE**	grid_pptr)
*
*	FUNCTION	Project world XZ onto extension of plane(s) defined by a
*				GRID_SQUARE in the GRID_STACK.  We start from the highest GRID_SQUARE,
*				and take the first one with any corner y below the input (or the lowest
*				GRID_SQUARE if none fit this condition)
*
*	INPUTS		x			-	world x
*				y			-	world y
*				z			-	world z
*				grid_pptr	-	ptr to GRID_SQUARE* to store where we projected onto (or NULL)
*
*	RESULT		height		-	world y
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	GetHeightFromWorldXYZ(	MR_LONG			x,
								MR_LONG			y,
								MR_LONG			z,
								GRID_SQUARE**	grid_pptr)
{
	MR_LONG			height;
	MR_LONG			dx;
	MR_LONG			dz;
	MR_LONG			gx;
	MR_LONG			gz;
	MR_LONG			i;
	MR_LONG			map_poly_y0;
	MR_LONG			map_poly_y1;
	MR_LONG			map_poly_y2;
	MR_LONG			map_poly_y3;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;


	gx 			= GET_GRID_X_FROM_WORLD_X(x);
	gz 			= GET_GRID_Z_FROM_WORLD_Z(z);
	grid_stack 	= Grid_stacks + (gz * Grid_xnum) + gx;

	if (!grid_stack->gs_numsquares)
		return(GRID_RETURN_VALUE_ERROR);

	// Start from highest GRID_SQUARE.  Take the first one with any corner y below the input (or the lowest GRID_SQUARE if
	// none fit this condition)
	i			= grid_stack->gs_numsquares;
	grid_square = Grid_squares + grid_stack->gs_index + i;
	while(i--)
		{
		grid_square--;
		if	(
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy >= y)
			)
			{
			// Take this GRID_SQUARE
			break;
			}
		}

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx = x & 0xff;	
	dz = z & 0xff;	
	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz			= 0x100 - dz;
		height		= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx			= 0x100 - dx;
		height		= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		}

	if (grid_pptr)
		*grid_pptr = grid_square;

	return(height);
}

#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% GetGridInfoFromWorldXZAndGridSquare
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridInfoFromWorldXZAndGridSquare(
*						MR_LONG			x,
*						MR_LONG			z,
*						GRID_SQUARE*	grid_square,
*						GRID_INFO*		grid_info)
*
*	FUNCTION	Project world XZAndGridSquare onto extension of plane(s) defined by the
*				GRID_SQUARE.  Also find directions of slope of poly
*
*	INPUTS		x			-	world x
*				z			-	world z
*				grid_square	-	ptr to GRID_SQUARE
*				grid_info	-	ptr to GRID_INFO in which to store results
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Tim Closs		Created
*	02.11.23	Kneesnap		Disabled as part of an effort to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	GetGridInfoFromWorldXZAndGridSquare(MR_LONG			x,
											MR_LONG			z,
											GRID_SQUARE*	grid_square,
											GRID_INFO*		grid_info)
{
	MR_LONG			dx;
	MR_LONG			dz;
	MR_LONG			map_poly_y0;
	MR_LONG			map_poly_y1;
	MR_LONG			map_poly_y2;
	MR_LONG			map_poly_y3;
	MR_VEC			xslope;
	MR_VEC			zslope;


	MR_ASSERT(grid_info);
	MR_ASSERT(grid_square);

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx 			= x & 0xff;	
	dz 			= z & 0xff;	
	xslope.vx 	= 0x100;
	xslope.vz 	= 0;
	zslope.vx 	= 0;
	zslope.vz 	= 0x100;

	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz				= 0x100 - dz;
		grid_info->gi_y	= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		xslope.vy		= map_poly_y1 - map_poly_y0;
		zslope.vy		= map_poly_y0 - map_poly_y2;
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx				= 0x100 - dx;
		grid_info->gi_y	= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		xslope.vy		= map_poly_y3 - map_poly_y2;
		zslope.vy		= map_poly_y1 - map_poly_y3;
		}

	MRNormaliseVEC(&xslope, &grid_info->gi_xslope);
	MRNormaliseVEC(&zslope, &grid_info->gi_zslope);
}
#endif


/******************************************************************************
*%%%% GetGridInfoFromWorldXZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridInfoFromWorldXZ(
*						MR_LONG		x,
*						MR_LONG		z,
*						GRID_INFO*	grid_info)
*
*	FUNCTION	Project world XZ onto extension of plane(s) defined by the
*				first GRID_SQUARE in the GRID_STACK.  Also find directions of
*				slope of poly
*
*	INPUTS		x			-	world x
*				z			-	world z
*				grid_info	-	ptr to GRID_INFO in which to store results
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	GetGridInfoFromWorldXZ(	MR_LONG		x,
								MR_LONG		z,
								GRID_INFO*	grid_info)
{
	MR_LONG			dx;
	MR_LONG			dz;
	MR_LONG			gx;
	MR_LONG			gz;
	MR_LONG			map_poly_y0;
	MR_LONG			map_poly_y1;
	MR_LONG			map_poly_y2;
	MR_LONG			map_poly_y3;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_VEC			xslope;
	MR_VEC			zslope;


	MR_ASSERT(grid_info);

	gx 			= GET_GRID_X_FROM_WORLD_X(x);
	gz 			= GET_GRID_Z_FROM_WORLD_Z(z);
	grid_stack 	= Grid_stacks + (gz * Grid_xnum) + gx;
	MR_ASSERT(grid_stack->gs_numsquares);
	grid_square = Grid_squares + grid_stack->gs_index;

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx 			= x & 0xff;	
	dz 			= z & 0xff;	
	xslope.vx 	= 0x100;
	xslope.vz 	= 0;
	zslope.vx 	= 0;
	zslope.vz 	= 0x100;

	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz				= 0x100 - dz;
		grid_info->gi_y	= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		xslope.vy		= map_poly_y1 - map_poly_y0;
		zslope.vy		= map_poly_y0 - map_poly_y2;
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx				= 0x100 - dx;
		grid_info->gi_y	= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		xslope.vy		= map_poly_y3 - map_poly_y2;
		zslope.vy		= map_poly_y1 - map_poly_y3;
		}

	MRNormaliseVEC(&xslope, &grid_info->gi_xslope);
	MRNormaliseVEC(&zslope, &grid_info->gi_zslope);
}


#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% GetGridInfoFromWorldXYZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetGridInfoFromWorldXYZ(
*						MR_LONG		x,
*						MR_LONG		y,
*						MR_LONG		z,
*						GRID_INFO*	grid_info)
*
*	FUNCTION	Project world XZ onto extension of plane(s) defined by a
*				GRID_SQUARE in the GRID_STACK.  Also find directions of
*				slope of poly.  We start from the highest GRID_SQUARE, and take
*				the first one with any corner y below the input (or the lowest
*				GRID_SQUARE if none fit this condition)
*
*	INPUTS		x			-	world x
*				y			-	world y
*				z			-	world z
*				grid_info	-	ptr to GRID_INFO in which to store results
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.07.97	Tim Closs		Created
*	02.11.23	Kneesnap		Disabled as part of an effort to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	GetGridInfoFromWorldXYZ(MR_LONG		x,
								MR_LONG		y,
								MR_LONG		z,
								GRID_INFO*	grid_info)
{
	MR_LONG			dx;
	MR_LONG			dz;
	MR_LONG			gx;
	MR_LONG			gz;
	MR_LONG			i;
	MR_LONG			map_poly_y0;
	MR_LONG			map_poly_y1;
	MR_LONG			map_poly_y2;
	MR_LONG			map_poly_y3;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_VEC			xslope;
	MR_VEC			zslope;


	MR_ASSERT(grid_info);

	gx 			= GET_GRID_X_FROM_WORLD_X(x);
	gz 			= GET_GRID_Z_FROM_WORLD_Z(z);
	grid_stack 	= Grid_stacks + (gz * Grid_xnum) + gx;
	MR_ASSERT(grid_stack->gs_numsquares);

	// Start from highest GRID_SQUARE.  Take the first one with any corner y below the input (or the lowest GRID_SQUARE if
	// none fit this condition)
	i			= grid_stack->gs_numsquares;
	grid_square = Grid_squares + grid_stack->gs_index + i;
	while(i--)
		{
		grid_square--;
		if	(
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy >= y) ||
			(Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy >= y)
			)
			{
			// Take this GRID_SQUARE
			break;
			}
		}

	// GRID_SQUARE points to a map poly, which we take to define two semi-infinite tris.
	// Work out which one we are over, then project onto it.
	dx 			= x & 0xff;	
	dz 			= z & 0xff;	
	xslope.vx 	= 0x100;
	xslope.vz 	= 0;
	zslope.vx 	= 0;
	zslope.vz 	= 0x100;

	if (dz >= dx)
		{
		// Top left tri
		map_poly_y0 = Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy;
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;

		dz				= 0x100 - dz;
		grid_info->gi_y	= map_poly_y0 + ((dx * (map_poly_y1 - map_poly_y0)) >> 8) + ((dz * (map_poly_y2 - map_poly_y0)) >> 8);
		xslope.vy		= map_poly_y1 - map_poly_y0;
		zslope.vy		= map_poly_y0 - map_poly_y2;
		}	
	else
		{
		// Bottom right tri
		map_poly_y1 = Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy;
		map_poly_y2 = Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy;
		map_poly_y3 = Map_vertices[grid_square->gs_map_poly->mp_vertices[3]].vy;

		dx				= 0x100 - dx;
		grid_info->gi_y	= map_poly_y3 + ((dx * (map_poly_y2 - map_poly_y3)) >> 8) + ((dz * (map_poly_y1 - map_poly_y3)) >> 8);
		xslope.vy		= map_poly_y3 - map_poly_y2;
		zslope.vy		= map_poly_y1 - map_poly_y3;
		}

	MRNormaliseVEC(&xslope, &grid_info->gi_xslope);
	MRNormaliseVEC(&zslope, &grid_info->gi_zslope);
}
#endif

/******************************************************************************
*%%%% GetNextGridLineIntersectionInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetNextGridLineIntersectionInit(
*								MR_SVEC*			start,
*								MR_SVEC*			end,
*								GRID_LINE_INTER*	gl_inter)
*
*	FUNCTION:	Performs an algorithm going through lanscape squares from the 
*				start world pos to the end world pos. 
*
*	INPUTS		start		-	start pos (vector)
*				end			-	end pos (vector)
*				gl_inter	-	grid line intersection algortim structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	Martin Kift		Created 
*
*%%%**************************************************************************/

MR_VOID GetNextGridLineIntersectionInit(MR_SVEC*			start, 
										MR_SVEC*			end, 
										GRID_LINE_INTER*	gl_inter)
{
	// set curr pos
	MR_COPY_VEC(&gl_inter->curr_pos, start);

	MR_SET_VEC(&gl_inter->step_vec, 	end->vx - start->vx,
										end->vy - start->vy,
										end->vz - start->vz);

	// work out number of iterations needed
	gl_inter->curr_step = 0;
	gl_inter->num_steps = MR_VEC_MOD(&gl_inter->step_vec) >> 8;		// Tile size is 256
	if (!gl_inter->num_steps)										// Must always be one step
		gl_inter->num_steps = 1;

	// get step vector
	MRNormaliseVEC(&gl_inter->step_vec, &gl_inter->step_vec);
	gl_inter->step_vec.vx <<= 8;
	gl_inter->step_vec.vy <<= 8;
	gl_inter->step_vec.vz <<= 8;

	// set end tile
	gl_inter->end_tile.x = GET_GRID_X_FROM_WORLD_X(end->vx);
	gl_inter->end_tile.y = GET_GRID_Z_FROM_WORLD_Z(end->vz);

	// set mode
	gl_inter->mode = LI_MODE_START;
}

/******************************************************************************
*%%%% GetNextGridLineIntersection
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GetNextGridLineIntersection(
*								GRID_LINE_INTER*	gl_inter)
*
*	FUNCTION:	Returns the next landscape tile that 3d line has intersected or 
*				null if none found	
*	MATCHES:	https://decomp.me/scratch/AV4Hc (By Kneesnap)
*
*	INPUTS		start		-	start pos (vector)
*				end			-	end pos (vector)
*				gl_inter	-	grid line intersection algortim structure
*
*	RESULT		returns zx index of the tile that has been intersected
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	Martin Kift		Created 
*	02.11.23	Kneesnap		Decompiled a byte-match to PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_XY GetNextTileInteresectingLine(GRID_LINE_INTER*	gl_inter)
{
	MR_SVEC		D;

	switch (gl_inter->mode)
		{
		//----------------------------------------------------------------------
		case LI_MODE_START:
			// return start point
			gl_inter->tile.x		= GET_GRID_X_FROM_WORLD_X(gl_inter->curr_pos.vx);
			gl_inter->tile.y		= GET_GRID_Z_FROM_WORLD_Z(gl_inter->curr_pos.vz);
			gl_inter->last_tile.x	= gl_inter->tile.x;
			gl_inter->last_tile.y	= gl_inter->tile.y;
			if (gl_inter->num_steps != 1) {
				gl_inter->mode		= LI_MODE_PROCESS;
			} else {
				gl_inter->mode		= LI_MODE_DONE;
			}
			break;

		//----------------------------------------------------------------------
		case LI_MODE_PROCESS:
		case LI_MODE_END:
			// get next new tile
			do 
				{
				// store last tile
				gl_inter->last_tile.x = gl_inter->tile.x;
				gl_inter->last_tile.y = gl_inter->tile.y;

				if (gl_inter->mode == LI_MODE_END)
					{
					// get end tile
					gl_inter->tile.x = gl_inter->end_tile.x;
					gl_inter->tile.y = gl_inter->end_tile.y;
					}
				else
					{
					// update curr pos
					gl_inter->curr_pos.vx += (gl_inter->step_vec.vx>>12);
					gl_inter->curr_pos.vy += (gl_inter->step_vec.vy>>12);
					gl_inter->curr_pos.vz += (gl_inter->step_vec.vz>>12);

					// get new tile
					gl_inter->tile.x = GET_GRID_X_FROM_WORLD_X(gl_inter->curr_pos.vx);
					gl_inter->tile.y = GET_GRID_Z_FROM_WORLD_Z(gl_inter->curr_pos.vz);
					}

				// error correction (for skipping tiles)
				if	(
					(gl_inter->tile.x == gl_inter->last_tile.x) &&
					(abs(gl_inter->tile.y - gl_inter->last_tile.y) > 1)
					)
					{
					gl_inter->tile.y = (gl_inter->tile.y + gl_inter->last_tile.y)>>1;
					break;
					}

				if	(
					(gl_inter->tile.y == gl_inter->last_tile.y) &&
					(abs(gl_inter->tile.x - gl_inter->last_tile.x) > 1)
					)
					{
					gl_inter->tile.x = (gl_inter->tile.x + gl_inter->last_tile.x)>>1;
					break;
					}

				// check tile in between diagonal?
				if (gl_inter->tile.x != gl_inter->last_tile.x &&
					gl_inter->tile.y != gl_inter->last_tile.y)
					{
					D.vx = gl_inter->step_vec.vx >> 8;
					D.vy = gl_inter->step_vec.vy >> 8;
					D.vz = gl_inter->step_vec.vz >> 8;
					
					if (Does2DLineIntersectGridTile(&gl_inter->curr_pos, &D, gl_inter->tile.x, gl_inter->last_tile.y))
						{
						// reset curr pos
						gl_inter->curr_pos.vx -= (gl_inter->step_vec.vx >>12);
						gl_inter->curr_pos.vy -= (gl_inter->step_vec.vy >>12);
						gl_inter->curr_pos.vz -= (gl_inter->step_vec.vz >>12);

						// get new in-between tile
						gl_inter->tile.y		= gl_inter->last_tile.y;				

						// store last tile
						gl_inter->last_tile.x	= gl_inter->tile.x;
						break;
						}
					else 
					if (Does2DLineIntersectGridTile(&gl_inter->curr_pos, &D, gl_inter->last_tile.x, gl_inter->tile.y))
						{
						// reset curr pos
						gl_inter->curr_pos.vx -= (gl_inter->step_vec.vx >>12);
   						gl_inter->curr_pos.vy -= (gl_inter->step_vec.vy >>12);
						gl_inter->curr_pos.vz -= (gl_inter->step_vec.vz >>12);

						// get new in-between tile
						gl_inter->tile.x		= gl_inter->last_tile.x;

						// store last tile
						gl_inter->last_tile.y	= gl_inter->tile.y;
						break;
						}
					}
			  
			  	// increase step count 
			  	gl_inter->curr_step++;

				// reached end?
				if (gl_inter->curr_step >= gl_inter->num_steps)
					{
					// check end tile
					if	(
						(gl_inter->tile.x == gl_inter->end_tile.x) &&
						(gl_inter->tile.y == gl_inter->end_tile.y)
						)
						{
						// if end tile is the same as this 
						gl_inter->mode = LI_MODE_DONE;
						break;
						}
					else
						{
						gl_inter->mode = LI_MODE_END;
						break;
						}
					}

				} while (gl_inter->tile.x == gl_inter->last_tile.x &&
						 gl_inter->tile.y == gl_inter->last_tile.y);
			break;

		//----------------------------------------------------------------------
		case LI_MODE_DONE:
			MR_ASSERTMSG(FALSE, "there are no more tiles - quit getting them!\n");
			break;
	}
	return gl_inter->tile;
}

/******************************************************************************
*%%%% Does2DLineIntersectGridTile
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	Does2DLineIntersectGridTile(
*								MR_SVEC*	start, 
*								MR_SVEC*	direction, 
*								MR_SHORT	tilex, 
*								MR_SHORT	tilez)	
*
*	FUNCTION:	Checks to see if infinite line intersects given grid tile.
*
*	INPUTS		start		- start vec
*				direction	- direction vec
*				tilex		- tilex
*				tilez		- tilez
*
*	RESULT		TRUE if intersection
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	Martin Kift		Created 
*
*%%%**************************************************************************/

MR_BOOL Does2DLineIntersectGridTile(	MR_SVEC*	start, 
										MR_SVEC*	direction, 
										MR_SHORT	tilex, 
										MR_SHORT	tilez)
{
	MR_SVEC		O, D;
	MR_SHORT	xl, xr, xi, zt, zb, zi;
	MR_LONG		K;

	MR_SET_SVEC(&O,	start->vx, 0, start->vz);
	MR_SET_SVEC(&D,	direction->vx, 0, direction->vz);
	VectorNormalSS(&D, &D);	

	// set borders of grid tile
	xl = (tilex 	<< 8) + Grid_base_x;
	xr = ((tilex+1) << 8) + Grid_base_x;

	zb = (tilez 	<< 8) + Grid_base_z;
	zt = ((tilez+1)	<< 8) + Grid_base_z;

	// check xl
	if (D.vx)
	{
		K = ((xl - O.vx)<<12) / D.vx;
		zi = O.vz + ((D.vz * K)>>12);
		if (zi >= zb && zi <= zt) 
			return TRUE;

		// check xr
		K = ((xr - O.vx)<<12) / D.vx;
		zi = O.vz + ((D.vz * K)>>12);
		if (zi >= zb && zi <= zt) 
			return TRUE;
	}

	// check zb
	if (D.vz)
		{
		K = ((zb - O.vz)<<12) / D.vz;
		xi = O.vx + ((D.vx * K)>>12);
		if	(
			(xi >= xl) && 
			(xi <= xr) 
			)
			{
			return TRUE;
			}

		// check zt
		K = ((zt - O.vz)<<12) / D.vz;
		xi = O.vx + ((D.vx * K)>>12);
		if	(
			(xi >= xl) && 
			(xi <= xr) 
			)
			{
			return TRUE;
			}
		}
	
	return FALSE;
}

/******************************************************************************
*%%%% GetGridStackHeight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	y =	GetGridStackHeight(
*							GRID_STACK*	grid_stack)
*
*	FUNCTION	Calculate the average y of all grid squares vertices inside
*				requested grid_stack
*
*	INPUTS		grid_stack	-	ptr to GRID_SQUARE
*
*	RESULT		y			-	height
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	GetGridStackHeight(GRID_STACK*	grid_stack)
{
	return (grid_stack->gs_average_ht << 6);
}

