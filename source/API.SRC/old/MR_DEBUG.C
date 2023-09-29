/******************************************************************************
*%%%% mr_debug.c
*------------------------------------------------------------------------------
*
*	Debugging routines (pretty much for PlayStation only at the moment)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	09.10.96	Tim Closs		MRGrabScreen 	becomes MRDebugGrabScreen
*								MRShowVram		becomes MRDebugShowVram
*								Functions and data added for debug display,
*								enclosed by #ifdef MR_DEBUG_DISPLAY
*	01.11.96	Tim Closs		MRDebug_2D_scale now stored >> 8, to increase
*								accuracy in 2D functions
*								Added MRDebugPlot2DWorldSplineMatrix()
*	21.01.97	Tim Closs		MRDebugPlotCollPrim() - fixed bug if cp_matrix exists
*	28.01.97	Tim Closs		MRDebugPlotCollPrim() - swapped inputs
*								MRDebugPlotBoundingBox() - added colour input
*								Added:
*								MRDebugPlotHiliteVertices()
*								MRDebugPlotHilitePrims()
*	31.01.97	Tim Closs		Added:
*								MRDebugPlot2DWorldBspline()
*								MRDebugPlot2DWorldSplineBezierArray()
*								MRDebugPlot2DWorldBsplineControlPoints()
*								MRDebugPlot2DWorldBezierControlPoints()
*								MRDebugPlot2DWorldSplineBezierArrayControlPoints()
*	05.02.97	Tim Closs		MRDebugPlotCollPrim() now does not use
*								MRViewtrans or MRViewtrans_ptr, and fixed
*								cp_offset bug
*	12.02.97	Tim Closs		MRDebugPlotCollPrim() now takes matrix and offset, not frame, inputs
*								MRDebugPlotBoundingBox() takes MR_BBOX* input, not MR_SVEC*
*	13.02.97	Dean Ashton		Added MR_ASSERT for MRVp_ptr everywhere
*	16.04.97	Tim Closs		Added MRDebugPlotWorldPolyF4().
*	18.04.97	Dean Ashton		Added MRDebugPlot2DWorldPolyF4();
*
*%%%**************************************************************************/

#include	"mr_all.h"


// Notes:
//
// In all these functions, primitives are added to the viewport specified in MRVp_ptr
// Colours are 24 bit, BbGgRr
// All tiles are added into the viewport OT at MRDebug_tile_otz (initially set to 0)
// All lines are added into the viewport OT at MRDebug_line_otz (initially set to 0)


MR_USHORT	MRRendered_meshes;
MR_USHORT	MRListed_meshes;


#ifdef MR_DEBUG_DISPLAY
TILE		MRDebug_tiles[2][MR_DEBUG_MAX_TILES];
LINE_F2		MRDebug_lines[2][MR_DEBUG_MAX_LINES];
TILE*		MRDebug_tile_ptr;
LINE_F2*	MRDebug_line_ptr;

MR_USHORT	MRDebug_tile_otz;
MR_USHORT	MRDebug_line_otz;

MR_LONG		MRDebug_2D_scale;
#endif


/******************************************************************************
*%%%% MRDebugShowVram
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugShowVram(MR_VOID)
*
*	FUNCTION	Using the currently defined DISPENV settings, show the VRAM
*				area, and allow the joypad to move around it.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugShowVram(MR_VOID)
{
	MR_BOOL	debugging_vram = TRUE;
	MR_SHORT	debug_x;
	MR_SHORT	debug_y;
	DISPENV	backup_dispenv;
	DISPENV	debug_dispenv;

	// Wait for drawing to finish, and make sure the screen is on.
	DrawSync(0);
	SetDispMask(1);

	
	// Get the current display environment into our work DISPENV, and a 
	// backup so we can set it again later.

	GetDispEnv(&backup_dispenv);
	GetDispEnv(&debug_dispenv);

	debug_x = debug_dispenv.disp.x;
	debug_y = debug_dispenv.disp.y;
	

	// Let the user move around...
	while (debugging_vram)
		{
		VSync(0);
		debug_dispenv.disp.x = debug_x;
		debug_dispenv.disp.y = debug_y;
		PutDispEnv(&debug_dispenv);
		MRReadInput();

		// Move display area left
		if (MR_CHECK_PAD_HELD(0,MRIP_LEFT))
			{
			debug_x -= MR_DEBUG_MOVE_SPEED;
			if (debug_x < 0) debug_x = 0;
			}

		// Move display area right
		if (MR_CHECK_PAD_HELD(0,MRIP_RIGHT))
			{
			debug_x += MR_DEBUG_MOVE_SPEED;
			if (debug_x > (1024-debug_dispenv.disp.w))
				debug_x = (1024-debug_dispenv.disp.w);
			}

		// Move display area up
		if (MR_CHECK_PAD_HELD(0,MRIP_UP))
			{
			debug_y -= MR_DEBUG_MOVE_SPEED;
			if (debug_y < 0) debug_y = 0;
			}
				
		// Move display area down
		if (MR_CHECK_PAD_HELD(0,MRIP_DOWN))
			{
			debug_y += MR_DEBUG_MOVE_SPEED;
			if (debug_y > (512-debug_dispenv.disp.h))
				debug_y = (512-debug_dispenv.disp.h);
			}

		// Quit MRDebugShowVram()
		if (MR_CHECK_PAD_RELEASED(0,MRIP_START))
			debugging_vram = FALSE;
		}
		
	// Restore DISPENV back to its former glory.
 	PutDispEnv(&backup_dispenv);
	VSync(0);
}


/******************************************************************************
*%%%% MRDebugGrabScreen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugGrabScreen(MR_VOID)
*
*	FUNCTION	Takes the currently defined screen, and saves it to a .TIM
*				file, normally in the users RAM/Temporary directory.
*
*	NOTES		This routine needs available RAM to dump the screen into. If
*				it is not available, the internal MRAllocMem() call will 
*				cause an assertion failure.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugGrabScreen(MR_VOID)
{
	DISPENV		 gs_dispenv;						// Copy of current dispenv
	MR_ULONG	 gs_dispsize;						// Size of display (in bytes)
	MR_GRAB_TIM	*gs_screen;							// Pointer to MR_GRAB_TIM structure

	// Wait for drawing to complete, then take a copy of the current DISPENV
	DrawSync(0);
	GetDispEnv(&gs_dispenv);
		
	// Get size of image (in bytes)
	gs_dispsize = (gs_dispenv.disp.w*gs_dispenv.disp.h*sizeof(MR_USHORT));

	// Allocate memory for the MR_GRAB_TIM structure and a copy of the currently displayed screen
	gs_screen = (MR_GRAB_TIM *)MRAllocMem(sizeof(MR_GRAB_TIM)+gs_dispsize, "GRABSCRN");

	gs_screen->st_id	= 0x00000010;					   				// TIM Format ID
	gs_screen->st_flag	= 0x00000002;					   				// 16-bit colour image
	gs_screen->st_bnum	= (gs_dispsize)+0x0c;			   				// Size of image + Pixel structure
	gs_screen->st_dxy	= 0x00000000;					   				// Image at (0,0)
	gs_screen->st_hw 	= (gs_dispenv.disp.h<<16)|(gs_dispenv.disp.w);	// Image size

	StoreImage(&gs_dispenv.disp, (MR_LONG*)gs_screen->st_data);
	DrawSync(0);
	
	MRSaveFile(MR_FILE_RAMDRIVE "\\SCREEN.TIM", (MR_ULONG*)gs_screen, sizeof(MR_GRAB_TIM)+gs_dispsize);
	
	MRFreeMem(gs_screen);
}


/******************************************************************************
*%%%% MRDebugInitialiseDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugInitialiseDisplay(MR_VOID)
*
*	FUNCTION	Set up tiles and lines for debug display
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugInitialiseDisplay(MR_VOID)
{
#ifdef MR_DEBUG_DISPLAY
	MR_USHORT	i, j;


	for (j = 0; j < 2; j++)
		{
		for (i = 0; i < MR_DEBUG_MAX_TILES; i++)
			{
			setTile(&MRDebug_tiles[j][i]);
			setWH(&MRDebug_tiles[j][i], 1, 1);
			}
		}
	for (j = 0; j < 2; j++)
		{
		for (i = 0; i < MR_DEBUG_MAX_LINES; i++)
			{
			setLineF2(&MRDebug_lines[j][i]);
			}
		}

	MRDebug_tile_otz = 0;
	MRDebug_line_otz = 1;
#endif
}


/******************************************************************************
*%%%% MRDebugStartDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugStartDisplay(MR_VOID)
*
*	FUNCTION	Set up tile and line ptrs for this frame
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugStartDisplay(MR_VOID)
{
#ifdef MR_DEBUG_DISPLAY
	MRDebug_tile_ptr = &MRDebug_tiles[MRFrame_index][0];
	MRDebug_line_ptr = &MRDebug_lines[MRFrame_index][0];
#endif
}


/******************************************************************************
*%%%% MRDebugPlotCollPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotCollPrim(
*						MR_COLLPRIM*	coll,
*						MR_MAT*			matrix,
*						MR_SVEC*		offset,
*						MR_ULONG		colour)
*
*	FUNCTION	Plots a collision prim from lines
*
*	INPUTS		coll		- 	ptr to MR_COLLPRIM
*				matrix		-	LW transform (or NULL if using collprim frame)
*				colour		- 	line colour
*
*	NOTES		This function must NOT change MRViewtrans or MRViewtrans_ptr,
*				because it is called from ..DisplayMeshInstance()
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*	21.01.97	Tim Closs		Fixed bug if cp_matrix exists
*	05.02.97	Tim Closs		Now does not use MRViewtrans or MRViewtrans_ptr
*								Fixed cp_offset bug
*	12.02.97	Tim Closs		Now takes matrix and offset, not frame, inputs
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotCollPrim(MR_COLLPRIM*	coll,
							MR_MAT*			matrix,
							MR_SVEC*		offset,
							MR_ULONG		colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_MAT*		lw_ptr;
	MR_MAT		worldtrans;
	MR_SVEC		points[4], dm_svec;
	MR_VEC		dm_vec;
	MR_SHORT	xlen = 0, ylen = 0, zlen = 0;
	MR_ULONG	rgbcode;
	MR_MAT		viewtrans;


	MR_ASSERT(coll);
	MR_ASSERT(MRDebug_line_ptr + 12 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	rgbcode = colour + MR_PRIM_GPU_CODE_LF2;

	if (matrix == NULL)
		{
		if (coll->cp_flags & MR_COLL_STATIC)
			lw_ptr = (MR_MAT*)coll->cp_frame;
		else
			lw_ptr = &coll->cp_frame->fr_lw_transform;
		}
	else
		lw_ptr = matrix;

	if (offset)
		{
		MR_ADD_SVEC_ABC(&coll->cp_offset, offset, &dm_svec);
		MRApplyMatrix(lw_ptr, &dm_svec, &dm_vec);
		}
	else
		MRApplyMatrix(lw_ptr, &coll->cp_offset, &dm_vec);

	if (coll->cp_matrix)
		{
		MRMulMatrixABC(lw_ptr, coll->cp_matrix, &worldtrans);
		MR_COPY_VEC(worldtrans.t, lw_ptr->t);  
		lw_ptr = &worldtrans;
		}
	
	MRMulMatrixABC(&MRVp_ptr->vp_render_matrix, lw_ptr, &viewtrans);
	dm_svec.vx = (MR_SHORT)lw_ptr->t[0] + (MR_SHORT)dm_vec.vx - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[0];
	dm_svec.vy = (MR_SHORT)lw_ptr->t[1] + (MR_SHORT)dm_vec.vy - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[1];
	dm_svec.vz = (MR_SHORT)lw_ptr->t[2] + (MR_SHORT)dm_vec.vz - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[2];
	MRApplyMatrix(&MRVp_ptr->vp_render_matrix, &dm_svec, (MR_VEC*)viewtrans.t);
	gte_SetRotMatrix(&viewtrans);
	gte_SetTransMatrix(&viewtrans);

	switch(coll->cp_type)
		{
		case MR_COLLPRIM_SPHERE:
			xlen = MR_SQRT(coll->cp_radius2);
			ylen = xlen;
			zlen = xlen;
			break;

		case MR_COLLPRIM_CUBOID:
			xlen = coll->cp_xlen;
			ylen = coll->cp_ylen;
			zlen = coll->cp_zlen;
			break;

		case MR_COLLPRIM_CYLINDER_X:
			ylen = MR_SQRT(coll->cp_radius2);
			zlen = ylen;
			xlen = coll->cp_xlen;
			break;

		case MR_COLLPRIM_CYLINDER_Y:
			xlen = MR_SQRT(coll->cp_radius2);
			zlen = xlen;
			ylen = coll->cp_ylen;
			break;

		case MR_COLLPRIM_CYLINDER_Z:
			xlen = MR_SQRT(coll->cp_radius2);
			ylen = xlen;
			zlen = coll->cp_zlen;
			break;
		}

	points[0].vx = -xlen;
	points[0].vy = -ylen;
	points[0].vz =  zlen;
	points[1].vx =  xlen;
	points[1].vy = -ylen;
	points[1].vz =  zlen;
	points[2].vx =  xlen;
	points[2].vy = -ylen;
	points[2].vz = -zlen;
	points[3].vx = -xlen;
	points[3].vy = -ylen;
	points[3].vz = -zlen;

	gte_ldv3(&points[0], &points[1], &points[2]);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&(MRDebug_line_ptr + 0)->x0);
	gte_stsxy1((MR_LONG*)&(MRDebug_line_ptr + 1)->x0);
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 2)->x0);
	gte_ldv0(&points[3]);
	gte_rtps();
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 0)->x1, (MRDebug_line_ptr + 1)->x0);
	MR_COPY32((MRDebug_line_ptr + 1)->x1, (MRDebug_line_ptr + 2)->x0);
	MR_COPY32((MRDebug_line_ptr + 2)->x1, (MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 3)->x1, (MRDebug_line_ptr + 0)->x0);

	points[0].vx = -xlen;
	points[0].vy =  ylen;
	points[0].vz =  zlen;
	points[1].vx =  xlen;
	points[1].vy =  ylen;
	points[1].vz =  zlen;
	points[2].vx =  xlen;
	points[2].vy =  ylen;
	points[2].vz = -zlen;
	points[3].vx = -xlen;
	points[3].vy =  ylen;
	points[3].vz = -zlen;

	gte_ldv3(&points[0], &points[1], &points[2]);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&(MRDebug_line_ptr + 4)->x0);
	gte_stsxy1((MR_LONG*)&(MRDebug_line_ptr + 5)->x0);
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 6)->x0);
	gte_ldv0(&points[3]);
	gte_rtps();
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 7)->x0);
	MR_COPY32((MRDebug_line_ptr + 4)->x1, (MRDebug_line_ptr + 5)->x0);
	MR_COPY32((MRDebug_line_ptr + 5)->x1, (MRDebug_line_ptr + 6)->x0);
	MR_COPY32((MRDebug_line_ptr + 6)->x1, (MRDebug_line_ptr + 7)->x0);
	MR_COPY32((MRDebug_line_ptr + 7)->x1, (MRDebug_line_ptr + 4)->x0);

	MR_COPY32((MRDebug_line_ptr + 8)->x0, (MRDebug_line_ptr + 0)->x0);
	MR_COPY32((MRDebug_line_ptr + 9)->x0, (MRDebug_line_ptr + 1)->x0);
	MR_COPY32((MRDebug_line_ptr +10)->x0, (MRDebug_line_ptr + 2)->x0);
	MR_COPY32((MRDebug_line_ptr +11)->x0, (MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 8)->x1, (MRDebug_line_ptr + 4)->x0);
	MR_COPY32((MRDebug_line_ptr + 9)->x1, (MRDebug_line_ptr + 5)->x0);
	MR_COPY32((MRDebug_line_ptr +10)->x1, (MRDebug_line_ptr + 6)->x0);
	MR_COPY32((MRDebug_line_ptr +11)->x1, (MRDebug_line_ptr + 7)->x0);

	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldPoint(
*						MR_SVEC*	point,
*						MR_ULONG	colour,
*						MR_USHORT	width)
*
*	FUNCTION	Plots a point in the world
*
*	INPUTS		point		-	point in world
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldPoint(	MR_SVEC*	point,
								MR_ULONG	colour,
								MR_USHORT	width)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC		dm_svec;

	MR_ASSERT(point);
	MR_ASSERT(MRDebug_tile_ptr + 1 <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	dm_svec.vx = point->vx - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[0];
	dm_svec.vy = point->vy - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[1];
	dm_svec.vz = point->vz - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[2];

	MRApplyMatrix(&MRVp_ptr->vp_render_matrix, &dm_svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetRotMatrix(&MRVp_ptr->vp_render_matrix);
	gte_SetTransMatrix(MRViewtrans_ptr);

	gte_ldv0(&MRNull_svec);
	gte_rtps();
	gte_stsxy((MR_LONG*)&MRDebug_tile_ptr->x0);

	MRDebug_tile_ptr->x0 -= (width >> 1);
	MRDebug_tile_ptr->y0 -= (width >> 1);
	MRDebug_tile_ptr->w = width;
	MRDebug_tile_ptr->h = width;
	
	*(MR_LONG*)&MRDebug_tile_ptr->r0 = MR_PRIM_GPU_CODE_TILE + colour;
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
	MRDebug_tile_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldPointVEC
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldPointVEC(
*						MR_VEC*		point,
*						MR_ULONG	colour,
*						MR_USHORT	width)
*
*	FUNCTION	Plots a point in the world (point specified as MR_VEC)
*
*	INPUTS		point		-	point in world
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldPointVEC(	MR_VEC*		point,
									MR_ULONG	colour,
									MR_USHORT	width)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec;

	MR_ASSERT(point);
	MR_ASSERT(MRDebug_tile_ptr + 1 <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);

	MR_SVEC_EQUALS_VEC(&svec, point);
	MRDebugPlotWorldPoint(&svec, colour, width);
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldSplineHermite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldSplineHermite(
*						MR_SPLINE_HERMITE*	spline,
*						MR_USHORT			lines,
*						MR_ULONG			colour)
*							
*	FUNCTION	Plot a hermite spline comprised of several lines
*
*	INPUTS		spline		-	ptr to spline
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldSplineHermite(	MR_SPLINE_HERMITE*	spline,
										MR_USHORT			lines,
										MR_ULONG 			colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SPLINE_MATRIX	coeff;

	MR_ASSERT(spline);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	MRCalculateSplineHermiteMatrix(spline, &coeff);
	MRDebugPlotWorldSplineMatrix(&coeff, lines, colour);
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldSplineBezier
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldSplineBezier(
*						MR_SPLINE_BEZIER*	spline,
*						MR_USHORT		 	lines,
*						MR_ULONG		 	colour)
*							
*	FUNCTION	Plot a bezier spline comprised of several lines
*
*	INPUTS		spline		-	ptr to spline
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldSplineBezier(	MR_SPLINE_BEZIER*	spline,
										MR_USHORT		 	lines,
										MR_ULONG		 	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SPLINE_MATRIX	coeff;


	MR_ASSERT(spline);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	MRCalculateSplineBezierMatrix(spline, &coeff);
	MRDebugPlotWorldSplineMatrix(&coeff, lines, colour);
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldBspline
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldBspline(
*						MR_SPLINE_BEZIER*	spline,
*						MR_USHORT		 	lines,
*						MR_ULONG		 	colour)
*							
*	FUNCTION	Plot a (single piece of) bspline comprised of several lines
*
*	INPUTS		spline		-	ptr to spline
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldBspline(MR_SPLINE_BEZIER*	spline,
								MR_USHORT		 	lines,
								MR_ULONG		 	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SPLINE_MATRIX	coeff;


	MR_ASSERT(spline);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	MRCalculateBsplineMatrix(spline, &coeff);
	MRDebugPlotWorldSplineMatrix(&coeff, lines, colour);
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldSplineMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldSplineMatrix(
*						MR_SPLINE_MATRIX*		matrix,
*						MR_USHORT				lines,
*						MR_ULONG				colour)
*							
*	FUNCTION	Plot a spline comprised of several lines
*
*	INPUTS		matrix		-	ptr to spline coefficient matrix
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldSplineMatrix(	MR_SPLINE_MATRIX*	matrix,
										MR_USHORT		 	lines,
										MR_ULONG		 	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ULONG	t, dt;
	MR_SVEC		svec;


	MR_ASSERT(matrix);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	t 	= 0;
	dt	= MR_SPLINE_PARAM_ONE / lines;

	svec.vx = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[2];
	MRApplyMatrix(&MRVp_ptr->vp_render_matrix, &svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetRotMatrix(&MRVp_ptr->vp_render_matrix);
	gte_SetTransMatrix(MRViewtrans_ptr);

	MRCalculateSplinePoint(matrix, t, &svec);
	gte_ldv0(&svec);
	gte_rtps();
	gte_stsxy((MR_LONG*)&MRDebug_line_ptr->x0);

	t += dt;
	while(t < MR_SPLINE_PARAM_ONE)
		{
		MRCalculateSplinePoint(matrix, t, &svec);
		gte_ldv0(&svec);
		gte_rtps();
		gte_stsxy((MR_LONG*)&MRDebug_line_ptr->x1);
		MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
		MRDebug_line_ptr++;
		gte_stsxy((MR_LONG*)&MRDebug_line_ptr->x0);
		t += dt;
		}

	t = MR_SPLINE_PARAM_ONE;
	MRCalculateSplinePoint(matrix, t, &svec);
	gte_ldv0(&svec);
	gte_rtps();
	gte_stsxy((MR_LONG*)&MRDebug_line_ptr->x1);
	MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlotBoundingBox
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotBoundingBox(
*						MR_BBOX*	bbox,
*						MR_ULONG	colour)
*
*	FUNCTION	Display a bounding box as a cuboid
*
*	INPUTS		bbox		-	ptr to 8 vertices in world
*				colour		-	line colour
*
*	NOTES		We assume RotMatrix and TransMatrix are already set up (this
*				function is usually called from within mesh display code, just
*				after bounding box clipping has been performed)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*	28.01.97	Tim Closs		Changed to accept colour input
*	12.02.97	Tim Closs		Now takes MR_BBOX* input, not MR_SVEC*
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotBoundingBox(	MR_BBOX*	bbox,
								MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ULONG	rgbcode;
	MR_SVEC*	vert_ptr;


	MR_ASSERT(bbox);
	MR_ASSERT(MRDebug_line_ptr + 12 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	rgbcode		= colour + MR_PRIM_GPU_CODE_LF2;
	vert_ptr	= bbox->mb_verts;
	
	gte_ldv3(vert_ptr + 1, vert_ptr + 0, vert_ptr + 2);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&(MRDebug_line_ptr + 0)->x0);
	gte_stsxy1((MR_LONG*)&(MRDebug_line_ptr + 1)->x0);
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 2)->x0);
	gte_ldv0(vert_ptr + 3);
	gte_rtps();
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 0)->x1, (MRDebug_line_ptr + 1)->x0);
	MR_COPY32((MRDebug_line_ptr + 1)->x1, (MRDebug_line_ptr + 2)->x0);
	MR_COPY32((MRDebug_line_ptr + 2)->x1, (MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 3)->x1, (MRDebug_line_ptr + 0)->x0);

	vert_ptr += 4;
	gte_ldv3(vert_ptr + 1, vert_ptr + 0, vert_ptr + 2);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&(MRDebug_line_ptr + 4)->x0);
	gte_stsxy1((MR_LONG*)&(MRDebug_line_ptr + 5)->x0);
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 6)->x0);
	gte_ldv0(vert_ptr + 3);
	gte_rtps();
	gte_stsxy2((MR_LONG*)&(MRDebug_line_ptr + 7)->x0);
	MR_COPY32((MRDebug_line_ptr + 4)->x1, (MRDebug_line_ptr + 5)->x0);
	MR_COPY32((MRDebug_line_ptr + 5)->x1, (MRDebug_line_ptr + 6)->x0);
	MR_COPY32((MRDebug_line_ptr + 6)->x1, (MRDebug_line_ptr + 7)->x0);
	MR_COPY32((MRDebug_line_ptr + 7)->x1, (MRDebug_line_ptr + 4)->x0);

	MR_COPY32((MRDebug_line_ptr + 8)->x0, (MRDebug_line_ptr + 0)->x0);
	MR_COPY32((MRDebug_line_ptr + 9)->x0, (MRDebug_line_ptr + 1)->x0);
	MR_COPY32((MRDebug_line_ptr +10)->x0, (MRDebug_line_ptr + 2)->x0);
	MR_COPY32((MRDebug_line_ptr +11)->x0, (MRDebug_line_ptr + 3)->x0);
	MR_COPY32((MRDebug_line_ptr + 8)->x1, (MRDebug_line_ptr + 4)->x0);
	MR_COPY32((MRDebug_line_ptr + 9)->x1, (MRDebug_line_ptr + 5)->x0);
	MR_COPY32((MRDebug_line_ptr +10)->x1, (MRDebug_line_ptr + 6)->x0);
	MR_COPY32((MRDebug_line_ptr +11)->x1, (MRDebug_line_ptr + 7)->x0);

	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
	*(MR_LONG*)&MRDebug_line_ptr->r0 = rgbcode, addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr), MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldLine
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldLine(
*						MR_SVEC*		point,
*						MR_SVEC*		vector,
*						MR_ULONG		colour)
*
*	FUNCTION	Plots a line in the world
*
*	INPUTS		point		-	start point in world
*				vector		-	line vector in world
*				colour		-	tile colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldLine(	MR_SVEC*	point,
								MR_SVEC*	vector,
								MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec0;
	MR_SVEC	svec1;


	MR_ASSERT(point);
	MR_ASSERT(vector);
	MR_ASSERT(MRDebug_line_ptr + 1 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	svec0.vx = point->vx - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[0];
	svec0.vy = point->vy - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[1];
	svec0.vz = point->vz - (MR_SHORT)MRVp_ptr->vp_render_matrix.t[2];

	MR_ADD_SVEC_ABC(&svec0, vector, &svec1);
	gte_SetRotMatrix(&MRVp_ptr->vp_render_matrix);
	gte_SetTransMatrix(&MRId_matrix);

	gte_ldv0(&svec0);
	gte_ldv1(&svec1);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&MRDebug_line_ptr->x0);
	gte_stsxy1((MR_LONG*)&MRDebug_line_ptr->x1);

	*(MR_LONG*)&MRDebug_line_ptr->r0 = MR_PRIM_GPU_CODE_LF2 + colour;
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldLineVEC
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldLineVEC(
*						MR_VEC*		point,
*						MR_VEC*		vector,
*						MR_ULONG		colour)
*
*	FUNCTION	Plots a line in the world (as above, but with MR_VEC inputs)
*
*	INPUTS		point		-	start point in world
*				vector		-	line vector in world
*				colour		-	tile colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldLineVEC(MR_VEC*		point,
								MR_VEC*		vector,
								MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec0;
	MR_SVEC	svec1;


	MR_ASSERT(point);
	MR_ASSERT(vector);
	MR_ASSERT(MRDebug_line_ptr + 1 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	MR_SVEC_EQUALS_VEC(&svec0, point);
	MR_SVEC_EQUALS_VEC(&svec1, vector);

	MRDebugPlotWorldLine(&svec0, &svec1, colour);
#endif
}


/******************************************************************************
*%%%% MRDebugPlotHiliteVertices
*-----------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotHiliteVertices(
*						MR_PART*	part_ptr,
*						MR_ULONG	colour)
*
*	FUNCTION	Plot hilite vertices on a mesh
*
*	INPUTS		part_ptr	-	ptr to MR_PART which points to hilites
*				colour		-	tile colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotHiliteVertices(	MR_PART*	part_ptr,
									MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_HILITE*	hilite_ptr;
	MR_USHORT	hilites;


	MR_ASSERT(part_ptr);

	hilite_ptr	= part_ptr->mp_hilite_ptr;
	hilites		= part_ptr->mp_hilites;

	MR_ASSERT(MRDebug_tile_ptr + hilites <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	while(hilites--)
		{
		if (hilite_ptr->mh_flags & MR_HILITE_VERTEX)
			{
			gte_ldv0((MR_SVEC*)(hilite_ptr->mh_target_ptr));
			gte_rtps();

			MRDebug_tile_ptr->w 	= 1;
			MRDebug_tile_ptr->h 	= 1;
			MR_SET32(MRDebug_tile_ptr->r0, MR_PRIM_GPU_CODE_TILE + colour);

			gte_stsxy((MR_LONG*)&(MRDebug_tile_ptr + 0)->x0);

			addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
			MRDebug_tile_ptr++;
			}
		hilite_ptr++;
		}
#endif
}


/******************************************************************************
*%%%% MRDebugPlotHilitePrims
*-----------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotHilitePrims(
*						MR_MOF*			mof,
*						MR_USHORT		part,
*						MR_MESH_INST*	mesh_inst,
*						MR_ULONG		colour)
*
*	FUNCTION	Plot hilite prims on a mesh
*
*	INPUTS		mof_ptr		-	ptr to static MOF file
*				part		-	index of part within static MOF
*				mesh_inst	-	ptr to MR_MESH_INST
*				colour		-	poly colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotHilitePrims(	MR_MOF*			mof,
								MR_USHORT		part,
								MR_MESH_INST*	mesh_inst,
								MR_ULONG		colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_PART*	part_ptr;
	MR_HILITE*	hilite_ptr;
	MR_USHORT	hilites;
	MR_UBYTE*	mem;


	MR_ASSERT(mof);
	MR_ASSERT(mesh_inst);
	MR_ASSERT(part < mof->mm_extra);

	part_ptr 	= ((MR_PART*)(mof + 1)) + part;
	hilite_ptr	= part_ptr->mp_hilite_ptr;
	hilites		= part_ptr->mp_hilites;
	mem 		= ((MR_UBYTE*)mesh_inst->mi_prims[part]) + (part_ptr->mp_buff_size * MRFrame_index);

	while(hilites--)
		{
		if (hilite_ptr->mh_flags & MR_HILITE_PRIM)
			{
			MR_SET32(mem + hilite_ptr->mh_prim_ofs, ((*(mem + hilite_ptr->mh_prim_ofs)) << 24) + colour);
			}
		hilite_ptr++;
		}
#endif
}


/******************************************************************************
*%%%% MRDebugSet2DScale
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugSet2DScale(
*						MR_LONG	scale);
*
*	FUNCTION	Sets the scale for 2D debug display
*
*	INPUTS		scale		- scale
*
*	NOTES		A scale of 0x1000 means that the world -32768..32767 will fit
*				into a square centred in the viewport and reaching the top and
*				bottom of the viewport.  A scale of 0x2000 will fit a world of
*				-16384..16383 into the same screen space, etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugSet2DScale(MR_LONG	scale)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ASSERT(MRVp_ptr);
	MRDebug_2D_scale	= (MRVp_ptr->vp_disp_inf.h * scale) >> 9;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldPoint(
*						MR_SVEC*	point,
*						MR_ULONG	colour,
*						MR_USHORT	width);
*
*	FUNCTION	Plots a 2D point
*
*	INPUTS		point		-	point in world
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldPoint(MR_SVEC*	point,
								MR_ULONG	colour,
								MR_USHORT	width)
{
#ifdef MR_DEBUG_DISPLAY


	MR_ASSERT(point);
	MR_ASSERT(MRDebug_tile_ptr + 1 <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	MRDebug_tile_ptr->x0 =  (((point->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x - (width >> 1);
	MRDebug_tile_ptr->y0 = -(((point->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y - (width >> 1);

	MRDebug_tile_ptr->w	= width;
	MRDebug_tile_ptr->h	= width;
	
	*(MR_LONG*)&MRDebug_tile_ptr->r0 = MR_PRIM_GPU_CODE_TILE + colour;
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
	MRDebug_tile_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldLine
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldLine(
*						MR_SVEC*	point,
*						MR_SVEC*	vector,
*						MR_ULONG	colour);
*
*	FUNCTION	Plots a 2D line
*
*	INPUTS		point		-	line start point in world
*				point		-	line vector
*				colour		-	line colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldLine(	MR_SVEC*	point,
						   		MR_SVEC*	vector,
						   		MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec;

	
	MR_ASSERT(point);
	MR_ASSERT(vector);
	MR_ASSERT(MRDebug_line_ptr + 1 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	MRDebug_line_ptr->x0 =  (((point->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y0 = -(((point->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;

	MR_ADD_SVEC_ABC(point, vector, &svec);
	MRDebug_line_ptr->x1 =  (((svec.vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y1 = -(((svec.vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;

	*(MR_LONG*)&MRDebug_line_ptr->r0 = MR_PRIM_GPU_CODE_LF2 + colour;
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldAxes
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldAxes(
*						MR_ULONG	colour);
*
*	FUNCTION	Plot the X and Y axes from -32768..32767
*
*	INPUTS		colour	-	axes colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldAxes(MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec0;	
	MR_SVEC	svec1;	


	MR_ASSERT(MRDebug_line_ptr + 4 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	MR_SET_SVEC(&svec0, -32768, 0, 0);
	MR_SET_SVEC(&svec1,  32767, 0, 0);
	MRDebugPlot2DWorldLine(&svec0, &svec1, colour);
	MR_SET_SVEC(&svec0,      0, 0, 0);
	MR_SET_SVEC(&svec1,  32767, 0, 0);
	MRDebugPlot2DWorldLine(&svec0, &svec1, colour);

	MR_SET_SVEC(&svec0, 0, -32767, 0);
	MR_SET_SVEC(&svec1, 0,  32767, 0);
	MRDebugPlot2DWorldLine(&svec0, &svec1, colour);
	MR_SET_SVEC(&svec0, 0,      0, 0);
	MR_SET_SVEC(&svec1, 0,  32767, 0);
	MRDebugPlot2DWorldLine(&svec0, &svec1, colour);
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldCircle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldCircle(
*						MR_ULONG	colour);
*
*	FUNCTION	Plot the circle in the XY plane of radius 32768
*
*	INPUTS		colour	-	axes colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldCircle(MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC		svec0;	
	MR_SVEC		svec1;	
	MR_USHORT	s;


	MR_ASSERT(MRDebug_line_ptr + 64 <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);

	for (s = 0; s < 64; s++)
		{
		svec0.vx = MIN(0x7fff, (rsin((s + 0) << 6) << 3));
		svec0.vy = MIN(0x7fff, (rcos((s + 0) << 6) << 3));
		svec1.vx = MIN(0x7fff, (rsin((s + 1) << 6) << 3));
		svec1.vy = MIN(0x7fff, (rcos((s + 1) << 6) << 3));

		svec1.vx -= svec0.vx;
		svec1.vy -= svec0.vy;
		MRDebugPlot2DWorldLine(&svec0, &svec1, colour);
		}	
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldSplineMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldSplineMatrix(
*						MR_SPLINE_MATRIX*	matrix,
*						MR_USHORT			lines,
*						MR_ULONG		 	colour)
*							
*	FUNCTION	Plot a spline comprised of several lines (2D XY plane)
*
*	INPUTS		matrix		-	ptr to spline coefficient matrix
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldSplineMatrix(	MR_SPLINE_MATRIX*	matrix,
										MR_USHORT		 	lines,
										MR_ULONG		 	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ULONG	t, dt;
	MR_SVEC		svec;


	MR_ASSERT(matrix);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	t 	= 0;
	dt	= MR_SPLINE_PARAM_ONE / lines;

	MRCalculateSplinePoint(matrix, t, &svec);
	MRDebug_line_ptr->x0 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y0 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;

	t += dt;
	while(t < MR_SPLINE_PARAM_ONE)
		{
		MRCalculateSplinePoint(matrix, t, &svec);
		MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
		MRDebug_line_ptr++;
		MRDebug_line_ptr->x0 =  (((svec.vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y0 = -(((svec.vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		t += dt;
		}

	t = MR_SPLINE_PARAM_ONE;
	MRCalculateSplinePoint(matrix, t, &svec);
	MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldBspline
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldBspline(
*						MR_BSPLINE*	bspline,
*						MR_USHORT	lines,
*						MR_ULONG	colour)
*							
*	FUNCTION	Plots a spline comprised of several lines (2D XY plane)
*
*	INPUTS		bspline		-	ptr to bspline
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldBspline(	MR_BSPLINE*	bspline,
									MR_USHORT	lines,
									MR_ULONG	colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ULONG	t, dt;
	MR_SVEC		svec;


	MR_ASSERT(bspline);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	t 	= 0;
	dt	= (bspline->bs_numsegments << MR_SPLINE_PARAM_SHIFT) / lines;

	MRCalculateBsplinePointDirectly((MR_SPLINE_BEZIER*)bspline->bs_points, 0, &svec);
	MRDebug_line_ptr->x0 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y0 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;

	t += dt;
	while((t >> MR_SPLINE_PARAM_SHIFT) < bspline->bs_numsegments)
		{
		MRCalculateBsplinePointDirectly(	(MR_SPLINE_BEZIER*)(bspline->bs_points + (t >> MR_SPLINE_PARAM_SHIFT)),
											t & (MR_SPLINE_PARAM_ONE - 1),
											&svec);

		MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
		MRDebug_line_ptr++;
		MRDebug_line_ptr->x0 =  (((svec.vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y0 = -(((svec.vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		t += dt;
		}

	MRCalculateBsplinePointDirectly(	(MR_SPLINE_BEZIER*)(bspline->bs_points + bspline->bs_numsegments - 1),
										MR_SPLINE_PARAM_ONE,
										&svec);

	MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldSplineBezierArray
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldSplineBezierArray(
*						MR_SPLINE_BEZIER_ARRAY*	array,
*						MR_USHORT				lines,
*						MR_ULONG				colour)
*							
*	FUNCTION	Plots a spline comprised of several lines (2D XY plane)
*
*	INPUTS		array		-	ptr to array
*				lines		-	number of lines to use
*				colour		-	colour
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldSplineBezierArray(MR_SPLINE_BEZIER_ARRAY*	array,
											MR_USHORT				lines,
											MR_ULONG				colour)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ULONG	t, dt;
	MR_SVEC		svec;


	MR_ASSERT(array);
	MR_ASSERT(MRDebug_line_ptr + lines <= &MRDebug_lines[MRFrame_index][MR_DEBUG_MAX_LINES]);
	MR_ASSERT(MRVp_ptr);

	t 	= 0;
	dt	= (array->sb_numbeziers << MR_SPLINE_PARAM_SHIFT) / lines;

	MRCalculateSplineBezierArrayPoint(array, 0, &svec);
	MRDebug_line_ptr->x0 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y0 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;

	t += dt;
	while((t >> MR_SPLINE_PARAM_SHIFT) < array->sb_numbeziers)
		{
		MRCalculateSplineBezierArrayPoint(array, t, &svec);
		MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
		MRDebug_line_ptr++;
		MRDebug_line_ptr->x0 =  (((svec.vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
		MRDebug_line_ptr->y0 = -(((svec.vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
		t += dt;
		}

	MRCalculateSplineBezierArrayPoint(array, (array->sb_numbeziers << MR_SPLINE_PARAM_SHIFT) - 1, &svec);
	MRDebug_line_ptr->x1 =  ((svec.vx * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	MRDebug_line_ptr->y1 = -((svec.vy * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	MR_SET32(MRDebug_line_ptr->r0, MR_PRIM_GPU_CODE_LF2 + colour);
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_line_otz, MRDebug_line_ptr);
	MRDebug_line_ptr++;
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldBsplineControlPoints
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldBsplineControlPoints(
*						MR_BSPLINE*	bspline,
*						MR_ULONG   	colour,
*						MR_USHORT 	width);
*
*	FUNCTION	Plots n control points of bspline
*
*	INPUTS		bspline		-	pointer to control points
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldBsplineControlPoints(	MR_BSPLINE*	bspline,
								  				MR_ULONG  	colour,
								  				MR_USHORT  	width)
{
#ifdef MR_DEBUG_DISPLAY
	MR_USHORT	i;
	MR_SVEC*	point;


	MR_ASSERT(bspline);
	MR_ASSERT(MRDebug_tile_ptr + bspline->bs_numpoints <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	point = bspline->bs_points;
	i		= bspline->bs_numpoints;
	while(i--)
		{
		MRDebug_tile_ptr->x0 =  (((point->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x - (width >> 1);
		MRDebug_tile_ptr->y0 = -(((point->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y - (width >> 1);

		MRDebug_tile_ptr->w	= width;
		MRDebug_tile_ptr->h	= width;
	
		*(MR_LONG*)&MRDebug_tile_ptr->r0 = MR_PRIM_GPU_CODE_TILE + colour;
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
		MRDebug_tile_ptr++;
		point++;
		}
#endif
}

/******************************************************************************
*%%%% MRDebugPlot2DWorldBezierControlPoints
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldBezierControlPoints(
*						MR_SPLINE_BEZIER*	spline,
*						MR_ULONG 			colour,
*						MR_USHORT			width);
*
*	FUNCTION	Plots 4 control points of bezier spline
*
*	INPUTS		spline		-	pointer to control points
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldBezierControlPoints(	MR_SPLINE_BEZIER*	spline,
												MR_ULONG 			colour,
												MR_USHORT			width)
{
#ifdef MR_DEBUG_DISPLAY
	MR_USHORT	i;
	MR_SVEC*		point;


	MR_ASSERT(spline);
	MR_ASSERT(MRDebug_tile_ptr + 4 <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	point = (MR_SVEC*)spline;
	i		= 4;
	while(i--)
		{
		MRDebug_tile_ptr->x0 =  (((point->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x - (width >> 1);
		MRDebug_tile_ptr->y0 = -(((point->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y - (width >> 1);

		MRDebug_tile_ptr->w	= width;
		MRDebug_tile_ptr->h	= width;
	
		*(MR_LONG*)&MRDebug_tile_ptr->r0 = MR_PRIM_GPU_CODE_TILE + colour;
		addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
		MRDebug_tile_ptr++;
		point++;
		}
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldSplineBezierArrayControlPoints
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldSplineBezierArrayControlPoints(
*						MR_SPLINE_BEZIER_ARRAY*	array,
*						MR_ULONG	 			colour,
*						MR_USHORT 				width);
*
*	FUNCTION	Plots n control points of spline bezier array
*
*	INPUTS		array		-	pointer to array structure
*				colour		-	tile colour
*				width		-	tile width
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.01.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldSplineBezierArrayControlPoints(	MR_SPLINE_BEZIER_ARRAY*	array,
															MR_ULONG	 			colour,
															MR_USHORT 				width)
{
#ifdef MR_DEBUG_DISPLAY
	MR_USHORT			p, b, numpoints;
	MR_SVEC*			point;
	MR_SPLINE_BEZIER*	bezier;


	MR_ASSERT(array);

	numpoints = (array->sb_numbeziers << 2)  - (array->sb_numbeziers - 1);

	MR_ASSERT(MRDebug_tile_ptr + numpoints <= &MRDebug_tiles[MRFrame_index][MR_DEBUG_MAX_TILES]);
	MR_ASSERT(MRVp_ptr);

	bezier	= array->sb_beziers;
	b			= array->sb_numbeziers;
	while(b--)
		{
		if (b)
			p = 3;
		else
			p = 4;

		point = (MR_SVEC*)bezier;
		while(p--)
			{
			MRDebug_tile_ptr->x0 =  (((point->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x - (width >> 1);
			MRDebug_tile_ptr->y0 = -(((point->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y - (width >> 1);

			MRDebug_tile_ptr->w	= width;
			MRDebug_tile_ptr->h	= width;
	
			*(MR_LONG*)&MRDebug_tile_ptr->r0 = MR_PRIM_GPU_CODE_TILE + colour;
			addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, MRDebug_tile_ptr);
			MRDebug_tile_ptr++;
			point++;
			}
		bezier++;
		}
#endif
}


/******************************************************************************
*%%%% MRDebugPlotWorldPolyF4
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlotWorldPolyF4(
*						MR_SVEC*	points,
*						POLY_F4*	poly)
*
*	FUNCTION	Plots a POLY_F4 in the world
*
*	INPUTS		points	-	ptr to 4 MR_SVEC coords
*				poly	- 	ptr to PLOY_F4 to redner
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlotWorldPolyF4(	MR_SVEC*	points,
								POLY_F4*	poly)
{
#ifdef MR_DEBUG_DISPLAY
	MR_SVEC	svec;


	MR_ASSERT(points);
	MR_ASSERT(poly);
	MR_ASSERT(MRVp_ptr);

	svec.vx = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)MRVp_ptr->vp_render_matrix.t[2];

	gte_SetRotMatrix(&MRVp_ptr->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);

	gte_ldv3(&points[0], &points[1], &points[2]);
	gte_rtpt();
	gte_stsxy0((MR_LONG*)&poly->x0);
	gte_stsxy1((MR_LONG*)&poly->x1);
	gte_stsxy2((MR_LONG*)&poly->x2);
	addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, poly);
	gte_ldv0(&points[3]);
	gte_rtps();
	gte_stsxy((MR_LONG*)&poly->x3);
#endif
}


/******************************************************************************
*%%%% MRDebugPlot2DWorldPolyF4
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDebugPlot2DWorldPolyF4(
*						MR_SVEC*	points,
*						POLY_F4*	poly)
*
*	FUNCTION	Plots a 2D world POLY_F4
*
*	INPUTS		points	-	ptr to 4 MR_SVEC coords
*				poly	- 	ptr to POLY_F4 to render
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRDebugPlot2DWorldPolyF4(	MR_SVEC*	points,
									POLY_F4*	poly)
{
#ifdef MR_DEBUG_DISPLAY
	MR_ASSERT(points);
	MR_ASSERT(poly);
	MR_ASSERT(MRVp_ptr);


	poly->x0 =  (((points->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	poly->y0 = -(((points->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	points++;

	poly->x1 =  (((points->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	poly->y1 = -(((points->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	points++;

	poly->x2 =  (((points->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	poly->y2 = -(((points->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	points++;

	poly->x3 =  (((points->vx >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_x;
	poly->y3 = -(((points->vy >> 0) * MRDebug_2D_scale) >> 15 >> 4) + MRVp_ptr->vp_geom_y;
	points++;

	addPrim(MRVp_ptr->vp_work_ot + MRDebug_tile_otz, poly);
#endif
}

