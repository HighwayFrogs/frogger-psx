/******************************************************************************
*%%%% mr_view.c
*------------------------------------------------------------------------------
*
*	Viewport related control functions
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	24.05.96	Dean Ashton		Added MRSetViewportCamera on request from Derek.
*	05.06.96	Dean Ashton		Added MRSetViewportFogColour for Derek.
*	05.06.96	Dean Ashton		Added MRSetViewportFogDistances for Derek.
*	19.06.96	Tim Closs		Changed return type for MRAddObjectToViewport
*	19.06.96	Tim Closs		Changed MRRenderViewport to pass in extra model, cel
*								params to MRDisplayMeshInstance
*	25.06.96	Tim Closs		MRRemoveLightInstanceFromViewport updates properly
*								MRAddObjectToViewport changed to build light matrices
*								correctly
*	09.07.96	Dean Ashton		Changed link pointer positions for 2D sprites
*	08.08.96	Tim Closs		MRAddObjectToViewport handles anims
*	20.08.96	Dean Ashton		Changed to call mr_stat/mr_anim functions for mesh
*								display. Changed the function name
*								MRRemoveLightInstanceFromDyingViewport to new
*								MRRemoveLightInstanceFromViewportPhysically.
*	18.09.96	Dean Ashton		Added assertion into MRCreateViewport for otsize
*	17.10.96	Dean Ashton		Added viewport view distance manipulation code
*	31.10.96	Dean Ashton		Added vp_view_distance, and also automatic setting
*								of viewport aspect matrix based on display size.
*	14.01.97	Tim Closs		MRCreateViewport() and MRRenderViewport() altered
*								to cope with new linked list of environment instances
*								hanging off MR_VIEWPORT
*	21.01.97	Tim Closs		MRKillViewport() now removes environment instances
*	27.01.97	Dean Ashton		Made particle generators respect MR_OBJ_NO_DISPLAY
*	06.02.97	Tim Closs		MRRenderViewport() deletion stuff handles MR_OBJ_MEMFIXED
*								MRRemove3DSpriteInstanceFromViewportPhysically() does also
*								MRRemovePgenInstanceFromViewportPhysically() does also
*	14.02.97	Tim Closs		Added	MRRemoveAllLightInstancesFromViewportPhysically()
*	17.02.97	Tim Closs		MRAddObjectToViewport() - added support for MR_ANIM_PART_REDUNDANT
*	26.02.97	Tim Closss		Mesh instances now have prims in one allocation:
*								MRRenderViewport()
*								MRAddObjectToViewport()
*								MRRemoveMeshInstanceFromViewportPhysically()
*	11.03.97	Dean Ashton		Re-added MRChangeViewport()... again.
*	23.04.97	Dean Ashton		MRChangeViewport() - Fixed bug to clear MR_VP_NO_ASPECT
*	17.06.97	Dean Ashton		Modified MRCreateViewport() to not allow viewport
*								creation on 24-bit displays.
*	18.06.97	Dean Ashton		Removed 2D sprite animation updates from MRRenderViewport, 
*								and moved into a separate routine MRUpdateViewport2DSpriteAnims();
*	02.07.97	Dean Ashton		Aspect matrix changed to respect PAL/NTSC sizes in MRCreateViewport();
*	21.07.97	Dean Ashton		Fixed aspect matrix bugs in MRCreate/ChangeViewport, 
*								and let MRChangeViewport() accept a NULL parameter to use
*								display defaults.
*
*%%%**************************************************************************/

#include	"mr_all.h"


MR_VIEWPORT		MRViewport_root;
MR_VIEWPORT*	MRViewport_root_ptr;
MR_USHORT		MRNumber_of_viewports;


/******************************************************************************
*%%%% MRMoveViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMoveViewport(
*						MR_VIEWPORT*	vp,
*						MR_SHORT		x,
*						MR_SHORT		y);
*
*	FUNCTION	Sets a viewports X/Y screen position
*
*	INPUTS		vp			-	Pointer to the MR_VIEWPORT to modify
*				x			-	New X screen position for the viewport
*				y			-	New Y screen position for the viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRMoveViewport(	MR_VIEWPORT*	vp,
						MR_SHORT		x,
						MR_SHORT 		y)
{
	SHORT x0,y0,x1,y1,x2,y2,x3,y3,w,h;

	MR_ASSERT(vp != NULL);

	// Set current viewport display information
	vp->vp_disp_inf.x = x;
	vp->vp_disp_inf.y = y;
	w = vp->vp_disp_inf.w;
	h = vp->vp_disp_inf.h;

	// Find out whether the Viewport is actually on screen
	if	(
		(x > MRDisplay_ptr->di_screen[0].w-1) ||	// Off the right
		(y > MRDisplay_ptr->di_screen[0].h-1) ||	// Off the bottom
		(x+w < 0) ||								// Off the left
		(y+h < 0)									// Off the top
		)										
		vp->vp_flags |= MR_VP_NO_DISPLAY;
	else
		vp->vp_flags &= ~MR_VP_NO_DISPLAY;

	// Generate real rect for the area (ie x0/y0, x1/y1, x2/y2, x3/y3) and clip to the screen
	x0 = x2 = MAX(0,(MIN(x,MRDisplay_ptr->di_screen[0].w-1)));					
	x1 = x3 = MAX(0,(MIN(x+w-1,MRDisplay_ptr->di_screen[0].w-1)));
	y0 = y1 = MAX(0,(MIN(y,MRDisplay_ptr->di_screen[0].h-1)));
	y2 = y3 = MAX(0,(MIN(y+h-1,MRDisplay_ptr->di_screen[0].h-1)));
	
	// Generate a new RECT based on this, placing into the drawing areas.

	// DR_AREA for buffer 0
	setRECT(&vp->vp_draw_areas[0], 				
			 MRDisplay_ptr->di_screen[0].x + x0,
			 MRDisplay_ptr->di_screen[0].y + y0,
			 (x1-x0+1),
			 (y2-y0+1));

	// DR_AREA for buffer 0
	setRECT(&vp->vp_draw_areas[1], 					
			 MRDisplay_ptr->di_screen[1].x + x0,	
			 MRDisplay_ptr->di_screen[1].y + y0,	
			 (x1-x0+1),
			 (y2-y0+1));

	// Generate new DR_OFFSET parameters
	vp->vp_draw_ofs[0].off_x = MRDisplay_ptr->di_screen[0].x + x;
	vp->vp_draw_ofs[0].off_y = MRDisplay_ptr->di_screen[0].y + y;

	vp->vp_draw_ofs[1].off_x = MRDisplay_ptr->di_screen[1].x + x;
	vp->vp_draw_ofs[1].off_y = MRDisplay_ptr->di_screen[1].y + y;

	// Request modifications to the MR_VPCHANGE primitives
	vp->vp_disp_change[0].vc_flags |= MR_VP_CHANGE_POS;
	vp->vp_disp_change[1].vc_flags |= MR_VP_CHANGE_POS;
}


/******************************************************************************
*%%%% MRMoveViewportAbs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMoveViewportAbs(
*						MR_VIEWPORT*	vp,
*						MR_RECT*		rect0,
*						MR_RECT*		rect1);
*
*	FUNCTION	Sets viewport buffers to be at the specified absolute VRAM
*				positions.
*
*	INPUTS		vp	 		-	Pointer to the MR_VIEWPORT to modify
*				rect0		-	Pointer to a rectangle from which the 
*								absolute VRAM coordinates for buffer 0
*								will be taken
*				rect1		-	Pointer to a rectangle from which the
*								absolute VRAM coordinates for buffer 1
*								will be taken
*
*	NOTES		This function is useful to get a viewport to render into 
*				texture ram, as it can then be used on a polygon. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	22.04.97	Dean Ashton		Patched vp_disp_inf.w/h too
*
*%%%**************************************************************************/

MR_VOID	MRMoveViewportAbs(	MR_VIEWPORT*	vp,
							MR_RECT*		rect0,
							MR_RECT*		rect1)
{
	MR_ASSERT(vp != NULL);

	// Set current viewport display information based on first rectangle
	vp->vp_disp_inf.x = rect0->x;
	vp->vp_disp_inf.y = rect0->y;
	vp->vp_disp_inf.w = rect0->w;
	vp->vp_disp_inf.h = rect0->h;

	// Set clip regions for this viewport
	setRECT(&vp->vp_draw_areas[0], rect0->x, rect0->y, rect0->w, rect0->h);
	setRECT(&vp->vp_draw_areas[1], rect1->x, rect1->y, rect1->w, rect1->h);

	// Set drawing offsets for this viewport
	vp->vp_draw_ofs[0].off_x = rect0->x;
	vp->vp_draw_ofs[0].off_y = rect0->y;

	vp->vp_draw_ofs[1].off_x = rect1->x;
	vp->vp_draw_ofs[1].off_y = rect1->y;

	// Request modifications to the MR_VPCHANGE primitives
	vp->vp_disp_change[0].vc_flags |= MR_VP_CHANGE_POS;
	vp->vp_disp_change[1].vc_flags |= MR_VP_CHANGE_POS;
}


/******************************************************************************
*%%%% MRChangeViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRChangeViewport(
*						MR_VIEWPORT*	vp,
*						MR_RECT*		info);
*
*	FUNCTION	Sets a viewports X/Y/W/H components, correctly adjusting the 
*				clip area, drawing offsets, geometry offsets and aspect ratio.
*
*	INPUTS		vp	 		-	Pointer to the MR_VIEWPORT to modify
*				info 		-	Pointer to a MR_RECT holding new X/Y/W/H
*								or NULL to use display sizes
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.01.97	Dean Ashton		Created
*	11.03.97	Dean Ashton		Back, after being accidentally removed...
*	22.04.97	Dean Ashton		Patched vp_disp_inf.w/h too
*	23.04.97	Dean Ashton		Fixed bug to clear MR_VP_NO_ASPECT
*	18.07.97	Dean Ashton		Fixed aspect matrix bug, let routine use NULL
*								pointer to rectangle.
*
*%%%**************************************************************************/

MR_VOID	MRChangeViewport(	MR_VIEWPORT*	vp,
							MR_RECT*		info)
{
	SHORT x0,y0,x1,y1,x2,y2,x3,y3,x,y,w,h;

	MR_ASSERT(vp != NULL);

	// Set current viewport display information
	if (info != NULL)
		{
		x = info->x;
		y = info->y;
	 	w = info->w;
		h = info->h;
		}
	else
		{
		x = 0;
		y = 0;
	 	w = MRDisplay_ptr->di_screen[0].w;
		h = MRDisplay_ptr->di_screen[0].h;
		}

	vp->vp_disp_inf.x = x;
	vp->vp_disp_inf.y = y;
	vp->vp_disp_inf.w = w;
	vp->vp_disp_inf.h = h;

	// Find out whether the Viewport is actually on screen
	if	(
		(x > MRDisplay_ptr->di_screen[0].w-1) ||		// Off the right
		(y > MRDisplay_ptr->di_screen[0].h-1) ||		// Off the bottom
		(x+w < 0) ||									// Off the left
		(y+h < 0)										// Off the top
		)
		vp->vp_flags |= MR_VP_NO_DISPLAY;
	else
		vp->vp_flags &= ~MR_VP_NO_DISPLAY;

	// Generate real rect for the area (ie x0/y0, x1/y1, x2/y2, x3/y3) and clip to the screen
	x0 = x2 = MAX(0,(MIN(x,MRDisplay_ptr->di_screen[0].w-1)));					
	x1 = x3 = MAX(0,(MIN(x+w-1,MRDisplay_ptr->di_screen[0].w-1)));
	y0 = y1 = MAX(0,(MIN(y,MRDisplay_ptr->di_screen[0].h-1)));
	y2 = y3 = MAX(0,(MIN(y+h-1,MRDisplay_ptr->di_screen[0].h-1)));
	
	// Generate a new RECT based on this, placing into the drawing areas.

	// DR_AREA for buffer 0
	setRECT(&vp->vp_draw_areas[0], 				
			 MRDisplay_ptr->di_screen[0].x + x0,
			 MRDisplay_ptr->di_screen[0].y + y0,
			 (x1-x0+1),
			 (y2-y0+1));

	// DR_AREA for buffer 0
	setRECT(&vp->vp_draw_areas[1], 					
			 MRDisplay_ptr->di_screen[1].x + x0,	
			 MRDisplay_ptr->di_screen[1].y + y0,	
			 (x1-x0+1),
			 (y2-y0+1));

	// Generate a new geometry offset position
	vp->vp_geom_x 	= (w >> 1);	// Geometry offset is center of viewport (excludes clipping of VP)
	vp->vp_geom_y 	= (h >> 1);
	

	// Generate new DR_OFFSET parameters
	vp->vp_draw_ofs[0].off_x = MRDisplay_ptr->di_screen[0].x + x;
	vp->vp_draw_ofs[0].off_y = MRDisplay_ptr->di_screen[0].y + y;

	vp->vp_draw_ofs[1].off_x = MRDisplay_ptr->di_screen[1].x + x;
	vp->vp_draw_ofs[1].off_y = MRDisplay_ptr->di_screen[1].y + y;

	// Request modifications to the MR_VPCHANGE primitives
	vp->vp_disp_change[0].vc_flags |= MR_VP_CHANGE_POS;
	vp->vp_disp_change[1].vc_flags |= MR_VP_CHANGE_POS;

	//	Set up aspect matrix from display aspect
	MR_INIT_MAT(&vp->vp_aspect_matrix);

	vp->vp_aspect_matrix.m[0][0] = (0x1000 * vp->vp_disp_inf.w) / 320;
#ifdef	MR_MODE_NTSC
	vp->vp_aspect_matrix.m[1][1] = (0x1000 * vp->vp_disp_inf.h) / 240;
#else
	vp->vp_aspect_matrix.m[1][1] = (0x1000 * vp->vp_disp_inf.h) / 256;		
#endif
	if ((vp->vp_aspect_matrix.m[0][0] == 0x1000) && (vp->vp_aspect_matrix.m[1][1] == 0x1000))
		vp->vp_flags |= MR_VP_NO_ASPECT;
	else
		vp->vp_flags &= ~MR_VP_NO_ASPECT;
}


/******************************************************************************
*%%%% MRCreateViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VIEWPORT* viewport =	MRCreateViewport(
*										MR_RECT*		rect_0,
*										MR_RECT*		rect_1,
*										MR_USHORT		otshift,
*										MR_USHORT		priority,
*
*	FUNCTION	Creates a viewport with dimensions taken from rect_0. If two 
*				rectangle pointers are supplied, then they are assumed to point
*				to absolute VRAM coodrinates for each viewport screen buffer. If
*				only the first pointer is supplied, then the X/Y position within
*				that rectangle is actually an offset within the current screen
*				definition.
*
*	INPUTS		rect_0		-	Pointer to rectangle (offset, or VRAM)
*							 	If NULL then a display sized rectangle is
*							 	used.
*				rect_1		-	Pointer to rectangle (NULL, or VRAM)
*				otshift		-	Ordering table is (1<<otshift) slots
*				priority	-	Low priority viewports are rendered first
*
*	RESULT		viewport	-	Pointer to viewport if created ok, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Changed to accept NULL as rect_0, to take 
*					   			dimensions from current display. 
*	09.07.96	Dean Ashton		Changed link pointers for 2D sprites
*	18.09.96	Dean Ashton		Added assertion on OT size
*	17.10.96	Dean Ashton		Added handling of adjustable view distance
*	31.10.96	Dean Ashton		Added vp_view_distance, and also automatic setting
*					   			of viewport aspect matrix based on display size.
*	14.01.97	Tim Closs		Altered to cope with new linked list of environment
*					   			instances hanging off MR_VIEWPORT
*	17.06.97	Dean Ashton		Viewports are not allowed when using 24-bit displays
*								due to PlayStation GPU restrictions.
*	02.07.97	Dean Ashton		Aspect matrix changed to respect PAL/NTSC sizes
*	21.07.97	Dean Ashton		Fixed above matrix changes... ooops.
*
*%%%**************************************************************************/

MR_VIEWPORT*	MRCreateViewport(	MR_RECT* 	rect_0,
					   				MR_RECT* 	rect_1,
					   				MR_USHORT	otshift,
					   				MR_USHORT	priority)
{
	MR_RECT			disp_rect;
	MR_VIEWPORT*	viewport;
	MR_VIEWPORT*	vp_search = MRViewport_root_ptr;

	// There has to be an active display for us create a viewport for
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	// We can't associate viewports with a 24-bit display
	MR_ASSERT(!(MRDisplay_ptr->di_video_flags & MR_DD_TRUECOLOUR));

	// There has to be a specified OT size
	MR_ASSERT(otshift != NULL);

	// If we're defaulting the viewport size to that of the display..
	if (rect_0 == NULL)
		{
		setRECT(&disp_rect, 0, 0, MRDisplay_ptr->di_screen[0].w, MRDisplay_ptr->di_screen[0].h);
		rect_0 = &disp_rect;
		}

	// Link new viewport into list... in correct place according to priority... search through
	// list and link viewport of priority (a) in before first viewport of priority (>= a)
	viewport = (MR_VIEWPORT*)MRAllocMem(sizeof(MR_VIEWPORT), "VIEWPORT");

	while(vp_search->vp_next_node)
		{
		if (vp_search->vp_next_node->vp_priority < priority)
			{
			// Link viewport in BEFORE this entry
			break;
			}
		vp_search = vp_search->vp_next_node;
		}

	viewport->vp_next_node	= vp_search->vp_next_node;
	viewport->vp_prev_node	= vp_search;
	vp_search->vp_next_node	= viewport;

	MRNumber_of_viewports++;

	//	Do stuff for instance table and two linked lists
	viewport->vp_text_area_root_ptr = &viewport->vp_text_area_root;
	((MR_TEXT_AREA*)(&viewport->vp_text_area_root))->ta_next_node = NULL;

	viewport->vp_mesh_root_ptr = &viewport->vp_mesh_root;
	((MR_MESH_INST*)(&viewport->vp_mesh_root))->mi_next_node = NULL;

	viewport->vp_light_root_ptr = &viewport->vp_light_root;
	((MR_LIGHT_INST*)(&viewport->vp_light_root))->li_next_node = NULL;

	viewport->vp_2dsprite_root_ptr = &viewport->vp_2dsprite_root;
	((MR_SP_CORE*)(&viewport->vp_2dsprite_root))->sc_next_node = NULL;

	viewport->vp_3dsprite_root_ptr = &viewport->vp_3dsprite_root;
	((MR_3DSPRITE_INST*)(&viewport->vp_3dsprite_root))->si_next_node = NULL;

	viewport->vp_pgen_root_ptr = &viewport->vp_pgen_root;
	((MR_PGEN_INST*)(&viewport->vp_pgen_root))->pi_next_node = NULL;

	viewport->vp_env_root_ptr = &viewport->vp_env_root;
	((MR_ANIM_ENV_INST*)(&viewport->vp_env_root))->ae_next_node = NULL;

	// Initialise viewport structure	
	viewport->vp_frame_count	= 0;
	viewport->vp_disp_inf.w		= rect_0->w;
	viewport->vp_disp_inf.h		= rect_0->h;

	// Allocate ordering tables 'otsize' slots long
	viewport->vp_view_distance = 1<<(15-MR_VP_VIEWDIST_DEFAULT);
	viewport->vp_ot_size			= 1<<otshift;
	MR_ASSERT(15-MR_VP_VIEWDIST_DEFAULT-otshift >= 0);							// Check for valid view distance scaling
	viewport->vp_ot_size_bits	= otshift;										// Store OT bit resolution
	viewport->vp_otz_shift		= (15-MR_VP_VIEWDIST_DEFAULT-otshift);			// Calculate otz shift based on OT bit resolution and view distance scaling
	viewport->vp_ot[0] = MRAllocMem((viewport->vp_ot_size * sizeof(MR_ULONG)), "VPORTOT0");
	viewport->vp_ot[1] = MRAllocMem((viewport->vp_ot_size * sizeof(MR_ULONG)), "VPORTOT1");

	// Set a pointer to the work ordering table, and clear both ordering tables too.
	viewport->vp_work_ot = viewport->vp_ot[MRFrame_index];
	ClearOTagR(viewport->vp_ot[0], viewport->vp_ot_size);
	ClearOTagR(viewport->vp_ot[1], viewport->vp_ot_size);

	// Set various geometry based things
	viewport->vp_geom_x 		= (rect_0->w >> 1);	// Geometry offset is center of viewport
	viewport->vp_geom_y 		= (rect_0->h >> 1);

	viewport->vp_camera			= NULL;							// No camera yet
	viewport->vp_perspective	= 1000;							// Default 'h' (distance from eye to screen)
	viewport->vp_fog_colour.r	= 0;
	viewport->vp_fog_colour.g	= 0;
	viewport->vp_fog_colour.b	= 0;
	viewport->vp_fog_near_dist	= 0;
	viewport->vp_fog_far_dist	= 100;

	viewport->vp_back_colour.r	= 0;
	viewport->vp_back_colour.g	= 0;
	viewport->vp_back_colour.b	= 0;
	MR_CLEAR_MAT(&viewport->vp_colour_matrix);
	
	// If the Viewport is display-offset based, set its position relative to display buffers
	// otherwise, set the clip/draw regions to absolute VRAM coordinates (note that the w/h
	// elements in the second rectangle are not used!)
	if (rect_1 == NULL)
		{
		viewport->vp_flags = NULL;
		MRMoveViewport(viewport, rect_0->x, rect_0->y);
		}
	else
		{
		viewport->vp_flags = MR_VP_ABS_VRAM;
		MRMoveViewportAbs(viewport, rect_0, rect_1);
		}

	viewport->vp_priority		= priority;
	viewport->vp_pointlights	= 0;

	// Set effect structure to NULL
	MR_CLEAR(viewport->vp_effect);

	viewport->vp_effect.fx_type = NULL;


	// Set this viewport as the default (if a default hasn't been defined already)
	if (MRDefault_vp == NULL)
		{
		MRDefault_vp 	= viewport;
		MRDefault_vp_ot	= viewport->vp_work_ot;
		MRVp_ptr	 	= viewport;
		} 
	
	//	Set up aspect matrix from display aspect
	MR_INIT_MAT(&viewport->vp_aspect_matrix);

	viewport->vp_aspect_matrix.m[0][0] = (0x1000 * viewport->vp_disp_inf.w) / 320;
#ifdef	MR_MODE_NTSC
	viewport->vp_aspect_matrix.m[1][1] = (0x1000 * viewport->vp_disp_inf.h) / 240;
#else
	viewport->vp_aspect_matrix.m[1][1] = (0x1000 * viewport->vp_disp_inf.h) / 256;
#endif
	if ((viewport->vp_aspect_matrix.m[0][0] == 0x1000) && (viewport->vp_aspect_matrix.m[1][1] == 0x1000))
		viewport->vp_flags |= MR_VP_NO_ASPECT;

	return(viewport);
}


/******************************************************************************
*%%%% MRKillViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillViewport(
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Kills a viewport. Note that this is not an instant destruction,
*				as we have to wait for current drawing to complete before 
*				freeing the memory associated with the viewport.
*
*	INPUTS		vp			-	Pointer to a valid MR_VIEWPORT structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	09.07.96	Dean Ashton		Changed link pointers for 2D sprites
*	20.08.96	Dean Ashton		Changed to call renamed function,
*								MRRemoveLightInstanceFromViewportPhysically
*	21.01.97	Tim Closs		Now removes environment instances
*
*%%%**************************************************************************/

MR_VOID	MRKillViewport(MR_VIEWPORT* vp)
{
	MR_ANIM_ENV_INST*	env_inst;
	MR_MESH_INST*		mesh_inst;
	MR_LIGHT_INST*		light_inst;
	MR_3DSPRITE_INST*	sprite3d_inst;
	MR_PGEN_INST*		pgen_inst;
	MR_2DSPRITE*		sprite2d;
	MR_TEXT_AREA*		text_area;

	MR_ASSERT(vp != NULL);

	// Do safety stuff for the viewport (waits for drawing to finish, clears both OT's)
	MRClearViewportOT(vp);

	// Free the memory associated with the OT's
	MRFreeMem(vp->vp_ot[0]);
	MRFreeMem(vp->vp_ot[1]);

	// Remove all environment instances
	env_inst = vp->vp_env_root_ptr;
	while(env_inst->ae_next_node)
		MRAnimRemoveEnvInstanceFromViewportPhysically(env_inst->ae_next_node, vp);

	//	Remove all mesh instances
	mesh_inst = vp->vp_mesh_root_ptr;
	while(mesh_inst->mi_next_node)
		MRRemoveMeshInstanceFromViewportPhysically(mesh_inst->mi_next_node, vp);

	//	Remove all light instances
	light_inst = vp->vp_light_root_ptr;
	while(light_inst->li_next_node)
		MRRemoveLightInstanceFromViewportPhysically(light_inst->li_next_node, vp);

	// Remove all 3d sprite instances
	sprite3d_inst = vp->vp_3dsprite_root_ptr;
	while(sprite3d_inst->si_next_node)
		MRRemove3DSpriteInstanceFromViewportPhysically(sprite3d_inst->si_next_node, vp);

	// Remove all pgen instances
	pgen_inst = vp->vp_pgen_root_ptr;
	while(pgen_inst->pi_next_node)
		MRRemovePgenInstanceFromViewportPhysically(pgen_inst->pi_next_node, vp);

	// Remove all 2d sprites
	sprite2d = vp->vp_2dsprite_root_ptr;
	while(sprite2d->sp_core.sc_next_node)
		MRRemove2DSpriteFromViewportPhysically(((MR_2DSPRITE*)(sprite2d->sp_core.sc_next_node)), vp);

	// Remove all text areas
	text_area = vp->vp_text_area_root_ptr;
	while(text_area->ta_next_node)
		MRRemoveTextAreaFromViewportPhysically(text_area->ta_next_node, vp);

	// If this was the default viewport, then clear the default vp/vp-ot variables		
	if (vp == MRDefault_vp)
		{
		MRDefault_vp	= NULL;
		MRDefault_vp_ot	= NULL;
		} 

	// Remove structure from linked list
	vp->vp_prev_node->vp_next_node = vp->vp_next_node;
	if	(vp->vp_next_node)
		vp->vp_next_node->vp_prev_node = vp->vp_prev_node;

	// Free viewport structure memory, and reduce viewport count
	MRFreeMem(vp);
	MRNumber_of_viewports--;
}


/******************************************************************************
*%%%% MRSetViewportCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL success =	MRSetViewportCamera(
*									MR_VIEWPORT*	viewport,
*									MR_FRAME*		frame);
*
*	FUNCTION	Abstracted method of setting the camera for a viewport.
*
*	INPUTS		viewport	-	Pointer to viewport
*				frame		-	Pointer to camera frame
*
*	RESULT		success		-	TRUE if it worked, else FALSE
*
*	NOTES		Function added for PC compatibility. Return value is only
*				used on PC API implementation.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_BOOL	MRSetViewportCamera(MR_VIEWPORT*	viewport,
							MR_FRAME*		frame)
{
	viewport->vp_camera = frame;
	return(TRUE);
}

/******************************************************************************
*%%%% MRSetDefaultViewport		
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetDefaultViewport(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Sets the specified viewport to be the system default viewport,
*				creating quick access pointers to the work ordering table.
*
*	INPUTS		viewport	-	Pointer to a valid MR_VIEWPORT structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetDefaultViewport(MR_VIEWPORT *viewport)
{
	MRDefault_vp 	= viewport;
	MRDefault_vp_ot	= viewport->vp_work_ot;
}


/******************************************************************************
*%%%% MRAddObjectToViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID* inst =	MRAddObjectToViewport(
*								MR_OBJECT*		object,
*							 	MR_VIEWPORT*	vp,
*								MR_USHORT		flags);
*
*	FUNCTION	Links an object into the viewports instance lists, automatically
*				creating instanced data where needed.
*
*	INPUTS		object		-	Object that needs linking into the viewport
*				viewport	-	Viewport that object need linking into.
*				flags		-	Flags
*
*	RESULT		inst 		-	ptr to instance created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Tim Closs		Created
*	19.06.96	Tim Closs		Changed to return MR_VOID* (cast to instance ptr)
*	25.06.96	Tim Closs		Changed to build light matrices correctly
*	08.08.96	Tim Closs		Handles anims
*	31.01.97	Dean Ashton		Removed excessive lighting code
*	17.02.97	Tim Closs		Added support for MR_ANIM_PART_REDUNDANT
*	26.02.97	Tim Closs		Mesh instances now have prims in one allocation
*
*%%%**************************************************************************/

MR_VOID*	MRAddObjectToViewport(	MR_OBJECT*		object,
									MR_VIEWPORT*	vp,
									MR_USHORT		flags)
{
	MR_MESH_INST*		mesh_inst;
	MR_MESH_INST*		mesh_root;
	MR_ANIM_ENV*		anim_env;
	MR_LIGHT_INST*		light_inst;
	MR_LIGHT_INST*		light_root;
	MR_3DSPRITE*		sprite_ptr;
	MR_3DSPRITE_INST*	spriteinst_ptr;
	MR_3DSPRITE_INST*	spriteinst_root_ptr;
	MR_PGEN_INST*		pgeninst_ptr = NULL;
	MR_PGEN_INST*		pgeninst_root_ptr;
	MR_LIGHT*			light_ptr;
	MR_MESH*			mesh_ptr;
	MR_PART*			part_ptr;
	MR_MOF*				mof_ptr;
	MR_ULONG			m;	
	MR_UBYTE*			parts_flags;
	MR_UBYTE*			prims;
	MR_USHORT			i, s, total_parts;


	MR_ASSERT(object != NULL);
	MR_ASSERT(vp != NULL);

	switch (object->ob_type)
		{
// ---- ADD MR_OBJTYPE_MESH ----

		case MR_OBJTYPE_STATIC_MESH:
		case MR_OBJTYPE_ANIM_MESH:

			//------------------------------------------------------------------------------------------
			// This should allocate a MR_MESH_INST structure (or equivalent)
			mesh_ptr 	= object->ob_extra.ob_extra_mesh;
			parts_flags	= NULL;

			if (object->ob_type == MR_OBJTYPE_STATIC_MESH)
				{
				// Static mesh instance
				mof_ptr		= mesh_ptr->me_extra.me_extra_static_mesh->sm_mof_ptr;
				total_parts	= mof_ptr->mm_extra;
				}
			else
				{
				// Animated mesh instance
				anim_env	= (MR_ANIM_ENV*)mesh_ptr->me_extra.me_extra_anim_mesh->am_environment;
				if (anim_env->ae_flags & MR_ANIM_ENV_IS_MULTIPLE)
					{
					mof_ptr	= anim_env->ae_header->ah_static_files[anim_env->ae_extra.ae_extra_env_multiple->ae_models[mesh_ptr->me_extra.me_extra_anim_mesh->am_model_no]->am_static_model];
					if (object->ob_owner.ob_owner_anim_env->ae_extra.ae_extra_env_multiple->ae_parts_flags)
						parts_flags = object->ob_owner.ob_owner_anim_env->ae_extra.ae_extra_env_multiple->ae_parts_flags[mesh_ptr->me_extra.me_extra_anim_mesh->am_model_no];
					}
				else
					{
					mof_ptr		= anim_env->ae_header->ah_static_files[anim_env->ae_extra.ae_extra_env_single->ae_model->am_static_model];
					parts_flags = object->ob_owner.ob_owner_anim_env->ae_extra.ae_extra_env_single->ae_parts_flags;
					}

				total_parts	= mof_ptr->mm_extra;
				// If environment has parts flags, check to see if any are MR_ANIM_PART_REDUNDANT
				if (parts_flags)
					{
					for (i = 0; i < mof_ptr->mm_extra; i++)
						{
						if (parts_flags[i] & MR_ANIM_PART_REDUNDANT)
							total_parts--;
						}		
					}
				}

			// Allocate room for MR_MESH_INST and one prim buffer ptr for each model
			mesh_inst 		   					= (MR_MESH_INST*)MRAllocMem(sizeof(MR_MESH_INST) + (total_parts * sizeof(MR_ULONG*)), "MR_MESI");
			mesh_inst->mi_ot   					= NULL;
			mesh_inst->mi_prims					= (MR_ULONG**)(((MR_UBYTE*)mesh_inst) + sizeof(MR_MESH_INST));
			mesh_inst->mi_extra.mi_extra_void	= NULL;	

			// Add up prim memory required for each part, storing offsets in mi_prims[]
			s 			= 0;
			m 			= 0;
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			for (i = 0; i < mof_ptr->mm_extra; i++)
				{
				if (
					(parts_flags) && 
					(parts_flags[i] & MR_ANIM_PART_REDUNDANT)
					)
					{
					// Skip part
					}
				else
					{
					mesh_inst->mi_prims[s] 	= (MR_ULONG*)m;
					m 		   				+= (part_ptr->mp_buff_size << 1);
					s++;
					}
				part_ptr++;
				}

			// Allocate prim memory
			prims = MRAllocMem(m, "MR_PRIMS");

			// Preset prim memory
			s 			= 0;
			part_ptr	= (MR_PART*)(mof_ptr + 1);
			for (i = 0; i < mof_ptr->mm_extra; i++)
				{
				if (
					(parts_flags) && 
					(parts_flags[i] & MR_ANIM_PART_REDUNDANT)
					)
					{
					// Skip part
					}
				else
					{
					mesh_inst->mi_prims[s] = (MR_ULONG*)(prims + (MR_LONG)mesh_inst->mi_prims[s]);
					MRPresetPartPrims(part_ptr, mesh_inst->mi_prims[s], TRUE);
					s++;
					}
				part_ptr++;
				}
			mesh_inst->mi_mof_models = total_parts;

			//------------------------------------------------------------------------------------------
			// Link instance into list
			mesh_root = vp->vp_mesh_root_ptr;
	
			if (mesh_inst->mi_next_node = mesh_root->mi_next_node)
				mesh_root->mi_next_node->mi_prev_node = mesh_inst;
	
			mesh_root->mi_next_node 	= mesh_inst;
			mesh_inst->mi_prev_node 	= mesh_root;
			mesh_inst->mi_object 		= object;
			mesh_inst->mi_kill_timer 	= 0;
			mesh_inst->mi_ot   			= NULL;
			mesh_inst->mi_flags			= NULL;
			mesh_inst->mi_light_flags	= NULL;

			object->ob_vp_inst_count++;
			return(mesh_inst);
			break;


// ---- ADD MR_OBJTYPE_LIGHT ----
		
		case MR_OBJTYPE_LIGHT:

			//------------------------------------------------------------------------------------------
			// This should allocate an MR_LIGHT_INST structure (or equivalent)

			light_inst = (MR_LIGHT_INST*)MRAllocMem(sizeof(MR_LIGHT_INST), "LIGHINST");

			//------------------------------------------------------------------------------------------
			// Creating an instance of a light... link instance into list
			light_root = vp->vp_light_root_ptr;
	
			if (light_inst->li_next_node = light_root->li_next_node)
				light_root->li_next_node->li_prev_node = light_inst;
	
			light_root->li_next_node 	= light_inst;
			light_inst->li_prev_node	= light_root;
			light_inst->li_object		= object;
		
			// Update viewport's ambient colour values or colour matrix or light matrix according to
			// light type being added... also update any mesh instance light matrices for this viewport
			light_ptr = object->ob_extra.ob_extra_light;
			
			switch(light_ptr->li_type)
				{
				case MR_LIGHT_TYPE_AMBIENT:
					//------------------------------------------------------------------------------------
					// Bump up ambient colour
					vp->vp_back_colour.r += light_ptr->li_colour.r;
					vp->vp_back_colour.g += light_ptr->li_colour.g;
					vp->vp_back_colour.b += light_ptr->li_colour.b;
					break;
	
				case MR_LIGHT_TYPE_PARALLEL:
					//------------------------------------------------------------------------------------
					// Flag for a rebuild of colour/light matrix
					vp->vp_flags |= (MR_VP_REBUILD_LIGHT_MATRIX | MR_VP_REBUILD_COLOUR_MATRIX);
					break;
	
				case MR_LIGHT_TYPE_POINT:
					//------------------------------------------------------------------------------------
					// Flag for a rebuild of colour matrix - no point in rebuilding light matrix for points
					vp->vp_flags |= MR_VP_REBUILD_COLOUR_MATRIX;

					// Increase viewport point light count
					vp->vp_pointlights++;
					break;
				}
			object->ob_vp_inst_count++;
			return(light_inst);
			break;


// ---- ADD MR_OBJTYPE_3DSPRITE

		case	MR_OBJTYPE_3DSPRITE:

			//--------------------------------------------------------------------------------------
			// This should allocate a MR_3DSPRITE_INST structure with room for POLY_FT4's

			spriteinst_ptr = (MR_3DSPRITE_INST*)MRAllocMem(sizeof(MR_3DSPRITE_INST), "3DSPRINS");

			//--------------------------------------------------------------------------------------
			// Creating an instance of a 3D-Sprite, so setup the FT4's and initialise image buffer ptrs
			
			setPolyFT4(&spriteinst_ptr->si_polygon[0]);
			setPolyFT4(&spriteinst_ptr->si_polygon[1]);
			
			spriteinst_ptr->si_image_buf[0]	= NULL;
			spriteinst_ptr->si_image_buf[1]	= NULL;
			spriteinst_ptr->si_light_flags	= NULL;

			//------------------------------------------------------------------------------------------
			// Link instance into list
			spriteinst_root_ptr = vp->vp_3dsprite_root_ptr;
	
			if (spriteinst_ptr->si_next_node = spriteinst_root_ptr->si_next_node)
				spriteinst_root_ptr->si_next_node->si_prev_node = spriteinst_ptr;
	
			spriteinst_root_ptr->si_next_node = spriteinst_ptr;
			spriteinst_ptr->si_prev_node = spriteinst_root_ptr;
			spriteinst_ptr->si_object = object;
	
			sprite_ptr = object->ob_extra.ob_extra_3dsprite;	

			spriteinst_ptr->si_kill_timer = 0;
			
			object->ob_vp_inst_count++;
			return(spriteinst_ptr);
			break;			

// ---- ADD MR_OBJTYPE_PGEN

		case	MR_OBJTYPE_PGEN:

			//--------------------------------------------------------------------------------------
			// This allocates a MR_PGEN_INST structure with room for appropriate polygons
			
			i = object->ob_extra.ob_extra_pgen->pg_max_particles;
			s = object->ob_extra.ob_extra_pgen->pg_prim_size;				// we assume prim sizes are long aligned

			pgeninst_ptr = (MR_PGEN_INST*)MRAllocMem(sizeof(MR_PGEN_INST) + (i * s << 1), "PGENINST");
			pgeninst_ptr->pi_particle_prims[0] = (MR_VOID*)((MR_BYTE*)(pgeninst_ptr) + sizeof(MR_PGEN_INST));
			pgeninst_ptr->pi_particle_prims[1] = (MR_VOID*)((MR_BYTE*)(pgeninst_ptr) + sizeof(MR_PGEN_INST) + (i * s));

			//------------------------------------------------------------------------------------------
			// Link instance into list
			pgeninst_root_ptr = vp->vp_pgen_root_ptr;
	
			if (pgeninst_ptr->pi_next_node = pgeninst_root_ptr->pi_next_node)
				pgeninst_root_ptr->pi_next_node->pi_prev_node = pgeninst_ptr;
	
			pgeninst_root_ptr->pi_next_node = pgeninst_ptr;
			pgeninst_ptr->pi_prev_node = pgeninst_root_ptr;
			pgeninst_ptr->pi_object = object;
	
			pgeninst_ptr->pi_kill_timer = 0;

			//--------------------------------------------------------------------------------------
			// Call the primitive initialisation routine

			MR_ASSERT(pgeninst_ptr->pi_object->ob_extra.ob_extra_pgen->pg_prim_init_callback != NULL);
					
			(pgeninst_ptr->pi_object->ob_extra.ob_extra_pgen->pg_prim_init_callback)(pgeninst_ptr);
			
			object->ob_vp_inst_count++;
			return(pgeninst_ptr);
			break;
		
		default:
			MR_ASSERT(FALSE);
			break;
		}
}

/******************************************************************************
*%%%% MRRemoveObjectFromViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	success =	MRRemoveObjectFromViewport(
*									MR_OBJECT*		object,
*									MR_VIEWPORT*	viewport);
*
*	FUNCTION	Remove an object from a viewports internal lists
*
*	INPUTS		object		-	Object that is currently linked to viewport
*				viewport	-	Viewport that object is currently linked to.
*
*	RESULT		success		-	TRUE if successful, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_BOOL	MRRemoveObjectFromViewport(	MR_OBJECT*		object,
							 		MR_VIEWPORT*	viewport)
{
	MR_MESH_INST*		mesh_inst;
	MR_LIGHT_INST*		light_inst;
	MR_3DSPRITE_INST*	spriteinst_ptr;
	MR_PGEN_INST*		pgeninst_ptr;


	MR_ASSERT(object != NULL);
	MR_ASSERT(viewport != NULL);

	switch (object->ob_type) 
		{
		case	MR_OBJTYPE_STATIC_MESH:
		case	MR_OBJTYPE_ANIM_MESH:
			// Removing an instance of a mesh, so set up kill timer to forbid display of this instance
			// and free poly mem after 2 frames
			mesh_inst = viewport->vp_mesh_root_ptr;

			while(mesh_inst = mesh_inst->mi_next_node)
				{		
				if (mesh_inst->mi_object == object)
					{
					// Remove it
					mesh_inst->mi_kill_timer = 2;
					object->ob_vp_inst_count--;
					return(TRUE);
					}
				}
			break;

		case	MR_OBJTYPE_LIGHT:
			// Removing an instance of a light
			light_inst = viewport->vp_light_root_ptr;
	
			// Remove instance from linked list... first find it in list!
			while(light_inst = light_inst->li_next_node)
				{		
				if (light_inst->li_object == object)
					{
					// This function adjusts the object instance counters too..
					MRRemoveLightInstanceFromViewportPhysically(light_inst, viewport);
					return(TRUE);
					}
				}
			break;

		case	MR_OBJTYPE_3DSPRITE:
			// Removing an instance of a 3D sprite
			spriteinst_ptr = viewport->vp_3dsprite_root_ptr;

			// Remove instance from linked list... first find it in list!
			while(spriteinst_ptr = spriteinst_ptr->si_next_node)
				{
				if (spriteinst_ptr->si_object == object)
					{
					MRRemove3DSpriteInstanceFromViewport(spriteinst_ptr, viewport);
					object->ob_vp_inst_count--;
					return(TRUE);
					}
				}
			break;


		case	MR_OBJTYPE_PGEN:
			// Removing an instance of a Particle Generator
			pgeninst_ptr = viewport->vp_pgen_root_ptr;

			// Remove instance from linked list... first find it in list!
			while(pgeninst_ptr = pgeninst_ptr->pi_next_node)
				{
				if (pgeninst_ptr->pi_object == object)
					{
					MRRemovePgenInstanceFromViewport(pgeninst_ptr, viewport);
					object->ob_vp_inst_count--;
					return(TRUE);
					}
				}
			break;

		default:
			MR_ASSERT(FALSE);
			break;

		}

	return(FALSE);
}


/******************************************************************************
*%%%% MRRemoveLightInstanceFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemoveLightInstanceFromViewportPhysically(
*						MR_LIGHT_INST*	light_inst,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an instance of a light from the specified viewport, but
*				don't bother updating any viewport matrices. 
*
*	INPUTS		light_inst	-	Pointer to valid MR_LIGHT_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	20.08.96	Dean Ashton		Changed name to match other remove functions
*	14.02.96	Dean Ashton		Now correctly handles removal...
*
*%%%**************************************************************************/

MR_VOID	MRRemoveLightInstanceFromViewportPhysically(	MR_LIGHT_INST*	light_inst,
														MR_VIEWPORT*	viewport)
{
	MR_LIGHT*	light_ptr;

	MR_ASSERT(light_inst != NULL);
	MR_ASSERT(viewport != NULL);

	light_ptr = light_inst->li_object->ob_extra.ob_extra_light;

	// Remove it
	light_inst->li_prev_node->li_next_node = light_inst->li_next_node;
	if	(light_inst->li_next_node)
		light_inst->li_next_node->li_prev_node = light_inst->li_prev_node;

	// Update stuff according to type of light removed
	switch(light_ptr->li_type)
		{
		case MR_LIGHT_TYPE_AMBIENT:
			// Removing ambient light - decrease viewports ambient colour
			viewport->vp_back_colour.r -= light_ptr->li_colour.r;
			viewport->vp_back_colour.g -= light_ptr->li_colour.g;
			viewport->vp_back_colour.b -= light_ptr->li_colour.b;
			break;
	
		case MR_LIGHT_TYPE_PARALLEL:
			viewport->vp_flags |= (MR_VP_REBUILD_LIGHT_MATRIX | MR_VP_REBUILD_COLOUR_MATRIX);
			break;

		case MR_LIGHT_TYPE_POINT:
			viewport->vp_flags |= MR_VP_REBUILD_COLOUR_MATRIX;
			break;
		}

	// Kill the light if there are no more instances hanging around
	if (!(--light_inst->li_object->ob_vp_inst_count))
		MRKillLight(light_inst->li_object);

	// Free memory
	MRFreeMem(light_inst);
}


/******************************************************************************
*%%%% MRRemoveAllLightInstancesFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemoveAllLightInstancesFromViewportPhysically(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes all instances lights from the specified viewport
*
*	INPUTS		viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.02.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemoveAllLightInstancesFromViewportPhysically(MR_VIEWPORT*	viewport)
{
	MR_LIGHT_INST*		light_inst;
	MR_LIGHT_INST*		light_inst_prev_ptr;


	MR_ASSERT(viewport);

	light_inst = viewport->vp_light_root_ptr;

	while(light_inst = light_inst->li_next_node)
		{
		// Remove light instance from viewport
		light_inst_prev_ptr = light_inst->li_prev_node;
		MRRemoveLightInstanceFromViewportPhysically(light_inst, viewport);
		light_inst = light_inst_prev_ptr;
		}
}


/******************************************************************************
*%%%% MRRemoveMeshInstanceFromViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemoveMeshInstanceFromViewport(
*						MR_MESH_INST*	mesh_inst,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an instance of a mesh from the specified viewport.
*
*	INPUTS		mesh_inst	-	Pointer to valid MR_MESH_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemoveMeshInstanceFromViewport(	MR_MESH_INST*	mesh_inst,
							 				MR_VIEWPORT*	viewport)
{
	MR_ASSERT(mesh_inst != NULL);
	MR_ASSERT(viewport != NULL);

	mesh_inst->mi_object->ob_vp_inst_count--;
	mesh_inst->mi_kill_timer = 2;
}


/******************************************************************************
*%%%% MRRemoveMeshInstanceFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemoveMeshInstanceFromViewportPhysically(
*						MR_MESH_INST*	mesh_inst,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an instance of a mesh from the specified viewport, but
*				immediately (frees polygon data, and mesh instance structures)
*
*	INPUTS		mesh_inst	-	Pointer to valid MR_MESH_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	26.02.97	Tim Closs		Mesh instances now have prims in one allocation
*
*%%%**************************************************************************/

MR_VOID	MRRemoveMeshInstanceFromViewportPhysically(	MR_MESH_INST*	mesh_inst,
							 						MR_VIEWPORT*	viewport)
{
	MR_ASSERT(mesh_inst != NULL);
	MR_ASSERT(viewport != NULL);

	// Free all mesh instance prims
	MRFreeMem(mesh_inst->mi_prims[0]);

	// Remove instance from viewport's mesh instance list
	mesh_inst->mi_prev_node->mi_next_node = mesh_inst->mi_next_node;
	if	(mesh_inst->mi_next_node)
		mesh_inst->mi_next_node->mi_prev_node = mesh_inst->mi_prev_node;

#ifdef BUILD_49
	// Kill the mesh if there are no more instances hanging around
	if (!(--mesh_inst->mi_object->ob_vp_inst_count))
		MRKillMesh(mesh_inst->mi_object);
#else
	// Kill the mesh if there are no more instances hanging around
	if (mesh_inst->mi_kill_timer == 0)
		{
		if (!(--mesh_inst->mi_object->ob_vp_inst_count))
			MRKillMesh(mesh_inst->mi_object);
		}
#endif

	// Free memory for instance structure
	MRFreeMem(mesh_inst);
}


/******************************************************************************
*%%%% MRRemove3DSpriteInstanceFromViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemove3DSpriteInstanceFromViewport(
*						MR_3DSPRITE_INST*	sprite_inst,
*						MR_VIEWPORT*		viewport);
*
*	FUNCTION	Removes an instance of a 3D sprite from the specified viewport.
*
*	INPUTS		sprite_inst	-	Pointer to valid MR_3DSPRITE_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemove3DSpriteInstanceFromViewport(	MR_3DSPRITE_INST*	sprite_inst,
												MR_VIEWPORT*		viewport)
{
	MR_ASSERT(sprite_inst != NULL);
	MR_ASSERT(viewport != NULL);

	sprite_inst->si_object->ob_vp_inst_count--;
	sprite_inst->si_kill_timer = 2;
}


/******************************************************************************
*%%%% MRRemove3DSpriteInstanceFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemove3DSpriteInstanceFromViewportPhysically(
*						MR_3DSPRITE_INST*	sprite_inst,
*						MR_VIEWPORT*		viewport);
*
*	FUNCTION	Removes an instance of a 3D sprite from the specified viewport,
*				immediately (frees polygon memory, and structures)
*
*	INPUTS		sprite_inst	-	Pointer to valid MR_3DSPRITE_INST structure
*				viewport  	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemove3DSpriteInstanceFromViewportPhysically(	MR_3DSPRITE_INST*	sprite_inst,
							 							MR_VIEWPORT*		viewport)
{
#ifdef BUILD_49
	MR_USHORT	flags;
#else
	MR_USHORT	flags = NULL;
#endif

	MR_ASSERT(sprite_inst != NULL);
	MR_ASSERT(viewport != NULL);

	// Remove sprite instance from viewport's 3d sprite instance list
	sprite_inst->si_prev_node->si_next_node = sprite_inst->si_next_node;
	if	(sprite_inst->si_next_node)
		sprite_inst->si_next_node->si_prev_node = sprite_inst->si_prev_node;

#ifdef BUILD_49
	flags = sprite_inst->si_object->ob_flags;

	// Kill sprite if there are no more instances...
	if (!(--sprite_inst->si_object->ob_vp_inst_count))
		MRKill3DSprite(sprite_inst->si_object);
#else
	// Kill sprite if there are no more instances...
	if (sprite_inst->si_kill_timer == 0)
		{
		flags = sprite_inst->si_object->ob_flags;
		if (!(--sprite_inst->si_object->ob_vp_inst_count))
			MRKill3DSprite(sprite_inst->si_object);
		}
#endif

#ifdef MR_MEMFIXED_3DSPRITE
	if (!(flags & MR_OBJ_MEMFIXED_WITH_INSTS))
#endif
	// Free memory for instance structure
	MRFreeMem(sprite_inst);
}


/******************************************************************************
*%%%% MRRemovePgenInstanceFromViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemovePgenInstanceFromViewport(
*						MR_PGEN_INST*	pgen_inst,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an instance of a particle generator from the specified
*				viewport.
*
*	INPUTS		pgen_inst	-	Pointer to valid MR_PGEN_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemovePgenInstanceFromViewport(	MR_PGEN_INST*	pgen_inst,
											MR_VIEWPORT*	viewport)
{
	MR_ASSERT(pgen_inst != NULL);
	MR_ASSERT(viewport != NULL);

	pgen_inst->pi_object->ob_vp_inst_count--;
	pgen_inst->pi_kill_timer = 2;
}


/******************************************************************************
*%%%% MRRemovePgenInstanceFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemovePgenInstanceFromViewportPhysically(
*						MR_PGEN_INST*	pgen_inst,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an instance of a particle generator from the specified
*				viewport immediately.
*
*	INPUTS		pgen_inst	-	Pointer to valid MR_PGEN_INST structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemovePgenInstanceFromViewportPhysically(	MR_PGEN_INST*	pgen_inst,
							 						MR_VIEWPORT*	viewport)
{
#ifdef BUILD_49
	MR_USHORT	flags;
#else
	MR_USHORT	flags = 0;
#endif

	MR_ASSERT(pgen_inst != NULL);
	MR_ASSERT(viewport != NULL);

	// Remove pgen instance from viewport's 3d pgen instance list
	pgen_inst->pi_prev_node->pi_next_node = pgen_inst->pi_next_node;
	if	(pgen_inst->pi_next_node)
		pgen_inst->pi_next_node->pi_prev_node = pgen_inst->pi_prev_node;

	flags = pgen_inst->pi_object->ob_flags;

#ifdef BUILD_49
	// Kill pgen if there are no more instances...
	if (!(--pgen_inst->pi_object->ob_vp_inst_count))
		MRKillPgen(pgen_inst->pi_object);
#else
	// Kill pgen if there are no more instances...
	if (pgen_inst->pi_kill_timer == 0)
		{
		flags = pgen_inst->pi_object->ob_flags;
		if (!(--pgen_inst->pi_object->ob_vp_inst_count))
			MRKillPgen(pgen_inst->pi_object);
		}
#endif

	// Free memory for instance structure
	MRFreeMem(pgen_inst);
}


/******************************************************************************
*%%%% MRRemove2DSpriteFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemove2DSpriteFromViewportPhysically(
*						MR_2DSPRITE*	sprite,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes an 2D sprite from the specified viewport,
*				immediately (frees polygon memory, and structures)
*
*	INPUTS		sprite		-	Pointer to valid MR_2DSPRITE structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	09.07.96	Dean Ashton		Changed link pointers for 2D sprites
*
*%%%**************************************************************************/

MR_VOID	MRRemove2DSpriteFromViewportPhysically(	MR_2DSPRITE* sprite,
							 					MR_VIEWPORT* viewport)
{
	MR_ASSERT(sprite != NULL);
	MR_ASSERT(viewport != NULL);

	// Remove from the viewport
	sprite->sp_core.sc_prev_node->sc_next_node = sprite->sp_core.sc_next_node;
	if	(sprite->sp_core.sc_next_node)
		sprite->sp_core.sc_next_node->sc_prev_node = sprite->sp_core.sc_prev_node;
	
	MRFreeMem(sprite);
}


/******************************************************************************
*%%%% MRRemoveTextAreaFromViewportPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRemoveTextAreaFromViewportPhysically(
*						MR_TEXT_AREA*	textarea,
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Removes a text area from the specified viewport,
*				immediately (frees polygon memory, and structures)
*
*	INPUTS		textarea	-	Pointer to valid MR_TEXT_AREA structure
*				viewport	-	Pointer to the MR_VIEWPORT to remove from
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRemoveTextAreaFromViewportPhysically(	MR_TEXT_AREA*	textarea,
								   				MR_VIEWPORT*	viewport)
{
	MR_ASSERT(textarea != NULL);
	MR_ASSERT(viewport != NULL);

	// Remove the area from the list

	textarea->ta_prev_node->ta_next_node = textarea->ta_next_node;
	if	(textarea->ta_next_node)
		textarea->ta_next_node->ta_prev_node = textarea->ta_prev_node;
	
	// Free memory associated with the area

	MRFreeMem(textarea);
}


/******************************************************************************
*%%%% MRRenderViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRenderViewport(
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Renders all objects linked to the specified viewport, calling
*				object specific display routines
*
*	INPUTS		vp			-	Pointer to a the MR_VIEWPORT to render
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	09.07.96	Dean Ashton		Changed link pointers for 2D sprites
*	14.01.97	Tim Closs		Altered to cope with new linked list of environment
*								instances hanging off MR_VIEWPORT
*	26.02.97	Tim Closs		Mesh instances now have prims in one allocation
*	06.06.97	Dean Ashton		Fixed bug to do with anim environment instance removal
*								(was removing mesh instances too early!)
*
*%%%**************************************************************************/

MR_VOID	MRRenderViewport(MR_VIEWPORT* vp)
{
	MR_USHORT			flags;
	
	// Ptrs for linked lists of structures
	MR_ANIM_ENV_INST*	env_inst;
	MR_MESH_INST*		mesh_inst;
	MR_MESH*			mesh_ptr;
	MR_3DSPRITE_INST*	sp3dinst_ptr;
	MR_2DSPRITE*		sprite2d_ptr;
	MR_TEXT_AREA*		text_area_ptr;
	MR_PGEN_INST*		pgeninst_ptr;
	MR_LIGHT_INST*		light_inst;
	MR_LIGHT*			light_ptr;

	// 'Previous' ptrs
	MR_ANIM_ENV_INST*	env_inst_prev_ptr;
	MR_MESH_INST*		mesh_inst_prev_ptr;
	MR_3DSPRITE_INST*	sp3dinst_prev_ptr;
	MR_2DSPRITE*		sprite2d_prev_ptr;
	MR_TEXT_AREA*		text_area_prev_ptr;
	MR_PGEN_INST*		pgeninst_prev_ptr;
	MR_LIGHT_INST*		light_inst_prev_ptr;


	MR_ASSERT(vp != NULL);

#ifdef MR_DEBUG
	MRRendered_meshes	= 0;
	MRListed_meshes		= 0;
#endif

	//	Initial: Process all lights for the viewport
	light_inst = vp->vp_light_root_ptr;

	while(light_inst = light_inst->li_next_node)
		{
		if (light_inst->li_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
			{
			// Remove light instance from viewport
			light_inst_prev_ptr = light_inst->li_prev_node;
			MRRemoveLightInstanceFromViewportPhysically(light_inst, vp);
			light_inst = light_inst_prev_ptr;
			}
		else
			{
		
			// If the light has changed direction/colour, we need to rebuild the viewport lighting matrix
			light_ptr = light_inst->li_object->ob_extra.ob_extra_light;
			if (light_ptr->li_flags & MR_LIGHT_CHANGED_DIRECTION) 
				vp->vp_flags |= MR_VP_REBUILD_LIGHT_MATRIX;
			if (light_ptr->li_flags & MR_LIGHT_CHANGED_COLOURS) 
				vp->vp_flags |= MR_VP_REBUILD_COLOUR_MATRIX;
			}
		}


	// Update light matrix if necessary
	if (vp->vp_flags & MR_VP_REBUILD_LIGHT_MATRIX)
		{
		MRUpdateViewportLightMatrix(vp);
		vp->vp_flags &= ~MR_VP_REBUILD_LIGHT_MATRIX;
		}

	// Update colour matrix if necessary
	if (vp->vp_flags & MR_VP_REBUILD_COLOUR_MATRIX)
		{
		MRUpdateViewportColourMatrix(vp);
		vp->vp_flags &= ~MR_VP_REBUILD_COLOUR_MATRIX;
		}


	// Set geometry variables for this Viewport
	gte_SetGeomOffset(vp->vp_geom_x, vp->vp_geom_y);
	gte_SetGeomScreen(vp->vp_perspective);

	// Set fogging parameters for this Viewport
	gte_SetFarColor(vp->vp_fog_colour.r, vp->vp_fog_colour.g, vp->vp_fog_colour.b);
	SetFogNearFar(vp->vp_fog_near_dist, vp->vp_fog_far_dist, vp->vp_perspective);	// Set user fog values

	// Set ambient and lighting colours for this Viewport
	gte_SetColorMatrix(&vp->vp_colour_matrix);
	gte_SetBackColor(vp->vp_back_colour.r,
						  vp->vp_back_colour.g,
						  vp->vp_back_colour.b);
	
	// Set up viewport variables in fastram
	MRVp_ptr				= vp;
	MRVp_otz_shift			= vp->vp_otz_shift;
	MRVp_ot_size 			= vp->vp_ot_size;
	MRVp_fog_near_distance	= vp->vp_fog_near_dist;
	MRVp_fog_far_distance	= vp->vp_fog_far_dist;
	MRVp_work_ot 			= vp->vp_work_ot;
	MRVp_disp_w		 		= vp->vp_disp_inf.w;
	MRVp_disp_h		 		= vp->vp_disp_inf.h;

	// Make sure the LW matrix is rebuilt first time
	MRWorldtrans_ptr 		= NULL;


	//	Step 0: Process all animation environment instances
	env_inst = vp->vp_env_root_ptr;
	while(env_inst = env_inst->ae_next_node)
		{
		if (env_inst->ae_kill_timer)
			{
			if (!(--env_inst->ae_kill_timer))
				{
				// Remove instance from viewport's environment instance list
				env_inst->ae_prev_node->ae_next_node = env_inst->ae_next_node;
				if	(env_inst->ae_next_node)
					env_inst->ae_next_node->ae_prev_node = env_inst->ae_prev_node;

				// Free memory for instance structure
				env_inst_prev_ptr = env_inst->ae_prev_node;
				MRFreeMem(env_inst);
				env_inst = env_inst_prev_ptr;

				// NOTE: we have NOT deleted the actual environment structure, or mesh objects here
		
				}
			}
		else
			{
			if (env_inst->ae_environment->ae_flags & MR_ANIM_ENV_DESTROY_BY_DISPLAY)
				{
				// Environment is flagged as 'destroy by display', ie. each time we are asked to display
				// an instance, decrease the environment's count by 1 and destroy when 0

				// Remove instance from viewport. Note that we're not calling MRAnimRemoveEnvInstanceFromViewport(),
				// as that would perform a removal of all of the environment instances mesh instances. If people
				// call MRAnimEnvDestroyByDisplay() then this will work fine, as the objects would be destroyed along
				// with their instances.
				env_inst->ae_environment->ae_vp_inst_count--;
				env_inst->ae_kill_timer = 2;

				if (!(env_inst->ae_environment->ae_vp_inst_count))
					{
					// Physically kill environment structure
					MRAnimKillEnv(env_inst->ae_environment);
					}
				}
			}
		}

	//	Step 1: Process all meshes
	mesh_inst = vp->vp_mesh_root_ptr;
	while(mesh_inst = mesh_inst->mi_next_node)
		{
		// Reset mesh instance displayed flag
		mesh_inst->mi_flags &= ~MR_MESH_INST_DISPLAYED_LAST_FRAME;
		if (mesh_inst->mi_kill_timer)
			{
			// Forbid display
			if (!(--mesh_inst->mi_kill_timer))
				{
				// Free all mesh instance prims
				MRFreeMem(mesh_inst->mi_prims[0]);

				// Remove instance from viewport's mesh instance list
				mesh_inst->mi_prev_node->mi_next_node = mesh_inst->mi_next_node;
				if	(mesh_inst->mi_next_node)
					mesh_inst->mi_next_node->mi_prev_node = mesh_inst->mi_prev_node;

				// Free memory for instance structure
				mesh_inst_prev_ptr = mesh_inst->mi_prev_node;
				MRFreeMem(mesh_inst);
				mesh_inst = mesh_inst_prev_ptr;

				// NOTE: we have NOT deleted the actual mesh object here... although it may have
				// previously been deleted by the code below
				}
			}
		else
			{
			if (mesh_inst->mi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
				{
				// Mesh is flagged as 'destroy by display', ie. each time we are asked to display
				// an instance, decrease the object's count by 1 and destroy when 0

				// Remove instance from viewport
				MRRemoveMeshInstanceFromViewport(mesh_inst, vp);

				if (!(mesh_inst->mi_object->ob_vp_inst_count))
					{
					// Physically kill mesh object
					MRKillMesh(mesh_inst->mi_object);
					}
				}
			else
				{
				// Display mesh 
				if (!(mesh_inst->mi_object->ob_flags & MR_OBJ_NO_DISPLAY))
					{
					mesh_ptr = mesh_inst->mi_object->ob_extra.ob_extra_mesh;
					if (mesh_ptr->me_flags & MR_MESH_ANIMATED)
						{
						MRAnimDisplayMeshInstance(	mesh_inst,
													vp);
						}
					else
						{
						MRStaticDisplayMeshInstance(mesh_inst,
													vp,
													mesh_ptr->me_extra.me_extra_static_mesh->sm_part,
													mesh_ptr->me_extra.me_extra_static_mesh->sm_partcel);
						}
#ifdef	MR_DEBUG
					MRListed_meshes++;
#endif
					}
				}
			}
		}

	//	Step 2: Process all 3D sprites (this is just the rendering stage)

	sp3dinst_ptr = vp->vp_3dsprite_root_ptr;

	while(sp3dinst_ptr = sp3dinst_ptr->si_next_node)
		{
		if (sp3dinst_ptr->si_kill_timer)
			{
			// Forbid display
			if (!(--sp3dinst_ptr->si_kill_timer))
				{
				// Remove instance from viewport's 3D sprite instance list
				sp3dinst_ptr->si_prev_node->si_next_node = sp3dinst_ptr->si_next_node;
				if	(sp3dinst_ptr->si_next_node)
					sp3dinst_ptr->si_next_node->si_prev_node = sp3dinst_ptr->si_prev_node;

				// Free memory for sprite instance structure
				sp3dinst_prev_ptr = sp3dinst_ptr->si_prev_node;

				flags = sp3dinst_ptr->si_object->ob_flags;
				if (!(--sp3dinst_ptr->si_object->ob_vp_inst_count))
					{
					// Physically kill sprite object
					MRKill3DSprite(sp3dinst_ptr->si_object);
					}

#ifdef MR_MEMFIXED_3DSPRITE
				if (!(flags & MR_OBJ_MEMFIXED_WITH_INSTS))
#endif
				MRFreeMem(sp3dinst_ptr);

				sp3dinst_ptr = sp3dinst_prev_ptr;
				}
			}
		else
			{
			if (sp3dinst_ptr->si_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
				{
				// 3D sprite is flagged as 'destroy by display', ie. each time we are asked to display
				// an instance, decrease the object's count by 1 and destroy when 0
				sp3dinst_ptr->si_kill_timer = 2;
				}
			else
				{
				// Display sprite
				if (!(sp3dinst_ptr->si_object->ob_flags & MR_OBJ_NO_DISPLAY))
					MRDisplay3DSpriteInstance(sp3dinst_ptr, vp);
				}
			}
		}
	
	//	Step 3: Process all 2D sprites (this does animation list processing, and rendering)

	sprite2d_ptr = vp->vp_2dsprite_root_ptr;

	while(sprite2d_ptr = ((MR_2DSPRITE*)(sprite2d_ptr->sp_core.sc_next_node)))
		{
		if (sprite2d_ptr->sp_kill_timer)
			{
			if (!(--sprite2d_ptr->sp_kill_timer))
				{
				sprite2d_ptr->sp_core.sc_prev_node->sc_next_node = sprite2d_ptr->sp_core.sc_next_node;
				if	(sprite2d_ptr->sp_core.sc_next_node)
					sprite2d_ptr->sp_core.sc_next_node->sc_prev_node = sprite2d_ptr->sp_core.sc_prev_node;

				// Free memory for sprite instance structure
				sprite2d_prev_ptr = (MR_2DSPRITE*)(sprite2d_ptr->sp_core.sc_prev_node);
				MRFreeMem(sprite2d_ptr);
				sprite2d_ptr = sprite2d_prev_ptr;
				}
			}
		else
			{
			MRDisplay2DSprite(sprite2d_ptr, vp);
			}
		}


	//	Step 4: Process all text areas linked to this viewport

	text_area_ptr = vp->vp_text_area_root_ptr;

	while(text_area_ptr = text_area_ptr->ta_next_node)
		{
		if (text_area_ptr->ta_kill_timer)
			{
			if (!(--text_area_ptr->ta_kill_timer))
				{
				text_area_ptr->ta_prev_node->ta_next_node = text_area_ptr->ta_next_node;
				if	(text_area_ptr->ta_next_node)
					text_area_ptr->ta_next_node->ta_prev_node = text_area_ptr->ta_prev_node;

				// Free memory for text area structure
				text_area_prev_ptr = text_area_ptr->ta_prev_node;
				MRFreeMem(text_area_ptr);
				text_area_ptr = text_area_prev_ptr;
				}
			}
		else
			MRRenderTextArea(text_area_ptr);
		}


	// Step 5: Process any effect linked to this viewport

	if (vp->vp_effect.fx_type)
		MRProcessEffect(vp);


	//	Step 6: Process all particle generator instances (only the primitives!)

	pgeninst_ptr = vp->vp_pgen_root_ptr;

	while(pgeninst_ptr = pgeninst_ptr->pi_next_node)
		{
		if (pgeninst_ptr->pi_kill_timer)
			{
			// Forbid display
			if (!(--pgeninst_ptr->pi_kill_timer))
				{
				// Remove instance from viewport's pgen instance list
				pgeninst_ptr->pi_prev_node->pi_next_node = pgeninst_ptr->pi_next_node;
				if	(pgeninst_ptr->pi_next_node)
					pgeninst_ptr->pi_next_node->pi_prev_node = pgeninst_ptr->pi_prev_node;

				// Free memory for instance structure
				pgeninst_prev_ptr = pgeninst_ptr->pi_prev_node;

				flags = pgeninst_ptr->pi_object->ob_flags;
				if (!(--pgeninst_ptr->pi_object->ob_vp_inst_count))
					{
					// Physically kill pgen object
					MRKillPgen(pgeninst_ptr->pi_object);
					}

#ifdef MR_MEMFIXED_PGEN
				if (!(flags & MR_OBJ_MEMFIXED_WITH_INSTS))
#endif
				MRFreeMem(pgeninst_ptr);

				pgeninst_ptr = pgeninst_prev_ptr;
				}
			}
		else
			{
			if (pgeninst_ptr->pi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
				{
				// pgen is flagged as 'destroy by display', ie. each time we are asked to display
				// an instance, decrease the object's count by 1 and destroy when 0
				pgeninst_ptr->pi_kill_timer = 2;
				}
			else
				{
				// Display pgen instance primitives
				(pgeninst_ptr->pi_object->ob_extra.ob_extra_pgen->pg_disp_callback)(pgeninst_ptr, vp);
				}
			}
		}

	vp->vp_frame_count++;
}


/******************************************************************************
*%%%% MRUpdateViewportRenderMatrices
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateViewportRenderMatrices(MR_VOID);
*
*	FUNCTION	Updates each viewports 'vp_render_matrix'. This is part of a
*				system which allows aspect ratio manipulation.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	25.05.97	Dean Ashton		Doesn't perform illegal memory access when no
*								camera is defined for viewport
*
*%%%**************************************************************************/

MR_VOID	MRUpdateViewportRenderMatrices(MR_VOID)
{
	MR_VIEWPORT*	vp = MRViewport_root_ptr;
	MR_MAT			matrix;


	while(vp = vp->vp_next_node)
		{
		if (vp->vp_camera)
			{
			if (vp->vp_flags & MR_VP_NO_ASPECT)
				{
				MRTransposeMatrix(&vp->vp_camera->fr_lw_transform, &vp->vp_render_matrix);
				}
			else
				{
				MRTransposeMatrix(&vp->vp_camera->fr_lw_transform, &matrix);
				MRMulMatrixABC(&vp->vp_aspect_matrix, &matrix, &vp->vp_render_matrix);
				}
			MR_COPY_VEC(vp->vp_render_matrix.t, vp->vp_camera->fr_lw_transform.t);	
			}
		}
}


/******************************************************************************
*%%%% MRUpdateViewport2DSpriteAnims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdateViewport2DSpriteAnims(
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Performs animation updates on all 2D sprites linked to the
*				specified viewport.
*
*	INPUTS		vp			-		Viewport pointer
*
*	NOTES		This processing used to be in MRRenderViewport(), but was
*				moved so that project-specific pause code could inhibit the
*				update of 2D sprite animations. 3D sprites have their update
*				called from MRUpdateObjects()
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRUpdateViewport2DSpriteAnims(MR_VIEWPORT* vp)
{
	MR_2DSPRITE*	sprite2d_ptr;

	MR_ASSERT(vp);

	sprite2d_ptr = vp->vp_2dsprite_root_ptr;

	while(sprite2d_ptr = ((MR_2DSPRITE*)(sprite2d_ptr->sp_core.sc_next_node)))
		{
		// No point processing animations for sprites that are dying..
		if (sprite2d_ptr->sp_kill_timer == 0)
			MRProcessSpriteAnim(&sprite2d_ptr->sp_core);
		}

}

/******************************************************************************
*%%%% MRSetViewportAspect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetViewportAspect(
*						MR_VIEWPORT*	vp,
*						MR_MAT*			aspect);
*
*	FUNCTION	Sets the specified viewport aspect matrix. 
*
*	INPUTS		vp	  		-	Pointer to a valid MR_VIEWPORT structure
*				aspect		-	Pointer to an aspect matrix.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetViewportAspect(MR_VIEWPORT* vp, MR_MAT* aspect)
{
	MR_ASSERT(vp != NULL);
	MR_ASSERT(aspect != NULL);

	// Copy the aspect matrix
	MR_COPY_MAT(&vp->vp_aspect_matrix, aspect);

	// This viewport now has a non-standard aspect
	vp->vp_flags &= ~MR_VP_NO_ASPECT;
}


/******************************************************************************
*%%%% MRResetViewportAspect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResetViewportAspect(
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Sets the specified viewport aspect matrix to 'I' (identity
*				matrix).
*
*	INPUTS		vp	  		-	Pointer to a valid MR_VIEWPORT structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRResetViewportAspect(MR_VIEWPORT* vp)
{
	MR_ASSERT(vp != NULL);

	// Init the aspect matrix
	MR_INIT_MAT(&vp->vp_aspect_matrix);

	// This viewport now has standard aspect
	vp->vp_flags |= MR_VP_NO_ASPECT;
}


/******************************************************************************
*%%%% MRSetActiveViewport
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetActiveViewport(MR_VIEWPORT* vp);
*
*	FUNCTION	Sets up required GTE registers to enable user code to use a 
*				viewport in the same manner as MRRenderViewport. After calling
*				this function the GTE screen/light/fog information is correctly
*				setup, and also the following common variables (held on the data
*				cache) are available. 
*				
*					MRVp_otz_shift			-	Use to shift down GTE 'Z' into OTZ range
*					MRVp_ot_size			-	Use to clip shifted otz into OTZ limits
*					MRVp_work_ot			-	A pointer to the viewport work OT
*					MRVp_fog_near_distance	-  Fog near distance
*					MRVp_fog_far_distance	-  Fog far distance
*					MRVp_disp_w				-	Width of viewport
*					MRVp_dish_h				-	Height of viewport
*
*	INPUTS		vp							-	Pointer to a valid MR_VIEWPORT
*
*	NOTES		The MRVp_fog_distance value can be handy in eliminating excess 
*				depth queuing calculations. Just compare the GTE 'Z' (prior to
*				shifting) with MRVp_fog_distance. If it's less than the 
*				MRVp_fog_distance value (actually it's the NEAR distance), then
*				don't bother doing the calcs... mucho speedup, senor... :)
*				Also, if the GTE 'Z' (prior to shifting) is greater than the fog
*				far distance, then you can probably bin the polygon.. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.10.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetActiveViewport(MR_VIEWPORT* vp)
{
	MR_ASSERT(vp != NULL);

	// Set up stuff for this Viewport
	gte_SetGeomOffset(vp->vp_geom_x, vp->vp_geom_y);
	gte_SetGeomScreen(vp->vp_perspective);

	gte_SetFarColor(vp->vp_fog_colour.r, vp->vp_fog_colour.g, vp->vp_fog_colour.b);

	SetFogNearFar(vp->vp_fog_near_dist, vp->vp_fog_far_dist, vp->vp_perspective);	// Set user fog values

	gte_SetColorMatrix(&vp->vp_colour_matrix);
	gte_SetBackColor(vp->vp_back_colour.r,
						  vp->vp_back_colour.g,
						  vp->vp_back_colour.b);

	// Set up viewport variables in fastram
	MRVp_ptr				= vp;
	MRVp_otz_shift			= vp->vp_otz_shift;
	MRVp_ot_size 			= vp->vp_ot_size;
	MRVp_fog_near_distance	= vp->vp_fog_near_dist;
	MRVp_fog_far_distance	= vp->vp_fog_far_dist;
	MRVp_work_ot 			= vp->vp_work_ot;
	MRVp_disp_w		 		= vp->vp_disp_inf.w;
	MRVp_disp_h		 		= vp->vp_disp_inf.h;

}


/******************************************************************************
*%%%% MRSetViewportFogColour
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	success =	MRSetViewportFogColour(
*							 		MR_VIEWPORT*	viewport,
*							 		MR_UBYTE		red,
*							 		MR_UBYTE		green,
*							 		MR_UBYTE		blue);
*
*	FUNCTION	Sets a viewports fog colour.
*
*	INPUTS		viewport	-	Pointer to viewport
*				red			-	Red colour component of fog
*				green		-	Green colour component of fog
*				blue		-	Blue colour component of fog
*
*	RESULT		success		-	TRUE if it worked (always TRUE on PSX)	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.96	Dean Ashton		Created at request of Derek Pollard.
*
*%%%**************************************************************************/

MR_BOOL	MRSetViewportFogColour(	MR_VIEWPORT*	viewport,
								MR_UBYTE		red,
								MR_UBYTE		green,
								MR_UBYTE		blue)
{
	MR_ASSERT(viewport != NULL);

	viewport->vp_fog_colour.r = red;
	viewport->vp_fog_colour.g = green;
	viewport->vp_fog_colour.b = blue;

	return(TRUE);
}


/******************************************************************************
*%%%% MRSetViewportFogDistances
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	success =	MRSetViewportFogDistances(
*									MR_VIEWPORT*	viewport,
*									MR_ULONG		near_distance,
*									MR_ULONG		far_distance);
*
*	FUNCTION	Sets a viewports fog colour.
*
*	INPUTS		viewport		-	Pointer to viewport
*				near_distance	-	Fog distance (0 disables fogging)
*				far_distance	-	Not implemented on PlayStation.
*
*	RESULT		success			-	TRUE if it worked
*
*	NOTES		Notice that a near_distance of zero disables fogging on models.
*				Also remember that (near-far) >= 100, as this is a requirement
*				within the PlayStation SetFogNearFar() function.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.96	Dean Ashton		Created at request of Derek Pollard.
*	01.10.96	Dean Ashton		Implemented independent near/far distances as on
*								PC version
*
*%%%**************************************************************************/

MR_BOOL	MRSetViewportFogDistances(	MR_VIEWPORT*	viewport,
									MR_ULONG		near_distance,
									MR_ULONG		far_distance)
{
	MR_ASSERT(viewport != NULL);

	MR_ASSERT((far_distance-near_distance) >= 100);

	viewport->vp_fog_near_dist	= near_distance;
	viewport->vp_fog_far_dist	= far_distance;

	return(TRUE);
}


/******************************************************************************
*%%%% MRSetViewportViewDistance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetViewportViewDistance(
*						MR_VIEWPORT*	viewport,
*						MR_USHORT		distance_id);
*
*	FUNCTION	Sets a viewports view distance, allowing a limited view distance
*				to take more advantage of OT slots. Any polygons past the view 
*				distance are not rendered.
*
*	INPUTS		viewport   	-	Pointer to viewport
*				distance_id	-	Distance ID (eg MR_VP_VIEWDIST_8192)	
*
*	NOTES		'distance_id' is actually a bit count modifier. Do not change
*				the define values in mr_big.h unless you know what you're doing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.10.96	Dean Ashton		Created
*	19.12.96	Dean Ashton		Fixed bug in the assert
*
*%%%**************************************************************************/

MR_VOID	MRSetViewportViewDistance(	MR_VIEWPORT*	viewport,
									MR_USHORT		distance_id)
{
	MR_ASSERT(viewport != NULL);

	MR_ASSERT(15 - distance_id - viewport->vp_ot_size_bits >= 0);		// Check for valid view distance scaling

	viewport->vp_view_distance = 1<<(15-distance_id);
	viewport->vp_otz_shift = (15 - distance_id-viewport->vp_ot_size_bits);
}


