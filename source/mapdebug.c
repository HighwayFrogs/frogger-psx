/******************************************************************************
*%%%% mapdebug.c
*------------------------------------------------------------------------------
*
*	Map Debug stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#include "mapdebug.h"
#include "mapview.h"
#include "grid.h"
#include "main.h"
#include "frog.h"


MR_BOOL				Map_debug_options_show 	= FALSE;		// Are we displaying/using the options dialog box

#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
MR_VIEWPORT*		Map_debug_main_viewport;			// Full screen viewport, suitable for text and grid display
POLY_F4				Map_debug_polys[2][MAP_MAX_POLY_GROUPS];

MR_VIEWPORT*		Map_debug_options_viewport;			// Option selection viewport, so we can have a snazzy scrolly text area
MR_TEXT_AREA*		Map_debug_options_title_area;		// Text area for options title bar
POLY_F4				Map_debug_options_bg_poly[2];		// Background for options area
LINE_F3				Map_debug_options_bg_line_0[2];		// Highlight line for top area
LINE_F3				Map_debug_options_bg_line_1[2];		// Shadow line for top area
LINE_F3				Map_debug_options_bg_line_2[2];		// Highlight line for bottom area
LINE_F3				Map_debug_options_bg_line_3[2];		// Shadow line for bottom area

MR_STRPTR			Map_debug_options_title_text[] =
					{
					"Frogger Debug V1.0", NULL
					};

// Option lines
MR_STRPTR			Map_debug_optline_select_char = ">";
MR_STRPTR			Map_debug_optline_select_none = " ";
MR_STRPTR			Map_debug_optline_select_insert;
MR_STRPTR			Map_debug_optline_text_insert;

MR_ULONG			Map_debug_optline_colour;

MR_STRPTR			Map_debug_optline_build_input[] =
					{
					"%c%s%C%s\n",	(MR_STRPTR)MR_FONT_COLOUR_YELLOW,
									(MR_STRPTR)&Map_debug_optline_select_insert,
									(MR_STRPTR)&Map_debug_optline_colour,
									(MR_STRPTR)&Map_debug_optline_text_insert,
					NULL
					};

MR_ULONG			Map_debug_optlines_selected;
MR_ULONG			Map_debug_optlines_count;

MAP_DEBUG_OPTLINE	Map_debug_optlines[] = 
					{
						{	MOPTLINE_ROOT, FALSE,	" Display map group grid\n" },
								{	MOPTLINE_SUB,	FALSE,	"      Display active groups\n" },
								{	MOPTLINE_SUB,	FALSE,	"      Display current group\n" },
								{	MOPTLINE_ROOT,	FALSE,	"    Use custom grid scaling\n" },
						{	MOPTLINE_ROOT,	FALSE,	" Show map poly count\n" },
						{	MOPTLINE_ROOT,	FALSE,	" Show live path ent count\n" },
						{	MOPTLINE_ROOT,	FALSE,	" Show live stat ent count\n" },
						{	MOPTLINE_ROOT,	FALSE,	" Show live path ent poly count\n" },
						{	MOPTLINE_ROOT,	FALSE,	" Show live stat ent poly count\n" },
#ifdef WIN95
						{	MOPTLINE_ROOT,	TRUE,	" Show frame rate\n" },
						{	MOPTLINE_ROOT,	TRUE,	" Show frame count\n" },
#endif
						{	MOPTLINE_END	},
					};

MR_LONG				Map_debug_scale_size = MAP_DEBUG_SCALE_INITIAL;

MR_TEXT_AREA*		Map_debug_show_text_area;
MR_STRPTR			Map_debug_show_map_poly_count_tag			=	"%c     Map Polys:%c%0w\n";
MR_STRPTR			Map_debug_show_live_path_ent_count_tag		=	"%c     Path Ents:%c%0w\n";
MR_STRPTR			Map_debug_show_live_stat_ent_count_tag		=	"%c     Stat Ents:%c%0w\n";
MR_STRPTR			Map_debug_show_live_path_ent_poly_count_tag	=	"%cPath Ent Polys:%c%0w\n";
MR_STRPTR			Map_debug_show_live_stat_ent_poly_count_tag	=	"%cStat Ent Polys:%c%0w\n";
#ifdef WIN95
MR_STRPTR			Map_debug_show_frame_rate					=	"%c    Frame rate:%c%0w\n";
MR_STRPTR			Map_debug_show_frame_count					=	"%c   Frame count:%c%0w\n";
#endif

MR_STRPTR			Map_debug_show_buff[(MAP_DEBUG_SHOW_MAX_LINES*5)+1];	// 5 MR_STRPTR's per show line, and a null terminator

#endif	// MR_DEBUG_DISPLAY

// MR_LONGs for debug variables go here
MR_LONG				Map_debug_land_polys;
MR_LONG				Map_debug_poly_groups;
					
MR_LONG				Map_debug_live_path_ents;
MR_LONG				Map_debug_live_stat_ents;
MR_LONG				Map_debug_live_path_ent_polys;
MR_LONG				Map_debug_live_stat_ent_polys;

#ifdef WIN95					
MR_LONG				Map_debug_frame_rate;
#endif

#endif	// MR_DEBUG

/******************************************************************************
*%%%% InitialiseMapDebugDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseMapDebugDisplay(MR_VOID)
*
*	FUNCTION	Performs setup operations to enable the display of debug
*				data.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.04.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed RECT to MR_RECT
*
*%%%**************************************************************************/

MR_VOID	InitialiseMapDebugDisplay(MR_VOID)
{			
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_RECT				temp_rect;
	MR_LONG				loop;
	MAP_DEBUG_OPTLINE*	optline_ptr;
	MR_LONG				optline_y;
	MR_BOOL				optline_last_root_active = TRUE;
	POLY_F4*			poly_f4;

	// Create full screen viewport for general debug output. Keep it small too, to increase OT clear/draw speed
	Map_debug_main_viewport = MRCreateViewport(NULL, NULL, MR_VP_SIZE_32, 0);
	
	// Setup camera 
	Map_debug_main_viewport->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);

	// Create the options dialog polygons on the main viewport
	for (loop = 0; loop < 2; loop++)
		{
		setPolyF4(&Map_debug_options_bg_poly[loop]);
		setRGB0(&Map_debug_options_bg_poly[loop], 0x60,0x60,0x60);
		setXYWH(&Map_debug_options_bg_poly[loop],
				MAP_DEBUG_OPTION_X,
				MAP_DEBUG_OPTION_Y,
				MAP_DEBUG_OPTION_WIDTH,
				(MAP_DEBUG_OPTION_TITLE_HEIGHT + MAP_DEBUG_OPTION_MAIN_HEIGHT));

		setLineF3(&Map_debug_options_bg_line_0[loop]);
		setRGB0(&Map_debug_options_bg_line_0[loop], 0xd0,0xd0,0xd0);
		setXY3(&Map_debug_options_bg_line_0[loop],
				MAP_DEBUG_OPTION_X, (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT),
				MAP_DEBUG_OPTION_X, MAP_DEBUG_OPTION_Y,
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH - 1), MAP_DEBUG_OPTION_Y);

		setLineF3(&Map_debug_options_bg_line_1[loop]);
		setRGB0(&Map_debug_options_bg_line_1[loop], 0x40,0x40,0x40);
		setXY3(&Map_debug_options_bg_line_1[loop],
				MAP_DEBUG_OPTION_X, (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT),
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH-1), (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT),
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH-1), MAP_DEBUG_OPTION_Y);

		setLineF3(&Map_debug_options_bg_line_2[loop]);
		setRGB0(&Map_debug_options_bg_line_2[loop], 0xd0,0xd0,0xd0);
		setXY3(&Map_debug_options_bg_line_2[loop],
				MAP_DEBUG_OPTION_X, (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT + MAP_DEBUG_OPTION_MAIN_HEIGHT - 1),
				MAP_DEBUG_OPTION_X, (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT + 1),
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH - 1), (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT + 1));

		setLineF3(&Map_debug_options_bg_line_3[loop]);
		setRGB0(&Map_debug_options_bg_line_3[loop], 0x40,0x40,0x40);
		setXY3(&Map_debug_options_bg_line_3[loop],
				MAP_DEBUG_OPTION_X, (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT + MAP_DEBUG_OPTION_MAIN_HEIGHT - 1),
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH - 1), (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_MAIN_HEIGHT + MAP_DEBUG_OPTION_TITLE_HEIGHT -1),
				(MAP_DEBUG_OPTION_X + MAP_DEBUG_OPTION_WIDTH - 1), (MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT + 1));
		}

	// Create a text area used for display of the options dialog box title
	Map_debug_options_title_area = MRAllocateTextArea(	NULL,
														&debug_font,
														Map_debug_main_viewport,
														50,
														MAP_DEBUG_OPTION_X+2, MAP_DEBUG_OPTION_Y+2,
														MAP_DEBUG_OPTION_WIDTH, MAP_DEBUG_OPTION_TITLE_HEIGHT);

	MRBuildText(Map_debug_options_title_area, Map_debug_options_title_text, MR_FONT_COLOUR_WHITE);

	// Create the viewport in the center of our options dialog box main area
	setRECT(&temp_rect,
			MAP_DEBUG_OPTION_X+2, MAP_DEBUG_OPTION_Y + MAP_DEBUG_OPTION_TITLE_HEIGHT -3,//+ 3,
			MAP_DEBUG_OPTION_WIDTH - 4, MAP_DEBUG_OPTION_MAIN_HEIGHT - 5);
 
	Map_debug_options_viewport = MRCreateViewport(&temp_rect, NULL, MR_VP_SIZE_32, 0);

	// Setup camera 
	Map_debug_options_viewport ->vp_camera 		= MRCreateFrame(&Null_vector, &Null_svector, NULL);

	// We start at the top of the list, so our scroll value is zero.
	Map_debug_optlines_selected = 0;
	Map_debug_optlines_count	= 0;

	// Create the text areas for each options line.
	optline_ptr = Map_debug_optlines;

	optline_y	= 5;
	
	while(optline_ptr->mo_type != MOPTLINE_END)
		{
		optline_ptr->mo_text_area = MRAllocateTextArea(	NULL,
														&debug_font,
														Map_debug_options_viewport,
														50,
														0, optline_y,
														MAP_DEBUG_OPTION_WIDTH, 8);	

		optline_ptr->mo_current_state = optline_ptr->mo_initial_state;
		
		if (optline_ptr->mo_type == MOPTLINE_ROOT)
			optline_last_root_active = optline_ptr->mo_current_state;

		if ((optline_ptr->mo_current_state == FALSE) ||
			(optline_ptr->mo_type == MOPTLINE_SUB) && (optline_last_root_active == FALSE))
			{
			Map_debug_optline_colour = MR_FONT_COLOUR_GREY;
			}
		else
			{
			Map_debug_optline_colour = MR_FONT_COLOUR_WHITE;
			}			

		if (Map_debug_optlines_count == Map_debug_optlines_selected)
			Map_debug_optline_select_insert = Map_debug_optline_select_char;
		else
			Map_debug_optline_select_insert = Map_debug_optline_select_none;

		Map_debug_optline_text_insert = optline_ptr->mo_text;

		MRBuildText(optline_ptr->mo_text_area, Map_debug_optline_build_input, MR_FONT_COLOUR_WHITE);

		optline_y += 8;
		optline_ptr++;
		Map_debug_optlines_count++;
		}

	// Create a text area for 'show text'
	Map_debug_show_text_area = MRAllocateTextArea(	NULL,
					   								&debug_font,
					   								Map_debug_main_viewport,
					   								MAP_DEBUG_SHOW_TEXT_MAX_CHARS,
					   								MAP_DEBUG_SHOW_TEXT_X, MAP_DEBUG_SHOW_TEXT_Y,
					   								MAP_DEBUG_SHOW_TEXT_W, MAP_DEBUG_SHOW_TEXT_H);

	MRVp_ptr = Map_debug_main_viewport;
	MRDebugSet2DScale(Map_debug_scale_size);
	MRDebug_line_otz = 17;
	MRDebug_tile_otz = 18;

	// Initialise the FT4s
	poly_f4 = Map_debug_polys[0];
	loop	= MAP_MAX_POLY_GROUPS << 1;
	while(loop--)
		{
		setPolyF4(poly_f4);
		setRGB0(poly_f4, 0, 0, 0);
		poly_f4++;
		}

	// API debug initialisation
	MRDebugInitialiseDisplay();
	MRDebug_tile_otz = 2;
	MRDebug_line_otz = 1;
#endif
#endif
}


/******************************************************************************
*%%%% KillMapDebugDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillMapDebugDisplay(MR_VOID)
*
*	FUNCTION	Destroys viewports associated with debug display.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	KillMapDebugDisplay(MR_VOID)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	if (Map_debug_options_viewport)
		{
		MRKillFrame(Map_debug_options_viewport->vp_camera);
		MRKillViewport(Map_debug_options_viewport);
		}

	if (Map_debug_main_viewport)
		{
		MRKillFrame(Map_debug_main_viewport->vp_camera);
		MRKillViewport(Map_debug_main_viewport);
		}
#endif
#endif
}


/******************************************************************************
*%%%% UpdateMapDebugDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateMapDebugDisplay(MR_VOID)
*
*	FUNCTION	Performs all input and update processing of debug display/
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.04.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Redefined pad defines.
*
*%%%**************************************************************************/

MR_VOID	UpdateMapDebugDisplay(MR_VOID)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MAP_DEBUG_OPTLINE*	optline_ptr;
	MR_LONG				optline_num;
	MR_BOOL				optline_update;
	MR_BOOL				optline_last_root_active = TRUE;


	if (Map_debug_options_show)
		{
		optline_update				= FALSE;
		optline_last_root_active	= TRUE;

		// React to joypad input
		if (MR_CHECK_PAD_PRESSED(MR_INPUT_PORT_0, MRIP_DOWN) && (Map_debug_optlines_selected < (Map_debug_optlines_count-1)))
			{
			Map_debug_optlines_selected++;
			optline_update = TRUE;
			}
		else
		if (MR_CHECK_PAD_PRESSED(MR_INPUT_PORT_0, MRIP_UP) && (Map_debug_optlines_selected > 0))
			{
			Map_debug_optlines_selected--;
			optline_update = TRUE;
			}
		else
		if (MR_CHECK_PAD_PRESSED(MR_INPUT_PORT_0, FRR_BLUE))
			{
			if (Map_debug_optlines[Map_debug_optlines_selected].mo_current_state == TRUE)
				Map_debug_optlines[Map_debug_optlines_selected].mo_current_state = FALSE;
			else
				Map_debug_optlines[Map_debug_optlines_selected].mo_current_state = TRUE;

			optline_update = TRUE;
			}					

		// Update option lines
		if (optline_update == TRUE)
			{
			optline_ptr = Map_debug_optlines;
			optline_num = 0;
		
			while(optline_ptr->mo_type != MOPTLINE_END)
				{
				if (optline_ptr->mo_type == MOPTLINE_ROOT)
					optline_last_root_active = optline_ptr->mo_current_state;
	
				if ((optline_ptr->mo_current_state == FALSE) ||
					(optline_ptr->mo_type == MOPTLINE_SUB) && (optline_last_root_active == FALSE))
					{
					Map_debug_optline_colour = MR_FONT_COLOUR_GREY;
					}
				else
					{
					Map_debug_optline_colour = MR_FONT_COLOUR_WHITE;
					}			
	
				if (optline_num == Map_debug_optlines_selected)
					Map_debug_optline_select_insert = Map_debug_optline_select_char;
				else
					Map_debug_optline_select_insert = Map_debug_optline_select_none;
	
				Map_debug_optline_text_insert = optline_ptr->mo_text;
	
				MRBuildText(optline_ptr->mo_text_area, Map_debug_optline_build_input, MR_FONT_COLOUR_WHITE);
				optline_ptr++;
				optline_num++;
				}
			}

		// Special code to handle adjustment of grid scaling factor
		if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_CUSTOM_GRID_SCALE) == FALSE)
			{
			MRVp_ptr = Map_debug_main_viewport;
			MRDebugSet2DScale(MAP_DEBUG_SCALE_INITIAL);
			}
		else
		if ((Map_debug_optlines_selected == MAP_OPTLINE_CUSTOM_GRID_SCALE) &&
			(GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_CUSTOM_GRID_SCALE) == TRUE))
			{
			if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_LEFT) && (Map_debug_scale_size > (0x800 - MAP_DEBUG_SCALE_INCREMENT)))
				{
				Map_debug_scale_size -= MAP_DEBUG_SCALE_INCREMENT;	
				}
			else
			if (MR_CHECK_PAD_HELD(MR_INPUT_PORT_0, MRIP_RIGHT) && (Map_debug_scale_size < (0x4000 - MAP_DEBUG_SCALE_INCREMENT)))
				{
				Map_debug_scale_size += MAP_DEBUG_SCALE_INCREMENT;	
				}
			MRVp_ptr = Map_debug_main_viewport;
			MRDebugSet2DScale(Map_debug_scale_size);
			}

		// Add options dialog polygons		
		addPrim(Map_debug_main_viewport->vp_work_ot + 16, &Map_debug_options_bg_poly[MRFrame_index]);
		addPrim(Map_debug_main_viewport->vp_work_ot + 15, &Map_debug_options_bg_line_0[MRFrame_index]);
		addPrim(Map_debug_main_viewport->vp_work_ot + 15, &Map_debug_options_bg_line_1[MRFrame_index]);
		addPrim(Map_debug_main_viewport->vp_work_ot + 15, &Map_debug_options_bg_line_2[MRFrame_index]);
		addPrim(Map_debug_main_viewport->vp_work_ot + 15, &Map_debug_options_bg_line_3[MRFrame_index]);

		// Render options dialog text
		MRRenderViewport(Map_debug_options_viewport);
		
		Map_debug_options_title_area->ta_display = TRUE;
		}
	else
		{
		// We do this so the 'Frogger Debug' title bar text, on the main debug viewport, isn't displayed
		Map_debug_options_title_area->ta_display = FALSE;
		}

	MRVp_ptr = Map_debug_main_viewport;
	BuildMapDebugGroups();
	BuildMapDebugShowText();

	MRRenderViewport(Map_debug_main_viewport);
#endif
#endif
}


/******************************************************************************
*%%%% BuildMapDebugGroups
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	BuildMapDebugGroups(MR_VOID)
*
*	FUNCTION	Builds the text required to map groups, and display information
*				on the resultant display.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	BuildMapDebugGroups(MR_VOID)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG		i, x, z;
	MR_SVEC		svec, svec2;
	MR_SVEC		corners[4];
	POLY_F4*	poly_f4;
	MR_SHORT*	index;

	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_DISPLAY_MAP_GROUP_GRID) == TRUE)
		{
		// Display world grids
		MR_SET_VEC(&svec2, 0, (Map_view_znum * Map_view_zlen), 0);
		for (i = 0; i <= Map_view_xnum; i++)
			{
			MR_SET_SVEC(&svec, Map_view_basepoint.vx + (i * Map_view_xlen), Map_view_basepoint.vz, 0);
			MRDebugPlot2DWorldLine(&svec, &svec2, 0x005000);
				}
		MR_SET_SVEC(&svec2, (Map_view_xnum * Map_view_xlen), 0, 0);
		for (i = 0; i <= Map_view_znum; i++)
			{
			MR_SET_SVEC(&svec, Map_view_basepoint.vx, Map_view_basepoint.vz + (i * Map_view_zlen), 0);
			MRDebugPlot2DWorldLine(&svec, &svec2, 0x005000);
			}

		if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_DISPLAY_ACTIVE_GROUPS_ON_GRID) == TRUE)
			{
			// Display active groups on world grid

			poly_f4 = Map_debug_polys[MRFrame_index];
			index 	= Map_group_view_list[0];
			while(*index >= 0)
				{
				i = *index;				// active MAP_GROUP index
				x = i % Map_view_xnum;
				z = i / Map_view_xnum;
				MR_SET_SVEC(&corners[0], ((x + 0) * Map_view_xlen) + Map_view_basepoint.vx, ((z + 1) * Map_view_zlen) + Map_view_basepoint.vz, 0);
				MR_SET_SVEC(&corners[1], ((x + 1) * Map_view_xlen) + Map_view_basepoint.vx, ((z + 1) * Map_view_zlen) + Map_view_basepoint.vz, 0);
				MR_SET_SVEC(&corners[2], ((x + 0) * Map_view_xlen) + Map_view_basepoint.vx, ((z + 0) * Map_view_zlen) + Map_view_basepoint.vz, 0);
				MR_SET_SVEC(&corners[3], ((x + 1) * Map_view_xlen) + Map_view_basepoint.vx, ((z + 0) * Map_view_zlen) + Map_view_basepoint.vz, 0);
#ifdef PSX
				MRDebugPlot2DWorldPolyF4(corners, poly_f4);
#endif
				setRGB0(poly_f4, 0x20, 0x20, 0x20);
				poly_f4++;
				index++;
				}
			}

		if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_DISPLAY_CURRENT_GROUP_ON_GRID) == TRUE)
			{
			// Display current group on world grid
			}
		}
#endif
#endif
}


/******************************************************************************
*%%%% BuildMapDebugShowText
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	BuildMapDebugShowText(MR_VOID)
*
*	FUNCTION	Builds the text required to show things like poly and entity
*				counts..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	BuildMapDebugShowText(MR_VOID)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_STRPTR*	showline_ptr;

	// Start creating the 'show' text stuff
	showline_ptr = &Map_debug_show_buff[0];
		
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_MAP_POLY_COUNT) == TRUE)
		{
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_map_poly_count_tag;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_YELLOW; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_land_polys;
		*showline_ptr++ = (MR_STRPTR)4;
		}
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_LIVE_PATH_ENT_COUNT) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_live_path_ent_count_tag;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_RED; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_live_path_ents;
		*showline_ptr++ = (MR_STRPTR)4;
		}
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_LIVE_STAT_ENT_COUNT) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_live_stat_ent_count_tag;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_RED; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_live_stat_ents;
		*showline_ptr++ = (MR_STRPTR)4;
		}
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_LIVE_PATH_ENT_POLY_COUNT) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_live_path_ent_poly_count_tag;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_GREEN; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_live_path_ent_polys;
		*showline_ptr++ = (MR_STRPTR)4;
		}
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_LIVE_STAT_ENT_POLY_COUNT) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_live_stat_ent_poly_count_tag;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_GREEN; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_live_stat_ent_polys;
		*showline_ptr++ = (MR_STRPTR)4;
		}
#ifdef WIN95
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_FRAME_RATE) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_frame_rate;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_GREEN; 
		*showline_ptr++ = (MR_STRPTR)&Map_debug_frame_rate;
		*showline_ptr++ = (MR_STRPTR)4;
		}
	if (GET_MAP_DEBUG_OPTION_STATE(MAP_OPTLINE_SHOW_FRAME_COUNT) == TRUE)
		{
		// Fill a line of status text
		*showline_ptr++ = (MR_STRPTR)Map_debug_show_frame_count;
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_WHITE;		
		*showline_ptr++ = (MR_STRPTR)MR_FONT_COLOUR_GREEN; 
		*showline_ptr++ = (MR_STRPTR)&Main_global_frame_count;
		*showline_ptr++ = (MR_STRPTR)4;
		}
#endif

	// Null terminate list
	*showline_ptr++ = NULL;

	// Build show text
	MRBuildText(Map_debug_show_text_area, Map_debug_show_buff, MR_FONT_COLOUR_WHITE);
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayGridFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayGridFlags(
*						MR_ULONG	mask,
*						MR_ULONG	colour)
*
*	FUNCTION	Overlay (in 3D) a coloured square on any grid square which has
*				flags set in the specified mask
*
*	INPUTS		mask	-	flags mask
*				colour	-	of POLY_F4
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayGridFlags(	MR_ULONG	mask,
									MR_ULONG	colour)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG			x, z;
	GRID_SQUARE*	grid_square;
	MR_SVEC			points[4];
	POLY_F4*		poly;


	grid_square = Grid_squares;
	poly		= Map_debug_polys[MRFrame_index];

	for (z = 0; z < Grid_znum; z++)
		{
		for (x = 0; x < Grid_xnum; x++)
			{
			if (grid_square->gs_flags & mask)
				{
				MR_COPY_SVEC(&points[0], &Map_vertices[grid_square->gs_map_poly->mp_vertices[0]]);
				MR_COPY_SVEC(&points[1], &Map_vertices[grid_square->gs_map_poly->mp_vertices[1]]);
				MR_COPY_SVEC(&points[2], &Map_vertices[grid_square->gs_map_poly->mp_vertices[2]]);
				MR_COPY_SVEC(&points[3], &Map_vertices[grid_square->gs_map_poly->mp_vertices[3]]);

				//MRDebugPlotWorldPolyF4(points, poly);
#ifdef PSX
				MR_SET32(poly->r0, (poly->code << 24) + colour);
#endif
				poly++;
				if (poly >= &Map_debug_polys[MRFrame_index][MAP_MAX_POLY_GROUPS])
					return;
				}
			grid_square++;
			}
		}
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayForm
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayForm(
*						FORM*	form,
*						MR_MAT*	lwtrans)
*
*	FUNCTION	Display a FORM grid
*
*	INPUTS		form	-	ptr to FORM
*				lwtrans	-	transform FORM is in
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayForm(FORM*	form,
						   	MR_MAT*	lwtrans)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG		x, z;
	MR_VEC		start[2];
	MR_VEC		dirn_x;
	MR_VEC		dirn_z;
	MR_VEC		dirn_xneg;
	MR_VEC		dirn_zneg;
	MR_SVEC		svecs[2];
	FORM_DATA*	form_data;
	MR_SHORT*	height_ptr;


	MR_ASSERT(form);
	MR_ASSERT(lwtrans);
	
	form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];

	MR_SET_SVEC(&svecs[0], form->fo_xnum << 8, 0, 0);
	MRApplyMatrix(lwtrans, &svecs[0], &dirn_x);
	
	switch(form_data->fd_height_type)
		{
		case FORM_DATA_HEIGHT_TYPE_GRID:
			// Single height for grid
			for (z = 0; z <= form->fo_znum; z++)
				{
				MR_SET_SVEC(&svecs[0], form->fo_xofs, form_data->fd_height, form->fo_zofs + (z << 8));
				MRApplyMatrix(lwtrans, &svecs[0], &start[0]);
				MR_ADD_VEC(&start[0], (MR_VEC*)lwtrans->t);
				MRDebugPlotWorldLineVEC(&start[0], &dirn_x, 0x000080);
				}			
		
			MR_SET_SVEC(&svecs[0], 0, 0, form->fo_znum << 8);
			MRApplyMatrix(lwtrans, &svecs[0], &dirn_z);
		
			for (x = 0; x <= form->fo_xnum; x++)
				{
				MR_SET_SVEC(&svecs[0], form->fo_xofs + (x << 8), form_data->fd_height, form->fo_zofs);
				MRApplyMatrix(lwtrans, &svecs[0], &start[0]);
				MR_ADD_VEC(&start[0], (MR_VEC*)lwtrans->t);
				MRDebugPlotWorldLineVEC(&start[0], &dirn_z, 0x000080);
				}			
			break;

		case FORM_DATA_HEIGHT_TYPE_SQUARE:
			// Height for each grid square
			gte_SetRotMatrix(lwtrans);
			MR_SET_SVEC(&svecs[0], 0x100, 0, 0);
			MRApplyRotMatrix(&svecs[0], &dirn_x);
			MR_SET_SVEC(&svecs[0], 0, 0, 0x100);
			MRApplyRotMatrix(&svecs[0], &dirn_z);
			MR_SUB_VEC_ABC(&Null_vector, &dirn_x, &dirn_xneg);
			MR_SUB_VEC_ABC(&Null_vector, &dirn_z, &dirn_zneg);
							 
			height_ptr = form_data->fd_heights;
			for (z = 0; z < form->fo_znum; z++)
				{
				for (x = 0; x < form->fo_xnum; x++)
					{
					MR_SET_SVEC(&svecs[0], form->fo_xofs + ((x + 0) << 8), *height_ptr, form->fo_zofs + ((z + 0) << 8));
					MR_SET_SVEC(&svecs[1], form->fo_xofs + ((x + 1) << 8), *height_ptr, form->fo_zofs + ((z + 1) << 8));

					gte_SetRotMatrix(lwtrans);
					MRApplyRotMatrix(&svecs[0], &start[0]);
					MRApplyRotMatrix(&svecs[1], &start[1]);
					MR_ADD_VEC(&start[0], (MR_VEC*)lwtrans->t);
					MR_ADD_VEC(&start[1], (MR_VEC*)lwtrans->t);
					MRDebugPlotWorldLineVEC(&start[0], &dirn_x, 0x000080);
					MRDebugPlotWorldLineVEC(&start[0], &dirn_z, 0x000080);
					MRDebugPlotWorldLineVEC(&start[1], &dirn_xneg, 0x000080);
					MRDebugPlotWorldLineVEC(&start[1], &dirn_zneg, 0x000080);

					height_ptr++;
					}
				}
			}
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayMapGroup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayMapGroup(
*						MAP_GROUP*	map_group)
*
*	FUNCTION	Display a MAP_GROUP (as a rectangle in the XZ plane)
*
*	INPUTS		map_group	-	ptr to MAP_GROUP
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayMapGroup(MAP_GROUP* map_group)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG		x, z, m;
	MR_VEC		start[2];
	MR_VEC		dirn_x;
	MR_VEC		dirn_z;
	MR_VEC		dirn_xneg;
	MR_VEC		dirn_zneg;


	MR_ASSERT(map_group);
	
	m = map_group - Map_groups;
	z = m / Map_view_xnum;
	x = m % Map_view_xnum;

	MR_SET_VEC(&dirn_x, Map_view_xlen, 0, 0);
	MR_SET_VEC(&dirn_xneg, -Map_view_xlen, 0, 0);
	MR_SET_VEC(&dirn_z, 0, 0, Map_view_zlen);
	MR_SET_VEC(&dirn_zneg, 0, 0, -Map_view_zlen);

	start[0].vx = ((x + 0) * Map_view_xlen) + Map_view_basepoint.vx;
	start[0].vy = 0;
	start[0].vz = ((z + 0) * Map_view_zlen) + Map_view_basepoint.vz;

	start[1].vx = ((x + 1) * Map_view_xlen) + Map_view_basepoint.vx;
	start[1].vy = 0;
	start[1].vz = ((z + 1) * Map_view_zlen) + Map_view_basepoint.vz;

	MRDebugPlotWorldLineVEC(&start[0], &dirn_x, 0x008000);
	MRDebugPlotWorldLineVEC(&start[0], &dirn_z, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_xneg, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_zneg, 0x008000);
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayZoneRegion
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayZoneRegion(
*						ZONE_REGION*	region)
*
*	FUNCTION	Display a ZONE_REGION (as a rectangle in the XZ plane)
*
*	INPUTS		region	-	ptr to ZONE_REGION
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayZoneRegion(ZONE_REGION* region)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_VEC		start[2];
	MR_VEC		dirn_x;
	MR_VEC		dirn_z;
	MR_VEC		dirn_xneg;
	MR_VEC		dirn_zneg;


	MR_ASSERT(region);
	
	MR_SET_VEC(&dirn_x, (region->zr_xmax + 1 - region->zr_xmin) << 8, 0, 0);
	MR_SET_VEC(&dirn_z, 0, 0, (region->zr_zmax + 1 - region->zr_zmin) << 8);
	MR_SET_VEC(&dirn_xneg, (region->zr_xmin - region->zr_xmax - 1) << 8, 0, 0);
	MR_SET_VEC(&dirn_zneg, 0, 0, (region->zr_zmin - region->zr_zmax - 1) << 8);

	start[0].vx = ((region->zr_xmin + 0) << 8) + Grid_base_x;
	start[0].vy = 0;
	start[0].vz = ((region->zr_zmin + 0) << 8) + Grid_base_z;

	start[1].vx = ((region->zr_xmax + 1) << 8) + Grid_base_x;
	start[1].vy = 0;
	start[1].vz = ((region->zr_zmax + 1) << 8) + Grid_base_z;

	MRDebugPlotWorldLineVEC(&start[0], &dirn_x, 0x008000);
	MRDebugPlotWorldLineVEC(&start[0], &dirn_z, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_xneg, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_zneg, 0x008000);
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayGridSquare
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayGridSquare(
*						GRID_SQUARE*	grid_square)
*
*	FUNCTION	Display a GRID_SQUARE (as a rectangle)
*
*	INPUTS		grid_square	-	ptr to GRID_SQUARE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayGridSquare(GRID_SQUARE* grid_square)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_VEC		start;
	MR_VEC		dirn;
	MR_SVEC*	map_poly_v0;
	MR_SVEC*	map_poly_v1;
	MR_SVEC*	map_poly_v2;
	MR_SVEC*	map_poly_v3;


	MR_ASSERT(grid_square);
	map_poly_v0 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[0]];
	map_poly_v1 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[1]];
	map_poly_v2 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[2]];
	map_poly_v3 = &Map_vertices[grid_square->gs_map_poly->mp_vertices[3]];
	
	MR_VEC_EQUALS_SVEC(&start, map_poly_v0);
	dirn.vx = map_poly_v1->vx - map_poly_v0->vx;
	dirn.vy = map_poly_v1->vy - map_poly_v0->vy;
	dirn.vz = map_poly_v1->vz - map_poly_v0->vz;
	MRDebugPlotWorldLineVEC(&start, &dirn, 0x808000);
	dirn.vx = map_poly_v2->vx - map_poly_v0->vx;
	dirn.vy = map_poly_v2->vy - map_poly_v0->vy;
	dirn.vz = map_poly_v2->vz - map_poly_v0->vz;
	MRDebugPlotWorldLineVEC(&start, &dirn, 0x808000);

	MR_VEC_EQUALS_SVEC(&start, map_poly_v3);
	dirn.vx = map_poly_v1->vx - map_poly_v3->vx;
	dirn.vy = map_poly_v1->vy - map_poly_v3->vy;
	dirn.vz = map_poly_v1->vz - map_poly_v3->vz;
	MRDebugPlotWorldLineVEC(&start, &dirn, 0x808000);
	dirn.vx = map_poly_v2->vx - map_poly_v3->vx;
	dirn.vy = map_poly_v2->vy - map_poly_v3->vy;
	dirn.vz = map_poly_v2->vz - map_poly_v3->vz;
	MRDebugPlotWorldLineVEC(&start, &dirn, 0x808000);
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayGridCoord
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayGridCoord(
*						MR_LONG	grid_x,
*						MR_LONG	grid_z)
*
*	FUNCTION	Display a grid coordinate (as a rectangle in the XZ plane)
*
*	INPUTS		grid_x	-	ptr to x coord
*				grid_z	-	ptr to z coord
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayGridCoord(	MR_LONG	grid_x,
									MR_LONG	grid_z)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_VEC		start[2];
	MR_VEC		dirn_x;
	MR_VEC		dirn_z;
	MR_VEC		dirn_xneg;
	MR_VEC		dirn_zneg;


	MR_SET_VEC(&dirn_x, 0x100, 0, 0);
	MR_SET_VEC(&dirn_z, 0, 0, 0x100);
	MR_SET_VEC(&dirn_xneg, -0x100, 0, 0);
	MR_SET_VEC(&dirn_zneg, 0, 0, -0x100);

	start[0].vx = ((grid_x + 0) << 8) + Grid_base_x;
	start[0].vy = 0;
	start[0].vz = ((grid_z + 0) << 8) + Grid_base_z;

	start[1].vx = ((grid_x + 1) << 8) + Grid_base_x;
	start[1].vy = 0;
	start[1].vz = ((grid_z + 1) << 8) + Grid_base_z;

	MRDebugPlotWorldLineVEC(&start[0], &dirn_x, 0x008000);
	MRDebugPlotWorldLineVEC(&start[0], &dirn_z, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_xneg, 0x008000);
	MRDebugPlotWorldLineVEC(&start[1], &dirn_zneg, 0x008000);
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayGrid
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayGrid(
*						MR_LONG	x0,
*						MR_LONG	z0,
*						MR_LONG	x1,
*						MR_LONG	z1,
*						MR_LONG	y)
*
*	FUNCTION	Display a grid in the XZ plane
*
*	INPUTS		x0	-	start x coord
*				z0	-	start z coord
*				x1	-	end x coord
*				z1	-	end z coord
*				y	-	height of grid
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayGrid(MR_LONG	x0,
							MR_LONG	z0,
							MR_LONG	x1,
							MR_LONG	z1,
							MR_LONG	y)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG		x, z;
	MR_VEC		start;
	MR_VEC		dirn_x;
	MR_VEC		dirn_z;


	x0 = MAX(x0, 0);
	z0 = MAX(z0, 0);
	x1 = MIN(x1, Grid_xnum - 1);
	z1 = MIN(z1, Grid_znum - 1);

	MR_SET_VEC(&dirn_x, (x1 + 1 - x0) << 8, 0, 0);
	for (z = z0; z <= (z1 + 1); z++)
		{
		MR_SET_VEC(&start, Grid_base_x + (x0 << 8), y, Grid_base_z + (z << 8));
		MRDebugPlotWorldLineVEC(&start, &dirn_x, 0x008000);
		}			

	MR_SET_VEC(&dirn_z, 0, 0, (z1 + 1 - z0) << 8);
	for (x = x0; x <= (x1 + 1); x++)
		{
		MR_SET_VEC(&start, Grid_base_x + (x << 8), y, Grid_base_z + (z0 << 8));
		MRDebugPlotWorldLineVEC(&start, &dirn_z, 0x008000);
		}			
#endif
#endif
}

/******************************************************************************
*%%%% MapDebugDisplayFormBoundingSphere
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayFormBoundingSphere(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Display a live_entity's bounding sphere
*
*	INPUTS		live_entity		- ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayFormBoundingSphere(LIVE_ENTITY* live_entity)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	FORM_BOOK*	form_book;
	MR_LONG		radius, i;
	MR_SVEC		svecs[4];
	MR_VEC		vecs[4], vec;
	MR_MAT*		lwtrans;


	form_book	= ENTITY_GET_FORM_BOOK(live_entity->le_entity);
	radius	 	= MR_SQRT(form_book->fb_radius2);
	lwtrans	 	= live_entity->le_lwtrans;
	MR_SET_SVEC(&svecs[0], 0, 0,  radius);
	MR_SET_SVEC(&svecs[1],  radius, 0, 0);
	MR_SET_SVEC(&svecs[2], 0, 0, -radius);
	MR_SET_SVEC(&svecs[3], -radius, 0, 0);
	gte_SetRotMatrix(lwtrans);
	MRApplyRotMatrix(&svecs[0], &vecs[0]);
	MR_ADD_VEC(&vecs[0], (MR_VEC*)lwtrans->t);
	MRApplyRotMatrix(&svecs[1], &vecs[1]);
	MR_ADD_VEC(&vecs[1], (MR_VEC*)lwtrans->t);
	MRApplyRotMatrix(&svecs[2], &vecs[2]);
	MR_ADD_VEC(&vecs[2], (MR_VEC*)lwtrans->t);
	MRApplyRotMatrix(&svecs[3], &vecs[3]);
	MR_ADD_VEC(&vecs[3], (MR_VEC*)lwtrans->t);

	for (i = 0; i < 4; i++)
		{
		MR_SUB_VEC_ABC(&vecs[(i + 1) & 3], &vecs[i], &vec);
		MRDebugPlotWorldLineVEC(&vecs[i], &vec, 0x008080);
		}
#endif
#endif
}


/******************************************************************************
*%%%% MapDebugDisplayPath
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MapDebugDisplayPath
*						PATH*	path)
*
*	FUNCTION	Display a path
*
*	INPUTS		path	-	ptr to PATH to display
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	MapDebugDisplayPath(PATH*	path)
{
#ifdef DEBUG
#ifdef MR_DEBUG_DISPLAY
	MR_LONG			segments, l, dist;
	PATH_SEGMENT**	segment_pptr;
	PATH_SPLINE*	path_spline;
	PATH_ARC*		path_arc;
	PATH_LINE*		path_line;
	MR_VEC			vec, vec2, vec3, diff;
	MR_SVEC			svec;
	MR_MAT			matrix;
	MR_LONG			cos, sin, c, t, a, y;


	segments 		= path->pa_numsegments;
	segment_pptr	= (PATH_SEGMENT**)(&path->pa_segment_ptrs);
	while(segments--)
		{
		switch(segment_pptr[0]->ps_type)
			{
			case PATH_SEGMENT_SPLINE:
				// Plot spline as 8 (red) lines
				path_spline = (PATH_SPLINE*)&segment_pptr[0]->ps_segment_ptr;
				MRCalculateSplinePoint(&path_spline->ps_matrix, 0, &svec);
				MR_VEC_EQUALS_SVEC(&vec, &svec);
				for (l = 1; l <= 8; l++)
					{
					MRCalculateSplinePoint(&path_spline->ps_matrix, (l * MR_SPLINE_PARAM_ONE) / 8, &svec);
					MR_VEC_EQUALS_SVEC(&vec2, &svec);
					MR_SUB_VEC_ABC(&vec2, &vec, &diff);				
					MRDebugPlotWorldLineVEC(&vec, &diff, 0x000080);
					MR_COPY_VEC(&vec, &vec2);
					}
				break;

			case PATH_SEGMENT_ARC:
				// Plot arc as 16 (yellow) lines
				path_arc	= (PATH_ARC*)&segment_pptr[0]->ps_segment_ptr;
				vec.vx 		= path_arc->pa_start.vx - path_arc->pa_centre.vx;
				vec.vy 		= path_arc->pa_start.vy - path_arc->pa_centre.vy;
				vec.vz 		= path_arc->pa_start.vz - path_arc->pa_centre.vz;
				MRNormaliseVEC(&vec, &vec);
				MR_VEC_EQUALS_SVEC(&vec2, &path_arc->pa_normal);
				MROuterProduct12(&vec, &vec2, &vec3);
				matrix.m[0][0] 	= vec.vx;
				matrix.m[1][0] 	= vec.vy;
				matrix.m[2][0] 	= vec.vz;
				matrix.m[0][1] 	= -vec2.vx;
				matrix.m[1][1] 	= -vec2.vy;
				matrix.m[2][1] 	= -vec2.vz;
				matrix.m[0][2] 	= -vec3.vx;
				matrix.m[1][2] 	= -vec3.vy;
				matrix.m[2][2]	= -vec3.vz;
				c				= path_arc->pa_radius * 0x6487;				  				// (2*PI*r << 12);

				// matrix is now the transform whose local XZ plane is the plane of the arc, and the line from centre to start
				// is the +ve x axis
				MR_VEC_EQUALS_SVEC(&vec, &path_arc->pa_start);
				for (l = 1; l <= 16; l++)
					{
					dist = (path_arc->pa_length * l) >> 4;
					
					// Calculate position of length 'dist' along arc
					t	= (dist << 12) / c;											// number of complete turns
					a	= ((dist << 18) - (t * c)) / (path_arc->pa_radius * 0x192);	// partial angle (0..0x1000)
					y	= (-path_arc->pa_pitch * dist) / path_arc->pa_length;
				
					cos	= rcos(a);
					sin	= rsin(a);
					MR_SET_SVEC(&svec, (cos * path_arc->pa_radius) >> 12, y, (sin * path_arc->pa_radius) >> 12);

					gte_SetRotMatrix(&matrix);
					MRApplyRotMatrix(&svec, &vec2);
					vec2.vx += path_arc->pa_centre.vx;
					vec2.vy += path_arc->pa_centre.vy;
					vec2.vz += path_arc->pa_centre.vz;

					MR_SUB_VEC_ABC(&vec2, &vec, &diff);				
					MRDebugPlotWorldLineVEC(&vec, &diff, 0x008080);
					MR_COPY_VEC(&vec, &vec2);
					}
				break;

			case PATH_SEGMENT_LINE:
				// Plot line as 8 (green) lines
				path_line 	= (PATH_LINE*)&segment_pptr[0]->ps_segment_ptr;
				MR_VEC_EQUALS_SVEC(&vec, &path_line->pl_start);
				diff.vx 	= (path_line->pl_end.vx - path_line->pl_start.vx) >> 3;
				diff.vy 	= (path_line->pl_end.vy - path_line->pl_start.vy) >> 3;
				diff.vz 	= (path_line->pl_end.vz - path_line->pl_start.vz) >> 3;
				l 			= 8;
				while(l--)
					{
					MRDebugPlotWorldLineVEC(&vec, &diff, 0x008000);
					MR_ADD_VEC(&vec, &diff);
					}
				break;
			}
		segment_pptr++;
		}
#endif
#endif
}
