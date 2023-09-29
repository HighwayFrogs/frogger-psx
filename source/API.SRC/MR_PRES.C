/******************************************************************************
*%%%% mr_pres.c
*------------------------------------------------------------------------------
*
*	Presentation code
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96	Tim Closs		Created (BETA)
*	14.08.96	Tim Closs		Added	MRShowTextPresitems, MRHideTextPresitems
*	27.09.96	Dean Ashton		Modified calls to MRCreateFrame to remove callback
*	04.11.96	Tim Closs		MRRenderPres() now takes viewport input
*								MRInputPres() now takes controller id input
*
*%%%**************************************************************************/

#include "mr_all.h"

MR_PRESITEM		MRPresitem_root;
MR_PRESITEM*	MRPresitem_root_ptr;
MR_OBJECT		MRPres_object_root;
MR_OBJECT*		MRPres_object_root_ptr;

MR_PRESITEM*	MRPresitem_ptr;
MR_USHORT		MRNumber_of_presitems;
MR_USHORT		MRPres_margin;
MR_USHORT		MRPres_text_ot;

MR_PRESOPTION	MRPresoptions[MR_PS_MAX_OPTIONS];
MR_USHORT		MRPresoption_index;
MR_USHORT		MRPresoption_timer;
MR_USHORT		MRPresoption_change_time;
MR_USHORT		MRPresoption_direction;

MR_PRESPAGE		MRPrespages[MR_PS_MAX_PAGES];
MR_USHORT		MRPrespage_index;

MR_VOID			(*MRPresoption_update_callback)(MR_VOID);
MR_VOID			(*MRPresoption_move_callback)(MR_VOID);
MR_PRESITEM*	MRPresoption_move_presitem;


/******************************************************************************
*%%%% MRInitialisePresentation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialisationPresentation(MR_VOID);
*
*	FUNCTION	Initialise presentation systems.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialisePresentation(MR_VOID)
{
	MRPresitem_root_ptr		= &MRPresitem_root;
	MRPres_object_root_ptr 	= &MRPres_object_root;
	MRPres_text_ot 			= 2;

	MRPresoption_move_callback = NULL;
	MRPresoption_move_presitem = NULL;

}


/******************************************************************************
*%%%% MRSetupPresentation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetupPresentation(
*						MR_LONG*		script_ptr,
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Setup a presentation page from a script.
*
*	INPUTS		script_ptr	-	ptr to start of a script array
*				vp	 		-	ptr to viewport to render into
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	05.11.96	Tim Closs		Changed to allow viewport input
*
*%%%**************************************************************************/

MR_VOID	MRSetupPresentation(MR_LONG* 		script_ptr,
							MR_VIEWPORT*	vp)
{
	MR_PRESITEM*	pi_ptr;
	MR_2DSPRITE*	sp_ptr;
	MR_USHORT		i, entries, bspacing;
	MR_LONG			script_line[16];
	MR_LONG*		sl_ptr;
	MR_VOID			(*function)();


	MRPresoption_index 	= 0;
	MRDefault_vp 			= vp;

	while(*script_ptr)
		{
		switch(*script_ptr++)
			{
			//---------------------------------------------------------------------------------------
			case MR_PS_BITMAP:
				// Create bitmap
				//
				// x (pixels), y (pixels), OT pos (-ve => OT_LENGTH - OT pos), MR_TEXTURE*

				pi_ptr = MRCreatePresitem(MR_PS_ITEMTYPE_2DSPRITE);

				sp_ptr = MRCreate2DSprite(*(script_ptr + 0),				// x
					 				  	  *(script_ptr + 1),				// y
							  			  MRDefault_vp,						// vport
							  			  (MR_VOID*)*(script_ptr + 3),		// MR_TEXTURE*
							  			  NULL);

				if (*(script_ptr + 2) >= 0)
					sp_ptr->sp_core.sc_ot_offset = *(script_ptr + 2);
				else
					sp_ptr->sp_core.sc_ot_offset = MRDefault_vp->vp_ot_size + *(script_ptr + 2);

				pi_ptr->pi_ptr0 = sp_ptr;

				script_ptr += 4;
				break;
			//---------------------------------------------------------------------------------------
			case MR_PS_MARGIN:
				// Set margin
				//
				// margin

				MRPres_margin = *script_ptr++;
				break;
			//---------------------------------------------------------------------------------------
			case MR_PS_ITEM:
				// Create item
				//
				// itemtype, direction, justification type, w (pixels), h (pixels), y (pixels),
				// ...followed by item specific variables

				script_ptr = MRCreatePresitemFromScriptLine(script_ptr);
				break;
			//---------------------------------------------------------------------------------------
			case MR_PS_OPTIONS:
				// Create options column
				//
				// #entries, b spacing (pixels), itemtype, direction, justification type, w (pixels), h (pixels), y (pixels) of first
				// entry, ...followed by individual item specifiers
				entries						= *script_ptr++;		
				bspacing 					= *script_ptr++;		
				MRPresoption_change_time	= *script_ptr++;		
				sl_ptr 						= script_line;

				for (i = 0; i < 6; i++)
					*sl_ptr++ = *script_ptr++;

				MRPresoption_direction		= script_line[1];

				switch(script_line[0])
					{
					// Depending on item type of option, we may need to copy a longer script line (eg. box colour, z coord)
					case MR_PS_ITEMTYPE_BOX:
						// Box colour
						*sl_ptr++ = *script_ptr++;
						break;
					case MR_PS_ITEMTYPE_3DSPRITE:
						// z coord, post-creation callback
						*sl_ptr++ = *script_ptr++;
						*sl_ptr++ = *script_ptr++;
						break;
					}

				// Scan down list of entries, creating MR_PRESITEMs as we go
				for (i = 0; i < entries; i++)
					{
					MRPresoptions[MRPresoption_index].po_flags = NULL;
					if (i == 0)
						MRPresoptions[MRPresoption_index].po_flags |= MR_PS_OPTION_TOP;
					if (i == (entries - 1))
						MRPresoptions[MRPresoption_index].po_flags |= MR_PS_OPTION_BOTTOM;

					MRPresoptions[MRPresoption_index].po_type = *script_ptr;
					
					switch(*script_ptr++)
						{
						case MR_PS_OPTIONTYPE_FIXED_CALLBACK:
							*sl_ptr = *script_ptr++;
							MRPresoptions[MRPresoption_index].po_callback 	= (MR_VOID*)*script_ptr++;
							MRPresoptions[MRPresoption_index].po_variable	= NULL;
							MRPresoptions[MRPresoption_index].po_text_list 	= NULL;

							MRCreatePresitemFromScriptLine(script_line);
							MRPresoptions[MRPresoption_index].po_presitem 	= MRPresitem_ptr;
							break;

						case MR_PS_OPTIONTYPE_WALK:
						case MR_PS_OPTIONTYPE_CYCLE:
							MRPresoptions[MRPresoption_index].po_callback 	= NULL;
							MRPresoptions[MRPresoption_index].po_variable 	= (MR_LONG*)*script_ptr++;
							MRPresoptions[MRPresoption_index].po_text_list 	= script_ptr++;
							while(*script_ptr++);

							*sl_ptr = *(MRPresoptions[MRPresoption_index].po_text_list +
										  (*MRPresoptions[MRPresoption_index].po_variable) + 1);

							MRCreatePresitemFromScriptLine(script_line);
							MRPresoptions[MRPresoption_index].po_presitem 	= MRPresitem_ptr;
							break;
						}
					// Increase script line y entry by item depth and row spacing
					script_line[5] += (script_line[4] + bspacing);
					MRPresoption_index++;
					}
				break;
			//---------------------------------------------------------------------------------------
			case MR_PS_OPTION_MOVE_CALLBACKS:
				// Set up an option movement method, and store callback for updating it
				//
				// setup callback, update callback, move callback

				function = (MR_VOID*)(*script_ptr++);
				(function)();

				MRPresoption_update_callback 	= (MR_VOID*)(*script_ptr++);
				MRPresoption_move_callback 		= (MR_VOID*)(*script_ptr++);
				break;
			//---------------------------------------------------------------------------------------
			}
		}

	// Set up stuff before returning
	MRPresoption_index = MRPrespages[MRPrespage_index].pp_def_option;
	MRPresoption_timer = 0;
}


/******************************************************************************
*%%%% MRCreatePresitemFromScriptLine
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG new_ptr=	MRCreatePresitemFromScriptLine(
*									MR_LONG*	script_ptr);
*
*	FUNCTION	Create a MR_PRESITEM from a MR_LONG[] script line
*
*	INPUTS		script_ptr	-	Pointer to start of a script array
*
*	RESULT		new_ptr		-	Pointer to next entry after script line
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	27.09.96	Dean Ashton		Removed callback param for MRCreateFrame
*
*%%%**************************************************************************/

MR_LONG*	MRCreatePresitemFromScriptLine(MR_LONG* script_ptr)
{
	MR_UBYTE		r, g, b;
	MR_USHORT		i;
	POLY_G4*		poly_g4_ptr;
	LINE_F3*		line_f3_ptr;
	MR_VEC			test_pos;
	MR_VOID			(*function)();


	MRPresitem_ptr = MRCreatePresitem(*(script_ptr + 0));					// type

	if (*(script_ptr + 1) == MR_PS_VERTICAL)
		{
		MRPresitem_ptr->pi_x = MRPresGetJustifiedX(*(script_ptr + 2),		// justification type
								  	  			 *(script_ptr + 3),			// width of item
							  		  			 MRPres_margin);			// margin
		MRPresitem_ptr->pi_w = *(script_ptr + 3);
		MRPresitem_ptr->pi_h = *(script_ptr + 4);
		MRPresitem_ptr->pi_y = *(script_ptr + 5);
		}
	else
		{
		MRPresitem_ptr->pi_y = MRPresGetJustifiedX(*(script_ptr + 2),		// justification type
												 *(script_ptr + 4),			// depth of item
												 MRPres_margin);			// margin
		MRPresitem_ptr->pi_w = *(script_ptr + 3);
		MRPresitem_ptr->pi_h = *(script_ptr + 4);
		MRPresitem_ptr->pi_x = *(script_ptr + 5);
		}
	script_ptr += 6;

	switch(MRPresitem_ptr->pi_type)
		{
		//-----------------------------------------------------------------------------------------
		case MR_PS_ITEMTYPE_BOX:
			// Set up background polys					
			r = (*script_ptr & 0xff0000) >> 16;
			g = (*script_ptr & 0xff00) >> 8;
			b = (*script_ptr & 0xff) >> 0;

			for (i = 0; i < 2; i++)
				{
				poly_g4_ptr = (POLY_G4*)MRPresitem_ptr->pi_prims[i];
				poly_g4_ptr->x0 = MRPresitem_ptr->pi_x;
				poly_g4_ptr->x2 = MRPresitem_ptr->pi_x;
				poly_g4_ptr->x1 = MRPresitem_ptr->pi_x + MRPresitem_ptr->pi_w;
				poly_g4_ptr->x3 = MRPresitem_ptr->pi_x + MRPresitem_ptr->pi_w;
				poly_g4_ptr->y0 = MRPresitem_ptr->pi_y;
				poly_g4_ptr->y1 = MRPresitem_ptr->pi_y;
				poly_g4_ptr->y2 = MRPresitem_ptr->pi_y + MRPresitem_ptr->pi_h;
				poly_g4_ptr->y3 = MRPresitem_ptr->pi_y + MRPresitem_ptr->pi_h;
				setRGB0(poly_g4_ptr, r, g, b);
				setRGB1(poly_g4_ptr, r, g, b);
				setRGB2(poly_g4_ptr, r, g, b);
				setRGB3(poly_g4_ptr, r, g, b);
				}
			script_ptr++;
		//-----------------------------------------------------------------------------------------
		case MR_PS_ITEMTYPE_TEXT:
			// Create and build text area
			MRPresitem_ptr->pi_flags |= MR_PS_ITEM_OWNS_TEXT;

			MRPresitem_ptr->pi_ptr0 = MRAllocateTextArea(NULL,
				   										MRDefault_font_info,
											 			MRDefault_vp,
									  		 			48,
									  		 			MRPresitem_ptr->pi_x,
											 			MRPresitem_ptr->pi_y + ((MRPresitem_ptr->pi_h - MRDefault_font_info->fi_font_height) >> 1),
											 			MRPresitem_ptr->pi_w,
											 			MRPresitem_ptr->pi_h);

			MRBuildText((MR_TEXT_AREA*)MRPresitem_ptr->pi_ptr0, (MR_STRPTR*)*script_ptr, MR_FONT_COLOUR_WHITE);
			((MR_TEXT_AREA*)MRPresitem_ptr->pi_ptr0)->ta_otz = MRPres_text_ot;
			script_ptr++;
			break;
		//-----------------------------------------------------------------------------------------
		case MR_PS_ITEMTYPE_OUTLINE:
			// Set up outline polys					
			r = (*script_ptr & 0xff0000) >> 16;
			g = (*script_ptr & 0xff00) >> 8;
			b = (*script_ptr & 0xff) >> 0;

			for (i = 0; i < 2; i++)
				{
				line_f3_ptr = (LINE_F3*)MRPresitem_ptr->pi_prims[i];
				line_f3_ptr->x0 = MRPresitem_ptr->pi_x;
				line_f3_ptr->x1 = MRPresitem_ptr->pi_x + MRPresitem_ptr->pi_w;
				line_f3_ptr->x2 = MRPresitem_ptr->pi_x + MRPresitem_ptr->pi_w;
				line_f3_ptr->y0 = MRPresitem_ptr->pi_y;
				line_f3_ptr->y1 = MRPresitem_ptr->pi_y;
				line_f3_ptr->y2 = MRPresitem_ptr->pi_y + MRPresitem_ptr->pi_h;
				setRGB0(line_f3_ptr, r, g, b);
				line_f3_ptr++;
				line_f3_ptr->x0 = MRPresitem_ptr->pi_x;
				line_f3_ptr->x1 = MRPresitem_ptr->pi_x;
				line_f3_ptr->x2 = MRPresitem_ptr->pi_x + MRPresitem_ptr->pi_w;
				line_f3_ptr->y0 = MRPresitem_ptr->pi_y;
				line_f3_ptr->y1 = MRPresitem_ptr->pi_y + MRPresitem_ptr->pi_h;
				line_f3_ptr->y2 = MRPresitem_ptr->pi_y + MRPresitem_ptr->pi_h;
				setRGB0(line_f3_ptr, r, g, b);
				}
			script_ptr++;
			break;
		//-----------------------------------------------------------------------------------------
		case MR_PS_ITEMTYPE_3DSPRITE:
			test_pos.vx = MRPresitem_ptr->pi_x;
			test_pos.vy = MRPresitem_ptr->pi_y;
			test_pos.vz = *script_ptr++;
			
			function = (MR_VOID*)*script_ptr++;

			// ptr1 becomes MR_FRAME*
			MRPresitem_ptr->pi_ptr1 = MRCreateFrame(&test_pos, &MRNull_svec, NULL);

			// ptr0 becomes MR_OBJECT*
			MRPresitem_ptr->pi_ptr0 = MRCreate3DSprite((MR_FRAME*)MRPresitem_ptr->pi_ptr1, NULL, (MR_VOID*)*script_ptr++);

			// Post-creation callback
			if (function)
				(function)();

			MRAddObjectToViewport((MR_OBJECT*)MRPresitem_ptr->pi_ptr0, MRDefault_vp, NULL);
			break;
		//-----------------------------------------------------------------------------------------
		}

	return(script_ptr);
}


/******************************************************************************
*%%%% MRPresGetJustifiedX
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_SHORT x_val =	MRPresGetJustifiedX(
*									MR_USHORT	type,
*									MR_USHORT	w,
*									MR_SHORT	margin);
*
*	FUNCTION	Get an X value based on a vertical margin and justification
*				type
*
*	INPUTS		type 		-	eg MR_PS_JUST_LEFT
*				w	 		-	width of item (in pixels)
*				margin		-	margin (in pixels)
*
*	RESULT		x_val		-	x value
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_SHORT	MRPresGetJustifiedX(MR_USHORT type,
								MR_USHORT w,
								MR_SHORT margin)
{
	switch(type)
		{
		case MR_PS_JUST_LEFT:
			return(margin);
			break;

		case MR_PS_JUST_CENTRE:
			return(margin - (w >> 1));
			break;

		case MR_PS_JUST_RIGHT:
			return(margin - w);
			break;
		}
}


/******************************************************************************
*%%%% MRCreatePresitem
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_PRESITEM*	MRCreatePresitem(
*								MR_USHORT	type);
*
*	FUNCTION	Allocate memory and link in a MR_PRESITEM structure
*
*	INPUTS		type			-	Presitem type
*
*	RESULT		presitem_ptr	-	Pointer to created MR_PRESITEM, or NULL
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_PRESITEM*	MRCreatePresitem(MR_USHORT type)
{
	MR_PRESITEM*	pi_ptr;
	LINE_F3*		line_f3_ptr;
	POLY_FT3*		poly_ft3_ptr;


	// Allocate memory for MR_PRESITEM and additional primitive space
	switch(type)
		{
		case MR_PS_ITEMTYPE_TEXT:
		case MR_PS_ITEMTYPE_2DSPRITE:
		case MR_PS_ITEMTYPE_3DSPRITE:
			// These require no extra prims
			pi_ptr = (MR_PRESITEM*)MRAllocMem(sizeof(MR_PRESITEM), "MR_PI");
			pi_ptr->pi_prims[0] = NULL;
			pi_ptr->pi_prims[1] = NULL;
			break;

		case MR_PS_ITEMTYPE_BOX:
			// __BOX requires POLY_G4 per buffer
			pi_ptr = (MR_PRESITEM*)MRAllocMem(sizeof(MR_PRESITEM) + (sizeof(POLY_G4) * 2) + (sizeof(POLY_FT3) * 2), "MR_PI");
			pi_ptr->pi_prims[0] = (MR_ULONG*)(((MR_BYTE*)pi_ptr) + sizeof(MR_PRESITEM));
			pi_ptr->pi_prims[1] = (MR_ULONG*)(((MR_BYTE*)pi_ptr) + sizeof(MR_PRESITEM) + sizeof(POLY_G4) + sizeof(POLY_FT3));
			setPolyG4((POLY_G4*)pi_ptr->pi_prims[0]);
			setPolyG4((POLY_G4*)pi_ptr->pi_prims[1]);
			setPolyFT3((POLY_FT3*)(((MR_BYTE*)pi_ptr->pi_prims[0]) + sizeof(POLY_G4)));
			setPolyFT3((POLY_FT3*)(((MR_BYTE*)pi_ptr->pi_prims[1]) + sizeof(POLY_G4)));
			setSemiTrans((POLY_G4*)pi_ptr->pi_prims[0], 1);
			setSemiTrans((POLY_G4*)pi_ptr->pi_prims[1], 1);

			poly_ft3_ptr = (POLY_FT3*)(((MR_BYTE*)pi_ptr->pi_prims[0]) + sizeof(POLY_G4));
			poly_ft3_ptr->x0 = -1;
			poly_ft3_ptr->x1 = -1;
			poly_ft3_ptr->x2 = -1;
			poly_ft3_ptr->y0 = -1;
			poly_ft3_ptr->y1 = -1;
			poly_ft3_ptr->y2 = -1;
			poly_ft3_ptr->tpage = defTPage(0, 0, 2);		// abr 2
			poly_ft3_ptr = (POLY_FT3*)(((MR_BYTE*)pi_ptr->pi_prims[1]) + sizeof(POLY_G4));
			poly_ft3_ptr->x0 = -1;
			poly_ft3_ptr->x1 = -1;
			poly_ft3_ptr->x2 = -1;
			poly_ft3_ptr->y0 = -1;
			poly_ft3_ptr->y1 = -1;
			poly_ft3_ptr->y2 = -1;
			poly_ft3_ptr->tpage = defTPage(0, 0, 2);		// abr 2
			break;

		case MR_PS_ITEMTYPE_OUTLINE:
			// __BOX requires two LINE_F3 per buffer
			pi_ptr = (MR_PRESITEM*)MRAllocMem(sizeof(MR_PRESITEM) + (sizeof(LINE_F3) * 4), "MR_PI");
			pi_ptr->pi_prims[0] = (MR_ULONG*)(((MR_BYTE*)pi_ptr) + sizeof(MR_PRESITEM));
			pi_ptr->pi_prims[1] = (MR_ULONG*)(((MR_BYTE*)pi_ptr) + sizeof(MR_PRESITEM) + sizeof(LINE_F3) * 2);

			line_f3_ptr = (LINE_F3*)pi_ptr->pi_prims[0];
			setLineF3(line_f3_ptr);
			line_f3_ptr++;
			setLineF3(line_f3_ptr);
			line_f3_ptr++;
			setLineF3(line_f3_ptr);
			line_f3_ptr++;
			setLineF3(line_f3_ptr);
			line_f3_ptr++;
			break;

		default:
			return(NULL);
			break;
		}

	// Link new object into list
	if (pi_ptr->pi_next_node = MRPresitem_root_ptr->pi_next_node)
		MRPresitem_root_ptr->pi_next_node->pi_prev_node = pi_ptr;
	MRPresitem_root_ptr->pi_next_node = pi_ptr;
	pi_ptr->pi_prev_node = MRPresitem_root_ptr;

	MRNumber_of_presitems++;

	// Initialise structure	
	pi_ptr->pi_type = type;
	pi_ptr->pi_flags = 0;
	pi_ptr->pi_timer = 0;

	return(pi_ptr);
}


/******************************************************************************
*%%%% MRKillAllPresitems
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKillAllPresitems(MR_VOID)
*
*	FUNCTION	Destroys all MR_PRESITEM's, but uses a kill timer so that 
*				the memory is only freed once the GPU has finished rendering
*				associated primitives, and also calls the timer-based object
*				destruction routines.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillAllPresitems(MR_VOID)
{
	MR_PRESITEM*	pi_ptr = MRPresitem_root_ptr;

	while(pi_ptr = pi_ptr->pi_next_node)
		{
		if (!pi_ptr->pi_timer)
			{		
			pi_ptr->pi_timer = 2;

			if (pi_ptr->pi_flags & MR_PS_ITEM_OWNS_TEXT)
				// Kill text area
				MRFreeTextArea((MR_TEXT_AREA*)pi_ptr->pi_ptr0);
			else
			if (pi_ptr->pi_type == MR_PS_ITEMTYPE_2DSPRITE)
				// Kill 2D sprite
				MRKill2DSprite((MR_2DSPRITE*)pi_ptr->pi_ptr0);
			else
			if (pi_ptr->pi_type == MR_PS_ITEMTYPE_3DSPRITE)
				{
				// Kill 3D sprite and associated MR_FRAME
				((MR_OBJECT*)pi_ptr->pi_ptr0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
				MRKillFrame((MR_FRAME*)pi_ptr->pi_ptr1);
				}
			}
		}
	MRPresoption_update_callback = NULL;
	MRPresoption_move_callback = NULL;
}


/******************************************************************************
*%%%% MRKillAllPresitemsPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	MRKillAllPresitemsPhysically(MR_VOID)
*
*	FUNCTION		Destroys all MR_PRESITEM's immediately.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.96		Tim Closs		Create
*
*%%%**************************************************************************/

MR_VOID	MRKillAllPresitemsPhysically(MR_VOID)
{
	MR_PRESITEM*	pi_ptr = MRPresitem_root_ptr;


	while(pi_ptr = pi_ptr->pi_next_node)
		{
		if (pi_ptr->pi_flags & MR_PS_ITEM_OWNS_TEXT)
			// Kill text area
			MRFreeTextAreaPhysically((MR_TEXT_AREA*)pi_ptr->pi_ptr0);
		else
		if (pi_ptr->pi_type == MR_PS_ITEMTYPE_2DSPRITE)
			// Kill 2D sprite
			MRKill2DSprite((MR_2DSPRITE*)pi_ptr->pi_ptr0);
		else
		if (pi_ptr->pi_type == MR_PS_ITEMTYPE_3DSPRITE)
			{
			// Kill 3D sprite and associated MR_FRAME
			((MR_OBJECT*)pi_ptr->pi_ptr0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
			MRKillFrame((MR_FRAME*)pi_ptr->pi_ptr1);
			}

		// Kill the MR_PRESITEM itself!
		pi_ptr = pi_ptr->pi_prev_node;
		MRKillPresitem(pi_ptr->pi_next_node);				
		}

	MRPresoption_update_callback = NULL;
	MRPresoption_move_callback = NULL;
}


/******************************************************************************
*%%%% MRKillPresitem
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	MRKillPresitem(
*								MR_PRESITEM* pi_ptr)
*
*	FUNCTION		Destroys a specific MR_PRESITEM, immediately.
*
*	INPUTS		pi_ptr		-		Pointer to a valid MR_PRESITEM structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.96		Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRKillPresitem(MR_PRESITEM* pi_ptr)
{
	// Remove structure from linked list
	pi_ptr->pi_prev_node->pi_next_node = pi_ptr->pi_next_node;
	if	(pi_ptr->pi_next_node)
		pi_ptr->pi_next_node->pi_prev_node = pi_ptr->pi_prev_node;

	// Free structure memory
	MRFreeMem(pi_ptr);
}


/******************************************************************************
*%%%% MRInputPres
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInputPres(MR_USHORT	pad_id);
*
*	FUNCTION	Alter presentation paged based on user input.
*
*	INPUTS		pad_id	-	controller to read (0 or 1)
*
*	NOTES		I do not like the access to joypad button definitions here. 
*				It isn't suitable for the API to be reading controller input!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.96	Tim Closs		Created
*	05.11.96	Tim Closs		Changed to accept pad id
*
*%%%**************************************************************************/

MR_VOID	MRInputPres(MR_USHORT	pad_id)
{
	static MR_ULONG input_maps[] =
		{
		MRIP_UP, MRIP_DOWN, MRIP_LEFT, MRIP_RIGHT,
		MRIP_LEFT, MRIP_RIGHT, MRIP_DOWN, MRIP_UP,
		};

	MR_ULONG*		map_ptr;
	MR_PRESOPTION*	po_ptr = &MRPresoptions[MRPresoption_index];


	if (MRPresoption_direction == MR_PS_VERTICAL)
		map_ptr = &input_maps[0];
	else
		map_ptr = &input_maps[4];

	if (!MRPresoption_timer)
		{
		// Move timer 0, so allow input
		if (
			(MR_CHECK_PAD_PRESSED(pad_id, map_ptr[0])) &&
			(!(po_ptr->po_flags & MR_PS_OPTION_TOP))
			)
			{
			if (MRPresoption_move_callback)
				(MRPresoption_move_callback)();
			MRPresoption_index--;
			MRPresoption_timer = MRPresoption_change_time;
			}
		else
		if (
			(MR_CHECK_PAD_PRESSED(pad_id, map_ptr[1])) &&
			(!(po_ptr->po_flags & MR_PS_OPTION_BOTTOM))
			)
			{
			if (MRPresoption_move_callback)
				(MRPresoption_move_callback)();
			MRPresoption_index++;
			MRPresoption_timer = MRPresoption_change_time;
			}
		else
		if (
			(MR_CHECK_PAD_PRESSED(pad_id, MRIP_BLUE)) &&
			(po_ptr->po_callback)
			)
			{
			(po_ptr->po_callback)();
			}
		else		
		if (po_ptr->po_text_list)
			{
			// Current option is variable
			if (MR_CHECK_PAD_PRESSED(pad_id, map_ptr[2]))
				{
				if (po_ptr->po_type == MR_PS_OPTIONTYPE_WALK)
					{			
					// Decrease variable if not min
					if (*(po_ptr->po_text_list + (*po_ptr->po_variable + 1) - 1))
						(*po_ptr->po_variable)--;
					}
				else
					{
					// Decrease variable  - if min, set to max
					if (!(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1) - 1)))
						{
						while(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1)))
							(*po_ptr->po_variable)++;
						}
					(*po_ptr->po_variable)--;
					}
				MRBuildText((MR_TEXT_AREA*)po_ptr->po_presitem->pi_ptr0, (MR_STRPTR*)(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1))), MR_FONT_COLOUR_WHITE);
				}
			else
			if (MR_CHECK_PAD_PRESSED(0, map_ptr[3]))
				{
				if (po_ptr->po_type == MR_PS_OPTIONTYPE_WALK)
					{			
					// Increase variable if not max
					if (*(po_ptr->po_text_list + (*po_ptr->po_variable + 1) + 1))
						(*po_ptr->po_variable)++;
					}
				else
					{
					// Increase variable  - if max, set to min
					if (!(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1) + 1)))
						{
						while(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1)))
							(*po_ptr->po_variable)--;
						}
					(*po_ptr->po_variable)++;
					}
				MRBuildText((MR_TEXT_AREA*)po_ptr->po_presitem->pi_ptr0, (MR_STRPTR*)(*(po_ptr->po_text_list + (*po_ptr->po_variable + 1))), MR_FONT_COLOUR_WHITE);
				}
			}
		}
}


/******************************************************************************
*%%%% MRUpdatePres
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUpdatePres(MR_VOID);
*
*	FUNCTION	Update miscellaneous elements related to presentation code
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRUpdatePres(MR_VOID)
{
	if (MRPresoption_timer)
		MRPresoption_timer--;

	if (MRPresoption_update_callback)
		(MRPresoption_update_callback)();
}


/******************************************************************************
*%%%% MRRenderPres
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRenderPres(
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Display all presentation elements not handled by the
*				MRRenderViewport function.
*
*	INPUTS		vp		-	ptr to viewport to render into
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	04.11.96	Tim Closs		Now takes viewport input
*
*%%%**************************************************************************/

MR_VOID	MRRenderPres(MR_VIEWPORT*	vp)
{
	MR_PRESITEM*	pi_ptr;
	POLY_G4*		poly_g4_ptr;
	LINE_F3*		line_f3_ptr;
	POLY_FT3*		poly_ft3_ptr;


	MRDefault_vp = vp;

	// Make sure the LW matrix is rebuilt first time
	MRWorldtrans_ptr = NULL;

 	pi_ptr = MRPresitem_root_ptr;
	while(pi_ptr = pi_ptr->pi_next_node)
		{
		if (pi_ptr->pi_timer)
			{
			if (!(--pi_ptr->pi_timer))
				{
				// Kill MR_PRESITEM
				pi_ptr = pi_ptr->pi_prev_node;
				MRKillPresitem(pi_ptr->pi_next_node);				
				}
			}
		else
			{
			switch(pi_ptr->pi_type)
				{
				//---------------------------------------------------------------------------------------
				case MR_PS_ITEMTYPE_BOX:
					poly_g4_ptr = (POLY_G4*)pi_ptr->pi_prims[MRFrame_index];
					poly_g4_ptr->x0 = pi_ptr->pi_x;
					poly_g4_ptr->x2 = pi_ptr->pi_x;
					poly_g4_ptr->x1 = pi_ptr->pi_x + pi_ptr->pi_w;
					poly_g4_ptr->x3 = pi_ptr->pi_x + pi_ptr->pi_w;
					poly_g4_ptr->y0 = pi_ptr->pi_y;
					poly_g4_ptr->y1 = pi_ptr->pi_y;
					poly_g4_ptr->y2 = pi_ptr->pi_y + pi_ptr->pi_h;
					poly_g4_ptr->y3 = pi_ptr->pi_y + pi_ptr->pi_h;
					addPrim(vp->vp_work_ot + MRPres_text_ot + 1, poly_g4_ptr);
					// Add POLY_FT3 (abr changer) last, to render first
					poly_ft3_ptr = (POLY_FT3*)(((MR_BYTE*)pi_ptr->pi_prims[MRFrame_index]) + sizeof(POLY_G4));
					addPrim(vp->vp_work_ot + MRPres_text_ot + 1, poly_ft3_ptr);
					break;														 	
				//---------------------------------------------------------------------------------------
				case MR_PS_ITEMTYPE_OUTLINE:
					line_f3_ptr = (LINE_F3*)pi_ptr->pi_prims[MRFrame_index];
					line_f3_ptr->x0 = pi_ptr->pi_x;
					line_f3_ptr->x1 = pi_ptr->pi_x + pi_ptr->pi_w - 1;
					line_f3_ptr->x2 = pi_ptr->pi_x + pi_ptr->pi_w - 1;
					line_f3_ptr->y0 = pi_ptr->pi_y;
					line_f3_ptr->y1 = pi_ptr->pi_y;
					line_f3_ptr->y2 = pi_ptr->pi_y + pi_ptr->pi_h - 1;
					setRGB0(line_f3_ptr, pi_ptr->pi_colour.r, pi_ptr->pi_colour.g, pi_ptr->pi_colour.b);
					addPrim(vp->vp_work_ot + MRPres_text_ot + 0, line_f3_ptr);
					line_f3_ptr++;
					line_f3_ptr->x0 = pi_ptr->pi_x;
					line_f3_ptr->x1 = pi_ptr->pi_x;
					line_f3_ptr->x2 = pi_ptr->pi_x + pi_ptr->pi_w - 1;
					line_f3_ptr->y0 = pi_ptr->pi_y;
					line_f3_ptr->y1 = pi_ptr->pi_y + pi_ptr->pi_h - 1;
					line_f3_ptr->y2 = pi_ptr->pi_y + pi_ptr->pi_h - 1;
					setRGB0(line_f3_ptr, pi_ptr->pi_colour.r, pi_ptr->pi_colour.g, pi_ptr->pi_colour.b);
					addPrim(vp->vp_work_ot + MRPres_text_ot + 0, line_f3_ptr);
					break;
				//---------------------------------------------------------------------------------------
				}
			}
		}
}


/******************************************************************************
*%%%% MRHideTextPresitems
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRHideTextPresitems(MR_VOID)
*
*	FUNCTION	Turns off any text owned by MR_PRESITEMs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRHideTextPresitems(MR_VOID)
{
	MR_PRESITEM*	pi_ptr = MRPresitem_root_ptr;


	while(pi_ptr = pi_ptr->pi_next_node)
		{
		if (pi_ptr->pi_flags & MR_PS_ITEM_OWNS_TEXT)
			{
			// Hide text area
			((MR_TEXT_AREA*)pi_ptr->pi_ptr0)->ta_display = FALSE;
			}
		}
}
	

/******************************************************************************
*%%%% MRShowTextPresitems
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShowTextPresitems(MR_VOID)
*
*	FUNCTION	Turns on any text owned by MR_PRESITEMs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRShowTextPresitems(MR_VOID)
{
	MR_PRESITEM*	pi_ptr = MRPresitem_root_ptr;


	while(pi_ptr = pi_ptr->pi_next_node)
		{
		if (pi_ptr->pi_flags & MR_PS_ITEM_OWNS_TEXT)
			{
			// Show text area
			((MR_TEXT_AREA*)pi_ptr->pi_ptr0)->ta_display = TRUE;
			}
		}
}
	
