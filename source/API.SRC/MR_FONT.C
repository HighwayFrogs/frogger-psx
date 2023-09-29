/******************************************************************************
*%%%% mr_font.c
*------------------------------------------------------------------------------
*
*	Font routines
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96	Dean Ashton		Created
*	03.07.96	Dean Ashton		Added MRSetDefaultFont() and changed 
*								MRAllocateTextArea() to use it.
*	07.08.96	Dean Ashton		Fixed bug with -ve handling in MRAddNumText
*	16.10.96	Dean Ashton		Added check for length > 0 in MRAddNumText
*	30.10.96	Dean Ashton		Fixed horizontal offset bug in MRBuildTextPrims
*	11.12.96	Tim Closs		Added MRSetTextTransparency and MRSetTextColour
*	14.02.97	Dean Ashton		Transparency now called Translucency... 
*	14.07.97	Dean Ashton		Supports in-line exclusion zone in MRParseText,
*								delimited by '%<' and '%>', allowing project
*								specific tokens into the text stream for
*								user-modification.
*	14.07.97	Dean Ashton		Added MRSetFontColourTable() to allow project
*								control of font colour choices.
*
*%%%**************************************************************************/

#include	"mr_all.h"


MR_UBYTE				MRFont_text_buff[MR_FONT_MAX_BUFF_LIMIT];		// Room for expanded text
MR_UBYTE*				MRFont_buff_ptr;					  			// Pointer into expanded text buffer
MR_FONT_LINE_INFO		MRFont_line_info[MR_FONT_MAX_LINE_LIMIT];		// Room for all our line info
MR_STRPTR*				MRFont_data_ptr;					  			// Pointer to next item in list

MR_CVEC					MRFont_default_colours[] = 
						{
							{0x80,0x80,0x80},		// MR_FONT_COLOUR_WHITE
							{0x01,0x01,0x01},		// MR_FONT_COLOUR_BLACK
							{0x80,0x00,0x00},		// MR_FONT_COLOUR_RED
							{0x00,0x80,0x00},		// MR_FONT_COLOUR_GREEN
							{0x00,0x00,0x80},		// MR_FONT_COLOUR_BLUE
							{0x00,0x80,0x80},		// MR_FONT_COLOUR_CYAN
							{0x80,0x00,0x80},		// MR_FONT_COLOUR_MAGENTA
							{0x80,0x80,0x00},		// MR_FONT_COLOUR_YELLOW
							{0xa0,0x60,0x20},		// MR_FONT_COLOUR_BROWN
							{0x50,0x50,0x50},		// MR_FONT_COLOUR_GREY
							{0x30,0x30,0x30},		// MR_FONT_COLOUR_DARK_GREY
							{0x20,0x20,0x50},		// MR_FONT_COLOUR_DARK_BLUE
							{0x01,0x01,0x01},		// MR_FONT_COLOUR_NEAR_BLACK
							{0xff,0x64,0x00},		// MR_FONT_COLOUR_CADMIUM
							{0x80,0x50,0x10},		// MR_FONT_COLOUR_ORANGE
						};

// Setup a pointer to our default font colour table
MR_CVEC*				MRFont_colour_table_ptr = MRFont_default_colours;
		
MR_FONT_INFO*			MRDefault_font_info;


/******************************************************************************
*%%%% MRSetDefaultFont
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetDefaultFont(
*						MR_FONT_INFO	font_info);
*
*	FUNCTION	Sets a pointer to a MR_FONT_INFO structure that will be used
*				as the default font.
*
*	INPUTS		font_info	-	Pointer to a valid MR_FONT_INFO
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetDefaultFont(MR_FONT_INFO* font_info)
{
	MR_ASSERT(font_info != NULL);

	MRDefault_font_info = font_info;
}


/******************************************************************************
*%%%% MRSetFontColourTable
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetDefaultFont(
*						MR_CVEC*	table_ptr);
*
*	FUNCTION	Sets a user supplied array of 16 MR_CVEC's to be our internal
*				font colour table.. 
*
*	INPUTS		table_ptr	-	Pointer to a 16 entry array of MR_CVEC's.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.07.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetFontColourTable(MR_CVEC*	table_ptr)
{
	MR_ASSERT(table_ptr != NULL);

	MRFont_colour_table_ptr = table_ptr;
}


/******************************************************************************
*%%%%	MRAllocateTextArea
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_TEXT_AREA* area =	MRAllocateTextArea(
*										MR_ULONG		at_flags,
*										MR_FONT_INFO*	at_font_info,
*										MR_VIEWPORT*	at_viewport,
*										MR_SHORT		at_max_chars,
*										MR_SHORT		at_box_x,
*										MR_SHORT		at_box_y,
*										MR_SHORT		at_box_w,
*										MR_SHORT		at_box_h);
*
*	FUNCTION	Allocates storage for a text area and the associated primitive
*				data, linking it into the specified viewport list for display.
*
*	INPUTS		at_flags	 	-		Flags for text area
*				at_font_info	-		Pointer to a font's MR_FONT_INFO structure
*										or NULL to use default font.
*				at_viewport		-		Viewport to link text area to
*				at_max_chars	-		Maximum number of characters in text area
*				at_box_x		-		Box x position (relative to viewport)
*				at_box_y		-		Box y position (relative to viewport)
*				at_box_w		-		Box width
*				at_box_h		-		Box height
*
*	RESULT		area			-		Pointer to allocated MR_TEXT_AREA.
*
*	NOTES		Text data and primitive data are in a single allocation for 
*				efficiency. Text is allocated as SPRT structures by default,
*				which means characters can only be even pixel widths. Flags
*				can be set to use polygon characters instead.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	03.07.96	Dean Ashton		Changed to accept NULL as pointer to font info
*					   			to indicate use of default font.
*	14.02.97	Dean Ashton		Transparency -> Translucency... 
*
*%%%**************************************************************************/

MR_TEXT_AREA*	MRAllocateTextArea(	MR_ULONG 		at_flags,
					   				MR_FONT_INFO*	at_font_info,
					   				MR_VIEWPORT*	at_viewport,
					   				MR_SHORT 		at_max_chars,
					   				MR_SHORT 		at_box_x,
					   				MR_SHORT 		at_box_y,
					   				MR_SHORT 		at_box_w,
					   				MR_SHORT 		at_box_h)
{

	MR_TEXT_AREA*	at_area_ptr;						// Pointer to currently allocated area
	MR_LONG			at_loop;
	MR_BOOL			at_using_sprites;
	SPRT*			at_sprt_0;
	SPRT*			at_sprt_1;
	POLY_FT4*		at_poly_0;
	POLY_FT4*		at_poly_1;
	POLY_FT3*		at_poly_ft3;

	MR_ASSERT(at_viewport != NULL);

	if (at_font_info == NULL)
		{
		MR_ASSERT(MRDefault_font_info != NULL);
		at_font_info = MRDefault_font_info;
		}

	// Allocate space for the area and primitive data, and resolve primitive pointers..
	if (at_flags & MR_FAREA_USE_POLYS)
		{
		at_area_ptr = (MR_TEXT_AREA *)MRAllocMem(sizeof(MR_TEXT_AREA)+(sizeof(POLY_FT4)*2*at_max_chars), "FONTPOLY");
		at_area_ptr->ta_prims[0] = (SPRT *)((MR_ULONG)at_area_ptr + sizeof(MR_TEXT_AREA));
		at_area_ptr->ta_prims[1] = (SPRT *)((MR_ULONG)at_area_ptr + sizeof(MR_TEXT_AREA) + (sizeof(POLY_FT4)*at_max_chars)); 	
		at_using_sprites = FALSE;
		}		
	else
		{
		at_area_ptr = (MR_TEXT_AREA *)MRAllocMem(sizeof(MR_TEXT_AREA)+(sizeof(SPRT)*2*at_max_chars), "FONTSPRT");
		at_area_ptr->ta_prims[0] = (SPRT *)((MR_ULONG)at_area_ptr + sizeof(MR_TEXT_AREA));
		at_area_ptr->ta_prims[1] = (SPRT *)((MR_ULONG)at_area_ptr + sizeof(MR_TEXT_AREA) + (sizeof(SPRT)*at_max_chars)); 	
		at_using_sprites = TRUE;
		}


	// Link text area into viewport
	if (at_area_ptr->ta_next_node = ((MR_TEXT_AREA*)(at_viewport->vp_text_area_root_ptr))->ta_next_node)
		((MR_TEXT_AREA*)(at_viewport->vp_text_area_root_ptr))->ta_next_node->ta_prev_node = at_area_ptr;

	((MR_TEXT_AREA*)(at_viewport->vp_text_area_root_ptr))->ta_next_node = at_area_ptr;
	at_area_ptr->ta_prev_node = ((MR_TEXT_AREA*)(at_viewport->vp_text_area_root_ptr));

	// Setup remaining fields within the MR_TEXT_AREA structure, and initialise primitives
	at_area_ptr->ta_font_info		= at_font_info;
	at_area_ptr->ta_viewport		= at_viewport;
	at_area_ptr->ta_display			= TRUE;
	at_area_ptr->ta_flags 			= at_flags;
	at_area_ptr->ta_otz				= MR_FONT_DEFAULT_OT_POS;
	at_area_ptr->ta_box_x			= at_box_x;
	at_area_ptr->ta_box_y			= at_box_y;
	at_area_ptr->ta_box_w			= at_box_w;
	at_area_ptr->ta_box_h			= at_box_h;
	at_area_ptr->ta_xofs 			= 0;
	at_area_ptr->ta_yofs 			= 0;
	at_area_ptr->ta_max_chars		= at_max_chars;
	at_area_ptr->ta_rend_chars		= 0;
	at_area_ptr->ta_tpage			= setABR(at_font_info->fi_font_sprite->te_tpage_id,at_font_info->fi_font_abr);
	at_area_ptr->ta_clut 			= at_font_info->fi_font_sprite->te_clut_id;
	at_area_ptr->ta_old_polys[0]	= 0;
	at_area_ptr->ta_old_polys[1]	= 0;
	at_area_ptr->ta_height_extra	= 0;
	at_area_ptr->ta_kill_timer		= 0;
	

	at_sprt_0 = (SPRT *)at_area_ptr->ta_prims[0];
	at_sprt_1 = (SPRT *)at_area_ptr->ta_prims[1];

	at_poly_0 = (POLY_FT4 *)at_area_ptr->ta_prims[0];
	at_poly_1 = (POLY_FT4 *)at_area_ptr->ta_prims[1];

	for (at_loop = 0; at_loop < at_max_chars; at_loop++)
		{
		if (at_using_sprites)
			{
			setSprt(at_sprt_0);
			setRGB0(at_sprt_0,0x80,0x80,0x80);
			at_sprt_0->clut = at_area_ptr->ta_clut;
			
			setSprt(at_sprt_1);
			setRGB0(at_sprt_1,0x80,0x80,0x80);
			at_sprt_1->clut = at_area_ptr->ta_clut;

			if (at_font_info->fi_font_flags & MR_FINFO_TRANSLUCENT)
				{
				setSemiTrans(at_sprt_0, 1);
				setSemiTrans(at_sprt_1, 1);
				}

			at_sprt_0++;
			at_sprt_1++;
			}
		else
			{
			setPolyFT4(at_poly_0);
			setRGB0(at_poly_0,0x80,0x80,0x80);
			at_poly_0->tpage	= at_area_ptr->ta_tpage;
			at_poly_0->clut	= at_area_ptr->ta_clut;
			
			setPolyFT4(at_poly_1);
			setRGB0(at_poly_1,0x80,0x80,0x80);
			at_poly_1->tpage	= at_area_ptr->ta_tpage;
			at_poly_1->clut	= at_area_ptr->ta_clut;

			if (at_font_info->fi_font_flags & MR_FINFO_TRANSLUCENT)
				{
				setSemiTrans(at_poly_0, 1);
				setSemiTrans(at_poly_1, 1);
				}

			at_poly_0++;
			at_poly_1++;
			}
		}


	// If we're using sprites, then we need to set texture page change primitives.
	if (at_using_sprites)
		{
		at_poly_ft3 			= &at_area_ptr->ta_change_tpage[0];
		setPolyFT3(at_poly_ft3);
		at_poly_ft3->x0 		= at_poly_ft3->x1 = at_poly_ft3->x2 = -1;
		at_poly_ft3->y0 		= at_poly_ft3->y1 = at_poly_ft3->y2 = -1;
		at_poly_ft3->tpage		= at_area_ptr->ta_tpage;
		at_poly_ft3->clut		= at_area_ptr->ta_clut;

		at_poly_ft3 			= &at_area_ptr->ta_change_tpage[1];
		setPolyFT3(at_poly_ft3);
		at_poly_ft3->x0 		= at_poly_ft3->x1 = at_poly_ft3->x2 = -1;
		at_poly_ft3->y0 		= at_poly_ft3->y1 = at_poly_ft3->y2 = -1;
		at_poly_ft3->tpage		= at_area_ptr->ta_tpage;
		at_poly_ft3->clut		= at_area_ptr->ta_clut;
		}

	return(at_area_ptr);

}


/******************************************************************************
*%%%% MRFreeTextArea
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRFreeTextArea(
*						MR_TEXT_AREA*	fa_text_area);
*
*	FUNCTION	Frees a text area that has previously been allocated with
*				MRAllocateTextArea().
*
*	INPUTS		fa_text_area	-	Pointer to a valid MR_TEXT_AREA
*
*	NOTES		This function uses kill timers to ensure the primitive data
*				isn't freed until it is clear from GPU rendering.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRFreeTextArea(MR_TEXT_AREA *fa_text_area)
{
	MR_ASSERT(fa_text_area != NULL);

	// Stop rendering of the area
	fa_text_area->ta_display = FALSE;	

	// Do something with kill timers here... and remember, we could do with a 
	// MRFreeTextAreaPhysically() function that frees immediately...
	fa_text_area->ta_kill_timer = 2;
}

/******************************************************************************
*%%%% MRFreeTextAreaPhysically
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRFreeTextAreaPhysically(
*						MR_TEXT_AREA*	fa_text_area);
*
*	FUNCTION	Frees a text area that has previously been allocated with
*				MRAllocateTextArea(), but free it immediately.
*
*	INPUTS		fa_text_area	-	Pointer to a valid MR_TEXT_AREA
*
*	NOTES		This function frees resources immediately. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRFreeTextAreaPhysically(MR_TEXT_AREA* fa_text_area)
{
	MR_ASSERT(fa_text_area != NULL);

	fa_text_area->ta_display = FALSE;	

	fa_text_area->ta_prev_node->ta_next_node = fa_text_area->ta_next_node;
	if	(fa_text_area->ta_next_node)
		fa_text_area->ta_next_node->ta_prev_node = fa_text_area->ta_prev_node;

	MRFreeMem(fa_text_area);
}


/******************************************************************************
*%%%% MRBuildText
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRBuildText(
*						MR_TEXT_AREA*	bt_area_ptr,
*						MR_STRPTR*		bt_text,
*						MR_USHORT		bt_colour);
*
*	FUNCTION	Performs processing necessary to build a list of primitives that
*				we can use to render a specific piece of text to a particular
*				area of the screen.
*
*	INPUTS		bt_area_ptr	-	Pointer to an allocated text area
*				bt_text		-	Pointer to an array of MR_STRPTR's pointing
*							 	to text and substitution variables.
*				bt_colour	-	Colour identifier
*
*	NOTES		'bt_text' does NOT point to text. It points to an array of
*				pointers to text and variables that is null terminated. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRBuildText(MR_TEXT_AREA*	bt_area_ptr,
					MR_STRPTR*		bt_text,
					MR_USHORT 		bt_colour)
{
	MR_ASSERT(bt_area_ptr != NULL);
	MR_ASSERT(bt_text != NULL);
	MR_ASSERT(bt_colour <= MR_FONT_MAX_COLOUR_ID);

	// Initialise some variables for us, will ya?
	MRFont_buff_ptr	= MRFont_text_buff;
	MRFont_data_ptr	= bt_text; 

	// First, mark both polygon buffers as invalid
	bt_area_ptr->ta_old_polys[0] = 1;
	bt_area_ptr->ta_old_polys[1] = 1;

	// Store the build colour in the text area
	bt_area_ptr->ta_build_colour = bt_colour;

	// Process the text array until all string pointers have been handled
	while	(*MRFont_data_ptr)
		{
		MRParseText((MR_STRPTR)(*MRFont_data_ptr));	// Expand a paragraph into buffer
		MRFont_data_ptr++;							// Point to the next string pointer
		}

	// Null terminate the last string in the expansion buffer
	*MRFont_buff_ptr	= 0x00;

	// Count the non-space and non-control characters (ie printable)
	MRFont_buff_ptr				= MRFont_text_buff;
	bt_area_ptr->ta_rend_chars	= 0;

	while (*MRFont_buff_ptr)
		{
		if ((*MRFont_buff_ptr > ' ') && (*MRFont_buff_ptr < MR_FBUFF_FLAG_CODE))
			bt_area_ptr->ta_rend_chars++;

		MRFont_buff_ptr++;
		}

	// Ensure there are enough characters
	MR_ASSERT(bt_area_ptr->ta_rend_chars <= bt_area_ptr->ta_max_chars);
	
	// Build the line information
	MRBuildLineInfo(bt_area_ptr);

	// Mark the current polygon buffer as valid...
	bt_area_ptr->ta_old_polys[MRFrame_index] = 0;

	// ... and then build the primitives (for current buffer. Other buffer is resolved later)
	MRBuildTextPrims(bt_area_ptr);

	// Dunno quite why we do this. I'd have thought the xofs/yofs bits would be zero to 
	// start with, but hey... it worked in Defcon 5!!!
	bt_area_ptr->ta_xofs = bt_area_ptr->ta_prims[MRFrame_index]->x0 - bt_area_ptr->ta_box_x;
	bt_area_ptr->ta_yofs = bt_area_ptr->ta_prims[MRFrame_index]->y0 - bt_area_ptr->ta_box_y;
}


/******************************************************************************
*%%%% MRParseText
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRParseText(
*						MR_STRPTR	pt_paragraph);
*
*	FUNCTION	Interprets a string of text, performing tokenisation of control
*				commands and insertion of parameters. Characters are inserted
*				into a global text buffer.
*
*	INPUTS		pt_paragraph	-	Pointer to an MR_STRPTR
*
*	NOTES		MRFont_data_ptr points to the next pointer in the MR_STRPTR
*				array. This could be a variable, replacement, or another 
*				paragraph.. whatever, it is modified by this routine..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	05.03.97	Dean Ashton		Added support for left justified numbers
*	17.04.97	Dean Ashton		Modified for in-line colour changing
*	14.07.97	Dean Ashton		Supports in-line exclusion zone, delimited by
*								'%<' and '%>', allowing project specific tokens
*								into the text stream for user-modification.
*
*%%%**************************************************************************/

MR_VOID	MRParseText(MR_STRPTR pt_paragraph)
{
	MR_ULONG	pt_state = MR_FPARS_NORMAL;
	MR_UBYTE	pt_last_char;

	MR_ASSERT(pt_paragraph != NULL);

	// First, we need to perform all variable substitution and
	// tokenise the command codes (such as justification and font
	// change requests).
	while (*(pt_paragraph))
		{
		switch(pt_state)
			{

			// Normal character control
			case MR_FPARS_NORMAL:
				switch (*pt_paragraph)
					{
					case	'%':								// Set state for percent 
						pt_state = MR_FPARS_PERCENT;			// control codes
						break;

					default:									// Normal text is just copied
						*MRFont_buff_ptr++ = *pt_paragraph;
						break;
					}
				break;  


			// Numeric insertion control
			case MR_FPARS_PERCENT:
				switch (*pt_paragraph)
					{
					case	's':								// String insertion
						MRFont_data_ptr++;						// Point to argument pointer
						strcpy(MRFont_buff_ptr,*(MR_STRPTR *)*(MRFont_data_ptr));
						MRFont_buff_ptr = MRFont_buff_ptr + strlen(*(MR_STRPTR *)*(MRFont_data_ptr));
						pt_state = MR_FPARS_NORMAL;
						break;
		
					case	'c':								// Colour modification
						MRFont_data_ptr++;						// Point to argument pointer
						*MRFont_buff_ptr++ = MR_FBUFF_COLOUR_CODE | (MR_UBYTE)(MR_ULONG)(*MRFont_data_ptr)&0x0f;
						pt_state = MR_FPARS_NORMAL;
						break;						

					case	'C':								// Colour modification (indirect)
						MRFont_data_ptr++;						// Point to argument pointer
						*MRFont_buff_ptr++ = MR_FBUFF_COLOUR_CODE | (MR_UBYTE)*(MR_ULONG*)(*MRFont_data_ptr)&0x0f;
						pt_state = MR_FPARS_NORMAL;
						break;						
					
					case	'j':								// Set state for justify code
						pt_state = MR_FPARS_JUSTIFY;
						break;	

					case	'0':								// Set state for numbers to
						pt_state = MR_FPARS_ZERONUM;			// have leading zeros
						break;
  			
					case	'l':								// Set state for numbers to
						pt_state = MR_FPARS_LEFTNUM;			// be left justified
						break;

					// Unsigned numeric insert (with leading spaces)
					case	'w':								// Unsigned Word with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_ULONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;			
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'h':								// Unsigned Halfword with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_USHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'b':								// Unsigned Byte with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_UBYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;

					// Signed numeric insert (with leading spaces)
					case	'W':								// Signed Word with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_LONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;			
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'H':								// Signed Halfword with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_SHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'B':								// Signed Byte with leading spaces
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_BYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),' ');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;
		
					// User-exclusion area processing
					case	'<':								// Start exclusion area processing
						// Loop through until we find a '%>' or end of paragraph
						pt_last_char = 0;
						while (*pt_paragraph)
							{
							if ((pt_last_char == '%') && (*pt_paragraph == '>'))
								break;
							pt_last_char = *pt_paragraph;
							pt_paragraph++;
							}
						break;

	
					// Unknown percent code
					default:									// Unknown character? Leave it!	
						*MRFont_buff_ptr++ = *pt_paragraph;		// then copy to buffer
						pt_state = MR_FPARS_NORMAL;
						break;
					}
				break;


			// Justification command 
			case	MR_FPARS_JUSTIFY:
				switch (*pt_paragraph)
					{
					case	'l':								// Insert left justify code
						*MRFont_buff_ptr++ = (MR_UBYTE)(MR_FBUFF_JUSTIFY_CODE + MR_FJUST_CODE_LEFT);
						pt_state = MR_FPARS_NORMAL;
						break;
			
					case	'r':								// Insert right justify code
						*MRFont_buff_ptr++ = (MR_UBYTE)(MR_FBUFF_JUSTIFY_CODE + MR_FJUST_CODE_RIGHT);
						pt_state = MR_FPARS_NORMAL;
						break;
		
					case	'c':								// Insert centre justify code
						*MRFont_buff_ptr++ = (MR_UBYTE)(MR_FBUFF_JUSTIFY_CODE + MR_FJUST_CODE_CENTRE);
						pt_state = MR_FPARS_NORMAL;
						break;

					default:
						pt_state = MR_FPARS_NORMAL;
					}
				break;

			// Number insertion with leading zeros
			case	MR_FPARS_ZERONUM:				 
				switch (*pt_paragraph)
					{

					// Unsigned numeric insert (with leading zeros)
					case	'w':								// Unsigned Word with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_ULONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;				
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'h':								// Unsigned Halfword with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_USHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'b':								// Unsigned Byte with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_UBYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;

					// Signed numeric insert (with leading zeros)
					case	'W':								// Signed Word with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_LONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;			
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'H':								// Signed Halfword with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_SHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'B':								// Signed Byte with leading zeros
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_BYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'0');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;
		
					// Not recognised type
					default:									// Normal if unknown type.
						pt_state = MR_FPARS_NORMAL;		
					}
				break;

			case	MR_FPARS_LEFTNUM:				 
				switch (*pt_paragraph)
					{

					// Unsigned numeric insert (left justified)
					case	'w':								// Unsigned Word with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_ULONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;				
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'h':								// Unsigned Halfword with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_USHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'b':								// Unsigned Byte with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_UBYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;

					// Signed numeric insert (left justified)
					case	'W':								// Signed Word with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_LONG *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;			
						pt_state = MR_FPARS_NORMAL;
						break;

					case	'H':								// Signed Halfword with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_SHORT *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;					
						pt_state = MR_FPARS_NORMAL;
						break;
	
					case	'B':								// Signed Byte with left justification
						MRFont_data_ptr++;						// Point to argument pointer
						MRAddNumText((MR_LONG)(*(MR_BYTE *)(*MRFont_data_ptr)),(MR_ULONG)(*(MRFont_data_ptr+1)),'l');
						MRFont_data_ptr++;
						pt_state = MR_FPARS_NORMAL;
						break;
		
					// Not recognised type
					default:									// Normal if unknown type.
						pt_state = MR_FPARS_NORMAL;		
					}
				break;


			// Safety net in case state is set to something else
			default:
					pt_state = MR_FPARS_NORMAL;
					break;
			}

		pt_paragraph++;								// Point to next character
		}
}


/******************************************************************************
*%%%% MRAddNumText
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAddNumText(
*						MR_LONG		an_value,
*						MR_ULONG	an_length,
*						MR_UBYTE	an_char);
*
*	FUNCTION	Inserts a specified integer, which may have been case from a
*				word, halfword, or byte, into the text buffer.
*
*	INPUTS		an_value	-	Numeric value to insert into the buffer
*				an_length	-	Number of characters the converted 
*							 	integer should take up in the buffer.
*							 	Note this is inclusive of sign.
*				an_char		-	Character to left-pad the string with.
*
*	NOTES		If an_char is '0' then the sign (if negative) will be placed in
*				the leftmost character of the string. If the character is not
*				'0' then the sign will be positioned to the left of the leftmost
*				digit of the string.
*
*				If an_char is 'l' then the number will be left justified within 
*				the space allowed
*					
*				If the actual number fills all digits, then any sign will be 
*				positioned over the digit on the left. This bug will not be fixed
*				in my lifetime.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	07.08.96	Dean Ashton		Fixed bug with placing '0' instead of '0' for -ve's.
*	16.10.96	Dean Ashton		Added assertion to check for length > 0
*	05.03.97	Dean Ashton		Added support for left justified numbers
*
*%%%**************************************************************************/

MR_VOID	MRAddNumText(MR_LONG an_value, MR_ULONG an_length, MR_UBYTE an_char)
{		 			 
	MR_LONG		an_count;									// General loop counter
	MR_LONG		an_count2;									// General loop counter
	MR_BOOL		an_negative;								// Whether an_value < 0 	
	MR_UBYTE	an_temp_string[MR_FONT_NUM_EXPAND_LIMIT+1];	// Room for scratch string + terminator
	MR_UBYTE	an_work_char;
	MR_STRPTR	an_work_strptr;

	// Length of added number must be > 0
	MR_ASSERT(an_length > 0);

	// Don't allow a length that won't fit in the buffer
	an_length = MIN((MR_FONT_NUM_EXPAND_LIMIT),an_length);
	
	// If the value is negative, set a flag and turn it into a positive number
	if (an_value < 0)
		{
		an_value = -an_value;
		an_negative = TRUE;
		}
	else
		an_negative = FALSE;

	// Fill in the temporary string with our leading character and terminate it..
	if (an_char == '0')
		an_work_char = '0';
	else
		an_work_char = ' ';

	for (an_count = 0; an_count < MR_FONT_NUM_EXPAND_LIMIT; an_count++)
		{
		an_temp_string[an_count] = an_work_char;
		}
	an_temp_string[an_length] = 0x00;

	// Find position to start backwards processing of number into temp string
	an_count2 = an_length - 1;			// example: 4 digit number, last char is char[3]

	// Loop through the number until (a) we've finished the number, or (b) we're out of space
	do	{
		an_temp_string[an_count2] = an_value % 10 + '0';
		an_count2--;
		} while ((an_count2 >= 0) && ((an_value /=10) > 0));

	// Set the negative flag in the right place
	an_work_strptr = &an_temp_string[0];							// Default is entire string...

	if (an_negative)
		{
		if (an_count2 < 0)
			{
			an_temp_string[0] = '-';
			}
		else
			{
			an_temp_string[an_count2] = '-';
			if (an_char == 'l')
				an_work_strptr = &an_temp_string[an_count2];		// We copy from '-' sign
			}
		}
	else
		{
		if (an_char == 'l')
			an_work_strptr = &an_temp_string[an_count2 + 1];		// We copy from most significant digit
		}

	// Copy the string into our real text buffer and adjust text pointer 
	strcpy(MRFont_buff_ptr, an_work_strptr);
	MRFont_buff_ptr = MRFont_buff_ptr + strlen(an_work_strptr);
}


/******************************************************************************
*%%%% MRBuildLineInfo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRBuildLineInfo(
*						MR_TEXT_AREA*	bl_area_ptr);
*
*	FUNCTION	Splits the text expansion buffer into lines, with the line data
*				held in an array of MR_FONT_LINE_INFO structures.
*
*	INPUTS		bl_area_num	-	Pointer to text area to build lines for.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	17.04.97	Dean Ashton		Modified for in-line colour changing
*
*%%%**************************************************************************/

MR_VOID	MRBuildLineInfo(MR_TEXT_AREA*	bl_area_ptr)
{
	MR_STRPTR			bl_text_ptr;					// Pointer to current character
	MR_STRPTR			bl_line_start_ptr;				// Address of the start of last line
	MR_STRPTR			bl_wordend_ptr = NULL;			// Address of last char in last word
	
	MR_BOOL				bl_newline;						// Flag if newline to process

	MR_FONT_LINE_INFO	*bl_line;						// Pointer to current line entry

	MR_UBYTE			bl_justify, bl_new_justify;		// Space for control values

	MR_USHORT			bl_pixlen;						// Current pixel length of line
	MR_USHORT			bl_wordend_pixlen;				// Pixel length of line to end of last word
	MR_USHORT			bl_chrlen;						// Current character length of line
	MR_USHORT			bl_wordend_chrlen;				// Char length of line to end of last word

  
	MR_ASSERT(bl_area_ptr != NULL);

	bl_line				= MRFont_line_info;				// Set pointer to start of line array
	bl_text_ptr 		= MRFont_text_buff;				// Set pointer to start of text expansion buffer
	bl_newline			= FALSE;						// Clear 'newline' flag

	bl_justify 			= MR_FJUST_CODE_LEFT;			// Set default justify method
	bl_new_justify		= MR_FJUST_CODE_LEFT;

	bl_pixlen			= 0;							// Clear our miscellaneous
	bl_chrlen			= 0;							// length counters
	bl_wordend_pixlen	= 0;
	bl_wordend_chrlen	= 0;


	bl_line_start_ptr = bl_text_ptr;

	while (*bl_text_ptr)										// Process until no more characters
		{
		if (*bl_text_ptr == '\n')								// If it's a newline, flag it... 
			{	
			bl_newline = TRUE;
			}
		else
		if (*bl_text_ptr >= MR_FBUFF_FLAG_CODE)					// If it's a command, do it...
			{
			switch (*bl_text_ptr & 0xf0)
				{				
				case	MR_FBUFF_JUSTIFY_CODE:					
					bl_new_justify = *bl_text_ptr & 0x0f;
					break;

				case	MR_FBUFF_COLOUR_CODE:					// At this stage, colour codes are just another character (not factored into line calculation though)
					if (bl_chrlen == 0)							// We still need a hook to the start of the line
						bl_line_start_ptr = bl_text_ptr;

					bl_chrlen++;								
					break;

				default:
					break;

				}

			// If we're mid-line, and we've had a control code that isn't a colour change, then newline it..
			if ((bl_chrlen != 0) && ((*bl_text_ptr & 0xf0) != MR_FBUFF_COLOUR_CODE))
				bl_newline	= TRUE;							
			else
				{
				bl_justify	= bl_new_justify;					// in command code parsing above
				}

			}
		else													// If it's a character..
			{												
			bl_pixlen = bl_pixlen + 
						bl_area_ptr->ta_font_info->fi_font_char[(*bl_text_ptr)-' '].fchar_w;
		

			if (bl_pixlen > bl_area_ptr->ta_box_w)				// If we're over a line
				{
				bl_pixlen	= bl_wordend_pixlen;				// Reset pix length of string
				bl_chrlen	= bl_wordend_chrlen;				// Reset chr length of string
				bl_text_ptr	= bl_wordend_ptr;					// Move to end of prev word
		
				// Error if we've got no valid previous line to go back to

				MR_ASSERT(bl_text_ptr);

				do {											// Skip end of spaces
					bl_text_ptr++;
					} while (*bl_text_ptr == ' ');
		
				bl_text_ptr--;							 		// Adjust for position

				bl_newline = TRUE;			  					// Flag we need to do a newline
				
				}
			else
				{
				if (bl_chrlen == 0)								// Set line pointer if needed
					bl_line_start_ptr = bl_text_ptr;

				bl_chrlen++;						  	 		// Increase character line width

				if ((*bl_text_ptr != ' ') &&					// If we're at the end of a word
					(*(bl_text_ptr+1) == ' '))	
					{
					bl_wordend_ptr		= bl_text_ptr;
					bl_wordend_pixlen	= bl_pixlen;
					bl_wordend_chrlen	= bl_chrlen; 
					}
				}
			}

		if (bl_newline)											// If there's a newline.. 
			{
			bl_line->fline_address		= bl_line_start_ptr;
			bl_line->fline_chrlen 		= bl_chrlen;
			bl_line->fline_pixlen	 	= bl_pixlen;
			bl_line->fline_justify_id	= bl_justify;

			bl_line++;

			bl_justify		= bl_new_justify;					// in command code parsing above

			bl_wordend_ptr	= NULL;
			bl_chrlen		= bl_wordend_chrlen = 0;
			bl_pixlen		= bl_wordend_pixlen = 0;
			bl_newline		= FALSE;

			}
		bl_text_ptr++;											// Point to next character
		}
	
		if (bl_chrlen > 0)										// If we've a line to write
			{
			bl_line->fline_address		= bl_line_start_ptr;
			bl_line->fline_chrlen		= bl_chrlen;
			bl_line->fline_pixlen		= bl_pixlen;
			bl_line->fline_justify_id	= bl_justify;
			bl_line++;				
			}

		bl_line->fline_address = NULL;							// Null-terminate line list
}


/******************************************************************************
*%%%% MRBuildTextPrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRBuildTextPrims(
*						MR_TEXT_AREA*	bt_area_ptr);
*
*	FUNCTION	Builds the raw primitives needed to render the text for a 
*				defined area. 
*
*	INPUTS		bt_area_ptr	-	Pointer to the area to build primitives for.
*
*	NOTES		This only builds primitives for the current work buffer. The
*				other set is automatically regenerated on display.
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*	30.10.96	Dean Ashton		Added horizontal offset for when fonts aren't at
*								0 within a texture page.
*	17.04.97	Dean Ashton		Modified for in-line colour changing
*
*%%%**************************************************************************/

MR_VOID	MRBuildTextPrims(MR_TEXT_AREA* bt_area_ptr)
{
	MR_FONT_LINE_INFO	*bt_line_ptr;					// Pointer to line information structures
	MR_FONT_CHAR_INFO	*bt_font_char;					// Pointer to start of font character information
	MR_FONT_CHAR_INFO	*bt_char_ptr;					// Pointer to required character information

	MR_STRPTR		 	bt_text_ptr;					// Pointer to text for current line
	MR_SHORT			bt_align_edge;
	MR_SHORT			bt_counter;						// Count for characters in the line
	MR_SHORT			bt_line_x;						// Pixel X position for character
	MR_SHORT			bt_line_y;						// Pixel Y position for character
	MR_UBYTE			bt_font_im_u;					// U coord of top of font image in VRAM
	MR_UBYTE			bt_font_im_v;					// V coord of top of font image in VRAM

	POLY_FT4		  	*bt_polys = NULL;
	SPRT				*bt_sprts = NULL;

	MR_SHORT			bt_colour;
	MR_USHORT			bt_font_height;					// Height of the font in this area
	
	MR_ASSERT(bt_area_ptr != NULL);

	// Set our initial values and pointers
	bt_font_height	= bt_area_ptr->ta_font_info->fi_font_height;
	bt_font_char	= bt_area_ptr->ta_font_info->fi_font_char;
	bt_font_im_u	= bt_area_ptr->ta_font_info->fi_font_sprite->te_u0;
	bt_font_im_v	= bt_area_ptr->ta_font_info->fi_font_sprite->te_v0;
	bt_colour		= bt_area_ptr->ta_build_colour;

	if (!(bt_area_ptr->ta_flags & MR_FAREA_USE_POLYS))
		bt_sprts	= (SPRT*)bt_area_ptr->ta_prims[MRFrame_index];
	else
		bt_polys	= (POLY_FT4*)bt_area_ptr->ta_prims[MRFrame_index];

	bt_line_y		= bt_area_ptr->ta_box_y;		
	bt_line_ptr		= MRFont_line_info;

	bt_align_edge	= 0;	

	// Clear our count of rendered characters
	bt_area_ptr->ta_rend_chars = 0;

	// Process each TXT_LINE structure
	while (bt_line_ptr->fline_address)
		{
		bt_text_ptr = bt_line_ptr->fline_address;
		bt_counter	= bt_line_ptr->fline_chrlen;

		// NOTE:
		// The prims are initially created assuming the box is at (0,0)
		// and a system whereby double buffered box x/y coordinates are 
		// used to calculate deltas. These deltas will be applied to the
		// primitives when the box x/y has changed for the current frame.
 		// A bit of a 'mare really...

		// Calculate starting X position based on justification method
		if (bt_line_ptr->fline_justify_id == MR_FJUST_CODE_RIGHT)
			bt_line_x = (bt_area_ptr->ta_box_w - bt_line_ptr->fline_pixlen);
		else
		if (bt_line_ptr->fline_justify_id == MR_FJUST_CODE_CENTRE)
			bt_line_x = ((bt_area_ptr->ta_box_w - bt_line_ptr->fline_pixlen) / 2);
		else
			bt_line_x = 0;

		bt_line_x = bt_line_x + bt_area_ptr->ta_box_x;

		// Loop through all characters on the line, adding non-space characters to our
		// list of primtives, adjusting rendered character counts...
		while (bt_counter)
			{
			bt_char_ptr = &bt_font_char[(*bt_text_ptr)-' '];

			// If the character is a Colour control code
			if ((*bt_text_ptr & 0xf0) == MR_FBUFF_COLOUR_CODE)
				{
				bt_colour = *bt_text_ptr & 0x0f;
				}
			else
			if (*bt_text_ptr >= ' ')
				{
				if (*bt_text_ptr != ' ')
					{
					if (!(bt_area_ptr->ta_flags & MR_FAREA_USE_POLYS))
						{
						// Write to SPRT
						bt_sprts->x0	= bt_line_x;
						bt_sprts->y0	= bt_line_y;
						bt_sprts->w		= bt_char_ptr->fchar_w;
						bt_sprts->h		= bt_font_height;
						bt_sprts->u0	= bt_char_ptr->fchar_x + bt_font_im_u;
						bt_sprts->v0	= bt_char_ptr->fchar_y + bt_font_im_v;
	
						bt_sprts->r0 	= MRFont_colour_table_ptr[bt_colour].r;
						bt_sprts->g0 	= MRFont_colour_table_ptr[bt_colour].g;
						bt_sprts->b0 	= MRFont_colour_table_ptr[bt_colour].b;
	
						bt_sprts++;
						}
					else
						{
						// Write to POLY
						setXYWH(bt_polys,bt_line_x, bt_line_y,
								  bt_char_ptr->fchar_w, bt_font_height);
	
						setUVWH(bt_polys,
								  bt_char_ptr->fchar_x + bt_font_im_u, bt_char_ptr->fchar_y + bt_font_im_v,
								  bt_char_ptr->fchar_w, bt_font_height);
					
						bt_polys->r0 	= MRFont_colour_table_ptr[bt_colour].r;
						bt_polys->g0 	= MRFont_colour_table_ptr[bt_colour].g;
						bt_polys->b0 	= MRFont_colour_table_ptr[bt_colour].b;
						bt_polys++;
						}
					bt_area_ptr->ta_rend_chars++;
					}

				// Calculate X position of next character
				bt_line_x += bt_char_ptr->fchar_w;
				}

			bt_text_ptr++;							// Point to next character on line
			bt_counter--;							// Decrement characters left
			}

		// Find vertical posn. of next line
		bt_line_y += (bt_font_height + bt_area_ptr->ta_height_extra);
		bt_line_ptr++;								
		}
}


/******************************************************************************
*%%%% MRRenderTextArea
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRRenderTextArea(
*						MR_TEXT_AREA*	rt_area_ptr);
*
*	FUNCTION	Physically adds the text primitives for the specified text area
*				to the viewport ordering table. As this uses MRVp_work_<xxx>
*				variables, which only have a valid context within the
*				MRRenderViewport() function, this function can only be called
*				from there, and as such is not for public use.
*
*	INPUTS		rt_area_ptr	-	Pointer to the text area to render
*
*	NOTES		The things in the ordering table are drawn backwards, ie the 
*				first thing added to an OT position here is, infact, the last
*				thing rendered for that OT position.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRRenderTextArea(MR_TEXT_AREA *rt_area_ptr)
{
	POLY_FT4*	rt_poly_prims;
	POLY_FT4*	rt_src_polys;
	POLY_FT4*	rt_dest_polys;

	SPRT*		rt_sprt_prims;
	SPRT*		rt_src_sprts;
	SPRT*		rt_dest_sprts;

	MR_LONG	 	rt_rend_count;

	MR_SHORT	rt_box_delta_x;
	MR_SHORT	rt_box_delta_y;
	MR_ULONG*	rt_ot_slot;

	MR_ASSERT(rt_area_ptr != NULL);	

	rt_ot_slot = MRVp_work_ot + rt_area_ptr->ta_otz;

	MR_ASSERT(rt_area_ptr->ta_otz < MRVp_ot_size);	// Area must be within OT size
	
	// If the polys aren't valid for this frame, then copy from the valid set and adjust...
	//	Oh yeah... check to see this area has a valid set of prims allocated first!!!
	if ((rt_area_ptr->ta_old_polys[MRFrame_index]) && (rt_area_ptr->ta_prims[0])) 
		{
		rt_area_ptr->ta_old_polys[MRFrame_index] = 0;
		
		rt_rend_count	= rt_area_ptr->ta_rend_chars;		// check type!

		if (!(rt_area_ptr->ta_flags & MR_FAREA_USE_POLYS))
			{
			rt_src_sprts	= (SPRT*)rt_area_ptr->ta_prims[MRFrame_index^0x01];
			rt_dest_sprts	= (SPRT*)rt_area_ptr->ta_prims[MRFrame_index];

			while (rt_rend_count)
				{
				MR_COPY32(rt_dest_sprts->r0, rt_src_sprts->r0);
				MR_COPY32(rt_dest_sprts->x0, rt_src_sprts->x0);
				MR_COPY32(rt_dest_sprts->u0, rt_src_sprts->u0);
				MR_COPY32(rt_dest_sprts->w,  rt_src_sprts->w);
				rt_src_sprts++;
				rt_dest_sprts++;
				rt_rend_count--;
				}
			}
		else
			{
			rt_src_polys	= (POLY_FT4*)rt_area_ptr->ta_prims[MRFrame_index^0x01];
			rt_dest_polys	= (POLY_FT4*)rt_area_ptr->ta_prims[MRFrame_index];

			while (rt_rend_count)
				{
				MR_COPY32(rt_dest_polys->r0, rt_src_polys->r0);
				MR_COPY32(rt_dest_polys->x0, rt_src_polys->x0);
				MR_COPY32(rt_dest_polys->u0, rt_src_polys->u0);
				MR_COPY32(rt_dest_polys->x1, rt_src_polys->x1);
				MR_COPY32(rt_dest_polys->u1, rt_src_polys->u1);
				MR_COPY32(rt_dest_polys->x2, rt_src_polys->x2);
				MR_COPY32(rt_dest_polys->u2, rt_src_polys->u2);
				MR_COPY32(rt_dest_polys->x3, rt_src_polys->x3);
				MR_COPY32(rt_dest_polys->u3, rt_src_polys->u3);
				rt_src_polys++;
				rt_dest_polys++;
				rt_rend_count--;
				}
			}
		}

	// Only process this areas primitives if they're going to be displayed.
	if (rt_area_ptr->ta_display)
		{
		// Set pointers and counters for this areas primitives
																					
		rt_rend_count	= rt_area_ptr->ta_rend_chars;
		rt_box_delta_x = rt_area_ptr->ta_box_x + rt_area_ptr->ta_xofs - rt_area_ptr->ta_prims[MRFrame_index]->x0;
		rt_box_delta_y = rt_area_ptr->ta_box_y + rt_area_ptr->ta_yofs - rt_area_ptr->ta_prims[MRFrame_index]->y0;

		if (rt_area_ptr->ta_flags & MR_FAREA_USE_POLYS)
			{
			// Add all POLY_FT4 primitives required for this area

			rt_poly_prims = (POLY_FT4*)rt_area_ptr->ta_prims[MRFrame_index];

			while (rt_rend_count)
				{
				if (rt_box_delta_x)
					{
					rt_poly_prims->x0 += rt_box_delta_x;
					rt_poly_prims->x1 += rt_box_delta_x;
					rt_poly_prims->x2 += rt_box_delta_x;
					rt_poly_prims->x3 += rt_box_delta_x;
					}
				if (rt_box_delta_y)
					{
					rt_poly_prims->y0 += rt_box_delta_y;
					rt_poly_prims->y1 += rt_box_delta_y;
					rt_poly_prims->y2 += rt_box_delta_y;
					rt_poly_prims->y3 += rt_box_delta_y;
					}
				addPrim(rt_ot_slot, rt_poly_prims);
				rt_poly_prims++;
				rt_rend_count--;
				}															 
			}	
		else
			{
			// Add all SPRT primitives required for this area
			rt_sprt_prims = (SPRT*)rt_area_ptr->ta_prims[MRFrame_index];

			while (rt_rend_count)
				{
				if (rt_box_delta_x)
					rt_sprt_prims->x0 += rt_box_delta_x;
	
				if (rt_box_delta_y)
					rt_sprt_prims->y0 += rt_box_delta_y;
	
				addPrim(rt_ot_slot, rt_sprt_prims);
				rt_sprt_prims++;
				rt_rend_count--;
				}

			addPrim(rt_ot_slot, &rt_area_ptr->ta_change_tpage[MRFrame_index]);
			}
		}
}


/******************************************************************************
*%%%% MRSetTextTranslucency
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetTextTranslucency(
*						MR_TEXT_AREA*	area,
*						MR_USHORT		index,
*						MR_USHORT		value)
*
*	FUNCTION	Do a SetSemiTrans on all polys used by a text area
*
*	INPUTS		area	-	ptr to text area
*				index	-	poly buffer frame index
*				value	-	0 or 1
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.12.96	Tim Closs		Created
*	14.02.97	Dean Ashton		Changed function name to MRSetTextTranslucency 
*
*%%%**************************************************************************/

MR_VOID	MRSetTextTranslucency(	MR_TEXT_AREA*	area,
								MR_USHORT		index,
								MR_USHORT		value)
{
	MR_USHORT	i;
	SPRT*		sprt;
	POLY_FT4*	poly_ft4;
	
	
	MR_ASSERT(area);	

	if (!(area->ta_flags & MR_FAREA_USE_POLYS))
		{
		sprt = (SPRT*)area->ta_prims[index];
		for (i = 0; i < area->ta_max_chars; i++)
			{
			// Using SPRTs
			setSemiTrans(sprt, value);
			sprt++;
			}
		}
	else
		{
		poly_ft4 = (POLY_FT4*)area->ta_prims[index];
		for (i = 0; i < area->ta_max_chars; i++)
			{
			// Using POLY_FT4s
			setSemiTrans(poly_ft4, value);
			poly_ft4++;
			}
		}
}


/******************************************************************************
*%%%% MRSetTextColour
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetTextColour(
*						MR_TEXT_AREA*	area,
*						MR_USHORT		index,
*						MR_ULONG		value)
*
*	FUNCTION	Set the rgb of all polys used by a text area
*
*	INPUTS		area	-	ptr to text area
*				index	-	poly buffer frame index
*				value	-	BbGgRr
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRSetTextColour(MR_TEXT_AREA*	area,
						MR_USHORT		index,
						MR_ULONG		value)
{
	MR_USHORT	i;
	SPRT*		sprt;
	POLY_FT4*	poly_ft4;
		

	MR_ASSERT(area);	

	if (!(area->ta_flags & MR_FAREA_USE_POLYS))
		{
		// Set upper 8 bit code
		sprt	= (SPRT*)area->ta_prims[index];
		value = (value & 0xffffff) + (sprt->code << 24);
		for (i = 0; i < area->ta_max_chars; i++)
			{
				{
				// Using SPRTs
				MR_SET32(sprt->r0, value);
				sprt++;
				}
			}
		}
	else
		{
		// Set upper 8 bit code
		poly_ft4 = (POLY_FT4*)area->ta_prims[index];
		value = (value & 0xffffff) + (poly_ft4->code << 24);
		for (i = 0; i < area->ta_max_chars; i++)
			{
				{
				// Using POLY_FT4s
				MR_SET32(poly_ft4->r0, value);
				poly_ft4++;
				}
			}
		}
}
