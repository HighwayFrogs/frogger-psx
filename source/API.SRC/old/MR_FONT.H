/******************************************************************************
*%%%% mr_font.h
*------------------------------------------------------------------------------
*
*	New header file for mr_font.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	11.12.96	Tim Closs		Added MRSetTextTransparency and MRSetTextColour
*	14.02.97	Dean Ashton		Transparency -> Translucency... 
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_font_line_info		MR_FONT_LINE_INFO;
typedef	struct	__mr_font_char_info		MR_FONT_CHAR_INFO;
typedef	struct	__mr_font_info			MR_FONT_INFO;	
typedef	struct	__mr_text_area			MR_TEXT_AREA;

#else
#ifndef	__MR_FONT_H
#define	__MR_FONT_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_FONT_MAX_LINE_LIMIT			(25)								// Maximum number of lines in one area
#define	MR_FONT_MAX_BUFF_LIMIT			(1024)								// Expansion buffer size
#define	MR_FONT_NUM_EXPAND_LIMIT		(12)								// String length for number->string expansion
#define	MR_FONT_DEFAULT_OT_POS			(2)									// Default OT position for text

#define	MR_FAREA_USE_POLYS				(1<<0)								// Use POLY_FT4's, not SPRT's

#define	MR_FINFO_TRANSLUCENT	  		(1<<0)								// The font is to be translucent

#define	MR_FPARS_NORMAL					(0)									// State is 'Normal Text Parse'
#define	MR_FPARS_PERCENT		  		(1)									// State is 'Percent Command Parse'
#define	MR_FPARS_ZERONUM		  		(2)									// State is 'Zero-led Numeric Parse'
#define	MR_FPARS_JUSTIFY		  		(3)									// State is 'Justification Method Parse'
#define	MR_FPARS_LEFTNUM		  		(4)									// State is 'Numbers aligned to left of number space'


#define	MR_FBUFF_FLAG_CODE				(0xe0)								// Special command start
#define	MR_FBUFF_JUSTIFY_CODE			(MR_FBUFF_FLAG_CODE + 0x00)			// Justify code ID
#define	MR_FBUFF_COLOUR_CODE	  		(MR_FBUFF_FLAG_CODE + 0x10)			// Colour code ID			


#define	MR_FJUST_CODE_LEFT				(0)
#define	MR_FJUST_CODE_RIGHT				(1)
#define	MR_FJUST_CODE_CENTRE	  		(2)

enum		{											  					// Index into different font base colours
			MR_FONT_COLOUR_WHITE,											// No more than 16 entries in this list!!
			MR_FONT_COLOUR_BLACK,
			MR_FONT_COLOUR_RED,
			MR_FONT_COLOUR_GREEN,
			MR_FONT_COLOUR_BLUE,
			MR_FONT_COLOUR_CYAN,
			MR_FONT_COLOUR_MAGENTA,
			MR_FONT_COLOUR_YELLOW,
			MR_FONT_COLOUR_BROWN,
			MR_FONT_COLOUR_GREY,
			MR_FONT_COLOUR_DARK_GREY,
			MR_FONT_COLOUR_DARK_BLUE,
			MR_FONT_COLOUR_NEAR_BLACK,
			MR_FONT_COLOUR_CADMIUM,
			MR_FONT_COLOUR_ORANGE,

			MR_FONT_MAX_COLOUR_ID = MR_FONT_COLOUR_ORANGE,					// Set max colour ID
			};


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_font_line_info
		{
		MR_STRPTR	fline_address;	 						// Pointer to start of line in paragraph buffer
		MR_USHORT	fline_chrlen;							// Length of line in characters
		MR_USHORT	fline_pixlen;							// Length of line in pixels
		MR_UBYTE	fline_justify_id;						// Justification method for this line
		MR_UBYTE	fline_pad;								// Pad

		};		// MR_FONT_LINE_INFO


struct	__mr_font_char_info
		{
		MR_UBYTE	fchar_x;								// Horizontal coordinate within texture page
		MR_UBYTE	fchar_y;								// Vertical coordinate within texture page
		MR_UBYTE	fchar_w;								// Width of character in pixels
		MR_UBYTE	fchar_pad;								// Pad to make structure 1 32-bit word long

		};		// MR_FONT_CHAR_INFO


struct	__mr_font_info
		{												  
		MR_TEXTURE*			fi_font_sprite;					// Pointer to the MR_MR_TEXTURE for this font			
		MR_FONT_CHAR_INFO*	fi_font_char;					// Pointer to an array of MR_FONT_CHAR_INFO structures
		MR_UBYTE		 	fi_font_height;					// Height of the font (in pixels)
		MR_UBYTE		 	fi_font_abr;					// Translucency/ABR value (0/1/2/3)
		MR_USHORT		 	fi_font_flags;					// Flags

		};		// MR_FONT_INFO


struct	__mr_text_area
		{
		struct	__mr_text_area*	ta_next_node;				// Pointer to next in linked list
		struct	__mr_text_area*	ta_prev_node;				// Pointer to previous in linked list

		MR_FONT_INFO*			ta_font_info;				// Pointer to this areas font information
		MR_VIEWPORT*			ta_viewport;				// Viewport that 'owns' this text area
		MR_BOOL					ta_display;					// Boolean to quickly display/hide text area

		MR_USHORT				ta_flags;					// Miscellaneous flags for text area
		MR_USHORT				ta_otz;						// Ordering table position for this text area

		MR_SHORT		 		ta_box_x;					// Text area position/dimensions
		MR_SHORT		 		ta_box_y;
		MR_SHORT		 		ta_box_w;
		MR_SHORT		 		ta_box_h;

		MR_SHORT		 		ta_xofs;					// Offsets from top left of text box to the
		MR_SHORT		 		ta_yofs;					// top left of first polygon to render

		MR_SHORT		 		ta_max_chars;				// Maximum characters allowable in this area
		MR_SHORT				ta_rend_chars;				// Number of rendered characters in this area

		SPRT*					ta_prims[2];				// Pointers to primitives (can also be POLY_FT4)
		POLY_FT3		 		ta_change_tpage[2];			// Used to change TPage when using SPRT prims
		MR_USHORT				ta_tpage;					// TPage ID to use when rendering	
		MR_USHORT				ta_clut;					// CLUT ID to use when rendering			

		MR_UBYTE		 		ta_old_polys[2];			// Set to 1 if the polys aren't up-to-date
		MR_SHORT		 		ta_height_extra;			// Modifier for font height (for line advancing)
 
		MR_SHORT		 		ta_kill_timer;				// Kill timer for text area destruction
		MR_SHORT		 		ta_build_colour;			// Pad to make structure 32-bit multiple

		};		// MR_TEXT_AREA


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_FONT_INFO*	MRDefault_font_info;
extern	MR_CVEC			MRFont_default_colours[];


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			MRSetDefaultFont(MR_FONT_INFO*);
extern	MR_VOID			MRSetFontColourTable(MR_CVEC*);
extern	MR_TEXT_AREA*	MRAllocateTextArea(MR_ULONG,MR_FONT_INFO*,MR_VIEWPORT*,MR_SHORT,MR_SHORT,MR_SHORT,MR_SHORT,MR_SHORT);
extern	MR_VOID			MRFreeTextArea(MR_TEXT_AREA*);
extern	MR_VOID			MRFreeTextAreaPhysically(MR_TEXT_AREA*);
extern	MR_VOID			MRBuildText(MR_TEXT_AREA*, MR_STRPTR*, MR_USHORT);
extern	MR_VOID			MRParseText(MR_STRPTR);
extern	MR_VOID			MRAddNumText(MR_LONG, MR_ULONG, MR_UBYTE);
extern	MR_VOID			MRBuildLineInfo(MR_TEXT_AREA*);
extern	MR_VOID			MRBuildTextPrims(MR_TEXT_AREA*);
extern	MR_VOID			MRRenderTextArea(MR_TEXT_AREA*);

extern	MR_VOID			MRSetTextTranslucency(MR_TEXT_AREA*, MR_USHORT,	MR_USHORT);
extern	MR_VOID			MRSetTextColour(MR_TEXT_AREA*, MR_USHORT,	MR_ULONG);

#endif	//__MR_FONT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

