/******************************************************************************
*%%%% mr_sprt.h
*------------------------------------------------------------------------------
*
*	New header file for mr_sprt.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	31.01.97	Dean Ashton		Removed si_light_matrix/si_light_matrix_ptr
*								from MR_3DSPRITE_INST
*	14.02.97	Dean Ashton		Updated MR_SPIB_<xxx> bit definitions, and
*								changed TRANSPARENT to TRANSLUCENT...
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_sp_core			MR_SP_CORE;
typedef	struct	__mr_2dsprite			MR_2DSPRITE;
typedef	struct	__mr_3dsprite			MR_3DSPRITE;
typedef	struct	__mr_3dsprite_inst		MR_3DSPRITE_INST;

#else
#ifndef	__MR_SPRT_H
#define	__MR_SPRT_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Bits/masks/macros required for Vorg files
#define	MR_SPIB_TRANSLUCENT				(0)
#define	MR_SPIB_ROTATED					(1)
#define	MR_SPIB_HIT_X					(2)
#define	MR_SPIB_HIT_Y					(3)
#define	MR_SPIB_REFERENCED_BY_NAME		(4)
#define	MR_SPIB_BLACK_TRANSPARENT		(5)
#define	MR_SPIB_UNUSED_6				(6)
#define	MR_SPIB_UNUSED_7				(7)
#define	MR_SPIB_USER_FLAG_0				(8)
#define	MR_SPIB_USER_FLAG_1				(9)
#define	MR_SPIB_USER_FLAG_2				(10)
#define	MR_SPIB_USER_FLAG_3				(11)
#define	MR_SPIB_USER_FLAG_4				(12)
#define	MR_SPIB_USER_FLAG_5				(13)
#define	MR_SPIB_USER_FLAG_6				(14)
#define	MR_SPIB_SPRITE_ID				(15)

#define	MR_SPIF_TRANSLUCENT				(1<<MR_SPIB_TRANSLUCENT)
#define	MR_SPIF_ROTATED					(1<<MR_SPIB_ROTATED)
#define	MR_SPIF_HIT_X					(1<<MR_SPIB_HIT_X)
#define	MR_SPIF_HIT_Y					(1<<MR_SPIB_HIT_Y)
#define	MR_SPIF_REFERENCED_BY_NAME		(1<<MR_SPIB_REFERENCED_BY_NAME)
#define	MR_SPIF_BLACK_TRANSPARENT		(1<<MR_SPIB_BLACK_TRANSPARENT)
#define	MR_SPIF_UNUSED_6				(1<<MR_SPIB_UNUSED_6)
#define	MR_SPIF_UNUSED_7				(1<<MR_SPIB_UNUSED_7)
#define	MR_SPIF_USER_FLAG_0				(1<<MR_SPIB_USER_FLAG_0)
#define	MR_SPIF_USER_FLAG_1				(1<<MR_SPIB_USER_FLAG_1)
#define	MR_SPIF_USER_FLAG_2				(1<<MR_SPIB_USER_FLAG_2)
#define	MR_SPIF_USER_FLAG_3				(1<<MR_SPIB_USER_FLAG_3)
#define	MR_SPIF_USER_FLAG_4				(1<<MR_SPIB_USER_FLAG_4)
#define	MR_SPIF_USER_FLAG_5				(1<<MR_SPIB_USER_FLAG_5)
#define	MR_SPIF_USER_FLAG_6				(1<<MR_SPIB_USER_FLAG_6)
#define	MR_SPIF_SPRITE_ID				(1<<MR_SPIB_SPRITE_ID)

#define	defTPage(tpage,depth,abr)		((((depth)>>3)<<7)+(tpage)+((abr)<<5))
#define	getABR(tpage_id)				(((tpage_id)&0x60)>>5)
#define	setABR(tpage_id,abr)			(((tpage_id)&(0x19f))|((abr)<<5) )

// Miscellaneous sprite defines

#define	MR_SP2D_DEFAULT_SCALE	(1<<16)		// Default scale for 2D sprites (ie no scaling)
#define	MR_SP2D_MIN_OT_POS		(1)			// Minimum OT position for a 2D sprite

#define	MR_SP3D_DEFAULT_SCALE	(4<<16)		// Default scale for sprite width->world coordinates
#define	MR_SP3D_MIN_OT_POS		(4)			// Minimum OT position for a 3D sprite (not infront of 2D sprites)

// sc_flags/MR_SP_CORE bits

#define	MR_SPF_NO_DISPLAY			(1<<0)		// Sprite should not be displayed
#define	MR_SPF_KILL_FROM_OWNER		(1<<1)		// Owning object routines will kill this sprite
#define	MR_SPF_FORCE_FRONT			(1<<2)		// Sprite should be placed at front of ordering table
#define	MR_SPF_FORCE_BACK			(1<<3)		// Sprite should be placed at back of ordering table
#define	MR_SPF_IS_IMAGE				(1<<4)		// Sprite is actually a single image, not a sprite anim...
#define	MR_SPF_SPRITE_IS_2D			(1<<5)		// Sprite is 2D variety. If not set, then it's 3D..
#define	MR_SPF_NO_3D_ROTATION		(1<<6)		// Sprite is Z positioned only (always faces camera)
#define	MR_SPF_USE_3D_NCLIP			(1<<7)		// Sprite should be normal clipped
#define	MR_SPF_ONLY_Z_ROTATE		(1<<8)		// Face the camera, rotate around Z - NOT IMPLEMENTED-
#define	MR_SPF_IN_CRITICAL			(1<<9)		// We are in an important animation.
#define	MR_SPF_2D_H_DOUBLE			(1<<10)		// Double horizontally (for 2D sprites only!)
#define	MR_SPF_NO_3D_SCALING		(1<<11)		// No 3D scaling. Offsets are absolute from center of sprite.
#define	MR_SPF_IN_XZ_PLANE			(1<<12)		// 3D sprite lies in local XZ plane (default is XY plane)
#define	MR_SPF_IN_YZ_PLANE			(1<<13)		// 3D sprite lies in local YZ plane (default is XY plane)
#define	MR_SPF_HORIZONTAL_FLIP		(1<<14)		// flip image u coords
#define	MR_SPF_VERTICAL_FLIP		(1<<15)		// flip image v coords

// Sprite Animation lists

#define	MR_SPALIST_CONTINUE			(TRUE)
#define	MR_SPALIST_STOP				(FALSE)

#define	MR_SPALIST_FORCE_NEXT		(1)
#define	MR_SPALIST_DEFAULT_SPEED	(1)
#define	MR_SPALIST_BIG_SPEED		(0x7fff)

// Sprite Anim Command ID's cannot be greater than 32768. Why? Well, to tell whether we're a
// sprite or an animation list, we read the first short. This is either the 'te_flags' word
// from a sprite, or the low-order word from an animation command ID. Lost? Ask Deany..

enum		{
			MR_SPRT_NOP,								// Dummy instruction
			MR_SPRT_SETIMAGE,							// Sets the current image
			MR_SPRT_SETBLANK,							// Clears current frame (stop display)
			MR_SPRT_SETSPEED,							// Change speed of animation
			MR_SPRT_SETSCALE,							// Change scaling factor (16:16)
			MR_SPRT_SETCOLOUR,							// Set base colour for sprite
			MR_SPRT_SETOTOFFSET,						// Set OT Z offset
			MR_SPRT_SETMASTERPOS,						// Set XY offset
												
			MR_SPRT_SETFLAGS,							// Set flag bits		
			MR_SPRT_CLRFLAGS,							// Clear flag bits
			
			MR_SPRT_ENTERCRITICAL,						// Start 'critical section'
			MR_SPRT_EXITCRITICAL,						// Stop 'critical section' 
	
			MR_SPRT_SETCOUNT,							// Set counter for loop (0 is infinite loop)
			MR_SPRT_LOOPBACK,							// Loop back (used with MR_SPRT_LOOPCOUNT)
											
			MR_SPRT_RESTART,							// Restart animation list
			MR_SPRT_HALT,								// Loop forever
			MR_SPRT_KILL,								// Kill the animation/sprite
			};

typedef	MR_BOOL(*MR_SPRT_CODE)(MR_SP_CORE *);	// Data type for function table (deals with MR_SP_CORE)


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_sp_core
		{
		struct __mr_sp_core*	sc_next_node;			// Pointer to next 2D sprite linked into viewport list
		struct __mr_sp_core*	sc_prev_node;			// Pointer to previous 2D sprite linked into viewport list

		MR_TEXTURE*				sc_image;				// Pointer to image information structure

		MR_USHORT				sc_flags;				// Flags for this sprite
		MR_SHORT				sc_ot_offset;			// OT position/adjustment value
		MR_CVEC					sc_base_colour;			// Base colour (cd entry set to POLY_FT4 on setup)
		
		MR_FRAC16				sc_scale;				// Scale for w/h (2D) or coordinates (3D) (16:16)

		MR_LONG*				sc_alist_addr;			// Pointer to current sprite animlist
		MR_SHORT				sc_alist_pc;			// PC within current sprite animlist
		MR_SHORT				sc_alist_count;			// Counter used for sprite animlist timings
		MR_SHORT				sc_alist_speed;			// Speed animlist should update at
		MR_SHORT				sc_alist_loop_pc;		// PC within sprite animlist for loops to return to		
		MR_SHORT				sc_alist_loop_count;	// Counter for loop lists

		MR_SHORT				sc_pad;					// Pad to make structure aligned to 32-bits
	
		};		// MR_SP_CORE


struct	__mr_2dsprite
		{
		MR_SP_CORE				sp_core;	 			// Data shared between 2D and 3D sprites

		POLY_FT4				sp_polygon[2];			// Polygon data for a 2d (non-instanced) sprite

		MR_TEXTURE*				sp_image_buf[2];		// Current image pointers for both buffers

		MR_XY*					sp_master_pos;			// If null, sp_xpos/ypos are real coords, else offsets
		MR_XY					sp_pos;					// X/Y position (or offset)
				  
		MR_XY					sp_offset;				// Offset position (for scaling/rotation)
		MR_SHORT				sp_angle;				// Angle of rotation for sprite

		MR_SHORT				sp_kill_timer;			// Timer for sprite destruction

		};		// MR_2DSPRITE


struct	__mr_3dsprite
		{
		MR_SP_CORE				sp_core;				// Data shared between 2D and 3D sprites
	
		MR_OBJECT*				sp_object;				// Pointer back to the object (for killing 3d sprites)
		MR_FRAME*				sp_frame;				// Pointer to the coordinate frame for this sprite
		MR_SVEC					sp_ofs_image;			// Offset from image origin (X/Y/Z)

		};		// MR_3DSPRITE


struct	__mr_3dsprite_inst
		{
		struct __mr_3dsprite_inst*	si_next_node;		// Pointer to next instance in list
		struct __mr_3dsprite_inst*	si_prev_node;		// Pointer to previous instance in list
		
		MR_OBJECT*					si_object;			// Pointer to the object we're instancing

		POLY_FT4					si_polygon[2];		// Polygon data

		MR_CVEC						si_colour_scale;	// used to scale colour matrix and applicable ambient colour (optional)
		MR_CVEC						si_custom_ambient;	// custom ambient colour (optional)

		MR_TEXTURE*					si_image_buf[2];	// Current image pointers for both buffers
																
		MR_USHORT					si_kill_timer;		// 3D sprite instance kill timer
		MR_USHORT					si_light_flags;		// Special lighting flags (shared with mesh)

		};		// MR_3DSPRITE_INST


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_2DSPRITE*	MRCreate2DSprite(MR_SHORT, MR_SHORT, MR_VIEWPORT*, MR_VOID*, MR_XY*);
extern	MR_VOID			MRKill2DSprite(MR_2DSPRITE*);
extern	MR_OBJECT*		MRCreate3DSprite(MR_FRAME*, MR_ULONG, MR_VOID*);
extern	MR_VOID			MRKill3DSprite(MR_OBJECT*);
extern	MR_VOID			MRChangeSprite(MR_VOID*, MR_VOID*);
extern	MR_VOID			MRProcessSpriteAnim(MR_SP_CORE*);
extern	MR_VOID			MRDisplay2DSprite(MR_2DSPRITE*, MR_VIEWPORT*);
extern	MR_VOID			MRDisplay3DSpriteInstance(MR_3DSPRITE_INST*, MR_VIEWPORT*);

extern	MR_BOOL			MRSprtCodeNOP(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETIMAGE(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETBLANK(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETSPEED(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETSCALE(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETCOLOUR(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETOTOFFSET(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETMASTERPOS(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETFLAGS(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeCLRFLAGS(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeENTERCRITICAL(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeEXITCRITICAL(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeSETCOUNT(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeLOOPBACK(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeRESTART(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeHALT(MR_SP_CORE*);
extern	MR_BOOL			MRSprtCodeKILL(MR_SP_CORE*);

extern	MR_OBJECT*		MRCreateMemfixedWithInsts3DSprite(MR_FRAME*,	MR_ULONG, MR_VOID*, MR_VIEWPORT**);


#endif	//__MR_SPRT_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

