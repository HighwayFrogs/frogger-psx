/******************************************************************************
*%%%% mr_sprt.c
*------------------------------------------------------------------------------
*
*	Routines to handle 2D and 3D sprites, and associated animation control
*	lists
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Added angular rotation + offsets for 2D sprites
*	18.06.96	Dean Ashton		Changed MRSprtCodeSETXYOFFSET function name to
*								MRSprtCodeSETMASTERPOS (to avoid name confusion)
*	09.07.96	Dean Ashton		Changed link pointer positions for 2D sprites
*	06.08.96	Dean Ashton		File now known as 'The source code formally known
*								as mr_anim.c' to avoid conflicts with model anims.
*	15.10.96	Tim Closs		Reordered stuff to fix bug for forced OTZ
*								in MRDisplay3DSpriteInstance
*	04.11.96	Tim Closs		Changed MRSprtCodeKILL to kill by instance
*								MRCreate3DSprite() now correctly sets pointer in
*								MR_3DSPRITE back to owning object
*	05.11.96	Tim Closs		MRDisplay3DSpriteInstance() - fixed bug with sc_otz_offset
*	04.12.96	Tim Closs		Added support for MR_SPF_HORIZONTAL_FLIP and
*								MR_SPF_VERTICAL_FLIP in MRDisplay2DSprite()
*	05.02.97	Dean Ashton		Changed lighting code to use new more efficient model
*	06.02.97	Tim Closs		Added MRCreateMemfixedWithInsts3DSprite()
*	14.02.97	Dean Ashton		Changed MR_SPIB_TRANSPARENT to MR_SPIB_TRANSLUCENT
*	04.03.97	Tim Closs		MRCreate3DSprite() - NULL frame now permitted
*										
*%%%**************************************************************************/

// Includes
#include	"mr_all.h"

// Data
MR_SVEC			MRSprt_light_normal		= {0,0, 4096};
MR_SVEC			MRSprt_light_normal_inv = {0,0,-4096};

MR_SPRT_CODE	MRSprt_functions[] =
					{
					MRSprtCodeNOP,	
					MRSprtCodeSETIMAGE,
					MRSprtCodeSETBLANK,			
					MRSprtCodeSETSPEED,			
					MRSprtCodeSETSCALE,			
					MRSprtCodeSETCOLOUR,			
					MRSprtCodeSETOTOFFSET,
					MRSprtCodeSETMASTERPOS,
												 			
					MRSprtCodeSETFLAGS,			
					MRSprtCodeCLRFLAGS,			

					MRSprtCodeENTERCRITICAL,			
					MRSprtCodeEXITCRITICAL,			

					MRSprtCodeSETCOUNT,			
					MRSprtCodeLOOPBACK,			

					MRSprtCodeRESTART,			
					MRSprtCodeHALT,			
					MRSprtCodeKILL,
					};			
			

/******************************************************************************
*%%%% MRCreate2DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_2DSPRITE* sprite_ptr =	MRCreate2DSprite(
*											MR_SHORT		x_pos,
*											MR_SHORT		y_pos,
*											MR_VIEWPORT*	vport,
*											MR_VOID*		image_alist,
*											MR_XY*			master_pos,
*
*	FUNCTION	Create a 2D sprite at the specified X and Y positions in the 
*				designated viewport, and initialises the animation list processor
*				to accept commands from the list which may be pointed to by the
*				'image_alist' parameter. 
*
*	INPUTS		x_pos  		-	X position for 2D sprite in viewport
*				y_pos  		-	Y position for 2D sprite in viewport
*				vport  		-	Pointer to MR_VIEWPORT structure
*				image_alist	-	Pointer to an animlist, or a sprite
*				master_pos	-	Pointer to a master position (or NULL)
*
*	RESULT		sprite_ptr	-	Pointer to the newly created sprite
*
*	NOTES		The X/Y positions relate to an absolute viewport position for the
*				sprite if 'master_pos' is NULL. If there is a pointer to a master
*				position, then X/Y positions are interpreted as offsets from that
*				master position. Also, the 'image_alist' parameter is MR_VOID* 
*				due to the fact that it can point to an MR_TEXTURE, or an array
*				of MR_ULONGS (as is used to define an animation list). 
*				Also, note that it is valid for 'image_alist' to be NULL, in
*				which case the creation is completed but no image processing is
*				performed.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	09.07.96	Dean Ashton		Changed link positions for 2D sprites
*
*%%%**************************************************************************/

MR_2DSPRITE* MRCreate2DSprite(	MR_SHORT 		x_pos,
								MR_SHORT 		y_pos,
								MR_VIEWPORT* 	vport,
								MR_VOID* 		image_alist,
								MR_XY*			master_pos)
{
	MR_ULONG		flags;
	MR_2DSPRITE*	sprite_root_ptr;
	MR_2DSPRITE*	sprite_ptr;
	MR_SP_CORE*		core_ptr;

	MR_ASSERT(vport != NULL);

	// Find out what we are... if bit 15 is set (MR_SPIB_SPRITE_ID) in the first short, then
	// it's a sprite, otherwise it's an animlist (because we can't have animlist command ID's
	// greater than 32768...
	if	((*((MR_USHORT*)image_alist) & MR_SPIF_SPRITE_ID) || (image_alist == NULL))
		flags = MR_SPF_SPRITE_IS_2D | MR_SPF_IS_IMAGE;
	else
		flags = MR_SPF_SPRITE_IS_2D;

	// Allocate the memory associated with the 2D Sprite....
	sprite_ptr	= (MR_2DSPRITE*)MRAllocMem(sizeof(MR_2DSPRITE), "MR2DSPR");
	core_ptr		= &sprite_ptr->sp_core;

	// Initialise the polygons...
	setPolyFT4(&sprite_ptr->sp_polygon[0]);
	setPolyFT4(&sprite_ptr->sp_polygon[1]);

	// Set sprite core variables
	core_ptr->sc_flags				= flags;
	core_ptr->sc_ot_offset			= NULL;
	core_ptr->sc_scale				= MR_SP2D_DEFAULT_SCALE;	// Scale is 1

	// Initialise animation list variables
	if (flags & MR_SPF_IS_IMAGE)
		{
		core_ptr->sc_alist_addr		= NULL;
		core_ptr->sc_image			= (MR_TEXTURE*)image_alist; 
		}
	else
		{
		core_ptr->sc_alist_addr		= (MR_ULONG*)image_alist;
		core_ptr->sc_image			= NULL;
		}

	core_ptr->sc_alist_pc			= 0;
	core_ptr->sc_alist_count		= MR_SPALIST_FORCE_NEXT;
	core_ptr->sc_alist_speed		= MR_SPALIST_DEFAULT_SPEED; 

	// Set base colour and POLY_FT4 code 
	core_ptr->sc_base_colour.b		= core_ptr->sc_base_colour.g = core_ptr->sc_base_colour.r = 0x80;
	core_ptr->sc_base_colour.cd		= 0x2c;			// Note: Change to an Equate! 

	// Set 2D sprite specific variables
	sprite_ptr->sp_image_buf[0]	= NULL;				// No images for this sprite set up, yet
	sprite_ptr->sp_image_buf[1]	= NULL;

	sprite_ptr->sp_master_pos		= master_pos;
	sprite_ptr->sp_pos.x			= x_pos;
	sprite_ptr->sp_pos.y			= y_pos;
	
	sprite_ptr->sp_offset.x			= 0;
	sprite_ptr->sp_offset.y			= 0;
	sprite_ptr->sp_angle			= 0;

	sprite_ptr->sp_kill_timer		= 0;
	
	// Link 2D sprite to specified viewport
	sprite_root_ptr = vport->vp_2dsprite_root_ptr;
	
	if (((MR_SP_CORE*)sprite_ptr)->sc_next_node = ((MR_SP_CORE*)sprite_root_ptr)->sc_next_node)
		((MR_SP_CORE*)sprite_root_ptr)->sc_next_node->sc_prev_node = ((MR_SP_CORE*)sprite_ptr);
	
	((MR_SP_CORE*)sprite_root_ptr)->sc_next_node = ((MR_SP_CORE*)sprite_ptr);
	((MR_SP_CORE*)sprite_ptr)->sc_prev_node = ((MR_SP_CORE*)sprite_root_ptr);

	return(sprite_ptr);
}


/******************************************************************************
*%%%% MRKill2DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKill2DSprite(
*						MR_2DSPRITE*	sprite_ptr);	
*
*	FUNCTION	Starts the kill mechanism for 2D sprites, which involves the use
*				of timers to ensure the sprite is only actually freed when none
*				of the sprites GPU primitives are being rendered.
*
*	INPUTS		sprite_ptr	-	Pointer to an MR_2DSPRITE structure	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRKill2DSprite(MR_2DSPRITE* sprite_ptr)
{
	MR_ASSERT(sprite_ptr != NULL);
	sprite_ptr->sp_kill_timer = 2;
}


/******************************************************************************
*%%%% MRCreate3DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT*	object_ptr =	MRCreate3DSprite(
*											MR_FRAME*	frame,
*											MR_ULONG	obj_flags,
*											MR_VOID*	image_alist);
*
*	FUNCTION	Creates a 3D sprite object at the work position pointed to by 
*				'frame', and initialises the animation list processor to accept
*				commands from the list which may be pointed to by 'image_alist'.
*
*	INPUTS		frame	 	-	Pointer to a valid MR_FRAME structure
*							 	from which the world position is copied, or
*							 	a pointer to a static matrix.
*				obj_flags	-	Flags to be used when creating the sprite
*							 	object. Typically NULL, or MR_OBJ_STATIC if
*							 	the sprite is linked to a static matrix, 
*							 	which is pointed to by frame.
*				image_alist	-	Pointer to an animlist, or a sprite, or NULL
*
*	RESULT		object_ptr	-	Pointer to the returned MR_OBJECT structure
*								if successful, or NULL if failure occurred.
*
*	NOTES		On PlayStation, this routine will not fail. MRCreateObject() will
*				only fail if a memory allocation error occurs, in which case
*				MRAllocMem() will cause an assertion.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	21.05.96	Dean Ashton		Added obj_flags, to enable object creation that
*								is pointing to a static matrix (via 'frame').
*	04.11.96	Tim Closs		Now correctly sets pointer in MR_3DSPRITE back
*								to owning object
*	04.03.97	Tim Closs		NULL frame now permitted
*
*%%%**************************************************************************/

MR_OBJECT*	MRCreate3DSprite(	MR_FRAME*	frame,
								MR_ULONG	obj_flags,
								MR_VOID*	image_alist)
{
	MR_ULONG		flags;
	MR_OBJECT*		object_ptr;
	MR_3DSPRITE*	sprite_ptr;
	MR_SP_CORE*		core_ptr;

	// Find out what we are... if bit 15 is set (MR_SPIB_SPRITE_ID) in the first short, then
	// it's a sprite, otherwise it's an animlist (because we can't have animlist command ID's
	// greater than 32768...
	if	((*((MR_USHORT*)image_alist) & MR_SPIF_SPRITE_ID) || (image_alist == NULL))
		flags = MR_SPF_IS_IMAGE;
	else
		flags = NULL;

	// Change to use callbacks at some time in the future
	if (object_ptr = MRCreateObject(MR_OBJTYPE_3DSPRITE, frame, obj_flags, NULL))
		{
		sprite_ptr	= object_ptr->ob_extra.ob_extra_3dsprite;
		core_ptr	= &sprite_ptr->sp_core;

		// Set sprite core variables
		core_ptr->sc_flags				= flags;
		core_ptr->sc_ot_offset			= NULL;
		core_ptr->sc_scale				= MR_SP3D_DEFAULT_SCALE;	// Scale is 1

		// Set things that changed between images and animlists
		if (flags & MR_SPF_IS_IMAGE)
			{
			core_ptr->sc_alist_addr		= NULL;
			core_ptr->sc_image			= (MR_TEXTURE*)image_alist; 
			}
		else
			{
			core_ptr->sc_alist_addr		= (MR_ULONG*)image_alist;
			core_ptr->sc_image			= NULL;
			}

		// Initialise animation list variables
		core_ptr->sc_alist_pc			= 0;
		core_ptr->sc_alist_count		= MR_SPALIST_FORCE_NEXT;
		core_ptr->sc_alist_speed		= MR_SPALIST_DEFAULT_SPEED; 

		// Set base colour and POLY_FT4 code 
		core_ptr->sc_base_colour.b		= core_ptr->sc_base_colour.g = core_ptr->sc_base_colour.r = 0x80;
		core_ptr->sc_base_colour.cd		= 0x2c;			// Note: Change to an Equate! 

		// Set sprite pointer back to object
		sprite_ptr->sp_object 			= object_ptr;

		// Set object flags
		object_ptr->ob_flags |= (MR_OBJ_ACCEPT_LIGHTS_AMBIENT |
								  	 	MR_OBJ_ACCEPT_LIGHTS_PARALLEL |
										MR_OBJ_ACCEPT_LIGHTS_POINT);

		sprite_ptr->sp_frame	= object_ptr->ob_frame;	// because NULL doesn't always mean NULL.... 8^/
		MR_CLEAR_SVEC(&sprite_ptr->sp_ofs_image);

		return(object_ptr);
		}
	else
		return(NULL);
}


/******************************************************************************
*%%%% MRKill3DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRKill3DSprite(
*						MR_OBJECT*	sprite_ptr);	
*
*	FUNCTION	Starts the kill mechanism for 3D sprites, which involves the use
*				of timers to ensure the sprite is only actually freed when none
*				of the sprites GPU primitives are being rendered.
*
*	INPUTS		sprite_ptr	-	Pointer to an MR_OBJECT structure	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRKill3DSprite(MR_OBJECT* sprite_ptr)
{
	MR_ASSERT(sprite_ptr != NULL);
	MR_ASSERT(sprite_ptr->ob_type == MR_OBJTYPE_3DSPRITE);

	MRKillObject(sprite_ptr);
}


/******************************************************************************
*%%%% MRChangeSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRChangeSprite(
*						MR_VOID*	sprite_ptr,
*						MR_VOID*	image_alist);
*
*	FUNCTION	Changes either a 2D or 3D sprite to use the specified animation
*				list (or static image). This means that a sprite that was 
*				animation-list based can be forced into a single image, which
*				would still obey the sprites parameter settings, and vice-versa.
*
*	INPUTS		sprite_ptr	-	Pointer to a MR_2D_SPRITE or MR_3D_SPRITE
*				image_alist	-	Pointer to an array of MR_ULONGs (in the 
*							 	case of an animation list), or a single
*							 	MR_TEXTURE.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRChangeSprite(	MR_VOID* sprite,
						MR_VOID* image_alist)
{
	MR_SP_CORE*	sprite_core = (MR_SP_CORE*)sprite;


	sprite_core = (MR_SP_CORE*)sprite;

	// Find out what we are, and set bits depending on what we find...
	if	((*((MR_USHORT*)image_alist) & MR_SPIF_SPRITE_ID) || (image_alist == NULL))
		{
		// Set flags to say we're image based, and clear critical section
		sprite_core->sc_flags			  |= MR_SPF_IS_IMAGE;		
		sprite_core->sc_flags			  &= ~(MR_SPF_IN_CRITICAL);

		// Set new image pointer
		sprite_core->sc_image				=	(MR_TEXTURE*)image_alist;		

		// Initialise redundant animation list stuff
		sprite_core->sc_alist_pc			=	NULL;					
		sprite_core->sc_alist_addr			= 	NULL;
		sprite_core->sc_alist_count			=	MR_SPALIST_FORCE_NEXT;
		sprite_core->sc_alist_speed			=	MR_SPALIST_DEFAULT_SPEED; 
		sprite_core->sc_alist_loop_pc		=	0;
		sprite_core->sc_alist_loop_count	=	0;

		}
	else
		{
		// Set flags - Not image based, and clear critical section
		sprite_core->sc_flags			  &= ~(MR_SPF_IS_IMAGE | MR_SPF_IN_CRITICAL);

		// Initialise new animation list stuff
		sprite_core->sc_alist_pc			=	NULL;
		sprite_core->sc_alist_addr			= 	(MR_ULONG*)image_alist;
		sprite_core->sc_alist_count			=	MR_SPALIST_FORCE_NEXT;
		sprite_core->sc_alist_speed			=	MR_SPALIST_DEFAULT_SPEED; 
		sprite_core->sc_alist_loop_pc		=	0;
		sprite_core->sc_alist_loop_count	=	0;

		}
}	


/******************************************************************************
*%%%% MRDisplay2DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDisplay2DSprite(
*						MR_2DSPRITE*	sprite_ptr,
*						MR_VIEWPORT*	vp);
*
*	FUNCTION	Performs all necessary processing to display a 2D sprite
*				on the specified viewport.
*
*	INPUTS		sprite_ptr	-	Pointer to a valid MR_2DSPRITE structure
*				vp			-	Pointer to the sprites owning MR_VIEWPORT
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	29.05.96	Dean Ashton		Added support for MR_SPF_2D_H_DOUBLE flag
*	04.12.96	Tim Closs		Added support for MR_SPF_HORIZONTAL_FLIP and
*								MR_SPF_VERTICAL_FLIP
*	14.02.97	Dean Ashton		Transparency -> Translucency... 
*
*%%%**************************************************************************/

MR_VOID	MRDisplay2DSprite(	MR_2DSPRITE* sprite_ptr,
							MR_VIEWPORT* vp)
{
	MR_SP_CORE*	spcore_ptr;
	POLY_FT4*	poly;
	MR_USHORT	sprite_otz;	
	
	MR_SHORT	x0,y0;	
	MR_SHORT	x1,y1;	
	MR_SHORT	x2,y2;	
	MR_SHORT	x3,y3;	
	MR_SHORT	ox,oy;

	MR_SHORT	tx,ty;

	MR_LONG		x0costheta,x0sintheta,x1costheta,x1sintheta;
	MR_LONG		y0costheta,y0sintheta,y2costheta,y2sintheta;

	MR_SHORT	costheta,sintheta;	

	MR_ASSERT(sprite_ptr != NULL);
	MR_ASSERT(vp != NULL);

	spcore_ptr	= &sprite_ptr->sp_core;
	poly		= &(sprite_ptr->sp_polygon[MRFrame_index]);

	// We only want to display the sprite if it's got an image to show..
	if (spcore_ptr->sc_image)
		{
		// If the image has changed, set our polygons up with new details
		if (spcore_ptr->sc_image != sprite_ptr->sp_image_buf[MRFrame_index])
			{
			// Update our current image pointer
			sprite_ptr->sp_image_buf[MRFrame_index] = spcore_ptr->sc_image;

			// Translucency if needed											
			if (spcore_ptr->sc_image->te_flags & MR_SPIF_TRANSLUCENT)
				{
				setSemiTrans(poly, 1);
				spcore_ptr->sc_base_colour.cd = 0x2e;
				}
			else
				{
				setSemiTrans(poly, 0);
				spcore_ptr->sc_base_colour.cd = 0x2c;
				}

			// Set texture page, CLUT, and texture coordinates
			MR_COPY32(poly->u0, spcore_ptr->sc_image->te_u0);	// Copies te_tpage_id too
			MR_COPY32(poly->u1, spcore_ptr->sc_image->te_u1);	// Copies te_clut_id too
			MR_COPY16(poly->u2, spcore_ptr->sc_image->te_u2);
			MR_COPY16(poly->u3, spcore_ptr->sc_image->te_u3);

			// Flipping requires that the image has been stored in VRAM with spare outer pixels
			if (spcore_ptr->sc_flags & MR_SPF_HORIZONTAL_FLIP)
				{
				poly->u0 = spcore_ptr->sc_image->te_u1 - 1;
				poly->u1 = spcore_ptr->sc_image->te_u0 - 1;
				poly->u2 = spcore_ptr->sc_image->te_u3 - 1;
				poly->u3 = spcore_ptr->sc_image->te_u2 - 1;
				}
			if (spcore_ptr->sc_flags & MR_SPF_VERTICAL_FLIP)
				{
				poly->v0 = spcore_ptr->sc_image->te_v2 - 1;
				poly->v2 = spcore_ptr->sc_image->te_v0 - 1;
				poly->v1 = spcore_ptr->sc_image->te_v3 - 1;
				poly->v3 = spcore_ptr->sc_image->te_v1 - 1;
				}
			}

		// If the sprite isn't required, bail out.
		if (spcore_ptr->sc_flags & MR_SPF_NO_DISPLAY)
			return;

		// Calculate origin of sprite
		ox = sprite_ptr->sp_pos.x + sprite_ptr->sp_offset.x;
		oy = sprite_ptr->sp_pos.y + sprite_ptr->sp_offset.y;

		// Calculate offsets for each corner (minimal set)
		x0 = -(sprite_ptr->sp_offset.x);
		y0 = -(sprite_ptr->sp_offset.y);

		x1 = (spcore_ptr->sc_image->te_w) + x0;
		y2 = (spcore_ptr->sc_image->te_h) + y0;

		// Apply the scale to each coordinate (if not a 1:1)
		if (spcore_ptr->sc_scale != 1<<16)
			{
			x0 = (x0 * spcore_ptr->sc_scale) >> 16;	
			x1 = (x1 * spcore_ptr->sc_scale) >> 16;	
		
			y0 = (y0 * spcore_ptr->sc_scale) >> 16;	
			y2 = (y2 * spcore_ptr->sc_scale) >> 16;	
			}

		// If we've got horizontal doubling, then scale it horizontally
		if (spcore_ptr->sc_flags & MR_SPF_2D_H_DOUBLE)
			{
			x0 = x0 << 1;
			x1 = x1 << 1;
			}

		// If we've got a rotation, then rotate the offsets
		if (sprite_ptr->sp_angle != 0)
			{
			costheta = rcos(sprite_ptr->sp_angle);
			sintheta = rsin(sprite_ptr->sp_angle);
		
			x0costheta = x0 * costheta;
 			x1costheta = x1 * costheta;
			y0costheta = y0 * costheta;
			y2costheta = y2 * costheta;

			x0sintheta = x0 * sintheta;
 			x1sintheta = x1 * sintheta;
			y0sintheta = y0 * sintheta;
			y2sintheta = y2 * sintheta;

			x0 = (x0costheta - y0sintheta)>>12;
			y0 = (y0costheta + x0sintheta)>>12;			

			x1 = (x1costheta - y0sintheta)>>12;
			y1 = (y0costheta + x1sintheta)>>12;			

			x2 = (x0costheta - y2sintheta)>>12;
			y2 = (y2costheta + x0sintheta)>>12;			

			x3 = (x1costheta - y2sintheta)>>12;
			y3 = (y2costheta + x1sintheta)>>12;			
			}
		else
			{
			x2 = x0;
			x3 = x1;
			y1 = y0;
			y3 = y2;
			}

		// Calculate our real screen-shove offsets
		if (sprite_ptr->sp_master_pos != NULL)
			{
			tx = sprite_ptr->sp_master_pos->x + sprite_ptr->sp_pos.x;
			ty = sprite_ptr->sp_master_pos->y + sprite_ptr->sp_pos.y;
			}
		else
			{
			tx = sprite_ptr->sp_pos.x;
			ty = sprite_ptr->sp_pos.y;
			}

		// Turn the offsets into real coordinates again, constructing polygon coordinates
		poly->x0 = x0 + tx;
		poly->x1 = x1 + tx;
		poly->x2 = x2 + tx;
		poly->x3 = x3 + tx;

		poly->y0 = y0 + ty;
		poly->y1 = y1 + ty;
		poly->y2 = y2 + ty;
		poly->y3 = y3 + ty;

		// Set base colour of the sprite (this copies the POLY_FT4 code from the CVECTOR too)
		MR_COPY32(poly->r0,spcore_ptr->sc_base_colour);
	
		// You _could_ bin 2D sprites if they were off screen, but I think it'd take more
		// time than letting the H/W clip it.. instead we'll respect the OT and associated
		// flags, and add the bugger to the OT.
		if (spcore_ptr->sc_flags & MR_SPF_FORCE_FRONT)	// Add to the front of the OT
			sprite_otz = MR_SP2D_MIN_OT_POS;
		else						  
		if (spcore_ptr->sc_flags & MR_SPF_FORCE_BACK)	// Add to the back of the OT
			sprite_otz = MRVp_ot_size - 1;
		else
			sprite_otz = MAX(MR_SP2D_MIN_OT_POS, spcore_ptr->sc_ot_offset);
		
		addPrim(vp->vp_ot[MRFrame_index]+sprite_otz, poly);
		}
}


/******************************************************************************
*%%%% MRDisplay3DSpriteInstance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDisplay3DSpriteInstance(
*						MR_3DSPRITE_INST*	spinst_ptr,
*						MR_VIEWPORT*		vp);
*
*	FUNCTION	Displays a 3D positioned/rotated sprite (using associated 
*				animation lists if necessary) in the specified viewport.
*
*	INPUTS		spinst_ptr	-	Pointer to a valid MR_3DSPRITE_INST structure
*				vp			-	Pointer to the sprites owning MR_VIEWPORT
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*	15.10.96	Tim Closs		Reordered stuff to fix bug for forced OTZ
*	05.11.96	Tim Closs		Fixed bug with sc_otz_offset
*	05.02.97	Dean Ashton		Changed lighting code
*	14.02.97	Dean Ashton		Transparency -> Translucency... 
*
*%%%**************************************************************************/

MR_VOID	MRDisplay3DSpriteInstance(	MR_3DSPRITE_INST*	spinst_ptr,
									MR_VIEWPORT* 		vp)
{
	MR_SP_CORE*		spcore_ptr;
	MR_3DSPRITE*	spr3d_ptr;
	POLY_FT4*		poly;
	MR_OBJECT*		object_ptr;
	MR_SVEC*		normal_ptr;
	MR_FRAME*		camera_frame;
	MR_SVEC			coords[4];
	MR_SVEC			svec;
	MR_VEC			vec;
	MR_LONG			sprite_long;
	MR_LONG			sprite_otz;
	MR_USHORT		sprite_w;
	MR_USHORT		sprite_h;
	MR_MAT*			rotation_ptr;
	MR_ULONG		lights_modified = NULL;
	
	MR_ASSERT(spinst_ptr != NULL);
	MR_ASSERT(vp != NULL);

	// Local variable initialisation
	spcore_ptr		= spinst_ptr->si_object->ob_extra.ob_extra_sp_core;
	spr3d_ptr		= (MR_3DSPRITE*)spcore_ptr;
	poly			= &(spinst_ptr->si_polygon[MRFrame_index]);
	object_ptr		= spinst_ptr->si_object;
	camera_frame	= vp->vp_camera;

	// We only want to display the sprite if it's got an image to show..
	if (spcore_ptr->sc_image)
		{
		// If the image has changed, set our polygons up with new details
		if (spcore_ptr->sc_image != spinst_ptr->si_image_buf[MRFrame_index])
			{
			// Update our current image pointer
			spinst_ptr->si_image_buf[MRFrame_index] = spcore_ptr->sc_image;

			// Translucency if needed
			if (spcore_ptr->sc_image->te_flags & MR_SPIF_TRANSLUCENT)
				{
				setSemiTrans(poly, 1);
				spcore_ptr->sc_base_colour.cd = 0x2e;
				}
			else
				{
				setSemiTrans(poly, 0);
				spcore_ptr->sc_base_colour.cd = 0x2c;
				}

			// Set texture page, CLUT, and texture coordinates
			MR_COPY32(poly->u0, spcore_ptr->sc_image->te_u0);	// Copies te_tpage_id too
			MR_COPY32(poly->u1, spcore_ptr->sc_image->te_u1);	// Copies te_clut_id too
			MR_COPY16(poly->u2, spcore_ptr->sc_image->te_u2);
			MR_COPY16(poly->u3, spcore_ptr->sc_image->te_u3);
			}
		
		// If the sprite isn't required, bail out.
		if (spcore_ptr->sc_flags & MR_SPF_NO_DISPLAY)
			goto shutdown;

		// Scale width and height, and divide by 2 (image is the center of a 3D sprite)
		sprite_w = ((MR_USHORT)(((spcore_ptr->sc_image->te_w) * (spcore_ptr->sc_scale)) >> 16))>>1;
		sprite_h = ((MR_USHORT)(((spcore_ptr->sc_image->te_h) * (spcore_ptr->sc_scale)) >> 16))>>1;
																				 
		// Calculate 3D coordinates for each corner point, taking offset into account.
		//
		//	Points are ordered:	0  1
		//
		// 							2  3
		if (spcore_ptr->sc_flags & MR_SPF_NO_3D_SCALING)
			{
			}
		else
			{
			if (spcore_ptr->sc_flags & MR_SPF_IN_YZ_PLANE)
				{
				// 3D sprite in local YZ plane
				coords[0].vz = coords[2].vz = spr3d_ptr->sp_ofs_image.vz - sprite_w;
				coords[1].vz = coords[3].vz = spr3d_ptr->sp_ofs_image.vz + sprite_w;
				coords[0].vy = coords[1].vy = spr3d_ptr->sp_ofs_image.vy - sprite_h;
				coords[2].vy = coords[3].vy = spr3d_ptr->sp_ofs_image.vy + sprite_h;
				coords[0].vx = coords[1].vx = coords[2].vx = coords[3].vx = spr3d_ptr->sp_ofs_image.vx;
				}
			else
			if (spcore_ptr->sc_flags & MR_SPF_IN_XZ_PLANE)
				{
				// 3D sprite in local XZ plane
				coords[0].vx = coords[2].vx = spr3d_ptr->sp_ofs_image.vx - sprite_w;
				coords[1].vx = coords[3].vx = spr3d_ptr->sp_ofs_image.vx + sprite_w;
				coords[0].vz = coords[1].vz = spr3d_ptr->sp_ofs_image.vz + sprite_h;
				coords[2].vz = coords[3].vz = spr3d_ptr->sp_ofs_image.vz - sprite_h;
				coords[0].vy = coords[1].vy = coords[2].vy = coords[3].vy = spr3d_ptr->sp_ofs_image.vy;
				}
			else
				{
				// 3D sprite in local XY plane
				coords[0].vx = coords[2].vx = spr3d_ptr->sp_ofs_image.vx - sprite_w;
				coords[1].vx = coords[3].vx = spr3d_ptr->sp_ofs_image.vx + sprite_w;
				coords[0].vy = coords[1].vy = spr3d_ptr->sp_ofs_image.vy - sprite_h;
				coords[2].vy = coords[3].vy = spr3d_ptr->sp_ofs_image.vy + sprite_h;
				coords[0].vz = coords[1].vz = coords[2].vz = coords[3].vz = spr3d_ptr->sp_ofs_image.vz;
				}
			}

		// ----- Horror 3D stuff coming up -----

		// Get pointer to sprite LW transform from MR_FRAME or MR_MAT according to whether or
		// not we're using a static frame
		if (spcore_ptr->sc_flags & MR_SPF_NO_3D_ROTATION)
			{
			rotation_ptr = &MRId_matrix;
			if (object_ptr->ob_flags & MR_OBJ_STATIC)
				MRWorldtrans_ptr = (MR_MAT*)(object_ptr->ob_frame);
			else
				MRWorldtrans_ptr = &object_ptr->ob_frame->fr_lw_transform;
			}
		else
			{
			rotation_ptr = MRViewtrans_ptr;
			if (object_ptr->ob_flags & MR_OBJ_STATIC)
				{
				if (MRWorldtrans_ptr != (MR_MAT*)object_ptr->ob_frame)
					{
					// If the camera matrix.m is the same as when this function was last called
					// then we only need to update the view matrix.m if the worldtrans matrix.m
					// is different... speed savings ahoy!
					MRWorldtrans_ptr = (MR_MAT*)(object_ptr->ob_frame);
					MRMulMatrixABC(&vp->vp_render_matrix, MRWorldtrans_ptr, MRViewtrans_ptr);
					}
				}
			else
				{
				// Object frame is not static
				if (MRWorldtrans_ptr != &object_ptr->ob_frame->fr_lw_transform)
					{
					// Same kind of speed optimisation as above for MR_OBJ_STATIC
					MRWorldtrans_ptr = &object_ptr->ob_frame->fr_lw_transform;
					MRMulMatrixABC(&vp->vp_render_matrix, MRWorldtrans_ptr, MRViewtrans_ptr);
					}
				}
			}
		MRApplyMatrix(MRWorldtrans_ptr, &object_ptr->ob_offset, &vec);
		svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] + (MR_SHORT)vec.vx - (MR_SHORT)vp->vp_render_matrix.t[0];
		svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] + (MR_SHORT)vec.vy - (MR_SHORT)vp->vp_render_matrix.t[1];
		svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] + (MR_SHORT)vec.vz - (MR_SHORT)vp->vp_render_matrix.t[2];
		MRApplyMatrix(&vp->vp_render_matrix, &svec, (MR_VEC*)MRViewtrans_ptr->t);


		//---------------------------------------------------------------------------------------------

		// If we:
		//		a. Have to scale the colour matrix, or have a custom ambient
		//		b.	Don't want an ambient colour
		//		c.	Don't want parallel lights	
		//		d. Are accepting pointlights, and there are some in the viewport
		//
		// Then:
		//		Recalculate the lighting matrix, and perhaps the ambient colour too..
		//
		//	Else:
		//		Use the viewport lighting matrix

		if (
			(spinst_ptr->si_light_flags & MR_INST_MODIFIED_LIGHT_MASK) ||
				(!(object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_AMBIENT)) || 
				(!(object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_PARALLEL)) ||
				((vp->vp_pointlights) && (object_ptr->ob_flags & MR_OBJ_ACCEPT_LIGHTS_POINT))
			)
			{
			lights_modified = MRCalculateCustomInstanceLights(	object_ptr,
			 													spinst_ptr->si_light_flags,
																&spinst_ptr->si_colour_scale,
																&spinst_ptr->si_custom_ambient);
			if (!(spcore_ptr->sc_flags & MR_SPF_NO_3D_ROTATION))
				{
				MRMulMatrixABC(&MRLight_matrix, MRWorldtrans_ptr, &MRLight_matrix);
				}
			gte_SetLightMatrix(&MRLight_matrix);
			}
		else
			{
			if (!(spcore_ptr->sc_flags & MR_SPF_NO_3D_ROTATION))
				{		
				MRMulMatrixABC(&vp->vp_light_matrix, MRWorldtrans_ptr, &MRLight_matrix);
				gte_SetLightMatrix(&MRLight_matrix);
				}
			else
				{
				gte_SetLightMatrix(&vp->vp_light_matrix);
				}
			lights_modified = NULL;
			}

		//---------------------------------------------------------------------------------------------

		// Set up GTE matrix and offset
		gte_SetRotMatrix(rotation_ptr);
		gte_SetTransMatrix(MRViewtrans_ptr);
	
		normal_ptr = &MRSprt_light_normal;							// normal for lighting

		if (spcore_ptr->sc_flags & MR_SPF_NO_3D_SCALING)
			{
			gte_ldv0(&spr3d_ptr->sp_ofs_image);
			gte_rtps();	
			gte_stsxy(&sprite_long);
			gte_stsz(&sprite_otz);
			poly->x0 = poly->x2 = ((MR_SHORT*)&sprite_long)[0] - sprite_w;
			poly->x1 = poly->x3 = ((MR_SHORT*)&sprite_long)[0] + sprite_w;
			poly->y0 = poly->y1 = ((MR_SHORT*)&sprite_long)[1] - sprite_h;
			poly->y2 = poly->y3 = ((MR_SHORT*)&sprite_long)[1] + sprite_h;
			}
		else
			{
			gte_ldv3(&coords[0], &coords[1], &coords[2]);			// Load vertices
			gte_rtpt();												// Rotate them			
			gte_nclip();											// Normal clip
			gte_stopz(&sprite_long);								// Store result of normal clip

			if (sprite_long <= 0)				
				{
				if (spcore_ptr->sc_flags & MR_SPF_USE_3D_NCLIP)		// Normal clipped == Bin?
					goto shutdown;									// Put on parachute, and bail out.
				else
					normal_ptr = &MRSprt_light_normal_inv;			// Use inverse normal for lighting
				}																
	
			gte_stsxy0((MR_LONG*)&poly->x0);						// Store screen coordinates from fifo
			gte_stsxy1((MR_LONG*)&poly->x1);
			gte_stsxy2((MR_LONG*)&poly->x2);
	
			gte_ldv0(&coords[3]);									// Load 4th vertex
			gte_rtps();												// Rotate it.
			gte_avsz4();											// Average 4 sz values in the fifo
			gte_stotz(&sprite_otz);									// Get OTZ 
			}
		
		// Perform any modifications to the sprite OTZ
		if (spcore_ptr->sc_flags & MR_SPF_FORCE_FRONT)				// Add to the front of the OT
			sprite_otz = MR_SP3D_MIN_OT_POS;
		else
		if (spcore_ptr->sc_flags & MR_SPF_FORCE_BACK)				// Add to the back of the OT
			sprite_otz = MRVp_ot_size - 1;
		else
			{
			sprite_otz = MAX(MR_SP3D_MIN_OT_POS, sprite_otz >> MRVp_otz_shift);
			sprite_otz += spcore_ptr->sc_ot_offset;
			}

		// If the OTZ is valid, then get the last sxy coordinate from the end of the fifo..
		if (
			(sprite_otz > MR_OT_NEAR_CLIP) &&
			(sprite_otz < MRVp_ot_size)
			)
			{
			if (!(spcore_ptr->sc_flags & MR_SPF_NO_3D_SCALING))
				gte_stsxy2((MR_LONG*)&poly->x3);							
				
			if (
				(((poly->y0 >= 0) ||
				  (poly->y1 >= 0) ||
				  (poly->y2 >= 0) ||
				  (poly->y3 >= 0)) &&
				 ((poly->y0 < MRVp_disp_h) ||
				  (poly->y1 < MRVp_disp_h) ||
				  (poly->y2 < MRVp_disp_h) ||
				  (poly->y3 < MRVp_disp_h)))
				)									 
				{
	
				// Set the polygon colour 
				if ((MRVp_fog_near_distance) && (spinst_ptr->si_object->ob_flags & MR_OBJ_ACCEPT_DPQ))
					{
					gte_ldrgb(&spcore_ptr->sc_base_colour);				// Load base colour
					gte_ldv0(normal_ptr);								// Load normal
					gte_ncds();											// NormalColorDpq core (p is already loaded)
					addPrim(vp->vp_ot[MRFrame_index]+sprite_otz, poly);	// This will probably be in delay slot
					gte_strgb((MR_CVEC*)&poly->r0);						// Store RGB into polygon
					}
				else
				if (spinst_ptr->si_object->ob_flags & MR_OBJ_ACCEPT_LIGHTS_MASK)	// Set if any lighting active
					{
					gte_ldrgb(&spcore_ptr->sc_base_colour);				// Load base colour
					gte_ldv0(normal_ptr);								// Load normal
					gte_nccs();						 					// NormalColorCol core
					addPrim(vp->vp_ot[MRFrame_index]+sprite_otz, poly);	// This will probably be in delay slot
					gte_strgb((MR_CVEC*)&poly->r0);						// Store RGB into polygon
					}
				else
					{
					MR_COPY32(poly->r0, spcore_ptr->sc_base_colour);	// Copy base colour from sprite
					addPrim(vp->vp_ot[MRFrame_index]+sprite_otz, poly);
					}
				}
			}
		}

shutdown:
	// If we've overwritten the colour matrix for this mesh, set it back to the viewport colour matrix
	if (lights_modified & MR_CHANGED_COLOUR_MATRIX)
		gte_SetColorMatrix(&vp->vp_colour_matrix);

	// If we've modified the ambient colour for this mesh, set it back to the viewport colour matrix
	if (lights_modified & MR_CHANGED_AMBIENT_COLOUR)
		gte_SetBackColor(vp->vp_back_colour.r, vp->vp_back_colour.g, vp->vp_back_colour.b);
}


/******************************************************************************
*%%%%	MRProcessSpriteAnim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRProcessSpriteAnim(
*						MR_SP_CORE*	core_ptr);
*
*	FUNCTION	Performs animation list processing for a given sprite core. The
*				sprite core is a data section common in both 3D and 2D sprite
*				processing, meaning we only need a single animation processor.
*
*	INPUTS		core_ptr	-	Pointer to a valid MR_SP_CORE structure
*
*	NOTES		This function header contains revision lists for all sprite
*				animation command functions (all defined after this routine).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRProcessSpriteAnim(MR_SP_CORE* core_ptr)
{
	MR_BOOL	pa_fetch_next_instruction;

	MR_ASSERT(core_ptr != NULL);

	// Only do list processing if we're actually a sprite with an animation list
	if (!(core_ptr->sc_flags & MR_SPF_IS_IMAGE))
		{
		// Adjust animlist counters, and if necessary execute all relevant animation commands
		pa_fetch_next_instruction = FALSE;
		core_ptr->sc_alist_count--;

		if (core_ptr->sc_alist_count == 0)
			{
			do	{
				// Execute the next command 
				pa_fetch_next_instruction = (*MRSprt_functions[*(core_ptr->sc_alist_addr + core_ptr->sc_alist_pc)])(core_ptr);

				// Reset the counter again... 
				core_ptr->sc_alist_count = core_ptr->sc_alist_speed;
				} while (pa_fetch_next_instruction);
			}
		}
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_NOP
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeNOP(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_NOP
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_NOP*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_NOP)/sizeof(MR_ULONG));

	return (MR_SPALIST_STOP);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETIMAGE
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETIMAGE(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETIMAGE
				{
				MR_ULONG			sp_opcode;
				MR_TEXTURE*			sp_sprite;
				} *sp_args = (struct sp_command_SETIMAGE*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_image		= sp_args->sp_sprite;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETIMAGE)/sizeof(MR_ULONG));

	return (MR_SPALIST_STOP);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETBLANK
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETBLANK(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETBLANK 
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_SETBLANK*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_image 		= NULL;	

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETBLANK)/sizeof(MR_ULONG));

	return (MR_SPALIST_STOP);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETSPEED
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETSPEED(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETSPEED
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_speed;
				} *sp_args = (struct sp_command_SETSPEED*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_alist_speed	=	sp_args->sp_speed;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETSPEED)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETSCALE
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETSCALE(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETSCALE 
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_scale;
				} *sp_args = (struct sp_command_SETSCALE*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_scale		= sp_args->sp_scale;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETSCALE)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETCOLOUR
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETCOLOUR(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETCOLOUR 
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_colour;
				} *sp_args = (struct sp_command_SETCOLOUR*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_base_colour.r	= (sp_args->sp_colour & 0xff0000)>>16;
	sp_sprite->sc_base_colour.g	= (sp_args->sp_colour & 0x00ff00)>>8;
	sp_sprite->sc_base_colour.b	= (sp_args->sp_colour & 0x0000ff)>>0;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETCOLOUR)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETOTOFFSET
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETOTOFFSET(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETOTOFFSET 
				{
				MR_ULONG			sp_opcode;
				MR_LONG				sp_offset;
				} *sp_args = (struct sp_command_SETOTOFFSET*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_ot_offset = (MR_SHORT)sp_args->sp_offset;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETOTOFFSET)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}

//---------------------------------------------------------------------------------------------
// MR_SPRT_SETMASTERPOS
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETMASTERPOS(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETMASTERPOS
				{
				MR_ULONG			sp_opcode;
				MR_LONG				sp_x_offset;
				MR_LONG				sp_y_offset;
				} *sp_args = (struct sp_command_SETMASTERPOS*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	((MR_2DSPRITE*)(sp_sprite))->sp_pos.x = (MR_SHORT)sp_args->sp_x_offset;
	((MR_2DSPRITE*)(sp_sprite))->sp_pos.y = (MR_SHORT)sp_args->sp_y_offset;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETMASTERPOS)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}

//---------------------------------------------------------------------------------------------
// MR_SPRT_SETFLAGS
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETFLAGS(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETFLAGS
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_flags;
				} *sp_args = (struct sp_command_SETFLAGS*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_flags	  |= sp_args->sp_flags;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_SETFLAGS)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_CLRFLAGS
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeCLRFLAGS(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_CLRFLAGS
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_flags;
				} *sp_args = (struct sp_command_CLRFLAGS*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_flags	  &= ~sp_args->sp_flags;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_CLRFLAGS)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_ENTERCRITICAL
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeENTERCRITICAL(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_ENTERCRITICAL
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_ENTERCRITICAL*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_flags	  |= MR_SPF_IN_CRITICAL;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_ENTERCRITICAL)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_EXITCRITICAL
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeEXITCRITICAL(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_EXITCRITICAL
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_EXITCRITICAL*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_flags	  &= ~MR_SPF_IN_CRITICAL;

	sp_sprite->sc_alist_pc += (sizeof(struct sp_command_EXITCRITICAL)/sizeof(MR_ULONG));

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_SETCOUNT
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeSETCOUNT(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_SETCOUNT 
				{
				MR_ULONG			sp_opcode;
				MR_ULONG			sp_count;
				} *sp_args = (struct sp_command_SETCOUNT*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_alist_loop_count = (MR_SHORT)(sp_args->sp_count - 1);

	sp_sprite->sc_alist_pc 			+= (sizeof(struct sp_command_SETCOUNT)/sizeof(MR_ULONG));

	sp_sprite->sc_alist_loop_pc	 = sp_sprite->sc_alist_pc;

	return (MR_SPALIST_CONTINUE);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_LOOPBACK
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeLOOPBACK(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_LOOPBACK 
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_LOOPBACK*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	// If count is -1 at this point, we're in an infinite loop
	// If it's zero, we've finished the loop
	// If it's none of these, we're in the normal loop

	if (sp_sprite->sc_alist_loop_count < 0)
		{
		sp_sprite->sc_alist_pc = sp_sprite->sc_alist_loop_pc;
		}
	else
	if (sp_sprite->sc_alist_loop_count != 0)
		{
		sp_sprite->sc_alist_loop_count--;
		sp_sprite->sc_alist_pc = sp_sprite->sc_alist_loop_pc;
		}
	else
		{
		sp_sprite->sc_alist_pc += (sizeof(struct sp_command_LOOPBACK)/sizeof(MR_ULONG));
		}

	return (MR_SPALIST_CONTINUE);

}


//---------------------------------------------------------------------------------------------
// MR_SPRT_RESTART
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeRESTART(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_RESTART 
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_RESTART*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_alist_pc		= NULL;

	return (MR_SPALIST_CONTINUE);

}


//---------------------------------------------------------------------------------------------
// MR_SPRT_HALT
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeHALT(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_HALT 
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_HALT*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	sp_sprite->sc_alist_speed = MR_SPALIST_BIG_SPEED;

	// No PC increment, as we stay here forever
	return (MR_SPALIST_STOP);
}


//---------------------------------------------------------------------------------------------
// MR_SPRT_KILL
//---------------------------------------------------------------------------------------------

MR_BOOL	MRSprtCodeKILL(MR_SP_CORE* sp_sprite)
{
	struct	sp_command_KILL
				{
				MR_ULONG			sp_opcode;
				};// *sp_args = (struct sp_command_KILL*)(sp_sprite->sc_alist_addr+sp_sprite->sc_alist_pc);

	// This kill mechanism needs some testing
	if (sp_sprite->sc_flags & MR_SPF_SPRITE_IS_2D)
		MRKill2DSprite((MR_2DSPRITE*)sp_sprite);
	else
		(((MR_3DSPRITE*)sp_sprite)->sp_object)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// No PC increment, as we stay here forever
	return (MR_SPALIST_STOP);
}


/******************************************************************************
*%%%% MRCreateMemfixedWithInsts3DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_OBJECT*	object =	MRCreateMemfixedWithInsts3DSprite
*										MR_FRAME*		frame,
*										MR_ULONG		obj_flags,
*										MR_VOID*		image_alist,
*										MR_VIEWPORT**	viewports);
*
*	FUNCTION	Calls MRCreate3DSprite with MR_OBJ_MEMFIXED, then instances it
*				in the viewports (object and instances are all in one fixed
*				memory slot)
*
*	INPUTS		frame		-	ptr to a valid MR_FRAME structure
*								from which the world position is copied, or
*								a pointer to a static matrix.
*				obj_flags	-	flags to be used when creating the sprite
*								object. Typically NULL, or MR_OBJ_STATIC if
*								the sprite is linked to a static matrix, 
*								which is pointed to by frame.
*				image_alist	-	ptr to an animlist, or a sprite, or NULL
*				viewports	-	ptr to NULL-terminated list of viewports to
*								instance into
*
*	RESULT		object		-	ptr to the returned MR_OBJECT structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef MR_MEMFIXED_3DSPRITE
MR_OBJECT*	MRCreateMemfixedWithInsts3DSprite(	MR_FRAME*		frame,
												MR_ULONG		obj_flags,
												MR_VOID*		image_alist,
												MR_VIEWPORT**	viewports)
{
	MR_OBJECT*			object;
	MR_3DSPRITE_INST*	spriteinst_ptr;
	MR_3DSPRITE_INST*	spriteinst_root_ptr;
	MR_VIEWPORT**		vp_pptr;
	MR_VIEWPORT*		vp;


	MR_ASSERT(frame);
	MR_ASSERT(viewports);
	
	// Create object from fixed memory
	object 			= MRCreate3DSprite(frame, obj_flags | MR_OBJ_MEMFIXED | MR_OBJ_MEMFIXED_WITH_INSTS, image_alist);

	// Set up instances and link them into viewports
	spriteinst_ptr	= (MR_3DSPRITE_INST*)(((MR_UBYTE*)object) + MRMemfixed_3dsprite->mm_obj_size);
	vp_pptr			= viewports;
	while(vp = *vp_pptr++)
		{
		spriteinst_ptr->si_image_buf[0] = NULL;
		spriteinst_ptr->si_image_buf[1] = NULL;

		spriteinst_root_ptr = vp->vp_3dsprite_root_ptr;
		if (spriteinst_ptr->si_next_node = spriteinst_root_ptr->si_next_node)
			spriteinst_root_ptr->si_next_node->si_prev_node = spriteinst_ptr;
	
		spriteinst_root_ptr->si_next_node 	= spriteinst_ptr;
		spriteinst_ptr->si_prev_node 		= spriteinst_root_ptr;
		spriteinst_ptr->si_object	 		= object;
		spriteinst_ptr->si_kill_timer 		= 0;
		spriteinst_ptr->si_light_flags		= NULL;
		object->ob_vp_inst_count++;

		spriteinst_ptr	= (MR_3DSPRITE_INST*)(((MR_UBYTE*)spriteinst_ptr) + MRMemfixed_3dsprite->mm_inst_size);
		}

	return(object);
}
#endif
























																				
