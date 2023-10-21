/******************************************************************************
*%%%% particle.c
*------------------------------------------------------------------------------
*
*	Particle effects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	10.09.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "particle.h"
#include "project.h"
#include "main.h"
#include "sprdata.h"
#include "gamesys.h"
#include "frog.h"
#include "effects.h"
#include "ent_for.h"
#include "misc.h"

#ifdef WIN95
#pragma warning (disable : 4245)
#endif

//----------------------------------------
// Particle generators
//----------------------------------------

MR_PGEN_INIT	PGIN_for_swarm =
		{
		MR_PTYPE_2D,								
		MR_PF_NO_GEOMETRY,						// Allocate no geometry
		sizeof(POLY_FT4),
		NULL,
		For_swarm_prim_init,					// Initialisation routine (primitives)
		Particle_no_geometry_move,				// Update routine
		For_swarm_disp,							// Display routine
		NULL,									// Gravity (16:16)
		FOR_NUM_SWARM_SPRITES,					// Max particles
		-1,										// Generator lifetime (-1 => Infinite)
		NULL,									// Min lifetime - LIFETIME NEVER DECREASED
		NULL,									// Max lifetime - LIFETIME NEVER DECREASED
		NULL,									// 
		(MR_ULONG)&im_for_swarm,				//
		};

MR_PGEN_INIT	PGIN_for_swarm_multiplayer =
		{
		MR_PTYPE_2D,								
		MR_PF_NO_GEOMETRY,						// Allocate no geometry
		sizeof(POLY_FT4),
		NULL,
		For_swarm_prim_init,					// Initialisation routine (primitives)
		Particle_no_geometry_move,				// Update routine
		For_swarm_disp,							// Display routine
		NULL,									// Gravity (16:16)
		FOR_NUM_SWARM_SPRITES_MULTIPLAYER,		// Max particles
		-1,										// Generator lifetime (-1 => Infinite)
		NULL,									// Min lifetime - LIFETIME NEVER DECREASED
		NULL,									// Max lifetime - LIFETIME NEVER DECREASED
		NULL,									// 
		(MR_ULONG)&im_for_swarm,				//
		};

MR_PGEN_INIT	PGIN_pickup =
		{
		MR_PTYPE_2D,								
		NULL,
		sizeof(POLY_FT4),
		NULL,
		Pickup_prim_init,						// Prim initialisation
		Pickup_move,
		Pickup_disp,							// Display routine
		NULL,									// Gravity (16:16)
		2,										// Max particles
		-1,										// Generator lifetime (-1 => Infinite)
		NULL,									// Min lifetime - LIFETIME NEVER DECREASED
		NULL,									// Max lifetime - LIFETIME NEVER DECREASED
		NULL,									// written as ptr to (colour then scale then) NULL terminated image list
		NULL,									//
		};


MR_PGEN_INIT	PGIN_pickup_explosion =	
		{
		MR_PTYPE_2D,								
		MR_PF_NO_GEOMETRY,						// Allocate no geometry
		sizeof(POLY_G4),
		NULL,
		Frog_pop_explosion_prim_init,				// Prim initialisation
		Particle_no_geometry_move,				// Update routine
		Pickup_explosion_disp,					// Display routine
		NULL,									// Gravity (16:16)
		8 + 2,									// Max particles
		PICKUP_EXPLOSION_DURATION,				// Generator lifetime
		NULL,									// Min lifetime
		NULL,									// Max lifetime
		(48 << 7),				  				// User Data 1 (scale value)
		NULL,									// User Data 2
		};

MR_PGEN_INIT	PGIN_frog_pop_explosion =	
		{
		MR_PTYPE_2D,								
		MR_PF_NO_GEOMETRY,						// Allocate no geometry
		sizeof(POLY_G4),
		NULL,
		Frog_pop_explosion_prim_init,			// Prim initialisation
		Particle_no_geometry_move,				// Update routine
		Frog_pop_explosion_disp,				// Display routine
		NULL,									// Gravity (16:16)
		8 + 2,									// Max particles
		FROG_POP_EXPLOSION_DURATION,			// Generator lifetime
		NULL,									// Min lifetime
		NULL,									// Max lifetime
		(48 << 7),				  				// User Data 1 (scale value)
		NULL,									// User Data 2
		};


MR_PGEN_INIT	PGIN_hilite_exhaust =
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		Hilite_exhaust_move,					// Update routine
		Hilite_exhaust_disp,					// Display routine
		-(1 << 16),								// Gravity (16:16)
		25,										// Max particles at any time
		-1,										// Generator lifetime (-1 => Infinite)
		5, 										// Min lifetime
		8,										// Max lifetime
		(64 << 9),								// User Data 1 (scale value)
		(MR_ULONG)&im_tongue_tip,				// User Data 2 (image)
		};



MR_TEXTURE*	Hilite_dust_textures[] =
	{
	&im_bison1,
	&im_bison2,
	&im_bison3,
	&im_bison4,
	&im_bison5,
	&im_bison6,
	NULL,
	};

MR_PGEN_INIT	PGIN_hilite_dust =
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_list_init,			// Initialisation routine (primitives)
		Hilite_exhaust_move,					// Update routine
		Hilite_dust_disp,						// Display routine
		-(1 << 16),								// Gravity (16:16)
		14,										// Max particles at any time
		-1,										// Generator lifetime (-1 => Infinite)
		12, 									// Min lifetime
		12,										// Max lifetime
		(64 << 11),								// User Data 1 (scale value)
		(MR_ULONG)&Hilite_dust_textures,		// User Data 2 (image's)
		};


MR_PGEN_INIT	PGIN_hilite_fire =
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		Hilite_fire_move,						// Update routine
		Hilite_fire_disp,						// Display routine
		-(1 << 16),								// Gravity (16:16)
		50,										// Max particles at any time
		-1,										// Generator lifetime (-1 => Infinite)
		15, 									// Min lifetime
		25,										// Max lifetime
		(80 << 10),								// User Data 1 (scale value)
		(MR_ULONG)&im_frog_smoke1,				// User Data 2 (image)
		};

// Frog pop explosion colours
MR_ULONG	Frog_pop_explosion_colours[] =
	{
	0x000400,	// GREEN
	0x040004,	// MAGENTA
	0x000404,	// YELLOW
	0x040400,	// CYAN
	0x000104,	// PINK - for baby frog explosion
	};	

//----------------------------------------
// Effect offsets
//----------------------------------------

MR_SVEC	Explosion_offsets_octagon[] =
	{
		// Outer
		{ 0x0000,	-0x1000,	0},
		{ 0x0b50,	-0x0b50,	0},
		{ 0x1000,	 0x0000,	0},
		{ 0x0b50,	 0x0b50,	0},
		{ 0x0000,	 0x1000,	0},
		{-0x0b50,	 0x0b50,	0},
		{-0x1000,	 0x0000,	0},
		{-0x0b50,	-0x0b50,	0},

		// Inner
		{ 0x0000,	-0x0800,	0},
		{ 0x05a8,	-0x05a8,	0},
		{ 0x0800, 	 0x0000,	0},
		{ 0x05a8,	 0x05a8,	0},
		{ 0x0000,	 0x0800,	0},
		{-0x05a8,	 0x05a8,	0},
		{-0x0800,	 0x0000,	0},
		{-0x05a8,	-0x05a8,	0},
	};

MR_SVEC	Shield_offsets_octagon[] =
	{
		// Outer
		{ 0x0000,	-0x1000,	0},
		{ 0x0b50,	-0x0b50,	0},
		{ 0x1000,	 0x0000,	0},
		{ 0x0b50,	 0x0b50,	0},
		{ 0x0000,	 0x1000,	0},
		{-0x0b50,	 0x0b50,	0},
		{-0x1000,	 0x0000,	0},
		{-0x0b50,	-0x0b50,	0},

		// Middle
		{ 0x0000,	-0x0c00,	0},
		{ 0x087c,	-0x087c,	0},
		{ 0x0c00,	 0x0000,	0},
		{ 0x087c,	 0x087c,	0},
		{ 0x0000,	 0x0c00,	0},
		{-0x087c,	 0x087c,	0},
		{-0x0c00,	 0x0000,	0},
		{-0x087c,	-0x087c,	0},

		// Inner
		{ 0x0000,	-0x0800,	0},
		{ 0x05a8,	-0x05a8,	0},
		{ 0x0800, 	 0x0000,	0},
		{ 0x05a8,	 0x05a8,	0},
		{ 0x0000,	 0x0800,	0},
		{-0x05a8,	 0x05a8,	0},
		{-0x0800,	 0x0000,	0},
		{-0x05a8,	-0x05a8,	0},
	};

	
//----------------------------------------
// Other
//----------------------------------------

MR_SHORT	Explosion_poly_offsets_octagon[] =
	{
	1, 1, 1, 1, 1, 1, 1, -7, 
	1, 1, 1, 1, 1, 1, 1, 0
	};

MR_MAT		Explosion_matrix = 
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, SYSTEM_PERSPECTIVE},
	};

MR_ULONG	Shield_vertex_rgbs[] =
	{
	0x0000e0,
	0x0010d0,
	0x0020c0,
	0x0030b0,
	0x0040a0,
	0x005090,
	0x006080,
	0x007070,
	0x007070,
	0x008060,
	0x009050,
	0x00a040,
	0x00b030,
	0x00c020,
	0x00d010,
	0x00e000,

	0x00e000,
	0x10d000,
	0x20c000,
	0x30b000,
	0x40a000,
	0x509000,
	0x608000,
	0x707000,
	0x707000,
	0x806000,
	0x905000,
	0xa04000,
	0xb03000,
	0xc02000,
	0xd01000,
	0xe00000,

	0xe00000,
	0xd00010,
	0xc00020,
	0xb00030,
	0xa00040,
	0x900050,
	0x800060,
	0x700070,
	0x700070,
	0x600080,
	0x500090,
	0x4000a0,
	0x3000b0,
	0x2000c0,
	0x1000d0,
	0x0000e0,
	};

MR_PGEN_INIT	PGIN_frog_slip_effect =	
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		FrogEffectSlippingMove,					// Update routine
		FrogEffectSlippingDisp,					// Display routine
		-(1 << 16),								// Gravity (16:16)
		50,										// Max particles at any time
		-1,										// Generator lifetime (-1 => Infinite)
		6, 										// Min lifetime
		12,										// Max lifetime
		(96 << 10),								// User Data 1 (scale value)
		(MR_ULONG)&im_frog_smoke1,				// User Data 2 (image)
		};

MR_PGEN_INIT	PGIN_frog_water_bubble =	
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		FrogEffectBubbleMove,					// Update routine
		FrogEffectSlippingDisp,					// Display routine
		-(1 << 16),								// Gravity (16:16)
		20,										// Max particles at any time
		90,										// Generator lifetime (-1 => Infinite)
		12, 									// Min lifetime
		12,										// Max lifetime
		(64 << 9),								// User Data 1 (scale value)
		(MR_ULONG)&im_wake2,					// User Data 2 (image)
		};

extern	MR_VOID	FrogEffectFireDisp(MR_PGEN_INST*, MR_VIEWPORT*);

MR_PGEN_INIT	PGIN_frog_on_fire =	
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		FrogEffectFireMove,						// Update routine
		FrogEffectFireDisp,						// Display routine
		-(1 << 16),								// Gravity (16:16)
		150,									// Max particles at any time
		-1,										// Generator lifetime (-1 => Infinite)
		40, 									// Min lifetime
		50,										// Max lifetime
		(120 << 9),								// User Data 1 (scale value)
		(MR_ULONG)&im_frog_smoke1,				// User Data 2 (image)
		};


FROG_PARTICLE	Frog_particle_effects[] = 
	{
		{
		//FROG_PARTICLE_SLIDE
		EFFECT_KILL_WHEN_FROG_DEAD|EFFECT_KILL_WHEN_FROG_RESET,
		&PGIN_frog_slip_effect,
		&PGIN_frog_slip_effect,
		},
		{
		//FROG_PARTICLE_WATER_BUBBLE
		EFFECT_KILL_WHEN_FROG_RESET,
		&PGIN_frog_water_bubble,
		NULL,
		},
		{
		//FROG_PARTICLE_ON_FIRE
		EFFECT_KILL_WHEN_FROG_RESET,
		&PGIN_frog_on_fire,
		NULL,
		},
	};

MR_PGEN_INIT	PGIN_stone_to_gold_frog =	
		{
		MR_PTYPE_2D,							// It's firing sprites!
		NULL,									// No flags
		sizeof(POLY_FT4),
		NULL,
		Particle_ft4_prim_init,					// Initialisation routine (primitives)
		Gold_frog_particle_move,				// Update routine
		FrogEffectSlippingDisp,					// Display routine
		-(1 << 16),								// Gravity (16:16)
		100,									// Max particles at any time
		30,										// Generator lifetime (-1 => Infinite)
		15, 									// Min lifetime
		20,										// Max lifetime
		(64 << 9),								// User Data 1 (scale value)
		(MR_ULONG)&im_frog_smoke1,				// User Data 2 (image)
		};

MR_PGEN_INIT	PGIN_gold_frog_glow =
		{
		MR_PTYPE_2D,								
		NULL,
		sizeof(POLY_FT4),
		NULL,
		Gold_frog_glow_prim_init,				// Prim initialisation
		Gold_frog_glow_move,
		Gold_frog_glow_disp,					// Display routine
		NULL,									// Gravity (16:16)
		1,										// Max particles
		-1,										// Generator lifetime (-1 => Infinite)
		NULL,									// Min lifetime - LIFETIME NEVER DECREASED
		NULL,									// Max lifetime - LIFETIME NEVER DECREASED
		NULL,									// written as ptr to (colour then scale then) NULL terminated image list
		NULL,									//
		};

//------------------------------------------------------------------------------------------------
MR_VOID	Pickup_prim_init(MR_PGEN_INST* pgeninst)
{
	MR_PGEN*		pgen		= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	POLY_FT4*		poly_ptr_0 	= (POLY_FT4*)pgeninst->pi_particle_prims[0]; 
	MR_LONG	 		loop		= 2;
	MR_TEXTURE*		image_ptr;


	image_ptr = &im_tongue_tip;
 	while(loop--)
		{
		// Glow
		MR_SET32(poly_ptr_0->r0, ((MR_ULONG*)pgen->pg_user_data_1)[0]);
		setPolyFT4(poly_ptr_0);
		setSemiTrans(poly_ptr_0, 1);
#ifdef PSX
		MR_COPY32(poly_ptr_0->u0, image_ptr->te_u0);	// Copies te_tpage_id too
		MR_COPY32(poly_ptr_0->u1, image_ptr->te_u1);	// Copies te_clut_id too
#else
		MR_COPY16(poly_ptr_0->u0, image_ptr->te_u0);
		MR_COPY16(poly_ptr_0->u1, image_ptr->te_u1);
		poly_ptr_0->tpage	= image_ptr->te_tpage_id;
		poly_ptr_0->a0		= 0x80;
#endif
		MR_COPY16(poly_ptr_0->u2, image_ptr->te_u2);
		MR_COPY16(poly_ptr_0->u3, image_ptr->te_u3);

		catPrim(poly_ptr_0, poly_ptr_0 + 1);
		poly_ptr_0++;

		// Image
		MR_SET32(poly_ptr_0->r0, 0x808080);
		setPolyFT4(poly_ptr_0);
		poly_ptr_0++;
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Pickup_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;

		 
	pgen 		= object->ob_extra.ob_extra_pgen;
	geom_ptr	= pgen->pg_particle_info;

	if (!(Game_timer & 0x1))
		{
		// Increase pickup image animlist
		geom_ptr->pt_lifetime++;
		if (((MR_TEXTURE**)pgen->pg_user_data_1)[geom_ptr->pt_lifetime + 2] == NULL)
			{
			// End of animlist: restart
			geom_ptr->pt_lifetime = 0;
			}
		}

	geom_ptr++;

	// Increase counter for glow pulsing
	geom_ptr->pt_lifetime = (geom_ptr->pt_lifetime + 0x100) & 0xfff;
}
//------------------------------------------------------------------------------------------------
MR_VOID	Pickup_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_TEXTURE*			glow_texture;
	MR_TEXTURE*			image_texture;
	MR_LONG				glow_mag;
	MR_XY				sxy;
	MR_SHORT			xofs;
	MR_SHORT			yofs;
	MR_LONG				otz, shift;
	MR_MAT*				lwtrans;
		 

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	// Don't display anything if no active parts
	if (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS)
		return;

	// Loop through the particle list, performing geometry updates and updating/adding the 
	// primitives (first set the relevant rot/trans matrices.
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];

	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	poly_ptr 		= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	glow_texture	= &im_tongue_tip;

	geom_ptr 		= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	image_texture	= ((MR_TEXTURE**)pgen->pg_user_data_1)[geom_ptr->pt_lifetime + 2];
	geom_ptr++;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
		lwtrans = (MR_MAT*)pgeninst->pi_object->ob_frame;
	else
		lwtrans = &pgeninst->pi_object->ob_frame->fr_lw_transform;

	// Loop through all active particles for this generator
	MR_SVEC_EQUALS_VEC(&svec, (MR_VEC*)lwtrans->t);
	gte_ldv0(&svec);
	gte_rtps();
	gte_stsz(&otz);

	otz >>= MRVp_otz_shift;
	otz += PICKUP_OT_OFFSET;
	
	if ((otz > 0) && (otz < MRVp_ot_size))	
		{
#ifndef BUILD_49
		// Glow
		gte_stsxy(&sxy);
		
		// Only try to render if abs(y) < 768
		if (abs(sxy.y) < 0x300)
			{
#endif
			// If half size viewports, halve size of sprites
			if (Game_total_viewports > 2)
				shift = 9;
			else
				shift = 8;
#ifdef BUILD_49
			// Glow
			gte_stsxy(&sxy);
#endif
			glow_mag 	= (rsin(geom_ptr->pt_lifetime) + 0x3800) << 3;
			xofs 		= ((glow_texture->te_w * glow_mag) / otz) >> shift;
			yofs 		= ((glow_texture->te_h * glow_mag) / otz) >> shift;
			poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
			poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
			poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
			poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;
	
			addPrims(MRVp_work_ot + otz, poly_ptr, poly_ptr + 1);
			poly_ptr++;
	
			// Image
			xofs = ((image_texture->te_w * ((MR_ULONG*)pgen->pg_user_data_1)[1]) / otz) >> shift;
			yofs = ((image_texture->te_h * ((MR_ULONG*)pgen->pg_user_data_1)[1]) / otz) >> shift;
			poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
			poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
			poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
			poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;
	
#ifdef PSX
			MR_COPY32(poly_ptr->u0, image_texture->te_u0);	// Copies te_tpage_id too
			MR_COPY32(poly_ptr->u1, image_texture->te_u1);	// Copies te_clut_id too
#else
			MR_COPY16(poly_ptr->u0, image_texture->te_u0);
			MR_COPY16(poly_ptr->u1, image_texture->te_u1);
			poly_ptr->tpage = image_texture->te_tpage_id;
#endif
			MR_COPY16(poly_ptr->u2, image_texture->te_u2);
			MR_COPY16(poly_ptr->u3, image_texture->te_u3);
#ifndef BUILD_49
			}
#endif
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Particle_ft4_prim_init(MR_PGEN_INST* pgeninst)
{
	MR_PGEN*		pgen		= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	MR_LONG			loop		= pgen->pg_max_particles * 2;
	POLY_FT4*		poly_ptr_0 	= (POLY_FT4*)pgeninst->pi_particle_prims[0]; 
	MR_TEXTURE*		image_ptr 	= (MR_TEXTURE*)pgen->pg_user_data_2;


 	while(loop--)
		{
		setPolyFT4(poly_ptr_0);
		setSemiTrans(poly_ptr_0, 1);

#ifdef PSX
		MR_COPY32(poly_ptr_0->u0, image_ptr->te_u0);	// Copies te_tpage_id too
		MR_COPY32(poly_ptr_0->u1, image_ptr->te_u1);	// Copies te_clut_id too
#else
		MR_COPY16(poly_ptr_0->u0, image_ptr->te_u0);
		MR_COPY16(poly_ptr_0->u1, image_ptr->te_u1);
		poly_ptr_0->tpage = image_ptr->te_tpage_id;
#endif
		MR_COPY16(poly_ptr_0->u2, image_ptr->te_u2);
		MR_COPY16(poly_ptr_0->u3, image_ptr->te_u3);
		poly_ptr_0++;
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	Particle_ft4_prim_list_init(MR_PGEN_INST* pgeninst)
{
	MR_PGEN*		pgen		= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	MR_LONG			loop		= pgen->pg_max_particles * 2;
	POLY_FT4*		poly_ptr_0 	= (POLY_FT4*)pgeninst->pi_particle_prims[0]; 
	MR_TEXTURE*		image_ptr	= (MR_TEXTURE*)*(MR_LONG*)pgen->pg_user_data_2;

 	while(loop--)
		{
		setPolyFT4(poly_ptr_0);
		setSemiTrans(poly_ptr_0, 1);

#ifdef PSX
		MR_COPY32(poly_ptr_0->u0, image_ptr->te_u0);	// Copies te_tpage_id too
		MR_COPY32(poly_ptr_0->u1, image_ptr->te_u1);	// Copies te_clut_id too
#else
		MR_COPY16(poly_ptr_0->u0, image_ptr->te_u0);
		MR_COPY16(poly_ptr_0->u1, image_ptr->te_u1);
		poly_ptr_0->tpage = image_ptr->te_tpage_id;
#endif
		MR_COPY16(poly_ptr_0->u2, image_ptr->te_u2);
		MR_COPY16(poly_ptr_0->u3, image_ptr->te_u3);
		poly_ptr_0++;
		}
}


//------------------------------------------------------------------------------------------------
MR_VOID	Particle_2D_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen		= object->ob_extra.ob_extra_pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	MR_LONG				loop		= pgen->pg_max_particles;
		 

	// No processing if inactive
	if (pgen->pg_flags & MR_PF_INACTIVE)
		{
		pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;
		return;
		}

	// Clear no active parts flag
	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;
			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of point within the world (and velocity with gravity value)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;		
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;		
			geom_ptr->pt_velocity.vy += pgen->pg_gravity;
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;		
			}
		geom_ptr++;	
		}

	// Deal with generator lifetime
	if (pgen->pg_generator_life > 0)
		{
		if (!(--pgen->pg_generator_life))
			{
			// Generator run out of life - put it into a state where it will kill itself (by
			// flagging the object as MR_OBJ_DESTROY_BY_DISPLAY) only when all associated particles
			// are no longer active
			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
			}
		}
	else
	if ((pgen->pg_generator_life == 0) && (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS))
		{
		// All instances of this MR_PGEN will be killed - only then will the MR_PGEN be killed
		object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	Particle_no_geometry_move(MR_OBJECT* object)
{
	MR_PGEN*	pgen;

		 
	pgen = object->ob_extra.ob_extra_pgen;

	// Deal with generator lifetime
	if (pgen->pg_generator_life > 0)
		{
		if (!(--pgen->pg_generator_life))
			{
			object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
			}
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	Frog_pop_explosion_prim_init(MR_PGEN_INST* pgeninst)
{
	POLY_G4*	poly_ptr;
	MR_LONG		i, loop;

	// Note: this is a complete bodge.  We have allocated room for 10 POLY_G4, because we want to
	// overwrite the first two (in each buffer) with a POLY_FT3 abr changer

	poly_ptr = (POLY_G4*)pgeninst->pi_particle_prims[0]; 
	for (i = 0; i < 2; i++)
		{
		SetupABRChangeFT3(poly_ptr, 1);
		poly_ptr += 2;
		catPrim(poly_ptr - 2, poly_ptr);

		loop = 8;
		while(loop--)
			{
			setPolyG4(poly_ptr);
			setRGB0(poly_ptr, 0x80, 0x80, 0x80);
			setRGB1(poly_ptr, 0x80, 0x80, 0x80);
			setRGB2(poly_ptr, 0x00, 0x00, 0x00);
			setRGB3(poly_ptr, 0x00, 0x00, 0x00);
			setSemiTrans(poly_ptr, 1);
			poly_ptr++;

			if (loop)
				catPrim(poly_ptr - 1, poly_ptr);
			}
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	Pickup_explosion_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
#ifdef PSX
	// This code needs un-optimising to work on the PC!
	MR_SVEC		svec;
	MR_VEC		vec;
	MR_PGEN*	pgen;
	POLY_G4*	poly_ptr0;
	POLY_G4*	poly_ptr1;
	MR_XY		sxy;
	MR_LONG		otz;
	MR_SHORT	i, j;
	MR_ULONG	rgb;
	MR_SVEC*	offset;
	MR_ULONG*	rgb_ptr;
	MR_ULONG*	xy_ptr;


	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	// Don't display anything if generator has died
	if (!pgen->pg_generator_life)
		return;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
		MRWorldtrans_ptr = (MR_MAT*)pgeninst->pi_object->ob_frame;
	else
		MRWorldtrans_ptr = &pgeninst->pi_object->ob_frame->fr_lw_transform;

	MRApplyMatrix(MRWorldtrans_ptr, &pgeninst->pi_object->ob_offset, &vec);
	svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] + (MR_SHORT)vec.vx - (MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] + (MR_SHORT)vec.vy - (MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] + (MR_SHORT)vec.vz - (MR_SHORT)viewport->vp_render_matrix.t[2];
	
	// Set up GTE matrix and offset
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	// Loop through all active particles for this generator
	gte_ldv0(&Null_svector);
	gte_rtps();
	gte_stsz(&otz);

	otz >>= MRVp_otz_shift;

	if ((otz > 0) && (otz < MRVp_ot_size))	
		{					
		otz = MAX(0, otz + PICKUP_EXPLOSION_OT_OFFSET);

		// Store screen coord of origin of octagon
		gte_stsxy(&sxy);			
		gte_SetGeomOffset(sxy.x, sxy.y);

		rgb	= (pgen->pg_generator_life * 0x080808) + 0x3a000000;	// semiTrans POLY_G4 code

		// Rotation and scaling
		i 	= (4 + PICKUP_EXPLOSION_DURATION - pgen->pg_generator_life) << 1;
		Explosion_matrix.m[0][0] =  i;
		Explosion_matrix.m[0][1] =  0;
		Explosion_matrix.m[1][0] =  0;
		Explosion_matrix.m[1][1] =  i;
		gte_SetRotMatrix(&Explosion_matrix);
		gte_SetTransMatrix(&Explosion_matrix);

		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
		j 			= 5;
		offset 		= Explosion_offsets_octagon;
		xy_ptr		= (MR_ULONG*)&poly_ptr0->x0;
		rgb_ptr		= (MR_ULONG*)&poly_ptr0->r0;

		while(j--)
			{
			gte_ldv3(offset + 0, offset + 1, offset + 2);
			gte_rtpt();												// use GTE delay slots here...
			offset += 3;
			*rgb_ptr	= rgb;
			rgb_ptr 	+= (sizeof(POLY_G4) >> 2);
			*rgb_ptr	= rgb;
			if (j == 2)
				{
				rgb_ptr -= 7 * (sizeof(POLY_G4) >> 2);		// move from poly7->rgb0 to poly0->rgb1
				rgb_ptr += 2;
				}
			else
				rgb_ptr 	+= (sizeof(POLY_G4) >> 2);

			*rgb_ptr	= rgb;
			rgb_ptr 	+= (sizeof(POLY_G4) >> 2);

			gte_stsxy0(xy_ptr);
			xy_ptr += (sizeof(POLY_G4) >> 2);
			gte_stsxy1(xy_ptr);
			if (j == 2)
				{
				xy_ptr -= 7 * (sizeof(POLY_G4) >> 2);		// move from poly7->x0 to poly0->x2
				xy_ptr += 4;
				}
			else
				xy_ptr += (sizeof(POLY_G4) >> 2);

			gte_stsxy2(xy_ptr);
			xy_ptr += (sizeof(POLY_G4) >> 2);
			}

		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 9;
		gte_ldv0(&Explosion_offsets_octagon[15]);
		gte_rtps();
		gte_stsxy(&poly_ptr0->x2);
		MR_SET32(poly_ptr0->r1, rgb);

		poly_ptr1 = ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
		MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
		MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);
		poly_ptr1 += 7;
		i = 7;
		while(i--)
			{
			poly_ptr0--;
			MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
			MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);
			poly_ptr1--;
			}
		
		// All 8 POLY_G4 and the abr changer are catted in one list
		addPrims(MRVp_work_ot + otz, poly_ptr0 - 2, poly_ptr0 + 7);
		}
	gte_SetGeomOffset(viewport->vp_geom_x, viewport->vp_geom_y);
#endif
}


//------------------------------------------------------------------------------------------------
MR_VOID	Frog_pop_explosion_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
	MR_SVEC		svec;
	MR_PGEN*	pgen;
	POLY_G4*	poly_ptr0 ;
	POLY_G4*	poly_ptr1;
	MR_XY		sxy;
	MR_SHORT	i, j;
	MR_ULONG	rgb0;
	MR_ULONG	rgb2;
	MR_SVEC*	offset;
	MR_ULONG*	rgb_ptr;
	MR_ULONG*	xy_ptr;
	MR_LONG		cos, sin;


	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	// Don't display anything if generator has died
	if (!pgen->pg_generator_life)
		return;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
		MRWorldtrans_ptr = (MR_MAT*)pgeninst->pi_object->ob_frame;
	else
		MRWorldtrans_ptr = &pgeninst->pi_object->ob_frame->fr_lw_transform;

	svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] - (MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] - (MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] - (MR_SHORT)viewport->vp_render_matrix.t[2];
	
	// Set up GTE matrix and offset
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	// Loop through all active particles for this generator
	gte_ldv0(&Null_svector);
	gte_rtps();

	// Store screen coord of origin of octagon
	gte_stsxy(&sxy);			
	gte_SetGeomOffset(sxy.x, sxy.y);

	rgb0 = (pgen->pg_generator_life * 0x000008) + 0x3a000000;	// semiTrans POLY_G4 code
	rgb2 = (pgen->pg_generator_life * pgen->pg_user_data_2);

	// Rotation and scaling
	i 		= ((FROG_POP_EXPLOSION_DURATION - pgen->pg_generator_life) + 10) << 1;
	cos 	= (rcos(Game_timer << 7) * i) >> 12;
	sin 	= (rsin(Game_timer << 7) * i) >> 12;
	Explosion_matrix.m[0][0] =  cos;
	Explosion_matrix.m[0][1] = -sin;
	Explosion_matrix.m[1][0] =  sin;
	Explosion_matrix.m[1][1] =  cos;
	gte_SetRotMatrix(&Explosion_matrix);
	gte_SetTransMatrix(&Explosion_matrix);

	poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
	j 			= 5;
	offset 		= Explosion_offsets_octagon;
	xy_ptr		= (MR_ULONG*)&poly_ptr0->x0;
	rgb_ptr		= (MR_ULONG*)&poly_ptr0->r0;

#ifdef PSX
	while(j--)
		{
		gte_ldv3(offset + 0, offset + 1, offset + 2);
		gte_rtpt();												// use GTE delay slots here...
		offset += 3;
		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		rgb_ptr += (sizeof(POLY_G4) >> 2);
		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		if (j == 2)
			{
			rgb_ptr -= 7 * (sizeof(POLY_G4) >> 2);		// move from poly7->rgb0 to poly0->rgb1
			rgb_ptr += 2;
			}
		else
			rgb_ptr += (sizeof(POLY_G4) >> 2);

		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		rgb_ptr += (sizeof(POLY_G4) >> 2);

		gte_stsxy0(xy_ptr);
		xy_ptr += (sizeof(POLY_G4) >> 2);
		gte_stsxy1(xy_ptr);
		if (j == 2)
			{
			xy_ptr -= 7 * (sizeof(POLY_G4) >> 2);		// move from poly7->x0 to poly0->x2
			xy_ptr += 4;
			}
		else
			xy_ptr += (sizeof(POLY_G4) >> 2);

		gte_stsxy2(xy_ptr);
		xy_ptr += (sizeof(POLY_G4) >> 2);
		}
#else
	// windows version of above loop, $mk
	while(j--)
		{
		gte_ldv3(offset + 0, offset + 1, offset + 2);
		gte_rtpt();												// use GTE delay slots here...
		offset += 3;
		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		rgb_ptr += (sizeof(POLY_G4) >> 2);
		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		if (j == 2)
			{
			rgb_ptr -= (7 * (sizeof(POLY_G4) >> 2));		// move from poly7->rgb0 to poly0->rgb1
			rgb_ptr += 2;
			}
		else
			rgb_ptr += (sizeof(POLY_G4) >> 2);

		*(rgb_ptr + 0)	= rgb0;
		*(rgb_ptr + 4)	= rgb2;
		rgb_ptr += (sizeof(POLY_G4) >> 2);

		gte_stsxy0(xy_ptr);
		xy_ptr += (sizeof(POLY_G4) >> 2);
		gte_stsxy1(xy_ptr);
		if (j == 2)
			{
			xy_ptr -= (7 * (sizeof(POLY_G4) >> 2));		// move from poly7->x0 to poly0->x2
			xy_ptr += 4;
			}
		else
			xy_ptr += (sizeof(POLY_G4) >> 2);

		gte_stsxy2(xy_ptr);
		xy_ptr += (sizeof(POLY_G4) >> 2);
		}
#endif	// PSX
	poly_ptr0 = ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 9;
	gte_ldv0(&Explosion_offsets_octagon[15]);
	gte_rtps();
	gte_stsxy(&poly_ptr0->x2);
	MR_SET32(poly_ptr0->r1, rgb0);
	MR_SET32(poly_ptr0->r3, rgb2);

	poly_ptr1 = ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
	MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
	MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);

	poly_ptr1 += 7;
	i = 7;
	while(i--)
		{
		poly_ptr0--;
		MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
		MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);
		poly_ptr1--;
		}
	
	// All 8 POLY_G4 and the abr changer are catted in one list
	addPrims(MRVp_work_ot + FROG_POPPING_FIXED_OT, poly_ptr0 - 2, poly_ptr0 + 7);
	gte_SetGeomOffset(viewport->vp_geom_x, viewport->vp_geom_y);
}

//------------------------------------------------------------------------------------------------
MR_VOID	Player_shield_prim_init(MR_PGEN_INST* pgeninst)
{
	POLY_G4*	poly_ptr;
	MR_LONG		i, loop;


	poly_ptr = (POLY_G4*)pgeninst->pi_particle_prims[0]; 
	for (i = 0; i < 2; i++)
		{
		SetupABRChangeFT3(poly_ptr, 1);
		poly_ptr += 2;		
		catPrim(poly_ptr - 2, poly_ptr);

		loop = 16;
		while(loop--)
			{
			setPolyG4(poly_ptr);
			setRGB0(poly_ptr, 0, 0, 0);
			setRGB1(poly_ptr, 0, 0, 0);
			setSemiTrans(poly_ptr, 1);
			poly_ptr++;

			if (loop)
				catPrim(poly_ptr - 1, poly_ptr);
			}
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Player_shield_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
#ifdef PSX
	// This code needs un-optimising to work on the PC!
//	MR_SVEC			svec;
//	MR_VEC			vec;
//	MR_PGEN*		pgen;
//	POLY_G4*		poly_ptr0;
//	POLY_G4*		poly_ptr1;
//	MR_XY			sxy;
//	MR_LONG			otz;
//	MR_USHORT		i, j, loop, units, max_units;
//	MR_SVEC*		offset;
//	MR_ULONG*		rgb_ptr;
//	MR_ULONG*		xy_ptr;
//	PLANE*			plane;
//	PLAYER_DATA*	player;
//	MR_LONG			cos, sin;
//
//
//	pgen	= pgeninst->pi_object->ob_extra.ob_extra_pgen;
//	plane	= pgen->pg_owner;
//	player 	= plane->pl_player_data;
//
//	if (!(player->py_flags & PLAYER_SHIELD))
//		return;
//	
//	poly_ptr0 	= (POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]; 
//	loop		= pgen->pg_max_particles;
//
//	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
//		MRWorldtrans_ptr = (MR_MAT*)(pgeninst->pi_object->ob_frame);
//	else
//		MRWorldtrans_ptr = &pgeninst->pi_object->ob_frame->fr_lw_transform;
//
//	MRApplyMatrix(MRWorldtrans_ptr, &pgeninst->pi_object->ob_offset, &vec);
//	svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] + (MR_SHORT)vec.vx - (MR_SHORT)viewport->vp_render_matrix.t[0];
//	svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] + (MR_SHORT)vec.vy - (MR_SHORT)viewport->vp_render_matrix.t[1];
//	svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] + (MR_SHORT)vec.vz - (MR_SHORT)viewport->vp_render_matrix.t[2];
//	
//	// Set up GTE matrix and offset
//	gte_SetRotMatrix(&viewport->vp_render_matrix);
//	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
//	gte_SetTransMatrix(MRViewtrans_ptr);
//	
//	// Loop through all active particles for this generator
//	gte_ldv0(&Null_svector);
//	gte_rtps();
//	gte_stsz(&otz);
//
//	otz >>= MRVp_otz_shift;
//
//	if ((otz > 0) && (otz < MRVp_ot_size))	
//		{					
//		otz = MAX(0, otz + SHIELD_OT_OFFSET);
//
//		// Store screen coord of origin of octagon
//		gte_stsxy(&sxy);			
//		gte_SetGeomOffset(sxy.x, sxy.y);
//
//		units 		= plane->pl_weapon_units;
//		max_units	= Weapon_library[plane->pl_weapon].wb_units;
//
//		if (units < 16)
//			i = units;
//		else
//			i = MIN(16, (max_units - units));
//
//		cos = (rcos(Game_timer << 5) * i * 3) >> 12;
//		sin = (rsin(Game_timer << 5) * i * 3) >> 12;
//		Explosion_matrix.m[0][0] =  cos;
//		Explosion_matrix.m[0][1] = -sin;
//		Explosion_matrix.m[1][0] =  sin;
//		Explosion_matrix.m[1][1] =  cos;
//
//		gte_SetRotMatrix(&Explosion_matrix);
//		gte_SetTransMatrix(&Explosion_matrix);
//
//		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
//		j 				= 8;
//		i				= 0;
//		offset 		= Shield_offsets_octagon;
//		xy_ptr		= (MR_ULONG*)&poly_ptr0->x0;
//		rgb_ptr		= (MR_ULONG*)&poly_ptr0->r2;
//
//		while(j--)
//			{
//			gte_ldv3(offset + 0, offset + 1, offset + 2);
//			gte_rtpt();												// use GTE delay slots here...
//			offset += 3;
//
//			gte_stsxy0(xy_ptr);
//
//			if (j == 2)
//				{
//				xy_ptr += (sizeof(POLY_G4) >> 2);			// move from poly7->x2 to poly8->x0
//				xy_ptr -= 4;
//				}
//			else
//				xy_ptr += (sizeof(POLY_G4) >> 2);
//
//			gte_stsxy1(xy_ptr);
//
//			if (j == 5)
//				{
//				xy_ptr -= 7 * (sizeof(POLY_G4) >> 2);		// move from poly7->x0 to poly0->x2
//				xy_ptr += 4;
//				}
//			else
//				xy_ptr += (sizeof(POLY_G4) >> 2);
//
//			gte_stsxy2(xy_ptr);
//			xy_ptr += (sizeof(POLY_G4) >> 2);
//			}
//
//		poly_ptr1 	= poly_ptr0 + 1;
//		i 				= 7;
//		while(i--)
//			{
//			MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
//			MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);
//			poly_ptr0++;
//			poly_ptr1++;
//			}
//		poly_ptr1 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
//		MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
//		MR_COPY32(poly_ptr0->x3, poly_ptr1->x2);
//		poly_ptr0++;
//		i 				= 8;
//		while(i--)
//			{
//			MR_COPY32(poly_ptr0->x2, poly_ptr1->x2);
//			MR_COPY32(poly_ptr0->x3, poly_ptr1->x3);
//			poly_ptr0++;
//			poly_ptr1++;
//			}
//		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2 + 8;
//		poly_ptr1 	= poly_ptr0 + 1;
//		i 				= 7;
//		while(i--)
//			{
//			MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
//			poly_ptr0++;
//			poly_ptr1++;
//			}
//		poly_ptr1 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2 + 8;
//		MR_COPY32(poly_ptr0->x1, poly_ptr1->x0);
//		
//		// Write rgbs
//		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
//		for (i = 0; i < 8; i++)
//			{
//			MR_SET32(poly_ptr0->r2, Shield_vertex_rgbs[(((i + 0) * 6) + Game_timer) % 48] >> 1);
//			MR_SET32(poly_ptr0->r3, Shield_vertex_rgbs[(((i + 1) * 6) + Game_timer) % 48] >> 1);
//			MR_SET32(poly_ptr1->r2, Shield_vertex_rgbs[(((i + 0) * 6) + Game_timer) % 48] >> 1);
//			MR_SET32(poly_ptr1->r3, Shield_vertex_rgbs[(((i + 1) * 6) + Game_timer) % 48] >> 1);
//			poly_ptr0++;
//			poly_ptr1++;
//			}		
//
//		// All 16 POLY_G4 and the abr changer are catted in one list
//		poly_ptr0 	= ((POLY_G4*)pgeninst->pi_particle_prims[MRFrame_index]) + 2;
//		addPrims(MRVp_work_ot + otz, poly_ptr0 - 2, poly_ptr0 + 15);
//		}
//	gte_SetGeomOffset(viewport->vp_geom_x, viewport->vp_geom_y);
	#endif
}

//------------------------------------------------------------------------------------------------
MR_VOID	Hilite_exhaust_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_LONG				loop;
	MR_TEXTURE*			image_ptr;
	MR_LONG				xcalc;
	MR_LONG				ycalc;
	MR_XY				sxy;
	MR_SHORT			xofs;
	MR_SHORT			yofs;
	MR_LONG				otz;
	ENTITY*				entity;
	LIVE_ENTITY*		live_entity;
	MR_MESH_INST**		mesh_inst_pptr;
	MR_MESH_INST*		mesh_inst_ptr;
	ENTITY_SPECIAL*		entity_special;
	MR_LONG				r, g, b, life;
		 
	pgen			= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	entity_special	= pgen->pg_owner;

	// Don't display anything if no active parts
	if (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS)
		return;

	// Loop through the particle list, performing geometry updates and updating/adding the 
	// primitives (first set the relevant rot/trans matrices.
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];

	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	image_ptr	= (MR_TEXTURE*)pgen->pg_user_data_2;
	xcalc		= (image_ptr->te_w * pgen->pg_user_data_1);
	ycalc		= (image_ptr->te_h * pgen->pg_user_data_1);

	// colour
	entity	= entity_special->es_entity;

	if (live_entity = entity->en_live_entity)
		{
		mesh_inst_pptr 	= (MR_MESH_INST**)live_entity->le_api_insts;
		mesh_inst_ptr	= *mesh_inst_pptr;
				
		r = mesh_inst_ptr->mi_colour_scale.r;
		g = mesh_inst_ptr->mi_colour_scale.g;
		b = mesh_inst_ptr->mi_colour_scale.b;
		}
	else
		{
		r = 128;
		g = 128;
		b = 128;
		}

	// Loop through all active particles for this generator
	loop		= pgen->pg_max_particles;
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update position of point within the world (and velocity with gravity value)
			svec.vx = geom_ptr->pt_position.vx >> 16;
			svec.vy = geom_ptr->pt_position.vy >> 16;
			svec.vz = geom_ptr->pt_position.vz >> 16;
	
			gte_ldv0(&svec);
			gte_rtps();
			gte_stsz(&otz);

			otz >>= MRVp_otz_shift;
			otz += HILITE_EXHAUST_OT_OFFSET;

			if ((otz > 0) && (otz < MRVp_ot_size))	
				{					
				xofs = ((xcalc) / otz) >> 8;
				if (xofs < PARTICLE_DISPLAY_MAX_HALFWIDTH)
					{
					yofs = ((ycalc) / otz) >> 8;
					gte_stsxy(&sxy);			

					poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
					poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
					poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
					poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

//					poly_ptr->r0 = poly_ptr->g0 = poly_ptr->b0 = MIN(geom_ptr->pt_lifetime << 4, 255);

					life			= MIN(geom_ptr->pt_lifetime << 4, 255);
					poly_ptr->r0	= MIN(life, r);
					poly_ptr->g0	= MIN(life, g);
					poly_ptr->b0	= MIN(life, b);

					addPrim(MRVp_work_ot + otz, poly_ptr);
					}
				}				
			}
		geom_ptr++;	
		poly_ptr++;
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Hilite_exhaust_add(MR_OBJECT* object)
{
	MR_PGEN*			pgen 			= object->ob_extra.ob_extra_pgen;
	MR_PTYPE_2D_GEOM* 	part_ptr;
	ENTITY_SPECIAL*		entity_special	= pgen->pg_owner;
	MR_SVEC				svec;
	MR_VEC				vec;

	// Get a pointer to the next particle
	part_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

	// Set the next particle number, and wrap round if we're at the end of the list
	pgen->pg_next_particle++;		

	if (pgen->pg_next_particle == pgen->pg_max_particles)
		pgen->pg_next_particle = 0;

	part_ptr->pt_lifetime	= pgen->pg_particle_max_life;
	part_ptr->pt_user		= 0;

	// Set the position and velocities
	MR_SET_SVEC(&svec, (rand() & 0xf) - 8, (rand() & 0xf) - 8, -0x10);
	MRApplyMatrix(&entity_special->es_lwtrans, &svec, &vec);

	part_ptr->pt_velocity.vx = vec.vx << 16;
	part_ptr->pt_velocity.vy = vec.vy << 16;
	part_ptr->pt_velocity.vz = vec.vz << 16;
	part_ptr->pt_position.vx = entity_special->es_lwtrans.t[0] << 16;
	part_ptr->pt_position.vy = entity_special->es_lwtrans.t[1] << 16;
	part_ptr->pt_position.vz = entity_special->es_lwtrans.t[2] << 16;

}

//------------------------------------------------------------------------------------------------
MR_VOID	Hilite_exhaust_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_LONG				loop;
		 

	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;

	if (!(pgen->pg_flags & MR_PF_INACTIVE))
		{
		if (rand() & 1)
			{
			// Add some new particles
			Hilite_exhaust_add(object);
			}
		}

	// Set no active parts flag
	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;
			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of point within the world (and velocity with gravity value)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;		
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;		
			geom_ptr->pt_velocity.vy += pgen->pg_gravity;
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;		
			}
		geom_ptr++;	
		}

	// Deal with generator lifetime
	if (pgen->pg_generator_life > 0)
		{
		if (!(--pgen->pg_generator_life))
			{
			// Generator run out of life - put it into a state where it will kill itself (by
			// flagging the object as MR_OBJ_DESTROY_BY_DISPLAY) only when all associated particles
			// are no longer active
			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
			}
		}
	else
	if ((pgen->pg_generator_life == 0) && (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS))
		{
		// All instances of this MR_PGEN will be killed - only then will the MR_PGEN be killed
		object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
}


/******************************************************************************
*%%%% FrogEffectSlippingDisp
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectParticleFT4Init(
*						MR_PGEN_INST*	pgeninst,
*						MR_VIEWPORT*	viewport)
*
*	FUNCTION	Display particle system
*
*	INPUTS		pgeninst		-	ptr to particle generator
*				viewport		-	ptr to viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectSlippingDisp(	MR_PGEN_INST*	pgeninst, 
								MR_VIEWPORT*	viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_LONG				loop;
	MR_TEXTURE*			image_ptr;
	MR_LONG				xcalc;
	MR_LONG				ycalc;
	MR_XY				sxy;
	MR_SHORT			xofs;
	MR_SHORT			yofs;
	MR_LONG				otz;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
		return;

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	// Setup rotation and translation matrices
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	image_ptr	= (MR_TEXTURE*)pgen->pg_user_data_2;
	xcalc		= (image_ptr->te_w * pgen->pg_user_data_1);
	ycalc		= (image_ptr->te_h * pgen->pg_user_data_1);

	// Loop through all active particles for this generator, updating geometry...
	loop		= pgen->pg_max_particles;
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update position of point within the world (and velocity with gravity value)
			MR_SET_SVEC(&svec,	geom_ptr->pt_position.vx >> 16,
								geom_ptr->pt_position.vy >> 16,
								geom_ptr->pt_position.vz >> 16);
	
			gte_ldv0(&svec);
			gte_rtps();
			gte_stsz(&otz);

			otz >>= MRVp_otz_shift;
			otz += FROG_EFFECT_SLIP_OT_OFFSET;

			if ((otz > 0) && (otz < MRVp_ot_size))	
				{					
				xofs = ((xcalc) / otz) >> 8;
				if (xofs < FROG_EFFECT_PARTICLE_DISPLAY_MAX_HALFWIDTH)
					{
					yofs = ((ycalc) / otz) >> 8;
					gte_stsxy(&sxy);			

					poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
					poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
					poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
					poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

					poly_ptr->r0 = poly_ptr->g0 = poly_ptr->b0 = MIN(geom_ptr->pt_lifetime << 2, 255);
					addPrim(MRVp_work_ot + otz, poly_ptr);
					}
				}				
			}
		geom_ptr++;	
		poly_ptr++;
		}
}

/******************************************************************************
*%%%% FrogEffectSlippingAdd
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectSlippingAdd(
*						MR_OBJECT*		object)
*
*	FUNCTION	add to particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectSlippingAdd(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM* 	part_ptr;
	MR_VEC				vec;
	MR_SVEC				svec;
	MR_MAT*				matrix;
	FROG*				frog;

	pgen	= object->ob_extra.ob_extra_pgen;
	matrix	= (MR_MAT*)object->ob_frame;
	frog	= pgen->pg_owner;
	
	// Only add particles if frog is moving???
	if	(
		(frog->fr_velocity.vx != 0) || 
		(frog->fr_velocity.vy != 0) || 
		(frog->fr_velocity.vz != 0))
		{
		// Get a pointer to the next particle
		part_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

		// Set the next particle number, and wrap round if we're at the end of the list
		pgen->pg_next_particle++;		

		if (pgen->pg_next_particle == pgen->pg_max_particles)
			pgen->pg_next_particle = 0;

		part_ptr->pt_lifetime = pgen->pg_particle_max_life;
			
		// Set the position and velocities
		MR_SET_SVEC(&svec, (rand() & 0x7)-4, -0xf, -(rand() & 0x7)-4);
		MRApplyMatrix(matrix, &svec, &vec);
		MR_SET_VEC(&part_ptr->pt_velocity, vec.vx << 16, vec.vy << 16, vec.vz << 16);

		MR_SET_SVEC(&svec, (rand() & 0x4f)-0x28, 0x1f, 0);
		MRApplyMatrix(matrix, &svec, &vec);
		MR_SET_VEC(&part_ptr->pt_position,	(matrix->t[0] + vec.vx) << 16, 
											(matrix->t[1] + vec.vy) << 16, 
											(matrix->t[2] + vec.vz) << 16);
		}
}

/******************************************************************************
*%%%% FrogEffectSlippingMove
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectSlippingMove(
*						MR_OBJECT*		object)
*
*	FUNCTION	move particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectSlippingMove(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_LONG				loop;
	FROG*				frog;
	
	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;
	frog		= pgen->pg_owner;

	// Add some new particles
	if (rand() & 1)
		FrogEffectSlippingAdd(object);

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;

			// Update position of point within the world (and velocity with gravity value)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;		
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;		
			geom_ptr->pt_velocity.vy += pgen->pg_gravity;
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;		
			}
		geom_ptr++;	
		}
}


/******************************************************************************
*%%%% FrogEffectBubbleAdd
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectBubbleAdd(
*						MR_OBJECT*		object)
*
*	FUNCTION	add to bubbles particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectBubbleAdd(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM* 	part_ptr;
	MR_VEC				vec;
	MR_SVEC				svec;
	MR_MAT*				matrix;

	pgen			= object->ob_extra.ob_extra_pgen;
	matrix			= (MR_MAT*)object->ob_frame;
	
	// Get a pointer to the next particle
	part_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

	// Set the next particle number, and wrap round if we're at the end of the list
	pgen->pg_next_particle++;		

	if (pgen->pg_next_particle >= pgen->pg_max_particles)
		pgen->pg_next_particle = 0;

	part_ptr->pt_lifetime = pgen->pg_particle_max_life;
		
	// Set the position and velocities
	MR_SET_SVEC(&svec, (rand() & 0x16)-8, -0x6, (rand() & 0x16)-8);
	MRApplyMatrix(matrix, &svec, &vec);
	MR_SET_VEC(&part_ptr->pt_velocity, vec.vx << 16, vec.vy << 16, vec.vz << 16);
	MR_SET_VEC(&part_ptr->pt_position, matrix->t[0] << 16, matrix->t[1] << 16, matrix->t[2] << 16);
}

/******************************************************************************
*%%%% FrogEffectFireAdd
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectFireAdd(
*						MR_OBJECT*		object)
*
*	FUNCTION	add to fire particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectFireAdd(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM* 	part_ptr;
	MR_VEC				vec;
	MR_SVEC				svec;
	MR_MAT*				matrix;

	pgen			= object->ob_extra.ob_extra_pgen;
	matrix			= (MR_MAT*)object->ob_frame;
	
	// Get a pointer to the next particle
	part_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

	// Set the next particle number, and wrap round if we're at the end of the list
	pgen->pg_next_particle++;		

	if (pgen->pg_next_particle == pgen->pg_max_particles)
		pgen->pg_next_particle = 0;

	part_ptr->pt_lifetime	= pgen->pg_particle_max_life;
	part_ptr->pt_user		= pgen->pg_particle_max_life+(rand() & 32);

	// Set the position and velocities
	MR_SET_SVEC(&svec, (rand() & 63)-32, -0x10, (rand() & 63)-32);
	MRApplyMatrix(matrix, &svec, &vec);
	MR_SET_VEC(&part_ptr->pt_velocity, 0, -(rand()&15)<<15, 0);
	MR_SET_VEC(&part_ptr->pt_position,	(matrix->t[0]+vec.vx)<< 16, 
										(matrix->t[1]+vec.vy) << 16, 
										(matrix->t[2]+vec.vz) << 16);
}



/******************************************************************************
*%%%% FrogEffectBubbleMove
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectBubbleMove(
*						MR_OBJECT*		object)
*
*	FUNCTION	move bubbles particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectBubbleMove(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_LONG				loop;
	FROG*				frog;

	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;
	frog		= pgen->pg_owner;


	if (!(pgen->pg_flags & MR_PF_INACTIVE))
		{
		// Add some new particles, maybe...
		if (!(pgen->pg_generator_life % 10))
			pgen->pg_max_particles = MAX(0, pgen->pg_max_particles-1);
		FrogEffectBubbleAdd(object);
		}

	// Set no active parts flag
	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;
			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of point within the world (and velocity with NO gravity)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;		
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;		
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;		
			}
		geom_ptr++;	
		}

	// Deal with generator lifetime
	if (pgen->pg_generator_life > 0)
		{
		if (!(--pgen->pg_generator_life))
			{
			// Request that the generator close and destroy itself.
			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
			}
		}
	else
	if	(
		(pgen->pg_generator_life == 0) && 
		(pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS)
		)
		{
		// No active parts and generator life finished, kill off
		object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

		// Remove frog data
		if (frog->fr_particle_api_item)
			frog->fr_particle_api_item = NULL;
		}
}

/******************************************************************************
*%%%% FrogEffectFireMove
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectFireMove(
*						MR_OBJECT*		object)
*
*	FUNCTION	move bubbles particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectFireMove(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_LONG				loop;
	FROG*				frog;

	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;
	frog		= pgen->pg_owner;

//	if (!(pgen->pg_flags & MR_PF_INACTIVE))
//		{
		if (rand() & 1)
//			{
			// Add some new particles
			FrogEffectFireAdd(object);
//			}
//		}
//
//	// Set no active parts flag
//	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;
//			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of point within the world (and velocity with NO gravity)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;	
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;	
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;	
			}
		geom_ptr++;	
		}

	// Deal with generator lifetime
//	if (pgen->pg_generator_life > 0)
//		{
//		if (!(--pgen->pg_generator_life))
//			{
//			// Request that the generator close and destroy itself.
//			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
//			}
//		}
//	else
//	if	(
//		(pgen->pg_generator_life == 0) && 
//		(pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS)
//		)
//		{
//		// No active parts and generator life finished, kill off
//		object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
//		pgen->pg_flags |= MR_PF_INACTIVE;
//
//		// Remove frog data
//		if (frog->fr_particle_api_item)
//			frog->fr_particle_api_item = NULL;
//		}
}


/******************************************************************************
*%%%% FrogEffectFireDisp
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectFireDisp(
*						MR_PGEN_INST*	pgeninst,
*						MR_VIEWPORT*	viewport)
*
*	FUNCTION	Display fire particle system
*
*	INPUTS		pgeninst		-	ptr to particle generator
*				viewport		-	ptr to viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogEffectFireDisp(	MR_PGEN_INST*	pgeninst, 
							MR_VIEWPORT*	viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_LONG				loop;
	MR_TEXTURE*			image_ptr;
	MR_LONG				xcalc, ycalc;
	MR_XY				sxy;
	MR_SHORT			xofs, yofs;
	MR_LONG				otz;
		 

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
		return;

	// Setup rotation and translation matrices
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	image_ptr	= (MR_TEXTURE*)pgen->pg_user_data_2;

	// Loop through all active particles for this generator, updating geometry...
	loop		= pgen->pg_max_particles;
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update position of point within the world (and velocity with gravity value)
			MR_SET_SVEC(&svec,	geom_ptr->pt_position.vx >> 16,
								geom_ptr->pt_position.vy >> 16,
								geom_ptr->pt_position.vz >> 16);

			xcalc	= (image_ptr->te_w * pgen->pg_user_data_1 * geom_ptr->pt_user)>>4;
			ycalc	= (image_ptr->te_h * pgen->pg_user_data_1 * geom_ptr->pt_user)>>4;
			
			gte_ldv0(&svec);
			gte_rtps();
			gte_stsz(&otz);

			otz >>= MRVp_otz_shift;
			otz += FROG_EFFECT_SLIP_OT_OFFSET;

			if ((otz > 0) && (otz < MRVp_ot_size))	
				{					
				xofs = ((xcalc) / otz) >> 8;
				if (xofs < FROG_EFFECT_PARTICLE_DISPLAY_MAX_HALFWIDTH)
					{
					yofs = ((ycalc) / otz) >> 8;
					gte_stsxy(&sxy);			

					poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
					poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
					poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
					poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

					if (geom_ptr->pt_user > 2)
						geom_ptr->pt_user -= 4;
					else
						geom_ptr->pt_user = 0;
					poly_ptr->r0	= 255;
					poly_ptr->g0	= MIN(255, geom_ptr->pt_user);
					poly_ptr->b0	= 0;
					addPrim(MRVp_work_ot + otz, poly_ptr);
					}
				}				
			}
		geom_ptr++;	
		poly_ptr++;
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Gold_frog_particle_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_PTYPE_2D_GEOM*	next_geom_ptr;
	MR_LONG				loop;
	MR_VEC				vec;
	MR_SVEC				svec;
	MR_MAT*				matrix;
		 
	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;

	if (!(pgen->pg_flags & MR_PF_INACTIVE))
		{
		if (rand() & 1)
			{
			// Add some new particles
			matrix			= (MR_MAT*)pgen->pg_owner;
	
			// Get a pointer to the next particle
			next_geom_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

			// Set the next particle number, and wrap round if we're at the end of the list
			pgen->pg_next_particle++;		

			if (pgen->pg_next_particle == pgen->pg_max_particles)
				pgen->pg_next_particle = 0;

			next_geom_ptr->pt_lifetime	= pgen->pg_particle_max_life;
			next_geom_ptr->pt_user		= MIN(4096, pgen->pg_particle_max_life*(rand() & 31));

			// Set the position and velocities
			MR_SET_SVEC(&svec, (rand() & 0x15)-7, -0x5, (rand() & 0x15)-7);
			MRApplyMatrix(matrix, &svec, &vec);
			MR_SET_VEC(&next_geom_ptr->pt_velocity, vec.vx << 16, vec.vy << 16, vec.vz << 16);
			MR_SET_VEC(&next_geom_ptr->pt_position, matrix->t[0] << 16, matrix->t[1] << 16, matrix->t[2] << 16);
			}
		}

	// Set no active parts flag
	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;
			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of point within the world (and velocity with gravity value)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;		
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;		
			geom_ptr->pt_velocity.vy += pgen->pg_gravity;
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;		
			}
		geom_ptr++;	
		}

	// Deal with generator lifetime
	if (pgen->pg_generator_life > 0)
		{
		if (!(--pgen->pg_generator_life))
			{
			// Generator run out of life - put it into a state where it will kill itself (by
			// flagging the object as MR_OBJ_DESTROY_BY_DISPLAY) only when all associated particles
			// are no longer active
			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
			}
		}
	else
	if ((pgen->pg_generator_life == 0) && (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS))
		{
		// All instances of this MR_PGEN will be killed - only then will the MR_PGEN be killed
		object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}
}

/******************************************************************************
*%%%% FrogEffectFireDisp
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogEffectFireDisp(
*						MR_PGEN_INST*	pgeninst,
*						MR_VIEWPORT*	viewport)
*
*	FUNCTION	Display animated textured particle system
*
*	INPUTS		pgeninst		-	ptr to particle generator
*				viewport		-	ptr to viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	Hilite_dust_disp(	MR_PGEN_INST*	pgeninst, 
							MR_VIEWPORT*	viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_LONG				loop;
	MR_TEXTURE*			image_ptr;
	MR_XY				sxy;
	MR_SHORT			xofs;
	MR_SHORT			yofs;
	MR_LONG				otz, xcalc, ycalc;
		 

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
		return;

	// Setup rotation and translation matrices
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 

	// Loop through all active particles for this generator, updating geometry...
	loop		= pgen->pg_max_particles;
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			if (image_ptr = (MR_TEXTURE*)* ((MR_LONG*)pgen->pg_user_data_2 + geom_ptr->pt_user))
				{
#ifdef PSX
				MR_COPY32(poly_ptr->u0, image_ptr->te_u0);	// Copies te_tpage_id too
				MR_COPY32(poly_ptr->u1, image_ptr->te_u1);	// Copies te_clut_id too
#else
				MR_COPY16(poly_ptr->u0, image_ptr->te_u0);
				MR_COPY16(poly_ptr->u1, image_ptr->te_u1);
				poly_ptr->tpage = image_ptr->te_tpage_id;
#endif
				MR_COPY16(poly_ptr->u2, image_ptr->te_u2);
				MR_COPY16(poly_ptr->u3, image_ptr->te_u3);

#ifdef WIN95
				// This sets ABR value 1.. useful for when someone forgets to set up Vorg correctly :/
				image_ptr->te_tpage_id |= (1<<8);
#endif

				xcalc		= (image_ptr->te_w * pgen->pg_user_data_1);
				ycalc		= (image_ptr->te_h * pgen->pg_user_data_1);

				// update counter
				geom_ptr->pt_user++;

				// Update position of point within the world (and velocity with gravity value)
				MR_SET_SVEC(&svec,	geom_ptr->pt_position.vx >> 16,
									geom_ptr->pt_position.vy >> 16,
									geom_ptr->pt_position.vz >> 16);
		
				gte_ldv0(&svec);
				gte_rtps();
				gte_stsz(&otz);

				otz >>= MRVp_otz_shift;
				otz += FROG_EFFECT_SLIP_OT_OFFSET;

				if ((otz > 0) && (otz < MRVp_ot_size))	
					{					
					xofs = (xcalc / otz) >> 8;
					if (xofs < FROG_EFFECT_PARTICLE_DISPLAY_MAX_HALFWIDTH)
						{
						yofs = ((ycalc) / otz) >> 8;
						gte_stsxy(&sxy);			

						poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
						poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
						poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
						poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

						poly_ptr->r0 = poly_ptr->g0 = poly_ptr->b0 = MIN(geom_ptr->pt_lifetime << 4, 255);
						addPrim(MRVp_work_ot + otz, poly_ptr);
						}
					}				
				}
			else
				{	
				geom_ptr->pt_lifetime = 0;
				}
			}
		geom_ptr++;	
		poly_ptr++;
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	For_swarm_prim_init(MR_PGEN_INST* pgeninst)
{
	MR_PGEN*		pgen		= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	MR_LONG			loop		= pgen->pg_max_particles * 2;
	POLY_FT4*		poly_ptr_0 	= (POLY_FT4*)pgeninst->pi_particle_prims[0]; 
	MR_TEXTURE*		image_ptr 	= (MR_TEXTURE*)pgen->pg_user_data_2;


 	while(loop--)
		{
		setPolyFT4(poly_ptr_0);
		setRGB0(poly_ptr_0, 0x80, 0x80, 0x80);
#ifdef PSX
		MR_COPY32(poly_ptr_0->u0, image_ptr->te_u0);	// Copies te_tpage_id too
		MR_COPY32(poly_ptr_0->u1, image_ptr->te_u1);	// Copies te_clut_id too
#else
		MR_COPY16(poly_ptr_0->u0, image_ptr->te_u0);
		MR_COPY16(poly_ptr_0->u1, image_ptr->te_u1);
		poly_ptr_0->tpage = image_ptr->te_tpage_id;
#endif
		MR_COPY16(poly_ptr_0->u2, image_ptr->te_u2);
		MR_COPY16(poly_ptr_0->u3, image_ptr->te_u3);
		poly_ptr_0++;
		}
}
//------------------------------------------------------------------------------------------------
MR_VOID	For_swarm_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	POLY_FT4*			poly_ptr;
	MR_LONG				otz;
	MR_MAT*				lwtrans;
	FOREST_RT_SWARM*	swarm;
	MR_MAT				matrix;
	MR_LONG				dx, dy;
	MR_VEC				vec_x, vec_y, vec_z;
	MR_MAT*				cam_matrix;
	MR_LONG				i;
	MR_VEC				trans_vec[FOR_NUM_SWARM_SPRITES];
	static MR_SVEC for_sprite_offsets[] =
		{
			{-0x80, -0x80, 0},
			{ 0x80, -0x80, 0},
			{-0x80,  0x80, 0},
			{ 0x80,  0x80, 0}
		};

	
	pgen 	= pgeninst->pi_object->ob_extra.ob_extra_pgen;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_NO_DISPLAY)
		return;

	swarm	= pgen->pg_owner;

	// Loop through the particle list, performing geometry updates and updating/adding the 
	// primitives (first set the relevant rot/trans matrices.
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];

	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
		lwtrans = (MR_MAT*)pgeninst->pi_object->ob_frame;
	else
		lwtrans = &pgeninst->pi_object->ob_frame->fr_lw_transform;

	// Calculate object matrix parallel to camera XY plane
	cam_matrix = &viewport->vp_camera->fr_lw_transform;
	dx = ((lwtrans->m[0][2] * cam_matrix->m[0][0]) + (lwtrans->m[1][2] * cam_matrix->m[1][0]) + (lwtrans->m[2][2] * cam_matrix->m[2][0])) >> 12;
	dy = ((lwtrans->m[0][2] * cam_matrix->m[0][1]) + (lwtrans->m[1][2] * cam_matrix->m[1][1]) + (lwtrans->m[2][2] * cam_matrix->m[2][1])) >> 12;
	
	vec_y.vx = -((dx * cam_matrix->m[0][0]) + (dy * cam_matrix->m[0][1])) >> 12;
	vec_y.vy = -((dx * cam_matrix->m[1][0]) + (dy * cam_matrix->m[1][1])) >> 12;
	vec_y.vz = -((dx * cam_matrix->m[2][0]) + (dy * cam_matrix->m[2][1])) >> 12;

	// Projected local Z onto camera XY.  This becomes local Y axis.
	// Now use camera Z axis as entity Y
	vec_z.vx = cam_matrix->m[0][2];
	vec_z.vy = cam_matrix->m[1][2];
	vec_z.vz = cam_matrix->m[2][2];
	MROuterProduct12(&vec_y, &vec_z, &vec_x);
	WriteAxesAsMatrix(&matrix, &vec_x, &vec_y, &vec_z);
	MRMulMatrixABC(&viewport->vp_render_matrix, &matrix, MRViewtrans_ptr);

	for (i = 0; i < FOR_NUM_SWARM_SPRITES; i++)
		{
		svec.vx = swarm->sw_positions[i].vx - (MR_SHORT)viewport->vp_render_matrix.t[0];
		svec.vy = swarm->sw_positions[i].vy - (MR_SHORT)viewport->vp_render_matrix.t[1];
		svec.vz = swarm->sw_positions[i].vz - (MR_SHORT)viewport->vp_render_matrix.t[2];
		MRApplyMatrix(&viewport->vp_render_matrix, &svec, &trans_vec[i]);
		}

	// Set up rotation matrix once only
	gte_SetRotMatrix(MRViewtrans_ptr);

	// Rotate centre of swarm for OTZ
	MR_SUB_VEC_ABC((MR_VEC*)swarm->sw_matrix.t, (MR_VEC*)viewport->vp_render_matrix.t, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	gte_ldv0(&Null_svector);
	gte_rtps();
	poly_ptr = (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	gte_stsz(&otz);

	otz >>= MRVp_otz_shift;
	otz = MAX(0, otz + FOR_SWARM_OT_OFFSET);
	
	if (otz < MRVp_ot_size)
		{					
		// Loop through all active particles for this generator
		for (i = 0; i < pgen->pg_max_particles; i++)
			{	
			MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &trans_vec[i]);
			gte_SetTransMatrix(MRViewtrans_ptr);
			gte_ldv3(&for_sprite_offsets[0], &for_sprite_offsets[1], &for_sprite_offsets[2]);
			gte_rtpt();
			addPrim(MRVp_work_ot + otz, poly_ptr);

			gte_stsxy3(	(MR_LONG*)&poly_ptr->x0,
						(MR_LONG*)&poly_ptr->x1,
						(MR_LONG*)&poly_ptr->x2);

			gte_ldv0(&for_sprite_offsets[3]);
			gte_rtps();
			gte_stsxy(	(MR_LONG*)&poly_ptr->x3);

			poly_ptr++;
			}
		}
}

/******************************************************************************
*%%%% Hilite_fire_add
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Hilite_fire_add(
*						MR_OBJECT*		object)
*
*	FUNCTION	add to fire particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	Hilite_fire_add(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM* 	part_ptr;
	ENTITY_SPECIAL*		entity_special;

	pgen			= object->ob_extra.ob_extra_pgen;
	entity_special	= (ENTITY_SPECIAL*)pgen->pg_owner;

	// Get a pointer to the next particle
	part_ptr = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

	// Set the next particle number, and wrap round if we're at the end of the list
	pgen->pg_next_particle++;		

	if (pgen->pg_next_particle == pgen->pg_max_particles)
		pgen->pg_next_particle = 0;

	part_ptr->pt_lifetime	= pgen->pg_particle_max_life;
	part_ptr->pt_user		= pgen->pg_particle_max_life + (rand() & 0x1f);	// was 32

	// Set the position and velocities
	part_ptr->pt_velocity.vx = ((rand() & 0xf) - 8) << 16;
	part_ptr->pt_velocity.vy = ((rand() & 0xf) - 8) << 16;
	part_ptr->pt_velocity.vz = ((rand() & 0xf) - 8) << 16;
	part_ptr->pt_position.vx = entity_special->es_lwtrans.t[0] << 16;
	part_ptr->pt_position.vy = entity_special->es_lwtrans.t[1] << 16;
	part_ptr->pt_position.vz = entity_special->es_lwtrans.t[2] << 16;
}


/******************************************************************************
*%%%% Hilite_fire_move
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Hilite_fire_move(
*						MR_OBJECT*		object)
*
*	FUNCTION	move fire particle system
*
*	INPUTS		object			-	ptr to object to add to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	Hilite_fire_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	MR_LONG				loop;
	FROG*				frog;

	pgen		= object->ob_extra.ob_extra_pgen;
 	geom_ptr	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	loop		= pgen->pg_max_particles;
	frog		= pgen->pg_owner;

	if (rand() & 1)
		Hilite_fire_add(object);

	// Loop through all active particles for this generator
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update lifetime
			geom_ptr->pt_lifetime--;

			// Update position of point within the world (and velocity with NO gravity)
			geom_ptr->pt_position.vx += geom_ptr->pt_velocity.vx;	
			geom_ptr->pt_position.vy += geom_ptr->pt_velocity.vy;	
			geom_ptr->pt_position.vz += geom_ptr->pt_velocity.vz;	
			}
		geom_ptr++;	
		}
}


/******************************************************************************
*%%%% Hilite_fire_disp
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Hilite_fire_disp(
*						MR_PGEN_INST*	pgeninst,
*						MR_VIEWPORT*	viewport)
*
*	FUNCTION	Display fire particle system
*
*	INPUTS		pgeninst		-	ptr to particle generator
*				viewport		-	ptr to viewport
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	Hilite_fire_disp(	MR_PGEN_INST*	pgeninst, 
							MR_VIEWPORT*	viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_LONG				loop;
	MR_TEXTURE*			image_ptr;
	MR_LONG				xcalc, ycalc;
	MR_XY				sxy;
	MR_SHORT			xofs, yofs;
	MR_LONG				otz;
		 

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_DESTROY_BY_DISPLAY)
		return;

	// Setup rotation and translation matrices
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];
	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	geom_ptr 	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	image_ptr	= (MR_TEXTURE*)pgen->pg_user_data_2;

	// Loop through all active particles for this generator, updating geometry...
	loop		= pgen->pg_max_particles;
	while(loop--)
		{
		if (geom_ptr->pt_lifetime)
			{
			// Update position of point within the world (and velocity with gravity value)
			MR_SET_SVEC(&svec,	geom_ptr->pt_position.vx >> 16,
								geom_ptr->pt_position.vy >> 16,
								geom_ptr->pt_position.vz >> 16);

			xcalc	= (image_ptr->te_w * pgen->pg_user_data_1 * geom_ptr->pt_user)>>4;
			ycalc	= (image_ptr->te_h * pgen->pg_user_data_1 * geom_ptr->pt_user)>>4;
			
			gte_ldv0(&svec);
			gte_rtps();
			gte_stsz(&otz);

			otz >>= MRVp_otz_shift;
			otz = MAX(1, otz + FROG_EFFECT_SLIP_OT_OFFSET);

			if (otz < MRVp_ot_size)
				{					
				xofs = ((xcalc) / otz) >> 8;
				if (xofs < FROG_EFFECT_PARTICLE_DISPLAY_MAX_HALFWIDTH)
					{
					yofs = ((ycalc) / otz) >> 8;
					gte_stsxy(&sxy);			

					poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
					poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
					poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
					poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

					if (geom_ptr->pt_user > 2)
						geom_ptr->pt_user -= 4;
					else
						geom_ptr->pt_user = 0;
					poly_ptr->r0	= 255;
					poly_ptr->g0	= MIN(255, geom_ptr->pt_user);
					poly_ptr->b0	= 0;
					addPrim(MRVp_work_ot + otz, poly_ptr);
					}
				}				
			}
		geom_ptr++;	
		poly_ptr++;
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Gold_frog_glow_prim_init(MR_PGEN_INST* pgeninst)
{
//	MR_PGEN*		pgen		= pgeninst->pi_object->ob_extra.ob_extra_pgen;
	POLY_FT4*		poly_ptr 	= (POLY_FT4*)pgeninst->pi_particle_prims[0]; 
	MR_LONG			loop		= 2;
	MR_TEXTURE*		image_ptr;
	
	image_ptr = &im_tongue_tip;

	while (loop--)
		{
		MR_SET32(poly_ptr->r0, 0x20aaaa);
		setPolyFT4(poly_ptr);
		setSemiTrans(poly_ptr, 1);
	#ifdef PSX
		MR_COPY32(poly_ptr->u0, image_ptr->te_u0);	// Copies te_tpage_id too
		MR_COPY32(poly_ptr->u1, image_ptr->te_u1);	// Copies te_clut_id too
	#else
		MR_COPY16(poly_ptr->u0, image_ptr->te_u0);
		MR_COPY16(poly_ptr->u1, image_ptr->te_u1);
		poly_ptr->tpage = image_ptr->te_tpage_id;
		poly_ptr->a0	= 0x80;
	#endif
		MR_COPY16(poly_ptr->u2, image_ptr->te_u2);
		MR_COPY16(poly_ptr->u3, image_ptr->te_u3);
		poly_ptr++;
		}
}

//------------------------------------------------------------------------------------------------
MR_VOID	Gold_frog_glow_move(MR_OBJECT* object)
{
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
		 
	pgen 		= object->ob_extra.ob_extra_pgen;
	geom_ptr	= pgen->pg_particle_info;

	// Increase counter for glow pulsing
	geom_ptr->pt_lifetime = (geom_ptr->pt_lifetime + 0x100) & 0xfff;
}

//------------------------------------------------------------------------------------------------
MR_VOID	Gold_frog_glow_disp(MR_PGEN_INST* pgeninst, MR_VIEWPORT* viewport)
{
	MR_SVEC				svec;
	MR_PGEN*			pgen;
	MR_PTYPE_2D_GEOM*	geom_ptr;
	POLY_FT4*			poly_ptr;
	MR_TEXTURE*			glow_texture;
	MR_LONG				glow_mag;
	MR_XY				sxy;
	MR_SHORT			xofs;
	MR_SHORT			yofs;
	MR_LONG				otz, shift;
	MR_MAT*				lwtrans;
#ifdef WIN95
	MR_LONG				z;
#endif

	pgen = pgeninst->pi_object->ob_extra.ob_extra_pgen;

	// Don't display anything if no active parts
	if (pgen->pg_flags & MR_PF_NO_ACTIVE_PARTS)
		return;

	// Loop through the particle list, performing geometry updates and updating/adding the 
	// primitives (first set the relevant rot/trans matrices.
	svec.vx = -(MR_SHORT)viewport->vp_render_matrix.t[0];
	svec.vy = -(MR_SHORT)viewport->vp_render_matrix.t[1];
	svec.vz = -(MR_SHORT)viewport->vp_render_matrix.t[2];

	gte_SetRotMatrix(&viewport->vp_render_matrix);
	MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);
	
	poly_ptr 		= (POLY_FT4*)pgeninst->pi_particle_prims[MRFrame_index]; 
	glow_texture	= &im_tongue_tip;
	geom_ptr 		= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;

	if (pgeninst->pi_object->ob_flags & MR_OBJ_STATIC)
		lwtrans = (MR_MAT*)pgeninst->pi_object->ob_frame;
	else
		lwtrans = &pgeninst->pi_object->ob_frame->fr_lw_transform;

	// Loop through all active particles for this generator
	MR_SVEC_EQUALS_VEC(&svec, (MR_VEC*)lwtrans->t);
	gte_ldv0(&svec);
	gte_rtps();
	gte_stsz(&otz);

	otz >>= MRVp_otz_shift;
	otz += (-0x30);
	
	if ((otz > 0) && (otz < MRVp_ot_size))	
		{
#ifndef BUILD_49			
		// Glow
		gte_stsxy(&sxy);	

		// Only try to render if abs(y) < 768
		if (abs(sxy.y) < 0x300)
			{
#endif
			// If half size viewports, halve size of sprites
			if (Game_total_viewports > 2)
				shift = 9;
			else
				shift = 8;
#ifdef BUILD_49
			// Glow
			gte_stsxy(&sxy);
#endif
			glow_mag 	= (rsin(geom_ptr->pt_lifetime) + 0x3800) << 4;
			xofs 		= ((glow_texture->te_w * glow_mag) / otz) >> shift;
			yofs 		= ((glow_texture->te_h * glow_mag) / otz) >> shift;
			poly_ptr->x2 = poly_ptr->x0 = sxy.x - xofs;
			poly_ptr->x3 = poly_ptr->x1 = sxy.x + xofs;
			poly_ptr->y1 = poly_ptr->y0 = sxy.y - yofs;
			poly_ptr->y2 = poly_ptr->y3 = sxy.y + yofs;

#ifdef WIN95
			poly_ptr->z0 = poly_ptr->z1 = poly_ptr->z2 = poly_ptr->z3 = otz;
#endif
			addPrim(MRVp_work_ot + otz, poly_ptr);
#ifndef BUILD_49
			}
#endif
		}
}

#ifdef WIN95
#pragma warning (default : 4245)
#endif
