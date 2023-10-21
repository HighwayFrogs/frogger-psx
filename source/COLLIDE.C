/******************************************************************************
*%%%% collide.c
*------------------------------------------------------------------------------
*
*	Collision functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	21.04.97	Tim Closs		Created
*	10.05.97	Martin Kift		Added entity->frog hit flag to ReactFrogWithForm()
*	12.05.97	Martin Kift		Added CollideEntity() function
*	15.05.97	Martin Kift		Rewrote CollideFrog to add collprim support,
*								also adding 2 new functions.
*	26.05.97	Martin Kift		Tweaked CollideFrog() such that if frog is 
*								jumping along an Entity, it always reacts.
*	10.07.97	Tim Closs		CollideFrog() - fixed bug with FORM_BOOK_FLAG_NO_MODEL
*								check causing break out of function
*	11.07.97	Tim Closs		CollideFrog() - fixed bug where functioning was bailing
*								in FROG_MODE_WAIT_FOR_CAMERA for camera twisting
*
*%%%**************************************************************************/

#include "collide.h"
#include "mapview.h"
#include "entity.h"
#include "form.h"
#include "camera.h"
#include "entlib.h"
#include "sound.h"
#include "froguser.h"
#include "ent_gen.h"
#include "library.h"
#include "froganim.h"
#include "misc.h"
#include "select.h"
#include "particle.h"

#ifdef MR_DEBUG
#include "mapdebug.h"
#endif

// Splash Lists
MR_ULONG	FrogSplashAnimList[]=
{
	// Wait for a few frames for top of turtle to be underwater
	MR_SPRT_NOP,
	MR_SPRT_NOP,
	MR_SPRT_NOP,
	MR_SPRT_NOP,
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x606060,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x404040,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_SETCOLOUR,	0x202020,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_ripple_tim6,
	MR_SPRT_KILL
};

/******************************************************************************
*%%%% CollideFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CollideFrog(
*						FROG*	frog)
*
*	FUNCTION	Handle collision of frog with entities
*
*	INPUTS		frog	-	ptr to FROG
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.04.97	Tim Closs		Created
*	17.05.97	Martin Kift		Rewrote to add collprim support.
*	26.05.97	Martin Kift		Tweaked code such that if frog is jumping along
*								an Entity, it always reacts with flags.
*	29.05.97	Martin Kift		Added no collision flag
*	10.07.97	Tim Closs		Fixed bug with FORM_BOOK_FLAG_NO_MODEL check
*								causing break out of function
*	11.07.97	Tim Closs		Fixed bug where functioning was bailing in
*								FROG_MODE_WAIT_FOR_CAMERA for camera twisting
*	03.08.97	Martin Kift		Reworked the forbid-entity code to fix bug.
*	20.08.97	Tim Closs		Changed fcoords check to <,> rather than <=,>=
*	21.08.97	Gary Richards	Added large OT if dying in water.
*
*%%%**************************************************************************/

MR_VOID	CollideFrog(FROG*	frog)
{
	MAP_GROUP*		map_group;
	MR_LONG			x, z, r, i;
	MR_LONG			mg_xmin, mg_xmax, mg_zmin, mg_zmax;
	MR_LONG			xmin, xmax, zmin, zmax;
	ENTITY*			entity;
	LIVE_ENTITY*	live_entity;
	FORM*			form;
	FORM_DATA*		form_data;
	MR_SVEC			svec;
	MR_VEC			fcoords;
	MR_MAT			entity_transmatrix;
	MR_LONG			distance;
	FORM_BOOK*		form_book;
	MR_OBJECT*		sprite_ptr;
	ENTITY*			forbid_entity;
#ifdef PSX
	MR_OT**			local_ot_ptr;		// Pointer to frog->fr_ot[0];
#endif
	MR_VEC			vec;

	// In certain modes, we don't want to do any collision
	switch(frog->fr_mode)
		{
		case FROG_MODE_DYING:
		case FROG_MODE_HIT_CHECKPOINT:
		case FROGUSER_MODE_CHECKPOINT_COLLECTED:
			return;
			break;

		case FROG_MODE_WAIT_FOR_CAMERA:
			if (!Cameras[frog->fr_frog_id].ca_twist_counter)
				return;
			break;
		}

	if (frog->fr_flags & FROG_MUST_DIE)
		return;

	// Check for death off map
	if 	(
		(frog->fr_lwtrans->t[0] < Fade_top_left_pos.vx ) ||
		(frog->fr_lwtrans->t[0] > Fade_bottom_right_pos.vx ) ||
		(frog->fr_lwtrans->t[2] < Fade_bottom_right_pos.vz ) ||
		(frog->fr_lwtrans->t[2] > Fade_top_left_pos.vz )
		)
		{
		FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
		return;
		}

	// Firstly: if in freefall, check if we have fallen below frog->fr_grid_square
	if	(
		(frog->fr_flags & FROG_FREEFALL) &&
		(frog->fr_grid_square)
		)
		{
		i = GetGridSquareHeight(frog->fr_grid_square);
		if (frog->fr_lwtrans->t[1] > i)
			{
			// Landed on land
			FrogLandedOnLand(frog);
			UpdateFrogPositionalInfo(frog);
			ReactFrogWithGridFlags(frog, (MR_USHORT)frog->fr_grid_square->gs_flags);
			return;
			}
		}

	// Check for death in water
	if (frog->fr_lwtrans->t[1] > Theme_library[Game_map_theme].tb_death_height)
		{
		frog->fr_lwtrans->t[1] 	= Theme_library[Game_map_theme].tb_death_height;

		// Clear velocity to stop it falling
		MR_CLEAR_VEC(&frog->fr_velocity);

		// Kill the frog
		MR_SET_VEC(&vec, 0, 5<<16, 0);
		FrogKill(frog, FROG_ANIMATION_DROWN, &vec);

		sprite_ptr = MRCreate3DSprite((MR_FRAME*)frog->fr_lwtrans, MR_OBJ_STATIC, FrogSplashAnimList);
		sprite_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
		sprite_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x10;
		GameAddObjectToViewports(sprite_ptr);

		// Request particle effect for bubbleing
		if (!frog->fr_particle_api_item)
			frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_WATER_BUBBLE, NULL);

		if (Game_map_theme == THEME_SKY)
			// Play SFX when hitting floor.
			MRSNDPlaySound(SFX_GEN_FROG_HIT_GROUND, NULL, 0, 0);
		else
			// Play SFX when drowning.
			MRSNDPlaySound(SFX_GEN_FROG_DROWN1, NULL, 0, 0);

#ifdef PSX
		//Only on suburbia and original
		if ((Game_map_theme == THEME_ORG) || (Game_map_theme == THEME_SUB))
			{
			// Set frog to have a LARGE ot position, so he appears below the env_map.
			i = Game_total_viewports;
			local_ot_ptr = frog->fr_ot;
			while(i--)
				{
				local_ot_ptr[0]->ot_flags |= MR_OT_FORCE_BACK;
				local_ot_ptr++;
				}
			}
#endif
		return;
		}

	r				= 0;//FROG_COLLIDE_RADIUS;
	forbid_entity	= frog->fr_forbid_entity;

#ifdef DEBUG_DISPLAY_FROG_GRID_SQUARES
	if (frog->fr_grid_square)
		MapDebugDisplayGridSquare(frog->fr_grid_square);

	MapDebugDisplayGridCoord(frog->fr_grid_x, frog->fr_grid_z);
#endif

	// Check for entity collision
	//
	// Calculate MAP_GROUP frog is in.  This will have to be expanded to check (max of) 3x3 MAP_GROUPs
	x		= (frog->fr_lwtrans->t[0] - Map_view_basepoint.vx) / Map_view_xlen;
	z 		= (frog->fr_lwtrans->t[2] - Map_view_basepoint.vz) / Map_view_zlen;
	mg_xmin	= MAX(0, x - 1);
	mg_xmax	= MIN(Map_view_xnum - 1, x + 1);
	mg_zmin	= MAX(0, z - 1);
	mg_zmax	= MIN(Map_view_znum - 1, z + 1);

	for (z = mg_zmin; z <= mg_zmax; z++)
		{
		for (x = mg_xmin; x <= mg_xmax; x++)
			{
			map_group = &Map_groups[(z * Map_view_xnum) + x];
#ifdef DEBUG_DISPLAY_FROG_MAP_GROUPS
			MapDebugDisplayMapGroup(map_group);
#endif	
			entity = map_group->mg_entity_root_ptr;
			while(entity = entity->en_next)
				{
				// Is entity LIVE?
				if (live_entity = entity->en_live_entity)
					{
					// If we are jumping from an entity, don't check the entity we are jumping from,
					// but we should react to its flags.
					if	(
						(entity != frog->fr_entity) &&
						(entity != forbid_entity)
						)
						{					
						// dont continue if no collision has been requested
						if (!(entity->en_flags & ENTITY_NO_COLLISION))
							{
							form_book = ENTITY_GET_FORM_BOOK(entity);

							// First do a sphere check (using precalculated values from the form book) to
							// see if its worth while doing a collision check at all...
							svec.vx = frog->fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0];
							svec.vy = frog->fr_lwtrans->t[1] - live_entity->le_lwtrans->t[1];
							svec.vz = frog->fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2];
							distance = MR_SVEC_MOD_SQR(&svec);

#ifdef DEBUG_DISPLAY_FORM_BOUNDING_SPHERES
							MapDebugDisplayFormBoundingSphere(live_entity);
#endif
							if (distance < (form_book->fb_radius2 + 0))//FROG_COLLIDE_RADIUS2))
								{
								// If we don't have a model, rely on a simple bounding sphere check between the
								// frog and the sphere (if there is one) which has already been done above
								if (form_book->fb_flags & FORM_BOOK_FLAG_NO_MODEL)
									{
									// This collision method relies on having a previously alloced collision structure
									if (form_book->fb_collprim_react)
										{
										// Collide with frog and exit
										form_book->fb_collprim_react(frog, live_entity, NULL);
										goto collide_with_frog;
										}
									else
										goto next_entity;
									}
										
								// Yes we are within range of this entity. Call a function to handle collision
								// with potential collprims, and if this function returns TRUE for a successful
								// hit, don't bother with FORM collision checking
								if (CollideFrogWithCollPrims(frog, live_entity, form_book) == FALSE)
									{
									form = ENTITY_GET_FORM(entity);

									// Continue with FORM collision checking
									if (form->fo_numformdatas)
										{					
										form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
#ifdef DEBUG_DISPLAY_FORMS
										MapDebugDisplayForm(form, live_entity->le_lwtrans);
#endif
										// Put frog origin in entity frame, using difference svec previously calc'ed
										MRTransposeMatrix(live_entity->le_lwtrans, &entity_transmatrix);
										MRApplyMatrix(&entity_transmatrix, &svec, &fcoords);

										// Check against FORM grid bounds
										xmin = form->fo_xofs;
										xmax = form->fo_xofs + (form->fo_xnum << 8);
										zmin = form->fo_zofs;
										zmax = form->fo_zofs + (form->fo_znum << 8);
										if	(
											(fcoords.vx > (xmin - r)) &&
											(fcoords.vx < (xmax + r)) &&
											(fcoords.vz > (zmin - r)) &&
											(fcoords.vz < (zmax + r))
											)
											{
											// Inside local XZ grid - check local Y
											if 	(
												(fcoords.vy >= form_data->fd_height) &&
												(fcoords.vy <= form->fo_max_y)
												)
												{
												// local Y is within form Y bounds, and local old Y is NOT
												ReactFrogWithForm(	frog,
																	form,
																	form_data,
																	entity,
																	&fcoords,
																	&entity_transmatrix);
												}
											}
										}
									}
								}
							}
						}
					}
				next_entity:;
				}
			}
		}

	// Re-react with an entity if we are standing on it, and jumping along it

	// If the frog is jumping both from and to our entity (i.e. hopping along it)
	// then react to the form flags... this provides constant hit information.
	if	(
		(entity = frog->fr_entity) &&
		(live_entity = frog->fr_entity->en_live_entity)
		)
		{
		if	(
			(frog->fr_flags & FROG_JUMP_TO_ENTITY) &&
			(frog->fr_flags & FROG_JUMP_FROM_ENTITY)
			)
			{
			// Get all necessary information so we can react with our entities form(s)
			form		= ENTITY_GET_FORM(entity);
			form_data	= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];

			svec.vx = frog->fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0];
			svec.vy = frog->fr_lwtrans->t[1] - live_entity->le_lwtrans->t[1];
			svec.vz = frog->fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2];
			MRTransposeMatrix(live_entity->le_lwtrans, &entity_transmatrix);
			MRApplyMatrix(&entity_transmatrix, &svec, &fcoords);

			// Only react to forms if we are on the last frame of them jump. This is not a very
			// ellegant way of doing it, but it works. I'll probably remove it if Tim tells me 
			// a better way to do it.
			if 	(frog->fr_count == 1)
				{
				ReactFrogWithForm(	frog,
									form,
									form_data,
									frog->fr_entity,
									&fcoords,
									&entity_transmatrix);

				// set the flag to indicate frog has hit this entity
				if (Cheat_collision_toggle == FALSE)
					live_entity->le_flags |= (LIVE_ENTITY_HIT_FROG_0 << frog->fr_frog_id);
				}
			}
		}

collide_with_frog:;
	CollideFrogWithFrogs(frog);
}


/******************************************************************************
*%%%% CollideFrogWithCollPrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	CollideFrogWithCollPrims(
*						FROG*			frog,
*						LIVE_ENTITY*	entity,
*						FORM_BOOK*		form_book)
*
*	FUNCTION	Handle collision of frog with an entity's collision primitives
*
*	INPUTS		frog		-	ptr to FROG
*				live_entity	-	ptr to LIVE_ENTITY
*				form_book	-	ptr to FORM_BOOK for the LIVE_ENTITY
*
*	RESULT		TRUE if a successful collision is detected, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.97	Martin Kift		Created
*	26.06.97	Tim Closs		Added flipbook support, and fixed bug with
*								setting up MR_COLLCHECK structure
*
*%%%**************************************************************************/

MR_BOOL CollideFrogWithCollPrims(	FROG*			frog, 
									LIVE_ENTITY*	live_entity,
									FORM_BOOK*		form_book)
{
	MR_COLLCHECK	coll_check;
	MR_LONG			flags_a;
	MR_LONG			flags_b;
	MR_LONG			flags_c;

	// If the frog is currently marked as having hit a collprim, don't check any more?
	if (frog->fr_flags & FROG_JUMP_FROM_COLLPRIM)
		return TRUE;	

	// if no model, then return NOW (it could be a sprite or something)
	if (ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL)
		return FALSE;

	memset(&coll_check, 0x0, sizeof(MR_COLLCHECK));

	// Frog is an animated model
	// set up (a) part of the collision structure, includes the frog information
	MR_ASSERT(frog->fr_api_item);
	coll_check.mc_a_owner	= frog->fr_api_item;	// ptr to anim env
	coll_check.mc_a_size	= 1;					// number of hilites
	flags_a 				= COLL_A_FLAGS;

	// set up (b) part of the collision structure, includes the ENTITY information,
	// but only if we have a valid API object/anim ptr
	if (live_entity->le_api_item0)
		{
		coll_check.mc_b_owner		= live_entity->le_api_item0;
		coll_check.mc_b_owner_part 	= 0;
		coll_check.mc_b_size		= 1;
		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				flags_b = COLL_B_FLAGS_FLIPBOOK;
			else
				flags_b = COLL_B_FLAGS_ANIM;
			}
		else
			flags_b = COLL_B_FLAGS_STATIC;

#if 0		
		// specify full check for the frog 
		flags_c = (MR_COLLCHECK_C_FACE | MR_COLLCHECK_C_REFLECTION | MR_COLLCHECK_C_POINT);

		// Setup relative motion of the frog. Note that fr_velocity is 16.16
		coll_check.mc_relative_motion.vx = frog->fr_velocity.vx >> 16;
		coll_check.mc_relative_motion.vy = frog->fr_velocity.vy >> 16;
		coll_check.mc_relative_motion.vz = frog->fr_velocity.vz >> 16;
#else
		// specify no extra return information (such as relative motion etc)
		flags_c = 0;
#endif

		// Call API collision function...
		if (MRCollisionCheck(&coll_check, flags_a, flags_b, flags_c) == TRUE)
			{
			// A collision has been registered, so act upon it
			ReactFrogWithCollPrim(frog, live_entity, form_book, &coll_check);		

			// set the flag to indicate frog has hit this entity
			if (Cheat_collision_toggle == FALSE)
				live_entity->le_flags |= (LIVE_ENTITY_HIT_FROG_0 << frog->fr_frog_id);

			// return TRUE so code doesn't attempt to collide with entity FORMs!
			return TRUE;				
			}
		}

	// No collisions detected.
	return FALSE;
}


/******************************************************************************
*%%%% ReactFrogWithCollPrim
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ReactFrogWithCollPrim(
*						FROG*			frog,
*						LIVE_ENTITY*	live_entity,
*						FORM*			form,
*						MR_USHORT		reaction)
*
*	FUNCTION	Frog has hit a collision primitive on an entity, and now needs
*				to react accordingly
*
*	INPUTS		frog			-	frog to react
*				live_entity		-	live_entity hit
*				form			-	ptr to FORM of the LIVE_ENTITY
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ReactFrogWithCollPrim(	FROG*			frog,
								LIVE_ENTITY*	live_entity,
								FORM_BOOK*		form_book,
								MR_COLLCHECK*	coll_check)
{
	MR_USHORT			reaction;
	MR_ULONG			i;
	MR_ANIM_ENV_INST*	env_inst_ptr;
	MR_MESH_INST*		mesh_inst_ptr;
	MR_VEC				vec;

	// get reaction type from cp_user in the collprim collided with
	reaction = ((MR_COLLPRIM*)coll_check->mc_c_item_b)->cp_user;

	// kill particle effect, if in operation...
	FROG_KILL_PARTICLE_EFFECT(frog);

	switch (reaction)
		{
		case 0:
		case COLLPRIM_TYPE_DEADLY:
			// Get pointer to form
			form_book = ENTITY_GET_FORM_BOOK(live_entity->le_entity);

			// Hit nasty entity, start death anim...
			switch ( form_book->fb_type_of_death )
				{
				// Squished ...
				case FORM_DEATH_SQUISHED:

					// Do squished animation
					FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);

					// Are we in arcade mode ?
					if ( Sel_mode == SEL_MODE_ARCADE )
						{
						// Yes ... create a tyre mark sprite
						// Make Frog flat ( zero y column of matrix, so as to give model no height )
						frog->fr_lwtrans->m[1][0] = 0;
						frog->fr_lwtrans->m[1][1] = 0;
						frog->fr_lwtrans->m[1][2] = 0;

						// Remove Frog local OT
						for (i = 0; i < Game_total_viewports; i++)
							{
							env_inst_ptr	= (MR_ANIM_ENV_INST*)frog->fr_api_insts[i];
							mesh_inst_ptr 	= env_inst_ptr->ae_mesh_insts[0];
							mesh_inst_ptr->mi_ot = NULL;
							}
						}

					break;

				// Drown ...
				case FORM_DEATH_DROWN:
					// Do drown animation
					MR_SET_VEC(&vec, 0, 5<<16, 0);
					FrogKill(frog, FROG_ANIMATION_DROWN, &vec);
					break;

				// Bitten ...
				case FORM_DEATH_BITTEN:
					// Do bitten animation
					FrogKill(frog, FROG_ANIMATION_BITTEN, NULL);
					break;

				// Flop ...
				case FORM_DEATH_FLOP:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_FLOP, NULL);
					frog->fr_shadow->ef_flags |= EFFECT_NO_DISPLAY;
					break;

				// POP ...
				case FORM_DEATH_POP:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_POP, NULL);
					break;

				// Crash ...
				case FORM_DEATH_CRASH:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_CRASH, NULL);
					break;

				// Mowed ...
				case FORM_DEATH_MOWED:
					// Do mowed animation
					FrogKill(frog, FROG_ANIMATION_MOWN, NULL);
					break;

				// Do this death in case of no other ...
				default:
					// Do squished animation
					FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
					break;
				}
			break;

		case COLLPRIM_TYPE_BOUNCY:
			SetFrogUserMode(frog, FROGUSER_MODE_BOUNCE);
			break;

		case COLLPRIM_TYPE_FORM:
			// user callback
			if (form_book->fb_collprim_react)
				form_book->fb_collprim_react(frog, live_entity, coll_check);
			break;
		}
}

/******************************************************************************
*%%%% ReactFrogWithGridFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ReactFrogWithGridFlags(
*						FROG*		frog,
*						MR_USHORT	flags)
*
*	FUNCTION	Frog has landed on a grid square (land or FORM).  React
*				according to flags
*
*	INPUTS		frog	-	frog to react
*				flags	-	flags for reaction type
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.05.97	Tim Closs		Created
*	28.07.97	Martin Kift		Added particle and water code
*	21.08.97	Gary Richards	Added large ot offset for when dying in water.
*
*%%%**************************************************************************/

MR_VOID	ReactFrogWithGridFlags(	FROG*		frog,
								MR_USHORT	flags)
{
	MR_OBJECT*		sprite_ptr;
	MR_VEC			vec;
#ifdef PSX
	MR_ULONG		i;
	MR_OT**			local_ot_ptr;		// Pointer to frog->fr_ot[0];
#endif

	if (flags & GRID_SQUARE_USABLE)
		{
		if (flags & GRID_SQUARE_CLIFF)
			{
			// kill particle effect, if in operation...
			FROG_KILL_PARTICLE_EFFECT(frog);

			// Go into roll frog user mode, but only if control is active (i.e. frog hasn't
			// already died because of a huge jump)
			if (frog->fr_flags & FROG_CONTROL_ACTIVE)
				SetFrogUserMode(frog, FROGUSER_MODE_CLIFF_ROLL);

			// No reaction
			return;
			}
		// Something in this grid square
		if (flags & GRID_SQUARE_SAFE)
			{
			// kill particle effect, if in operation...
			FROG_KILL_PARTICLE_EFFECT(frog);

			// No reaction
			return;
			}
		if (flags & GRID_SQUARE_DEADLY)
			{
			// Kill frog
			MR_SET_VEC(&vec, 0, 5<<16, 0);
			FrogKill(frog, FROG_ANIMATION_DROWN, &vec);
			return;
			}
		if (flags & GRID_SQUARE_POPDEATH)
			{
			// Kill frog
			FrogKill(frog, FROG_ANIMATION_POP, NULL);
			return;
			}
		if (flags & GRID_SQUARE_WATER)
			{
			// Kill frog
			MR_SET_VEC(&vec, 0, 5<<16, 0);
			FrogKill(frog, FROG_ANIMATION_DROWN, &vec);
		
			// Clear velocity to stop it falling
//			MR_CLEAR_VEC(&frog->fr_velocity);

			sprite_ptr = MRCreate3DSprite((MR_FRAME*)frog->fr_lwtrans, MR_OBJ_STATIC, FrogSplashAnimList);
			sprite_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
			sprite_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x10;
			GameAddObjectToViewports(sprite_ptr);

			// Request particle effect for bubbleing
			if (!frog->fr_particle_api_item)
				frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_WATER_BUBBLE, NULL);

			// Play SFX when drown in water. 
			MRSNDPlaySound(SFX_GEN_FROG_DROWN2, NULL, 0, 0);

#ifdef PSX
			//Only on suburbia and original
			if ((Game_map_theme == THEME_ORG) || (Game_map_theme == THEME_SUB))
				{
				// Set frog to have a LARGE ot position, so he appears below the env_map.
				i = Game_total_viewports;
				local_ot_ptr = frog->fr_ot;
				while(i--)
					{
					local_ot_ptr[0]->ot_flags |= MR_OT_FORCE_BACK;
					local_ot_ptr++;
					}
				}
#endif	
			return;
			}
		if (flags & GRID_SQUARE_SLIPPY)
			{
			SetFrogUserMode(frog, FROGUSER_MODE_SLIPPING_LAND_GRID);
			return;
			}
		if (flags & GRID_SQUARE_SIMPLE_SLIPPY)
			{
			SetFrogUserMode(frog, FROGUSER_MODE_SIMPLE_SLIPPING_LAND_GRID);
			return;
			}
		if (flags & GRID_SQUARE_FREEFORM_SLIPPY)
			{
			SetFrogUserMode(frog, FROGUSER_MODE_SLIPPING_LAND_NONGRID);
			return;
			}
		if (flags & GRID_SQUARE_BOUNCY)
			{
			// kill particle effect, if in operation...
			FROG_KILL_PARTICLE_EFFECT(frog);

			// go into froguser mode for bounce
			SetFrogUserMode(frog, FROGUSER_MODE_BOUNCE);

			return;
			}
		}	
}


/******************************************************************************
*%%%% ReactFrogWithForm
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ReactFrogWithForm(
*						FROG*			frog,
*						FORM*			form,
*						FORM_DATA*		form_data,
*						ENTITY*			entity,
*						MR_VEC*			frog_vec,
*						MR_MAT*			entity_transmatrix)
*
*	FUNCTION	Frog has collided with form - effect reaction
*
*	INPUTS		frog				-	ptr to FROG
*				form				-	ptr to FORM
*				form_data			-	ptr to FORM_DATA
*				entity				-	ptr to owning ENTITY
*				frog_vec			-	ptr to form->frog offset in entity coords
*				entity_transmatrix	-	ptr to transpose of entity lwtrans
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Tim Closs		Created
*	02.05.97	Tim Closs		Changed for new grid forms
*	10.05.97	Martin Kift		Added entity->frog hit flag code...
*	21.05.97	Martin Kift		Updated check point code.
*	15.07.97	Martin Kift		Fixed soft landing code.
*
*%%%**************************************************************************/

MR_VOID	ReactFrogWithForm(	FROG*			frog,
							FORM*			form,
							FORM_DATA*		form_data,
							ENTITY*			entity,
							MR_VEC*			frog_vec,
							MR_MAT*			entity_transmatrix)
{
	ENTITY_BOOK*	entity_book;
	LIVE_ENTITY*	live_entity;
	MR_VEC			vec;
	MR_SVEC			svec;
	MR_LONG			height, x, z, l;
	MR_USHORT		flags;
	CAMERA*			camera;
	FORM_BOOK*		form_book;
	MR_BOOL			frog_centring;
	MR_MAT			ent_proj_mat;
	MR_MAT			ent_proj_mat_trans;

	live_entity = entity->en_live_entity;
	camera		= &Cameras[frog->fr_frog_id];
	form_book	= ENTITY_GET_FORM_BOOK(entity);

	// Calculate the grid square we are in
	x 		= (frog_vec->vx - form->fo_xofs) >> 8;
	z 		= (frog_vec->vz - form->fo_zofs) >> 8;
	flags	= form_data->fd_grid_squares[(z * form->fo_xnum) + x];

	// Get height according to FORM type
	switch(form_data->fd_height_type)
		{
		case FORM_DATA_HEIGHT_TYPE_GRID:
			height = form_data->fd_height;
			break;
	
		case FORM_DATA_HEIGHT_TYPE_SQUARE:
			height = form_data->fd_heights[(z * form->fo_xnum) + x];
			break;
	
		default:
			height = 0;
#ifdef	DEBUG
			MR_ASSERTMSG(NULL, "FORM_DATA type not implemented");
#endif
		}

	if (flags & GRID_SQUARE_USABLE)
		{
		// There is something here...
		if (flags & GRID_SQUARE_CHECKPOINT)
			{
			// Hit check point
			//
			// Must be stationary or jumping to land
			if	(
				(frog->fr_mode == FROG_MODE_STATIONARY) ||
				(frog->fr_mode == FROGUSER_MODE_SLIPPING_LAND_GRID) ||
				(frog->fr_mode == FROGUSER_MODE_SLIPPING_LAND_NONGRID) ||
				(frog->fr_mode == FROGUSER_MODE_SIMPLE_SLIPPING_LAND_GRID) ||
				(frog->fr_flags & FROG_JUMP_TO_LAND)
				)
				{
				if (frog->fr_entity)
					{
					if	(
						(frog->fr_entity != entity) &&
						(!(frog->fr_flags & FROG_ON_ENTITY))
						)
						{
						// Frog is still linked to an entity, but is not sitting on the entity
						//
						// (Camera_mod) = (Camera_mod * old_entity(projected))
						ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &ent_proj_mat);
						MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat);

						// (Camera_mod) = (Camera_mod / new_entity(projected)trans)
//						ProjectMatrixOntoWorldXZ(entity->en_live_entity->le_lwtrans, &ent_proj_mat);
//						MRTransposeMatrix(&ent_proj_mat, &ent_proj_mat_trans);
//						MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat_trans);
						frog->fr_entity = NULL;
						}
					}
				FrogCollectCheckPoint(frog, entity);
				}
			else
				{
				return;
				}
			}
		else
		if 	(flags & GRID_SQUARE_SAFE)
			{
			// If the entity is too vertical in the world, bail out
			if	((MR_SQR(live_entity->le_lwtrans->m[0][2]) + MR_SQR(live_entity->le_lwtrans->m[2][2])) < COLLIDE_ENTITY_TOO_VERTICAL_EPSILON2)
				return;

			// Only do alignment if we are NOT jumping across a single entity?
			if (!(frog->fr_flags & FROG_JUMP_TO_ENTITY) ||
				!(frog->fr_flags & FROG_JUMP_FROM_ENTITY))
				{
				// Consider height we have fallen
				if (!(flags & GRID_SQUARE_SOFT))
					FrogReactToFallDistance(frog, frog->fr_lwtrans->t[1] - frog->fr_old_y);
				else
					{
					// Frog is OK
					frog->fr_mode 		= FROG_MODE_STATIONARY;

					// go back into pant mode
					FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
					}

				entity_book	= ENTITY_GET_ENTITY_BOOK(entity);

				frog->fr_entity_grid_x	= x;
				frog->fr_entity_grid_z	= z;

				frog->fr_entity_ofs.vx 	= frog_vec->vx	<< 16;
				frog->fr_entity_ofs.vy 	= height		<< 16;
				frog->fr_entity_ofs.vz 	= frog_vec->vz	<< 16;

				//-------------------------------------------------------------------------
				// Centring code
				//-------------------------------------------------------------------------
				// If frogger is at the end of a form (along a particular axes), centring will always occur along that axis.
				// Otherwise, centring will occur along that axis UNLESS FORM_BOOK_FROG_NO_CENTRING_? is set

				// To start with, centring target is current pos
				frog->fr_target_pos.vx 	= frog_vec->vx;
				frog->fr_target_pos.vy 	= height;
				frog->fr_target_pos.vz 	= frog_vec->vz;
				frog_centring			= FALSE;

				// Consider local X
				if	(
					(!(form_book->fb_flags & FORM_BOOK_FROG_NO_CENTRING_X)) ||
					(frog_vec->vx > ( (form->fo_xnum - 1) * 0x80)) ||
					(frog_vec->vx < (-(form->fo_xnum - 1) * 0x80))
					)
					{
					// Centre along local X
					frog->fr_target_pos.vx 	= form->fo_xofs + (x << 8) + 0x80;
					frog_centring			= TRUE;
					}
				// Consider local Z
				if	(
					(!(form_book->fb_flags & FORM_BOOK_FROG_NO_CENTRING_Z)) ||
					(frog_vec->vz > ( (form->fo_znum - 1) * 0x80)) ||
					(frog_vec->vz < (-(form->fo_znum - 1) * 0x80))
					)
					{
					// Centre along local Z
					frog->fr_target_pos.vz 	= form->fo_zofs + (z << 8) + 0x80;
					frog_centring			= TRUE;
					}

				if (frog_centring == TRUE)
					{
					if	(
						(abs(frog->fr_target_pos.vx - frog_vec->vx) >= FROG_CENTRING_ANIMATION_TOLERANCE) ||
						(abs(frog->fr_target_pos.vz - frog_vec->vz) >= FROG_CENTRING_ANIMATION_TOLERANCE)
						)
						{
						// Play centring anim
						FrogRequestAnimation(frog, FROG_ANIMATION_STRUGGLE, 0, 0);
						}
					else
						{
#ifdef DEBUG
						frog_centring = FALSE;
#endif
						FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
						}
					svec.vx 				= frog->fr_target_pos.vx - (frog->fr_entity_ofs.vx >> 16);
					svec.vy 				= frog->fr_target_pos.vy - (frog->fr_entity_ofs.vy >> 16);
					svec.vz 				= frog->fr_target_pos.vz - (frog->fr_entity_ofs.vz >> 16);
					l 						= MR_SVEC_MOD(&svec);					 
	
					frog->fr_mode			= FROG_MODE_CENTRING;
	
					frog->fr_count			= (l / FROG_CENTRING_SPEED) + 1;
					frog->fr_velocity.vx 	= (svec.vx << 16) / frog->fr_count;
					frog->fr_velocity.vy 	= (svec.vy << 16) / frog->fr_count;
					frog->fr_velocity.vz 	= (svec.vz << 16) / frog->fr_count;
	
					svec.vx					= frog->fr_entity_ofs.vx >> 16;
					svec.vy					= frog->fr_entity_ofs.vy >> 16;
					svec.vz					= frog->fr_entity_ofs.vz >> 16;
					MRApplyMatrix(live_entity->le_lwtrans, &svec, &vec);
					frog->fr_pos.vx			= (live_entity->le_lwtrans->t[0] + vec.vx) << 16;
					frog->fr_pos.vy			= (live_entity->le_lwtrans->t[1] + vec.vy) << 16;
					frog->fr_pos.vz			= (live_entity->le_lwtrans->t[2] + vec.vz) << 16;
					}
				//-------------------------------------------------------------------------
				// End of centring code
				//-------------------------------------------------------------------------
	
				UpdateFrogPositionalInfo(frog);
				frog->fr_y				= frog->fr_lwtrans->t[1];
				frog->fr_old_y			= frog->fr_y;
			
				if (!(form_book->fb_flags & FORM_BOOK_FROG_NO_ROTATION_SNAPPING))
					{
					// Snap frog rotation
					frog->fr_old_direction	= frog->fr_direction;
					frog->fr_direction		= SnapFrogRotationToMatrix(frog, live_entity->le_lwtrans, entity_transmatrix);
					}
				else
					{
					// Snap frog (with no rotation)
					SnapFrogToMatrix(frog, live_entity->le_lwtrans);
					}

				if (!(form_book->fb_flags & FORM_BOOK_FROG_NO_ENTITY_ANGLE))
					{			
					// Work out which direction, relative to the entity, that UP will take us
					MR_SVEC_EQUALS_VEC(&svec, &camera->ca_direction_vectors[FROG_DIRECTION_N]);
					MRApplyMatrix(entity_transmatrix, &svec, &vec);
					if (abs(vec.vz) > abs(vec.vx))
						{
						if (vec.vz > 0)
							{
							// UP is N
							frog->fr_entity_angle = FROG_DIRECTION_N;
							}
						else
							{
							// UP is S
							frog->fr_entity_angle = FROG_DIRECTION_S;
							}
						}
					else
						{
						if (vec.vx > 0)
							{
							// UP is E
							frog->fr_entity_angle = FROG_DIRECTION_E;
							}
						else
							{
							// UP is W
							frog->fr_entity_angle = FROG_DIRECTION_W;
							}
						}
					}

				frog->fr_flags 	&= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
 				frog->fr_flags 	|= FROG_ON_ENTITY;

				// Store transform (current frog / current entity)
				MRMulMatrixABC(frog->fr_lwtrans, entity_transmatrix, &frog->fr_entity_transform);
				ProjectMatrixOntoWorldXZ(&frog->fr_entity_transform, &frog->fr_entity_transform);
			
				// If we are currently applying a camera mod to an entity, new mod should be:
				// (Camera_mod * old_entity) / (new_entity)
				if (frog->fr_entity)
					{
					if (frog->fr_entity != entity)
						{
						// (Camera_mod) = (Camera_mod * old_entity(projected))
						ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &ent_proj_mat);
						MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat);

						// (Camera_mod) = (Camera_mod / new_entity(projected)trans)
						ProjectMatrixOntoWorldXZ(entity->en_live_entity->le_lwtrans, &ent_proj_mat);
						MRTransposeMatrix(&ent_proj_mat, &ent_proj_mat_trans);
						MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat_trans);
						}
					}
				else
					{
					// (Camera_mod) = (Camera_mod / new_entity(projected)trans)
					ProjectMatrixOntoWorldXZ(entity->en_live_entity->le_lwtrans, &ent_proj_mat);
					MRTransposeMatrix(&ent_proj_mat, &ent_proj_mat_trans);
					MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat_trans);
					}

				if (!(form_book->fb_flags & FORM_BOOK_FROG_NO_ROTATION_SNAPPING))
					SetupCameraYRotation(camera);

				frog->fr_entity	= entity;

				// set flag so that live_entity knows which frog has sat on it!
				live_entity->le_flags |= (LIVE_ENTITY_CARRIES_FROG_0 << frog->fr_frog_id);
				}
//		if (flags & GRID_SQUARE_CHECKPOINT)
//			{
//			// Hit check point
//			FrogCollectCheckPoint(frog, entity);
//			}
			}
		else
		if (flags & GRID_SQUARE_POPDEATH)
			{
			FrogKill(frog,FROG_ANIMATION_POP, NULL);
			}
		else
		if (flags & GRID_SQUARE_DEADLY)
			{
			// Get pointer to form
			form_book = ENTITY_GET_FORM_BOOK(entity);

			// Hit nasty entity, start death anim...
			switch ( form_book->fb_type_of_death )
				{
				// Squished ...
				case FORM_DEATH_SQUISHED:
					// Do squished animation
					FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
					break;

				// Drown ...
				case FORM_DEATH_DROWN:
					// Do drown animation
					MR_SET_VEC(&vec, 0, 5<<16, 0);
					FrogKill(frog, FROG_ANIMATION_DROWN, &vec);
					break;

				// Bitten ...
				case FORM_DEATH_BITTEN:
					// Do bitten animation
					FrogKill(frog, FROG_ANIMATION_BITTEN, NULL);
					break;

				// Flop ...
				case FORM_DEATH_FLOP:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_FLOP, NULL);
					frog->fr_shadow->ef_flags |= EFFECT_NO_DISPLAY;
					break;

				// POP ...
				case FORM_DEATH_POP:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_POP, NULL);
					break;

				// Crash ...
				case FORM_DEATH_CRASH:
					// Do flop animation
					FrogKill(frog, FROG_ANIMATION_CRASH, NULL);
					break;

				// Mowed ...
				case FORM_DEATH_MOWED:
					// Do mowed animation
					FrogKill(frog, FROG_ANIMATION_MOWN, NULL);
					break;

				// Do this death in case of no other ...
				default:
					// Do squished animation
					FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
					break;
				}

			}	
		else
		if (flags & GRID_SQUARE_SLIPPY)
			{
			;	// not a lot happening here.
			}
		else 
		if (flags & GRID_SQUARE_BOUNCY)
			{
			frog->fr_forbid_entity = entity;

			// Cheat and set frog to center of entity bouncing off
			if (entity->en_live_entity)
				{
				frog->fr_pos.vx = entity->en_live_entity->le_lwtrans->t[0] << 16;
				frog->fr_pos.vz = entity->en_live_entity->le_lwtrans->t[2] << 16;
				UpdateFrogPositionalInfo(frog);
				}
			SetFrogUserMode(frog, FROGUSER_MODE_BOUNCE);
			}
		}
	else
		{
		// Grid square is not usable: frog falls
		return;
		}
	
	// set the flag to indicate frog has hit this entity
	if (Cheat_collision_toggle == FALSE)
		live_entity->le_flags |= (LIVE_ENTITY_HIT_FROG_0 << frog->fr_frog_id);
}


/******************************************************************************
*%%%% CollideEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	CollideEntity(
*						LIVE_ENTITY*	live_entity,
*						ENTITY**		coll_entity_pptr)
*
*	FUNCTION	Handle collision of live_entities with other live_entities
*
*	INPUTS		live_entity		-	ptr to live_entity
*				coll_entity		-	ptr to ptr to entity (which is filled in on
*									successful collision)
*
*	RESULTS		TRUE if theres a collision detected, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.05.97	Martin Kift		Created
*	17.05.97	Martin Kift		Updated to use linked lists of entities
*	03.06.97	Martin Kift		Recoded to remove params and do a move expansive
*								check for entities in surrounding grid squares,
*								also moved most of code out to single entity func.
*
*%%%**************************************************************************/

MR_BOOL	CollideEntity(LIVE_ENTITY*	live_entity,
					  ENTITY**		coll_entity_pptr)
{
	MAP_GROUP*		map_group;
	MR_LONG			x, z;
	MR_LONG			mg_xmin, mg_xmax, mg_zmin, mg_zmax;
	ENTITY*			entity;
	LIVE_ENTITY*	check_live_entity;

	// Check for entity collision
	//
	// Calculate MAP_GROUP live_entity is in!
	// This will have to be expanded to check (max of) 3x3 MAP_GROUPs
	//
	x 			= (live_entity->le_lwtrans->t[0] - Map_view_basepoint.vx) / Map_view_xlen;
	z 			= (live_entity->le_lwtrans->t[2] - Map_view_basepoint.vz) / Map_view_zlen;
	mg_xmin		= MAX(0, x - 1);
	mg_xmax		= MIN(Map_view_xnum - 1, x + 1);
	mg_zmin		= MAX(0, z - 1);
	mg_zmax		= MIN(Map_view_znum - 1, z + 1);

	// Loop for 3x3 map groups
	for (z = mg_zmin; z <= mg_zmax; z++)
		{
		for (x = mg_xmin; x <= mg_xmax; x++)
			{
			map_group = &Map_groups[(z * Map_view_xnum) + x];

			entity = map_group->mg_entity_root_ptr;
			while(entity = entity->en_next)
				{
				// Is entity LIVE?
				if (check_live_entity = entity->en_live_entity)
					{
					// Do a entity to entity collision check
					if (CollideEntityWithEntity(live_entity, check_live_entity))
						{
						// Collision found, store results and return
						*coll_entity_pptr = check_live_entity->le_entity;
						return TRUE;
						}
					}
				}
			}
		}
	// No collision
	return FALSE;
}


/******************************************************************************
*%%%% CollideEntityWithEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	CollideEntityWithEntity(
*						LIVE_ENTITY*	live_entity,
*						LIVE_ENTITY*	check_live_entity)
*
*	FUNCTION	Handle collision of a live_entity with a single other entity.
*
*	INPUTS		live_entity		-	ptr to live_entity
*				entity			-	ptr to entity being checked against
*
*	RESULTS		TRUE if theres a collision detected, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL	CollideEntityWithEntity(LIVE_ENTITY*	live_entity, 
								LIVE_ENTITY*	check_live_entity)
{
	MR_LONG			xmin, xmax, zmin, zmax, r;
	MR_SVEC			svec;
	MR_VEC			fcoords;
	MR_MAT			entity_transmatrix;
	FORM_BOOK*		form_book0;
	FORM_BOOK*		form_book1;
	MR_LONG			distance;
	FORM*			form;
	FORM_DATA*		form_data;
	ENTITY*			check_entity;

	MR_ASSERT (check_live_entity);

	check_entity	= check_live_entity->le_entity;
	form			= ENTITY_GET_FORM(check_entity);
	r				= 0;

	if (form->fo_numformdatas)
		{					
		form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];

		// First do a sphere check (using precalculated values from the form book) to
		// see if its worth while doing a collision check at all...
		svec.vx = live_entity->le_lwtrans->t[0] - check_live_entity->le_lwtrans->t[0];
		svec.vy = live_entity->le_lwtrans->t[1] - check_live_entity->le_lwtrans->t[1];
		svec.vz = live_entity->le_lwtrans->t[2] - check_live_entity->le_lwtrans->t[2];
		distance = MR_SVEC_MOD_SQR(&svec);

		form_book0 	= ENTITY_GET_FORM_BOOK(live_entity->le_entity);
		form_book1	= ENTITY_GET_FORM_BOOK(check_live_entity->le_entity);
		if (distance < (form_book0->fb_radius2 + form_book1->fb_radius2))
			{
			form = ENTITY_GET_FORM(check_entity);

			if (form->fo_numformdatas)
				{					
				form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
			
				// Put colliding live_entity origin in entity frame
				MRTransposeMatrix(check_live_entity->le_lwtrans, &entity_transmatrix);
				MRApplyMatrix(&entity_transmatrix, &svec, &fcoords);
						
				// Check against FORM grid bounds
				xmin = form->fo_xofs;
				xmax = form->fo_xofs + (form->fo_xnum << 8);
				zmin = form->fo_zofs;
				zmax = form->fo_zofs + (form->fo_znum << 8);
				if	(
					(fcoords.vx >= (xmin - r)) &&
					(fcoords.vx <= (xmax + r)) &&
					(fcoords.vz >= (zmin - r)) &&
					(fcoords.vz <= (zmax + r))
					)
					{
					// Inside local XZ grid - check local Y
					if 	(
						(fcoords.vy >= form_data->fd_height) &&
						(fcoords.vy <= form->fo_max_y)
						)
						{
						// <= height of grid by small amount... collision
						return TRUE;
						}
					}				
				}
			}
		}

	// No collision
	return FALSE;
}


/******************************************************************************
*%%%% CollideFrogWithFrogs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CollideFrogWithFrogs(
*						FROG*	frog)
*
*	FUNCTION	Collide frog with other frogs
*
*	INPUTS		frog	-	ptr to FROG to collide
*
*	NOTES		Collide with ALL frogs which are stationary
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Tim Closs		Created
*	26.06.97	Tim Closs		Completely revised
*
*%%%**************************************************************************/

MR_VOID	CollideFrogWithFrogs(FROG*	frog)
{
	FROG*		frog_b;
	FROG*		frog_s;
	MR_LONG		i;
	MR_SVEC		svec;
	MR_VEC		vec;
	MR_MAT		transpose;
	MR_MAT		entity_transmatrix;
	CAMERA*		camera;
	FORM_BOOK*	form_book;
	MR_MAT		ent_proj_mat;
	MR_MAT		ent_proj_mat_trans;


	if	(
		(frog->fr_stack_slave == NULL) &&
		(frog->fr_stack_master == NULL)
		)
		{
		frog_b 	= Frogs;
		i		= Game_total_players;
		camera 	= &Cameras[frog->fr_frog_id];

		while(i--)
			{
			// Look for collision with a slave
			if	(
				(frog_b != frog) &&
				(frog_b->fr_mode != FROG_MODE_JUMPING)
				)
				{
				MRTransposeMatrix(frog_b->fr_lwtrans, &transpose);
				if (CheckFrogStackCollision(frog, frog_b, &transpose) == TRUE)
					{
					// Move to top of stack
					while(frog_b->fr_stack_master)
						frog_b = frog_b->fr_stack_master;

					// frog_b is now top of stack we have collided with
					frog->fr_stack_slave	= frog_b;
					frog_b->fr_stack_master	= frog;
					frog->fr_flags			&= ~FROG_LANDED_ON_LAND_CLEAR_MASK;

					if (frog_b->fr_flags & FROG_ON_ENTITY)
						{
						form_book 	= ENTITY_GET_FORM_BOOK(frog_b->fr_entity);
						MRTransposeMatrix(frog_b->fr_entity->en_live_entity->le_lwtrans, &entity_transmatrix);
						if (!(form_book->fb_flags & FORM_BOOK_FROG_NO_ROTATION_SNAPPING))
							{
							// Make frog master 90 degree rotation about slave entity matrix
							frog->fr_old_direction	= frog->fr_direction;
							frog->fr_direction		= SnapFrogRotationToMatrix(frog, frog_b->fr_entity->en_live_entity->le_lwtrans, &entity_transmatrix);
							}

						if (!(form_book->fb_flags & FORM_BOOK_FROG_NO_ENTITY_ANGLE))
							{			
							// Work out which direction, relative to the entity, that UP will take us
							MR_SVEC_EQUALS_VEC(&svec, &camera->ca_direction_vectors[FROG_DIRECTION_N]);
							MRApplyMatrix(&entity_transmatrix, &svec, &vec);
							if (vec.vz >= 0x800)
								{
								// UP will take us (local N) on entity
								frog->fr_entity_angle = FROG_DIRECTION_N;
								}
							else
							if (vec.vz < -0x800)
								{
								// UP will take us (local N) on entity
								frog->fr_entity_angle = FROG_DIRECTION_S;
								}
							else
							if (vec.vx >= 0x800)
								{
								// UP will take us (local E) on entity
								frog->fr_entity_angle = FROG_DIRECTION_E;
								}
							else
								{
								// UP will take us (local W) on entity
								frog->fr_entity_angle = FROG_DIRECTION_W;
								}
							}
						}
					else
						{
						// Make frog master 90 degree rotation about slave matrix
						SnapFrogRotationToMatrix(frog, frog_b->fr_lwtrans, &transpose);
						}

					// Store (master lwtrans / slave lwtrans)
					MRMulMatrixABC(frog->fr_lwtrans, &transpose, &frog->fr_stack_mod_matrix);

					if (frog_b->fr_flags & FROG_ON_ENTITY)
						{
						// Slave is on entity: master must be set up to be on entity also
						frog->fr_flags	|= FROG_ON_ENTITY;

						MR_COPY_VEC(&frog->fr_entity_ofs, &frog_b->fr_entity_ofs);
						frog->fr_entity_grid_x	= frog_b->fr_entity_grid_x;
						frog->fr_entity_grid_z	= frog_b->fr_entity_grid_z;
						MRMulMatrixABC(&frog->fr_stack_mod_matrix, &frog_b->fr_entity_transform, &frog->fr_entity_transform);

						// If we are currently applying a camera mod to an entity, new mod should be:
						// (Camera_mod * old_entity) / (new_entity)
						if (frog->fr_entity)
							{
							if (frog->fr_entity != frog_b->fr_entity)
								{
								// (Camera_mod) = (Camera_mod * old_entity(projected))
								ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &ent_proj_mat);
								MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat);
		
								// (Camera_mod) = (Camera_mod / new_entity(projected)trans)
								ProjectMatrixOntoWorldXZ(frog_b->fr_entity->en_live_entity->le_lwtrans, &ent_proj_mat);
								MRTransposeMatrix(&ent_proj_mat, &ent_proj_mat_trans);
								MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat_trans);

//								MRMulMatrixABA(&camera->ca_mod_matrix, frog->fr_entity->en_live_entity->le_lwtrans);
//								MRMulMatrixABA(&camera->ca_mod_matrix, &entity_transmatrix);
								}
							}
						else
							{
							// (Camera_mod) = (Camera_mod / new_entity(projected)trans)
							ProjectMatrixOntoWorldXZ(frog_b->fr_entity->en_live_entity->le_lwtrans, &ent_proj_mat);
							MRTransposeMatrix(&ent_proj_mat, &ent_proj_mat_trans);
							MRMulMatrixABA(&camera->ca_mod_matrix, &ent_proj_mat_trans);

//							MRMulMatrixABA(&camera->ca_mod_matrix, &entity_transmatrix);
							}
						frog->fr_entity	= frog_b->fr_entity;
						}

					frog->fr_mode = FROG_MODE_STACK_MASTER;

					// Find the bottom slave, and set up the squash count
					frog_s = frog_b;
					while(frog_s->fr_stack_slave)
						frog_s = frog_s->fr_stack_slave;
					frog_s->fr_stack_count = FROG_STACK_SQUASH_TIME - 1;

					UpdateFrogStackMaster(frog_b, frog_s);

					// Play squish sound/anims
					MRSNDPlaySound(SFX_GEN_FROG_COLL_STACK, NULL, 0, 0);
					return;
					}
				}
			frog_b++;
			}
		}	
}


/******************************************************************************
*%%%% CheckFrogStackCollision
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	result =	CheckFrogStackCollision(
*									FROG*	frog_a,
*									FROG*	frog_b,
*									MR_MAT*	frog_b_transpose)
*
*	FUNCTION	Check if frog_a is in collision with frog_b
*
*	INPUTS		frog_a				-	ptr to FROG a
*				frog_b				-	ptr to FROG b
*				frog_b_transpose	-	ptr to transpose of frog_b->fr_lwtrans
*
*	RESULT		result	-	TRUE if in collision
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_BOOL	CheckFrogStackCollision(FROG*	frog_a,
								FROG*	frog_b,
								MR_MAT*	frog_b_transpose)
{
	MR_VEC	vec;
	MR_VEC	vec2;
	MR_SVEC	svec;
	MR_SVEC	svec2;
	MR_LONG	d;


	MR_ASSERT(frog_a);
	MR_ASSERT(frog_b);

	svec.vx = frog_a->fr_lwtrans->t[0] - frog_b->fr_lwtrans->t[0];
	svec.vy = frog_a->fr_lwtrans->t[1] - frog_b->fr_lwtrans->t[1];
	svec.vz = frog_a->fr_lwtrans->t[2] - frog_b->fr_lwtrans->t[2];
	MRApplyMatrix(frog_b_transpose, &svec, &vec);

	// vec is vector from frog_b origin to frog_a origin in frog_b frame
	if	(
#ifdef BUILD_49
		(vec.vy > -(FROG_STACK_COLLISION_HEIGHT)) &&
#else
		(vec.vy >= -(FROG_STACK_COLLISION_HEIGHT + 10)) &&
#endif
		(abs(vec.vx) < 0x40) &&
		(abs(vec.vz) < 0x40)
		)
		{
		// In collision.  Check dot product of b->a with velocity of a, all in b's frame
		// (vec is b->a in b's frame)
		if 	(
			(frog_a->fr_entity) &&
			(!(frog_a->fr_flags & FROG_JUMP_TO_LAND))
			)
			{
			// frog->fr_velocity is relative to entity
			svec.vx = frog_a->fr_velocity.vx >> 16;
			svec.vy = frog_a->fr_velocity.vy >> 16;
			svec.vz = frog_a->fr_velocity.vz >> 16;
			MRApplyMatrixSVEC(frog_a->fr_entity->en_live_entity->le_lwtrans, &svec, &svec2);
			}
		else	
			{
			svec2.vx = frog_a->fr_velocity.vx >> 16;
			svec2.vy = frog_a->fr_velocity.vy >> 16;
			svec2.vz = frog_a->fr_velocity.vz >> 16;
			}
		MRApplyMatrix(frog_b_transpose, &svec2, &vec2);

		d = MR_VEC_DOT_VEC(&vec, &vec2);
		if (d <= 0)
			return(TRUE);
		}
	return(FALSE);
}


/******************************************************************************
*%%%% ValidForm
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL ValidForm(	
*								MR_ULONG*		form_list_ptr,
*								MR_USHORT		num_forms,
*								MR_USHORT		form_id,
*
*	FUNCTION	This function walks through th supplied list of form ids, and if
*				the requested form appears in this list, success (TRUE) is
*				returned, else FALSE.
*
*	INPUTS		form_list_ptr	- ptr to list of form id's
*				num_forms		- number of forms in list
*				form_id			- form id looked for
*
*	RESULTS		TRUE if found, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL ValidForm(	MR_ULONG*	form_list_ptr,
					MR_ULONG	num_forms,
					MR_ULONG	form_id)
{
	while (num_forms--)
	{
		if (*form_list_ptr++ == form_id)
			return TRUE;
	}
	return FALSE;
}


/******************************************************************************
*%%%% VisibilityCollisionCheck
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG VisibilityCollisionCheck(	
*								MR_MAT*					matrix, 
*								MR_VEC*					direction_vec,
*								COLL_VISIBILITY_INFO*	vis_info,
*								COLL_VISIBILITY_DATA*	vis_data)
*
*	FUNCTION	This function walks through all *visible* entities and does a 
*				basic coll check, but only if it matches the required FORM(s) 
*				types if a form list is provided.
*
*	INPUTS		matrix			- ptr to matrix of entity being checked
*				direction_vec	- vector direction entity is looking
*				vis_info		- visibility info structure
*				vis_data		- visibility data (filled in with collision info)
*
*	RESULTS		Number of collisions found, else zero.
*
*	NOTES		This function doesn't just return after the first collision, 
*				because several could potentially happen :/ Therefore a list 
*				is build up, up to a maximum of defined in vis_info.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_LONG	VisibilityCollisionCheck(	MR_MAT*					matrix, 
									MR_VEC*					direction_vec,
									COLL_VISIBILITY_INFO*	vis_info,
									COLL_VISIBILITY_DATA*	vis_data)
{
	COLL_VISIBILITY_DATA*	vis_data_ptr;
	MR_LONG					v, x, z;
	MR_LONG					xmin, xmax, zmin, zmax, distance;
	MR_ULONG				num_hits;
	MR_VEC					position, normal;
	MR_LONG					steps, max_steps;
	MR_VEC					target;
	MAP_GROUP*				map_group;
	ENTITY*					entity;
	LIVE_ENTITY*			live_entity;
	FORM*					form;
	FORM_DATA*				form_data;
	MR_SVEC					svec;
	MR_VEC					fcoords, vec;
	MR_MAT					entity_transmatrix;
	FORM_BOOK*				form_book;
	FROG*					frog;

	// Initialise
	num_hits		= 0;
	vis_data_ptr	= vis_data;

	// copy the matrix position into a working matrix
	MR_COPY_VEC(&position, (MR_VEC*)matrix->t);

	// Find target vector, and normal of vector
	MR_ADD_VEC_ABC((MR_VEC*)matrix->t, direction_vec, &target);
	MRNormaliseVEC(direction_vec, &normal);

	// work out number of required steps
	max_steps 	= MAX((abs(target.vx - matrix->t[0]) >> 4), (abs(target.vy - matrix->t[1]) >> 4));
	max_steps 	= MAX(max_steps, (abs(target.vz - matrix->t[2]) >> 4));	

	steps 		= max_steps;
	while (steps--)
		{
		// Update position
		position.vx += (normal.vx << 4) >> MR_FP_MAT;
		position.vy += (normal.vy << 4) >> MR_FP_MAT;
		position.vz += (normal.vz << 4) >> MR_FP_MAT;

		// Get current grid
		x	= (position.vx - Map_view_basepoint.vx) / Map_view_xlen;
		z	= (position.vz - Map_view_basepoint.vz) / Map_view_zlen;

		// Is grid visible?
		if ((x < 0) ||
			(x > Map_view_xnum - 1) ||
			(z < 0) ||
			(z > Map_view_znum - 1)
			)
			{
			return num_hits;
			}

		// Check for frog(s) first
		xmin = 0;
		frog = &Frogs[0];

		while (xmin < 4)
			{
			if (frog->fr_flags & FROG_ACTIVE)
				{
				MR_SUB_VEC_ABC((MR_VEC*)frog->fr_lwtrans->t, &position, &vec);
				v = MR_VEC_MOD_SQR(&vec);

				// Interpret calculation as: master (frog) has 0 coll radius, slave (frog_b) has non-0 coll radius
				if (v <= MR_SQR(FROG_STACK_MASTER_RADIUS))
					{
					// setup data for this collision 
					MR_COPY_VEC(&vis_data_ptr->hit_position, &position);	// position
					vis_data_ptr->hit_entity		= frog;					// hit entity
					vis_data_ptr->hit_entity_frog	= TRUE;					// mark hit entity as a frog

					// update coll struct counter, and check for limit
					if (++num_hits >= vis_info->max_vis_entities)
						return num_hits;

					// update coll struct to next element and continue
					vis_data_ptr++;
					}

				}
			frog++;
			xmin++;
			}

		map_group = &Map_groups[(z * Map_view_xnum) + x];
		entity = map_group->mg_entity_root_ptr;
		while(entity = entity->en_next)
			{
			// Is entity LIVE?
			if (live_entity = entity->en_live_entity)
				{
				// Is this an entity we should be checking?
		        if (ValidForm(vis_info->form_ids_ptr, vis_info->num_forms, entity->en_form_book_id))
					{
					// dont continue if no collision has been requested
					if (!(entity->en_flags & ENTITY_NO_COLLISION))
						{
						form_book	= ENTITY_GET_FORM_BOOK(entity);
						form		= ENTITY_GET_FORM(entity);

						svec.vx = position.vx - live_entity->le_lwtrans->t[0];
						svec.vy = position.vy - live_entity->le_lwtrans->t[1];
						svec.vz = position.vz - live_entity->le_lwtrans->t[2];
						distance = MR_SVEC_MOD_SQR(&svec);

						if (distance < (form_book->fb_radius2 + 0))//FROG_COLLIDE_RADIUS2))
							{
							// Continue with FORM collision checking
							if (form->fo_numformdatas)
								{					
								form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];

								// Put frog origin in entity frame, using difference svec 
								MRTransposeMatrix(live_entity->le_lwtrans, &entity_transmatrix);
								MRApplyMatrix(&entity_transmatrix, &svec, &fcoords);
						
								// Check against FORM grid bounds
								xmin = form->fo_xofs;
								xmax = form->fo_xofs + (form->fo_xnum << 8);
								zmin = form->fo_zofs;
								zmax = form->fo_zofs + (form->fo_znum << 8);
								if	(
									(fcoords.vx >= xmin) &&
									(fcoords.vx <= xmax) &&
									(fcoords.vz >= zmin) &&
									(fcoords.vz <= zmax)
									)
									{
									// Inside local XZ grid

									// setup data for this collision 
									MR_COPY_VEC(&vis_data_ptr->hit_position, &position);	// position
									vis_data_ptr->hit_entity		= entity;				// hit entity
									vis_data_ptr->hit_entity_frog	= FALSE;				// mark hit entity as a frog

									// if this is the first time through the loop, mark this 
									// collision as an actual collision
									if (steps == max_steps)
										vis_data_ptr->hit_actual_hit	= TRUE;
									else
										vis_data_ptr->hit_actual_hit	= FALSE;

									// update coll struct counter, and check for limit
									if (++num_hits >= vis_info->max_vis_entities)
										return num_hits;

									// update coll struct to next element and continue
									vis_data_ptr++;
									}
								}
							}
						}
					}
				}
			}
		}

	// return number of hits
	return num_hits;
}


/******************************************************************************
*%%%% SnapFrogRotationToMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	angle =	SnapFrogRotationToMatrix(
*								FROG*	frog,
*								MR_MAT*	lwtrans,
*								MR_MAT*	transpose)
*
*	FUNCTION	Snap frog lwtrans to a 90 degree rotation about matrix local Y
*
*	INPUTS		frog		-	ptr to FROG to snap
*				lwtrans		-	matrix
*				transpose	-	of matrix
*
*	RESULT		angle		-	0..3 according to multiple of 90
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.06.97	Tim Closs		Created
*	20.08.97	Tim Closs		Made decision more accurate
*
*%%%**************************************************************************/

MR_LONG	SnapFrogRotationToMatrix(	FROG*	frog,
									MR_MAT*	lwtrans,
									MR_MAT*	transpose)
{
	MR_SVEC	svec;
	MR_VEC	vec;
	MR_LONG	cos, sin, angle;


	MR_ASSERT(frog);
	MR_ASSERT(lwtrans);
	MR_ASSERT(transpose);

	// Put frog rotation in local frame
	svec.vx = frog->fr_lwtrans->m[0][2];
	svec.vy = frog->fr_lwtrans->m[1][2];
	svec.vz = frog->fr_lwtrans->m[2][2];
	MRApplyMatrix(transpose, &svec, &vec);
	vec.vy 	= 0;
	MRNormaliseVEC(&vec, &vec);

	if (abs(vec.vz) > abs(vec.vx))
		{
		if (vec.vz > 0)
			{
			// Snap rotation: (0x000 about world Y) * (entity trans)
			cos 	=  0x1000;
			sin 	=  0x0000;
			angle 	= FROG_DIRECTION_N;
			}
		else
			{
			// Snap rotation: (0x800 about world Y) * (entity trans)
			cos 	= -0x1000;
			sin 	=  0x0000;
			angle 	= FROG_DIRECTION_S;
			}
		}
	else
		{
		if (vec.vx > 0)
			{
			// Snap rotation: (0x400 about world Y) * (entity trans)
			cos 	=  0x0000;
			sin 	=  0x1000;
			angle 	= FROG_DIRECTION_E;
			}
		else
			{
			// Snap rotation: (0xc00 about world Y) * (entity trans)
			cos 	=  0x0000;
			sin 	= -0x1000;
			angle 	= FROG_DIRECTION_W;
			}
		}

	MRRot_matrix_Y.m[0][0] =  cos;
	MRRot_matrix_Y.m[0][2] =  sin;
	MRRot_matrix_Y.m[2][0] = -sin;
	MRRot_matrix_Y.m[2][2] =  cos;
	MRMulMatrixABC(&MRRot_matrix_Y, lwtrans, frog->fr_lwtrans);
	return(angle);
}


/******************************************************************************
*%%%% SnapFrogToMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	angle =	SnapFrogToMatrix(
*								FROG*	frog,
*								MR_MAT*	lwtrans)
*
*	FUNCTION	Snap frog lwtrans to matrix local Y
*
*	INPUTS		frog		-	ptr to FROG to snap
*				lwtrans		-	matrix

*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SnapFrogToMatrix(	FROG*	frog,
							MR_MAT*	lwtrans)
{
	MR_VEC	vec_z, vec_x, vec_y;

	vec_z.vx = frog->fr_lwtrans->m[0][2];
	vec_z.vy = 0;
	vec_z.vz = frog->fr_lwtrans->m[2][2];

	vec_y.vx = lwtrans->m[0][1];
	vec_y.vy = lwtrans->m[1][1];
	vec_y.vz = lwtrans->m[2][1];

	MRNormaliseVEC(&vec_z, &vec_z);
	MROuterProduct12(&vec_y, &vec_z, &vec_x);		
	MRNormaliseVEC(&vec_x, &vec_x);
	WriteAxesAsMatrix(frog->fr_lwtrans, &vec_x, &vec_y, &vec_z);
}
