/******************************************************************************
*%%%% effects.c
*------------------------------------------------------------------------------
*
*	Special effects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "effects.h"
#include "main.h"
#include "ent_gen.h"
#include "sound.h"
#include "score.h"
#include "misc.h"
#include "particle.h"
#include "entlib.h"


MR_SVEC		Tongue_x_pos_offset = { 0x10, 0, 0};
MR_SVEC		Tongue_x_neg_offset = {-0x10, 0, 0};

MR_SVEC		Tongue_frog_origin_offset 	= {0x0, -0x20, 0x30};
MR_SVEC		Tongue_frog_eye_offset 		= {0x8, -0x50, 0x30};

EFFECT		Effect_root;
EFFECT*		Effect_root_ptr;


/******************************************************************************
*%%%% InitialiseEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseEffects(MR_VOID)
*
*	FUNCTION	Initialise effects list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.10.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseEffects(MR_VOID)
{
	Effect_root_ptr 				= &Effect_root;
	Effect_root_ptr->ef_next_node 	= NULL;
}


/******************************************************************************
*%%%% CreateEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	EFFECT*	effect = 	CreateEffect(
*									MR_USHORT	type)
*
*	FUNCTION	Allocate an EFFECT structure of particular sub-type
*
*	INPUTS		type	-	effect sub-type to create
*
*	RESULT		effect	-	ptr to structure allocated
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

EFFECT*	CreateEffect(MR_USHORT	type)
{	
	EFFECT*	effect;
		

	effect = NULL;
	switch(type)
		{
		// Allocate memory
		case EFFECT_TYPE_SHADOW:
			effect = MRAllocMem(sizeof(EFFECT) + sizeof(SHADOW), "SHADOW EFFECT");
			break;

		case EFFECT_TYPE_SIGHTS:
			effect = MRAllocMem(sizeof(EFFECT) + sizeof(SIGHTS), "SIGHTS EFFECT");
			break;

		case EFFECT_TYPE_TRAIL:
			effect = MRAllocMem(sizeof(EFFECT) + sizeof(TRAIL), "TRAIL EFFECT");
			break;

		case EFFECT_TYPE_TONGUE:
			effect = MRAllocMem(sizeof(EFFECT) + sizeof(TONGUE), "TONGUE EFFECT");
			break;

		default:
			MR_ASSERTMSG(NULL, "Effect type not recognised");
		}

	// Set up linked list
	if (effect->ef_next_node = Effect_root_ptr->ef_next_node)
		Effect_root_ptr->ef_next_node->ef_prev_node = effect;

	Effect_root_ptr->ef_next_node = effect;
	effect->ef_prev_node = Effect_root_ptr;

	// Set up structure
	effect->ef_flags		= EFFECT_KILL_WHEN_FINISHED;
	effect->ef_type			= type;
	effect->ef_kill_timer	= 0;
	effect->ef_extra 		= effect + 1;

	return(effect);
}


/******************************************************************************
*%%%% CreateShadow
*------------------------------------------------------------------------------
*
*	SYNOPSIS	EFFECT*	shadow = 	CreateShadow(
*									MR_TEXTURE* texture,
*									MR_MAT*		lwtrans,
*									MR_SVEC*	offsets)
*
*	FUNCTION	Set up a SHADOW structure
*
*	INPUTS		texture		-	ptr to texture to use
*				lwtrans		-	transform to apply to offsets
*				offsets		-	ptr to array of 4 corner offsets (in PSX format)
*
*	RESULT		shadow		-	ptr to effect created
*
*	RESULT		Pointer to structure allocated
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.09.96	Tim Closs		Created
*	29.10.96	Tim Closs		Structure changed, new inputs
*	12.12.96	Tim Closs		Added darkness input
*	15.05.97	Tim Closs		New inputs
*	02.06.97	Martin Kift		PC'er'fied
*	04.07.97	Tim Closs		Revised
*
*%%%**************************************************************************/

EFFECT*	CreateShadow(	MR_TEXTURE*	texture,
						MR_MAT*	   	lwtrans,
						MR_SVEC*	offsets)
{
	MR_USHORT	i, j, k;
	SHADOW*		shadow;
	POLY_FT4*	poly;
	EFFECT*		effect;
	

	// Allocate memory
	effect	= CreateEffect(EFFECT_TYPE_SHADOW);
	shadow	= (SHADOW*)effect->ef_extra;

	// Set up polys
	for (k = 0; k < 2; k++)
		{
		poly = shadow->sh_polys[k][0];
		for (j = 0; j < Game_total_viewports; j++)
			{
			for (i = 0; i < 2; i++)
				{
				setPolyFT4(poly);
#ifdef PSX
				MR_COPY32(poly->u0, texture->te_u0);
				MR_COPY32(poly->u1, texture->te_u1);
#else
				poly->tpage = texture->te_tpage_id;
				MR_COPY16(poly->u0, texture->te_u0);
				MR_COPY16(poly->u1, texture->te_u1);
#endif
				MR_COPY16(poly->u2, texture->te_u2);
				MR_COPY16(poly->u3, texture->te_u3);
	
				setRGB0(poly, 0x30, 0x30, 0x30);
				setSemiTrans(poly, 1);
		
				poly++;
				}
			}
		}

	shadow->sh_texture	= texture;
	shadow->sh_lwtrans	= lwtrans;
	shadow->sh_offsets	= offsets;

	for (i = 0; i < Game_total_viewports; i++)
		shadow->sh_ot_ptr[i] = NULL;

	return(effect);
}


/******************************************************************************
*%%%% KillEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillEffect(
*						EFFECT* effect)
*
*	FUNCTION	Remove structure from list and free memory
*
*	INPUTS		effect	-	ptr to EFFECT to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillEffect(EFFECT* effect)
{
	MR_ASSERT(effect);

	// Remove structure from linked list
	effect->ef_prev_node->ef_next_node = effect->ef_next_node;
	if	(effect->ef_next_node)
		effect->ef_next_node->ef_prev_node = effect->ef_prev_node;

	// Do any type-specific freeing
	switch(effect->ef_type)
		{
		//-----------------------------------------------------------------------
		case EFFECT_TYPE_TRAIL:
			MRFreeMem(((TRAIL*)effect->ef_extra)->tr_polys[0][0]);
			break;

		//-----------------------------------------------------------------------
		}

	// Free structure memory
	MRFreeMem(effect);
}


/******************************************************************************
*%%%% KillAllEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillAllEffects(MR_VOID)
*
*	FUNCTION	Kill all effects
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillAllEffects(MR_VOID)
{
	while(Effect_root_ptr->ef_next_node)
		KillEffect(Effect_root_ptr->ef_next_node);
}


/******************************************************************************
*%%%% UpdateEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateEffects(MR_VOID)
*
*	FUNCTION	Update (but not render) all effects
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.11.96	Tim Closs		Created
*	02.06.97	Martin Kift		PC'er'fied
*	07.07.97	Gary Richards	Update the Tongue object code.
*	20.08.97	Martin Kift		Fixed the update to the tongue code.
*
*%%%**************************************************************************/

MR_VOID	UpdateEffects(MR_VOID)
{
	EFFECT*				effect;
	SHADOW*				shadow;
	TRAIL*				trail;
	TONGUE*				tongue;
	MR_SVEC*			ofs_ptr;
	MR_SVEC*			svec_ptr;
	MR_VEC				vec[4];
	MR_VEC				temp_vec;
	MR_LONG				x0, z0, x1, x2, z2;
	MR_LONG				i, cos, sin;
	MR_TEXTURE*			texture;
	MR_LONG				y, value;
	LIVE_ENTITY*		live_entity;
	MR_SPLINE_BEZIER	spline_bezier;
	MR_SPLINE_MATRIX	spline_matrix;
	FORM_BOOK*			form_book;
	GRID_SQUARE*		grid_square0;
	GRID_SQUARE*		grid_square1;
	MR_LONG				map_poly_y0;
	MR_LONG				map_poly_y1;
	MR_LONG				map_poly_y2;
	MR_LONG				map_poly_y3;
		
	effect = Effect_root_ptr;
	while(effect = effect->ef_next_node)
		{
		if (!(effect->ef_kill_timer))
			{
			if (effect->ef_flags & EFFECT_NO_UPDATE)
				goto next_effect;

			switch(effect->ef_type)
				{
				//----------------------------------------------------------------
				case EFFECT_TYPE_SIGHTS:
					if (Game_flags & GAME_FLAG_PAUSED)
						goto next_effect;

					((SIGHTS*)effect->ef_extra)->si_timer++;
					break;
				//----------------------------------------------------------------
				case EFFECT_TYPE_SHADOW:
					if (Game_flags & GAME_FLAG_PAUSED)
						goto next_effect;

					shadow	= (SHADOW*)effect->ef_extra;
					texture	= shadow->sh_texture;

					if (effect->ef_flags & EFFECT_STATIC)
						{
						// Don't project onto anything: just use offsets in specified frame
						effect->ef_flags |= EFFECT_STANDARD_MODE;

						gte_SetRotMatrix(shadow->sh_lwtrans);
						for (i = 0; i < 4; i++)
							{
							MRApplyRotMatrix(&shadow->sh_offsets[i], &vec[i]);
							shadow->sh_corners[0][i].vx = vec[i].vx + shadow->sh_lwtrans->t[0];
							shadow->sh_corners[0][i].vy = vec[i].vy + shadow->sh_lwtrans->t[1];
							shadow->sh_corners[0][i].vz = vec[i].vz + shadow->sh_lwtrans->t[2];
							}
						MR_COPY16(shadow->sh_uv[0][0][0], texture->te_u0);
						MR_COPY16(shadow->sh_uv[0][1][0], texture->te_u1);
						MR_COPY16(shadow->sh_uv[0][2][0], texture->te_u2);
						MR_COPY16(shadow->sh_uv[0][3][0], texture->te_u3);
						}
					else
						{
						if (effect->ef_flags & EFFECT_NO_ROTATION)
							{
							// Don't use shadow->sh_lwtrans rotation: assume shadow is circular, and get rotation according
							// to whether we are across X line or Z line
							for (i = 0; i < 4; i++)
								{
								vec[i].vx = shadow->sh_lwtrans->t[0] + shadow->sh_offsets[i].vx;
								vec[i].vy = shadow->sh_lwtrans->t[1] + shadow->sh_offsets[i].vy;
								vec[i].vz = shadow->sh_lwtrans->t[2] + shadow->sh_offsets[i].vz;
								}		   
							// Calculate grid x,z for corner points 0,1,2
							x0 = GET_GRID_X_FROM_WORLD_X(vec[0].vx);
							z0 = GET_GRID_Z_FROM_WORLD_Z(vec[0].vz);
							x1 = GET_GRID_X_FROM_WORLD_X(vec[1].vx);
							x2 = GET_GRID_X_FROM_WORLD_X(vec[2].vx);
							z2 = GET_GRID_Z_FROM_WORLD_Z(vec[2].vz);
							if (x0 != x1)
								{
								MR_COPY_VEC(&temp_vec, &vec[2]);
								MR_COPY_VEC(&vec[2], &vec[0]);
								MR_COPY_VEC(&vec[0], &vec[1]);
								MR_COPY_VEC(&vec[1], &vec[3]);
								MR_COPY_VEC(&vec[3], &temp_vec);
								x2	= x0;
								z2	= z0;
								z0 	= GET_GRID_Z_FROM_WORLD_Z(vec[0].vz);
								}
							}
						else
							{
							// Calculate world coords of shadow corners	in vec[]
							i 	= GetWorldYQuadrantFromMatrix(shadow->sh_lwtrans);
							cos	= rcos(i * 0x400);
							sin	= rsin(i * 0x400);
							MRTemp_matrix.m[0][0] = cos;
							MRTemp_matrix.m[0][1] = 0;
							MRTemp_matrix.m[0][2] = sin;
							MRTemp_matrix.m[1][0] = 0;
							MRTemp_matrix.m[1][1] = 0x1000;
							MRTemp_matrix.m[1][2] = 0;
							MRTemp_matrix.m[2][0] = -sin;
							MRTemp_matrix.m[2][1] = 0;
							MRTemp_matrix.m[2][2] = cos;
	
							gte_SetRotMatrix(&MRTemp_matrix);
							for (i = 0; i < 4; i++)
								{
								MRApplyRotMatrix(&shadow->sh_offsets[i], &vec[i]);
								MR_ADD_VEC(&vec[i], (MR_VEC*)shadow->sh_lwtrans->t);
								}
							// Calculate grid x,z for corner points 0,1,2
							x0 = GET_GRID_X_FROM_WORLD_X(vec[0].vx);
							x2 = GET_GRID_X_FROM_WORLD_X(vec[2].vx);
							z0 = GET_GRID_Z_FROM_WORLD_Z(vec[0].vz);
							z2 = GET_GRID_Z_FROM_WORLD_Z(vec[2].vz);
							}
	
						// Need distance between offset[0].vz and offset[2].vz as divisor
						y = shadow->sh_offsets[0].vz - shadow->sh_offsets[2].vz;
	
						// Calculate where to split shadow area into 2 polys (if at all)
						if	(
							(x0 != x2) ||
							(z0 != z2)
							)
							{
							// Split along line parallel to edge 0/1 and 2/3
							effect->ef_flags &= ~EFFECT_STANDARD_MODE;
	
							// Poly 0, points 0,1
							shadow->sh_corners[0][0].vx = vec[0].vx;
							if ((value = GetHeightFromWorldXYZ(vec[0].vx, vec[0].vy, vec[0].vz, &grid_square0)) == GRID_RETURN_VALUE_ERROR)
								goto shadow_error;
							shadow->sh_corners[0][0].vy = value;
							shadow->sh_corners[0][0].vz = vec[0].vz;
							shadow->sh_corners[0][1].vx = vec[1].vx;
							if ((value = GetHeightFromWorldXYZ(vec[1].vx, vec[1].vy, vec[1].vz, NULL)) == GRID_RETURN_VALUE_ERROR)
								goto shadow_error;
							shadow->sh_corners[0][1].vy = value;
							shadow->sh_corners[0][1].vz = vec[1].vz;
							MR_COPY16(shadow->sh_uv[0][0][0], texture->te_u0);
							MR_COPY16(shadow->sh_uv[0][1][0], texture->te_u1);
	
							// Poly 1, points 2,3
							shadow->sh_corners[1][2].vx = vec[2].vx;
							if ((value = GetHeightFromWorldXYZ(vec[2].vx, vec[2].vy, vec[2].vz, &grid_square1)) == GRID_RETURN_VALUE_ERROR)
								goto shadow_error;
							shadow->sh_corners[1][2].vy = value;
							shadow->sh_corners[1][2].vz = vec[2].vz;
							shadow->sh_corners[1][3].vx = vec[3].vx;
							if ((value = GetHeightFromWorldXYZ(vec[3].vx, vec[3].vy, vec[3].vz, NULL)) == GRID_RETURN_VALUE_ERROR)
								goto shadow_error;
							shadow->sh_corners[1][3].vy = value;
							shadow->sh_corners[1][3].vz = vec[3].vz;
							MR_COPY16(shadow->sh_uv[1][2][0], texture->te_u2);
							MR_COPY16(shadow->sh_uv[1][3][0], texture->te_u3);
	
							if ((vec[0].vz - vec[2].vz) > 0x40)
								{
								// Alignment N
								//
								// Poly 0, points 2,3
								shadow->sh_corners[0][2].vx = vec[0].vx;
								shadow->sh_corners[0][3].vx = vec[1].vx;
								shadow->sh_corners[0][2].vz = vec[0].vz & ~0xff;
								shadow->sh_corners[0][3].vz = vec[1].vz & ~0xff;
								map_poly_y2 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[2]].vy;
								map_poly_y3 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[3]].vy;
								shadow->sh_corners[0][2].vy = map_poly_y2 + (((vec[0].vx & 0xff) * (map_poly_y3 - map_poly_y2)) >> 8);
								shadow->sh_corners[0][3].vy = map_poly_y2 + (((vec[1].vx & 0xff) * (map_poly_y3 - map_poly_y2)) >> 8);
	
								shadow->sh_uv[0][2][1] = texture->te_v0 + (((vec[0].vz & 0xff) * texture->te_h) / y);
	
								// Poly 1, points 0,1
								shadow->sh_corners[1][0].vx = vec[2].vx;
								shadow->sh_corners[1][1].vx = vec[3].vx;
								shadow->sh_corners[1][0].vz = vec[0].vz & ~0xff;
								shadow->sh_corners[1][1].vz = vec[1].vz & ~0xff;
								map_poly_y0 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[0]].vy;
								map_poly_y1 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[1]].vy;
								shadow->sh_corners[1][0].vy = map_poly_y0 + (((vec[2].vx & 0xff) * (map_poly_y1 - map_poly_y0)) >> 8);
								shadow->sh_corners[1][1].vy = map_poly_y0 + (((vec[3].vx & 0xff) * (map_poly_y1 - map_poly_y0)) >> 8);
								}
							else
							if ((vec[0].vx - vec[2].vx) > 0x40)
								{
								// Alignment E
								//
								// Poly 0, points 2,3
								shadow->sh_corners[0][2].vz = vec[0].vz;
								shadow->sh_corners[0][3].vz = vec[1].vz;
								shadow->sh_corners[0][2].vx = vec[0].vx & ~0xff;
								shadow->sh_corners[0][3].vx = vec[1].vx & ~0xff;
								map_poly_y0 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[0]].vy;
								map_poly_y2 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[2]].vy;
								shadow->sh_corners[0][2].vy = map_poly_y2 + (((vec[0].vz & 0xff) * (map_poly_y0 - map_poly_y2)) >> 8);
								shadow->sh_corners[0][3].vy = map_poly_y2 + (((vec[1].vz & 0xff) * (map_poly_y0 - map_poly_y2)) >> 8);
	
								shadow->sh_uv[0][2][1] = texture->te_v0 + (((vec[0].vx & 0xff) * texture->te_h) / y);
	
								// Poly 1, points 0,1
								shadow->sh_corners[1][0].vz = vec[2].vz;
								shadow->sh_corners[1][1].vz = vec[3].vz;
								shadow->sh_corners[1][0].vx = vec[0].vx & ~0xff;
								shadow->sh_corners[1][1].vx = vec[1].vx & ~0xff;
								map_poly_y1 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[1]].vy;
								map_poly_y3 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[3]].vy;
								shadow->sh_corners[1][0].vy = map_poly_y3 + (((vec[2].vz & 0xff) * (map_poly_y1 - map_poly_y3)) >> 8);
								shadow->sh_corners[1][1].vy = map_poly_y3 + (((vec[3].vz & 0xff) * (map_poly_y1 - map_poly_y3)) >> 8);
								}
							else
							if ((vec[0].vz - vec[2].vz) < -0x40)
								{
								// Alignment S
								//
								// Poly 0, points 2,3
								shadow->sh_corners[0][2].vx = vec[0].vx;
								shadow->sh_corners[0][3].vx = vec[1].vx;
								shadow->sh_corners[0][2].vz = vec[2].vz & ~0xff;
								shadow->sh_corners[0][3].vz = vec[3].vz & ~0xff;
								map_poly_y0 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[0]].vy;
								map_poly_y1 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[1]].vy;
								shadow->sh_corners[0][2].vy = map_poly_y0 + (((vec[0].vx & 0xff) * (map_poly_y1 - map_poly_y0)) >> 8);
								shadow->sh_corners[0][3].vy = map_poly_y0 + (((vec[1].vx & 0xff) * (map_poly_y1 - map_poly_y0)) >> 8);
	
								shadow->sh_uv[0][2][1] = texture->te_v0 + (((0x100 - (vec[0].vz & 0xff)) * texture->te_h) / y);
	
								// Poly 1, points 0,1
								shadow->sh_corners[1][0].vx = vec[2].vx;
								shadow->sh_corners[1][1].vx = vec[3].vx;
								shadow->sh_corners[1][0].vz = vec[2].vz & ~0xff;
								shadow->sh_corners[1][1].vz = vec[3].vz & ~0xff;
								map_poly_y2 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[2]].vy;
								map_poly_y3 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[3]].vy;
								shadow->sh_corners[1][0].vy = map_poly_y2 + (((vec[2].vx & 0xff) * (map_poly_y3 - map_poly_y2)) >> 8);
								shadow->sh_corners[1][1].vy = map_poly_y2 + (((vec[3].vx & 0xff) * (map_poly_y3 - map_poly_y2)) >> 8);
								}
							else
								{
								// Alignment W
								//
								// Poly 0, points 2,3
								shadow->sh_corners[0][2].vz = vec[0].vz;
								shadow->sh_corners[0][3].vz = vec[1].vz;
								shadow->sh_corners[0][2].vx = vec[2].vx & ~0xff;
								shadow->sh_corners[0][3].vx = vec[3].vx & ~0xff;
								map_poly_y1 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[1]].vy;
								map_poly_y3 = Map_vertices[grid_square0->gs_map_poly->mp_vertices[3]].vy;
								shadow->sh_corners[0][2].vy = map_poly_y3 + (((vec[0].vz & 0xff) * (map_poly_y1 - map_poly_y3)) >> 8);
								shadow->sh_corners[0][3].vy = map_poly_y3 + (((vec[1].vz & 0xff) * (map_poly_y1 - map_poly_y3)) >> 8);
	
								shadow->sh_uv[0][2][1] = texture->te_v0 + (((0x100 - (vec[0].vx & 0xff)) * texture->te_h) / y);
	
								// Poly 1, points 0,1
								shadow->sh_corners[1][0].vz = vec[2].vz;
								shadow->sh_corners[1][1].vz = vec[3].vz;
								shadow->sh_corners[1][0].vx = vec[2].vx & ~0xff;
								shadow->sh_corners[1][1].vx = vec[3].vx & ~0xff;
								map_poly_y0 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[0]].vy;
								map_poly_y2 = Map_vertices[grid_square1->gs_map_poly->mp_vertices[2]].vy;
								shadow->sh_corners[1][0].vy = map_poly_y2 + (((vec[2].vz & 0xff) * (map_poly_y0 - map_poly_y2)) >> 8);
								shadow->sh_corners[1][1].vy = map_poly_y2 + (((vec[3].vz & 0xff) * (map_poly_y0 - map_poly_y2)) >> 8);
								}
	
							shadow->sh_uv[1][0][0] = texture->te_u0;
							shadow->sh_uv[1][1][0] = texture->te_u1;
							shadow->sh_uv[0][2][0] = texture->te_u2;
							shadow->sh_uv[0][3][0] = texture->te_u3;
							shadow->sh_uv[0][3][1] = shadow->sh_uv[0][2][1];
							shadow->sh_uv[1][0][1] = shadow->sh_uv[0][2][1];
							shadow->sh_uv[1][1][1] = shadow->sh_uv[0][2][1];
							}
						else
							{
							// No split
							effect->ef_flags |= EFFECT_STANDARD_MODE;
	
							for (i = 0; i < 4; i++)
								{
								shadow->sh_corners[0][i].vx = vec[i].vx;
								shadow->sh_corners[0][i].vy = GetHeightFromWorldXYZ(vec[i].vx, vec[i].vy, vec[i].vz, NULL);
								shadow->sh_corners[0][i].vz = vec[i].vz;
								}							 
							MR_COPY16(shadow->sh_uv[0][0][0], texture->te_u0);
							MR_COPY16(shadow->sh_uv[0][1][0], texture->te_u1);
							MR_COPY16(shadow->sh_uv[0][2][0], texture->te_u2);
							MR_COPY16(shadow->sh_uv[0][3][0], texture->te_u3);
							}
						}
					break;
				//----------------------------------------------------------------
				case EFFECT_TYPE_TRAIL:
					if (Game_flags & GAME_FLAG_PAUSED)
						goto next_effect;

					if (effect->ef_flags & EFFECT_RESET)
						{
						ResetTrail(effect);
						effect->ef_flags &= ~EFFECT_RESET;
						}
					trail	= (TRAIL*)effect->ef_extra;
					if (trail->tr_timer)
						{
						if (!(--trail->tr_timer))
							{
							if (effect->ef_flags & EFFECT_KILL_WHEN_FINISHED)
								{
								effect->ef_kill_timer = 2;
								break;
								}
							}
					
						// Add velocity to vertex coords
						ofs_ptr	= trail->tr_vertex_coords;
						i 		= trail->tr_sections << 1;
						while(i--)
							{
							MR_ADD_SVEC(ofs_ptr, &trail->tr_velocity);
							ofs_ptr++;
							}
	
						// Update RGB
						if (trail->tr_timer <= TRAIL_DECREASE_TIMER)
							{
							if (trail->tr_rgb)
								trail->tr_rgb = MAX(0, trail->tr_rgb - trail->tr_rgb_decrease);
							}
						else
							{
							if (trail->tr_rgb < TRAIL_RGB_MAX)
								trail->tr_rgb += trail->tr_rgb_increase;
							}
	
						// Write new vertex coords
						gte_SetRotMatrix(trail->tr_lwtrans);
						MRApplyRotMatrix(&trail->tr_offsets[0], &vec[0]);
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 0)->vx = vec[0].vx + trail->tr_lwtrans->t[0];
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 0)->vy = vec[0].vy + trail->tr_lwtrans->t[1];
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 0)->vz = vec[0].vz + trail->tr_lwtrans->t[2];
						MRApplyRotMatrix(&trail->tr_offsets[1], &vec[0]);
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 1)->vx = vec[0].vx + trail->tr_lwtrans->t[0];
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 1)->vy = vec[0].vy + trail->tr_lwtrans->t[1];
						(trail->tr_vertex_coords + (trail->tr_current_section << 1) + 1)->vz = vec[0].vz + trail->tr_lwtrans->t[2];
						if (!(trail->tr_current_section))
							trail->tr_current_section = trail->tr_sections - 1;
						else
							trail->tr_current_section--;

						trail->tr_display_sections = MIN(trail->tr_sections - 1, trail->tr_display_sections + 1);
						}
					break;
				//----------------------------------------------------------------
				case EFFECT_TYPE_TONGUE:
					if (Game_flags & GAME_FLAG_PAUSED)
						goto next_effect;

					tongue = (TONGUE*)effect->ef_extra;
					if (tongue->to_target)
						live_entity = tongue->to_target->en_live_entity;
					else
						live_entity = NULL;

					if (tongue->to_flags & TONGUE_FLAG_MOVING_OUT)
						{
						// Tongue moving out
						tongue->to_section++;
						if (tongue->to_section == TONGUE_MAX_SECTIONS)
							{
							// Set up grab mode
							tongue->to_flags 	&= ~TONGUE_FLAG_MOVING_OUT;
							tongue->to_flags 	|= TONGUE_FLAG_GRABBING;
							if (tongue->to_target)
								tongue->to_counter 	= TONGUE_GRABBING_DURATION;
							else
								tongue->to_counter 	= (TONGUE_GRABBING_DURATION << 1);

							if (tongue->to_target)
								{
								// Set ENTITY to follow tongue back in
								tongue->to_target->en_flags |= ENTITY_NO_MOVEMENT;
								live_entity->le_flags		|= LIVE_ENTITY_TONGUED;
								}
							}
						}
					else
					if (tongue->to_flags & TONGUE_FLAG_MOVING_IN)
						{
						// Tongue moving in
						tongue->to_section--;
						if (!(tongue->to_section))
							{
							// Turn effect off
							effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
							
							if (tongue->to_target)
								{
								// Turn ENTITY off
								tongue->to_target->en_flags |= ENTITY_HIDDEN;
								form_book					= ENTITY_GET_FORM_BOOK(tongue->to_target);

								// Set frog to scale up and down - give score
								//
								// Note: we assume owner is FROG, and target entity is GEN_BONUS_FLY
								FrogSetScaling(tongue->to_owner, TONGUE_OWNER_MAX_SCALE, TONGUE_OWNER_SCALE_UP_TIME, TONGUE_OWNER_SCALE_DOWN_TIME);
		
								if (form_book->fb_bonus_callback)
									form_book->fb_bonus_callback(tongue->to_owner, live_entity, NULL);
								else
									AddFrogScore(tongue->to_owner, Bonus_fly_scores[((GEN_BONUS_FLY*)(tongue->to_target + 1))->bf_type], NULL);
								
								// play sfx
								MRSNDPlaySound(SFX_GEN_FROG_FLY_GULP, NULL, 0, 0);
								}
							}
						}
					else
						{
						// Tongue grabbing
						if (!(--tongue->to_counter))
							{
							tongue->to_flags 	&= ~TONGUE_FLAG_GRABBING;
							tongue->to_flags 	|= TONGUE_FLAG_MOVING_IN;
							}
						}	

					// Set up spline matrix, and calculate (tongue->to_section) points from frog to target
					gte_SetRotMatrix(tongue->to_lwtrans);
					MRApplyRotMatrix(&Tongue_frog_origin_offset, &temp_vec);
					spline_bezier.sb_p1.vx = tongue->to_lwtrans->t[0] + temp_vec.vx;
					spline_bezier.sb_p1.vy = tongue->to_lwtrans->t[1] + temp_vec.vy;
					spline_bezier.sb_p1.vz = tongue->to_lwtrans->t[2] + temp_vec.vz;
					if (live_entity)
						{
						MR_SVEC_EQUALS_VEC(&spline_bezier.sb_p4, (MR_VEC*)live_entity->le_lwtrans->t);
						spline_bezier.sb_p2.vx = spline_bezier.sb_p1.vx + (tongue->to_lwtrans->m[0][2] >> 4);
						spline_bezier.sb_p2.vy = spline_bezier.sb_p1.vy + (tongue->to_lwtrans->m[1][2] >> 4);
						spline_bezier.sb_p2.vz = spline_bezier.sb_p1.vz + (tongue->to_lwtrans->m[2][2] >> 4);
						spline_bezier.sb_p3.vx = (spline_bezier.sb_p4.vx + spline_bezier.sb_p2.vx) >> 1;
						spline_bezier.sb_p3.vy = (spline_bezier.sb_p4.vy + spline_bezier.sb_p2.vy) >> 1;
						spline_bezier.sb_p3.vz = (spline_bezier.sb_p4.vz + spline_bezier.sb_p2.vz) >> 1;
						}
					else
						{
						// Clean eyes
						MRApplyRotMatrix(&Tongue_frog_eye_offset, &temp_vec);
						spline_bezier.sb_p4.vx = tongue->to_lwtrans->t[0] + temp_vec.vx;
						spline_bezier.sb_p4.vy = tongue->to_lwtrans->t[1] + temp_vec.vy;
						spline_bezier.sb_p4.vz = tongue->to_lwtrans->t[2] + temp_vec.vz;

						spline_bezier.sb_p2.vx = spline_bezier.sb_p1.vx + (tongue->to_lwtrans->m[0][2] >> 5) + (tongue->to_lwtrans->m[0][0] >> 5);
						spline_bezier.sb_p2.vy = spline_bezier.sb_p1.vy + (tongue->to_lwtrans->m[1][2] >> 5) + (tongue->to_lwtrans->m[1][0] >> 5);
						spline_bezier.sb_p2.vz = spline_bezier.sb_p1.vz + (tongue->to_lwtrans->m[2][2] >> 5) + (tongue->to_lwtrans->m[2][0] >> 5);
						spline_bezier.sb_p3.vx = spline_bezier.sb_p1.vx + (tongue->to_lwtrans->m[0][2] >> 5) - (tongue->to_lwtrans->m[0][0] >> 5);
						spline_bezier.sb_p3.vy = spline_bezier.sb_p1.vy + (tongue->to_lwtrans->m[1][2] >> 5) - (tongue->to_lwtrans->m[1][0] >> 5);
						spline_bezier.sb_p3.vz = spline_bezier.sb_p1.vz + (tongue->to_lwtrans->m[2][2] >> 5) - (tongue->to_lwtrans->m[2][0] >> 5);
						}
					MRCalculateSplineBezierMatrix(&spline_bezier, &spline_matrix);

					svec_ptr = &tongue->to_vertices[0][0];
					for (i = 0; i <= tongue->to_section; i++)
						{
						y = (i * MR_SPLINE_PARAM_ONE) / TONGUE_MAX_SECTIONS;
						MRCalculateSplinePoint(&spline_matrix, y, svec_ptr);
						MRCalculateSplineTangentNormalised(&spline_matrix, y, &vec[2]);	// local z

						vec[1].vx = tongue->to_lwtrans->m[0][1];
						vec[1].vy = tongue->to_lwtrans->m[1][1];
						vec[1].vz = tongue->to_lwtrans->m[2][1];
						MROuterProduct12(&vec[1], &vec[2], &vec[0]);
						MRNormaliseVEC(&vec[0], &vec[0]);								// local x
						MROuterProduct12(&vec[2], &vec[0], &vec[1]);					// local y
						WriteAxesAsMatrix(&MRTemp_matrix, &vec[0], &vec[1], &vec[2]);

						gte_SetRotMatrix(&MRTemp_matrix);
						MRApplyRotMatrix(&Tongue_x_pos_offset, &vec[1]);
						(svec_ptr + 1)->vx = svec_ptr->vx + vec[1].vx;
						(svec_ptr + 1)->vy = svec_ptr->vy + vec[1].vy;
						(svec_ptr + 1)->vz = svec_ptr->vz + vec[1].vz;
						MRApplyRotMatrix(&Tongue_x_neg_offset, &vec[1]);
						(svec_ptr + 2)->vx = svec_ptr->vx + vec[1].vx;
						(svec_ptr + 2)->vy = svec_ptr->vy + vec[1].vy;
						(svec_ptr + 2)->vz = svec_ptr->vz + vec[1].vz;
						svec_ptr += 3;
						}

					if	(
						(tongue->to_flags & TONGUE_FLAG_MOVING_IN) &&
						(live_entity)
						)
						{
						// ENTITY follows tongue back in
						MR_VEC_EQUALS_SVEC((MR_VEC*)live_entity->le_lwtrans->t, &tongue->to_vertices[tongue->to_section][0]);
						}
					break;
				//----------------------------------------------------------------
				case EFFECT_TYPE_PARTICLE:
					break;

				//----------------------------------------------------------------
				}
			}
		next_effect:;
		}
	return;

	shadow_error:;
	effect->ef_flags |= EFFECT_NO_DISPLAY;
	goto next_effect;
}


/******************************************************************************
*%%%% RenderEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderEffects(MR_VOID)
*
*	FUNCTION	Handle rendering/killing of effects
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.11.96	Tim Closs		Created
*	02.06.97	Martin Kift		PC'er'fied
*
*%%%**************************************************************************/

MR_VOID	RenderEffects(MR_VOID)
{
	EFFECT*			effect;
	EFFECT*			effect_prev;
	SHADOW*			shadow;
	TRAIL*			trail;
	TONGUE*			tongue;
	FROG*			frog;
	MR_SVEC			svec;
	MR_SVEC*		svec_ptr;
	POLY_FT4*		poly_ft4;
	POLY_G3*		poly_g3;
	POLY_G4*		poly_g4;
	MR_LONG			poly_otz, z;
	MR_ULONG		i, j, k;
	MR_VIEWPORT*	vp;
	MR_LONG			old_xy0;
	MR_LONG			old_xy1;
	MR_LONG			old_xy2;
	MR_LONG			col;
	MR_LONG			old_col;
	MR_LONG			temp;


	// Pass 1: sort out kill timer
	effect = Effect_root_ptr;
	while(effect = effect->ef_next_node)
		{
		if (effect->ef_kill_timer)
			{
			if (!(--effect->ef_kill_timer))
				{
				// Free memory
				effect_prev = effect->ef_prev_node;
				KillEffect(effect);
				effect = effect_prev;
				}
			}
		}

	// Pass 2: shadows and sights
	for (i = 0; i < Game_total_viewports; i++)
		{
		if (vp = Game_viewports[i])
			{
			MRSetActiveViewport(vp);
			svec.vx = -vp->vp_render_matrix.t[0];
			svec.vy = -vp->vp_render_matrix.t[1];
			svec.vz = -vp->vp_render_matrix.t[2];
			MRApplyMatrix(&vp->vp_render_matrix, &svec, (MR_VEC*)MRViewtrans_ptr->t);
			gte_SetRotMatrix(&vp->vp_render_matrix);
			gte_SetTransMatrix(MRViewtrans_ptr);
		
			effect = Effect_root_ptr;
			while(effect = effect->ef_next_node)
				{
				if ((!effect->ef_kill_timer) && (!(effect->ef_flags & EFFECT_NO_DISPLAY)))
					{
					switch(effect->ef_type)
						{
						//-----------------------------------------------------------------
						case EFFECT_TYPE_SHADOW:
							shadow		= (SHADOW*)effect->ef_extra;
	
							if (effect->ef_flags & EFFECT_STANDARD_MODE)
								j = 1;
							else
								j = 2;
	
							while(j--)
								{
						 		poly_ft4 = &shadow->sh_polys[j][i][MRFrame_index];
			
								gte_ldv3(	&shadow->sh_corners[j][0],
											&shadow->sh_corners[j][1],
											&shadow->sh_corners[j][2]);
								gte_rtpt();
								gte_stsxy3(	(MR_LONG*)&poly_ft4->x0,
											(MR_LONG*)&poly_ft4->x1,
											(MR_LONG*)&poly_ft4->x2);
/*
#ifdef WIN95
								gte_stsz3(	(MR_LONG*)&poly_ft4->z0,
											(MR_LONG*)&poly_ft4->z1,
											(MR_LONG*)&poly_ft4->z2);
#endif
*/
								gte_ldv0(&shadow->sh_corners[j][3]);
								gte_rtps();
								gte_stsxy2((MR_LONG*)&poly_ft4->x3);
			
								if	(
									(poly_ft4->x0 < vp->vp_disp_inf.w) ||
									(poly_ft4->x1 < vp->vp_disp_inf.w) ||
									(poly_ft4->x2 < vp->vp_disp_inf.w) ||
									(poly_ft4->x3 < vp->vp_disp_inf.w)
									)
									{
									// Copy UVs from SHADOW to poly (and clut and tpage)
									MR_COPY16(poly_ft4->u0, shadow->sh_uv[j][0][0]);
									MR_COPY16(poly_ft4->u1, shadow->sh_uv[j][1][0]);
									poly_ft4->tpage = shadow->sh_texture->te_tpage_id;
	#ifdef PSX
									poly_ft4->clut 	= shadow->sh_texture->te_clut_id;
	#endif
									MR_COPY16(poly_ft4->u2, shadow->sh_uv[j][2][0]);
									MR_COPY16(poly_ft4->u3, shadow->sh_uv[j][3][0]);

									gte_avsz4();
									gte_stotz(&poly_otz);
									if (((poly_otz >>= vp->vp_otz_shift) > 0) && (poly_otz < vp->vp_ot_size))
										{
										poly_otz = MAX(MR_OT_NEAR_CLIP, poly_otz + SHADOW_OT_OFFSET);
										addPrim(vp->vp_work_ot + poly_otz, poly_ft4);
										}
									}
								}
							break;
						//-----------------------------------------------------------------
						}
					}
				}
			}
		}

	// Pass 3: trails and tongues
	for (i = 0; i < Game_total_viewports; i++)
		{
		if (vp = Game_viewports[i])
			{
			MRSetActiveViewport(vp);
			effect	= Effect_root_ptr;
			while(effect = effect->ef_next_node)
				{
				if ((!effect->ef_kill_timer) && (!(effect->ef_flags & EFFECT_NO_DISPLAY)))
					{
					switch(effect->ef_type)
						{
						//----------------------------------------------------------------
						case EFFECT_TYPE_TRAIL:
							trail 	= (TRAIL*)effect->ef_extra;
							if (trail->tr_timer)
								{	
						 		poly_g3 = trail->tr_polys[i][MRFrame_index];
								j		= trail->tr_current_section;
								if (++j == trail->tr_sections)
									j = 0;
								svec_ptr = &trail->tr_vertex_coords[j << 1];
			
								// Calculate screen coords of first vertex pair
								svec.vx = -vp->vp_render_matrix.t[0];
								svec.vy = -vp->vp_render_matrix.t[1];
								svec.vz = -vp->vp_render_matrix.t[2];
								gte_SetRotMatrix(&vp->vp_render_matrix);
								MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
								gte_SetTransMatrix(MRViewtrans_ptr);
			
								gte_ldv3(	svec_ptr + 0,
											svec_ptr + 1,
											&Null_svector);
								gte_rtpt();
								gte_stsxy0(&old_xy0);
								gte_stsxy1(&old_xy1);
			 	
								k 		= trail->tr_display_sections;
								old_col	= trail->tr_rgb;
								col		= old_col + 0x32000000;				// semiTrans POLY_G3 code
			
								while(k--)
									{
									// Write top poly coords from old screen coords
									MR_COPY32((poly_g3 + 0)->x0, old_xy0);
									MR_COPY32((poly_g3 + 0)->x1, old_xy1);
									MR_COPY32((poly_g3 + 1)->x1, old_xy1);
			
									// Write top RGBs		
									MR_SET32((poly_g3 + 0)->r0, col);
									MR_SET32((poly_g3 + 0)->r1, col);
									MR_SET32((poly_g3 + 1)->r1, col);
			
									// Calculate two new coords
									if (++j == trail->tr_sections)
										{
										j = 0;
										svec_ptr = trail->tr_vertex_coords;
										}
									else
										svec_ptr += 2;
			
									gte_ldv3(	svec_ptr + 0,
												svec_ptr + 1,
												&Null_svector);
									gte_rtpt();
									gte_stsxy0(&old_xy0);
									gte_stsxy1(&old_xy1);
			
									// Calculate bottom RGBs
									old_col	= MAX(0, old_col - 0x101010);
									col		= old_col + 0x32000000;				// semiTrans POLY_G3 code
			
									// Write bottom poly coords from old screen coords
									MR_COPY32((poly_g3 + 0)->x2, old_xy0);
									MR_COPY32((poly_g3 + 1)->x0, old_xy0);
									MR_COPY32((poly_g3 + 1)->x2, old_xy1);
			
									// Write bottom RGBs
									MR_SET32((poly_g3 + 0)->r2, col);
									MR_SET32((poly_g3 + 1)->r0, col);
									MR_SET32((poly_g3 + 1)->r2, col);
			
									if (trail->tr_ot_ptr[i])
										{
										// Trail sits in a local OT, so add in at furthest entry
										addPrim(trail->tr_ot_ptr[i]->ot_ot[MRFrame_index] + (1 << trail->tr_ot_ptr[i]->ot_shift) - 1, (poly_g3 + 0));
										addPrim(trail->tr_ot_ptr[i]->ot_ot[MRFrame_index] + (1 << trail->tr_ot_ptr[i]->ot_shift) - 1, (poly_g3 + 1));
										}
									else
										{
										gte_stotz(&poly_otz);
										poly_otz 	>>= vp->vp_otz_shift;
										poly_otz 	= MIN(MAX(MR_OT_NEAR_CLIP, poly_otz), vp->vp_ot_size - 1);
										addPrim(vp->vp_work_ot + poly_otz, (poly_g3 + 0));
										addPrim(vp->vp_work_ot + poly_otz, (poly_g3 + 1));
										}
									// Next pair of points
									poly_g3 += 2;
									}
		
								// Add dummy abr changer poly
								if (trail->tr_ot_ptr[i])
									addPrim(trail->tr_ot_ptr[i]->ot_ot[MRFrame_index] + (1 << trail->tr_ot_ptr[i]->ot_shift) - 1, &trail->tr_poly_ft3[i][MRFrame_index]);
								else
									addPrim(vp->vp_work_ot + poly_otz, &trail->tr_poly_ft3[i][MRFrame_index]);
								}
							break;
						//----------------------------------------------------------------
						case EFFECT_TYPE_TONGUE:
							tongue 		= (TONGUE*)effect->ef_extra;
		
					 		poly_g4 	= tongue->to_polys[i][MRFrame_index];
							svec_ptr	= tongue->to_vertices[0];
		
							// Calculate screen coords of first vertex
							svec.vx = -vp->vp_render_matrix.t[0];
							svec.vy = -vp->vp_render_matrix.t[1];
							svec.vz = -vp->vp_render_matrix.t[2];
							MRApplyMatrix(&vp->vp_render_matrix, &svec, (MR_VEC*)MRViewtrans_ptr->t);
							gte_SetRotMatrix(&vp->vp_render_matrix);
							gte_SetTransMatrix(MRViewtrans_ptr);
						
							gte_ldv3(svec_ptr + 0, svec_ptr + 1, svec_ptr + 2);
							gte_rtpt();
							gte_stsxy0(&old_xy0);
							gte_stsxy1(&old_xy1);
							gte_stsxy2(&old_xy2);
	
							// All G4 need to be at same OT, so that dummy F3 can have effect
							gte_avsz3();
							gte_stotz(&poly_otz);
							poly_otz >>= vp->vp_otz_shift;
							poly_otz = MIN(MAX(MR_OT_NEAR_CLIP, poly_otz), vp->vp_ot_size - 1);
	
							// Grab the frog to which this tongue belongs.
							frog = (FROG*)tongue->to_owner;
	
							// Check it for SUPER TONGUE;
							if (frog->fr_powerup_flags & FROG_POWERUP_SUPER_TONGUE)
								{
								// Set the colours.
								if (tongue->to_flags & TONGUE_FLAG_FADING_UP)
									{
									if (tongue->to_colour < 0x8f)
										{
										temp = (frog->fr_super_tongue_timer >> 4);
										tongue->to_colour += ( frog->fr_super_tongue_timer >> 4 );
										tongue->to_colour &= 0xff;
										}
									else
										{
										tongue->to_flags &= ~TONGUE_FLAG_FADING_UP;
										tongue->to_flags |= TONGUE_FLAG_FADING_DOWN;
										}
									}
								else
								 	{
								 	if (tongue->to_colour > 0x4f)
										{
								 		tongue->to_colour -= ( frog->fr_super_tongue_timer >> 4 );
										tongue->to_colour &= 0xff;
										}
								 	else
								 		{
								 		tongue->to_flags &= ~TONGUE_FLAG_FADING_DOWN;
								 		tongue->to_flags |= TONGUE_FLAG_FADING_UP;
										}
									}
								}
							else
								tongue->to_colour = 0x20;
		 	
							k  = tongue->to_section;
							while(k--)
								{
								// Write poly coords 0,2
								MR_COPY32((poly_g4 + 0)->x0, old_xy0);
								MR_COPY32((poly_g4 + 1)->x0, old_xy0);
								MR_COPY32((poly_g4 + 0)->x2, old_xy2);
								MR_COPY32((poly_g4 + 1)->x2, old_xy1);
	
								// Calculate new coords
								svec_ptr += 3;
								gte_ldv3(svec_ptr + 0, svec_ptr + 1, svec_ptr + 2);
								gte_rtpt();
								gte_stsxy0(&old_xy0);
								gte_stsxy1(&old_xy1);
								gte_stsxy2(&old_xy2);
		
								// Write poly coords 1,3
								MR_COPY32((poly_g4 + 0)->x1, old_xy0);
								MR_COPY32((poly_g4 + 1)->x1, old_xy0);
								MR_COPY32((poly_g4 + 0)->x3, old_xy2);
								MR_COPY32((poly_g4 + 1)->x3, old_xy1);
		
								setRGB0(poly_g4 + 0, 0xa0, tongue->to_colour, 0x0);
								setRGB1(poly_g4 + 0, 0xa0, tongue->to_colour, 0x0);
								setRGB0(poly_g4 + 1, 0xa0, tongue->to_colour, 0x0);
								setRGB1(poly_g4 + 1, 0xa0, tongue->to_colour, 0x0);
	
								addPrim(vp->vp_work_ot + poly_otz, (poly_g4 + 0));
								addPrim(vp->vp_work_ot + poly_otz, (poly_g4 + 1));
	
								// Next polys
								poly_g4 += 2;
								}
		
							if (tongue->to_section)
								{
								// Add dummy abr changer poly
								addPrim(vp->vp_work_ot + poly_otz, &tongue->to_poly_ft3[i][MRFrame_index]);
	
								// Add end of tongue image
								poly_ft4 	= &tongue->to_poly_ft4[i][MRFrame_index];
								gte_avsz3();
								gte_stotz(&poly_otz);
								poly_otz 	>>= vp->vp_otz_shift;
								poly_otz 	= MIN(MAX(MR_OT_NEAR_CLIP, poly_otz + TONGUE_END_OT_OFFSET), vp->vp_ot_size - 1);
								z 			= 0x1000 / poly_otz;
	
								if (tongue->to_flags & TONGUE_FLAG_GRABBING)
									{
									if (tongue->to_target)
										{
										z += (tongue->to_counter << 2);
										setRGB0(poly_ft4, 0x60, 0x60, 0x60);
										}
									else
										{
										// Cleaning eyes
										z -= (tongue->to_counter & 1) << 4;
										setRGB0(poly_ft4, 0xc0, tongue->to_colour, 0x00);
										}
									}
								else
									setRGB0(poly_ft4, 0xc0, tongue->to_colour, 0x00);
	
								poly_ft4->x0 	= (MR_SHORT)(old_xy0 & 0xffff)	- z;
								poly_ft4->x1 	= (MR_SHORT)(old_xy0 & 0xffff)	+ z;
								poly_ft4->x2 	= (MR_SHORT)(old_xy0 & 0xffff)	- z;
								poly_ft4->x3 	= (MR_SHORT)(old_xy0 & 0xffff)	+ z;
								poly_ft4->y0 	= (MR_SHORT)(old_xy0 >> 16)    	- z;
								poly_ft4->y1 	= (MR_SHORT)(old_xy0 >> 16)    	- z;
								poly_ft4->y2 	= (MR_SHORT)(old_xy0 >> 16)    	+ z;
								poly_ft4->y3 	= (MR_SHORT)(old_xy0 >> 16)    	+ z;
								poly_otz 		= MIN(vp->vp_ot_size - 1, poly_otz + TONGUE_END_OT_OFFSET);
								addPrim(vp->vp_work_ot + poly_otz, poly_ft4);
								}					
							break;
						//----------------------------------------------------------------
						}	
					}
				}
			}
		}
}


/******************************************************************************
*%%%% ClearEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ClearEffects(MR_VOID)
*
*	FUNCTION	Handles killing of effects. (Need in a separete function for tidy-up)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ClearEffects(MR_VOID)
{
	EFFECT*			effect;
	EFFECT*			effect_prev;

	// Pass 1: sort out kill timer
	effect = Effect_root_ptr;
	while(effect = effect->ef_next_node)
		{
		if (effect->ef_kill_timer)
			{
			if (!(--effect->ef_kill_timer))
				{
				// Free memory
				effect_prev = effect->ef_prev_node;
				KillEffect(effect);
				effect = effect_prev;
				}
			}
		}
}


/******************************************************************************
*%%%% SetupABRChangeFT3
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetupABRChangeFT3(
*						MR_VOID*	poly,
*						MR_USHORT	abr)
*
*	FUNCTION	Sets up a dummy POLY_FT3 with an abr value
*
*	INPUTS		poly	-	ptr to memory to write POLY_FT3
*				abr		-	abr value (0..3)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	SetupABRChangeFT3(	MR_VOID*	poly,
							MR_USHORT	abr)
{
	POLY_FT3*	poly_ft3;

	MR_ASSERT(poly);
	poly_ft3 = poly;

	setPolyFT3(poly_ft3);
	poly_ft3->x0 = -1,	poly_ft3->x1 = -1,	poly_ft3->x2 = -1;
	poly_ft3->y0 = -1,	poly_ft3->y1 = -1,	poly_ft3->y2 = -1;

#ifdef PSX
	poly_ft3->tpage = defTPage(0, 0, abr);
#else
	poly_ft3->tpage = 1;//defTPage(0, 0, abr);
#endif
}


/******************************************************************************
*%%%% CreateTrail
*------------------------------------------------------------------------------
*
*	SYNOPSIS	EFFECT*	trail =	CreateTrail(
*								MR_MAT*		lwtrans,
*								MR_SVEC*	offsets,
*								MR_ULONG	sections)
*
*	FUNCTION	Set up a TRAIL structure
*
*	INPUTS		lwtrans		-	ptr to lw transform of owning frame
*				offsets		-	ptr to two offsets in owning frame for creating new vertex pair
*				sections	-	number of vertex pairs in trail
*
*	RESULT		trail		-	ptr to effect created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.11.96	Tim Closs		Created
*
*%%%**************************************************************************/

EFFECT*	CreateTrail(MR_MAT*		lwtrans,
  					MR_SVEC*	offsets,
					MR_ULONG	sections)
{
	MR_USHORT	i, j, k;
	TRAIL*		trail;
	POLY_G3*	poly;
	POLY_FT3*	poly_ft3;
	EFFECT*		effect;
	

	// Allocate memory
	effect	= CreateEffect(EFFECT_TYPE_TRAIL);
	trail	= (TRAIL*)effect->ef_extra;

	trail->tr_sections			= sections;
	trail->tr_timer				= 0;
	trail->tr_display_sections	= 0;
	trail->tr_lwtrans			= lwtrans;
	trail->tr_offsets			= offsets;
	MR_CLEAR_SVEC(&trail->tr_velocity);
	trail->tr_rgb_increase		= TRAIL_RGB_INCREASE;
	trail->tr_rgb_decrease		= TRAIL_RGB_DECREASE;

	// For each section, need 4n tris: 2 for each quad, n for each viewport, 2 for each frame
	// For each section, need 2 svecs
	trail->tr_polys[0][0]	= MRAllocMem((sizeof(POLY_G3) * sections * 4 * SYSTEM_MAX_VIEWPORTS) + (sizeof(MR_SVEC) * sections * 2), "TRA_TRIS");
	trail->tr_polys[0][1]	= trail->tr_polys[0][0] + (sections * 2);

	for (k = 1; k < SYSTEM_MAX_VIEWPORTS; k++)
		{
		trail->tr_polys[k][0]	= trail->tr_polys[k - 1][1] + (sections * 2);
		trail->tr_polys[k][1]	= trail->tr_polys[k - 0][0] + (sections * 2);
		}

	trail->tr_vertex_coords = (MR_SVEC*)(((MR_UBYTE*)trail->tr_polys[0][0]) + (sizeof(POLY_G3) * sections * 4 * SYSTEM_MAX_VIEWPORTS));
	
	// Set up polys
	poly		= (POLY_G3*)trail->tr_polys[0][0];
	poly_ft3 	= trail->tr_poly_ft3[0];
	for (k = 0; k < Game_total_viewports; k++)
		{
		for (j = 0; j < 2; j++)
			{
			for (i = 0; i < sections; i++)
				{
				setPolyG3(poly);
				setSemiTrans(poly, 1);
				poly++;

				setPolyG3(poly);
				setSemiTrans(poly, 1);
				poly++;
				}
			// Set up dummy abrs
			SetupABRChangeFT3(poly_ft3, 1);
			poly_ft3++;
			}
		}
	
	ResetTrail(effect);
	return(effect);
}


/******************************************************************************
*%%%% ResetTrail
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetTrail(
*						EFFECT*	effect)
*
*	FUNCTION	Reset up a TRAIL structure
*
*	INPUTS		effect		-	ptr to EFFECT of type TRAIL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Tim Closs		Resetd
*
*%%%**************************************************************************/

MR_VOID	ResetTrail(EFFECT*	effect)
{
	MR_SVEC*	svec_ptr;
	MR_SVEC		coords[2];
	MR_VEC		vec;
	TRAIL*		trail;
	MR_LONG		i;


	trail						= (TRAIL*)effect->ef_extra;
	trail->tr_current_section	= trail->tr_sections - 2;
	trail->tr_display_sections	= 0;

	// Set up vertex pairs
	MRApplyMatrix(trail->tr_lwtrans, trail->tr_offsets, &vec);
	coords[0].vx = vec.vx + trail->tr_lwtrans->t[0];
	coords[0].vy = vec.vy + trail->tr_lwtrans->t[1];
	coords[0].vz = vec.vz + trail->tr_lwtrans->t[2];
	MRApplyRotMatrix(&trail->tr_offsets[1], &vec);
	coords[1].vx = vec.vx + trail->tr_lwtrans->t[0];
	coords[1].vy = vec.vy + trail->tr_lwtrans->t[1];
	coords[1].vz = vec.vz + trail->tr_lwtrans->t[2];

	svec_ptr = trail->tr_vertex_coords;
	for (i = 0; i < trail->tr_sections; i++)
		{
		MR_COPY_SVEC(svec_ptr, &coords[0]);
		svec_ptr++;
		MR_COPY_SVEC(svec_ptr, &coords[1]);
		svec_ptr++;
		}
}

	
/******************************************************************************
*%%%% CreatePolyMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	POLY_MESH*	poly_mesh =	CreatePolyMesh(
*									   	MR_TEXTURE*		texture,
*									   	MR_SHORT		x,
*									   	MR_SHORT		y,
*									   	MR_USHORT		w,
*									   	MR_USHORT		h,
*									   	MR_VIEWPORT*	vp,
*									   	MR_ULONG		otz)
*									   	MR_USHORT		semi_trans)
*
*	FUNCTION	Create a mesh of POLY_GT4
*
*	INPUTS		texture		-	to map onto mesh
*				x			-	screen x of top left of mesh
*				y			-	screen y of top left of mesh
*				w			-	width of mesh in polys
*				h			-	height of mesh in polys
*				vp			-	ptr to viewport to render into
*				otz			-  OT position ot add prims to
*				semi_trans	-  value to use in SetSemiTrans
*								
*	RESULT		poly_mesh	-	ptr to the POLY_MESH structure created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

POLY_MESH*	CreatePolyMesh(	MR_TEXTURE*		texture,
							MR_SHORT		x,
							MR_SHORT		y,
							MR_USHORT		w,
							MR_USHORT		h,
							MR_VIEWPORT*	vp,
							MR_ULONG		otz,
							MR_USHORT		semi_trans)
{
	MR_USHORT	i, j, k;
	POLY_GT4*	poly_gt4;
	POLY_MESH*	poly_mesh;


	MR_ASSERT(texture);

	poly_mesh				= MRAllocMem(sizeof(POLY_MESH) + (sizeof(POLY_GT4) * 2 * w * h), "POLYMESH");
	poly_mesh->pm_texture	= texture;
	poly_mesh->pm_x			= x;
	poly_mesh->pm_y			= y;
	poly_mesh->pm_w			= w;
	poly_mesh->pm_h			= h;
	poly_mesh->pm_viewport	= vp;
	poly_mesh->pm_otz		= otz;
	poly_mesh->pm_polys[0]	= (POLY_GT4*)(((MR_UBYTE*)poly_mesh) + sizeof(POLY_MESH));
	poly_mesh->pm_polys[1]	= (POLY_GT4*)(((MR_UBYTE*)poly_mesh) + sizeof(POLY_MESH) + (sizeof(POLY_GT4) * w * h));
	poly_gt4 				= poly_mesh->pm_polys[0]; 

	for (i = 0; i < 2; i++)
		{
		for (j = 0; j < h; j++)
			{
			for (k = 0; k < w; k++)
				{
				setPolyGT4(poly_gt4);
				setSemiTrans(poly_gt4, semi_trans);
				setRGB0(poly_gt4, 0x80, 0x80, 0x80);
				setRGB1(poly_gt4, 0x80, 0x80, 0x80);
				setRGB2(poly_gt4, 0x80, 0x80, 0x80);
				setRGB3(poly_gt4, 0x80, 0x80, 0x80);
				poly_gt4->x0	= x + (((k + 0) * texture->te_w) / w);
				poly_gt4->x1	= x + (((k + 1) * texture->te_w) / w);
				poly_gt4->x2	= poly_gt4->x0;
				poly_gt4->x3	= poly_gt4->x1;

				poly_gt4->y0	= y + (((j + 0) * texture->te_h) / h);
				poly_gt4->y2	= y + (((j + 1) * texture->te_h) / h);
				poly_gt4->y1	= poly_gt4->y0;
				poly_gt4->y3	= poly_gt4->y2;

				poly_gt4->u0	= texture->te_u0 + (((k + 0) * texture->te_w) / w);
				poly_gt4->u1	= texture->te_u0 + (((k + 1) * texture->te_w) / w);
				poly_gt4->u2	= poly_gt4->u0;
				poly_gt4->u3	= poly_gt4->u1;

				poly_gt4->v0	= texture->te_v0 + (((j + 0) * texture->te_h) / h);
				poly_gt4->v2	= texture->te_v0 + (((j + 1) * texture->te_h) / h);
				poly_gt4->v1	= poly_gt4->v0;
				poly_gt4->v3	= poly_gt4->v2;

				poly_gt4->tpage	= texture->te_tpage_id;
#ifdef PSX
				poly_gt4->clut	= texture->te_clut_id;
#endif
				poly_gt4++;
				}
			}
		}
	return(poly_mesh);
}


/******************************************************************************
*%%%% KillPolyMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillPolyMesh(
*						POLY_MESH*	poly_mesh)
*
*	FUNCTION	Kill a mesh of POLY_GT4 (and free all memory)
*
*	INPUTS		poly_mesh	-	ptr to structure to kill
*								
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillPolyMesh(POLY_MESH*	poly_mesh)
{
	MRFreeMem(poly_mesh);
}	


/******************************************************************************
*%%%% UpdatePolyMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdatePolyMesh(
*						POLY_MESH*			poly_mesh,
*						POLY_MESH_LIGHT*	light0,
*						POLY_MESH_LIGHT*	light1,
*						POLY_MESH_LIGHT*	light2)
*
*	FUNCTION	Write the poly RGBs based on up to three lights
*
*	INPUTS		poly_mesh	- ptr to structure to update
*				light0		- ptr to 1st light (or NULL)
*				light1		- ptr to 2nd light (or NULL)
*				light2		- ptr to 3rd light (or NULL)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdatePolyMesh(	POLY_MESH*			poly_mesh,
						POLY_MESH_LIGHT*	light0,
						POLY_MESH_LIGHT*	light1,
						POLY_MESH_LIGHT*	light2)
{
	MR_USHORT			i, j, l, vx, vy, w, h;
	MR_LONG				dx, dy, m;
	POLY_GT4*			poly0;
	POLY_GT4*			poly1;
	POLY_GT4*			poly2;
	POLY_GT4*			poly3;
	MR_USHORT			r, g, b;
	MR_ULONG			rgb;
	POLY_MESH_LIGHT*	lights[3];
	MR_UBYTE			code;


	MR_ASSERT(poly_mesh);

	w 			= poly_mesh->pm_w;
	h 			= poly_mesh->pm_h;
	lights[0] 	= light0;
	lights[1] 	= light1;
	lights[2] 	= light2;

	// Write rgbs
	poly3	= poly_mesh->pm_polys[MRFrame_index];
	poly2	= poly3 - 1;
	poly1	= poly3 - w;
	poly0	= poly1 - 1;

#ifdef PSX
	code	= poly3->code;
#endif

	for (j = 0; j <= h; j++)
		{
		for (i = 0; i <= w; i++)
			{
			// Get vertex x, y
			if (i == 0)
				{
				if (j == 0)
					vx = poly3->x0,	vy = poly3->y0;
				else
					vx = poly1->x2,	vy = poly1->y2;
				}
			else
				{
				if (j == 0)
					vx = poly2->x1,	vy = poly2->y1;
				else
					vx = poly0->x1,	vy = poly0->y1;
				}

			// Reset vertex rgb
			r	= 0;
			g	= 0;
			b	= 0;

			// Add effect from up to 3 lights
			for (l = 0; l < 3; l++)
				{			
				if (lights[l])
					{
					dx	= lights[l]->pm_x - vx;
					dy	= lights[l]->pm_y - vy;
					m 	= MR_SQRT(MR_SQR(dx) + MR_SQR(dy));
					m 	= MAX(lights[l]->pm_min_dist, m);
					r 	+= (lights[l]->pm_cvec.r * lights[l]->pm_strength) / m;
					g 	+= (lights[l]->pm_cvec.g * lights[l]->pm_strength) / m;
					b 	+= (lights[l]->pm_cvec.b * lights[l]->pm_strength) / m;
					}
				}
			r	= MIN(0xff, r);
			g	= MIN(0xff, g);
			b	= MIN(0xff, b);

			// Write to 1..4 polys
			rgb	= (code << 24) + (b << 16) + (g << 8) + (r << 0);
			if ((j > 0) && (i > 0))
				MR_SET32(poly0->r3, rgb);
			if ((j > 0) && (i < w))
				MR_SET32(poly1->r2, rgb);
			if ((j < h) && (i > 0))
				MR_SET32(poly2->r1, rgb);
			if ((j < h) && (i < w))
				MR_SET32(poly3->r0, rgb);

			poly0++;
			poly1++;
			poly2++;
			poly3++;
			}
		poly0--;
		poly1--;
		poly2--;
		poly3--;
		}
}


/******************************************************************************
*%%%% RenderPolyMesh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderPolyMesh(
*						POLY_MESH*	poly_mesh)
*
*	FUNCTION	Add the polys to an OT
*
*	INPUTS		poly_mesh	- ptr to mesh
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.12.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	RenderPolyMesh(POLY_MESH*	poly_mesh)
{
	MR_USHORT	i;
	POLY_GT4*	poly;
	

	MR_ASSERT(poly_mesh);

	// Add prims
	poly	= poly_mesh->pm_polys[MRFrame_index];
	i 		= (poly_mesh->pm_w * poly_mesh->pm_h);
	while(i--)
		{
		addPrim(poly_mesh->pm_viewport->vp_work_ot + poly_mesh->pm_otz, poly);
		poly++;
		}
}


/******************************************************************************
*%%%% CreateTongue
*------------------------------------------------------------------------------
*
*	SYNOPSIS	EFFECT*	tongue =	CreateTongue(
*									MR_MAT*		lwtrans,
*									MR_VOID*	owner)
*
*	FUNCTION	Set up a TONGUE structure
*
*	INPUTS		lwtrans		-	ptr to lw transform of owning frame
*				owner		-	usually FROG*
*
*	RESULT		tongue		-	ptr to effect created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.07.97	Tim Closs		Created
*	02.06.97	Martin Kift		PC'er'fied
*
*%%%**************************************************************************/

EFFECT*	CreateTongue(	MR_MAT*		lwtrans,
						MR_VOID*	owner)
{
	MR_USHORT	i, j, k;
	TONGUE*		tongue;
	POLY_G4*	poly_g4;
	POLY_FT3*	poly_ft3;
	POLY_FT4*	poly_ft4;
	EFFECT*		effect;
	MR_TEXTURE*	texture;
	

	// Allocate memory
	effect	= CreateEffect(EFFECT_TYPE_TONGUE);
	tongue	= (TONGUE*)effect->ef_extra;
	texture	= &im_tongue_tip;

	tongue->to_flags	= NULL;
	tongue->to_section	= 0;
	tongue->to_lwtrans	= lwtrans;
	tongue->to_target	= NULL;
	tongue->to_owner	= owner;

	// Set up polys
	poly_g4		= tongue->to_polys[0][0];
	poly_ft3 	= tongue->to_poly_ft3[0];
	poly_ft4 	= tongue->to_poly_ft4[0];
	for (k = 0; k < Game_total_viewports; k++)
		{
		for (j = 0; j < 2; j++)
			{
			for (i = 0; i < TONGUE_MAX_SECTIONS; i++)
				{
				setPolyG4(poly_g4);
				setSemiTrans(poly_g4, 1);		
				setRGB0(poly_g4, 0xa0, 0x20, 0x20);
				setRGB1(poly_g4, 0xa0, 0x20, 0x20);
				setRGB2(poly_g4, 0x00, 0x00, 0x00);
				setRGB3(poly_g4, 0x00, 0x00, 0x00);
				poly_g4++;

				setPolyG4(poly_g4);
				setSemiTrans(poly_g4, 1);		
				setRGB0(poly_g4, 0xa0, 0x20, 0x20);
				setRGB1(poly_g4, 0xa0, 0x20, 0x20);
				setRGB2(poly_g4, 0x00, 0x00, 0x00);
				setRGB3(poly_g4, 0x00, 0x00, 0x00);
				poly_g4++;
				}

			// Set up dummy abr
			SetupABRChangeFT3(poly_ft3, 1);
			poly_ft3++;

			// Set up tongue end image
			setPolyFT4(poly_ft4);
			setSemiTrans(poly_ft4, 1);		
			setRGB0(poly_ft4, 0xc0, 0x00, 0x00);
#ifdef PSX
			MR_COPY32(poly_ft4->u0, texture->te_u0);
			MR_COPY32(poly_ft4->u1, texture->te_u1);
#else
			poly_ft4->tpage = texture->te_tpage_id;
			MR_COPY16(poly_ft4->u0, texture->te_u0);
			MR_COPY16(poly_ft4->u1, texture->te_u1);
#endif
			MR_COPY16(poly_ft4->u2, texture->te_u2);
			MR_COPY16(poly_ft4->u3, texture->te_u3);
			poly_ft4++;
			}
		}
	return(effect);
}


/******************************************************************************
*%%%% StartTongue
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	StartTongue(
*						EFFECT*	effect,
*						ENTITY*	target)
*
*	FUNCTION	Start a TONGUE moving out
*
*	INPUTS		effect	-	ptr to effect of type TONGUE
*				target	-	ptr to ENTITY target
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	StartTongue(EFFECT*	effect,
					ENTITY*	target)
{
	TONGUE*			tongue;


	MR_ASSERT(effect);
	tongue = effect->ef_extra;

	effect->ef_flags 	&= ~(EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
	tongue->to_flags 	= TONGUE_FLAG_MOVING_OUT | TONGUE_FLAG_FADING_UP;
	tongue->to_target	= target;
	tongue->to_section	= 0;
	tongue->to_colour	= 0x40;

	if (target)
		{
		MR_ASSERT(target->en_live_entity);
		target->en_live_entity->le_flags |= LIVE_ENTITY_TARGETTED;
		}
	else
		{
		// No target - clean eyes
		}
}


/******************************************************************************
*%%%% ResetTongue
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetTongue(
*						EFFECT*	effect)
*
*	FUNCTION	Reset a TONGUE
*
*	INPUTS		effect	-	ptr to effect of type TONGUE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ResetTongue(EFFECT*	effect)
{
	TONGUE*			tongue;


	MR_ASSERT(effect);
	tongue = effect->ef_extra;

	effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
	if (tongue->to_target)
		tongue->to_target->en_flags |= ENTITY_HIDDEN;

	tongue->to_flags 	= NULL;
	tongue->to_target	= NULL;
	tongue->to_section	= 0;
}


/******************************************************************************
*%%%% CreateMeshPolyPieces
*------------------------------------------------------------------------------
*
*	SYNOPSIS	POLY_PIECE* pieces = 	CreateMeshPolyPieces(
*										MR_MOF*	mof)
*
*	FUNCTION	Allocate a POLY_PIECE for each poly in the (1st part of the)
*				mof
*
*	INPUTS		mof		-	ptr to mof
*
*	RESULT		pieces	-	ptr to POLY_PIECEs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

POLY_PIECE*	CreateMeshPolyPieces(MR_MOF*	mof)
{
	MR_PART*	part_ptr;
	POLY_PIECE*	poly_piece;
	POLY_PIECE*	first_piece;
	MR_LONG		prims, i, type;
	MR_ULONG*	prim_ptr;
	MR_SVEC*	vertex_block;


	MR_ASSERT(mof);
	MR_ASSERT(!(mof->mm_flags & MR_MOF_ANIMATED));
	MR_ASSERT(mof->mm_extra == 1);

	part_ptr 		= (MR_PART*)(mof + 1);
	prims			= part_ptr->mp_prims;
	prim_ptr		= part_ptr->mp_prim_ptr;
	poly_piece		= MRAllocMem(sizeof(POLY_PIECE) * prims, "POLY PIECES");
	first_piece		= poly_piece;
	vertex_block	= part_ptr->mp_partcel_ptr->mp_vert_ptr;

	while(prims)
		{
		type	= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
		i		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
		prims	-= i;
		prim_ptr++;
			
		switch(type)
			{
			case MR_MPRIMID_F3:
			case MR_MPRIMID_FT3:
			case MR_MPRIMID_G3:
			case MR_MPRIMID_GT3:
			case MR_MPRIMID_E3:
			case MR_MPRIMID_GE3:
				// Tri
				while(i--)
					{
					MR_COPY_SVEC(&poly_piece->pp_vertices[0], &vertex_block[((MR_MPRIM_F3*)prim_ptr)->mp_p0]);
					MR_COPY_SVEC(&poly_piece->pp_vertices[1], &vertex_block[((MR_MPRIM_F3*)prim_ptr)->mp_p1]);
					MR_COPY_SVEC(&poly_piece->pp_vertices[2], &vertex_block[((MR_MPRIM_F3*)prim_ptr)->mp_p2]);
					poly_piece->pp_origin.vx = (poly_piece->pp_vertices[0].vx + poly_piece->pp_vertices[1].vx + poly_piece->pp_vertices[2].vx) / 3;
					poly_piece->pp_origin.vy = (poly_piece->pp_vertices[0].vy + poly_piece->pp_vertices[1].vy + poly_piece->pp_vertices[2].vy) / 3;
					poly_piece->pp_origin.vz = (poly_piece->pp_vertices[0].vz + poly_piece->pp_vertices[1].vz + poly_piece->pp_vertices[2].vz) / 3;
					MR_SUB_SVEC(&poly_piece->pp_vertices[0], &poly_piece->pp_origin);
					MR_SUB_SVEC(&poly_piece->pp_vertices[1], &poly_piece->pp_origin);
					MR_SUB_SVEC(&poly_piece->pp_vertices[2], &poly_piece->pp_origin);
					poly_piece++;
					prim_ptr += MRPrim_type_mod_sizes[type];
					}
				break;			

			case MR_MPRIMID_F4:
			case MR_MPRIMID_FT4:
			case MR_MPRIMID_G4:
			case MR_MPRIMID_GT4:
			case MR_MPRIMID_E4:
			case MR_MPRIMID_GE4:
				// Quad
				while(i--)
					{
					MR_COPY_SVEC(&poly_piece->pp_vertices[0], &vertex_block[((MR_MPRIM_F4*)prim_ptr)->mp_p0]);
					MR_COPY_SVEC(&poly_piece->pp_vertices[1], &vertex_block[((MR_MPRIM_F4*)prim_ptr)->mp_p1]);
					MR_COPY_SVEC(&poly_piece->pp_vertices[2], &vertex_block[((MR_MPRIM_F4*)prim_ptr)->mp_p2]);
					MR_COPY_SVEC(&poly_piece->pp_vertices[3], &vertex_block[((MR_MPRIM_F4*)prim_ptr)->mp_p3]);
					poly_piece->pp_origin.vx = (poly_piece->pp_vertices[0].vx + poly_piece->pp_vertices[1].vx + poly_piece->pp_vertices[2].vx + poly_piece->pp_vertices[3].vx) >> 2;
					poly_piece->pp_origin.vy = (poly_piece->pp_vertices[0].vy + poly_piece->pp_vertices[1].vy + poly_piece->pp_vertices[2].vy + poly_piece->pp_vertices[3].vy) >> 2;
					poly_piece->pp_origin.vz = (poly_piece->pp_vertices[0].vz + poly_piece->pp_vertices[1].vz + poly_piece->pp_vertices[2].vz + poly_piece->pp_vertices[3].vz) >> 2;
					MR_SUB_SVEC(&poly_piece->pp_vertices[0], &poly_piece->pp_origin);
					MR_SUB_SVEC(&poly_piece->pp_vertices[1], &poly_piece->pp_origin);
					MR_SUB_SVEC(&poly_piece->pp_vertices[2], &poly_piece->pp_origin);
					MR_SUB_SVEC(&poly_piece->pp_vertices[3], &poly_piece->pp_origin);
					poly_piece++;
					prim_ptr += MRPrim_type_mod_sizes[type];
					}
				break;			
			}
		}
	return(first_piece);
}


/******************************************************************************
*%%%% UpdatePolyPiecePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdatePolyPiecePop(
*						POLY_PIECE_POP*	poly_piece_pop)
*
*	FUNCTION	Update popping polys
*
*	INPUTS		poly_piece_pop	-	ptr to structure to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdatePolyPiecePop(POLY_PIECE_POP*	poly_piece_pop)
{
	MR_LONG				i;
	POLY_PIECE_DYNAMIC*	poly_piece_dynamic;


	MR_ASSERT(poly_piece_pop);
	
	if (poly_piece_pop->pp_timer)
		{
		poly_piece_pop->pp_timer--;

		MR_ADD_SVEC(&poly_piece_pop->pp_rotation, &poly_piece_pop->pp_ang_vel);
		poly_piece_pop->pp_ang_vel.vx += POLY_PIECE_POP_ANG_ACC_X;
		poly_piece_pop->pp_ang_vel.vy += POLY_PIECE_POP_ANG_ACC_Y;
		poly_piece_pop->pp_ang_vel.vz += POLY_PIECE_POP_ANG_ACC_Z;

		// Set up position/velocity of pieces
		i 					= poly_piece_pop->pp_numpolys;
		poly_piece_dynamic 	= poly_piece_pop->pp_poly_piece_dynamics;
		while(i--)
			{
			poly_piece_dynamic->pp_velocity.vy += (WORLD_GRAVITY << 1);

			MR_ADD_VEC(&poly_piece_dynamic->pp_position, &poly_piece_dynamic->pp_velocity);
			poly_piece_dynamic++;
			}
		}
}


/******************************************************************************
*%%%% RenderPolyPiecePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RenderPolyPiecePop(
*						POLY_PIECE_POP*	poly_piece_pop,
*						MR_MESH_INST*	mesh_inst_ptr,
*						MR_ULONG		vp_id)
*
*	FUNCTION	Render popping polys
*
*	INPUTS		poly_piece_pop	-	ptr to structure to update
*				mesh_inst_ptr	-	ptr to MR_MESH_INST (to get to polys)
*				vp_id			-	viewport id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	RenderPolyPiecePop(	POLY_PIECE_POP*	poly_piece_pop,
							MR_MESH_INST*	mesh_inst_ptr,
							MR_ULONG		vp_id)
{
	MR_VIEWPORT*		vp;
	MR_PART*			part_ptr;
	POLY_PIECE*			poly_piece;
	POLY_PIECE_DYNAMIC*	poly_piece_dynamic;
	MR_LONG				prims, i, type, scale, otz;
	MR_ULONG*			prim_ptr;
	MR_UBYTE*			poly_ptr;
	MR_MAT				matrix;
	MR_SVEC				svec;


	vp			= Game_viewports[vp_id];
	part_ptr 	= (MR_PART*)(poly_piece_pop->pp_mof + 1);
	prim_ptr	= part_ptr->mp_prim_ptr;
	poly_ptr	= ((MR_UBYTE*)mesh_inst_ptr->mi_prims[0]) + (part_ptr->mp_buff_size * MRFrame_index);
	otz			= poly_piece_pop->pp_otz;

	// Set up gte rotation
	MRRotMatrix(&poly_piece_pop->pp_rotation, &matrix);
	MRMulMatrixABA(&matrix, poly_piece_pop->pp_lwtrans);

	// Scale up slightly in general.. down towards end of effect
	scale = MIN(0x1200, poly_piece_pop->pp_timer << 8);
	MRScale_matrix.m[0][0] = scale;
	MRScale_matrix.m[1][1] = scale;
	MRScale_matrix.m[2][2] = scale;
	MRMulMatrixABB(&MRScale_matrix, &matrix);
	MRMulMatrixABC(&vp->vp_render_matrix, &matrix, MRViewtrans_ptr);

	// First, set up pp_render_translation entries, so we can keep one rotation matrix for the main poly loop
	prims				= poly_piece_pop->pp_numpolys;
	poly_piece			= poly_piece_pop->pp_poly_pieces;
	poly_piece_dynamic	= poly_piece_pop->pp_poly_piece_dynamics;
	gte_SetRotMatrix(&vp->vp_render_matrix);
	while(prims--)
		{
		svec.vx = (poly_piece_dynamic->pp_position.vx >> 16) - vp->vp_render_matrix.t[0];
		svec.vy = (poly_piece_dynamic->pp_position.vy >> 16) - vp->vp_render_matrix.t[1];
		svec.vz = (poly_piece_dynamic->pp_position.vz >> 16) - vp->vp_render_matrix.t[2];
		MRApplyRotMatrix(&svec, &poly_piece->pp_render_translation);
		poly_piece++;
		poly_piece_dynamic++;
		}

	// Now do the polys
	prims		= poly_piece_pop->pp_numpolys;
	poly_piece	= poly_piece_pop->pp_poly_pieces;
	gte_SetRotMatrix(MRViewtrans_ptr);
	while(prims)
		{
		type		= ((MR_MPRIM_HEADER*)prim_ptr)->mm_type;
		i			= ((MR_MPRIM_HEADER*)prim_ptr)->mm_count;
		prims		-= i;
		prim_ptr 	+= (1 + (MRPrim_type_mod_sizes[type] * i));
			
		switch(type)
			{
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_F3:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);
	
					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[2]);
					gte_rtpt();
					poly_piece++;
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_F3*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_F3*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_F3*)poly_ptr)->x2);
					((POLY_F3*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_FT3:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);
	
					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[2]);
					gte_rtpt();
					poly_piece++;
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_FT3*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_FT3*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_FT3*)poly_ptr)->x2);
					((POLY_FT3*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_G3:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);
	
					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[2]);
					gte_rtpt();
					poly_piece++;
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_G3*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_G3*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_G3*)poly_ptr)->x2);
					((POLY_G3*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_GT3:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);
	
					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[2]);
					gte_rtpt();
					poly_piece++;
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_GT3*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_GT3*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_GT3*)poly_ptr)->x2);
					((POLY_GT3*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_F4:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);

					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[3]);
					gte_rtpt();
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_F4*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_F4*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_F4*)poly_ptr)->x2);

					gte_ldv0(&poly_piece->pp_vertices[2]);
					gte_rtps();
					poly_piece++;
					gte_stsxy((MR_LONG*)&((POLY_F4*)poly_ptr)->x3);
					((POLY_F4*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_FT4:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);

					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[3]);
					gte_rtpt();
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_FT4*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_FT4*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_FT4*)poly_ptr)->x2);

					gte_ldv0(&poly_piece->pp_vertices[2]);
					gte_rtps();
					poly_piece++;
					gte_stsxy((MR_LONG*)&((POLY_FT4*)poly_ptr)->x3);
					((POLY_FT4*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_G4:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);

					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[3]);
					gte_rtpt();
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_G4*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_G4*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_G4*)poly_ptr)->x2);

					gte_ldv0(&poly_piece->pp_vertices[2]);
					gte_rtps();
					poly_piece++;
					gte_stsxy((MR_LONG*)&((POLY_G4*)poly_ptr)->x3);
					((POLY_G4*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			case MR_MPRIMID_GT4:
				while(i--)
					{
					MR_COPY_VEC((MR_VEC*)MRViewtrans_ptr->t, &poly_piece->pp_render_translation);
					gte_SetTransMatrix(MRViewtrans_ptr);

					gte_ldv3(	&poly_piece->pp_vertices[0],
								&poly_piece->pp_vertices[1],
								&poly_piece->pp_vertices[3]);
					gte_rtpt();
					addPrim(vp->vp_work_ot + otz, poly_ptr);
					gte_stsxy3(	(MR_LONG*)&((POLY_GT4*)poly_ptr)->x0,
								(MR_LONG*)&((POLY_GT4*)poly_ptr)->x1,
								(MR_LONG*)&((POLY_GT4*)poly_ptr)->x2);

					gte_ldv0(&poly_piece->pp_vertices[2]);
					gte_rtps();
					poly_piece++;
					gte_stsxy((MR_LONG*)&((POLY_GT4*)poly_ptr)->x3);
					((POLY_GT4*)poly_ptr)++;
					}
				break;
			//---------------------------------------------------------------------------------
			}
		}
}


/******************************************************************************
*%%%% CreateParticleEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	EFFECT*	pgen = 	CreateSlipParticleEffect(
*									MR_VOID*		frog,
*									MR_ULONG		particle_type,
*									MR_SVEC*		svec)
*
*	FUNCTION	Set up a slip particle generator structure
*
*	INPUTS		frog		-	ptr to frog 
*				pgen_init	-	ptr to pgen init structure
*				svec		-	ptr to svec (offset for generator)
*
*	RESULT		pgen		-	ptr to effect created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_OBJECT*	CreateParticleEffect(	MR_VOID*		frog_void_ptr,
									MR_ULONG		particle_type,
									MR_SVEC*		svec)
{
	MR_SVEC			temp_svec;
	MR_PGEN_INIT*	pgen_inst;
	MR_OBJECT*		object;
	FROG*			frog;

	frog = (FROG*)frog_void_ptr;

	MR_ASSERT (particle_type < FROG_PARTICLE_MAX);

	// Only create a particle generator if one is specced for this type, and this
	// game mode (single or multiplayer)
	if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS)
		pgen_inst = Frog_particle_effects[particle_type].fp_pgen_single;
	else
		pgen_inst = Frog_particle_effects[particle_type].fp_pgen_multi;

	if (pgen_inst)
		{
		// Temp code maybe.. if svec was NULL, just use frog position
		if (svec)
			{
			object 	= MRCreatePgen(pgen_inst, (MR_FRAME*)frog->fr_lwtrans, MR_OBJ_STATIC, svec);
			}
		else
			{
			MR_SVEC_EQUALS_VEC(&temp_svec, (MR_VEC*)frog->fr_lwtrans->t);

			object	= MRCreatePgen(pgen_inst, (MR_FRAME*)frog->fr_lwtrans, MR_OBJ_STATIC, &temp_svec);
			}

		// Store FROG* as owner of particle generator
		object->ob_extra.ob_extra_pgen->pg_owner = frog;

		// Add object to viewport(s)
		GameAddObjectToViewports(object);

		// Store flags
		frog->fr_particle_flags |= Frog_particle_effects[particle_type].fp_flags;
		return object;
		}
	return NULL;
}


