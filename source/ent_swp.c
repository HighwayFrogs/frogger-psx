/******************************************************************************
*%%%% ent_swp.c
*------------------------------------------------------------------------------
*
*	Swamp code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Martin Kift		Created
*	24.05.97	Martin Kift		Added squirts and crushers
*
*%%%**************************************************************************/

#include "ent_swp.h"
#include "scripter.h"
#include "scripts.h"
#include "sound.h"
#include "frog.h"
#include "collide.h"

MR_MAT		Rat_splash_matrix;

/******************************************************************************
*%%%% ENTSTRSwpCreateSquirt
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreateSquirt(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a falling squirt for the swamp level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpCreateSquirt(LIVE_ENTITY* live_entity)
{
	SWAMP_SQUIRT*		squirt_map_data;
	SWAMP_RT_SQUIRT*	squirt;
	ENTITY*				entity;

	entity 			= live_entity->le_entity;
	squirt_map_data	= (SWAMP_SQUIRT*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	// the runtime structure has already been alloced
	squirt = (SWAMP_RT_SQUIRT*)live_entity->le_specific;

	// setup runtime data
	squirt->sq_curr_time	= squirt_map_data->sq_time_delay;
	squirt->sq_action		= SWAMP_SQUIRT_WAITING;
	MR_SET_VEC(&squirt->sq_velocity, 0, 0, 0);
	MR_SET_VEC(&squirt->sq_position, 0, 0, 0);

	MR_COPY_MAT(live_entity->le_lwtrans, &squirt_map_data->sq_matrix);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)squirt_map_data->sq_matrix.t);
}


/******************************************************************************
*%%%% ENTSTRSwpUpdateSquirt
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpUpdateSquirt(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the swamp squirt entity.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*	26.06.97	Gary Richards	Changed so it doesn't fall under gravity.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpUpdateSquirt(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	SWAMP_RT_SQUIRT*		squirt;
	SWAMP_SQUIRT*			squirt_map_data;

	entity			= live_entity->le_entity;
	squirt			= live_entity->le_specific;
	squirt_map_data	= (SWAMP_SQUIRT*)(entity + 1);

   	switch (squirt->sq_action)
		{
		// ---------------------------------------------------------------------------
		case SWAMP_SQUIRT_WAITING:
			// Check to see if the time limit is up.
			if (squirt->sq_curr_time > 0)
				squirt->sq_curr_time--;
			else
				squirt->sq_action = SWAMP_SQUIRT_FALL_PREPARE;
			break;
		// ------------------------------------------------------------------------------
		case SWAMP_SQUIRT_FALL_PREPARE:
			// Time's up, so drop to the ground.

			// Set the Positional Offset to the current position.
			squirt->sq_position.vx = (live_entity->le_lwtrans->t[0] << 16);
			squirt->sq_position.vy = (live_entity->le_lwtrans->t[1] << 16);
			squirt->sq_position.vz = (live_entity->le_lwtrans->t[2] << 16);

			// Find distance between where we are and where we want to be.
			squirt->sq_velocity.vx = (squirt_map_data->sq_target.vx << 16) - squirt->sq_position.vx;
			squirt->sq_velocity.vy = (squirt_map_data->sq_target.vy << 16) - squirt->sq_position.vy;
			squirt->sq_velocity.vz = (squirt_map_data->sq_target.vz << 16) - squirt->sq_position.vz;

			// Divide this over time to work out how much we travel each frame.
			squirt->sq_velocity.vx /= squirt_map_data->sq_drop_time;
			squirt->sq_velocity.vy /= squirt_map_data->sq_drop_time;
			squirt->sq_velocity.vz /= squirt_map_data->sq_drop_time;

			squirt->sq_curr_time	= squirt_map_data->sq_drop_time;
			squirt->sq_action		= SWAMP_SQUIRT_FALLING;
			if ( DistanceToFrogger(live_entity,0,0)  < SWP_SQUIRT_DISTANCE)
		 		MRSNDPlaySound(SFX_SWP_ACID_DRIP, NULL, 0, 0);
			break;
			
		// ------------------------------------------------------------------------------
		case SWAMP_SQUIRT_FALLING:
			// Squirt is falling towards the target
			live_entity->le_lwtrans->t[0] += (squirt->sq_velocity.vx >> 16 );
			live_entity->le_lwtrans->t[1] += (squirt->sq_velocity.vy >> 16 );
			live_entity->le_lwtrans->t[2] += (squirt->sq_velocity.vz >> 16 );
		
			// Check to see if Time has reached zero.
			if (squirt->sq_curr_time-- <= 0)
				{
				// If Zero then, reset the squirt to be waiting.
				squirt->sq_action		= SWAMP_SQUIRT_FALL_PREPARE;

				// reset the position based on the supplied matrix...
				MR_COPY_MAT(live_entity->le_lwtrans, &squirt_map_data->sq_matrix);
				MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)squirt_map_data->sq_matrix.t);
				}
			break;
		// ------------------------------------------------------------------------------------------
		}
}


/******************************************************************************
*%%%% ENTSTRSwpCreateCrusher
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreateCrusher(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a crusher for the swamp level
*	MATCH		https://decomp.me/scratch/G9TXb	(By Kneesnap)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpCreateCrusher(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	SWAMP_RT_CRUSHER*		crusher;
	SWAMP_CRUSHER*			crusher_map_data;

	entity				= live_entity->le_entity;
	crusher				= live_entity->le_specific;
	crusher_map_data	= (SWAMP_CRUSHER*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	crusher->cr_direction = SWAMP_CRUSHER_IN;
	crusher->cr_time	= crusher_map_data->cr_delay;
	crusher->cr_action	= SWAMP_CRUSHER_WAITING;
	crusher->cr_count = 0;
	PlayMovingSound(live_entity, SFX_SWP_CRUSH_AMB, 768, 1280);
}


/******************************************************************************
*%%%% ENTSTRSwpUpdateCrusher
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpUpdateCrusher(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the swamp crusher entity.
*	MATCH		https://decomp.me/scratch/UsN6l	(By Kneesnap)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpUpdateCrusher(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	SWAMP_RT_CRUSHER*		crusher;
	SWAMP_CRUSHER*			crusher_map_data;

	entity				= live_entity->le_entity;
	crusher				= live_entity->le_specific;
	crusher_map_data	= (SWAMP_CRUSHER*)(entity + 1);

	if (crusher->cr_count)
		crusher->cr_count--;

	if (crusher->cr_action == SWAMP_CRUSHER_WAITING)
		{
		if (!crusher->cr_time--)
			crusher->cr_action = SWAMP_CRUSHER_CRUSHING;
		}
	else
		{
		switch (crusher_map_data->cr_direction)
			{
			case SWAMP_CRUSHER_NORTH:
				if (crusher->cr_direction == SWAMP_CRUSHER_IN)
					{
					live_entity->le_lwtrans->t[2] += (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[2] > (crusher_map_data->cr_matrix.t[2] + crusher_map_data->cr_distance))
						crusher->cr_direction = !crusher->cr_direction;
					}
				else
					{
					live_entity->le_lwtrans->t[2] -= (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[2] < crusher_map_data->cr_matrix.t[2])
						crusher->cr_direction = !crusher->cr_direction;
					}
				break;
			case SWAMP_CRUSHER_EAST:
				if (crusher->cr_direction == SWAMP_CRUSHER_IN)
					{
					live_entity->le_lwtrans->t[0] += (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[0] > (crusher_map_data->cr_matrix.t[0] + crusher_map_data->cr_distance))
						crusher->cr_direction = !crusher->cr_direction;
					}
				else
					{
					live_entity->le_lwtrans->t[0] -= (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[0] < crusher_map_data->cr_matrix.t[0])
						crusher->cr_direction = !crusher->cr_direction;
					}
				break;
			case SWAMP_CRUSHER_SOUTH:
				if (crusher->cr_direction == SWAMP_CRUSHER_IN)
					{
					live_entity->le_lwtrans->t[2] -= (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[2] < (crusher_map_data->cr_matrix.t[2] - crusher_map_data->cr_distance))
						crusher->cr_direction = !crusher->cr_direction;
					}
				else
					{
					live_entity->le_lwtrans->t[2] += (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[2] > crusher_map_data->cr_matrix.t[2])
						crusher->cr_direction = !crusher->cr_direction;
					}
				break;
			case SWAMP_CRUSHER_WEST:
				if (crusher->cr_direction == SWAMP_CRUSHER_IN)
					{
					live_entity->le_lwtrans->t[0] -= (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[0] < (crusher_map_data->cr_matrix.t[0] - crusher_map_data->cr_distance))
						crusher->cr_direction = !crusher->cr_direction;
					}
				else
					{
					live_entity->le_lwtrans->t[0] += (crusher_map_data->cr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[0] > crusher_map_data->cr_matrix.t[0])
						crusher->cr_direction = !crusher->cr_direction;
					}
				break;
			}
		}
}



/******************************************************************************
*%%%% SwpCrusherCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID SwpCrusherCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for swamp crushers. When struck, it looks
*				at the frogs velocity, and attempts to bounce it off.
*	MATCH		https://decomp.me/scratch/3nLrQ	(By Kneesnap & stuck-pixel)
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Martin Kift		Created
*	17.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID SwpCrusherCallback(	MR_VOID*	void_frog,
							MR_VOID*	void_live_entity,
							MR_VOID*	void_coll_check)
{
	ENTITY*				entity;
	SWAMP_RT_CRUSHER*	crusher;
	SWAMP_CRUSHER*		crusher_map_data;
	FROG*				frog;
	LIVE_ENTITY*		live_entity;
	MR_COLLCHECK*		coll_check;
	MR_LONG				u, y1, s, grid_x, grid_z, dx, dz;
	GRID_STACK*			grid_stack;
	GRID_SQUARE*		grid_square;
	FORM*				form;
	FORM_DATA*			form_data;
	MR_MAT				matrix;
	MR_SVEC				svec;
	MR_VEC				vec;
	MR_LONG				temp, x_pos, z_pos;

	frog				= (FROG*)void_frog;
	live_entity			= (LIVE_ENTITY*)void_live_entity;
	coll_check			= (MR_COLLCHECK*)void_coll_check;
	entity				= live_entity->le_entity;
	crusher_map_data	= (SWAMP_CRUSHER*)(entity+1);
	crusher				= (SWAMP_RT_CRUSHER*)live_entity->le_specific;

	if (Game_map_theme == THEME_SWP)
		{
		if (crusher->cr_count)
			return;
			
		crusher->cr_count = 5;
		grid_x = (frog->fr_lwtrans->t[0] - Grid_base_x) >> 8;
		grid_z = (frog->fr_lwtrans->t[2] - Grid_base_z) >> 8;
		if (frog->fr_velocity.vx || frog->fr_velocity.vz)
			{
			if (abs(frog->fr_velocity.vx) > abs(frog->fr_velocity.vz))
				{
				if (frog->fr_velocity.vx > 0)
					{
					dx = -1;
					dz = 0;
					u = FROG_DIRECTION_W;
					}
				else
					{
					dx = 1;
					dz = 0;
					u = FROG_DIRECTION_E;
					}
				}
			else
				{
				if (frog->fr_velocity.vz > 0)
					{
					dx = 0;
					dz = -1;
					u = FROG_DIRECTION_S;
					}
				else
					{
					dx = 0;
					dz = 1;
					u = FROG_DIRECTION_N;
					}
				}
			}
		else
			goto default_handler;
		}
	else
		{
default_handler:
		// work out grid we are now heading towards
		grid_x	= frog->fr_grid_x;
		grid_z	= frog->fr_grid_z;

		// We have hit a collprim, work out the angle at which we are jumping into
		// the collprim, reverse it so we bounce back, and then work out the nearest
		// grid square to aim for, and go for it.
		u	= frog->fr_direction;
		switch (u)
			{
			case FROG_DIRECTION_N:
				dx	=  0;
				dz	= -1;
				u	= FROG_DIRECTION_S;
				break;
			case FROG_DIRECTION_E:
				dx = -1;
				dz =  0;
				u	= FROG_DIRECTION_W;
				break;
			case FROG_DIRECTION_S:
				dx =  0;
				dz =  1;
				u	= FROG_DIRECTION_N;
				break;
			case FROG_DIRECTION_W:
				dx =  1;
				dz =  0;
				u	= FROG_DIRECTION_E;
				break;
			default:
				dx = 0;
				dz = 0;
				break;
			}
		}

	grid_x += dx;
	grid_z += dz;
	grid_stack 	= GetGridStack(grid_x, grid_z);
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				y1 = GetGridSquareHeight(grid_square);
					{
					// Adjacent square is usable. If we are sliding at present, contine to slide, else
					// jump back to slope
					if (frog->fr_mode >= FROG_MODE_USER)
						{
						frog->fr_count = FROG_JUMP_TIME;
						frog->fr_grid_x = grid_x;
						frog->fr_grid_z = grid_z;
						frog->fr_grid_square = grid_square;

						// Snap player position to grid tile
						frog->fr_target_pos.vx = (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
						frog->fr_target_pos.vy = GetGridSquareHeight(grid_square);
						frog->fr_target_pos.vz = (frog->fr_grid_z << 8) + Grid_base_z + 0x80;

						// Update velocity
						frog->fr_velocity.vx = ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
						frog->fr_velocity.vy = ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
						frog->fr_velocity.vz = ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;
						crusher->cr_count = 4;
						}
					else
						{
						frog->fr_flags		|= (FROG_JUMP_TO_LAND | FROG_JUMP_FROM_COLLPRIM);

						frog->fr_grid_x 		= grid_x;
						frog->fr_grid_z 		= grid_z;
						frog->fr_grid_square	= grid_square;
						frog->fr_direction		= u;
						frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
						frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
						
						// set jumping mode
						frog->fr_mode 			= FROG_MODE_JUMPING;
						frog->fr_forbid_entity	= live_entity->le_entity;

						// try leaving fr_count to same as before...
						frog->fr_count			= 6;

						frog->fr_old_y			= frog->fr_y;
						y1 						= frog->fr_y - frog->fr_lwtrans->t[1];
						u  						= ((y1 << 16) / (frog->fr_count + 1)) - ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1);

						frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
						frog->fr_velocity.vy 	= u;
						frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

						// push the frog ever so slightly back, to try and avoid repeated hits on the collprim
						frog->fr_lwtrans->t[0]	+= (frog->fr_velocity.vx>>15);
						frog->fr_lwtrans->t[2]	+= (frog->fr_velocity.vz>>15);
						break;
						}
					}
				}
			}
		}

	// Kill frog if it has reached a deadly form
	if ((Game_map_theme == THEME_SWP) && ((form = ENTITY_GET_FORM(entity))->fo_numformdatas != 0))
		{
		form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
		svec.vx = frog->fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0];
		svec.vy = frog->fr_lwtrans->t[1] - live_entity->le_lwtrans->t[1];
		svec.vz = frog->fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2];
		MRTransposeMatrix(live_entity->le_lwtrans, &matrix);
		MRApplyMatrix(&matrix, &svec, &vec);
		temp = form->fo_xofs;
		x_pos = form->fo_xofs + (form->fo_xnum << 8); 
		z_pos = form->fo_zofs + (form->fo_znum << 8);
		if ((vec.vx > form->fo_xofs) && (x_pos > vec.vx)
			&& (vec.vz > form->fo_zofs) && (z_pos > vec.vz)
			&& (vec.vy >= form_data->fd_height) && (vec.vy <= form->fo_max_y))
			{
			temp = form_data->fd_grid_squares[(((vec.vz - form->fo_zofs) >> 8) * form->fo_xnum) + ((vec.vx - form->fo_xofs) >> 8)];
			if (temp & GRID_SQUARE_DEADLY)
				FrogKill(frog, FROG_ANIMATION_SQUISHED, 0);
			}
		}
}


/******************************************************************************
*%%%% ENTSTRSwpCreatePress
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreatePress(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a press for the swamp level
*	MATCH		https://decomp.me/scratch/hPxoz	(By Kneesnap)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Gary Richards	Created
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpCreatePress(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	SWAMP_RT_PRESS*			press;
	SWAMP_PRESS*			press_map_data;

	entity				= live_entity->le_entity;
	press				= live_entity->le_specific;
	press_map_data		= (SWAMP_PRESS*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	press->pr_direction = SWAMP_PRESS_MOVING_UP;
	press->pr_time		= press_map_data->pr_delay;
	press->pr_action	= SWAMP_PRESS_WAITING;
	PlayMovingSound(live_entity, SFX_SWP_MACHINE, 768, 1280);
}


/******************************************************************************
*%%%% ENTSTRSwpUpdatePress
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpUpdatePress(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the swamp press entity.
*	MATCH		https://decomp.me/scratch/89Pq4	(By Kneesnap)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Gary Richards	Created
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpUpdatePress(LIVE_ENTITY*	live_entity)
{
	ENTITY*				entity;
	SWAMP_RT_PRESS*		press;
	SWAMP_PRESS*		press_map_data;

	entity				= live_entity->le_entity;
	press				= live_entity->le_specific;
	press_map_data		= (SWAMP_PRESS*)(entity + 1);

	if (press->pr_action == SWAMP_PRESS_WAITING)
		{
		if (!press->pr_time--)
			press->pr_action = SWAMP_PRESS_CRUSHING;
		}
	else
		{
		switch (press_map_data->pr_direction)
			{
			// --------------------------------------------------------------------------------------------------------
			case SWAMP_PRESS_UP:
				if (press->pr_direction == SWAMP_PRESS_MOVING_UP)
					{
					live_entity->le_lwtrans->t[1] -= (press_map_data->pr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[1] < (press_map_data->pr_matrix.t[1] - press_map_data->pr_distance))
						{
						press->pr_direction = !press->pr_direction;
						}
					}
				else
					{
					live_entity->le_lwtrans->t[1] += (press_map_data->pr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[1] > press_map_data->pr_matrix.t[1])
						{
						press->pr_direction = !press->pr_direction;
						// At top play SFX.
						if ((live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG))
					 		MRSNDPlaySound(SFX_SWP_FROG_CRUSH, NULL, 0, 0);
						else if (DistanceToFrogger(live_entity, 0, 0) < SWP_PRESS_DISTANCE)
							MRSNDPlaySound(SFX_SWP_CRUSHER, NULL, 0, 0);
						}
					}
				break;
			// --------------------------------------------------------------------------------------------------------
			case SWAMP_PRESS_DOWN:
				if (press->pr_direction == SWAMP_PRESS_MOVING_UP)
					{
					live_entity->le_lwtrans->t[1] += (press_map_data->pr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[1] > (press_map_data->pr_matrix.t[1] + press_map_data->pr_distance))
						{
						press->pr_direction = !press->pr_direction;
						}
					}
				else
					{
					live_entity->le_lwtrans->t[1] -= (press_map_data->pr_speed>>WORLD_SHIFT);
					if (live_entity->le_lwtrans->t[1] < press_map_data->pr_matrix.t[1])
						{
						press->pr_direction = !press->pr_direction;
						// At bottom play SFX.
						if ((live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG))
					 		MRSNDPlaySound(SFX_SWP_FROG_CRUSH, NULL, 0, 0);
						else if (DistanceToFrogger(live_entity, 0, 0) < SWP_PRESS_DISTANCE)
							MRSNDPlaySound(SFX_SWP_CRUSHER, NULL, 0, 0);
						}
					}
				break;
			// --------------------------------------------------------------------------------------------------------
			}
		}
}

//------------------------------------------------------------------------------------------------
// SWP Nuclear Barrels 
//
// These wait for the frog to hit them, and then proceed to throw the frog off, either in a
// predefined direction, or most probably in the direction the frog is currently standing..
//
// To achieve this, several scripts are needed (see below)
//

MR_LONG		script_swp_nuclear_barrel_ejecting[] =
	{
	ENTSCR_PLAY_SOUND,				SFX_SWP_NUCLEAR_BARREL_EXPLODE,
	ENTSCR_EJECT_FROG,				ENTSCR_REGISTERS,			ENTSCR_REGISTER_0,	ENTSCR_REGISTER_1,
	ENTSCR_POP,						
	ENTSCR_END,
	};

MR_LONG		script_swp_nuclear_barrel_waiting[] =
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(PATH_INFO),			2,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_GOSUB_SCRIPT,		ENTSCR_SAFE_FROG,	SCRIPT_SWP_NUCLEAR_BARLLEL_EJECTING,		0,
	
		ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_NUCLEAR_BARREL_GEIGER,		
										ENTSCR_NO_REGISTERS,		512,		1536,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART																												
	};

MR_LONG		script_swp_snail[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_SNAIL_MOVE,		
										ENTSCR_NO_REGISTERS,		1024,		1536,
		ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,		0,						// set time to zero
		ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,		20,						// wait until delay
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART																												
	};


//------------------------------------------------------------------------------------------------
// SWP waste Barrels 
//
// These wait for the frog to hit them, spin rapidly around their Z...
// To achieve this, several scripts are needed (see below)
//
MR_LONG		script_swp_waste_barrel_spinning[] =
	{
	ENTSCR_ROTATE,					ENTSCR_COORD_Z,				NULL,	0x10,	ENTSCR_TIME_INFINITE,
	ENTSCR_SETLOOP,
		ENTSCR_RETURN_GOSUB_IF,		ENTSCR_NO_SAFE_FROG,	
	ENTSCR_ENDLOOP,
	ENTSCR_END,
	};

MR_LONG		script_swp_waste_barrel_waiting[] =
	{
	ENTSCR_SCRIPT_IF,				ENTSCR_GOSUB_SCRIPT,		ENTSCR_SAFE_FROG,	SCRIPT_SWP_WASTE_BARLLEL_SPINNING,	0,
	ENTSCR_RESTART
	};

//------------------------------------------------------------------------------------------------
// SWP bobbing waste Barrels
//
// These bob up and down, with an initial delay time entered via mappy into register 0
//

MR_LONG		script_swp_bobbing_waste_barrel[] =
	{
	ENTSCR_REGISTER_CALLBACK,			ENTSCR_CALLBACK_1,		SCRIPT_CB_DIVE_COLOUR_CHANGE,		ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,

	ENTSCR_PREPARE_REGISTERS,			sizeof(MR_MAT),			1,						// prepare registers
	ENTSCR_SET_ENTITY_TYPE,				ENTSCR_ENTITY_TYPE_MATRIX,						// set as matrix entity
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,	0,						// set time to zero
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,		ENTSCR_REGISTER_0,		// wait until mappy entered delay
	ENTSCR_SETLOOP,																				
		//ENTSCR_PLAY_SOUND,				SFX_SWP_WASTE_BARREL,							// sound when they start to sink.
		ENTSCR_DEVIATE,					ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,		0x120,	0x8<<8,	-1,		// deviate
		ENTSCR_WAIT_DEVIATED,															// wait til finished
		ENTSCR_KILL_SAFE_FROG,			FROG_ANIMATION_DROWN,	SFX_GEN_FROG_DROWN1,
		ENTSCR_RETURN_DEVIATE,			ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,		-0x8<<8,	
		ENTSCR_WAIT_DEVIATED,															// wait til finished
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Swamp Oil Drum.
//
MR_LONG		script_swp_oil_drum[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_OIL_DRUM,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpOilDrum(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SWP_HOLLOW_THUD, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp pallet.
//
MR_LONG		script_swp_pallet[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_PALLET,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpPallet(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_SPLASH1, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp Raccon.(eek when jumpped on!)
//
MR_LONG		script_swp_raccoon[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_RACCOON,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpRaccoon(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SWP_RAT, NULL, 0, 0);
	MRSNDPlaySound(SFX_GEN_FROG_SPLASH2, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp sunkcar.
//

MR_LONG		script_swp_sunkcar[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_SUNKCAR,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpSunkCar(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_THUD, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp Stat pipe
//

MR_LONG		script_swp_stat_pipe[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_STAT_PIPE,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpStatPipe(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SWP_HOLLOW_THUD, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp Stat pipe big str
//

MR_LONG		script_swp_stat_pipe_big_str[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_STAT_PIPE_BIG_STR,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpStatPipeBigStr(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SWP_HOLLOW_THUD, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Swamp Stat pipe hole.
//

MR_LONG		script_swp_stat_pipe_hole[] = 
	{
	//ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_STAT_PIPE_HOLE,
	ENTSCR_STOP,
	};


//------------------------------------------------------------------------------------------------
// Swp WaterNoise
//

MR_LONG		script_swp_water_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_STAT_FLUME,		// 	MIN		MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0,	ENTSCR_REGISTER_1,	// wait until mappy entered delay

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_swp_weir_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_STAT_WEIR,		// 	MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, 	ENTSCR_REGISTER_1,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_swp_recycle_bin_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_WATERNOISE,		// 	MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, 	ENTSCR_REGISTER_1,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// Wait to randomly trigger the rat.
MR_LONG		script_swp_rat[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_SWP_RAT_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_swp_rat_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_SWP_RAT,
										ENTSCR_COORD_Z,  		   256,

	ENTSCR_RESTART,
	};

/******************************************************************************
*%%%% ENTSTRSwpCreateRat
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreateRat(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a press for the swamp level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpCreateRat(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY*					entity;
	SWAMP_RT_RAT*			rat;
	SWAMP_RAT*				rat_map_data;
	MR_VEC					dist;
	MR_LONG					total_dist;

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	// Set up pointers
	entity				= live_entity->le_entity;
	rat					= live_entity->le_specific;
	rat_map_data		= (SWAMP_RAT*)(entity + 1);

	// Initialise entity specific stuff
	rat->ra_speed = rat_map_data->ra_speed / 30;			// World units per frame

	// Set start position of rat
	live_entity->le_lwtrans->t[0] = rat_map_data->ra_start_target.vx;
	live_entity->le_lwtrans->t[1] = rat_map_data->ra_start_target.vy;
	live_entity->le_lwtrans->t[2] = rat_map_data->ra_start_target.vz;

	// Store current y position
	rat->ra_prev_y = live_entity->le_lwtrans->t[1];

	// Calculate distance of first jump
	dist.vx = MR_SQR(rat_map_data->ra_start_run_target.vx - rat_map_data->ra_start_target.vx);
	dist.vy = MR_SQR(rat_map_data->ra_start_run_target.vy - rat_map_data->ra_start_target.vy);
	dist.vz = MR_SQR(rat_map_data->ra_start_run_target.vz - rat_map_data->ra_start_target.vz);
	total_dist = MR_SQRT(dist.vx + dist.vy + dist.vz);
	rat->ra_jump1_time = total_dist / 30;
	// Calculate velocity for first jump
	rat->ra_jump1_vel.vx = ((rat_map_data->ra_start_run_target.vx - rat_map_data->ra_start_target.vx)<<4)/rat->ra_jump1_time;
	rat->ra_jump1_vel.vy = ((rat_map_data->ra_start_run_target.vy - rat_map_data->ra_start_target.vy)<<4)/rat->ra_jump1_time;
	rat->ra_jump1_vel.vz = ((rat_map_data->ra_start_run_target.vz - rat_map_data->ra_start_target.vz)<<4)/rat->ra_jump1_time;

	// Calculate distance of jump ( only in XZ )
	dist.vy = 0;
	total_dist = MR_SQRT(dist.vx + dist.vy + dist.vz);
	rat->ra_jump1_dist = total_dist;

	// Calculate movement through sin table
	rat->ra_jump1_sin_movement = 2048 / rat->ra_jump1_time;

	// Calculate distance of run
	dist.vx = MR_SQR(rat_map_data->ra_end_run_target.vx - rat_map_data->ra_start_run_target.vx);
	dist.vy = MR_SQR(rat_map_data->ra_end_run_target.vy - rat_map_data->ra_start_run_target.vy);
	dist.vz = MR_SQR(rat_map_data->ra_end_run_target.vz - rat_map_data->ra_start_run_target.vz);
	total_dist = MR_SQRT(dist.vx + dist.vy + dist.vz);
	rat->ra_run_time = total_dist / rat->ra_speed;
	// Calculate velocity for run
	rat->ra_run_vel.vx = ((rat_map_data->ra_end_run_target.vx - rat_map_data->ra_start_run_target.vx)<<4)/rat->ra_run_time;
	rat->ra_run_vel.vy = ((rat_map_data->ra_end_run_target.vy - rat_map_data->ra_start_run_target.vy)<<4)/rat->ra_run_time;
	rat->ra_run_vel.vz = ((rat_map_data->ra_end_run_target.vz - rat_map_data->ra_start_run_target.vz)<<4)/rat->ra_run_time;

	// Calculate distance of run
	dist.vx = MR_SQR(rat_map_data->ra_end_target.vx - rat_map_data->ra_end_run_target.vx);
	dist.vy = MR_SQR(rat_map_data->ra_end_target.vy - rat_map_data->ra_end_run_target.vy);
	dist.vz = MR_SQR(rat_map_data->ra_end_target.vz - rat_map_data->ra_end_run_target.vz);
	total_dist = MR_SQRT(dist.vx + dist.vy + dist.vz);
	rat->ra_jump2_time = total_dist / 30;
	// Calculate velocity for second jump
	rat->ra_jump2_vel.vx = ((rat_map_data->ra_end_target.vx - rat_map_data->ra_end_run_target.vx)<<4)/rat->ra_jump2_time;
	rat->ra_jump2_vel.vy = ((rat_map_data->ra_end_target.vy - rat_map_data->ra_end_run_target.vy)<<4)/rat->ra_jump2_time;
	rat->ra_jump2_vel.vz = ((rat_map_data->ra_end_target.vz - rat_map_data->ra_end_run_target.vz)<<4)/rat->ra_jump2_time;

	// Calculate distance of jump ( only in XZ )
	dist.vy = 0;
	total_dist = MR_SQRT(dist.vx + dist.vy + dist.vz);
	rat->ra_jump2_dist = total_dist;

	// Calculate movement through sin table
	rat->ra_jump2_sin_movement = 2048 / rat->ra_jump2_time;

	// Set mode
//	rat->ra_mode = SWAMP_RAT_MODE_INIT_FIRST_JUMP;
	rat->ra_mode = SWAMP_RAT_MODE_RESTART;

	// Set up rat position
	MR_COPY_VEC(&rat->ra_pos,(MR_VEC*)&live_entity->le_lwtrans->t[0]);
	rat->ra_pos.vx <<= 4;
	rat->ra_pos.vy <<= 4;
	rat->ra_pos.vz <<= 4;

}

/******************************************************************************
*%%%% ENTSTRSwpUpdateRat
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpUpdateRat(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the swamp press entity.
*	MATCH		https://decomp.me/scratch/QJRqC	(By Kneesnap)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	William Bell	Created
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpUpdateRat(LIVE_ENTITY*	live_entity)
{

	// Locals
	ENTITY*				entity;
	SWAMP_RT_RAT*		rat;
	SWAMP_RAT*			rat_map_data;
	MR_OBJECT*			sprite_ptr;

	// Set up pointers
	entity				= live_entity->le_entity;
	rat					= live_entity->le_specific;
	rat_map_data		= (SWAMP_RAT*)(entity + 1);

	// According to mode of operation do ...
	switch( rat->ra_mode )
		{
		//-----------------------------
		case SWAMP_RAT_MODE_INIT_FIRST_JUMP:

			// Start jump animation
			MRAnimEnvSingleSetAction(live_entity->le_api_item0, SWAMP_RAT_ANIM_JUMP);

			// Flag animation as single shot
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

			// Initialise time to reach first target
			rat->ra_count = 0;

			// Initialise sin positions
			rat->ra_jump1_sin_pos = 0;
			rat->ra_jump2_sin_pos = 0;

			// Initialise y
			rat->ra_prev_y = rat->ra_pos.vy;

			// Go on to next mode
			rat->ra_mode = SWAMP_RAT_MODE_JUMP1;

			break;
		//-----------------------------
		case SWAMP_RAT_MODE_JUMP1:

			// Move rat towards second target
			rat->ra_pos.vx += rat->ra_jump1_vel.vx;
			rat->ra_pos.vy = rat->ra_prev_y + rat->ra_jump1_vel.vy;
			rat->ra_pos.vz += rat->ra_jump1_vel.vz;
			
			// Store y
			rat->ra_prev_y = rat->ra_pos.vy;

			// Add on sin data
			rat->ra_pos.vy -= ((rsin(rat->ra_jump1_sin_pos)*250)>>12)<<4;

			// Inc movement through sin table
			rat->ra_jump1_sin_pos += rat->ra_jump1_sin_movement;

			// Inc time to reach target
			rat->ra_count++;

			// Reached second target ?
			if ( rat->ra_count == rat->ra_jump1_time )
				// Yes ... go on to roll
				rat->ra_mode = SWAMP_RAT_MODE_INIT_ROLL;

			break;
		//-----------------------------
		case SWAMP_RAT_MODE_INIT_ROLL:

			// Start roll animation
			MRAnimEnvSingleSetAction(live_entity->le_api_item0, SWAMP_RAT_ANIM_ROLL);

			// Flag animation as single shot
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

			// Reset count
			rat->ra_count = 0;

			// Go on to run
			rat->ra_mode = SWAMP_RAT_MODE_ROLL;

			break;

		//-----------------------------
		case SWAMP_RAT_MODE_ROLL:

			// Inc count
			rat->ra_count++;

			// End of roll ?
			if ( rat->ra_count == 24 )
				{
				// Yes ... start run animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, SWAMP_RAT_ANIM_RUN);
				// Flag run as repeating animation
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
				// Reset count
				rat->ra_count = 0;
				// Go on to run
				rat->ra_mode = SWAMP_RAT_MODE_RUN;
				}

			break;
		//-----------------------------
		case SWAMP_RAT_MODE_RUN:

			// Move rat towards third target
			rat->ra_pos.vx += rat->ra_run_vel.vx;
			rat->ra_pos.vy += rat->ra_run_vel.vy;
			rat->ra_pos.vz += rat->ra_run_vel.vz;

			// Inc time to reach target
			rat->ra_count++;

			// Reached third target ?
			if ( rat->ra_count == rat->ra_run_time )
				{
				// Yes ... trigger jump animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, SWAMP_RAT_ANIM_JUMP);
				// Flag animation as single shot
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
				// Reset count
				rat->ra_count = 0;
				// Initialise y
				rat->ra_prev_y = rat->ra_pos.vy;
				// Go on to jump
				rat->ra_mode = SWAMP_RAT_MODE_JUMP2;
				}

			break;
		//-----------------------------
		case SWAMP_RAT_MODE_JUMP2:

			// Move towards final target
			rat->ra_pos.vx += rat->ra_jump2_vel.vx;
			rat->ra_pos.vy = rat->ra_prev_y + rat->ra_jump2_vel.vy;
			rat->ra_pos.vz += rat->ra_jump2_vel.vz;

			// Store y
			rat->ra_prev_y = rat->ra_pos.vy;

			// Add on sin data
			rat->ra_pos.vy -= ((rsin(rat->ra_jump2_sin_pos)*250)>>12)<<4;

			// Create sprite
			if (((rat->ra_pos.vy >> 4) >= -0xFF) & rat->ra_has_sprite == FALSE)
				{
				rat->ra_has_sprite = TRUE;
				MR_INIT_MAT(&Rat_splash_matrix);
				MR_COPY_VEC(Rat_splash_matrix.t, &rat->ra_pos);
				Rat_splash_matrix.t[0] >>= 4;
				Rat_splash_matrix.t[1] >>= 4;
				Rat_splash_matrix.t[2] >>= 4;
				sprite_ptr = MRCreate3DSprite((MR_FRAME*)&Rat_splash_matrix, MR_OBJ_STATIC, &FrogSplashAnimList);
				sprite_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
				sprite_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x10;
				GameAddObjectToViewports(sprite_ptr);
				SetLiveEntityScaleColours(live_entity, 0x80, 0x80, 0x80);
				SetLiveEntityCustomAmbient(live_entity, 0xff, 0, 0xff);
				}

			// Inc movement through sin table
			rat->ra_jump2_sin_pos += rat->ra_jump2_sin_movement;

			// Inc count to reach target
			rat->ra_count++;

			// Reached fourth target ?
			if ( rat->ra_count == rat->ra_jump2_time )
				// Yes ... go on to restart
				rat->ra_mode = SWAMP_RAT_MODE_RESTART;

			break;
		//-----------------------------
		case SWAMP_RAT_MODE_RESTART:

			// Reset rat position
			rat->ra_pos.vx = rat_map_data->ra_start_target.vx<<4;
			rat->ra_pos.vy = rat_map_data->ra_start_target.vy<<4;
			rat->ra_pos.vz = rat_map_data->ra_start_target.vz<<4;

			// Reset rat colour and sprite
			SetLiveEntityScaleColours(live_entity, 0x80, 0x80, 0x80);
			SetLiveEntityCustomAmbient(live_entity, 0xff, 0xff, 0xff);
			rat->ra_has_sprite = FALSE;

			// Store y
			rat->ra_prev_y = rat->ra_pos.vy;

			// Go back to first jump
			rat->ra_mode = SWAMP_RAT_MODE_INIT_FIRST_JUMP;

			break;
		//-----------------------------
		}

	// Set position
	MR_COPY_VEC((MR_VEC*)&live_entity->le_lwtrans->t[0],&rat->ra_pos);
	live_entity->le_lwtrans->t[0] >>= 4;
	live_entity->le_lwtrans->t[1] >>= 4;
	live_entity->le_lwtrans->t[2] >>= 4;

}


//------------------------------------------------------------------------------------------------
// Swp Mutant Fish.

MR_LONG	script_swp_mutant_fish[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,	SCRIPT_CB_SWP_MUTANT_FISH,	ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,
	ENTSCR_STOP,
	};


//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSwpMutantFish(LIVE_ENTITY* live_entity)
{
	MR_LONG	height;
	MR_LONG	col_r, col_g, col_b;

	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		// Find the distance from the path in Y.
		height = live_entity->le_entity->en_path_runner->pr_position.vy;

		if (height == 0)
			{
			// Change colour under water.
			col_r	= 0x40;	
			col_g	= 0xA0;
			col_b	= 0x60;
			SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
			SetLiveEntityCustomAmbient(live_entity, 0x40, 0x40, 0x40);
			}
		else
			{
			// Change colour back to normal.
			col_r	= 0x80;	
			col_g	= 0x80;
			col_b	= 0x80;
			SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
			SetLiveEntityCustomAmbient(live_entity, 0x40, 0xd0, 0x40);
			}

	
		// Ensure fade code respects the values we have set
		live_entity->le_flags |= (LIVE_ENTITY_RESPECT_SCALE_COLOURS | LIVE_ENTITY_RESPECT_AMBIENT_COLOURS);
		}
}

/******************************************************************************
*%%%% ENTSTRSwpCreateSlug
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreateSlug(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a swamp slug as a moving mof
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpCreateSlug(LIVE_ENTITY*	live_entity)
{
	
	// Locals
	ENTITY*				entity;
	SWAMP_SLUG*			slug_map_data;

	// Create slug as MovingMOF
	ENTSTRCreateMovingMOF(live_entity);

	// Set up pointers
	entity				= live_entity->le_entity;
	slug_map_data		= (SWAMP_SLUG*)(entity + 1);

	// Are we a curvy slug ?
	if ( slug_map_data->sl_motion_type == SWAMP_SLUG_MOTION_TYPE_CURVY )
		{
		// Yes ... play bend animation instead
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0,SWAMP_SLUG_ANIM_CURVY);
		}

	// Set local align flag
//	entity->en_flags |= ENTITY_LOCAL_ALIGN;

}



#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% ENTSTRSwpKillSlug
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpKillSlug(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a swamp slug
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.08.97	William Bell	Created
*	04.11.23	Kneesnap		Disabled as part of byte-matching PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpKillSlug(LIVE_ENTITY*	live_entity)
{

	// Kill slug as moving mof
	ENTSTRKillMovingMOF(live_entity);

}


/******************************************************************************
*%%%% ENTSTRSwpUpdateSlug
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpUpdateSlug(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a swamp slug
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.08.97	William Bell	Created
*	04.11.23	Kneesnap		Disabled as part of byte-matching PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSwpUpdateSlug(LIVE_ENTITY*	live_entity)
{

	// Update slug as a moving mof
	ENTSTRUpdateMovingMOF(live_entity);

}
#endif

//------------------------------------------------------------------------------------------------
MR_LONG		script_swp_pelican[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SWP_PELICAN_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SWP_BIRD_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,

	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SWP_PELICAN_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSwpPelicanCall(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SWP_PELICAN_CALL_FRENZIED, NULL, 0, 0);
}

MR_LONG	script_swp_pelican_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SWP_PELICAN_CALL,
										ENTSCR_COORD_Z,				128,
	ENTSCR_RESTART,
	};

/******************************************************************************
*%%%% ENTSTRSwpCreateWeir
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSwpCreateWeir(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a swamp weir as a dynamic mof
*	MATCH		https://decomp.me/scratch/0LYr5	(By Kneesnap)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID ENTSTRSwpCreateWeir(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	MR_SVEC				svec;
	SWAMP_STAT_WEIR*	weir_map_data;

	entity 			= live_entity->le_entity;
	weir_map_data   = (SWAMP_STAT_WEIR*)(entity + 1);

	MR_SET_SVEC(&svec, 0, 0, SWP_WEIR_ROTATION);
	MRRotMatrix(&svec, &weir_map_data->wr_matrix);
	ENTSTRCreateDynamicMOF(live_entity);
}


MR_LONG	script_swp_weir_rotate[] =
	{
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,										// set as matrix entity
	ENTSCR_SETLOOP,
	ENTSCR_ROTATE,					ENTSCR_COORD_X,			0x1000,	0x20,	-1,
	ENTSCR_WAIT_UNTIL_ROTATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};