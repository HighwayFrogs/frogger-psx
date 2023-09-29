/******************************************************************************
*%%%% ent_org.c
*------------------------------------------------------------------------------
*
*	Code for original level.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "ent_org.h"
#include "scripter.h"
#include "scripts.h"
#include "sound.h"
#include "frog.h"
#include "collide.h"
#include "entlib.h"
#include "org_baby.h"
#include "ent_gen.h"
#include "froganim.h"
#include "score.h"
#include "particle.h"

MR_SVEC		Org_baby_frog_directions[] = 
	{
	{ 0, 0,		0, 0},
	{ 0, 1024,	0, 0},
	{ 0, 2048,	0, 0},
	{ 0, 3072,	0, 0},
	};


MR_ULONG	Animlist_org_bonus_fly[] =
	{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_fly_500,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_fly_500a,
	MR_SPRT_LOOPBACK
	};

/******************************************************************************
*%%%% ENTSTROrgCreateLogSnake
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgCreateLogSnake(
*										LIVE_ENTITY* live_entity)
*
*	FUNCTION	Create a log snake entity for the original map.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID ENTSTROrgCreateLogSnake(LIVE_ENTITY* live_entity)
{
	ORG_LOG_SNAKE_DATA*	log_snake_map_data;
	ORG_RT_LOG_SNAKE*	log_snake;
	ENTITY*				entity;

	entity 				= live_entity->le_entity;
	log_snake_map_data	= (ORG_LOG_SNAKE_DATA*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	// the runtime structure has already been alloced
	log_snake = (ORG_RT_LOG_SNAKE*)live_entity->le_specific;
	log_snake->ls_log_entity = NULL;
}

/******************************************************************************
*%%%% ENTSTROrgUpdateLogSnake
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgUpdateLogSnake(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the original map log snake.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgUpdateLogSnake(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	ORG_RT_LOG_SNAKE*		snake;
	ORG_LOG_SNAKE_DATA*		snake_map_data;
	MR_VEC					vec;
	MR_MAT*					log_mat;
	FORM*					form;
	FORM_DATA*				form_data;

	entity			= live_entity->le_entity;
	snake			= live_entity->le_specific;
	snake_map_data	= (ORG_LOG_SNAKE_DATA*)(entity + 1);

	// if the pointer to the log upon which the logsnake is standing is NULL,
	// it needs to be resolved... this is a fairly time consuming process,
	// but since its only done once (first call to Update()), any overhead
	// is fairly minimal throughout the rest of the game
	if (!snake->ls_log_entity)
		{
		// get a ptr to the log gof
		snake->ls_log_entity = GetNextEntityWithUniqueId(snake_map_data->ls_unique_log_id);
		MR_ASSERT (snake->ls_log_entity != NULL);

		// first position baby frog somewhere on it.... easier said than done maybe
		snake->ls_direction = 1;
		
		MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, &snake->ls_log_entity->en_path_runner->pr_position);

		// Work out how far we can move along the log before we should turn around... 
		// The following code assumes that the base point for the entities is roughly in the centre,
		// such that radius's suffice to calculate distance...
		snake->ls_movement_range = abs	(
										MR_SQRT(ENTITY_GET_FORM_BOOK(entity)->fb_radius2) -
										MR_SQRT(ENTITY_GET_FORM_BOOK(snake->ls_log_entity)->fb_radius2)
										);
		// snake  starts in the middle... 
		snake->ls_offset.vx = 0;
		snake->ls_offset.vz = 0;

		// work out height of form of our log
		form				= ENTITY_GET_FORM(snake->ls_log_entity);
		form_data 			= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
		snake->ls_offset.vy = form_data->fd_height;
		}

	// if we get here, then we MUST have a parent log (though not in the API sense), 
	// since the above code ensures it!

	// is snake going forwards?
	if (1 == snake->ls_direction)
		{
		// if the snake has reached its limit, turn around
		if (snake->ls_offset.vz >= snake->ls_movement_range)
			snake->ls_direction = 0;
		}
	// no, its backwards
	else
		{
		// if the snake has reached its limit, turn around
		if (snake->ls_offset.vz <= -snake->ls_movement_range)
			snake->ls_direction = 1;
		}
		
	// the following code only works for a snake moing length-wise along
	// its log, which actually copes with quite a few circumstances!
	if (1 == snake->ls_direction)
		{
		snake->ls_offset.vz += (snake_map_data->ls_speed>>WORLD_SHIFT);

		// Rotate babyfrog matrix
		MRRotMatrix(&Org_baby_frog_directions[0], live_entity->le_lwtrans);
		}
	else
		{
		snake->ls_offset.vz -= (snake_map_data->ls_speed>>WORLD_SHIFT);

		// Rotate babyfrog matrix
		MRRotMatrix(&Org_baby_frog_directions[2], live_entity->le_lwtrans);
		}

	// Recalculate snake position and rotation....
	if (snake->ls_log_entity->en_live_entity)
		{
		log_mat = snake->ls_log_entity->en_live_entity->le_lwtrans;

		MRApplyMatrix(log_mat, &snake->ls_offset, &vec);
		MR_ADD_VEC_ABC(	(MR_VEC*)log_mat->t, &vec, (MR_VEC*)live_entity->le_lwtrans->t);
		MRMulMatrixABB(log_mat, live_entity->le_lwtrans);

		// parent, make ourselves visible
//		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_DISPLAY;
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
		}
	else
		{
		// no parent, make ourselves invisible
//		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
		}

	if (live_entity->le_moving_sound == NULL)
		{
		// Play SFX of the Snake Hissing. 
		PlayMovingSound(live_entity, SFX_ORG_SNAKE_HISS, 512, 1024);
		}
}

/******************************************************************************
*%%%% ENTSTROrgCreateBabyFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgCreateBabyFrog(LIVE_ENTITY* live_entity)
*
*	FUNCTION	Create a baby frog entity for the original map.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID ENTSTROrgCreateBabyFrog(LIVE_ENTITY* live_entity)
{
	ORG_BABY_FROG_DATA*	frog_map_data;
	ORG_RT_BABY_FROG*	frog;
	ENTITY*				entity;

	entity 			= live_entity->le_entity;
	frog_map_data	= (ORG_BABY_FROG_DATA*)(entity + 1);

	// DO NOT CREATE this baby frog if its a GOLD variety AND this theme has already got its
	// gold frog
	if	(
		(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID) &&
		(Gold_frogs & (1<<Game_map_theme))
		)
		{
		// mark it as no display
		live_entity->le_entity->en_flags |= ENTITY_NO_DISPLAY;
		return;
		}

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	// the runtime structure has already been alloced
	frog					= (ORG_RT_BABY_FROG*)live_entity->le_specific;
	frog->bf_entity			= NULL;
	frog->bf_frog			= NULL;
	frog->bf_mode			= ORG_BABY_FROG_SEARCHING;
	frog->bf_entity_angle	= 0;
	frog->bf_flags			= 0;
	frog->bf_search_count	= 0;

	// Don't do pouch if we are a gold frog
//	if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
//		{
//		frog->bf_croak_mode		= FROG_CROAK_NONE;
//		frog->bf_croak_timer	= 0;
//		frog->bf_croak_scale	= FROG_CROAK_MIN_SCALE;
//		MR_INIT_MAT(&frog->bf_croak_scale_matrix);
//
//		MRAnimEnvSingleSetPartFlags(live_entity->le_api_item0, POUCHY, MR_ANIM_PART_TRANSFORM_PART_SPACE);
//		MRAnimEnvSingleSetImportedTransform(live_entity->le_api_item0, POUCHY, &frog->bf_croak_scale_matrix);
//
//		MRAnimEnvSingleSetAction(live_entity->le_api_item0, ORG_BABY_FROG_COMPLETE);
//		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags = (MR_ANIM_ENV_DEFAULT_FLAGS|MR_ANIM_ENV_ONE_SHOT);
//		}

	// Is this animated ?
	if ( live_entity->le_flags & LIVE_ENTITY_ANIMATED )
		{
		// Yes ... make all animations single shot
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
		}

}

/******************************************************************************
*%%%% ENTSTROrgUpdateBabyFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgUpdateBabyFrog(LIVE_ENTITY* live_entity)
*
*	FUNCTION	This function is used to update the baby frog original map
*				entity.
*
*	INPUTS		live_entity		- ptr to live entity
*
*	NOTES		The baby frog should jump backwards and forwards along the log, 
*				which is a complex procedure at the best of times... I think we 
*				should be able to pre-calculate most of this, by looking at the 
*				size of the log and work out how many jumps the baby frog can 
*				make, with a minimum probably of 3, raising to 5, 7, etc.. This 
*				makes the task of jumping the baby frog around the log much 
*				easier, its a little bit cheesey but it should suffice for the 
*				original map at least.!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*	27.06.97	Gary Richards	Added Sound Effects.
*	14.08.97	Gary Richards	Changed Code because this became a FlipBook.
*
*%%%**************************************************************************/

MR_VOID ENTSTROrgUpdateBabyFrog(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	ORG_RT_BABY_FROG*		frog;
	ORG_BABY_FROG_DATA*		frog_map_data;
	MR_VEC					vec;
	MR_ULONG				u;
	MR_LONG					dx, dz, height;
	MR_LONG					grid_x, grid_z;
	FORM*					form;
	FORM_DATA*				form_data;
	MR_ULONG				flags;
	MR_SVEC					svec;
	ENTITY*					parent_entity;
	MR_MAT					entity_transmatrix;
	MR_MAT*					parent_matrix;
	FROG*					parent_frog;
	MR_OBJECT*				object;

	entity				= live_entity->le_entity;
	frog				= live_entity->le_specific;
	frog_map_data		= (ORG_BABY_FROG_DATA*)(entity + 1);
	parent_matrix		= NULL;

	// DO NOT UPDATE this baby frog if its a GOLD variety AND this theme has already got its
	// gold frog
	if (live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY)
		return;

	switch (frog->bf_mode)
		{
		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_SEARCHING:
			// if the pointer to the log upon which the babyfrog is standing is NULL,
			// it needs to be resolved... this is a fairly time consuming process,
			// but since its only done once (first call to Update()), any overhead
			// is fairly minimal throughout the rest of the game
			if (NULL == frog->bf_entity)
				{
				// get log live_entity 
				parent_entity = GetNextEntityWithUniqueId(frog_map_data->bf_unique_log_id);
				MR_ASSERT (parent_entity != NULL);

				// Does our entity have a live_entity?
				if (parent_entity->en_live_entity)
					{
					// have we searched enough?
					if (++frog->bf_search_count >= ORG_BABY_FROG_SEARCH_BEFORE_LAND)
						{
						frog->bf_search_count	= 0;
						frog->bf_entity			= parent_entity;
						frog->bf_entity_grid_x	= 0;
						frog->bf_entity_grid_z	= 0;
						frog->bf_direction		= FROG_DIRECTION_N;
						frog->bf_count			= 0;
						frog->bf_delay			= 30;

						// set some runtimes...
						frog->bf_delay = ORG_BABY_FROG_JUMP_DELAY;
						MR_SET_VEC(&frog->bf_velocity, 0, 0, 0);

						// Trigger wait animation
						if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
							{
							LiveEntitySetAction( live_entity, ORG_BABY_FROG_COMPLETE);
							}

						// Need to sit the baby frog on the correct place
						form 		= ENTITY_GET_FORM(frog->bf_entity);
						form_data 	= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
						flags		= form_data->fd_grid_squares[(frog->bf_entity_grid_z * form->fo_xnum) + frog->bf_entity_grid_x];
						height		= form_data->fd_height;

						live_entity->le_lwtrans->t[0] = frog->bf_entity->en_live_entity->le_lwtrans->t[0] + form->fo_xofs + 0x80;
						live_entity->le_lwtrans->t[1] = height;
						live_entity->le_lwtrans->t[2] = frog->bf_entity->en_live_entity->le_lwtrans->t[2] + form->fo_zofs + 0x80;

						frog->bf_mode = ORG_BABY_FROG_ON_ENTITY;

						// setup positional information
						MR_INIT_MAT(live_entity->le_lwtrans);
						MR_SET_VEC(&frog->bf_entity_ofs, 0, height, 0);
						MRTransposeMatrix(frog->bf_entity->en_live_entity->le_lwtrans, &entity_transmatrix);
						MRMulMatrixABC(live_entity->le_lwtrans, &entity_transmatrix, &frog->bf_entity_transform);

						// Reset jump count
						frog->bf_jump_time_count = 0;
						}
					}
				else
					{
					frog->bf_mode = ORG_BABY_FROG_WAIT_TO_SEARCH_AGAIN;
					}
				}
			break;

		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_WAIT_TO_SEARCH_AGAIN:
			if (NULL == frog->bf_entity)
				{
				// get log live_entity 
				parent_entity = GetNextEntityWithUniqueId(frog_map_data->bf_unique_log_id);
				MR_ASSERT (parent_entity != NULL);

				// Does our entity have a live_entity?
				if (!parent_entity->en_live_entity)
					frog->bf_mode = ORG_BABY_FROG_SEARCHING;
				}
			break;

		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_ON_ENTITY:
			// We need to check to see what the baby frog is doing, if its:
			//  (a) Standing on a frog, it cannot move...
			//  (b) Standing on a log, it is free to jump, but probably after a small delay
			// yes, is it a log, count down delay until zero and then jump

			// check to see if entity we are standing on is still alive.
			if (!frog->bf_entity->en_live_entity)
				{
				// Force a research
				frog->bf_mode	= ORG_BABY_FROG_SEARCHING;
				frog->bf_entity = NULL;
				frog->bf_frog   = NULL;
				frog->bf_delay	= 0;
				break;
				}

			if (!frog->bf_delay--)
				{
baby_frog_calc_jump:;
				// Can we jump in current direction...
				form 				= ENTITY_GET_FORM(frog->bf_entity);

				u 					= (frog->bf_entity_angle + frog->bf_direction) & 3;
				frog->bf_direction 	= u;
				switch (u)
					{
					case FROG_DIRECTION_N:
						dx =  0;
						dz =  1;
						break;
					case FROG_DIRECTION_E:
						dx =  1;
						dz =  0;
						break;
					case FROG_DIRECTION_S:
						dx =  0;
						dz = -1;
						break;
					case FROG_DIRECTION_W:
						dx = -1;
						dz =  0;
						break;
					default:
						dx = 0;
						dz = 0;
						break;
					}

				// set up velocity for jump
				MR_SET_VEC(&frog->bf_velocity, FROG_JUMP_DISTANCE, 0, FROG_JUMP_DISTANCE);
				grid_x	= frog->bf_entity_grid_x + dx;
				grid_z	= frog->bf_entity_grid_z + dz;

				// Are we jumping out of range?
				if 	(
					(grid_x < 0) ||
					(grid_x >= form->fo_xnum) ||
					(grid_z < 0) ||
					(grid_z >= form->fo_znum)
					)
					{
					// Yes, need to turn around.
					switch (frog->bf_direction)
						{
						case FROG_DIRECTION_N:
							frog->bf_direction = FROG_DIRECTION_S;
							break;
						case FROG_DIRECTION_E:
							frog->bf_direction = FROG_DIRECTION_W;
							break;
						case FROG_DIRECTION_S:
							frog->bf_direction = FROG_DIRECTION_N;
							break;
						case FROG_DIRECTION_W:
							frog->bf_direction = FROG_DIRECTION_E;
							break;
						}
						goto baby_frog_calc_jump;
					}

				// Even if these go outside the form boundary, they will be used to calculate 
				// the jump target in entity's frame
				frog->bf_entity_grid_x = grid_x;
				frog->bf_entity_grid_z = grid_z;

				form_data 	= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
				flags		= form_data->fd_grid_squares[(frog->bf_entity_grid_z * form->fo_xnum) + frog->bf_entity_grid_x];
				height		= form_data->fd_height;
				if (flags & GRID_SQUARE_USABLE)
					{
					// Jump from entity to useable grid square on same entity
					// Jump will be performed as offset in entity frame
					frog->bf_target_pos.vx 	= (frog->bf_entity_grid_x << 8) + form->fo_xofs + 0x80;
					frog->bf_target_pos.vy 	= height;
					frog->bf_target_pos.vz 	= (frog->bf_entity_grid_z << 8) + form->fo_zofs + 0x80;
					frog->bf_count			= 6;
					}

				// Calc velocity
				u						= -((SYSTEM_GRAVITY * (frog->bf_count + 1)) >> 1);
				frog->bf_velocity.vx 	= ((frog->bf_target_pos.vx << 16) - frog->bf_entity_ofs.vx) / frog->bf_count;
				frog->bf_velocity.vy 	= u;
				frog->bf_velocity.vz 	= ((frog->bf_target_pos.vz << 16) - frog->bf_entity_ofs.vz) / frog->bf_count;

				frog->bf_mode			= ORG_BABY_FROG_JUMPING;
				if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
					{
					LiveEntitySetAction(live_entity, ORG_BABY_FROG_HOP);
					}
					
				// update animation
				//vShowGofAnimation(gof, ORG_C_ACTION_BABYFROG_JUMPING, 0);
				// Check we don't already have an SFX playing on this channel.
				if (live_entity->le_moving_sound == NULL)
					{
					// Play SFX of Baby Frog Jumping.
					PlayMovingSound(live_entity, SFX_GEN_BABY_FROG_HOP, 768, 1536);
					}
				}									
			break;

		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_JUMPING:
			// are we in the process of jumping? To find out, just check X, since the ladyfrog only jumps
			// through the X plane
			if (!(--frog->bf_count))
				{
				// Move to target
				frog->bf_entity_ofs.vx = frog->bf_target_pos.vx << 16;
				frog->bf_entity_ofs.vy = frog->bf_target_pos.vy << 16;
				frog->bf_entity_ofs.vz = frog->bf_target_pos.vz << 16;
				MR_CLEAR_VEC(&frog->bf_velocity);
				frog->bf_mode = ORG_BABY_FROG_ON_ENTITY;
				frog->bf_delay = ORG_BABY_FROG_JUMP_DELAY;

				// Trigger wait animation
				if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
					{
					LiveEntitySetAction( live_entity, ORG_BABY_FROG_COMPLETE);
					}
				}
			else
				{
				MR_ADD_VEC(&frog->bf_entity_ofs, &frog->bf_velocity);
				}
			break;

		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_ON_FROG:
			// we are on the frog... check the hitflags to see if the frog has died, hit trigger,
			// etc, etc...
			MR_ASSERT (frog->bf_frog);
			parent_frog			= (FROG*)frog->bf_frog;
			frog->bf_direction	= FROG_DIRECTION_N;

			// Are we in a jump ?
			if ( frog->bf_jump_time_count )
				// Yes ... dec time till end of jump
				frog->bf_jump_time_count--;


			// Has Frogger been killed ?
			if	( 
				(parent_frog->fr_mode == FROG_MODE_DYING) && 
				!(frog->bf_flags & ORG_BABY_FROG_DEAD_FLAG) 
				)
				{
				// Make baby frog disappear
				if (live_entity->le_api_item0)
					((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;

				// Set baby frog dead flag
				frog->bf_flags |= ORG_BABY_FROG_DEAD_FLAG;
				
				// Do headrush explosion thingy
				object = MRCreatePgen(&PGIN_frog_pop_explosion, (MR_FRAME*)live_entity->le_lwtrans, MR_OBJ_STATIC, NULL);
				object->ob_extra.ob_extra_pgen->pg_user_data_2 = Frog_pop_explosion_colours[4];
				GameAddObjectToViewports(object);
				
				// Change mode
				frog->bf_mode = ORG_BABY_FROG_NOTHING;
				}

			// Frog hit trigger ?
			if	(
				(parent_frog->fr_mode == FROG_MODE_HIT_CHECKPOINT) && 
				!(frog->bf_flags & ORG_BABY_FROG_HOME_FLAG) )
				{
				// Yes ... give five hundred points for reaching checkpoint
				AddFrogScore(parent_frog, SCORE_500, live_entity->le_lwtrans);

				// make lady frog disappear
				frog->bf_mode = ORG_BABY_FROG_NOTHING;
				
				// Flag this baby frog as home
				frog->bf_flags |= ORG_BABY_FROG_HOME_FLAG;

				return;
				}

			// Time to start jump animation ?
			if ( (parent_frog->fr_mode == FROG_MODE_JUMPING) && (!frog->bf_jump_time_count) )
				{
				// Yes ... start jumping animation
				if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
					{
					LiveEntitySetAction( live_entity, ORG_BABY_FROG_HOP);
					}
				// Set frame count
				frog->bf_jump_time_count = 6;
				}
			break;

		//------------------------------------------------------------------------------
		case ORG_BABY_FROG_NOTHING:
			// no parent, make ourselves invisible
			if (live_entity->le_api_item0)
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
			return;
		//------------------------------------------------------------------------------
		default:
			// Attempt to catch strange overwrite bug!!!
			MR_ASSERT(0);
			break;
		}

	// If we are a gold frog, then just look for frog hitting us, and cash us in as a checkpoint
	if (entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID)
		{
		// are we NOT standing on a frog???
		if (frog->bf_mode != ORG_BABY_FROG_ON_FROG)
			{
			// we now need to check for being hit by a frog
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				frog->bf_mode = ORG_BABY_FROG_NOTHING;
				FrogCollectGoldFrog(&Frogs[0], entity);
				return;
				}
			}
		}
	else
		{
		// We are a normal ORG baby frog
		if (frog->bf_mode != ORG_BABY_FROG_ON_FROG)
			{
			// we now need to check for being hit by a frog
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// we are a normal baby frog, and we stay on this frog until it finishes or dies!!!
				MR_SET_VEC(&frog->bf_entity_ofs, 0, -20<<16, -20<<16);

				// find frog
				dx				= 0;
				frog->bf_frog	= NULL;
				while (dx < 4)
					{
					if (live_entity->le_flags & (LIVE_ENTITY_HIT_FROG_0 << dx))
						{
						frog->bf_frog	= &Frogs[dx];
						frog->bf_entity	= NULL;
						break;
						}
					dx++;
					}

				// Setup mode and animation
				frog->bf_mode = ORG_BABY_FROG_ON_FROG;
				if (!(entity->en_form_book_id == ORG_GOLD_BABY_FROG_FORM_ID))
					LiveEntitySetAction( live_entity, ORG_BABY_FROG_HOP);
				MR_INIT_MAT(live_entity->le_lwtrans);
				}
			}
		}

	// Work out if we have a parent
	if (frog->bf_entity)
		{
		if ( frog->bf_entity->en_live_entity )
			{
			parent_matrix = frog->bf_entity->en_live_entity->le_lwtrans;
			}
		}
	else
		{
		if (frog->bf_frog)
			{
			parent_matrix = ((FROG*)frog->bf_frog)->fr_lwtrans;
			}
		}

	// Update ourselves relative a parent
	if (parent_matrix)
		{
		// Rotate babyfrog matrix
		MRRotMatrix(&Org_baby_frog_directions[frog->bf_direction], live_entity->le_lwtrans);

		svec.vx 		= frog->bf_entity_ofs.vx >> 16;
		svec.vy 		= frog->bf_entity_ofs.vy >> 16;
		svec.vz 		= frog->bf_entity_ofs.vz >> 16;
		MRApplyMatrix(parent_matrix, &svec, &vec);

		frog->bf_pos.vx = (vec.vx + parent_matrix->t[0]) << 16;
		frog->bf_pos.vy = (vec.vy + parent_matrix->t[1]) << 16;
		frog->bf_pos.vz = (vec.vz + parent_matrix->t[2]) << 16;

		// Write fr_pos to lwtrans
		live_entity->le_lwtrans->t[0] 	= frog->bf_pos.vx >> 16;
		live_entity->le_lwtrans->t[1] 	= frog->bf_pos.vy >> 16;
		live_entity->le_lwtrans->t[2] 	= frog->bf_pos.vz >> 16;

		// Mult matrix by parent
		MRMulMatrixABB(parent_matrix, live_entity->le_lwtrans);

		// parent, make ourselves visible
//		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_DISPLAY;
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;
		}
	else
		{
		// no parent, make ourselves invisible
//		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
		}

	// Update croak sack
	switch (frog->bf_croak_mode)
		{
		//---------------------------------------------------------------------
		case FROG_CROAK_INFLATE:
			frog->bf_croak_timer--;
			frog->bf_croak_scale = (((FROG_CROAK_MAX_SCALE - FROG_CROAK_MIN_SCALE) * (FROG_CROAK_INFLATE_TIME - frog->bf_croak_timer)) / FROG_CROAK_INFLATE_TIME) + FROG_CROAK_MIN_SCALE;

			if (!frog->bf_croak_timer)
				{
				frog->bf_croak_mode 	= FROG_CROAK_HOLD;
				frog->bf_croak_timer 	= FROG_CROAK_HOLD_TIME;
				}
			break;
		//---------------------------------------------------------------------
		case FROG_CROAK_HOLD:
			frog->bf_croak_timer--;

			if (!frog->bf_croak_timer)
				{
				frog->bf_croak_mode 	= FROG_CROAK_DEFLATE;
				frog->bf_croak_timer 	= FROG_CROAK_DEFLATE_TIME;
				}
			break;
		//---------------------------------------------------------------------
		case FROG_CROAK_DEFLATE:
			frog->bf_croak_timer--;
			frog->bf_croak_scale = (((FROG_CROAK_MAX_SCALE - FROG_CROAK_MIN_SCALE) * frog->bf_croak_timer) / FROG_CROAK_DEFLATE_TIME) + FROG_CROAK_MIN_SCALE;

			if (!frog->bf_croak_timer)
				frog->bf_croak_mode 	= FROG_CROAK_NONE;

			break;
		//---------------------------------------------------------------------
		}

	frog->bf_croak_scale_matrix.m[0][0] = frog->bf_croak_scale;
	frog->bf_croak_scale_matrix.m[1][1] = frog->bf_croak_scale;
	frog->bf_croak_scale_matrix.m[2][2] = frog->bf_croak_scale;
}


/******************************************************************************
*%%%% 					SCRIPTS FOR ORIGINAL ENTITIES
*------------------------------------------------------------------------------
*%%%**************************************************************************/

//-------------------------------------------------------------------------------
//

//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the bulldozer Noise.
MR_LONG		script_org_bull_dozer[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,	SCRIPT_ORG_BULL_DOZER_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_org_bull_dozer_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	20,		SFX_ORG_BULLDOZER_HORN02,
									ENTSCR_COORD_Z,  		256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the truck Noise.
MR_LONG		script_org_truck[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_ORG_TRUCK_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_org_truck_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_ORG_BULLDOZER_HORN,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the Car Noise.
MR_LONG		script_org_car_purple[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_ORG_CAR_PURPLE_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_org_car_purple_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_ORG_CAR_HORN01,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the Car Noise.
MR_LONG		script_org_car_blue[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_ORG_CAR_BLUE_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_org_car_blue_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_ORG_CAR_HORN02,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//
// Wait to randomly trigger the Lorry Noise.
MR_LONG		script_org_lorry[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_ORG_LORRY_SFX,	2,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// We are Randomly Triggering, are we close enough ??? (20) is strange value!!!
//	ENTSCR_COORD_Z moves the collision point from the middle of the lorry to the front.
MR_LONG		script_org_lorry_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_ORG_LORRY_HORN02,
										ENTSCR_COORD_Z,			    384,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBFrogTrafficSplat(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_SPLAT, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBLogSplash(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_SPLASH2, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// ORG log
//
// These wait for the frog to hit them, then make a splash noise, and then wait for the frog to
// jump off before making another splash... they can probably make an extra splash graphical
// affect maybe when the frog jumps on too?
//
MR_LONG		script_log_splash[] = 
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_LOG_SPLASH,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
// ORG RoadNoise (Radius supplied by Mappy)
//

MR_LONG		script_org_road_noise[] = 
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_ORG_ROAD_NOISE,		//    MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
															// Min, Max	   Shift,  Range, Pitch,
	//ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	64,		84,		3,		9,		72,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// ORG WaterNoise
//

MR_LONG		script_org_water_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_ORG_WATER_NOISE,	// 	   MIN		 		MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
															// Min, Max	  Speed,	Range,
	//ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	48,		84,		3,		  7,	64,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// ORG bonus flies
//
// These appear once at a time, over random trigger points, although only if that checkpoint has
// not been hit already. If hit, they award the frog bonus points. 
//
MR_LONG		script_org_bonus_fly_collected[] = 
	{
	// play sound, maybe anim, and then make us disappear and go back to start of other script
	ENTSCR_PLAY_SOUND,					SFX_GEN_FROG_FLY_GULP,
	ENTSCR_AWARD_FROG_POINTS,			1000,
	ENTSCR_START_SCRIPT,				SCRIPT_ORG_BONUS_FLY,
	ENTSCR_COLL_CHECKPOINT,
	ENTSCR_COLL_CHECKPOINT
	};

MR_LONG		script_org_bonus_fly[] = 
	{
	// ensure fly is hidden
	ENTSCR_DISAPPEAR_ENTITY,

	// wait for preset amount of time
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_NO_REGISTERS,		120,

	// choose a random checkpoint
	ENTSCR_CHOOSE_RND_CHECKPOINT,
//	ENTSCR_NO_COLL_CHECKPOINT,
	ENTSCR_APPEAR_ENTITY,				
	
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,				ENTSCR_NEW_SCRIPT,			ENTSCR_HIT_FROG,	SCRIPT_ORG_BONUS_FLY_COLLECTED,		0,
		ENTSCR_BREAKLOOP_IF_TIMER,		ENTSCR_NO_REGISTERS,		120,
	ENTSCR_ENDLOOP,

	// Bring back check point
	ENTSCR_COLL_CHECKPOINT,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// ORG crocodile
//
MR_LONG		script_org_crocodile[] =
	{
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,		30,
	ENTSCR_SET_ACTION,				ORG_ACTION_CROCODILE_SNAPPING,
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,		30,
	ENTSCR_SET_ACTION,				ORG_ACTION_CROCODILE_SWIMMING,
	// Play snap sound when animation finishes.
	ENTSCR_PLAY_MOVING_SOUND,		SFX_ORG_CROCODILE_SNAP,		//  MIN		MAX.
									ENTSCR_NO_REGISTERS,			768,	1536,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// ORG snake
//
MR_LONG		script_org_snake[] =
	{
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_ORG_SNAKE_HISS,		//  MIN		MAX.
									ENTSCR_NO_REGISTERS,	768,		1536,
	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
// Turtle Script. (NO DIVE)

MR_LONG		script_turtle_no_dive[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_HIT_TURTLE,		ENTSCR_HIT_FROG,	ENTSCR_CALLBACK_ONCE,
	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBHitTurtle(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_THUD, NULL, 0, 0);
	MRSNDPlaySound(SFX_GEN_FROG_SPLASH1, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Turtle Script.

MR_LONG		script_org_turtle_swim[] =
	{
	ENTSCR_WAIT_DEVIATED,		
	ENTSCR_KILL_SAFE_FROG,				FROG_ANIMATION_DROWN,		NULL,

	// Swim (submerged) for mappy defined frames
	ENTSCR_SET_ACTION,					ACTION_TURTLE_SWIMMING,
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_1,

	// Deviate through set distance (and speed), waiting for deviation to finish, play splash at end!
	ENTSCR_SET_ACTION,					ACTION_TURTLE_DIVING,
	ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0, -0x8<<8, -1,
	ENTSCR_WAIT_DEVIATED,		
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_GEN_ENTITY_DIVE1,
										ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

MR_LONG		script_turtle[] =
	{
	ENTSCR_PREPARE_REGISTERS,	sizeof(PATH_INFO),			3,
	ENTSCR_SET_ENTITY_TYPE,		ENTSCR_ENTITY_TYPE_PATH,
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,			SCRIPT_CB_HIT_TURTLE,			ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_2,			SCRIPT_CB_DIVE_COLOUR_CHANGE,	ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,

	ENTSCR_SETLOOP,
		// Swim for mappy defined frames
		ENTSCR_SET_ACTION,					ACTION_TURTLE_SWIMMING,
		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_0,

		// Deviate through set distance (and speed), waiting for deviation to finish
		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0x80, 0x8<<8, -1,
		ENTSCR_SET_ACTION,					ACTION_TURTLE_DIVING,

		ENTSCR_PLAY_MOVING_SOUND,			SFX_GEN_ENTITY_DIVE1,		// Min	Max.
											ENTSCR_NO_REGISTERS,		512,	1024,

		ENTSCR_CREATE_3D_SPRITE,			0,
		ENTSCR_WAIT_DEVIATED,		
		//ENTSCR_KILL_SAFE_FROG,				FROG_ANIMATION_DROWN,		NULL,

		// Swim (submerged) for mappy defined frames
		ENTSCR_SET_ACTION,					ACTION_TURTLE_SWIMMING,
		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_1,

		// Deviate through set distance (and speed), waiting for deviation to finish, play splash at end!
		ENTSCR_SET_ACTION,					ACTION_TURTLE_DIVING,
		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0, -0x8<<8, -1,
		ENTSCR_WAIT_DEVIATED,		
		ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_GEN_ENTITY_DIVE1,
											ENTSCR_COORD_Z,			    256,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,

	ENTSCR_END,
	};

/*******************************************************************************
*%%%% ENTSTROrgCreateBeaver
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgCreateBeaver(
*										LIVE_ENTITY* live_entity)
*
*	FUNCTION	Create a beaver entity for the original map.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID ENTSTROrgCreateBeaver(LIVE_ENTITY* live_entity)
{
	ORG_BEAVER_DATA*	beaver_map_data;
	ORG_RT_BEAVER*		beaver;
	ENTITY*				entity;

	entity 				= live_entity->le_entity;
	beaver_map_data		= (ORG_BEAVER_DATA*)(entity + 1);

	// Create the entity using standard moving entity function
	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	beaver = (ORG_RT_BEAVER*)live_entity->le_specific;
	beaver->bv_follow_entity = NULL;
	beaver->bv_curr_movement = ORG_BEAVER_WAITING_FIRSTLOG;

}


/******************************************************************************
*%%%% OrgCollideEntityWithPathEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ENTITY*	OrgCollideEntityWithPathEntities(
*								LIVE_ENTITY*	live_entity,
*								PATH*			path)
*
*	FUNCTION	This function is used by the beaver to run through the entities
*				on a path, and do simple collision checks (basically the 
*				bounding sphere check) to find any hits. Its basic, but it
*				works fine for the original map where logs or turtles only 
*				go sideways.
*
*	INPUTS		live_entity		-	to check
*				path			-	
*
*	RESULTS		PTR to entity that was hit if if collision is detected, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

ENTITY*	OrgCollideEntityWithPathEntities(	LIVE_ENTITY*	live_entity,
											PATH*			path)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	ENTITY_BOOK*	entity_book;
	MR_SHORT*		entity_index_ptr;
	FORM_BOOK*		form_book_0;
	FORM_BOOK*		form_book_1;
	MR_SVEC			svec;
	PATH_RUNNER*	path_runner;
	MR_LONG			distance;

	// get checkee entity form book
	form_book_0	= ENTITY_GET_FORM_BOOK(live_entity->le_entity);

	// Walk through the entities in the path (ignoring our beaver of course)
	// and check each
	entity_index_ptr	= path->pa_entity_indices;
	entity_pptr			= Map_entity_ptrs;

	while (*entity_index_ptr != -1)
		{
		entity			= (ENTITY*)*(entity_pptr + *entity_index_ptr);
		entity_book		= ENTITY_GET_ENTITY_BOOK(entity);

		MR_ASSERT (entity_book->eb_flags & ENTITY_BOOK_PATH_RUNNER);
			
		// Only check at entity thats not me
		if (entity != live_entity->le_entity)
			{
			// get checker entity form book, and path runner
			form_book_1	= ENTITY_GET_FORM_BOOK(entity);
			path_runner = entity->en_path_runner;
			
			// radius check
			svec.vx = live_entity->le_lwtrans->t[0] - path_runner->pr_position.vx;
			svec.vy = live_entity->le_lwtrans->t[1] - path_runner->pr_position.vy;
			svec.vz = live_entity->le_lwtrans->t[2] - path_runner->pr_position.vz;
			distance = MR_SVEC_MOD_SQR(&svec);

			if (distance < (1000 + form_book_1->fb_radius2))
				{
				// collision successful, return ptr to entity
				return entity;
				}
			}

		// next entity
		entity_index_ptr++;
		}

	// no collision found, return NULL
	return NULL;
}

/******************************************************************************
*%%%% ENTSTROrgUpdateBeaver
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgUpdateBeaver(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the original map beaver.
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		The beaver waits at its start position until (somehow) it 
*				detects that theres no log/turtle/whatever for a certain 
*				distance ahead of it on its current spline (which fotunately 
*				is straight) and then it initialises itself and chases whatever 
*				it is chasing...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgUpdateBeaver(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	ORG_RT_BEAVER*			beaver;
	ORG_BEAVER_DATA*		beaver_map_data;
	PATH_RUNNER*			path_runner;
	ENTITY*					hit_entity;
	MR_LONG					frog_index;
	FROG*					frog_ptr;
	MR_VEC					vec;
	MR_LONG					distance;
	MR_LONG					height;
	MR_LONG					path_height;
	MR_LONG					col_r, col_g, col_b;

	entity			= live_entity->le_entity;
	beaver			= live_entity->le_specific;
	beaver_map_data	= (ORG_BEAVER_DATA*)(entity + 1);
	path_runner		= entity->en_path_runner;

	switch (beaver->bv_curr_movement)
		{
		//------------------------------------------------------------------------------------
		case ORG_BEAVER_WAITING_FIRSTLOG:
			// Make sure path runner is marked as NOT active
			path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;

			// Make sure beaver is marked as no display
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;

			// look at the current path, and see the entities that are running on it
			if (hit_entity = OrgCollideEntityWithPathEntities(live_entity, path_runner->pr_path))
				{
				// hit a log, set up pointer to it and change mode
				beaver->bv_follow_entity	= hit_entity;
				beaver->bv_curr_movement	= ORG_BEAVER_WAITING_FIRSTLOGEND;
				}
			break;

		//------------------------------------------------------------------------------------
		case ORG_BEAVER_WAITING_FIRSTLOGEND:
			// Wait for log to pass
			hit_entity = OrgCollideEntityWithPathEntities(live_entity, path_runner->pr_path);
			if (!hit_entity)
				{
				beaver->bv_delay			= beaver_map_data->bv_delay;
				beaver->bv_curr_movement	= ORG_BEAVER_WAITING_GAP;
				}
			break;
							
		//------------------------------------------------------------------------------------
		case ORG_BEAVER_WAITING_GAP:
			// no, must be waiting for the right gap...
			if (beaver->bv_delay--)
				{
				// check to see if another log has come around, and if so we have to restart
				if (hit_entity = OrgCollideEntityWithPathEntities(live_entity, path_runner->pr_path))
					{
					if (hit_entity != beaver->bv_follow_entity)
						{
						// Found a different entity, have to restart
						beaver->bv_curr_movement = ORG_BEAVER_WAITING_FIRSTLOG;
						return;
						}
					}
				}
			else
				{
				// delay is zero...
				beaver->bv_curr_movement = ORG_BEAVER_SWIMMING;

				// Go back to repeating animation of swimming
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, ORG_ACTION_BEAVER_SWIM);

				// Make sure path runner is marked as active
				path_runner->pr_flags |= PATH_RUNNER_ACTIVE;

				// Play SFX of Beaver Swimming
				if (live_entity->le_moving_sound == NULL)
					{
					PlayMovingSound(live_entity, SFX_GEN_FROG_SPLASH2, 1024, 2048);
					}

				}
			break;

		//------------------------------------------------------------------------------------
		case ORG_BEAVER_SWIMMING:
			// Call standard function to update movement of beaver along its spline
			ENTSTRUpdateMovingMOF(live_entity);

			// Make sure beaver is visible
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_DISPLAY;

			if (beaver->bv_follow_entity->en_live_entity)
				{
				// We need to check to see if we have hit the end of an entity we were chasing, after 
				// which we pause for a few secs, then disappear back to the beginning!
				if (hit_entity = OrgCollideEntityWithPathEntities(live_entity, path_runner->pr_path))
					{
					if (hit_entity == beaver->bv_follow_entity)
						{
						beaver->bv_curr_movement	= ORG_BEAVER_SWIMMING_ENDPAUSE;
						beaver->bv_delay			= ORG_BEAVER_CHECK_PAUSE;

						// is there a frog on our log, if so, and its close, kill it!
						frog_index = 0;
						while (frog_index < 4)
							{
							frog_ptr = &Frogs[frog_index];
							if	(	
								(frog_ptr->fr_entity) && 
								(frog_ptr->fr_entity == beaver->bv_follow_entity)
								)
								{
								// yup there is.. is it within 2 grid squares.. if so, kill it
								MR_SUB_VEC_ABC(	(MR_VEC*)frog_ptr->fr_lwtrans->t, 
												(MR_VEC*)live_entity->le_lwtrans->t,
												&vec);

								distance = MR_VEC_MOD(&vec);

								if (distance < ORG_BEAVER_KILL_DISTANCE)
									{
									// Play rear up and bite animation
									MRAnimEnvSingleSetAction(live_entity->le_api_item0, ORG_ACTION_BEAVER_BITE);
									((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

									// Kill Frogger
									FrogKill(frog_ptr, FROG_ANIMATION_BITTEN, NULL);

									// Set count
									beaver->bv_wait = 20;
									// Go on to waiting
									beaver->bv_curr_movement = ORG_BEAVER_WAITING_TO_FINISH_BITE;

									break;
									}
								}
							frog_index++;
							}

						// Did we bite a frog ?
						if ( beaver->bv_curr_movement != ORG_BEAVER_WAITING_TO_FINISH_BITE )
							{
							beaver->bv_curr_movement	= ORG_BEAVER_SWIMMING_ENDPAUSE;
							beaver->bv_delay			= ORG_BEAVER_DIVE_COUNT>>1;
							beaver->bv_dive_offset		= 0;
							}

						}
					}
				}
			else
				{
				// Stop chasing the log since its gone, wait til beaver is off screen, then reset


				// just end for the time being
				beaver->bv_curr_movement = ORG_BEAVER_WAITING_FIRSTLOG;
		
				// Reset beaver back to its original position
				ResetPathRunner(entity);
				ENTSTRUpdateMovingMOF(live_entity);
				}
			break;

		//------------------------------------------------------------------------------------
		case ORG_BEAVER_WAITING_TO_FINISH_BITE:

			// Call standard function to update movement of beaver along its spline
			ENTSTRUpdateMovingMOF(live_entity);

			// Dec wait
			beaver->bv_wait--;

			// End of wait ?
			if ( !beaver->bv_wait )
				{
				// Yes ... reset beaver for the time being
				beaver->bv_curr_movement = ORG_BEAVER_WAITING_FIRSTLOG;

				// Reset beaver back to its original position
				ResetPathRunner(entity);
				ENTSTRUpdateMovingMOF(live_entity);
				}

			break;

		//------------------------------------------------------------------------------------
		case ORG_BEAVER_SWIMMING_ENDPAUSE:
			// Count down timer, if zero, reset beaver, else dive beaver and
			// do a colour change (if possible?)
			ENTSTRUpdateMovingMOF(live_entity);

			if (!(beaver->bv_delay--))
				{
				// Reset beaver back to its original position
				beaver->bv_curr_movement = ORG_BEAVER_WAITING_FIRSTLOG;
				ResetPathRunner(entity);
				ENTSTRUpdateMovingMOF(live_entity);

				live_entity->le_flags &= ~(LIVE_ENTITY_NO_SCREEN_FADE);
				}
			else
				{
				beaver->bv_dive_offset			+= ORG_BEAVER_DIVE_SPEED;
				live_entity->le_lwtrans->t[1]	+= beaver->bv_dive_offset;

				// Find the distance from the path in Y.
				path_height = live_entity->le_entity->en_path_runner->pr_position.vy;
				height 		= path_height - live_entity->le_lwtrans->t[1];
			
				// THIS ALWAYS ASSUME THE TURTLE DIVE DEPTH IS -128 
				col_r	= MAX(0, 0x80 + (height));			
				col_g	= MAX(0, 0x80 - (height >> 1));	
				col_b	= MAX(0, 0x80 - (height << 1));

				live_entity->le_flags |= (LIVE_ENTITY_NO_SCREEN_FADE);
			
				// Ensure fade code respects the values we have set
				SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
				SetLiveEntityCustomAmbient(live_entity, 0x40, 0x40, 0xc0);
				}
			break;

		}
}


/******************************************************************************
*%%%% ENTSTROrgChooseRandomCheckPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	ENTSTROrgChooseRandomCheckPoint(	
*								LIVE_ENTITY*	live_entity, 
*								MR_LONG*		checkpoint_id, 
*								MR_SVEC*		position)
*
*	FUNCTION	This function is used to find a free check point, returning
*				its id, and position, for whatever purposes the caller wants.
*
*	INPUTS		live_entity		-	of caller
*				checkpoint_id	-	id of check point called
*				position		-	position of the check point
*			
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL	ENTSTROrgChooseRandomCheckPoint(	LIVE_ENTITY*	live_entity, 
											MR_ULONG*		checkpoint_id, 
											MR_SVEC*		position)
{
	MR_ULONG	check_id;
	MR_ULONG	once_through;

	once_through = 0;

	// This function tries to find an as yet unreached checkpoint, and sets up a position
	// so that an entity can appear there
	check_id = rand()%5;

	if	(
		!(Checkpoints & (1<<check_id)) &&
		!(Checkpoint_data[check_id].cp_flags & GEN_CHECKPOINT_IS_COVERED)
		)
		{
		MR_COPY_SVEC(position, &Checkpoint_data[check_id].cp_position);
		*checkpoint_id = check_id;
		return TRUE;
		}

	return FALSE;
}

/******************************************************************************
*%%%% ENTSTROrgCreateBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgCreateBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a original map BONUS_FLY...
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgCreateBonusFly(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	ORG_BONUS_FLY*		bonus_fly_data;
	ORG_RT_BONUS_FLY*	bonus_fly;

	entity 			= live_entity->le_entity;
	bonus_fly_data	= (ORG_BONUS_FLY*)(entity + 1);
	bonus_fly		= (ORG_RT_BONUS_FLY*)(live_entity->le_specific);
	
	// Transform can be identity, copy translation from ENTITY
	live_entity->le_lwtrans		= &live_entity->le_matrix;
	MR_INIT_MAT(live_entity->le_lwtrans);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)bonus_fly_data->bf_matrix.t);

	// Create 3D sprite
	live_entity->le_api_item0	= MRCreate3DSprite(	(MR_FRAME*)live_entity->le_lwtrans,
													MR_OBJ_STATIC,
													&Animlist_org_bonus_fly);

	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_flags		|= MR_SPF_NO_3D_ROTATION;
	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_ot_offset	= ORG_BONUS_FLY_OT_OFFSET;
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags									&= ~MR_OBJ_ACCEPT_LIGHTS_MASK;
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags									|= MR_OBJ_NO_DISPLAY;

	GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);

	// disappear entity...
	live_entity->le_entity->en_flags |= ENTITY_HIDDEN;
	live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;

	// Setup entity
	bonus_fly->bf_mode		= ORG_BONUS_FLY_WAITING;
	bonus_fly->bf_timer		= ORG_BONUS_FLY_APPEAR_TIME;

	// Important, set type
	bonus_fly_data->bf_type		= 0;
}


/******************************************************************************
*%%%% ENTSTROrgUpdateBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenUpdateBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a BONUS_FLY
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgUpdateBonusFly(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	ORG_BONUS_FLY*		bonus_fly_data;
	ORG_RT_BONUS_FLY*	bonus_fly;
	MR_SVEC				position;

	entity 			= live_entity->le_entity;
	bonus_fly_data	= (ORG_BONUS_FLY*)(entity + 1);
	bonus_fly		= (ORG_RT_BONUS_FLY*)(live_entity->le_specific);

	switch (bonus_fly->bf_mode)
		{
		case ORG_BONUS_FLY_WAITING:
			if (!(bonus_fly->bf_timer--))
				{
				// Try and find a free check point
				if (ENTSTROrgChooseRandomCheckPoint(live_entity, &bonus_fly->bf_checkpoint_id, &position))
					{
					// make fly appear in right place
					position.vy -= 256;
					position.vz -= 50;

					// make our entity appear at the precalculated position
					MR_VEC_EQUALS_SVEC((MR_VEC*)live_entity->le_lwtrans->t, &position);

					// make check point covered
					Checkpoint_data[bonus_fly->bf_checkpoint_id].cp_flags |= GEN_CHECKPOINT_IS_COVERED;
					
					// make it appear
					live_entity->le_entity->en_flags &= ~ENTITY_HIDDEN;
					live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
					((MR_OBJECT*)live_entity->le_api_item0)->ob_flags &= ~MR_OBJ_NO_DISPLAY;

					bonus_fly->bf_mode  = ORG_BONUS_FLY_APPEARED;
					bonus_fly->bf_timer = ORG_BONUS_FLY_DISAPPEAR_TIME;
					}
				else
					{
					// No check point found, restart
					bonus_fly->bf_mode  = ORG_BONUS_FLY_WAITING;
					bonus_fly->bf_timer = ORG_BONUS_FLY_APPEAR_TIME;
					}
				}
			break;

		case ORG_BONUS_FLY_APPEARED:
			if (bonus_fly->bf_timer--)
				{
				// Count down, looking for hit by frog, this will be marked by having our 
				// hidden flag set suddenly
				if (live_entity->le_entity->en_flags & ENTITY_HIDDEN)
					{
					// play sound, etc
					MRSNDPlaySound(SFX_GEN_FROG_FLY_GULP, NULL, 0, 0);

					// make sure fly can be targetting again
					live_entity->le_flags &= ~LIVE_ENTITY_TARGETTED;

					// Disappear fly and start again
					live_entity->le_entity->en_flags |= ENTITY_HIDDEN;
					live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;
					bonus_fly->bf_mode  = ORG_BONUS_FLY_WAITING;
					bonus_fly->bf_timer = ORG_BONUS_FLY_APPEAR_TIME;
					((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
					Checkpoint_data[bonus_fly->bf_checkpoint_id].cp_flags &= ~GEN_CHECKPOINT_IS_COVERED;
					}
				}
			else
				{
				// Disappear fly and start again
				live_entity->le_entity->en_flags |= ENTITY_HIDDEN;
				live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;
				bonus_fly->bf_mode  = ORG_BONUS_FLY_WAITING;
				bonus_fly->bf_timer = ORG_BONUS_FLY_APPEAR_TIME;
				((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
				Checkpoint_data[bonus_fly->bf_checkpoint_id].cp_flags &= ~GEN_CHECKPOINT_IS_COVERED;
				}
			break;
		}
}


/******************************************************************************
*%%%% ENTSTROrgKillBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgKillBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a original map BONUS_FLY
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgKillBonusFly(LIVE_ENTITY*	live_entity)
{
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
}


/******************************************************************************
*%%%% ENTSTROrgCreateCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgCreateCrocHead(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a original map crochead...
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgCreateCrocHead(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY*				entity;
	ORG_CROC_HEAD*		croc_head_data;
	ORG_RT_CROC_HEAD*	croc_head;
	
	// Create model
	ENTSTRCreateDynamicMOF(live_entity);
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	// Set up pointers
	entity 			= live_entity->le_entity;
	croc_head_data	= (ORG_CROC_HEAD*)(entity + 1);
	croc_head		= (ORG_RT_CROC_HEAD*)(live_entity->le_specific);

	// Make entity invisible with no collision
	entity->en_flags |= ENTITY_HIDDEN;
	entity->en_flags |= ENTITY_NO_COLLISION;
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;

	// Initialise entity
	croc_head->ch_mode				= ORG_CROC_HEAD_WAITING;
	croc_head->ch_timer				= ORG_CROC_HEAD_APPEAR_TIME;

	// Important, set type
	croc_head_data->ch_type			= 0;
	croc_head->ch_checkpoint_id		= -1;
}

/******************************************************************************
*%%%% ENTSTROrgResetCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgResetCrocHead(
*						LIVE_ENTITY*		live_entity,
*						ENTITY*				entity,
*						ORG_RT_CROC_HEAD*	croc_head)
*
*	FUNCTION	Resets a croc head
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.09.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgResetCrocHead(	LIVE_ENTITY*		live_entity,
								ENTITY*				entity,
								ORG_RT_CROC_HEAD*	croc_head)
{
	entity->en_flags |= ENTITY_HIDDEN;
	entity->en_flags |= ENTITY_NO_COLLISION;

	croc_head->ch_mode  = ORG_BONUS_FLY_WAITING;
	croc_head->ch_timer = ORG_BONUS_FLY_APPEAR_TIME;
	
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;
	Checkpoint_data[croc_head->ch_checkpoint_id].cp_flags &= ~GEN_CHECKPOINT_IS_COVERED;

	// put collision back on checkpoint
	if (Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity)
		{
		Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity->en_flags &= ~ENTITY_NO_COLLISION;
		croc_head->ch_checkpoint_id = -1;
		}
}

/******************************************************************************
*%%%% ENTSTROrgUpdateCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgUpdateCrocHead(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a croc head
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgUpdateCrocHead(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	ORG_CROC_HEAD*		croc_head_data;
	ORG_RT_CROC_HEAD*	croc_head;
	MR_SVEC				position;
	MR_ULONG			frog_index;
	FROG*				frog;
	MR_SVEC				rot;

	// Set up pointers
	entity 			= live_entity->le_entity;
	croc_head_data	= (ORG_CROC_HEAD*)(entity + 1);
	croc_head		= (ORG_RT_CROC_HEAD*)(live_entity->le_specific);

	// According to mode do ...
	switch (croc_head->ch_mode)
		{
		// Waiting to appear ...
		case ORG_CROC_HEAD_WAITING:

			// Set no collision
			entity->en_flags	|= ENTITY_NO_COLLISION;

			if (!(croc_head->ch_timer--))
				{
				// Try and find a free check point
				if (ENTSTROrgChooseRandomCheckPoint(live_entity, &croc_head->ch_checkpoint_id, &position))
					{
					// make croc_head appear in right place
					position.vz -= 50;

					// make our entity appear at the precalculated position
					MR_VEC_EQUALS_SVEC((MR_VEC*)live_entity->le_lwtrans->t, &position);

					// make check point covered
					Checkpoint_data[croc_head->ch_checkpoint_id].cp_flags |= GEN_CHECKPOINT_IS_COVERED;
					
					// Make entity appear with collision
					entity->en_flags &= ~ENTITY_HIDDEN;
					((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_DISPLAY;

					// Restart the animation ( to get the snap part of the anim to coinside with the sound effect )
					MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, 0);

					// Set up counts etc.
					croc_head->ch_mode  	= ORG_CROC_HEAD_APPEARING;	
					croc_head->ch_timer 	= ORG_CROC_HEAD_APPEARING_TIME;	
					croc_head->ch_snd_timer	= ORG_CROC_HEAD_FRAMES;

					// Set orientation
					rot.vx = 0;
					rot.vy = 2048;
					rot.vz = 0;
					MRRotMatrix(&rot,live_entity->le_lwtrans);

					// Three quarters scale
					live_entity->le_lwtrans->m[0][0] = (live_entity->le_lwtrans->m[0][0]/4)*3;
					live_entity->le_lwtrans->m[0][1] = (live_entity->le_lwtrans->m[0][1]/4)*3;
					live_entity->le_lwtrans->m[0][2] = (live_entity->le_lwtrans->m[0][2]/4)*3;
					live_entity->le_lwtrans->m[1][0] = (live_entity->le_lwtrans->m[1][0]/4)*3;
					live_entity->le_lwtrans->m[1][1] = (live_entity->le_lwtrans->m[1][1]/4)*3;
					live_entity->le_lwtrans->m[1][2] = (live_entity->le_lwtrans->m[1][2]/4)*3;
					live_entity->le_lwtrans->m[2][0] = (live_entity->le_lwtrans->m[2][0]/4)*3;
					live_entity->le_lwtrans->m[2][1] = (live_entity->le_lwtrans->m[2][1]/4)*3;
					live_entity->le_lwtrans->m[2][2] = (live_entity->le_lwtrans->m[2][2]/4)*3;

					}
				else
					{
					// No check point found, restart
					croc_head->ch_mode  = ORG_CROC_HEAD_WAITING;
					croc_head->ch_timer = ORG_CROC_HEAD_APPEAR_TIME;
					}
				}
			break;

		// Croc head appearing ( warning that checkpoint is about to become deadly ) ...
		case ORG_CROC_HEAD_APPEARING:
			// Dec count
			croc_head->ch_timer--;

			// If a frog has hit a checkpoint (could be refined to our checkpoint), then
			// we should reset now
			frog_index = 0;
			while (frog_index < 4)
				{
				frog = &Frogs[frog_index];
				if	( 
					(frog->fr_mode == FROG_MODE_HIT_CHECKPOINT) && 
					(frog->fr_flags & FROG_ACTIVE) 
					)
					{
					// Reset crochead
					ENTSTROrgResetCrocHead(live_entity, entity, croc_head);
					break;
					}
				frog_index++;
				}

			// End of count ?
			if (!croc_head->ch_timer)
				{
				// Yes ... set correct orientation and scale
				rot.vx = 0;
				rot.vy = 2048;
				rot.vz = 0;
				MRRotMatrix(&rot,live_entity->le_lwtrans);

				// Set collision
				entity->en_flags &= ~ENTITY_NO_COLLISION;

				// remove collision from checkpoint
				if (Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity)
					Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity->en_flags |= ENTITY_NO_COLLISION;

				// Go on to appeared
				croc_head->ch_mode  	= ORG_CROC_HEAD_APPEARED;
				croc_head->ch_timer 	= ORG_CROC_HEAD_DISAPPEAR_TIME;
				}

			break;

		// Croc head has appeared ...
		case ORG_CROC_HEAD_APPEARED:
			// End of life ?
			if (croc_head->ch_timer--)
				{
				// No ... dec time to play sound effect
				croc_head->ch_snd_timer--;

				// Time to play sound effect ?
				if (!croc_head->ch_snd_timer)
					{
					// Reset count down
					croc_head->ch_snd_timer = ORG_CROC_HEAD_FRAMES;
					
					// Yes ... Play SFX of Crocodile Snapping
					if (live_entity->le_moving_sound == NULL)
						PlayMovingSound(live_entity, SFX_ORG_CROCODILE_SNAP, 512, 1536);
					}

				// Has frog hit us ?
				if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
					{
					// Yes ... look to find which frog we are dealing with
					frog_index = 0;
					while (frog_index < 4)
						{
						frog = &Frogs[frog_index];
						if (live_entity->le_flags & (LIVE_ENTITY_HIT_FROG_0 << frog_index))
							{	
							// kill frog
							FrogKill(frog, FROG_ANIMATION_BITTEN, NULL);	
							MRSNDPlaySound(SFX_ORG_FROG_CROC_MUNCH, NULL, 0, 0);
							break;
							}
						frog_index++;
						}
	
					// Reset crochead
					ENTSTROrgResetCrocHead(live_entity, entity, croc_head);
					}
				}
			else
				{
				// Reset crochead
				ENTSTROrgResetCrocHead(live_entity, entity, croc_head);
				}
			break;
		}
}

/******************************************************************************
*%%%% ENTSTROrgKillCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgKillCrocHead(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	kill a croc head
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.09.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgKillCrocHead(LIVE_ENTITY* live_entity)
{
	ORG_RT_CROC_HEAD*	croc_head;

	// Set up pointers
	croc_head		= (ORG_RT_CROC_HEAD*)(live_entity->le_specific);

	// put collision back on checkpoint that we were covering perhaps?
	if (croc_head->ch_checkpoint_id != -1)
		{
		if (Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity)
			Checkpoint_data[croc_head->ch_checkpoint_id].cp_entity->en_flags &= ~ENTITY_NO_COLLISION;
		}

	// kill model
	ENTSTRKillDynamicMOF(live_entity);
}
