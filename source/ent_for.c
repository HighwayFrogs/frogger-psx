/******************************************************************************
*%%%% ent_for.c
*------------------------------------------------------------------------------
*
*	Forest level
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	09.06.97	Martin Kift		Created
*	02.07.97	Martin Kift		Added a lot more entities
*	26.07.97	Gary Richards	Added SFX.
*
*%%%**************************************************************************/

#include "ent_for.h"
#include "frog.h"
#include "collide.h"
#include "sound.h"
#include "scripter.h"
#include "scripts.h"
#include "particle.h"


MR_ULONG	Forest_swarm_animlist[] =
	{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_for_swarm,
	MR_SPRT_LOOPBACK
	};

MR_ULONG	Forest_swarm_collide_forms[4] =	
	{	
	9,		//FOR_STAT_TREESTUMP 
	13,		//FOR_STAT_TREESTUMP2
	14,		//FOR_STAT_TREESTUMP3
	35,		//FOR_STAT_TREESTUMP1
	};

COLL_VISIBILITY_INFO	Forest_swarm_vis_info = 
	{
	&Forest_swarm_collide_forms[0],	// addy of form list
	4,								// 3 forms to check
	FOREST_MAX_VIS_ENTITIES,		// max entities to check for
	};			

COLL_VISIBILITY_DATA	Forest_swarm_vis_data[FOREST_MAX_VIS_ENTITIES];
MR_LONG					num_of_swarms;	// This is used to tell how many swarms are active. For SFX.


/******************************************************************************
*%%%% ENTSTRForCreateHive
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateHive(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a hive entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateHive(LIVE_ENTITY*	live_entity)
{
	FOREST_HIVE*		hive_map_data;
	FOREST_RT_HIVE*		hive;
	ENTITY*				entity;

	entity 			= live_entity->le_entity;
	hive_map_data	= (FOREST_HIVE*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateStationaryMOF(live_entity);	  
	
	// the runtime structure has already been alloced
	hive						= (FOREST_RT_HIVE*)live_entity->le_specific;
	hive->hv_state				= FOR_ACTION_HIVE_WAITING;
	hive->hv_swarm.sw_api_item0 = NULL;

	// create 3d sound for the hive....
	if (live_entity->le_moving_sound == NULL)
		{
		// Play SFX.
		PlayMovingSound(live_entity, SFX_FOR_BEE_BUZZ, 512, 1024);
		}

	// Keep track of the number of active swarms. (We can do this because Hives/swarms are immotal.)
	num_of_swarms = 0;

	// Create PGEN for the hive, but flag it as off
	if (Game_total_players > 1)
		{
		hive->hv_swarm.sw_api_item0 = MRCreatePgen(	&PGIN_for_swarm_multiplayer,
													(MR_FRAME*)&hive->hv_swarm.sw_matrix,
												  	MR_OBJ_STATIC,
												  	NULL);
		}
	else
		{
		hive->hv_swarm.sw_api_item0 = MRCreatePgen(	&PGIN_for_swarm,
													(MR_FRAME*)&hive->hv_swarm.sw_matrix,
												  	MR_OBJ_STATIC,
												  	NULL);
		}

	// Set PGEN owner to point to FOREST_RT_SWARM
	((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_extra.ob_extra_pgen->pg_owner = &hive->hv_swarm;
	((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
	GameAddObjectToViewportsStoreInstances(hive->hv_swarm.sw_api_item0, (MR_MESH_INST**)hive->hv_swarm.sw_api_insts);
}


/******************************************************************************
*%%%% ENTSTRForUpdateHive
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateHive(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a hive entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*	03.07.97	Tim Closs		Removed COLL_VISIBILITY_DATA locals to globals
*	26.07.97	Gary Richards	Added SFX.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateHive(LIVE_ENTITY* live_entity)
{
	FOREST_HIVE*			hive_map_data;
	FOREST_RT_HIVE*			hive;
	FOREST_RT_SWARM*		swarm;
	ENTITY*					hive_entity;
	FROG*					frog;
	MR_ULONG				count;
	MR_LONG					i, j;
	MR_LONG					dist, num_hits;
	MR_VEC					sub_vec;
	MR_VEC					dir_vec;
	MR_VEC					norm_dir_vec;
	MR_VEC					vec;
	COLL_VISIBILITY_DATA*	vis_data_ptr;	
	GRID_STACK*				grid_stack;
	GRID_SQUARE*			grid_square;
	MR_LONG					pitch_bend;
	MR_LONG					voice_id;
	MR_LONG					standard_pitch;


	hive_entity 	= live_entity->le_entity;
	hive			= live_entity->le_specific;
	hive_map_data	= (FOREST_HIVE*)(hive_entity + 1);
	frog			= (FROG*)hive->hv_swarm.sw_frog;
	swarm			= (FOREST_RT_SWARM*)hive;										// Swarm is start of hive.

	switch (hive->hv_state)
		{
        //---------------------------------------------------------------------
		case FOR_ACTION_HIVE_WAITING:
			// Walk through all frogs, trying to find one within range
			count	= 4;
			frog	= Frogs;

			while (count--)
				{
				// is frog active?
				if	(
					(frog->fr_flags & FROG_ACTIVE) &&
					(frog->fr_flags & FROG_CONTROL_ACTIVE)
					)
					{	
					// get distance from playing frog(s) to our hive
					MR_SUB_VEC_ABC(	(MR_VEC*)live_entity->le_lwtrans->t, 
									(MR_VEC*)frog->fr_lwtrans->t, 
									&sub_vec);
			
					dist = MR_VEC_MOD(&sub_vec);
					if (dist < hive_map_data->hv_release_distance)
						{
						// frog is within critical distance.... trigger the swarm.
					
						// initialise swarm structure
						hive->hv_swarm.sw_frog	= frog;
						hive->hv_swarm.sw_speed	= 0;

						// Initialise swarm matrix
						MR_COPY_MAT(&hive->hv_swarm.sw_matrix, live_entity->le_lwtrans);
						MR_COPY_VEC((MR_VEC*)&hive->hv_swarm.sw_matrix.t, (MR_VEC*)live_entity->le_lwtrans->t);

						// Init swarm bee positions and offsets	
						for (i = 0; i < FOR_NUM_SWARM_SPRITES; i++)
							hive->hv_swarm.sw_ofs_angle[i] = i * 0x500;

						// Go into swarm movement mode
						hive->hv_state = FOR_ACTION_HIVE_SWARM_CHASING;

						// Stop, or turn off, or whatever, the sound effect. We will do this by effectively
						// passing control of our buzzing noise to the swarm... the hive essentially becomes
						// quiet... control will be passed back when the swarm returns!
						num_of_swarms++;

						if (live_entity->le_moving_sound)
							((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_source = (MR_VEC*)&hive->hv_swarm.sw_matrix.t;
						}
					 }
				// try next frog
				frog++;
				}

			// No frogs triggered this hive, so just vibrate and make sound as normal!
			// change vibration rate dependent on distance, and sound volume!!
			break;
		
        //---------------------------------------------------------------------
		case FOR_ACTION_HIVE_SWARM_CHASING:

			// First an important check, if we detect that the frog we are chasing is dying,
			// then stop chasing the poor fellow
			if	(
				(frog->fr_mode == FROG_MODE_DYING) || 
				(frog->fr_mode == FROG_MODE_HIT_CHECKPOINT)
				)
				{
	            hive->hv_state = FOR_ACTION_HIVE_SWARM_RETURNING;
//				ENTSTRHiveResetSwarm(hive, live_entity);
				return;
				}

			// accelerate (maybe in a better way?)
			if (swarm->sw_speed < hive_map_data->hv_swarm_speed)
				swarm->sw_speed += 1<<(WORLD_SHIFT-1);	

			// Make swarm face frog: rest of matrix will be generated in disdplay code
			MR_SUB_VEC_ABC((MR_VEC*)frog->fr_lwtrans->t, (MR_VEC*)swarm->sw_matrix.t, &dir_vec);
			MRNormaliseVEC(&dir_vec, &norm_dir_vec);	
			swarm->sw_matrix.m[0][2] = (MR_SHORT)norm_dir_vec.vx;
			swarm->sw_matrix.m[1][2] = (MR_SHORT)norm_dir_vec.vy;
			swarm->sw_matrix.m[2][2] = (MR_SHORT)norm_dir_vec.vz;

			// Add speed
			swarm->sw_matrix.t[0] += ((norm_dir_vec.vx * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;
			swarm->sw_matrix.t[2] += ((norm_dir_vec.vz * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;

			// Follow heightfield in Y
			i 	= GET_GRID_X_FROM_WORLD_X(swarm->sw_matrix.t[0]);
			j	= GET_GRID_Z_FROM_WORLD_Z(swarm->sw_matrix.t[2]);
			if	(
				(i >= 0) &&
				(i < Grid_xnum) &&
				(j >= 0) &&
				(j < Grid_znum)
				)
				{
				grid_stack 				= GetGridStack(i, j);
				grid_square				= &Grid_squares[grid_stack->gs_index + grid_stack->gs_numsquares - 1];
				swarm->sw_matrix.t[1]  = GetGridSquareHeight(grid_square);
				}

			// Create swarm positions as offsets from swarm->sw_matrix.t
			for (i = 0; i < FOR_NUM_SWARM_SPRITES; i++)
				{
				swarm->sw_positions[i].vx 	= swarm->sw_matrix.t[0] + (rcos(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_positions[i].vy 	= swarm->sw_matrix.t[1] - (i * 0x40);
				swarm->sw_positions[i].vz 	= swarm->sw_matrix.t[2] + (rsin(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_ofs_angle[i]		+= FOR_SWARM_ANGLE_SPEED;
				}
	
			// We need to do our own collision function, since we are a poor sprite...
			count	= 4;
			frog	= Frogs;
			while (count--)
				{
				if (frog->fr_flags & FROG_ACTIVE)
					{
					MR_SUB_VEC_ABC((MR_VEC*)frog->fr_lwtrans->t, (MR_VEC*)swarm->sw_matrix.t, &vec);
				
					// Interpret calculation as: master (frog) has 0 coll radius, slave (frog_b) has non-0 coll radius
					if (MR_VEC_MOD_SQR(&vec) <= MR_SQR(FROG_COLLIDE_FROG_Y_OFFSET))
						{
						FrogKill(frog, FROG_ANIMATION_FLOP, NULL);

			            hive->hv_state = FOR_ACTION_HIVE_SWARM_RETURNING;

						MRSNDPlaySound(SFX_FOR_BEE_STING, NULL, 0, 0);
						}
					}
				frog++;
				}

			// check to see if we can see the frog... if so we can follow, if something (??)
			// gets in the way, then we have to return to base so to speak!
			num_hits = VisibilityCollisionCheck(&swarm->sw_matrix, 
												&dir_vec, 
												&Forest_swarm_vis_info,
												Forest_swarm_vis_data);
		
			// check if theres a hit, and what has been hit first!
			count			= num_hits;
			vis_data_ptr	= &Forest_swarm_vis_data[0];

			while (count--)
				{
				// if this is anything BUT a frog, then we've hit something we didn't
				// want too, so set swarm to milling and break outa here!
				MR_ASSERT (vis_data_ptr->hit_entity);
				if (!vis_data_ptr->hit_entity_frog)
					{
					// oops, detected a tree stump before detecting the frog, go into milling mode
					hive->hv_state	= FOR_ACTION_HIVE_SWARM_MILLING;
					swarm->sw_delay	= 0;
					break;
					}
				else
					// detected a frog first, so continue to chase!
					break;
			
				// inc ptr
				vis_data_ptr++;
				} 

			// Ensure display
			((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_flags &= ~MR_OBJ_NO_DISPLAY;
			break;

        //---------------------------------------------------------------------
		case FOR_ACTION_HIVE_SWARM_MILLING:
			// milling around, waiting to detect frog. Just move in current direction, 
			// slowing down!
		
			// First an important check, if we detect that the frog we are chasing is dying,
			// then stop chasing the poor fellow
			if	(
				(frog->fr_mode == FROG_MODE_DYING) || 
				(frog->fr_mode == FROG_MODE_HIT_CHECKPOINT)
				)
				{
	            hive->hv_state = FOR_ACTION_HIVE_SWARM_RETURNING;
				return;
				}

			// reduce speed (slow down)
			if (swarm->sw_speed < (2<<WORLD_SHIFT))
				swarm->sw_speed = 0;
			else
				swarm->sw_speed -= (1<<WORLD_SHIFT);

			// some like of movement pattern!
			if (swarm->sw_delay++ > FOR_HIVE_INTEREST_TIME)
				{
	            hive->hv_state = FOR_ACTION_HIVE_SWARM_RETURNING;
				break;
				}
	
			// Add speed
			swarm->sw_matrix.t[0] += ((swarm->sw_matrix.m[0][2] * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;
			swarm->sw_matrix.t[2] += ((swarm->sw_matrix.m[2][2] * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;

			// Follow heightfield in Y
			i 	= GET_GRID_X_FROM_WORLD_X(swarm->sw_matrix.t[0]);
			j	= GET_GRID_Z_FROM_WORLD_Z(swarm->sw_matrix.t[2]);
			if	(
				(i >= 0) &&
				(i < Grid_xnum) &&
				(j >= 0) &&
				(j < Grid_znum)
				)
				{
				grid_stack 				= GetGridStack(i, j);
				grid_square				= &Grid_squares[grid_stack->gs_index + grid_stack->gs_numsquares - 1];
				swarm->sw_matrix.t[1]  = GetGridSquareHeight(grid_square);
				}

			// Create swarm positions as offsets from swarm->sw_matrix.t
			for (i = 0; i < FOR_NUM_SWARM_SPRITES; i++)
				{
				swarm->sw_positions[i].vx 	= swarm->sw_matrix.t[0] + (rcos(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_positions[i].vy 	= swarm->sw_matrix.t[1] - (i * 0x40);
				swarm->sw_positions[i].vz 	= swarm->sw_matrix.t[2] + (rsin(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_ofs_angle[i]		+= (FOR_SWARM_ANGLE_SPEED >> 1);
				}

			// get difference vector of swarm from frog
			MR_SUB_VEC_ABC((MR_VEC*)frog->fr_lwtrans->t, (MR_VEC*)swarm->sw_matrix.t, &dir_vec);

			// check to see if we can see the frog... if so we can follow, if something (??)
			// gets in the way, then we have to return to base so to speak!
			num_hits = VisibilityCollisionCheck(&swarm->sw_matrix, 
												&dir_vec, 
												&Forest_swarm_vis_info,
												Forest_swarm_vis_data);
		
			// check if theres a hit, and what has been hit first!
			count			= num_hits;
			vis_data_ptr	= Forest_swarm_vis_data;

			while (count--)
				{
				// have we detected the frog?
				MR_ASSERT (vis_data_ptr->hit_entity);
				if (vis_data_ptr->hit_entity_frog)
					{
					// ahha, found a frog, which must have been before a tree stump
					hive->hv_state = FOR_ACTION_HIVE_SWARM_CHASING;
					break;
					}
				else
					{
					// we must have found one of the other entity form types we requested
					// hence we should break out now. But, if its an actual entity, stop 
					// immediately
					if (vis_data_ptr->hit_actual_hit == TRUE)
						{
						swarm->sw_speed = 0;
						}
					break;
					}
				vis_data_ptr++;
				}
			// Ensure display
			((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_flags &= ~MR_OBJ_NO_DISPLAY;
			break;

        //---------------------------------------------------------------------
		case FOR_ACTION_HIVE_SWARM_RETURNING:
			// returning to base

			// accelerate (maybe in a better way?)
			if (swarm->sw_speed < (hive_map_data->hv_swarm_speed<<WORLD_SHIFT))		
				swarm->sw_speed += (1<<WORLD_SHIFT);

			// don't worry about a collision as such, waste of time, just get very close
			// get difference vector of swarm from hive
			MR_SUB_VEC_ABC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)swarm->sw_matrix.t, &dir_vec);
			MRNormaliseVEC(&dir_vec, &norm_dir_vec);	
			swarm->sw_matrix.m[0][2] = (MR_SHORT)norm_dir_vec.vx;
			swarm->sw_matrix.m[1][2] = (MR_SHORT)norm_dir_vec.vy;
			swarm->sw_matrix.m[2][2] = (MR_SHORT)norm_dir_vec.vz;

			// Add speed
			swarm->sw_matrix.t[0] += ((norm_dir_vec.vx * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;
			swarm->sw_matrix.t[1] += (norm_dir_vec.vy >> (MR_FP_MAT-1));
			swarm->sw_matrix.t[2] += ((norm_dir_vec.vz * (swarm->sw_speed >> (WORLD_SHIFT + 0))))>>MR_FP_MAT;

			// Create swarm positions as offsets from swarm->sw_matrix.t
			for (i = 0; i < FOR_NUM_SWARM_SPRITES; i++)
				{
				swarm->sw_positions[i].vx 	= swarm->sw_matrix.t[0] + (rcos(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_positions[i].vy 	= swarm->sw_matrix.t[1] - (i * 0x40);
				swarm->sw_positions[i].vz 	= swarm->sw_matrix.t[2] + (rsin(swarm->sw_ofs_angle[i]) >> 7);
				swarm->sw_ofs_angle[i]		+= (FOR_SWARM_ANGLE_SPEED >> 2);
				}
	
			// check how close we are, accept half a grid square
			if ( (abs(dir_vec.vx)<128) && (abs(dir_vec.vy)<128) && (abs(dir_vec.vz)<128))
				ENTSTRHiveResetSwarm(hive, live_entity);

			break;
		}

	// Work out how many swarms are active and adjust the pitch bend.
	if	( 
		(live_entity->le_moving_sound) && 
		(((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0] != -1)
		)
		{
		// Grab voice id.
		voice_id		= ((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0];
		standard_pitch	= (FOR_SWARM_CENTER_PITCH - (rand()&15));		// +/- 8 around a center pitch of 64.
		
		// Adjust pitch for number of active swarms. More swarms higher pitch.
		standard_pitch += (num_of_swarms * FOR_SWARM_PITCH_MOD);		// Up a pitch for each swarm.

		// Grab position with Sin table.	
		pitch_bend		= standard_pitch - ((rsin((Game_timer << FOR_SWARM_SIN_SPEED))) >> FOR_SWARM_SHIFT);	

		MRSNDPitchBend(voice_id,pitch_bend);
		}
}


/******************************************************************************
*%%%% ENTSTRForKillHive
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForKillHive(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a Hive + swarm. (If there is one)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Gary Richards	Create
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForKillHive(LIVE_ENTITY*	live_entity)
{
	FOREST_RT_HIVE*	hive;

	hive = live_entity->le_specific;

	if (hive->hv_swarm.sw_api_item0)
		((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	hive->hv_swarm.sw_api_item0 = NULL;

	// Kill the Static (hive) as well.
	ENTSTRKillStationaryMOF(live_entity);
}



/******************************************************************************
*%%%% ENTSTRForCreateFallingLeaf
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateFallingLeaf(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a falling leaf entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateFallingLeaf(LIVE_ENTITY*	live_entity)
{
	FOREST_FALLING_LEAF*		leaf_map_data;
	FOREST_RT_FALLING_LEAF*		leaf;
	ENTITY*						entity;

	entity 			= live_entity->le_entity;
	leaf_map_data	= (FOREST_FALLING_LEAF*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateMovingMOF(live_entity);
	
	// the runtime structure has already been alloced
	leaf			= (FOREST_RT_FALLING_LEAF*)live_entity->le_specific;

	leaf->fl_curr_displacement	= 0;
	leaf->fl_curr_dir			= 0;
	leaf->fl_speed				= 2048 / leaf_map_data->fl_sway_duration;

	// temp fix
	if (leaf_map_data->fl_sway_angle == 0)
		leaf_map_data->fl_sway_angle = 45;

}

/******************************************************************************
*%%%% ENTSTRForUpdateFallingLeaf
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateFallingLeaf(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a hive entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateFallingLeaf(LIVE_ENTITY* live_entity)
{
	FOREST_FALLING_LEAF*		leaf_map_data;
	FOREST_RT_FALLING_LEAF*		leaf;
	ENTITY*						entity;

	entity 			= live_entity->le_entity;
	leaf_map_data	= (FOREST_FALLING_LEAF*)(entity + 1);
	leaf			= (FOREST_RT_FALLING_LEAF*)live_entity->le_specific;

	// handle displacement/rotation around Y Axis.. I hate to use sin funcs and
	// a divide here, but theres no way around it really, not without sacrifing
	// any accuracy on the angles that can be achieved... :/
//	gof->pObject->ob_frame->fr_rotation.vz = rsin(leaf->fl_curr_displacement) << MR_FP_VEC;
//	gof->pObject->ob_frame->fr_rotation.vz /= leaf->fl_angle_divider;
//	gof->pObject->ob_frame->fr_flags |= MR_FRAME_REBUILD;

	// update curr displacement of leaf
	if (0 == leaf->fl_curr_dir)
		{
		leaf->fl_curr_displacement += leaf->fl_speed;
		if (leaf->fl_curr_displacement >= 1024)
			leaf->fl_curr_dir = 1;
		}
	else
		{
		leaf->fl_curr_displacement -= leaf->fl_speed;
		if (leaf->fl_curr_displacement <= -1024)
			leaf->fl_curr_dir = 0;
		}
}


/******************************************************************************
*%%%% ENTSTRForCreateSwayingBranch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateSwayingBranch(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a swaying branch entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateSwayingBranch(LIVE_ENTITY*	live_entity)
{
	FOREST_SWAYING_BRANCH*		branch_map_data;
	FOREST_RT_SWAYING_BRANCH*	branch;
	ENTITY*						entity;

	entity 			= live_entity->le_entity;
	branch_map_data	= (FOREST_SWAYING_BRANCH*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);
	
	// the runtime structure has already been alloced
	branch = (FOREST_RT_SWAYING_BRANCH*)live_entity->le_specific;

	branch->sb_curr_displace	= 0;
	branch->sb_curr_dir			= 0;
	branch->sb_speed			= (MR_USHORT)(2048 / branch_map_data->sb_sway_duration);
	branch->sb_mode				= FOREST_SWAY_BRANCH_WAITING;
	branch->sb_timer			= branch_map_data->sb_once_off_delay;

	// temp fix
	if (0 == branch_map_data->sb_sway_angle)
		branch_map_data->sb_sway_angle = 45;

	branch->sb_angle_divider = (MR_USHORT)((360*2)/branch_map_data->sb_sway_angle);
}

/******************************************************************************
*%%%% ENTSTRForUpdateSwayingBranch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateSwayingBranch(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a swaying branch entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateSwayingBranch(LIVE_ENTITY* live_entity)
{
	FOREST_SWAYING_BRANCH*		branch_map_data;
	FOREST_RT_SWAYING_BRANCH*	branch;
	ENTITY*						entity;
	MR_SVEC						svec;

	entity 			= live_entity->le_entity;
	branch_map_data	= (FOREST_SWAYING_BRANCH*)(entity + 1);
	branch 			= (FOREST_RT_SWAYING_BRANCH*)live_entity->le_specific;

	switch (branch->sb_mode)
		{
		case FOREST_SWAY_BRANCH_WAITING:
			if (!branch->sb_timer--)
				branch->sb_mode = FOREST_SWAY_BRANCH_SWAYING;
			break;

		case FOREST_SWAY_BRANCH_SWAYING:
			// handle displacement/rotation around Y Axis.. I hate to use sin funcs and
			// a divide here, but theres no way around it really, not without sacrifing
			// any accuracy on the angles that can be achieved... :/
			branch->sb_rotation.vy = rsin(branch->sb_curr_displace) << 16;
			branch->sb_rotation.vy /= branch->sb_angle_divider;

			MR_SET_SVEC(&svec, 0, branch->sb_rotation.vy >> 16, 0);
			MRRotMatrix(&svec, live_entity->le_lwtrans);
			MRMulMatrixABB(&branch_map_data->sb_matrix, live_entity->le_lwtrans);

			// update curr displacement of branch
			if (0 == branch->sb_curr_dir)
				{
				branch->sb_curr_displace += branch->sb_speed;
				if (branch->sb_curr_displace >= 1024)
					branch->sb_curr_dir = 1;
				}
			else
				{
				branch->sb_curr_displace -= branch->sb_speed;
				if (branch->sb_curr_displace <= -1024)
					branch->sb_curr_dir = 0;
				}
			break;
		}
}


/******************************************************************************
*%%%% ENTSTRForCreateBreakingBranch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateBreakingBranch(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a breaking branch entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateBreakingBranch(LIVE_ENTITY*	live_entity)
{
	FOREST_BREAKING_BRANCH*		branch_map_data;
	FOREST_RT_BREAKING_BRANCH*	branch;
	ENTITY*						entity;

	entity 			= live_entity->le_entity;
	branch_map_data	= (FOREST_BREAKING_BRANCH*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);
	
	// the runtime structure has already been alloced
	branch = (FOREST_RT_BREAKING_BRANCH*)live_entity->le_specific;

	branch->bb_break_count	= branch_map_data->bb_break_delay;
	branch->bb_action		= FOREST_BRANCH_OK;
	branch->bb_fall_height	= 0;

	MR_CLEAR_SVEC(&branch->bb_rot);

	// turn on collision for this entity
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
}

/******************************************************************************
*%%%% ENTSTRForUpdateBreakingBranch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateBreakingBranch(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a breaking branch entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateBreakingBranch(LIVE_ENTITY* live_entity)
{
	FOREST_BREAKING_BRANCH*		branch_map_data;
	FOREST_RT_BREAKING_BRANCH*	branch;
	ENTITY*						entity;
	MR_LONG						grid_x, grid_z;
	GRID_STACK*					grid_stack;
	GRID_SQUARE*				grid_square;
	FROG*						frog;
	MR_LONG						frog_index;
	MR_LONG						sin, cos;

	entity 			= live_entity->le_entity;
	branch_map_data	= (FOREST_BREAKING_BRANCH*)(entity + 1);
	branch 			= (FOREST_RT_BREAKING_BRANCH*)live_entity->le_specific;

	switch (branch->bb_action)
		{
        //---------------------------------------------------------------------
		case FOREST_BRANCH_OK:
			// waiting for frog to jump on us!
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// start breaking mechanism
				branch->bb_action = FOREST_BRANCH_BREAKING;

				// play breaking sound
				MRSNDPlaySound(SFX_FOR_BRANCH_SNAP, NULL, 0, 0);
				}
			break;

        //---------------------------------------------------------------------
		case FOREST_BRANCH_BREAKING:
			if (0 == branch->bb_break_count--)
				{
				// mark branch as broken!
				branch->bb_action = FOREST_BRANCH_BROKEN;

				// work out the height to fall too
				grid_x		= GET_GRID_X_FROM_WORLD_X(live_entity->le_lwtrans->t[0]);
				grid_z		= GET_GRID_Z_FROM_WORLD_Z(live_entity->le_lwtrans->t[2]);
				grid_stack 	= GetGridStack(grid_x, grid_z);
				
				// look through grid stacks to find a valid one to slide too!
				grid_square				= &Grid_squares[grid_stack->gs_index];
				branch->bb_fall_height	= GetGridSquareHeight(grid_square);

				// turn off collision for this entity
				live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;

				// set up speed
				branch->bb_fall_speed = 0;

				// turn off parent entity for frog, and make it FALL
				frog		= Frogs;
				frog_index	= 4;
				while (frog_index--)
					{
					if (frog->fr_entity == live_entity->le_entity)
						{
						FROG_FALL(frog);
						}
					frog++;
					}
				}
			break;

        //---------------------------------------------------------------------
		case FOREST_BRANCH_BROKEN:
			// have we fallen to the landscape? 
			if (live_entity->le_lwtrans->t[1] < branch->bb_fall_height)
				{
				branch->bb_fall_speed += (SYSTEM_GRAVITY>>2);
				live_entity->le_lwtrans->t[1] += (branch->bb_fall_speed>>16); 

				cos = rcos(0x20);
				sin = rsin(0x20);
				MRRot_matrix_Z.m[0][0] =  cos;
				MRRot_matrix_Z.m[0][1] = -sin;
				MRRot_matrix_Z.m[1][0] =  sin;
				MRRot_matrix_Z.m[1][1] =  cos;
				MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_Z);
				}
			else
				{
				live_entity->le_lwtrans->t[1]	= branch->bb_fall_height - 20;

				if (live_entity->le_effect == NULL)
					{
					LiveEntityInitPop(live_entity);
					LiveEntityStartPolyPiecePop(live_entity);
					}
				}
			break;
		}
}


/******************************************************************************
*%%%% ENTSTRForCreateSquirrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateSquirrel(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a squirrel entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateSquirrel(LIVE_ENTITY*	live_entity)
{
	FOREST_SQUIRREL*		squirrel_map_data;
	FOREST_RT_SQUIRREL*		squirrel;
	ENTITY*					entity;
	MR_USHORT				number_cels;
	MR_ANIM_ENV_SINGLE*		env_single;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;

	entity 				= live_entity->le_entity;
	squirrel_map_data	= (FOREST_SQUIRREL*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateMovingMOF(live_entity);
	
	// the runtime structure has already been alloced
	squirrel = (FOREST_RT_SQUIRREL*)live_entity->le_specific;

#if 1
	// set up animation
	LiveEntitySetAction(live_entity, FOREST_SQUIRREL_RUNNING);
#endif

	// precalculate the animation delay required for the turning animation
	// to achieve the correct speed! The value stored in the squirrel is
	// in frames.... (30 per sec), so if the animation has 10 frames, we
	// require a delay of 30/10 to make it work right!
	squirrel->sq_animation_delay	= 0;
	squirrel->sq_action				= FOREST_SQUIRREL_RUNNING;

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
		{
		env_flipbook	= ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
		number_cels		= env_flipbook->ae_total_cels;
		}
	else
		{
		env_single		= ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_single;
		number_cels		= env_single->ae_total_cels;
		}

	if (squirrel_map_data->sq_turn_duration < number_cels)
		squirrel->sq_animation_delay	= 0;
	else
		squirrel->sq_animation_delay 	= (squirrel_map_data->sq_turn_duration / number_cels) - 1;

	//	Set initial update period, which will be zero since the squirrel will be running
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_update_period = 0;
}

/******************************************************************************
*%%%% ENTSTRForUpdateSquirrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateSquirrel(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a squirrel entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateSquirrel(LIVE_ENTITY* live_entity)
{
	FOREST_SQUIRREL*		squirrel_map_data;
	FOREST_RT_SQUIRREL*		squirrel;
	ENTITY*					entity;

	entity 				= live_entity->le_entity;
	squirrel_map_data	= (FOREST_SQUIRREL*)(entity + 1);
	squirrel 			= (FOREST_RT_SQUIRREL*)live_entity->le_specific;

	// update spline movement
	ENTSTRUpdateMovingMOF(live_entity);

	switch (squirrel->sq_action)
		{
        //---------------------------------------------------------------------
		case FOREST_SQUIRREL_RUNNING:
			// check path runner flags to see if its hit the end of the path
			if 	(
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_START) ||
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_END)
				)
				{
				// go into turning mode...
#if 1
				LiveEntitySetAction(live_entity, FOREST_SQUIRREL_TURNING);
#else
				squirrel->sq_animation_delay = squirrel_map_data->sq_turn_duration;
#endif
				squirrel->sq_action	= FOREST_SQUIRREL_TURNING;

#if 1
				// set duration of turn animation to precalculated value!
//				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_update_period = squirrel->sq_animation_delay;
#endif
				// Need to pause the path runner so it doesn't keep going
				live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
				}
			break;

        //---------------------------------------------------------------------
		case FOREST_SQUIRREL_TURNING:
			// need to wait for anim to end!!
#if 1
			if (LiveEntityCheckAnimationFinished(live_entity))
#else
			if (squirrel->sq_animation_delay-- == 0)
#endif
				{
#if 1
				LiveEntitySetAction(live_entity, FOREST_SQUIRREL_RUNNING);
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_update_period = 0;
#endif
				squirrel->sq_action = FOREST_SQUIRREL_RUNNING;

				// upause the path runner so it doesn't keep going
				live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
				}
			break;
		}
}


/******************************************************************************
*%%%% ENTSTRForKillSquirrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForKillSquirrel(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a squirrel entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForKillSquirrel(LIVE_ENTITY* live_entity)
{
	// kill the moving entity
	ENTSTRKillMovingMOF(live_entity);
}

/******************************************************************************
*%%%% ENTSTRForCreateHedgehog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForCreateHedgehog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a hedgehog entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForCreateHedgehog(LIVE_ENTITY*	live_entity)
{
	FOREST_HEDGEHOG*		hedgehog_map_data;
	FOREST_RT_HEDGEHOG*		hedgehog;
	ENTITY*					entity;

	entity 				= live_entity->le_entity;
	hedgehog_map_data	= (FOREST_HEDGEHOG*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateMovingMOF(live_entity);
	
	// the runtime structure has already been alloced
	hedgehog = (FOREST_RT_HEDGEHOG*)live_entity->le_specific;

	// set up entity
	FOREST_HEDGEHOG_START_RUNNING(live_entity, hedgehog, hedgehog_map_data);
}

/******************************************************************************
*%%%% ENTSTRForUpdateHedgehog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRForUpdateHedgehog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a hedgehog entity
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Martin Kift		Created
*	08.07.97	Martin Kift		Changed so that hedgehog resets to run mode
*								if it reaches end of its path (on reset)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRForUpdateHedgehog(LIVE_ENTITY* live_entity)
{
	FOREST_HEDGEHOG*		hedgehog_map_data;
	FOREST_RT_HEDGEHOG*		hedgehog;
	ENTITY*					entity;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;

	entity 				= live_entity->le_entity;
	hedgehog_map_data	= (FOREST_HEDGEHOG*)(entity + 1);
	hedgehog 			= (FOREST_RT_HEDGEHOG*)live_entity->le_specific;

	// update path movement
	ENTSTRUpdateMovingMOF(live_entity);

	switch (hedgehog->hh_action)
		{
        //---------------------------------------------------------------------
		case FOREST_HEDGEHOG_RUNNING:
			// count down until time is up
			if (!(hedgehog->hh_count--))
				{
				// go into prepare for roll mode
				hedgehog->hh_action	= FOREST_HEDGEHOG_PREPARE_TO_ROLL;
				}
			break;

        //---------------------------------------------------------------------
		case FOREST_HEDGEHOG_PREPARE_TO_ROLL:
			// need to wait for anim to end before going into roll mode
			env_flipbook = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
				{
				FOREST_HEDGEHOG_START_ROLLING(live_entity, hedgehog, hedgehog_map_data);
				}
			break;

        //---------------------------------------------------------------------
		case FOREST_HEDGEHOG_ROLLING:
			// count down until time is up
			if (!(hedgehog->hh_count--))
				{
				// go into prepare for roll mode
				hedgehog->hh_action	= FOREST_HEDGEHOG_PREPARE_TO_RUN;
				}

			// check for reaching end of path... if we do, reset counters now!
			if	(
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_START) || 
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_END)
				)
				{
				FOREST_HEDGEHOG_START_RUNNING(live_entity, hedgehog, hedgehog_map_data);
				}
			break;

		//---------------------------------------------------------------------
		case FOREST_HEDGEHOG_PREPARE_TO_RUN:
			// need to wait for anim to end before going into roll mode
			env_flipbook = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
				{
				FOREST_HEDGEHOG_START_RUNNING(live_entity, hedgehog, hedgehog_map_data);
				}
			break;
		}
}

/******************************************************************************
*%%%% ENTSTRHiveResetSwarm
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRHiveResetSwarm(
*						FOREST_RT_HIVE*		hive)
*
*	FUNCTION	Kills off a hives swarm, and resets hive mode to waiting
*
*	INPUTS		hive		- hive ptr
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRHiveResetSwarm(FOREST_RT_HIVE* hive, LIVE_ENTITY* live_entity)
{
	// give sound back to hive
	if (live_entity->le_moving_sound)
		((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_source = (MR_VEC*)live_entity->le_lwtrans->t;

	if (num_of_swarms-- < 0)
		num_of_swarms = 0;

	// now reset ourselves
	((MR_OBJECT*)hive->hv_swarm.sw_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;

	hive->hv_state = FOR_ACTION_HIVE_WAITING;
}

// Wait to randomly trigger the squirrel Noise.
MR_LONG		script_for_squirrel[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,	SCRIPT_FOR_SQUIRREL_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	8,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_for_squirrel_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	32,		SFX_FOR_SQUIRREL,
									ENTSCR_COORD_Z,  		256,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
// Wait to randomly trigger the owl Noise.
MR_LONG		script_for_owl[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_FOR_BIRD_WING,
									ENTSCR_NO_REGISTERS,		512,	1024,

		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,	SCRIPT_FOR_OWL_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	15,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_for_owl_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	32,		SFX_FOR_OWL01,
									ENTSCR_COORD_Z,  		256,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	5,

	ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	24,		SFX_FOR_OWL02,
									ENTSCR_COORD_Z,  		256,
	ENTSCR_RESTART,
	};

// --------------------------------------------------------------------------------------------
MR_LONG		script_for_swan[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_FOR_SWAN_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_for_swan_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_FOR_SWAN_CALL,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};



//------------------------------------------------------------------------------------------------
// For riverNoise
//

MR_LONG		script_for_river_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_FOR_RIVER,	// 	   MIN		 		MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
															// Min, Max	  Speed,	Range,
	ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	48,		84,		3,	  7,	64,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

