/******************************************************************************
*%%%% desert.c
*------------------------------------------------------------------------------
*
*	Desert Create/Update/Kill Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	28.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "desert.h"
#include "entlib.h"
#include "form.h"
#include "mapload.h"
#include "gamesys.h"
#include "project.h"
#include "sound.h"
#include "..\vlo\frogvram.h"
   
/******************************************************************************
*%%%% ENTSTRDesCreateFallingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateFallingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a falling rock fo desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesCreateFallingRock(LIVE_ENTITY*	live_entity)
{
	DESERT_FALLINGROCK*		rock_map_data;
	DESERT_RT_FALLINGROCK*	rock;
	ENTITY*					entity;
	MR_LONG					i;

	entity 			= live_entity->le_entity;
	rock_map_data	= (DESERT_FALLINGROCK*)(entity + 1);

	// not really stationary, but it'll do the job
	ENTSTRCreateStationaryMOF(live_entity);

	// Set specific falling rock runtime data.
	rock = MRAllocMem(sizeof(DESERT_RT_FALLINGROCK), "DESERT_RT_FALLINGROCK");
	live_entity->le_specific = rock;

	// setup runtime data
	MR_CLEAR_VEC(&rock->fr_position);
	MR_CLEAR_VEC(&rock->fr_velocity);
	rock->fr_state = DES_C_ACTION_FALLING_ROCK_CHECKING;
	rock->fr_earth_quake = NULL;		// Used to tell if this is unpaused by the earthquake.

	// create shadow
	for(i=0;i<2;i++)
	{
		setPolyFT4(&rock->fr_shadow_poly[i]);
		
#ifdef PSX
		rock->fr_shadow_poly[i].clut	= im_gen_shadow.te_clut_id;
#endif
		rock->fr_shadow_poly[i].tpage	= im_gen_shadow.te_tpage_id;
		rock->fr_shadow_poly[i].u0		= im_gen_shadow.te_u0;
		rock->fr_shadow_poly[i].v0		= im_gen_shadow.te_v0;
		rock->fr_shadow_poly[i].u1		= im_gen_shadow.te_u1;
		rock->fr_shadow_poly[i].v1		= im_gen_shadow.te_v1;
		rock->fr_shadow_poly[i].u2		= im_gen_shadow.te_u2;
		rock->fr_shadow_poly[i].v2		= im_gen_shadow.te_v2;
		rock->fr_shadow_poly[i].u3		= im_gen_shadow.te_u3;
		rock->fr_shadow_poly[i].v3		= im_gen_shadow.te_v3;
	}
}

/******************************************************************************
*%%%% ENTSTRDesUpdateFallingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateFallingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the fallingrock for the desert maps.
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		Waits until it's triggered by an earthquake, then it waits at it's 
*				initial map position, until the delay reaches zero.
*
* 				It then moves along at it's speed, until it gets to the end of the 
*				spline,	when it will 'bounce' to it's first target and then 
*				depending on the number	of bounces set it may explode or bounce 
*				to the next target.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateFallingRock(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	DESERT_RT_FALLINGROCK*	rock;
	DESERT_FALLINGROCK*		rock_map_data;
	LIVE_ENTITY*			find_entity;
	LIVE_ENTITY*			earth_quake_entity;
	DESERT_EARTHQUAKE*		earth_quake;
	MR_ULONG				count;

	entity			= live_entity->le_entity;
	rock			= live_entity->le_specific;
	rock_map_data	= (DESERT_FALLINGROCK*)(entity + 1);
	find_entity		= NULL;
	earth_quake		= NULL;

	// What is the Falling Rock doing.
	switch (rock->fr_state)
		{
		// --------------------------------------------------------------------------------------
		// Check to see if this is a entity that is Triggered by an earthquake.
		case DES_C_ACTION_FALLING_ROCK_CHECKING:
			while (NULL != (find_entity = GetNextLiveEntityOfType(find_entity, ENTITY_TYPE_DES_EARTH_QUAKE)))
				{
				// Found an earthquake, lets see if we are in the list.
				earth_quake_entity = find_entity;
				earth_quake = (DESERT_EARTHQUAKE*)(earth_quake_entity + 1);

				for (count=0; count<DES_C_MAX_ENT_UNPAUSED_BY_QUAKE; count++)
					{
					if (earth_quake->eq_pause_list[count] == entity->en_unique_id)
						{
						// Found it, so save a pointer.
						rock->fr_earth_quake = find_entity;
						break;
						}
					}
				}
			// If not found in the list then trigger it NOW.
			rock->fr_state = DES_C_ACTION_FALLING_ROCK_START;
			break;
		
		// ---------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_START:	
			// Check to see if we are an earthquake trigger rock
			if (rock->fr_earth_quake == NULL)	
				{	
				// DONT WAIT FOR AN EARTHQUAKE.
				// Set the Falling Rock to start 
				rock->fr_curr_time = rock_map_data->fr_delay;
				rock->fr_state = DES_C_ACTION_FALLING_ROCK_DELAY;					
				}
			else
				{
				// Wait for an EarthQuake.
				// is the earthquake unpaused, and hence active!
				if (1)//!(GOFFLAG_ISPAUSED & rock->fr_earth_quake->uwFlags))
					{
					rock->fr_curr_time = rock_map_data->fr_delay;
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_DELAY;					
					}
				}
			break;

		// ----------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_DELAY:
			// Falling Rock is waiting to move.
			if (rock->fr_curr_time-- == 0)
				{
				// Work out X & Z movement.
				rock->fr_velocity = CalculateInitialVelocity(live_entity->le_lwtrans,
														   &rock_map_data->fr_target1,
														   &rock->fr_position,
   														   rock_map_data->fr_time1);
				rock->fr_state = DES_C_ACTION_FALLING_ROCK_TARGET1;
				rock->fr_curr_time = rock_map_data->fr_time1;
				}
			break;

		// ----------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_TARGET1:
			// Rock is falling towards the first target.
			UpdateEntityWithVelocity(live_entity->le_lwtrans,
									 &rock->fr_position,
									 &rock->fr_velocity);

			// check if object is onscreen, and if so, draw shadow
//			if (NULL != gof->pFrame)
//				DrawShadowAligned(gof->pFrame, 128, &rock->fr_shadow_poly[MRFrame_index]);
			
			// Check to see if Time has reached zero.
			if (rock->fr_curr_time-- <= 0)
				{
				// do we have any more bounced to process?
				if (rock_map_data->fr_num_bounces > 1)
					{
					// Got to the first target.... N E X T.
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_TARGET2;
				
					// Work out X & Z movement.
					rock->fr_velocity = CalculateInitialVelocity(live_entity->le_lwtrans,
																 &rock_map_data->fr_target2,
																 &rock->fr_position,
																 rock_map_data->fr_time2);

					rock->fr_state = DES_C_ACTION_FALLING_ROCK_TARGET2;
					rock->fr_curr_time = rock_map_data->fr_time2;
				
					// SFX of rock bouncing.
//					lPlay3DSoundDistance(SNDFX_DES_FALLING_ROCK_BOUNCE,127,(MR_VEC *)&gof->pMat->t[0],DES_LVL_3D_SOUND_DISTANCE);
					}
				else
					{
					// explode
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_EXPLODE;
//					lPlay3DSoundDistance(SNDFX_DES_FALLING_ROCK_EXPLODE,127,(MR_VEC *)&gof->pMat->t[0],DES_LVL_3D_SOUND_DISTANCE);
					}
				}
			break;

		// ---------------------------------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_TARGET2:
			// Rock is falling towards the second target.
			UpdateEntityWithVelocity(	live_entity->le_lwtrans,
										&rock->fr_position,
										&rock->fr_velocity);

			// check if object is onscreen, and if so, draw shadow
//			if (NULL != gof->pFrame)
//				vDrawShadowAligned(gof->pFrame, 128, &rock->fr_shadow_poly[MRFrame_index]);
				
			// Check to see if Time has reached zero.
			if (rock->fr_curr_time-- <= 0) 
				{
				// do we have any more bounced to process?
				if (rock_map_data->fr_num_bounces > 2)
					{
					// Got to the first target.... N E X T.
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_TARGET3;

					// Work out X & Z movement.
					rock->fr_velocity = CalculateInitialVelocity(	live_entity->le_lwtrans,
																	&rock_map_data->fr_target3,
																	&rock->fr_position,
																	rock_map_data->fr_time3);
			
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_TARGET3;
					rock->fr_curr_time = rock_map_data->fr_time3;
				
					// SFX of rock bouncing.
//					lPlay3DSoundDistance(SNDFX_DES_FALLING_ROCK_BOUNCE,127,(MR_VEC *)&gof->pMat->t[0],DES_LVL_3D_SOUND_DISTANCE);
					}
				else
					{
					// explode
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_EXPLODE;
//					lPlay3DSoundDistance(SNDFX_DES_FALLING_ROCK_EXPLODE,127,(MR_VEC *)&gof->pMat->t[0],DES_LVL_3D_SOUND_DISTANCE);
					}
				}
			break;

		// --------------------------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_TARGET3:
			// Rock is falling towards the third target.
			UpdateEntityWithVelocity(	live_entity->le_lwtrans,
										&rock->fr_position,
										&rock->fr_velocity);
		
			// check if object is onscreen, and if so, draw shadow
//			if (NULL != gof->pFrame)
//				vDrawShadowAligned(gof->pFrame, 128, &rock->fr_shadow_poly[MRFrame_index]);

			// Check to see if Time has reached zero.
			if (rock->fr_curr_time-- <= 0) 
				{
				// Got to the first target.... N E X T.
				rock->fr_state = DES_C_ACTION_FALLING_ROCK_EXPLODE;
			
				// SFX of rock exploding.
//				lPlay3DSoundDistance(SNDFX_DES_FALLING_ROCK_EXPLODE,127,(MR_VEC *)&gof->pMat->t[0],DES_LVL_3D_SOUND_DISTANCE);
				}
			break;

		// ---------------------------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_EXPLODE:
			// Once it has exploded, restart from the beginning.

			// code the explosion later, just restart!
			rock->fr_curr_time = rock_map_data->fr_delay;
			rock->fr_state = DES_C_ACTION_FALLING_ROCK_START;					

			// reset the position based on the supplied matrix...
			MR_COPY_MAT(live_entity->le_lwtrans, &rock_map_data->et_matrix);
			MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)rock_map_data->et_matrix.t);
			break;
		}
}

/******************************************************************************
*%%%% ENTSTRSubKillFallingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubKillFallingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a falling rock
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Martin Kift 	Created (based on original frogger code)
*
*%%%**************************************************************************/
MR_VOID	ENTSTRSubKillFallingRock(LIVE_ENTITY*	live_entity)
{
	// Free the memory for the runtime structures.
	MRFreeMem(live_entity->le_specific);
	ENTSTRKillMovingMOF(live_entity);
}

