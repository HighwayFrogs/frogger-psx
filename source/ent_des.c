/******************************************************************************
*%%%% ent_des.c
*------------------------------------------------------------------------------
*
*	Desert Create/Update/Kill Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	28.04.97	Martin Kift		Created
*	06.05.97	Martin Kift		Update entities to new entity standard (i.e. removed
*								call MRAllocMem for runtime struct)
*	06.05.97	Martin Kift		Added Themal entities
*	26.06.97	Gary Richards	Added Cracks.
*	07.07.97	Tim Closs		Revised for new shadows.
*								Added ENTSTRDesFallingRockCalculateInitialVelocity()
*	18.07.97	Martin Kift		Rewrote rock tumbling code
*
*%%%**************************************************************************/

#include "ent_des.h"
#include "entlib.h"
#include "form.h"
#include "mapload.h"
#include "gamesys.h"
#include "project.h"
#include "sound.h"
#include "scripter.h"
#include "scripts.h"
#include "misc.h"
#include "frog.h"


MR_SVEC		Des_rock_shadow_offsets[] =
	{
		{-0x70, 0,  0x70},
		{ 0x70, 0,  0x70},
		{-0x70, 0, -0x70},
		{ 0x70, 0, -0x70},
	};


//------------------------------------------------------------------------------------------------
// Des snake
//
MR_LONG		script_des_snake[] =
	{
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_DES_SNAKE_HISS,		//  MIN		MAX.
									ENTSCR_NO_REGISTERS,	768,		1024,

		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	64,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Des Vulture Script
//
// Play's a sound effect if Frogger gets to close too the vulture.
//
/*
MR_LONG		script_des_vulture[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_DES_VULTURE_KILL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_DES_VULTURE_SFX,	2,
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_des_vulture_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_DES_VULTURE,
										ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBDesVultureKill(LIVE_ENTITY* live_entity)
{
	// change animation and play kill sound.
	//MRSNDPlaySound(SFX_ORG_FROG_TRAFFIC_SKID_SPLAT, NULL, 0, 0);

	// Check to make sure that this is an animated model.
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		// Only change if displayed.
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, DES_ANIM_VULTURE_SWEEP);
		}
} */

//------------------------------------------------------------------------------------------------
// Des Falling Rock Script

MR_LONG		script_des_falling_rock[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,

		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	100,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
// Des Bison Script
//
// Play's a sound effect if Frogger gets to close to the bison.
//

MR_LONG		script_des_bison[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,			SCRIPT_DES_BISON_SFX,	2,

		ENTSCR_PLAY_MOVING_SOUND,	SFX_DES_BISON_NOISE,
									ENTSCR_NO_REGISTERS,	1024,	2048,

		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,	0,
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_des_bison_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_DES_BISON,
										ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Des Beetle Script
//
// Play's a sound effect for the beetle.(3d moving sound!)
//
MR_LONG		script_des_beetle[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_DES_LIZARD,		
									ENTSCR_NO_REGISTERS,		512,	1024,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Des lizard Script
//
// Play's a sound effect for the lizard.(3d moving sound!)
//
MR_LONG		script_des_lizard[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_DES_LIZARD,		
									ENTSCR_NO_REGISTERS,		512,	1024,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
// Des Salamander Script
//
// Play's a sound effect for the Salamander.(3d moving sound!)
//
MR_LONG		script_des_salamander[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_DES_SALAMANDER,		
									ENTSCR_NO_REGISTERS,		512,	1024,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};



/******************************************************************************
*%%%% ENTSTRDesCreateFallingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateFallingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a falling rock fo desert level
*	MATCH		https://decomp.me/scratch/AaUXF	(By Kneesnap)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Created
*	18.07.97	Martin Kift		Rewrote rock tumbling code
*	04.11.23	Kneesnap		Byte-matched function in PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesCreateFallingRock(LIVE_ENTITY*	live_entity)
{
	DESERT_FALLING_ROCK*			rock_map_data;
	DESERT_RT_FALLING_ROCK*			rock;
	ENTITY*							entity;
	DESERT_FALLING_ROCK_TARGETS*	target;
	MR_LONG							i;

	entity 			= live_entity->le_entity;
	rock_map_data	= (DESERT_FALLING_ROCK*)(entity + 1);

	if (rock_map_data->fr_flags != DESERT_FALLING_ROCK_TARGETS_RESOLVED)
		{
		// Project target SVECs onto landscape
		target 	= rock_map_data->fr_targets;
		i		= rock_map_data->fr_num_bounces;
		while(i--)
			{
			target->fr_target.vx 	= (target->fr_target.vx & ~0xff) + 0x80;
			target->fr_target.vz 	= (target->fr_target.vz & ~0xff) + 0x80;
			target->fr_target.vy	= GetHeightFromWorldXYZ(target->fr_target.vx, target->fr_target.vy, target->fr_target.vz, NULL);
			MR_ASSERT((MR_USHORT)target->fr_target.vy != GRID_RETURN_VALUE_ERROR);
			if (i == (rock_map_data->fr_num_bounces - 1))
				target->fr_target.vy -= 0x80;
				
			target++;
			}
		rock_map_data->fr_flags = DESERT_FALLING_ROCK_TARGETS_RESOLVED;
		}

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);

	// the runtime structure has already been alloced
	rock = (DESERT_RT_FALLING_ROCK*)live_entity->le_specific;

	// setup runtime data
	rock->fr_position.vx = rock_map_data->fr_matrix.t[0] << 16;
	rock->fr_position.vy = rock_map_data->fr_matrix.t[1] << 16;
	rock->fr_position.vz = rock_map_data->fr_matrix.t[2] << 16;

	MR_CLEAR_VEC(&rock->fr_velocity);
	rock->fr_state				= DES_C_ACTION_FALLING_ROCK_CHECKING;	// Set initial mode
	rock->fr_curr_bounces		= 0;									// Start on first bounce, obviously
	rock->fr_anim_rock			= NULL;									// Anim environment

	// Create shadow (turned off)
	rock->fr_shadow				= CreateShadow(&im_gen_shadow, live_entity->le_lwtrans, Des_rock_shadow_offsets);
	rock->fr_shadow->ef_flags	|= (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE | EFFECT_NO_ROTATION);

	// Setup matrix
	MR_COPY_MAT(live_entity->le_lwtrans, &rock_map_data->fr_matrix);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)rock_map_data->fr_matrix.t);

	// Turn on collision (this applies to ALL falling rocks)
//	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
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
*				The default model for this entity is a static rock, which needs
*				pointing and rotating in code. When about to explode, we simply
*				create an animated model, play it, and kill it off later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Created
*	29.05.97	Martin Kift		updated aniimation code.
*	06.06.97	Martin Kift		Added shadow code
*	12.07.97	Martin Kift		Fixed rotation code
*	11.08.97	Gary Richards	Change model to number 25 and made it an equate.
*								If the position within buildwad changes, this
*								must also been changed to tie-up.
*	18.07.97	Martin Kift		Rewrote rock tumbling code
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateFallingRock(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	DESERT_RT_FALLING_ROCK*	rock;
	DESERT_FALLING_ROCK*	rock_map_data;
	LIVE_ENTITY*			find_entity;
	MR_MOF*					mof;
	MR_ULONG				i;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;
	MR_ANIM_ENV_SINGLE*		env_single;
	MR_LONG					sin, cos;
	MR_VEC					vec_x, vec_z, vec_y;

	entity			= live_entity->le_entity;
	rock			= live_entity->le_specific;
	rock_map_data	= (DESERT_FALLING_ROCK*)(entity + 1);
	find_entity		= NULL;

	// What is the Falling Rock doing.
	switch (rock->fr_state)
		{
		// ----------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_CHECKING:
			rock->fr_curr_time			= rock_map_data->fr_delay;
			rock->fr_state				= DES_C_ACTION_FALLING_ROCK_DELAY;					

			// Turn on shadow
			rock->fr_shadow->ef_flags 	&= ~(EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE);
			break;

		// ----------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_DELAY:
			// Falling Rock is waiting to move.
			if (rock->fr_curr_time-- == 0)
				{
				// Work out X & Z movement to aim for the first target in the list, which should hopefully
				// always be valid
				ENTSTRDesFallingRockCalculateInitialVelocity(live_entity, rock_map_data, rock);

				rock->fr_curr_time 	= rock_map_data->fr_targets[rock->fr_curr_bounces].fr_time;
				rock->fr_state		= DES_C_ACTION_FALLING_ROCK_TARGETS;

				// make static display
				for (i = 0; i < Game_total_viewports; i++)
					((MR_MESH_INST*)live_entity->le_api_insts[i])->mi_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;

				// Turn ON collision 
//				live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;

				// Turn on shadow
				rock->fr_shadow->ef_flags 	&= ~(EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE);
				}
			break;

		// ----------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_TARGETS:
			// Rock is falling towards the next target, previously calculated
			UpdateEntityWithVelocity(live_entity->le_entity, live_entity->le_lwtrans, &rock->fr_position, &rock->fr_velocity);
			live_entity->le_lwtrans->t[1] -= DES_ROCK_RADIUS;

			vec_z.vx = rock->fr_velocity.vx >> 16;
			vec_z.vy = rock->fr_velocity.vy >> 16;
			vec_z.vz = rock->fr_velocity.vz >> 16;
			MRNormaliseVEC(&vec_z, &vec_z);
			MROuterProduct12(&Game_y_axis_pos, &vec_z, &vec_x);
			MRNormaliseVEC(&vec_x, &vec_x);
			MROuterProduct12(&vec_z, &vec_x, &vec_y);
			WriteAxesAsMatrix(live_entity->le_lwtrans, &vec_x, &vec_y, &vec_z);

			rock->fr_rotation = (rock->fr_rotation - 0x60) & 0xfff;
			cos = rcos(rock->fr_rotation);
			sin = rsin(rock->fr_rotation);
			MRRot_matrix_X.m[1][1] =  cos;
			MRRot_matrix_X.m[1][2] = -sin;
			MRRot_matrix_X.m[2][1] =  sin;
			MRRot_matrix_X.m[2][2] =  cos;
			MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_X);

			// Check to see if Time has reached zero.
			if (rock->fr_curr_time-- <= 0)
				{
				// do we have any more bounced to process?
				if (++rock->fr_curr_bounces < rock_map_data->fr_num_bounces)
					{
					// Move to target for neatness
					rock->fr_position.vx = rock_map_data->fr_targets[rock->fr_curr_bounces - 1].fr_target.vx << 16;
					rock->fr_position.vz = rock_map_data->fr_targets[rock->fr_curr_bounces - 1].fr_target.vz << 16;

					// Work out new velocity
					ENTSTRDesFallingRockCalculateInitialVelocity(live_entity, rock_map_data, rock);

					rock->fr_curr_time = rock_map_data->fr_targets[rock->fr_curr_bounces].fr_time;

					// SFX of rock bouncing.
					PlaySoundDistance(live_entity, SFX_DES_ROCK_BOUNCE, 30);
					}
				else
					{
					// go into explode mode
					rock->fr_state = DES_C_ACTION_FALLING_ROCK_EXPLODE;

					PlaySoundDistance(live_entity, SFX_DES_ROCK_BREAK, 30);
					}
				}
			// Turn on shadow
			rock->fr_shadow->ef_flags 	&= ~(EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE);
			break;

		// ---------------------------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_EXPLODE:
			// Currently hardcoded, probably BAD  *Very bad, Caused me a problem!! $gr*
			mof	= Map_mof_ptrs[DES_FALL_ROCKROLL];		
			MR_ASSERT (mof);

			// Create and setup the animation (anim type indepedent you will note)
			if (mof->mm_flags & MR_MOF_FLIPBOOK)
				{
				rock->fr_anim_rock = MRAnimEnvFlipbookCreateWhole(mof, MR_OBJ_STATIC, (MR_FRAME*)(live_entity->le_lwtrans));
				MRAnimEnvFlipbookSetAction(rock->fr_anim_rock, 0);
				}
			else
				{
				rock->fr_anim_rock =  MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)mof, 0, MR_OBJ_STATIC, (MR_FRAME*)(live_entity->le_lwtrans));
				MRAnimEnvFlipbookSetAction(rock->fr_anim_rock, 0);
				}

			// Add environment to viewport(s)
			GameAddAnimEnvToViewports(rock->fr_anim_rock);

			// Reinit the matrix to make it look right
			MR_INIT_MAT(live_entity->le_lwtrans);

			// Make model no display
			for (i = 0; i < Game_total_viewports; i++)
				((MR_MESH_INST*)live_entity->le_api_insts[i])->mi_object->ob_flags |= MR_OBJ_NO_DISPLAY;

			rock->fr_state = DES_C_ACTION_FALLING_ROCK_EXPLODING;					

			// Turn OFF collision 
//			live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;

			// Turn off shadow
			rock->fr_shadow->ef_flags |= (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE);
			break;

		// ---------------------------------------------------------------------------------------------------------------------
		case DES_C_ACTION_FALLING_ROCK_EXPLODING:
			mof	= Map_mof_ptrs[DES_FALL_ROCKROLL];		
			MR_ASSERT (mof);

			// Create and setup the animation (anim type indepedent you will note)
			if (mof->mm_flags & MR_MOF_FLIPBOOK)
				{			
				env_flipbook = ((MR_ANIM_ENV*)rock->fr_anim_rock)->ae_extra.ae_extra_env_flipbook;
				if (env_flipbook->ae_cel_number < env_flipbook->ae_total_cels-1)
					return;
				}
			else
				{
				env_single = ((MR_ANIM_ENV*)rock->fr_anim_rock)->ae_extra.ae_extra_env_single;
				if (env_single->ae_cel_number < env_single->ae_total_cels-1)
					return;
				}

			// Once it has exploded, restart from the beginning. This may need to wait
			// for the animation to finish
			rock->fr_curr_time		= 0;		
			rock->fr_state			= DES_C_ACTION_FALLING_ROCK_DELAY;					
			rock->fr_curr_bounces	= 0;

			// Kill of animation environment
			MRAnimEnvDestroyByDisplay(((MR_ANIM_ENV*)rock->fr_anim_rock));
			rock->fr_anim_rock = NULL;

			// reset the position based on the supplied matrix...
			rock->fr_position.vx = rock_map_data->fr_matrix.t[0] << 16;
			rock->fr_position.vy = rock_map_data->fr_matrix.t[1] << 16;
			rock->fr_position.vz = rock_map_data->fr_matrix.t[2] << 16;
			
			MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)rock_map_data->fr_matrix.t);
			break;
		}
}


/******************************************************************************
*%%%% ENTSTRDesKillFallingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesKillFallingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a desert falling rock
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesKillFallingRock(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	DESERT_RT_FALLING_ROCK*	rock;

	entity			= live_entity->le_entity;
	rock			= live_entity->le_specific;

	// Kill off static mof
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
#ifdef MR_DEBUG
		live_entity->le_api_item0 = NULL;
#endif
		}

	// Kill off animated model if there is one
	if (rock->fr_anim_rock)
		{
		MRAnimEnvDestroyByDisplay(((MR_ANIM_ENV*)rock->fr_anim_rock));
		rock->fr_anim_rock = NULL;
		}

	// Kill shadow
	if (rock->fr_shadow)
		{
		// Kill Effect.
		rock->fr_shadow->ef_kill_timer = 2;		// Flag this for Kill.
		}
}




#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% ENTSTRDesCreateThermal
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateThermal(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a tumble weed for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	Martin Kift		Created
*	19.08.97	Gary Richards	Removed as they are not used.
*	04.11.23	Kneesnap		#ifdef'd out to match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesCreateThermal(LIVE_ENTITY*	live_entity)
{
//	DESERT_THERMAL*			thermal_map_data;
//	DESERT_RT_THERMAL*		thermal;
//	ENTITY*					entity;
//
//	entity 				= live_entity->le_entity;
//	thermal_map_data	= (DESERT_THERMAL*)(entity + 1);
//
//	// use standard path-based entity creation function
//	ENTSTRCreateMovingMOF(live_entity);
//
//	// the runtime structure has already been alloced
//	thermal = (DESERT_RT_THERMAL*)live_entity->le_specific;
//
//	// need to work out the required rotate (Y) speed
//	thermal->tw_rotate_step = (4096 / thermal_map_data->tw_rotate_time);
//
//	// setup rotation
//	MR_CLEAR_SVEC(&thermal->tw_rotation);
}

/******************************************************************************
*%%%% ENTSTRDesUpdateThermal
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateThermal(LIVE_ENTITY* live_entity)
*
*	FUNCTION	Update function for the thermal entity.
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		Moves along its spline as normal. If the frog jumps onto it,
*				it acts like a spining platform. If the frog jumps into the side
*				of the thermal, it grabs the frog, holds it for a second, and then
*				spits it out in a random direction for approximately two grids 
*				squares.

*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97 	Martin Kift		Rewrote and ported to new frogger
*	04.11.23	Kneesnap		#ifdef'd out to match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesUpdateThermal(LIVE_ENTITY* live_entity)
{
//	DESERT_THERMAL*		thermal_map_data;
//	DESERT_RT_THERMAL*	thermal;
//	ENTITY*				entity;
//
//	entity 				= live_entity->le_entity;
//	thermal_map_data	= (DESERT_THERMAL*)(entity + 1);
//	thermal				= (DESERT_RT_THERMAL*)live_entity->le_specific;
//
//	// update entity WRT path
//	ENTSTRUpdateMovingMOF(live_entity);
//
//	// spin the thermal at the required speed
//	if (NULL != live_entity->le_lwtrans)
//	{
//		thermal->tw_rotation.vy += thermal->tw_rotate_step;
//		thermal->tw_rotation.vy &= 4095;
//		MRRotMatrix(&thermal->tw_rotation, live_entity->le_lwtrans);
//	}
}
#endif

/******************************************************************************
*%%%% ENTSTRDesCreateSnake
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateSnake(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a snake for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesCreateSnake(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_SNAKE*	snake;

	// use standard path-based entity creation function
	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	snake = (DESERT_RT_SNAKE*)live_entity->le_specific;
	
	// clear the animation.
	snake->sn_request_anim 	 = FALSE;
	snake->sn_requested_anim = DES_ANIM_SNAKE_NORMAL;
	snake->sn_frame_count	 = 0;

	// Flag it as moving now turn has finished
	live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						
	// If entity is path based, UN-PAUSE it.
	if (live_entity->le_entity->en_path_runner)
		live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;

}

/******************************************************************************
*%%%% ENTSTRDesUpdateSnake
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateSnake(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the snake for the desert maps.
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		This has been change from script because of the changes in animations
*				require counts etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.06.97	Gary Richards	Create.
*	09.07.97	Martin Kift		Fixed code
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateSnake(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_SNAKE*		snake;
	MR_LONG					distance;

	// the runtime structure has already been alloced
	snake 		 			= (DESERT_RT_SNAKE*)live_entity->le_specific;

	ENTSTRUpdateMovingMOF(live_entity);
	
	distance = DistanceToFrogger(live_entity, ENTSCR_COORD_Z, 512);

	switch (LiveEntityGetAction(live_entity))
		{
		// -----------------------------------------------------------------------------------------
		case DES_ANIM_SNAKE_NORMAL:
			// Check if we are inside the rattle range.
			if (distance < DES_SNAKE_BITE_RANGE)
			{
				// We also need to check to make sure that the snake is facing Frogger.
				if ((abs(live_entity->le_lwtrans->m[0][2])) > (abs(live_entity->le_lwtrans->m[2][2])))
				{
				 	// Check to make sure Frogger is sitting in the same 'lane'
				 	if ((Frogs[0].fr_lwtrans->t[2] > (live_entity->le_lwtrans->t[2] - 64)) &&
				 	   (Frogs[0].fr_lwtrans->t[2] < (live_entity->le_lwtrans->t[2] + 64)))
				 	{
				 		snake->sn_request_anim = TRUE;					// We would like a new animations.
				 		snake->sn_requested_anim = DES_ANIM_SNAKE_BITE;	// Go with Bite.
				 	}
				 
				}
				else
				{
					// Check to make sure Frogger is sitting in the same 'lane'
					if ((Frogs[0].fr_lwtrans->t[0] > (live_entity->le_lwtrans->t[0] - 64)) &&
					   (Frogs[0].fr_lwtrans->t[0] < (live_entity->le_lwtrans->t[0] + 64)))
					{
						snake->sn_request_anim = TRUE;					// We would like a new animations.
						snake->sn_requested_anim = DES_ANIM_SNAKE_BITE;	// Go with Bite.
					}
				}
			}
			
			if ((distance > DES_SNAKE_BITE_RANGE) && (distance < DES_SNAKE_RATTLE_RANGE))
			{
				snake->sn_request_anim = TRUE;						// We would like a new animation.
				snake->sn_requested_anim = DES_ANIM_SNAKE_RATTLE;	// Go with Rattle.
			}
			break;
		// ------------------------------------------------------------------------------------------
		case DES_ANIM_SNAKE_RATTLE:
			// Are we inside the SNAKE BITE RANGE??
			if (distance < DES_SNAKE_BITE_RANGE)
			{
				// Play SFX when Snake bites.
				MRSNDPlaySound(SFX_DES_SNAKE_RATTLE, NULL, 0, 0);

				// We also need to check to make sure that the snake is facing Frogger.
				if ((abs(live_entity->le_lwtrans->m[0][2])) > (abs(live_entity->le_lwtrans->m[2][2])))
				{
				 	// Check to make sure Frogger is sitting in the same 'lane'
				 	if ((Frogs[0].fr_lwtrans->t[2] > (live_entity->le_lwtrans->t[2] - 64)) &&
				 	   (Frogs[0].fr_lwtrans->t[2] < (live_entity->le_lwtrans->t[2] + 64)))
				 	{
				 		snake->sn_request_anim = TRUE;					// We would like a new animations.
				 		snake->sn_requested_anim = DES_ANIM_SNAKE_BITE;	// Go with Bite.
				 	}
				 
				}
				else
				{
					// Check to make sure Frogger is sitting in the same 'lane'
					if ((Frogs[0].fr_lwtrans->t[0] > (live_entity->le_lwtrans->t[0] - 64)) &&
					   (Frogs[0].fr_lwtrans->t[0] < (live_entity->le_lwtrans->t[0] + 64)))
					{
						snake->sn_request_anim = TRUE;					// We would like a new animations.
						snake->sn_requested_anim = DES_ANIM_SNAKE_BITE;	// Go with Bite.
					}
				}
			}

			// Check to see if we are outside the rattle range.
			if (distance > DES_SNAKE_RATTLE_RANGE)
			{	
				snake->sn_request_anim = TRUE;						// We would like a new animation.
				snake->sn_requested_anim = DES_ANIM_SNAKE_NORMAL;	// Return to normal
			}
			else
			{
				// Still inside so check to see if we need another SFX>
				if (LiveEntityCheckAnimationFinished(live_entity))
				{
					// Trigger SFX when the anim resets.
					MRSNDPlaySound(SFX_DES_SNAKE_RATTLE, NULL, 0, 0);
				}
			}
			break;
		// ------------------------------------------------------------------------------------------
		case DES_ANIM_SNAKE_BITE:
			// Check to see if we are outside the bite range.
			if (distance > DES_SNAKE_BITE_RANGE)
			{	
				snake->sn_request_anim = TRUE;						// We would like a new animation.
				snake->sn_requested_anim = DES_ANIM_SNAKE_NORMAL;	// Return to normal
			}
			break;
		// ------------------------------------------------------------------------------------------
		case DES_ANIM_SNAKE_TURNING:
				// Go back to normal anim when turning finished
				if (snake->sn_frame_count == 0)
					{
					snake->sn_request_anim = TRUE;						// We would like a new animation.
					snake->sn_requested_anim = DES_ANIM_SNAKE_NORMAL;	// Return to normal

					// Flag it as moving now turn has finished
					live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						
					// If entity is path based, UN-PAUSE it.
					if (live_entity->le_entity->en_path_runner)
						live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
					}
				else
					snake->sn_frame_count--;
			break;
		// ------------------------------------------------------------------------------------------
		}

	// Check to see if we have got to the end of the spline.
	if  (
		(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_END) || 
		(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_START)
		)
			// If so, play animation of snake turning around.
			{
			// Must be done now, can't wait!
			MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0,DES_ANIM_SNAKE_TURNING);
			// Wait for this number of frames, before going back to a 'normal' move.
			snake->sn_frame_count	 = 19;
			// Flag it as no movement when turning.
			live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
						
			// If entity is path based, PAUSE it.
			if (live_entity->le_entity->en_path_runner)
				live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
			}

	// Check to see if we are waiting for a new anim.
	if (snake->sn_request_anim == TRUE)
	{
		// Wait for the current animation to finished before starting the new one.
		if (LiveEntityCheckAnimationFinished(live_entity))
		{
			// Change anim.
			LiveEntitySetAction(live_entity, snake->sn_requested_anim);
			snake->sn_request_anim = FALSE;
		}
	}
}

/******************************************************************************
*%%%% ENTSTRDesCreateVulture
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateVulture(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Vulture for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesCreateVulture(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_VULTURE*	vulture;

	// use standard path-based entity creation function
	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	vulture = (DESERT_RT_VULTURE*)live_entity->le_specific;
	
	// clear the animation.
	vulture->vu_request_anim   = FALSE;
	vulture->vu_requested_anim = DES_ANIM_VULTURE_NORMAL;
}

/******************************************************************************
*%%%% ENTSTRDesUpdateVulture
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateVulture(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the Vulture for the desert maps.
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		This has been change from script because of the changes in animations
*				require counts etc.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Gary Richards	Create.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateVulture(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_VULTURE*	vulture;
	ENTITY*				entity;
	PATH_RUNNER*		path_runner;
	MR_VEC				tan;

	// the runtime structure has already been alloced
	vulture 	 		= (DESERT_RT_VULTURE*)live_entity->le_specific;

	ENTSTRUpdateMovingMOF(live_entity);
	
	entity 		= live_entity->le_entity;
	path_runner = entity->en_path_runner;
	tan			= path_runner->pr_tangent;

	switch(vulture->vu_requested_anim)
		{
		// -------------------------------------------------------------------------
		case DES_ANIM_VULTURE_NORMAL:
			// Check the Y to see if we are diving.
			if (tan.vy > -128)
			{
			   vulture->vu_request_anim = TRUE;
			   vulture->vu_requested_anim = DES_ANIM_VULTURE_SWOOP;

				PlayMovingSound(live_entity, SFX_DES_VULTURE, 1024, 2048);
			}
			break;
		// -------------------------------------------------------------------------
		case DES_ANIM_VULTURE_SWOOP:
			// Check for Y going the other way.
			if (tan.vy < -128)
			{
				vulture->vu_request_anim = TRUE;
				vulture->vu_requested_anim = DES_ANIM_VULTURE_NORMAL;
			}
			break;
		// -------------------------------------------------------------------------
		}

	// Check to see if we are waiting for a new anim.
	if (vulture->vu_request_anim == TRUE)
	{
		// Wait for the current animation to finished before starting the new one.
		if (LiveEntityCheckAnimationFinished(live_entity))
		{
			// Change anim.
			LiveEntitySetAction(live_entity, vulture->vu_requested_anim);
			vulture->vu_request_anim = FALSE;
		}
	}
}


/******************************************************************************
*%%%% ENTSTRDesCreateCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateCrocHead(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a CrocHead for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesCreateCrocHead(LIVE_ENTITY*	live_entity)
{

	// Locals
	DES_RT_CROC_HEAD*		crochead_rt_ptr;

	// Use standard matrix-based entity creation function
	ENTSTRCreateDynamicMOF(live_entity);

	// Get pointer to runtime structre.  The runtime structure has already been alloced.
	crochead_rt_ptr = (DES_RT_CROC_HEAD*)live_entity->le_specific;

	// Initialise run time data, making head deadly
	crochead_rt_ptr->ch_rt_mode				= DES_CROCHEAD_PAUSE3;
	crochead_rt_ptr->ch_rt_start_position	= live_entity->le_lwtrans->t[1];
	crochead_rt_ptr->ch_rt_wait_count		= 0;
	crochead_rt_ptr->ch_rt_deadly			= TRUE;

	// Set up head animation as single shot
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

}

/******************************************************************************
*%%%% ENTSTRDesUpdateCrocHead
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateCrocHead(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the Croc Head for the desert maps.
*	MATCH		https://decomp.me/scratch/Phibl	(By Kneesnap)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	William Bell	Created.
*	23.06.97	William Bell	Added pause3.
*	21.08.97	Gary Richards	Added SFX.
*	04.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateCrocHead(LIVE_ENTITY*	live_entity)
{

	// Locals
	ENTITY*					entity;
	DES_CROC_HEAD*			crochead_ptr;
	DES_RT_CROC_HEAD*		crochead_rt_ptr;
	MR_ULONG				frog_id;

	// Get pointer to runtime structure
	entity 					= live_entity->le_entity;
	crochead_ptr			= (DES_CROC_HEAD*)(entity + 1);
	crochead_rt_ptr	 		= (DES_RT_CROC_HEAD*)live_entity->le_specific;

	// Depending on mode of operation do ...
	switch(crochead_rt_ptr->ch_rt_mode)
		{

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_PAUSE3:

			// Inc wait count
			crochead_rt_ptr->ch_rt_wait_count++;

			// Have we reached pause 3 time ?
			if ( crochead_rt_ptr->ch_rt_wait_count == crochead_ptr->ch_submerged_delay )
				{
				// Yes ... reset wait count
				crochead_rt_ptr->ch_rt_wait_count = 0;

				// Go on to rise
				crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_RISE;

				// Make head safe
				crochead_rt_ptr->ch_rt_deadly = FALSE;

				}

			break;

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_RISE:

			// Move crochead up
			live_entity->le_lwtrans->t[1] -= crochead_ptr->ch_rise_speed;

			// Have we reached top ?
			if ( live_entity->le_lwtrans->t[1] < (crochead_rt_ptr->ch_rt_start_position - crochead_ptr->ch_rise_height) )
				{
				// Yes ... set crochead to top position
				live_entity->le_lwtrans->t[1] = crochead_rt_ptr->ch_rt_start_position - crochead_ptr->ch_rise_height;
				// Reset wait count
				crochead_rt_ptr->ch_rt_wait_count = 0;
				// Go on to pause 1
				crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_PAUSE1;
				}

			break;

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_PAUSE1:

			// Inc wait count
			crochead_rt_ptr->ch_rt_wait_count++;

			// Have we reached pause 1 time ?
			if ( crochead_rt_ptr->ch_rt_wait_count == crochead_ptr->ch_snap_delay )
				{
				// Yes ... should we snap ?
				if ( crochead_ptr->ch_snap_or_not_to_snap == 1 )
					{
					// Yes ... reset wait count
					crochead_rt_ptr->ch_rt_wait_count = 0;
					// Go on to snap
					crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_SNAP;
					// Make head deadly
					crochead_rt_ptr->ch_rt_deadly = TRUE;
					}
				else
					{
					// No ... reset wait count
					crochead_rt_ptr->ch_rt_wait_count = 0;
					// Go on to pause 2
					crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_PAUSE2;
					}
				}
			break;

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_SNAP:

			// Inc wait count
			crochead_rt_ptr->ch_rt_wait_count++;

			// Is wait count 1 ?
			if ( crochead_rt_ptr->ch_rt_wait_count == 1 )
				{
				// Yes ... trigger snap animation
				MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, 0);
				}

			// Have we reached end of animation yet ?
			if ( crochead_rt_ptr->ch_rt_wait_count == 10 )
				{
				// Yes ... reset wait count
				crochead_rt_ptr->ch_rt_wait_count = 0;

				// Go on to pause 2
				crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_PAUSE2;

				// Make head safe
				crochead_rt_ptr->ch_rt_deadly = FALSE;
				
				// Make SFX of mouth snapping shut.
				if (!live_entity->le_moving_sound)
					PlayMovingSound(live_entity, SFX_DES_CROCODILE_SNAP, 512, 1536);
				}

			break;

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_PAUSE2:

			// Inc wait count
			crochead_rt_ptr->ch_rt_wait_count++;

			// Have we reached pause 2 time ?
			if ( crochead_rt_ptr->ch_rt_wait_count == crochead_ptr->ch_pause_delay )
				{
				// Yes ... reset wait count
				crochead_rt_ptr->ch_rt_wait_count = 0;

				// Go on to fall
				crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_FALL;
				}

			break;

		// -------------------------------------------------------------------------
		case DES_CROCHEAD_FALL:

			// Move crochead down
			live_entity->le_lwtrans->t[1] += crochead_ptr->ch_rise_speed;

			// Have we reached bottom ?
			if ( live_entity->le_lwtrans->t[1] > crochead_rt_ptr->ch_rt_start_position )
			{
				// Yes ... go back to waiting to rise
				crochead_rt_ptr->ch_rt_mode = DES_CROCHEAD_PAUSE3;
				// Make head deadly
				crochead_rt_ptr->ch_rt_deadly = TRUE;
			}

			break;

		}

	// Is croc head deadly ?
	if ( crochead_rt_ptr->ch_rt_deadly == TRUE )
		{
		// Yes ... is croc head carrying any frogs ?
		if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
			{
			// Yes ... loop once for each frog
			frog_id = 0;
			while (frog_id < 4)
				{
				// Is croc head carrying this frog ?
				if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_id))
					{
					// Yes ... kill frog
					FrogKill(&Frogs[frog_id],FROG_ANIMATION_BITTEN, NULL);
					MRSNDPlaySound(SFX_DES_FROG_CROC_MUNCH, NULL, 0, 0);
					}
				// Next frog
				frog_id++;
				}
			}
		}

}


/******************************************************************************
*%%%% ENTSTRDesCreateCrack
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateCrack(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Crack for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.06.97	Gary Richards	Created
*	12.07.97	Martin Kift		Fixed updating code
*
*%%%**************************************************************************/

MR_VOID ENTSTRDesCreateCrack(LIVE_ENTITY*	live_entity)
{
	DES_RT_CRACK*			rt_crack;
	MR_MESH*				mesh;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;

	// Use standard matrix-based entity creation function
	ENTSTRCreateDynamicMOF(live_entity);

	// Get pointer to runtime structre.  The runtime structure has already been alloced.
	rt_crack = (DES_RT_CRACK*)live_entity->le_specific;

	// Initialise run time data
	rt_crack->cr_state		  	= DES_CRACK_WAITING_FOR_HITS;
	rt_crack->cr_current_wait 	= 0;
	rt_crack->cr_num_hits	  	= 0;
	rt_crack->cr_vel_y			= 0;

	// Probably need to set the animation in here somewhere as well.
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK);
	env_flip		= ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
	mesh			= env_flip->ae_object->ob_extra.ob_extra_mesh;

	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;
	LiveEntitySetCel(live_entity, 0); 

	// turn on collision for this entity
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
}

/******************************************************************************
*%%%% ENTSTRDesUpdateCrack
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateCrack(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the Crack for the desert maps.
*	MATCH		https://decomp.me/scratch/mbAEZ	(By Kneesnap)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.06.97	Gary Richards	Created.
*	12.07.97	Martin Kift		Added Updating code
*	04.11.23	Kneesnap		Byte-matched function to PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateCrack(LIVE_ENTITY*	live_entity)
{
	// Locals
	ENTITY*	  				entity;
	DES_CRACK*				crack_ptr;
	DES_RT_CRACK*			crack_rt_ptr;
	MR_ANIM_ENV*			env;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_MESH*				mesh;
	MR_MESH_ANIMATED_POLY*	anim_poly;
	MR_LONG					num;
	FROG*					frog;
	MR_ULONG				frog_index;
	MR_LONG					col;

	// Get pointer to runtime structure
	entity 			= live_entity->le_entity;
	crack_ptr		= (DES_CRACK*)(entity + 1);
	crack_rt_ptr	= (DES_RT_CRACK*)live_entity->le_specific;

	env			= (MR_ANIM_ENV*)live_entity->le_api_item0;
	env_flip	= env->ae_extra.ae_extra_env_flipbook;
	mesh		= env_flip->ae_object->ob_extra.ob_extra_mesh;

	// Depending on mode of operation do ...
	switch(crack_rt_ptr->cr_state)
		{
		// -------------------------------------------------------------------------
		case DES_CRACK_WAITING_FOR_HITS:
			// Waiting for a hit from Frogger.
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				anim_poly = mesh->me_animated_polys;
				for ( num = 0; num < mesh->me_num_animated_polys; num++ ) 
				{
					anim_poly->ma_animlist_entry = (DES_CRACK_NUM_ANIM_TEXTURES - 
												   (crack_ptr->cr_hops_before - crack_rt_ptr->cr_num_hits));
					anim_poly++;
				}
				// We have just been hit by the Frog, increase number of hits received.
				crack_rt_ptr->cr_num_hits++;

				// Play SFX when hit. 
				MRSNDPlaySound(SFX_DES_CRACK, NULL, 0, 0);


				// We we arn't passed our limit.
				if ( crack_rt_ptr->cr_num_hits >= crack_ptr->cr_hops_before )
					{
					// Best we start falling.
					crack_rt_ptr->cr_current_wait = 2;
					crack_rt_ptr->cr_state = DES_CRACK_WAITING_TO_FALL;
					}
				}
			break;
		// -------------------------------------------------------------------------
		case DES_CRACK_WAITING_TO_FALL:
			crack_rt_ptr->cr_current_wait--;
		
			// Start fall sound/anim a little before we drop the frog
			if (crack_rt_ptr->cr_current_wait)
				{
				// Turn on anims
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= (MR_ANIM_ENV_STEP|MR_ANIM_ENV_ONE_SHOT);

				// Make SFX for falling .
				PlaySoundDistance(live_entity, SFX_DES_HOLE01, 30);
				
				// Start crack falling
				crack_rt_ptr->cr_state 	= DES_CRACK_FALLING;
				crack_rt_ptr->cr_y		= live_entity->le_lwtrans->t[1] << 16;
				}
			break;
		// -------------------------------------------------------------------------
		// This really should be opening, but we don't have the animations for it yet.
		case DES_CRACK_FALLING:
			if (LiveEntityCheckAnimationFinished(live_entity) == FALSE)
				break;
			
			if (crack_rt_ptr->cr_current_wait > 0) 
				{
				if (!(--crack_rt_ptr->cr_current_wait))
					{
					// turn off collision for this entity
					live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;
	
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
				}
			else
				{
				crack_rt_ptr->cr_vel_y += (SYSTEM_GRAVITY * 5) / 4;
				if (live_entity->le_lwtrans->t[1] < 1024)
					{
					crack_rt_ptr->cr_y 				+= crack_rt_ptr->cr_vel_y;
					live_entity->le_lwtrans->t[1] 	= crack_rt_ptr->cr_y >> 16;
					}
				else
					crack_rt_ptr->cr_state = DES_CRACK_FINISHED;
				}
			live_entity->le_flags |= LIVE_ENTITY_NO_SCREEN_FADE;
			col = MAX(0, (crack_ptr->cr_matrix.t[1] - live_entity->le_lwtrans->t[1] >> 3) + 0x80);
			SetLiveEntityScaleColours(live_entity, col, col, col);
			break;
		// -------------------------------------------------------------------------
		}

}

/******************************************************************************
*%%%% ENTSTRDesFallingRockCalculateInitialVelocity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesFallingRockCalculateInitialVelocity(
*						LIVE_ENTITY*			live_entity,
*						DESERT_FALLING_ROCK*	rock_map_data,
* 						DESERT_RT_FALLING_ROCK*	rock)
*
*	FUNCTION	Used to calculate initial velocity for falling objects under gravity.
*
*	INPUTS		live_entity		-	ptr to LIVE_ENTITY
*				rock_map_data	-	map data for entity
*				rock			-	runtime data
*
*	NOTES		These are the mechanical functions used to do the calcs:
*				s 	= ut + 1/2at^2
*				u  	= (s - 1/2at^2)/t
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Ported from old frogger code (written by Gary)
*	07.07.97	Tim Closs		Removed from entity.c and revised inputs
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesFallingRockCalculateInitialVelocity(	LIVE_ENTITY*			live_entity,
														DESERT_FALLING_ROCK*	rock_map_data,
														DESERT_RT_FALLING_ROCK*	rock)
{
	MR_SVEC*	dest_pos;
	MR_VEC*		position;
	MR_LONG		t;


	dest_pos 				= &rock_map_data->fr_targets[rock->fr_curr_bounces].fr_target;
	position				= &rock->fr_position;
	t						= rock_map_data->fr_targets[rock->fr_curr_bounces].fr_time;
		
	rock->fr_velocity.vx 	= ((dest_pos->vx << 16) - position->vx) / t;
	rock->fr_velocity.vz 	= ((dest_pos->vz << 16) - position->vz) / t;
	rock->fr_velocity.vy 	= (((dest_pos->vy << 16) - position->vy) / t) - (WORLD_GRAVITY * (t>>1));
}


/******************************************************************************
*%%%% ENTSTRDesCreateRollingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateRollingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a rolling rock fo desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesCreateRollingRock(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_ROLLING_ROCK*			rock;
	
	// Create the entity using standard function
	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	rock				= (DESERT_RT_ROLLING_ROCK*)live_entity->le_specific;
	rock->rr_anim_rock	= NULL;		
	rock->rr_mode		= DES_ROLLING_ROCK_ROLLING;
	rock->rr_rotation	= 0;

	// init the matrix to make it look right
	MR_INIT_MAT(&rock->rr_matrix);

	// Turn on collision (this applies to ALL rolling rocks)
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
}


/******************************************************************************
*%%%% ENTSTRDesUpdateRollingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateRollingRock(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the rolling rock for the desert maps.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*	12.07.97	Martin Kift		Fixed rotation code
*	11.08.97	Gary Richards	Change model to number 25 and made it an equate.
*								If the position within buildwad changes, this
*								must also been changed to tie-up.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateRollingRock(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_ROLLING_ROCK*		rock;
	ENTITY*						entity;
	MR_MOF*						mof;
	MR_ULONG					i;
	MR_ANIM_ENV_FLIPBOOK*		env_flipbook;
	MR_ANIM_ENV_SINGLE*			env_single;
	MR_LONG						cos, sin;

	entity	= live_entity->le_entity;
	rock	= live_entity->le_specific;

	ENTSTRUpdateMovingMOF(live_entity);

	switch (rock->rr_mode)
		{
		case DES_ROLLING_ROCK_ROLLING:
			// Roll rock
			rock->rr_rotation = (rock->rr_rotation - 0x40) & 0xfff;
			cos = rcos(rock->rr_rotation);
			sin = rsin(rock->rr_rotation);
			MRRot_matrix_X.m[1][1] =  cos;
			MRRot_matrix_X.m[1][2] = -sin;
			MRRot_matrix_X.m[2][1] =  sin;
			MRRot_matrix_X.m[2][2] =  cos;
			MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_X);

			// Have we reached end of path?
			MR_ASSERT (live_entity->le_entity->en_path_runner);

			if  (
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_START) || 
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_END)
				)
				{
				rock->rr_mode = DES_ROLLING_ROCK_EXPLODING;

				// Currently hardcoded, probably BAD. *VERY BAD ! Caused me problems !! *$gr
				mof	= Map_mof_ptrs[DES_FALL_ROCKROLL];		
				MR_ASSERT (mof);

				// Create and setup the animation (anim type indepedent you will note)
				if (mof->mm_flags & MR_MOF_FLIPBOOK)
					{
					rock->rr_anim_rock = MRAnimEnvFlipbookCreateWhole(mof, MR_OBJ_STATIC, (MR_FRAME*)&rock->rr_matrix);
					MRAnimEnvFlipbookSetAction(rock->rr_anim_rock, 0);
					}
				else
					{
					rock->rr_anim_rock =  MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)mof, 0, MR_OBJ_STATIC, (MR_FRAME*)&rock->rr_matrix);
					MRAnimEnvFlipbookSetAction(rock->rr_anim_rock, 0);
					}

				// Pause path runner
				live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;

				// Add environment to viewport(s)
				GameAddAnimEnvToViewports(rock->rr_anim_rock);

				// Turn OFF collision 
				live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;

				// Make model no display
				for (i = 0; i < Game_total_viewports; i++)
					((MR_MESH_INST*)live_entity->le_api_insts[i])->mi_object->ob_flags |= MR_OBJ_NO_DISPLAY;
				}
			else
				MR_COPY_VEC((MR_VEC*)rock->rr_matrix.t, (MR_VEC*)live_entity->le_lwtrans->t);
			break;

		// ---------------------------------------------------------------------------------------------------------------------
		case DES_ROLLING_ROCK_EXPLODING:
			mof	= Map_mof_ptrs[DES_FALL_ROCKROLL];		
			MR_ASSERT (mof);

			// Create and setup the animation (anim type indepedent you will note)
			if (mof->mm_flags & MR_MOF_FLIPBOOK)
				{			
				env_flipbook = ((MR_ANIM_ENV*)rock->rr_anim_rock)->ae_extra.ae_extra_env_flipbook;
				if (env_flipbook->ae_cel_number < env_flipbook->ae_total_cels-1)
					return;
				}
			else
				{
				env_single = ((MR_ANIM_ENV*)rock->rr_anim_rock)->ae_extra.ae_extra_env_single;
				if (env_single->ae_cel_number < env_single->ae_total_cels-1)
					return;
				}

			// Once it has exploded, restart from the beginning. This may need to wait
			// for the animation to finish
			rock->rr_mode		= DES_ROLLING_ROCK_ROLLING;					
			rock->rr_rotation	= 0;

			// Kill of animation environment
			MRAnimEnvDestroyByDisplay(((MR_ANIM_ENV*)rock->rr_anim_rock));
			rock->rr_anim_rock = NULL;

			// UNPause path runner
			live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;

			// Turn OFF collision 
			live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;

			// make static display
			for (i = 0; i < Game_total_viewports; i++)
				((MR_MESH_INST*)live_entity->le_api_insts[i])->mi_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;

			break;
		}
}


/******************************************************************************
*%%%% ENTSTRDesKillRollingRock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesKillRollingRock(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a desert rolling rock
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesKillRollingRock(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_ROLLING_ROCK*	rock;

	rock = live_entity->le_specific;

	// Kill off static mof
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
#ifdef MR_DEBUG
		live_entity->le_api_item0 = NULL;
#endif
		}

	// Kill off animated model if there is one
	if (rock->rr_anim_rock)
		{
		MRAnimEnvDestroyByDisplay(((MR_ANIM_ENV*)rock->rr_anim_rock));
		rock->rr_anim_rock = NULL;
		}
}

/******************************************************************************
*%%%% ENTSTRDesCreateTumbleWeed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesCreateTumbleWeed(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a tumble weed for desert level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Martin Kift		Created
*	22.08.97	Gary Richrds	Added SFX.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesCreateTumbleWeed(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_TUMBLE_WEED*	weed;
	
	// Create the entity using standard function
	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	weed				= (DESERT_RT_TUMBLE_WEED*)live_entity->le_specific;
	weed->tw_rotation	= 0;
	weed->tw_count		= 0;		
	
	MR_CLEAR_VEC(&weed->tw_velocity);

	// Create shadow (turned off)
	weed->tw_shadow	= CreateShadow(&im_gen_shadow, live_entity->le_lwtrans, Des_rock_shadow_offsets);
	weed->tw_shadow	->ef_flags	|= (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE | EFFECT_NO_ROTATION);

	if (live_entity->le_moving_sound == NULL)
		{
		// Play SFX of the tumble weed rolling. 
		PlayMovingSound(live_entity, SFX_DES_TUMBLEWEED, 512, 1024);
		}
}


/******************************************************************************
*%%%% ENTSTRDesUpdateTumbleWeed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesUpdateTumbleWeed(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the tumble weed for the desert maps.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesUpdateTumbleWeed(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_TUMBLE_WEED*		weed;
	MR_LONG						cos, sin;
	MR_LONG						x, z;

	// get runtime ptr
	weed	= live_entity->le_specific;

	// call standard update
	ENTSTRUpdateMovingMOF(live_entity);

	// Turn off shadow if its off map
	x = GET_GRID_X_FROM_WORLD_X(live_entity->le_lwtrans->t[0]);
	z = GET_GRID_Z_FROM_WORLD_Z(live_entity->le_lwtrans->t[2]);
	if	(
		(x < 1) ||
		(x >= (Grid_xnum-1)) ||
		(z < 1) ||
		(z >= (Grid_znum-1))
		)
		{
		weed->tw_shadow->ef_flags	|= (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE | EFFECT_NO_ROTATION);
		}
	else
		{
		weed->tw_shadow->ef_flags	&= ~(EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE | EFFECT_NO_ROTATION);
		}

	// Roll the tumble weed
	weed->tw_rotation = (weed->tw_rotation - 0x60) & 0xfff;
	cos = rcos(weed->tw_rotation);
	sin = rsin(weed->tw_rotation);
	MRRot_matrix_X.m[1][1] =  cos;
	MRRot_matrix_X.m[1][2] = -sin;
	MRRot_matrix_X.m[2][1] =  sin;
	MRRot_matrix_X.m[2][2] =  cos;
	MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_X);

	// Has the count reached zero? If so, recalc velocity
	if (!(weed->tw_count--))
		{
		// Calculate a random number of frames, between 6 and 10.
		weed->tw_count = rand()%4 + 6;

		// Calculate jumping velocity based on frame count for jump (assume we end up at same height)
		weed->tw_velocity.vy = -((SYSTEM_GRAVITY * (weed->tw_count + 1)) >> 1);

		// get height
		weed->tw_height = live_entity->le_lwtrans->t[1];
		}
	else
		{
		// Add velocity
		weed->tw_velocity.vy += SYSTEM_GRAVITY;
		weed->tw_height += (weed->tw_velocity.vy >> 16);
		live_entity->le_lwtrans->t[1] = weed->tw_height;
		}
}


/******************************************************************************
*%%%% ENTSTRDesKillTumbleWeed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRDesKillTumbleWeed(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a tumble weed
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRDesKillTumbleWeed(LIVE_ENTITY*	live_entity)
{
	DESERT_RT_TUMBLE_WEED*	weed;

	weed = live_entity->le_specific;

	// Kill off static mof
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
#ifdef MR_DEBUG
		live_entity->le_api_item0 = NULL;
#endif
		}

	// Kill shadow
	if (weed->tw_shadow)
		{
		// Kill Effect.
		weed->tw_shadow->ef_kill_timer = 2;		// Flag this for Kill.
		}
}
