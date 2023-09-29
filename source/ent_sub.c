/******************************************************************************
*%%%% ent_sub.c
*------------------------------------------------------------------------------
*
*	Suburbia Create/Update/Kill Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.11.96	Gary Richards	Created
*	04.12.96	Martin Kift 	Changed for new API
*	19.02.97	Martin Kift		Removed most passing of pFrame's in create functions
*	24.04.97	Gary Richards	Added to the new Frogger code.
*	25.04.97	Martin Kift		Added to crocodile, snake code etc.
*	06.05.97	Martin Kift		Moved about everything to scripts
*
*%%%**************************************************************************/

#include "ent_sub.h"
#include "scripter.h"
#include "scripts.h"
#include "sound.h"
#include "gamesys.h"
#include "sub_snak.h"
#include "sub_turt.h"
#include "frog.h"
#include "entlib.h"

/******************************************************************************
*%%%% ENTSTRSubCreateTurtle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubCreateTurtle(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a turtle
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubCreateTurtle(LIVE_ENTITY*	live_entity)
{
	SUBURBIA_TURTLE*	turtle;
	ENTITY*				entity;

	entity	= live_entity->le_entity;
	turtle	= (SUBURBIA_TURTLE*)(entity + 1);

	ENTSTRCreateMovingMOF(live_entity);

	// if not a diving type, revert to the non diving script
	if (turtle->st_turtle_type == SUB_TURTLE_NOTDIVING)
		StartScript((SCRIPT_INFO*)live_entity->le_script, SCRIPT_TURTLE_NO_DIVE, live_entity);
}

//------------------------------------------------------------------------------------------------
// Scripts
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBDiveColourChange(LIVE_ENTITY* live_entity)
{
	MR_LONG				height;
	MR_LONG				path_height;
	MR_LONG				col_r, col_g, col_b;
	MR_LONG				frog_id;
	ENTSTR_STATIC*		entity_type;

	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		// Check to see if this *IS* a path runner.
		if (live_entity->le_entity->en_path_runner)
			{
			// If the entity is going off screen, then don't set the no-screen-fade
			// flag, since this overrides the fade to black code. In fact, if offscreen
			// don't really bother doing any colour stuff at all
			if 	(
				(live_entity->le_lwtrans->t[0] < Fade_top_left_pos.vx) ||
				(live_entity->le_lwtrans->t[0] > Fade_bottom_right_pos.vx) ||
				(live_entity->le_lwtrans->t[2] < Fade_bottom_right_pos.vz) ||
				(live_entity->le_lwtrans->t[2] > Fade_top_left_pos.vz)
				)
				{
				live_entity->le_flags &= ~(LIVE_ENTITY_NO_SCREEN_FADE);
				}
			else
				{
				live_entity->le_flags |= (LIVE_ENTITY_NO_SCREEN_FADE);

				// Find the distance from the path in Y.
				path_height = live_entity->le_entity->en_path_runner->pr_position.vy;
				height 		= path_height - live_entity->le_lwtrans->t[1];
				
				// THIS ALWAYS ASSUME THE TURTLE DIVE DEPTH IS -128 $gr.
				col_r	= 0x80 + (height);			// Decrease the Red. (Neg is into the map)
				col_g	= 0x80 + (height >> 1);		// Decrease the Green. (Only halve the green)
				col_b	= 0x80 - (height + 1 );	 	// Increase the Blue.

				// Ensure fade code respects the values we have set
				SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
				SetLiveEntityCustomAmbient(live_entity, 0x40, 0x40, 0xc0);
				}

			// If turtle has reached max depth (hard coded value) then kill any safe frog
			// Look at whether we have a safe frog, and kill it if we are below certain depth
			if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
				{
				if ((live_entity->le_lwtrans->t[1] - live_entity->le_entity->en_path_runner->pr_position.vy) >= 0x80)
					{				
					frog_id = 0;
					while (frog_id < 4)
						{
						if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_id))
							{
							FrogKill(&Frogs[frog_id], FROG_ANIMATION_DROWN, NULL);
							live_entity->le_flags &= ~(LIVE_ENTITY_CARRIES_FROG_0 << frog_id);
							}
						frog_id++;
						}
					}
				}
			}
		else
			{
			// It must be a static, so use it as a static.
			entity_type	= (ENTSTR_STATIC*)(live_entity->le_entity + 1);
			height	= live_entity->le_lwtrans->t[1]-entity_type->et_matrix.t[1];
			height  >>= 2;
			col_r	= MAX(0, 0x40 - (height));
			col_g	= MAX(0, 0x40 - (height));
			col_b	= MAX(0, 0x60 - (height));
		
			live_entity->le_flags |= (LIVE_ENTITY_NO_SCREEN_FADE);
			SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
			SetLiveEntityCustomAmbient(live_entity, 0x20, 0xf0, 0xa0);
			}
		}
}

/******************************************************************************
*%%%% ENTSTRSubCreateDog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubCreateDog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Dog
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubCreateDog(LIVE_ENTITY*	live_entity)
{
	SUBURBIA_DOG*		dog_map_data;
	SUBURBIA_RT_DOG*	dog;
	ENTITY*				entity;

	entity			= live_entity->le_entity;
	dog_map_data 	= (SUBURBIA_DOG*)(entity + 1);

	ENTSTRCreateMovingMOF(live_entity);

	// the runtime structure has already been alloced
	dog = (SUBURBIA_RT_DOG*)live_entity->le_specific;

	// Set specific data.
	dog->do_state 		 = SUB_DOG_WAITING;
	dog->do_current_wait = dog_map_data->do_wait_delay;
	// Stop the path runner from moving.
	entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;                  
}


/******************************************************************************
*%%%% ENTSTRSubUpdateDog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubUpdateDog(LIVE_ENTITY* live_entity)
*
*	FUNCTION	Update function for the dog
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Gary Richards	Created
*	23.07.97	William Bell	Add bite animation
*
*%%%**************************************************************************/

MR_VOID ENTSTRSubUpdateDog(LIVE_ENTITY* live_entity)
{

	// Locals
	SUBURBIA_DOG*		dog_map_data;
	SUBURBIA_RT_DOG*	dog;
	ENTITY*				entity;
	MR_SVEC				pos;				// Position of frog from dog
	MR_SVEC				rot;				// Rotation of frog in dog mouth
	MR_MAT				mat;				// Orientation of frog in dog mouth
	MR_ULONG			loop_counter;		// Temp loop count

	// Set up pointers
	entity 			= live_entity->le_entity;
	dog_map_data	= (SUBURBIA_DOG*)(entity + 1);
	dog				= (SUBURBIA_RT_DOG*)live_entity->le_specific;

	// According to dog mode do ...
	switch(dog->do_state)
		{
		// ---------------------------------------------
		case SUB_DOG_WAITING:

			// End of wait ?
			if (dog->do_current_wait-- == 0)
				{
				// Yes ... set off down the path.
				dog->do_state = SUB_DOG_WALKING;
				entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
				// Bark before moving ?
				if ( DistanceToFrogger(live_entity,0,0)  < SUB_DOG_BARK_DISTANCE)
					// Yes ... play sound effect
			 		MRSNDPlaySound(SFX_SUB_DOG_BARK, NULL, 0, 0);
				}

			break;
		// ---------------------------------------------
		case SUB_DOG_WALKING:

			// Have we reached the (other) end of the path ?
			if (entity->en_path_runner->pr_flags & (PATH_RUNNER_JUST_BOUNCED_END | PATH_RUNNER_JUST_BOUNCED_START) )
				{
				// Yes ... go back to waiting
				dog->do_state 		 = SUB_DOG_WAITING;
				dog->do_current_wait = dog_map_data->do_wait_delay;
				// Stop the path runner from moving.
				entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;                  
				}

			// Fall over ?
			if ( rand()%500 == 1 )
				{
				// Yes ... pause dog
				entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
				// Trigger fall over
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, 1);
				// Reset pause count
				dog->do_current_wait = 50;
				// Go on to fall over anim
				dog->do_state		= SUB_DOG_FALLING;
				}

			// Has dog hit a frog ?
			if ( live_entity->le_flags & LIVE_ENTITY_HIT_FROG )
				{
				// Yes ... stop dog moving
				entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
				// Start biting animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, 2);
				// Go on to biting
				dog->do_state		= SUB_DOG_BITING;
				}

			break;
		// ---------------------------------------------
		case SUB_DOG_FALLING:

			// End of animation ?
			if ( !--dog->do_current_wait )
				{
				// Yes ... unpause dog
				entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
				// Start run animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, 0);
				// Go back to walking
				dog->do_state			= SUB_DOG_WALKING;
				}

			// Has dog hit a frog ?
			if ( live_entity->le_flags & LIVE_ENTITY_HIT_FROG )
				{
				// Yes ... stop dog moving
				entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
				// Start biting animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, 2);
				// Go on to biting
				dog->do_state		= SUB_DOG_BITING;
				}

			break;
		// ---------------------------------------------
		}


	// Are we being biten ?
	if ( dog->do_state == SUB_DOG_BITING )
		{
		// Yes ... has dog just hit a frog ?
		if ( live_entity->le_flags & LIVE_ENTITY_HIT_FROG )
			{
			// Yes ... set up bite count
			dog->do_bite_count = 50;

			// Set up position of frog
			pos.vx = 0;
			pos.vy = 0;
			pos.vz = 128+64;
			// Apply dog rotation
			MRApplyMatrixSVEC(live_entity->le_lwtrans,&pos,&pos);

			// Set up temp rotation for frog
			rot.vx = 0;
			rot.vy = 1024;
			rot.vz = 0;
			MRRotMatrix(&rot,&mat);

			// Yes ... play sound effect of dog biting
	 		MRSNDPlaySound(SFX_SUB_DOG_EAT, NULL, 0, 0);

			// Yes ... loop once for each dog
			for(loop_counter=0;loop_counter<4;loop_counter++)
				{
				// Is dog hiting this frog ?
				if ( live_entity->le_flags & (LIVE_ENTITY_HIT_FROG_0<<loop_counter) )
					{
					// Yes .... set frog position to offset plus dog position
					Frogs[loop_counter].fr_lwtrans->t[0] = pos.vx + live_entity->le_lwtrans->t[0];
					Frogs[loop_counter].fr_lwtrans->t[1] = pos.vy + live_entity->le_lwtrans->t[1];
					Frogs[loop_counter].fr_lwtrans->t[2] = pos.vz + live_entity->le_lwtrans->t[2];

					// Multiply matrices
					MRMulMatrixABC(live_entity->le_lwtrans,&mat,Frogs[loop_counter].fr_lwtrans);
					}
				}
			}
		else
			{
			// No ... still biting ?
			if ( !--dog->do_bite_count )
				{
				// No ... go back to walking
				dog->do_state		= SUB_DOG_WALKING;
				// Unpause entity
				entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
				// Start run animation
				MRAnimEnvSingleSetAction(live_entity->le_api_item0, 0);
				}
			}
		}


	// Update entity along path
	ENTSTRUpdateMovingMOF(live_entity);

}

// ------------------------------------------------------------------------------------------------------------------

// Wait to randomly trigger the Car Noise.
MR_LONG		script_sub_car_blue[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_SUB_CAR_BLUE_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,

									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_ROAD_NOISE,	// MIN	MAX.
									ENTSCR_NO_REGISTERS,	512, 1024,
															// Min, Max	  Speed,  Range,
	ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	48,		84,		3,		7,	64,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_car_blue_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_SUB_CAR_HORN02,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the truck Noise.
MR_LONG		script_sub_truck[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_SUB_TRUCK_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_truck_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_SUB_LORRY_HORN01,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//

//------------------------------------------------------------------------------------------------
//

// Wait to randomly trigger the lorry Noise.
MR_LONG		script_sub_lorry[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_SUB_LORRY_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_lorry_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_SUB_LORRY_HORN02,
										ENTSCR_COORD_Z,  		   384,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Sub Lawn Mower
//
// Play's a Sound Effect when killing Frogger.
//

MR_LONG		script_sub_lawn_mower[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_HIT_FROG,		SCRIPT_SUB_LAWN_MOWER_KILL_FROGGER,		0,
	
		ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_MOWER,		
										ENTSCR_NO_REGISTERS,	512,		1536,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_lawn_mower_kill_frogger[] =
	{
	ENTSCR_PLAY_SOUND,					SFX_SUB_FROG_MOWED,
	ENTSCR_END,
	};

MR_LONG		script_sub_swan[] =
	{
	// No SFX for this..... yet.
	//ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,		SCRIPT_CB_FROG_TRAFFIC_SPLAT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_SUB_SWAN_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_swan_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_SUB_SWAN_CALL,
										ENTSCR_COORD_Z,  		   256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Sub lilly pad
//
// It rotates round in circles
//

MR_LONG		script_sub_lilly_pad[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SUB_LILLY_PAD,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	ENTSCR_SETLOOP,
		ENTSCR_ROTATE,				ENTSCR_COORD_Y,				0x1000,		0x20,	-1,
		ENTSCR_WAIT_UNTIL_ROTATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSubLillyPad(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_GEN_FROG_SPLASH1, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// SUB snake
//
MR_LONG		script_sub_snake[] =
	{
	ENTSCR_SET_ACTION,					SUB_SNAKE_SLITHER,
	ENTSCR_SETLOOP,
										// SFX										   
		ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_SNAKE_HISS,		//  MIN		MAX.
										ENTSCR_NO_REGISTERS,	512,		768,
		ENTSCR_SCRIPT_IF,				ENTSCR_GOSUB_SCRIPT,		ENTSCR_END_OF_PATH,		SCRIPT_SUB_SNAKE_TURN,	0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sub_snake_turn[] = 
	{
	ENTSCR_PAUSE_ENTITY_ON_PATH,
	ENTSCR_SET_ACTION,					SUB_SNAKE_TURN,
	ENTSCR_WAIT_UNTIL_ACTION_FINISHED,
	ENTSCR_SET_ACTION,					SUB_SNAKE_SLITHER,
	ENTSCR_UNPAUSE_ENTITY_ON_PATH,
	ENTSCR_END,
	};
	
//------------------------------------------------------------------------------------------------
// Sub RoadNoise (Radius supplied by Mappy)
//

MR_LONG		script_sub_road_noise[] = 
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_ROAD_NOISE,		//    MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Sub WaterNoise
//

MR_LONG		script_sub_water_noise[] = 
	{								// SFX				
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_WATER_NOISE,	// 	   MIN		 		MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// SUB SMALL_BIRD
//
MR_LONG		script_sub_small_bird[] =
	{
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_PELICAN_WING,	//  MIN		MAX.
									ENTSCR_NO_REGISTERS,	512,		768,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sub_pelican[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SUB_PELICAN_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,

	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SUB_PELICAN_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG	script_sub_pelican_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SUB_PELICAN_CALL,
										ENTSCR_COORD_Z,			    128,
	ENTSCR_RESTART,
	};


// Taken out because it's the same as the original turtles.
//MR_LONG		script_sub_turtle[] =
//	{
//	ENTSCR_PREPARE_REGISTERS,			sizeof(PATH_INFO),				3,
//	ENTSCR_SET_ENTITY_TYPE,				ENTSCR_ENTITY_TYPE_PATH,
//	ENTSCR_REGISTER_CALLBACK,			ENTSCR_CALLBACK_1,				SCRIPT_CB_SUB_TURTLE,		ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,
//	ENTSCR_REGISTER_CALLBACK,			ENTSCR_CALLBACK_2,				SCRIPT_CB_HIT_TURTLE,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
//
//	ENTSCR_SETLOOP,
//		// Swim for mappy defined frames
//		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
//		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_0,
//
//		// Deviate through set distance (and speed), waiting for deviation to finish
//		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0x80, 0x8<<8, -1,
//		ENTSCR_SET_ACTION,					SUB_TURTLE_DIVE,
//		ENTSCR_PLAY_SOUND,					SFX_GEN_ENTITY_DIVE1,
//		ENTSCR_CREATE_3D_SPRITE,			0,
//		ENTSCR_WAIT_DEVIATED,		
//		ENTSCR_KILL_SAFE_FROG,	FROG_ANIMATION_DROWN,
//
//		// Swim (submerged) for mappy defined frames
//		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
//		ENTSCR_SET_ACTION,					SUB_TURTLE_SWIM,
//		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_1,
//
//		// Deviate through set distance (and speed), waiting for deviation to finish, play splash at end!
//		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0, -0x8<<8, -1,
//		ENTSCR_SET_ACTION,					SUB_TURTLE_DIVE,
//		ENTSCR_WAIT_DEVIATED,		
//		ENTSCR_PLAY_SOUND,					SFX_GEN_ENTITY_DIVE1,
//	ENTSCR_ENDLOOP,
//	ENTSCR_RESTART,
//	};

/******************************************************************************
*%%%% ENTSTRSubCreateLawnmower
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubCreateLawnmower(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a lawnmower
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubCreateLawnmower(LIVE_ENTITY* live_entity)
{

	// Locals
	SUB_RT_LAWNMOWER*	lawnmower;

	// Call normal create function
	ENTSTRCreateMovingMOF(live_entity);

	// Get pointer to runtime data
	lawnmower = (SUB_RT_LAWNMOWER*)live_entity->le_specific;

	// Set specific data.
	lawnmower->lm_state 		 = SUB_LAWNMOWER_MOWING;

}

/******************************************************************************
*%%%% ENTSTRSubUpdateLawnmower
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubUpdateLawnmower(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update lawnmower
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubUpdateLawnmower(LIVE_ENTITY* live_entity)
{

	// Locals
	SUB_RT_LAWNMOWER*	lawnmower;
	MR_SVEC				pos;

	// Get pointer to runtime data
	lawnmower = (SUB_RT_LAWNMOWER*)live_entity->le_specific;

	// According to mode of operation do ...
	switch ( lawnmower->lm_state )
		{

		// Mowing ...
		case SUB_LAWNMOWER_MOWING:

			// Play mowing sound
			PlayMovingSound(live_entity, SFX_SUB_MOWER, 512, 1536);

			// Have we hit a Frog ?
			if ( live_entity->le_flags & LIVE_ENTITY_HIT_FROG )
				{
				// Yes ... go on to chopping mode
				lawnmower->lm_state = SUB_LAWNMOWER_CHOPPING;
				// Play 2D sound
				MRSNDPlaySound(SFX_SUB_FROG_MOWED, NULL, 0, 0);
				}

			break;

		// Lawnmower chopping Frogger ...
		case SUB_LAWNMOWER_CHOPPING:

			// Yes ... set up position of frog relative to lawnmower base point
			pos.vx = 0;
			pos.vy = 0;
			pos.vz = 128;
			// Apply lawnmower rotation
			MRApplyMatrixSVEC(live_entity->le_lwtrans,&pos,&pos);

			// Set Frog orientation to that of lawnmower
			MR_COPY_MAT(Frogs[0].fr_lwtrans,live_entity->le_lwtrans);

			// Set frog position to offset plus lawnmower position
			Frogs[0].fr_lwtrans->t[0] = pos.vx + live_entity->le_lwtrans->t[0];
			Frogs[0].fr_lwtrans->t[1] = pos.vy + live_entity->le_lwtrans->t[1];
			Frogs[0].fr_lwtrans->t[2] = pos.vz + live_entity->le_lwtrans->t[2];

			// Change lawnmower mode
			lawnmower->lm_state = SUB_LAWNMOWER_DO_NOTHING;

			break;
		}

	// Update entity along path
	ENTSTRUpdateMovingMOF(live_entity);

}

