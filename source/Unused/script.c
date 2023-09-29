/******************************************************************************
*%%%% script.c
*------------------------------------------------------------------------------
*
*	Scripting information for entity control
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	01.05.97	Martin Kift		Created
*	06.05.97	Martin Kift		Added support for branching of scripts (in several ways)
*	10.05.97	Martin Kift		Added more scripts, including balloons, better
*								processing of gosubs and extra return conditions
*	
*%%%**************************************************************************/

#include "script.h"
#include "ent_sub.h"
#include "frog.h"

//------------------------------------------------------------------------------------------------
// Script command function pointers
//------------------------------------------------------------------------------------------------
MR_LONG (*Script_commands[])(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*) =
	{
	ENTSCR_WAIT_UNTIL_TIMER_command,
	ENTSCR_WAIT_UNTIL_ACTION_FINISHED_command,
	ENTSCR_WAIT_UNTIL_PATH_END_command,
	ENTSCR_SET_ACTION_command,
	ENTSCR_PLAY_SOUND_command,
	ENTSCR_RESTART_command,
	ENTSCR_END_command,
	ENTSCR_SET_TIMER_command,
	ENTSCR_DEVIATE_command,
	ENTSCR_WAIT_DEVIATED_command,
	ENTSCR_PLAY_RNDSOUND_command,
	ENTSCR_SETLOOP_command,
	ENTSCR_ENDLOOP_command,
	ENTSCR_SCRIPT_IF_command,
	ENTSCR_BREAKLOOP_IF_TIMER_command,
	ENTSCR_PAUSE_ENTITY_ON_PATH_command,
	ENTSCR_UNPAUSE_ENTITY_ON_PATH_command,
	ENTSCR_ROTATE_command,
	ENTSCR_WAIT_UNTIL_ROTATED_command,
	ENTSCR_HOME_IN_ON_FROG_command,
	ENTSCR_RETURN_GOSUB_IF_command,
	ENTSCR_EJECT_FROG_command,
	ENTSCR_CHOOSE_RND_CHECK_POINT_command,
	ENTSCR_APPEAR_ENTITY_command,
	ENTSCR_DISAPPEAR_ENTITY_command,
	ENTSCR_START_SCRIPT_command,
	ENTSCR_AWARD_FROG_POINTS_command,
	ENTSCR_AWARD_FROG_LIVES_command,
	ENTSCR_AWARD_FROG_TIME_command,
	};


//------------------------------------------------------------------------------------------------
// Script command lengths (includes command itself). This is used for script loops and suchlike
//------------------------------------------------------------------------------------------------
MR_ULONG	Script_command_lengths[] =	// INCLUDING the token itself
	{
	2,			//ENTSCR_WAIT_UNTIL_TIMER
	1,			//ENTSCR_WAIT_UNTIL_ACTION_FINISHED
	1,			//ENTSCR_WAIT_UNTIL_PATH_END
	2,			//ENTSCR_SET_ACTION
	2,			//ENTSCR_PLAY_SOUND
	1,			//ENTSCR_RESTART
	1,			//ENTSCR_END
	2,			//ENTSCR_SET_TIMER
	3,			//ENTSCR_DEVIATE
	1,			//ENTSCR_WAIT_DEVIATED
	2,			//ENTSCR_PLAY_RNDSOUND
	1,			//ENTSCR_SETLOOP
	1,			//ENTSCR_ENDLOOP
	4,			//ENTSCR_SCRIPT_IF
	2,			//ENTSCR_BREAKLOOP_IF_TIMER
	1,			//ENTSCR_PAUSE_ENTITY_ON_PATH
	1,			//ENTSCR_UNPAUSE_ENTITY_ON_PATH
	5,			//ENTSCR_ROTATE
	1,			//ENTSCR_WAIT_UNTIL_ROTATED
	3,			//ENTSCR_HOME_IN_ON_FROG
	2,			//ENTSCR_RETURN_GOSUB_IF
	2,			//ENTSCR_EJECT_FROG
	1,			//ENTSCR_CHOOSE_RND_CHECK_POINT
	1,			//ENTSCR_APPEAR_ENTITY
	1,			//ENTSCR_DISAPPEAR_ENTITY
	2,			//ENTSCR_START_SCRIPT
	2,			//ENTSCR_AWARD_FROG_POINTS
	2,			//ENTSCR_AWARD_FROG_LIVES
	2,			//ENTSCR_AWARD_FROG_TIME
	};


//------------------------------------------------------------------------------------------------
// Scripts
//------------------------------------------------------------------------------------------------
MR_LONG		script_sub_turtle[] =
	{
// Wait for 90 frames, checking to see if frog has hit us (playing that script if it does)
	ENTSCR_SET_TIMER,					0,
	//ENTSCR_SET_ACTION,				SUB_ACTION_TURTLE_SWIMMING,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,				ENTSCR_GOSUB_SCRIPT,		ENTSCR_HIT_FROG,	SCRIPT_SUB_TURTLE_HITFROG,
		ENTSCR_BREAKLOOP_IF_TIMER,		90,
	ENTSCR_ENDLOOP,

// Deviate through set distance (and speed), waiting for deviation to finish
	ENTSCR_DEVIATE,						ENTSCR_COORD_Y,			0x80,		0x8,	-1,
	//ENTSCR_SET_ACTION,				SUB_ACTION_TURTLE_DIVING,
	//ENTSCR_PLAY_SOUND,				SFX_ORG_TURTLE_SPLASH,
	ENTSCR_WAIT_DEVIATED,		

// Swim (submerged) for 90 frames
	ENTSCR_SET_TIMER,					0,
	//ENTSCR_SET_ACTION,				SUB_ACTION_TURTLE_SWIMMING,
	ENTSCR_WAIT_UNTIL_TIMER,			90,

// Deviate through set distance (and speed), waiting for deviation to finish, play splash at end!
	ENTSCR_DEVIATE,						ENTSCR_COORD_Y,			-0x80,		-0x8,	-1,
	//ENTSCR_SET_ACTION,				SUB_ACTION_TURTLE_DIVING,
	ENTSCR_WAIT_DEVIATED,		
//	ENTSCR_PLAY_SOUND,					SFX_ORG_TURTLE_SPLASH,
	ENTSCR_ROTATE,						ENTSCR_COORD_Y,	 		0x1000,		0x60, -1,
	ENTSCR_WAIT_UNTIL_ROTATED,			

	ENTSCR_RESTART
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_org_crocodile[] =
	{
// following removed since at the moment we don't have the second croc action
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			90,
//	ENTSCR_SET_ACTION,					ORG_ACTION_CROCODILE_SNAPPING,
//	ENTSCR_PLAY_SOUND,					0, //SFX_ORG_CROCODILE_SNAP,
//	ENTSCR_SET_TIMER,					0,
//	ENTSCR_WAIT_UNTIL_TIMER,			90,
//	ENTSCR_SET_ACTION,					ORG_ACTION_CROCODILE_SWIMMING,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_org_car[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				LORRY_CAR01,
//	ENTSCR_SET_TIMER,					0,
//	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_HOME_IN_ON_FROG,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_org_lorry[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				LORRY_HORN01,
//	ENTSCR_SET_TIMER,					0,
//	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_HOME_IN_ON_FROG,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_org_snake[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				SFX_ORG_SNAKE_HISS,
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sub_swan[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				SWAN_CALL,
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_org_truck[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				CAR_HORN2,
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_bird1_1[] =
	{
//	ENTSCR_PLAY_RNDSOUND,				SKY_BIRD1_1,
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			90,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sub_turtle_hitfrog[] =
	{
//	ENTSCR_PLAY_SOUND,				SFX_SUB_TURTLE_THUD,
	ENTSCR_END,
	};

//------------------------------------------------------------------------------------------------
// SKY Rising balloon script(s)
//
// Balloon waits for a frog to jump on it, at which point it starts rising. If the frog jumps off,
// it starts falling again until its back to where it was. If it reaches a certain height, it 
// pops, hopefully sending the frog to its death.
//
// To achieve this, several scripts are needed (see below)
//

MR_LONG		script_sky_rising_balloon_popping[] =
	{
//	ENTSCR_SET_ACTION,			SKY_BALLOON_POP,
//	ENTSCR_PLAY_SOUND,			SFX_SKY_BALLOON_POP,
	ENTSCR_EJECT_FROG,			0,
	ENTSCR_END,
	};

MR_LONG		script_sky_rising_balloon_rising[] =
	{
	ENTSCR_DEVIATE,				ENTSCR_COORD_Y,			-0x400,	-0x10,	-1,
	ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_DEVIATED,		SCRIPT_SKY_RISING_BALLOON_POPPING,
	ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_NO_HIT_FROG,		SCRIPT_SKY_RISING_BALLOON_SINKING,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_rising_balloon_sinking[] =
	{
	ENTSCR_DEVIATE,				ENTSCR_COORD_Y,			0, 10, -1,
	ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_DEVIATED,		SCRIPT_SKY_RISING_BALLOON_WAITING,
	ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_HIT_FROG,		SCRIPT_SKY_RISING_BALLOON_RISING,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_rising_balloon_waiting[] =
	{
	ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,			ENTSCR_HIT_FROG,	SCRIPT_SKY_RISING_BALLOON_RISING,
	ENTSCR_RESTART
	};

//------------------------------------------------------------------------------------------------
// SWP Nuclear Barallels 
//
// These wait for the frog to hit them, and then proceed to throw the frog off, either in a
// predefined direction, or most probably in the direction the frog is currently standing..
//
// To achieve this, several scripts are needed (see below)
//

MR_LONG		script_swp_nuclear_barrel_ejecting[] =
	{
//	ENTSCR_PLAY_SOUND,				SFX_SWP_NUCLEAR_BANG,
	ENTSCR_EJECT_FROG,				2,
	ENTSCR_END,
	};

MR_LONG		script_swp_nuclear_barrel_waiting[] =
	{
	ENTSCR_SCRIPT_IF,			ENTSCR_GOSUB_SCRIPT,		ENTSCR_HIT_FROG,	SCRIPT_SWP_NUCLEAR_BARLLEL_EJECTING,
	ENTSCR_RESTART
	};

//------------------------------------------------------------------------------------------------
// ORG log
//
// These wait for the frog to hit them, then make a splash noise, and then wait for the frog to
// jump off before making another splash... they can probably make an extra splash graphical
// affect maybe when the frog jumps on too?
//
MR_LONG		script_org_log_splash[] = 
	{
//	ENTSCR_PLAY_SOUND,				SFX_ORG_LOG_SPLASH,
	ENTSCR_SETLOOP,
		ENTSCR_RETURN_GOSUB_IF,		ENTSCR_NO_HIT_FROG,	
	ENTSCR_ENDLOOP
	};

MR_LONG		script_org_log[] =
	{
	ENTSCR_SCRIPT_IF,				ENTSCR_GOSUB_SCRIPT,	ENTSCR_HIT_FROG,	SCRIPT_ORG_LOG_SPLASH,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// ORG bonus flies
//
// These appear once at a time, over random trigger points, although only if that trigger point has
// not been hit already. If hit, they award the frog bonus points. 
//
MR_LONG		script_org_bonus_fly_collected[] = 
	{
	// play sound, maybe anim, and then make us disappear and go back to start of other script
//	ENTSCR_PLAY_SOUND,					SFX_ORG_FROG_FY_GULP,
	ENTSCR_AWARD_FROG_POINTS,			1000,
	ENTSCR_DISAPPEAR_ENTITY,
	ENTSCR_START_SCRIPT,				SCRIPT_ORG_BONUS_FLY_COLLECTED,
	};

MR_LONG		script_org_bonus_fly[] = 
	{
	// wait for preset amount of time
	ENTSCR_SET_TIMER,					0,
	ENTSCR_WAIT_UNTIL_TIMER,			120,

	// choose a random trigger point
	ENTSCR_CHOOSE_RND_CHECK_POINT,
	ENTSCR_APPEAR_ENTITY,				
	
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,				ENTSCR_NEW_SCRIPT,		ENTSCR_HIT_FROG,	SCRIPT_ORG_BONUS_FLY_COLLECTED,
		ENTSCR_BREAKLOOP_IF_TIMER,		120,
	ENTSCR_ENDLOOP,

	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Main script lookup table
//------------------------------------------------------------------------------------------------
MR_LONG*	Scripts[] = {
		script_sub_turtle,
		script_org_crocodile,
		script_org_car,
		script_org_lorry,
		script_org_snake,
		script_sub_swan,
		script_org_truck,
		script_sky_bird1_1,
		script_sub_turtle_hitfrog,
		script_sky_rising_balloon_waiting,
		script_sky_rising_balloon_rising,
		script_sky_rising_balloon_sinking,
		script_sky_rising_balloon_popping,
		script_swp_nuclear_barrel_waiting,
		script_swp_nuclear_barrel_ejecting,
		script_org_log,
		script_org_log_splash,
		script_org_bonus_fly,
		script_org_bonus_fly_collected,
	};	

//------------------------------------------------------------------------------------------------
// Script commands follow
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PLAY_SOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
//	if (entity = live_entity->le_entity)
//		MRSNDPlaySound((MR_SHORT)script[0], NULL, 0, 0);
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SET_ACTION_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
	MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)script[0]);
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_ACTION_FINISHED_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ANIM_ENV_SINGLE*	env_sing;

	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
	env_sing = (MR_ANIM_ENV_SINGLE*)((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra;

	if (env_sing->ae_cel_number >= env_sing->ae_total_cels)
		{
		// yes the animation has finished
		script_info->si_script = script + 1;
		return ENTSCR_RETURN_CONTINUE;
		}

	return ENTSCR_RETURN_BREAK;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_TIMER_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if (script_info->si_timer >= script[0])
		{
		script_info->si_script = script + 1;
		return ENTSCR_RETURN_CONTINUE;
		}

	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SET_TIMER_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	script_info->si_timer	= script[0];
	script_info->si_script	= script + 1;

	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_END_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// May want to tidy up any movement that has occured?
	return ENTSCR_RETURN_END;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_RESTART_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// restart script at the beginning of current script
	script_info->si_script	= Scripts[script_info->si_type];
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_PATH_END_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	ENTITY*			entity;

	if (entity = live_entity->le_entity)
		{
		if (entity->en_path_runner->pr_flags & PATH_RUNNER_AT_END)
			{
			script_info->si_script = script + 1;
			return ENTSCR_RETURN_CONTINUE;
			}
		}

	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_DEVIATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	SCR_DEVIATE*		deviate;

	deviate = (SCR_DEVIATE*)script;

	// fill in deviate values
	(&script_info->si_dev_dest_x)[deviate->dv_coord] 	= deviate->dv_dest;
	(&script_info->si_dev_dx)[deviate->dv_coord]		= deviate->dv_delta;
	(&script_info->si_dev_dx_count)[deviate->dv_coord] 	= deviate->dv_count;

	// move to next command
	script_info->si_script = (MR_LONG*)(((MR_UBYTE*)script) + sizeof(SCR_DEVIATE));
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_DEVIATED_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if ((script_info->si_dev_dx_count) ||
		(script_info->si_dev_dy_count) ||
		(script_info->si_dev_dz_count)
		)
		{
		// movement still in progress
		return(ENTSCR_RETURN_BREAK);
		}

	// movement finished
	script_info->si_script = script;
	return(ENTSCR_RETURN_CONTINUE);
}
	
//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_RETURN_PATH_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PLAY_RNDSOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if ( rand()%300 == 1 )
		{
//		MRSNDCreateMovingSound(	(MR_VEC*)live_entity->le_lwtrans->t,
//								(MR_VEC*)live_entity->le_lwtrans->t,
//								script[0]);
		}
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SETLOOP_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	script_info->si_script_loop_start	= script;
	script_info->si_script				= script;

	// Find next ENTSCR_ENDLOOP command
	while (script[0] != ENTSCR_ENDLOOP)
		script += Script_command_lengths[script[0]];

	script_info->si_script_loop_end 	= script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_ENDLOOP_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT(script_info->si_script_loop_start);
	script_info->si_script	= script_info->si_script_loop_start;
	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_BREAKLOOP_IF_TIMER_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT(script_info->si_script_loop_start);
	MR_ASSERT(script_info->si_script_loop_end);

	if (script_info->si_timer < script[0])
		{
		// Timer still in progress
		script_info->si_script = script + 1;
		return ENTSCR_RETURN_CONTINUE;
		}
	else
		{
		// Timer finished, break loop
		script_info->si_script 				= script_info->si_script_loop_end;
		script_info->si_script_loop_start	= NULL;
		script_info->si_script_loop_end		= NULL;
		return ENTSCR_RETURN_CONTINUE;
		}
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SCRIPT_IF_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	SCR_NEW_SCRIPT*		new_script;

	new_script = (SCR_NEW_SCRIPT*)script;

	// check condition of gosubing to new script
	switch (new_script->eni_mode)
		{
		//----------------------------------------------------------------------------------------
		case ENTSCR_HIT_FROG:
			// is there a frog standing on us?

			if (live_entity->le_flags & LIVE_ENTITY_FROG_ON)
				{
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_HIT_FROG:
			// is there NOT a frog standing on us?

			if (!(live_entity->le_flags & LIVE_ENTITY_FROG_ON))
				{
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_DEVIATED:
			if ((!script_info->si_dev_dx_count) &&
				(!script_info->si_dev_dy_count) &&
				(!script_info->si_dev_dz_count))
				{
				// movement finished, so go for new script
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_ROTATED:
			if ((!script_info->si_dx_count) &&
				(!script_info->si_dy_count) &&
				(!script_info->si_dz_count))
				{
				// movement finished, so go for new script
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;
		}

	// move to next instruction
	script_info->si_script = (MR_LONG*)(((MR_UBYTE*)script) + sizeof(SCR_NEW_SCRIPT));
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PAUSE_ENTITY_ON_PATH_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT(live_entity->le_entity->en_path_runner);

	// pause path runner
	live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_UNPAUSE_ENTITY_ON_PATH_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT(live_entity->le_entity->en_path_runner);

	// unpause path runner
	live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_ROTATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// If destination angle is NULL, we rotate for the specified duration, else we rotate until we hit or pass the
	// destination angle
	SCR_ROTATE*		scr_rotate;

	scr_rotate = (SCR_ROTATE*)script;

	(&script_info->si_dest_x)[scr_rotate->rt_coord] 	= scr_rotate->rt_dest;
	(&script_info->si_dx)[scr_rotate->rt_coord]			= scr_rotate->rt_delta;
	(&script_info->si_dx_count)[scr_rotate->rt_coord] 	= scr_rotate->rt_count;

	script_info->si_script = (MR_LONG*)(((MR_UBYTE*)script) + sizeof(SCR_ROTATE));
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_ROTATED_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if ((script_info->si_dx_count) ||
		(script_info->si_dy_count) ||
		(script_info->si_dz_count)
		)
		{
		// Axis rotation still in progress
		return ENTSCR_RETURN_BREAK;
		}

	// Axis rotation finished
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_HOME_IN_ON_FROG_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_VEC	dir_vec;
	MR_VEC	norm_dir_vec;

	MR_SUB_VEC_ABC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)Frogs[0].fr_lwtrans->t, &dir_vec);
	MRNormaliseVEC(&dir_vec, &norm_dir_vec);	
	live_entity->le_lwtrans->m[0][2] = (MR_SHORT)norm_dir_vec.vx;
	live_entity->le_lwtrans->m[1][2] = 0;
	live_entity->le_lwtrans->m[2][2] = (MR_SHORT)norm_dir_vec.vz;
	MRGenerateYXMatrixFromZColumn(live_entity->le_lwtrans);

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_EJECT_FROG_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// For the time being, until such time as more information is available about which frog actually
	// hit the frog, we'll just assume single player, and Frogs[0]


	// no code at present, need to know how to control the frog (make it jump, or make it fall)
	// rather not hack the code at present

	
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_RETURN_GOSUB_IF_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// check condition of gosubing to new script
	switch (script[0])
		{
		//----------------------------------------------------------------------------------------
		case ENTSCR_HIT_FROG:
			// is there a frog standing on us?
			if (live_entity->le_flags & LIVE_ENTITY_FROG_ON)
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_HIT_FROG:
			// is there NOT a frog standing on us?

			if (!(live_entity->le_flags & LIVE_ENTITY_FROG_ON))
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_DEVIATED:
			if ((!script_info->si_dev_dx_count) &&
				(!script_info->si_dev_dy_count) &&
				(!script_info->si_dev_dz_count))
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_ROTATED:
			if ((!script_info->si_dx_count) &&
				(!script_info->si_dy_count) &&
				(!script_info->si_dz_count))
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;
		}

	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
// UNFINISHED
//
MR_LONG	ENTSCR_CHOOSE_RND_CHECK_POINT_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_SHORT	check_id;
	MR_SHORT	once_through;

	once_through = 0;

	// This function tries to find an as yet unreached checkpoint, and sets up a position
	// so that an entity can appear there
	
	// Need some function to get the position of a check point, and whether its available, and
	// suchlike
	check_id = rand()%5;
	while (0) // IsTriggerCollected(check_id) == TRUE
		{
		check_id++;
		if (check_id > 4)
			{
			check_id = 0;
			once_through++;
			}

		if (once_through > 1)
			break;
		}

	// TOBEDONE

	//GetTriggerPosition(check_id, &svec);
	MR_CLEAR_SVEC(&script_info->si_position);		// temp

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_APPEAR_ENTITY_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// make our entity appear at the precalculated position
	MR_VEC_EQUALS_SVEC((MR_VEC*)live_entity->le_lwtrans->t, &script_info->si_position);

	// make it appear... somehow... ;/
	// TOBEDONE

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_DISAPPEAR_ENTITY_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// make it disappear... somehow... ;/
	// TOBEDONE

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_START_SCRIPT_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// start a new script (from its beginning), don't want to really reset contents though, so
	// don't called StartScript()

	script_info->si_type	= script[0];
	script_info->si_script	= Scripts[script[0]];

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_POINTS_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// TOBEDONE
	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_LIVES_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// TOBEDONE
	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_TIME_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// TOBEDONE
	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

/******************************************************************************
*%%%% UpdateScriptInfo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateScriptInfo(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Handles starting and parsing of live entity scripts
*
*	INPUTS		live_entity	-	ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*	06.05.97	Martin Kift		Added support for relooping of gosub looped scripts
*
*%%%**************************************************************************/

MR_VOID	UpdateScriptInfo(LIVE_ENTITY *live_entity)
{
	ENTITY*			entity;
	SCRIPT_INFO*	script_info;
	MR_LONG			ret;
	MR_LONG			i;
	MR_LONG			cos, sin;

	MR_ASSERT(live_entity);
	
	entity			= live_entity->le_entity;
	script_info		= live_entity->le_script;

	// Update any active stunt
	if (script_info->si_flags & SCRIPT_INFO_ACTIVE)
		{
		// Parse script
		ret = ENTSCR_RETURN_CONTINUE;
		while (ret == ENTSCR_RETURN_CONTINUE)
			{
			ret = (Script_commands[script_info->si_script[0]])(live_entity, script_info, script_info->si_script + 1);
			}

		// Update deviations
		for (i = ENTSCR_COORD_X; i <= ENTSCR_COORD_Z; i++)
			{
			if ((&script_info->si_dev_dx_count)[i])
				{
				if ((&script_info->si_dev_dx_count)[i] < 0)
					{
					// Move until passed si_dest_
					if ((&script_info->si_dev_dx)[i] > 0)
						{
						(&script_info->si_dev_x)[i] += (&script_info->si_dev_dx)[i];
						if ((&script_info->si_dev_x)[i] >= (&script_info->si_dev_dest_x)[i])
							{
							(&script_info->si_dev_x)[i] 		= (&script_info->si_dev_dest_x)[i];
							(&script_info->si_dev_dx)[i] 		= 0;
							(&script_info->si_dev_dx_count)[i]  = 0;
							}
						}
					else if ((&script_info->si_dev_dx)[i] < 0)
						{
						(&script_info->si_dev_x)[i] += (&script_info->si_dev_dx)[i];
						if ((&script_info->si_dev_x)[i] <= (&script_info->si_dev_dest_x)[i])
							{
							(&script_info->si_dev_x)[i] 		= (&script_info->si_dev_dest_x)[i];
							(&script_info->si_dev_dx)[i] 		= 0;
							(&script_info->si_dev_dx_count)[i]	= 0;
							}
						}
					}
				else
					{
					// Move and decrease count
					(&script_info->si_dev_x)[i] += (&script_info->si_dev_dx)[i];
					if (!(--((&script_info->si_dev_dx_count)[i])))
						(&script_info->si_dev_dx)[i] = 0;
					}
				}
			}

		// Update angles
		for (i = ENTSCR_COORD_X; i <= ENTSCR_COORD_Z; i++)
			{
			if ((&script_info->si_dx_count)[i])
				{
				if ((&script_info->si_dx_count)[i] < 0)
					{
					// Move until passed si_dest_
					if ((&script_info->si_dx)[i] > 0)
						{
						(&script_info->si_x)[i] += (&script_info->si_dx)[i];
						if ((&script_info->si_x)[i] >= (&script_info->si_dest_x)[i])
							{
							(&script_info->si_x)[i] 		= (&script_info->si_dest_x)[i] & 0xfff;
							(&script_info->si_dx)[i] 		= 0;
							(&script_info->si_dx_count)[i]  = 0;
							}
						}
					else if ((&script_info->si_dx)[i] < 0)
						{
						(&script_info->si_x)[i] += (&script_info->si_dx)[i];
						if ((&script_info->si_x)[i] <= (&script_info->si_dest_x)[i])
							{
							(&script_info->si_x)[i] 		= (&script_info->si_dest_x)[i] & 0xfff;
							(&script_info->si_dx)[i] 		= 0;
							(&script_info->si_dx_count)[i]	= 0;
							}
						}
					}
				else
					{
					// Move and decrease count
					(&script_info->si_x)[i] += (&script_info->si_dx)[i];
					(&script_info->si_x)[i] &= 0xfff;
					if (!(--((&script_info->si_dx_count)[i])))
						(&script_info->si_dx)[i] = 0;
					}
				}
			}

		// Build lwtrans
		if (script_info->si_x)
			{
			cos = rcos(script_info->si_x);
			sin = rsin(script_info->si_x);
			MRRot_matrix_X.m[1][1] =  cos;
			MRRot_matrix_X.m[1][2] = -sin;
			MRRot_matrix_X.m[2][1] =  sin;
			MRRot_matrix_X.m[2][2] =  cos;
			MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_X);
			}				
		if (script_info->si_y)
			{
			cos = rcos(script_info->si_y);
			sin = rsin(script_info->si_y);
			MRRot_matrix_Y.m[0][0] =  cos;
			MRRot_matrix_Y.m[0][2] =  sin;
			MRRot_matrix_Y.m[2][0] = -sin;
			MRRot_matrix_Y.m[2][2] =  cos;
			MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_Y);
			}				
		if (script_info->si_z)
			{
			cos = rcos(script_info->si_z);
			sin = rsin(script_info->si_z);
			MRRot_matrix_Z.m[0][0] =  cos;
			MRRot_matrix_Z.m[0][1] = -sin;
			MRRot_matrix_Z.m[1][0] =  sin;
			MRRot_matrix_Z.m[1][1] =  cos;
			MRMulMatrixABA(live_entity->le_lwtrans, &MRRot_matrix_Z);
			}				

		// apply our deviation (translation)
		live_entity->le_lwtrans->t[0] += script_info->si_dev_x;
		live_entity->le_lwtrans->t[1] += script_info->si_dev_y;
		live_entity->le_lwtrans->t[2] += script_info->si_dev_z;

		// Call any registered callback functions
		if (script_info->si_script_callback)
			(script_info->si_script_callback) (live_entity, script_info, script_info->si_script);

		// Update timer
		script_info->si_timer++;

		// Consider action on leaving script
		switch(ret)		
			{
			case ENTSCR_RETURN_BREAK:
				break;

			case ENTSCR_RETURN_END:
				// were we in a subroutine script? In which case, consider going back to where we
				// were in the previous script!
				if (script_info->si_flags & SCRIPT_INFO_SUBROUTINE)
					{
					MR_ASSERT (script_info->si_script_previous != NULL);
					
					// put back previous script info, and clear flag (V.IMPORTANT)
					script_info->si_script				= script_info->si_script_previous;
					script_info->si_script_loop_start	= script_info->si_script_loop_start_previous;				
					script_info->si_script_loop_end		= script_info->si_script_loop_end_previous;
					
					script_info->si_flags	&= ~SCRIPT_INFO_SUBROUTINE;
					}
				else
					{
					// end of script, finish gracefully
					script_info->si_flags = NULL;
					goto end_update;
					}
			}
		}
end_update:;
}


/******************************************************************************
*%%%% StartScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	StartScript(
*								SCRIPT_INFO*	script_info,
*								MR_USHORT		script_type,
*								LIVE_ENTITY*	live_entity)
*								
*	FUNCTION	Start a script for a given live entity
*
*	INPUTS		script_info	-	ptr to live entities SCRIPT_INFO
*				script_type	-	script type
*				live_entity	-	ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	StartScript(SCRIPT_INFO*	script_info,
					MR_LONG			script_type,
					LIVE_ENTITY*	live_entity)
{
	MR_ASSERT(script_info);
	MR_ASSERT(live_entity);

	ResetScript(script_info);

	script_info->si_flags 	= SCRIPT_INFO_ACTIVE;
	script_info->si_type	= script_type;
	script_info->si_script	= Scripts[script_type];
}


/******************************************************************************
*%%%% ResetScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetScript(
*							SCRIPT_INFO*	script_info)
*								
*	FUNCTION	Reset script for a given live entity
*
*	INPUTES		script_info		- ptr to script's SCRIPT_INFO structure.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ResetScript(SCRIPT_INFO*	script_info)
{
	MR_ASSERT(script_info);

	memset (script_info, 0x0, sizeof (SCRIPT_INFO));
}


/******************************************************************************
*%%%% BranchToNewScript
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	BranchToNewScript(
*							SCR_NEW_SCRIPT*	new_script,
*							SCRIPT_INFO*	script_info,
*							MR_LONG*		script)
*								
*	FUNCTION	Branches script for a live entity from current script to a new
*				one, either as a complete branch, or as a gosub.
*
*	INPUTS		new_script		- ptr to newscript information used to branch.
*				script_info		- ptr to script's SCRIPT_INFO structure.
*				script			- ptr to current script instruction.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	BranchToNewScript(	SCR_NEW_SCRIPT*	new_script,
							SCRIPT_INFO*	script_info,
							MR_LONG*		script)
{
	// If this is a gosub branch type, we need to back up the current script information	
	// so that we can return from whence we came. Note that when we backup the current 
	// script position, we move it beyond the current instruction, to avoid getting
	// into infinite loops
	if (new_script->eni_branch == ENTSCR_GOSUB_SCRIPT)
		{
		script_info->si_script_previous				= (MR_LONG*)(((MR_UBYTE*)script) + sizeof(SCR_NEW_SCRIPT));
		script_info->si_script_loop_start_previous	= script_info->si_script_loop_start;
		script_info->si_script_loop_end_previous 	= script_info->si_script_loop_end;

		// V.important, set the subroutine flag, since we are doing a gosub
		script_info->si_flags |= SCRIPT_INFO_SUBROUTINE;
		}
			
	// Set the current script info up to point at the requested script
	script_info->si_script				= Scripts[new_script->eni_script_id];
	script_info->si_script_loop_start	= NULL;
	script_info->si_script_loop_end 	= NULL;
}
