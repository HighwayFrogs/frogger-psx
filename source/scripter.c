/******************************************************************************
*%%%% scripter.c
*------------------------------------------------------------------------------
*
*	The main scripting update code to handle processing of scripts for entites.
*	Also includes all script commands. Note that all the scripts themselves are
*	contained within scripts.c
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	12.05.97	Martin Kift		Created
*	13.05.97	Martin Kift		Added register(s) for scripts to load mappy data
*
*%%%**************************************************************************/

#include "scripter.h"
#include "scripts.h"
#include "frog.h"
#include "entity.h"
#include "entlib.h"
#include "ent_gen.h"
#include "camera.h"
#include "froganim.h"
#include "sound.h"
#include "froguser.h"
#include "tempopt.h"

MR_LONG		tester = 0;

// Splash Lists
MR_ULONG	TurtleSplashAnimList[]=
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
	ENTSCR_CHOOSE_RND_CHECKPOINT_command,
	ENTSCR_APPEAR_ENTITY_command,
	ENTSCR_DISAPPEAR_ENTITY_command,
	ENTSCR_START_SCRIPT_command,
	ENTSCR_AWARD_FROG_POINTS_command,
	ENTSCR_AWARD_FROG_LIVES_command,
	ENTSCR_AWARD_FROG_TIME_command,
	ENTSCR_STOP_ROTATE_command,
	ENTSCR_STOP_DEVIATE_command,
	ENTSCR_PREPARE_REGISTERS_command,
	ENTSCR_CLEAR_DEVIATE_command,
	ENTSCR_RETURN_DEVIATE_command,
	ENTSCR_REGISTER_CALLBACK_command,
	ENTSCR_SET_ENTITY_TYPE_command,
	ENTSCR_PLAY_SOUND_DISTANCE_command,
	ENTSCR_PLAY_MOVING_SOUND_command,
	ENTSCR_STOP_command,
	ENTSCR_MUTATE_MESH_COLOR_command,
	ENTSCR_NO_COLL_CHECKPOINT_command,
	ENTSCR_COLL_CHECKPOINT_command,
	ENTSCR_KILL_SAFE_FROG_command,
	ENTSCR_CHANGE_ENTITY_ANIM_command,
	ENTSCR_CREATE_3D_SPRITE_command,
	ENTSCR_PITCH_BEND_MOVING_SOUND_command,
	ENTSCR_POP_command,
	ENTSCR_NO_COLLISION_command,
	ENTSCR_COLLISION_command,
	};

//------------------------------------------------------------------------------------------------
// Script command lengths (includes command itself). This is used for script loops and suchlike
//------------------------------------------------------------------------------------------------
MR_ULONG	Script_command_lengths[] =	// INCLUDING the token itself
	{
	3,			//ENTSCR_WAIT_UNTIL_TIMER
	1,			//ENTSCR_WAIT_UNTIL_ACTION_FINISHED
	1,			//ENTSCR_WAIT_UNTIL_PATH_END
	2,			//ENTSCR_SET_ACTION
	2,			//ENTSCR_PLAY_SOUND
	1,			//ENTSCR_RESTART
	1,			//ENTSCR_END
	3,			//ENTSCR_SET_TIMER
	6,			//ENTSCR_DEVIATE
	1,			//ENTSCR_WAIT_DEVIATED
	3,			//ENTSCR_PLAY_RNDSOUND
	1,			//ENTSCR_SETLOOP
	1,			//ENTSCR_ENDLOOP
	5,			//ENTSCR_SCRIPT_IF
	3,			//ENTSCR_BREAKLOOP_IF_TIMER
	1,			//ENTSCR_PAUSE_ENTITY_ON_PATH
	1,			//ENTSCR_UNPAUSE_ENTITY_ON_PATH
	5,			//ENTSCR_ROTATE
	1,			//ENTSCR_WAIT_UNTIL_ROTATED
	4,			//ENTSCR_HOME_IN_ON_FROG
	2,			//ENTSCR_RETURN_GOSUB_IF
	4,			//ENTSCR_EJECT_FROG
	1,			//ENTSCR_CHOOSE_RND_CHECKPOINT
	1,			//ENTSCR_APPEAR_ENTITY
	1,			//ENTSCR_DISAPPEAR_ENTITY
	2,			//ENTSCR_START_SCRIPT
	2,			//ENTSCR_AWARD_FROG_POINTS
	2,			//ENTSCR_AWARD_FROG_LIVES
	2,			//ENTSCR_AWARD_FROG_TIME
	1,			//ENTSCR_STOP_ROTATE
	1,			//ENTSCR_STOP_DEVIATE
	3,			//ENTSCR_PREPARE_REGISTERS
	1,			//ENTSCR_CLEAR_DEVIATE
	4,			//ENTSCR_RETURN_DEVIATE
	5,			//ENTSCR_REGISTER_CALLBACK
	2,			//ENTSCR_SET_ENTITY_TYPE
	6,			//ENTSCR_PLAY_SOUND_DISTANCE
	5,			//ENTSCR_PLAY_MOVING_SOUND
	1,			//ENTSCR_STOP
	1,			//ENTSCR_MUTATE_MESH_COLOR
	1,			//ENTSCR_NO_COLL_CHECKPOINT
	1,			//ENTSCR_COLL_CHECKPOINT
	3,			//ENTSCR_KILL_SAFE_FROG
	2,			//ENTSCR_CHANGE_ENTITY_ANIM
	2,			//ENTSCR_CREATE_3D_SPRITE
	7,			//ENTSCR_PITCH_BEND_MOVING_SOUND
	1,			//ENTSCR_POP
	1,			//ENTSCR_NO_COLLISION
	1,			//ENTSCR_COLLISION
	};

//------------------------------------------------------------------------------------------------ Match: https://decomp.me/scratch/WcyWg (By Kneesnap)
MR_LONG	ENTSCR_PLAY_SOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if (!Game_over_no_new_sound)
		MRSNDPlaySound((MR_SHORT)script[0], NULL, 0, 0);
	
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SET_ACTION_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)script[0]);
	else
		MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)script[0]);

	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_ACTION_FINISHED_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_ANIM_ENV_SINGLE*		env_sing;
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;
	
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
		{
		env_flipbook = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;

		if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
			{
			// yes the animation has finished
			script_info->si_script = script;
			return ENTSCR_RETURN_CONTINUE;
			}
		}
	else
		{
		env_sing = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_single;

		if (env_sing->ae_cel_number >= env_sing->ae_total_cels-1)
			{
			// yes the animation has finished
			script_info->si_script = script;
			return ENTSCR_RETURN_CONTINUE;
			}
		}

	return ENTSCR_RETURN_BREAK;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_WAIT_UNTIL_TIMER_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// if script if a register command, then we need to grab the exact value...
	if (script[0] == ENTSCR_REGISTERS)
		{
		if (script_info->si_timer >= script_info->si_registers[script[1]])
			{
			script_info->si_script = script + 2;
			return ENTSCR_RETURN_CONTINUE;
			}
		}
	else
		{
		if (script_info->si_timer >= script[1])
			{
			script_info->si_script = script + 2;
			return ENTSCR_RETURN_CONTINUE;
			}
		}

	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SET_TIMER_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// if script if a register command, then we need to grab the exact value...
	if (script[0] == ENTSCR_REGISTERS)
		script_info->si_timer	= script_info->si_registers[script[1]];
	else
		script_info->si_timer	= script[1];
	
	// move to next command
	script_info->si_script	= script + 2;
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
		MR_ASSERT (entity->en_path_runner);

		if	(
			(entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_START) ||
			(entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_END) ||
			(entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_START) ||
			(entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_END)
			)
			{
			script_info->si_script = script;
			return ENTSCR_RETURN_CONTINUE;
			}
		}

	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_DEVIATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	SCR_DEVIATE*	deviate;
	MR_LONG			coord;

	deviate = (SCR_DEVIATE*)script;
	coord = deviate->dv_coord;

	if (coord > ENTSCR_COORD_Z)
		{
		// a negative coord specified
		coord -= ENTSCR_NEG_COORD_X;

		if (deviate->dv_registers != ENTSCR_REGISTERS)
			{
			(&script_info->si_dev_dest_x)[coord]	= deviate->dv_dest;
			(&script_info->si_dev_dx)[coord]		= -deviate->dv_delta;
			(&script_info->si_dev_dx_count)[coord] 	= deviate->dv_count;
			}
		else
			{
			(&script_info->si_dev_dest_x)[coord]	= script_info->si_registers[deviate->dv_dest];
			(&script_info->si_dev_dx)[coord]		= -script_info->si_registers[deviate->dv_delta];
			(&script_info->si_dev_dx_count)[coord] 	= deviate->dv_count;
			}
		}	
	else
		{
		// a normal coord was specified

		if (deviate->dv_registers != ENTSCR_REGISTERS)
			{
			(&script_info->si_dev_dest_x)[coord]	= deviate->dv_dest;
			(&script_info->si_dev_dx)[coord]		= deviate->dv_delta;
			(&script_info->si_dev_dx_count)[coord] 	= deviate->dv_count;
			}
		else
			{
			(&script_info->si_dev_dest_x)[coord]	= script_info->si_registers[deviate->dv_dest];
			(&script_info->si_dev_dx)[coord]		= script_info->si_registers[deviate->dv_delta];
			(&script_info->si_dev_dx_count)[coord] 	= deviate->dv_count;
			}
		}

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


//------------------------------------------------------------------------------------------------ Match: https://decomp.me/scratch/YJ07i (By Kneesnap)
MR_LONG	ENTSCR_PLAY_RNDSOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if ( !Game_over_no_new_sound && rand()%(MR_SHORT)script[1] == 1 )
		{
		MRSNDPlaySound((MR_SHORT)script[0], NULL, 0, 0);
		}
	script_info->si_script = script + 2;
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
	MR_LONG		time;

	MR_ASSERT(script_info->si_script_loop_start);
	MR_ASSERT(script_info->si_script_loop_end);

	if (script[0] == ENTSCR_REGISTERS)
		time = script_info->si_registers[script[1]];
	else
		time = script[1];

	if (script_info->si_timer < time)
		{
		// Timer still in progress
		script_info->si_script = script + 2;
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
		case ENTSCR_SAFE_FROG:
			// is there a frog standing on us?
			if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
				{
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_SAFE_FROG:
			// is there NOT a frog standing on us?
			if (!(live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG))
				{
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_HIT_FROG:
			// has a frog just hit us
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_HIT_FROG:
			// has no frog hit us?
			if (!(live_entity->le_flags & LIVE_ENTITY_HIT_FROG))
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

		//----------------------------------------------------------------------------------------
		case ENTSCR_RANDOM:
			// Wait for Random Hit.
			if (rand()%new_script->eni_value == 1)
				{
				// Movement finished, so go for new script
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break; 
		//----------------------------------------------------------------------------------------
		case ENTSCR_END_OF_PATH:
			MR_ASSERT (live_entity->le_entity->en_path_runner);
			
			if (
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_START) ||
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_BOUNCED_END) ||
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_START) ||
				(live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_JUST_REPEATED_END)
				)
				{
				// Movement finished, so go for new script
				BranchToNewScript(new_script, script_info, script);
				return ENTSCR_RETURN_CONTINUE;
				}
			break;
		//----------------------------------------------------------------------------------------
		case ENTSCR_ALWAYS: 
			BranchToNewScript(new_script, script_info, script);
			return ENTSCR_RETURN_CONTINUE;
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
	MR_LONG	distance;

	// Is Frogger not dead or hit check point ?
	if ( (Frogs[0].fr_mode != FROG_MODE_DYING) && (Frogs[0].fr_mode != FROG_MODE_HIT_CHECKPOINT) && (Frogs[0].fr_mode != FROGUSER_MODE_CHECKPOINT_COLLECTED) )
		{

		MR_SUB_VEC_ABC((MR_VEC*)Frogs[0].fr_lwtrans->t, (MR_VEC*)live_entity->le_lwtrans->t, &dir_vec);
		distance = MR_VEC_MOD(&dir_vec);

		// are we close enough?
		if (
			((script[0] == ENTSCR_REGISTERS) && (MR_VEC_MOD(&dir_vec) < script_info->si_registers[script[2]])) ||
			(distance < script[2]))
			{

			// If we are within a set distance, don't update, since it'll just look silly
			if (distance > 4)
				{
				MRNormaliseVEC(&dir_vec, &norm_dir_vec);	
				live_entity->le_lwtrans->m[0][2] = (MR_SHORT)norm_dir_vec.vx;
				live_entity->le_lwtrans->m[1][2] = (MR_SHORT)norm_dir_vec.vy;
				live_entity->le_lwtrans->m[2][2] = (MR_SHORT)norm_dir_vec.vz;
				MRGenerateYXMatrixFromZColumn(live_entity->le_lwtrans);

				if (script[0] == ENTSCR_REGISTERS)
					{
					// move towards frog at set speed
					live_entity->le_lwtrans->t[0] += (live_entity->le_lwtrans->m[0][2] * (script_info->si_registers[script[1]]>>WORLD_SHIFT)) >> 12;
					live_entity->le_lwtrans->t[1] += (live_entity->le_lwtrans->m[1][2] * (script_info->si_registers[script[1]]>>WORLD_SHIFT)) >> 12;
					live_entity->le_lwtrans->t[2] += (live_entity->le_lwtrans->m[2][2] * (script_info->si_registers[script[1]]>>WORLD_SHIFT)) >> 12;
					}
				else
					{
					// move towards frog at set speed
					live_entity->le_lwtrans->t[0] += (live_entity->le_lwtrans->m[0][2] * (script[1]>>WORLD_SHIFT)) >> 12;
					live_entity->le_lwtrans->t[1] += (live_entity->le_lwtrans->m[1][2] * (script[1]>>WORLD_SHIFT)) >> 12;
					live_entity->le_lwtrans->t[2] += (live_entity->le_lwtrans->m[2][2] * (script[1]>>WORLD_SHIFT)) >> 12;
					}
				}
			else
				{
				live_entity->le_lwtrans->t[0] = Frogs[0].fr_lwtrans->t[0];
				live_entity->le_lwtrans->t[1] = Frogs[0].fr_lwtrans->t[1] + 10;	// hacks we love them
				live_entity->le_lwtrans->t[2] = Frogs[0].fr_lwtrans->t[2];
				}
			}
		}

	script_info->si_script = script + 3;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_EJECT_FROG_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_USHORT	frog_index;
	FROG*		frog;
	MR_LONG		flags;
	MR_LONG		distance;
	CAMERA*		camera;


	if (script[0] == ENTSCR_REGISTERS)
		{
		flags		= script_info->si_registers[script[1]];
		distance	= script_info->si_registers[script[2]];
		}
	else
		{
		flags		= script[1];
		distance	= script[2];
		}

	// search for all 4 possible frogs
	frog_index = 0;
	while (frog_index < 4)
		{
		if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_index))
			{	
			// we have found our frog,, eject it, in the direction we are currently facing
			frog 	= &Frogs[frog_index];
			camera	= &Cameras[frog->fr_frog_id];

#ifdef WIN95
			if (MNIsNetGameRunning())
				camera = &Cameras[0];
#endif
			
			// if distance is zero, make frog fall
			if (distance == 0)
				{
				FROG_FALL(frog);
				}
			else
				{
				if (frog->fr_flags & FROG_ON_ENTITY)
					{
					JumpFrog(	frog, 
								(frog->fr_direction - frog->fr_entity_angle) & 3,
								FROG_JUMP_FORCED, 
								flags,
								distance);
					}
				else
					{
					JumpFrog(	frog, 
								(frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N]) & 3,
								FROG_JUMP_FORCED, 
								flags,
								distance);
					}
				}
			}
		frog_index++;
		}

	// goto next script command
	script_info->si_script = script + 3;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_RETURN_GOSUB_IF_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// check condition of gosubing to new script
	switch (script[0])
		{
		//----------------------------------------------------------------------------------------
		case ENTSCR_SAFE_FROG:
			// is there a frog standing on us?
			if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_SAFE_FROG:
			// is there NOT a frog standing on us?

			if (!(live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG))
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_HIT_FROG:
			// has a frog hit us?
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break;

		//----------------------------------------------------------------------------------------
		case ENTSCR_NO_HIT_FROG:
			// has a frog NOT a hit us?
			if (!(live_entity->le_flags & LIVE_ENTITY_HIT_FROG))
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

		//----------------------------------------------------------------------------------------
		case ENTSCR_RANDOM:
			// Wait for Random Hit.
			if (rand()%script[3] == 1)
				{
				// movement finished, so return from this gosub loop
				return ENTSCR_RETURN_END;
				}
			break; 

		//----------------------------------------------------------------------------------------
		case ENTSCR_ALWAYS:
			return ENTSCR_RETURN_END;
			break;
		}

	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_CHOOSE_RND_CHECKPOINT_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_SHORT	check_id;
	MR_SHORT	once_through;

	once_through = 0;

	// Do a once only random check
	if (rand()%5 < 2)
		{
		// This function tries to find an as yet unreached checkpoint, and sets up a position
		// so that an entity can appear there
		check_id = rand()%5;
		while (1)
			{
			// Has check point been collected, or is it marked as NO_COLLISION, which means something is already
			// marked the checkpoint
			if	(
				!(Checkpoints & (1<<check_id)) &&
				 (Checkpoint_data[check_id].cp_entity->en_flags |= ENTITY_NO_COLLISION)
				)
				{
				MR_COPY_SVEC(&script_info->si_position, &Checkpoint_data[check_id].cp_position);
				script_info->si_user_data = check_id;
				break;
				}

			if (++check_id >= GEN_MAX_CHECKPOINTS)
				{
				check_id = 0;
				once_through++;
				}

			if (once_through > 1)
				{
				// failed, so just return... (this should never happen)
				MR_SET_SVEC(&script_info->si_position, 0, -20000, 0);
				break;
				}
			}
		}
	else
		{
		// failed, so just return... (this should never happen)
		MR_SET_SVEC(&script_info->si_position, 0, -20000, 0);
		}

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_APPEAR_ENTITY_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// make our entity appear at the precalculated position
	MR_VEC_EQUALS_SVEC((MR_VEC*)live_entity->le_lwtrans->t, &script_info->si_position);

	// make it appear
	live_entity->le_entity->en_flags &= ~ENTITY_HIDDEN;
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_DISAPPEAR_ENTITY_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// make it disappear... 
	live_entity->le_entity->en_flags |= ENTITY_HIDDEN;
	live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;
	
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
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_POINTS_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
//	FROG*		frog;
	MR_USHORT	frog_index;

	// search for all 4 possible frogs
	frog_index = 0;
	while (frog_index < 4)
		{
		if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_index))
			{	
			// we have found our frog.. 

			}
		frog_index++;
		}
	
	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_LIVES_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
//	FROG*		frog;
	MR_USHORT	frog_index;

	// search for all 4 possible frogs
	frog_index = 0;
	while (frog_index < 4)
		{
		if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_index))
			{	
			// we have found our frog.. 

			}
		frog_index++;
		}

	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_AWARD_FROG_TIME_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
//	FROG*		frog;
	MR_USHORT	frog_index;

	// search for all 4 possible frogs
	frog_index = 0;
	while (frog_index < 4)
		{
		if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_index))
			{	
			// we have found our frog.. 

			}
		frog_index++;
		}

	// move to next instruction
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_STOP_ROTATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// stop rotation
	script_info->si_dx_count = 0;
	script_info->si_dy_count = 0;
	script_info->si_dz_count = 0;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_STOP_DEVIATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// stop deviation
	script_info->si_dev_dx_count = 0;
	script_info->si_dev_dy_count = 0;
	script_info->si_dev_dz_count = 0;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_CLEAR_DEVIATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// stop deviation
	script_info->si_dev_dx = 0;
	script_info->si_dev_dy = 0;
	script_info->si_dev_dz = 0;
	script_info->si_dev_dest_x = 0;
	script_info->si_dev_dest_y = 0;
	script_info->si_dev_dest_z = 0;
	script_info->si_dev_x = 0;
	script_info->si_dev_y = 0;
	script_info->si_dev_z = 0;
	script_info->si_dev_dx_count = 0;
	script_info->si_dev_dy_count = 0;
	script_info->si_dev_dz_count = 0;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PREPARE_REGISTERS_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_LONG		loop_count;	
	
	// set script register offset
	script_info->si_register_offset		= script[0];
	script_info->si_offset_entity_data	= (MR_BYTE*)script_info->si_entity_data + script_info->si_register_offset;

	// copy register data
	for (loop_count=0; loop_count < script[1]; loop_count++)
		script_info->si_registers[loop_count] = *((MR_LONG*)script_info->si_offset_entity_data + loop_count);

	// move to next instruction
	script_info->si_script = script + 2;
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_RETURN_DEVIATE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	ENTSTR_STATIC*		entity_type;
	ENTITY*				entity;
	MR_USHORT			coord;

	entity 		= live_entity->le_entity;
	entity_type	= (ENTSTR_STATIC*)(entity + 1);
	coord		= script[1];

	if (script[0] == ENTSCR_REGISTERS)
		{
		if (coord > ENTSCR_NEG_COORD_X)
			{
			// a negative coord specified?
			coord -= ENTSCR_NEG_COORD_X;
			(&script_info->si_dev_dest_x)[coord]	= 0;//entity_type->et_matrix.t[coord] - live_entity->le_lwtrans->t[coord];
			(&script_info->si_dev_dx)[coord]		= -script_info->si_registers[script[2]];
			(&script_info->si_dev_dx_count)[coord] 	= -1;
			}
		else
			{
			// a normal coord was specified
			(&script_info->si_dev_dest_x)[coord]	= 0;//entity_type->et_matrix.t[coord] - live_entity->le_lwtrans->t[coord];
			(&script_info->si_dev_dx)[coord]		= script_info->si_registers[script[2]];
			(&script_info->si_dev_dx_count)[coord] 	= -1;
			}
		}
	else
		{
		if (coord > ENTSCR_COORD_Z)
			{
			// a negative coord specified?
			coord -= ENTSCR_NEG_COORD_X;
			(&script_info->si_dev_dest_x)[coord]	= 0;//entity_type->et_matrix.t[coord] - live_entity->le_lwtrans->t[coord];
			(&script_info->si_dev_dx)[coord]		= -script[2];
			(&script_info->si_dev_dx_count)[coord] 	= -1;
			}
		else
			{
			// a normal coord was specified
			(&script_info->si_dev_dest_x)[coord]	= 0;//entity_type->et_matrix.t[coord] - live_entity->le_lwtrans->t[coord];
			(&script_info->si_dev_dx)[coord]		= script[2];
			(&script_info->si_dev_dx_count)[coord] 	= -1;
			}
		}

	// move to next command
	script_info->si_script = script + 3;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_REGISTER_CALLBACK_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	script_info->si_script_callback[script[0]]				= script_callback_functions[script[1]];
	script_info->si_script_callback_condition[script[0]]	= script[2];
	script_info->si_script_callback_type[script[0]]			= script[3];
	script_info->si_script_callback_called[script[0]]		= SCRIPT_CALLBACK_NOT_CALLED;

	// move to next command
	script_info->si_script = script + 4;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_SET_ENTITY_TYPE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// set entity type
	script_info->si_entity_type = script[0];

	// move to next command
	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------ Match: https://decomp.me/scratch/m3VMU (By Kneesnap)
MR_LONG	ENTSCR_PLAY_SOUND_DISTANCE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	FROG*		frog;
	MR_USHORT	frog_index;
	MR_LONG		closest_distance;
	MR_SVEC		svec;
	MR_SVEC		svec_offset;
	MR_LONG		value;

	// search for all 4 possible frogs
	frog_index			= 0;
	closest_distance	= 9999999;

	while (frog_index < 4)
		{
		frog = &Frogs[frog_index++];

		// is frog active?
		if (frog->fr_flags & FROG_ACTIVE)
			{
			// Adjust the position of the entity collision point.
			switch(script[3])
				{
				//-------------------------------------------------------------------
				case ENTSCR_COORD_X:
					svec_offset.vx = script[4];
					svec_offset.vy = 0;
					svec_offset.vz = 0;
					break;
				//-------------------------------------------------------------------
				case ENTSCR_COORD_Y:
					svec_offset.vx = 0;
					svec_offset.vy = script[4];
					svec_offset.vz = 0;
					break;
				//-------------------------------------------------------------------
				case ENTSCR_COORD_Z:
					svec_offset.vx = 0;
					svec_offset.vy = 0;
					svec_offset.vz = script[4];
					break;
				//-------------------------------------------------------------------
				}

			MRApplyMatrixSVEC(live_entity->le_lwtrans, (MR_SVEC*)&svec_offset.vx, (MR_SVEC*)&svec_offset.vx);
			svec_offset.vx += live_entity->le_lwtrans->t[0];
			svec_offset.vy += live_entity->le_lwtrans->t[1];
			svec_offset.vz += live_entity->le_lwtrans->t[2];

			svec.vx = frog->fr_lwtrans->t[0] - svec_offset.vx;
			svec.vy = frog->fr_lwtrans->t[1] - svec_offset.vy;
			svec.vz = frog->fr_lwtrans->t[2] - svec_offset.vz;

			closest_distance = MIN(closest_distance, MR_SVEC_MOD(&svec));
			}
		}

	// if closest_distance is less than our allowed distance, play required sound effect
	if (!Game_over_no_new_sound)
		{
		if (script[0] == ENTSCR_REGISTERS)
			{
			if (script_info->si_registers[script[1]] < MR_SQRT(closest_distance))
				MRSNDPlaySound((MR_SHORT)script_info->si_registers[script[2]], NULL, 0, 0);
			}
		else
			{
			value = MR_SQRT(closest_distance);
			if (script[1] > MR_SQRT(closest_distance))
				MRSNDPlaySound((MR_SHORT)script[2], NULL, 0, 0);
			}
		}

	// move to next command
	script_info->si_script	= script + 5;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PLAY_MOVING_SOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_LONG		min_radius;
	MR_LONG		max_radius;

	if (script[1] == ENTSCR_REGISTERS)
		{
		min_radius	= script_info->si_registers[script[2]];
		max_radius	= script_info->si_registers[script[3]];
		}
	else
		{
		min_radius	= script[2];
		max_radius	= script[3];
		}

	if (live_entity->le_moving_sound == NULL)
		{
		PlayMovingSound(live_entity, (MR_SHORT)script[0], min_radius, max_radius);
		}

	// move to next command
	script_info->si_script	= script + 4;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_STOP_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	return ENTSCR_RETURN_BREAK;
}

//------------------------------------------------------------------------------------------------
MR_LONG ENTSCR_MUTATE_MESH_COLOR_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_LONG			height;
	MR_LONG			col_r, col_g, col_b;
	MR_ULONG		i, j;
	MR_MESH_INST**	mesh_inst_pptr;
	MR_MESH_INST*	mesh_inst_ptr;
	
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		height	= MIN(0, live_entity->le_lwtrans->t[1]);
		col_r	= 0x10 + ((height*(0x00 - 0x10)) >> 9);
		col_g	= 0x40 + ((height*(0x20 - 0x40)) >> 9);	
		col_b	= 0x60 + ((height*(0x40 - 0x60)) >> 9);

		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			{
			// Yes ... loop once for each viewport
			for (j = 0; j < Game_total_viewports; j++)
				{
				// Valid instance ?
				if (NULL != live_entity->le_api_insts[j])
					{
					// Yes ... get pointer to mesh inst list
					mesh_inst_pptr = ((MR_ANIM_ENV_INST*)live_entity->le_api_insts[j])->ae_mesh_insts;
		
					// Get pointer to mesh instance
					mesh_inst_ptr = *mesh_inst_pptr;
		
					// Loop once for each model in anim env inst
					i = ((MR_ANIM_ENV_INST*)live_entity->le_api_insts[j])->ae_models;
					while(i--)
						{
						MR_ASSERT (i == 0);

						// Get pointer to mesh instance
						mesh_inst_ptr = *mesh_inst_pptr;
	
						// Set mesh instance base colour
						mesh_inst_ptr->mi_light_flags |= (MR_INST_USE_SCALED_COLOURS|MR_INST_USE_CUSTOM_AMBIENT);

						// here's the ambient
						mesh_inst_ptr->mi_custom_ambient.r	= 0x40;
						mesh_inst_ptr->mi_custom_ambient.g	= 0x80;
						mesh_inst_ptr->mi_custom_ambient.b	= 0xc0;

						mesh_inst_ptr->mi_colour_scale.r	= col_r;
						mesh_inst_ptr->mi_colour_scale.g	= col_g;
						mesh_inst_ptr->mi_colour_scale.b	= col_b;
						
						// Move through pointer list
						mesh_inst_pptr++;
						}
					}
				}
			}
		else
			{
			// Loop once for each viewport
			for (j = 0; j < Game_total_viewports; j++)
				{
				// Valid live entity mesh instance ?
				if (NULL != live_entity->le_api_insts[j])
					{
					// Yes ... get pointer to mesh inst
					mesh_inst_ptr = (MR_MESH_INST*)live_entity->le_api_insts[j];
	
					// Set mesh instance base colour
					mesh_inst_ptr->mi_light_flags |= (MR_INST_USE_SCALED_COLOURS|MR_INST_USE_CUSTOM_AMBIENT);

					mesh_inst_ptr->mi_custom_ambient.r	= 0x40;
					mesh_inst_ptr->mi_custom_ambient.g	= 0x80;
					mesh_inst_ptr->mi_custom_ambient.b	= 0xc0;

					mesh_inst_ptr->mi_colour_scale.r	= col_r;
					mesh_inst_ptr->mi_colour_scale.g	= col_g;
					mesh_inst_ptr->mi_colour_scale.b	= col_b;
					}
				}
			}
		}
	script_info->si_script	= script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_NO_COLL_CHECKPOINT_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	if (Checkpoint_data[script_info->si_user_data].cp_entity)
		Checkpoint_data[script_info->si_user_data].cp_entity->en_flags |= ENTITY_NO_COLLISION;

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}


//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_KILL_SAFE_FROG_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_LONG		frog_id;

	// Look at whether we have a safe frog, and kill it
	if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
		{
		frog_id = 0;
		while (frog_id < 4)
			{
			if (live_entity->le_flags & (LIVE_ENTITY_CARRIES_FROG_0 << frog_id))
				{
				FrogKill(&Frogs[frog_id],script[0],NULL);
				// Check to see if we need ti play SFX when dying.
				if (script[1] != NULL)
					MRSNDPlaySound(script[1], NULL, 0, 0);
				}
			frog_id++;
			}
		}

	script_info->si_script = script + 2;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_COLL_CHECKPOINT_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_LONG		i;

	for (i=0; i<GEN_MAX_CHECKPOINTS; i++)
		{
		if (Checkpoint_data[i].cp_entity)
			Checkpoint_data[i].cp_entity->en_flags &= ~ENTITY_NO_COLLISION;
		}

	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_CHANGE_ENTITY_ANIM_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// Check to make sure that this is an animated model.
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		// Only change if displayed.
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)script[0]);
			else
				MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)script[0]);
			}
		}

	script_info->si_script = script + 1;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
// Note from Martin (18:08:97):
// 
// Whoever wrote this command wrote it for suburbia/original turtles, since it uses form id's and
// suchlike to generate ripples... sigh... however, someone then came along and used this command
// for jungle hippo's, the result being that about 10 ripples are created in a strange place...
// So since we are up against it, I've added a big switch/case statement to handle different
// entities... bad, but its too late in the day to worry now
//
MR_LONG	ENTSCR_CREATE_3D_SPRITE_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	MR_OBJECT*	sprite_ptr;
	MR_SVEC		offset;
	MR_ULONG	j;
	MR_LONG		formid;
	
	switch (Game_map_theme)
		{
		case THEME_ORG:
			// Grab form id - 18,19,20 are turtles 1,2,3
			formid = live_entity->le_entity->en_form_book_id;
	
			// First sprite is somewhere in local -ve Z
			MR_SET_SVEC(&offset, 0, -0x40, -((formid - 19) * 128));

			// Create 1,2 or 3 sprites
			j = (formid - 18);
			while(j--)
				{
				sprite_ptr = MRCreate3DSprite((MR_FRAME*)live_entity->le_lwtrans, MR_OBJ_STATIC, TurtleSplashAnimList);
				sprite_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
				sprite_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x10;

				MR_COPY_SVEC(&sprite_ptr->ob_offset, &offset);
				offset.vz += 0x100;

				GameAddObjectToViewports(sprite_ptr);
				}
			break;

		case THEME_JUN:
		default:
			sprite_ptr = MRCreate3DSprite((MR_FRAME*)live_entity->le_lwtrans, MR_OBJ_STATIC, TurtleSplashAnimList);
			sprite_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
			sprite_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x10;
			GameAddObjectToViewports(sprite_ptr);
			break;
		}

	script_info->si_script = script + 1;		 
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_PITCH_BEND_MOVING_SOUND_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
//	NOTE: When pitch bending the default value for a sample to be played at is 64.

	MR_LONG				min_pitch_bend;
	MR_LONG				max_pitch_bend;
	MR_LONG				pitch_bend;
	MR_LONG				sin;
	MR_LONG				sin_speed;
	MR_LONG				shift_range;
	MR_LONG				voice_id;
	MR_LONG				mid_pitch;

	if (script[0] == ENTSCR_REGISTERS)
		{
		min_pitch_bend	= script_info->si_registers[script[1]];
		max_pitch_bend	= script_info->si_registers[script[2]];
		sin_speed		= script_info->si_registers[script[3]];
		shift_range		= script_info->si_registers[script[4]];
		mid_pitch		= script_info->si_registers[script[4]];
		}												   
	else
		{
		min_pitch_bend	= script[1];
		max_pitch_bend	= script[2];
		sin_speed		= script[3];
		shift_range		= script[4];
		mid_pitch		= script[5];
		}

	if	(
		(live_entity->le_moving_sound) &&
		(((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0] != -1)
		)
		{
		// Grab voice id.
		voice_id = ((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0];

		sin = rsin( (script_info->si_timer << sin_speed) );
		sin = sin >> shift_range;
		pitch_bend = mid_pitch - (sin);

		if (pitch_bend < min_pitch_bend)
			pitch_bend = min_pitch_bend;
		else
			{
			if (pitch_bend > max_pitch_bend)
				pitch_bend = max_pitch_bend;
			}

		MRSNDPitchBend(voice_id,pitch_bend);
		}

	// move to next command
	script_info->si_script	= script + 6;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_POP_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	// if effect hasn't been created, create it now
	if (live_entity->le_effect == NULL)
		{
		LiveEntityInitPop(live_entity);
		LiveEntityStartPolyPiecePop(live_entity);
		}
	// move to next command
	script_info->si_script	= script;
	return ENTSCR_RETURN_CONTINUE;
}

/******************************************************************************
*%%%% UpdateScriptInfo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateScriptInfo(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Handles starting and parsing of live entity scripts
*	MATCH		https://decomp.me/scratch/7eHVw	(By Kneesnap)
*
*	INPUTS		live_entity	-	ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*	06.05.97	Martin Kift		Added support for relooping of gosub looped scripts
*	03.11.23	Kneesnap		Byte-matched PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	UpdateScriptInfo(LIVE_ENTITY *live_entity)
{
	ENTITY*			entity;
	SCRIPT_INFO*	script_info;
	MR_LONG			ret;
	MR_LONG			i;
	MR_LONG			cos, sin;
	ENTSTR_STATIC*	ent_static;
	MR_SVEC			svec;
	MR_MAT		  matrix;

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
						(&script_info->si_dev_x)[i] += ((&script_info->si_dev_dx)[i] >> WORLD_SHIFT);
						if ((&script_info->si_dev_x)[i] >= (&script_info->si_dev_dest_x)[i])
							{
							(&script_info->si_dev_x)[i] 		= (&script_info->si_dev_dest_x)[i];
							(&script_info->si_dev_dx)[i] 		= 0;
							(&script_info->si_dev_dx_count)[i]  = 0;
							}
						}
					else if ((&script_info->si_dev_dx)[i] < 0)
						{
						(&script_info->si_dev_x)[i] += ((&script_info->si_dev_dx)[i] >> WORLD_SHIFT);
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
					(&script_info->si_dev_x)[i] += ((&script_info->si_dev_dx)[i] >> WORLD_SHIFT);
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

		// apply our rotation, which is dependent on the entity type
		// (path gets constant addition of deviation, since it gets reset every frame,
		// matrix based add relative to based matrix position)
		if (script_info->si_entity_type == ENTSCR_ENTITY_TYPE_PATH)
			{
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
			}
		else
			{
			if ((script_info->si_x) ||
				(script_info->si_y) ||
				(script_info->si_z))
				{
				ent_static = (ENTSTR_STATIC*)(entity + 1);
				MR_SET_SVEC(&svec, script_info->si_x, script_info->si_y, script_info->si_z);
				MRRotMatrix(&svec, &matrix);
				MRMulMatrixABC(&matrix, &ent_static->et_matrix, live_entity->le_lwtrans);
				}
			}

		// apply our deviation (translation), which is dependent on the entity type
		// (path gets constant addition of deviation, since it gets reset every frame,
		// matrix based add relative to based matrix position)
		if (script_info->si_entity_type == ENTSCR_ENTITY_TYPE_PATH)
			{
			live_entity->le_lwtrans->t[0] += script_info->si_dev_x;
			live_entity->le_lwtrans->t[1] += script_info->si_dev_y;
			live_entity->le_lwtrans->t[2] += script_info->si_dev_z;
			}
		else
			{
			ent_static = (ENTSTR_STATIC*)(entity + 1);
			live_entity->le_lwtrans->t[0] = ent_static->et_matrix.t[0] + script_info->si_dev_x;
			live_entity->le_lwtrans->t[1] = ent_static->et_matrix.t[1] + script_info->si_dev_y;
			live_entity->le_lwtrans->t[2] = ent_static->et_matrix.t[2] + script_info->si_dev_z;
			}

		// Update any registered callback functions, but only call if either 'call every frame',
		// or 'call once and not called already'
		UpdateScriptCallbacks(script_info, live_entity);

		// Update timer
		script_info->si_timer++;

		// Consider action on leaving script
		switch(ret)		
			{
			case ENTSCR_RETURN_BREAK:
				break;

			case ENTSCR_RETURN_END:
				// were we in a subroutine script? In which case, consider going back to where we
				// were in the previous script
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

	script_info->si_flags 		= SCRIPT_INFO_ACTIVE;
	script_info->si_type		= script_type;
	script_info->si_script		= Scripts[script_type];

	// setup entity data pointer
	script_info->si_entity_data	= ((ENTITY*)live_entity->le_entity) + 1;
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

	// default to path based entity
	script_info->si_entity_type = ENTSCR_ENTITY_TYPE_PATH;
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


/******************************************************************************
*%%%% UpdateScriptCallbacks
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateScriptCallbacks(
*									SCRIPT_INFO*	script_info,
*									LIVE_ENTITY*	live_entity)
*								
*	FUNCTION	Checks for a registered callback and condition, and if that
*				condition is meet, the callback is called.
*
*	INPUTS		script_info		- ptr to script's SCRIPT_INFO structure.
*				live_entity		- ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID UpdateScriptCallbacks(	SCRIPT_INFO* script_info, 
								LIVE_ENTITY* live_entity)
{
	MR_LONG		i;

	for (i=0; i<ENTSCR_MAX_CALLBACKS; i++)
		{
		if (script_info->si_script_callback[i])
			{
			if ((script_info->si_script_callback_type[i] == ENTSCR_CALLBACK_ALWAYS) ||
				(script_info->si_script_callback_called[i] != SCRIPT_CALLBACK_CALLED))
				{
				// check condition of gosubing to new script
				switch (script_info->si_script_callback_condition[i])
					{
					//----------------------------------------------------------------------------------------
					case ENTSCR_NO_CONDITION:
						(script_info->si_script_callback[i]) (live_entity);
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_SAFE_FROG:
						// is there a frog standing on us?
						if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_NO_SAFE_FROG:
						// is there NOT a frog standing on us?

						if (!(live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG))
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_HIT_FROG:
						// has a frog hit us?
						if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_NO_HIT_FROG:
						// has a frog NOT a hit us?
						if (!(live_entity->le_flags & LIVE_ENTITY_HIT_FROG))
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_DEVIATED:
						if ((!script_info->si_dev_dx_count) &&
							(!script_info->si_dev_dy_count) &&
							(!script_info->si_dev_dz_count))
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;

					//----------------------------------------------------------------------------------------
					case ENTSCR_ROTATED:
						if ((!script_info->si_dx_count) &&
							(!script_info->si_dy_count) &&
							(!script_info->si_dz_count))
							{
							(script_info->si_script_callback[i]) (live_entity);
							}
						break;
					}
				}
			}
		}
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_NO_COLLISION_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	live_entity->le_entity->en_flags |= ENTITY_NO_COLLISION;

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}

//------------------------------------------------------------------------------------------------
MR_LONG	ENTSCR_COLLISION_command(LIVE_ENTITY* live_entity, SCRIPT_INFO* script_info, MR_LONG* script)
{
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;

	// move to next instruction
	script_info->si_script = script;
	return ENTSCR_RETURN_CONTINUE;
}
