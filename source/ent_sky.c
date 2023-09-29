/******************************************************************************
*%%%% ent_sky.c
*------------------------------------------------------------------------------
*
*	Sky code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "ent_sky.h"
#include "scripter.h"
#include "scripts.h"
#include "sound.h"

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_magical_popping_balloon_pop[] =
	{
	ENTSCR_POP,
	ENTSCR_PLAY_SOUND,			SFX_SKY_RUBBER_BALLOON_FART,				// play sound effect
	ENTSCR_END,																// stop processing
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_magical_popping_balloon[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_HIT_FROG,	SCRIPT_SKY_MAGICAL_POPPING_BALLOON_POP,	0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Sky helicopter 
//
// It goes up and down... woo err
//

MR_LONG		script_sky_helicopter[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_FROG_HELICOPTER,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),		2,
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,

	ENTSCR_PLAY_MOVING_SOUND,		SFX_SKY_HELICOPTER_NOISE,
									ENTSCR_NO_REGISTERS,		1024,	3072,
	ENTSCR_SETLOOP,
		ENTSCR_DEVIATE,				ENTSCR_REGISTERS,	ENTSCR_COORD_Y,		ENTSCR_REGISTER_0,	ENTSCR_REGISTER_1,	-1,
		ENTSCR_WAIT_DEVIATED,
		ENTSCR_RETURN_DEVIATE,		ENTSCR_REGISTERS,	ENTSCR_NEG_COORD_Y,	ENTSCR_REGISTER_1,
		ENTSCR_WAIT_DEVIATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSkyFrogHelicopter(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SKY_HELICOPTER_FROG_KILL, NULL, 0, 0);
}

//------------------------------------------------------------------------------------------------
// Sky homing birds 
//
// It chases the frog at a set speed...
//

MR_LONG		script_sky_homing_bird_hit_frog[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,		20,			SFX_SKY_HAWK_CALL,
									ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_homing_bird[] =
	{
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),		2,
	ENTSCR_SET_ACTION,				1,
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_BIRD4_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
	ENTSCR_SETLOOP,
		ENTSCR_HOME_IN_ON_FROG,		ENTSCR_REGISTERS,	ENTSCR_REGISTER_0,	ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// SKY rubber balloon script(s)
//
// Opposite of the helium balloon, which sinks instead of rises!
//
// To achieve this, several scripts are needed (see below)
//

MR_LONG		script_sky_rubber_balloon_popping[] =
	{
	ENTSCR_POP,
	ENTSCR_PLAY_SOUND,			SFX_SKY_RUBBER_BALLOON_FART,		// play sound effect
	ENTSCR_EJECT_FROG,			ENTSCR_NO_REGISTERS, 0,	0,			// eject frog 
	ENTSCR_NO_COLLISION,											// turn off collision
	ENTSCR_END,														// stop processing
	};

MR_LONG		script_sky_rubber_balloon_rising[] =
	{
	ENTSCR_RETURN_DEVIATE,			ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,			-0x10<<8,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_DEVIATED,		SCRIPT_SKY_RUBBER_BALLOON_WAITING,		0,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_SAFE_FROG,		SCRIPT_SKY_RUBBER_BALLOON_SINKING,		0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_rubber_balloon_sinking[] =
	{
	ENTSCR_PLAY_SOUND,				SFX_SKY_RUBBER_BALLOON_SQUEAK,
	ENTSCR_DEVIATE,					ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,			0x400,	0x10<<8,	-1,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_DEVIATED,		SCRIPT_SKY_RUBBER_BALLOON_POPPING,		0,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_NO_SAFE_FROG,	SCRIPT_SKY_RUBBER_BALLOON_RISING,		0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_rubber_balloon_waiting[] =
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			3,
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	ENTSCR_APPEAR_ENTITY,
	ENTSCR_CLEAR_DEVIATE,															// clear deviation
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_SAFE_FROG,		SCRIPT_SKY_RUBBER_BALLOON_SINKING,		0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_bird1_1[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_BIRD1_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SKY_BIRD1_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,

	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SKY_BIRD1_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSkyBird1Call(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SKY_PELICAN_CALL_FRENZIED, NULL, 0, 0);
}

MR_LONG	script_sky_bird1_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SKY_PELICAN_CALL,
										ENTSCR_COORD_Z,			    128,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_bird2_1[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_BIRD2_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SKY_BIRD1_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,

	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SKY_BIRD2_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSkyBird2Call(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SKY_CROW_CALL_FRENZIED, NULL, 0, 0);
}

MR_LONG	script_sky_bird2_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SKY_CROW_CALL,
										ENTSCR_COORD_Z,			    128,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_bird3_1[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_BIRD3_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SKY_BIRD1_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,

	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SKY_BIRD3_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSkyBird3Call(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SKY_SEAGULL_CALL_FRENZIED, NULL, 0, 0);
}

MR_LONG	script_sky_bird3_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SKY_SEAGULL_CALL,
										ENTSCR_COORD_Z,			    128,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_bird4_1[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_SKY_BIRD4_CALL,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,		SFX_SKY_BIRD1_WING,
									ENTSCR_NO_REGISTERS,		1024,	2048,
	ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_SKY_BIRD4_CALL_SFX,	4,

	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,	10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_VOID	ScriptCBSkyBird4Call(LIVE_ENTITY* live_entity)
{
	MRSNDPlaySound(SFX_SKY_DUCK_CALL_FRENZIED, NULL, 0, 0);
}

MR_LONG	script_sky_bird4_call_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		30,		SFX_SKY_DUCK_CALL,
										ENTSCR_COORD_Z,			    128,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_jet1[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,			SFX_SKY_JET1,
										ENTSCR_NO_REGISTERS,	1024,	2048,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_jet3[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,			SFX_SKY_JET3,
										ENTSCR_NO_REGISTERS,	1024,	2048,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
MR_LONG		script_sky_biplane[] =
	{
	ENTSCR_SETLOOP,
	ENTSCR_PLAY_MOVING_SOUND,			SFX_SKY_BIPLANE1,
										ENTSCR_NO_REGISTERS,	768,	1536,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
// SKY helium balloon script(s)
//
// Balloon waits for a frog to jump on it, at which point it starts rising, and comes back down
// if the frog jumps off. If it gets to a high level, it pops!
//
// To achieve this, several scripts are needed (see below)
//

MR_LONG		script_sky_helium_balloon_popping[] =
	{
	ENTSCR_POP,															// pop 
	ENTSCR_PLAY_SOUND,			SFX_GEN_FROG_CROAK,						// play sound effect
	ENTSCR_PLAY_SOUND,			SFX_SKY_HELIUM_BALLOON_POP,				// play sound effect
	ENTSCR_EJECT_FROG,			ENTSCR_NO_REGISTERS,		0,	0,		// eject frog
	ENTSCR_NO_COLLISION,												// turn off collision
	ENTSCR_END,															// stop processing
	};

MR_LONG		script_sky_helium_balloon_rising[] =
	{
	ENTSCR_CLEAR_DEVIATE,															// clear deviation
	ENTSCR_DEVIATE,				ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,			-0x600,	-0x10<<8,	-1,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_DEVIATED,		SCRIPT_SKY_HELIUM_BALLOON_POPPING,		0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_helium_balloon_sinking[] =
	{
	ENTSCR_RESTART,
	};

MR_LONG		script_sky_helium_balloon_waiting[] =
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),				2,
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,			SCRIPT_CB_SKY_HELIUM_BALLOON, ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,
	ENTSCR_APPEAR_ENTITY,
	ENTSCR_CLEAR_DEVIATE,															// clear deviation
	ENTSCR_SETLOOP,
		ENTSCR_DEVIATE,				ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0,	0x5<<8,		10,
		ENTSCR_WAIT_DEVIATED,
		ENTSCR_DEVIATE,				ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0,	-0x5<<8,	10,
		ENTSCR_WAIT_DEVIATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBSkyHeliumBalloon(LIVE_ENTITY* live_entity)
{
	START_NEW_SCRIPT((SCRIPT_INFO*)live_entity->le_script, SCRIPT_SKY_HELIUM_BALLOON_RISING);
} 


