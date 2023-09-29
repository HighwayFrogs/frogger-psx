/******************************************************************************
*%%%% ent_jun.c
*------------------------------------------------------------------------------
*
*	Jungle entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "ent_jun.h"
#include "scripts.h"
#include "scripter.h"
#include "frog.h"
#include "ent_sub.h"
#include "ent_org.h"
#include "sound.h"
#include "gen_gold.h"

MR_LONG		Jun_outro_gold_frog_jumps[9][13] =
	{
		{ 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,-1},
		{ 1, 0, 0, 0, 0, 1, 1, 0, 0, 0,-1,-1,-1},
		{ 1, 0, 0, 1, 1, 0, 0, 0,-1,-1,-1,-1,-1},
		{ 1, 1, 1, 0, 0, 0,-1,-1,-1,-1,-1,-1,-1},
		{ 3, 3, 3, 0, 0, 0,-1,-1,-1,-1,-1,-1,-1},
		{ 3, 0, 0, 3, 3, 0, 0, 0,-1,-1,-1,-1,-1},
		{ 3, 0, 0, 0, 0, 3, 3, 0, 0, 0,-1,-1,-1},
		{ 3, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0,-1},
		{ 2, 2, 1, 1, 0, 0, 0, 0, 3, 3, 0, 0, 0},
	};

MR_LONG		Jun_outro_frog_jumps[13] =
	{
	1, 0, 0, 3, 3, 3, 3, 2, 2, 3, 3, 3, -1
	};

/******************************************************************************
*%%%% ENTSTRJunCreatePlant
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreatePlant(LIVE_ENTITY* live_entity)
*
*	FUNCTION	Create a jungle snapping plant
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreatePlant(LIVE_ENTITY*	live_entity)
{
	JUN_PLANT*			plant_map_data;
	JUN_RT_PLANT*		plant;
	ENTITY*				entity;

	entity 			= live_entity->le_entity;
	plant_map_data	= (JUN_PLANT*)(entity + 1);

	// Create the entity using standard function
	ENTSTRCreateDynamicMOF(live_entity);
	
	// the runtime structure has already been alloced
	plant = (JUN_RT_PLANT*)live_entity->le_specific;

	// set up runtime
	plant->jp_mode	= 0;
	plant->jp_timer	= 0;

	// Set first cel for animation
	LiveEntitySetCel(live_entity, 0);

	if (!(live_entity->le_flags & LIVE_ENTITY_FLIPBOOK))
		MRAnimEnvSingleCreateLWTransforms(live_entity->le_api_item0);
}

/******************************************************************************
*%%%% ENTSTRJunUpdatePlant
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunUpdatePlant(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a jungle plant
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunUpdatePlant(LIVE_ENTITY* live_entity)
{
	JUN_PLANT*			plant_map_data;
	JUN_RT_PLANT*		plant;
	ENTITY*				entity;
	MR_LONG				distance;

	entity 			= live_entity->le_entity;
	plant_map_data	= (JUN_PLANT*)(entity + 1);
	plant			= (JUN_RT_PLANT*)live_entity->le_specific;

	switch (plant->jp_mode)
		{
		case JUN_PLANT_WAITING:
			// Set and stop on first frame of anim 
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;

			// has frog entering one grid square distance?
			distance = DistanceToFrogger(live_entity, ENTSCR_COORD_Z, 0);
			if (distance < JUN_PLANT_HIT_DISTANCE)
				{
				// go into snap mode
				plant->jp_mode	= JUN_PLANT_WAITING_TO_SNAP;
				plant->jp_timer	= plant_map_data->jp_snap_time;
				}
			break;
	
		case JUN_PLANT_WAITING_TO_SNAP:
			// count down timer
			if (!(plant->jp_timer--))
				{
				// set anim to go 
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;
				plant->jp_mode	= JUN_PLANT_SNAPPING;
				// Play SFX for Plant Snapping. (If close enough!)
				PlaySoundDistance(live_entity, SFX_JUN_PLANT_SNAP, 30);
				}
			break;

		case JUN_PLANT_SNAPPING:
			// Wait for anim to end
			if (LiveEntityCheckAnimationFinished(live_entity))
				{
				plant->jp_mode	= JUN_PLANT_DELAY_AFTER_SNAPPING;
				plant->jp_timer	= plant_map_data->jp_snap_delay;
				}
			break;

		case JUN_PLANT_DELAY_AFTER_SNAPPING:
			if (!(plant->jp_timer--))
				{
				// Set first cel for animation
				LiveEntitySetCel(live_entity, 0);

				plant->jp_mode	= JUN_PLANT_WAITING;
				}
			break;
		}
}


//------------------------------------------------------------------------------------------------
// Jun floating tree
//
// These wait for the frog to hit them (they are initially paused on their path) and proceed to
// move down their spline (one shot) after a defined delay
//

MR_LONG		script_jun_floating_tree_moving[] =
	{
	ENTSCR_UNPAUSE_ENTITY_ON_PATH,
	ENTSCR_END,
	};

MR_LONG		script_jun_floating_tree[] =
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(PATH_INFO),			1,
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_GOSUB_SCRIPT,		ENTSCR_SAFE_FROG,	SCRIPT_JUN_FLOATING_TREE_MOVING,	0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART																												
	};

/******************************************************************************
*%%%% ENTSTRJunCreateRopeBridge
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateRopeBridge(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a rope bridge for jungle level
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRJunCreateRopeBridge(LIVE_ENTITY*	live_entity)
{
	JUN_RT_ROPE_BRIDGE*		bridge;

	// Use standard matrix-based entity creation function
	ENTSTRCreateDynamicMOF(live_entity);

	// Get pointer to runtime structre.  The runtime structure has already been alloced.
	bridge = (JUN_RT_ROPE_BRIDGE*)live_entity->le_specific;

	// Initialise run time data
	bridge->rb_state		= JUN_ROPE_BRIDGE_WAITING_FOR_HITS;
	bridge->rb_current_wait = 0;
	bridge->rb_num_hits		= 0;

	// Probably need to set the animation in here somewhere as well.
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;

	// Set it up as a one shot, just in case
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

	// turn on collision for this entity
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
}

/******************************************************************************
*%%%% ENTSTRJunUpdateRopeBridge
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateRopeBridge(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the rope bridge for jun
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.07.97	Martin Kift		Created.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunUpdateRopeBridge(LIVE_ENTITY*	live_entity)
{
	ENTITY*	  				entity;
	JUN_ROPE_BRIDGE*		bridge_map_data;
	JUN_RT_ROPE_BRIDGE*		bridge;
	FROG*					frog;
	MR_ULONG				frog_index;

	// Get pointer to runtime structure
	entity 			= live_entity->le_entity;
	bridge_map_data	= (JUN_ROPE_BRIDGE*)(entity + 1);
	bridge			= (JUN_RT_ROPE_BRIDGE*)live_entity->le_specific;

	// Depending on mode of operation do ...
	switch (bridge->rb_state)
		{
		// -------------------------------------------------------------------------
		case JUN_ROPE_BRIDGE_WAITING_FOR_HITS:
			// Waiting for a hit from Frogger.
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// We have just been hit by the Frog, increase number of hits received.
				bridge->rb_num_hits++;
	
				// We we arn't passed our limit.
				if (bridge->rb_num_hits >= bridge_map_data->rb_hops_before)
					{
					// Best we start falling.
					bridge->rb_current_wait = bridge_map_data->rb_fall_delay;
					bridge->rb_state		= JUN_ROPE_BRIDGE_WAITING_TO_FALL;
					}
				}
			break;
		// -------------------------------------------------------------------------
		case JUN_ROPE_BRIDGE_WAITING_TO_FALL:
			// Wait for delay, before falling.
			if (bridge->rb_current_wait-- <= 0) 
				{
				bridge->rb_state = JUN_ROPE_BRIDGE_FALLING;
	
				// make anim go
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;

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
		
		// -------------------------------------------------------------------------
		case JUN_ROPE_BRIDGE_FALLING:
			break;
		// -------------------------------------------------------------------------
		}

}

/******************************************************************************
*%%%% ENTSTRJunCreateHippo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateHippo(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a a jungle Hippo.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Gary Richards	Created. (Although this is really a turtle, except
*								it has to have it's own create functions and scripts
*								so it can play it's own SFX's.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreateHippo(LIVE_ENTITY*	live_entity)
{
	SUBURBIA_TURTLE*	turtle;
	ENTITY*				entity;

	entity	= live_entity->le_entity;
	turtle	= (SUBURBIA_TURTLE*)(entity + 1);

	ENTSTRCreateMovingMOF(live_entity);

	// if not a diving type, revert to the non diving script
	if (turtle->st_turtle_type == SUB_TURTLE_NOTDIVING)
		StartScript((SCRIPT_INFO*)live_entity->le_script, SCRIPT_JUN_HIPPO_NO_DIVE, live_entity);
}

//------------------------------------------------------------------------------------------------
// Scripts
//------------------------------------------------------------------------------------------------
MR_LONG		script_jun_hippo[] =
	{
	ENTSCR_PREPARE_REGISTERS,			sizeof(PATH_INFO),				3,
	ENTSCR_SET_ENTITY_TYPE,				ENTSCR_ENTITY_TYPE_PATH,
	ENTSCR_REGISTER_CALLBACK,			ENTSCR_CALLBACK_1,				SCRIPT_CB_DIVE_COLOUR_CHANGE,	ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,
	ENTSCR_REGISTER_CALLBACK,			ENTSCR_CALLBACK_2,				SCRIPT_CB_JUN_HIPPO_HIT,		ENTSCR_HIT_FROG,		ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		// May be Play SFX at top of Swim.
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_JUN_HIPPO_SFX,	4,
		// Swim for mappy defined frames
		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_0,

		// Deviate through set distance (and speed), waiting for deviation to finish
		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0x80, 0x8<<8, -1,

		//ENTSCR_PLAY_SOUND,					SFX_JUB_HIPPO_SPLASH,
		ENTSCR_CREATE_3D_SPRITE,			0,
		ENTSCR_WAIT_DEVIATED,		
		ENTSCR_KILL_SAFE_FROG,				0,	NULL,

		// Swim (submerged) for mappy defined frames
		ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,

		ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_REGISTERS,			ENTSCR_REGISTER_1,

		// Deviate through set distance (and speed), waiting for deviation to finish, play splash at end!
		ENTSCR_DEVIATE,						ENTSCR_NO_REGISTERS,		ENTSCR_COORD_Y,		0, -0x8<<8, -1,

		ENTSCR_WAIT_DEVIATED,		
		//ENTSCR_PLAY_SOUND,					SFX_JUN_HIPPO_SPLASH,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Jun Hippo Script. (NO DIVE) Wait to randomly trigger the Hippo growl
MR_LONG	script_jun_hippo_no_dive[] =
	{
	ENTSCR_REGISTER_CALLBACK,		ENTSCR_CALLBACK_1,		SCRIPT_CB_JUN_HIPPO_HIT,		ENTSCR_HIT_FROG,	ENTSCR_CALLBACK_ONCE,

	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_JUN_HIPPO_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		20,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_jun_hippo_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_JUN_HIPPO,
										ENTSCR_COORD_Z,  		 0,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBJunHippoHit(LIVE_ENTITY* live_entity)
{
	//MRSNDPlaySound(SFX_JUN_HIPPO_THUD, NULL, 0, 0);
}


//------------------------------------------------------------------------------------------------
// Jun Water Noise.
//

MR_LONG		script_jun_water_noise[] = 
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_JUN_WATER_NOISE,			//    MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// Wait to randomly trigger the Monkey Noise.
MR_LONG		script_jun_monkey[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_JUN_MONKEY_SFX,			4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		20,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_JUN_MONKEY_SCREAM_SFX,	4,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_jun_monkey_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_JUN_MONKEY_CHAT,
										ENTSCR_COORD_Z,  		 0,
	ENTSCR_RESTART,
	};

MR_LONG		script_jun_monkey_scream_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_JUN_MONKEY_SCREAM,
										ENTSCR_COORD_Z,  		 0,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Jun crocodile
//
MR_LONG		script_jun_crocodile[] =
	{
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,		30,
	ENTSCR_SET_ACTION,				ORG_ACTION_CROCODILE_SNAPPING,
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_NO_REGISTERS,		30,
	ENTSCR_SET_ACTION,				ORG_ACTION_CROCODILE_SWIMMING,
	// Play snap sound when animation finishes.
	ENTSCR_PLAY_MOVING_SOUND,		SFX_JUN_FROG_CROC_SNAP,		//  MIN		MAX.
									ENTSCR_NO_REGISTERS,			768,	1536,
	ENTSCR_RESTART,
	};


//------------------------------------------------------------------------------------------------
// Jun Scorpion
//

MR_LONG		script_jun_scorpion[] =
	{
	ENTSCR_SETLOOP,

		ENTSCR_PLAY_MOVING_SOUND,		SFX_JUN_SCORPION,		
										ENTSCR_NO_REGISTERS,	512,		1536,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// Wait to randomly trigger the Rhino Growl
MR_LONG		script_jun_rhino[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,		ENTSCR_RANDOM,		SCRIPT_JUN_RHINO_SFX,	4,
	ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_NO_REGISTERS,		20,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

MR_LONG		script_jun_rhino_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_JUN_RHINO_GROWL,
										ENTSCR_COORD_Z,  		 0,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Jun Piranaha Script.

MR_LONG	script_jun_piranaha[] =
	{
	ENTSCR_REGISTER_CALLBACK,	ENTSCR_CALLBACK_1,	SCRIPT_CB_JUN_PIRANAHA,	ENTSCR_NO_CONDITION,	ENTSCR_CALLBACK_ALWAYS,
	ENTSCR_STOP,
	};

//------------------------------------------------------------------------------------------------
MR_VOID	ScriptCBJunPiranaha(LIVE_ENTITY* live_entity)
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
			col_g	= 0x60;
			col_b	= 0xA0;
			SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
			SetLiveEntityCustomAmbient(live_entity, 0x40, 0x40, 0xd0);
			}
		else
			{
			// Change colour back to normal.
			col_r	= 0x80;	
			col_g	= 0x80;
			col_b	= 0x80;
			SetLiveEntityScaleColours(live_entity, col_r, col_g, col_b);
			SetLiveEntityCustomAmbient(live_entity, 0x40, 0x40, 0x40);
			}
	
		// Ensure fade code respects the values we have set
		live_entity->le_flags |= (LIVE_ENTITY_RESPECT_SCALE_COLOURS | LIVE_ENTITY_RESPECT_AMBIENT_COLOURS);
		}
}


/******************************************************************************
*%%%% ENTSTRJunCreateOutroDoor
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateOutroDoor(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a outro door
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreateOutroDoor(LIVE_ENTITY*	live_entity)
{
	// Create mof, and pause its animation
	ENTSTRCreateStationaryMOF(live_entity);

	MR_ASSERT (live_entity->le_api_item0);
//	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);
//	LiveEntitySetCel(live_entity, 0);
//	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
//	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;
}

/******************************************************************************
*%%%% ENTSTRJunCreateStatue
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateStatue(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a statue
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreateStatue(LIVE_ENTITY*	live_entity)
{
	// Create mof, and pause its animation
	ENTSTRCreateStationaryMOF(live_entity);
}


/******************************************************************************
*%%%% ENTSTRJunCreatePlinth
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreatePlinth(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a plinth
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*	08.08.97	Gary Richards	Changed so that plinth is now an index into a 
*								look-up table.
*
*%%%**************************************************************************/

MR_UBYTE	jun_plinth_table[]=
{
	50+JUNGLE_WAD_OFFSET,	// Actually plinth included in the map.
	0,						// These's are at the top of the WAD.
	1,
	2,
	3,
	4,
	5,
	6,
	7,
};

MR_VOID	ENTSTRJunCreatePlinth(LIVE_ENTITY*	live_entity)
{
	JUN_OUTRO_FROGPLINTH_DATA*		data;
	ENTITY*							entity;
	MR_LONG							mof_id;
	FORM_BOOK*						form_book;
	MR_MOF*							mof;

	// The model for this plinth is based on its number (0 to 7 plus form model id)
	entity					= live_entity->le_entity;
	data					= (JUN_OUTRO_FROGPLINTH_DATA*)(entity+1);
	form_book				= ENTITY_GET_FORM_BOOK(live_entity->le_entity);
	live_entity->le_lwtrans = &data->op_matrix;

	// work out mof id and get pointer to mof
#ifdef	MR_DEBUG
	MR_ASSERTMSG (data->op_id < 8, "Illegal plinth id, should be 0 to 7");
#endif
	// This is now a index.
	mof_id		= jun_plinth_table[data->op_id];
	mof			= Map_mof_ptrs[mof_id];

	live_entity->le_api_item0 	= MRCreateMesh(	mof,
								   				(MR_FRAME*)live_entity->le_lwtrans,	
								   				MR_OBJ_STATIC,
								   				NULL);
#ifdef ENTITY_DEBUG_PLOT_STATIC_BBOX	
	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_PART_BBOX;
#endif
#ifdef ENTITY_DEBUG_PLOT_COLLPRIMS
	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;
#endif
	// Add mesh to viewport(s)
	GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);
	live_entity->le_flags &= ~LIVE_ENTITY_ANIMATED;
}


/******************************************************************************
*%%%% ENTSTRJunCreateGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a gold frog
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreateGoldFrog(LIVE_ENTITY*	live_entity)
{
	JUN_OUTRO_RT_GOLD_FROG*	frog;

	live_entity->le_entity->en_flags &= ~ENTITY_NO_DISPLAY;
	ENTSTRCreateStationaryMOF(live_entity);
	live_entity->le_entity->en_flags |= ENTITY_NO_DISPLAY;

	// setup runtime
	frog				= (JUN_OUTRO_RT_GOLD_FROG*)live_entity->le_specific;
	frog->op_counter	= 0;
	frog->op_mode		= JUN_GOLD_FROG_SITTING;

	// make it vanish
	MR_ASSERT (live_entity->le_api_item0);
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK);
		
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_DISPLAY;

	LiveEntitySetAction(live_entity, GEN_GOLD_FROG_BACKFLIP);
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;

	live_entity->le_entity->en_flags |= ENTITY_NO_DISPLAY;
}

/******************************************************************************
*%%%% ENTSTRJunUpdateGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunUpdateGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a gold frog
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunUpdateGoldFrog(LIVE_ENTITY*	live_entity)
{
	JUN_OUTRO_RT_GOLD_FROG*	frog;

	frog = (JUN_OUTRO_RT_GOLD_FROG*)live_entity->le_specific;

	switch (frog->op_mode)
		{
		case JUN_GOLD_FROG_SITTING:
			break;

		case JUN_GOLD_FROG_JUMPING:
			// If counter is set, jump with provided velocity
			if (!(frog->op_counter--))
				{
				MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, &frog->op_target);
				frog->op_mode = JUN_GOLD_FROG_SITTING;
				
				//LiveEntitySetAction(live_entity, GEN_GOLD_FROG_SIT);
				LiveEntitySetCel(live_entity, 0);
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;
				}
			else
				{
				frog->op_velocity.vy += SYSTEM_GRAVITY;
				live_entity->le_lwtrans->t[0] += (frog->op_velocity.vx>>16);
				live_entity->le_lwtrans->t[1] += (frog->op_velocity.vy>>16);
				live_entity->le_lwtrans->t[2] += (frog->op_velocity.vz>>16);
				}
			MRRotMatrix(&Org_baby_frog_directions[frog->op_direction], live_entity->le_lwtrans);
			break;
		}


}


/******************************************************************************
*%%%% ENTSTRJunKillGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunKillGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a gold frog
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunKillGoldFrog(LIVE_ENTITY*	live_entity)
{
	ENTSTRKillStationaryMOF(live_entity);
}

/******************************************************************************
*%%%% JunJumpGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	JunJumpGoldFrog(
*						LIVE_ENTITY*	live_entity,
*						MR_LONG			jump_dir)
*
*	FUNCTION	Jumps a gold frog
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	JunJumpGoldFrog(	LIVE_ENTITY*	live_entity,
							MR_LONG			jump_dir)
{
	JUN_OUTRO_RT_GOLD_FROG*		frog;
	MR_LONG						grid_x, grid_z, s, u, y1;
	GRID_STACK*					grid_stack;
	GRID_SQUARE*				grid_square;

	// Jump the gold frog
	frog			= (JUN_OUTRO_RT_GOLD_FROG*)live_entity->le_specific;
	frog->op_mode	= JUN_GOLD_FROG_SITTING;

	// See where we need to go and work out target and velocity
	grid_x = GET_GRID_X_FROM_WORLD_X(live_entity->le_lwtrans->t[0]);
	grid_z = GET_GRID_Z_FROM_WORLD_Z(live_entity->le_lwtrans->t[2]);

	switch (jump_dir)
		{
		case FROG_DIRECTION_N:
			grid_z++;
			break;
		case FROG_DIRECTION_E:
			grid_x++;
			break;
		case FROG_DIRECTION_S:
			grid_z--;
			break;
		case FROG_DIRECTION_W:
			grid_x--;
			break;
		}

	grid_stack 	= GetGridStack(grid_x, grid_z);

	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				y1 = GetGridSquareHeight(grid_square);

				frog->op_target.vx		= (grid_x << 8) + Grid_base_x + 0x80;
				frog->op_target.vy		= y1;
				frog->op_target.vz		= (grid_z << 8) + Grid_base_z + 0x80;

				frog->op_counter		= 6;
				y1						-= live_entity->le_lwtrans->t[1];
				u  						= ((y1 << 16) / (frog->op_counter + 1)) - ((SYSTEM_GRAVITY * (frog->op_counter + 1)) >> 1);
				
				frog->op_velocity.vx 	= ((frog->op_target.vx - live_entity->le_lwtrans->t[0])<<16) / frog->op_counter;
				frog->op_velocity.vy 	= u;
				frog->op_velocity.vz 	= ((frog->op_target.vz - live_entity->le_lwtrans->t[2])<<16) / frog->op_counter;

				frog->op_mode			= JUN_GOLD_FROG_JUMPING;
				frog->op_direction		= jump_dir;

				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= (MR_ANIM_ENV_STEP|MR_ANIM_ENV_ONE_SHOT);
				LiveEntitySetAction(live_entity, GEN_GOLD_FROG_HOP);
				return;
				}
			}
		}
}


/******************************************************************************
*%%%% JunFindEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	JunFindEntity(
*						MR_LONG		form_id,
*						MR_LONG		entity_id)
*
*	FUNCTION	Searches through entities to find our entity
*
*	INPUTS		form_id		- form id to look for
*				entity_id	- entity id to look for (or -1 if not needed)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

LIVE_ENTITY*	JunFindEntity(MR_LONG	form_id, 
							  MR_LONG	entity_id)
{
	LIVE_ENTITY*				live_entity;
	ENTITY*						entity;
	JUN_OUTRO_FROGPLINTH_DATA*	data;

	live_entity = NULL;

	if (entity_id == -1)
		{
		live_entity = GetNextLiveEntityOfType(live_entity, (MR_USHORT)form_id);
		}
	else
		{
		while (live_entity = GetNextLiveEntityOfType(live_entity, (MR_USHORT)form_id))
			{
			// found one, is this the right one?
			entity	= live_entity->le_entity;
			data	= (JUN_OUTRO_FROGPLINTH_DATA*)(entity+1);

			if (data->op_id == entity_id)
				break;
			}
		}
	return live_entity;
}


/******************************************************************************
*%%%% ENTSTRJunCreateBouncyMushroom
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunCreateBouncyMushroom(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a jungle bouncy mushroom
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunCreateBouncyMushroom(LIVE_ENTITY*	live_entity)
{
	// Create normal static
	ENTSTRCreateStationaryMOF(live_entity);

	// Yes ... make animation one shot
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
}

/******************************************************************************
*%%%% ENTSTRJunUpdateBouncyMushroom
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunUpdateBouncyMushroom(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a jungle bouncy mushroom
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunUpdateBouncyMushroom(LIVE_ENTITY*	live_entity)
{
	// Have we been hit by a frog ?
	if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
		;//LiveEntitySetAction(live_entity->le_api_item0, 0);
}


/******************************************************************************
*%%%% ENTSTRJunKillBouncyMushroom
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRJunKillBouncyMushroom(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a jungle bouncy mushroom
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRJunKillBouncyMushroom(LIVE_ENTITY*	live_entity)
{
	// Kill normal static
	ENTSTRKillStationaryMOF(live_entity);
}
