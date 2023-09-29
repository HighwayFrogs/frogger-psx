/******************************************************************************
*%%%% ent_vol.c
*------------------------------------------------------------------------------
*
*	Source code for the	volcano level, which is actually the Industrial.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.07.97	Gary Richards	Created
*	30.07.97	Gary Richards	Added SFX.
*
*%%%**************************************************************************/

#include "ent_vol.h"
#include "scripter.h"
#include "ent_des.h"
#include "frog.h"
#include "sound.h"

//------------------------------------------------------------------------------------------------
// Volcano mechanism
//
// Rise Delay	-	Reg_0
// Rise Speed 	- 	Reg_1
// Fall Delay	-	Reg_2
// Fall Speed 	-	Reg_3
// Height		-	Reg_4
// Once Delay	-	Reg_5
//

MR_ULONG	Vol_switch_table[]=
{
	3+VOLCANO_WAD_OFFSET,	// Actually switches included in the map.
	0,						// These's are at the top of the WAD.
	1,
	2,
	3,
	4,
	5,
	6,
	7,
};

MR_LONG		script_vol_mechanism[] =
	{

	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),		6,
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	// Wait for the Once Only delay.
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,0,						// set time to zero
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_REGISTERS,	ENTSCR_REGISTER_5,		// wait until mappy entered delay
	ENTSCR_SETLOOP,
		// Wait for fall timer to hit zero.
		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,0,					
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_REGISTERS,	ENTSCR_REGISTER_2,	
		// Play SFX.
		ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_IND_HYDRAULIC,
											ENTSCR_COORD_Z,  		 0,
		// Fall until height reaches.		
		ENTSCR_DEVIATE,				ENTSCR_REGISTERS,	ENTSCR_COORD_Y,		ENTSCR_REGISTER_4,	ENTSCR_REGISTER_1,	-1,
		ENTSCR_WAIT_DEVIATED,
		// Wait for rise timer to hit zero.
		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,0,					
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_REGISTERS,	ENTSCR_REGISTER_0,	
		// Play SFX.
		ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,	32,		SFX_IND_HYDRAULIC,
											ENTSCR_COORD_Z,  		 0,
		// Rise back to original position.
		ENTSCR_RETURN_DEVIATE,		ENTSCR_REGISTERS,			ENTSCR_NEG_COORD_Y,	ENTSCR_REGISTER_3,
		ENTSCR_WAIT_DEVIATED,
		ENTSCR_KILL_SAFE_FROG,		FROG_ANIMATION_SQUISHED,	SFX_GEN_FROG_SPLAT,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

/******************************************************************************
*%%%% ENTSTRVolCreateFallingPlatform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRVolCreateFallingPlatform(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Falling platform for industrail level. (No animation for 
*				this entity yet!)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRVolCreateFallingPlatform(LIVE_ENTITY*	live_entity)
{
	DES_RT_CRACK*			rt_crack;

	// Use standard matrix-based entity creation function
	ENTSTRCreateDynamicMOF(live_entity);

	// Get pointer to runtime structre.  The runtime structure has already been alloced.
	rt_crack = (DES_RT_CRACK*)live_entity->le_specific;

	// Initialise run time data
	rt_crack->cr_state		  = DES_CRACK_WAITING_FOR_HITS;
	rt_crack->cr_current_wait = 0;
	rt_crack->cr_num_hits	  = 0;

	// Probably need to set the animation in here somewhere as well.
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK);

	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;
	LiveEntitySetCel(live_entity, 0); 

	// turn on collision for this entity
	live_entity->le_entity->en_flags &= ~ENTITY_NO_COLLISION;
}

/******************************************************************************
*%%%% ENTSTRVolUpdateFallingPlatform
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRVolUpdateFallingPlatform(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the Falling Platform for the industrial.
*				(No animation for this entity yet!)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.07.97	Gary Richards	Created.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRVolUpdateFallingPlatform(LIVE_ENTITY*	live_entity)
{
	ENTITY*	  				entity;
	DES_CRACK*				crack_ptr;
	DES_RT_CRACK*			crack_rt_ptr;
	FROG*					frog;
	MR_ULONG				frog_index;
	MR_MESH*				mesh;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;

	// Get pointer to runtime structure
	entity 			= live_entity->le_entity;
	crack_ptr		= (DES_CRACK*)(entity + 1);
	crack_rt_ptr	= (DES_RT_CRACK*)live_entity->le_specific;
	env_flip		= ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
	mesh			= env_flip->ae_object->ob_extra.ob_extra_mesh;

	// Depending on mode of operation do ...
	switch(crack_rt_ptr->cr_state)
		{
		// -------------------------------------------------------------------------
		case DES_CRACK_WAITING_FOR_HITS:
			// Waiting for a hit from Frogger.
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// We have just been hit by the Frog, increase number of hits received.
				crack_rt_ptr->cr_num_hits++;

				// We we arn't passed our limit.
				if ( crack_rt_ptr->cr_num_hits >= crack_ptr->cr_hops_before )
					{
					// Best we start falling.
					crack_rt_ptr->cr_current_wait = crack_ptr->cr_fall_delay;
					crack_rt_ptr->cr_state = DES_CRACK_WAITING_TO_FALL;
					}
				}
			else
				mesh->me_flags |= MR_MESH_PAUSE_ANIMATED_POLYS;
			break;
		// -------------------------------------------------------------------------
		case DES_CRACK_WAITING_TO_FALL:
			if ( crack_rt_ptr->cr_current_wait-- <= 0 ) 
				{
				// Wait for delay, before falling.
				crack_rt_ptr->cr_state = DES_CRACK_FALLING;

				// Play effect of falling platform.
				MRSNDPlaySound(SFX_IND_PLATFORM_FALLING, NULL, 0, 0);

				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= (MR_ANIM_ENV_STEP|MR_ANIM_ENV_ONE_SHOT);

				//***********************************************************
				// FROG FALLING OFF PLATFORM AS IT FALLS WAS DEEMED TO BE BAD
				//***********************************************************

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
		// This really should be opening, but we don't have the animations for it yet.
		case DES_CRACK_FALLING:
//			if (live_entity->le_lwtrans->t[1] < 1024)
//				live_entity->le_lwtrans->t[1] += 32;		// Temp move it down.
			break;
		// -------------------------------------------------------------------------
		}
}


/******************************************************************************
*%%%% ENTSTRVolCreateColourTrigger
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRVolCreateColourTrigger(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a coloured (animated) trigger entity
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_UBYTE	vol_switch_table[]=
{
	3+VOLCANO_WAD_OFFSET,	// Actually switches included in the map.
	0,						// These's are at the top of the WAD.
	1,
	2,
	3,
	4,
	5,
	6,
	7,
};


MR_VOID	ENTSTRVolCreateColourTrigger(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	VOL_COLOUR_TRIGGER*		trigger;
	VOL_RT_COLOUR_TRIGGER*	rt_trigger;
	FORM_BOOK*				form_book;
	MR_ULONG				mof_id;
	MR_MOF*					mof;

	entity					= live_entity->le_entity;
	trigger					= (VOL_COLOUR_TRIGGER*)(entity+1);
	rt_trigger				= (VOL_RT_COLOUR_TRIGGER*)live_entity->le_specific;
	form_book				= ENTITY_GET_FORM_BOOK(live_entity->le_entity);
	live_entity->le_lwtrans	= &trigger->ct_matrix;

	// Work out mof id
	MR_ASSERTMSG (trigger->ct_colour < 9, "Illegal vol switch colour type");
	mof_id		= Vol_switch_table[trigger->ct_colour];		//Index into lookup table.

	// Examine whether the entity's mof is static or animated, and handle accordingly
	mof	= Map_mof_ptrs[mof_id];

	MR_ASSERT (mof->mm_flags & MR_MOF_FLIPBOOK);

	live_entity->le_api_item0 	= MRAnimEnvFlipbookCreateWhole(	mof, 
															   	MR_OBJ_STATIC,
															   	(MR_FRAME*)live_entity->le_lwtrans);

	// Set a default animation action of zero, default behaviour so to speak
	MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, VOL_SWITCH_ACTION_UP);
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
	
	// set on first frame and stop update
//	MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)live_entity->le_api_item0, 0);
//	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags &= ~MR_ANIM_ENV_STEP;

	// Add environment to viewport(s)
	GameAddAnimEnvToViewportsStoreInstances(live_entity->le_api_item0, (MR_ANIM_ENV_INST**)live_entity->le_api_insts);
	live_entity->le_flags |= (LIVE_ENTITY_ANIMATED | LIVE_ENTITY_FLIPBOOK);

	// Turn off texture animation for this model
	((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_PAUSE_ANIMATED_POLYS;

	// Set up run-time structure
	rt_trigger->ct_forbid_timer	= 0;
	rt_trigger->ct_flags		= VOL_SWITCH_FLAG_FIRST_TIME;
	rt_trigger->ct_state		= VOL_SWITCH_OFF_UP;			// Switch is off and up
}


/******************************************************************************
*%%%% ENTSTRVolUpdateColourTrigger
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRVolUpdateColourTrigger(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a trigger entity
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Martin Kift		Created
*	05.08.97	Gary Richards	Added to reset moving platforms after death.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRVolUpdateColourTrigger(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	VOL_COLOUR_TRIGGER*		trigger;
	VOL_RT_COLOUR_TRIGGER*	rt_trigger;
	LIVE_ENTITY*			trigger_live_entity;
	MR_ULONG				count;
	ENTITY*					triggered_entity;
	VOL_TRIGGERED_PLATFORM*	triggered_platform;

	entity		= live_entity->le_entity;
	trigger		= (VOL_COLOUR_TRIGGER*)(entity+1);
	rt_trigger	= (VOL_RT_COLOUR_TRIGGER*)live_entity->le_specific;


	if (rt_trigger->ct_forbid_timer)
		rt_trigger->ct_forbid_timer--;

	// Check to see if this is the first time through this function.
	if (rt_trigger->ct_flags & VOL_SWITCH_FLAG_FIRST_TIME)
		{
		// Set ALL entities in the list to be PAUSED.
		for (count=0; count<VOL_COLOUR_TRIGGER_MAX_IDS; count++)
			{
			// is ID valid?
			if (trigger->ct_unique_ids[count] != -1)
				{
				// find entity with unique id
				trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->ct_unique_ids[count]);
				
				//	This has to wait for about 3 - 5 frames before all the entities are created.
				if ( trigger_live_entity != NULL )
					{
					// Grab pointers to platform entity.
					triggered_entity   	= trigger_live_entity->le_entity;
					triggered_platform 	= (VOL_TRIGGERED_PLATFORM*)(triggered_entity + 1);

					if (triggered_platform->vt_initial_movement == VOL_INITIAL_MOVEMENT_STOPPED)
						{
						// Flag it as no movement.
						trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
						
						// If entity is path based, PAUSE it.
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
						}
					else
						{
						// Flag it as moving.
						trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						
						// If entity is path based, PAUSE it.
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
						}
					}
				}
			}
		rt_trigger->ct_flags &= ~VOL_SWITCH_FLAG_FIRST_TIME;
		}

	// VOL_SWITCH_FLAG_NO_FROG_CONTACT is only reset if frog was in contact with switch last frame
	if (rt_trigger->ct_flags & VOL_SWITCH_FLAG_NO_FROG_CONTACT)
		{
		switch (rt_trigger->ct_state)
			{
			case VOL_SWITCH_ON_DOWN:
				// Switch is ON and DOWN, but frog has moved off
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, VOL_SWITCH_ACTION_UP);
				rt_trigger->ct_state 		= VOL_SWITCH_ON_UP;
				rt_trigger->ct_forbid_timer	= VOL_SWITCH_FORBID_TIME;
				MRSNDPlaySound(SFX_IND_SWITCH, NULL, 0, 0);
				break;
	
			case VOL_SWITCH_OFF_DOWN:
				// Switch is OFF and DOWN, but frog has moved off
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, VOL_SWITCH_ACTION_UP);
				rt_trigger->ct_state 		= VOL_SWITCH_OFF_UP;
				rt_trigger->ct_forbid_timer	= VOL_SWITCH_FORBID_TIME;
				MRSNDPlaySound(SFX_IND_SWITCH, NULL, 0, 0);
				break;
			}
		}

	rt_trigger->ct_flags |= VOL_SWITCH_FLAG_NO_FROG_CONTACT;
}


/******************************************************************************
*%%%% VolColourTriggerEntityCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID VolColourTriggerEntityCallback(	
*						MR_VOID*		frog,
*						MR_VOID*		live_entity,
*						MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for all trigger entities, which deals
*				(via a switch/case) all types of trigger entities, such as PAUSE
*				etc.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.07.97	Martin Kift		Created
*	12.08.97	Gary Richards	Fixed bug where we get TWO hits to the entity, 
*								which turns it ON/OFF instantly. 
*
*%%%**************************************************************************/

MR_VOID VolColourTriggerEntityCallback(	MR_VOID*	void_frog,
										MR_VOID*	void_live_entity,
										MR_VOID*	void_coll_check)
{
	ENTITY*					entity;
	VOL_COLOUR_TRIGGER*		trigger;
	VOL_RT_COLOUR_TRIGGER*	rt_trigger;
	MR_LONG					count;
	LIVE_ENTITY*			trigger_live_entity;
	FROG*					frog;
	LIVE_ENTITY*			live_entity;
	MR_COLLCHECK*			coll_check;


	frog		= (FROG*)void_frog;
	live_entity	= (LIVE_ENTITY*)void_live_entity;
	coll_check	= (MR_COLLCHECK*)void_coll_check;
	entity		= live_entity->le_entity;
	trigger		= (VOL_COLOUR_TRIGGER*)(entity+1);
	rt_trigger	= (VOL_RT_COLOUR_TRIGGER*)live_entity->le_specific;

	rt_trigger->ct_flags &= ~VOL_SWITCH_FLAG_NO_FROG_CONTACT;

	if (rt_trigger->ct_forbid_timer)
		return;

	// Setup trigger mode
	switch (rt_trigger->ct_state)
		{
		case VOL_SWITCH_ON_DOWN:
		case VOL_SWITCH_OFF_DOWN:
			// Nudge frog up above land
			frog->fr_lwtrans->t[1] = frog->fr_y - 0x30;
			return;

		case VOL_SWITCH_ON_UP:
			MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, VOL_SWITCH_ACTION_DOWN);
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;
			rt_trigger->ct_state 		= VOL_SWITCH_OFF_DOWN;
			rt_trigger->ct_forbid_timer	= VOL_SWITCH_FORBID_TIME;

			// Set texture on switch to 'off'
			MRMeshAnimatedPolysSetCels(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh, 0);
			break;

		case VOL_SWITCH_OFF_UP:
			MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, VOL_SWITCH_ACTION_DOWN);
			((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_flags |= MR_ANIM_ENV_STEP;
			rt_trigger->ct_state 		= VOL_SWITCH_ON_DOWN;
			rt_trigger->ct_forbid_timer	= VOL_SWITCH_FORBID_TIME;

			// Set texture on switch to 'on'
			MRMeshAnimatedPolysSetCels(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh, 1);
			break;
		}

	// switch/case on the trigger type
	switch (trigger->ct_type)
		{
		case VOL_TYPE_TRIGGER_FREEZE:
			// Unpause all entity in the list
			for (count=0; count<VOL_COLOUR_TRIGGER_MAX_IDS; count++)
				{
				// is ID valid?
				if (trigger->ct_unique_ids[count] != -1)
					{
					// find entity with unique id
					trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->ct_unique_ids[count]);
					MR_ASSERTMSG (trigger_live_entity != NULL, "Entity start trigger with invalid unique id");

					// reverse no-movement flag
					if (trigger_live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
						{
						trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						// If entity is path based, set path based flag to start it
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
						}
					else
						{
						trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
						// If entity is path based, set path based flag to start it
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
						}
					}
				}
			break;

		case VOL_TYPE_TRIGGER_REVERSE:
			// reverse all entity in the list
			for (count=0; count<VOL_COLOUR_TRIGGER_MAX_IDS; count++)
				{
				// is ID valid?
				if (trigger->ct_unique_ids[count] != -1)
					{
					// find entity with unique id
					trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->ct_unique_ids[count]);
					MR_ASSERTMSG (trigger_live_entity != NULL, "Entity reverse trigger with invalid unique id");

					// Check that entity is PATH based
					MR_ASSERTMSG (trigger_live_entity->le_entity->en_path_runner, "Entity reverse trigger speced for non path based entity");

					// reverse movement flag...
					if (trigger_live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_BACKWARDS)
						trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_BACKWARDS;
					else
						trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_BACKWARDS;
					}
				}

			break;

		case VOL_TYPE_TRIGGER_START:
			// Unpause all entity in the list
			for (count=0; count<VOL_COLOUR_TRIGGER_MAX_IDS; count++)
				{
				// is ID valid?
				if (trigger->ct_unique_ids[count] != -1)
					{
					// find entity with unique id
					trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->ct_unique_ids[count]);
					MR_ASSERTMSG (trigger_live_entity != NULL, "Entity start trigger with invalid unique id");

					// reverse no-movement flag
					if (trigger_live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
						{
						trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						// If entity is path based, set path based flag to start it
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
						}
					else
						{
						trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
						// If entity is path based, set path based flag to start it
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
						}
					}
				}
			break;
		}
}

//------------------------------------------------------------------------------------------------
// Vol Cog Noise.
//

MR_LONG		script_vol_cog_noise[] = 
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_IND_COGS,			//    MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Vol Lava Noise.
//

MR_LONG		script_vol_lava_noise[] = 
	{
	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),			2,
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_IND_LAVA,			//    MIN				MAX.
									ENTSCR_REGISTERS,		ENTSCR_REGISTER_0, ENTSCR_REGISTER_1,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// Spinner SFX.
MR_LONG		script_vol_spinner[] =
	{
	ENTSCR_SETLOOP,

	// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_IND_CHAIN,			// MIN	MAX.
									ENTSCR_NO_REGISTERS,	512, 1024,
															// Min, Max	  Speed,  Range,
	ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	48,		84,		3,	7,  64,

	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};


MR_LONG		script_vol_lava_spray[] = 
	{
	ENTSCR_SETLOOP,
	ENTSCR_ROTATE,					ENTSCR_COORD_Z,				0x1000,		0x80,	-1,
	ENTSCR_WAIT_UNTIL_ROTATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
// Volcano furnace platform.
//
// Rise Delay	-	Reg_0
// Rise Speed 	- 	Reg_1
// Fall Delay	-	Reg_2
// Fall Speed 	-	Reg_3
// Height		-	Reg_4
// Once Delay	-	Reg_5
//

MR_LONG		script_vol_furnace_platform[] =
	{

	ENTSCR_PREPARE_REGISTERS,		sizeof(MR_MAT),		6,
	ENTSCR_SET_ENTITY_TYPE,			ENTSCR_ENTITY_TYPE_MATRIX,
	// Wait for the Once Only delay.
	ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,0,						// set time to zero
	ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_REGISTERS,	ENTSCR_REGISTER_5,		// wait until mappy entered delay
	ENTSCR_SETLOOP,
		// Wait for fall timer to hit zero.
		ENTSCR_SET_TIMER,			ENTSCR_NO_REGISTERS,0,					
		ENTSCR_WAIT_UNTIL_TIMER,	ENTSCR_REGISTERS,	ENTSCR_REGISTER_2,	
		// Play SFX.
		ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	32,		SFX_IND_HYDRAULIC,
										ENTSCR_COORD_Z,  		 0,
		// Fall until height reaches.		
		ENTSCR_DEVIATE,					ENTSCR_REGISTERS,	ENTSCR_COORD_Y,		ENTSCR_REGISTER_4,	ENTSCR_REGISTER_1,	-1,
		ENTSCR_WAIT_DEVIATED,

		// Kill Frog if standing on this platform at lowest hight.
		ENTSCR_KILL_SAFE_FROG,			FROG_ANIMATION_DROWN,	NULL,
		
		// Wait for rise timer to hit zero.
		ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,0,					
		ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_REGISTERS,	ENTSCR_REGISTER_0,	
		
		// Play SFX.
		ENTSCR_PLAY_SOUND_DISTANCE,		ENTSCR_NO_REGISTERS,	32,		SFX_IND_HYDRAULIC,
										ENTSCR_COORD_Z,  		 0,
		// Rise back to original position.
		ENTSCR_RETURN_DEVIATE,			ENTSCR_REGISTERS,	ENTSCR_NEG_COORD_Y,	ENTSCR_REGISTER_3,
		ENTSCR_WAIT_DEVIATED,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};
