/******************************************************************************
*%%%% ent_cav.c
*------------------------------------------------------------------------------
*
*	Caves entities code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "ent_cav.h"
#include "scripter.h"
#include "scripts.h"
#include "project.h"
#include "mapdisp.h"
#include "frog.h"
#include "entlib.h"
#include "sound.h"
#include "froguser.h"
#include "score.h"
#include "ent_gen.h"
#include "particle.h"

//CAV_WEB_LINES web_lines[] = 
//	{
//	
//	{ {    0,    0,    0 }, { 100,    0,   0}, },
//	{ {    0,    0,    0 }, {   0,  100,   0}, },
//	{ {    0,    0,    0 }, {-100,    0,   0}, },
//	{ {    0,	 0,    0 }, {   0, -100,   0}, },
//	{ {    0,    0,    0 }, { 100,  100,   0}, },
//	{ {    0,    0,    0 }, {-100,  100,   0}, },
//	{ {    0,	 0,    0 }, { 100, -100,   0}, },
//	{ {    0,    0,    0 }, {-100, -100,   0}, },
//	
//	{ {  25,  25,    0,}, { 25, -25,   0}, },
//	{ {  25, -25,    0,}, {-25, -25,   0}, },
//	{ { -25, -25,    0,}, {-25,  25,   0}, },
//	{ { -25,  25,    0,}, { 25,  25,   0}, },
//	{ {  50,  50,    0,}, { 50, -50,   0}, },
//	{ {  50, -50,    0,}, {-50, -50,   0}, },
//	{ { -50, -50,    0,}, {-50,  50,   0}, },
//	{ { -50,  50,    0,}, { 50,  50,   0}, },
//	{ {  75,  75,    0,}, { 75, -75,   0}, },
//	{ {  75, -75,    0,}, {-75, -75,   0}, },
//	{ { -75, -75,    0,}, {-75,  75,   0}, },
//	{ { -75,  75,    0,}, { 75,  75,   0}, },
//
//	};

MR_BOOL		Cav_light_switch;			// Cave light switch

/******************************************************************************
*%%%% CavRockFallFloor
*------------------------------------------------------------------------------
*
*	Scripts to make a floor tile fall after Frogger has been standing on it 
*	for a mappy set time.
*
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Gary Richards	Created
*
*%%%**************************************************************************/

// Wait for Frogger to stand on floor.
MR_LONG		script_cav_rockfallfloor_waiting[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,			ENTSCR_NEW_SCRIPT,		ENTSCR_HIT_FROG,		SCRIPT_CAV_ROCKFALLFLOOR_FALLING,		0,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// Make floor falling after a mappy defined time.
MR_LONG		script_cav_rockfallfloor_falling[] =
	{
	ENTSCR_PREPARE_REGISTERS,			sizeof(MR_MAT),			1,
	ENTSCR_SETLOOP,
		ENTSCR_SET_TIMER,				ENTSCR_NO_REGISTERS,	0,						// set time to zero
		ENTSCR_WAIT_UNTIL_TIMER,		ENTSCR_REGISTERS,		ENTSCR_REGISTER_0,		// wait until mappy entered delay
		ENTSCR_PLAY_SOUND,				SFX_CAV_ROCKFALLFLOOR,
		ENTSCR_DEVIATE,					ENTSCR_NO_REGISTERS,	ENTSCR_COORD_Y,			0x100,	0x5<<WORLD_SHIFT,	-1,		// deviate
		ENTSCR_WAIT_DEVIATED,															// wait til finished
		ENTSCR_CLEAR_DEVIATE,															// clear deviation
	ENTSCR_ENDLOOP,
	ENTSCR_END,
	};


/******************************************************************************
*%%%% ENTSTRCaveCreateFroggerLight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavCreateWeb(
*								LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create the Frogger light entity which lights the landscape
*
*	INPUTS		live_entity	-	pointer to live entity relating to this light
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	William Bell	Created, based on old code from previous project.
*	31.05.97	Martin Kift		Had to bodge the code, since it changed and
*								rechanged on frogdeath/game restart :/
*
*%%%**************************************************************************/

MR_VOID ENTSTRCavCreateFroggerLight(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	CAVES_FROG_LIGHT*		frog_light_map_data_ptr;
	CAVES_RT_FROG_LIGHT*	frog_light;

	// Get pointer to run time data
	entity 					= live_entity->le_entity;
	frog_light_map_data_ptr	= (CAVES_FROG_LIGHT*)(entity + 1);
	frog_light				= (CAVES_RT_FROG_LIGHT*)live_entity->le_specific;

	// Turn on global light resource
	Cav_light_switch = TRUE;

	// Use standard matrix-based entity creation function
	ENTSTRCreateStationaryMOF(live_entity);

	// Check input data ok!!!
#ifdef	DEBUG
	MR_ASSERTMSG("Frogger light minimum radius too low, must be at least 1!!!",frog_light_map_data_ptr->fl_min_radius>1);
	MR_ASSERTMSG("Frogger light maximum radius must be greater than minimum radius!!!",frog_light_map_data_ptr->fl_min_radius<frog_light_map_data_ptr->fl_max_radius);
#endif

	// Do PRE calculations
	frog_light->fl_min_radius = MR_SQR(frog_light_map_data_ptr->fl_min_radius<<8);
	frog_light->fl_max_radius = MR_SQR(frog_light_map_data_ptr->fl_max_radius<<8);

	// Shift up amount to die per second
	frog_light->fl_die_speed = frog_light_map_data_ptr->fl_die_speed << 8;
	frog_light->fl_die_speed /= 30;
	frog_light->fl_die_speed = MR_SQR(frog_light->fl_die_speed);
	frog_light->fl_die_speed >>= 8;

	// Reset ready for count
	frog_light->fl_count = 0;

	Map_light_max_r2 = frog_light->fl_max_radius;
	Map_light_min_r2 = frog_light->fl_max_radius-0x100000;	//0x40000;
	if ( Map_light_min_r2 > Map_light_max_r2 )
		Map_light_min_r2 = 1;
}

/******************************************************************************
*%%%% ENTSTRCaveUpdateFroggerLight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavUpdateFroggerLight(
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the Frogger light for the caves maps.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	William Bell	Created, based on the previous project's routine.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCavUpdateFroggerLight(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	CAVES_RT_FROG_LIGHT*	frog_light;

	// Only update light if the global toggle in on
	if (Cav_light_switch)
		{
		// Get pointer to run time data
		entity 		= live_entity->le_entity;
		frog_light	= (CAVES_RT_FROG_LIGHT*)live_entity->le_specific;
	
		// Only if we are not using the 'special' cave light user movement function.
		if ( Frog_cave_light_special == FALSE)
			{
			// Current light level greater than maximum redius ?
			if ( Map_light_max_r2 > frog_light->fl_max_radius )
				{
				// Yes ... crop light to greatest radius
				Map_light_max_r2 = frog_light->fl_max_radius;
				Map_light_min_r2 = frog_light->fl_max_radius-0x100000;//0x40000;
				if ( Map_light_min_r2 > Map_light_max_r2 )
					Map_light_min_r2 = 1;
				} 
			}

		// Current light level greater than minimum radius ?
		if ( Map_light_max_r2 > frog_light->fl_min_radius )
			{
			// Yes ... dec light by die speed
			Map_light_max_r2 -= frog_light->fl_die_speed;
			Map_light_min_r2 = Map_light_max_r2 - 0x100000;//-= frog_light->fl_die_speed;
			if ( Map_light_min_r2 > Map_light_max_r2 )
				Map_light_min_r2 = 1;
			} 
		}	  
}

/******************************************************************************
*%%%% CavStickyWebCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CavStickyWebCallback(
*									MR_VOID*	void_frog,
*									MR_VOID*	void_live_entity
*									MR_VOID*	void_coll_check)
*
*	FUNCTION	This is the callback for the sticky cave cobwebs, which grab the
*				frog and requrie it to break loose, while the spider chases
*				of course.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check	-	ptr to collision structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	Martin Kift		Created
*	30.05.97	Martin Kift		Changed params to MR_VOID*'s
*
*%%%**************************************************************************/


MR_VOID CavStickyWebCallback(	MR_VOID*	void_frog,
								MR_VOID*	void_live_entity,
								MR_VOID*	void_coll_check)
{
	// Save collcheck and entity structure in case its needed
	((FROG*)void_frog)->fr_user_data1 = void_coll_check;
	((FROG*)void_frog)->fr_user_data2 = void_live_entity;

	// Go into frog user mode for stickyness
	SetFrogUserMode((FROG*)void_frog, FROGUSER_MODE_COBWEB);
}


/******************************************************************************
*%%%% CavBounceWebCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CavBounceWebCallback(
*									MR_VOID*	void_frog,
*									MR_VOID*	void_live_entity
*									MR_VOID*	void_coll_check)
*
*	FUNCTION	This is the callback for the bouncy cave cobwebs, which bounce 
*				the frog off in the direction of reflection at the collprim
*				collided with, but off course back to a center of a grid
*				square
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check	-	ptr to collision structure
*
*	NOTES		This could (mainly due to the limit of only jumping up/down/left
*				or right in Frogger) can only handle bouncy collprims at right
*				angles or 45 degrees
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	Martin Kift		Created
*	30.05.97	Martin Kift		Changed params to MR_VOID*'s
*
*%%%**************************************************************************/

MR_VOID CavBounceWebCallback(	MR_VOID*	void_frog,
								MR_VOID*	void_live_entity,
								MR_VOID*	void_coll_check)
{
	LIVE_ENTITY*	live_entity;
	CAV_RT_WEB*		web;		
		
	live_entity	= (LIVE_ENTITY*)void_live_entity;
	web			= (CAV_RT_WEB*)live_entity->le_specific;

	// Is this a cobweb with spider? If so, don't go into bouncy mode, its BAD
	if (!web->cw_spider)
		{
		// Save collcheck and entity structure in case its needed
		((FROG*)void_frog)->fr_user_data1 = void_coll_check;
		((FROG*)void_frog)->fr_user_data2 = void_live_entity;

		// Go into frog user mode for bouncyness
		SetFrogUserMode((FROG*)void_frog, FROGUSER_MODE_BOUNCY_COBWEB);
		}
}


//------------------------------------------------------------------------------------------------
//
// Wait to randomly trigger Bat Noises.
MR_LONG		script_cav_bat[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_CAV_BAT_SFX,	2,
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// We are Randomly Triggering, are we close enough ??? (20) is strange value!!!
MR_LONG		script_cav_bat_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_CAV_BAT,
										ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

//------------------------------------------------------------------------------------------------
//
// Wait to randomly trigger Vamp Bat Noises.
MR_LONG		script_cav_vamp_bat[] =
	{
	ENTSCR_SETLOOP,
		ENTSCR_SCRIPT_IF,		ENTSCR_NEW_SCRIPT,	ENTSCR_RANDOM,		SCRIPT_CAV_VAMP_BAT_SFX,	2,
	ENTSCR_SET_TIMER,					ENTSCR_NO_REGISTERS,		0,
	ENTSCR_WAIT_UNTIL_TIMER,			ENTSCR_NO_REGISTERS,		10,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};

// We are Randomly Triggering, are we close enough ??? (20) is strange value!!!
MR_LONG		script_cav_vamp_bat_sfx[] =
	{
	ENTSCR_PLAY_SOUND_DISTANCE,			ENTSCR_NO_REGISTERS,		20,		SFX_CAV_VAMP_BAT,
										ENTSCR_COORD_Z,			    256,
	ENTSCR_RESTART,
	};

/******************************************************************************
*%%%% ENTSTRCavCreateFatFireFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavCreateFatFireFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Fat Fire Fly. (Code mostly nicked from GEN_BONUS_FLY)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCavCreateFatFireFly(LIVE_ENTITY*	live_entity)
{
	ENTITY*				entity;
	CAV_FAT_FIRE_FLY*	fat_fire_fly;
	

	entity 			= live_entity->le_entity;
	fat_fire_fly	= (CAV_FAT_FIRE_FLY*)(entity + 1);	
			
	// Transform can be identity, copy translation from ENTITY
	live_entity->le_lwtrans		= &live_entity->le_matrix;
	MR_INIT_MAT(live_entity->le_lwtrans);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)fat_fire_fly->ff_matrix.t);

	// Create 3D sprite
//	live_entity->le_api_item0	= MRCreate3DSprite(	(MR_FRAME*)live_entity->le_lwtrans,
//													MR_OBJ_STATIC,
//													Animlist_cav_fire_fly);
//
////	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_flags		|= MR_SPF_NO_3D_ROTATION;
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_ot_offset	= GEN_BONUS_FLY_OT_OFFSET;
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags									&= ~MR_OBJ_ACCEPT_LIGHTS_MASK;

	// Create PGEN
	PGIN_pickup.pgi_user_data_1 = (MR_ULONG)Pickup_data[GEN_FAT_FIRE_FLY];
	live_entity->le_api_item0	= MRCreatePgen(	&PGIN_pickup,
												(MR_FRAME*)live_entity->le_lwtrans,
											  	MR_OBJ_STATIC,
											  	NULL);

	GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);
}


/******************************************************************************
*%%%% ENTSTRCavUpdateFatFireFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavUpdateFatFireFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a Fat Fire Fly. (Code mostly nick from Update_bonus_fly.)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCavUpdateFatFireFly(LIVE_ENTITY*	live_entity)
{
	ENTITY*			entity;
	MR_ULONG		i;

	entity  = live_entity->le_entity;
	if (!(entity->en_flags & ENTITY_NO_MOVEMENT))
		{
		// Bob fly up and down
		i 								= (((entity->en_unique_id & 7) << 7) + (Game_timer << 8)) & 0xfff;
		live_entity->le_lwtrans->t[1] 	= ((ENTSTR_STATIC*)(entity + 1))->et_matrix.t[1] + (rsin(i) >> 5);

		if (rand()%20 == 1)
			PlaySoundDistance(live_entity, SFX_GEN_FLY_BUZZ, 20);
		}
}

/******************************************************************************
*%%%% ENTSTRCavKillFatFireFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavKillFatFireFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a Fat Fire fly and copies the data required to move Frogger
*				to the target position and back again.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Gary Richards	Created.
*
*	Note:	Still need to make it find the correct Frog.
*	Note:	Also need to be able to tell if it's been eaten or just killed.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCavKillFatFireFly(LIVE_ENTITY*	live_entity)
{
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
}

/******************************************************************************
*%%%% ENTSTRCavCreateRaceSnail
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavCreateRaceSnail(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Race Snail.
*
*	INPUTS		live_entity		- ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

#define	RACE_SNAIL_ACC	(4)

MR_VOID ENTSTRCavCreateRaceSnail(LIVE_ENTITY* live_entity)
{
	CAVES_RACE_SNAIL*		race_snail_data;
	CAVES_RT_RACE_SNAIL*	race_snail;
	ENTITY*					entity;
	MR_FRAC16				velocity;

	entity 			= live_entity->le_entity;
	race_snail_data	= (CAVES_RACE_SNAIL*)(entity + 1);
	race_snail		= (CAVES_RT_RACE_SNAIL*)live_entity->le_specific;

	// use standard path-based entity creation function
	ENTSTRCreateMovingMOF(live_entity);

	race_snail->rs_state 		  = ACTION_RACE_SNAIL_FORWARD;
	race_snail->rs_position		  = 0;
	race_snail->rs_mid_point	  = ((-race_snail_data->rs_backward_dist) + race_snail_data->rs_forward_dist ) >> 1;
	// Time to calculate Initial Velocity;
	velocity = (((RACE_SNAIL_ACC << 1) * race_snail_data->rs_forward_dist) << 16);
	race_snail->rs_velocity = MR_SQRT(velocity);
	race_snail->rs_speed 	= race_snail_data->rs_path_info.pi_speed;
}

/******************************************************************************
*%%%% ENTSTRCavUpdateRaceSnail
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCavUpdateRaceSnail(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Follow;s the Race Window.
*
*	INPUTS		live_entity		- ptr to live_entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID ENTSTRCavUpdateRaceSnail(LIVE_ENTITY* live_entity)
{
	CAVES_RACE_SNAIL*		race_snail_data;
	CAVES_RT_RACE_SNAIL*	race_snail;
	ENTITY*					entity;
	MR_SHORT				speed;

	entity 			= live_entity->le_entity;
	race_snail_data	= (CAVES_RACE_SNAIL*)(entity + 1);
	race_snail		= (CAVES_RT_RACE_SNAIL*)live_entity->le_specific;

	switch (race_snail->rs_state)
		{
		// -------------------------------------------------------------------------------------
		case ACTION_RACE_SNAIL_FORWARD:
			if ( race_snail->rs_position < race_snail->rs_mid_point )
				{
				race_snail->rs_state = ACTION_RACE_SNAIL_BACKWARD;
				race_snail->rs_velocity += (RACE_SNAIL_ACC << 8);
				}
			else
				race_snail->rs_velocity += - ((RACE_SNAIL_ACC) << 8);
			break;
		// -------------------------------------------------------------------------------------
		case ACTION_RACE_SNAIL_BACKWARD:
			if ( race_snail->rs_position > race_snail->rs_mid_point )	
				{
				race_snail->rs_state = ACTION_RACE_SNAIL_FORWARD;
				race_snail->rs_velocity += - ((RACE_SNAIL_ACC) << 8);
				}
			else
				race_snail->rs_velocity += (RACE_SNAIL_ACC << 8);
			break;
		// -------------------------------------------------------------------------------------
		} 

	race_snail->rs_position += ( race_snail->rs_velocity >> 8 );
	
	// Change the Path-Runners speed on the fly.
	speed = ( race_snail->rs_velocity >> 8 ) + race_snail->rs_speed;

	if (speed < 0)
		speed = 0;

	entity->en_path_runner->pr_speed = speed;

	// update entity WRT path
	ENTSTRUpdateMovingMOF(live_entity);
}


/******************************************************************************
*%%%% CavFireFlyCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID GenFireFlyCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		void_null)
*
*	FUNCTION	This is the callback for the Cave Fire Fly.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity.
*				void_null	-	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID CavFireFlyCallBack(	MR_VOID*	void_frog,
					 		MR_VOID*	void_live_entity,
					 		MR_VOID*	void_null)
{
	FROG*				frog;

	frog 		= (FROG*)void_frog;

	// Give set score for Fire Fly.
	AddFrogScore(frog, SCORE_250, NULL);

	// Increase the light for this Frog.
	Map_light_max_r2	+= CAVE_FIRE_FLY_LIGHT;
	Map_light_min_r2	+= CAVE_FIRE_FLY_LIGHT;
}

// Spiders make a noise.
MR_LONG		script_cav_spider[] =
	{
	ENTSCR_SETLOOP,
									// SFX										   
	ENTSCR_PLAY_MOVING_SOUND,		SFX_CAV_SPIDER,	// MIN	MAX.
									ENTSCR_NO_REGISTERS,	1024, 2048,
															// Min, Max	  Speed,  Range,
	ENTSCR_PITCH_BEND_MOVING_SOUND,	ENTSCR_NO_REGISTERS,	48,		84,		3,	7,	64,
	ENTSCR_ENDLOOP,
	ENTSCR_RESTART,
	};







									  
