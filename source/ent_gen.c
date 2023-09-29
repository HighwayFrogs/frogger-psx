/******************************************************************************
*%%%% ent_gen.c
*------------------------------------------------------------------------------
*
*	General Create/Update/Kill Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	19.05.97	Tim Closs		Created
*	21.05.97	Martin Kift		Added check point code
*
*%%%**************************************************************************/

#include "ent_gen.h"
#include "entlib.h"
#include "form.h"
#include "mapload.h"
#include "gamesys.h"
#include "project.h"
#include "sprdata.h"
#include "sound.h"
#include "score.h"
#include "select.h"
#include "particle.h"
#include "gen_gold.h"
#include "camera.h"

MR_TEXTURE*		Pickup_data_gen_fly_10[] =
	{
	(MR_TEXTURE*)0x824682,
	(MR_TEXTURE*)0x20000,
	&im_fly_10,
	&im_fly_10a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_25[] =
	{
	(MR_TEXTURE*)0x824682,
	(MR_TEXTURE*)0x20000,
	&im_fly_25,
	&im_fly_25a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_50[] =
	{
	(MR_TEXTURE*)0x964664,
	(MR_TEXTURE*)0x20000,
	&im_fly_50,
	&im_fly_50a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_100[] =
	{
	(MR_TEXTURE*)0xbe6ebe,
	(MR_TEXTURE*)0x20000,
	&im_fly_100,
	&im_fly_100a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_200[] =
	{
	(MR_TEXTURE*)0xbe6ebe,
	(MR_TEXTURE*)0x20000,
	&im_fly_200,
	&im_fly_200a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_500[] =
	{
	(MR_TEXTURE*)0xd26e8c,
	(MR_TEXTURE*)0x20000,
	&im_fly_500,
	&im_fly_500a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_1000[] =
	{
	(MR_TEXTURE*)0xff82ff,
	(MR_TEXTURE*)0x20000,
	&im_fly_1000,
	&im_fly_1000a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_5000[] =
	{
	(MR_TEXTURE*)0xff82c8,
	(MR_TEXTURE*)0x20000,
	&im_fly_5000,
	&im_fly_5000a,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_min[] =
	{
	(MR_TEXTURE*)0x3c963c,
	(MR_TEXTURE*)0x10000,
	&im_time_min,
	&im_time_mina,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_med[] =
	{
	(MR_TEXTURE*)0x82823c,
	(MR_TEXTURE*)0x10000,
	&im_time_med,
	&im_time_meda,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fly_max[] =
	{
	(MR_TEXTURE*)0x329696,
	(MR_TEXTURE*)0x10000,
	&im_time_max,
	&im_time_maxa,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_glow_worm[] =
	{
	(MR_TEXTURE*)0x508484,
	(MR_TEXTURE*)0x10000,
	&im_fire_fly,
	&im_fire_flya,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_fat_fire_fly[] =
	{
	(MR_TEXTURE*)0x78e6e6,
	(MR_TEXTURE*)0x10000,
	&im_fire_fly_fat,
	&im_fire_fly_fata,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_black_fly[] =
	{
	(MR_TEXTURE*)0x3232c8,
	(MR_TEXTURE*)0x10000,
	&im_fly_bad,
	&im_fly_bada,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_black_time[] =
	{
	(MR_TEXTURE*)0x3232c8,
	(MR_TEXTURE*)0x10000,
	&im_time_bad,
	&im_time_bada,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_super_tongue[] =
	{
	(MR_TEXTURE*)0x8c5abe,
	(MR_TEXTURE*)0x10000,
	&im_super_tongue,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_quick_jump[] =
	{
	(MR_TEXTURE*)0x969650,
	(MR_TEXTURE*)0x10000,
	&im_quick_jump,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_auto_hop[] =
	{
	(MR_TEXTURE*)0x3c323c,
	(MR_TEXTURE*)0x10000,
	&im_auto_jump,
	NULL
	};
MR_TEXTURE*		Pickup_data_gen_extra_life[] =
	{
	(MR_TEXTURE*)0x636363,
	(MR_TEXTURE*)0x10000,
	&im_extra_life1,
	&im_extra_life2,
	&im_extra_life3,
	&im_extra_life4,
	&im_extra_life5,
	NULL
	};

MR_TEXTURE**	Pickup_data[] =
	{
	Pickup_data_gen_fly_10,			// Score flies. 
	Pickup_data_gen_fly_25,
	Pickup_data_gen_fly_50,
	Pickup_data_gen_fly_100,
	Pickup_data_gen_fly_200,
	Pickup_data_gen_fly_500,
	Pickup_data_gen_fly_1000,
	Pickup_data_gen_fly_5000,
	Pickup_data_gen_glow_worm,		// Light
	Pickup_data_gen_fat_fire_fly,
	Pickup_data_gen_fly_min,		// Time.
	Pickup_data_gen_fly_med,
	Pickup_data_gen_fly_max,
	Pickup_data_gen_black_fly,		// Reduce Score Fly.
	Pickup_data_gen_black_time,		// Increase Time Count Down Speed Fly.
	Pickup_data_gen_extra_life,		// Extra Life
	Pickup_data_gen_super_tongue,	// Super Tongue.
	Pickup_data_gen_quick_jump,		// Quick Jump.
	Pickup_data_gen_auto_hop,		// Auto Hop.
	};

MR_ULONG	Bonus_fly_scores[] =
	{
	SCORE_10,
	SCORE_25,
	SCORE_50,
	SCORE_100,
	SCORE_200,
	SCORE_500,
	SCORE_1000,
	SCORE_5000,
	LIGHT_5,
	ADD_SUPER_LIGHT,
	TIME_MIN,
	TIME_MED,
	TIME_MAX,
	REDUCE_SCORE_100,
	ADD_TIMER_SPEED,
	ADD_EXTRA_LIFE,
	ADD_SUPER_TONGUE,
	ADD_QUICK_JUMP,
	ADD_AUTO_HOP,
	};

// Checkpoint global data
MR_ULONG				Checkpoints;
MR_ULONG				Checkpoint_last_collected;
GEN_CHECKPOINT_DATA		Checkpoint_data[GEN_MAX_CHECKPOINTS];

// Gold frog global data
MR_ULONG				Gold_frogs;					// Gold frogs collected in all games (saved to cart)
MR_ULONG				Gold_frogs_current;			// Gold frogs collected in current game (flushed on game-start)
MR_ULONG				Gold_frogs_zone;			// Gold frogs collected in current game-zone (flushed on game-start)
GEN_GOLD_FROG_DATA		Gold_frog_data;				// Data for gold frog collected (can only be one at a time)

/******************************************************************************
*%%%% ENTSTRGenCreateBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a BONUS_FLY
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateBonusFly(LIVE_ENTITY*	live_entity)
{
	ENTITY*			entity;
	GEN_BONUS_FLY*	bonus_fly;

	entity 		= live_entity->le_entity;
	bonus_fly	= (GEN_BONUS_FLY*)(entity + 1);
			
	// Transform can be identity, copy translation from ENTITY
	live_entity->le_lwtrans		= &live_entity->le_matrix;
	MR_INIT_MAT(live_entity->le_lwtrans);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)bonus_fly->bf_matrix.t);

	// Check for a valid type.
	MR_ASSERT(bonus_fly->bf_type <= GEN_AUTO_HOP);

	// Create 3D sprite
//	live_entity->le_api_item0	= MRCreate3DSprite(	(MR_FRAME*)live_entity->le_lwtrans,
//													MR_OBJ_STATIC,
//													Bonus_fly_animlists[bonus_fly->bf_type]);
//
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_flags		|= MR_SPF_NO_3D_ROTATION;
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_ot_offset	= GEN_BONUS_FLY_OT_OFFSET;
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags									&= ~MR_OBJ_ACCEPT_LIGHTS_MASK;

	// Create PGEN
	PGIN_pickup.pgi_user_data_1 = (MR_ULONG)Pickup_data[bonus_fly->bf_type];
	live_entity->le_api_item0	= MRCreatePgen(	&PGIN_pickup,
												(MR_FRAME*)live_entity->le_lwtrans,
											  	MR_OBJ_STATIC,
											  	NULL);

	GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);

	// We need the light bonus NOT to be effected by the lights.
	live_entity->le_flags |= LIVE_ENTITY_NO_COLOUR_FADE;


	// create 3d sound for each of the flies. (Hopefully taking NO voices until active!)
	if (live_entity->le_moving_sound == NULL)
		{
		// Check to see what type of fly we have.
		if (bonus_fly->bf_type == GEN_GLOW_WORM)
			// Glow worms have a different sound.
			PlayMovingSound(live_entity, SFX_CAV_GLOW_WORM, 256, 768);
		else
			// Play SFX of the fly buzzing.
			PlayMovingSound(live_entity, SFX_GEN_FLY_BUZZ02, 256, 768);
		}
}


/******************************************************************************
*%%%% ENTSTRGenUpdateBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenUpdateBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a BONUS_FLY
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.05.97	Tim Closs		Updated
*	14.08.97	Gary Richards	Added moving sound + pitch bend.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenUpdateBonusFly(LIVE_ENTITY*	live_entity)
{
	ENTITY*		entity;
	MR_ULONG	i;
	MR_LONG		standard_pitch;
	MR_LONG		pitch_bend;
	MR_LONG		voice_id;

	entity  = live_entity->le_entity;
	if (!(entity->en_flags & ENTITY_NO_MOVEMENT))
		{
		// Bob fly up and down
		i 								= (((entity->en_unique_id & 7) << 7) + (Game_timer << 8)) & 0xfff;

//		live_entity->le_lwtrans->t[1] 	= ((ENTSTR_STATIC*)(entity + 1))->et_matrix.t[1] + (rsin(i) >> 5);
		// Make fly move only in upper half of previous wave
		live_entity->le_lwtrans->t[1] 	= ((ENTSTR_STATIC*)(entity + 1))->et_matrix.t[1] + (rsin(i) >> 6) + (0x1000 >> 6);

		// Work out how many flies are active and adjust the pitch bend.
		if	( 
			(live_entity->le_moving_sound) && 
			(((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0] != -1)
			)
			{
			// Grab voice id.
			voice_id = ((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0];
		
			standard_pitch = (GEN_FLY_CENTER_PITCH - (rand()&15));			// +/- 8 around a center pitch of 64.
			standard_pitch += ((rand()&0x3) * GEN_FLY_PITCH_MOD);
			// Grab position with Sin table.	
			pitch_bend = standard_pitch - ((rsin((Game_timer << GEN_FLY_SIN_SPEED))) >> GEN_FLY_SHIFT);	
		
			MRSNDPitchBend(voice_id,pitch_bend);
			}
		}
}		


/******************************************************************************
*%%%% ENTSTRGenKillBonusFly
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenKillBonusFly(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a BONUS_FLY
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.05.97	Tim Closs		Killd
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenKillBonusFly(LIVE_ENTITY*	live_entity)
{
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
}

/******************************************************************************
*%%%% InitialiseCheckPoints
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseCheckPoints(MR_VOID)
*
*	FUNCTION	Initialises the check point arrays, clearing collected flags
*				and suchlike...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID InitialiseCheckPoints(MR_VOID)
{
	ENTITY**				entity_pptr;
	ENTITY*					entity;
	FORM_BOOK*				form_book;
	MR_LONG					i, c;
	GEN_CHECKPOINT_DATA*	data;

	Checkpoints 	= 0;
	data 			= Checkpoint_data;
	i 				= GEN_MAX_CHECKPOINTS;
	while(i--)
		{
		data->cp_frog_collected_id 	= -1;
		data->cp_time				= 0;

		// Croak
		data->cp_croak_mode			= FROG_CROAK_NONE;
		data->cp_croak_timer		= 0;
		data++;
		}

	// This function must be called after InitialiseMap()
	// Run through map ENTITY array: if we find any ENTITY_TYPE_CHECKPOINT, set Checkpoint_data up from this structure
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		entity		= *entity_pptr;
		form_book	= ENTITY_GET_FORM_BOOK(entity);

		if ( (form_book->fb_entity_type == ENTITY_TYPE_CHECKPOINT) ||
			 (form_book->fb_entity_type == ENTITY_TYPE_MULTIPOINT) )
			{
			// Note: as a bodge, you could renumber the cp_id entries here from 0..4, as follows:
			((GEN_CHECKPOINT*)(entity + 1))->cp_id = (entity->en_form_book_id & 0x7fff);

			// Check that we are not multi-points.
			if ( ((GEN_CHECKPOINT*)(entity + 1))->cp_id > 4 )
				((GEN_CHECKPOINT*)(entity + 1))->cp_id -= 11;		// Reduce if we are a multi-point.
	
			c = ((GEN_CHECKPOINT*)(entity + 1))->cp_id;

			Checkpoint_data[c].cp_entity = entity;
			MR_SVEC_EQUALS_VEC(&Checkpoint_data[c].cp_position, (MR_VEC*)((GEN_CHECKPOINT*)(entity + 1))->cp_matrix.t);

			// Init user data, and flags
			Checkpoint_data[c].cp_user_data = 0;
			Checkpoint_data[c].cp_flags		= 0;			
			}	
		entity_pptr++;
		}
}


/******************************************************************************
*%%%% ENTSTRGenCreateCheckPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateCheckPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a checkpoint. Most of the hard work is handled by
*				ENTSTRCreateStationaryMOF()
*
*	INPUTS		live_entity	-	to create
*
*	NOTE		This is ONLY the single player checkpoint (multiplayer is 'multipoint')
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Martin Kift		Updated
*   01.06.97	Gary Richards	Only create CheckPoints that have NOT been collected.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateCheckPoint(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;
	MR_LONG					colour;
	MR_ULONG				i, j;
	MR_MESH_INST**			mesh_inst_list_ptr;
	MR_MESH_INST*			mesh_inst_ptr;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint 	= (GEN_CHECKPOINT*)(entity + 1);
	
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data = &Checkpoint_data[checkpoint->cp_id];

	// create entity (Only if not collected)
	if (data->cp_frog_collected_id == -1)
		{
		// Create baby frog animation
		ENTSTRCreateStationaryMOF(live_entity);

		// if animated model, set action
		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 0);

		// store position of this checkpoint, maybe including other things
		MR_SVEC_EQUALS_VEC(&data->cp_position, (MR_VEC*)live_entity->le_lwtrans->t);

		// Store entity
		data->cp_entity = live_entity->le_entity;

// Change custom ambient
#define GEN_CHECKPOINT_RED		(160)
#define GEN_CHECKPOINT_GREEN	(160)
#define GEN_CHECKPOINT_BLUE		(160)

		// Look at map header to find requested colour information. The information in the
		// map header is a slider from -128 to 128... with 0 meaning NO ambient
		colour = (GEN_CHECKPOINT_RED << 16) + (GEN_CHECKPOINT_GREEN << 8) + (GEN_CHECKPOINT_BLUE);

		// Loop through each viewport, setting colour information
		for (j = 0; j < Game_total_viewports; j++)
			{
			// Is there a valid mesh inst pointer ?
			if (live_entity->le_api_insts[j])
				{
				// Yes ... is it animated ?
				MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

				mesh_inst_list_ptr	= ((MR_ANIM_ENV_INST*)live_entity->le_api_insts[j])->ae_mesh_insts;
				mesh_inst_ptr		= *mesh_inst_list_ptr;
						
				// Loop once for each model in anim env inst
				i = ((MR_ANIM_ENV_INST*)live_entity->le_api_insts[j])->ae_models;
				MR_ASSERT(i);
				while(i--)
					{
					mesh_inst_ptr = *mesh_inst_list_ptr;
					// Set mesh instance base colour
					mesh_inst_ptr->mi_light_flags |= MR_INST_USE_CUSTOM_AMBIENT;
					mesh_inst_ptr->mi_light_flags &= ~MR_INST_USE_SCALED_COLOURS;
					MR_SET32(mesh_inst_ptr->mi_custom_ambient, colour);
					// Move through pointer list
					mesh_inst_list_ptr++;
					}
				}
			}
		}
	else
		data->cp_entity = NULL;
}


/******************************************************************************
*%%%% ENTSTRGenUpdateCheckPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenUpdateCheckPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update checkpoint (eg. croak)
*
*	INPUTS		live_entity	-	to update
*
*	NOTE		This is ONLY the single player checkpoint (multiplayer is 'multipoint')
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenUpdateCheckPoint(LIVE_ENTITY*	live_entity)
{

	// Locals
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;
	MR_ANIM_ENV_FLIPBOOK*	env_flip;
	MR_VEC					dist;
	MR_ULONG				total_dist_sqr;

	// if NOT an animated checkpoint model, return now
	if (!(live_entity->le_flags & LIVE_ENTITY_ANIMATED))
		return;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint	= (GEN_CHECKPOINT*)(entity + 1);
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data 		= &Checkpoint_data[checkpoint->cp_id];

	// According to mode do ...
	switch(data->cp_croak_mode)
		{
		//---------------------------------------------------------------------
		case CHECKPOINT_MODE_WAITING:
			// Hang around until flipbook anim is on ground before switching to croak anim
			env_flip = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flip->ae_cel_number == 0)
				{
				// Calculate distance from trigger point
				dist.vx = MR_SQR(Frogs[0].fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0]);
				dist.vy = MR_SQR(Frogs[0].fr_lwtrans->t[1] - live_entity->le_lwtrans->t[1]);
				dist.vz = MR_SQR(Frogs[0].fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2]);
				total_dist_sqr = dist.vx + dist.vy + dist.vz; 
				// Is Frogger close enough ?
				if ( total_dist_sqr < (512*512) )
					{
					// Yes ... should we jump ?
					if ( rand()%10 == 1 )
						{
						// Yes ... go on to jump
						MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 2);
						data->cp_croak_mode		= CHECKPOINT_MODE_JUMP;
						}
					}
				}
			break;
		//---------------------------------------------------------------------
		case CHECKPOINT_MODE_INFLATE:
			// Hang around until flipbook anim is on ground before switching to croak anim
			env_flip = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flip->ae_cel_number == 0)
				{
				MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 1);
				data->cp_croak_mode 	= CHECKPOINT_MODE_DEFLATE;
				}
			break;
		//---------------------------------------------------------------------
		case CHECKPOINT_MODE_DEFLATE:
			// Wait for croak anim to finish
			env_flip = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flip->ae_cel_number >= (env_flip->ae_total_cels - 1))
				{
				MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 0);
				data->cp_croak_mode 	= CHECKPOINT_MODE_WAITING;
				}
			break;
		//---------------------------------------------------------------------
		case CHECKPOINT_MODE_JUMP:
			// Hang around until flipbook anim is on ground before switching to jump anim
			env_flip = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
			if (env_flip->ae_cel_number >= (env_flip->ae_total_cels - 1))
				{
				MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 0);
				data->cp_croak_mode 	= CHECKPOINT_MODE_WAITING;
				}
			break;
		//---------------------------------------------------------------------
		}
}


/******************************************************************************
*%%%% ENTSTRGenKillCheckPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenKillCheckPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a check point
*
*	INPUTS		live_entity	-	to kill
*
*	NOTE		This is ONLY the single player checkpoint (multiplayer is 'multipoint')
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Martin Kift		Updated
*	01.06.97	Gary Richards	Don't kill a CheckPoint that doesn't exist.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenKillCheckPoint(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint	= (GEN_CHECKPOINT*)(entity + 1);
	
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data = &Checkpoint_data[checkpoint->cp_id];

	// Kill entity (Only if there is one.)
	if (data->cp_entity != NULL)
		ENTSTRKillStationaryMOF(live_entity);
}


/******************************************************************************
*%%%% ENTSTRGenCreateMultiPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateMultiPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a Multipoint. Most of the hard work is handled by
*				ENTSTRCreateStationaryMOF() This is a check used in Multi-player.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Martin Kift		Updated
*   01.06.97	Gary Richards	Only create MultiPoints that have NOT been collected.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateMultiPoint(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint 	= (GEN_CHECKPOINT*)(entity + 1);
	
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data = &Checkpoint_data[checkpoint->cp_id];

	// create entity (Only if not collected)
	if (data->cp_frog_collected_id == -1)
		{
		// Create baby frog animation
		ENTSTRCreateStationaryMOF(live_entity);

		// store position of this checkpoint, maybe including other things
		MR_SVEC_EQUALS_VEC(&data->cp_position, (MR_VEC*)live_entity->le_lwtrans->t);

		// Store entity
		data->cp_entity = live_entity->le_entity;
		}
	else
		data->cp_entity = NULL;
}


/******************************************************************************
*%%%% ENTSTRGenUpdateMultiPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenUpdateMultiPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update Multipoint
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenUpdateMultiPoint(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint	= (GEN_CHECKPOINT*)(entity + 1);
	
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data = &Checkpoint_data[checkpoint->cp_id];
}

/******************************************************************************
*%%%% ENTSTRGenKillMultiPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenKillMultiPoint(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a Multi point
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	Martin Kift		Updated
*	01.06.97	Gary Richards	Don't kill a MultiPoint that doesn't exist.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenKillMultiPoint(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	GEN_CHECKPOINT*			checkpoint;
	GEN_CHECKPOINT_DATA*	data;

	// setup any data needed
	entity 		= live_entity->le_entity;
	checkpoint	= (GEN_CHECKPOINT*)(entity + 1);
	
	MR_ASSERT (checkpoint->cp_id < GEN_MAX_CHECKPOINTS);
	data = &Checkpoint_data[checkpoint->cp_id];

	// Kill entity (Only if there is one.)
	if (data->cp_entity != NULL)
		ENTSTRKillStationaryMOF(live_entity);
}

/******************************************************************************
*%%%% GenBlockCollPrimCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID GenBlockCollPrimCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for gen blocks, which push the frog.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GenBlockCollPrimCallback(	MR_VOID*	void_frog,
									MR_VOID*	void_live_entity,
									MR_VOID*	void_coll_check)
{
	FROG*			frog;
	LIVE_ENTITY*	live_entity;
	MR_SVEC			svec;
	MR_VEC			vec;
	MR_MAT			mat;
	FORM*			form;

	frog = (FROG*)void_frog;

	// only reset the frogs position if its not dead... obvious really
	if (frog->fr_flags & FROG_ACTIVE)
		{
		if (frog->fr_entity)
			{
			MR_COPY_VEC(&frog->fr_pos, &frog->fr_old_pos);
			UpdateFrogPositionalInfo(frog);

			live_entity = frog->fr_entity->en_live_entity;

			svec.vx		= frog->fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0];
			svec.vy		= frog->fr_lwtrans->t[1] - live_entity->le_lwtrans->t[1];
			svec.vz		= frog->fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2];
	
			MRTransposeMatrix(live_entity->le_lwtrans, &mat);
			MRApplyMatrix(&mat, &svec, &vec);
		
			frog->fr_entity_ofs.vx = vec.vx << 16;
			frog->fr_entity_ofs.vy = vec.vy << 16;
			frog->fr_entity_ofs.vz = vec.vz << 16;

			// work out entity offset grid
			form						= ENTITY_GET_FORM(frog->fr_entity);
			frog->fr_entity_grid_x 		= (vec.vx - form->fo_xofs) >> 8;
			frog->fr_entity_grid_z 		= (vec.vz - form->fo_zofs) >> 8;
			}
		else
			{
			MR_COPY_VEC(&frog->fr_pos, &frog->fr_old_pos);
			UpdateFrogPositionalInfo(frog);
			}

		// Need to set the frog as jumping to and from an entity. This fixes any problems
		// as the frog gets shoved.
		frog->fr_flags |= FROG_JUMP_TO_ENTITY;
		frog->fr_flags |= FROG_JUMP_FROM_ENTITY;
		frog->fr_count = 1;
		}
}


/******************************************************************************
*%%%% GenButterflyCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID GenButterFlyCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		void_null)
*
*	FUNCTION	This is the callback for the Desert butterfly.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				void_null	-	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID GenButterFlyCallBack(	MR_VOID*	void_frog,
								MR_VOID*	void_live_entity,
								MR_VOID*	void_null)
{
	FROG*				frog;
	LIVE_ENTITY*		live_entity;
	ENTSTR_BUTTERFLY*	butterfly;
	ENTITY*				entity;

	frog 		= (FROG*)void_frog;
	live_entity = (LIVE_ENTITY*)void_live_entity;
	entity 		= live_entity->le_entity;
	butterfly	= (ENTSTR_BUTTERFLY*)(entity + 1);

	// Add the score to the Frog.
	AddFrogScore(frog, Bonus_fly_scores[butterfly->et_type], NULL);
}

/******************************************************************************
*%%%% ENTSTRGenCreateTopLeft
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateTopLeft(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Store position of top left boundary of fade area
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateTopLeft(LIVE_ENTITY*	live_entity)
{

	// Locals
	ENTSTR_STATIC*	entity_type;
	ENTITY*			entity;
	FORM*  			form;

	// Set up matrix
	entity 					= live_entity->le_entity;
	form					= ENTITY_GET_FORM(entity);
	entity_type				= (ENTSTR_STATIC*)(entity + 1);
	live_entity->le_lwtrans	= &entity_type->et_matrix;

	// Store top left position of fade edge
	Fade_top_left_pos.vx = live_entity->le_lwtrans->t[0];
	Fade_top_left_pos.vy = live_entity->le_lwtrans->t[1];
	Fade_top_left_pos.vz = live_entity->le_lwtrans->t[2];

}

/******************************************************************************
*%%%% ENTSTRGenCreateBottomRight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateBottomRight(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Store position of bottom right boundary of fade area
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateBottomRight(LIVE_ENTITY*	live_entity)
{

	// Locals
	ENTSTR_STATIC*	entity_type;
	ENTITY*			entity;
	FORM*  			form;

	// Set up matrix
	entity 					= live_entity->le_entity;
	form					= ENTITY_GET_FORM(entity);
	entity_type				= (ENTSTR_STATIC*)(entity + 1);
	live_entity->le_lwtrans	= &entity_type->et_matrix;

	// Store bottom right position of fade edge
	Fade_bottom_right_pos.vx = live_entity->le_lwtrans->t[0];
	Fade_bottom_right_pos.vy = live_entity->le_lwtrans->t[1];
	Fade_bottom_right_pos.vz = live_entity->le_lwtrans->t[2];

}

/******************************************************************************
*%%%% ENTSTRGenCreateGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenCreateGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a gold frog checkpoint. Most of the hard work is handled by
*				ENTSTRCreateStationaryMOF()
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Updated
*	02.09.97	Martin Kift		Created glow
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenCreateGoldFrog(LIVE_ENTITY*	live_entity)
{
	ENTITY*					entity;
	GEN_GOLD_FROG*			gold_frog;
	GEN_RT_GOLD_FROG*		rt_gold;

	// setup any data needed
	entity 					= live_entity->le_entity;
	gold_frog				= (GEN_GOLD_FROG*)(entity + 1);
	rt_gold					= live_entity->le_specific;
	rt_gold->gf_mode		= GEN_GOLD_FROG_WAITING;
	rt_gold->gf_api_item	= NULL;

	// create entity (Only if not collected)
	if (!(Gold_frogs & (1<<Game_map_theme)))
		{
		// Create baby frog animation
		ENTSTRCreateStationaryMOF(live_entity);

		// if animated model, set action
		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			{
			MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK);
			MRAnimEnvFlipbookSetAction(live_entity->le_api_item0, 0);
			}

		// store position of this checkpoint, maybe including other things
		MR_SVEC_EQUALS_VEC(&Gold_frog_data.gf_position, (MR_VEC*)live_entity->le_lwtrans->t);

		// Store entity
		Gold_frog_data.gf_entity			= live_entity->le_entity;
		Gold_frog_data.gf_frog_collected_id = -1;

		LiveEntitySetAction(live_entity, GEN_GOLD_FROG_LOOKAROUND);

		// Create glow
		rt_gold->gf_api_item	= MRCreatePgen(	&PGIN_gold_frog_glow,
												(MR_FRAME*)live_entity->le_lwtrans,
											  	MR_OBJ_STATIC,
											  	NULL);
		GameAddObjectToViewports(rt_gold->gf_api_item);
		}
	else
		Gold_frog_data.gf_entity = NULL;

	// setup hud effect
	rt_gold->gf_hud_script = SetupHUDScript(HUD_script_gold_frog, 0);
}


/******************************************************************************
*%%%% ENTSTRGenUpdateGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenUpdateGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update gold frog (eg. croak)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Created
*	07.08.97	Gary Richards	Added a fade to make frog 'glow'
*	20.08.97	Martin Kift		Added more thought
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenUpdateGoldFrog(LIVE_ENTITY*	live_entity)
{
	GEN_RT_GOLD_FROG*	rt_gold;
	POLY_PIECE_POP*		pop;

	rt_gold = live_entity->le_specific;

	switch (rt_gold->gf_mode)
		{
		case GEN_GOLD_FROG_WAITING:
			if (live_entity->le_flags & LIVE_ENTITY_HIT_FROG)
				{
				// go into pop mode... 
				LiveEntityInitPop(live_entity);
				LiveEntityStartPolyPiecePop(live_entity);
				rt_gold->gf_mode = GEN_GOLD_FROG_JUMPING;

				// kill off glow
				if (rt_gold->gf_api_item)
					{
					((MR_OBJECT*)rt_gold->gf_api_item)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
					rt_gold->gf_api_item = NULL;
					}
				}
			break;

		case GEN_GOLD_FROG_JUMPING:
			if (live_entity->le_effect)
				{
				pop = (POLY_PIECE_POP*)live_entity->le_effect;
				if (!pop->pp_timer)
					{
					// pop has finished, tidy up
					LiveEntityFreePop(live_entity);
					rt_gold->gf_mode = GEN_GOLD_FROG_FINISHED;
					}
				break;
				}
			break;

		case GEN_GOLD_FROG_FINISHED:
			break;
		}

	// enable movement in script if we have been collected
	if (Gold_frogs & (1<<Game_map_theme))
		((HUD_ITEM*)rt_gold->gf_hud_script)->hi_flags &= ~HUD_ITEM_NO_UPDATE;

	// update hud
	UpdateHUDScript(rt_gold->gf_hud_script, 0);
}

/******************************************************************************
*%%%% ENTSTRGenKillGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRGenKillGoldFrog(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a gold frog
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.07.97	Martin Kift		Updated
*
*%%%**************************************************************************/

MR_VOID	ENTSTRGenKillGoldFrog(LIVE_ENTITY* live_entity)
{
	ENTITY*					entity;
	GEN_GOLD_FROG*			gold_frog;
	GEN_RT_GOLD_FROG*		rt_gold;

	// setup any data needed
	entity 		= live_entity->le_entity;
	gold_frog	= (GEN_GOLD_FROG*)(entity + 1);
	rt_gold		= live_entity->le_specific;

	// destroy glow particle effect
	if (rt_gold->gf_api_item)
		((MR_OBJECT*)rt_gold->gf_api_item)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// kill hud script
	if (rt_gold->gf_hud_script)
		KillHUDScript(rt_gold->gf_hud_script);
	
	// Kill entity (Only if there is one.)
	if (Gold_frog_data.gf_entity != NULL)
		ENTSTRKillStationaryMOF(live_entity);
}

/******************************************************************************
*%%%% GenBlockWaterFallCollPrimCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID GenBlockWaterFallCollPrimCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for gen blocks, which removes Frogger from 
*				his entity and makes him fall earthwards.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID GenBlockWaterFallCollPrimCallback(	MR_VOID*	void_frog,
											MR_VOID*	void_live_entity,
											MR_VOID*	void_coll_check)
{
	FROG*	frog;

	frog = (FROG*)void_frog;

	// only reset the frogs position if its not dead... obvious really
	if (frog->fr_flags & FROG_ACTIVE)
		{
		// Check to make sure his is on an entity.
		if (frog->fr_entity	!= NULL)
			{
			// Yep, so make him fall off.
			FROG_FALL(frog);
		 	}
		}
}

/******************************************************************************
*%%%% GenBlockFallCollPrimCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID GenBlockFallCollPrimCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for gen blocks, which removes Frogger from 
*				his entity and makes him fall earthwards. (Used on industrial to stop
*				Frogger from 'jumping' through platforms he shouldn't.)
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID GenBlockFallCollPrimCallback(	MR_VOID*	void_frog,
										MR_VOID*	void_live_entity,
										MR_VOID*	void_coll_check)
{
	FROG*			frog;
	LIVE_ENTITY*	live_entity;

	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_LONG			s;

	frog		= (FROG*)void_frog;
	live_entity = (LIVE_ENTITY*)void_live_entity;

	// only reset the frogs position if its not dead... obvious really
	if (frog->fr_flags & FROG_ACTIVE)
		{
		// If on caves map, make frog fall more subtley
		if (Game_map_theme == THEME_CAV)
			{
			frog->fr_entity			= NULL;											
			frog->fr_mode			= FROG_MODE_JUMPING;				
			frog->fr_flags			&= ~FROG_LANDED_ON_LAND_CLEAR_MASK;	
			frog->fr_count			= 0xffff;						
			frog->fr_forbid_entity	= live_entity->le_entity;
			frog->fr_velocity.vx >>= 1;
			frog->fr_velocity.vz >>= 1;
			}
		else
			{
			// Make him fall when he hits this block.
			FROG_FALL(frog);

			// To this Grid Square.
			frog->fr_grid_x			= GET_GRID_X_FROM_WORLD_X(frog->fr_lwtrans->t[0]);
			frog->fr_grid_z			= GET_GRID_Z_FROM_WORLD_Z(frog->fr_lwtrans->t[2]);
			frog->fr_grid_square	= NULL;
		
			grid_stack 				= Grid_stacks + (frog->fr_grid_z * Grid_xnum) + frog->fr_grid_x;
		
			// look through grid stacks to find a valid one to fall too!
			if (s = grid_stack->gs_numsquares)
				{
				grid_square = &Grid_squares[grid_stack->gs_index];
				while(s--)
					{
					if (grid_square->gs_flags & GRID_SQUARE_USABLE)
						{
						frog->fr_grid_square = grid_square;

						// put into freefall mode
						frog->fr_flags |= FROG_FREEFALL;
						break;
						}
					grid_square++;
					}
				}
			}
		}
}

