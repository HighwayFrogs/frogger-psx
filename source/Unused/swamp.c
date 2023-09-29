/******************************************************************************
*%%%% swamp.c
*------------------------------------------------------------------------------
*
*	Swamp Entity Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.01.97	Gary Richards	Created
*	30.04.97	Gary Richards	Added to the New Frogger.
*
*%%%**************************************************************************/

#include "swamp.h"

/******************************************************************************
*%%%% SwpCreateOilDrum
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateOilDrum(FG_GOF* gof)
*
*	FUNCTION	Creates a oil drum
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateOilDrum(MR_VOID* data)
{
	FG_GOF*		gof;
	FG_OIL_DRUM*	oil_drum = NULL;
  	STRUCTURE   lsstruct = {  sizeof(FG_OIL_DRUM),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_OIL_DRUM_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	oil_drum = (FG_OIL_DRUM*)gof->pGameData;
	oil_drum->od_bob_depth = 0;
  	oil_drum->od_sin_position = rand() & 4095;  // So they all start at different heights.
	oil_drum->od_bob_height_offset = 0;
	oil_drum->od_curr_delay = rand() & 255;	
	oil_drum->od_state = ACTION_OFF_OIL_DRUM;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_OIL_DRUM_CRUSHED, 0);

	return gof;
}

/******************************************************************************
*%%%% SwpCreateSinkingBox
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateSinkingBox(FG_GOF* gof)
*
*	FUNCTION	Creates a sinking box
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateSinkingBox(MR_VOID* data)
{
	FG_GOF*			gof;
	FG_SINKING_BOX*	sinking_box = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_SINKING_BOX),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_SINKING_BOX_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	sinking_box = (FG_SINKING_BOX*)gof->pGameData;
	sinking_box->sb_curr_height = 0;	// No offset to add at the start.
	sinking_box->sb_state = ACTION_SINKING_BOX_NORMAL;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_SINKING_BOX_CRUSHED, 0);
	return gof;
}

/******************************************************************************
*%%%% SwpCreateRaccoon
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateRaccoon(FG_GOF* gof)
*
*	FUNCTION	Creates a Raccoon (Same as sinking box.)
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateRaccoon(MR_VOID* data)
{
	FG_GOF*		gof;
	FG_RACCOON*	raccoon = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_RACCOON),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_SINKING_BOX_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	raccoon = (FG_RACCOON*)gof->pGameData;
	raccoon->ra_curr_height   = 0;				// No offset to add at the start.
	raccoon->ra_state = ACTION_RACCOON_NORMAL;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_RACCOON_NORMAL, 0);

	return gof;
}

/******************************************************************************
*%%%% SwpCreateRat
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateRat(FG_GOF* gof)
*
*	FUNCTION	Creates a Rat.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateRat(MR_VOID* data)
{
	FG_GOF*		gof;
	FG_RAT*		rat = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_RAT),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_RAT_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	// set the 'no destroy' flag
	gof->uwFlags |= (GOFFLAG_DONTKILLFRAME|GOFFLAG_DONTKILLOBJECT);

	rat = (FG_RAT*)gof->pGameData;
	MR_SET_VEC(&rat->ra_velocity, 0, 0, 0);
	MR_SET_VEC(&rat->ra_position, 0, 0, 0);
	rat->ra_catch_up = 0;
	rat->ra_state = ACTION_RAT_RUNNING;
	
	return gof;
}

/******************************************************************************
*%%%% SwpCreateNewsPaper
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateNewsPaper(FG_GOF* gof)
*
*	FUNCTION	Creates a NewsPaper.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateNewsPaper(MR_VOID* data)
{
	FG_GOF		*gof;
	gof = pCreateStdMovingEnt(data);
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_NEWSPAPER_NORMAL, 0);
	return gof;
}

/******************************************************************************
*%%%% SwpCreateOilPatch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateOilPatch(FG_GOF* gof)
*
*	FUNCTION	Creates an Oil Patch.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateOil(MR_VOID* data)
{
	return pCreateStdMovingEnt(data);
}

/******************************************************************************
*%%%% SwpCreateNewsPaperTorn
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateNewsPaperTorn(FG_GOF* gof)
*
*	FUNCTION	Creates a NewsPaper Torn.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateNewsPaperTorn(MR_VOID* data)
{
	FG_GOF*				gof;
	FG_NEWSPAPER_TORN*	newspaper_torn = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_NEWSPAPER_TORN),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_NEWSPAPER_TORN_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	newspaper_torn = (FG_NEWSPAPER_TORN*)gof->pGameData;
	newspaper_torn->nt_curr_time = newspaper_torn->nt_map_diff_data->nt_rip_rate;
	newspaper_torn->nt_state = ACTION_NEWSPAPER_TORN_OFF;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_NEWSPAPER_NORMAL, 0);
	return gof;
}

/******************************************************************************
*%%%% SwpCreateWasteSpinningBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateWasteSpinningBarrel(FG_GOF* gof)
*
*	FUNCTION	Creates a Waste Spinning Barrel.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateWasteBarrel(MR_VOID* data)
{
	FG_GOF*				gof;
	FG_SWP_WASTE_BARREL* waste_barrel = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_SWP_WASTE_BARREL),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_SWP_WASTE_BARREL_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	waste_barrel = (FG_SWP_WASTE_BARREL*)gof->pGameData;
	waste_barrel->wb_curr_time = waste_barrel->wb_map_diff_data->wb_float_time;
	waste_barrel->wb_curr_height = 0;
	waste_barrel->wb_curr_spin_speed = 0;
  	waste_barrel->wb_curr_spin_acc = 0;
	waste_barrel->wb_spin_rotation = 0;
	waste_barrel->wb_float_state = ACTION_WASTE_BARREL_FLOATING;
	waste_barrel->wb_spin_state = ACTION_WASTE_BARREL_NO_SPIN;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_WASTE_BARREL_NORMAL, 0);

	return gof;
}

/******************************************************************************
*%%%% SwpCreateNuclearBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateNuclearBarrel(FG_GOF* gof)
*
*	FUNCTION	Creates a Nuclear Barrel.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateNuclearBarrel(MR_VOID* data)
{
	FG_GOF*					gof;
	FG_SWP_NUCLEAR_BARREL*	nuclear_barrel = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_SWP_NUCLEAR_BARREL),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_SWP_NUCLEAR_BARREL_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	// set the 'no destroy' flag
	gof->uwFlags |= (GOFFLAG_DONTKILLFRAME|GOFFLAG_DONTKILLOBJECT);

	nuclear_barrel = (FG_SWP_NUCLEAR_BARREL*)gof->pGameData;
	MR_SET_VEC(&nuclear_barrel->nb_velocity, 0, 0, 0);
	MR_SET_VEC(&nuclear_barrel->nb_position, 0, 0, 0);
	nuclear_barrel->nb_curr_time = 0;
	nuclear_barrel->nb_state = ACTION_NUCLEAR_BARREL_NORMAL;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_NUCLEAR_BARREL_NORMAL, 0);
	
	return gof;
}

/******************************************************************************
*%%%% SwpCreateWeirRubbish
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateWeirRubbish(FG_GOF* gof)
*
*	FUNCTION	Creates a Weir Rubbish.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateWeirRubbish(MR_VOID* data)
{
	FG_GOF*				gof;
	FG_SWP_WEIR_RUBBISH* weir_rubbish = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_SWP_WEIR_RUBBISH),
					   		  sizeof(FG_SPLINEENTITYDATA),
							  sizeof(FG_SWP_WEIR_RUBBISH_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateSplineGof((FG_SPLINEENTITYDATA*)data, &lsstruct);

	weir_rubbish = (FG_SWP_WEIR_RUBBISH*)gof->pGameData;	  
	weir_rubbish->wr_curr_time = weir_rubbish->wr_map_diff_data->wr_time_delay;
	weir_rubbish->wr_curr_speed = 0;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_WEIR_RUBBISH_NORMAL, 0);
	
	return gof;
}

/******************************************************************************
*%%%% SwpCreateSquirt
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateSquirt(FG_GOF* gof)
*
*	FUNCTION	Creates a Squirt.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateSquirt(MR_VOID* data)
{
	FG_GOF*			gof;
	FG_SWP_SQUIRT*	squirt = NULL;
	STRUCTURE   lsstruct = {  sizeof(FG_SWP_SQUIRT),
					   		  sizeof(FG_MATRIXENTITYDATA),
							  sizeof(FG_SWP_SQUIRT_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateDynamicGof((FG_MATRIXENTITYDATA*)data, &lsstruct);

	// set the 'no destroy' flag
	gof->uwFlags |= (GOFFLAG_DONTKILLFRAME|GOFFLAG_DONTKILLOBJECT);

	squirt = (FG_SWP_SQUIRT*)gof->pGameData;
	squirt->sq_curr_time = squirt->sq_map_diff_data->sq_time_delay;
	squirt->sq_action = ACTION_SWP_SQUIRT_WAITING;
	MR_SET_VEC(&squirt->sq_velocity, 0, 0, 0);
	MR_SET_VEC(&squirt->sq_position, 0, 0, 0);
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_SQUIRT_NORMAL, 0);
	
	return gof;
}

/******************************************************************************
*%%%% SwpCreateSTATWasteBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FG_GOF*	SwpCreateSTATWasteBarrel(FG_GOF* gof)
*
*	FUNCTION	Creates a Static Waste Barrel.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
FG_GOF* SwpCreateSTATWasteBarrel(MR_VOID* data)
{
	FG_GOF*						gof;
	FG_SWP_STAT_WASTE_BARREL*	waste_barrel = NULL;
  	STRUCTURE   lsstruct = {  sizeof(FG_SWP_STAT_WASTE_BARREL),
					   		  sizeof(FG_MATRIXENTITYDATA),
							  sizeof(FG_SWP_STAT_WASTE_BARREL_DIFF_DATA) };

	// Create main gof, which creates any mesh/mofs etc and places the GOF
	// into the global list
	gof = pCreateDynamicGof((FG_MATRIXENTITYDATA*)data, &lsstruct);

	waste_barrel = (FG_SWP_STAT_WASTE_BARREL*)gof->pGameData;
	waste_barrel->wb_curr_time = waste_barrel->wb_map_diff_data->wb_float_time;
	waste_barrel->wb_curr_height = 0;
	waste_barrel->wb_starting_height = gof->pFrame->fr_matrix.t[1];
	waste_barrel->wb_float_state = ACTION_WASTE_BARREL_FLOATING;
	// Set Default animation.
	vShowGofAnimation(gof, ANIM_SWP_WASTE_BARREL_NORMAL, 0);

	return gof;
}


/******************************************************************************
*%%%% swp_u.c
*------------------------------------------------------------------------------
*
*	Swamp Update Functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/

#include "level\swp_c.h"
#include "general\sound.h"
#include "entities\entgen.h"
#include "define.h"
#include "game\frog.h" 

/******************************************************************************
*%%%% SwpUpdateOilDrum
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateOilDrum(FG_GOF* gof)
*
*	FUNCTION	Updates the move of an oil drum. This dips when Frogger lands on it.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateOilDrum(FG_GOF *pGof)
{
	FG_OIL_DRUM* oil_drum = (FG_OIL_DRUM*)(pGof->pGameData);
	MR_UBYTE	status_flags;

	// check too see if the swamp Crusher has hit this object.
	if (pGof->ubHitFlags & ENTITY_HIT)
		// Yes, so change the anim list.
		vShowGofAnimation(pGof, ANIM_SWP_OIL_DRUM_CRUSHED, 0);
		
	// Only do this if we are on-screen
	if (NULL != pGof->pFrame)
		{							   
		// Check too see if Frogger has just jumped on the Oil Drum
		if (pGof->ubHitFlags & PARENT_HIT)
			{
			// Only just jumped on.
			if (ACTION_OFF_OIL_DRUM == oil_drum->od_state)
				{
				// Play SFX of splosh.
				lPlaySample((MR_USHORT)SNDFX_SWP_OIL_DRUM_SPLOSH,127);
				oil_drum->od_state = ACTION_ON_OIL_DRUM;
				}
			oil_drum->od_bob_height_offset = OIL_DRUM_BOB_OFFSET << 1;	// Lower in the water if Frogger is on the drum.
			oil_drum->od_bob_depth = OIL_DRUM_BOB_ON_DEPTH;
			}
		else
			{
			// Check too see if Frogger has Just jumped off the drum.
			if (ACTION_ON_OIL_DRUM == oil_drum->od_state)
				oil_drum->od_state = ACTION_OFF_OIL_DRUM;
			
			oil_drum->od_bob_height_offset = OIL_DRUM_BOB_OFFSET;
			oil_drum->od_bob_depth = OIL_DRUM_BOB_OFF_DEPTH;
			}
		}
	
	pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction
									// and there is no reaction for jumpping off.

	status_flags = ubUpdateSplineMovement(pGof, &oil_drum->od_path, &(oil_drum->od_map_data->PathData), 
										   oil_drum->od_map_diff_data->od_speed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// If kill the height and restart the OilDrum as normal.
		oil_drum->od_state = ACTION_OFF_OIL_DRUM;
		oil_drum->od_bob_depth = OIL_DRUM_BOB_OFF_DEPTH;
		}

	// check to see if we need another bob
	if (oil_drum->od_curr_delay <= 0)
		{
		// Adjust the height so it looks like it's bobbing up and down.
		oil_drum->od_sin_position+=OIL_DRUM_BOB_SPEED;
		oil_drum->od_sin_position &= 4095;
		// Only add this if on-screen
		if (NULL != pGof->pObject)
			{
			pGof->pFrame->fr_matrix.t[1] += oil_drum->od_bob_height_offset;	// Make it under the water.
			pGof->pFrame->fr_matrix.t[1] += (rsin(oil_drum->od_sin_position) >> oil_drum->od_bob_depth);	
			}

		if (oil_drum->od_sin_position < OIL_DRUM_BOB_SPEED)
			{
			// Done a bob, so wait for a while.
			oil_drum->od_curr_delay = rand() & 255 ;		// oil_drum->_map_diff_data->wBobDelay;
			}
		}
	else
		oil_drum->od_curr_delay--;

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSinkingBox
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSinkingBox(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of a sinking box.
*				It will float around the swamp until Frogger jumps on it, then
*				it will start too sink. Once Frogger has jumpped off, it will rise back.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSinkingBox(FG_GOF* pGof)
{
	FG_SINKING_BOX*	sinking_box = (FG_SINKING_BOX*)(pGof->pGameData);
	MR_UBYTE		status_flags;

	// All Boxes SINKING!!!!
	switch (sinking_box->sb_state)
		{
		// Sinking Box is falling down, with frogger?
		case ACTION_SINKING_BOX_SINKING:
			sinking_box->sb_curr_height += sinking_box->sb_map_diff_data->sb_sink_rate;
			break;

			// If not on the back, then the box returns to it's normal height..... may be.
		default:
			// If the box HAS been sinking, then we rise back up slowly. Once frogger has left.
			if (sinking_box->sb_curr_height > 0)
				sinking_box->sb_curr_height -= sinking_box->sb_map_diff_data->sb_sink_rate;
			else
				sinking_box->sb_curr_height = 0;			// If greater than zero, make it zero.
			break;
		}

	// check too see if the swamp Crusher has hit this object.
	if (pGof->ubHitFlags & ENTITY_HIT)
		// Yes, so change the anim list.
		vShowGofAnimation(pGof, ANIM_SWP_SINKING_BOX_CRUSHED, 0);

	// Don't check this, if on-screen
	if (NULL != pGof->pFrame)
		{
		// Check too see if Frogger is on the SinkingBox.
		if (pGof->ubHitFlags & PARENT_HIT)
			{
			// Check to see if we have just jumped on the box
			if (sinking_box->sb_state == ACTION_SINKING_BOX_NORMAL)
				{
				// Play SFX of splosh.
				lPlaySample((MR_USHORT)SNDFX_SWP_BOX_THUD,127);
				sinking_box->sb_state = ACTION_SINKING_BOX_SINKING;
				}
			}
		else
			{
			// Check too see if Frogger just jumpped off.
			if (sinking_box->sb_state == ACTION_SINKING_BOX_SINKING)
				// Then Frogger just jumpped off.
				sinking_box->sb_state = ACTION_SINKING_BOX_JUMPED_OFF;
			else										
				sinking_box->sb_state = ACTION_SINKING_BOX_NORMAL;
			}
		}

	pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction
									// and there is no reaction for jumpping off.

	// This moves the SinkingBox along it's Spline.
	status_flags = ubUpdateSplineMovement(pGof, &sinking_box->sb_path, &(sinking_box->sb_map_data->PathData),
										   sinking_box->sb_map_diff_data->sb_speed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// If kill the height and restart the SinkingBox as normal.
		sinking_box->sb_state = ACTION_SINKING_BOX_NORMAL;
		sinking_box->sb_curr_height = 0;
		}

	// Adjust the height.
	if (NULL != pGof->pFrame)
		{
		pGof->pFrame->fr_matrix.t[1] += sinking_box->sb_curr_height >> WORLD_SHIFT;
		pGof->pFrame->fr_flags |= MR_FRAME_NO_UPDATE;
		}

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateRat
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateRat(FG_GOF* gof)
*
*	FUNCTION	Updates the move of a Rat. This moves along a spline until it gets
*				to the end, when it will jump towards a target. If Frogger gets too
*				close to a rat, the rat will jump at him.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateRat(FG_GOF* pGof)
{
	FG_RAT*		rat = (FG_RAT*)(pGof->pGameData);
	MR_UBYTE	status_flags;
	MR_USHORT	dist;
	FG_GOF*		frog_gof;
	MR_UBYTE	player = NO_PLAYER;

	switch (rat->ra_state)
		{	
		// ------------------------------------------------------------------------------------------------------
		// Rat running along spline.
		case ACTION_RAT_RUNNING:
		// Get the next player.
		while ((player = ubGetNextPlayer(player)) != NO_PLAYER)
			{
			// Need to check too see if Frogger is close to the RAT.
			frog_gof = &gFrogsGof[player];		// Get Frog gof

			// Get distance from playing frog(s) to RAT. (See you can solve everything with Tri-angles!)
			dist = (MR_USHORT) MR_SQRT(
						((pGof->pMat->t[0] - frog_gof->pMat->t[0]) * (pGof->pMat->t[0] - frog_gof->pMat->t[0])) + 
						((pGof->pMat->t[1] - frog_gof->pMat->t[1]) * (pGof->pMat->t[1] - frog_gof->pMat->t[1])) + 
						((pGof->pMat->t[2] - frog_gof->pMat->t[2]) * (pGof->pMat->t[2] - frog_gof->pMat->t[2])));

			// And not playing Catchup.
			if ((dist < rat->ra_map_diff_data->ra_distance) && (rat->ra_catch_up == 0))
				{
				// We are close enough to jump at the frogger. (YES)
				// Grab the current (WORLD) position of Frogger.
				rat->ra_velocity = vCalculateInitialVelocity(frog_gof->pFrame->fr_matrix,
														rat->ra_map_diff_data->ra_target,
														&rat->ra_position,
													    rat->ra_map_diff_data->ra_time);
				rat->ra_curr_time = rat->ra_map_diff_data->ra_time << 1;
				rat->ra_state = ACTION_RAT_JUMPING_TOWARDS_FROGGER;
				}

			if (rat->ra_catch_up == 0)
				status_flags = ubUpdateSplineMovement(pGof, &rat->ra_path, &(rat->ra_map_data->PathData),
													   rat->ra_map_diff_data->ra_speed);
			else
				{
				// Get the current position of the Rat along the Spline. (Where we would like to be)
				status_flags = ubGetSplineMovement(&rat->ra_desired_position, &rat->ra_path, &(rat->ra_map_data->PathData),
													(rat->ra_map_diff_data->ra_speed));

				// So we know where we are, now we need to get there.
				// Calc the new position for the X.
				if ((rat->ra_desired_position.t[0] - pGof->pFrame->fr_matrix.t[0]) > (rat->ra_map_diff_data->ra_speed * 2))
					pGof->pFrame->fr_matrix.t[0] += rat->ra_map_diff_data->ra_speed*2;
				else
					pGof->pFrame->fr_matrix.t[0] = rat->ra_desired_position.t[0];

				// Y is always assumed.

				// Calc the new position for the Z.
				if ((rat->ra_desired_position.t[2] - pGof->pFrame->fr_matrix.t[2]) > (rat->ra_map_diff_data->ra_speed * 2))
					pGof->pFrame->fr_matrix.t[2] += rat->ra_map_diff_data->ra_speed*2;
				else
					pGof->pFrame->fr_matrix.t[2] = rat->ra_desired_position.t[2];

				rat->ra_catch_up--;
				}

			// Check to see if we reached the end of the spline on this movement,
			if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART)) 
				{
				// Start the Rat jumping into the water.
				rat->ra_state = ACTION_RAT_JUMPING;
				// Calculate the stuff needed to jump the rat.
				rat->ra_velocity = vCalculateInitialVelocity(pGof->pFrame->fr_matrix,
														rat->ra_map_diff_data->ra_target,
														&rat->ra_position,
														rat->ra_map_diff_data->ra_time);
				rat->ra_state = ACTION_RAT_JUMPING;
				rat->ra_curr_time = rat->ra_map_diff_data->ra_time << 1;
				}
			}
			break;
		// ----------------------------------------------------------------------------------------------------------
		// Rat is jumping towards the target.
		case ACTION_RAT_JUMPING:
			// Hopefully because we are not calling UpdateSplineMovement, these should stay put.
			xUpdateGofWithVelocity(&pGof->pFrame->fr_matrix,
								   &rat->ra_position,
								   &rat->ra_velocity);
			// Check to see if Time has reached zero.
			if (rat->ra_curr_time-- <= 0)
				{
				// Restart the rat.
				rat->ra_state = ACTION_RAT_RUNNING;
				}
			break;
		// -----------------------------------------------------------------------------------------------------------
		// Rat is jumping towards Frogger.
		case ACTION_RAT_JUMPING_TOWARDS_FROGGER:
			// Get position of Rat (on Spline) if we were jumpping towards Frogger.
			status_flags = ubGetSplineMovement(&rat->ra_desired_position, &rat->ra_path, &(rat->ra_map_data->PathData),
												rat->ra_map_diff_data->ra_speed);
			// Check to see if Time has reached zero.
			if (rat->ra_curr_time-- <= 0)
				// Restart the rat.
				rat->ra_state = ACTION_RAT_RUNNING;

			// So we know how long we have been away from the spline.
			rat->ra_catch_up++;
			break;
		// -------------------------------------------------------------------------------------------------------------
		}
		
	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSTATSunkCar
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSTATSunkCar(FG_GOF* gof)
*
*	FUNCTION	Normally Statics don't have update functions, but this has to make
*				a sound when hit, so we need one.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSTATSunkCar(FG_GOF *pGof)
{
	// Check too see if Frogger has landed on the STAT.
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// Play SFX of splosh.
		lPlaySample((MR_USHORT)SNDFX_SWP_SUNKCAR_THUD,127);
		}
	
	pGof->ubHitFlags = 0;

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateNewsPaper
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateNwsPaper(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of a newspaper.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateNewsPaper(FG_GOF *pGof)
{
	MR_BOOL	xReturn;

	xReturn = xUpdateStdMovingEnt(pGof);

	// check too see if the swamp Crusher has hit this object.
	if (pGof->ubHitFlags & ENTITY_HIT)
		// Yes, so change the anim list.
		vShowGofAnimation(pGof, ANIM_SWP_NEWSPAPER_CRUSHED, 0);

	// Check too see if Frogger has landed on the newpaper.
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// Play SFX of splosh.
		lPlaySample((MR_USHORT)SNDFX_SWP_NEWPAPER_SPLOSH,127);
		}
	
	pGof->ubHitFlags = 0;

	return xReturn;
}

/******************************************************************************
*%%%% SwpUpdateNewsPaperTorn
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateNewsPaperTorn(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of a ripping news paper.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateNewsPaperTorn(FG_GOF* pGof)
{
	FG_NEWSPAPER_TORN*	newspaper_torn = (FG_NEWSPAPER_TORN*)(pGof->pGameData);
	MR_UBYTE	status_flags;

	// Check too see if we are standing on the NewsPaper.
	if (ACTION_NEWSPAPER_TORN_ON == newspaper_torn->nt_state)
		{
		// Yes, so lets dec the timer.
		newspaper_torn->nt_curr_time--;
		// Some sort of anim code goes here to move the frames on.
		}

	// Check too see if Frogger is on the NewsPaper.
	if (pGof->ubHitFlags & PARENT_HIT)
		newspaper_torn->nt_state = ACTION_NEWSPAPER_TORN_ON;
	else
		{
		// Check too see if Frogger just jumpped off.
		if (newspaper_torn->nt_state == ACTION_NEWSPAPER_TORN_ON)
			newspaper_torn->nt_state = ACTION_NEWSPAPER_TORN_OFF;	// Yes.
		}

	pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction
									// and there is no reaction for jumpping off.

	// This moves the NewsPaperTorn along it's Spline.
	status_flags = ubUpdateSplineMovement(pGof, &newspaper_torn->nt_path, &(newspaper_torn->nt_map_data->PathData),
										   newspaper_torn->nt_map_diff_data->nt_speed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// If kill the height and restart the NewsPaperTorn as normal.
		newspaper_torn->nt_state = ACTION_NEWSPAPER_TORN_OFF;
		newspaper_torn->nt_curr_time = newspaper_torn->nt_map_diff_data->nt_rip_rate;
		// Reset Anim Frames to Start.
		}

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSTATPipe.
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSTATPipe(FG_GOF* gof)
*
*	FUNCTION	Normally static's don't have update functions, but this has to make
*				a sound when we hit it.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSTATPipe(FG_GOF *pGof)
{
	// Check too see if Frogger has landed on the STAT.
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// Play SFX of splosh.
		lPlaySample((MR_USHORT)SNDFX_SWP_PIPE_THUD,127);
		}
	
	pGof->ubHitFlags = 0;

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateRaccoon
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateRaccoon(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of the raccoon. It will swim around the
*				swamp until Frogger jumps of it, then it will start too sink.
*				Once Frogger has jumpped off, it will rise back. (Choking!)
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateRaccoon(FG_GOF* pGof)
{
	FG_RACCOON*	raccoon = (FG_RACCOON*)(pGof->pGameData);
	MR_UBYTE	status_flags;

	// All raccoons sink!
	switch (raccoon->ra_state)
		{
		// ------------------------------------------------------------------------------------------
		// Raccon sinks with frogger?
		case ACTION_RACCOON_SINKING:
			raccoon->ra_curr_height += raccoon->ra_map_diff_data->sb_sink_rate;
			break;
		// --------------------------------------------------------------------------------------------
		// Has just jumped off the raccoon, so clear the fall rate ready to start the slow climb back up.
		case ACTION_RACCOON_JUMPED_OFF:
			// Check too see if the raccoon is 'low' enough to be drowning.
			if (raccoon->ra_curr_height > RACCOON_DROWN_HEIGHT)
				{
				// Raccoon Almost drowned, so make him cough when he comes back up.
				pGof->uwAnimNumber = ANIM_RACCOON_DROWNING;
				raccoon->ra_state = ACTION_RACCOON_DEFAULT;
				}
			break;
		// ------------------------------------------------------------------------------------------
		// If not on the back, then the Raccoons returns to it's normal height..... may be.
		default:
			// If the Raccoons HAS been sinking, then we rise back up slowly. Once frogger has left.
			if (raccoon->ra_curr_height > 0)
				{
				if (pGof->uwAnimNumber == ANIM_RACCOON_DROWNING)
					raccoon->ra_curr_height -= raccoon->ra_map_diff_data->sb_sink_rate >> 1;	// Rise back at half speed.
				else
					raccoon->ra_curr_height -= raccoon->ra_map_diff_data->sb_sink_rate;
				}
			else
				raccoon->ra_curr_height = 0;			// If greater than zero, make it zero.
			break;
		}

	// Check too see if Frogger is on the Raccoon
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// check to see if we have just jumped on the Raccoon
		if (raccoon->ra_state == ACTION_RACCOON_NORMAL)
			{
			raccoon->ra_state = ACTION_RACCOON_SINKING;			// Set the Raccoon sinking.
			pGof->uwAnimNumber = ANIM_RACCOON_SINKING;			// Set anim of raccoon sinking.
			}				
		}
	else
		{
		// Check too see if Frogger just jumpped off.
		if (raccoon->ra_state == ACTION_RACCOON_SINKING)
			// Then Frogger just jumpped off.
			raccoon->ra_state = ACTION_RACCOON_JUMPED_OFF;
		else
			raccoon->ra_state = ACTION_RACCOON_NORMAL;
		}

	pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction
									// and there is no reaction for jumpping off.

	// This moves the Raccoon along it's Spline.
	status_flags = ubUpdateSplineMovement(pGof, &raccoon->ra_path, &(raccoon->ra_map_data->PathData),
										   raccoon->ra_map_diff_data->sb_speed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// If kill the height and restart the Raccoon as normal.
		raccoon->ra_state = ACTION_RACCOON_NORMAL;
		raccoon->ra_curr_height = 0;
		pGof->uwAnimNumber = ANIM_RACCOON_NORMAL;
		}

	// Adjust the height.
	if (NULL != pGof->pFrame)
		{
		pGof->pFrame->fr_matrix.t[1] += raccoon->ra_curr_height >> WORLD_SHIFT;
		pGof->pFrame->fr_flags |= MR_FRAME_NO_UPDATE;
		}

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateOilPatch
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateOilPatch(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of an oil patch
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateOil(FG_GOF *pGof)
{
	return xUpdateStdMovingEnt(pGof);
}

/******************************************************************************
*%%%% SwpUpdateWasteBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateWasteBarrel(FG_GOF* gof)
*
*	FUNCTION	Updates the move of an oil drum. 
*
*	It floats/sink under the water much the same as a TURTLE, but spins when
*	Frogger lands on it.
*
*	The Spinning increases the longer Frogger is on the Barrel and he must jump
*  	'forward' in order to stay alive. Once he jumps off it will slow down until
*	static.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateWasteBarrel(FG_GOF* pGof)
{
	FG_SWP_WASTE_BARREL* waste_barrel = (FG_SWP_WASTE_BARREL*)(pGof->pGameData);
	MR_MAT	temp_mat;
	MR_SVEC	rot;

	// Handle floating/Sinking stuff, if -1 then no sink data.
	if (waste_barrel->wb_map_diff_data->wb_float_time != -1)
		{
		switch (waste_barrel->wb_float_state)
			{
			// ----------------------------------------------------------------------
			case ACTION_WASTE_BARREL_FLOATING:
				// Wait for the barrel to sink.
				if (waste_barrel->wb_curr_time-- == 0)
			  		waste_barrel->wb_float_state = ACTION_WASTE_BARREL_SINKING;
			  	break;
			// ---------------------------------------------------------------------------		
			case ACTION_WASTE_BARREL_SINKING:
				// The barrel is sinking under the water.
				if (waste_barrel->wb_curr_height < SWP_WASTE_BARREL_SINK_HEIGHT)
					waste_barrel->wb_curr_height += SWP_WASTE_BARREL_SINK_SPEED;
				else
					{
					// The Waste Barrel has reached maximum depth.
					waste_barrel->wb_float_state = ACTION_WASTE_BARREL_SUNK;
					waste_barrel->wb_curr_time = waste_barrel->wb_map_diff_data->wb_sunk_time;
					}
				break;
			// ---------------------------------------------------------------------------
			case ACTION_WASTE_BARREL_SUNK:
				// Wait for the Barrel to rise.
				if (waste_barrel->wb_curr_time-- == 0)
					{
					waste_barrel->wb_float_state = ACTION_WASTE_BARREL_RISING;
					}
				break;
			// ---------------------------------------------------------------------------
			case ACTION_WASTE_BARREL_RISING:
				if (waste_barrel->wb_curr_height > 0)
					waste_barrel->wb_curr_height -= SWP_WASTE_BARREL_RISE_SPEED;
				else
					{
					// Waste Barrel has reached the surface.
					waste_barrel->wb_curr_time = waste_barrel->wb_map_diff_data->wb_float_time;
					waste_barrel->wb_float_state = ACTION_WASTE_BARREL_FLOATING;
					}
				break;
			// -----------------------------------------------------------------------------
			}
		}

	// This moves the waste barrel along it's Spline.
	ubUpdateSplineMovement(pGof, &waste_barrel->wb_path, &(waste_barrel->wb_map_data->PathData),
						   waste_barrel->wb_map_diff_data->wb_speed);

	// Don't bother if off-screen
	if (NULL != pGof->pFrame)
		{
		// Adjust the height. (-1 means no sink height.)
		if (waste_barrel->wb_map_diff_data->wb_float_time != -1)
			pGof->pFrame->fr_matrix.t[1] += waste_barrel->wb_curr_height >> WORLD_SHIFT;
		}

	// check too see if the swamp Crusher has hit this object.
	if (pGof->ubHitFlags & ENTITY_HIT)
		// Yes, so change the anim list.
		vShowGofAnimation(pGof, ANIM_SWP_WASTE_BARREL_CRUSHED, 0);

	// Check too see if Frogger is on the barrel.
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// check to see if we have just jumped on the barrel
		if (waste_barrel->wb_spin_state == ACTION_WASTE_BARREL_NO_SPIN)
			waste_barrel->wb_spin_state = ACTION_WASTE_BARREL_SPINNING;		// Set the Barrel Spinning
		}
	else
		{
		// Check too see if Frogger just jumpped off.
		if (waste_barrel->wb_spin_state == ACTION_WASTE_BARREL_SPINNING)
			// Then Frogger just jumpped off.
			waste_barrel->wb_spin_state = ACTION_WASTE_BARREL_STOPPING_SPIN;
		else 
			waste_barrel->wb_spin_state = ACTION_WASTE_BARREL_NO_SPIN;
		}

	pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction

	// Check too see if the barrel is Spinning.
	switch(waste_barrel->wb_spin_state)
		{
		// ---------------------------------------------------------------------------------------
		case ACTION_WASTE_BARREL_SPINNING:
			if (waste_barrel->wb_curr_spin_speed < waste_barrel->wb_map_diff_data->wb_max_spin )
				waste_barrel->wb_curr_spin_speed += waste_barrel->wb_map_diff_data->wb_spin_acc;
			break;
		// ---------------------------------------------------------------------------------------
		case ACTION_WASTE_BARREL_STOPPING_SPIN:
			if (waste_barrel->wb_curr_spin_speed > waste_barrel->wb_map_diff_data->wb_spin_acc)
				waste_barrel->wb_curr_spin_speed -= waste_barrel->wb_map_diff_data->wb_spin_acc;
			else
				waste_barrel->wb_curr_spin_speed = 0;
			break;
		// ---------------------------------------------------------------------------------------
		}

	if (waste_barrel->wb_spin_state != ACTION_WASTE_BARREL_NO_SPIN)
		{
		waste_barrel->wb_spin_rotation += (waste_barrel->wb_curr_spin_speed >> WORLD_SHIFT);
		waste_barrel->wb_spin_rotation &= 4095;
		rot.vx = 0;
		rot.vy = 0;
		rot.vz = waste_barrel->wb_spin_rotation;

		// Apply any Z rotation we want to make the barrel roll if pFrame is valid.
		if (NULL != pGof->pFrame)
			{
			MRRotMatrix(&rot, &temp_mat);
			MRMulMatrixABA(&pGof->pFrame->fr_matrix,&temp_mat);
			}
		}

	return MR_SUCCESS;
}
/******************************************************************************
*%%%% SwpUpdateNuclearBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateNuclearBarrel(FG_GOF* gof)
*
*	FUNCTION	Updates the move of an oil drum. 
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateNuclearBarrel(FG_GOF* pGof)
{
	FG_SWP_NUCLEAR_BARREL*	nuclear_barrel = (FG_SWP_NUCLEAR_BARREL*)(pGof->pGameData);
	FG_FROG*	real_frog;
	FG_GOF*		frog_gof;
	MR_UBYTE	player = NO_PLAYER;

	// Find the Frog that's on the barrel.
	player = ubGetNextPlayer(player);
	
	frog_gof = &gFrogsGof[player];		// Get Frog gof
	real_frog = (FG_FROG*)(frog_gof->pGameData);

	switch (nuclear_barrel->nb_state)
		{
		// ---------------------------------------------------------------------------------------------
		// Barrel running along spline.
		case ACTION_NUCLEAR_BARREL_NORMAL:
			ubUpdateSplineMovement(pGof, &nuclear_barrel->nb_path, &(nuclear_barrel->nb_map_data->PathData),
								   nuclear_barrel->nb_map_diff_data->nb_speed);

			// Check too see if Frogger is on the barrel.
			if (pGof->ubHitFlags & PARENT_HIT)
				{
				// Once on the barrel, throw frogger to the target.
				nuclear_barrel->nb_state = ACTION_NUCLEAR_BARREL_EXPLODING;
				nuclear_barrel->nb_velocity = vCalculateInitialVelocity(frog_gof->pFrame->fr_matrix,
																	  nuclear_barrel->nb_map_diff_data->nb_target,
																	  &nuclear_barrel->nb_position,
																	  FROGGER_TIME_TO_NUCLEAR_TARGET);
				nuclear_barrel->nb_curr_time = (FROGGER_TIME_TO_NUCLEAR_TARGET-5);	// Because we drop Frogger above ground.
		
				// need to check that parent is valid...!
				if (NULL != real_frog->pParentGof)
					{
					vDetachGofFromGof(frog_gof, real_frog->pParentGof);	// Detach Frog FROM this Gof.
					real_frog->pParentGof = NULL;
					}
				real_frog->uwAction |= FROGACTION_NORESPOND;			// Stop user input
				}
		
			pGof->ubHitFlags = 0;			// This has to be cleared every frame as it only gets SET on a reaction
			break;
		// --------------------------------------------------------------------------------------------------
		case ACTION_NUCLEAR_BARREL_EXPLODING:
			// Move the Frog and explode the barrel.
			xUpdateGofWithVelocity(&frog_gof->pFrame->fr_matrix,
								   &nuclear_barrel->nb_position,
								   &nuclear_barrel->nb_velocity);
			// Check to see if Time has reached zero.
			if (nuclear_barrel->nb_curr_time-- <= 0)
				{						
				// Restart the Barrel.
				nuclear_barrel->nb_state = ACTION_NUCLEAR_BARREL_DEAD;
				
				// Drop the Frog and let him fall.
				vFrogChangeState(frog_gof, FROGFLAG_JUMPING);
				
				// Remove the norespond flag.
				real_frog->uwAction &= ~FROGACTION_NORESPOND;	// Restart User Input.
				}
			break;
		// ---------------------------------------------------------------------------------------------------
		// The Barrels been killed.
		case ACTION_NUCLEAR_BARREL_DEAD:
			break;
		// --------------------------------------------------------------------------------------------------
	}
	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSTATMarsh
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSTATMarsh(FG_GOF* gof)
*
*	FUNCTION	Normally Static's don't have update functions, but this has to 
*				to make a sound when hit, so we need one.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSTATMarsh(FG_GOF *pGof)
{
	// Check too see if Frogger has landed on the STAT.
	if (pGof->ubHitFlags & PARENT_HIT)
		{
		// Play SFX of splosh.
		lPlaySample((MR_USHORT)SNDFX_SWP_MARSH_MUD,127);
		}
	
	pGof->ubHitFlags = 0;

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateCrusher
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateCrusher(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of the crusher so we can have a SFX when they hit.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateCrusher(FG_GOF* pGof)
{
	FG_LOG*		log = (FG_LOG*)(pGof->pGameData);
	MR_UBYTE	status_flags;
	GOFHITSTRUCT	CollHitStruct;
	MR_BOOL	xResult;

	status_flags = ubUpdateSplineMovement(pGof, &log->Path, &(log->pMapData->PathData), 
										   log->pMapDiffData->uwSpeed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// If got to the end of the Spline, then play the SFX.
		lPlaySample((MR_USHORT)SNDFX_SWP_CRUSHER_CLOSE,127);
		}

	// Should we only check if we have an object?
	if (NULL != pGof->pObject)
		{
		// Check to see if we have hit a Gof???
		xResult = xCheckCollGofs(pGof,&CollHitStruct);

		// Was an entity hit ?
		if ( MR_SUCCESS == xResult )
			// Yes ... Flag entity as hit.
			CollHitStruct.pHitGof->ubHitFlags |= ENTITY_HIT;
		}

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateWeirRubbish
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateWeirRubbish(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of Weir Rubbish. 
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateWeirRubbish(FG_GOF* pGof)
{
	FG_SWP_WEIR_RUBBISH* weir_rubbish = (FG_SWP_WEIR_RUBBISH*)(pGof->pGameData);
	MR_UBYTE	status_flags;
	MR_USHORT	speed;			// Used to pass Speed to UpdateSpline.

	// Take the initial Speed.
	speed = weir_rubbish->wr_map_diff_data->wr_speed;
	// Check to see if the time limit is up.
	if (weir_rubbish->wr_curr_time > 0)
		weir_rubbish->wr_curr_time--;
	else
		{
		// Add the current accelertion to current speed. 
		speed += (MR_USHORT)(weir_rubbish->wr_curr_speed >> WORLD_SHIFT);
		weir_rubbish->wr_curr_speed += weir_rubbish->wr_map_diff_data->wr_acceleration;
		}

	status_flags = ubUpdateSplineMovement(pGof, &weir_rubbish->wr_path, &(weir_rubbish->wr_map_data->PathData), 
										  speed);

	// Check to see if we reached the end of the spline on this movement,
	if (status_flags & (MOVEMENT_REVERSE|MOVEMENT_RESTART))
		{
		// End of Spline, so reset the speed.
		weir_rubbish->wr_curr_speed = 0;
		weir_rubbish->wr_curr_time = weir_rubbish->wr_map_diff_data->wr_time_delay;	// And the time.
		}

	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSquirt
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSquirt(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of a squirt.
*
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSquirt(FG_GOF* pGof)
{
	FG_SWP_SQUIRT*	squirt = (FG_SWP_SQUIRT*)(pGof->pGameData);

   		switch(squirt->sq_action)
			{
			// ---------------------------------------------------------------------------
			case ACTION_SWP_SQUIRT_WAITING:
				// Check to see if the time limit is up.
				if (squirt->sq_curr_time > 0)
					squirt->sq_curr_time--;
				else
					{
					// Time's up, so drop to the ground.
					squirt->sq_velocity = vCalculateInitialVelocity(pGof->pFrame->fr_matrix,
																   squirt->sq_map_diff_data->sq_target,
																   &squirt->sq_position,
																   squirt->sq_map_diff_data->sq_drop_time);
					squirt->sq_action = ACTION_SWP_SQUIRT_FALLING;
					vShowGofAnimation(pGof, ANIM_SWP_SQUIRT_FALLING, 0);
					squirt->sq_curr_time = squirt->sq_map_diff_data->sq_drop_time;
					}
				break;
			// ------------------------------------------------------------------------------
			case ACTION_SWP_SQUIRT_FALLING:
				// Squirt is falling towards the target
				xUpdateGofWithVelocity(&pGof->pFrame->fr_matrix,
									   &squirt->sq_position,
									   &squirt->sq_velocity);
			
				// Check to see if Time has reached zero.
				if (squirt->sq_curr_time-- <= 0)
					{
					// If Zero then, reset the squirt to be waiting.
					squirt->sq_action = ACTION_SWP_SQUIRT_WAITING;
					squirt->sq_curr_time = squirt->sq_map_diff_data->sq_time_delay;
					// May be trigger some sort of 'squash' animation.
					vShowGofAnimation(pGof, ANIM_SWP_SQUIRT_SQUASHED, 0);
					// reset the position based on the supplied matrix...
					MR_COPY_MAT(&pGof->pFrame->fr_matrix, &squirt->sq_map_data->mat);
					MR_COPY_VEC(&pGof->pFrame->fr_matrix.t, &squirt->sq_map_data->mat.t);
					}
					break;
			// ------------------------------------------------------------------------------------------
			}
	return MR_SUCCESS;
}

/******************************************************************************
*%%%% SwpUpdateSTATWasteBarrel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL			SwpUpdateSTATWasteBarrel(FG_GOF* gof)
*
*	FUNCTION	Updates the movement of a static barrel.
*
*	INPUTS		gof		-		ptr to the gof to set.
*
*	RESULT		NONE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.01.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_BOOL SwpUpdateSTATWasteBarrel(FG_GOF* pGof)
{
	FG_SWP_STAT_WASTE_BARREL*	stat_waste_barrel = (FG_SWP_STAT_WASTE_BARREL*)(pGof->pGameData);

	// Handle floating/Sinking stuff, if -1 then no sink data.
	if (stat_waste_barrel->wb_map_diff_data->wb_float_time != -1)
		{
		switch (stat_waste_barrel->wb_float_state)
			{
			// -----------------------------------------------------------------------------------
			case ACTION_WASTE_BARREL_FLOATING:
				// Wait for the barrel to sink.
				if (stat_waste_barrel->wb_curr_time-- == 0)
		  			stat_waste_barrel->wb_float_state = ACTION_WASTE_BARREL_SINKING;
		  		break;
			// ----------------------------------------------------------------------------------			
			case ACTION_WASTE_BARREL_SINKING:
				// The barrel is sinking under the water.
				if (stat_waste_barrel->wb_curr_height < SWP_STAT_WASTE_BARREL_SINK_HEIGHT)
					stat_waste_barrel->wb_curr_height += SWP_STAT_WASTE_BARREL_SINK_SPEED;
				else
					{
					// The Waste Barrel has reached maximum depth.
					stat_waste_barrel->wb_float_state = ACTION_WASTE_BARREL_SUNK;
					stat_waste_barrel->wb_curr_time = stat_waste_barrel->wb_map_diff_data->wb_sunk_time;
					}
				break;
			// ---------------------------------------------------------------------------------
			case ACTION_WASTE_BARREL_SUNK:
				// Wait for the Barrel to rise.
				if (stat_waste_barrel->wb_curr_time-- == 0)
					stat_waste_barrel->wb_float_state = ACTION_WASTE_BARREL_RISING;
				break;
			// -----------------------------------------------------------------------------------------
			case ACTION_WASTE_BARREL_RISING:
				if (stat_waste_barrel->wb_curr_height > 0)
					stat_waste_barrel->wb_curr_height -= SWP_STAT_WASTE_BARREL_RISE_SPEED;
				else
					{
					// Waste Barrel has reached the surface.	
					stat_waste_barrel->wb_curr_time = stat_waste_barrel->wb_map_diff_data->wb_float_time;
					stat_waste_barrel->wb_float_state = ACTION_WASTE_BARREL_FLOATING;
					}
				break;
			// ------------------------------------------------------------------------------------------
			}

		// Adjust the height. (-1 means no sink height.)
		if (stat_waste_barrel->wb_map_diff_data->wb_float_time != -1)
			pGof->pFrame->fr_matrix.t[1] += stat_waste_barrel->wb_starting_height + (stat_waste_barrel->wb_curr_height >> WORLD_SHIFT);
	}

	return MR_SUCCESS;
}
