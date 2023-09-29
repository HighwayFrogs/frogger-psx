// DELETED CODE FOLLOWS!!!


// Theses are here as a TEST. I realize that this is a crap way of doing things, but 
// it's only a quick hack for the Build to SONY. It stops the same type of entity triggering
// a sfx if that sound is already playing.

MR_USHORT	lorrysfx;
MR_USHORT	carsfx;
MR_USHORT	swansfx;
MR_USHORT	snakesfx;
   

MR_VOID	ENTSTRSubUpdateLorry(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if (lorrysfx == 0)
		{
		if ( rand()%200 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],LORRY_HORN01);
			lorrysfx = 5 * 30;			// Stop's us getting another lorry SFX for a while.
			}
		}
	else
		{
		lorrysfx--;
		}

#endif

}

MR_VOID	ENTSTROrgUpdateSnake(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if (snakesfx == 0)
		{
		if ( rand()%300 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],SFX_ORG_SNAKE_HISS);
			snakesfx = 5 * 30;			// Stop's us getting another snake SFX for a while.
			}
		}
	else
		{
		snakesfx--;
		}

#endif

}

MR_VOID	ENTSTRSubUpdateSwan(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if (swansfx == 0)
		{
		if ( rand()%200 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],SWAN_CALL);
			swansfx = 5 * 30;			// Stop's us getting another swan SFX for a while.
			}
		}
	else
		{
		swansfx--;
		}

#endif

}

MR_VOID	ENTSTRSubUpdateLawnMower(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);
#ifdef FROG_SOUND
	//if ( rand()%200 == 1 )
	//	MRSNDPlaySound(MOWER_NORMAL,NULL,0,0);
#endif
}

MR_VOID	ENTSTRSkyUpdateBird1(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if ( birdsfx == 0 )
		{
		if ( rand()%300 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],SKY_BIRD1_1);
			birdsfx = 5 * 30;
			}
		}
	else
		{
		birdsfx--;
		}

#endif

}

MR_VOID	ENTSTROrgUpdateTruckRed(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if (carsfx == 0)
		{
		if ( rand()%300 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],CAR_HORN02);
			carsfx = 5 * 30;			// Stop's us getting another car SFX for a while.
			}
		}
	else
		{
		carsfx--;
		}

#endif

}

MR_VOID	ENTSTROrgUpdateCarPurple(LIVE_ENTITY*	live_entity)
{
	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef FROG_SOUND

	if (carsfx == 0)
		{
		if ( rand()%300 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],CAR_HORN01);
			carsfx = 5 * 30;
			}
		}
	else
		{
		carsfx--;
		}

#endif

}




/******************************************************************************
*%%%% ENTSTRSubCreateSwan
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID ENTSTRSubCreateSwan(LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a swan entity.
*
*	INPUTS		live_entity		- ptr to entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.11.96	Gary Richards	Created
*	25.04.97	Martin Kift		Added to new frogger
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubCreateSwan(LIVE_ENTITY*	live_entity)
{ 
	SUB_SWAN*  		swan_map_data;
	SUB_SWAN_RT*	swan;
	ENTITY*			entity;


	entity 			= live_entity->le_entity;
	swan_map_data	= (SUB_SWAN*)(entity + 1);

	// call standard create function
	ENTSTRCreateMovingMOF(live_entity);

	// Set specific swan runtime data.
	swan = MRAllocMem(sizeof(SUB_SWAN_RT),"SUB_RT_SWAN");
	swan->sw_flap_delay = swan_map_data->sw_swimming_time;

	swan->sw_moving_sound = NULL;

	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
	MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ANIM_SWAN_SWIMMING);

	live_entity->le_specific = swan;
}

/******************************************************************************
*%%%% ENTSTRSubKillSwan
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubKillSwan(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a Swan
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Martin Kift 	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubKillSwan(LIVE_ENTITY*	live_entity)
{
	// Free the memory for the runtime structures.
	MRFreeMem(live_entity->le_specific);
	ENTSTRKillMovingMOF(live_entity);
}


/******************************************************************************
*%%%% ENTSTROrgUpdateSwan
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTROrgUpdateSwan(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a Swan
*
*	INPUTS		live_entity	-	to update
*
*	NOTES		A swan will move along a (normally) closed splines.
*				After a (flap) delay it will start to 'think' about flapping, at which point 
*				Frogger will need to get off. Once the 'think' delay has reached zero, the 
*				swan will starting flapping and if Frogger is still on it's back, Frogger will
*				be thrown off.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Gary Richards	Created
*	25.04.97	Martin Kift		Added to new code
*
*%%%**************************************************************************/

MR_VOID	ENTSTROrgUpdateSwan(LIVE_ENTITY*	live_entity)
{
	ENTITY*	   		entity;
	SUB_SWAN_RT*	swan;
	SUB_SWAN*		swan_map_data;


	entity			= live_entity->le_entity;
	swan			= live_entity->le_specific;
	swan_map_data	= (SUB_SWAN*)(entity + 1);

	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

	switch (swan->sw_action)
		{
		// ----------------------------------------------------------------------------------------
		// Do nothing if FlapDelay == -1 else count down to start flapping
		case SUB_ACTION_SWAN_SWIMMING:
			if(swan->sw_flap_delay != -1)
				{
				if(swan->sw_flap_delay-- == 0)
					{
					swan->sw_action = SUB_ACTION_SWAN_START_FLAP;
					swan->sw_flap_delay = swan_map_data->sw_flap_think_time;
					}
				}
			break;
		// ------------------------------------------------------------------------------------------
		// Swan has started flapping, count down to full flappyness
		case SUB_ACTION_SWAN_START_FLAP:
			if (swan->sw_flap_delay-- == 0)
				{
				swan->sw_action = SUB_ACTION_SWAN_FLAPPING;
				swan->sw_flap_delay = swan_map_data->sw_flapping_time;

				MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
				MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ANIM_SWAN_FLAPPING);
				}
			break;
		// ----------------------------------------------------------------------------------------------
		// Swan is flapping, keep going still he gets tired
		case SUB_ACTION_SWAN_FLAPPING:
			if (swan->sw_flap_delay-- == 0)
				{
				swan->sw_action = SUB_ACTION_SWAN_STOP_FLAP;
				swan->sw_flap_delay = swan_map_data->sw_flap_think_time;
				}
			break;
		// ----------------------------------------------------------------------------------------------
		// Swam is stopping his flap, keep going till he;s back to swimming
		case SUB_ACTION_SWAN_STOP_FLAP:
			if (swan->sw_flap_delay-- == 0)
				{
				swan->sw_action = SUB_ACTION_SWAN_SWIMMING;
				swan->sw_flap_delay = swan_map_data->sw_swimming_time;

				MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
				MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ANIM_SWAN_SWIMMING);
				}
			break;
		}
}

/******************************************************************************
*%%%% ENTSTRSubCreateTurtle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubCreateTurtle(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a moving turtle.
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.11.96	Martin Kift		Created
*	07.01.97	Martin Kift		Added code for animated models (although commented 
*								out at the moment since we don't actually have any!
*	17.04.97	Martin Kift		Rewrote to conform to new coding standard
*	24.04.97	Gary Richards	Included in the new game code.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubCreateTurtle(LIVE_ENTITY*	live_entity)
{
	SUB_TURTLE*		turtle_map_data;
	SUB_TURTLE_RT*	turtle;
	ENTITY*			entity;

	entity 		= live_entity->le_entity;
	turtle_map_data	= (SUB_TURTLE*)(entity + 1);

	ENTSTRCreateMovingMOF(live_entity);

	// Set specific Turtle runtime data.
	turtle = MRAllocMem(sizeof(SUB_TURTLE_RT),"SUB_TURTLE");
	turtle->tu_dive_count	= turtle_map_data->tu_dive_delay;
	turtle->tu_dive_height	= 0;	// Y Offset from spline base.
	turtle->tu_state		= SUB_ACTION_TURTLE_SWIMMING;
	live_entity->le_specific = turtle;
}

/******************************************************************************
*%%%% ENTSTRSubUpdateTurtle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubUpdateTurtle(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function is used to update the position of a turtle.
*				It uses the data defined in the map to control it's movement.
*				A turtle swims along the surface of the water, dives under and 
*				swims along under the water, before rising back to the surface.
*				It uses UpdateSplineMovement to move it along the spline, taking 
*				the angle of the spline to sets its own rotations.
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.11.96	Gary Richards	Created
*	09.01.97	Martin Kift		Added code for animated models (although commented 
*								out at the moment since we don't actually have any!
*	09.01.97	Martin Kift		Removed call to updatemoving sound, since its not needed
*	17.04.97	Martin Kift		Rewrote to conform to new coding standard
*	25.04.97	Martin Kift		Changed old frogger animation code to API calls
*
*%%%**************************************************************************/

MR_VOID	ENTSTRSubUpdateTurtle(LIVE_ENTITY*	live_entity)
{
	ENTITY*			entity;
	SUB_TURTLE_RT*	turtle;
	SUB_TURTLE*		turtle_map_data;


	entity	= live_entity->le_entity;
	turtle  = live_entity->le_specific;
	turtle_map_data	= (SUB_TURTLE*)(entity + 1);

	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

	// Handle diving/rising stuff, if -1 then no dive data.
	if (turtle_map_data->tu_dive_delay != -1)
		{
		switch (turtle->tu_state)
			{
			case SUB_ACTION_TURTLE_SWIMMING:
				// Wait for the turtle to trigger a dive.
				if (turtle->tu_dive_count-- == 0)
					{
					MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
					MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ACTION_TURTLE_DIVING);
					turtle->tu_state = SUB_ACTION_TURTLE_DIVING;
#ifdef FROG_SOUND
					MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],SFX_ORG_TURTLE_SPLASH);
#endif
					}
					break;
		
			case SUB_ACTION_TURTLE_DIVING:
				// The turtle is diving under the water.
				if (turtle->tu_dive_height < SUB_TURTLE_DIVE_HEIGHT)
					turtle->tu_dive_height += turtle_map_data->tu_dive_speed;
				else
					{
					// The turtle has reached maximum depth.
		
					// show turtle swimming animation
					MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
					MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ACTION_TURTLE_SWIMMING);
					turtle->tu_state = SUB_ACTION_TURTLE_UNDERWATER_SWIMMING;
					turtle->tu_dive_count = turtle_map_data->tu_rise_delay;
					}
				break;
		
			case SUB_ACTION_TURTLE_UNDERWATER_SWIMMING:
				// Wait for the turtle to trigger a rise.
				if (turtle->tu_dive_count-- == 0)
					{
					// show diving turtle animation
					turtle->tu_state = SUB_ACTION_TURTLE_RISING;
					
					// show only 3rd (index 2) frame of animation
					MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
					MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ACTION_TURTLE_DIVING);
					}
				break;
		
			case SUB_ACTION_TURTLE_RISING:
				if (turtle->tu_dive_height > 0)
					turtle->tu_dive_height -= turtle_map_data->tu_rise_speed;
				else
					{
					// Turtle has reached the surface.
					turtle->tu_dive_count = turtle_map_data->tu_dive_delay;
		
					// show turtle swimming animation
					MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ISANIMATED);
					MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, SUB_ACTION_TURTLE_SWIMMING);
					turtle->tu_state = SUB_ACTION_TURTLE_SWIMMING;
					}
				break;
			}
		}
	
	// Adjust the height. (-1 means no dive height.)
	if (turtle_map_data->tu_dive_delay != -1)
		live_entity->le_lwtrans->t[1] += (turtle->tu_dive_height >> WORLD_SHIFT);
}

/******************************************************************************
*%%%% ENTSTRSubKillTurtle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRSubKillTurtle(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a Turtle
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID	ENTSTRSubKillTurtle(LIVE_ENTITY*	live_entity)
{
	// Free the memory for the runtime structures.
	MRFreeMem(live_entity->le_specific);
	ENTSTRKillMovingMOF(live_entity);
}


// These's are temp functions.
MR_VOID	ENTSTRSubUpdateCar(LIVE_ENTITY*	live_entity)
{

	// Call standard moving entity.
	ENTSTRUpdateMovingMOF(live_entity);

#ifdef	FROG_SOUND

	if (carsfx == 0)
		{
		if ( rand()%200 == 1 )
			{
			MRSNDCreateMovingSound((MR_VEC*)&live_entity->le_lwtrans->t[0],(MR_VEC*)&live_entity->le_lwtrans->t[0],CAR_HORN01);
			carsfx = 5 * 30;			// Stop's us getting another car SFX for a while.
			}
		}
	else
		{
		carsfx--;
		}

#endif

}

