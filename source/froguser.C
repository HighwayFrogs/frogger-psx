/******************************************************************************
*%%%% froguser.c
*------------------------------------------------------------------------------
*
*	User frog control
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	13.05.97	Tim Closs		Created
*	20.05.97	Martin Kift		Added des_thermal & slippy functions
*	25.05.97	Martin Kift		Added 2 cobweb (cave) user modes
*	25.06.97	Martin Kift		Added freeform slippy code
*
*%%%**************************************************************************/

#include "froguser.h"
#include "frog.h"
#include "camera.h"
#include "froganim.h"
#include "particle.h"
#include "sound.h"
#include "ent_gen.h"
#include "ent_cav.h"

//------------------------------------------------------------------------------------------------
// User setup functions		- called from SetFrogUserMode()
//------------------------------------------------------------------------------------------------
MR_VOID (*Froguser_mode_setup_functions[])(FROG*, MR_ULONG) =
	{
	FroguserThrowSetup,
	FroguserThermalSetup,
	FroguserSlippingLandGridSetup,
	FroguserSlippingEntitySetup,
	FroguserCobwebSetup,
	FroguserBouncyCobwebSetup,
	FroguserSlippingLandNonGridSetup,
	NULL,
	FroguserCheckpointCollectedSetup,						// FROGUSER_MODE_CHECKPOINT_COLLECTED
	FroguserLevelStartBounceSetup,								// FROGUSER_MODE_LEVEL_START_BOUNCE
	FroguserLevelStartComeToRestSetup,						// FROGUSER_MODE_LEVEL_START_COME_TO_REST
	FroguserSlippingSimpleLandGridSetup,					// 
	FroguserBounceSetup,									// FROGUSER_MODE_BOUNCE
	FroguserCliffRollSetup,									// FROGUSER_MODE_CLIFF_ROLL
	};


//------------------------------------------------------------------------------------------------
// User control functions	- called from ControlFrog() from UpdateFrog()
//------------------------------------------------------------------------------------------------
MR_VOID (*Froguser_mode_control_functions[])(FROG*, MR_ULONG) =
	{
	NULL,
	NULL,
	FroguserSlippingLandGridControl,
	FroguserSlippingEntityControl,
	FroguserCobwebControl,
	FroguserBouncyCobwebControl,
	FroguserSlippingLandNonGridControl,
	NULL,
	NULL,													// FROGUSER_MODE_CHECKPOINT_COLLECTED
	NULL,													// FROGUSER_MODE_LEVEL_START_BOUNCE
	NULL,													// FROGUSER_MODE_LEVEL_START_COME_TO_REST
	FroguserSlippingLandGridControl,
	FroguserBounceControl,									// FROGUSER_MODE_BOUNCE
	NULL,													// FROGUSER_MODE_CLIFF_ROLL
	};


//------------------------------------------------------------------------------------------------
// User movement functions	- called from MoveFrog() from UpdateFrog()
//------------------------------------------------------------------------------------------------
MR_ULONG (*Froguser_mode_movement_functions[])(FROG*, MR_ULONG, MR_ULONG*) =
	{
	NULL,
	NULL,
	FroguserSlippingLandGridMovement,
	FroguserSlippingEntityMovement,
	FroguserCobwebMovement,
	FroguserBouncyCobwebMovement,
	FroguserSlippingLandNonGridMovement,
	FroguserMoveFroggerToTargetAndBackMovement,
	FroguserCheckpointCollectedMovement,					// FROGUSER_MODE_CHECKPOINT_COLLECTED
	FroguserLevelStartBounceMovement,						// FROGUSER_MODE_LEVEL_START_BOUNCE
	FroguserLevelStartComeToRestMovement,					// FROGUSER_MODE_LEVEL_START_COME_TO_REST
	FroguserSlippingLandGridMovement,
	FroguserBounceMovement,									// FROGUSER_MODE_BOUNCE
	FroguserCliffRollMovement,								// FROGUSER_MODE_CLIFF_ROLL
	};

//------------------------------------------------------------------------------------------------
// Array which is used by the slidey code to fairly accurately slide the frog over an angled
// slope. The angle of a slope will be reduced down to maybe 8 levels, hence the smallness of
// the array. Speeds are measured in the number of frames that should be taken to slide for
// this sloped grid square... the default for a flat slippy piece of ground is 10 frames
//------------------------------------------------------------------------------------------------
MR_LONG FrogSlopeSpeeds1[9] = 
	{
	1,		// vertical away
	1,
	2,
	2,
	3,		// flat
	3,
	4,
	4,
	5,		// Vertical towards
	};

MR_LONG FrogSlopeSpeeds2[9] = 
	{
	1,		// vertical away
	1,
	2,
	2,
	3,		// flat
	3,
	4,
	4,
	5,		// Vertical towards
	};

/******************************************************************************
*%%%% FroguserThrowSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserThrowSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog being thrown.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserThrowSetup(FROG* frog, MR_ULONG mode)
{
	CAMERA*	camera;

	// Throw frogger in direction he is facing
	camera = &Cameras[frog->fr_frog_id];
#ifdef WIN95
	if (MNIsNetGameRunning())
		camera = &Cameras[0];
#endif

	JumpFrog(frog, frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N], NULL, 2, 10);

	// frog->fr_mode is now FROG_MODE_JUMPING
}

/******************************************************************************
*%%%% FroguserThrowMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserThrowMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog being thrown.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserThrowMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	return 0;
}

/******************************************************************************
*%%%% FroguserThermalSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserThermalSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog being thrown by desert thermal.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserThermalSetup(FROG* frog, MR_ULONG mode)
{
	// setup count to wait for 2 secs (60 frames)
	frog->fr_count = 60;
}


/******************************************************************************
*%%%% FroguserThermalMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserThermalMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog being thrown by desert thermal
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserThermalMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	CAMERA*	camera;

	// if count reaches zero, throw frog!
	if (!frog->fr_count--)
		{
		// Throw frogger in direction he is facing, for 2 grid squares
		camera = &Cameras[frog->fr_frog_id];

#ifdef WIN95
	if (MNIsNetGameRunning())
		camera = &Cameras[0];
#endif

		JumpFrog(frog, frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N], NULL, 2, 15);

		// frog->fr_mode is now FROG_MODE_JUMPING
		}

	// return no flags
	return 0;
}

/******************************************************************************
*%%%% FroguserSlippingLandGridSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandGridSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	NOTES		This mode attempts a lot of things. Basically, if the frog jumps
*				onto a slippy grid square, it should slip in its current direction
*				if the slope if less than 45 degrees against it, else is should
*				slip backwards. The speed of the slip (well the duration acutally)
*				is also defined by the gradient of the slope. Friction and suchlike
*				is ignored.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingLandGridSetup(FROG* frog, MR_ULONG mode)
{
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	GRID_SQUARE*	grid_square_backup;
	MR_LONG			dx, dz;
	MR_LONG			u, y1, grid_x, grid_z, s;
	MR_VEC			normal, shift_normal;
	MR_LONG			count;

	// WE have had a slipping request... However, because the frog could have jumped whilst
	// already slipping, we may be between 2 grid squares... this will result in a wierd jump.
	// There I think we should re-calc our grid_x and grid_z, and resultance grid_square, to
	// stop these problems

	// back up old data first
	dx						= frog->fr_grid_x;
	dz						= frog->fr_grid_z;
	grid_square_backup		= frog->fr_grid_square;
	
	// calc new data
	frog->fr_grid_x			= GET_GRID_X_FROM_WORLD_X(frog->fr_lwtrans->t[0]);
	frog->fr_grid_z			= GET_GRID_Z_FROM_WORLD_Z(frog->fr_lwtrans->t[2]);
	frog->fr_grid_square	= NULL;

	grid_stack 				= Grid_stacks + (frog->fr_grid_z * Grid_xnum) + frog->fr_grid_x;

	// look through grid stacks to find a valid one to slide too!
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				y1 = GetGridSquareHeight(grid_square);
				
				if (abs(frog->fr_lwtrans->t[1] - y1) <= FROG_JUMPUP_LARGE_DY)
					{
					frog->fr_grid_square = grid_square;
					break;
					}
				}
			grid_square++;
			}
		}

	// check for NULL gridsquare, if so, put back old data
	if	(!frog->fr_grid_square)
		{
		frog->fr_grid_x			= dx;
		frog->fr_grid_z			= dz;
		frog->fr_grid_square	= grid_square_backup;
		}

	// get normal of this grid square
	// normal will be frog's local Y (-ve)
	GetGridSquareAverageNormal(frog->fr_grid_square, &normal);		

	// Generate shifted normal's vx and vz to be -1 to 1 based numbers, dependent on the slope.
	if (normal.vx > FROGUSER_GRID_SLIP_MIN_SLOPE)
		shift_normal.vx = 1;
	else 
	if (normal.vx < -FROGUSER_GRID_SLIP_MIN_SLOPE)
		shift_normal.vx = -1;
	else
		shift_normal.vx = 0;

	if (normal.vz > FROGUSER_GRID_SLIP_MIN_SLOPE)
		shift_normal.vz = 1;
	else 
	if (normal.vz < -FROGUSER_GRID_SLIP_MIN_SLOPE)
		shift_normal.vz = -1;
	else
		shift_normal.vz = 0;

	normal.vy = -normal.vy;

	// Look at direction of frog, and compare this to the direction and steepness of the slope
	// to calc the actual direction and speed of slip
	u	= frog->fr_direction;
	dx	= shift_normal.vx;
	dz	= shift_normal.vz;

	// Calculate count for the slide, which is more difficult that it sounds... If the
	// slope is with the frog, then use speed
	
	if	(
		(dx == 0) &&
		(dz == 0)
		)
		{
		// set default slip speed
		count = 10;

		// no direction perferred by the slope, hence its fairly flat, so slip in the
		// direction the frog is currently slipping, else the direction he's facing.
		if (frog->fr_velocity.vx != 0)
			{
			if (frog->fr_velocity.vx < 0)
				{
				dx = -1;
				dz =  0;
				}
			else
				{
				dx =  1;
				dz =  0;
				}
			}
		else 
		if (frog->fr_velocity.vz != 0)
			{
			if (frog->fr_velocity.vz < 0)
				{
				dx =  0;
				dz = -1;
				}
			else
				{
				dx =  0;
				dz =  1;
				}
			}
		else
			{
			switch (u)
				{
				case FROG_DIRECTION_N:
					dx =  0;
					dz =  1;
					break;
				case FROG_DIRECTION_E:
					dx =  1;
					dz =  0;
					break;
				case FROG_DIRECTION_S:
					dx =  0;
					dz = -1;
					break;
				case FROG_DIRECTION_W:
					dx = -1;
					dz =  0;
					break;
				default:
					dx = 0;
					dz = 0;
					break;
				}
			}
		}
	else
		{
		switch (u)
			{
			case FROG_DIRECTION_N:
				// Is the direction of the slope away
				if (shift_normal.vz != 0)
					{
					if (normal.vz >= 0)	
						{
						// Slide in current direction
						count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
						}
					else
						{
						// turn around and slide
						dz = -1;
						count = FrogSlopeSpeeds2[MAX((normal.vy >> 9), 0)];
						}
					}
				else
					{
					count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
					}
				break;
			case FROG_DIRECTION_E:
				// Is the direction of the slope away
				if (shift_normal.vx != 0)
					{
					if (normal.vx >= 0)
						{
						// Slide in current direction
						count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
						}
					else
						{
						// turn around and slide
						dx = -1;
						count = FrogSlopeSpeeds2[MAX((normal.vy >> 9), 0)];
						}
					}
				else
					{
					count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
					}
				break;
			case FROG_DIRECTION_S:
				// Is the direction of the slope away
				if (shift_normal.vz != 0)
					{
					if (normal.vz <= 0)
						{
						// Slide in current direction
						count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
						}
					else
						{
						// turn around and slide
						dz = 1;
						count = FrogSlopeSpeeds2[MAX((normal.vy >> 9), 0)];
						}
					}
				else
					{
					count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
					}
				break;
			case FROG_DIRECTION_W:
				// Is the direction of the slope away
				if (shift_normal.vx != 0)
					{
					if (normal.vx <= 0)
						{
						// Slide in current direction
						count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
						}
					else
						{
						// turn around and slide
						dx = 1;
						count = FrogSlopeSpeeds2[MAX((normal.vy >> 9), 0)];
						}
					}
				else
					{
					count = FrogSlopeSpeeds1[MAX((normal.vy >> 9), 0)];
					}
				break;
			default:
				count = 10;
				break;
			}
		}

	// work out target grid
	grid_x		= frog->fr_grid_x + dx;
	grid_z		= frog->fr_grid_z + dz;
	grid_stack 	= GetGridStack(grid_x, grid_z);

	// look through grid stacks to find a valid one to slide too!
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				y1 = GetGridSquareHeight(grid_square);
				
				if	(
					((y1 <= frog->fr_lwtrans->t[1]) && ((frog->fr_lwtrans->t[1] - y1) <= 0x1f0)) ||
					((y1 >= frog->fr_lwtrans->t[1]) && ((y1 - frog->fr_lwtrans->t[1]) <= FROG_JUMP_DOWN_DISTANCE))
					)
					{
					// Found usable grid square to slide too!
					frog->fr_flags 			&= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
					frog->fr_grid_x 		= grid_x;
					frog->fr_grid_z 		= grid_z;
					frog->fr_grid_square	= grid_square;
					frog->fr_direction		= u;
					frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
					frog->fr_target_pos.vy	= GetGridSquareHeight(grid_square);
					frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
					
					// The count for this slide is based on the steepness of the slope
					frog->fr_count			= count;

					// work out velocity, this is currently rather temporary...
					frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
					frog->fr_velocity.vy 	= ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
					frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

					FrogRequestAnimation(frog, FROG_ANIMATION_SLIP, 0, 0);
					if (Game_map_theme == THEME_SWP)
						FrogPlayLoopingSound(frog, SFX_SWP_SLIPPING);
					
					// Request particle effect for slipping
					if (!frog->fr_particle_api_item)
						frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_SLIDE, NULL);

					// return now, and let the update routine do all the work
					return;
					}
				}
			grid_square++;
			}
		}

	frog->fr_flags 	&= ~FROG_LANDED_ON_LAND_CLEAR_MASK;

	// not able to slip, brake out of this user-mode and return
	frog->fr_count			= 0;
	frog->fr_mode			= FROG_MODE_STATIONARY;
	frog->fr_target_pos.vx	= frog->fr_pos.vx >> 16;
	frog->fr_target_pos.vy	= frog->fr_pos.vy >> 16;
	frog->fr_target_pos.vz	= frog->fr_pos.vz >> 16;
	MR_CLEAR_VEC(&frog->fr_velocity);
}

/******************************************************************************
*%%%% FroguserSlippingLandGridControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandGridControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingLandGridControl(FROG* frog, MR_ULONG mode)
{
	FrogModeControlStationary(frog, mode);
}

/******************************************************************************
*%%%% FroguserSlippingLandGridMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandGridMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserSlippingLandGridMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_VEC		normal, local_x, local_z;
	MR_VEC*		direction;
	MR_ULONG	flags;

	flags = NULL;

	// check if the frog has reached its destination. If so, snap to it,
	// and pass back flags of the grid square just landed in, to react
	// accordingly with it
	if (!frog->fr_count)
		{	
		// set position to the target position (effectively lock it!)
		frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
		frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
		frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

		frog->fr_y		= frog->fr_pos.vy >> 16;
		frog->fr_old_y	= frog->fr_y;

		frog->fr_mode = FROG_MODE_STATIONARY;
		// Kill Slipping SFX.
		FrogKillLoopingSound(frog);
	
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);

		*grid_flags = frog->fr_grid_square->gs_flags;
		flags			|= FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS;
		flags 			|= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
		flags 			|= FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS;
		}
	else
		{
		// slip towards target point, realigning the frog	
		MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);

		// request that code use fr_pos to update the frog position
		flags =	FROG_MOVEMENT_CALLBACK_UPDATE_POS;

		frog->fr_count--;
		}

	// Do alignment, to make frog look correct as it slides across
	// the landscape!
	GetGridSquareAverageNormal(frog->fr_grid_square, &normal);		// normal will be frog's local Y (-ve)
	direction = &Frog_fixed_vectors[frog->fr_direction];

	MROuterProduct12(direction, &normal, &local_x);					// local_x will be frog's local X (+ve)
	MRNormaliseVEC(&local_x, &local_x);
	MROuterProduct12(&normal, &local_x, &local_z);					// local_z will be frog's local Z (+ve)

	frog->fr_lwtrans->m[0][0] = local_x.vx;
	frog->fr_lwtrans->m[1][0] = local_x.vy;
	frog->fr_lwtrans->m[2][0] = local_x.vz;
	frog->fr_lwtrans->m[0][1] = -normal.vx;
	frog->fr_lwtrans->m[1][1] = -normal.vy;
	frog->fr_lwtrans->m[2][1] = -normal.vz;
	frog->fr_lwtrans->m[0][2] = local_z.vx;
	frog->fr_lwtrans->m[1][2] = local_z.vy;
	frog->fr_lwtrans->m[2][2] = local_z.vz;

	return flags;
}


/******************************************************************************
*%%%% FroguserSlippingEntitySetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingEntitySetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for slipping frog over an entity.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingEntitySetup(FROG* frog, MR_ULONG mode)
{
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_LONG			dx, dz;
	MR_LONG			grid_x, grid_z, s;
	MR_LONG			u;
	FORM*			form;
	FORM_DATA*		form_data;
	MR_LONG			height;
	ENTITY*			entity;
	MR_ULONG		flags;
	CAMERA*			camera;


	// This will slip the frog in the direction its facing, until it runs out of slippy
	// grids to slide along...
 	camera = &Cameras[frog->fr_frog_id];

#ifdef WIN95
	if (MNIsNetGameRunning())
		camera = &Cameras[0];
#endif

	if (frog->fr_flags & FROG_ON_ENTITY)
		{
		entity				= frog->fr_entity;
		form 				= ENTITY_GET_FORM(entity);
		u 					= (frog->fr_entity_angle + frog->fr_direction) & 3;

		frog->fr_direction 	= u;
		switch(u)
			{
			case FROG_DIRECTION_N:
				dx =  0;
				dz =  1;
				break;
			case FROG_DIRECTION_E:
				dx =  1;
				dz =  0;
				break;
			case FROG_DIRECTION_S:
				dx =  0;
				dz = -1;
				break;
			case FROG_DIRECTION_W:
				dx = -1;
				dz =  0;
				break;
			default:
				dx = 0;
				dz = 0;
				break;
			}

		// Even if these go outside the form boundary, they will be used to calculate the jump target in entity's frame
		grid_x		= frog->fr_entity_grid_x + dx;
		grid_z		= frog->fr_entity_grid_z + dz;

		// Even if these go outside the form boundary, they will be used to calculate the jump target in entity's frame
		frog->fr_entity_grid_x = grid_x;
		frog->fr_entity_grid_z = grid_z;

		if 	(
			(grid_x >= 0) &&
			(grid_x < form->fo_xnum) &&
			(grid_z >= 0) &&
			(grid_z < form->fo_znum)
			)
			{
			goto user_test_form_grid_square;
			}
		else
			{
			goto user_no_grid_square;
			}

user_test_form_grid_square:;
		form_data 	= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
		flags		= form_data->fd_grid_squares[(frog->fr_entity_grid_z * form->fo_xnum) + frog->fr_entity_grid_x];
		height		= form_data->fd_height;
		if (flags & GRID_SQUARE_USABLE)
			{
			// Jump from entity to useable grid square on same entity
			// Jump will be performed as offset in entity frame
			frog->fr_flags 			|= (FROG_JUMP_FROM_ENTITY | FROG_JUMP_TO_ENTITY);
			frog->fr_grid_x 		= grid_x;
			frog->fr_grid_z 		= grid_z;
			frog->fr_grid_square	= NULL;
			frog->fr_direction		= u;
			frog->fr_target_pos.vx 	= (frog->fr_entity_grid_x << 8) + form->fo_xofs + 0x80;
			frog->fr_target_pos.vy 	= height;
			frog->fr_target_pos.vz 	= (frog->fr_entity_grid_z << 8) + form->fo_zofs + 0x80;
			frog->fr_count			= 10;		// primitive!

			frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_entity_ofs.vx) / frog->fr_count;
			frog->fr_velocity.vy 	= u;
			frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_entity_ofs.vz) / frog->fr_count;

			return;
			}
		else
			{
user_no_grid_square:;
			frog->fr_flags	&= ~FROG_JUMP_TO_ENTITY;
			frog->fr_flags	|= FROG_JUMP_FROM_ENTITY;
	
			// Are we jumping to a usable land square?
			u = (frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N]) & 3;
			switch(u)
				{
				case FROG_DIRECTION_N:
					dx =  0;
					dz =  1;
					break;
				case FROG_DIRECTION_E:
					dx =  1;
					dz =  0;
					break;
				case FROG_DIRECTION_S:
					dx =  0;
					dz = -1;
					break;
				case FROG_DIRECTION_W:
					dx = -1;
					dz =  0;
					break;
				}


			// work out target grid
			grid_x		= frog->fr_grid_x + dx;
			grid_z		= frog->fr_grid_z + dz;
			grid_stack 	= GetGridStack(grid_x, grid_z);

			// look through grid stacks to find a valid one to slide too!
			if (s = grid_stack->gs_numsquares)
			{
				grid_square = &Grid_squares[grid_stack->gs_index];
				while(s--)
					{
					if (grid_square->gs_flags & GRID_SQUARE_USABLE)
						{
						// Found usable grid square to slide too!
						frog->fr_flags 			&= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
						frog->fr_grid_x 		= grid_x;
						frog->fr_grid_z 		= grid_z;
						frog->fr_grid_square	= grid_square;
						frog->fr_direction		= u;
						frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
						frog->fr_target_pos.vy	= frog->fr_pos.vy >> 16;
						frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
						frog->fr_count			= 10;		// primitive!

						// work out velocity, this is currently rather temporary...
						frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
						frog->fr_velocity.vy 	= ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
						frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

						// return now, and let the update routine do all the work
						return;
						}
					grid_square++;
					}
				}
			}
		}

	// Create particle generator to mark out trail
//	pSlidePGen = MRCreatePgen(&gsBubbleGenerator, pFrame, NULL, pOffset);
//	if(pBubbleGen)
//	{
//		((MR_PGEN*)pBubbleGen->ob_extra)->pg_owner = pOwner;	// set the owning pond
//		MRAddObjectToViewport(pBubbleGen, pViewport, NULL);
//	}

	// not able to slip, brake out of this user-mode and return
	frog->fr_mode = FROG_MODE_STATIONARY;
}


/******************************************************************************
*%%%% FroguserSlippingEntityControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingEntityControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for slipping frog over the entity.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingEntityControl(FROG* frog, MR_ULONG mode)
{
	FrogModeControlStationary(frog, mode);
}


/******************************************************************************
*%%%% FroguserSlippingEntityMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingEntityMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for slipping frog over the entity.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserSlippingEntityMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_VEC		normal, local_x, local_z;
	MR_VEC*		direction;
	MR_ULONG	flags;
	ENTITY*		entity;
	FORM*		form;
	FORM_DATA*	form_data;
	MR_ULONG	height;

	// check if the frog has reached its destination. If so, snap to it,
	// and pass back flags of the grid square just landed in, to react
	// accordingly with it
	if (!frog->fr_count)
		{	
		// set position to the target position (effectively lock it!)
		frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
		frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
		frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

		frog->fr_mode	= FROG_MODE_STATIONARY;
		frog->fr_flags &= ~FROG_ON_ENTITY;

		flags =	FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS;
		}
	else
		{
		entity		= frog->fr_entity;
		form 		= ENTITY_GET_FORM(entity);
		form_data 	= ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
		height		= form_data->fd_height;

		// slip towards target point, realigning the frog	
		MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);
		frog->fr_pos.vy = height << 16;

		// request that code use fr_pos to update the frog position
		flags =	FROG_MOVEMENT_CALLBACK_UPDATE_POS;

		frog->fr_count--;
		}

	// Do alignment, to make frog look correct as it slides across an entity!
	normal.vx = -frog->fr_lwtrans->m[0][1];
	normal.vy = -frog->fr_lwtrans->m[1][1];
	normal.vz = -frog->fr_lwtrans->m[2][1];
	MRNormaliseVEC(&normal, &normal);
	direction = &Frog_fixed_vectors[frog->fr_direction];

	MROuterProduct12(direction, &normal, &local_x);					// local_x will be frog's local X (+ve)
	MRNormaliseVEC(&local_x, &local_x);
	MROuterProduct12(&normal, &local_x, &local_z);					// local_z will be frog's local Z (+ve)

	frog->fr_lwtrans->m[0][0] = local_x.vx;
	frog->fr_lwtrans->m[1][0] = local_x.vy;
	frog->fr_lwtrans->m[2][0] = local_x.vz;
	frog->fr_lwtrans->m[0][1] = -normal.vx;
	frog->fr_lwtrans->m[1][1] = -normal.vy;
	frog->fr_lwtrans->m[2][1] = -normal.vz;
	frog->fr_lwtrans->m[0][2] = local_z.vx;
	frog->fr_lwtrans->m[1][2] = local_z.vy;
	frog->fr_lwtrans->m[2][2] = local_z.vz;

	return flags;
}


/******************************************************************************
*%%%% FroguserCobwebSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCobwebSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for jumping off a cowweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserCobwebSetup(FROG* frog, MR_ULONG mode)
{
	// are we already in this mode, if so, don't bother resetting
	if (frog->fr_mode != FROGUSER_MODE_COBWEB)
		{
		// Let frog be stuck in place, start a count, and then wait until different
		// directions have been pressed so many times.
		frog->fr_user_count = 0;
		}
}

/******************************************************************************
*%%%% FroguserCobwebControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCobwebControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for frog on cobweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserCobwebControl(FROG* frog, MR_ULONG mode)
{
	CAMERA*		camera;
	MR_LONG		direction;

	if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_UP))
		{
		frog->fr_user_count += 4;
		}
	else 
	if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_RIGHT))
		{
		frog->fr_user_count += 4;
		}
	else
	if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_DOWN))
		{
		frog->fr_user_count += 4;
		}
	else
	if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_LEFT))
		{
		frog->fr_user_count += 4;
		}
	else
	if (frog->fr_user_count > 0)
		frog->fr_user_count--;

	// If count reaches predefined MAX, call control function to break out of this mode
	if (frog->fr_user_count > 50)
		{
		// Throw frogger in opp direction he is facing, for 2 grid squares
		camera 		= &Cameras[frog->fr_frog_id];

#ifdef WIN95
	if (MNIsNetGameRunning())
		camera		= &Cameras[0];
#endif

		direction 	= FROG_DIRECTION_N;
		switch (frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N])
			{
			case FROG_DIRECTION_N:
				direction = FROG_DIRECTION_S;
				break;
			case FROG_DIRECTION_S:
				//direction = FROG_DIRECTION_N;
				break;
			case FROG_DIRECTION_E:
				direction = FROG_DIRECTION_W;
				break;
			case FROG_DIRECTION_W:
				direction = FROG_DIRECTION_E;
				break;
			}
		JumpFrog(frog, direction, NULL, 2, 15);
		frog->fr_mode = 0;
		}
}

/******************************************************************************
*%%%% FroguserCobwebMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCobwebMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog on cobweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserCobwebMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	return 0L;
}

/******************************************************************************
*%%%% FroguserBouncyCobwebSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBouncyCobwebSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for bouncing off a cowweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*   NOTES       Rewritten to work differently. Now the frog nows in advance
*               that its jumping into a cobweb, and it jumps half its frames
*               as normal, and the other half in reverse, landing back where
*               it started.
*
*   CHANGED     PROGRAMMER      REASON
*	-------		----------		------
*	30.05.97	Martin Kift		Created
*   18.06.97    Martin Kift     Rewritten to new spec
*
*%%%**************************************************************************/

MR_VOID	FroguserBouncyCobwebSetup(FROG* frog, MR_ULONG mode)
{
    MR_VEC      target_pos;
    MR_LONG     y1, u;

    // Calculate where we want to go to, ignoring the cobweb, since
    // we'll hit it half way anyway
    target_pos.vx  = ((MR_ULONG)frog->fr_user_data1 << 8) + Grid_base_x + 0x80;
    target_pos.vz  = ((MR_ULONG)frog->fr_user_data2 << 8) + Grid_base_z + 0x80;

    // Set the actual target position as the current position, since we
    // will be returning
    frog->fr_target_pos.vx  = (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
    frog->fr_target_pos.vz  = (frog->fr_grid_z << 8) + Grid_base_z + 0x80;

    // go for 6 frames, 3 each way, maybe sticking half way
    frog->fr_count  = 6;

    // Note, we'll leave grid_x, grid_z, direction and fr_grid_square the
    // same as they are at the moment, and in fact all but fr_direction
    // we always be the same since we are rebounding

    // Destination height is got from land
    frog->fr_y  = GetGridSquareHeight(frog->fr_grid_square);
    y1          = frog->fr_y - frog->fr_old_y;
    u           = ((y1 << 16) / (frog->fr_count + 1)) - ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1);

    // Calculate jump velocty
    frog->fr_velocity.vx    = ((target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
    frog->fr_velocity.vy    = u;
    frog->fr_velocity.vz    = ((target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

	FrogRequestAnimation(frog, FROG_ANIMATION_HOP, 0, 0);
}

/******************************************************************************
*%%%% FroguserBouncyCobwebControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBouncyCobwebControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for frog on bouncy cobweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.05.97	Martin Kift		Created
*   18.06.97    Martin Kift     Rewritten to new spec
*
*%%%**************************************************************************/

MR_VOID	FroguserBouncyCobwebControl(FROG* frog, MR_ULONG mode)
{
    // No control allowed as you can see
}

/******************************************************************************
*%%%% FroguserBouncyCobwebMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBouncyCobwebMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog on bouncy_cobweb.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*   NOTES       Rewritten to work differently. Now the frog nows in advance
*               that its jumping into a cobweb, and it jumps half its frames
*               as normal, and the other half in reverse, landing back where
*               it started.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.05.97	Martin Kift		Created
*   18.06.97    Martin Kift     Rewritten to new spec
*
*%%%**************************************************************************/

MR_ULONG FroguserBouncyCobwebMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_ULONG		flags;

	flags 	= NULL;

    // Count down frames, when 3, reverse direction and velocity and finish
    // jump off to land back where started

    // If count is valid
    if (frog->fr_count)
        {
        if (!(--frog->fr_count))
            {
            // Count has reached zero, put frog in correct place
            frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
            frog->fr_pos.vz = frog->fr_target_pos.vz << 16;
	
            FrogLandedOnLand(frog);
            flags                   |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
            flags                   |= FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS;

            *grid_flags             = (MR_ULONG)frog->fr_grid_square->gs_flags;
            flags                   |= FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS;
            }
        else
        if (frog->fr_count == 3)
            {
            // Turn around
            frog->fr_velocity.vx = -frog->fr_velocity.vx;
            frog->fr_velocity.vz = -frog->fr_velocity.vz;

            // May want to reverse the direction here too.

            goto bounce_move_add_vel;
            }
		else
			{
bounce_move_add_vel:;
			// Add gravity
			frog->fr_velocity.vy += SYSTEM_GRAVITY;
            MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);
			flags |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
			}
		}

	flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
	return(flags);
}


/******************************************************************************
*%%%% FroguserSlippingLandNonGridSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandNonGridSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	NOTES		This mode attempts a lot of things. Basically, if the frog jumps
*				onto a non-grid slippy grid square, it slips and continues to 
*				slip until it comes out again. The frog is not grid based whilst
*				slipping.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingLandNonGridSetup(FROG* frog, MR_ULONG mode)
{
	MR_LONG		height;	
	
	// Look at the distance between the frog now, and the detected grid square.
	// If its too great, then just kill the frog on the spot
	height = GetGridSquareHeight(frog->fr_grid_square);

	// Reset velocity, which is based on old verus new frog position (but set y to zero)
	frog->fr_velocity.vx = frog->fr_pos.vx - frog->fr_old_pos.vx;
	frog->fr_velocity.vy = 0;
	frog->fr_velocity.vz = frog->fr_pos.vz - frog->fr_old_pos.vz;
	
	// no display on the frog shadow	
	frog->fr_shadow->ef_flags |= EFFECT_NO_DISPLAY;

	// Request particle effect for slipping
	if (!frog->fr_particle_api_item)
		frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_SLIDE, NULL);
}

/******************************************************************************
*%%%% FroguserSlippingLandNonGridControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandNonGridControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingLandNonGridControl(FROG* frog, MR_ULONG mode)
{
	MR_SVEC		speed_svec;
	MR_VEC		speed_vec;
	MR_ULONG	key, u;
	CAMERA*		camera;
	ENTITY*		entity;
	MR_VEC		normal;

	camera	= &Cameras[frog->fr_frog_id];

#ifdef WIN95
	if (MNIsNetGameRunning())
		camera = &Cameras[0];
#endif

	key	= FROG_DIRECTION_NO_INPUT;

	if (MR_CHECK_PAD_HELD(frog->fr_input_id, FR_UP))
		key = FROG_DIRECTION_N;
	else
	if (MR_CHECK_PAD_HELD(frog->fr_input_id, FR_RIGHT))
		key = FROG_DIRECTION_E;
	else
	if (MR_CHECK_PAD_HELD(frog->fr_input_id, FR_DOWN))
		key = FROG_DIRECTION_S;
	else
	if (MR_CHECK_PAD_HELD(frog->fr_input_id, FR_LEFT))
		key = FROG_DIRECTION_W;
	else 
	if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FR_TONGUE))
		{
		// Yes ... tongue
		if (frog->fr_tongue)
			{
			if (frog->fr_tongue->ef_flags == (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY))
				{
				// Reset no input timer
				frog->fr_no_input_timer = 0;

				// Tongue not already in action
				if (entity = FrogGetNearestTongueTarget(frog))
					{
					// Set off tongue to get target
					StartTongue(frog->fr_tongue, entity);
					DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE);
					}
				else
					{
					// Set off tongue to clean eyes
					StartTongue(frog->fr_tongue, NULL);
					DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE);
					}
				}
			}
		}
	
	if (key != FROG_DIRECTION_NO_INPUT)
		{
		u = (camera->ca_frog_controller_directions[key & 3] - frog->fr_direction) & 3;

		gte_SetRotMatrix(frog->fr_lwtrans);

		switch (u)
			{
			case FROG_DIRECTION_W:
				MR_SET_SVEC(&speed_svec, -15, 0, 0);
				MRApplyRotMatrix(&speed_svec, &speed_vec);

				frog->fr_velocity.vx += (speed_vec.vx<<14);
				frog->fr_velocity.vz += (speed_vec.vz<<14);

				if ( ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_single->ae_action_number != FROG_ANIMATION_SLIPLEFT )
					{
					FrogRequestAnimation(frog, FROG_ANIMATION_SLIPLEFT, 0, 0);
					if (Game_map_theme == THEME_SWP)
						FrogPlayLoopingSound(frog, SFX_SWP_SLIPPING);
					}
				break;
			case FROG_DIRECTION_E:
				MR_SET_SVEC(&speed_svec, 15, 0, 0);
				MRApplyRotMatrix(&speed_svec, &speed_vec);

				frog->fr_velocity.vx += (speed_vec.vx<<14);
				frog->fr_velocity.vz += (speed_vec.vz<<14);

				if ( ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_single->ae_action_number != FROG_ANIMATION_SLIPRIGHT )
					{
					FrogRequestAnimation(frog, FROG_ANIMATION_SLIPRIGHT, 0, 0);
					if (Game_map_theme == THEME_SWP)
						FrogPlayLoopingSound(frog, SFX_SWP_SLIPPING);
					}
				break;
			case FROG_DIRECTION_N:
				MR_SET_SVEC(&speed_svec, 0, 0, 10);
				MRApplyRotMatrix(&speed_svec, &speed_vec);

				GetGridSquareAverageNormal(frog->fr_grid_square, &normal);
				if	(
					((speed_vec.vx>0) && (normal.vx<0)) ||
					((speed_vec.vx<0) && (normal.vx>0))
					)
					{
					speed_vec.vx = 0;
					}
				if	(
					((speed_vec.vz>0) && (normal.vz<0)) ||
					((speed_vec.vz<0) && (normal.vz>0))
					)
					{
					speed_vec.vz = 0;
					}

				frog->fr_velocity.vx += (speed_vec.vx<<14);
				frog->fr_velocity.vz += (speed_vec.vz<<14);
				break;
			case FROG_DIRECTION_S:
				MR_SET_SVEC(&speed_svec, 0, 0, -15);
				MRApplyRotMatrix(&speed_svec, &speed_vec);

				// can't go backwards
				if (speed_vec.vx != 0)
					{
					if (frog->fr_velocity.vx > 0)
						{
						frog->fr_velocity.vx += (speed_vec.vx<<13);
						if (frog->fr_velocity.vx < 0)
							frog->fr_velocity.vx = 0;
						}
					else
						{
						frog->fr_velocity.vx += (speed_vec.vx<<13);
						if (frog->fr_velocity.vx > 0)
							frog->fr_velocity.vx = 0;
						}
					}
				if (speed_vec.vz != 0)
					{
					if (frog->fr_velocity.vz > 0)
						{
						frog->fr_velocity.vz += (speed_vec.vz<<13);
						if (frog->fr_velocity.vz < 0)
							frog->fr_velocity.vz = 0;
						}
					else
						{
						frog->fr_velocity.vz += (speed_vec.vz<<13);
						if (frog->fr_velocity.vz > 0)
							frog->fr_velocity.vz = 0;
						}
					}
				break;
			}
		}
}

/******************************************************************************
*%%%% FroguserSlippingLandNonGridMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingLandNonGridMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

#define FROG_USER_SLIP_MAX_SLIPDEATH_HEIGHT		(196)
#define FROG_USER_SLIP_MAX_HEIGHT_ALLOWED		(512)

MR_ULONG FroguserSlippingLandNonGridMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_VEC			normal;
	MR_LONG			s;
	MR_ULONG		flags;
	MR_VEC*			direction;
	MR_VEC			local_x, local_z, vec;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	GRID_INFO		grid_info;
	MR_LONG			x, z, height;

	flags = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS);

	// Check for death off map
	if 	(
		(frog->fr_grid_x < 0) ||
		(frog->fr_grid_x >= Grid_xnum) ||
		(frog->fr_grid_z < 0) ||
		(frog->fr_grid_z >= Grid_znum)
		)
		{
		FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
		return flags;
		}

	// Get current gridx, z, and grid stack
	x 			= GET_GRID_X_FROM_WORLD_X(frog->fr_lwtrans->t[0]);
	z 			= GET_GRID_Z_FROM_WORLD_Z(frog->fr_lwtrans->t[2]);
	grid_stack 	= Grid_stacks + (z * Grid_xnum) + x;

	// Check for no polys (probably end of map or something, just fall)
	if (grid_stack->gs_numsquares == 0)
		{
		// freefall, if not already
		if (!(frog->fr_flags & FROG_FREEFALL))
			{
			frog->fr_flags 			|= (FROG_FREEFALL | FROG_FREEFALL_NO_ANIMATION);
			frog->fr_count  		= 0x7ffffff;
			frog->fr_grid_square	= NULL;
			}
		
		// kill particle effect, if in operation...
		FROG_KILL_PARTICLE_EFFECT(frog);

		// enter jumping mode so freefall can happen
		frog->fr_mode	= FROG_MODE_JUMPING;
		return flags;
		}

	// Look at angle of current slope, if its greater/less than a certain range then
	// enter slippy/slidey mode
	GetGridSquareAverageNormal(frog->fr_grid_square, &normal);		
	GetGridInfoFromWorldXZ(frog->fr_lwtrans->t[0],frog->fr_lwtrans->t[2], &grid_info);
	
	// Get resultant vector down the slope
	MROuterProduct12(&grid_info.gi_xslope, &grid_info.gi_zslope, &vec);

	if 	(frog->fr_velocity.vx > 0)
		{
		if (grid_info.gi_xslope.vy < -FROGUSER_SLIP_MAX_SLOPE)
			frog->fr_velocity.vx = (frog->fr_velocity.vx * 2) / 3;
		}
	else
	if (frog->fr_velocity.vx < 0)
		{
		if (grid_info.gi_xslope.vy > FROGUSER_SLIP_MAX_SLOPE)
			frog->fr_velocity.vx = (frog->fr_velocity.vx * 2) / 3;
		}
	
	if (frog->fr_velocity.vz > 0)
		{
		if (grid_info.gi_zslope.vy < -FROGUSER_SLIP_MAX_SLOPE)
			frog->fr_velocity.vz = (frog->fr_velocity.vz * 2) / 3;
		}
	else
	if (frog->fr_velocity.vz < 0)
		{
		if (grid_info.gi_zslope.vy > FROGUSER_SLIP_MAX_SLOPE)
			frog->fr_velocity.vz = (frog->fr_velocity.vz * 2) / 3;
		}

	// update velocity of the frog
	frog->fr_velocity.vx = MIN(frog->fr_velocity.vx + (vec.vx << 3), (64<<16));
	frog->fr_velocity.vz = MIN(frog->fr_velocity.vz + (vec.vz << 3), (64<<16));
	frog->fr_velocity.vy += (SYSTEM_GRAVITY>>1);		

	// Setup the frog matrix to stand properly on the grid
	normal.vx = -frog->fr_lwtrans->m[0][1];
	normal.vy = -frog->fr_lwtrans->m[1][1];
	normal.vz = -frog->fr_lwtrans->m[2][1];
	MRNormaliseVEC(&normal, &normal);
	direction = &Frog_fixed_vectors[frog->fr_direction];

	MROuterProduct12(direction, &normal, &local_x);					// local_x will be frog's local X (+ve)
	MRNormaliseVEC(&local_x, &local_x);
	MROuterProduct12(&normal, &local_x, &local_z);					// local_z will be frog's local Z (+ve)

	frog->fr_lwtrans->m[0][0] = local_x.vx;
	frog->fr_lwtrans->m[1][0] = local_x.vy;
	frog->fr_lwtrans->m[2][0] = local_x.vz;
	frog->fr_lwtrans->m[0][1] = -normal.vx;
	frog->fr_lwtrans->m[1][1] = -normal.vy;
	frog->fr_lwtrans->m[2][1] = -normal.vz;
	frog->fr_lwtrans->m[0][2] = local_z.vx;
	frog->fr_lwtrans->m[1][2] = local_z.vy;
	frog->fr_lwtrans->m[2][2] = local_z.vz;

	// point frog in right direction
	if (abs(frog->fr_velocity.vx) > abs(frog->fr_velocity.vz))
		{
		if (frog->fr_velocity.vx > 0)
			{
			if (frog->fr_direction != FROG_DIRECTION_E)
				{
				frog->fr_direction = FROG_DIRECTION_E;
				flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
				}
			}
		else
			{
			if (frog->fr_direction != FROG_DIRECTION_W)
				{
				frog->fr_direction = FROG_DIRECTION_W;
				flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
				}
			}
		}
	else
		{
		if (frog->fr_velocity.vz > 0)
			{
			if (frog->fr_direction != FROG_DIRECTION_N)
				{
				frog->fr_direction = FROG_DIRECTION_N;
				flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
				}
			}
		else
			{
			if (frog->fr_direction != FROG_DIRECTION_S)
				{
				frog->fr_direction = FROG_DIRECTION_S;
				flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
				}
			}
		}

	// slip towards target point, realigning the frog	
	MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);

	// set grid Y to frog Y
	if (frog->fr_pos.vy > (grid_info.gi_y << 16))
		{
		frog->fr_pos.vy = grid_info.gi_y << 16;
		frog->fr_velocity.vy = 0;
		}

	// look through grid stacks to find a valid one to slide too, if none are found, we
	// need to exit slippy code
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				height = GetGridSquareHeight(grid_square);

				// if deadly AND slippy, we are moving towards a jump... only allow if difference
				// in height is less than a small tolerance...
				if (grid_square->gs_flags & GRID_SQUARE_DEADLY)
					{
					if (grid_square->gs_flags & GRID_SQUARE_FREEFORM_SLIPPY)
						{
						if ((frog->fr_lwtrans->t[1] - height) > FROG_USER_SLIP_MAX_SLIPDEATH_HEIGHT)
							{
							// put back old pos...
							MR_COPY_VEC(&frog->fr_pos, &frog->fr_old_pos);
							FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
							return flags;
							}
						}
					else
					if (abs(frog->fr_lwtrans->t[1] - height) < 128)
						{
						MR_COPY_VEC(&frog->fr_pos, &frog->fr_old_pos);
						FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
						return flags;
						}
					}

				// if deadly, die of course
				if	(grid_square->gs_flags & GRID_SQUARE_CLIFF)
					{
					// kill particle effect, if in operation...
					FROG_KILL_PARTICLE_EFFECT(frog);

					// Go into roll frog user mode
					SetFrogUserMode(frog, FROGUSER_MODE_CLIFF_ROLL);
					return flags;
					}

				// Check that the height of the next grid square is not too high, else we should not
				// be slipping to it
				if ((frog->fr_lwtrans->t[1] - height) < FROG_USER_SLIP_MAX_HEIGHT_ALLOWED)
					{
					// update height and grid square
					frog->fr_lwtrans->t[1]	= height;
					frog->fr_grid_square	= grid_square;
					frog->fr_grid_x			= x;
					frog->fr_grid_z			= z;

					// If this grid is NOT slippy, then we need to break out of the slippy code nicely
					if (!(grid_square->gs_flags & GRID_SQUARE_FREEFORM_SLIPPY))
						{
						// end it now!
						frog->fr_y			= frog->fr_pos.vy >> 16;
						frog->fr_old_y		= frog->fr_y;

						// turn shadow back on
						frog->fr_shadow->ef_flags &= ~EFFECT_NO_DISPLAY;

						// kill particle effect
						FROG_KILL_PARTICLE_EFFECT(frog);

						frog->fr_mode = FROG_MODE_STATIONARY;
						}

					// return now
					return flags;
					}
				else
					{
					if (grid_square->gs_flags & GRID_SQUARE_FREEFORM_SLIPPY)
						{
						FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
						return flags;
						}
					}
				}
			grid_square++;
			}
		}

	// If we have got here, then we failed to find a valid square to slip to, either
	// a slippy square within useable distance, or a useable square in general. So
	// we need to exit now, maybe with a faling death reaction or something...

	frog->fr_y		= frog->fr_pos.vy >> 16;
	frog->fr_old_y	= frog->fr_y;

	// freefall, if not already
	if (!(frog->fr_flags & FROG_FREEFALL))
		{
		frog->fr_flags 			|= (FROG_FREEFALL | FROG_FREEFALL_NO_ANIMATION);
		frog->fr_count  		= 0x7ffffff;
		}

	// kill particle effect, if in operation...
	FROG_KILL_PARTICLE_EFFECT(frog);

	// enter jumping mode so freefall can happen
	frog->fr_mode = FROG_MODE_STATIONARY;

	// return flags
	return flags;
}


/******************************************************************************
*%%%% FroguserMoveFroggerToTargetAndBackMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserMoveFroggerToTargetAndBackMovement(
*									FROG*		frog, 
*									MR_ULONG	mode)
*									MR_ULONG*	dummy)
*
*	FUNCTION	Used when Frogger eats a Fat Fire Fly. It moves him to the Target
*				position and then back to the source.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Gary Richards	Created
*	10.07.97	Gary Richards	Modified to move Camera, not Frogger.
*	01.09.97	Gary Richards	Finally Kev saw the *light* and remove this entity.
*
*%%%**************************************************************************/

MR_ULONG FroguserMoveFroggerToTargetAndBackMovement(FROG* frog, MR_ULONG mode, MR_ULONG* dummy)
{
#if	0
	// Find out what we are currently doing.
	// -----------------------------------------------------------------------------------------
	// Are we moving towards target.
	if (frog->fr_user_flags & (FROGUSER_MOVING_TOWARDS_SOURCE | FROGUSER_MOVING_TOWARDS_TARGET) ) 
		{
		// Find out where the Target IS.
		if (frog->fr_user_current.vx < frog->fr_user_target.vx )
			{
			// Find distance between. (Infront)
			if ( (frog->fr_user_target.vx - frog->fr_user_current.vx) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vx += frog->fr_user_speed;
			else
				frog->fr_user_current.vx = frog->fr_user_target.vx;
			}
		else
			{
			// Find distance between. (Behind)
			if ( (frog->fr_user_current.vx - frog->fr_user_target.vx) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vx -= frog->fr_user_speed;
			else
				frog->fr_user_current.vx = frog->fr_user_target.vx;
			} 

		// Find out where the Target IS.
		if (frog->fr_user_current.vy < frog->fr_user_target.vy )
			{
			// Find distance between. (Infront)
			if ( (frog->fr_user_target.vy - frog->fr_user_current.vy) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vy += frog->fr_user_speed;
			else
				frog->fr_user_current.vy = frog->fr_user_target.vy;
			}
		else
			{
			// Find distance between. (Behind)
			if ( (frog->fr_user_current.vy - frog->fr_user_target.vy) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vy -= frog->fr_user_speed;
			else
				frog->fr_user_current.vy = frog->fr_user_target.vy;
			}

		// Find out where the Target IS.
		if (frog->fr_user_current.vz < frog->fr_user_target.vz )
			{
			// Find distance between. (Infront)
			if ( (frog->fr_user_target.vz - frog->fr_user_current.vz) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vz += frog->fr_user_speed;
			else
				frog->fr_user_current.vz = frog->fr_user_target.vz;
			}
		else
			{
			// Find distance between. (Behind)
			if ( (frog->fr_user_current.vz - frog->fr_user_target.vz) > FROGUSER_MOVING_MAX_SPEED )
				frog->fr_user_current.vz -= frog->fr_user_speed;
			else
				frog->fr_user_current.vz = frog->fr_user_target.vz;
			}

		// Move Frogger.
		if (frog->fr_user_speed < FROGUSER_MOVING_MAX_SPEED)
			{
			frog->fr_user_speed += frog->fr_user_acceleration;
			frog->fr_user_acceleration += FROGUSER_MOVING_ACCELERATION;
			}

		// Check to see if we have reached our target. (In all three planes.
		if ( ( frog->fr_user_current.vx == frog->fr_user_target.vx ) &&
		     ( frog->fr_user_current.vy == frog->fr_user_target.vy ) &&
		     ( frog->fr_user_current.vz == frog->fr_user_target.vz ) )
			{
			// Check to see if we are moving to (real) Target OR back to source.
			if (frog->fr_user_flags & FROGUSER_MOVING_TOWARDS_TARGET)
				{
				// Moving to REAL target, so wait when we get there.
				frog->fr_user_flags &= ~FROGUSER_MOVING_TOWARDS_TARGET;
				frog->fr_user_flags |= FROGUSER_WAITING_AT_TARGET;
				frog->fr_user_timer = FROGUSER_MOVING_WAIT_TIME;
				// Turn on BRIGHT light once we've got to target.
				Frog_cave_light_special = TRUE;
				Map_light_min_r2 += 128 << 16;
				Map_light_max_r2 += 128 << 16;
				// Turn off light decay
				Cav_light_switch = FALSE;
				}
			else
				{
				// We must be moving back, so give control back to the user.
				frog->fr_user_flags &= ~FROGUSER_MOVING_TOWARDS_SOURCE;
				// Give control back to the player.
				frog->fr_mode = FROG_MODE_STATIONARY;
				Frog_cave_light_special = FALSE;
				// Set the camera offset to point BACK at frogger.
				Cameras[frog->fr_frog_id].ca_offset_origin = (MR_VEC*)&frog->fr_lwtrans->t;
				// Reduce the light just given to half.
				Map_light_min_r2 -= 128 << 16;
				Map_light_max_r2 -= 128 << 16;
				// Turn on light decay
				Cav_light_switch = FALSE;
				}
			}
		}	// Out of the FROGUSER_MOVING_TOWARDS_TARGET (if)

	//--------------------------------------------------------------------------------------------
	// Are we waiting at target??
	if (frog->fr_user_flags & FROGUSER_WAITING_AT_TARGET)
		{
		if ( frog->fr_user_timer > 0 )
		{
			frog->fr_user_timer--;
		}
		else
			{
			// Wait is OVER.
			frog->fr_user_flags &= ~FROGUSER_WAITING_AT_TARGET;
			frog->fr_user_flags |= FROGUSER_MOVING_TOWARDS_SOURCE;
			frog->fr_user_speed = 0;
			frog->fr_user_acceleration = 0 ;
			// Copy the source to the target, so we can use the same code to move back.
			//	Have to do this by hand, as one is a MR_VEC and we have a MR_SVEC.
			frog->fr_user_target.vx = frog->fr_user_source.vx;
			frog->fr_user_target.vy = frog->fr_user_source.vy;
			frog->fr_user_target.vz = frog->fr_user_source.vz;
			}
		}
	//--------------------------------------------------------------------------------------------
#endif
	return NULL;
}

/******************************************************************************
*%%%% FroguserCheckpointCollectedSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCheckpointCollectedSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog collecting checkpoint
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserCheckpointCollectedSetup(	FROG*		frog,
											MR_ULONG	mode)
{
	CAMERA*			camera;
	LIVE_ENTITY*	checkpoint;
	MR_LONG			y1, u;

	// Carry frog up until reached predefined height (off top of screen). 
	camera = &Cameras[frog->fr_frog_id];
	camera->ca_flags |= CAMERA_IGNORE_FROG_Y;

	// Using the id of the checkpoint just hit, make it jump onto our backs?
	frog->fr_user_data1		= Checkpoint_data[Checkpoint_last_collected].cp_entity;
	frog->fr_user_flags		= 0;
	checkpoint				= ((ENTITY*)frog->fr_user_data1)->en_live_entity;

	frog->fr_user_timer		= 6;
	y1 						= (frog->fr_lwtrans->t[1]-256) - checkpoint->le_lwtrans->t[1];
	u  						= ((y1 << 16) / (frog->fr_user_timer + 1)) - ((SYSTEM_GRAVITY * (frog->fr_user_timer + 1)) >> 1);

	frog->fr_user_source.vx = (frog->fr_pos.vx - (checkpoint->le_lwtrans->t[0]<<16)) / frog->fr_user_timer;
	frog->fr_user_source.vy = u;
	frog->fr_user_source.vz = (frog->fr_pos.vz - (checkpoint->le_lwtrans->t[2]<<16)) / frog->fr_user_timer;
	
}

/******************************************************************************
*%%%% FroguserCheckpointCollectedMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCheckpointCollectedMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog collecting check point.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	NOTES		This function(s) uses fr_count as a result feedback value into
*				the rest of the code...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserCheckpointCollectedMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_ULONG		flags;
	LIVE_ENTITY*	checkpoint;

	flags		= 0;
	checkpoint	= ((ENTITY*)frog->fr_user_data1)->en_live_entity;

	// set fr_count to zero.. this is a feed back value from this function
	frog->fr_user_count = 0;

	switch (frog->fr_user_flags)
		{
		case 0:	// i'll put defines in SOON
			if (frog->fr_user_timer--)
				{
				frog->fr_user_source.vy += SYSTEM_GRAVITY;

				if (checkpoint)
					{
					checkpoint->le_lwtrans->t[0] += (frog->fr_user_source.vx >> 16);
					checkpoint->le_lwtrans->t[1] += (frog->fr_user_source.vy >> 16);
					checkpoint->le_lwtrans->t[2] += (frog->fr_user_source.vz >> 16);
					}
				}
			else
				frog->fr_user_flags = 1;
			break;
		case 1:
			// make checkpoint croak or something
			frog->fr_user_flags = 2;
			frog->fr_user_timer = 30;
			break;
		case 2:
			// wait for pause period
			if (!(frog->fr_user_timer--))
				{
				// request some animation
				FrogRequestAnimation(frog, FROG_ANIMATION_BACKFLIP, 0, 0);
				frog->fr_user_flags = 3;
				}
			break;

		case 3:
			// Wait for Frog to reach point above camera ( used to wait for define, FROG_USER_CHECKPOINT_RAISE_HEIGHT )
			if (frog->fr_lwtrans->t[1] > (Cameras[0].ca_matrix->t[1]-100))
				{
				frog->fr_lwtrans->t[1]				+= FROG_USER_CHECKPOINT_RAISE_SPEED;
				if (checkpoint)
					checkpoint->le_lwtrans->t[1]	+= FROG_USER_CHECKPOINT_RAISE_SPEED;
				}
			else
				{
				frog->fr_user_flags = 4;
				frog->fr_user_timer	= 10;
				}
			break;

		case 4:
			// wait for pause period
			if (!(frog->fr_user_timer--))
				frog->fr_user_flags = 5;
			break;

		case 5:
			frog->fr_user_count = 1;
			break;
		}
	return (flags);
}


/******************************************************************************
*%%%% FroguserLevelStartBounceSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FrogUserLevelStartBounceSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog on start up
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID FroguserLevelStartBounceSetup(FROG* frog, MR_ULONG mode)
{
	MR_CLEAR_VEC(&frog->fr_velocity);
}

/******************************************************************************
*%%%% FroguserLevelStartBounceMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FrogUserLevelStartBounceMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for frog on start up
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserLevelStartBounceMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_ULONG	flags;


	flags = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);

	if (frog->fr_target_y < (frog->fr_lwtrans->t[1]<<16))
		{
		frog->fr_velocity.vy = -(2*frog->fr_velocity.vy)/3;
		frog->fr_flags |= FROG_JUST_BOUNCED;

		// if velocity is small, come to rest
		if (frog->fr_velocity.vy > -(16<<16))
			{
			frog->fr_velocity.vy = 0;
			SetFrogUserMode(frog, FROGUSER_MODE_LEVEL_START_COME_TO_REST);
			return flags;
			}
		}

	// Add gravity
	frog->fr_velocity.vy += SYSTEM_GRAVITY;

	// Update position
	MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);

	return flags;
}

/******************************************************************************
*%%%% FroguserLevelStartComeToRestSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FrogUserLevelStartComeToRestSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog on start up
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID FroguserLevelStartComeToRestSetup(FROG* frog, MR_ULONG mode)
{
	MR_CLEAR_VEC(&frog->fr_velocity);
}

/******************************************************************************
*%%%% FroguserLevelStartComeToRestMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG flags =	FroguserLevelStartComeToRestMovement(
*									FROG*		frog,
*									MR_ULONG	mode,
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Frog movement callback
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	frog->fr_mode
*				grid_flags	-	ptr to where to store grid flags to react with (if any)
*
*	RESULT		flags		-	what to do when we return from this function
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG	FroguserLevelStartComeToRestMovement(	
									FROG*		frog,
									MR_ULONG	mode,
									MR_ULONG*	grid_flags)
{
	MR_ULONG	flags;


	flags = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);

	// Have we hit the ground yet? If so, reverse velocty (with less magnitude)
	// so we bounce...
	if (frog->fr_target_y <= (frog->fr_lwtrans->t[1]<<16))
		{
		frog->fr_pos.vy	= frog->fr_target_y;
		MR_CLEAR_VEC(&frog->fr_velocity);
		}
	else
		{
		frog->fr_velocity.vy += SYSTEM_GRAVITY;

		// Update position
		MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);
		}

	return flags;
}

/******************************************************************************
*%%%% FroguserSlippingSimpleLandGridSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserSlippingSimpleLandGridSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for slipping frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	NOTES		This mode is a simple version of the other landscape grid slippy
*				code. It takes no account of slope, i.e. doesn't slip backwards
*				or sidewards.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserSlippingSimpleLandGridSetup(FROG* frog, MR_ULONG mode)
{
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_LONG			dx, dz;
	MR_LONG			u, y1, grid_x, grid_z, s;
	MR_LONG			count;

	u = frog->fr_direction;

	switch (u)
		{
		case FROG_DIRECTION_N:
			dx =  0;
			dz =  1;
			break;
		case FROG_DIRECTION_E:
			dx =  1;
			dz =  0;
			break;
		case FROG_DIRECTION_S:
			dx =  0;
			dz = -1;
			break;
		case FROG_DIRECTION_W:
			dx = -1;
			dz =  0;
			break;
		default:
			dx = 0;
			dz = 0;
			break;
		}
	count = 10;

	// work out target grid
	grid_x		= frog->fr_grid_x + dx;
	grid_z		= frog->fr_grid_z + dz;
	grid_stack 	= GetGridStack(grid_x, grid_z);

	// look through grid stacks to find a valid one to slide too!
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				y1 = GetGridSquareHeight(grid_square);
				
				if	(
					((y1 <= frog->fr_lwtrans->t[1]) && ((frog->fr_lwtrans->t[1] - y1) <= FROG_JUMPUP_LARGE_DY)) ||
					((y1 >= frog->fr_lwtrans->t[1]) && ((y1 - frog->fr_lwtrans->t[1]) <= FROG_JUMP_DOWN_DISTANCE))
					)
					{
					// Found usable grid square to slide too!
					frog->fr_flags 			&= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
					frog->fr_grid_x 		= grid_x;
					frog->fr_grid_z 		= grid_z;
					frog->fr_grid_square	= grid_square;
					frog->fr_direction		= u;
					frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
					frog->fr_target_pos.vy	= GetGridSquareHeight(grid_square);
					frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
					
					// The count for this slide is based on the steepness of the slope
					frog->fr_count			= count;

					// work out velocity, this is currently rather temporary...
					frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
					frog->fr_velocity.vy 	= ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
					frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

					FrogRequestAnimation(frog, FROG_ANIMATION_SLIP, 0, 0);
					if (Game_map_theme == THEME_SWP)
						FrogPlayLoopingSound(frog, SFX_SWP_SLIPPING);
	
					// return now, and let the update routine do all the work
					return;
					}
				}
			grid_square++;
			}
		}

	// not able to slip, brake out of this user-mode and return
	frog->fr_count			= 0;
	frog->fr_mode			= FROG_MODE_STATIONARY;
	frog->fr_target_pos.vx	= frog->fr_pos.vx >> 16;
	frog->fr_target_pos.vy	= frog->fr_pos.vy >> 16;
	frog->fr_target_pos.vz	= frog->fr_pos.vz >> 16;
}


/******************************************************************************
*%%%% FroguserBounceSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBounceSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for bouncing frog
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserBounceSetup(FROG* frog, MR_ULONG mode)
{
	CAMERA*	camera;

	// Throw frogger in direction he is facing
	camera = &Cameras[frog->fr_frog_id];
#ifdef WIN95
	if (MNIsNetGameRunning())
		camera = &Cameras[0];
#endif

	// Bounce frog in current direction, over predefined distance/ht for the time being
	JumpFrog(frog, frog->fr_direction - camera->ca_frog_controller_directions[FROG_DIRECTION_N], FROG_JUMP_FORCED, 2, 15);
}

/******************************************************************************
*%%%% FroguserBounceControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBounceControl(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Control callback for bouncing frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FroguserBounceControl(FROG* frog, MR_ULONG mode)
{
	// no control allowed
}

/******************************************************************************
*%%%% FroguserBounceMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserBounceMovement(
*									FROG*		frog, 
*									MR_ULONG	mode, 
*									MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for bouncing frog over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserBounceMovement(FROG* frog, MR_ULONG mode, MR_ULONG* grid_flags)
{
	MR_ULONG	flags;

	// check if the frog has reached its destination. If so, snap to it,
	// and pass back flags of the grid square just landed in, to react
	// accordingly with it
	if (!frog->fr_count)
		{	
		// set position to the target position (effectively lock it!)
		frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
		frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
		frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

		frog->fr_y		= frog->fr_pos.vy >> 16;
		frog->fr_old_y	= frog->fr_y;

		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);

		*grid_flags = frog->fr_grid_square->gs_flags;
		flags = (FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS | FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS);
		}
	else
		{
		// slip towards target point, realigning the frog	
		MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);

		// request that code use fr_pos to update the frog position
		flags =	FROG_MOVEMENT_CALLBACK_UPDATE_POS;

		frog->fr_count--;
		}

	return flags;
}

/******************************************************************************
*%%%% FroguserCliffRollSetup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG FroguserCliffRollSetup(
*									FROG*		frog, 
*									MR_ULONG	mode)
*
*	FUNCTION	Setup callback for frog rolling down cliff face.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*	
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Martin Kift		Created
*	18.08.97	Martin Kift		Updated to fix probs with repeated slipping.
*
*%%%**************************************************************************/

MR_VOID	FroguserCliffRollSetup(	FROG*		frog, 
								MR_ULONG	mode)
{
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_LONG			dx, dz;
	MR_LONG			y1, grid_x, grid_z, s;

	switch (frog->fr_old_direction)
		{
		case FROG_DIRECTION_N:
			dx =  0;
			dz =  1;
			break;
		case FROG_DIRECTION_S:
			dx =  0;
			dz = -1;
			break;
		case FROG_DIRECTION_E:
			dx =  1;
			dz =  0;
			break;
		case FROG_DIRECTION_W:
			dx = -1;
			dz =  0;
			break;
		default:
			dx =  0;
			dz =  0;
			break;
		}

	// work out target grid
	grid_x		= frog->fr_grid_x + dx;
	grid_z		= frog->fr_grid_z + dz;
	grid_stack 	= GetGridStack(grid_x, grid_z);

	// look through grid stacks to find a valid one to slide too!
	if (s = grid_stack->gs_numsquares)
		{
		grid_square = &Grid_squares[grid_stack->gs_index];
		while(s--)
			{
			if (grid_square->gs_flags & GRID_SQUARE_USABLE)
				{
				// The grid we are going too is useable, but if its not safe, or 
				// cliff, etc.. then we need to go into freefall.. this style suits
				// the sky maps amoungst others
				if	(grid_square->gs_flags == GRID_SQUARE_USABLE)
					{
					// go into freefall (well set grid to NULL, and let movement function do it)
					frog->fr_grid_square = NULL;
					return;
					}

				y1 = GetGridSquareHeight(grid_square);
				
				// Found usable grid square to slide too!
				frog->fr_flags 			&= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
				frog->fr_grid_x 		= grid_x;
				frog->fr_grid_z 		= grid_z;
				frog->fr_grid_square	= grid_square;
				frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
				frog->fr_target_pos.vy	= GetGridSquareHeight(grid_square);
				frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
				frog->fr_mode			= FROGUSER_MODE_CLIFF_ROLL;
				frog->fr_flags			&= ~FROG_MUST_DIE;

				// The count for this slide is based on the steepness of the slope
				frog->fr_count			= 20;

				// work out velocity, this is currently rather temporary...
				frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
				frog->fr_velocity.vy 	= ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
				frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

				FrogRequestAnimation(frog, FROG_ANIMATION_ROLL_REPEATING, 0, 0);

				// return now, and let the update routine do all the work
				return;
				}
			grid_square++;
			}
		}
	else
		{
		// Found no valid grids to jump too/roll too, go into freefall.. this style suits
		// the sky maps amoungst others

		// go into freefall (well set grid to NULL, and let movement function do it)
		frog->fr_grid_square = NULL;
		return;
		}

	// not able to slip, brake out of this user-mode and kill the frog
	FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
}


/******************************************************************************
*%%%% FroguserSlippingLandGridMovement
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FroguserCliffRollMovement(
*				FROG*		frog, 
*				MR_ULONG	mode, 
*				MR_ULONG*	grid_flags)
*
*	FUNCTION	Movement callback for rolling down cliff over the landscape.
*
*	INPUTS		frog		-	ptr to FROG
*				mode		-	mode of movement
*				grid_flags	-	grid flags
*
*	RESULTS		flags which tell controller function what to update (pos, etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ULONG FroguserCliffRollMovement(	FROG*		frog, 
									MR_ULONG	mode, 
									MR_ULONG*	grid_flags)
{
	MR_VEC			normal, local_x, local_z;
	MR_VEC*			direction;
	MR_ULONG		flags;
	GRID_STACK*		grid_stack;
	GRID_SQUARE*	grid_square;
	MR_LONG			y1, s;
	MR_LONG			dx, dz;
	GRID_INFO		grid_info;

	flags = NULL;

	// if frog grid square is NULL, go into free fall mode
	if (!frog->fr_grid_square)
		{
		FROG_FALL(frog);
		frog->fr_flags 	|= FROG_FREEFALL;
		FrogRequestAnimation(frog, FROG_ANIMATION_FALLING, 0, 0);
		return flags;
		}
	
	// check if the frog has reached its destination. If so, snap to it,
	// and pass back flags of the grid square just landed in, to react
	// accordingly with it
	if (!frog->fr_count)
		{	
		// set position to the target position (effectively lock it!)
		frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
		frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
		frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

		frog->fr_y		= frog->fr_pos.vy >> 16;
		frog->fr_old_y	= frog->fr_y;

		// Look at current grid square. If its a CLIFF one, then look at the slope
		// of the current grid square. If its downhill, then slip down, its its uphill
		// then die NOW! If its not a CLIFF one, then die anyway.


		// First, is this grid square NOT cliffy
		if (!(frog->fr_grid_square->gs_flags & GRID_SQUARE_CLIFF))
			{
			// Die
			FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
			return NULL;
			}

		// We are on a slippy square. Look at slope of this square to see where
		switch (frog->fr_old_direction)
			{
			case FROG_DIRECTION_N:
				dx =  0;
				dz =  1;
				break;
			case FROG_DIRECTION_S:
				dx =  0;
				dz = -1;
				break;
			case FROG_DIRECTION_E:
				dx =  1;
				dz =  0;
				break;
			case FROG_DIRECTION_W:
				dx = -1;
				dz =  0;
				break;
			default:
				dx =  0;
				dz =  0;
				break;
			}

		// Work out target grid
		frog->fr_grid_x		= frog->fr_grid_x + dx;
		frog->fr_grid_z 	= frog->fr_grid_z + dz;
		grid_stack 			= GetGridStack(frog->fr_grid_x, frog->fr_grid_z);

		// look through grid stacks to find a valid one to slide too!
		if (s = grid_stack->gs_numsquares)
			{
			grid_square = &Grid_squares[grid_stack->gs_index];
			while(s--)
				{
				if (grid_square->gs_flags & GRID_SQUARE_USABLE)
					{
					// Is this grid much higher than the existing one? If so we don't want to roll
					// to it, since we will end up rolling up hill... woo hoo misses.
					y1 = GetGridSquareHeight(grid_square);

					if ((frog->fr_lwtrans->t[1] - y1) > 0)
						{
						// Found usable grid square (thats downhill) to slide too!
						frog->fr_flags 			&= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
						frog->fr_grid_square	= grid_square;
						frog->fr_target_pos.vx	= (frog->fr_grid_x << 8) + Grid_base_x + 0x80;
						frog->fr_target_pos.vy	= GetGridSquareHeight(grid_square);
						frog->fr_target_pos.vz	= (frog->fr_grid_z << 8) + Grid_base_z + 0x80;
					
						// The count for this slide is based on the steepness of the slope
						frog->fr_count			= 20;

						// work out velocity, this is currently rather temporary...
						frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
						frog->fr_velocity.vy 	= ((frog->fr_target_pos.vy << 16) - frog->fr_pos.vy) / frog->fr_count;
						frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

						// return now
						return NULL;
						}
					grid_square++;
					}
				}
			}

		// didn't find any grids, or any cliff ones anyway, so die now
		FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
		return NULL;
		}

	// slip towards target point, realigning the frog	
	MR_ADD_VEC(&frog->fr_pos, &frog->fr_velocity);
	frog->fr_count--;

	// Do alignment, to make frog look correct as it slides across
	// the landscape!
	GetGridSquareAverageNormal(frog->fr_grid_square, &normal);		// normal will be frog's local Y (-ve)
	direction = &Frog_fixed_vectors[frog->fr_direction];

	MROuterProduct12(direction, &normal, &local_x);					// local_x will be frog's local X (+ve)
	MRNormaliseVEC(&local_x, &local_x);
	MROuterProduct12(&normal, &local_x, &local_z);					// local_z will be frog's local Z (+ve)

	frog->fr_lwtrans->m[0][0] = local_x.vx;
	frog->fr_lwtrans->m[1][0] = local_x.vy;
	frog->fr_lwtrans->m[2][0] = local_x.vz;
	frog->fr_lwtrans->m[0][1] = -normal.vx;
	frog->fr_lwtrans->m[1][1] = -normal.vy;
	frog->fr_lwtrans->m[2][1] = -normal.vz;
	frog->fr_lwtrans->m[0][2] = local_z.vx;
	frog->fr_lwtrans->m[1][2] = local_z.vy;
	frog->fr_lwtrans->m[2][2] = local_z.vz;

	// Set height to follow cliff face properly
	GetGridInfoFromWorldXZ(frog->fr_lwtrans->t[0], frog->fr_lwtrans->t[2], &grid_info);
	frog->fr_lwtrans->t[1] = grid_info.gi_y - 30;

	return FROG_MOVEMENT_CALLBACK_UPDATE_POS;
}
