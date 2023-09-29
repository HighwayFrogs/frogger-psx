/******************************************************************************
*%%%% froguser.h
*------------------------------------------------------------------------------
*
*	User frog control
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	13.05.97	Tim Closs		Created
*	20.05.97	Martin Kift		Added des_thermal & slippy functions
*	25.05.97	Martin Kift		Added 2 cobweb (cave) user modes
*	20.06.97	Gary Richards	Added MoveFrogToTargetAndBack.
*
*%%%**************************************************************************/

#ifndef	__FROGUSER_H
#define	__FROGUSER_H

#include "mr_all.h"
#include "frog.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum	{
		FROGUSER_MODE_THROW_1 = FROG_MODE_USER,
		FROGUSER_MODE_THERMAL,							// Frog gets picked up and throw by desert thermal entity
		FROGUSER_MODE_SLIPPING_LAND_GRID,				// Frog slips across landscape grids
		FROGUSER_MODE_SLIPPING_ENTITY,					// Frog slips across entity
		FROGUSER_MODE_COBWEB,							// Frog is stuck on a cobweb
		FROGUSER_MODE_BOUNCY_COBWEB,					// Frog is stuck on a bouncy cobweb
		FROGUSER_MODE_SLIPPING_LAND_NONGRID,			// Frog slips across landscape (freeform)
		FROGUSER_MODE_MOVE_FROGGER_TO_TARGET,			// Frog to Target and Back.
		FROGUSER_MODE_CHECKPOINT_COLLECTED,				// Frog has just collected a check point
		FROGUSER_MODE_LEVEL_START_BOUNCE,				// Frog bouncing on level start
		FROGUSER_MODE_LEVEL_START_COME_TO_REST,			// Frog coming to rest after bouncing
		FROGUSER_MODE_SIMPLE_SLIPPING_LAND_GRID,		// Frog slips across landscape grids (simple mode, not accounting for wierrd slopes)
		FROGUSER_MODE_BOUNCE,							// Frog bounces
		FROGUSER_MODE_CLIFF_ROLL,						// Frog rolls down cliff
		FROGUSER_MODE_MAX,
		};

#define	FROGUSER_CAV_BOUNCY_COBWEB_STICK_TIME	(20)	// Time to stick to cobweb before being thrown off

#define	FROGUSER_MOVING_TOWARDS_TARGET			(1<<0)	// Moving towards target position.
#define	FROGUSER_WAITING_AT_TARGET				(1<<1)
#define	FROGUSER_MOVING_TOWARDS_SOURCE			(1<<2)	// Back to were we started.

#define	FROGUSER_GRID_SLIP_MIN_SLOPE			(256)	// Min slope that affects the frog

#define	FROGUSER_MOVING_MAX_SPEED				(48)	// Speed to target
#define	FROGUSER_MOVING_ACCELERATION			(4)		// Acceleration to Max Speed.
#define	FROGUSER_MOVING_WAIT_TIME				(45)	// Wait for a second and a half.

#define FROG_USER_CHECKPOINT_RAISE_HEIGHT		(-4000)
#define FROG_USER_CHECKPOINT_RAISE_SPEED		(-100)

#define FROGUSER_SLIP_MAX_SLOPE					(3500)

enum	{
		FROGUSER_SLIP_N,
		FROGUSER_SLIP_S,
		FROGUSER_SLIP_E,
		FROGUSER_SLIP_W
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_VOID		(*Froguser_mode_setup_functions[])(FROG*, MR_ULONG);
extern	MR_VOID 	(*Froguser_mode_control_functions[])(FROG*, MR_ULONG);
extern	MR_ULONG 	(*Froguser_mode_movement_functions[])(FROG*, MR_ULONG, MR_ULONG*);


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		FroguserThrowSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserThrowMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserThermalSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserThermalMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserSlippingLandGridSetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserSlippingLandGridControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserSlippingLandGridMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserSlippingEntitySetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserSlippingEntityControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserSlippingEntityMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserCobwebSetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserCobwebControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserCobwebMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserBouncyCobwebSetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserBouncyCobwebControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserBouncyCobwebMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserSlippingLandNonGridSetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserSlippingLandNonGridControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserSlippingLandNonGridMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_ULONG 	FroguserMoveFroggerToTargetAndBackMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserCheckpointCollectedSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserCheckpointCollectedMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserLevelStartBounceSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserLevelStartBounceMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserLevelStartComeToRestSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserLevelStartComeToRestMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserSlippingSimpleLandGridSetup(FROG*, MR_ULONG);

extern	MR_VOID		FroguserBounceSetup(FROG*, MR_ULONG);
extern	MR_VOID		FroguserBounceControl(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserBounceMovement(FROG*, MR_ULONG, MR_ULONG*);

extern	MR_VOID		FroguserCliffRollSetup(FROG*, MR_ULONG);
extern	MR_ULONG	FroguserCliffRollMovement(FROG*, MR_ULONG, MR_ULONG*);

#endif		//__FROGUSER_H

