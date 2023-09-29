/******************************************************************************
*%%%% desert.h
*------------------------------------------------------------------------------
*
*	This is used to hold all the structures/defines etc for the desert entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	28.04.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef __desert_h
#define __desert_h

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

//
// Falling rock - dynamic entity
//
enum 
	{
	DES_C_ACTION_FALLING_ROCK_CHECKING,
	DES_C_ACTION_FALLING_ROCK_DELAY,
	DES_C_ACTION_FALLING_ROCK_START,
	DES_C_ACTION_FALLING_ROCK_TARGET1,
	DES_C_ACTION_FALLING_ROCK_TARGET2,
	DES_C_ACTION_FALLING_ROCK_TARGET3,
	DES_C_ACTION_FALLING_ROCK_EXPLODE,
	};


//
// Desert EarthQuake.
//

#define DES_C_MAX_ENT_UNPAUSED_BY_QUAKE		(10)

enum 
	{
	DES_C_ACTION_EARTH_QUAKE_STARTING,
	DES_C_ACTION_EARTH_QUAKE_WAITING,
	DES_C_ACTION_EARTH_QUAKE_SHAKING,
	DES_C_ACTION_EARTH_QUAKE_RAMPING_DOWN,
	DES_C_ACTION_EARTH_QUAKE_STOPPED,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef	struct __desert_fallingrock		DESERT_FALLINGROCK;
typedef struct __desert_rt_fallingrock	DESERT_RT_FALLINGROCK;
typedef	struct __desert_earthquake		DESERT_EARTHQUAKE;
typedef struct __desert_rt_earthquake	DESERT_RT_EARTHQUAKE;


//
// Desert Falling Rocks.
//

struct __desert_fallingrock
	{	
	MR_USHORT	fr_delay;			// Delay until rock starts moving.
	MR_SVEC		fr_target1;			// Position of target1.
	MR_USHORT	fr_time1;			// Time to reach target 1
	MR_SVEC		fr_target2;			// Position of target2.
	MR_USHORT	fr_time2;			// Time to reach target 2
	MR_SVEC		fr_target3;			// Position of target3.
	MR_USHORT	fr_time3;			// Time to reach target 3
	MR_UBYTE	fr_num_bounces;		// Number of bounces
	MR_UBYTE	fr_pad[3];			// Pad.

	MR_MAT		et_matrix;			// matrix of entity
	};	// DESERT_FALLINGROCK

struct __desert_rt_fallingrock
	{
	LIVE_ENTITY*	fr_earth_quake;		// Is this un-paused by an earthquake. HAS TOO BE FIRST.
	MR_VEC			fr_position;
	MR_VEC			fr_velocity;
	MR_USHORT		fr_curr_time;
	MR_BYTE			fr_state;
	MR_BYTE			fr_curr_bounces;
	POLY_FT4		fr_shadow_poly[2];
	};	// DESERT_RT_FALLINGROCK

//
// Desert EarthQuake.
//

struct __desert_earthquake
	{	
	MR_SHORT				eq_time_flag;
	MR_SHORT				eq_pad;
	MR_USHORT				eq_pause_list[DES_C_MAX_ENT_UNPAUSED_BY_QUAKE];
	};	// DESERT_EARTHQUAKE

struct __desert_rt_earthquake
	{
	MR_LONG		eq_voice_id;		// Voice ID
	MR_LONG		eq_sample_volume;	// Used to control the volume of the earthquake.
	MR_LONG		eq_sample_rate;		// Sample rate
	MR_LONG		eq_state;			// Current state (action)
	};	// FG_DES_EARTH_QUAKE;

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	ENTSTRDesCreateFallingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateFallingRock(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesKillFallingRock(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRDesCreateEarthQuake(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesUpdateEarthQuake(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRDesKillEarthQuake(LIVE_ENTITY*);


#endif //__desert