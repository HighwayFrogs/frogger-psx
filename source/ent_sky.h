/******************************************************************************
*%%%% ent_sky.h
*------------------------------------------------------------------------------
*
*	Sky header, definitions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	22.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_SKY_H
#define	__ENT_SKY_H

#include "mr_all.h"
#include "entity.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG		script_sky_bird1_1[];
extern	MR_LONG		script_sky_bird1_call_sfx[];
extern	MR_LONG		script_sky_bird2_1[];
extern	MR_LONG		script_sky_bird2_call_sfx[];
extern	MR_LONG		script_sky_bird3_1[];
extern	MR_LONG		script_sky_bird3_call_sfx[];
extern	MR_LONG		script_sky_bird4_1[];
extern	MR_LONG		script_sky_bird4_call_sfx[];
extern	MR_LONG		script_sky_helium_balloon_popping[];
extern	MR_LONG		script_sky_helium_balloon_rising[];
extern	MR_LONG		script_sky_helium_balloon_sinking[];
extern	MR_LONG		script_sky_helium_balloon_waiting[];
extern	MR_LONG		script_sky_rubber_balloon_popping[];
extern	MR_LONG		script_sky_rubber_balloon_rising[];
extern	MR_LONG		script_sky_rubber_balloon_sinking[];
extern	MR_LONG		script_sky_rubber_balloon_waiting[];
extern	MR_LONG		script_sky_helicopter[];
extern	MR_LONG		script_sky_homing_bird[];
extern	MR_LONG		script_sky_homing_bird_hit_frog[];
extern	MR_LONG		script_sky_jet1[];
extern	MR_LONG		script_sky_jet3[];
extern	MR_LONG		script_sky_biplane[];
extern	MR_LONG		script_sky_magical_popping_balloon[];
extern	MR_LONG		script_sky_magical_popping_balloon_pop[];

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID	ScriptCBSkyBird1Call(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBSkyBird2Call(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBSkyBird3Call(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBSkyBird4Call(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBSkyFrogHelicopter(LIVE_ENTITY*);
extern	MR_VOID	ScriptCBSkyHeliumBalloon(LIVE_ENTITY*);


#endif	//__ENT_SKY_H
