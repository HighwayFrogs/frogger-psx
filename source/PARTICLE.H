/******************************************************************************
*%%%% particle.h
*------------------------------------------------------------------------------
*
*	Particle effects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	10.09.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__PARTICLE_H
#define	__PARTICLE_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

#define	PARTICLE_DISPLAY_MAX_HALFWIDTH					0x60

// OT offsets (in actual OT range, 0..1023)
#define	PICKUP_OT_OFFSET								-0x10		// changed from -8 by Tim 26/08/97
#define	SHIELD_OT_OFFSET								-80
#define	PICKUP_EXPLOSION_OT_OFFSET						20
#define	HILITE_EXHAUST_OT_OFFSET						0x10
#define	FOR_SWARM_OT_OFFSET								-0x20

// Specific defines
#define	PICKUP_EXPLOSION_DURATION						30
#define	FROG_POP_EXPLOSION_DURATION						30

// Effects defines
#define FROG_EFFECT_SLIP_OT_OFFSET						-0x10
#define	FROG_EFFECT_PARTICLE_DISPLAY_MAX_HALFWIDTH		0x60

// Types of particle generators for frogs
enum	{
		FROG_PARTICLE_SLIDE,
		FROG_PARTICLE_WATER_BUBBLE,
		FROG_PARTICLE_ON_FIRE,
		FROG_PARTICLE_MAX,
		};

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

typedef	struct	__frog_particle		FROG_PARTICLE;

struct __frog_particle
	{
	MR_ULONG		fp_flags;
	MR_PGEN_INIT*	fp_pgen_single;
	MR_PGEN_INIT*	fp_pgen_multi;
	};

//-----------------------------------------------------------------------------
// Externs
//-----------------------------------------------------------------------------

// Particle generators
extern	MR_PGEN_INIT	PGIN_pickup;
extern	MR_PGEN_INIT	PGIN_player_shield;
extern	MR_PGEN_INIT	PGIN_pickup_explosion;
extern	MR_PGEN_INIT	PGIN_frog_pop_explosion;
extern	MR_PGEN_INIT	PGIN_hilite_exhaust;
extern	MR_PGEN_INIT	PGIN_frog_slip_effect;
extern	MR_PGEN_INIT	PGIN_stone_to_gold_frog;
extern	MR_PGEN_INIT	PGIN_hilite_dust;
extern	MR_PGEN_INIT	PGIN_hilite_fire;
extern	MR_PGEN_INIT	PGIN_for_swarm;
extern	MR_PGEN_INIT	PGIN_for_swarm_multiplayer;
extern	MR_PGEN_INIT	PGIN_gold_frog_glow;

// Particle structures
extern	FROG_PARTICLE	Frog_particle_effects[];

// Effect vertices
extern	MR_SVEC			Explosion_offsets_octagon[];
extern	MR_SVEC			Shield_offsets_octagon[];

// Misc
extern	MR_ULONG		Frog_pop_explosion_colours[];


//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

// General functions
extern	MR_VOID			Particle_ft4_prim_init(MR_PGEN_INST*);
extern	MR_VOID			Particle_2D_move(MR_OBJECT*);
extern	MR_VOID			Particle_no_geometry_move(MR_OBJECT*);

// Specific functions
extern	MR_VOID			Pickup_prim_init(MR_PGEN_INST*);
extern	MR_VOID			Pickup_move(MR_OBJECT*);
extern	MR_VOID			Pickup_disp(MR_PGEN_INST*, MR_VIEWPORT*);

extern	MR_VOID			Frog_pop_explosion_prim_init(MR_PGEN_INST*);
extern	MR_VOID			Pickup_explosion_disp(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			Frog_pop_explosion_disp(MR_PGEN_INST*, MR_VIEWPORT*);

extern	MR_VOID			Player_shield_prim_init(MR_PGEN_INST*);
extern	MR_VOID			Player_shield_disp(MR_PGEN_INST*, MR_VIEWPORT*);

extern	MR_VOID			Hilite_exhaust_disp(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			Hilite_exhaust_add(MR_OBJECT*);
extern	MR_VOID			Hilite_exhaust_move(MR_OBJECT*);

extern	MR_VOID			FrogEffectSlippingDisp(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			FrogEffectSlippingMove(MR_OBJECT*);
extern	MR_VOID			FrogEffectSlippingAdd(MR_OBJECT*);

extern	MR_VOID			FrogEffectBubbleAdd(MR_OBJECT*);
extern	MR_VOID			FrogEffectBubbleMove(MR_OBJECT*);

extern	MR_VOID			FrogEffectFireAdd(MR_OBJECT*);
extern	MR_VOID			FrogEffectFireMove(MR_OBJECT*);

extern	MR_VOID			Gold_frog_particle_move(MR_OBJECT*);

extern	MR_VOID			Hilite_dust_disp(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			Particle_ft4_prim_list_init(MR_PGEN_INST*);

extern	MR_VOID			For_swarm_prim_init(MR_PGEN_INST*);
extern	MR_VOID			For_swarm_disp(MR_PGEN_INST*, MR_VIEWPORT*);

extern	MR_VOID			Hilite_fire_disp(MR_PGEN_INST*, MR_VIEWPORT*);
extern	MR_VOID			Hilite_fire_move(MR_OBJECT*);
extern	MR_VOID			Hilite_fire_add(MR_OBJECT*);

extern	MR_VOID			Gold_frog_glow_prim_init(MR_PGEN_INST*);
extern	MR_VOID			Gold_frog_glow_move(MR_OBJECT*);
extern	MR_VOID			Gold_frog_glow_disp(MR_PGEN_INST*, MR_VIEWPORT*);

#endif	//__PARTICLE_H
