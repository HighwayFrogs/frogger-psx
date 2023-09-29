/******************************************************************************
*%%%% entity.h
*------------------------------------------------------------------------------
*
*	General entity handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Added new entity flag, and changed MR_OBJECT
*								ptr to a void pointer, to cope with animation.
*	01.05.97	Martin Kift		Added scripting code
*	12.05.97	Martin Kift		Externed Live_entity_root_ptr, which is only
*								a temp thing probably, need by temp collision
*								code (see collide.c)
*	15.05.97	Martin Kift		Added hit_frog flags
*	20.05.97	Martin Kift		Added moving sound variable to live_entity
*	16.06.97	Martin Kift		Added trigger generic entity
*	20.06.97	Tim Closs		Added ENTITY_ALIGN_TO_WORLD flag
*	02.07.97	Tim Closs		Added ENTITY_PROJECT_ON_LAND flag
*	03.07.97	Tim Closs		Added LIVE_ENTITY_RESPECT_SCALE_COLOURS flag
*								Added LIVE_ENTITY_RESPECT_AMBIENT_COLOURS flag
*	30.07.97	Gary Richards	Added UpdateMovingPlatformMOF
*	21.08.97	Martin Kift		Added popping code for live entities
*
*%%%**************************************************************************/

#ifndef	__ENTITY_H
#define	__ENTITY_H

#include "mr_all.h"
#include "path.h"
#include "form.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	ENTITY_DEBUG_PLOT_STATIC_BBOX	
//#define	ENTITY_DEBUG_PLOT_COLLPRIMS
//#define	ENTITY_DEBUG_DISPLAY_UNIQUE_IDS


#define	MAX_NUM_SPECIAL_EFFECTS			10			// Max number of special effects per live entity
#define	ENTITY_BASE_COLOUR_FADE_SHIFT	2			// Amount of fade per frame for entity base colour
#define	ENTITY_MAX_UNIQUE_ID_TEXT_AREAS	48			// debug


// Enum list of hilite types used to denote entity specials ( all types )
enum	{
		HILITE_TYPE_COLLISION,						// Collision hilite type
		HILITE_TYPE_3DSPRITE_SPLASH,				// Splash hilite type ( 3D sprite )
		HILITE_TYPE_3DSPRITE_WAKE,					// Wake hilite type ( 3D sprite )
		HILITE_TYPE_PARTICLE_EXHAUST,				// Car and lawnmower exhaust ( Particle generator )
		HILITE_TYPE_PARTICLE_CLOUD,					// Bison cloud ( Particle generator )
		HILITE_TYPE_PARTICLE_SMOKE,					// Smoke
		HILITE_TYPE_PARTICLE_FIRE,					// Fire
		HILITE_TYPE_MESH,							// Static mesh hilite type
		HILITE_TYPE_ANIM,							// Animating mesh hilite type
		};

// Enum list of Entity Special types
enum	{
		ENTITY_SPECIAL_TYPE_SPRITE,					// 3D Sprite entity special
		ENTITY_SPECIAL_TYPE_PARTICLE,				// Particle generator entity special
		ENTITY_SPECIAL_TYPE_MESH,					// Static mesh entity special
		ENTITY_SPECIAL_TYPE_ANIM,					// Animating mesh entity special
		};

// ENTITY flags
#define	ENTITY_HIDDEN						(1<<0) 	// don't create LIVE_ENTITY while this is set
#define	ENTITY_NO_DISPLAY					(1<<1) 	// don't display any mesh, etc
#define	ENTITY_NO_MOVEMENT					(1<<2) 	// don't move the entity
#define ENTITY_NO_COLLISION					(1<<3) 	// no collision for this entity
#define ENTITY_ALIGN_TO_WORLD				(1<<4) 	// entity matrix always aligned to world axes
#define ENTITY_PROJECT_ON_LAND				(1<<5) 	// entity position/tangent is projected onto landscape
#define ENTITY_LOCAL_ALIGN					(1<<6)	// entity matrix is calculated locally (using Y part of entity matrix)

// LIVE_ENTITY flags
#define	LIVE_ENTITY_DESTROY					(1<<0)
#define LIVE_ENTITY_ANIMATED				(1<<1)
#define	LIVE_ENTITY_CARRIES_FROG_0			(1<<2) 	// frog 0 is on this entity (check (LIVE_ENTITY_CARRIES_FROG_0 << frog->fr_frog_id))
#define	LIVE_ENTITY_CARRIES_FROG_1			(1<<3) 	// frog 1 is on this entity
#define	LIVE_ENTITY_CARRIES_FROG_2			(1<<4) 	// frog 2 is on this entity
#define	LIVE_ENTITY_CARRIES_FROG_3			(1<<5) 	// frog 3 is on this entity

#define	LIVE_ENTITY_HIT_FROG_0				(1<<6) 	// frog 0 has hit this entity (check (LIVE_ENTITY_HIT_FROG_0 << frog->fr_frog_id))
#define	LIVE_ENTITY_HIT_FROG_1				(1<<7) 	// frog 1 has hit this entity
#define	LIVE_ENTITY_HIT_FROG_2				(1<<8) 	// frog 2 has hit this entity
#define	LIVE_ENTITY_HIT_FROG_3				(1<<9) 	// frog 3 has hit this entity
											
#define	LIVE_ENTITY_TARGETTED				(1<<10)	// targetted by TONGUE
#define	LIVE_ENTITY_TONGUED					(1<<11)	// hit by TONGUE
#define LIVE_ENTITY_FLIPBOOK				(1<<12)	// used in conjunction with LIVE_ENTITY_ANIMATED
#define LIVE_ENTITY_RESPECT_SCALE_COLOURS	(1<<13)	// when setting mi_colour_scale, multiply by colour values already set
#define LIVE_ENTITY_RESPECT_AMBIENT_COLOURS	(1<<14)	// when setting mi_custom_ambient, multiply by colour values already set
#define LIVE_ENTITY_NO_COLOUR_FADE			(1<<15)	// Used so Sprites are effected by cave lighting.
#define LIVE_ENTITY_NO_SCREEN_FADE			(1<<16)	// don't fade entity wrt screen, since it does it's own fading

#define	LIVE_ENTITY_CARRIES_FROG		(LIVE_ENTITY_CARRIES_FROG_0 | LIVE_ENTITY_CARRIES_FROG_1 | LIVE_ENTITY_CARRIES_FROG_2 | LIVE_ENTITY_CARRIES_FROG_3)

#define	LIVE_ENTITY_HIT_FROG			(LIVE_ENTITY_HIT_FROG_0 | LIVE_ENTITY_HIT_FROG_1 | LIVE_ENTITY_HIT_FROG_2 | LIVE_ENTITY_HIT_FROG_3)

// Clear this from flags each frame
#define	LIVE_ENTITY_CLEAR_MASK			(LIVE_ENTITY_CARRIES_FROG | LIVE_ENTITY_HIT_FROG | LIVE_ENTITY_RESPECT_SCALE_COLOURS | LIVE_ENTITY_RESPECT_AMBIENT_COLOURS)

// Some numbers used by target based entities
#define WORLD_SHIFT						(8)			// world shift (1 unit = 256)
#define	WORLD_GRAVITY					(0x2d800)	// world gravity (2560 << 16) / (30*30))	


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__entity				ENTITY;
typedef	struct	__live_entity			LIVE_ENTITY;
typedef	struct	__entity_special		ENTITY_SPECIAL;


struct __entity_special
	{
	MR_USHORT		es_type;			 	// Type of entity special ( these would be MR_HILITE type )
	MR_USHORT		es_part_index;		 	// Index of MR_PART within animation
	MR_MOF*			es_mof_ptr;	 			// MOF file (static or animated) used by hilite
	MR_SVEC*		es_vertex;			 	// Ptr to vertex within MR_PART vertex
	MR_MAT			es_lwtrans;		 		// Position/rotation in world of attachment
	MR_VOID*		es_api_item;		 	// Ptr to API item ( MR_OBJECT or MR_ANIM_ENV ) we created for this special
	MR_VOID*		es_api_insts[4];	 	// Ptr to API insts in viewport(s)
	ENTITY*			es_entity;				// Ptr to entity that this was created on
	};	// ENTITY_SPECIAL


struct	__entity
	{
	MR_USHORT		en_form_grid_id;	// index into map file formgrid list
	MR_USHORT		en_unique_id;		// unique instance id
	MR_USHORT		en_form_book_id;	// index into code FORM library for theme (0x8000 set if general list)
	MR_USHORT		en_flags;			// entity flags
	LIVE_ENTITY*	en_live_entity;		// ptr to LIVE_ENTITY if created, else NULL
	PATH_RUNNER*	en_path_runner;		// ptr to PATH_ENTITY if created, else NULL
	ENTITY*			en_next;			// ..in MAP_GROUP linked list
	ENTITY*			en_prev;			// ..in MAP_GROUP linked list
	
	};	// ENTITY


struct	__live_entity
	{
	LIVE_ENTITY*	le_next;
	LIVE_ENTITY*	le_prev;
	ENTITY*			le_entity;			// ptr back to ENTITY from which this was created
	MR_ULONG		le_flags;
	MR_MAT*			le_lwtrans;			// ptr to lw transform
	MR_MAT			le_matrix;			// lw transform of live entity (if not in map data)
	MR_VOID*		le_api_item0;		// ptr to API item (MR_OBJECT or MR_ANIM_ENV)
	MR_VOID*		le_api_item1;		// ptr to API item
	MR_VOID*		le_api_insts[4];	// ptr to API mesh instance ( as returned by MRAddObjectToViewport )
	MR_VOID*		le_specific;		// ptr to run time vars.
	MR_VOID*		le_script;			// ptr to script file to follow (or NULL)
	MR_VOID*		le_moving_sound;	// ptr to a potential moving sound (must be killed on deletion of a live_entity)
	MR_VOID*		le_effect;			// ptr to special effect

	MR_ULONG		le_numspecials;		// number of special effects this entity has
	ENTITY_SPECIAL*	le_specials;		// ptr to special effects

	};	// LIVE_ENTITY;


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	ENTITY_GET_FORM(a) \
		(Map_form_ptrs[(a)->en_form_grid_id])

#define	ENTITY_GET_ENTITY_TYPE(a) \
		((ENTITY_GET_FORM_BOOK(a))->fb_entity_type)

#define	ENTITY_GET_ENTITY_BOOK(a) \
		(&Entity_library[(ENTITY_GET_FORM_BOOK(a))->fb_entity_type])

#define	ENTITY_GET_FORM_BOOK(a) \
		(Form_library_ptrs[((a)->en_form_book_id & 0x8000) >> 15] + ((a)->en_form_book_id & 0x7fff))

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

// Positions for fading entities at edge of map
extern	MR_SVEC			Fade_top_left_pos;
extern	MR_SVEC			Fade_bottom_right_pos;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			InitialiseLiveEntities(MR_VOID);
extern	LIVE_ENTITY*	CreateLiveEntity(ENTITY*);
extern	MR_VOID			KillLiveEntity(LIVE_ENTITY*);
extern	MR_VOID			KillAllLiveEntities(MR_VOID);
extern	MR_VOID			UpdateLiveEntities(MR_VOID);
extern	MR_VOID*		EntityLinkToMapGroup(ENTITY*, MR_VEC*);
extern	MR_VOID			LinkEntities(MR_VOID);
extern	MR_VOID			UnlinkEntities(MR_VOID);
extern	MR_VOID			HideAllEntitiesExcept(MR_LONG);

// Entity callbacks
extern	MR_VOID			ENTSTRCreateStationaryMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRKillStationaryMOF(LIVE_ENTITY*);

extern	MR_VOID			ENTSTRCreateMovingMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRKillMovingMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRUpdateMovingMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRUpdateMovingPlatformMOF(LIVE_ENTITY*);

extern	MR_VOID			ENTSTRCreateDynamicMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRUpdateDynamicMOF(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRKillDynamicMOF(LIVE_ENTITY*);

extern	MR_VOID			ENTSTRCreateMovingSprite(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRKillMovingSprite(LIVE_ENTITY*);

// Trigger create/update/callback functions
extern	MR_VOID			ENTSTRCreateTrigger(LIVE_ENTITY*);
extern	MR_VOID			ENTSTRUpdateTrigger(LIVE_ENTITY*);
extern	MR_VOID 		TriggerEntityCallback(MR_VOID*, MR_VOID*, MR_VOID*);

extern	MR_VOID			ENTSTRCreateMOF(LIVE_ENTITY*, FORM*);
extern	MR_VOID			ENTSTRCreateSprite(LIVE_ENTITY*, FORM*);

extern	MR_VOID			UpdateEntityWithVelocity(ENTITY*, MR_MAT*, MR_VEC*, MR_VEC*);
extern	LIVE_ENTITY*	GetNextLiveEntityOfType(LIVE_ENTITY*, MR_USHORT);
extern	LIVE_ENTITY*	GetNextLiveEntityWithUniqueId(MR_USHORT);
extern	ENTITY*			GetNextEntityWithUniqueId(MR_USHORT);

extern	MR_VOID 		FadeLiveEntity(LIVE_ENTITY*);
extern	MR_VOID			SetLiveEntityScaleColours(LIVE_ENTITY*, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID			SetLiveEntityCustomAmbient(LIVE_ENTITY*, MR_LONG, MR_LONG, MR_LONG);

extern	MR_VOID 		CreateLiveEntitySpecials(LIVE_ENTITY*);
extern	MR_VOID			UpdateLiveEntitySpecials(LIVE_ENTITY*);
extern	MR_VOID			KillLiveEntitySpecials(LIVE_ENTITY*);

extern	MR_VOID			ResetEntities(MR_VOID);

extern	MR_LONG			DistanceToFrogger(LIVE_ENTITY*, MR_BYTE, MR_LONG);

extern	MR_VOID			InitPrims(MR_PGEN_INST*);
extern	MR_VOID			UpdateGenerator(MR_OBJECT*);
extern	MR_VOID			CreateParticle(MR_OBJECT*);
extern	MR_VOID			DisplayPrims(MR_PGEN_INST*, MR_VIEWPORT*);

// Animation functions
extern	MR_VOID			LiveEntitySetAction(LIVE_ENTITY*, MR_ULONG);
extern	MR_ANIM_ENV* 	LiveEntityCreateAnimationEnvironment(LIVE_ENTITY*, MR_MOF*);
extern	MR_BOOL			LiveEntityCheckAnimationFinished(LIVE_ENTITY*);
extern	MR_SHORT		LiveEntityGetAction(LIVE_ENTITY* live_entity);
extern	MR_VOID			LiveEntitySetCel(LIVE_ENTITY*, MR_SHORT);
extern	MR_VOID			LiveEntityChangeVolume(MR_UBYTE, MR_BOOL);

extern	MR_VOID			LiveEntityInitPop(LIVE_ENTITY*);
extern	MR_VOID			LiveEntityStartPolyPiecePop(LIVE_ENTITY*);
extern	MR_BOOL			LiveEntityUpdatePolyPiecePop(LIVE_ENTITY*);
extern	MR_VOID			LiveEntityFreePop(LIVE_ENTITY*);

#endif		//__ENTITY_H

