/******************************************************************************
*%%%% collide.h
*------------------------------------------------------------------------------
*
*	Collision functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	21.04.97	Tim Closs		Created
*	12.05.97	Martin Kift		Added CollideEntity() function
*	15.05.97	Martin Kift		Added collprim support (defines and suchlike)
*	26.06.97	Tim Closs		Added COLL_B_FLAGS_FLIPBOOK
*
*%%%**************************************************************************/

#ifndef	__COLLIDE_H
#define	__COLLIDE_H

#include "mr_all.h"
#include "frog.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	DEBUG_DISPLAY_FROG_MAP_GROUPS
//#define	DEBUG_DISPLAY_FROG_GRID_SQUARES
//#define	DEBUG_DISPLAY_FORMS
//#define	DEBUG_DISPLAY_FORM_BOUNDING_SPHERES

// Collision prim reaction types
enum	{
		COLLPRIM_TYPE_SAFE,			// take out
		COLLPRIM_TYPE_DEADLY,
		COLLPRIM_TYPE_BOUNCY,
		COLLPRIM_TYPE_FORM,			// user callback
		};

// MRCollisionCheck flags
#define COLL_A_FLAGS			(MR_COLLCHECK_A_OWNER_ANIM_ENV | MR_COLLCHECK_A_ALL_PARTS | MR_COLLCHECK_A_HILITE)
#define COLL_B_FLAGS_STATIC		(MR_COLLCHECK_B_OWNER_STATIC_MESH | MR_COLLCHECK_B_COLLPRIM)
#define COLL_B_FLAGS_ANIM		(MR_COLLCHECK_B_OWNER_ANIM_ENV | MR_COLLCHECK_B_ALL_PARTS | MR_COLLCHECK_B_COLLPRIM)
#define COLL_B_FLAGS_FLIPBOOK	(MR_COLLCHECK_B_OWNER_ANIM_ENV | MR_COLLCHECK_B_COLLPRIM)

// Entity too vertical to jump onto
#define	COLLIDE_ENTITY_TOO_VERTICAL_EPSILON2	MR_SQR(0x700)


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct __coll_visibility_info		COLL_VISIBILITY_INFO;
typedef	struct __coll_visibility_data		COLL_VISIBILITY_DATA;

struct __coll_visibility_info
	{
	// following are setup before calling the coll function...!
	MR_ULONG*		form_ids_ptr;			// Ptr to a list of FORM id's that you wish to check against (or NULL)
	MR_ULONG		num_forms;				// Number of forms in above list (unneccessary if NULL)
	MR_ULONG		max_vis_entities;		// Maximum number of entities that can be checked for
	};	// COLL_VISIBILITY_INFO


// Collision-used structure for retrieving info from several collision functions, 
// such as VisibilityCollisionCheck(), 
struct __coll_visibility_data
	{
    // The following data is supplied by the collision functions for each collision!
	MR_VOID*		hit_entity;					// Ptr to entity collided with
	MR_LONG			hit_entity_frog;			// Is this entity a frog?
    MR_COLLPRIM*	hit_entity_coll_prim;		// Ptr to collprim hit (could be NULL)
    MR_VEC			hit_position;				// position of entity when it hit
//	MR_VEC			hit_normal;					// normal to vector as entity hit it!
//	MR_VEC			hit_reflection;				// reflection to vector as entity hit it!
//	MR_SVEC			hit_prim_position;			// point on prim that was hit
	MR_BOOL			hit_actual_hit;				// did we actually (and not in a look ahead fashion) hit an entity

	};	// COLL_VISIBILITY_DATA


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

// Frog
extern	MR_VOID		CollideFrog(FROG*);
extern	MR_VOID		ReactFrogWithForm(FROG*, FORM*, FORM_DATA*, ENTITY*, MR_VEC*, MR_MAT*);
extern	MR_VOID		ReactFrogWithGridFlags(FROG*, MR_USHORT);
extern	MR_BOOL		CollideFrogWithCollPrims(FROG*, LIVE_ENTITY*, FORM_BOOK*);
extern	MR_VOID		ReactFrogWithCollPrim(FROG*, LIVE_ENTITY*, FORM_BOOK*, MR_COLLCHECK*);

// Frog stack
extern	MR_VOID		CollideFrogWithFrogs(FROG*);
extern	MR_BOOL		CheckFrogStackCollision(FROG*, FROG*, MR_MAT*);

// Entity
extern	MR_BOOL		CollideEntity(LIVE_ENTITY*, ENTITY**);
extern	MR_BOOL		CollideEntityWithEntity(LIVE_ENTITY*, LIVE_ENTITY*);
extern	MR_LONG		VisibilityCollisionCheck(MR_MAT*, MR_VEC*, COLL_VISIBILITY_INFO*, COLL_VISIBILITY_DATA*);
extern	MR_BOOL		ValidForm(MR_ULONG*, MR_ULONG, MR_ULONG);
extern	MR_LONG		SnapFrogRotationToMatrix(FROG*, MR_MAT*, MR_MAT*);
extern	MR_VOID		SnapFrogToMatrix(FROG*, MR_MAT*);

#endif	//__COLLIDE_H

