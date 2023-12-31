/******************************************************************************
*%%%% entity.c
*------------------------------------------------------------------------------
*
*	General entity handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Added animated mof support to standard entities
*	30.04.97	Martin Kift		Added an 'immortal' entity
*	02.05.97	Martin Kift		Added new entity library variable, for size
*								of runtime structure. Also scripting code.
*	06.05.97	William Bell	Added base colour fade out for entities take leave
*								the map area.
*	06.05.97	William Bell	Added 3D sprite effects for models.
*	20.05.97	Martin Kift		Added moving sound suport for live entities
*	26.05.97	Martin Kift		Added new TRIGGER entity types
*	04.06.97	Gary Richards	Added DistanceToFrog.
*	20.06.97	Tim Closs		Functions respect ENTITY_ALIGN_TO_WORLD flag
*	02.07.97	Tim Closs		ENTSTRUpdateMovingMOF() 
*								respects ENTITY_PROJECT_ON_LAND flag
*	03.07.97	Tim Closs		Added SetLiveEntityScaleColours()
*								Added SetLiveEntityCustomAmbient()
*								Renamed UpdateEntityBaseColour() to
*								FadeLiveEntity()
*							
*%%%**************************************************************************/

#include "entity.h"
#include "gamesys.h"
#include "project.h"
#include "library.h"
#include "form.h"
#include "mapload.h"
#include "misc.h"
#include "entlib.h"
#include "mapdebug.h"
#include "frog.h"
#include "scripter.h"
#include "mapview.h"
#include "collide.h"

LIVE_ENTITY		Live_entity_root;
LIVE_ENTITY*	Live_entity_root_ptr;

// Anim lists
MR_ULONG		Splash_display_list[]	=
{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_splash3,
	MR_SPRT_RESTART
};

MR_ULONG		Wake_display_list[]		=
{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETSCALE,	(8<<16),
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_wake4,
	MR_SPRT_RESTART
};

// Particle Fountain definitions
MR_PGEN_INIT	Fountain_definition		=
{
	MR_PTYPE_2D,			// 2D point
	NULL,					// no flags
	sizeof(POLY_FT4),		// size of particle poly

	NULL,					// geom init
	InitPrims,				// prim init
	UpdateGenerator,		// move
	DisplayPrims,			// disp

	(-10<<16),				// gravity
	4,						// max num particles
	(MR_USHORT)-1,			// lifetime of generator, -1 = infinite

	7,						// particle min life
	50,						// particle max life

	(MR_ULONG)&im_gatso,	// particle image, single image
	NULL,

};

MR_ULONG	Static_mesh_specials_resource_id[]=
	{
	RES_ORG_FLY_XMR,
	};

MR_ULONG	Anim_mesh_specials_resource_id[]=
	{
//	RES_ORG_BEAVER_XAR,
	RES_ORG_SNAKE_XMR,
	};

/******************************************************************************
*%%%% InitialiseLiveEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseLiveEntities(MR_VOID)
*
*	FUNCTION	Initialise the live entities list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseLiveEntities(MR_VOID)
{
	Live_entity_root_ptr = &Live_entity_root;

	Live_entity_root_ptr->le_next = NULL;
	Live_entity_root_ptr->le_prev = NULL;
}


/******************************************************************************
*%%%% CreateLiveEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	LIVE_ENTITY* live_entity =	CreateLiveEntity(
*											ENTITY*	entity)
*
*	FUNCTION	Create a LIVE_ENTITY from an ENTITY
*
*	INPUTS		entity			-	from which to create
*
*	RESULT		live_entity		-	created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	02.04.97	Martin Kift		Added new entity library variable, for size
*								of runtime structure. Also scripting code.
*	12.05.97	Martin Kift		Recoded scripting code (scripts moved to formlib)
*	
*%%%**************************************************************************/

LIVE_ENTITY*	CreateLiveEntity(ENTITY*	entity)
{
	LIVE_ENTITY*	live_entity;
	ENTITY_BOOK*	entity_book;
	MR_LONG			alloc_size;
	MR_ULONG		i;
	MR_LONG			script_id;

	MR_ASSERT(entity);

	entity_book 	= ENTITY_GET_ENTITY_BOOK(entity);
	script_id		= ENTITY_GET_FORM_BOOK(entity)->fb_script;

	// Need to work out size of memory to alloc, which is a factor of the LIVE_ENTITY size,
	// whether a runtime structure is needed, and finally whether a SCRIPT_INFO structure is required
	alloc_size = sizeof(LIVE_ENTITY) + entity_book->eb_runtime_data_size;
	if (script_id)
		alloc_size += sizeof(SCRIPT_INFO);

	// Create structure, remembering to include the runtie structure of the required entity
	live_entity 			= MRAllocMem(alloc_size, "LIVE ENTITY");
	entity->en_live_entity 	= live_entity;

	// Link new structure into list
	if (live_entity->le_next = Live_entity_root_ptr->le_next)
		Live_entity_root_ptr->le_next->le_prev = live_entity;
	Live_entity_root_ptr->le_next = live_entity;
	live_entity->le_prev = Live_entity_root_ptr;

	// Initialise structure
	live_entity->le_entity			= entity;
	live_entity->le_flags 			= NULL;
	live_entity->le_lwtrans			= &live_entity->le_matrix;
	live_entity->le_api_item0		= NULL;
	live_entity->le_api_item1		= NULL;
	live_entity->le_moving_sound	= NULL;

	for (i = 0; i < Game_total_viewports; i++)
		live_entity->le_api_insts[i] = NULL;

	live_entity->le_specific		= live_entity + 1;
	live_entity->le_script			= NULL;
	
	// have to initialise the script at this point, if one exists
	if (script_id)
		{
		// work out pointer (offset) to the SCRIPT_INFO structure
		live_entity->le_script = (MR_UBYTE*)live_entity->le_specific + entity_book->eb_runtime_data_size;
		StartScript((SCRIPT_INFO*)live_entity->le_script, script_id, live_entity);
		}

	// Call specific ENTITY_BOOK creation callback
	//
	// Note: entity create callbacks must not tamper with the LIVE_ENTITY linked list
	if (entity_book->eb_callback_create)
	 	(entity_book->eb_callback_create)(live_entity);

	// $wb - Create all required 3D sprites
	CreateLiveEntitySpecials(live_entity);

	return(live_entity);
}


/******************************************************************************
*%%%% KillLiveEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillLiveEntity(
*				   		LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a LIVE_ENTITY
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	20.05.97	Martin Kift		Added killing of moving sounds (if alloced)
*	03.06.97	William Bell	Commented assertion if Frog on entity when
*								entity killed.  To stop this from asserting
*								during Game Over.
*
*%%%**************************************************************************/

MR_VOID	KillLiveEntity(LIVE_ENTITY*	live_entity)
{
	ENTITY_BOOK*	entity_book;

	MR_ASSERT(live_entity);
	MR_ASSERT(live_entity->le_entity);

	// $wb - See comment in function header
//	if (Frogs[0].fr_entity)
//		{
//		MR_ASSERT(Frogs[0].fr_entity->en_live_entity != live_entity);
//		}

	// Kill live entities specials
	KillLiveEntitySpecials(live_entity);

	entity_book	= ENTITY_GET_ENTITY_BOOK(live_entity->le_entity);

	// Remove structure from linked list
	live_entity->le_prev->le_next = live_entity->le_next;
	if	(live_entity->le_next)
		live_entity->le_next->le_prev = live_entity->le_prev;

	// Call specific ENTITY_BOOK kill callback
	//
	// Note: entity kill callbacks must not tamper with the LIVE_ENTITY linked list
	if (entity_book->eb_callback_kill)		
	 	(entity_book->eb_callback_kill)(live_entity);

	// Set owning ENTITY ptr to NULL
	live_entity->le_entity->en_live_entity = NULL;

	// Kill off moving sound if previously created
	if (live_entity->le_moving_sound)
		MRSNDKillMovingSound(live_entity->le_moving_sound);

	// Free structure memory
	MRFreeMem(live_entity);
}


/******************************************************************************
*%%%% KillAllLiveEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillAllLiveEntities(MR_VOID)
*
*	FUNCTION	Kill all LIVE_ENTITYs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillAllLiveEntities(MR_VOID)
{
	while(Live_entity_root_ptr->le_next)
		KillLiveEntity(Live_entity_root_ptr->le_next);
}


/******************************************************************************
*%%%% UpdateLiveEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateLiveEntities(MR_VOID)
*
*	FUNCTION	Update all LIVE_ENTITYs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	30.04.97	Martin Kift		Added an 'immortal' entity
*	02.04.97	Martin Kift		Added calls to new live entity scripting funcs.
*
*%%%**************************************************************************/

MR_VOID	UpdateLiveEntities(MR_VOID)
{
	LIVE_ENTITY*	live_entity;
	ENTITY_BOOK*	entity_book;


	live_entity = Live_entity_root_ptr;

	while(live_entity = live_entity->le_next)
		{
		// Should we destroy this LIVE_ENTITY?
		if	(
			(live_entity->le_flags & LIVE_ENTITY_DESTROY) &&
			(!((Frogs[0].fr_entity) && (Frogs[0].fr_entity->en_live_entity == live_entity)))
			)
			{
			live_entity = live_entity->le_prev;
			KillLiveEntity(live_entity->le_next);
			}
		else
			{
			entity_book	= ENTITY_GET_ENTITY_BOOK(live_entity->le_entity);

			// Note: entity update must not tamper with the LIVE_ENTITY linked list
			if	(entity_book->eb_callback_update)
				(entity_book->eb_callback_update)(live_entity);

			// Call the scripting update if one exists
			if (live_entity->le_script)
				UpdateScriptInfo(live_entity);

			// Set the flag to destroy this LIVE_ENTITY.  This will be cleared by CreateMapGroups if entity is in range
			
			// Exception to the rule above, don't set the destroy flag for immortal entityes, since this
			// results in a waste of time checking later
			if (!(entity_book->eb_flags & ENTITY_BOOK_IMMORTAL))
				// not an immortal entity, so its safe to mark as destroy please!
				live_entity->le_flags |= LIVE_ENTITY_DESTROY;

#ifdef DEBUG_DISPLAY_COLLISION_AREAS
			if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
				{
				if (live_entity->le_flags & LIVE_ENTITY_CARRIES_FROG)
					{
					if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
						{
						}
					else
						{
						if (live_entity->le_api_item0)
							{
							((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_PART_BBOX;
							((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;
							}
						}
					}
				else
					{
					if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
						{
						}
					else
						{
						if (live_entity->le_api_item0)
							{
							((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags &= ~MR_MESH_DEBUG_DISPLAY_PART_BBOX;
							((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;
							}
						}
					}
				}
#endif
		 	// Fade entity if off map/outside cave light
			FadeLiveEntity(live_entity);

			// Update live entity specials!!!
			UpdateLiveEntitySpecials(live_entity);
	
			// Clear various flags.  Note that LIVE_ENTITY_CARRIES_FROG_? will be set in UpdateFrogs()
			live_entity->le_flags &= ~LIVE_ENTITY_CLEAR_MASK;
			}
		}
}


/******************************************************************************
*%%%% ENTSTRCreateStationaryMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateStationaryMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a stationary MOF (static or animated)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Renamed
*	24.04.97	Martin Kift		Moved all model creation to a separate function
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateStationaryMOF(LIVE_ENTITY*	live_entity)
{
	ENTSTR_STATIC*	entity_type;
	ENTITY*			entity;
	FORM*  			form;
#ifdef DEBUG
	MR_ULONG		i, polys = 0;
	MR_PART*		part_ptr;
	MR_MOF**		mof_pptr;
	MR_MOF*			mof_ptr;
	MR_ANIM_ENV*	env;
#endif


	entity 					= live_entity->le_entity;
	form					= ENTITY_GET_FORM(entity);
	entity_type				= (ENTSTR_STATIC*)(entity + 1);
	live_entity->le_lwtrans	= &entity_type->et_matrix;

	// call generic function to create our MOF (be it static or animated model)
	ENTSTRCreateMOF(live_entity, form);
	
#ifdef DEBUG
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				{
				polys = ((MR_PART*)(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
				}
			else
				{
				env			= (MR_ANIM_ENV*)live_entity->le_api_item0;
				mof_pptr	= env->ae_header->ah_static_files;
				mof_ptr		= mof_pptr[env->ae_extra.ae_extra_env_single->ae_model->am_static_model];
				part_ptr	= (MR_PART*)(mof_ptr + 1);
				i			= mof_ptr->mm_extra;
				polys		= 0;
				while(i--)
					{
					polys	+= part_ptr->mp_prims;
					part_ptr++;
					}
				}
			}
		else
			{
			polys = ((MR_PART*)(((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
			}
		}
	Map_debug_live_stat_ent_polys 	+= polys;
	Map_debug_live_stat_ents++;
#endif
}


/******************************************************************************
*%%%% ENTSTRKillStationaryMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRKillStationaryMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a stationary MOF (static or animated)
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Renamed
*	24.04.97	Martin Kift		Recoded to cope with animated and static mofs
*
*%%%**************************************************************************/

MR_VOID	ENTSTRKillStationaryMOF(LIVE_ENTITY*	live_entity)
{
#ifdef DEBUG
	MR_ULONG		i, polys;
	MR_PART*		part_ptr;
	MR_MOF**		mof_pptr;
	MR_MOF*			mof_ptr;
	MR_ANIM_ENV*	env;
#endif


	// Is this entity a static or animated one?
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
#ifdef DEBUG
		Map_debug_live_stat_ents--;
//		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		if (live_entity->le_api_item0)
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				{
				polys = ((MR_PART*)(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
				}
			else
				{
				env			= (MR_ANIM_ENV*)live_entity->le_api_item0;
				mof_pptr	= env->ae_header->ah_static_files;
				mof_ptr		= mof_pptr[env->ae_extra.ae_extra_env_single->ae_model->am_static_model];
				part_ptr	= (MR_PART*)(mof_ptr + 1);
				i			= mof_ptr->mm_extra;
				polys		= 0;
				while(i--)
					{
					polys	+= part_ptr->mp_prims;
					part_ptr++;
					}
				}
			Map_debug_live_stat_ent_polys -= polys;
			}
#endif

		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			// Animated entity, need to kill it
			MRAnimEnvDestroyByDisplay((MR_ANIM_ENV*)live_entity->le_api_item0);

#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}
	else
		{
#ifdef DEBUG
		Map_debug_live_stat_ents--;
//		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		if (live_entity->le_api_item0)
			{
			polys							= ((MR_PART*)(((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
			Map_debug_live_stat_ent_polys 	-= polys;
			}
#endif

		// Static MOF
//		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		if (live_entity->le_api_item0)
			{
			((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}
}


/******************************************************************************
*%%%% ENTSTRCreateDynamicMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateDynamicMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a dynamic MOF (one that moves around world but is not
*				path based)
*
*	INPUTS		live_entity	-	to create
*
*	NOTES		Unlike a stationary MOF, a dynamic one doesn't want the lwtrans
*				to be pointed at the mapdata matrix, since this will in effect
*				alter the mapdata matrix and it will be lost forever (and the
*				entity could potentially require resetting in some cases). 
*
*				Therefore the create function copies the matrix into the live
*				entity matrix, and points the lwtrans at that. 
*
*				VERY IMPORTANT NOTE: because of the way this works, dynamic
*				entities must be flagged as IMMORTAL, since otherwise the
*				world matrix will be lost and the entity will be buggered. To
*				compensate for this, the code will at least attempt to turn off 
*				the model and suchlike to save as much processing time as possible!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateDynamicMOF(LIVE_ENTITY*	live_entity)
{
	ENTSTR_DYNAMIC*		entity_type;
	ENTITY*				entity;
	FORM*  				form;
#ifdef MR_DEBUG
	ENTITY_BOOK*		entity_book;
#endif

	entity 					= live_entity->le_entity;
	form					= ENTITY_GET_FORM(entity);
	entity_type				= (ENTSTR_DYNAMIC*)(entity + 1);
	live_entity->le_lwtrans	= &live_entity->le_matrix;

	// copy over initial world position from the map data, to place the entity
	// in the correct world position
	MR_COPY_MAT(&live_entity->le_matrix, &entity_type->et_matrix);
	MR_COPY_VEC((MR_VEC*)live_entity->le_matrix.t, (MR_VEC*)entity_type->et_matrix.t);

#ifdef MR_DEBUG
	// Assert if the entity is not flagged as immortal, its essential!
	entity_book	= ENTITY_GET_ENTITY_BOOK(entity);
	MR_ASSERT (entity_book->eb_flags & ENTITY_BOOK_IMMORTAL);
#endif // MR_DEBUG

	// call generic function to create our MOF (be it static or animated model)
	ENTSTRCreateMOF(live_entity, form);
}


/******************************************************************************
*%%%% ENTSTRUpdateDynamicMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRUpdateDynamicMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a dynamic MOF
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	Martin Kift		Created
*	29.05.97	Martin Kift		Added colour stuff...
*
*%%%**************************************************************************/

MR_VOID	ENTSTRUpdateDynamicMOF(LIVE_ENTITY*	live_entity)
{
	ENTSTR_DYNAMIC*		entity_type;
	ENTITY*				entity;

	entity 		= live_entity->le_entity;
	entity_type	= (ENTSTR_DYNAMIC*)(entity + 1);

	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, (MR_VEC*)entity_type->et_matrix.t);
}


/******************************************************************************
*%%%% ENTSTRKillDynamicMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRKillDynamicMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a dynamic MOF (static or animated)
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRKillDynamicMOF(LIVE_ENTITY*	live_entity)
{
	// Is this entity a static or animated one?
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			// Animated entity, need to kill it
			MRAnimEnvDestroyByDisplay((MR_ANIM_ENV*)live_entity->le_api_item0);
#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}
	else
		{
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			// Static entity
			((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}
}


/******************************************************************************
*%%%% ENTSTRCreateMovingMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateMovingMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a moving MOF
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Renamed
*	24.04.97	Martin Kift		Moved all model creation to a separate function
*	20.06.97	Tim Closs		Respects ENTITY_ALIGN_TO_WORLD flag
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateMovingMOF(LIVE_ENTITY*	live_entity)
{
	ENTSTR_STATIC*	entity_type;
	ENTITY*			entity;
	FORM*  			form;
	MR_VEC			vec_x;
	MR_VEC			vec_y;
	MR_VEC			vec_z;
#ifdef DEBUG
	MR_ULONG		i, polys = 0;
	MR_PART*		part_ptr;
	MR_MOF**		mof_pptr;
	MR_MOF*			mof_ptr;
	MR_ANIM_ENV*	env;
#endif

	entity 		= live_entity->le_entity;
	form		= ENTITY_GET_FORM(entity);
	entity_type	= (ENTSTR_STATIC*)(entity + 1);

	// We assume the entity already has a PATH_RUNNER
	MR_ASSERT(entity->en_path_runner);

	// Set up live entity position and rotation from PATH_RUNNER
	live_entity->le_lwtrans	= &live_entity->le_matrix;
	MR_INIT_MAT(live_entity->le_lwtrans);
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, &entity->en_path_runner->pr_position);

	if (!(entity->en_flags & ENTITY_ALIGN_TO_WORLD))
		{
		MR_COPY_VEC(&vec_z, &entity->en_path_runner->pr_tangent);
		MROuterProduct12(&Game_y_axis_pos, &vec_z, &vec_x);
		MRNormaliseVEC(&vec_x, &vec_x);
		MROuterProduct12(&vec_z, &vec_x, &vec_y);
		WriteAxesAsMatrix(live_entity->le_lwtrans, &vec_x, &vec_y, &vec_z);
		}
	
	// call generic function to create our MOF (be it static or animated model)
	ENTSTRCreateMOF(live_entity, form);

#ifdef DEBUG
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				{
				polys = ((MR_PART*)(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
				}
			else
				{
				env			= (MR_ANIM_ENV*)live_entity->le_api_item0;
				mof_pptr	= env->ae_header->ah_static_files;
				mof_ptr		= mof_pptr[env->ae_extra.ae_extra_env_single->ae_model->am_static_model];
				part_ptr	= (MR_PART*)(mof_ptr + 1);
				i			= mof_ptr->mm_extra;
				polys		= 0;
				while(i--)
					{
					polys	+= part_ptr->mp_prims;
					part_ptr++;
					}
				}
			}
		else
			{
			polys = ((MR_PART*)(((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
			}
		}
	Map_debug_live_path_ent_polys 	+= polys;
	Map_debug_live_path_ents++;
#endif
}


/******************************************************************************
*%%%% ENTSTRKillMovingMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRKillMovingMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a moving MOF
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	24.04.97	Martin Kift		Recoded to cope with animated and static mofs
*
*%%%**************************************************************************/

MR_VOID	ENTSTRKillMovingMOF(LIVE_ENTITY*	live_entity)
{
#ifdef DEBUG
	MR_ULONG		i, polys;
	MR_PART*		part_ptr;
	MR_MOF**		mof_pptr;
	MR_MOF*			mof_ptr;
	MR_ANIM_ENV*	env;
#endif

	// Is this entity a static or animated one?
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
#ifdef DEBUG
		Map_debug_live_path_ents--;
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
				{
				polys = ((MR_PART*)(((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
				}
			else
				{
				env			= (MR_ANIM_ENV*)live_entity->le_api_item0;
				mof_pptr	= env->ae_header->ah_static_files;
				mof_ptr		= mof_pptr[env->ae_extra.ae_extra_env_single->ae_model->am_static_model];
				part_ptr	= (MR_PART*)(mof_ptr + 1);
				i			= mof_ptr->mm_extra;
				polys		= 0;
				while(i--)
					{
					polys	+= part_ptr->mp_prims;
					part_ptr++;
					}
				}
			Map_debug_live_path_ent_polys -= polys;
			}
#endif

		// Animated entity
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			MRAnimEnvDestroyByDisplay((MR_ANIM_ENV*)live_entity->le_api_item0);
#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}
	else
		{
#ifdef DEBUG
		Map_debug_live_path_ents--;
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			polys							= ((MR_PART*)(((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_extra.me_extra_static_mesh->sm_mof_ptr + 1))->mp_prims;
			Map_debug_live_path_ent_polys 	-= polys;
			}
#endif
		// Static entity
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
#ifdef MR_DEBUG
			live_entity->le_api_item0 = NULL;
#endif
			}
		}

	// $wb - Moved to KillLiveEntity()
//	KillLiveEntitySpecials(live_entity);
}


/******************************************************************************
*%%%% ENTSTRUpdateMovingMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRUpdateMovingMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a moving MOF
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	20.06.97	Tim Closs		Respects ENTITY_ALIGN_TO_WORLD flag
*
*%%%**************************************************************************/

MR_VOID	ENTSTRUpdateMovingMOF(LIVE_ENTITY*	live_entity)
{
	ENTITY*		entity;
	MR_VEC		vec_x;
	MR_VEC		vec_y;
	MR_VEC		vec_z;


 	entity	= live_entity->le_entity;

	// We assume the entity already has a PATH_RUNNER
	MR_ASSERT(entity->en_path_runner);
		
	// Set up live entity position and rotation from PATH_RUNNER
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, &entity->en_path_runner->pr_position);

	if (!(entity->en_flags & ENTITY_ALIGN_TO_WORLD))
		{
		MR_COPY_VEC(&vec_z, &entity->en_path_runner->pr_tangent);

		if (!(entity->en_flags & ENTITY_LOCAL_ALIGN))
			{
			MROuterProduct12(&Game_y_axis_pos, &vec_z, &vec_x);
			}
		else
			{
			MR_SET_VEC(&vec_y,	live_entity->le_lwtrans->m[0][1],
								live_entity->le_lwtrans->m[1][1],
								live_entity->le_lwtrans->m[2][1]);
			MROuterProduct12(&vec_y, &vec_z, &vec_x);
			}

		MRNormaliseVEC(&vec_x, &vec_x);
		MROuterProduct12(&vec_z, &vec_x, &vec_y);
		WriteAxesAsMatrix(live_entity->le_lwtrans, &vec_x, &vec_y, &vec_z);
		}
	else
		{
		vec_x.vx = 0;
		}
}


/******************************************************************************
*%%%% ENTSTRCreateMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Creates the model (be it static mesh or animated environment)
*				for the live entity
*
*	INPUTS		live_entity	-	live entity to create
*				form		-	form ptr (for this entity)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Martin Kift		Created
*	01.05.97	William Bell	Updated to initialise the colour scale element of
*								the mesh instance structure for both static and
*								animating models
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateMOF(LIVE_ENTITY*	live_entity,
						FORM*			form)
{
	MR_MOF*			mof;


	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		// Examine whether the entity's mof is static or animated, and handle accordingly
		mof	= Map_mof_ptrs[ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_mof_id];
		if (mof->mm_flags & MR_MOF_ANIMATED)
			{
			// Model is animated, so created a single environment for it!
			live_entity->le_api_item0 = MRAnimEnvSingleCreateWhole(	(MR_ANIM_HEADER*)mof, 
																   	0, 
																   	MR_OBJ_STATIC,
																   	(MR_FRAME*)live_entity->le_lwtrans);
	
			// Set a default animation action of zero, default behaviour so to speak
			MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, 0);
	
			// Add environment to viewport(s)
			GameAddAnimEnvToViewportsStoreInstances(live_entity->le_api_item0, (MR_ANIM_ENV_INST**)live_entity->le_api_insts);
			live_entity->le_flags |= LIVE_ENTITY_ANIMATED;
			}
		else
			{
			// Model is static - is it a flipbook?
			if (mof->mm_flags & MR_MOF_FLIPBOOK)
				{
				live_entity->le_api_item0 	= MRAnimEnvFlipbookCreateWhole(	mof, 
																		   	MR_OBJ_STATIC,
																		   	(MR_FRAME*)live_entity->le_lwtrans);

				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, 0);

				// Add environment to viewport(s)
				GameAddAnimEnvToViewportsStoreInstances(live_entity->le_api_item0, (MR_ANIM_ENV_INST**)live_entity->le_api_insts);
				live_entity->le_flags |= (LIVE_ENTITY_ANIMATED | LIVE_ENTITY_FLIPBOOK);
				}
			else
				{
				live_entity->le_api_item0 	= MRCreateMesh(	mof,
											   				(MR_FRAME*)live_entity->le_lwtrans,	
											   				MR_OBJ_STATIC,
											   				NULL);
#ifdef ENTITY_DEBUG_PLOT_STATIC_BBOX	
				((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_PART_BBOX;
#endif
#ifdef ENTITY_DEBUG_PLOT_COLLPRIMS
				((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;
#endif
				// Add mesh to viewport(s)
				GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);
				live_entity->le_flags &= ~LIVE_ENTITY_ANIMATED;
				}
			}	
		}
	else
		{
		// ENTITY_NO_DISPLAY
		mof	= Map_mof_ptrs[ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_mof_id];
		if (!(mof->mm_flags & MR_MOF_ANIMATED))
			{
			live_entity->le_api_item0 	= MRCreateMesh(	mof,
										   				(MR_FRAME*)live_entity->le_lwtrans,	
										   				MR_OBJ_STATIC,
										   				NULL);

			((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
			}
		}
}


/******************************************************************************
*%%%% CalculateInitialVelocity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VEC CalculateInitialVelocity(	
*									MR_MAT*		curr_matrix, 
*									MR_SVEC*	dest_pos, 
*									MR_VEC*		position, 
*									MR_LONG		time)
*
*	FUNCTION	Used to calculate initial velocity for falling objects under gravity.
*
*	INPUTS		curr_matrix	- current matrix of the entity
*				dest_pos	- destinition position
*				position	- dup
*				time		- time to get to target
*
*	RESULT		Vector:
*					X & Z Positional Changes. 
*					Y is initial velocity.
*					ALL Shift by 16
*
*	NOTES		These are the mechanical functions used to do the calcs:
*					s = ut + 1/2at^2
*					u  = (s - 1/2at^2)/t
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Ported from old frogger code (written by Gary)
*
*%%%**************************************************************************/

MR_VEC CalculateInitialVelocity(	MR_MAT*		curr_matrix, 
									MR_SVEC*	dest_pos, 
									MR_VEC*		position, 
									MR_SHORT	time)
{
	MR_VEC		result;
	MR_LONG64	temp;
	MR_LONG		half_time;
	
	// To speed up calculate times.
	half_time = (time << (16-1));			

	// Set the Positional Offset to the current position.
	position->vx = curr_matrix->t[0] << 16;
	position->vy = curr_matrix->t[1] << 16;
	position->vz = curr_matrix->t[2] << 16;

	// Find distance between where we are and where we want to be.
	result.vx = (dest_pos->vx - curr_matrix->t[0]) << 16;
	result.vy = (dest_pos->vy - curr_matrix->t[1]) << 16;
	result.vz = (dest_pos->vz - curr_matrix->t[2]) << 16;
	MR_ASSERTMSG(time, "Target time not set for target-based entity");
	
	// Calc the initial velocity of Y.
	temp = ((MR_LONG64)WORLD_GRAVITY * (MR_LONG64)time * (MR_LONG64)time)>>1;
	temp = result.vy - temp;
	result.vy = (temp + half_time) / time;
	result.vx = (result.vx + half_time) / time;
	result.vz = (result.vz + half_time) / time;

	// return vector
	return result;
}


/******************************************************************************
*%%%% UpdateEntityWithVelocity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateEntityWithVelocity(
*										MR_MAT* matrix, 
*										MR_VEC* position, 
*										MR_VEC* velocity)
*
*	FUNCTION	Used to update the current entities with it's new velocity 
*				falling under gravity.
*
*	INPUTS		entity		- ptr to entity to update
*				matrix		- matrix of the entity to update 
*				position	- dup
*				velocity	- velocity to add to entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Ported from old frogger code (written by Gary)
*	26.05.97	Martin Kift		Added entity param, so pausing/unpausing is respected.
*
*%%%**************************************************************************/

MR_VOID UpdateEntityWithVelocity(ENTITY*	entity,
								 MR_MAT*	matrix, 
								 MR_VEC*	position, 
								 MR_VEC*	velocity)
{
	// is movement flag set?
	if (!(entity->en_flags & ENTITY_NO_MOVEMENT))
		{
		// First adjust velocity as due to gravity
		// NOTE Y is actually velocity NOT position.
		velocity->vy += WORLD_GRAVITY;		

		// Now update the entities accurate position
		MR_ADD_VEC(position, velocity);

		// Finally copy the entities accurate position into the integer actual position
		matrix->t[0] = (position->vx >> 16);
		matrix->t[1] = (position->vy >> 16);
		matrix->t[2] = (position->vz >> 16);
	}
}

/******************************************************************************
*%%%% GetNextLiveEntityOfType
*------------------------------------------------------------------------------
*
*	SYNOPSIS	LIVE_ENTITY* GetNextLiveEntityOfType(	
*										LIVE_ENTITY*	last_live_entity, 
*										MR_USHORT		form_id)
*
*	FUNCTION	This function loops through the live_entity list, finding each 
*				(in turn) live entity of the requested type...It should be 
*				primed by an initial call of NULL (for live entity ptr) to find 
*				the first one... if the function returns NULL it means there are 
*				no more to find!
*
*	INPUTS		last_live_entity	-	ptr to last live entity ptr found, or NULL 
*										if search should start at beginning of list.
*				form_id				-	form ID to search for.
*
*	RESULT		Pointer to live entuty is one is found, else NULL.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.04.97	Martin Kift		Ported from old frogger code (written by myself)
*
*%%%**************************************************************************/

LIVE_ENTITY* GetNextLiveEntityOfType(LIVE_ENTITY*	last_live_entity, 
									 MR_USHORT		form_id)
{
	LIVE_ENTITY*	live_entity;
	ENTITY*			entity;

	// setup the live entity pointer to point to the correct place, either root
	// or the requested entity
	if (!last_live_entity)
		live_entity = Live_entity_root_ptr;
	else
		live_entity = last_live_entity;

	// start loop through the live entity list, starting with the 'NEXT' one of
	// course, since either the root entity or the passed in entity should not
	// be checked!
	while(live_entity = live_entity->le_next)
		{
		entity = live_entity->le_entity;

		// is this entity of the right type?
		if (entity->en_form_book_id == form_id)
			{
			// yes it is, return a pointer to it
			return live_entity;
			}
		}

	// nothing found, return NULL
	return NULL;
}

/******************************************************************************
*%%%% GetNextLiveEntityWithUniqueId
*------------------------------------------------------------------------------
*
*	SYNOPSIS	LIVE_ENTITY* GetNextLiveEntityWithUniqueId(
*										MR_USHORT		unique_id)
*
*	FUNCTION	This function loops through the live_entity list, trying to find
*				a live_entity with the supplied unique id
*
*	INPUTS		unique_id		-	unique ID to search for.
*
*	RESULT		Pointer to live entuty is one is found, else NULL.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

LIVE_ENTITY* GetNextLiveEntityWithUniqueId(MR_USHORT unique_id)
{
	LIVE_ENTITY*	live_entity;

	live_entity = Live_entity_root_ptr;

	while(live_entity = live_entity->le_next)
		{
		// is this entity of the right type?
		if (live_entity->le_entity->en_unique_id == unique_id)
			{
			// yes it is, return a pointer to it
			return live_entity;
			}
		}

	// nothing found, return NULL
	return NULL;
}

/******************************************************************************
*%%%% GetNextEntityWithUniqueId
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ENTITY* GetNextEntityWithUniqueId(MR_USHORT	unique_id)
*
*	FUNCTION	This function loops through the entity list in the map, trying 
*				to find	an entity with the supplied unique id.
*
*	INPUTS		unique_id		-	unique ID to search for.
*
*	RESULT		Pointer to entuty is one is found, else NULL.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

ENTITY* GetNextEntityWithUniqueId(MR_USHORT unique_id)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	MR_ULONG		i, ofs;

	// Resolve entity offsets to ptrs
	ofs			= (MR_ULONG)Map_header;
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;

	while(i--)
		{
		*entity_pptr 	= (ENTITY*)*entity_pptr;
		entity			= *entity_pptr;

		// Is this our entity?
		if (entity->en_unique_id == unique_id)
			return entity;

		entity_pptr++;
		}

	// nothing found, return NULL
	return NULL;
}


/******************************************************************************
*%%%% FadeLiveEntity
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID FadeLiveEntity(	
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function calculates the distance an entity is from the map
*				and then sets the model's base colour accordingly.  The further
*				from the map the darker the colour.
*
*	INPUTS		live_entity		-	ptr to live entity to fade
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	William Bell	Created
*	11.06.97	Martin Kift		Changed so that it works differently on caves
*
*%%%**************************************************************************/

MR_VOID FadeLiveEntity(LIVE_ENTITY* live_entity)
{
	MR_ULONG	x_dist;
	MR_ULONG	z_dist;
	MR_LONG		col;


	if (!(ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL))
		{
		if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
			{
			if (!(Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT))
				{
				x_dist = 0;
				z_dist = 0;
			
				// Calculate distance from map edges
				if ( live_entity->le_lwtrans->t[0] < Grid_base_x )
					x_dist = Grid_base_x - live_entity->le_lwtrans->t[0];
				else if ( live_entity->le_lwtrans->t[0] > ( Grid_base_x + ( Grid_xlen * Grid_xnum ) ) )
					x_dist = live_entity->le_lwtrans->t[0] - ( Grid_base_x + ( Grid_xlen * Grid_xnum ) );
			
				// Is z off bottom map edge ?
				if ( live_entity->le_lwtrans->t[2] < Grid_base_z )
					z_dist = Grid_base_z - live_entity->le_lwtrans->t[2];
				else if ( live_entity->le_lwtrans->t[2] > ( Grid_base_z + ( Grid_zlen * Grid_znum ) ) )
					z_dist = live_entity->le_lwtrans->t[2] - ( Grid_base_z + ( Grid_zlen * Grid_znum ) );
				}
			else
				{
				x_dist = abs(Frogs[0].fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0]);
				z_dist = abs(Frogs[0].fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2]);
				}
			
			// Calculate colour value according to distance
			col = (x_dist + z_dist) >> ENTITY_BASE_COLOUR_FADE_SHIFT;
			col	= MAX(0, 0x80 - col);
			SetLiveEntityScaleColours(live_entity, col, col, col);
			}
		}
}


/******************************************************************************
*%%%% SetLiveEntityScaleColours
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetLiveEntityScaleColours(
*						LIVE_ENTITY*	live_entity,
*						MR_LONG			r,
*						MR_LONG			g,
*						MR_LONG			b)
*
*	FUNCTION	Set the mi_colour_scale of all mesh instances of a LIVE_ENTITY.
*				If LIVE_ENTITY_RESPECT_SCALE_COLOURS is set, we use the inputs
*				as multipliers
*
*	INPUTS		live_entity	-	ptr to LIVE_ENTITY to set
*				r			-	colour r
*				g			-	colour g
*				b			-	colour b
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	SetLiveEntityScaleColours(	LIVE_ENTITY*	live_entity,
									MR_LONG			r,
									MR_LONG			g,
									MR_LONG			b)
{
	MR_LONG				i, rgb;
	MR_ANIM_ENV_INST**	anim_env_inst_pptr;
	MR_MESH_INST**		mesh_inst_pptr;
	MR_MESH_INST*		mesh_inst_ptr;


	MR_ASSERT(live_entity);

	rgb = (b << 16) + (g << 8) + r;

	// Is this an animated MOF ?
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		anim_env_inst_pptr 	= (MR_ANIM_ENV_INST**)live_entity->le_api_insts;
		i 					= Game_total_viewports;
		while(i--)
			{
			// Get pointer to mesh instance
			mesh_inst_ptr = (*anim_env_inst_pptr)->ae_mesh_insts[0];

			// temp fix $mk
			if (!mesh_inst_ptr)
				break;
			// end of temp fix $mk

			// Set mesh instance base colour
			mesh_inst_ptr->mi_light_flags |= MR_INST_USE_SCALED_COLOURS;
			if (live_entity->le_flags & LIVE_ENTITY_RESPECT_SCALE_COLOURS)
				{
				mesh_inst_ptr->mi_colour_scale.r = (mesh_inst_ptr->mi_colour_scale.r * r) >> 7;
				mesh_inst_ptr->mi_colour_scale.g = (mesh_inst_ptr->mi_colour_scale.g * g) >> 7;
				mesh_inst_ptr->mi_colour_scale.b = (mesh_inst_ptr->mi_colour_scale.b * b) >> 7;
				}
			else
				MR_SET32(mesh_inst_ptr->mi_colour_scale, rgb);
					
			// Move through pointer list
			anim_env_inst_pptr++;
			}
		}
	else
		{
		// Loop once for each viewport
		mesh_inst_pptr 	= (MR_MESH_INST**)live_entity->le_api_insts;
		i 				= Game_total_viewports;
		while(i--)
			{
			mesh_inst_ptr = *mesh_inst_pptr;

			// temp fix $mk
			if (!mesh_inst_ptr)
				break;
			// end of temp fix $mk

			// Set mesh instance base colour
			mesh_inst_ptr->mi_light_flags |= MR_INST_USE_SCALED_COLOURS;
			if (live_entity->le_flags & LIVE_ENTITY_RESPECT_SCALE_COLOURS)
				{
				mesh_inst_ptr->mi_colour_scale.r = (mesh_inst_ptr->mi_colour_scale.r * r) >> 7;
				mesh_inst_ptr->mi_colour_scale.g = (mesh_inst_ptr->mi_colour_scale.g * g) >> 7;
				mesh_inst_ptr->mi_colour_scale.b = (mesh_inst_ptr->mi_colour_scale.b * b) >> 7;
				}
			else
				MR_SET32(mesh_inst_ptr->mi_colour_scale, rgb);

			// Move through pointer list
			mesh_inst_pptr++;
			}
		}
}


/******************************************************************************
*%%%% SetLiveEntityCustomAmbient
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetLiveEntityCustomAmbient(
*						LIVE_ENTITY*	live_entity,
*						MR_LONG			r,
*						MR_LONG			g,
*						MR_LONG			b)
*
*	FUNCTION	Set the mi_custom_ambient of all mesh instances of a LIVE_ENTITY.
*				If LIVE_ENTITY_RESPECT_AMBIENT_COLOURS is set, we use the inputs
*				as multipliers
*
*	INPUTS		live_entity	-	ptr to LIVE_ENTITY to set
*				r			-	colour r
*				g			-	colour g
*				b			-	colour b
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	SetLiveEntityCustomAmbient(	LIVE_ENTITY*	live_entity,
									MR_LONG			r,
									MR_LONG			g,
									MR_LONG			b)
{
	MR_LONG				i, rgb;
	MR_ANIM_ENV_INST**	anim_env_inst_pptr;
	MR_MESH_INST**		mesh_inst_pptr;
	MR_MESH_INST*		mesh_inst_ptr;


	MR_ASSERT(live_entity);

	rgb = (b << 16) + (g << 8) + r;

	// Is this an animated MOF ?
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		anim_env_inst_pptr 	= (MR_ANIM_ENV_INST**)live_entity->le_api_insts;
		i 					= Game_total_viewports;
		while(i--)
			{
			// Get pointer to mesh instance
			mesh_inst_ptr = (*anim_env_inst_pptr)->ae_mesh_insts[0];

			// temp fix $mk
			if (!mesh_inst_ptr)
				break;
			// end of temp fix $mk

			// Set mesh instance base colour
			mesh_inst_ptr->mi_light_flags |= MR_INST_USE_CUSTOM_AMBIENT;
			if (live_entity->le_flags & LIVE_ENTITY_RESPECT_AMBIENT_COLOURS)
				{
				mesh_inst_ptr->mi_custom_ambient.r = (mesh_inst_ptr->mi_custom_ambient.r * r) >> 7;
				mesh_inst_ptr->mi_custom_ambient.g = (mesh_inst_ptr->mi_custom_ambient.g * g) >> 7;
				mesh_inst_ptr->mi_custom_ambient.b = (mesh_inst_ptr->mi_custom_ambient.b * b) >> 7;
				}
			else
				MR_SET32(mesh_inst_ptr->mi_custom_ambient, rgb);
					
			// Move through pointer list
			anim_env_inst_pptr++;
			}
		}
	else
		{
		// Loop once for each viewport
		mesh_inst_pptr 	= (MR_MESH_INST**)live_entity->le_api_insts;
		i 				= Game_total_viewports;
		while(i--)
			{
			mesh_inst_ptr = *mesh_inst_pptr;

			// temp fix $mk
			if (!mesh_inst_ptr)
				break;
			// end of temp fix $mk

			// Set mesh instance base colour
			mesh_inst_ptr->mi_light_flags |= MR_INST_USE_CUSTOM_AMBIENT;
			if (live_entity->le_flags & LIVE_ENTITY_RESPECT_AMBIENT_COLOURS)
				{
				mesh_inst_ptr->mi_custom_ambient.r = (mesh_inst_ptr->mi_custom_ambient.r * r) >> 7;
				mesh_inst_ptr->mi_custom_ambient.g = (mesh_inst_ptr->mi_custom_ambient.g * g) >> 7;
				mesh_inst_ptr->mi_custom_ambient.b = (mesh_inst_ptr->mi_custom_ambient.b * b) >> 7;
				}
			else
				MR_SET32(mesh_inst_ptr->mi_custom_ambient, rgb);

			// Move through pointer list
			mesh_inst_pptr++;
			}
		}
}


/******************************************************************************
*%%%% CreateLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG CreateLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function creates special effects at the points denoted by
*				hilites of the correct type
*
*	INPUTS		live_entity			-	ptr to live entity to create special effect for
*
*	NOTES		An ENTITY_SPECIAL_TYPE_ANIM currently results in MRGetMemStats crashing ?
*				I'm not sure why!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID CreateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{
 	// Locals
	MR_ULONG		num_effects;						// Number of effects we have created for this model
	MR_ULONG		loop_counter;						// Temp loop count
	MR_ULONG		loop_counter_2;						// Temp loop count
	ENTITY_SPECIAL*	special_ptr;						// Pointer to special effects
	ENTITY_SPECIAL	specials[MAX_NUM_SPECIAL_EFFECTS];	// Temp store for special effects
	MR_ULONG		i;									// Temp while count
	MR_FRAME*		frame_ptr;							// Temp pointer to frame used to create sprites etc
	MR_SVEC			rot;								// Initial rotation
	MR_MOF*			mof_ptr;
	MR_ANIM_HEADER*	anim_header_ptr;						   
	MR_PART*		part_ptr;
	MR_HILITE*		hilite_ptr;
	MR_USHORT		num_static_mofs;
	MR_MOF*			mesh_ptr;
	MR_ANIM_HEADER*	anim_ptr;
	MR_ANIM_ENV*	anim_env_ptr;

//	MR_ULONG*		sprite_ptrs;
//	MR_OBJECT*		sprite_object_ptrs[FROG_MAX_NUM_3D_SPRITES];
//	MR_SVEC* 		sprite_position_ptrs[FROG_MAX_NUM_3D_SPRITES];
//	MR_SVEC			temp_svec;
//	MR_ULONG		sprite_parts[FROG_MAX_NUM_3D_SPRITES];

	// Initialise
	i = 0;
	num_effects = 0;
	MR_CLEAR_SVEC(&rot);

	// Get pointer to mof, and form
	mof_ptr = Map_mof_ptrs[ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_mof_id];

	// Does this entity have a model? Obviously if it doesn't, then we should ignore it
	if (!(ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL))
		{
		// Is MOF animated ?
		if ( MR_MOF_ANIMATED == ( mof_ptr->mm_flags & MR_MOF_ANIMATED ) )
			{
			// Yes ... get pointer to anim header
			anim_header_ptr = (MR_ANIM_HEADER*)mof_ptr;

			// Get number of static mofs
			num_static_mofs = anim_header_ptr->ah_no_of_static_files;

			// Assert if more than one static mof ( currently not coded for more than 1 )!!!
			MR_ASSERT(num_static_mofs == 1);

			// Get pointer to mof
			mof_ptr = *anim_header_ptr->ah_static_files;

			// Store pointer to anim env
			anim_env_ptr = (MR_ANIM_ENV*)live_entity->le_api_item0;
			}
		else
			{
			// No ... clear pointer to anim env
			anim_env_ptr = NULL;
			}

		// Get pointer to first part
		part_ptr = (MR_PART*)(mof_ptr + 1);

		// Loop once for each part of mof
		for(loop_counter_2=0;loop_counter_2<mof_ptr->mm_extra;loop_counter_2++)
			{

			// Get hilite info
			i = part_ptr->mp_hilites;
			hilite_ptr = part_ptr->mp_hilite_ptr;

			// Are there any highlights ?
			if ( i )
				{

				// Yes ... loop once for each highlight
				while ( i-- )
					{

					// Assert if too many effects attempted to be allocated!!!
					MR_ASSERT(num_effects != MAX_NUM_SPECIAL_EFFECTS);

					// According to hilite type do ...
					switch ( hilite_ptr->mh_type )
						{

						// Reserved ...
						case HILITE_TYPE_COLLISION:
							break;

						// 3D sprite ...
						case HILITE_TYPE_3DSPRITE_SPLASH:
						case HILITE_TYPE_3DSPRITE_WAKE:

							// Set hilite type
							specials[num_effects].es_type = ENTITY_SPECIAL_TYPE_SPRITE;

							// Store part number
							specials[num_effects].es_part_index = loop_counter_2;

							// Store pointer to MR_SVEC
							specials[num_effects].es_vertex = (MR_SVEC*)hilite_ptr->mh_target_ptr;

							// Store pointer to anim env we are attached to
							specials[num_effects].es_anim_env_ptr = anim_env_ptr;

							// Create a frame
							frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);

							// Create a 3D sprite for this highlight
							if ( hilite_ptr->mh_type == HILITE_TYPE_3DSPRITE_SPLASH )
								(MR_OBJECT*)specials[num_effects].es_api_item = MRCreate3DSprite(frame_ptr,0,&Splash_display_list);
							else
								(MR_OBJECT*)specials[num_effects].es_api_item = MRCreate3DSprite(frame_ptr,0,&Wake_display_list);

							// Add object to viewport(s)
							for (loop_counter=0;loop_counter<Game_total_viewports;loop_counter++)
								specials[num_effects].es_api_insts[loop_counter] = MRAddObjectToViewport((MR_OBJECT*)specials[num_effects].es_api_item,Game_viewports[loop_counter],0);

							// Inc number of effects
							num_effects++;

							break;

	//					// Splash ...
	//					case FROG_HILITE_SPLASH:
	//						// Yes ... assert if too many sprites attempted to be allocated!!!
	//						MR_ASSERT(num_effects != FROG_MAX_NUM_3D_SPRITES);
	//
	//						// Create a frame
	//						frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);
	//
	//						// Create a 3D sprite for this highlight
	//						sprite_object_ptrs[num_effects] = MRCreate3DSprite(frame_ptr,0,&gulSplashDisplayList);
	//
	//						// Add object to viewport
	//						MRAddObjectToViewport(sprite_object_ptrs[num_effects],Game_viewport0,0);
	//
	//						// Store part number
	//						sprite_parts[num_effects] = loop_counter_2;
	//
	//						// Store pointer to MR_SVEC
	//						sprite_position_ptrs[num_effects] = (MR_SVEC*)hilite_ptr->mh_target_ptr;
	//
	//						// Apply object orientation to sprite position
	//						MRApplyMatrixSVEC(live_entity->le_lwtrans,sprite_position_ptrs[num_effects],&temp_svec);
	//
	//						// Re-orient sprite ( to be flat ) and apply entities orientation
	//						rot.vx = 3072;
	//						rot.vy = 0;
	//						rot.vz = 0;
	//						MRRotMatrix(&rot,&frame_ptr->fr_matrix);
	//						MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);
	//
	//						// Add on entity position to sprite position and store sprite position
	//						frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
	//						frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
	//						frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];
	//
	//						// Inc number of sprites allocated
	//						num_effects++;
	//
	//						break;
	//					
	//					// Wake ...
	//					case FROG_HILITE_WAKE:
	//						// Yes ... assert if too many sprites attempted to be allocated!!!
	//						MR_ASSERT(num_effects != FROG_MAX_NUM_3D_SPRITES);
	//
	//						// Create a frame
	//						frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);
	//
	//						// Create a 3D sprite for this highlight
	//						sprite_object_ptrs[num_effects] = MRCreate3DSprite(frame_ptr,0,&gulWakeDisplayList);
	//
	//						// Add object to viewport
	//						MRAddObjectToViewport(sprite_object_ptrs[num_effects],Game_viewport0,0);
	//
	//						// Store part number
	//						sprite_parts[num_effects] = loop_counter_2;
	//
	//						// Store pointer to MR_VEC
	//						sprite_position_ptrs[num_effects] = (MR_SVEC*)hilite_ptr->mh_target_ptr;
	//
	//						// Apply object orientation to sprite position
	//						MRApplyMatrixSVEC(live_entity->le_lwtrans,sprite_position_ptrs[num_effects],&temp_svec);
	//
	//						// Re-orient sprite ( to be flat ) and apply entities orientation
	//						rot.vx = 3072;
	//						rot.vy = 0;
	//						rot.vz = 0;
	//						MRRotMatrix(&rot,&frame_ptr->fr_matrix);
	//						MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);
	//
	//						// Add on entity position to sprite position and store sprite position
	//						frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
	//						frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
	//						frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];
	//
	//						// Inc number of sprites allocated
	//						num_effects++;
	//
	//						break;

						// Particle fountain ...
						case HILITE_TYPE_PARTICLE_EXHAUST:
						case HILITE_TYPE_PARTICLE_CLOUD:

							// Set hilite type
							specials[num_effects].es_type = ENTITY_SPECIAL_TYPE_PARTICLE;

							// Store part number
							specials[num_effects].es_part_index = loop_counter_2;

							// Store pointer to MR_SVEC
							specials[num_effects].es_vertex = (MR_SVEC*)hilite_ptr->mh_target_ptr;

							// Store pointer to anim env we are attached to
							specials[num_effects].es_anim_env_ptr = anim_env_ptr;

							// Create a frame
							frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);

							// Create particle generator
							(MR_OBJECT*)specials[num_effects].es_api_item = MRCreatePgen(&Fountain_definition,frame_ptr,NULL,NULL);

							// Add object to viewport(s)
							for (loop_counter=0;loop_counter<Game_total_viewports;loop_counter++)
								specials[num_effects].es_api_insts[loop_counter] = MRAddObjectToViewport((MR_OBJECT*)specials[num_effects].es_api_item,Game_viewports[loop_counter],0);

							// Inc number of effects
							num_effects++;

							break;

						// Mesh ...
						case HILITE_TYPE_MESH:

							// Set hilite type
							specials[num_effects].es_type = ENTITY_SPECIAL_TYPE_MESH;

							// Store part number
							specials[num_effects].es_part_index = loop_counter_2;

							// Store pointer to MR_SVEC
							specials[num_effects].es_vertex = (MR_SVEC*)hilite_ptr->mh_target_ptr;

							// Store pointer to anim env we are attached to
							specials[num_effects].es_anim_env_ptr = anim_env_ptr;

							// Create a frame
							frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);

							// Get address of mesh in memory
							mesh_ptr = MR_GET_RESOURCE_ADDR(Static_mesh_specials_resource_id[0]);

							// Assert if mesh currently not in memory
							MR_ASSERT(mesh_ptr!=NULL);

							// Create static mesh
							(MR_OBJECT*)specials[num_effects].es_api_item = MRCreateMesh(mesh_ptr,frame_ptr,0,NULL);

							// Add object to viewport(s)
							for (loop_counter=0;loop_counter<Game_total_viewports;loop_counter++)
								specials[num_effects].es_api_insts[loop_counter] = MRAddObjectToViewport((MR_OBJECT*)specials[num_effects].es_api_item,Game_viewports[loop_counter],0);

							// Inc number of effects
							num_effects++;

							break;

						// Animated mesh ...
						case HILITE_TYPE_ANIM:

							// Set hilite type
							specials[num_effects].es_type = ENTITY_SPECIAL_TYPE_ANIM;

							// Store part number
							specials[num_effects].es_part_index = loop_counter_2;

							// Store pointer to MR_SVEC
							specials[num_effects].es_vertex = (MR_SVEC*)hilite_ptr->mh_target_ptr;

							// Store pointer to anim env we are attached to
							specials[num_effects].es_anim_env_ptr = anim_env_ptr;

							// Create a frame
							frame_ptr = MRCreateFrame((MR_VEC*)&live_entity->le_lwtrans->t,&rot,NULL);

							// Get address of anim in memory
							anim_ptr = MR_GET_RESOURCE_ADDR(Anim_mesh_specials_resource_id[0]);

							// Assert if anim currently not in memory
							MR_ASSERT(anim_ptr!=NULL);

							// Create anim
							(MR_ANIM_ENV*)specials[num_effects].es_api_item = MRAnimEnvSingleCreateWhole(anim_ptr,0,0,frame_ptr);

							// Add object to viewport(s)
							for (loop_counter=0;loop_counter<Game_total_viewports;loop_counter++)
								specials[num_effects].es_api_insts[loop_counter] = MRAnimAddEnvToViewport((MR_ANIM_ENV*)specials[num_effects].es_api_item,Game_viewports[loop_counter],0);

							// Inc number of effects
							num_effects++;

							break;

						// Other ...
						default :

							// Assert if we encounter an unknown type of hilite!
							MR_ASSERT(0);

							break;

						}

					// Inc hilite pointer
					hilite_ptr++;

					};
				}
			// Next part
			part_ptr++;
			}

		// Did we allocate any effects ?
		if ( num_effects )
			{
			// Yes ... allocate chunk of memory equal to number of effects
			live_entity->le_numspecials = num_effects;
			live_entity->le_specials = MRAllocMem(sizeof(ENTITY_SPECIAL)*num_effects,"ENTITY SPECIALS");

			// Set up temp pointer
			special_ptr = live_entity->le_specials;

			// Loop once for each effect we allocated
			for(loop_counter=0;loop_counter<num_effects;loop_counter++)
				{
				// Copy special data
				memcpy(special_ptr,&specials[loop_counter],sizeof(ENTITY_SPECIAL));

				// Inc pointer
				special_ptr++;
				}
			}
		else
			{
			// No ... blank entity data
			live_entity->le_numspecials = 0;
			live_entity->le_specials = NULL;
			}

		if ( anim_env_ptr )
			{
			MRAnimEnvSingleSetAction(anim_env_ptr, 0);
			MRAnimEnvSingleSetCel(anim_env_ptr,0);
			}
		}
	else
		{
		// Blank entity data
		live_entity->le_numspecials = 0;
		live_entity->le_specials = NULL;
		}
}
			
/******************************************************************************
*%%%% UpdateLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function updates the special effects
*
*	INPUTS		live_entity			-	ptr to live entity to update special effects for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID UpdateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY_SPECIAL*	special_ptr;		// Ptr to entity specials
	MR_ULONG		i;					// While count
	MR_SVEC			temp_svec;			// Temp svec
	MR_FRAME*		frame_ptr;			// Ptr to API frame
	MR_SVEC			rot;				// Rotation
	MR_ULONG		part_num;			// Number of part special attached to
	MR_ANIM_ENV*	anim_env_ptr;		// Ptr to anim env we are attached to

	// Are there any effects for this entity ?
	if (live_entity->le_numspecials)
		{
		// Yes ... get pointer to effects data
		special_ptr = live_entity->le_specials;

		// Get number of effects
		i = live_entity->le_numspecials;

		// Loop once for each effect
		while ( i-- )
			{
			// According to type of effect do ...
			switch(special_ptr->es_type)
				{
				// 3D sprite ...
				case ENTITY_SPECIAL_TYPE_SPRITE:

					// Get anim env pointer
					anim_env_ptr = (MR_ANIM_ENV*)special_ptr->es_anim_env_ptr;

					// Get number of part
					part_num = (MR_ULONG)special_ptr->es_part_index;

					// Get pointer to sprite frame
					frame_ptr = ((MR_OBJECT*)special_ptr->es_api_item)->ob_frame;

					// Initialise temp svec ( offset of sprite from entity base point )
					MR_COPY_SVEC(&temp_svec,special_ptr->es_vertex);

					// Apply entities orientation to sprite position
					MRApplyMatrixSVEC(live_entity->le_lwtrans,&temp_svec,&temp_svec);

					// Re-orient sprite ( to be flat ) and apply entities orientation
					rot.vx = 3072;
					rot.vy = 0;
					rot.vz = 0;
					MRRotMatrix(&rot,&frame_ptr->fr_matrix);
					MRMulMatrixABB(live_entity->le_lwtrans,&frame_ptr->fr_matrix);

					// Add on entities position to sprites position
					frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
					frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
					frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];

					// Is there a valid anim env pointer ( ie are we attached to an animated model ) ?
//					if ( anim_env_ptr )
//						{
//						// Get part's transform matrix
//						MRAnimEnvGetPartTransform(anim_env_ptr,&mat,0,part_num);
//						MRApplyMatrixVEC(live_entity->le_lwtrans,(MR_VEC*)&mat.t,(MR_VEC*)&mat.t);
//						// Apply translation to sprite
//						MR_ADD_VEC(&frame_ptr->fr_matrix.t[0],&mat.t[0]);
//						}

					break;

				// Particle generator ...
				case ENTITY_SPECIAL_TYPE_PARTICLE:

					// Get pointer to mesh frame
					frame_ptr = ((MR_OBJECT*)special_ptr->es_api_item)->ob_frame;

					// Initialise temp svec ( offset of mesh from entity base point )
					MR_COPY_SVEC(&temp_svec,special_ptr->es_vertex);

					// Apply entities orientation to mesh position
					MRApplyMatrixSVEC(live_entity->le_lwtrans,&temp_svec,&temp_svec);

					// Set orientation of mesh to that of entity
					MR_COPY_MAT(&frame_ptr->fr_matrix.m,live_entity->le_lwtrans);

					// Add on entities position to mesh position
					frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
					frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
					frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];

					break;

				// Mesh ...
				case ENTITY_SPECIAL_TYPE_MESH:

					// Get pointer to mesh frame
					frame_ptr = ((MR_OBJECT*)special_ptr->es_api_item)->ob_frame;

					// Initialise temp svec ( offset of mesh from entity base point )
					MR_COPY_SVEC(&temp_svec,special_ptr->es_vertex);

					// Apply entities orientation to mesh position
					MRApplyMatrixSVEC(live_entity->le_lwtrans,&temp_svec,&temp_svec);

					// Set orientation of mesh to that of entity
					MR_COPY_MAT(&frame_ptr->fr_matrix.m,live_entity->le_lwtrans);

					// Add on entities position to mesh position
					frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
					frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
					frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];

					break;

				// Animating mesh ...
				case ENTITY_SPECIAL_TYPE_ANIM:

					// Get pointer to anim frame
					frame_ptr = ((MR_OBJECT*)special_ptr->es_api_item)->ob_frame;

					// Initialise temp svec ( offset of anim from entity base point )
					MR_COPY_SVEC(&temp_svec,special_ptr->es_vertex);

					// Apply entities orientation to anim position
					MRApplyMatrixSVEC(live_entity->le_lwtrans,&temp_svec,&temp_svec);

					// Set orientation of anim to that of entity
					MR_COPY_MAT(&frame_ptr->fr_matrix.m,live_entity->le_lwtrans);

					// Add on entities position to anim position
					frame_ptr->fr_matrix.t[0] = temp_svec.vx + live_entity->le_lwtrans->t[0];
					frame_ptr->fr_matrix.t[1] = temp_svec.vy + live_entity->le_lwtrans->t[1];
					frame_ptr->fr_matrix.t[2] = temp_svec.vz + live_entity->le_lwtrans->t[2];

					break;

				// Unkown type ...
				default:

					// Assert if we have encountered an unknown special type
					MR_ASSERT(0);

					break;
				}

			// Next effect
			special_ptr++;

			};
		}

}

/******************************************************************************
*%%%% KillLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID KillLiveEntitySpecials(	
*										LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function kills any special effects allocated by CreateLiveEntitySpecialEffects
*
*	INPUTS		live_entity			-	ptr to live entity that had special effects created for it
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*
*%%%**************************************************************************/

MR_VOID KillLiveEntitySpecials(LIVE_ENTITY* live_entity)
{

	// Locals
	ENTITY_SPECIAL*	special_ptr;
	MR_ULONG		i;

	// Are there any effects for this entity ?
	if ( live_entity->le_numspecials )
		{ 

		// Yes ... get pointer to sprite object ptrs
		special_ptr = live_entity->le_specials;

		// Get number of effects
		i = live_entity->le_numspecials;

		// Loop once for each effect
		while ( i-- )
			{

			// According to type of effect do ...
			switch ( special_ptr->es_type )
				{

				// 3D Sprites ...
				case ENTITY_SPECIAL_TYPE_SPRITE:
					// Kill sprite
					((MR_OBJECT*)special_ptr->es_api_item)->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
					break;

				// Particle generator ...
				case ENTITY_SPECIAL_TYPE_PARTICLE:
					// Kill particle generator
					MRShutdownPgen((MR_OBJECT*)special_ptr->es_api_item);
					break;

				// Mesh ...
				case ENTITY_SPECIAL_TYPE_MESH:
					// Kill static mesh
					((MR_OBJECT*)special_ptr->es_api_item)->ob_flags |= MR_OBJ_NO_DISPLAY | MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
					break;

				// Animated mesh ...
				case ENTITY_SPECIAL_TYPE_ANIM:
					// Kill anim
					MRAnimEnvDestroyByDisplay((MR_ANIM_ENV*)special_ptr->es_api_item);
					break;

				}

			// Next effect
			special_ptr++;

			};

		// Free memory we grabbed during the create
		MRFreeMem(live_entity->le_specials);

		// Invalidate pointer and number
		live_entity->le_specials = NULL;
		live_entity->le_numspecials = 0;

		}

}


/******************************************************************************
*%%%% EntityLinkToMapGroup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID*	map_group =	EntityLinkToMapGroup(
*										ENTITY*	entity,
*										MR_VEC*	pos)
*
*	FUNCTION	Find which MAP_GROUP an entity projects over, and link it
*				in
*
*	INPUTS		entity		-	to link
*				pos			-	world pos of entity
*
*	RESULT		map_group	-	MAP_GROUP we linked in to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID*	EntityLinkToMapGroup(	ENTITY*	entity,
									MR_VEC*	pos)
{
	MAP_GROUP*	map_group;
	MR_LONG		x, z;


	x = (pos->vx - Map_view_basepoint.vx) / Map_view_xlen;
	z = (pos->vz - Map_view_basepoint.vz) / Map_view_zlen;

//	MR_ASSERT(x >= 0);
//	MR_ASSERT(x < Map_view_xnum);
//	MR_ASSERT(z >= 0);
//	MR_ASSERT(z < Map_view_znum);

	if(x < 0)
		x = 0;
	if(x >= Map_view_xnum)
		x = Map_view_xnum-1;

	if(z < 0)
		z = 0;
	if(z >= Map_view_znum)
		z = Map_view_znum-1;


	map_group = &Map_groups[(z * Map_view_xnum) + x];

	// Link into list
	if (entity->en_next = map_group->mg_entity_root_ptr->en_next)
		entity->en_next->en_prev = entity;

	map_group->mg_entity_root_ptr->en_next = entity;
	entity->en_prev = map_group->mg_entity_root_ptr;

	return(map_group);
}


/******************************************************************************
*%%%% UnlinkEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UnlinkEntities(MR_VOID)
*
*	FUNCTION	Run through all map entities, unlinking them from MAP_GROUPs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UnlinkEntities(MR_VOID)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	ENTITY_BOOK*	entity_book;
	MR_ULONG		i;


	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;

	while(i--)
		{
		entity		= *entity_pptr;
		entity_book	= ENTITY_GET_ENTITY_BOOK(entity);

		if (!(entity_book->eb_flags & ENTITY_BOOK_STATIC))
			{
			if (entity->en_prev)
				{
				// Entity is not STATIC, and is linked in
				entity->en_prev->en_next 		= entity->en_next;
				if (entity->en_next)
					entity->en_next->en_prev 	= entity->en_prev;
				entity->en_prev					= NULL;
				entity->en_next					= NULL;
				}
			}
		entity_pptr++;
		}
}


/******************************************************************************
*%%%% LinkEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LinkEntities(MR_VOID)
*
*	FUNCTION	Run through all map entities, linking them to MAP_GROUPs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	LinkEntities(MR_VOID)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	ENTITY_BOOK*	entity_book;
	MR_ULONG		i;


	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;

	while(i--)
		{
		entity		= *entity_pptr;
		entity_book	= ENTITY_GET_ENTITY_BOOK(entity);

		if 	(
			(!(entity_book->eb_flags & ENTITY_BOOK_STATIC)) &&
			(!(entity->en_flags & ENTITY_HIDDEN))
			)
			{
			// Assert ENTITY not already linked
			MR_ASSERT(entity->en_prev == NULL);

			// Now either entity has a PATH_RUNNER, or is IMMORTAL (else we don't know its position)
			if (entity->en_path_runner)
				{
				EntityLinkToMapGroup(entity, (MR_VEC*)&entity->en_path_runner->pr_position);
				}
			else
				{
				MR_ASSERT(entity_book->eb_flags & ENTITY_BOOK_IMMORTAL);
				MR_ASSERT(entity->en_live_entity);

				EntityLinkToMapGroup(entity, (MR_VEC*)&entity->en_live_entity->le_lwtrans->t);
				}
			}
		entity_pptr++;
		}
}


/******************************************************************************
*%%%% ResetEntities
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetEntities(MR_VOID)
*
*	FUNCTION	Runs through all map entities, resetting them (this is called
*				on game restart) if they are IMMORTAL. This is because they 
*				may have deviated from their initial positions.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.05.97	Martin Kift		Created
*	30.05.97	Martin Kift		Recoded to work better.
*
*%%%**************************************************************************/

MR_VOID ResetEntities(MR_VOID)
{
	ENTITY_BOOK*		entity_book;
	ENTITY*				entity;
	ENTITY**			entity_pptr;
	MR_ULONG			i, ofs;
	FORM_BOOK*			form_book;

	// Reset path runners
	ResetPathRunners();

	// Resolve entity offsets to ptrs
	ofs			= (MR_ULONG)Map_header;
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		*entity_pptr 	= (ENTITY*)(*entity_pptr);
		entity			= *entity_pptr;
		entity_book		= ENTITY_GET_ENTITY_BOOK(entity);
		form_book		= ENTITY_GET_FORM_BOOK(entity);

		// Is there a live entity.
		if (entity->en_live_entity)
			{
			// Check to see how the game is resetting, and whether the entity flag
			// excludes resetting this entity in this type of reset.
//			if (Game_reset_flags & GAME_RESET_CHECKPOINT_COLLECTED)
//				{
//				if (!(form_book->fb_flags & FORM_BOOK_NO_RESET_ON_CHECKPOINT))
//					{
//					// Kill off live entity
//					KillLiveEntity(entity->en_live_entity);
//					}
//				}
//			else 
//			if (Game_reset_flags & GAME_RESET_FROGS_DEAD)
//				{
//				if (!(form_book->fb_flags & FORM_BOOK_NO_RESET_ON_FROG_DEATH))
//					{
//					// Kill off live entity
//					KillLiveEntity(entity->en_live_entity);
//					}
//				}
//			else
				// Kill off live entity
				KillLiveEntity(entity->en_live_entity);
			}

		entity_pptr++;
		}


	// Reloop back through list, creating IMMORTAL entities
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		*entity_pptr 	= (ENTITY*)(*entity_pptr);
		entity			= *entity_pptr;
		entity_book		= ENTITY_GET_ENTITY_BOOK(entity);

		// If immortal, create live entity, but not if already created.
		if (!entity->en_live_entity)
			{
			if (entity_book->eb_flags & ENTITY_BOOK_IMMORTAL)
				CreateLiveEntity(entity);
			}
		entity_pptr++;
		}
}

/******************************************************************************
*%%%% DistanceToFrogger
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	DistanceToFrogger(LIVE_ENTITY* live_entity,
*										  MR_BYTE	axis_adjust,
*										  MR_LONG	axis_offset)
*
*	FUNCTION	Calculates the distance between the live_entity and Frogger.
*				Uses the center of the entity as the source point, unless you 
*				specify axis_adjust & offset.
*				axis_adjust allows you to move the source point in any ONE of
*				the three axis. (ENTSCR_COORD_X, Y Z)
*				axis_offset is the distance you wish to move the source point by.
*
*	INPUTS		live_entity	-	Entity you wish to find the distance to.
*				axis_adjust	-	Axis you wish to move the point to which you check.
*				axis_offset - 	Distance to move the point by. (In world units)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_LONG	DistanceToFrogger(LIVE_ENTITY* live_entity, MR_BYTE axis_adjust, MR_LONG axis_offset)
{
	FROG*		frog;
	MR_USHORT	frog_index;
	MR_LONG		closest_distance;
	MR_SVEC		svec;
	MR_SVEC		svec_offset;

	// search for all 4 possible frogs
	frog_index			= 0;
	closest_distance	= 9999999;

	while (frog_index < 4)
		{
		frog = &Frogs[frog_index++];

		// is frog active?
		if (frog->fr_flags & FROG_ACTIVE)
			{
			svec_offset.vx = 0;
			svec_offset.vy = 0;
			svec_offset.vz = 0;

			// Adjust the position of the entity collision point.
			switch(axis_adjust)
				{
				//-------------------------------------------------------------------
				case ENTSCR_COORD_X:
					svec_offset.vx = axis_offset;
					break;
				//-------------------------------------------------------------------
				case ENTSCR_COORD_Y:
					svec_offset.vy = axis_offset;
					break;
				//-------------------------------------------------------------------
				case ENTSCR_COORD_Z:
					svec_offset.vz = axis_offset;
					break;
				//-------------------------------------------------------------------
				}

			MRApplyMatrixSVEC(live_entity->le_lwtrans, (MR_SVEC*)&svec_offset.vx, (MR_SVEC*)&svec_offset.vx);
			svec_offset.vx += live_entity->le_lwtrans->t[0];
			svec_offset.vy += live_entity->le_lwtrans->t[1];
			svec_offset.vz += live_entity->le_lwtrans->t[2];

			svec.vx = frog->fr_lwtrans->t[0] - svec_offset.vx;
			svec.vy = frog->fr_lwtrans->t[1] - svec_offset.vy;
			svec.vz = frog->fr_lwtrans->t[2] - svec_offset.vz;

			closest_distance = MIN(closest_distance, MR_SVEC_MOD(&svec));
			}
		}

	return closest_distance;
}


/******************************************************************************
*%%%% ENTSTRCreateTrigger
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateTrigger(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a trigger entity
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateTrigger(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	ENTSTR_TRIGGER*		trigger;
	ENTSTR_RT_TRIGGER*	rt_trigger;

	// create entity
	ENTSTRCreateStationaryMOF(live_entity);

	entity		= live_entity->le_entity;
	trigger		= (ENTSTR_TRIGGER*)(entity+1);
	rt_trigger	= (ENTSTR_RT_TRIGGER*)live_entity->le_specific;

	// Set up frame count
	rt_trigger->et_frame_count = 0;
	rt_trigger->et_first_time  = TRUE;							// So we know it's the first time though.
}

/******************************************************************************
*%%%% ENTSTRUpdateTrigger
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRUpdateTrigger(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a trigger entity
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Martin Kift		Created
*	26.06.97	Gary Richards	Reset ALL path runners to no movement when the level
*								starts or Frogger dies.
*
*	NOTE: This may have to change as it will currently override any entities in
*	the triggers list that wishes to start UNPAUSED.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRUpdateTrigger(LIVE_ENTITY* live_entity)
{
	ENTITY*				entity;
	ENTSTR_TRIGGER*		trigger;
	ENTSTR_RT_TRIGGER*	rt_trigger;
	LIVE_ENTITY*		trigger_live_entity;
	MR_ULONG			count;

	entity		= live_entity->le_entity;
	trigger		= (ENTSTR_TRIGGER*)(entity+1);
	rt_trigger	= (ENTSTR_RT_TRIGGER*)live_entity->le_specific;

	// This routine constantly dec's the hit frame count to zero...
	if (rt_trigger->et_frame_count > 0)
		rt_trigger->et_frame_count--;

	// Check to see if this is the first time through this function.
	if (rt_trigger->et_first_time == TRUE)
		{
		// Set ALL entities in the list to be PAUSED.
		for (count=0; count<ENTITY_TYPE_TRIGGER_MAX_IDS; count++)
			{
			// is ID valid?
			if (trigger->et_unique_ids[count] != -1)
				{
				// find entity with unique id
				trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->et_unique_ids[count]);
				//	This has to wait for about 3 - 5 frames before all the entities are created.
				if ( trigger_live_entity != NULL )
					{
					// Flag it as no movement.
					trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
					// If entity is path based, PAUSE it.
					if (trigger_live_entity->le_entity->en_path_runner)
						trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
					}
				}
			}
		rt_trigger->et_first_time = FALSE;
		}
}

/******************************************************************************
*%%%% TriggerEntityCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID TriggerEntityCallback(	
*								MR_VOID*		frog,
*								MR_VOID*		live_entity,
*								MR_VOID*		coll_check)
*
*	FUNCTION	This is the callback for all trigger entities, which deals
*				(via a switch/case) all types of trigger entities, such as PAUSE
*				etc.
*
*	INPUTS		frog		-	ptr to frog (VOID* for convenience on prototype)
*				live_entity	-	ptr to live entity that was collide with
*				coll_check		-	ptr to coll check structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.05.97	Martin Kift		Created
*	30.05.97	Martin Kift		Changed params to MR_VOID*'s
*
*%%%**************************************************************************/

MR_VOID TriggerEntityCallback(	MR_VOID*	void_frog,
								MR_VOID*	void_live_entity,
								MR_VOID*	void_coll_check)
{
	ENTITY*				entity;
	ENTSTR_TRIGGER*		trigger;
	ENTSTR_RT_TRIGGER*	rt_trigger;
	MR_LONG				count;
	LIVE_ENTITY*		trigger_live_entity;
	FROG*				frog;
	LIVE_ENTITY*		live_entity;
	MR_COLLCHECK*		coll_check;

	frog		= (FROG*)void_frog;
	live_entity	= (LIVE_ENTITY*)void_live_entity;
	coll_check	= (MR_COLLCHECK*)void_coll_check;
	entity		= live_entity->le_entity;
	trigger		= (ENTSTR_TRIGGER*)(entity+1);
	rt_trigger	= (ENTSTR_RT_TRIGGER*)live_entity->le_specific;

	// Only process a hit if the frame hit count is zero, which stops multiple processes as
	// the frog sits on top of this entity
	if (!rt_trigger->et_frame_count)
		{
		// switch/case on the trigger type
		switch (trigger->et_type)
			{
			case ENTITY_TYPE_TRIGGER_FREEZE:
				// Unpause all entity in the list
				for (count=0; count<ENTITY_TYPE_TRIGGER_MAX_IDS; count++)
					{
					// is ID valid?
					if (trigger->et_unique_ids[count] != -1)
						{
						// find entity with unique id
						trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->et_unique_ids[count]);
						MR_ASSERTMSG (trigger_live_entity != NULL, "Entity start trigger with invalid unique id");

						// reverse no-movement flag
						if (trigger_live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
							{
							trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
							// If entity is path based, set path based flag to start it
							if (trigger_live_entity->le_entity->en_path_runner)
								trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
							}
						else
							{
							trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
							// If entity is path based, set path based flag to start it
							if (trigger_live_entity->le_entity->en_path_runner)
								trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
							}
						}
					}
				break;

			case ENTITY_TYPE_TRIGGER_REVERSE:
				// reverse all entity in the list
				for (count=0; count<ENTITY_TYPE_TRIGGER_MAX_IDS; count++)
					{
					// is ID valid?
					if (trigger->et_unique_ids[count] != -1)
						{
						// find entity with unique id
						trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->et_unique_ids[count]);
						MR_ASSERTMSG (trigger_live_entity != NULL, "Entity reverse trigger with invalid unique id");

						// Check that entity is PATH based
						MR_ASSERTMSG (trigger_live_entity->le_entity->en_path_runner, "Entity reverse trigger speced for non path based entity");

						// reverse movement flag...
						if (trigger_live_entity->le_entity->en_path_runner->pr_flags & PATH_RUNNER_BACKWARDS)
							trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_BACKWARDS;
						else
							trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_BACKWARDS;
						}
					}

				break;

			case ENTITY_TYPE_TRIGGER_START:
				// Unpause all entity in the list
				for (count=0; count<ENTITY_TYPE_TRIGGER_MAX_IDS; count++)
					{
					// is ID valid?
					if (trigger->et_unique_ids[count] != -1)
						{
						// find entity with unique id
						trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->et_unique_ids[count]);
						MR_ASSERTMSG (trigger_live_entity != NULL, "Entity start trigger with invalid unique id");

						// reverse no-movement flag
						if (trigger_live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
							{
							trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
							// If entity is path based, set path based flag to start it
							if (trigger_live_entity->le_entity->en_path_runner)
								trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
							}
						else
							{
							trigger_live_entity->le_entity->en_flags |= ENTITY_NO_MOVEMENT;
							// If entity is path based, set path based flag to start it
							if (trigger_live_entity->le_entity->en_path_runner)
								trigger_live_entity->le_entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
							}
						}
					}
				break;
			}
		}

	// Set hit count to some small number to stop multiple hits
	rt_trigger->et_frame_count	= 3;
}

/******************************************************************************
*%%%% InitPrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID InitPrims(	
*								 MR_PGEN_INST* pGen_inst)
*
*	FUNCTION	This function initialises primitives for the particle fountain used
*				in the attachment system
*
*	INPUTS		pGen_inst		-	ptr to particle generator instance
*
*	NOTES		Based on Julian Rex's water code ( 03.03.97 ) for the original Frogger.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.03.97	Julian Rex		Created
*	24.06.97	William Bell	Recreated for new frogger attachment system
*
*%%%**************************************************************************/

MR_VOID InitPrims(MR_PGEN_INST* pGen_inst)
{

	// Locals
	MR_PGEN*			pGen		= pGen_inst->pi_object->ob_extra.ob_extra_pgen;
	MR_LONG				lPrim_count = pGen->pg_max_particles * 2;
	POLY_FT4*			pPoly		= (POLY_FT4*)pGen_inst->pi_particle_prims[0];
	MR_TEXTURE*			pTexture	= (MR_TEXTURE*)pGen->pg_user_data_1;

	// Loop once for each poly
	while(lPrim_count)
		{

#ifdef WIN95
		// Initialise texture uv's
		setTexture4(pPoly, pTexture);

		// Set poly base colour
//		setCVEC(pPoly, 0x80, 0x80, 0x80, 0);
		MR_SET32(pPoly->r0, 0x808080);
#else
		// Initialise texture uv's
		MR_COPY32(pPoly->u0, pTexture->te_u0);
		MR_COPY32(pPoly->u1, pTexture->te_u1);
		MR_COPY16(pPoly->u2, pTexture->te_u2);
		MR_COPY16(pPoly->u3, pTexture->te_u3);

		// Initialise poly base colour ( overwriting poly code )
		MR_SET32(pPoly->r0, 0x808080);
#endif

		// Set poly codes
		setPolyFT4(pPoly);
		setSemiTrans(pPoly, 1);

		// Next poly
		pPoly++;
		lPrim_count--;

		}

}

/******************************************************************************
*%%%% UpdateGenerator
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateGenerator(
*								 MR_OBJECT* pbubble_gen)
*
*	FUNCTION	This function updates the particle generator.  Creating new particles
*				at random intervals and updating the position of current particles.
*
*	INPUTS		pbubble_gen		-	ptr to particle generator object
*
*	NOTES		Based on Julian Rex's water code ( 03.03.97 ) for the original Frogger.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.03.97	Julian Rex		Created
*	24.06.97	William Bell	Recreated for new frogger attachment system
*
*%%%**************************************************************************/

MR_VOID UpdateGenerator(MR_OBJECT* pbubble_gen)
{	

	// Locals
	MR_PGEN*			pgen = pbubble_gen->ob_extra.ob_extra_pgen;			// Ptr to particle generator
	MR_PTYPE_2D_GEOM*	pbubble;											// Ptr to particle
	MR_SHORT			wcount;												// Number of particles

	// Is the generator inactive?
	if(pgen->pg_flags & MR_PF_INACTIVE)
		// No ... return
		return;

	// Generate a new particle ?
	if(!(rand() & 15))
		// Yes ... create a new particle
		CreateParticle(pbubble_gen);

	// Flag generator has having no active particles	
	pgen->pg_flags |= MR_PF_NO_ACTIVE_PARTS;

	// Get pointer to first particle and number of particles
	pbubble		= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;
	wcount		= pgen->pg_max_particles;

	// Loop once for each particle
	while(wcount--)
	{

		// Is particle alive ?
		if ( pbubble->pt_lifetime )
			{
			// Yes ... dec life of particle
			pbubble->pt_lifetime--;

			// Flag generator as having a live particle
			pgen->pg_flags &= ~MR_PF_NO_ACTIVE_PARTS;

			// Update position of particle
			pbubble->pt_position.vx += 0;
			pbubble->pt_position.vy += pgen->pg_gravity;
			pbubble->pt_position.vz += 0;

			}

		// Next particle
		pbubble++;

	}

	// Does generator have a finite life ?
	if (pgen->pg_generator_life > 0)
	{
		// Yes ... is it at end of life ?
		if (!(--pgen->pg_generator_life))
		{
			// Yes ...
			// Generator run out of life - put it into a state where it will kill itself (by
			// flagging the object as MR_OBJ_DESTROY_BY_DISPLAY) only when all associated particles
			// are no longer active
			pgen->pg_flags |= MR_PF_CLOSING_DOWN;
		}
	}

}

/******************************************************************************
*%%%% CreateParticle
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID CreateParticle(
*								 MR_OBJECT* bubble_gen)
*
*	FUNCTION	This function creates new particles for the generator.
*
*	INPUTS		bubble_gen		-	ptr to particle generator object
*
*	NOTES		Based on Julian Rex's water code ( 03.03.97 ) for the original Frogger.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.03.97	Julian Rex		Created
*	24.06.97	William Bell	Recreated for new frogger attachment system
*
*%%%**************************************************************************/

MR_VOID CreateParticle(MR_OBJECT* bubble_gen)
{

	// Locals
	MR_PGEN				*pgen		= bubble_gen->ob_extra.ob_extra_pgen;	// Ptr to particle generator
	MR_PTYPE_2D_GEOM	*pbubble;											// Ptr to particle
	MR_MAT				*powner_mat = &bubble_gen->ob_frame->fr_matrix;		// Ptr to frame

	// Is generator dying ?
	if (!pgen->pg_generator_life || (pgen->pg_flags & MR_PF_CLOSING_DOWN) )
		// Yes ... leave
		return;

	// next please!
	if(++pgen->pg_next_particle >=  pgen->pg_max_particles)
		pgen->pg_next_particle = 0;

	// Get pointer to particle
	pbubble = &((MR_PTYPE_2D_GEOM*)pgen->pg_particle_info)[pgen->pg_next_particle];

	// Is this particle still alive ?
	if ( pbubble->pt_lifetime )
		// Yes ... leave
		return;
	
	// Initialise particle life
	pbubble->pt_lifetime = (MR_ULONG)10;

	// Initialise start position of particle
	pbubble->pt_position.vx = (powner_mat->t[0] + pgen->pg_offset.vx)<<16;		// add offset to mouth!
	pbubble->pt_position.vy = (powner_mat->t[1] + pgen->pg_offset.vy)<<16;
	pbubble->pt_position.vz = (powner_mat->t[2] + pgen->pg_offset.vz)<<16;

}

/******************************************************************************
*%%%% DisplayPrims
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID DisplayPrims(
*								 MR_PGEN_INST* pGen_inst,MR_VIEWPORT* viewport_ptr)
*
*	FUNCTION	This function displays primitives for the particle fountain used
*				in the attachment system
*
*	INPUTS		pGen_inst		-	ptr to particle generator instance
*
*				viewport_ptr	-	ptr to viewport to display particles in
*
*	NOTES		Based on Julian Rex's water code ( 03.03.97 ) for the original Frogger.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.03.97	Julian Rex		Created
*	24.06.97	William Bell	Recreated for new frogger attachment system
*
*%%%**************************************************************************/

MR_VOID DisplayPrims(MR_PGEN_INST* pgen_inst, MR_VIEWPORT* viewport_ptr)
{

	// Locals
	MR_PGEN*			pgen = pgen_inst->pi_object->ob_extra.ob_extra_pgen;
	MR_PTYPE_2D_GEOM*	particle;
	MR_LONG				lprim_count;
	MR_SVEC				svec, coords[4];
	POLY_FT4*			ppoly;
//	MR_TEXTURE*			ptexture;
	MR_LONG				lpolyz, lotz;
//	MR_LONG				lxcalc, lycalc;
//	MR_LONG				lxofs, lyofs;
//	MR_SVEC				sxy;
	MR_LONG				lscale;

	// Is generator active ?
	if( pgen->pg_flags & (MR_PF_INACTIVE|MR_PF_NO_ACTIVE_PARTS) )
		// No ... return
		return;

	// Initialise ( number of primitives, pointer to first particle )
	lprim_count	= pgen->pg_max_particles;
	particle	= (MR_PTYPE_2D_GEOM*)pgen->pg_particle_info;

	// Set up the projection / transformation data
	gte_SetRotMatrix(&viewport_ptr->vp_render_matrix);
	svec.vx	= -(MR_SHORT)viewport_ptr->vp_camera->fr_lw_transform.t[0];
	svec.vy	= -(MR_SHORT)viewport_ptr->vp_camera->fr_lw_transform.t[1];
	svec.vz	= -(MR_SHORT)viewport_ptr->vp_camera->fr_lw_transform.t[2];
	MRApplyRotMatrix(&svec, (MR_VEC*)&MRViewtrans_ptr->t);
	gte_SetTransMatrix(MRViewtrans_ptr);

	// Get pointer to prims buffer
	ppoly	= (POLY_FT4*)pgen_inst->pi_particle_prims[MRFrame_index]; 

	// Loop once for each particle
	while(lprim_count)
		{


		// Is this particle alive ?
		if( (MR_LONG)particle->pt_lifetime > 0 )
			{
			// Yes ... 

			// Calculate size of prim ( world size )
			lscale = /*pextra->fpg_sp_core.sc_scale*/256;

			// Calculate point positions
			coords[0].vx = coords[2].vx = (particle->pt_position.vx>>16) - lscale;
			coords[1].vx = coords[3].vx = (particle->pt_position.vx>>16) + lscale;
			coords[0].vz = coords[1].vz = (particle->pt_position.vz>>16) - lscale;
			coords[2].vz = coords[3].vz = (particle->pt_position.vz>>16) + lscale;
			coords[0].vy = coords[1].vy = coords[2].vy = coords[3].vy = (particle->pt_position.vy>>16);

			// Load vertices and rotate
			gte_ldv3(&coords[0], &coords[1], &coords[2]);
			gte_rtpt();
		
			// Store position of rotated points
			gte_stsxy0((MR_LONG*)&ppoly->x0);
			gte_stsxy1((MR_LONG*)&ppoly->x1);
			gte_stsxy2((MR_LONG*)&ppoly->x2);

			// Load last point and rotate
			gte_ldv0(&coords[3]);
			gte_rtps();

			// Average last 4 z positions and store
			gte_avsz4();
			gte_stsz(&lpolyz);

			// Calculate OT position
			lotz = lpolyz >> MRVp_otz_shift;

			// Store position of rotated point
			gte_stsxy2((MR_LONG*)&ppoly->x3);

			// Is OT position valid ?
			if( (lotz < MRVp_ot_size) && (lotz > 0) )
				{
				// Yes ... add prim to OT
				addPrim(MRVp_work_ot + lotz, ppoly);
				}

			}

		// Next poly, next particle, dec count
		ppoly++;
		particle++;
		lprim_count--;
		}
}


/******************************************************************************
*%%%% HideAllEntitiesExcept
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HideAllEntitiesExcept(
*						MR_LONG	unique_id)
*
*	FUNCTION	Run through map ENTITY array, setting all entities as
*				ENTITY_HIDDEN, except one with the specified unique_id
*
*	INPUTS		unique_id	-	unique id of ENTITY to remain
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	HideAllEntitiesExcept(MR_LONG	unique_id)
{
#ifdef DEBUG
	ENTITY**	entity_pptr;
	ENTITY*		entity;
	MR_ULONG	i;

 
	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		entity = *entity_pptr;
		if (entity->en_unique_id != unique_id)
			entity->en_flags |= ENTITY_HIDDEN;
			
		entity_pptr++;
		}	
#endif
}

/******************************************************************************
*%%%% LiveEntitySetAction
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID LiveEntitySetAction(
*										LIVE_ENTITY*	live_entity,
*										MR_ULONG		action_number)
*
*	FUNCTION	This function sets an action for the requested live_entity.
*				In debug mode it checks that the live entity is in fact an
*				animated entity, plus is it animated type independent.
*
*	INPUTS		live_entity		- ptr to live_entity
*				action_number	- action number
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID LiveEntitySetAction(	LIVE_ENTITY*	live_entity, 
								MR_ULONG		action_number)
{
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, action_number);
	else
		MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, action_number);
}

/******************************************************************************
*%%%% LiveEntityCreateAnimationEnvironment
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID LiveEntityCreateAnimationEnvironment(
*								LIVE_ENTITY*	live_entity,
*								MOF*			mof)
*
*	FUNCTION	This function sets up an animation environment for the supplied
*				live_entity. This function is of course animation type 
*				independent.
*
*	INPUTS		live_entity		- ptr to live entity
*
*	RETURNS		Ptr to animation environment created by this function.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_ANIM_ENV* LiveEntityCreateAnimationEnvironment(	LIVE_ENTITY*	live_entity,
													MR_MOF*			mof)
{
	MR_ASSERT (mof);

	if (mof->mm_flags & MR_MOF_FLIPBOOK)
		{
		live_entity->le_flags |= (LIVE_ENTITY_FLIPBOOK|LIVE_ENTITY_ANIMATED);
		return MRAnimEnvFlipbookCreateWhole(mof, MR_OBJ_STATIC, (MR_FRAME*)(live_entity->le_lwtrans));
		}
	else
		{
		live_entity->le_flags |= (LIVE_ENTITY_ANIMATED);
		return MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)mof, 0, MR_OBJ_STATIC, (MR_FRAME*)(live_entity->le_lwtrans));
		}
}


/******************************************************************************
*%%%% LiveEntityCheckAnimationFinished
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID LiveEntityCheckAnimationFinished(
*								LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function checks for the final cel for an animation. This 
*				function is of course animation type independent.
*
*	INPUTS		live_entity		- ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL LiveEntityCheckAnimationFinished(LIVE_ENTITY*	live_entity)
{
	MR_ANIM_ENV_FLIPBOOK*	env_flipbook;
	MR_ANIM_ENV_SINGLE*		env_single;

	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)												
		{			
		env_flipbook = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook;
		if (env_flipbook->ae_cel_number >= env_flipbook->ae_total_cels-1)
			return TRUE;
		}
	else
		{
		env_single = ((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_single;
		if (env_single->ae_cel_number >= env_single->ae_total_cels-1)
			return TRUE;
		}
	return FALSE;
}
