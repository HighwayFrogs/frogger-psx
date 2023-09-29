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
*	07.07.97	Gary Richards	Added ENTSTRCreateMovingSprite,
*								Added ENTSTRCreateSprite,
*	08.07.97	Gary Richards	Changed FadeLiveEntity to include Sprites.
*	17.07.97	Tim Closs		Added support for ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
*	15.08.97	Gary Richards	Added LiveEntityChangeVolume to return the voice of any moving 
*								sounds attached to the entity.
*	21.08.97	Martin Kift		Added popping code for live entities
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
#include "particle.h"
#include "sound.h"
#include "ent_gen.h"
#include "camera.h"
#include "tempopt.h"

LIVE_ENTITY		Live_entity_root;
LIVE_ENTITY*	Live_entity_root_ptr;


MR_ULONG		Static_mesh_specials_resource_id[]=
	{
	0,
	};

MR_ULONG		Anim_mesh_specials_resource_id[]=
	{
	0,
	};

MR_ULONG*		Entity_special_sprite_animlists[] =
	{
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	};

MR_PGEN_INIT*	Entity_special_particle_generators[] =
	{
	NULL,
	NULL,
	NULL,
	&PGIN_hilite_exhaust,
	&PGIN_hilite_exhaust,
	&PGIN_hilite_dust,
	&PGIN_hilite_fire,
	NULL,
	NULL,
	};

// This is hideous, putting this here, but we haven't got time for niceties
MR_ULONG	Animlist_fire_fly[] =
	{
	MR_SPRT_SETSPEED,	2,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_fire_fly,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_fire_flya,
	MR_SPRT_LOOPBACK,
	NULL
	};

// Positions for fading entities at edge of map
MR_SVEC			Fade_top_left_pos;
MR_SVEC			Fade_bottom_right_pos;

#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
MR_TEXT_AREA*	Entity_unique_id_text_areas[ENTITY_MAX_UNIQUE_ID_TEXT_AREAS];
MR_LONG	 		Entity_unique_id;
MR_STRPTR 		Entity_unique_id_text[] = {"%jc%w", (MR_STRPTR)&Entity_unique_id, (MR_STRPTR)6, NULL};
#endif

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
*	17.07.97	Tim Closs		Added support for ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
*
*%%%**************************************************************************/

MR_VOID	InitialiseLiveEntities(MR_VOID)
{
#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
	MR_TEXT_AREA*	text_area;
	MR_TEXT_AREA**	text_area_pptr;
	MR_LONG			i;


	text_area_pptr 	= Entity_unique_id_text_areas;
	i 				= ENTITY_MAX_UNIQUE_ID_TEXT_AREAS;
	while(i--)
		{
		text_area 				= MRAllocateTextArea(NULL, &debug_font, Game_viewport0, 6, 0, 0, 40, 8);
		text_area->ta_display	= FALSE;
		*text_area_pptr 		= text_area;
		text_area_pptr++;
		}	
#endif	

	// Initialise list
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
	live_entity->le_effect			= NULL;

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

	// Create all required 3D sprites
	CreateLiveEntitySpecials(live_entity);

	// $wb - Set up fade colours when live entity 
 	// Fade entity if off map/outside cave light, and we are allowed too
	// Fade live entity cannot be called on the caves map at this point cos the frog hasn't
	// been created, so for the time being, i'll simply not call it on caves maps
	if (Game_map_theme != THEME_CAV)
		{
		if (!(live_entity->le_flags & LIVE_ENTITY_NO_SCREEN_FADE))
			FadeLiveEntity(live_entity);
		}

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

	// Free pop memory if any, just in case
	LiveEntityFreePop(live_entity);

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
*	17.07.97	Tim Closs		Added support for ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
*
*%%%**************************************************************************/

MR_VOID	KillAllLiveEntities(MR_VOID)
{
#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
	MR_TEXT_AREA**	text_area_pptr;
	MR_LONG			i;


	text_area_pptr 	= Entity_unique_id_text_areas;
	i 				= ENTITY_MAX_UNIQUE_ID_TEXT_AREAS;
	while(i--)
		{
		MRFreeTextArea(*text_area_pptr);
		text_area_pptr++;
		}	
#endif	

	// Kill all live entities
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
	LIVE_ENTITY*		live_entity;
	ENTITY_BOOK*		entity_book;

#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
	MR_TEXT_AREA*		text_area;
	MR_TEXT_AREA**		text_area_pptr;
	MR_SVEC				svec;


	text_area_pptr 	= Entity_unique_id_text_areas;
#endif

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

		 	// Fade entity if off map/outside cave light, and we are allowed too
			if (!(live_entity->le_flags & LIVE_ENTITY_NO_SCREEN_FADE))
				FadeLiveEntity(live_entity);

			// Update live entity specials!!!
			UpdateLiveEntitySpecials(live_entity);
	
			// If this entity has an effect variable, its popping, or popped...
			if (live_entity->le_effect)
				LiveEntityUpdatePolyPiecePop(live_entity);

			// Clear various flags.  Note that LIVE_ENTITY_CARRIES_FROG_? will be set in UpdateFrogs()
			live_entity->le_flags &= ~LIVE_ENTITY_CLEAR_MASK;

#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
			if (text_area_pptr < (Entity_unique_id_text_areas + ENTITY_MAX_UNIQUE_ID_TEXT_AREAS))
				{
				text_area 				= *text_area_pptr;
				text_area->ta_display	= TRUE;
				text_area_pptr++;
	
				// Build unique id text
				Entity_unique_id		= live_entity->le_entity->en_unique_id;
				MRBuildText(text_area, Entity_unique_id_text, MR_FONT_COLOUR_RED);
	
				// Calculate screen coords of text area
				MRMulMatrixABC(&Game_viewport0->vp_render_matrix, live_entity->le_lwtrans, MRViewtrans_ptr);
				svec.vx = live_entity->le_lwtrans->t[0] - Game_viewport0->vp_render_matrix.t[0];
				svec.vy = live_entity->le_lwtrans->t[1] - Game_viewport0->vp_render_matrix.t[1];
				svec.vz = live_entity->le_lwtrans->t[2] - Game_viewport0->vp_render_matrix.t[2];
				MRApplyMatrix(&Game_viewport0->vp_render_matrix, &svec, (MR_VEC*)MRViewtrans_ptr->t);
				gte_SetRotMatrix(MRViewtrans_ptr);
				gte_SetTransMatrix(MRViewtrans_ptr);
				gte_ldv0(&Null_svector);
				gte_rtps();
				gte_stsxy0((MR_LONG*)&text_area->ta_xofs);
				text_area->ta_xofs -= 20;
				text_area->ta_yofs -=  4;
				}
#endif
			}
		}
#ifdef ENTITY_DEBUG_DISPLAY_UNIQUE_IDS
	while(text_area_pptr < (Entity_unique_id_text_areas + ENTITY_MAX_UNIQUE_ID_TEXT_AREAS))
		{
		(*text_area_pptr)->ta_display = FALSE;
		text_area_pptr++;
		}
#endif
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

	// Moved after the matrix pointer has been set.
	if (ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL)
		return;

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

	if (ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL)
		return;

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
	
	if (ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL)
		return;

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
*	02.07.97	Tim Closs		Respects ENTITY_PROJECT_ON_LAND flag
*	18.08.97	Martin Kift		Fixed LOCAL_ALIGN code (which I wrote) to work 
*								better on certain alignments, beware the bodge.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRUpdateMovingMOF(LIVE_ENTITY*	live_entity)
{
	ENTITY*		entity;
	MR_VEC		vec_x;
	MR_VEC		vec_y;
	MR_VEC		vec_z;
	GRID_INFO	grid_info;
	MR_LONG		dx, dy, dz;
	MR_MAT*		cam_matrix;


 	entity		= live_entity->le_entity;
	cam_matrix 	= Cameras[0].ca_matrix;

	// We assume the entity already has a PATH_RUNNER
	MR_ASSERT(entity->en_path_runner);
		
	// Set up live entity position and rotation from PATH_RUNNER
	MR_COPY_VEC((MR_VEC*)live_entity->le_lwtrans->t, &entity->en_path_runner->pr_position);

	if (!(entity->en_flags & ENTITY_ALIGN_TO_WORLD))
		{
		if (entity->en_flags & ENTITY_PROJECT_ON_LAND)
			{
			// Project path runner position/tangent onto grid square
			GetGridInfoFromWorldXZ(live_entity->le_lwtrans->t[0], live_entity->le_lwtrans->t[2], &grid_info);
			live_entity->le_lwtrans->t[1] = grid_info.gi_y;
			dx = MR_VEC_DOT_VEC(&grid_info.gi_xslope, &entity->en_path_runner->pr_tangent) >> 12;
			dz = MR_VEC_DOT_VEC(&grid_info.gi_zslope, &entity->en_path_runner->pr_tangent) >> 12;

			vec_z.vx = ((grid_info.gi_xslope.vx * dx) + (grid_info.gi_zslope.vx * dz)) >> 12;
			vec_z.vy = ((grid_info.gi_xslope.vy * dx) + (grid_info.gi_zslope.vy * dz)) >> 12;
			vec_z.vz = ((grid_info.gi_xslope.vz * dx) + (grid_info.gi_zslope.vz * dz)) >> 12;
			}
		else
			{
			MR_COPY_VEC(&vec_z, &entity->en_path_runner->pr_tangent);
			}

		// Generate matrix from local Z and some roll vector
		if (!(entity->en_flags & ENTITY_LOCAL_ALIGN))
			{
			// No local alignment
			if (ENTITY_GET_ENTITY_BOOK(entity)->eb_flags & ENTITY_BOOK_XZ_PARALLEL_TO_CAMERA)
				{
				// Use live_entity local Z axis.  Create local XY plane parallel to camera XY plane (use camera 0)
				dx = ((vec_z.vx * cam_matrix->m[0][0]) + (vec_z.vy * cam_matrix->m[1][0]) + (vec_z.vz * cam_matrix->m[2][0])) >> 12;
				dy = ((vec_z.vx * cam_matrix->m[0][1]) + (vec_z.vy * cam_matrix->m[1][1]) + (vec_z.vz * cam_matrix->m[2][1])) >> 12;
				
				vec_y.vx = -((dx * cam_matrix->m[0][0]) + (dy * cam_matrix->m[0][1])) >> 12;
				vec_y.vy = -((dx * cam_matrix->m[1][0]) + (dy * cam_matrix->m[1][1])) >> 12;
				vec_y.vz = -((dx * cam_matrix->m[2][0]) + (dy * cam_matrix->m[2][1])) >> 12;

				// Projected live_entity local Z onto camera XY.  This becomes local Y axis.
				// Now use camera Z axis as entity Y
				vec_z.vx = cam_matrix->m[0][2];
				vec_z.vy = cam_matrix->m[1][2];
				vec_z.vz = cam_matrix->m[2][2];
				MROuterProduct12(&vec_y, &vec_z, &vec_x);
				WriteAxesAsMatrix(live_entity->le_lwtrans, &vec_x, &vec_y, &vec_z);
				return;
				}
			else
				MROuterProduct12(&Game_y_axis_pos, &vec_z, &vec_x);
			}
		else
			{
			// Local alignment
			MR_SET_VEC(&vec_y,	live_entity->le_lwtrans->m[0][1],
								live_entity->le_lwtrans->m[1][1],
								live_entity->le_lwtrans->m[2][1]);
			
			if (abs(live_entity->le_lwtrans->m[2][0]) > 0x800)
				{
				MR_COPY_VEC(&vec_x, &Game_z_axis_pos);
				}
			else
				{
				MR_COPY_VEC(&vec_x, &Game_x_axis_pos);
				}
			}

		MRNormaliseVEC(&vec_x, &vec_x);
		MROuterProduct12(&vec_z, &vec_x, &vec_y);
		WriteAxesAsMatrix(live_entity->le_lwtrans, &vec_x, &vec_y, &vec_z);
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
	
			// Set cel to zero... stops code baffing first time through
			MRAnimEnvSingleSetCel((MR_ANIM_ENV*)live_entity->le_api_item0, 0);

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

#ifdef ENTITY_DEBUG_PLOT_STATIC_BBOX	
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_PART_BBOX;
#endif
#ifdef ENTITY_DEBUG_PLOT_COLLPRIMS
				((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_DEBUG_DISPLAY_COLLPRIMS;
#endif
				// Set a default animation action of zero, default behaviour so to speak
				MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, 0);

				// Set cel to zero... stops code baffing first time through
				MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)live_entity->le_api_item0, 0);

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
				
			// Have to add to the viewport (but with MR_OBJ_NO_DISPLAY of course) so that they can
			// be cleaned up properly.... maybe.
			GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);
			live_entity->le_flags &= ~LIVE_ENTITY_ANIMATED;
			}
		}
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
		entity	= *entity_pptr;

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
*	08.07.97	Gary Richards	Changed to include Sprites.
*
*%%%**************************************************************************/

MR_VOID FadeLiveEntity(LIVE_ENTITY* live_entity)
{
	MR_ULONG	x_dist;
	MR_ULONG	z_dist;
	MR_LONG		col;
	MR_LONG		dist;
	MR_LONG		fall;
	
	if (!(live_entity->le_entity->en_flags & ENTITY_NO_DISPLAY))
		{
		if (!(Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT))
			{
			x_dist = 0;
			z_dist = 0;
			
			// Calculate distance from map edges
			if (live_entity->le_lwtrans->t[0] < Fade_top_left_pos.vx)
				x_dist = Fade_top_left_pos.vx - live_entity->le_lwtrans->t[0];
			else 
			if (live_entity->le_lwtrans->t[0] > (Fade_bottom_right_pos.vx ) )
				x_dist = live_entity->le_lwtrans->t[0] - Fade_bottom_right_pos.vx;
			
			// Is z off bottom map edge ?
			if ( live_entity->le_lwtrans->t[2] < /*Grid_base_z*/Fade_bottom_right_pos.vz )
				z_dist = /*Grid_base_z*/Fade_bottom_right_pos.vz - live_entity->le_lwtrans->t[2];
			else if ( live_entity->le_lwtrans->t[2] > ( /*Grid_base_z + ( Grid_zlen * Grid_znum )*/Fade_top_left_pos.vz ) )
				z_dist = live_entity->le_lwtrans->t[2] - ( /*Grid_base_z + ( Grid_zlen * Grid_znum )*/Fade_top_left_pos.vz );

			// Calculate colour value according to distance
			col = (x_dist + z_dist) >> ENTITY_BASE_COLOUR_FADE_SHIFT;
			col	= MAX(0, 0x80 - col);															
			}
		else
			{
			// Calculate distance
			x_dist = MR_SQR(Frogs[0].fr_lwtrans->t[0] - live_entity->le_lwtrans->t[0]);
			z_dist = MR_SQR(Frogs[0].fr_lwtrans->t[2] - live_entity->le_lwtrans->t[2]);
			col = x_dist + z_dist;

			// Is light within min ?
			if ( col <= Map_light_min_r2 )
				{
				// Yes ... set colour to max
				col = 0x80;
				}
			// Is light greater than max ?
			else if ( col >= Map_light_max_r2 )
				{
				// Yes ... set colour to min
				col = 0x00;
				}
			// Within fall off
			else
				{
				// Get dist in fade off area
				col = col - Map_light_min_r2;
				// Get width of fall off area
				dist = Map_light_max_r2-Map_light_min_r2;
				// Calculate fall off per unit in fade off area
				fall = (0x80<<16) / dist;
				// Calculate colour at point
				col = (col * fall)>>16;
				// Calculate colour
				col	= MAX(0, 0x80 - col);
				}

			}
		
		SetLiveEntityScaleColours(live_entity, col, col, col);
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
*	08.07.97	Gary Richards	Changed to include Sprites.
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
		
	MR_OBJECT*			object_ptr;
	MR_3DSPRITE*		sprite_ptr;
	MR_SP_CORE*			core_ptr;
	FORM_BOOK*			form_book;
	MR_LONG				red,green,blue;
		
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
		if ((ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL))
			{
			// Must be a Sprite..... Check we want the scaling.
			form_book = ENTITY_GET_FORM_BOOK(live_entity->le_entity);
			if ( !(form_book->fb_flags & FORM_BOOK_FLAG_NO_COLOUR_FADE) &&
				 !(live_entity->le_flags & LIVE_ENTITY_NO_COLOUR_FADE) )
				{
				object_ptr = (MR_OBJECT*)live_entity->le_api_item0;
				sprite_ptr	= object_ptr->ob_extra.ob_extra_3dsprite;
				core_ptr	= &sprite_ptr->sp_core;
				// Because the flies are above the ground, we need to adjust the light to account for this.
				if ( (red = r << 2) > 128)
					red = 128;
				if ( (green = g << 2) > 128)
					green = 128;
				if ( (blue = b << 2) > 128)
					blue = 128;

				core_ptr->sc_base_colour.r = red;
				core_ptr->sc_base_colour.g = green;
				core_ptr->sc_base_colour.b = blue;
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
*	SYNOPSIS	MR_ULONG 	CreateLiveEntitySpecials(	
*							LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function creates special effects at the points denoted by
*				hilites of the correct type
*
*	INPUTS		live_entity		-	ptr to live entity to create special effect for
*
*	NOTES		An ENTITY_SPECIAL_TYPE_ANIM currently results in MRGetMemStats crashing ?
*				I'm not sure why!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*	11.07.97	Tim Closs		Finished off for Beta
*
*%%%**************************************************************************/

MR_VOID CreateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{
	MR_LONG			i, h;
	ENTITY_SPECIAL*	entity_special;
	MR_MOF*			mof_ptr;
	MR_MOF*			static_mof_ptr;
	MR_PART*		part_ptr;
	MR_HILITE*		hilite_ptr;


	live_entity->le_specials 	= NULL;
	live_entity->le_numspecials = 0;

	// Get pointer to mof, and form
	mof_ptr = Map_mof_ptrs[ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_mof_id];

	// Does this entity have a model? Obviously if it doesn't, then we should ignore it
	if (!(ENTITY_GET_FORM_BOOK(live_entity->le_entity)->fb_flags & FORM_BOOK_FLAG_NO_MODEL))
		{
		// Is MOF animated ?
		if (mof_ptr->mm_flags & MR_MOF_ANIMATED)
			static_mof_ptr = ((MR_ANIM_HEADER*)mof_ptr)->ah_static_files[0];
		else
			static_mof_ptr = mof_ptr;

		// Count MR_HILITEs in MOF
		h			= 0;
		i			= static_mof_ptr->mm_extra;
		part_ptr 	= (MR_PART*)(static_mof_ptr + 1);
		while(i--)
			{
			h += part_ptr->mp_hilites;
			part_ptr++;
			}

		if (h)
			{
			// Allocate space for h ENTITY_SPECIAL structures
			live_entity->le_numspecials = h;
			live_entity->le_specials 	= MRAllocMem(sizeof(ENTITY_SPECIAL) * h, "ENTITY SPECIALS");
			
			// Set up each ENTITY_SPECIAL
			entity_special 	= live_entity->le_specials;
			part_ptr 		= (MR_PART*)(static_mof_ptr + 1);
	
			// Loop through each MR_PART
			for (i = 0; i < static_mof_ptr->mm_extra; i++)
				{
				hilite_ptr 	= part_ptr->mp_hilite_ptr;
				h			= part_ptr->mp_hilites;
	
				// Loop through each MR_HILITE
				while(h--)
					{
					switch (hilite_ptr->mh_type)
						{
						//-------------------------------------------------------------------
						// Reserved
						case HILITE_TYPE_COLLISION:
							break;
						//-------------------------------------------------------------------
						// 3D sprite
						case HILITE_TYPE_3DSPRITE_SPLASH:
						case HILITE_TYPE_3DSPRITE_WAKE:
							entity_special->es_type 		= ENTITY_SPECIAL_TYPE_SPRITE;
							entity_special->es_part_index 	= i;
							entity_special->es_vertex 		= (MR_SVEC*)hilite_ptr->mh_target_ptr;
							entity_special->es_entity		= live_entity->le_entity;

							// Create MR_OBJECT
							entity_special->es_api_item 	= MRCreate3DSprite(	(MR_FRAME*)&entity_special->es_lwtrans,
																				MR_OBJ_STATIC,
																				Entity_special_sprite_animlists[hilite_ptr->mh_type]);
							// Add object to viewport(s)
							GameAddObjectToViewportsStoreInstances(entity_special->es_api_item, (MR_MESH_INST**)entity_special->es_api_insts);
							break;
						//-------------------------------------------------------------------
						// Particle generator
						case HILITE_TYPE_PARTICLE_EXHAUST:
						case HILITE_TYPE_PARTICLE_CLOUD:
						case HILITE_TYPE_PARTICLE_SMOKE:
						case HILITE_TYPE_PARTICLE_FIRE:
							entity_special->es_type 		= ENTITY_SPECIAL_TYPE_PARTICLE;
							entity_special->es_part_index 	= i;
							entity_special->es_vertex 		= (MR_SVEC*)hilite_ptr->mh_target_ptr;
							entity_special->es_entity		= live_entity->le_entity;
	
							// Create MR_OBJECT
							entity_special->es_api_item 	= MRCreatePgen(	Entity_special_particle_generators[hilite_ptr->mh_type],
																			NULL,
																		  	MR_OBJ_STATIC,
																			entity_special->es_vertex);

							// Store ENTITY_SPECIAL* as owner of particle generator
							((MR_OBJECT*)entity_special->es_api_item)->ob_extra.ob_extra_pgen->pg_owner = entity_special;

							// Add object to viewport(s)
							GameAddObjectToViewportsStoreInstances(entity_special->es_api_item, (MR_MESH_INST**)entity_special->es_api_insts);
							break;
						//-------------------------------------------------------------------
						default:
							MR_ASSERTMSG(NULL, "Entity MOF unrecognised hilite type");
							break;
						//-------------------------------------------------------------------
						}
	
					entity_special->es_mof_ptr = mof_ptr;
					entity_special++;

					hilite_ptr++;
					}
				part_ptr++;
				}
			}
		}
}
			

/******************************************************************************
*%%%% UpdateLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID UpdateLiveEntitySpecials(	
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function updates the special effects
*
*	INPUTS		live_entity		-	ptr to live entity to update special effects for
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*	11.07.97	Tim Closs		Finished off for Beta
*	02.08.97	Martin Kift		Fixed handling of anim models, which was badly broken.
*
*%%%**************************************************************************/

MR_VOID UpdateLiveEntitySpecials(LIVE_ENTITY* live_entity)
{
	ENTITY_SPECIAL*	entity_special;
	MR_LONG			i;
	MR_MAT			matrix;
	MR_MAT*			matrix_ptr;
	MR_MAT*			lwtrans_ptr;
	MR_VEC			vec;


	if (i = live_entity->le_numspecials)
		{
		entity_special = live_entity->le_specials;
		while(i--)
			{
			switch(entity_special->es_type)
				{
				//-------------------------------------------------------------------
				case ENTITY_SPECIAL_TYPE_SPRITE:
				case ENTITY_SPECIAL_TYPE_PARTICLE:
					// Calculate world position of hilite vertex in model/part coords
					lwtrans_ptr = &entity_special->es_lwtrans;
					if (entity_special->es_mof_ptr->mm_flags & MR_MOF_ANIMATED)
						{			
						// Get part transform (note that translation is also stored in MRTemp_svec)
						matrix_ptr = &matrix;
						MRAnimEnvGetPartTransform(live_entity->le_api_item0, matrix_ptr, 0, entity_special->es_part_index);

						// Multiply by live entity transform
						MRMulMatrixABC(live_entity->le_lwtrans, matrix_ptr, lwtrans_ptr);
						MRApplyMatrix(lwtrans_ptr, entity_special->es_vertex, &vec);
						MR_ADD_VEC_ABC((MR_VEC*)live_entity->le_lwtrans->t, &vec, (MR_VEC*)lwtrans_ptr->t);
						}
					else
						{
						MR_COPY_MAT(lwtrans_ptr, live_entity->le_lwtrans);
						MRApplyMatrix(lwtrans_ptr, entity_special->es_vertex, &vec);
						MR_ADD_VEC_ABC((MR_VEC*)live_entity->le_lwtrans->t, &vec, (MR_VEC*)lwtrans_ptr->t);
						}
					break;
				//-------------------------------------------------------------------
				default:
					MR_ASSERTMSG(NULL, "Entity MOF unrecognised hilite type");
					break;
				//-------------------------------------------------------------------
				}
			entity_special++;
			}
		}
}


/******************************************************************************
*%%%% KillLiveEntitySpecials
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID KillLiveEntitySpecials(	
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function kills any special effects allocated by CreateLiveEntitySpecialEffects
*
*	INPUTS		live_entity		-	ptr to live entity that had special effects created for it
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.05.97	William Bell	Created
*	23.06.97	William Bell	Rewrote with general special effects in mind
*	11.07.97	Tim Closs		Finished off for Beta
*
*%%%**************************************************************************/

MR_VOID KillLiveEntitySpecials(LIVE_ENTITY* live_entity)
{
	ENTITY_SPECIAL*	entity_special;
	MR_LONG			i;


	if (i = live_entity->le_numspecials)
		{
		entity_special = live_entity->le_specials;
		while(i--)
			{
			switch(entity_special->es_type)
				{
				//-------------------------------------------------------------------
				case ENTITY_SPECIAL_TYPE_SPRITE:
				case ENTITY_SPECIAL_TYPE_PARTICLE:
					// Kill sprite/particle generator
					((MR_OBJECT*)entity_special->es_api_item)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
					break;
				//-------------------------------------------------------------------
				}
			entity_special++;
			}

		// Free memory we grabbed during the create
		MRFreeMem(live_entity->le_specials);

		// Invalidate pointer and number
		live_entity->le_specials 	= NULL;
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
	ENTITY**			entity_pptr;
	ENTITY*				entity;
	ENTITY_BOOK*		entity_book;
	MR_ULONG			i;

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

				EntityLinkToMapGroup(entity, (MR_VEC*)entity->en_live_entity->le_lwtrans->t);
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
*	20.08.97	Martin Kift		Added code to re-enable bonus time flies
*
*%%%**************************************************************************/

MR_VOID ResetEntities(MR_VOID)
{
	ENTITY_BOOK*		entity_book;
	ENTITY*				entity;
	ENTITY**			entity_pptr;
	MR_ULONG			i, ofs;
	FORM_BOOK*			form_book;
	GEN_BONUS_FLY*		bonus_fly;

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
			if (Game_reset_flags & GAME_RESET_CHECKPOINT_COLLECTED)
				{
				if (form_book->fb_flags & FORM_BOOK_RESET_ON_CHECKPOINT)
					KillLiveEntity(entity->en_live_entity);
				}
			else 
			if (Game_reset_flags & GAME_RESET_FROGS_DEAD)
				{
				if (form_book->fb_flags & FORM_BOOK_RESET_ON_FROG_DEATH)
					KillLiveEntity(entity->en_live_entity);
				}
			else
				KillLiveEntity(entity->en_live_entity);
			}

		entity_pptr++;
		}

	// Make sure that all the MR_PRIMS are clear.
	GameClearRender();

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
			else
				{
//				// only on sky themes, reset time flies
//				if (Game_map_theme == THEME_SKY)
//					{
					form_book = ENTITY_GET_FORM_BOOK(entity);
					if (form_book->fb_entity_type == ENTITY_TYPE_BONUS_FLY)
						{
						bonus_fly	= (GEN_BONUS_FLY*)(entity + 1);
						if  (
							(bonus_fly->bf_type >= GEN_FLY_MIN) && 
							(bonus_fly->bf_type <= GEN_FLY_MAX)
							)
							{
							entity->en_flags &= ~ENTITY_HIDDEN;
							}
						}
//					}
				}
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

	// switch/case on the trigger type
	switch (trigger->et_type)
		{
		case ENTITY_TYPE_TRIGGER_FREEZE:
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

		case ENTITY_TYPE_TRIGGER_BEGIN:
			// Unpause all entity in the list
			for (count=0; count<ENTITY_TYPE_TRIGGER_MAX_IDS; count++)
				{
				// is ID valid?
				if (trigger->et_unique_ids[count] != -1)
					{
					// find entity with unique id
					trigger_live_entity = GetNextLiveEntityWithUniqueId(trigger->et_unique_ids[count]);
					MR_ASSERTMSG (trigger_live_entity != NULL, "Entity start trigger with invalid unique id");

					// remove no-movement flag if necessary
					if (trigger_live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
						{
						trigger_live_entity->le_entity->en_flags &= ~ENTITY_NO_MOVEMENT;
						// If entity is path based, set path based flag to start it
						if (trigger_live_entity->le_entity->en_path_runner)
							trigger_live_entity->le_entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;
						}
					}
				}
			break;
		}

	// set this entity as forbid-collision
	frog->fr_forbid_entity	 = entity;
	frog->fr_flags			|= FROG_JUMP_FROM_COLLPRIM;
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
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)action_number);
	else
		MRAnimEnvSingleSetAction((MR_ANIM_ENV*)live_entity->le_api_item0, (MR_SHORT)action_number);
}

/******************************************************************************
*%%%% LiveEntitySetCel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID LiveEntitySetCel(
*										LIVE_ENTITY*	live_entity,
*										MR_SHORT		cel)
*
*	FUNCTION	This function sets a cel for an anim env.
*
*	INPUTS		live_entity		- ptr to live_entity
*				cel				- cel number
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID LiveEntitySetCel(	LIVE_ENTITY*	live_entity, 
							MR_SHORT		cel)
{
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)
		MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*)live_entity->le_api_item0, cel);
	else
		MRAnimEnvSingleSetCel((MR_ANIM_ENV*)live_entity->le_api_item0, cel);
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

/******************************************************************************
*%%%% LiveEntityGetAction
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_SHORT	LiveEntityGetAction(
*								LIVE_ENTITY*	live_entity)
*
*	FUNCTION	This function gets the action number for an animation.
*
*	INPUTS		live_entity		- ptr to live entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_SHORT LiveEntityGetAction(LIVE_ENTITY* live_entity)
{
	MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_ANIMATED);

	if (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK)												
		{	
		return ((MR_ANIM_ENV_FLIPBOOK*)((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook)->ae_action_number;
		}
	else
		{
		return ((MR_ANIM_ENV_SINGLE*)((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_single)->ae_action_number;
		}
}


/******************************************************************************
*%%%% ENTSTRCreateSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateSprite(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Creates the Sprite (3D)	for the live entity
*
*	INPUTS		live_entity	-	live entity to create
*				form		-	form ptr (for this entity)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateSprite(LIVE_ENTITY*	live_entity,
						   FORM*		form)
{
	// Create 3D sprite
	live_entity->le_api_item0	= MRCreate3DSprite(	(MR_FRAME*)live_entity->le_lwtrans,
													MR_OBJ_STATIC,
													Animlist_fire_fly);

	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags &= ~MR_OBJ_ACCEPT_LIGHTS_MASK;
//	((MR_OBJECT*)live_entity->le_api_item0)->ob_extra.ob_extra_sp_core->sc_flags |= MR_SPF_NO_3D_ROTATION;

	GameAddObjectToViewportsStoreInstances(live_entity->le_api_item0, (MR_MESH_INST**)live_entity->le_api_insts);
}

/******************************************************************************
*%%%% ENTSTRCreateMovingSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRCreateMovingSprite(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Create a moving Sprite. (Instead of a Moving Mof.)
*
*	INPUTS		live_entity	-	to create
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Gary Richards	Created.
*
*%%%**************************************************************************/

MR_VOID	ENTSTRCreateMovingSprite(LIVE_ENTITY*	live_entity)
{
	ENTSTR_STATIC*	entity_type;
	ENTITY*			entity;
	FORM*  			form;
	MR_VEC			vec_x;
	MR_VEC			vec_y;
	MR_VEC			vec_z;

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
	
	// call generic function to create our Sprite.
	ENTSTRCreateSprite(live_entity, form);
}


/******************************************************************************
*%%%% ENTSTRKillMovingSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRKillMovingSprite(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Kill a moving Sprite
*
*	INPUTS		live_entity	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRKillMovingSprite(LIVE_ENTITY*	live_entity)
{
	// ...... and finally kill the sprite.
	((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
}


/******************************************************************************
*%%%% ENTSTRUpdateMovingPlatformMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ENTSTRUpdateMovingPlatformMOF(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Update a moving MOF and plays a SFX for when it's moving.
*				(Done like this to save memory.)
*
*	INPUTS		live_entity	-	to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	ENTSTRUpdateMovingPlatformMOF(LIVE_ENTITY*	live_entity)
{
	ENTSTRUpdateMovingMOF(live_entity);
	// Check to see which level we are on.
	if (Game_map_theme == THEME_VOL)
		{
		// Check to see if moving platform is actually moving.
		if (live_entity->le_entity->en_flags & ENTITY_NO_MOVEMENT)
			{
			// Not moving, so no sound.
			KillMovingSound(live_entity);
			}
			else
			{
			// Is moving so play sound moving sound.
			PlayMovingSound(live_entity, SFX_IND_CHAIN, 1024, 2048);
			}
		}
}


/******************************************************************************
*%%%% LiveEntityChangeVolume
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LiveEntityChangeVolume(MRSND_VOLUME* Volume)
*
*	FUNCTION	Sets the volume for any live entites that may have a moving sound.
*
*	INPUTS		Volume		-	New level to set.
*				Auto_volume	-	Used to set/unset the auto-volume within the API.
*
*	NOTE		This should really only be called from PAUSE MODE.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.08.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID	LiveEntityChangeVolume(MR_UBYTE Volume, MR_BOOL Auto_volume)				  
{
	MR_LONG			voice_id;
	LIVE_ENTITY*	live_entity; 	 
	MRSND_VOLUME	Sound;

	// Set the new volume.
	Sound.left  = (127 * Volume) / OPTIONS_SOUND_STAGES;
	Sound.right = (127 * Volume) / OPTIONS_SOUND_STAGES;

	// Loop through all the live_entities to find any with moving_sounds which are playing.
	live_entity = Live_entity_root_ptr;
	while(live_entity = live_entity->le_next)
		{
		if	(live_entity->le_moving_sound != NULL)
			{
			// Turn on Automactic Volume control by the sound API.
			if (Auto_volume == TRUE)
				((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_flags |= (MRSND_MOVING_SOUND_ACCEPT_FADE | MRSND_MOVING_SOUND_ACCEPT_PAN);
			else
				((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_flags &= ~(MRSND_MOVING_SOUND_ACCEPT_FADE | MRSND_MOVING_SOUND_ACCEPT_PAN);
			// Grab voice id.
			voice_id = ((MRSND_MOVING_SOUND*)live_entity->le_moving_sound)->ms_voice_id[0];
			if (voice_id != -1)
				MRSNDChangeVolume(voice_id,  &Sound);
			}
		}
}

/******************************************************************************
*%%%% LiveEntityInitPop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID		LiveEntityInitPop(
*							LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Initialises and returns ptr to poly_piece pop structure.
*
*	INPUTS		live_entity	- ptr to live entity
*
*	RETURNS		Ptr to live_entity to pop
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Martin Kift		Created
*	21.08.97	Martin Kift		Renamed and moved to generic function
*
*%%%**************************************************************************/

MR_VOID LiveEntityInitPop(LIVE_ENTITY* live_entity)
{
	POLY_PIECE_POP*		pop;
	FORM_BOOK*			form_book;
	MR_MOF*				mof;

	MR_ASSERT(live_entity);

	// if already pop, forget it
	if (live_entity->le_effect)
		return;

	form_book					= ENTITY_GET_FORM_BOOK(live_entity->le_entity);
	mof							= Map_mof_ptrs[form_book->fb_mof_id];

	// setup pop structure
	live_entity->le_effect		= MRAllocMem(sizeof(POLY_PIECE_POP) + (sizeof(POLY_PIECE_DYNAMIC) * ((MR_PART*)(mof + 1))->mp_prims), "FROG POLY PIECE POP");
	pop							= ((POLY_PIECE_POP*)live_entity->le_effect);

	pop->pp_mof					= mof;
	pop->pp_numpolys 			= ((MR_PART*)(pop->pp_mof + 1))->mp_prims;
	pop->pp_timer				= 0;
	pop->pp_lwtrans				= live_entity->le_lwtrans;
	pop->pp_poly_pieces			= CreateMeshPolyPieces(mof);
	pop->pp_poly_piece_dynamics	= (POLY_PIECE_DYNAMIC*)(pop	+ 1);
}

/******************************************************************************
*%%%% LiveEntityStartPolyPiecePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LiveEntityStartPolyPiecePop(
*						LIvE_ENTITY*		live_entity)
*
*	FUNCTION	Turn off animated model, and set things up to update and render
*				popping polys
*
*	INPUTS		live_entity	-	ptr to live_entity to pop
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.07.97	Martin Kift		Created
*	21.08.97	Martin Kift		Renamed and moved to generic function
*
*%%%**************************************************************************/

MR_VOID	LiveEntityStartPolyPiecePop(LIVE_ENTITY*	live_entity)
{
	MR_LONG				i;
	POLY_PIECE*			poly_piece;
	POLY_PIECE_DYNAMIC*	poly_piece_dynamic;
	MR_VEC				vec;
	POLY_PIECE_POP*		piece_pop;

	MR_ASSERT(live_entity);

	piece_pop = (POLY_PIECE_POP*)live_entity->le_effect;
	MR_ASSERT(piece_pop);

	// Turn off existing model
	if (live_entity->le_flags & LIVE_ENTITY_ANIMATED)
		{
		MR_ASSERT (live_entity->le_flags & LIVE_ENTITY_FLIPBOOK);
		((MR_ANIM_ENV*)live_entity->le_api_item0)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
		}
	else
		{
		((MR_OBJECT*)live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
		}

	// Set up pop	
	piece_pop->pp_timer 		= FROG_POLY_PIECE_POP_DURATION;
	piece_pop->pp_duration 		= FROG_POLY_PIECE_POP_DURATION;
	piece_pop->pp_otz			= FROG_POPPING_FIXED_OT;
#ifdef	WIN95
	piece_pop->pp_frame_index	= -1;
#endif

	MR_CLEAR_SVEC(&piece_pop->pp_rotation);
	MR_CLEAR_SVEC(&piece_pop->pp_ang_vel);
	
	// Set up position/velocity of pieces
	i 					= piece_pop->pp_numpolys;
	poly_piece		 	= piece_pop->pp_poly_pieces;
	poly_piece_dynamic 	= piece_pop->pp_poly_piece_dynamics;
	gte_SetRotMatrix(piece_pop->pp_lwtrans);
	while(i--)
		{
		MRApplyRotMatrix(&poly_piece->pp_origin, &vec);

		// Set position
		poly_piece_dynamic->pp_position.vx = (piece_pop->pp_lwtrans->t[0] + vec.vx) << 16;
		poly_piece_dynamic->pp_position.vy = (piece_pop->pp_lwtrans->t[1] + vec.vy) << 16;
		poly_piece_dynamic->pp_position.vz = (piece_pop->pp_lwtrans->t[2] + vec.vz) << 16;

		// Set velocity
		vec.vy -= 0x80;
		MRNormaliseVEC(&vec, &vec); 
		poly_piece_dynamic->pp_velocity.vx = vec.vx << 10;
		poly_piece_dynamic->pp_velocity.vy = vec.vy << 10;
		poly_piece_dynamic->pp_velocity.vz = vec.vz << 10;

		poly_piece++;
		poly_piece_dynamic++;
		}	
}

/******************************************************************************
*%%%% LiveEntityUpdatePolyPiecePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LiveEntityUpdatePolyPiecePop(
*						MR_VOID*			pop)
*
*	FUNCTION	Turn off animated model, and set things up to update and render
*				popping polys
*
*	INPUTS		live_entity	-	ptr to live_entity to pop
*
*	RETURN		TRUE if finished, FALSE if not
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL LiveEntityUpdatePolyPiecePop(LIVE_ENTITY*	live_entity)
{
	MR_LONG			i;
	POLY_PIECE_POP* pop;

	MR_ASSERT(live_entity);
	pop = (POLY_PIECE_POP*)live_entity->le_effect;
	MR_ASSERT(pop);
	
	// update any pops
	if	(
		(pop) &&
		(pop->pp_timer)
		)
		{
		UpdatePolyPiecePop(pop);

#ifdef WIN95
		// Have we rendered this frame already? This code only operates on windows
		// with its flexible frame update system, on the psx its not needed
		if (pop->pp_frame_index != MRFrame_number)
			{
			// Render and update counter
			pop->pp_frame_index = MRFrame_number;
#endif
			for (i = 0; i < Game_total_viewports; i++)
				{
				if (!(live_entity->le_flags & LIVE_ENTITY_FLIPBOOK))
					RenderPolyPiecePop(pop, (MR_MESH_INST*)live_entity->le_api_insts[i], i);
				else
					RenderPolyPiecePop(pop, ((MR_ANIM_ENV_INST*)live_entity->le_api_insts[i])->ae_mesh_insts[0], i);

				}
#ifdef WIN95
			}
#endif
		return FALSE;
		}
	return TRUE;
}

/******************************************************************************
*%%%% LiveEntityFreePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LiveEntityFreePop(
*						LIVE_ENTITY*	live_entity)
*
*	FUNCTION	Free poly pop
*
*	INPUTS		live_entity	-	ptr to live_entity to pop
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID LiveEntityFreePop(LIVE_ENTITY*	live_entity)
{
	POLY_PIECE_POP*		pop;

	MR_ASSERT(live_entity);

	// Valid effect ?
	if (live_entity->le_effect)
		{
		// Yes ... get pointer to pop pieces
		pop	= ((POLY_PIECE_POP*)live_entity->le_effect);

		// Free pop pieces
		MRFreeMem(pop->pp_poly_pieces);

		// Free governing structure
		MRFreeMem(live_entity->le_effect);
		}

	live_entity->le_effect = NULL;
}
