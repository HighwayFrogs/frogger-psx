
#define	MAX_NUM_SPECIAL_EFFECTS			10			// Max number of special effects per live entity

// Enum list of hilite types used to denote entity specials ( all types )
enum	{
		HILITE_TYPE_COLLISION,						// Collision hilite type
		HILITE_TYPE_SPLASH,							// Splash hilite type ( 3D sprite )
		HILITE_TYPE_WAKE,							// Wake hilite type ( 3D sprite )
		HILITE_TYPE_PARTICLE,						// Particle generator hilite type
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

struct __entity_special
	{
	MR_USHORT	es_type;							// Type of entity special ( these would be MR_HILITE type )
	MR_USHORT	es_part_index;						// Index of MR_PART within animation
	MR_SVEC*	es_vertex;							// Ptr to vertex within MR_PART vertex
	MR_SVEC*	es_position;						// Position in world of attachment
	MR_VOID*	es_api_item;						// Ptr to API item ( MR_OBJECT or MR_ANIM_ENV ) we created for this special
	MR_VOID*	es_api_insts[4];					// Ptr to API insts in viewport(s)

	// extras

	};	// ENTITY_SPECIAL

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
	MR_ULONG*		le_sprite_ptrs;		// ptr to sprite data (number and then object ptr and vec position ptr for each sprite )
	MR_VOID*		le_moving_sound;	// ptr to a potential moving sound (must be killed on deletion of a live_entity)

	MR_ULONG		le_numspecials;		// number of special effects this entity has
	ENTITY_SPECIAL*	le_specials;		// ptr to special effects

	};	// LIVE_ENTITY;

extern	MR_ULONG 		CreateLiveEntitySpecials(LIVE_ENTITY*);
extern	MR_VOID			UpdateLiveEntitySpecials(LIVE_ENTITY*);
extern	MR_VOID			KillLiveEntitySpecials(LIVE_ENTITY*);
