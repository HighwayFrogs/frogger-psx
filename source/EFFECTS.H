/******************************************************************************
*%%%% effects.h
*------------------------------------------------------------------------------
*
*	Special effects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__EFFECTS_H
#define	__EFFECTS_H

#include "mr_all.h"
#include "gamesys.h"
#include "grid.h"
#include "entity.h"


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// Shadow
#define	SHADOW_OT_OFFSET				-4					// added to shadow poly OT (if in global OT)

// Trail
#define	TRAIL_RGB_START					0x202020
#define	TRAIL_RGB_MAX					0x606060
#define	TRAIL_RGB_INCREASE				0x080808
#define	TRAIL_RGB_DECREASE				0x080808
#define	TRAIL_DECREASE_TIMER			12

// Tongue
#define	TONGUE_MAX_SECTIONS				8
#define	TONGUE_GRAB_RADIUS2				MR_SQR(0x80)		// if target within this range, snap to target
#define	TONGUE_TARGETTABLE_RADIUS2		MR_SQR(0x280)		// if target within this range, start tongue
#define	SUPERTONGUE_TARGETTABLE_RADIUS2	MR_SQR(0x480)		// if target within this range, start tongue. (Super Tongue)
#define	TONGUE_VIEW_ANGLE_Z				0					// max z of normalised vector in owner frame ((cos 60) << 12)
#define	TONGUE_OT_OFFSET				0
#define	TONGUE_END_OT_OFFSET			0x10
#define	TONGUE_GRABBING_DURATION		4
#define	TONGUE_OWNER_MAX_SCALE			0x1400
#define	TONGUE_OWNER_SCALE_UP_TIME		4
#define	TONGUE_OWNER_SCALE_DOWN_TIME	4

#define	TONGUE_FLAG_MOVING_OUT			(1<<0)				// tongue mode: moving out
#define	TONGUE_FLAG_MOVING_IN			(1<<1)				// tongue mode: moving in
#define	TONGUE_FLAG_GRABBING			(1<<2)				// tongue mode: moving grabbing
#define	TONGUE_FLAG_FADING_UP			(1<<3)				// tongue mode:	fading up.
#define TONGUE_FLAG_FADING_DOWN			(1<<4)				// tongue mode: fading down.

// Poly piece pop
#define	POLY_PIECE_POP_ANG_ACC_X		0x08
#define	POLY_PIECE_POP_ANG_ACC_Y		0x0c
#define	POLY_PIECE_POP_ANG_ACC_Z		0x10

// Effect types
enum	{
		EFFECT_TYPE_SHADOW,
		EFFECT_TYPE_SIGHTS,
		EFFECT_TYPE_EXHAUST,
		EFFECT_TYPE_TRAIL,
		EFFECT_TYPE_TONGUE,
		EFFECT_TYPE_PARTICLE,
		};

// Effect flags
#define	EFFECT_STATIC						(1<<0)			// effect is linked to a static matrix
#define	EFFECT_NO_UPDATE					(1<<1)
#define	EFFECT_NO_DISPLAY					(1<<2)
#define	EFFECT_REWRITE_MATRICES				(1<<3)
#define	EFFECT_KILL_WHEN_FINISHED			(1<<4)
#define	EFFECT_STANDARD_MODE				(1<<5)
#define	EFFECT_NO_ROTATION					(1<<6)
#define	EFFECT_RESET						(1<<7)
#define	EFFECT_KILL_WHEN_FROG_DEAD			(1<<8)
#define	EFFECT_KILL_WHEN_FROG_RESET			(1<<9)
	
//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

typedef	struct 	__lens_flare			LENS_FLARE;
typedef struct 	__effect				EFFECT;
typedef struct 	__shadow				SHADOW;
typedef struct 	__sights				SIGHTS;
typedef struct 	__trail					TRAIL;
typedef struct 	__tongue				TONGUE;
typedef	struct	__poly_mesh				POLY_MESH;
typedef	struct	__poly_mesh_light		POLY_MESH_LIGHT;
typedef	struct	__poly_piece			POLY_PIECE;
typedef	struct	__poly_piece_dynamic	POLY_PIECE_DYNAMIC;
typedef	struct	__poly_piece_pop		POLY_PIECE_POP;

struct __lens_flare
	{
	MR_TEXTURE*			lf_image;								// texture pointer
	MR_LONG				lf_distance;							// distance image will appear along line joining camera to source (0..4096)
	MR_ULONG   			lf_scale;								// image scale
	MR_CVEC				lf_cvec;								// image rgb

	};		//	LENS_FLARE


struct __effect
	{
	EFFECT*				ef_next_node;							// list links
	EFFECT*				ef_prev_node;
	MR_USHORT			ef_flags;				
	MR_UBYTE   			ef_type;								// effect sub-type
	MR_UBYTE   			ef_kill_timer;							// if non-zero, decrease to zero, then remove structure
	MR_VOID*   			ef_extra;
	};		// EFFECT


struct __shadow													// (effect sub-type)
	{
	MR_TEXTURE*			sh_texture;								// texture to use
	MR_SVEC*			sh_offsets;								// ptr to array of 4 shadow corner offsets (in PSX format)
	POLY_FT4   			sh_polys[2][SYSTEM_MAX_VIEWPORTS][2];	// two quad shadows, double buffered, in viewport(s)
	MR_SVEC				sh_corners[2][4];						// corner points in world (2 polys, 4 corners)
	MR_UBYTE			sh_uv[2][4][2];							// absolute UV coords (2 polys, 4 corners, u and v)
	MR_MAT*				sh_lwtrans;								// to transform above into world
	MR_OT*				sh_ot_ptr[SYSTEM_MAX_VIEWPORTS];		// ptr to local OT (or NULL for global OT) for viewport(s)
	
	};		// SHADOW


struct __sights													// (effect sub-type)
	{
	MR_TEXTURE*			si_texture;								// texture to use
	POLY_FT4			si_polys[2];							// double buffered poly in ONE VIEWPORT ONLY
	MR_USHORT			si_racer_id;							// racer id (0..3)
	MR_USHORT			si_timer;
	MR_VOID*			si_target;								// NULL, or targetted plane

	};		// SIGHTS


struct __trail													// (effect sub-type)
	{
	MR_ULONG			tr_sections;							// number of sections (vertex pairs) in trail
	MR_ULONG			tr_current_section;						// section (vertex pair) to write to next
	MR_ULONG			tr_timer;								// counts down to 0, then kills effect
	MR_ULONG			tr_display_sections;					// counts up to tr_sections
	MR_SVEC*			tr_vertex_coords;						// ptr to (2 * tr_sections) world coords	(ALLOCATED with below)
	POLY_G3*			tr_polys[SYSTEM_MAX_VIEWPORTS][2];		// double buffered polys in viewport(s)		ALLOCATED
	POLY_FT3			tr_poly_ft3[SYSTEM_MAX_VIEWPORTS][2];	// dummy abr changers
	MR_SVEC				tr_velocity;							// velocity of trail (added to tr_vertex_coords each frame)
	MR_MAT*				tr_lwtrans;								// ptr to lw transform of owning frame
	MR_SVEC*			tr_offsets;								// ptr to two offsets in owning frame for creating new vertex pair
	MR_OT*				tr_ot_ptr[SYSTEM_MAX_VIEWPORTS];		// ptr to local OT (or NULL for global OT) for viewport(s)
	MR_ULONG			tr_rgb;									// current colour of current section
	MR_ULONG			tr_rgb_increase;						// added to tr_rgb each frame as we fade up
	MR_ULONG			tr_rgb_decrease;						// subtracted from tr_rgb each frame as we fade down
	
	};		// TRAIL


struct __tongue														// (effect sub-type)
	{
	MR_ULONG			to_flags;
	MR_ULONG			to_counter;									// counts down to 0
	MR_ULONG			to_section;									// section to write to next
	MR_SVEC				to_vertices[TONGUE_MAX_SECTIONS + 1][3];	// tongue section endpoints
	POLY_G4				to_polys[SYSTEM_MAX_VIEWPORTS][2][TONGUE_MAX_SECTIONS << 1];
	POLY_FT3			to_poly_ft3[SYSTEM_MAX_VIEWPORTS][2];		// dummy abr changers
	POLY_FT4			to_poly_ft4[SYSTEM_MAX_VIEWPORTS][2];		// end of tongue image
	MR_MAT*				to_lwtrans;									// ptr to lw transform of owning frame
	ENTITY*				to_target;									// ptr to target entity
	MR_OT*				to_ot_ptr[SYSTEM_MAX_VIEWPORTS];			// ptr to local OT (or NULL for global OT) for viewport(s)
	MR_VOID*			to_owner;									// usually FROG*
	MR_ULONG			to_colour;									// Colour to add to the tongue in super mode.
	
	};		// TONGUE


struct __poly_mesh
	{
	MR_TEXTURE*			pm_texture;								// ptr to texture used
	MR_SHORT			pm_x;									// screen x of top left of mesh
	MR_SHORT			pm_y;									// screen y of top left of mesh
	MR_USHORT			pm_w;									// width of mesh in polys
	MR_USHORT			pm_h;									// height of mesh in polys
	MR_VIEWPORT*		pm_viewport;							// ptr to viewport to render into
	MR_ULONG			pm_otz;									// OT position to add polys to
	POLY_GT4*			pm_polys[2];							// ptr to mesh of POLY_GT4 (for each frame)
	
	};		// POLY_MESH


struct __poly_mesh_light
	{
	MR_SHORT			pm_x;									// screen x of light source
	MR_SHORT			pm_y;									// screen y of light source
	MR_CVEC				pm_cvec;								// colour of light source
	MR_SHORT			pm_strength;							// poly r = (cvec.r * strength) / distance
	MR_USHORT			pm_min_dist;							// minimum distance a light can be from a poly vertex
	MR_SHORT			pm_user0;								// user data (eg. angle of light source)
	MR_SHORT			pm_user1;

	};		// POLY_MESH_LIGHT	


struct	__poly_piece
	{
	MR_SVEC				pp_vertices[4];							// poly vertices, relative to origin
	MR_SVEC				pp_origin;								// poly origin, relative to mesh origin
	MR_VEC				pp_render_translation;					// used to speed up render code

	};		// POLY_PIECE


struct	__poly_piece_dynamic
	{
	MR_VEC				pp_position;							// position of POLY_PIECE in world (16.16)
	MR_VEC				pp_velocity;							// velocity of POLY_PIECE in world (16.16)
	};


struct	__poly_piece_pop
	{
	MR_MOF*				pp_mof;									// ptr to the (static, single part) mof
	MR_LONG				pp_numpolys;							// number of POLY_PIECEs
	MR_LONG				pp_timer;								// counts down to 0
	MR_LONG				pp_duration;							// where timer starts from
	MR_LONG				pp_otz;									// polys are added at fixed otz
	MR_MAT*				pp_lwtrans;								// ptr to model transform
	MR_SVEC				pp_rotation;							// rotation to apply to model transform
	MR_SVEC				pp_ang_vel;								// added to rotation
	POLY_PIECE*			pp_poly_pieces;							// array of (pp_numpolys) POLY_PIECEs
	POLY_PIECE_DYNAMIC*	pp_poly_piece_dynamics;					// array of (pp_numpolys) POLY_PIECE_DYNAMICs
#ifdef WIN95
	MR_LONG				pp_frame_index;							// used to prevent multiple renders on win95
#endif
	};		// POLY_PIECE_POP

//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

// Lens flare
extern	MR_VOID			InitialiseLensFlare(MR_VOID);
extern	MR_VOID			CalculateLensFlare(MR_VOID);
extern	MR_VOID*		FindNearestFlareSource(MR_VEC*, MR_VEC*, MR_ULONG*);

// Shadow
extern	EFFECT*			CreateShadow(MR_TEXTURE*, MR_MAT*, MR_SVEC*);

// Sights
extern	EFFECT*			CreateSights(MR_TEXTURE*, MR_USHORT);

// Trail
extern	EFFECT*			CreateTrail(MR_MAT*, MR_SVEC*, MR_ULONG);
extern	MR_VOID			ResetTrail(EFFECT*);

// Tongue
extern	EFFECT*			CreateTongue(MR_MAT*, MR_VOID*);
extern	MR_VOID			StartTongue(EFFECT*, ENTITY*);
extern	MR_VOID			ResetTongue(EFFECT*);

// Poly mesh
extern	POLY_MESH*		CreatePolyMesh(MR_TEXTURE*, MR_SHORT, MR_SHORT, MR_USHORT, MR_USHORT, MR_VIEWPORT*, MR_ULONG, MR_USHORT);
extern	MR_VOID			KillPolyMesh(POLY_MESH*);
extern	MR_VOID			UpdatePolyMesh(POLY_MESH*, POLY_MESH_LIGHT*, POLY_MESH_LIGHT*, POLY_MESH_LIGHT*);
extern	MR_VOID			RenderPolyMesh(POLY_MESH*);

// Poly piece
extern	POLY_PIECE*		CreateMeshPolyPieces(MR_MOF*);
extern	MR_VOID			UpdatePolyPiecePop(POLY_PIECE_POP*);
extern	MR_VOID			RenderPolyPiecePop(POLY_PIECE_POP*, MR_MESH_INST*, MR_ULONG);

// General
extern	MR_VOID			InitialiseEffects(MR_VOID);
extern	EFFECT*			CreateEffect(MR_USHORT);
extern	MR_VOID			KillEffect(EFFECT*);
extern	MR_VOID			KillAllEffects(MR_VOID);
extern	MR_VOID			UpdateEffects(MR_VOID);
extern	MR_VOID			RenderEffects(MR_VOID);
extern	MR_VOID			SetupABRChangeFT3(MR_VOID*, MR_USHORT);
extern	MR_VOID			ClearEffects(MR_VOID);

// Particle effects
extern	MR_OBJECT*		CreateParticleEffect(MR_VOID*, MR_ULONG, MR_SVEC*);

#endif	//__EFFECTS_H



