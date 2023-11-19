/******************************************************************************
*%%%% select.h
*------------------------------------------------------------------------------
*
*	Level Select (Version 3)
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef	__SELECT_H
#define	__SELECT_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	SELECT_LEVEL_BACKGROUNDS		// have backgrounds for level select

// Defines
//#ifdef DEBUG
//#define	SEL_TIME_OUT_TIME				(6 * 30)
//#else
//#define	SEL_TIME_OUT_TIME				(20 * 30)
//#endif

#define	SEL_NUMBER_OF_WORLDS			(10)
#define	SEL_ARCADE_LEVELS_PER_WORLD		(5)
#define	SEL_RACE_LEVELS_PER_WORLD		(1)
#define	SEL_NUMBER_OF_ARCADE_LEVELS		(SEL_ARCADE_LEVELS_PER_WORLD*SEL_NUMBER_OF_WORLDS)
#define	SEL_NUMBER_OF_RACE_LEVELS		(SEL_RACE_LEVELS_PER_WORLD*SEL_NUMBER_OF_WORLDS)
#define	SEL_NUMBER_OF_LEVELS			(SEL_NUMBER_OF_WORLDS*SEL_LEVELS_PER_WORLD)

#define	SEL_STACK_X_POS					-0xa00
#define	SEL_STACK_Z_POS					-0xa00

#define	SEL_INIT_CAMERA_X				(-0x1000)
#define	SEL_INIT_CAMERA_Y				(-0x1800)
#define	SEL_INIT_CAMERA_Z				(-0x1800)

#define	SEL_ADJ_CAMERA_X				(0x700)
#define	SEL_ADJ_CAMERA_Y				(0x900)
#define	SEL_ADJ_CAMERA_Z				(0x700)

#define	SEL_BOX_X_SIZE					(0xf0)
#define	SEL_BOX_Z_SIZE					(0xf0)

#define	SEL_POLYS_PER_LEVEL_MOF			(6)
#define	SEL_VERTS_PER_LEVEL_MOF			(8)

#define	SEL_WF_ENABLE_FIRST				(1<<0)
#define	SEL_WF_HIDDEN					(1<<1)
#define	SEL_WF_COMPLETED				(1<<2)

#define	SEL_LF_COMPLETED				(1<<0)
#define	SEL_LF_SELECTABLE				(1<<1)
#define	SEL_LF_ZONEACCESSIBLE			(1<<2)

#define	SEL_LEVEL_SLIDE_INC				(0x40)
#define	SEL_LEVEL_SLIDE_DIST			((-SEL_BOX_Z_SIZE)<<1)

#define	SEL_CAMERA_GOING_UP	 			(1<<0)
#define	SEL_CAMERA_GOING_DOWN			(1<<1)
#define	SEL_CAMERA_STATIONARY			(1<<2)
#define	SEL_CAMERA_STOPPING				(1<<3)

#define	SEL_CAMERA_MAX_VEL				(56)
#define	SEL_CAMERA_ACC					(4)

#define	SEL_SPIN_OUT					(1<<0)
#define	SEL_SPIN_IN						(1<<1)
#define	SEL_SPIN_HOLD					(1<<2)

#define	SEL_SPIN_TIME					(10)

#ifdef PSX
	#define	SEL_STATUS_END_X_POS			(168)
	#define	SEL_STATUS_WIDTH				(24 * 8)
	#define	SEL_LEVEL_TITLE_Y				(138)
	#define	SEL_LEVEL_SCORE_LINE_0_Y		(160+(16*0))
	#define	SEL_LEVEL_SCORE_LINE_1_Y		(160+(16*1))
	#define	SEL_LEVEL_SCORE_LINE_2_Y		(160+(16*2))
	#define	SEL_PROMPT_SPRITE_Y				(212)
#else
	#define	SEL_STATUS_END_X_POS			(400)
	#define	SEL_STATUS_WIDTH				(160)
	#define	SEL_LEVEL_TITLE_Y				(300)
	#define	SEL_LEVEL_SCORE_LINE_0_Y		(320+(16*0))
	#define	SEL_LEVEL_SCORE_LINE_1_Y		(320+(16*1))
	#define	SEL_LEVEL_SCORE_LINE_2_Y		(320+(16*2))
	#define	SEL_PROMPT_SPRITE_Y				(400)
#endif

// Game modes (Arcade, or Race/Multiplayer)
enum	{
		SEL_MODE_ARCADE,
		SEL_MODE_RACE,
		SEL_MODE_MAIN_HIGH_SCORES,
		};


// Main operating mode
enum	{
		SEL_GAME_MODE_SELECTING,
		SEL_GAME_MODE_SHOW_LEVEL_INFO,
		SEL_GAME_MODE_START_FADE,
		SEL_GAME_MODE_UPDATE_FADE,
//		SEL_GAME_MODE_FALL_STACK,
//		SEL_GAME_MODE_LOADING,
//		SEL_GAME_MODE_LOAD,
		SEL_GAME_MODE_EXIT,
		};


// Search directions
enum	{
		SEL_FIND_PREV,
		SEL_FIND_NEXT,
		};

// World identifiers
enum	{
		SEL_WORLD_ID_SUBURBIA,
		SEL_WORLD_ID_ORIGINAL,
		SEL_WORLD_ID_SWAMP,								
		SEL_WORLD_ID_SEWER = SEL_WORLD_ID_SWAMP,		
		SEL_WORLD_ID_SKY,
		SEL_WORLD_ID_FOREST,
		SEL_WORLD_ID_VOLCANO,
		SEL_WORLD_ID_DESERT,
		SEL_WORLD_ID_CAVES,
		SEL_WORLD_ID_JUNGLE_RIVER,
		SEL_WORLD_ID_RUINED_CITY,
		};



// Arcade level identifiers
enum	{
		SEL_ARCADE_LEVEL_1_ID,
		SEL_ARCADE_LEVEL_2_ID,
		SEL_ARCADE_LEVEL_3_ID,
		SEL_ARCADE_LEVEL_4_ID,
		SEL_ARCADE_LEVEL_5_ID,
		};

// Race level identifiers
enum	{
		SEL_RACE_LEVEL_1_ID,
		};


// Level counts per theme

#define	SEL_SUBURBIA_ARC_LEVELS		(5)
#define	SEL_ORIGINAL_ARC_LEVELS		(5)
#define	SEL_SWAMP_ARC_LEVELS		(5)
#define	SEL_SKY_ARC_LEVELS			(4)
#define	SEL_FOREST_ARC_LEVELS		(2)
#define	SEL_VOLCANO_ARC_LEVELS		(3)
#define	SEL_DESERT_ARC_LEVELS		(5)
#define	SEL_CAVES_ARC_LEVELS		(3)
#define	SEL_JUNGLE_ARC_LEVELS		(1)

#define	SEL_SUBURBIA_RACE_LEVELS	(1)
#define	SEL_ORIGINAL_RACE_LEVELS	(1)
#define	SEL_FOREST_RACE_LEVELS		(1)
#define	SEL_VOLCANO_RACE_LEVELS		(1)
#define	SEL_JUNGLE_RACE_LEVELS		(1)

// Select BG sprites
#define	SELECT_BG_ONSCREEN_TILES_X	8
#define	SELECT_BG_ONSCREEN_TILES_Y	6
#define	SELECT_BG_TILE_MOVE_SPEED	24

#define	BG_UP				(1<<0)								// For a bit of randomness.
#define	BG_DOWN				(1<<1)
#define	BG_RIGHT			(1<<2)
#define	BG_LEFT				(1<<3)


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__sel_level_mof		SEL_LEVEL_MOF;
typedef	struct	__sel_level_info	SEL_LEVEL_INFO;
typedef	struct	__sel_world_info	SEL_WORLD_INFO;
typedef	struct	__sel_info			SEL_INFO;
//typedef struct	__select_object		SELECT_OBJECT;
//typedef struct	__select_path		SELECT_PATH;
//typedef struct	__select_camera_info SELECT_CAMERA_INFO;

struct	__sel_level_mof								  					
		{
		MR_MOF			sm_mof;
		MR_PART			sm_part;
		MR_PARTCEL		sm_partcel;
		MR_SVEC			sm_verts[SEL_VERTS_PER_LEVEL_MOF];
		MR_SVEC			sm_norms[SEL_POLYS_PER_LEVEL_MOF];
		MR_MPRIM_HEADER	sm_prim_header;
		MR_MPRIM_FT4	sm_prims[SEL_POLYS_PER_LEVEL_MOF];

		};	// SEL_LEVEL_MOF


struct	__sel_level_info
		{
		MR_LONG			li_library_id;									// Index into game library, also the level identifier
		MR_ULONG		li_world_id;									// World identifier (for VLO/model stuff)
		MR_ULONG		li_stack_pos;									// %wb - Position in stack ( 0 - top, etc ).
		MR_ULONG		li_theme_no;									// $wb - Alphabetical ordered theme numbers ( required for golden frog look up )
		MR_ULONG		li_level_within_world;							// Must be >= 0 and < levels within world
		MR_ULONG		li_levels_in_world;								// Cheesy number of levels within the world
		MR_TEXTURE*		li_world_image_selectable;						// Cheesy pointer to image for the world (selectable)
		MR_TEXTURE*		li_world_image_visited;							// Cheesy pointer to image for the world (visited)
		MR_TEXTURE*		li_world_image_not_tried;						// Cheesy pointer to image for the world (not-tried)
		MR_TEXTURE*		li_level_texture;								// Pointer to specific texture to represent this level
		MR_TEXTURE*		li_level_name_texture;							// Pointer to specific texture showing this level name
		MR_TEXTURE*		li_level_name_texture_in_game;					// Pointer to specific texture showing this level name (IN GAME)
		MR_ULONG		li_flags;										// Flags for this level
		SEL_LEVEL_MOF*	li_level_mof;									// Pointer to this levels MOF
		MR_OBJECT*		li_object;										// Pointer to owning object for destruction purposes
		MR_MESH_INST*	li_mesh_inst;									// Pointer to mesh instance for manipulation
		MR_FRAME*		li_frame;										// Pointer to owning frame
		POLY_FT4*		li_polys[2];									// Pointers to primitives in mesh instance for each frame
		MR_OT*			li_ot;											// Local OT for when sliding out (so we can offset in Z)	
		MR_LONG			li_current_z;									// Z level is at (when sliding out). zero = not sliding
		MR_LONG			li_y_size;										// Y size of this level (based on box height and number of levels in group)
		MR_LONG			li_y_position;									// Y position of center of level

		};	// SEL_LEVEL_INFO
																

struct	__sel_world_info												 
		{
		MR_ULONG		wi_init_flags;									// Non-writable version of flags (for re-initialisation)
		MR_TEXTURE*		wi_normal_texture;								// Pointer to texture for arcade mode representation
		MR_TEXTURE*		wi_dim_texture;									// Pointer to texture for race mode representation
		MR_TEXTURE*		wi_grey_texture;								// Pointer to texture for race mode representation
		MR_TEXTURE*		wi_level_texture[SEL_ARCADE_LEVELS_PER_WORLD];	// Pointer to texture for each level holding image
		MR_TEXTURE*		wi_level_name[SEL_ARCADE_LEVELS_PER_WORLD];		// Pointer to texture for each level holding name
		MR_ULONG		wi_flags;										// Modifiable flags (copied from wi_init_flags on start)
		};	// SEL_WORLD_INFO

//struct	__select_object
//		{
//		MR_ULONG			so_flags;
//		MR_ULONG			so_type;
//		MR_SVEC				so_rot;
//		MR_VEC				so_vel;
//		MR_SVEC				so_ang_vel;
//		MR_FRAME*			so_frame_ptr;
//		MR_OBJECT*			so_object_ptr;
//		
//		MR_VEC				so_movement;
//		MR_VEC				so_pos;
//
//		MR_ULONG			so_path_number;		// Number of path to follow
//
//		struct __select_path*	so_path_ptr;	// Ptr to path info
//		MR_ULONG			so_spline_pos;		// 0 to 1<<MR_SPLINE_PARAM_SHIFT
//		MR_ULONG			so_spline_speed;	// Speed at which to move along spline
//		MR_ULONG			so_spline_number;	// Number of spline in path currently in
//		MR_SPLINE_MATRIX	so_spline_matrix;	// Spline matrix
//
//		};	// SELECT_OBJECT

//struct	__select_path
//		{
//		MR_ULONG			sp_num_splines;			// Number of splines in path
//		MR_SPLINE_HERMITE	sp_spline_hermite[10];	// Spline info
//		};

//struct	__select_camera_info
//		{
//		MR_VEC		sc_camera_pos;
//		MR_VEC		sc_camera_target;
//		};

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define ROUND_SHIFT_DOWN(a, b) (((a) + (1<<(b-1)))>>b)
// a = value to shift down
// b = number of bits to shift
//
// NOTE: - This is useful for say the case when you have a velocity which is shifted down
//			and then added to a position. If you don't round the shift then biasing can
//			occur as a side effect. e.g 1>>1 = 0 but -1>>1 = -1 !
//			Hopefully this macro has a fairly small overhead,
//			but is still quicker than doing a divide.

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//extern	MR_VIEWPORT*	SelectBG_viewport_ptr;					// Viewport for scrolly background
extern	MR_LONG			Sel_mode;								// Mode of operation - single or multiplayer

extern	MR_BOOL			Sel_first_time;

extern	SEL_LEVEL_INFO	Sel_arcade_levels[];					//     score view.
extern	SEL_LEVEL_INFO	Sel_race_levels[];
extern	MR_LONG			Sel_game_mode;
extern	MR_LONG			Sel_spin_mode;
extern	MR_LONG			Sel_spin_time;
extern	MR_LONG			Sel_spin_max_time;
extern	MR_2DSPRITE*	Sel_user_prompt;
extern	MR_FRAME*		Sel_spin_frame;
extern	MR_VEC			Sel_temp_pos;
extern	MR_VEC			Sel_temp_vec_y;
extern	MR_VEC			Sel_temp_vec_roll;
extern	MR_2DSPRITE*	Sel_level_title;
extern	MR_LONG			Sel_status_temp_x;
extern	MR_TEXT_AREA*	Sel_score_line[];
extern	MR_LONG			Sel_camera_vel;
extern	MR_LONG			Sel_camera_acc;
extern	MR_LONG			Sel_camera_y;
extern	MR_LONG			Sel_camera_flag;
extern	MR_FRAME*		Sel_camera_frame;
extern	MR_LONG			Sel_target_y;
extern	SEL_LEVEL_INFO*	Sel_level_ptr;
extern	SEL_LEVEL_INFO*	Sel_work_level_ptr;
extern	MR_STRPTR		Sel_hiscore_text[3][25];
extern	MR_BOOL			Sel_requested_play;
extern	MR_VIEWPORT*	Sel_viewport;
extern	MR_LONG			Sel_status_start_x;
extern	SEL_LEVEL_INFO*	Sel_arcade_level_ptr;
extern	SEL_LEVEL_INFO*	Sel_race_level_ptr;

extern	MR_ULONG		Sel_vlo_res_id[];

extern	MR_LONG			Sel_camera_y_offset;

extern	MR_2DSPRITE*	Sel_loading_sprite_ptr;
extern	MR_2DSPRITE*	Sel_level_title;

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		SelectLevelClearLevelFlags(MR_VOID);
extern	MR_VOID		SelectLevelInitialiseLevelFlags(MR_VOID);

extern	MR_VOID		SelectLevelInit(MR_VOID);
extern	MR_VOID		SelectSetLevelFlags(MR_LONG, MR_ULONG);
extern	MR_ULONG	SelectGetLevelFlags(MR_LONG);
extern	SEL_LEVEL_INFO*	SelectGetLevelPointer(MR_LONG);

extern	MR_VOID		SelectLevelStartup(MR_VOID);
extern	MR_VOID		SelectLevelShutdown(MR_VOID);
extern	MR_VOID		SelectLevelUpdate(MR_VOID);
extern	MR_VOID		SelectCreateScene(MR_VOID);
extern	MR_VOID		SelectCreateMOF(SEL_LEVEL_MOF*, SEL_LEVEL_INFO*);

extern	MR_VOID		SelectUpdateGlowyColours(MR_VOID);
					
extern	MR_VOID		SelectUpdate_MODE_SELECTING(MR_VOID);
extern	MR_VOID		SelectUpdateLevelZ(SEL_LEVEL_INFO*);
extern	MR_VOID		SelectUpdateLevelSlide(MR_VOID);
extern	MR_BOOL		SelectFindTarget(MR_LONG direction);
					
extern	MR_VOID		SelectUpdate_MODE_SHOW_LEVEL_INFO(MR_VOID);
extern	MR_VOID		SelectEnableSpinMOF(SEL_LEVEL_INFO*);
extern	MR_VOID		SelectDisableSpinMOF(MR_VOID);
extern	MR_VOID		SelectUpdateInterpolation(MR_VOID);

extern	MR_VOID		SelectLevelCreateBG(MR_VOID);
extern	MR_VOID		SelectLevelUpdateBG(MR_VOID);
extern	MR_VOID		SelectLevelKillBG(MR_VOID);

extern	MR_VOID		SelectLevelCollectGoldFrog(MR_VOID);

#endif	//__SELECT_H

