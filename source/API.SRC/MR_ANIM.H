/******************************************************************************
*%%%% mr_anim.h
*------------------------------------------------------------------------------
*
*	Functions for handling animated MOFs
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	07.08.96	Tim Closs		Created
*	15.10.96	Tim Closs		Added basic environment and event handling.
*									MR_ANIM_MESH removed from mr_big.h and placed here
*									New flags added for environments and events
*	21.10.96	Tim Closs		Added MRAnimSetAction(), MRAnimSetCel(), total_cels
*									field in environments
*	31.10.96	Tim Closs		Added MR_ANIM_ENV_INST structure
*	20.11.96	Tim Closs		Altered all animation functions, added low level
*									functions
*	10.01.97	Tim Closs		MRAnimCreateEnvSingle/MultipleEntirely changed to
*									MRAnimCreateWholeEnvSingle/Multiple
*								Added:
*									MRAnimEnvUpdateLWTransforms()
*									MRAnimEnvSetFlags()
*									MRAnimEnvClearFlags()
*									MRAnimEnvGetFlags()
*									MRAnimEnvSetSpecialFlags()
*									MRAnimEnvClearSpecialFlags()
*									MRAnimEnvGetSpecialFlags()
*
*	14.01.97	Tim Closs		Added:
*									MRAnimEnvSingleSetPartFlags()
*									MRAnimEnvSingleClearPartFlags()
*									MRAnimEnvSingleGetPartFlags()
*									MRAnimEnvMultipleSetPartFlags()
*									MRAnimEnvMultipleClearPartFlags()
*									MRAnimEnvMultipleGetPartFlags()
*									MRAnimEnvSingleSetImportedTransform()
*									MRAnimEnvSingleClearImportedTransform()
*									MRAnimEnvMultipleSetImportedTransform()
*									MRAnimEnvMultipleClearImportedTransform()
*									MRAnimRemoveEnvInstanceFromViewport()
*									MRAnimEnvDestroyByDisplay()
*									Added support for type '1' files (byte transforms)
*									and MR_MAT34B structure
*									Added MR_ANIM_ENV_DESTROY_BY_DISPLAY flag
*	15.01.97	Tim Closs		Added:
*									MRAnimEnvSingleGetImportedTransform()
*									MRAnimEnvMultipleGetImportedTransform()
*									MRAnimEnvSingleSetAction()
*									MRAnimEnvSingleSetCel()
*									MRAnimEnvMultipleSetAction()
*									MRAnimEnvMultipleSetCel()
*									MRAnimEnvMultipleSetActionAll()
*									MRAnimEnvMultipleSetCelAll()
*								Removed:
*									MRAnimSetAction()
*									MRAnimSetCel()
*									MRAnimKillEnvInst()
*	17.01.97	Tim Closs		Renamed and added so much stuff I can't be bothered
*								to detail it
*	20.01.97	Tim Closs		Added all events functions
*	22.01.97	Tim Closs		Added support for MR_ANIM_ENV_NOT_ACTIVE and
*								MR_ANIM_ENV_ONE_SHOT_AND_KILL
*								Added MRAnimRemoveEnvInstanceFromViewportPhysically()
*	23.01.97	Dean Ashton		Removed MRAnimUnresolveMOFTextures()
*	10.02.97	Tim Closs		Added MRAnimEnvUpdateModelLWTransforms()
*	17.02.97	Tim Closs		Added MR_ANIM_PART_REDUNDANT
*	18.03.97	Tim Closs		Added MR_QUATB_TRANS and MR_ANIM_FILE_ID_QUAT_TRANSFORMS
*	19.03.97	Tim Closs		Created MR_ANIM_CPT_PARAMS structure for passing
*								parameters into MRAnimCalculatePartTransform()
*	24.03.97	Tim Closs		Removed all Multiple specific functions to mr_anim2
*	12.06.97	Tim Closs		New file transform type:
*								MR_ANIM_FILE_ID_QUAT_TRANSFORMS		(16bit quaternion)
*								New structure:
*								MR_QUAT_TRANS
*								New flags (MR_ANIM_CELS now has flags field)
*								MR_ANIM_CELS_VIRTUAL_STANDARD
*								MR_ANIM_CELS_VIRTUAL_INTERPOLATION
*	13.06.97	Tim Closs		New file transform types:
*								MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS		(8bit quaternion, scaled)
*								MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS		(16bit quaternion, scaled)
*								New structures:
*								MR_QUAT_SCALE_TRANS
*								MR_QUATB_SCALE_TRANS
*								New flags (scaled transform have flags field):
*								MR_QUAT_SCALE_TRANS_USE_SCALING
*								New define:
*								MR_QUAT_SCALE_TRANS_FIXED_POINT
*	18.06.97 	Tim Closs		Added support for MR_ANIM_ENV_FLIPBOOK
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef struct __mr_vec3					MR_VEC3;
typedef struct __mr_vec4					MR_VEC4;
typedef struct __mr_mat34					MR_MAT34;
typedef struct __mr_mat34b					MR_MAT34B;
typedef struct __mr_quat_trans				MR_QUAT_TRANS;
typedef struct __mr_quatb_trans				MR_QUATB_TRANS;
typedef struct __mr_quat_scale_trans		MR_QUAT_SCALE_TRANS;
typedef struct __mr_quatb_scale_trans		MR_QUATB_SCALE_TRANS;

typedef struct __mr_anim_header				MR_ANIM_HEADER;
typedef struct __mr_anim_model_set			MR_ANIM_MODEL_SET;
typedef struct __mr_anim_model				MR_ANIM_MODEL;
typedef struct __mr_anim_cel_set			MR_ANIM_CEL_SET;
typedef struct __mr_anim_cels				MR_ANIM_CELS;
typedef struct __mr_anim_cels_parts			MR_ANIM_CELS_PARTS;
typedef struct __mr_anim_bbox_set			MR_ANIM_BBOX_SET;
typedef struct __mr_anim_bboxes				MR_ANIM_BBOXES;
typedef struct __mr_anim_model_object		MR_ANIM_MODEL_OBJECT;
typedef struct __mr_anim_model_point		MR_ANIM_MODEL_POINT;
typedef struct __mr_anim_constraint			MR_ANIM_CONSTRAINT;
typedef struct __mr_anim_common_data		MR_ANIM_COMMON_DATA;
typedef struct __mr_anim_env				MR_ANIM_ENV;
typedef struct __mr_anim_env_single			MR_ANIM_ENV_SINGLE;
typedef struct __mr_anim_env_multiple		MR_ANIM_ENV_MULTIPLE;
typedef struct __mr_anim_env_flipbook		MR_ANIM_ENV_FLIPBOOK;
typedef struct __mr_anim_event				MR_ANIM_EVENT;
typedef struct __mr_anim_event_list			MR_ANIM_EVENT_LIST;
typedef struct __mr_anim_mesh				MR_ANIM_MESH;
typedef struct __mr_anim_env_inst			MR_ANIM_ENV_INST;
typedef struct __mr_anim_env_param			MR_ANIM_ENV_PARAM;
typedef struct __mr_anim_cpt_params			MR_ANIM_CPT_PARAMS;

#else
#ifndef	__MR_ANIM_H
#define	__MR_ANIM_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// File types
#define MR_ANIM_FILE_ID_NORMAL					'0'
#define MR_ANIM_FILE_ID_BYTE_TRANSFORMS			'1'
#define MR_ANIM_FILE_ID_QUATB_TRANSFORMS		'2'
#define MR_ANIM_FILE_ID_QUAT_TRANSFORMS			'3'
#define MR_ANIM_FILE_ID_QUATB_SCALE_TRANSFORMS	'4'
#define MR_ANIM_FILE_ID_QUAT_SCALE_TRANSFORMS	'5'

#define	MR_ANIM_FILE_START_FRAME_AT_ZERO		'1'

// MR_ANIM_MODEL_SET flags
#define MR_ANIM_MODEL_SET_HIERARCHICHAL			(1<<0)

// MR_ANIM_MODEL flags
#define MR_ANIM_GLOBAL_BBOXES_INCLUDED			(1<<0)
#define MR_ANIM_PERCEL_BBOXES_INCLUDED			(1<<1)

// MR_QUAT_SCALE_TRANS flags
#define MR_QUAT_SCALE_TRANS_USE_SCALING			(1<<0)
#define MR_QUAT_SCALE_TRANS_FIXED_POINT			5			// fractional bits in byte scale values

// MR_ANIM_CELS flags
#define MR_ANIM_CELS_VIRTUAL_STANDARD			(1<<0)		// standard virtual cels
#define MR_ANIM_CELS_VIRTUAL_INTERPOLATION		(1<<1)		// virtual cel indices are read as (prev, next, interp. value)

// Anim constraint flags
#define MR_ANIM_CONSTRAINT_IS_OBJECT			(1<<0)
#define MR_ANIM_CONSTRAINT_IS_POINT				(1<<1)

// MR_ANIM_COMMON_DATA flags
#define MR_ANIM_COMMON_TRANSFORMS_PRESENT		(1<<0)
#define MR_ANIM_COMMON_ROTATIONS_PRESENT		(1<<1)
#define MR_ANIM_COMMON_TRANSLATIONS_PRESENT		(1<<2)
#define MR_ANIM_COMMON_BBOXES_PRESENT			(1<<3)

// MR_ANIM_ENV flags
#define MR_ANIM_ENV_NOT_ACTIVE					(1<<0)		// environment is effectively removed from linked list
#define MR_ANIM_ENV_MODELS_ORDERED				(1<<1)
#define MR_ANIM_ENV_IS_MULTIPLE					(1<<2)		// environment is MR_ANIM_ENV_MULTIPLE
#define MR_ANIM_ENV_ONE_SHOT					(1<<8)		// action plays to end and stops at last frame
#define MR_ANIM_ENV_ONE_SHOT_AND_KILL			(1<<9)		// action plays to end, then environment is killed

#define MR_ANIM_ENV_STEP						(1<<10)		// env will increase virtual cel number
#define MR_ANIM_ENV_UPDATE						(1<<11)		//	env will calculate lw transforms
#define MR_ANIM_ENV_DISPLAY						(1<<12)		// env will display
#define MR_ANIM_ENV_DESTROY_BY_DISPLAY			(1<<13)		// environment will be killed
#define MR_ANIM_ENV_IS_FLIPBOOK					(1<<14)		// environment is MR_ANIM_ENV_FLIPBOOK

#define MR_ANIM_ENV_DEFAULT_FLAGS				(MR_ANIM_ENV_STEP | MR_ANIM_ENV_UPDATE | MR_ANIM_ENV_DISPLAY)

// Environment special flags
#define MR_ANIM_ENV_DISPLAY_LIMITED_PARTS		(1<<0)		// use part flags 			(if they exist)
#define MR_ANIM_ENV_EVENT_LIST_ACTIVE		 	(1<<1)		// use events 					(if they exist)
#define MR_ANIM_ENV_PARAMS_ACTIVE				(1<<2)		// use parameters 			(if they exist)
#define MR_ANIM_ENV_USER_CALLBACK_ACTIVE		(1<<3)		// use user callback 		(if it exists)
#define MR_ANIM_ENV_STORE_LW_TRANSFORMS			(1<<4)		// store lw transforms		(if they exist)
#define MR_ANIM_ENV_IMPORTED_TRANSFORMS			(1<<5)		// use imported transforms	(if they exist)

// Environment part flags
#define MR_ANIM_PART_DISPLAY					(1<<0)		// display part
#define MR_ANIM_PART_TRANSFORM_PART_SPACE		(1<<1)		// imported transform acts in part space
#define MR_ANIM_PART_TRANSFORM_MODEL_SPACE		(1<<2)		// imported transform acts in model space
#define MR_ANIM_PART_REDUNDANT					(1<<3)		// part is NEVER transformed or displayed

// MR_ANIM_MODEL animation types
#define MR_ANIM_OBJECT							(1)
#define MR_ANIM_SKIN							(2)
#define MR_ANIM_QUICK_SKIN						(3)

// Anim constraint types
#define MR_ANIM_CONSTRAINT_LOOSE				(1<<24)
#define MR_ANIM_CONSTRAINT_TIGHT				(2<<24)
#define MR_ANIM_CONSTRAINT_TIGHT_NON_CO			(3<<24)
#define MR_ANIM_CONSTRAINT_PASSIVE				(4<<24)
#define MR_ANIM_CONSTRAINT_ACTIVE 				(5<<24)

#define MR_ANIM_CONSTRAINT_GEOMETRICAL			(1<<16)
#define MR_ANIM_CONSTRAINT_DIRECTIONAL			(2<<16)

#define MR_ANIM_CONSTRAINT_TRANSLATION			(1<<8)
#define MR_ANIM_CONSTRAINT_ROTATION				(2<<8)
#define MR_ANIM_CONSTRAINT_SCALE				(3<<8)
#define MR_ANIM_CONSTRAINT_TRANSFORM			(4<<8)
#define MR_ANIM_CONSTRAINT_VELOCITY				(5<<8)
#define MR_ANIM_CONSTRAINT_FORCE				(6<<8)

#define MR_ANIM_CONSTRAINT_HIERARCHY_NONE		(1)
#define MR_ANIM_CONSTRAINT_HIERARCHY_LOCAL		(2)
#define MR_ANIM_CONSTRAINT_HIERARCHY_YES		(3)

// Events
enum	{
		MR_ANIM_EVENT_MODE_STANDARD,
		MR_ANIM_EVENT_MODE_SEARCH,
		};
#define	MR_ANIM_EVENT_EMPTY						0xffff


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct __mr_vec3
	{
	MR_SHORT		vx;
	MR_SHORT		vy;
	MR_SHORT		vz;
	
	};	//	MR_VEC3


struct __mr_vec4
	{
	MR_SHORT		vx;
	MR_SHORT		vy;
	MR_SHORT		vz;
	MR_SHORT		t;

	};	//	MR_VEC4


struct __mr_mat34
	{
	MR_SHORT		m[3][3];
	MR_SHORT		t[3];

	};	// MR_MAT34


struct __mr_mat34b
	{
	MR_BYTE		m[3][3];
	MR_BYTE		pad;
	MR_SHORT		t[3];

	};	// MR_MAT34B


struct __mr_quat_trans
	{
	MR_QUAT			q;
	MR_SHORT		t[3];

	};	// MR_QUAT_TRANS


struct __mr_quatb_trans
	{
	MR_QUATB		q;			// 8bit quaternion
	MR_SHORT		t[3];		

	};	// MR_QUATB_TRANS


struct __mr_quat_scale_trans
	{
	MR_QUAT			q;			// 16bit quaternion
	MR_SHORT		t[3];		
	MR_BYTE			s[3];		// 3.5 scaling x,y,z	
	MR_BYTE			flags;		// bit 0 set if scaling used

	};	// MR_QUAT_SCALE_TRANS


struct __mr_quatb_scale_trans
	{
	MR_QUATB		q;			// 8bit quaternion
	MR_SHORT		t[3];		
	MR_BYTE			s[3];		// 3.5 scaling x,y,z	
	MR_BYTE			flags;		// bit 0 set if scaling used

	};	// MR_QUATB_SCALE_TRANS


struct 	__mr_anim_header
	{
	MR_LONG 				ah_id;						// note that these first 3 fields MUST BE identical to MR_MOF
	MR_LONG					ah_length;
	MR_LONG 				ah_flags;
	MR_USHORT				ah_no_of_model_sets;
	MR_USHORT				ah_no_of_static_files;
	MR_ANIM_MODEL_SET* 		ah_model_sets;
	MR_ANIM_COMMON_DATA*	ah_common_data;
	MR_MOF**				ah_static_files;

	};	//	MR_ANIM_HEADER


struct	__mr_anim_model_set
	{
	MR_ULONG 				am_type;
	MR_UBYTE				am_no_of_models;
	MR_UBYTE				am_no_of_cel_sets;
	MR_UBYTE				am_no_of_bbox_sets;
	MR_UBYTE    			am_pad;
	MR_ANIM_MODEL* 			am_models;
	MR_ANIM_CEL_SET*		am_cel_set;
	MR_ANIM_BBOX_SET*		am_bbox_sets;

	};	//	MR_ANIM_MODEL_SET


struct	__mr_anim_model
{
	MR_USHORT 				am_animation_type;
	MR_USHORT 				am_flags;
	MR_USHORT 				am_no_of_parts;
	MR_USHORT				am_static_model;
	MR_ANIM_CEL_SET*		am_cel_set;
	MR_BBOX*				am_static_bbox;
	MR_ANIM_BBOX_SET*		am_bbox_set;
	MR_ANIM_CONSTRAINT*		am_constraint;

	};	// MR_ANIM_MODEL


struct	__mr_anim_mesh
	{
	MR_ANIM_ENV*			am_environment;			// pointer to environment which owns this mesh
	MR_ULONG				am_model_no;   			// model number within multiple environment

	};	// MR_ANIM_MESH


struct	__mr_anim_cel_set
	{
	MR_USHORT 				ac_no_of_cels_structures;
	MR_USHORT 				ac_pad;
	union u_cels
		{
		MR_ANIM_CELS*		ac_cels;
		MR_ANIM_CELS_PARTS*	ac_cels_parts;
		} ac_cels;

	};	//	MR_ANIM_CEL_SET


struct	__mr_anim_cels
	{
	MR_USHORT 				ac_no_of_cels;
	MR_USHORT 				ac_no_of_parts;
	MR_USHORT 				ac_no_of_virtual_cels;
	MR_USHORT 				ac_flags;						// new
	MR_USHORT*				ac_cel_numbers;
	union u_transforms
		{
		MR_SHORT* 			ac_indices;
		MR_MAT34*			ac_transforms;					// this is never used: transforms are ALWAYS indexed
		}	ac_transforms;

	};	//	MR_ANIM_CELS


struct	__mr_anim_cels_parts									// this is never used
	{
	MR_USHORT 				ac_no_of_cels;
	MR_USHORT 				ac_no_of_parts;
	MR_USHORT 				ac_no_of_virtual_cels;
	MR_USHORT 				ac_pad;
	MR_USHORT*				ac_cel_numbers;
	MR_USHORT*				ac_rotations;				
	MR_USHORT*				ac_translations;

	};	//	MR_ANIM_CELS_PARTS


struct	__mr_anim_bbox_set
	{
	MR_SHORT 				ab_no_of_bbox_structures;
	MR_SHORT 				ab_pad;
	MR_ANIM_BBOXES*			ab_bboxes;

	};	//	MR_ANIM_BBOX_SET


struct	__mr_anim_bboxes
	{
	MR_SHORT 				ab_no_of_cels;
	MR_SHORT          		ab_pad;
	union u_bboxes
		{
		MR_SHORT* 			ab_indices;
		MR_BBOX*			ab_bboxes;
		} ab_bboxes;

	};	//	MR_ANIM_BBOXES


struct	__mr_anim_model_object
	{
	MR_ANIM_MODEL*			am_model;
	MR_SHORT 				am_object;
	MR_SHORT 				am_pad;

	};	//	MR_ANIM_MODEL_OBJECT


struct	__mr_anim_model_point
	{
	MR_ANIM_MODEL*			am_model;
	MR_SHORT 				am_object;
	MR_SHORT 				am_pad;
	MR_VEC					am_point;
	
	};	//	MR_ANIM_MODEL_POINT


struct	__mr_anim_constraint
	{
	MR_LONG 				ac_type;
	MR_LONG 				ac_flags;
	MR_ULONG*				ac_initial_condition;
	MR_ULONG*				ac_constant_part;
	union
		{
		MR_ANIM_MODEL_OBJECT*	ac_object;
		MR_ANIM_MODEL_POINT*	ac_point;
		} ac_root;
	union
		{
		MR_ANIM_MODEL_OBJECT*	ac_object;
		MR_ANIM_MODEL_POINT*	ac_point;
		} ac_child;

	MR_ULONG*				ac_root_parameters;
	MR_ULONG*				ac_child_parameters;
	
	};	//	MR_ANIM_CONSTRAINT


struct	__mr_anim_env
	{
	MR_ANIM_ENV*			ae_prev_node;
	MR_ANIM_ENV*			ae_next_node;
	MR_USHORT 				ae_flags;
	MR_USHORT 				ae_special_flags;
	MR_USHORT				ae_update_count;
	MR_USHORT 				ae_update_period;
	MR_USHORT 				ae_vp_inst_count;
	MR_USHORT 				ae_pad;
	MR_ANIM_HEADER*			ae_header;
	MR_ANIM_MODEL_SET*		ae_model_set;
	MR_VOID					(*ae_user_callback)(MR_ANIM_ENV*);

	union		
		{
		MR_VOID*				ae_extra_void;
		MR_ANIM_ENV_SINGLE*		ae_extra_env_single;
		MR_ANIM_ENV_MULTIPLE*	ae_extra_env_multiple;
		MR_ANIM_ENV_FLIPBOOK*	ae_extra_env_flipbook;
		} ae_extra;

	}; // MR_ANIM_ENV


struct	__mr_anim_env_single
	{
	MR_ANIM_MODEL*			ae_model;
	MR_OBJECT*				ae_object;
	MR_SHORT				ae_pad;
	MR_SHORT				ae_total_cels;
	MR_SHORT				ae_last_cel_number;
	MR_SHORT				ae_last_action_number;
	MR_SHORT				ae_cel_number;
	MR_SHORT				ae_action_number;
	MR_UBYTE*				ae_parts_flags;
	MR_ANIM_EVENT**			ae_events;
	MR_MAT*					ae_lw_transforms;
	MR_MAT**				ae_imported_transforms;
	MR_ANIM_ENV_PARAM*		ae_parameters;
	MR_VOID*				ae_user_struct;

	};	//	MR_ANIM_ENV_SINGLE


struct	__mr_anim_env_multiple
	{
	MR_ANIM_MODEL**			ae_models;
	MR_OBJECT**				ae_objects;
	MR_UBYTE				ae_no_of_models;
	MR_UBYTE				ae_pad[3];
	MR_SHORT*				ae_total_cels;
	MR_SHORT*				ae_last_cel_number;
	MR_SHORT*				ae_last_action_number;
	MR_SHORT*				ae_cel_number;
	MR_SHORT*				ae_action_number;
	MR_MAT34**				ae_transforms;
	MR_SHORT**				ae_no_of_transforms;
	MR_UBYTE*				ae_model_order;
	MR_UBYTE**				ae_parts_flags;
	MR_ANIM_EVENT***		ae_events;
	MR_MAT**				ae_lw_transforms;
	MR_MAT***				ae_imported_transforms;
	MR_ANIM_ENV_PARAM*		ae_parameters;
	MR_VOID*				ae_user_struct;


	};	//	MR_ANIM_ENV_MULTIPLE


struct	__mr_anim_env_flipbook
	{
	MR_OBJECT*				ae_object;
	MR_SHORT				ae_pad;
	MR_SHORT				ae_total_cels;
	MR_SHORT				ae_last_cel_number;
	MR_SHORT				ae_last_action_number;
	MR_SHORT				ae_cel_number;
	MR_SHORT				ae_action_number;
	MR_ANIM_EVENT**			ae_events;

	};	//	MR_ANIM_ENV_FLIPBOOK


struct	__mr_anim_env_inst
	{	
	MR_ANIM_ENV_INST*		ae_next_node;				// ptr to next in linked list
	MR_ANIM_ENV_INST*		ae_prev_node;				// ptr to prev in linked list
	MR_ANIM_ENV*			ae_environment;				// ptr to environment instanced
	MR_VIEWPORT*			ae_viewport;				// ptr to viewport instanced in
	MR_USHORT				ae_models;					// number of models
	MR_USHORT				ae_kill_timer;				// counts down to 0, then instance is removed
	MR_MESH_INST**			ae_mesh_insts;				// pointer to array of MR_MESH_INST* (one for each model)

	};	// MR_ANIM_ENV_INST


struct	__mr_anim_common_data
	{
	MR_LONG					ac_flags;
	MR_SHORT				ac_no_of_transforms;
	MR_SHORT				ac_no_of_rotations;
	MR_SHORT				ac_no_of_translations;
	MR_SHORT				ac_no_of_bboxes;
	MR_MAT34*				ac_transforms;
	MR_MAT34*				ac_rotations;
	MR_VEC*					ac_translations;
	MR_BBOX*				ac_bboxes;
								
	};	//	MR_ANIM_COMMON_DATA


struct	__mr_anim_event
	{
	MR_UBYTE				ae_event_callback;
	MR_UBYTE				ae_user_param;

	};	// MR_ANIM_EVENT

 
struct	__mr_anim_event_list
	{
	MR_LONG					ae_mode;
	MR_LONG					ae_size;
	MR_LONG					ae_allocated;
	MR_LONG					ae_next;
	MR_LONG					(**ae_event_list)(MR_ANIM_EVENT, MR_VOID*);

	};	// MR_ANIM_EVENT_LIST


struct	__mr_anim_env_param
	{
	MR_ULONG				pad;

	};	// MR_ANIM_ENV_PARAM


struct	__mr_anim_cpt_params
	{
	MR_ANIM_CELS*			ac_cels_ptr;
	MR_USHORT				ac_model;
	MR_USHORT				ac_part;
	MR_USHORT				ac_cel;
	MR_USHORT				pad;

	};	// MR_ANIM_CPT_PARAMS



//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------

extern	MR_ANIM_ENV			MRAnim_env_root;
extern	MR_ANIM_ENV*		MRAnim_env_root_ptr;
extern	MR_USHORT			MRNumber_of_anim_envs;
extern	MR_ANIM_EVENT_LIST*	MRAnim_event_list;
 

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

// Resolution
extern	MR_VOID				MRAnimResolveMOF(MR_MOF*);
extern	MR_VOID				MRAnimResolveMOFTextures(MR_MOF*);
extern	MR_VOID				MRAnimPatchMOFTranslucency(MR_MOF*, MR_BOOL);

// Display
extern	MR_VOID				MRAnimDisplayMeshInstance(MR_MESH_INST*, MR_VIEWPORT*);

// General environment
extern	MR_VOID				MRAnimUpdateEnvironments(MR_VOID);
extern	MR_VOID				MRAnimKillEnv(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvCreateMeshes(MR_ANIM_ENV*,	MR_FRAME*, MR_USHORT);
extern	MR_VOID				MRAnimLinkEnv(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimUnlinkEnv(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvGetPartTransform(MR_ANIM_ENV*, MR_MAT*, MR_USHORT,	MR_USHORT);
extern	MR_VOID				MRAnimEnvUpdateLWTransforms(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvUpdateModelLWTransforms(MR_ANIM_ENV*, MR_ANIM_CELS*, MR_USHORT, MR_USHORT);
extern	MR_USHORT			MRAnimEnvSetFlags(MR_ANIM_ENV*, MR_USHORT);
extern	MR_USHORT			MRAnimEnvClearFlags(MR_ANIM_ENV*, MR_USHORT);
extern	MR_USHORT			MRAnimEnvGetFlags(MR_ANIM_ENV*);
extern	MR_USHORT			MRAnimEnvSetSpecialFlags(MR_ANIM_ENV*, MR_USHORT);
extern	MR_USHORT			MRAnimEnvClearSpecialFlags(MR_ANIM_ENV*, MR_USHORT);
extern	MR_USHORT			MRAnimEnvGetSpecialFlags(MR_ANIM_ENV*);
extern	MR_MAT*				MRAnimCalculatePartTransform(MR_ANIM_ENV*, MR_ANIM_CPT_PARAMS*);
extern	MR_VOID				MRAnimEnvDestroyByDisplay(MR_ANIM_ENV*);

// Instancing
extern	MR_ANIM_ENV_INST*	MRAnimAddEnvToViewport(MR_ANIM_ENV*, MR_VIEWPORT*, MR_USHORT);
extern	MR_VOID			 	MRAnimRemoveEnvInstanceFromViewport(MR_ANIM_ENV_INST*, MR_VIEWPORT*);
extern	MR_VOID			 	MRAnimRemoveEnvInstanceFromViewportPhysically(MR_ANIM_ENV_INST*, MR_VIEWPORT*);

// Single environment
extern	MR_ANIM_ENV*	 	MRAnimEnvSingleCreate(MR_VOID);
extern	MR_VOID			 	MRAnimEnvSingleLoad(MR_ANIM_ENV*, MR_ANIM_HEADER*, MR_USHORT, MR_USHORT);
extern	MR_ANIM_ENV*	 	MRAnimEnvSingleCreateWhole(MR_ANIM_HEADER*, MR_USHORT, MR_USHORT, MR_FRAME*);
extern	MR_UBYTE		 	MRAnimEnvSingleSetPartFlags(MR_ANIM_ENV*,	MR_USHORT, MR_UBYTE);
extern	MR_UBYTE		 	MRAnimEnvSingleClearPartFlags(MR_ANIM_ENV*, MR_USHORT, MR_UBYTE);
extern	MR_UBYTE		 	MRAnimEnvSingleGetPartFlags(MR_ANIM_ENV*,	MR_USHORT);
extern	MR_VOID			 	MRAnimEnvSingleDeletePartFlags(MR_ANIM_ENV*);
extern	MR_MAT*			 	MRAnimEnvSingleCreateLWTransforms(MR_ANIM_ENV*);
extern	MR_VOID			 	MRAnimEnvSingleDeleteLWTransforms(MR_ANIM_ENV*);
extern	MR_VOID			 	MRAnimEnvSingleSetImportedTransform(MR_ANIM_ENV*, MR_USHORT, MR_MAT*);
extern	MR_VOID			 	MRAnimEnvSingleClearImportedTransform(MR_ANIM_ENV*, MR_USHORT);
extern	MR_MAT*			 	MRAnimEnvSingleGetImportedTransform(MR_ANIM_ENV*, MR_USHORT);
extern	MR_VOID			 	MRAnimEnvSingleDeleteImportedTransforms(MR_ANIM_ENV*);
extern	MR_VOID			 	MRAnimEnvSingleSetAction(MR_ANIM_ENV*, MR_SHORT);
extern	MR_VOID			 	MRAnimEnvSingleSetCel(MR_ANIM_ENV*, MR_SHORT);

// Events
extern	MR_ANIM_EVENT_LIST*	MRAnimCreateEventList(MR_USHORT);
extern	MR_ANIM_EVENT_LIST*	MRAnimSetEventList(MR_ANIM_EVENT_LIST*);
extern	MR_VOID			 	MRAnimClearEventList(MR_ANIM_EVENT_LIST*);
extern	MR_VOID			 	MRAnimKillEventList(MR_ANIM_EVENT_LIST*);
extern	MR_ULONG		 	MRAnimAllocEvent(MR_LONG (*event)(MR_ANIM_EVENT, MR_VOID*));
extern	MR_VOID			 	MRAnimFreeEvent(MR_ULONG);
extern	MR_LONG				MRAnimEventCallback(MR_ANIM_EVENT);
extern	MR_LONG				MRAnimEnvEventCallback(MR_ANIM_EVENT, MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvSingleSetEvent(MR_ANIM_ENV*, MR_USHORT, MR_USHORT, MR_UBYTE, MR_UBYTE);
extern	MR_VOID				MRAnimEnvCheckEvents(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvSingleClearEvent(	MR_ANIM_ENV*, MR_USHORT, MR_USHORT);
extern	MR_VOID				MRAnimEnvCleanEvents(MR_ANIM_ENV*);
extern	MR_VOID				MRAnimEnvDeleteEvents(MR_ANIM_ENV*);

#endif	//__MR_ANIM_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS 
