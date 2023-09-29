/******************************************************************************
*%%%% camera.h
*------------------------------------------------------------------------------
*
*	Camera handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.04.97	Tim Closs		Created
*	08.07.97	Tim Closs		Added ca_offset_origin to CAMERA for Gary
*	30.07.97	Martin Kift		Added momentum code to camera in x/z plane
*
*%%%**************************************************************************/

#ifndef	__CAMERA_H
#define	__CAMERA_H

#include "mr_all.h"
#include "zone.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

//#define	DEBUG_DISPLAY_FROG_CAMERA_ZONES
//#define	CAMERA_DEBUG_DISPLAY_GRID
//#define	CAMERA_DEBUG_REMOTE
//#define	CAMERA_FORCE_DEFAULT
//#define	CAMERA_NO_NEW_ZONES

// Camera offsets
//
// Default (debug only)
#define	CAMERA_FROG_DEFAULT_SOURCE_OFS_X		0
#define	CAMERA_FROG_DEFAULT_SOURCE_OFS_Y		-500
#define	CAMERA_FROG_DEFAULT_SOURCE_OFS_Z		-500

#define	CAMERA_FROG_DEFAULT_TARGET_OFS_X		0
#define	CAMERA_FROG_DEFAULT_TARGET_OFS_Y		0
#define	CAMERA_FROG_DEFAULT_TARGET_OFS_Z		0

// Start
#define	CAMERA_FROG_START_SOURCE_OFS_X			200
#define	CAMERA_FROG_START_SOURCE_OFS_Y			-400
#define	CAMERA_FROG_START_SOURCE_OFS_Z			 400

#define	CAMERA_FROG_START_TARGET_OFS_X			0
#define	CAMERA_FROG_START_TARGET_OFS_Y			100
#define	CAMERA_FROG_START_TARGET_OFS_Z			0

#define	CAMERA_START_SWINGOUT_TIME				30

// Hit checkpoint
#define	CAMERA_FROG_CHECKPOINT_SOURCE_OFS_X		0
#define	CAMERA_FROG_CHECKPOINT_SOURCE_OFS_Y		-1000
#define	CAMERA_FROG_CHECKPOINT_SOURCE_OFS_Z		-100

#define	CAMERA_FROG_CHECKPOINT_TARGET_OFS_X		0
#define	CAMERA_FROG_CHECKPOINT_TARGET_OFS_Y		0
#define	CAMERA_FROG_CHECKPOINT_TARGET_OFS_Z		0
#define	CAMERA_FROG_CHECKPOINT_TIME				45

// Death
#define	CAMERA_FROG_DEATH_SOURCE_OFS_X			0
#define	CAMERA_FROG_DEATH_SOURCE_OFS_Y			-1000
#define	CAMERA_FROG_DEATH_SOURCE_OFS_Z			-100

#define	CAMERA_FROG_DEATH_TARGET_OFS_X			0
#define	CAMERA_FROG_DEATH_TARGET_OFS_Y			0
#define	CAMERA_FROG_DEATH_TARGET_OFS_Z			0
#define	CAMERA_FROG_DEATH_TIME					45

// Other
#define	CAMERA_ZONE_MOVE_TIME					30
#define	CAMERA_TWIST_TIME						8
#define	CAMERA_Y_MOVE_RATE						0x18
#define	CAMERA_X_MOVE_RATE						0x30
#define	CAMERA_Z_MOVE_RATE						0x30
#define	CAMERA_XZ_MINIMUM_OFFSET				0x05

#define	CAMERA_MOD_MATRIX_DELTA_YTHETA			0x20
#define	CAMERA_SELF_ROLL_TOLERANCE				0x20

// Shake
#define	CAMERA_SHAKE_FREQ_X						0x6000		// total input angle of shake sin function
#define	CAMERA_SHAKE_FREQ_Y						0x5000		

// Camera flags
#define	CAMERA_FLAG_SHAKING						(1<<0)
#define CAMERA_IGNORE_FROG_Y					(1<<1)		// Stop following the frog through Y

// Camera modes
enum	{
		CAMERA_MODE_FOLLOW_FROG,
		CAMERA_MODE_DEBUG,
		CAMERA_MODE_FIXED_SWEEP,
		CAMERA_MODE_START,
		CAMERA_MODE_FIXED,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__camera		CAMERA;

struct	__camera
	{
	MR_MAT*		ca_matrix;							// transform associated with camera
	MR_VEC*		ca_offset_origin;					// usually frog origin
	MR_ULONG	ca_mode;							// eg. CAMERA_MODE_FOLLOW_FROG
	MR_ULONG	ca_flags;							// eg. CAMERA_MODE_FOLLOW_FROG
	MR_ULONG	ca_id;								// camera id (0..3 for viewport 0..3)
	ZONE*		ca_zone;							// ptr to current camera zone
	MR_LONG		ca_move_timer;						// counts down to 0 as we move from current to next offsets

	// Offsets
	MR_SVEC		ca_current_source_ofs;				// current offset from frog to camera
	MR_SVEC		ca_current_target_ofs;				// current offset from frog to camera
	MR_SVEC		ca_next_source_ofs;					// next offset from frog to camera
	MR_SVEC		ca_next_target_ofs;					// next offset from frog to camera

	// Twist
	MR_LONG		ca_twist_counter;					// counts from +/-1 to +/-(CAMERA_TWIST_TIME * ca_twist_quadrants)
	MR_LONG		ca_twist_quadrants;					// usually 1 or 2
	MR_VEC		ca_current;							// camera current position (before adding source offset)

	// Rotation/direction
	MR_MAT		ca_mod_matrix;						// modification to camera matrix (eg. on moving entity, or on land with 90 deg rot)
	MR_VEC		ca_direction_vectors[4];			// these are set by camera code to move in screen coords
	MR_VEC		ca_frog_direction_vectors[4];		// these are set by camera code to move in screen coords
	MR_LONG		ca_frog_controller_directions[4];	// which world XZ direction does "UP" correspond to, etc?
	MR_LONG		ca_mod_matrix_delta_ytheta;			// if non-0, ca_mod_matrix is being generated from current_ytheta
	MR_LONG		ca_mod_matrix_current_ytheta;		// current ytheta, moves by delta_ytheta to dest_ytheta
	MR_LONG		ca_mod_matrix_dest_ytheta;			// dest ytheta (multiple of 0x400)

	// Shake
	MR_LONG		ca_shake_amp_x;						// camera shake x amplitude
	MR_LONG		ca_shake_amp_y;						// camera shake y amplitude
	MR_LONG		ca_shake_duration;					// camera shake duration
	MR_LONG		ca_shake_timer;						// camera shake timer
	MR_LONG		ca_shake_freq_x;					// camera shake x frequency
	MR_LONG		ca_shake_freq_y;					// camera shake y frequency
	
	};	// CAMERA


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS		MR_COPY_SVEC(&camera->ca_next_source_ofs, &Map_general_header->gh_default_camera_source_ofs)
#define	CAMERA_SET_DEFAULT_NEXT_TARGET_OFS		MR_COPY_SVEC(&camera->ca_next_target_ofs, &Map_general_header->gh_default_camera_target_ofs)
#define	CAMERA_SET_DEFAULT_CURRENT_SOURCE_OFS	MR_COPY_SVEC(&camera->ca_current_source_ofs, &Map_general_header->gh_default_camera_source_ofs)
#define	CAMERA_SET_DEFAULT_CURRENT_TARGET_OFS	MR_COPY_SVEC(&camera->ca_current_target_ofs, &Map_general_header->gh_default_camera_target_ofs)


//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	CAMERA		Cameras[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		InitialiseCameras(MR_VOID);
extern	MR_VOID		InitialiseCamera(CAMERA*, MR_VIEWPORT*);
extern	MR_VOID		UpdateCameras(MR_VOID);
extern	MR_VOID		UpdateCamera(CAMERA*);
extern	MR_VOID		ResetCameras(MR_VOID);
extern	MR_VOID		ResetCamera(CAMERA*);
extern	MR_VOID		ShakeCamera(CAMERA*, MR_LONG, MR_LONG, MR_LONG);
extern	MR_VOID		SetupCameraYRotation(CAMERA*);
extern	MR_VOID		CreateCameraMatrix(CAMERA*, MR_VEC*);


#endif		//__CAMERA_H

