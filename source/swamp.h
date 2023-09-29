/******************************************************************************
*%%%% swamp.h
*------------------------------------------------------------------------------
*
*	This is used to hold all the structures/defines etc for the swamp entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	15.01.97	Gary Richards	Created
*	30.04.97	Gary Richards	Added to the New Frogger.
*
*%%%**************************************************************************/
#ifndef __swamp_h
#define __swamp_h
 
#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

enum
	{
	ACTION_OFF_OIL_DRUM,
    ACTION_ON_OIL_DRUM
    };

enum
	{
	ANIM_SWP_OIL_DRUM_NORMAL,
	ANIM_SWP_OIL_DRUM_CRUSHED
	};

enum
	{
	ACTION_SINKING_BOX_NORMAL,
	ACTION_SINKING_BOX_SINKING,
	ACTION_SINKING_BOX_JUMPED_OFF,
	};

enum
	{
	ANIM_SWP_SINKING_BOX_NORMAL,
	ANIM_SWP_SINKING_BOX_CRUSHED
	};

enum
	{
	ACTION_RACCOON_DEFAULT,
	ACTION_RACCOON_NORMAL,
	ACTION_RACCOON_SINKING,
	ACTION_RACCOON_JUMPED_OFF,
	};

enum
	{
	ANIM_RACCOON_NORMAL,
	ANIM_RACCOON_SINKING,
	ANIM_RACCOON_DROWNING,
	};

#define RACCOON_DROWN_HEIGHT	(20)

enum
	{
	ACTION_RAT_RUNNING,
	ACTION_RAT_JUMPING,
	ACTION_RAT_JUMPING_TOWARDS_FROGGER,
	};

enum
	{
	ACTION_NEWSPAPER_TORN_OFF,
	ACTION_NEWSPAPER_TORN_ON
	};

enum
	{
	ANIM_SWP_NEWSPAPER_NORMAL,
	ANIM_SWP_NEWSPAPER_CRUSHED
	};

enum
	{
	ACTION_WASTE_BARREL_FLOATING, 
	ACTION_WASTE_BARREL_SINKING,
	ACTION_WASTE_BARREL_SUNK,
	ACTION_WASTE_BARREL_RISING,

	ACTION_WASTE_BARREL_NO_SPIN,
	ACTION_WASTE_BARREL_SPINNING,
	ACTION_WASTE_BARREL_STOPPING_SPIN
	};

enum
	{
	ANIM_SWP_WASTE_BARREL_NORMAL,
	ANIM_SWP_WASTE_BARREL_CRUSHED
	};

enum
	{
	ACTION_NUCLEAR_BARREL_NORMAL,
	ACTION_NUCLEAR_BARREL_EXPLODING,
	ACTION_NUCLEAR_BARREL_DEAD
	};

enum
	{
	ANIM_SWP_NUCLEAR_BARREL_NORMAL,
	ANIM_SWP_NUCLEAR_BARREL_CRUSHED
	};

enum
	{
	ANIM_SWP_SQUIRT_NORMAL,
	ANIM_SWP_SQUIRT_FALLING,
	ANIM_SWP_SQUIRT_SQUASHED
	};

enum
	{
	ACTION_SWP_SQUIRT_WAITING,
	ACTION_SWP_SQUIRT_FALLING
	};

#define	OIL_DRUM_BOB_OFFSET				(32)	// How far under the water level does it sit.
#define OIL_DRUM_BOB_SPEED				(128)	// How quickly does it move up/down.
#define	OIL_DRUM_BOB_OFF_DEPTH  		(7)		// How far does it move up/down (4096>>?)
#define OIL_DRUM_BOB_ON_DEPTH 			(8)		// It moves less when Frog is on it. (4096>>?)
#define ANIM_SWP_WEIR_RUBBISH_NORMAL	(0)
#define SWP_WASTE_BARREL_SINK_HEIGHT 	(256 << WORLD_SHIFT)
#define SWP_WASTE_BARREL_SINK_SPEED		(16 << WORLD_SHIFT)
#define SWP_WASTE_BARREL_RISE_SPEED		(16 << WORLD_SHIFT)
#define FROGGER_TIME_TO_NUCLEAR_TARGET	(2*30)
#define SWP_STAT_WASTE_BARREL_SINK_HEIGHT (256 << WORLD_SHIFT)
#define SWP_STAT_WASTE_BARREL_SINK_SPEED	(16 << WORLD_SHIFT)
#define SWP_STAT_WASTE_BARREL_RISE_SPEED	(16 << WORLD_SHIFT)


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef struct __fg_swp_oil_drum_diff_data			FG_OIL_DRUM_DIFF_DATA;
typedef struct __fg_swp_oil_drum					FG_OIL_DRUM;
typedef struct __fg_sinking_box_diff_data			FG_SINKING_BOX_DIFF_DATA;
typedef struct __fg_sinking_box						FG_SINKING_BOX;
typedef struct __fg_raccoon							FG_RACCOON;
typedef struct __fg_rat_diff_data					FG_RAT_DIFF_DATA;
typedef struct __fg_rat								FG_RAT;
typedef struct __fg_newspaper_torn_diff_data		FG_NEWSPAPER_TORN_DIFF_DATA;
typedef struct __fg_newspaper_torn					FG_NEWSPAPER_TORN;
typedef struct __fg_swp_waste_barrel_diff_data		FG_SWP_WASTE_BARREL_DIFF_DATA;
typedef struct __fg_swp_waste_barrel				FG_SWP_WASTE_BARREL;
typedef struct __fg_swp_nuclear_barrel_diff_data	FG_SWP_NUCLEAR_BARREL_DIFF_DATA;
typedef struct __fg_swp_nuclear_barrel				FG_SWP_NUCLEAR_BARREL;
typedef struct __fg_swp_weir_rubbish_diff_data		FG_SWP_WEIR_RUBBISH_DIFF_DATA;
typedef struct __fg_swp_weir_rubbish				FG_SWP_WEIR_RUBBISH;
typedef struct __fg_swp_squirt_diff_data			FG_SWP_SQUIRT_DIFF_DATA;
typedef struct __fg_swp_squirt						FG_SWP_SQUIRT;
typedef struct __fg_swp_stat_waste_barrel_diff_data	FG_SWP_STAT_WASTE_BARREL_DIFF_DATA;
typedef struct __fg_swp_stat_waste_barrel			FG_SWP_STAT_WASTE_BARREL;

//-------------------------------------------------------------------
// Swamp Oil Drum
//
//

struct __fg_swp_oil_drum_diff_data
	{	
	MR_USHORT	od_speed;			// Speed of the box.
	MR_USHORT	od_bob_delay;			// Delay between each 'bob'
	};	//FG_OIL_DRUM_DIFF_DATA

struct __fg_swp_oil_drum
	{
	// definition data, supplied from map!
	FG_SPLINEENTITYDATA*	od_map_data;
	FG_OIL_DRUM_DIFF_DATA*	od_map_diff_data;

	// Run Time specific code	
	PATH		od_path;
	MR_SHORT	od_sin_position;		// position within the sin table.
	MR_SHORT	od_bob_height_offset;
	MR_SHORT	od_bob_depth;			// Depth to which the oil drum bobs.
	MR_SHORT	od_curr_delay;
	MR_BYTE		od_state;
	MR_BYTE		od_pad;
	};	// FG_OIL_DRUM

//-------------------------------------------------------------------
// This is the entity structure for the SinkingBox on the Swamp Map.
//

struct __fg_sinking_box_diff_data
	{	
	MR_SHORT	sb_sink_rate;			// Rate at which the Box sinks
	MR_USHORT	sb_speed;			// Speed of the box.		
	}; // FG_SINKING_BOX_DIFF_DATA

struct __fg_sinking_box
	{
	// Small Bird definition data, supplied from map!
	FG_SPLINEENTITYDATA*		sb_map_data;
	FG_SINKING_BOX_DIFF_DATA*	sb_map_diff_data;

	// run specific code	
	PATH		sb_path;
	MR_LONG		sb_curr_height;	// This increase as the box sinks, added to the real height.
	MR_BYTE		sb_state;			// So we know what actions it's currently doing.
	MR_BYTE		sb_pad[3];
	};	// FG_SINKING_BOX

//----------------------------------------------------------------------------------------------
// This is the entity structure for the raccoon on the Swamp Map.
//
// This is basicly the same as a sinking box, so the structure contains a sinking box.
//

struct __fg_raccoon
	{
	// Small Bird definition data, supplied from map!
	FG_SPLINEENTITYDATA*		ra_map_data;
	FG_SINKING_BOX_DIFF_DATA*	ra_map_diff_data;

	// run specific code	
	PATH		ra_path;
	MR_LONG		ra_curr_height;		// This increase as the box sinks, added to the real height.
 	MR_BYTE		ra_state;				// So we know what actions it's currently doing.
	MR_BYTE		ra_pad[3];
	};	// FG_RACCOON

//----------------------------------------------------------------------------------------------
// This is the entity structure for the rat on the Swamp Map.
//
//

struct __fg_rat_diff_data
	{	
	MR_SVEC		ra_target;			// Position of the target.
	MR_USHORT	ra_speed;			// Speed of the rat along spline.
	MR_USHORT	ra_time;			// Time it takes the rat to jump to the target.
	MR_USHORT	ra_distance;		// Distance before Rat jumps at Frogger.
	MR_USHORT	ra_pad;
	}; // FG_RAT_DIFF_DATA;

struct __fg_rat
	{
	// Rat definition data, supplied from map!
	FG_SPLINEENTITYDATA*	ra_map_data;
	FG_RAT_DIFF_DATA*		ra_map_diff_data;

	// run specific code	
	PATH		ra_path;
	MR_BYTE		ra_state;				// So we know what actions it's currently doing.
	MR_BYTE		ra_catch_up;			// How long have we missed the update for.
	MR_SHORT	ra_curr_time;			// How long does the fall last.
	MR_VEC		ra_velocity;			// Contains X,Z move + Y Velocity;
	MR_VEC		ra_position;
	MR_MAT		ra_desired_position;	// Desired position of the rat.
 	};	// FG_RAT

//-------------------------------------------------------------------
// This is the entity structure for the NewsPaperTorn on the Swamp Map.
//

struct __fg_newspaper_torn_diff_data
	{	
	MR_SHORT	nt_rip_rate;	// Rate at which the NewsPaper break up.
	MR_USHORT	nt_speed;		// Speed of the NewsPaper alone the spline.
	}; // FG_NEWSPAPER_TORN_DIFF_DATA;

struct __fg_newspaper_torn
	{
	// NewsPaperTorn definition data, supplied from map!
	FG_SPLINEENTITYDATA*		nt_map_data;
	FG_NEWSPAPER_TORN_DIFF_DATA* nt_map_diff_data;

	// run specific code	
	PATH		nt_path;
	MR_SHORT	nt_curr_time;		// Time left before the newpaper breaks up.
	MR_BYTE		nt_state;			// So we know what actions it's currently doing.
	MR_BYTE		nt_pad;
	};	// FG_NEWSPAPER_TORN

//-------------------------------------------------------------------
// This is the entity structure for the Waste Barrel on the Swamp Map.
//

struct __fg_swp_waste_barrel_diff_data
	{	
	MR_USHORT	wb_speed;			// Speed along the Spline.
	MR_SHORT	wb_float_time;			// Time before the barrel sinks.
	MR_SHORT	wb_sunk_time;			// Time before the barrel rises.
	MR_SHORT	wb_pad;
	MR_LONG		wb_spin_acc;			// Acceleration for the Spin.
	MR_LONG		wb_max_spin;			// Max Speed for the Spin.
	};	// FG_SWP_WASTE_BARREL_DIFF_DATA;

struct __fg_swp_waste_barrel
	{
	// WasteBarrel definition data, supplied from map!
	FG_SPLINEENTITYDATA*			wb_map_data;
	FG_SWP_WASTE_BARREL_DIFF_DATA*	wb_map_diff_data;

	// run specific code	
	PATH		wb_path;
	MR_LONG		wb_curr_spin_speed;	// Curr Speed that the barrel is Spinning at.
  	MR_LONG		wb_curr_spin_acc;	// The current Spin that is added.
	MR_SHORT	wb_spin_rotation;	// The current rotation value.
	MR_LONG		wb_curr_height;		// Curr Height offset below the Spline.
	MR_SHORT	wb_curr_time;		// Time Before a state change.
	MR_BYTE		wb_float_state;		// Are we Sinking ????
	MR_BYTE		wb_spin_state;		// Are we Spinning ???
	};	// FG_SWP_WASTE_BARREL

//----------------------------------------------------------------------------------------------
// This is the entity structure for the Nuclear Barrel on the Swamp Map.
//
//

struct __fg_swp_nuclear_barrel_diff_data	
	{	
	MR_SVEC		nb_target;			// Position of the target.
	MR_USHORT	nb_speed;			// Speed of the nuclear barrel along spline.
	MR_USHORT	nb_pad;
	};	// FG_SWP_NUCLEAR_BARREL_DIFF_DATA

struct __fg_swp_nuclear_barrel
	{
	// Nuclear definition data, supplied from map!
	FG_SPLINEENTITYDATA*			nb_map_data;
	FG_SWP_NUCLEAR_BARREL_DIFF_DATA* nb_map_diff_data;

	// run specific code	
	PATH			nb_path;
	MR_BYTE			nb_state;				// So we know what actions it's currently doing.
	MR_VEC			nb_velocity;			// Contains X,Z move + Y Velocity;
	MR_VEC			nb_position;
	MR_SHORT		nb_curr_time;
  	}; // FG_SWP_NUCLEAR_BARREL

//----------------------------------------------------------------------------------------------
// This is the entity structure for the Weir Rubbish on the Swamp Map.
//
//

struct __fg_swp_weir_rubbish_diff_data
	{	
	MR_USHORT	wr_speed;			// Speed of the nuclear barrel along spline.
	MR_SHORT	wr_time_delay;		// Until entity is affected by Acceleration.
	MR_LONG		wr_acceleration;	// Rate at which the entity increases.
	};	// FG_SWP_WEIR_RUBBISH_DIFF_DATA

struct __fg_swp_weir_rubbish
	{
	// Weir Rubbish definition data, supplied from map!
	FG_SPLINEENTITYDATA*			wr_map_data;
	FG_SWP_WEIR_RUBBISH_DIFF_DATA*	wr_map_diff_data;

	// run specific code	
	PATH		wr_path;
	MR_SHORT	wr_curr_time;
	MR_LONG		wr_curr_speed;			// Fraction.
  	};	// FG_SWP_WEIR_RUBBISH

//----------------------------------------------------------------------------------------------
// This is the entity structure for the squirt on the Swamp Map.
//
//

struct __fg_swp_squirt_diff_data
	{	
	MR_SHORT	sq_time_delay;		// Delay inbetween each drip.
	MR_SHORT	sq_drop_time;		// Time to reach Target.
	MR_SVEC		sq_target;			// Place where the drip is going to end up.
	};	// FG_SWP_SQUIRT_DIFF_DATA;

struct __fg_swp_squirt
	{ 
	// Squirt definition data, supplied from map!
	FG_MATRIXENTITYDATA*	sq_map_data;
	FG_SWP_SQUIRT_DIFF_DATA* sq_map_diff_data;

	// run specific code	
 	MR_SHORT	sq_curr_time;
	MR_VEC		sq_velocity;			// The amount we should move every frame.
	MR_VEC		sq_position;
	MR_BYTE		sq_action;
	MR_BYTE		sq_anim;
	};	// FG_SWP_SQUIRT

//----------------------------------------------------------------------------------------------
// This is the entity structure for the STAT WasteBarrel on the Swamp Map.
// Same as Waste Barrel, except it's a matrix based instead of Spline.
//

struct __fg_swp_stat_waste_barrel_diff_data
	{	
	MR_USHORT	wb_speed;			// Speed along the Spline.
	MR_SHORT	wb_float_time;			// Time before the barrel sinks.
	MR_SHORT	wb_sunk_time;			// Time before the barrel rises.
	MR_SHORT	wb_pad;
	};	// FG_SWP_STAT_WASTE_BARREL_DIFF_DATA

struct __fg_swp_stat_waste_barrel
	{
	// WasteBarrel definition data, supplied from map!
	FG_MATRIXENTITYDATA*				wb_map_data;
	FG_SWP_STAT_WASTE_BARREL_DIFF_DATA*	wb_map_diff_data;

	// run specific code	
	PATH		wb_path;
	MR_LONG		wb_curr_height;		// Curr Height offset below the Spline.
	MR_LONG		wb_starting_height;	// The height at which the Barrel starts on the map.
	MR_SHORT	wb_curr_time;		// Time Before a state change.
	MR_BYTE		wb_float_state;		// Are we Sinking ????
	MR_BYTE		wb_pad[3];
	};	// FG_SWP_STAT_WASTE_BARREL


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

//-{ Prototypes (CREATE}----------------------------------------------------------------
extern FG_GOF* SwpCreateOilDrum(MR_VOID*);
extern FG_GOF* SwpCreateSinkingBox(MR_VOID*);
extern FG_GOF* SwpCreateNewsPaper(MR_VOID*);
extern FG_GOF* SwpCreateNewsPaperTorn(MR_VOID*);
extern FG_GOF* SwpCreateRaccoon(MR_VOID*);
extern FG_GOF* SwpCreateOil(MR_VOID*);
extern FG_GOF* SwpCreateRat(MR_VOID*);
extern FG_GOF* SwpCreateWasteBarrel(MR_VOID*);
extern FG_GOF* SwpCreateNuclearBarrel(MR_VOID*);
extern FG_GOF* SwpCreateWeirRubbish(MR_VOID*);
extern FG_GOF* SwpCreateSquirt(MR_VOID*);
extern FG_GOF* SwpCreateSTATWasteBarrel(MR_VOID*);

//-{ Prototypes (UPDATE}----------------------------------------------------------------
extern MR_BOOL SwpUpdateOilDrum(FG_GOF*);
extern MR_BOOL SwpUpdateSinkingBox(FG_GOF*);
extern MR_BOOL SwpUpdateSTATSunkCar(FG_GOF*);
extern MR_BOOL SwpUpdateNewsPaper(FG_GOF*);
extern MR_BOOL SwpUpdateNewsPaperTorn(FG_GOF*);
extern MR_BOOL SwpUpdateSTATPipe(FG_GOF*);
extern MR_BOOL SwpUpdateSTATMarsh(FG_GOF*);
extern MR_BOOL SwpUpdateRaccoon(FG_GOF*);
extern MR_BOOL SwpUpdateRat(FG_GOF*);
extern MR_BOOL SwpUpdateOil(FG_GOF*);
extern MR_BOOL SwpUpdateWasteBarrel(FG_GOF*);
extern MR_BOOL SwpUpdateNuclearBarrel(FG_GOF*);
extern MR_BOOL SwpUpdateCrusher(FG_GOF*);
extern MR_BOOL SwpUpdateWeirRubbish(FG_GOF*);
extern MR_BOOL SwpUpdateSquirt(FG_GOF*);
extern MR_BOOL SwpUpdateSTATWasteBarrel(FG_GOF*);

#endif //__swp_h