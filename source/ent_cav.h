/******************************************************************************
*%%%% ent_cav.h
*------------------------------------------------------------------------------
*
*	Caves theme header file
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	28.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__ENT_CAV_H
#define	__ENT_CAV_H

#include "mr_all.h"
#include "entity.h"
#include "frog.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Caves Spider
enum
	{
	ACTION_SPIDER_WAIT,
	ACTION_SPIDER_CHASE,
	ACTION_SPIDER_HOME,
	};

enum 
	{
	CAV_WEB_FIND_SPIDER,
	CAV_WEB_CONTROL_SPIDER,
	CAV_WEB_NOTHING,
	};

enum {
	CAV_SPIDER_COORD_X,
	CAV_SPIDER_COORD_Y,
	CAV_SPIDER_COORD_Z,

	CAV_SPIDER_WAIT,
	CAV_SPIDER_CHASE,
	CAV_SPIDER_HOME,
	};

#define CAV_MAX_WEB_LINES	20

enum
	{
	ACTION_RACE_SNAIL_FORWARD,
	ACTION_RACE_SNAIL_BACKWARD,
	};

#define	CAVE_FIRE_FLY_LIGHT	(8)

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------
typedef struct __caves_frog_light		CAVES_FROG_LIGHT;
typedef struct __caves_rt_frog_light	CAVES_RT_FROG_LIGHT;
typedef struct __caves_spider			CAVES_SPIDER;
typedef struct __caves_rt_spider		CAVES_RT_SPIDER;
typedef struct __caves_web				CAVES_WEB;
typedef struct __caves_rt_web			CAVES_RT_WEB;
typedef struct __cav_web_vertex			CAV_WEB_VERTEX;
typedef struct __cav_web_lines			CAV_WEB_LINES;
typedef struct __cav_web				CAV_WEB;
typedef struct __cav_rt_web				CAV_RT_WEB;
typedef struct __cav_spider				CAV_SPIDER;
typedef struct __cav_rt_spider			CAV_RT_SPIDER;
typedef	struct __cav_fat_fire_fly		CAV_FAT_FIRE_FLY;
typedef	struct __caves_race_window		CAVES_RACE_WINDOW;
typedef struct __caves_rt_race_window	CAVES_RT_RACE_WINDOW;
typedef	struct __caves_race_snail		CAVES_RACE_SNAIL;
typedef struct __caves_rt_race_snail	CAVES_RT_RACE_SNAIL;

// Caves Spider
struct __caves_spider
	{
	MR_MAT		sp_matrix;			// matrix of entity
	MR_USHORT	sp_speed;
	MR_USHORT	sp_pad;
	};	// CAVES_SPIDER

struct __caves_rt_spider
	{
	// Run time data
	MR_USHORT		sp_mode;  			// Spider mode ( WAIT / GET FROGGER )
	MR_LONG			sp_home_x;			// Home position in X
	MR_LONG			sp_home_y;			// Home position in Y
	MR_LONG			sp_home_z;			// Home position in Z
	struct __caves_rt_web*	sp_web;		// Pointer to spider's WEB
	};	// CAVES_RT_SPIDER

// Caves WEB
struct __caves_web
	{
	MR_MAT		we_matrix;			// matrix of entity
	MR_SHORT	we_spider_id;		// Number of entity 
	MR_USHORT	we_pad;
	};	// CAVES_WEB

struct __caves_rt_web
	{
	struct __caves_rt_spider*	we_spider;			// Spider attached to this web.	
	MR_BOOL			we_first_time;		// Are we finding the spider??
	MR_SHORT		we_x1_bound;		// Lower x boundary
	MR_SHORT		we_x2_bound;		// Upper x boundary
	MR_SHORT		we_y1_bound;		// Lower y boundary
	MR_SHORT		we_y2_bound;		// Upper y boundary
	MR_SHORT		we_z1_bound;		// Lower z boundary
	MR_SHORT		we_z2_bound;		// Upper z boundary
	};	// CAVES_RT_WEB

// Caves Frogger light
struct __caves_frog_light
	{
	MR_MAT			fl_matrix;			// Matrix of entity
	MR_ULONG		fl_min_radius;		// Number of grid squares
	MR_ULONG		fl_max_radius;		// Number of grid squares
	MR_ULONG		fl_die_speed;		// Die speed ( world units per second )
	MR_ULONG		fl_count;			// $wb - Used to keep track of die time
	MR_ULONG		fl_setup;			// Aleady setup?
	};	// CAVES_FROG_LIGHT

// Caves Frogger light
struct __caves_rt_frog_light
	{
	MR_ULONG		fl_min_radius;		// Number of grid squares
	MR_ULONG		fl_max_radius;		// Number of grid squares
	MR_ULONG		fl_die_speed;		// Die speed ( world units per second )
	MR_ULONG		fl_count;			// $wb - Used to keep track of die time
	};	// CAVES_RT_FROG_LIGHT


struct __cav_spider
	{
	MR_MAT			cs_matrix;			// matrix of entity
	MR_USHORT		cs_speed;
	MR_USHORT		cs_pad;
	};	// CAV_SPIDER

struct __cav_rt_spider
	{
	MR_ULONG		cs_mode;  			// Spider mode ( WAIT / GET FROGGER )
	MR_LONG			cs_home_x;			// Home position x
	MR_LONG			cs_home_y;			// Home position y
	MR_LONG			cs_home_z;			// Home position z
	CAV_RT_WEB*		cs_web;				// Pointer to spider's WEB
	MR_VOID*		cs_frog;			// Ptr to frog (when landed on web)
	MR_LONG			cs_frog_id;			// Frog id (of above)
	};	// CAV_RT_SPIDER


struct __cav_web_vertex
	{
	MR_SHORT		we_vertex_x;
	MR_SHORT		we_vertex_y;
	MR_SHORT		we_vertex_z;
	MR_SHORT		we_pad;
	}; // CAV_WEB_VERTEX

struct __cav_web_lines
	{
	CAV_WEB_VERTEX	we_line_1;
	CAV_WEB_VERTEX	we_line_2;
	};	// CAV_WEB_LINES

struct __cav_web
	{
	MR_MAT			we_matrix;			// matrix of entity
	MR_SHORT		we_spider_id;		// Number of entity 
	MR_USHORT		we_pad;
	};	// CAV_WEB

struct __cav_rt_web
	{
	LINE_G2*		cw_web_lines[SYSTEM_MAX_VIEWPORTS][2];	// polys for quads in each viewport
	CAV_WEB_LINES*	cw_lines;								// Ptr to lines
	CAV_RT_SPIDER*	cw_spider;								// Spider attached to this web.	
	MR_LONG			cw_mode;								// Are we finding the spider??
	MR_SHORT		we_x1_bound;							// Lower x boundary
	MR_SHORT		we_x2_bound;							// Upper x boundary
	MR_SHORT		we_y1_bound;							// Lower y boundary
	MR_SHORT		we_y2_bound;							// Upper y boundary
	MR_SHORT		we_z1_bound;							// Lower z boundary
	MR_SHORT		we_z2_bound;							// Upper z boundary
	};	// CAV_RT_WEB

struct	__cav_fat_fire_fly
	{
	MR_MAT		ff_matrix;
	MR_USHORT	ff_type;
	MR_USHORT	ff_pad;
	MR_SVEC		ff_target;
	};	// CAV_FAT_FIRE_FLY

struct __caves_race_snail
	{
	PATH_INFO	rs_path_info;
	MR_USHORT	rs_forward_dist;			// Size of Window.
	MR_USHORT	rs_backward_dist;			
	};	// CAVES_RACE_SNAIL

struct __caves_rt_race_snail
	{
	// Run time data
	MR_USHORT		rs_state;
	MR_SHORT		rs_position;
	MR_FRAC16		rs_velocity;
	MR_SHORT		rs_mid_point;
	MR_USHORT		rs_speed;
	};	// CAVES_RT_RACE_SNAIL

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------


extern	MR_LONG		script_cav_rockfallfloor_waiting[];
extern	MR_LONG		script_cav_rockfallfloor_falling[];
extern	MR_LONG		script_cav_bat[];
extern	MR_LONG		script_cav_bat_sfx[];
extern	MR_LONG		script_cav_vamp_bat[];
extern	MR_LONG		script_cav_vamp_bat_sfx[];

extern	MR_BOOL		Cav_light_switch;
extern	MR_LONG		script_cav_spider[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID ENTSTRCavCreateFroggerLight(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRCavUpdateFroggerLight(LIVE_ENTITY*);

extern	MR_VOID CavBounceWebCallback(MR_VOID*, MR_VOID*, MR_VOID*);
extern	MR_VOID CavStickyWebCallback(MR_VOID*, MR_VOID*, MR_VOID*);

extern	MR_VOID	ENTSTRCavCreateFatFireFly(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRCavUpdateFatFireFly(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRCavKillFatFireFly(LIVE_ENTITY*);

extern	MR_VOID	ENTSTRCavCreateRaceSnail(LIVE_ENTITY*);
extern	MR_VOID	ENTSTRCavUpdateRaceSnail(LIVE_ENTITY*);

extern	MR_VOID CavFireFlyCallBack(MR_VOID*, MR_VOID*, MR_VOID*);

#endif	//__ENT_CAV_H
