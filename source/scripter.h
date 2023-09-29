/******************************************************************************
*%%%% scripter.h
*------------------------------------------------------------------------------
*
*	Script informaton for entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	12.05.97	Martin Kift		Created
*
*%%%**************************************************************************/

#ifndef	__SCRIPTER_H
#define	__SCRIPTER_H

#include	"mr_all.h"
#include	"entity.h"

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

enum	{
		// SCRIPT_INFO script commands
		ENTSCR_WAIT_UNTIL_TIMER,
		ENTSCR_WAIT_UNTIL_ACTION_FINISHED,
		ENTSCR_WAIT_UNTIL_PATH_END,
		ENTSCR_SET_ACTION,
		ENTSCR_PLAY_SOUND,
		ENTSCR_RESTART,
		ENTSCR_END,
		ENTSCR_SET_TIMER,
		ENTSCR_DEVIATE,
		ENTSCR_WAIT_DEVIATED,
		ENTSCR_PLAY_RNDSOUND,
		ENTSCR_SETLOOP,
		ENTSCR_ENDLOOP,
		ENTSCR_SCRIPT_IF,
		ENTSCR_BREAKLOOP_IF_TIMER,
		ENTSCR_PAUSE_ENTITY_ON_PATH,
		ENTSCR_UNPAUSE_ENTITY_ON_PATH,
		ENTSCR_ROTATE,
		ENTSCR_WAIT_UNTIL_ROTATED,
		ENTSCR_HOME_IN_ON_FROG,
		ENTSCR_RETURN_GOSUB_IF,
		ENTSCR_EJECT_FROG,
		ENTSCR_CHOOSE_RND_CHECKPOINT,
		ENTSCR_APPEAR_ENTITY,
		ENTSCR_DISAPPEAR_ENTITY,
		ENTSCR_START_SCRIPT,
		ENTSCR_AWARD_FROG_POINTS,
		ENTSCR_AWARD_FROG_LIVES,
		ENTSCR_AWARD_FROG_TIME,
		ENTSCR_STOP_ROTATE,
		ENTSCR_STOP_DEVIATE,
		ENTSCR_PREPARE_REGISTERS,
		ENTSCR_CLEAR_DEVIATE,
		ENTSCR_RETURN_DEVIATE,
		ENTSCR_REGISTER_CALLBACK,
		ENTSCR_SET_ENTITY_TYPE,
		ENTSCR_PLAY_SOUND_DISTANCE,
		ENTSCR_PLAY_MOVING_SOUND,
		ENTSCR_STOP,
		ENTSCR_MUTATE_MESH_COLOR,
		ENTSCR_NO_COLL_CHECKPOINT,
		ENTSCR_COLL_CHECKPOINT,
		ENTSCR_KILL_SAFE_FROG,
		ENTSCR_CHANGE_ENTITY_ANIM,
		ENTSCR_CREATE_3D_SPRITE,
		ENTSCR_PITCH_BEND_MOVING_SOUND,
		ENTSCR_POP,
		ENTSCR_NO_COLLISION,
		ENTSCR_COLLISION,
		};

enum	{
		// Used to reference into array of 3 longs, to provide X, Y and Z
		ENTSCR_COORD_X,
		ENTSCR_COORD_Y,
		ENTSCR_COORD_Z,
		ENTSCR_NEG_COORD_X,
		ENTSCR_NEG_COORD_Y,
		ENTSCR_NEG_COORD_Z,
		};

enum	{
		// Callback type enums
		ENTSCR_CALLBACK_ONCE,			// Only called once, have to reinit to start again
		ENTSCR_CALLBACK_ALWAYS,			// Always call (every frame)

		// callback states
		SCRIPT_CALLBACK_NOT_CALLED,		// Callback not called
		SCRIPT_CALLBACK_CALLED,			// Callback called
		};

enum	{
		// callback number
		ENTSCR_CALLBACK_1,				// Callback 1
		ENTSCR_CALLBACK_2,				// Callback 2
		ENTSCR_MAX_CALLBACKS,			// Terminator
		};

enum	{
		ENTSCR_ENTITY_TYPE_PATH,
		ENTSCR_ENTITY_TYPE_MATRIX,
		};

enum	{
		// Return types from script commands
		ENTSCR_RETURN_CONTINUE,			// Continue to the next command in this frame
		ENTSCR_RETURN_BREAK,			// Stop processing of commands for this frame
		ENTSCR_RETURN_END				// End processing of scripts for this entity
		};

enum	{
		// Condition types for script branching, and returning from (in the case of gosubs)
		ENTSCR_HIT_FROG,				// hit frog
		ENTSCR_NO_HIT_FROG,				// Not hitting a frog
		ENTSCR_DEVIATED,				// finished deviation
		ENTSCR_ROTATED,					// finished rotating
		ENTSCR_SAFE_FROG,				// frog is sitting on us
		ENTSCR_NO_SAFE_FROG,			// frog is not sitting on us
		ENTSCR_RANDOM,					// random number hit
		ENTSCR_NO_CONDITION,			// No condition at all
		ENTSCR_END_OF_PATH,				// Reached end of path
		ENTSCR_ALWAYS,					// always
		};

enum	{
		// Types of condition branches
		ENTSCR_NEW_SCRIPT,				// branch to new script (no coming back)
		ENTSCR_GOSUB_SCRIPT,			// gosub to new script
		};

#define		ENTSCR_REGISTER_0		0
#define		ENTSCR_REGISTER_1		1
#define		ENTSCR_REGISTER_2		2
#define		ENTSCR_REGISTER_3		3
#define		ENTSCR_REGISTER_4		4
#define		ENTSCR_REGISTER_5		5

#define		ENTSCR_REGISTERS		1
#define		ENTSCR_NO_REGISTERS		0

#define	ENTSCR_FALSE				(0)
#define	ENTSCR_TRUE					(-1)
#define	ENTSCR_TIME_INFINITE		(65535)

// SCRIPT_INFO flags
#define	SCRIPT_INFO_ACTIVE			(1<<0)		// script parsing in progress
#define SCRIPT_INFO_SUBROUTINE		(1<<1)		// in a subroutine of the major script

//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------
typedef struct	__script_info		SCRIPT_INFO;
typedef struct	__scr_deviate		SCR_DEVIATE;
typedef struct	__scr_new_script	SCR_NEW_SCRIPT;
typedef struct	__scr_rotate		SCR_ROTATE;

struct	__script_info
	{
	MR_USHORT		si_flags;							// eg. STUNT_INFO_ACTIVE
	MR_USHORT		si_pad;								// Cos it's out.

	// Following are used for rotation of entities (in all planes)
	MR_SHORT		si_x;								// current local x rotation
	MR_SHORT		si_y;								// current local y rotation
	MR_SHORT		si_z;								// current local z rotation
	MR_SHORT		si_dx;								// delta x angle
	MR_SHORT		si_dy;								// delta y angle
	MR_SHORT		si_dz;								// delta z angle
	MR_SHORT		si_dx_count;						// counts down to 0 if adding dx 
	MR_SHORT		si_dy_count;						// counts down to 0 if adding dy 
	MR_SHORT		si_dz_count;						// counts down to 0 if adding dz 
	MR_SHORT		si_dest_x;							// local x rotation destination
	MR_SHORT		si_dest_y;							// local y rotation destination
	MR_SHORT		si_dest_z;							// local z rotation destination

	// Following are used for translations (in all planes)
	MR_SHORT		si_dev_x;							// current local x offset
	MR_SHORT		si_dev_y;							// current local y offset
	MR_SHORT		si_dev_z;							// current local z offset
	MR_SHORT		si_dev_dx;							// delta x angle
	MR_SHORT		si_dev_dy;							// delta y angle
	MR_SHORT		si_dev_dz;							// delta z angle
	MR_SHORT		si_dev_dx_count;					// counts down to 0 if adding dx 
	MR_SHORT		si_dev_dy_count;					// counts down to 0 if adding dy 
	MR_SHORT		si_dev_dz_count;					// counts down to 0 if adding dz 
	MR_SHORT		si_dev_dest_x;						// local x deviation destination
	MR_SHORT		si_dev_dest_y;						// local y deviation destination
	MR_SHORT		si_dev_dest_z;						// local z deviation destination

	MR_LONG			si_type;							// see enum list of scripts above
	MR_LONG*		si_script;							// ptr to current script action
	MR_LONG*		si_script_previous;					// ptr to previous script action (used for gosub to routines)

	MR_LONG*		si_script_loop_start;				// start of loop
	MR_LONG*		si_script_loop_end;					// end of loop
	MR_LONG*		si_script_loop_start_previous;		// start of previous loop (for gosubs)
	MR_LONG*		si_script_loop_end_previous;		// end of previous loop (for gosubs)

	MR_SVEC			si_position;						// variable used as temp storage when calcing entity positions
	MR_LONG			si_user_data;						// Used in various scripts

	MR_VOID			(*si_script_callback[ENTSCR_MAX_CALLBACKS]) (LIVE_ENTITY*);		// script callbank (if required)
	MR_LONG			si_script_callback_condition[ENTSCR_MAX_CALLBACKS];				// condition for the callback to be effective?
	MR_BYTE			si_script_callback_type[ENTSCR_MAX_CALLBACKS];					// Callback type
	MR_BYTE			si_script_callback_called[ENTSCR_MAX_CALLBACKS];				// Has been called already? (useful for once only callS)

	MR_USHORT		si_entity_type;						// Entity type (path or matrix at the moment)

	MR_USHORT		si_timer;							// script timer
	MR_USHORT		si_register_offset;					// script offset
	MR_VOID*		si_entity_data;						// pointer to entity data structure
	MR_VOID*		si_offset_entity_data;				// pointer to REGISTER 0 in entity data structure
	
	MR_LONG			si_registers[ENTSCR_REGISTER_5+1];	// registers
	};		// SCRIPT_INFO		


struct	__scr_deviate
	{
	MR_LONG		dv_registers;
	MR_LONG		dv_coord;
	MR_LONG		dv_dest;
	MR_LONG		dv_delta;
	MR_LONG		dv_count;
	};	// SCR_ROTATE

struct	__scr_new_script
	{
	MR_LONG		eni_branch;				// Is this a gosub or a newscript branch?
	MR_LONG		eni_mode;				// Conditional mode to decide whether to branch?
	MR_LONG		eni_script_id;			// Script to branch to!
	MR_LONG		eni_value;				// If conditional branch meets this value.
	};	// SCR_NEW_SCRIPT

struct	__scr_rotate
	{
	MR_LONG		rt_coord;
	MR_LONG		rt_dest;
	MR_LONG		rt_delta;
	MR_LONG		rt_count;
	};	// SCR_ROTATE

//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

#define STOP_SCRIPT(script_info) \
						((script_info)->si_flags = NULL)

#define START_NEW_SCRIPT(script_info, equate) \
						(script_info)->si_script			= Scripts[equate];	\
						(script_info)->si_script_loop_start	= NULL;				\
						(script_info)->si_script_loop_end 	= NULL;					

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------
extern	MR_ULONG	Script_command_lengths[];

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------
extern	MR_VOID		UpdateScriptInfo(LIVE_ENTITY*);
extern	MR_VOID		StartScript(SCRIPT_INFO*, MR_LONG, LIVE_ENTITY*);
extern	MR_VOID		ResetScript(SCRIPT_INFO*);
extern	MR_VOID		BranchToNewScript(SCR_NEW_SCRIPT*, SCRIPT_INFO*, MR_LONG*);
extern	MR_VOID		UpdateScriptCallbacks(SCRIPT_INFO*, LIVE_ENTITY*);

extern	MR_LONG		ENTSCR_WAIT_UNTIL_TIMER_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_WAIT_UNTIL_ACTION_FINISHED_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_WAIT_UNTIL_PATH_END_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_SET_ACTION_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PLAY_SOUND_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_RESTART_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_END_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_SET_TIMER_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_RESTART_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_WAIT_UNTIL_PATH_END_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_DEVIATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_WAIT_DEVIATED_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PLAY_RNDSOUND_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_SETLOOP_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_ENDLOOP_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_BREAKLOOP_IF_TIMER_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_SCRIPT_IF_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PAUSE_ENTITY_ON_PATH_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_UNPAUSE_ENTITY_ON_PATH_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_ROTATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_WAIT_UNTIL_ROTATED_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_HOME_IN_ON_FROG_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_RETURN_PATH_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_RETURN_GOSUB_IF_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_EJECT_FROG_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_CHOOSE_RND_CHECKPOINT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_APPEAR_ENTITY_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_DISAPPEAR_ENTITY_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_START_SCRIPT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_AWARD_FROG_POINTS_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_AWARD_FROG_LIVES_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_AWARD_FROG_TIME_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_STOP_ROTATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_STOP_DEVIATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PREPARE_REGISTERS_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_CLEAR_DEVIATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_RETURN_DEVIATE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_REGISTER_CALLBACK_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_SET_ENTITY_TYPE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PLAY_SOUND_DISTANCE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PLAY_RNDSOUND_DISTANCE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PLAY_MOVING_SOUND_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_STOP_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_MUTATE_MESH_COLOR_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_DISAPPEAR_CHECKPOINT(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_NO_COLL_CHECKPOINT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_COLL_CHECKPOINT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_KILL_SAFE_FROG_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_CHANGE_ENTITY_ANIM_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_CREATE_3D_SPRITE_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_PITCH_BEND_MOVING_SOUND_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_POP_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_NO_COLLISION_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);
extern	MR_LONG		ENTSCR_COLLISION_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);

#endif	//__SCRIPTER_H
