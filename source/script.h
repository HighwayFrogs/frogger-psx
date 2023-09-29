/******************************************************************************
*%%%% script.h
*------------------------------------------------------------------------------
*
*	Script informaton for entities
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	01.05.97	Martin Kift		Created
*	06.05.97	Martin Kift		Added looping and subroutines for scripts
*	07.05.97	Martin Kift		Added rotation and other fancy stuff
*	10.05.97	Martin Kift		Added more scripts, including balloons, better
*								processing of gosubs and extra return conditions
*
*%%%**************************************************************************/

#ifndef	__SCRIPT_H
#define	__SCRIPT_H

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
		ENTSCR_CHOOSE_RND_CHECK_POINT,
		ENTSCR_APPEAR_ENTITY,
		ENTSCR_DISAPPEAR_ENTITY,
		ENTSCR_START_SCRIPT,
		ENTSCR_AWARD_FROG_POINTS,
		ENTSCR_AWARD_FROG_LIVES,
		ENTSCR_AWARD_FROG_TIME,
		};

enum	{
		// Used to reference into array of 3 longs, to provide X, Y and Z
		ENTSCR_COORD_X,
		ENTSCR_COORD_Y,
		ENTSCR_COORD_Z
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
		ENTSCR_DEVIATED,				// finished deviation
		ENTSCR_ROTATED,					// finished rotating
		ENTSCR_NO_HIT_FROG,				// Not hitting a frog
		};

enum	{
		// Types of condition branches
		ENTSCR_NEW_SCRIPT,				// branch to new script (no coming back)
		ENTSCR_GOSUB_SCRIPT,			// gosub to new script
		};

enum	{
		// Main script enum list...!
		SCRIPT_SUB_TURTLE,
		SCRIPT_ORG_CROCODILE,
		SCRIPT_ORG_CAR,
		SCRIPT_ORG_LORRY,
		SCRIPT_ORG_SNAKE,
		SCRIPT_SUB_SWAN,
		SCRIPT_ORG_TRUCK,
		SCRIPT_SKY_BIRD1_1,
		SCRIPT_SUB_TURTLE_HITFROG,
		SCRIPT_SKY_RISING_BALLOON_WAITING,
		SCRIPT_SKY_RISING_BALLOON_RISING,
		SCRIPT_SKY_RISING_BALLOON_SINKING,
		SCRIPT_SKY_RISING_BALLOON_POPPING,
		SCRIPT_SWP_NUCLEAR_BARLLEL_WAITING,
		SCRIPT_SWP_NUCLEAR_BARLLEL_EJECTING,
		SCRIPT_ORG_LOG,
		SCRIPT_ORG_LOG_SPLASH,
		SCRIPT_ORG_BONUS_FLY,
		SCRIPT_ORG_BONUS_FLY_COLLECTED,
		};


#define	ENTSCR_FALSE				(0)
#define	ENTSCR_TRUE					(-1)

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

	MR_VOID			(*si_script_callback)(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG*);	// script callbank (if required)
	
	MR_USHORT		si_timer;							// script timer
	MR_USHORT		si_pad;								// pad
	};		// SCRIPT_INFO		


struct	__scr_deviate
	{
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

//------------------------------------------------------------------------------------------------
//	Externs
//------------------------------------------------------------------------------------------------
extern	MR_LONG*	Scripts[];
extern	MR_ULONG	Script_command_lengths[];

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------
extern	MR_VOID		UpdateScriptInfo(LIVE_ENTITY*);
extern	MR_VOID		StartScript(SCRIPT_INFO*, MR_LONG, LIVE_ENTITY*);
extern	MR_VOID		ResetScript(SCRIPT_INFO*);
extern	MR_VOID		BranchToNewScript(SCR_NEW_SCRIPT*, SCRIPT_INFO*, MR_LONG*);

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
extern	MR_LONG		ENTSCR_RETURN_PATH_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_RETURN_GOSUB_IF_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_EJECT_FROG_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_CHOOSE_RND_CHECK_POINT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_APPEAR_ENTITY_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_DISAPPEAR_ENTITY_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_START_SCRIPT_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_AWARD_FROG_POINTS_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_AWARD_FROG_LIVES_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);
extern	MR_LONG		ENTSCR_AWARD_FROG_TIME_command(LIVE_ENTITY*, SCRIPT_INFO*, MR_LONG* script);

#endif	//__SCRIPT_H
