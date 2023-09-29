/******************************************************************************
*%%%% credits.h
*------------------------------------------------------------------------------
*
*	Header file for credits routines
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

#ifndef	__CREDITS_H
#define	__CREDITS_H

#include "mr_all.h"

#if 0

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	CREDITS_MAX_NUM_STRINGS				160
#define CREDITS_MAX_NUM_LETTERS_PER_STRING	38

#define	CREDITS_MAX_NUM_ENTRIES_ON_SCREEN	5
#define	CREDITS_MAX_NUM_MODELS_ON_SCREEN	5

// Credit commands
enum
	{
	CREDIT_COMMAND_ENTRY,
	CREDIT_COMMAND_MODEL,
	CREDIT_COMMAND_DELAY,
	CREDIT_COMMAND_END_FRAME,
	CREDIT_COMMAND_END,
	};

// Credit models
enum
	{
	CREDIT_MODEL_CAV_BAT,
	CREDIT_MODEL_SNAIL,
	CREDIT_MODEL_SPIDER,
	CREDIT_MODEL_BEETLE,
	CREDIT_MODEL_BISON,
	CREDIT_MODEL_SNAKE,
	CREDIT_MODEL_TUMBLEWEED,
	CREDIT_MODEL_VULTURE,
	CREDIT_MODEL_HEDGEHOG,
	CREDIT_MODEL_FROG,
	CREDIT_MODEL_CROCODILE,
	CREDIT_MODEL_TURTLE,
	CREDIT_MODEL_BIPLANE1,
	CREDIT_MODEL_BIRD1,
	CREDIT_MODEL_HELICOPTER,
	CREDIT_MODEL_SQUADRON,
	CREDIT_MODEL_BUTTERFLY2,
	CREDIT_MODEL_DOG,
	CREDIT_MODEL_SWAN,
	CREDIT_MODEL_MUTANT_FISH,
	CREDIT_MODEL_RAT,
	};

// Credit fonts
enum
	{
	CREDIT_FONT_BIG,
//	CREDIT_FONT_SML,
	};

#define	CREDIT_FONT_SML	CREDIT_FONT_BIG			// temporary - delete when small font arrives

// Credit entry update modes
enum
	{
	CREDITS_RUNTIME_ENTRY_MODE_FADE_UP,
	CREDITS_RUNTIME_ENTRY_MODE_WAIT,
	CREDITS_RUNTIME_ENTRY_MODE_FADE_DOWN,
	CREDITS_RUNTIME_ENTRY_MODE_KILL,
	};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef struct __credit_entry			CREDIT_ENTRY;
typedef struct __credit_model			CREDIT_MODEL;
typedef struct __credit_runtime_entry	CREDIT_RUNTIME_ENTRY;
typedef struct __credit_runtime_model	CREDIT_RUNTIME_MODEL;

struct __credit_entry
	{
	MR_ULONG	ce_font_number;				// Font to use to draw text
	MR_USHORT	ce_xpos;					// Start x position of text
	MR_USHORT	ce_ypos;					// Start y position of text
	MR_UBYTE*	ce_text_ptr;				// Ptr to text ( NULL terminated )
	MR_ULONG	ce_fade_up_time;			// Time taken to fade up
	MR_ULONG	ce_on_screen_time;			// Time on screen
	MR_ULONG	ce_fade_down_time;			// Time taken to fade down
	};	// CREDIT_ENTRY

struct __credit_model
	{
	MR_ULONG	cm_model_number;			// Number of model
	MR_VEC		cm_start_pos;				// Start position of model
	MR_VEC		cm_end_pos;					// End position of model
	MR_ULONG	cm_speed;					// Speed at which model travels
	MR_VOID*	cm_update;					// Ptr to update function
	};	// CREDIT_MODEL

struct __credit_runtime_entry
	{
	MR_BOOL			re_active;				// Structure in use ( TRUE - in use )
	MR_ULONG		re_num_sprites;			// Number of sprites used to generate this entry
	MR_2DSPRITE*	re_sprite_ptr[CREDITS_MAX_NUM_LETTERS_PER_STRING];		// Pointers to sprites used to generate this entry
	MR_ULONG		re_mode;				// Current mode of operation
	MR_ULONG		re_time;				// Time to hold text for
	MR_ULONG		re_fade_up_value;
	MR_ULONG		re_fade_down_value;
	MR_ULONG		re_base_colour;
	};	// CREDIT_RUNTIME_ENTRY

struct __credit_runtime_model
	{
	MR_BOOL		rm_active;					// Structure in use ( TRUE - in use )
	MR_OBJECT*	rm_object_ptr;
	MR_VEC		rm_movement;
	MR_ULONG	rm_dist;
	};	// CREDIT_RUNTIME_MODEL

#endif

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		CreditsStartup(MR_VOID);
extern	MR_VOID		CreditsUpdate(MR_VOID);
extern	MR_VOID		CreditsShutdown(MR_VOID);

#if 0

extern	MR_VOID		CreditsCreateEntry(CREDIT_ENTRY*);
extern	MR_VOID		CreditsUpdateEntries(MR_VOID);

extern	MR_VOID		CreditsCreateModel(CREDIT_MODEL*);
extern	MR_VOID		CreditsUpdateModels(MR_VOID);

#endif

#endif	//__CREDITS_H
