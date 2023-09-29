/******************************************************************************
*%%%% options.h
*------------------------------------------------------------------------------
*
*	Options Processing
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef	__OPTIONS_H
#define	__OPTIONS_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	FROG_OPTIONS
//#define	OPTIONS_SHOW_MEM

#define	OPTION_MIN_LEVEL 	0
#define	OPTION_MAX_LEVEL 	8

#define	OPTION_MAX_SPCORES	8			// glowing text sprites

enum	{
		OPTIONS_PAGE_EXIT = -1,
		OPTIONS_PAGE_NULL,
		OPTIONS_PAGE_VERSION,
#ifdef PSX
		OPTIONS_PAGE_ANTI_PIRACY,
#endif
		OPTIONS_PAGE_HASBRO_LOGO,
		OPTIONS_PAGE_MILLENNIUM_LOGO,
		OPTIONS_PAGE_LANGUAGE_SELECTION,
		OPTIONS_PAGE_CHECK,
		OPTIONS_PAGE_INTRO,
		OPTIONS_PAGE_MAIN_OPTIONS,
		OPTIONS_PAGE_OPTIONS,
#ifdef WIN95
		OPTIONS_PAGE_MULTIPLAYER_MODE_OPTIONS,
		OPTIONS_PAGE_NETWORK_TYPE,
		OPTIONS_PAGE_NETWORK_HOST,
		OPTIONS_PAGE_NETWORK_PLAY,
#endif
		OPTIONS_PAGE_FROG_SELECTION,
		OPTIONS_PAGE_LEVEL_SELECT,
		OPTIONS_PAGE_CONTINUE,
		OPTIONS_PAGE_GAME_OVER,
		OPTIONS_PAGE_OUTRO,
		OPTIONS_PAGE_CREDITS,
		OPTIONS_PAGE_HIGH_SCORE_INPUT,
		OPTIONS_PAGE_HIGH_SCORE_VIEW,
		OPTIONS_PAGE_SAVE,
		OPTIONS_PAGE_LOAD,
#ifdef PSX		
		OPTIONS_PAGE_REDEFINE_PSX_BUTTONS,
#else			
		OPTIONS_PAGE_CHOOSE_WIN_CONTROLLER,
#endif			
		OPTIONS_PAGE_GAME,
		OPTIONS_PAGE_LEVEL_COMPLETE,
		OPTIONS_PAGE_SHOW_WATER,
		OPTIONS_PAGE_PLAY_AGAIN,
		};

#define	OPTION_NUM_PRIM_PACKETS	10		// Total number of packets available
#define	PRIM_PACKET_FLAG_ACTIVE	(1<<0)	// Packet currently in use


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__option_page		OPTION_PAGE;
typedef struct	__prim_packet		PRIM_PACKET;
typedef struct	__options_camera	OPTIONS_CAMERA;

struct	__option_page
		{
		MR_VOID		(*op_callback_startup)(MR_VOID);
		MR_VOID		(*op_callback_update)(MR_VOID);
		MR_VOID		(*op_callback_shutdown)(MR_VOID);

		};	// OPTION_PAGE

struct __prim_packet
		{
		MR_ULONG		pp_flags;				// Flags about status of packet
		MR_UBYTE*		pp_prim_adr;			// Pointer to prims
		MR_ULONG		pp_count;				// Life of prims remaining

		};	// PRIM_PACKET

struct __options_camera
		{
		MR_VEC			oc_start_pos;
		MR_VEC			oc_start_target;
		MR_VEC			oc_end_pos;
		MR_VEC			oc_end_target;
		};

//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG			Option_page_request;
extern	MR_VIEWPORT*	Option_viewport_ptr;
extern	MR_LONG			Option_level_number;
extern	MR_LONG			Option_page_current;
extern	MR_FRAME*		Option_camera_ptr;

extern	MR_SP_CORE*		Option_spcore_ptrs[];
extern	MR_LONG			Option_spcore_index;
extern	MR_LONG			Option_spcore_value;


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_BOOL		OptionStart(MR_VOID);
extern	MR_VOID		FreePrims(MR_VOID);
extern	MR_VOID		InitialisePrimFree(MR_UBYTE*);
extern	MR_VOID		ClearOptions(MR_VOID);

extern	MR_VOID		OptionKill3DSprites(MR_VOID);
extern	MR_VOID		OptionClearSpcores(MR_VOID);
extern	MR_VOID		OptionUpdateSpcores(MR_VOID);
extern	MR_VOID		KillOptionsForStream(MR_VOID);
extern	MR_VOID 	CreateOptionsAfterStream(MR_VOID);

#endif		//__OPTIONS_H

