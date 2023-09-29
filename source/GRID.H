/******************************************************************************
*%%%% grid.h
*------------------------------------------------------------------------------
*
*	Grid handling functions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	17.04.97	Tim Closs		Created
*	18.06.97	Martin Kift		Added bouncy wall defines
*	03.07.97	Tim Closs		Removed entity launch grid flags
*	08.07.97	Tim Closs		Added GRID_SQUARE_EXTEND_HOP_HEIGHT
*
*%%%**************************************************************************/

#ifndef	__GRID_H
#define	__GRID_H

#include "mr_all.h"
#include "mapload.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Grid square flags
#define	GRID_SQUARE_USABLE				(1<<0)		// frog can jump here
#define	GRID_SQUARE_SAFE				(1<<1)		// standard land
#define	GRID_SQUARE_DEADLY				(1<<2)		// frog dies
#define	GRID_SQUARE_WATER				(1<<3)		// frog swims in this square
#define	GRID_SQUARE_SLIPPY				(1<<4)		// lager lager lager
#define	GRID_SQUARE_BOUNCY				(1<<5)		// frog bounces
#define GRID_SQUARE_CHECKPOINT			(1<<6)		// checkpoint
#define GRID_SQUARE_FREEFORM_SLIPPY		(1<<7)		// free form slippy
#define GRID_SQUARE_SOFT				(1<<8)		// frog will never be stunned/killed when falling here
#define GRID_SQUARE_EXTEND_HOP_HEIGHT	(1<<9)		// FROG_JUMP_SMALL_DY is extended
#define	GRID_SQUARE_SIMPLE_SLIPPY		(1<<10)		// simple slipping
#define	GRID_SQUARE_CLIFF				(1<<11)		// unsure, req'ed by Kev
#define	GRID_SQUARE_POPDEATH			(1<<12)		// frog dies with a pop animation

#define	GRID_SQUARE_SAFE_MASK			(GRID_SQUARE_SAFE | GRID_SQUARE_SLIPPY | GRID_SQUARE_SIMPLE_SLIPPY | GRID_SQUARE_BOUNCY)	// convenience

// These flags are ONLY use on land, not on FORM_DATA grids
#define GRID_SQUARE_BOUNCE_WALL_N		(1<<14)		// Bouncy wall north
#define GRID_SQUARE_BOUNCE_WALL_E		(1<<15)		// Bouncy wall east

// Don't re-use these flags!  They are not used by code, but are set in some maps
#define	GRID_SQUARE_ENTITY_N			(1<<16)
#define	GRID_SQUARE_ENTITY_E			(1<<17)
#define	GRID_SQUARE_ENTITY_S			(1<<18)
#define	GRID_SQUARE_ENTITY_W			(1<<19)

// Don't centre when landing on a grid square flagged as follows
#define	GRID_SQUARE_DONT_CENTRE_WHEN_LANDED_MASK	(GRID_SQUARE_WATER | GRID_SQUARE_DEADLY | GRID_SQUARE_POPDEATH)

// Error value from various functions
#define GRID_RETURN_VALUE_ERROR			0xbabe		// an error occurred in the function

// line-tile extraction modes
enum
	{
	LI_MODE_START,	
	LI_MODE_PROCESS,
	LI_MODE_END,		
	LI_MODE_DONE
	};
	
//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__grid_square		GRID_SQUARE;
typedef	struct	__grid_stack		GRID_STACK;
typedef	struct	__grid_info			GRID_INFO;
typedef	struct	__grid_line_inter	GRID_LINE_INTER;


struct	__grid_square
	{
	MR_ULONG	gs_flags;		// eg. GRID_SQUARE_LAND
	MAP_F4*		gs_map_poly;	// to reference vertices

	};	// GRID_SQUARE
	

struct	__grid_stack
	{
	MR_UBYTE	gs_numsquares;	// number of GRID_SQUAREs in stack
	MR_UBYTE	gs_average_ht;	// Average 
	MR_USHORT	gs_index;		// index of 1st stack square in GRID_SQUAREs array

	};	// GRID_STACK


struct	__grid_info
	{
	MR_LONG		gi_y;			// height of landscape
	MR_VEC		gi_xslope;		// vector aligned to grid poly in +ve x (normalised)
	MR_VEC		gi_zslope;		// vector aligned to grid poly in +ve z (normalised)

	};	// GRID_INFO

struct __grid_line_inter
	{
	MR_USHORT 	mode;
	MR_USHORT 	pad;

	MR_USHORT	curr_step;
	MR_USHORT	num_steps;	// number of checks along the line

	MR_VEC		step_vec;	// vector 1.19.12 describing size of step 
	MR_SVEC		curr_pos;	// current world pos 

	MR_XY		tile;		// current tile
	MR_XY		last_tile;	// previous tile
	MR_XY		end_tile;	// end-of-line tile
	}; //GRID_LINE_INTER


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	GET_GRID_X_FROM_WORLD_X(a) \
		(((a) - Grid_base_x) >> 8)

#define	GET_GRID_Z_FROM_WORLD_Z(a) \
		(((a) - Grid_base_z) >> 8)


//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_LONG			Grid_base_x;
extern	MR_LONG			Grid_base_z;
extern	MR_LONG			Grid_xnum;
extern	MR_LONG			Grid_znum;
extern	MR_LONG			Grid_xshift;
extern	MR_LONG			Grid_zshift;
extern	MR_LONG			Grid_xlen;
extern	MR_LONG			Grid_zlen;

extern	GRID_SQUARE*	Grid_squares;
extern	GRID_STACK*		Grid_stacks;


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			InitialiseGrid(MR_VOID);
extern	GRID_STACK*		GetGridStack(MR_LONG, MR_LONG);
extern	MR_VOID			GetGridSquareCentre(GRID_SQUARE*, MR_SVEC*);
extern	MR_LONG			GetGridSquareHeight(GRID_SQUARE*);
extern	MR_VOID			GetGridSquareNormals(GRID_SQUARE*, MR_VEC*, MR_VEC*);
extern	MR_VOID			GetGridSquareAverageNormal(GRID_SQUARE*, MR_VEC*);
extern	MR_LONG			GetHeightFromWorldXZAndGridSquare(MR_LONG, MR_LONG, GRID_SQUARE*);
extern	MR_LONG			GetHeightFromWorldXZ(MR_LONG, MR_LONG);
extern	MR_LONG			GetHeightFromWorldXYZ(MR_LONG, MR_LONG, MR_LONG, GRID_SQUARE**);
extern	MR_VOID			GetGridInfoFromWorldXZAndGridSquare(MR_LONG, MR_LONG, GRID_SQUARE*,	GRID_INFO*);
extern	MR_VOID			GetGridInfoFromWorldXZ(MR_LONG, MR_LONG, GRID_INFO*);
extern	MR_VOID			GetGridInfoFromWorldXYZ(MR_LONG, MR_LONG, MR_LONG, GRID_INFO*);
extern	MR_LONG			GetGridStackHeight(GRID_STACK*);

extern	MR_XY			GetNextTileInteresectingLine(GRID_LINE_INTER*);
extern	MR_VOID			GetNextGridLineIntersectionInit(MR_SVEC*, MR_SVEC*, GRID_LINE_INTER*);
extern	MR_BOOL			Does2DLineIntersectGridTile(MR_SVEC*, MR_SVEC*, MR_SHORT, MR_SHORT);

#endif	//__GRID_H

