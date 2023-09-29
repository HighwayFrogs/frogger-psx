/******************************************************************************
*%%%% path.h
*------------------------------------------------------------------------------
*
*	Handling of (spline and arc) paths
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__PATH_H
#define	__PATH_H

#include "mr_all.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options
//#define	DEBUG_DISPLAY_PATHS

// Path runner flags (PATH_INFO flags)
#define	PATH_RUNNER_ACTIVE				(1<<0)		// update runner
#define	PATH_RUNNER_BACKWARDS			(1<<1)		// runner is moving from end of path to start
#define	PATH_RUNNER_ONE_SHOT			(1<<2)		// runner stops at end of path
#define	PATH_RUNNER_REPEAT				(1<<3)		// runner repeats path
#define	PATH_RUNNER_AT_END				(1<<4)		// runner has stopped at end of path
//#define	PATH_RUNNER_NO_SPLINE_SMOOTHING	(1<<5)		// object moves at constant parameter speed on spline segments

// ..for what the PATH_RUNNER did last frame
#define	PATH_RUNNER_JUST_BOUNCED_START	(1<<16)		// bounced off start						ALTERNATING
#define	PATH_RUNNER_JUST_BOUNCED_END	(1<<17)		// bounced off end							ALTERNATING
#define	PATH_RUNNER_JUST_REPEATED_START	(1<<18)		// repeated by flipping from start to end	REPEATING
#define	PATH_RUNNER_JUST_REPEATED_END	(1<<19)		// repeated by flipping from end to start	REPEATING
#define	PATH_RUNNER_JUST_HIT_START		(1<<20)		// hit start								ONE SHOT
#define	PATH_RUNNER_JUST_HIT_END		(1<<21)		// hit end									ONE SHOT

#define	PATH_RUNNER_JUST_CLEAR_MASK		(0x3f0000)	// mask to clear all the above


// Path types
enum	{
		PATH_SEGMENT_SPLINE,
		PATH_SEGMENT_ARC,
		PATH_SEGMENT_LINE,
		};

//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__path				PATH;
typedef	struct	__path_segment		PATH_SEGMENT;
typedef	struct	__path_spline		PATH_SPLINE;
typedef	struct	__path_arc			PATH_ARC;
typedef	struct	__path_line			PATH_LINE;
typedef	struct	__path_runner		PATH_RUNNER;
typedef	struct	__path_info			PATH_INFO;
typedef	struct	__path_interval		PATH_INTERVAL;


struct	__path
	{
	MR_SHORT*			pa_entity_indices;	// ptr (offset) to (-1 terminated) list of entity indices (or NULL)
	MR_ULONG			pa_numsegments;		// number of segments in path
	MR_ULONG			pa_segment_ptrs;	// cast the address of this to a PATH_SEGMENT**

	};	// PATH


struct	__path_segment
	{
	MR_ULONG			ps_type;			// eg. PATH_TYPE_ARC
	MR_ULONG*			ps_segment_ptr;		// cast the address of this to a PATH_SPLINE* or whatever

	};	// PATH_SEGMENT


struct	__path_spline
	{
	MR_LONG				ps_length;			// segment length
	MR_SPLINE_MATRIX	ps_matrix;			// API spline matrix
	MR_LONG				ps_smooth_t[4];		// smoothing coefficients
	MR_LONG				ps_smooth_c[4][3];	// smoothing coefficients

	};	// PATH_SPLINE


struct	__path_arc
	{
	MR_LONG				pa_length;			// segment length
	MR_SVEC				pa_start;			// start point
	MR_SVEC				pa_centre;			// centre point
	MR_SVEC				pa_normal;			// normal (mod 0x1000)
	MR_LONG				pa_radius;			// radius
	MR_LONG				pa_pitch;			// delta y in helix frame (this can be -ve.. opposite direction of normal)

	};	// PATH_ARC


struct	__path_line
	{
	MR_LONG				pl_length;			// segment length
	MR_SVEC				pl_start;			// start point
	MR_SVEC				pl_end;				// end point

	};	// PATH_LINE


struct	__path_runner
	{
	PATH_RUNNER*		pr_next;
	PATH_RUNNER*		pr_prev;
	MR_ULONG			pr_flags;			// eg. PATH_RUNNER_ONE_SHOT, PATH_RUNNER_ACTIVE
	MR_ULONG			pr_numsegments;		// number of segments in path
	PATH_SEGMENT**		pr_segments;		// ptr to array of pointers to PATH_SEGMENTs
	MR_ULONG			pr_segment_type;	// current segment type
	MR_VOID*			pr_segment_ptr;		// cast to segment ptr of current type
	MR_LONG				pr_segment_index;	// 0..(numsegments - 1)
	MR_LONG				pr_segment_param;	// current param along current segment (0..0x1000)
	MR_LONG				pr_segment_dist;	// current distance along current segment
	MR_LONG				pr_segment_length;	// of segment in world units
	MR_LONG				pr_speed;			// speed (world units per update)
	MR_VEC				pr_position;		// evaluated position in world
	MR_VEC				pr_tangent;			// evaluated tangent
	MR_LONG				pr_total_dist;		// total distance along path
	PATH*				pr_path;			// ptr to path

	};	// PATH_RUNNER


struct	__path_info
	{
	MR_USHORT			pi_path_id;	   		// index of PATH in map file
	MR_USHORT			pi_segment_id;		// index of segment in PATH
	MR_USHORT			pi_segment_dist;	// distance along segment to start at

	MR_USHORT			pi_motion_type;		// flags, eg. PATH_RUNNER_BACKWARDS
	MR_USHORT			pi_speed;			// speed
	MR_USHORT			pi_pad;

	};	// PATH_INFO


struct	__path_interval
	{
	MR_LONG				pi_path_id;			// index into map PATH list
	MR_LONG				pi_min_length;		// minimum (total) length along PATH
	MR_LONG				pi_max_length;		// maximum (total) length along PATH

	};	// PATH_INTERVAL



//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID			TestPaths(MR_VOID);

extern	MR_VOID			InitialisePathRunners(MR_VOID);
extern	PATH_RUNNER*	CreatePathRunner(PATH*,	MR_LONG, MR_LONG);
extern	MR_VOID			UpdatePathRunner(PATH_RUNNER*);
extern	MR_VOID			UpdatePathRunners(MR_VOID);
extern	MR_VOID			KillPathRunner(PATH_RUNNER*);
extern	MR_VOID			KillAllPathRunners(MR_VOID);
extern	MR_VOID			EvaluatePathRunnerPosition(PATH_RUNNER*);
extern	MR_VOID			EvaluatePathRunnerTotalDistance(PATH_RUNNER*);
extern	MR_LONG			GetSplineParamFromLength(PATH_SPLINE*, MR_LONG);
extern	MR_VOID			ResetPathRunners(MR_VOID);
extern	MR_VOID			ResetPathRunner(MR_VOID*);

#endif	//__PATH_H

