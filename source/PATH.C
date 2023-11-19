/******************************************************************************
*%%%% path.c
*------------------------------------------------------------------------------
*
*	Handling of (spline and arc) paths
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	17.04.97	Tim Closs		Created
*	
*%%%**************************************************************************/

#include "path.h"
#include "entity.h"
#include "entlib.h"
#include "form.h"
#include "mapload.h"
#include "gamesys.h"


PATH_RUNNER		Path_runner_root;
PATH_RUNNER*	Path_runner_root_ptr;

MR_LONG	Path_spline_fixed_t[6] =
	{
	0x200 * 0,
	0x200 * 0,
	0x200 * 1,
	0x200 * 2,
	0x200 * 3,
	0x200 * 4,
	};


/******************************************************************************
*%%%% InitialisePathRunners
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialisePathRunners(MR_VOID)
*
*	FUNCTION	Initialise the path runners list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialisePathRunners(MR_VOID)
{
	Path_runner_root_ptr = &Path_runner_root;

	Path_runner_root_ptr->pr_next = NULL;
	Path_runner_root_ptr->pr_prev = NULL;
}


/******************************************************************************
*%%%% CreatePathRunner
*------------------------------------------------------------------------------
*
*	SYNOPSIS	PATH_RUNNER*	path_runner =	CreatePathRunner(
*												PATH*	path,
*												MR_LONG	segment,
*												MR_LONG	length)
*
*	FUNCTION	Creates and initialises a PATH_RUNNER to follow a PATH
*
*	INPUTS		path		- 	ptr to path to follow
*				segment		-	segment to start at
*				dist		-	distance along specified segment to start at
*
*	RESULT		path_runner	-	ptr to created structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

PATH_RUNNER*	CreatePathRunner(	PATH*	path,
									MR_LONG	segment,
									MR_LONG	dist)
{
	PATH_RUNNER*	path_runner;
	PATH_SPLINE*	path_spline;


	MR_ASSERT(path);
	MR_ASSERT(segment >= 0);
	MR_ASSERT(segment < path->pa_numsegments);

	// Create structure
	path_runner	= MRAllocMem(sizeof(PATH_RUNNER), "PATH RUNNER");

	// Link new structure into list
	if (path_runner->pr_next = Path_runner_root_ptr->pr_next)
		Path_runner_root_ptr->pr_next->pr_prev = path_runner;
	Path_runner_root_ptr->pr_next = path_runner;
	path_runner->pr_prev = Path_runner_root_ptr;

	// Initialise structure
	path_runner->pr_flags 			= PATH_RUNNER_ACTIVE;
	path_runner->pr_numsegments		= path->pa_numsegments;
	path_runner->pr_segments		= (PATH_SEGMENT**)(&path->pa_segment_ptrs);
	path_runner->pr_segment_type	= path_runner->pr_segments[segment]->ps_type;
	path_runner->pr_segment_ptr		= &path_runner->pr_segments[segment]->ps_segment_ptr;
	path_runner->pr_segment_index	= segment;
	path_runner->pr_segment_dist	= dist;
	path_runner->pr_speed			= 0;
	path_runner->pr_path			= path;

	path_spline 					= path_runner->pr_segment_ptr;
	path_runner->pr_segment_length 	= path_spline->ps_length;

	EvaluatePathRunnerPosition(path_runner);
	EvaluatePathRunnerTotalDistance(path_runner);

	return(path_runner);
}


/******************************************************************************
*%%%% UpdatePathRunners
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdatePathRunners(MR_VOID)
*
*	FUNCTION	Move all PATH_RUNNERs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdatePathRunners(MR_VOID)
{
	PATH_RUNNER*	path_runner;
#ifdef DEBUG_DISPLAY_PATHS
	PATH**			path_pptr;
	MR_LONG			i;
#endif

	path_runner = Path_runner_root_ptr;
	while(path_runner = path_runner->pr_next)
		{
		UpdatePathRunner(path_runner);
		}	

#ifdef DEBUG_DISPLAY_PATHS
	path_pptr 	= Map_path_ptrs;
	i			= Map_path_header->ph_numpaths;
	while(i--)
		{
		MapDebugDisplayPath(*path_pptr);
		path_pptr++;
		}
#endif
}


/******************************************************************************
*%%%% UpdatePathRunner
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdatePathRunner(
*						PATH_RUNNER*	path_runner)
*
*	FUNCTION	Move a PATH_RUNNER along its PATH
*
*	INPUTS		path_runner	-	ptr to PATH_RUNNER to move
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdatePathRunner(PATH_RUNNER*	path_runner)
{
	PATH_SPLINE*	path_spline;


	MR_ASSERT(path_runner);

	path_runner->pr_flags &= ~PATH_RUNNER_JUST_CLEAR_MASK;
	if (path_runner->pr_flags & PATH_RUNNER_ACTIVE)
		{
		if (path_runner->pr_flags & PATH_RUNNER_BACKWARDS)
			{
			// Moving backwards
			path_runner->pr_segment_dist 	-= path_runner->pr_speed;
			path_runner->pr_total_dist 		-= path_runner->pr_speed;
			if (path_runner->pr_segment_dist < 0)
				{
				// Moved into new segment
				if (--path_runner->pr_segment_index < 0)
					{
					// Gone past start of path
					if (path_runner->pr_flags &	PATH_RUNNER_ONE_SHOT)
						{
						// Stop at start
						path_runner->pr_flags |= PATH_RUNNER_AT_END;
						path_runner->pr_flags |= PATH_RUNNER_JUST_HIT_START;

						// Move to start
						path_runner->pr_segment_index++;
						path_runner->pr_segment_param 	= 0;
						path_runner->pr_segment_length 	= 0;
						path_runner->pr_segment_dist 	= 0;
						path_runner->pr_total_dist 		= 0;
						}
					else
						{
						if (path_runner->pr_flags &	PATH_RUNNER_REPEAT)
							{
							// Continue round (next cycle)
							path_runner->pr_segment_index 	= path_runner->pr_numsegments - 1;
							path_runner->pr_flags 			|= PATH_RUNNER_JUST_REPEATED_START;
							goto new_seg;
							}
						else
							{
							// Turn around
							path_runner->pr_flags 			&= ~PATH_RUNNER_BACKWARDS;
							path_runner->pr_flags 			|= PATH_RUNNER_JUST_BOUNCED_START;

							// Bounce off end
							path_runner->pr_segment_index++;
							path_runner->pr_segment_param 	= 0;
							path_runner->pr_segment_length 	= 0;
							path_runner->pr_segment_dist 	= -path_runner->pr_segment_dist;
							path_runner->pr_total_dist 		= path_runner->pr_segment_dist;
							}
						}
					goto tidy_up;
					}
				else
					{
					// Moved into previous segment: not beyond start
					goto new_seg;
					// _dist is -ve, but tidy_up will sort this out
					}
				}
			else
				{
				// Not beyond start of segment
				goto tidy_up;
				}
			}
		else
			{
			// Moving forwards
			path_runner->pr_segment_dist 	+= path_runner->pr_speed;
			path_runner->pr_total_dist 		+= path_runner->pr_speed;
			if (path_runner->pr_segment_dist >= path_runner->pr_segment_length)
				{
				// Moved into new segment
				if (++path_runner->pr_segment_index == path_runner->pr_numsegments)
					{
					// Gone past end of path
					if (path_runner->pr_flags &	PATH_RUNNER_ONE_SHOT)
						{
						// Stop at end
						path_runner->pr_flags 			|= PATH_RUNNER_AT_END;
						path_runner->pr_flags 			|= PATH_RUNNER_JUST_HIT_END;

						// Move to end
						path_runner->pr_segment_index--;
						path_runner->pr_total_dist		-= (path_runner->pr_segment_dist - path_runner->pr_segment_length);
						path_runner->pr_segment_dist	= path_runner->pr_segment_length;
						path_runner->pr_segment_param	= (1 << 12);
						}
					else
						{
						if (path_runner->pr_flags &	PATH_RUNNER_REPEAT)
							{
							// Continue round (next cycle)
							path_runner->pr_segment_index 	= 0;
							path_runner->pr_segment_dist	-= path_runner->pr_segment_length;
							path_runner->pr_total_dist		= path_runner->pr_segment_dist;
							path_runner->pr_flags 			|= PATH_RUNNER_JUST_REPEATED_END;
							goto new_seg;
							}
						else
							{
							// Turn around
							path_runner->pr_flags 			|= PATH_RUNNER_BACKWARDS;
							path_runner->pr_flags 			|= PATH_RUNNER_JUST_BOUNCED_END;

							// Bounce off end
							path_runner->pr_segment_index--;
							path_runner->pr_total_dist		-= ((path_runner->pr_segment_dist - path_runner->pr_segment_length) << 1);
							path_runner->pr_segment_dist	= (path_runner->pr_segment_length << 1) - path_runner->pr_segment_dist;
							path_runner->pr_segment_param	= (1 << 12);
							}
						}
					goto tidy_up;
					}
				else
					{
					// Moved into next segment: not beyond end
					path_runner->pr_segment_dist -= path_runner->pr_segment_length;
					goto new_seg;
					}
				}
			else
				{
				// Not beyond end of segment
				goto tidy_up;
				}
			}

	new_seg:;
		// Have moved into a new segment (which could be of any type)
		// pr_segment_index is the correct new index
		path_runner->pr_segment_type	= path_runner->pr_segments[path_runner->pr_segment_index]->ps_type;
		path_runner->pr_segment_ptr		= &path_runner->pr_segments[path_runner->pr_segment_index]->ps_segment_ptr;

	tidy_up:;
		// All segment types have segment length as 1st entry
		path_spline 					= path_runner->pr_segment_ptr;
		path_runner->pr_segment_length 	= path_spline->ps_length;

		if (path_runner->pr_segment_dist < 0)
			path_runner->pr_segment_dist += path_runner->pr_segment_length;
	
		if (path_runner->pr_total_dist < 0)
			EvaluatePathRunnerTotalDistance(path_runner);

		EvaluatePathRunnerPosition(path_runner);
		}
}


/******************************************************************************
*%%%% KillPathRunner
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillPathRunner(
*				   		PATH_RUNNER*	path_runner)
*
*	FUNCTION	Kill a PATH_RUNNER
*
*	INPUTS		path_runner	-	to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	25.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	KillPathRunner(PATH_RUNNER*	path_runner)
{
	MR_ASSERT(path_runner);
		
	// Remove structure from linked list
	path_runner->pr_prev->pr_next = path_runner->pr_next;
	if	(path_runner->pr_next)
		path_runner->pr_next->pr_prev = path_runner->pr_prev;

	// Free structure memory
	MRFreeMem(path_runner);
}

/******************************************************************************
*%%%% KillAllPathRunners
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillAllPathRunners(MR_VOID)
*
*	FUNCTION	Kill all PATH_RUNNERs
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	02.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	KillAllPathRunners(MR_VOID)
{
	while(Path_runner_root_ptr->pr_next)
		KillPathRunner(Path_runner_root_ptr->pr_next);
}

/******************************************************************************
*%%%% EvaluatePathRunnerPosition
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	EvaluatePathRunnerPosition(
*						PATH_RUNNER*	path_runner)
*
*	FUNCTION	Evaluate position/tangent of path runner
*
*	INPUTS		path_runner	-	ptr to PATH_RUNNER
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Tim Closs		Created
*	13.05.97	Martin Kift		Added reversing entity code
*
*%%%**************************************************************************/

MR_VOID	EvaluatePathRunnerPosition(PATH_RUNNER*	path_runner)
{
	PATH_SPLINE*	path_spline;
	PATH_ARC*		path_arc;
	PATH_LINE*		path_line;
	MR_VEC			vec, vec2, vec3;
	MR_SVEC			svec;
	MR_MAT			matrix;
	MR_LONG			cos, sin, c, t, a, y;


	switch(path_runner->pr_segment_type)
		{
		case PATH_SEGMENT_SPLINE:
			path_spline = path_runner->pr_segment_ptr;
			path_runner->pr_segment_param 	= GetSplineParamFromLength(path_spline, path_runner->pr_segment_dist) << 1;
			MRCalculateSplinePoint(&path_spline->ps_matrix, path_runner->pr_segment_param >> 1, &svec);
			MR_VEC_EQUALS_SVEC(&path_runner->pr_position, &svec);
			MRCalculateSplineTangentNormalised(&path_spline->ps_matrix, path_runner->pr_segment_param >> 1, &path_runner->pr_tangent);
			break;

		case PATH_SEGMENT_ARC:
			path_arc	= path_runner->pr_segment_ptr;
			vec.vx 		= path_arc->pa_start.vx - path_arc->pa_centre.vx;
			vec.vy 		= path_arc->pa_start.vy - path_arc->pa_centre.vy;
			vec.vz 		= path_arc->pa_start.vz - path_arc->pa_centre.vz;
			MRNormaliseVEC(&vec, &vec);
			MR_VEC_EQUALS_SVEC(&vec2, &path_arc->pa_normal);
			MROuterProduct12(&vec, &vec2, &vec3);

			matrix.m[0][0] = vec.vx;
			matrix.m[1][0] = vec.vy;
			matrix.m[2][0] = vec.vz;
			matrix.m[0][1] = -vec2.vx;
			matrix.m[1][1] = -vec2.vy;
			matrix.m[2][1] = -vec2.vz;
			matrix.m[0][2] = -vec3.vx;
			matrix.m[1][2] = -vec3.vy;
			matrix.m[2][2] = -vec3.vz;
			// matrix is now the transform whose local XZ plane is the plane of the arc, and the line from centre to start
			// is the +ve x axis
			path_runner->pr_segment_param	= (path_runner->pr_segment_dist * 0x1000) / path_runner->pr_segment_length;

			c	= path_arc->pa_radius * 0x6487;														// (2*PI*r << 12);
			t	= (path_runner->pr_segment_dist << 12) / c;											// number of complete turns
			a	= ((path_runner->pr_segment_dist << 18) - (t * c)) / (path_arc->pa_radius * 0x192);	// partial angle (0..0x1000)

//			a	= ((path_runner->pr_segment_dist << 12) / (path_arc->pa_radius * 2)) - (t * 0x800);
			y	= (-path_arc->pa_pitch * path_runner->pr_segment_dist) / path_runner->pr_segment_length;
		
			cos	= rcos(a);
			sin	= rsin(a);
			MR_SET_SVEC(&svec, (cos * path_arc->pa_radius) >> 12, y, (sin * path_arc->pa_radius) >> 12);

			gte_SetRotMatrix(&matrix);
			MRApplyRotMatrix(&svec, &vec);
			path_runner->pr_position.vx = vec.vx + path_arc->pa_centre.vx;
			path_runner->pr_position.vy = vec.vy + path_arc->pa_centre.vy;
			path_runner->pr_position.vz = vec.vz + path_arc->pa_centre.vz;

			MR_SET_SVEC(&svec, -sin, 0, cos);
			MRApplyRotMatrix(&svec, &path_runner->pr_tangent);
			break;

		case PATH_SEGMENT_LINE:
			path_line 	= path_runner->pr_segment_ptr;
			vec.vx	= path_line->pl_end.vx - path_line->pl_start.vx;
			vec.vy	= path_line->pl_end.vy - path_line->pl_start.vy;
			vec.vz	= path_line->pl_end.vz - path_line->pl_start.vz;
			path_runner->pr_position.vx = path_line->pl_start.vx + ((vec.vx * path_runner->pr_segment_dist) / path_runner->pr_segment_length);
			path_runner->pr_position.vy = path_line->pl_start.vy + ((vec.vy * path_runner->pr_segment_dist) / path_runner->pr_segment_length);
			path_runner->pr_position.vz = path_line->pl_start.vz + ((vec.vz * path_runner->pr_segment_dist) / path_runner->pr_segment_length);
			MRNormaliseVEC(&vec, &path_runner->pr_tangent);
			path_runner->pr_segment_param	= (path_runner->pr_segment_dist * 0x1000) / path_runner->pr_segment_length;
			break;
		}

	if (path_runner->pr_flags & PATH_RUNNER_BACKWARDS)
		{
		path_runner->pr_tangent.vx = -path_runner->pr_tangent.vx;
		path_runner->pr_tangent.vy = -path_runner->pr_tangent.vy;
		path_runner->pr_tangent.vz = -path_runner->pr_tangent.vz;
		}
}


/******************************************************************************
*%%%% EvaluatePathRunnerTotalDistance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	EvaluatePathRunnerTotalDistance(
*						PATH_RUNNER*	path_runner)
*
*	FUNCTION	Evaluate pr_total_dist
*
*	INPUTS		path_runner	-	ptr to PATH_RUNNER
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	EvaluatePathRunnerTotalDistance(PATH_RUNNER*	path_runner)
{
	PATH_SEGMENT**	segment_pptr;
	MR_LONG			dist, s;


	dist 			= 0;
	segment_pptr 	= path_runner->pr_segments;		
	s				= path_runner->pr_segment_index;
	while(s--)
		{
		// Add on segment length
		dist += ((PATH_SPLINE*)&(*segment_pptr)->ps_segment_ptr)->ps_length;
		segment_pptr++;
		}

	dist 						+= path_runner->pr_segment_dist;
	path_runner->pr_total_dist 	= dist;
}


/******************************************************************************
*%%%% GetSplineParamFromLength
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG param =	GetSplineParamFromLength(
*								PATH_SPLINE*	spline,
*								MR_LONG			length)
*
*	FUNCTION	Get the parameter along a spline from the length along the spline
*
*	INPUTS		spline	-	ptr to spline segment
*				length	-	length in world units along segment
*
*	RESULT		param	-	param (0..0x1000)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.04.97	Tim Closs		Created
*	16.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_LONG	GetSplineParamFromLength(	PATH_SPLINE*	spline,
									MR_LONG			length)
{
	MR_ULONG	i;
	MR_LONG		d, e;


//	length <<= 0;
//	d = length;
//
//	// t is shifted up by 8
//	for (i = 3; i > 0; i--)
//		{
//		d = length - (spline->ps_smooth_t[i - 1] >> 8);
//		if (d >= 0)
//			break;
//		}
//
//	if (!i)
//		d = length;
//
//	// d is ((length - t) << 0)
//	//
//	// The c coefficients are shifted yp by (8 + 8 + 11)
//	e = d;
//	d = 0;
//	d += (spline->ps_smooth_c[i][0] >> 16);
//	d *= e;
//	d >>= 8;
//
//	d += (spline->ps_smooth_c[i][1] >> 16);
//	d *= e;
//	d >>= 8;
//
//	d += (spline->ps_smooth_c[i][2] >> 16);
//	d *= e;
//	d >>= 8;
//
//	d += Path_spline_fixed_t[i];
//	return(d);

	length <<= 5;	// world shift
	d = length;

	// t is shifted up by 8
	for (i = 3; i > 0; i--)
		{
		d = length - (spline->ps_smooth_t[i - 1] >> 3);	// (8 - world shift)
		if (d >= 0)
			break;
		}

	if (!i)
		d = length;

	// d is ((length - t) << (world shift))
	//
	// The c coefficients are shifted up by (8 + 8 + 11)
	e = d;
	d = 0;
	d += (spline->ps_smooth_c[i][0] >> 11);	// (16 - world shift)
	d *= e;
	d >>= 13;		// (8 + world_shift)

	d += (spline->ps_smooth_c[i][1] >> 11);
	d *= e;
	d >>= 13;

	d += (spline->ps_smooth_c[i][2] >> 11);
	d *= e;
	d >>= 13;
	d >>= 5;		// world shift

	d += Path_spline_fixed_t[i + 1];
	return(d);
}


/******************************************************************************
*%%%% ResetPathRunners
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetPathRunners(MR_VOID)
*
*	FUNCTION	Reset all PATH_RUNNERs to PATH_INFO map status
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.04.97	Tim Closs		Created
*	03.06.97	Martin Kift		Moved body of code to ResetPathRunner()
*
*%%%**************************************************************************/

MR_VOID	ResetPathRunners(MR_VOID)
{
	ENTITY**		entity_pptr;
	ENTITY*			entity;
	MR_ULONG		i;
	ENTITY_BOOK*	entity_book;
	FORM_BOOK*		form_book;

	entity_pptr = Map_entity_ptrs;
	i			= Map_entity_header->eh_numentities;
	while(i--)
		{
		entity		= *entity_pptr;
		entity_book	= ENTITY_GET_ENTITY_BOOK(entity);
		form_book	= ENTITY_GET_FORM_BOOK(entity);

		if (entity_book->eb_flags & ENTITY_BOOK_PATH_RUNNER)
			{
			// Check to see how the game is resetting, and whether the entity flag
			// excludes resetting this entity in this type of reset.
			if (Game_reset_flags & GAME_RESET_CHECKPOINT_COLLECTED)
				{
				if (form_book->fb_flags & FORM_BOOK_RESET_ON_CHECKPOINT)
					ResetPathRunner(entity);
				}
			else 
			if (Game_reset_flags & GAME_RESET_FROGS_DEAD)
				{
				if (form_book->fb_flags & FORM_BOOK_RESET_ON_FROG_DEATH)
					ResetPathRunner(entity);
				}
			else
				ResetPathRunner(entity);
			}
		
		entity_pptr++;
		}
}

/******************************************************************************
*%%%% ResetPathRunner
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetPathRunner(MR_VOID* entity_void_ptr)
*
*	FUNCTION	Reset a PATH_RUNNER to PATH_INFO map status
*
*	INPUTS		entity_void_ptr		- void ptr to entity to reset
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.97	Martin Kift		Created
*	04.07.97	Martin Kift		Added support for ENTITY_NO_MOVEMENT flag
*
*%%%**************************************************************************/

MR_VOID	ResetPathRunner(MR_VOID* entity_void_ptr)
{
	PATH_INFO*		path_info;
	PATH_RUNNER*	path_runner;
	PATH_SPLINE*	path_spline;
	ENTITY*			entity;

	entity		= (ENTITY*)entity_void_ptr;
	path_info	= (PATH_INFO*)(entity + 1);
	path_runner = entity->en_path_runner;

	// Couple of asserts to ensure everything is ok
	MR_ASSERT(entity->en_path_runner);

	path_runner->pr_segment_index	= path_info->pi_segment_id,
	path_runner->pr_segment_dist	= path_info->pi_segment_dist;
	path_runner->pr_speed 			= path_info->pi_speed;

	path_runner->pr_segment_type	= path_runner->pr_segments[path_runner->pr_segment_index]->ps_type;
	path_runner->pr_segment_ptr		= &path_runner->pr_segments[path_runner->pr_segment_index]->ps_segment_ptr;

	path_runner->pr_flags 			= PATH_RUNNER_ACTIVE | path_info->pi_motion_type;

	path_spline 					= path_runner->pr_segment_ptr;
	path_runner->pr_segment_length 	= path_spline->ps_length;

	// Look at the entity flag (really the no movement flag) and if its set, 
	// mark the path runner as paused too
	if (entity->en_flags & ENTITY_NO_MOVEMENT)
		entity->en_path_runner->pr_flags &= ~PATH_RUNNER_ACTIVE;
	else
		entity->en_path_runner->pr_flags |= PATH_RUNNER_ACTIVE;

	EvaluatePathRunnerPosition(path_runner);
	EvaluatePathRunnerTotalDistance(path_runner);
}

/******************************************************************************
*%%%% TestPaths
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	TestPaths(MR_VOID)
*
*	FUNCTION	Test path functions
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	TestPaths(MR_VOID)
{
#ifdef	DEBUG
	MR_VIEWPORT*	viewport0;
	MR_FRAME*		frame_camera;
	MR_VEC			vec;
	MR_SVEC			svec;

   	MRSetDisplayClearColour(0x00, 0x00, 0x40);

	MRDebugInitialiseDisplay();

	// Set up viewport
	MR_SET_VEC(&vec, 0, -8192, 0);
	MR_SET_SVEC(&svec, -1000, 0, 0); 
	viewport0 		= MRCreateViewport(NULL, NULL, MR_VP_SIZE_2048, 0);
	frame_camera 	= MRCreateFrame(&vec, &svec, NULL);
	MRSetViewportCamera(viewport0, frame_camera);
	
	while(1)
		{
#ifdef PSX
		DrawSync(0);
		VSync(0);
#endif
		MRSwapDisplay();
		MRDebugStartDisplay();

		MRReadInput();
		MRUpdateFrames();
		MRUpdateObjects();           
		MRUpdateViewportRenderMatrices();
		MRRenderViewport(viewport0);
#ifdef PSX  
		ProgressMonitor();
#endif
		}

#endif
}
