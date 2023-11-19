/******************************************************************************
*%%%% water.c
*------------------------------------------------------------------------------
*
*	This file contains all functions / anim lists relating to water effects. 
*	These include splashes, bubbles, incidental fish (although these could 
*	be made more complex). Most of these use particle generators.
*
*	A lot of the particle code allocates an SP_CORE structure and uses the 
*	API sprite code to handle images.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "water.h"

// Globals
MR_BYTE			Water_sin_offset_table[WATER_SIN_OFFSET_TABLE_SIZE];	// 32 bytes seems fine

//MR_ULONG		Water_surface_display_list[]=
//{
//	MR_SPRT_SETSPEED,	8,
//	MR_SPRT_SETSCALE,	50,
///*	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf00,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf01,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf02,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf03,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf04,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf05,
//	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_surf06,*/
//	MR_SPRT_HALT												
//};


/******************************************************************************
*%%%% WaterInitialiseSinOffsetsTable
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	WaterInitialiseSinOffsetsTable(MR_VOID)
*
*	FUNCTION	Set up water sin table
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	WaterInitialiseSinOffsetsTable(MR_VOID)
{
	MR_LONG		i, angle, total, offset;
	MR_LONG		last_sin, current_sin;
	MR_BYTE		*entry;

	// Initialise vars
	last_sin	= 0;
	total		= 0;
	entry		= Water_sin_offset_table;
	
	// Now do the biz!
	for(i=0; i<WATER_SIN_OFFSET_TABLE_SIZE; i++)
		{
		angle = ( (i+1) << (12 - WATER_SIN_OFFSET_TABLE_SHIFT) ) & 0xfff;

		// get the result of sin, and scale the result DOWN.
		current_sin = rsin(angle) >> WATER_SIN_OFFSET_TABLE_SCALE_SHIFT;

		// we only want to step
		offset = current_sin - last_sin;
		MR_ASSERT( abs(offset) < 64);										// this MUST fit in a byte (signed)
		total += offset;
	
		// fill out the entry in the table
		*entry = (MR_BYTE)offset;

		// next please
		last_sin = current_sin;
		entry++;
	}

	// Just a check to make sure we end up where we started
	MR_ASSERT(total == 0);
}

/******************************************************************************
*%%%% WaterWibbleVertices
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	WaterWibbleVertices(MR_VOID)
*
*	FUNCTION	Wibble water vertices
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	WaterWibbleVertices(	MR_SVEC**	vertices, 
								MR_LONG		num_vertices)
{
	MR_SHORT		sin, cos;
	MR_LONG			start, entry;
	static MR_SHORT	count = 0;
	MR_SVEC**		source;

	source = vertices;
	MR_ASSERT(source);

	// first entry in table
	start = count >> WATER_SIN_OFFSET_TABLE_SPEED;			// could use MRFrame_number, *if* this is called from 												
															// render code.
	// run through the vertices
	while (num_vertices)
		{
		// sin
		entry	= start & (WATER_SIN_OFFSET_TABLE_SIZE-1);
		sin		= (MR_SHORT)Water_sin_offset_table[entry];

		// cos
		entry	+= WATER_SIN_OFFSET_TABLE_COS_OFFSET;
		entry	&= (WATER_SIN_OFFSET_TABLE_SIZE-1);
		cos		= (MR_SHORT)Water_sin_offset_table[entry];
		
		(*source)->vx += sin;						// You may want to shift these values UP.
		(*source)->vz += cos;						// IN NO CIRCUMSTANCE SHIFT THEM DOWN, as you may
													// end up with polys/object/whatever creeping across
		start++;									// the screen. :(
		source++;
		num_vertices--;
		}
	count++;
}

#ifdef INCLUDE_UNUSED_FUNCTIONS
/******************************************************************************
*%%%% WaterGetSinCosOffsets
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	WaterGetSinCosOffsets(
*						MR_SHORT*	sin,
*						MR_SHORT*	cos)
*
*	FUNCTION	Simple func to retrieve sin/cos offset from table - based on 
*				entry from MRFrame_number
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*	12.11.23	Kneesnap		Disabled to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	WaterGetSinCosOffsets(	MR_SHORT*	sin, 
								MR_SHORT*	cos)
{
	MR_LONG		i;

	// sin
	if (sin)
		{
		i		= (MRFrame_number >> WATER_SIN_OFFSET_TABLE_SPEED) & (WATER_SIN_OFFSET_TABLE_SIZE-1);
		*sin	= (MR_SHORT)Water_sin_offset_table[i];
		}

	// cos
	if (cos)
		{
		i		= ((MRFrame_number >> WATER_SIN_OFFSET_TABLE_SPEED)+WATER_SIN_OFFSET_TABLE_COS_OFFSET) & (WATER_SIN_OFFSET_TABLE_SIZE-1);
		*cos	= (MR_SHORT)Water_sin_offset_table[i];
		}
}



/******************************************************************************
*%%%% WaterGetSinCosOffsets
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	WaterGetSinCosOffsets(
*						MR_VIEWPORT*	viewport,
*						MR_VOID*		owner)
*
*	FUNCTION	Creates randomly positioned sploshes
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Martin Kift		Created
*	12.11.23	Kneesnap		Disabled to byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_OBJECT* WaterCreateSurfaceIndication(MR_VIEWPORT*	viewport, 
										MR_VOID*		owner)
{
//	MR_OBJECT*	gen;
//	
//	gen = NULL;
//
//	MR_ASSERT(viewport);
//
//	// create the particle generator
//	if (gen = MRCreatePgen(&Water_surface_generator, NULL, MR_OBJ_STATIC, NULL))
//		{
//		((MR_PGEN*)gen->ob_extra)->pg_owner = owner;							
//		MRAddObjectToViewport(gen, viewport, NULL);
//		}
//	return gen;

	return NULL;
}
#endif
