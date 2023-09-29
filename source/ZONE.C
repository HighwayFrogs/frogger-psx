/******************************************************************************
*%%%% zone.c
*------------------------------------------------------------------------------
*
*	Zone handling code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "zone.h"
#include "mapload.h"



/******************************************************************************
*%%%% CheckCoordsInZoneRegion
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ZONE_REGION* region =	CheckCoordsInZoneRegion(
*										MR_LONG			x,
*										MR_LONG			z,
*										ZONE_REGION*	region)
*
*	FUNCTION	Check if grid coords are inside a ZONE_REGION
*
*	INPUTS		x		-	grid x coord
*				z		-	grid z coord
*				region	-	region to check against
*
*	RESULT		region	-	input region if inside, else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

ZONE_REGION*	CheckCoordsInZoneRegion(MR_LONG			x,
										MR_LONG			z,
										ZONE_REGION*	region)
{
	MR_ASSERT(region);

	
	if	(
		(x >= region->zr_xmin) &&
		(x <= region->zr_xmax) &&
		(z >= region->zr_zmin) &&
		(z <= region->zr_zmax)
		)
		return(region);
	else
		return(NULL);
}


/******************************************************************************
*%%%% CheckCoordsInZone
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ZONE_REGION* region =	CheckCoordsInZone(
*										MR_LONG	x,
*										MR_LONG	z,
*										ZONE*	zone)
*
*	FUNCTION	Check if grid coords are inside a ZONE
*
*	INPUTS		x		-	grid x coord
*				z		-	grid z coord
*				zone	-	zone to check against
*
*	RESULT		region	-	ZONE_REGION we are inside (if any), else NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

ZONE_REGION*	CheckCoordsInZone(	MR_LONG	x,
									MR_LONG	z,
									ZONE*	zone)
{
	ZONE_REGION*	region;
	MR_ULONG		i;


	MR_ASSERT(zone);
	
	if	(
		(x >= zone->zo_xmin) &&
		(x <= zone->zo_xmax) &&
		(z >= zone->zo_zmin) &&
		(z <= zone->zo_zmax)
		)
		{
		// Inside zone bounding area
		region 	= zone->zo_regions;
		if (i = zone->zo_numregions)
			{
			while(i--)
				{
				if	(
					(x >= region->zr_xmin) &&
					(x <= region->zr_xmax) &&
					(z >= region->zr_zmin) &&
					(z <= region->zr_zmax)
					)
					return(region);

				region++;
				}
			}
		else
			{
			// ZONE has 0 regions, ie. bounding area is whole zone
			region = (ZONE_REGION*)&zone->zo_xmin;
			return(region);
			}
		}

	return(NULL);
}


/******************************************************************************
*%%%% CheckCoordsInZones
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL result =	CheckCoordsInZones(
*							  		MR_LONG			x,
*							  		MR_LONG			z,
*							  		MR_ULONG		type,
*							  		ZONE**			zone_pptr,
*							  		ZONE_REGION**	zone_region_pptr)
*
*	FUNCTION	Check if grid coords are inside any ZONE
*
*	INPUTS		x					-	grid x coord
*				z					-	grid z coord
*				type				-	type of zone to check against
*				zone_pptr			-	ptr to where to store ZONE* (or NULL)
*				zone_region_pptr	-	ptr to where to store ZONE_REGION* (or NULL)
*
*	RESULT		result				-	TRUE if inside any ZONE, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_BOOL	CheckCoordsInZones(	MR_LONG			x,
					  		MR_LONG			z,
					  		MR_ULONG		type,
					  		ZONE**			zone_pptr,
					  		ZONE_REGION**	zone_region_pptr)
{
	ZONE*			zone;
	ZONE**			zone_list;
	ZONE_REGION*	region;
	MR_ULONG		i, j;


	MR_ASSERT(zone_pptr);
	MR_ASSERT(zone_region_pptr);
	
	zone_list	= Map_zone_ptrs;
	i			= Map_zone_header->zh_numzones;	
	while(i--)
		{
		zone = *zone_list;
		if (zone->zo_type == type)
			{
			if	(
				(x >= zone->zo_xmin) &&
				(x <= zone->zo_xmax) &&
				(z >= zone->zo_zmin) &&
				(z <= zone->zo_zmax)
				)
				{
				// Inside zone bounding area
				region 	= zone->zo_regions;
				if (j = zone->zo_numregions)
					{
					while(j--)
						{
						if	(
							(x >= region->zr_xmin) &&
							(x <= region->zr_xmax) &&
							(z >= region->zr_zmin) &&
							(z <= region->zr_zmax)
							)
							goto found;
		
						region++;
						}
					}
				else
					{
					// ZONE has 0 regions, ie. bounding area is whole zone
					region = (ZONE_REGION*)&zone->zo_xmin;
					goto found;
					}
	
				// Inside ZONE, but not any ZONE_REGION
				}
			}
		zone_list++;
		}

	// Checked all ZONEs
	*zone_pptr 			= NULL;
	*zone_region_pptr 	= NULL;
	return(FALSE);

	found:;
	*zone_pptr 			= zone;
	*zone_region_pptr 	= region;
	return(TRUE);
}
