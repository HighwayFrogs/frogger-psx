/******************************************************************************
*%%%% zone.h
*------------------------------------------------------------------------------
*
*	Zone handling code
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	21.04.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	__ZONE_H
#define	__ZONE_H

#include "mr_all.h"


//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

// Compile options

// Zone types
enum	{
		ZONE_TYPE_CAMERA,
		};

// Zone flags
#define	ZONE_FLAG_OUTRO			(1<<1)		// special outro camera zone
#define	ZONE_FLAG_SEMIFORCED	(1<<2)		// if this is set, player CAN rotate away from specified direction
#define	ZONE_FLAG_ABSOLUTE_Y	(1<<3)		// interpret y value in source and target offsets as world y
#define	ZONE_FLAG_CHECKPOINT	(1<<4)		// ignore code zoom-in, and keep mappy camera offset


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

typedef	struct	__zone				ZONE;
typedef	struct	__zone_region		ZONE_REGION;
typedef	struct	__zone_camera		ZONE_CAMERA;


struct	__zone
	{
	MR_USHORT		zo_type;			// zone type (enum in entities file)
	MR_USHORT		zo_numregions;		// number of ZONE_REGIONs (0 or 2..)
	MR_USHORT		zo_xmin;			// grid square coords of bounding region
	MR_USHORT		zo_zmin;
	MR_USHORT		zo_xmax;
	MR_USHORT		zo_zmax;
	ZONE_REGION*	zo_regions;			// ptr to start of ZONE_REGION array

	};	// ZONE	


struct	__zone_region
	{
	MR_SHORT		zr_xmin;			// grid square coords of region
	MR_SHORT		zr_zmin;
	MR_SHORT		zr_xmax;
	MR_SHORT		zr_zmax;

	};	// ZONE_REGION


struct	__zone_camera
	{
	MR_USHORT		zc_flags;
	MR_SHORT		zc_direction;		// force camera rotation to this direction (or -1 if none)
	MR_SVEC			zc_source_ofs_n;
	MR_SVEC			zc_target_ofs_n;
	MR_SVEC			zc_source_ofs_e;
	MR_SVEC			zc_target_ofs_e;
	MR_SVEC			zc_source_ofs_s;
	MR_SVEC			zc_target_ofs_s;
	MR_SVEC			zc_source_ofs_w;
	MR_SVEC			zc_target_ofs_w;

	};	// ZONE_CAMERA


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

ZONE_REGION*	CheckCoordsInZoneRegion(MR_LONG, MR_LONG, ZONE_REGION*);
ZONE_REGION*	CheckCoordsInZone(MR_LONG, MR_LONG,	ZONE*);
MR_BOOL			CheckCoordsInZones(MR_LONG,	MR_LONG, MR_ULONG, ZONE**, ZONE_REGION**);


#endif	//__ZONE_H

