/******************************************************************************
*%%%% xalist.h
*------------------------------------------------------------------------------
*
*	Header file for XA-Track List 
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	13.5.97		Gary Richards	Created
*
*%%%**************************************************************************/

#ifndef	__XALIST_H
#define	__XALIST_H

#include	"system.h"
#include	"mr_all.h"

// Track list for the level tunes.

// ----------- PSX defines ----------------
#ifdef PSX

// Track ONE.
enum
	{
	LEVEL_TUNES1,				// Track One.
	LEVEL_TUNES2,				// Track Two.	(Starts at LT_SKY1)
	LEVEL_TUNES3,				// Track Three	(Starts at LT_ORIGINAL2)
	LEVEL_TUNES4,				// Track Four 	(Zone Complete.)
	LEVEL_TUNES5,				// Track Five 	(More Zone Complete.)
	};											

// Channels within Track ONE.
enum
	{
	// ----------------------------------------------
	LT_SKY1,					// Channel 0, Track 1.
	LT_INDUSTRIAL2,				// Channel 1, Track 1.
	LT_CAVES1,					// Channel 2, Track 1.
	LT_SUBURBIA2,				// Channel 3, Track 1.
	LT_SEWER1,					// Channel 4, Track 1.
	LT_CAVES2,					// Channel 5, Track 1.	
	LT_SUBURBIA1,				// Channel 6, Track 1.
	// ----------------------------------------------
	LT_ORIGINAL1,				// Channel 0, Track 2.
	LT_JUNGLE3,					// Channel 1, Track 2.
	LT_DESERT1,					// Channel 2, Track 2.
	LT_JUNGLE1,					// Channel 3, Track 2.			
	LT_SEWER2,					// Channel 4, Track 2.
	LT_INDUSTRIAL1,				// Channel 5, Track 2.
	LT_DESERT2,					// Channel 6, Track 2.		
	// ----------------------------------------------
	LT_JUNGLE2,					// Channel 0, Track 3.
	LT_FOREST1,					// Channel 1, Track 3.		
	LT_SKY2,					// Channel 2, Track 3.
	LT_ORIGINAL2,				// Channel 3, Track 3.
	LT_FOREST2,					// Channel 4, Track 3.
	LT_LEVEL_SELECT,			// Channel 5, Track 3.
	LT_PAD,						// 
	// ----------------------------------------------
	// Zone Complete from here.
	// ----------------------------------------------
	LT_CAVE_ZONE_COMPLETE,		// Channel 0, Track 4.
	LT_DESERT_ZONE_COMPLETE,	// Channel 1, Track 4.		
	LT_FOREST_ZONE_COMPLETE,	// Channel 2, Track 4.
	LT_JUNGLE_ZONE_COMPLETE,	// Channel 3, Track 4.
	LT_RETRO_ZONE_COMPLETE,		// Channel 4, Track 4.
	LT_RUINS_ZONE_COMPLETE,		// Channel 5, Track 4.
	LT_SWAMP_ZONE_COMPLETE,		// Channel 6, Track 4. 
	// ----------------------------------------------
	LT_SKY_ZONE_COMPLETE,		// Channel 0, Track 5.
	LT_SUBURBIA_ZONE_COMPLETE,	// Channel 1, Track 5.		
	LT_VOLCANO_ZONE_COMPLETE,	// Channel 2, Track 5.
	LT_GAMEOVER,				// Channel 3, Track 5.
	LT_PAD1,					// Channel 4, Track 5.
	LT_PAD2,					// Channel 5, Track 5.
	LT_PAD3,					// Channel 6, Track 5.
	// ----------------------------------------------
	};

#define	TRACK1_SWAP		(LT_ORIGINAL1)
#define TRACK2_SWAP		(LT_JUNGLE2)
#define	TRACK3_SWAP		(LT_CAVE_ZONE_COMPLETE)
#define	TRACK4_SWAP		(LT_SKY_ZONE_COMPLETE)

// ----------- Win95 defines ----------------
#else

enum
	{
	LT_CAVES1 = 2,
	LT_CAVES2,
	LT_DESERT1,
	LT_DESERT2,
	LT_FOREST1,
	LT_FOREST2,
	LT_VOLCANO1,
	LT_VOLCANO2,
	LT_JUNGLE1,
	LT_JUNGLE2,
	LT_JUNGLE3,
	LT_LEVEL_SELECT,
	LT_ORIGINAL1,
	LT_ORIGINAL2,
	LT_SWAMP1,
	LT_SWAMP2,
	LT_SKY1,
	LT_SKY2,
	LT_SUBURBIA1,
	LT_SUBURBIA2,

	// below are dummy, until tracks turn up
	LT_SEWER1,
	LT_SEWER2,
	LT_INDUSTRIAL1,
	LT_INDUSTRIAL2,
	};

#endif

extern MR_VOID PlayZoneComplete(MR_VOID);
extern MR_VOID PlayLevelMusic(MR_LONG);

extern MR_BYTE	Game_xa_tunes[80];
extern MR_BOOL	Game_pausing_xa;

#endif	//__XALIST_H
