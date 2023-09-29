/******************************************************************************
*%%%% xalist.c
*------------------------------------------------------------------------------
*
*	XA-Track list for each level
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	20.05.97	Gary Richards	Created
*	26.06.97	Gary Richards	Updated with new Tunes.
*
*%%%**************************************************************************/

#include "xalist.h"
#include "gamesys.h"

MR_BYTE	Game_xa_tunes[80]	= 
{
	LT_CAVES1,		// Caves
	LT_CAVES2,
	LT_CAVES1,
	LT_CAVES2,
	LT_CAVES1,
	LT_CAVES2,

	LT_DESERT2,		// Desert
	LT_DESERT1,
	LT_DESERT2,
	LT_DESERT2,
	LT_DESERT1,
	LT_DESERT1,

	LT_JUNGLE3,		// Forest
	LT_FOREST1,
	LT_JUNGLE3,
	LT_FOREST1,
	LT_JUNGLE3,
	LT_FOREST1,

	LT_JUNGLE1,		// Jungle
	LT_JUNGLE1,
	LT_JUNGLE1,
	LT_JUNGLE1,
	LT_JUNGLE1,
	LT_JUNGLE1,

	LT_ORIGINAL1,	// Original
	LT_ORIGINAL1,
	LT_ORIGINAL2,
	LT_ORIGINAL2,
	LT_ORIGINAL2,
	LT_ORIGINAL1,

	LT_JUNGLE3,		// Ruins
	LT_JUNGLE3,
	LT_JUNGLE3,
	LT_JUNGLE3,
	LT_JUNGLE3,
	LT_JUNGLE3,

	LT_SEWER2,		// Swamp
	LT_SEWER2,
	LT_SEWER1,
	LT_SEWER2,
	LT_SEWER1,
	LT_SEWER1,

	LT_SKY2,	   	// Sky
	LT_SKY1,
	LT_SKY2,
	LT_SKY2,
	LT_SKY1,
	LT_SKY1,
		 
	LT_SUBURBIA1,	// Suburbia
	LT_SUBURBIA2,
	LT_SUBURBIA2,
	LT_SUBURBIA1,
	LT_SUBURBIA2,
	LT_SUBURBIA2,

	LT_INDUSTRIAL2,
	LT_INDUSTRIAL1,
	LT_INDUSTRIAL2,
	LT_INDUSTRIAL1,
	LT_INDUSTRIAL2,
	LT_INDUSTRIAL1,

	-1,				// Dummy!!!	
	-1,
	-1,
	-1,
	-1,
	-1,
};

MR_BOOL	Game_pausing_xa = FALSE;

#ifdef	PSX
/******************************************************************************
*%%%% PlayZoneComplete
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayZoneComplete
*
*	FUNCTION	Takes the level number and plays the zone complete XA for that level.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Gary Richards	Created
*	28.08.97	Tim Closs		Fixed bug
*
*%%%**************************************************************************/
MR_VOID PlayZoneComplete(MR_VOID)
{
	MR_LONG	index;


	index = Game_map_theme - 1;					// 0..9

#ifdef PSX
	XAPlayChannel(	LEVEL_TUNES4 + (index / 7),	// this is TUNES4 or TUNES5
					index % 7,					// this is 0..6
					FALSE);				
#endif
}


/******************************************************************************
*%%%% PlayLevelMusic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayLevelMusic
*
*	FUNCTION	Play's the tunes for the curent level.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.08.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID PlayLevelMusic(MR_LONG requested_tune)
{
#ifdef PSX
	// Only if Tune is valid.																				  
	if (requested_tune != -1)
		{
//		if (requested_tune < TRACK1_SWAP)
//			// Play from Stream 1.
//			XAPlayChannel(LEVEL_TUNES1,requested_tune,TRUE);						// Play channel and loop it!
//		else
//			{
//			if (requested_tune < TRACK2_SWAP)
//				// Play from Stream 2.
//				XAPlayChannel(LEVEL_TUNES2,(requested_tune - TRACK1_SWAP),TRUE);	// Play channel and loop it!
//			else
//				// Play from Stream 3.
//				XAPlayChannel(LEVEL_TUNES3,(requested_tune - TRACK2_SWAP),TRUE);	// Play channel and loop it!
//			}

		// Tim's suggested alternative:
		XAPlayChannel(	LEVEL_TUNES1 + (requested_tune / 7),	// TUNES1, TUNES2 or TUNES3
						requested_tune % 7,
						TRUE);

		Game_pausing_xa = FALSE;
		}
#endif
}

#endif //PSX
