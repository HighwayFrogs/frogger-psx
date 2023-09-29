/******************************************************************************
*%%%% frogcard.c
*------------------------------------------------------------------------------
*
*	Specific Frogger Memory card load/save/format/delete routines.
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	26.3.97		Gary Richards	Created
*
*%%%**************************************************************************/

#include	"mr_all.h"
#include	"memcard.h"
#include	"frogcard.h"
#include	"project.h"

// None of these SHOULD be used outside this file.
MR_USHORT	guwVersion;				// Stores current version number of save game.
MR_UBYTE	gubSGState;				// What State is the Save Game in ????
MR_BYTE		gbSelectedCard;			// Which card are we currently saving to????
MR_ULONG 	gulResult[2];			// Used to store the results of the H/W CARD_READ.

/******************************************************************************
*%%%% vSGInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	vSGInit();
*
*	FUNCTION		This is used Initialize all the variables that are used 
*					in the save game functions AND to check for any saved
*					games at the start for controller configs and Hi-Scores.
*
*	INPUTS			NONE
*
*	RESULT			MR_SUCCESS/MR_FAILURE
*
*	NOTES			This is basicly a Frogger wrapper for the API functions.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	 8.4.97		Gary Richards	Created
*
*%%%**************************************************************************/

MR_VOID	vSGInit(MR_VOID)
{
	MR_UBYTE i;

	MRDisablePollhost();
	gulResult[0] = Card_get_info(0,TRUE);		// Check for GAME as well.
	gulResult[1] = Card_get_info(1,TRUE);		// Check for GAME as well.
	MREnablePollhost();

	guwVersion = SAVE_GAME_VERSION;				// Stores current version number of save game.
	gubSGState = SAVE_GAME_WAITING;				// What State is the Save Game in ????
	gbSelectedCard = -1;						// Default to 'No Cards' found.
	
	// Check Slots for a current GAME.
	for(i=0;i<2;i++)
	{
		if (CI_GAME_FOUND & gulResult[i])
		{
			printf("Game Found on Card %ld.\n",i);
			// Code goes here to load any required save game data.
		}
	}
}

/******************************************************************************
*%%%% xSaveFroggerData
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_BOOL	xSaveFroggerData();
*
*	FUNCTION		This is used to save a game to a memory card on the PSX.
*					It first checks to see if there are any cards availible
*					and if there are any saved games on these cards.
*
*	INPUTS			NONE
*
*	RESULT			MR_SUCCESS/MR_FAILURE
*
*	NOTES			This is basicly a Frogger wrapper for the API functions.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.3.97		Gary Richards	Created
*
*%%%**************************************************************************/

MR_BOOL	xSaveFroggerData(MR_VOID)
{
	MR_BOOL	xResult = MR_FAILURE;

	switch(gubSGState)
	{
		// Do nothing.
		case SAVE_GAME_WAITING:
			if (MR_CHECK_PAD_PRESSED(0,FRR_TRIANGLE))		// To save game.
				gubSGState = SAVE_GAME_CHECKING_FOR_CARDS;
			break;

		// check the state of any cards that are plugged in.
		case SAVE_GAME_CHECKING_FOR_CARDS:
			MRDisablePollhost();
			gulResult[0] = Card_get_info(0,TRUE);		// Check for GAME as well.
			gulResult[1] = Card_get_info(1,TRUE);		// Check for GAME as well.
			MREnablePollhost();
	
			printf("Card One %d. ",gulResult[0]);
			printf("Card Two %d.\n",gulResult[1]);

			// Check to see if we have TWO cards.
			if ((CI_CARD_PRESENT & gulResult[0]) && (CI_CARD_PRESENT & gulResult[1]))
			{
				printf("Found BOTH cards. Save on which?\n");
				printf("Square for Card 1   Circle for Card 2\n");

				if (MR_CHECK_PAD_PRESSED(0,FRR_SQUARE))
					gbSelectedCard = 0;
	
				if (MR_CHECK_PAD_PRESSED(0,FRR_CIRCLE))
					gbSelectedCard = 1;
			}
			else
			{
				// Find the only card.
				if (CI_CARD_PRESENT & gulResult[0])
					gbSelectedCard = 0;
				else
				{
					if (CI_CARD_PRESENT & gulResult[1])
						gbSelectedCard = 1;
					else
					{
						gbSelectedCard = -1;		// No Cards where found.
						gubSGState = SAVE_GAME_WAITING;
					}
				}
				printf("Found Card %ld.\n",gbSelectedCard);
			}

			if (-1 != gbSelectedCard)
				gubSGState = SAVE_GAME_CHECKING_STATE_OF_SELECTED_CARD;
			break;

		// Check that the card is formated and doesn't contain a saved game.
		case SAVE_GAME_CHECKING_STATE_OF_SELECTED_CARD:
			if (CI_UNFORMATTED & gulResult[gbSelectedCard])
			{
				printf("Selected card not formatted.\n");
				printf("Format Card. Are you sure??.\n");
				printf("Square YES Circle NO.\n");
				gubSGState = SAVE_GAME_FORMAT_CARD;
				break;
			}

			// Check the selected card for a current GAME to overwrite.
			if (CI_GAME_FOUND & gulResult[gbSelectedCard])
			{
				printf("Game Found. Overwrite this Game?\n");
				printf("Square YES Circle NO.\n");
				gubSGState = SAVE_GAME_OVERWRITE_GAME;
				break;
			}
			
			// Found a blank formatted card, so save away.......
			gubSGState = SAVE_GAME_TO_SELECTED_CARD;
			break;

		// Really Format the selected card????
		case SAVE_GAME_FORMAT_CARD:
			if (MR_CHECK_PAD_PRESSED(0,FRR_SQUARE))
			{
				if (CFC_FORMAT_OK == Card_format(gbSelectedCard))
					printf("Format Ok.\n");
				else
					printf("Format Failed.\n");
				gubSGState = SAVE_GAME_WAITING;		// Back to the Start.
				break;
			}
		
			if (MR_CHECK_PAD_PRESSED(0,FRR_CIRCLE))
				gubSGState = SAVE_GAME_WAITING;		// Back to where we started.
			break;

		// Really OverWrite Game????
		case SAVE_GAME_OVERWRITE_GAME:
			if (MR_CHECK_PAD_PRESSED(0,FRR_SQUARE))
				gubSGState = SAVE_GAME_TO_SELECTED_CARD;		// Back to the Start.
		
			if (MR_CHECK_PAD_PRESSED(0,FRR_CIRCLE))
				gubSGState = SAVE_GAME_WAITING;		// Back to where we started.
			break;

		// Save the game to the selected slot.
		case SAVE_GAME_TO_SELECTED_CARD:
			if (MR_FAILURE == xSaveGameDataToCard(gbSelectedCard))
				printf("Save Game Failed.\n");
			else
				printf("Save Game Successful.\n");
			gubSGState = SAVE_GAME_WAITING;
			break;

	}	
	
	return xResult;
}

/******************************************************************************
*%%%% xSaveGameDataToCard
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_BOOL	xSaveGameDataToCard();
*
*	FUNCTION		This is used to save the game data to the memory card. It
*					assume that all checks have been made and that there is 
*					a card in the slot that is passed.
*
*	INPUTS			MR_BYTE	bSelectedCard : The Slot to save the data to.
*
*	RESULT			MR_SUCCESS/MR_FAILURE
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	3.4.97		Gary Richards	Created
*
*%%%**************************************************************************/

MR_BOOL	xSaveGameDataToCard(MR_BYTE bSelectedCard)
{
	MR_ULONG*	ulSaveData;
	MR_ULONG ulResult;

	printf("Starting to save game on card %d.\n",bSelectedCard);

	ulSaveData = Compile_savegame();		// Compile the data for the save game.

	MRDisablePollhost();
	ulResult = Card_save_file((MR_UBYTE*)ulSaveData,SAVEGAME_BUFFER_SIZE,bSelectedCard);
	MREnablePollhost();

	if ((ulResult == CSG_SAVE_ERROR) || (ulResult == CSG_NO_CARD))
	{
		printf("SAVE GAME ERROR!!\n");
		MRFreeMem(ulSaveData);
		return MR_FAILURE;
	}

	MRFreeMem(ulSaveData);
	return MR_SUCCESS;
}

/**********************************************************************************************
* Save Game code From Dean.
***********************************************************************************************/

/**********************************************************************************************
* This is the table that contains all the data that is too be saved to the memory card.
* The first variable is the version number. This is defind in frogcard.h and MUST be
* incremented every time a change is made to the savegame_global_list.
* This is done to avoid problems that can occur when loading an old saved game after the 
* savegame_global_list has changed.
*
* It does mean that some saved games will be lost when changes to the list occur.
*
* History
* 08/04/97,	Gary Richards	Created.
***********************************************************************************************/

BYTE*	Savegame_global_list[] = 
		{
		(MR_BYTE*)&guwVersion,			(MR_BYTE*)(sizeof(MR_USHORT)),
		0};		// Null Terminated.

/*		This is here for reference ONLY 
		(BYTE*)Boom_moving_models, (BYTE*)(sizeof(BOOM_MOVING_MODEL) * 12),
		(BYTE*)turret_info, 			(BYTE*)(sizeof(TURRET_INF) * 6),
		(BYTE*)Crash_sites, 			(BYTE*)(sizeof(CRASH_SITE) * MAX_CRASH_SITES),
		(BYTE*)&Global_Plot,			(BYTE*)(sizeof(struct PH_Plot)),
		(BYTE*)bullet_stock,			(BYTE*)24,
		(BYTE*)missile_stock,		(BYTE*)24,
		(BYTE*)LIMO_damage_flags,	(BYTE*)24,

		(BYTE*)&Boom_worldx,			(BYTE*)4,
		(BYTE*)&Boom_worldz,			(BYTE*)4,
		(BYTE*)&Boom_ytheta,			(BYTE*)4,
		(BYTE*)&Boom_forced_move,	(BYTE*)2,
		(BYTE*)&Boom_player_buls,	(BYTE*)2,
		(BYTE*)&Boom_player_clips,	(BYTE*)2,
		(BYTE*)&Boom_gun_type,		(BYTE*)2,
		(BYTE*)&Boom_mom,				(BYTE*)4,
		(BYTE*)&Boom_angmom,			(BYTE*)4,

		(BYTE*)&fx_on,					(BYTE*)4,
		(BYTE*)&tunes_on,				(BYTE*)4,

		(BYTE*)&vosgen_access_software_counter,	(BYTE*)2,
		(BYTE*)&vosgen_access_droid_counter,		(BYTE*)2,
		(BYTE*)&vosgen_access_destruct_counter,	(BYTE*)2,
		(BYTE*)&joypad_map_id,							(BYTE*)2,*/
										
/*************************************************************************************************
*%%%% Compile_savegame																						Tim Closs
**************************************************************************************************
*

*	SYNOPSIS		MR_ULONG*	Compile_savegame(MR_VOID)
*
*	FUNCTION		Allocates memory for the savegame and compiles it
*
*	INPUTS		none
*
*	RESULT		MR_ULONG*	-	pointer to the start of the compiled game in RAM
*
*%%%*********************************************************************************************/

MR_ULONG*	Compile_savegame(MR_VOID)
{
	MR_ULONG*	mem;
	MR_ULONG*	ptr;
	MR_BYTE*	by_ptr;
	MR_BYTE**	bs_ptr;
	MR_LONG		checksum = 0;

	mem = (MR_ULONG*)MRAllocMem(SAVEGAME_BUFFER_SIZE, "SAVEBUFF");

	// First two longwords will be (checksum), (total length in bytes)
	ptr = mem + 2;										

	memset(mem, 0, SAVEGAME_BUFFER_SIZE);

	//	Add the global data... run through the list of BYTE* and lengths

	by_ptr = (MR_BYTE*)ptr;
	bs_ptr = Savegame_global_list;

	while (*bs_ptr)
		{
		memcpy(by_ptr, *bs_ptr, (MR_LONG)*(bs_ptr + 1));

		by_ptr += (MR_LONG)*(bs_ptr + 1);
		bs_ptr += 2;
		}

	*(mem + 1) = by_ptr - ((MR_BYTE*)mem);

#ifdef PSX_DEBUG
	printf("Savegame size: %d bytes\n", *(mem + 1));
#endif

	// Add longword checksum to first longword in buffer...

	while(--by_ptr >= (MR_BYTE*)(mem + 1))
		{
		checksum += *by_ptr;
		}
	*mem = checksum;

	return(mem);
}


/*************************************************************************************************
*%%%% Uncompile_savegame																					Tim Closs
**************************************************************************************************
*
*	SYNOPSIS		MR_BOOL	Uncompile_savegame(MR_ULONG* ptr)
*
*	FUNCTION		Uncompile a savegame which has been loaded to RAM
*
*	INPUTS		MR_ULONG*	ptr	-	pointer to the start of the compiled game in RAM
*
*	RESULT		FALSE if checksum fails, else TRUE
*
*%%%*********************************************************************************************/

MR_BOOL	Uncompile_savegame(MR_ULONG* ptr)
{
	MR_USHORT	i = 0;
	MR_ULONG*	mem = ptr;
	MR_BYTE*	by_ptr;
	MR_BYTE**	bs_ptr;
  	MR_LONG		checksum = 0;

	// Add longword checksum to first longword in buffer...

	for (i = 4; i < *(mem + 1); i++)
		{
		checksum += *(((MR_BYTE*)(mem)) + i);
		}
	if (checksum != *mem)
		{
		// Bad checksum !
		return(FALSE);
		}

	ptr += 2;

	//	Add the global data... run through the list of BYTE* and lengths

	by_ptr = (MR_BYTE*)ptr;
	bs_ptr = Savegame_global_list;

	while (*bs_ptr)
		{
		memcpy(*bs_ptr, by_ptr, (MR_ULONG)*(bs_ptr + 1));

		by_ptr += (MR_ULONG)*(bs_ptr + 1);
		bs_ptr += 2;
		}

//	Free the memory NO!!! THIS IS DONE IN THE HUD CODE AFTER CALLING THIS FUNCTION!!!
//	Free_mem(mem);

//	Now do all the other stuff that needs doing when a savegame is loaded... 
	// Uncompiled successfully
	return(TRUE);
}



