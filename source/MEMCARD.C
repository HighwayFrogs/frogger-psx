/******************************************************************************
*%%%% memcard.c
*------------------------------------------------------------------------------
*
*	Memory card load/save/format/delete routines.
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

#include	"mr_all.h"
#include	"memcard.h"
#include	"project.h"
#include	"binaries.h"

CARD_HEADER	card_header;

MR_UBYTE		card_buffer[128];

MR_STRPTR	card_names[] = 		// Device names (port 0 and port 1)
				{
				"bu00:",
				"bu10:"
				};

MR_TEXT		card_workstring[64];	// For temporary filenames 'n' stuff


// Memory card event handles (Software)
MR_ULONG		card_SwEvSpIOE;
MR_ULONG		card_SwEvSpERROR;
MR_ULONG		card_SwEvSpTIMOUT;
MR_ULONG		card_SwEvSpNEW;


// Memory card event handles (Hardware)
MR_ULONG		card_HwEvSpIOE;
MR_ULONG		card_HwEvSpERROR;
MR_ULONG		card_HwEvSpTIMOUT;
MR_ULONG		card_HwEvSpNEW;


// --- 
#ifdef	DEBUG

MR_VOID	TestCard(MR_VOID)
{
	MRDisablePollhost();

	while(TRUE)
		{
		VSync(0);

		printf("%02lx ", Card_test_cards());

		pollhost();
		}

	MREnablePollhost();
}

#endif

/******************************************************************************
*%%%% Card_init
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	Card_init(MR_VOID);
*
*	FUNCTION		Initialises the memory card subsystem.
*
*	NOTES			If you change this, be really careful. The memory card subsystem
*					doesn't like being messed with.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Card_init(MR_VOID)
{
	MRDisablePollhost();

	// Open our software/hardware events related to memory cards
	EnterCriticalSection();
	card_SwEvSpIOE		=	OpenEvent(SwCARD,	EvSpIOE,		EvMdNOINTR,	NULL);
	card_SwEvSpERROR 	=	OpenEvent(SwCARD,	EvSpERROR,	EvMdNOINTR,	NULL);
	card_SwEvSpTIMOUT	=	OpenEvent(SwCARD,	EvSpTIMOUT,	EvMdNOINTR,	NULL);
	card_SwEvSpNEW		=	OpenEvent(SwCARD,	EvSpNEW,		EvMdNOINTR,	NULL);
	card_HwEvSpIOE		=	OpenEvent(HwCARD,	EvSpIOE,		EvMdNOINTR,	NULL);
	card_HwEvSpERROR 	=	OpenEvent(HwCARD,	EvSpERROR,	EvMdNOINTR,	NULL);
	card_HwEvSpTIMOUT	=	OpenEvent(HwCARD,	EvSpTIMOUT,	EvMdNOINTR,	NULL);
	card_HwEvSpNEW		=	OpenEvent(HwCARD,	EvSpNEW,		EvMdNOINTR,	NULL);
	ExitCriticalSection();

	// Start the memory card system (shared with controller ports)
	InitCARD(1);
	StartCARD();
	_bu_init();

	// Enable the events	
	EnableEvent(card_SwEvSpIOE);
	EnableEvent(card_SwEvSpERROR);
	EnableEvent(card_SwEvSpTIMOUT);
	EnableEvent(card_SwEvSpNEW);
	EnableEvent(card_HwEvSpIOE);
	EnableEvent(card_HwEvSpERROR);
	EnableEvent(card_HwEvSpTIMOUT);
	EnableEvent(card_HwEvSpNEW);

	MREnablePollhost();
}



/******************************************************************************
*%%%% Card_test_cards
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG	tc_result = Card_test_cards(MR_VOID)
*
*	FUNCTION		Performs testing of both memory card slots, and returns the
*					current status of each memory card slot (in a processed form).				
*
*	RESULT		tc_result	-		Contains flag bits indicating, for each slot,
*											whether a card is present, and whether a 
*											game was found. 
*
*	NOTES			This is a convenience routine. If you want something more 
*					complex, then it's easy to write it yourself.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_test_cards(MR_VOID)
{	

	MR_ULONG tc_result;
	MR_ULONG	tc_status;

	tc_result = 0;

	tc_status = Card_get_info(0, TRUE);		// Get status of slot 0, and look for a save
	if (tc_status & CI_CARD_PRESENT)			// If the card is there, flag it...			
		tc_result |= TC_FOUND_CARD_0;
	if (tc_status & CI_GAME_FOUND)			// If card contains a save, flag it..
		tc_result |= TC_FOUND_GAME_0;

	tc_status = Card_get_info(1, TRUE);		// Get status of slot 1, and look for a save
	if (tc_status & CI_CARD_PRESENT)			// If the card is there, flag it...
		tc_result |= TC_FOUND_CARD_1;
	if (tc_status & CI_GAME_FOUND)			// If card contains a save, flag it...
		tc_result |= TC_FOUND_GAME_1;

	return(tc_result);
}

/******************************************************************************
*%%%% Card_load_file
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG lg_result = Card_load_file(
*												MR_UBYTE*	lg_address,
*												MR_ULONG		lg_length,
*												MR_ULONG		lg_card);
*
*	FUNCTION		Control routine to load 'lg_length' bytes of data from the 
*					saved file on card 'lg_card' to address 'lg_address'. This 
*					function retrys the load a few times.
*
*	INPUTS		lg_address	-			Address to load data into
*					lg_length	-			Bytes of data to load from saved file
*					lg_card		-			Card to load from (0 or 1)
*
*	RESULT		lg_result	-			Result containing status of operation
*
*	NOTES			We can only load 128 byte sectors from the card, so this routine
*					validates lg_length to be a 128-byte multiple.
*
*					This routine retries the load 'CARD_RETRY' times.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_load_file(MR_UBYTE*	lg_address,
								MR_ULONG 	lg_length,
								MR_ULONG		lg_card)
{
	MR_ULONG	lg_retry_count = CARD_RETRY;
	MR_ULONG	lg_load_result = NULL;

	do {
		
		// Attempt to load the file
		lg_load_result = Card_load_file_core(lg_address, lg_length, lg_card);

		// If the load returned an error, retry, else bail out
		if ((lg_load_result == CLG_LOAD_ERROR) || (lg_load_result == CLG_NO_CARD))
			{
			lg_retry_count--;
			}
		else
			break;

		} while (lg_retry_count);

	return(lg_load_result);
}

/******************************************************************************
*%%%% Card_load_file_core
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG	lg_result = Card_load_file_core(
*												MR_UBYTE*	lg_address,
*												MR_ULONG		lg_length,
*												MR_ULONG		lg_card);
*
*	FUNCTION		Core loading routine. Typically called from Card_load_file(), 
*					this routine performs the loading operations on the memory card
*					device.
*
*	INPUTS		lg_address	-			Address to load data into
*					lg_length	-			Bytes of data to load from saved file
*					lg_card		-			Card to load from (0 or 1)
*
*	RESULT		lg_result	-			Result containing status of operation
*
*	NOTES			We can only load 128 byte sectors from the card, so this routine
*					validates lg_length to be a 128-byte multiple.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_load_file_core(	MR_UBYTE*	lg_address,
										MR_ULONG 	lg_length,
										MR_ULONG 	lg_card)
{
	MR_ULONG		lg_status;
	MR_LONG		lg_handle;
	MR_LONG		lg_result;	

	// Get the card status (along with space information)
	lg_status = Card_get_info(lg_card, TRUE);

	if (lg_status & CI_CARD_PRESENT)
		{
		if (lg_status & CI_UNFORMATTED)
			{
			return(CLG_UNFORMATTED);
			}
		else
		if (lg_status & CI_GAME_FOUND)
			{
			
			// Build the filename
			strcpy(card_workstring, card_names[lg_card]);	// Make first part of filename
			strcat(card_workstring, SAVED_GAME_FILE);	  		// Make the rest of the filename

			// Try opening the file
			lg_handle = open(card_workstring, O_RDONLY);

			// If it failed, flag a load error
			if (lg_handle == -1)
				{
				return(CLG_LOAD_ERROR);
				}

			lg_result = CLG_LOAD_OK;

			// Try to read the header, and the main data. 
			if (read(lg_handle, &card_header, sizeof(CARD_HEADER)) != -1)
				{		
				if (read(lg_handle, lg_address, lg_length) == -1)
					lg_result = CLG_LOAD_ERROR;
				}
			else
				lg_result = CLG_LOAD_ERROR;

			// Close the file
			close(lg_handle);

			}
		else
			return(CLG_NO_GAME);	
		}
	else
	if (lg_status & CI_CARD_ERROR)
		{
		lg_result = CLG_LOAD_ERROR;
		}
	else
		{
		lg_result = CLG_NO_CARD;
		}

	return(lg_result);	
}


/******************************************************************************
*%%%% Card_save_file
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG sg_result = Card_save_file(
*												MR_UBYTE*	sg_address,
*												MR_ULONG		sg_length,
*												MR_ULONG		sg_card);
*
*	FUNCTION		Control routine to save 'sg_length' bytes of data to the 
*					saved file on card 'sg_card' from address 'sg_address'. This 
*					function retrys the save a few times.
*
*	INPUTS		sg_address	-			Address to save data from
*					sg_length	-			Bytes of data to save to saved file
*					sg_card		-			Card to save to (0 or 1)
*
*	RESULT		sg_result	-			Result containing status of operation
*
*	NOTES			We can only save 128 byte sectors to the card, so this routine
*					validates sg_length to be a 128-byte multiple.
*
*					This routine retries the save 'CARD_RETRY' times.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_save_file(MR_UBYTE*	sg_address,
								MR_ULONG		sg_length,
								MR_ULONG		sg_card)
{
	MR_ULONG	sg_retry_count = CARD_RETRY;
	MR_ULONG	sg_save_result;

	do {
		
		// Attempt to save the game
		sg_save_result = Card_save_file_core(sg_address, sg_length, sg_card);

		// If save errored, then retry else bail out
		if ((sg_save_result == CSG_SAVE_ERROR) || (sg_save_result == CSG_NO_CARD))
			sg_retry_count--;
		else		
			break;


		} while (sg_retry_count);

	return(sg_save_result);
}


/******************************************************************************
*%%%% Card_save_file_core
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG	sg_result = Card_save_file_core(
*												MR_UBYTE*	sg_address,
*												MR_ULONG		sg_length,
*												MR_ULONG		sg_card);
*
*	FUNCTION		Core saving routine. Typically called from Card_save_file(), 
*					this routine performs the saving operations on the memory card
*					device.
*
*	INPUTS		sg_address	-			Address to save data from
*					sg_length	-			Bytes of data to save to saved file
*					sg_card		-			Card to save to (0 or 1)
*
*	RESULT		sg_result	-			Result containing status of operation
*
*	NOTES			We can only save 128 byte sectors to the card, so this routine
*					validates sg_length to be a 128-byte multiple.
*
*					It is assumed that we're not saving any more that 1 block of
*					data.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_save_file_core(	MR_UBYTE*	sg_address,
									MR_ULONG 	sg_length,
									MR_ULONG	sg_card)
{
	MR_ULONG	sg_status;
	MR_LONG		sg_handle;
	MR_LONG		sg_result;

	// Fill the card header with animation frame, clut data etc etc
	card_header.mc_magic[0] = 'S';										// Magic number 'SC'
	card_header.mc_magic[1] = 'C';
	card_header.mc_type		= 0x11;										// Single icon image
	card_header.mc_blocks	= 1;											// Single block of data (8k)

	strcpy(card_header.mc_name, 	SAVED_GAME_NAME);					// Save game name 

	memcpy(card_header.mc_clut,     ((CARD_IMAGE*)card_image)->ci_clut,  32); 		// Copy CLUT from image 0
	memcpy(card_header.mc_image[0], ((CARD_IMAGE*)card_image)->ci_image, 128);		// Copy image 

//	memcpy(card_header.mc_image[1], ((CARD_IMAGE*)card_image)->ci_image, 128);		// Copy image 
//	memcpy(card_header.mc_image[2], ((CARD_IMAGE*)card_image)->ci_image, 128);		// Copy image 

	// Get the current card status (along with space information)
	sg_status = Card_get_info(sg_card, TRUE);

	if (sg_status & CI_CARD_PRESENT)
		{
		if (sg_status & CI_UNFORMATTED)
			{
			return(CSG_UNFORMATTED);
			}
		else
		if (sg_status & CI_CARD_FULL)
			{
			return(CSG_FULL_CARD);
			}
		else
			{

			// Build the filename
			strcpy(card_workstring, card_names[sg_card]);	// Make first part of filename
			strcat(card_workstring, SAVED_GAME_FILE);	  		// Make the rest of the filename

			// If a game already exists, delete it.
			if (sg_status & CI_GAME_FOUND)
				{
				delete(card_workstring);							// Attempt delete of the file
				}
				 
			// Try opening the file. If we manage it, close it again. The manual says to do this.
			sg_handle = open(card_workstring, O_CREAT | (1<<16));
	
			if (sg_handle == -1)
				return(CSG_SAVE_ERROR);
			else
				close(sg_handle);
	
			// Open the new instance of the game
			sg_handle = open(card_workstring, O_WRONLY);

			if (sg_handle == -1)	
				return(CSG_SAVE_ERROR);

			sg_result = CSG_SAVE_OK;
			
			// Attempt to save the card header and the data
			if (write(sg_handle, &card_header, sizeof(CARD_HEADER)) != -1)
				{
				if (write(sg_handle, sg_address, sg_length) == -1)
					sg_result = CSG_SAVE_ERROR;
				}
			else
				{
				sg_result = CSG_SAVE_ERROR;
				}
		
			close(sg_handle);
			}
		}
	else
	if (sg_status & CI_CARD_ERROR)
		{
		sg_result = CSG_SAVE_ERROR;
		}
	else
		{
		sg_result = CSG_NO_CARD;
		}

	return(sg_result);

}


/******************************************************************************
*%%%% Card_format
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG	fc_result = Card_format(
*												MR_ULONG	fc_card);
*
*	FUNCTION		Formats the card in slot 'fc_card', returning the status of
*					the format.
*
*	INPUTS		fc_card		-			Card slot to perform format operation on
*
*	RESULT		fc_result	-			Result of format operation
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_format(MR_ULONG fc_card)
{
	MR_ULONG	fc_status;
	MR_ULONG	fc_res;
	MR_ULONG	fc_result;

	// Get status of card
	fc_status = Card_get_info(fc_card,FALSE);

	// If a card is there, format the thing...
	if (fc_status & CI_CARD_PRESENT)
		{
		fc_res = format(card_names[fc_card]);	
		
		if (fc_res == 1)
			fc_result = CFC_FORMAT_OK;
		else
			fc_result = CFC_FORMAT_FAILED;
		}
	else
		{
		fc_result = CFC_NO_CARD;
		}

	return(fc_result);
}

/******************************************************************************
*%%%%	Card_get_info
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_ULONG	gc_result = Card_get_info(
*												MR_ULONG	gc_card,
*												MR_ULONG	gc_check_space);
*
*	FUNCTION		Checks the status of the card in slot 'gc_card'. If 
*					'gc_check_space' is true, then this function will 
*					search for a saved game, and flag if the card is full.
*
*	INPUTS		gc_card			-		Card slot to check
*					gc_check_space	-		TRUE to check card contents, else FALSE	
*
*	RESULT		gc_result		-		Status of the card, and optionally it's
*												contents.
*
*	NOTES			This code assumes that we're using a single saved file, taking
*					1 block from the 15 available on a card. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_get_info(	MR_ULONG	gc_card,
								MR_BOOL	gc_check_space)
{
	MR_ULONG		gc_event;
	MR_ULONG		gc_result;
	MR_LONG		gc_chan;
	MR_LONG		gc_block_count;
	struct	DIRENTRY	gc_direntry;
	
	MR_ASSERT((gc_card == 0) || (gc_card == 1));

	gc_result = 0;

	// Which channel is it?
	if (gc_card == 0x00)
		gc_chan = 0x00;			// Channel is slot 00
	else
		gc_chan = 0x10;			// Channel is slot 01

	// Get status of card (if any) in specified slot
	if (_card_info(gc_chan))
		{
		gc_event = Card_get_events_sw();
		
		if (gc_event == CARD_ERROR) 				// If we had an error, inform 
			return(CI_CARD_ERROR);					// calling routine
		else
		if	(gc_event == CARD_TIMOUT)				// No card in slot, so just
			return(CI_NULL);		 					// tell calling routine
		else
		if (gc_event == CARD_NEW)
			{
			Card_clear_events_sw();					// Clear outstanding SW events
			Card_clear_events_hw();					// Clear outstanding HW events
			_card_clear(gc_chan);					// Clear condition for new card
			gc_event = Card_get_events_hw();		// Get new HW event
			}

		Card_clear_events_sw();
		Card_clear_events_hw();
		_card_load(gc_chan);
		
		gc_event = Card_get_events_sw();

		if (gc_event == CARD_NEW)					// --- UNFORMATTED CARD ---
			{
			gc_result |= CI_CARD_PRESENT;			// There's a card in the slot
			gc_result |= CI_UNFORMATTED;			// but it's unformatted
			}
		else 
		if (gc_event == CARD_IOE)					// --- FORMATTED CARD ---
			{
			gc_result |= CI_CARD_PRESENT;			// There's a card in the slot

			// If we've got a card, and it's formatted, and we need space info then go and get it.

			if (gc_check_space)
				{
				gc_block_count = 0;
	
				if ((struct DIRENTRY *)firstfile(card_names[gc_card], &gc_direntry) == &gc_direntry)
					{
					do	{
						gc_block_count += (gc_direntry.size/8192);
		
						// If our save game file is present on the card, set our flag

						if (strcmp(SAVED_GAME_FILE,gc_direntry.name) == 0)
							gc_result |= CI_GAME_FOUND;
				
						} while ((struct DIRENTRY *)nextfile(&gc_direntry) == &gc_direntry);

					// If we've found a saved game, then it doesn't count in the block total
					// because it'll be deleted prior to a new save

					if (gc_result & CI_GAME_FOUND)
						gc_block_count--;

					// If the card is really full, then make a note.

					if (gc_block_count == 15)
						gc_result |= CI_CARD_FULL;
					}
				}
			}
		}

	return(gc_result);		
}


/******************************************************************************
*%%%% Card_get_events_sw
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	Card_get_events_sw(MR_VOID);
*
*	FUNCTION		Returns the current software event type for the memory card
*					subsystem. The type is used to determine the current state of
*					the memory cards.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96.		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_get_events_sw(MR_VOID)
{
	while (1)
		{
		if (TestEvent(card_SwEvSpIOE) == 1)		return(CARD_IOE);
		if (TestEvent(card_SwEvSpERROR) == 1)	return(CARD_ERROR);
		if (TestEvent(card_SwEvSpTIMOUT) == 1)	return(CARD_TIMOUT);
		if (TestEvent(card_SwEvSpNEW) == 1)		return(CARD_NEW);
		}
}

/******************************************************************************
*%%%% Card_get_events_hw
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	Card_get_events_hw(MR_VOID);
*
*	FUNCTION		Returns the current hardware event type for the memory card
*					subsystem. The type is used to determine the current state of
*					the memory cards.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96.		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	Card_get_events_hw(MR_VOID)
{
	while (1)
		{
		if (TestEvent(card_HwEvSpIOE) == 1)		return(CARD_IOE);
		if (TestEvent(card_HwEvSpERROR) == 1)	return(CARD_ERROR);
		if (TestEvent(card_HwEvSpTIMOUT) == 1)	return(CARD_TIMOUT);
		if (TestEvent(card_HwEvSpNEW) == 1)		return(CARD_NEW);
		}
}


/******************************************************************************
*%%%% Card_clear_events_sw
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	Card_clear_events_sww(MR_VOID);
*
*	FUNCTION		Clears all outstanding software events used by the memory card
*					subsystem.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96.		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Card_clear_events_sw(MR_VOID)
{	
	TestEvent(card_SwEvSpIOE);
	TestEvent(card_SwEvSpERROR);
	TestEvent(card_SwEvSpTIMOUT);
	TestEvent(card_SwEvSpNEW);
}


/******************************************************************************
*%%%% Card_clear_events_hw
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	Card_clear_events_hw(MR_VOID);
*
*	FUNCTION		Clears all outstanding hardware events used by the memory card
*					subsystem.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.6.96.		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Card_clear_events_hw(MR_VOID)
{	
	TestEvent(card_HwEvSpIOE);
	TestEvent(card_HwEvSpERROR);
	TestEvent(card_HwEvSpTIMOUT);
	TestEvent(card_HwEvSpNEW);
}
