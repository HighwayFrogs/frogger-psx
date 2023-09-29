/******************************************************************************
*%%%% playxa.c
*------------------------------------------------------------------------------
*
*	Routines to handle all XA based files for PlayStation, specifically video
*	streams and interleaved XA audio tracks.
*
*	NOTE:	There is an inherent problem with LIBCD.LIB, whereby if you issue a 
*			CdlPause directly after a CdlPlay it can return a successful result,
*			but not actually pause the CD mechanism. This is present in all 
*			versions (as of writing, current version of LIBCD.LIB is 3.5).
*
*			Currently the CdlPlay code in XASubmit issues a number of CdlPause
*			requests to try to get around this. If it becomes a problem, then
*			either add more CdlPause requests, or re-visit the pausing mechanism
*			used within this code. Specifically, it could be changed to chain
*			a number of commands, notably CdlMute, CdlGetLocL, CdlPause. This 
*			would mean that although the Pause could fail, there would be no 
*			audio (unless the CdlMute failed!). On restart of the audio, we could
*			chain a CdlReadS using the sector location from the previous
*			CdlGetLocL command, and a CdlDeMute too.. just to make sure the audio
*			was starting up again.
*
*			Or, alternatively, make a 'Play' request actually queue a 'Seek' and
*			a 'Play'. Then, when the 'Play' is interpreted, we can ignore it if 
*			we're in pause mode. After all, there only seems to be a problem when
*			we use CdlPlay() with a starting sector location... 
*
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	05.06.95	Dean Ashton		Created
*	29.07.97	Gary Richards	Added a Start/Shutdown flag.
*
*%%%**************************************************************************/

#include	"system.h"
#include	"mr_all.h"
#include	"playxa.h"
#include	"sprdata.h"
#include	"project.h"
#include	"main.h"

// Names of all stream/interleaved XA files in order of associated enum value
XA_FILE		xa_file_list[] =
				{
					// XF_FR_LEVEL_TUNES1_XA

					{	"\\L_TUNES1.STR;1",				// File name
				 		NULL,						 	// Pointer to change list 
						{			
						DEF_XA_LENGTH(2,26,0),			// Sky1
						DEF_XA_LENGTH(2,8,4),			// Industrial2
						DEF_XA_LENGTH(2,5,21),			// Caves1
						DEF_XA_LENGTH(2,5,7),			// Suburbia2
						DEF_XA_LENGTH(2,5,1),			// Sewer1
						DEF_XA_LENGTH(2,4,24),			// Caves2
						DEF_XA_LENGTH(2,4,22),			// Suburbia1
						},
					},

					{	"\\L_TUNES2.STR;1",				// File name
				 		NULL,						 	// Pointer to change list 
						{			
						DEF_XA_LENGTH(2,4,5),			// Original1
						DEF_XA_LENGTH(2,1,0),			// Jungle3.
						DEF_XA_LENGTH(2,0,4),			// Desert1
						DEF_XA_LENGTH(1,59,22),			// Jungle1
						DEF_XA_LENGTH(1,58,25),			// Sewer2 
						DEF_XA_LENGTH(1,58,11),			// Industrial1
						DEF_XA_LENGTH(1,50,1),			// Desert2
						},
					},

					{	"\\L_TUNES3.STR;1",				// File name
				 		NULL,						 	// Pointer to change list 
						{			
						DEF_XA_LENGTH(1,25,4),			// Jungle2
						DEF_XA_LENGTH(1,25,3),			// Forest1
						DEF_XA_LENGTH(1,24,10),			// Sky2
						DEF_XA_LENGTH(1,23,29),			// Original2
						DEF_XA_LENGTH(0,59,7),			// Forest2
						DEF_XA_LENGTH(0,57,4),			// Level Select 
						DEF_XA_LENGTH(0,57,4),			// Dummy Track
						},
					},

					{	"\\L_TUNES4.STR;1",				// File name
				 		NULL,						 	// Pointer to change list 
						{			
						DEF_XA_LENGTH(0,10,0),			// Caves Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Desert Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Forest Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Jungle Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Retro Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Ruins Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Sewer Zone Complete
						},
					},

					{	"\\L_TUNES5.STR;1",				// File name
				 		NULL,						 	// Pointer to change list 
						{			
						DEF_XA_LENGTH(0,10,0),			// Sky Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Sub Zone Complete.
						DEF_XA_LENGTH(0,10,0),			// Industrial Zone Complete.
						DEF_XA_LENGTH(0,9,0),			// Game Over.
						DEF_XA_LENGTH(0,10,0),			// Pad1.
						DEF_XA_LENGTH(0,10,0),			// Pad2.
						DEF_XA_LENGTH(0,10,0),			// Pad3.
						},
					},

					// List terminator

					{	NULL,								
				 		NULL,									
						{			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						DEF_XA_LENGTH(0,0,0),			
						},
					},

				};


// --- Variables used by XA interleaved audio subsystem ---

MR_UBYTE	xa_param[8];							// Parameter block for LIBCD routines
MR_UBYTE	xa_result[8];							// Result block for LIBCD routines
MR_BOOL		xa_reading_cd;							// TRUE if we're supposed to be reading the CD
MR_BOOL		xa_paused_cd;							// TRUE if we're in pause mode, else FALSE.
XA_COMMAND	xa_command_list[XA_MAX_COMMANDS];		// List of commands/parameters
MR_ULONG	xa_command_count;						// Number of commands in the list
MR_ULONG	xa_execute_index;						// Index of currently executing command
MR_ULONG	xa_add_index;							// Index of next command slot to add to
CdlFILTER	xa_filter;								// Filter used to select XA channel
MR_BOOL		xa_channel_play;						// Are we playing a channel-based track
MR_BOOL		xa_looped_play;							// Do we want to loop?

MR_VOID*	xa_old_ready_callback;					// System CdReadyCallback() routine address
MR_VOID*	xa_old_sync_callback;					// System CdSyncCallback() routine address

MR_BOOL		xa_startup_flag;						// This is set to TRUE when startup called
													// and FALSE when shutdown is called.

volatile MR_ULONG	xa_current_file;				// Current file index
volatile MR_LONG	xa_startpos;					// Start position for current XA track
volatile MR_LONG	xa_currpos;						// Current position for current XA track
volatile MR_LONG	xa_endpos;						// End position (adjusted) for current XA track
volatile MR_ULONG*	xa_change_list;					// Changes pointer for current XA track
volatile MR_ULONG	xa_change_index;				// Change index for current XA track
volatile MR_BOOL	xa_requested_change;			// TRUE if we've a pending channel change
volatile MR_ULONG	xa_requested_channel;			// Holds channel we've a pending change to.
volatile MR_ULONG	xa_command_status;				// Current command status


/******************************************************************************
*%%%% XAInitialise
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAInitialise(MR_VOID)
*
*	FUNCTION		Called once (on program boot), this function caches information
*					relating to XA files (ie interleaved audio, or video). This
*					saves us time later on, as we can just seek directly to any file
*					without having to call CdSearchFile().
*
*	NOTES			This function could be slow. It needs testing under real-life
*					conditions. If speed is a problem, consider calling it while
*					doing initial memory card accesses.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XAInitialise(MR_VOID)
{
#ifdef	PSX_ENABLE_XA

	XA_FILE*		ix_file_ptr	= xa_file_list;
	MR_ULONG*	ix_changes_ptr;
	MR_ULONG		ix_work;

	// Set this on initialise.
	xa_startup_flag = FALSE;

	// Find information relating to all XA files for the project	
	while(ix_file_ptr->xf_filename)
		{
		// Infinite attempts to read file information
		while(!CdSearchFile(&ix_file_ptr->xf_fileinfo, ix_file_ptr->xf_filename))
			{
			printf("Retry file: %s\n", ix_file_ptr->xf_filename);
			};
		printf("File: %s (%d bytes)\n", ix_file_ptr->xf_filename, ix_file_ptr->xf_fileinfo.size); 

		// Calculate last valid sector position for XA track replay, and store absolute sectors
		
		ix_file_ptr->xf_startpos	= CdPosToInt(&ix_file_ptr->xf_fileinfo.pos);
		ix_file_ptr->xf_endpos		= ix_file_ptr->xf_startpos + (ix_file_ptr->xf_fileinfo.size / XA_SECTOR_SIZE) - XA_SECTOR_LEADOUT;

		printf("Start = %d, End = %d\n", ix_file_ptr->xf_startpos, ix_file_ptr->xf_endpos);

		// If there is a defined change list, then turn the sector offsets into absolute.
		if (ix_file_ptr->xf_changes)
			{
			ix_changes_ptr = ix_file_ptr->xf_changes;
			while(*ix_changes_ptr)
				{
				if (*ix_changes_ptr & XA_DEF_RELOC_ID)
					{
					ix_work = ((*ix_changes_ptr) & (~XA_DEF_RELOC_ID));
					*ix_changes_ptr = ix_work + ix_file_ptr->xf_startpos;
					}
				ix_changes_ptr++;
				} 	
			}		

		ix_file_ptr++;
		}

#endif	PSX_ENABLE_XA
}

/******************************************************************************
*%%%% XAControl
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAControl(
*								MR_ULONG	command,
*								MR_ULONG	param);
*
*	FUNCTION		Adds a request for a specific XA command to the command queue.
*					
*	INPUTS		command	-		XA command to issue
*					param		-		Parameter for the specified XA command
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.6.96		Dean Ashton		10.6.96
*
*%%%**************************************************************************/

MR_VOID	XAControl(MR_ULONG command, MR_ULONG param)
{
#ifdef	PSX_ENABLE_XA

	xa_command_count++;

	if (xa_command_count == XA_MAX_COMMANDS)
		{
		MR_ASSERT(FALSE);
		}

	xa_command_list[xa_add_index].xc_command_id 		= command;
	xa_command_list[xa_add_index].xc_command_param	= param;
	
	xa_add_index++;
	if (xa_add_index == XA_MAX_COMMANDS)
		xa_add_index = 0;

#endif	
}


/******************************************************************************
*%%%% XAChange
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAChange(
*								MR_ULONG channel);
*
*	FUNCTION		Requests a change of XA channel (0 to 6) at the next applicable
*					change point.
*
*	INPUTS		channel		-		XA channel to play back (0 to 6)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	12.06.96		Dean Ashton		Created
*	06.04.97		Dean Ashton		Oops. Channels go from 0 to 7... 
*
*%%%**************************************************************************/

MR_VOID	XAChange(MR_ULONG channel)
{
	MR_ASSERT((channel >= 0) && (channel < XA_MAX_CHANNEL));

	if (xa_requested_change == FALSE)
		{
		xa_requested_change	= TRUE;
		xa_requested_channel = channel;
		}
}



/******************************************************************************
*%%%% XAPlayChannel
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAPlayChannel(
*								MR_ULONG	track
*								MR_ULONG channel,
*								MR_BOOL	loop_flag);
*
*	FUNCTION		Requests a looped play of the specified channel for the 
*					specified track.
*
*	INPUTS		track			-		Track to play back
*					channel		-		XA channel to play back (0 to 6)
*					loop_flag	-		TRUE if we're to loop, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.03.97	Dean Ashton		Created
*	06.04.97	Dean Ashton		Oops. Channels go from 0 to 7... 
*
*%%%**************************************************************************/

MR_VOID	XAPlayChannel(MR_ULONG track, MR_ULONG channel, MR_BOOL loop_flag)
{
	MR_ASSERT(track < XF_XA_FILE_COUNT);
	MR_ASSERT((channel >= 0) && (channel < XA_MAX_CHANNEL));

	// We have to set the channel here, because XACOM_PLAY uses it to find the
	// length of the track... 
	xa_filter.chan = channel;

	// Queue a 'play' with appropriate flags
	if (loop_flag)
		XAControl(XACOM_PLAY, track | XA_DEF_PLAY_CHANNEL_ID);
	else
		XAControl(XACOM_PLAY, track | XA_DEF_PLAY_CHANNEL_ID | XA_DEF_NO_LOOPING);

	// Once the play is underway, change the channel to the right one.
	XAControl(XACOM_CHANNEL, channel);
}


/******************************************************************************
*%%%% XAUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAUpdate(MR_VOID);
*
*	FUNCTION		Typically called once per frame, this function handles command
*					retry processing and execution queue processing. 
*
*	NOTES			If you are wanting to execute commands out of your main game
*					loop, you will have to make sure you call XAUpdate until the
*					variable 'xa_command_count' is zero (which means there are no
*					commands left in the queue). A macro will be supplied for this
*					check.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XAUpdate(MR_VOID)
{
#ifdef	PSX_ENABLE_XA

	// If we've no commands, then why bother continuing
	if (xa_command_count == 0)
		return;

	// Act on the last command status
	if (xa_command_status == XACOMSTAT_RETRY_COMMAND)
		{
		XASubmit(&xa_command_list[xa_execute_index]);
		}
	else
	if (xa_command_status == XACOMSTAT_FETCH_NEXT_COMMAND)
		{
		xa_execute_index++;
		if (xa_execute_index == XA_MAX_COMMANDS)
			xa_execute_index = 0;

		XASubmit(&xa_command_list[xa_execute_index]);
		}
					 
#endif
}


/******************************************************************************
*%%%% XASubmit
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XASubmit(
*								XA_COMMAND* command);
*
*	FUNCTION		Submits an XA interleaved audio command to the hardware, 
*					performing necessary initialisation.
*
*	INPUTS		command		-			XA_COMMAND structure to submit to hardware
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.96		Dean Ashton		Created
*	06.04.97		Dean Ashton		Oops. Channels go from 0 to 7... 
*
*%%%**************************************************************************/

MR_VOID	XASubmit(XA_COMMAND* command)
{
#ifdef	PSX_ENABLE_XA
	XA_FILE*	file_ptr;

	// Clear our command status flag
	xa_command_status = XACOMSTAT_NULL;

	switch(command->xc_command_id)
		{
		
		// 'Nop' does nothing at all. 
		case	XACOM_NOP:
			CdControl(CdlNop, 0, xa_result);
			break;


		// 'Play' has to start a read from the start sector of the required track. If we're paused, queue a pause after it.
		case	XACOM_PLAY:
			MR_ASSERT((command->xc_command_param & 0xffff) < XF_XA_FILE_COUNT);
			file_ptr = &xa_file_list[command->xc_command_param & 0x7fff];
			xa_startpos 		=	file_ptr->xf_startpos;
			xa_currpos	 		=	xa_startpos;
			if (command->xc_command_param & XA_DEF_PLAY_CHANNEL_ID)
				{
				xa_channel_play	=	TRUE;
				xa_endpos			=	xa_currpos + file_ptr->xf_channel_length[xa_filter.chan];	// chan goes from 0->6
				xa_change_list		=	NULL;
				xa_change_index	=	0;
				}
			else
				{
				xa_channel_play	=	FALSE;
				xa_endpos			=	file_ptr->xf_endpos;
				xa_change_list		=	file_ptr->xf_changes;
				xa_change_index	=	0;
				}
			
			if (command->xc_command_param & XA_DEF_NO_LOOPING)
				xa_looped_play = FALSE;
			else
				xa_looped_play = TRUE;
				
		
			xa_current_file	=	command->xc_command_param;
			xa_reading_cd		= TRUE;			
			CdControl(CdlReadS, (MR_UBYTE*)&file_ptr->xf_fileinfo, xa_result);
			if (xa_paused_cd == TRUE)
				{
				XAControl(XACOM_PAUSE, 0);		// Yes. This is a kludge. Sometimes a single pause doesn't pause the mechanism
				XAControl(XACOM_PAUSE, 0);		
				XAControl(XACOM_PAUSE, 0);		
				XAControl(XACOM_PAUSE, 0);		
				XAControl(XACOM_PAUSE, 0);		
				XAControl(XACOM_PAUSE, 0);		
				}
			break;
	

		// 'Pause' is only valid when playing. 
		case	XACOM_PAUSE:
			if (xa_reading_cd == TRUE)
				{
				xa_paused_cd = TRUE;
				CdControl(CdlPause, 0, xa_result);
				}
			else
				{
				xa_command_status = XACOMSTAT_FETCH_NEXT_COMMAND;
				}
			break;

		
		// 'Resume', does a CdlReadS, assuming the position is valid. If it isn't then we'll have to wire the callback. 
		case	XACOM_RESUME:
			if (xa_reading_cd == TRUE)	
				{
				xa_paused_cd = FALSE;
				CdControl(CdlReadS, 0, xa_result);
				}
			else	
				{
				xa_command_status = XACOMSTAT_FETCH_NEXT_COMMAND;
				}
			break;


		// 'Channel' changes the currently selected XA channel
		case	XACOM_CHANNEL:
			xa_filter.chan = command->xc_command_param; 
			xa_requested_change = FALSE;
			CdControl(CdlSetfilter,(MR_UBYTE*)&xa_filter, xa_result);
			break;


		// 'Stop' is really just a 'Pause' that can never restart
		case	XACOM_STOP:
			if (xa_reading_cd == TRUE)
				{
				xa_reading_cd	=	FALSE;
				xa_paused_cd	=	FALSE;
				CdControl(CdlPause, 0, xa_result);
				}
			else
				{
				xa_command_status = XACOMSTAT_FETCH_NEXT_COMMAND;
				}
			break;


		// Unknown command? Oh dear..
		default:
			MR_ASSERT(FALSE);
			break;
		}

#endif
}


/******************************************************************************
*%%%% XAStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAStartup(MR_VOID);
*
*	FUNCTION		Starts the XA interleaved audio subsystem.
*
*	NOTES			While this system is active, API file access has to be disabled.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XAStartup(MR_VOID)
{
#ifdef	PSX_ENABLE_XA

	// Initialise CD mode (Double speed, XA, with filter selection)
	xa_param[0] = CdlModeSpeed | CdlModeRT | CdlModeSF;
	CdControlB(CdlSetmode, xa_param, 0);

	// Initialise XA channel selector
	xa_filter.file = 1;
	xa_filter.chan = 1;
	CdControl(CdlSetfilter, (MR_UBYTE*)&xa_filter, 0);

	// Wait for CD to be silent...
	CdSync(0,0);	

	// Set up our callbacks
	xa_old_ready_callback	= (MR_VOID*)CdReadyCallback(XAReadyCallback);
	xa_old_sync_callback		= (MR_VOID*)CdSyncCallback(XASyncCallback);

	// Initialise our variables
	xa_command_count			=	0;
	xa_execute_index			=	-1;
	xa_add_index				=	0;
	xa_reading_cd				=	FALSE;
	xa_paused_cd				=	FALSE;
	xa_requested_change		=	FALSE;
	xa_channel_play			=	FALSE;
	xa_looped_play				=	FALSE;
	xa_command_status 		=	XACOMSTAT_FETCH_NEXT_COMMAND;

#ifdef	DEBUG
	if (TRUE == xa_startup_flag)
		MRPrintf("XA_Startup called while XA already running.\n");
#endif
	// Set this so we know that the system has been started.
	xa_startup_flag = TRUE;

#endif
}


/******************************************************************************
*%%%% XAShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAShutdown(MR_VOID)
*
*	FUNCTION		Closedown XA interleaved audio subsystem
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XAShutdown(MR_VOID)
{
#ifdef	PSX_ENABLE_XA

	if (FALSE == xa_startup_flag)
		{
#ifdef	DEBUG
		MRPrintf("XA_Shutdown called without a Startup.\n");
#endif
		return;			// Quit without trying to shutdown.		
		}

	// So we know it's been killed.
	xa_startup_flag = FALSE;

	// Request an XA_STOP to halt the XA track
	XAControl(XACOM_STOP, 0);

	// Loop until we've got an empty command queue

	while(xa_command_count != 0)
		{
		VSync(0);
		XAUpdate();
		};

	// Restore system callbacks
	CdSyncCallback(xa_old_sync_callback);
	CdReadyCallback(xa_old_ready_callback);

	// Put CD back into default mode
	xa_param[0] = CdlModeSpeed;
	CdControlB(CdlSetmode, xa_param, 0);

	// Wait for CD to settle
	CdSync(0,0);

#endif
}


/******************************************************************************
*%%%% XAReadyCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XAReadyCallback(
*								MR_UBYTE		intr,
*								MR_UBYTE*	result);
*
*	FUNCTION		Callback routine executed when a data sector arrives in the 
*					sector buffer.  
*
*	INPUTS		intr			-			Interrupt type
*					result		-			Holds report mode when using CD-DA audio
*
*	NOTES			Remember! DO NOT USE 'printf' CALLS IN THIS ROUTINE!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XAReadyCallback(	MR_UBYTE 	intr,
									MR_UBYTE*	result)
{
#ifdef	PSX_ENABLE_XA

	if ((intr == CdlDataReady))
		{
		xa_currpos += XA_SECTOR_INCR;

		// Check to see if we're past the end of the track. If we are, ask for a 'Play' command of the current track
		// if we're supposed to be a looping track. 
		if ((xa_currpos > xa_endpos))
			{
			if (xa_looped_play == TRUE)
				{
				if (xa_channel_play == TRUE)
					XAControl(XACOM_PLAY, xa_current_file | XA_DEF_PLAY_CHANNEL_ID);	// Loop a channel-based track
				else	
					XAControl(XACOM_PLAY, xa_current_file);									// Loop the normal track
				}
			else
				{
				XAControl(XACOM_STOP, NULL);														// No looping.. stop the train!
				}
			xa_currpos = 0;	
			return;
			}

		// Handle updating of change index and also requesting of channel change (if change table has been supplied)
		if (xa_change_list != NULL)
			{
			if	(
				(xa_currpos >= (xa_change_list[xa_change_index] - (XA_SECTOR_INCR))) &&
				(xa_currpos <= (xa_change_list[xa_change_index] + (XA_SECTOR_INCR)))
				)
				{
				if (xa_requested_change)
					{
					XAControl(XACOM_CHANNEL, xa_requested_channel);
					}

				xa_change_index++;
				if (xa_change_list[xa_change_index] == NULL)
					xa_change_index = 0;
				}
 			}
		else
			{
			if (xa_requested_change)
				XAControl(XACOM_CHANNEL, xa_requested_channel);
			}
		}

#endif
}


/******************************************************************************
*%%%% XASyncCallback
*------------------------------------------------------------------------------
*
*	SYNOPSIS		MR_VOID	XASyncCallback(
*								MR_UBYTE		intr,
*								MR_UBYTE*	result);
*
*	FUNCTION		Callback routine executed when command status shifts from 
*					CdlNoIntr to CdlDiskError or CdlComplete.
*
*	INPUTS		intr			-			Interrupt type
*					result		-			Unknown. Required parameter by libraries.
*
*	NOTES			Remember! DO NOT USE 'printf' CALLS IN THIS ROUTINE!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	XASyncCallback(MR_UBYTE 	intr,
								MR_UBYTE*	result)
{
#ifdef	PSX_ENABLE_XA

	if (xa_command_status == XACOMSTAT_NULL)
		{
		if (intr	== CdlDiskError)
			{
			xa_command_status = XACOMSTAT_RETRY_COMMAND;
			}
		else
		if (intr == CdlComplete)	
			{
			xa_command_status	= XACOMSTAT_FETCH_NEXT_COMMAND;
			xa_command_count--;
			}
		}

#endif
}
