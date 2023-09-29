/******************************************************************************
*%%%% frognet.c
*------------------------------------------------------------------------------
*
*	Frogger win95 network code (win95 only)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

#include "frognet.h"
#include "frog.h"
#include "froganim.h"
#include "tempopt.h"
#include "select.h"
#include "options.h"

volatile	MR_ULONG	CurrentPlayersSynced;
volatile	MR_ULONG	PlayerSyncData[4];
volatile	MR_BOOL		WaitingForSync;

#ifdef	WIN95

/******************************************************************************
*%%%% GameMessageHandlerCallBack
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameMessageHandlerCallBack(	
*								LPMNGAMEMSG_GENERIC		msg,
*								DWORD					msg_size,
*								DPIP					id_from,
*								DPIP					id_to)
*
*	FUNCTION	Message callback function, the heart of the network communication
*				under windows for remote frogger play.
*
*	INPUTS		Obvious
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID GameMessageHandlerCallBack(	FRNET_GENERIC*	msg, 
									DWORD			msg_size, 
									DPID			id_from, 
									DPID			id_to)
{
	FROG*					frog;
	FRNET_GAME_FROG_DATA*	frog_data;

	switch (msg->msg)
		{
		// -------------------------------------------------------------------
		case FRNET_MSG_GAME_FROG_DATA:
			{
			frog_data = (FRNET_GAME_FROG_DATA*)msg;

			// If it's us then ignore
			if (MNGetPlayerNumber() != frog_data->player_number)
				{
				// set requested frog position
				MR_ASSERT(frog_data->player_number < 4);
				
				frog = &Frogs[frog_data->player_number];

				// Has position been updated?
				if (frog_data->flags & FRNET_FROG_FLAG_POS)
					{
					if (frog->fr_lwtrans)
						{
						MR_COPY_MAT(frog->fr_lwtrans, &frog_data->matrix);
						MR_COPY_VEC((MR_VEC*)frog->fr_lwtrans->t, (MR_VEC*)frog_data->matrix.t);
						}
					}

				// Has animation been requested?
				if (frog_data->flags & FRNET_FROG_FLAG_ANIM)
					FrogRequestAnimation(frog, frog_data->anim_equate, frog_data->anim_type, 1);

				// Has frogger flags been changed?
				if (frog_data->flags & FRNET_FROG_FLAG_FLAGS)
					frog->fr_flags = frog_data->frog_flags;
				}	
			}	
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_OPTIONS_FROG_SELECT:
			{
			FRNET_OPTIONS_FROG_SELECT*	frog_select = (FRNET_OPTIONS_FROG_SELECT*)msg;

			// If it's us then ignore
			if (MNGetPlayerNumber() != msg->player_number)
				{
				// set requested frog position
				MR_ASSERT(frog_select->player_number < 4);

				// set master selection flags
				Frog_selection_network_request_flags = frog_select->master_flags;
				}	
			}	
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_OPTIONS_START_GAME:
			{
			// If it's us then ignore
			if (MNGetPlayerNumber() != msg->player_number)
				{
				// setup world and level numbers
//				Sel_race_world	= ((FRNET_OPTIONS_START_GAME*)msg)->world;
//				Sel_race_level	= ((FRNET_OPTIONS_START_GAME*)msg)->level;

				// setup mode to jump into game
				Option_page_request = OPTIONS_PAGE_GAME;
				}	
			}	
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_SYNC:
			{
			FRNET_SYNC*	sync = (FRNET_SYNC*)msg;

			if (WaitingForSync == TRUE)
				{
				// If it's us then ignore
				if (MNGetPlayerNumber() != msg->player_number)
					{
					// Has this player already synced? If not, then do it now
					if (PlayerSyncData[sync->player_number] == 0)
						{
						PlayerSyncData[sync->player_number] = 1;
						CurrentPlayersSynced++;

						// A machine has probably lagged behind us, send out our sync msg again
						SendSync();
						}
					}
				}
			}
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_OPTIONS_GOTO_FROG_SELECT:
			{
			// Go from network options screen to frog select, but only if this is not us

			// If it's us then ignore
			if (MNGetPlayerNumber() != msg->player_number)
				{
				// We are not the host, so we should wait for player numbers to be issued..

				// wait for player numbers to be issued
				while (MNGetPlayerNumber()==MN_INVALID);

				MNStopPoll();
				MNSetGameMessageHandlerCallback((void (*)(LPMNGAMEMSG_GENERIC, DWORD, DPID, DPID))GameMessageHandlerCallBack);
				MNSignalGameStart();
				Option_page_request = OPTIONS_PAGE_FROG_SELECTION;
				}
			}
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_GAME_RESTART:
			{
			// Go from network options screen to frog select, but only if this is not us

			// If it's us then ignore
			if (MNGetPlayerNumber() != msg->player_number)
				{
				InitialiseSync();
				Game_flags |= GAME_FLAG_RESTART_GAME;
				SendSync();
				}
			}
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_GAME_FRAME_COUNT_SYNC:
			{
			if (WaitingForSync == TRUE)
				{
				if (MNHost())
					{
					// If it's us then ignore
					if (MNGetPlayerNumber() != msg->player_number)
						{
						// Is the frame correct?
						if ( ((FRNET_GAME_FRAME_SYNC*)msg)->frame == Main_global_frame_count)
							{
							// Has this player already synced? If not, then do it now
							if (PlayerSyncData[((FRNET_GAME_FRAME_SYNC*)msg)->player_number] == 0)
								{
								PlayerSyncData[((FRNET_GAME_FRAME_SYNC*)msg)->player_number] = 1;
								CurrentPlayersSynced++;

								// Check for end condition and reply to all machines with go message 
								// if necessary
								if (CheckForNetworkSync())
									{
									SendSyncOk();
									WaitingForSync = FALSE;
									}
								}
							}
						}
					}
					SendFrameSync();
				}
			}
			break;

		// -------------------------------------------------------------------
		case FRNET_MSG_SYNC_OK:
			WaitingForSync = FALSE;
			break;
		}
}

/******************************************************************************
*%%%% SendFrogData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendFrogData(
*								MR_ULONG	flags,
*								MR_MAT*		matrix,
*								MR_ULONG	anim_equate,
*								MR_ULONG	anim_type,
*								MR_ULONG	frog_flags)
*
*	FUNCTION	Sends the frogs position (on this computer) to all other
*				playing computers.
*
*	INPUTS		matrix		- frog matrix
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID SendFrogData(	MR_ULONG	flags,
						MR_VOID*	frog_void_ptr,
						MR_ULONG	anim_equate,
						MR_ULONG	anim_type,
						MR_ULONG	frog_flags)
{
	FRNET_GAME_FROG_DATA	frog_data;
	FROG*					frog;

	frog  = (FROG*)frog_void_ptr;

	if (MNIsNetGameRunning())
		{
		frog_data.type				= MNRM_GAME_BROADCAST;
		frog_data.msg				= FRNET_MSG_GAME_FROG_DATA;			// For the sake of argument
		frog_data.player_number		= MNGetPlayerNumber();
		frog_data.size				= sizeof(FRNET_GAME_FROG_DATA);
		
		frog_data.flags				= flags | FRNET_FROG_FLAG_FLAGS;
		frog_data.anim_equate		= anim_equate;
		frog_data.anim_type			= anim_type;
		frog_data.frog_flags		= frog_flags;

		if (frog->fr_lwtrans)
			{
			MR_COPY_MAT(&frog_data.matrix, frog->fr_lwtrans);
			MR_COPY_VEC((MR_VEC*)frog_data.matrix.t, (MR_VEC*)frog->fr_lwtrans->t);
			}

		MNDispatch((LPMNMSG_GENERIC)&frog_data, frog_data.size);
		}
}

/******************************************************************************
*%%%% SendOptionsFrogSelect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendOptionsFrogSelect(
*									MR_ULONG	master_flags)
*
*	FUNCTION	Sends information on a frog joining to the other computers.
*
*	INPUTS		master_flags	- flags for frog selection
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendOptionsFrogSelect(MR_ULONG master_flags)
{
	FRNET_OPTIONS_FROG_SELECT	frog_select;

	if (MNIsNetGameRunning())
		{
		frog_select.type			= MNRM_GAME_BROADCAST_GUARANTEED;
		frog_select.msg				= FRNET_MSG_OPTIONS_FROG_SELECT;			
		frog_select.player_number	= MNGetPlayerNumber();
		frog_select.size			= sizeof(FRNET_OPTIONS_FROG_SELECT);
		
		frog_select.master_flags	= master_flags;

		MNDispatch((LPMNMSG_GENERIC)&frog_select, frog_select.size);
		}
}

/******************************************************************************
*%%%% SendOptionsStartLevel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendOptionsStartLevel(
*									MR_ULONG	world,
*									MR_ULONG	level)
*
*	FUNCTION	Sends information on what level to start playing.
*
*	INPUTS		world			- world (theme) number
*				level			- level number
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendOptionsStartGame(MR_ULONG world, MR_ULONG level)
{
	FRNET_OPTIONS_START_GAME	game;

	if (MNIsNetGameRunning())
		{
		game.type			= MNRM_GAME_BROADCAST_GUARANTEED;
		game.msg			= FRNET_MSG_OPTIONS_START_GAME;			
		game.player_number	= MNGetPlayerNumber();
		game.size			= sizeof(FRNET_OPTIONS_START_GAME);
		
		game.world			= world;
		game.level			= level;

		MNDispatch((LPMNMSG_GENERIC)&game, game.size);
		}
}


/******************************************************************************
*%%%% SendOptionsLevelSelect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendOptionsLevelSelect(
*									MR_ULONG	world,
*									MR_ULONG	level)
*
*	FUNCTION	Sends information on what level select screen is doing. This
*				updates all non-master player screens with what is happening,
*				although they are allowed no input.
*
*	INPUTS		world			- world (theme) number
*				level			- level number
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendOptionsLevelSelect(MR_ULONG world, MR_ULONG level)
{
/*	FRNET_OPTIONS_LEVEL_SELECT	level_select;

	if (MNIsNetGameRunning())
		{
		game.type			= MNRM_GAME_BROADCAST_GUARANTEED;
		game.msg			= FRNET_MSG_OPTIONS_START_GAME;			
		game.dpidID			= MNGetID();
		game.player_number	= MNGetPlayerNumber();
		game.size			= sizeof(FRNET_OPTIONS_START_GAME);
		
		Sel_camera_acc	= 0;
		Sel_camera_vel	= 0;
		Sel_camera_flag = SEL_CAMERA_STATIONARY;
		Sel_camera_y	= Sel_target_y;
		Sel_camera_frame->fr_matrix.t[1] = Sel_camera_y;

		Sel_game_mode = SEL_GAME_MODE_SHOW_LEVEL_INFO;

		MNDispatch((LPMNMSG_GENERIC)&game, game.size);
		}*/
}

/******************************************************************************
*%%%% SendGameReadyToStart
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendGameReadyToStart(MR_vOID)
*
*	FUNCTION	Sends msg that game has inited, and is ready to start
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendGameReadyToStart(MR_VOID)
{
	FRNET_GAME_READY_TO_START	start;

	if (MNIsNetGameRunning())
		{
		start.type			= MNRM_GAME_BROADCAST_GUARANTEED;
		start.msg			= FRNET_MSG_GAME_READY_TO_START;			
		start.player_number	= MNGetPlayerNumber();
		start.size			= sizeof(FRNET_GAME_READY_TO_START);
		
		MNDispatch((LPMNMSG_GENERIC)&start, start.size);
		}
}

/******************************************************************************
*%%%% SendSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendSync(MR_vOID)
*
*	FUNCTION	Sends msg that this machine has synced ok
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendSync(MR_VOID)
{
	FRNET_SYNC	sync;

	sync.type			= MNRM_GAME_BROADCAST_GUARANTEED;
	sync.msg			= FRNET_MSG_SYNC;			
	sync.player_number	= MNGetPlayerNumber();
	sync.size			= sizeof(FRNET_SYNC);

	MNDispatch((LPMNMSG_GENERIC)&sync, sync.size);
}

/******************************************************************************
*%%%% SendSyncOk
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendSyncOk(MR_vOID)
*
*	FUNCTION	Sends msg that this machine has synced ok
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendSyncOk(MR_VOID)
{
	FRNET_SYNC	sync;

	sync.type			= MNRM_GAME_BROADCAST_GUARANTEED;
	sync.msg			= FRNET_MSG_SYNC_OK;			
	sync.player_number	= MNGetPlayerNumber();
	sync.size			= sizeof(FRNET_SYNC);

	MNDispatch((LPMNMSG_GENERIC)&sync, sync.size);
}

/******************************************************************************
*%%%% SendFrameSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendFrameSync(MR_vOID)
*
*	FUNCTION	Sends msg that this machine has synced at frame
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendFrameSync(MR_VOID)
{
	FRNET_GAME_FRAME_SYNC	sync;

	sync.type			= MNRM_GAME_BROADCAST_GUARANTEED;
	sync.msg			= FRNET_MSG_GAME_FRAME_COUNT_SYNC;			
	sync.player_number	= MNGetPlayerNumber();
	sync.size			= sizeof(FRNET_GAME_FRAME_SYNC);
	sync.frame			= Main_global_frame_count;

	MNDispatch((LPMNMSG_GENERIC)&sync, sync.size);
}

/******************************************************************************
*%%%% InitialiseSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseSync(MR_vOID)
*
*	FUNCTION	Initialises sync variables. Code can then wait for sync msgs
*				from all other machines.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseSync(MR_VOID)
{
	MR_LONG		i;

	WaitingForSync = TRUE;

	// init sync number to 1, includes local player of course
	CurrentPlayersSynced = 1;

	// set player data structs...
	for (i=0; i<4; i++)
		PlayerSyncData[i] = 0;

	// set local player bit as synced
	MR_ASSERT (MNGetPlayerNumber() < 4);
	PlayerSyncData[MNGetPlayerNumber()] = 1;
}

/******************************************************************************
*%%%% DeinitialiseSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DeinitialiseSync(MR_vOID)
*
*	FUNCTION	Deinitialises sync variables. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	DeinitialiseSync(MR_VOID)
{
	WaitingForSync = FALSE;
}

/******************************************************************************
*%%%% CheckForNetworkSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	CheckForNetworkSync(MR_vOID)
*
*	FUNCTION	Waits for all frogs to initialise, returning TRUE or FALSE/
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_BOOL	CheckForNetworkSync(MR_VOID)
{
	PLAYERLIST*		player_list;

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif

	player_list	= MNGetPlayerList();
	MR_ASSERT (player_list);

	// has number of played synced reached total players?
	if (CurrentPlayersSynced == player_list->uiPlayerListSize)
		return TRUE;
	return FALSE;
}


/******************************************************************************
*%%%% InitAndWaitForSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitAndWaitForSync(MR_VOID)
*
*	FUNCTION	Inits a sync (with supplied condition such as game restarting)
*				and waits til all machine agree... if wait goes over certain
*				time another request is sent out.. if this fails another
*				predefined number of times, everything is aborted.
*
*	INPUTS		mode		-	mode to apply (see enum list in frognet.h)
*								This must correspond to one of the enums.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID InitAndWaitForSync(MR_ULONG	mode)
{
	MR_LONG		sync_count;
	MR_LONG		request_number;

	sync_count		= 0;
	request_number	= 0;

	// Only operate if a network game is running
	if (MNIsNetGameRunning())
		{
		// Send out the requested message
		SendGenericMessage(mode);

		// Initialise synced of all network machines 
		InitialiseSync();

		// send our own sync msg here
		SendSync();

		// Don't allow this function to exit until all machines has respected the sync...
		// If a sync isn't achieved for a predeterminded number of frames (say 5 secs), then
		// re-request the correct mode and try again
		while (1)
			{
			if (CheckForNetworkSync())
				break;

			if (++sync_count > MAX_SYNC_WAIT_TIME)
				{
				// have the max number of requests been reached?
				if (++request_number > MAX_NUMBER_REQUESTS)
					{
					// abort here perhaps?
					return;
					}

				// all gone wrong, restart 
				SendSync();
				sync_count = 0;
				}
			}
		}
}

/******************************************************************************
*%%%% SendGenericMessage
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SendGenericMessage(MR_ULONG message)
*
*	FUNCTION	Sends msg requested... this should be a zero data message!
*
*	INPUTS		message	- message id to send
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	SendGenericMessage(MR_ULONG message)
{
	FRNET_GENERIC		gen;

	if (MNIsNetGameRunning())
		{
		gen.type			= MNRM_GAME_BROADCAST_GUARANTEED;
		gen.msg				= message;			
		gen.player_number	= MNGetPlayerNumber();
		gen.size			= sizeof(FRNET_GENERIC);
		
		MNDispatch((LPMNMSG_GENERIC)&gen, gen.size);
		}
}

/******************************************************************************
*%%%% WaitForNetworkSync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	WaitForNetworkSync(MR_VOID)
*
*	FUNCTION	Inits a sync, and waits for all connected machines to respond.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID WaitForNetworkSync(MR_VOID)
{
	if	(Game_is_network)
		{
		InitialiseSync();

		// send our own sync msg here
		SendSync();

		while (1)
			{
			if (CheckForNetworkSync())
				break;
			MNReceiveMessages();
			}
		}
}

/******************************************************************************
*%%%% InitialiseSyncAndWaitForFrame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseSyncAndWaitForFrame(MR_VOID)
*
*	FUNCTION	Inits a sync, and waits for all connected machines to respond
*				that they are ready to process the current game frame.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID InitialiseSyncAndWaitForFrame(MR_VOID)
{
	InitialiseSync();

	// send our own sync msg here
	SendFrameSync();

	while (1)
		{
		if (CheckForNetworkSync())
			break;
		MNReceiveMessages();

#ifdef WIN95
		if (MR_KEY_DOWN(MRIK_ESCAPE))
			Option_page_request = OPTIONS_PAGE_EXIT;
#endif
		}
}


#endif // WIN95