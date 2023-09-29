/******************************************************************************
*%%%% mr_over.c
*------------------------------------------------------------------------------
*
*	PlayStation API Overlay Handling
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	23.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#include "mr_all.h"

// Default 
MR_TEXT		MROverlay_name[MR_RES_MAX_NAME];
MR_STRPTR	MROverlay_prefix;
MR_BOOL		MROverlay_use_cd;
MR_OVERLAY*	MROverlay_info;
MR_LONG		MROverlay_count;

/******************************************************************************
*%%%% MRInitialiseOverlays
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseOverlays(
*						MR_OVERLAY*	overlay_array,
*						MR_STRPTR	directory_prefix);
*
*	FUNCTION	Initialises variables associated with the overlay system, and
*				performs cacheing of overlay CD positions. On PC filesystems 
*				this function prefixes overlay names with the supplied directory
*				prefix. 
*
*	INPUTS		overlay_info		-	Pointer to a null terminated array of
*										overlay information.
*
*				directory_prefix	-	NULL to use CD loading, otherwise a
*										to a string that will be prefixed to
*										the filename (to allow PC filesystem
*										loading from a particular directory).	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseOverlays(MR_OVERLAY* overlay_info, MR_STRPTR directory_prefix)
{
	MR_LONG	pc_handle;

	MR_ASSERT(overlay_info);
	
	MROverlay_prefix	=	directory_prefix;
	MROverlay_info		=	overlay_info;
	MROverlay_count		=	NULL;

	if (directory_prefix == NULL)
		MROverlay_use_cd = TRUE;
	else
		MROverlay_use_cd = FALSE;

	while(overlay_info->mo_overlay_name)
		{
		if (MROverlay_use_cd)
			{
			// Construct name suiteble for ISO 9660 Access (eg '\\FILENAME.EXT;1')
			strcpy(MROverlay_name, "\\");
			strcat(MROverlay_name, overlay_info->mo_overlay_name);
			strcat(MROverlay_name, ";1");
		
			MRResetCDRetry();
			while(!(CdSearchFile(&overlay_info->mo_overlay_pos, MROverlay_name)))
				{
				MRProcessCDRetry();
				MRPrintf("Retry overlay: %s\n", MROverlay_name);
				};
			}
		else	
			{
			// Check for existence of PC file 
			strcpy(MROverlay_name, MROverlay_prefix);
			strcat(MROverlay_name, overlay_info->mo_overlay_name);

			pc_handle = PCopen(MROverlay_name, 0, 0);
			if (pc_handle == -1)
				{
				MRPrintf("Failure to load overlay: %s\n", MROverlay_name);
				MR_ASSERTMSG(FALSE, "Program halted");
				}
			PCclose(pc_handle);
			}

		MROverlay_count++;
		overlay_info++;
		}	
}

/******************************************************************************
*%%%% MRLoadOverlay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID MRLoadOverlay(MR_LONG overlay_id);
*
*	FUNCTION	Using the information in the supplied overlay information 
*				table, this function loads an overlay binary to the appropriate
*				execution address and performs the necessary cache flushing 
*				operations required to enable execution of the loaded code.
*
*	INPUTS		overlay_id		-		Valid overlay id
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	23.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRLoadOverlay(MR_LONG overlay_id)
{
	MR_OVERLAY*	overlay_info;
	MR_ULONG*	overlay_dest;
	MR_LONG		pc_handle;
	MR_LONG		pc_readlen;
	MR_BOOL		cd_load_error;
	MR_ULONG*	cd_load_buffer;
	MR_ULONG*	cd_load_addr;
	MR_ULONG	cd_load_size;
	MR_LONG		cd_readsync_result;

	MR_ASSERT(overlay_id < MROverlay_count);

	overlay_info = &MROverlay_info[overlay_id];
	overlay_dest = (MR_ULONG*)(*overlay_info->mo_overlay_addr);

	if (MROverlay_use_cd)
		{
		// Loading overlay from CD Filesystem, so used previously cached file information and attempt the read
		cd_load_size 	= overlay_info->mo_overlay_pos.size;
		cd_load_addr 	= MRAllocMem(MR_GET_SECTOR_SIZE(cd_load_size), "OVERLAY");
		cd_load_buffer	= cd_load_addr;
	
		*cd_load_buffer	= MR_INVALID_LOAD_ID;

		MRResetCDRetry();

		do	{
			// Try to seek to the position, and if it works then try to start reading. If any
			// of these operations fail (at command level) then flag an error so we can retry.

			cd_load_error	= FALSE;

			if (!CdControlB(CdlSeekL,(MR_UBYTE*)&overlay_info->mo_overlay_pos.pos, 0))			// Seek
				{
				cd_load_error = TRUE;
				}
			else
			if (!CdRead(MR_GET_NUM_SECTORS(cd_load_size), cd_load_buffer, CdlModeSpeed))		// If seek worked, perform read
				{
				cd_load_error = TRUE;
				}	   
			else																				// Read worked.. just check it.
				{															
				cd_readsync_result = CdReadSync(0, MRCd_status);		
				if	(
					(MRCd_status[0] & CdlDiskError) ||			
					(cd_readsync_result == -1) ||
					((cd_readsync_result == 0) && (*cd_load_buffer == MR_INVALID_LOAD_ID))
					)
					{
					cd_load_error = TRUE;
					}
				}

			// Something went wrong. Register a retry event
			if (cd_load_error == TRUE)
				MRProcessCDRetry();

			} while(cd_load_error == TRUE);

		// Load completed successfully (well.. everything indicates that it worked anyway), so copy to the overlay destination
		cd_load_size = MR_WORD_ALIGN(cd_load_size) / sizeof(MR_ULONG);

		while(cd_load_size--)
			*overlay_dest++ = *cd_load_buffer++;

		MRFreeMem(cd_load_addr);		

		}
	else
		{
		// Loading overlay from PSYQ Filesystem, so construct name suitable for PC access (eg 'P:\APIWORK\OVERLAYS\TITLE.BIN')
		strcpy(MROverlay_name, MROverlay_prefix);
		strcat(MROverlay_name, overlay_info->mo_overlay_name);

		pc_handle = PCopen(MROverlay_name, 0, 0);
		if (pc_handle == -1)
			{
			MRPrintf("Failure to load overlay: %s\n", MROverlay_name);
			MR_ASSERTMSG(FALSE, "Program halted");
			}

		pc_readlen = PClseek(pc_handle, 0, 2);		// Offset relative to end is 0
		PClseek(pc_handle, 0, 0);					// Seek back to start
		PCread(pc_handle, (MR_UBYTE*)overlay_dest, pc_readlen);
		PCclose(pc_handle);

		}

	// We've loaded the overlay, so we need to flush the instruction cache
	FlushCache();
}
