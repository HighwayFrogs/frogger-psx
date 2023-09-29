//---------------------------------------------------------------------------
//---------------------------------------------------------------------------

// Includes -----------------------------------------------------------------

#include "mr_all.h"
#include "xa.h"

// Definitions --------------------------------------------------------------

#define			RING_SIZE					32		// Size of ring buffer in sectors 

// Globals ------------------------------------------------------------------

CdlFILE			str_cdlfile;
MR_ULONG*		str_ring_buffer;					// Pointer to the ring buffer
MR_ULONG		str_file_size;
MR_UBYTE		str_params[8];
MR_ULONG		gulXAPlayTime = 0;

//---------------------------------------------------------------------------
//
//	xInitXA
//
//		Initialise XA system
//
//---------------------------------------------------------------------------

MR_BOOL xInitXA(MR_VOID)
{

	// Set up ring buffer
	str_ring_buffer = MRAllocMem((RING_SIZE*SECTOR_SIZE)*4, "STRMRING");
	StSetRing(str_ring_buffer, RING_SIZE);

}

//---------------------------------------------------------------------------
//
//	xOpenXA
//
//		Open XA track on CD
//
//---------------------------------------------------------------------------

MR_BOOL xOpenXA(MR_STRPTR pFileName)
{

	// Locals
	MR_UBYTE		ubName[48];

	// Convert file name to ISO standard
	strcpy(ubName,"\\");
	strcat(ubName,pFileName);
	strcat(ubName,";1");

	// Can we find this file on the CD ?
	if ( !CdSearchFile(&str_cdlfile,ubName) )
	{

		// No ... print error
		printf("Failed to open file %s!!!\n",ubName);

		// Return with failure
		return MR_FAILURE;

	}

	// Convert file size to sectors
	str_file_size = str_cdlfile.size = (str_cdlfile.size+2048-1)&(~(2048-1));

	// Return ok!!!
	return MR_SUCCESS;
	
}			 

//---------------------------------------------------------------------------
//
//	xPlayXA
//
//		Play an XA track from the CD
//
//---------------------------------------------------------------------------

MR_BOOL xPlayXA(MR_VOID)
{

	// Can we seek to the first seek in the file ?
	if ( !CdControlB(CdlSeekL,(MR_STRPTR)&str_cdlfile.pos,0) )
	{

		// No ... print error and return
		printf("\nSeek failure on file!!!\n");

		// Return with failure
		MR_ASSERT(0);
		return MR_FAILURE;

	}

	// Play audio ?
	if ( CdRead2(CdlModeSpeed|CdlModeRT) != 1 )
	{
		// No ... return failure!!!
		MR_ASSERT(0);
		return MR_FAILURE;
	}

	// Initialise XA playtime length
	gulXAPlayTime = 60*30*2;		// Reduce the time for the tune. 60*60*2;

	// Return ok!!!
	return MR_SUCCESS;

}

//---------------------------------------------------------------------------
//
//	xChangeTrack
//
//		Play a different track with the current XA
//
//---------------------------------------------------------------------------

MR_BOOL xChangeTrack(MR_LONG lTrackNo)
{

	// Reset speed
/*	str_params[0] = CdlSetfilter;
	CdControlB(CdlSetmode,str_params, lTrackNo);*/

}

//---------------------------------------------------------------------------
//
//	xMonitorXA
//
//		Monitor XA playtime and restart if required.
//
//---------------------------------------------------------------------------

MR_BOOL xRestartXA(MR_VOID)
{

	// Is XA current playing ?
	if ( gulXAPlayTime > 0 )
	{

		// Dec time left time end of stream
		gulXAPlayTime--;

		// Yes ... XA finished ?
		if ( 0 == gulXAPlayTime )
		{

			// Yes ... replay XA
			xPlayXA();

			// Change background colour
			//MRSetDisplayClearColour(0xFF,0x00,0x00);

		}

	}

}

//---------------------------------------------------------------------------
//
//	xStopXA
//
//		Stop the current XA playing
//
//---------------------------------------------------------------------------

MR_BOOL xStopXA(MR_VOID)
{

	// Mute audio to prevent ADPCM glitch
	CdControl(CdlMute,0,0);

	// Reset speed
	str_params[0] = CdlModeSpeed;
	CdControlB(CdlSetmode,str_params, 0);

	// Pause CD playback ?
	CdControlB(CdlPause,0,0);

	// Demute audio
	CdControl(CdlDemute,0,0);

	// Reset remaining playtime
	gulXAPlayTime = 0;

}

//---------------------------------------------------------------------------
//
//	xDeinitXA
//
//		Deinitialise XA audio
//
//---------------------------------------------------------------------------

MR_BOOL xDeinitXA(MR_VOID)
{

	// Unset ring buffer
	StUnSetRing();

	// Free ring buffer
	MRFreeMem(str_ring_buffer);

}

//---------------------------------------------------------------------------
//
//	End of file
//
//---------------------------------------------------------------------------





