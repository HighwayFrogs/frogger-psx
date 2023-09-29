/******************************************************************************
*%%%% stream.c	
*------------------------------------------------------------------------------
*
*	PlayStation interleaved audio/video playback routines. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	16.06.97	Dean Ashton		Created, and implemented automatic 24-bit 
*								playback of interleaved audio/video.
*	21.07.97	Paul Donovan	Fixed a warning
*
*%%%**************************************************************************/

// Includes

#include	"mr_all.h"
#include	"stream.h"
#include	"project.h"

// Globals

DECENV		dec;								// Instance of a DECENV structures
MR_ULONG*	str_ring_buffer;					// Pointer to the ring buffer
MR_ULONG	str_frame;							// Frame number
MR_ULONG	str_old_frame;						// Frame number

CdlFILE		str_cdlfile;
MR_ULONG	str_file_size;

// Video stream information (name, x, y, w, h, frames)
VIDEO		str_info[] = 
				{

				{"DUMMY.STR",		0,	0,				320,	176,	100, 	STRF_NULL},	// This is never used... hence the name 'Dummy'!

				{"HASLOGO.STR",    STREAM_XPOS+24,STREAM_YPOS,320,240,172, STRF_NULL},	// Hasbro Logo.
				{"INTRO.STR",      STREAM_XPOS,STREAM_YPOS,256,240,411, STRF_NULL},	
				{"OUTRO.STR",      STREAM_XPOS,STREAM_YPOS,256,240,253, STRF_NULL},		
				{"CREDITS.STR",    STREAM_XPOS,STREAM_YPOS,256,240,1697, STRF_NULL},		

				};

VIDEO*		str_video;
MR_USHORT	str_frame_index;
MR_UBYTE	str_params[8];
MR_RECT		str_work_rect[2];


/******************************************************************************
*%%%% Play_stream
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	Play_stream(MR_ULONG ps_stream_id)
*
*	FUNCTION	Plays a spooled audio/video sequence on the current display.
*
*	INPUTS		ps_stream_id	-	ID of the sequence to play
*
*	RESULT		ps_quit			-	TRUE if we quit sequence with a button press
*									else FALSE
*
*	NOTES		This routine interrogates the current display bit-depth and
*				processes the sequence accordingly. Be aware that 24-bit streams
*				are MUCH better than 16-bit.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*	21.07.97	Chris Sorrell	Locals put into ifdef
*	21.07.97	Paul Donovan	Moved #ifdef
*
*%%%**************************************************************************/

MR_BOOL	Play_stream(MR_ULONG	ps_stream_id)
{
	MR_BOOL		ps_quit = FALSE;

#ifdef	PSX_CD_STREAMS

	MR_LONG		ps_delay;

	// Some general initialisation
	str_frame = str_old_frame = 0;

	// Keep hold of what the current frame index is, so we can position on it at completion
	str_frame_index	= MRFrame_index;

	// Point to right video information structure
	str_video = &str_info[ps_stream_id];

	// Check we have a screen
	MR_ASSERT(MRDisplay_ptr->di_flags & MR_DI_ACTIVE);

	// Determine whether we're running a 24-bit or 16-bit display.
	if (MRDisplay_ptr->di_video_flags & MR_DD_TRUECOLOUR)
		dec.str_24bit = TRUE;
	else
		dec.str_24bit = FALSE;

	// Initialise the structures and memory needed for the stream
	str_ring_buffer			= MRAllocMem((RING_SIZE*SECTOR_SIZE)*4, "STRMRING");								// Allocate ring buffer
	dec.str_vlctable		= MRAllocMem(sizeof(DECDCTTAB), "VLCTABLE");
	dec.str_vlcbuf[0]		= MRAllocMem((str_video->str_width*str_video->str_height)*2,  "STRMVLC0");	// Room for VLC buffer #0
	dec.str_vlcbuf[1]		= MRAllocMem((str_video->str_width*str_video->str_height)*2,  "STRMVLC1");	// Room for VLC buffer #1

	if (dec.str_24bit)
		{
		dec.str_imagebuff[0]	= MRAllocMem((SLICE_WIDTH*str_video->str_height)*3, "STRMIMG0");	// Room for MDEC strip #0
		dec.str_imagebuff[1]	= MRAllocMem((SLICE_WIDTH*str_video->str_height)*3, "STRMIMG1");	// Room for MDEC strip #1
		}
	else
		{
		dec.str_imagebuff[0]	= MRAllocMem((SLICE_WIDTH*str_video->str_height)*2, "STRMIMG0");	// Room for MDEC strip #0
		dec.str_imagebuff[1]	= MRAllocMem((SLICE_WIDTH*str_video->str_height)*2, "STRMIMG1");	// Room for MDEC strip #1
		}
	
	// Build VLC table
	DecDCTvlcBuild(*(dec.str_vlctable));

	// Open the file, seeking to the start position, retrying on a fail
	MRResetCDRetry();
	while (Stream_open_file(str_video->str_filename) == FALSE)	
		MRProcessCDRetry();

	// Initialise the rectangles required for the decompression environment
	setRECT(&dec.str_rect[0],
				Stream_scale_ppw(str_video->str_xpos) + MRDisplay_ptr->di_screen[0].x,
				str_video->str_ypos + MRDisplay_ptr->di_screen[0].y,
				Stream_scale_ppw(str_video->str_width), str_video->str_height);

	setRECT(&str_work_rect[0],
				Stream_scale_ppw(str_video->str_xpos) + MRDisplay_ptr->di_screen[0].x,
				str_video->str_ypos + MRDisplay_ptr->di_screen[0].y,
				Stream_scale_ppw(str_video->str_width), str_video->str_height);

	setRECT(&dec.str_rect[1],
				Stream_scale_ppw(str_video->str_xpos) + MRDisplay_ptr->di_screen[1].x,
				str_video->str_ypos + MRDisplay_ptr->di_screen[1].y,
				Stream_scale_ppw(str_video->str_width), str_video->str_height);

	setRECT(&str_work_rect[1],
				Stream_scale_ppw(str_video->str_xpos) + MRDisplay_ptr->di_screen[1].x,
				str_video->str_ypos + MRDisplay_ptr->di_screen[1].y,
				Stream_scale_ppw(str_video->str_width), str_video->str_height);

	setRECT(&dec.str_slice,
				Stream_scale_ppw(str_video->str_xpos) + MRDisplay_ptr->di_screen[0].x,
				str_video->str_ypos + MRDisplay_ptr->di_screen[0].y,
				Stream_scale_ppw(SLICE_WIDTH), str_video->str_height);

	// Set initial state stuff
	dec.str_imageid		= 0;
	dec.str_vlcid		= 0;
	dec.str_isdone		= FALSE; 
	dec.str_complete	= FALSE;

	// Initialise the streaming stuff
	DecDCTReset(0);										// Reset the MDEC decompression system
	DecDCToutCallback(Stream_callback);					// Set up a callback for MDEC slice decompression complete
	StSetRing(str_ring_buffer, RING_SIZE);				// Set up a suitably sized Ring Buffer
	StSetStream(dec.str_24bit, 1, 0xffffffff, 0, 0);	// Set up streaming params (16 or 24 bit, all frames)

	// Kick the CD into life (Set for streaming, double speed, interleaved audio)
	while (CdRead2(CdlModeStream|CdlModeSpeed|CdlModeRT) == 0);

	// Bodge a frame sync so we always start on index 0...
	if (str_frame_index == 1)
		{
		VSync(0);
		MRSwapDisplay();						// Swap the display buffers
		str_frame_index ^= 0x01;				// and the corresponding frame index
		}

	Stream_next_vlc();


	// Play the stream..
	while (dec.str_complete == FALSE)
		{
		if (!(str_video->str_flags & STRF_NO_VBLANK))
			VSync(0);
		MRSwapDisplay();						// Swap the display buffers
		str_frame_index ^= 0x01;				// and the corresponding frame index

		MRReadInput();							// Get current button presses

		// Stop stream when 'START' or 'X' pressed - CHANGE TO YOUR OWN BUTTON PRESS EQUATES!!!!
		if (MR_CHECK_PAD_PRESSED(0,MRIP_BLUE | MRIP_START))
			{
			dec.str_complete = TRUE;
			ps_quit = TRUE;
			break;
			}

		// Set current rectangle indexes. I think we need to swap them because frame_index
		// is set to be the index of the work screen	when the next ordering table is processed
		// where we really need to use the index of the _real_ current work screen (because
		// LoadImage() will happen straight away
		dec.str_rectid		= str_frame_index ^ 0x01;

		// Pass it to the MDEC decoder
		if (dec.str_24bit)
			DecDCTin(dec.str_vlcbuf[dec.str_vlcid],3);
		else
			DecDCTin(dec.str_vlcbuf[dec.str_vlcid],2);

		// Get the first slice, which in turn triggers the rest of the slices
		DecDCTout((MR_ULONG*)dec.str_imagebuff[dec.str_imageid], dec.str_slice.w*dec.str_slice.h/2);

		// Get next frame into VLC buffer
		Stream_next_vlc();
		
		// Wait for all the slices to be complete
		Stream_sync();

		}

	// Try to kill the sound glitch caused by dodgy ADPCM sectors (probably)
	CdControl(CdlMute,0,0);

	// Reset the callbacks associated with the stream, and turn off ADPCM sector playback
	str_params[0] = CdlModeSpeed;
	CdControlB(CdlSetmode,str_params, 0);
	DecDCToutCallback(0);
	StUnSetRing();
	CdControlB(CdlPause,0,0);

	// Wait for any drawing to be completed
	DrawSync(0);

	// Try to synchronise both screen buffers, and wait for it to finish
	MoveImage(&str_work_rect[str_frame_index],
				  Stream_scale_ppw(str_work_rect[str_frame_index ^ 0x01].x),
				  str_work_rect[str_frame_index ^ 0x01].y);
	DrawSync(0);

	// Put either screen buffer 0 or 1 back on display, depending on what was displayed at start
	if (str_frame_index != MRFrame_index)
		MRSwapDisplay();

	// Free all associated memory for this stream, in reverse order to minimise any
	// possible fragmentation (even though the Free_mem routine performs some block
	// optimization when deallocating memory).
	MRFreeMem(dec.str_imagebuff[1]);				  
	MRFreeMem(dec.str_imagebuff[0]);
	MRFreeMem(dec.str_vlcbuf[1]);
	MRFreeMem(dec.str_vlcbuf[0]);
	MRFreeMem(dec.str_vlctable);
	MRFreeMem(str_ring_buffer);

	for (ps_delay = 0; ps_delay < (FRAMES_PER_SECOND/4); ps_delay++)
		{
		VSync(0);
		}

	// Turn the CD sound back on..
	CdControl(CdlDemute,0,0);


#endif	//PSX_CD_STREAMS

	return(ps_quit);							// TRUE if we aborted the stream, else FALSE

}


/******************************************************************************
*%%%% Stream_next_vlc
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Stream_next_vlc(MR_VOID)
*
*	FUNCTION	Obtains the next frame from the stream ring buffer, and if
*				it's ready performs VLC decoding on it.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Stream_next_vlc(MR_VOID)
{
	MR_LONG		snv_count = STR_TIMEOUT;
	MR_ULONG*	snv_data;

	// Try for 'STR_TIMEOUT' times to get the next frame from the CD ring buffer
	while ((snv_data = Stream_next_frame()) == 0)
		{
		if (--snv_count == 0)
			return;
		}

	dec.str_vlcid = dec.str_vlcid ^ 0x01;
	DecDCTvlc2(snv_data, dec.str_vlcbuf[dec.str_vlcid],*dec.str_vlctable);	// VLC decode into buffer
	StFreeRing(snv_data);  													// Free sectors in ring buffer
}


/******************************************************************************
*%%%% Stream_next_frame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG* frame_addr = Stream_next_frame(MR_VOID)
*
*	FUNCTION	This routine waits for a complete frame of data to appear in
*				the streaming ring buffer, and returns the address of said
*				frame to the caller
*
*	RESULT		frame_addr		-	Address of new frame 
*
*	NOTES		This routine does not handle variable resolution streams yet,
*				so please make sure all frames in a stream are of the same
*				size.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG*	Stream_next_frame(MR_VOID)
{
	MR_LONG		snf_count = STR_TIMEOUT;
	MR_ULONG*	snf_data;
	StHEADER*	snf_header;

	// Try 'STR_TIMEOUT' times to get the next frames worth of data from the ring buffer
	while (StGetNext((MR_ULONG**)&snf_data, (MR_ULONG**)&snf_header))
		{
		if (--snf_count == 0)
			return(NULL);
		}

	// If we're at the end of the stream, flag the stream as complete
	str_old_frame = str_frame;
	str_frame = snf_header->frameCount;

	if ((str_frame >= str_video->str_numframes) || (str_frame < str_old_frame))
		{
		dec.str_complete = TRUE;
		}


	// Safety net!
	if ((snf_header->width != str_video->str_width) || (snf_header->height != str_video->str_height))
		{
		printf("Stream_next_frame: Size change - ABORT\n");
		dec.str_complete = TRUE;
		}

	return(snf_data);
}


/******************************************************************************
*%%%% Stream_sync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Stream_sync(MR_VOID)
*
*	FUNCTION	This function waits for current stream frame processing to be
*				completed
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Stream_sync(MR_VOID)
{
	MR_LONG	ss_count = STR_TIMEOUT;

	while(dec.str_isdone == FALSE)
		{
		if (--ss_count == 0)
			{
			printf("Stream_sync: Timeout in decoding\n");		// Inform of timeout
			dec.str_isdone 	= TRUE;								// Flag frame as done to exit loop
			dec.str_rectid 	= dec.str_rectid ? 0: 1;			// Swap VRAM areas over
			dec.str_slice.x = dec.str_rect[dec.str_rectid].x;	// Re-point slice coordinates
			dec.str_slice.y = dec.str_rect[dec.str_rectid].y;	// to match current rectangle
			}
		}

	dec.str_isdone = FALSE;										// Clear for next frame

}


/******************************************************************************
*%%%% Stream_callback
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	Stream_callback(MR_VOID)
*
*	FUNCTION	This callback routine is used by the MDEC decompression system.
*				Each slice of image data is taken from the MDEC, triggering
*				the next MDEC slice decompres. Each slice is also DMA'd to the
*				frame buffer at the appropriate position.
*
*	NOTES		Do not modify the 24-bit mode handling code at the top of this
*				function. 24-bit streaming is a tricky business at the best
*				of times...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	Stream_callback(MR_VOID)
{
	// In 24-bit mode, call StCdInterrupt() manually
	if (dec.str_24bit)
		{
		extern	StCdIntrFlag;
		if (StCdIntrFlag)
			{
			StCdInterrupt();
			StCdIntrFlag = 0;
			}
		}

	// Copy the slice data made available by MDEC into VRAM
	LoadImage(&dec.str_slice, (MR_ULONG*)dec.str_imagebuff[dec.str_imageid]);

	// Swap the image buffer number. This gives us more time to decode/transfer
	dec.str_imageid = dec.str_imageid ? 0: 1;

	// Move the slice position along the width of the image
	dec.str_slice.x += dec.str_slice.w;

	if (dec.str_slice.x < (dec.str_rect[dec.str_rectid].x + dec.str_rect[dec.str_rectid].w))
		{

		// If we've more to do, then trigger another MDEC slice decode
		DecDCTout((MR_ULONG*)dec.str_imagebuff[dec.str_imageid], dec.str_slice.w*dec.str_slice.h/2);
		}
	else
		{
		// If we've completed this frame...
		dec.str_isdone	= TRUE;								// Mark it as complete
		dec.str_rectid	= dec.str_rectid ? 0: 1;			// Swap VRAM areas over
		dec.str_slice.x = dec.str_rect[dec.str_rectid].x;	// and set the slice parameters
		dec.str_slice.y = dec.str_rect[dec.str_rectid].y;	// for the next frame's decode

		}
}


/******************************************************************************
*%%%% Stream_scale_ppw
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG scaled_result = Stream_scale_ppw(input)
*
*	FUNCTION	Performs scaling of the input number (assumed to be a width or
*				X position of some kind) based on whether the VRAM is currently
*				set in 24-bit display mode, whereby each pixel of data takes 3
*				bytes as opposed to the 2 bytes for a 16-bit display.
*
*	INPUTS		input			-		Number we're scaling
*
*	RESULT		scaled_result	-		Appropriately scaled result
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG Stream_scale_ppw(MR_ULONG n)
{	
	if (dec.str_24bit)
		return ((n * 3) / 2);
	else
		return (n);
}


/******************************************************************************
*%%%% Stream_open_file
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	Stream_open_file(MR_STRPTR sof_filename)
*
*	FUNCTION	Attempts to seek to the start of a file used for streaming
*				interleaved audio/video data.
*
*	INPUTS		sof_filename	-		Pointer to the filename we're opening
*
*	RESULT		sof_result		-		TRUE if it worked, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.06.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_BOOL	Stream_open_file(MR_STRPTR sof_filename)
{
	MR_UBYTE		sof_name[48];			// Room for real filename

	// CD File System has all filenames ending in ';1'... ISO9660, guv
	strcpy(sof_name,"\\");					// Filename is from the root
	strcat(sof_name,sof_filename);			// Add in the filename bit
	strcat(sof_name,";1");					// And the ISO filename terminator

	// Try to find the file on the CD
	if (!CdSearchFile(&str_cdlfile, sof_name))
		{
		printf("Stream_open_file: Find Failure: %s\n", sof_name);
		return(FALSE);
		}

	// Adjust size of file so it's in sectors... looks messy, but it's quick. Honest.
	str_file_size = str_cdlfile.size = (str_cdlfile.size+2048-1)&(~(2048-1));

	// Perform a blocking seek to the first sector in the file
	if (!CdControlB(CdlSeekL,(MR_STRPTR)&str_cdlfile.pos, 0))
		{
		printf("Stream_open_file: Seek Failure:%s\n", sof_filename);
		return(FALSE);
		}

	return(TRUE);
}





