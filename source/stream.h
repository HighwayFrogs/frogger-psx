/*************************************************************************************************
*%%%% stream.h				Dean Ashton 12/4/95
**************************************************************************************************
*
* Header file for 'stream.c', used for streaming motion video/audio from CD
*
*%%%*********************************************************************************************/

#ifndef	__STREAM_H
#define	__STREAM_H

// Includes

#include	"system.h"

// Defines

#define	RING_SIZE	32	 		   				// Size of ring buffer in sectors 

#define	SLICE_WIDTH	16			   				// Width of an MDEC slice

#define	STR_TIMEOUT	WAIT_TIME					// Use GPU timeout value for streaming timeout

#define	STRF_NULL				(1<<0)
#define	STRF_NO_VBLANK			(1<<1)

#ifdef	PSX_MODE_PAL
#define STREAM_YPOS		16
#else
#define	STREAM_YPOS		0
#endif

#define	STREAM_XPOS		(0)

enum		VIDEO_IDENTIFIERS					// These are used as array indices.
			{
			STR_DUMMY,

			STR_HASBRO_LOGO,
			STR_INTRO,
			STR_OUTRO,
			STR_CREDITS,
			};
			
// Structures

typedef	struct __video_info
			{
			MR_STRPTR	str_filename;			// Name of the stream
			MR_USHORT	str_xpos;				// Screen X position to render to
			MR_USHORT	str_ypos;				// Screen Y position to render to
			MR_USHORT	str_width;				// Width of stream (multiple of 16 pixels)
			MR_USHORT	str_height;				// Height of stream
			MR_USHORT	str_numframes;			// Length of stream (in frames)
			MR_USHORT	str_flags;				// Pad to make structure longword multiple
			} VIDEO;


typedef	struct __decenv_env
			{
			MR_BOOL		str_24bit;				// TRUE if we're in 24-bit display mode, else FALSE
			DECDCTTAB*	str_vlctable;			// Pointer to allocated VLC table
			MR_ULONG*	str_vlcbuf[2];			// Pointers to a single vlc buffer 
			MR_LONG		str_vlcid;
			MR_USHORT*	str_imagebuff[2];		// Pointer to buffer for MDEC decompressed images
			MR_LONG		str_imageid;			// Current image buffer id 
			MR_RECT		str_rect[2];			// Rectangles for current areas
			MR_LONG		str_rectid;				// Current rectangle id for loads to VRAM
			MR_RECT		str_slice;				// Rectangle for current slice
			MR_BOOL		str_isdone;				// Frame complete flag
			MR_BOOL		str_complete;			// Is the stream complete
			} DECENV;


// Prototypes

extern	MR_BOOL		Play_stream(MR_ULONG);
extern	MR_VOID		Stream_next_vlc(MR_VOID);
extern	MR_ULONG*	Stream_next_frame(MR_VOID);
extern	MR_VOID		Stream_sync(MR_VOID);
extern	MR_VOID		Stream_callback(MR_VOID);
extern	MR_ULONG	Stream_scale_ppw(MR_ULONG);
extern	MR_BOOL		Stream_open_file(MR_STRPTR);

#endif	//__STREAM_H






