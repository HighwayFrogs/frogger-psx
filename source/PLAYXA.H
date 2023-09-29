/******************************************************************************
*%%%% playxa.h
*------------------------------------------------------------------------------
*
*	Header file for XA-related routines in 'playxa.c'
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	5.6.96		Dean Ashton		Created
*
*%%%**************************************************************************/

#ifndef	__PLAYXA_H
#define	__PLAYXA_H

#include	"system.h"
#include	"mr_all.h"

#ifdef PSX

// Defines for XA routines
#define	XA_SECTOR_LEADOUT			(4)		// Number of empty sectors at the end of an XA file
#define	XA_SECTOR_SIZE				(2336)	// Sector size of XA interleaved file 
#define	XA_MAX_CHANNEL				(7)		// Maximum number of XA channels on the track
#define	XA_MAX_COMMANDS				(16)	// Maximum number of queued commands

#define	XA_SECTOR_INCR				(8)		// 1 in 8 sectors is data, and will give us a callback

#define	XA_DEF_NO_LOOPING			(1<<30)
#define	XA_DEF_PLAY_CHANNEL_ID		(1<<31)

#define	XA_DEF_RELOC_ID				(1<<31)

#define	DEF_XA_CHANGE(mm,ss,ff)		((((mm)*60*150)+((ss)*150)+((ff)*6)) | (XA_DEF_RELOC_ID))
#define	DEF_XA_LENGTH(mm,ss,ff)		((((mm)*60*150)+((ss)*150)+((ff)*6)))


// Macromungus
#define	XA_IS_BEING_PLAYED			(xa_reading_cd == TRUE)


// -- Project specific XA file enumerations --
enum		{
			XF_FR_LEVEL_TUNES1_XA,
			XF_FR_LEVEL_TUNES2_XA,
			XF_FR_LEVEL_TUNES3_XA,
			XF_FR_LEVEL_TUNES4_XA,
			XF_FR_LEVEL_TUNES5_XA,
			XF_XA_FILE_COUNT,
			};
// -------------------------------------------

// Commands for XAControl()
enum		{
			XACOM_NOP,
			XACOM_PLAY,
			XACOM_PAUSE,
			XACOM_RESUME,
			XACOM_CHANNEL,
			XACOM_STOP,
			};

#define	XACOMSTAT_NULL						(0<<0)
#define	XACOMSTAT_RETRY_COMMAND				(1<<0)
#define	XACOMSTAT_FETCH_NEXT_COMMAND		(1<<1)

typedef	struct	__xa_command
			{
			MR_ULONG	xc_command_id;
			MR_ULONG	xc_command_param;
			}	XA_COMMAND;

typedef	struct	__xa_file
			{
			MR_STRPTR	xf_filename;
			MR_ULONG*	xf_changes;
			MR_ULONG	xf_channel_length[7];
			CdlFILE		xf_fileinfo;
			MR_LONG		xf_change_index;
			MR_LONG		xf_startpos;
			MR_LONG		xf_endpos;
			}	XA_FILE;


// External references
extern	MR_BOOL	xa_reading_cd;

extern	MR_VOID	XAInitialise(MR_VOID);
extern	MR_VOID	XAControl(MR_ULONG, MR_ULONG);
extern	MR_VOID	XAChange(MR_ULONG);
extern	MR_VOID	XAPlayChannel(MR_ULONG, MR_ULONG, MR_BOOL);
extern	MR_VOID	XAUpdate(MR_VOID);
extern	MR_VOID	XASubmit(XA_COMMAND*);
extern	MR_VOID	XAStartup(MR_VOID);
extern	MR_VOID	XAShutdown(MR_VOID);
extern	MR_VOID	XAReadyCallback(MR_UBYTE, MR_UBYTE*);
extern	MR_VOID	XASyncCallback(MR_UBYTE, MR_UBYTE*);

#endif

#endif	//__PLAYXA_H
