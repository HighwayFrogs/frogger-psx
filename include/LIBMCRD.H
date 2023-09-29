#ifndef _MEMCARD_H_
#define _MEMCARD_H_
/*
 * File:libmcrd.h	Rev. 4.0
*/
/*
 * $PSLibId: Run-time Library Release 4.0$
 */
#include <kernel.h>

typedef void (*MemCB)( unsigned long cmds, unsigned long rslt );

#define McFuncExist		(1)
#define McFuncAccept		(2)
#define McFuncReadFile		(3)
#define McFuncWriteFile		(4)
#define McFuncReadData		(5)
#define McFuncWriteData		(6)

#define	McErrNone		(0)
#define	McErrCardNotExist	(1)
#define	McErrCardInvalid	(2)
#define	McErrNewCard		(3)
#define	McErrNotFormat		(4)
#define	McErrFileNotExist	(5)
#define	McErrAlreadyExist	(6)
#define	McErrBlockFull		(7)
#define	McErrExtend		(0x8000)

extern void MemCardInit( long flg );
extern void MemCardEnd( void );
extern void MemCardStart(void);
extern void MemCardStop(void);
extern long MemCardExist( long chan );
extern long MemCardAccept( long chan );
extern long MemCardOpen( long chan, char* fnam, unsigned long flag );
extern void MemCardClose(void);
extern long MemCardReadData( long* adrs, long ofs, long bytes );
extern long MemCardReadFile( long chan, char* fnam, long* adrs, long ofs, long bytes );
extern long MemCardWriteData( long* adrs, long ofs, long bytes );
extern long MemCardWriteFile( long chan, char* fnam, long* adrs, long ofs ,long bytes );
extern long MemCardCreateFile( long chan, char* fnam, long blocks );
extern long MemCardDeleteFile( long chan, char* fnam );
extern long MemCardFormat( long chan );
extern long MemCardUnformat(long chan);
extern long MemCardSync( long mode, unsigned long* cmds, unsigned long* rslt );
extern MemCB MemCardCallback( MemCB func );
extern long MemCardGetDirentry( long chan, char* name, struct DIRENTRY* pdir, long* files, long ofs, long max );
#endif /* _MEMCARD_H_ */
