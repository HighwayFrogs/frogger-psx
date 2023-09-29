#ifndef __xa_h
#define __xa_h

// Prototypes ---------------------------------------------------------------

MR_BOOL xInitXA(MR_VOID);
MR_BOOL xOpenXA(MR_STRPTR);
MR_BOOL xPlayXA(MR_VOID);
MR_BOOL xChangeTrack(MR_LONG);
MR_BOOL xRestartXA(MR_VOID);
MR_BOOL xStopXA(MR_VOID);
MR_BOOL xDeinitXA(MR_VOID);

#endif		// __xa_h