#ifndef _M_CDAUDIOH
#define _M_CDAUDIOH

extern BOOL		MCCloseCDAudio();
extern BOOL		MCOpenCDAudio(char);
extern void		MCPlayTrack(UINT);
extern void		MCPlayLoopingTrack(UINT);
extern void		MCStop();

extern UINT		MCGetStatus();
extern char		MCGetDriveLetter();

enum{
	MC_FAULT,
	MC_PLAYING,
	MC_SEEKING,
	MC_PAUSED,
};

#endif