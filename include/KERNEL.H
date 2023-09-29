#ifndef _KERNEL_H
#define _KERNEL_H

/*
 * File:kernel.h 	Rev. 3
*/
/*
 * $PSLibId: Run-time Library Release 4.0$
 */
#include <r3000.h>
#include <asm.h>

/* don't change these macros and structures which is refereced in kernel code */ 

#define DescMask 	0xff000000
#define DescTH 		DescMask
#define DescHW   	0xf0000000
#define DescEV   	0xf1000000
#define DescRC   	0xf2000000
#define DescUEV   	0xf3000000	/* User event */
#define DescSW   	0xf4000000	/* BIOS */

#define HwVBLANK	(DescHW|0x01)	/* VBLANK */
#define HwGPU		(DescHW|0x02)	/* GPU */
#define HwCdRom		(DescHW|0x03)	/* CDROM Decorder */
#define HwDMAC		(DescHW|0x04)	/* DMA controller */
#define HwRTC0		(DescHW|0x05)	/* RTC0 */
#define HwRTC1		(DescHW|0x06)	/* RTC1 */
#define HwRTC2		(DescHW|0x07)	/* RTC2 */
#define HwCNTL		(DescHW|0x08)	/* Controller */
#define HwSPU		(DescHW|0x09)	/* SPU */
#define HwPIO		(DescHW|0x0a)	/* PIO */
#define HwSIO		(DescHW|0x0b)	/* SIO */

#define HwCPU		(DescHW|0x10)	/* Exception */
#define HwCARD		(DescHW|0x11)	/* memory card */
#define HwCARD_0	(DescHW|0x12)	/* memory card */
#define HwCARD_1	(DescHW|0x13)	/* memory card */
#define SwCARD		(DescSW|0x01)	/* memory card */
#define SwMATH          (DescSW|0x02)	/* libmath */

#define RCntCNT0     	(DescRC|0x00)  	/* 表示ピクセル */
#define RCntCNT1  	(DescRC|0x01)  	/* 水平同期 */
#define RCntCNT2  	(DescRC|0x02)  	/* システムクロック８分周 */
#define RCntCNT3  	(DescRC|0x03)  	/* 垂直同期 ターゲット値は１に固定 */

#define RCntMdINTR	0x1000
#define RCntMdNOINTR	0x2000
#define RCntMdSC	0x0001
#define RCntMdSP	0x0000
#define RCntMdFR	0x0000
#define RCntMdGATE	0x0010

#define EvSpCZ		0x0001		/* counter becomes zero */
#define EvSpINT		0x0002		/* interrupted */
#define EvSpIOE		0x0004		/* end of i/o */
#define EvSpCLOSE	0x0008		/* file was closed */
#define EvSpACK		0x0010		/* command acknowledged */
#define EvSpCOMP	0x0020		/* command completed */
#define EvSpDR		0x0040		/* data ready */
#define EvSpDE		0x0080		/* data end */
#define EvSpTIMOUT      0x0100          /* time out */
#define EvSpUNKNOWN     0x0200          /* unknown command */
#define EvSpIOER	0x0400		/* end of read buffer */
#define EvSpIOEW	0x0800		/* end of write buffer */
#define EvSpTRAP       	0x1000          /* general interrupt */
#define EvSpNEW		0x2000		/* new device */
#define EvSpSYSCALL	0x4000		/* system call instruction */
#define EvSpERROR	0x8000		/* error happned */
#define EvSpPERROR	0x8001		/* previous write error happned */
#define EvSpEDOM        0x0301		/* domain error in libmath */
#define EvSpERANGE      0x0302		/* range error in libmath */

#define EvMdINTR	0x1000
#define EvMdNOINTR	0x2000

#define EvStUNUSED    	0x0000
#define EvStWAIT    	0x1000
#define EvStACTIVE    	0x2000
#define EvStALREADY   	0x4000

#define TcbMdRT		0x1000		/* reserved by system */
#define TcbMdPRI	0x2000		/* reserved by system */

#define TcbStUNUSED	0x1000
#define	TcbStACTIVE	0x4000

#if defined(LANGUAGE_C)||defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
struct ToT {
	unsigned long *head;
	long size;
};

struct TCBH {
	struct TCB *entry;	/* NULL */
	long flag;
};

struct TCB {
	long status;
	long mode;
	unsigned long reg[NREGS];	/* never change the offset of this */
	long system[6];			/* reserved by system */
};

struct EvCB {
	unsigned long desc;	
	long status;
	long spec;
	long mode;
	long (*FHandler)();
	long system[2];			/* reserved by system */
};


struct EXEC {                   
        unsigned long pc0;      
        unsigned long gp0;      
        unsigned long t_addr;   
        unsigned long t_size;   
        unsigned long d_addr;   
        unsigned long d_size;   
        unsigned long b_addr;   
        unsigned long b_size;   
	unsigned long s_addr;
	unsigned long s_size;
	unsigned long sp,fp,gp,ret,base;
};


struct XF_HDR {
	char key[8];
	unsigned long text;
	unsigned long data;
	struct EXEC exec;
	char title[60];		/* "PlayStation(tm) Executable A1" */
};


struct DIRENTRY {
	char name[20];
	long attr;
	long size;
	struct DIRENTRY *next;
	long head;
	char system[4];
};


extern struct ToT SysToT[32];

extern long SysClearRCnt[];

/* prototypes added by suzu 96/03/01 and changed by hakama 96/06/06*/

extern long SetRCnt(unsigned long, unsigned short, long);
extern long GetRCnt(unsigned long);
extern long ResetRCnt(unsigned long);
extern long StartRCnt(unsigned long);
extern long StopRCnt(unsigned long);

extern long OpenEvent(unsigned long,long,long,long (*func)());
extern long CloseEvent(long);
extern long WaitEvent(long);
extern long TestEvent(long);
extern long EnableEvent(long);
extern long DisableEvent(long);
extern void DeliverEvent(unsigned long, unsigned long);
extern void UnDeliverEvent(unsigned long, unsigned long);

extern long OpenTh(long (*func)(), unsigned long , unsigned long);
extern int CloseTh(long);
extern int ChangeTh(long);

extern long open(char *, unsigned long);
extern long close(long);
extern long lseek(long, long, long);
extern long read(long, void *, long);
extern long write(long, void *, long);
extern long ioctl(long, long, long);
extern struct DIRENTRY * firstfile(char *, struct DIRENTRY *);
extern struct DIRENTRY * nextfile(struct DIRENTRY *);
extern long erase(char *);

#if defined(LANGUAGE_C)
#define delete	erase
#endif /* LANGUAGE_C */

extern long undelete(char *);
extern long format(char *);
extern long rename(char *, char *);
extern long cd(char *);

extern long LoadTest(char *, struct EXEC *);
extern long Load(char *, struct EXEC *);
extern long Exec(struct EXEC *, long, char **);
extern long LoadExec(char *, unsigned long, unsigned long);

extern long InitPAD(char *,long ,char *,long);
extern long StartPAD(void);
extern void StopPAD(void);
extern long SendPAD(char *,long ,char *,long);
extern void EnablePAD(void);
extern void DisablePAD(void);

extern void FlushCache(void);
extern void ReturnFromException(void);
extern int  EnterCriticalSection(void);
extern void ExitCriticalSection(void);
extern void Exception(void);
extern void SwEnterCriticalSection(void);
extern void SwExitCriticalSection(void);

extern unsigned long SetSp(unsigned long);
extern unsigned long GetSp( void );
extern unsigned long GetGp( void );
extern unsigned long GetCr( void );
extern unsigned long GetSr( void );
extern unsigned long GetSysSp(void);

extern long SetConf(unsigned long,unsigned long,unsigned long);
extern void GetConf(unsigned long *,unsigned long *,unsigned long *);

extern long _get_errno(void);
extern long _get_error(long);

extern void SystemError( char, long);
extern void SetMem(long);

extern long Krom2RawAdd( unsigned long );
extern long Krom2RawAdd2(unsigned short);

extern void _96_init(void);
extern void _96_remove(void);
extern void _boot(void);

extern void ChangeClearPAD( long );

/* prototypes added by shino 96/05/22 */
extern void InitCARD(long val);
extern long StartCARD(void);
extern long StopCARD(void);
extern void _bu_init(void);
extern long _card_info(long chan);
extern long _card_clear(long chan);
extern long _card_load(long chan);
extern long _card_auto(long val);
extern void _new_card(void);
extern long _card_status(long drv);
extern long _card_wait(long drv);
extern unsigned long _card_chan(void);
extern long _card_write(long chan, long block, unsigned char *buf);
extern long _card_read(long chan, long block, unsigned char *buf);

#ifndef NULL
#define NULL (0)
#endif

#endif /* LANGUAGE_C||_LANGUAGE_C_PLUS_PLUS||__cplusplus||c_plusplus */
#endif /* _KERNEL_H */


