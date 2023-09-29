/*
 * File:fs.h
 */
/*
 * $PSLibId: Run-time Library Release 4.0$
 */

#ifndef _FS_H
#define _FS_H

#define	EXSTKSZ	1024

#if defined(LANGUAGE_C)||defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
/* device table */
struct device_table {
	char *dt_string;	/* device name */
	int (*dt_init)();	/* device init routine */
	int (*dt_open)();	/* device open routine */
	int (*dt_strategy)();	/* device strategy routine, returns cnt */
	int (*dt_close)();	/* device close routine */
	int (*dt_ioctl)();	/* device ioctl routine */
	int dt_type;		/* device "type" */
	int dt_fs;		/* file system type */
	char *dt_desc;		/* device description */
};
#endif

/* device types */
#define	DTTYPE_CHAR	0x1	/* character device */
#define	DTTYPE_CONS	0x2	/* can be console */
#define	DTTYPE_BLOCK	0x4	/* block device */
#define DTTYPE_RAW	0x8	/* raw device that uses fs switch */

/* File structure types */
#define	DTFS_NONE	0	/* no file structure on device */
#define	DTFS_BFS	1	/* bfs protocol */
#define	DTFS_DVH	2	/* disk volume header */
#define	DTFS_TPD	3	/* boot tape directory */
#define DTFS_NCP	4	/* Network console protocol */
#define	DTFS_BSD42	5	/* 4.2 BSD file system */
#define	DTFS_SYSV	6	/* System V file system */
#define	DTFS_BOOTP	7	/* bootp protocol */
#define	DTFS_EFS	8	/* sgi extent file system */
#define	DTFS_AUTO	-1	/* determined from partition table */

#if defined(LANGUAGE_C)||defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
struct fs_table {
	int (*fs_init)();	/* fs init routine */
	int (*fs_open)();	/* fs open routine */
	int (*fs_read)();	/* fs read routine, returns count */
	int (*fs_write)();	/* fs write routine, return count */
	int (*fs_ioctl)();	/* fs ioctl routine */
	int (*fs_close)();	/* fs close routine */
};
#endif


/* character device flags */
#define	DB_RAW		0x1	/* don't interpret special chars */
#define	DB_STOPPED	0x2	/* stop output */

/* character device buffer */
#define	CBUFSIZE	1024

#if defined(LANGUAGE_C)||defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
struct device_buf {
	int db_flags;		/* character device flags */
	char *db_in;		/* pts at next free char */
	char *db_out;		/* pts at next filled char */
	char db_buf[CBUFSIZE];	/* circular buffer for input */
};
#endif

/* circular buffer functions */
#define	CIRC_EMPTY(x)	((x)->db_in == (x)->db_out)
#define	CIRC_FLUSH(x)	((x)->db_in = (x)->db_out = (x)->db_buf)
#define	CIRC_STOPPED(x)	((x)->db_flags & DB_STOPPED)

#define IOB_INODE	316
#define IOB_FS		8196

/* io block */
#if defined(LANGUAGE_C)||defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
struct	iob {
	int	i_flgs;		/* see F_ below */
	int	i_ctlr;		/* controller board */
	int	i_unit;		/* pseudo device unit */
	int	i_part;		/* disk partition */
	char	*i_ma;		/* memory address of i/o buffer */
	int	i_cc;		/* character count of transfer */
	off_t	i_offset;	/* seek offset in file */
	daddr_t	i_bn;		/* 1st block # of next read */
	int	i_fstype;	/* file system type */
	int	i_errno;	/* error # return */
	unsigned int	i_devaddr;	/* csr address */
	struct device_table *i_dp;	/* pointer into device_table */
	char	*i_buf;			/* i/o buffer for blk devs */
#if 0
	char	i_ino_dir[IOB_INODE];	/* inode or disk/tape directory */
	char	i_fs_tape[IOB_FS];	/* file system or tape header */
#endif
};
#endif

#ifndef NULL
#define NULL 0
#endif

/* file flags */
#define F_READ		0x0001		/* file opened for reading */
#define F_WRITE		0x0002		/* file opened for writing */
#define	F_NBLOCK	0x0004		/* non-blocking io */
#define	F_SCAN		0x0008		/* device should be scanned */

/* Request codes */
#define	READ	1
#define	WRITE	2

#define	DEVIOCTL(io, cmd, arg)	(*(io)->i_dp->dt_ioctl)(io, cmd, arg)
#define	DEVREAD(io)		(*(io)->i_dp->dt_strategy)(io, READ)
#define	DEVWRITE(io)		(*(io)->i_dp->dt_strategy)(io, WRITE)

#define NIOB	4	/* max number of open files */
#define NBUF	4	/* buffer for iob */

#ifdef DEBUG
#define ASSERT(EX) if (!(EX))assfail("EX", __FILE__, __LINE__)
#else
#define ASSERT(x)
#endif DEBUG

#endif /* _FS_H */
