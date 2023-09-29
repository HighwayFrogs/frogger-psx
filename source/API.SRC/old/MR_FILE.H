/******************************************************************************
*%%%% mr_file.h
*------------------------------------------------------------------------------
*
*	Header file for mr_file.c (File/Resource management)
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	22.05.96	Dean Ashton		Created
*	03.06.96	Dean Ashton		Added lock p-types and changed callback p-types.
*	04.03.97	Dean Ashton		Miscellaneous changes for compression stuff
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_resinfo				MR_RESINFO;
typedef	struct	__mr_resgroup				MR_RESGROUP;
typedef	struct	__mr_resproc				MR_RESPROC;
typedef	struct	__mr_resource				MR_RESOURCE;
typedef struct	__mr_cderror_tim			MR_CDERROR_TIM;

#else
#ifndef	__MR_FILE_H
#define	__MR_FILE_H


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_RES_MAX_NAME						(255)
#define	MR_RES_MAX_CALLBACKS				(16)
#define	MR_CD_SECTOR_SIZE					(2048)

#define	MR_CD_RETRY_COUNT					(5)

#define	MR_INVALID_LOAD_ID					(0xDEADBEEF)
										
#define	MR_RES_TYPE_NULL			 		(0)
#define	MR_RES_TYPE_ACCESS_SINGLE			(1<<0)
#define	MR_RES_TYPE_ACCESS_GROUP 			(1<<1)
#define	MR_RES_TYPE_IS_GROUP		 		(1<<2)
#define	MR_RES_TYPE_ABSOLUTE_PATH			(1<<3)
#define	MR_RES_TYPE_DEPACK_AUTO	 			(1<<4)
#define	MR_RES_TYPE_DEPACK_MANUAL			(1<<5)

#define	MR_CD_LOCK_NONE						(0)
#define	MR_CD_LOCK_SUPER					(1<<0)
#define	MR_CD_LOCK_USER						(1<<1)
#define	MR_CD_ANY_LOCK_MASK					(MR_CD_LOCK_SUPER | MR_CD_LOCK_USER)

// Decompression defines

#define	MR_PPID_CHAR_0						'P'
#define	MR_PPID_CHAR_1						'P'
#define	MR_PPID_CHAR_2						'2'
#define	MR_PPID_CHAR_3						'0'

#define	MR_PPDECRUNCH_ERROR					(0)
#define	MR_PPDECRUNCH_OK					(1)

//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

#define	MR_GET_SECTOR_SIZE(size)			(((size)+(MR_CD_SECTOR_SIZE-1))&(~(MR_CD_SECTOR_SIZE-1)))
#define	MR_GET_NUM_SECTORS(size)			(((size)+(MR_CD_SECTOR_SIZE-1))/MR_CD_SECTOR_SIZE)

#define	MR_GET_RESOURCE_ADDR(resource)		MRGetResourceAddr((resource))
#define	MR_GET_RESOURCE_SIZE(resource)		MRGetResourceSize((resource))
#define	MR_GET_RESOURCE_NAME(resource)		(MRResource_base.rb_resource_info[(resource)].ri_filename)


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_resinfo
			{
			MR_STRPTR	ri_filename;									// Pointer to filename (originally an offset) 
			MR_ULONG	ri_flags;										// Flags (is a group, in a group, is compressed etc)
			MR_ULONG	ri_file_type;									// Type ID (for files)
			MR_ULONG	ri_sector_offset;								// Sector offset from start of .MWD
			MR_ULONG*	ri_address;										// Address resource has been loaded at (NULL == Not loaded)
			MR_ULONG*	ri_depacked_address;							// Address resource has been depacked into (NULL if not compressed)
			MR_ULONG	ri_file_size;									// Size of resource (not rounded to 2048 bytes!)
			MR_ULONG	ri_real_size;									// Real (ie depacked) size (not rounded to 2048 bytes!)

			};	// MR_RESINFO


struct	__mr_resgroup
			{
			MR_LONG		rg_resource_id;									// Resource ID (-1 means end of group resources)
			MR_ULONG	rg_type_id;										// Type ID
			MR_ULONG	rg_size;										// Size (longword aligned)		
			MR_ULONG	rg_pad;											// Structure pad 

			};	// MR_RESGROUP


struct	__mr_resproc
			{
			MR_BOOL		rp_active;										// Says whether the callback is active
			MR_BOOL		(*rp_callback)(MR_ULONG, MR_ULONG*, MR_ULONG);	// Callback function pointer

			};	// MR_RESPROC


struct	__mr_resource
			{
			MR_LONG		rb_root_sector;									// Sector that merged file starts at on CD
			MR_LONG		rb_resource_count;								// Number of resources
			MR_RESINFO*	rb_resource_info;								// Pointer to resource info (typically a .MWI file)
			MR_RESPROC*	rb_callback_info;								// Pointer to callback table (for file processing)
			MR_TEXT		rb_base_directory[MR_RES_MAX_NAME];				// Base directory for PC filesystem operations
			MR_TEXT		rb_work_filename[MR_RES_MAX_NAME];				// Work area for PC filesystem name operations

			};	// MR_RESOURCE
			

struct	__mr_cderror_tim
			{
			MR_ULONG	ce_id;
			MR_ULONG	ce_flag;
			MR_ULONG	ce_bnum;
			MR_ULONG	ce_dxy;
			MR_ULONG	ce_hw;
			MR_USHORT	ce_data[0];
	
			};	// MR_CDERROR_TIM


//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_RESOURCE		MRResource_base;
extern	MR_BOOL			MRLoad_error;
extern	MR_BOOL			MRUse_cd_routines;
extern	MR_UBYTE		MRCd_status[8];
extern	MR_UBYTE		MRPP_rev_table[256];

extern	MR_UBYTE		MRCd_error_pp[];		// Included in mr_bin.s, contains CD error bitmap
extern	MR_ULONG		MRCd_error_len;			// Defined in mr_bin.s

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

// File initialisation and configuration
extern	MR_VOID		MRInitialiseResources(MR_STRPTR, MR_RESINFO*, MR_STRPTR, MR_ULONG);
extern	MR_VOID		MRSetFileProcess(MR_ULONG, MR_BOOL (*sfc_callback)(MR_ULONG, MR_ULONG*, MR_ULONG));
extern	MR_VOID		MRClearFileProcess(MR_ULONG);

// Resource handling
extern	MR_LONG		MRGetResourceIDFromAddress(MR_VOID* address);
extern	MR_VOID		MRLoadResource(MR_ULONG);
extern	MR_VOID		MRLoadResourceAsync(MR_ULONG);
extern	MR_VOID		MRPrepareResource(MR_ULONG);
extern	MR_VOID		MRReadResourceAsync(MR_ULONG);
extern	MR_LONG		MRGetAsyncStatus(MR_ULONG);
extern	MR_VOID		MRProcessResource(MR_ULONG);
extern	MR_VOID		MRUnloadResource(MR_ULONG);
extern	MR_VOID		MRPreseekResource(MR_ULONG);

// File locking mechanisms
extern	MR_VOID		MRLockUserCD(MR_VOID);
extern	MR_VOID		MRUnlockUserCD(MR_VOID);

// Debug functions
extern	MR_VOID		MRSaveFile(MR_STRPTR, MR_ULONG*, MR_LONG);
extern	MR_VOID		MRLoadAbsToAnywhere(MR_STRPTR, MR_ULONG*);
extern	MR_VOID		MRLoadAbsToAnywhereAnyLength(MR_STRPTR, MR_ULONG*, MR_ULONG);

// Resource information functions
extern	MR_VOID*	MRGetResourceAddr(MR_ULONG);
extern	MR_ULONG	MRGetResourceSize(MR_ULONG);

// Special 'packed resource' functions
extern	MR_VOID		MRAllocPackedResource(MR_ULONG);
extern	MR_VOID		MRFreePackedResource(MR_ULONG);

// Decompression functions (refers to either mr_m_pak.obj, or mr_c_pak.obj routines)
extern	MR_ULONG	MRPPDecrunchBuffer(MR_UBYTE*, MR_UBYTE*, MR_ULONG);
extern	MR_ULONG	MRPPGetBits(MR_ULONG);

// CD Retry handling functions
extern	MR_VOID		MRResetCDRetry(MR_VOID);
extern	MR_VOID		MRProcessCDRetry(MR_VOID);

#endif	//__MR_FILE_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
















