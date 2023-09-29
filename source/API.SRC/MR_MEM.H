/******************************************************************************
*%%%% mr_mem.h
*------------------------------------------------------------------------------
*
*	Header file for mr_mem.c
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	28.05.96	Dean Ashton		Created
*	12.06.96	Dean Ashton		Added prototype for MRShowMemSummary()
*	27.06.96	Dean Ashton		Changed prototype for MRCheckMem();
*	05.02.97	Chris Sorrell	New implementation of memory code
*	06.02.97	Chris Sorrell	Additional error types added.
*	22.05.97	Dean Ashton		Added defines and structure mods for optional
*								tag checking (used to trap multiple frees)
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct __mr_mem_tag			MR_MEM_TAG;
typedef	struct __mr_mem_status		MR_MEM_STATUS;
typedef	struct __mr_mem_name		MR_MEM_NAME;
typedef	struct __mr_memfixed		MR_MEMFIXED;

#else
#ifndef __MR_MEM_H
#define __MR_MEM_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#ifdef	MR_MEM_FULL_DEBUG
#ifndef MR_MEM_DEBUG
#define	MR_MEM_DEBUG
#endif	// MR_MEM_DEBUG
#endif	// MR_MEM_FULL_DEBUG

#define	MR_MEM_MIN_ALLOCATION			(16)
#define	MR_MEM_MIN_FREE_SIZE			(128)
#define	MR_MEM_SENTINEL_SIZE			(0x7fffffff)
#define	MR_MEM_ORDERING_TABLE_MIN_B		(4)			// Min ordering table representation is 16-31.
#define	MR_MEM_ORDERING_TABLE_MAX_B		(16)		// Max ordering table representation is 65536+.
#define	MR_MEM_ORDERING_TABLE_SIZE		(MR_MEM_ORDERING_TABLE_MAX_B - MR_MEM_ORDERING_TABLE_MIN_B)
#define	MR_MEM_OVERWRITE_TAG			(0xDEADFACE)
#define	MR_MEM_TORTURE_ALLOC_VAL		(0x55555555)
#define	MR_MEM_TORTURE_FREE_VAL			(0xbbbbbbbb)
#define	MR_MEM_ALLOCATION_ID_VAL		(0xF00DFACE)

// Number of different allocation names we can handle in MRShowMemNameSummary()

#ifndef	MR_MEM_NAME_LIST_SIZE
#define	MR_MEM_NAME_LIST_SIZE			(128)
#endif	

#define	MR_MEM_NAME_LIST_WIDTH			(39)

// Formatting defines for MemShow tag output...

#ifndef	MR_MEM_LINE_LEN
#define	MR_MEM_LINE_LEN					(78)		// Width of debug display - should remain user definable!
#endif
#ifndef	MR_MEM_TAG_DISP_LEN
#define	MR_MEM_TAG_DISP_LEN				(14)		// Width of each tag column - should remain user definable!
#endif

#define	MR_MEM_NUM_COLUMNS				(MR_MEM_LINE_LEN / MR_MEM_TAG_DISP_LEN)
#define	MR_MEM_NUM_GAPS					(MR_MEM_NUM_COLUMNS - 1)
#define	MR_MEM_GAP_SIZE					((MR_MEM_LINE_LEN - (MR_MEM_NUM_COLUMNS * MR_MEM_TAG_DISP_LEN)) / MR_MEM_NUM_GAPS)

#if (MR_MEM_GAP_SIZE < 2)
#undef	MR_MEM_NUM_COLUMNS
#define	MR_MEM_NUM_COLUMNS				((MR_MEM_LINE_LEN / MR_MEM_TAG_DISP_LEN) - 1)
#undef	MR_MEM_GAP_SIZE
#define	MR_MEM_GAP_SIZE			 	 	((MR_MEM_LINE_LEN - (MR_MEM_NUM_COLUMNS * MR_MEM_TAG_DISP_LEN)) / MR_MEM_NUM_GAPS)
#endif

// Flags for status return from vEntMemStatus()...

enum	MR_MEM_STAT_ERRS
			{
			MR_MEM_ERR_FREE_MANAGEMENT_MISMATCH_B,	// Discrepancy between physical managed amount, and that within ordered lists.
			MR_MEM_ERR_DAMAGED_TAGS_B,				// One or more blocks have corrupted limiting tags.
			MR_MEM_ERR_DANGLING_BLOCKS_B,			// One or more blocks were found in ordered lists but not in the physical list.
			MR_MEM_ERR_COUNT_DISCREPANCY_B,			// The amount of managed memory (+ structures) != Allocated pool size
			MR_MEM_ERR_MULTIPLE_FREES_B				// There have been more Frees than Allocs.
			};

#define	MR_MEM_ERR_FREE_MANAGEMENT_MISMATCH_F	(1 << MR_MEM_ERR_FREE_MANAGEMENT_MISMATCH_B)
#define	MR_MEM_ERR_DAMAGED_TAGS_F				(1 << MR_MEM_ERR_DAMAGED_TAGS_B)
#define	MR_MEM_ERR_DANGLING_BLOCKS_F			(1 << MR_MEM_ERR_DANGLING_BLOCKS_B)
#define	MR_MEM_ERR_COUNT_DISCREPANCY_F			(1 << MR_MEM_ERR_COUNT_DISCREPANCY_B)
#define	MR_MEM_ERR_MULTIPLE_FREES_F				(1 << MR_MEM_ERR_MULTIPLE_FREES_B)


//------------------------------------------------------------------------------------------------
//	Macros
//------------------------------------------------------------------------------------------------

#define	MR_WORD_ALIGN(a)	(((a)+3)&0xfffffffc)			// Used to 32-bit align a number


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_mem_tag
		{
		MR_MEM_TAG*		mt_pool_prev;
		MR_MEM_TAG*		mt_pool_next;
		
		MR_MEM_TAG*		mt_ordered_prev;
		MR_MEM_TAG*		mt_ordered_next;
		
		MR_LONG			mt_avail;
		MR_BYTE*		mt_text_tag;
	
#ifdef	MR_MEM_DEBUG
		MR_ULONG		mt_allocation_id;
#endif				  
		}; // MR_MEM_TAG;


struct	__mr_mem_status
		{
		MR_ULONG		ms_status;					// Summarising error code (from MR_MEM_STAT_ERRS)
		MR_ULONG		ms_check_frame_count;		// Frame number that MRCheckMem() was called on

		MR_LONG			ms_available_memory;		// Total amount of managed free memory.
		MR_LONG			ms_used_memory;				// Total amount of memory in use.
		MR_LONG			ms_largest_block;  			// Largest available free block.
		MR_LONG			ms_lowest_free;				// Lowest amount of free managed memory.
		MR_LONG			ms_lowest_largest_free;		// Lowest value for ms_largest_block.
	
		MR_ULONG		ms_num_allocs;	   			// Number of allocations made by system.
		MR_ULONG		ms_num_frees;	   			// Number of frees made by system.
	
		MR_ULONG		ms_free_blocks;				// Blocks in free list.
		MR_ULONG		ms_used_blocks;				// Blocks currently in use.
		MR_ULONG		ms_damaged_blocks;			// Blocks with damaged tags.
		MR_ULONG		ms_ordered_free_blocks;		// Number of available blocks in ordered list.
	
		}; // MR_MEM_STATUS


struct	__mr_mem_name
		{
		MR_STRPTR		mn_name;
		MR_ULONG   		mn_alloc_count;
		MR_ULONG   		mn_alloc_total;
		
		}; // MR_MEM_NAME;


struct	__mr_memfixed								// Fixed memory array
		{
		MR_USHORT  		mm_max;						// maximum number of items
		MR_USHORT  		mm_number;					// number currently in use
		MR_USHORT  		mm_size;					// total size of item
		MR_USHORT  		mm_obj_size;				// size of object
		MR_USHORT  		mm_inst_size;				// size of single instance (0 if none)
		MR_USHORT  		mm_pad;
		MR_VOID*   		mm_items;					// ptr to array of items
		MR_VOID**  		mm_stack;					// ptr to array of item ptrs
		MR_VOID**  		mm_stack_ptr;				// ptr to next available item ptr
	
		};	// MR_MEMFIXED

//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

#ifdef	MR_MEM_DEBUG
extern	MR_MEM_STATUS	MRMem_status;
#endif	//	MR_MEM_DEBUG

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			MRInitMem(MR_ULONG*, MR_ULONG);
extern	MR_VOID*		MRAllocMem(MR_ULONG, MR_STRPTR);
extern	MR_VOID 		MRMemOrderBlock(MR_MEM_TAG*);
extern	MR_VOID 		MRFreeMem(MR_VOID*);
extern	MR_VOID 		MRShowAllocFail(MR_LONG, MR_STRPTR);
extern	MR_VOID 		MRGetMemoryStats(MR_VOID);
extern	MR_ULONG 		MRCheckMem(MR_VOID);
extern	MR_VOID			MRShowMem(MR_STRPTR);
extern	MR_VOID 		MRShowMemNameSummary(MR_STRPTR);
extern	MR_VOID 		MRShowMemSummary(MR_STRPTR);
extern	MR_VOID			MRResetMemStats(MR_VOID);

extern	MR_MEMFIXED*	MRInitMemfixed(MR_MEMFIXED**, MR_USHORT, MR_USHORT);
extern	MR_VOID*		MRAllocMemfixed(MR_MEMFIXED*);
extern	MR_VOID			MRFreeMemfixed(MR_MEMFIXED*, MR_VOID*);
extern	MR_MEMFIXED*	MRInitMemfixedWithInsts3DSprite(	MR_MEMFIXED**, MR_USHORT, MR_USHORT, MR_USHORT, MR_VIEWPORT**);
extern	MR_MEMFIXED*	MRInitMemfixedWithInstsPgen(MR_MEMFIXED**, MR_USHORT,	MR_USHORT, MR_USHORT, MR_VIEWPORT**);


//------------------------------------------------------------------------------

#endif	//__MR_MEM_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

