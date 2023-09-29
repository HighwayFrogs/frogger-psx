/******************************************************************************
*%%%% mr_mem.c
*------------------------------------------------------------------------------
*
*	Memory management code
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	07.02.97	Chris Sorrell	Created
*	07.02.97	Dean Ashton		Mangled to fit API 'standards'.. 
*	22.05.97	Dean Ashton		Added MR_MEM_DEBUG debug code to trap 
*								multiple MRFreeMem() calls
*	11.08.97	Dean Ashton		Modified MRInitMem() to use specified heap base
*								rather that use malloc() (for demo disk usage)
*
*%%%**************************************************************************/

#include	"mr_all.h"


#ifdef	MR_MEM_DEBUG
MR_MEM_STATUS	MRMem_status;
MR_MEM_NAME		MRMem_name_list[MR_MEM_NAME_LIST_SIZE];
#endif // MR_MEM_DEBUG

static	MR_LONG			MRMem_pool_size;
static	MR_MEM_TAG*		MRMem_pool;			 // Pointer to main memory pool...
static	MR_MEM_TAG		MROrdering_sentinels[MR_MEM_ORDERING_TABLE_MAX_B - MR_MEM_ORDERING_TABLE_MIN_B];

// Note:
// (Each ordering table base is a dummy sentinel structure rather than just an
// MR_MEM_TAG* to permit list searches without special case limit checks...


/******************************************************************************
*%%%% MRInitMem
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitMem(
*						MR_ULONG*	im_start,
*						MR_ULONG	im_size);
*
*	FUNCTION	Allocates 'im_size' bytes from the PlayStation memory heap,
*				which was prepared on startup by LIBSN. It then prepares it
*				for our custom memory allocation routines.
*
*	INPUTS		im_start	-	Start address for our heap (normally __heapbase)
*				im_size		-	Required size of our memory pool (bytes)
*
*	NOTES		This issues a single call to 'malloc'.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*	11.08.97	Dean Ashton		No more malloc() call.. 
*
*%%%**************************************************************************/

MR_VOID	MRInitMem(MR_ULONG* im_start, MR_ULONG im_size)
{
	MR_ULONG	ulCount;

	im_size		= MR_WORD_ALIGN(im_size);

//	MRMem_pool	= (MR_MEM_TAG*)malloc(im_size);
	MRMem_pool	= (MR_MEM_TAG*)im_start;

	MR_ASSERT(MRMem_pool != NULL);
	
	// Create empty ordered links within all but the last ordering table
	// position...

	for (ulCount = 0; ulCount < MR_MEM_ORDERING_TABLE_SIZE - 1; ulCount++)
		{
		MROrdering_sentinels[ulCount].mt_ordered_next	= &MROrdering_sentinels[ulCount];
		MROrdering_sentinels[ulCount].mt_ordered_prev	= &MROrdering_sentinels[ulCount];
		MROrdering_sentinels[ulCount].mt_avail			= MR_MEM_SENTINEL_SIZE;			
		}		

	// Set circular links for the single free block, initially referenced
	// only by the last ordering table position...

	MROrdering_sentinels[ulCount].mt_ordered_next		= MRMem_pool;
	MROrdering_sentinels[ulCount].mt_ordered_prev		= MRMem_pool;
	MROrdering_sentinels[ulCount].mt_avail	  			= MR_MEM_SENTINEL_SIZE;

	MRMem_pool->mt_ordered_prev	= &MROrdering_sentinels[ulCount];
	MRMem_pool->mt_ordered_next	= &MROrdering_sentinels[ulCount];

	MRMem_pool->mt_pool_prev		= NULL;	// Flag as terminator.
	MRMem_pool->mt_pool_next		= NULL;	// Flag as terminator.

	MRMem_pool->mt_avail			= im_size - sizeof(MR_MEM_TAG);
	MRMem_pool->mt_text_tag			= NULL;

#ifdef	MR_MEM_DEBUG
	MRMem_pool->mt_allocation_id	= NULL;
#endif	// MR_MEM_CHECK_ON_FREE

	MRMem_pool_size					= im_size;

	// Initialise all status fields...

#ifdef	MR_MEM_DEBUG
	MRMem_status.ms_status				= 0;
	MRMem_status.ms_check_frame_count	= 0;
	MRMem_status.ms_available_memory	= im_size;
	MRMem_status.ms_used_memory			= 0;
	MRMem_status.ms_largest_block		= im_size;
	MRMem_status.ms_lowest_free			= im_size;
	MRMem_status.ms_lowest_largest_free	= im_size;
	MRMem_status.ms_num_allocs			= 0;
	MRMem_status.ms_num_frees			= 0;
	MRMem_status.ms_free_blocks			= 1;
	MRMem_status.ms_used_blocks			= 0;	
	MRMem_status.ms_damaged_blocks		= 0;	
	MRMem_status.ms_ordered_free_blocks = 0;	
#endif // MR_MEM_DEBUG

}


/******************************************************************************
*%%%% MRAllocMem
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID*	am_addr	=	MRAllocMem(
*										MR_ULONG	am_size,
*										MR_STRPTR	am_text_tag);
*
*	FUNCTION	Allocates 'am_size' bytes (rounded to next longword) from the
*				custom memory pool (previously initialised with the MRInitMem()
*				function).
*
*	INPUTS		am_size		-	Required size of our allocation (bytes)
*				am_text_tag	-	Pointer to a string identifying this allocation.
*
*	RESULT		am_addr		-	Address of the allocated memory
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*	22.05.97	Dean Ashton		Added setting of tag safety value (optional)
*
*%%%**************************************************************************/

MR_VOID*	MRAllocMem(	MR_ULONG 	am_reqsize,
						MR_STRPTR	am_text_tag)
{
	MR_MEM_TAG*	am_work;
	MR_MEM_TAG*	am_workB;
	MR_MEM_TAG*	am_new;
	MR_LONG		am_remainder;
	MR_VOID*	am_addr;
	MR_LONG		am_ordering_index;

#ifdef MR_MEM_TORTURE
	MR_ULONG	am_fill_count;
#endif // MR_MEM_TORTURE

#ifdef MR_MEM_DEBUG
	MRMem_status.ms_num_allocs++;
#endif
	
	// Increase size to add room for tag, and then round up to 32-bit multiple

	am_reqsize += sizeof(MR_ULONG);
	am_reqsize	= MR_WORD_ALIGN(am_reqsize);

	// We have a minimum allocation size

	am_reqsize	= MAX(am_reqsize, MR_MEM_MIN_ALLOCATION);

	// Find most significant non-zero bit in requested size... This is a candidate for using Lzc()

	for (am_ordering_index = 0; !(am_reqsize & (1 << (32 - am_ordering_index))); am_ordering_index++);

	// Workout index into ordering table...
	// (NOTE: values are one less than required due to necessity for
	// pre-increment in OT search).

	am_ordering_index = ((32-1) - MR_MEM_ORDERING_TABLE_MIN_B) - am_ordering_index;

	if (am_ordering_index > (MR_MEM_ORDERING_TABLE_SIZE - 2))
		{
		// Large blocks always start searches from final ordering table list 
		// position...

		am_ordering_index = MR_MEM_ORDERING_TABLE_SIZE - 2;
		}

	// Set pointers to first and last entries within the size-ordered list
	// that links from the appropriate ordering table position's sentinel...

	while (1)
		{
		do
			{
			// Early ordering table positions may not contain links to any
			// available free block... This loop scans through until a valid
			// position is found. 

			am_ordering_index++;

			// If the end of the ordering table is exceeded without a valid
			// free-list being found, then the cupboard is bare - eek...

			if (am_ordering_index >= MR_MEM_ORDERING_TABLE_SIZE)
				{
				MRShowAllocFail(am_reqsize, am_text_tag);
				MR_ASSERT(FALSE);
				return (NULL);
				}

			MR_ASSERT(am_ordering_index < MR_MEM_ORDERING_TABLE_SIZE);
			}
		while ((am_work = MROrdering_sentinels[am_ordering_index].mt_ordered_next) == &MROrdering_sentinels[am_ordering_index]);

		am_workB = MROrdering_sentinels[am_ordering_index].mt_ordered_prev;

		// Scan forwards for first large enough slot...

		while (am_reqsize > am_work->mt_avail)
			{
			// ...And backwards for first slot that isn't too big...
		
			if ( am_reqsize > am_workB->mt_avail )
				{
				am_work = am_workB->mt_ordered_next;
				break;
				}

			am_work	= am_work->mt_ordered_next;
			am_workB	= am_workB->mt_ordered_prev;
			}

		// Gets here if suitable slot found, or sentinel reached...

		if ( am_work->mt_avail != MR_MEM_SENTINEL_SIZE )
			{
			// A suitable block has been found - break out and use it!

			break;
			}

		// Gets here if no large enough block was available in the ordered list
		// suggested by the alloc-request's MSB... Move on to the next list
		// containing free blocks - this will be guaranteed to contain a block
		// of suitable size...

		}

	// Gets here when a free block of appropriate size has been found...

	if ((am_remainder = am_work->mt_avail - am_reqsize) >= (MR_MEM_MIN_FREE_SIZE - sizeof(MR_MEM_TAG)))
		{
		// Add a new entry only if its available size will be greater than the
		// lower limit specified by MIN_FREE_ENTRY_SIZE...
	
		am_new = (MR_MEM_TAG*)((MR_BYTE*)am_work + sizeof(MR_MEM_TAG) + am_reqsize);
		am_new->mt_pool_prev	= am_work;
		am_new->mt_pool_next	= am_work->mt_pool_next;
		am_new->mt_avail		= am_remainder - sizeof(MR_MEM_TAG);

		MRMemOrderBlock(am_new);	// Add to ordered available block list...

		// Patch up information in block being allocated...

		if (am_work->mt_pool_next)
			{
			am_work->mt_pool_next->mt_pool_prev = am_new;
			}
		am_work->mt_pool_next	= am_new;
		am_work->mt_avail		= am_reqsize;
		}

	// Remove block from ordered free list...

	am_work->mt_ordered_prev->mt_ordered_next = am_work->mt_ordered_next;
	am_work->mt_ordered_next->mt_ordered_prev = am_work->mt_ordered_prev;

	am_addr = (MR_BYTE*)am_work + sizeof(MR_MEM_TAG);

	// Set the final allocated long to a tag value to allow checking
	// for overwrite as part of free...

	*(MR_ULONG*)((MR_BYTE*)am_addr + am_work->mt_avail - 4) = MR_MEM_OVERWRITE_TAG;

	am_work->mt_avail			= -am_work->mt_avail;	// NEGATIVE flags currently in use.
	am_work->mt_text_tag		= am_text_tag;			// Point to owner-describing string.

#ifdef	MR_MEM_DEBUG
	am_work->mt_allocation_id	= MR_MEM_ALLOCATION_ID_VAL;
#endif	// MR_MEM_DEBUG

#ifdef MR_MEM_TORTURE

	// Fill allocated memory with a dummy value so that other user code
	// can later check for uninitialised data references...

	am_reqsize = (am_reqsize >> 2) - 1;	// (-1 to avoid damaging the tag!)

	for (am_fill_count = 0; am_fill_count < am_reqsize; am_fill_count++)
		{
		*(MR_ULONG*)((MR_ULONG*)am_addr + am_fill_count) = MR_MEM_TORTURE_ALLOC_VAL;
		}
#endif // MR_MEM_TORTURE

#ifdef MR_MEM_FULL_DEBUG

	// Conduct system status check - ASSERT on error...

	if (MRCheckMem() != 0)
	{
		MR_ASSERT(FALSE);
	}

#endif // MR_MEM_FULL_DEBUG

	return(am_addr);
}


/******************************************************************************
*%%%% MRMemOrderBlock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMemOrderBlock(MR_MEM_TAG* ob_ordered);
*
*	FUNCTION	Inserts a free memory block into the size ordered available 
*				free block list...
*
*	INPUTS		ob_ordered	-	Address of MR_MEM_TAG structure being made 
*								available
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*
*%%%**************************************************************************/

MR_VOID MRMemOrderBlock(MR_MEM_TAG* ob_ordered )
{
	MR_MEM_TAG*	ob_workF;
	MR_MEM_TAG*	ob_workB;
	MR_LONG		ob_size;
	MR_ULONG	ob_ordering_index;

	// First workout which ordering table entry's list the new block should be
	// sorted into...

	ob_size = ob_ordered->mt_avail;

	// Find most significant non-zero bit in requested size...

	for (ob_ordering_index = 0; !(ob_size & (1 << (32 - ob_ordering_index))); ob_ordering_index++ );

	// Workout index into ordering table...

	ob_ordering_index = (32 - MR_MEM_ORDERING_TABLE_MIN_B) - ob_ordering_index;

	if (ob_ordering_index > (MR_MEM_ORDERING_TABLE_SIZE - 1))
		{
		// Large blocks are always placed in the final ordering table position...

		ob_ordering_index = MR_MEM_ORDERING_TABLE_SIZE - 1;
		}

	// Set pointers to first and last entries within the size-ordered list
	// that links from the appropriate ordering table position's sentinel...

	ob_workF = MROrdering_sentinels[ob_ordering_index].mt_ordered_next;
	ob_workB = MROrdering_sentinels[ob_ordering_index].mt_ordered_prev;

	while (1)
		{
		// Search forwards and backwards for the appropriate insertion position...

		if (ob_size <= ob_workF->mt_avail)
			{
			// Gets here if block should be inserted BEFORE psWorkF...

			ob_workB = ob_workF;
			ob_workF = ob_workF->mt_ordered_prev;
			break;
			}

		if (ob_size >= ob_workB->mt_avail)
			{
			// Gets here if block should be inserted AFTER psWorkB...
			
			ob_workF = ob_workB;
			ob_workB = ob_workB->mt_ordered_next;
			break;				
			}

		ob_workF = ob_workF->mt_ordered_next;	// Scan forwards...
		ob_workB = ob_workB->mt_ordered_prev;	// Scan backwards...
	}

	// New free block should be inserted AFTER psWorkF and BEFORE psWorkB...

	ob_workF->mt_ordered_next	= ob_ordered;
	ob_ordered->mt_ordered_prev	= ob_workF;
	ob_workB->mt_ordered_prev	= ob_ordered;
	ob_ordered->mt_ordered_next	= ob_workB;
}


/******************************************************************************
*%%%% MRFreeMem
*------------------------------------------------------------------------------
*
*	SYNOPSIS  	MR_VOID	MRFreeMem( MR_VOID* fm_addr);
*
*	FUNCTION  	Restores a previously allocated block of memory to the pool.
*
*	INPUTS		am_addr		-	Address of a previously allocated block of memory
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97  	Chris Sorrell	Created
*	22.05.97	Dean Ashton		Added optional check for multiple MRFreeMem's
*
*%%%**************************************************************************/

MR_VOID MRFreeMem(MR_VOID* fm_addr)
{
	MR_MEM_TAG*	fm_new_free;
	MR_MEM_TAG*	fm_workP;
	MR_MEM_TAG*	fm_workN;

#ifdef	MR_MEM_TORTURE
	MR_ULONG  	fm_fill_count;
	MR_ULONG  	fm_long_size;
#endif	// MR_MEM_TORTURE

	MR_ASSERT( fm_addr != NULL );

#ifdef	MR_MEM_DEBUG
	MRMem_status.ms_num_frees++;
#endif	// MR_MEM_DEBUG

	fm_new_free = (MR_MEM_TAG*)((MR_BYTE*)fm_addr - sizeof(MR_MEM_TAG));

#ifdef	MR_MEM_DEBUG
	MR_ASSERT(fm_new_free->mt_allocation_id == MR_MEM_ALLOCATION_ID_VAL);
	fm_new_free->mt_allocation_id = 0;
#endif

	fm_new_free->mt_avail = -fm_new_free->mt_avail;

#ifdef MR_MEM_TORTURE

	// Fill allocated memory with a dummy value so that other user code
	// can later check for uninitialised data references...

	fm_long_size = fm_new_free->mt_avail >> 2;	

	for (fm_fill_count = 0; fm_fill_count < fm_long_size; fm_fill_count++)
		{
		*(MR_ULONG*)((MR_ULONG*)fm_addr + fm_fill_count) = MR_MEM_TORTURE_FREE_VAL;
		}
#endif // MR_MEM_TORTURE
	
	// At allocation time, the block will have been removed from the relevant
	// ordered free block list, so this needn't be worried about...
 
	fm_workP = fm_new_free->mt_pool_prev;
	fm_workN = fm_new_free->mt_pool_next;

	if ((fm_workP != NULL) && (fm_workP->mt_avail > 0))
		{
		// Gets here if the previous block in the pool is currently unused - dissolve
		// the block being freed and add to the previous...
		
		fm_workP->mt_pool_next = fm_workN;
		if (fm_workN != NULL)
			{
			fm_workN->mt_pool_prev = fm_workP;
			}
		fm_workP->mt_avail += (fm_new_free->mt_avail + sizeof(MR_MEM_TAG));

		// Remove old sized block from ordered free list...

		fm_workP->mt_ordered_prev->mt_ordered_next = fm_workP->mt_ordered_next;
		fm_workP->mt_ordered_next->mt_ordered_prev = fm_workP->mt_ordered_prev;

		fm_new_free = fm_workP;
	 	}

	if ((fm_workN != NULL) && (fm_workN->mt_avail > 0))
	{
		// Gets here if the next block in the pool is currently unused - dissolve
		// the next block and add to the new free unit...

		fm_new_free->mt_pool_next = fm_workN->mt_pool_next;
		if ( fm_workN->mt_pool_next != NULL )
		{
			fm_workN->mt_pool_next->mt_pool_prev = fm_new_free;
		}
		fm_new_free->mt_avail += (fm_workN->mt_avail + sizeof(MR_MEM_TAG));

		// Remove dissolving block from ordered free list...

		fm_workN->mt_ordered_prev->mt_ordered_next = fm_workN->mt_ordered_next;
		fm_workN->mt_ordered_next->mt_ordered_prev = fm_workN->mt_ordered_prev;
	}

	// Add the newly free block (including potential merges) to the available list...

	MRMemOrderBlock(fm_new_free);

#ifdef MR_MEM_FULL_DEBUG

	// Conduct system status check - ASSERT on error...

	if (MRCheckMem() != 0)
		{
		MR_ASSERT(FALSE);
		}

#endif // MR_MEM_FULL_DEBUG
}


/******************************************************************************
*%%%% MRShowAllocFail
*------------------------------------------------------------------------------
*
*	SYNOPSIS  	MR_VOID	MRShowAllocFail(MR_ULONG		af_size,
*			  	  						MR_STRPTR	af_text_tag);
*
*	FUNCTION	Called pending allocation failure, this routine displays text
*				describing the failed request.
*
*	INPUTS		af_size		-	Required size of our failed allocation (bytes)
*				af_text_tag	-	Pointer to a string identifying this allocation.
*
*	NOTES		This is still called on release builds...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*
*%%%**************************************************************************/

MR_VOID MRShowAllocFail(MR_LONG af_size, MR_STRPTR af_text_tag)
{
	// Display full memory system status (on debug)...
#ifdef MR_MEM_DEBUG
	MRShowMem("Allocation failure.");
#endif // MR_MEM_DEBUG

	// Display the failed allocation details
	MRPrintf("MRAllocMem(%ld, '%s') failed\n\n", af_size, af_text_tag);

}	


/******************************************************************************
*%%%% MRGetMemoryStats
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRGetMemoryStats(MR_VOID);
*
*	FUNCTION	Calculates memory usage information for use by external code, 
*				such as the Gatso routines.
*
*	NOTES		Currently, this routine only gathers the following usage stats:
*
*					Used memory (total)
*					Free memory (total)
*					Lowest value recorded of free memory
*					Largest single block size in free memory pool
*					Lowest value of largest single block size in free memory pool
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Dean Ashton		Created
*
*%%%**************************************************************************/


MR_VOID MRGetMemoryStats(MR_VOID)
{
#ifdef MR_MEM_DEBUG
	MR_MEM_TAG*	gs_work;

	MRMem_status.ms_used_memory			= 0;
	MRMem_status.ms_available_memory	= 0;
	MRMem_status.ms_largest_block		= 0;

	gs_work = MRMem_pool;
 
	do	{
		if (gs_work->mt_avail > 0)
			{
			MRMem_status.ms_available_memory += gs_work->mt_avail;

			if (gs_work->mt_avail > MRMem_status.ms_largest_block)
				{
				MRMem_status.ms_largest_block = gs_work->mt_avail;
				}
			}
		else
		if (gs_work->mt_avail < 0)
			{
			MRMem_status.ms_used_memory -= gs_work->mt_avail;	// Count up memory
			}
		} while ((gs_work = gs_work->mt_pool_next) != NULL);


	// Update the lowest available free record...
	if (MRMem_status.ms_available_memory < MRMem_status.ms_lowest_free)
		MRMem_status.ms_lowest_free = MRMem_status.ms_available_memory;

	// Update the lowest largest free record...
	if (MRMem_status.ms_largest_block < MRMem_status.ms_lowest_largest_free)
		MRMem_status.ms_lowest_largest_free = MRMem_status.ms_largest_block;

	// Keep a copy of the frame number this was called on
	MRMem_status.ms_check_frame_count = MRFrame_number;

#endif // MR_MEM_DEBUG
}



/******************************************************************************
*%%%% MRCheckMem
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG status =	MRCheckMem(MR_VOID);
*
*	FUNCTION	Checks the integrity of the memory management system, filling out
*				a global status structure with relevant information.
*
*	RESULT		status		-	This is a mirror of MRMem_status.ulStatus.
*	
*								This may contain any of the following:
*
*									- 0 if everythings OK.
*									- 1 if Pool free/Ordered free mismatch.
*									- 2 if there are block(s) with damaged tags.
*									- 3 if there are Ordered entries not in the Pool.
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*
*%%%**************************************************************************/

MR_ULONG MRCheckMem(MR_VOID)
{
#ifdef MR_MEM_DEBUG

	MR_MEM_TAG*	cm_work;
	MR_MEM_TAG*	cm_temp;
	MR_VOID*	cm_addr;
	MR_ULONG	cm_ot_count;

// -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

	MRMem_status.ms_available_memory	= 0;
	MRMem_status.ms_largest_block		= 0;
	MRMem_status.ms_free_blocks			= 0;
	cm_work = MRMem_pool;
 
	// Get the following data:
	//		Current largest block
	//		Available memory
	// 	Number of used blocks
	//		Number of free blocks

	do	{
		if (cm_work->mt_avail > 0)
			{
			MRMem_status.ms_available_memory += cm_work->mt_avail;
			MRMem_status.ms_free_blocks++;		

			if (cm_work->mt_avail > MRMem_status.ms_largest_block)
				{
				MRMem_status.ms_largest_block = cm_work->mt_avail;
				}
			}
		} while ((cm_work = cm_work->mt_pool_next) != NULL);

	// Update the lowest available free record...

	if (MRMem_status.ms_available_memory < MRMem_status.ms_lowest_free)
		MRMem_status.ms_lowest_free = MRMem_status.ms_available_memory;

	// Update the lowest largest free record...

	if (MRMem_status.ms_largest_block < MRMem_status.ms_lowest_largest_free)
		MRMem_status.ms_lowest_largest_free = MRMem_status.ms_largest_block;

	// Clear out rest of status block ready to fill out with data...

	MRMem_status.ms_status				= 0;
	MRMem_status.ms_used_memory			= 0;
	MRMem_status.ms_used_blocks			= 0;
	MRMem_status.ms_damaged_blocks		= 0;
	MRMem_status.ms_ordered_free_blocks	= 0;


// -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

	// Count number of ORDERED free blocks...

	for (cm_ot_count = 0; cm_ot_count < MR_MEM_ORDERING_TABLE_SIZE; cm_ot_count++)
		{
		cm_work = MROrdering_sentinels[cm_ot_count].mt_ordered_next;

		while ( cm_work != &MROrdering_sentinels[cm_ot_count] )
			{
			MRMem_status.ms_ordered_free_blocks++;	
	
			cm_temp = MRMem_pool;
			do	{
				if (cm_work == cm_temp) 
					{
					break;
					}
				} while ((cm_temp = cm_temp->mt_pool_next) != NULL);

			// Flag error if ordered block not found in main list...
		
			if (cm_temp == NULL)
				{
				MRMem_status.ms_status |= MR_MEM_ERR_DANGLING_BLOCKS_F;
				}
			cm_work = cm_work->mt_ordered_next;
			}
		}

	// Flag error if number of actual free blocks, and number of ordered free
	// blocks is different...

	if (MRMem_status.ms_free_blocks != MRMem_status.ms_ordered_free_blocks)
		{
		MRMem_status.ms_status |= MR_MEM_ERR_FREE_MANAGEMENT_MISMATCH_F;
		}

// -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

	// Count number of used blocks, and check for tag errors...
	// (Also add up the memory 'in use'.)

	cm_work = MRMem_pool;

	do	{
		if (cm_work->mt_avail < 0)
			{
			MRMem_status.ms_used_blocks++;		
			MRMem_status.ms_used_memory -= cm_work->mt_avail;	// Count up memory...

			cm_addr = (MR_BYTE*)cm_work + sizeof(MR_MEM_TAG);

			if (*(MR_ULONG*)((MR_BYTE*)cm_addr + -cm_work->mt_avail - 4) != MR_MEM_OVERWRITE_TAG)
				{
				// Flag damaged tag error...

				MRMem_status.ms_status |= MR_MEM_ERR_DAMAGED_TAGS_F;
				MRMem_status.ms_damaged_blocks++;
				}
			}
		} while ((cm_work = cm_work->mt_pool_next) != NULL);

// -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

	// Add up the amount of memory currently being managed + the amount used
	// in the management structures... This should equal the amount initially
	// allocated to the system.

	if (MRMem_status.ms_available_memory + MRMem_status.ms_used_memory + 
		 ((MRMem_status.ms_free_blocks + MRMem_status.ms_used_blocks) * sizeof(MR_MEM_TAG)) 
			!= MRMem_pool_size)
		{
		MRMem_status.ms_status |= MR_MEM_ERR_COUNT_DISCREPANCY_F;	 	
		}

	// Check that there haven't been more frees than allocs...

	if (MRMem_status.ms_num_allocs < MRMem_status.ms_num_frees)
		{
		MRMem_status.ms_status |= MR_MEM_ERR_MULTIPLE_FREES_F;
		}
	
	// Keep a copy of the frame number this was called on
	MRMem_status.ms_check_frame_count = MRFrame_number;

	return (MRMem_status.ms_status);

#endif // MR_MEM_DEBUG
}




/******************************************************************************
*%%%% MRShowMem
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShowMem(MR_STRPTR sm_callpoint)
*
*	FUNCTION	Shows current memory pool state.
*
*	INPUTS		sm_callpoint	-	Text string describing call-point (or NULL).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*	10.02.97	Chris Sorrell	Speedier divider line display added.	
*
*%%%**************************************************************************/

MR_VOID	MRShowMem(MR_STRPTR sm_callpoint)
{
#ifdef MR_MEM_DEBUG

	MR_MEM_TAG*	sm_work;
	MR_LONG		sm_col_count;
	MR_LONG		sm_gap_count;
	MR_BYTE		sm_work_line[MR_MEM_LINE_LEN + 1];
	MR_BYTE*	sm_line_ptr;
	MR_BYTE		sm_divider_line[MR_MEM_LINE_LEN + 1];

	MRPrintf("\n\n- Active block tags ");

	for (sm_col_count = 0; sm_col_count < MR_MEM_LINE_LEN; sm_col_count++)
		{
		sm_divider_line[ sm_col_count ] = '-';
		}

	sm_divider_line[ MR_MEM_LINE_LEN - 20 ] = 0;
	MRPrintf("%s\n",sm_divider_line);

	sm_work = MRMem_pool;

	while (1)
		{
		sm_line_ptr = sm_work_line;
		for (sm_col_count = 0; sm_col_count < MR_MEM_NUM_COLUMNS;)
			{
			// Build up a line of potentially truncated tags...

			if (sm_work->mt_avail < 0)
				{
				sm_col_count++;
	
				// Print tag...

				if (sm_work->mt_text_tag != NULL)
					{
					strncpy(sm_line_ptr, sm_work->mt_text_tag, MR_MEM_TAG_DISP_LEN);
					if (strlen(sm_work->mt_text_tag) > MR_MEM_TAG_DISP_LEN)
						{
						*(sm_line_ptr + MR_MEM_TAG_DISP_LEN - 1) = '~';
						}
					}			
				else
					{
					strncpy(sm_line_ptr, "NULL-TAG", MR_MEM_TAG_DISP_LEN);
					}
				
				sm_line_ptr += MR_MEM_TAG_DISP_LEN;

				if (sm_col_count != MR_MEM_NUM_COLUMNS)
					{
					sm_gap_count = 0;	

					while (*(sm_line_ptr + sm_gap_count - 1) == 0)
						{
						// Loop back through the NULL terminators that strncpy may
						// have left...

						sm_gap_count--;
						}

					for ( ;sm_gap_count < MR_MEM_GAP_SIZE; sm_gap_count++)
						{
						// Convert NULLs into spaces and add a between-columns gap...

						*(sm_line_ptr + sm_gap_count) = ' ';					
						}
	
					sm_line_ptr += sm_gap_count;
					}
				else
					{
					*sm_line_ptr = 0;
					}
				}		
				
			if ((sm_work = sm_work->mt_pool_next) == NULL)
				{
				*sm_line_ptr = 0;
				break;
				}
			}

		// Print the line just built...			

		MRPrintf("%s\n", sm_work_line);

		if (sm_work == NULL)
			{
			break;
			}
		}

	sm_divider_line[ MR_MEM_LINE_LEN - 20 ] = '-';
	sm_divider_line[ MR_MEM_LINE_LEN ] = 0;
	MRPrintf("%s\n",sm_divider_line);

	MRShowMemSummary(sm_callpoint);

#endif // MR_MEM_DEBUG
}


/******************************************************************************
*%%%% MRShowMemNameSummary
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShowMemNameSummary(MR_STRPTR sm_name)
*
*	FUNCTION	Shows current memory pool state.
*
*	INPUTS		sm_callpoint	-	Name tag used to allocate memory, or NULL to
*									get a list of all used names and information.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Dean Ashton		Created
*	10.02.97	Chris Sorrell	Nicer formatting of long tag names added!
*
*%%%**************************************************************************/

MR_VOID	MRShowMemNameSummary(MR_STRPTR sm_name)
{
#ifdef MR_MEM_DEBUG

	MR_MEM_TAG*		sm_work_tag;
	MR_MEM_NAME*	sm_name_info;
	MR_STRPTR		sm_work_name;
	MR_LONG			sm_found_count;
	MR_LONG			sm_name_idx;
	MR_LONG			sm_col_count;
	MR_BOOL			sm_matched;

	MR_BYTE			sm_buffer[ MR_MEM_NAME_LIST_WIDTH + 1 ];

	sm_work_tag		= MRMem_pool;
	sm_found_count	= NULL;

	while (1)
		{
		if (sm_work_tag->mt_avail < 0)
			{
			if ((sm_name == NULL) || (strcmp(sm_name, sm_work_tag->mt_text_tag) == 0)) 
				{
				// We require information for this allocation (name matches, or we didn't specify a name)
				// so we now loop through our list, comparing strings. Break out when we find a match, or
				// the list is exhausted. If the string wasn't found, then we need a new list entry.. 
				//	if it was found, then add the details of this allocation onto it.
									
				if (sm_name == NULL)
					sm_work_name = sm_work_tag->mt_text_tag;
				else
					sm_work_name = sm_name;

				sm_name_idx 	= 0;
				sm_name_info	= MRMem_name_list;
				sm_matched		= FALSE;
			
				while (sm_name_idx < sm_found_count) 
					{
					if (strcmp(sm_work_name, sm_name_info->mn_name) == 0)
						{
						// We found a match! Modify the totals for this name of allocation
						// and then force a break out of the loop;

						sm_name_info->mn_alloc_count++;
						sm_name_info->mn_alloc_total += (-sm_work_tag->mt_avail);
						sm_matched = TRUE;
						break;
						}
					sm_name_info++;
					sm_name_idx++;
					}
								
				if (sm_matched == FALSE)
					{
					// We didn't find the name in our list, so create a new entry (if there's room!)

					MRMem_name_list[sm_found_count].mn_name			= sm_work_name;
					MRMem_name_list[sm_found_count].mn_alloc_count	= 1;
					MRMem_name_list[sm_found_count].mn_alloc_total	= (-sm_work_tag->mt_avail);
					sm_found_count++;

					MR_ASSERT(sm_found_count < MR_MEM_NAME_LIST_SIZE);
					}
				}
			}		

		// Skip to the next MR_MEM_TAG
				
		if ((sm_work_tag = sm_work_tag->mt_pool_next) == NULL)
			{
			break;
			}
		}

	// If we've got any valid named allocations, then print out the details

	if (sm_found_count != NULL)
		{
		sm_name_info	= MRMem_name_list;

		for (sm_col_count = 0; sm_col_count < MR_MEM_NAME_LIST_WIDTH; sm_col_count++)
			{
			sm_buffer[ sm_col_count ] = '-';
			}

		sm_buffer[ MR_MEM_NAME_LIST_WIDTH ] = 0;
		MRPrintf( "\n%s\n", sm_buffer );
			
		MRPrintf("Name                  Count        Size\n");
		MRPrintf( "%s\n", sm_buffer );

		while(sm_found_count--)  
			{
			strncpy( sm_buffer, sm_name_info->mn_name, MR_MEM_NAME_LIST_WIDTH );
			if ( sm_buffer[ 16 ] != 0 )
				{
				sm_buffer[ 16 ] = '~';
				sm_buffer[ 17 ] = 0;
				}

			MRPrintf("%-17s     %5d     %7d\n", sm_buffer, sm_name_info->mn_alloc_count, sm_name_info->mn_alloc_total);
			sm_name_info++;
			}

		for (sm_col_count = 0; sm_col_count < MR_MEM_NAME_LIST_WIDTH; sm_col_count++)
			{
			sm_buffer[ sm_col_count ] = '-';
			}

		sm_buffer[ MR_MEM_NAME_LIST_WIDTH ] = 0;
		MRPrintf( "%s\n", sm_buffer );
		}
	else
		{
		if (sm_name != NULL)
			MRPrintf("\nNo allocations matched specified name (%s)\n", sm_name);
		else
			MRPrintf("\nNo memory allocations appear to exist at the moment\n");

		}
#endif // MR_MEM_DEBUG
}


/******************************************************************************
*%%%% MRShowMemSummary
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRShowMemSummary(MR_STRPTR sms_callpoint)
*
*	FUNCTION	Shows current memory pool state in summary form (ie no link
*				information).
*
*	INPUTS		sms_callpoint	-	Text string describing call-point (or NULL).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Chris Sorrell	Created
*
*%%%**************************************************************************/

MR_VOID MRShowMemSummary(MR_STRPTR sms_callpoint)
{
#ifdef MR_MEM_DEBUG

	// Fill out the memory status structure with relevant info...

	MRCheckMem();

	MRPrintf("\n");

	if (sms_callpoint != NULL)
		{
		MRPrintf("CallPoint: %s\n\n", sms_callpoint);
		}

	MRPrintf("Number of ALLOCs: %7ld\n", MRMem_status.ms_num_allocs);
	MRPrintf(" Number of FREEs: %7ld\n", MRMem_status.ms_num_frees);

	MRPrintf("Allocated memory: %7ld bytes in %4ld block(s)\n",
			MRMem_status.ms_used_memory,
			MRMem_status.ms_used_blocks );

	MRPrintf("Available memory: %7ld bytes in %4ld block(s)\n",
			MRMem_status.ms_available_memory,
			MRMem_status.ms_free_blocks );

	MRPrintf("Lowest ever free: %7ld bytes\n",
			MRMem_status.ms_lowest_free );

	MRPrintf("   Largest block: %7ld bytes\n",
			MRMem_status.ms_largest_block );

	MRPrintf("  Lowest largest: %7ld bytes\n\n",
			MRMem_status.ms_lowest_largest_free );
	
	if (MRMem_status.ms_status == 0)
		{
		MRPrintf("There are no memory management discrepancies...\n\n");
		}
	else
		{
		MRPrintf("There are the following system errors -\n");

		if (MRMem_status.ms_status & MR_MEM_ERR_FREE_MANAGEMENT_MISMATCH_F)
			{
			MRPrintf("  * Physical list/ordered list totals mismatch.\n");
			}

		if (MRMem_status.ms_status & MR_MEM_ERR_DAMAGED_TAGS_F)
			{
			MRPrintf("  * %ld block(s) have damaged tags.\n", 
					MRMem_status.ms_damaged_blocks);
			}
		
		if (MRMem_status.ms_status & MR_MEM_ERR_DANGLING_BLOCKS_F)
			{
			MRPrintf("  * Physical list/ordered list links mismatch.\n");
			}

		if (MRMem_status.ms_status & MR_MEM_ERR_COUNT_DISCREPANCY_F)
			{
			MRPrintf("  * Memory has been lost.\n");
			}

		if (MRMem_status.ms_status & MR_MEM_ERR_MULTIPLE_FREES_F)
			{
			MRPrintf("  * More FREES than ALLOCS.\n");
			}

		MRPrintf("\nPlease contact your memory-code supplier for an update!\n\n");
		}
#endif // MR_MEM_DEBUG	
}	


/******************************************************************************
*%%%% MRResetMemStats
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResetMemStats(MR_VOID);
*
*	FUNCTION	Sets the variables associated with peak memory usage monitoring
*				(specifically ms_lowest_free) to current values. This is useful
*				should you want to view lowest free memory values for different
*				sections of your titles.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	07.02.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID MRResetMemStats(MR_VOID)
{
#ifdef MR_MEM_DEBUG
	MRMem_status.ms_available_memory	= MRMem_status.ms_available_memory;
#endif // MR_MEM_DEBUG
}


/******************************************************************************
*%%%% MRInitMemFixed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MEMFIXED*	memfixed =	MRInitMemfixed(
*											MR_MEMFIXED**	memfixed_ptr,
*											MR_USHORT		total,
*											MR_USHORT		size)
*
*	FUNCTION	Allocates and sets up a MR_MEMFIXED array to a certain size
*
*	INPUTS		memfixed_ptr	-	API ptr to set
*				total			-	number of items in array
*				size			-	size of item
*
*	RESULT		memfixed		-	ptr to structure created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_MEMFIXED*	MRInitMemfixed(	MR_MEMFIXED**	memfixed_ptr,
							 	MR_USHORT		total,
							 	MR_USHORT		size)
{
	MR_MEMFIXED*	memfixed;
	MR_USHORT		i;

	
	MR_ASSERT(memfixed_ptr);
	
	// Allocate and set up structure
	memfixed				= MRAllocMem(sizeof(MR_MEMFIXED) + ((sizeof(MR_VOID*) + size) * total), "MR_MFIXD");

	memfixed->mm_max		= total;
	memfixed->mm_number		= 0;
	memfixed->mm_size		= size;
	memfixed->mm_obj_size	= size;
	memfixed->mm_inst_size	= 0;
	memfixed->mm_items		= memfixed + 1;														  		// array of (total + 1) structs
	memfixed->mm_stack		= (MR_VOID**)(((MR_UBYTE*)(memfixed + 1)) + (size * total));	// array of (total) pointers
	memfixed->mm_stack_ptr	= memfixed->mm_stack;

	// Set up stack of item ptrs
	for (i = 0; i < total; i++)
		{
		memfixed->mm_stack[i]	= (MR_UBYTE*)memfixed->mm_items + (i * size);
		}	

	*memfixed_ptr = memfixed;
	return(memfixed);
}


/******************************************************************************
*%%%% MRAllocMemfixed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID*	item	=	MRAllocMemfixed(
*										MR_MEMFIXED*	memfixed)
*
*	FUNCTION	Works like MRAllocMem, but from fixed memory
*
*	INPUTS		memfixed	-	ptr to fixed memory structure
*
*	RESULT		item		-	ptr to free item found
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID*	MRAllocMemfixed(MR_MEMFIXED*	memfixed)
{
	MR_VOID*	item = NULL;

	MR_ASSERT(memfixed);

	if (memfixed->mm_number < memfixed->mm_max)
		{
		item 	= *memfixed->mm_stack_ptr++;
		memfixed->mm_number++;
		}
	else
		MR_ASSERTMSG(FALSE, "No room left in fixed memory structure");

	return(item);
}


/******************************************************************************
*%%%% MRFreeMemfixed
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRFreeMemfixed(
*						MR_MEMFIXED*	memfixed,
*						MR_VOID*			item)
*
*	FUNCTION	Works like MRFreeMem, but from fixed memory
*
*	INPUTS		memfixed	-	ptr to fixed memory structure
*				item		-	ptr to item to free
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRFreeMemfixed(	MR_MEMFIXED*	memfixed,
						MR_VOID*		item)
{
	MR_ASSERT(memfixed);
	MR_ASSERT(item);

	*(--memfixed->mm_stack_ptr) = item;
	memfixed->mm_number--;
}


/******************************************************************************
*%%%% MRInitMemfixedWithInsts3DSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MEMFIXED*	memfixed =	MRInitMemfixedWithInsts3DSprite(
*											MR_MEMFIXED**	memfixed_ptr,
*											MR_USHORT		total,
*											MR_USHORT		obj_size,
*											MR_USHORT		inst_size,
*											MR_VIEWPORT**	viewports)
*
*	FUNCTION	Allocates and sets up a MR_MEMFIXED array.  Each item is a 
*				3D sprite together with its viewport instances
*
*	INPUTS		memfixed_ptr	-	API ptr to set
*				total	 		-	number of items in array
*				obj_size 		-	size of object
*				inst_size		-	size of viewport instance
*				viewports		-	ptr to NULL-terminated list of viewport ptrs
*
*	RESULT		memfixed 		-	ptr to structure created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef MR_MEMFIXED_3DSPRITE

MR_MEMFIXED*	MRInitMemfixedWithInsts3DSprite(MR_MEMFIXED**	memfixed_ptr,
												MR_USHORT		total,
												MR_USHORT		obj_size,
												MR_USHORT		inst_size,
												MR_VIEWPORT**	viewports)
{
	MR_MEMFIXED*		memfixed;
	MR_USHORT			i, size;
	MR_VIEWPORT**		vp_pptr;
	MR_VIEWPORT*		vp;
	MR_OBJECT*			object;
	MR_3DSPRITE_INST*	spriteinst;

	
	MR_ASSERT(memfixed_ptr);
	MR_ASSERT(viewports);
	
	size		= obj_size;
	vp_pptr	= viewports;
	while(*vp_pptr++)
		size += inst_size;

	// Allocate and set up structure
	memfixed	= MRInitMemfixed(memfixed_ptr, total, size);

	// Store individual object and instance sizes also
	memfixed->mm_obj_size	= obj_size;
	memfixed->mm_inst_size	= inst_size;

	object  	= memfixed->mm_items;
	i		  	= total;
	while(i--)
		{
		// Set up sprite instances
		spriteinst	= (MR_3DSPRITE_INST*)(((MR_UBYTE*)object) + obj_size);

		vp_pptr	= viewports;
		while(vp = *vp_pptr++)
			{
			setPolyFT4(&spriteinst->si_polygon[0]);
			setPolyFT4(&spriteinst->si_polygon[1]);
			spriteinst->si_object 				= object;
			spriteinst->si_light_matrix_ptr 	= &vp->vp_light_matrix;
			spriteinst = (MR_3DSPRITE_INST*)(((MR_UBYTE*)spriteinst) + inst_size);
			}
		object	= (MR_OBJECT*)(((MR_UBYTE*)object) + size);
		}

	*memfixed_ptr = memfixed;
	return(memfixed);
}

#endif	//MR_MEMFIXED_3DSPRITE


/******************************************************************************
*%%%% MRInitMemfixedWithInstsPgen
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_MEMFIXED*	memfixed =	MRInitMemfixedWithInstsPgen(
*											MR_MEMFIXED**	memfixed_ptr,
*											MR_USHORT		total,
*											MR_USHORT		obj_size,
*											MR_USHORT		inst_size,
*											MR_VIEWPORT**	viewports)
*
*	FUNCTION	Allocates and sets up a MR_MEMFIXED array.  Each item is a 
*				particle generator together with its viewport instances
*
*	INPUTS		memfixed_ptr	-	API ptr to set
*				total			-	number of items in array
*				obj_size		-	size of object
*				inst_size		-	size of viewport instance
*				viewports		-	ptr to NULL-terminated list of viewport ptrs
*
*	RESULT		memfixed		-	ptr to structure created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.02.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifdef MR_MEMFIXED_PGEN

MR_MEMFIXED*	MRInitMemfixedWithInstsPgen(MR_MEMFIXED**	memfixed_ptr,
											MR_USHORT		total,
											MR_USHORT		obj_size,
											MR_USHORT		inst_size,
											MR_VIEWPORT**	viewports)
{
	MR_MEMFIXED*	memfixed;
	MR_USHORT		i, size, buffsize;
	MR_VIEWPORT**	vp_pptr;
	MR_VIEWPORT*	vp;
	MR_OBJECT*		object;
	MR_PGEN_INST*	pgeninst;

	
	MR_ASSERT(memfixed_ptr);
	MR_ASSERT(viewports);
	
	size	= obj_size;
	vp_pptr	= viewports;
	while(*vp_pptr++)
		size += inst_size;

	// Allocate and set up structure
	memfixed	= MRInitMemfixed(memfixed_ptr, total, size);

	// Store individual object and instance sizes also
	memfixed->mm_obj_size	= obj_size;
	memfixed->mm_inst_size	= inst_size;

	object  	= memfixed->mm_items;
	i		  	= total;
	buffsize	= (inst_size - sizeof(MR_PGEN_INST)) >> 1;
	while(i--)
		{
		// Set up pgen instances
		pgeninst	= (MR_PGEN_INST*)(((MR_UBYTE*)object) + obj_size);

		vp_pptr	= viewports;
		while(vp = *vp_pptr++)
			{
			pgeninst->pi_particle_prims[0] 	= ((MR_BYTE*)pgeninst) + sizeof(MR_PGEN_INST);
			pgeninst->pi_particle_prims[1] 	= ((MR_BYTE*)pgeninst) + sizeof(MR_PGEN_INST) + buffsize;
			pgeninst->pi_object 			= object;
			pgeninst = (MR_PGEN_INST*)(((MR_UBYTE*)pgeninst) + inst_size);
			}
		object	= (MR_OBJECT*)(((MR_UBYTE*)object) + size);
		}

	*memfixed_ptr = memfixed;
	return(memfixed);
}

#endif	// MR_MEMFIXED_PGEN
