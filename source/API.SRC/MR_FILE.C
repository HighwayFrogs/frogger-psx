/******************************************************************************
*%%%% mr_file.c
*------------------------------------------------------------------------------
*
*	File/Resource handling routines, for CD and PsyQ file systems
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	22.05.96	Dean Ashton		Created
*	03.06.96	Dean Ashton		Added locking mechanism, changed the interface
*					 			to user-process routines to incorporate size.
*	18.06.96	Dean Ashton		General changes to locking mechanism
*	26.06.96	Tim Closs		Added MRLoadAbsToAnywhereAnyLength
*	02.07.96	Dean Ashton		Changed MRGetAsyncStatus() to clear lock for PC
*	13.09.96	Dean Ashton		Added support for absolute paths in .MWI file
*	04.03.97	Dean Ashton		Miscellaneous changes for file compression
*	14.03.97	Dean Ashton		Added file-size override for development system
*					 			loads of single files when the define for 
*					 			MR_FILE_FORCE_REAL_SIZE has been set.
*	04.04.97	Dean Ashton		Added dynamic safety margin code.
*	02.06.97	Dean Ashton		Modification to MRProcessResource to pass a 
*								resource ID through to file type callbacks.
*
*%%%**************************************************************************/

#include	"mr_all.h"

//#define	MR_FILE_FORCE_REAL_SIZE

MR_RESOURCE		MRResource_base;
MR_RESPROC		MRResource_callbacks[MR_RES_MAX_CALLBACKS];
MR_BOOL			MRUse_cd_routines;
MR_BOOL			MRLoad_error;
MR_TEXT			MRMerge_name[MR_RES_MAX_NAME];
MR_UBYTE		MRCd_status[8];
MR_ULONG		MRCd_lock;
MR_LONG			MRCd_retry_count;

MR_UBYTE		MRPP_rev_table[256];


/******************************************************************************
*%%%% MRInitialiseResources
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInitialiseResources(
*						MR_STRPTR	ir_merge_name,
*						MR_RESINFO*	ir_resource_info,
*						MR_STRPTR	ir_base_directory,
*						MR_ULONG		ir_resource_count);
*
*	FUNCTION	Initialises the file subsystem for either CD (if 'ir_merge_name'
*				is non-NULL) or PC. For PC, 'ir_base_directory' prefixes every
*				filename. 'ir_resource_info' points to an array of MR_RESINFO
*				structures, as is output by BuildWad.exe. Normally this .MWI
*				file is linked into the program. This function also resolves
*				the filename offsets within MR_RESINFO structures into real 
*				string pointers.
*
*	INPUTS		ir_merge_name		-	Name of merged file on CD, or NULL if we're
*							  			using PC filesystem.
*				ir_resource_info	-	Pointer to the .MWI file output by BuildWad
*				ir_base_directory	-	Root directory for all PC file access	
*				ir_resource_count	-	Number of resources (for filename resolve)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRInitialiseResources(	MR_STRPTR	ir_merge_name,
							  	MR_RESINFO*	ir_resource_info,
							  	MR_STRPTR	ir_base_directory,
							  	MR_ULONG	ir_resource_count)
{
	CdlFILE		ir_work_cdlfile;
	MR_LONG		ir_loop;
	MR_LONG		ir_byte;
	MR_LONG		ir_byte_in;
	MR_LONG		ir_byte_out;
	MR_LONG		ir_bit;
	
	MR_ASSERT(ir_resource_info != NULL);

	// Clear locking flags
	MRCd_lock = MR_CD_LOCK_NONE;

	// Initialise decompression table (only 256 bytes)
	for (ir_byte = 0; ir_byte < 256; ir_byte++)
		{
		ir_byte_in	= ir_byte;
		ir_byte_out	= 0;
		for (ir_bit = 0; ir_bit < 8; ir_bit++)
			{
			ir_byte_out = ir_byte_out << 1;
			if (ir_byte_in & 0x01)
				ir_byte_out = ir_byte_out | 1;
			ir_byte_in = ir_byte_in >> 1;
			}
		MRPP_rev_table[ir_byte] = ir_byte_out;
		}										  

	// Set miscellaneous fields within MRResource_base
	strcpy(MRResource_base.rb_base_directory, ir_base_directory);	// Copy the base directory name
	MRResource_base.rb_resource_info		=	ir_resource_info;			// Point to resource information
	MRResource_base.rb_resource_count	=	ir_resource_count;		// Set resource count
	
	// Initialise callback tables
	for (ir_loop = 0; ir_loop < MR_RES_MAX_CALLBACKS; ir_loop++)
		{
		MRResource_callbacks[ir_loop].rp_active		=	FALSE;
		MRResource_callbacks[ir_loop].rp_callback	=	NULL; 
		}

	// If no merged filename has been specified, then we assume we are running a PC filesystem
	if	(ir_merge_name != NULL)
		MRUse_cd_routines = TRUE;
	else
		MRUse_cd_routines = FALSE;

	// If we're doing CD stuff, then get the start sector of the merged file.
	if (MRUse_cd_routines == TRUE)
		{
		// ISO 9660 filenames are like '\FILENAME.EXT;1', or '\DIRNAME\FILENAME.EXT;1'
		strcpy(MRMerge_name, "\\");
		strcat(MRMerge_name, ir_merge_name);
		strcat(MRMerge_name, ";1");

		// Attempt to find the file.. bail if we couldn't
		MRResetCDRetry();
		while (!CdSearchFile(&ir_work_cdlfile, MRMerge_name))	
			MRProcessCDRetry();

#ifdef	MR_DEBUG
		// There could be debug code to read the first sector, and
		// print the merged file information from the header in here.
#endif
		
		// Cache sector position for the start of the merged file
		MRResource_base.rb_root_sector	=	CdPosToInt(&ir_work_cdlfile.pos);
		}
	else
		MRResource_base.rb_root_sector	=	NULL;

	// Patch the filename pointers (if necessary)
	if ((MR_LONG)MRResource_base.rb_resource_info[0].ri_filename != -1)
		{
		for (ir_loop = 0; ir_loop < ir_resource_count; ir_loop++)
			{
		 	MRResource_base.rb_resource_info[ir_loop].ri_filename = (MR_UBYTE*)((MR_ULONG)MRResource_base.rb_resource_info[ir_loop].ri_filename + (MR_ULONG)ir_resource_info);
			}
		}
	else
		MRPrintf("MRInitialiseResources: No filename information available in .MWI\n");

	// Clear CD retry count
	MRResetCDRetry();
}


/******************************************************************************
*%%%% MRSetFileProcess
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSetFileProcess(
*						MR_ULONG	sfc_file_type,
*						MR_BOOL	(*sfc_callback)(MR_ULONG*));
*
*	FUNCTION	Sets a callback function that is to be called when processing
*				a particular file type.
*
*	INPUTS		sfc_file_type	-	File type (eg BP_FTYPE_MOF)
*				sfc_callback	-	Callback routine for this type.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	03.06.96	Dean Ashton		Changed callback prototype to include size.
*
*%%%**************************************************************************/
																									 
MR_VOID	MRSetFileProcess(	MR_ULONG	sfc_file_type,
					  	 	MR_BOOL		(*sfc_callback)(MR_ULONG, MR_ULONG*, MR_ULONG))
{
	MR_ASSERT(sfc_file_type < MR_RES_MAX_CALLBACKS);

	MRResource_callbacks[sfc_file_type].rp_active 	=	TRUE;
	MRResource_callbacks[sfc_file_type].rp_callback	=	sfc_callback;
}


/******************************************************************************
*%%%% MRClearFileProcess
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRClearFileProcess(
*						MR_ULONG	cfc_file_type);
*
*	FUNCTION	Clears the callback function for a particular file type.
*
*	INPUTS		cfc_file_type	-	File type (eg BP_FTYPE_MOF)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRClearFileProcess(MR_ULONG	cfc_file_type)
{
	MR_ASSERT(cfc_file_type < MR_RES_MAX_CALLBACKS);

	MRResource_callbacks[cfc_file_type].rp_active	=	FALSE;
	MRResource_callbacks[cfc_file_type].rp_callback	=	NULL;
}


/******************************************************************************
*%%%% MRGetResourceIDFromAddress
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	MRGetResourceIDFromAddress(
*						MR_VOID* address);
*
*	FUNCTION	Returns the resource id associated with the input address, or
*				-1 if the address isn't in use by any currently loaded resource.
*
*	INPUTS		address		-	Address we want to find the corresponding resource
*								ID for
*
*	RESULT		resource_id	-	Resource ID using address, else -1 if not found
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.04.97	Dean Ashton		Created
*	04.04.97	Dean Ashton		Changed to mask low 24-bits of ri_real_size
*								for dynamic safety margin handling
*
*%%%**************************************************************************/

MR_LONG	MRGetResourceIDFromAddress(MR_VOID* address)
{
	MR_RESINFO*	res_info;
	MR_LONG		res_id;
	MR_LONG		res_count;

	// Validate input and resource status
	MR_ASSERT(MRResource_base.rb_resource_info);
	MR_ASSERT(address);
	
	// Initialise some variables
	res_info	=	MRResource_base.rb_resource_info;
	res_id		=	0;
	res_count	=	MRResource_base.rb_resource_count;

	// Loop through all resources, checking for an address match 
	//
	// Note that access to ri_real_size masks low 24-bits (upper 8 bits are used for safety margin 32-bit word count)

	while(res_count--)
		{
		if ((res_info->ri_flags & MR_RES_TYPE_DEPACK_AUTO) || (res_info->ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
			{
			if (	(
					((MR_ULONG)address >= (MR_ULONG)res_info->ri_depacked_address) && 
					((MR_ULONG)address <= ((MR_ULONG)res_info->ri_depacked_address + (res_info->ri_real_size & 0x00ffffff) )) && 
					(!(res_info->ri_flags & MR_RES_TYPE_IS_GROUP))
					) ||
					(
					((MR_ULONG)address == (MR_ULONG)res_info->ri_depacked_address) &&
					(res_info->ri_flags & MR_RES_TYPE_IS_GROUP)
					)
				)
				return(res_id);
			}
		else
			{
			if (	(
					((MR_ULONG)address >= (MR_ULONG)res_info->ri_address) && 
					((MR_ULONG)address <= ((MR_ULONG)res_info->ri_address + res_info->ri_file_size)) && 
					(!(res_info->ri_flags & MR_RES_TYPE_IS_GROUP))
					) ||
					(
					((MR_ULONG)address == (MR_ULONG)res_info->ri_address) &&
					(res_info->ri_flags & MR_RES_TYPE_IS_GROUP)
					)
				)

				return(res_id);
			}
		res_info++;
		res_id++;
		}

	// We didn't find it... return -1 to caller
	return(-1);
}


/******************************************************************************
*%%%% MRLoadResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRLoadResource(
*						MR_ULONG lr_resource_id);
*
*	FUNCTION	Allocates memory for the relevant resource, and loads the data
*				for the resource. This routine blocks until the read is complete
*
*	INPUTS		lr_resource_id	-	Resource ID to load into RAM
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*
*%%%**************************************************************************/

MR_VOID	MRLoadResource(MR_ULONG lr_resource_id)
{
	MR_LONG		lr_sectors_left;

#ifdef	MR_FILE_FORCE_REAL_SIZE
	MR_LONG		lr_psyq_handle;
	MR_LONG		lr_readlen;
	MR_RESINFO*	lr_resinfo_ptr;
#endif

//	MRShowMem("MRLoadResource");

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// We can't load when we've an outstanding lock
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_NONE);

	// If we're loading, then we need to lock the CD too..
	MRCd_lock = MR_CD_LOCK_SUPER;

#ifdef	MR_FILE_FORCE_REAL_SIZE
	lr_resinfo_ptr = &MRResource_base.rb_resource_info[lr_resource_id];

	if (
		((MR_LONG)lr_resinfo_ptr->ri_filename != -1) && 
		(lr_resinfo_ptr->ri_flags & MR_RES_TYPE_ACCESS_SINGLE) &&
		((lr_resinfo_ptr->ri_flags & (MR_RES_TYPE_DEPACK_AUTO | MR_RES_TYPE_DEPACK_MANUAL)) == 0)		
		)
		{
		if (lr_resinfo_ptr->ri_flags & MR_RES_TYPE_ABSOLUTE_PATH)
			{
			strcpy(MRResource_base.rb_work_filename, lr_resinfo_ptr->ri_filename);
			}
		else
			{
			strcpy(MRResource_base.rb_work_filename, MRResource_base.rb_base_directory);
			strcat(MRResource_base.rb_work_filename, lr_resinfo_ptr->ri_filename);
			}
	
		lr_psyq_handle = PCopen(MRResource_base.rb_work_filename, 0, 0);
		if (lr_psyq_handle == -1)
			{
			MRPrintf("Failure to obtain PC file size: %s\n", MRResource_base.rb_work_filename);
			MR_ASSERTMSG(FALSE, "Program halted");
			}
		else
			{
			lr_readlen	=	PClseek(lr_psyq_handle, 0, 2);					// Offset relative to end is 0 
			lr_resinfo_ptr->ri_file_size = MR_WORD_ALIGN(lr_readlen);	// Align file size and patch resource
			PClseek(lr_psyq_handle, 0, 0);										// Seek back to start
			PCclose(lr_psyq_handle);
			MRPrintf("File: Re-read file size for '%s' is %ld bytes\n", MRResource_base.rb_work_filename, lr_readlen);
			}
		}
#endif

	MRPrepareResource(lr_resource_id);

	MRResetCDRetry();	
	do	{
		MRReadResourceAsync(lr_resource_id);
		if (MRLoad_error == FALSE)
			{
			do	{
				lr_sectors_left = MRGetAsyncStatus(lr_resource_id);
				} while (lr_sectors_left > 0);	
			}

		if (MRLoad_error == TRUE)
			MRProcessCDRetry();

		} while (MRLoad_error == TRUE);
}


/******************************************************************************
*%%%% MRLoadResourceAsync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRLoadResourceAsync(
*						MR_ULONG la_resource_id);
*
*	FUNCTION	Allocates memory for the relevant resource, and starts to load
*				the data for the resource. This routine returns immediately. The
*				MRGetAsyncStatus() routine must be used to find out when the 
*				data is available.
*
*	INPUTS		la_resource_id	-	Resource ID to load into RAM
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*
*%%%**************************************************************************/

MR_VOID	MRLoadResourceAsync(MR_ULONG la_resource_id)
{
	// We can't load when we've an outstanding user lock
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_NONE);

	// If we're loading, then we need to lock the CD too..
	MRCd_lock = MR_CD_LOCK_SUPER;

	MRPrepareResource(la_resource_id);
	MRResetCDRetry();	
	do {
		MRReadResourceAsync(la_resource_id);

		if (MRLoad_error == TRUE)
			MRProcessCDRetry();
		} while (MRLoad_error == TRUE);
}


/******************************************************************************
*%%%% MRPrepareResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRPrepareResource(
*						MR_ULONG pr_resource_id);
*
*	FUNCTION	Allocates the memory associated with a resource, whether the
*				resource is a file or a group.
*
*	INPUTS		pr_resource_id	-	Resource ID to prepare
*
*	NOTES		When loading from CD, allocated memory is rounded to next 
*				sector. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	04.04.97	Dean Ashton		Modifications to allocate dynamic safety margin
*
*%%%**************************************************************************/

MR_VOID	MRPrepareResource(MR_ULONG pr_resource_id)
{
	MR_RESINFO*	pr_resinfo_ptr;
	MR_LONG		pr_safety_margin;
	MR_LONG		pr_alloc_size;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	pr_resinfo_ptr = &MRResource_base.rb_resource_info[pr_resource_id];

	// We can't load files that are components of a group
	MR_ASSERT(!(pr_resinfo_ptr->ri_flags & MR_RES_TYPE_ACCESS_GROUP));

	// We can't load files that are already loaded.
	MR_ASSERT(pr_resinfo_ptr->ri_address == NULL);

	// Allocate memory for the load (determine size based on compression methods)
	if (pr_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_AUTO)
		{
		// Extract count of 32-bit safety margin words from upper 8 bits of 'ri_real_size', and turn into byte count
		pr_safety_margin = (pr_resinfo_ptr->ri_real_size >> 24) << 2;

		//	printf("Safety: %ld\n", pr_safety_margin);

		pr_alloc_size = MIN	(
							(MR_GET_SECTOR_SIZE( (pr_resinfo_ptr->ri_real_size & 0xffffff) + pr_safety_margin)),
							(MR_GET_SECTOR_SIZE( (pr_resinfo_ptr->ri_real_size & 0xffffff)) + pr_safety_margin)
						 	);
		
		pr_resinfo_ptr->ri_address = MRAllocMem(pr_alloc_size, "RESOURCE");
		}
	else
		pr_resinfo_ptr->ri_address = MRAllocMem(MR_GET_SECTOR_SIZE(pr_resinfo_ptr->ri_file_size), "RESOURCE");

}


/******************************************************************************
*%%%% MRReadResourceAsync
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRReadResourceAsync(
*						MR_ULONG	rr_resource_id);
*
*	FUNCTION	If we're using CD file access, then this routine seeks
*				to the resource within the merged file, and then starts an
*				asynchronous read. Note that
*
*	INPUTS		rr_resource_id	-		Resource ID to read in
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*	13.09.96	Dean Ashton		Added support for MR_RES_TYPE_ABSOLUTE_PATH
*
*%%%**************************************************************************/

MR_VOID	MRReadResourceAsync(MR_ULONG rr_resource_id)
{
	MR_RESINFO*	rr_resinfo_ptr;
	MR_LONG		rr_res_sector;
	MR_LONG		rr_psyq_handle;
	CdlLOC		rr_res_cdlloc;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// Must have a supervisor lock in place
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_SUPER);

	rr_resinfo_ptr = &MRResource_base.rb_resource_info[rr_resource_id];

	MRLoad_error = FALSE;

	*rr_resinfo_ptr->ri_address = MR_INVALID_LOAD_ID;

	if (MRUse_cd_routines == TRUE)
		{
		// Load using CD subsystem

		// If we're loading from CD, and the sector offset is NULL, then the .MWI wasn't build for merged file access from CD
		MR_ASSERT(rr_resinfo_ptr->ri_sector_offset != NULL);

		// Calculate the sector the required resource starts at, an create a CdlLoc using it
		rr_res_sector = MRResource_base.rb_root_sector + rr_resinfo_ptr->ri_sector_offset;
		CdIntToPos(rr_res_sector, &rr_res_cdlloc);

		// Try to seek to the position, and if it works then try to start reading. If any
		// of these operations fail (at command level) then flag an error so we can retry.
		if (!CdControlB(CdlSeekL,(MR_UBYTE*)&rr_res_cdlloc, 0))
			{
			MRLoad_error = TRUE;
			}
		else
		if (!CdRead(MR_GET_NUM_SECTORS(rr_resinfo_ptr->ri_file_size), rr_resinfo_ptr->ri_address, CdlModeSpeed))
			{
			MRLoad_error = TRUE;
			}					
		}
	else
		{
		// Load using PsyQ filesystem, but first check we've gt
		MR_ASSERTMSG(((MR_LONG)rr_resinfo_ptr->ri_filename != -1), "No filenames included in .MWI - PsyQ load not possible");

		if (rr_resinfo_ptr->ri_flags & MR_RES_TYPE_ABSOLUTE_PATH)
			{
			strcpy(MRResource_base.rb_work_filename, rr_resinfo_ptr->ri_filename);
			}
		else
			{
			strcpy(MRResource_base.rb_work_filename, MRResource_base.rb_base_directory);
			strcat(MRResource_base.rb_work_filename, rr_resinfo_ptr->ri_filename);
			}

		rr_psyq_handle = PCopen(MRResource_base.rb_work_filename, 0, 0);
		if (rr_psyq_handle == -1)
			{
			MRPrintf("Failure to load PC file: %s\n", MRResource_base.rb_work_filename);
			MR_ASSERTMSG(FALSE, "Program halted");
			MRLoad_error = TRUE;
			}
		else
			{
			// Note: I use the size from the .MWI file to read the file. If the file
			// changes, you should always rebuild the .MWI anyway.
			PCread(rr_psyq_handle, (MR_UBYTE*)rr_resinfo_ptr->ri_address, rr_resinfo_ptr->ri_file_size);
			PCclose(rr_psyq_handle);
			}
		}
}

/******************************************************************************
*%%%% MRGetAsyncStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG status	=	MRGetAsyncStatus(
*									MR_ULONG	ga_resource_id);
*
*	FUNCTION	Returns status of a CD load currently taking place
*
*	INPUTS		ga_resource_id	-	Resource ID we're checking status of
*
*	RESULT		status			-	status > 0  -> Number of sectors left to load
*									status = 0  -> Load complete (releases lock)
*									status = -1	-> Load error
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*	02.07.96	Dean Ashton		Fixed PC filesystem locking mechanism.
*
*%%%**************************************************************************/

MR_LONG	MRGetAsyncStatus(MR_ULONG ga_resource_id)
{
	MR_RESINFO*	ga_resinfo_ptr;
	MR_LONG		ga_readsync_result;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// We can't have a user-lock present
	MR_ASSERT(!(MRCd_lock & MR_CD_LOCK_USER));

	ga_resinfo_ptr = &MRResource_base.rb_resource_info[ga_resource_id];
	
	if (MRUse_cd_routines)
		{
		ga_readsync_result = CdReadSync(1,MRCd_status);

		// If:
		//		a) The hardware says there's a disk error
		//		b)	CdReadSync() says there's a disk error
		//		c)	CdReadSync() says we've finished, but the memory still has the invalid memory tag
		//	then we want to set our error flag, and return -1.
		//
		// If everything looks ok, then just return the number of sectors left (which is going to 
		// be zero when the file has loaded successfully).
	
		if (
			(MRCd_status[0] & CdlDiskError) ||
			(ga_readsync_result == -1) ||
			((ga_readsync_result == 0) && (*ga_resinfo_ptr->ri_address == MR_INVALID_LOAD_ID))
			)
			{
			MRLoad_error = TRUE;
			return(-1);
			}

		if (ga_readsync_result == 0)
			MRCd_lock = MR_CD_LOCK_NONE;	// We only clear the supervisor lock when successful

		return(ga_readsync_result);
		}
	else
		{
	  	MRCd_lock = MR_CD_LOCK_NONE;	// We only clear the supervisor lock when successful
		return(0);
		}
}

/******************************************************************************
*%%%% MRProcessResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRProcessResource(
*						MR_ULONG	pr_resource_id);
*
*	FUNCTION	For a loaded resource (identified by rr_resource_id), this 
*				routine calls associated callback routines which can be used
*				to perform on-load manipulation of the resource buffer.
*
*	INPUTS		pr_resource_id	-		Resource ID to process
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*	03.06.96	Dean Ashton		Changed callback to pass resource size (bytes)
*	04.04.97	Dean Ashton		Changed to use dynamic safety margin allocation
*	02.06.97	Dean Ashton		Changed to pass resource ID through to file
*								callbacks.
*
*%%%**************************************************************************/

MR_VOID	MRProcessResource(MR_ULONG pr_resource_id)
{
	MR_RESGROUP*	pr_resgroup_ptr;
	MR_RESPROC*		pr_resproc_ptr;
	MR_RESINFO*		pr_resinfo_ptr;
	MR_UBYTE*		pr_byte_memory_ptr;


	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	pr_resinfo_ptr = &MRResource_base.rb_resource_info[pr_resource_id];

	// For us to process a resource, it has to have been loaded.
	MR_ASSERT(pr_resinfo_ptr->ri_address != NULL);
	
	// Resources that are actually part of groups can't be processed individually
	MR_ASSERT(!(pr_resinfo_ptr->ri_flags & MR_RES_TYPE_ACCESS_GROUP));

	// If our resource (file or group) is to be automatically decompressed, then decompress it and
	// set the relevant depacked address pointer in the resource structure
	if (pr_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_AUTO)
		{
		// The ((real_size>>24)<<2) bit is extracting the upper 8 bits of ri_real_size, and turning it from a count of 32-bit
		// words needed for safety margin, into a count of bytes needed for the safety margin area
		pr_resinfo_ptr->ri_depacked_address = (MR_ULONG*)((MR_ULONG)pr_resinfo_ptr->ri_address + ((pr_resinfo_ptr->ri_real_size >> 24)<<2));
		MRPPDecrunchBuffer(	(MR_UBYTE*)pr_resinfo_ptr->ri_address, 
									(MR_UBYTE*)pr_resinfo_ptr->ri_depacked_address,
									pr_resinfo_ptr->ri_file_size);
		pr_byte_memory_ptr = (MR_UBYTE*)pr_resinfo_ptr->ri_depacked_address;	// We process the file from the depacked space
		}		
	else
		{
		pr_byte_memory_ptr = (MR_UBYTE*)pr_resinfo_ptr->ri_address;				// Not compressed, or manual.. process from load space
		}

	// If the resource is a manual depack type, then we can't process the resource here. That has to be done later on..
	if (!(pr_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
		{
		if (pr_resinfo_ptr->ri_flags & MR_RES_TYPE_IS_GROUP)
			{
			pr_resgroup_ptr = (MR_RESGROUP*)pr_byte_memory_ptr;
	
			// Process each embedded resource until we reach the end of the list
			while (pr_resgroup_ptr->rg_resource_id != -1)
				{
				pr_byte_memory_ptr += sizeof(MR_RESGROUP);
	
				pr_resproc_ptr = &MRResource_callbacks[pr_resgroup_ptr->rg_type_id];
		
				MRResource_base.rb_resource_info[pr_resgroup_ptr->rg_resource_id].ri_address = (MR_ULONG*)pr_byte_memory_ptr;
		
				// If the embedded resource isn't a manually depacked file, then we can process its callback..
				if (!(MRResource_base.rb_resource_info[pr_resgroup_ptr->rg_resource_id].ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
					{
					// The callback for this type has to be active
					MR_ASSERT(pr_resproc_ptr->rp_active == TRUE);
				
					// But it can be NULL, in which case there is no callback routine
					if (pr_resproc_ptr->rp_callback)
						{
						(pr_resproc_ptr->rp_callback)(pr_resgroup_ptr->rg_resource_id, (MR_ULONG*)pr_byte_memory_ptr, MRResource_base.rb_resource_info[pr_resgroup_ptr->rg_resource_id].ri_file_size);
						}
					}
		
				// Point to the next group link in this group
				pr_byte_memory_ptr += MR_WORD_ALIGN(pr_resgroup_ptr->rg_size);
				pr_resgroup_ptr = (MR_RESGROUP*)pr_byte_memory_ptr;
				}
			}
		else
			{
			pr_resproc_ptr = &MRResource_callbacks[pr_resinfo_ptr->ri_file_type];
		
			MR_ASSERT(pr_resproc_ptr->rp_active == TRUE);
		
			if (pr_resproc_ptr->rp_callback)
				{
				(pr_resproc_ptr->rp_callback)(pr_resource_id, (MR_ULONG*)pr_byte_memory_ptr, pr_resinfo_ptr->ri_file_size);
				}
			}
		}
}


/******************************************************************************
*%%%% MRUnloadResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUnloadResource(
*						MR_ULONG	ur_resource_id);
*
*	FUNCTION	For a loaded resource (identified by ur_resource_id), this 
*				routine frees allocated memory and clears address pointers for
*				resource elements within groups.
*
*	INPUTS		ur_resource_id	-	Resource ID to unload
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRUnloadResource(MR_ULONG ur_resource_id)
{
	MR_RESGROUP*	ur_resgroup_ptr;
	MR_RESINFO*		ur_resinfo_ptr;
	MR_UBYTE*		ur_byte_memory_ptr;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// Get a pointer to the main resource (group or file)
	ur_resinfo_ptr = &MRResource_base.rb_resource_info[ur_resource_id];

	// For us to unload a resource, it has to have been loaded.
	MR_ASSERT(ur_resinfo_ptr->ri_address != NULL);
		
	// Resources that are actually part of groups can't be unloaded individually
	MR_ASSERT(!(ur_resinfo_ptr->ri_flags & MR_RES_TYPE_ACCESS_GROUP));

	// Resources flagged as MR_RES_TYPE_DEPACK_MANUAL have to have have been freed (ie depack address is NULL)
	if ((ur_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL) && (ur_resinfo_ptr->ri_depacked_address != NULL))
		MR_ASSERT(FALSE);

	// Get address of the resource (doesn't matter if it's a group or a file)
	if (ur_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_AUTO)
		{
		ur_byte_memory_ptr = (MR_UBYTE*)ur_resinfo_ptr->ri_depacked_address;	// We process the file from the depacked space
		ur_resinfo_ptr->ri_depacked_address = NULL;
		}		
	else
		{
		ur_byte_memory_ptr = (MR_UBYTE*)ur_resinfo_ptr->ri_address;				// Not compressed, or manual.. process from load space
		}

	// If we're not a manually depacked group, then we can clear each embedded resources address.
	if ((ur_resinfo_ptr->ri_flags & MR_RES_TYPE_IS_GROUP) && (!(ur_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL)))
		{
		ur_resgroup_ptr = (MR_RESGROUP*)ur_byte_memory_ptr;

		// Process each embedded resource until we reach the end of the list
		while (ur_resgroup_ptr->rg_resource_id != -1)
			{
			ur_byte_memory_ptr += sizeof(MR_RESGROUP);

			// Clear the memory pointer for this embedded resource
			MRResource_base.rb_resource_info[ur_resgroup_ptr->rg_resource_id].ri_address = NULL;			

			// Point to the next group link in this group
			ur_byte_memory_ptr += MR_WORD_ALIGN(ur_resgroup_ptr->rg_size);
			ur_resgroup_ptr = (MR_RESGROUP*)ur_byte_memory_ptr;
			}
		}

	// Free memory (and clear the pointer to that memory) associated with this resource
	MRFreeMem(ur_resinfo_ptr->ri_address);
	ur_resinfo_ptr->ri_address	= NULL;
}


/******************************************************************************
*%%%% MRPreseekResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRPreseekResource(
*						MR_ULONG ps_resource_id);
*
*	FUNCTION	Seeks to the CD location of the required resource
*
*	INPUTS		ps_resource_id	-	Resource ID to preseek to
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRPreseekResource(MR_ULONG ps_resource_id)
{
	MR_RESINFO*	ps_resinfo_ptr;
	MR_LONG		ps_res_sector;
	CdlLOC		ps_res_cdlloc;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// We can't do this if someone's locked the CD 
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_NONE);

	// Get a pointer to the main resource (group or file)
	ps_resinfo_ptr = &MRResource_base.rb_resource_info[ps_resource_id];

	// We can't preseek to files that are components of a group
	MR_ASSERT(!(ps_resinfo_ptr->ri_flags & MR_RES_TYPE_ACCESS_GROUP));

	// Clear CD error status
	MRResetCDRetry();

	do	{
		// Flag that everything was ok..
		MRLoad_error = FALSE;

		if (MRUse_cd_routines == TRUE)
			{
					
			// If the sector offset is NULL, then the .MWI wasn't build for merged file access from CD
			MR_ASSERT(ps_resinfo_ptr->ri_sector_offset != NULL);

			// Calculate the sector the required resource starts at, an create a CdlLoc using it
			ps_res_sector = MRResource_base.rb_root_sector + ps_resinfo_ptr->ri_sector_offset;
			CdIntToPos(ps_res_sector, &ps_res_cdlloc);

			// Try to seek to the position, and if the operation fails (at command level)
			// then flag an error so we can retry.
			if (!CdControlB(CdlSeekL,(MR_UBYTE*)&ps_res_cdlloc, 0))
				{
				MRLoad_error = TRUE;
				}

			// Perform CD error handling			
			if (MRLoad_error == TRUE)
				MRProcessCDRetry();
			}

		} while (MRLoad_error == TRUE);
}


/******************************************************************************
*%%%% MRLockUserCD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRLockUserCD(MR_VOID);
*
*	FUNCTION	Lets application code inhibit API use of the CD-ROM mechanism.
*					
*	NOTES		When I say 'Inhibit API use of the CD-ROM', I mean that the file
*				code will cause an assertion failure if API file access is 
*				attempted while between a MRLockUserCD()/MRUnlockUserCD()
*				function pair. This routine will cause an assertion failure in
*				the API is currently reading a file. Therefore, these functions
*				are primarily used to trap problems during project development.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*
*%%%**************************************************************************/

MR_VOID	MRLockUserCD(MR_VOID)
{
	// Only allow MRUnlockUserCD if we haven't got a current lock.
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_NONE);

	// Set user locking flags
	MRCd_lock = MR_CD_LOCK_USER;
}


/******************************************************************************
*%%%% MRUnlockUserCD
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRUnlockUserCD(MR_VOID);
*
*	FUNCTION	Releases the lock on the CD-ROM mechanism obtained by the 
*				MRLockUserCD() routine
*					
*	NOTES		See MRLockUserCD() for a full description of how this is used.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.06.96	Dean Ashton		Created
*	18.06.96	Dean Ashton		Locking mechanism modifications
*
*%%%**************************************************************************/

MR_VOID	MRUnlockUserCD(MR_VOID)
{
	// Only allow MRUnlockUserCD if we've got a current user lock.
	MR_ASSERT(MRCd_lock == MR_CD_LOCK_USER);

	// Clear locking flags
	MRCd_lock = MR_CD_LOCK_NONE;
}



/******************************************************************************
*%%%% MRSaveFile
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSaveFile(
*						MR_STRPTR	filename,
*						MR_ULONG*	address,
*						MR_LONG		length);
*
*	FUNCTION	Development routine to save an area of memory to a file on the
*				host PC.
*
*	INPUTS		filename	-	File to save as
*				address		-	Address to save from
*				length		-	Number of bytes to save
*
*	NOTES		DEVELOPMENT ROUTINE ONLY!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSaveFile(	MR_STRPTR	filename,
					MR_ULONG*	address,
					MR_LONG		length)
{
	MR_LONG	handle;
	
	// Try to open the file, creating if it doesn't exist.
	handle	=	PCopen(filename, 1, 0);
	if (handle == -1)
		{
		handle = PCcreat(filename, 0);
		if (handle == -1)
			{
			MRPrintf("Failure to save PC file: %s\n", filename);
			MR_ASSERTMSG(FALSE, "Program halted");
			}
		}

	// Write the file, close it, and exit
	PCwrite(handle, (MR_UBYTE*)address, length);
	PCclose(handle);
	return;
}

/******************************************************************************
*%%%% MRLoadAbsToAnywhere
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRLoadAbsToAnywhere(
*						MR_STRPTR	filename,
*						MR_ULONG*	address);
*
*	FUNCTION	Development routine to load a PC file to an absolute address
*				in main RAM.
*
*	INPUTS		filename	-	File to load
*				address		-	Address to load to
*
*	NOTES		DEVELOPMENT ROUTINE ONLY!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRLoadAbsToAnywhere(MR_STRPTR	filename,
							MR_ULONG*	address)
{
	MR_LONG	readlen;
	MR_LONG	handle;
	
	handle	=	PCopen(filename, 0, 0);
	
	if (handle == -1)
		{
		MRPrintf("Failure to load PC file: %s\n", filename);
		MR_ASSERTMSG(FALSE, "Program halted");
		}

	readlen	=	PClseek(handle, 0, 2);	// Offset relative to end is 0
	PClseek(handle, 0, 0);					// Seek back to start
	PCread(handle, (MR_UBYTE*)address, readlen);
	PCclose(handle);
}	


/******************************************************************************
*%%%% MRLoadAbsToAnywhereAnyLength
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRLoadAbsToAnywhereAnyLength(
*						MR_STRPTR	filename,
*						MR_ULONG*	address,
*						MR_ULONG	length)
*
*	FUNCTION	Development routine to load a PC file to an absolute address
*				in main RAM... length of read specified.
*
*	INPUTS		filename	-	File to load
*				address		-	Address to load to
*				length		-	Number of bytes to load
*
*	NOTES		DEVELOPMENT ROUTINE ONLY!
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.06.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRLoadAbsToAnywhereAnyLength(	MR_STRPTR	filename,
										MR_ULONG*	address,
										MR_ULONG		length)
{
	MR_LONG	readlen;
	MR_LONG	handle;
	
	handle	=	PCopen(filename, 0, 0);
	
	if (handle == -1)
		{
		MRPrintf("Failure to load PC file: %s\n", filename);
		MR_ASSERTMSG(FALSE, "Program halted");
		}

	readlen	=	PClseek(handle, 0, 2);	// Offset relative to end is 0
	PClseek(handle, 0, 0);					// Seek back to start
	PCread(handle, (MR_UBYTE*)address, length);
	PCclose(handle);
}	


/******************************************************************************
*%%%% MRGetResourceAddr
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID*	addr =	MRGetResourceAddr( MR_ULONG	ga_resource_id);
*
*	FUNCTION	Returns the address of a resource. This function will correctly
*				return the address for a resource marked as compressed (where
*				the address of the data is not the load address of the resource).
*
*	INPUTS		ga_resource_id	-	Resource ID we're getting address of
*
*	RESULT		addr			-	Address of specified resource, or NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID*	MRGetResourceAddr(MR_ULONG ga_resource_id)
{
	MR_RESINFO*	ga_resinfo_ptr;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	ga_resinfo_ptr = &MRResource_base.rb_resource_info[ga_resource_id];

	if ((ga_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_AUTO) ||
		(ga_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
		{
		return(ga_resinfo_ptr->ri_depacked_address);
		}
	else
		return(ga_resinfo_ptr->ri_address);

}


/******************************************************************************
*%%%% MRGetResourceSize
*------------------------------------------------------------------------------
*
*	SYNOPSIS   	MR_ULONG	size =	MRGetResourceSize( MR_ULONG gs_resource_id);
*
*	FUNCTION   	Returns the size of a resource. This function will correctly
*			   	return the address for a resource marked as compressed.
*
*	INPUTS		gs_resource_id	-	Resource ID we're getting size of
*
*	RESULT		size			-	Size of specified resource.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.03.97   	Dean Ashton		Created
*	04.04.97   	Dean Ashton		Made sure size is read only from low 24-bits of
*			   					ri_real_size.
*
*%%%**************************************************************************/

MR_ULONG	MRGetResourceSize(MR_ULONG gs_resource_id)
{
	MR_RESINFO*	gs_resinfo_ptr;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	gs_resinfo_ptr = &MRResource_base.rb_resource_info[gs_resource_id];

	if ((gs_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_AUTO) ||
		(gs_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
		{
		return(gs_resinfo_ptr->ri_real_size & 0xffffff);
		}
	else
		return(gs_resinfo_ptr->ri_file_size);

}


/******************************************************************************
*%%%% MRAllocPackedResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRAllocPackedResource(MR_ULONG ap_resource_id);
*
*	FUNCTION	Given a packed resource ID, this routine allocates room for the
*				unpacked resource, decompresses from the resources address to
*				the new allocation, and performs processing similar to that used
*				in MRProcessResource() in order to invoke callbacks and resolve
*				addresses.
*
*	INPUTS		ap_resource_id	-	Resource ID we're going to process..
*
*	NOTES		This routine makes a separate allocation that will be released by
*		 		a call to MRFreePackedResource(), otherwise the memory won't be
*				freed.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.03.97	Dean Ashton		Created
*	04.04.97	Dean Ashton		Only use low 24-bits of ri_real_size. Upper 8-bits
*								are used for safety margin calculations.
*	02.06.97	Dean Ashton		Modified to pass resource ID through to file type
*								callbacks.
*
*%%%**************************************************************************/

MR_VOID	MRAllocPackedResource(MR_ULONG ap_resource_id)
{							
	MR_RESGROUP*	ap_resgroup_ptr;
	MR_RESPROC*		ap_resproc_ptr;
	MR_RESINFO*		ap_resinfo_ptr;
	MR_UBYTE*		ap_byte_memory_ptr;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);
	ap_resinfo_ptr = &MRResource_base.rb_resource_info[ap_resource_id];

	// For us to process a resource, it has to have been loaded.
	MR_ASSERT(ap_resinfo_ptr->ri_address != NULL);
	
	// Resources that aren't flagged as MR_RES_TYPE_DEPACK_MANUAL cannot be processed with this function
	MR_ASSERT(ap_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL);

	// Resources that have already been decompressed cannot be processed again
	MR_ASSERT(ap_resinfo_ptr->ri_depacked_address == NULL);

	// Allocate the room needed to decompress the resource. No safety margin required here, as we're decompressing
	// to a completely separate memory area.
	ap_resinfo_ptr->ri_depacked_address = MRAllocMem((ap_resinfo_ptr->ri_real_size&0xffffff), "PACKEDRESOURCE");

	MRPPDecrunchBuffer(	(MR_UBYTE*)ap_resinfo_ptr->ri_address,
								(MR_UBYTE*)ap_resinfo_ptr->ri_depacked_address,
								ap_resinfo_ptr->ri_file_size);

	ap_byte_memory_ptr = (MR_UBYTE*)ap_resinfo_ptr->ri_depacked_address;

	// Manually depacked group
	if (ap_resinfo_ptr->ri_flags & MR_RES_TYPE_IS_GROUP)
		{
		ap_resgroup_ptr = (MR_RESGROUP*)ap_byte_memory_ptr;

		// Process each embedded resource until we reach the end of the list
		while (ap_resgroup_ptr->rg_resource_id != -1)
			{
			ap_byte_memory_ptr += sizeof(MR_RESGROUP);

			ap_resproc_ptr = &MRResource_callbacks[ap_resgroup_ptr->rg_type_id];
	
			MRResource_base.rb_resource_info[ap_resgroup_ptr->rg_resource_id].ri_address = (MR_ULONG*)ap_byte_memory_ptr;
	
			// If the embedded resource isn't a manually depacked file, then we can process its callback..
			if (!(MRResource_base.rb_resource_info[ap_resgroup_ptr->rg_resource_id].ri_flags & MR_RES_TYPE_DEPACK_MANUAL))
				{
				// The callback for this type has to be active
				MR_ASSERT(ap_resproc_ptr->rp_active == TRUE);
			
				// But it can be NULL, in which case there is no callback routine
				if (ap_resproc_ptr->rp_callback)
					{
					(ap_resproc_ptr->rp_callback)(ap_resgroup_ptr->rg_resource_id, (MR_ULONG*)ap_byte_memory_ptr, MRResource_base.rb_resource_info[ap_resgroup_ptr->rg_resource_id].ri_file_size);
					}
				}
	
			// Point to the next group link in this group
			ap_byte_memory_ptr += MR_WORD_ALIGN(ap_resgroup_ptr->rg_size);
			ap_resgroup_ptr = (MR_RESGROUP*)ap_byte_memory_ptr;
			}
		}
	else
		{
		ap_resproc_ptr = &MRResource_callbacks[ap_resinfo_ptr->ri_file_type];
	
		MR_ASSERT(ap_resproc_ptr->rp_active == TRUE);
	
		if (ap_resproc_ptr->rp_callback)
			{
			(ap_resproc_ptr->rp_callback)(ap_resource_id, (MR_ULONG*)ap_byte_memory_ptr, ap_resinfo_ptr->ri_file_size);
			}
		}
}



/******************************************************************************
*%%%% MRFreePackedResource
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRFreePackedResource(MR_ULONG fp_resource_id);
*
*	FUNCTION	Given a packed resource ID, this routine frees the unpacked 
*				copy (created by MRAllocPackedResource), and performs processing
*				similar to that used in MRUnloadResource() in order to clear
*				addresses.
*
*	INPUTS		fp_resource_id	- 	Resource ID we're going to process..
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRFreePackedResource(MR_ULONG fp_resource_id)
{
	MR_RESGROUP*	fp_resgroup_ptr;
	MR_RESINFO*		fp_resinfo_ptr;
	MR_UBYTE*		fp_byte_memory_ptr;

	// We've got to have a valid resource list
	MR_ASSERT(MRResource_base.rb_resource_info);

	// Get a pointer to the main resource (group or file)
	fp_resinfo_ptr = &MRResource_base.rb_resource_info[fp_resource_id];

	// Resources that aren't flagged as MR_RES_TYPE_DEPACK_MANUAL cannot be processed with this function
	MR_ASSERT(fp_resinfo_ptr->ri_flags & MR_RES_TYPE_DEPACK_MANUAL);

	// For us to free a packed resource, it has to have been previoulsy through MRAllocPackedResource()
	MR_ASSERT(fp_resinfo_ptr->ri_depacked_address != NULL);
		
	fp_byte_memory_ptr = (MR_UBYTE*)fp_resinfo_ptr->ri_depacked_address;

	// If we're not a manually depacked group, then we can clear each embedded resources address.
	if (fp_resinfo_ptr->ri_flags & MR_RES_TYPE_IS_GROUP)
		{
		fp_resgroup_ptr = (MR_RESGROUP*)fp_byte_memory_ptr;

		// Process each embedded resource until we reach the end of the list
		while (fp_resgroup_ptr->rg_resource_id != -1)
			{
			fp_byte_memory_ptr += sizeof(MR_RESGROUP);
		
			// All files within a group should have a depacked address of NULL. If this isn't NULL then it means our
			// manually depacked group had manually depacked files within it that haven't had MRFreePackedResource()
			// called for them..
			MR_ASSERT(MRResource_base.rb_resource_info[fp_resgroup_ptr->rg_resource_id].ri_depacked_address == NULL);

			// Clear the memory pointer for this embedded resource
			MRResource_base.rb_resource_info[fp_resgroup_ptr->rg_resource_id].ri_address = NULL;			

			// Point to the next group link in this group
			fp_byte_memory_ptr += MR_WORD_ALIGN(fp_resgroup_ptr->rg_size);
			fp_resgroup_ptr = (MR_RESGROUP*)fp_byte_memory_ptr;
			}
		}

	// Free memory (and clear the pointer to that memory) associated with this resources depacked area
	MRFreeMem(fp_resinfo_ptr->ri_depacked_address);
	fp_resinfo_ptr->ri_depacked_address	= NULL;
}


/******************************************************************************
*%%%% MRResetCDRetry
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRResetCDRetry(MR_VOID);
*
*	FUNCTION	Resets the internal counter associated with CD seeking and
*				reading errors.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRResetCDRetry(MR_VOID)
{
	MRCd_retry_count = 0;
}


/******************************************************************************
*%%%% MRProcessCDRetry
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRProcessCDRetry(MR_VOID);
*
*	FUNCTION	This routine is called when there are CD seeking or reading
*				errors. Once a retry limit is reached, a screen will be shown
*				with a suitable error message.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	Dean Ashton		Created
*	15.08.97	Dean Ashton		Changed to use 256-pixel wide screen
*
*%%%**************************************************************************/

MR_VOID	MRProcessCDRetry(MR_VOID)
{
	DISPENV			error_dispenv;					// Display/Drawing environments
	DRAWENV			error_drawenv;
	RECT			error_rect;
	MR_UBYTE*		source_ptr;
	MR_ULONG		unpacked_len;
	MR_CDERROR_TIM*	dest_ptr;
	MR_SHORT		screen_w, screen_h, w,h;

	MRCd_retry_count++;

	if (MRCd_retry_count > MR_CD_RETRY_COUNT)
		{
	
		// Reset graphics subsystem
		DrawSync(0);
		VSync(0);
		ResetGraph(0);

		// Initialise a screen
		screen_w = 256;

#ifdef	MR_MODE_NTSC
		screen_h = 240;
#else
		screen_h = 256;
#endif

		setDefDrawEnv(&error_drawenv, 0, 0, screen_w, screen_h);
		setDefDispEnv(&error_dispenv, 0, 0, screen_w, screen_h);

#ifdef	MR_MODE_PAL
		error_dispenv.screen.y = 16;
		error_dispenv.screen.h = 256;
#endif

		setRECT(&error_rect,0,0,screen_w,screen_h);
		ClearImage(&error_rect, 0x00, 0x00, 0x00);
		PutDrawEnv(&error_drawenv);
		PutDispEnv(&error_dispenv);
		
		// Obtain the length of the error bitmap
		source_ptr		=	&MRCd_error_pp[0] + MRCd_error_len - 4;
		unpacked_len	=	source_ptr[0] << 16 | source_ptr[1] << 8 | source_ptr[2];

		// Allocate room for the decompressed data
		dest_ptr		=	MRAllocMem(unpacked_len, "CDERROR");

		MRPPDecrunchBuffer((MR_UBYTE*)&MRCd_error_pp, (MR_UBYTE*)dest_ptr, MRCd_error_len);
		
		w = dest_ptr->ce_hw & 0xffff;		// Fetch width of image
		h = dest_ptr->ce_hw >> 16;			// Fetch height of image

		setRECT(&error_rect, ((screen_w-w)/2), ((screen_h-h)/2), w, h);				
		LoadImage(&error_rect, (MR_LONG*)dest_ptr->ce_data);
	
		// Display the screen
		DrawSync(0);	
		VSync(0);
		SetDispMask(1);			   

		// Free the image memory 
		MRFreeMem(dest_ptr);

		// Busy loop
		while(1)
			{
			VSync(0);
			}
		}
}

