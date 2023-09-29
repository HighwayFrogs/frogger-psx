/******************************************************************************
*%%%% mr_vram.c
*------------------------------------------------------------------------------
*
*	Routines to handle the processing of Vorg2 VLO files.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	09.07.96	Dean Ashton		Created
*	12.12.96	Dean Ashton		Added new processing for textures placed at the
*								right/bottom of texture pages
*	08.07.97	Dean Ashton		Oh dear. MRFreeTextureResourceBlock failed if
*								there were no textures at all.. but now it's fixed.
*	15.07.97	Dean Ashton		Bug fixed in dynamic texture block checking.
*								Ta Mr.Busbutt! 
*	15.07.97	Dean Ashton		Fixed another dynamic texture block bug to do with
*								multiple texture loads.
*
*%%%**************************************************************************/

#include	"mr_all.h"

MR_BOOL		MRTexture_block_root_initialised = FALSE;
MR_TBLOCK	MRTexture_block_root;
MR_TBLOCK*	MRTexture_block_root_ptr;
MR_LONG		MRTexture_block_count;

/******************************************************************************
*%%%% MRProcessVLO
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	success =	MRProcessVLO(
*									MR_ULONG	pv_resource_id,
*									MR_ULONG* 	pv_vlo_addr)
*
*	FUNCTION	For a given VLO file located at memory address 'pv_vlo_addr', 
*				this routine will move data to the areas of VRAM defined within  
*				the VLO file (as dictated by Vorg 2). As of 04.06.97, this 
*				function will perform dynamic allocation of MR_TEXTURE
*				structures for textures that are not referenced by name. The
*				information pertaining the the specific allocation is stored
*				in a linked list, so we can allow freeing of the associated
*				texture structures based on resource ID, and also perform
*				multiple-load and free-twice checking for the appropriate 
*				resources
*
*	INPUTS		pv_resource_id	-	Resource ID associated with this VLO
*
*				pv_vlo_addr		-	Address of the VLO in memory
*
*	RESULT		success			-	TRUE if everything is OK, else FALSE.
*
*	NOTES		Note that due to the nature of this routine, it has to call
*				DrawSync(0) many times. Because of this, it's probably not
*				suitable for use within a main loop that performs ordering table
*				rendering.
*
*	EXTRA		This routine now deals with textures that are positioned at the 
*				bottom and right of a texture page by reducing the texture 
*				dimensions by 1 pixel. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.96	Dean Ashton		Created
*	12.12.96	Dean Ashton		Modified to use HIT_X and HIT_Y flag bits
*	05.06.97	Dean Ashton		Modified to support the MR_SPIF_REFERENCED_BY_NAME
*								flag, and hence create/maintain blocks of dynamic
*				 				MR_TEXTURE structures.
*	15.07.97	Dean Ashton		Bug fixed in dynamic texture block checking.
*								Ta Mr.Busbutt! 
*	15.07.97	Dean Ashton		Fixed another dynamic texture block bug to do with
*								multiple texture loads.
*
*%%%**************************************************************************/

MR_BOOL	MRProcessVLO(	MR_ULONG	pv_resource_id,
						MR_ULONG*	pv_vlo_addr)
{
	MR_LONG				pv_unnamed_count;
	MR_SHORT			pv_w, pv_h;
	MR_SHORT			pv_hit_x, pv_hit_y;
	MR_LONG	  			pv_count;
	MR_VLOFILE*			pv_vlofile_ptr;
	MR_TXSETUP*			pv_txsetup_ptr;
	MR_CLUTSETUP*		pv_clutsetup_ptr;
	MR_TEXTURE*			pv_texture_ptr;	
	MR_TEXTURE***		pv_pointer_ptr;
	MR_TBLOCK*			pv_tblock_ptr;

	MR_ASSERT(pv_vlo_addr != NULL);

	// Get a pointer to the MR_VLOFILE structure (at the start of the file)
	pv_vlofile_ptr 	=	(MR_VLOFILE*)pv_vlo_addr;

	// Validate VLO header
	if (pv_vlofile_ptr->vf_ident != MR_VLO_TAG)
		{
		MR_ASSERT(FALSE);
		return(FALSE);
		}

	// ----- 
	// Find total number of un-named textures

	pv_unnamed_count 	=	0;
	pv_count			=	pv_vlofile_ptr->vf_txsetup_count;
	pv_txsetup_ptr		=	(MR_TXSETUP*)(pv_vlofile_ptr->vf_txsetup_offset + (MR_ULONG)pv_vlo_addr);

	while(pv_count--)
		{
		if (!(pv_txsetup_ptr->ts_flags & MR_SPIF_REFERENCED_BY_NAME))
			pv_unnamed_count++;
		pv_txsetup_ptr++;
		}

	// -----

	if (pv_unnamed_count)
		{
		// If we haven't setup our root texture block, do so and set a flag so we don't do it again.
		if (!MRTexture_block_root_initialised)
			{
			MRTexture_block_root_ptr = &MRTexture_block_root;
			MRTexture_block_root_ptr->tb_next_node = NULL;
			MRTexture_block_root_ptr->tb_prev_node = NULL;
			MRTexture_block_count= 0;

			MRTexture_block_root_initialised = TRUE;
			}

		// Check for existing allocation with the resource ID within it, and assert if we find it
		pv_tblock_ptr = MRTexture_block_root_ptr;
		while(pv_tblock_ptr = pv_tblock_ptr->tb_next_node)
			{
			if (pv_tblock_ptr->tb_resource_id == pv_resource_id)
				{
				MR_ASSERT(FALSE);
				return(FALSE);
				}
			}			   

		// Perform allocation of (Link, 'n+1' pointers to texture pointers, 'n' MR_TEXTURE structures) and link into list
		pv_tblock_ptr = MRAllocMem( sizeof(MR_TBLOCK) + 
									((pv_unnamed_count+1) * sizeof(MR_TEXTURE*)) + 
									((pv_unnamed_count) * sizeof(MR_TEXTURE)),
									"MR_TBLOCK");

		// Link into list, and setup the MR_TBLOCK
		if (pv_tblock_ptr->tb_next_node = MRTexture_block_root_ptr->tb_next_node)
			MRTexture_block_root_ptr->tb_next_node->tb_prev_node = pv_tblock_ptr;

		MRTexture_block_root_ptr->tb_next_node = pv_tblock_ptr;
		pv_tblock_ptr->tb_prev_node = MRTexture_block_root_ptr;
		MRTexture_block_count++;

		pv_tblock_ptr->tb_resource_id	=	pv_resource_id;
		pv_tblock_ptr->tb_pointers		=	(MR_TEXTURE***)(pv_tblock_ptr+1);
		pv_tblock_ptr->tb_textures		=	(MR_TEXTURE*)((pv_tblock_ptr->tb_pointers) + (pv_unnamed_count+1));

		// Loop through textures in VLO again, setting the texture address in the API texture list, and storing
		// the address of the pointer in our pointer cache block. The actual MR_TEXTURE structures will be filled
		// in later on.
		pv_count			=	pv_vlofile_ptr->vf_txsetup_count;
		pv_pointer_ptr		=	pv_tblock_ptr->tb_pointers;
		pv_texture_ptr		=	pv_tblock_ptr->tb_textures;

		pv_txsetup_ptr		=	(MR_TXSETUP*)(pv_vlofile_ptr->vf_txsetup_offset + (MR_ULONG)pv_vlo_addr);

		while(pv_count--)
			{
			if (!(pv_txsetup_ptr->ts_flags & MR_SPIF_REFERENCED_BY_NAME))
				{
				*pv_pointer_ptr = &(MRTexture_list_ptr[pv_txsetup_ptr->ts_id]);
				pv_pointer_ptr++;

				// We can't dynamically patch an already loaded texture. Sorry!
				MR_ASSERT(MRTexture_list_ptr[pv_txsetup_ptr->ts_id] == NULL);

				MRTexture_list_ptr[pv_txsetup_ptr->ts_id] = pv_texture_ptr;
				pv_texture_ptr++;
				}
			pv_txsetup_ptr++;
			}
		
		// Null terminate pointer array (we allocated one more than necessary above)
		*pv_pointer_ptr = NULL;
		}

	// ---

	// Process MR_TXSETUP structures within this VLO file
	pv_count			=	pv_vlofile_ptr->vf_txsetup_count;
	pv_txsetup_ptr		=	(MR_TXSETUP*)(pv_vlofile_ptr->vf_txsetup_offset + (MR_ULONG)pv_vlo_addr);

	while(pv_count--)
		{
		DrawSync(0);
		LoadImage(&pv_txsetup_ptr->ts_vram_rect, (MR_ULONG*)(pv_txsetup_ptr->ts_vram_offset + (MR_ULONG)pv_vlo_addr + 0));

		// Fetch HIT_X
		if (pv_txsetup_ptr->ts_flags & MR_SPIF_HIT_X)
			pv_hit_x = 1;
		else
			pv_hit_x = 0;

		// Fetch HIT_Y
		if (pv_txsetup_ptr->ts_flags & MR_SPIF_HIT_Y)
			pv_hit_y = 1;
		else
			pv_hit_y = 0;

		// Deal with width/height of zero (meaning it's 256.. but we're in a UBYTE y'see)
		if (pv_txsetup_ptr->ts_w == 0)
			pv_w = 256;
		else
			pv_w = pv_txsetup_ptr->ts_w;

		if (pv_txsetup_ptr->ts_h == 0)
			pv_h = 256;
		else
			pv_h = pv_txsetup_ptr->ts_h;
	
		pv_texture_ptr = MRTexture_list_ptr[pv_txsetup_ptr->ts_id];

		pv_texture_ptr->te_flags		=	pv_txsetup_ptr->ts_flags;		
		pv_texture_ptr->te_w 			=	pv_w - pv_hit_x;
		pv_texture_ptr->te_h 			=	pv_h - pv_hit_y;
 
		pv_texture_ptr->te_u0			=	pv_txsetup_ptr->ts_u;
		pv_texture_ptr->te_v0			=	pv_txsetup_ptr->ts_v;
		pv_texture_ptr->te_clut_id		=	pv_txsetup_ptr->ts_clut_id;

		pv_texture_ptr->te_u1			=	pv_txsetup_ptr->ts_u + pv_texture_ptr->te_w;
		pv_texture_ptr->te_v1			=	pv_txsetup_ptr->ts_v;
		pv_texture_ptr->te_tpage_id		=	pv_txsetup_ptr->ts_tpage_id;

		pv_texture_ptr->te_u2			=	pv_txsetup_ptr->ts_u;
		pv_texture_ptr->te_v2			=	pv_txsetup_ptr->ts_v + pv_texture_ptr->te_h;

		pv_texture_ptr->te_u3			=	pv_txsetup_ptr->ts_u + pv_texture_ptr->te_w;
		pv_texture_ptr->te_v3			=	pv_txsetup_ptr->ts_v + pv_texture_ptr->te_h;

		DrawSync(0);
		pv_txsetup_ptr++;
		}

	// Process MR_CLUTSETUP structures within this VLO file
	pv_count			=	pv_vlofile_ptr->vf_clutsetup_count;
	pv_clutsetup_ptr	=	(MR_CLUTSETUP*)(pv_vlofile_ptr->vf_clutsetup_offset + (MR_ULONG)pv_vlo_addr);

	while(pv_count--)
		{
		DrawSync(0);
		LoadImage(&pv_clutsetup_ptr->cs_clut_rect, (MR_ULONG*)(pv_clutsetup_ptr->cs_clut_offset + (MR_ULONG)pv_vlo_addr));
		DrawSync(0);
		pv_clutsetup_ptr++;
		}

	return(TRUE);
}


/******************************************************************************
*%%%% MRFreeResourceTextureBlock
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL found_block =	MRFreeResourceTextureBlock(
*								   		MR_ULONG ft_resource_id);
*
*	FUNCTION	Frees a dynamic texture block that was (possibly) allocated by
*				a call to MRProcessVLO(). 
*
*	INPUTS		ft_resource_id	-	Resource ID of the VLO that has a dynamic 
*									texture block in memory.
*
*	RESULT		found_block		-	TRUE if we found a texture block for this
*									resource and freed it, else FALSE
*
*	NOTES		If the resource has no allocated texture block, this function
*				will do nothing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.06.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Oh dear. It failed if there were no textures
*								at all.. but now it's fixed.
*
*%%%**************************************************************************/

MR_BOOL	MRFreeResourceTextureBlock(MR_ULONG ft_resource_id)
{
	MR_TBLOCK*		ft_tblock_ptr;
	MR_TEXTURE***	ft_pointer_ptr;

	// No textures? No problem.. just return that we didn't find anything. 
	if (MRTexture_block_root_initialised == FALSE)
		return(FALSE);

	// Check for existing allocation with the resource ID within it, and assert if we find it
	ft_tblock_ptr = MRTexture_block_root_ptr;


	while(ft_tblock_ptr = ft_tblock_ptr->tb_next_node)
		{
		if (ft_tblock_ptr->tb_resource_id == ft_resource_id)
			{

			// Remove structure from linked list
			ft_tblock_ptr->tb_prev_node->tb_next_node = ft_tblock_ptr->tb_next_node;
			if	(ft_tblock_ptr->tb_next_node)
				ft_tblock_ptr->tb_next_node->tb_prev_node = ft_tblock_ptr->tb_prev_node;

			// Clear all pointers in texture list
			ft_pointer_ptr = ft_tblock_ptr->tb_pointers;
			while(*ft_pointer_ptr != NULL)
				{
				**ft_pointer_ptr = NULL;
				ft_pointer_ptr++;
				}
		
			// Free memory
			MRFreeMem(ft_tblock_ptr);			

			// Decrease count
			MRTexture_block_count--;
	
			// Return, telling caller we found a texture block for the resource and subsequently freed it
			return(TRUE);
			}
		}			   

	// We didn't find this resource.. never mind...
	return(FALSE);
}

