/******************************************************************************
*%%%% mr_c_pak.c
*------------------------------------------------------------------------------
*
*	'C' Decompression Code - for use in PC titles. PlayStation titles should use
*	the assembler version of this file. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	04.03.97	Dean Ashton		New file
*
*%%%**************************************************************************/

#include	"mr_all.h"

MR_ULONG		MRPP_shift_in;
MR_ULONG		MRPP_counter;
MR_UBYTE*		MRPP_source_ptr;


/******************************************************************************
*%%%% MRPPDecrunchBuffer
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG status =	MRPPDecrunchBuffer(
*									MR_UBYTE*	source,
*									MR_UBYTE*	dest,
*									MR_ULONG	packed_length);
*
*	FUNCTION	Decompresses a block of previously compressed data. This routine
*				should allow you to decompress over the source area, so
*				theoretically dest could be 'source+8'. In practise, I guess a
*				32-byte margin is safer. Time will probably tell...
*
*	INPUTS		source			-	Pointer to start of compressed data
*				dest			-	Pointer to start of destination area
*				packed_length	-	Length of compressed file
*
*	RESULT		status			-	MR_PPDECRUNCH_ERROR if not compressed
*								 	or MR_PPDECRUNCH_OK if all went well...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	MRPPDecrunchBuffer(MR_UBYTE* source, MR_UBYTE* dest, MR_ULONG packed_length)
{
	MR_UBYTE*	dest_ptr;
	MR_ULONG	unpacked_length;
	MR_LONG		n_bits;
	MR_LONG		idx;
	MR_ULONG	bytes;
	MR_LONG		to_add;
	MR_ULONG	offset;
	MR_UBYTE	offset_sizes[4];
	MR_ULONG	i;

	// Check for file signature
	if (source[0] != MR_PPID_CHAR_0 ||
		source[1] != MR_PPID_CHAR_1 ||
		source[2] != MR_PPID_CHAR_2 ||
		source[3] != MR_PPID_CHAR_3)
		return(MR_PPDECRUNCH_ERROR);
	
	// Point our global source pointer to the end of the file
	MRPP_source_ptr	=	source + packed_length - 4;
	unpacked_length	=	MRPP_source_ptr[0] << 16 | MRPP_source_ptr[1] << 8 | MRPP_source_ptr[2];
	dest_ptr 		=	dest + unpacked_length;
	MRPP_counter	=	0;
	MRPP_shift_in	=	0;

	// Fetch efficiency array
	offset_sizes[0] =	source[4];
	offset_sizes[1] =	source[5];
	offset_sizes[2] =	source[6];
	offset_sizes[3] =	source[7];	

	// skip bits (last byte of compressed data holds number of bits to trash)
	MRPPGetBits(MRPP_source_ptr[3]);

	// do it forever, i.e., while the whole file isn't unpacked
	while (1)
	{
		// copy some bytes from the source anyway
		if (MRPPGetBits(1) == 0)
		{
			bytes = 0;
			do 
			{
				to_add = MRPPGetBits(2);
				bytes += to_add;
			} while (to_add == 3);

			for (i = 0; i <= bytes; i++)
				*--dest_ptr = MRPPGetBits(8);

			if (dest_ptr <= dest)
				return(MR_PPDECRUNCH_OK);
		}
		
		// decode what to copy from the destination file 
		idx = MRPPGetBits(2);
		n_bits = offset_sizes[idx];

		// bytes to copy 
		bytes = idx+1;
		if (bytes == 4)	// 4 means >=4
		{
			// and maybe a bigger offset 
			if (MRPPGetBits(1) == 0)
				offset = MRPPGetBits(7);
			else
				offset = MRPPGetBits(n_bits);

			do
			{
				to_add = MRPPGetBits(3);
				bytes += to_add;
			}
			while (to_add == 7);
		}
		else
		{
			offset = MRPPGetBits(n_bits);
		}

		for (i = 0; i <= bytes; i++)
		{
			dest_ptr[-1] = dest_ptr[offset];
			dest_ptr--;
		}

		if (dest_ptr <= dest)
			return(MR_PPDECRUNCH_OK);
	}
}



/******************************************************************************
*%%%% MRPPGetBits
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG result = MRPPGetBits(MR_ULONG num)
*
*	FUNCTION	Returns 'num' bits from the source area
*
*	INPUTS		num		-		Number of bits of data we want to pull from source
*
*	RESULT		result	-		Data from source file
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_ULONG	MRPPGetBits(MR_ULONG num)
{
	MR_ULONG	result = 0;

	while(num)
		{
		if (num < MRPP_counter)
			{
			MRPP_counter -= num;
			result <<= num;
			result = result | (MRPP_shift_in >> (32-num));
			MRPP_shift_in = (MRPP_shift_in << num);
			num = 0;
			}
		else
			{
			result = (MRPP_shift_in >> (32-MRPP_counter));
			num -= MRPP_counter;
			MRPP_counter = 32;
			MRPP_shift_in = MRPP_rev_table[*--MRPP_source_ptr];
			MRPP_shift_in = (MRPP_shift_in << 8) | MRPP_rev_table[*--MRPP_source_ptr];
			MRPP_shift_in = (MRPP_shift_in << 8) | MRPP_rev_table[*--MRPP_source_ptr];
			MRPP_shift_in = (MRPP_shift_in << 8) | MRPP_rev_table[*--MRPP_source_ptr];
			}
		}
	
	return(result);
}
												 

