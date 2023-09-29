;//*******************************************************************************
;//*%%%% mr_bin.s
;//*------------------------------------------------------------------------------
;//*
;//*	Data that is linked into the project memory map
;//*
;//*	CHANGED		PROGRAMMER		REASON
;//*  	-------  	---------- 	 	------
;//*	20.5.96		Dean Ashton		Created
;//*
;//*%%%**************************************************************************/


		PUBLIC	on

data		group	
		SECTION	.data

		cnop	0,4
MRAcos_table	incbin	"..\API.BIN\ACOS_LE.DAT"

		cnop	0,4
MRCd_error_pp	incbin	"..\API.BIN\CD_ERROR.PP"
MRCd_error_len	dw	*-MRCd_error_pp
		end














