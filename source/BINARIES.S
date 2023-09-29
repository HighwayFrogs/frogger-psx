;///******************************************************************************
;//*%%%% binaries.s
;//*------------------------------------------------------------------------------
;//*
;//*	Files that are to be linked into the project.
;//*
;//*	CHANGED		PROGRAMMER		REASON
;//* 	-------  	----------  		------
;//*	20.5.96		Dean Ashton		Created
;//*
;//*%%%**************************************************************************/


		PUBLIC	on

data		group	
		SECTION	.data

		cnop	0,4
frogpsx_mwi	incbin	"..\MERGE\FROGPSX.MWI"
		cnop	0,4
card_image	incbin	"..\BINARIES\FROGSAVE.TIM"
		end
















