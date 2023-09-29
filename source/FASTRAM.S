;///******************************************************************************
;//*%%%% fastram.s
;//*------------------------------------------------------------------------------
;//*
;//*	Declarations for variables that are in the PlayStation's memory mapped
;//*	D-Cache area. 
;//*
;//*	NOTE:	This file includes 'api.src\mr_fast.s', which declares all of the
;//*		variables used by the API that reside in the D-Cache.
;//*
;//*	CHANGED		PROGRAMMER		REASON
;//*	-------  	----------  		------
;//*	30.5.96		Dean Ashton		Created
;//*
;//*%%%**************************************************************************/


FASTRAM_ADDR	equ	$1f800000		;// Address of Scratch RAM
		PUBLIC	on
text		group
		SECTION	.text

		
		rsset	FASTRAM_ADDR

saved_stack	rw	1			;// MR_ULONG	-	Backup stack pointer




		include	"api.src\mr_fast.s"	;// **PRIVATE**	-	API variables
stack_safety	rw	1			;// MR_ULONG	-	Used for stack overwrite check

		rsreset
