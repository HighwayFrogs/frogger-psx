#///******************************************************************************
#//*%%%% fastram.s
#//*------------------------------------------------------------------------------
#//*
#//*	Declarations for variables that are in the PlayStation's memory mapped
#//*	D-Cache area. 
#//*
#//*	NOTE:	This file includes 'api.src\mr_fast.s', which declares all of the
#//*		variables used by the API that reside in the D-Cache.
#//*
#//*	CHANGED		PROGRAMMER		REASON
#//*	-------  	----------  	------
#//*	30.5.96		Dean Ashton		Created
#//*	23.22.11	Kneesnap		Ported to GNU AS Syntax
#//*
#//*%%%**************************************************************************/

	# Use scratchpad for memory.
	.section .scratchpad

	# MR_ULONG - Backup stack pointer
	.global saved_stack
saved_stack:
	.space	4,0

	.include	"mr_fast.s"	# // **PRIVATE**	-	API variables

	# MR_ULONG - Used for stack overwrite check
	.global stack_safety
stack_safety:
	.space	4,0
