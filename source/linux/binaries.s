#///******************************************************************************
#//*%%%% binaries.s
#//*------------------------------------------------------------------------------
#//*
#//*	Files that are to be linked into the project.
#//*
#//*	CHANGED		PROGRAMMER		REASON
#//* 	-------  	----------  	------
#//*	20.05.96	Dean Ashton		Created
#//*	23.22.11	Kneesnap		Ported to GNU AS Syntax
#//*
#//*%%%**************************************************************************/


	.data

	.align 4
	.global frogpsx_mwi
frogpsx_mwi:
	.incbin	"../../merge/FROGPSX.MWI"

	.align 4
	.global card_image
card_image:
	.incbin	"../../binaries/FROGSAVE.TIM"