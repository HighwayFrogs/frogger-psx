#//*******************************************************************************
#//*%%%% mr_bin.s
#//*------------------------------------------------------------------------------
#//*
#//*	Data that is linked into the project memory map
#//*
#//*	CHANGED		PROGRAMMER		REASON
#//*  	-------  	---------- 	 	------
#//*	20.5.96		Dean Ashton		Created
#//*	23.23.11	Kneesnap		Ported to GNU AS Syntax
#//*
#//*%%%**************************************************************************/

		.data

		.align 4
		.global MRAcos_table
MRAcos_table:
		.incbin	"../API.BIN/acos_le.dat"

		.align 4
		.global MRCd_error_pp
MRCd_error_pp:
		.incbin	"../API.BIN/cd_error.pp"

		.global MRCd_error_len
		.type MRCd_error_len, @object
MRCd_error_len:
		.int MRCd_error_len - MRCd_error_pp
