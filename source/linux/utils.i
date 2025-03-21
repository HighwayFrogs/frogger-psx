#/******************************************************************************
#/*%%%% utils.i
#/*------------------------------------------------------------------------------
#/*
#/*	Contains utilities for handwritten assembly in GNU Assembler syntax.
#/*
#/*	CHANGED		PROGRAMMER		REASON
#/*	-------  	----------  	------
#/*	19.03.25	Kneesnap		Created
#/*
#/*%%%**************************************************************************/

# -------------------------------------------------------------------------------
# Struct Definition Utilities
# -------------------------------------------------------------------------------

# The original Frogger handwritten assembly files were written for ASMPSX.EXE, which was a proprietary SN Systems assembler.
# Our conversions of them to GNU Assembler syntax need some macros to help replicate original conventions.
# They would declare structs in their assembly like the following:
#// ---- SVECTOR ----
#				rsreset
#SVEC_vx			rh	1
#SVEC_vy			rh	1
#SVEC_vz			rh	1
#SVEC_pad			rh	1	
#sizeof_SVEC		rb	0

# rsreset would presumably reset the location counter to 0, and they would just declare variables, and then when you'd use for example SVEC_vz, it would evaluate to the position in the struct that SVEC_vz is located at.
# The following allow using a similar declarative approach to structs:

.macro new_struct
.set INTERNAL_STRUCT_SIZE_COUNTER, 0
.endm

.macro struct_entry name, size
.set \name, INTERNAL_STRUCT_SIZE_COUNTER
.set INTERNAL_STRUCT_SIZE_COUNTER, INTERNAL_STRUCT_SIZE_COUNTER + \size
.endm

# The following is an alternative approach which appears to work, but I didn't test resetting the position. ". = 0" or ".org 0"
# It has been included just in case it may be useful.
#.macro struct_entry name, size
#.section .discard_structdefs
#\name:
#	.space \size
#.section .text
#.endm

# The SVECTOR example seen previously would now be written as:
#new_struct
#struct_entry SVEC_vx, 2
#struct_entry SVEC_vy, 2
#struct_entry SVEC_vz, 2
#struct_entry SVEC_pad, 2
#struct_entry sizeof_SVEC, 0
