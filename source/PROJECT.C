/******************************************************************************
*%%%% project.c
*------------------------------------------------------------------------------
*
*	Project information that's really destined for use by the Millennium API.
*	The reason it's here is so the API isn't dependent on any project related
*	gubbins.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	23.5.96		Dean Ashton		Created
*	24.4.97		Martin Kift		Added win95 default table... not sure if neeed tho
*
*%%%**************************************************************************/

#include	"project.h"

// Standard controller remapping tables

#ifdef PSX
MR_USHORT	FRInput_default_map[MR_MAX_INPUT_ACTIONS+1] =
				{

				// PlayStation H/W						Game				Debug

				MR_IPPSX_LEFT,							// FR_LEFT		/	FRR_LEFT
				MR_IPPSX_RIGHT,							// FR_RIGHT		/	FRR_RIGHT
				MR_IPPSX_UP,							// FR_UP		/	FRR_UP
				MR_IPPSX_DOWN,							// FR_DOWN		/	FRR_DOWN

				MR_IPPSX_CROSS,							// FR_FIRE		/	FRR_BLUE
	
				MR_IPPSX_START,							// FR_START		/	FRR_START
	
				MR_IPPSX_SELECT,						// FR_SELECT	/	FRR_SELECT
				MR_IPPSX_SQUARE,						// <UNDEFINED	/	FRR_PINK
				MR_IPPSX_CIRCLE,						// <UNDEFINED>	/	FRR_RED
				MR_IPPSX_TRIANGLE,						// <UNDEFINED>	/	FRR_GREEN
				MR_IPPSX_L1,							// <UNDEFINED>	/	FRR_LEFT_1
				MR_IPPSX_L2,							// <UNDEFINED>	/	FRR_LEFT_2
				MR_IPPSX_R1,							// <UNDEFINED>	/	FRR_RIGHT_1
				MR_IPPSX_R2,							// <UNDEFINED>	/	FRR_RIGHT_2

				NULL									// List terminator
				};
#else
MR_ULONG	FRInput_default_map[MR_MAX_INPUT_ACTIONS+1] =
				{
				// Win95 H/W							Game				Debug
				MR_IPPC_LEFT,							// FR_LEFT		/	FRR_LEFT
				MR_IPPC_RIGHT,							// FR_RIGHT		/	FRR_RIGHT
				MR_IPPC_UP,								// FR_UP		/	FRR_UP
				MR_IPPC_DOWN,							// FR_DOWN		/	FRR_DOWN
				MR_IPPC_FIRE1,							// FR_REPEAT	/	FRR_BLUE
				MR_IPPC_FIRE2,							// FR_START		/	FRR_START
				MR_IPPC_FIRE3,							// FR_SELECT	/	FRR_SELECT
				MR_IPPC_FIRE4,							// FR_SUPERJUMP	/	FRR_PINK
				MR_IPPC_FIRE5,							// <UNDEFINED>	/	FRR_RED
				MR_IPPC_FIRE6,							// <UNDEFINED>	/	FRR_GREEN
				MR_IPPC_FIRE7,							// <UNDEFINED>	/	FRR_LEFT_1
				MR_IPPC_FIRE8,							// <UNDEFINED>	/	FRR_LEFT_2
				MR_IPPC_FIRE9,							// <UNDEFINED>	/	FRR_RIGHT_1
				MR_IPPC_FIRE10,							// <UNDEFINED>	/	FRR_RIGHT_2
				NULL									// List terminator
				};

MR_ULONG FRInput_default_key_map1[]=	// these map exactly to the above
{
				MRIK_LEFT,								// FR_LEFT					/	FRR_LEFT
				MRIK_RIGHT,								// FR_RIGHT					/	FRR_RIGHT
				MRIK_UP,								// FR_UP					/	FRR_UP
				MRIK_DOWN,								// FR_DOWN					/	FRR_DOWN
				MRIK_RETURN,							// FR_SUPERJUMP				/	FRR_BLUE
				MRIK_RCONTROL,							// FR_TONGUE				/	FRR_START
				MRIK_RSHIFT,							// FR_CROAK					/	FRR_SELECT
				MRIK_SPACE,								// FR_SUPERJUMP				/	FRR_PINK
				MRIK_C,									// <UNDEFINED>				/	FRR_RED
				MRIK_D,									// <UNDEFINED>				/	FRR_GREEN
				MRIK_APOSTROPHE,						// FR_CAMERA_CLOCKWISE		/	FRR_LEFT_1
				MRIK_SEMICOLON,							// FR_CAMERA_ANTICLOCKWISE	/	FRR_LEFT_2
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									//<UNDEFINED>				/	FRR_RIGHT_2
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				0xffffffff,
};

MR_ULONG FRInput_default_key_map2[]=	// these map exactly to the above
{
				MRIK_N,									// FR_LEFT					/	FRR_LEFT
				MRIK_M,									// FR_RIGHT					/	FRR_RIGHT
				MRIK_G,									// FR_UP					/	FRR_UP
				MRIK_B,									// FR_DOWN					/	FRR_DOWN
				MRIK_F,									// FR_SUPERJUMP				/	FRR_BLUE
				MRIK_COMMA,								// FR_TONGUE				/	FRR_START
				MRIK_SPACE,								// FR_CROAK					/	FRR_SELECT
				MRIK_SPACE,								// FR_SUPERJUMP				/	FRR_PINK
				MRIK_C,									// <UNDEFINED>				/	FRR_RED
				MRIK_D,									// <UNDEFINED>				/	FRR_GREEN
				MRIK_H,									// FR_CAMERA_CLOCKWISE		/	FRR_LEFT_1
				MRIK_J,									// FR_CAMERA_ANTICLOCKWISE	/	FRR_LEFT_2
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									//<UNDEFINED>				/	FRR_RIGHT_2
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				0xffffffff,
};

MR_ULONG FRInput_default_key_map3[]=	// these map exactly to the above
{
				MRIK_E,									// FR_LEFT					/	FRR_LEFT
				MRIK_R,									// FR_RIGHT					/	FRR_RIGHT
				MRIK_2,									// FR_UP					/	FRR_UP
				MRIK_W,									// FR_DOWN					/	FRR_DOWN
				MRIK_1,									// FR_SUPERJUMP				/	FRR_BLUE
				MRIK_T,									// FR_TONGUE				/	FRR_START
				MRIK_TAB,								// FR_CROAK					/	FRR_SELECT
				MRIK_SPACE,								// FR_SUPERJUMP				/	FRR_PINK
				MRIK_C,									// <UNDEFINED>				/	FRR_RED
				MRIK_D,									// <UNDEFINED>				/	FRR_GREEN
				MRIK_3,									// FR_CAMERA_CLOCKWISE		/	FRR_LEFT_1
				MRIK_4,									// FR_CAMERA_ANTICLOCKWISE	/	FRR_LEFT_2
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									//<UNDEFINED>				/	FRR_RIGHT_2
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				0xffffffff,
};

MR_ULONG FRInput_default_key_map4[]=	// these map exactly to the above
{
				MRIK_O,									// FR_LEFT					/	FRR_LEFT
				MRIK_P,									// FR_RIGHT					/	FRR_RIGHT
				MRIK_I,									// FR_UP					/	FRR_UP
				MRIK_O,									// FR_DOWN					/	FRR_DOWN
				MRIK_7,									// FR_SUPERJUMP				/	FRR_BLUE
				MRIK_LBRACKET,							// FR_TONGUE				/	FRR_START
				MRIK_Y,									// FR_CROAK					/	FRR_SELECT
				MRIK_SPACE,								// FR_SUPERJUMP				/	FRR_PINK
				MRIK_C,									// <UNDEFINED>				/	FRR_RED
				MRIK_D,									// <UNDEFINED>				/	FRR_GREEN
				MRIK_9,									// FR_CAMERA_CLOCKWISE		/	FRR_LEFT_1
				MRIK_0,									// FR_CAMERA_ANTICLOCKWISE	/	FRR_LEFT_2
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									//<UNDEFINED>				/	FRR_RIGHT_2
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_P,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				MRIK_D,									// <UNDEFINED>				/	FRR_RIGHT_1
				0xffffffff,
};

#endif

MR_MOF*		Map_mof_ptrs[PROJECT_MAX_THEME_MOFS + PROJECT_MAX_GEN_MOFS];
MR_ULONG	Map_mof_index;


/******************************************************************************
*%%%% FRFileProcess_VLO
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	FRFileProcess_VLO(
*						MR_ULONG	resource_id,
*						MR_ULONG*	resource_addr,
*						MR_ULONG	resource_size);
*
*	FUNCTION	Callback for VLO processing
*
*	INPUTS		resource_id		-	ID of resource to process
*				resource_addr	-	Address of resource to process
*				resource_size	-	Size of resource to process
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_BOOL	FRFileProcess_VLO(	MR_ULONG	resource_id,
							MR_ULONG* 	resource_addr,
							MR_ULONG 	resource_size)
{
	MRProcessVLO(resource_id, resource_addr);
	return MR_SUCCESS;
}


/******************************************************************************
*%%%% FRFileProcess_MOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	FRFileProcess_MOF(
*						MR_ULONG	resource_id,
*						MR_ULONG*	resource_addr,
*						MR_ULONG	resource_size);
*
*	FUNCTION	Callback for MOF processing
*
*	INPUTS		resource_id		-	ID of resource to process
*				resource_addr	-	Address of resource to process
*				resource_size	-	Size of resource to process
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_BOOL	FRFileProcess_MOF(	MR_ULONG	resource_id,
							MR_ULONG* 	resource_addr,
							MR_ULONG 	resource_size)
{
	MRResolveMOF((MR_MOF*)resource_addr);
	MRResolveMOFTextures((MR_MOF*)resource_addr);
	MRPatchMOFTranslucency((MR_MOF*)resource_addr, TRUE);
	return MR_SUCCESS;
}


/******************************************************************************
*%%%% FRFileProcess_MAPMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	FRFileProcess_MAPMOF(
*						MR_ULONG	resource_id,
*						MR_ULONG*	resource_addr,
*						MR_ULONG	resource_size);
*
*	FUNCTION	Same as above, but for map MOFs: must set up array of ptrs
*
*	INPUTS		resource_id		-	ID of resource to process
*				resource_addr	-	Address of resource to process
*				resource_size	-	Size of resource to process
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	16.04.97	Tim Closs		Created
*	10.07.97	Gary Richards	Updated to allow us have DUMMY entries in the WAD file.
*
*%%%**************************************************************************/

MR_BOOL	FRFileProcess_MAPMOF(	MR_ULONG	resource_id,
								MR_ULONG* 	resource_addr,
								MR_ULONG 	resource_size)
{
	MR_UBYTE	*ptr;

	ptr = (MR_UBYTE*)resource_addr;
	if  ( (*ptr == 'D') && (*(ptr+1) == 'U') && (*(ptr+2) == 'M') )
		{
		Map_mof_ptrs[Map_mof_index++] = NULL;		//(MR_MOF*)resource_addr;
		}
	else
		{
   		MRResolveMOF((MR_MOF*)resource_addr);
		MRResolveMOFTextures((MR_MOF*)resource_addr);
		MRPatchMOFTranslucency((MR_MOF*)resource_addr, TRUE);
		Map_mof_ptrs[Map_mof_index++] = (MR_MOF*)resource_addr;
		}

	return MR_SUCCESS;
}

#ifdef WIN95

/******************************************************************************
*%%%% DummyGetAsyncStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG	DummyGetAsyncStatus(MR_LONG)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.08.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_LONG	DummyGetAsyncStatus(MR_LONG	dummy)
{
	return 0;
}

#endif // WIN95
