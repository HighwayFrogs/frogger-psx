/******************************************************************************
*%%%% loadsave.c
*------------------------------------------------------------------------------
*
*	Routines for memory card \ registry access.
*	Generally, startup, update and shutdown.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	07.07.97	William Bell	Created
*
*%%%**************************************************************************/

#include "mr_all.h"
#include "loadsave.h"
#include "options.h"
#include "memcard.h"
#include "gamefont.h"
#include "gamesys.h"
#include "project.h"
#include "sound.h"
#include "tempopt.h"
#include "ent_gen.h"
#include "frog.h"
#include "camera.h"
#include "select.h"


#ifdef WIN95
#pragma warning (disable : 4761)
#endif

MR_TEXTURE*			LS_title_texture_ptr;									// Ptr to title texture
MR_TEXTURE*			LS_selection_texture_ptrs[MAX_NUM_SELECTIONS];			// Ptr to selection textures
MR_TEXTURE*			LS_message_texture_ptr;									// Ptr to message texture

MR_2DSPRITE*		LS_title_sprite_ptr;									// Ptr to generic title sprite
MR_2DSPRITE*		LS_selection_sprite_ptr[MAX_NUM_SELECTIONS];			// Ptr to generic selection sprites
MR_2DSPRITE*		LS_message_sprite_ptr;									// Ptr to generic message sprite

MR_XY				LS_title_sprite_pos;									// Position of generic title sprite
MR_XY				LS_selection_sprite_pos[MAX_NUM_SELECTIONS];			// Positions of selection sprites
MR_XY				LS_message_sprite_pos;									// Position of generic message sprite

MR_ULONG			LS_num_selections;										// Number of selections available
MR_LONG				LS_selection;											// Generic selection ( current selection )
MR_ULONG			LS_selection_dir;										// Direction of selection ( up-down / left-right )
MR_ULONG			LS_wait;												// Generic wait ( delay count )
MR_ULONG			LS_card_number;											// Number of card to load\save from

MR_ULONG			LS_load_mode;											// Operation mode for load
MR_ULONG			LS_save_mode;											// Operation mode for save
MR_ULONG			LS_check_mode;											// Operation mode for check saves
MR_ULONG			LS_select_mode;											// Operation mode for select screen
MR_ULONG			LS_message_mode;										// Operation mode for message screen
MR_ULONG			LS_exit_mode;											// Exit of function
MR_ULONG			LS_delay_timer;											// Ensure stable display before blocking functions

#ifdef PSX
MR_UBYTE*			LS_matrices;											// Ptr to memory block allocated to hold matrices for models
MR_MAT*				LS_extras_matrix_ptr[2];								// Ptr to each models matrix
MR_OBJECT*			LS_extras_object_ptr[2];								// Ptr to each object
MR_MESH_INST*		LS_extras_mesh_inst_ptr[2];
MR_ULONG			LS_extras_resource_id[2] =								// Models used to display memory cards
					{
					RES_OPT_CARD_1_XMR,
					RES_OPT_CARD_2_XMR,
					};
MR_SHORT			LS_memory_card_rotation1;
MR_SHORT			LS_memory_card_rotation2;
#endif

//---------------------------------------------------------------------------

MR_ULONG			LoadSave_memory_card_rot = 0;			// Current rotation of memory card model
MR_OBJECT*			Memory_card_object_ptr[2];

// Read from memory card ----------------------------------

MR_USHORT	Read_status;					// Status of operation for read memory card screen

#ifdef WIN95	// Windows Specific code ------------------------------------

HKEY			Save_key;				// Handle to open "save" registry key
MR_BOOL			Save_data_flag;			// Flag to indicate whether save data is available

#else			// PSX Specific code ----------------------------------------

MR_BOOL			Card0_present;			// Flag to indicate whether card 0 available
MR_BOOL			Card1_present;			// Flag to indicate whether card 1 available
MR_BOOL			Game0_present;			// Flag to indicate whether game 0 available
MR_BOOL			Game1_present;			// Flag to indicate whether game 1 available

#endif			// WIN95

MR_USHORT	Load_status;					// Status of operation for load screen
MR_USHORT	Save_status;					// Status of operation for save screen

CONTROL_OPTIONS	Load_data;					// Load data!!!
CONTROL_OPTIONS	Save_data;					// Save data!!!


#ifdef WIN95	// Windows specific code ------------------------------------

/******************************************************************************
*%%%% OptionsGetRegistryStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsGetRegistryStatus(MR_VOID)
*
*	FUNCTION	Gets the status of the registry and game saves for the options
*				screens.  Also opens the registry if the information is present.
*
*	NOTES		This function is for windows only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID OptionsGetRegistryStatus(MR_VOID)
{

	// Locals
	MR_LONG		reg_result;			// Result of call to registry

	// Flag key as not available
	Save_data_flag = FALSE;

	// Open key for control options
	reg_result = RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\Millennium Interactive\\Frogger\\Save",0,KEY_ALL_ACCESS,&Save_key);

	// Error ?
	if ( reg_result == ERROR_SUCCESS )
		// No ... flag options save data as present
		Save_data_flag = TRUE;

}

/******************************************************************************
*%%%% OptionsCloseRegistry
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsCloseRegistry(MR_VOID)
*
*	FUNCTION	Closes the registry key that was opened by a call to
*				OptionsGetRegistryStatus.
*
*	NOTES		This function is for windows only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID OptionsCloseRegistry(MR_VOID)
{

	// Was save data present ?
	if ( Save_data_flag == TRUE )
		// Yes ... close key
		RegCloseKey(Save_key);

}

#else	// PSX Specific code ------------------------------------------------

/******************************************************************************
*%%%% OptionsGetCardStatus
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsGetCardStatus(MR_VOID)
*
*	FUNCTION	Gets the status of the memory cards and game saves for the options
*				screens.
*
*	NOTES		This function is for the playstation only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID OptionsGetCardStatus(MR_VOID)
{
	MR_ULONG	card_status;


	// Flag cards and games as not present
	Card0_present 	= FALSE;
	Card1_present 	= FALSE;
	Game0_present 	= FALSE;
	Game1_present 	= FALSE;
	card_status		= NULL;

	// Get status of memory cards
#ifdef	PSX_CARD
	MRDisablePollhost();
	card_status = Card_test_cards();
	MREnablePollhost();
#endif	// PSX_CARD

	// Card available in port 0 ?
	if ( card_status & TC_FOUND_CARD_0 )
		{
		// Yes ... flag card as available
		Card0_present = TRUE;
		// Was there a save available on port 0 ?
		if ( card_status & TC_FOUND_GAME_0 )
			{
			// Yes ... flag save as available
			Game0_present = TRUE;
			}
		}

	// Card available in port 1 ?
	if ( card_status & TC_FOUND_CARD_1 )
		{
		// Yes ... flag card as available
		Card1_present = TRUE;
		// Was there a save available on port 1 ?
		if ( card_status & TC_FOUND_GAME_1 )
			{
			// Yes ... flag save as available
			Game1_present = TRUE;
			}
		}

}

#endif	// WIN95

#ifdef WIN95	// Windows specific code ------------------------------------

/******************************************************************************
*%%%% OptionsSaveSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsSaveSaveData(MR_VOID)
*
*	FUNCTION	Saves game information to registry.  Completes save data structure.
*				Opens exisiting registry key, if data already saved to registry or
*				creates the key if first time save.  Sets registry values and closes
*				key.
*
*	NOTES		This code is for windows only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID OptionsSaveSaveData(MR_VOID)
{

	// Locals
	HKEY		save_key;			// Registry key opened for writing!!!

	// Encode save data
	EncodeSaveData();

	// Open key ( creating if currently not present )
	RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\Millennium Interactive\\Frogger\\Save",0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&save_key,NULL);

	// Save options settings
	RegSetValueEx(save_key,"Music Volume",0,REG_DWORD,(unsigned char *)&Save_data.co_music_volume,2);
	RegSetValueEx(save_key,"Sound Volume",0,REG_DWORD,(unsigned char *)&Save_data.co_sound_volume,2);
	RegSetValueEx(save_key,"Language",0,REG_DWORD,(unsigned char *)&Save_data.co_language,2);

	// Save controller data
	RegSetValueEx(save_key,"Device ID",0,REG_DWORD,(unsigned char *)&Save_data.co_device_id[0],2*4);
	RegSetValueEx(save_key,"Hop Up",0,REG_DWORD,(unsigned char *)&Save_data.co_hop_up[0],2*4);
	RegSetValueEx(save_key,"Hop Down",0,REG_DWORD,(unsigned char *)&Save_data.co_hop_down[0],2*4);
	RegSetValueEx(save_key,"Hop Left",0,REG_DWORD,(unsigned char *)&Save_data.co_hop_left[0],2*4);
	RegSetValueEx(save_key,"Hop Right",0,REG_DWORD,(unsigned char *)&Save_data.co_hop_right[0],2*4);
	RegSetValueEx(save_key,"Croak",0,REG_DWORD,(unsigned char *)&Save_data.co_croak[0],2*4);
	RegSetValueEx(save_key,"Super Tongue",0,REG_DWORD,(unsigned char *)&Save_data.co_super_tongue[0],2*4);
	RegSetValueEx(save_key,"Super Jump",0,REG_DWORD,(unsigned char *)&Save_data.co_super_jump[0],2*4);
	RegSetValueEx(save_key,"Rotate Left",0,REG_DWORD,(unsigned char *)&Save_data.co_rotate_left[0],2*4);
	RegSetValueEx(save_key,"Rotate Right",0,REG_DWORD,(unsigned char *)&Save_data.co_rotate_right[0],2*4);

	// Save High Scores
	RegSetValueEx(save_key,"Game high scores",0,REG_BINARY,(unsigned char *)&Save_data.co_game_high_score[0],sizeof(HIGH_SCORE_ENTRY)*10);
	RegSetValueEx(save_key,"Level high scores",0,REG_BINARY,(unsigned char *)&Save_data.co_level_high_scores[0],sizeof(HIGH_SCORE_ENTRY)*60*3);

	// Save game status
	RegSetValueEx(save_key,"Selectable Levels",0,REG_DWORD,(unsigned char *)&Save_data.co_selectable_levels,2*60);
	RegSetValueEx(save_key,"Number Of Golden Frogs",0,REG_DWORD,(unsigned char *)&Save_data.co_number_of_golden_frogs,2);

	// Close key
	RegCloseKey(save_key);

}

#else			// PSX Specific code ----------------------------------------

/******************************************************************************
*%%%% OptionsCheckCardFull
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL		OptionsCheckCardFull(
*									MR_ULONG of_card_no	)
*
*	FUNCTION	Checks if a card is full.
*
*	INPUTS		of_card_no		- Number of card to check if full
*
*	RETURN		TRUE			- Card IS full
*				FALSE			- Card is NOT full
*
*	NOTES		This code is for PSX only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_BOOL	OptionsCheckCardFull(MR_ULONG of_card_no)
{

	// Get info about space
#ifdef	PSX_CARD

	// Locals
	MR_ULONG	card_info;

	MRDisablePollhost();
	card_info = Card_get_info(of_card_no,TRUE);
	MREnablePollhost();

	// Card full ?
	if ( card_info & CI_CARD_FULL )
		{
		// Yes ... 
		return TRUE;
		}
	else
		{
		// No ... 
		return FALSE;
		}
#else

	// Pretend cards have space
	return FALSE;

#endif	// PSX_CARD

}

/******************************************************************************
*%%%% OptionsFormatCard
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID		OptionsFormatCard(
*									MR_ULONG of_card_no	)
*
*	FUNCTION	Formats memory card ready for save game information.
*
*	INPUTS		of_card_no		- Number of card to format
*
*	RETURN		MR_ULONG		- Result of format
*
*	NOTES		This code is for PSX only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_ULONG OptionsFormatCard(MR_ULONG of_card_no)
{

#ifdef	PSX_CARD

	// Locals
	MR_ULONG	format_result;

	MRDisablePollhost();
	format_result = Card_format(of_card_no);
	MREnablePollhost();

	// Return result of format
	return format_result;

#else

	// Return format ok!
	return CFC_FORMAT_OK;

#endif	// PSX_CARD

}

/******************************************************************************
*%%%% OptionsSaveSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	OptionsSaveSaveData(
*									MR_ULONG sd_card_no	)
*
*	FUNCTION	Saves game information to memory card.
*
*	INPUTS		sd_card_no		- Number of card to save to
*
*	RESULT		MR_ULONG		- Return code
*
*	NOTES		This code is for PSX only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_ULONG OptionsSaveSaveData(MR_ULONG sd_card_no)
{

#ifdef	PSX_CARD
	// Locals
	MR_ULONG		save_status = NULL;
#endif

	// Compile data
	EncodeSaveData();

	// Save data
#ifdef	PSX_CARD
	MRDisablePollhost();
	save_status = Card_save_file((MR_UBYTE*)&Save_data,sizeof(Save_data),sd_card_no);
	MREnablePollhost();

	// Return code
	return save_status;

#else

	// Return ok!!!
	return CSG_SAVE_OK;

#endif	// PSX_CARD
}
#endif	// WIN95


#ifdef WIN95	// Windows specific code ------------------------------------

/******************************************************************************
*%%%% OptionsLoadSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsLoadSaveData(MR_VOID)
*
*	FUNCTION	Loads save data from registry.
*
*	NOTES		This is for windows only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID OptionsLoadSaveData(MR_VOID)
{

	// Locals
	MR_ULONG		entry_size;				// Size of registry entry in bytes
	MR_LONG			entry_type;				// Type of value got from registry

	// Load game status
	entry_size = 2*60;
	RegQueryValueEx(Save_key,"Selectable Levels",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_selectable_levels[0],(LPDWORD)&entry_size);
	entry_size = 2;
	RegQueryValueEx(Save_key,"Number Of Golden Frogs",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_number_of_golden_frogs,(LPDWORD)&entry_size);

	// Load high scores
	entry_size = sizeof(HIGH_SCORE_ENTRY)*60*3;
	RegQueryValueEx(Save_key,"Level high scores",(LPDWORD)NULL,(LPDWORD)&entry_type,(unsigned char *)&Load_data.co_level_high_scores[0],(LPDWORD)&entry_size);
	entry_size = sizeof(HIGH_SCORE_ENTRY)*10;
	RegQueryValueEx(Save_key,"Game high scores",(LPDWORD)NULL,(LPDWORD)&entry_type,(unsigned char *)&Load_data.co_game_high_score[0],(LPDWORD)&entry_size);

	// Load options
	entry_size = 2;
	RegQueryValueEx(Save_key,"Music Volume",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_music_volume,(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Sound Volume",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_sound_volume,(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Language",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_language,(LPDWORD)&entry_size);
	entry_size = 2*4;
	RegQueryValueEx(Save_key,"Device ID",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_device_id[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Hop Up",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_hop_up[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Hop Down",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_hop_down[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Hop Left",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_hop_left[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Hop Right",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_hop_right[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Croak",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_croak[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Super Tongue",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_super_tongue[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Super Jump",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_super_jump[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Rotate Left",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_rotate_left[0],(LPDWORD)&entry_size);
	RegQueryValueEx(Save_key,"Rotate Right",(LPDWORD)NULL,(LPDWORD)&entry_type,(char *)&Load_data.co_rotate_right[0],(LPDWORD)&entry_size);

	// Decode save data
	DecodeSaveData();

}

#else	// PSX Specific code ------------------------------------------------

/******************************************************************************
*%%%% OptionsLoadSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	OptionsLoadSaveData(
*									MR_ULONG ld_card_no			)
*
*	FUNCTION	Loads save data from memory card.
*
*	INPUTS		ld_card_no			- Number of card to load from.
*
*	RETURN		MR_ULONG			- Status of load
*
*	NOTES		This is for PSX only, hence the ifdef above.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_ULONG OptionsLoadSaveData(MR_ULONG ld_card_no)
{

	// Load save data into Load_data structure!!!
#ifdef	PSX_CARD

	// Locals
	MR_ULONG		load_status;

	MRDisablePollhost();
	load_status = Card_load_file((MR_UBYTE*)&Load_data,sizeof(Load_data),ld_card_no);
	MREnablePollhost();

	// Load ok ?
	if ( load_status == CLG_LOAD_OK )
		// Yes ... decode save data
		DecodeSaveData();

	// Return status of load
	return load_status;

#else

	// Return load ok!
	return CLG_LOAD_OK;

#endif	// PSX_CARD

}

#endif	// WIN95


/******************************************************************************
*%%%% SaveStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SaveStartup(MR_VOID)
*
*	FUNCTION	Start up code for Save screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID SaveStartup(MR_VOID)
{
	// Initialise mode of operation
	LS_save_mode 	= LS_SAVE_MODE_INIT_INIT;
	LS_delay_timer	= 3;

	High_score_view_delayed_request = NULL;

	// Kill the option tune when saving/loading
	ShutdownOptionsMusic();
}

/******************************************************************************
*%%%% SaveUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SaveUpdate(MR_VOID)
*
*	FUNCTION	Update code for Save screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	SaveUpdate(MR_VOID)
{

#ifdef PSX		// PSX Specific code ----------------------------------------

	MR_ULONG	save_status;
	MR_ULONG	format_status;

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();
	HSUpdateFlying();

	if	(
		(High_score_view_delayed_request == OPTIONS_PAGE_OPTIONS) ||
		(Option_page_request == OPTIONS_PAGE_OPTIONS)
		)
		return;

	// According to save mode do ...
	switch ( LS_save_mode )
		{
		// Initialise save --------------------------------------------------
		case LS_SAVE_MODE_INIT_INIT:
			// Wait for camera
			if (!Cameras[0].ca_move_timer)
				{
				if (!(--LS_delay_timer))
					{
					// Set up checking message
					LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_CHECKING][Game_language];
					LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
					LS_message_sprite_pos.y = (Game_display_height>>1);

					// Set up dodgy wait time, because we only want message while we are waiting
					LS_wait = 34;
					LS_message_mode = LS_MESSAGE_MODE_INIT;
					LS_exit_mode = 0;

					// Do dummy message call to display message
					LSMessage();

					// Go on to update
					LS_save_mode = LS_SAVE_MODE_INIT_WAIT;
					}
				}
			break;

		// Wait for "NOW CHECKING" message ----------------------------------
		case LS_SAVE_MODE_INIT_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to load
				LS_save_mode = LS_SAVE_MODE_INIT_CHECK;

			break;

		// Do message card check --------------------------------------------
		case LS_SAVE_MODE_INIT_CHECK:

			// Check card status
			OptionsGetCardStatus();

			// Kill message
			LSMessage();
	
			// Are they any cards ?
			if ( (Card0_present == TRUE) || (Card1_present == TRUE) )
				{
				// Yes ... go to "are you sure?"
				LS_save_mode = LS_SAVE_MODE_SURE_INIT;
				}
			else
				{
				// No ... go to "no cards"
				LS_save_mode = LS_SAVE_MODE_NO_CARDS_INIT;
				}

			break;

		// Initialise "sure?" request ---------------------------------------
		case LS_SAVE_MODE_SURE_INIT:

			// Set up sure selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_SAVE_HS][Game_language];
			LS_title_sprite_pos.x	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0]	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_sprite_pos[0].x 	= (Game_display_width>>2)-(LS_selection_texture_ptrs[0]->te_w>>1);
			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1)+64;

			LS_selection_texture_ptrs[1]	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_sprite_pos[1].x 	= ((Game_display_width>>2)*3)-(LS_selection_texture_ptrs[1]->te_w>>1);
			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 2;
			LS_selection_dir 	= LS_SELECT_DIR_LEFT_AND_RIGHT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Go on to update
			LS_save_mode 		= LS_SAVE_MODE_SURE_UPDATE;
			break;

		// Update "sure?" request -------------------------------------------
		case LS_SAVE_MODE_SURE_UPDATE:

			// Do selection
			LSSelect();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to sure_deinit
				LS_save_mode = LS_SAVE_MODE_SURE_DEINIT;
				}
			else
				break;

		// Deinit "sure?" request -------------------------------------------
		case LS_SAVE_MODE_SURE_DEINIT:

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_save_mode = LS_SAVE_MODE_EXIT;
				// Return
				return;
				}

			// Was selection yes ?
			if ( !LS_selection )
				{
				// Yes ... are there two cards ?
				if ( (Card0_present == TRUE) && (Card1_present == TRUE) )
					{
					// Yes ... go on to select cards
					LS_save_mode = LS_SAVE_MODE_SELECT_CARD_INIT;
					}
				else
					{
					// No ... is first card present ?
					if ( Card0_present == TRUE )
						{
						// Yes ... set card number
						LS_card_number = 0;
						// Is game present on first card ?
						if ( Game0_present == TRUE )
							{
							// Yes ... go on to overwrite
							LS_save_mode = LS_SAVE_MODE_OVERWRITE_INIT;
							}
						else
							{
							// No ... go on to save
							LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
							}
						}
					else
						{
						// No ... set card number
						LS_card_number = 1;
						// Is game present on second card ?
						if ( Game1_present == TRUE )
							{
							// Yes ... go on to overwrite
							LS_save_mode = LS_SAVE_MODE_OVERWRITE_INIT;
							}
						else
							{
							// No ... go on to save
							LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
							}
						}
					}
				}
			else
				{
				// No ... go on to exit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "select card" request ---------------------------------
		case LS_SAVE_MODE_SELECT_CARD_INIT:

			// Set up card selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_SELECT_CARD][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0]	= NULL;
			LS_selection_texture_ptrs[1]	= NULL;

			LS_selection_texture_ptrs[2]	= Options_text_textures[OPTION_TEXT_RETURN][Game_language];
			LS_selection_sprite_pos[2].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[2]->te_w>>1);
			LS_selection_sprite_pos[2].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 3;
			LS_selection_dir 	= LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Show memory card models
			LSCreateMemoryCards();

			// Go on to update
			LS_save_mode 		= LS_SAVE_MODE_SELECT_CARD_UPDATE;

			break;

		// Update "select card" request -------------------------------------
		case LS_SAVE_MODE_SELECT_CARD_UPDATE:

			// Do selection
			LSSelect();

			// Update memory card models
			LSUpdateMemoryCards();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to select_card_deinit
				LS_save_mode = LS_SAVE_MODE_SELECT_CARD_DEINIT;
				}

			break;

		// Deinit "select card" request -------------------------------------
		case LS_SAVE_MODE_SELECT_CARD_DEINIT:

			// Hide memory card models
			LSKillMemoryCards();

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_save_mode = LS_SAVE_MODE_EXIT;
				// Return
				return;
				}

			// Did user choose card ?
			if ( LS_selection < 2 )
				{
				// Yes ... set card number
				LS_card_number = LS_selection;
				// Is it first card ?
				if ( LS_card_number == 0 )
					{
					// Yes ... is there a save here already ?
					if ( Game0_present == TRUE )
						{
						// Yes ... go to overwrite
						LS_save_mode = LS_SAVE_MODE_OVERWRITE_INIT;
						}
					else
						{
						// No ... go to save
						LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
						}
					}
				else
					{
					// No ... is there a save here already ?
					if ( Game1_present == TRUE )
						{
						// Yes ... go to overwrite
						LS_save_mode = LS_SAVE_MODE_OVERWRITE_INIT;
						}
					else
						{
						// No ... go to save
						LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
						}
					}
				}
			else
				{
				// No ... exit now
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise save high score data ----------------------------------
		case LS_SAVE_MODE_SAVE_INIT:

			// Set up saving message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_SAVING][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			// Set up dodgy wait time, because we only want message while we are waiting
			LS_wait = 4;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Do dummy message call to display message
			LSMessage();

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_SAVE_WAIT;

			break;

		// Wait for "NOW SAVING" message ------------------------------------
		case LS_SAVE_MODE_SAVE_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to save
				LS_save_mode = LS_SAVE_MODE_SAVE;

			break;

		// Save high score data ---------------------------------------------
		case LS_SAVE_MODE_SAVE:
			
			// Save
			save_status = OptionsSaveSaveData(LS_card_number);
			
			// Kill message
			LSMessage();

			// According to return from save do ...
			switch ( save_status )
				{
				// Ok ...
				case CSG_SAVE_OK:
					// Go on to success
					LS_save_mode = LS_SAVE_MODE_SUCCESS_INIT;
					break;
				// No card ...
				case CSG_NO_CARD:
					// Go on to no card present
					LS_save_mode = LS_SAVE_MODE_NO_CARD_INIT;
					break;
				// Full ... 
				case CSG_FULL_CARD:
					// Go on to card full
					LS_save_mode = LS_SAVE_MODE_CARD_FULL_INIT;
					break;
				// Save error ...
				case CSG_SAVE_ERROR:
					// Go on to error whilst saving
					LS_save_mode = LS_SAVE_MODE_SAVE_ERROR_INIT;
					break;
				// Unformatted ...
				case CSG_UNFORMATTED:
					// Go on to format card
					LS_save_mode = LS_SAVE_MODE_FORMAT_INIT;
					break;
				// Default ...
				default:
					// Go on to error whilst saving
					LS_save_mode = LS_SAVE_MODE_SAVE_ERROR_INIT;
					break;
				}

			break;

		// Initialise "no card present" message -----------------------------
		case LS_SAVE_MODE_NO_CARD_INIT:

			// Set up "no card" message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_CARD][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_NO_CARD_UPDATE;

			break;

		// Update "no card" message ----------------------------------------
		case LS_SAVE_MODE_NO_CARD_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "save error" message -----------------------------
		case LS_SAVE_MODE_SAVE_ERROR_INIT:

			// Set up "save error" message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_SAVE_FAILED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_SAVE_ERROR_UPDATE;

			break;

		// Update "save error" message ----------------------------------------
		case LS_SAVE_MODE_SAVE_ERROR_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "format error" message -----------------------------
		case LS_SAVE_MODE_FORMAT_ERROR_INIT:

			// Set up "format error" message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_FORMAT_FAILED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_FORMAT_ERROR_UPDATE;

			break;

		// Update "format error" message ----------------------------------------
		case LS_SAVE_MODE_FORMAT_ERROR_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "overwrite?" selection --------------------------------
		case LS_SAVE_MODE_OVERWRITE_INIT:

			// Set up "overwrite?" selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_OVERWRITE][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0] 	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_sprite_pos[0].x 	= (Game_display_width>>2)-(LS_selection_texture_ptrs[0]->te_w>>1);
			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1)+64;

			LS_selection_texture_ptrs[1] 	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_sprite_pos[1].x 	= ((Game_display_width>>2)*3)-(LS_selection_texture_ptrs[1]->te_w>>1);
			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 2;
			LS_selection_dir 	= LS_SELECT_DIR_LEFT_AND_RIGHT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Go on to update
			LS_save_mode 		= LS_SAVE_MODE_OVERWRITE_UPDATE;

			break;

		// Update "overwrite?" selection ------------------------------------
		case LS_SAVE_MODE_OVERWRITE_UPDATE:

			// Update selection
			LSSelect();

			// Has selection been made ?
			if ( LS_exit_mode )
				{
				// Yes ... did player quit ?
				if ( LS_selection == -1 )
					{
					// Yes ... quit now
					LS_save_mode = LS_SAVE_MODE_EXIT;
					// Return
					return;
					}
				// Overwrite ?
				if ( !LS_selection  )
					{
					// Yes ... go on to save
					LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
					}
				else
					{
					// No ... go on to exit
					LS_save_mode = LS_SAVE_MODE_EXIT;
					goto ls_save_mode_exit;
					}
				}

			break;

		// Initialise format ------------------------------------------------
		case LS_SAVE_MODE_FORMAT_INIT:

			// Set up selection for format
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_FORMAT2][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0] 	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_sprite_pos[0].x 	= (Game_display_width>>2)-(LS_selection_texture_ptrs[0]->te_w>>1);
			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1)+64;

			LS_selection_texture_ptrs[1] 	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_sprite_pos[1].x 	= ((Game_display_width>>2)*3)-(LS_selection_texture_ptrs[1]->te_w>>1);
			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 2;
			LS_selection_dir 	= LS_SELECT_DIR_LEFT_AND_RIGHT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Call dummy selection to initialise
			LSSelect();

			// Now reset default selection to NO
			LS_selection		= 1;

			// Go on to update
			LS_save_mode 		= LS_SAVE_MODE_FORMAT_UPDATE;

			break;

		// Update format ----------------------------------------------------
		case LS_SAVE_MODE_FORMAT_UPDATE:

			// Update selection
			LSSelect();

			// Has selection been made ?
			if ( LS_exit_mode )
				{
				// Did player quit ?
				if ( LS_selection == -1 )
					{
					// Yes ... quit now
					LS_save_mode = LS_SAVE_MODE_EXIT;
					// Return
					return;
					}
				// Yes ... did we choose to format ?
				if ( !LS_selection )
					{
					// Yes ... go on to format deinit
					LS_save_mode = LS_SAVE_MODE_FORMAT_MESSAGE_INIT;
					}
				else
					{
					// No ... exit
					LS_save_mode = LS_SAVE_MODE_EXIT;
					goto ls_save_mode_exit;
					}
				}

			break;

		// Initialise format ------------------------------------------------
		case LS_SAVE_MODE_FORMAT_MESSAGE_INIT:

			// Set up loading message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_FORMATTING][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			// Set up dodgy wait time, because we only want message while we are waiting
			LS_wait = 4;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Do dummy message call to display message
			LSMessage();

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_FORMAT_WAIT;

			break;

		// Wait for "NOW LOADING" message -----------------------------------
		case LS_SAVE_MODE_FORMAT_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to format
				LS_save_mode = LS_SAVE_MODE_FORMAT_DEINIT;

			break;

		// Deinit format ----------------------------------------------------
		case LS_SAVE_MODE_FORMAT_DEINIT:

			// Format card
			format_status = OptionsFormatCard(LS_card_number);

			// Kill message
			LSMessage();

			// According to result of format do ...
			switch ( format_status )
				{
				// Ok ... go back to save
				case CFC_FORMAT_OK:
					LS_save_mode = LS_SAVE_MODE_SAVE_INIT;
					break;
				// No card ... go to display no card
				case CFC_NO_CARD:
					LS_save_mode = LS_SAVE_MODE_NO_CARD_INIT;
					break;
				// Format failed ... go to message
				case CFC_FORMAT_FAILED:
					LS_save_mode = LS_SAVE_MODE_FORMAT_ERROR_INIT;
					break;
				// Default ...
				default:
					LS_save_mode = LS_SAVE_MODE_FORMAT_ERROR_INIT;
					break;
				}
			
			break;

		// Initialise "no cards" message ------------------------------------
		case LS_SAVE_MODE_NO_CARDS_INIT:

			// Set up "no cards" message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_CARD][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait 		= 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode 	= 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_NO_CARDS_UPDATE;

			break;

		// Update "no cards" message ----------------------------------------
		case LS_SAVE_MODE_NO_CARDS_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "card full" message -----------------------------------
		case LS_SAVE_MODE_CARD_FULL_INIT:

			// Set up "card full" message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_SPACE][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_CARD_FULL_UPDATE;

			break;

		// Update "card full" message ----------------------------------------
		case LS_SAVE_MODE_CARD_FULL_UPDATE:
			
			// Update message
			LSMessage();

			// Message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to exit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Initialise "succes" message --------------------------------------
		case LS_SAVE_MODE_SUCCESS_INIT:

			// Set up message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_SAVE_OK][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_save_mode = LS_SAVE_MODE_SUCCESS_UPDATE;

			break;

		// Update "success" message -----------------------------------------
		case LS_SAVE_MODE_SUCCESS_UPDATE:

			// Update message
			LSMessage();

			// Message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to exit
				LS_save_mode = LS_SAVE_MODE_EXIT;
				goto ls_save_mode_exit;
				}

			break;

		// Deinit save ------------------------------------------------------
		case LS_SAVE_MODE_EXIT:
	ls_save_mode_exit:;
			// Return to options
			High_score_view_delayed_request = OPTIONS_PAGE_OPTIONS;

			// Start moving camera NOW
			OptionsCameraMoveToOptions();
			High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
			break;
		}
#else			// WIN95 Specific code --------------------------------------

	// According to save mode do ...
	switch ( LS_save_mode )
		{

		// Initialise save --------------------------------------------------
		case LS_SAVE_MODE_INIT_INIT:
			break;

		}

#endif			// End platform specific code -------------------------------

}

/******************************************************************************
*%%%% SaveShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SaveShutdown(MR_VOID)
*
*	FUNCTION	Shut down code for Save screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID SaveShutdown(MR_VOID)
{
	// Re-start music when out of load/save.
	PlayOptionsMusic();
}

/******************************************************************************
*%%%% LoadStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LoadStartup(MR_VOID)
*
*	FUNCTION	Start up code for Load screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LoadStartup(MR_VOID)
{
	// Initialise mode of operation
	LS_load_mode 	= LS_LOAD_MODE_INIT_INIT;
	LS_delay_timer	= 3;

	High_score_view_delayed_request = NULL;

	// Kill the option tune when saving/loading
	ShutdownOptionsMusic();
}

/******************************************************************************
*%%%% LoadUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LoadUpdate(MR_VOID)
*
*	FUNCTION	Update code for Load screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	LoadUpdate(MR_VOID)
{

#ifdef PSX		// PSX Specific code ----------------------------------------

	MR_ULONG		load_status;

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();
	HSUpdateFlying();

	if	(
		(High_score_view_delayed_request == OPTIONS_PAGE_OPTIONS) ||
		(Option_page_request == OPTIONS_PAGE_OPTIONS)
		)
		return;

	// According to load mode do ...
	switch ( LS_load_mode )
		{
		// Initialise load --------------------------------------------------
		case LS_LOAD_MODE_INIT_INIT:
			// Wait for camera
			if (!Cameras[0].ca_move_timer)
				{
				if (!(--LS_delay_timer))
					{
					// Set up checking message
					LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_CHECKING][Game_language];
					LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
					LS_message_sprite_pos.y = (Game_display_height>>1);

					// Set up dodgy wait time, because we only want message while we are waiting
					LS_wait = 34;
					LS_message_mode = LS_MESSAGE_MODE_INIT;
					LS_exit_mode = 0;

					// Do dummy message call to display message
					LSMessage();

					// Go on to update
					LS_load_mode = LS_LOAD_MODE_INIT_WAIT;
					}
				}
			break;

		// Wait for "NOW CHECKING" message ----------------------------------
		case LS_LOAD_MODE_INIT_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to load
				LS_load_mode = LS_LOAD_MODE_INIT_CHECK;

			break;

		// Initialise check -------------------------------------------------
		case LS_LOAD_MODE_INIT_CHECK:

			// Get status of cards
			OptionsGetCardStatus();

			// Kill message
			LSMessage();
	
			// Go on to update
			LS_load_mode = LS_LOAD_MODE_INIT_UPDATE;

			break;

		// Update load initialise -------------------------------------------
		case LS_LOAD_MODE_INIT_UPDATE:

			// Were there any cards ?
			if ( ( Card0_present == FALSE ) && ( Card1_present == FALSE ) )
				{
				// No ... go on to no cards
				LS_load_mode = LS_LOAD_MODE_NO_CARD_PRESENT_INIT;
				}
			else
				{
				// Yes ... are there any saves ?
				if ( (Game0_present==TRUE) || (Game1_present == TRUE) )
					{
					// Yes ... go on to sure
					LS_load_mode = LS_LOAD_MODE_SURE_INIT;
					}
				else
					{
					// No ... go on to no saves
					LS_load_mode = LS_LOAD_MODE_NO_SAVES_INIT;
					}
				}

			break;

		// Initialise "sure?" request ---------------------------------------
		case LS_LOAD_MODE_SURE_INIT:

			// Set up sure selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_HS_SM][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0] 	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_sprite_pos[0].x 	= (Game_display_width>>2)-(LS_selection_texture_ptrs[0]->te_w>>1);
			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1)+64;

			LS_selection_texture_ptrs[1] 	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_sprite_pos[1].x 	= ((Game_display_width>>2)*3)-(LS_selection_texture_ptrs[1]->te_w>>1);
			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 2;
			LS_selection_dir 	= LS_SELECT_DIR_LEFT_AND_RIGHT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Go on to update
			LS_load_mode 		= LS_LOAD_MODE_SURE_UPDATE;

			break;

		// Update "sure?" request -------------------------------------------
		case LS_LOAD_MODE_SURE_UPDATE:

			// Do selection
			LSSelect();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to sure_deinit
				LS_load_mode = LS_LOAD_MODE_SURE_DEINIT;
				}
				break;

		// Deinit "sure?" request -------------------------------------------
		case LS_LOAD_MODE_SURE_DEINIT:

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_load_mode = LS_LOAD_MODE_EXIT;
				// Return
				return;
				}

			// Was selection yes ?
			if ( !LS_selection )
				{
				// Yes ... are there two saves ?
				if ( (Game0_present == TRUE) && (Game1_present == TRUE) )
					{
					// Yes ... go on to select cards
					LS_load_mode = LS_LOAD_MODE_SELECT_CARD_INIT;
					}
				else
					{
					// No ... go on to load
					LS_load_mode = LS_LOAD_MODE_LOAD_INIT;
					// Is card 0 present
					if ( Game0_present == TRUE )
						{
						// Yes ... set card number
						LS_card_number = 0;
						}
					else
						{
						// No ... set card number
						LS_card_number = 1;
						}
					}
				}
			else
				{
				// No ... go on to exit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "select card" request ---------------------------------
		case LS_LOAD_MODE_SELECT_CARD_INIT:

			// Set up card selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_SELECT_CARD][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

//			LS_selection_texture_ptrs[0]	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_texture_ptrs[0]	= NULL;
//			LS_selection_sprite_pos[0].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[0]->te_w>>1);
//			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1);

//			LS_selection_texture_ptrs[1]	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_texture_ptrs[1]	= NULL;
//			LS_selection_sprite_pos[1].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[1]->te_w>>1);
//			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+32;

			LS_selection_texture_ptrs[2]	= Options_text_textures[OPTION_TEXT_RETURN][Game_language];
			LS_selection_sprite_pos[2].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[2]->te_w>>1);
			LS_selection_sprite_pos[2].y 	= (Game_display_height>>1)+64;

			LS_num_selections = 3;
			LS_selection_dir = LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT;
			LS_select_mode = LS_SELECT_MODE_INIT;
			LS_exit_mode = 0;

			// Make memory cards visible
			LSCreateMemoryCards();

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_SELECT_CARD_UPDATE;

			break;

		// Update "select card" request -------------------------------------
		case LS_LOAD_MODE_SELECT_CARD_UPDATE:

			// Do selection
			LSSelect();

			// Update memory cards
			LSUpdateMemoryCards();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to select_card_deinit
				LS_load_mode = LS_LOAD_MODE_SELECT_CARD_DEINIT;
				}

			break;

		// Deinit "select card" request -------------------------------------
		case LS_LOAD_MODE_SELECT_CARD_DEINIT:

			// Hide memory cards
			LSKillMemoryCards();

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_load_mode = LS_LOAD_MODE_EXIT;
				// Return
				return;
				}

			// Did user choose card ?
			if ( LS_selection < 2 )
				{
				// Yes ... set card number
				LS_card_number = LS_selection;
				// Go to load
				LS_load_mode = LS_LOAD_MODE_LOAD_INIT;
				}
			else
				{
				// No ... exit now
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise load high score data ----------------------------------
		case LS_LOAD_MODE_LOAD_INIT:

			// Set up loading message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_LOADING][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			// Set up dodgy wait time, because we only want message while we are waiting
			LS_wait = 4;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Do dummy message call to display message
			LSMessage();

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_LOAD_WAIT;

			break;

		// Wait for "NOW LOADING" message -----------------------------------
		case LS_LOAD_MODE_LOAD_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to load
				LS_load_mode = LS_LOAD_MODE_LOAD;

			break;

		// Load high score data ---------------------------------------------
		case LS_LOAD_MODE_LOAD:
			
			// Load
			load_status = OptionsLoadSaveData(LS_card_number);

			// Kill message
			LSMessage();

			// According to status of load do ...
			switch(load_status)
				{
				// Load ok ... go on to "load ok!"
				case CLG_LOAD_OK:
					LS_load_mode = LS_LOAD_MODE_SUCCESS_INIT;
					break;
				// No card present ... go on to no card present
				case CLG_NO_CARD:
					LS_load_mode = LS_LOAD_MODE_NO_CARD_INIT;
					break;
				// No game found ... go on to 
				case CLG_NO_GAME:
					LS_load_mode = LS_LOAD_MODE_NO_GAME_INIT;
					break;
				// Load error ... go on to load failed
				case CLG_LOAD_ERROR:
					LS_load_mode = LS_LOAD_MODE_FAILURE_INIT;
					break;
				// Card unformatted ... go on to card unformatted
				case CLG_UNFORMATTED:
					LS_load_mode = LS_LOAD_MODE_UNFORMATTED_INIT;
					break;
				// Default ... go on to load failed
				default:
					LS_load_mode = LS_LOAD_MODE_FAILURE_INIT;
					break;
				}

			break;
			

		// Initialise "no card" message ------------------------------------
		case LS_LOAD_MODE_NO_CARD_INIT:

			// Set up no card message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_CARD][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_NO_CARD_UPDATE;

			break;

		// Update "no saves" message ----------------------------------------
		case LS_LOAD_MODE_NO_CARD_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "no game" message ------------------------------------
		case LS_LOAD_MODE_NO_GAME_INIT:

			// Set up no saves message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_DATA][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_NO_GAME_UPDATE;

			break;

		// Update "no game" message ----------------------------------------
		case LS_LOAD_MODE_NO_GAME_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "unformatted" message ------------------------------------
		case LS_LOAD_MODE_UNFORMATTED_INIT:

			// Set up unformatteed message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_UNFORMATTED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_UNFORMATTED_UPDATE;

			break;

		// Update "no saves" message ----------------------------------------
		case LS_LOAD_MODE_UNFORMATTED_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "no saves" message ------------------------------------
		case LS_LOAD_MODE_NO_SAVES_INIT:

			// Set up no saves message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_DATA][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_NO_SAVES_UPDATE;

			break;

		// Update "no saves" message ----------------------------------------
		case LS_LOAD_MODE_NO_SAVES_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "load ok!" message ------------------------------------
		case LS_LOAD_MODE_SUCCESS_INIT:

			// Set up success message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_OK][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait 		= 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode 	= 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_SUCCESS_UPDATE;

			break;

		// Update "load ok!" message ----------------------------------------
		case LS_LOAD_MODE_SUCCESS_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "load failed" message ---------------------------------
		case LS_LOAD_MODE_FAILURE_INIT:

			// Set up failure message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_FAILED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = Game_display_height>>1;

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_FAILURE_UPDATE;

			break;

		// Update "load failed" message -------------------------------------
		case LS_LOAD_MODE_FAILURE_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Initialise "no cards present" message ----------------------------
		case LS_LOAD_MODE_NO_CARD_PRESENT_INIT:

			// Set up no card present message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_CARD][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = Game_display_height>>1;

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_load_mode = LS_LOAD_MODE_NO_CARD_PRESENT_UPDATE;

			break;

		// Update "no cards present" message --------------------------------
		case LS_LOAD_MODE_NO_CARD_PRESENT_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_load_mode = LS_LOAD_MODE_EXIT;
				goto ls_load_mode_exit;
				}

			break;

		// Deinit load ------------------------------------------------------
		case LS_LOAD_MODE_EXIT:
	ls_load_mode_exit:;
			// Return to options
			High_score_view_delayed_request = OPTIONS_PAGE_OPTIONS;

			// Start moving camera NOW
			OptionsCameraMoveToOptions();
			High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
			break;

		}

#else			// WIN95 Specific code --------------------------------------

/*	switch ( LS_load_mode )
		{

		case LS_LOAD_MODE_init_init:
			// Anything in registry ?
				// No ... exit
				// Yes ... go on to sure
			break;

		case LS_LOAD_MODE_sure_init:
			// Set up sure selection
			// Go on to update
			break;

		case LS_LOAD_MODE_sure_update:
			// Do selection
			// Has selection finished ?
				// Yes ... go on to sure_deinit
			break;

		case LS_LOAD_MODE_sure_deinit:
			// Was selection yes ?
				// Yes ... load
					// Was load successful ?
						// Yes ... go on to success init
						// No ... go on to failure init
			break;

		case LS_LOAD_MODE_success_init:
			// Set up success message
			// Go on to update
			break;

		case LS_LOAD_MODE_success_update:
			// Do message
			// Has message finished ?
				// Yes ... go on to deinit
			break;

		case LS_LOAD_MODE_failure_init:
			// Set up failure message
			// Go on to update
			break;

		case LS_LOAD_MODE_failure_update:
			// Do message
			// Has message finished ?
				// Yes ... go no to deinit
			break;

		case LS_LOAD_MODE_init_exit:
			break;

		}
*/
#endif			// End platform specific code -------------------------------

}

/******************************************************************************
*%%%% LoadShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LoadShutdown(MR_VOID)
*
*	FUNCTION	Load shut down.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LoadShutdown(MR_VOID)
{
	// Re-start music when out of load/save.
	PlayOptionsMusic();
}

/******************************************************************************
*%%%% CheckStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CheckStartup(MR_VOID)
*
*	FUNCTION	Start up code for check save screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID CheckStartup(MR_VOID)
{

#ifdef PSX_MODE_NTSC
	// Load options resources
	LoadOptionsResources();
#endif

	// Initialise mode of operation
	LS_check_mode = LS_CHECK_MODE_INIT_INIT;

}

/******************************************************************************
*%%%% CheckUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CheckUpdate(MR_VOID)
*
*	FUNCTION	Update code for check save screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CheckUpdate(MR_VOID)
{

#ifdef PSX		// PSX Specific code ----------------------------------------

	// Locals
	MR_ULONG		load_status;

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();

	// According to check mode do ...
	switch ( LS_check_mode )
		{

		// Initialise load high score data ----------------------------------
		case LS_CHECK_MODE_INIT_INIT:

			// Set up loading message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_CHECKING][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			// Set up dodgy wait time, because we only want message while we are waiting
			LS_wait = 34;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Do dummy message call to display message
			LSMessage();

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_INIT_WAIT;

			break;

		// Wait for "NOW CHECKING" message ----------------------------------
		case LS_CHECK_MODE_INIT_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to load
				LS_check_mode = LS_CHECK_MODE_INIT_CHECK;

			break;

		// Initialise check -------------------------------------------------
		case LS_CHECK_MODE_INIT_CHECK:

			// Get status of cards
			OptionsGetCardStatus();

			// Kill message
			LSMessage();
			
			// Go on to update
			LS_check_mode = LS_CHECK_MODE_INIT_UPDATE;

			break;

		// Update check initialise ------------------------------------------
		case LS_CHECK_MODE_INIT_UPDATE:

			// Were there any cards ?
			if ( ( Card0_present == FALSE ) && ( Card1_present == FALSE ) )
				{
				// No ... go on to exit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}
			else
				{
				// Yes ... are there any saves ?
				if ( (Game0_present==TRUE) || (Game1_present == TRUE) )
					{
					// Yes ... go on to sure
					LS_check_mode = LS_CHECK_MODE_SURE_INIT;
					}
				else
					{
					// No ... go on to check info
					LS_check_mode = LS_CHECK_INFO;
					}
				}

			break;

		// Check free space of card -----------------------------------------
		case LS_CHECK_INFO:

			// Is there a card present in first slot only ?
			if ( (Card0_present == TRUE) && (Card1_present == FALSE) )
				{
				// Yes ... is there enough space for Frogger save ?
				if ( OptionsCheckCardFull(0) )
					// No ... display dodgy message
					LS_check_mode = LS_CHECK_MODE_FULL_INIT;
				else
					// Yes ... exit
					LS_check_mode = LS_CHECK_MODE_EXIT;
				}
			else
			// Is there a card present in second slot only ?
			if ( (Card1_present == TRUE) && (Card0_present == FALSE) )
				{
				// Yes ... is there enough space for Frogger save ?
				if ( OptionsCheckCardFull(1) )
					// No ... display dodgy message
					LS_check_mode = LS_CHECK_MODE_FULL_INIT;
				else
					// Yes ... exit
					LS_check_mode = LS_CHECK_MODE_EXIT;
				}
			else
			// Cards in both slots ...
				{
				// Yes ... is there not enough space on either card ?
				if ( (OptionsCheckCardFull(0)) && (OptionsCheckCardFull(1)) )
					// Yes ... display dodgy message
					LS_check_mode = LS_CHECK_MODE_FULL_INIT;
				else
					// No ... exit
					LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "sure?" request ---------------------------------------
		case LS_CHECK_MODE_SURE_INIT:

			// Set up sure selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_HS_SM][Game_language];
			LS_title_sprite_pos.x	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y	= (Game_display_height>>1)-64;

			LS_selection_texture_ptrs[0] 	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_sprite_pos[0].x 	= (Game_display_width>>2)-(LS_selection_texture_ptrs[0]->te_w>>1);
			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1)+64;

			LS_selection_texture_ptrs[1] 	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_sprite_pos[1].x 	= ((Game_display_width>>2)*3)-(LS_selection_texture_ptrs[1]->te_w>>1);
			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+64;

			LS_num_selections = 2;
			LS_selection_dir = LS_SELECT_DIR_LEFT_AND_RIGHT;
			LS_select_mode = LS_SELECT_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_SURE_UPDATE;

			break;

		// Update "sure?" request -------------------------------------------
		case LS_CHECK_MODE_SURE_UPDATE:

			// Do selection
			LSSelect();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to sure_deinit
				LS_check_mode = LS_CHECK_MODE_SURE_DEINIT;
				}

			break;

		// Deinit "sure?" request -------------------------------------------
		case LS_CHECK_MODE_SURE_DEINIT:

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_check_mode = LS_CHECK_MODE_EXIT;
				// Return
				return;
				}

			// Was selection yes ?
			if ( !LS_selection )
				{
				// Yes ... are there two saves ?
				if ( (Game0_present == TRUE) && (Game1_present == TRUE) )
					{
					// Yes ... go on to select cards
					LS_check_mode = LS_CHECK_MODE_SELECT_CARD_INIT;
					}
				else
					{
					// No ... go on to load
					LS_check_mode = LS_CHECK_MODE_LOAD_INIT;
					// Is card 0 present
					if ( Card0_present == TRUE )
						{
						// Yes ... set card number
						LS_card_number = 0;
						}
					else
						{
						// No ... set card number
						LS_card_number = 1;
						}
					}
				}
			else
				{
				// No ... go on to exit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "select card" request ---------------------------------
		case LS_CHECK_MODE_SELECT_CARD_INIT:

			// Set up card selection
			LS_title_texture_ptr 	= Options_text_textures[OPTION_TEXT_SELECT_CARD][Game_language];
			LS_title_sprite_pos.x 	= (Game_display_width>>1)-(LS_title_texture_ptr->te_w>>1);
			LS_title_sprite_pos.y 	= (Game_display_height>>1)-64;

//			LS_selection_texture_ptrs[0]	= Options_text_textures[OPTION_TEXT_YES][Game_language];
			LS_selection_texture_ptrs[0]	= NULL;
//			LS_selection_sprite_pos[0].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[0]->te_w>>1);
//			LS_selection_sprite_pos[0].y 	= (Game_display_height>>1);

//			LS_selection_texture_ptrs[1]	= Options_text_textures[OPTION_TEXT_NO][Game_language];
			LS_selection_texture_ptrs[1]	= NULL;
//			LS_selection_sprite_pos[1].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[1]->te_w>>1);
//			LS_selection_sprite_pos[1].y 	= (Game_display_height>>1)+32;

			LS_selection_texture_ptrs[2] = Options_text_textures[OPTION_TEXT_EXIT][Game_language];
			LS_selection_sprite_pos[2].x 	= (Game_display_width>>1)-(LS_selection_texture_ptrs[2]->te_w>>1);
			LS_selection_sprite_pos[2].y 	= (Game_display_height>>1)+64;

			LS_num_selections 	= 3;
			LS_selection_dir 	= LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT;
			LS_select_mode 		= LS_SELECT_MODE_INIT;
			LS_exit_mode 		= 0;

			// Show memory cards
			LSCreateMemoryCards();
				
			// Go on to update
			LS_check_mode = LS_CHECK_MODE_SELECT_CARD_UPDATE;

			break;

		// Update "select card" request -------------------------------------
		case LS_CHECK_MODE_SELECT_CARD_UPDATE:

			// Do selection
			LSSelect();

			// Update memory card models
			LSUpdateMemoryCards();

			// Has selection finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to select_card_deinit
				LS_check_mode = LS_CHECK_MODE_SELECT_CARD_DEINIT;
				}

			break;

		// Deinit "select card" request -------------------------------------
		case LS_CHECK_MODE_SELECT_CARD_DEINIT:

			// Hide memory cards
			LSKillMemoryCards();

			// Did player quit ?
			if ( LS_selection == -1 )
				{
				// Yes ... quit now
				LS_check_mode = LS_CHECK_MODE_EXIT;
				// Return
				return;
				}

			// Did user choose card ?
			if ( LS_selection < 2 )
				{
				// Yes ... set card number
				LS_card_number = LS_selection;
				// Go to load
				LS_check_mode = LS_CHECK_MODE_LOAD_INIT;
				}
			else
				{
				// No ... exit now
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise load high score data ----------------------------------
		case LS_CHECK_MODE_LOAD_INIT:

			// Set up loading message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NOW_LOADING][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			// Set up dodgy wait time, because we only want message while we are waiting
			LS_wait = 4;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Do dummy message call to display message
			LSMessage();

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_LOAD_WAIT;

			break;

		// Wait for "NOW LOADING" message -----------------------------------
		case LS_CHECK_MODE_LOAD_WAIT:

			// Update message
			LSMessage();

			// Is message about to shut down ?
			if ( LS_message_mode == LS_MESSAGE_MODE_EXIT )
				// Yes ... go on to load
				LS_check_mode = LS_CHECK_MODE_LOAD;

			break;

		// Load high score data ---------------------------------------------
		case LS_CHECK_MODE_LOAD:
			
			// Load
			load_status = OptionsLoadSaveData(LS_card_number);
			
			// Update message status, killing sprite
			LSMessage();

			// According to status of load do ...
			switch(load_status)
				{
				// Load ok ... go on to "load ok!"
				case CLG_LOAD_OK:
					LS_check_mode = LS_CHECK_MODE_SUCCESS_INIT;
					break;
				// No card present ... go on to 
				case CLG_NO_CARD:
					LS_check_mode = LS_CHECK_MODE_NO_CARD_INIT;
					break;
				// No game found ... go on to 
				case CLG_NO_GAME:
					LS_check_mode = LS_CHECK_MODE_NO_GAME_INIT;
					break;
				// Load error ... go on to load failed
				case CLG_LOAD_ERROR:
					LS_check_mode = LS_CHECK_MODE_FAILURE_INIT;
					break;
				// Card unformatted ... go on to card unformatted
				case CLG_UNFORMATTED:
					LS_check_mode = LS_CHECK_MODE_UNFORMATTED_INIT;
					break;
				// Default ... go on to load failed
				default:
					LS_check_mode = LS_CHECK_MODE_FAILURE_INIT;
					break;
				}

			break;

		// Initialise "load ok!" message ------------------------------------
		case LS_CHECK_MODE_SUCCESS_INIT:

			// Set up success message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_OK][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_SUCCESS_UPDATE;

			break;

		// Update "load ok!" message ----------------------------------------
		case LS_CHECK_MODE_SUCCESS_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "no card" message ------------------------------------
		case LS_CHECK_MODE_NO_CARD_INIT:

			// Set up full message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_CARD][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_NO_CARD_UPDATE;

			break;

		// Update "no card" message ----------------------------------------
		case LS_CHECK_MODE_NO_CARD_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "no game" message ------------------------------------
		case LS_CHECK_MODE_NO_GAME_INIT:

			// Set up full message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_NO_DATA][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_NO_GAME_UPDATE;

			break;

		// Update "no game" message ----------------------------------------
		case LS_CHECK_MODE_NO_GAME_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "unformatted" message ------------------------------------
		case LS_CHECK_MODE_UNFORMATTED_INIT:

			// Set up full message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_UNFORMATTED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1);

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_UNFORMATTED_UPDATE;

			break;

		// Update "unformatted" message ----------------------------------------
		case LS_CHECK_MODE_UNFORMATTED_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "memory card full" message ------------------------------------
		case LS_CHECK_MODE_FULL_INIT:

			// Set up full message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_MEM_MESSAGE][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = (Game_display_height>>1)-(LS_message_texture_ptr->te_h>>1);

			LS_wait = 30*8;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_FULL_UPDATE;

			break;

		// Update "memory card full" message ----------------------------------------
		case LS_CHECK_MODE_FULL_UPDATE:
			
			// Do message
			LSMessage();
			
			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Initialise "load failed" message ---------------------------------
		case LS_CHECK_MODE_FAILURE_INIT:

			// Set up failure message
			LS_message_texture_ptr 	= Options_text_textures[OPTION_TEXT_LOAD_FAILED][Game_language];
			LS_message_sprite_pos.x = (Game_display_width>>1)-(LS_message_texture_ptr->te_w>>1);
			LS_message_sprite_pos.y = Game_display_height>>1;

			LS_wait = 30*2;
			LS_message_mode = LS_MESSAGE_MODE_INIT;
			LS_exit_mode = 0;

			// Go on to update
			LS_check_mode = LS_CHECK_MODE_FAILURE_UPDATE;

			break;

		// Update "load failed" message -------------------------------------
		case LS_CHECK_MODE_FAILURE_UPDATE:

			// Do message
			LSMessage();

			// Has message finished ?
			if ( LS_exit_mode )
				{
				// Yes ... go on to deinit
				LS_check_mode = LS_CHECK_MODE_EXIT;
				}

			break;

		// Deinit check -----------------------------------------------------
		case LS_CHECK_MODE_EXIT:

//			if ( 1 == 1 )
//				{
				// Go on to main options
				Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
//				}
//			else
//				{
//				// Go on to main options
//				Option_page_request = OPTIONS_PAGE_OPTIONS;
//				}

			break;

		}

#else			// WIN95 Specific code --------------------------------------

/*	switch ( LS_load_mode )
		{

		case LS_LOAD_MODE_init_init:
			// Anything in registry ?
				// No ... exit
				// Yes ... go on to sure
			break;

		case LS_LOAD_MODE_sure_init:
			// Set up sure selection
			// Go on to update
			break;

		case LS_LOAD_MODE_sure_update:
			// Do selection
			// Has selection finished ?
				// Yes ... go on to sure_deinit
			break;

		case LS_LOAD_MODE_sure_deinit:
			// Was selection yes ?
				// Yes ... load
					// Was load successful ?
						// Yes ... go on to success init
						// No ... go on to failure init
			break;

		case LS_LOAD_MODE_success_init:
			// Set up success message
			// Go on to update
			break;

		case LS_LOAD_MODE_success_update:
			// Do message
			// Has message finished ?
				// Yes ... go on to deinit
			break;

		case LS_LOAD_MODE_failure_init:
			// Set up failure message
			// Go on to update
			break;

		case LS_LOAD_MODE_failure_update:
			// Do message
			// Has message finished ?
				// Yes ... go no to deinit
			break;

		case LS_LOAD_MODE_init_exit:
			break;

		}
*/
	Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
#endif			// End platform specific code -------------------------------
}

/******************************************************************************
*%%%% CheckShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CheckShutdown(MR_VOID)
*
*	FUNCTION	Check saves shut down.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID CheckShutdown(MR_VOID)
{

}

/******************************************************************************
*%%%% LSSelect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LSSelect(MR_VOID)
*
*	FUNCTION	Load/Save generic selection screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LSSelect(MR_VOID)
{
	MR_LONG	i;


	// According to mode of operation do ...
	switch ( LS_select_mode)
		{

		// Initialise selection screen --------------------------------------
		case LS_SELECT_MODE_INIT:

			// Create title sprite
			LS_title_sprite_ptr = MRCreate2DSprite(LS_title_sprite_pos.x, LS_title_sprite_pos.y, Option_viewport_ptr, LS_title_texture_ptr, NULL);

			// Loop once for each selection
			for(i = 0; i < LS_num_selections; i++)
				{
				// Is there a choice to display ?
				if ( LS_selection_texture_ptrs[i] != NULL )
					{
					// Yes ... create selection sprite
					LS_selection_sprite_ptr[i] 	= MRCreate2DSprite(LS_selection_sprite_pos[i].x, LS_selection_sprite_pos[i].y, Option_viewport_ptr, LS_selection_texture_ptrs[i], NULL);
					Option_spcore_ptrs[i]		= (MR_SP_CORE*)LS_selection_sprite_ptr[i];
					}
				}

			// Are we in "up and down & left and right" mode ?
			if ( LS_selection_dir == LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT )
				{
				// Yes ... set up Option_spcore_ptrs
				Option_spcore_ptrs[0] = (MR_SP_CORE*)LS_title_sprite_ptr;
				Option_spcore_ptrs[1] = (MR_SP_CORE*)LS_title_sprite_ptr;
				Option_spcore_ptrs[2] = (MR_SP_CORE*)LS_selection_sprite_ptr[2];
				Option_spcore_ptrs[3] = (MR_SP_CORE*)LS_selection_sprite_ptr[2];
				Option_spcore_ptrs[4] = NULL;
				}

			// Initialise current selection
			LS_selection = 0;

			// Go on to input
			LS_select_mode = LS_SELECT_MODE_INPUT;

			break;

		// Allow user to make choice ----------------------------------------
		case LS_SELECT_MODE_INPUT:

			// Select left and right ?
			if ( LS_selection_dir == LS_SELECT_DIR_LEFT_AND_RIGHT )
				{
				// Yes ... did user press left ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_LEFT) )
					{
					// Yes ... are we on first item ?
					if ( LS_selection )
						{
						// No ... dec selection
						LS_selection--;
						}
					}

				// Did user press right ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_RIGHT) )
					{
					// Yes ... are we on last item ?
					if ( LS_selection < (LS_num_selections-1) )
						{
						// No ... inc selection
						LS_selection++;
						}
					}
				}
			else
			if ( LS_selection_dir == LS_SELECT_DIR_UP_AND_DOWN )
				{
				// No ... did user press up ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_UP) )
					{
					// Yes ... are we on first item ?
					if ( LS_selection )
						{
						// No ... dec selection
						LS_selection--;
						}
					}

				// Did user press down ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN) )
					{
					// Yes ... are we on last item ?
					if ( LS_selection < (LS_num_selections-1) )
						{
						// No ... inc selection
						LS_selection++;
						}
					}
				}
			else
			if ( LS_selection_dir == LS_SELECT_DIR_UP_AND_DOWN_AND_RIGHT_AND_LEFT )
				{
				// No ... did user press up ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_UP) )
					{
					// Yes ... 
					if ( LS_selection > 1 )
						{
						// Yes ... 
						LS_selection -= 2;
						}
					}

				// Did user press down ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN) )
					{
					// Yes ... 
					if ( LS_selection < 2 )
						{
						// Yes ... 
						LS_selection += 2;
						}
					}

				// Did user press left ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_LEFT) )
					{
					// Yes ... 
					if ( LS_selection == 1 )
						{
						// Yes ... dec selection
						LS_selection--;
						}
					}

				// Did user press right ?
				if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_RIGHT) )
					{
					// Yes ... 
					if ( !LS_selection )
						{
						// Yes ... 
						LS_selection++;
						}
					}

				}

			// Did user press fire ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
				{
				// Yes ... go on to exit
				LS_select_mode = LS_SELECT_MODE_EXIT;
				}

			Option_spcore_index = LS_selection;

			// Did user press exit ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0],FRR_TRIANGLE) )
				{
				// Yes ... go on to exit
				LS_select_mode = LS_SELECT_MODE_EXIT;
				// Change selection to indicate exit condition
				LS_selection = -1;
				}

			break;

		// Shut down selection screen ---------------------------------------
		case LS_SELECT_MODE_EXIT:

			// Kill title sprite
			MRKill2DSprite(LS_title_sprite_ptr);

			// Kill selection sprites
			for(i = 0; i < LS_num_selections; i++)
				{
				// Was there a choice to display ?
				if ( LS_selection_texture_ptrs[i] != NULL )
					{
					// Yes ... kill sprite
					MRKill2DSprite(LS_selection_sprite_ptr[i]);
					}
				}

			// Go back
			LS_exit_mode = 1;
			break;
		}
}


/******************************************************************************
*%%%% LSMessage
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LSMessage(MR_VOID)
*
*	FUNCTION	Load/Save message screen.  Display message, wait then exit.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LSMessage(MR_VOID)
{

	// According to mode of operation do ...
	switch ( LS_message_mode )
		{

		// Initialise message screen ----------------------------------------
		case LS_MESSAGE_MODE_INIT:

			// Create message sprite
			LS_message_sprite_ptr = MRCreate2DSprite(LS_message_sprite_pos.x,LS_message_sprite_pos.y,Option_viewport_ptr,LS_message_texture_ptr,NULL);

			// Go on to wait
			LS_message_mode = LS_MESSAGE_MODE_WAIT;

			break;

		// Wait -------------------------------------------------------------
		case LS_MESSAGE_MODE_WAIT:

			// Dec wait
			LS_wait--;

			// Was exit pressed ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0],FRR_TRIANGLE|FR_GO) )
				{
				// Yes ... exit
				LS_wait = 0;
				}

			// End of wait ?
			if ( !LS_wait )
				{
				// Yes ... exit
				LS_message_mode = LS_MESSAGE_MODE_EXIT;
				}

			break;

		// Shut down message screen -----------------------------------------
		case LS_MESSAGE_MODE_EXIT:

			// Kill message sprite
			MRKill2DSprite(LS_message_sprite_ptr);

			// Go back
			LS_exit_mode = 1;

			break;

		}

}

#ifdef PSX

/******************************************************************************
*%%%% LSCreateMemoryCards
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LSCreateMemoryCards(MR_VOID)
*
*	FUNCTION	Create memory card models
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LSCreateMemoryCards(MR_VOID)
{
	MR_LONG	i;
	MR_SVEC	pos;
	

	// Allocate memory for matrices
	LS_matrices = MRAllocMem(sizeof(MR_MAT) * 2, "LS matrices");

	// Create two memory card models
	for (i = 0; i < 2; i++)
		{
		(MR_UBYTE*)LS_extras_matrix_ptr[i] = LS_matrices + (sizeof(MR_MAT)*i);
		MR_COPY_MAT(LS_extras_matrix_ptr[i], &Option_viewport_ptr->vp_camera->fr_matrix);

		pos.vx = -0x200+(i*0x400);
		pos.vy = 0;
		pos.vz = 0xA00;
		MRApplyMatrixSVEC(&Option_viewport_ptr->vp_camera->fr_matrix,&pos,&pos);
		LS_extras_matrix_ptr[i]->t[0] = pos.vx + Option_viewport_ptr->vp_camera->fr_matrix.t[0];
		LS_extras_matrix_ptr[i]->t[1] = pos.vy + Option_viewport_ptr->vp_camera->fr_matrix.t[1];
		LS_extras_matrix_ptr[i]->t[2] = pos.vz + Option_viewport_ptr->vp_camera->fr_matrix.t[2];

		LS_extras_object_ptr[i] 	= MRCreateMesh(MR_GET_RESOURCE_ADDR(LS_extras_resource_id[i]), (MR_FRAME*)LS_extras_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		LS_extras_mesh_inst_ptr[i] 	= MRAddObjectToViewport(LS_extras_object_ptr[i], Option_viewport_ptr, 0);

		// Use colour scaling
		LS_extras_mesh_inst_ptr[i]->mi_light_flags |= MR_INST_USE_SCALED_COLOURS;
		}

	// Initialise rotation
	LS_memory_card_rotation1 = 0;
	LS_memory_card_rotation2 = 0;
}


/******************************************************************************
*%%%% LSUpdateMemoryCards
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LSUpdateMemoryCards(MR_VOID)
*
*	FUNCTION	Update memory card models
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LSUpdateMemoryCards(MR_VOID)
{
	MR_LONG	cos;
	MR_LONG	sin;
	MR_LONG	angle;
	MR_MAT*	matrix;

	
	if (LS_selection == 0)
		{
		// Memory card 1 selected
		LS_memory_card_rotation1 += LOADSAVE_CARD_ROTATION_RATE;
		LS_memory_card_rotation1 &= 0xfff;

		// Set rotation of card
		angle	= LS_memory_card_rotation1;
		matrix	= LS_extras_matrix_ptr[0];

		// Scale model colours
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.r = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.g = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.b = 0x40;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.r = 0xa0;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.g = 0xa0;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.b = 0xa0;
		}
	else
	if (LS_selection == 1)
		{
		// Memory card 2 selected
		LS_memory_card_rotation2 += LOADSAVE_CARD_ROTATION_RATE;
		LS_memory_card_rotation2 &= 0xfff;

		// Set rotation of card
		angle	= LS_memory_card_rotation2;
		matrix	= LS_extras_matrix_ptr[1];

		// Scale model colours
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.r = 0x40;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.g = 0x40;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.b = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.r = 0xa0;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.g = 0xa0;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.b = 0xa0;
		}
	else
		{
		// Scale model colours
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.r = 0x40;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.g = 0x40;
		LS_extras_mesh_inst_ptr[0]->mi_colour_scale.b = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.r = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.g = 0x40;
		LS_extras_mesh_inst_ptr[1]->mi_colour_scale.b = 0x40;
		return;
		}
	
	cos = rcos(angle);
	sin = rsin(angle);
	MRRot_matrix_Y.m[0][0] =  cos;
	MRRot_matrix_Y.m[0][2] =  sin;
	MRRot_matrix_Y.m[2][0] = -sin;
	MRRot_matrix_Y.m[2][2] =  cos;
	MRMulMatrixABC(&Option_viewport_ptr->vp_camera->fr_matrix, &MRRot_matrix_Y, matrix);
}


/******************************************************************************
*%%%% LSKillMemoryCards
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LSKillMemoryCards(MR_VOID)
*
*	FUNCTION	Kill memory card models
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LSKillMemoryCards(MR_VOID)
{

	// Locals
	MR_ULONG		i;

	// Did we allocate a buffer ?
	if ( LS_matrices )
		{
		// Yes ... free buffer
		MRFreeMem(LS_matrices);
		// Null ptr
		LS_matrices = NULL;
		}

	// Destroy all models
	for (i = 0; i < 2; i++)
		LS_extras_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Clear flashing text
	OptionClearSpcores();
}

#endif

/******************************************************************************
*%%%% DecodeSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	DecodeSaveData(MR_VOID)
*
*	FUNCTION	Moves information from save data structure "Load_data" into Frogger's
*				main variables.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID DecodeSaveData(MR_VOID)
{

	// Locals
	SEL_LEVEL_INFO*		level_ptr;
	MR_ULONG			i;

	// Decode main options
	Music_volume = Load_data.co_music_volume;
	Sound_volume = Load_data.co_sound_volume;
	Game_language = Load_data.co_language;

	// Decode controller configurations

#ifdef WIN95	// Windows Specific code ------------------------------------



#else			// PSX Specific code ----------------------------------------

	Frog_current_control_methods[0] = Load_data.co_pad0_control_config;
	Frog_current_control_methods[1] = Load_data.co_pad1_control_config;
	Frog_current_control_methods[2] = Load_data.co_pad2_control_config;
	Frog_current_control_methods[3] = Load_data.co_pad3_control_config;

#endif			// End of Specific code -------------------------------------

	// Decode high scores
	memcpy(&Game_high_score[0],&Load_data.co_game_high_score[0],sizeof(HIGH_SCORE_ENTRY)*10);
	memcpy(&Level_high_scores[0][0],&Load_data.co_level_high_scores[0][0],sizeof(HIGH_SCORE_ENTRY)*60*3);

	// Decode game status
	level_ptr = &Sel_arcade_levels[0];
	i = 0;
	while ( level_ptr->li_library_id != -1 )
		{
		// Store stack flags
		level_ptr->li_flags = Load_data.co_selectable_levels[i];
		// Next level
		level_ptr++;
		i++;
		}

	// Decode gold frog status
	Gold_frogs = Load_data.co_number_of_golden_frogs;

}

/******************************************************************************
*%%%% EncodeSaveData
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	EncodeSaveData(MR_VOID)
*
*	FUNCTION	Moves information from main variables into save data structure 
*				"Soad_data".
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID EncodeSaveData(MR_VOID)
{

	// Locals
	SEL_LEVEL_INFO*		level_ptr;
	MR_ULONG			i;

	// Encode main options
	Save_data.co_music_volume = Music_volume;
	Save_data.co_sound_volume = Sound_volume;
	Save_data.co_language = Game_language;

	// Encode controller configurations

#ifdef WIN95	// Windows Specific code ------------------------------------

#else			// PSX Specific code ----------------------------------------

	Save_data.co_pad0_control_config = Frog_current_control_methods[0];
	Save_data.co_pad1_control_config = Frog_current_control_methods[1];
	Save_data.co_pad2_control_config = Frog_current_control_methods[2];
	Save_data.co_pad3_control_config = Frog_current_control_methods[3];

#endif			// End of Specific code -------------------------------------

	// Encode high scores
	memcpy(&Save_data.co_game_high_score[0],&Game_high_score[0],sizeof(HIGH_SCORE_ENTRY)*10);
	memcpy(&Save_data.co_level_high_scores[0][0],&Level_high_scores[0][0],sizeof(HIGH_SCORE_ENTRY)*60*3);

	// Encode game status
	level_ptr = &Sel_arcade_levels[0];
	i = 0;
	while ( level_ptr->li_library_id != -1 )
		{
		// Store stack flags
		Save_data.co_selectable_levels[i] = level_ptr->li_flags;
		// Next level
		level_ptr++;
		i++;
		}

	// Encode golden frog status
	Save_data.co_number_of_golden_frogs = Gold_frogs;

}

#ifdef WIN95
#pragma warning (default : 4761)
#endif
