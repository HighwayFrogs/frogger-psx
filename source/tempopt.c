/******************************************************************************
*%%%% tempopt.c
*------------------------------------------------------------------------------
*
*	Routines for temp options screens.
*	Generally, startup, update and shutdown.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	13.05.97	William Bell	Created
*	24.06.97	Martin Kift		Rewritten a few key areas to work better in
*								network mode.
*	09.07.97	Martin Kift		Rewrote continue screen
*
*%%%**************************************************************************/

#define INITGUID

#include "mr_all.h"
#include "options.h"
#include "tempopt.h"
#include "gamefont.h"
#include "gamesys.h"
#include "main.h"
#ifdef PSX
#include "stream.h"
#endif
#include "memcard.h"
#include "library.h"
#include "mapdebug.h"
#include "gen_frog.h"
#include "frog.h"
#include "model.h"
#include "sound.h"
#include "xalist.h"
#include "system.h"
#include "select.h"
#include "hsview.h"
#include "hsinput.h"
#include "camera.h"
#include "froganim.h"
#include "score.h"
#include "mapview.h"
#include "sound.h"
#include "ent_gen.h"
#include "hud.h"
#include "particle.h"
#include "water.h"
#include "pause.h"
#include "playxa.h"

#ifdef WIN95
#pragma warning (disable : 4761)
#endif

// Version ------------------------------------------------

MR_TEXT_AREA*		Version_text_area[4];

// Misc ---------------------------------------------------

MR_ULONG	Option_number;					// Number of option currently selected

MR_ULONG	Options_count_down_ticks;		// Number of ticks remaining in count down
MR_ULONG	Options_count_down_units;		// Number of units remaining in count down

// Anti piracy ( PSX ONLY ) -------------------------------

#ifdef PSX	// PSX Specific code --------------------------------------------

MR_ULONG	Anti_piracy_count;			// Time anti piracy on screen for

MR_2DSPRITE*	Warning_ptr;				// Ptr to 2D sprite for the anti piracy

#endif	// PSX

// Main Options -------------------------------------------

MR_USHORT	Main_options_status;					// Status of operation for main options screen

MR_BOOL		Recording_demo = FALSE;					// Flag recording demo
MR_BYTE*	Demo_data_input_ptr;					// Pointer to demo mode input data
MR_LONG		Demo_time;								// Time demo mode lasts for
MR_ULONG	Num_demo_levels_seen = 0;				// Number of demo levels viewed so far

MR_2DSPRITE*	Start_ptr;
MR_2DSPRITE*	Race_ptr;
MR_2DSPRITE*	Options_ptr;

POLY_FT4	Cloud_polys[2];							// For cloud to darken behind menu

MR_2DSPRITE*	Main_options_background_sprite_ptr[10];

//DEMO_DATA*	Demo_data_ptrs[MAX_NUM_DEMO_LEVELS];	// Pointer to demo data in memory ( as loaded from resource )
DEMO_DATA*		Demo_data_ptr;						// Ptr to current demo data being played back

DEMO_DATA	Demo_data;								// Actual demo data

MR_LONG		Demo_level_table[][3]	=	// Table of demo levels to show
	{

	// Level number			// Resource id			// Level to check open, before playing demo mode
	//LEVEL_ORIGINAL1,		RES_ORG1DEMO_DAT,		LEVEL_ORIGINAL1,
	LEVEL_ORIGINAL2,		RES_ORG2DEMO_DAT,		LEVEL_ORIGINAL1,
	LEVEL_ORIGINAL3,		RES_ORG3DEMO_DAT,		LEVEL_ORIGINAL1,
	LEVEL_ORIGINAL4,		RES_ORG4DEMO_DAT,		LEVEL_ORIGINAL1,
	LEVEL_ORIGINAL5,		RES_ORG5DEMO_DAT,		LEVEL_ORIGINAL1,

	LEVEL_SUBURBIA1,		RES_SUB1DEMO_DAT,		LEVEL_SUBURBIA1,
	LEVEL_SUBURBIA2,		RES_SUB2DEMO_DAT,		LEVEL_SUBURBIA1,
	LEVEL_SUBURBIA3,		RES_SUB3DEMO_DAT,		LEVEL_SUBURBIA1,
	LEVEL_SUBURBIA4,		RES_SUB4DEMO_DAT,		LEVEL_SUBURBIA1,
	LEVEL_SUBURBIA5,		RES_SUB5DEMO_DAT,		LEVEL_SUBURBIA1,

	LEVEL_FOREST1,			RES_FOR1DEMO_DAT,		LEVEL_FOREST1,
//	LEVEL_FOREST2,			RES_FOR2DEMO_DAT,		LEVEL_FOREST1,

	LEVEL_VOLCANO1,			RES_VOL1DEMO_DAT,		LEVEL_VOLCANO1,
//	LEVEL_VOLCANO2,			RES_VOL2DEMO_DAT,		LEVEL_VOLCANO1,
	LEVEL_VOLCANO3,			RES_VOL3DEMO_DAT,		LEVEL_VOLCANO1,

	LEVEL_CAVES1,			RES_CAV1DEMO_DAT,		LEVEL_CAVES1,
//	LEVEL_CAVES3,			RES_CAV3DEMO_DAT,		LEVEL_CAVES1,		// Removed because it looks poor
//	LEVEL_CAVES4,			RES_CAV4DEMO_DAT,		LEVEL_CAVES1,		// Removed because start position is now invalid

	LEVEL_SKY1,				RES_SKY1DEMO_DAT,		LEVEL_SKY1,
//	LEVEL_SKY2,				RES_SKY2DEMO_DAT,		LEVEL_SKY1,			// Removed because it causes a STACK overflow in CreateMapGroups.
	LEVEL_SKY3,				RES_SKY3DEMO_DAT,		LEVEL_SKY1,
	LEVEL_SKY4,				RES_SKY4DEMO_DAT,		LEVEL_SKY1,

	LEVEL_SWAMP1,			RES_SWP1DEMO_DAT,		LEVEL_SWAMP1,
	LEVEL_SWAMP2,			RES_SWP2DEMO_DAT,		LEVEL_SWAMP1,
	LEVEL_SWAMP3,			RES_SWP3DEMO_DAT,		LEVEL_SWAMP1,
	LEVEL_SWAMP4,			RES_SWP4DEMO_DAT,		LEVEL_SWAMP1,
	LEVEL_SWAMP5,			RES_SWP5DEMO_DAT,		LEVEL_SWAMP1,

	LEVEL_DESERT1,			RES_DES1DEMO_DAT,		LEVEL_DESERT1,
	LEVEL_DESERT2,			RES_DES2DEMO_DAT,		LEVEL_DESERT1,
	LEVEL_DESERT3,			RES_DES3DEMO_DAT,		LEVEL_DESERT1,
//	LEVEL_DESERT4,			RES_DES4DEMO_DAT,		LEVEL_DESERT1,		// Removed because it needs too much memory
	LEVEL_DESERT5,			RES_DES5DEMO_DAT,		LEVEL_DESERT1,

//	LEVEL_JUNGLE1,			RES_JUN1DEMO_DAT,		LEVEL_JUNGLE1,		// Removed by order of Kev

	// End of list
	-1,						-1,						-1,

	};

#ifndef PSX_RELEASE
MR_UBYTE	Demo_file_name[60][16]=
{

	{"cav1demo.dat"},
	{"cav2demo.dat"},
	{"cav3demo.dat"},
	{"cav4demo.dat"},
	{"cav5demo.dat"},
	{"cav6demo.dat"},

	{"des1demo.dat"},
	{"des2demo.dat"},
	{"des3demo.dat"},
	{"des4demo.dat"},
	{"des5demo.dat"},
	{"des6demo.dat"},

	{"for1demo.dat"},
	{"for2demo.dat"},
	{"for3demo.dat"},
	{"for4demo.dat"},
	{"for5demo.dat"},
	{"for6demo.dat"},

	{"jun1demo.dat"},
	{"jun2demo.dat"},
	{"jun3demo.dat"},
	{"jun4demo.dat"},
	{"jun5demo.dat"},
	{"jun6demo.dat"},

	{"org1demo.dat"},
	{"org2demo.dat"},
	{"org3demo.dat"},
	{"org4demo.dat"},
	{"org5demo.dat"},
	{"org6demo.dat"},

	{"arn1demo.dat"},
	{"arn2demo.dat"},
	{"arn3demo.dat"},
	{"arn4demo.dat"},
	{"arn5demo.dat"},
	{"arn6demo.dat"},
	
	{"swp1demo.dat"},
	{"swp2demo.dat"},
	{"swp3demo.dat"},
	{"swp4demo.dat"},
	{"swp5demo.dat"},
	{"swp6demo.dat"},

	{"sky1demo.dat"},
	{"sky2demo.dat"},
	{"sky3demo.dat"},
	{"sky4demo.dat"},
	{"sky5demo.dat"},
	{"sky6demo.dat"},

	{"sub1demo.dat"},
	{"sub2demo.dat"},
	{"sub3demo.dat"},
	{"sub4demo.dat"},
	{"sub5demo.dat"},
	{"sub6demo.dat"},

	{"vol1demo.dat"},
	{"vol2demo.dat"},
	{"vol3demo.dat"},
	{"vol4demo.dat"},
	{"vol5demo.dat"},
	{"vol6demo.dat"}

};

#endif

// Langauge Specific Text Images -------------------------------------

MR_ULONG	Opt_resource_files[] = 
	{
	RES_OPTE_RAM_VLO,
	RES_OPTI_RAM_VLO,
	RES_OPTG_RAM_VLO,
	RES_OPTF_RAM_VLO,
	RES_OPTS_RAM_VLO,
	};

MR_TEXTURE*		Options_text_textures[OPTION_TEXT_TOTAL][MAX_NUM_LANGUAGES] =
	{
		{	&im_next,				&im_next_i,				&im_next_g,				&im_next_f,				&im_next_s},				// OPTION_TEXT_NEXT,			
		{	&im_opt_paused,			&im_opti_paused,		&im_optg_paused,		&im_optf_paused,		&im_opts_paused},			// OPTION_TEXT_PAUSED,			
		{	&im_press_fire,			&im_press_fire_i,		&im_press_fire_g,		&im_press_fire_f,		&im_press_fire_s},			// OPTION_TEXT_PRESS_FIRE,		
		{	&im_quit,				&im_quit_i,				&im_quit_g,				&im_quit_f,				&im_quit_s},				// OPTION_TEXT_QUIT,			
		{	&im_total_score,		&im_total_score_i,		&im_total_score_g,		&im_total_score_f,		&im_total_score_s},			// OPTION_TEXT_TOTAL_SCORE,	
		{	&im_total_time,			&im_total_time_i,		&im_total_time_g,		&im_total_time_f,		&im_total_time_s},			// OPTION_TEXT_TOTAL_TIME,		
		{	&im_mem_message,		&im_mem_message_i,		&im_mem_message_g,		&im_mem_message_f,		&im_mem_message_s},			// OPTION_TEXT_MEM_MESSAGE,	
		{	&im_lost,				&im_lost_i,				&im_lost_g,				&im_lost_f,				&im_lost_s},				// OPTION_TEXT_LOST,			
		{	&im_played,				&im_played_i,			&im_played_g,			&im_played_f,			&im_played_s},				// OPTION_TEXT_PLAYED,			
		{	&im_won,				&im_won_i,				&im_won_g,				&im_won_f,				&im_won_s},					// OPTION_TEXT_WON,			
		{	&im_select1,			&im_select1_i,			&im_select1_g,			&im_select1_f,			&im_select1_s},				// OPTION_TEXT_SELECT1,		
		{	&im_select2,			&im_select2_i,			&im_select2_g,			&im_select2_f,			&im_select2_s},				// OPTION_TEXT_SELECT2,		
		{	&im_select3,			&im_select3_i,			&im_select3_g,			&im_select3_f,			&im_select3_s},				// OPTION_TEXT_SELECT3,		
#ifdef GAME_TIMS_BODGED_COMPILE
		{	&im_select3,			&im_select3_i,			&im_select3_g,			&im_select3_f,			&im_select3_s},				// OPTION_TEXT_SELECT3,		
		{	&im_select3,			&im_select3_i,			&im_select3_g,			&im_select3_f,			&im_select3_s},				// OPTION_TEXT_SELECT3,		
#else
		{	&im_select4,			&im_select4_i,			&im_select4_g,			&im_select4_f,			&im_select4_s},				// OPTION_TEXT_SELECT4,
		{	&im_select5,			&im_select5_i,			&im_select5_g,			&im_select5_f,			&im_select5_s},				// OPTION_TEXT_SELECT5,
#endif
		{	&im_sel_loading,		&im_seli_loading,		&im_selg_loading,		&im_self_loading,		&im_sels_loading},			// OPTION_TEXT_LOADING,		
		{	&im_opt_insert_pad,		&im_opti_insert_pad,	&im_optg_insert_pad,	&im_optf_insert_pad,	&im_opts_insert_pad},		// OPTION_TEXT_INSERT_PAD,		
		{	&im_opt_start,			&im_opti_start,			&im_optg_start,			&im_optf_start,			&im_opts_start},			// OPTION_TEXT_START,			
		{	&im_opt_options,		&im_opti_options,		&im_optg_options,		&im_optf_options,		&im_opts_options},			// OPTION_TEXT_OPTIONS,		
		{	&im_opt_race,			&im_opti_race,			&im_optg_race,			&im_optf_race,			&im_opts_race},				// OPTION_TEXT_RACE,			
		{	&im_opt_yes,			&im_opti_yes,			&im_optg_yes,			&im_optf_yes,			&im_opts_yes},				// OPTION_TEXT_YES,			
		{	&im_opt_no,				&im_opti_no,			&im_optg_no,			&im_optf_no,			&im_opts_no},				// OPTION_TEXT_NO,				
		{	&im_opt_gameover,		&im_opt_gameover,		&im_opt_gameover,		&im_opt_gameover,		&im_opt_gameover},			// OPTION_TEXT_GAMEOVER,		
		{	&im_opt_ctrl_config,	&im_opti_ctrl_config,	&im_optg_ctrl_config,	&im_optf_ctrl_config,	&im_opts_ctrl_config},		// OPTION_TEXT_CTRL_CONFIG,	
		{	&im_opt_exit,			&im_opti_exit,			&im_optg_exit,			&im_optf_exit,			&im_opts_exit},				// OPTION_TEXT_EXIT,			
		{	&im_opt_load_hs,		&im_opti_load_hs,		&im_optg_load_hs,		&im_optf_load_hs,		&im_opts_load_hs},			// OPTION_TEXT_LOAD_HS,		
		{	&im_opt_load_hs_sm,		&im_opti_load_hs_sm,	&im_optg_load_hs_sm,	&im_optf_load_hs_sm,	&im_opts_load_hs_sm},		// OPTION_TEXT_LOAD_HS_SM,		
		{	&im_opt_save_hs,		&im_opti_save_hs,		&im_optg_save_hs,		&im_optf_save_hs,		&im_opts_save_hs},			// OPTION_TEXT_SAVE_HS,		
		{ 	&im_opt_load_ok,		&im_opti_load_ok,		&im_optg_load_ok,		&im_optf_load_ok,		&im_opts_load_ok},			// OPTION_TEXT_LOAD_OK,		
		{ 	&im_opt_no_cards,		&im_opti_no_cards,		&im_optg_no_cards,		&im_optf_no_cards,		&im_opts_no_cards},			// OPTION_TEXT_NO_CARD,		
		{ 	&im_opt_no_data,		&im_opti_no_data,		&im_optg_no_data,		&im_optf_no_data,		&im_opts_no_data},			// OPTION_TEXT_NO_DATA,		
		{	&im_opt_no_space,		&im_opti_no_space,		&im_optg_no_space,		&im_optf_no_space,		&im_opts_no_space},			// OPTION_TEXT_NO_SPACE,		
		{	&im_opt_format2,		&im_opti_format2,		&im_optg_format2,		&im_optf_format2,		&im_opts_format2},			// OPTION_TEXT_FORMAT2,		
		{	&im_opt_overwrite,		&im_opti_overwrite,		&im_optg_overwrite,		&im_optf_overwrite,		&im_opts_overwrite},		// OPTION_TEXT_OVERWRITE,		
		{	&im_opt_return,			&im_opti_return,		&im_optg_return,		&im_optf_return,		&im_opts_return},			// OPTION_TEXT_RETURN,			
		{	&im_opt_save_ok,		&im_opti_save_ok,		&im_optg_save_ok,		&im_optf_save_ok,		&im_opts_save_ok},			// OPTION_TEXT_SAVE_OK,		
		{	&im_opt_select_card,	&im_opti_select_card,	&im_optg_select_card,	&im_optf_select_card,	&im_opts_select_card},		// OPTION_TEXT_SELECT_CARD,	
		{	&im_zone_complete,		&im_zone_complete_i,	&im_zone_complete_g,	&im_zone_complete_f,	&im_zone_complete_s},		// OPTION_TEXT_ZONE_COMPLETE,	
		{	&im_opt_save_failed,	&im_opti_save_failed,	&im_optg_save_failed,	&im_optf_save_failed,	&im_opts_save_failed},		// OPTION_TEXT_SAVE_FAILED,	
		{	&im_opt_format_failed,	&im_opti_format_failed,	&im_optg_format_failed,	&im_optf_format_failed,	&im_opts_format_failed},	// OPTION_TEXT_FORMAT_FAILED,	
		{	&im_opt_format,			&im_opti_format,		&im_optg_format,		&im_optf_format,		&im_opts_format},			// OPTION_TEXT_UNFORMATTED,	
		{	&im_opt_load_failed,	&im_opti_load_failed,	&im_optg_load_failed,	&im_optf_load_failed,	&im_opts_load_failed},		// OPTION_TEXT_LOAD_FAILED,	
		{	&im_hop_to_it,			&im_hop_to_it_i,		&im_hop_to_it_g,		&im_hop_to_it_f,		&im_hop_to_it_s},			// OPTION_TEXT_HOP_TO_IT,		
		{	&im_go_frogger,			&im_go_frogger_i,		&im_go_frogger_g,		&im_go_frogger_f,		&im_go_frogger_s},			// OPTION_TEXT_GO_FROGGER,		
		{	&im_go,					&im_go_i,				&im_go_g,				&im_go_f,				&im_go_s},					// OPTION_TEXT_GO,				
		{	&im_go_get_em,			&im_go_get_em_i,		&im_go_get_em_g,		&im_go_get_em_f,		&im_go_get_em_s},			// OPTION_TEXT_GO_GET_EM,		
		{	&im_jump_to_it,			&im_jump_to_it_i,		&im_jump_to_it_g,		&im_jump_to_it_f,		&im_jump_to_it_s},			// OPTION_TEXT_JUMP_TO_IT,		
		{	&im_croak,				&im_croak_i,			&im_croak_g,			&im_croak_f,			&im_croak_s},				// OPTION_TEXT_CROAK,			
		{	&im_select_level,		&im_select_level_i,		&im_select_level_g,		&im_select_level_f,		&im_select_level_s},		// OPTION_TEXT_SELECT_LEVEL,	
		{	&im_opt_view_hs,		&im_opti_view_hs,		&im_optg_view_hs,		&im_optf_view_hs,		&im_opts_view_hs},			// OPTION_TEXT_VIEW_HISCORES,	
		{	&im_play_again,			&im_play_again_i,		&im_play_again_g,		&im_play_again_f,		&im_play_again_s},			// OPTION_TEXT_PLAY_AGAIN,		
		{	&im_choose_course,		&im_choose_course_i,	&im_choose_course_g,	&im_choose_course_f,	&im_choose_course_s},		// OPTION_TEXT_CHOOSE_COURSE,	
		{	&im_start_race,			&im_start_race_i,		&im_start_race_g,		&im_start_race_f,		&im_start_race_s},			// OPTION_TEXT_START_RACE,		
		{	&im_opt_check_save,		&im_opti_check_save,	&im_optg_check_save,	&im_optf_check_save,	&im_opts_check_save},		// OPTION_TEXT_CHECK_SAVE,
		{	&im_timeout,			&im_timeout_i,			&im_timeout_g,			&im_timeout_f,			&im_timeout_s},				// OPTION_TEXT_TIMEOUT,
		{	&im_bonus,				&im_bonus_i,			&im_bonus_g,			&im_bonus_f,			&im_bonus_s},				// OPTION_TEXT_BONUS,
		{	&im_opt_big_continue,	&im_opti_big_continue,	&im_optg_big_continue,	&im_optf_big_continue,	&im_opts_big_continue},		// OPTION_TEXT_BIG_CONTINUE,
		{	&im_skip_hi_score,		&im_skip_hi_score_i,	&im_skip_hi_score_g,	&im_skip_hi_score_f,	&im_skip_hi_score_s},		// OPTION_TEXT_SKIP_HI_SCORE,
		{	&im_opt_now_saving,		&im_opti_now_saving,	&im_optg_now_saving,	&im_optf_now_saving,	&im_opts_now_saving},		// OPTION_TEXT_NOW_SAVING,
		{	&im_opt_now_loading,	&im_opti_now_loading,	&im_optg_now_loading,	&im_optf_now_loading,	&im_opts_now_loading},		// OPTION_TEXT_NOW_LOADING,
		{	&im_opt_now_formatting,	&im_opti_now_formatting,&im_optg_now_formatting,&im_optf_now_formatting,&im_opts_now_formatting},	// OPTION_TEXT_NOW_FORMATTING,
		{	&im_opt_now_checking,	&im_opti_now_checking,	&im_optg_now_checking,	&im_optf_now_checking,	&im_opts_now_checking},		// OPTION_TEXT_NOW_CHECKING,
	};		
		



// Options ------------------------------------------------

MR_MAT*			Options_extras_matrix_ptr[OPTIONS_NUM_EXTRAS];
MR_OBJECT*		Options_extras_object_ptr[OPTIONS_NUM_EXTRAS];
MR_MESH_INST*	Options_extras_mesh_inst_ptr[OPTIONS_NUM_EXTRAS];

MR_ULONG		Options_extras_resource_id[] =
	{
	RES_OPT_MUSIC_XMU,
	RES_OPT_SFX_XMU,

	RES_OPT_STAT_BULLRUSH_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_LILLY_XMR,
	RES_OPT_STAT_BULLRUSH_XMR,
	};

MR_LONG			Options_extras_coords[] =
	{
	 0x400, -0x280,	// music
	 0x400, -0x400,	// sfx 

	-0x680,  0x520,	// left bullrush
	 0x180,  0x680,	// middle lilly
	 0x580,  0x440,	// right lilly
	-0x600,  0x100,	// left lilly
	 0x040, -0x580,	// bottom bullrush
	};

MR_TEXTURE*		Options_title_textures[MAX_NUM_LANGUAGES][5]=
	{
		{
		// English, normal
		&im_opt_exit,
		&im_opt_view_hs,
		&im_opt_load_hs,
		&im_opt_save_hs,
		&im_opt_ctrl_config,
		},
		{
		&im_opti_exit,
		&im_opti_view_hs,
		&im_opti_load_hs,
		&im_opti_save_hs,
		&im_opti_ctrl_config,
		},
		{
		&im_optg_exit,
		&im_optg_view_hs,
		&im_optg_load_hs,
		&im_optg_save_hs,
		&im_optg_ctrl_config,
		},
		{
		&im_optf_exit,
		&im_optf_view_hs,
		&im_optf_load_hs,
		&im_optf_save_hs,
		&im_optf_ctrl_config,
		},
		{
		&im_opts_exit,
		&im_opts_view_hs,
		&im_opts_load_hs,
		&im_opts_save_hs,
		&im_opts_ctrl_config,
		},
	};

// These are copies of the above MR_TEXTUREs, with abr of 2 (subtractive)
MR_TEXTURE		Options_shadow_textures[OPTIONS_NUM_OPTIONS];

MR_ULONG		Options_update_mode;
MR_ULONG		Options_current_selection;

MR_ULONG		Game_language;
MR_2DSPRITE*	Language_flag_sprites_ptr[MAX_NUM_LANGUAGES];
MR_TEXTURE*		Language_flag_textures_ptr[MAX_NUM_LANGUAGES][2]=
	{
#ifdef GAME_TIMS_BODGED_COMPILE
	NULL, NULL,
	NULL, NULL,
	NULL, NULL,
	NULL, NULL,
	NULL, NULL,
#else
	&im_opt_flag_brit1,&im_opt_flag_brit2,
	&im_opt_flag_ital1,&im_opt_flag_ital2,
	&im_opt_flag_germ1,&im_opt_flag_germ2,
	&im_opt_flag_fren1,&im_opt_flag_fren2,
	&im_opt_flag_span1,&im_opt_flag_span2,
#endif
	};

MR_ULONG	Options_language_mode;
MR_BOOL		From_options;					// Flag to tell ( TRUE ) if we selected this from the options list

MR_UBYTE	Music_volume = OPTION_START_MUSIC_VALUE;	// Volume for music
MR_UBYTE	Sound_volume = OPTION_START_SOUND_VALUE;	// Volume for sound effects
MR_LONG		Sound_voice = -1;							// Voice for test sample

// Language resources
MR_ULONG	Language_res[]=
	{
	RES_FIXE_VRAM_VLO,
	RES_FIXI_VRAM_VLO,
	RES_FIXG_VRAM_VLO,
	RES_FIXF_VRAM_VLO,
	RES_FIXS_VRAM_VLO,
	};

// Redefine Buttons ( PSX ONLY ) --------------------------

#ifdef PSX

// Pad images
MR_TEXTURE*		Pad_text_images[MAX_NUM_LANGUAGES][MAX_NUM_PAD_CONFIGS] =
	{
		{
		&im_opt_joypad_layout1,
		&im_opt_joypad_layout2,
		&im_opt_joypad_layout3,
		&im_opt_joypad_layout4,
		},
		{
		&im_opti_joypad_layout1,
		&im_opti_joypad_layout2,
		&im_opti_joypad_layout3,
		&im_opti_joypad_layout4,
		},
		{
		&im_optg_joypad_layout1,
		&im_optg_joypad_layout2,
		&im_optg_joypad_layout3,
		&im_optg_joypad_layout4,
		},
		{
		&im_optf_joypad_layout1,
		&im_optf_joypad_layout2,
		&im_optf_joypad_layout3,
		&im_optf_joypad_layout4,
		},
		{
		&im_opts_joypad_layout1,
		&im_opts_joypad_layout2,
		&im_opts_joypad_layout3,
		&im_opts_joypad_layout4,
		},
	};

// Pad configurations
MR_ULONG		Pad_configs[MAX_NUM_PADS] = {0,0,0,0};

// Pad sprite ptrs
MR_2DSPRITE*	Pad_sprite_ptrs[MAX_NUM_PADS];
MR_2DSPRITE*	Pad_text_sprite_ptrs[MAX_NUM_PADS];
MR_2DSPRITE*	Pad_insert_sprite_ptrs[MAX_NUM_PADS];
MR_2DSPRITE*	Pad_arrow_sprite_ptrs[MAX_NUM_PADS*2];

#endif

// Choose Controller ( WIN95 ONLY ) -----------------------

#ifdef WIN95

MR_TEXT_AREA*	Option_choose_win_controller_text_area;
MR_STRPTR		Option_choose_win_controller_text_title[]	=	{"%jcCHOOSE WIN CONTROLLER", NULL};

#endif


#ifdef WIN95

// Let's now define our GUID
// {D3EE8F73-D7EA-11d0-8069-0020AFF4866A}
DEFINE_GUID(FROGGER_GUID, 0x31fab820, 0xe959, 0x11d0, 0x80, 0x81, 0x0, 0x20, 0xaf, 0xf4, 0x86, 0x6a);

//------------------------------------------------------------------
// Multiplayer mode Options 
//
MR_TEXT_AREA*	Option_multiplayer_mode_text_area[3];

MR_STRPTR		Option_multiplayer_mode_text[3][50]	=
				{		
				{"%jcMULTIPLAYER GAME OPTIONS", NULL},
				{"%jcLOCAL RACE", NULL},
				{"%jcNETWORK RACE", NULL},
				};

MR_ULONG		Option_multiplayer_mode = OPTION_MULTIPLAYER_MODE_LOCAL;


//------------------------------------------------------------------
// Multiplayer network service provider Options 
//
MR_TEXT_AREA*	Option_network_type_text_area[OPTION_NETWORK_TYPE_MAX_ENTRIES];
MR_STRPTR		Option_network_type_text_buff[OPTION_NETWORK_TYPE_MAX_ENTRIES][70];
MR_STRPTR		Option_network_type_text_tag	= "%jc%s";
MR_ULONG		Option_network_type_number_providers;
MR_ULONG		Option_network_type_selected_provider;

//------------------------------------------------------------------
// Multiplayer network host Options 
//
MR_TEXT_AREA*	Option_network_host_title_area;
MR_STRPTR		Option_network_host_title_text[] = {"%jcSELECT GAME TO ENTER OR START NEW GAME", NULL};
MR_TEXT_AREA*	Option_network_host_text_area[OPTION_NETWORK_HOST_MAX_ENTRIES];
MR_STRPTR		Option_network_host_text_buff[OPTION_NETWORK_HOST_MAX_ENTRIES][70];
MR_STRPTR		Option_network_host_text_tag	= "%jc%s";
MR_ULONG		Option_network_host_number_sessions;
MR_LONG			Option_network_host_selected_session;

//------------------------------------------------------------------
// Multiplayer network play Options 
//
MR_TEXT_AREA*	Option_network_play_title_area;
MR_STRPTR		Option_network_play_title_text[] = {"%jcPLAYERS IN THIS GAME", NULL};
MR_TEXT_AREA*	Option_network_play_text_area[OPTION_NETWORK_PLAY_MAX_ENTRIES];
MR_STRPTR		Option_network_play_text_buff[OPTION_NETWORK_PLAY_MAX_ENTRIES][70];
MR_STRPTR		Option_network_play_text_tag	= "%jc%s";
MR_ULONG		Option_network_play_number_players;

#endif

//------------------------------------------------------------------
// Frog Selection 
//
FROG_SELECTION	Frog_selection[4];			// Misc data for each Frog

MR_ANIM_ENV*		Frog_anim_env_ptr[4];			// Anim env created
MR_ANIM_ENV_INST*	Frog_anim_inst_ptr[4];			// Instance of anim env added to viewport
MR_VEC				Frog_anim_position[4]=			// Position of each Frog on screen
	{
	{-150, -20, 0},
	{ 150, -20, 0},
	{-150, 180, 0},
	{ 150, 180, 0},
	};

//MR_ULONG	Frog_selection_animation_count[4];		// Animation frame count ( 0 - when at end of animation )
MR_ULONG		Frog_selection_master_flags;		// Frog selection flags
MR_ULONG		Frog_selection_number_players;		// Number of players in game (upto 4)
MR_ULONG		Frog_selection_states[4];			// NULL for no pad, 1 for pad but not selected, 2 for pad and selected
MR_2DSPRITE*	Frog_selection_sprites[4];			// sprites for INSERT CONTROLLER

MR_ULONG	Frog_selection_network_request_flags;	// Network player input flags
MR_ULONG	Frog_selection_master_player_id;		// Master player id (in multiplayer network mode)
MR_ULONG	Frog_selection_request_flags;			// Frog selection request flags

MR_TEXT_AREA*	Option_frog_selection_text_area[8];

MR_STRPTR	Option_frog_selection_text[5][20]	=	// Test text
	{
	{"%jcWAITING TO JOIN", NULL},
	{"%jcSELECTING FROG", NULL},
	{"%jcFROG SELECTED", NULL},
	{"%jcMASTER", NULL},
	{"%jcSLAVE", NULL},
	};

// Test level selects -------------------------------------

MR_ULONG	Options_world_number;			// Number of world currently selected in level select
MR_ULONG	Options_level_number;			// Number of level currently selected in level select


// Continue -----------------------------------------------

MR_2DSPRITE*	Continue_title_sprite_ptr;
MR_2DSPRITE*	Continue_time_sprite_ptr;
MR_2DSPRITE*	Continue_no_sprite_ptr;
MR_2DSPRITE*	Continue_yes_sprite_ptr;
MR_2DSPRITE*	Continue_left_ptr;

MR_TEXTURE*		Continue_time_sprite_table[10]=
	{
		&im_32x32_0,
		&im_32x32_1,
		&im_32x32_2,
		&im_32x32_3,
		&im_32x32_4,
		&im_32x32_5,
		&im_32x32_6,
		&im_32x32_7,
		&im_32x32_8,
		&im_32x32_9,
	};

// Game Over ----------------------------------------------

MR_2DSPRITE*		Gameover_title_sprite_ptr;			// Pointer to 2D sprite

MR_2DSPRITE*		Playagain_pa_sprite_ptr;
MR_2DSPRITE*		Playagain_cc_sprite_ptr;
MR_2DSPRITE*		Playagain_ex_sprite_ptr;

// Level Complete -----------------------------------------

// Added by martin, for level select screen
OPT_LEVEL_COMPLETE	Level_complete;

//MR_LONG		Sel_first_phase_level_numbers[]	=
//			{
//			LEVEL_ORIGINAL1,
//			LEVEL_ORIGINAL2,
//			LEVEL_ORIGINAL3,
//			LEVEL_ORIGINAL4,
//			LEVEL_ORIGINAL5,
//			LEVEL_SUBURBIA1,
//			LEVEL_SUBURBIA2,
//			LEVEL_SUBURBIA3,
//			LEVEL_SUBURBIA4,
//			LEVEL_SUBURBIA5,
//			LEVEL_FOREST1,
//			LEVEL_FOREST2,
//			LEVEL_VOLCANO1,
//			LEVEL_VOLCANO2,
//			LEVEL_VOLCANO3,
//			-1
//			};

//MR_LONG		Sel_second_phase_level_numbers[]	=
//			{
//			LEVEL_CAVES1,
//			LEVEL_CAVES3,
//			LEVEL_CAVES4,
//			LEVEL_SKY1,
//			LEVEL_SKY2,
//			LEVEL_SKY4,
//			LEVEL_SKY3,
//			LEVEL_SWAMP1,
//			LEVEL_SWAMP2,
//			LEVEL_SWAMP3,
//			LEVEL_SWAMP4,
//			LEVEL_SWAMP5,
//			LEVEL_DESERT1,
//			LEVEL_DESERT2,
//			LEVEL_DESERT3,
//			LEVEL_DESERT4,
//			LEVEL_DESERT5,
//			-1
//			};

// Gloden Frog!!!
MR_ULONG	Animlist_level_complete_golden_frog[] =
	{
	MR_SPRT_SETSPEED,	1,
	MR_SPRT_SETCOUNT,	0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_0,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_1,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_2,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_3,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_4,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_5,
	MR_SPRT_SETIMAGE,	(MR_ULONG)&im_babyfroggold_6,
	MR_SPRT_LOOPBACK
	};

// Flag if first time in the intro
MR_BOOL		Intro_first_time 	  = TRUE;
MR_BOOL		Options_music_playing = FALSE;
MR_LONG		Demo_loading_mode	  = DEMO_LOADING_INIT;
MR_BOOL		Game_demo_loading	  = FALSE;
MR_BOOL		Game_over_no_new_sound = FALSE;

/******************************************************************************
*%%%% VersionStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID VersionStartup(MR_VOID)
*
*	FUNCTION	Start up code for version number screen.  Builds on screen text.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID VersionStartup(MR_VOID)
{
	// Allocate text area to display "version number", "compile time" and "date"
	Version_text_area[0] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)-20, Game_display_width, 16);
	Version_text_area[1] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)+20, Game_display_width, 16);
	Version_text_area[2] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)+30, Game_display_width, 16);
	Version_text_area[3] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)+40, Game_display_width, 16);
}

/******************************************************************************
*%%%% VersionUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID VersionUpdate(MR_VOID)
*
*	FUNCTION	Update code for version number screen.  Waits for fire button.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID VersionUpdate(MR_VOID)
{
	// Any button pressed ?
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// Yes ... exit
#ifdef PSX
#ifdef	PSX_MODE_PAL
		// Go on to AntiPiracy
		Option_page_request = OPTIONS_PAGE_ANTI_PIRACY;
#else
		// Go on to Hasbro Logo
		Option_page_request = OPTIONS_PAGE_HASBRO_LOGO;
#endif
#else
		// Go on to Hasbro Logo
		Option_page_request = OPTIONS_PAGE_HASBRO_LOGO;
#endif
		}
	else
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_SELECT))
		{
		// Cheat for QA: display water for video
		Option_page_request = OPTIONS_PAGE_SHOW_WATER;
		}
}

/******************************************************************************
*%%%% VersionShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID VersionShutdown(MR_VOID)
*
*	FUNCTION	Shut down code for version number screen.  Frees text.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	10.07.97	William Bell	Created
*	21.07.97	Gary Richards	Added code to try and stop memory fragmentation.
*
*%%%**************************************************************************/

MR_VOID VersionShutdown(MR_VOID)
{
	// Free text areas
	MRFreeTextArea(Version_text_area[3]);
	MRFreeTextArea(Version_text_area[2]);
	MRFreeTextArea(Version_text_area[1]);
	MRFreeTextArea(Version_text_area[0]);

	// Give API a chance to tidy these Free's.
	OptionsTidyMemory(FALSE);
}

#ifdef PSX	// PSX specific code --------------------------------------------

/******************************************************************************
*%%%% AntiPiracyStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	AntiPiracyStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Anti Piracy screen.  Create the 2D
*				sprite for the anti piracy logo.  And initialise time
*			to display for.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	AntiPiracyStartup(MR_VOID)
{
   	// Set back ground colour
	MRSetDisplayClearColour(0x00,0x00,0x00);

#ifdef	PSX_MODE_PAL
	// Load Sony warning and other start up gfx
	MRLoadResource(RES_START_VRAM_VLO);
	MRProcessResource(RES_START_VRAM_VLO);
	MRUnloadResource(RES_START_VRAM_VLO);

	// Create sprite for piracy message
	Warning_ptr = MRCreate2DSprite(56,25,Option_viewport_ptr,&im_sonywarn,NULL);
#else
	// Load Frogger Logo for other Areas.
	MRLoadResource(RES_STARTNTSC_VLO);
	MRProcessResource(RES_STARTNTSC_VLO);
	MRUnloadResource(RES_STARTNTSC_VLO);

	// Create sprite for piracy message
	Warning_ptr = MRCreate2DSprite(56,25,Option_viewport_ptr,&im_froglogo,NULL);
#endif

	// Set time Anti Piracy on screen for
	Anti_piracy_count = ANTI_PIRACY_TIME;
}

/******************************************************************************
*%%%% AntiPiracyUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	AntiPiracyUpdate(MR_VOID)
*
*	FUNCTION	Update code for Anti Piracy screen.  Wait for time limit
*			to expire before continuing to Hasbro logo.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	AntiPiracyUpdate(MR_VOID)
{
	// Are we the first time though this function?? (Wait for the screen to be drawn!)
	if ( Anti_piracy_count == (ANTI_PIRACY_TIME - 5))
		{
		// Load the GENERIC SFX (Theses stay loaded all the time,until the game is quit!!)
		// Load these while the Anti-Piracy screen is up. (Hopefully they will be loaded in 5 secs)
		Game_map_theme = 0;
		InitialiseVab();
		}

	// Has frame count reached zero ?
	if ( !Anti_piracy_count-- )
		{
		// Yes ... skip to Hasbro logo
		Option_page_request = OPTIONS_PAGE_HASBRO_LOGO;
		}
}

/******************************************************************************
*%%%% AntiPiracyShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	AntiPiracyShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Anti Piracy screen.  Kill the 2D sprites.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	AntiPiracyShutdown(MR_VOID)
{
#ifdef	PSX_MODE_PAL
	// Remove piracy sprite from display
	MRKill2DSprite(Warning_ptr);
#endif
}

#endif	// PSX

/******************************************************************************
*%%%% HasbroLogoStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HasbroLogoStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Hasbro Logo screen.  Currently does nothing.
*				Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HasbroLogoStartup(MR_VOID)
{

	// Do nothing ... ( yet !!! )

}

/******************************************************************************
*%%%% HasbroLogoUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HasbroLogoUpdate(MR_VOID)
*
*	FUNCTION	Update code for Hasbro Logo screen.  Start playing the stream
*				and go on to the next page when this has finished.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HasbroLogoUpdate(MR_VOID)
{

	// Locals
	MR_BOOL			fmv_skipped;

	// Initialise
	fmv_skipped = FALSE;

#ifdef	PSX_CD_STREAMS

	// Play HASBRO logo video stream
	fmv_skipped = Play_stream(STR_HASBRO_LOGO);

#endif	// PSX_CD_STREAMS

// IF THE PLAYER SKIPS THE LOGO, THEY SHOULD SEE THE INTRO. AT LEAST IAN THINKS SO!

	// Was logo skipped ?
//	if ( fmv_skipped == TRUE )
//		{
//#ifdef PSX_MODE_PAL
//		// Yes ... go on to language selection
//		Option_page_request = OPTIONS_PAGE_LANGUAGE_SELECTION;
//#else
//		// Yes ... go on to check saves
//		Option_page_request = OPTIONS_PAGE_CHECK;
//#endif
//		}
//	else
//		{
		// No ... go on to intro
		Option_page_request = OPTIONS_PAGE_INTRO;
//		}

}

/******************************************************************************
*%%%% HasbroLogoShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	HasbroLogoShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Hasbro Logo screen.  Currently does nothing.
*				Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	HasbroLogoShutdown(MR_VOID)
{

	// Do nothing ... ( yet!!! )

}

/******************************************************************************
*%%%% MillenniumLogoStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MillenniumLogoStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Millennium Logo screen.  Currently does
*				nothing.  Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	MillenniumLogoStartup(MR_VOID)
{

	// Do nothing ... ( yet!!! )

}

/******************************************************************************
*%%%% MillenniumLogoUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MillenniumLogoUpdate(MR_VOID)
*
*	FUNCTION	Update code for Millennium Logo screen.  Start playing the Millennium
*				logo stream and then go on to the read memory card when this returns.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	04.08.97	Gary Richards	No longer needed as we are now SONY.
*
*%%%**************************************************************************/

MR_VOID	MillenniumLogoUpdate(MR_VOID)
{

#ifdef	PSX_CD_STREAMS

	// Play MILLENNIUM logo video stream
	// Play_stream(STR_MILLENNIUM_LOGO);

#endif	// PSX_CD_STREAMS

	// Go on to check saves
	Option_page_request = OPTIONS_PAGE_INTRO;

}

/******************************************************************************
*%%%% MillenniumLogoShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MillenniumLogoShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Millennium Logo screen.  Currently does nothing.
*				Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	MillenniumLogoShutdown(MR_VOID)
{

	// Do nothing ... ( yet!!! )

}

/******************************************************************************
*%%%% IntroStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	IntroStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Intro screen.  Does nothing at the moment.
*			Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	26.08.97	Gary Richards	Added New Stream Playback code.
*
*%%%**************************************************************************/

MR_VOID	IntroStartup(MR_VOID)
{
#ifdef	PSX
	// Kill all viewports/camera frames etc...
	KillOptionsForStream();

	// Create 24bit for stream playback.
	MRCreateDisplay(MR_SCREEN_TRUECOLOUR_STANDARD_256);

	// Play the Intro Stream.
#ifdef	PSX_CD_STREAMS

	// Play Intro stream
	Play_stream(STR_INTRO);

#endif	// PSX_CD_STREAMS

	// Remove the 24Bit display.
	MRKillDisplay();	

	// Create a standard one in it's place.
	MRCreateDisplay(SYSTEM_DISPLAY_MODE);
		 
	// Now we have to put everything back to how it was.
	CreateOptionsAfterStream();
#endif
}

/******************************************************************************
*%%%% IntroUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	IntroUpdate(MR_VOID)
*
*	FUNCTION	Update code for Intro screen.  Start the FMV stream and go on
*				to the main options screen when this has finished.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	04.07.97	Gary Richards	Remove the Intro Stream.
*
*%%%**************************************************************************/

MR_VOID	IntroUpdate(MR_VOID)
{
	// First time in intro ?
	if ( Intro_first_time == TRUE )
		{
#ifdef PSX_MODE_PAL
		// Yes ... go on to language selection
		Option_page_request = OPTIONS_PAGE_LANGUAGE_SELECTION;
#else
		// Yes ... go on to check memory cards
		Option_page_request = OPTIONS_PAGE_CHECK;
#endif
		// Flag first time as over
		Intro_first_time = FALSE;
		}
	else
		{
		// No ... go on to main options
		Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
		}

}

/******************************************************************************
*%%%% IntroShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	IntroShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Intro screen.  Does nothing at the moment.
*			Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	IntroShutdown(MR_VOID)
{

	// Do nothing ... ( yet!!! )

}

/******************************************************************************
*%%%% MainOptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MainOptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Main Options screen.  Currently just
*				builds text area for the three choices.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	28.07.97	Gary Richards	Changed the order of loads.
*
*%%%**************************************************************************/

MR_VOID	MainOptionsStartup(MR_VOID)
{
	MR_TEXTURE*	texture;
	MR_ULONG	width;
	MR_ULONG	loop_counter;
	POLY_FT4*	poly_ft4;

	// Load options resources
	LoadOptionsResources();			// This MUST be loaded here to keep memory order.

	// Load GEN wad
	LoadGenericWad(0);				// This MUST be loaded first to keep memory order.

	// Display main 3 entry menu
	texture		= Options_text_textures[OPTION_TEXT_START][Game_language];
	Start_ptr	= MRCreate2DSprite((Game_display_width - texture->te_w) >> 1, Game_display_height - MAIN_MENU_Y_OFFSET +  0 + 80, Option_viewport_ptr, texture, NULL);

	texture		= Options_text_textures[OPTION_TEXT_RACE][Game_language];
	Race_ptr	= MRCreate2DSprite((Game_display_width - texture->te_w) >> 1, Game_display_height - MAIN_MENU_Y_OFFSET + 16 + 80, Option_viewport_ptr, texture, NULL);

	texture		= Options_text_textures[OPTION_TEXT_OPTIONS][Game_language];
	Options_ptr	= MRCreate2DSprite((Game_display_width - texture->te_w) >> 1, Game_display_height - MAIN_MENU_Y_OFFSET + 32 + 80, Option_viewport_ptr, texture, NULL);

	Option_spcore_ptrs[0] = (MR_SP_CORE*)Start_ptr;
	Option_spcore_ptrs[1] = (MR_SP_CORE*)Race_ptr;
	Option_spcore_ptrs[2] = (MR_SP_CORE*)Options_ptr;

	// Calculate width and height of subtractive poly area
	width 		= MAX(Options_text_textures[OPTION_TEXT_START][Game_language]->te_w,
				  MAX(Options_text_textures[OPTION_TEXT_RACE][Game_language]->te_w,
				  Options_text_textures[OPTION_TEXT_OPTIONS][Game_language]->te_w)) + (OPTIONS_CLOUD_BORDER << 1);

	poly_ft4	= Cloud_polys;
	texture		= &im_opt_menu_cloud;
	// Loop once for each poly
	for(loop_counter=0;loop_counter<2;loop_counter++)
		{
		// Set poly code
		MR_SET32(poly_ft4->r0, 0x404040);
		setPolyFT4(poly_ft4);
		setSemiTrans(poly_ft4, 1);

		// Set poly position
		poly_ft4->x0 = (Game_display_width>>1)-(width>>1);
		poly_ft4->y0 = (Game_display_height - MAIN_MENU_Y_OFFSET +  0)-OPTIONS_CLOUD_BORDER;
		poly_ft4->x1 = (Game_display_width>>1)+(width>>1);
		poly_ft4->y1 = (Game_display_height - MAIN_MENU_Y_OFFSET +  0)-OPTIONS_CLOUD_BORDER;
		poly_ft4->x2 = (Game_display_width-width)>>1;
		poly_ft4->y2 = (Game_display_height - MAIN_MENU_Y_OFFSET + 32) + Options_text_textures[OPTION_TEXT_OPTIONS][Game_language]->te_h + 16;
		poly_ft4->x3 = (Game_display_width+width)>>1;
		poly_ft4->y3 = (Game_display_height - MAIN_MENU_Y_OFFSET + 32) + Options_text_textures[OPTION_TEXT_OPTIONS][Game_language]->te_h + 16;

#ifdef PSX
		MR_COPY32(poly_ft4->u0, texture->te_u0);
		MR_COPY32(poly_ft4->u1, texture->te_u1);
#else
		MR_COPY16(poly_ft4->u0, texture->te_u0);
		MR_COPY16(poly_ft4->u1, texture->te_u1);
		poly_ft4->tpage = texture->te_tpage_id;
#endif
		MR_COPY16(poly_ft4->u2, texture->te_u2);
		MR_COPY16(poly_ft4->u3, texture->te_u3);
		poly_ft4++;
		}

	// Initialise option number variable
	Option_number 		= 0;
	From_options		= FALSE;
	Main_options_status = MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT;

}


/******************************************************************************
*%%%% MainOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MainOptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for Main Options screen.  Currently just reads input,
*				moves selection and allows the user to exit with there current
*				selection.  Also shows game demo or high score tables in
*				background from time to time.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	MainOptionsUpdate(MR_VOID)
{
	static	MR_ULONG	score_time;
	MR_ULONG			count;
	SEL_LEVEL_INFO*		sel_level_info_ptr;
	MR_BOOL				valid_demo_level;
	MR_OBJECT*			object_ptr;
	MR_UBYTE			i;
	POLY_F4*			poly_f4;
	MR_LONG				Sectors_left;
	MR_TEXTURE*			texture;

	//-------------------------------------------------------------------------------
	// This handles stuff for hiscore view and demo mode
	//-------------------------------------------------------------------------------
	//
	// Depending on mode of operation do...
	switch (Main_options_status)
		{
		// Initialise a demo level ...
		case MAIN_OPTIONS_STATUS_DEMO_INIT:
			// This is so we can do an async load -----------------------------------
			switch (Demo_loading_mode)
				{
				case DEMO_LOADING_INIT:
					// Flag that we are loading the Demo.
					Game_demo_loading = TRUE;
					// Move the Options Menu Off Screen.
					High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
					// Turn On Loading Sprite.
					texture					= Options_text_textures[OPTION_TEXT_LOADING][Game_language];
					Sel_loading_sprite_ptr->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
					MRChangeSprite(Sel_loading_sprite_ptr,texture);
					Sel_loading_sprite_ptr->sp_pos.x = (Game_display_width >> 1) - (texture->te_w >> 1);
					Sel_loading_sprite_ptr->sp_pos.y = (Game_display_height >> 1) - (texture->te_h >> 1);
					Sel_loading_sprite_ptr->sp_core.sc_ot_offset = 1;

					Sel_loading_sprite_ptr->sp_core.sc_base_colour.r = 0;
					Sel_loading_sprite_ptr->sp_core.sc_base_colour.g = 0;
					Sel_loading_sprite_ptr->sp_core.sc_base_colour.b = 0;

					// Shutdown the Options music.
					ShutdownOptionsMusic();
					
					// Remove the Options when going into Demo Mode, to stop textures getting trashed.
					//
					// The following also deinits the water
					UnloadOptionsResources();

					// Initialise selected demo level in one player mode
					Game_total_players 		= 1;
					Game_total_viewports 	= 1;
					Game_map 				= Demo_level_table[Num_demo_levels_seen][0];
					
					// Set up controller and other information
					for (count=0; count<4; count++)
						{
#ifdef WIN95			
						Frog_player_data[count].fp_is_local = 1;
#endif					
						Frog_player_data[count].fp_port_id	= count;
						}
					
					// Switch off HUD
					Game_flags &= ~(GAME_FLAG_HUD_SCORE|GAME_FLAG_HUD_TIMER|GAME_FLAG_HUD_HELP|GAME_FLAG_HUD_CHECKPOINTS|GAME_FLAG_HUD_LIVES);
					
					// Set up start position (Taken out cos it was causing a crash.
					// I think that Map_general_header is pointing to the LAST map and not
					// the new one, so is overwritting memory.
					// It gets set in InitialiseMap Anyway! $gr
					//Map_general_header->gh_start_x = Demo_data_ptr->dd_start_grid_x;
					//Map_general_header->gh_start_z = Demo_data_ptr->dd_start_grid_z;
					
					// $wb - Remove all high score objects from display ( including those annoying splashes! )
					// Remove ALL objects from display
					object_ptr = MRObject_root_ptr;
					while(object_ptr = object_ptr->ob_next_node)
						{
							object_ptr->ob_flags |= MR_OBJ_NO_DISPLAY;
						}

					
					// Load demo data (async)
					MRLoadResourceAsync(Demo_level_table[Num_demo_levels_seen][1]);
					
					Demo_loading_mode = DEMO_LOADING_DEMO_LOADING;
				  	break;
				// ---------------------------------------------------------------------------------------
				case DEMO_LOADING_DEMO_LOADING:
					// Get Status of Async Loading.
					Sectors_left = MRGetAsyncStatus(Demo_level_table[Num_demo_levels_seen][1]);

					// Scroll 2Dsprite menu if necessary
					if (High_score_view_flyoff_counter--)
						{
						Start_ptr->sp_pos.y 	+= 8;
						Race_ptr->sp_pos.y 		+= 8;
						Options_ptr->sp_pos.y 	+= 8;
						Sel_loading_sprite_ptr->sp_core.sc_base_colour.r += 16;
						Sel_loading_sprite_ptr->sp_core.sc_base_colour.g += 16;
						Sel_loading_sprite_ptr->sp_core.sc_base_colour.b += 16;
						}

					// Wait for Async to happen.			
					if ((Sectors_left <= 0) && (!(High_score_view_flyoff_counter)))
						{
						MRProcessResource(Demo_level_table[Num_demo_levels_seen][1]);

						// Get addresses of demo playbacks in memory
						Demo_data_ptr = MR_GET_RESOURCE_ADDR(Demo_level_table[Num_demo_levels_seen][1]);

						// Once loaded, go on to next.
						Demo_loading_mode   = DEMO_LOADING_GAME_START;
						// Wait for this function to finished before going on.
						Game_start_mode = GAME_START_INIT;
						}
					break;
				// ----------------------------------------------------------------------------------------
				case DEMO_LOADING_GAME_START:
					// Initialise level
					switch(Game_start_mode)
						{
						// -----------------------------------------------
						case GAME_START_INIT:
							GameStart();
							Game_start_mode++;
							break;
						// -----------------------------------------------
						case GAME_START_RUNNING:							
							Game_start_mode++;
							break;
						// -----------------------------------------------
						case GAME_START_FINISHED:
							Demo_loading_mode = DEMO_LOADING_LEVEL_START;
							break;
						// -----------------------------------------------
						}
					break;
				// ----------------------------------------------------------------------------------------
				case DEMO_LOADING_LEVEL_START:
					// Start level
					LevelStart(GAME_MODE_LEVEL_FAST_START);
				
					// Set time to run demo for
					Demo_time = Demo_data_ptr->dd_num_frames;
				
					// Set up pointer to demo mode input data
					Demo_data_input_ptr = &Demo_data_ptr->dd_input_data[0];
					
					// Go on to main update
					Main_options_status = MAIN_OPTIONS_STATUS_DEMO_MAIN;
					Demo_loading_mode = DEMO_LOADING_INIT;

					// Flag demo as running
					Game_flags |= GAME_FLAG_DEMO_RUNNING;

					// Move the Options Menu On Screen.
					High_score_view_flyon_counter 	= OPTIONS_CAMERA_FLYON_TIME;

					// Flag that we have finished loading the Demo.
					Game_demo_loading = FALSE;
					break;
				// --------------------------------------------------------------------------------------
				}
			break;

		// Run demo level ...
		case MAIN_OPTIONS_STATUS_DEMO_MAIN:

			// Scroll 2Dsprite menu if necessary
			if (High_score_view_flyon_counter)
				{
				Start_ptr->sp_pos.y 	-= 8;
				Race_ptr->sp_pos.y 		-= 8;
				Options_ptr->sp_pos.y 	-= 8;
				High_score_view_flyon_counter--;
				}
	
			// Update demo level
			GameMainloop();

			// End of demo level ? (decreased in GameUpdateLogic)
			if (Demo_time == 30)
				{
				// Yes ... go on to finish
				Main_options_status = MAIN_OPTIONS_STATUS_DEMO_FADE_OUT;
//				Main_options_status = MAIN_OPTIONS_STATUS_DEMO_FINISH;
				// Set fade time
				Options_count_down_units = 30;
				// Move the Options Menu Off Screen.
				High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
				// Loading Sprite as well Please.
				Sel_loading_sprite_ptr->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
				// Increase the brightness of the Loading Sprite.
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.r = 0;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.g = 0;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.b = 0;
				}

			break;

		// Fade out last frame of demo mode ...
		case MAIN_OPTIONS_STATUS_DEMO_FADE_OUT:

			// Update demo level
			GameMainloop();

			// Scroll 2Dsprite menu if necessary
			if (High_score_view_flyoff_counter)
				{
				Start_ptr->sp_pos.y 	+= 8;
				Race_ptr->sp_pos.y 		+= 8;
				Options_ptr->sp_pos.y 	+= 8;

				// Increase the brightness of the Loading Sprite.
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.r += 16;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.g += 16;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.b += 16;

				High_score_view_flyoff_counter--;
				}

			// Dec count down
			Options_count_down_units--;

			// Fade screen over 1 second, and GAME OVER sprite up in same time
			i 			= MIN(0xff, ((30 - Options_count_down_units) * 0xff) / 30);
			poly_f4 	= &Pause_poly[MRFrame_index];
			poly_f4->r0 = i;
			poly_f4->g0 = i;
			poly_f4->b0 = i;

			// Add faded poly
			GamePauseAddPrim();

			// End of count down ?
			if ( !Options_count_down_units )
				{
				// Yes ... go on to finish
				Main_options_status = MAIN_OPTIONS_STATUS_DEMO_FINISH;
				}
			
			break;

		// Finish demo level ...
		case MAIN_OPTIONS_STATUS_DEMO_FINISH:
			// Add faded poly
			GamePauseAddPrim();

			// Deinitialise selected demo level
			GameEnd();

			// Flag demo mode as NOT running
			Game_flags &= ~GAME_FLAG_DEMO_RUNNING;
			Game_flags |= (GAME_FLAG_HUD_SCORE|GAME_FLAG_HUD_TIMER|GAME_FLAG_HUD_HELP|GAME_FLAG_HUD_CHECKPOINTS|GAME_FLAG_HUD_LIVES);

			// Unload resources ( before we inc demo number )
			MRUnloadResource(Demo_level_table[Num_demo_levels_seen][1]);

			// Flag no valid demo level found
			valid_demo_level = FALSE;

			// Loop until we find a valid demo level to play
			do
				{
					// Inc number of demo levels played
					Num_demo_levels_seen++;

					// Have all demo levels been seen ?
					if ( Demo_level_table[Num_demo_levels_seen][0] == -1 )
						// Yes ... reset level number
						Num_demo_levels_seen = 0;

					// Is this world open ?
					if ( SelectGetLevelFlags(Demo_level_table[Num_demo_levels_seen][2]) & SEL_LF_SELECTABLE )
						// Yes ... flag valid demo level
						valid_demo_level = TRUE;

				}
			while ( valid_demo_level == FALSE );

			// Have all demo levels been seen ?
			if ( Num_demo_levels_seen == 0 )
				{
				// Yes ... go back to the intro
				Option_page_request = OPTIONS_PAGE_INTRO;
				// Fool MainOptionsShutdown() in to thinking not to run GameEnd()
				Main_options_status = MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT;
				}
			else
				{
				// Go on to initialise high score mode
				Main_options_status = MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT;
				}

			// Reload the options resource, to reset trashed textures.  Also sets up water
			LoadOptionsResources();
			LoadGenericWad(0);

 			OptionsCameraSnapToMain();
			// Turn OFF the loading Sprite.
			Sel_loading_sprite_ptr->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

			break;

		// Initialise high score table view ...
		case MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_INIT:

			// Ensure camera starts where it should
			High_score_view_delayed_request	= NULL;
//			OptionsCameraSnapToMain();

			// Position menu
			Start_ptr->sp_pos.y 	= Game_display_height - MAIN_MENU_Y_OFFSET +   0 + 90;
			Race_ptr->sp_pos.y 		= Game_display_height - MAIN_MENU_Y_OFFSET +  16 + 90;
			Options_ptr->sp_pos.y 	= Game_display_height - MAIN_MENU_Y_OFFSET +  32 + 90;

			// Initialise high score view
			HSInitialiseScrollyHighScore();
			High_score_camera_operation_mode = HIGH_SCORE_CAMERA_OPERATION_MODE_SCROLLY;

			High_score_view_mode 	= HIGH_SCORE_VIEW_INIT_MODE;
			score_time 				= SCORE_TIME;
			Main_options_status 	= MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_MAIN;

			// Start me some options music.
			PlayOptionsMusic();

		// Show high score table
		case MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_MAIN:

			// Show high scores
			HSUpdateScrollyHighScores();

			// Scroll 2Dsprite menu if necessary
			if (High_score_view_flyoff_counter)
				{
				Start_ptr->sp_pos.y 	+= 8;
				Race_ptr->sp_pos.y 		+= 8;
				Options_ptr->sp_pos.y 	+= 8;
				}
			else
			if (High_score_view_flyon_counter)
				{
				Start_ptr->sp_pos.y 	-= 8;
				Race_ptr->sp_pos.y 		-= 8;
				Options_ptr->sp_pos.y 	-= 8;
				}

			// End of time ?
			if (score_time)
				{
				score_time--;
				if	(
					(!score_time) &&
					(!High_score_view_flyoff_counter) &&
					(!High_score_view_delayed_request)
					)
					{
					// Yes ... switch mode to finish
					Main_options_status = MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_FINISH;
					}
				}
			break;

		// Finish high score table view ...
		case MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_FINISH:
			HSDeinitialiseScrollyHighScore();

			Main_options_status = MAIN_OPTIONS_STATUS_DEMO_INIT;
			break;
		}

	//-------------------------------------------------------------------------------
	// Display subtractive poly
	//-------------------------------------------------------------------------------
	//
	// Sort out cloud coords
	Cloud_polys[MRFrame_index].y0 = Start_ptr->sp_pos.y - OPTIONS_CLOUD_BORDER;
	Cloud_polys[MRFrame_index].y1 = Start_ptr->sp_pos.y - OPTIONS_CLOUD_BORDER;
	Cloud_polys[MRFrame_index].y2 = Options_ptr->sp_pos.y + OPTIONS_CLOUD_BORDER + 16;
	Cloud_polys[MRFrame_index].y3 = Options_ptr->sp_pos.y + OPTIONS_CLOUD_BORDER + 16;

	// Add darkening prims to display behind menu
	addPrim(Option_viewport_ptr->vp_work_ot + 10, &Cloud_polys[MRFrame_index]);

	//-------------------------------------------------------------------------------
	// This is always called wherever there is a main menu
	//-------------------------------------------------------------------------------
	//
	// Has up been pressed ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_UP) )
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
		// Yes ... not at top ?
		if ( Option_number > 0 )
			{
			// Yes ... move option up
			Option_number--;
			}
		else
			{
			// No ... reset option to bottom
			Option_number = NUM_MAIN_OPTIONS_OPTIONS-1;
			}
		}

	// Has down been pressed ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN) )
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
		// Yes ... not at bottom ?
		if ( Option_number < (NUM_MAIN_OPTIONS_OPTIONS-1) )
			{
			// Yes ... move option down
			Option_number++;
			}
		else
			{
			// No ... reset option to top
			Option_number = 0;
			}
		}

	Option_spcore_index = Option_number;

	//-------------------------------------------------------------------------------
	// Handle cheat mode to bring up full level stack
	//-------------------------------------------------------------------------------
#ifndef PSX_RELEASE
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE) )
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

		// Yes ... are we on START ?
		if ( Option_number == 0 )
			{
			// Go on to level selection
			Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
	
			// Initialise level select mode
			Sel_mode = SEL_MODE_ARCADE;
	
			// Reset state of level select stack
			SelectLevelInit();
	
			// Open required levels
			sel_level_info_ptr = &Sel_arcade_levels[0];
			while ( sel_level_info_ptr->li_library_id != -1 )
				{
				// Open level
				SelectSetLevelFlags(sel_level_info_ptr->li_library_id,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
				// Next level
				sel_level_info_ptr++;
				}

			// Initialise position in level select stack
			Sel_arcade_level_ptr	= SelectGetLevelPointer(LEVEL_ORIGINAL1);
	
			// Initialise the player data
			GameInitialise();

			// Set number of players
			Game_total_players		= 1;
			Game_total_viewports	= 1;
	
			// Set up controller and other information
			for (count=0; count<4; count++)
				{
#ifdef WIN95
				Frog_player_data[count].fp_is_local = 1;
#endif
				Frog_player_data[count].fp_port_id	= count;
				}

			// Initialise scores etc. ready for high score table
			HighScoreInitialiseData();
			goto is_option_from_demo_mode;
			}
		}
#endif
	//-------------------------------------------------------------------------------
	// End of cheat mode
	//-------------------------------------------------------------------------------

	// Has fire button been pressed ?
	if	(
		(!High_score_view_flyon_counter) &&
		(!High_score_view_flyoff_counter) &&
		(!Game_demo_loading)			   &&					// Not trying to load a demo mode.
		(MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		)
		{
		// Yes
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
		switch (Option_number)
			{
			// START
			case 0:
				// Kill the Options music when going to Level Select.
				ShutdownOptionsMusic();

				// Go on to level selection
				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;

				// Initialise level select mode
				Sel_mode = SEL_MODE_ARCADE;

				// Initialise position in level select stack
				Sel_arcade_level_ptr	= SelectGetLevelPointer(LEVEL_ORIGINAL1);

				// Initialise the player data
				GameInitialise();

				// Set number of players
				Game_total_players		= 1;
				Game_total_viewports	= 1;

				// Set up controller and other information
				for (count=0; count<4; count++)
					{
#ifdef WIN95
					Frog_player_data[count].fp_is_local = 1;
#endif
					Frog_player_data[count].fp_port_id	= count;
					}

				// Initialise scores etc. ready for high score table
				HighScoreInitialiseData();

			is_option_from_demo_mode:;
				if (Game_flags & GAME_FLAG_DEMO_RUNNING)
					{
					GameEnd();
					Game_flags &= ~GAME_FLAG_DEMO_RUNNING;
					Game_flags |= (GAME_FLAG_HUD_SCORE|GAME_FLAG_HUD_TIMER|GAME_FLAG_HUD_HELP|GAME_FLAG_HUD_CHECKPOINTS|GAME_FLAG_HUD_LIVES);
					MRUnloadResource(Demo_level_table[Num_demo_levels_seen][1]);
					LoadOptionsResources();
					LoadGenericWad(0);

					if (High_score_view_delayed_request)
						{
						Option_page_request	= High_score_view_delayed_request;
						High_score_view_delayed_request	= NULL;
						High_score_view_flyoff_counter 	= 0;
						MR_COPY_SVEC(&Cameras[0].ca_current_source_ofs, &Cameras[0].ca_next_source_ofs);
						MR_COPY_SVEC(&Cameras[0].ca_current_target_ofs, &Cameras[0].ca_next_target_ofs);
						Cameras[0].ca_move_timer = 0;
						}
					}
				break;

			// RACE
			case 1:
#ifndef PSX		// WIN95 Specific code --------------------------------------
				// Go on to multiplayer mode options ( if WIN95 )
				High_score_view_delayed_request = OPTIONS_PAGE_MULTIPLAYER_MODE_OPTIONS;
#else			// PSX Specific code ----------------------------------------
				// Go on to frog selection ( if PSX )
				High_score_view_delayed_request = OPTIONS_PAGE_FROG_SELECTION;
#endif			// WIN95

				// Initialise level select mode
				Sel_mode = SEL_MODE_RACE;

				// Initialise the player data
				GameInitialise();

				// Initialise position in level select stack
				Sel_race_level_ptr		= SelectGetLevelPointer(LEVEL_ORIGINAL_MULTI_PLAYER);

				// Reset state of level select stack
				//SelectLevelInit();

				// Initialise scores etc. ready for high score table
				HighScoreInitialiseData();

				// Initialise multiplayer stats
				Frogs[0].fr_multi_games_won = 0;
				Frogs[0].fr_multi_games_lost = 0;
				Frogs[1].fr_multi_games_won = 0;
				Frogs[1].fr_multi_games_lost = 0;
				Frogs[2].fr_multi_games_won = 0;
				Frogs[2].fr_multi_games_lost = 0;
				Frogs[3].fr_multi_games_won = 0;
				Frogs[3].fr_multi_games_lost = 0;
			
				if (Game_flags & GAME_FLAG_DEMO_RUNNING)
					{
					GameEnd();
					MRUnloadResource(Demo_level_table[Num_demo_levels_seen][1]);
					LoadOptionsResources();
					LoadGenericWad(0);
					}
				// Start moving camera NOW
				MR_SET_SVEC(&Cameras[0].ca_next_source_ofs, 0, -1200, -10);
				MR_SET_SVEC(&Cameras[0].ca_next_target_ofs,	0, 0, 0);
				Cameras[0].ca_move_timer 		= OPTIONS_CAMERA_MOVE_TIME;
				High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;

				if (Game_flags & GAME_FLAG_DEMO_RUNNING)
					{	
					Game_flags &= ~GAME_FLAG_DEMO_RUNNING;
					Game_flags |= (GAME_FLAG_HUD_SCORE|GAME_FLAG_HUD_TIMER|GAME_FLAG_HUD_HELP|GAME_FLAG_HUD_CHECKPOINTS|GAME_FLAG_HUD_LIVES);
					Option_page_request 			= High_score_view_delayed_request;
					High_score_view_delayed_request	= NULL;
					High_score_view_flyoff_counter 	= 0;
					MR_COPY_SVEC(&Cameras[0].ca_current_source_ofs, &Cameras[0].ca_next_source_ofs);
					MR_COPY_SVEC(&Cameras[0].ca_current_target_ofs, &Cameras[0].ca_next_target_ofs);
					Cameras[0].ca_move_timer = 0;
					}
				break;

				goto is_option_from_demo_mode;

			// OPTIONS
			case 2:
				// Go on to main options screen
				High_score_view_delayed_request = OPTIONS_PAGE_OPTIONS;

				if (Game_flags & GAME_FLAG_DEMO_RUNNING)
					{
					GameEnd();
					MRUnloadResource(Demo_level_table[Num_demo_levels_seen][1]);
					LoadOptionsResources();
					LoadGenericWad(0);
					}
				// Start moving camera NOW
				OptionsCameraMoveToOptions();
				High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;

				if (Game_flags & GAME_FLAG_DEMO_RUNNING)
					{	
					Game_flags &= ~GAME_FLAG_DEMO_RUNNING;
					Game_flags |= (GAME_FLAG_HUD_SCORE|GAME_FLAG_HUD_TIMER|GAME_FLAG_HUD_HELP|GAME_FLAG_HUD_CHECKPOINTS|GAME_FLAG_HUD_LIVES);
					Option_page_request 			= High_score_view_delayed_request;
					High_score_view_delayed_request	= NULL;
					High_score_view_flyoff_counter 	= 0;
					MR_COPY_SVEC(&Cameras[0].ca_current_source_ofs, &Cameras[0].ca_next_source_ofs);
					MR_COPY_SVEC(&Cameras[0].ca_current_target_ofs, &Cameras[0].ca_next_target_ofs);
					Cameras[0].ca_move_timer = 0;
					}
				break;
			}
		}
}

/******************************************************************************
*%%%% MainOptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MainOptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Main Options screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	21.07.97	Gary Richards	Added code to tidy the free's.
*
*%%%**************************************************************************/

MR_VOID	MainOptionsShutdown(MR_VOID)
{
	// Kill sprites
	MRKill2DSprite(Start_ptr);
	MRKill2DSprite(Race_ptr);
	MRKill2DSprite(Options_ptr);

	// Flag triangle as active first time into level select stack
	Sel_first_time = TRUE;

	// Were we in high score view mode when we quit ?
	if ( ( Main_options_status == MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_MAIN ) || ( Main_options_status == MAIN_OPTIONS_STATUS_HIGH_SCORE_VIEW_FINISH ) )
		{
#if 0
		// Yes ... shut down high score table
		MRKill2DSprite(Main_options_background_sprite_ptr[0]);
		MRKill2DSprite(Main_options_background_sprite_ptr[1]);
		MRKill2DSprite(Main_options_background_sprite_ptr[2]);
		MRFreeTextArea(Option_main_options_text_area[10]);
		MRFreeTextArea(Option_main_options_text_area[9]);
		MRFreeTextArea(Option_main_options_text_area[8]);
		MRFreeTextArea(Option_main_options_text_area[7]);
		MRFreeTextArea(Option_main_options_text_area[6]);
		MRFreeTextArea(Option_main_options_text_area[5]);
		MRFreeTextArea(Option_main_options_text_area[4]);
		MRFreeTextArea(Option_main_options_text_area[3]);
		MRFreeTextArea(Option_main_options_text_area[2]);
		MRFreeTextArea(Option_main_options_text_area[1]);
		MRFreeTextArea(Option_main_options_text_area[0]);
#endif

		HSDeinitialiseScrollyHighScore();
		}

	From_options = TRUE;
	OptionKill3DSprites();
}

#ifdef WIN95
/******************************************************************************
*%%%% MultiplayerModeOptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MultiplayerModeOptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for multiplayer mode options screen.
*				This screen decides on whether the multiplayer game
*				is a local or network game.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	24.06.97	Martin Kift		Added bulk of code
*
*%%%**************************************************************************/

MR_VOID	MultiplayerModeOptionsStartup(MR_VOID)
{
	// Display test text
	Option_multiplayer_mode_text_area[0] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)-20, Game_display_width, 16);
	Option_multiplayer_mode_text_area[1] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1), Game_display_width, 16);
	Option_multiplayer_mode_text_area[2] = MRAllocateTextArea(NULL, &std_font,	Option_viewport_ptr, 100, 0, (Game_display_height>>1)+10, Game_display_width, 16);

	MRBuildText(Option_multiplayer_mode_text_area[0], Option_multiplayer_mode_text[0], MR_FONT_COLOUR_YELLOW);

	if (Option_multiplayer_mode == OPTION_MULTIPLAYER_MODE_LOCAL)
		{
		MRBuildText(Option_multiplayer_mode_text_area[1], Option_multiplayer_mode_text[1], MR_FONT_COLOUR_CADMIUM);
		MRBuildText(Option_multiplayer_mode_text_area[2], Option_multiplayer_mode_text[2], MR_FONT_COLOUR_YELLOW);
		}
	else
		{
		MRBuildText(Option_multiplayer_mode_text_area[1], Option_multiplayer_mode_text[1], MR_FONT_COLOUR_YELLOW);
		MRBuildText(Option_multiplayer_mode_text_area[2], Option_multiplayer_mode_text[2], MR_FONT_COLOUR_CADMIUM);
		}
}

/******************************************************************************
*%%%% MultiplayerModeOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID MultiplayerModeOptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for multiplayer model options screen
*				This screen decides on whether the multiplayer game
*				is a local or network game.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	24.06.97	Martin Kift		Added bulk of code
*
*%%%**************************************************************************/

MR_VOID	MultiplayerModeOptionsUpdate(MR_VOID)
{
	// Check pad presses for up/down and fire
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// If mode is local, go to frog selection, else goto network screens
		if (Option_multiplayer_mode == OPTION_MULTIPLAYER_MODE_LOCAL)
			Option_page_request = OPTIONS_PAGE_FROG_SELECTION;
		else
			Option_page_request = OPTIONS_PAGE_NETWORK_TYPE;
		}

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_UP) || 
		MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN))
		{
		if (Option_multiplayer_mode == OPTION_MULTIPLAYER_MODE_LOCAL)
			{
			Option_multiplayer_mode = OPTION_MULTIPLAYER_MODE_NETWORK;
			MRBuildText(Option_multiplayer_mode_text_area[1], Option_multiplayer_mode_text[1], MR_FONT_COLOUR_YELLOW);
			MRBuildText(Option_multiplayer_mode_text_area[2], Option_multiplayer_mode_text[2], MR_FONT_COLOUR_CADMIUM);
			}
		else
			{
			Option_multiplayer_mode = OPTION_MULTIPLAYER_MODE_LOCAL;
			MRBuildText(Option_multiplayer_mode_text_area[1], Option_multiplayer_mode_text[1], MR_FONT_COLOUR_CADMIUM);
			MRBuildText(Option_multiplayer_mode_text_area[2], Option_multiplayer_mode_text[2], MR_FONT_COLOUR_YELLOW);
			}
		}

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}

/******************************************************************************
*%%%% MultiplayerModeOptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MultiplayerModeOptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for multiplayer model options screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	24.06.97	Martin Kift		Added bulk of code
*
*%%%**************************************************************************/

MR_VOID	MultiplayerModeOptionsShutdown(MR_VOID)
{
	MR_ULONG	count;

	// Free text areas
	for (count=0; count<3; count++)
		MRFreeTextArea(Option_multiplayer_mode_text_area[count]);
}

/******************************************************************************
*%%%% NetworkTypeOptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkTypeOptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkTypeOptionsStartup(MR_VOID)
{
	SPLIST*		provider_list;
	MR_ULONG	count;
	MR_STRPTR*	line_ptr;
	MR_ULONG	y_offset;
	MR_ULONG	colour;

	// Init important data
	Option_network_type_selected_provider = 0;

	// This is the ideal time to actually start the network up
	if (MNInitialise((LPGUID)&FROGGER_GUID) != S_OK)
		{
		// Network failed to init, exit to options screen, maybe with message
		Option_page_request = OPTIONS_PAGE_EXIT;
		return;
		}

	MNRegisterWindow(MRDisplay_ptr->di_hwnd);
	
	// Initially find all the available service providers
	MNFindServiceProviders();

	// Get list of providers
	provider_list = MNGetServiceProviderList();
	if (!provider_list)
		{
		// Network failed to init, exit to options screen, maybe with message
		Option_page_request = OPTIONS_PAGE_EXIT;
		}

	// get number of entries in the SP list
	Option_network_type_number_providers = provider_list->uiSPListSize;

	// check for max
	if (Option_network_type_number_providers >= OPTION_NETWORK_TYPE_MAX_ENTRIES)
		Option_network_type_number_providers = OPTION_NETWORK_TYPE_MAX_ENTRIES;

	count 		= 0;
	y_offset	= (Game_display_height>>1)-(Option_network_type_number_providers>>1)*10;
	colour		= MR_FONT_COLOUR_CADMIUM;

	// Walk through list of service providers, setting up each												
	while (count < Option_network_type_number_providers)
		{
		// Alloc text buffer
		Option_network_type_text_area[count] = MRAllocateTextArea(
												NULL,
												&std_font,
												Option_viewport_ptr,
												70,
												0, y_offset,
												Game_display_width, 16);

		line_ptr	= &Option_network_type_text_buff[count][0];

		*line_ptr++ = (MR_STRPTR)Option_network_type_text_tag;
		*line_ptr++ = (MR_STRPTR)&provider_list->spSPList[count].lpszSPName;
		*line_ptr++ = NULL;

		MRBuildText(Option_network_type_text_area[count],
					Option_network_type_text_buff[count],
					colour);

		y_offset+=10;
		count++;
		colour = MR_FONT_COLOUR_YELLOW;
		}
}

/******************************************************************************
*%%%% NetworkTypeOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID NetworkTypeOptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkTypeOptionsUpdate(MR_VOID)
{
	// Check pad presses for up/down and fire
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// Try and connect to required protocol
		if (MNCreateConnection(Option_network_type_selected_provider))			
			{
			Option_page_request = OPTIONS_PAGE_NETWORK_HOST;
			return;
			}
		}

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_UP))
		{
		if (Option_network_type_selected_provider > 0)
			{
			MRBuildText(Option_network_type_text_area[Option_network_type_selected_provider],
						Option_network_type_text_buff[Option_network_type_selected_provider],
						MR_FONT_COLOUR_YELLOW);
			Option_network_type_selected_provider--;
			MRBuildText(Option_network_type_text_area[Option_network_type_selected_provider],
						Option_network_type_text_buff[Option_network_type_selected_provider],
						MR_FONT_COLOUR_CADMIUM);
			}
		}
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_DOWN))
		{
		if (Option_network_type_selected_provider < Option_network_type_number_providers-1)
			{
			MRBuildText(Option_network_type_text_area[Option_network_type_selected_provider],
						Option_network_type_text_buff[Option_network_type_selected_provider],
						MR_FONT_COLOUR_YELLOW);
			Option_network_type_selected_provider++;
			MRBuildText(Option_network_type_text_area[Option_network_type_selected_provider],
						Option_network_type_text_buff[Option_network_type_selected_provider],
						MR_FONT_COLOUR_CADMIUM);
			}
		}
#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}

/******************************************************************************
*%%%% NetworkTypeOptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkTypeOptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkTypeOptionsShutdown(MR_VOID)
{
	MR_ULONG	count;

	// Free text areas
	for (count=0; count<Option_network_type_number_providers; count++)
		MRFreeTextArea(Option_network_type_text_area[count]);
}

/******************************************************************************
*%%%% NetworkHostOptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkHostOptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkHostOptionsStartup(MR_VOID)
{
	// Init important data
	Option_network_host_selected_session	= -1;
	Option_network_host_number_sessions		= 0;

	Option_network_host_title_area = MRAllocateTextArea(
												NULL,
												&std_font,
												Option_viewport_ptr,
												70,
												0, (Game_display_height>>1)-100,
												Game_display_width, 16);
	MRBuildText(Option_network_host_title_area, Option_network_host_title_text, MR_FONT_COLOUR_CADMIUM);
}

/******************************************************************************
*%%%% NetworkHostOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID NetworkHostOptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkHostOptionsUpdate(MR_VOID)
{
	SESSIONLIST*	session_list;
	MR_ULONG		count;
	MR_STRPTR*		line_ptr;
	MR_ULONG		y_offset;
	MR_ULONG		colour;
	MR_ULONG		number_sessions;

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_SQUARE))
		{
		session_list = MNFindActiveSessions();
		if (session_list)
			{
			number_sessions = session_list->uiSessionListSize;

			// Any more or less sessions than before?
			if (number_sessions != Option_network_host_number_sessions)
				{
				// Delete current entries
				count = 0;
				while (count < Option_network_host_number_sessions)
					{
					MRFreeTextArea(Option_network_host_text_area[count]);
					count++;
					}

				// set number of sessions
				Option_network_host_number_sessions = number_sessions;

				// check for max
				if (Option_network_host_number_sessions > OPTION_NETWORK_HOST_MAX_ENTRIES)
					Option_network_host_number_sessions = OPTION_NETWORK_HOST_MAX_ENTRIES;

				count 		= 0;
				y_offset	= (Game_display_height>>1)-80;
				colour		= MR_FONT_COLOUR_YELLOW;

				while (count < Option_network_host_number_sessions)
					{
					// Alloc text buffer
					Option_network_host_text_area[count] = MRAllocateTextArea(
													NULL,
													&std_font,
													Option_viewport_ptr,
													70,
													0, y_offset,
													Game_display_width, 16);

					line_ptr	= &Option_network_host_text_buff[count][0];

					*line_ptr++ = (MR_STRPTR)Option_network_host_text_tag;
					*line_ptr++ = (MR_STRPTR)&session_list->lpDPSessionDesc[count]->lpszSessionNameA;
					*line_ptr++ = NULL;

					MRBuildText(Option_network_host_text_area[count],
								Option_network_host_text_buff[count],
								colour);

					y_offset+=10;
					count++;
					}
				}
			}
		}

	// Check pad presses for up/down and fire(s)
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// This is a JOIN game request, only continue if one is selected
		if (Option_network_host_selected_session != -1)
			{
			MNJoinGame(Option_network_host_selected_session);
			MNCreatePlayer();
			MNGetSessionDescription();

			Option_page_request = OPTIONS_PAGE_NETWORK_PLAY;
			return;
			}
		}

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE))
		{
		// This is a NEW game request
		MNNewGame("Temp session name");
		MNCreatePlayer();
		MNGetSessionDescription();

		// this is probably temp code
		MNSetLocalPlayerName("");

		Option_page_request = OPTIONS_PAGE_NETWORK_PLAY;
		return;
		}

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_UP))
		{
		// If theres any sessions, move between them
		if (Option_network_host_number_sessions > 0)
			{
			if (Option_network_host_selected_session != -1)
				{
				if (Option_network_host_selected_session > 0)
					{
					MRBuildText(Option_network_host_text_area[Option_network_host_selected_session],
								Option_network_host_text_buff[Option_network_host_selected_session],
								MR_FONT_COLOUR_YELLOW);
					Option_network_host_selected_session--;
					MRBuildText(Option_network_host_text_area[Option_network_host_selected_session],
								Option_network_host_text_buff[Option_network_host_selected_session],
								MR_FONT_COLOUR_CADMIUM);
					}
				}
			}
		}

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_DOWN))
		{
		// If theres any sessions, move between them
		if (Option_network_host_number_sessions > 0)
			{
			if (Option_network_host_selected_session != -1)
				{
				if (Option_network_host_selected_session < (MR_LONG)Option_network_host_number_sessions-1)
					{
					MRBuildText(Option_network_host_text_area[Option_network_host_selected_session],
								Option_network_host_text_buff[Option_network_host_selected_session],
								MR_FONT_COLOUR_YELLOW);
					Option_network_host_selected_session++;
					MRBuildText(Option_network_host_text_area[Option_network_host_selected_session],
								Option_network_host_text_buff[Option_network_host_selected_session],
								MR_FONT_COLOUR_CADMIUM);
					}
				}
			else
				{
				// make first the default
				Option_network_host_selected_session = 0;

				MRBuildText(Option_network_host_text_area[Option_network_host_selected_session],
							Option_network_host_text_buff[Option_network_host_selected_session],
							MR_FONT_COLOUR_CADMIUM);
				}
			}
		}

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}

/******************************************************************************
*%%%% NetworkHostOptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkHostOptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for network type selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkHostOptionsShutdown(MR_VOID)
{
	MR_ULONG	count;

	// Free text areas
	MRFreeTextArea(Option_network_host_title_area);

	for (count=0; count<Option_network_host_number_sessions; count++)
		MRFreeTextArea(Option_network_host_text_area[count]);
}

/******************************************************************************
*%%%% NetworkPlayOptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkPlayOptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for network play selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	26.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkPlayOptionsStartup(MR_VOID)
{
	// Init important data
	Option_network_play_number_players = 0;			

	Option_network_play_title_area = MRAllocateTextArea(
												NULL,
												&std_font,
												Option_viewport_ptr,
												70,
												0, (Game_display_height>>1)-100,
												Game_display_width, 16);
	MRBuildText(Option_network_play_title_area, Option_network_play_title_text, MR_FONT_COLOUR_CADMIUM);
}

/******************************************************************************
*%%%% NetworkPlayOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID NetworkPlayOptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for network play selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkPlayOptionsUpdate(MR_VOID)
{
	PLAYERLIST*		player_list;
	MR_ULONG		count;
	MR_STRPTR*		line_ptr;
	MR_ULONG		y_offset;
	MR_ULONG		colour;
	MR_ULONG		current_players;

	// Find all current players
	MNFindCurrentGamePlayers();

	// Get player list
	player_list = MNGetPlayerList();
	if (player_list)
		{
		// get number of entries in the SP list
		current_players = player_list->uiPlayerListSize;

		// If the number of players has changed, then need to refresh list
		if (current_players != Option_network_play_number_players)
			{
			// Delete current entries
			count = 0;
			while (count < Option_network_play_number_players)
				{
				MRFreeTextArea(Option_network_play_text_area[count]);
				count++;
				}

			// Setup data and text on screen
			Option_network_play_number_players	= current_players;
			count								= 0;
			y_offset							= (Game_display_height>>1)-80;
			colour								= MR_FONT_COLOUR_YELLOW;

			if (Option_network_play_number_players > OPTION_NETWORK_PLAY_MAX_ENTRIES)
				Option_network_play_number_players = OPTION_NETWORK_PLAY_MAX_ENTRIES;

			while (count < Option_network_play_number_players)
				{
				// Alloc text buffer
				Option_network_play_text_area[count] = MRAllocateTextArea(
												NULL,
												&std_font,
												Option_viewport_ptr,
												70,
												0, y_offset,
												Game_display_width, 16);

				line_ptr	= &Option_network_play_text_buff[count][0];

				*line_ptr++ = (MR_STRPTR)Option_network_play_text_tag;
				*line_ptr++ = (MR_STRPTR)&player_list->lpPLPlayerData[count]->Name.lpszShortNameA;
				*line_ptr++ = NULL;
	
				MRBuildText(Option_network_play_text_area[count],
							Option_network_play_text_buff[count],
							colour);

				y_offset+=10;
				count++;
				}
			}
		}	

	// Check pad presses for up/down and fire(s)
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// This is a START game request, only continue if more than one player
		if (Option_network_play_number_players > 1)
			{
			if (MNHost())
				{
				// Issue the player numbers since we are the host
				MNIssuePlayerNumbers();

				// send messge to other machines to start game
				//SendGenericMessage(FRNET_MSG_OPTIONS_GOTO_FROG_SELECT);

				MNStopPoll();
				MNSetGameMessageHandlerCallback((void (*)(LPMNGAMEMSG_GENERIC, DWORD, DPID, DPID))GameMessageHandlerCallBack);
				MNSignalGameStart();
				Option_page_request = OPTIONS_PAGE_FROG_SELECTION;
				}
			}
		}


	// If player numbers are issued (and we are not the host) then goto frog selection screen
	if (!MNHost())
		{
		if (MNGetPlayerNumber() != MN_INVALID)
			{
			MNStopPoll();
			MNSetGameMessageHandlerCallback((void (*)(LPMNGAMEMSG_GENERIC, DWORD, DPID, DPID))GameMessageHandlerCallBack);
			MNSignalGameStart();
			Option_page_request = OPTIONS_PAGE_FROG_SELECTION;
			}
		}

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}

/******************************************************************************
*%%%% NetworkPlayOptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	NetworkPlayOptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for network play selection options screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	NetworkPlayOptionsShutdown(MR_VOID)
{
	MR_ULONG	count;

	// Free text areas
	MRFreeTextArea(Option_network_play_title_area);

	for (count=0; count<Option_network_play_number_players; count++)
		MRFreeTextArea(Option_network_play_text_area[count]);
}
#endif


/******************************************************************************
*%%%% FrogSelectionStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Frog Selection screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	22.06.97	Martin Kift		Totally recoded to work with networks and 
*								different number of players
*
*%%%**************************************************************************/

MR_VOID	FrogSelectionStartup(MR_VOID)
{
	MR_LONG		i, x, y;
#ifdef WIN95
	PLAYERLIST*	player_list;
#endif
	MR_TEXTURE*	texture;


	// Load GEN wad for frogs
	LoadGenericWad(0);

	High_score_matrices = MRAllocMem(sizeof(MR_MAT) * 4, "HS matrices");
	for (i = 0; i < 4; i++)	
		High_score_view_number_matrix_ptr[i] = High_score_matrices + i;

	// Create blank lillies for frogs to sit on
	for (i = 0; i < 4; i++)
		{
		MR_INIT_MAT(High_score_view_number_matrix_ptr[i]);
		High_score_view_number_matrix_ptr[i]->t[0] =  -0x100 + (0x200 * (i & 1));
		High_score_view_number_matrix_ptr[i]->t[1] 	= OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_number_matrix_ptr[i]->t[2] =   0x100 - (0x200 * (i >> 1));

		High_score_view_number_object_ptr[i] = MRCreateMesh(MR_GET_RESOURCE_ADDR(RES_OPT_LILLYPAD_BLANK_XMR), (MR_FRAME*)High_score_view_number_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_view_number_object_ptr[i], Option_viewport_ptr, 0);
		}

	High_score_view_flyon_counter 	= OPTIONS_CAMERA_FLYON_TIME;
	High_score_view_delayed_request	= NULL;

	// Set global for number of frogs player, 4 for local game (on psx and win95)
	// and any number up to 4 for network game (one per machine)
#ifdef PSX
	Frog_selection_number_players = 4;
#else
	// windows specific code
	if (MNIsNetGameRunning())
		{
		// Initialise synced of all network machines 
		InitialiseSync();

		player_list	= MNGetPlayerList();
		MR_ASSERT (player_list);

		// get number of entries in the SP list
		Frog_selection_number_players	= player_list->uiPlayerListSize;				
		
		// check that no more than four players are in game
		MR_ASSERT (Frog_selection_number_players <= 4);
		}
	else
		Frog_selection_number_players = 4;
#endif

	// Create croak sack scaling matrix
	MR_INIT_MAT(&High_score_view_frog_sack_scale_matrix);
	High_score_view_frog_sack_scale_matrix.m[0][0] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[1][1] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[2][2] = FROG_CROAK_MIN_SCALE;

	Frog_selection_master_flags = NULL;

	// Loop once for each player (playing)
	for (i = 0; i < 4; i++)
		{
		// Create anim env for frog
		FrogSelectionCreateFrog(i, i);

		// Create INSERT CONTROLLER sprite
		texture = Options_text_textures[OPTION_TEXT_INSERT_PAD][Game_language];
		x		= (Game_display_width >> 2) + ((Game_display_width >> 1) * (i & 1));		// 1/4 or 3/4
		y		= (Game_display_height >> 1) * (i >> 1) + (Game_display_height >> 2);
		if (i & 2)
			y += (9 * 10);
		else
			y -= (9 * 10);

		Frog_selection_sprites[i] = MRCreate2DSprite(x - (texture->te_w >> 1), y - (texture->te_h >> 1), Option_viewport_ptr, texture, NULL);
		Frog_selection_sprites[i]->sp_core.sc_base_colour.r = 0x60;
		Frog_selection_sprites[i]->sp_core.sc_base_colour.g = 0x60;
		Frog_selection_sprites[i]->sp_core.sc_base_colour.b = 0x60;

		// Set selection state
		Frog_selection_states[i] = NULL;
		}

#ifdef WIN95
	// init and wait for a sync message
	SendSync();
#endif
}


/******************************************************************************
*%%%% FrogSelectionOptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionUpdate(MR_VOID)
*
*	FUNCTION	Update code for Frog Selection screen.  Waits for player
*				to press fire to join game.  Once player has joined they
*				can select a Frog.  Once all joined players have selected
*				a Frog, the master can start the game by pressing START.
*				The master can be changed by using the cowering and growling
*				actions of the Frogs.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	20.06.97	Martin Kift		Added support for win95 network mode, which
*								meant I had to add a layer over loop_counter
*
*%%%**************************************************************************/

MR_VOID	FrogSelectionUpdate(MR_VOID)
{
	MR_LONG		i, num_frogs;
	MR_LONG		player_id, x, y;
	MR_OBJECT*	object;
	MR_SVEC		svec;
	MR_MAT		matrix;
	MR_TEXTURE*	texture;
	
	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();
	HSUpdateFlying();

	// Set up scale matrix to enlarge all models
	MRScale_matrix.m[0][0] = 0x1800;
	MRScale_matrix.m[1][1] = 0x1800;
	MRScale_matrix.m[2][2] = 0x1800;
	MR_SET_SVEC(&svec, 0, 0x800, 0);
	MRRotMatrix(&svec, &matrix);
	MRMulMatrixABB(&MRScale_matrix, &matrix);

	// Apply wave deltas to lillies
	HSProjectMatricesOntoWaterSurface(High_score_view_number_matrix_ptr[0], 4, &matrix);

	// Scroll 2Dsprites if necessary
	if	(
		(High_score_view_flyoff_counter) ||
		(Option_page_request)
		)
		{
		Frog_selection_sprites[0]->sp_pos.y -= 10;
		Frog_selection_sprites[1]->sp_pos.y -= 10;
		Frog_selection_sprites[2]->sp_pos.y += 10;
		Frog_selection_sprites[3]->sp_pos.y += 10;
		goto exit;
		}

	// Count number of selected frogs
	num_frogs = 0;
	for (i = 0; i < 4; i++)
		{
#ifdef PSX
		player_id		= i;
#else
		if (MNIsNetGameRunning())
			player_id	= MNGetPlayerNumber();
		else
			player_id	= i;
#endif
		if (Frog_selection_states[player_id] == 2)
			num_frogs++;
		}

	// Loop once for each active player
	for (i = 0; i < 4; i++)
		{
		// Big change here (from old code). Player_id is mostly the same as i, unless we are in a
		// windows95 only network game, in which case its the network player id (assigned by network code)
#ifdef PSX
		player_id		= i;
#else
		if (MNIsNetGameRunning())
			player_id	= MNGetPlayerNumber();
		else
			player_id	= i;
#endif

		// Get current state of frog
		if (Frog_input_ports[player_id] == -1)
			{
			// Player 3 or 4, and no multitap, so don't display lily, frog or text
			Frog_anim_env_ptr[player_id]->ae_flags 			&= ~MR_ANIM_ENV_DISPLAY;
			Frog_selection_sprites[i]->sp_core.sc_flags 	|= MR_SPF_NO_DISPLAY;
			High_score_view_number_object_ptr[i]->ob_flags 	|= MR_OBJ_NO_DISPLAY;
			}
		else
			{
			High_score_view_number_object_ptr[i]->ob_flags 	&= ~MR_OBJ_NO_DISPLAY;
	
			if (MRInput[Frog_input_ports[player_id]].in_flags & MRIF_TYPE_NONE)
				{
				// No pad
				Frog_selection_states[player_id] = NULL;
	
				// Set message
				Frog_selection_sprites[i]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
				texture = Options_text_textures[OPTION_TEXT_INSERT_PAD][Game_language];
				MRChangeSprite(Frog_selection_sprites[i], texture);
				x		= (Game_display_width >> 2) + ((Game_display_width >> 1) * (i & 1));
				y		= (Game_display_height >> 1) * (i >> 1) + (Game_display_height >> 2);
				Frog_selection_sprites[i]->sp_pos.x = x - (texture->te_w >> 1);
				Frog_selection_sprites[i]->sp_pos.y = y - (texture->te_h >> 1);
	
				// Turn frog anim off, text sprite on
				Frog_anim_env_ptr[player_id]->ae_flags &= ~MR_ANIM_ENV_DISPLAY;
				MRAnimEnvSingleSetAction(Frog_anim_env_ptr[player_id], GEN_FROG_PANT);
		
				Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_MASTER << player_id);
				Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_JOINED << player_id);
				Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_FROG_SELECTED << player_id);
	
				// If master flag set, clear it
				if (Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER << player_id))
					Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_MASTER << player_id);
				}
			else
				{
				// Pad in
				//
				// Turn frog anim on
				Frog_anim_env_ptr[player_id]->ae_flags |= MR_ANIM_ENV_DISPLAY;
	
				if (Frog_selection_states[player_id] < 2)
					{
					// Pad in, not selected
					//
					// Set message
					Frog_selection_sprites[i]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
					texture = Options_text_textures[OPTION_TEXT_PRESS_FIRE][Game_language];
					MRChangeSprite(Frog_selection_sprites[i], texture);
					x		= (Game_display_width >> 2) + ((Game_display_width >> 1) * (i & 1));
					y		= (Game_display_height >> 1) * (i >> 1) + ((Game_display_height * 3) / 8);
					Frog_selection_sprites[i]->sp_pos.x = x - (texture->te_w >> 1);
					Frog_selection_sprites[i]->sp_pos.y = y - (texture->te_h >> 1);
	
					// Turn on colour scaling (to dim frog)
					Frog_anim_inst_ptr[player_id]->ae_mesh_insts[0]->mi_light_flags |= MR_INST_USE_SCALED_COLOURS;
	
					Frog_selection_states[player_id] = 1;
					if (MR_CHECK_PAD_PRESSED(Frog_input_ports[player_id], FR_GO))
						{
						// Player has just joined game
						Frog_selection_states[player_id] = 2;
	
						MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
						MRAnimEnvSingleSetAction(Frog_anim_env_ptr[player_id], GEN_FROG_WAIT3);
		
						object = MRCreatePgen(&PGIN_pickup_explosion, (MR_FRAME*)High_score_view_number_matrix_ptr[player_id], MR_OBJ_STATIC, NULL);
						object->ob_offset.vy = -0x30;
						MRAddObjectToViewport(object, Option_viewport_ptr, NULL);
	
						// Turn off colour scaling
						Frog_anim_inst_ptr[player_id]->ae_mesh_insts[0]->mi_light_flags &= ~MR_INST_USE_SCALED_COLOURS;
	
						Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_JOINED << player_id);
						Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_FROG_SELECTED << player_id);
	
						// If no master flag set, set one for this frog
						if (!(Frog_selection_master_flags & FROG_SELECTION_ALL_MASTERS))
							{
							Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_MASTER << player_id);
							}
	
						// Turn off message
						Frog_selection_sprites[i]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
						}
					}
				else
					{
					// If number of selected frogs >= 2, set message for master
					if	(
						(num_frogs >= 2) &&
						(Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER << player_id))
						)
						{
						// Set message
						Frog_selection_sprites[i]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
						texture = Options_text_textures[OPTION_TEXT_START_RACE][Game_language];
						MRChangeSprite(Frog_selection_sprites[i], texture);
						x		= (Game_display_width >> 2) + ((Game_display_width >> 1) * (i & 1));
						y		= (Game_display_height >> 1) * (i >> 1) + ((Game_display_height * 3) / 8);
						Frog_selection_sprites[i]->sp_pos.x = x - (texture->te_w >> 1);
						Frog_selection_sprites[i]->sp_pos.y = y - (texture->te_h >> 1);
						}
					else
						{
						// Turn off message
						Frog_selection_sprites[i]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
						}
					}
	
				if	(
					(!High_score_view_flyon_counter) &&
					(!High_score_view_flyoff_counter) &&
					(MR_CHECK_PAD_PRESSED(Frog_input_ports[player_id], FRR_TRIANGLE))
					)
					{
					// Unselect all frogs
					Frog_selection_master_flags = NULL;
	
					// Player has requested to go back to options (bail out)
					High_score_view_delayed_request = OPTIONS_PAGE_MAIN_OPTIONS;
	
					// Start moving camera NOW
					OptionsCameraMoveToMain();
					High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
					return;
					}
				}
			}
		
		}

	// Consider allowing start of game
	if (num_frogs >= 2)
		{
		for (i = 0; i < 4; i++)
			{
#ifdef PSX
			player_id		= i;
#else
			if (MNIsNetGameRunning())
				player_id	= MNGetPlayerNumber();
			else
				player_id	= i;
#endif
			// Only master can start game
			if	(
				(Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER << player_id)) &&
				(Frog_selection_states[player_id] == 2) &&
				(MR_CHECK_PAD_PRESSED(Frog_input_ports[player_id], FRR_START)) &&
				(!High_score_view_flyon_counter) &&
				(!High_score_view_flyoff_counter)
				)
				{
				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
				// Kill the option tune when going to level select.
				ShutdownOptionsMusic();
				return;
				}
			}
		}


	exit:;
#ifdef WIN95
	// update windows network
	if (MNIsNetGameRunning())
		SendOptionsFrogSelect(Frog_selection_master_flags);				
#endif
}


/******************************************************************************
*%%%% FrogSelectionReadInput
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionReadInput(MR_VOID)
*
*	FUNCTION	Read input for player (or players in local machine game) and
*				update input flags.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID FrogSelectionReadInput(MR_VOID)
{
//	MR_ULONG	i;
//	MR_ULONG	player_id;
//	MR_ULONG	port_id;
//
//	// Clear input request flags (ready for checking input)
//	Frog_selection_request_flags = NULL;
//
//	// If network game just read one input, else read for each player playing
//	for(i=0;i<Frog_selection_number_players;i++)
//		{
//		// Big change here (from old code). Player_id is mostly the same as i, unless we are in a
//		// windows95 only network game, in which case its the network player id (assigned by network code)
//#ifdef PSX
//		player_id	= i;
//		port_id		= Frog_input_ports[player_id];
//#else
//		if (MNIsNetGameRunning())
//			{
//			player_id	= MNGetPlayerNumber();
//			port_id		= MR_INPUT_PORT_0;
//			}
//		else
//			{
//			player_id	= i;
//			port_id		= Frog_input_ports[player_id];
//			}
//#endif
//
//		// Has this player joined the game ?
//		if ( !(Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_JOINED<<player_id)) )
//			{
//			// No ... has player pressed fire ?
//			if ( MR_CHECK_PAD_PRESSED(port_id, FRR_CROSS) )
//				{
//				// Yes ... play sound
//				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
//				// Yes ... flag player as wanting to join
//				Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_JOINING<<player_id);
//				}
//			}
//		else
//			{
//			// Player is in game already, check selection input
//			if ( MR_CHECK_PAD_PRESSED(port_id, FRR_DOWN) )
//				{
//				// Yes ... play sound
////				MRSNDPlaySound(SFX_OPT_COWER,NULL,0,0);
//				// Yes ... flag Frog as cowering
//				Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_COWERING<<player_id);
//				}
//
//			// Did player push up ?
//			if (MR_CHECK_PAD_PRESSED(port_id, FRR_UP))
//				{
//				// Yes ... play growl
////				MRSNDPlaySound(SFX_OPT_GROWL,NULL,0,0);
//				// Yes ... flag Frog as growling
//				Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_GROWLING<<player_id);
//				}
//
//			// Has player already selected frog ?
//			if ( !(Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_FROG_SELECTED<<player_id)) )
//				{
//				// No ... has player pushed right ?
//				if ( MR_CHECK_PAD_PRESSED(port_id, FRR_RIGHT) )
//					{
//					// Yes ... play sound
//					MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
//					Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_INCFROG<<player_id);
//					}
//
//				// Has player pushed left ?
//				if ( MR_CHECK_PAD_PRESSED(port_id, FRR_LEFT) )
//					{
//					// Yes ... play sound
//					MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
//					Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_DECFROG<<player_id);
//					}
//
//				// Did player push fire ?
//				if ( MR_CHECK_PAD_PRESSED(port_id, FRR_CROSS) )
//					{
//					// Yes ... play sound
//					MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
//					Frog_selection_request_flags |= (FROG_REQUEST_PLAYER1_FROG_SELECTED<<player_id);
//					}
//				}
//			}
//
//		// Is this player the master ?
//		if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER<<i) )
//			{
//			// Yes ... have they pressed fire ?
//			if ( MR_CHECK_PAD_PRESSED(port_id, FRR_START) )
//				{
//				// Yes ... play sound
////				MRSNDPlaySound(SFX_OPT_GO,NULL,0,0);
//				// Yes ... set START GAME request flag
//				Frog_selection_request_flags |= FROG_REQUEST_START_GAME;
//				}
//			}
//		}
//
//	
//#ifdef WIN95
//	// If an input has been detected, then send information to all other machines
//	if	(
//		(MNIsNetGameRunning()) &&
//		(Frog_selection_request_flags)
//		)
//		{
//		SendOptionsFrogSelect(Frog_selection_request_flags);				
//		}
//#endif
}

/******************************************************************************
*%%%% FrogSelectionNetworkUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionNetworkUpdate(MR_VOID)
*
*	FUNCTION	Update code for Frog Selection screen.  Waits for player
*				to press fire to join game.  Once player has joined they
*				can select a Frog.  Once all joined players have selected
*				a Frog, the master can start the game by pressing START.
*				The master can be changed by using the cowering and growling
*				actions of the Frogs.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	22.06.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	FrogSelectionNetworkUpdate(MR_VOID)
{
//	MR_ULONG	i;
//	MR_BOOL		all_frogs_selected_flag;
//	MR_BOOL		frog_already_selected_flag;
//	MR_ULONG	num_frogs;
//	MR_BOOL		exit_request;
//
//#ifdef WIN95
//	// On windows, in network mode only, don't allow any updates at all until we 
//	// have synced with all machines
//	if	(
//		(MNIsNetGameRunning()) &&
//		(!CheckForNetworkSync())
//		)
//		{
//		return;
//		}
//#endif
//
//	num_frogs = 0;
//	
//	// Flag all Players joined as having selected a Frog
//	all_frogs_selected_flag = TRUE;
//
//	// check if ant network settings and use, else check for local input
//#ifdef PSX
//	// Read frog select input
//	FrogSelectionReadInput();
//#else
//	// A better solution than this may be required eventually, since it could
//	// flood local machines with other machines messages (unlikely though)
//	if (Frog_selection_network_request_flags)
//		{
//		Frog_selection_request_flags			= Frog_selection_network_request_flags;
//		Frog_selection_network_request_flags	= NULL;
//		}
//	else
//		FrogSelectionReadInput();
//#endif
//
//	// Loop once for all players the local player only..
//	for(i=0;i<4;i++)
//		{
//		// Are we currently animating this Frog ?
//		if ( Frog_selection_animation_count[i] )
//			// Yes ... dec animation count
//			Frog_selection_animation_count[i]--;
//
//		// Has this player joined the game ?
//		if (Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_JOINING<<i))
//			{
//			// Yes ... flag player as joined
//			Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_JOINED<<i);
//
//			// Up base colour of player's Frog
//			MRBuildText(Option_frog_selection_text_area[i], Option_frog_selection_text[1],	MR_FONT_COLOUR_YELLOW);
//
//			// Is this the first player to join ?
//			if (Frog_selection_master_flags & FROG_SELECTION_NO_MASTER)
//				{
//				// Yes ... flag as master
//				Frog_selection_master_flags &= ~FROG_SELECTION_NO_MASTER;
//				Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_MASTER<<i);
//				}
//			}
//		else
//			{
//			// Yes ... rotate Frog
//			Frog_selection[i].fs_rot.vx = -1024;
//			Frog_selection[i].fs_rot.vy += 100;
//			Frog_selection[i].fs_rot.vy &= 4095;
//			MRRotMatrix(&Frog_selection[i].fs_rot,&Frog_anim_frames_ptr[i]->fr_matrix);
//
//			// Are we currently cowering ?
//			if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_COWERING<<i) )
//				{
//				// Yes ... end of cowering ?
//				if ( !Frog_selection_animation_count[i] )
//					{
//					// Yes ... clear cowering flag
//					Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_COWERING<<i);
//
//					// Are we current master ?
//					if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER<<i) )
//						{
//						// Yes ... clear master up for grabs
//						Frog_selection_master_flags &= ~FROG_SELECTION_MASTER_WANTED;
//						}
//					}
//				}
//			else
//				{
//				// No ... are we currently growling ?
//				if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_GROWLING<<i) )
//					{
//					// Yes ...  end of growling ?
//					if ( !Frog_selection_animation_count[i] )
//						{
//						// Yes ... clear growling flag
//						Frog_selection_master_flags &= ~(FROG_SELECTION_PLAYER1_GROWLING<<i);
//						}
//					}
//				else
//					{
//					// No ... at end of current animation ?
//					if ( !Frog_selection_animation_count[i] )
//						{
//						// Yes ... time to trigger new animation
//						if ( rand()%50 == 1 )
//							{
//							// Yes ... set animation
//							MRAnimEnvSingleSetAction(Frog_anim_env_ptr[i], rand()%8);
//							// Set animation count
//							Frog_selection_animation_count[i] = 10;
//							}
//						}
//					}
//				}
//
//			// Did player select cowering?
//			if (Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_COWERING<<i))
//				{
//				// Yes ... flag Frog as cowering
//				Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_COWERING<<i);
//
//				// Set animation
//
//				// Set animation count
//				Frog_selection_animation_count[i] = NUM_FRAMES_COWERING_ANIMATION;
//
//				// Are we the master ?
//				if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER<<i) )
//					{
//					// Yes ... put master flag up for grabs
//					Frog_selection_master_flags |= FROG_SELECTION_MASTER_WANTED;
//					}
//
//				}
//
//			// Did player select growling?
//			if ((Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_GROWLING<<i)) )
//				{
//				// Yes ... flag Frog as growling
//				Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_GROWLING<<i);
//
//				// Set animation
//
//				// Set animation count
//				Frog_selection_animation_count[i] = NUM_FRAMES_GROWLING_ANIMATION;
//
//				// Is the master flag up for grabs ?
//				if ( Frog_selection_master_flags & FROG_SELECTION_MASTER_WANTED )
//					{
//					// Yes ... clear current master
//					Frog_selection_master_flags &= ~FROG_SELECTION_ALL_MASTERS;
//					// Clear master for grabs
//					Frog_selection_master_flags &= ~FROG_SELECTION_MASTER_WANTED;
//					// Set this player as new master
//					Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_MASTER<<i);
//					}
//				}
//
//			// Has player select INCFROG?
//			if (Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_INCFROG<<i))
//				{
//				// Flag frog as selected
//				frog_already_selected_flag = TRUE;
//
//				// do
//				do
//					{
//					// Inc player's frog number
//					Frog_selection[i].fs_current_frog++;
//
//					// Past max Frogs ?
//					if ( Frog_selection[i].fs_current_frog == MAX_SELECTABLE_FROGS )
//						{
//						// Yes ... reset Frog number
//						Frog_selection[i].fs_current_frog = 0;
//						}
//
//					// Is frog already selected ?
//					if ( 1 == 1 )
//						{
//						// No ... flag frog as NOT selected
//						frog_already_selected_flag = FALSE;
//						}
//					// while frog is selected
//					} while ( frog_already_selected_flag == TRUE );
//
//				// Free current animation
//				MRAnimEnvDestroyByDisplay(Frog_anim_env_ptr[i]);
//
//				// Create frogs and add to viewport
////				Frog_anim_env_ptr[i] 	= MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + Frog_selection[i].fs_current_frog], 0, 0, Frog_anim_frames_ptr[i]);
//				Frog_anim_env_ptr[i] 	= MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0], 0, 0, Frog_anim_frames_ptr[i]);
//
//				// Try and make the Frog anim a ONE SHOT.
//				Frog_anim_env_ptr[i]->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
//
//				// Set a default animation action of zero, default behaviour so to speak
//				MRAnimEnvSingleSetAction(Frog_anim_env_ptr[i], 0);
//
//				// Attach to game viewports
//				Frog_anim_inst_ptr[i] = MRAnimAddEnvToViewport(
//									Frog_anim_env_ptr[i],
//									Option_viewport_ptr,
//									0);
//				}
//
//			// Has player pushed left ?
//			if (Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_DECFROG<<i))
//				{
//				// Flag Frog as selected
//				frog_already_selected_flag = FALSE;
//
//				// do
//				do
//					{
//					// Dec player's frog number
//					Frog_selection[i].fs_current_frog--;
//
//					// Past max frogs ?
//					if ( Frog_selection[i].fs_current_frog > MAX_SELECTABLE_FROGS-1 )
//						{
//						// Yes ... set Frog number to MAX_SELECTABLE_FROGS-1
//						Frog_selection[i].fs_current_frog = MAX_SELECTABLE_FROGS-1;
//						}
//
//					// Is frog already selected ?
//					if ( 1 == 1 )
//						{
//						// No ... flag frog as not selected
//						frog_already_selected_flag = FALSE;
//						}
//
//				// while frog is selected
//				} while ( frog_already_selected_flag == TRUE );
//
//				// Free current animation
//				MRAnimEnvDestroyByDisplay(Frog_anim_env_ptr[i]);
//
//				// Create frogs and add to viewport
////				Frog_anim_env_ptr[i] 	= MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + Frog_selection[i].fs_current_frog], 0, 0, Frog_anim_frames_ptr[i]);
//				Frog_anim_env_ptr[i] 	= MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0], 0, 0, Frog_anim_frames_ptr[i]);
//
//				// Try and make the Frog anim a ONE SHOT.
//				Frog_anim_env_ptr[i]->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
//
//				// Set a default animation action of zero, default behaviour so to speak
//				MRAnimEnvSingleSetAction(Frog_anim_env_ptr[i], 0);
//
//				// Attach to game viewports
//				Frog_anim_inst_ptr[i] = MRAnimAddEnvToViewport(
//							Frog_anim_env_ptr[i],
//							Option_viewport_ptr,
//							0);
//
//				}
//
//			// Did player push fire ?
//			if (Frog_selection_request_flags & (FROG_REQUEST_PLAYER1_FROG_SELECTED<<i))
//				{
//				// Yes ... flag frog as selected
//				Frog_selection_master_flags |= (FROG_SELECTION_PLAYER1_FROG_SELECTED<<i);
//
//				MRBuildText(Option_frog_selection_text_area[i], Option_frog_selection_text[2],	MR_FONT_COLOUR_YELLOW);
//				}
//			}
//
//		// Has this frog joined game ?
//		if ( Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_JOINED<<i) )
//			{
//			// Yes ... has it chosen a frog ?
//			if ( !(Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_FROG_SELECTED<<i)) )
//				{
//				// No ... flag exit as not possible
//				all_frogs_selected_flag = FALSE;
//				}
//			}
//
//		}
//
//	// Has the master been selected ?
//	if ( !(Frog_selection_master_flags & FROG_SELECTION_NO_MASTER) )
//		{
//		// Yes ... do particle effects around master player
//		MRBuildText(Option_frog_selection_text_area[4], Option_frog_selection_text[4],	MR_FONT_COLOUR_BLUE);
//		MRBuildText(Option_frog_selection_text_area[5], Option_frog_selection_text[4],	MR_FONT_COLOUR_BLUE);
//		MRBuildText(Option_frog_selection_text_area[6], Option_frog_selection_text[4],	MR_FONT_COLOUR_BLUE);
//		MRBuildText(Option_frog_selection_text_area[7], Option_frog_selection_text[4],	MR_FONT_COLOUR_BLUE);
//
//		// Player 1 master ?
//		if ( Frog_selection_master_flags & FROG_SELECTION_PLAYER1_MASTER )
//			MRBuildText(Option_frog_selection_text_area[4], Option_frog_selection_text[3],	MR_FONT_COLOUR_CYAN);
//
//		// Player 2 master ?
//		if ( Frog_selection_master_flags & FROG_SELECTION_PLAYER2_MASTER )
//			MRBuildText(Option_frog_selection_text_area[5], Option_frog_selection_text[3],	MR_FONT_COLOUR_CYAN);
//		
//		// Player 3 master ?
//		if ( Frog_selection_master_flags & FROG_SELECTION_PLAYER3_MASTER )
//			MRBuildText(Option_frog_selection_text_area[6], Option_frog_selection_text[3],	MR_FONT_COLOUR_CYAN);
//		
//		// Player 4 master ?
//		if ( Frog_selection_master_flags & FROG_SELECTION_PLAYER4_MASTER )
//			MRBuildText(Option_frog_selection_text_area[7], Option_frog_selection_text[3],	MR_FONT_COLOUR_CYAN);
//		}
//
//	// Flag exit as not requested
//	exit_request = FALSE;
//
//	// If all frogs are selected and there is a master player, listen to see if the 
//	// master player has requested a game start
//	if	( 
//		(all_frogs_selected_flag) && 
//		(!(Frog_selection_master_flags & FROG_SELECTION_NO_MASTER)) )
//		{
//		// If a request start game has been received by the master player, then start game
//		if (Frog_selection_request_flags & FROG_REQUEST_START_GAME)
//			{
//			// Yes ... go on to level select
//			exit_request 	= TRUE;
//			num_frogs 		= 0;
//
//			// Also store the frog id
//			for (i=0; i<4; i++)
//				{
//				if (Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER<<i))
//					Frog_selection_master_player_id	= i;
//				}
//			}
//		}
//
//	// Do we want to exit ?
//	if ( exit_request == TRUE )
//		{
//		// Yes ... are there enough frogs ?
//		if ( num_frogs > 1 )
//			{
//			// Yes ... exit
//			Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
//			}
//		}
//
//#ifdef WIN95
//	if (MR_KEY_DOWN(MRIK_ESCAPE))
//		Option_page_request = OPTIONS_PAGE_EXIT;
//#endif
}

/******************************************************************************
*%%%% FrogSelectionShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Frog Selection screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	FrogSelectionShutdown(MR_VOID)
{
	MR_LONG			i;
	MR_OBJECT*		object;


	// Kill all particle effects
	object = MRObject_root_ptr;
	while(object = object->ob_next_node)
		{
		if (object->ob_type == MR_OBJTYPE_PGEN)
			object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}

	// Remove Frogs and frames for each player
	for (i = 0; i < 4; i++)
		{
		// Kill anim env
		MRAnimEnvDestroyByDisplay(Frog_anim_env_ptr[i]);

		// Kill text sprite
		MRKill2DSprite(Frog_selection_sprites[i]);

		// Destroy lily
		High_score_view_number_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		}

	// Initialise number of players in game
	Game_total_players		= 0;
	Game_total_viewports	= 0;

	// Loop once for each frog
	for (i = 0; i < 4; i++)
		{
		// Is this frog in the game ?
		if (Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_FROG_SELECTED << i))
			{
			if (Frog_selection_master_flags & (FROG_SELECTION_PLAYER1_MASTER << i))
				{
				// This frog is the master
				Frog_selection_master_player_id	= Game_total_players;
				}
#ifdef PSX
			// Fill in the frog structure with controller, and other information...
			Frog_player_data[Game_total_players].fp_port_id		= Frog_input_ports[i];
			Game_total_viewports++;
#else
			if (MNIsNetGameRunning())
				{
				// If the player number of the player on THIS machine is the same as this loop_count,
				// mark is as LOCAL and set up a port, else, mark it as NETWORK.
				if (MNGetPlayerNumber() == i)
					{
					Frog_player_data[Game_total_players].fp_is_local	= 1;
					Frog_player_data[Game_total_players].fp_port_id		= Frog_input_ports[0];
					}
				else
					{
					Frog_player_data[Game_total_players].fp_is_local	= 0;
					}
				Game_total_viewports = 1;
				}
			else
				{
				Frog_player_data[Game_total_players].fp_is_local		= 1;
				Frog_player_data[Game_total_players].fp_port_id			= Frog_input_ports[i];
				Game_total_viewports++;
				}
#endif
			Frog_player_data[Game_total_players].fp_player_id			= i;

			// Inc number of players in game
			Game_total_players++;
			}
		}

	Game_viewports[0] = NULL;
	Game_viewports[1] = NULL;
	Game_viewports[2] = NULL;
	Game_viewports[3] = NULL;
}


/******************************************************************************
*%%%% FrogSelectionCreateFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSelectionCreateFrog(
*						MR_LONG	frog_index,
*						MR_LONG	model_index)
*
*	FUNCTION	Create a frog animation environment and link it to the viewport
*
*	INPUTS		frog_index	-	player index
*				model_index	-	frog type
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	FrogSelectionCreateFrog(MR_LONG	frog_index,
								MR_LONG	model_index)
{
	Frog_anim_env_ptr[frog_index] 	= MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*)Model_MOF_ptrs[MODEL_MOF_FROG_CONSTRUCTION_0 + model_index], 0, MR_OBJ_STATIC, (MR_FRAME*)High_score_view_number_matrix_ptr[frog_index]);

	MRAnimEnvSingleSetAction(Frog_anim_env_ptr[frog_index], GEN_FROG_PANT);

	// Scale croak sack down
	MRAnimEnvSingleCreateLWTransforms(Frog_anim_env_ptr[frog_index]);
	MRAnimEnvSingleSetPartFlags(Frog_anim_env_ptr[frog_index], THROAT, MR_ANIM_PART_TRANSFORM_PART_SPACE);
	MRAnimEnvSingleSetImportedTransform(Frog_anim_env_ptr[frog_index], THROAT, &High_score_view_frog_sack_scale_matrix);

	Frog_anim_inst_ptr[frog_index] 	= MRAnimAddEnvToViewport(Frog_anim_env_ptr[frog_index], Option_viewport_ptr, 0);

	// Set up colour scaling
	Frog_anim_inst_ptr[frog_index]->ae_mesh_insts[0]->mi_colour_scale.r = 0x20;
	Frog_anim_inst_ptr[frog_index]->ae_mesh_insts[0]->mi_colour_scale.g = 0x20;
	Frog_anim_inst_ptr[frog_index]->ae_mesh_insts[0]->mi_colour_scale.b = 0x20;
}


/******************************************************************************
*%%%% ContinueStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ContinueStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Continue screen.  Currently sets up
*				text areas for continue code.  Also initialises the count down
*				allowed to select continue choice in.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	08.08.97	Gary Richards	Added number of continues left.
*
*%%%**************************************************************************/

MR_VOID	ContinueStartup(MR_VOID)
{
#if 0
	MR_TEXTURE*	texture;

	// Create 2D sprites for continue screen
	texture 					= Options_text_textures[OPTION_TEXT_CONTINUE][Game_language];
	Continue_title_sprite_ptr 	= MRCreate2DSprite((Game_display_width>>1)-(16*4),(Game_display_height>>1)-64,Option_viewport_ptr,texture,NULL);

	Continue_time_sprite_ptr  	= MRCreate2DSprite((Game_display_width>>1)-16,(Game_display_height>>1)-16,Option_viewport_ptr,&im_32x32_9,NULL);

	texture 					= Options_text_textures[OPTION_TEXT_YES2][Game_language];
	Continue_yes_sprite_ptr   	= MRCreate2DSprite((Game_display_width>>1)-132,(Game_display_height>>1)+32,Option_viewport_ptr,texture,NULL);

	texture 					= Options_text_textures[OPTION_TEXT_NO][Game_language];
	Continue_no_sprite_ptr 	  	= MRCreate2DSprite((Game_display_width>>1)+100,(Game_display_height>>1)+32,Option_viewport_ptr,texture,NULL);

	// Initialise count down
	Options_count_down_ticks = NUM_CONTINUE_TICKS;
	Options_count_down_units = NUM_CONTINUE_UNITS;

	// Initialise current selection to yes
	Option_number = 0;
#endif

#ifdef WIN95
	Game_running = FALSE;
#endif

}

/******************************************************************************
*%%%% ContinueUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ContinueUpdate(MR_VOID)
*
*	FUNCTION	Update code for Continue screen.  Checks for continues, if the player
*				doesn't have any then it will skip straight to game over, else it will
*				count down a timer whilst allowing the player to select yes or no.  If the
*				time runs out or the player presses fire then the relevant page is
*				selected.  Meanwhile the game can be seen in the background.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ContinueUpdate(MR_VOID)
{
	OptUpdateGame();

#if 0

	// Are there any continues left ?
	//if ( !Num_continues )
	//	{
	//	// No ... go to game over
	//	Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
	//	}

	// Dec ticks
	Options_count_down_ticks--;

	// Ticks zero ?
	if ( !Options_count_down_ticks )
		{
		// Do we have any continue units left ?
		if ( Options_count_down_units )
			{
			// Yes ... dec continue units
			Options_count_down_units--;
			// Reset ticks count
			Options_count_down_ticks = NUM_CONTINUE_TICKS;
			}
		}

	// Do we still have continue time left ?
	if ( Options_count_down_units || Options_count_down_ticks )
		{

		// Yes ... did player push right ?
		if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_RIGHT) )
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

			// Yes ... were we on yes ?
			if ( Option_number == 0 )
				{
				// Yes ... go to no
				Option_number = 1;
				}
			else
				{
				// No ... go to yes
				Option_number = 0;
				}
			}

		// Did player push left ?
		if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_LEFT) )
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

			// Yes ... were we on no ?
			if ( Option_number == 1 )
				{
				// Yes ... go to yes
				Option_number = 0;
				}
			else
				{
				// No ... go to no
				Option_number = 1;
				}
			}

		// Did player push fire ?
		if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

			// Yes ... were we on yes ?
			if ( Option_number == 0 )
				{
				// Yes ... go back to level select
				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
//				Option_page_request = OPTIONS_PAGE_GAME;

				// initialise the player data
				GameInitialise();
				}
			else
				{
				// No ... go to game over
//				Option_page_request = OPTIONS_PAGE_GAME_OVER;
//				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
				Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
				}
			}
		}
	else
		{
		// No ... were we on yes ?
		if ( Option_number == 0 )
			{
			// Yes ... go back to game
			Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
//			Option_page_request = OPTIONS_PAGE_GAME;

			// initialise the player data
			GameInitialise();
			}
		else
			{
			// No ... go to game over
//			Option_page_request = OPTIONS_PAGE_GAME_OVER;
//			Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
			Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
			}
		}

	// Is yes selected ?
	if ( Option_number == 0 )
		{
		// Yes ... display "YES" in selected colour
		MRChangeSprite(Continue_yes_sprite_ptr, Options_text_textures[OPTION_TEXT_YES2][Game_language]);
		// Display "NO" in deselected colour
		MRChangeSprite(Continue_no_sprite_ptr, Options_text_textures[OPTION_TEXT_NO][Game_language]);
		}
	else
		{
		// No ... display "NO" in selected colour
		MRChangeSprite(Continue_no_sprite_ptr, Options_text_textures[OPTION_TEXT_NO2][Game_language]);
		// Display "YES" in deselected colour
		MRChangeSprite(Continue_yes_sprite_ptr, Options_text_textures[OPTION_TEXT_YES][Game_language]);
		}

	// Update timer text
	MRChangeSprite(Continue_time_sprite_ptr,Continue_time_sprite_table[Options_count_down_units]);

#else

	// Are we in race mode ?
	if ( Sel_mode == SEL_MODE_RACE )
		{
		// Yes ... according to exit from choose course do ...
		switch ( Option_number )
			{
			// Play again ...
			case 0:
				Option_page_request = OPTIONS_PAGE_GAME;
				break;
			// Choose different course ...
			case 1:
				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
				break;
			// Exit ...
			case 2:
//				Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
				Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
				break;
			}
		}
	else
		{
		// No ... go on to high score input
		Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
		}

#endif

}

/******************************************************************************
*%%%% ContinueShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ContinueShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Continue screen.  Currently just frees the
*				allocated text areas.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ContinueShutdown(MR_VOID)
{
#if 0
	// Kill 2D sprites
	MRKill2DSprite(Continue_title_sprite_ptr);
	MRKill2DSprite(Continue_time_sprite_ptr);
	MRKill2DSprite(Continue_yes_sprite_ptr);
	MRKill2DSprite(Continue_no_sprite_ptr);
	//MRKill2DSprite(Continue_left_ptr);
#endif

#ifdef WIN95
	Game_running = TRUE;
#endif

	GameEnd();

	if (Option_page_request != OPTIONS_PAGE_LEVEL_SELECT)
		{
		// We have elected NOT to continue: go back to main menu
		}
}


/******************************************************************************
*%%%% GameOverStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameOverStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Game Over screen.  Currently just initialises
*				the text and time.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	GameOverStartup(MR_VOID)
{
	MR_TEXTURE*	texture0;
	
	// Create sprites
	texture0					= Options_text_textures[OPTION_TEXT_GAMEOVER][Game_language];
	Gameover_title_sprite_ptr 	= MRCreate2DSprite((Game_display_width>>1)-(texture0->te_w>>1),(Game_display_height>>1)-(texture0->te_h>>1),Option_viewport_ptr,texture0,NULL);
	Gameover_title_sprite_ptr->sp_core.sc_base_colour.r = 0;
	Gameover_title_sprite_ptr->sp_core.sc_base_colour.g = 0;
	Gameover_title_sprite_ptr->sp_core.sc_base_colour.b = 0;

	if (Game_paused_selection == HIDDEN_MENU_QUIT_GAME)
		{
		// Got here from quitting the game
		Options_count_down_units 	= GAME_OVER_DURATION + 30 - 15;
		}
	else
		{
		// Initialise count down
		Options_count_down_units 	= GAME_OVER_DURATION + GAME_OVER_PREDELAY;
		}

	// Game over finished.
	Game_over_no_new_sound = TRUE;

#ifdef	PSX
#ifdef	PSX_ENABLE_XA
	// Play's Game Over.
	XAPlayChannel(LEVEL_TUNES5,3,FALSE);
#endif
#endif

}


/******************************************************************************
*%%%% GameOverUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameOverUpdate(MR_VOID)
*
*	FUNCTION	Update code for Game Over screen.  Waits for button press or time
*				limit before going on to high score input.  Also continues to render
*				the last game screen in the background.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	GameOverUpdate(MR_VOID)
{
	MR_LONG		i;
	POLY_F4*	poly_f4;

	// Update game
	OptUpdateGame();

	// And kill all SFX.
	LiveEntityChangeVolume(0, FALSE);

	Options_count_down_units--;

	if (Options_count_down_units < GAME_OVER_DURATION + 30)
		{
		// Screen has faded down
		if (!Options_count_down_units)
			{
			Option_page_request = OPTIONS_PAGE_CONTINUE;
			}
		else
			{
			if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
				{
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				Option_page_request = OPTIONS_PAGE_CONTINUE;
				}
			}
	
		// Fade screen over 1 second, and GAME OVER sprite up in same time
		i 			= MIN(0xff, ((GAME_OVER_DURATION + 30 - Options_count_down_units) * 0xff) / 30);
		poly_f4 	= &Pause_poly[MRFrame_index];
		poly_f4->r0 = i;
		poly_f4->g0 = i;
		poly_f4->b0 = i;
	
		i >>= 1;
		Gameover_title_sprite_ptr->sp_core.sc_base_colour.r = i;
		Gameover_title_sprite_ptr->sp_core.sc_base_colour.g = i;
		Gameover_title_sprite_ptr->sp_core.sc_base_colour.b = i;
	
		GamePauseAddPrim();
		}
}

/******************************************************************************
*%%%% GameOverShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	GameOverShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Game Over screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	GameOverShutdown(MR_VOID)
{
	// Game over finished.
	Game_over_no_new_sound = FALSE;

	// Kill 2D sprite
	MRKill2DSprite(Gameover_title_sprite_ptr);
}


/******************************************************************************
*%%%% OutroStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OutroStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Outro screen.  Currently does nothing.
*			Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	OutroStartup(MR_VOID)
{
	// Does nothing ... ( yet!!! )
}

/******************************************************************************
*%%%% OutroUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OutroUpdate(MR_VOID)
*
*	FUNCTION	Update code for Outro screen.  Starts video stream and exits when
*				button pressed or stream finished.  Then goes on
*			to either standard or extended credits depending on type of
*			outro shown.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	23.08.97	Gary Richards	Re-coded.
*
*%%%**************************************************************************/

MR_VOID	OutroUpdate(MR_VOID)
{

#ifdef	PSX
	// Kill all viewports/camera frames etc...
	KillOptionsForStream();

	// Create 24bit for stream playback.
	MRCreateDisplay(MR_SCREEN_TRUECOLOUR_STANDARD_256);

#ifdef	PSX_CD_STREAMS

	// Play outro.
	Play_stream(STR_OUTRO);

#endif	// PSX_CD_STREAMS

	// Remove the 24Bit display.
	MRKillDisplay();	

	// Create a standard one in it's place.
	MRCreateDisplay(SYSTEM_DISPLAY_MODE);
		 
	// Now we have to put everything back to how it was.
	CreateOptionsAfterStream();
#endif

	// Leave Outro/Credits and go on to high score input
	Option_page_request = OPTIONS_PAGE_CREDITS;
}

/******************************************************************************
*%%%% OutroShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OutroShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Outro screen.  Currently does nothing.
*			Maybe needed later.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	OutroShutdown(MR_VOID)
{
	// Does nothing ... ( yet!!! )
}


/******************************************************************************
*%%%% OptionsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Options screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	OptionsStartup(MR_VOID)
{
	MR_LONG		i, k;
	FROG*		frog;

	// Make sure the music hasn't stopped.
	PlayOptionsMusic();

	// Copy title textures to shadow textures
	for (i = 0; i < (OPTIONS_NUM_OPTIONS - 2); i++)
		{
		// Copy structure
		Options_shadow_textures[i] = *Options_title_textures[Game_language][i];

		// Set new abr
		Options_shadow_textures[i].te_tpage_id = setABR(Options_shadow_textures[i].te_tpage_id, 2);
		}

	// Allocate memory for all matrices
	// (1 frog, 7/8 numbers (blank), 7/8 initials (titles), 2 logs, extras)
	High_score_matrices = MRAllocMem(sizeof(MR_MAT) * (1 + OPTIONS_NUM_OPTIONS + OPTIONS_NUM_OPTIONS + 2 + OPTIONS_NUM_EXTRAS), "HS matrices");

	High_score_view_frog_anim_matrix_ptr 		= High_score_matrices;
	for (k = 0; k < OPTIONS_NUM_OPTIONS; k++)	
		High_score_view_number_matrix_ptr[k] 	= High_score_matrices + 1 + k;
	for (k = 0; k < OPTIONS_NUM_OPTIONS; k++)	
		High_score_view_initials_matrix_ptr[k] 	= High_score_matrices + 1 + OPTIONS_NUM_OPTIONS + k;
	for (k = 0; k < 2; k++)	
		High_score_view_log_matrix_ptr[k]		= High_score_matrices + 1 + OPTIONS_NUM_OPTIONS + OPTIONS_NUM_OPTIONS + k;
	for (k = 0; k < OPTIONS_NUM_EXTRAS; k++)	
		Options_extras_matrix_ptr[k]			= High_score_matrices + 1 + OPTIONS_NUM_OPTIONS + OPTIONS_NUM_OPTIONS + 2 + k;

	// Create extras
	for (i = 0; i < OPTIONS_NUM_EXTRAS; i++)
		{
		MR_INIT_MAT(Options_extras_matrix_ptr[i]);
		Options_extras_matrix_ptr[i]->t[0] 	= Options_extras_coords[(i << 1) + 0];
		Options_extras_matrix_ptr[i]->t[1] 	= OPTIONS_CAMERA_FLYON_HEIGHT;
		Options_extras_matrix_ptr[i]->t[2] 	= Options_extras_coords[(i << 1) + 1];
		Options_extras_object_ptr[i] 		= MRCreateMesh(MR_GET_RESOURCE_ADDR(Options_extras_resource_id[i]), (MR_FRAME*)Options_extras_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		Options_extras_mesh_inst_ptr[i] 	= MRAddObjectToViewport(Options_extras_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Extras 0,1 are music and SFX models: use custom colours
	Options_extras_mesh_inst_ptr[0]->mi_light_flags |= MR_INST_USE_CUSTOM_AMBIENT;
	Options_extras_mesh_inst_ptr[1]->mi_light_flags |= MR_INST_USE_CUSTOM_AMBIENT;

	// Create blank lillies down left hand side (0 a top)
	for (i = 0; i < OPTIONS_NUM_OPTIONS; i++)
		{
		MR_INIT_MAT(High_score_view_number_matrix_ptr[i]);
		High_score_view_number_matrix_ptr[i]->t[0] =  -0x380;
		High_score_view_number_matrix_ptr[i]->t[1] = OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_number_matrix_ptr[i]->t[2] = (-7 * 0xc0) + (((OPTIONS_NUM_OPTIONS - 0) - i) * 0x180);

		High_score_view_number_object_ptr[i] = MRCreateMesh(MR_GET_RESOURCE_ADDR(RES_OPT_LILLYPAD_BLANK_XMR), (MR_FRAME*)High_score_view_number_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_view_number_object_ptr[i], Option_viewport_ptr, 0);
		}

	// Create logs for FX and music volume
	for (i = 0; i < 2; i++)
		{
		MR_INIT_MAT(High_score_view_log_matrix_ptr[i]);
		High_score_view_log_matrix_ptr[i]->t[0] =  0;
		High_score_view_log_matrix_ptr[i]->t[1]	= OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_log_matrix_ptr[i]->t[2] = (-7 * 0xc0) + ((2 - i) * 0x180);

		High_score_view_log_object_ptr[i] = MRCreateMesh(MR_GET_RESOURCE_ADDR(RES_HI_LOG_XMR), (MR_FRAME*)High_score_view_log_matrix_ptr[i], MR_OBJ_STATIC, NULL);
		MRAddObjectToViewport(High_score_view_log_object_ptr[i], Option_viewport_ptr, 0);

		High_score_view_log_object_ptr[i]->ob_extra.ob_extra_mesh->me_flags |= MR_MESH_PAUSE_ANIMATED_POLYS;
		}
	// Set up animated polys
	OptionsSetupVolumeLogAnimatedPolys(High_score_view_log_object_ptr[0]->ob_extra.ob_extra_mesh, Music_volume);
	OptionsSetupVolumeLogAnimatedPolys(High_score_view_log_object_ptr[1]->ob_extra.ob_extra_mesh, Sound_volume);

	// Create title 3D sprites
	k = 0;
	for (i = 0; i < OPTIONS_NUM_OPTIONS - 2; i++)
		{
		MR_INIT_MAT(High_score_view_initials_matrix_ptr[i]);
		High_score_view_initials_matrix_ptr[i]->t[0] = -0x200 + ((Options_title_textures[Game_language][i]->te_w >> 1) * 0x8);
		High_score_view_initials_matrix_ptr[i]->t[1] = OPTIONS_CAMERA_FLYON_HEIGHT;
		High_score_view_initials_matrix_ptr[i]->t[2] = (-7 * 0xc0) + (((OPTIONS_NUM_OPTIONS - 0) - i) * 0x180);

		High_score_view_initials_object_ptr[i] = MRCreate3DSprite((MR_FRAME*)High_score_view_initials_matrix_ptr[i], MR_OBJ_STATIC, Options_title_textures[Game_language][i]);
		High_score_view_initials_object_ptr[i]->ob_extra.ob_extra_sp_core->sc_scale = (10 << 16);
		High_score_view_initials_object_ptr[i]->ob_extra.ob_extra_3dsprite->sp_ofs_image.vy = -0x40;

		MRAddObjectToViewport(High_score_view_initials_object_ptr[i], Option_viewport_ptr, 0);

		Option_spcore_ptrs[i] = (MR_SP_CORE*)High_score_view_initials_object_ptr[i]->ob_extra.ob_extra_3dsprite;
		k++;
		}

	// Create reflections (use same matrices)
	for (i = 0; i < OPTIONS_NUM_OPTIONS - 2; i++)
		{
		High_score_view_initials_object_ptr[k] = MRCreate3DSprite((MR_FRAME*)High_score_view_initials_matrix_ptr[i], MR_OBJ_STATIC, &Options_shadow_textures[i]);
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_scale 		= (10 << 16);
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_flags			|= MR_SPF_IN_XZ_PLANE;
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_ot_offset		= 0x10;
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_base_colour.r = 0x40;
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_base_colour.g = 0x40;
		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_sp_core->sc_base_colour.b = 0x40;

		High_score_view_initials_object_ptr[k]->ob_extra.ob_extra_3dsprite->sp_ofs_image.vz = 0x48;

		MRAddObjectToViewport(High_score_view_initials_object_ptr[k], Option_viewport_ptr, 0);
		k++;
		}

	// Create Frog ready to jump up lillies
	//
	// Get address of Frog model in memory
	High_score_view_frog_anim_model_ptr = MR_GET_RESOURCE_ADDR(RES_GEN_FROG_XAR);

	MR_INIT_MAT(High_score_view_frog_anim_matrix_ptr);

	// Create frogs and add to viewport
	High_score_view_frog_anim_env_ptr = MRAnimEnvSingleCreateWhole(High_score_view_frog_anim_model_ptr, 0, MR_OBJ_STATIC, (MR_FRAME*)High_score_view_frog_anim_matrix_ptr);

	// Try and make the Frog anim a ONE SHOT.
	High_score_view_frog_anim_env_ptr->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

	// Set a default animation action of zero, default behaviour so to speak
	MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_WAIT2);
	High_score_view_frog_anim_env_ptr->ae_update_period = 2;

	// Scale croak sack down
	MRAnimEnvSingleCreateLWTransforms(High_score_view_frog_anim_env_ptr);
	MRAnimEnvSingleSetPartFlags(High_score_view_frog_anim_env_ptr, THROAT, MR_ANIM_PART_TRANSFORM_PART_SPACE);
	MRAnimEnvSingleSetImportedTransform(High_score_view_frog_anim_env_ptr, THROAT, &High_score_view_frog_sack_scale_matrix);
	MR_INIT_MAT(&High_score_view_frog_sack_scale_matrix);
	High_score_view_frog_sack_scale_matrix.m[0][0] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[1][1] = FROG_CROAK_MIN_SCALE;
	High_score_view_frog_sack_scale_matrix.m[2][2] = FROG_CROAK_MIN_SCALE;

	// Attach to game viewports
	MRAnimAddEnvToViewport(High_score_view_frog_anim_env_ptr, Option_viewport_ptr, 0);
	
	// Only reset current selection if coming from main triple menu
	if (From_options == TRUE)
		{
		From_options 				= FALSE;
		Options_current_selection 	= 0;
		}
	Options_update_mode = OPTION_UPDATE_MODE_MAIN;

	// Use Frogs[0] to store info about frog jumping along numbers
	frog		   		= &Frogs[0];
	frog->fr_lwtrans 	= High_score_view_frog_anim_matrix_ptr;
	frog->fr_grid_z		= Options_current_selection;						// lily that frog starts on
	frog->fr_mode 		= FROG_MODE_STATIONARY;
	frog->fr_count		= 0;
	frog->fr_pos.vx		= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[0] << 16;
	frog->fr_pos.vy		= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1] << 16;
	frog->fr_pos.vz		= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[2] << 16;
	frog->fr_direction 	= FROG_DIRECTION_S;

	// Create shadow for frog
	frog->fr_shadow 			= CreateShadow(Frog_jump_shadow_textures[0], frog->fr_lwtrans, Frog_jump_shadow_offsets[0]);
	frog->fr_shadow->ef_flags	|= EFFECT_STATIC;
	frog->fr_shadow->ef_flags	&= ~EFFECT_KILL_WHEN_FINISHED;

	High_score_view_flyon_counter 	= OPTIONS_CAMERA_FLYON_TIME;
	High_score_view_delayed_request	= NULL;
}


/******************************************************************************
*%%%% OptionsSetupVolumeLogAnimatedPolys
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsSetupVolumeLogAnimatedPolys(
*						MR_MESH*	mesh_ptr,
*						MR_LONG		volume)
*
*	FUNCTION	Set up animated polys on HI_LOG to show 8-stage volume
*
*	INPUTS		mesh_ptr	-	ptr to log mesh
*				volume		-	0..8
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsSetupVolumeLogAnimatedPolys(	MR_MESH*	mesh_ptr,
											MR_LONG		volume)
{
	MR_LONG	i, k;


	if (volume == 0)
		{
		i = 1;
		}
	else
		{
		for (i = 1; i <= 8; i++)
			{
			if (volume == i)
				{
				// 'Half' image
				for (k = 0; k < 8; k++)
					MRMeshAnimatedPolySetCel(mesh_ptr, High_score_log_animated_poly_indices[(i - 1)] + k, 12);
				i++;
				break;
				}			
			// 'Full' image
			for (k = 0; k < 8; k++)
				MRMeshAnimatedPolySetCel(mesh_ptr, High_score_log_animated_poly_indices[(i - 1)] + k, 11);
			}
		}

	while(i <= 8)
		{
		// 'Blank' image
		for (k = 0; k < 8; k++)
			MRMeshAnimatedPolySetCel(mesh_ptr, High_score_log_animated_poly_indices[(i - 1)] + k, 10);
		i++;
		}
}


/******************************************************************************
*%%%% OptionsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsUpdate(MR_VOID)
*
*	FUNCTION	Update code for Options screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	OptionsUpdate(MR_VOID)
{
	EFFECT*		effect;
	SHADOW*		shadow;
	MR_LONG		i, cos, sin;
	FROG*		frog;
	MR_MAT		transform;


	frog = &Frogs[0];

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();
	HSUpdateFlying();

	// Set up scale matrix to enlarge all models
	MRScale_matrix.m[0][0] = 0x1600;
	MRScale_matrix.m[1][1] = 0x1600;
	MRScale_matrix.m[2][2] = 0x1600;

	// Apply wave deltas to lillies
	HSProjectMatricesOntoWaterSurface(High_score_view_number_matrix_ptr[0], OPTIONS_NUM_OPTIONS, &MRScale_matrix);

	// Apply wave deltas to logs
	MRRot_matrix_X.m[1][1] = -0x1000;
	MRRot_matrix_X.m[1][2] =  0;
	MRRot_matrix_X.m[2][1] =  0;
	MRRot_matrix_X.m[2][2] = -0x1000;
	MRScale_matrix.m[0][0] = 0x1300;
	MRScale_matrix.m[1][1] = 0x1300;
	MRScale_matrix.m[2][2] = 0x1300;
	MRMulMatrixABC(&MRScale_matrix, &MRRot_matrix_X, &transform);
	HSProjectMatricesOntoWaterSurface(High_score_view_log_matrix_ptr[0], 2, &transform);

	// Apply wave deltas to titles
	MRScale_matrix.m[0][0] = 0x1000;
	MRScale_matrix.m[1][1] = 0x1400;
	MRScale_matrix.m[2][2] = 0x1000;
	HSProjectMatricesOntoWaterSurface(High_score_view_initials_matrix_ptr[0], OPTIONS_NUM_OPTIONS - 2, &MRScale_matrix);

	// Apply wave deltas to extras (not volume models)
	MRScale_matrix.m[0][0] = 0x1800;
	MRScale_matrix.m[1][1] = 0x1800;
	MRScale_matrix.m[2][2] = 0x1800;
	HSProjectMatricesOntoWaterSurface(Options_extras_matrix_ptr[2], OPTIONS_NUM_EXTRAS - 2, &MRScale_matrix);

	// Apply wave deltas to extras (volume models)
	cos = rcos(0x400);
	sin = rsin(0x400);
	MRRot_matrix_X.m[1][1] =  cos;
	MRRot_matrix_X.m[1][2] = -sin;
	MRRot_matrix_X.m[2][1] =  sin;
	MRRot_matrix_X.m[2][2] =  cos;
	cos = rcos(Option_viewport_ptr->vp_frame_count << 8);
	sin = rsin(Option_viewport_ptr->vp_frame_count << 8);
	MRRot_matrix_Y.m[0][0] =  cos;
	MRRot_matrix_Y.m[0][2] =  sin;
	MRRot_matrix_Y.m[2][0] = -sin;
	MRRot_matrix_Y.m[2][2] =  cos;
	MRMulMatrixABC(&MRRot_matrix_Y, &MRRot_matrix_X, &transform);
	HSProjectMatricesOntoWaterSurface(Options_extras_matrix_ptr[0], 2, &transform);

	// Extras 0,1 are music and SFX models: ramp custom colours
	Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.r = 0x20;
	Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.g = 0x20;
	Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.b = 0x20;
	Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.r = 0x20;
	Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.g = 0x20;
	Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.b = 0x20;

	// Move frog
	OptionsUpdateFrog();
	UpdateEffects();

	Option_spcore_index = Frogs[0].fr_grid_z;

	// UpdateEffects has set y of shadow vertices to frog y... we want to project them onto the water
	if (effect = Frogs[0].fr_shadow)
		{
		shadow = effect->ef_extra;
		for (i = 0; i < 4; i++)						
			shadow->sh_corners[0][i].vy = HSGetWaterSurfaceInfoFromXZ(shadow->sh_corners[0][i].vx, shadow->sh_corners[0][i].vz, NULL, NULL);
		}

	// Was triangle pressed ?
	if ( MR_CHECK_PAD_PRESSED(frog->fr_input_id,FRR_TRIANGLE) )
		{
		// Yes ... kill all current sounds ( including sound test )
		if ( Sound_voice != -1 )
			{
			MRSNDKillSound(Sound_voice);
			Sound_voice = -1;
			}
		MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
//		MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_OUCH);

		// Skip back to main options
		High_score_view_delayed_request 	= OPTIONS_PAGE_MAIN_OPTIONS;
		High_score_view_flyoff_counter 		= OPTIONS_CAMERA_FLYOFF_TIME;

		// Start moving camera NOW
		OptionsCameraMoveToMain();
		High_score_view_flyoff_counter 		= OPTIONS_CAMERA_FLYOFF_TIME;

		// Exit now!
		return;
		}

	// According to mode do ...
	switch (Options_update_mode)
		{
		//------------------------------------------------------------------------
		// Main menu
		//------------------------------------------------------------------------
		case OPTION_UPDATE_MODE_MAIN:
			// According to current lilly do update
			if (frog->fr_mode == FROG_MODE_STATIONARY)
				{
				switch(frog->fr_grid_z)
					{
					//----------------------------------------------------------------
					case OPTIONS_FX_OPTION:
						// Update FX volume
						Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.r = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.g = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						Options_extras_mesh_inst_ptr[1]->mi_custom_ambient.b = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_RIGHT))
							{
							if (Sound_volume < OPTIONS_SOUND_STAGES)
								{
								Sound_volume++;
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								if (Sound_volume == 1)
									{
									// Yes ... trigger (repeating) croak animation
									MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_PANT2);
									High_score_view_frog_anim_env_ptr->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
									}
								}
							}
						else
						if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_LEFT))
							{
							if (Sound_volume)
								{
								Sound_volume--;
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								if (!Sound_volume)
									{
									// Yes ... stop croak animation
									High_score_view_frog_anim_env_ptr->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
									}
								}
							}
	
						// Commit sound volume
						MRSNDSetVolumeLevel(MRSND_FX_VOLUME, (127 * Sound_volume) / OPTIONS_SOUND_STAGES);
	
						// Set up animated polys
						OptionsSetupVolumeLogAnimatedPolys(High_score_view_log_object_ptr[1]->ob_extra.ob_extra_mesh, Sound_volume);
						break;
					//----------------------------------------------------------------
					case OPTIONS_MUSIC_OPTION:
						// Update music volume
						Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.r = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.g = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						Options_extras_mesh_inst_ptr[0]->mi_custom_ambient.b = (Option_viewport_ptr->vp_frame_count & 0x7) << 5;
						if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_RIGHT))
							{
							if (Music_volume < OPTIONS_SOUND_STAGES)
								{
								Music_volume++;
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								if (Music_volume == 1)
									{
									// Yes ... trigger (repeating) croak animation
									MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_DANCE);
									High_score_view_frog_anim_env_ptr->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
									}
								}
							}
						else
						if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, FRR_LEFT))
							{
							if (Music_volume)
								{
								Music_volume--;
								MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);
								if (!Music_volume)
									{
									// Yes ... stop croak animation
									High_score_view_frog_anim_env_ptr->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
									}
								}
							}
	
						// Commit music volume
						MRSNDSetVolumeLevel(MRSND_CD_VOLUME, (127 * Music_volume) / OPTIONS_SOUND_STAGES);

						// Set up animated polys
						OptionsSetupVolumeLogAnimatedPolys(High_score_view_log_object_ptr[0]->ob_extra.ob_extra_mesh, Music_volume);
						break;
					//----------------------------------------------------------------
					}

				// Was fire pressed ?
				if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
					{
					MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);
					MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_OUCH);

					// Do action accordingly
					switch(frog->fr_grid_z)
						{
						case OPTIONS_EXIT_OPTION:
							// Skip back to main options
							High_score_view_delayed_request 	= OPTIONS_PAGE_MAIN_OPTIONS;
							High_score_view_flyoff_counter 		= OPTIONS_CAMERA_FLYOFF_TIME;

							// Start moving camera NOW
							OptionsCameraMoveToMain();
							High_score_view_flyoff_counter 		= OPTIONS_CAMERA_FLYOFF_TIME;
							break;

						case OPTIONS_VIEW_HIGH_SCORES_OPTION:
							// Ask for high score view, starting in arcade mode, operating in manual mode
							High_score_operation_mode 			= HIGH_SCORE_OPERATION_MODE_LEVEL_SELECT;
							High_score_camera_operation_mode 	= HIGH_SCORE_CAMERA_OPERATION_MODE_STATIC;
							Sel_mode 							= SEL_MODE_ARCADE;
							From_options 						= TRUE;
							HSView_automatic_flag 				= FALSE;

//							High_score_view_delayed_request 	= OPTIONS_PAGE_HIGH_SCORE_VIEW;
//							High_score_view_flyoff_counter 		= OPTIONS_CAMERA_FLYOFF_TIME;
							Option_page_request 				= OPTIONS_PAGE_HIGH_SCORE_VIEW;
							break;

						case OPTIONS_LOAD_HS_OPTION:
							// Go on to load high scores
							High_score_view_delayed_request	= OPTIONS_PAGE_LOAD;

							// Start moving camera NOW
							MR_SET_SVEC(&Cameras[0].ca_next_source_ofs, 1500, -2400, -1000);
							MR_SET_SVEC(&Cameras[0].ca_next_target_ofs,	0, 0, 0);
							Cameras[0].ca_move_timer 		= OPTIONS_CAMERA_MOVE_TIME;
							High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
							break;

						case OPTIONS_SAVE_HS_OPTION:
							// Go on to save high scores
							High_score_view_delayed_request	= OPTIONS_PAGE_SAVE;

							// Start moving camera NOW
							MR_SET_SVEC(&Cameras[0].ca_next_source_ofs, 1500, -2400, -1000);
							MR_SET_SVEC(&Cameras[0].ca_next_target_ofs,	0, 0, 0);
							Cameras[0].ca_move_timer 		= OPTIONS_CAMERA_MOVE_TIME;
							High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
							break;

						case OPTIONS_CTRL_CONFIG_OPTION:
							// Go on to control configuration
#ifdef  PSX
							High_score_view_delayed_request = OPTIONS_PAGE_REDEFINE_PSX_BUTTONS;
#else
							High_score_view_delayed_request = OPTIONS_PAGE_CHOOSE_WIN_CONTROLLER;
#endif
							// Start moving camera NOW
							MR_SET_SVEC(&Cameras[0].ca_next_source_ofs, 1500, -2400, -1000);
							MR_SET_SVEC(&Cameras[0].ca_next_target_ofs,	0, 0, 0);
							Cameras[0].ca_move_timer 		= OPTIONS_CAMERA_MOVE_TIME;
							High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
							break;
						}
					}
				}
			break;

		//------------------------------------------------------------------------
		// Language selection
		//------------------------------------------------------------------------
		case OPTION_UPDATE_MODE_LANG_MAIN:
			LanguageSelectionUpdate();
			break;

		case OPTION_UPDATE_MODE_LANG_DEINIT:
			LanguageSelectionShutdown();
			Options_update_mode = OPTION_UPDATE_MODE_MAIN;
			break;
		}
}


/******************************************************************************
*%%%% OptionsUpdateFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsUpdateFrog(MR_VOID)
*
*	FUNCTION	Move the frog around the number pads
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsUpdateFrog(MR_VOID)
{
	FROG*		frog;
	MR_MAT		matrix;
	MR_LONG		i, dy, old_grid_z;
	MR_OBJECT*	object_ptr;
	EFFECT*		effect;
	SHADOW*		shadow;
	MR_BOOL		jump;


	frog = &Frogs[0];
	switch(frog->fr_mode)
		{
		//--------------------------------------------------------------------
		case FROG_MODE_STATIONARY:
			// Get y coord from current pad
			frog->fr_pos.vy	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1] << 16;
			jump			= FALSE;
			old_grid_z		= frog->fr_grid_z;
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_UP)) &&
				(frog->fr_grid_z > 0)
				)
				{
				// Jump up
				frog->fr_direction = FROG_DIRECTION_N;
				frog->fr_grid_z--;
				jump = TRUE;
				}
			else
			if	(
				(MR_CHECK_PAD_HELD(frog->fr_input_id, FRR_DOWN)) &&
				(frog->fr_grid_z < (OPTIONS_NUM_OPTIONS - 1))
				)
				{
				// Jump up
				frog->fr_direction = FROG_DIRECTION_S;
				frog->fr_grid_z++;
				jump = TRUE;
				}

			if (jump == TRUE)			
				{
				frog->fr_mode			= FROG_MODE_JUMPING;
				frog->fr_count			= HIGH_SCORE_VIEW_FROG_JUMP_TIME;

				// Calculate target pos
				frog->fr_target_pos.vx 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[0];
				frog->fr_target_pos.vy 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1];
				frog->fr_target_pos.vz 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[2];

				frog->fr_y				= frog->fr_pos.vy;
				frog->fr_velocity.vx 	= ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
				frog->fr_velocity.vz 	= ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;

				MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_HOP);
				// Play Sound Effect when jumping.
				MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, 0);

				// Do stuff according to where we jumped from
				switch(old_grid_z)
					{
					case OPTIONS_FX_OPTION:
						MRSNDKillSound(Sound_voice);
						Sound_voice = -1;
						break;

					case OPTIONS_MUSIC_OPTION:
						break;
					}
				}

			// Get rotation from current pad (scaled up)
			MR_COPY_MAT(frog->fr_lwtrans, High_score_view_number_matrix_ptr[frog->fr_grid_z]);
			MRScale_matrix.m[0][0] = 0x1400;
			MRScale_matrix.m[1][1] = 0x1400;
			MRScale_matrix.m[2][2] = 0x1400;
			MRMulMatrixABB(&MRScale_matrix, frog->fr_lwtrans);
						
			if (frog->fr_direction == FROG_DIRECTION_S)
				{
				MR_INIT_MAT(&matrix);
				matrix.m[0][0] = -0x1000;
				matrix.m[0][2] =  0;
				matrix.m[2][0] =  0;
				matrix.m[2][2] = -0x1000;
				MRMulMatrixABB(&matrix, frog->fr_lwtrans);
				}
			break;
		//--------------------------------------------------------------------
		case FROG_MODE_JUMPING:
			// Handle jump
			//
			// Move fr_y in a line from source to target: actual y is parabola offset from this
			frog->fr_target_pos.vy 	= High_score_view_number_matrix_ptr[frog->fr_grid_z]->t[1];
			frog->fr_y 				+= ((frog->fr_target_pos.vy << 16) - frog->fr_y) / frog->fr_count;

			dy						= (-8 << 16)  * (MR_SQR(HIGH_SCORE_VIEW_FROG_JUMP_TIME >> 1) - MR_SQR(frog->fr_count - (HIGH_SCORE_VIEW_FROG_JUMP_TIME >> 1)));
			frog->fr_pos.vy 		= frog->fr_y + dy;

			frog->fr_pos.vx 		+= frog->fr_velocity.vx;
			frog->fr_pos.vz 		+= frog->fr_velocity.vz;

			if (!(--frog->fr_count))
				{
				// Jump complete
				frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
				frog->fr_pos.vy = frog->fr_target_pos.vy << 16;
				frog->fr_pos.vz = frog->fr_target_pos.vz << 16;

				frog->fr_mode	= FROG_MODE_STATIONARY;
				MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_WAIT1);

				// Create splash sprite
				object_ptr = MRCreate3DSprite((MR_FRAME*)High_score_view_number_matrix_ptr[frog->fr_grid_z], MR_OBJ_STATIC, High_score_splash_animlist);
				MRAddObjectToViewport(object_ptr, Option_viewport_ptr, NULL);

				// Play Sound Effect when jumping.
				MRSNDPlaySound(SFX_GEN_FROG_SPLASH1, NULL, 0, 0);

				object_ptr->ob_extra.ob_extra_sp_core->sc_flags 	|= MR_SPF_IN_XZ_PLANE;
				object_ptr->ob_extra.ob_extra_sp_core->sc_ot_offset = -0x8;
				object_ptr->ob_extra.ob_extra_sp_core->sc_scale		= 10 << 16;

				// Do stuff according to where we jumped to
				switch(frog->fr_grid_z)
					{
					case OPTIONS_FX_OPTION:
						Sound_voice = MRSNDPlaySound(SFX_GEN_FROG_CROAK_REPEAT, NULL, 0, 0);
						MRSNDSetVolumeLevel(MRSND_FX_VOLUME, (127 * Sound_volume) / OPTIONS_SOUND_STAGES);
						break;

					case OPTIONS_MUSIC_OPTION:
						MRSNDSetVolumeLevel(MRSND_CD_VOLUME, (127 * Music_volume) / OPTIONS_SOUND_STAGES);

						// Is music volume greater than zero ?
						if (Music_volume > 0)
							{
							// Yes ... trigger music animation
							MRAnimEnvSingleSetAction(High_score_view_frog_anim_env_ptr, GEN_FROG_DANCE);
							High_score_view_frog_anim_env_ptr->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;
							}
						break;
					}
				}
			break;
		//--------------------------------------------------------------------
		}

	Options_current_selection = frog->fr_grid_z;
	
	if (High_score_view_flyoff_counter)
		{
		frog->fr_pos.vx 		-= (OPTIONS_CAMERA_FLYOFF_SPEED << 16);
		frog->fr_target_pos.vx 	-= OPTIONS_CAMERA_FLYOFF_SPEED;
		}
	
	// Get frog position/rotation
	frog->fr_lwtrans->t[0] 	= frog->fr_pos.vx >> 16;
	frog->fr_lwtrans->t[1] 	= frog->fr_pos.vy >> 16;
	frog->fr_lwtrans->t[2] 	= frog->fr_pos.vz >> 16;

	// Force anim code to rebuild LW transforms
	High_score_view_frog_anim_env_ptr->ae_extra.ae_extra_env_single->ae_last_cel_number = -1;

	// Update shadow
	if (effect = frog->fr_shadow)
		{
		// Update sh_texture and sh_offsets
		if (High_score_view_flyon_counter)
			effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
		else
			{
			effect->ef_flags &= ~(EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
			shadow = effect->ef_extra;
			if (frog->fr_mode == FROG_MODE_JUMPING)
				{
				i = ((HIGH_SCORE_VIEW_FROG_JUMP_TIME - frog->fr_count) * 6) / HIGH_SCORE_VIEW_FROG_JUMP_TIME;
				i = MAX(0, MIN(5, i));
				}
			else
				{
				i = 0;
				}
			shadow->sh_offsets 	= Frog_jump_shadow_offsets[i];
			shadow->sh_texture	= Frog_jump_shadow_textures[i];
			}
		}
}


/******************************************************************************
*%%%% OptionsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Options screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	OptionsShutdown(MR_VOID)
{
	MR_LONG	i;

//	HSDeinitialiseWater();

	// Free allocated matrices
	MRFreeMem(High_score_matrices);

	// Destroy all number models
	for (i = 0; i < OPTIONS_NUM_OPTIONS; i++)
		High_score_view_number_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all initial models
	for (i = 0; i < (OPTIONS_NUM_OPTIONS - 2) << 1; i++)
		High_score_view_initials_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all log models
	for (i = 0; i < 2; i++)
		High_score_view_log_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy all extra models
	for (i = 0; i < OPTIONS_NUM_EXTRAS; i++)
		Options_extras_object_ptr[i]->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;

	// Destroy frog and shadow
	MRAnimEnvDestroyByDisplay(High_score_view_frog_anim_env_ptr);
	if (Frogs[0].fr_shadow)
		Frogs[0].fr_shadow->ef_kill_timer = 2;
}


/******************************************************************************
*%%%% LanguageSelectionStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LanguageSelectionStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Language Select screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LanguageSelectionStartup(MR_VOID)
{

	// Locals
	MR_ULONG		i;

	// Load options resources
	LoadOptionsResources();

	// Loop once for each flag
	for(i=0;i<MAX_NUM_LANGUAGES;i++)
		{
		// Create sprite off screen
		Language_flag_sprites_ptr[i] = MRCreate2DSprite(Game_display_width+(i*FLAG_X_GAP),(Game_display_height>>1)-(Language_flag_textures_ptr[0][1]->te_h>>1),Option_viewport_ptr,Language_flag_textures_ptr[i][1],NULL);
		// Set OT position of sprite
		Language_flag_sprites_ptr[i]->sp_core.sc_ot_offset = 0;
		}

	// Initialise mode of operation
	Options_language_mode = OPTIONS_LANGUAGE_MODE_SCROLL_ON;

	// Initialise time
	Options_count_down_ticks = 0;

}


/******************************************************************************
*%%%% LanguageSelectionUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LanguageSelectionUpdate(MR_VOID)
*
*	FUNCTION	Update code for Language Select screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LanguageSelectionUpdate(MR_VOID)
{

	// Locals
	MR_ULONG		i;

	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();

	// According to mode do ...
	switch ( Options_language_mode )
		{

		// Scroll on ...
		case OPTIONS_LANGUAGE_MODE_SCROLL_ON:

			// Loop once for each flag
			for(i=0;i<MAX_NUM_LANGUAGES;i++)
				// Move sprites on from right hand side
				Language_flag_sprites_ptr[i]->sp_pos.x-=FLAG_MOVEMENT_SPEED;

			// Have first flag reached selection position ?
			if ( Language_flag_sprites_ptr[0]->sp_pos.x < FIRST_FLAG_X_POSITION )
				// Yes ... go on to selection
				Options_language_mode = OPTIONS_LANGUAGE_MODE_SELECTION;

			break;

		// Selection
		case OPTIONS_LANGUAGE_MODE_SELECTION:

			// Has player pressed left ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_LEFT) )
				{
				// Reset time out
				Options_count_down_ticks = 0;

				// Are we on first flag ?
				if ( Game_language )
					{
					// No ... move down flag list
					Game_language--;
					// Play sound
					MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
					}
				}

			// Has player pressed right ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_RIGHT) )
				{
				// Reset time out
				Options_count_down_ticks = 0;
				// Are we on last flag ?
				if ( Game_language != MAX_NUM_LANGUAGES-1 )
					{
					// No ... move up flag list
					Game_language++;
					// Play sound
					MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
					}
				}

			// Has player pressed fire ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
				{
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				// Reset time out
				Options_count_down_ticks = 0;
				// Go on to scroll off
				Options_language_mode = OPTIONS_LANGUAGE_MODE_SCROLL_OFF;
				}

			break;

		// Scroll off ...
		case OPTIONS_LANGUAGE_MODE_SCROLL_OFF:

			// Loop once for each flag
			for(i=0;i<MAX_NUM_LANGUAGES;i++)
				// Move sprite off left hand side
				Language_flag_sprites_ptr[i]->sp_pos.x-=FLAG_MOVEMENT_SPEED;

			// Has last sprite reached end position ?
			if ( Language_flag_sprites_ptr[MAX_NUM_LANGUAGES-1]->sp_pos.x < LAST_FLAG_X_POSITION )
				{
				// Yes ... did we come from options ?
				if ( From_options == TRUE )
					{
					// Yes ... set main options mode
					Options_update_mode = OPTION_UPDATE_MODE_LANG_DEINIT;
					}
				else
					{
					// No ... go on to main options
					Option_page_request = OPTIONS_PAGE_CHECK;
					}
				}

			break;

		}

	// Loop once for each flag
	for(i=0;i<MAX_NUM_LANGUAGES;i++)
		// Reset sprite "flags" image
		MRChangeSprite(Language_flag_sprites_ptr[i],Language_flag_textures_ptr[i][1]);

	// Are we in selection mode ?
	if ( Options_language_mode == OPTIONS_LANGUAGE_MODE_SELECTION )
		{
		// Yes ... make current one flash ?
//		if ( MRFrame_index )
			{
			// Yes ... show highlight selected flag
			MRChangeSprite(Language_flag_sprites_ptr[Game_language],Language_flag_textures_ptr[Game_language][0]);
			}
		}

	// Inc number of ticks
	Options_count_down_ticks++;

	// End of time ?
	if ( Options_count_down_ticks == (20*(FRAMES_PER_SECOND>>1)) )
		{
		// Yes ... exit with current language
		Options_language_mode = OPTIONS_LANGUAGE_MODE_SCROLL_OFF;
		// Reset time out thing
		Options_count_down_ticks = 0;
		}

}

/******************************************************************************
*%%%% LanguageSelectionShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LanguageSelectionShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Language Select screen.  Kill off sprite "flags".
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	05.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID LanguageSelectionShutdown(MR_VOID)
{

	// Locals
	MR_ULONG		i;

	// Loop once for each language 
	for(i=0;i<MAX_NUM_LANGUAGES;i++)
		// Kill sprite "flag"
		MRKill2DSprite(Language_flag_sprites_ptr[i]);

	// Unload options
	UnloadOptionsResources();

	// Reload FIX vram
	MRLoadResource(Language_res[Game_language]);
	MRProcessResource(Language_res[Game_language]);
	MRUnloadResource(Language_res[Game_language]);

	// Re-load options
	LoadOptionsResources();

}

#ifdef PSX		// PSX Specific code ----------------------------------------

/******************************************************************************
*%%%% RedefinePSXButtonsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RedefinePSXButtonsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Redefine PSX Buttons screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	RedefinePSXButtonsStartup(MR_VOID)
{
	MR_LONG		i, x, y;
	MR_TEXTURE*	texture;

	// Initialise pad configurations
	Pad_configs[0] = Frog_current_control_methods[0];
	Pad_configs[1] = Frog_current_control_methods[1];
	Pad_configs[2] = Frog_current_control_methods[2];
	Pad_configs[3] = Frog_current_control_methods[3];

	// Create sprite for each pad
	for (i = 0; i < MAX_NUM_PADS; i++)
		{
		// Create 2D sprite of pad
		texture = &im_opt_joypad;
		x		= (Game_display_width >> 1) * (i & 1);
		y		= 16 + (texture->te_h * (i >> 1));
		if (i & 2)
			y += (10 * 10);
		else
			y -= (10 * 10);
		Pad_sprite_ptrs[i] = MRCreate2DSprite(x, y, Option_viewport_ptr, texture, NULL);
		Pad_sprite_ptrs[i]->sp_core.sc_ot_offset += 1;

		// Create 2D sprite of pad text
		texture = Pad_text_images[Game_language][Pad_configs[i]];
		x		= (Game_display_width >> 1) * (i & 1);
		y		= 16 + (texture->te_h * (i >> 1));
		if (i & 2)
			y += (10 * 10);
		else
			y -= (10 * 10);
		Pad_text_sprite_ptrs[i] = MRCreate2DSprite(x, y, Option_viewport_ptr, texture, NULL);

		// Create 2D sprite of "insert pad"
		texture = Options_text_textures[OPTION_TEXT_INSERT_PAD][Game_language];
		x		= (Game_display_width >> 1) * (i & 1) + (Game_display_width >> 2);
		if (i & 2)
			{
			y = (Game_display_height >> 1) + (104 >> 1);
			y += (10 * 10);
			}
		else
			{
			y = (Game_display_height >> 1) - (104 >> 1);
			y -= (10 * 10);
			}
		Pad_insert_sprite_ptrs[i] = MRCreate2DSprite(x - (texture->te_w >> 1), y - (texture->te_h >> 1), Option_viewport_ptr, texture, NULL);
		Pad_insert_sprite_ptrs[i]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
		Pad_insert_sprite_ptrs[i]->sp_core.sc_base_colour.r = 0x60;
		Pad_insert_sprite_ptrs[i]->sp_core.sc_base_colour.g = 0x60;
		Pad_insert_sprite_ptrs[i]->sp_core.sc_base_colour.b = 0x60;

		// Create 2D sprite of arrows (facing left)
		texture = &im_opt_arrow_small_left;
		Pad_arrow_sprite_ptrs[i*2+0] = MRCreate2DSprite(x - texture->te_w, y + 32, Option_viewport_ptr, texture, NULL);

		// Create 2D sprite of arrows (facing right)
		texture = &im_opt_arrow_small_right;
		Pad_arrow_sprite_ptrs[i*2+1] = MRCreate2DSprite(x, y + 32, Option_viewport_ptr, texture, NULL);
		}

	High_score_view_flyon_counter 	= OPTIONS_CAMERA_FLYON_TIME + 1;
	High_score_view_delayed_request	= NULL;
}


/******************************************************************************
*%%%% RedefinePSXButtonsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RedefinePSXButtonsUpdate(MR_VOID)
*
*	FUNCTION	Update code for Redefine PSX Buttons screen.  Currently just waits for
*				the fire button before continuing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	RedefinePSXButtonsUpdate(MR_VOID)
{
	MR_LONG	i;


	// Move camera
	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();
	HSUpdateFlying();

	// Scroll 2Dsprites if necessary
	if (High_score_view_flyoff_counter)
		{
		Pad_sprite_ptrs[0]->sp_pos.y 			-= 10;
		Pad_sprite_ptrs[1]->sp_pos.y 			-= 10;
		Pad_sprite_ptrs[2]->sp_pos.y 			+= 10;
		Pad_sprite_ptrs[3]->sp_pos.y 			+= 10;
		Pad_text_sprite_ptrs[0]->sp_pos.y 		-= 10;
		Pad_text_sprite_ptrs[1]->sp_pos.y 		-= 10;
		Pad_text_sprite_ptrs[2]->sp_pos.y 		+= 10;
		Pad_text_sprite_ptrs[3]->sp_pos.y 		+= 10;
		Pad_insert_sprite_ptrs[0]->sp_pos.y		-= 10;
		Pad_insert_sprite_ptrs[1]->sp_pos.y		-= 10;
		Pad_insert_sprite_ptrs[2]->sp_pos.y		+= 10;
		Pad_insert_sprite_ptrs[3]->sp_pos.y		+= 10;
		Pad_arrow_sprite_ptrs[0*2+0]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[1*2+0]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[2*2+0]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[3*2+0]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[0*2+1]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[1*2+1]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[2*2+1]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[3*2+1]->sp_pos.y 	+= 10;
		}
	else
	if (High_score_view_flyon_counter)
		{
		Pad_sprite_ptrs[0]->sp_pos.y 			+= 10;
		Pad_sprite_ptrs[1]->sp_pos.y 			+= 10;
		Pad_sprite_ptrs[2]->sp_pos.y 			-= 10;
		Pad_sprite_ptrs[3]->sp_pos.y 			-= 10;
		Pad_text_sprite_ptrs[0]->sp_pos.y 		+= 10;
		Pad_text_sprite_ptrs[1]->sp_pos.y 		+= 10;
		Pad_text_sprite_ptrs[2]->sp_pos.y 		-= 10;
		Pad_text_sprite_ptrs[3]->sp_pos.y 		-= 10;
		Pad_insert_sprite_ptrs[0]->sp_pos.y		+= 10;
		Pad_insert_sprite_ptrs[1]->sp_pos.y		+= 10;
		Pad_insert_sprite_ptrs[2]->sp_pos.y		-= 10;
		Pad_insert_sprite_ptrs[3]->sp_pos.y		-= 10;
		Pad_arrow_sprite_ptrs[0*2+0]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[1*2+0]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[2*2+0]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[3*2+0]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[0*2+1]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[1*2+1]->sp_pos.y 	+= 10;
		Pad_arrow_sprite_ptrs[2*2+1]->sp_pos.y 	-= 10;
		Pad_arrow_sprite_ptrs[3*2+1]->sp_pos.y 	-= 10;
		}

	// Loop once for each pad
	for(i = 0; i < MAX_NUM_PADS; i++)
		{
		if (Frog_input_ports[i] == -1)
			{
			// Player 3 or 4, and no multitap, so don't display anything
			//
			// Turn off sprites
			Pad_sprite_ptrs[i]->sp_core.sc_flags 		|= MR_SPF_NO_DISPLAY;
			Pad_text_sprite_ptrs[i]->sp_core.sc_flags 	|= MR_SPF_NO_DISPLAY;
			Pad_insert_sprite_ptrs[i]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

			// Turn off arrows
			Pad_arrow_sprite_ptrs[i*2 + 0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			Pad_arrow_sprite_ptrs[i*2 + 1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			}
		else
		// Is this pad in ?
		if (MRInput[Frog_input_ports[i]].in_flags & MRIF_TYPE_NONE)
			{
			// No... turn off sprites
			Pad_sprite_ptrs[i]->sp_core.sc_flags 		|= MR_SPF_NO_DISPLAY;
			Pad_text_sprite_ptrs[i]->sp_core.sc_flags 	|= MR_SPF_NO_DISPLAY;

			// Flag "insert pad" sprite as visible
			Pad_insert_sprite_ptrs[i]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;

			// Turn off arrows
			Pad_arrow_sprite_ptrs[i*2 + 0]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			Pad_arrow_sprite_ptrs[i*2 + 1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
			}
		else
			{
			// Turn on sprites
			Pad_sprite_ptrs[i]->sp_core.sc_flags 		&= ~MR_SPF_NO_DISPLAY;
			Pad_text_sprite_ptrs[i]->sp_core.sc_flags 	&= ~MR_SPF_NO_DISPLAY;

			// Flag "insert pad" sprite as not visible
			Pad_insert_sprite_ptrs[i]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

			// Has pad pushed right ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[i],FRR_RIGHT) )
				{
				// Yes ... last config ?
				if ( Pad_configs[i] < (MAX_NUM_PAD_CONFIGS-1) )
					{
					// No ... up config
					Pad_configs[i]++;
					}
				}
			// Has pad pushed left ?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[i],FRR_LEFT) )
				{
				// Yes ... first config ?
				if ( Pad_configs[i] )
					{
					// No ... down config
					Pad_configs[i]--;
					}
				}
			// Has pad opted to go back to options?
			if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[i],FR_GO|FRR_TRIANGLE) )
				{
				// Yes ... return to options
				High_score_view_delayed_request = OPTIONS_PAGE_OPTIONS;

				// Start moving camera NOW
				OptionsCameraMoveToOptions();
				High_score_view_flyoff_counter 	= OPTIONS_CAMERA_FLYOFF_TIME;
				return;
				}

			// Are we on first config ?
			if ( !Pad_configs[i] )
				{
				// Yes ... cause left arrow to disappear
				Pad_arrow_sprite_ptrs[i*2]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
				}
			else
				{
				// No ... cause left arrow to appear
				Pad_arrow_sprite_ptrs[i*2]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
				}
	
			// Are we on last config ?
			if ( Pad_configs[i] == (MAX_NUM_PAD_CONFIGS-1) )
				{
				// Yes ... cause right arrow to disappear
				Pad_arrow_sprite_ptrs[(i*2)+1]->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
				}
			else
				{
				// No ... cause right arrow to appear
				Pad_arrow_sprite_ptrs[(i*2)+1]->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
				}
			}

		// Update control config sprite image
		MRChangeSprite(Pad_text_sprite_ptrs[i],Pad_text_images[Game_language][Pad_configs[i]]);

		// Glow arrow sprites
		Pad_arrow_sprite_ptrs[i*2 + 0]->sp_core.sc_base_colour.r = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		Pad_arrow_sprite_ptrs[i*2 + 0]->sp_core.sc_base_colour.g = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		Pad_arrow_sprite_ptrs[i*2 + 0]->sp_core.sc_base_colour.b = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		Pad_arrow_sprite_ptrs[i*2 + 1]->sp_core.sc_base_colour.r = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		Pad_arrow_sprite_ptrs[i*2 + 1]->sp_core.sc_base_colour.g = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		Pad_arrow_sprite_ptrs[i*2 + 1]->sp_core.sc_base_colour.b = (Option_viewport_ptr->vp_frame_count & 0xff) << 4;
		}
}


/******************************************************************************
*%%%% RedefinePSXButtonsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RedefinePSXButtonsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Redefine PSX Buttons screen.  Just frees text area at
*				the moment.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	RedefinePSXButtonsShutdown(MR_VOID)
{

	// Locals
	MR_ULONG		i;

	// Loop once for each pad
	for(i=0;i<MAX_NUM_PADS;i++)
		{
		// Kill sprites
		MRKill2DSprite(Pad_sprite_ptrs[i]);
		MRKill2DSprite(Pad_text_sprite_ptrs[i]);
		MRKill2DSprite(Pad_insert_sprite_ptrs[i]);
		MRKill2DSprite(Pad_arrow_sprite_ptrs[i*2]);
		MRKill2DSprite(Pad_arrow_sprite_ptrs[(i*2)+1]);
		}

	// Store pad configurations
	Frog_current_control_methods[0] = Pad_configs[0];
	Frog_current_control_methods[1] = Pad_configs[1];
	Frog_current_control_methods[2] = Pad_configs[2];
	Frog_current_control_methods[3] = Pad_configs[3];

}

#else

/******************************************************************************
*%%%% ChooseWINControllerStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ChooseWINControllerStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Choose WIN Controller screen.  Just initialises text
*				area at the moment.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ChooseWINControllerStartup(MR_VOID)
{

	// Display test text
	Option_choose_win_controller_text_area = MRAllocateTextArea(NULL, &std_font, Option_viewport_ptr, 100, 0, (Game_display_height>>1)-20, Game_display_width, 16);
	MRBuildText(Option_choose_win_controller_text_area, Option_choose_win_controller_text_title,	MR_FONT_COLOUR_YELLOW);

}

/******************************************************************************
*%%%% ChooseWINControllerUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ChooseWINControllerUpdate(MR_VOID)
*
*	FUNCTION	Update code for Choose WIN Controller screen.  Currently just waits for
*				the fire button before continuing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ChooseWINControllerUpdate(MR_VOID)
{

	// Has fire button been pressed ?
	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
		// Yes ... skip back to options
		Option_page_request = OPTIONS_PAGE_OPTIONS;
		}

}

/******************************************************************************
*%%%% ChooseWINControllerShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ChooseWINControllerShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Choose WIN Controller screen.  Just frees text area at
*				the moment.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	ChooseWINControllerShutdown(MR_VOID)
{

	// Free text area
	MRFreeTextArea(Option_choose_win_controller_text_area);

}

#endif	// PSX

/******************************************************************************
*%%%% LevelCompleteStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelCompleteStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Level Complete screen.  Currently just initialises
*				the text and time.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	LevelCompleteStartup(MR_VOID)
{
	MR_LONG			j, y;
	MR_2DSPRITE**	sprite_pptr;
	MR_2DSPRITE*	sprite_ptr;
	MR_ULONG		current_map;
	MR_ULONG		total_time, value, digit_a, digit_b, digit_c;
	SEL_LEVEL_INFO*	arcade_level_ptr;
	SEL_LEVEL_INFO*	arcade_next_level_ptr;
	MR_TEXTURE*		texture;

	// Initialise count down
	Options_count_down_ticks = NUM_GAME_OVER_TICKS;
	Options_count_down_units = 20;//NUM_GAME_OVER_UNITS;

	// Create hud checkpoint graphics
	y	= (Game_display_height>>1) - 70;
	for (j=0; j<GEN_MAX_CHECKPOINTS; j++)
		{
		sprite_ptr										= Level_complete.Level_complete_checkpoints[j];
		Level_complete.Level_complete_checkpoints[j]	= MRCreate2DSprite((Game_display_width>>1)-85, y, Option_viewport_ptr, Hud_checkpoint_animlists[j], NULL);
		y += 20;
		}

	// Create hud checkpoint time graphics
	total_time	= 0;
	y			= (Game_display_height>>1) - 70;
	for (j=0; j<GEN_MAX_CHECKPOINTS; j++)
		{
		Level_complete.Level_complete_checkpoint_time[j] = MRAllocMem(sizeof(MR_2DSPRITE*) * 2, "CHECKPOINT 2DSPRITE PTRS");
		sprite_pptr		= (MR_2DSPRITE**)Level_complete.Level_complete_checkpoint_time[j];

		HUDGetDigits(Frog_score_data[Game_map][0].he_time_to_checkpoint[j], &digit_a, &digit_b, &digit_c);
		total_time += Frog_score_data[Game_map][0].he_time_to_checkpoint[j];

		*sprite_pptr++	= MRCreate2DSprite(	(Game_display_width>>1) -64, y, Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL);
		*sprite_pptr++	= MRCreate2DSprite(	(Game_display_width>>1) -48, y, Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL);
		y += 20;
		}

	HUDGetDigits(total_time, &digit_a, &digit_b, &digit_c);
	Level_complete.Level_complete_total_time_text	= MRCreate2DSprite((Game_display_width>>1)-26, (Game_display_height>>1)-60, Option_viewport_ptr, Options_text_textures[OPTION_TEXT_TOTAL_TIME][Game_language], NULL);
	Level_complete.Level_complete_total_time[0]		= MRCreate2DSprite((Game_display_width>>1), (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[7]], NULL);
	Level_complete.Level_complete_total_time[1]		= MRCreate2DSprite((Game_display_width>>1)+16, (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL);
	Level_complete.Level_complete_total_time[2]		= MRCreate2DSprite((Game_display_width>>1)+32, (Game_display_height>>1)-40, Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL);

	value = Frog_score_data[Game_map][0].he_score;
	HUDGetDigits(value, &digit_a, &digit_b, &digit_c);
	Level_complete.Level_complete_total_score_text	= MRCreate2DSprite((Game_display_width>>1)-30,	(Game_display_height>>1)-15,Option_viewport_ptr, Options_text_textures[OPTION_TEXT_TOTAL_SCORE][Game_language], NULL);
	Level_complete.Level_complete_total_score[0]	= MRCreate2DSprite((Game_display_width>>1)-16,	(Game_display_height>>1)+5,	Option_viewport_ptr, Hud_score_images[Hud_digits[5]], NULL);
	Level_complete.Level_complete_total_score[1]	= MRCreate2DSprite((Game_display_width>>1),		(Game_display_height>>1)+5,	Option_viewport_ptr, Hud_score_images[Hud_digits[6]], NULL);
	Level_complete.Level_complete_total_score[2]	= MRCreate2DSprite((Game_display_width>>1)+16,	(Game_display_height>>1)+5,	Option_viewport_ptr, Hud_score_images[Hud_digits[7]], NULL);
	Level_complete.Level_complete_total_score[3]	= MRCreate2DSprite((Game_display_width>>1)+32,	(Game_display_height>>1)+5,	Option_viewport_ptr, Hud_score_images[Hud_digits[8]], NULL);
	Level_complete.Level_complete_total_score[4]	= MRCreate2DSprite((Game_display_width>>1)+48,	(Game_display_height>>1)+5,	Option_viewport_ptr, Hud_score_images[Hud_digits[9]], NULL);

	// Yes ... are we in arcade mode ?
	if (Sel_mode == SEL_MODE_ARCADE)
		{
		// Yes ... try to go on to next level in current world, else return to level select
		current_map		= Game_map;

		// Flag current level as complete in level select stack
		SelectSetLevelFlags(Game_map,SEL_LF_COMPLETED|SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);

		// Walk through the list of levels, to see if we have another map in the current theme
		// which we can play.
		arcade_level_ptr	= Sel_arcade_levels;
		
		while (arcade_level_ptr->li_library_id != -1)
			{
			if (arcade_level_ptr->li_library_id == Game_map)
				break;
			arcade_level_ptr++;
			}

		if (arcade_level_ptr->li_library_id != -1)
			{
			arcade_next_level_ptr = arcade_level_ptr+1;

			// Is the next entry in the table the same theme id? Not sure, but we should trap the
			//jungle river here just in case (i.e. -1 in li_library_id)

			if (arcade_next_level_ptr->li_library_id == -1)
				{
				// end of game here, so zone finished
				Level_complete.Level_complete_next_level = FALSE;

				// Hack the level stack data to point jungle 1 to jungle 2.... WIll told me to do it,
				// honest guv, on my life...
				if (arcade_level_ptr->li_library_id == LEVEL_JUNGLE1)
					arcade_level_ptr->li_library_id = LEVEL_JUNGLE2;
				}
			else
				{
				if (arcade_level_ptr->li_world_id == arcade_next_level_ptr->li_world_id)
					{
					Game_map = arcade_next_level_ptr->li_library_id;
					Level_complete.Level_complete_next_level = TRUE;
					}
				else
					{
					Level_complete.Level_complete_next_level = FALSE;
					}
				}
	
			if (Level_complete.Level_complete_next_level)
				{
				// Did we find a golden frog on this level ?
				if ( Gold_frogs_current & (1<<Game_map_theme) )
					{
					// Yes ... show golden frog
					Level_complete.Level_complete_golden_frog		= MRCreate2DSprite(	(Game_display_width>>1) + 80, 
																						(Game_display_height>>1) + 40, 
																						Option_viewport_ptr, 
																						&Animlist_level_complete_golden_frog, 
																						NULL);
					// Flush current
					Gold_frogs_current &= ~(1<<Game_map_theme);
					// Set zone
					Gold_frogs_zone |= (1<<Game_map_theme);
					}

				texture = Options_text_textures[OPTION_TEXT_NEXT][Game_language];
				Level_complete.Level_complete_next_level_des	= MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), 
																					Game_display_height-90, 
																					Option_viewport_ptr, 
																					texture,
																					NULL);
				Level_complete.Level_complete_next_level_text	= MRCreate2DSprite((Game_display_width>>1) - (arcade_next_level_ptr->li_level_name_texture_in_game->te_w>>1), 
																					Game_display_height-70, 
																					Option_viewport_ptr, 
																					arcade_next_level_ptr->li_level_name_texture_in_game, 
																					NULL);
				texture = Options_text_textures[OPTION_TEXT_SELECT4][Game_language];
				Level_complete.Level_complete_press_tri			= MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), 
																					Game_display_height-30, 
																					Option_viewport_ptr, 
																					texture,
																					NULL);
				texture = Options_text_textures[OPTION_TEXT_PRESS_FIRE][Game_language];
				Level_complete.Level_complete_press_fire		= MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), 
																					Game_display_height-50, 
																					Option_viewport_ptr, 
																					texture,
																					NULL);
				// Play SFX for Level Complete.
				MRSNDPlaySound(SFX_MUSIC_TARGET_COMPLETE,NULL,0,0);
				}
			else
				{
				// Did we just find a golden frog on this last level ?
				if ( Gold_frogs_current & (1<<Game_map_theme) )
					{
					// Yes ... flush current
					Gold_frogs_current &= ~(1<<Game_map_theme);
					// Set zone
					Gold_frogs_zone |= (1<<Game_map_theme);
					}

				// Did we find a golden frog on this zone ?
				if ( Gold_frogs_zone & (1<<Game_map_theme) )
					{
					// Yes ... show golden frog
					Level_complete.Level_complete_golden_frog		= MRCreate2DSprite((Game_display_width>>1) + 80, 
																						(Game_display_height>>1) + 40, 
																						Option_viewport_ptr, 
																						&Animlist_level_complete_golden_frog, 
																						NULL);
					// Flush zone
					Gold_frogs_zone &= ~(1<<Game_map_theme);
					}
#ifdef PSX
				// Zone Complete, so play Zone complete Music.
				PlayZoneComplete();
#endif

				Level_complete.Level_complete_next_level_text	= NULL;

				texture = Options_text_textures[OPTION_TEXT_ZONE_COMPLETE][Game_language];
				Level_complete.Level_complete_next_level_des	= MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), 
																					Game_display_height-50, 
																					Option_viewport_ptr, 
																					texture,
																					NULL);
				texture = Options_text_textures[OPTION_TEXT_PRESS_FIRE][Game_language];
				Level_complete.Level_complete_press_fire		= MRCreate2DSprite((Game_display_width>>1) - (texture->te_w>>1), 
																					Game_display_height-32, 
																					Option_viewport_ptr, 
																					texture,
																					NULL);

				}
			}
		}

	// init background
	InitTransparentPolyBackground(0, 0, Game_display_width, Game_display_height);
}


/******************************************************************************
*%%%% LevelCompleteUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelCompleteUpdate(MR_VOID)
*
*	FUNCTION	Update code for Level Complete screen.  Waits for button press or time
*				limit before going back to game.  Also continues to render
*				the last game screen in the background.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	LevelCompleteUpdate(MR_VOID)
{
	// Update game in background
	OptUpdateGame();

	// Show subtractive polys
	UpdateTransparentPolyBackground();

	// $wb - No time out on this screen, order of Kev!!!
	// Dec ticks
//	Options_count_down_ticks--;

	// Ticks zero ?
	if ( !Options_count_down_ticks )
		{
		// Yes ... do we have any units left ?
		if ( Options_count_down_units )
			{
			// Yes ... dec units
			Options_count_down_units--;
			// Reset ticks count
			Options_count_down_ticks = NUM_GAME_OVER_TICKS;
			}
		}

	// Did we press fire to skip ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO) )
		{
		// Yes ... stop count down
		Options_count_down_units = 0;
		Options_count_down_ticks = 0;
		// Play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
		}

	// Was triangle pressed ?
	if ( MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_TRIANGLE) )
		{
		// Yes ... go back to level select stack
		Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
		// Level after current one ?
		if (Level_complete.Level_complete_next_level)
				{
				// Yes ... make it accessable
				SelectSetLevelFlags(Game_map,SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
				Sel_arcade_level_ptr	= SelectGetLevelPointer(Game_map);
				}
		}
	// Do we still have time left ?
	else
	if ( !(Options_count_down_units || Options_count_down_ticks) )
		{
		// No ... are we in arcade mode ?
		if ( Sel_mode == SEL_MODE_ARCADE )
			{
			if (!Level_complete.Level_complete_next_level)
				{
				// Yes ... return to level select stack
				Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
				}
			else
				{
				// Yes ... go back to game in next level
				Option_page_request = OPTIONS_PAGE_GAME;

				// $wb - Active this level in the level select stack so that we can come back later
				SelectSetLevelFlags(Game_map,SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
				Sel_arcade_level_ptr	= SelectGetLevelPointer(Game_map);
				}
			}
		else
			{
			// No ... return to level select
			Option_page_request = OPTIONS_PAGE_LEVEL_SELECT;
			}
		}

	// Is there a next level ?
	if ( Level_complete.Level_complete_next_level_text )
		{
		// Yes ... 
		if ( MRFrame_number & 16 )
			Level_complete.Level_complete_press_fire->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
		else
			Level_complete.Level_complete_press_fire->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
		}

}

/******************************************************************************
*%%%% LevelCompleteShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LevelCompleteShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Level Complete screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.06.97	William Bell	Created
*	09.07.97	Martin Kift		Completely rewrote
*
*%%%**************************************************************************/

MR_VOID	LevelCompleteShutdown(MR_VOID)
{
	MR_2DSPRITE**	sprite_pptr;
	MR_LONG			j;

	for (j=0; j<GEN_MAX_CHECKPOINTS; j++)
		MRKill2DSprite(Level_complete.Level_complete_checkpoints[j]);

	for (j=0; j<GEN_MAX_CHECKPOINTS; j++)
		{
		sprite_pptr	= (MR_2DSPRITE**)Level_complete.Level_complete_checkpoint_time[j];
		MRKill2DSprite(*sprite_pptr++);
		MRKill2DSprite(*sprite_pptr++);
		MRFreeMem(Level_complete.Level_complete_checkpoint_time[j]);
		}

	MRKill2DSprite(Level_complete.Level_complete_total_time_text);
	MRKill2DSprite(Level_complete.Level_complete_total_score_text);
	for (j=0; j<3; j++)
		MRKill2DSprite(Level_complete.Level_complete_total_time[j]);
	for (j=0; j<5; j++)
		MRKill2DSprite(Level_complete.Level_complete_total_score[j]);
	
	if ( Level_complete.Level_complete_golden_frog )
		MRKill2DSprite(Level_complete.Level_complete_golden_frog);

	if (Level_complete.Level_complete_press_fire)
		MRKill2DSprite(Level_complete.Level_complete_press_fire);

	if (Level_complete.Level_complete_press_tri)
		MRKill2DSprite(Level_complete.Level_complete_press_tri);

	if (Level_complete.Level_complete_next_level_text)
		MRKill2DSprite(Level_complete.Level_complete_next_level_text);

	if (Level_complete.Level_complete_next_level_des)
		MRKill2DSprite(Level_complete.Level_complete_next_level_des);

	// Shut down main game
	GameEnd();
}

/******************************************************************************
*%%%% OptUpdateGame
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptUpdateGame(MR_VOID)
*
*	FUNCTION	Update the game
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID OptUpdateGame(MR_VOID)
{
	MR_ULONG	i;

	// Continue to render game in background
	//--------------------------------------
	// This block is identical to the 'is game not paused' section of GameUpdateLogic
	UnlinkEntities();
	UpdatePathRunners();
	UpdateLiveEntities();
	LinkEntities();
	UpdateFrogs();
	UpdateCameras();

	MRUpdateFrames();
	MRUpdateObjects();

	UpdateFrogAnimationScripts();
	MRAnimUpdateEnvironments();
	MRUpdateMeshesAnimatedPolys();
	MRUpdateViewportRenderMatrices();
	MapUpdateAnimatedPolys();
	MRUpdateViewport2DSpriteAnims(Game_viewporth);

	UpdateScoreSprites();
	UpdateEffects();

	if (Map_wibble_water.ww_vertices_ptr)
		WaterWibbleVertices(Map_wibble_water.ww_vertices_ptr, Map_wibble_water.ww_num_vertices);
	//--------------------------------------

	UpdateHUD();

#ifdef GAME_CLEAR_USING_TILES
	addPrim(Game_viewportc->vp_work_ot, &Game_clear_tiles[MRFrame_index]);
	MRRenderViewport(Game_viewportc);
#endif

	for (i = 0; i < Game_total_viewports; i++)
		CreateMapViewList(i);
	for (i = 0; i < Game_total_viewports; i++)
		CreateMapGroups(i);
	UpdateSkyLand();
	for(i=0;i<Game_total_viewports;i++)
		{
		MRRenderViewport(Game_viewports[i]);
		MRUpdateViewportMeshInstancesAnimatedPolys(Game_viewports[i]);
		}
	for (i = 0; i < Game_total_viewports; i++)
		{
		MRSetActiveViewport(Game_viewports[i]);
		RenderMap(i);
		}
	MRRenderViewport(Game_viewporth);
}

/******************************************************************************
*%%%% OptionsTidyMemory
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsTidyMemory(MR_BOOL	FreePrim)
*
*	FUNCTION	Used to give the API a chance to free any alloc's that may still
*				be around..... MR_PRIMS etc... (To try and stop fragmentation.)
*
*	INPUT		FreePrim	-	Do we called FreePrims??
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Gary Richards	Created. 
*	28.07.97	Gary Richards	Added parameter.
*
*%%%**************************************************************************/

MR_VOID OptionsTidyMemory(MR_BOOL FreePrim)
{
	MR_LONG		i = 4;


#ifdef WIN95
	while (i--)
		{
		if (MRDraw_valid == 0)
			MRClearAllViewportOTs();
		MRSwapDisplay();
		MRClearAllViewportOTs();
		}
#else	// PSX
	while (i--)
		{
		DrawSync(0);
		VSync(2);
		MRSwapDisplay();

		// Making sure we have the viewports to render.
		if ( Option_viewport_ptr )
			MRRenderViewport(Option_viewport_ptr);

		// This was added to remove any dead effects.
		ClearEffects();

		if (FreePrim == TRUE)
			FreePrims();			// To remove the options water prims.
		}
#endif
}

/******************************************************************************
*%%%% LoadOptionsResources
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	LoadOptionsResources(MR_VOID)
*
*	FUNCTION	Loads all options/language resources if necessary
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	LoadOptionsResources(MR_VOID)
{
	MR_LONG	cos;
	MR_LONG	sin;
#ifdef PSX
	MR_ULONG	saved_sp;


	saved_sp = SetSp(saved_stack);
#endif

	// Load options VRAM, VAB and WAD if not already loaded
	if (MR_GET_RESOURCE_ADDR(RES_OPTIONS_WAD) == NULL)
		{	
		// Load options VRAM
		MRLoadResource(RES_OPT_VRAM_VLO);
		MRProcessResource(RES_OPT_VRAM_VLO);
		MRUnloadResource(RES_OPT_VRAM_VLO);

		// Load language VRAM
		MRLoadResource(Opt_resource_files[Game_language]);
		MRProcessResource(Opt_resource_files[Game_language]);
		MRUnloadResource(Opt_resource_files[Game_language]);

		// Load VAB
#ifdef MR_API_SOUND
		MRLoadResource(gVABInfo[VAB_SELECT].va_vh_resource_id);
		MRProcessResource(gVABInfo[VAB_SELECT].va_vh_resource_id);
		MRLoadResource(gVABInfo[VAB_SELECT].va_vb_resource_id);
		MRProcessResource(gVABInfo[VAB_SELECT].va_vb_resource_id);
		MRSNDOpenVab(VAB_SELECT, TRUE); 
		MRUnloadResource(gVABInfo[VAB_SELECT].va_vb_resource_id);
#endif

		// Load WAD
		Map_mof_index = 0;
		MRLoadResource(RES_OPTIONS_WAD);
		MRProcessResource(RES_OPTIONS_WAD);

		// Rotate number turtle model
		cos = rcos(0xc00);
		sin = rsin(0xc00);
		MRRot_matrix_Y.m[0][0] =  cos;
		MRRot_matrix_Y.m[0][2] =  sin;
		MRRot_matrix_Y.m[2][0] = -sin;
		MRRot_matrix_Y.m[2][2] =  cos;
		MRRotateMOF(MR_GET_RESOURCE_ADDR(RES_OPT_TURTLE_XMR), &MRRot_matrix_Y);

		// Intialise water
		HSInitialiseWater(&im_opt_env_sky, &im_opt_bank3);

		// Set up current position of water camera
		InitialiseOptionsCamera();
		}

#ifdef PSX
	SetSp(saved_sp);
#endif
}
	

/******************************************************************************
*%%%% UnloadOptionsResources
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UnloadOptionsResources(MR_VOID)
*
*	FUNCTION	Unloads all options/language resources if necessary
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	24.07.97	Tim Closs		Created
*	05.08.97	Martin Kift		Had to reorder cleanup functions
*
*%%%**************************************************************************/

MR_VOID	UnloadOptionsResources(MR_VOID)
{
	// If options stuff loaded, unload it
	if (MR_GET_RESOURCE_ADDR(RES_OPTIONS_WAD) != NULL)
		{	
#ifdef MR_API_SOUND
		// 'Unload' VAB (close VAB)
		MRSNDCloseVab(VAB_SELECT);

		// Unload VAB
		MRUnloadResource(gVABInfo[VAB_SELECT].va_vh_resource_id);
#endif

		// Unload WAD
		MRUnloadResource(RES_OPTIONS_WAD);

		// Deintialise water
		HSDeinitialiseWater();
		}
}


/******************************************************************************
*%%%% InitialiseOptionsCamera
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseOptionsCamera(MR_VOID)
*
*	FUNCTION	Sets up Cameras[0] to pan over water views
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseOptionsCamera(MR_VOID)
{
	CAMERA*	camera;


	Option_viewport_ptr->vp_camera 		= Option_camera_ptr;
	Option_viewport_ptr->vp_perspective = HIGH_SCORE_VIEW_PERSPECTIVE;
	gte_SetGeomScreen(HIGH_SCORE_VIEW_PERSPECTIVE);
	camera 								= &Cameras[0];
	InitialiseCamera(camera, Option_viewport_ptr);
	camera->ca_offset_origin			= &Null_vector;

	OptionsCameraSnapToMain();

//	MR_SET_SVEC(&camera->ca_current_source_ofs,
//				OPTIONS_CAMERA_MAIN_SOURCE_OFS_X,
//				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Y,
//				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Z);
//
//	MR_SET_SVEC(&camera->ca_current_target_ofs,
//				OPTIONS_CAMERA_MAIN_TARGET_OFS_X,
//				OPTIONS_CAMERA_MAIN_TARGET_OFS_Y,
//				OPTIONS_CAMERA_MAIN_TARGET_OFS_Z);
}


/******************************************************************************
*%%%% OptionsCameraMoveToMain
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsCameraMoveToMain(MR_VOID)
*
*	FUNCTION	Set options camera up to move to main menu position
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsCameraMoveToMain(MR_VOID)
{
	CAMERA*	camera;


	camera = &Cameras[0];

	// Offsets for static view (all hiscores)
	MR_SET_SVEC(&camera->ca_next_source_ofs,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_X,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Y,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Z);

	MR_SET_SVEC(&camera->ca_next_target_ofs,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_X,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_Y,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_Z);

	// Move time
	camera->ca_move_timer = OPTIONS_CAMERA_MOVE_TIME;
}


/******************************************************************************
*%%%% OptionsCameraSnapToMain
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsCameraSnapToMain(MR_VOID)
*
*	FUNCTION	Set options camera up to move to main menu position
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsCameraSnapToMain(MR_VOID)
{
	CAMERA*	camera;


	camera = &Cameras[0];

	// Offsets for static view (all hiscores)
	MR_SET_SVEC(&camera->ca_current_source_ofs,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_X,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Y,
				OPTIONS_CAMERA_MAIN_SOURCE_OFS_Z);

	MR_SET_SVEC(&camera->ca_current_target_ofs,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_X,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_Y,
				OPTIONS_CAMERA_MAIN_TARGET_OFS_Z);

	// Move time
	camera->ca_move_timer 			= 0;
	High_score_view_flyoff_counter 	= 0;
	High_score_view_flyon_counter 	= 0;
}


/******************************************************************************
*%%%% OptionsCameraMoveToOptions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsCameraMoveToOptions(MR_VOID)
*
*	FUNCTION	Set options camera up to move to main menu position
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsCameraMoveToOptions(MR_VOID)
{
	CAMERA*	camera;


	camera = &Cameras[0];

	// Offsets for static view (all hiscores)
	MR_SET_SVEC(&camera->ca_next_source_ofs,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_X,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Y,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Z);

	MR_SET_SVEC(&camera->ca_next_target_ofs,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_X,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Y,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Z);

	// Move time
	camera->ca_move_timer = OPTIONS_CAMERA_MOVE_TIME;
}


/******************************************************************************
*%%%% OptionsCameraSnapToOptions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	OptionsCameraSnapToOptions(MR_VOID)
*
*	FUNCTION	Set options camera up to move to options menu position
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	OptionsCameraSnapToOptions(MR_VOID)
{
	CAMERA*	camera;


	camera = &Cameras[0];

	// Offsets for static view (all hiscores)
	MR_SET_SVEC(&camera->ca_current_source_ofs,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_X,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Y,
				OPTIONS_CAMERA_OPTIONS_SOURCE_OFS_Z);

	MR_SET_SVEC(&camera->ca_current_target_ofs,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_X,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Y,
				OPTIONS_CAMERA_OPTIONS_TARGET_OFS_Z);

	// Move time
	camera->ca_move_timer	 		= 0;
	High_score_view_flyoff_counter 	= 0;
	High_score_view_flyon_counter 	= 0;
}


/******************************************************************************
*%%%% ShowWaterStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ShowWaterStartup(MR_VOID)
*
*	FUNCTION	Cheat for QA: display water fo video
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ShowWaterStartup(MR_VOID)
{
	// Set up water
	HSInitialiseWater(&im_opt_env_sky, &im_opt_bank3);

	// Set up camera
	OptionsCameraMoveToMain();
}


/******************************************************************************
*%%%% ShowWaterUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ShowWaterUpdate(MR_VOID)
*
*	FUNCTION	Cheat for QA: display water fo video
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ShowWaterUpdate(MR_VOID)
{
	// Move camera
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_UP))
		Cameras[0].ca_current_target_ofs.vz += 0x10;
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_DOWN))
		Cameras[0].ca_current_target_ofs.vz -= 0x10;
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_LEFT))
		Cameras[0].ca_current_target_ofs.vx -= 0x10;
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_RIGHT))
		Cameras[0].ca_current_target_ofs.vx += 0x10;
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_GREEN))
		Cameras[0].ca_current_source_ofs.vy -= 0x10;
	if (MR_CHECK_PAD_HELD(Frog_input_ports[0], FRR_BLUE))
		Cameras[0].ca_current_source_ofs.vy += 0x10;

	HSUpdateScrollyCamera();

	// River bed and water
	HSUpdateWater();

	if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_SELECT))
		{
#ifdef PSX
#ifdef	PSX_MODE_PAL
		// Go on to AntiPiracy
		Option_page_request = OPTIONS_PAGE_ANTI_PIRACY;
#else
		// Go on to Hasbro Logo
		Option_page_request = OPTIONS_PAGE_HASBRO_LOGO;
#endif
#else
		// Go on to Hasbro Logo
		Option_page_request = OPTIONS_PAGE_HASBRO_LOGO;
#endif
		}
}


/******************************************************************************
*%%%% ShowWaterShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ShowWaterShutdown(MR_VOID)
*
*	FUNCTION	Cheat for QA: display water fo video
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	11.08.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	ShowWaterShutdown(MR_VOID)
{
	// Deinitialise water
	HSDeinitialiseWater();
}

/******************************************************************************
*%%%% PlayAgainStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayAgainStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for Play Again screen.  Currently just initialises
*				the text and time.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	PlayAgainStartup(MR_VOID)
{

	// Locals
	MR_TEXTURE*	texture;
	MR_ULONG	width;
	MR_ULONG	loop_counter;
	POLY_FT4*	poly_ft4;

	// Create sprites
	texture					= Options_text_textures[OPTION_TEXT_PLAY_AGAIN][Game_language];
	Playagain_pa_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)-24,Option_viewport_ptr,texture,NULL);

	texture					= Options_text_textures[OPTION_TEXT_CHOOSE_COURSE][Game_language];
	Playagain_cc_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)-8,Option_viewport_ptr,texture,NULL);

	texture					= Options_text_textures[OPTION_TEXT_EXIT][Game_language];
	Playagain_ex_sprite_ptr = MRCreate2DSprite((Game_display_width>>1)-(texture->te_w>>1),(Game_display_height>>1)+8,Option_viewport_ptr,texture,NULL);

	Option_spcore_ptrs[0] 	= (MR_SP_CORE*)Playagain_pa_sprite_ptr;
	Option_spcore_ptrs[1] 	= (MR_SP_CORE*)Playagain_cc_sprite_ptr;
	Option_spcore_ptrs[2] 	= (MR_SP_CORE*)Playagain_ex_sprite_ptr;

	// Initialise count down
	Options_count_down_ticks 	= (FRAMES_PER_SECOND>>1);
	Options_count_down_units 	= 20;

	// Initialise current selection
	Option_number = 0;

	// Calculate width
	width = MAX(Options_text_textures[OPTION_TEXT_PLAY_AGAIN][Game_language]->te_w,
			MAX(Options_text_textures[OPTION_TEXT_CHOOSE_COURSE][Game_language]->te_w,
				Options_text_textures[OPTION_TEXT_EXIT][Game_language]->te_w));

	// Set up darken polys
	poly_ft4	= Cloud_polys;
	texture		= &im_opt_menu_cloud;
	// Loop once for each poly
	for(loop_counter=0;loop_counter<2;loop_counter++)
		{
		// Set poly code
		MR_SET32(poly_ft4->r0, 0x404040);
		setPolyFT4(poly_ft4);
		setSemiTrans(poly_ft4, 1);

		// Set poly position
		poly_ft4->x0 = (Game_display_width>>1)-(width>>1);
		poly_ft4->y0 = (Game_display_height>>1)-(24+8);
		poly_ft4->x1 = (Game_display_width>>1)+(width>>1);
		poly_ft4->y1 = (Game_display_height>>1)-(24+8);
		poly_ft4->x2 = (Game_display_width>>1)-(width>>1);
		poly_ft4->y2 = (Game_display_height>>1)+(8+16+8);
		poly_ft4->x3 = (Game_display_width>>1)+(width>>1);
		poly_ft4->y3 = (Game_display_height>>1)+(8+16+8);

#ifdef PSX
		MR_COPY32(poly_ft4->u0, texture->te_u0);
		MR_COPY32(poly_ft4->u1, texture->te_u1);
#else
		MR_COPY16(poly_ft4->u0, texture->te_u0);
		MR_COPY16(poly_ft4->u1, texture->te_u1);
		poly_ft4->tpage = texture->te_tpage_id;
#endif
		MR_COPY16(poly_ft4->u2, texture->te_u2);
		MR_COPY16(poly_ft4->u3, texture->te_u3);
		poly_ft4++;
		}

}

/******************************************************************************
*%%%% PlayAgainUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayAgainUpdate(MR_VOID)
*
*	FUNCTION	Update code for Play Again screen.  Waits for button press or time
*				limit before going on to high score input.  Also continues to render
*				the last game screen in the background.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	PlayAgainUpdate(MR_VOID)
{
	// update game
	OptUpdateGame();

	// Dec ticks
	Options_count_down_ticks--;

	// Ticks zero ?
	if ( !Options_count_down_ticks )
		{
		// Yes ... do we have any units left ?
		if ( Options_count_down_units )
			{
			// Yes ... dec units
			Options_count_down_units--;
			// Reset ticks count
			Options_count_down_ticks = (FRAMES_PER_SECOND>>1);
			}
		}

	// Do we still have time left ?
	if ( Options_count_down_units || Options_count_down_ticks )
		{
		// Yes ... was up pressed ?
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_UP))
			{
			// Yes ... reset count down
			Options_count_down_ticks 	= (FRAMES_PER_SECOND>>1);
			Options_count_down_units 	= 20;
			// Are we at top ?
			if ( Option_number )
				{
				// No ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				// Move up options
				Option_number--;
				}
			}

		// Was down pressed ?
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FRR_DOWN))
			{
			// Yes ... reset count down
			Options_count_down_ticks 	= (FRAMES_PER_SECOND>>1);
			Options_count_down_units 	= 20;
			// Are we at bottom ?
			if ( Option_number != 2 )
				{
				// No ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);
				// Move down options
				Option_number++;
				}
			}

		// Has fire button been pressed ?
		if (MR_CHECK_PAD_PRESSED(Frog_input_ports[0], FR_GO))
			{
			// Yes ... play sound
			MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

			// Go on to continue
			Option_page_request = OPTIONS_PAGE_CONTINUE;
			}
		}
	else
		{
		// No ... exit to continue
		Option_page_request = OPTIONS_PAGE_CONTINUE;
		}


	Option_spcore_index = Option_number;
//	// According to selection display highlighted selection
//	switch ( Option_number )
//		{
//		case 0:
//			MRChangeSprite(Playagain_pa_sprite_ptr,Options_text_textures[OPTION_TEXT_PLAY_AGAIN2][Game_language]);
//			MRChangeSprite(Playagain_cc_sprite_ptr,Options_text_textures[OPTION_TEXT_CHOOSE_COURSE][Game_language]);
//			MRChangeSprite(Playagain_ex_sprite_ptr,Options_text_textures[OPTION_TEXT_EXIT][Game_language]);
//			break;
//		case 1:
//			MRChangeSprite(Playagain_pa_sprite_ptr,Options_text_textures[OPTION_TEXT_PLAY_AGAIN][Game_language]);
//			MRChangeSprite(Playagain_cc_sprite_ptr,Options_text_textures[OPTION_TEXT_CHOOSE_COURSE2][Game_language]);
//			MRChangeSprite(Playagain_ex_sprite_ptr,Options_text_textures[OPTION_TEXT_EXIT][Game_language]);
//			break;
//		case 2:
//			MRChangeSprite(Playagain_pa_sprite_ptr,Options_text_textures[OPTION_TEXT_PLAY_AGAIN][Game_language]);
//			MRChangeSprite(Playagain_cc_sprite_ptr,Options_text_textures[OPTION_TEXT_CHOOSE_COURSE][Game_language]);
//			MRChangeSprite(Playagain_ex_sprite_ptr,Options_text_textures[OPTION_TEXT_EXIT2][Game_language]);
//			break;
//		}

	// Add darkening prims to display behind menu
	addPrim(Option_viewport_ptr->vp_work_ot + 10, &Cloud_polys[MRFrame_index]);

}

/******************************************************************************
*%%%% PlayAgainShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayAgainShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for Play Again screen
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	PlayAgainShutdown(MR_VOID)
{

	// Kill 2D sprites
	MRKill2DSprite(Playagain_pa_sprite_ptr);
	MRKill2DSprite(Playagain_cc_sprite_ptr);
	MRKill2DSprite(Playagain_ex_sprite_ptr);

}

/******************************************************************************
*%%%% PlayOptionsMusic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	PlayOptionsMusic(MR_VOID)
*
*	FUNCTION	Checks to see if the option music is playing, if not starts it.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID	PlayOptionsMusic(MR_VOID)
{
#ifdef	PSX
	// Check to see if already playing.
	if (Options_music_playing == FALSE)
		{
		// Start me some options music.
		XAStartup();
		PlayLevelMusic(LT_JUNGLE2);		
		Options_music_playing = TRUE;
		}
#endif
}

/******************************************************************************
*%%%% ShutdownOptionsMusic
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ShutdownOptionsMusic(MR_VOID)
*
*	FUNCTION	Shutdowns the Options music is playing, if not starts it.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	27.08.97	Gary Richards	Created
*
*%%%**************************************************************************/
MR_VOID	ShutdownOptionsMusic(MR_VOID)
{
#ifdef	PSX
	// Check to make sure it's playing
	if (Options_music_playing == TRUE)
		{
		XAShutdown();
		Options_music_playing = FALSE;
		}
#ifdef	DEBUG
	else
		printf("Trying to shutdown options music, when it's not playing.\n");
#endif
#endif
}


/******************************************************************************
*%%%% SwitchOffOptionsMenu
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SwitchOffOptionsMenu(MR_VOID)
*
*	FUNCTION	Used to switch off the START/RACE/OPTIONS sprites when going 
*				into Demo Mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.08.97	Gary Richards	Created 
*
*%%%**************************************************************************/
MR_VOID	SwitchOffOptionsMenu(MR_VOID)
{
	// Switch off the START/RACE/OPTIONS Sprites after coming from the Demo Mode.
	Start_ptr->sp_core.sc_flags   |= MR_SPF_NO_DISPLAY;
	Race_ptr->sp_core.sc_flags 	  |= MR_SPF_NO_DISPLAY;
	Options_ptr->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
}

/******************************************************************************
*%%%% SwitchOnOptionsMenu
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SwitchOnOptionsMenu(MR_VOID)
*
*	FUNCTION	Used to switch on the START/RACE/OPTIONS sprites when going 
*				into Demo Mode.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.08.97	Gary Richards	Created 
*
*%%%**************************************************************************/
MR_VOID	SwitchOnOptionsMenu(MR_VOID)
{
	// Switch on the START/RACE/OPTIONS Sprites after coming from the Demo Mode.
	Start_ptr->sp_core.sc_flags  &= ~MR_SPF_NO_DISPLAY;
	Race_ptr->sp_core.sc_flags 	 &= ~MR_SPF_NO_DISPLAY;
	Options_ptr->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
}



#ifdef WIN95
#pragma warning (default : 4761)
#endif
