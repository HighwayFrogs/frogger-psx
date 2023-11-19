/******************************************************************************
*%%%% select.c
*------------------------------------------------------------------------------
*
*	Level Select Re-write (Version 3)
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.05.97	Dean Ashton		Created
*	22.06.97	Martin Kift		Added windows network code (and better control
*								of the level stack, for master player only)
*	08.07.97	Dean Ashton		Modified yet again for bloody Kev... bastard.
*
*%%%**************************************************************************/

#include "select.h"
#include "sprdata.h"
#include "gamefont.h"
#include "project.h"
#include "options.h"
#include "main.h"
#include "gamesys.h"
#include "hsview.h"
#include "library.h"
#include "tempopt.h"
#include "frog.h"
#include "sound.h"
#include "xalist.h"
#include "ent_gen.h"
#include "camera.h"
#include "pause.h"

#ifdef WIN95
#pragma warning (disable : 4761)
#pragma warning (disable : 4245)
#pragma warning (disable : 4146)
#endif

MR_BOOL			Sel_first_time;

MR_ULONG		Sel_count;
MR_2DSPRITE*	Sel_loading_sprite_ptr;

MR_ULONG		Sel_vlo_res_id[]=
				{
				RES_LS_SUB_VLO,
				RES_LS_ORG_VLO,
				RES_LS_SWP_VLO,
				RES_LS_SKY_VLO,
				RES_LS_FOR_VLO,
				RES_LS_VOL_VLO,
				RES_LS_DES_VLO,
				RES_LS_CAV_VLO,
				RES_LS_JUN_VLO,
				};

//MR_ULONG		Sel_time_out;									// $wb - E3 requirement, time out count

MR_LONG			Sel_mode;										// Level selection run type (arcade, or race/multiplayer?)
MR_LONG			Sel_game_mode;									// Current operation mode for Level selection update

MR_BOOL			Sel_requested_play;

SEL_LEVEL_INFO*	Sel_level_ptr;									// Pointer to appropriate level bank (for operating mode)
MR_LONG			Sel_camera_y_offset;							// Where camera is in 'Y' when looking at slice at (0,0,0)
MR_LONG			Sel_target_y;									// Where the camera is looking at..

SEL_LEVEL_MOF*	Sel_mof_bank;									// Pointer to allocated block of MOFs for levels
MR_VIEWPORT*	Option_viewport_ptr;							// Local pointer to the viewport (for speed)

MR_FRAME*		Sel_spin_frame;									// Frame for spinning MOF
MR_FRAME*		Sel_stack_frame;								// Frame for level stack
MR_FRAME*		Sel_camera_frame;								// Frame for camera
MR_FRAME*		Sel_light_frame_0;								// Frame for directional light 0
MR_FRAME*		Sel_light_frame_1;								// Frame for directional light 1
MR_FRAME*		Sel_light_frame_2;								// Frame for directional light 2
MR_OBJECT*		Sel_light_object_a;								// Object for ambient light
MR_OBJECT*		Sel_light_object_0;								// Object for directional light 0
MR_OBJECT*		Sel_light_object_1;								// Object for directional light 1
MR_OBJECT*		Sel_light_object_2;								// Object for directional light 2
MR_LIGHT_INST*	Sel_light_inst_a;								// Light instance for ambient light
MR_LIGHT_INST*	Sel_light_inst_0;								// Light instance for directional light 0
MR_LIGHT_INST*	Sel_light_inst_1;								// Light instance for directional light 1
MR_LIGHT_INST*	Sel_light_inst_2;								// Light instance for directional light 2

MR_2DSPRITE*	Sel_title;
MR_2DSPRITE*	Sel_user_prompt;
MR_2DSPRITE*	Sel_level_title;
MR_TEXT_AREA*	Sel_score_line[3];

SEL_LEVEL_INFO*	Sel_arcade_level_ptr;
SEL_LEVEL_INFO*	Sel_race_level_ptr;

SEL_LEVEL_INFO*	Sel_work_level_ptr;
															
MR_LONG			Sel_camera_y;									// Miscellaneous camera movement variables	   	
MR_LONG			Sel_camera_acc;
MR_LONG			Sel_camera_vel;
MR_LONG			Sel_camera_flag = SEL_CAMERA_STATIONARY;

MR_SVEC			Sel_start_pos;
MR_SVEC			Sel_end_pos;
MR_VEC			Sel_temp_pos;

MR_SVEC			Sel_start_vec_y;
MR_SVEC			Sel_dest_vec_y;
MR_VEC			Sel_temp_vec_y;

MR_SVEC			Sel_start_vec_roll;
MR_SVEC			Sel_dest_vec_roll;
MR_VEC			Sel_temp_vec_roll;

MR_LONG			Sel_status_start_x;
MR_LONG			Sel_status_end_x;
MR_LONG			Sel_status_temp_x;

MR_LONG			Sel_spin_max_time;
MR_LONG			Sel_spin_time;
MR_LONG			Sel_spin_mode;


#define			SEL_GLOWY_MIN		0x60
#define			SEL_GLOWY_MAX		0xa0
#define			SEL_GLOWY_SPEED		16
#define			SEL_DARK_COLOUR		0x40
#define			SEL_LIGHT_COLOUR	0x80

MR_CVEC			Sel_glowy_col;
MR_LONG			Sel_glowy_dir;
SEL_LEVEL_INFO*	Sel_glowy_level_ptr;


MR_LONG			Port_id;

// DMA:	At the moment the hiscore text area is faked up. Once you've put a place for the top 3 names/times/scores into the
//		SEL_LEVEL_INFO structure (or your equivalent somewhere else in your code) then you'll need to modify the calls to
//		MRBuildText() later on.
MR_STRPTR		Sel_hiscore_text[3][25]	=
				{//	  0123456789012345678901
//					{"%jc   DMA 32345678   ", NULL},	// race score is centred as here
					{"%jc1.DMA 0000000000:00s  ", NULL},	// arcade score is centred as here
					{"%jc2.DMA  1:11 22345678  ", NULL},
					{"%jc3.DMA  1:11 32345678  ", NULL},
				};

SEL_LEVEL_INFO*	Sel_spin_backup_ptr;										// So we can re-enable level mof after spin
SEL_LEVEL_INFO	Sel_spin_level;												// Level to contain data for spinning MOF

SEL_LEVEL_INFO	Sel_arcade_levels[] =										// List of levels for arcade mode
				{
					// ------------------------------------------------------------------------------------------------
					// Retro/Original levels: 1, 2, 3, 4, 5

  					// RETRO 1
					{	
					LEVEL_ORIGINAL1, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,					// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_ORIGINAL_ARC_LEVELS, 		// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_org1pic, &im_org1name,								// Level representation and Level name bitmaps
					&im_org1name,											// IN GAME level name bitmap
					},

  					// RETRO 2
					{	
					LEVEL_ORIGINAL2, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,					// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_ORIGINAL_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_org2pic, &im_org2name,								// Level representation and Level name bitmaps
					&im_org2name,											// IN GAME level name bitmap
					},

  					// RETRO 3
					{	
					LEVEL_ORIGINAL3, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,					// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_ORIGINAL_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_org3pic, &im_org3name,								// Level representation and Level name bitmaps
					&im_org3name,											// IN GAME level name bitmap
					},

  					// RETRO 4
					{	
					LEVEL_ORIGINAL4, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,					// Library ID
					SEL_ARCADE_LEVEL_4_ID, SEL_ORIGINAL_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_org4pic, &im_org4name,								// Level representation and Level name bitmaps
					&im_org4name,											// IN GAME level name bitmap
					},

  					// RETRO 5
					{	
					LEVEL_ORIGINAL5, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,					// Library ID
					SEL_ARCADE_LEVEL_5_ID, SEL_ORIGINAL_ARC_LEVELS, 		// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_org5pic, &im_org5name,								// Level representation and Level name bitmaps
					&im_org5name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Suburbia levels: 1, 2, 3, 4, 5

					// SUBURBIA 1
					{	
					LEVEL_SUBURBIA1, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,					// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_SUBURBIA_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sub1pic, &im_sub1name,								// Level representation and Level name bitmaps
					&im_sub1name,											// IN GAME level name bitmap
					},

					// SUBURBIA 2
					{	
					LEVEL_SUBURBIA2, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,					// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_SUBURBIA_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sub2pic, &im_sub2name,								// Level representation and Level name bitmaps
					&im_sub2name,											// IN GAME level name bitmap
					},

					// SUBURBIA 3
					{	
					LEVEL_SUBURBIA3, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,					// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_SUBURBIA_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sub3pic, &im_sub3name,								// Level representation and Level name bitmaps
					&im_sub3name,											// IN GAME level name bitmap
					},

					// SUBURBIA 4
					{	
					LEVEL_SUBURBIA4, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,					// Library ID
					SEL_ARCADE_LEVEL_4_ID, SEL_SUBURBIA_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sub4pic, &im_sub4name,								// Level representation and Level name bitmaps
					&im_sub4name,											// IN GAME level name bitmap
					},
					// SUBURBIA 5
					{	
					LEVEL_SUBURBIA5, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,					// Library ID
					SEL_ARCADE_LEVEL_5_ID, SEL_SUBURBIA_ARC_LEVELS, 		// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sub5pic, &im_sub5name,								// Level representation and Level name bitmaps
					&im_sub5name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Forest levels: 1, 2, 3

  					// FOREST 1
					{	
					LEVEL_FOREST1, SEL_WORLD_ID_FOREST,2,THEME_FOR,						// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_FOREST_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_for_col, &im_for_grey,	&im_for_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_for1pic, &im_for1name,								// Level representation and Level name bitmaps
					&im_for1name,											// IN GAME level name bitmap
					},

  					// FOREST 2
					{	
					LEVEL_FOREST2, SEL_WORLD_ID_FOREST,2,THEME_FOR,	 					// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_FOREST_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_for_col, &im_for_grey,	&im_for_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_for2pic, &im_for2name,								// Level representation and Level name bitmaps
					&im_for2name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Industrial/Volcano levels: 1, 3, 2

  					// VOLCANO 1
					{	
					LEVEL_VOLCANO1, SEL_WORLD_ID_VOLCANO,3,THEME_VOL,					// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_VOLCANO_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_vol_col, &im_vol_grey,	&im_vol_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_vol1pic, &im_vol1name,								// Level representation and Level name bitmaps
					&im_vol1name,											// IN GAME level name bitmap
					},

  					// VOLCANO 3
					{	
					LEVEL_VOLCANO3,	SEL_WORLD_ID_VOLCANO,3,THEME_VOL,					// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_VOLCANO_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_vol_col, &im_vol_grey,	&im_vol_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_vol3pic, &im_vol3name,								// Level representation and Level name bitmaps
					&im_vol3name,											// IN GAME level name bitmap
					},

  					// VOLCANO 2
					{	
					LEVEL_VOLCANO2, SEL_WORLD_ID_VOLCANO,3,THEME_VOL,					// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_VOLCANO_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_vol_col, &im_vol_grey,	&im_vol_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_vol2pic, &im_vol2name,								// Level representation and Level name bitmaps
					&im_vol2name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Cave levels: 1, 2, 4

  					// CAVES 1
					{	
					LEVEL_CAVES1, SEL_WORLD_ID_CAVES,4,THEME_CAV,						// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_CAVES_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_cav_col, &im_cav_grey,	&im_cav_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_cav1pic, &im_cav1name,								// Level representation and Level name bitmaps
					&im_cav1name,											// IN GAME level name bitmap
					},

  					// CAVES 2
					{	
					LEVEL_CAVES3, SEL_WORLD_ID_CAVES,4,THEME_CAV,						// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_CAVES_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_cav_col, &im_cav_grey,	&im_cav_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_cav3pic, &im_cav3name,								// Level representation and Level name bitmaps
					&im_cav3name,											// IN GAME level name bitmap
					},

  					// CAVES 3
					{	
					LEVEL_CAVES4, SEL_WORLD_ID_CAVES,4,THEME_CAV,						// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_CAVES_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_cav_col, &im_cav_grey,	&im_cav_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_cav4pic, &im_cav4name,								// Level representation and Level name bitmaps
					&im_cav4name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Sky levels: 1, 3, 4, 2

  					// SKY 1
					{	
					LEVEL_SKY1,	SEL_WORLD_ID_SKY,5,THEME_SKY,							// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_SKY_ARC_LEVELS, 				// Number of level in world, and level count in world		
					&im_sky_col, &im_sky_grey,	&im_sky_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sky1pic, &im_sky1name,								// Level representation and Level name bitmaps
					&im_sky1name,											// IN GAME level name bitmap
					},

  					// SKY 3
					{	
					LEVEL_SKY3,	SEL_WORLD_ID_SKY,5,THEME_SKY,							// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_SKY_ARC_LEVELS, 				// Number of level in world, and level count in world		
					&im_sky_col, &im_sky_grey,	&im_sky_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sky3pic, &im_sky3name,								// Level representation and Level name bitmaps
					&im_sky3name,											// IN GAME level name bitmap
					},

  					// SKY 4
					{	
					LEVEL_SKY4,	SEL_WORLD_ID_SKY,5,THEME_SKY,							// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_SKY_ARC_LEVELS, 				// Number of level in world, and level count in world		
					&im_sky_col, &im_sky_grey,	&im_sky_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sky4pic, &im_sky4name,								// Level representation and Level name bitmaps
					&im_sky4name,											// IN GAME level name bitmap
					},

					// SKY 2
					{	
					LEVEL_SKY2, SEL_WORLD_ID_SKY,5,THEME_SKY,							// Library ID
					SEL_ARCADE_LEVEL_4_ID, SEL_SKY_ARC_LEVELS, 				// Number of level in world, and level count in world		
					&im_sky_col, &im_sky_grey,	&im_sky_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_sky2pic, &im_sky2name,								// Level representation and Level name bitmaps
					&im_sky2name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Swamp levels: 1, 4, 3, 2, 5

  					// SWAMP 1
					{	
					LEVEL_SWAMP1, SEL_WORLD_ID_SWAMP,6,THEME_SWP,						// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_SWAMP_ARC_LEVELS, 			// Number of level in world, and level count in world		
					&im_swp_col, &im_swp_grey,	&im_swp_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_swp1pic, &im_swp1name,								// Level representation and Level name bitmaps
					&im_swp1name,											// IN GAME level name bitmap
					},

  					// SWAMP 4
					{	
					LEVEL_SWAMP4, SEL_WORLD_ID_SWAMP,6,THEME_SWP,						// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_SWAMP_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_swp_col, &im_swp_grey,	&im_swp_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_swp4pic, &im_swp4name,								// Level representation and Level name bitmaps
					&im_swp4name,											// IN GAME level name bitmap
					},

  					// SWAMP 3
					{	
					LEVEL_SWAMP3, SEL_WORLD_ID_SWAMP,6,THEME_SWP,						// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_SWAMP_ARC_LEVELS, 			// Number of level in world, and level count in world		
					&im_swp_col, &im_swp_grey,	&im_swp_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_swp3pic, &im_swp3name,								// Level representation and Level name bitmaps
					&im_swp3name,											// IN GAME level name bitmap
					},

  					// SWAMP 2
					{	
					LEVEL_SWAMP2, SEL_WORLD_ID_SWAMP,6,THEME_SWP,						// Library ID
					SEL_ARCADE_LEVEL_4_ID, SEL_SWAMP_ARC_LEVELS, 			// Number of level in world, and level count in world		
					&im_swp_col, &im_swp_grey,	&im_swp_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_swp2pic, &im_swp2name,								// Level representation and Level name bitmaps
					&im_swp2name,											// IN GAME level name bitmap
					},

  					// SWAMP 5
					{	
					LEVEL_SWAMP5, SEL_WORLD_ID_SWAMP,6,THEME_SWP,						// Library ID
					SEL_ARCADE_LEVEL_5_ID, SEL_SWAMP_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_swp_col, &im_swp_grey,	&im_swp_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_swp5pic, &im_swp5name,								// Level representation and Level name bitmaps
					&im_swp5name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Desert levels: 1, 2, 3, 4, 5

  					// DESERT 1
					{	
					LEVEL_DESERT1, SEL_WORLD_ID_DESERT,7,THEME_DES,						// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_DESERT_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_des_col, &im_des_grey,	&im_des_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_des1pic, &im_des1name,								// Level representation and Level name bitmaps
					&im_des1name,											// IN GAME level name bitmap
					},

  					// DESERT 2
					{	
					LEVEL_DESERT2, SEL_WORLD_ID_DESERT,7,THEME_DES,						// Library ID
					SEL_ARCADE_LEVEL_2_ID, SEL_DESERT_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_des_col, &im_des_grey,	&im_des_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_des2pic, &im_des2name,								// Level representation and Level name bitmaps
					&im_des2name,											// IN GAME level name bitmap
					},

  					// DESERT 3
					{	
					LEVEL_DESERT3, SEL_WORLD_ID_DESERT,7,THEME_DES,						// Library ID
					SEL_ARCADE_LEVEL_3_ID, SEL_DESERT_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_des_col, &im_des_grey,	&im_des_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_des3pic, &im_des3name,								// Level representation and Level name bitmaps
					&im_des3name,											// IN GAME level name bitmap
					},

  					// DESERT 4
					{	
					LEVEL_DESERT4, SEL_WORLD_ID_DESERT,7,THEME_DES,						// Library ID
					SEL_ARCADE_LEVEL_4_ID, SEL_DESERT_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_des_col, &im_des_grey,	&im_des_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_des4pic, &im_des4name,								// Level representation and Level name bitmaps
					&im_des4name,											// IN GAME level name bitmap
					},

  					// DESERT 5
					{	
					LEVEL_DESERT5, SEL_WORLD_ID_DESERT,7,THEME_DES,						// Library ID
					SEL_ARCADE_LEVEL_5_ID, SEL_DESERT_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_des_col, &im_des_grey,	&im_des_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_des5pic, &im_des5name,								// Level representation and Level name bitmaps
					&im_des5name,											// IN GAME level name bitmap
					},

					// ------------------------------------------------------------------------------------------------
					// Jungle levels: 1

  					// JUNGLE 1
					{	
					LEVEL_JUNGLE1, SEL_WORLD_ID_JUNGLE_RIVER,8,THEME_JUN,				// Library ID
					SEL_ARCADE_LEVEL_1_ID, SEL_JUNGLE_ARC_LEVELS,			// Number of level in world, and level count in world		
					&im_jun_col, &im_jun_grey,	&im_jun_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_jun1pic, &im_jun1name,								// Level representation and Level name bitmaps
					NULL,
					},

					// ------------------------------------------------------------------------------------------------
					// List terminator

					{	
					-1, 0,9,255,													// Library ID
					0, 0,													// Number of level in world, and level count in world		
					NULL, NULL, NULL,										// Selectable, visited, and not-tried world images (30x30x256)
					NULL, NULL,												// Level representation and Level name bitmaps
					},

				};


SEL_LEVEL_INFO	Sel_race_levels[] = 										// List of levels for race mode
				{
					// ------------------------------------------------------------------------------------------------
					// Retro/Original multiplayer level

					{	
					LEVEL_ORIGINAL_MULTI_PLAYER, SEL_WORLD_ID_ORIGINAL,0,THEME_ORG,		// Library ID
					SEL_RACE_LEVEL_1_ID, SEL_ORIGINAL_RACE_LEVELS,			// Number of level in world, and level count in world		
					&im_org_col, &im_org_grey,	&im_org_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_orgmpic, &im_orgmname,								// Level representation and Level name bitmaps
					},

					// ------------------------------------------------------------------------------------------------
					// Suburbia multiplayer level
			
					{	
					LEVEL_SUBURBIA_MULTI_PLAYER, SEL_WORLD_ID_SUBURBIA,1,THEME_SUB,		// Library ID
					SEL_RACE_LEVEL_1_ID, SEL_SUBURBIA_RACE_LEVELS,			// Number of level in world, and level count in world		
					&im_sub_col, &im_sub_grey,	&im_sub_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_submpic, &im_submname,								// Level representation and Level name bitmaps
					},

					// ------------------------------------------------------------------------------------------------
					// Forest multiplayer level

					{	
					LEVEL_FOREST_MULTI_PLAYER, SEL_WORLD_ID_FOREST,2,THEME_FOR,			// Library ID
					SEL_RACE_LEVEL_1_ID, SEL_FOREST_RACE_LEVELS,			// Number of level in world, and level count in world		
					&im_for_col, &im_for_grey,	&im_for_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_formpic, &im_formname,								// Level representation and Level name bitmaps
					},

					// ------------------------------------------------------------------------------------------------
					// Volcano multiplayer level

					{	
					LEVEL_VOLCANO_MULTI_PLAYER, SEL_WORLD_ID_VOLCANO,3,THEME_VOL,		// Library ID
					SEL_RACE_LEVEL_1_ID, SEL_VOLCANO_RACE_LEVELS,			// Number of level in world, and level count in world
					&im_vol_col, &im_vol_grey,	&im_vol_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_volmpic, &im_volmname,								// Level representation and Level name bitmaps
					},

					// ------------------------------------------------------------------------------------------------
					// Jungle multiplayer level

					{	
					LEVEL_JUNGLE_MULTI_PLAYER, SEL_WORLD_ID_JUNGLE_RIVER,4,THEME_JUN,	// Library ID
					SEL_RACE_LEVEL_1_ID, SEL_JUNGLE_RACE_LEVELS,			// Number of level in world, and level count in world		
					&im_jun_col, &im_jun_grey,	&im_jun_grey,				// Selectable, visited, and not-tried world images (30x30x256)
					&im_junmpic, &im_junmname,								// Level representation and Level name bitmaps
					},

					// ------------------------------------------------------------------------------------------------
					// List terminator

					{	
					-1, 0,5,0,													// Library ID
					0, 0,													// Number of level in world, and level count in world		
					NULL, NULL, NULL,										// Selectable, visited, and not-tried world images (30x30x256)
					NULL, NULL,												// Level representation and Level name bitmaps
					},

				};


// Stuff required for Golden Frog on side of level select stack
POLY_FT4		Sel_golden_frog_polys[2][10];
MR_ULONG		Sel_base_col = 0x80808080;
MR_SVEC			Sel_golden_frog_points[2*12];

// Scrolling background for hiscore view
POLY_FT4*		Select_bg_polys[2];
MR_LONG			Select_bg_direction;
MR_LONG			Select_bg_counter;
MR_LONG			Select_bg_xnum;
MR_LONG			Select_bg_ynum;
MR_LONG			Select_bg_xlen;
MR_LONG			Select_bg_ylen;

// Conversion table for displaying high score frogs
MR_ULONG		Level_table[10]=
				{
				4,
				7,
				2,
				8,
				0,
				0,
				6,
				5,
				1,
				3,
				};

/******************************************************************************
*%%%% SelectLevelInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelInit(MR_VOID)
*
*	FUNCTION	Performs once only initialisation of the world/level status
*				flags. Can also be called when the user wants to start a 
*				completely new game (without any of the previously obtained 
*				levels being available).
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Modified yet again for bloody Kev.
*
*%%%**************************************************************************/

MR_VOID	SelectLevelInit(MR_VOID)
{
	SEL_LEVEL_INFO*	level_ptr;
	SEL_LEVEL_INFO*	next_level_ptr;
	MR_LONG			level_y_pos;


	// Initialise all arcade levels 
	level_y_pos	= 0;
	level_ptr	= Sel_arcade_levels;
	while (level_ptr->li_library_id != -1)
		{
		level_ptr->li_y_size	 = (SEL_BOX_X_SIZE/level_ptr->li_levels_in_world);
  		level_ptr->li_y_position = level_y_pos;
  		level_y_pos += (SEL_BOX_X_SIZE/level_ptr->li_levels_in_world);
		next_level_ptr = level_ptr + 1;
		if (next_level_ptr->li_library_id != -1)
			level_y_pos += (SEL_BOX_X_SIZE/next_level_ptr->li_levels_in_world);
		level_ptr->li_flags = NULL;
		level_ptr++;
		}
	level_y_pos	= (level_ptr - 1)->li_y_position;
	level_ptr	= Sel_arcade_levels;
	while (level_ptr->li_library_id != -1)
		{
  		level_ptr->li_y_position -= level_y_pos;
		level_ptr++;
		}

	// Initialise all race levels 
	level_y_pos	= 0;
	level_ptr	= Sel_race_levels;
	while (level_ptr->li_library_id != -1)
		{
		level_ptr->li_y_size	 = (SEL_BOX_X_SIZE/level_ptr->li_levels_in_world);
  		level_ptr->li_y_position = level_y_pos;
  		level_y_pos += (SEL_BOX_X_SIZE/level_ptr->li_levels_in_world);
		next_level_ptr = level_ptr + 1;
		if (next_level_ptr->li_library_id != -1)
			level_y_pos += (SEL_BOX_X_SIZE/next_level_ptr->li_levels_in_world);
		level_ptr->li_flags = NULL;
		level_ptr++;
		}
	level_y_pos	= (level_ptr - 1)->li_y_position;
	level_ptr	= Sel_race_levels;
	while (level_ptr->li_library_id != -1)
		{
  		level_ptr->li_y_position -= level_y_pos;
		level_ptr++;
		}

	// Set initial flags for arcade levels here
	SelectSetLevelFlags(LEVEL_ORIGINAL1,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA1,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_FOREST1,		SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_VOLCANO1,		SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);

	
	SelectSetLevelFlags(LEVEL_ORIGINAL2,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_ORIGINAL3,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_ORIGINAL4,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_ORIGINAL5,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA2,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA3,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA4,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA5,	SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_FOREST2,		SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_VOLCANO2,		SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_VOLCANO3,		SEL_LF_ZONEACCESSIBLE);
	
	// Set initial flags for race levels here
	SelectSetLevelFlags(LEVEL_ORIGINAL_MULTI_PLAYER,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_SUBURBIA_MULTI_PLAYER,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_FOREST_MULTI_PLAYER,		SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_VOLCANO_MULTI_PLAYER,		SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
	SelectSetLevelFlags(LEVEL_JUNGLE_MULTI_PLAYER,		SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);

	// Set initial pointers to levels
	Sel_arcade_level_ptr	= SelectGetLevelPointer(LEVEL_ORIGINAL1);
	Sel_race_level_ptr		= SelectGetLevelPointer(LEVEL_ORIGINAL_MULTI_PLAYER);
}


/******************************************************************************
*%%%% SelectSetLevelFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectSetLevelFlags(
*						MR_LONG		sl_game_map,
*						MR_ULONG	sl_flags)
*
*	FUNCTION	A mechanism for writing a new value for a levels selection 
*				flags
*
*	INPUTS		sl_game_map	-	Library ID of the level to modify selection
*								flags for (must exist in level stack!)
*
*				sl_flags	-	Value to prod into levels li_flags field	
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	SelectSetLevelFlags(MR_LONG sl_game_map, MR_ULONG sl_flags)
{
	SEL_LEVEL_INFO*	level_ptr;
	
	if	(
		(sl_game_map == LEVEL_CAVES_MULTI_PLAYER)		||
		(sl_game_map == LEVEL_DESERT_MULTI_PLAYER)		||
		(sl_game_map == LEVEL_FOREST_MULTI_PLAYER) 		||
		(sl_game_map == LEVEL_JUNGLE_MULTI_PLAYER) 		||
		(sl_game_map == LEVEL_ORIGINAL_MULTI_PLAYER) 	||
		(sl_game_map == LEVEL_RUINS_MULTI_PLAYER)		||
		(sl_game_map == LEVEL_SWAMP_MULTI_PLAYER)		||
		(sl_game_map == LEVEL_SKY_MULTI_PLAYER)			||
		(sl_game_map == LEVEL_SUBURBIA_MULTI_PLAYER)	||
		(sl_game_map == LEVEL_VOLCANO_MULTI_PLAYER)		
		)
		level_ptr = Sel_race_levels;
	else
		level_ptr = Sel_arcade_levels;

	while(level_ptr->li_library_id != -1)
		{
		if (level_ptr->li_library_id == sl_game_map)
			{
			level_ptr->li_flags = sl_flags;
			return;
			}
		level_ptr++;
		}

	// Didn't find the level in the appropriate stack.. Barf.
//	MR_ASSERT(FALSE);
}


/******************************************************************************
*%%%% SelectGetLevelFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	gl_flags =	SelectGetLevelFlags(
*									MR_LONG		gl_game_map);
*
*	FUNCTION	A mechanism for reading a levels selection flags 
*	MATCH		https://decomp.me/scratch/IdCV9	(By Kneesnap)
*
*	INPUTS		gl_game_map	-	Library ID of the level to read selection
*								flags for (must exist in level stack!)
*
*	RESULT		gl_flags	-	Flags for thislevel
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Dean Ashton		Created
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_ULONG	SelectGetLevelFlags(MR_LONG gl_game_map)
{
	SEL_LEVEL_INFO*	level_ptr;
	
	if	(
		(gl_game_map == LEVEL_CAVES_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_DESERT_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_FOREST_MULTI_PLAYER) 		||
		(gl_game_map == LEVEL_JUNGLE_MULTI_PLAYER) 		||
		(gl_game_map == LEVEL_ORIGINAL_MULTI_PLAYER) 	||
		(gl_game_map == LEVEL_RUINS_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_SWAMP_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_SKY_MULTI_PLAYER)			||
		(gl_game_map == LEVEL_SUBURBIA_MULTI_PLAYER)	||
		(gl_game_map == LEVEL_VOLCANO_MULTI_PLAYER)		
		)
		level_ptr = Sel_race_levels;
	else
		level_ptr = Sel_arcade_levels;

	while(level_ptr->li_library_id != -1)
		{
		if (level_ptr->li_library_id == gl_game_map)
			{
			return(level_ptr->li_flags);
			}
		level_ptr++;
		}

	// The jungle levels should always return the flags from the first level in the stack, due to level replacement
	if (gl_game_map >= LEVEL_JUNGLE1 && gl_game_map <= LEVEL_JUNGLE2)
		{
		level_ptr = Sel_arcade_levels;
		while(level_ptr->li_library_id != -1)
			{
			if (level_ptr->li_library_id >= LEVEL_JUNGLE1 && level_ptr->li_library_id <= LEVEL_JUNGLE2)
				{
				return(level_ptr->li_flags);
				}
			level_ptr++;
			}
		}

	// Didn't find the level in the appropriate stack.. Barf.
	MR_ASSERT(FALSE);
}


/******************************************************************************
*%%%% SelectGetLevelPointer
*------------------------------------------------------------------------------
*
*	SYNOPSIS	SEL_LEVEL_INFO*	gl_level =	SelectGetLevelPointer(
*											MR_LONG		gl_game_map);
*
*	FUNCTION	A mechanism for obtaining a pointer to a specific levels 
*				selection info structure
*
*	INPUTS		gl_game_map	-	Library ID of the level to read selection
*								flags for (must exist in level stack!)
*			  
*	RESULT		gl_level	-	Pointer to a SEL_LEVEL_INFO structure
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.07.97	Dean Ashton		Created
*
*%%%**************************************************************************/

SEL_LEVEL_INFO*	SelectGetLevelPointer(MR_LONG gl_game_map)
{
	SEL_LEVEL_INFO*	level_ptr;
	
	if	(
		(gl_game_map == LEVEL_CAVES_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_DESERT_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_FOREST_MULTI_PLAYER) 		||
		(gl_game_map == LEVEL_JUNGLE_MULTI_PLAYER) 		||
		(gl_game_map == LEVEL_ORIGINAL_MULTI_PLAYER) 	||
		(gl_game_map == LEVEL_RUINS_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_SWAMP_MULTI_PLAYER)		||
		(gl_game_map == LEVEL_SKY_MULTI_PLAYER)			||
		(gl_game_map == LEVEL_SUBURBIA_MULTI_PLAYER)	||
		(gl_game_map == LEVEL_VOLCANO_MULTI_PLAYER)		
		)
		level_ptr = Sel_race_levels;
	else
		level_ptr = Sel_arcade_levels;

	while(level_ptr->li_library_id != -1)
		{
		if (level_ptr->li_library_id == gl_game_map)
			{
			return(level_ptr);
			}
		level_ptr++;
		}

	// Didn't find the level in the appropriate stack.. Barf.
	MR_ASSERT(FALSE);
}


/******************************************************************************
*%%%% SelectLevelStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelStartup(MR_VOID)
*
*	FUNCTION	Performs initialisation for the level selection mechanism, 
*				including the request for generation of all slice MOF's. 
*				This routine also generates a 'proper' MOF, with origin relative
*				coordinates, that can be used for the spin-out to show the level
*				picture/details.
*
*	MATCH		https://decomp.me/scratch/VnJUx	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Modified yet again for bloody Kev.
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	SelectLevelStartup(MR_VOID)
{
	MR_ULONG		level_count;
	SEL_LEVEL_INFO*	level_ptr;
	SEL_LEVEL_MOF*	level_mof_ptr;	
	MR_ULONG		world_id;
	MR_ULONG		loop_counter;
	MR_ULONG		loop_counter_1;
	MR_ULONG		loop_counter_2;
	MR_TEXTURE*		texture;

	Map_mof_index = 0;

#ifdef WIN95
	// windows specific code
	if (MNIsNetGameRunning())
		{
		// Initialise synced of all network machines 
		InitialiseSync();
		}
#endif

	if (Game_total_players > 1)
		{
		// Work out which port to listen too
		Port_id = Frog_player_data[Frog_selection_master_player_id].fp_port_id;
		}
	else
		Port_id = Frog_input_ports[0];

	// Check options resources are loaded
	LoadOptionsResources();

	// Initialise selection mode
	Sel_game_mode =	SEL_GAME_MODE_SELECTING;

	// Initialise time out count
//	Sel_time_out = 0;

	// Setup common variables based on the operating mode
	if (Sel_mode == SEL_MODE_ARCADE)
		{
		Sel_level_ptr		= Sel_arcade_levels;
		Sel_work_level_ptr	= Sel_arcade_level_ptr;
		Sel_glowy_level_ptr	= Sel_arcade_level_ptr;
		}
	else
		{
		Sel_level_ptr		= Sel_race_levels;
		Sel_work_level_ptr	= Sel_race_level_ptr;
		Sel_glowy_level_ptr	= Sel_arcade_level_ptr;
		}

	// Calculate how many level mofs we're going to need 
	level_ptr	= Sel_level_ptr;
	level_count = 0;
	while (level_ptr->li_library_id != -1)
		{
		level_count++;
		level_ptr++;
		}

	// Create scene information (camera, lights)
	Option_viewport_ptr->vp_perspective = 1000;
	SelectCreateScene();

	// initialise the glowy colour stuff for accessible but uncompleted levels
	Sel_glowy_col.r = SEL_GLOWY_MAX;
	Sel_glowy_col.g = SEL_GLOWY_MAX;
	Sel_glowy_col.b = SEL_GLOWY_MAX;			// set glowy colour to max
	Sel_glowy_dir = -SEL_GLOWY_SPEED;	// and default to ramping down
	
	// Allocate room for the MOFs (number active in world, + 1 to create the active level MOF)
	Sel_mof_bank = level_mof_ptr = MRAllocMem(sizeof(SEL_LEVEL_MOF) * (level_count+1), "LEVELMOFS");

	// Now create all the required level mofs
	level_ptr = Sel_level_ptr;
	while (level_ptr->li_library_id != -1)
		{
		// Create each MOF, and adds it to the viewport linked to the appropriate frame
		SelectCreateMOF(level_mof_ptr, level_ptr);
		level_mof_ptr++;
		level_ptr++;
		}

	// Create the mof needed for the spinny-out bit (special world/level in order to create si_active_level)
	// but flag it as 'do not display'
	SelectCreateMOF(level_mof_ptr, &Sel_spin_level);
	Sel_spin_level.li_object->ob_flags |= MR_OBJ_NO_DISPLAY;

	// Initialise viewing positions here... 
	level_ptr							= Sel_work_level_ptr;
	Sel_camera_y						= level_ptr->li_y_position + Sel_camera_y_offset;
	Sel_camera_frame->fr_matrix.t[1] 	= level_ptr->li_y_position + Sel_camera_y_offset;
	Sel_status_start_x					= Game_display_width + 32;
	Sel_status_end_x					= SEL_STATUS_END_X_POS;

	// Create 2D sprite for title
	texture 	= Options_text_textures[OPTION_TEXT_SELECT_LEVEL][Game_language];
	Sel_title	= MRCreate2DSprite((Game_display_width >> 1)-(texture->te_w >> 1), 24, Option_viewport_ptr, texture, NULL);
	Sel_title->sp_core.sc_base_colour.r = 0x60;
	Sel_title->sp_core.sc_base_colour.g = 0x60;
	Sel_title->sp_core.sc_base_colour.b = 0x60;
	if ((Option_page_current == OPTIONS_PAGE_HIGH_SCORE_VIEW) && (HSView_automatic_flag == TRUE)) 
		Sel_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

	// Create 2D sprite for user-prompting
	if ( (Sel_first_time == TRUE) || (Sel_mode == SEL_MODE_RACE) )
		{
		texture			= Options_text_textures[OPTION_TEXT_SELECT1][Game_language];
		}
	else
		{
		texture			= Options_text_textures[OPTION_TEXT_SELECT5][Game_language];
		}
	Sel_user_prompt = MRCreate2DSprite(SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w, SEL_PROMPT_SPRITE_Y, Option_viewport_ptr, texture, NULL);

	// Create 2D sprite for level title (off screen, dimmed)
//	Sel_level_title	= MRCreate2DSprite(Sel_status_start_x, SEL_LEVEL_TITLE_Y, Option_viewport_ptr, texture, NULL);
	Sel_level_title->sp_pos.x = Sel_status_start_x;
	Sel_level_title->sp_pos.y = SEL_LEVEL_TITLE_Y;
	MRChangeSprite(Sel_level_title,texture);
	Sel_level_title->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
	Sel_level_title->sp_core.sc_base_colour.r = 0x60;
	Sel_level_title->sp_core.sc_base_colour.g = 0x60;
	Sel_level_title->sp_core.sc_base_colour.b = 0x60;

	// Create 3 text areas (one per line) off screen
	Sel_score_line[0] = MRAllocateTextArea(NULL, NULL, Option_viewport_ptr, 32, Sel_status_start_x, SEL_LEVEL_SCORE_LINE_0_Y, SEL_STATUS_WIDTH, 16); 
	Sel_score_line[1] = MRAllocateTextArea(NULL, NULL, Option_viewport_ptr, 32, Sel_status_start_x, SEL_LEVEL_SCORE_LINE_1_Y, SEL_STATUS_WIDTH, 16); 
	Sel_score_line[2] = MRAllocateTextArea(NULL, NULL, Option_viewport_ptr, 32, Sel_status_start_x, SEL_LEVEL_SCORE_LINE_2_Y, SEL_STATUS_WIDTH, 16); 

#ifdef WIN95
	// send our own sync msg here
	SendSync();
#endif

#ifdef	PSX_ENABLE_XA
#ifdef PSX
	StopLoadingSfxLoop();
	Sel_loading_sprite_ptr->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
	Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

	
	// Only Play Level Select Music, if actually Selecting a level.
	if (Options_music_playing == FALSE)
		{
		XAStartup();
		XAPlayChannel(LEVEL_TUNES3,5,TRUE);
		}
#else
#endif
#endif

	// Loop once for each position on level select stack
	for(loop_counter_1=0;loop_counter_1<10;loop_counter_1++)
		{
		// Loop once for each frame buffer
		for(loop_counter_2=0;loop_counter_2<2;loop_counter_2++)
			{
			// Set up prims to show golden frog on level select stack
			MR_COPY32(Sel_golden_frog_polys[loop_counter_2][loop_counter_1].r0,Sel_base_col);
			setPolyFT4(&Sel_golden_frog_polys[loop_counter_2][loop_counter_1]);

			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].u0 = im_ls_gold_frog.te_u0;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].v0 = im_ls_gold_frog.te_v0;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].u1 = im_ls_gold_frog.te_u1;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].v1 = im_ls_gold_frog.te_v1;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].u2 = im_ls_gold_frog.te_u2;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].v2 = im_ls_gold_frog.te_v2;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].u3 = im_ls_gold_frog.te_u3;
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].v3 = im_ls_gold_frog.te_v3;

		#ifdef PSX
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].clut = im_ls_gold_frog.te_clut_id;
		#endif
			Sel_golden_frog_polys[loop_counter_2][loop_counter_1].tpage = im_ls_gold_frog.te_tpage_id;
			}
		}

	// Get pointer to first mof
	level_mof_ptr = Sel_mof_bank;

	// Set pointer to top of arcade levels
	level_ptr = Sel_arcade_levels;

	// Store current theme
	world_id = level_ptr->li_world_id;

	// Loop once for each level
	for(loop_counter=0;loop_counter<9;loop_counter++)
		{
		// Initialise points for golden frog texture
		Sel_golden_frog_points[0+(loop_counter*2)].vx = level_mof_ptr->sm_verts[4].vx + SEL_STACK_X_POS;
		Sel_golden_frog_points[0+(loop_counter*2)].vy = level_mof_ptr->sm_verts[4].vy;
		Sel_golden_frog_points[0+(loop_counter*2)].vz = level_mof_ptr->sm_verts[4].vz + SEL_STACK_Z_POS;

		Sel_golden_frog_points[1+(loop_counter*2)].vx = level_mof_ptr->sm_verts[0].vx + SEL_STACK_X_POS;
		Sel_golden_frog_points[1+(loop_counter*2)].vy = level_mof_ptr->sm_verts[0].vy;
		Sel_golden_frog_points[1+(loop_counter*2)].vz = level_mof_ptr->sm_verts[0].vz + SEL_STACK_Z_POS;

		// Scan for start of next world
		do
			{
			// Next level
			level_ptr++;
			// Next mof
			level_mof_ptr++;
			}
			while ( world_id == level_ptr->li_world_id );

		// Store new world id
		world_id = level_ptr->li_world_id;

		}

	level_mof_ptr--;

	// Set bottom of last box
	Sel_golden_frog_points[0+(loop_counter*2)].vx = level_mof_ptr->sm_verts[6].vx + SEL_STACK_X_POS;
	Sel_golden_frog_points[0+(loop_counter*2)].vy = level_mof_ptr->sm_verts[6].vy;
	Sel_golden_frog_points[0+(loop_counter*2)].vz = level_mof_ptr->sm_verts[6].vz + SEL_STACK_Z_POS;

	Sel_golden_frog_points[1+(loop_counter*2)].vx = level_mof_ptr->sm_verts[2].vx + SEL_STACK_X_POS;
	Sel_golden_frog_points[1+(loop_counter*2)].vy = level_mof_ptr->sm_verts[2].vy;
	Sel_golden_frog_points[1+(loop_counter*2)].vz = level_mof_ptr->sm_verts[2].vz + SEL_STACK_Z_POS;

	// Ensure camera is correct straight away for first call to HSUpdateWater()
	MRUpdateFrames();

	MRUpdateViewportRenderMatrices();

}


/******************************************************************************
*%%%% SelectLevelShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelShutdown(MR_VOID)
*
*	FUNCTION	This routine performs all shutdown code required for the level
*				selection screen. This includes the destruction of all objects,
*				release of frames, and deallocation of memory used for code
*				generated MOFs.
*
*	MATCH		https://decomp.me/scratch/BmNdB	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Modified again for bloody Kev.
*	21.07.97	Gary Richards	Added code to give the API a chance to tidy Free's.
*	20.08.97	Gary Richards	Fixed bug with Sel_camera_frame being left over.
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	SelectLevelShutdown(MR_VOID)
{
	SEL_LEVEL_INFO*	level_ptr;

#ifdef	PSX_ENABLE_XA
#ifdef  PSX
	// Stop music, if not playing options tune.
	if (Options_music_playing == FALSE)
		XAShutdown();
#else
#endif
#endif

	// Clear the OT
//	MRClearViewportOT(Option_viewport_ptr);

	// Free text areas
	MRFreeTextArea(Sel_score_line[2]);
	MRFreeTextArea(Sel_score_line[1]);
	MRFreeTextArea(Sel_score_line[0]);

	// Kill sprites
//	MRKill2DSprite(Sel_level_title);
	MRKill2DSprite(Sel_user_prompt);
	MRKill2DSprite(Sel_title);
	
	// Remove all meshes from viewport
	level_ptr = Sel_level_ptr;
	while (level_ptr->li_library_id != -1)
		{
		MRDetachFrameFromObject(level_ptr->li_object);
		level_ptr->li_object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
		level_ptr++;
		}

	// Free program-generated MOF bank
	MRFreeMem(Sel_mof_bank);

	// Remove all lights from viewports
	MRRemoveLightInstanceFromViewportPhysically(Sel_light_inst_2, Option_viewport_ptr);
	MRRemoveLightInstanceFromViewportPhysically(Sel_light_inst_1, Option_viewport_ptr);
	MRRemoveLightInstanceFromViewportPhysically(Sel_light_inst_0, Option_viewport_ptr);
	MRRemoveLightInstanceFromViewportPhysically(Sel_light_inst_a, Option_viewport_ptr);

	// Kill light frames
	MRKillFrame(Sel_light_frame_2);
	MRKillFrame(Sel_light_frame_1);
	MRKillFrame(Sel_light_frame_0);


	// Kill special spinning MOF object/frame
	MRDetachFrameFromObject(Sel_spin_level.li_object);
	Sel_spin_level.li_object->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY;
	MRKillFrame(Sel_spin_frame);

	// Kill miscellaneous frames
	MRKillFrame(Sel_stack_frame);

	// Kill camera frames
	MRKillFrame(Sel_camera_frame);

	// Are we in arcade mode ?
	if ( Sel_mode == SEL_MODE_ARCADE )
		{
		// Yes ... pull from arcade level structure
		Game_map = Sel_arcade_level_ptr->li_library_id;
		}
	else
		{
		// No ... pull from race level structure
		Game_map = Sel_race_level_ptr->li_library_id;
		}

	OptionsTidyMemory(FALSE);

	// Kill all local Ordering Tables
	MRKillAllOTs();

	// If going to options menu (NOT the main options), make sure we don't screw the offsets which are already set
	InitialiseOptionsCamera();
	if (Option_page_request == OPTIONS_PAGE_OPTIONS)
		{
		OptionsCameraSnapToOptions();
		HSUpdateScrollyCamera();
		MRUpdateFrames();
		MRUpdateViewportRenderMatrices();
		From_options = FALSE;
		}

	Main_menu_fast_camera = TRUE;
}


/******************************************************************************
*%%%% SelectLevelUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelUpdate(MR_VOID)
*
*	FUNCTION	This function, which is called once per frame, passes control
*				onto mode specific functions, designed for each level selection
*				state (ie waiting for slice selection, moving between slices,
*				waiting for slice advancement, etc etc)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*	16.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	SelectLevelUpdate(MR_VOID)
{
	MR_ULONG	level_number;
	MR_TEXTURE*	texture;
	MR_LONG		i, x;
	POLY_F4*	poly_f4;
	MR_SVEC		rot;
	MR_ULONG	loop_counter;

#ifdef WIN95
	// On windows, in network mode only, don't allow any updates at all until we 
	// have synced with all machines
	if	(MNIsNetGameRunning()) 
		{
		if (!CheckForNetworkSync())
			return;
		// Don't time out under network mode.. BAD
		}
//	else
//		{
//		if (Sel_time_out++ == (SEL_TIME_OUT_TIME))
//			{
//			// Go back to main options
//			Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
//	
//			// Hide level name sprite
//			Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//
//			// Ensure camera starts where it should
//			High_score_view_delayed_request	= NULL;
//			OptionsCameraSnapToMain();
//			}
//		}
#else
//	if (Sel_time_out++ == (SEL_TIME_OUT_TIME))
//		{
//		// Go back to main options
//		Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
//
//		// Hide level name sprite
//		Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;
//
//		// Ensure camera starts where it should
//		High_score_view_delayed_request	= NULL;
//		OptionsCameraSnapToMain();
//		}
#endif

	// River bed and water
	HSUpdateWater();

	SelectUpdateLevelSlide();

	switch (Sel_game_mode)
		{
		case SEL_GAME_MODE_SELECTING:
#ifdef PSX
			SelectUpdateGlowyColours();
			SelectUpdate_MODE_SELECTING();				
#else
			if (!MNIsNetGameRunning())
			{
				SelectUpdate_MODE_SELECTING();
			}
			else
			if (MNGetPlayerNumber() == Frog_selection_master_player_id)
				{
				// we are the master, so allow control
				SelectUpdate_MODE_SELECTING();				
				}
#endif
			break;

		case SEL_GAME_MODE_SHOW_LEVEL_INFO:
#ifdef PSX
			SelectUpdateGlowyColours();
			SelectUpdate_MODE_SHOW_LEVEL_INFO();
#else
			// Don't allow any input in network mode unless we are the master player...
			if (!MNIsNetGameRunning())
				SelectUpdate_MODE_SHOW_LEVEL_INFO();
			else
			if (MNGetPlayerNumber() == Frog_selection_master_player_id)
				{
				// we are the master, so allow control
				SelectUpdate_MODE_SHOW_LEVEL_INFO();				
				}
#endif
			break;

		// Set up fade
		case SEL_GAME_MODE_START_FADE:
			// Set up fade polys
			poly_f4 = &Pause_poly[0];
			for (i = 0; i < 2; i++)
				{
				MR_SET32(poly_f4->r0, 0x000000);
				setPolyF4(poly_f4);
				setSemiTrans(poly_f4, 1);

				// Set poly position
				poly_f4->x0 = 0;
				poly_f4->y0 = 0;
				poly_f4->x1 = Game_display_width;
				poly_f4->y1 = 0;
				poly_f4->x2 = 0;
				poly_f4->y2 = Game_display_height;
				poly_f4->x3 = Game_display_width;
				poly_f4->y3 = Game_display_height;

				// Next prim
				poly_f4++;
				}

			SetupABRChangeFT3(&Pause_poly2[0], 2);
			SetupABRChangeFT3(&Pause_poly2[1], 2);

			// Set up LOADING bitmap
			texture					= Options_text_textures[OPTION_TEXT_LOADING][Game_language];
//			Sel_loading_sprite_ptr 	= MRCreate2DSprite((Game_display_width >> 1) - (texture->te_w >> 1), (Game_display_height >> 1) - (texture->te_h >> 1), Option_viewport_ptr, texture, NULL);
			Sel_loading_sprite_ptr->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;
			MRChangeSprite(Sel_loading_sprite_ptr,texture);
			Sel_loading_sprite_ptr->sp_pos.x = (Game_display_width >> 1) - (texture->te_w >> 1);
			Sel_loading_sprite_ptr->sp_pos.y = (Game_display_height >> 1) - (texture->te_h >> 1);
			Sel_loading_sprite_ptr->sp_core.sc_ot_offset = 1;

			// Reset time out count
//			Sel_time_out 	= 0;
			Sel_count		= 0;
			Sel_game_mode 	= SEL_GAME_MODE_UPDATE_FADE;

		// Update fade
		case SEL_GAME_MODE_UPDATE_FADE:
			if (++Sel_count <= 0x20)
				{
				// Fade down screen
				poly_f4 = &Pause_poly[MRFrame_index];
				poly_f4->r0 = (Sel_count * 8) - 1;
				poly_f4->g0 = (Sel_count * 8) - 1;
				poly_f4->b0 = (Sel_count * 8) - 1;
				addPrim(Option_viewport_ptr->vp_work_ot + 2, poly_f4);
				addPrim(Option_viewport_ptr->vp_work_ot + 2, &Pause_poly2[MRFrame_index]);

				// Fade up LOADING bitmap
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.r = Sel_count * 4;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.g = Sel_count * 4;
				Sel_loading_sprite_ptr->sp_core.sc_base_colour.b = Sel_count * 4;

				// Move other bitmaps
				Sel_title->sp_pos.y 		-= 8;
				Sel_user_prompt->sp_pos.y 	+= 8;

				// Move level name bitmap
				x = (Game_display_width >> 1) - (Sel_level_title->sp_image_buf[MRFrame_index]->te_w >> 1);
				Sel_level_title->sp_pos.x -= ((Sel_level_title->sp_pos.x - x) / (0x21 - Sel_count));
				}
			else
				{
				poly_f4 = &Pause_poly[MRFrame_index];
				poly_f4->r0 = 0xff;
				poly_f4->g0 = 0xff;
				poly_f4->b0 = 0xff;
				addPrim(Option_viewport_ptr->vp_work_ot + 2, poly_f4);
				addPrim(Option_viewport_ptr->vp_work_ot + 2, &Pause_poly2[MRFrame_index]);

				// Kill loading sprite
//				MRKill2DSprite(Sel_loading_sprite_ptr);

				// Leave now
				Option_page_request = OPTIONS_PAGE_GAME;
				}
			break;

		default:
			break;
		}

	// Update camera frame before continuing
	MRUpdateFrameLWTransform(Sel_camera_frame);

	// Are we in arcade mode ?
	if ( Sel_mode == SEL_MODE_ARCADE )
		{
		// Yes ... initialise GTE
//		rot.vx = -Option_viewport_ptr->vp_render_matrix.t[0];
//		rot.vy = -Option_viewport_ptr->vp_render_matrix.t[1];
//		rot.vz = -Option_viewport_ptr->vp_render_matrix.t[2];
		rot.vx = -Sel_camera_frame->fr_matrix.t[0];
		rot.vy = -Sel_camera_frame->fr_matrix.t[1];
		rot.vz = -Sel_camera_frame->fr_matrix.t[2];
		gte_SetRotMatrix(&Option_viewport_ptr->vp_render_matrix);
		MRApplyRotMatrix(&rot, (MR_VEC*)MRViewtrans_ptr->t);
		gte_SetTransMatrix(MRViewtrans_ptr);
		// Loop once for each position on level select stack
		for(loop_counter=0;loop_counter<10;loop_counter++)
			{
			// Yes ... have we got a gold frog ?
			if ( Gold_frogs & (1<<(loop_counter+1)) )
				{
				// Yes ... display golden frog on level select stack
				level_number = Level_table[loop_counter];
				level_number *= 2;
				gte_ldv3(&Sel_golden_frog_points[level_number+0],&Sel_golden_frog_points[level_number+1],&Sel_golden_frog_points[level_number+2]);
				gte_rtpt();
				gte_stsxy3(&Sel_golden_frog_polys[MRFrame_index][loop_counter].x0,
							&Sel_golden_frog_polys[MRFrame_index][loop_counter].x1,
							&Sel_golden_frog_polys[MRFrame_index][loop_counter].x2);
				gte_ldv0(&Sel_golden_frog_points[level_number+3]);
				gte_rtps();
				gte_stsxy(&Sel_golden_frog_polys[MRFrame_index][loop_counter].x3);
				addPrim(Option_viewport_ptr->vp_work_ot + 3,&Sel_golden_frog_polys[MRFrame_index][loop_counter]);
				}
			}
		}

}

/******************************************************************************
*%%%% SelectUpdateGlowyColours
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdateGlowyColours(MR_VOID)
* 
*	FUNCTION	Updates the colours for the various bits of pizza
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	31.08.97	Kevin Mullard	Created
*
*%%%**************************************************************************/

MR_VOID	SelectUpdateGlowyColours(MR_VOID)
{
	SEL_LEVEL_INFO*	level_ptr;
	MR_LONG			loop_counter;

	// If the camera is not stationary, ensure the direction is getting darker
	if((Sel_camera_flag != SEL_CAMERA_STATIONARY) || 
			(Sel_game_mode == SEL_GAME_MODE_UPDATE_FADE) ||
			(Sel_glowy_col.r > SEL_GLOWY_MAX))
		Sel_glowy_dir = -abs(Sel_glowy_dir);
	else if(Sel_glowy_col.r < SEL_GLOWY_MIN)
			Sel_glowy_dir = +abs(Sel_glowy_dir);

	if((Sel_glowy_col.r >= SEL_DARK_COLOUR) || (Sel_glowy_col.r >= SEL_GLOWY_MIN))
	{
		Sel_glowy_col.r += (MR_BYTE) Sel_glowy_dir;
		Sel_glowy_col.g += (MR_BYTE) Sel_glowy_dir;
		Sel_glowy_col.b += (MR_BYTE) Sel_glowy_dir;
	}

	// Set all poly which are selectable but uncompleted to the glowy colour
	level_ptr = Sel_level_ptr;
	while (level_ptr->li_library_id != -1)
	{
			for (loop_counter = 0; loop_counter < SEL_POLYS_PER_LEVEL_MOF; loop_counter++)
				{
					if ((level_ptr->li_flags & SEL_LF_SELECTABLE)
					 && !(level_ptr->li_flags & SEL_LF_COMPLETED)
					 &&	(Sel_glowy_level_ptr->li_theme_no == level_ptr->li_theme_no))
					{
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.r	= Sel_glowy_col.r;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.g	= Sel_glowy_col.g;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.b	= Sel_glowy_col.b;
					}
					else if (level_ptr->li_flags & SEL_LF_COMPLETED |  !(level_ptr->li_flags & SEL_LF_ZONEACCESSIBLE))
					{
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.r	= SEL_LIGHT_COLOUR;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.g	= SEL_LIGHT_COLOUR;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.b	= SEL_LIGHT_COLOUR;
					}
					else
					{
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.r	= SEL_DARK_COLOUR;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.g	= SEL_DARK_COLOUR;
						level_ptr->li_level_mof->sm_prims[loop_counter].mp_cvec.b	= SEL_DARK_COLOUR;
					}
		}
  		level_ptr++;
	}
}

/******************************************************************************
*%%%% SelectCreateScene
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectCreateScene(MR_VOID)
* 
*	FUNCTION	Creates an environment full of useful things like a camera,
*				and lights...
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	SelectCreateScene(MR_VOID)
{
	MR_VEC		vec_top;
	MR_VEC		vec_cam;
	MR_SVEC		svec;


	// ---------------------------------------- Stack and Spin Frame ------------------------------------------------

	MR_SET_VEC(&vec_top, SEL_STACK_X_POS, 0, SEL_STACK_Z_POS);
	Sel_stack_frame	= MRCreateFrame(&vec_top, &Null_svector, NULL);
	Sel_spin_frame	= MRCreateFrame(&vec_top, &Null_svector, NULL);

	// ----------------------------------------------- Camera -------------------------------------------------------

	// Set our vector to be the position of the camera
	vec_cam.vx = vec_top.vx + SEL_INIT_CAMERA_X;
	vec_cam.vy = vec_top.vy + SEL_INIT_CAMERA_Y;
	vec_cam.vz = vec_top.vz + SEL_INIT_CAMERA_Z;

	// Create the camera at the specified position, but with no rotation
	Sel_camera_frame = MRCreateFrame(&vec_cam, &Null_svector, NULL);

	// Point the camera at the origin of the world. We had to use this routine, because the order of rotation screwed up things.
	MRPointMatrixAtVector(&Sel_camera_frame->fr_matrix, &vec_top, &Game_y_axis_pos);

	// Now we have the camera matrix correctly pointing at the origin of the world (ie the first slice), we 
	// adjust the matrix 't' elements so that the level stack is offset to one side of the screen.
	Sel_camera_frame->fr_matrix.t[0]	+=	SEL_ADJ_CAMERA_X;
	Sel_camera_frame->fr_matrix.t[1]	+=	SEL_ADJ_CAMERA_Y;
	Sel_camera_frame->fr_matrix.t[2]	+=	SEL_ADJ_CAMERA_Z;

	// Keep a hold of the current camera 'Y', because we'll need it later on when moving between levels
	Sel_camera_y_offset = Sel_camera_frame->fr_matrix.t[1];

	// Set viewport camera
	Option_viewport_ptr->vp_camera = Sel_camera_frame;

	// ------------------------------------------ Ambient Light -----------------------------------------------------
	
	Sel_light_object_a	=	MRCreateLight(MR_LIGHT_TYPE_AMBIENT, 0x202020, NULL, MR_OBJ_STATIC);	// 0x202020
	Sel_light_inst_a	=	MRAddObjectToViewport(Sel_light_object_a, Option_viewport_ptr, NULL);

	// --------------------------------------- Directional Light 0 --------------------------------------------------
		
	MR_SET_SVEC(&svec, 0, -0x200, 0);
	Sel_light_frame_0	=	MRCreateFrame(&Null_vector, &svec, NULL);
	Sel_light_object_0	=	MRCreateLight(MR_LIGHT_TYPE_PARALLEL, 0x606060, Sel_light_frame_0, NULL);
	Sel_light_inst_0	=	MRAddObjectToViewport(Sel_light_object_0, Option_viewport_ptr, NULL);

	// --------------------------------------- Directional Light 1 --------------------------------------------------

	MR_SET_SVEC(&svec, 0, 0x200, 0);
	Sel_light_frame_1	=	MRCreateFrame(&Null_vector, &svec, NULL);
	Sel_light_object_1	=	MRCreateLight(MR_LIGHT_TYPE_PARALLEL, 0x404040, Sel_light_frame_1, NULL);
	Sel_light_inst_1	=	MRAddObjectToViewport(Sel_light_object_1, Option_viewport_ptr, NULL);

	// --------------------------------------- Directional Light 2 --------------------------------------------------

	MR_SET_SVEC(&svec, 0, 0, 0);
	Sel_light_frame_2	=	MRCreateFrame(&Null_vector, &svec, NULL);
	Sel_light_object_2	=	MRCreateLight(MR_LIGHT_TYPE_PARALLEL, 0x303030, Sel_light_frame_2, NULL);
	Sel_light_inst_2	=	MRAddObjectToViewport(Sel_light_object_2, Option_viewport_ptr, NULL);
}


/******************************************************************************
*%%%% SelectCreateMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectCreateMOF(SEL_LEVEL_MOF*	mof_ptr,
*										SEL_LEVEL_INFO*	level_ptr);
*
*	FUNCTION	Given the input parameters, this routine creates a SEL_LEVEL_MOF
*				structure (containing all elements needed in the user-creation
*				of a static MOF) at the address pointed to by 'mof_ptr'. It uses
*				the y position to create a unique set of vertices for each model
*				in order to attempt to remove vertex calculation inaccuracies 
*				(and therefore, at least in the initial state, all models created
*				by this routine have a single parent frame). 
*
*				After the model is created, this routine instances the model in
*				the level selection viewport.
*
*	INPUTS		mof_ptr			-		Pointer to an area of memory in which
*										a SEL_LEVEL_MOF structure will be created
*
*				level_ptr		-		Pointer to the level to store info in.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		#ifdef'ed out PSX specific code
*	11.06.97	Gary Richards	Added FALSE to MRWritePrimPart.
*	09.07.97	Dean Ashton		Mutilated.
*
*%%%**************************************************************************/

MR_VOID	SelectCreateMOF(SEL_LEVEL_MOF* mof_ptr, SEL_LEVEL_INFO* level_ptr)
{
	MR_LONG			loop;
	MR_LONG			buffloop, sideloop;
	POLY_FT4*		poly_ptr;
	MR_TEXTURE*		tex_ptr;
	MR_UBYTE		u,v,w,h;
	MR_LONG			y_size;
	MR_LONG			y_position;

 	mof_ptr->sm_mof.mm_length			=	sizeof(SEL_LEVEL_MOF);								// Total length of MOF
	mof_ptr->sm_mof.mm_flags			=	MR_MOF_OFFSETS_RESOLVED |
											MR_MOF_SIZES_RESOLVED |
											MR_MOF_TEXTURES_RESOLVED;							// Flags for MOF
	mof_ptr->sm_mof.mm_extra			=	1;													// 1 model in this MOF
	
	mof_ptr->sm_part.mp_flags			=	NULL;												// No flags
	mof_ptr->sm_part.mp_partcels		=	1;													// Only one MR_PARTCEL
	mof_ptr->sm_part.mp_verts			=	SEL_VERTS_PER_LEVEL_MOF;							// Vertex count
	mof_ptr->sm_part.mp_norms			=	SEL_POLYS_PER_LEVEL_MOF;							// Normal count
	mof_ptr->sm_part.mp_prims			=	SEL_POLYS_PER_LEVEL_MOF;							// Prim count
	mof_ptr->sm_part.mp_hilites			=	0;													// No MR_HILITEs
	mof_ptr->sm_part.mp_partcel_ptr		=	&mof_ptr->sm_partcel;								// Hook to MR_PARTCEL
	mof_ptr->sm_part.mp_prim_ptr		=	(MR_ULONG*)&mof_ptr->sm_prim_header;				// Hook to MR_MPRIM_HEADER
	mof_ptr->sm_part.mp_hilite_ptr		=	NULL;												// No MR_HILITEs (again)
	mof_ptr->sm_part.mp_buff_size		=	sizeof(POLY_FT4) * SEL_POLYS_PER_LEVEL_MOF;			// Size of single buffer of prims
	mof_ptr->sm_part.mp_collprim_ptr	=	NULL;												// No collision primitive
	mof_ptr->sm_part.mp_matrix_ptr		=	NULL;												// No overriding matrices
	mof_ptr->sm_part.mp_pad0			=	0;													// Clear this for safety 
	mof_ptr->sm_part.mp_pad1			=	0;													// And this too...

	mof_ptr->sm_partcel.mp_vert_ptr		=	&mof_ptr->sm_verts[0];								// Point to vertex array
	mof_ptr->sm_partcel.mp_norm_ptr		=	&mof_ptr->sm_norms[0];								// Point to normal array
	mof_ptr->sm_partcel.mp_bbox_ptr		=	(MR_BBOX*)&mof_ptr->sm_verts[0];					// Use vertices as a bounding box
	mof_ptr->sm_partcel.mp_pad0			=	NULL;												// Clear for safety

	mof_ptr->sm_prim_header.mm_type		=	MR_MPRIMID_FT4;										// Only one group of prims, FT4's
	mof_ptr->sm_prim_header.mm_count	=	SEL_POLYS_PER_LEVEL_MOF;							// And there's this many of them.

	// Set y size and y position
	
	if (level_ptr != &Sel_spin_level)
		{
		y_size		= level_ptr->li_y_size;
		y_position	= level_ptr->li_y_position;
		}
	else
		{
		y_size		= 0;
		y_position	= 0;
		}


	// Set vertices for MOF
	MR_SET_SVEC(&mof_ptr->sm_verts[0],	-SEL_BOX_X_SIZE,	(-y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[1],	 SEL_BOX_X_SIZE,	(-y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[2],	-SEL_BOX_X_SIZE,	( y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[3],	 SEL_BOX_X_SIZE,	( y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[4],	-SEL_BOX_X_SIZE,	(-y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[5],	 SEL_BOX_X_SIZE,	(-y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[6],	-SEL_BOX_X_SIZE,	( y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&mof_ptr->sm_verts[7],	 SEL_BOX_X_SIZE,	( y_size)+y_position,	 SEL_BOX_Z_SIZE);

	// Write PlayStation GPU codes (and Ignore the semiTrans Bit).
	MRWritePartPrimCodes(&mof_ptr->sm_part, FALSE);

	// Write data for poly 0	
	MR_SET_SVEC(&mof_ptr->sm_norms[0], 0, 0, 4096);
	mof_ptr->sm_prims[0].mp_p0 = 0;		
	mof_ptr->sm_prims[0].mp_p1 = 1;		
	mof_ptr->sm_prims[0].mp_p2 = 3;		
	mof_ptr->sm_prims[0].mp_p3 = 2;		
	mof_ptr->sm_prims[0].mp_n0 = 0;		
	mof_ptr->sm_prims[0].mp_image_id = 0;
	
	// Write data for poly 1
	MR_SET_SVEC(&mof_ptr->sm_norms[1], 4096, 0, 0);
	mof_ptr->sm_prims[1].mp_p0 = 4;		
	mof_ptr->sm_prims[1].mp_p1 = 0;		
	mof_ptr->sm_prims[1].mp_p2 = 2;		
	mof_ptr->sm_prims[1].mp_p3 = 6;		
	mof_ptr->sm_prims[1].mp_n0 = 1;		
	mof_ptr->sm_prims[1].mp_image_id = 0;

	// Write data for poly 2	
	MR_SET_SVEC(&mof_ptr->sm_norms[2], 0, 0, -4096);
	mof_ptr->sm_prims[2].mp_p0 = 5;		
	mof_ptr->sm_prims[2].mp_p1 = 4;		
	mof_ptr->sm_prims[2].mp_p2 = 6;		
	mof_ptr->sm_prims[2].mp_p3 = 7;		
	mof_ptr->sm_prims[2].mp_n0 = 2;		
	mof_ptr->sm_prims[2].mp_image_id = 0;

	// Write data for poly 3	
	MR_SET_SVEC(&mof_ptr->sm_norms[3], -4096, 0, 0);
	mof_ptr->sm_prims[3].mp_p0 = 1;		
	mof_ptr->sm_prims[3].mp_p1 = 5;		
	mof_ptr->sm_prims[3].mp_p2 = 7;		
	mof_ptr->sm_prims[3].mp_p3 = 3;		
	mof_ptr->sm_prims[3].mp_n0 = 3;		
	mof_ptr->sm_prims[3].mp_image_id = 0;

	// Write data for poly 4	
	MR_SET_SVEC(&mof_ptr->sm_norms[4], 0, 4096, 0);
	mof_ptr->sm_prims[4].mp_p0 = 4;		
	mof_ptr->sm_prims[4].mp_p1 = 5;		
	mof_ptr->sm_prims[4].mp_p2 = 1;		
	mof_ptr->sm_prims[4].mp_p3 = 0;		
	mof_ptr->sm_prims[4].mp_n0 = 4;		
	mof_ptr->sm_prims[4].mp_image_id = 0;
	

	// Write data for poly 5	
	MR_SET_SVEC(&mof_ptr->sm_norms[5], 0, -4096, 0);
	mof_ptr->sm_prims[5].mp_p0 = 6;		
	mof_ptr->sm_prims[5].mp_p1 = 2;		
	mof_ptr->sm_prims[5].mp_p2 = 3;		
	mof_ptr->sm_prims[5].mp_p3 = 7;		
	mof_ptr->sm_prims[5].mp_n0 = 5;		
	mof_ptr->sm_prims[5].mp_image_id = 0;

	// We set all polygons to default brightness for the time being
	for (loop = 0; loop < SEL_POLYS_PER_LEVEL_MOF; loop++)
		{
			if(level_ptr->li_flags & SEL_LF_COMPLETED)
			{
				mof_ptr->sm_prims[loop].mp_cvec.r	= SEL_LIGHT_COLOUR;
				mof_ptr->sm_prims[loop].mp_cvec.g	= SEL_LIGHT_COLOUR;
				mof_ptr->sm_prims[loop].mp_cvec.b	= SEL_LIGHT_COLOUR;
			} else {
				mof_ptr->sm_prims[loop].mp_cvec.r	= SEL_DARK_COLOUR;
				mof_ptr->sm_prims[loop].mp_cvec.g	= SEL_DARK_COLOUR;
				mof_ptr->sm_prims[loop].mp_cvec.b	= SEL_DARK_COLOUR;
			}
  		}
 
	// If we're doing a normal stacked MOF, then calculate world and level pointers... otherwise fix the level
	// pointer to be our active level.
	if (level_ptr != &Sel_spin_level)
		{
		level_ptr->li_frame		=	NULL;
		level_ptr->li_object	=	MRCreateMesh((MR_MOF*)mof_ptr, Sel_stack_frame, NULL, NULL);
		}
	else
		{
		level_ptr->li_frame		=	Sel_spin_frame;
		level_ptr->li_object	=	MRCreateMesh((MR_MOF*)mof_ptr, Sel_spin_frame, NULL, NULL);
		}

	level_ptr->li_level_mof		=	mof_ptr;
	level_ptr->li_mesh_inst		=	MRAddObjectToViewport(level_ptr->li_object, Option_viewport_ptr, NULL);
	level_ptr->li_polys[0]		=	(POLY_FT4*)(level_ptr->li_mesh_inst->mi_prims[0]);
	level_ptr->li_polys[1]		=	(POLY_FT4*)((MR_ULONG)level_ptr->li_polys[0] + (sizeof(POLY_FT4)*SEL_POLYS_PER_LEVEL_MOF));
	level_ptr->li_current_z		=	0;
	level_ptr->li_y_position	=	y_position;

//	if ((level_ptr->li_flags & SEL_LF_SELECTABLE) || (level_ptr == &Sel_spin_level))
//		{
//		level_ptr->li_mesh_inst->mi_light_flags |= 	MR_INST_USE_CUSTOM_AMBIENT;
//		level_ptr->li_mesh_inst->mi_custom_ambient.r = 0x50;
//		level_ptr->li_mesh_inst->mi_custom_ambient.g = 0x50;
//		level_ptr->li_mesh_inst->mi_custom_ambient.b = 0x50;
//		}

	// If this is our 'proper' frame-based MOF, then don't set the the textures yet...
	if (level_ptr == &Sel_spin_level)
		return;

	
	// Point to the appropriate texture for this world/level
	if (level_ptr->li_flags & SEL_LF_ZONEACCESSIBLE)
		tex_ptr = level_ptr->li_world_image_selectable;
	else
		tex_ptr = level_ptr->li_world_image_not_tried;

	w = tex_ptr->te_w;
	u = tex_ptr->te_u0;
	h = ((tex_ptr->te_h) / level_ptr->li_levels_in_world);
	v = tex_ptr->te_v0 + (level_ptr->li_level_within_world * h);

	for (buffloop = 0; buffloop < 2; buffloop++)
		{
		// Point to appropriate polygon set
		poly_ptr = level_ptr->li_polys[buffloop];

		// Loop through side polygons...
		for (sideloop = 0; sideloop < SEL_POLYS_PER_LEVEL_MOF; sideloop++)
			{
			poly_ptr->tpage		=	tex_ptr->te_tpage_id;

#ifdef PSX
			poly_ptr->clut		=	tex_ptr->te_clut_id;
#endif
			if (sideloop < 4)
				{
				poly_ptr->u0	=	u;
				poly_ptr->v0	=	v;
				poly_ptr->u1	=	u + w;
				poly_ptr->v1	=	v;
				poly_ptr->u2	=	u;
				poly_ptr->v2	=	v + h;
				poly_ptr->u3	=	u + w;
				poly_ptr->v3	=	v + h;
				}
			else
				{
				poly_ptr->u0	= tex_ptr->te_u0;		
				poly_ptr->v0	= tex_ptr->te_v0;		
				poly_ptr->u1	= tex_ptr->te_u1;		
				poly_ptr->v1	= tex_ptr->te_v1;		
				poly_ptr->u2	= tex_ptr->te_u2;		
				poly_ptr->v2	= tex_ptr->te_v2;		
				poly_ptr->u3	= tex_ptr->te_u3;		
				poly_ptr->v3	= tex_ptr->te_v3;		
				}
			poly_ptr++;
			}
		}

	// Create a _small_ local OT for each slice.
	level_ptr->li_ot = MRCreateOT(MR_VP_SIZE_4, 13, Sel_stack_frame);

	// We calculate a Z position based on the number of the level within the list.. 
	if (Sel_mode == SEL_MODE_ARCADE)
		level_ptr->li_ot->ot_frame_offset.vz = level_ptr->li_y_position;
	else
		level_ptr->li_ot->ot_frame_offset.vz = level_ptr->li_y_position;

	level_ptr->li_mesh_inst->mi_ot = level_ptr->li_ot;
}


/******************************************************************************
*%%%% SelectUpdate_MODE_SELECTING
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdate_MODE_SELECTING(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SELECTING'
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*	29.07.97	Gary Richards	Added unpack code for packed VLO's.
*
*%%%**************************************************************************/

MR_VOID	SelectUpdate_MODE_SELECTING(MR_VOID)
{
	MR_BOOL			reached_target;
	SEL_LEVEL_INFO*	level_ptr;
	MR_TEXTURE*		texture;

	// Update camera position/acceleration/velocity, and move into matrix
	Sel_camera_vel 	+= Sel_camera_acc;

	if (Sel_camera_vel > SEL_CAMERA_MAX_VEL)
		Sel_camera_vel = SEL_CAMERA_MAX_VEL;

	if (Sel_camera_vel < -SEL_CAMERA_MAX_VEL)
		Sel_camera_vel = -SEL_CAMERA_MAX_VEL;

	Sel_camera_y	+= Sel_camera_vel;

	// Decide whether we've reached our target this frame...
	reached_target = FALSE;	
	if (Sel_camera_flag & SEL_CAMERA_GOING_DOWN)
		{
		if ((Sel_camera_frame->fr_matrix.t[1] <= Sel_target_y) && (Sel_camera_y >= Sel_target_y))
			{
				reached_target = TRUE;		
				Sel_glowy_col.r = SEL_DARK_COLOUR;
				Sel_glowy_col.g = SEL_DARK_COLOUR;
				Sel_glowy_col.b = SEL_DARK_COLOUR;
			}
		}
	else
	if (Sel_camera_flag & SEL_CAMERA_GOING_UP)
		{
		if ((Sel_camera_frame->fr_matrix.t[1] >= Sel_target_y) && (Sel_camera_y <= Sel_target_y))
			{
				reached_target = TRUE;		
				Sel_glowy_col.r = SEL_DARK_COLOUR;
				Sel_glowy_col.g = SEL_DARK_COLOUR;
				Sel_glowy_col.b = SEL_DARK_COLOUR;
			}
		}
	else
	if (Sel_camera_flag == SEL_CAMERA_STATIONARY)
		reached_target = TRUE;

	Sel_camera_frame->fr_matrix.t[1] = Sel_camera_y;

	if (Sel_camera_flag & SEL_CAMERA_STATIONARY)
		{
		if (MR_CHECK_PAD_HELD(Port_id, MRIP_DOWN))	
			{
			// Reset time out
//			Sel_time_out = 0;
			if (SelectFindTarget(SEL_FIND_NEXT) == TRUE)
				{
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
				Sel_camera_flag = SEL_CAMERA_GOING_DOWN;
				Sel_camera_acc	= SEL_CAMERA_ACC;
				reached_target = FALSE;
				}
			else
				{
				// DMA: No target below us.. perhaps a sound effect here?
				// Yes ... play sound
//				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
				}
			}
		else
		if (MR_CHECK_PAD_HELD(Port_id, MRIP_UP))
			{
			// Reset time out
//			Sel_time_out = 0;
			if (SelectFindTarget(SEL_FIND_PREV) == TRUE)
				{
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
				Sel_camera_flag = SEL_CAMERA_GOING_UP;
				Sel_camera_acc	= -SEL_CAMERA_ACC;
				reached_target = FALSE;
				}
			else
				{
				// DMA: No target above us.. perhaps a sound effect here?
				// Yes ... play sound
//				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);
				}
			}
		else
		if	(MR_CHECK_PAD_PRESSED(Port_id, FR_GO))
			{
			// Reset time out
//			Sel_time_out = 0;
			level_ptr = Sel_work_level_ptr;
			if (level_ptr->li_current_z == SEL_LEVEL_SLIDE_DIST)
				{
				// Yes ... play sound
				MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

				// Unpack "world" VLO
				MRAllocPackedResource(Sel_vlo_res_id[level_ptr->li_world_id]);
				// Download "world" VLO
				MRProcessVLO(Sel_vlo_res_id[level_ptr->li_world_id],MR_GET_RESOURCE_ADDR(Sel_vlo_res_id[level_ptr->li_world_id]));	
				// Free space used by packed "world" VLO
				MRFreePackedResource(Sel_vlo_res_id[level_ptr->li_world_id]);

				// DMA: We have selected a fully extended selectable level.. do something here maybe?
				Sel_game_mode = SEL_GAME_MODE_SHOW_LEVEL_INFO;
				SelectEnableSpinMOF(level_ptr);

				// Set correct level name sprite, and turn it on
				MRChangeSprite(Sel_level_title, level_ptr->li_level_name_texture);
				Sel_level_title->sp_core.sc_flags &= ~MR_SPF_NO_DISPLAY;

				// Change and move prompt sprite
				texture	= Options_text_textures[OPTION_TEXT_SELECT2][Game_language];
				MRChangeSprite(Sel_user_prompt, texture);
				Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;

				// Are we in arcade mode ?
				if ( Sel_mode == SEL_MODE_ARCADE )
					{
					// Yes ... build arcade table for display
					HighScoreBuildArcadeTimeTable(level_ptr->li_library_id,3);
					}
				else
					{
					// No ... build race table for display
					HighScoreBuildRaceScoreTable(level_ptr->li_library_id,3);
					}

				// Display first three entries of high score table
				MRBuildText(Sel_score_line[0], Sel_hiscore_text[0], MR_FONT_COLOUR_WHITE);
				MRBuildText(Sel_score_line[1], Sel_hiscore_text[1], MR_FONT_COLOUR_WHITE);
				MRBuildText(Sel_score_line[2], Sel_hiscore_text[2], MR_FONT_COLOUR_WHITE);
				return;
				}
			}
		else
		if ( (Sel_mode == SEL_MODE_RACE) || (Sel_first_time == TRUE) )
			{
			if	(MR_CHECK_PAD_PRESSED(Port_id, FRR_TRIANGLE))
				{
				// Reset time out
//				Sel_time_out = 0;

				// DMA: We're leaving the level selection screen, but we didn't select a level
				//		I suggest you replace the 'OPTIONS_PAGE_EXIT' with an appropriate return page identifier.
				Sel_requested_play	= FALSE;
				Option_page_request = OPTIONS_PAGE_MAIN_OPTIONS;
				}
			}
		}

	if (Sel_camera_flag == SEL_CAMERA_GOING_DOWN)
		{
		if ((!MR_CHECK_PAD_HELD(Port_id, MRIP_DOWN)))
			{
			// Reset time out
//			Sel_time_out = 0;
			Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		else
		if (reached_target == TRUE)
			{
			if (SelectFindTarget(SEL_FIND_NEXT))
				reached_target = FALSE;
			else
				Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}			
		}

	if (Sel_camera_flag == SEL_CAMERA_GOING_UP)
		{
		if ((!MR_CHECK_PAD_HELD(Port_id, MRIP_UP)))
			{
			// Reset time out
//			Sel_time_out = 0;
			Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}
		else
		if (reached_target == TRUE)
			{
			if (SelectFindTarget(SEL_FIND_PREV))
				reached_target = FALSE;
			else
				Sel_camera_flag |= SEL_CAMERA_STOPPING;
			}			
		}

	
	if ((Sel_camera_flag & SEL_CAMERA_STOPPING) && (reached_target == TRUE))
		{
		Sel_camera_acc	= 0;
		Sel_camera_vel	= 0;
		Sel_camera_flag = SEL_CAMERA_STATIONARY;
		Sel_camera_y	= Sel_target_y;
		Sel_camera_frame->fr_matrix.t[1] = Sel_camera_y;
		}

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}


/******************************************************************************
*%%%% SelectUpdateLevelZ
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdateLevelZ(	SEL_LEVEL_INFO*	level_ptr);
*
*	FUNCTION	This function modifies the 'Z' component of all the vertices 
*				used by the requested world/level MOF, so they're offset from
*				the origin of the world by 'level_ptr->li_current_z' units..
*
*	INPUTS		level_ptr		-		Pointer to level we're going to update
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	SelectUpdateLevelZ(SEL_LEVEL_INFO* level_ptr)
{
	level_ptr->li_level_mof->sm_verts[0].vz = (-SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[1].vz = (-SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[2].vz = (-SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[3].vz = (-SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[4].vz = ( SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[5].vz = ( SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[6].vz = ( SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
	level_ptr->li_level_mof->sm_verts[7].vz = ( SEL_BOX_Z_SIZE)+level_ptr->li_current_z;
}


/******************************************************************************
*%%%% SelectUpdateLevelSlide
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdateLevelSlide(MR_VOID)
*
*	FUNCTION	This routine runs through the list of displayed levels, updating
*				the 'Z' of each level based on whether the camera is looking
*				at it.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Changed again for Kev...
*
*%%%**************************************************************************/

MR_VOID	SelectUpdateLevelSlide(MR_VOID)
{
	MR_LONG			viewed_y;
	MR_LONG			max_z;
	SEL_LEVEL_INFO*	level_ptr;

	viewed_y = Sel_camera_frame->fr_matrix.t[1] - Sel_camera_y_offset;
	level_ptr = Sel_level_ptr;
	Sel_glowy_level_ptr = Sel_work_level_ptr;
	max_z = Sel_glowy_level_ptr->li_current_z;

	while (level_ptr->li_library_id != -1)
		{

		if ((viewed_y >= level_ptr->li_y_position - level_ptr->li_y_size) &&
			(viewed_y <= level_ptr->li_y_position + level_ptr->li_y_size))
			{
			level_ptr->li_current_z -= SEL_LEVEL_SLIDE_INC;
			if (level_ptr->li_current_z < SEL_LEVEL_SLIDE_DIST)
				level_ptr->li_current_z = SEL_LEVEL_SLIDE_DIST;									
			}
		else
			{
			level_ptr->li_current_z += SEL_LEVEL_SLIDE_INC;
			if (level_ptr->li_current_z > 0)
				level_ptr->li_current_z = 0;									
			}

		if(level_ptr->li_current_z < max_z)
			Sel_glowy_level_ptr = level_ptr;			// set ptr to further sticking out block

		SelectUpdateLevelZ(level_ptr);
		level_ptr++;
		}
}


/******************************************************************************
*%%%% SelectFindTarget
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	SelectFindTarget(MR_LONG direction);
*
*	FUNCTION	A routine to look for a new target level in a particular 
*				direction. Once found the target Y, world and level are stored
*				in some variables.
*
*	INPUTS		direction		-	Either SEL_FIND_PREV, to look back through
*									the levels starting at our current position
*									or SEL_FIND_NEXT to look forward.
*
*	RESULT		found_target	-	TRUE if we found a new selectable target in
*									the	specified direction, else FALSE
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Dean Ashton		Created
*	08.07.97	Dean Ashton		Modified for Kev...
*
*%%%**************************************************************************/

MR_BOOL	SelectFindTarget(MR_LONG direction)
{
	MR_BOOL			found_target;
	MR_BOOL			finished_read;
	SEL_LEVEL_INFO*	level_ptr;

	found_target 	=	FALSE;
	finished_read	=	FALSE;
	level_ptr 		=	Sel_work_level_ptr;

	while (!(found_target) && (!finished_read))
		{
		if (direction == SEL_FIND_PREV)
			{
			// Look up from current position
			level_ptr--;
			if (level_ptr < Sel_level_ptr)					// Past the start of the table.. 
				{
				finished_read = TRUE;
				continue;
				}
			else
			if (level_ptr->li_flags & SEL_LF_SELECTABLE)
				{
				found_target = TRUE;
				continue;
				}
			}
		else
			{
			// Look down from current position
			level_ptr++;
			if (level_ptr->li_library_id == -1)				// Positioned at terminator in level list
				{
				finished_read = TRUE;
				continue;
				}
			else
			if (level_ptr->li_flags & SEL_LF_SELECTABLE)
				{
				found_target = TRUE;
				continue;
				}
			}
		}

	if (found_target == TRUE)
		{
		Sel_work_level_ptr = level_ptr;
		Sel_target_y = level_ptr->li_y_position + Sel_camera_y_offset;
		}

	return(found_target);
}


/******************************************************************************
*%%%% SelectUpdate_MODE_SHOW_LEVEL_INFO
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdate_MODE_SHOW_LEVEL_INFO(MR_VOID);
*
*	FUNCTION	Performs update when mode is 'SEL_GAME_MODE_SHOW_LEVEL_INFO'
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.97	Dean Ashton		Created
*	22.05.97	Martin Kift		Changed pad press defines to frogger ones.
*
*%%%**************************************************************************/

MR_VOID	SelectUpdate_MODE_SHOW_LEVEL_INFO(MR_VOID)
{
	MR_VEC		local_x;
	MR_VEC		local_y;
	MR_VEC		local_z;
	MR_TEXTURE*	texture;


	if ((Sel_spin_mode == SEL_SPIN_OUT) || (Sel_spin_mode == SEL_SPIN_IN))
		{
		SelectUpdateInterpolation();

		if (Sel_spin_mode == SEL_SPIN_OUT)
			{
			Sel_spin_time++;
			if (Sel_spin_time > Sel_spin_max_time)
				{
				// DMA: You could put a sound here for when the spinning mof is at its 2d-like target position
				//		and all hi-scores are in place.
				Sel_spin_time = Sel_spin_max_time;
				Sel_spin_mode = SEL_SPIN_HOLD;
				}
			}
		else
			{
			Sel_spin_time--;
			if (Sel_spin_time < 0)
				{
				// DMA: You could put a sound here for when the spinning mof has returned to its rest position
				Sel_game_mode = SEL_GAME_MODE_SELECTING;
				SelectDisableSpinMOF();

				// Turn off level name sprite
				Sel_level_title->sp_core.sc_flags |= MR_SPF_NO_DISPLAY;

				// Change and move prompt sprite
				if ( (Sel_mode == SEL_MODE_RACE) || (Sel_first_time == TRUE) )
					{
					texture	= Options_text_textures[OPTION_TEXT_SELECT1][Game_language];
					}
				else
					{
					texture	= Options_text_textures[OPTION_TEXT_SELECT5][Game_language];
					}
				MRChangeSprite(Sel_user_prompt, texture);
				Sel_user_prompt->sp_pos.x = SEL_STATUS_END_X_POS + SEL_STATUS_WIDTH - texture->te_w;
				}				
			}

		// Update spinning levels position
		Sel_spin_frame->fr_matrix.t[0] = Sel_temp_pos.vx;
		Sel_spin_frame->fr_matrix.t[1] = Sel_temp_pos.vy;
		Sel_spin_frame->fr_matrix.t[2] = Sel_temp_pos.vz;

		// Update spinning levels rotation
		MRNormaliseVEC(&Sel_temp_vec_y, &local_y);
		MROuterProduct12(&local_y, &Sel_temp_vec_roll, &local_x);
		MRNormaliseVEC(&local_x, &local_x);
		MROuterProduct12(&local_x, &local_y, &local_z);

		Sel_spin_frame->fr_matrix.m[0][0] = local_x.vx;
		Sel_spin_frame->fr_matrix.m[1][0] = local_x.vy;
		Sel_spin_frame->fr_matrix.m[2][0] = local_x.vz;
	
		Sel_spin_frame->fr_matrix.m[0][1] = local_y.vx;
		Sel_spin_frame->fr_matrix.m[1][1] = local_y.vy;
		Sel_spin_frame->fr_matrix.m[2][1] = local_y.vz;
	
		Sel_spin_frame->fr_matrix.m[0][2] = local_z.vx;
		Sel_spin_frame->fr_matrix.m[1][2] = local_z.vy;
		Sel_spin_frame->fr_matrix.m[2][2] = local_z.vz;

		// Update score/level name positions
		Sel_level_title->sp_pos.x	= Sel_status_temp_x + (SEL_STATUS_WIDTH >> 1) - (Sel_level_title->sp_image_buf[0]->te_w >> 1);

		Sel_score_line[0]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[1]->ta_box_x	= Sel_status_temp_x;
		Sel_score_line[2]->ta_box_x	= Sel_status_temp_x;
		}
	else
	if (MR_CHECK_PAD_PRESSED(Port_id, FRR_TRIANGLE))
		{
		// Reset time out
//		Sel_time_out = 0;

		// DMA: You could add a sound effect here for when we go back to level stack from level information
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_HOP,NULL,0,0);

		// Back to level stack
		Sel_spin_mode = SEL_SPIN_IN;
		}
	else
	if (MR_CHECK_PAD_PRESSED(Port_id, FR_GO))
		{
		// Yes ... play sound
		MRSNDPlaySound(SFX_GEN_FROG_CROAK,NULL,0,0);

		// Reset time out
//		Sel_time_out = 0;
 		Sel_requested_play = TRUE;
		if (Sel_mode == SEL_MODE_ARCADE)
			{
			Sel_arcade_level_ptr = Sel_work_level_ptr;
			}
		else
			{
			Sel_race_level_ptr = Sel_work_level_ptr;
			}

		// DMA: We've selected to play a level.. perhaps we need a sound here?
		// Cause stack to fall away
		Sel_game_mode 	= SEL_GAME_MODE_START_FADE;
		Sel_count 		= 0;

		Sel_first_time = FALSE;

#ifdef WIN95			
		// Network win95 code
//		SendOptionsStartGame(Sel_race_world, Sel_race_level);				
#endif
		}

#ifdef WIN95
	if (MR_KEY_DOWN(MRIK_ESCAPE))
		Option_page_request = OPTIONS_PAGE_EXIT;
#endif
}


/******************************************************************************
*%%%% SelectEnableSpinMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectEnableSpinMOF(SEL_LEVEL_INFO* level_ptr);
*
*	FUNCTION	Initialises the MOF and associated variables required for the
*				spinning of the currently selected level to its appropriate
*				place.
*
*	INPUTS		level_ptr		-		Pointer to currently selected level
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Dean Ashton		Created
*	21.05.97	Martin Kift		#ifdef'ed out PSX specific code
*	08.07.97	Dean Ashton		Changed to copy vertex block from selected 
*								level mof, and use new level info structure.
*
*%%%**************************************************************************/

MR_VOID	SelectEnableSpinMOF(SEL_LEVEL_INFO* level_ptr)
{
	MR_LONG		buffloop, polyloop;
	POLY_FT4*	src_ptr;	
	POLY_FT4*	dest_ptr;
	MR_TEXTURE*	level_image_ptr;
	MR_VEC		target_offset;
	MR_LONG		y_size, y_position;
	MR_LONG		cos, sin;


	// Keep a pointer to the level we're going to spin around
	Sel_spin_backup_ptr = level_ptr;

	// Get a pointer to the level-specific image
	level_image_ptr		= Sel_work_level_ptr->li_level_texture;
	
	// Turn off original level
	level_ptr->li_object->ob_flags |= MR_OBJ_NO_DISPLAY;	
	
	// Patch spin MOF to have correct textures on it

	for (buffloop = 0; buffloop < 2; buffloop++)
		{
		// Point to appropriate polygon set
		src_ptr		= level_ptr->li_polys[buffloop];
		dest_ptr	= Sel_spin_level.li_polys[buffloop];

		// Loop through side polygons...
		for (polyloop = 0; polyloop < SEL_POLYS_PER_LEVEL_MOF; polyloop++)
			{

			if (polyloop < (SEL_POLYS_PER_LEVEL_MOF - 1))
				{
				dest_ptr->tpage		=	src_ptr->tpage;
#ifdef PSX
				dest_ptr->clut		=	src_ptr->clut;
#endif
				dest_ptr->u0		=	src_ptr->u0;
				dest_ptr->v0		=	src_ptr->v0;
				dest_ptr->u1		=	src_ptr->u1;
				dest_ptr->v1		=	src_ptr->v1;
				dest_ptr->u2		=	src_ptr->u2;
				dest_ptr->v2		=	src_ptr->v2;
				dest_ptr->u3		=	src_ptr->u3;
				dest_ptr->v3		=	src_ptr->v3;
			
				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.r = level_ptr->li_level_mof->sm_prims[polyloop].mp_cvec.r;
				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.g = level_ptr->li_level_mof->sm_prims[polyloop].mp_cvec.g;
				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.b = level_ptr->li_level_mof->sm_prims[polyloop].mp_cvec.b;

				}
			else
				{
				dest_ptr->tpage		=	level_image_ptr->te_tpage_id;
#ifdef PSX
				dest_ptr->clut		=	level_image_ptr->te_clut_id;
#endif
				dest_ptr->u0		=	level_image_ptr->te_u2;
				dest_ptr->v0		=	level_image_ptr->te_v2;
				dest_ptr->u1		=	level_image_ptr->te_u0;
				dest_ptr->v1		=	level_image_ptr->te_v0;
				dest_ptr->u2		=	level_image_ptr->te_u3;
				dest_ptr->v2		=	level_image_ptr->te_v3;
				dest_ptr->u3		=	level_image_ptr->te_u1;
				dest_ptr->v3		=	level_image_ptr->te_v1;

				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.r = 0x80;
				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.g = 0x80;
				Sel_spin_level.li_level_mof->sm_prims[polyloop].mp_cvec.b = 0x80;

				}

			src_ptr++;
			dest_ptr++;
			}
		}

	// Set y size and y position (yeah, y_position is always zero, but I wanted to keep the code the same)
	y_size		= level_ptr->li_y_size;
	y_position	= 0;

	// Set vertices for MOF to be that of requested level dimensions
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[0],	-SEL_BOX_X_SIZE,	(-y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[1],	 SEL_BOX_X_SIZE,	(-y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[2],	-SEL_BOX_X_SIZE,	( y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[3],	 SEL_BOX_X_SIZE,	( y_size)+y_position,	-SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[4],	-SEL_BOX_X_SIZE,	(-y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[5],	 SEL_BOX_X_SIZE,	(-y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[6],	-SEL_BOX_X_SIZE,	( y_size)+y_position,	 SEL_BOX_Z_SIZE);
	MR_SET_SVEC(&Sel_spin_level.li_level_mof->sm_verts[7],	 SEL_BOX_X_SIZE,	( y_size)+y_position,	 SEL_BOX_Z_SIZE);
	
	// Position spin MOF, and enable
	Sel_spin_level.li_frame->fr_matrix.t[0] = SEL_STACK_X_POS;
	Sel_spin_level.li_frame->fr_matrix.t[1] = level_ptr->li_y_position;
	Sel_spin_level.li_frame->fr_matrix.t[2] = SEL_STACK_Z_POS + level_ptr->li_current_z;
	Sel_spin_level.li_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;	

	// Calculate start and end position
	MR_SET_VEC(&target_offset, 295, -181, 201);
	target_offset.vz += (level_ptr->li_y_size);

	MRApplyMatrixVEC(&Sel_camera_frame->fr_matrix, &target_offset, &target_offset);

	Sel_start_pos.vx	=	Sel_spin_level.li_frame->fr_matrix.t[0];
	Sel_start_pos.vy	=	Sel_spin_level.li_frame->fr_matrix.t[1];
	Sel_start_pos.vz	=	Sel_spin_level.li_frame->fr_matrix.t[2];

	Sel_end_pos.vx		=	Sel_camera_frame->fr_matrix.t[0] + (Sel_camera_frame->fr_matrix.m[0][2]) + target_offset.vx;	
	Sel_end_pos.vy		=	Sel_camera_frame->fr_matrix.t[1] + (Sel_camera_frame->fr_matrix.m[1][2]) + target_offset.vy;	
	Sel_end_pos.vz		=	Sel_camera_frame->fr_matrix.t[2] + (Sel_camera_frame->fr_matrix.m[2][2]) + target_offset.vz;	
	
	// Calculate start and end vectors
	Sel_start_vec_y.vx	=	0;
	Sel_start_vec_y.vy	=	4096;
	Sel_start_vec_y.vz	=	0;

	Sel_dest_vec_y.vx	=	-(Sel_camera_frame->fr_matrix.m[0][2]);
	Sel_dest_vec_y.vy	=	-(Sel_camera_frame->fr_matrix.m[1][2]);
	Sel_dest_vec_y.vz	=	-(Sel_camera_frame->fr_matrix.m[2][2]);
	cos = rcos(0x40);
	sin = rsin(0x40);
	MRRot_matrix_Y.m[0][0] =  cos;
	MRRot_matrix_Y.m[0][2] =  sin;
	MRRot_matrix_Y.m[2][0] = -sin;
	MRRot_matrix_Y.m[2][2] =  cos;
	MRApplyMatrixSVEC(&MRRot_matrix_Y, &Sel_dest_vec_y, &Sel_dest_vec_y);
	
	Sel_start_vec_roll.vx	=	0;
	Sel_start_vec_roll.vy	=	0;
	Sel_start_vec_roll.vz	=	4096;

	Sel_dest_vec_roll.vx	=	Sel_camera_frame->fr_matrix.m[0][1];
	Sel_dest_vec_roll.vy	=	Sel_camera_frame->fr_matrix.m[1][1];
	Sel_dest_vec_roll.vz	=	Sel_camera_frame->fr_matrix.m[2][1];
	
	// Initialise timers 
	Sel_spin_max_time	=	SEL_SPIN_TIME;
	Sel_spin_time		=	0;
	Sel_spin_mode		=	SEL_SPIN_OUT;

}


/******************************************************************************
*%%%% SelectDisableSpinMOF
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectDisableSpinMOF(MR_VOID)
*
*	FUNCTION	Disables the spinning level MOF, replacing the selected level
*				MOF with one that resides in the level stack
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	SelectDisableSpinMOF(MR_VOID)
{
	// Disable spinning MOF
	Sel_spin_level.li_object->ob_flags |= MR_OBJ_NO_DISPLAY;
	
	// Re-enable original MOF
	Sel_spin_backup_ptr->li_object->ob_flags &= ~MR_OBJ_NO_DISPLAY;	
}


/******************************************************************************
*%%%% SelectUpdateInterpolation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectUpdateInterpolation(MR_VOID)	
*
*	FUNCTION	Given Sel_spin_time, Sel_spin_max_time and a multitude of other
*				variables that require smooth interpolation, this function
*				updates a number of temporary variables.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.05.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	SelectUpdateInterpolation(MR_VOID)
{
	MR_LONG	sin;

	if (Sel_spin_time < (Sel_spin_max_time >> 1))
		{
		sin = -(rsin((((Sel_spin_max_time >> 1) - Sel_spin_time) * 0x800) / Sel_spin_max_time));
		}
	else
		{
		sin = rsin(((Sel_spin_time - (Sel_spin_max_time >> 1)) * 0x800) / Sel_spin_max_time);
		}

	Sel_temp_pos.vx = Sel_start_pos.vx + ((sin + 0x1000) * (Sel_end_pos.vx - Sel_start_pos.vx)) / 0x2000;
	Sel_temp_pos.vy = Sel_start_pos.vy + ((sin + 0x1000) * (Sel_end_pos.vy - Sel_start_pos.vy)) / 0x2000;
	Sel_temp_pos.vz = Sel_start_pos.vz + ((sin + 0x1000) * (Sel_end_pos.vz - Sel_start_pos.vz)) / 0x2000;

	Sel_temp_vec_y.vx = Sel_start_vec_y.vx + ((sin + 0x1000) * (Sel_dest_vec_y.vx - Sel_start_vec_y.vx)) / 0x2000;
	Sel_temp_vec_y.vy = Sel_start_vec_y.vy + ((sin + 0x1000) * (Sel_dest_vec_y.vy - Sel_start_vec_y.vy)) / 0x2000;
	Sel_temp_vec_y.vz = Sel_start_vec_y.vz + ((sin + 0x1000) * (Sel_dest_vec_y.vz - Sel_start_vec_y.vz)) / 0x2000;

	Sel_temp_vec_roll.vx = Sel_start_vec_roll.vx + ((sin + 0x1000) * (Sel_dest_vec_roll.vx - Sel_start_vec_roll.vx)) / 0x2000;
	Sel_temp_vec_roll.vy = Sel_start_vec_roll.vy + ((sin + 0x1000) * (Sel_dest_vec_roll.vy - Sel_start_vec_roll.vy)) / 0x2000;
	Sel_temp_vec_roll.vz = Sel_start_vec_roll.vz + ((sin + 0x1000) * (Sel_dest_vec_roll.vz - Sel_start_vec_roll.vz)) / 0x2000;

	Sel_status_temp_x = Sel_status_start_x + ((sin + 0x1000) * (Sel_status_end_x  - Sel_status_start_x)) / 0x2000;

}


/******************************************************************************
*%%%% SelectLevelCreateBG
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelCreateBG(MR_VOID)	
*
*	FUNCTION	Set up tiled background
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Gary Richards	Created
*	15.08.97	Tim Closs		Changed
*
*%%%**************************************************************************/

MR_VOID	SelectLevelCreateBG(MR_VOID)
{
	MR_LONG		i, j, k;
	MR_TEXTURE*	textures[2];
	MR_TEXTURE*	texture;
	POLY_FT4*	poly_ft4;


	// Pick random textures
	switch (rand() & 3)
		{
		case 0:
			textures[0] = &im_jun_col;
			textures[1] = &im_des_col;
			break;

		case 1:
			textures[0] = &im_cav_col;
			textures[1] = &im_vol_col;
			break;

		case 2:
			textures[0] = &im_sky_col;
			textures[1] = &im_org_col;
			break;

		case 3:
			textures[0] = &im_for_col;
			textures[1] = &im_sub_col;
			break;
		}

	// Calculate number and width of polys
	Select_bg_xnum 		= SELECT_BG_ONSCREEN_TILES_X;
	Select_bg_ynum 		= SELECT_BG_ONSCREEN_TILES_Y;

	Select_bg_xlen 		= (((Game_display_width / 384) + 1) * 384)  / Select_bg_xnum;
	Select_bg_ylen 		= (((Game_display_height / 288) + 1) * 288)  / Select_bg_ynum;

	Select_bg_xnum++;	
	Select_bg_ynum++;	
	i 					= Select_bg_xnum * Select_bg_ynum;
	Select_bg_polys[0] 	= MRAllocMem(i * 2 * sizeof(POLY_FT4), "Select BG polys");
	Select_bg_polys[1] 	= Select_bg_polys[0] + i;

	poly_ft4 = Select_bg_polys[0];
 	for (k = 0; k < 2; k++)
		{
	 	for (j = 0; j < Select_bg_ynum; j++)
			{	
		 	for (i = 0; i < Select_bg_xnum; i++)
				{
				// Get texture
				texture	= textures[(i + j) & 1];
	
				// Set up poly			
				MR_SET32(poly_ft4->r0, 0x202020);
				setPolyFT4(poly_ft4);
				poly_ft4->x0 = (i + 0) * Select_bg_xlen;
				poly_ft4->x1 = (i + 1) * Select_bg_xlen;
				poly_ft4->x2 = (i + 0) * Select_bg_xlen;
				poly_ft4->x3 = (i + 1) * Select_bg_xlen;
				poly_ft4->y0 = (j + 0) * Select_bg_ylen;
				poly_ft4->y1 = (j + 1) * Select_bg_ylen;
				poly_ft4->y2 = (j + 0) * Select_bg_ylen;
				poly_ft4->y3 = (j + 1) * Select_bg_ylen;
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
		}

	// Select a direction
	Select_bg_direction = 0;
	Select_bg_counter	= 0;

	if (rand() & 1)
		Select_bg_direction |= BG_RIGHT;
	else
		Select_bg_direction |= BG_LEFT;

	if (rand() & 1)
		Select_bg_direction |= BG_UP;
	else
		Select_bg_direction |= BG_DOWN;
}


/******************************************************************************
*%%%% SelectLevelUpdateBG
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelUpdateBG(MR_VOID)	
*
*	FUNCTION	Update tiled background
*	MATCH		https://decomp.me/scratch/UiIc1	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Gary Richards	Created
*	15.08.97	Tim Closs		Changed
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	SelectLevelUpdateBG(MR_VOID)
{
	MR_LONG		x, y, i, j;
	POLY_FT4*	poly_ft4;


	if ((HSView_automatic_flag == FALSE))
		{
		if (++Select_bg_counter == SELECT_BG_TILE_MOVE_SPEED)
    		Select_bg_counter = 0;
		}
	else
		Select_bg_counter = SELECT_BG_TILE_MOVE_SPEED>>1;

	if (Select_bg_direction & BG_LEFT)
		x = (Select_bg_counter * Select_bg_xlen) / SELECT_BG_TILE_MOVE_SPEED;
	else
		x = Select_bg_xlen - ((Select_bg_counter * Select_bg_xlen) / SELECT_BG_TILE_MOVE_SPEED);

	if (Select_bg_direction & BG_UP)
		y = (Select_bg_counter * Select_bg_ylen) / SELECT_BG_TILE_MOVE_SPEED;
	else
		y = Select_bg_ylen - ((Select_bg_counter * Select_bg_ylen) / SELECT_BG_TILE_MOVE_SPEED);

	poly_ft4 = Select_bg_polys[MRFrame_index];
 	for (j = 0; j < Select_bg_ynum; j++)
		{	
	 	for (i = 0; i < Select_bg_xnum; i++)
			{
			// Alter xy
			poly_ft4->x0 = ((i + 0) * Select_bg_xlen) - x;
			poly_ft4->x1 = ((i + 1) * Select_bg_xlen) - x;
			poly_ft4->x2 = ((i + 0) * Select_bg_xlen) - x;
			poly_ft4->x3 = ((i + 1) * Select_bg_xlen) - x;
			poly_ft4->y0 = ((j + 0) * Select_bg_ylen) - y;
			poly_ft4->y1 = ((j + 0) * Select_bg_ylen) - y;
			poly_ft4->y2 = ((j + 1) * Select_bg_ylen) - y;
			poly_ft4->y3 = ((j + 1) * Select_bg_ylen) - y;
			addPrim(Option_viewport_ptr->vp_work_ot + Option_viewport_ptr->vp_ot_size - 2, poly_ft4);
			poly_ft4++;
			}
		}	
}

	
/******************************************************************************
*%%%% SelectLevelKillBG
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelKillBG(MR_VOID)	
*
*	FUNCTION	Kill tiled background
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.06.97	Gary Richards	Created
*	15.08.97	Tim Closs		Changed
*
*%%%**************************************************************************/

MR_VOID	SelectLevelKillBG(MR_VOID)
{
	InitialisePrimFree((MR_UBYTE*)Select_bg_polys[0]);
}

/******************************************************************************
*%%%% SelectLevelCollectGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SelectLevelCollectGoldFrog(MR_VOID)	
*
*	FUNCTION	Open first level of next world when a gold frog is collected.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	20.08.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID SelectLevelCollectGoldFrog(MR_VOID)
{

	// Locals
	SEL_LEVEL_INFO*	level_ptr;
	MR_ULONG		theme_id;
	MR_ULONG		level_id;
	MR_BOOL			open_flag;

	// Get pointer to start of level select table
	level_ptr = &Sel_arcade_levels[0];

	// Loop until end of table
	while ( level_ptr->li_library_id != -1 )
	{
		// Store current theme id
		theme_id = level_ptr->li_theme_no;

		// Store id of first level in theme
		level_id = level_ptr->li_library_id;

		// Flag no level as currently open in this theme
		open_flag = FALSE;

		// Loop for each level in this theme
		while ( level_ptr->li_theme_no == theme_id )
			{
			// Is this level selectable ?
			if ( level_ptr->li_flags & SEL_LF_SELECTABLE )
				{
				// Yes ... flag this world as open
				open_flag = TRUE;
				}
			// Next level
			level_ptr++;
			}

		// Is this world closed ?
		if ( open_flag == FALSE )
			{
				// Loop for each level in this theme
				level_ptr = Sel_level_ptr;
				while (level_ptr->li_library_id != -1)
				{
					if(level_ptr->li_theme_no == theme_id)
						SelectSetLevelFlags(level_ptr->li_library_id,	SEL_LF_ZONEACCESSIBLE);
			  		level_ptr++;
				}

				SelectSetLevelFlags(level_id,	SEL_LF_SELECTABLE | SEL_LF_ZONEACCESSIBLE);
				// Leave now
				return;
			}

	}

}

#ifdef WIN95
#pragma warning (default : 4761)
#pragma warning (default : 4245)
#pragma warning (default : 4146)
#endif
