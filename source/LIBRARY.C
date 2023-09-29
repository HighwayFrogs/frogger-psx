/******************************************************************************
*%%%% library.c
*------------------------------------------------------------------------------
*
*	Libraries of books for various subjects
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	14.04.97	Tim Closs		Created
*	06.05.97	Tim Closs		Revised map and theme libraries
*
*%%%**************************************************************************/

#include "library.h"
#include "project.h"
#include "sprdata.h"
#include "entity.h"
#include "formlib.h"
#include "mapdisp.h"

//-----------------------------------------------------------------------------
// Map library
//-----------------------------------------------------------------------------
MAP_BOOK	Map_library[] =
	{
		{
		// CAVES1
		RES_CAV1_MAP,				// MAP to load and resolve
		txl_cav1,					// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cav1.map",
#endif
#endif

#ifdef PSX
		RES_THEME_CAV1_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// CAVES2
		NULL,						// MAP to load and resolve
		NULL,						// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cav2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_CAV_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// CAVES3
		RES_CAV3_MAP,				// MAP to load and resolve
		txl_cav3,					// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cav3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_CAV3_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// CAVES4
		RES_CAV4_MAP,				// MAP to load and resolve
		txl_cav4,					// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cav4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_CAV4_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// CAVES5
		NULL,						// MAP to load and resolve
		txl_cav4,					// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cav5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_CAV4_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// CAVES6 (MULTI-PLAYER)
		NULL,						// MAP to load and resolve
		NULL,						// MAP texture list
		MAP_BOOK_FLAG_CAVE_LIGHT,	// Use special cave lighting
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\caves\\cavm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_CAV_WAD,			// model WAD to load
#else
		RES_THEME_CAV_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT1
		RES_DES1_MAP,				// MAP to load and resolve
		txl_des1,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\des1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES1_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT2
		RES_DES2_MAP,				// MAP to load and resolve
		txl_des2,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\des2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES2_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT3
		RES_DES3_MAP,				// MAP to load and resolve
		txl_des3,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\des3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES3_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT4
		RES_DES4_MAP,				// MAP to load and resolve
		txl_des4,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\des4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES4_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT5
		RES_DES5_MAP,				// MAP to load and resolve
		txl_des5,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\des5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES5_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// DESERT6 (MULTI-PLAYER)
		NULL,						// MAP to load and resolve
		NULL,						// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\desert\\desm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_DES_WAD,			// model WAD to load
#else
		RES_THEME_DES_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST1
		RES_FOR1_MAP,				// MAP to load and resolve
		txl_for1,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\for1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FOR1_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST2
		RES_FOR2_MAP,				// MAP to load and resolve
		txl_for2,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\for2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FOR2_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST3
		NULL,						// MAP to load and resolve
		txl_for3,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\for3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FOR2_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST4
		NULL,								// MAP to load and resolve
		NULL,//txl_for4,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\for4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FOR2_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST5
		NULL,								// MAP to load and resolve
		NULL,//txl_for5,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\for5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FOR2_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// FOREST6
		RES_FORM_MAP,				// MAP to load and resolve
		txl_form,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\forest\\form.map",
#endif
#endif
#ifdef PSX
		RES_THEME_FORM_WAD,			// model WAD to load
#else
		RES_THEME_FOR_WAD,			// model WAD to load
#endif
		},
		{
		// JUNGLE1
		RES_JUN1_MAP,				// MAP to load and resolve
		txl_jun1,					// MAP texture list
		0,							// flags
		&im_jun_floor1,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\jun1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_JUN1_WAD,			// model WAD to load
#else
		RES_THEME_JUN_WAD,			// model WAD to load
#endif
		},
		{
		// JUNGLE2
		RES_JUN2_MAP,				// MAP to load and resolve
		txl_jun2,					// MAP texture list
		0,							// flags
		&im_jun_floor1,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\jun2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_JUN2_WAD,			// model WAD to load
#else
		RES_THEME_JUN_WAD,			// model WAD to load
#endif
		},
		{
		// JUNGLE3
		NULL,						// MAP to load and resolve
		NULL,//txl_jun3,			// MAP texture list
		0,							// flags
		&im_jun_floor1,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\jun3.map",
#endif
#endif
		RES_THEME_JUN_WAD,
		},
		{
		// JUNGLE4
		NULL,								// MAP to load and resolve
		NULL,//txl_jun4,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\jun4.map",
#endif
#endif
		RES_THEME_JUN_WAD,
		},
		{
		// JUNGLE5
		NULL,								// MAP to load and resolve
		NULL,//txl_jun5,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\jun5.map",
#endif
#endif
		RES_THEME_JUN_WAD,
		},
		{
		// JUNGLE6 (MULTI-PLAYER)
		RES_JUNM_MAP,				// MAP to load and resolve
		txl_junm,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\jungle\\junm.map",
#endif
#endif
		RES_THEME_JUNM_WAD,			// model WAD to load
		},
		{
		// ORIGINAL1
		RES_ORG1_MAP,				// MAP to load and resolve
		txl_org1,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\org1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORG1_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		// ORIGINAL2
		RES_ORG2_MAP,				// MAP to load and resolve
		txl_org2,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\org2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORG2_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		// ORIGINAL3
		RES_ORG3_MAP,				// MAP to load and resolve
		txl_org3,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\org3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORG3_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		// ORIGINAL4
		RES_ORG4_MAP,				// MAP to load and resolve
		txl_org4,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\org4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORG4_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		// ORIGINAL5
		RES_ORG5_MAP,				// MAP to load and resolve
		txl_org5,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\org5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORG5_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		// ORIGINAL6 (MULTI-PLAYER)
		RES_ORGM_MAP,				// MAP to load and resolve
		txl_orgm,					// MAP texture list
		0,							// flags
		&im_org_env_sky,			// env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\original\\orgm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_ORGM_WAD,			// model WAD to load
#else
		RES_THEME_ORG_WAD,			// model WAD to load
#endif
		},
		{
		0,
		// RUINS1
//		NULL,						// MAP to load and resolve
//		NULL,						// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arn1.map",
//#endif
//#endif
//		NULL,
		},
		{
		0,
		// RUINS2
//		NULL,								// MAP to load and resolve
//		NULL,//txl_arn2,					// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arn2.map",
//#endif
//#endif
//		NULL,
		},
		{
		0,
		// RUINS3
//		NULL,								// MAP to load and resolve
//		NULL,//txl_arn3,					// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arn3.map",
//#endif
//#endif
//		NULL,
		},
		{
		0,
		// RUINS4
//		NULL,								// MAP to load and resolve
//		NULL,//txl_arn4,					// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arn4.map",
//#endif
//#endif
//		NULL,
		},
		{
		0,
		// RUINS5
//		NULL,								// MAP to load and resolve
//		NULL,//txl_arn5,					// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arn5.map",
//#endif
//#endif
//		NULL,
		},
		{
		0,
//		// RUINS6 (MULTI-PLAYER)
//		NULL,						// MAP to load and resolve
//		NULL,						// MAP texture list
//		0,							// flags
//		NULL,						// no env map
//#ifdef MR_DEBUG
//#ifdef WIN95
//		"maps\\ruins\\arnm.map",
//#endif
//#endif
//		RES_THEME_ARNM_WAD,			// model WAD to load
		},
		{
		// SWAMP1
		RES_SWP1_MAP,				// MAP to load and resolve
		txl_swp1,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swp1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP1_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SWAMP2
		RES_SWP2_MAP,				// MAP to load and resolve
		txl_swp2,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swp2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP2_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SWAMP3
		RES_SWP3_MAP,				// MAP to load and resolve
		txl_swp3,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swp3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP3_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SWAMP4
		RES_SWP4_MAP,				// MAP to load and resolve
		txl_swp4,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swp4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP4_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SWAMP5
		RES_SWP5_MAP,				// MAP to load and resolve
		txl_swp5,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swp5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP5_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SWAMP6 (MULTI-PLAYER)
		NULL,						// MAP to load and resolve
		NULL,						// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\swamp\\swpm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SWP_WAD,			// model WAD to load
#else
		RES_THEME_SWP_WAD,			// model WAD to load
#endif
		},
		{
		// SKY1
		RES_SKY1_MAP,				// MAP to load and resolve
		txl_sky1,					// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\sky1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SKY1_WAD,			// model WAD to load
#else
		RES_THEME_SKY_WAD,			// model WAD to load
#endif
		},
		{
		// SKY2
		RES_SKY2_MAP,				// MAP to load and resolve
		txl_sky2,					// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\sky2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SKY2_WAD,			// model WAD to load
#else
		RES_THEME_SKY_WAD,			// model WAD to load
#endif
		},
		{
		// SKY3
		RES_SKY3_MAP,				// MAP to load and resolve
		txl_sky3,					// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\sky3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SKY3_WAD,			// model WAD to load
#else
		RES_THEME_SKY_WAD,			// model WAD to load
#endif
		},
		{
		// SKY4
		RES_SKY4_MAP,				// MAP to load and resolve
		txl_sky4,					// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\sky4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SKY4_WAD,			// model WAD to load
#else
		RES_THEME_SKY_WAD,			// model WAD to load
#endif
		},
		{
		// SKY5
		NULL,								// MAP to load and resolve
		NULL,//txl_sky5,					// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\sky5.map",
#endif
#endif
		RES_THEME_SKY_WAD,
		},
		{
		// SKY6 (MULTI-PLAYER)
		NULL,						// MAP to load and resolve
		NULL,						// MAP texture list
		0,							// flags
		&im_sky_balloon_env,		// sky env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\sky\\skym.map",
#endif
#endif
		RES_THEME_SKY_WAD,			// model WAD to load
		},
		{
		// SUBURBIA1
		RES_SUB1_MAP,				// MAP to load and resolve
		txl_sub1,					// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\sub1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUB1_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// SUBURBIA2
		RES_SUB2_MAP,				// MAP to load and resolve
		txl_sub2,					// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\sub2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUB2_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// SUBURBIA3
		RES_SUB3_MAP,				// MAP to load and resolve
		txl_sub3,					// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\sub3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUB3_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// SUBURBIA4
		RES_SUB4_MAP,				// MAP to load and resolve
		txl_sub4,				// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\sub4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUB4_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// SUBURBIA5
		RES_SUB5_MAP,				// MAP to load and resolve
		txl_sub5,					// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\sub5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUB5_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// SUBURBIA6 (MULTI-PLAYER)
		RES_SUBM_MAP,				// MAP to load and resolve
		txl_subm,					// MAP texture list
		0,							// flags
		&im_sub_env_sky,			// Env bitmap
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\suburbia\\subm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_SUBM_WAD,			// model WAD to load
#else
		RES_THEME_SUB_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO1
		RES_VOL1_MAP,				// MAP to load and resolve
		txl_vol1,					// MAP texture list
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\vol1.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOL1_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO2
		RES_VOL2_MAP,				// MAP to load and resolve
		txl_vol2,					// MAP texture list
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\vol2.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOL2_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO3
		RES_VOL3_MAP,				// MAP to load and resolve
		txl_vol3,					// MAP texture list
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\vol3.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOL3_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO4
		NULL,						// MAP to load and resolve
		txl_vol3,					// MAP texture list (NOT USED IN GAME ANYMORE)
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\vol4.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOL3_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO5
		NULL,								// MAP to load and resolve
		NULL,//txl_vol5,					// MAP texture list
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\vol5.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOL3_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},
		{
		// VOLCANO6 (MULTI-PLAYER)
		RES_VOLM_MAP,				// MAP to load and resolve
		txl_volm,					// MAP texture list
		0,							// flags
		&im_vol_tile51,				// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\volcano\\volm.map",
#endif
#endif
#ifdef PSX
		RES_THEME_VOLM_WAD,			// model WAD to load
#else
		RES_THEME_VOL_WAD,			// model WAD to load
#endif
		},

#ifdef MR_DEBUG
		// This is a test map
		{
		// ISLAND
		0, //$km RES_ISLAND_MAP,				// MAP to load and resolve
		0, //$km txl_island,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\test\\island.map",
#endif
#endif
		},
		// This is a test map
		{
		// QB
		0, //$km RES_QB_MAP,					// MAP to load and resolve
		0, //$km txl_island,					// MAP texture list
		0,							// flags
		NULL,						// no env map
#ifdef MR_DEBUG
#ifdef WIN95
		"maps\\test\\qb.map",
#endif
#endif
		},
#endif
};

//-----------------------------------------------------------------------------
// Theme library
//-----------------------------------------------------------------------------
THEME_BOOK	Theme_library[] =
	{
		{
		// THEME_GEN
		RES_THEME_GEN_WAD,			// model WAD to load
		Form_library_gen,			// form library
		RES_GEN_VRAM_VLO,			// VLO to load
		0x100,
		RES_THEME_GENM_WAD,			// WAD to load (Multi-player)
		RES_GENM_RAM_VLO,			// VLO to load (Multi-player)
		},
		{
		// THEME_CAV
		RES_THEME_CAV_WAD,			// model WAD to load
		Form_library_cav,			// form library
		RES_CAV_VRAM_VLO,			// VLO to load
		0x1000,
		NULL,						// These are level specific.
		NULL,						// VLO to load (Multi-player)
		},
		{
		// THEME_DES
		RES_THEME_DES_WAD,			// model WAD to load
		Form_library_des,			// form library
		RES_DES_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		NULL,						// VLO to load (Multi-player)
		},
		{
		// THEME_FOR
		RES_THEME_FOR_WAD,			// model WAD to load
		Form_library_for,			// form library
		RES_FOR_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		RES_FORM_RAM_VLO,			// VLO to load (Multi-player)
		},
		{
		// THEME_JUN
		RES_THEME_JUN_WAD,			// model WAD to load
		Form_library_jun,			// form library
		RES_JUN_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		RES_JUNM_RAM_VLO,			// VLO to load (Multi-player)
		},
		{
		// THEME_ORG
		RES_THEME_ORG_WAD,			// model WAD to load
		Form_library_org,			// form library
		RES_ORG_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		RES_ORGM_RAM_VLO,			// VLO to load (Multi-player)
		},
		{
		0,
//		// THEME_ARN
//		RES_THEME_ARN_WAD,			// model WAD to load
//		Form_library_arn,			// form library
//		RES_ARN_VRAM_VLO,			// VLO to load
//		0x100,
//		NULL,						// These are level specific
//		NULL,						// VLO to load (Multi-player)
		},
		{
		// THEME_SWP
		RES_THEME_SWP_WAD,			// model WAD to load
		Form_library_swp,			// form library
		RES_SWP_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		NULL,						// VLO to load (Multi-player)
		},
		{
		// THEME_SKY
		RES_THEME_SKY_WAD,			// model WAD to load
		Form_library_sky,			// form library
		RES_SKY_VRAM_VLO,			// VLO to load
		SKY_LAND_HEIGHT << 1,
		NULL,						// These are level specific
		NULL,						// VLO to load (Multi-player)
		},
		{
		// THEME_SUB
		RES_THEME_SUB_WAD,			// model WAD to load
		Form_library_sub,			// form library
		RES_SUB_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		RES_SUBM_RAM_VLO,			// VLO to load (Multi-player)
		},
		{
		// THEME_VOL
		RES_THEME_VOL_WAD,			// model WAD to load
		Form_library_vol,			// form library
		RES_VOL_VRAM_VLO,			// VLO to load
		0x100,
		NULL,						// These are level specific
		RES_VOLM_RAM_VLO,			// VLO to load (Multi-player)
		},
	};	
