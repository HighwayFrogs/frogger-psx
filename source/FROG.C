/******************************************************************************
*%%%% FROG.C
*------------------------------------------------------------------------------
*
*	Manages frogs / player characters.
*	This file seems to have been corrupted in the source backup.
*	As such, it needed to be recreated. The code functions in this file were decomped to match PSX Build 50/50b (both share the same executable).
*	Many Thanks to Sonic Dreamcaster who helped extensively with setup.
*	Many Thanks to Ethan & Everyone who has contributed to decomp.me. It really sped this process up big time.
*	Many Thanks to mono21400/Mc-muffin, pixel-stuck, petrie911, and potentially others who helped match some of the more tricky functions.
*
*	Decomp Settings:
*	 - Compiler: "PSYQ3.5 (gcc 2.6.0 + aspsx 2.34)", Compiler Flags: "-O3"
*	 - Compiler: "gcc 2.6.3-psx + masmpsx", Compiler Flags: "-O3 -G0 -gcoff" (This is better than "gcc 2.6.3 + masmpsx" as seen in the InitialiseFrogs() function.
*	 - Compiler: "gcc 2.6.3 + masmpsx", Compiler Flags: "-O3 -G0 -gcoff"
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	02.04.19	Kneesnap		Started to rebuild.
*	02.05.22	Kneesnap		Fixed many inaccuracies in the recreation.
*	10.09.23	Kneesnap		Perfectly byte-matched all functions to PSX build 50 using decomp tools (& help from others credited above).
*
*%%%**************************************************************************/

#include "camera.h"
#include "collide.h"
#include "entlib.h"
#include "ent_cav.h"
#include "ent_gen.h"
#include "entity.h"
#include "form.h"
#include "frog.h"
#include "froguser.h"
#include "gen_frog.h"
#include "grid.h"
#include "hsview.h"
#include "mapdisp.h"
#include "mapview.h"
#include "model.h"
#include "particle.h"
#include "playxa.h"
#include "score.h"
#include "select.h"
#include "sound.h"
#include "system.h"
#include "tempopt.h"
#include "xalist.h"

MR_MAT Frog_splash_matrix;

// This is the only function in this file not declared in FROG.H
MR_ULONG TestFrogHasLineOfSight(FROG* frog, LIVE_ENTITY* entity);

FROG Frogs[4];

MR_ULONG Frog_current_control_methods[] = {0, 0, 0, 0}; // Proper start values.

// Correct mappings.
FROG_CONTROL_METHOD Frog_control_methods[] = {
	{
		FR_UP, // up
		FR_RIGHT, // right
		FR_DOWN, // down
		FR_LEFT, // left
	
		FRR_LEFT_2, // Clock-wise control.
		FRR_RIGHT_2, // Counter-clockwise control.
		
		FRR_SQUARE, // Tongue.
		FRR_CROSS, // Super-jump.
		FRR_TRIANGLE, // Repeat.
		FRR_CIRCLE, // Croak.
	},
	{
		FR_UP, // up
		FR_RIGHT, // right
		FR_DOWN, // down
		FR_LEFT, // left
		
		FRR_LEFT_2, // Clock-wise control.
		FRR_RIGHT_2, // Counter-clockwise control.
		
		FRR_LEFT_1 | FRR_RIGHT_1, // Tongue.
		FRR_SQUARE | FRR_CROSS, // Super-jump.
		FRR_TRIANGLE, // Repeat.
		FRR_CIRCLE, // Croak.
	},
	{
		FR_UP, // up
		FR_RIGHT, // right
		FR_DOWN, // down
		FR_LEFT, // left
		
		FRR_LEFT_2, // Clock-wise control.
		FRR_RIGHT_2, // Counter-clockwise control.
		
		FRR_TRIANGLE, // Tongue.
		FRR_CIRCLE, // Super-jump.
		FRR_SQUARE, // Repeat.
		FRR_CROSS, // Croak.
	},
	{
		FR_UP, // up
		FR_RIGHT, // right
		FR_DOWN, // down
		FR_LEFT, // left
		
		FRR_LEFT_2, // Clock-wise control.
		FRR_RIGHT_2, // Counter-clockwise control.
		
		FRR_CROSS, // Tongue.
		FRR_CIRCLE | FRR_SQUARE, // Super-jump.
		FRR_TRIANGLE, // Repeat.
		FRR_LEFT_1 | FRR_RIGHT_1, // Croak.
	}
};

MR_VEC				Frog_fixed_vectors[] = { // Correct values.
	{0, 0, 0x1000},
	{0x1000, 0, 0},
	{0, 0, 0xFFFFF000},
	{0xFFFFF000, 0, 0}
};

MR_LONG				Frog_input_ports[] = {MR_INPUT_PORT_0_0, MR_INPUT_PORT_1_0, MR_INPUT_PORT_0_2, MR_INPUT_PORT_0_3}; // Correct values.

FROG_PLAYER_DATA	Frog_player_data[4];
MR_BOOL	Frog_cave_light_special = FALSE; // If the fullbright bug effect is active.

MR_SVEC Frog_trail_offsets[] = {
	{0x0000, 0xFFC0, 0x0040},
	{0xFFC0, 0xFFF0, 0xFFE0},
	{0x0040, 0xFFF0, 0xFFE0}
};

MR_SVEC Frog_shadow_offsets1[] = {
	{0xFFA0, 0x0000, 0x0070},
	{0x0060, 0x0000, 0x0070},
	{0xFFA0, 0x0000, 0xFFA0},
	{0x0060, 0x0000, 0xFFA0}
};
MR_SVEC Frog_shadow_offsets2[] = {
	{0xFFA0, 0x0000, 0x0090},
	{0x0060, 0x0000, 0x0090},
	{0xFFA0, 0x0000, 0xFFA0},
	{0x0060, 0x0000, 0xFFA0}
};

MR_SVEC Frog_shadow_offsets3[] = {
	{0xFFA0, 0x0000, 0x00B0},
	{0x0060, 0x0000, 0x00B0},
	{0xFFA0, 0x0000, 0xFF80},
	{0x0060, 0x0000, 0xFF80}
};

MR_SVEC Frog_shadow_offsets4[] = {
	{0xFFA0, 0x0000, 0x00D0},
	{0x0060, 0x0000, 0x00D0},
	{0xFFA0, 0x0000, 0xFF50},
	{0x0060, 0x0000, 0xFF50}
};

MR_SVEC*			Frog_jump_shadow_offsets[] = {
	&Frog_shadow_offsets1[0],
	&Frog_shadow_offsets2[0],
	&Frog_shadow_offsets3[0],
	&Frog_shadow_offsets4[0],
	&Frog_shadow_offsets3[0],
	&Frog_shadow_offsets2[0]
};

MR_TEXTURE*			Frog_jump_shadow_textures[] = {
	&im_frog_shadow0,
	&im_frog_shadow1,
	&im_frog_shadow2,
	&im_frog_shadow2,
	&im_frog_shadow2,
	&im_frog_shadow1
};

MR_VOID (*Frog_controller_hooks[])(FROG*, MR_ULONG) =
	{
	FrogModeControlStationary,
	FrogModeControlJumping,
	NULL,
	NULL,
	NULL,
	FrogModeControlStationary,
	NULL,
	FrogModeControlStationary,
	NULL
	};
	
MR_ULONG (*Frog_movement_hooks[])(FROG*, MR_ULONG, MR_ULONG*) =
	{
	FrogModeMovementStationary,
	FrogModeMovementJumping,
	FrogModeMovementDying,
	FrogModeMovementStationary,
	FrogModeMovementHitCheckpoint,
	FrogModeMovementCentring,
	FrogModeMovementStunned,
	NULL
	};

#ifdef WIN95
MR_ULONG Frog_local_id = 0;				
FROG* Frog_local_ptr = NULL;
#endif

/******************************************************************************
*%%%% InitialiseFrogs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseFrogs(MR_VOID)
*
*	FUNCTION	Sets up a frog for each of the players in Game_total_players.
*	MATCH		https://decomp.me/scratch/8dWVD (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID	InitialiseFrogs(MR_VOID) {
	MR_ULONG frog_id;
	MR_ULONG x_face;
	MR_ULONG z_face;

    x_face = 0;
    z_face = 0;
    switch (Map_general_header->gh_rotation) {
        case FROG_DIRECTION_N:
            z_face = 0;
            x_face = -1;
            break;
        case FROG_DIRECTION_E:
            z_face = 1;
            x_face = 0;
            break;
        case FROG_DIRECTION_S:
            z_face = 0;
            x_face = 1;
            break;
        case FROG_DIRECTION_W:
            x_face = 0;
            z_face = -1;
            break;
        default:
            x_face = 1;
            z_face = 0;
            break;
	}
	
	MRReadInput();
	for (frog_id = 0; frog_id < Game_total_players; frog_id++) {
		CreateFrog(frog_id, Frog_player_data[frog_id].fp_port_id, (MR_ULONG) (Map_general_header->gh_start_x) + (frog_id * x_face), (MR_ULONG)(Map_general_header->gh_start_z) + (frog_id * z_face));
		UpdateFrogCameraZone(&Frogs[frog_id]);
	}
	
	UpdateFrogAnimationScripts();
}

/******************************************************************************
*%%%% CreateFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FROG*	CreateFrog(
*							MR_ULONG	frog_id,
*							MR_ULONG		input,
*							MR_ULONG		startX,
*							MR_ULONG		startZ)
*
*	FUNCTION	Creates a frog representation for the provided player at the provided position
*	MATCH		https://decomp.me/scratch/akXaF (By Kneesnap & Anon)
*				https://decomp.me/scratch/HzhTp (By Kneesnap)
*
*	INPUTS		frog_id		-	The id (between 0 and 3) of the frog to create.
*				input		-	The index into the Frog_current_control_methods array.
*				startX		-	The x grid position to create the frog at
*				startZ		-	The z grid position to create the frog at
*
*	RESULT		frog		-	a pointer to the newly created FROG
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

FROG* CreateFrog(MR_ULONG frog_id, MR_ULONG input, MR_ULONG startX, MR_ULONG startZ) {
    EFFECT* shadow;
    EFFECT* tongue;
    EFFECT* trail;
    FROG* frog;
    MR_OT** ot;
    MR_LONG i;
    MR_MOF* model;

    frog = &Frogs[frog_id];
    frog->fr_input_id = input;
    frog->fr_control_method = &Frog_control_methods[Frog_current_control_methods[frog_id]];
    frog->fr_lwtrans = &frog->fr_matrix;
    frog->fr_voice_id = -1;
    frog->fr_current_sfx = -1;
    frog->fr_frog_id = frog_id;
    
    if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS) { // Use high-poly frogs.
        model = Model_MOF_ptrs[Frog_player_data[frog_id].fp_player_id + MODEL_MOF_FROG_CONSTRUCTION_0];
        frog->fr_api_item = MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*) model, 0, MR_OBJ_STATIC, (MR_FRAME*) frog->fr_lwtrans);
        MRAnimEnvSingleCreateLWTransforms(frog->fr_api_item);
        MR_INIT_MAT(&frog->fr_croak_scale_matrix);
        MRAnimEnvSingleSetPartFlags(frog->fr_api_item, THROAT, MR_ANIM_PART_TRANSFORM_PART_SPACE);
        MRAnimEnvSingleSetImportedTransform((MR_ANIM_ENV*) frog->fr_api_item, THROAT, &frog->fr_croak_scale_matrix);
		((MR_ANIM_ENV*) frog->fr_api_item)->ae_special_flags |= MR_ANIM_ENV_DISPLAY_LIMITED_PARTS;
        MRAnimEnvSingleClearPartFlags((MR_ANIM_ENV*) frog->fr_api_item, THROAT, MR_ANIM_PART_DISPLAY);
    } else { // Use low poly frogs.
        model = Model_MOF_ptrs[Frog_player_data[frog_id].fp_player_id + MODEL_MOF_FROG_FLIPBOOK_0];
        frog->fr_api_item = MRAnimEnvFlipbookCreateWhole(model, MR_OBJ_STATIC, (MR_FRAME*) frog->fr_lwtrans);
        MRAnimEnvFlipbookSetAction(frog->fr_api_item, 0);
        MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*) frog->fr_api_item, 0);
        ((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;
        ((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags &= ~MR_ANIM_ENV_STEP;
    }

    // Setup default ani
    FrogInitialiseAnimation(frog, FROG_ANIMATION_PANT, 0);

    // Create OTs.
    ot = frog->fr_ot;
    i = Game_total_viewports;
    while (i--) {
        *ot = MRCreateOT(7, 2, (MR_FRAME* ) frog->fr_lwtrans);
        (*ot++)->ot_global_ot_offset = FROG_GLOBAL_OT_OFFSET;
    }

    // Register OTs
    GameAddAnimEnvToViewportsStoreInstances((MR_ANIM_ENV*)frog->fr_api_item, (MR_ANIM_ENV_INST**)frog->fr_api_insts);

    // Set OTs on frog mesh instances.
    ot = frog->fr_ot;
    for (i = 0; i < Game_total_viewports; i++)
        ((MR_ANIM_ENV_INST*)frog->fr_api_insts[i])->ae_mesh_insts[0]->mi_ot = *ot++;

    // Set frog position as a moving sound target.
    MRSNDSetMovingSoundTarget(0, (MR_VEC*) &frog->fr_lwtrans->t, (MR_VEC*) &frog->fr_lwtrans->t, frog->fr_lwtrans);

    // Creates a shadow effect.
    shadow = CreateShadow(*Frog_jump_shadow_textures, frog->fr_lwtrans, *Frog_jump_shadow_offsets);
    frog->fr_shadow = shadow;
    shadow->ef_flags &= ~EFFECT_KILL_WHEN_FINISHED;
    for (i = 0; i < Game_total_viewports; i++)
        (((SHADOW*)frog->fr_shadow->ef_extra)->sh_ot_ptr[i]) = (MR_OT*) frog->fr_ot[i];

    // Create the frog's tongue.
    tongue = CreateTongue(frog->fr_lwtrans, frog);
    frog->fr_tongue = tongue;
    tongue->ef_flags = (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE);

    // Create the movement trail effect.
    trail = CreateTrail(frog->fr_lwtrans, &Frog_trail_offsets[1], 6);
    frog->fr_trail = trail;
    trail->ef_flags &= ~EFFECT_KILL_WHEN_FINISHED;
    for (i = 0; i < Game_total_viewports; i++)
        ((TRAIL*) frog->fr_trail->ef_extra)->tr_ot_ptr[i] = NULL;

    // Setup misc 
    frog->fr_particle_api_item = NULL;
    frog->fr_scale = 0x1000; // 1.0 aka (1 << 12)

    // Setup Poly Piece Pop
    if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS) {
        frog->fr_poly_piece_pop = MRAllocMem(sizeof(POLY_PIECE_POP) + (Frog_model_pieces_polys * sizeof(POLY_PIECE_DYNAMIC)), "FROG POLY PIECE POP");
        frog->fr_poly_piece_pop->pp_mof = Model_MOF_ptrs[Frog_player_data[frog_id].fp_player_id + MODEL_MOF_FROG_FLIPBOOK_0];
        frog->fr_poly_piece_pop->pp_numpolys = Frog_model_pieces_polys;
        frog->fr_poly_piece_pop->pp_timer = 0;
        frog->fr_poly_piece_pop->pp_lwtrans = frog->fr_lwtrans;
        frog->fr_poly_piece_pop->pp_poly_pieces = Frog_model_pieces;
        frog->fr_poly_piece_pop->pp_poly_piece_dynamics = (POLY_PIECE_DYNAMIC* ) (frog->fr_poly_piece_pop + 1);
    } else {
        frog->fr_poly_piece_pop = NULL;
    }

    // Clear animation data.
    memset(&frog->fr_anim_info, 0, sizeof(FROG_ANIM_INFO));
    memset(&frog->fr_tex_anim_info, 0, sizeof(FROG_TEX_ANIM_INFO));
    frog->fr_start_grid_x = (MR_LONG)startX;
    frog->fr_start_grid_z = (MR_LONG)startZ;
    ResetFrog(frog, frog->fr_start_grid_x, (MR_LONG)startZ, GAME_MODE_SINGLE_START);
    return frog;
}

/******************************************************************************
*%%%% FrogInitCustomAmbient
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogInitCustomAmbient(
*						FROG*	frog)
*
*	FUNCTION	Resets/initialises the frog's ambient color to the current map settings.
*	MATCH		https://decomp.me/scratch/VJRzc (By Kneesnap)
*
*	INPUTS		frog			-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogInitCustomAmbient(FROG* frog) {
    MR_LONG models;
    MR_ULONG i;
    MR_MESH_INST* mesh;
    MR_ANIM_ENV_INST* inst;
    MR_MESH_INST** mesh_insts;
    MR_ULONG colourVector = ((Map_general_header->gh_level_header.gh_frog_red + 0x80) << 16)
        + ((Map_general_header->gh_level_header.gh_frog_green + 0x80) << 8)
        + (Map_general_header->gh_level_header.gh_frog_blue + 0x80);

    for (i = 0; i < Game_total_viewports; i++) {
        inst = frog->fr_api_insts[i];
        if (inst != NULL) {
            mesh_insts = inst->ae_mesh_insts;
            models = inst->ae_models;
            while (models--) {
                mesh = *mesh_insts;
                if ((Map_general_header->gh_level_header.gh_frog_red != 0) || (Map_general_header->gh_level_header.gh_frog_green != 0) || (Map_general_header->gh_level_header.gh_frog_blue != 0)) {
                    MR_SET32(mesh->mi_custom_ambient, colourVector);
                    mesh->mi_light_flags |= MR_MESH_INST_DISPLAYED_LAST_FRAME;
                    mesh->mi_light_flags &= ~MR_MESH_INST_IGNORE_NCLIP;
                } else {
                    mesh->mi_light_flags &= ~(MR_MESH_INST_IGNORE_NCLIP | MR_MESH_INST_DISPLAYED_LAST_FRAME);
                }
                mesh_insts++;
            }
        }
    }
}

/******************************************************************************
*%%%% ResetFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ResetFrog(
*						FROG*		frog,
*						MR_LONG		gridStartX,
*						MR_LONG		gridStartZ,
*						MR_ULONG	game_mode)
*
*	FUNCTION	Resets the provided frog to the provided position
*	MATCH		https://decomp.me/scratch/GBPEd (By Kneesnap)
				https://decomp.me/scratch/XeHVp (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				gridStartX	-	the x grid coordinate to place the frog on
*				gridStartZ	-	the z grid coordinate to place the frog on
*				game_mode	-	the mode explains the situation requiring this function be called
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID ResetFrog(FROG* frog, MR_LONG gridStartX, MR_LONG gridStartZ, MR_ULONG game_mode) {
    MR_SVEC grid_centre;
    CAMERA* camera;
    MR_OT** ot;
    MR_SHORT cos;
    MR_SHORT sin;
    MR_LONG frog_dir;
    MR_LONG i, j;
    GRID_STACK* grid_stack;
    MR_OBJECT* frog_obj;
    FROG* temp_frog, *temp_frog2;
    MR_MAT matrix;
    MR_LONG x, z;

    // Reset basic frog data.
    frog->fr_flags = (FROG_CONTROL_ACTIVE | FROG_ACTIVE);
    frog->fr_direction = Map_general_header->gh_rotation;
    frog->fr_count = 0;
    frog->fr_powerup_flags = 0;
    frog->fr_auto_hop_timer = 0;
    frog->fr_super_tongue_timer = 0;
    frog->fr_quick_jump_timer = 0;
    frog->fr_num_buffered_keys = 0;
    frog->fr_buffered_input_count = 0;

    // Reset OTs.
    ot = frog->fr_ot;
    i = Game_total_viewports;
    while (i--)
        (*ot++)->ot_flags &= ~MR_OT_FORCE_BACK;

    // Position frog on the starting grid square.
    grid_stack = GetGridStack(gridStartX, gridStartZ);
    frog->fr_grid_square = &Grid_squares[grid_stack->gs_index + grid_stack->gs_numsquares - 1];
    GetGridSquareCentre(frog->fr_grid_square, &grid_centre);
    frog->fr_pos.vx = grid_centre.vx << 16;
    frog->fr_pos.vy = grid_centre.vy << 16;
    frog->fr_pos.vz = grid_centre.vz << 16;

    // Setup camera.
    camera = &Cameras[frog->fr_frog_id];
    camera->ca_flags &= ~CAMERA_IGNORE_FROG_Y;

    // Setup the frog based on the provided game mode.
    switch (game_mode) {
        case GAME_MODE_SINGLE_START:
            SetFrogUserMode(frog, FROGUSER_MODE_LEVEL_START_BOUNCE);
            frog->fr_target_y = grid_centre.vy << 16;
            frog->fr_pos.vy += (-FROG_COLLIDE_RADIUS2 << 12); 
            break;
        case GAME_MODE_SINGLE_TRIGGER_COLLECTED:
        case GAME_MODE_SINGLE_FROG_DIED:
        case GAME_MODE_MULTI_START:
        case GAME_MODE_MULTI_TRIGGER_COLLECTED:
        case GAME_MODE_MULTI_FROG_DIED:
        case GAME_MODE_LEVEL_FAST_START:
        case GAME_MODE_LEVEL_PLAY:
        default:
            frog->fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
            break;
    }

    // Update frog position.
    UpdateFrogPositionalInfo(frog);
    frog->fr_y = frog->fr_lwtrans->t[1];
    UpdateFrogOldPositionalInfo(frog);

    // Setup camera position & frog rotation.
    MR_COPY_VEC(&camera->ca_current, frog->fr_lwtrans->t);
    MR_INIT_MAT(frog->fr_lwtrans);
    frog_dir = frog->fr_direction << 10;
    cos = rcos(frog_dir);
    sin = rsin(frog_dir);
    frog->fr_lwtrans->m[0][0] = cos;
    frog->fr_lwtrans->m[0][2] = sin;
    frog->fr_lwtrans->m[2][0] = -sin;
    frog->fr_lwtrans->m[2][2] = cos;

    // Clear data.
    frog->fr_cam_zone = NULL;
    frog->fr_cam_zone_region = NULL;
    frog->fr_entity = NULL;
    frog->fr_forbid_entity = NULL;
    frog->fr_croak_mode = 0;
    frog->fr_croak_timer = 0;
    frog->fr_croak_scale = FROG_CROAK_MIN_SCALE;

    // Reset animation
    FrogInitialiseAnimation(frog, FROG_ANIMATION_PANT, 0);

    // Reset movement trail effect.
    if (frog->fr_trail != NULL) {
        frog->fr_trail->ef_flags |= EFFECT_RESET;
        ((TRAIL*) frog->fr_trail->ef_extra)->tr_timer = 0;
    }

    // Reset tongue.
    if (frog->fr_tongue != NULL)
        ResetTongue(frog->fr_tongue);

    // Reset stacking
    if (frog->fr_stack_master != NULL) {
        frog->fr_stack_master->fr_stack_slave = NULL;
        frog->fr_stack_master = NULL;
    }

    if (frog->fr_stack_slave != NULL) {
        frog->fr_stack_slave->fr_stack_master = NULL;
        frog->fr_stack_slave = NULL;
    }

    // Update stacked frogs on the square the frog is placed
    temp_frog = Frogs; // Should be: a2, is: a3 ot
    j = Game_total_players; // Should be a3, is: a1
    while (j--) {
        if ((temp_frog != frog) && (temp_frog->fr_flags & FROG_ACTIVE) && (temp_frog->fr_mode == FROG_MODE_STATIONARY) && temp_frog->fr_lwtrans != NULL) {
            x = (temp_frog->fr_lwtrans->t[0] - Grid_base_x) >> 8;
            z = (temp_frog->fr_lwtrans->t[2] - Grid_base_z) >> 8;

            if (x == gridStartX && z == gridStartZ && (temp_frog->fr_stack_slave == NULL)) {
                temp_frog->fr_stack_slave = frog;
                frog->fr_stack_master = temp_frog;
                
                temp_frog2 = frog;
                while (temp_frog2->fr_stack_master != NULL) {
                    MRTransposeMatrix(temp_frog2->fr_lwtrans, &matrix);
                    SnapFrogRotationToMatrix(temp_frog2->fr_stack_master, temp_frog2->fr_lwtrans, &matrix);
                    MRMulMatrixABC(temp_frog2->fr_stack_master->fr_lwtrans, &matrix, &temp_frog2->fr_stack_master->fr_stack_mod_matrix);
                    temp_frog2 = temp_frog2->fr_stack_master;
                }
                break; 
            }
        }

        temp_frog++;
    }

    // Find the object for the frog character.
    if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS) {
        frog_obj = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_flipbook->ae_object;
    } else {
        frog_obj = ((MR_ANIM_ENV*)frog->fr_api_item)->ae_extra.ae_extra_env_single->ae_object;
    }

    // Hide the frog, and disable any active poly piece pop
    frog_obj->ob_flags &= ~MR_OBJ_NO_DISPLAY;
    if (frog->fr_poly_piece_pop != NULL)
        frog->fr_poly_piece_pop->pp_timer = 0;

    // Reset checkpoint hud script if singleplayer.
    if (Game_total_players == 1)
        (&frog->fr_hud_script[HUD_ITEM_CHECKPOINTS])->hi_flags |= HUD_ITEM_REBUILD;

    // Reset frog color. (Remove drowning color, etc)
    // We have a problem, the compiler really wants to inline this function.
    // This version of GCC has no method of allowing for excluding a function from the inliner.
#ifdef WIN95
    FrogInitCustomAmbient(frog);
#else
    asm volatile (
        ".set\tnoreorder\n"
        "jal FrogInitCustomAmbient\n"
        "move $4, %0\n"
        ".set\treorder\n" 
        
        :
        : "r" (frog));
#endif

    // Kill the particle effect if it should be killed upon reset.
    if ((frog->fr_particle_api_item != NULL) && (frog->fr_particle_flags & EFFECT_KILL_WHEN_FROG_RESET))
        FROG_KILL_PARTICLE_EFFECT(frog);

    // Allow camera zones to update again.
    frog->fr_flags &= ~FROG_DO_NOT_UPDATE_CAMERA_ZONES;

    // Resume music
    if (Game_pausing_xa == TRUE)
        Game_pausing_xa = FALSE;
    
    SetTemporaryMusicVolume(Music_volume);
    LiveEntityChangeVolume(0, TRUE);
}

/******************************************************************************
*%%%% KillFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	KillFrog(
*						FROG*	frog)
*
*	FUNCTION	Destroys all effects (including poly piece pop) and OTs associated with the particular frog.
*	MATCH		https://decomp.me/scratch/tSPWX (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID KillFrog(FROG* frog) {
	MR_ULONG i;
	
	MRAnimEnvDestroyByDisplay((MR_ANIM_ENV*) frog->fr_api_item);
	
	frog->fr_api_item = NULL;
	for (i = 0; i < Game_total_viewports; i++)
		frog->fr_api_insts[i] = NULL;
	
	if (frog->fr_shadow != NULL)
		KillEffect(frog->fr_shadow);
	if (frog->fr_tongue != NULL)
		KillEffect(frog->fr_tongue);
	if (frog->fr_trail != NULL)
		KillEffect(frog->fr_trail);
	
	if (frog->fr_particle_api_item != NULL)
		FROG_KILL_PARTICLE_EFFECT(frog);
	
	if (frog->fr_poly_piece_pop != NULL) {
		MRFreeMem(frog->fr_poly_piece_pop);
		frog->fr_poly_piece_pop = NULL;
	}
	
	for (i = 0; i < Game_total_viewports; i++) {
		if (frog->fr_ot[i] != NULL) {
			MRKillOT(frog->fr_ot[i]);
			frog->fr_ot[i] = NULL;
		}
	}
}

/******************************************************************************
*%%%% UpdateFrogs
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogs(MR_VOID)
*
*	FUNCTION	Updates all frogs by handling controller input / movement and by updating powerups, effects, frog coloring, and, stacking.
*	MATCH		https://decomp.me/scratch/KO13T (By Kneesnap)
*				https://decomp.me/scratch/MUjyD (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID UpdateFrogs(MR_VOID) {
    FROG* frog;
    FROG* master;
    MR_ULONG i;

    // Update frog controls, movement, and powerups.
    frog = Frogs;
    i = Game_total_players;
    while (i--) {
        ControlFrog(frog);
        MoveFrog(frog);
        UpdateFrogPowerUps(frog);
        frog++;
    }

    // Update frogs on top of each other. (Multiplayer only)
    frog = Frogs;
    i = Game_total_players;
    while (i--) {
        if ((frog->fr_stack_master != NULL) && (frog->fr_stack_slave == NULL)) {
            if (frog->fr_stack_count != 0)
                frog->fr_stack_count--;
            
            master = frog;
            while (master->fr_stack_master != NULL) {
                UpdateFrogStackMaster(master, frog);
                master = master->fr_stack_master;
            }
        }
        
        frog++;
    }

    // Handle collision, and update FX.
    frog = Frogs;
    i = Game_total_players;
    while (i--) {
        if ((frog->fr_flags & FROG_ACTIVE) == FROG_ACTIVE)
            CollideFrog(frog);
        
        UpdateFrogEffects(frog);
        UpdateFrogBaseColour(frog);
        frog++;
    }
}

/******************************************************************************
*%%%% ControlFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	ControlFrog(
*						FROG*	frog)
*
*	FUNCTION	Listens and performs updates for any controller inputs the player performs.
*	MATCH		https://decomp.me/scratch/6D8Zh (By Kneesnap)
*				https://decomp.me/scratch/OPejj (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID ControlFrog(FROG* frog) {
    CAMERA* camera;

    if (frog->fr_flags & FROG_MUST_DIE) {
        frog->fr_flags &= ~FROG_MUST_DIE;
        if ((frog->fr_mode != FROG_MODE_JUMPING) || !(frog->fr_flags & FROG_JUMP_TO_LAND))
            frog->fr_count = 0;
		
        frog->fr_mode = FROG_MODE_DYING;
        frog->fr_death_count = FROG_DEATH_TIME;
        camera = &Cameras[frog->fr_frog_id];
        camera->ca_next_source_ofs.vx = CAMERA_FROG_DEATH_SOURCE_OFS_X;
        camera->ca_next_source_ofs.vy = CAMERA_FROG_DEATH_SOURCE_OFS_Y;
        camera->ca_next_source_ofs.vz = CAMERA_FROG_DEATH_SOURCE_OFS_Z;
        camera->ca_next_target_ofs.vx = CAMERA_FROG_DEATH_TARGET_OFS_X;
        camera->ca_next_target_ofs.vy = CAMERA_FROG_DEATH_TARGET_OFS_Y;
        camera->ca_next_target_ofs.vz = CAMERA_FROG_DEATH_TARGET_OFS_Z;
        camera->ca_move_timer = CAMERA_FROG_DEATH_TIME;
    }
    
    if ((Game_start_timer == 0) && (frog->fr_flags & FROG_CONTROL_ACTIVE)) {
        if (frog->fr_mode < FROG_MODE_USER) {
            if (Frog_controller_hooks[frog->fr_mode] != NULL)
				Frog_controller_hooks[frog->fr_mode](frog, frog->fr_mode);
		} else {
			if (Froguser_mode_control_functions[frog->fr_mode - FROG_MODE_USER] != NULL)
				Froguser_mode_control_functions[frog->fr_mode - FROG_MODE_USER](frog, frog->fr_mode);
		}
    }
    
    FrogUpdateCroak(frog);
}

/******************************************************************************
*%%%% MoveFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MoveFrog(
*						FROG*	frog)
*
*	FUNCTION	Updates the provided frog's movement regardless of its current state (eg: sliding, hopping, etc)
*	MATCH		https://decomp.me/scratch/o2JEl (By Kneesnap & nneonneo)
*				https://decomp.me/scratch/V6Hyn (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID MoveFrog(FROG* frog) {
    MR_ULONG react_flags;
    MR_ULONG (*move_callback)(FROG*, MR_ULONG, MR_ULONG*);
    MR_ULONG flags;
    MR_ULONG mode;

    flags = 0;
    MR_COPY_VEC(&frog->fr_old_pos, &frog->fr_pos);

    // Run a movement hook depending on the frog's movement mode.
    mode = frog->fr_mode;
    if (mode < FROG_MODE_USER) {
        move_callback = Frog_movement_hooks[mode];
    } else {
        move_callback = Froguser_mode_movement_functions[mode - FROG_MODE_USER];
    }
    if (move_callback != NULL)
        flags = move_callback(frog, mode, &react_flags);

    // Run updates based on the flags we got back.
    if (flags & FROG_MOVEMENT_CALLBACK_UPDATE_POS)
        UpdateFrogPositionalInfo(frog);
    
    if (flags & FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX)
        UpdateFrogMatrix(frog);
    
    if (flags & FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS)
        ReactFrogWithGridFlags(frog, (MR_USHORT)react_flags);
    
    if (flags & FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS)
        UpdateFrogOldPositionalInfo(frog);
    
    if (frog->fr_flags & FROG_ON_ENTITY) {
        if (frog->fr_entity->en_live_entity == NULL) {
            frog->fr_flags &= ~FROG_ON_ENTITY;
        } else {
            frog->fr_entity->en_live_entity->le_flags |= (LIVE_ENTITY_CARRIES_FROG_0 << frog->fr_frog_id);
        }        
    }
    
    UpdateFrogCameraZone(frog);
}

/******************************************************************************
*%%%% UpdateFrogPositionalInfo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogPositionalInfo(
*						FROG*	frog)
*
*	FUNCTION	Updates the frog's positional info
*	MATCH		https://decomp.me/scratch/eQw1p (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID UpdateFrogPositionalInfo(FROG* frog) {
    frog->fr_lwtrans->t[0] = frog->fr_pos.vx >> 16;
    frog->fr_lwtrans->t[1] = frog->fr_pos.vy >> 16;
    frog->fr_lwtrans->t[2] = frog->fr_pos.vz >> 16;
    frog->fr_grid_x = (frog->fr_lwtrans->t[0] - Grid_base_x) >> 8;
    frog->fr_grid_z = (frog->fr_lwtrans->t[2] - Grid_base_z) >> 8;
}

/******************************************************************************
*%%%% UpdateFrogOldPositionalInfo
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogOldPositionalInfo(
*						FROG*	frog)
*
*	FUNCTION	Updates the frog's old positional info
*	MATCH		https://decomp.me/scratch/rFgiL (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID UpdateFrogOldPositionalInfo(FROG* frog) {
	frog->fr_old_pos.vx = frog->fr_pos.vx;
	frog->fr_old_pos.vy = frog->fr_pos.vy;
	frog->fr_old_pos.vz = frog->fr_pos.vz;
	frog->fr_old_grid_x = frog->fr_grid_x;
	frog->fr_old_grid_z = frog->fr_grid_z;
	frog->fr_old_grid_square = frog->fr_grid_square;
	frog->fr_old_y = frog->fr_y;
}

/******************************************************************************
*%%%% SetFrogUserMode
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetFrogUserMode(
*						FROG*		frog,
*						MR_ULONG*	mode)
*
*	FUNCTION	Puts the frog into a "user mode", from "froguser.c"
*	MATCH		https://decomp.me/scratch/lajF9 (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	The user mode to put the frog into
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID SetFrogUserMode(FROG* frog, MR_ULONG mode) {
	if (Froguser_mode_setup_functions[mode - FROG_MODE_USER] != NULL)
		Froguser_mode_setup_functions[mode - FROG_MODE_USER](frog, mode);
	
	frog->fr_mode = mode;
}

/******************************************************************************
*%%%% JumpFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	JumpFrog(
*						FROG*		frog,
*						MR_LONG		direction,
*						MR_ULONG	jump_type,
*						MR_LONG		grid_delta,
*						MR_LONG		jump_time)
*
*	FUNCTION	Enters the jumping process to cause the frog to jump in a particular direction.
*	MATCH		https://decomp.me/scratch/mjSV0 (By mono21400 & stuck-pixel & Kneesnap) Extra extra thanks to mono21400 for this function.
*				https://decomp.me/scratch/vv0WT	(By Kneesnap & mono21400 for the giga-brain match)
*
*	INPUTS		frog		-	pointer to the frog
*				direction	-	the cardinal direction to move the frog
*				jump_type	-	the jump type flags (is it a super hop? is it forced by the game?)
*				grid_delta	-	the number of grid squares to move in the specified direction
*				jump_time	-	the amount of time the jump should take
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID JumpFrog(FROG* frog, MR_LONG jump_direction, MR_ULONG jump_type, MR_LONG grid_delta, MR_LONG jump_time) {
    MR_SVEC svec;
    MR_VEC vec;
    MR_LONG old_direction;
    MR_LONG new_direction;
    MR_BOOL actually_moved;
    CAMERA* camera;
    FORM_BOOK* form_book;
    MR_LONG form_height;
    MR_LONG original_entity_grid_x, original_entity_grid_z;
    ENTITY* entity;
    FORM* form;
    FROG* temp_frog;
    GRID_SQUARE* grid_square;
    GRID_STACK* grid_stack;
    MR_SHORT r_cos, r_sin;
    MR_LONG temp_velocity;
    MR_LONG y1;
    MR_LONG temp_gs_index;
    MR_LONG y;
    MR_LONG i;
    MR_LONG allowed_jump_height;
    MR_LONG squares;
    MR_LONG x, z;
    MR_LONG x_dir, z_dir;
    MR_USHORT gs_flags;
    FORM_DATA* form_data;

    actually_moved = FALSE;
    form_height = 0;
    old_direction = frog->fr_direction;
    camera = &Cameras[frog->fr_frog_id];

    // Grid positions
    original_entity_grid_x = frog->fr_entity_grid_x;
    x_dir = 0; 
    
    entity = frog->fr_entity;
    
    original_entity_grid_z = frog->fr_entity_grid_z;
    z_dir = 0;

    // mono21400 somehow figured this out.
    // I have no idea why this makes the code match, but it does.
    // It swaps register v0 with v1, which is the temporary place "camera" is kept.
    if (x)
      x = !x;

    // Determine the allowed jump height.
    if ((jump_type & FROG_JUMP_SUPER)) {
        allowed_jump_height = FROG_JUMPUP_LARGE_DY;
    } else if (jump_type & FROG_JUMP_FORCED) {
        allowed_jump_height = FROG_JUMPUP_FORCED_DY;
    } else if ((frog->fr_grid_square != NULL) && (frog->fr_grid_square->gs_flags & GRID_SQUARE_EXTEND_HOP_HEIGHT)) {
        allowed_jump_height = FROG_JUMPUP_SMALL_DY_EXTENDED;
    } else {
        allowed_jump_height = FROG_JUMPUP_SMALL_DY;
    }
    
    new_direction = camera->ca_frog_controller_directions[jump_direction & 3];
    if (frog->fr_flags & FROG_ON_ENTITY) {
        form = ENTITY_GET_FORM(entity);
        form_book = ENTITY_GET_FORM_BOOK(entity);
        frog->fr_flags &= ~FROG_ON_ENTITY;
        
        if (form_book->fb_flags & FORM_BOOK_FROG_NO_ENTITY_ANGLE) {
            // If the entity is not at an angle, we can just directly calculate the target grid position.
            frog->fr_target_pos.vx = frog->fr_lwtrans->t[0] + ((grid_delta * camera->ca_frog_direction_vectors[jump_direction].vx) >> 4);
            frog->fr_target_pos.vy = frog->fr_lwtrans->t[1] + ((grid_delta * camera->ca_frog_direction_vectors[jump_direction].vy) >> 4);
            frog->fr_target_pos.vz = frog->fr_lwtrans->t[2] + ((grid_delta * camera->ca_frog_direction_vectors[jump_direction].vz) >> 4);
            frog->fr_direction = camera->ca_frog_controller_directions[jump_direction];
            x = (frog->fr_target_pos.vx - Grid_base_x) >> WORLD_SHIFT;
            z = (frog->fr_target_pos.vz - Grid_base_z) >> WORLD_SHIFT;
        } else {
            // The entity is capable of being at an angle, so we must calculate the target position as such.
            old_direction = frog->fr_direction;
            frog->fr_direction = new_direction = (jump_direction + frog->fr_entity_angle) & 3;

            // Determine the direction the frog wants to move. (Taking into consideration the entity angle)
            switch (new_direction) {
                case FROG_DIRECTION_N:
                    x_dir = 0;
                    z_dir = 1;
                    break;
                case FROG_DIRECTION_E:
                    x_dir = 1;
                    z_dir = 0;
                    break;
                case FROG_DIRECTION_S:
                    x_dir = 0;
                    z_dir = -1;
                    break;
                case FROG_DIRECTION_W:
                    x_dir = -1;
                    z_dir = 0;
                    break;
            }

            // Calculate the new form grid position (Grid position on the entity)
            temp_velocity = grid_delta * (x_dir << 24);
            x = (x_dir * grid_delta) + frog->fr_entity_grid_x;
            z = (z_dir * grid_delta) + frog->fr_entity_grid_z;
            frog->fr_velocity.vx = temp_velocity;
            frog->fr_velocity.vy = 0;
            frog->fr_velocity.vz = temp_velocity;
            frog->fr_entity_grid_x = x;
            frog->fr_entity_grid_z = z;

            // Attempt to collide with the entity's local collision grid (form).
            form_data = ((FORM_DATA**)&form->fo_formdata_ptrs)[0];
            if ((x < 0) || (((x >= form->fo_xnum))) || (z < 0) || (form->fo_znum <= z)) {
                // The frog is hopping somewhere outside of the form grid. (Hopping off of the entity.)
                form_height =  form_data->fd_height;
            } else {
                // Get the flags for the form grid square the frog jumped on.
                temp_gs_index = ((form->fo_xnum * z) + frog->fr_entity_grid_x);
                gs_flags = form_data->fd_grid_squares[temp_gs_index];

                // Get the height of the form grid square.
                switch(form_data->fd_height_type) {
                    case FORM_DATA_HEIGHT_TYPE_GRID:
                        form_height = form_data->fd_height;
                        break;
                    case FORM_DATA_HEIGHT_TYPE_SQUARE:
                        form_height = form_data->fd_heights[temp_gs_index];
                        break;
                }

                // If the form grid square is usable, treat it as the hop target and hop to it.
                if (gs_flags & GRID_SQUARE_USABLE) {
                    actually_moved = TRUE;
                    frog->fr_flags |= (FROG_JUMP_FROM_ENTITY | FROG_JUMP_TO_ENTITY);
                    
                    frog->fr_target_pos.vx = (frog->fr_entity_grid_x << WORLD_SHIFT) + form->fo_xofs + 0x80;
                    frog->fr_target_pos.vy = form_height;
                    frog->fr_target_pos.vz = (frog->fr_entity_grid_z << WORLD_SHIFT) + form->fo_zofs + 0x80;
                    goto jump_if_possible;
                } else if (!(gs_flags & GRID_SQUARE_BOUNCE_WALL_N)) {
                    goto movement_failure;
                }
            }

            // The frog is hopping off the entity.
            frog->fr_flags = (frog->fr_flags & ~FROG_JUMP_TO_ENTITY) | FROG_JUMP_FROM_ENTITY;
            new_direction = camera->ca_frog_controller_directions[jump_direction & 3];
            switch (new_direction) {
                case FROG_DIRECTION_N:
                    x_dir = 0;
                    z_dir = 1;
                    break;
                case FROG_DIRECTION_E:
                    x_dir = 1;
                    z_dir = 0;
                    break;
                case FROG_DIRECTION_S:
                    x_dir = 0;
                    z_dir = -1;
                    break;
                case FROG_DIRECTION_W:
                    x_dir = -1;
                    z_dir = 0;
                    break;
            }

            // Calculate the new X + Z of the target grid stack.
            x = (x_dir * grid_delta) + frog->fr_grid_x;
            z = (z_dir * grid_delta) + frog->fr_grid_z;
        }

        // Collision in theory is disabled with the entity when frog->fr_forbid_entity is set, but it doesn't appear this variable is ever used.
        frog->fr_forbid_entity = frog->fr_entity;

        // Search all of the grid squares in the target grid stack.
        grid_stack = GetGridStack(x, z);
        if (squares = grid_stack->gs_numsquares) {
            grid_square = &Grid_squares[grid_stack->gs_index];
            while (squares--) {
                if (!(grid_square->gs_flags & GRID_SQUARE_USABLE)) {
                    movement_failure:
                    // The square is not usable, play the "OUCH" animation. (Animation played if you try to hop into a wall.)
                    FrogRequestAnimation(frog, FROG_ANIMATION_OUCH, 0, 0);
                    frog->fr_entity_grid_x = original_entity_grid_x;
                    frog->fr_entity_grid_z = original_entity_grid_z;
                    MR_CLEAR_VEC(&frog->fr_velocity);
                    frog->fr_flags = (frog->fr_flags & ~FROG_JUMP_FROM_ENTITY) | FROG_ON_ENTITY;
                    r_cos = rcos(frog->fr_direction << 10);
                    r_sin = rsin(frog->fr_direction << 10);
                    frog->fr_entity_transform.m[0][0] = r_cos;
                    frog->fr_entity_transform.m[0][1] = 0;
                    frog->fr_entity_transform.m[0][2] = r_sin;
                    frog->fr_entity_transform.m[1][0] = 0;
                    frog->fr_entity_transform.m[1][1] = 0x1000;
                    frog->fr_entity_transform.m[1][2] = 0;
                    frog->fr_entity_transform.m[2][0] = -r_sin;
                    frog->fr_entity_transform.m[2][1] = 0;
                    frog->fr_entity_transform.m[2][2] = r_cos;
                    goto jump_if_possible;
                } else {
                    // The square is usable, so if it is within the allowed jump range, jump to it!
                    y1 = GetGridSquareHeight(grid_square);
                    y = frog->fr_lwtrans->t[1];
                    if ((((y >= y1) && (((allowed_jump_height >= (y - y1))))) || ((y1 >= y) && ((y1 - y) <= FROG_JUMP_DOWN_DISTANCE))) && !(grid_square->gs_flags & GRID_SQUARE_WATER)) {
                        frog->fr_flags |= FROG_JUMP_TO_LAND;
                        goto found_grid_square;
                    }
                }

                grid_square++;
            }
        }

        // We didn't find any applicable grid squares.
        // Allow the frog to hop anyways, but it will fall out of the world (unless it hits an entity).
        frog->fr_grid_x = x;
        frog->fr_grid_z = z;
        frog->fr_grid_square = NULL;

        frog->fr_flags = (frog->fr_flags | FROG_JUMP_FROM_ENTITY) & ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
        if (form_book->fb_flags & FORM_BOOK_FROG_NO_ENTITY_ANGLE) {
            ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
            MRMulMatrixABA(&camera->ca_mod_matrix, &MRTemp_matrix);
            frog->fr_entity = NULL;
            frog->fr_flags &= ~FROG_JUMP_FROM_ENTITY;
        } else {
            frog->fr_target_pos.vx = (frog->fr_entity_grid_x << WORLD_SHIFT) + form->fo_xofs + 0x80;
            frog->fr_target_pos.vy = form_height;
            frog->fr_target_pos.vz = (frog->fr_entity_grid_z << WORLD_SHIFT) + form->fo_zofs + 0x80;
        }
        
        actually_moved = TRUE;
    } else {
        // Determine the direction the frog should move.
        switch (new_direction) {
            case FROG_DIRECTION_N:
                x_dir = 0;
                z_dir = 1;
                break;
            case FROG_DIRECTION_E:
                x_dir = 1;
                z_dir = 0;
                break;
            case FROG_DIRECTION_S:
                x_dir = 0;
                z_dir = -1;
                break;
            case FROG_DIRECTION_W:
                x_dir = -1;
                z_dir = 0;
                break;
        }

        // Calculate the new grid position the frog should hop to.
        x = (x_dir * grid_delta) + frog->fr_grid_x;
        z = (z_dir * grid_delta) + frog->fr_grid_z;

        // This code appears to try and keep the frog's target position within the bounds of the grid.
        // However, it doesn't look like it quite works. It works if x or z is less than zero, but not if either is greater than the maximum grid bounds.
        // It is speculated (but unconfirmed) that this bug is why "Time Flies" has broken behavior jumping off the bird squadron near the end of its path.
        i = grid_delta;
        while (i-- != 0) {
            if ((x < 0) || (x >= Grid_xnum) || (z < 0) || (z >= Grid_znum)) {
                x += x_dir;
                z += z_dir;
            } else {
                break;
            }
        }

        if (i >= 0) { // i >= 0 means the player is fully within the collision grid.
            if (z_dir == 1) { // The frog is moving north, test if the north bouncy wall flag is set on the CURRENT grid square.
                if (frog->fr_grid_square->gs_flags & GRID_SQUARE_BOUNCE_WALL_N) {
                    frog->fr_user_data1 = (MR_VOID*) x;
                    frog->fr_user_data2 = (MR_VOID*) z;
                    frog->fr_direction = new_direction;
                    SetFrogUserMode(frog, FROGUSER_MODE_BOUNCY_COBWEB);
                    return;
                }
            } else if (z_dir == -1) {
                grid_stack = GetGridStack(x, z);
                squares = grid_stack->gs_numsquares;
                if (squares != 0) {
                    grid_square = &Grid_squares[grid_stack->gs_index];
                    while (squares-- != 0) {  // The frog is moving south, test if the north bouncy wall flag is set on the TARGET grid square.
                        if (grid_square->gs_flags & GRID_SQUARE_BOUNCE_WALL_N) {
                            frog->fr_user_data1 = (MR_VOID*) x;
                            frog->fr_user_data2 = (MR_VOID*) z;
                            frog->fr_direction = new_direction;
                            SetFrogUserMode(frog, FROGUSER_MODE_BOUNCY_COBWEB);
                            return;
                        }

                        grid_square++;
                    }
                }
            } else if (x_dir == 1) { // The frog is moving east, test if the east bouncy wall flag is set on the CURRENT square.
                if (frog->fr_grid_square->gs_flags & GRID_SQUARE_BOUNCE_WALL_E) {
                    frog->fr_user_data1 = (MR_VOID*) x;
                    frog->fr_user_data2 = (MR_VOID*) z;
                    frog->fr_direction = new_direction;
                    SetFrogUserMode(frog, FROGUSER_MODE_BOUNCY_COBWEB);
                    return;
                }
            } else if (x_dir == -1) { // The frog is moving west, test if the east bouncy flag is set on the TARGET square.
                grid_stack = GetGridStack(x, z);
                squares = grid_stack->gs_numsquares;
                if (squares != 0) {
                    grid_square = &Grid_squares[grid_stack->gs_index];
                    while (squares-- != 0) {
                        if (grid_square->gs_flags & GRID_SQUARE_BOUNCE_WALL_E) {
                            frog->fr_user_data1 = (MR_VOID*) x;
                            frog->fr_user_data2 = (MR_VOID*) z;
                            frog->fr_direction = new_direction;
                            SetFrogUserMode(frog, FROGUSER_MODE_BOUNCY_COBWEB);
                            return;
                        }

                        grid_square++;
                    }
                }
            }

            // Attempt to hop to a square on the target grid .
            grid_stack = GetGridStack(x, z);
            if (squares = grid_stack->gs_numsquares) {
                grid_square = &Grid_squares[grid_stack->gs_index];
                while (squares-- != 0) {
                    if (grid_square->gs_flags & GRID_SQUARE_USABLE) {
                        // If the square is a cliff death, and it slopes upward, don't let the frog jump into it.
                        // An example of this behavior can be seen in Lily Islands (SUB1) at the bird pickup spot to the purple frog.
                        if (grid_square->gs_flags & GRID_SQUARE_CLIFF) {
                            y1 = -GetGridStackHeight(grid_stack);
                            if (frog->fr_lwtrans->t[1] >= y1) {
                                frog->fr_user_data1 = (MR_VOID*) x;
                                frog->fr_user_data2 = (MR_VOID*) z;
                                frog->fr_direction = new_direction;
                                SetFrogUserMode(frog, FROGUSER_MODE_BOUNCY_COBWEB);
                                return;
                            }
                        }

                        // If the frogger is within allowed jumping range to the target square, do the jump.
                        // This jump is an instant hop. A hop with meaningful fall distance is handled below.
                        y1 = GetGridSquareHeight(grid_square);
                        y = frog->fr_lwtrans->t[1];
                        if (((y >= y1) && (allowed_jump_height >= (y - y1)))) {
                            frog->fr_flags |= FROG_JUMP_TO_LAND;
                            goto found_grid_square;
                        } else if (((y1 >= y) && (FROG_JUMP_DOWN_DISTANCE >= (y1 - y)))) {
                            frog->fr_flags |= FROG_JUMP_TO_LAND;
                            goto found_grid_square;
                        }
                    }
                    grid_square++;
                }

                // Attempt to jump to hop to any grid square in the stack which is usable which is at or below the frog's height.
                // It doesn't matter if the frog will survive, shake camera on land, etc.
                squares = grid_stack->gs_numsquares;
                grid_square = &Grid_squares[grid_stack->gs_index + squares - 1];
                while (squares-- != 0) {
                    y1 = GetGridSquareHeight(grid_square);
                    if ((grid_square->gs_flags & GRID_SQUARE_USABLE) && (y1 >= frog->fr_lwtrans->t[1])) {
                        frog->fr_flags &= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
                        goto found_grid_square;
                    }

                    grid_square--;
                }

                // We have no possible destination for the frog.
                if (jump_type & FROG_JUMP_FORCED) {
                    // If the jump is forced, do it anyways and let the frog fall to their death.
                    frog->fr_flags &= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
                    goto found_grid_square;
                } else {
                    // Otherwise, let's cancel the movement since there's nowhere to go.
                    // Play the "can't move" animation too.
                    frog->fr_old_direction = frog->fr_direction;
                    frog->fr_direction = new_direction;
                    FrogRequestAnimation(frog, FROG_ANIMATION_OUCH, 0, 0);
                    return;
                }
            } else {
                // There are no grid squares in the target stack, so it's jumping out of the world.
                grid_square = NULL;
                frog->fr_flags &= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
            }
        } else {
            // The frog is hopping outside of the grid bounds,  so it's jumping out of the world.
            grid_square = NULL;
            frog->fr_flags &= ~(FROG_JUMP_TO_LAND | FROG_JUMP_TO_ENTITY);
        }

        // The following code prepares the frog to move.
        // It should only be called if the frog will actually move.
found_grid_square:
        actually_moved = TRUE;
        frog->fr_grid_x = x;
        frog->fr_grid_z = z;
        frog->fr_grid_square = grid_square;
        frog->fr_direction = new_direction;
        frog->fr_target_pos.vx = (frog->fr_grid_x << WORLD_SHIFT) + Grid_base_x + 0x80;
        frog->fr_target_pos.vz = (frog->fr_grid_z << WORLD_SHIFT) + Grid_base_z + 0x80;
    }
    
jump_if_possible:
    if (frog->fr_stack_master != NULL) {
        frog->fr_stack_master->fr_stack_slave = NULL;
        frog->fr_stack_master = NULL;
    }
    
    if (frog->fr_stack_slave != NULL) {
        frog->fr_stack_slave->fr_stack_master = NULL;
        frog->fr_stack_slave = NULL;
    }

    if (actually_moved != TRUE)
        return; // No jump should occur, get outta here.

    // Play sounds, animations, etc, and add score for 
    frog->fr_mode = FROG_MODE_JUMPING;
    if (jump_type & FROG_JUMP_SUPER) {
        // Play superhop animation, sound, particle FX, etc.
        frog->fr_flags |= FROG_SUPERJUMP;
        MRSNDPlaySound(SFX_GEN_FROG_SUPER_HOP, NULL, 0, 0);
        FrogRequestAnimation(frog, FROG_ANIMATION_SUPERJUMP, 0, 0);
        AddFrogScore(frog, SCORE_10, NULL);
        DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_SUPERJUMP, 0, TRUE);
        frog->fr_trail->ef_flags |= EFFECT_RESET;
        ((TRAIL*)frog->fr_trail->ef_extra)->tr_rgb = ((TRAIL_RGB_START + TRAIL_RGB_MAX) >> 1);
        ((TRAIL*)frog->fr_trail->ef_extra)->tr_timer = 26;
    } else {
        MRSNDPlaySound(SFX_GEN_FROG_HOP, NULL, 0, (MRFrame_number & 3) << 7);
        
        if (frog->fr_powerup_flags & FROG_POWERUP_QUICK_JUMP) {
            FrogRequestAnimation(frog, FROG_ANIMATION_SUPERHOP, 0, 0);
            AddFrogScore(frog, SCORE_50, NULL);
        } else if (frog->fr_powerup_flags & FROG_POWERUP_AUTO_HOP) {
            FrogRequestAnimation(frog, FROG_ANIMATION_AUTOHOP, 0, 0);
        } else if (frog->fr_direction == old_direction) {
            if (frog->fr_buffered_input_count > FROG_PERFECT_JUMPS_BEFORE_ROLL) {
                FrogRequestAnimation(frog, FROG_ANIMATION_ROLL, 0, 0);
                AddFrogScore(frog, SCORE_50, NULL);
                frog->fr_buffered_input_count = 0;
            } else {
                FrogRequestAnimation(frog, FROG_ANIMATION_HOP, 0, 0);
                AddFrogScore(frog, SCORE_5, NULL);
            }
        } else {
            FrogRequestAnimation(frog, FROG_ANIMATION_HOP, 0, 0);
            AddFrogScore(frog, SCORE_5, NULL);
        }

        // Show movement trail effect.
        frog->fr_trail->ef_flags |= EFFECT_RESET;
        ((TRAIL*)frog->fr_trail->ef_extra)->tr_rgb = ((TRAIL_RGB_START + TRAIL_RGB_MAX) >> 1);
        ((TRAIL*)frog->fr_trail->ef_extra)->tr_timer = 16;
    }

    // Calculate the frog's new velocity (& potentially y position).
    frog->fr_count = jump_time;
    frog->fr_old_y = frog->fr_y;
    if (frog->fr_flags & FROG_JUMP_TO_LAND) {
        temp_frog = Frogs;
        i = Game_total_players;
        while (i-- != 0) {
            if ((temp_frog != frog) && (temp_frog->fr_grid_square == frog->fr_grid_square) && (temp_frog->fr_stack_master == NULL)) {
                frog->fr_y = temp_frog->fr_lwtrans->t[1] - FROG_COLLIDE_FROG_Y_OFFSET;
                goto block_173;
            }
                
            temp_frog++;
        }

        frog->fr_y = GetGridSquareHeight(frog->fr_grid_square);;

block_173:
        // ent_swp.c provides good reason to think new_direction (or rather u) is reused like this.
        y1 = (frog->fr_y - frog->fr_lwtrans->t[1]);
        new_direction = ((((y1 << 16) / (frog->fr_count + 1)))) - ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1);
    } else if ((frog->fr_flags & FROG_JUMP_FROM_ENTITY) && (frog->fr_flags & FROG_JUMP_TO_ENTITY)) {
        temp_frog = Frogs;
        i = Game_total_players;
        while (i-- != 0) {
            if ((temp_frog != frog) && (temp_frog->fr_entity == frog->fr_entity) && (temp_frog->fr_stack_master == NULL)) {
                frog->fr_y = temp_frog->fr_lwtrans->t[1] - FROG_COLLIDE_FROG_Y_OFFSET;
                goto block_173_1;
            }
            temp_frog++;
        } 

        // Calculate the new y position from the target position.
        svec.vx = 0;
        svec.vy = frog->fr_target_pos.vy;
        svec.vz = 0;
        MRApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &svec, &vec);
        frog->fr_y = vec.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1];
            
block_173_1:
        // ent_swp.c provides good reason to think new_direction (or rather u) is reused like this.
        y1 = (frog->fr_y - frog->fr_lwtrans->t[1]);
        new_direction = ((((y1 << 16) / (frog->fr_count + 1)))) - ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1);
    } else {
        // ent_swp.c provides good reason to think new_direction (or rather u) is reused like this.
        new_direction = -((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1);
        frog->fr_y = frog->fr_lwtrans->t[1];
    }

    // Calculate the frog's velocity.
    if ((frog->fr_entity != NULL) && !(frog->fr_flags & FROG_JUMP_TO_LAND)) {
        frog->fr_velocity.vx = ((frog->fr_target_pos.vx << 16) - frog->fr_entity_ofs.vx) / frog->fr_count;
        frog->fr_velocity.vy = new_direction;
        frog->fr_velocity.vz = ((frog->fr_target_pos.vz << 16) - frog->fr_entity_ofs.vz) / frog->fr_count;
    } else {
        frog->fr_velocity.vx = ((frog->fr_target_pos.vx << 16) - frog->fr_pos.vx) / frog->fr_count;
        frog->fr_velocity.vy = new_direction;
        frog->fr_velocity.vz = ((frog->fr_target_pos.vz << 16) - frog->fr_pos.vz) / frog->fr_count;
    }
}

/******************************************************************************
*%%%% FrogModeControlStationary
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogModeControlStationary(
*						FROG*		frog,
*						MR_ULONG*	mode)
*
*	FUNCTION	The update hook run when the frog is stationary
*	MATCH		https://decomp.me/scratch/Wi789 (By Kneesnap & an unknown helper who didn't sign in)
*				https://decomp.me/scratch/8G7qt (By Kneesnap & ethteck)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogModeControlStationary(FROG* frog, MR_ULONG mode) {
    MATRIX matrix;
    MR_UBYTE input;
    MR_LONG i;
    MR_LONG* key_ptr;
    CAMERA* camera;
    ENTITY* tongue_target;
    MR_LONG jump_time;
    MR_ULONG jump_type;

    jump_type = 0;
    camera = &Cameras[frog->fr_frog_id];
    input = FROG_DIRECTION_NO_INPUT;
    frog->fr_previous_key = frog->fr_current_key;
    frog->fr_no_input_timer++;

    // If no demo is recording and an input is buffered, grab the buffered key.
    if (Recording_demo != TRUE) {
        i = frog->fr_num_buffered_keys;
        key_ptr = frog->fr_buffered_key;
        while(i-- != 0) {
            switch(*key_ptr) {
                case FROG_DIRECTION_N:
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
                        input = *key_ptr;
                        frog->fr_buffered_input_count++;
                        goto loop_end;
                    }
                    break;
                case FROG_DIRECTION_E:
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
                        input = *key_ptr;
                        frog->fr_buffered_input_count++;
                        goto loop_end;
                    }
                    break;
                case FROG_DIRECTION_S:
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
                        input = *key_ptr;
                        frog->fr_buffered_input_count++;
                        goto loop_end;
                    }
                    break;
                case FROG_DIRECTION_W:
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_left_control)) {
                        input = *key_ptr;
                        frog->fr_buffered_input_count++;
                        goto loop_end;
                    }
                    break;
                case FROG_DIRECTION_SUPER_JUMP:
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_superjump_control)) {
                        input = *key_ptr;
                        frog->fr_buffered_input_count++;
                        goto loop_end;
                    }
                    break;
            }
            
            key_ptr++;
        }
        
        if(frog->fr_buffered_input_count > 0)
            frog->fr_buffered_input_count--;
        
        loop_end:
    }
    
    frog->fr_num_buffered_keys = 0;

    // If there were no buffered keys, check the controller. 
    if (input  == FROG_DIRECTION_NO_INPUT) {
        if (Cheat_control_toggle == 0) {
            if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_camera_clockwise_control))
                input |= FROG_DIRECTION_CAMERA_CLOCKWISE;
            
            if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_camera_anticlockwise_control))
                input |= FROG_DIRECTION_CAMERA_ANTICLOCKWISE;
            
            if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_tongue_control))
                input |= FROG_DIRECTION_TONGUE;
            
            if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_superjump_control) && (frog->fr_stack_master == NULL))
                input |= FROG_DIRECTION_SUPER_JUMP;
            
            if ((Cheat_control_toggle == 0) && (frog->fr_stack_master == NULL)) {
                if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
                    input = FROG_DIRECTION_N;
                } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
                    input = FROG_DIRECTION_E;
                } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
                    input = FROG_DIRECTION_S;
                } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_left_control)) {
                    input = FROG_DIRECTION_W;
                }
                
                if (frog->fr_powerup_flags & FROG_POWERUP_AUTO_HOP) {
                    if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
                        input = FROG_DIRECTION_N;
                    } else if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
                        input = FROG_DIRECTION_E;
                    } else if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
                        input = FROG_DIRECTION_S;
                    } else if (MR_CHECK_PAD_HELD(frog->fr_input_id, frog->fr_control_method->fc_left_control)) {
                        input = FROG_DIRECTION_W;
                    }
                }
            }
        }

        // If a demo is recording, save the key to the demo buffer.
        if (Recording_demo == TRUE)
            *Demo_data_input_ptr++ = input;

        // If a demo is running, overwrite all input with the demo keypress.
        if (Game_flags & GAME_FLAG_DEMO_RUNNING)
            input = *Demo_data_input_ptr++;

        // Rotate the camera clockwise if the button is pressed.
        if ((input & FROG_DIRECTION_CAMERA_CLOCKWISE) && ((camera->ca_zone == NULL) || (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_direction < 0) || (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_SEMIFORCED))) {
            if (frog->fr_mode == FROG_MODE_STATIONARY || frog->fr_mode == FROG_MODE_STACK_MASTER)
                frog->fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
            
            camera->ca_twist_counter = 1;
            camera->ca_twist_quadrants = 1;
            camera->ca_move_timer = CAMERA_TWIST_TIME;
            if (frog->fr_cam_zone != NULL) {
                if (frog->fr_entity != NULL) {
                    ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
                    MRMulMatrixABC(&camera->ca_mod_matrix, &MRTemp_matrix, &matrix);
                    i = (GetWorldYQuadrantFromMatrix(&matrix) + 1) & 3;
                } else {
                    i = (GetWorldYQuadrantFromMatrix(&camera->ca_mod_matrix) + 1) & 3;
                }

                MR_COPY_SVEC(&camera->ca_next_source_ofs, &(((ZONE_CAMERA*)&camera->ca_zone[i + 1]))->zc_source_ofs_n);
                MR_COPY_SVEC(&camera->ca_next_target_ofs, &(((ZONE_CAMERA*)&camera->ca_zone[i + 1]))->zc_target_ofs_n);
            } else {
                CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS;
                CAMERA_SET_DEFAULT_NEXT_TARGET_OFS;
            }
            return;
        }

        // Rotate the camera counter-clockwise if the button is pressed.
        if ((input & FROG_DIRECTION_CAMERA_ANTICLOCKWISE) && ((camera->ca_zone == NULL) || (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_direction < 0) || (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_SEMIFORCED))) {
            if (frog->fr_mode == FROG_MODE_STATIONARY || frog->fr_mode == FROG_MODE_STACK_MASTER)
                frog->fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
            
            camera->ca_twist_counter = -1;
            camera->ca_twist_quadrants = 1;
            camera->ca_move_timer = CAMERA_TWIST_TIME;
            if (frog->fr_cam_zone != NULL) {
                if (frog->fr_entity != NULL) {
                    ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
                    MRMulMatrixABC(&camera->ca_mod_matrix, &MRTemp_matrix, &matrix);
                    i = (GetWorldYQuadrantFromMatrix(&matrix) - 1) & 3;
                } else {
                    i = (GetWorldYQuadrantFromMatrix(&camera->ca_mod_matrix) - 1) & 3;
                }

                MR_COPY_SVEC(&camera->ca_next_source_ofs, &(((ZONE_CAMERA*)&camera->ca_zone[i + 1]))->zc_source_ofs_n);
                MR_COPY_SVEC(&camera->ca_next_target_ofs, &(((ZONE_CAMERA*)&camera->ca_zone[i + 1]))->zc_target_ofs_n);
            } else {
                CAMERA_SET_DEFAULT_NEXT_SOURCE_OFS;
                CAMERA_SET_DEFAULT_NEXT_TARGET_OFS;
            }
            return;
        }

        // Activate the player's tongue if the button is pressed.
        if ((input & FROG_DIRECTION_TONGUE) && (frog->fr_tongue != NULL) && (frog->fr_tongue->ef_flags & (TONGUE_FLAG_MOVING_IN | TONGUE_FLAG_GRABBING))) {
            frog->fr_no_input_timer = 0;
            tongue_target = FrogGetNearestTongueTarget(frog);
            if (tongue_target != NULL) {
                StartTongue(frog->fr_tongue, tongue_target);
                DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE, 0, TRUE);
            } else {
                StartTongue(frog->fr_tongue, NULL);
                DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE, 0, TRUE);
            }
            
            MRSNDPlaySound(SFX_GEN_FROG_SLURP, NULL, 0, 0);
        }
    }

    // Determine the length and type of jump.
    if (input & FROG_DIRECTION_SUPER_JUMP) {
        // Strip input data down to the direction to jump (in the current facing direction).
        if (frog->fr_flags & FROG_ON_ENTITY) {
            input = (frog->fr_direction - frog->fr_entity_angle) & 3;
        } else {
            input = (frog->fr_direction - camera->ca_frog_controller_directions[0]) & 3;
        }
        
        jump_type |= FROG_JUMP_SUPER;
        jump_time = FROG_SUPERJUMP_TIME;
    } else {
        jump_time = (frog->fr_powerup_flags & FROG_POWERUP_QUICK_JUMP) ? FROG_QUICK_JUMP_TIME : FROG_JUMP_TIME;
    }

    // If a directional jump should occur, do it.
    if (!(input & FROG_DIRECTION_NO_INPUT)) {
        frog->fr_no_input_timer = 0;
        JumpFrog(frog, input, jump_type, 1, jump_time);
    }

    // Save the current input.
    frog->fr_current_key = input;
}

/******************************************************************************
*%%%% FrogModeMovementStationary
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	FrogModeMovementStationary(
*								FROG*		frog,
*								MR_ULONG	mode,
*								MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is stationary. 
*	MATCH		https://decomp.me/scratch/wMB4c (By Kneesnap & sonicdcer)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementStationary(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
    LIVE_ENTITY* entity;
    MR_SVEC svec;
    MR_VEC vec;
    MR_ULONG flags = 0;

    if (frog->fr_flags & FROG_ON_ENTITY) {
        entity = frog->fr_entity->en_live_entity;
        svec.vx = (frog->fr_entity_ofs.vx >> 16);
        svec.vy = (frog->fr_entity_ofs.vy >> 16);
        svec.vz = (frog->fr_entity_ofs.vz >> 16);
        MRApplyMatrix(entity->le_lwtrans, &svec, &vec);
        frog->fr_pos.vx = ((vec.vx + entity->le_lwtrans->t[0]) << 16);
        frog->fr_pos.vy = ((vec.vy + entity->le_lwtrans->t[1]) << 16);
        frog->fr_pos.vz = ((vec.vz + entity->le_lwtrans->t[2]) << 16);
        frog->fr_y = (frog->fr_pos.vy >> 16);
        flags |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
    }

    if ((Cameras[frog->fr_frog_id].ca_move_timer == 0) && (Cameras[frog->fr_frog_id].ca_twist_counter == 0)) {
        frog->fr_mode = 0;
        frog->fr_num_buffered_keys = 0;
    }

    return flags | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
}

/******************************************************************************
*%%%% FrogModeMovementCentring
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	FrogModeMovementCentring(
*								FROG*		frog,
*								MR_ULONG	mode,
*								MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is centering. 
*	MATCH		https://decomp.me/scratch/y4Pga (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementCentring(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
    MR_SVEC pos;
    MR_VEC result;
    LIVE_ENTITY* entity;
    MR_ULONG flags = 0;
 
    if (--frog->fr_count == 0) {
        MR_CLEAR_VEC(&frog->fr_velocity);
        frog->fr_mode = FROG_MODE_STATIONARY;
        frog->fr_entity_ofs.vx = frog->fr_target_pos.vx << 16;
        frog->fr_entity_ofs.vy = frog->fr_target_pos.vy << 16;
        frog->fr_entity_ofs.vz = frog->fr_target_pos.vz << 16;
        FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
    } else {
        MR_ADD_VEC(&frog->fr_entity_ofs, &frog->fr_velocity);
    }

    // Get the frog's current position.
    entity = frog->fr_entity->en_live_entity;
    pos.vx = frog->fr_entity_ofs.vx >> 16;
    pos.vy = frog->fr_entity_ofs.vy >> 16;
    pos.vz = frog->fr_entity_ofs.vz >> 16;

    // Calculate & apply frog position.
    MRApplyMatrix(entity->le_lwtrans, &pos, &result);
    frog->fr_pos.vx = (result.vx + entity->le_lwtrans->t[0]) << 16;
    frog->fr_pos.vy = (result.vy + entity->le_lwtrans->t[1]) << 16;
    frog->fr_pos.vz = (result.vz + entity->le_lwtrans->t[2]) << 16;

    // Return flags. This needs to be on a separate line from the return statement in order to match.
    flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX | FROG_MOVEMENT_CALLBACK_UPDATE_POS;
    return flags;
}

/******************************************************************************
*%%%% FrogModeMovementHitCheckpoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	FrogModeMovementHitCheckpoint(
*								FROG*		frog,
*								MR_ULONG	mode,
*								MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is hitting a checkpoint. 
*	MATCH		https://decomp.me/scratch/SCbXg (By Kneesnap)
*				https://decomp.me/scratch/oCOTN (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementHitCheckpoint(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
    MR_SHORT cos;
    MR_SHORT sin;
    MR_ULONG flags = 0;
    LIVE_ENTITY* live_entity;

    if (Game_total_players > 1) { // Multiplayer
        if (frog->fr_count != 0) {
            if (--frog->fr_count == 0) {
                if (Game_mode != GAME_MODE_MULTI_COMPLETE) {
                    if (frog->fr_flags & FROG_ACTIVE) {
                        ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, GAME_MODE_LEVEL_FAST_START);
                        ResetCamera(&Cameras[frog->fr_frog_id]);
                    } else {
                        frog->fr_mode = FROG_MODE_NO_CONTROL;
                    }
                } else {
                    frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
                }
            }
            
            if (frog->fr_user_data1 != NULL) {
                live_entity = ((ENTITY*)frog->fr_user_data1)->en_live_entity;
                if (live_entity != NULL) {
                    cos = rcos(64);
                    sin = rsin(64);
                    MRRot_matrix_Y.m[0][0] = cos;
                    MRRot_matrix_Y.m[0][2] = sin;
                    MRRot_matrix_Y.m[2][0] = -sin;
                    MRRot_matrix_Y.m[2][2] = cos;
                    live_entity->le_lwtrans->t[1] -= 30;
                    MRMulMatrixABB(&MRRot_matrix_Y, live_entity->le_lwtrans);
                }
            }
        }
    } else { // Singleplayer.
        flags = (FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_UPDATE_POS);
        if (frog->fr_count != 0) {
            FrogModeMovementJumping(frog, mode, react_flags);
            flags &= ~FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
        }
        
        frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
    }
    
    return flags;
}

/******************************************************************************
*%%%% FrogUpdateFreefall
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	FrogUpdateFreefall(
*								FROG*		frog,
*
*	FUNCTION	Called to update freefall. 
*	MATCH		https://decomp.me/scratch/cS5pY (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogUpdateFreefall(FROG* frog) {
    MR_VEC vec;
    LIVE_ENTITY* live_entity;

    frog->fr_velocity.vy += SYSTEM_GRAVITY;
    if (((frog->fr_flags & (FROG_FREEFALL_NO_ANIMATION | FROG_FREEFALL)) == (FROG_FREEFALL_NO_ANIMATION | FROG_FREEFALL)) && (frog->fr_lwtrans->t[1] - frog->fr_old_y) >= 0) {
        if ((Game_map >= LEVEL_SKY1) && (Game_map <= LEVEL_SKY_MULTI_PLAYER)) {
            FrogRequestAnimation(frog, FROG_ANIMATION_FREEFALL, 0, 0);
        } else {
            FrogRequestAnimation(frog, FROG_ANIMATION_FALLING, 0, 0);
        }
        
        frog->fr_flags &= ~FROG_FREEFALL_NO_ANIMATION;
    }
    
    if ((frog->fr_entity != NULL) && !(frog->fr_flags & FROG_JUMP_TO_LAND)) {
        frog->fr_entity_ofs.vx += frog->fr_velocity.vx;
        frog->fr_entity_ofs.vz += frog->fr_velocity.vz;
        live_entity = frog->fr_entity->en_live_entity;
        MRApplyMatrixVEC(live_entity->le_lwtrans, &frog->fr_entity_ofs, &vec);
        frog->fr_pos.vx = (live_entity->le_lwtrans->t[0] << 16) + vec.vx;
        frog->fr_pos.vy += frog->fr_velocity.vy;
        frog->fr_pos.vz = (live_entity->le_lwtrans->t[2] << 16) + vec.vz;
    } else {
        frog->fr_pos.vx += frog->fr_velocity.vx;
        frog->fr_pos.vy += frog->fr_velocity.vy;
        frog->fr_pos.vz += frog->fr_velocity.vz;
    }
}

/******************************************************************************
*%%%% FrogModeMovementJumping
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_ULONG	FrogModeMovementJumping(
*								FROG*		frog,
*								MR_ULONG	mode,
*								MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is jumping. 
*	MATCH		https://decomp.me/scratch/Q62No (By Kneesnap)
*				https://decomp.me/scratch/91c0Y	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementJumping(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
    MR_SVEC svec;
    MR_VEC vec;
    MATRIX matrix;
    CAMERA* camera;
    FORM* form;
    GRID_SQUARE* grid_square;
    GRID_STACK* grid_stack;
    LIVE_ENTITY* entity;
    MR_LONG grid_square_height;
    MR_LONG flags;
    MR_USHORT gs_flags;
    MR_ULONG i;

    flags = 0;
    camera = &Cameras[frog->fr_frog_id];
    if (frog->fr_count != 0) {
        if (--frog->fr_count == 0) {
            if (frog->fr_flags & FROG_JUMP_FROM_ENTITY) {
                if (frog->fr_flags & FROG_JUMP_TO_ENTITY) {
                    entity = frog->fr_entity->en_live_entity;
                    
                    // Update frog flags.
                    frog->fr_flags &= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
                    frog->fr_flags |= FROG_ON_ENTITY;
                    frog->fr_mode = FROG_MODE_STATIONARY;
                    FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);

                    // Update position.
                    frog->fr_entity_ofs.vx = frog->fr_target_pos.vx << 16;
                    frog->fr_entity_ofs.vy = frog->fr_target_pos.vy << 16;
                    frog->fr_entity_ofs.vz = frog->fr_target_pos.vz << 16;
                    MRTransposeMatrix(entity->le_lwtrans, &matrix);
                    MRMulMatrixABC(frog->fr_lwtrans, &matrix, &frog->fr_entity_transform);
                    ProjectMatrixOntoWorldXZ(&frog->fr_entity_transform, &frog->fr_entity_transform);
                    entity = frog->fr_entity->en_live_entity;
                    svec.vx = frog->fr_entity_ofs.vx >> 16;
                    svec.vy = frog->fr_entity_ofs.vy >> 16;
                    svec.vz = frog->fr_entity_ofs.vz >> 16;
                    MRApplyMatrix(entity->le_lwtrans, &svec, &vec);
                    frog->fr_pos.vx = (vec.vx + entity->le_lwtrans->t[0]) << 16;
                    frog->fr_pos.vy = (vec.vy + entity->le_lwtrans->t[1]) << 16;
                    frog->fr_pos.vz = (vec.vz + entity->le_lwtrans->t[2]) << 16;
                    MR_CLEAR_VEC(&frog->fr_velocity);

                    // Get reaction grid flags from the form.
                    form = ENTITY_GET_FORM(entity->le_entity);
                    gs_flags = ((FORM_DATA**) &form->fo_formdata_ptrs)[0]->fd_grid_squares[(frog->fr_entity_grid_z * form->fo_xnum) + frog->fr_entity_grid_x];
                    *react_flags = gs_flags;

                    // Apply reaction.
                    flags = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS); 
                    if (!(gs_flags & GRID_SQUARE_SOFT)) {
                        FrogReactToFallDistance(frog, frog->fr_lwtrans->t[1] - frog->fr_old_y, *react_flags);
                    } else {
                        frog->fr_mode = FROG_MODE_STATIONARY;
                        FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0); 
                    }

                    return flags | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
                }

                // If the frog is not jumping to land, use the entity to calculate pos.
                if (!(frog->fr_flags & FROG_JUMP_TO_LAND)) {
                    FrogUpdateFreefall(frog);
                    flags |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
                    goto block_15;
                } else {
                    goto block_12;
                }
            }
            
            frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
            frog->fr_pos.vz = frog->fr_target_pos.vz << 16;
            if (frog->fr_flags & FROG_JUMP_TO_ENTITY) {
                frog->fr_flags &= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
                frog->fr_count = 0x7FFFFFF;
                frog->fr_velocity.vx = 0;
                frog->fr_velocity.vz = 0;
                flags = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS);
            } else if (frog->fr_flags & FROG_JUMP_TO_LAND) {
block_12:
                flags |= (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS);
                if (frog->fr_entity != NULL) {
                    ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
                    MRMulMatrixABA(&camera->ca_mod_matrix, &MRTemp_matrix);
                    frog->fr_entity = NULL;
                }
                
                FrogLandedOnLand(frog);
                *react_flags = frog->fr_grid_square->gs_flags;
            } else {
block_15:
                if (frog->fr_entity != NULL) {
                    ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
                    MRMulMatrixABA(&camera->ca_mod_matrix, &MRTemp_matrix);
                    frog->fr_entity = NULL;
                }

                // Search each grid stack for a usable square.
                if (frog->fr_grid_square == NULL) {
                    grid_stack = GetGridStack(frog->fr_grid_x, frog->fr_grid_z);
                    i = grid_stack->gs_numsquares;
                    grid_square = &Grid_squares[grid_stack->gs_index + i - 1];

                    while (i--) {
                        grid_square_height = GetGridSquareHeight(grid_square);
                        if ((grid_square->gs_flags & GRID_SQUARE_USABLE) && (grid_square_height >= frog->fr_lwtrans->t[1]))
                            goto set_grid_square;
                        
                        grid_square--;
                    }
                    grid_square = NULL;
                    
set_grid_square:
                    frog->fr_grid_square = grid_square;
                }

                // Update flags.
                frog->fr_flags &= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
                frog->fr_flags |= FROG_FREEFALL_NO_ANIMATION;
                frog->fr_flags |= FROG_FREEFALL;
                frog->fr_count = 0x7FFFFFF;
                frog->fr_velocity.vx = 0;
                frog->fr_velocity.vz = 0;
                flags |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
                flags |= FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS;
            }
        } else {
            FrogUpdateFreefall(frog);
            flags |= FROG_MOVEMENT_CALLBACK_UPDATE_POS;
        }
    }
    
    return flags | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
}

/******************************************************************************
*%%%% FrogModeMovementDying
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogModeMovementDying(
*						FROG*		frog,
*						MR_ULONG	mode,
*						MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is dying. 
*	MATCH		https://decomp.me/scratch/WT0s0 (By Kneesnap)
*				https://decomp.me/scratch/z1Vgp	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	01.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementDying(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
    MR_SVEC svec;
    MR_VEC vec;
    LIVE_ENTITY* live_entity;
    MR_ULONG flags = FROG_MOVEMENT_CALLBACK_UPDATE_POS;

    // Handle the frog being on an entity.
    if (frog->fr_flags & FROG_ON_ENTITY) {
        live_entity = frog->fr_entity->en_live_entity;
        if (live_entity != NULL) {
            svec.vx = frog->fr_entity_ofs.vx >> 16;
            svec.vy = frog->fr_entity_ofs.vy >> 16;
            svec.vz = frog->fr_entity_ofs.vz >> 16;
            MRApplyMatrix(live_entity->le_lwtrans, &svec, &vec);
            
            frog->fr_pos.vx = (vec.vx + live_entity->le_lwtrans->t[0]) << 16;
            frog->fr_pos.vy = (vec.vy + live_entity->le_lwtrans->t[1]) << 16;
            frog->fr_pos.vz = (vec.vz + live_entity->le_lwtrans->t[2]) << 16;
            frog->fr_y = frog->fr_pos.vy >> 16;
        }
    }

    // When the movement finishes.
    if (--frog->fr_death_count == 0) {
        if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS) { // Multiplayer
            frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
            if (frog->fr_flags & FROG_ACTIVE) {
                ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, GAME_MODE_LEVEL_PLAY);
                ResetCamera(&Cameras[frog->fr_frog_id]);
            } else {
                frog->fr_mode = FROG_MODE_NO_CONTROL;
            }
        } else { // Singleplayer
            frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
            if (frog->fr_lives == 0)
                frog->fr_flags &= ~FROG_ACTIVE;
            
            if (Game_mode == GAME_MODE_END_OF_GAME) {
                if (frog->fr_lives == 0) {
                    MRFreeMem(Game_mode_data);
                    Game_mode_data = NULL;
                    SetGameMainloopMode(GAME_MODE_SINGLE_FAILED);
                } else {
                    LevelEnd();
                    LevelStart(GAME_MODE_LEVEL_PLAY);
                }
            } else {
                SetGameMainloopMode(GAME_MODE_SINGLE_FROG_DIED);
            }
        }
    }

    // Handle position updates, unless the animation disables them.
    if ((frog->fr_death_equate == FROG_ANIMATION_MOWN) || (frog->fr_death_equate == FROG_ANIMATION_BITTEN)) {
        flags = 0;
    } else {
        if ((frog->fr_entity != NULL) && (frog->fr_entity->en_live_entity == NULL)) {
            frog->fr_entity = NULL;
            frog->fr_count = 0;
            frog->fr_flags &= ~FROG_LANDED_ON_LAND_CLEAR_MASK;
        }
        
        if (frog->fr_count != 0) {
            FrogModeMovementJumping(frog, mode, react_flags);
            frog->fr_mode = FROG_MODE_DYING;
            flags |= FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS;
        } else {
            frog->fr_pos.vx += frog->fr_velocity.vx;
            frog->fr_pos.vy += frog->fr_velocity.vy;
            frog->fr_pos.vz += frog->fr_velocity.vz;
            flags |= FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;

            // Webs cavern has special logic for handling velocity (Probably related to webs)
            if (Game_map == LEVEL_CAVES3) {
                frog->fr_velocity.vx = frog->fr_velocity.vx * 14 >> 4;
                frog->fr_velocity.vy = frog->fr_velocity.vy * 14 >> 4;
                frog->fr_velocity.vz = frog->fr_velocity.vz * 14 >> 4;
            }
        }
    }

    return flags;
}

/******************************************************************************
*%%%% FrogModeMovementStunned
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogModeMovementStunned(
*						FROG*		frog,
*						MR_ULONG	mode,
*						MR_ULONG*	react_flags)
*
*	FUNCTION	The movement update hook called while the frog is stunned (from a fall). 
*	MATCH		https://decomp.me/scratch/BvHQ3 (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				mode		-	the current game mode
*				react_flags	-	A pointer to grid reaction bit flags, which can be set to cause a reaction
*
*	RESULT		move_flags	-	Movement callback flags to indicate further required action
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_ULONG FrogModeMovementStunned(FROG* frog, MR_ULONG mode, MR_ULONG* react_flags) {
	if (--frog->fr_count == 0) {
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
	}
	
	return FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
}

/******************************************************************************
*%%%% FrogLandedOnLand
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogLandedOnLand(
*						FROG*	frog)
*
*	FUNCTION	Handles the frog landing on land
*	MATCH		https://decomp.me/scratch/4fZKI (By Kneesnap)
*				https://decomp.me/scratch/PP6JY (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogLandedOnLand(FROG* frog) {
    MR_SVEC grid_square_centre;
    CAMERA* camera;

    // Get camera.
    camera = &Cameras[frog->fr_frog_id];

    // Snap frog position to grid square.
    GetGridSquareCentre(frog->fr_grid_square, &grid_square_centre);
    if (!(frog->fr_grid_square->gs_flags & GRID_SQUARE_DONT_CENTRE_WHEN_LANDED_MASK)) {
        frog->fr_pos.vx = grid_square_centre.vx << 16;
        frog->fr_pos.vy = grid_square_centre.vy << 16;
        frog->fr_pos.vz = grid_square_centre.vz << 16;
    }
    
    frog->fr_y = frog->fr_pos.vy >> 16;
    if (!(frog->fr_grid_square->gs_flags & GRID_SQUARE_SOFT)) {
        FrogReactToFallDistance(frog, frog->fr_y - frog->fr_old_y, frog->fr_grid_square->gs_flags);
    } else {
        frog->fr_mode = FROG_MODE_STATIONARY;
        FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
    }

    // Reset data
    frog->fr_entity = NULL;
    frog->fr_forbid_entity = NULL;
    MR_CLEAR_VEC(&frog->fr_velocity);
	
    frog->fr_old_y = frog->fr_y;
    frog->fr_flags &= ~FROG_LANDED_ON_LAND_CLEAR_MASK;
    if (camera->ca_twist_counter == 0)
        SetupCameraYRotation(camera);

    // Update direction
    frog->fr_old_direction = frog->fr_direction;
    frog->fr_direction = GetWorldYQuadrantFromMatrix(frog->fr_lwtrans);
}

/******************************************************************************
*%%%% FrogReactToFallDistance
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogReactToFallDistance(
*						FROG*	frog,
*						MR_LONG	distance,
*						MR_USHORT react_flags)
*
*	FUNCTION	Reacts to falling a specified distance
*	MATCH		https://decomp.me/scratch/Tox8o (By Kneesnap)
*				https://decomp.me/scratch/AUzFn	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				distance	-	the distance the frog fell
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogReactToFallDistance(FROG* frog, MR_LONG distance, MR_USHORT react_flags) {
    MR_VEC vec;
    MR_OBJECT* sprite;
    MR_LONG i;
    MR_OT** local_ot_ptr;
    
    if (distance <= FROG_FREEFALL_SAFE_HEIGHT) {
        frog->fr_mode = FROG_MODE_STATIONARY;
        FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0, 0);
    } else if (distance <= FROG_FREEFALL_STUN_HEIGHT) {
        frog->fr_mode = FROG_MODE_STUNNED;
        frog->fr_count = FROG_FREEFALL_STUN_TIME;
        MRSNDPlaySound(SFX_GEN_FROG_STUNNED, NULL, 0, 0);
        FrogRequestAnimation(frog, FROG_ANIMATION_CRASH, 0, 0);
        ShakeCamera(&Cameras[frog->fr_frog_id], MR_OBJ_STATIC, frog->fr_count, CAMERA_SHAKE_FREQ_Y);
    } else {
        frog->fr_mode = FROG_MODE_STATIONARY;
        if (react_flags & GRID_SQUARE_DEADLY) {
            if (Game_map_theme == THEME_FOR) {
                MRSNDPlaySound(SFX_GEN_FROG_THUD, NULL, 0, 0);
                FrogKill(frog, FROG_ANIMATION_FLOP, NULL);
            } else {
                MR_SET_VEC(&vec, 0, 1<<16, 0);
                FrogKill(frog, FROG_ANIMATION_DROWN, &vec);
            }
        } else if (react_flags & GRID_SQUARE_POPDEATH) {
            FrogKill(frog, FROG_ANIMATION_POP, NULL);
        } else if (react_flags & GRID_SQUARE_WATER) {
            MR_SET_VEC(&vec, 0, 1<<16, 0);
            FrogKill(frog, FROG_ANIMATION_DROWN, &vec);

            // Create water bubble particle for drowning
            MR_INIT_MAT(&Frog_splash_matrix);
            MR_COPY_VEC(&Frog_splash_matrix.t, &frog->fr_lwtrans->t);
            sprite = MRCreate3DSprite((MR_FRAME*)&Frog_splash_matrix, MR_OBJ_STATIC, &FrogSplashAnimList);
            sprite->ob_extra.ob_extra_3dsprite->sp_core.sc_flags |= MR_SPF_IN_XZ_PLANE;
            sprite->ob_extra.ob_extra_3dsprite->sp_core.sc_ot_offset = -0x10; 
            GameAddObjectToViewports(sprite);
            if (frog->fr_particle_api_item == NULL)
                frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_WATER_BUBBLE, 0);
                    
            MRSNDPlaySound(SFX_GEN_FROG_DROWN2, NULL, 0, 0);

#ifdef PSX
		//Only on suburbia and original
		if ((Game_map_theme == THEME_ORG) || (Game_map_theme == THEME_SUB))
			{
			// Set frog to have a LARGE ot position, so he appears below the env_map.
			i = Game_total_viewports;
			local_ot_ptr = frog->fr_ot;
			while(i--)
				{
				local_ot_ptr[0]->ot_flags |= MR_OT_FORCE_BACK;
				local_ot_ptr++;
				}
			}
#endif
        } else {
            FrogKill(frog, FROG_ANIMATION_SQUISHED, NULL);
        }
    }
}

/******************************************************************************
*%%%% UpdateFrogEffects
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogEffects(
*						FROG*	frog)
*
*	FUNCTION	Updates visual effects for the frog.
*	MATCH		https://decomp.me/scratch/rG7nV (By Kneesnap)
*				https://decomp.me/scratch/h71DW	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID UpdateFrogEffects(FROG* frog) {
    SHADOW* shadow;
    EFFECT* shadow_effect;
    MR_LONG count;

    // Update the shadow displayed under the frog to show at the right position & show the right texture.
    shadow_effect = frog->fr_shadow;
    if (shadow_effect != NULL) {
        if (frog->fr_entity == NULL && (frog->fr_flags & FROG_ACTIVE) && (frog->fr_mode != FROG_MODE_DYING) && (frog->fr_mode != FROGUSER_MODE_CHECKPOINT_COLLECTED) && ((frog->fr_mode != FROG_MODE_JUMPING) || (frog->fr_flags & FROG_JUMP_TO_LAND)) && (Game_mode != GAME_MODE_SINGLE_COMPLETE)) {
            shadow = shadow_effect->ef_extra;
            if (frog->fr_mode == FROG_MODE_JUMPING && !(frog->fr_flags & FROG_JUMP_ON_SPOT)) {
                if (frog->fr_flags & FROG_SUPERJUMP) {
                    count = ((FROG_SUPERJUMP_TIME - frog->fr_count) * FROG_JUMP_TIME) / FROG_SUPERJUMP_TIME;
                } else {
                    count = FROG_JUMP_TIME - frog->fr_count;
                }

                // Get the count to within the bounds of the array.
                if (count >= FROG_JUMP_TIME)
                    count = FROG_JUMP_TIME - 1;

                if (count < 0)
                    count = 0;
            } else {
                count = 0;
            }
            
            shadow->sh_offsets = Frog_jump_shadow_offsets[count];
            shadow->sh_texture = Frog_jump_shadow_textures[count];
            shadow_effect->ef_flags &= ~(EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
        } else {
            shadow_effect->ef_flags |= (EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
        }
    }

    // Update poly piece pop if it's active.
    if ((frog->fr_poly_piece_pop != NULL) && (frog->fr_poly_piece_pop->pp_timer != 0))
        UpdatePolyPiecePop(frog->fr_poly_piece_pop);
}

/******************************************************************************
*%%%% TestFrogHasLineOfSight
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	TestFrogHasLineOfSight(
*						FROG*			frog,
*						LIVE_ENTITY*	entity)
*
*	FUNCTION	Test if the frog has line of sight to the given entity
*	MATCH		https://decomp.me/scratch/NFPxQ (By Kneesnap)
*
*	INPUTS		frog	-	pointer to the frog
*				entity	-	pointer to the entity to test
*
*
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_ULONG TestFrogHasLineOfSight(FROG* frog, LIVE_ENTITY* entity) {
    GRID_LINE_INTER intersection;
    MR_XY grid_pos;
    MR_SVEC frog_pos;
    MR_SVEC target_pos;
    GRID_SQUARE* grid_square;
    GRID_STACK* grid_stack;
    MR_LONG min_height;
    MR_LONG i;

    // Form a line between the frog and the provided entity, and initialize the grid intersection test.
    MR_SVEC_EQUALS_VEC(&frog_pos, &frog->fr_lwtrans->t);
    MR_SVEC_EQUALS_VEC(&target_pos, &entity->le_lwtrans->t);
    GetNextGridLineIntersectionInit(&frog_pos, &target_pos, &intersection);

    do {
        grid_pos = GetNextTileInteresectingLine(&intersection);
        grid_stack = GetGridStack(grid_pos.x, grid_pos.y);

        // Check all grid squares in the stack to see if any obstruct line of sight between the frog & entity.
        i = grid_stack->gs_numsquares;
        if (i != 0) {
            grid_square = &Grid_squares[grid_stack->gs_index];
            min_height = intersection.curr_pos.vy - FROG_TONGUE_ALLOWANCE_HEIGHT;

            while (i--) {
                if (min_height > Map_vertices[grid_square->gs_map_poly->mp_vertices[0]].vy)
                    return LI_MODE_START;

                if (min_height > Map_vertices[grid_square->gs_map_poly->mp_vertices[1]].vy)
                    return LI_MODE_START;

                if (min_height > Map_vertices[grid_square->gs_map_poly->mp_vertices[2]].vy)
                    return LI_MODE_START;

                grid_square++;
            }
        }

        // If the intersection process has completed, it's time to exit.
        if (intersection.mode == LI_MODE_DONE)
            return LI_MODE_DONE;
    } while (TRUE);
}

/******************************************************************************
*%%%% FrogGetNearestTongueTarget
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ENTITY*	FrogGetNearestTongueTarget(
*							FROG*	frog)
*
*	FUNCTION	Gets the nearest tongue target which the frog can eat, if one exists within tongue range
*	MATCH		https://decomp.me/scratch/vyiLA (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	RESULT		entity		-	pointer to nearest tongueable entity with line of sight
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

ENTITY* FrogGetNearestTongueTarget(FROG* frog) {
    MR_MAT matrix;
    MR_VEC unused_vec;
    MR_SVEC distance_vec;
    MR_LONG x, minX, maxX;
    MR_LONG z, minZ, maxZ;
    MR_LONG distance, best_distance;
    LIVE_ENTITY *best_entity, *live_entity;
    ENTITY_BOOK *entity_book;
    ENTITY *entity;

    // Setup rotation matrix.
    MRTransposeMatrix(frog->fr_lwtrans, &matrix);
    gte_SetRotMatrix(&matrix);
    best_entity = NULL;

    // Set tongue distance.
    best_distance = TONGUE_TARGETTABLE_RADIUS2;
    if (frog->fr_powerup_flags & FROG_POWERUP_SUPER_TONGUE)
        best_distance = SUPERTONGUE_TARGETTABLE_RADIUS2;

    // Calculate the minimum and maximum bounds to search.
    x = (frog->fr_lwtrans->t[0] - Map_view_basepoint.vx) / Map_view_xlen;
    z = (frog->fr_lwtrans->t[2] - Map_view_basepoint.vz) / Map_view_zlen;
    minX = MAX(x - 1, 0);
    maxX = MIN(Map_view_xnum - 1, x + 1);
    minZ = MAX(z - 1, 0);
    maxZ = MIN(Map_view_znum - 1, z + 1);

    // Go through map groups to find the closest tongueable entity.
    for (z = minZ; z <= maxZ; z++) {
        for (x = minX; x <= maxX; x++) {
            entity = Map_groups[(z * Map_view_xnum) + x].mg_entity_root_ptr;
            while (entity = entity->en_next) {
                live_entity = entity->en_live_entity;
                if (live_entity != NULL && !(live_entity->le_flags & LIVE_ENTITY_TARGETTED)) {
                    entity_book = ENTITY_GET_ENTITY_BOOK(entity);
                    if (entity_book->eb_flags & ENTITY_BOOK_TONGUEABLE) {
                        distance_vec.vx = live_entity->le_lwtrans->t[0] - frog->fr_lwtrans->t[0];
                        distance_vec.vy = live_entity->le_lwtrans->t[1] - frog->fr_lwtrans->t[1];
                        distance_vec.vz = live_entity->le_lwtrans->t[2] - frog->fr_lwtrans->t[2];
                        MRApplyRotMatrix(&distance_vec, &unused_vec);
                        MRNormaliseVEC(&unused_vec, &unused_vec);
                        
                        // Test if the entity is closer than the current best entity.
                        distance = MR_SVEC_MOD_SQR(&distance_vec);
                        if (distance < best_distance && (TestFrogHasLineOfSight(frog, live_entity) != 0)) {
                            best_entity = live_entity;
                            best_distance = distance;
                        }
                    }
                }  
            }  
        }
    }

    // If an entity was found, return it.
    if (best_entity != NULL)
        return best_entity->le_entity;
    
    return NULL;
}

/******************************************************************************
*%%%% UpdateFrogMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogMatrix(
*							FROG*	frog)
*
*	FUNCTION	Updates the frog's translation matrix
*	MATCH		https://decomp.me/scratch/JowxA (By Kneesnap)
*				https://decomp.me/scratch/fiwfW	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (PSX Retail)
*
*%%%**************************************************************************/

MR_VOID UpdateFrogMatrix(FROG* frog) {
    MR_VEC vec1;
    MR_VEC vec2;
    MR_VEC vec3;
    MR_VEC vec4;
    MR_SVEC svec;
    MR_VEC* direction_vec;
    MR_MAT* matrix;

    if (frog->fr_flags & FROG_ON_ENTITY) {
		if (frog->fr_entity->en_live_entity != NULL) {
		    matrix = frog->fr_entity->en_live_entity->le_lwtrans;
		    MRMulMatrixABC(matrix, &frog->fr_entity_transform, frog->fr_lwtrans);
		}
    } else if (frog->fr_flags & FROG_FREEFALL) {
        vec1.vx = -frog->fr_lwtrans->m[0][1];
        vec1.vy = -frog->fr_lwtrans->m[1][1];
        vec1.vz = -frog->fr_lwtrans->m[2][1];
        vec4.vx = frog->fr_lwtrans->m[0][2];
        vec4.vy = frog->fr_lwtrans->m[1][2];
        vec4.vz = frog->fr_lwtrans->m[2][2];
        MRNormaliseVEC(&vec1, &vec1);
        MRNormaliseVEC(&vec4, &vec4);
    } else {
        if ((frog->fr_flags & (FROG_JUMP_TO_LAND | FROG_JUMP_FROM_ENTITY)) == FROG_JUMP_FROM_ENTITY) {
            matrix = frog->fr_entity->en_live_entity->le_lwtrans;

            // Apply rotation to face correct direction while on land..
            MR_SVEC_EQUALS_VEC(&svec, &Frog_fixed_vectors[frog->fr_direction]);
            MRApplyMatrix(matrix, &svec, &vec4);
            direction_vec = &vec4;

            // Apply it to the vector.
            vec1.vx = -frog->fr_lwtrans->m[0][1];
            vec1.vy = -frog->fr_lwtrans->m[1][1];
            vec1.vz = -frog->fr_lwtrans->m[2][1];
            MRNormaliseVEC(&vec1, &vec1);
        } else {
            if ((frog->fr_flags & FROG_JUMP_TO_ENTITY) || frog->fr_grid_square == NULL) {
                vec1.vx = -frog->fr_lwtrans->m[0][1];
                vec1.vy = -frog->fr_lwtrans->m[1][1];
                vec1.vz = -frog->fr_lwtrans->m[2][1];
                MRNormaliseVEC(&vec1, &vec1);
            } else {
                GetGridSquareAverageNormal(frog->fr_grid_square, &vec1);
            }
            
            direction_vec = &Frog_fixed_vectors[frog->fr_direction];
        }
        
        MROuterProduct12(direction_vec, &vec1, &vec2);
        MRNormaliseVEC(&vec2, &vec2);
        MROuterProduct12(&vec1, &vec2, &vec3);
        frog->fr_lwtrans->m[0][0] = vec2.vx;
        frog->fr_lwtrans->m[1][0] = vec2.vy;
        frog->fr_lwtrans->m[2][0] = vec2.vz;
        frog->fr_lwtrans->m[0][1] = -vec1.vx;
        frog->fr_lwtrans->m[1][1] = -vec1.vy;
        frog->fr_lwtrans->m[2][1] = -vec1.vz;
        frog->fr_lwtrans->m[0][2] = vec3.vx;
        frog->fr_lwtrans->m[1][2] = vec3.vy;
        frog->fr_lwtrans->m[2][2] = vec3.vz;
    }
    
    if (frog->fr_flags & FROG_SCALING_UP) {
        frog->fr_scale += (frog->fr_max_scale - frog->fr_scale) / (frog->fr_scale_up_time - frog->fr_scale_timer);
        
        if (++frog->fr_scale_timer == frog->fr_scale_up_time) {
            frog->fr_flags &= ~FROG_SCALING_UP;
            frog->fr_flags |= FROG_SCALING_DOWN;
            frog->fr_scale_timer = frog->fr_scale_down_time;
        }

        // Create scaled identity matrix.
        MR_SCALE_MATRIX(frog->fr_lwtrans, frog->fr_scale, frog->fr_scale, frog->fr_scale);
    } else if (frog->fr_flags & FROG_SCALING_DOWN) {
        frog->fr_scale += (FROG_CROAK_MAX_SCALE - frog->fr_scale) / frog->fr_scale_timer;
        if (--frog->fr_scale_timer == 0)
            frog->fr_flags &= ~FROG_SCALING_DOWN;
        
        // Create scaled identity matrix.
        MR_SCALE_MATRIX(frog->fr_lwtrans, frog->fr_scale, frog->fr_scale, frog->fr_scale);
    }
}

/******************************************************************************
*%%%% FrogSetScaling
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogSetScaling(
*							FROG*	frog,
*							MR_LONG	max_scale,
*							MR_LONG	scale_up_time,
*							MR_LONG	scale_down_time)
*
*	FUNCTION	Sets the scale of the provided frog
*	MATCH		https://decomp.me/scratch/P5wUG (By Kneesnap)
*
*	INPUTS		frog			-	pointer to the frog
*				max_scale		-	max size to grow to
*				scale_up_time	-	time to shrink grow to large size
*				scale_down_time	-	time to shrink back to normal size
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogSetScaling(FROG* frog, MR_LONG max_scale, MR_LONG scale_up_time, MR_LONG scale_down_time) {
	frog->fr_scale_up_time = scale_up_time;
	frog->fr_scale_down_time = scale_down_time;
	frog->fr_scale_timer = 0;
	frog->fr_max_scale = max_scale;
	frog->fr_flags |= FROG_SCALING_UP;
}

/******************************************************************************
*%%%% FrogCollectCheckPoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogCollectCheckPoint(
*							FROG*	frog,
*							ENTITY*	checkpoint_entity)
*
*	FUNCTION	Handle collection of a checkpoint entity
*	MATCH		https://decomp.me/scratch/m9N5z (By Kneesnap)
*				https://decomp.me/scratch/fpIap	(By Kneesnap)
*
*	INPUTS		frog				-	pointer to the frog
*				checkpoint_entity	-	pointer to the collected checkpoint entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogCollectCheckPoint(FROG* frog, ENTITY* checkpoint_entity) {
    MR_LONG checkpoint_count[4];
    MR_LONG max_checkpoints;
    MR_LONG num_winning_frogs;
    CAMERA* camera;
    MR_LONG entity_type;
    MR_LONG checkpoint_id;
    GEN_CHECKPOINT_DATA* checkpoint;

    entity_type = ENTITY_GET_FORM_BOOK(checkpoint_entity)->fb_entity_type;
    if ((frog->fr_flags & FROG_MUST_DIE) || (frog->fr_mode == FROG_MODE_DYING))
        return;
    
    if (entity_type == ENTITY_TYPE_GEN_GOLD_FROG) {
        FrogCollectGoldFrog(frog, checkpoint_entity);
    } else {
        DampenMusicVolumeTemporarily();
        Game_pausing_xa = TRUE;
        LiveEntityChangeVolume(0, 0);
        checkpoint_id = checkpoint_entity->en_form_book_id & 0x7FFF;
        if (checkpoint_id >= GEN_MAX_CHECKPOINTS)
            checkpoint_id -= 11; // The offset in formlib to the multiplayer models.

        // If the checkpoint is already obtained, get outta here.
        if (Checkpoints & (1 << checkpoint_id))
            return;

        // Update global checkpoint state.
        Checkpoints |= 1 << checkpoint_id;
        Checkpoint_last_collected = checkpoint_id;

        // Update checkpoint data.
        checkpoint = &Checkpoint_data[checkpoint_id];
        checkpoint->cp_frog_collected_id = frog->fr_frog_id;
        checkpoint->cp_time = Game_map_timer_decimalised;
        if (Game_total_players == 1) // Singleplayer
            checkpoint->cp_flags |= GEN_CHECKPOINT_NO_HUD_UPDATE;

        // Add score.
        AddFrogScore(frog, SCORE_500, 0);
        if (Sel_mode == 0) {
            // Round up
            while (Game_map_timer_decimalised != 0 && (Game_map_timer_decimalised != (Game_map_timer_decimalised / 30) * 30))
                Game_map_timer_decimalised++;
            
             if (Game_map_timer_decimalised >= 2971) {
                Frog_time_data[checkpoint_id] = 99;
            } else {
                Frog_time_data[checkpoint_id] = (Game_map_timer_decimalised) / 30;
            }
        }

        // Play collection sound.
        if ((Checkpoints != GEN_ALL_CHECKPOINTS) || (Game_total_players == 1))
            MRSNDPlaySound(SFX_MUSIC_TARGET_COMPLETE, NULL, 0, MusicPitchTable[Game_map][0] << 7);

        // Play animation, and update frog.
        if (Game_total_players > 1) { // Multiplayer
            frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
            frog->fr_count = FROG_MULTIPLAYER_HIT_CHECKPOINT_DELAY;
            frog->fr_user_data1 = Checkpoint_data[Checkpoint_last_collected].cp_entity;
            FrogRequestAnimation(frog, FROG_ANIMATION_COMPLETE, 0, 0);
            if ((Checkpoints == GEN_ALL_CHECKPOINTS) || (GameGetMultiplayerFrogCheckpointData(checkpoint_count, &max_checkpoints, &num_winning_frogs), (max_checkpoints == 3))) {
                SetGameMainloopMode(GAME_MODE_MULTI_COMPLETE);
                DampenMusicVolumeTemporarily();
                Game_pausing_xa = TRUE;
            } else {
                ((MR_OBJECT*)(Checkpoint_data[Checkpoint_last_collected].cp_entity->en_live_entity->le_api_item0))->ob_flags |= MR_OBJ_NO_DISPLAY;
            }
        } else { // Singleplayer
            FrogRequestAnimation(frog, FROG_ANIMATION_COMPLETE, 0, 0);
            if (frog->fr_mode != FROG_MODE_JUMPING)
                frog->fr_count = 0;
            
            frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
            SetGameMainloopMode(GAME_MODE_SINGLE_TRIGGER_COLLECTED);
        }
    }

    // Kill particle effect.
    if (frog->fr_particle_api_item != NULL)
        FROG_KILL_PARTICLE_EFFECT(frog);

    // Setup checkpoint camera behavior.
    if ((entity_type != ENTITY_TYPE_GEN_GOLD_FROG) && ((camera = &Cameras[frog->fr_frog_id], (camera->ca_zone == NULL)) || !(((ZONE_CAMERA*) (camera->ca_zone + 1))->zc_flags & ZONE_FLAG_CHECKPOINT))) {
        camera = &Cameras[frog->fr_frog_id];
        camera->ca_next_source_ofs.vx = CAMERA_FROG_CHECKPOINT_SOURCE_OFS_X;
        camera->ca_next_source_ofs.vy = CAMERA_FROG_CHECKPOINT_SOURCE_OFS_Y;
        camera->ca_next_source_ofs.vz = CAMERA_FROG_CHECKPOINT_SOURCE_OFS_Z;
        camera->ca_next_target_ofs.vx = CAMERA_FROG_CHECKPOINT_TARGET_OFS_X;
        camera->ca_next_target_ofs.vy = CAMERA_FROG_CHECKPOINT_TARGET_OFS_Y;
        camera->ca_next_target_ofs.vz = CAMERA_FROG_CHECKPOINT_TARGET_OFS_Z;
        camera->ca_move_timer = CAMERA_FROG_CHECKPOINT_TIME;
    }
}

/******************************************************************************
*%%%% FrogCollectGoldFrog
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogCollectGoldFrog(
*							FROG*	frog,
*							ENTITY*	checkpoint)
*
*	FUNCTION	Handle collection of a golden frog entity
*	MATCH		https://decomp.me/scratch/ae9kB (By Kneesnap & nim-ka)
*
*	INPUTS		frog		-	pointer to the frog
*				checkpoint	-	pointer to the collected golden frog entity
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogCollectGoldFrog(FROG* frog, ENTITY* checkpoint) {
    if (Gold_frogs & (1 << Game_map_theme))
        return; // Frog already collected.
    
    MRSNDPlaySound(SFX_MUSIC_GOLD_COMPLETE, NULL, 0, MusicPitchTable[Game_map][0] << 7);
    AddFrogScore(frog, SCORE_1000, NULL);
    Gold_frogs |= (1 << Game_map_theme);
    Gold_frogs_current |= (1 << Game_map_theme);
    Gold_frog_data.gf_frog_collected_id = Frogs[0].fr_frog_id;
    SelectLevelCollectGoldFrog();
}

/******************************************************************************
*%%%% FrogUpdateCroak
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogUpdateCroak(
*							FROG*	frog)
*
*	FUNCTION	Updates the frog's croak
*	MATCH		https://decomp.me/scratch/KeCQC (By Kneesnap)
*				https://decomp.me/scratch/x9yIH	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogUpdateCroak(FROG* frog) {
    MR_VEC vec;
    MR_SVEC svec;
    MR_MAT matrix;
    FROG *curr_frog;
    MR_LONG i;
    ENTITY* checkpoint;
    GEN_CHECKPOINT_DATA* checkpoint_data;
    MR_ULONG croak_timer;

    if (!(Game_flags & GAME_FLAG_DEMO_RUNNING)) {
        switch (frog->fr_croak_mode) {
        case FROG_CROAK_NONE:
            if ((Cheat_control_toggle == FALSE) && (frog->fr_flags & FROG_CONTROL_ACTIVE) && (frog->fr_mode != FROG_MODE_HIT_CHECKPOINT) && MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_croak_control)) {
                DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_CROAK, 0, TRUE);
                if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS) { // High-poly
                    MRAnimEnvSingleSetPartFlags((MR_ANIM_ENV* ) frog->fr_api_item, THROAT, MR_ANIM_PART_DISPLAY); 
                    frog->fr_croak_mode = FROG_CROAK_INFLATE;
                    frog->fr_croak_timer = FROG_CROAK_INFLATE_TIME;
                }

                // Setup croak data & play sound.
                Cav_light_switch = FALSE;
                frog->fr_croak_radius_max = Map_light_max_r2;
                frog->fr_croak_radius_min = Map_light_min_r2;
                frog->fr_croak_rate = Map_light_max_r2 / FROG_CROAK_INFLATE_TIME;
                MRSNDPlaySound(SFX_GEN_FROG_CROAK, NULL, 0, 0);

                // Freeze other frogs in multiplayer (ignoring the player who croaked). 
                curr_frog = Frogs;
                i = Game_total_players;
                while (i--) {
                    if ((curr_frog != frog) && (curr_frog->fr_stack_master == NULL) && (curr_frog->fr_stack_slave == NULL)) {
                        MRTransposeMatrix(curr_frog->fr_lwtrans, &matrix);
                        svec.vx = frog->fr_lwtrans->t[0] - curr_frog->fr_lwtrans->t[0];
                        svec.vy = frog->fr_lwtrans->t[1] - curr_frog->fr_lwtrans->t[1];
                        svec.vz = frog->fr_lwtrans->t[2] - curr_frog->fr_lwtrans->t[2];
                        MRApplyMatrix(&matrix, &svec, &vec);
                        
                        if ((MR_ULONG) (vec.vz + 319) < 319 && (abs(vec.vx) + 20) < -vec.vz && (curr_frog->fr_mode == FROG_MODE_STATIONARY)) {
                            JumpFrogOnSpot(curr_frog, 12);
                            MRSNDPlaySound(SFX_GEN_FROG_SCARED, NULL, 0, 0);
                        }
                    }
                    curr_frog++;
                }
            }
            break;
        case FROG_CROAK_INFLATE:
            croak_timer = --frog->fr_croak_timer;
            Map_light_max_r2 += frog->fr_croak_rate;
            Map_light_min_r2 += frog->fr_croak_rate;
            frog->fr_croak_scale = (((FROG_CROAK_INFLATE_TIME - croak_timer) * 0xA00) / FROG_CROAK_INFLATE_TIME) + FROG_CROAK_MIN_SCALE;
            
            if (frog->fr_croak_timer == 0) {
                frog->fr_croak_mode = FROG_CROAK_HOLD;
                frog->fr_croak_timer = FROG_CROAK_HOLD_TIME;
            }
            break;
        case FROG_CROAK_HOLD:
            if (--frog->fr_croak_timer == 0) {
                frog->fr_croak_mode = FROG_CROAK_DEFLATE;
                frog->fr_croak_timer = FROG_CROAK_DEFLATE_TIME;
            }
            break;
        case FROG_CROAK_DEFLATE:
            croak_timer = --frog->fr_croak_timer;
            Map_light_max_r2 -= frog->fr_croak_rate;
            Map_light_min_r2 -= frog->fr_croak_rate;
            frog->fr_croak_scale = ((croak_timer * 0xA00) / FROG_CROAK_DEFLATE_TIME) + FROG_CROAK_MIN_SCALE;
            
            if (frog->fr_croak_timer == 0) {
                frog->fr_croak_mode = FROG_CROAK_NONE;
                Cav_light_switch = TRUE;
                Map_light_max_r2 = frog->fr_croak_radius_max;
                Map_light_min_r2 = frog->fr_croak_radius_min;
                if (Game_total_players <= GAME_MAX_HIGH_POLY_PLAYERS)
                    MRAnimEnvSingleClearPartFlags((MR_ANIM_ENV* ) frog->fr_api_item, THROAT, MR_ANIM_PART_DISPLAY);
                
                checkpoint = FrogGetNearestCheckpoint(frog);
                if (checkpoint != NULL) {
                    if (ENTITY_GET_ENTITY_TYPE(checkpoint) == ENTITY_TYPE_GEN_GOLD_FROG) {
                        if (checkpoint->en_live_entity != NULL)
                            PlayMovingSound(checkpoint->en_live_entity, SFX_GEN_GOLD_FROG_CROAK, -1, -1);
                    } else {
                        checkpoint_data = &Checkpoint_data[(((GEN_CHECKPOINT*)(checkpoint + 1))->cp_id)];
                        checkpoint_data->cp_croak_mode = FROG_CROAK_INFLATE;
                        checkpoint_data->cp_croak_timer = FROG_CROAK_INFLATE_TIME;
                        if (checkpoint->en_live_entity != NULL)
                            PlayMovingSound(checkpoint->en_live_entity, SFX_GEN_BABY_FROG, -1, -1);
                    }
                }
            }
            break;
        }
    }

    // Setup identity matrix multiplied by a scalar (fr_croak_scale).
    frog->fr_croak_scale_matrix.m[0][0] = frog->fr_croak_scale;
    frog->fr_croak_scale_matrix.m[1][1] = frog->fr_croak_scale;
    frog->fr_croak_scale_matrix.m[2][2] = frog->fr_croak_scale;
}

/******************************************************************************
*%%%% FrogGetNearestCheckpoint
*------------------------------------------------------------------------------
*
*	SYNOPSIS	ENTITY*	FrogGetNearestCheckpoint(
*							FROG*	frog)
*
*	FUNCTION	Gets the nearest checkpoint to the frog
*	MATCH		https://decomp.me/scratch/rO6rW (By Kneesnap)
*				https://decomp.me/scratch/4IdAn	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	RESULT		checkpoint	-	nearest checkpoint to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

ENTITY* FrogGetNearestCheckpoint(FROG* frog) {
    MR_VEC gold_frog_pos;
    MR_VEC pos_offset;
    ENTITY* entity;
    ENTITY* result;
    MR_LONG temp_distance;
    MR_LONG closest_distance;
    MR_LONG i;

    // Check each checkpoint frog/flag to find the closest one
    result = NULL;
    closest_distance = FROG_CROAK_TARGET_RADIUS2;
    for (i = 0; i < GEN_MAX_CHECKPOINTS; i++) {
        if (Checkpoint_data[i].cp_frog_collected_id == -1) {
            entity = Checkpoint_data[i].cp_entity;
            if (entity != NULL) {
				MR_SUB_VEC_ABC(((GEN_CHECKPOINT*)(entity + 1))->cp_matrix.t, (MR_VEC*)frog->fr_lwtrans->t, &pos_offset); // pos_offset = checkpoint->cp_matrix->t - frog->fr_lwtrans->t
				temp_distance = MR_VEC_MOD_SQR(&pos_offset);
				if (temp_distance < closest_distance) {
					result = entity;
					closest_distance = temp_distance;
				}
			}
        }
    }

    // Test if the gold frog is close
    if (Gold_frog_data.gf_entity != NULL) {
        if (Gold_frog_data.gf_frog_collected_id == -1) {
            MR_VEC_EQUALS_SVEC(&gold_frog_pos, &Gold_frog_data.gf_position);
            MR_SUB_VEC_ABC(&gold_frog_pos, frog->fr_lwtrans->t, &pos_offset); // pos_offset = checkpoint->cp_matrix->t - frog->fr_lwtrans->t

            // Check if the gold frog is closer than the closest frog.
            temp_distance = MR_VEC_MOD_SQR(&pos_offset);
            if (temp_distance < closest_distance)
                result = Gold_frog_data.gf_entity;
        }
    }
    
    return result;
}

/******************************************************************************
*%%%% FrogKill
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogKill(
*							FROG*		frog,
*							MR_ULONG	animation,
*							MR_VEC*		velocity)
*
*	FUNCTION	Kill the provided frog (And enter the death process)
*	MATCH		https://decomp.me/scratch/nn5Ez (By Kneesnap)
*				https://decomp.me/scratch/4IdAn	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*				animation	-	death animation to enact
*				velocity	-	pointer to velocity vector to apply to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogKill(FROG* frog, MR_ULONG animation, MR_VEC* velocity) {
    MR_SVEC colour;
    MR_OBJECT* obj;

    if (frog->fr_particle_api_item != NULL && (frog->fr_particle_flags & EFFECT_KILL_WHEN_FROG_DEAD))
        FROG_KILL_PARTICLE_EFFECT(frog);
    
    if ((frog->fr_mode != FROG_MODE_DYING) && (frog->fr_mode != FROG_MODE_HIT_CHECKPOINT) && (Cheat_collision_toggle == FALSE)) {
        if (!(frog->fr_flags & FROG_MUST_DIE) && (frog->fr_mode != FROG_MODE_DYING)) {
			// Unlink from frog stack
			if (frog->fr_stack_master != NULL) {
                frog->fr_stack_master->fr_stack_slave = NULL;
                frog->fr_stack_master = NULL;
            }

            if (frog->fr_stack_slave != NULL) {
                frog->fr_stack_slave->fr_stack_master = NULL;
                frog->fr_stack_slave = NULL;
            }
			
            frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
            Cameras[frog->fr_frog_id].ca_mode = CAMERA_MODE_FIXED;

            // Singleplayer.
            if (Game_total_players == 1) {
                if (Cheat_infinite_lives_toggle == 0) {
                    if (frog->fr_lives > 0)
                        frog->fr_lives--;
                    
                    if (frog->fr_lives == 0)
                        (frog->fr_hud_script + HUD_ITEM_LIVES - 1)->hi_flags |= HUD_ITEM_REBUILD;
                }

                if (frog->fr_lives == 0)
                    frog->fr_flags &= ~FROG_ACTIVE;
            }

            // Request frog death and associated animation.
            frog->fr_flags |= FROG_MUST_DIE;
            if (animation != -1) {
                FrogRequestAnimation(frog, animation, 0, 0);
                frog->fr_death_equate = animation;
            }

            // Setup explosion pgen & poly piece pop.
            if (frog->fr_poly_piece_pop != NULL) {
                FrogStartPolyPiecePop(frog);
                obj = MRCreatePgen(&PGIN_frog_pop_explosion, (MR_FRAME*)frog->fr_poly_piece_pop->pp_lwtrans, MR_OBJ_STATIC, 0);
                obj->ob_extra.ob_extra_pgen->pg_user_data_2 = Frog_pop_explosion_colours[Frog_player_data[frog->fr_frog_id].fp_player_id];
                GameAddObjectToViewports(obj);
            } else {
                obj = MRCreatePgen(&PGIN_frog_pop_explosion, (MR_FRAME*)frog->fr_lwtrans, MR_OBJ_STATIC, 0);
                obj->ob_extra.ob_extra_pgen->pg_user_data_2 = Frog_pop_explosion_colours[Frog_player_data[frog->fr_frog_id].fp_player_id];
                GameAddObjectToViewports(obj);
            }

            // Create explosion pgen.
            if (velocity != NULL) {
                MR_COPY_VEC(&frog->fr_velocity, velocity);
            } else if ((frog->fr_mode != FROG_MODE_JUMPING) || !(frog->fr_flags & FROG_JUMP_TO_LAND)) {
                MR_CLEAR_VEC(&frog->fr_velocity);
            }

            // Create smoke particle FX on death.
            if ((Game_map_theme == THEME_VOL) && ((animation == FROG_ANIMATION_DROWN) || (animation == FROG_ANIMATION_FLOP))) {
                if (frog->fr_particle_api_item == NULL) {
                    colour.vx = 0;
                    colour.vy = -80;
                    colour.vz = 40;
                    frog->fr_particle_api_item = CreateParticleEffect(frog, FROG_PARTICLE_ON_FIRE, &colour);
                }
                
                SetFrogScaleColours(frog, 24, 0, 0);
                FrogRequestAnimation(frog, FROG_ANIMATION_DROWN, 0, 0);
            }
        }
    }
}

/******************************************************************************
*%%%% FrogModeControlJumping
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogModeControlJumping(
*							FROG*	frog)
*	FUNCTION	This is a hook run when the frog is jumping to buffer input
*	MATCH		https://decomp.me/scratch/N3wGo (By Kneesnap & sonicdcer)
*				https://decomp.me/scratch/etORm	(By Kneesnap)
*
*	INPUTS		frog		-	pointer to single environment
*				mode		-	index of part within model
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*	02.11.23	Kneesnap		Byte-matching decompilation from PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID FrogModeControlJumping(FROG* frog, MR_ULONG mode) {
    CAMERA* camera;
    MR_LONG buffered_key_count;
    MR_LONG key_dir;
	ENTITY* target;
	
	if (Game_flags & GAME_FLAG_DEMO_RUNNING)
        return;
	
	camera = &Cameras[frog->fr_frog_id];

    // Find the direction to buffer with the key
    key_dir = FROG_DIRECTION_NO_INPUT;
    if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
        key_dir = FROG_DIRECTION_N;
    } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
        key_dir = FROG_DIRECTION_E;
    } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
        key_dir = FROG_DIRECTION_S;
    } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_left_control)) {
        key_dir = FROG_DIRECTION_W;
    } else if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_superjump_control)) {
        key_dir = FROG_DIRECTION_SUPER_JUMP;
    }
	
    // Apply tongue
    if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_tongue_control) && (frog->fr_tongue != NULL) && (frog->fr_tongue->ef_flags & (EFFECT_NO_DISPLAY | EFFECT_NO_UPDATE))) {
        frog->fr_no_input_timer = 0;
        target = FrogGetNearestTongueTarget(frog);
        if (target != NULL) {
            StartTongue(frog->fr_tongue, target);
			DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE, 0, TRUE);
        } else {
            StartTongue(frog->fr_tongue, NULL);
			DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE, 0, TRUE);
        }
        
        MRSNDPlaySound(SFX_GEN_FROG_SLURP, NULL, 0, 0);
    }

    // Buffer input
    if (key_dir != FROG_DIRECTION_NO_INPUT) {
		if (key_dir != FROG_DIRECTION_SUPER_JUMP) {
			// Rotate direction along with entity or camera.
			if (frog->fr_flags & FROG_ON_ENTITY) {
				key_dir = key_dir - frog->fr_entity_angle;
			} else {
				key_dir = (key_dir - camera->ca_frog_controller_directions[0]) & 3;
			}
		}

        // Buffer the movement keypress.
        buffered_key_count = frog->fr_num_buffered_keys;
        if (frog->fr_num_buffered_keys < MAX_BUFFERED_KEYS) {
            frog->fr_num_buffered_keys++;
            frog->fr_buffered_key[buffered_key_count] = key_dir;
        }
    }
}

/******************************************************************************
*%%%% UpdateFrogBaseColour
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogBaseColour(
*							FROG*	frog)
*
*	FUNCTION	Update the base colour of the provided frog
*	MATCH		https://decomp.me/scratch/2ZuE5 (By pixel-stuck)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID UpdateFrogBaseColour(FROG* frog) {
    MR_LONG x, z, y_delta;
    MR_ULONG x_offset, z_offset;
    MR_ULONG i, j;
    MR_LONG fade_strength;
    MR_ULONG scale_red, scale_green, scale_blue;
    MR_MESH_INST* mesh;
    MR_ANIM_ENV_INST* env_inst;
    MR_MESH_INST** mesh_ptrs;

    if (!(Map_library[Game_map].mb_flags & MAP_BOOK_FLAG_CAVE_LIGHT)) {
        x_offset = 0;
        z_offset = 0;

        // Determine how far outside playable area the player is in the x direction.
        x = frog->fr_lwtrans->t[0];
        if (x < Fade_top_left_pos.vx) {
            x_offset = Fade_top_left_pos.vx - x;
        } else if (Fade_bottom_right_pos.vx < x) {
            x_offset = x - Fade_bottom_right_pos.vx;
        }

        // Determine how far outside playable area the player is in the z direction.
        z = frog->fr_lwtrans->t[2];
        if (z < Fade_bottom_right_pos.vz) {
            z_offset = Fade_bottom_right_pos.vz - z;
        } else if (Fade_top_left_pos.vz < z) {
            z_offset = z - Fade_top_left_pos.vz;
        }

        // Calculate fade strength.
        fade_strength = (x_offset + z_offset) / 2;
        fade_strength = MAX(0, 0x80 - fade_strength);
        fade_strength *= 0x010101;

        // Apply colour_scale value.
        for (i = 0; i < Game_total_viewports; i++) {
			if (NULL != frog->fr_api_insts[i]) {
				mesh_ptrs = ((MR_ANIM_ENV_INST*)frog->fr_api_insts[i])->ae_mesh_insts;
				mesh = *mesh_ptrs;
		
				// Loop once for each model in anim env inst
				j = ((MR_ANIM_ENV_INST*)frog->fr_api_insts[i])->ae_models;
				while(j--) {
					mesh = *mesh_ptrs++;
					MR_SET32(mesh->mi_colour_scale, fade_strength);
                    mesh->mi_light_flags |= MR_INST_USE_SCALED_COLOURS;
				}
			}
		}
    }

    // Apply water color when player is drowning.
    if ((frog->fr_mode == FROG_MODE_DYING) && (frog->fr_death_equate == FROG_ANIMATION_DROWN)) {
        y_delta = frog->fr_lwtrans->t[1] - frog->fr_old_y;
        
        if (Game_map_theme == THEME_SWP) { // Green sludge color (green).      
            scale_red = MAX(-(y_delta << 4) >> 9, 0);
            scale_green = MAX(((y_delta << 5) >> 9) + 128, 0);
            scale_blue = MAX((-(y_delta << 5) >> 9) + 32, 0);
        } else { // Normal water color (blue).
            scale_red = MAX(-(y_delta << 4) >> 9, 0);
            scale_green = MAX((-(y_delta << 5) >> 9) + 64, 0);
            scale_blue = MAX((-(y_delta << 5) >> 9) + 192, 0);
        }

        // Apply color to the player character mesh (in each viewport).
        for (i = 0; i < Game_total_viewports; i++) {
            env_inst = frog->fr_api_insts[i];
            if (env_inst != NULL) {
                j = env_inst->ae_models;
                mesh_ptrs = env_inst->ae_mesh_insts;
                while (j--) {
                    mesh = *mesh_ptrs++;
                    mesh->mi_custom_ambient.r = 32;
                    mesh->mi_custom_ambient.g = 64;
                    mesh->mi_custom_ambient.b = 64;
                    mesh->mi_colour_scale.r = scale_red;
                    mesh->mi_colour_scale.g = scale_green;
                    mesh->mi_colour_scale.b = scale_blue;
                    mesh->mi_light_flags |= MR_INST_MODIFIED_LIGHT_MASK;
                }
            }
        }
    }
}

/******************************************************************************
*%%%% SetFrogScaleColours
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	SetFrogScaleColours(
*							FROG*	frog,
*							MR_LONG	red,
*							MR_LONG	green,
*							MR_LONG	blue)
*
*	FUNCTION	Set the scale colours onto the provided frog
*	MATCH		https://decomp.me/scratch/Al7Bc (By Kneesnap & sonicdcer & ethteck)
*
*	INPUTS		frog	-	pointer to the frog
*				red		-	The red colour component
*				green	-	The green colour component
*				blue	-	The blue colour component
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID SetFrogScaleColours(FROG* frog, MR_LONG red, MR_LONG green, MR_LONG blue) {
    MR_ULONG models;
    MR_ULONG i;
    MR_ANIM_ENV_INST* inst;
    MR_MESH_INST* mesh;
    MR_MESH_INST** mesh_insts;

    MR_ULONG colourVector = (blue << 16) + (green << 8) + red;

    for (i = 0; i < Game_total_viewports; i++) {
        inst = frog->fr_api_insts[i];
        if (inst != NULL) {
            mesh_insts = inst->ae_mesh_insts;
            models = inst->ae_models;
            while (models-- > 0) {
                mesh = *mesh_insts++;
                MR_SET32(mesh->mi_custom_ambient, colourVector);
                MR_SET32(mesh->mi_colour_scale, colourVector);
                mesh->mi_light_flags |= MR_INST_MODIFIED_LIGHT_MASK;
            }
        }
    }
}

/******************************************************************************
*%%%% UpdateFrogPowerUps
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogPowerUps(
*							FROG*	frog)
*
*	FUNCTION	Update the powerups active for the provided frog
*	MATCH		https://decomp.me/scratch/DSdsm (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID UpdateFrogPowerUps(FROG* frog) {
    // Tick AutoHop
    if (frog->fr_powerup_flags & FROG_POWERUP_AUTO_HOP) {
        if (frog->fr_auto_hop_timer != 0) {
            frog->fr_auto_hop_timer--;
        } else {
            frog->fr_powerup_flags &= ~FROG_POWERUP_AUTO_HOP;
        }
    }

    // Tick Super Tongue
    if (frog->fr_powerup_flags & FROG_POWERUP_SUPER_TONGUE) {
        if (frog->fr_super_tongue_timer != 0) {
            frog->fr_super_tongue_timer--;
        } else {
            frog->fr_powerup_flags &= ~FROG_POWERUP_SUPER_TONGUE;
        }
    }

    // Tick Quick Jump
    if (frog->fr_powerup_flags & FROG_POWERUP_QUICK_JUMP) {
        if (frog->fr_quick_jump_timer != 0) {
            frog->fr_quick_jump_timer--;
        } else {
            frog->fr_powerup_flags &= ~FROG_POWERUP_QUICK_JUMP;
        }
    }

    // Tick Increased Timer Speed (This is actually more of a debuff than something the player wants...)
    if (frog->fr_powerup_flags & FROG_POWERUP_TIMER_SPEED) {
        if (Game_map_timer_flags & GAME_TIMER_FLAGS_COUNT_UP) {
            if (Game_map_timer_frac <= GAME_TIMER_FRAC_LIMIT) {
                Game_map_timer_frac += GAME_TIMER_FRAC;
            } else {
                Game_map_timer_flags &= ~GAME_TIMER_FLAGS_COUNT_UP;
                Game_map_timer_flags |= GAME_TIMER_FLAGS_COUNT_DOWN;
                Game_map_timer_frac = 0;
            }
        } else if (Game_map_timer_frac >= ~(GAME_TIMER_DEFAULT - 1)) {
            Game_map_timer_frac -= GAME_TIMER_FRAC;
        } else {
            Game_map_timer_flags &= ~GAME_TIMER_FLAGS_COUNT_DOWN;
            Game_map_timer_flags |= GAME_TIMER_FLAGS_COUNT_UP;
        }

        // Change speed until it gets lower than the default, when we'll disable the "powerup".
        Game_map_timer_speed += Game_map_timer_frac;
        if (Game_map_timer_speed < GAME_TIMER_DEFAULT) {
            Game_map_timer_speed = GAME_TIMER_DEFAULT;
            frog->fr_powerup_flags &= ~FROG_POWERUP_TIMER_SPEED;
        }
    }
}

/******************************************************************************
*%%%% UpdateFrogStackMaster
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogStackMaster(
*							FROG*	master,
*							FROG*	slave)
*
*	FUNCTION	Update frogs stacked on top of one another
*	MATCH		https://decomp.me/scratch/ZQkcU (By Kneesnap & KieronJ)
*
*	INPUTS		master	-	pointer to the frog considered the "master"
*				slave	-	pointer to the frog considered the "slave"
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

void UpdateFrogStackMaster(FROG *master, FROG *slave) {
    MR_SVEC svec;
    MR_VEC  result;
    FROG   *frog;
    MR_LONG count;
    MR_LONG y;

    frog = master->fr_stack_master;
    count = (8 - slave->fr_stack_count) << 12;

    y = rcos(count / 8) + 4096;
    y *= FROG_STACK_CENTRE_OFFSET;
    y >>= 13;
    y += FROG_STACK_MASTER_OFFSET_MIN;
    
    svec.vx = 0;
    svec.vy = -y;
    svec.vz = 0;

    MRApplyMatrix(master->fr_lwtrans, &svec, &result);
    MR_ADD_VEC_ABC(&master->fr_lwtrans->t, &result, &frog->fr_lwtrans->t); // frog->lwtrans->t = master->fr_lwtrans->t + result;
    
    frog->fr_pos.vx = frog->fr_lwtrans->t[0] << 16;
    frog->fr_pos.vy = frog->fr_lwtrans->t[1] << 16;
    frog->fr_pos.vz = frog->fr_lwtrans->t[2] << 16;
    MRMulMatrixABC(&frog->fr_stack_mod_matrix, master->fr_lwtrans, frog->fr_lwtrans);
    frog->fr_grid_x = master->fr_grid_x;
    frog->fr_grid_z = master->fr_grid_z;
    frog->fr_grid_square = master->fr_grid_square;
    frog->fr_old_grid_x = master->fr_old_grid_x;
    frog->fr_old_grid_z = master->fr_old_grid_z;
    frog->fr_old_grid_square = master->fr_old_grid_square;
    MR_COPY_VEC(&frog->fr_velocity, &master->fr_velocity);
}

/******************************************************************************
*%%%% JumpFrogOnSpot
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	JumpFrogOnSpot(
*							FROG*	frog,
*							MR_LONG	count)
*
*	FUNCTION	Handles the frog jumping on the spot (grid tile or form entity)
*	MATCH		https://decomp.me/scratch/bpQeH (By Kneesnap)
*
*	INPUTS		frog	-	pointer to the frog
*				count	-	the distance away from completing the jump
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID JumpFrogOnSpot(FROG* frog, MR_LONG count) {
    FORM* form;

    frog->fr_mode = FROG_MODE_JUMPING;
    frog->fr_count = count;
    frog->fr_flags |= FROG_JUMP_ON_SPOT;
    if (frog->fr_flags & FROG_ON_ENTITY) {
        frog->fr_flags |= (FROG_JUMP_FROM_ENTITY | FROG_JUMP_TO_ENTITY);

        // Update velocity.
        frog->fr_velocity.vx = 0;
        frog->fr_velocity.vy = -((MR_LONG) ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1));
        frog->fr_velocity.vz = 0;

        // Snap the target position to the entity
        frog->fr_y = frog->fr_lwtrans->t[1];
        form = ENTITY_GET_FORM(frog->fr_entity);
        frog->fr_target_pos.vx = (frog->fr_entity_grid_x << WORLD_SHIFT) + form->fo_xofs + 0x80;
        frog->fr_target_pos.vz = (frog->fr_entity_grid_z << WORLD_SHIFT) + form->fo_zofs + 0x80;
    } else {
        frog->fr_flags |= FROG_JUMP_TO_LAND;

        // Update velocity.
        frog->fr_velocity.vx = 0;
        frog->fr_velocity.vy = -((MR_LONG) ((SYSTEM_GRAVITY * (frog->fr_count + 1)) >> 1));
        frog->fr_velocity.vz = 0;

        // Snap the target position to the grid.
        frog->fr_y = frog->fr_lwtrans->t[1];
        frog->fr_target_pos.vx = ((frog->fr_grid_x << WORLD_SHIFT) + Grid_base_x) + 0x80;
        frog->fr_target_pos.vz = ((frog->fr_grid_z << WORLD_SHIFT) + Grid_base_z) + 0x80;
    }
}

/******************************************************************************
*%%%% FrogStartPolyPiecePop
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogStartPolyPiecePop(
*							FROG*	frog)
*
*	FUNCTION	Start a poly-piece pop animation for the provided frog
*	MATCH		https://decomp.me/scratch/ycPYA (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogStartPolyPiecePop(FROG* frog) {
    POLY_PIECE* poly_piece_ptr;
    POLY_PIECE_DYNAMIC* poly_piece_dynamic;
    MR_ANIM_ENV* anim_env;
    MR_VEC vec;
    MR_LONG i;

    // Hide the normal mesh (since the poly piece pop mesh is displayed in its place)
    anim_env = ((MR_ANIM_ENV*)frog->fr_api_item);
    anim_env->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;

    // Init Poly Piece Pop Data
    frog->fr_poly_piece_pop->pp_timer = FROG_POLY_PIECE_POP_DURATION;
    frog->fr_poly_piece_pop->pp_duration = FROG_POLY_PIECE_POP_DURATION;
    frog->fr_poly_piece_pop->pp_otz = FROG_POPPING_FIXED_OT;
	MR_CLEAR_SVEC(&frog->fr_poly_piece_pop->pp_rotation);
	MR_CLEAR_SVEC(&frog->fr_poly_piece_pop->pp_ang_vel);

    // Setup initial polygon positions & rotations.
    i = frog->fr_poly_piece_pop->pp_numpolys;
    poly_piece_ptr = frog->fr_poly_piece_pop->pp_poly_pieces;
    poly_piece_dynamic = frog->fr_poly_piece_pop->pp_poly_piece_dynamics;
    gte_SetRotMatrix(frog->fr_poly_piece_pop->pp_lwtrans);
    while (i--) {
        MRApplyRotMatrix(&(poly_piece_ptr++)->pp_origin, &vec);

        // Apply default position.
        poly_piece_dynamic->pp_position.vx = (frog->fr_poly_piece_pop->pp_lwtrans->t[0] + vec.vx) << 16;
        poly_piece_dynamic->pp_position.vy = (frog->fr_poly_piece_pop->pp_lwtrans->t[1] + vec.vy) << 16;
        poly_piece_dynamic->pp_position.vz = (frog->fr_poly_piece_pop->pp_lwtrans->t[2] + vec.vz) << 16;

        // Apply default velocity.
        vec.vy -= 0x80;
        MRNormaliseVEC(&vec, &vec);
        poly_piece_dynamic->pp_velocity.vx = (vec.vx << 10);
        poly_piece_dynamic->pp_velocity.vy = (vec.vy << 10);
        poly_piece_dynamic->pp_velocity.vz = (vec.vz << 10);
        poly_piece_dynamic++;
    }
}

/******************************************************************************
*%%%% RemoveAllFrogsFromDisplay
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	RemoveAllFrogsFromDisplay(MR_VOID)
*
*	FUNCTION	Hide all frogs from all viewports
*	MATCH		https://decomp.me/scratch/Dv4GB (By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID RemoveAllFrogsFromDisplay(MR_VOID) {
    FROG* frog = &Frogs[0];
    MR_LONG players = Game_total_players;
    while (players--) {
        if (Game_total_players > GAME_MAX_HIGH_POLY_PLAYERS) {
            ((MR_ANIM_ENV*) frog->fr_api_item)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
        } else {
            ((MR_ANIM_ENV*) frog->fr_api_item)->ae_extra.ae_extra_env_single->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
        }

        frog++;
    }
}

/******************************************************************************
*%%%% UpdateFrogCameraZone
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateFrogCameraZone(
*							FROG*	frog)
*
*	FUNCTION	Update the camera zone for the provided frog
*	MATCH		https://decomp.me/scratch/NyhZk (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID UpdateFrogCameraZone(FROG* frog) {
    if (frog->fr_flags & FROG_DO_NOT_UPDATE_CAMERA_ZONES)
        return;

    if (frog->fr_cam_zone != NULL) {
        if ((frog->fr_cam_zone_region == NULL) || (CheckCoordsInZoneRegion(frog->fr_grid_x, frog->fr_grid_z, frog->fr_cam_zone_region) == 0)) {
            frog->fr_cam_zone_region = CheckCoordsInZone(frog->fr_grid_x, frog->fr_grid_z, frog->fr_cam_zone);
            if (frog->fr_cam_zone_region == NULL)
                CheckCoordsInZones(frog->fr_grid_x, frog->fr_grid_z, ZONE_TYPE_CAMERA, &frog->fr_cam_zone, &frog->fr_cam_zone_region);
        }
    } else {
        CheckCoordsInZones(frog->fr_grid_x, frog->fr_grid_z, ZONE_TYPE_CAMERA, &frog->fr_cam_zone, &frog->fr_cam_zone_region);
    }
}

/******************************************************************************
*%%%% FrogPlayLoopingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogPlayLoopingSound(
*							FROG*	frog,
*							MR_LONG	sound)
*
*	FUNCTION	Play a looping sound for the frog
*	MATCH		https://decomp.me/scratch/YtZxT (By Kneesnap)
*
*	INPUTS		frog	-	pointer to the frog
*				sound	-	the sound effect to play on loop.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogPlayLoopingSound(FROG* frog, MR_LONG sound) {
    if (sound == frog->fr_current_sfx)
        return;
    
    if (frog->fr_voice_id != -1)
        FrogKillLoopingSound(frog);
    
    frog->fr_voice_id = -1;
    frog->fr_current_sfx = sound;
}

/******************************************************************************
*%%%% FrogKillLoopingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FrogKillLoopingSound(
*							FROG*	frog)
*
*	FUNCTION	Kills the active looping sound for the frog, if there is one.
*	MATCH		https://decomp.me/scratch/kYvLG (By Kneesnap)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FrogKillLoopingSound(FROG* frog) {
	if (frog->fr_voice_id != -1)
		MRSNDKillSound(frog->fr_voice_id);
	frog->fr_voice_id = -1;
	frog->fr_current_sfx = -1;
}

/******************************************************************************
*%%%% FROG_FALL
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	FROG_FALL(
*							FROG*	frog)
*
*	FUNCTION	Enters the provided frog into free-fall mode.
*	MATCH		https://decomp.me/scratch/pmdum (By Kneesnap & sonicdcer)
*
*	INPUTS		frog		-	pointer to the frog
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.10.23	Kneesnap		Byte-matching decompilation from PSX Build 50.
*
*%%%**************************************************************************/

MR_VOID FROG_FALL(FROG* frog) {
    MATRIX mtx;

    if (frog->fr_mode == FROG_MODE_DYING)
        return;

	// Dismount from riding entity
    if (frog->fr_entity != NULL) {
        ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &mtx);
        MRMulMatrixABA(&Cameras[frog->fr_frog_id].ca_mod_matrix, &mtx);
        frog->fr_entity = NULL;
    }
    
	// Enter free-fall
    frog->fr_mode = FROG_MODE_JUMPING;
    frog->fr_count = 0xFFFF;
	MR_CLEAR_VEC(&frog->fr_velocity);
    frog->fr_flags &= ~FROG_LANDED_ON_LAND_CLEAR_MASK;
    FrogRequestAnimation(frog, FROG_ANIMATION_FREEFALL, 0, 0);
}