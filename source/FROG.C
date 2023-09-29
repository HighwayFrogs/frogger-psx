/******************************************************************************
*%%%% FROG.C
*------------------------------------------------------------------------------
*
*	File rebuilt by Kneesnap for compilation. Was corrupted.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	02.04.19	Kneesnap		Started to rebuild.
*	02.05.22	Kneesnap		Fixed many inaccuracies in the recreation.
*
*%%%**************************************************************************/

//TODO: Implement / Cleanup: JumpFrog, FrogGetNearestTongueTarget
// Change bitwise ands from 0xFFFFF7FF form to ~(FLAG_1 | FLAG1)

//TODO: Go over todos.
//TODO: Add support for effects like shadow, UpdateFrogEffects
//TODO: Fix the display driver showing parts of VRAM it shouldn't show.
//TODO: Fix sounds.
//TODO: SWP5 slippy.
//TODO: Fix shadow effect.
//TODO: ?

// Notes:
// setCopControlWord(2,0,*(undefined4 *)pMVar2->m); -> gte_SetRotMatrix

#include "camera.h"
#include "entlib.h"
#include "ENTITY.H"
extern  LIVE_ENTITY*   Live_entity_root_ptr; // Added by Kneesnap to make FROG.C compileable. Should probably be removed later...?

#include "frog.h"
#include "SYSTEM.H"
#include "gen_frog.H"
#include "HSView.H"
#include "model.H"
#include "froguser.H"
#include "PLAYXA.H"
#include "xalist.h"
#include "tempopt.h"
#include "ent_gen.h"
#include "sound.h"
#include "form.h"
#include "GRID.H"
#include "mapdisp.H"
#include "PARTICLE.H"
#include "score.H"
#include "SELECT.H"

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

MR_VOID (*Frogger_controller_hooks[])(FROG*, MR_ULONG) =
	{
	FrogModeControlStationary,
	FrogModeControlJumping,
	NULL,
	NULL,
	NULL,
	FrogModeControlStationary,
	NULL,
	FrogModeControlStationary
	};
	
MR_ULONG (*Frogger_movement_hooks[])(FROG*, MR_ULONG, MR_ULONG*) =
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

// Confirmed
MR_VOID	InitialiseFrogs(MR_VOID) { // Done - For Sure.
	MR_ULONG frog_id;
	MR_ULONG x_face;
	MR_ULONG z_face;
	
    switch(Map_general_header->gh_rotation) {
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
            z_face = -1;
            x_face = 0;
            break;
        default:
            z_face = 0;
            x_face = 1;
	}
	
	MRReadInput();
	for(frog_id=0; frog_id < Game_total_players; frog_id++) {
		CreateFrog(frog_id, Frog_player_data[frog_id].fp_port_id, (MR_ULONG) (Map_general_header->gh_start_x) + (frog_id * x_face), (MR_ULONG)(Map_general_header->gh_start_z) + (frog_id * z_face));
		UpdateFrogCameraZone(&Frogs[frog_id]);
	}
	UpdateFrogAnimationScripts();
}

// Confirmed.
FROG* CreateFrog(MR_ULONG frog_id, MR_ULONG input, MR_ULONG startX, MR_ULONG startZ) { // Not Done.
	FROG* frog;
	MR_VOID* inst_pptr;
	ULONG i;
	
	frog = &Frogs[frog_id];
	frog->fr_input_id = input;
	frog->fr_frog_id = frog_id;
	frog->fr_lwtrans = &frog->fr_matrix;
	frog->fr_voice_id = -1;
	frog->fr_current_sfx = -1;
	frog->fr_control_method = &Frog_control_methods[Frog_current_control_methods[frog_id]];
	
	if (Game_total_players == 1) { // Single frog.
		frog->fr_api_item = MRAnimEnvSingleCreateWhole((MR_ANIM_HEADER*) MR_GET_RESOURCE_ADDR(RES_GEN_FROG_XAR), 0, MR_OBJ_STATIC, (MR_FRAME*) frog->fr_lwtrans);
		MRAnimEnvSingleCreateLWTransforms((MR_ANIM_ENV*) frog->fr_api_item);
		
		MR_INIT_MAT(&frog->fr_croak_scale_matrix);
		frog->fr_croak_scale_matrix.m[0][0] = FROG_CROAK_MIN_SCALE;
		frog->fr_croak_scale_matrix.m[1][1] = FROG_CROAK_MIN_SCALE;
		frog->fr_croak_scale_matrix.m[2][2] = FROG_CROAK_MIN_SCALE;
		MRAnimEnvSingleSetPartFlags((MR_ANIM_ENV*) frog->fr_api_item, THROAT, MR_ANIM_PART_TRANSFORM_PART_SPACE);
		MRAnimEnvSingleSetImportedTransform((MR_ANIM_ENV*) frog->fr_api_item, THROAT, &frog->fr_croak_scale_matrix);
		MRAnimEnvSingleClearPartFlags((MR_ANIM_ENV*) frog->fr_api_item, THROAT, 1);
	} else { // Multiple frogs.
		frog->fr_api_item = MRAnimEnvFlipbookCreateWhole(MR_GET_RESOURCE_ADDR(RES_GENM_FROG_XMR + Frog_player_data[frog->fr_frog_id].fp_player_id), MR_OBJ_STATIC, (MR_FRAME*) frog->fr_lwtrans);
		MRAnimEnvFlipbookSetAction((MR_ANIM_ENV*) frog->fr_api_item, 0);
		MRAnimEnvFlipbookSetCel((MR_ANIM_ENV*) frog->fr_api_item, 0);
		((MR_ANIM_ENV*) frog->fr_api_item)->ae_flags |= 0x100;
		((MR_ANIM_ENV*) frog->fr_api_item)->ae_flags &= 0xfbff;
	}
	
	FrogInitialiseAnimation(frog, FROG_ANIMATION_PANT, 0);
	
	inst_pptr = frog->fr_ot;
	for (i = 0; i < Game_total_viewports; i++) {
		frog->fr_ot[i] = (MR_OT*) MRCreateOT(7, 2, (MR_FRAME*) frog->fr_lwtrans);
		frog->fr_ot[i]->ot_global_ot_offset = FROG_GLOBAL_OT_OFFSET;
	}
	
	GameAddAnimEnvToViewportsStoreInstances((MR_ANIM_ENV*) frog->fr_api_item, (MR_ANIM_ENV_INST**) frog->fr_api_insts);
	
    for (i = 0; i < Game_total_viewports; i++)
		((MR_ANIM_ENV_INST*) frog->fr_api_insts[i])->ae_mesh_insts[0]->mi_ot = frog->fr_ot[i];
	
	MRSNDSetMovingSoundTarget(0, (MR_VEC*) frog->fr_lwtrans->t, (MR_VEC*) frog->fr_lwtrans->t, (MR_MAT*) frog->fr_lwtrans);
	
	frog->fr_shadow = NULL;
	
	// TODO: Enabling the shadow causes weird crashes, and doesn't even display the shadow properly. Unclear what's up.
	frog->fr_shadow = CreateShadow(Frog_jump_shadow_textures[0], frog->fr_lwtrans, Frog_jump_shadow_offsets[0]);
    frog->fr_shadow->ef_flags &= 0xffef;
	
	for (i = 0; i < Game_total_viewports; i++)
		((SHADOW*) frog->fr_shadow->ef_extra)->sh_ot_ptr[i] = frog->fr_ot[i];
	
    frog->fr_tongue = CreateTongue(frog->fr_lwtrans, frog);
    frog->fr_tongue->ef_flags = 6;
    frog->fr_trail = CreateTrail(frog->fr_lwtrans, &Frog_trail_offsets[1], 6);
	frog->fr_trail->ef_flags &= 0xffef;
	
	for (i = 0; i < Game_total_viewports; i++)
		((TRAIL*) frog->fr_trail->ef_extra)->tr_ot_ptr[i] = NULL;
	
	frog->fr_particle_api_item = NULL;
	frog->fr_scale = 0x1000;
	if (Game_total_players > 1) {
		frog->fr_poly_piece_pop = MRAllocMem(sizeof(POLY_PIECE_POP), "FROG POLY PIECE POP");
		frog->fr_poly_piece_pop->pp_mof = NULL;
		frog->fr_poly_piece_pop->pp_numpolys = 0;
		frog->fr_poly_piece_pop->pp_timer = 0;
		frog->fr_poly_piece_pop->pp_lwtrans = frog->fr_lwtrans;
		frog->fr_poly_piece_pop->pp_poly_pieces = NULL;
		frog->fr_poly_piece_pop->pp_poly_piece_dynamics = (POLY_PIECE_DYNAMIC*) (frog->fr_poly_piece_pop + 1);
	} else {
		frog->fr_poly_piece_pop = NULL;
	}
	
	// Animation related.
	memset(&frog->fr_anim_info, 0, sizeof(FROG_ANIM_INFO)); // TODO: Does using '&' cause the wrong memory location to get written to? IE: Is it writing in the frog instead of the anim struct?
	memset(&frog->fr_tex_anim_info, 0, sizeof(FROG_TEX_ANIM_INFO));
	frog->fr_start_grid_x = startX;
	frog->fr_start_grid_z = startZ;
    ResetFrog(frog, startX, startZ, GAME_MODE_SINGLE_START);
	
	return frog;
}

// Confirmed.
MR_VOID FrogInitCustomAmbient(FROG* frog) { // Done. For sure.
	MR_ULONG i;
	MR_ULONG model;
	MR_ANIM_ENV_INST* env_inst;
	MR_SHORT red, green, blue;
	
	red = Map_general_header->gh_level_header.gh_frog_red;
	green = Map_general_header->gh_level_header.gh_frog_green;
	blue = Map_general_header->gh_level_header.gh_frog_blue;
	
	for (i = 0; i < Game_total_viewports; i++) {
		env_inst = (MR_ANIM_ENV_INST*) frog->fr_api_insts[i];
		
		for (model = 0; model < env_inst->ae_models; model++) {
			if (red == (MR_USHORT) 0 && blue == (MR_USHORT) 0 && green == (MR_USHORT) 0) {
				env_inst->ae_mesh_insts[model]->mi_light_flags &= 0xFFFC;
			} else {
				env_inst->ae_mesh_insts[model]->mi_custom_ambient.r = ((MR_LONG) red) + 0x80;
				env_inst->ae_mesh_insts[model]->mi_custom_ambient.g = ((MR_LONG) green) + 0x80;
				env_inst->ae_mesh_insts[model]->mi_custom_ambient.b = ((MR_LONG) blue) + 0x80;
				env_inst->ae_mesh_insts[model]->mi_light_flags = env_inst->ae_mesh_insts[model]->mi_light_flags & 0xFFFD | 1;
			}
			
		}
	}
}

// Confirmed.
// Example Gamemodes: GAME_MODE_SINGLE_START, GAME_MODE_MULTI_COMPLETE, etc. Registered in gamesys.H.
MR_VOID ResetFrog(FROG* frog, MR_LONG gridStartX, MR_LONG gridStartZ, MR_ULONG game_mode) { // Done, For Sure.
	MR_ULONG i;
	MR_ANIM_ENV* env;
	GRID_STACK* grid_stack;
	MR_SVEC vec;
		
	frog->fr_flags = (FROG_ACTIVE | FROG_CONTROL_ACTIVE);
	frog->fr_count = 0;
	frog->fr_powerup_flags = 0;
	frog->fr_auto_hop_timer = (MR_USHORT) 0;
	frog->fr_super_tongue_timer = (MR_USHORT) 0;
	frog->fr_quick_jump_timer = (MR_USHORT) 0;
	frog->fr_num_buffered_keys = 0;
	frog->fr_buffered_input_count = 0;
	frog->fr_direction = Map_general_header->gh_rotation;
	
	for (i = 0; i < Game_total_viewports; i++)
		(*frog->fr_ot[i]).ot_flags &= 0xFFFFFFFD;
	
	grid_stack = GetGridStack(gridStartX, gridStartZ);
	frog->fr_grid_square = &Grid_squares[grid_stack->gs_index + grid_stack->gs_numsquares - 1];
	GetGridSquareCentre(frog->fr_grid_square, &vec);
	frog->fr_pos.vx = vec.vx << 16;
	frog->fr_pos.vy = vec.vy << 16;
	frog->fr_pos.vz = vec.vz << 16;
	MR_CLEAR_VEC(&frog->fr_velocity);
	
	Cameras[frog->fr_frog_id].ca_flags &= 0xFFFFFFFD;
	switch(game_mode) {
		case GAME_MODE_SINGLE_START:
			SetFrogUserMode(frog, FROGUSER_MODE_LEVEL_START_BOUNCE);
			frog->fr_target_y = frog->fr_pos.vy;
			frog->fr_pos.vy += 0xfe700000;
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

	UpdateFrogPositionalInfo(frog);
	frog->fr_y = frog->fr_lwtrans->t[1];
	UpdateFrogOldPositionalInfo(frog);
	
	Cameras[frog->fr_frog_id].ca_current.vx = frog->fr_lwtrans->t[0];
	Cameras[frog->fr_frog_id].ca_current.vy = frog->fr_lwtrans->t[1];
	Cameras[frog->fr_frog_id].ca_current.vz = frog->fr_lwtrans->t[2];
	MR_INIT_MAT(&frog->fr_matrix);
	frog->fr_lwtrans->m[0][0] = rcos(frog->fr_direction << 10);
	frog->fr_lwtrans->m[0][2] = rsin(frog->fr_direction << 10);
	frog->fr_lwtrans->m[2][0] = -rsin(frog->fr_direction << 10);
	frog->fr_lwtrans->m[2][2] = rcos(frog->fr_direction << 10);
	frog->fr_cam_zone = NULL;
	frog->fr_cam_zone_region = NULL;
	frog->fr_entity = NULL;
	frog->fr_forbid_entity = NULL;
	frog->fr_croak_mode = 0;
	frog->fr_croak_timer = 0;
	frog->fr_croak_scale = FROG_CROAK_MIN_SCALE;
	FrogInitialiseAnimation(frog, FROG_ANIMATION_PANT, 0);
	
	if (frog->fr_trail != NULL) {
		frog->fr_trail->ef_flags |= EFFECT_RESET; // 0x80
		((TRAIL*) frog->fr_trail->ef_extra)->tr_timer = 0;
	}
	
	if (frog->fr_tongue != NULL)
		ResetTongue(frog->fr_tongue);
	
	frog->fr_stack_master = NULL;
	frog->fr_stack_slave = NULL;
	
	env = (MR_ANIM_ENV*) frog->fr_api_item;
	if (Game_total_players > 1) {
		env->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags &= (0xFFFF ^ MR_OBJ_NO_DISPLAY);
	} else {
		env->ae_extra.ae_extra_env_single->ae_object->ob_flags &= (0xFFFF ^ MR_OBJ_NO_DISPLAY);
	}
	
	if (frog->fr_poly_piece_pop != NULL)
		frog->fr_poly_piece_pop->pp_timer = 0;
	
	if (Game_total_players == 1)
		(frog->fr_hud_script + HUD_ITEM_LIVES - 1)->hi_flags |= HUD_ITEM_REBUILD;
	
	FrogInitCustomAmbient(frog);
	
	if (frog->fr_particle_api_item != NULL && (frog->fr_particle_flags & 0x200U))
		FROG_KILL_PARTICLE_EFFECT(frog);
	
	frog->fr_flags &= 0xFFEFFFFF;
	
	if (Game_pausing_xa == -1) {
		XAControl(XACOM_RESUME, 0);
		Game_pausing_xa = 0;
	}
}

// Confirmed.
MR_VOID KillFrog(FROG* frog) { // Done, For Sure.
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

// Confirmed.
MR_VOID UpdateFrogs(MR_VOID) { // Done, For Sure.
	MR_LONG frog_id;
	FROG* frog;
	FROG* frog_other;
	
	for (frog_id = 0; frog_id < Game_total_players; frog_id++) {
		frog = &Frogs[frog_id];
		ControlFrog(frog);
		MoveFrog(frog);
		UpdateFrogPowerUps(frog); // BaseColor -> 1 -> This -> UpdateFrogStackMaster
	}
	
	for (frog_id = 0; frog_id < Game_total_players; frog_id++) {
		frog = &Frogs[frog_id];
		
		if ((frog->fr_stack_master != NULL) && (frog->fr_stack_slave == NULL)) {
			if (frog->fr_stack_count != 0)
				frog->fr_stack_count--;
			
			frog_other = frog;
			while (frog_other != NULL) {
				UpdateFrogStackMaster(frog_other, frog);
				frog_other = frog_other->fr_stack_master;
			}
		}
	}
	
	for (frog_id = 0; frog_id < Game_total_players; frog_id++) {
		frog = &Frogs[frog_id];
		if ((frog->fr_flags & (FROG_ACTIVE | FROG_CONTROL_ACTIVE)) == (FROG_ACTIVE | FROG_CONTROL_ACTIVE))
			CollideFrog(frog);
		UpdateFrogEffects(frog);
		UpdateFrogBaseColour(frog);
	}
}

// Confirmed.
MR_VOID ControlFrog(FROG* frog) { // Done, For Sure.

	if (frog->fr_flags & FROG_MUST_DIE) {
		frog->fr_flags &= ~FROG_MUST_DIE;
		frog->fr_mode = FROG_MODE_DYING;
		frog->fr_count = FROG_DEATH_TIME;
		Cameras[frog->fr_frog_id].ca_next_source_ofs.vy = -1000;
		Cameras[frog->fr_frog_id].ca_next_source_ofs.vz = -100;
		Cameras[frog->fr_frog_id].ca_next_source_ofs.vx = 0;
		Cameras[frog->fr_frog_id].ca_next_target_ofs.vx = 0;
		Cameras[frog->fr_frog_id].ca_next_target_ofs.vy = 0;
		Cameras[frog->fr_frog_id].ca_next_target_ofs.vz = 0;
		Cameras[frog->fr_frog_id].ca_move_timer = 0x2d;
	}
	
	if (Game_start_timer == 0 && (frog->fr_flags & FROG_CONTROL_ACTIVE)) {
		if (frog->fr_mode >= FROG_MODE_USER) {
			if (Froguser_mode_control_functions[frog->fr_mode - FROG_MODE_USER] != NULL)
				Froguser_mode_control_functions[frog->fr_mode - FROG_MODE_USER](frog, frog->fr_mode);
		} else {
			if (Frogger_controller_hooks[frog->fr_mode] != NULL)
				Frogger_controller_hooks[frog->fr_mode](frog, frog->fr_mode);
		}
	}
	
	FrogUpdateCroak(frog);
}

// Confirmed.
MR_VOID MoveFrog(FROG* frog) { // Done, For Sure.
	MR_ULONG result;
	MR_ULONG local_num;
	LIVE_ENTITY* live_ent;
	
	result = 0;
	frog->fr_old_pos.vx = frog->fr_pos.vx;
	frog->fr_old_pos.vy = frog->fr_pos.vy;
	frog->fr_old_pos.vz = frog->fr_pos.vz;
	
	if (frog->fr_mode >= FROG_MODE_USER) {
		if (Froguser_mode_movement_functions[frog->fr_mode - FROG_MODE_USER] != NULL)
			result = Froguser_mode_movement_functions[frog->fr_mode - FROG_MODE_USER](frog, frog->fr_mode, &local_num);
	} else {
		if (Frogger_movement_hooks[frog->fr_mode] != NULL)
			result = Frogger_movement_hooks[frog->fr_mode](frog, frog->fr_mode, &local_num);
	}
	
	if (result & FROG_MOVEMENT_CALLBACK_UPDATE_POS)
		UpdateFrogPositionalInfo(frog);
	
	if (result & FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX)
		UpdateFrogMatrix(frog);
	
	if (result & FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS)
		ReactFrogWithGridFlags(frog, (MR_USHORT) local_num);
	
	if (result & FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS)
		UpdateFrogOldPositionalInfo(frog);
	
	if (frog->fr_flags & FROG_ON_ENTITY) {
		live_ent = frog->fr_entity->en_live_entity;
		live_ent->le_flags |= (FROG_ON_ENTITY << (frog->fr_frog_id & 0x1F));
	}
	
	UpdateFrogCameraZone(frog);
}

// Confirmed.
MR_VOID UpdateFrogPositionalInfo(FROG* frog) { // Done, For Sure.
	frog->fr_lwtrans->t[0] = (frog->fr_pos.vx >> 16);
	frog->fr_lwtrans->t[1] = (frog->fr_pos.vy >> 16);
	frog->fr_lwtrans->t[2] = (frog->fr_pos.vz >> 16);
	frog->fr_grid_x = (frog->fr_lwtrans->t[0] - Grid_base_x) >> 8;
	frog->fr_grid_z = (frog->fr_lwtrans->t[2] - Grid_base_z) >> 8;
}

// Confirmed.
MR_VOID UpdateFrogOldPositionalInfo(FROG* frog) { // Done, For Sure.
	frog->fr_old_pos.vx = frog->fr_pos.vx;
	frog->fr_old_pos.vy = frog->fr_pos.vy;
	frog->fr_old_pos.vz = frog->fr_pos.vz;
	frog->fr_old_grid_x = frog->fr_grid_x;
	frog->fr_old_grid_z = frog->fr_grid_z;
	frog->fr_old_grid_square = frog->fr_grid_square;
	frog->fr_old_y = frog->fr_y;
}

// Confirmed.
MR_VOID SetFrogUserMode(FROG* frog, MR_ULONG mode) { // Done, For Sure.
	if (Froguser_mode_setup_functions[mode] != NULL && mode < FROG_MODE_USER) // This calls the last mode.
		Froguser_mode_setup_functions[mode](frog, mode);
	
	frog->fr_mode = mode;
}

// Confirmed.
//NOTE: Trap appears to be division error checking.
//uint -> MR_ULONG
//bool -> MR_BOOL
//ushort -> MR_USHORT
//undefined4 -> MR_ULONG
//void -> MR_VOID (Optional)
// Don't forget to make the formpointers thing cast to (FORM_DATA**), then dereference into FORM_DATA*.
// Get rid of traps, which are division safety checks.
//  printf("JumpFrog(%d, %d, %d, %d, %d);\n", frog->fr_frog_id, arg1, arg2, arg3, arg4);
//  printf("Frog Flags: %d\n", frog->fr_flags);
MR_VOID JumpFrog(FROG* frog, MR_LONG arg1, MR_ULONG arg2, MR_LONG arg3, MR_LONG arg4) { // Not Done.
  MR_BOOL bVar1;
  MR_USHORT uVar2;
  short sVar3;
  short sVar4;
  FORM_BOOK *pFVar5;
  GRID_STACK *pGVar6;
  MR_ULONG local_v0_2972;
  ENTITY *pEVar7;
  int iVar8;
  void *pvVar9;
  MR_MAT **ppMVar10;
  int iVar11;
  FROG **ppFVar12;
  FROG *pFVar13;
  MR_ULONG uVar14;
  FORM_DATA *local_a2_788;
  int iParm2;
  int iVar15;
  int iVar16;
  int iVar17;
  MR_ULONG uVar18;
  GRID_SQUARE *pGVar19;
  void *pvVar20;
  MR_ULONG uVar21;
  FORM *pFVar22;
  int iVar23;
  int iVar24;
  MR_SVEC local_80;
  MR_VEC MStack120;
  MR_ULONG local_68;
  MR_ULONG local_60;
  int local_58;
  CAMERA *camera;
//  printf("JumpFrog(%d, %d, %d, %d, %d);\n", frog->fr_frog_id, arg1, arg2, arg3, arg4);
//  printf("Frog Flags: %d\n", frog->fr_flags);
  
  local_58 = 0;
  sVar3 = 0;
  local_60 = frog->fr_direction;
  camera = Cameras + frog->fr_frog_id;
  iVar16 = frog->fr_entity_grid_x;
  iVar15 = 0;
  pEVar7 = frog->fr_entity;
  iVar17 = frog->fr_entity_grid_z;
  iParm2 = 0;
  if (frog->fr_stack_master != (FROG *)0x0) {
    frog->fr_stack_master->fr_stack_slave = (FROG *)0x0;
    frog->fr_stack_master = (FROG *)0x0;
  }
  if (frog->fr_stack_slave != (FROG *)0x0) {
    frog->fr_stack_slave->fr_stack_master = (FROG *)0x0;
    frog->fr_stack_slave = (FROG *)0x0;
  }
  iVar23 = 0x1c0;
  if ((arg2 & 1) == 0) {
    if ((arg2 & 2) == 0) {
      iVar23 = 200;
      if ((frog->fr_grid_square != (GRID_SQUARE *)0x0) &&
         ((frog->fr_grid_square->gs_flags & 0x200) != 0)) {
        iVar23 = 0xff;
      }
    }
    else {
      iVar23 = 0x7fff;
    }
  }
  uVar21 = camera->ca_frog_controller_directions[arg1 & 3];
  if ((frog->fr_flags & FROG_ON_ENTITY) == 0) {
    if (uVar21 == 1) {
      iVar15 = 1;
LAB_80027c30:
      iParm2 = 0;
LAB_80027c34:
      iVar16 = iVar15 * arg3;
    }
    else {
      if ((int)uVar21 < 2) {
        iVar16 = 0;
        if (uVar21 == 0) {
          iVar15 = 0;
          iParm2 = 1;
          goto LAB_80027c34;
        }
      }
      else {
        if (uVar21 == 2) {
          iVar15 = 0;
          iParm2 = -1;
          goto LAB_80027c34;
        }
        iVar16 = 0;
        if (uVar21 == 3) {
          iVar15 = -1;
          goto LAB_80027c30;
        }
      }
    }
    iVar17 = arg3 + -1;
    pvVar20 = (void *)(frog->fr_grid_x + iVar16);
    pvVar9 = (void *)(frog->fr_grid_z + iParm2 * arg3);
    if (arg3 != 0) {
      do {
        if ((((-1 < (int)pvVar20) && ((int)pvVar20 < Grid_xnum)) && (-1 < (int)pvVar9)) &&
           ((int)pvVar9 < Grid_znum)) break;
        pvVar20 = (void *)((int)pvVar20 + iVar15);
        pvVar9 = (void *)((int)pvVar9 + iParm2);
        bVar1 = iVar17 != 0;
        iVar17 += -1;
      } while (bVar1);
    }
    local_68 = arg2;
    if (iVar17 < 0) {
LAB_80028018:
      pGVar19 = (GRID_SQUARE *)0x0;
LAB_8002801c:
      uVar18 = frog->fr_flags & 0xffffffbd;
LAB_80028028:
      frog->fr_flags = uVar18;
      *(void **)&frog->fr_grid_x = pvVar20;
      iParm2 = Grid_base_x;
      *(void **)&frog->fr_grid_z = pvVar9;
      frog->fr_grid_square = pGVar19;
      frog->fr_direction = uVar21;
      (frog->fr_target_pos).vx = (short)frog->fr_grid_x * 0x100 + (short)iParm2 + 0x80;
      sVar4 = (short)Grid_base_z;
      sVar3 = (short)(frog->fr_grid_z << 8);
LAB_80028070:
      local_58 = -1;
      (frog->fr_target_pos).vz = sVar3 + sVar4 + 0x80;
    }
    else {
      if (iParm2 == 1) {
        local_68 = arg2;
        if ((frog->fr_grid_square->gs_flags & 0x4000) != 0) {
          frog->fr_user_data1 = pvVar20;
          local_68 = arg2;
LAB_80027e38:
          frog->fr_user_data2 = pvVar9;
          frog->fr_direction = uVar21;
          FroguserBouncyCobwebSetup(frog,0x105);
          frog->fr_mode = 0x105;
          return;
        }
      }
      else {
        if (iParm2 == -1) {
          local_68 = arg2;
          pGVar6 = GetGridStack((int)pvVar20,(int)pvVar9);
          uVar18 = (MR_ULONG)pGVar6->gs_numsquares;
          if (pGVar6->gs_numsquares != 0) {
            pGVar19 = Grid_squares + (MR_ULONG)pGVar6->gs_index;
            do {
              uVar18 -= 1;
              if ((pGVar19->gs_flags & 0x4000) != 0) goto LAB_80027e34;
              pGVar19 = pGVar19 + 1;
            } while (uVar18 != 0);
          }
        }
        else {
          if (iVar15 == 1) {
            local_68 = arg2;
            if ((frog->fr_grid_square->gs_flags & 0x8000) != 0) {
              frog->fr_user_data1 = pvVar20;
              local_68 = arg2;
              goto LAB_80027e38;
            }
          }
          else {
            local_68 = arg2;
            if (iVar15 == -1) {
              local_68 = arg2;
              pGVar6 = GetGridStack((int)pvVar20,(int)pvVar9);
              uVar18 = (MR_ULONG)pGVar6->gs_numsquares;
              if (pGVar6->gs_numsquares != 0) {
                pGVar19 = Grid_squares + (MR_ULONG)pGVar6->gs_index;
                do {
                  uVar18 -= 1;
                  if ((pGVar19->gs_flags & 0x8000) != 0) goto LAB_80027e34;
                  pGVar19 = pGVar19 + 1;
                } while (uVar18 != 0);
              }
            }
          }
        }
      }
      pGVar6 = GetGridStack((int)pvVar20,(int)pvVar9);
      uVar18 = (MR_ULONG)pGVar6->gs_numsquares;
      if (pGVar6->gs_numsquares == 0) goto LAB_80028018;
      pGVar19 = Grid_squares + (MR_ULONG)pGVar6->gs_index;
      do {
        uVar18 -= 1;
        if ((pGVar19->gs_flags & 1) != 0) {
          if (((pGVar19->gs_flags & 0x800) != 0) &&
             (iParm2 = GetGridStackHeight(pGVar6), -iParm2 <= frog->fr_lwtrans->t[1])) goto LAB_80027e34;
          iParm2 = GetGridSquareHeight(pGVar19);
          iVar15 = frog->fr_lwtrans->t[1];
          if ((iParm2 <= iVar15) && (iVar15 - iParm2 <= iVar23)) {
            uVar18 = frog->fr_flags | 0x40;
            goto LAB_80028028;
          }
          if ((iVar15 <= iParm2) && (iParm2 - iVar15 < 0x101)) {
            uVar18 = frog->fr_flags | 0x40;
            goto LAB_80028028;
          }
        }
        pGVar19 = pGVar19 + 1;
      } while (uVar18 != 0);
      uVar18 = (MR_ULONG)pGVar6->gs_numsquares;
      pGVar19 = Grid_squares + (MR_ULONG)pGVar6->gs_index + uVar18 + -1;
      while (bVar1 = uVar18 != 0, uVar18 -= 1, bVar1) {
        iParm2 = GetGridSquareHeight(pGVar19);
        if (((pGVar19->gs_flags & 1) != 0) && (frog->fr_lwtrans->t[1] <= iParm2)) goto LAB_8002801c;
        pGVar19 = pGVar19 + -1;
      }
      if ((local_68 & 2) != 0) goto LAB_8002801c;
      uVar18 = frog->fr_direction;
      frog->fr_direction = uVar21;
      frog->fr_old_direction = uVar18;
      FrogRequestAnimation(frog,0x10,0);
    }
  }
  else {
    uVar2 = pEVar7->en_form_book_id;
    pFVar22 = ENTITY_GET_FORM(pEVar7);
    pFVar5 = Form_library_ptrs[(MR_ULONG)(uVar2 >> 0xf)]; //TODO: Change this code and the code that uses this value to run ENTITY_GET_FORM_BOOK.
    frog->fr_flags = frog->fr_flags & 0xfffffffb;
    if (!(pFVar5[(MR_ULONG)uVar2 & 0x7fff].fb_flags & FORM_BOOK_FROG_NO_ENTITY_ANGLE)) {
      local_60 = frog->fr_direction;
      uVar21 = (frog->fr_entity_angle + arg1) & 3; // NOTE: Parenthesis were added by me.
      frog->fr_direction = uVar21;
//	  printf("uVar21: %d :::: (%d + %d) & 3\n", uVar21, frog->fr_entity_angle, arg1);
	  if (uVar21 == 1) { // East
		iVar15 = 1;
		iParm2 = 0;
	  } else if (uVar21 == 2) { // South
		iVar15 = 0;
        iParm2 = -1;
	  } else if (uVar21 == 0) { // North
		iVar15 = 0;
        iParm2 = 1;
	  } else if (uVar21 == 3) { // West
		iVar15 = -1;
		iParm2 = 0;
	  }
	  
      uVar21 = arg3 * iVar15 * 0x1000000;
      iVar8 = frog->fr_entity_grid_x;
      iVar11 = frog->fr_entity_grid_z;
	  iVar8 += iVar15 * arg3;
	  iVar11 += iParm2 * arg3;
      (frog->fr_velocity).vy = 0;
      frog->fr_entity_grid_x = iVar8;
      frog->fr_entity_grid_z = iVar11;
      (frog->fr_velocity).vx = uVar21;
      (frog->fr_velocity).vz = uVar21;
      local_a2_788 = ((FORM_DATA **) &pFVar22->fo_formdata_ptrs)[0];
//	  printf("Test 2 - Real: [%d, %d] Max: [%d, %d]\n", iVar8, iVar11, (int)pFVar22->fo_xnum, (int)pFVar22->fo_znum);
      if ((((-1 < iVar8) && (iVar8 < (int)pFVar22->fo_xnum)) && (-1 < iVar11)) && (iVar11 < (int)pFVar22->fo_znum)) {
        iVar24 = 0;
		iVar24 = (iVar11 * (int)pFVar22->fo_xnum) + frog->fr_entity_grid_x;
		
		if (local_a2_788->fd_height_type == 0) {
          sVar3 = local_a2_788->fd_height;
        } else if (local_a2_788->fd_height_type == 1) {
          sVar3 = local_a2_788->fd_heights[iVar24];
        }
		
//		printf("Index: %d, Height: %d, Flags: %d, Height Type: %d\n", iVar24, sVar3, local_a2_788->fd_grid_squares[iVar24], local_a2_788->fd_height_type);
//		printf("Flags: [%d %d %d %d %d %d [%d %d]]\n", local_a2_788->fd_grid_squares[0], local_a2_788->fd_grid_squares[1], local_a2_788->fd_grid_squares[2], local_a2_788->fd_grid_squares[3], local_a2_788->fd_grid_squares[4], local_a2_788->fd_grid_squares[5], local_a2_788->fd_grid_squares[-1], local_a2_788->fd_grid_squares[-2]);
        if ((local_a2_788->fd_grid_squares[iVar24] & GRID_SQUARE_USABLE) == 0) goto LAB_80027990;
        iParm2 = frog->fr_entity_grid_x;
        frog->fr_flags = frog->fr_flags | (FROG_JUMP_FROM_ENTITY | FROG_JUMP_TO_ENTITY);
        sVar4 = pFVar22->fo_xofs;
        iVar15 = frog->fr_entity_grid_z;
        (frog->fr_target_pos).vy = sVar3;
        (frog->fr_target_pos).vx = sVar4 + (short)iParm2 * 0x100 + 0x80;
        sVar3 = pFVar22->fo_zofs;
        sVar4 = (short)(iVar15 << 8);
        local_68 = arg2;
        goto LAB_80028070;
      }
      sVar3 = local_a2_788->fd_height;
LAB_80027990:
      frog->fr_flags = (frog->fr_flags & 0xfffffffd) | FROG_JUMP_FROM_ENTITY;
      uVar21 = camera->ca_frog_controller_directions[arg1 & 3];
      if (uVar21 == 1) { // East
        iVar15 = 1;
LAB_80027a1c:
        iParm2 = 0;
LAB_80027a20:
        iVar15 *= arg3;
      }
      else {
        if ((int)uVar21 < 2) {
          iVar15 *= arg3;
          if (uVar21 == 0) { // North
            iVar15 = 0;
            iParm2 = 1;
            goto LAB_80027a20;
          }
        }
        else {
          if (uVar21 == 2) { // South
            iVar15 = 0;
            iParm2 = -1;
            goto LAB_80027a20;
          }
          iVar15 *= arg3;
          if (uVar21 == 3) { // West
            iVar15 = -1;
            goto LAB_80027a1c;
          }
        }
      }
      pvVar20 = (void *)(frog->fr_grid_x + iVar15);
      pvVar9 = (void *)(frog->fr_grid_z + iParm2 * arg3);
    }
    else {
      ppMVar10 = &camera->ca_matrix + arg1 * 4;
      (frog->fr_target_pos).vx =
           (short)frog->fr_lwtrans->t[0] + (short)((int)ppMVar10[0x2d] * arg3 >> 4);
      (frog->fr_target_pos).vy =
           (short)frog->fr_lwtrans->t[1] + (short)((int)ppMVar10[0x2e] * arg3 >> 4);
      iParm2 = Grid_base_z;
      pvVar20 = (void *)((int)(frog->fr_target_pos).vx - Grid_base_x >> 8);
      (frog->fr_target_pos).vz =
           (short)frog->fr_lwtrans->t[2] + (short)((int)ppMVar10[0x2f] * arg3 >> 4);
      pvVar9 = (void *)((int)(frog->fr_target_pos).vz - iParm2 >> 8);
      frog->fr_direction = camera->ca_frog_controller_directions[arg1];
    }
    frog->fr_forbid_entity = frog->fr_entity;
    local_68 = arg2;
    pGVar6 = GetGridStack((int)pvVar20,(int)pvVar9);
    uVar18 = (MR_ULONG)pGVar6->gs_numsquares;
    if (pGVar6->gs_numsquares != 0) {
      pGVar19 = Grid_squares + (MR_ULONG)pGVar6->gs_index;
      do {
        uVar18 -= 1;
        if ((pGVar19->gs_flags & 1) == 0) {
          FrogRequestAnimation(frog,0x10,0);
          uVar18 = frog->fr_direction;
          uVar21 = frog->fr_flags;
          frog->fr_entity_grid_x = iVar16;
          frog->fr_entity_grid_z = iVar17;
          (frog->fr_velocity).vx = 0;
          (frog->fr_velocity).vy = 0;
          (frog->fr_velocity).vz = 0;
          frog->fr_flags = uVar21 & 0xffffffef | 4;
          sVar3 = rcos(uVar18 << 10);
          sVar4 = rsin(frog->fr_direction << 10);
          (frog->fr_entity_transform).m[0][2] = sVar4;
          (frog->fr_entity_transform).m[0][0] = sVar3;
          (frog->fr_entity_transform).m[0][1] = 0;
          (frog->fr_entity_transform).m[1][0] = 0;
          (frog->fr_entity_transform).m[1][1] = 0x1000;
          (frog->fr_entity_transform).m[1][2] = 0;
          (frog->fr_entity_transform).m[2][0] = -sVar4;
          (frog->fr_entity_transform).m[2][1] = 0;
          (frog->fr_entity_transform).m[2][2] = sVar3;
          goto LAB_8002807c;
        }
        iParm2 = GetGridSquareHeight(pGVar19);
        iVar15 = frog->fr_lwtrans->t[1];
        if ((((iParm2 <= iVar15) && (iVar15 - iParm2 <= iVar23)) ||
            ((iVar15 <= iParm2 && (iParm2 - iVar15 < 0x101)))) && ((pGVar19->gs_flags & 8) == 0)) {
          uVar18 = frog->fr_flags | 0x40;
          goto LAB_80028028;
        }
        pGVar19 = pGVar19 + 1;
      } while (uVar18 != 0);
    }
    *(void **)&frog->fr_grid_x = pvVar20;
    *(void **)&frog->fr_grid_z = pvVar9;
    frog->fr_grid_square = (GRID_SQUARE *)0x0;
    frog->fr_flags = frog->fr_flags & 0xffffffbd | 0x10;
    if ((pFVar5[(MR_ULONG)uVar2 & 0x7fff].fb_flags & 4) == 0) {
      iParm2 = frog->fr_entity_grid_x;
      sVar4 = pFVar22->fo_xofs;
      iVar15 = frog->fr_entity_grid_z;
      (frog->fr_target_pos).vy = sVar3;
      (frog->fr_target_pos).vx = sVar4 + (short)iParm2 * 0x100 + 0x80;
      (frog->fr_target_pos).vz = pFVar22->fo_zofs + (short)iVar15 * 0x100 + 0x80;
    }
    else {
      ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans,&MRTemp_matrix);
      MulMatrix(&camera->ca_mod_matrix,&MRTemp_matrix);
      frog->fr_entity = (ENTITY *)0x0;
      frog->fr_flags = frog->fr_flags & 0xffffffef;
    }
    local_58 = -1;
  }
LAB_8002807c:
  if (local_58 != -1) {
    return;
  }
  frog->fr_mode = 1;
  if ((local_68 & 1) == 0) {
    MRSNDPlaySound(6,0,0,(Game_timer & 3) << 7);
    if ((frog->fr_powerup_flags & 2) == 0) {
      if ((frog->fr_powerup_flags & 4) == 0) {
        if (frog->fr_direction == local_60) {
          if (3 < frog->fr_buffered_input_count) {
            FrogRequestAnimation(frog,0x13,0);
            AddFrogScore(frog,3,(MR_MAT *)0x0);
            frog->fr_buffered_input_count = 0;
            goto LAB_80028254;
          }
LAB_80028234:
          iParm2 = 0x17;
        }
        else {
          if (((frog->fr_flags & 0x12) != 0x10) || (local_60 != frog->fr_direction - 2))
          goto LAB_80028234;
          iParm2 = 2;
        }
        FrogRequestAnimation(frog,iParm2,0);
        uVar21 = 0;
        goto LAB_8002824c;
      }
      FrogRequestAnimation(frog,0,0);
    }
    else {
      FrogRequestAnimation(frog,0x1c,0);
      uVar21 = 3;
LAB_8002824c:
      AddFrogScore(frog,uVar21,(MR_MAT *)0x0);
    }
LAB_80028254:
    frog->fr_trail->ef_flags = frog->fr_trail->ef_flags | 0x80;
    *(MR_ULONG *)((int)frog->fr_trail->ef_extra + 0x154) = 0x404040;
    pvVar9 = frog->fr_trail->ef_extra;
    local_v0_2972 = 0x10;
  }
  else {
    frog->fr_flags = frog->fr_flags | 0x20;
    MRSNDPlaySound(7,0,0,0);
    FrogRequestAnimation(frog,0x19,0);
    AddFrogScore(frog,1,(MR_MAT *)0x0);
    DisplayHUDHelp(frog->fr_frog_id,0);
    frog->fr_trail->ef_flags = frog->fr_trail->ef_flags | 0x80;
    *(MR_ULONG *)((int)frog->fr_trail->ef_extra + 0x154) = 0x404040;
    pvVar9 = frog->fr_trail->ef_extra;
    local_v0_2972 = 0x1a;
  }
  *(MR_ULONG *)((int)pvVar9 + 8) = local_v0_2972;
  frog->fr_count = arg4;
  frog->fr_old_y = frog->fr_y;
  if ((frog->fr_flags & 0x40) == 0) {
    if ((frog->fr_flags & 0x12) != 0x12) {
      uVar21 = -((frog->fr_count + 1) * 0x100000 >> 1);
      frog->fr_y = frog->fr_lwtrans->t[1];
      goto LAB_80028478;
    }
    pFVar13 = &Frogs[0];
    if (Game_total_players != 0) {
      ppFVar12 = &Frogs[0].fr_stack_master;
      uVar21 = Game_total_players;
      do {
        uVar21 -= 1;
        if (((pFVar13 != frog) && (ppFVar12[-100] == (FROG *)frog->fr_entity)) &&
           (*ppFVar12 == (FROG *)0x0)) {
          iParm2 = pFVar13->fr_lwtrans->t[1] + -100;
          goto LAB_800283f8;
        }
        ppFVar12 = ppFVar12 + 0xab;
        pFVar13 = pFVar13 + 1;
      } while (uVar21 != 0);
    }
    local_80.vx = 0;
    local_80.vy = (frog->fr_target_pos).vy;
    local_80.vz = 0;
    ApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans,&local_80,&MStack120);
    iParm2 = MStack120.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1];
LAB_800283f8:
    frog->fr_y = iParm2;
  }
  else {
    pFVar13 = &Frogs[0];
    if (Game_total_players != 0) {
      ppFVar12 = &Frogs[0].fr_stack_master;
      uVar21 = Game_total_players;
      do {
        uVar21 -= 1;
        if (((pFVar13 != frog) && (ppFVar12[-0x94] == (FROG *)frog->fr_grid_square)) &&
           (*ppFVar12 == (FROG *)0x0)) {
          iParm2 = pFVar13->fr_lwtrans->t[1] + -100;
          goto LAB_800283f8;
        }
        ppFVar12 = ppFVar12 + 0xab;
        pFVar13 = pFVar13 + 1;
      } while (uVar21 != 0);
    }
    iParm2 = GetGridSquareHeight(frog->fr_grid_square);
    frog->fr_y = iParm2;
  }
  iVar15 = (frog->fr_y - frog->fr_lwtrans->t[1]) * 0x10000;
  iParm2 = frog->fr_count + 1;
  uVar21 = iVar15 / iParm2 - (iParm2 * 0x100000 >> 1);
LAB_80028478:
  if ((frog->fr_entity == (ENTITY *)0x0) || ((frog->fr_flags & 0x40) != 0)) {
    iParm2 = frog->fr_count;
    iVar15 = (int)(frog->fr_target_pos).vx * 0x10000 - (frog->fr_pos).vx;
    uVar18 = iVar15 / iParm2;
    uVar14 = (frog->fr_pos).vz;
  }
  else {
    iParm2 = frog->fr_count;
    iVar15 = (int)(frog->fr_target_pos).vx * 0x10000 - (frog->fr_entity_ofs).vx;
    uVar18 = iVar15 / iParm2;
    uVar14 = (frog->fr_entity_ofs).vz;
  }
  iVar15 = frog->fr_count;
  iParm2 = (int)(frog->fr_target_pos).vz * 0x10000 - uVar14;
  (frog->fr_velocity).vy = uVar21;
  (frog->fr_velocity).vx = uVar18;
  (frog->fr_velocity).vz = iParm2 / iVar15;
  return;
LAB_80027e34:
  frog->fr_user_data1 = pvVar20;
  goto LAB_80027e38;
}

// Confirmed.
MR_VOID FrogModeControlStationary(FROG* frog, MR_ULONG mode) { // Done, For Sure.
	MR_ULONG i;
	MR_LONG iVar3;
	MR_ULONG dir;
	MR_ULONG jumpArg2;
	MR_ULONG jumpArg4;
	ZONE* zone;
	CAMERA* camera;
	ZONE_CAMERA* zone_camera;
	
	dir = FROG_DIRECTION_NO_INPUT;
	frog->fr_previous_key = frog->fr_current_key;
	frog->fr_no_input_timer++;
	
	i = frog->fr_num_buffered_keys;
	jumpArg2 = 0;
	jumpArg4 = frog->fr_frog_id;
	while (i--) {
		iVar3 = frog->fr_buffered_key[frog->fr_num_buffered_keys - 1 - i];
		
		switch (iVar3) {
			case 0:
				if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
					dir = 0;
					i = frog->fr_buffered_input_count + 1;
				}
				break;
			case 1:
				if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
					dir = 1;
					i = frog->fr_buffered_input_count + 1;
				}
				break;
			case 2:
				if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
					dir = 2;
					i = frog->fr_buffered_input_count + 1;
				}
				break;
			case 3:
				if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_left_control)) {
					dir = 3;
					i = frog->fr_buffered_input_count + 1;
				}
				break;
			default:
//				printf("[FrogModeControlStationary] Don't know how to handle: %d\n", iVar3);
				break;
		}

		if (dir != FROG_DIRECTION_NO_INPUT)
			break;
	}
	
	if (dir == FROG_DIRECTION_NO_INPUT)
		i = frog->fr_buffered_input_count - 1;
	
	if (dir != FROG_DIRECTION_NO_INPUT || frog->fr_buffered_input_count > 0)
		frog->fr_buffered_input_count = i;
		
	frog->fr_num_buffered_keys = 0;
	
	if (dir == FROG_DIRECTION_NO_INPUT) {
		if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_camera_clockwise_control))
			dir |= FROG_DIRECTION_CAMERA_CLOCKWISE;
		if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_camera_anticlockwise_control))
			dir |= FROG_DIRECTION_CAMERA_ANTICLOCKWISE;
		if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_tongue_control))
			dir |= FROG_DIRECTION_TONGUE;
		if (MR_CHECK_PAD_RELEASED(frog->fr_input_id, frog->fr_control_method->fc_superjump_control) && frog->fr_stack_master == NULL)
			dir |= FROG_DIRECTION_SUPER_JUMP;
		
		if (frog->fr_stack_master == NULL) {
			if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
				if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
					if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
						if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_left_control))
							dir = 3;
					} else {
						dir = 2;
					}
				} else {
					dir = 1;
				}
			} else {
				dir = 0;
			}
			
			if (frog->fr_powerup_flags & 4) {
				if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
					if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
						if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
							if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_left_control))
								dir = 3;
						} else {
							dir = 2;
						}
					} else {
						dir = 1;
					}
				} else {
					dir = 0;
				}
			}
		}
		
		if (Game_flags & GAME_FLAG_DEMO_RUNNING) { // Apply demo key-strokes.
			dir = *Demo_data_input_ptr;
			Demo_data_input_ptr++;
		}
		
		if (frog->fr_mode == FROG_MODE_STATIONARY) {
			camera = &Cameras[frog->fr_frog_id];
			zone = camera->ca_zone;
			zone_camera = ((ZONE_CAMERA*)(zone + 1));
			
			if ((dir & FROG_DIRECTION_CAMERA_CLOCKWISE) && (zone == NULL || zone_camera->zc_direction < 0 || (zone_camera->zc_flags & ZONE_FLAG_SEMIFORCED))) {
				frog->fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
				camera->ca_twist_counter = 1;
				camera->ca_twist_quadrants = 1;
				camera->ca_move_timer = 8;
				
				if (frog->fr_cam_zone == NULL) {
					camera->ca_next_source_ofs = Map_general_header->gh_default_camera_source_ofs;
					camera->ca_next_source_ofs.vz = Map_general_header->gh_default_camera_source_ofs.vz;
					camera->ca_next_target_ofs = Map_general_header->gh_default_camera_target_ofs;
					camera->ca_next_target_ofs.vz = Map_general_header->gh_default_camera_target_ofs.vz;
					return;
				}
				
				dir = GetWorldYQuadrantFromMatrix(camera->ca_mod_matrix) + 1;
				
				dir &= 3;
				zone_camera = ((ZONE_CAMERA*)(zone + 1 + dir));
				
				camera->ca_next_source_ofs = zone_camera->zc_source_ofs_n;
				camera->ca_next_source_ofs.vz = zone_camera->zc_source_ofs_n.vz;
				camera->ca_next_target_ofs = zone_camera->zc_target_ofs_n;
				camera->ca_next_target_ofs.vz = zone_camera->zc_target_ofs_n.vz;
				return;
			}
				
			if ((dir & FROG_DIRECTION_CAMERA_ANTICLOCKWISE) && (zone == NULL || zone_camera->zc_direction < 0 || (zone_camera->zc_flags & ZONE_FLAG_SEMIFORCED))) {
				frog->fr_mode = FROG_MODE_WAIT_FOR_CAMERA;
				camera->ca_twist_counter = -1;
				camera->ca_twist_quadrants = 1;
				camera->ca_move_timer = 8;
				
				if (frog->fr_cam_zone == NULL) {
					camera->ca_next_source_ofs = Map_general_header->gh_default_camera_source_ofs;
					camera->ca_next_source_ofs.vz = Map_general_header->gh_default_camera_source_ofs.vz;
					camera->ca_next_target_ofs = Map_general_header->gh_default_camera_target_ofs;
					camera->ca_next_target_ofs.vz = Map_general_header->gh_default_camera_target_ofs.vz;
					return;
				}
				
				dir = GetWorldYQuadrantFromMatrix(camera->ca_mod_matrix) - 1;
				
				dir &= 3;
				zone_camera = ((ZONE_CAMERA*)(zone + 1 + dir));
				camera->ca_next_source_ofs = zone_camera->zc_source_ofs_n;
				camera->ca_next_source_ofs.vz = zone_camera->zc_source_ofs_n.vz;
				camera->ca_next_target_ofs = zone_camera->zc_target_ofs_n;
				camera->ca_next_target_ofs.vz = zone_camera->zc_target_ofs_n.vz;
				return;
			}
		}
		
		if ((dir & FROG_DIRECTION_TONGUE) && frog->fr_tongue != NULL && (frog->fr_tongue->ef_flags & (TONGUE_FLAG_MOVING_IN | TONGUE_FLAG_GRABBING))) {
			frog->fr_no_input_timer = 0;
			StartTongue(frog->fr_tongue, FrogGetNearestTongueTarget(frog));
			DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_TONGUE);
			MRSNDPlaySound(SFX_GEN_FROG_SLURP, 0, 0, 0);
		}
	}
	
	if (!(dir & FROG_DIRECTION_SUPER_JUMP)) {
		jumpArg4 = 6;
		if (frog->fr_powerup_flags & 2)
			jumpArg4 = 3;
	} else {
		if (!(frog->fr_flags & FROG_ON_ENTITY)) {
			dir = frog->fr_direction - (&Cameras[jumpArg4])->ca_frog_controller_directions[0];
		} else {
			dir = frog->fr_direction - frog->fr_entity_angle;
		}
		
		dir &= 3;
		jumpArg2 = 1;
		jumpArg4 = 0xF;
	}
	
	if (!(dir & FROG_DIRECTION_NO_INPUT)) {
		frog->fr_no_input_timer = 0;
		JumpFrog(frog, dir, jumpArg2, 1, jumpArg4);
	}
	
	frog->fr_current_key = dir;
}

// Confirmed.
MR_ULONG FrogModeMovementStationary(FROG* frog, MR_ULONG mode, MR_ULONG* result) { // Done, For Sure.
	LIVE_ENTITY *entity;
	MR_ULONG flags;
	MR_SVEC svec;
	MR_VEC vec;
	
	flags = FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
	
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
	
	if ((&Cameras[frog->fr_frog_id])->ca_move_timer == 0 && (&Cameras[frog->fr_frog_id])->ca_twist_counter == 0) {
		frog->fr_mode = FROG_MODE_STATIONARY;
		frog->fr_num_buffered_keys = 0;
	}
	
	return flags;
}

// Confirmed.
MR_ULONG FrogModeMovementCentring(FROG *frog, MR_ULONG mode, MR_ULONG* result) { // Done, For Sure.
	MR_SVEC svec;
	MR_VEC vec;

	if (--frog->fr_count == 0) {
		MR_CLEAR_VEC(&frog->fr_velocity);
		frog->fr_mode = FROG_MODE_STATIONARY;
		frog->fr_entity_ofs.vx = (frog->fr_target_pos.vx << 16);
		frog->fr_entity_ofs.vy = (frog->fr_target_pos.vy << 16);
		frog->fr_entity_ofs.vz = (frog->fr_target_pos.vz << 16);
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
	} else {
		frog->fr_entity_ofs.vx += frog->fr_velocity.vx;
		frog->fr_entity_ofs.vy += frog->fr_velocity.vy;
		frog->fr_entity_ofs.vz += frog->fr_velocity.vz;
	}
	
	svec.vx = (frog->fr_entity_ofs.vx >> 16); // Example of how int + 2 casted to short is bitshift right 16.
	svec.vy = (frog->fr_entity_ofs.vy >> 16);
	svec.vz = (frog->fr_entity_ofs.vz >> 16);
	ApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &svec, &vec);
	frog->fr_pos.vx = ((vec.vx + frog->fr_entity->en_live_entity->le_lwtrans->t[0]) << 16);
	frog->fr_pos.vy = ((vec.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1]) << 16);
	frog->fr_pos.vz = ((vec.vz + frog->fr_entity->en_live_entity->le_lwtrans->t[2]) << 16);
	return (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);
}

// Confirmed.
MR_ULONG FrogModeMovementHitCheckpoint(FROG *frog, MR_ULONG mode, MR_ULONG* result) { // Done.
	MR_ULONG returnVal;
	LIVE_ENTITY* checkpoint;
	
	if (Game_total_players < 2) {
		returnVal = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);
		
		if (frog->fr_count != 0) {
			FrogModeMovementJumping(frog, mode, result);
			returnVal = (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS);
		}
		
		frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
		return returnVal;
	}
	
	if (frog->fr_count-- != 0) {
		if (frog->fr_count == 0) {
			if (Game_mode == GAME_MODE_MULTI_COMPLETE) {
				frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
			} else {
				ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, GAME_MODE_LEVEL_FAST_START);
				ResetCamera(&Cameras[frog->fr_frog_id]);
			}
		}
		
		if (frog->fr_user_data1 != NULL) {
			checkpoint = ((ENTITY*)frog->fr_user_data1)->en_live_entity;
			if (checkpoint != NULL) {
				MRRot_matrix_Y.m[0][2] = rsin(0x40);
				MRRot_matrix_Y.m[2][0] = -rsin(0x40);
				MRRot_matrix_Y.m[0][0] = rcos(0x40);
				MRRot_matrix_Y.m[2][2] = rcos(0x40);
				checkpoint->le_lwtrans->t[1] -= 20;
				MRMulMatrixABB(&MRRot_matrix_Y, checkpoint->le_lwtrans); // MulMatrix2.
			}
		}
	}
	
	return 0;
}

// Good place to test: SWP1. It has barrels right at the start.
// Confirmed.
MR_ULONG FrogModeMovementJumping(FROG* frog, MR_ULONG mode, MR_ULONG* result) { // Done, for sure.
	MR_VEC vec;
	MR_SVEC svec;
	MR_MAT* frog_matrix;
	MR_MAT matrix;
	FORM* form;
	MR_USHORT flags;
	GRID_STACK* grid_stack;
	GRID_SQUARE* grid_square;
	MR_LONG i;
	
	if (frog->fr_count == 0)
		return FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
	
	frog->fr_count--;
	
	if (frog->fr_count != 0) {
		frog->fr_velocity.vy += SYSTEM_GRAVITY;
		if ((frog->fr_flags & (FROG_FREEFALL_NO_ANIMATION | FROG_FREEFALL)) == (FROG_FREEFALL_NO_ANIMATION | FROG_FREEFALL) && (frog->fr_lwtrans->t[1] - frog->fr_old_y) >= 0) {
			FrogRequestAnimation(frog, (Game_map_theme == THEME_SKY) ? FROG_ANIMATION_FREEFALL : FROG_ANIMATION_FALLING, 0);
			frog->fr_flags &= ~FROG_FREEFALL_NO_ANIMATION;
		}
	
		if (frog->fr_entity == NULL || (frog->fr_flags & FROG_JUMP_TO_LAND)) {
			frog->fr_pos.vx += frog->fr_velocity.vx;
			frog->fr_pos.vy += frog->fr_velocity.vy;
			frog->fr_pos.vz += frog->fr_velocity.vz;
		} else {
			frog->fr_entity_ofs.vx += frog->fr_velocity.vx;
			frog->fr_entity_ofs.vz += frog->fr_velocity.vz;
			MRApplyMatrixVEC(frog->fr_entity->en_live_entity->le_lwtrans, &frog->fr_entity_ofs, &vec); // ApplyMatrixLV
			frog->fr_pos.vx = (frog->fr_entity->en_live_entity->le_lwtrans->t[0] << 16) + vec.vx;
			frog->fr_pos.vy += frog->fr_velocity.vy;
			frog->fr_pos.vz = (frog->fr_entity->en_live_entity->le_lwtrans->t[2] << 16) + vec.vz;
		}
		
		return FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
	}
	
	if (!(frog->fr_flags & FROG_JUMP_FROM_ENTITY)) {
		frog->fr_pos.vx = frog->fr_target_pos.vx << 16;
		frog->fr_pos.vz = frog->fr_target_pos.vz << 16;
		if (frog->fr_flags & FROG_JUMP_TO_ENTITY) {
			frog->fr_flags &= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
			frog->fr_count = 0x7FFFFFF;
			frog->fr_velocity.vx = 0;
			frog->fr_velocity.vz = 0;
			return (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);
		}
		
	} else if (frog->fr_flags & FROG_JUMP_TO_ENTITY) {
		frog->fr_flags = (frog->fr_flags & ~FROG_LANDED_ON_ENTITY_CLEAR_MASK) | FROG_ON_ENTITY;
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
		frog->fr_entity_ofs.vx = (frog->fr_target_pos.vx << 16);
		frog->fr_entity_ofs.vy = (frog->fr_target_pos.vy << 16);
		frog->fr_entity_ofs.vz = (frog->fr_target_pos.vz << 16);
		MRTransposeMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &matrix); // TransposeMatrix
		frog_matrix = &frog->fr_entity_transform;
		MRMulMatrixABC(frog->fr_lwtrans, &matrix, frog_matrix); // MulMatrix0
		ProjectMatrixOntoWorldXZ(frog_matrix, frog_matrix);
		
		svec.vx = (frog->fr_entity_ofs.vx >> 16);
		svec.vy = (frog->fr_entity_ofs.vy >> 16);
		svec.vz = (frog->fr_entity_ofs.vz >> 16);
		MRApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &svec, &vec); // ApplyMatrix
		frog->fr_pos.vx = ((vec.vx + frog->fr_entity->en_live_entity->le_lwtrans->t[0]) << 16);
		frog->fr_pos.vy = ((vec.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1]) << 16);
		frog->fr_pos.vz = ((vec.vz + frog->fr_entity->en_live_entity->le_lwtrans->t[2]) << 16);
		frog->fr_velocity.vx = 0;
		frog->fr_velocity.vy = 0;
		frog->fr_velocity.vz = 0;
			
		form = ENTITY_GET_FORM(frog->fr_entity->en_live_entity->le_entity);
		flags = ((FORM_DATA**) &form->fo_formdata_ptrs)[0]->fd_grid_squares[(frog->fr_entity_grid_z * form->fo_xnum) + frog->fr_entity_grid_x];
		*result = (MR_ULONG) flags;
		if (!(flags & GRID_SQUARE_SOFT)) {
			FrogReactToFallDistance(frog, frog->fr_lwtrans->t[1] - frog->fr_old_y);
			return FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
		}
		
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
		return FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;	
	} else {
		if (!(frog->fr_flags & FROG_JUMP_TO_LAND)) {
			frog->fr_entity_ofs.vx = (frog->fr_target_pos.vx << 16);
			frog->fr_entity_ofs.vy = (frog->fr_target_pos.vy << 16);
			frog->fr_entity_ofs.vz = (frog->fr_target_pos.vz << 16);
			svec.vx = (frog->fr_entity_ofs.vx >> 16);
			svec.vy = (frog->fr_entity_ofs.vy >> 16);
			svec.vz = (frog->fr_entity_ofs.vz >> 16);
			ApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &svec, &vec);
			frog->fr_pos.vx = ((vec.vx + frog->fr_entity->en_live_entity->le_lwtrans->t[0]) << 16);
			frog->fr_pos.vy = ((vec.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1]) << 16);
			frog->fr_pos.vz = ((vec.vz + frog->fr_entity->en_live_entity->le_lwtrans->t[2]) << 16);
		}
	}
		
	if (!(frog->fr_flags & FROG_JUMP_TO_LAND)) {
		if (frog->fr_entity != NULL) {
			ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
			MRMulMatrixABA(&Cameras[frog->fr_frog_id].ca_mod_matrix, &MRTemp_matrix); // MulMatrix
			frog->fr_entity = NULL;
		}
			
		if (frog->fr_grid_square == NULL) {
			grid_stack = GetGridStack(frog->fr_grid_x, frog->fr_grid_z);
			grid_square = &Grid_squares[grid_stack->gs_index + grid_stack->gs_numsquares - 1];
			i = grid_stack->gs_numsquares;
			while (i--) {
				if ((grid_square->gs_flags & GRID_SQUARE_USABLE) && (frog->fr_lwtrans->t[1] <= GetGridSquareHeight(grid_square)))
					goto set_grid_square;
				grid_square--;
			}
				
			grid_square = NULL;
set_grid_square:
			frog->fr_grid_square = grid_square;
		}
			
		frog->fr_count = 0x7FFFFFF; // I believe they originally mean't to add another F to this value, so it would be the max positive integer value, however this is what the value is in the executable, so...
		frog->fr_velocity.vx = 0;
		frog->fr_velocity.vz = 0;
		frog->fr_flags &= ~FROG_LANDED_ON_ENTITY_CLEAR_MASK;
		frog->fr_flags |= (FROG_FREEFALL_NO_ANIMATION | FROG_FREEFALL);
		return FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
	}
	
	if (frog->fr_entity != NULL) {
		ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &MRTemp_matrix);
		MulMatrix(&Cameras[frog->fr_frog_id].ca_mod_matrix, &MRTemp_matrix);
		frog->fr_entity = NULL;
	}
	FrogLandedOnLand(frog);
	*result = frog->fr_grid_square->gs_flags;
	
	return FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_REACT_WITH_FLAGS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
}

// Confirmed.
MR_ULONG FrogModeMovementDying(FROG* frog,  MR_ULONG mode, MR_ULONG* result) { // Done, For Sure.
	MR_SVEC svec;
	MR_VEC vec;
	
	if ((frog->fr_flags & FROG_ON_ENTITY) && frog->fr_entity->en_live_entity != NULL) {
		svec.vx = (frog->fr_entity_ofs.vx << 16);
		svec.vy = (frog->fr_entity_ofs.vy << 16);
		svec.vz = (frog->fr_entity_ofs.vz << 16);
		MRApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &svec, &vec);
		frog->fr_pos.vx = (vec.vx + frog->fr_entity->en_live_entity->le_lwtrans->t[0]) * 0x10000;
		frog->fr_pos.vy = (vec.vy + frog->fr_entity->en_live_entity->le_lwtrans->t[1]) * 0x10000;
		frog->fr_pos.vz = (vec.vz + frog->fr_entity->en_live_entity->le_lwtrans->t[2]) * 0x10000;
		frog->fr_y = (frog->fr_pos.vy >> 16);
	}
	
	frog->fr_count--;
	
	if (frog->fr_count == 0) {
		frog->fr_flags &= ~FROG_CONTROL_ACTIVE;

		if (Game_total_players == 1) {
			if (frog->fr_lives == 0)
				frog->fr_flags &= ~FROG_ACTIVE;
			
			if ((Game_mode == GAME_MODE_END_OF_GAME) && frog->fr_lives != 0) {
				LevelEnd();
				LevelStart(GAME_MODE_LEVEL_PLAY);
			} else {
				SetGameMainloopMode(GAME_MODE_SINGLE_FROG_DIED);
			}
		} else {
			ResetFrog(frog, frog->fr_start_grid_x, frog->fr_start_grid_z, GAME_MODE_LEVEL_PLAY);
			ResetCamera(&Cameras[frog->fr_frog_id]);
		}
	}
	
	if ((frog->fr_death_equate == FROG_ANIMATION_MOWN) || (frog->fr_death_equate == FROG_ANIMATION_BITTEN))
		return 0;
	
	frog->fr_pos.vx += frog->fr_velocity.vx;
	frog->fr_pos.vy += frog->fr_velocity.vy;
	frog->fr_pos.vz += frog->fr_velocity.vz;
	return (FROG_MOVEMENT_CALLBACK_UPDATE_POS | FROG_MOVEMENT_CALLBACK_UPDATE_OLD_POS | FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX);
}

// Confirmed.
MR_ULONG FrogModeMovementStunned(FROG* frog, MR_ULONG a, MR_ULONG* b) { // Done, For Sure.
	if (--frog->fr_count == 0) {
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
	}
	
	return FROG_MOVEMENT_CALLBACK_UPDATE_MATRIX;
}

// Confirmed.
MR_VOID FrogLandedOnLand(FROG* frog) { // Done, for sure.
	MR_SVEC svec;
	
	GetGridSquareCentre(frog->fr_grid_square, &svec);
	if (!(frog->fr_grid_square->gs_flags & GRID_SQUARE_DONT_CENTRE_WHEN_LANDED_MASK)) {
		frog->fr_pos.vx = (svec.vx << 16);
		frog->fr_pos.vy = (svec.vy << 16);
		frog->fr_pos.vz = (svec.vz << 16);
	}
	frog->fr_y = (frog->fr_pos.vy >> 16);
	
	if (frog->fr_grid_square->gs_flags & GRID_SQUARE_SOFT) {
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
	} else {
		FrogReactToFallDistance(frog, frog->fr_y - frog->fr_old_y);
	}
	
	frog->fr_entity = NULL;
	frog->fr_forbid_entity = NULL;
	frog->fr_velocity.vx = 0;
	frog->fr_velocity.vy = 0;
	frog->fr_velocity.vz = 0;
	frog->fr_old_y = frog->fr_y;
	frog->fr_flags &= ~FROG_LANDED_ON_LAND_CLEAR_MASK;
	if ((&Cameras[frog->fr_frog_id])->ca_twist_counter == 0)
		SetupCameraYRotation(&Cameras[frog->fr_frog_id]);
	
	frog->fr_old_direction = frog->fr_direction;
	frog->fr_direction = GetWorldYQuadrantFromMatrix(frog->fr_lwtrans);
}

// Confirmed.
MR_VOID FrogReactToFallDistance(FROG* frog, MR_LONG distance) { // Done, for sure.
	if (distance <= FROG_FREEFALL_SAFE_HEIGHT) {
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogRequestAnimation(frog, FROG_ANIMATION_PANT, 0);
	} else if (distance <= FROG_FREEFALL_STUN_HEIGHT) {
		frog->fr_mode = FROG_MODE_STUNNED;
		frog->fr_count = FROG_FREEFALL_STUN_TIME;
		MRSNDPlaySound(SFX_GEN_FROG_STUNNED, 0, 0, 0);
		FrogRequestAnimation(frog, FROG_ANIMATION_CRASH, 0);
		ShakeCamera(&Cameras[frog->fr_frog_id], MR_OBJ_STATIC, frog->fr_count, 0x5000);
	} else {
		frog->fr_mode = FROG_MODE_STATIONARY;
		FrogKill(frog, ((Game_map_theme == THEME_VOL) ? FROG_ANIMATION_DROWN : FROG_ANIMATION_SQUISHED), NULL);
	}
}

// Confirmed.
MR_VOID UpdateFrogEffects(FROG* frog) { // Done, for sure.
	EFFECT* shadow_effect;
	SHADOW* shadow;
	MR_LONG stage;
	
	shadow_effect = frog->fr_shadow;
	
	if (shadow_effect != NULL) {
		if (frog->fr_entity == NULL
			&& (frog->fr_mode != FROG_MODE_DYING)
			&& (frog->fr_mode != FROGUSER_MODE_CHECKPOINT_COLLECTED)
			&& (frog->fr_mode != FROG_MODE_JUMPING || frog->fr_flags & FROG_JUMP_TO_LAND))
		{
			if (frog->fr_mode == FROG_MODE_JUMPING && !(frog->fr_flags & FROG_JUMP_ON_SPOT)) {
				if (frog->fr_flags & FROG_SUPERJUMP) {
					stage = ((FROG_SUPERJUMP_TIME - frog->fr_count) * FROG_JUMP_TIME) / FROG_SUPERJUMP_TIME;
				} else {
					stage = FROG_JUMP_TIME - frog->fr_count;
				}
				
				stage = MAX(0, MIN(FROG_JUMP_TIME - 1, stage));
			} else {
				stage = 0;
			}
			
			// Update texture & flags.
			shadow	= (SHADOW*)shadow_effect->ef_extra;
			shadow->sh_offsets = Frog_jump_shadow_offsets[stage];
			shadow->sh_texture = Frog_jump_shadow_textures[stage];
			shadow_effect->ef_flags &= ~(EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY);
		} else {
			shadow_effect->ef_flags |= EFFECT_NO_UPDATE | EFFECT_NO_DISPLAY;
		}
	}
	
	if (frog->fr_poly_piece_pop != NULL && frog->fr_poly_piece_pop->pp_timer != 0)
		UpdatePolyPiecePop(frog->fr_poly_piece_pop);
}

// Confirmed
ENTITY* FrogGetNearestTongueTarget(FROG* frog) { // TODO: Implement.
	LIVE_ENTITY*	live_entity;
	MR_LONG			best_distance;
	ENTITY*			best_entity;
	
	best_distance = 10000000;
	best_entity = NULL;
	live_entity = Live_entity_root_ptr;

	while(live_entity = live_entity->le_next) {
		if ((ENTITY_GET_ENTITY_BOOK(live_entity->le_entity)->eb_flags & ENTITY_BOOK_TONGUEABLE) && DistanceToFrogger(live_entity, 0, 0) < best_distance) {
			best_distance = DistanceToFrogger(live_entity, 0, 0);
			best_entity = live_entity->le_entity;
		}
	}

	return best_entity; // nothing found, return NULL
}

// Confirmed.
MR_VOID UpdateFrogMatrix(FROG* frog) { // Could use some more cleanup, but eh.
	MR_VEC *direction;
	MR_VEC rot;
	MR_VEC vec2;
	MR_VEC local_58;
	MR_VEC local_48;
	MR_SVEC local_28;
	
	if (frog->fr_flags & FROG_ON_ENTITY) {
		MRMulMatrixABC(frog->fr_entity->en_live_entity->le_lwtrans,&frog->fr_entity_transform, frog->fr_lwtrans); // MulMatrix0
	} else if (frog->fr_flags & FROG_FREEFALL) { // Freefall
		rot.vx = -frog->fr_lwtrans->m[0][1]; // 1
		rot.vy = -frog->fr_lwtrans->m[1][1]; // 4
		rot.vz = -frog->fr_lwtrans->m[2][1]; // 7
		vec2.vx = frog->fr_lwtrans->m[0][2];
		vec2.vy = frog->fr_lwtrans->m[1][2];
		vec2.vz = frog->fr_lwtrans->m[2][2];
		MRNormaliseVEC(&rot, &rot);
		MRNormaliseVEC(&vec2, &vec2); // Doesn't seem like this actually uses these numbers for anything.
	} else {
		if ((frog->fr_flags & (FROG_JUMP_TO_LAND | FROG_JUMP_FROM_ENTITY)) == FROG_JUMP_FROM_ENTITY) { // From entity not to land.
			direction = &vec2;
			local_28.vx = (short)Frog_fixed_vectors[frog->fr_direction].vx;
			local_28.vy = (short)Frog_fixed_vectors[frog->fr_direction].vy;
			local_28.vz = (short)Frog_fixed_vectors[frog->fr_direction].vz;
			ApplyMatrix(frog->fr_entity->en_live_entity->le_lwtrans, &local_28, direction);
			rot.vx = -frog->fr_lwtrans->m[0][1];
			rot.vy = -frog->fr_lwtrans->m[1][1];
			rot.vz = -frog->fr_lwtrans->m[2][1];
			MRNormaliseVEC(&rot, &rot);
		} else {
			if (!(frog->fr_flags & FROG_JUMP_TO_ENTITY) && (frog->fr_grid_square != NULL)) { // Not jumping on entity, and has a grid square.
				GetGridSquareAverageNormal(frog->fr_grid_square, &rot); // Use rotation from grid square.
			} else {
				rot.vx = -frog->fr_lwtrans->m[0][1];
				rot.vy = -frog->fr_lwtrans->m[1][1];
				rot.vz = -frog->fr_lwtrans->m[2][1];
				MRNormaliseVEC(&rot, &rot);
			}
			
			direction = &Frog_fixed_vectors[frog->fr_direction]; // Use vector for direction.
		}
		
		MROuterProduct12(direction, &rot, &local_58);
		MRNormaliseVEC(&local_58, &local_58);
		MROuterProduct12(&rot, &local_58, &local_48);
		frog->fr_lwtrans->m[0][0] = (short)local_58.vx;
		frog->fr_lwtrans->m[0][1] = -(short)rot.vx;
		frog->fr_lwtrans->m[0][2] = (short)local_48.vx;
		frog->fr_lwtrans->m[1][0] = (short)local_58.vy;
		frog->fr_lwtrans->m[1][1] = -(short)rot.vy;
		frog->fr_lwtrans->m[1][2] = (short)local_48.vy;
		frog->fr_lwtrans->m[2][0] = (short)local_58.vz;
		frog->fr_lwtrans->m[2][1] = -(short)rot.vz;
		frog->fr_lwtrans->m[2][2] = (short)local_48.vz;
	}
	
	if (frog->fr_flags & FROG_SCALING_UP) {
		frog->fr_scale += (frog->fr_max_scale - frog->fr_scale) / (frog->fr_scale_up_time - frog->fr_scale_timer);
		
		if (++frog->fr_scale_timer == frog->fr_scale_up_time) {
			frog->fr_flags &= ~FROG_SCALING_UP; // Stop scaling up.
			frog->fr_flags |= FROG_SCALING_DOWN; // Start scaling down.
			frog->fr_scale_timer = frog->fr_scale_down_time;
		}
	} else {
		if (!(frog->fr_flags & FROG_SCALING_DOWN))
			return;
		
		frog->fr_scale += ((FROG_CROAK_MAX_SCALE - frog->fr_scale) / frog->fr_scale_timer);
		if (--frog->fr_scale_timer == 0)
			frog->fr_flags &= ~FROG_SCALING_DOWN;
	}
	
	// Apply to scale matrix.
	MRScale_matrix.m[0][0] = (MR_SHORT)frog->fr_scale;
	MRScale_matrix.m[1][1] = (MR_SHORT)frog->fr_scale;
	MRScale_matrix.m[2][2] = (MR_SHORT)frog->fr_scale;
	MRMulMatrixABB(&MRScale_matrix, frog->fr_lwtrans); // MulMatrix2
}

// Confirmed.
MR_VOID FrogSetScaling(FROG* frog, MR_LONG max_scale, MR_LONG scale_up_time, MR_LONG scale_down_time) { // Done, for sure.
	frog->fr_scale_up_time = scale_up_time;
	frog->fr_scale_down_time = scale_down_time;
	frog->fr_scale_timer = 0;
	frog->fr_max_scale = max_scale;
	frog->fr_flags |= FROG_SCALING_UP;
}

// Confirmed.
MR_VOID FrogCollectCheckPoint(FROG* frog, ENTITY* checkpoint) { // Done, for sure.
	CAMERA* camera;
	MR_ULONG checkfrog_id;
	
	MR_LONG checkpoint_count [4];
	MR_LONG checkpoints;
	MR_LONG num_winning_frogs;
		
	if (ENTITY_GET_ENTITY_TYPE(checkpoint) == ENTITY_TYPE_GEN_GOLD_FROG) {
		FrogCollectGoldFrog(frog, checkpoint);
	} else {
		//XAControl(XACOM_PAUSE, 0); // Disabled by Knee, since this doesn't improve anything.
		//Game_pausing_xa = -1;
		LiveEntityChangeVolume(0, 0);
		
		checkfrog_id = ((GEN_CHECKPOINT*)(checkpoint + 1))->cp_id;
		if (Checkpoints & (1 << checkfrog_id))
			return; // Already collected.
		
		Checkpoint_last_collected = checkfrog_id;
		Checkpoints |= (1 << checkfrog_id);
		Checkpoint_data[checkfrog_id].cp_frog_collected_id = frog->fr_frog_id;
		Checkpoint_data[checkfrog_id].cp_time = Game_map_time - Game_map_timer;
		if (Game_total_players == 1)
			Checkpoint_data[checkfrog_id].cp_flags |= GEN_CHECKPOINT_NO_HUD_UPDATE;
		AddFrogScore(frog, SCORE_500, 0);
		
		if (Sel_mode == 0)
			Frog_time_data[checkfrog_id] = (MR_SHORT) ((MR_ULONG) (Game_map_time * 0x1E - Game_map_timer) / 0x1E);
		
		if (Checkpoints != GEN_ALL_CHECKPOINTS || Game_total_players == 1)
			MRSNDPlaySound(SFX_MUSIC_TARGET_COMPLETE, 0, 0, MusicPitchTable[Game_map][0] << 7);
		
		if (Game_total_players > 1) {
			frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
			frog->fr_count = FROG_MULTIPLAYER_HIT_CHECKPOINT_DELAY;
			frog->fr_user_data1 = Checkpoint_data[Checkpoint_last_collected].cp_entity;
			FrogRequestAnimation(frog, FROG_ANIMATION_COMPLETE, 0);
			
			if (Checkpoints == GEN_ALL_CHECKPOINTS
				|| (GameGetMultiplayerFrogCheckpointData(&checkpoint_count[0], &checkpoints, &num_winning_frogs), checkpoints == 3))
			{
				SetGameMainloopMode(GAME_MODE_MULTI_COMPLETE);
				XAControl(XACOM_PAUSE, 0);
				Game_pausing_xa = -1;
			} else {
				((MR_OBJECT*) (Checkpoint_data[Checkpoint_last_collected].cp_entity)->en_live_entity->le_api_item0)->ob_flags |= MR_OBJ_NO_DISPLAY;
			}
		} else {
			FrogRequestAnimation(frog, FROG_ANIMATION_COMPLETE, 0);
			if (frog->fr_mode != FROG_MODE_JUMPING)
				frog->fr_count = 0;
			frog->fr_mode = FROG_MODE_HIT_CHECKPOINT;
			SetGameMainloopMode(GAME_MODE_SINGLE_TRIGGER_COLLECTED);
		}
	}
	
	if (frog->fr_particle_api_item != NULL)
		FROG_KILL_PARTICLE_EFFECT(frog);
	
	if (ENTITY_GET_ENTITY_TYPE(checkpoint) != ENTITY_TYPE_GEN_GOLD_FROG) {
		camera = &Cameras[frog->fr_frog_id];
		if (camera->ca_zone == NULL || (((ZONE_CAMERA*)(camera->ca_zone + 1))->zc_flags & ZONE_FLAG_CHECKPOINT)) {
			camera->ca_next_source_ofs.vx = 0;
			camera->ca_next_source_ofs.vy = -1000;
			camera->ca_next_source_ofs.vz = -100;
			camera->ca_next_target_ofs.vx = 0;
			camera->ca_next_target_ofs.vy = 0;
			camera->ca_next_target_ofs.vz = 0;
			camera->ca_move_timer = 0x2D;
		}
	}
}

// Confirmed.
MR_VOID FrogCollectGoldFrog(FROG* frog, ENTITY* checkpoint) { // Done, for sure.
	if (Gold_frogs & (1 << Game_map_theme))
		return; // Already collected(?).
	
	MRSNDPlaySound(SFX_MUSIC_GOLD_COMPLETE, 0, 0, MusicPitchTable[Game_map][0] << 7);
	AddFrogScore(frog, SCORE_1000, 0);
	Gold_frogs |= (1 << Game_map_theme);
	Gold_frog_data.gf_frog_collected_id = Frogs[0].fr_frog_id;
	Gold_frogs_zone |= (1 << Game_map_theme);
}

// Confirmed.
MR_VOID FrogUpdateCroak(FROG* frog) { // Done, for sure.
	FROG* target_frog;
	ENTITY* checkpoint_ent;
	GEN_CHECKPOINT* checkpoint;
	MR_LONG i;
	MR_MAT matrix;
	MR_SVEC svec;
	MR_VEC vec;
	
	if (!(Game_flags & GAME_FLAG_DEMO_RUNNING)) {
		if (frog->fr_croak_mode == FROG_CROAK_NONE && (frog->fr_flags & FROG_CONTROL_ACTIVE) && MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_croak_control)) {
			
			DisplayHUDHelp(frog->fr_frog_id, HUD_ITEM_HELP_CROAK);
			if (Game_total_players == 1) {
				MRAnimEnvSingleSetPartFlags(frog->fr_api_item, THROAT, 1);
				frog->fr_croak_mode = FROG_CROAK_INFLATE;
				frog->fr_croak_timer = FROG_CROAK_INFLATE_TIME;
			}
			
			//DAT_800aac40 = 0; // Never read? Unsure.
			frog->fr_croak_radius_max = Map_light_max_r2;
			frog->fr_croak_radius_min = Map_light_min_r2;
			frog->fr_croak_rate = Map_light_max_r2 / FROG_CROAK_INFLATE_TIME;
			MRSNDPlaySound(SFX_GEN_FROG_CROAK, 0, 0, 0);
			
			// This right here is the logic which makes it so when someone croaks in multiplayer, other frogs freeze.
			for (i = 0; i < Game_total_players; i++) {
				target_frog = &Frogs[i];
				if (target_frog == frog || target_frog->fr_stack_master != NULL || target_frog->fr_stack_slave != NULL)
					continue; // Don't handle.
				
				TransposeMatrix(target_frog->fr_lwtrans, &matrix);
				svec.vx = ((MR_SHORT) (frog->fr_lwtrans->t[0])) - ((MR_SHORT) target_frog->fr_lwtrans->t[0]);
				svec.vy = ((MR_SHORT) (frog->fr_lwtrans->t[1])) - ((MR_SHORT) target_frog->fr_lwtrans->t[1]);
				svec.vz = ((MR_SHORT) (frog->fr_lwtrans->t[2])) - ((MR_SHORT) target_frog->fr_lwtrans->t[2]);
				MRApplyMatrix(&matrix, &svec, &vec);
				
				if (vec.vz + 319 < 319 && abs(vec.vx) < -vec.vz && target_frog->fr_mode == FROG_MODE_STATIONARY) { // I have no idea why this doesn't compare vec.vz with 0.
					JumpFrogOnSpot(frog, 12);
					MRSNDPlaySound(SFX_GEN_FROG_SCARED, 0, 0, 0);
				}
			}
			
		} else if (frog->fr_croak_mode == FROG_CROAK_INFLATE) {
			frog->fr_croak_timer--;
			Map_light_min_r2 += frog->fr_croak_rate;
			Map_light_max_r2 += frog->fr_croak_rate;
			frog->fr_croak_scale = (((FROG_CROAK_INFLATE_TIME - frog->fr_croak_timer) * 0xE00) / FROG_CROAK_INFLATE_TIME) + FROG_CROAK_MIN_SCALE;
			if (frog->fr_croak_timer == 0) {
				frog->fr_croak_mode = FROG_CROAK_HOLD;
				frog->fr_croak_timer = FROG_CROAK_HOLD_TIME;
			}
		} else if (frog->fr_croak_mode == FROG_CROAK_HOLD) {
			if (--frog->fr_croak_timer == 0) {
				frog->fr_croak_mode = FROG_CROAK_DEFLATE;
				frog->fr_croak_timer = FROG_CROAK_DEFLATE_TIME;
			}
		} else if (frog->fr_croak_mode == FROG_CROAK_DEFLATE) {
			frog->fr_croak_timer--;
			Map_light_min_r2 -= frog->fr_croak_rate;
			Map_light_max_r2 -= frog->fr_croak_rate;
			frog->fr_croak_scale = ((frog->fr_croak_timer * 0xE00) / FROG_CROAK_DEFLATE_TIME) + FROG_CROAK_MIN_SCALE;
			
			if (frog->fr_croak_timer == 0) {
				Map_light_max_r2 = frog->fr_croak_radius_max;
				Map_light_min_r2 = frog->fr_croak_radius_min;
				frog->fr_croak_mode = FROG_CROAK_NONE;
				//DAT_800aac40 = -1; // Never read by anything, so not sure what this is.
				
				if (Game_total_players == 1)
					MRAnimEnvSingleClearPartFlags(frog->fr_api_item, THROAT, 1);
				
				checkpoint_ent = FrogGetNearestCheckpoint(frog);
				if (checkpoint_ent != NULL) {
					if (ENTITY_GET_ENTITY_TYPE(checkpoint_ent) == ENTITY_TYPE_GEN_GOLD_FROG) {
						if (checkpoint_ent->en_live_entity != NULL)
							PlayMovingSound(checkpoint_ent->en_live_entity, SFX_GEN_GOLD_FROG_CROAK, -1, -1);
					} else {
						checkpoint = (GEN_CHECKPOINT*)(checkpoint_ent + 1);
						
						(&Checkpoint_data[checkpoint->cp_id])->cp_croak_mode = FROG_CROAK_INFLATE;
						(&Checkpoint_data[checkpoint->cp_id])->cp_croak_timer = FROG_CROAK_INFLATE_TIME;
						if (checkpoint_ent->en_live_entity != NULL)
							PlayMovingSound(checkpoint_ent->en_live_entity, SFX_GEN_BABY_FROG, -1, -1);
					}
				}
			}
		}
	}
	
	frog->fr_croak_scale_matrix.m[0][0] = (MR_SHORT) frog->fr_croak_scale;
	frog->fr_croak_scale_matrix.m[1][1] = (MR_SHORT) frog->fr_croak_scale;
	frog->fr_croak_scale_matrix.m[2][2] = (MR_SHORT) frog->fr_croak_scale;
}

// Confirmed.
ENTITY* FrogGetNearestCheckpoint(FROG* frog) { // Done, for sure.
	ENTITY *entity;
	GEN_CHECKPOINT *checkpoint;
	MR_VEC vec;
	MR_ULONG distanceSq;
	MR_ULONG closestDistanceSq;
	ENTITY *closestEntity;
	MR_ULONG i;
	
	closestEntity = NULL;
	closestDistanceSq = 0x1000000;
	for (i = 0; i < 5; i++) {
		if (Checkpoint_data[i].cp_frog_collected_id == -1) {
			entity = Checkpoint_data[i].cp_entity;
			checkpoint = (GEN_CHECKPOINT*)(entity + 1);
			
			MR_SUB_VEC_ABC((MR_VEC*)checkpoint->cp_matrix.t, (MR_VEC*)frog->fr_lwtrans->t, &vec); // vec = checkpoint->cp_matrix->t - frog->fr_lwtrans->t
			//vec.vx = checkpoint->cp_matrix.t[0] - frog->fr_lwtrans->t[0];
			//vec.vy = checkpoint->cp_matrix.t[1] - frog->fr_lwtrans->t[1];
			//vec.vz = checkpoint->cp_matrix.t[2] - frog->fr_lwtrans->t[2];
			
			distanceSq = MR_VEC_MOD_SQR(&vec);
			
			if (distanceSq < closestDistanceSq) {
				closestDistanceSq = distanceSq;
				closestEntity = entity;
			}
		}
	}
	
	// Test if the golden frog entity is closer than the closest checkpoint.
	if ((Gold_frog_data.gf_entity != NULL) && (Gold_frog_data.gf_frog_collected_id == -1)) {
		MR_SUB_VEC_ABC((MR_SVEC*)&Gold_frog_data.gf_position, (MR_VEC*)frog->fr_lwtrans->t, &vec);
		//vec.vx = Gold_frog_data.gf_position.vx - frog->fr_lwtrans->t[0];
		//vec.vy = Gold_frog_data.gf_position.vy - frog->fr_lwtrans->t[1];
		//vec.vz = Gold_frog_data.gf_position.vz - frog->fr_lwtrans->t[2];
		if (closestDistanceSq > MR_VEC_MOD_SQR(&vec))
			closestEntity = Gold_frog_data.gf_entity;
	}
	
	return closestEntity;
}

// Confirmed.
MR_VOID FrogKill(FROG* frog, MR_ULONG animation, MR_VEC* vec) { // Done, for sure.
	MR_SVEC svec;
	MR_MAT* lwtrans;
	MR_OBJECT* object;
	
	if (frog->fr_particle_api_item != NULL && (frog->fr_particle_flags & 0x100U))
		FROG_KILL_PARTICLE_EFFECT(frog);
	
	if (frog->fr_mode == FROG_MODE_DYING)
		return;
	
	if (frog->fr_mode == FROG_MODE_HIT_CHECKPOINT)
		return;
	
	if (frog->fr_flags & FROG_MUST_DIE)
		return;
	
	if (Cheat_collision_toggle)
		return;
	
	frog->fr_flags &= ~FROG_CONTROL_ACTIVE;
	Cameras[frog->fr_frog_id].ca_mode = CAMERA_MODE_FIXED;
	
	if (Game_total_players == 1) {
		if (Cheat_infinite_lives_toggle == FALSE)
		{
			if (frog->fr_lives > 0) {
				frog->fr_lives--;
				(frog->fr_hud_script + HUD_ITEM_LIVES - 1)->hi_flags |= HUD_ITEM_REBUILD;
			}
		}

		if (frog->fr_lives == 0)
			frog->fr_flags &= ~FROG_ACTIVE;
	}
	
	frog->fr_flags |= FROG_MUST_DIE;
	
	if (animation != -1) {
		FrogRequestAnimation(frog, animation, 0, 0);
		frog->fr_death_equate = animation;
	}
	
	if (frog->fr_poly_piece_pop != NULL) {
		FrogStartPolyPiecePop(frog);
		lwtrans = frog->fr_poly_piece_pop->pp_lwtrans;
	} else {
		lwtrans = frog->fr_lwtrans;
	}
		
	// Create the colored death ring.
	object = MRCreatePgen(&PGIN_frog_pop_explosion, (MR_FRAME*)lwtrans, MR_OBJ_STATIC, NULL);
	object->ob_extra.ob_extra_pgen->pg_user_data_2 = Frog_pop_explosion_colours[Frog_player_data[frog->fr_frog_id].fp_player_id];
	GameAddObjectToViewports(object);
	
	frog->fr_velocity.vx = vec != NULL ? vec->vx : 0;
	frog->fr_velocity.vy = vec != NULL ? vec->vy : 0;
	frog->fr_velocity.vz = vec != NULL ? vec->vz : 0;
		
	if (Game_map_theme == THEME_VOL && (animation == FROG_ANIMATION_DROWN || animation == FROG_ANIMATION_FLOP)) {
		if (frog->fr_particle_api_item == NULL) {
			svec.vx = -0x50;
			svec.vy = 0;
			svec.vz = 0x28;
			frog->fr_particle_api_item = CreateParticleEffect(frog, 2, &svec);
		}
		
		SetFrogScaleColours(frog, 0x18, 0, 0);
		FrogRequestAnimation(frog, FROG_ANIMATION_FLOP, 0);
	}
}

// Confirmed.
MR_VOID FrogModeControlJumping(FROG* frog, MR_ULONG mode) { // Done, for sure.
	MR_ULONG dir;
	MR_LONG key;
	
	dir = FROG_DIRECTION_NO_INPUT;
	if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_up_control)) {
		if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_right_control)) {
			if (!MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_down_control)) {
				if (MR_CHECK_PAD_PRESSED(frog->fr_input_id, frog->fr_control_method->fc_left_control))
					dir = 3;
			} else {
				dir = 2;
			}
		} else {
			dir = 1;
		}
	} else {
		dir = 0;
	}
	
	if (dir != FROG_DIRECTION_NO_INPUT) {
		if (frog->fr_flags & FROG_ON_ENTITY) {
			key = dir - frog->fr_entity_angle;
		} else {
			key = dir - (&Cameras[frog->fr_frog_id])->ca_frog_controller_directions[0] & 3;
		}
		
		if (frog->fr_num_buffered_keys < MAX_BUFFERED_KEYS)
			frog->fr_buffered_key[frog->fr_num_buffered_keys++] = key;
	}
}

// Confirmed.
MR_VOID UpdateFrogBaseColour(FROG* frog) { // Done. TODO: Cleanup.
	MR_USHORT uVar1;
	MR_VOID *pvVar2;
	MR_ANIM_ENV_INST *local_v0_572;
	int iVar3;
	int iVar4;
	MR_MESH_INST *pMVar5;
	MR_ULONG uVar6;
	MR_ULONG uVar7;
	int *piVar8;
	MR_MESH_INST **ppMVar9;
	MR_UBYTE uVar10;
	MR_UBYTE uVar11;
	FROG *pFVar12;
	MR_UBYTE uVar13;
	
	if ((Map_library[Game_map].mb_flags & 1) != 0) goto LAB_8002b620;
	uVar7 = 0;
	iVar3 = frog->fr_lwtrans->t[0];
	if (iVar3 < (int)Fade_top_left_pos.vx) {
		uVar7 = (int)Fade_top_left_pos.vx - iVar3;
	}
	else {
		if ((int)Fade_bottom_right_pos.vx < iVar3) {
			uVar7 = iVar3 - (int)Fade_bottom_right_pos.vx;
		}
	}
	iVar3 = frog->fr_lwtrans->t[2];
	if (iVar3 < (int)Fade_bottom_right_pos.vz) {
		iVar3 = (int)Fade_bottom_right_pos.vz - iVar3;
LAB_8002b578:
		uVar7 += iVar3;
	}
	else {
		if ((int)Fade_top_left_pos.vz < iVar3) {
			iVar3 -= (int)Fade_top_left_pos.vz;
			goto LAB_8002b578;
		}
	}
	iVar3 = 0x80 - (uVar7 >> 1);
	if (iVar3 < 0) {
		iVar3 = 0;
	}
	uVar7 = 0;
	pFVar12 = frog;
	if (Game_total_viewports != 0) {
		do {
			pvVar2 = pFVar12->fr_api_insts[0];
			if (pvVar2 != (MR_VOID *)0x0) {
				uVar6 = (MR_ULONG)*(MR_USHORT *)((int)pvVar2 + 0x10);
				piVar8 = *(int **)((int)pvVar2 + 0x14);
				if (*(MR_USHORT *)((int)pvVar2 + 0x10) != 0) {
					do {
						uVar6 -= 1;
						iVar4 = *piVar8;
						piVar8 = piVar8 + 1;
						*(int *)(iVar4 + 0x10) = iVar3 * 0x10101;
						*(MR_USHORT *)(iVar4 + 0x1e) = *(MR_USHORT *)(iVar4 + 0x1e) | 2;
					} while (uVar6 != 0);
				}
			}
			uVar7 += 1;
			pFVar12 = (FROG *)&pFVar12->fr_mode;
		} while (uVar7 < Game_total_viewports);
	}
LAB_8002b620:
	if ((frog->fr_mode == 2) && (frog->fr_death_equate == 0xb)) {
		iVar3 = frog->fr_lwtrans->t[1] - frog->fr_old_y;
		if (Game_map_theme == 7) {
			iVar4 = iVar3 * -0x10 >> 9;
			uVar13 = (MR_UBYTE)iVar4;
			if (iVar4 < 0) {
				uVar13 = 0;
			}
			iVar4 = (iVar3 * 0x20 >> 9) + 0x80;
			uVar11 = (MR_UBYTE)iVar4;
			if (iVar4 < 0) {
				uVar11 = 0;
			}
			iVar3 = (iVar3 * -0x20 >> 9) + 0x20;
		}
		else {
			iVar4 = iVar3 * -0x10 >> 9;
			uVar13 = (MR_UBYTE)iVar4;
			if (iVar4 < 0) {
				uVar13 = 0;
			}
			iVar3 = iVar3 * -0x20 >> 9;
			iVar4 = iVar3 + 0x40;
			uVar11 = (MR_UBYTE)iVar4;
			iVar3 += 0xc0;
			if (iVar4 < 0) {
				uVar11 = 0;
			}
		}
		uVar10 = (MR_UBYTE)iVar3;
		if (iVar3 < 0) {
			uVar10 = 0;
		}
		uVar7 = 0;
		if (Game_total_viewports != 0) {
			do {
				local_v0_572 = (MR_ANIM_ENV_INST *)frog->fr_api_insts[0];
				if (local_v0_572 != (MR_ANIM_ENV_INST *)0x0) {
					uVar6 = (MR_ULONG)local_v0_572->ae_models;
					ppMVar9 = local_v0_572->ae_mesh_insts;
					if (local_v0_572->ae_models != 0) {
						do {
							uVar6 -= 1;
							pMVar5 = *ppMVar9;
							ppMVar9 = ppMVar9 + 1;
							uVar1 = pMVar5->mi_light_flags;
							(pMVar5->mi_custom_ambient).r = ' ';
							(pMVar5->mi_custom_ambient).g = '@';
							(pMVar5->mi_custom_ambient).b = '@';
							(pMVar5->mi_colour_scale).r = uVar13;
							(pMVar5->mi_colour_scale).g = uVar11;
							(pMVar5->mi_colour_scale).b = uVar10;
							pMVar5->mi_light_flags = uVar1 | 3;
						} while (uVar6 != 0);
					}
				}
				uVar7 += 1;
				frog = (FROG *)&frog->fr_mode;
			} while (uVar7 < Game_total_viewports);
		}
	}
}

// Confirmed.
MR_VOID SetFrogScaleColours(FROG* frog, MR_LONG red, MR_LONG green, MR_LONG blue) { // Done, for sure.
	MR_ANIM_ENV_INST* env;
	MR_MESH_INST* mesh;
	MR_LONG i, j;
	MR_ULONG color;
	
	color = (blue << 16) | (green << 8) | (red << 0);
	
	for (i = 0; i < Game_total_viewports; i++) {
		env = (MR_ANIM_ENV_INST*) frog->fr_api_insts[i];
		if (env == NULL || env->ae_models == NULL)
			continue;
		
		for (j = 0; j < (MR_ULONG) env->ae_models; j++) {
			mesh = env->ae_mesh_insts[j];
			mesh->mi_custom_ambient.r = (MR_BYTE) red;
			mesh->mi_custom_ambient.g = (MR_BYTE) green;
			mesh->mi_custom_ambient.b = (MR_BYTE) blue;
			mesh->mi_colour_scale.r = (MR_BYTE) red;
			mesh->mi_colour_scale.g = (MR_BYTE) green;
			mesh->mi_colour_scale.b = (MR_BYTE) blue;
			mesh->mi_light_flags |= MR_INST_MODIFIED_LIGHT_MASK;
		}
	}
}

MR_VOID UpdateFrogPowerUps(FROG* frog) { // Done.
	
	if (frog->fr_powerup_flags & FROG_POWERUP_AUTO_HOP) {
		if (frog->fr_auto_hop_timer == 0) {
			frog->fr_powerup_flags &= ~FROG_POWERUP_AUTO_HOP;
		} else {
			frog->fr_auto_hop_timer--;
		}
	}
	
	if (frog->fr_powerup_flags & FROG_POWERUP_SUPER_TONGUE) {
		if (frog->fr_super_tongue_timer == 0) {
			frog->fr_powerup_flags &= ~FROG_POWERUP_SUPER_TONGUE;
		} else {
			frog->fr_super_tongue_timer--;
		}
	}
	
	if (frog->fr_powerup_flags & FROG_POWERUP_QUICK_JUMP) {
		if (frog->fr_quick_jump_timer == 0) {
			frog->fr_powerup_flags &= ~FROG_POWERUP_QUICK_JUMP;
		} else {
			frog->fr_quick_jump_timer--;
		}
	}
	
	if (frog->fr_powerup_flags & FROG_POWERUP_TIMER_SPEED) {
		if (Game_map_timer_flags & 1) {
			if (Game_map_timer_frac < 0x10001) {
				Game_map_timer_frac += 0xCCC;
			} else {
				Game_map_timer_flags = Game_map_timer_flags & 0xFE | 2;
				Game_map_timer_frac = 0;
			}
		} else {
			if (Game_map_timer_frac < -0x10000) {
				Game_map_timer_flags = Game_map_timer_flags & 0xFD | 1;
			} else {
				Game_map_timer_frac -= 0xCCC;
			}
		}
		
		Game_map_timer_speed += Game_map_timer_frac;
		if (Game_map_timer_speed < 0x10000) {
			Game_map_timer_speed = 0x10000;
			frog->fr_powerup_flags &= ~FROG_POWERUP_TIMER_SPEED;
		}
	}
}

// Confirmed.
MR_VOID UpdateFrogStackMaster(FROG* frog_a, FROG* frog_b) { // Done.
	int iVar1;
	MR_MAT *pMVar2;
	MR_MAT *pMVar3;
	FROG *master_frog;
	MR_SVEC svec;
	MR_VEC vec;
	
	master_frog = frog_a->fr_stack_master;
	iVar1 = (8 - frog_b->fr_stack_count) * 0x1000;
	if (iVar1 < 0) {
		iVar1 += 7;
	}
	iVar1 = rcos(iVar1 >> 3);
	svec.vy = -((short)((iVar1 + 0x1000) * 0x32 >> 0xd) + 0x32);
	svec.vx = 0;
	svec.vz = 0;
	MRApplyMatrix(frog_a->fr_lwtrans, &svec, &vec);
	master_frog->fr_lwtrans->t[0] = frog_a->fr_lwtrans->t[0] + vec.vx;
	master_frog->fr_lwtrans->t[1] = frog_a->fr_lwtrans->t[1] + vec.vy;
	master_frog->fr_lwtrans->t[2] = frog_a->fr_lwtrans->t[2] + vec.vz;
	(master_frog->fr_pos).vx = master_frog->fr_lwtrans->t[0] << 16;
	(master_frog->fr_pos).vy = master_frog->fr_lwtrans->t[1] << 16;
	(master_frog->fr_pos).vz = master_frog->fr_lwtrans->t[2] << 16;
	
	MRMulMatrixABC(&master_frog->fr_stack_mod_matrix, frog_a->fr_lwtrans, master_frog->fr_lwtrans);
	
	master_frog->fr_grid_x = frog_a->fr_grid_x;
	master_frog->fr_grid_z = frog_a->fr_grid_z;
	master_frog->fr_grid_square = frog_a->fr_grid_square;
	master_frog->fr_old_grid_x = frog_a->fr_old_grid_x;
	master_frog->fr_old_grid_z = frog_a->fr_old_grid_z;
	master_frog->fr_old_grid_square = frog_a->fr_old_grid_square;
	(master_frog->fr_velocity).vx = (frog_a->fr_velocity).vx;
	(master_frog->fr_velocity).vy = (frog_a->fr_velocity).vy;
	(master_frog->fr_velocity).vz = (frog_a->fr_velocity).vz;
}

// Confirmed.
MR_VOID JumpFrogOnSpot(FROG* frog, MR_LONG count) { // Done, for sure.
	MR_SHORT z1, z2;
	FORM* form;
	
	frog->fr_mode = FROG_MODE_JUMPING;
	frog->fr_count = count;
	frog->fr_flags |= FROG_JUMP_ON_SPOT;
	frog->fr_velocity.vx = 0;
	frog->fr_velocity.vy = -((count + 1) * SYSTEM_GRAVITY >> 1);
	frog->fr_velocity.vz = 0;
	frog->fr_y = frog->fr_lwtrans->t[1];

	if (frog->fr_flags & FROG_ON_ENTITY) {
		frog->fr_flags |= (FROG_JUMP_FROM_ENTITY | FROG_JUMP_TO_ENTITY);
		form = ENTITY_GET_FORM(frog->fr_entity);
		frog->fr_target_pos.vx = form->fo_xofs + (MR_SHORT) (frog->fr_entity_grid_x << 8) + 0x80;
		z1 = (MR_SHORT) frog->fr_entity_grid_z;
		z2 = form->fo_zofs;
	} else {
		frog->fr_flags |= FROG_JUMP_TO_LAND;
		frog->fr_target_pos.vx = (frog->fr_grid_x << 8) + ((MR_SHORT) Grid_base_x) + 0x80;
		z1 = (MR_SHORT) frog->fr_grid_z;
		z2 = (MR_SHORT) Grid_base_z;
	}
	
	frog->fr_target_pos.vz = (z1 << 8) + z2 + 0x80;
}

// Confirmed.
MR_VOID FrogStartPolyPiecePop(FROG* frog) { // Done, for sure.
	MR_LONG				i;
	POLY_PIECE*			poly_piece;
	POLY_PIECE_DYNAMIC*	poly_piece_dynamic;
	MR_VEC				vec;
	POLY_PIECE_POP* piece_pop;
	
	// Hide the real model, only show the popped faces.
	((MR_ANIM_ENV*) frog->fr_api_item)->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
	
	// Set up pop	
	piece_pop = frog->fr_poly_piece_pop;
	piece_pop->pp_timer 	= FROG_POLY_PIECE_POP_DURATION;
	piece_pop->pp_duration 	= FROG_POLY_PIECE_POP_DURATION;
	piece_pop->pp_otz		= FROG_POPPING_FIXED_OT;
	
	MR_CLEAR_SVEC(&piece_pop->pp_rotation);
	MR_CLEAR_SVEC(&piece_pop->pp_ang_vel);
	
	// Set up position/velocity of pieces
	i 					= piece_pop->pp_numpolys;
	poly_piece		 	= piece_pop->pp_poly_pieces;
	poly_piece_dynamic 	= piece_pop->pp_poly_piece_dynamics;
	gte_SetRotMatrix(piece_pop->pp_lwtrans);
	
	while(i--) {
		MRApplyRotMatrix(&poly_piece->pp_origin, &vec);

		// Set position
		poly_piece_dynamic->pp_position.vx = (piece_pop->pp_lwtrans->t[0] + vec.vx) << 16;
		poly_piece_dynamic->pp_position.vy = (piece_pop->pp_lwtrans->t[1] + vec.vy) << 16;
		poly_piece_dynamic->pp_position.vz = (piece_pop->pp_lwtrans->t[2] + vec.vz) << 16;

		// Set velocity
		vec.vy -= 0x80;
		MRNormaliseVEC(&vec, &vec); 
		poly_piece_dynamic->pp_velocity.vx = vec.vx << 10;
		poly_piece_dynamic->pp_velocity.vy = vec.vy << 10;
		poly_piece_dynamic->pp_velocity.vz = vec.vz << 10;

		poly_piece++;
		poly_piece_dynamic++;
	}
}

// Confirmed.
MR_VOID RemoveAllFrogsFromDisplay(MR_VOID) { // Done, For Sure.
	ULONG frog_id;
	MR_ANIM_ENV* env;
	
	for (frog_id = 0; frog_id < Game_total_players; frog_id++) {
		env = (MR_ANIM_ENV*)Frogs[frog_id].fr_api_item;
		if (Game_total_players == 1) {
			env->ae_extra.ae_extra_env_single->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
		} else {
			env->ae_extra.ae_extra_env_flipbook->ae_object->ob_flags |= MR_OBJ_NO_DISPLAY;
		}
	}
}

MR_VOID UpdateFrogCameraZone(FROG* frog) { // Done, for sure.
	if (frog->fr_flags & FROG_DO_NOT_UPDATE_CAMERA_ZONES)
		return;
	
	if (frog->fr_cam_zone != NULL) {
		if (frog->fr_cam_zone_region != NULL && CheckCoordsInZoneRegion(frog->fr_grid_x, frog->fr_grid_z, frog->fr_cam_zone_region) != NULL)
			return;
		frog->fr_cam_zone_region = CheckCoordsInZone(frog->fr_grid_x, frog->fr_grid_z, frog->fr_cam_zone);
		if (frog->fr_cam_zone_region != NULL)
			return;
	}
	CheckCoordsInZones(frog->fr_grid_x, frog->fr_grid_z, 0, &frog->fr_cam_zone, &frog->fr_cam_zone_region);
	return;
}

// Confirmed.
MR_VOID FrogPlayLoopingSound(FROG* frog, MR_LONG sound) { // Done, for sure.
	if (sound == frog->fr_current_sfx)
		return;
	
	if (frog->fr_voice_id != -1)
		FrogKillLoopingSound(frog);
	frog->fr_voice_id = -1;
	frog->fr_current_sfx = sound;
}

// Confirmed.
MR_VOID FrogKillLoopingSound(FROG* frog) { // Done, for sure.
	if (frog->fr_voice_id != -1)
		MRSNDKillSound(frog->fr_voice_id);
	frog->fr_voice_id = -1;
	frog->fr_current_sfx = -1;
}

// Confirmed.
MR_VOID FROG_FALL(FROG* frog) { // Done, for sure.
	MR_MAT matrix;
	
	if (frog->fr_mode == FROG_MODE_DYING)
		return;
	
	if (frog->fr_entity != NULL) {
		ProjectMatrixOntoWorldXZ(frog->fr_entity->en_live_entity->le_lwtrans, &matrix);
		MulMatrix(&Cameras[frog->fr_frog_id].ca_mod_matrix, &matrix);
		frog->fr_entity = NULL;
	}
	
	frog->fr_mode = FROG_MODE_JUMPING;
	frog->fr_count = 0xFFFF;
    frog->fr_velocity.vx = 0;
    frog->fr_velocity.vy = 0;
    frog->fr_velocity.vz = 0;
	frog->fr_flags &= ~FROG_LANDED_ON_LAND_CLEAR_MASK;
    FrogRequestAnimation(frog, FROG_ANIMATION_FREEFALL, 0);
}
