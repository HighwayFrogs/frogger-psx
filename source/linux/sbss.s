# This file specifies the symbol ordering in the .sbss section seen in the original game.
# The original linker (PSYLINK) used a sorted list (by hash, documented in the vlo/ folder in the repository) to determine symbol order.
# In order to recreate the original symbol order, we just reference the symbols in our desired order

.section .sbss
	.global Map_path_header; Map_path_header: .space 4												# Linker Hash: 1, Assembler Hash: 242, Object: mapload.c
	.global Map_graphical_header; Map_graphical_header: .space 4									# Linker Hash: 4, Assembler Hash: 240, Object: mapload.c
	.global Game_timer; Game_timer: .space 4														# Linker Hash: 4, Assembler Hash: 250, Object: gamesys.c
	.global Main_options_status; Main_options_status: .space 2										# Linker Hash: 6, Assembler Hash: 243, Object: tempopt.c
	.space	2 # Padding
	.global Map_form_header; Map_form_header: .space 4												# Linker Hash: 8, Assembler Hash: 249, Object: mapload.c
	.global High_high_score; High_high_score: .space 4												# Linker Hash: 9, Assembler Hash: 250, Object: hsinput.c
	.global Sky_land_header; Sky_land_header: .space 4												# Linker Hash: 12, Assembler Hash: 253, Object: mapdisp.c
	.global Map_zone_header; Map_zone_header: .space 4												# Linker Hash: 16, Assembler Hash: 1, Object: mapload.c
	.global Gold_frogs; Gold_frogs: .space 4														# Linker Hash: 16, Assembler Hash: 6, Object: ent_gen.c
	.global Sel_stack_frame; Sel_stack_frame: .space 4												# Linker Hash: 18, Assembler Hash: 3, Object: select.c
	.global Map_lights; Map_lights: .space 4														# Linker Hash: 18, Assembler Hash: 8, Object: mapload.c
	.global Frog_selection_number_players; Frog_selection_number_players: .space 4					# Linker Hash: 23, Assembler Hash: 250, Object: tempopt.c
	.global Game_map_timer_flags; Game_map_timer_flags: .space 1									# Linker Hash: 23, Assembler Hash: 3, Object: gamesys.c
	.space	3 # Padding
	.global High_score_view_flyon_counter; High_score_view_flyon_counter: .space 4					# Linker Hash: 24, Assembler Hash: 251, Object: hsview.c
	.global Game_map_timer_speed; Game_map_timer_speed: .space 4									# Linker Hash: 27, Assembler Hash: 7, Object: gamesys.c
	.global Game_hud_script; Game_hud_script: .space 4												# Linker Hash: 29, Assembler Hash: 14, Object: gamesys.c
	.global MRCalc_peak; MRCalc_peak: .space 4														# Linker Hash: 29, Assembler Hash: 18, Object: mr_disp.c
	.global Options_count_down_ticks; Options_count_down_ticks: .space 4							# Linker Hash: 32, Assembler Hash: 8, Object: tempopt.c
	.global Option_viewport_ptr; Option_viewport_ptr: .space 4										# Linker Hash: 32, Assembler Hash: 13, Object: options.c
	.global Sel_arcade_level_ptr; Sel_arcade_level_ptr: .space 4									# Linker Hash: 35, Assembler Hash: 15, Object: select.c
	.global xa_change_index; xa_change_index: .space 4												# Linker Hash: 36, Assembler Hash: 21, Object: playxa.c
	.global Map_groups; Map_groups: .space 4														# Linker Hash: 39, Assembler Hash: 29, Object: mapload.c
	.global High_score_view_riverbed_prim_ptrs; High_score_view_riverbed_prim_ptrs: .space 8		# Linker Hash: 40, Assembler Hash: 6, Object: hsview.c
	.global card_HwEvSpTIMOUT; card_HwEvSpTIMOUT: .space 4											# Linker Hash: 41, Assembler Hash: 24, Object: memcard.c
	.global Sel_level_title; Sel_level_title: .space 4												# Linker Hash: 43, Assembler Hash: 28, Object: select.c
	.global MRCalc_time; MRCalc_time: .space 4														# Linker Hash: 43, Assembler Hash: 32, Object: mr_disp.c
	.space	4 # Padding
	.global Select_bg_polys; Select_bg_polys: .space 8												# Linker Hash: 45, Assembler Hash: 30, Object: select.c
	.global High_score_view_mode; High_score_view_mode: .space 4									# Linker Hash: 45, Assembler Hash: 25, Object: hsview.c
	.global Gold_frogs_zone; Gold_frogs_zone: .space 4												# Linker Hash: 48, Assembler Hash: 33, Object: ent_gen.c
	.global Hud_bonus_score; Hud_bonus_score: .space 4												# Linker Hash: 49, Assembler Hash: 34, Object: hud.c
	.global xa_old_sync_callback; xa_old_sync_callback: .space 4									# Linker Hash: 51, Assembler Hash: 31, Object: playxa.c
	.global LS_extras_object_ptr; LS_extras_object_ptr: .space 8									# Linker Hash: 52, Assembler Hash: 32, Object: loadsave.c
	.global Effect_root_ptr; Effect_root_ptr: .space 4												# Linker Hash: 52, Assembler Hash: 37, Object: effects.c
	.global card_SwEvSpTIMOUT; card_SwEvSpTIMOUT: .space 4											# Linker Hash: 52, Assembler Hash: 35, Object: memcard.c
	.global Sel_start_vec_y; Sel_start_vec_y: .space 8												# Linker Hash: 53, Assembler Hash: 38, Object: select.c
	.global Options_count_down_units; Options_count_down_units: .space 4							# Linker Hash: 53, Assembler Hash: 29, Object: tempopt.c
	.global xa_channel_play; xa_channel_play: .space 4												# Linker Hash: 53, Assembler Hash: 38, Object: playxa.c
	.global Game_over_press_fire; Game_over_press_fire: .space 4									# Linker Hash: 58, Assembler Hash: 38, Object: gamesys.c
	.global MRSND_sample_info_ptr; MRSND_sample_info_ptr: .space 4									# Linker Hash: 58, Assembler Hash: 37, Object: mr_sound.c
	.global MRMouse_down_buttons; MRMouse_down_buttons: .space 2									# Linker Hash: 65, Assembler Hash: 45, Object: mr_input.c
	.space	2 # Padding
	.global Checkpoint_last_collected; Checkpoint_last_collected: .space 4							# Linker Hash: 66, Assembler Hash: 41, Object: ent_gen.c
	.global str_params; str_params: .space 8														# Linker Hash: 70, Assembler Hash: 60, Object: stream.c
	.global xa_current_file; xa_current_file: .space 4												# Linker Hash: 73, Assembler Hash: 58, Object: playxa.c
	.global str_frame_index; str_frame_index: .space 2												# Linker Hash: 73, Assembler Hash: 58, Object: stream.c
	.space	2 # Padding
	.global Map_light_min_r2; Map_light_min_r2: .space 4											# Linker Hash: 75, Assembler Hash: 59, Object: mapdisp.c
	.global Map_light_max_r2; Map_light_max_r2: .space 4											# Linker Hash: 77, Assembler Hash: 61, Object: mapdisp.c
	.global MRProf_time; MRProf_time: .space 4														# Linker Hash: 79, Assembler Hash: 68, Object: mr_disp.c
	.global xa_currpos; xa_currpos: .space 4														# Linker Hash: 80, Assembler Hash: 70, Object: playxa.c
	.global str_ring_buffer; str_ring_buffer: .space 4												# Linker Hash: 80, Assembler Hash: 65, Object: stream.c
	.global Map_entity_ptrs; Map_entity_ptrs: .space 4												# Linker Hash: 81, Assembler Hash: 66, Object: mapload.c
	.global LSunformatted_sprite; LSunformatted_sprite: .space 4									# Linker Hash: 82, Assembler Hash: 62, Object: loadsave.c
	.space	4 # Padding
	.global LS_extras_matrix_ptr; LS_extras_matrix_ptr: .space 8									# Linker Hash: 82, Assembler Hash: 62, Object: loadsave.c
	.global Sel_user_prompt; Sel_user_prompt: .space 4												# Linker Hash: 82, Assembler Hash: 67, Object: select.c
	.global xa_startup_flag; xa_startup_flag: .space 4												# Linker Hash: 83, Assembler Hash: 68, Object: playxa.c
	.global MRCd_status; MRCd_status: .space 8														# Linker Hash: 84, Assembler Hash: 73, Object: mr_file.c
	.global xa_requested_channel; xa_requested_channel: .space 4									# Linker Hash: 86, Assembler Hash: 66, Object: playxa.c
	.global Sel_light_inst_0; Sel_light_inst_0: .space 4											# Linker Hash: 87, Assembler Hash: 71, Object: select.c
	.global Sel_light_inst_1; Sel_light_inst_1: .space 4											# Linker Hash: 88, Assembler Hash: 72, Object: select.c
	.global Sky_land_texture_ids; Sky_land_texture_ids: .space 4									# Linker Hash: 88, Assembler Hash: 68, Object: mapdisp.c
	.global LS_title_texture_ptr; LS_title_texture_ptr: .space 4									# Linker Hash: 89, Assembler Hash: 69, Object: loadsave.c
	.global Sel_light_inst_2; Sel_light_inst_2: .space 4											# Linker Hash: 89, Assembler Hash: 73, Object: select.c
	.global LS_user_prompt_controls_sprite_ptr; LS_user_prompt_controls_sprite_ptr: .space 4		# Linker Hash: 94, Assembler Hash: 60, Object: loadsave.c
	.global High_score_input_frog_num; High_score_input_frog_num: .space 4							# Linker Hash: 95, Assembler Hash: 70, Object: hsinput.c
	.global LS_matrices; LS_matrices: .space 4														# Linker Hash: 97, Assembler Hash: 86, Object: loadsave.c
	.global Grid_base_x; Grid_base_x: .space 4														# Linker Hash: 98, Assembler Hash: 87, Object: grid.c
	.global Game_total_viewports; Game_total_viewports: .space 4									# Linker Hash: 99, Assembler Hash: 79, Object: gamesys.c
	.global Grid_base_z; Grid_base_z: .space 4														# Linker Hash: 100, Assembler Hash: 89, Object: grid.c
	.global MREnv_strip; MREnv_strip: .space 4														# Linker Hash: 100, Assembler Hash: 89, Object: mr_mof.c
	.global Sel_camera_frame; Sel_camera_frame: .space 4											# Linker Hash: 102, Assembler Hash: 86, Object: select.c
	.global Map_light_header; Map_light_header: .space 4											# Linker Hash: 109, Assembler Hash: 93, Object: mapload.c
	.global High_score_view_frog_anim_model_ptr; High_score_view_frog_anim_model_ptr: .space 4		# Linker Hash: 110, Assembler Hash: 75, Object: hsview.c
	.global MRNumber_of_anim_envs; MRNumber_of_anim_envs: .space 2									# Linker Hash: 112, Assembler Hash: 91, Object: mr_anim.c
	.space	2 # Padding
	.global LS_selection_dir; LS_selection_dir: .space 4											# Linker Hash: 114, Assembler Hash: 98, Object: loadsave.c
	.global Path_runner_root_ptr; Path_runner_root_ptr: .space 4									# Linker Hash: 114, Assembler Hash: 94, Object: path.c
	.global MRFrame_root_ptr; MRFrame_root_ptr: .space 4											# Linker Hash: 114, Assembler Hash: 98, Object: mr_frame.c
	.global MRCd_retry_count; MRCd_retry_count: .space 4											# Linker Hash: 115, Assembler Hash: 99, Object: mr_file.c
	.space	4 # Padding
	.global Sel_end_pos; Sel_end_pos: .space 8														# Linker Hash: 118, Assembler Hash: 107, Object: select.c
	.global High_score_view_flyoff_counter; High_score_view_flyoff_counter: .space 4				# Linker Hash: 119, Assembler Hash: 89, Object: hsview.c
	.global Live_entity_root_ptr; Live_entity_root_ptr: .space 4									# Linker Hash: 120, Assembler Hash: 100, Object: entity.c
	.global Game_reset_flags; Game_reset_flags: .space 4											# Linker Hash: 120, Assembler Hash: 104, Object: gamesys.c
	.global Grid_stacks; Grid_stacks: .space 4														# Linker Hash: 121, Assembler Hash: 110, Object: grid.c
	.global Gameover_title_sprite_ptr; Gameover_title_sprite_ptr: .space 4							# Linker Hash: 123, Assembler Hash: 98, Object: tempopt.c
	.global High_level_score; High_level_score: .space 4											# Linker Hash: 130, Assembler Hash: 114, Object: hsinput.c
	.global Map_group_header; Map_group_header: .space 4											# Linker Hash: 130, Assembler Hash: 114, Object: mapload.c
	.space	4 # Padding
	.global Map_wibble_water; Map_wibble_water: .space 8											# Linker Hash: 132, Assembler Hash: 116, Object: mapdisp.c
	.global Game_map_timer_decimalised; Game_map_timer_decimalised: .space 4						# Linker Hash: 132, Assembler Hash: 106, Object: gamesys.c
	.global Grid_xshift; Grid_xshift: .space 4														# Linker Hash: 134, Assembler Hash: 123, Object: grid.c
	.global Checkpoints; Checkpoints: .space 4														# Linker Hash: 134, Assembler Hash: 123, Object: ent_gen.c
	.global Sel_light_inst_a; Sel_light_inst_a: .space 4											# Linker Hash: 136, Assembler Hash: 120, Object: select.c
	.global Grid_zshift; Grid_zshift: .space 4														# Linker Hash: 136, Assembler Hash: 125, Object: grid.c
	.global Map_water_height; Map_water_height: .space 4											# Linker Hash: 136, Assembler Hash: 120, Object: mapload.c
	.global Read_status; Read_status: .space 2														# Linker Hash: 138, Assembler Hash: 127, Object: loadsave.c
	.space	2 # Padding
	.global Frog_model_pieces_mof; Frog_model_pieces_mof: .space 4									# Linker Hash: 140, Assembler Hash: 119, Object: model.c
	.global Options_current_selection; Options_current_selection: .space 4							# Linker Hash: 140, Assembler Hash: 115, Object: tempopt.c
	.global xa_old_ready_callback; xa_old_ready_callback: .space 4									# Linker Hash: 140, Assembler Hash: 119, Object: playxa.c
	.global Load_status; Load_status: .space 2														# Linker Hash: 142, Assembler Hash: 131, Object: loadsave.c
	.space	2 # Padding
	.global Cav_light_switch; Cav_light_switch: .space 4											# Linker Hash: 146, Assembler Hash: 130, Object: ent_cav.c
	.global Game_perspective; Game_perspective: .space 4											# Linker Hash: 147, Assembler Hash: 131, Object: gamesys.c
	.global MRMouse_delta_buttons; MRMouse_delta_buttons: .space 2									# Linker Hash: 148, Assembler Hash: 127, Object: mr_input.c
	.space	2 # Padding
	.global Game_paused_selection; Game_paused_selection: .space 4									# Linker Hash: 149, Assembler Hash: 128, Object: pause.c
	.global Game_start_timer; Game_start_timer: .space 4											# Linker Hash: 151, Assembler Hash: 135, Object: gamesys.c
	.global MRTexture_block_count; MRTexture_block_count: .space 4									# Linker Hash: 151, Assembler Hash: 130, Object: mr_vram.c
	.global High_score_view_riverbed_points_ptr; High_score_view_riverbed_points_ptr: .space 4		# Linker Hash: 155, Assembler Hash: 120, Object: hsview.c
	.global Save_status; Save_status: .space 2														# Linker Hash: 157, Assembler Hash: 146, Object: loadsave.c
	.space	2 # Padding
	.global LS_message_sprite_pos; LS_message_sprite_pos: .space 4									# Linker Hash: 159, Assembler Hash: 138, Object: loadsave.c
	.global LS_message_sprite_ptr; LS_message_sprite_ptr: .space 4									# Linker Hash: 163, Assembler Hash: 142, Object: loadsave.c
	.global MRNumber_of_viewports; MRNumber_of_viewports: .space 2									# Linker Hash: 163, Assembler Hash: 142, Object: mr_view.c
	.space	2 # Padding
	.global Sel_status_end_x; Sel_status_end_x: .space 4											# Linker Hash: 164, Assembler Hash: 148, Object: select.c
	.global Sel_light_frame_0; Sel_light_frame_0: .space 4											# Linker Hash: 165, Assembler Hash: 148, Object: select.c
	.global Sel_light_frame_1; Sel_light_frame_1: .space 4											# Linker Hash: 166, Assembler Hash: 149, Object: select.c
	.global Sel_light_frame_2; Sel_light_frame_2: .space 4											# Linker Hash: 167, Assembler Hash: 150, Object: select.c
	.global Fade_bottom_right_pos; Fade_bottom_right_pos: .space 8									# Linker Hash: 167, Assembler Hash: 146, Object: entity.c
	.global Options_language_mode; Options_language_mode: .space 4									# Linker Hash: 168, Assembler Hash: 147, Object: tempopt.c
	.global Options_ptr; Options_ptr: .space 4														# Linker Hash: 172, Assembler Hash: 161, Object: tempopt.c
	.global LS_load_mode; LS_load_mode: .space 4													# Linker Hash: 174, Assembler Hash: 162, Object: loadsave.c
	.global xa_command_count; xa_command_count: .space 4											# Linker Hash: 175, Assembler Hash: 159, Object: playxa.c
	.global xa_execute_index; xa_execute_index: .space 4											# Linker Hash: 178, Assembler Hash: 162, Object: playxa.c
	.global MRLoad_error; MRLoad_error: .space 4													# Linker Hash: 180, Assembler Hash: 168, Object: mr_file.c
	.global MRSND_number_of_groups; MRSND_number_of_groups: .space 4								# Linker Hash: 181, Assembler Hash: 159, Object: mr_sound.c
	.global LS_wait; LS_wait: .space 4																# Linker Hash: 186, Assembler Hash: 179, Object: loadsave.c
	.global Selection_Options_ptr; Selection_Options_ptr: .space 4									# Linker Hash: 187, Assembler Hash: 166, Object: tempopt.c
	.global LS_save_mode; LS_save_mode: .space 4													# Linker Hash: 189, Assembler Hash: 177, Object: loadsave.c
	.global MRRendered_meshes; MRRendered_meshes: .space 2											# Linker Hash: 189, Assembler Hash: 172, Object: mr_debug.c
	.space	2 # Padding
	.global xa_startpos; xa_startpos: .space 4														# Linker Hash: 195, Assembler Hash: 184, Object: playxa.c
	.global LS_exit_mode; LS_exit_mode: .space 4													# Linker Hash: 200, Assembler Hash: 188, Object: loadsave.c
	.global Sel_mof_bank; Sel_mof_bank: .space 4													# Linker Hash: 204, Assembler Hash: 192, Object: select.c
	.global LS_selection; LS_selection: .space 4													# Linker Hash: 208, Assembler Hash: 196, Object: loadsave.c
	.global Sel_camera_y; Sel_camera_y: .space 4													# Linker Hash: 208, Assembler Hash: 196, Object: select.c
	.global MRAnim_event_list; MRAnim_event_list: .space 4											# Linker Hash: 209, Assembler Hash: 192, Object: mr_anim.c
	.global High_score_view_delayed_request; High_score_view_delayed_request: .space 4				# Linker Hash: 211, Assembler Hash: 180, Object: hsview.c
	.global Options_extras_user_prompt_ptr; Options_extras_user_prompt_ptr: .space 4				# Linker Hash: 212, Assembler Hash: 182, Object: tempopt.c
	.global Frog_selection_master_player_id; Frog_selection_master_player_id: .space 4				# Linker Hash: 213, Assembler Hash: 182, Object: tempopt.c
	.global Port_id; Port_id: .space 4																# Linker Hash: 216, Assembler Hash: 209, Object: select.c
	.global MRUse_cd_routines; MRUse_cd_routines: .space 4											# Linker Hash: 219, Assembler Hash: 202, Object: mr_file.c
	.global Score_sprite_root_ptr; Score_sprite_root_ptr: .space 4									# Linker Hash: 223, Assembler Hash: 202, Object: score.c
	.global MRObject_root_ptr; MRObject_root_ptr: .space 4											# Linker Hash: 223, Assembler Hash: 206, Object: mr_obj.c
	.global MRColl_matrix_ptr; MRColl_matrix_ptr: .space 4											# Linker Hash: 227, Assembler Hash: 210, Object: mr_coll.c
	.global xa_add_index; xa_add_index: .space 4													# Linker Hash: 228, Assembler Hash: 216, Object: playxa.c
	.global Game_running; Game_running: .space 4													# Linker Hash: 230, Assembler Hash: 218, Object: gamesys.c
	.global Frog_model_pieces; Frog_model_pieces: .space 4											# Linker Hash: 231, Assembler Hash: 214, Object: model.c
	.global xa_paused_cd; xa_paused_cd: .space 4													# Linker Hash: 236, Assembler Hash: 224, Object: playxa.c
	.global Sel_target_y; Sel_target_y: .space 4													# Linker Hash: 238, Assembler Hash: 226, Object: select.c
	.global Map_vertices; Map_vertices: .space 4													# Linker Hash: 238, Assembler Hash: 226, Object: mapload.c
	.space	4 # Padding
	.global Fade_top_left_pos; Fade_top_left_pos: .space 8											# Linker Hash: 238, Assembler Hash: 221, Object: entity.c
	.global MRSND_vab_info_ptr; MRSND_vab_info_ptr: .space 4										# Linker Hash: 238, Assembler Hash: 220, Object: mr_sound.c
	.global MRSND_moving_sound_root_ptr; MRSND_moving_sound_root_ptr: .space 4						# Linker Hash: 238, Assembler Hash: 211, Object: mr_sound.c
	.global High_score_view_frog_anim_matrix_ptr; High_score_view_frog_anim_matrix_ptr: .space 4	# Linker Hash: 243, Assembler Hash: 207, Object: hsview.c
	.global Map_entity_header; Map_entity_header: .space 4											# Linker Hash: 243, Assembler Hash: 226, Object: mapload.c
	.global High_score_view_water_prim_ptrs; High_score_view_water_prim_ptrs: .space 8				# Linker Hash: 245, Assembler Hash: 214, Object: hsview.c
	.global Grid_squares; Grid_squares: .space 4													# Linker Hash: 245, Assembler Hash: 233, Object: grid.c
	.global LS_num_selections; LS_num_selections: .space 4											# Linker Hash: 247, Assembler Hash: 230, Object: loadsave.c
	.global Select_bg_counter; Select_bg_counter: .space 4											# Linker Hash: 248, Assembler Hash: 231, Object: select.c
	.space	4 # Padding
	.global Sel_dest_vec_roll; Sel_dest_vec_roll: .space 8											# Linker Hash: 249, Assembler Hash: 232, Object: select.c
	.global Pause_volume; Pause_volume: .space 1													# Linker Hash: 257, Assembler Hash: 245, Object: pause.c
	.space	3 # Padding
	.global Sel_spin_max_time; Sel_spin_max_time: .space 4											# Linker Hash: 257, Assembler Hash: 240, Object: select.c
	.global Option_camera_ptr; Option_camera_ptr: .space 4											# Linker Hash: 263, Assembler Hash: 246, Object: options.c
	.global Sky_land_vertices; Sky_land_vertices: .space 4											# Linker Hash: 266, Assembler Hash: 249, Object: mapdisp.c
	.global From_options; From_options: .space 4													# Linker Hash: 267, Assembler Hash: 255, Object: tempopt.c
	.global MRSND_number_of_samples; MRSND_number_of_samples: .space 4								# Linker Hash: 267, Assembler Hash: 244, Object: mr_sound.c
	.global Anti_piracy_count; Anti_piracy_count: .space 4											# Linker Hash: 268, Assembler Hash: 251, Object: tempopt.c
	.global MRRender_peak; MRRender_peak: .space 4													# Linker Hash: 268, Assembler Hash: 255, Object: mr_disp.c
	.global LS_check_mode; LS_check_mode: .space 4													# Linker Hash: 269, Assembler Hash: 0, Object: loadsave.c
	.global Sel_light_object_0; Sel_light_object_0: .space 4										# Linker Hash: 274, Assembler Hash: 0, Object: select.c
	.global Memory_card_object_ptr; Memory_card_object_ptr: .space 8								# Linker Hash: 275, Assembler Hash: 253, Object: loadsave.c
	.global Sel_light_object_1; Sel_light_object_1: .space 4										# Linker Hash: 275, Assembler Hash: 1, Object: select.c
	.global Sel_light_object_2; Sel_light_object_2: .space 4										# Linker Hash: 276, Assembler Hash: 2, Object: select.c
	.global Frog_selection_network_request_flags; Frog_selection_network_request_flags: .space 4	# Linker Hash: 276, Assembler Hash: 240, Object: tempopt.c
	.global Game0_present; Game0_present: .space 4													# Linker Hash: 279, Assembler Hash: 10, Object: loadsave.c
	.global Card0_present; Card0_present: .space 4													# Linker Hash: 279, Assembler Hash: 10, Object: loadsave.c
	.global Game1_present; Game1_present: .space 4													# Linker Hash: 280, Assembler Hash: 11, Object: loadsave.c
	.global Card1_present; Card1_present: .space 4													# Linker Hash: 280, Assembler Hash: 11, Object: loadsave.c
	.global MRRender_time; MRRender_time: .space 4													# Linker Hash: 282, Assembler Hash: 13, Object: mr_disp.c
	.global LS_message_texture_ptr; LS_message_texture_ptr: .space 4								# Linker Hash: 286, Assembler Hash: 8, Object: loadsave.c
	.global Game_map; Game_map: .space 4															# Linker Hash: 287, Assembler Hash: 23, Object: gamesys.c
	.global card_HwEvSpIOE; card_HwEvSpIOE: .space 4												# Linker Hash: 289, Assembler Hash: 19, Object: memcard.c
	.space	4 # Padding
	.global Form_library_ptrs; Form_library_ptrs: .space 8											# Linker Hash: 289, Assembler Hash: 16, Object: form.c
	.global Sel_loading_sprite_ptr; Sel_loading_sprite_ptr: .space 4								# Linker Hash: 290, Assembler Hash: 12, Object: select.c
	.global Sel_status_temp_x; Sel_status_temp_x: .space 4											# Linker Hash: 292, Assembler Hash: 19, Object: select.c
	.global Frog_selection_master_flags; Frog_selection_master_flags: .space 4						# Linker Hash: 293, Assembler Hash: 10, Object: tempopt.c
	.global MROT_root_ptr; MROT_root_ptr: .space 4													# Linker Hash: 295, Assembler Hash: 26, Object: mr_ot.c
	.global High_score_view_automatic_picked_flag; High_score_view_automatic_picked_flag: .space 4	# Linker Hash: 296, Assembler Hash: 3, Object: hsview.c
	.global Game_language; Game_language: .space 4													# Linker Hash: 298, Assembler Hash: 29, Object: tempopt.c
	.global xa_command_status; xa_command_status: .space 4											# Linker Hash: 299, Assembler Hash: 26, Object: playxa.c
	.global MRNumber_of_frames; MRNumber_of_frames: .space 2										# Linker Hash: 299, Assembler Hash: 25, Object: mr_frame.c
	.space	2 # Padding
	.global card_SwEvSpIOE; card_SwEvSpIOE: .space 4												# Linker Hash: 300, Assembler Hash: 30, Object: memcard.c
	.global MRColl_lw_ptr; MRColl_lw_ptr: .space 4													# Linker Hash: 301, Assembler Hash: 32, Object: mr_coll.c
	.global Sel_game_mode; Sel_game_mode: .space 4													# Linker Hash: 302, Assembler Hash: 33, Object: select.c
	.global card_HwEvSpNEW; card_HwEvSpNEW: .space 4												# Linker Hash: 302, Assembler Hash: 32, Object: memcard.c
	.global Map_book; Map_book: .space 4															# Linker Hash: 304, Assembler Hash: 40, Object: mapload.c
	.global Sel_mode; Sel_mode: .space 4															# Linker Hash: 304, Assembler Hash: 40, Object: select.c
	.global Game_map_time; Game_map_time: .space 4													# Linker Hash: 306, Assembler Hash: 37, Object: gamesys.c
	.global Map_general_header; Map_general_header: .space 4										# Linker Hash: 309, Assembler Hash: 35, Object: mapload.c
	.global Race_ptr; Race_ptr: .space 4															# Linker Hash: 312, Assembler Hash: 48, Object: tempopt.c
	.global card_SwEvSpNEW; card_SwEvSpNEW: .space 4												# Linker Hash: 313, Assembler Hash: 43, Object: memcard.c
	.global Demo_data_ptr; Demo_data_ptr: .space 4													# Linker Hash: 320, Assembler Hash: 51, Object: tempopt.c
	.global MRMouse_pminx; MRMouse_pminx: .space 4													# Linker Hash: 320, Assembler Hash: 51, Object: mr_input.c
	.global MRMouse_pminy; MRMouse_pminy: .space 4													# Linker Hash: 321, Assembler Hash: 52, Object: mr_input.c
	.global MRMouse_pmaxx; MRMouse_pmaxx: .space 4													# Linker Hash: 322, Assembler Hash: 53, Object: mr_input.c
	.global Sel_light_object_a; Sel_light_object_a: .space 4										# Linker Hash: 323, Assembler Hash: 49, Object: select.c
	.global Map_mof_index; Map_mof_index: .space 4													# Linker Hash: 323, Assembler Hash: 54, Object: project.c
	.global MRMouse_pmaxy; MRMouse_pmaxy: .space 4													# Linker Hash: 323, Assembler Hash: 54, Object: mr_input.c
	.global xa_reading_cd; xa_reading_cd: .space 4													# Linker Hash: 325, Assembler Hash: 56, Object: playxa.c
	.global Game_paused_finish; Game_paused_finish: .space 4										# Linker Hash: 333, Assembler Hash: 59, Object: pause.c
	.global Sel_spin_mode; Sel_spin_mode: .space 4													# Linker Hash: 334, Assembler Hash: 65, Object: select.c
	.global xa_param; xa_param: .space 8															# Linker Hash: 337, Assembler Hash: 73, Object: playxa.c
	.global Map_group_entity_roots; Map_group_entity_roots: .space 4								# Linker Hash: 338, Assembler Hash: 60, Object: mapload.c
	.global Game_multiplayer_play_off_sprite; Game_multiplayer_play_off_sprite: .space 4			# Linker Hash: 342, Assembler Hash: 54, Object: gamesys.c
	.global MRCd_lock; MRCd_lock: .space 4															# Linker Hash: 343, Assembler Hash: 78, Object: mr_file.c
	.global Sel_spin_time; Sel_spin_time: .space 4													# Linker Hash: 344, Assembler Hash: 75, Object: select.c
	.global MRSND_system_options_panning; MRSND_system_options_panning: .space 4					# Linker Hash: 345, Assembler Hash: 61, Object: mr_sound.c
	.global Map_view_xlen; Map_view_xlen: .space 4													# Linker Hash: 347, Assembler Hash: 78, Object: mapview.c
	.global Sel_race_level_ptr; Sel_race_level_ptr: .space 4										# Linker Hash: 348, Assembler Hash: 74, Object: select.c
	.global Sel_level_ptr; Sel_level_ptr: .space 4													# Linker Hash: 349, Assembler Hash: 80, Object: select.c
	.global Map_view_zlen; Map_view_zlen: .space 4													# Linker Hash: 349, Assembler Hash: 80, Object: mapview.c
	.global Sel_glowy_col; Sel_glowy_col: .space 4													# Linker Hash: 351, Assembler Hash: 82, Object: select.c
	.global Map_path_ptrs; Map_path_ptrs: .space 4													# Linker Hash: 351, Assembler Hash: 82, Object: mapload.c
	.global Sel_glowy_dir; Sel_glowy_dir: .space 4													# Linker Hash: 352, Assembler Hash: 83, Object: select.c
	.global Game_display_width; Game_display_width: .space 4										# Linker Hash: 352, Assembler Hash: 78, Object: gamesys.c
	.global Map_form_ptrs; Map_form_ptrs: .space 4													# Linker Hash: 358, Assembler Hash: 89, Object: mapload.c
	.global High_score_view_water_points_ptr; High_score_view_water_points_ptr: .space 4			# Linker Hash: 360, Assembler Hash: 72, Object: hsview.c
	.global Map_view_xnum; Map_view_xnum: .space 4													# Linker Hash: 364, Assembler Hash: 95, Object: mapview.c
	.global MRSND_current_ident; MRSND_current_ident: .space 4										# Linker Hash: 364, Assembler Hash: 89, Object: mr_sound.c
	.global MRMouse_up_buttons; MRMouse_up_buttons: .space 2										# Linker Hash: 364, Assembler Hash: 90, Object: mr_input.c
	.space	2 # Padding
	.global Option_number; Option_number: .space 4													# Linker Hash: 366, Assembler Hash: 97, Object: tempopt.c
	.global Map_view_znum; Map_view_znum: .space 4													# Linker Hash: 366, Assembler Hash: 97, Object: mapview.c
	.global Map_zone_ptrs; Map_zone_ptrs: .space 4													# Linker Hash: 366, Assembler Hash: 97, Object: mapload.c
	.space	4 # Padding
	.global Map_view_basepoint; Map_view_basepoint: .space 8										# Linker Hash: 366, Assembler Hash: 92, Object: mapview.c
	.global Game_total_players; Game_total_players: .space 4										# Linker Hash: 366, Assembler Hash: 92, Object: gamesys.c
	.global str_old_frame; str_old_frame: .space 4													# Linker Hash: 366, Assembler Hash: 97, Object: stream.c
	.global Sel_start_pos; Sel_start_pos: .space 8													# Linker Hash: 367, Assembler Hash: 98, Object: select.c
	.global MRTexture_list_ptr; MRTexture_list_ptr: .space 4										# Linker Hash: 370, Assembler Hash: 96, Object: mr_mof.c
	.space	4 # Padding
	.global Sel_start_vec_roll; Sel_start_vec_roll: .space 8										# Linker Hash: 376, Assembler Hash: 102, Object: select.c
	.global MRSND_master_volume; MRSND_master_volume: .space 4										# Linker Hash: 377, Assembler Hash: 102, Object: mr_sound.c
	.global MRUser_pc; MRUser_pc: .space 4															# Linker Hash: 377, Assembler Hash: 112, Object: mr_disp.c
	.global Map_numgroups; Map_numgroups: .space 4													# Linker Hash: 378, Assembler Hash: 109, Object: mapload.c
	.global Gold_frogs_current; Gold_frogs_current: .space 4										# Linker Hash: 378, Assembler Hash: 104, Object: ent_gen.c
	.global Sel_requested_play; Sel_requested_play: .space 4										# Linker Hash: 380, Assembler Hash: 106, Object: select.c
	.global Playagain_cc_sprite_ptr; Playagain_cc_sprite_ptr: .space 4								# Linker Hash: 381, Assembler Hash: 102, Object: tempopt.c
	.global str_file_size; str_file_size: .space 4													# Linker Hash: 383, Assembler Hash: 114, Object: stream.c
	.global Sel_camera_acc; Sel_camera_acc: .space 4												# Linker Hash: 384, Assembler Hash: 114, Object: select.c
	.global MRFrame_number; MRFrame_number: .space 4												# Linker Hash: 384, Assembler Hash: 114, Object: mr_disp.c
	.space	4 # Padding
	.global HSView_arrow_sprite_ptr; HSView_arrow_sprite_ptr: .space 8								# Linker Hash: 386, Assembler Hash: 107, Object: hsview.c
	.global Frog_model_pieces_polys; Frog_model_pieces_polys: .space 4								# Linker Hash: 387, Assembler Hash: 108, Object: model.c
	.global Sel_work_level_ptr; Sel_work_level_ptr: .space 4										# Linker Hash: 388, Assembler Hash: 114, Object: select.c
	.global Game_mode_data; Game_mode_data: .space 4												# Linker Hash: 389, Assembler Hash: 119, Object: gamesys.c
	.global Game_mode; Game_mode: .space 4															# Linker Hash: 391, Assembler Hash: 126, Object: gamesys.c
	.global Playagain_pa_sprite_ptr; Playagain_pa_sprite_ptr: .space 4								# Linker Hash: 392, Assembler Hash: 113, Object: tempopt.c
	.global MRMouse_x; MRMouse_x: .space 4															# Linker Hash: 392, Assembler Hash: 127, Object: mr_input.c
	.global MRMouse_y; MRMouse_y: .space 4															# Linker Hash: 393, Assembler Hash: 128, Object: mr_input.c
	.space	4 # Padding
	.global LS_extras_mesh_inst_ptr; LS_extras_mesh_inst_ptr: .space 8								# Linker Hash: 394, Assembler Hash: 115, Object: loadsave.c
	.global num_of_swarms; num_of_swarms: .space 4													# Linker Hash: 397, Assembler Hash: 128, Object: ent_for.c
	.global LS_card_number; LS_card_number: .space 4												# Linker Hash: 398, Assembler Hash: 128, Object: loadsave.c
	.global LS_select_mode; LS_select_mode: .space 4												# Linker Hash: 400, Assembler Hash: 130, Object: loadsave.c
	.global Playagain_ex_sprite_ptr; Playagain_ex_sprite_ptr: .space 4								# Linker Hash: 404, Assembler Hash: 125, Object: tempopt.c
	.global Game_map_theme; Game_map_theme: .space 4												# Linker Hash: 407, Assembler Hash: 137, Object: gamesys.c
	.global Game_viewport0; Game_viewport0: .space 4												# Linker Hash: 407, Assembler Hash: 137, Object: gamesys.c
	.global Game_viewport1; Game_viewport1: .space 4												# Linker Hash: 408, Assembler Hash: 138, Object: gamesys.c
	.global MRDefault_font_info; MRDefault_font_info: .space 4										# Linker Hash: 408, Assembler Hash: 133, Object: mr_font.c
	.global MRNumber_of_objects; MRNumber_of_objects: .space 2										# Linker Hash: 408, Assembler Hash: 133, Object: mr_obj.c
	.space	2 # Padding
	.global Game_viewport2; Game_viewport2: .space 4												# Linker Hash: 409, Assembler Hash: 139, Object: gamesys.c
	.global Game_viewport3; Game_viewport3: .space 4												# Linker Hash: 410, Assembler Hash: 140, Object: gamesys.c
	.global LS_delay_timer; LS_delay_timer: .space 4												# Linker Hash: 411, Assembler Hash: 141, Object: loadsave.c
	.global MRSND_moving_sound_count; MRSND_moving_sound_count: .space 4							# Linker Hash: 411, Assembler Hash: 131, Object: mr_sound.c
	.global Demo_time; Demo_time: .space 4															# Linker Hash: 412, Assembler Hash: 147, Object: tempopt.c
	.global Sel_status_start_x; Sel_status_start_x: .space 4										# Linker Hash: 413, Assembler Hash: 139, Object: select.c
	.global Map_anims; Map_anims: .space 4															# Linker Hash: 414, Assembler Hash: 149, Object: mapload.c
	.global Sel_camera_vel; Sel_camera_vel: .space 4												# Linker Hash: 416, Assembler Hash: 146, Object: select.c
	.space	4 # Padding
	.global MRColl_transpt; MRColl_transpt: .space 8												# Linker Hash: 418, Assembler Hash: 148, Object: mr_coll.c
	.global HSView_counter; HSView_counter: .space 4												# Linker Hash: 419, Assembler Hash: 149, Object: hsview.c
	.global Frog_selection_request_flags; Frog_selection_request_flags: .space 4					# Linker Hash: 419, Assembler Hash: 135, Object: tempopt.c
	.global High_score_view_frog_anim_env_ptr; High_score_view_frog_anim_env_ptr: .space 4			# Linker Hash: 420, Assembler Hash: 131, Object: hsview.c
	.global Grid_xlen; Grid_xlen: .space 4															# Linker Hash: 421, Assembler Hash: 156, Object: grid.c
	.global Game_map_timer; Game_map_timer: .space 4												# Linker Hash: 421, Assembler Hash: 151, Object: gamesys.c
	.global Game_map_timer_frac; Game_map_timer_frac: .space 4										# Linker Hash: 421, Assembler Hash: 146, Object: gamesys.c
	.global Grid_zlen; Grid_zlen: .space 4															# Linker Hash: 423, Assembler Hash: 158, Object: grid.c
	.global LS_memory_card_rotation1; LS_memory_card_rotation1: .space 2							# Linker Hash: 424, Assembler Hash: 144, Object: loadsave.c
	.global LS_memory_card_rotation2; LS_memory_card_rotation2: .space 2							# Linker Hash: 425, Assembler Hash: 145, Object: loadsave.c
	.global Select_bg_xlen; Select_bg_xlen: .space 4												# Linker Hash: 428, Assembler Hash: 158, Object: select.c
	.global Select_bg_ylen; Select_bg_ylen: .space 4												# Linker Hash: 429, Assembler Hash: 159, Object: select.c
	.global Sel_title; Sel_title: .space 4															# Linker Hash: 430, Assembler Hash: 165, Object: select.c
	.global Any_high_score; Any_high_score: .space 4												# Linker Hash: 432, Assembler Hash: 162, Object: hsinput.c
	.global MRSND_cd_volume; MRSND_cd_volume: .space 4												# Linker Hash: 432, Assembler Hash: 161, Object: mr_sound.c
	.global New_high_score; New_high_score: .space 1												# Linker Hash: 434, Assembler Hash: 164, Object: hsinput.c
	.space	3 # Padding
	.global Sel_count; Sel_count: .space 4															# Linker Hash: 437, Assembler Hash: 172, Object: select.c
	.global Sel_spin_frame; Sel_spin_frame: .space 4												# Linker Hash: 437, Assembler Hash: 167, Object: select.c
	.global Sel_dest_vec_y; Sel_dest_vec_y: .space 8												# Linker Hash: 438, Assembler Hash: 168, Object: select.c
	.global Grid_xnum; Grid_xnum: .space 4															# Linker Hash: 438, Assembler Hash: 173, Object: grid.c
	.global MRAnim_env_root_ptr; MRAnim_env_root_ptr: .space 4										# Linker Hash: 439, Assembler Hash: 164, Object: mr_anim.c
	.global Grid_znum; Grid_znum: .space 4															# Linker Hash: 440, Assembler Hash: 175, Object: grid.c
	.global Game_display_height; Game_display_height: .space 4										# Linker Hash: 442, Assembler Hash: 167, Object: gamesys.c
	.global Select_bg_direction; Select_bg_direction: .space 4										# Linker Hash: 443, Assembler Hash: 168, Object: select.c
	.global Select_bg_xnum; Select_bg_xnum: .space 4												# Linker Hash: 445, Assembler Hash: 175, Object: select.c
	.global Sel_camera_y_offset; Sel_camera_y_offset: .space 4										# Linker Hash: 445, Assembler Hash: 170, Object: select.c
	.global Game_last_map_timer; Game_last_map_timer: .space 4										# Linker Hash: 445, Assembler Hash: 170, Object: gamesys.c
	.global Select_bg_ynum; Select_bg_ynum: .space 4												# Linker Hash: 446, Assembler Hash: 176, Object: select.c
	.global MRSND_number_of_vabs; MRSND_number_of_vabs: .space 4									# Linker Hash: 447, Assembler Hash: 171, Object: mr_sound.c
	.global MRNumber_of_OTs; MRNumber_of_OTs: .space 2												# Linker Hash: 448, Assembler Hash: 177, Object: mr_ot.c
	.space	2 # Padding
	.global High_score_matrices; High_score_matrices: .space 4										# Linker Hash: 453, Assembler Hash: 178, Object: hsview.c
	.global Sel_first_time; Sel_first_time: .space 4												# Linker Hash: 455, Assembler Hash: 185, Object: select.c
	.global xa_filter; xa_filter: .space 4															# Linker Hash: 455, Assembler Hash: 190, Object: playxa.c
	.global xa_change_list; xa_change_list: .space 4												# Linker Hash: 455, Assembler Hash: 185, Object: playxa.c
	.global MRSND_fx_volume; MRSND_fx_volume: .space 4												# Linker Hash: 455, Assembler Hash: 184, Object: mr_sound.c
	.global MRMouse_old_buttons; MRMouse_old_buttons: .space 2										# Linker Hash: 455, Assembler Hash: 180, Object: mr_input.c
	.space	2 # Padding
	.global xa_endpos; xa_endpos: .space 4															# Linker Hash: 458, Assembler Hash: 193, Object: playxa.c
	.global Game_viewportc; Game_viewportc: .space 4												# Linker Hash: 458, Assembler Hash: 188, Object: gamesys.c
	.global Start_ptr; Start_ptr: .space 4															# Linker Hash: 460, Assembler Hash: 195, Object: tempopt.c
	.global Map_vertex_min; Map_vertex_min: .space 8												# Linker Hash: 460, Assembler Hash: 190, Object: mapload.c
	.global str_frame; str_frame: .space 4															# Linker Hash: 460, Assembler Hash: 195, Object: stream.c
	.space	4 # Padding
	.global Map_vertex_max; Map_vertex_max: .space 8												# Linker Hash: 462, Assembler Hash: 192, Object: mapload.c
	.global Game_continues_left; Game_continues_left: .space 4										# Linker Hash: 462, Assembler Hash: 187, Object: gamesys.c
	.global Game_viewporth; Game_viewporth: .space 4												# Linker Hash: 463, Assembler Hash: 193, Object: gamesys.c
	.global card_HwEvSpERROR; card_HwEvSpERROR: .space 4											# Linker Hash: 464, Assembler Hash: 192, Object: memcard.c
	.global MRMouse_new_buttons; MRMouse_new_buttons: .space 2										# Linker Hash: 466, Assembler Hash: 191, Object: mr_input.c
	.space	2 # Padding
	.global Demo_data_input_ptr; Demo_data_input_ptr: .space 4										# Linker Hash: 469, Assembler Hash: 194, Object: tempopt.c
	.global Recording_demo_text_area; Recording_demo_text_area: .space 4							# Linker Hash: 469, Assembler Hash: 189, Object: gamesys.c
	.global str_video; str_video: .space 4															# Linker Hash: 472, Assembler Hash: 207, Object: stream.c
	.global LS_title_sprite_pos; LS_title_sprite_pos: .space 4										# Linker Hash: 474, Assembler Hash: 199, Object: loadsave.c
	.global Sel_spin_backup_ptr; Sel_spin_backup_ptr: .space 4										# Linker Hash: 474, Assembler Hash: 199, Object: select.c
	.global card_SwEvSpERROR; card_SwEvSpERROR: .space 4											# Linker Hash: 475, Assembler Hash: 203, Object: memcard.c
	.global LS_title_sprite_ptr; LS_title_sprite_ptr: .space 4										# Linker Hash: 478, Assembler Hash: 203, Object: loadsave.c
	.global xa_looped_play; xa_looped_play: .space 4												# Linker Hash: 478, Assembler Hash: 208, Object: playxa.c
	.global xa_result; xa_result: .space 8															# Linker Hash: 480, Assembler Hash: 215, Object: playxa.c
	.global xa_requested_change; xa_requested_change: .space 4										# Linker Hash: 482, Assembler Hash: 207, Object: playxa.c
	.global MRSND_group_info_ptr; MRSND_group_info_ptr: .space 4									# Linker Hash: 484, Assembler Hash: 208, Object: mr_sound.c
	.global Options_update_mode; Options_update_mode: .space 4										# Linker Hash: 485, Assembler Hash: 210, Object: tempopt.c
	.global MRSND_viewports; MRSND_viewports: .space 2												# Linker Hash: 485, Assembler Hash: 214, Object: mr_sound.c
	.space	2 # Padding
	.global Pad_user_prompt_text_instptr; Pad_user_prompt_text_instptr: .space 4					# Linker Hash: 487, Assembler Hash: 203, Object: tempopt.c
	.global Option_page_current; Option_page_current: .space 4										# Linker Hash: 490, Assembler Hash: 215, Object: options.c
	.global MRTexture_block_root_ptr; MRTexture_block_root_ptr: .space 4							# Linker Hash: 490, Assembler Hash: 210, Object: mr_vram.c
	.global MRViewport_root_ptr; MRViewport_root_ptr: .space 4										# Linker Hash: 490, Assembler Hash: 215, Object: mr_view.c
	.global MRMouse_dx; MRMouse_dx: .space 2														# Linker Hash: 493, Assembler Hash: 227, Object: mr_input.c
	.space	2 # Padding
	.global Option_spcore_index; Option_spcore_index: .space 4										# Linker Hash: 494, Assembler Hash: 219, Object: options.c
	.global MRMouse_dy; MRMouse_dy: .space 2														# Linker Hash: 494, Assembler Hash: 228, Object: mr_input.c
	.space	2 # Padding
	.global Map_header; Map_header: .space 4														# Linker Hash: 496, Assembler Hash: 230, Object: mapload.c
	.global Option_page_request; Option_page_request: .space 4										# Linker Hash: 496, Assembler Hash: 221, Object: options.c
	.global Game_flags; Game_flags: .space 4														# Linker Hash: 496, Assembler Hash: 230, Object: gamesys.c
	.global Game_cheat_mode; Game_cheat_mode: .space 4												# Linker Hash: 497, Assembler Hash: 226, Object: gamesys.c
	.global Option_spcore_value; Option_spcore_value: .space 4										# Linker Hash: 499, Assembler Hash: 224, Object: options.c
	.global Game_debug_mode; Game_debug_mode: .space 4												# Linker Hash: 499, Assembler Hash: 228, Object: gamesys.c
	.global MRFont_data_ptr; MRFont_data_ptr: .space 4												# Linker Hash: 499, Assembler Hash: 228, Object: mr_font.c
	.global Sel_glowy_level_ptr; Sel_glowy_level_ptr: .space 4										# Linker Hash: 500, Assembler Hash: 225, Object: select.c
	.global LS_message_mode; LS_message_mode: .space 4												# Linker Hash: 502, Assembler Hash: 231, Object: loadsave.c
	.global MRListed_meshes; MRListed_meshes: .space 2												# Linker Hash: 503, Assembler Hash: 232, Object: mr_debug.c
	.space	2 # Padding
	.global Map_anim_header; Map_anim_header: .space 4												# Linker Hash: 505, Assembler Hash: 234, Object: mapload.c
	.global MRMouse_px; MRMouse_px: .space 4														# Linker Hash: 505, Assembler Hash: 239, Object: mr_input.c
	.global Map_grid_header; Map_grid_header: .space 4												# Linker Hash: 506, Assembler Hash: 235, Object: mapload.c
	.global MRMouse_py; MRMouse_py: .space 4														# Linker Hash: 506, Assembler Hash: 240, Object: mr_input.c
	.global MRFont_buff_ptr; MRFont_buff_ptr: .space 4												# Linker Hash: 508, Assembler Hash: 237, Object: mr_font.c

