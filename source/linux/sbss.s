.section .sbss

# XXX
.global __ra_temp
__ra_temp:
    .space 8,0

.global Map_path_header
Map_path_header:
    .space 4,0

.global Map_graphical_header
Map_graphical_header:
    .space 4,0

.global Game_timer
Game_timer:
    .space 4,0

.global Main_options_status
Main_options_status:
    .space 4,0

.global Map_form_header
Map_form_header:
    .space 4,0

.global High_high_score
High_high_score:
    .space 4,0

.global Sky_land_header
Sky_land_header:
    .space 4,0

.global Map_zone_header
Map_zone_header:
    .space 4,0

.global Gold_frogs
Gold_frogs:
    .space 4,0

.global Sel_stack_frame
Sel_stack_frame:
    .space 4,0

.global Map_lights
Map_lights:
    .space 4,0

.global Frog_selection_number_players
Frog_selection_number_players:
    .space 4,0

.global Game_map_timer_flags
Game_map_timer_flags:
    .space 4,0

.global High_score_view_flyon_counter
High_score_view_flyon_counter:
    .space 4,0

.global Game_map_timer_speed
Game_map_timer_speed:
    .space 4,0

.global Game_hud_script
Game_hud_script:
    .space 4,0

.global MRCalc_peak
MRCalc_peak:
    .space 4,0

.global Options_count_down_ticks
Options_count_down_ticks:
    .space 4,0

.global Option_viewport_ptr
Option_viewport_ptr:
    .space 4,0

.global Sel_arcade_level_ptr
Sel_arcade_level_ptr:
    .space 4,0

.global xa_change_index
xa_change_index:
    .space 4,0

.global Map_groups
Map_groups:
    .space 4,0

.global High_score_view_riverbed_prim_ptrs
High_score_view_riverbed_prim_ptrs:
    .space 8,0

.global card_HwEvSpTIMOUT
card_HwEvSpTIMOUT:
    .space 4,0

.global Sel_level_title
Sel_level_title:
    .space 4,0

.global MRCalc_time
MRCalc_time:
    .space 8,0

.global Select_bg_polys
Select_bg_polys:
    .space 8,0

.global High_score_view_mode
High_score_view_mode:
    .space 4,0

.global Gold_frogs_zone
Gold_frogs_zone:
    .space 4,0

.global Hud_bonus_score
Hud_bonus_score:
    .space 4,0

.global xa_old_sync_callback
xa_old_sync_callback:
    .space 4,0

.global LS_extras_object_ptr
LS_extras_object_ptr:
    .space 8,0

.global Effect_root_ptr
Effect_root_ptr:
    .space 4,0

.global card_SwEvSpTIMOUT
card_SwEvSpTIMOUT:
    .space 4,0

.global Sel_start_vec_y
Sel_start_vec_y:
    .space 8,0

.global Options_count_down_units
Options_count_down_units:
    .space 4,0

.global xa_channel_play
xa_channel_play:
    .space 4,0

.global Game_over_press_fire
Game_over_press_fire:
    .space 4,0

.global MRSND_sample_info_ptr
MRSND_sample_info_ptr:
    .space 4,0

.global MRMouse_down_buttons
MRMouse_down_buttons:
    .space 4,0

.global Checkpoint_last_collected
Checkpoint_last_collected:
    .space 4,0

.global str_params
str_params:
    .space 8,0

.global xa_current_file
xa_current_file:
    .space 4,0

.global str_frame_index
str_frame_index:
    .space 4,0

.global Map_light_min_r2
Map_light_min_r2:
    .space 4,0

.global Map_light_max_r2
Map_light_max_r2:
    .space 4,0

.global MRProf_time
MRProf_time:
    .space 4,0

.global xa_currpos
xa_currpos:
    .space 4,0

.global str_ring_buffer
str_ring_buffer:
    .space 4,0

.global Map_entity_ptrs
Map_entity_ptrs:
    .space 4,0

.global LSunformatted_sprite
LSunformatted_sprite:
    .space 8,0

.global LS_extras_matrix_ptr
LS_extras_matrix_ptr:
    .space 8,0

.global Sel_user_prompt
Sel_user_prompt:
    .space 4,0

.global xa_startup_flag
xa_startup_flag:
    .space 4,0

.global MRCd_status
MRCd_status:
    .space 8,0

.global xa_requested_channel
xa_requested_channel:
    .space 4,0

.global Sel_light_inst_0
Sel_light_inst_0:
    .space 4,0

.global Sel_light_inst_1
Sel_light_inst_1:
    .space 4,0

.global Sky_land_texture_ids
Sky_land_texture_ids:
    .space 4,0

.global LS_title_texture_ptr
LS_title_texture_ptr:
    .space 4,0

.global Sel_light_inst_2
Sel_light_inst_2:
    .space 4,0

.global LS_user_prompt_controls_sprite_ptr
LS_user_prompt_controls_sprite_ptr:
    .space 4,0

.global High_score_input_frog_num
High_score_input_frog_num:
    .space 4,0

.global LS_matrices
LS_matrices:
    .space 4,0

.global Grid_base_x
Grid_base_x:
    .space 4,0

.global Game_total_viewports
Game_total_viewports:
    .space 4,0

.global Grid_base_z
Grid_base_z:
    .space 4,0

.global MREnv_strip
MREnv_strip:
    .space 4,0

.global Sel_camera_frame
Sel_camera_frame:
    .space 4,0

.global Map_light_header
Map_light_header:
    .space 4,0

.global High_score_view_frog_anim_model_ptr
High_score_view_frog_anim_model_ptr:
    .space 4,0

.global MRNumber_of_anim_envs
MRNumber_of_anim_envs:
    .space 4,0

.global LS_selection_dir
LS_selection_dir:
    .space 4,0

.global Path_runner_root_ptr
Path_runner_root_ptr:
    .space 4,0

.global MRFrame_root_ptr
MRFrame_root_ptr:
    .space 4,0

.global MRCd_retry_count
MRCd_retry_count:
    .space 8,0

.global Sel_end_pos
Sel_end_pos:
    .space 8,0

.global High_score_view_flyoff_counter
High_score_view_flyoff_counter:
    .space 4,0

.global Live_entity_root_ptr
Live_entity_root_ptr:
    .space 4,0

.global Game_reset_flags
Game_reset_flags:
    .space 4,0

.global Grid_stacks
Grid_stacks:
    .space 4,0

.global Gameover_title_sprite_ptr
Gameover_title_sprite_ptr:
    .space 4,0

.global High_level_score
High_level_score:
    .space 4,0

.global Map_group_header
Map_group_header:
    .space 8,0

.global Map_wibble_water
Map_wibble_water:
    .space 8,0

.global Game_map_timer_decimalised
Game_map_timer_decimalised:
    .space 4,0

.global Grid_xshift
Grid_xshift:
    .space 4,0

.global Checkpoints
Checkpoints:
    .space 4,0

.global Sel_light_inst_a
Sel_light_inst_a:
    .space 4,0

.global Grid_zshift
Grid_zshift:
    .space 4,0

.global Map_water_height
Map_water_height:
    .space 4,0

.global Read_status
Read_status:
    .space 4,0

.global Frog_model_pieces_mof
Frog_model_pieces_mof:
    .space 4,0

.global Options_current_selection
Options_current_selection:
    .space 4,0

.global xa_old_ready_callback
xa_old_ready_callback:
    .space 4,0

.global Load_status
Load_status:
    .space 4,0

.global Cav_light_switch
Cav_light_switch:
    .space 4,0

.global Game_perspective
Game_perspective:
    .space 4,0

.global MRMouse_delta_buttons
MRMouse_delta_buttons:
    .space 4,0

.global Game_paused_selection
Game_paused_selection:
    .space 4,0

.global Game_start_timer
Game_start_timer:
    .space 4,0

.global MRTexture_block_count
MRTexture_block_count:
    .space 4,0

.global High_score_view_riverbed_points_ptr
High_score_view_riverbed_points_ptr:
    .space 4,0

.global Save_status
Save_status:
    .space 4,0

.global LS_message_sprite_pos
LS_message_sprite_pos:
    .space 4,0

.global LS_message_sprite_ptr
LS_message_sprite_ptr:
    .space 4,0

.global MRNumber_of_viewports
MRNumber_of_viewports:
    .space 4,0

.global Sel_status_end_x
Sel_status_end_x:
    .space 4,0

.global Sel_light_frame_0
Sel_light_frame_0:
    .space 4,0

.global Sel_light_frame_1
Sel_light_frame_1:
    .space 4,0

.global Sel_light_frame_2
Sel_light_frame_2:
    .space 4,0

.global Fade_bottom_right_pos
Fade_bottom_right_pos:
    .space 8,0

.global Options_language_mode
Options_language_mode:
    .space 4,0

.global Options_ptr
Options_ptr:
    .space 4,0

.global LS_load_mode
LS_load_mode:
    .space 4,0

.global xa_command_count
xa_command_count:
    .space 4,0

.global xa_execute_index
xa_execute_index:
    .space 4,0

.global MRLoad_error
MRLoad_error:
    .space 4,0

.global MRSND_number_of_groups
MRSND_number_of_groups:
    .space 4,0

.global LS_wait
LS_wait:
    .space 4,0

.global Selection_Options_ptr
Selection_Options_ptr:
    .space 4,0

.global LS_save_mode
LS_save_mode:
    .space 4,0

.global MRRendered_meshes
MRRendered_meshes:
    .space 4,0

.global xa_startpos
xa_startpos:
    .space 4,0

.global LS_exit_mode
LS_exit_mode:
    .space 4,0

.global Sel_mof_bank
Sel_mof_bank:
    .space 4,0

.global LS_selection
LS_selection:
    .space 4,0

.global Sel_camera_y
Sel_camera_y:
    .space 4,0

.global MRAnim_event_list
MRAnim_event_list:
    .space 4,0

.global High_score_view_delayed_request
High_score_view_delayed_request:
    .space 4,0

.global Options_extras_user_prompt_ptr
Options_extras_user_prompt_ptr:
    .space 4,0

.global Frog_selection_master_player_id
Frog_selection_master_player_id:
    .space 4,0

.global Port_id
Port_id:
    .space 4,0

.global MRUse_cd_routines
MRUse_cd_routines:
    .space 4,0

.global Score_sprite_root_ptr
Score_sprite_root_ptr:
    .space 4,0

.global MRObject_root_ptr
MRObject_root_ptr:
    .space 4,0

.global MRColl_matrix_ptr
MRColl_matrix_ptr:
    .space 4,0

.global xa_add_index
xa_add_index:
    .space 4,0

.global Game_running
Game_running:
    .space 4,0

.global Frog_model_pieces
Frog_model_pieces:
    .space 4,0

.global xa_paused_cd
xa_paused_cd:
    .space 4,0

.global Sel_target_y
Sel_target_y:
    .space 4,0

.global Map_vertices
Map_vertices:
    .space 8,0

.global Fade_top_left_pos
Fade_top_left_pos:
    .space 8,0

.global MRSND_vab_info_ptr
MRSND_vab_info_ptr:
    .space 4,0

.global MRSND_moving_sound_root_ptr
MRSND_moving_sound_root_ptr:
    .space 4,0

.global High_score_view_frog_anim_matrix_ptr
High_score_view_frog_anim_matrix_ptr:
    .space 4,0

.global Map_entity_header
Map_entity_header:
    .space 4,0

.global High_score_view_water_prim_ptrs
High_score_view_water_prim_ptrs:
    .space 8,0

.global Grid_squares
Grid_squares:
    .space 4,0

.global LS_num_selections
LS_num_selections:
    .space 4,0

.global Select_bg_counter
Select_bg_counter:
    .space 8,0

.global Sel_dest_vec_roll
Sel_dest_vec_roll:
    .space 8,0

.global Pause_volume
Pause_volume:
    .space 4,0

.global Sel_spin_max_time
Sel_spin_max_time:
    .space 4,0

.global Option_camera_ptr
Option_camera_ptr:
    .space 4,0

.global Sky_land_vertices
Sky_land_vertices:
    .space 4,0

.global From_options
From_options:
    .space 4,0

.global MRSND_number_of_samples
MRSND_number_of_samples:
    .space 4,0

.global Anti_piracy_count
Anti_piracy_count:
    .space 4,0

.global MRRender_peak
MRRender_peak:
    .space 4,0

.global LS_check_mode
LS_check_mode:
    .space 4,0

.global Sel_light_object_0
Sel_light_object_0:
    .space 4,0

.global Memory_card_object_ptr
Memory_card_object_ptr:
    .space 8,0

.global Sel_light_object_1
Sel_light_object_1:
    .space 4,0

.global Sel_light_object_2
Sel_light_object_2:
    .space 4,0

.global Frog_selection_network_request_flags
Frog_selection_network_request_flags:
    .space 4,0

.global Game0_present
Game0_present:
    .space 4,0

.global Card0_present
Card0_present:
    .space 4,0

.global Game1_present
Game1_present:
    .space 4,0

.global Card1_present
Card1_present:
    .space 4,0

.global MRRender_time
MRRender_time:
    .space 4,0

.global LS_message_texture_ptr
LS_message_texture_ptr:
    .space 4,0

.global Game_map
Game_map:
    .space 4,0

.global card_HwEvSpIOE
card_HwEvSpIOE:
    .space 8,0

.global Form_library_ptrs
Form_library_ptrs:
    .space 8,0

.global Sel_loading_sprite_ptr
Sel_loading_sprite_ptr:
    .space 4,0

.global Sel_status_temp_x
Sel_status_temp_x:
    .space 4,0

.global Frog_selection_master_flags
Frog_selection_master_flags:
    .space 4,0

.global MROT_root_ptr
MROT_root_ptr:
    .space 4,0

.global High_score_view_automatic_picked_flag
High_score_view_automatic_picked_flag:
    .space 4,0

.global Game_language
Game_language:
    .space 4,0

.global xa_command_status
xa_command_status:
    .space 4,0

.global MRNumber_of_frames
MRNumber_of_frames:
    .space 4,0

.global card_SwEvSpIOE
card_SwEvSpIOE:
    .space 4,0

.global MRColl_lw_ptr
MRColl_lw_ptr:
    .space 4,0

.global Sel_game_mode
Sel_game_mode:
    .space 4,0

.global card_HwEvSpNEW
card_HwEvSpNEW:
    .space 4,0

.global Map_book
Map_book:
    .space 4,0

.global Sel_mode
Sel_mode:
    .space 4,0

.global Game_map_time
Game_map_time:
    .space 4,0

.global Map_general_header
Map_general_header:
    .space 4,0

.global Race_ptr
Race_ptr:
    .space 4,0

.global card_SwEvSpNEW
card_SwEvSpNEW:
    .space 4,0

.global Demo_data_ptr
Demo_data_ptr:
    .space 4,0

.global MRMouse_pminx
MRMouse_pminx:
    .space 4,0

.global MRMouse_pminy
MRMouse_pminy:
    .space 4,0

.global MRMouse_pmaxx
MRMouse_pmaxx:
    .space 4,0

.global Sel_light_object_a
Sel_light_object_a:
    .space 4,0

.global Map_mof_index
Map_mof_index:
    .space 4,0

.global MRMouse_pmaxy
MRMouse_pmaxy:
    .space 4,0

.global xa_reading_cd
xa_reading_cd:
    .space 4,0

.global Game_paused_finish
Game_paused_finish:
    .space 4,0

.global Sel_spin_mode
Sel_spin_mode:
    .space 4,0

.global xa_param
xa_param:
    .space 8,0

.global Map_group_entity_roots
Map_group_entity_roots:
    .space 4,0

.global Game_multiplayer_play_off_sprite
Game_multiplayer_play_off_sprite:
    .space 4,0

.global MRCd_lock
MRCd_lock:
    .space 4,0

.global Sel_spin_time
Sel_spin_time:
    .space 4,0

.global MRSND_system_options_panning
MRSND_system_options_panning:
    .space 4,0

.global Map_view_xlen
Map_view_xlen:
    .space 4,0

.global Sel_race_level_ptr
Sel_race_level_ptr:
    .space 4,0

.global Sel_level_ptr
Sel_level_ptr:
    .space 4,0

.global Map_view_zlen
Map_view_zlen:
    .space 4,0

.global Sel_glowy_col
Sel_glowy_col:
    .space 4,0

.global Map_path_ptrs
Map_path_ptrs:
    .space 4,0

.global Sel_glowy_dir
Sel_glowy_dir:
    .space 4,0

.global Game_display_width
Game_display_width:
    .space 4,0

.global Map_form_ptrs
Map_form_ptrs:
    .space 4,0

.global High_score_view_water_points_ptr
High_score_view_water_points_ptr:
    .space 4,0

.global Map_view_xnum
Map_view_xnum:
    .space 4,0

.global MRSND_current_ident
MRSND_current_ident:
    .space 4,0

.global MRMouse_up_buttons
MRMouse_up_buttons:
    .space 4,0

.global Option_number
Option_number:
    .space 4,0

.global Map_view_znum
Map_view_znum:
    .space 4,0

.global Map_zone_ptrs
Map_zone_ptrs:
    .space 8,0

.global Map_view_basepoint
Map_view_basepoint:
    .space 8,0

.global Game_total_players
Game_total_players:
    .space 4,0

.global str_old_frame
str_old_frame:
    .space 4,0

.global Sel_start_pos
Sel_start_pos:
    .space 8,0

.global MRTexture_list_ptr
MRTexture_list_ptr:
    .space 8,0

.global Sel_start_vec_roll
Sel_start_vec_roll:
    .space 8,0

.global MRSND_master_volume
MRSND_master_volume:
    .space 4,0

.global MRUser_pc
MRUser_pc:
    .space 4,0

.global Map_numgroups
Map_numgroups:
    .space 4,0

.global Gold_frogs_current
Gold_frogs_current:
    .space 4,0

.global Sel_requested_play
Sel_requested_play:
    .space 4,0

.global Playagain_cc_sprite_ptr
Playagain_cc_sprite_ptr:
    .space 4,0

.global str_file_size
str_file_size:
    .space 4,0

.global Sel_camera_acc
Sel_camera_acc:
    .space 4,0

.global MRFrame_number
MRFrame_number:
    .space 8,0

.global HSView_arrow_sprite_ptr
HSView_arrow_sprite_ptr:
    .space 8,0

.global Frog_model_pieces_polys
Frog_model_pieces_polys:
    .space 4,0

.global Sel_work_level_ptr
Sel_work_level_ptr:
    .space 4,0

.global Game_mode_data
Game_mode_data:
    .space 4,0

.global Game_mode
Game_mode:
    .space 4,0

.global Playagain_pa_sprite_ptr
Playagain_pa_sprite_ptr:
    .space 4,0

.global MRMouse_x
MRMouse_x:
    .space 4,0

.global MRMouse_y
MRMouse_y:
    .space 8,0

.global LS_extras_mesh_inst_ptr
LS_extras_mesh_inst_ptr:
    .space 8,0

.global num_of_swarms
num_of_swarms:
    .space 4,0

.global LS_card_number
LS_card_number:
    .space 4,0

.global LS_select_mode
LS_select_mode:
    .space 4,0

.global Playagain_ex_sprite_ptr
Playagain_ex_sprite_ptr:
    .space 4,0

.global Game_map_theme
Game_map_theme:
    .space 4,0

.global Game_viewport0
Game_viewport0:
    .space 4,0

.global Game_viewport1
Game_viewport1:
    .space 4,0

.global MRDefault_font_info
MRDefault_font_info:
    .space 4,0

.global MRNumber_of_objects
MRNumber_of_objects:
    .space 4,0

.global Game_viewport2
Game_viewport2:
    .space 4,0

.global Game_viewport3
Game_viewport3:
    .space 4,0

.global LS_delay_timer
LS_delay_timer:
    .space 4,0

.global MRSND_moving_sound_count
MRSND_moving_sound_count:
    .space 4,0

.global Demo_time
Demo_time:
    .space 4,0

.global Sel_status_start_x
Sel_status_start_x:
    .space 4,0

.global Map_anims
Map_anims:
    .space 4,0

.global Sel_camera_vel
Sel_camera_vel:
    .space 8,0

.global MRColl_transpt
MRColl_transpt:
    .space 8,0

.global HSView_counter
HSView_counter:
    .space 4,0

.global Frog_selection_request_flags
Frog_selection_request_flags:
    .space 4,0

.global High_score_view_frog_anim_env_ptr
High_score_view_frog_anim_env_ptr:
    .space 4,0

.global Grid_xlen
Grid_xlen:
    .space 4,0

.global Game_map_timer
Game_map_timer:
    .space 4,0

.global Game_map_timer_frac
Game_map_timer_frac:
    .space 4,0

.global Grid_zlen
Grid_zlen:
    .space 4,0

.global LS_memory_card_rotation1
LS_memory_card_rotation1:
    .space 2,0

.global LS_memory_card_rotation2
LS_memory_card_rotation2:
    .space 2,0

.global Select_bg_xlen
Select_bg_xlen:
    .space 4,0

.global Select_bg_ylen
Select_bg_ylen:
    .space 4,0

.global Sel_title
Sel_title:
    .space 4,0

.global Any_high_score
Any_high_score:
    .space 4,0

.global MRSND_cd_volume
MRSND_cd_volume:
    .space 4,0

.global New_high_score
New_high_score:
    .space 4,0

.global Sel_count
Sel_count:
    .space 4,0

.global Sel_spin_frame
Sel_spin_frame:
    .space 4,0

.global Sel_dest_vec_y
Sel_dest_vec_y:
    .space 8,0

.global Grid_xnum
Grid_xnum:
    .space 4,0

.global MRAnim_env_root_ptr
MRAnim_env_root_ptr:
    .space 4,0

.global Grid_znum
Grid_znum:
    .space 4,0

.global Game_display_height
Game_display_height:
    .space 4,0

.global Select_bg_direction
Select_bg_direction:
    .space 4,0

.global Select_bg_xnum
Select_bg_xnum:
    .space 4,0

.global Sel_camera_y_offset
Sel_camera_y_offset:
    .space 4,0

.global Game_last_map_timer
Game_last_map_timer:
    .space 4,0

.global Select_bg_ynum
Select_bg_ynum:
    .space 4,0

.global MRSND_number_of_vabs
MRSND_number_of_vabs:
    .space 4,0

.global MRNumber_of_OTs
MRNumber_of_OTs:
    .space 4,0

.global High_score_matrices
High_score_matrices:
    .space 4,0

.global Sel_first_time
Sel_first_time:
    .space 4,0

.global xa_filter
xa_filter:
    .space 4,0

.global xa_change_list
xa_change_list:
    .space 4,0

.global MRSND_fx_volume
MRSND_fx_volume:
    .space 4,0

.global MRMouse_old_buttons
MRMouse_old_buttons:
    .space 4,0

.global xa_endpos
xa_endpos:
    .space 4,0

.global Game_viewportc
Game_viewportc:
    .space 4,0

.global Start_ptr
Start_ptr:
    .space 4,0

.global Map_vertex_min
Map_vertex_min:
    .space 8,0

.global str_frame
str_frame:
    .space 8,0

.global Map_vertex_max
Map_vertex_max:
    .space 8,0

.global Game_continues_left
Game_continues_left:
    .space 4,0

.global Game_viewporth
Game_viewporth:
    .space 4,0

.global card_HwEvSpERROR
card_HwEvSpERROR:
    .space 4,0

.global MRMouse_new_buttons
MRMouse_new_buttons:
    .space 4,0

.global Demo_data_input_ptr
Demo_data_input_ptr:
    .space 4,0

.global Recording_demo_text_area
Recording_demo_text_area:
    .space 4,0

.global str_video
str_video:
    .space 4,0

.global LS_title_sprite_pos
LS_title_sprite_pos:
    .space 4,0

.global Sel_spin_backup_ptr
Sel_spin_backup_ptr:
    .space 4,0

.global card_SwEvSpERROR
card_SwEvSpERROR:
    .space 4,0

.global LS_title_sprite_ptr
LS_title_sprite_ptr:
    .space 4,0

.global xa_looped_play
xa_looped_play:
    .space 4,0

.global xa_result
xa_result:
    .space 8,0

.global xa_requested_change
xa_requested_change:
    .space 4,0

.global MRSND_group_info_ptr
MRSND_group_info_ptr:
    .space 4,0

.global Options_update_mode
Options_update_mode:
    .space 4,0

.global MRSND_viewports
MRSND_viewports:
    .space 4,0

.global Pad_user_prompt_text_instptr
Pad_user_prompt_text_instptr:
    .space 4,0

.global Option_page_current
Option_page_current:
    .space 4,0

.global MRTexture_block_root_ptr
MRTexture_block_root_ptr:
    .space 4,0

.global MRViewport_root_ptr
MRViewport_root_ptr:
    .space 4,0

.global MRMouse_dx
MRMouse_dx:
    .space 4,0

.global Option_spcore_index
Option_spcore_index:
    .space 4,0

.global MRMouse_dy
MRMouse_dy:
    .space 4,0

.global Map_header
Map_header:
    .space 4,0

.global Option_page_request
Option_page_request:
    .space 4,0

.global Game_flags
Game_flags:
    .space 4,0

.global Game_cheat_mode
Game_cheat_mode:
    .space 4,0

.global Option_spcore_value
Option_spcore_value:
    .space 4,0

.global Game_debug_mode
Game_debug_mode:
    .space 4,0

.global MRFont_data_ptr
MRFont_data_ptr:
    .space 4,0

.global Sel_glowy_level_ptr
Sel_glowy_level_ptr:
    .space 4,0

.global LS_message_mode
LS_message_mode:
    .space 4,0

.global MRListed_meshes
MRListed_meshes:
    .space 4,0

.global Map_anim_header
Map_anim_header:
    .space 4,0

.global MRMouse_px
MRMouse_px:
    .space 4,0

.global Map_grid_header
Map_grid_header:
    .space 4,0

.global MRMouse_py
MRMouse_py:
    .space 4,0

.global MRFont_buff_ptr
MRFont_buff_ptr:
    .space 4,0
