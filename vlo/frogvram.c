
// frogvram.c - FrogLord Export Frogger PSX Retail [NTSC, SLUS-00506] (1997-09-23) (psx-retail-usa)
// This file contains texture definitions generated from the game. Must be accompanied by texmacro.h generated from the ghidra script.

#include "frogvram.h"

MR_TEXTURE* bmp_pointers[] = {
	&im_img0, &im_img1, &im_img2, &im_img3, &im_img4, &im_img5, &im_img6, &im_img7, &im_img8, &im_img9, &im_img10, &im_img11, &im_img12, &im_img13, &im_img14, &im_img15,
	&im_img16, &im_img17, &im_img18, &im_img19, &im_img20, &im_img21, &im_img22, &im_img23, &im_img24, &im_img25, &im_img26, &im_img27, &im_img28, &im_img29, &im_img30, &im_img31,
	&im_for_swarm, &im_img33, &im_img34, &im_img35, &im_img36, &im_img37, &im_img38, &im_img39, &im_img40, &im_img41, &im_img42, &im_img43, &im_img44, &im_img45, &im_img46, &im_img47,
	&im_img48, &im_img49, &im_img50, &im_img51, &im_img52, &im_img53, &im_img54, &im_img55, &im_img56, &im_img57, &im_img58, &im_img59, &im_img60, &im_img61, &im_img62, &im_img63,
	&im_img64, &im_img65, &im_img66, &im_tongue_tip, &im_dbugfont, &im_fire_fly, &im_fire_flya, &im_fly_10, &im_fly_100, &im_fly_1000, &im_fly_1000a, &im_fly_100a, &im_fly_10a, &im_fly_200, &im_fly_200a, &im_fly_25,
	&im_fly_25a, &im_fly_50, &im_fly_500, &im_fly_5000, &im_fly_5000a, &im_fly_500a, &im_fly_50a, &im_fly_bad, &im_fly_bada, &im_quick_jump, &im_super_tongue, &im_time_max, &im_time_maxa, &im_time_med, &im_time_meda, &im_time_min,
	&im_time_mina, &im_auto_jump, &im_gen_shadow, &im_32x32_9, &im_32x32_1, &im_32x32_2, &im_32x32_3, &im_32x32_4, &im_32x32_5, &im_32x32_6, &im_32x32_7, &im_32x32_8, &im_32x32_0, &im_score_10, &im_score_100, &im_score_150,
	&im_score_200, &im_score_250, &im_score_50, &im_score_500, &im_score_75, &im_img117, &im_img118, &im_img119, &im_img120, &im_img121, &im_img122, &im_img123, &im_img124, &im_img125, &im_img126, &im_img127,
	&im_img128, &im_img129, &im_img130, &im_img131, &im_img132, &im_img133, &im_img134, &im_img135, &im_img136, &im_img137, &im_img138, &im_img139, &im_img140, &im_img141, &im_img142, &im_img143,
	&im_img144, &im_img145, &im_img146, &im_img147, &im_img148, &im_img149, &im_img150, &im_img151, &im_img152, &im_img153, &im_img154, &im_img155, &im_img156, &im_img157, &im_img158, &im_wake2,
	&im_img160, &im_img161, &im_babyfrog5_6, &im_babyfrog1_1, &im_babyfrog1_2, &im_babyfrog1_3, &im_babyfrog1_4, &im_babyfrog1_5, &im_babyfrog1_6, &im_babyfrog2_0, &im_babyfrog2_1, &im_babyfrog2_2, &im_babyfrog2_3, &im_babyfrog2_4, &im_babyfrog2_5, &im_babyfrog2_6,
	&im_babyfrog3_0, &im_babyfrog3_1, &im_babyfrog3_2, &im_babyfrog3_3, &im_babyfrog3_4, &im_babyfrog3_5, &im_babyfrog3_6, &im_babyfrog4_0, &im_babyfrog4_1, &im_babyfrog4_2, &im_babyfrog4_3, &im_babyfrog4_4, &im_babyfrog4_5, &im_babyfrog4_6, &im_babyfrog5_0, &im_babyfrog5_1,
	&im_babyfrog5_2, &im_babyfrog5_3, &im_babyfrog5_4, &im_babyfrog5_5, &im_babyfrog1_0, &im_des1pic, &im_des2pic, &im_org1pic, &im_sub1pic, &im_img201, &im_img202, &im_img203, &im_img204, &im_img205, &im_img206, &im_img207,
	&im_img208, &im_img209, &im_img210, &im_img211, &im_img212, &im_img213, &im_img214, &im_img215, &im_img216, &im_img217, &im_img218, &im_img219, &im_img220, &im_img221, &im_img222, &im_img223,
	&im_img224, &im_img225, &im_img226, &im_img227, &im_img228, &im_img229, &im_img230, &im_img231, &im_img232, &im_img233, &im_img234, &im_img235, &im_img236, &im_img237, &im_img238, &im_img239,
	&im_img240, &im_img241, &im_img242, &im_img243, &im_img244, &im_img245, &im_img246, &im_img247, &im_img248, &im_gatso, &im_cav1pic, &im_des3pic, &im_des4pic, &im_des5pic, &im_for1pic, &im_for2pic,
	&im_jun1pic, &im_org2pic, &im_org3pic, &im_org4pic, &im_org5pic, &im_select1, &im_select2, &im_sky1pic, &im_sky2pic, &im_sky3pic, &im_sky4pic, &im_sub2pic, &im_sub3pic, &im_sub4pic, &im_sub5pic, &im_swp1pic,
	&im_swp2pic, &im_swp3pic, &im_swp4pic, &im_swp5pic, &im_vol1pic, &im_vol2pic, &im_vol3pic, &im_img279, &im_img280, &im_img281, &im_img282, &im_img283, &im_img284, &im_img285, &im_img286, &im_img287,
	&im_img288, &im_img289, &im_img290, &im_img291, &im_img292, &im_img293, &im_img294, &im_img295, &im_img296, &im_img297, &im_img298, &im_img299, &im_img300, &im_img301, &im_img302, &im_img303,
	&im_img304, &im_img305, &im_img306, &im_img307, &im_img308, &im_img309, &im_img310, &im_img311, &im_org_splash_2, &im_org_splash_0, &im_org_splash_1, &im_img315, &im_img316, &im_img317, &im_img318, &im_img319,
	&im_img320, &im_img321, &im_img322, &im_img323, &im_img324, &im_img325, &im_img326, &im_img327, &im_img328, &im_img329, &im_img330, &im_img331, &im_img332, &im_img333, &im_img334, &im_org_log,
	&im_img336, &im_img337, &im_img338, &im_img339, &im_img340, &im_sky_balloon_env, &im_img342, &im_img343, &im_img344, &im_img345, &im_img346, &im_img347, &im_img348, &im_img349, &im_img350, &im_img351,
	&im_vol_tile51, &im_img353, &im_img354, &im_img355, &im_img356, &im_img357, &im_img358, &im_img359, &im_score_5000, &im_score_1000, &im_score_25, &im_sub_env_sky, &im_org_env_sky, &im_img365, &im_img366, &im_img367,
	&im_img368, &im_img369, &im_img370, &im_img371, &im_img372, &im_img373, &im_img374, &im_img375, &im_img376, &im_img377, &im_img378, &im_img379, &im_img380, &im_img381, &im_img382, &im_img383,
	&im_img384, &im_img385, &im_img386, &im_img387, &im_img388, &im_img389, &im_img390, &im_img391, &im_hi_back, &im_img393, &im_img394, &im_img395, &im_img396, &im_img397, &im_img398, &im_img399,
	&im_img400, &im_img401, &im_img402, &im_img403, &im_img404, &im_img405, &im_img406, &im_img407, &im_img408, &im_img409, &im_img410, &im_img411, &im_img412, &im_img413, &im_img414, &im_img415,
	&im_img416, &im_img417, &im_img418, &im_img419, &im_img420, &im_img421, &im_img422, &im_img423, &im_img424, &im_img425, &im_img426, &im_img427, &im_img428, &im_img429, &im_img430, &im_img431,
	&im_img432, &im_img433, &im_img434, &im_img435, &im_img436, &im_img437, &im_img438, &im_img439, &im_img440, &im_img441, &im_img442, &im_img443, &im_img444, &im_img445, &im_img446, &im_img447,
	&im_img448, &im_img449, &im_img450, &im_img451, &im_img452, &im_img453, &im_img454, &im_img455, &im_img456, &im_img457, &im_img458, &im_img459, &im_img460, &im_img461, &im_img462, &im_img463,
	&im_img464, &im_img465, &im_img466, &im_img467, &im_img468, &im_img469, &im_img470, &im_img471, &im_img472, &im_img473, &im_img474, &im_img475, &im_img476, &im_img477, &im_opt_env_sky, &im_img479,
	&im_newfont, &im_opt_arrow, &im_img482, &im_img483, &im_img484, &im_img485, &im_img486, &im_img487, &im_img488, &im_img489, &im_img490, &im_img491, &im_img492, &im_img493, &im_img494, &im_img495,
	&im_img496, &im_img497, &im_img498, &im_img499, &im_img500, &im_img501, &im_img502, &im_img503, &im_img504, &im_img505, &im_img506, &im_img507, &im_img508, &im_img509, &im_img510, &im_img511,
	&im_img512, &im_img513, &im_img514, &im_img515, &im_img516, &im_img517, &im_img518, &im_img519, &im_img520, &im_img521, &im_img522, &im_img523, &im_img524, &im_img525, &im_img526, &im_img527,
	&im_img528, &im_img529, &im_img530, &im_img531, &im_img532, &im_img533, &im_img534, &im_img535, &im_img536, &im_img537, &im_img538, &im_img539, &im_img540, &im_img541, &im_img542, &im_img543,
	&im_img544, &im_img545, &im_img546, &im_img547, &im_img548, &im_img549, &im_img550, &im_img551, &im_img552, &im_img553, &im_img554, &im_img555, &im_img556, &im_img557, &im_img558, &im_img559,
	&im_img560, &im_img561, &im_img562, &im_img563, &im_img564, &im_img565, &im_img566, &im_img567, &im_img568, &im_img569, &im_img570, &im_img571, &im_img572, &im_img573, &im_img574, &im_img575,
	&im_img576, &im_img577, &im_img578, &im_img579, &im_img580, &im_img581, &im_img582, &im_img583, &im_img584, &im_img585, &im_img586, &im_img587, &im_img588, &im_img589, &im_img590, &im_img591,
	&im_img592, &im_img593, &im_img594, &im_img595, &im_img596, &im_img597, &im_img598, &im_img599, &im_img600, &im_img601, &im_img602, &im_img603, &im_img604, &im_img605, &im_img606, &im_img607,
	&im_img608, &im_img609, &im_img610, &im_img611, &im_img612, &im_img613, &im_img614, &im_img615, &im_img616, &im_img617, &im_img618, &im_img619, &im_img620, &im_img621, &im_img622, &im_img623,
	&im_img624, &im_img625, &im_img626, &im_img627, &im_img628, &im_img629, &im_img630, &im_img631, &im_img632, &im_img633, &im_img634, &im_img635, &im_img636, &im_img637, &im_img638, &im_img639,
	&im_img640, &im_img641, &im_img642, &im_img643, &im_img644, &im_img645, &im_img646, &im_img647, &im_img648, &im_img649, &im_img650, &im_img651, &im_img652, &im_img653, &im_img654, &im_img655,
	&im_img656, &im_img657, &im_img658, &im_img659, &im_img660, &im_img661, &im_img662, &im_img663, &im_img664, &im_img665, &im_img666, &im_img667, &im_img668, &im_img669, &im_img670, &im_ripple_tim6,
	&im_ripple_tim2, &im_ripple_tim3, &im_ripple_tim4, &im_ripple_tim5, &im_ripple_tim1, &im_img677, &im_img678, &im_img679, &im_img680, &im_img681, &im_img682, &im_img683, &im_img684, &im_img685, &im_img686, &im_img687,
	&im_img688, &im_img689, &im_img690, &im_img691, &im_img692, &im_img693, &im_img694, &im_lives_bg5, &im_lifes2, &im_lifes3, &im_lifes4, &im_lifes5, &im_lives_bg1, &im_lives_bg2, &im_lives_bg3, &im_lives_bg4,
	&im_lifes1, &im_hop_to_it_f, &im_hop_to_it_s, &im_hop_to_it_i, &im_hop_to_it_g, &im_go_frogger_s, &im_go_frogger_g, &im_go_frogger_i, &im_go_frogger_f, &im_go_s, &im_go_g, &im_go_i, &im_go_f, &im_go_get_em_s, &im_go_get_em_g, &im_go_get_em_i,
	&im_go_get_em_f, &im_jump_to_it_s, &im_jump_to_it_f, &im_jump_to_it_g, &im_jump_to_it_i, &im_optf_yes, &im_optg_no, &im_optg_yes, &im_opti_no, &im_opti_yes, &im_opts_no, &im_opts_yes, &im_optf_no, &im_zone_complete_g, &im_zone_complete_f, &im_zone_complete_i,
	&im_zone_complete_s, &im_next_s, &im_next_g, &im_next_i, &im_next_f, &im_bonus_s, &im_bonus_g, &im_bonus_i, &im_bonus_f, &im_total_time_s, &im_total_time_g, &im_total_time_i, &im_total_time_f, &im_total_score_f, &im_total_score_g, &im_total_score_i,
	&im_total_score_s, &im_opts_paused, &im_optg_paused, &im_opti_paused, &im_optf_paused, &im_quit_g, &im_quit_i, &im_quit_s, &im_quit_f, &im_croak_s, &im_croak_f, &im_croak_g, &im_croak_i, &im_select2_s, &im_select1_g, &im_select1_i,
	&im_select1_s, &im_select2_f, &im_select2_g, &im_select2_i, &im_select1_f, &im_opts_start, &im_optf_race, &im_optf_start, &im_optg_options, &im_optg_race, &im_optg_start, &im_opti_options, &im_opti_race, &im_opti_start, &im_opts_options, &im_opts_race,
	&im_optf_options, &im_img785, &im_img786, &im_img787, &im_img788, &im_img789, &im_img790, &im_img791, &im_img792, &im_img793, &im_img794, &im_skip_hi_score_f, &im_press_fire_f, &im_press_fire_g, &im_press_fire_i, &im_optf_insert_pad,
	&im_optf_ctrl_config, &im_optf_exit, &im_optf_format, &im_optf_check_save, &im_optf_load_hs, &im_optf_load_ok, &im_optf_no_cards, &im_optf_no_space, &im_optf_overwrite, &im_optf_return, &im_optf_save_hs, &im_optf_save_ok, &im_optf_select_card, &im_optf_view_hs, &im_optg_insert_pad, &im_optg_ctrl_config,
	&im_optg_exit, &im_optg_format, &im_optg_check_save, &im_optg_load_hs, &im_optg_load_ok, &im_optg_no_cards, &im_optg_no_space, &im_optg_overwrite, &im_optg_return, &im_optg_save_hs, &im_optg_save_ok, &im_optg_select_card, &im_optg_view_hs, &im_skip_hi_score_g, &im_opti_insert_pad, &im_opti_ctrl_config,
	&im_opti_exit, &im_opti_format, &im_opti_check_save, &im_opti_load_hs, &im_opti_load_ok, &im_opti_no_cards, &im_opti_no_space, &im_opti_overwrite, &im_opti_return, &im_opti_save_hs, &im_opti_save_ok, &im_opti_select_card, &im_opti_view_hs, &im_skip_hi_score_i, &im_opts_insert_pad, &im_opts_ctrl_config,
	&im_opts_exit, &im_opts_format, &im_opts_check_save, &im_opts_load_hs, &im_opts_load_ok, &im_opts_no_cards, &im_opts_no_space, &im_opts_overwrite, &im_opts_return, &im_opts_save_hs, &im_opts_save_ok, &im_opts_select_card, &im_opts_view_hs, &im_skip_hi_score_s, &im_img862, &im_img863,
	&im_img864, &im_img865, &im_img866, &im_img867, &im_img868, &im_img869, &im_img870, &im_img871, &im_img872, &im_img873, &im_img874, &im_img875, &im_img876, &im_img877, &im_img878, &im_img879,
	&im_img880, &im_img881, &im_img882, &im_img883, &im_img884, &im_img885, &im_img886, &im_img887, &im_img888, &im_img889, &im_img890, &im_img891, &im_img892, &im_img893, &im_img894, &im_img895,
	&im_img896, &im_img897, &im_img898, &im_img899, &im_img900, &im_img901, &im_img902, &im_img903, &im_img904, &im_img905, &im_img906, &im_img907, &im_img908, &im_img909, &im_img910, &im_img911,
	&im_img912, &im_opt_turtle_1, &im_img914, &im_img915, &im_img916, &im_img917, &im_img918, &im_img919, &im_img920, &im_img921, &im_img922, &im_img923, &im_img924, &im_img925, &im_img926, &im_img927,
	&im_img928, &im_img929, &im_img930, &im_img931, &im_img932, &im_img933, &im_img934, &im_img935, &im_img936, &im_img937, &im_img938, &im_img939, &im_cav4pic, &im_vol_grey, &im_cav_grey, &im_des_col,
	&im_des_grey, &im_for_col, &im_for_grey, &im_jun_col, &im_jun_grey, &im_org_col, &im_org_grey, &im_sky_col, &im_sky_grey, &im_sub_col, &im_sub_grey, &im_swp_col, &im_swp_grey, &im_vol_col, &im_cav_col, &im_img959,
	&im_img960, &im_img961, &im_img962, &im_img963, &im_img964, &im_img965, &im_img966, &im_img967, &im_img968, &im_img969, &im_img970, &im_img971, &im_img972, &im_img973, &im_img974, &im_img975,
	&im_img976, &im_img977, &im_img978, &im_img979, &im_img980, &im_img981, &im_img982, &im_img983, &im_img984, &im_img985, &im_img986, &im_img987, &im_img988, &im_img989, &im_img990, &im_img991,
	&im_img992, &im_img993, &im_fire_fly_fata, &im_fire_fly_fat, &im_img996, &im_img997, &im_img998, &im_img999, &im_img1000, &im_img1001, &im_img1002, &im_img1003, &im_img1004, &im_img1005, &im_img1006, &im_img1007,
	&im_img1008, &im_img1009, &im_img1010, &im_img1011, &im_img1012, &im_img1013, &im_img1014, &im_img1015, &im_img1016, &im_img1017, &im_img1018, &im_img1019, &im_img1020, &im_img1021, &im_img1022, &im_img1023,
	&im_img1024, &im_img1025, &im_img1026, &im_img1027, &im_img1028, &im_img1029, &im_img1030, &im_img1031, &im_img1032, &im_img1033, &im_img1034, &im_img1035, &im_img1036, &im_img1037, &im_img1038, &im_img1039,
	&im_img1040, &im_img1041, &im_img1042, &im_img1043, &im_img1044, &im_img1045, &im_img1046, &im_img1047, &im_img1048, &im_img1049, &im_img1050, &im_img1051, &im_img1052, &im_babyfroggold_0, &im_babyfroggold_1, &im_babyfroggold_2,
	&im_babyfroggold_3, &im_babyfroggold_4, &im_babyfroggold_5, &im_babyfroggold_6, &im_flag1_0, &im_flag1_1, &im_flag1_2, &im_flag1_3, &im_flag1_4, &im_flag2_0, &im_flag2_1, &im_flag2_2, &im_flag2_3, &im_flag2_4, &im_flag3_0, &im_flag3_1,
	&im_flag3_2, &im_flag3_3, &im_flag3_4, &im_flag4_0, &im_flag4_1, &im_flag4_2, &im_flag4_3, &im_flag4_4, &im_flag5_0, &im_flag5_1, &im_flag5_2, &im_flag5_3, &im_flag5_4, &im_img1085, &im_img1086, &im_img1087,
	&im_img1088, &im_img1089, &im_img1090, &im_img1091, &im_img1092, &im_img1093, &im_img1094, &im_ls_gold_frog, &im_jump_to_it, &im_croak, &im_go, &im_go_frogger, &im_go_get_em, &im_hop_to_it, &im_quit, &im_timeout,
	&im_total_score, &im_total_time, &im_zone_complete, &im_opt_no, &im_opt_options, &im_opt_paused, &im_opt_start, &im_opt_yes, &im_next, &im_opt_load_hs_sm, &im_opt_ctrl_config, &im_opt_exit, &im_opt_format, &im_opt_format2, &im_opt_insert_pad, &im_opt_load_hs,
	&im_opt_check_save, &im_opt_load_ok, &im_opt_no_cards, &im_opt_no_space, &im_opt_overwrite, &im_opt_return, &im_opt_save_hs, &im_opt_save_ok, &im_opt_select_card, &im_opt_view_hs, &im_skip_hi_score, &im_opt_gameover, &im_timeout_s, &im_timeout_g, &im_timeout_i, &im_timeout_f,
	&im_img1136, &im_img1137, &im_img1138, &im_img1139, &im_img1140, &im_img1141, &im_img1142, &im_img1143, &im_img1144, &im_img1145, &im_img1146, &im_img1147, &im_img1148, &im_img1149, &im_img1150, &im_img1151,
	&im_img1152, &im_img1153, &im_img1154, &im_img1155, &im_opt_no_data, &im_press_fire_s, &im_bonus, &im_mem_message, &im_select_level, &im_volmpic, &im_orgmpic, &im_submpic, &im_formpic, &im_junmpic, &im_img1166, &im_frog_shadow1,
	&im_frog_shadow2, &im_frog_shadow0, &im_img1170, &im_img1171, &im_img1172, &im_img1173, &im_img1174, &im_img1175, &im_img1176, &im_img1177, &im_img1178, &im_img1179, &im_img1180, &im_img1181, &im_img1182, &im_img1183,
	&im_img1184, &im_img1185, &im_img1186, &im_img1187, &im_img1188, &im_img1189, &im_img1190, &im_img1191, &im_img1192, &im_img1193, &im_img1194, &im_img1195, &im_img1196, &im_img1197, &im_img1198, &im_img1199,
	&im_img1200, &im_img1201, &im_img1202, &im_img1203, &im_img1204, &im_img1205, &im_img1206, &im_img1207, &im_img1208, &im_img1209, &im_img1210, &im_img1211, &im_img1212, &im_img1213, &im_img1214, &im_img1215,
	&im_img1216, &im_32x32_colon, &im_cav3pic, &im_mem_message_s, &im_mem_message_g, &im_mem_message_i, &im_mem_message_f, &im_opt_save_failed, &im_opt_load_failed, &im_opt_format_failed, &im_optf_save_failed, &im_optf_load_failed, &im_optf_format_failed, &im_optg_save_failed, &im_optg_load_failed, &im_optg_format_failed,
	&im_opti_save_failed, &im_opti_load_failed, &im_opti_format_failed, &im_opts_save_failed, &im_opts_load_failed, &im_opts_format_failed, &im_optf_no_data, &im_optg_no_data, &im_opti_no_data, &im_opts_no_data, &im_img1242, &im_img1243, &im_img1244, &im_img1245, &im_img1246, &im_img1247,
	&im_img1248, &im_img1249, &im_img1250, &im_img1251, &im_img1252, &im_img1253, &im_img1254, &im_img1255, &im_img1256, &im_img1257, &im_img1258, &im_img1259, &im_img1260, &im_img1261, &im_img1262, &im_img1263,
	&im_img1264, &im_img1265, &im_img1266, &im_img1267, &im_img1268, &im_img1269, &im_img1270, &im_img1271, &im_img1272, &im_img1273, &im_img1274, &im_img1275, &im_img1276, &im_img1277, &im_img1278, &im_img1279,
	&im_img1280, &im_img1281, &im_img1282, &im_img1283, &im_img1284, &im_img1285, &im_img1286, &im_img1287, &im_img1288, &im_img1289, &im_img1290, &im_img1291, &im_img1292, &im_img1293, &im_img1294, &im_img1295,
	&im_img1296, &im_img1297, &im_img1298, &im_img1299, &im_img1300, &im_img1301, &im_img1302, &im_img1303, &im_img1304, &im_img1305, &im_img1306, &im_img1307, &im_img1308, &im_img1309, &im_img1310, &im_img1311,
	&im_img1312, &im_img1313, &im_img1314, &im_img1315, &im_img1316, &im_img1317, &im_img1318, &im_img1319, &im_img1320, &im_img1321, &im_img1322, &im_img1323, &im_img1324, &im_img1325, &im_img1326, &im_img1327,
	&im_img1328, &im_img1329, &im_img1330, &im_img1331, &im_img1332, &im_img1333, &im_img1334, &im_img1335, &im_img1336, &im_img1337, &im_img1338, &im_img1339, &im_img1340, &im_img1341, &im_img1342, &im_img1343,
	&im_img1344, &im_img1345, &im_img1346, &im_img1347, &im_img1348, &im_img1349, &im_img1350, &im_img1351, &im_img1352, &im_img1353, &im_img1354, &im_img1355, &im_img1356, &im_img1357, &im_jun_floor1, &im_img1359,
	&im_img1360, &im_img1361, &im_img1362, &im_img1363, &im_img1364, &im_img1365, &im_img1366, &im_img1367, &im_img1368, &im_img1369, &im_img1370, &im_img1371, &im_img1372, &im_img1373, &im_img1374, &im_img1375,
	&im_img1376, &im_img1377, &im_img1378, &im_img1379, &im_img1380, &im_img1381, &im_img1382, &im_img1383, &im_1up1, &im_img1385, &im_img1386, &im_img1387, &im_img1388, &im_img1389, &im_img1390, &im_img1391,
	&im_img1392, &im_img1393, &im_img1394, &im_img1395, &im_img1396, &im_img1397, &im_img1398, &im_img1399, &im_img1400, &im_img1401, &im_img1402, &im_img1403, &im_img1404, &im_img1405, &im_img1406, &im_img1407,
	&im_img1408, &im_img1409, &im_img1410, &im_img1411, &im_img1412, &im_img1413, &im_img1414, &im_img1415, &im_img1416, &im_img1417, &im_img1418, &im_img1419, &im_img1420, &im_img1421, &im_img1422, &im_img1423,
	&im_img1424, &im_opt_arrow_small_right, &im_opt_arrow_small_left, &im_opt_bank3, &im_opt_joypad, &im_opt_joypad_layout4, &im_opt_joypad_layout2, &im_opt_joypad_layout3, &im_opt_joypad_layout1, &im_img1433, &im_img1434, &im_img1435, &im_img1436, &im_img1437, &im_img1438, &im_img1439,
	&im_img1440, &im_img1441, &im_optf_joypad_layout4, &im_optf_joypad_layout2, &im_optf_joypad_layout3, &im_optf_joypad_layout1, &im_optg_joypad_layout4, &im_optg_joypad_layout2, &im_optg_joypad_layout3, &im_optg_joypad_layout1, &im_opti_joypad_layout4, &im_opti_joypad_layout2, &im_opti_joypad_layout3, &im_opti_joypad_layout1, &im_opts_joypad_layout4, &im_opts_joypad_layout2,
	&im_opts_joypad_layout3, &im_opts_joypad_layout1, &im_img1458, &im_opt_menu_cloud, &im_img1460, &im_img1461, &im_img1462, &im_img1463, &im_img1464, &im_img1465, &im_img1466, &im_img1467, &im_img1468, &im_img1469, &im_img1470, &im_img1471,
	&im_img1472, &im_img1473, &im_bison6, &im_bison2, &im_bison3, &im_bison4, &im_bison5, &im_bison1, &im_img1480, &im_img1481, &im_img1482, &im_img1483, &im_img1484, &im_img1485, &im_won, &im_lost,
	&im_play_again, &im_played, &im_choose_course, &im_won_f, &im_lost_f, &im_play_again_f, &im_played_f, &im_choose_course_f, &im_won_g, &im_lost_g, &im_play_again_g, &im_played_g, &im_choose_course_g, &im_won_i, &im_lost_i, &im_play_again_i,
	&im_played_i, &im_choose_course_i, &im_won_s, &im_lost_s, &im_play_again_s, &im_played_s, &im_choose_course_s, &im_extra_life5, &im_extra_life2, &im_extra_life3, &im_extra_life4, &im_extra_life1, &im_time_bada, &im_time_bad, &im_img1518, &im_img1519,
	&im_img1520, &im_img1521, &im_img1522, &im_img1523, &im_img1524, &im_img1525, &im_img1526, &im_img1527, &im_time_plus5, &im_time_plus10, &im_time_plus2, &im_score_minus500, &im_img1532, &im_img1533, &im_img1534, &im_img1535,
	&im_img1536, &im_img1537, &im_img1538, &im_img1539, &im_img1540, &im_img1541, &im_img1542, &im_img1543, &im_img1544, &im_img1545, &im_select3, &im_select3_f, &im_select3_g, &im_select3_i, &im_select3_s, &im_start_race,
	&im_start_race_f, &im_start_race_g, &im_start_race_i, &im_start_race_s, &im_img1556, &im_img1557, &im_img1558, &im_img1559, &im_img1560, &im_img1561, &im_img1562, &im_img1563, &im_img1564, &im_img1565, &im_img1566, &im_img1567,
	&im_img1568, &im_sel_loading, &im_self_loading, &im_selg_loading, &im_seli_loading, &im_sels_loading, &im_optf_format2, &im_optg_format2, &im_opti_format2, &im_opts_format2, &im_opt_big_continue, &im_optf_big_continue, &im_optg_big_continue, &im_opti_big_continue, &im_opts_big_continue, &im_opt_now_saving,
	&im_opt_now_formatting, &im_opt_now_loading, &im_opt_now_checking, &im_optf_now_saving, &im_optf_now_formatting, &im_optf_now_loading, &im_optf_now_checking, &im_optg_now_saving, &im_optg_now_formatting, &im_optg_now_loading, &im_optg_now_checking, &im_opti_now_saving, &im_opti_now_formatting, &im_opti_now_loading, &im_opti_now_checking, &im_opts_now_saving,
	&im_opts_now_formatting, &im_opts_now_loading, &im_opts_now_checking, &im_img1603, &im_multback, &im_img1605, &im_img1606, &im_img1607, &im_frog_smoke1, &im_img1609, &im_img1610, &im_img1611, &im_img1612, &im_img1613, &im_img1614, &im_img1615,
	&im_img1616, &im_img1617, &im_img1618, &im_img1619, &im_vol1name, &im_vol2name, &im_vol3name, &im_volmname, &im_des5name, &im_des2name, &im_des3name, &im_des4name, &im_des1name, &im_sky4name, &im_sky2name, &im_sky3name,
	&im_sky1name, &im_formname, &im_for2name, &im_for1name, &im_jun1name, &im_junmname, &im_cav4name, &im_cav3name, &im_cav1name, &im_submname, &im_sub2name, &im_sub3name, &im_sub4name, &im_sub5name, &im_sub1name, &im_orgmname,
	&im_org2name, &im_org3name, &im_org4name, &im_org5name, &im_org1name, &im_swp4name, &im_swp2name, &im_swp3name, &im_swp1name, &im_med_9, &im_med_1, &im_med_2, &im_med_3, &im_med_4, &im_med_5, &im_med_7,
	&im_med_8, &im_med_0, &im_med_6, &im_swp5name, &im_img1668, &im_img1669, &im_press_fire, &im_select_level_f, &im_select_level_g, &im_select_level_i, &im_select_level_s, &im_img1675, &im_img1676, &im_img1677, &im_img1678, &im_img1679,
	&im_img1680, &im_opt_flag_span2, &im_opt_flag_brit2, &im_opt_flag_fren1, &im_opt_flag_fren2, &im_opt_flag_germ1, &im_opt_flag_germ2, &im_opt_flag_ital1, &im_opt_flag_ital2, &im_opt_flag_span1, &im_opt_flag_brit1, &im_img1691, &im_img1692, &im_select4, &im_select4_f, &im_select4_g,
	&im_select4_i, &im_select4_s, &im_img1698, &im_img1699, &im_img1700, &im_img1701, &im_img1702, &im_opt_race, &im_optf_load_hs_sm, &im_optg_load_hs_sm, &im_opti_load_hs_sm, &im_opts_load_hs_sm, &im_select5, &im_select5_f, &im_select5_g, &im_select5_i,
	&im_select5_s, &im_img1713, &im_img1714, &im_img1715, &im_img1716, &im_img1717, &im_img1718, &im_img1719, &im_img1720, &im_img1721, &im_img1722, &im_img1723, &im_img1724, &im_img1725, &im_img1726, &im_img1727,
	&im_img1728, &im_img1729, &im_img1730, &im_img1731, &im_img1732, &im_img1733, &im_img1734, &im_img1735, &im_img1736, &im_img1737, &im_img1738, &im_img1739, &im_img1740, &im_img1741, &im_img1742, &im_img1743,
	&im_img1744, &im_img1745, &im_img1746, &im_img1747, &im_img1748, &im_img1749, &im_img1750, &im_img1751, &im_img1752, &im_img1753, &im_img1754, &im_img1755, &im_img1756, &im_img1757, &im_img1758, &im_img1759,
	&im_img1760, &im_img1761, &im_img1762, &im_img1763, &im_img1764, &im_img1765, &im_img1766, &im_img1767, &im_img1768, &im_img1769, &im_img1770, &im_img1771, &im_img1772, &im_img1773, &im_img1774, &im_img1775,
	&im_img1776, &im_img1777, &im_img1778, &im_img1779, &im_img1780, &im_img1781, &im_img1782, &im_img1783, &im_img1784, &im_img1785, &im_img1786, &im_img1787, &im_img1788, &im_img1789, &im_img1790, &im_img1791,
	&im_img1792, &im_img1793, &im_img1794, &im_img1795, &im_img1796, &im_froglogo, &im_img1798, &im_img1799, &im_img1800, &im_opt_sec, &im_optf_sec, &im_optg_sec, &im_opti_sec, &im_opts_sec, &im_rank_equal, &im_rank_2,
	&im_rank_3, &im_rank_4, &im_rank_1, &im_play_off, &im_play_off_f, &im_play_off_g, &im_play_off_i, &im_play_off_s, &im_img1816, &im_select7, &im_select6, &im_select7_f, &im_select6_f, &im_select7_g, &im_select6_g, &im_select7_i,
	&im_select6_i, &im_select6_s, &im_select7_s, &im_img1827, &im_img1828, &im_img1829, &im_img1830,
};

MR_USHORT txl_sub1[] = {
	439, 428, 427, 429, 430, 431, 432, 1024, 1025, 433, 434, 517, 435, 996, 997, 436, 1001, 1002, 1026, 437, 1028, 1000, 438, 1029, 1171, 616, 1172, 1031, 1027, 1004, 1003, 1032, 
	1033, 1034, 1035, 1173, 1174, 1175, 1176, 1036, 1177, 1037, 6, 518, 363, 1051, 349, 1030, 4, 7, 
};

MR_USHORT txl_sub2[] = {
	1178, 1179, 996, 1024, 1182, 1026, 1000, 1034, 1033, 1181, 1025, 1183, 1030, 1172, 1028, 1035, 1036, 1184, 1180, 1173, 1174, 1027, 1176, 1003, 1185, 998, 1186, 1001, 1002, 1187, 1188, 2, 
	997, 516, 517, 438, 429, 439, 437, 433, 436, 430, 427, 616, 434, 617, 428, 1032, 999, 435, 1051, 1037, 518, 694, 863, 1039, 865, 869, 866, 908, 1609, 363, 1532, 1004, 
	7, 875, 876, 877, 878, 879, 880, 881, 882, 864, 883, 884, 885, 886, 887, 888, 1533, 1534, 1535, 
};

MR_USHORT txl_sub3[] = {
	996, 1189, 1186, 1027, 1040, 1026, 1182, 1187, 1034, 1036, 1035, 1041, 997, 1181, 1183, 1032, 1042, 998, 1188, 1190, 1191, 1024, 1192, 1025, 999, 1029, 1000, 1028, 1179, 1031, 1038, 1039, 
	1185, 1043, 1172, 1033, 1001, 1002, 1003, 1004, 1178, 1044, 1037, 1030, 7, 
};

MR_USHORT txl_sub4[] = {
	427, 428, 429, 430, 431, 432, 433, 434, 435, 996, 436, 1026, 1027, 437, 997, 1000, 438, 1171, 439, 1030, 1172, 1004, 1003, 1001, 1002, 1032, 516, 616, 1033, 1034, 1035, 1173, 
	1180, 1175, 1174, 1460, 1193, 1176, 1177, 1184, 1036, 1037, 1024, 1025, 1028, 1031, 1029, 349, 6, 363, 2, 694, 7, 
};

MR_USHORT txl_sub5[] = {
	996, 1179, 1040, 1000, 1034, 1033, 1181, 1182, 1036, 1030, 1035, 1183, 1184, 1180, 1173, 1174, 1027, 1176, 1003, 1172, 1185, 998, 1186, 1001, 1002, 1026, 1187, 1188, 2, 997, 516, 517, 
	438, 429, 439, 437, 433, 436, 430, 427, 616, 434, 617, 428, 1032, 999, 435, 518, 694, 1039, 863, 869, 908, 866, 865, 1609, 1532, 363, 7, 875, 876, 877, 878, 879, 
	880, 881, 882, 864, 883, 884, 885, 886, 887, 888, 1533, 1534, 1535, 
};

MR_USHORT txl_cav1[] = {
	519, 296, 299, 287, 521, 294, 291, 618, 283, 522, 292, 303, 304, 295, 293, 290, 524, 525, 301, 302, 527, 284, 619, 620, 621, 622, 300, 623, 520, 624, 298, 528, 
	643, 647, 648, 526, 625, 626, 627, 523, 628, 629, 630, 289, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 644, 645, 646, 649, 650, 651, 652, 
};

MR_USHORT txl_cav3[] = {
	1678, 1563, 521, 1676, 1465, 1461, 1677, 1468, 1467, 1675, 1463, 1557, 1464, 1558, 284, 1556, 1559, 528, 1564, 1560, 1562, 283, 1565, 1566, 1561, 1567, 1568, 287, 1462, 1466, 
};

MR_USHORT txl_cav4[] = {
	620, 618, 291, 619, 290, 528, 292, 293, 654, 622, 301, 287, 294, 653, 655, 295, 621, 296, 303, 297, 657, 521, 299, 298, 300, 522, 624, 302, 660, 656, 658, 659, 
	520, 519, 524, 304, 623, 661, 283, 525, 1668, 284, 1537, 1539, 1540, 1538, 1536, 1713, 1714, 1669, 629, 630, 289, 526, 626, 625, 627, 523, 628, 631, 632, 633, 634, 635, 
	636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 
};

MR_USHORT txl_for1[] = {
	1201, 1194, 1198, 1199, 1200, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 440, 441, 662, 442, 443, 444, 445, 1211, 446, 447, 1679, 20, 1680, 448, 515, 663, 1196, 23, 31, 
};

MR_USHORT txl_for2[] = {
	1202, 1201, 444, 445, 1199, 1242, 1203, 1243, 1205, 447, 1244, 443, 442, 446, 1198, 1200, 1206, 1210, 1207, 1204, 1208, 20, 440, 515, 1209, 662, 1005, 1006, 1007, 1010, 1008, 1009, 
	23, 1011, 1012, 1013, 1014, 448, 1195, 1194, 1197, 1246, 1245, 1247, 664, 1715, 960, 959, 31, 
};

MR_USHORT txl_for3[] = {
	1829, 1830, 448, 515, 20, 
};

MR_USHORT txl_des1[] = {
	1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255, 1257, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268, 1270, 1271, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279, 1280, 1281, 
	1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1304, 1305, 1306, 1307, 1308, 1309, 1310, 1311, 1312, 1313, 
	1314, 1315, 1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1324, 1325, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335, 1269, 1336, 1256, 9, 10, 11, 
};

MR_USHORT txl_des3[] = {
	1249, 1281, 1282, 1275, 1337, 1278, 1274, 1338, 1254, 1255, 1270, 1283, 1279, 1257, 1248, 1260, 1304, 1259, 1258, 1294, 1251, 1295, 1253, 1339, 1272, 1277, 1250, 1309, 1340, 1302, 1312, 1313, 
	1314, 1315, 1316, 1317, 1318, 1320, 1321, 1322, 1323, 1326, 1327, 1328, 1329, 1286, 1331, 1332, 1333, 1252, 1311, 1336, 1341, 1342, 1343, 1335, 1344, 1298, 1287, 1305, 1798, 1308, 1324, 1292, 
	1296, 1345, 1310, 1291, 1299, 1267, 1346, 1334, 1285, 1265, 1347, 1293, 1297, 1319, 1266, 1381, 1256, 9, 
};

MR_USHORT txl_des4[] = {
	1254, 1250, 1251, 1252, 1253, 1249, 1255, 1257, 1248, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1273, 1265, 1266, 1267, 1270, 1271, 1272, 1274, 1275, 1276, 1277, 1278, 1279, 1306, 1280, 1281, 
	1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1330, 1304, 1305, 1319, 1309, 1269, 1308, 1311, 1307, 1324, 
	1325, 1335, 1334, 1336, 1256, 9, 10, 11, 
};

MR_USHORT txl_des5[] = {
	1249, 1290, 1301, 1286, 1287, 1252, 1311, 1302, 1295, 1348, 1257, 1288, 1379, 1349, 1338, 1306, 1299, 1258, 1304, 1259, 1337, 1300, 1278, 1335, 1307, 1280, 1283, 1350, 1276, 1255, 1351, 1303, 
	1325, 1294, 1330, 1352, 1251, 1250, 1353, 1274, 1305, 1275, 1279, 1273, 1270, 1281, 1309, 1291, 1253, 1312, 1336, 1313, 1314, 1315, 1316, 1317, 1318, 1254, 1260, 1320, 1321, 1322, 1323, 1342, 
	1326, 1327, 1328, 1329, 1292, 1293, 1341, 1344, 1284, 1331, 1332, 1333, 1296, 1297, 1347, 1345, 1272, 1277, 1289, 1282, 1308, 1343, 1346, 1354, 1355, 1267, 1356, 1268, 1357, 1256, 9, 10, 11, 
};

MR_USHORT txl_org1[] = {
	1212, 1213, 1214, 1215, 342, 449, 331, 450, 451, 452, 343, 141, 1216, 142, 288, 364, 
};

MR_USHORT txl_org2[] = {
	1212, 1213, 1214, 1215, 342, 331, 449, 450, 452, 343, 141, 1216, 142, 288, 364, 
};

MR_USHORT txl_org3[] = {
	1212, 1213, 1214, 1215, 342, 449, 331, 452, 450, 343, 141, 1216, 142, 288, 364, 
};

MR_USHORT txl_org4[] = {
	1212, 1213, 1214, 1215, 342, 449, 331, 450, 452, 343, 141, 1216, 142, 288, 364, 
};

MR_USHORT txl_org5[] = {
	1212, 1213, 1214, 1215, 342, 331, 449, 450, 452, 343, 141, 1216, 142, 288, 364, 
};

MR_USHORT txl_jun1[] = {
	1518, 1700, 1364, 686, 684, 693, 1358, 1519, 1361, 1362, 1360, 1363, 683, 682, 691, 1365, 681, 688, 687, 685, 689, 1359, 1366, 1367, 665, 1368, 1369, 1370, 1371, 909, 889, 890, 
	667, 870, 871, 666, 910, 1610, 1372, 1373, 1374, 1375, 891, 1376, 668, 1480, 1716, 669, 1611, 872, 670, 893, 896, 895, 897, 690, 692, 894, 1137, 892, 1520, 1521, 1522, 1523, 
	1524, 1525, 1816, 512, 1526, 1527, 
};

MR_USHORT txl_swp1[] = {
	147, 157, 201, 144, 145, 202, 146, 143, 148, 149, 150, 151, 152, 153, 233, 234, 229, 453, 209, 210, 238, 213, 205, 206, 207, 208, 239, 240, 235, 224, 223, 228, 
	227, 454, 455, 218, 459, 460, 461, 230, 231, 457, 458, 222, 217, 219, 214, 215, 216, 211, 212, 236, 237, 155, 154, 232, 225, 221, 226, 333, 203, 204, 156, 456, 
	529, 530, 874, 332, 42, 41, 
};

MR_USHORT txl_swp2[] = {
	234, 229, 453, 454, 455, 218, 213, 205, 206, 207, 208, 209, 210, 238, 239, 240, 235, 459, 460, 461, 230, 231, 462, 456, 457, 458, 224, 201, 236, 237, 149, 222, 
	217, 219, 214, 215, 216, 211, 212, 153, 155, 225, 221, 154, 226, 227, 228, 223, 232, 233, 148, 147, 333, 151, 152, 150, 203, 204, 156, 529, 157, 144, 145, 202, 
	146, 143, 874, 530, 332, 41, 42, 
};

MR_USHORT txl_swp3[] = {
	247, 147, 531, 532, 150, 151, 333, 152, 153, 217, 218, 219, 214, 215, 201, 148, 149, 223, 224, 225, 533, 1385, 1386, 1387, 1392, 229, 230, 231, 226, 227, 1390, 1391, 
	1389, 1388, 235, 236, 237, 232, 233, 208, 209, 210, 238, 239, 534, 216, 211, 212, 220, 221, 222, 228, 234, 240, 205, 206, 207, 535, 202, 1136, 536, 213, 1393, 241, 
	204, 1395, 537, 475, 474, 476, 538, 539, 540, 530, 541, 1394, 1396, 1397, 1398, 1399, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411, 542, 543, 544, 545, 
	546, 547, 548, 549, 550, 551, 552, 553, 554, 898, 899, 900, 
};

MR_USHORT txl_swp4[] = {
	205, 454, 455, 218, 219, 234, 221, 222, 201, 206, 207, 208, 209, 210, 227, 228, 456, 457, 458, 224, 225, 226, 212, 213, 214, 215, 216, 211, 233, 459, 460, 461, 
	230, 231, 453, 239, 240, 235, 236, 237, 229, 1393, 217, 223, 247, 232, 238, 555, 220, 462, 532, 531, 556, 557, 204, 1412, 1413, 1414, 1377, 203, 529, 530, 539, 541, 
	540, 463, 1415, 42, 41, 1416, 1417, 1418, 1419, 1420, 1421, 898, 899, 900, 538, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 
};

MR_USHORT txl_swp5[] = {
	228, 867, 148, 149, 147, 868, 227, 223, 224, 225, 207, 208, 209, 210, 205, 206, 201, 151, 233, 234, 229, 230, 231, 226, 152, 153, 239, 240, 235, 236, 237, 232, 
	333, 238, 150, 246, 285, 242, 202, 1390, 1388, 1386, 1385, 1136, 1392, 213, 155, 1391, 219, 1389, 1387, 216, 222, 534, 532, 241, 35, 154, 332, 243, 244, 204, 1413, 1412, 
	1414, 1395, 247, 156, 530, 1166, 901, 539, 541, 540, 203, 144, 874, 1541, 1396, 1397, 1398, 1399, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411, 898, 899, 
	900, 547, 548, 549, 550, 551, 552, 553, 554, 902, 903, 904, 1416, 1417, 1418, 1419, 1420, 1421, 1542, 1543, 1544, 
};

MR_USHORT txl_sky1[] = {
	286, 334, 316, 604, 605, 606, 607, 608, 609, 610, 611, 
};

MR_USHORT txl_sky2[] = {
	611, 604, 610, 606, 607, 608, 1469, 1470, 605, 609, 
};

MR_USHORT txl_sky3[] = {
	334, 1052, 316, 286, 
};

MR_USHORT txl_sky4[] = {
	286, 334, 316, 604, 605, 606, 607, 608, 609, 610, 611, 
};

MR_USHORT txl_vol1[] = {
	370, 464, 369, 352, 465, 1691, 366, 574, 961, 962, 580, 963, 354, 568, 353, 1434, 355, 356, 367, 964, 368, 1692, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974, 
	371, 372, 1433, 1471, 466, 467, 468, 469, 470, 471, 472, 473, 569, 570, 571, 572, 573, 575, 576, 577, 578, 579, 581, 582, 583, 584, 585, 
};

MR_USHORT txl_vol2[] = {
	1481, 1482, 352, 1483, 356, 355, 353, 558, 559, 560, 561, 562, 563, 564, 1434, 464, 565, 566, 567, 372, 1698, 1699, 357, 1433, 466, 467, 468, 469, 470, 471, 472, 473, 
	568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 
};

MR_USHORT txl_vol3[] = {
	1481, 1434, 353, 1482, 366, 352, 355, 356, 370, 580, 568, 574, 372, 1433, 464, 466, 467, 468, 469, 470, 471, 472, 473, 569, 570, 571, 572, 573, 575, 576, 577, 578, 
	579, 581, 582, 583, 584, 585, 
};

MR_USHORT txl_des2[] = {
	1249, 1290, 1301, 1794, 1287, 1252, 1311, 1286, 1302, 1295, 1348, 1257, 1260, 1304, 1259, 1258, 1288, 1379, 1349, 1280, 1330, 1306, 1338, 1299, 1337, 1278, 1335, 1300, 1307, 1283, 1350, 1276, 
	1255, 1351, 1303, 1325, 1294, 1352, 1251, 1250, 1292, 1293, 1305, 1354, 1353, 1274, 1296, 1297, 1309, 1279, 1272, 1273, 1270, 1291, 1281, 1254, 1289, 1253, 1312, 1336, 1313, 1314, 1315, 1316, 
	1317, 1318, 1320, 1321, 1322, 1323, 1275, 1342, 1326, 1327, 1328, 1329, 1341, 1344, 1284, 1331, 1332, 1333, 1347, 1345, 1277, 1282, 1343, 1346, 1355, 1267, 1356, 1357, 1256, 10, 11, 
};

MR_USHORT txl_sky_land[] = {
	1721, 1720, 1751, 1722, 1723, 1724, 1725, 1726, 1727, 1719, 1718, 1717, 1762, 1763, 1764, 1728, 1729, 1730, 1731, 1732, 1733, 1734, 1735, 1736, 1737, 1738, 1739, 1740, 1741, 1742, 1743, 1744, 
	1745, 1746, 1747, 1750, 1748, 1749, 1752, 1753, 1754, 1755, 1773, 1756, 1757, 1758, 1759, 1760, 1761, 1766, 1765, 1767, 1769, 1770, 1771, 1772, 1774, 1775, 1776, 1777, 1778, 1768, 1779, 1780, 
	1781, 1782, 1783, 1784, 1785, 1786, 1787, 1788, 1789, 1790, 1791, 1792, 
};

MR_USHORT txl_form[] = {
	1201, 1194, 1196, 1198, 1199, 1200, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 440, 441, 662, 442, 443, 444, 445, 1211, 446, 447, 1679, 20, 1680, 448, 515, 663, 
};

MR_USHORT txl_orgm[] = {
	1212, 1213, 1214, 1215, 141, 1216, 142, 288, 1827, 
};

MR_USHORT txl_junm[] = {
	1518, 1361, 1362, 1700, 910, 891, 909, 889, 895, 896, 1374, 667, 1828, 1371, 1369, 1701, 1139, 1142, 1143, 1144, 1145, 1141, 1146, 1147, 1148, 1149, 1138, 1150, 1151, 1152, 1140, 1153, 1154, 1155, 
};

MR_USHORT txl_subm[] = {
	996, 997, 1173, 1174, 1193, 1180, 1032, 1030, 
};

MR_USHORT txl_volm[] = {
	352, 1433, 353, 356, 1481, 1482, 367, 355, 561, 966, 558, 559, 560, 563, 1434, 972, 464, 466, 467, 468, 469, 470, 471, 472, 473, 568, 569, 570, 571, 572, 573, 574, 
	575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 
};

MR_USHORT txl_jun2[] = {
	1518, 1700, 1364, 686, 684, 693, 1358, 1519, 1361, 1362, 1360, 1363, 683, 682, 691, 1365, 681, 688, 687, 685, 689, 1359, 1366, 1367, 665, 1368, 1369, 1370, 1371, 909, 889, 890, 
	667, 870, 871, 666, 910, 1610, 1372, 1373, 1374, 1375, 891, 1376, 668, 1480, 1716, 669, 1611, 872, 670, 893, 896, 895, 897, 690, 692, 894, 1137, 892, 1520, 1521, 1522, 1523, 
	1524, 1525, 1816, 512, 1526, 1527, 
};


MR_TEXTURE im_img0;
MR_TEXTURE im_img1;
MR_TEXTURE im_img2;
MR_TEXTURE im_img3;
MR_TEXTURE im_img4;
MR_TEXTURE im_img5;
MR_TEXTURE im_img6;
MR_TEXTURE im_img7;
MR_TEXTURE im_img8;
MR_TEXTURE im_img9;
MR_TEXTURE im_img10;
MR_TEXTURE im_img11;
MR_TEXTURE im_img12;
MR_TEXTURE im_img13;
MR_TEXTURE im_img14;
MR_TEXTURE im_img15;
MR_TEXTURE im_img16;
MR_TEXTURE im_img17;
MR_TEXTURE im_img18;
MR_TEXTURE im_img19;
MR_TEXTURE im_img20;
MR_TEXTURE im_img21;
MR_TEXTURE im_img22;
MR_TEXTURE im_img23;
MR_TEXTURE im_img24;
MR_TEXTURE im_img25;
MR_TEXTURE im_img26;
MR_TEXTURE im_img27;
MR_TEXTURE im_img28;
MR_TEXTURE im_img29;
MR_TEXTURE im_img30;
MR_TEXTURE im_img31;
MR_TEXTURE im_for_swarm;
MR_TEXTURE im_img33;
MR_TEXTURE im_img34;
MR_TEXTURE im_img35;
MR_TEXTURE im_img36;
MR_TEXTURE im_img37;
MR_TEXTURE im_img38;
MR_TEXTURE im_img39;
MR_TEXTURE im_img40;
MR_TEXTURE im_img41;
MR_TEXTURE im_img42;
MR_TEXTURE im_img43;
MR_TEXTURE im_img44;
MR_TEXTURE im_img45;
MR_TEXTURE im_img46;
MR_TEXTURE im_img47;
MR_TEXTURE im_img48;
MR_TEXTURE im_img49;
MR_TEXTURE im_img50;
MR_TEXTURE im_img51;
MR_TEXTURE im_img52;
MR_TEXTURE im_img53;
MR_TEXTURE im_img54;
MR_TEXTURE im_img55;
MR_TEXTURE im_img56;
MR_TEXTURE im_img57;
MR_TEXTURE im_img58;
MR_TEXTURE im_img59;
MR_TEXTURE im_img60;
MR_TEXTURE im_img61;
MR_TEXTURE im_img62;
MR_TEXTURE im_img63;
MR_TEXTURE im_img64;
MR_TEXTURE im_img65;
MR_TEXTURE im_img66;
MR_TEXTURE im_tongue_tip;
MR_TEXTURE im_dbugfont;
MR_TEXTURE im_fire_fly;
MR_TEXTURE im_fire_flya;
MR_TEXTURE im_fly_10;
MR_TEXTURE im_fly_100;
MR_TEXTURE im_fly_1000;
MR_TEXTURE im_fly_1000a;
MR_TEXTURE im_fly_100a;
MR_TEXTURE im_fly_10a;
MR_TEXTURE im_fly_200;
MR_TEXTURE im_fly_200a;
MR_TEXTURE im_fly_25;
MR_TEXTURE im_fly_25a;
MR_TEXTURE im_fly_50;
MR_TEXTURE im_fly_500;
MR_TEXTURE im_fly_5000;
MR_TEXTURE im_fly_5000a;
MR_TEXTURE im_fly_500a;
MR_TEXTURE im_fly_50a;
MR_TEXTURE im_fly_bad;
MR_TEXTURE im_fly_bada;
MR_TEXTURE im_quick_jump;
MR_TEXTURE im_super_tongue;
MR_TEXTURE im_time_max;
MR_TEXTURE im_time_maxa;
MR_TEXTURE im_time_med;
MR_TEXTURE im_time_meda;
MR_TEXTURE im_time_min;
MR_TEXTURE im_time_mina;
MR_TEXTURE im_auto_jump;
MR_TEXTURE im_gen_shadow;
MR_TEXTURE im_32x32_9;
MR_TEXTURE im_32x32_1;
MR_TEXTURE im_32x32_2;
MR_TEXTURE im_32x32_3;
MR_TEXTURE im_32x32_4;
MR_TEXTURE im_32x32_5;
MR_TEXTURE im_32x32_6;
MR_TEXTURE im_32x32_7;
MR_TEXTURE im_32x32_8;
MR_TEXTURE im_32x32_0;
MR_TEXTURE im_score_10;
MR_TEXTURE im_score_100;
MR_TEXTURE im_score_150;
MR_TEXTURE im_score_200;
MR_TEXTURE im_score_250;
MR_TEXTURE im_score_50;
MR_TEXTURE im_score_500;
MR_TEXTURE im_score_75;
MR_TEXTURE im_img117;
MR_TEXTURE im_img118;
MR_TEXTURE im_img119;
MR_TEXTURE im_img120;
MR_TEXTURE im_img121;
MR_TEXTURE im_img122;
MR_TEXTURE im_img123;
MR_TEXTURE im_img124;
MR_TEXTURE im_img125;
MR_TEXTURE im_img126;
MR_TEXTURE im_img127;
MR_TEXTURE im_img128;
MR_TEXTURE im_img129;
MR_TEXTURE im_img130;
MR_TEXTURE im_img131;
MR_TEXTURE im_img132;
MR_TEXTURE im_img133;
MR_TEXTURE im_img134;
MR_TEXTURE im_img135;
MR_TEXTURE im_img136;
MR_TEXTURE im_img137;
MR_TEXTURE im_img138;
MR_TEXTURE im_img139;
MR_TEXTURE im_img140;
MR_TEXTURE im_img141;
MR_TEXTURE im_img142;
MR_TEXTURE im_img143;
MR_TEXTURE im_img144;
MR_TEXTURE im_img145;
MR_TEXTURE im_img146;
MR_TEXTURE im_img147;
MR_TEXTURE im_img148;
MR_TEXTURE im_img149;
MR_TEXTURE im_img150;
MR_TEXTURE im_img151;
MR_TEXTURE im_img152;
MR_TEXTURE im_img153;
MR_TEXTURE im_img154;
MR_TEXTURE im_img155;
MR_TEXTURE im_img156;
MR_TEXTURE im_img157;
MR_TEXTURE im_img158;
MR_TEXTURE im_wake2;
MR_TEXTURE im_img160;
MR_TEXTURE im_img161;
MR_TEXTURE im_babyfrog5_6;
MR_TEXTURE im_babyfrog1_1;
MR_TEXTURE im_babyfrog1_2;
MR_TEXTURE im_babyfrog1_3;
MR_TEXTURE im_babyfrog1_4;
MR_TEXTURE im_babyfrog1_5;
MR_TEXTURE im_babyfrog1_6;
MR_TEXTURE im_babyfrog2_0;
MR_TEXTURE im_babyfrog2_1;
MR_TEXTURE im_babyfrog2_2;
MR_TEXTURE im_babyfrog2_3;
MR_TEXTURE im_babyfrog2_4;
MR_TEXTURE im_babyfrog2_5;
MR_TEXTURE im_babyfrog2_6;
MR_TEXTURE im_babyfrog3_0;
MR_TEXTURE im_babyfrog3_1;
MR_TEXTURE im_babyfrog3_2;
MR_TEXTURE im_babyfrog3_3;
MR_TEXTURE im_babyfrog3_4;
MR_TEXTURE im_babyfrog3_5;
MR_TEXTURE im_babyfrog3_6;
MR_TEXTURE im_babyfrog4_0;
MR_TEXTURE im_babyfrog4_1;
MR_TEXTURE im_babyfrog4_2;
MR_TEXTURE im_babyfrog4_3;
MR_TEXTURE im_babyfrog4_4;
MR_TEXTURE im_babyfrog4_5;
MR_TEXTURE im_babyfrog4_6;
MR_TEXTURE im_babyfrog5_0;
MR_TEXTURE im_babyfrog5_1;
MR_TEXTURE im_babyfrog5_2;
MR_TEXTURE im_babyfrog5_3;
MR_TEXTURE im_babyfrog5_4;
MR_TEXTURE im_babyfrog5_5;
MR_TEXTURE im_babyfrog1_0;
MR_TEXTURE im_des1pic;
MR_TEXTURE im_des2pic;
MR_TEXTURE im_org1pic;
MR_TEXTURE im_sub1pic;
MR_TEXTURE im_img201;
MR_TEXTURE im_img202;
MR_TEXTURE im_img203;
MR_TEXTURE im_img204;
MR_TEXTURE im_img205;
MR_TEXTURE im_img206;
MR_TEXTURE im_img207;
MR_TEXTURE im_img208;
MR_TEXTURE im_img209;
MR_TEXTURE im_img210;
MR_TEXTURE im_img211;
MR_TEXTURE im_img212;
MR_TEXTURE im_img213;
MR_TEXTURE im_img214;
MR_TEXTURE im_img215;
MR_TEXTURE im_img216;
MR_TEXTURE im_img217;
MR_TEXTURE im_img218;
MR_TEXTURE im_img219;
MR_TEXTURE im_img220;
MR_TEXTURE im_img221;
MR_TEXTURE im_img222;
MR_TEXTURE im_img223;
MR_TEXTURE im_img224;
MR_TEXTURE im_img225;
MR_TEXTURE im_img226;
MR_TEXTURE im_img227;
MR_TEXTURE im_img228;
MR_TEXTURE im_img229;
MR_TEXTURE im_img230;
MR_TEXTURE im_img231;
MR_TEXTURE im_img232;
MR_TEXTURE im_img233;
MR_TEXTURE im_img234;
MR_TEXTURE im_img235;
MR_TEXTURE im_img236;
MR_TEXTURE im_img237;
MR_TEXTURE im_img238;
MR_TEXTURE im_img239;
MR_TEXTURE im_img240;
MR_TEXTURE im_img241;
MR_TEXTURE im_img242;
MR_TEXTURE im_img243;
MR_TEXTURE im_img244;
MR_TEXTURE im_img245;
MR_TEXTURE im_img246;
MR_TEXTURE im_img247;
MR_TEXTURE im_img248;
MR_TEXTURE im_gatso;
MR_TEXTURE im_cav1pic;
MR_TEXTURE im_des3pic;
MR_TEXTURE im_des4pic;
MR_TEXTURE im_des5pic;
MR_TEXTURE im_for1pic;
MR_TEXTURE im_for2pic;
MR_TEXTURE im_jun1pic;
MR_TEXTURE im_org2pic;
MR_TEXTURE im_org3pic;
MR_TEXTURE im_org4pic;
MR_TEXTURE im_org5pic;
MR_TEXTURE im_select1;
MR_TEXTURE im_select2;
MR_TEXTURE im_sky1pic;
MR_TEXTURE im_sky2pic;
MR_TEXTURE im_sky3pic;
MR_TEXTURE im_sky4pic;
MR_TEXTURE im_sub2pic;
MR_TEXTURE im_sub3pic;
MR_TEXTURE im_sub4pic;
MR_TEXTURE im_sub5pic;
MR_TEXTURE im_swp1pic;
MR_TEXTURE im_swp2pic;
MR_TEXTURE im_swp3pic;
MR_TEXTURE im_swp4pic;
MR_TEXTURE im_swp5pic;
MR_TEXTURE im_vol1pic;
MR_TEXTURE im_vol2pic;
MR_TEXTURE im_vol3pic;
MR_TEXTURE im_img279;
MR_TEXTURE im_img280;
MR_TEXTURE im_img281;
MR_TEXTURE im_img282;
MR_TEXTURE im_img283;
MR_TEXTURE im_img284;
MR_TEXTURE im_img285;
MR_TEXTURE im_img286;
MR_TEXTURE im_img287;
MR_TEXTURE im_img288;
MR_TEXTURE im_img289;
MR_TEXTURE im_img290;
MR_TEXTURE im_img291;
MR_TEXTURE im_img292;
MR_TEXTURE im_img293;
MR_TEXTURE im_img294;
MR_TEXTURE im_img295;
MR_TEXTURE im_img296;
MR_TEXTURE im_img297;
MR_TEXTURE im_img298;
MR_TEXTURE im_img299;
MR_TEXTURE im_img300;
MR_TEXTURE im_img301;
MR_TEXTURE im_img302;
MR_TEXTURE im_img303;
MR_TEXTURE im_img304;
MR_TEXTURE im_img305;
MR_TEXTURE im_img306;
MR_TEXTURE im_img307;
MR_TEXTURE im_img308;
MR_TEXTURE im_img309;
MR_TEXTURE im_img310;
MR_TEXTURE im_img311;
MR_TEXTURE im_org_splash_2;
MR_TEXTURE im_org_splash_0;
MR_TEXTURE im_org_splash_1;
MR_TEXTURE im_img315;
MR_TEXTURE im_img316;
MR_TEXTURE im_img317;
MR_TEXTURE im_img318;
MR_TEXTURE im_img319;
MR_TEXTURE im_img320;
MR_TEXTURE im_img321;
MR_TEXTURE im_img322;
MR_TEXTURE im_img323;
MR_TEXTURE im_img324;
MR_TEXTURE im_img325;
MR_TEXTURE im_img326;
MR_TEXTURE im_img327;
MR_TEXTURE im_img328;
MR_TEXTURE im_img329;
MR_TEXTURE im_img330;
MR_TEXTURE im_img331;
MR_TEXTURE im_img332;
MR_TEXTURE im_img333;
MR_TEXTURE im_img334;
MR_TEXTURE im_org_log;
MR_TEXTURE im_img336;
MR_TEXTURE im_img337;
MR_TEXTURE im_img338;
MR_TEXTURE im_img339;
MR_TEXTURE im_img340;
MR_TEXTURE im_sky_balloon_env;
MR_TEXTURE im_img342;
MR_TEXTURE im_img343;
MR_TEXTURE im_img344;
MR_TEXTURE im_img345;
MR_TEXTURE im_img346;
MR_TEXTURE im_img347;
MR_TEXTURE im_img348;
MR_TEXTURE im_img349;
MR_TEXTURE im_img350;
MR_TEXTURE im_img351;
MR_TEXTURE im_vol_tile51;
MR_TEXTURE im_img353;
MR_TEXTURE im_img354;
MR_TEXTURE im_img355;
MR_TEXTURE im_img356;
MR_TEXTURE im_img357;
MR_TEXTURE im_img358;
MR_TEXTURE im_img359;
MR_TEXTURE im_score_5000;
MR_TEXTURE im_score_1000;
MR_TEXTURE im_score_25;
MR_TEXTURE im_sub_env_sky;
MR_TEXTURE im_org_env_sky;
MR_TEXTURE im_img365;
MR_TEXTURE im_img366;
MR_TEXTURE im_img367;
MR_TEXTURE im_img368;
MR_TEXTURE im_img369;
MR_TEXTURE im_img370;
MR_TEXTURE im_img371;
MR_TEXTURE im_img372;
MR_TEXTURE im_img373;
MR_TEXTURE im_img374;
MR_TEXTURE im_img375;
MR_TEXTURE im_img376;
MR_TEXTURE im_img377;
MR_TEXTURE im_img378;
MR_TEXTURE im_img379;
MR_TEXTURE im_img380;
MR_TEXTURE im_img381;
MR_TEXTURE im_img382;
MR_TEXTURE im_img383;
MR_TEXTURE im_img384;
MR_TEXTURE im_img385;
MR_TEXTURE im_img386;
MR_TEXTURE im_img387;
MR_TEXTURE im_img388;
MR_TEXTURE im_img389;
MR_TEXTURE im_img390;
MR_TEXTURE im_img391;
MR_TEXTURE im_hi_back;
MR_TEXTURE im_img393;
MR_TEXTURE im_img394;
MR_TEXTURE im_img395;
MR_TEXTURE im_img396;
MR_TEXTURE im_img397;
MR_TEXTURE im_img398;
MR_TEXTURE im_img399;
MR_TEXTURE im_img400;
MR_TEXTURE im_img401;
MR_TEXTURE im_img402;
MR_TEXTURE im_img403;
MR_TEXTURE im_img404;
MR_TEXTURE im_img405;
MR_TEXTURE im_img406;
MR_TEXTURE im_img407;
MR_TEXTURE im_img408;
MR_TEXTURE im_img409;
MR_TEXTURE im_img410;
MR_TEXTURE im_img411;
MR_TEXTURE im_img412;
MR_TEXTURE im_img413;
MR_TEXTURE im_img414;
MR_TEXTURE im_img415;
MR_TEXTURE im_img416;
MR_TEXTURE im_img417;
MR_TEXTURE im_img418;
MR_TEXTURE im_img419;
MR_TEXTURE im_img420;
MR_TEXTURE im_img421;
MR_TEXTURE im_img422;
MR_TEXTURE im_img423;
MR_TEXTURE im_img424;
MR_TEXTURE im_img425;
MR_TEXTURE im_img426;
MR_TEXTURE im_img427;
MR_TEXTURE im_img428;
MR_TEXTURE im_img429;
MR_TEXTURE im_img430;
MR_TEXTURE im_img431;
MR_TEXTURE im_img432;
MR_TEXTURE im_img433;
MR_TEXTURE im_img434;
MR_TEXTURE im_img435;
MR_TEXTURE im_img436;
MR_TEXTURE im_img437;
MR_TEXTURE im_img438;
MR_TEXTURE im_img439;
MR_TEXTURE im_img440;
MR_TEXTURE im_img441;
MR_TEXTURE im_img442;
MR_TEXTURE im_img443;
MR_TEXTURE im_img444;
MR_TEXTURE im_img445;
MR_TEXTURE im_img446;
MR_TEXTURE im_img447;
MR_TEXTURE im_img448;
MR_TEXTURE im_img449;
MR_TEXTURE im_img450;
MR_TEXTURE im_img451;
MR_TEXTURE im_img452;
MR_TEXTURE im_img453;
MR_TEXTURE im_img454;
MR_TEXTURE im_img455;
MR_TEXTURE im_img456;
MR_TEXTURE im_img457;
MR_TEXTURE im_img458;
MR_TEXTURE im_img459;
MR_TEXTURE im_img460;
MR_TEXTURE im_img461;
MR_TEXTURE im_img462;
MR_TEXTURE im_img463;
MR_TEXTURE im_img464;
MR_TEXTURE im_img465;
MR_TEXTURE im_img466;
MR_TEXTURE im_img467;
MR_TEXTURE im_img468;
MR_TEXTURE im_img469;
MR_TEXTURE im_img470;
MR_TEXTURE im_img471;
MR_TEXTURE im_img472;
MR_TEXTURE im_img473;
MR_TEXTURE im_img474;
MR_TEXTURE im_img475;
MR_TEXTURE im_img476;
MR_TEXTURE im_img477;
MR_TEXTURE im_opt_env_sky;
MR_TEXTURE im_img479;
MR_TEXTURE im_newfont;
MR_TEXTURE im_opt_arrow;
MR_TEXTURE im_img482;
MR_TEXTURE im_img483;
MR_TEXTURE im_img484;
MR_TEXTURE im_img485;
MR_TEXTURE im_img486;
MR_TEXTURE im_img487;
MR_TEXTURE im_img488;
MR_TEXTURE im_img489;
MR_TEXTURE im_img490;
MR_TEXTURE im_img491;
MR_TEXTURE im_img492;
MR_TEXTURE im_img493;
MR_TEXTURE im_img494;
MR_TEXTURE im_img495;
MR_TEXTURE im_img496;
MR_TEXTURE im_img497;
MR_TEXTURE im_img498;
MR_TEXTURE im_img499;
MR_TEXTURE im_img500;
MR_TEXTURE im_img501;
MR_TEXTURE im_img502;
MR_TEXTURE im_img503;
MR_TEXTURE im_img504;
MR_TEXTURE im_img505;
MR_TEXTURE im_img506;
MR_TEXTURE im_img507;
MR_TEXTURE im_img508;
MR_TEXTURE im_img509;
MR_TEXTURE im_img510;
MR_TEXTURE im_img511;
MR_TEXTURE im_img512;
MR_TEXTURE im_img513;
MR_TEXTURE im_img514;
MR_TEXTURE im_img515;
MR_TEXTURE im_img516;
MR_TEXTURE im_img517;
MR_TEXTURE im_img518;
MR_TEXTURE im_img519;
MR_TEXTURE im_img520;
MR_TEXTURE im_img521;
MR_TEXTURE im_img522;
MR_TEXTURE im_img523;
MR_TEXTURE im_img524;
MR_TEXTURE im_img525;
MR_TEXTURE im_img526;
MR_TEXTURE im_img527;
MR_TEXTURE im_img528;
MR_TEXTURE im_img529;
MR_TEXTURE im_img530;
MR_TEXTURE im_img531;
MR_TEXTURE im_img532;
MR_TEXTURE im_img533;
MR_TEXTURE im_img534;
MR_TEXTURE im_img535;
MR_TEXTURE im_img536;
MR_TEXTURE im_img537;
MR_TEXTURE im_img538;
MR_TEXTURE im_img539;
MR_TEXTURE im_img540;
MR_TEXTURE im_img541;
MR_TEXTURE im_img542;
MR_TEXTURE im_img543;
MR_TEXTURE im_img544;
MR_TEXTURE im_img545;
MR_TEXTURE im_img546;
MR_TEXTURE im_img547;
MR_TEXTURE im_img548;
MR_TEXTURE im_img549;
MR_TEXTURE im_img550;
MR_TEXTURE im_img551;
MR_TEXTURE im_img552;
MR_TEXTURE im_img553;
MR_TEXTURE im_img554;
MR_TEXTURE im_img555;
MR_TEXTURE im_img556;
MR_TEXTURE im_img557;
MR_TEXTURE im_img558;
MR_TEXTURE im_img559;
MR_TEXTURE im_img560;
MR_TEXTURE im_img561;
MR_TEXTURE im_img562;
MR_TEXTURE im_img563;
MR_TEXTURE im_img564;
MR_TEXTURE im_img565;
MR_TEXTURE im_img566;
MR_TEXTURE im_img567;
MR_TEXTURE im_img568;
MR_TEXTURE im_img569;
MR_TEXTURE im_img570;
MR_TEXTURE im_img571;
MR_TEXTURE im_img572;
MR_TEXTURE im_img573;
MR_TEXTURE im_img574;
MR_TEXTURE im_img575;
MR_TEXTURE im_img576;
MR_TEXTURE im_img577;
MR_TEXTURE im_img578;
MR_TEXTURE im_img579;
MR_TEXTURE im_img580;
MR_TEXTURE im_img581;
MR_TEXTURE im_img582;
MR_TEXTURE im_img583;
MR_TEXTURE im_img584;
MR_TEXTURE im_img585;
MR_TEXTURE im_img586;
MR_TEXTURE im_img587;
MR_TEXTURE im_img588;
MR_TEXTURE im_img589;
MR_TEXTURE im_img590;
MR_TEXTURE im_img591;
MR_TEXTURE im_img592;
MR_TEXTURE im_img593;
MR_TEXTURE im_img594;
MR_TEXTURE im_img595;
MR_TEXTURE im_img596;
MR_TEXTURE im_img597;
MR_TEXTURE im_img598;
MR_TEXTURE im_img599;
MR_TEXTURE im_img600;
MR_TEXTURE im_img601;
MR_TEXTURE im_img602;
MR_TEXTURE im_img603;
MR_TEXTURE im_img604;
MR_TEXTURE im_img605;
MR_TEXTURE im_img606;
MR_TEXTURE im_img607;
MR_TEXTURE im_img608;
MR_TEXTURE im_img609;
MR_TEXTURE im_img610;
MR_TEXTURE im_img611;
MR_TEXTURE im_img612;
MR_TEXTURE im_img613;
MR_TEXTURE im_img614;
MR_TEXTURE im_img615;
MR_TEXTURE im_img616;
MR_TEXTURE im_img617;
MR_TEXTURE im_img618;
MR_TEXTURE im_img619;
MR_TEXTURE im_img620;
MR_TEXTURE im_img621;
MR_TEXTURE im_img622;
MR_TEXTURE im_img623;
MR_TEXTURE im_img624;
MR_TEXTURE im_img625;
MR_TEXTURE im_img626;
MR_TEXTURE im_img627;
MR_TEXTURE im_img628;
MR_TEXTURE im_img629;
MR_TEXTURE im_img630;
MR_TEXTURE im_img631;
MR_TEXTURE im_img632;
MR_TEXTURE im_img633;
MR_TEXTURE im_img634;
MR_TEXTURE im_img635;
MR_TEXTURE im_img636;
MR_TEXTURE im_img637;
MR_TEXTURE im_img638;
MR_TEXTURE im_img639;
MR_TEXTURE im_img640;
MR_TEXTURE im_img641;
MR_TEXTURE im_img642;
MR_TEXTURE im_img643;
MR_TEXTURE im_img644;
MR_TEXTURE im_img645;
MR_TEXTURE im_img646;
MR_TEXTURE im_img647;
MR_TEXTURE im_img648;
MR_TEXTURE im_img649;
MR_TEXTURE im_img650;
MR_TEXTURE im_img651;
MR_TEXTURE im_img652;
MR_TEXTURE im_img653;
MR_TEXTURE im_img654;
MR_TEXTURE im_img655;
MR_TEXTURE im_img656;
MR_TEXTURE im_img657;
MR_TEXTURE im_img658;
MR_TEXTURE im_img659;
MR_TEXTURE im_img660;
MR_TEXTURE im_img661;
MR_TEXTURE im_img662;
MR_TEXTURE im_img663;
MR_TEXTURE im_img664;
MR_TEXTURE im_img665;
MR_TEXTURE im_img666;
MR_TEXTURE im_img667;
MR_TEXTURE im_img668;
MR_TEXTURE im_img669;
MR_TEXTURE im_img670;
MR_TEXTURE im_ripple_tim6;
MR_TEXTURE im_ripple_tim2;
MR_TEXTURE im_ripple_tim3;
MR_TEXTURE im_ripple_tim4;
MR_TEXTURE im_ripple_tim5;
MR_TEXTURE im_ripple_tim1;
MR_TEXTURE im_img677;
MR_TEXTURE im_img678;
MR_TEXTURE im_img679;
MR_TEXTURE im_img680;
MR_TEXTURE im_img681;
MR_TEXTURE im_img682;
MR_TEXTURE im_img683;
MR_TEXTURE im_img684;
MR_TEXTURE im_img685;
MR_TEXTURE im_img686;
MR_TEXTURE im_img687;
MR_TEXTURE im_img688;
MR_TEXTURE im_img689;
MR_TEXTURE im_img690;
MR_TEXTURE im_img691;
MR_TEXTURE im_img692;
MR_TEXTURE im_img693;
MR_TEXTURE im_img694;
MR_TEXTURE im_lives_bg5;
MR_TEXTURE im_lifes2;
MR_TEXTURE im_lifes3;
MR_TEXTURE im_lifes4;
MR_TEXTURE im_lifes5;
MR_TEXTURE im_lives_bg1;
MR_TEXTURE im_lives_bg2;
MR_TEXTURE im_lives_bg3;
MR_TEXTURE im_lives_bg4;
MR_TEXTURE im_lifes1;
MR_TEXTURE im_hop_to_it_f;
MR_TEXTURE im_hop_to_it_s;
MR_TEXTURE im_hop_to_it_i;
MR_TEXTURE im_hop_to_it_g;
MR_TEXTURE im_go_frogger_s;
MR_TEXTURE im_go_frogger_g;
MR_TEXTURE im_go_frogger_i;
MR_TEXTURE im_go_frogger_f;
MR_TEXTURE im_go_s;
MR_TEXTURE im_go_g;
MR_TEXTURE im_go_i;
MR_TEXTURE im_go_f;
MR_TEXTURE im_go_get_em_s;
MR_TEXTURE im_go_get_em_g;
MR_TEXTURE im_go_get_em_i;
MR_TEXTURE im_go_get_em_f;
MR_TEXTURE im_jump_to_it_s;
MR_TEXTURE im_jump_to_it_f;
MR_TEXTURE im_jump_to_it_g;
MR_TEXTURE im_jump_to_it_i;
MR_TEXTURE im_optf_yes;
MR_TEXTURE im_optg_no;
MR_TEXTURE im_optg_yes;
MR_TEXTURE im_opti_no;
MR_TEXTURE im_opti_yes;
MR_TEXTURE im_opts_no;
MR_TEXTURE im_opts_yes;
MR_TEXTURE im_optf_no;
MR_TEXTURE im_zone_complete_g;
MR_TEXTURE im_zone_complete_f;
MR_TEXTURE im_zone_complete_i;
MR_TEXTURE im_zone_complete_s;
MR_TEXTURE im_next_s;
MR_TEXTURE im_next_g;
MR_TEXTURE im_next_i;
MR_TEXTURE im_next_f;
MR_TEXTURE im_bonus_s;
MR_TEXTURE im_bonus_g;
MR_TEXTURE im_bonus_i;
MR_TEXTURE im_bonus_f;
MR_TEXTURE im_total_time_s;
MR_TEXTURE im_total_time_g;
MR_TEXTURE im_total_time_i;
MR_TEXTURE im_total_time_f;
MR_TEXTURE im_total_score_f;
MR_TEXTURE im_total_score_g;
MR_TEXTURE im_total_score_i;
MR_TEXTURE im_total_score_s;
MR_TEXTURE im_opts_paused;
MR_TEXTURE im_optg_paused;
MR_TEXTURE im_opti_paused;
MR_TEXTURE im_optf_paused;
MR_TEXTURE im_quit_g;
MR_TEXTURE im_quit_i;
MR_TEXTURE im_quit_s;
MR_TEXTURE im_quit_f;
MR_TEXTURE im_croak_s;
MR_TEXTURE im_croak_f;
MR_TEXTURE im_croak_g;
MR_TEXTURE im_croak_i;
MR_TEXTURE im_select2_s;
MR_TEXTURE im_select1_g;
MR_TEXTURE im_select1_i;
MR_TEXTURE im_select1_s;
MR_TEXTURE im_select2_f;
MR_TEXTURE im_select2_g;
MR_TEXTURE im_select2_i;
MR_TEXTURE im_select1_f;
MR_TEXTURE im_opts_start;
MR_TEXTURE im_optf_race;
MR_TEXTURE im_optf_start;
MR_TEXTURE im_optg_options;
MR_TEXTURE im_optg_race;
MR_TEXTURE im_optg_start;
MR_TEXTURE im_opti_options;
MR_TEXTURE im_opti_race;
MR_TEXTURE im_opti_start;
MR_TEXTURE im_opts_options;
MR_TEXTURE im_opts_race;
MR_TEXTURE im_optf_options;
MR_TEXTURE im_img785;
MR_TEXTURE im_img786;
MR_TEXTURE im_img787;
MR_TEXTURE im_img788;
MR_TEXTURE im_img789;
MR_TEXTURE im_img790;
MR_TEXTURE im_img791;
MR_TEXTURE im_img792;
MR_TEXTURE im_img793;
MR_TEXTURE im_img794;
MR_TEXTURE im_skip_hi_score_f;
MR_TEXTURE im_press_fire_f;
MR_TEXTURE im_press_fire_g;
MR_TEXTURE im_press_fire_i;
MR_TEXTURE im_optf_insert_pad;
MR_TEXTURE im_optf_ctrl_config;
MR_TEXTURE im_optf_exit;
MR_TEXTURE im_optf_format;
MR_TEXTURE im_optf_check_save;
MR_TEXTURE im_optf_load_hs;
MR_TEXTURE im_optf_load_ok;
MR_TEXTURE im_optf_no_cards;
MR_TEXTURE im_optf_no_space;
MR_TEXTURE im_optf_overwrite;
MR_TEXTURE im_optf_return;
MR_TEXTURE im_optf_save_hs;
MR_TEXTURE im_optf_save_ok;
MR_TEXTURE im_optf_select_card;
MR_TEXTURE im_optf_view_hs;
MR_TEXTURE im_optg_insert_pad;
MR_TEXTURE im_optg_ctrl_config;
MR_TEXTURE im_optg_exit;
MR_TEXTURE im_optg_format;
MR_TEXTURE im_optg_check_save;
MR_TEXTURE im_optg_load_hs;
MR_TEXTURE im_optg_load_ok;
MR_TEXTURE im_optg_no_cards;
MR_TEXTURE im_optg_no_space;
MR_TEXTURE im_optg_overwrite;
MR_TEXTURE im_optg_return;
MR_TEXTURE im_optg_save_hs;
MR_TEXTURE im_optg_save_ok;
MR_TEXTURE im_optg_select_card;
MR_TEXTURE im_optg_view_hs;
MR_TEXTURE im_skip_hi_score_g;
MR_TEXTURE im_opti_insert_pad;
MR_TEXTURE im_opti_ctrl_config;
MR_TEXTURE im_opti_exit;
MR_TEXTURE im_opti_format;
MR_TEXTURE im_opti_check_save;
MR_TEXTURE im_opti_load_hs;
MR_TEXTURE im_opti_load_ok;
MR_TEXTURE im_opti_no_cards;
MR_TEXTURE im_opti_no_space;
MR_TEXTURE im_opti_overwrite;
MR_TEXTURE im_opti_return;
MR_TEXTURE im_opti_save_hs;
MR_TEXTURE im_opti_save_ok;
MR_TEXTURE im_opti_select_card;
MR_TEXTURE im_opti_view_hs;
MR_TEXTURE im_skip_hi_score_i;
MR_TEXTURE im_opts_insert_pad;
MR_TEXTURE im_opts_ctrl_config;
MR_TEXTURE im_opts_exit;
MR_TEXTURE im_opts_format;
MR_TEXTURE im_opts_check_save;
MR_TEXTURE im_opts_load_hs;
MR_TEXTURE im_opts_load_ok;
MR_TEXTURE im_opts_no_cards;
MR_TEXTURE im_opts_no_space;
MR_TEXTURE im_opts_overwrite;
MR_TEXTURE im_opts_return;
MR_TEXTURE im_opts_save_hs;
MR_TEXTURE im_opts_save_ok;
MR_TEXTURE im_opts_select_card;
MR_TEXTURE im_opts_view_hs;
MR_TEXTURE im_skip_hi_score_s;
MR_TEXTURE im_img862;
MR_TEXTURE im_img863;
MR_TEXTURE im_img864;
MR_TEXTURE im_img865;
MR_TEXTURE im_img866;
MR_TEXTURE im_img867;
MR_TEXTURE im_img868;
MR_TEXTURE im_img869;
MR_TEXTURE im_img870;
MR_TEXTURE im_img871;
MR_TEXTURE im_img872;
MR_TEXTURE im_img873;
MR_TEXTURE im_img874;
MR_TEXTURE im_img875;
MR_TEXTURE im_img876;
MR_TEXTURE im_img877;
MR_TEXTURE im_img878;
MR_TEXTURE im_img879;
MR_TEXTURE im_img880;
MR_TEXTURE im_img881;
MR_TEXTURE im_img882;
MR_TEXTURE im_img883;
MR_TEXTURE im_img884;
MR_TEXTURE im_img885;
MR_TEXTURE im_img886;
MR_TEXTURE im_img887;
MR_TEXTURE im_img888;
MR_TEXTURE im_img889;
MR_TEXTURE im_img890;
MR_TEXTURE im_img891;
MR_TEXTURE im_img892;
MR_TEXTURE im_img893;
MR_TEXTURE im_img894;
MR_TEXTURE im_img895;
MR_TEXTURE im_img896;
MR_TEXTURE im_img897;
MR_TEXTURE im_img898;
MR_TEXTURE im_img899;
MR_TEXTURE im_img900;
MR_TEXTURE im_img901;
MR_TEXTURE im_img902;
MR_TEXTURE im_img903;
MR_TEXTURE im_img904;
MR_TEXTURE im_img905;
MR_TEXTURE im_img906;
MR_TEXTURE im_img907;
MR_TEXTURE im_img908;
MR_TEXTURE im_img909;
MR_TEXTURE im_img910;
MR_TEXTURE im_img911;
MR_TEXTURE im_img912;
MR_TEXTURE im_opt_turtle_1;
MR_TEXTURE im_img914;
MR_TEXTURE im_img915;
MR_TEXTURE im_img916;
MR_TEXTURE im_img917;
MR_TEXTURE im_img918;
MR_TEXTURE im_img919;
MR_TEXTURE im_img920;
MR_TEXTURE im_img921;
MR_TEXTURE im_img922;
MR_TEXTURE im_img923;
MR_TEXTURE im_img924;
MR_TEXTURE im_img925;
MR_TEXTURE im_img926;
MR_TEXTURE im_img927;
MR_TEXTURE im_img928;
MR_TEXTURE im_img929;
MR_TEXTURE im_img930;
MR_TEXTURE im_img931;
MR_TEXTURE im_img932;
MR_TEXTURE im_img933;
MR_TEXTURE im_img934;
MR_TEXTURE im_img935;
MR_TEXTURE im_img936;
MR_TEXTURE im_img937;
MR_TEXTURE im_img938;
MR_TEXTURE im_img939;
MR_TEXTURE im_cav4pic;
MR_TEXTURE im_vol_grey;
MR_TEXTURE im_cav_grey;
MR_TEXTURE im_des_col;
MR_TEXTURE im_des_grey;
MR_TEXTURE im_for_col;
MR_TEXTURE im_for_grey;
MR_TEXTURE im_jun_col;
MR_TEXTURE im_jun_grey;
MR_TEXTURE im_org_col;
MR_TEXTURE im_org_grey;
MR_TEXTURE im_sky_col;
MR_TEXTURE im_sky_grey;
MR_TEXTURE im_sub_col;
MR_TEXTURE im_sub_grey;
MR_TEXTURE im_swp_col;
MR_TEXTURE im_swp_grey;
MR_TEXTURE im_vol_col;
MR_TEXTURE im_cav_col;
MR_TEXTURE im_img959;
MR_TEXTURE im_img960;
MR_TEXTURE im_img961;
MR_TEXTURE im_img962;
MR_TEXTURE im_img963;
MR_TEXTURE im_img964;
MR_TEXTURE im_img965;
MR_TEXTURE im_img966;
MR_TEXTURE im_img967;
MR_TEXTURE im_img968;
MR_TEXTURE im_img969;
MR_TEXTURE im_img970;
MR_TEXTURE im_img971;
MR_TEXTURE im_img972;
MR_TEXTURE im_img973;
MR_TEXTURE im_img974;
MR_TEXTURE im_img975;
MR_TEXTURE im_img976;
MR_TEXTURE im_img977;
MR_TEXTURE im_img978;
MR_TEXTURE im_img979;
MR_TEXTURE im_img980;
MR_TEXTURE im_img981;
MR_TEXTURE im_img982;
MR_TEXTURE im_img983;
MR_TEXTURE im_img984;
MR_TEXTURE im_img985;
MR_TEXTURE im_img986;
MR_TEXTURE im_img987;
MR_TEXTURE im_img988;
MR_TEXTURE im_img989;
MR_TEXTURE im_img990;
MR_TEXTURE im_img991;
MR_TEXTURE im_img992;
MR_TEXTURE im_img993;
MR_TEXTURE im_fire_fly_fata;
MR_TEXTURE im_fire_fly_fat;
MR_TEXTURE im_img996;
MR_TEXTURE im_img997;
MR_TEXTURE im_img998;
MR_TEXTURE im_img999;
MR_TEXTURE im_img1000;
MR_TEXTURE im_img1001;
MR_TEXTURE im_img1002;
MR_TEXTURE im_img1003;
MR_TEXTURE im_img1004;
MR_TEXTURE im_img1005;
MR_TEXTURE im_img1006;
MR_TEXTURE im_img1007;
MR_TEXTURE im_img1008;
MR_TEXTURE im_img1009;
MR_TEXTURE im_img1010;
MR_TEXTURE im_img1011;
MR_TEXTURE im_img1012;
MR_TEXTURE im_img1013;
MR_TEXTURE im_img1014;
MR_TEXTURE im_img1015;
MR_TEXTURE im_img1016;
MR_TEXTURE im_img1017;
MR_TEXTURE im_img1018;
MR_TEXTURE im_img1019;
MR_TEXTURE im_img1020;
MR_TEXTURE im_img1021;
MR_TEXTURE im_img1022;
MR_TEXTURE im_img1023;
MR_TEXTURE im_img1024;
MR_TEXTURE im_img1025;
MR_TEXTURE im_img1026;
MR_TEXTURE im_img1027;
MR_TEXTURE im_img1028;
MR_TEXTURE im_img1029;
MR_TEXTURE im_img1030;
MR_TEXTURE im_img1031;
MR_TEXTURE im_img1032;
MR_TEXTURE im_img1033;
MR_TEXTURE im_img1034;
MR_TEXTURE im_img1035;
MR_TEXTURE im_img1036;
MR_TEXTURE im_img1037;
MR_TEXTURE im_img1038;
MR_TEXTURE im_img1039;
MR_TEXTURE im_img1040;
MR_TEXTURE im_img1041;
MR_TEXTURE im_img1042;
MR_TEXTURE im_img1043;
MR_TEXTURE im_img1044;
MR_TEXTURE im_img1045;
MR_TEXTURE im_img1046;
MR_TEXTURE im_img1047;
MR_TEXTURE im_img1048;
MR_TEXTURE im_img1049;
MR_TEXTURE im_img1050;
MR_TEXTURE im_img1051;
MR_TEXTURE im_img1052;
MR_TEXTURE im_babyfroggold_0;
MR_TEXTURE im_babyfroggold_1;
MR_TEXTURE im_babyfroggold_2;
MR_TEXTURE im_babyfroggold_3;
MR_TEXTURE im_babyfroggold_4;
MR_TEXTURE im_babyfroggold_5;
MR_TEXTURE im_babyfroggold_6;
MR_TEXTURE im_flag1_0;
MR_TEXTURE im_flag1_1;
MR_TEXTURE im_flag1_2;
MR_TEXTURE im_flag1_3;
MR_TEXTURE im_flag1_4;
MR_TEXTURE im_flag2_0;
MR_TEXTURE im_flag2_1;
MR_TEXTURE im_flag2_2;
MR_TEXTURE im_flag2_3;
MR_TEXTURE im_flag2_4;
MR_TEXTURE im_flag3_0;
MR_TEXTURE im_flag3_1;
MR_TEXTURE im_flag3_2;
MR_TEXTURE im_flag3_3;
MR_TEXTURE im_flag3_4;
MR_TEXTURE im_flag4_0;
MR_TEXTURE im_flag4_1;
MR_TEXTURE im_flag4_2;
MR_TEXTURE im_flag4_3;
MR_TEXTURE im_flag4_4;
MR_TEXTURE im_flag5_0;
MR_TEXTURE im_flag5_1;
MR_TEXTURE im_flag5_2;
MR_TEXTURE im_flag5_3;
MR_TEXTURE im_flag5_4;
MR_TEXTURE im_img1085;
MR_TEXTURE im_img1086;
MR_TEXTURE im_img1087;
MR_TEXTURE im_img1088;
MR_TEXTURE im_img1089;
MR_TEXTURE im_img1090;
MR_TEXTURE im_img1091;
MR_TEXTURE im_img1092;
MR_TEXTURE im_img1093;
MR_TEXTURE im_img1094;
MR_TEXTURE im_ls_gold_frog;
MR_TEXTURE im_jump_to_it;
MR_TEXTURE im_croak;
MR_TEXTURE im_go;
MR_TEXTURE im_go_frogger;
MR_TEXTURE im_go_get_em;
MR_TEXTURE im_hop_to_it;
MR_TEXTURE im_quit;
MR_TEXTURE im_timeout;
MR_TEXTURE im_total_score;
MR_TEXTURE im_total_time;
MR_TEXTURE im_zone_complete;
MR_TEXTURE im_opt_no;
MR_TEXTURE im_opt_options;
MR_TEXTURE im_opt_paused;
MR_TEXTURE im_opt_start;
MR_TEXTURE im_opt_yes;
MR_TEXTURE im_next;
MR_TEXTURE im_opt_load_hs_sm;
MR_TEXTURE im_opt_ctrl_config;
MR_TEXTURE im_opt_exit;
MR_TEXTURE im_opt_format;
MR_TEXTURE im_opt_format2;
MR_TEXTURE im_opt_insert_pad;
MR_TEXTURE im_opt_load_hs;
MR_TEXTURE im_opt_check_save;
MR_TEXTURE im_opt_load_ok;
MR_TEXTURE im_opt_no_cards;
MR_TEXTURE im_opt_no_space;
MR_TEXTURE im_opt_overwrite;
MR_TEXTURE im_opt_return;
MR_TEXTURE im_opt_save_hs;
MR_TEXTURE im_opt_save_ok;
MR_TEXTURE im_opt_select_card;
MR_TEXTURE im_opt_view_hs;
MR_TEXTURE im_skip_hi_score;
MR_TEXTURE im_opt_gameover;
MR_TEXTURE im_timeout_s;
MR_TEXTURE im_timeout_g;
MR_TEXTURE im_timeout_i;
MR_TEXTURE im_timeout_f;
MR_TEXTURE im_img1136;
MR_TEXTURE im_img1137;
MR_TEXTURE im_img1138;
MR_TEXTURE im_img1139;
MR_TEXTURE im_img1140;
MR_TEXTURE im_img1141;
MR_TEXTURE im_img1142;
MR_TEXTURE im_img1143;
MR_TEXTURE im_img1144;
MR_TEXTURE im_img1145;
MR_TEXTURE im_img1146;
MR_TEXTURE im_img1147;
MR_TEXTURE im_img1148;
MR_TEXTURE im_img1149;
MR_TEXTURE im_img1150;
MR_TEXTURE im_img1151;
MR_TEXTURE im_img1152;
MR_TEXTURE im_img1153;
MR_TEXTURE im_img1154;
MR_TEXTURE im_img1155;
MR_TEXTURE im_opt_no_data;
MR_TEXTURE im_press_fire_s;
MR_TEXTURE im_bonus;
MR_TEXTURE im_mem_message;
MR_TEXTURE im_select_level;
MR_TEXTURE im_volmpic;
MR_TEXTURE im_orgmpic;
MR_TEXTURE im_submpic;
MR_TEXTURE im_formpic;
MR_TEXTURE im_junmpic;
MR_TEXTURE im_img1166;
MR_TEXTURE im_frog_shadow1;
MR_TEXTURE im_frog_shadow2;
MR_TEXTURE im_frog_shadow0;
MR_TEXTURE im_img1170;
MR_TEXTURE im_img1171;
MR_TEXTURE im_img1172;
MR_TEXTURE im_img1173;
MR_TEXTURE im_img1174;
MR_TEXTURE im_img1175;
MR_TEXTURE im_img1176;
MR_TEXTURE im_img1177;
MR_TEXTURE im_img1178;
MR_TEXTURE im_img1179;
MR_TEXTURE im_img1180;
MR_TEXTURE im_img1181;
MR_TEXTURE im_img1182;
MR_TEXTURE im_img1183;
MR_TEXTURE im_img1184;
MR_TEXTURE im_img1185;
MR_TEXTURE im_img1186;
MR_TEXTURE im_img1187;
MR_TEXTURE im_img1188;
MR_TEXTURE im_img1189;
MR_TEXTURE im_img1190;
MR_TEXTURE im_img1191;
MR_TEXTURE im_img1192;
MR_TEXTURE im_img1193;
MR_TEXTURE im_img1194;
MR_TEXTURE im_img1195;
MR_TEXTURE im_img1196;
MR_TEXTURE im_img1197;
MR_TEXTURE im_img1198;
MR_TEXTURE im_img1199;
MR_TEXTURE im_img1200;
MR_TEXTURE im_img1201;
MR_TEXTURE im_img1202;
MR_TEXTURE im_img1203;
MR_TEXTURE im_img1204;
MR_TEXTURE im_img1205;
MR_TEXTURE im_img1206;
MR_TEXTURE im_img1207;
MR_TEXTURE im_img1208;
MR_TEXTURE im_img1209;
MR_TEXTURE im_img1210;
MR_TEXTURE im_img1211;
MR_TEXTURE im_img1212;
MR_TEXTURE im_img1213;
MR_TEXTURE im_img1214;
MR_TEXTURE im_img1215;
MR_TEXTURE im_img1216;
MR_TEXTURE im_32x32_colon;
MR_TEXTURE im_cav3pic;
MR_TEXTURE im_mem_message_s;
MR_TEXTURE im_mem_message_g;
MR_TEXTURE im_mem_message_i;
MR_TEXTURE im_mem_message_f;
MR_TEXTURE im_opt_save_failed;
MR_TEXTURE im_opt_load_failed;
MR_TEXTURE im_opt_format_failed;
MR_TEXTURE im_optf_save_failed;
MR_TEXTURE im_optf_load_failed;
MR_TEXTURE im_optf_format_failed;
MR_TEXTURE im_optg_save_failed;
MR_TEXTURE im_optg_load_failed;
MR_TEXTURE im_optg_format_failed;
MR_TEXTURE im_opti_save_failed;
MR_TEXTURE im_opti_load_failed;
MR_TEXTURE im_opti_format_failed;
MR_TEXTURE im_opts_save_failed;
MR_TEXTURE im_opts_load_failed;
MR_TEXTURE im_opts_format_failed;
MR_TEXTURE im_optf_no_data;
MR_TEXTURE im_optg_no_data;
MR_TEXTURE im_opti_no_data;
MR_TEXTURE im_opts_no_data;
MR_TEXTURE im_img1242;
MR_TEXTURE im_img1243;
MR_TEXTURE im_img1244;
MR_TEXTURE im_img1245;
MR_TEXTURE im_img1246;
MR_TEXTURE im_img1247;
MR_TEXTURE im_img1248;
MR_TEXTURE im_img1249;
MR_TEXTURE im_img1250;
MR_TEXTURE im_img1251;
MR_TEXTURE im_img1252;
MR_TEXTURE im_img1253;
MR_TEXTURE im_img1254;
MR_TEXTURE im_img1255;
MR_TEXTURE im_img1256;
MR_TEXTURE im_img1257;
MR_TEXTURE im_img1258;
MR_TEXTURE im_img1259;
MR_TEXTURE im_img1260;
MR_TEXTURE im_img1261;
MR_TEXTURE im_img1262;
MR_TEXTURE im_img1263;
MR_TEXTURE im_img1264;
MR_TEXTURE im_img1265;
MR_TEXTURE im_img1266;
MR_TEXTURE im_img1267;
MR_TEXTURE im_img1268;
MR_TEXTURE im_img1269;
MR_TEXTURE im_img1270;
MR_TEXTURE im_img1271;
MR_TEXTURE im_img1272;
MR_TEXTURE im_img1273;
MR_TEXTURE im_img1274;
MR_TEXTURE im_img1275;
MR_TEXTURE im_img1276;
MR_TEXTURE im_img1277;
MR_TEXTURE im_img1278;
MR_TEXTURE im_img1279;
MR_TEXTURE im_img1280;
MR_TEXTURE im_img1281;
MR_TEXTURE im_img1282;
MR_TEXTURE im_img1283;
MR_TEXTURE im_img1284;
MR_TEXTURE im_img1285;
MR_TEXTURE im_img1286;
MR_TEXTURE im_img1287;
MR_TEXTURE im_img1288;
MR_TEXTURE im_img1289;
MR_TEXTURE im_img1290;
MR_TEXTURE im_img1291;
MR_TEXTURE im_img1292;
MR_TEXTURE im_img1293;
MR_TEXTURE im_img1294;
MR_TEXTURE im_img1295;
MR_TEXTURE im_img1296;
MR_TEXTURE im_img1297;
MR_TEXTURE im_img1298;
MR_TEXTURE im_img1299;
MR_TEXTURE im_img1300;
MR_TEXTURE im_img1301;
MR_TEXTURE im_img1302;
MR_TEXTURE im_img1303;
MR_TEXTURE im_img1304;
MR_TEXTURE im_img1305;
MR_TEXTURE im_img1306;
MR_TEXTURE im_img1307;
MR_TEXTURE im_img1308;
MR_TEXTURE im_img1309;
MR_TEXTURE im_img1310;
MR_TEXTURE im_img1311;
MR_TEXTURE im_img1312;
MR_TEXTURE im_img1313;
MR_TEXTURE im_img1314;
MR_TEXTURE im_img1315;
MR_TEXTURE im_img1316;
MR_TEXTURE im_img1317;
MR_TEXTURE im_img1318;
MR_TEXTURE im_img1319;
MR_TEXTURE im_img1320;
MR_TEXTURE im_img1321;
MR_TEXTURE im_img1322;
MR_TEXTURE im_img1323;
MR_TEXTURE im_img1324;
MR_TEXTURE im_img1325;
MR_TEXTURE im_img1326;
MR_TEXTURE im_img1327;
MR_TEXTURE im_img1328;
MR_TEXTURE im_img1329;
MR_TEXTURE im_img1330;
MR_TEXTURE im_img1331;
MR_TEXTURE im_img1332;
MR_TEXTURE im_img1333;
MR_TEXTURE im_img1334;
MR_TEXTURE im_img1335;
MR_TEXTURE im_img1336;
MR_TEXTURE im_img1337;
MR_TEXTURE im_img1338;
MR_TEXTURE im_img1339;
MR_TEXTURE im_img1340;
MR_TEXTURE im_img1341;
MR_TEXTURE im_img1342;
MR_TEXTURE im_img1343;
MR_TEXTURE im_img1344;
MR_TEXTURE im_img1345;
MR_TEXTURE im_img1346;
MR_TEXTURE im_img1347;
MR_TEXTURE im_img1348;
MR_TEXTURE im_img1349;
MR_TEXTURE im_img1350;
MR_TEXTURE im_img1351;
MR_TEXTURE im_img1352;
MR_TEXTURE im_img1353;
MR_TEXTURE im_img1354;
MR_TEXTURE im_img1355;
MR_TEXTURE im_img1356;
MR_TEXTURE im_img1357;
MR_TEXTURE im_jun_floor1;
MR_TEXTURE im_img1359;
MR_TEXTURE im_img1360;
MR_TEXTURE im_img1361;
MR_TEXTURE im_img1362;
MR_TEXTURE im_img1363;
MR_TEXTURE im_img1364;
MR_TEXTURE im_img1365;
MR_TEXTURE im_img1366;
MR_TEXTURE im_img1367;
MR_TEXTURE im_img1368;
MR_TEXTURE im_img1369;
MR_TEXTURE im_img1370;
MR_TEXTURE im_img1371;
MR_TEXTURE im_img1372;
MR_TEXTURE im_img1373;
MR_TEXTURE im_img1374;
MR_TEXTURE im_img1375;
MR_TEXTURE im_img1376;
MR_TEXTURE im_img1377;
MR_TEXTURE im_img1378;
MR_TEXTURE im_img1379;
MR_TEXTURE im_img1380;
MR_TEXTURE im_img1381;
MR_TEXTURE im_img1382;
MR_TEXTURE im_img1383;
MR_TEXTURE im_1up1;
MR_TEXTURE im_img1385;
MR_TEXTURE im_img1386;
MR_TEXTURE im_img1387;
MR_TEXTURE im_img1388;
MR_TEXTURE im_img1389;
MR_TEXTURE im_img1390;
MR_TEXTURE im_img1391;
MR_TEXTURE im_img1392;
MR_TEXTURE im_img1393;
MR_TEXTURE im_img1394;
MR_TEXTURE im_img1395;
MR_TEXTURE im_img1396;
MR_TEXTURE im_img1397;
MR_TEXTURE im_img1398;
MR_TEXTURE im_img1399;
MR_TEXTURE im_img1400;
MR_TEXTURE im_img1401;
MR_TEXTURE im_img1402;
MR_TEXTURE im_img1403;
MR_TEXTURE im_img1404;
MR_TEXTURE im_img1405;
MR_TEXTURE im_img1406;
MR_TEXTURE im_img1407;
MR_TEXTURE im_img1408;
MR_TEXTURE im_img1409;
MR_TEXTURE im_img1410;
MR_TEXTURE im_img1411;
MR_TEXTURE im_img1412;
MR_TEXTURE im_img1413;
MR_TEXTURE im_img1414;
MR_TEXTURE im_img1415;
MR_TEXTURE im_img1416;
MR_TEXTURE im_img1417;
MR_TEXTURE im_img1418;
MR_TEXTURE im_img1419;
MR_TEXTURE im_img1420;
MR_TEXTURE im_img1421;
MR_TEXTURE im_img1422;
MR_TEXTURE im_img1423;
MR_TEXTURE im_img1424;
MR_TEXTURE im_opt_arrow_small_right;
MR_TEXTURE im_opt_arrow_small_left;
MR_TEXTURE im_opt_bank3;
MR_TEXTURE im_opt_joypad;
MR_TEXTURE im_opt_joypad_layout4;
MR_TEXTURE im_opt_joypad_layout2;
MR_TEXTURE im_opt_joypad_layout3;
MR_TEXTURE im_opt_joypad_layout1;
MR_TEXTURE im_img1433;
MR_TEXTURE im_img1434;
MR_TEXTURE im_img1435;
MR_TEXTURE im_img1436;
MR_TEXTURE im_img1437;
MR_TEXTURE im_img1438;
MR_TEXTURE im_img1439;
MR_TEXTURE im_img1440;
MR_TEXTURE im_img1441;
MR_TEXTURE im_optf_joypad_layout4;
MR_TEXTURE im_optf_joypad_layout2;
MR_TEXTURE im_optf_joypad_layout3;
MR_TEXTURE im_optf_joypad_layout1;
MR_TEXTURE im_optg_joypad_layout4;
MR_TEXTURE im_optg_joypad_layout2;
MR_TEXTURE im_optg_joypad_layout3;
MR_TEXTURE im_optg_joypad_layout1;
MR_TEXTURE im_opti_joypad_layout4;
MR_TEXTURE im_opti_joypad_layout2;
MR_TEXTURE im_opti_joypad_layout3;
MR_TEXTURE im_opti_joypad_layout1;
MR_TEXTURE im_opts_joypad_layout4;
MR_TEXTURE im_opts_joypad_layout2;
MR_TEXTURE im_opts_joypad_layout3;
MR_TEXTURE im_opts_joypad_layout1;
MR_TEXTURE im_img1458;
MR_TEXTURE im_opt_menu_cloud;
MR_TEXTURE im_img1460;
MR_TEXTURE im_img1461;
MR_TEXTURE im_img1462;
MR_TEXTURE im_img1463;
MR_TEXTURE im_img1464;
MR_TEXTURE im_img1465;
MR_TEXTURE im_img1466;
MR_TEXTURE im_img1467;
MR_TEXTURE im_img1468;
MR_TEXTURE im_img1469;
MR_TEXTURE im_img1470;
MR_TEXTURE im_img1471;
MR_TEXTURE im_img1472;
MR_TEXTURE im_img1473;
MR_TEXTURE im_bison6;
MR_TEXTURE im_bison2;
MR_TEXTURE im_bison3;
MR_TEXTURE im_bison4;
MR_TEXTURE im_bison5;
MR_TEXTURE im_bison1;
MR_TEXTURE im_img1480;
MR_TEXTURE im_img1481;
MR_TEXTURE im_img1482;
MR_TEXTURE im_img1483;
MR_TEXTURE im_img1484;
MR_TEXTURE im_img1485;
MR_TEXTURE im_won;
MR_TEXTURE im_lost;
MR_TEXTURE im_play_again;
MR_TEXTURE im_played;
MR_TEXTURE im_choose_course;
MR_TEXTURE im_won_f;
MR_TEXTURE im_lost_f;
MR_TEXTURE im_play_again_f;
MR_TEXTURE im_played_f;
MR_TEXTURE im_choose_course_f;
MR_TEXTURE im_won_g;
MR_TEXTURE im_lost_g;
MR_TEXTURE im_play_again_g;
MR_TEXTURE im_played_g;
MR_TEXTURE im_choose_course_g;
MR_TEXTURE im_won_i;
MR_TEXTURE im_lost_i;
MR_TEXTURE im_play_again_i;
MR_TEXTURE im_played_i;
MR_TEXTURE im_choose_course_i;
MR_TEXTURE im_won_s;
MR_TEXTURE im_lost_s;
MR_TEXTURE im_play_again_s;
MR_TEXTURE im_played_s;
MR_TEXTURE im_choose_course_s;
MR_TEXTURE im_extra_life5;
MR_TEXTURE im_extra_life2;
MR_TEXTURE im_extra_life3;
MR_TEXTURE im_extra_life4;
MR_TEXTURE im_extra_life1;
MR_TEXTURE im_time_bada;
MR_TEXTURE im_time_bad;
MR_TEXTURE im_img1518;
MR_TEXTURE im_img1519;
MR_TEXTURE im_img1520;
MR_TEXTURE im_img1521;
MR_TEXTURE im_img1522;
MR_TEXTURE im_img1523;
MR_TEXTURE im_img1524;
MR_TEXTURE im_img1525;
MR_TEXTURE im_img1526;
MR_TEXTURE im_img1527;
MR_TEXTURE im_time_plus5;
MR_TEXTURE im_time_plus10;
MR_TEXTURE im_time_plus2;
MR_TEXTURE im_score_minus500;
MR_TEXTURE im_img1532;
MR_TEXTURE im_img1533;
MR_TEXTURE im_img1534;
MR_TEXTURE im_img1535;
MR_TEXTURE im_img1536;
MR_TEXTURE im_img1537;
MR_TEXTURE im_img1538;
MR_TEXTURE im_img1539;
MR_TEXTURE im_img1540;
MR_TEXTURE im_img1541;
MR_TEXTURE im_img1542;
MR_TEXTURE im_img1543;
MR_TEXTURE im_img1544;
MR_TEXTURE im_img1545;
MR_TEXTURE im_select3;
MR_TEXTURE im_select3_f;
MR_TEXTURE im_select3_g;
MR_TEXTURE im_select3_i;
MR_TEXTURE im_select3_s;
MR_TEXTURE im_start_race;
MR_TEXTURE im_start_race_f;
MR_TEXTURE im_start_race_g;
MR_TEXTURE im_start_race_i;
MR_TEXTURE im_start_race_s;
MR_TEXTURE im_img1556;
MR_TEXTURE im_img1557;
MR_TEXTURE im_img1558;
MR_TEXTURE im_img1559;
MR_TEXTURE im_img1560;
MR_TEXTURE im_img1561;
MR_TEXTURE im_img1562;
MR_TEXTURE im_img1563;
MR_TEXTURE im_img1564;
MR_TEXTURE im_img1565;
MR_TEXTURE im_img1566;
MR_TEXTURE im_img1567;
MR_TEXTURE im_img1568;
MR_TEXTURE im_sel_loading;
MR_TEXTURE im_self_loading;
MR_TEXTURE im_selg_loading;
MR_TEXTURE im_seli_loading;
MR_TEXTURE im_sels_loading;
MR_TEXTURE im_optf_format2;
MR_TEXTURE im_optg_format2;
MR_TEXTURE im_opti_format2;
MR_TEXTURE im_opts_format2;
MR_TEXTURE im_opt_big_continue;
MR_TEXTURE im_optf_big_continue;
MR_TEXTURE im_optg_big_continue;
MR_TEXTURE im_opti_big_continue;
MR_TEXTURE im_opts_big_continue;
MR_TEXTURE im_opt_now_saving;
MR_TEXTURE im_opt_now_formatting;
MR_TEXTURE im_opt_now_loading;
MR_TEXTURE im_opt_now_checking;
MR_TEXTURE im_optf_now_saving;
MR_TEXTURE im_optf_now_formatting;
MR_TEXTURE im_optf_now_loading;
MR_TEXTURE im_optf_now_checking;
MR_TEXTURE im_optg_now_saving;
MR_TEXTURE im_optg_now_formatting;
MR_TEXTURE im_optg_now_loading;
MR_TEXTURE im_optg_now_checking;
MR_TEXTURE im_opti_now_saving;
MR_TEXTURE im_opti_now_formatting;
MR_TEXTURE im_opti_now_loading;
MR_TEXTURE im_opti_now_checking;
MR_TEXTURE im_opts_now_saving;
MR_TEXTURE im_opts_now_formatting;
MR_TEXTURE im_opts_now_loading;
MR_TEXTURE im_opts_now_checking;
MR_TEXTURE im_img1603;
MR_TEXTURE im_multback;
MR_TEXTURE im_img1605;
MR_TEXTURE im_img1606;
MR_TEXTURE im_img1607;
MR_TEXTURE im_frog_smoke1;
MR_TEXTURE im_img1609;
MR_TEXTURE im_img1610;
MR_TEXTURE im_img1611;
MR_TEXTURE im_img1612;
MR_TEXTURE im_img1613;
MR_TEXTURE im_img1614;
MR_TEXTURE im_img1615;
MR_TEXTURE im_img1616;
MR_TEXTURE im_img1617;
MR_TEXTURE im_img1618;
MR_TEXTURE im_img1619;
MR_TEXTURE im_vol1name;
MR_TEXTURE im_vol2name;
MR_TEXTURE im_vol3name;
MR_TEXTURE im_volmname;
MR_TEXTURE im_des5name;
MR_TEXTURE im_des2name;
MR_TEXTURE im_des3name;
MR_TEXTURE im_des4name;
MR_TEXTURE im_des1name;
MR_TEXTURE im_sky4name;
MR_TEXTURE im_sky2name;
MR_TEXTURE im_sky3name;
MR_TEXTURE im_sky1name;
MR_TEXTURE im_formname;
MR_TEXTURE im_for2name;
MR_TEXTURE im_for1name;
MR_TEXTURE im_jun1name;
MR_TEXTURE im_junmname;
MR_TEXTURE im_cav4name;
MR_TEXTURE im_cav3name;
MR_TEXTURE im_cav1name;
MR_TEXTURE im_submname;
MR_TEXTURE im_sub2name;
MR_TEXTURE im_sub3name;
MR_TEXTURE im_sub4name;
MR_TEXTURE im_sub5name;
MR_TEXTURE im_sub1name;
MR_TEXTURE im_orgmname;
MR_TEXTURE im_org2name;
MR_TEXTURE im_org3name;
MR_TEXTURE im_org4name;
MR_TEXTURE im_org5name;
MR_TEXTURE im_org1name;
MR_TEXTURE im_swp4name;
MR_TEXTURE im_swp2name;
MR_TEXTURE im_swp3name;
MR_TEXTURE im_swp1name;
MR_TEXTURE im_med_9;
MR_TEXTURE im_med_1;
MR_TEXTURE im_med_2;
MR_TEXTURE im_med_3;
MR_TEXTURE im_med_4;
MR_TEXTURE im_med_5;
MR_TEXTURE im_med_7;
MR_TEXTURE im_med_8;
MR_TEXTURE im_med_0;
MR_TEXTURE im_med_6;
MR_TEXTURE im_swp5name;
MR_TEXTURE im_img1668;
MR_TEXTURE im_img1669;
MR_TEXTURE im_press_fire;
MR_TEXTURE im_select_level_f;
MR_TEXTURE im_select_level_g;
MR_TEXTURE im_select_level_i;
MR_TEXTURE im_select_level_s;
MR_TEXTURE im_img1675;
MR_TEXTURE im_img1676;
MR_TEXTURE im_img1677;
MR_TEXTURE im_img1678;
MR_TEXTURE im_img1679;
MR_TEXTURE im_img1680;
MR_TEXTURE im_opt_flag_span2;
MR_TEXTURE im_opt_flag_brit2;
MR_TEXTURE im_opt_flag_fren1;
MR_TEXTURE im_opt_flag_fren2;
MR_TEXTURE im_opt_flag_germ1;
MR_TEXTURE im_opt_flag_germ2;
MR_TEXTURE im_opt_flag_ital1;
MR_TEXTURE im_opt_flag_ital2;
MR_TEXTURE im_opt_flag_span1;
MR_TEXTURE im_opt_flag_brit1;
MR_TEXTURE im_img1691;
MR_TEXTURE im_img1692;
MR_TEXTURE im_select4;
MR_TEXTURE im_select4_f;
MR_TEXTURE im_select4_g;
MR_TEXTURE im_select4_i;
MR_TEXTURE im_select4_s;
MR_TEXTURE im_img1698;
MR_TEXTURE im_img1699;
MR_TEXTURE im_img1700;
MR_TEXTURE im_img1701;
MR_TEXTURE im_img1702;
MR_TEXTURE im_opt_race;
MR_TEXTURE im_optf_load_hs_sm;
MR_TEXTURE im_optg_load_hs_sm;
MR_TEXTURE im_opti_load_hs_sm;
MR_TEXTURE im_opts_load_hs_sm;
MR_TEXTURE im_select5;
MR_TEXTURE im_select5_f;
MR_TEXTURE im_select5_g;
MR_TEXTURE im_select5_i;
MR_TEXTURE im_select5_s;
MR_TEXTURE im_img1713;
MR_TEXTURE im_img1714;
MR_TEXTURE im_img1715;
MR_TEXTURE im_img1716;
MR_TEXTURE im_img1717;
MR_TEXTURE im_img1718;
MR_TEXTURE im_img1719;
MR_TEXTURE im_img1720;
MR_TEXTURE im_img1721;
MR_TEXTURE im_img1722;
MR_TEXTURE im_img1723;
MR_TEXTURE im_img1724;
MR_TEXTURE im_img1725;
MR_TEXTURE im_img1726;
MR_TEXTURE im_img1727;
MR_TEXTURE im_img1728;
MR_TEXTURE im_img1729;
MR_TEXTURE im_img1730;
MR_TEXTURE im_img1731;
MR_TEXTURE im_img1732;
MR_TEXTURE im_img1733;
MR_TEXTURE im_img1734;
MR_TEXTURE im_img1735;
MR_TEXTURE im_img1736;
MR_TEXTURE im_img1737;
MR_TEXTURE im_img1738;
MR_TEXTURE im_img1739;
MR_TEXTURE im_img1740;
MR_TEXTURE im_img1741;
MR_TEXTURE im_img1742;
MR_TEXTURE im_img1743;
MR_TEXTURE im_img1744;
MR_TEXTURE im_img1745;
MR_TEXTURE im_img1746;
MR_TEXTURE im_img1747;
MR_TEXTURE im_img1748;
MR_TEXTURE im_img1749;
MR_TEXTURE im_img1750;
MR_TEXTURE im_img1751;
MR_TEXTURE im_img1752;
MR_TEXTURE im_img1753;
MR_TEXTURE im_img1754;
MR_TEXTURE im_img1755;
MR_TEXTURE im_img1756;
MR_TEXTURE im_img1757;
MR_TEXTURE im_img1758;
MR_TEXTURE im_img1759;
MR_TEXTURE im_img1760;
MR_TEXTURE im_img1761;
MR_TEXTURE im_img1762;
MR_TEXTURE im_img1763;
MR_TEXTURE im_img1764;
MR_TEXTURE im_img1765;
MR_TEXTURE im_img1766;
MR_TEXTURE im_img1767;
MR_TEXTURE im_img1768;
MR_TEXTURE im_img1769;
MR_TEXTURE im_img1770;
MR_TEXTURE im_img1771;
MR_TEXTURE im_img1772;
MR_TEXTURE im_img1773;
MR_TEXTURE im_img1774;
MR_TEXTURE im_img1775;
MR_TEXTURE im_img1776;
MR_TEXTURE im_img1777;
MR_TEXTURE im_img1778;
MR_TEXTURE im_img1779;
MR_TEXTURE im_img1780;
MR_TEXTURE im_img1781;
MR_TEXTURE im_img1782;
MR_TEXTURE im_img1783;
MR_TEXTURE im_img1784;
MR_TEXTURE im_img1785;
MR_TEXTURE im_img1786;
MR_TEXTURE im_img1787;
MR_TEXTURE im_img1788;
MR_TEXTURE im_img1789;
MR_TEXTURE im_img1790;
MR_TEXTURE im_img1791;
MR_TEXTURE im_img1792;
MR_TEXTURE im_img1793;
MR_TEXTURE im_img1794;
MR_TEXTURE im_img1795;
MR_TEXTURE im_img1796;
MR_TEXTURE im_froglogo;
MR_TEXTURE im_img1798;
MR_TEXTURE im_img1799;
MR_TEXTURE im_img1800;
MR_TEXTURE im_opt_sec;
MR_TEXTURE im_optf_sec;
MR_TEXTURE im_optg_sec;
MR_TEXTURE im_opti_sec;
MR_TEXTURE im_opts_sec;
MR_TEXTURE im_rank_equal;
MR_TEXTURE im_rank_2;
MR_TEXTURE im_rank_3;
MR_TEXTURE im_rank_4;
MR_TEXTURE im_rank_1;
MR_TEXTURE im_play_off;
MR_TEXTURE im_play_off_f;
MR_TEXTURE im_play_off_g;
MR_TEXTURE im_play_off_i;
MR_TEXTURE im_play_off_s;
MR_TEXTURE im_img1816;
MR_TEXTURE im_select7;
MR_TEXTURE im_select6;
MR_TEXTURE im_select7_f;
MR_TEXTURE im_select6_f;
MR_TEXTURE im_select7_g;
MR_TEXTURE im_select6_g;
MR_TEXTURE im_select7_i;
MR_TEXTURE im_select6_i;
MR_TEXTURE im_select6_s;
MR_TEXTURE im_select7_s;
MR_TEXTURE im_img1827;
MR_TEXTURE im_img1828;
MR_TEXTURE im_img1829;
MR_TEXTURE im_img1830;
