#/******************************************************************************
#/*%%%% mr_m_hdr.i
#/*------------------------------------------------------------------------------
#/*
#/*	Header file for MIPS assembler polygon rendering modules.
#/*
#/*	CHANGED		PROGRAMMER	REASON
#/*	-------  	----------  	------
#/*	18.9.96		Dean Ashton	Created
#/*	
#/*%%%**************************************************************************/

.include "macro.inc"
.include "utils.i"

# ---- SVECTOR ----
new_struct
struct_entry SVEC_vx, 2
struct_entry SVEC_vy, 2
struct_entry SVEC_vz, 2
struct_entry SVEC_pad, 2	
struct_entry sizeof_SVEC, 0


# ---- VECTOR ----
new_struct
struct_entry VEC_vx, 4
struct_entry VEC_vy, 4
struct_entry VEC_vz, 4
struct_entry VEC_pad, 4
struct_entry sizeof_VEC, 0


# ---- MATRIX ----
new_struct
struct_entry MAT_r11r12, 0	# Used for GTE accesses
struct_entry MAT_r11, 2
struct_entry MAT_r12, 2
struct_entry MAT_r13r21, 0	# Used for GTE accesses
struct_entry MAT_r13, 2
struct_entry MAT_r21, 2
struct_entry MAT_r22r23, 0	# Used for GTE accesses
struct_entry MAT_r22, 2
struct_entry MAT_r23, 2
struct_entry MAT_r31r32, 0	# Used for GTE accesses
struct_entry MAT_r31, 2
struct_entry MAT_r32, 2
struct_entry MAT_r33pad, 0	# Used for GTE accesses
struct_entry MAT_r33, 2
struct_entry MAT_pad, 2
struct_entry sizeof_MAT, 0


# ---- MR_TEXTURE ----
new_struct
struct_entry TEX_flags, 2
struct_entry TEX_w, 1
struct_entry TEX_h, 1
struct_entry TEX_u0, 1
struct_entry TEX_v0, 1
struct_entry TEX_clut_id, 2
struct_entry TEX_u1, 1
struct_entry TEX_v1, 1
struct_entry TEX_tpage_id, 2
struct_entry TEX_u2, 1
struct_entry TEX_v2, 1
struct_entry TEX_u3, 1
struct_entry TEX_v3, 1
struct_entry sizeof_TEXTURE, 0


# ---- MR_MESH_PARAM ----
new_struct
struct_entry MP_p0, 4
struct_entry MP_p1, 4
struct_entry MP_p2, 4
struct_entry MP_p3, 4
struct_entry MP_n0, 4
struct_entry MP_n1, 4
struct_entry MP_n2, 4
struct_entry MP_n3, 4
struct_entry MP_work_ot, 4
struct_entry MP_otz_shift, 2
struct_entry MP_ot_otz_delta, 2
struct_entry MP_ot_size, 4
struct_entry MP_ot_clip, 4
struct_entry MP_ot_view_origin_z, 4
struct_entry MP_nclip_result, 4
struct_entry MP_poly_otz, 4
struct_entry MP_mem_ptr, 4
struct_entry MP_prim_ptr, 4
struct_entry MP_prims, 4
struct_entry sizeof_MESH_PARAM, 0



# ---- MR_MPRIM_F3 ----
new_struct
struct_entry MPF3_p0, 2
struct_entry MPF3_p1, 2
struct_entry MPF3_p2, 2
struct_entry MPF3_n0, 2
struct_entry MPF3_cvec, 4
struct_entry sizeof_MPF3, 0


# ---- MR_MPRIM_F4 ----
new_struct
struct_entry MPF4_p0, 2
struct_entry MPF4_p1, 2
struct_entry MPF4_p2, 2
struct_entry MPF4_p3, 2
struct_entry MPF4_n0, 2
struct_entry MPF4_pad, 2
struct_entry MPF4_cvec, 4
struct_entry sizeof_MPF4, 0


# ---- MR_MPRIM_FT3 ----
new_struct
struct_entry MPFT3_p0, 2
struct_entry MPFT3_p1, 2
struct_entry MPFT3_p2, 2
struct_entry MPFT3_n0, 2
struct_entry MPFT3_u0, 1
struct_entry MPFT3_v0, 1
struct_entry MPFT3_clut_id, 2
struct_entry MPFT3_u1, 1
struct_entry MPFT3_v1, 1
struct_entry MPFT3_tpage_id, 2
struct_entry MPFT3_u2, 1
struct_entry MPFT3_v2, 1
struct_entry MPFT3_image_id, 2
struct_entry MPFT3_cvec, 4
struct_entry sizeof_MPFT3, 0


# ---- MR_MPRIM_FT4 ----
new_struct
struct_entry MPFT4_p0, 2
struct_entry MPFT4_p1, 2
struct_entry MPFT4_p2, 2
struct_entry MPFT4_p3, 2
struct_entry MPFT4_n0, 2
struct_entry MPFT4_image_id, 2
struct_entry MPFT4_u0, 1
struct_entry MPFT4_v0, 1
struct_entry MPFT4_clut_id, 2
struct_entry MPFT4_u1, 1
struct_entry MPFT4_v1, 1
struct_entry MPFT4_tpage_id, 2
struct_entry MPFT4_u2, 1
struct_entry MPFT4_v2, 1
struct_entry MPFT4_u3, 1
struct_entry MPFT4_v3, 1
struct_entry MPFT4_cvec, 4
struct_entry sizeof_MPFT4, 0


# ---- MR_MPRIM_G3 ----
new_struct
struct_entry MPG3_p0, 2
struct_entry MPG3_p1, 2
struct_entry MPG3_p2, 2
struct_entry MPG3_n0, 2
struct_entry MPG3_n1, 2
struct_entry MPG3_n2, 2
struct_entry MPG3_cvec, 4
struct_entry sizeof_MPG3, 0


# ---- MR_MPRIM_G4 ----
new_struct
struct_entry MPG4_p0, 2
struct_entry MPG4_p1, 2
struct_entry MPG4_p2, 2
struct_entry MPG4_p3, 2
struct_entry MPG4_n0, 2
struct_entry MPG4_n1, 2
struct_entry MPG4_n2, 2
struct_entry MPG4_n3, 2
struct_entry MPG4_cvec, 4
struct_entry sizeof_MPG4, 0


# ---- MR_MPRIM_GT3 ----
new_struct
struct_entry MPGT3_p0, 2
struct_entry MPGT3_p1, 2
struct_entry MPGT3_p2, 2
struct_entry MPGT3_n0, 2
struct_entry MPGT3_n1, 2
struct_entry MPGT3_n2, 2
struct_entry MPGT3_u0, 1
struct_entry MPGT3_v0, 1
struct_entry MPGT3_clut_id, 2
struct_entry MPGT3_u1, 1
struct_entry MPGT3_v1, 1
struct_entry MPGT3_tpage_id, 2
struct_entry MPGT3_u2, 1
struct_entry MPGT3_v2, 1
struct_entry MPGT3_image_id, 2
struct_entry MPGT3_cvec, 4
struct_entry sizeof_MPGT3, 0


# ---- MR_MPRIM_GT4 ----
new_struct
struct_entry MPGT4_p0, 2
struct_entry MPGT4_p1, 2
struct_entry MPGT4_p2, 2
struct_entry MPGT4_p3, 2
struct_entry MPGT4_n0, 2
struct_entry MPGT4_n1, 2
struct_entry MPGT4_n2, 2
struct_entry MPGT4_n3, 2
struct_entry MPGT4_u0, 1
struct_entry MPGT4_v0, 1
struct_entry MPGT4_clut_id, 2
struct_entry MPGT4_u1, 1
struct_entry MPGT4_v1, 1
struct_entry MPGT4_tpage_id, 2
struct_entry MPGT4_u2, 1
struct_entry MPGT4_v2, 1
struct_entry MPGT4_u3, 1
struct_entry MPGT4_v3, 1
struct_entry MPGT4_image_id, 2
struct_entry MPGT4_pad, 2
struct_entry MPGT4_cvec, 4
struct_entry sizeof_MPGT4, 0


# ---- MR_MPRIM_E3 ----
new_struct
struct_entry MPE3_p0, 2
struct_entry MPE3_p1, 2
struct_entry MPE3_p2, 2
struct_entry MPE3_en0, 2
struct_entry MPE3_en1, 2
struct_entry MPE3_en2, 2
struct_entry MPE3_n0, 2
struct_entry MPE3_pad, 2
struct_entry MPE3_cvec, 4
struct_entry sizeof_MPE3, 0


# ---- MR_MPRIM_E4 ----
new_struct
struct_entry MPE4_p0, 2
struct_entry MPE4_p1, 2
struct_entry MPE4_p2, 2
struct_entry MPE4_p3, 2
struct_entry MPE4_en0, 2
struct_entry MPE4_en1, 2
struct_entry MPE4_en2, 2
struct_entry MPE4_en3, 2
struct_entry MPE4_n0, 2
struct_entry MPE4_pad, 2
struct_entry MPE4_cvec, 4
struct_entry sizeof_MPE4, 0


# ---- MR_MPRIM_GE3 ----
new_struct
struct_entry MPGE3_p0, 2
struct_entry MPGE3_p1, 2
struct_entry MPGE3_p2, 2
struct_entry MPGE3_en0, 2
struct_entry MPGE3_en1, 2
struct_entry MPGE3_en2, 2
struct_entry MPGE3_n0, 2
struct_entry MPGE3_n1, 2
struct_entry MPGE3_n2, 2
struct_entry MPGE3_pad, 2
struct_entry MPGE3_cvec, 4
struct_entry sizeof_MPGE3, 0


# ---- MR_MPRIM_GE4 ----
new_struct
struct_entry MPGE4_p0, 2
struct_entry MPGE4_p1, 2
struct_entry MPGE4_p2, 2
struct_entry MPGE4_p3, 2
struct_entry MPGE4_en0, 2
struct_entry MPGE4_en1, 2
struct_entry MPGE4_en2, 2
struct_entry MPGE4_en3, 2
struct_entry MPGE4_n0, 2
struct_entry MPGE4_n1, 2
struct_entry MPGE4_n2, 2
struct_entry MPGE4_n3, 2
struct_entry MPGE4_cvec, 4
struct_entry sizeof_MPGE4, 0



# ---- POLY_F3 ----
new_struct
struct_entry PF3_tag, 4
struct_entry PF3_rgb, 4
struct_entry PF3_x0, 2
struct_entry PF3_y0, 2
struct_entry PF3_x1, 2
struct_entry PF3_y1, 2
struct_entry PF3_x2, 2
struct_entry PF3_y2, 2
struct_entry sizeof_PF3, 0
.set primsize_PF3, (sizeof_PF3>>2)-1

# ---- POLY_F4 ----
new_struct
struct_entry PF4_tag, 4
struct_entry PF4_rgb, 4
struct_entry PF4_x0, 2
struct_entry PF4_y0, 2
struct_entry PF4_x1, 2
struct_entry PF4_y1, 2
struct_entry PF4_x2, 2
struct_entry PF4_y2, 2
struct_entry PF4_x3, 2
struct_entry PF4_y3, 2
struct_entry sizeof_PF4, 0
.set primsize_PF4, (sizeof_PF4>>2)-1


# ---- POLY_FT3 ----
new_struct
struct_entry PFT3_tag, 4

struct_entry PFT3_rgb, 4

struct_entry PFT3_x0, 2
struct_entry PFT3_y0, 2

struct_entry PFT3_u0, 1
struct_entry PFT3_v0, 1
struct_entry PFT3_clut, 2

struct_entry PFT3_x1, 2
struct_entry PFT3_y1, 2

struct_entry PFT3_u1, 1
struct_entry PFT3_v1, 1
struct_entry PFT3_tpage, 2

struct_entry PFT3_x2, 2
struct_entry PFT3_y2, 2

struct_entry PFT3_u2, 1
struct_entry PFT3_v2, 1
struct_entry PFT3_pad1, 2

struct_entry sizeof_PFT3, 0
.set primsize_PFT3, (sizeof_PFT3>>2)-1

# ---- POLY_FT4 ----
new_struct
struct_entry PFT4_tag, 4
struct_entry PFT4_rgb, 4
struct_entry PFT4_x0, 2
struct_entry PFT4_y0, 2
struct_entry PFT4_u0, 1
struct_entry PFT4_v0, 1
struct_entry PFT4_clut, 2
struct_entry PFT4_x1, 2
struct_entry PFT4_y1, 2
struct_entry PFT4_u1, 1
struct_entry PFT4_v1, 1
struct_entry PFT4_tpage, 2
struct_entry PFT4_x2, 2
struct_entry PFT4_y2, 2
struct_entry PFT4_u2, 1
struct_entry PFT4_v2, 1
struct_entry PFT4_pad1, 2
struct_entry PFT4_x3, 2
struct_entry PFT4_y3, 2
struct_entry PFT4_u3, 1
struct_entry PFT4_v3, 1
struct_entry PFT4_pad2, 2
struct_entry sizeof_PFT4, 0
.set primsize_PFT4, (sizeof_PFT4>>2)-1


# ---- POLY_G3 ----
new_struct
struct_entry PG3_tag, 4
struct_entry PG3_rgb0, 4
struct_entry PG3_x0, 2
struct_entry PG3_y0, 2
struct_entry PG3_rgb1, 4
struct_entry PG3_x1, 2
struct_entry PG3_y1, 2
struct_entry PG3_rgb2, 4
struct_entry PG3_x2, 2
struct_entry PG3_y2, 2
struct_entry sizeof_PG3, 0
.set primsize_PG3, (sizeof_PG3>>2)-1
			
			
# ---- POLY_G4 ----
new_struct
struct_entry PG4_tag, 4
struct_entry PG4_rgb0, 4
struct_entry PG4_x0, 2
struct_entry PG4_y0, 2
struct_entry PG4_rgb1, 4
struct_entry PG4_x1, 2
struct_entry PG4_y1, 2
struct_entry PG4_rgb2, 4
struct_entry PG4_x2, 2
struct_entry PG4_y2, 2
struct_entry PG4_rgb3, 4
struct_entry PG4_x3, 2
struct_entry PG4_y3, 2
struct_entry sizeof_PG4, 0
.set primsize_PG4, (sizeof_PG4>>2)-1

			
# ---- POLY_GT3 ----
new_struct
struct_entry PGT3_tag, 4
struct_entry PGT3_rgb0, 4
struct_entry PGT3_x0, 2
struct_entry PGT3_y0, 2
struct_entry PGT3_u0, 1
struct_entry PGT3_v0, 1
struct_entry PGT3_clut, 2
struct_entry PGT3_rgb1, 4
struct_entry PGT3_x1, 2
struct_entry PGT3_y1, 2
struct_entry PGT3_u1, 1
struct_entry PGT3_v1, 1
struct_entry PGT3_tpage, 2
struct_entry PGT3_rgb2, 4
struct_entry PGT3_x2, 2
struct_entry PGT3_y2, 2
struct_entry PGT3_u2, 1
struct_entry PGT3_v2, 1
struct_entry PGT3_pad2, 2
struct_entry sizeof_PGT3, 0
.set primsize_PGT3, (sizeof_PGT3>>2)-1


# ---- POLY_GT4 ----
new_struct
struct_entry PGT4_tag, 4
struct_entry PGT4_rgb0, 4
struct_entry PGT4_x0, 2
struct_entry PGT4_y0, 2
struct_entry PGT4_u0, 1
struct_entry PGT4_v0, 1
struct_entry PGT4_clut, 2
struct_entry PGT4_rgb1, 4
struct_entry PGT4_x1, 2
struct_entry PGT4_y1, 2
struct_entry PGT4_u1, 1
struct_entry PGT4_v1, 1
struct_entry PGT4_tpage, 2
struct_entry PGT4_rgb2, 4
struct_entry PGT4_x2, 2
struct_entry PGT4_y2, 2
struct_entry PGT4_u2, 1
struct_entry PGT4_v2, 1
struct_entry PGT4_pad2, 2
struct_entry PGT4_rgb3, 4
struct_entry PGT4_x3, 2
struct_entry PGT4_y3, 2
struct_entry PGT4_u3, 1
struct_entry PGT4_v3, 1
struct_entry PGT4_pad3, 2
struct_entry sizeof_PGT4, 0
.set primsize_PGT4, (sizeof_PGT4>>2)-1


# ---- Stack layout ----
new_struct
struct_entry MESH_STACK_arg_0, 4
struct_entry MESH_STACK_arg_1, 4
struct_entry MESH_STACK_arg_2, 4
struct_entry MESH_STACK_arg_3, 4

struct_entry MESH_STACK_s0, 4
struct_entry MESH_STACK_s1, 4
struct_entry MESH_STACK_s2, 4
struct_entry MESH_STACK_s3, 4
struct_entry MESH_STACK_s4, 4
struct_entry MESH_STACK_s5, 4
struct_entry MESH_STACK_s6, 4
struct_entry MESH_STACK_s7, 4
struct_entry MESH_STACK_s8, 4

struct_entry sizeof_MESH_STACK, 0


new_struct
struct_entry MESH_ENVSTACK_arg_0, 4
struct_entry MESH_ENVSTACK_arg_1, 4
struct_entry MESH_ENVSTACK_arg_2, 4
struct_entry MESH_ENVSTACK_arg_3, 4

struct_entry MESH_ENVSTACK_s0, 4
struct_entry MESH_ENVSTACK_s1, 4
struct_entry MESH_ENVSTACK_s2, 4
struct_entry MESH_ENVSTACK_s3, 4
struct_entry MESH_ENVSTACK_s4, 4
struct_entry MESH_ENVSTACK_s5, 4
struct_entry MESH_ENVSTACK_s6, 4
struct_entry MESH_ENVSTACK_s7, 4
struct_entry MESH_ENVSTACK_s8, 4

struct_entry MESH_ENVSTACK_ot_and, 4
struct_entry MESH_ENVSTACK_ot_or, 4

struct_entry MESH_ENVSTACK_uofs, 4
struct_entry MESH_ENVSTACK_vofs, 4

struct_entry sizeof_MESH_ENVSTACK, 0

