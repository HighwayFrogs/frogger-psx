#/******************************************************************************
#/*%%%% mapasm.i
#/*------------------------------------------------------------------------------
#/*
#/*	Header file for mapasm.s
#/*
#/*	CHANGED		PROGRAMMER	REASON
#/*	-------  	----------  ------
#/*	03.07.97	Dean Ashton	Created
#/*	19.03.25	Kneesnap	Ported to GNU Assembler Syntax
#/*	
#/*%%%**************************************************************************/

.include "macro.inc"
.include "utils.i"

# ---- OT flags ----
	.set MAP_POLY_OT_OFFSET, 64
	.set MAP_POLY_CLIP_OTZ, 16

# ---- Render flags ----
	.set MAP_RENDER_FLAGS_TEXTURED, 1<<0
	.set MAP_RENDER_FLAGS_GOURAUD, 1<<1
	.set MAP_RENDER_FLAGS_LIT, 1<<2

# ---- Poly flags ----
	.set MAP_POLY_SEMITRANS, 1<<0
	.set MAP_POLY_ENVMAP, 1<<1
	.set MAP_POLY_MAX_OT, 1<<2
	.set MAP_POLY_ANIM_UV, 1<<3
	.set MAP_POLY_ANIM_TEXTURE, 1<<4

	.set MAP_POLY_ENVMAP_SHIFT, 5

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


# ---- MAP_F3 ----		
new_struct
struct_entry MF3_vertices, 6
struct_entry MF3_pad, 2
struct_entry MF3_rgb0, 4
struct_entry sizeof_MAP_F3, 0

# ---- MAP_F4 ----
new_struct
struct_entry MF4_vertices, 8
struct_entry MF4_rgb0, 4
struct_entry sizeof_MAP_F4, 0

# ---- MAP_G3 ----		
new_struct
struct_entry MG3_vertices, 6
struct_entry MG3_pad, 2
struct_entry MG3_rgb0, 4
struct_entry MG3_rgb1, 4
struct_entry MG3_rgb2, 4
struct_entry sizeof_MAP_G3, 0

# ---- MAP_G4 ----		
new_struct
struct_entry MG4_vertices, 8
struct_entry MG4_rgb0, 4
struct_entry MG4_rgb1, 4
struct_entry MG4_rgb2, 4
struct_entry MG4_rgb3, 4
struct_entry sizeof_MAP_G4, 0

# ---- MAP_FT3 ----
new_struct
struct_entry MFT3_vertices, 6
struct_entry MFT3_pad0, 2
struct_entry MFT3_flags, 2
struct_entry MFT3_pad1, 2
struct_entry MFT3_u0, 1
struct_entry MFT3_v0, 1
struct_entry MFT3_clut_id, 2
struct_entry MFT3_u1, 1
struct_entry MFT3_v1, 1
struct_entry MFT3_tpage_id, 2
struct_entry MFT3_u2, 1
struct_entry MFT3_v2, 1
struct_entry MFT3_pad2, 2
struct_entry MFT3_rgb0, 4
struct_entry sizeof_MAP_FT3, 0

# ---- MAP_FT4 ----
new_struct
struct_entry MFT4_vertices, 8
struct_entry MFT4_flags, 2
struct_entry MFT4_pad0, 2
struct_entry MFT4_u0, 1
struct_entry MFT4_v0, 1
struct_entry MFT4_clut_id, 2
struct_entry MFT4_u1, 1
struct_entry MFT4_v1, 1
struct_entry MFT4_tpage_id, 2
struct_entry MFT4_u2, 1
struct_entry MFT4_v2, 1
struct_entry MFT4_u3, 1
struct_entry MFT4_v3, 1
struct_entry MFT4_rgb0, 4
struct_entry sizeof_MAP_FT4, 0

# ---- MAP_GT3 ----
new_struct
struct_entry MGT3_vertices, 6
struct_entry MGT3_pad0, 2
struct_entry MGT3_flags, 2
struct_entry MGT3_pad1, 2
struct_entry MGT3_u0, 1
struct_entry MGT3_v0, 1
struct_entry MGT3_clut_id, 2
struct_entry MGT3_u1, 1
struct_entry MGT3_v1, 1
struct_entry MGT3_tpage_id, 2
struct_entry MGT3_u2, 1
struct_entry MGT3_v2, 1
struct_entry MGT3_pad2, 2
struct_entry MGT3_rgb0, 4
struct_entry MGT3_rgb1, 4
struct_entry MGT3_rgb2, 4
struct_entry sizeof_MAP_GT3, 0

# ---- MAP_GT4 ----
new_struct
struct_entry MGT4_vertices, 8
struct_entry MGT4_flags, 2
struct_entry MGT4_pad0, 2
struct_entry MGT4_u0, 1
struct_entry MGT4_v0, 1
struct_entry MGT4_clut_id, 2
struct_entry MGT4_u1, 1
struct_entry MGT4_v1, 1
struct_entry MGT4_tpage_id, 2
struct_entry MGT4_u2, 1
struct_entry MGT4_v2, 1
struct_entry MGT4_u3, 1
struct_entry MGT4_v3, 1
struct_entry MGT4_rgb0, 4
struct_entry MGT4_rgb1, 4
struct_entry MGT4_rgb2, 4
struct_entry MGT4_rgb3, 4
struct_entry sizeof_MAP_GT4, 0

# ---- POLY_NODE ----
new_struct
struct_entry PN_next, 4
struct_entry PN_prev, 4
struct_entry PN_numpolys, 4
struct_entry PN_map_polys, 4
struct_entry PN_prims, 8
struct_entry sizeof_POLY_NODE, 0


# ---- MAP_RENDER_PARAMS ----
new_struct
struct_entry MRP_poly_size, 4
struct_entry MRP_prim_size, 4
struct_entry MRP_prim_coord_ofs, 4
struct_entry MRP_prim_flags, 4
struct_entry MRP_prim_x0_ofs, 4
struct_entry MRP_frog_svec, 8
struct_entry sizeof_MAP_RENDER_PARAMS, 0


# ---- Stack layout ----
new_struct
struct_entry MAPASM_STACK_arg_0, 4
struct_entry MAPASM_STACK_arg_1, 4
struct_entry MAPASM_STACK_arg_2, 4
struct_entry MAPASM_STACK_arg_3, 4

struct_entry MAPASM_STACK_s0, 4
struct_entry MAPASM_STACK_s1, 4
struct_entry MAPASM_STACK_s2, 4
struct_entry MAPASM_STACK_s3, 4
struct_entry MAPASM_STACK_s4, 4
struct_entry MAPASM_STACK_s5, 4
struct_entry MAPASM_STACK_s6, 4
struct_entry MAPASM_STACK_s7, 4
struct_entry MAPASM_STACK_s8, 4
struct_entry MAPASM_STACK_diff_svec, 8
struct_entry MAPASM_STACK_light_factor, 4
struct_entry MAPASM_STACK_light_min, 4
struct_entry MAPASM_STACK_light_max, 4
struct_entry MAPASM_STACK_work_ot, 4   
struct_entry MAPASM_STACK_ot_size, 4   
struct_entry MAPASM_STACK_otz_shift, 4   
struct_entry MAPASM_STACK_ot_and_mask, 4
struct_entry MAPASM_STACK_ot_or_mask, 4
struct_entry MAPASM_STACK_temp_svec_ptr, 4

struct_entry sizeof_MAPASM_STACK, 0
