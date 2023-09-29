;/******************************************************************************
;/*%%%% mapasm.i
;/*------------------------------------------------------------------------------
;/*
;/*	Header file for mapasm.s
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------  	----------  	------
;/*	03.07.97	Dean Ashton	Created
;/*	
;/*%%%**************************************************************************/

				include	"gtereg.h"


;// ---- OT flags ----

MAP_POLY_OT_OFFSET		equ	(64)
MAP_POLY_CLIP_OTZ		equ	(16)


;// ---- Render flags ----

MAP_RENDER_FLAGS_TEXTURED	equ	(1<<0)
MAP_RENDER_FLAGS_GOURAUD	equ	(1<<1)
MAP_RENDER_FLAGS_LIT		equ	(1<<2)


;// ---- Poly flags ----

MAP_POLY_SEMITRANS		equ	(1<<0)
MAP_POLY_ENVMAP			equ	(1<<1)
MAP_POLY_MAX_OT			equ	(1<<2)
MAP_POLY_ANIM_UV		equ	(1<<3)
MAP_POLY_ANIM_TEXTURE		equ	(1<<4)

MAP_POLY_ENVMAP_SHIFT		equ	(5)

;// ---- SVECTOR ----
				rsreset
SVEC_vx				rh	1
SVEC_vy				rh	1
SVEC_vz				rh	1
SVEC_pad			rh	1	
sizeof_SVEC			rb	0
				

;// ---- VECTOR ----
      				rsreset
VEC_vx				rw	1
VEC_vy				rw	1
VEC_vz				rw	1
VEC_pad				rw	1
sizeof_VEC			rb	0
			

;// ---- MATRIX ----
				rsreset
MAT_r11r12			rw	0	; Used for GTE accesses
MAT_r11				rh	1
MAT_r12				rh	1
MAT_r13r21			rw	0	; Used for GTE accesses
MAT_r13				rh	1
MAT_r21				rh	1
MAT_r22r23			rw	0	; Used for GTE accesses
MAT_r22				rh	1
MAT_r23				rh	1
MAT_r31r32			rw	0	; Used for GTE accesses
MAT_r31				rh	1
MAT_r32				rh	1
MAT_r33pad			rw	0	; Used for GTE accesses
MAT_r33				rh	1
MAT_pad				rh	1
sizeof_MAT			rb	0



;// ---- POLY_F3 ----
				rsreset
PF3_tag				rw	1
PF3_rgb				rw	1
PF3_x0				rh	1
PF3_y0				rh	1
PF3_x1				rh	1
PF3_y1				rh	1
PF3_x2				rh	1
PF3_y2				rh	1
sizeof_PF3			rb	0
primsize_PF3			equ	(sizeof_PF3>>2)-1

;// ---- POLY_F4 ----
				rsreset
PF4_tag				rw	1
PF4_rgb				rw	1
PF4_x0				rh	1
PF4_y0				rh	1
PF4_x1				rh	1
PF4_y1				rh	1
PF4_x2				rh	1
PF4_y2				rh	1
PF4_x3				rh	1
PF4_y3				rh	1
sizeof_PF4			rb	0
primsize_PF4			equ	(sizeof_PF4>>2)-1
			

;// ---- POLY_FT3 ----
				rsreset
PFT3_tag		   	rw	1
PFT3_rgb			rw	1
PFT3_x0				rh	1
PFT3_y0				rh	1
PFT3_u0				rb	1
PFT3_v0				rb	1
PFT3_clut			rh	1
PFT3_x1				rh	1
PFT3_y1				rh	1
PFT3_u1				rb	1
PFT3_v1				rb	1
PFT3_tpage			rh	1
PFT3_x2				rh	1
PFT3_y2				rh	1
PFT3_u2				rb	1
PFT3_v2				rb	1
PFT3_pad1			rh	1
sizeof_PFT3			rb    	0
primsize_PFT3			equ	(sizeof_PFT3>>2)-1

;// ---- POLY_FT4 ----
				rsreset
PFT4_tag		   	rw	1
PFT4_rgb			rw	1
PFT4_x0				rh	1
PFT4_y0				rh	1
PFT4_u0				rb	1
PFT4_v0				rb	1
PFT4_clut			rh	1
PFT4_x1				rh	1
PFT4_y1				rh	1
PFT4_u1				rb	1
PFT4_v1				rb	1
PFT4_tpage			rh	1
PFT4_x2				rh	1
PFT4_y2				rh	1
PFT4_u2				rb	1
PFT4_v2				rb	1
PFT4_pad1			rh	1
PFT4_x3				rh	1
PFT4_y3				rh	1
PFT4_u3				rb	1
PFT4_v3				rb	1
PFT4_pad2			rh	1
sizeof_PFT4			rb    	0
primsize_PFT4			equ	(sizeof_PFT4>>2)-1


;// ---- POLY_G3 ----
				rsreset
PG3_tag				rw	1
PG3_rgb0			rw	1
PG3_x0				rh	1
PG3_y0				rh	1
PG3_rgb1			rw	1
PG3_x1				rh	1
PG3_y1				rh	1
PG3_rgb2			rw	1
PG3_x2				rh	1
PG3_y2				rh	1
sizeof_PG3			rb	0
primsize_PG3			equ	(sizeof_PG3>>2)-1
			
			
;// ---- POLY_G4 ----
				rsreset
PG4_tag				rw	1
PG4_rgb0			rw	1
PG4_x0				rh	1
PG4_y0				rh	1
PG4_rgb1			rw	1
PG4_x1				rh	1
PG4_y1				rh	1
PG4_rgb2			rw	1
PG4_x2				rh	1
PG4_y2				rh	1
PG4_rgb3			rw	1
PG4_x3				rh	1
PG4_y3				rh	1
sizeof_PG4			rb	0
primsize_PG4			equ	(sizeof_PG4>>2)-1
			
			
;// ---- POLY_GT3 ----
				rsreset
PGT3_tag			rw	1
PGT3_rgb0			rw	1
PGT3_x0				rh	1
PGT3_y0				rh	1
PGT3_u0				rb	1
PGT3_v0				rb	1
PGT3_clut			rh	1
PGT3_rgb1			rw	1
PGT3_x1				rh	1
PGT3_y1				rh	1
PGT3_u1				rb	1
PGT3_v1				rb	1
PGT3_tpage			rh	1
PGT3_rgb2			rw	1
PGT3_x2				rh	1
PGT3_y2				rh	1
PGT3_u2				rb	1
PGT3_v2				rb	1
PGT3_pad2			rh	1
sizeof_PGT3			rb	0
primsize_PGT3			equ	(sizeof_PGT3>>2)-1
			

;// ---- POLY_GT4 ----
				rsreset
PGT4_tag			rw	1
PGT4_rgb0			rw	1
PGT4_x0				rh	1
PGT4_y0				rh	1
PGT4_u0				rb	1
PGT4_v0				rb	1
PGT4_clut			rh	1
PGT4_rgb1			rw	1
PGT4_x1				rh	1
PGT4_y1				rh	1
PGT4_u1				rb	1
PGT4_v1				rb	1
PGT4_tpage			rh	1
PGT4_rgb2			rw	1
PGT4_x2				rh	1
PGT4_y2				rh	1
PGT4_u2				rb	1
PGT4_v2				rb	1
PGT4_pad2			rh	1
PGT4_rgb3			rw	1
PGT4_x3				rh	1
PGT4_y3				rh	1
PGT4_u3				rb	1
PGT4_v3				rb	1
PGT4_pad3			rh	1
sizeof_PGT4			rb	0
primsize_PGT4			equ	(sizeof_PGT4>>2)-1


;// ---- MAP_F3 ----		
				rsreset
MF3_vertices			rh	3
MF3_pad				rh	1
MF3_rgb0			rw	1
sizeof_MAP_F3			rb	0


;// ---- MAP_F4 ----
				rsreset
MF4_vertices			rh	4
MF4_rgb0			rw	1
sizeof_MAP_F4			rb	0


;// ---- MAP_G3 ----		
				rsreset
MG3_vertices			rh	3
MG3_pad				rh	1
MG3_rgb0			rw	1
MG3_rgb1			rw	1
MG3_rgb2			rw	1
sizeof_MAP_G3			rb	0


;// ---- MAP_G4 ----		
				rsreset
MG4_vertices			rh	4
MG4_rgb0			rw	1
MG4_rgb1			rw	1
MG4_rgb2			rw	1
MG4_rgb3			rw	1
sizeof_MAP_G4			rb	0


;// ---- MAP_FT3 ----
				rsreset
MFT3_vertices			rh	3
MFT3_pad0			rh	1
MFT3_flags			rh	1
MFT3_pad1			rh	1
MFT3_u0				rb	1
MFT3_v0				rb	1
MFT3_clut_id			rh	1
MFT3_u1				rb	1
MFT3_v1				rb	1
MFT3_tpage_id			rh	1
MFT3_u2				rb	1
MFT3_v2				rb	1
MFT3_pad2			rh	1
MFT3_rgb0			rw	1
sizeof_MAP_FT3			rb	0


;// ---- MAP_FT4 ----
				rsreset
MFT4_vertices			rh	4
MFT4_flags			rh	1
MFT4_pad0			rh	1
MFT4_u0				rb	1
MFT4_v0				rb	1
MFT4_clut_id			rh	1
MFT4_u1				rb	1
MFT4_v1				rb	1
MFT4_tpage_id			rh	1
MFT4_u2				rb	1
MFT4_v2				rb	1
MFT4_u3				rb	1
MFT4_v3				rb	1
MFT4_rgb0			rw	1
sizeof_MAP_FT4			rb	0


;// ---- MAP_GT3 ----
				rsreset
MGT3_vertices			rh	3
MGT3_pad0			rh	1
MGT3_flags			rh	1
MGT3_pad1			rh	1
MGT3_u0				rb	1
MGT3_v0				rb	1
MGT3_clut_id			rh	1
MGT3_u1				rb	1
MGT3_v1				rb	1
MGT3_tpage_id			rh	1
MGT3_u2				rb	1
MGT3_v2				rb	1
MGT3_pad2			rh	1
MGT3_rgb0			rw	1
MGT3_rgb1			rw	1
MGT3_rgb2			rw	1
sizeof_MAP_GT3			rb	0


;// ---- MAP_GT4 ----
				rsreset
MGT4_vertices			rh	4
MGT4_flags			rh	1
MGT4_pad0			rh	1
MGT4_u0				rb	1
MGT4_v0				rb	1
MGT4_clut_id			rh	1
MGT4_u1				rb	1
MGT4_v1				rb	1
MGT4_tpage_id			rh	1
MGT4_u2				rb	1
MGT4_v2				rb	1
MGT4_u3				rb	1
MGT4_v3				rb	1
MGT4_rgb0			rw	1
MGT4_rgb1			rw	1
MGT4_rgb2			rw	1
MGT4_rgb3			rw	1
sizeof_MAP_GT4			rb	0


;// ---- POLY_NODE ----
				rsreset
PN_next				rw	1
PN_prev				rw	1
PN_numpolys			rw	1
PN_map_polys			rw	1
PN_prims			rw	2
sizeof_POLY_NODE		rb	0


;// ---- MAP_RENDER_PARAMS ----
				rsreset
MRP_poly_size			rw	1
MRP_prim_size			rw	1
MRP_prim_coord_ofs		rw	1
MRP_prim_flags			rw	1
MRP_prim_x0_ofs			rw	1
MRP_frog_svec			rh	4
sizeof_MAP_RENDER_PARAMS	rb	0


;// ---- Stack layout ----
				rsreset
MAPASM_STACK_arg_0		rw	1
MAPASM_STACK_arg_1		rw	1
MAPASM_STACK_arg_2		rw	1
MAPASM_STACK_arg_3		rw	1
				
MAPASM_STACK_s0			rw	1
MAPASM_STACK_s1			rw	1
MAPASM_STACK_s2			rw	1
MAPASM_STACK_s3			rw	1
MAPASM_STACK_s4			rw	1
MAPASM_STACK_s5			rw	1
MAPASM_STACK_s6			rw	1
MAPASM_STACK_s7			rw	1
MAPASM_STACK_s8			rw	1
MAPASM_STACK_diff_svec		rh	4
MAPASM_STACK_light_factor	rw	1
MAPASM_STACK_light_min		rw	1
MAPASM_STACK_light_max		rw	1
MAPASM_STACK_work_ot		rw	1   
MAPASM_STACK_ot_size		rw	1   
MAPASM_STACK_otz_shift		rw	1   
MAPASM_STACK_ot_and_mask	rw	1
MAPASM_STACK_ot_or_mask		rw	1
MAPASM_STACK_temp_svec_ptr	rw	1
				
sizeof_MAPASM_STACK		rb	0
