;/******************************************************************************
;/*%%%% mr_m_hdr.i
;/*------------------------------------------------------------------------------
;/*
;/*	Header file for MIPS assembler polygon rendering modules.
;/*
;/*	CHANGED		PROGRAMMER	REASON
;/*	-------  	----------  	------
;/*	18.9.96		Dean Ashton	Created
;/*	
;/*%%%**************************************************************************/

			include	"..\..\include\gtereg.h"


;// ---- SVECTOR ----
			rsreset
SVEC_vx			rh	1
SVEC_vy			rh	1
SVEC_vz			rh	1
SVEC_pad		rh	1	
sizeof_SVEC		rb	0


;// ---- VECTOR ----
      			rsreset
VEC_vx			rw	1
VEC_vy			rw	1
VEC_vz			rw	1
VEC_pad			rw	1
sizeof_VEC		rb	0


;// ---- MATRIX ----
			rsreset
MAT_r11r12		rw	0	; Used for GTE accesses
MAT_r11			rh	1
MAT_r12			rh	1
MAT_r13r21		rw	0	; Used for GTE accesses
MAT_r13			rh	1
MAT_r21			rh	1
MAT_r22r23		rw	0	; Used for GTE accesses
MAT_r22			rh	1
MAT_r23			rh	1
MAT_r31r32		rw	0	; Used for GTE accesses
MAT_r31			rh	1
MAT_r32			rh	1
MAT_r33pad		rw	0	; Used for GTE accesses
MAT_r33			rh	1
MAT_pad			rh	1
sizeof_MAT		rb	0


;// ---- MR_TEXTURE ----
			rsreset
TEX_flags		rh	1
TEX_w			rb	1
TEX_h			rb	1
TEX_u0	 		rb	1
TEX_v0			rb	1
TEX_clut_id		rh	1
TEX_u1			rb	1
TEX_v1			rb	1
TEX_tpage_id		rh	1
TEX_u2			rb	1
TEX_v2			rb	1
TEX_u3			rb	1
TEX_v3			rb	1
sizeof_TEXTURE		rb	0


;// ---- MR_MESH_PARAM ----
			rsreset
MP_p0			rw	1
MP_p1			rw	1
MP_p2			rw	1
MP_p3			rw	1
MP_n0			rw	1
MP_n1			rw	1
MP_n2			rw	1
MP_n3			rw	1
MP_work_ot		rw	1
MP_otz_shift		rh	1
MP_ot_otz_delta		rh	1
MP_ot_size		rw	1
MP_ot_clip		rw	1
MP_ot_view_origin_z	rw	1
MP_nclip_result		rw	1
MP_poly_otz		rw	1
MP_mem_ptr		rw	1
MP_prim_ptr		rw	1
MP_prims		rw	1
sizeof_MESH_PARAM	rb	0



;// ---- MR_MPRIM_F3 ----
			rsreset
MPF3_p0			rh	1
MPF3_p1			rh	1
MPF3_p2			rh	1
MPF3_n0			rh	1
MPF3_cvec		rw	1
sizeof_MPF3		rb	0


;// ---- MR_MPRIM_F4 ----
			rsreset
MPF4_p0			rh	1
MPF4_p1			rh	1
MPF4_p2			rh	1
MPF4_p3			rh	1
MPF4_n0			rh	1
MPF4_pad		rh	1
MPF4_cvec		rw	1
sizeof_MPF4		rb	0


;// ---- MR_MPRIM_FT3 ----
			rsreset
MPFT3_p0   		rh	1
MPFT3_p1   		rh	1
MPFT3_p2   		rh	1
MPFT3_n0   		rh	1
MPFT3_u0		rb	1
MPFT3_v0		rb	1
MPFT3_clut_id		rh	1
MPFT3_u1		rb	1
MPFT3_v1		rb	1
MPFT3_tpage_id		rh	1
MPFT3_u2		rb	1
MPFT3_v2		rb	1
MPFT3_image_id		rh	1
MPFT3_cvec		rw	1
sizeof_MPFT3		rb	0


;// ---- MR_MPRIM_FT4 ----
			rsreset
MPFT4_p0   		rh	1
MPFT4_p1   		rh	1
MPFT4_p2   		rh	1
MPFT4_p3   		rh	1
MPFT4_n0   		rh	1
MPFT4_image_id		rh	1
MPFT4_u0		rb	1
MPFT4_v0		rb	1
MPFT4_clut_id		rh	1
MPFT4_u1		rb	1
MPFT4_v1		rb	1
MPFT4_tpage_id		rh	1
MPFT4_u2		rb	1
MPFT4_v2		rb	1
MPFT4_u3		rb	1
MPFT4_v3		rb	1
MPFT4_cvec		rw	1
sizeof_MPFT4		rb	0


;// ---- MR_MPRIM_G3 ----
			rsreset
MPG3_p0			rh	1
MPG3_p1			rh	1
MPG3_p2			rh	1
MPG3_n0			rh	1
MPG3_n1			rh	1
MPG3_n2			rh	1
MPG3_cvec		rw	1
sizeof_MPG3		rb	0


;// ---- MR_MPRIM_G4 ----
			rsreset
MPG4_p0			rh	1
MPG4_p1			rh	1
MPG4_p2			rh	1
MPG4_p3			rh	1
MPG4_n0			rh	1
MPG4_n1			rh	1
MPG4_n2			rh	1
MPG4_n3			rh	1
MPG4_cvec		rw	1
sizeof_MPG4		rb	0


;// ---- MR_MPRIM_GT3 ----
			rsreset
MPGT3_p0   		rh	1
MPGT3_p1   		rh	1
MPGT3_p2   		rh	1
MPGT3_n0   		rh	1
MPGT3_n1   		rh	1
MPGT3_n2   		rh	1
MPGT3_u0		rb	1
MPGT3_v0		rb	1
MPGT3_clut_id		rh	1
MPGT3_u1		rb	1
MPGT3_v1		rb	1
MPGT3_tpage_id		rh	1
MPGT3_u2		rb	1
MPGT3_v2		rb	1
MPGT3_image_id		rh	1
MPGT3_cvec		rw	1
sizeof_MPGT3		rb	0


;// ---- MR_MPRIM_GT4 ----
			rsreset
MPGT4_p0   		rh	1
MPGT4_p1   		rh	1
MPGT4_p2   		rh	1
MPGT4_p3   		rh	1
MPGT4_n0   		rh	1
MPGT4_n1   		rh	1
MPGT4_n2   		rh	1
MPGT4_n3   		rh	1
MPGT4_u0		rb	1
MPGT4_v0		rb	1
MPGT4_clut_id		rh	1
MPGT4_u1		rb	1
MPGT4_v1		rb	1
MPGT4_tpage_id		rh	1
MPGT4_u2		rb	1
MPGT4_v2		rb	1
MPGT4_u3		rb	1
MPGT4_v3		rb	1
MPGT4_image_id		rh	1
MPGT4_pad		rh	1
MPGT4_cvec		rw	1
sizeof_MPGT4		rb	0


;// ---- MR_MPRIM_E3 ----
			rsreset
MPE3_p0			rh	1
MPE3_p1			rh	1
MPE3_p2			rh	1
MPE3_en0		rh	1
MPE3_en1		rh	1
MPE3_en2		rh	1
MPE3_n0			rh	1
MPE3_pad		rh	1
MPE3_cvec		rw	1
sizeof_MPE3		rb	0


;// ---- MR_MPRIM_E4 ----
			rsreset
MPE4_p0			rh	1
MPE4_p1			rh	1
MPE4_p2			rh	1
MPE4_p3			rh	1
MPE4_en0		rh	1
MPE4_en1		rh	1
MPE4_en2		rh	1
MPE4_en3		rh	1
MPE4_n0			rh	1
MPE4_pad		rh	1
MPE4_cvec		rw	1
sizeof_MPE4		rb	0


;// ---- MR_MPRIM_GE3 ----
			rsreset
MPGE3_p0    		rh	1
MPGE3_p1    		rh	1
MPGE3_p2    		rh	1
MPGE3_en0		rh	1
MPGE3_en1		rh	1
MPGE3_en2		rh	1
MPGE3_n0    		rh	1
MPGE3_n1    		rh	1
MPGE3_n2    		rh	1
MPGE3_pad		rh	1
MPGE3_cvec		rw	1
sizeof_MPGE3		rb	0


;// ---- MR_MPRIM_GE4 ----
			rsreset
MPGE4_p0		rh	1
MPGE4_p1		rh	1
MPGE4_p2		rh	1
MPGE4_p3		rh	1
MPGE4_en0		rh	1
MPGE4_en1		rh	1
MPGE4_en2		rh	1
MPGE4_en3		rh	1
MPGE4_n0		rh	1
MPGE4_n1		rh	1
MPGE4_n2		rh	1
MPGE4_n3		rh	1
MPGE4_cvec		rw	1
sizeof_MPGE4		rb	0



;// ---- POLY_F3 ----
			rsreset
PF3_tag			rw	1
PF3_rgb			rw	1
PF3_x0			rh	1
PF3_y0			rh	1
PF3_x1			rh	1
PF3_y1			rh	1
PF3_x2			rh	1
PF3_y2			rh	1
sizeof_PF3		rb	0
primsize_PF3		equ	(sizeof_PF3>>2)-1

;// ---- POLY_F4 ----
			rsreset
PF4_tag			rw	1
PF4_rgb			rw	1
PF4_x0			rh	1
PF4_y0			rh	1
PF4_x1			rh	1
PF4_y1			rh	1
PF4_x2			rh	1
PF4_y2			rh	1
PF4_x3			rh	1
PF4_y3			rh	1
sizeof_PF4		rb	0
primsize_PF4		equ	(sizeof_PF4>>2)-1


;// ---- POLY_FT3 ----
			rsreset
PFT3_tag	   	rw	1

PFT3_rgb		rw	1

PFT3_x0			rh	1
PFT3_y0			rh	1

PFT3_u0			rb	1
PFT3_v0			rb	1
PFT3_clut		rh	1

PFT3_x1			rh	1
PFT3_y1			rh	1

PFT3_u1			rb	1
PFT3_v1			rb	1
PFT3_tpage		rh	1

PFT3_x2			rh	1
PFT3_y2			rh	1

PFT3_u2			rb	1
PFT3_v2			rb	1
PFT3_pad1		rh	1

sizeof_PFT3		rb    	0
primsize_PFT3		equ	(sizeof_PFT3>>2)-1

;// ---- POLY_FT4 ----
			rsreset
PFT4_tag	   	rw	1
PFT4_rgb		rw	1
PFT4_x0			rh	1
PFT4_y0			rh	1
PFT4_u0			rb	1
PFT4_v0			rb	1
PFT4_clut		rh	1
PFT4_x1			rh	1
PFT4_y1			rh	1
PFT4_u1			rb	1
PFT4_v1			rb	1
PFT4_tpage		rh	1
PFT4_x2			rh	1
PFT4_y2			rh	1
PFT4_u2			rb	1
PFT4_v2			rb	1
PFT4_pad1		rh	1
PFT4_x3			rh	1
PFT4_y3			rh	1
PFT4_u3			rb	1
PFT4_v3			rb	1
PFT4_pad2		rh	1
sizeof_PFT4		rb    	0
primsize_PFT4		equ	(sizeof_PFT4>>2)-1


;// ---- POLY_G3 ----
			rsreset
PG3_tag			rw	1
PG3_rgb0		rw	1
PG3_x0			rh	1
PG3_y0			rh	1
PG3_rgb1		rw	1
PG3_x1			rh	1
PG3_y1			rh	1
PG3_rgb2		rw	1
PG3_x2			rh	1
PG3_y2			rh	1
sizeof_PG3		rb	0
primsize_PG3		equ	(sizeof_PG3>>2)-1
			
			
;// ---- POLY_G4 ----
			rsreset
PG4_tag			rw	1
PG4_rgb0		rw	1
PG4_x0			rh	1
PG4_y0			rh	1
PG4_rgb1		rw	1
PG4_x1			rh	1
PG4_y1			rh	1
PG4_rgb2		rw	1
PG4_x2			rh	1
PG4_y2			rh	1
PG4_rgb3		rw	1
PG4_x3			rh	1
PG4_y3			rh	1
sizeof_PG4		rb	0
primsize_PG4		equ	(sizeof_PG4>>2)-1
			
			
;// ---- POLY_GT3 ----
			rsreset
PGT3_tag		rw	1
PGT3_rgb0		rw	1
PGT3_x0			rh	1
PGT3_y0			rh	1
PGT3_u0			rb	1
PGT3_v0			rb	1
PGT3_clut		rh	1
PGT3_rgb1		rw	1
PGT3_x1			rh	1
PGT3_y1			rh	1
PGT3_u1			rb	1
PGT3_v1			rb	1
PGT3_tpage		rh	1
PGT3_rgb2		rw	1
PGT3_x2			rh	1
PGT3_y2			rh	1
PGT3_u2			rb	1
PGT3_v2			rb	1
PGT3_pad2		rh	1
sizeof_PGT3		rb	0
primsize_PGT3		equ	(sizeof_PGT3>>2)-1
			

;// ---- POLY_GT4 ----
			rsreset
PGT4_tag		rw	1
PGT4_rgb0		rw	1
PGT4_x0			rh	1
PGT4_y0			rh	1
PGT4_u0			rb	1
PGT4_v0			rb	1
PGT4_clut		rh	1
PGT4_rgb1		rw	1
PGT4_x1			rh	1
PGT4_y1			rh	1
PGT4_u1			rb	1
PGT4_v1			rb	1
PGT4_tpage		rh	1
PGT4_rgb2		rw	1
PGT4_x2			rh	1
PGT4_y2			rh	1
PGT4_u2			rb	1
PGT4_v2			rb	1
PGT4_pad2		rh	1
PGT4_rgb3		rw	1
PGT4_x3			rh	1
PGT4_y3			rh	1
PGT4_u3			rb	1
PGT4_v3			rb	1
PGT4_pad3		rh	1
sizeof_PGT4		rb	0
primsize_PGT4		equ	(sizeof_PGT4>>2)-1
			
			
;// ---- Stack layout ----

			rsreset
MESH_STACK_arg_0	rw	1
MESH_STACK_arg_1	rw	1
MESH_STACK_arg_2	rw	1
MESH_STACK_arg_3	rw	1

MESH_STACK_s0		rw	1
MESH_STACK_s1		rw	1
MESH_STACK_s2		rw	1
MESH_STACK_s3		rw	1
MESH_STACK_s4		rw	1
MESH_STACK_s5		rw	1
MESH_STACK_s6		rw	1
MESH_STACK_s7		rw	1
MESH_STACK_s8		rw	1

sizeof_MESH_STACK	rb	0


			rsreset
MESH_ENVSTACK_arg_0	rw	1
MESH_ENVSTACK_arg_1	rw	1
MESH_ENVSTACK_arg_2	rw	1
MESH_ENVSTACK_arg_3	rw	1

MESH_ENVSTACK_s0	rw	1
MESH_ENVSTACK_s1	rw	1
MESH_ENVSTACK_s2	rw	1
MESH_ENVSTACK_s3	rw	1
MESH_ENVSTACK_s4	rw	1
MESH_ENVSTACK_s5	rw	1
MESH_ENVSTACK_s6	rw	1
MESH_ENVSTACK_s7	rw	1
MESH_ENVSTACK_s8	rw	1

MESH_ENVSTACK_ot_and	rw	1
MESH_ENVSTACK_ot_or	rw	1

MESH_ENVSTACK_uofs	rw	1
MESH_ENVSTACK_vofs	rw	1

sizeof_MESH_ENVSTACK	rb	0


