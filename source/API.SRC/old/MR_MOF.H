/******************************************************************************
*%%%% mr_mof.h
*------------------------------------------------------------------------------
*
*	New header file for mr_mof.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*	24.01.97	Tim Closs		MRCheckBoundingBoxOnScreen() changed to return
*								flags field
*	28.01.97	Tim Closs		Added:
*									MRPartGetPrim()
*									MRPartGetPrimOffset()
*									MRGetNumberOfHilites()
*									MRGetFirstHilite()
*									MRFillHiliteSVECArray()
*									MRFillHiliteSVECPointerArray()
*	12.02.97	Tim Closs		Moved MR_BBOX to mr_sys.h
*	06.06.97	Tim Closs		Added support for animated polys.  New functions:
*								MRPartGetPrimOffsetFromPointer()
*								MRCalculateMOFAnimatedPolys()
*								New structures:
*								MR_PART_POLY_ANIM
*								MR_PART_POLY_ANIMLIST_ENTRY
*								New flags:
*								MR_MOF_ANIMATED_POLYS
*	18.06.97	Tim Closs		Added support for flipbooks.  New defines:
*								MR_MOF_FLIPBOOK
*								New structures:
*								MR_PART_FLIPBOOK
*								MR_PART_FLIPBOOK_ACTION
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_mof   						MR_MOF;
typedef	struct	__mr_part						MR_PART;
typedef	struct	__mr_partcel					MR_PARTCEL;
typedef	struct	__mr_hilite						MR_HILITE;
typedef	struct	__mr_mprim_header				MR_MPRIM_HEADER;
typedef	struct	__mr_mprim_f3					MR_MPRIM_F3;
typedef	struct	__mr_mprim_f4					MR_MPRIM_F4;
typedef	struct	__mr_mprim_ft3					MR_MPRIM_FT3;
typedef	struct	__mr_mprim_ft4					MR_MPRIM_FT4;
typedef	struct	__mr_mprim_g3					MR_MPRIM_G3;
typedef	struct	__mr_mprim_g4					MR_MPRIM_G4;
typedef	struct	__mr_mprim_gt3					MR_MPRIM_GT3;
typedef	struct	__mr_mprim_gt4					MR_MPRIM_GT4;
typedef	struct	__mr_mprim_e3					MR_MPRIM_E3;
typedef	struct	__mr_mprim_e4					MR_MPRIM_E4;
typedef	struct	__mr_mprim_lf2					MR_MPRIM_LF2;
typedef	struct	__mr_mprim_lf3					MR_MPRIM_LF3;
typedef	struct	__mr_mprim_hlf3					MR_MPRIM_HLF3;
typedef	struct	__mr_mprim_hlf4					MR_MPRIM_HLF4;
typedef	struct	__mr_mprim_ge3					MR_MPRIM_GE3;
typedef	struct	__mr_mprim_ge4					MR_MPRIM_GE4;
typedef	struct	__mr_part_poly_anim				MR_PART_POLY_ANIM;
typedef	struct	__mr_part_poly_animlist_entry	MR_PART_POLY_ANIMLIST_ENTRY;
typedef	struct	__mr_part_flipbook				MR_PART_FLIPBOOK;
typedef	struct	__mr_part_flipbook_action		MR_PART_FLIPBOOK_ACTION;

#else
#ifndef	__MR_MOF_H
#define	__MR_MOF_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_PRIM_GPU_SIZE_F3				(sizeof(POLY_F3) >> 2)
#define	MR_PRIM_GPU_SIZE_F4				(sizeof(POLY_F4) >> 2)
#define	MR_PRIM_GPU_SIZE_FT3			(sizeof(POLY_FT3) >> 2)
#define	MR_PRIM_GPU_SIZE_FT4			(sizeof(POLY_FT4) >> 2)
#define	MR_PRIM_GPU_SIZE_G3				(sizeof(POLY_G3) >> 2)
#define	MR_PRIM_GPU_SIZE_G4				(sizeof(POLY_G4) >> 2)
#define	MR_PRIM_GPU_SIZE_GT3			(sizeof(POLY_GT3) >> 2)
#define	MR_PRIM_GPU_SIZE_GT4			(sizeof(POLY_GT4) >> 2)
#define	MR_PRIM_GPU_SIZE_E3				(sizeof(POLY_FT3) >> 2)
#define	MR_PRIM_GPU_SIZE_E4				(sizeof(POLY_FT4) >> 2)
#define	MR_PRIM_GPU_SIZE_GE3			(sizeof(POLY_FT3) >> 2)
#define	MR_PRIM_GPU_SIZE_GE4			(sizeof(POLY_FT4) >> 2)

// PSX GPU codes
#define	MR_PRIM_GPU_CODE_LF2			(0x40 << 24)
#define	MR_PRIM_GPU_CODE_TILE			(0x60 << 24)
#define	MR_PRIM_GPU_CODE_FT4			(0x2c << 24)

// MOF flags (3rd longword in all MOF files)
#define	MR_MOF_OFFSETS_RESOLVED					(1<<0)	// inidicates pointers in OBJ_HEADER have been
														// resolved from offsets relative to the very start of
														// the file to absolute memory pointers
#define	MR_MOF_SIZES_RESOLVED  					(1<<1)	// indicates sizes of prim buffers for models have been
														// calculated
#define	MR_MOF_TEXTURES_RESOLVED				(1<<2)	// indicates that UV's on textured faces have been resolved
#define	MR_MOF_ANIMATED							(1<<3)	// MOF is an animation file
#define	MR_MOF_ANIMATED_POLYS					(1<<4)	// MOF contains some animated textured polys
#define	MR_MOF_FLIPBOOK							(1<<5)	// MOF is a static flipbook file

#define	MR_MOF_WIREFRAME						(1<<8)
#define	MR_MOF_WIREFRAME_MONOCHROME				(1<<9)

#define	MR_MOF_ANIM_TRANSFORMS_INDEXED	 		(1<<16)
#define	MR_MOF_ANIM_INDEXED_TRANSFORMS_IN_PARTS	(1<<17)
#define	MR_MOF_ANIM_BBOXES_INDEXED			   	(1<<20)

// MR_PART flags
#define	MR_PART_ANIMATED_POLYS					(1<<0)	// MR_PART contains some animated textured polys

// MR_BBOX function flags
#define	MR_BBOX_DISPLAY_NO_VERTICES			   	(0)
#define	MR_BBOX_DISPLAY_SOME_VERTICES		   	(1)
#define	MR_BBOX_DISPLAY_ALL_VERTICES		   	(2)

enum		{
			MR_MPRIMID_F3,
			MR_MPRIMID_F4,
			MR_MPRIMID_FT3,
			MR_MPRIMID_FT4,
			MR_MPRIMID_G3,
			MR_MPRIMID_G4,
			MR_MPRIMID_GT3,
			MR_MPRIMID_GT4,
			MR_MPRIMID_E3,
			MR_MPRIMID_E4,
			MR_MPRIMID_LF2,
			MR_MPRIMID_LF3,
			MR_MPRIMID_HLF3,
			MR_MPRIMID_HLF4,
			MR_MPRIMID_GE3,
			MR_MPRIMID_GE4,
			};

// MR_HILITE flags
#define	MR_HILITE_VERTEX					   	(1<<0)	// hilite is a vertex
#define	MR_HILITE_PRIM						   	(1<<1)	// hilite is a primitive


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_mof
		{
		MR_ULONG			mm_id;				// 'MOF' then id number
		MR_ULONG			mm_length;			// total length in bytes of file, including header
		MR_ULONG			mm_flags;			// eg. tells if addresses in object headers are absolute of offsets
		MR_ULONG			mm_extra;			// (?) file specific (for static mesh files, this is number of models in the file)

		};		// MR_MOF


struct	__mr_part
		{
		MR_USHORT			mp_flags;			// none defined at present
		MR_USHORT 			mp_partcels;		// number of partcels
		MR_USHORT			mp_verts;			// number of vertices
		MR_USHORT			mp_norms;			// number of normals
		MR_USHORT 			mp_prims;			// number of primitives
		MR_USHORT			mp_hilites;			// number of hilites
		MR_PARTCEL*			mp_partcel_ptr;		// ptr to first partcel header (abs or offset)	
		MR_ULONG*			mp_prim_ptr; 		// ptr to start of primitive block (abs or offset)
		MR_HILITE* 			mp_hilite_ptr;		// ptr to start of MR_HILITE block (abs or offset) (or NULL)
		MR_ULONG  			mp_buff_size; 		// size of a single set of preset polygons for this model in bytes
		MR_COLLPRIM*		mp_collprim_ptr;	// ptr to start of MR_COLLPRIM block (abs or offset) (or NULL)
		MR_MAT*				mp_matrix_ptr;		// ptr to start of MR_MAT block (abs or offset) (or NULL)
		MR_VOID*			mp_pad0;			// for future use 	(animated textures)
		MR_VOID*			mp_pad1;			// for future use	(flipbook files)
	
		};		// MR_PART


struct	__mr_partcel
		{
		MR_SVEC* 			mp_vert_ptr;		// ptr to start of vertex block (abs or offset)
		MR_SVEC* 			mp_norm_ptr;		// ptr to start of normal block (abs or offset)
		MR_BBOX* 	  		mp_bbox_ptr;		// ptr to bounding box (or NULL)
		MR_VOID*			mp_pad0;

		};		// MR_PARTCEL;


struct	__mr_hilite
		{
		MR_UBYTE			mh_type;			// eg. MR_HILITE_COLLISION_VERTEX
		MR_UBYTE			mh_flags;			// eg. MR_HILITE_VERTEX, MR_HILITE_PRIM
		MR_USHORT			mh_index;			// index of element within block (eg. 2 for 3rd prim in prim block)				
		MR_ULONG*			mh_target_ptr;		// abs address of target element (could be a vertex, or an MR_MPOLY_<xx>)
	 	MR_ULONG			mh_prim_ofs;		// byte offset into mesh instance primitive buffer (resolved - only for MR_HILITE_PRIM)
	
		};		// MR_HILITE


struct	__mr_mprim_header
		{
		MR_USHORT			mm_type; 			// eg. MR_MPRIMID_F3
		MR_USHORT			mm_count;			// number of prims in this block

		};		// MR_MPRIM_HEADER


struct	__mr_mprim_f3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_n0;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_F3


struct	__mr_mprim_f4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_F4


struct	__mr_mprim_ft3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_n0;
		MR_UBYTE			mp_u0;
		MR_UBYTE			mp_v0;
		MR_USHORT			mp_clut_id;
		MR_UBYTE			mp_u1;
		MR_UBYTE			mp_v1;
		MR_USHORT			mp_tpage_id;
		MR_UBYTE			mp_u2;
		MR_UBYTE			mp_v2;
		MR_USHORT			mp_image_id;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_FT3


struct	__mr_mprim_ft4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_image_id;
		MR_UBYTE			mp_u0;
		MR_UBYTE			mp_v0;
		MR_USHORT			mp_clut_id;
		MR_UBYTE			mp_u1;
		MR_UBYTE			mp_v1;
		MR_USHORT			mp_tpage_id;
		MR_UBYTE			mp_u2;
		MR_UBYTE			mp_v2;
		MR_UBYTE			mp_u3;
		MR_UBYTE			mp_v3;
		MR_CVEC				mp_cvec;
	
		};		// MR_MPRIM_FT4


struct	__mr_mprim_g3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_G3


struct	__mr_mprim_g4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_USHORT			mp_n3;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_G4


struct	__mr_mprim_gt3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_UBYTE			mp_u0;
		MR_UBYTE			mp_v0;
		MR_USHORT			mp_clut_id;
		MR_UBYTE			mp_u1;
		MR_UBYTE			mp_v1;
		MR_USHORT			mp_tpage_id;
		MR_UBYTE			mp_u2;
		MR_UBYTE			mp_v2;
		MR_USHORT			mp_image_id;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_GT3


struct	__mr_mprim_gt4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_USHORT			mp_n3;
		MR_UBYTE			mp_u0;
		MR_UBYTE			mp_v0;
		MR_USHORT			mp_clut_id;
		MR_UBYTE			mp_u1;
		MR_UBYTE			mp_v1;
		MR_USHORT			mp_tpage_id;
		MR_UBYTE			mp_u2;
		MR_UBYTE			mp_v2;
		MR_UBYTE			mp_u3;
		MR_UBYTE			mp_v3;
		MR_USHORT			mp_image_id;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_GT4


struct	__mr_mprim_e3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_en0;
		MR_USHORT			mp_en1;
		MR_USHORT			mp_en2;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_E3


struct	__mr_mprim_e4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_USHORT			mp_en0;
		MR_USHORT			mp_en1;
		MR_USHORT			mp_en2;
		MR_USHORT			mp_en3;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_E4



struct	__mr_mprim_ge3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_en0;
		MR_USHORT			mp_en1;
		MR_USHORT			mp_en2;
		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_GE3


struct	__mr_mprim_ge4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
  		MR_USHORT			mp_en0;
		MR_USHORT			mp_en1;
		MR_USHORT			mp_en2;
		MR_USHORT			mp_en3;
  		MR_USHORT			mp_n0;
		MR_USHORT			mp_n1;
		MR_USHORT			mp_n2;
		MR_USHORT			mp_n3;
  		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_GE4


struct	__mr_mprim_lf2
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_LF2


struct	__mr_mprim_lf3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_LF3


struct	__mr_mprim_hlf3
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_pad;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_HLF3


struct	__mr_mprim_hlf4
		{
		MR_USHORT			mp_p0;
		MR_USHORT			mp_p1;
		MR_USHORT			mp_p2;
		MR_USHORT			mp_p3;
		MR_CVEC				mp_cvec;

		};		// MR_MPRIM_HLF4


// Animated texture stuff (hangs off mp_pad0)
struct	__mr_part_poly_anim
		{
		MR_ULONG	mp_mprim_type;	// enum type of MR_MPRIM
		MR_ULONG*	mp_mprim_ptr;	// index of MR_MPRIM within MR_PART's poly list (resolved to ptr)
		MR_ULONG	mp_poly_offset;	// offset into primitive buffer of actual poly (written in MRStaticResolveMOF))
		MR_ULONG*	mp_animlist;	// offset (resolved to ptr) to animlist data (at end of MOF)
	
		};	// MR_PART_POLY_ANIM


struct	__mr_part_poly_animlist_entry
		{
		MR_USHORT	mp_image_id;	// within .TXL (resolved to global image id)
		MR_USHORT	mp_duration;	// >= 1 (game cycles)
	
		};	// MR_PART_POLY_ANIMLIST_ENTRY


// Flipbook stuff (hangs off mp_pad1)
struct	__mr_part_flipbook
		{
		MR_USHORT	mp_flags;
		MR_USHORT	mp_numactions;	// number of MR_PART_FLIPBOOK_ACTIONs to follow

		};	// MR_PART_FLIPBOOK


struct	__mr_part_flipbook_action
		{
		MR_USHORT	mp_numpartcels;
		MR_USHORT	mp_partcel_index;	// actual index into MR_PART partcel array of cel 0.. others are consecutive

		};	// MR_PART_FLIPBOOK_ACTION



//------------------------------------------------------------------------------------------------
//	Externals
//------------------------------------------------------------------------------------------------

extern	MR_USHORT		MRPrim_type_gpu_sizes[];
extern	MR_USHORT		MRPrim_type_mod_sizes[];
extern	MR_USHORT		MRPrim_type_gpu_codes[];
extern	MR_TEXTURE**	MRTexture_list_ptr;
extern	MR_TEXTURE*		MREnv_strip;		


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID			MRInitialiseTextures(MR_VOID);
extern	MR_VOID			MRSetEnvMap(MR_TEXTURE*);
extern	MR_VOID			MRSetTextureList(MR_TEXTURE**);

extern	MR_VOID			MRResolveMOF(MR_MOF*);
extern	MR_VOID			MRResolveMOFTextures(MR_MOF*);
extern	MR_VOID			MRPatchMOFTranslucency(MR_MOF*, MR_BOOL);

extern	MR_ULONG		MRCalculatePartPrimSize(MR_PART*);
extern	MR_LONG			MRPresetPartPrims(MR_PART*, MR_ULONG*, MR_BOOL);
extern	MR_VOID			MRWritePartPrimCodes(MR_PART*, MR_BOOL);

extern	MR_VOID			MRScaleMOF(MR_MOF*, MR_SHORT);
extern	MR_VOID			MRRotateMOF(MR_MOF*, MR_MAT*);

extern	MR_VOID			MRCalculateMOFDimensions(MR_MOF*, MR_VEC*);
extern	MR_VOID			MRCalculateMOFVertexExtremes(MR_MOF*, MR_VEC*, MR_VEC*);
extern	MR_ULONG		MRCheckBoundingBoxOnScreen(MR_SVEC*, MR_ULONG*);
extern	MR_ULONG		MRCheckBoundingBoxOnScreenUsingEdges(MR_SVEC*, MR_ULONG*);

extern	MR_MOF*			MRCreateWireframeMOF(MR_MOF*, MR_USHORT, MR_ULONG);
extern	MR_MOF*			MRStaticCreateWireframeMOF(MR_MOF*, MR_USHORT, MR_ULONG);

// Hilites
extern	MR_ULONG*		MRPartGetPrim(MR_MOF*, MR_USHORT, MR_USHORT);
extern	MR_ULONG		MRPartGetPrimOffset(MR_MOF*, MR_USHORT, MR_USHORT);
extern	MR_ULONG		MRPartGetPrimOffsetFromPointer(MR_MOF*, MR_USHORT, MR_ULONG*);
extern	MR_USHORT		MRGetNumberOfHilites(MR_MOF*,	MR_LONG,	MR_LONG);
extern	MR_HILITE*		MRGetFirstHilite(MR_MOF*, MR_LONG, MR_LONG);
extern	MR_USHORT		MRFillHiliteSVECArray(MR_MOF*, MR_LONG, MR_LONG, MR_SVEC*);
extern	MR_USHORT		MRFillHiliteSVECPointerArray(MR_MOF*, MR_LONG, MR_LONG, MR_SVEC**);

extern	MR_ULONG		MRCalculateMOFAnimatedPolys(MR_MOF*);

#endif 	//__MR_MOF_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

