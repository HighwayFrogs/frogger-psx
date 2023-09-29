/******************************************************************************
*%%%% mr_vram.h
*------------------------------------------------------------------------------
*
*	Header file for mr_vram.c
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	09.07.96	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_texture			MR_TEXTURE;
typedef	struct	__mr_vlofile			MR_VLOFILE;
typedef	struct	__mr_txsetup			MR_TXSETUP;
typedef	struct	__mr_clutsetup			MR_CLUTSETUP;
typedef struct	__mr_tblock				MR_TBLOCK;

#else
#ifndef	__MR_VRAM_H
#define	__MR_VRAM_H


//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------


#define	MR_VLO_TAG						MR_MAKE_ID('V','R','G','2')

#define	MR_GET_TEXTURE_W(i)				((i)->te_w)
#define	MR_GET_TEXTURE_H(i)				((i)->te_h)
#define	MR_GET_TEXTURE_VRAM_X(i)		(((((i)->te_tpage_id)&0xf)<<6) + ((i)->te_u0 >> (2 - ((((i)->te_tpage_id>>7)&3)))))
#define	MR_GET_TEXTURE_VRAM_Y(i)		((((i)->te_tpage_id&0x10)<<4)+((i)->te_v0)) 
#define	MR_GET_TEXTURE_CLUT_X(i)		(((i)->te_clut_id & 0x3f)<<4)	
#define	MR_GET_TEXTURE_CLUT_Y(i)		(((i)->te_clut_id)>>6)
#define	MR_GET_TEXTURE_ABR(i)			(((i)->te_tpage_id & 0x60)>>5)
#define	MR_SET_TEXTURE_ABR(i,a)			((i)->te_tpage_id=(((i)->te_tpage_id&0x19f)|((a)<<5)))


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_texture
			{
			MR_USHORT		te_flags;		// Yeah. Flags. This _could_ indicate it's a sprite (bit 15)
			MR_UBYTE		te_w;	 		// Width of sprite (after hit adjustment)
			MR_UBYTE		te_h;	 		// Height of sprite (after hit adjustment)
		
			MR_UBYTE		te_u0;			// Copy as an MR_LONG
			MR_UBYTE		te_v0;
			MR_USHORT		te_clut_id;
		
			MR_UBYTE		te_u1;	  		// Copy as an MR_LONG
			MR_UBYTE		te_v1;
			MR_USHORT		te_tpage_id;
		
			MR_UBYTE		te_u2;			// Copy as an MR_SHORT
			MR_UBYTE		te_v2;
		
			MR_UBYTE		te_u3;			// Copy as an MR_SHORT
			MR_UBYTE		te_v3;
		
			};		// MR_TEXTURE

struct	__mr_vlofile
			{
			MR_ULONG		vf_ident;
			MR_ULONG		vf_txsetup_count;
			MR_ULONG		vf_txsetup_offset;
			MR_ULONG		vf_clutsetup_count;
			MR_ULONG		vf_clutsetup_offset;

			};		// MR_VLOFILE

struct	__mr_txsetup
			{
			MR_RECT			ts_vram_rect;
			MR_ULONG		ts_vram_offset;
			MR_USHORT		ts_id;
			MR_USHORT		ts_tpage_id;
			MR_USHORT		ts_clut_id;
			MR_USHORT		ts_flags;
			MR_UBYTE		ts_u;
			MR_UBYTE		ts_v;
			MR_UBYTE		ts_w;
			MR_UBYTE		ts_h;

			};		//	MR_TXSETUP;

struct	__mr_clutsetup
			{
			MR_RECT			cs_clut_rect;
			MR_ULONG		cs_clut_offset;

			};		//	MR_CLUTSETUP;

struct	__mr_tblock
			{
			MR_TBLOCK*		tb_next_node;			// pointer to next object in linked list		
			MR_TBLOCK*		tb_prev_node;			// pointer to previous object in linked list
			
			MR_ULONG		tb_resource_id;			// Resource ID associated with this dynamic texture block
	
			MR_TEXTURE***	tb_pointers;			// Pointer to block of pointers (to MR_TEXTURES)
			MR_TEXTURE*		tb_textures;			// Pointer to block of MR_TEXTUREs

			};		//	MR_TBLOCK;

//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_BOOL	MRProcessVLO(MR_ULONG, MR_ULONG*);
extern	MR_BOOL	MRFreeResourceTextureBlock(MR_ULONG);

#endif	//__MR_VRAM_H 
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
