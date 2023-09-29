/******************************************************************************
*%%%% filename.ext
*------------------------------------------------------------------------------
*
*	<Description>
*
*	CHANGED		PROGRAMMER		REASON
*  -------  	----------  	------
*	<date>		<Name>			<Description>
*
*%%%**************************************************************************/

#ifndef	__MEMCARD_H
#define	__MEMCARD_H

#include	"system.h"

// Defines for memory card filenames and descriptions
#ifdef PSX_MODE_NTSC
#define	SAVED_GAME_NAME	"\x82" "\x65" "\x82" "\x92" "\x82" "\x8f" "\x82" "\x87" "\x82" "\x87" "\x82" "\x85" "\x82" "\x92"
#define	SAVED_GAME_FILE	"BASLUS-00506FROGGER"
#else
#define	SAVED_GAME_NAME	"\x82" "\x65" "\x82" "\x71" "\x82" "\x6e" "\x82" "\x66" "\x82" "\x66" "\x82" "\x64" "\x82" "\x71"
#define	SAVED_GAME_FILE	"BESLES-00704FROGGER" 
//#else
//#ifdef FROGGER_JAP
//#define	SAVED_GAME_NAME	"\x82" "\x65" "\x82" "\x71" "\x82" "\x6e" "\x82" "\x66" "\x82" "\x66" "\x82" "\x64" "\x82" "\x71"
//#define	SAVED_GAME_FILE	"BISLPS-00000FROGGER" 
#endif


// Defines for internal memcard.c use
#define	CARD_IOE				(0)
#define	CARD_ERROR			(1)
#define	CARD_TIMOUT			(2)
#define	CARD_NEW				(3)

// Number of times for retrying load/save routines
#define	CARD_RETRY			(2)

// Bits returned by Card_test_cards();
#define	TC_FOUND_CARD_0	(1<<0)
#define	TC_FOUND_CARD_1	(1<<1)
#define	TC_FOUND_GAME_0	(1<<2)
#define	TC_FOUND_GAME_1	(1<<3)

// Bits returned by Card_get_info();
#define	CI_NULL				(0<<0)			// If there's no card...
#define	CI_CARD_ERROR		(1<<0)			// Set if the card commands errored
#define	CI_CARD_PRESENT	(1<<1)			// Set if a card was found in the slot
#define	CI_UNFORMATTED		(1<<2)			// Set if it was unformatted
#define	CI_CARD_FULL		(1<<3)			// Set if the card was full (if gc_check_space)
#define	CI_GAME_FOUND		(1<<4)			// Set if a saved game was found (if gc_check_space)


// Return values for	Card_load_file()/Card_load_file_core();
enum		{
			CLG_LOAD_OK,
			CLG_NO_CARD,
			CLG_NO_GAME,
			CLG_LOAD_ERROR,
			CLG_UNFORMATTED,
			};


// Return values for	Card_save_file()/Card_save_file_core();
enum		{
			CSG_SAVE_OK,
			CSG_NO_CARD,
			CSG_FULL_CARD,
			CSG_SAVE_ERROR,
			CSG_UNFORMATTED,
			};


// Return values for Format_card();

enum		{
			CFC_FORMAT_OK,
			CFC_NO_CARD,
			CFC_FORMAT_FAILED
			};


// Structures

typedef	struct	__card_image
			{
			MR_ULONG		ci_id;
			MR_ULONG		ci_flag;
			MR_ULONG		ci_cbnum;
			MR_USHORT	ci_clutx;
			MR_USHORT	ci_cluty;
			MR_USHORT	ci_clutw;
			MR_USHORT	ci_cluth;
			MR_UBYTE		ci_clut[32];
			MR_ULONG		ci_pbnum;
			MR_USHORT	ci_pixx;
			MR_USHORT	ci_pixy;
			MR_USHORT	ci_pixw;
			MR_USHORT	ci_pixh;
			MR_UBYTE		ci_image[2];
			} CARD_IMAGE;


typedef	struct _card_header 
			{
			MR_UBYTE		mc_magic[2];
			MR_UBYTE		mc_type;
			MR_UBYTE		mc_blocks;
			MR_UBYTE		mc_name[64];
			MR_UBYTE		mc_pad[28];
			MR_UBYTE		mc_clut[32];
			MR_UBYTE		mc_image[3][128];
			}	CARD_HEADER;

// Prototypes

extern	MR_VOID		TestCard(MR_VOID);
							
extern	MR_VOID		Card_init(MR_VOID);
extern	MR_ULONG		Card_test_cards(MR_VOID);
extern	MR_ULONG		Card_load_file(MR_UBYTE*, MR_ULONG, MR_ULONG);
extern	MR_ULONG		Card_load_file_core(MR_UBYTE*, MR_ULONG, MR_ULONG);
extern	MR_ULONG		Card_save_file(MR_UBYTE*, MR_ULONG, MR_ULONG);
extern	MR_ULONG		Card_save_file_core(MR_UBYTE*, MR_ULONG, MR_ULONG);
extern	MR_ULONG		Card_format(MR_ULONG);

extern	MR_ULONG		Card_get_info(	MR_ULONG, MR_BOOL);
extern	MR_ULONG		Card_get_events_sw(MR_VOID);
extern	MR_ULONG		Card_get_events_hw(MR_VOID);
extern	MR_VOID		Card_clear_events_sw(MR_VOID);
extern	MR_VOID		Card_clear_events_hw(MR_VOID);

#endif	//_MEMCARD_H


