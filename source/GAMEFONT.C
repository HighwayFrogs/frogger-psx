/******************************************************************************
*%%%% gamefont.c
*------------------------------------------------------------------------------
*
*	Font definitions
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	10.04.97	Dean Ashton		Created
*
*%%%**************************************************************************/

#include	"gamefont.h"

MR_FONT_CHAR_INFO std_font_chars[] =
			{
			// X,Y,Width, Page

			{  0,  0,8,0},							// SPACE
			{  8,  0,8,0},							// !
			{ 16,  0,8,0},							// "
			{ 24,  0,8,0},							// #
			{ 32,  0,8,0},							// $	
			{ 40,  0,8,0},							// %
			{ 48,  0,8,0},							// &
			{ 56,  0,8,0},							// '
			{ 64,  0,8,0},							// (
			{ 72,  0,8,0},							// )
			{ 80,  0,8,0},							// *
			{ 88,  0,8,0},							// +
			{ 96,  0,8,0},							// ,
			{106,  0,8,0},							// -
			{112,  0,8,0},							// .
			{120,  0,8,0},							// /
			{128,  0,8,0},							// 0
			{136,  0,8,0},							// 1 
			{144,  0,8,0},							// 2
			{152,  0,8,0},							// 3
			{160,  0,8,0},							// 4
			{168,  0,8,0},							// 5
			{176,  0,8,0},							// 6
			{184,  0,8,0},							// 7
			{192,  0,8,0},							// 8
			{200,  0,8,0},							// 9
			{208,  0,8,0},							// :
			{216,  0,8,0},							// ;
			{224,  0,8,0},							// <
			{232,  0,8,0},							// =
			{240,  0,8,0},							// >
			{248,  0,8,0},							// ?

			{  0,  8,8,0},							// @
			{  8,  8,8,0},							// A
			{ 16,  8,8,0},							// B
			{ 24,  8,8,0},							// C
			{ 32,  8,8,0},							// D
			{ 40,  8,8,0},							// E
			{ 48,  8,8,0},							// F
			{ 56,  8,8,0},							// G
			{ 64,  8,8,0},							// H
			{ 72,  8,8,0},							// I
			{ 80,  8,8,0},							// J
			{ 88,  8,8,0},							// K
			{ 96,  8,8,0},							// L
			{104,  8,8,0},							// M
			{112,  8,8,0},							// N
			{120,  8,8,0},							// O
			{128,  8,8,0},							// P
			{136,  8,8,0},							// Q 
			{144,  8,8,0},							// R
			{152,  8,8,0},							// S
			{160,  8,8,0},							// T
			{168,  8,8,0},							// U
 			{176,  8,8,0},							// V
			{184,  8,8,0},							// W
			{192,  8,8,0},							// X
			{200,  8,8,0},							// Y
			{208,  8,8,0},							// Z
			{216,  8,8,0},							// [
			{224,  8,8,0},							// This is a forward slash (top-left to bottom right)
			{232,  8,8,0},							// ]
			{240,  8,8,0},							// ^	... this is a 'degrees' symbol
			{248,  8,8,0},							// _

			{  0, 16,8,0},							// `
			{  8, 16,8,0},							// a
			{ 16, 16,8,0},							// b
			{ 24, 16,8,0},							// c
			{ 32, 16,8,0},							// d
			{ 40, 16,8,0},							// e
			{ 48, 16,8,0},							// f
			{ 56, 16,8,0},							// g
			{ 64, 16,8,0},							// h
			{ 72, 16,8,0},							// i
			{ 80, 16,8,0},							// j
			{ 88, 16,8,0},							// k
			{ 96, 16,8,0},							// l
			{104, 16,8,0},							// m
			{112, 16,8,0},							// n
			{120, 16,8,0},							// o
			{128, 16,8,0},							// p
			{136, 16,8,0},							// q 
			{144, 16,8,0},							// r
			{152, 16,8,0},							// s
			{160, 16,8,0},							// t
			{168, 16,8,0},							// u
			{176, 16,8,0},							// v
			{184, 16,8,0},							// w
			{192, 16,8,0},							// x
			{200, 16,8,0},							// y
			{208, 16,8,0},							// z
			{216, 16,8,0},							// {
			{224, 16,8,0},							// |
			{232, 16,8,0},							// }
			{240, 16,8,0},							// ~
			{248, 16,8,0},							// 

			// European extra characters

			{  0,  0,8,0},							// graph accent lowercase a 0x80
			{  0,  0,8,0},							// graph accent lowercase e
			{  0,  0,8,0},							// graph accent lowercase i
			{  0,  0,8,0},							// graph accent lowercase o
			{  0,  0,8,0},							// graph accent lowercase u
									
			{  0,  0,8,0},							// graph accent uppercase A 0x85
			{  0,  0,8,0},							// graph accent uppercase E
			{  0,  0,8,0},							// graph accent uppercase I
			{  0,  0,8,0},							// graph accent uppercase O
			{  0,  0,8,0},							// graph accent uppercase U

			{  0,  0,8,0},							// acute accent lowercase a 0x8a
			{  0,  0,8,0},							// acute accent lowercase e
			{  0,  0,8,0},							// acute accent lowercase i
			{  0,  0,8,0},							// acute accent lowercase o
			{  0,  0,8,0},							// acute accent lowercase u

			{  0,  0,8,0},							// acute accent uppercase A 0x8f
			{  0,  0,8,0},							// acute accent uppercase E
			{  0,  0,8,0},							// acute accent uppercase I
			{  0,  0,8,0},							// acute accent uppercase O
			{  0,  0,8,0},							// acute accent uppercase U

			{  0,  0,8,0},							// hatted lowercase a 0x94
			{  0,  0,8,0},							// hatted lowercase e
			{  0,  0,8,0},							// hatted lowercase i
			{  0,  0,8,0},							// hatted lowercase o
			{  0,  0,8,0},							// hatted lowercase u

			{  0,  0,8,0},							// hatted uppercase A
			{  0,  0,8,0},							// hatted uppercase E
			{  0,  0,8,0},							// hatted uppercase I
			{  0,  0,8,0},							// hatted uppercase O
			{  0,  0,8,0},							// hatted uppercase U

			{  0,  0,8,0},							// umlauted lowercase a
			{  0,  0,8,0},							// umlauted lowercase i
			{  0,  0,8,0},							// umlauted lowercase o
			{  0,  0,8,0},							// umlauted lowercase u
							
			{  0,  0,8,0},							// umlauted uppercase A
			{  0,  0,8,0},							// umlauted uppercase I
			{  0,  0,8,0},							// umlauted uppercase O
			{  0,  0,8,0},							// umlauted uppercase U

			{  0,  0,8,0},							// cedilla lowercase 'c'
			{  0,  0,8,0},							// cedilla uppercase 'C'

			{  0,  0,8,0},							// tilde lowercase 'n'
			{  0,  0,8,0},							// tilde uppercase 'N'

			{  0,  0,8,0},							// Upside down '?'
	
			{  0,  0,8,0},							// lowercase 'oe'
			{  0,  0,8,0},							// uppercase 'OE'

			{  0,  0,8,0},							// German 'Beta' symbol

			{  0,  0,8,0},							// German 'SS' symbol

			};



MR_FONT_CHAR_INFO debug_font_chars[] =
			{
			// X,Y,Width, Page

			{  0,  0,6,0},							// SPACE
			{  6,  0,6,0},							// !
			{ 12,  0,6,0},							// "
			{ 18,  0,6,0},							// #
			{ 24,  0,6,0},							// $
			{ 30,  0,6,0},							// %
			{ 36,  0,6,0},							// &
			{ 42,  0,6,0},							// '
			{ 48,  0,6,0},							// (
			{ 54,  0,6,0},							// )
			{ 60,  0,6,0},							// *
			{ 66,  0,6,0},							// +
			{ 72,  0,6,0},							// ,
			{ 78,  0,6,0},							// -
			{ 84,  0,6,0},							// .
			{ 90,  0,6,0},							// /
			{ 96,  0,6,0},							// 0
			{102,  0,6,0},							// 1 
			{108,  0,6,0},							// 2
			{114,  0,6,0},							// 3
			{120,  0,6,0},							// 4
			{126,  0,6,0},							// 5
			{132,  0,6,0},							// 6
			{138,  0,6,0},							// 7
			{144,  0,6,0},							// 8
			{150,  0,6,0},							// 9
			{156,  0,6,0},							// :
			{162,  0,6,0},							// ;
			{168,  0,6,0},							// <
			{174,  0,6,0},							// =
			{180,  0,6,0},							// >
			{186,  0,6,0},							// ?

			{  0,  6,6,0},							// @
			{  6,  6,6,0},							// A
			{ 12,  6,6,0},							// B
			{ 18,  6,6,0},							// C
			{ 24,  6,6,0},							// D
			{ 30,  6,6,0},							// E
			{ 36,  6,6,0},							// F
			{ 42,  6,6,0},							// G
			{ 48,  6,6,0},							// H
			{ 54,  6,6,0},							// I
			{ 60,  6,6,0},							// J
			{ 66,  6,6,0},							// K
			{ 72,  6,6,0},							// L
			{ 78,  6,6,0},							// M
			{ 84,  6,6,0},							// N
			{ 90,  6,6,0},							// O
			{ 96,  6,6,0},							// P
			{102,  6,6,0},							// Q 
			{108,  6,6,0},							// R
			{114,  6,6,0},							// S
			{120,  6,6,0},							// T
			{126,  6,6,0},							// U
 			{132,  6,6,0},							// V
			{138,  6,6,0},							// W
			{144,  6,6,0},							// X
			{150,  6,6,0},							// Y
			{156,  6,6,0},							// Z
			{162,  6,6,0},							// [
			{168,  6,6,0},							// This is a forward slash (top-left to bottom right)
			{174,  6,6,0},							// ]
			{180,  6,6,0},							// ^	... this is a 'degrees' symbol
			{186,  6,6,0},							// _

			{  0, 12,6,0},							// `
			{  6, 12,6,0},							// a
			{ 12, 12,6,0},							// b
			{ 18, 12,6,0},							// c
			{ 24, 12,6,0},							// d
			{ 30, 12,6,0},							// e
			{ 36, 12,6,0},							// f
			{ 42, 12,6,0},							// g
			{ 48, 12,6,0},							// h
			{ 54, 12,6,0},							// i
			{ 60, 12,6,0},							// j
			{ 66, 12,6,0},							// k
			{ 72, 12,6,0},							// l
			{ 78, 12,6,0},							// m
			{ 84, 12,6,0},							// n
			{ 90, 12,6,0},							// o
			{ 96, 12,6,0},							// p
			{102, 12,6,0},							// q 
			{108, 12,6,0},							// r
			{114, 12,6,0},							// s
			{120, 12,6,0},							// t
			{126, 12,6,0},							// u
			{132, 12,6,0},							// v
			{138, 12,6,0},							// w
			{144, 12,6,0},							// x
			{150, 12,6,0},							// y
			{156, 12,6,0},							// z
			{162, 12,6,0},							// {
			{168, 12,6,0},							// |
			{174, 12,6,0},							// }
			{180, 12,6,0},							// ~
			{186, 12,6,0},							// 6

			// European extra characters

			{  0,  0,6,0},							// graph accent lowercase a 0x80
			{  0,  0,6,0},							// graph accent lowercase e
			{  0,  0,6,0},							// graph accent lowercase i
			{  0,  0,6,0},							// graph accent lowercase o
			{  0,  0,6,0},							// graph accent lowercase u
									
			{  0,  0,6,0},							// graph accent uppercase A 0x85
			{  0,  0,6,0},							// graph accent uppercase E
			{  0,  0,6,0},							// graph accent uppercase I
			{  0,  0,6,0},							// graph accent uppercase O
			{  0,  0,6,0},							// graph accent uppercase U

			{  0,  0,6,0},							// acute accent lowercase a 0x8a
			{  0,  0,6,0},							// acute accent lowercase e
			{  0,  0,6,0},							// acute accent lowercase i
			{  0,  0,6,0},							// acute accent lowercase o
			{  0,  0,6,0},							// acute accent lowercase u

			{  0,  0,6,0},							// acute accent uppercase A 0x8f
			{  0,  0,6,0},							// acute accent uppercase E
			{  0,  0,6,0},							// acute accent uppercase I
			{  0,  0,6,0},							// acute accent uppercase O
			{  0,  0,6,0},							// acute accent uppercase U

			{  0,  0,6,0},							// hatted lowercase a 0x94
			{  0,  0,6,0},							// hatted lowercase e
			{  0,  0,6,0},							// hatted lowercase i
			{  0,  0,6,0},							// hatted lowercase o
			{  0,  0,6,0},							// hatted lowercase u

			{  0,  0,6,0},							// hatted uppercase A
			{  0,  0,6,0},							// hatted uppercase E
			{  0,  0,6,0},							// hatted uppercase I
			{  0,  0,6,0},							// hatted uppercase O
			{  0,  0,6,0},							// hatted uppercase U

			{  0,  0,6,0},							// umlauted lowercase a
			{  0,  0,6,0},							// umlauted lowercase i
			{  0,  0,6,0},							// umlauted lowercase o
			{  0,  0,6,0},							// umlauted lowercase u
						
			{  0,  0,6,0},							// umlauted uppercase A
			{  0,  0,6,0},							// umlauted uppercase I
			{  0,  0,6,0},							// umlauted uppercase O
			{  0,  0,6,0},							// umlauted uppercase U

			{  0,  0,6,0},							// cedilla lowercase 'c'
			{  0,  0,6,0},							// cedilla uppercase 'C'

			{  0,  0,6,0},							// tilde lowercase 'n'
			{  0,  0,6,0},							// tilde uppercase 'N'

			{  0,  0,6,0},							// Upside down '?'
	
			{  0,  0,6,0},							// lowercase 'oe'
			{  0,  0,6,0},							// uppercase 'OE'

			{  0,  0,6,0},							// German 'Beta' symbol

			{  0,  0,6,0},							// German 'SS' symbol

			};

// -- Main MR_FONT_INFO structures --

MR_FONT_INFO std_font =
			{
			&im_newfont,							// Pointer to the base sprite for this font image
			&std_font_chars[0],						// Pointer to an array of MR_FONT_CHAR_INFO structures
			8,	   									// Height of characters in this font
			1,	   									// Abr 1 (Additive)
			NULL,  									// Flags (Transparency on)
			};

MR_FONT_INFO debug_font =
			{
			&im_dbugfont,							// Pointer to the base sprite for this font image
			debug_font_chars,						// Pointer to an array of MR_FONT_CHAR_INFO structures
			6,										// Height of characters in this font
			1,										// Abr 1 (Additive)
			NULL,									// Flags (Transparency on)
			};
