/******************************************************************************
*%%%% credits.c
*------------------------------------------------------------------------------
*
*	Routines for credits screens.
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

#include "mr_all.h"
#include "credits.h"
#include "tempopt.h"
#include "gamefont.h"
#include "options.h"
#include "gamesys.h"
#include "project.h"
#ifdef PSX
#include "stream.h"
#endif

#if 0

MR_TEXT_AREA*	Option_credits_text_area;

MR_STRPTR		Option_std_credits_text_title[]				=	{"%jcSTANDARD CREDITS", NULL};

// Font textures
MR_TEXTURE*		Credit_font_textures[2][26]=
	{
		{
		&im_hi_a,
		&im_hi_b,
		&im_hi_c,
		&im_hi_d,
		&im_hi_e,
		&im_hi_f,
		&im_hi_g,
		&im_hi_h,
		&im_hi_i,
		&im_hi_j,
		&im_hi_k,
		&im_hi_l,
		&im_hi_m,
		&im_hi_n,
		&im_hi_o,
		&im_hi_p,
		&im_hi_q,
		&im_hi_r,
		&im_hi_s,
		&im_hi_t,
		&im_hi_u,
		&im_hi_v,
		&im_hi_w,
		&im_hi_x,
		&im_hi_y,
		&im_hi_z,
		},
		{
		&im_hi_a,
		&im_hi_b,
		&im_hi_c,
		&im_hi_d,
		&im_hi_e,
		&im_hi_f,
		&im_hi_g,
		&im_hi_h,
		&im_hi_i,
		&im_hi_j,
		&im_hi_k,
		&im_hi_l,
		&im_hi_m,
		&im_hi_n,
		&im_hi_o,
		&im_hi_p,
		&im_hi_q,
		&im_hi_r,
		&im_hi_s,
		&im_hi_t,
		&im_hi_u,
		&im_hi_v,
		&im_hi_w,
		&im_hi_x,
		&im_hi_y,
		&im_hi_z,
		},
	};

// Model resource ids
MR_ULONG	Credit_model_resouce_id[]=
	{
//	RES_CRD_CAV_BAT_XAR,
//	RES_CRD_CAV_SNAIL_XAR,
//	RES_CRD_CAV_SPIDER_XAR,
//	RES_CRD_DES_BEETLE_XMR,
//	RES_CRD_DES_BISON_XAR,
//	RES_CRD_DES_SNAKE_XMR,
//	RES_CRD_DES_TUMBLEWEED_XAR,
//	RES_CRD_DES_VULTURE_XAR,
//	RES_CRD_FOR_HEDGEHOG_XMR,
//	RES_CRD_GEN_FROG_XAR,
//	RES_CRD_ORG_CROCODILE_XAR,
//	RES_CRD_ORG_TURTLE_XMR,
//	RES_CRD_SKY_BIPLANE1_XAR,
//	RES_CRD_SKY_BIRD1_XAR,
//	RES_CRD_SKY_HELICOPTER_XAR,
//	RES_CRD_SKY_SQUADRON_XAR,
//	RES_CRD_SUB_BUTTERFLY2_XMR,
//	RES_CRD_SUB_DOG_XAR,
//	RES_CRD_SUB_SWAN_XAR,
//	RES_CRD_SWP_MUTANT_FISH_XMR,
//	RES_CRD_SWP_RAT_XAR,
	NULL,
	};

// Strings used in credit entries
MR_UBYTE		Credit_text[CREDITS_MAX_NUM_STRINGS][CREDITS_MAX_NUM_LETTERS_PER_STRING]=
	{
	{"Development Team"},								// 00
		{"Programming Team"},							// 01
			{"Lead Programmer"},						// 02
				{"Tim Closs"},							// 03
			{"Programmers"},							// 04
				{"Martin Kift"},						// 05
				{"William Bell"},						// 06
				{"Gary Richards"},						// 07
			{"Programming Support"},					// 08
				{"Mark Stamps"},						// 09
		{"Level Creators"},								// 10
			{"Level Design"},							// 11
				{"Ian Saunter"},						// 12
				{"Jon Double"},							// 13
				{"Dave Holloway"},						// 14
				{"Chris Down of Hasbro Interactive"},	// 15
			{"Mapping"},								// 16
				{"Jon Double"},							// 17
				{"Dave Holloway"},						// 18
		{"Art Team"},									// 19
			{"Lead Artist"},							// 20
				{"Marcus Broome"},						// 21
			{"Artists"},								// 22
				{"Barry Scott"},						// 23
				{"Jason Evans"},						// 24
				{"Leavon Archer"},						// 25
		{"Project Management"},							// 26
			{"Project Leader"},							// 27
				{"Kevin Mullard "},						// 28
			{"Development Assistant"},					// 29
				{"Lindsay Pollard"},					// 30
			{"Executive Producer"},						// 31
				{"Ian Saunter"},						// 32
	{"Support Teams"},									// 33
		{"AV Department"},								// 34
			{"AV Manager"},								// 35
				{"Pete Murphy"},						// 36
			{"Music"},									// 37
				{"Andrew Barnabas"},					// 38
				{"Paul Arnold"},						// 39
				{"Pete Murphy"},						// 40
			{"Sound Effects"},							// 41
				{"Paul Arnold"},						// 42
			{"Video Post Production"},					// 43
				{"Tom Oswald"},							// 44
		{"Quality Assurance"},							// 45
			{"Lead Tester"},							// 46
				{"Alex Sulman"},						// 47
			{"Additional Testing"},						// 48
				{"Sarah Lloyd"},						// 49
				{"Dan Smith"},							// 50
		{"Technologies Group"},							// 51
			{"Technologies Group Manager"},				// 52
				{"Mike Ball"},							// 53
			{"Project Leader"},							// 54
				{"Dean Ashton"},						// 55
			{"Playstation Technologies"},				// 56
				{"Tim Closs"},							// 57
				{"Dean Ashton"},						// 58
			{"Windows 95 Technologies"},				// 59
				{"Julian Rex"},							// 60
			{"Mapping and Conversion Technologies"},	// 61
				{"Andrew Ostler"},						// 62
				{"Matt Johnson"},						// 63
			{"Animation Technologies"},					// 64
				{"Ian Elsley"},							// 65
		{"IT Department"},								// 66
			{"IT Manager"},								// 67
				{"Steve Loughran"},						// 68
			{"IT Assistant"},							// 69
				{"Dean Miller"},						// 70
	{"Special Thanks To"},								// 71
		{"Katie Lea"},									// 72
		{"Colin Swinbourne"},							// 73
		{"Craig Sullivan"},								// 74
		{"Gillian Henderson"},							// 75
	{"Hasbro Interactive Frogger team"},				// 76
		{"Visionary"},									// 77
			{"Tom Dusenberry"},							// 78
		{"Vice President, R&D"},						// 79
			{"Tony Parks"},								// 80
		{"Managing Director, Europe"},					// 81
			{"Barry Jafrato"},							// 82
		{"Development director"},						// 83
			{"Kevin Buckner"},							// 84
		{"Producers"},									// 85
			{"Chris Down"},								// 86
			{"Andrei Nadin"},							// 87
		{"Associate Producer"},							// 88
			{"Louise McTighe"},							// 89
		{"Creative Directors"},							// 90
			{"Clive Robert"},							// 91
			{"John Sutyak"},							// 92
		{"Additional Design"},							// 93
			{"David Walls"},							// 94
				{"Chris Down"},							// 95
		{"US Product Coordinator"},						// 96
			{"BIG Mike Glosecki"},						// 97
		{"Vice President, Marketing"},					// 98
			{"Gary Carlin"},							// 99
			{"US Debra Shlens"},						// 100
			{"Europe Mary Miller"},						// 101
			{"Germany Torsten Opperman"},				// 102
			{"France Olivier Salomon"},					// 103
		{"Localization"},								// 104
			{"Sam Baker"},								// 105
		{"Packaging"},									// 106
			{"US Steve Webster"},						// 107
			{"Europe Mary Miller"},						// 108
				{"Liz Morgan"},							// 109
		{"Website creator"},							// 110
			{"James Sheahan"},							// 111
		{"Quality Assurance UK"},						// 112
			{"QA Manager	"},							// 113
				{"Roger Carpenter"},					// 114
			{"Lead tester"},							// 115
				{"Stuart Thody"},						// 116
			{"Testers"},								// 117
				{"Richard Alexander"},					// 118
				{"Neall Campbell"},						// 119
		{"Quality Assurance US"},						// 120
			{"Director of Quality Assurance"},			// 121
				{"Mike Craighead"},						// 122
			{"Testers"},								// 123
				{"????"},								// 124
				{"?????"},								// 125
				{"????"},								// 126
		{"Public Relations"},							// 127
			{"Dana Henry"},								// 128
		{"Vice President, Finance"},					// 129
			{"Ron Parkinson"},							// 130
		{"Sales"},										// 131
			{"Vice President, Sales"},					// 132
				{"Jim Adams"},							// 133
				{"??? Jonathon Leech?"},				// 134
				{"??? Russell Serbegi??"},				// 135
				{"???"},								// 136
				{"???"},								// 137
				{"UK: Zoe Tremlett"},					// 138
		{"Special Thanks "},							// 139
			{"Kevin Gillespie"},						// 140
			{"Kim Hannaway"},							// 141
			{"Whitney Grimm"},							// 142
			{"John Lamond"},							// 143
			{"Lee McLaughlin"},							// 144
			{"Tony Moreira"},							// 145
			{"Lori Rostkowski"},						// 146
			{"Bob Sedacca"},							// 147
			{"Mike Constantas"},						// 148
			{"Richard Lever"},							// 149
			{"Janet Oakes"},							// 150
			{"Alka Patel"},								// 151
			{"Kellie Rice"},							// 152
	
	};

// Models that move about
CREDIT_MODEL	Credit_models[]=
	{
	// Model number				Start position	End position	Speed	// Update
	{CREDIT_MODEL_CAV_BAT,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_SNAIL,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_SPIDER,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_BEETLE,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_BISON,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_SNAKE,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_TUMBLEWEED,	-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_VULTURE,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_HEDGEHOG,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_FROG,			-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_CROCODILE,	-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_TURTLE,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_BIPLANE1,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_BIRD1,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_HELICOPTER,	-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_SQUADRON,		-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_BUTTERFLY2,	-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_DOG,			-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_SWAN,			-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_MUTANT_FISH,	-200,0,0,0,		100,0,0,0,		10,		NULL},
	{CREDIT_MODEL_RAT,			-200,0,0,0,		100,0,0,0,		10,		NULL},
};

// Text entries that appear on the screen
CREDIT_ENTRY	Credit_entry[]=
	{
	// Font number		 XPos	YPos	Text ptr			Fade up/On screen/Fade down
	{CREDIT_FONT_BIG,	  16,	 16,	&Credit_text[0][0],  30*1,		30*15,	30*1},

	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[1][0],  30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[2][0],  30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[3][0],  30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[4][0],  30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[5][0],  30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[6][0],  30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[7][0],  30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[8][0],  30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[9][0],  30*1,		30*1,	30*1},

	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[10][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[11][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[12][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[13][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[14][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[15][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[16][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[17][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[18][0], 30*1,		30*1,	30*1},

	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[19][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[20][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[21][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[22][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[23][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[24][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[25][0], 30*1,		30*1,	30*1},

	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[26][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[27][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[28][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[29][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[30][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[31][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[32][0], 30*1,		30*1,	30*1},


	 {CREDIT_FONT_BIG,	  16,	 16,	&Credit_text[33][0], 30*1,		30*1,	30*1},
	
	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[34][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[35][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[36][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[37][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[38][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[39][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[40][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[41][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[42][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[43][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[44][0], 30*1,		30*1,	30*1},
	
	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[45][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[46][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[47][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[48][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[49][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[50][0], 30*1,		30*1,	30*1},
	
	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[51][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[52][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[53][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[54][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[55][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[56][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[57][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[58][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[59][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[60][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[61][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[62][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[63][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[64][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[65][0], 30*1,		30*1,	30*1},
	
	 {CREDIT_FONT_BIG,	  48,	 48,	&Credit_text[66][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[67][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[68][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  80,	128,	&Credit_text[69][0], 30*1,		30*1,	30*1},
	   {CREDIT_FONT_SML,  96,	150,	&Credit_text[70][0], 30*1,		30*1,	30*1},
	
	 {CREDIT_FONT_BIG,	  16,	 16,	&Credit_text[71][0], 30*1,		30*1,	15*1},
	  {CREDIT_FONT_SML,	  96,	150,	&Credit_text[72][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  96,	150,	&Credit_text[73][0], 30*1,		30*1,	30*1},
	  {CREDIT_FONT_SML,	  96,	150,	&Credit_text[74][0], 30*1,		30*1,	30*1},
      {CREDIT_FONT_SML,   96,   150,    &Credit_text[75][0], 30*1,      30*1,   30*1},


	{CREDIT_FONT_SML,     16,   100,    &Credit_text[76][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[77][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[78][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[79][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[80][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[81][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[82][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[83][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[84][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[85][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[86][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[87][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[88][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[89][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[90][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[91][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[92][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[93][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[94][0], 30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[95][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[96][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[97][0], 30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[98][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[99][0], 30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[100][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[101][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[102][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[103][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[104][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[105][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[106][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[107][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[108][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[109][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[110][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[111][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[112][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[113][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[114][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[115][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[116][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[117][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[118][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[119][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[120][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[121][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[122][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[123][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[124][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[125][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[126][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[127][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[128][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[129][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[130][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[131][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[132][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[133][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[134][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[135][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[136][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[137][0],30*1,      30*1,   30*1},
	   {CREDIT_FONT_SML,  16,   100,    &Credit_text[138][0],30*1,      30*1,   30*1},
	 {CREDIT_FONT_SML,    16,   100,    &Credit_text[139][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[140][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[141][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[142][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[143][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[144][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[145][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[146][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[147][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[148][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[149][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[150][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[151][0],30*1,      30*1,   30*1},
	  {CREDIT_FONT_SML,   16,   100,    &Credit_text[152][0],30*1,      30*1,   30*1},
	};

// Sequence of credits
MR_ULONG		Credits_script[]=
	{
	// Data
//	CREDIT_COMMAND_MODEL,		(MR_ULONG)&Credit_models[0],		// Start model

	// Start Frame
		CREDIT_COMMAND_ENTRY,				(MR_ULONG)&Credit_entry[0],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		200,

// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[1],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[2],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[3],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[4],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[5],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[6],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[7],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[8],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[9],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[10],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[11],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[12],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[13],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[14],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[15],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[16],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[17],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[18],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[19],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[20],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[21],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[22],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[23],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[24],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[25],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[26],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[27],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[28],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[29],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[30],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[31],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[32],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,


// Start Frame
		CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[33],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
	CREDIT_COMMAND_DELAY,		1,
		
// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[34],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[35],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[36],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[37],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[38],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[39],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[40],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[41],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[42],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[43],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[44],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
		
// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[45],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[46],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[47],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[48],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[49],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[50],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
			
// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[51],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[52],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[53],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[54],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[55],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[56],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[57],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[58],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[59],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[60],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[61],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[62],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[63],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[64],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[65],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
		
// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[66],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[67],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[68],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[69],
					CREDIT_COMMAND_ENTRY,	(MR_ULONG)&Credit_entry[70],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
			
// Start Frame
			CREDIT_COMMAND_ENTRY,			(MR_ULONG)&Credit_entry[71],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,
// Start Frame

				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[72],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[73],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[74],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_entry[75],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,


	
// Start Frame
		CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[76],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[77],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[78],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[79],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[80],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[81],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[82],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[83],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[84],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[85],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[86],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[87],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[88],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[89],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[90],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[91],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[92],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[93],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[94],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[95],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[96],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[97],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[98],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[99],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[100],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[101],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[102],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[103],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[104],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[105],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[106],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[107],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[108],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[109],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[110],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[111],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
		CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[112],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[113],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[114],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[115],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[116],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[117],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[118],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[119],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
		CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[120],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[121],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[122],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[123],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[124],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[125],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[126],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[127],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[128],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[129],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[130],
		CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[131],
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[132],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[133],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[134],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[135],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[136],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[137],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[138],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

// Start Frame
			CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[139],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[140],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[141],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[142],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[143],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[144],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[145],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[146],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[147],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[148],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[149],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[150],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[151],
				CREDIT_COMMAND_ENTRY,		(MR_ULONG)&Credit_text[152],
	CREDIT_COMMAND_END_FRAME,	0,
	CREDIT_COMMAND_DELAY,		1,

	CREDIT_COMMAND_END,			0,									// Exit	Credit sequence
	};

MR_ULONG		Credits_script_PC;				// Current position in script
MR_ULONG		Credits_delay;					// Current delay

CREDIT_RUNTIME_ENTRY	Credits_runtime_entries[CREDITS_MAX_NUM_ENTRIES_ON_SCREEN];
CREDIT_RUNTIME_MODEL	Credits_runtime_models[CREDITS_MAX_NUM_MODELS_ON_SCREEN];

#endif

/******************************************************************************
*%%%%	CreditsStartup
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsStartup(MR_VOID)
*
*	FUNCTION	Initialisation code for	Credits screen.  Initialise script PC and
*				delay count.
*
*	MATCH		https://decomp.me/scratch/eekPx	(By Kneesnap)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*	12.11.23	Kneesnap		Byte-match PSX Build 71. (Retail NTSC)
*
*%%%**************************************************************************/

MR_VOID	CreditsStartup(MR_VOID)
{

#ifdef	PSX
	// Stop sfx loading loop
	StopLoadingSfxLoop();

	// Kill all viewports/camera frames etc...
	KillOptionsForStream();

	// Create 24bit for stream playback.
	MRCreateDisplay(MR_SCREEN_TRUECOLOUR_STANDARD_256);

	// Play the Intro Stream.
#ifdef	PSX_CD_STREAMS

	// Play credits.
	Play_stream(STR_CREDITS);

#endif	// PSX_CD_STREAMS

	// Remove the 24Bit display.
	MRKillDisplay();	

	// Create a standard one in it's place.
	MRCreateDisplay(SYSTEM_DISPLAY_MODE);
		 
	// Now we have to put everything back to how it was.
	CreateOptionsAfterStream();
	Game_flags &= ~GAME_FLAG_NO_PAUSE_ALLOWED;
#endif

}

/******************************************************************************
*%%%%	CreditsUpdate
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsUpdate(MR_VOID)
*
*	FUNCTION	Update code for	Credits screen.  Processes	Credits script for
*				the current frame.  Also updates currently created text and models.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsUpdate(MR_VOID)
{
	// Leave	Credits and go on to high score input
	Option_page_request = OPTIONS_PAGE_HIGH_SCORE_INPUT;
}

/******************************************************************************
*%%%%	CreditsShutdown
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsShutdown(MR_VOID)
*
*	FUNCTION	Shutdown code for	Credits screen.  Removes and bins any remaining
*				sprites or models.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsShutdown(MR_VOID)
{


}

#if 0

/******************************************************************************
*%%%%	CreditsCreateEntry
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsCreateEntry(CREDIT_ENTRY*	Credit_entry_ptr)
*
*	FUNCTION	Creates a new text entry.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsCreateEntry(CREDIT_ENTRY*	credit_entry_ptr)
{

	// Locals
	MR_ULONG		loop_counter_1;
	MR_ULONG		num_sprites;
	MR_UBYTE*		text_ptr;
	MR_ULONG		xpos;
	MR_ULONG		ypos;

	// Loop once for each entry
	for(loop_counter_1=0;loop_counter_1<CREDITS_MAX_NUM_ENTRIES_ON_SCREEN;loop_counter_1++)
		{
		// Is model active ?
		if (	Credits_runtime_entries[loop_counter_1].re_active == FALSE )
			{
			// No ... break
			break;
			}
		}

	// Flag entry as valid
	Credits_runtime_entries[loop_counter_1].re_active = TRUE;

	// Reset number of sprites
	num_sprites = 0;

	// Initialise start x pos
	xpos =	credit_entry_ptr->ce_xpos;
	ypos =	credit_entry_ptr->ce_ypos;

#ifdef	WIN95
	xpos <<= 1;
	ypos <<= 1;			// $km Oh well. dicey as hell but at least it allows me to get them working.
#endif

	// Get pointer to text
	text_ptr =	credit_entry_ptr->ce_text_ptr;

	// Loop once for each byte in string
	while ( *text_ptr != 0 )
		{
		// Valid letter
		if ( *text_ptr > 64 && *text_ptr < 98 )
			{
			// Create sprite
			Credits_runtime_entries[loop_counter_1].re_sprite_ptr[num_sprites] = MRCreate2DSprite(xpos,ypos,Option_viewport_ptr,Credit_font_textures[credit_entry_ptr->ce_font_number][(*text_ptr)-65],NULL);
			// Set base colour of sprite to black
			Credits_runtime_entries[loop_counter_1].re_sprite_ptr[num_sprites]->sp_core.sc_base_colour.r = 0x00;
			Credits_runtime_entries[loop_counter_1].re_sprite_ptr[num_sprites]->sp_core.sc_base_colour.g = 0x00;
			Credits_runtime_entries[loop_counter_1].re_sprite_ptr[num_sprites]->sp_core.sc_base_colour.b = 0x00;
			// Inc x pos
			xpos +=	Credit_font_textures[credit_entry_ptr->ce_font_number][(*text_ptr)-65]->te_w;
			// Inc number of sprites
			num_sprites++;
			// Created too many sprites ?
			MR_ASSERT(num_sprites <	CREDITS_MAX_NUM_LETTERS_PER_STRING);
			}
		// Next character
		text_ptr++;
		}

	// Store number of sprites
	Credits_runtime_entries[loop_counter_1].re_num_sprites = num_sprites;

	// Set mode of operation
	Credits_runtime_entries[loop_counter_1].re_mode =	CREDITS_RUNTIME_ENTRY_MODE_FADE_UP;

	// Set time on screen
	Credits_runtime_entries[loop_counter_1].re_time =	credit_entry_ptr->ce_on_screen_time;

	// Set fade up increament
	Credits_runtime_entries[loop_counter_1].re_fade_up_value = (0x80<<16) /	credit_entry_ptr->ce_fade_up_time;

	// Set fade down increament
	Credits_runtime_entries[loop_counter_1].re_fade_down_value = (0x80<<16) /	credit_entry_ptr->ce_fade_down_time;

	// Set temp base colour
	Credits_runtime_entries[loop_counter_1].re_base_colour = 0;

}

/******************************************************************************
*%%%%	CreditsUpdateEntries
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsUpdateEntries(MR_VOID)
*
*	FUNCTION	Updates all current entries on screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsUpdateEntries(MR_VOID)
{

	// Locals
	MR_ULONG		loop_counter_1;
	MR_ULONG		loop_counter_2;

	// Loop once for each entry
	for(loop_counter_1=0;loop_counter_1<CREDITS_MAX_NUM_ENTRIES_ON_SCREEN;loop_counter_1++)
		{

		// Is this entry active ?
		if (	Credits_runtime_entries[loop_counter_1].re_active == TRUE )
			{

			// According to mode of entry do ...
			switch (	Credits_runtime_entries[loop_counter_1].re_mode )
				{

				// Fade up ...
				case	CREDITS_RUNTIME_ENTRY_MODE_FADE_UP:

					// Loop once for each sprite
					for(loop_counter_2=0;loop_counter_2<Credits_runtime_entries[loop_counter_1].re_num_sprites;loop_counter_2++)
						{

						// Heighten base colour
						Credits_runtime_entries[loop_counter_1].re_base_colour +=	Credits_runtime_entries[loop_counter_1].re_fade_up_value;

						// Set sprite's base colour
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.g =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.b =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;

						// Base colour at max ?
						if (	Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r > 0x7f )
							{
							// Yes ... update mode to wait
							Credits_runtime_entries[loop_counter_1].re_mode =	CREDITS_RUNTIME_ENTRY_MODE_WAIT;
							// Reset base colour to max
							Credits_runtime_entries[loop_counter_1].re_base_colour = 0x80<<16;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r = 0x80;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.g = 0x80;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.b = 0x80;
							}

						}

					break;

				// Wait ...
				case	CREDITS_RUNTIME_ENTRY_MODE_WAIT:

					// Dec time
					Credits_runtime_entries[loop_counter_1].re_time--;

					// Time reached zero ?
					if ( !Credits_runtime_entries[loop_counter_1].re_time )
						{
						// Yes ... update mode to fade down
						Credits_runtime_entries[loop_counter_1].re_mode =	CREDITS_RUNTIME_ENTRY_MODE_FADE_DOWN;
						}

					break;

				// Fade down ...
				case	CREDITS_RUNTIME_ENTRY_MODE_FADE_DOWN:

					// Loop once for each sprite
					for(loop_counter_2=0;loop_counter_2<Credits_runtime_entries[loop_counter_1].re_num_sprites;loop_counter_2++)
						{
						// Darken base colour
						Credits_runtime_entries[loop_counter_1].re_base_colour -=	Credits_runtime_entries[loop_counter_1].re_fade_down_value;

						// Set sprite base colour
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.g =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;
						Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.b =	Credits_runtime_entries[loop_counter_1].re_base_colour>>16;

						// Base colour at min ?
						if (	Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r > 0x80 )
							{
							// Yes ... update mode to kill
							Credits_runtime_entries[loop_counter_1].re_mode =	CREDITS_RUNTIME_ENTRY_MODE_KILL;
							// Reset base colour to 0
							Credits_runtime_entries[loop_counter_1].re_base_colour = 0;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.r = 0;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.g = 0;
							Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]->sp_core.sc_base_colour.b = 0;
							}
						}

					break;

				// Kill ...
				case	CREDITS_RUNTIME_ENTRY_MODE_KILL:

					// Loop once for each sprite
					for(loop_counter_2=0;loop_counter_2<Credits_runtime_entries[loop_counter_1].re_num_sprites;loop_counter_2++)
						{
						// Flag sprite as destroy by display and not display
						MRKill2DSprite(Credits_runtime_entries[loop_counter_1].re_sprite_ptr[loop_counter_2]);
						}

					// Flag entry as inactive
					Credits_runtime_entries[loop_counter_1].re_active = FALSE;

					break;
				}
			}
		}

}

/******************************************************************************
*%%%%	CreditsCreateModel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsCreateModel(CREDIT_MODEL*	Credit_model_ptr)
*
*	FUNCTION	Creates a new model.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsCreateModel(CREDIT_MODEL*	credit_model_ptr)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_FRAME*		frame_ptr;
	MR_MOF*			model_ptr;
	MR_VEC			movement;

	// Loop once for each model
	for(loop_counter=0;loop_counter<CREDITS_MAX_NUM_MODELS_ON_SCREEN;loop_counter++)
		{
		// Is model active ?
		if (	Credits_runtime_models[loop_counter].rm_active == FALSE )
			{
			// No ... break
			break;
			}
		}

	// Flag entry as valid
	Credits_runtime_models[loop_counter].rm_active = TRUE;

	// Calculate movement per frame
	Credits_runtime_models[loop_counter].rm_movement.vx = (credit_model_ptr->cm_end_pos.vx -	credit_model_ptr->cm_start_pos.vx)/credit_model_ptr->cm_speed;
	Credits_runtime_models[loop_counter].rm_movement.vy = (credit_model_ptr->cm_end_pos.vy -	credit_model_ptr->cm_start_pos.vy)/credit_model_ptr->cm_speed;
	Credits_runtime_models[loop_counter].rm_movement.vz = (credit_model_ptr->cm_end_pos.vz -	credit_model_ptr->cm_start_pos.vz)/credit_model_ptr->cm_speed;

	// Get address of model in memory
	model_ptr = MR_GET_RESOURCE_ADDR(Credit_model_resouce_id[credit_model_ptr->cm_model_number]);

	// Create frame
	frame_ptr = MRCreateFrame(&credit_model_ptr->cm_start_pos,&MRNull_svec,0);

	// Create model
	Credits_runtime_models[loop_counter].rm_object_ptr = MRCreateMesh(model_ptr,frame_ptr,0,NULL);

	// Add model to viewport
	MRAddObjectToViewport(Credits_runtime_models[loop_counter].rm_object_ptr,Option_viewport_ptr,0);

	// Calculate dist to be moved
	movement.vx =	credit_model_ptr->cm_end_pos.vx -	credit_model_ptr->cm_start_pos.vx;
	movement.vy =	credit_model_ptr->cm_end_pos.vy -	credit_model_ptr->cm_start_pos.vy;
	movement.vz =	credit_model_ptr->cm_end_pos.vz -	credit_model_ptr->cm_start_pos.vz;
	Credits_runtime_models[loop_counter].rm_dist = MR_VEC_MOD(&movement);

}

/******************************************************************************
*%%%%	CreditsUpdateModels
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	CreditsUpdateModels(MR_VOID)
*
*	FUNCTION	Updates all current models on screen.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.07.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID	CreditsUpdateModels(MR_VOID)
{

	// Locals
	MR_ULONG		loop_counter;
	MR_FRAME*		frame_ptr;

	// Loop once for each model
	for(loop_counter=0;loop_counter<CREDITS_MAX_NUM_MODELS_ON_SCREEN;loop_counter++)
		{
		// Is this model active ?
		if (	Credits_runtime_models[loop_counter].rm_active == TRUE )
			{
			// Yes ... update position of model
			frame_ptr =	Credits_runtime_models[loop_counter].rm_object_ptr->ob_frame;
			frame_ptr->fr_matrix.t[0] +=	Credits_runtime_models[loop_counter].rm_movement.vx;
			frame_ptr->fr_matrix.t[1] +=	Credits_runtime_models[loop_counter].rm_movement.vy;
			frame_ptr->fr_matrix.t[2] +=	Credits_runtime_models[loop_counter].rm_movement.vz;

			// Dec dist moved
			Credits_runtime_models[loop_counter].rm_dist--;

			// Has model reached end point ?
			if ( !Credits_runtime_models[loop_counter].rm_dist )
				{
				// Yes ... flag model as destroy by display, no display and kill frame
				Credits_runtime_models[loop_counter].rm_object_ptr->ob_flags |= MR_OBJ_DESTROY_BY_DISPLAY | MR_OBJ_NO_DISPLAY | MR_OBJ_KILL_FRAME_WITH_OBJECT;
				}

			}
		}

}

#endif