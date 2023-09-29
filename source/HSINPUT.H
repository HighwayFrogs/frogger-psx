/******************************************************************************
*%%%% hsinput.h
*------------------------------------------------------------------------------
*
*	Header file for high score input routines
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	16.06.97	William Bell	Created
*
*%%%**************************************************************************/

#ifndef	__HSINPUT_H
#define	__HSINPUT_H

#include "mr_all.h"
#include "frog.h"

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

typedef	struct	__hsi_lily_info						HSI_LILY_INFO;


// Compile options
#define HIGH_SCORE_FORCE_INPUT

// Defines
#define HIGH_SCORE_INPUT_NUM_EXTRAS					6
#define HIGH_SCORE_NUM_INITIALS						3
#define HIGH_SCORE_INPUT_FROG_JUMP_TIME				6

#define HIGH_SCORE_INPUT_LETTER_RUB					28
#define HIGH_SCORE_INPUT_LETTER_END					29

#define	HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_X		0
#define	HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_Y		-2400
#define	HIGH_SCORE_INPUT_STATIC_SOURCE_OFS_Z		-256
#define	HIGH_SCORE_INPUT_STATIC_TARGET_OFS_X		0
#define	HIGH_SCORE_INPUT_STATIC_TARGET_OFS_Y		1024
#define	HIGH_SCORE_INPUT_STATIC_TARGET_OFS_Z		0


//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

struct	__hsi_lily_info
	{
	MR_OBJECT*	hs_object;			// object to twist and kill, or create and twist
	MR_LONG		hs_angle;			// twist angle
	MR_LONG		hs_initial_index;	// 0..11
	MR_MOF*		hs_new_mof;			// ptr to new MOF to create

	};	// HSI_LILY_INFO


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//	Externs
//-----------------------------------------------------------------------------

extern	MR_UBYTE	New_high_score;
extern	MR_UBYTE	New_high_scores[];
extern	MR_STRPTR	Option_high_score_input_text_initials[4][4][50];
extern	MR_ULONG	High_score_input_letters_resource_id[];


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_VOID		HighScoreInitialiseData(MR_VOID);

extern	MR_VOID		HighScoreInputStartup(MR_VOID);
extern	MR_VOID		HighScoreInputUpdate(MR_VOID);
extern	MR_VOID		HighScoreInputShutdown(MR_VOID);

extern	MR_BOOL		HighScoreCheckScore(MR_ULONG);
extern	MR_BOOL		HighScoreCheckArcadeTime(MR_ULONG, MR_ULONG);
extern	MR_BOOL		HighScoreCheckRaceScore(MR_ULONG, MR_ULONG);

extern	MR_VOID		HighScoreEnterScore(MR_ULONG);
extern	MR_VOID		HighScoreEnterArcadeTime(MR_ULONG, MR_ULONG);
extern	MR_VOID		HighScoreEnterRaceScore(MR_ULONG, MR_ULONG);

extern	MR_BOOL		HighScoreCheckAllArcadeTimes(MR_ULONG);
extern	MR_BOOL		HighScoreCheckAllRaceScores(MR_ULONG);

extern	MR_VOID		HighScoreAddAllArcadeTimes(MR_ULONG);
extern	MR_VOID		HighScoreAddAllRaceScores(MR_ULONG);

extern	MR_VOID 	HSInputInitialiseCamera(MR_VOID);
extern	MR_VOID		HSInputUpdateFrog(FROG*);


#endif	//__HSINPUT_H
