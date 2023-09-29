/******************************************************************************
*%%%% score.c
*------------------------------------------------------------------------------
*
*	Score stuff
*
*	CHANGED		PROGRAMMER		REASON
* 	-------  	----------  	------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

#include "score.h"
#include "sprdata.h"
#include "gamesys.h"
#include "ent_cav.h"
#include "froguser.h"
#include "camera.h"
#include "select.h"
#include "sound.h"


SCORE_SPRITE	Score_sprite_root;
SCORE_SPRITE*	Score_sprite_root_ptr;

SCORE_BOOK		Score_library[] =
	{
	//	Value						Texture				Type
		{5,							NULL,				SCORE_FLAG_SCORE},		
		{10,						&im_score_10,		SCORE_FLAG_SCORE},		
		{25,						&im_score_25,		SCORE_FLAG_SCORE},
		{50,						&im_score_50,		SCORE_FLAG_SCORE},
		{75,						&im_score_75,		SCORE_FLAG_SCORE},
		{100,						&im_score_100,		SCORE_FLAG_SCORE},
		{150,						&im_score_150,		SCORE_FLAG_SCORE},
		{200,						&im_score_200,		SCORE_FLAG_SCORE},
		{250,						&im_score_250,		SCORE_FLAG_SCORE},
		{500,						&im_score_500,		SCORE_FLAG_SCORE},
		{1000,						&im_score_1000,		SCORE_FLAG_SCORE},
		{5000,						&im_score_5000,		SCORE_FLAG_SCORE},
									
		{5,							NULL,				SCORE_FLAG_LIGHT},		
		{8,							NULL,				SCORE_FLAG_LIGHT},		
		{FROG_POWERUP_SUPER_LIGHT,	NULL,				SCORE_FLAG_POWERUP},		
									
		{60,						&im_time_plus2,		SCORE_FLAG_TIME },		
		{150,						&im_time_plus5,		SCORE_FLAG_TIME },
		{300,						&im_time_plus10,	SCORE_FLAG_TIME },
									
		{-500,						&im_score_minus500,	SCORE_FLAG_REDUCE_SCORE},
		{FROG_POWERUP_TIMER_SPEED,	NULL,				SCORE_FLAG_POWERUP},
										
		{1,							&im_1up1,			SCORE_FLAG_ADD_EXTRA_LIFE},
		{FROG_POWERUP_SUPER_TONGUE,	NULL,				SCORE_FLAG_POWERUP},
		{FROG_POWERUP_QUICK_JUMP,	NULL,				SCORE_FLAG_POWERUP},
		{FROG_POWERUP_AUTO_HOP,		NULL,				SCORE_FLAG_POWERUP},
	};

/******************************************************************************
*%%%% InitialiseScoreSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	InitialiseScoreSprites(MR_VOID)
*
*	FUNCTION	Initialise the score linked list
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	InitialiseScoreSprites(MR_VOID)
{
	Score_sprite_root_ptr		= &Score_sprite_root;
	Score_sprite_root.ss_next	= NULL;
}


/******************************************************************************
*%%%% CreateScoreSprite
*------------------------------------------------------------------------------
*
*	SYNOPSIS	SCORE_SPRITE*	sprite =	CreateScoreSprite(
*											MR_SHORT		x,
*											MR_SHORT		y,
*											MR_TEXTURE*		texture,
*											MR_VIEWPORT*	vp)
*
*	FUNCTION	Create a score sprite
*
*	INPUTS		x	  	-	viewport x to start at
*				y	  	-	viewport y to start at
*				texture	-	score image
*				vp	  	-	viewport to link to
*
*	RESULT		sprite	-	ptr to SCORE_SPRITE created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

SCORE_SPRITE*	CreateScoreSprite(	MR_SHORT		x,
									MR_SHORT		y,
									MR_TEXTURE*		texture,
									MR_VIEWPORT*	vp)
{
	SCORE_SPRITE*	sprite;


	MR_ASSERT(texture);
	MR_ASSERT(vp);

	// Allocate and link structure
	sprite	= MRAllocMem(sizeof(SCORE_SPRITE), "SCSPRITE");

	if (sprite->ss_next = Score_sprite_root_ptr->ss_next)
		Score_sprite_root_ptr->ss_next->ss_prev = sprite;
	Score_sprite_root_ptr->ss_next = sprite;
	sprite->ss_prev = Score_sprite_root_ptr;

	// Initialise structure
	sprite->ss_2dsprite = MRCreate2DSprite(-texture->te_w >> 1, -texture->te_h >> 1, vp, texture, &sprite->ss_xy);
	sprite->ss_x		= x << 16;
	sprite->ss_y		= y << 16;
	sprite->ss_vx		= 0;
	sprite->ss_vy		= -0x8000;
	sprite->ss_xy.x		= x;
	sprite->ss_xy.y		= y;
	sprite->ss_timer	= SCORE_SPRITE_LIFETIME;
//	MR_SET32(sprite->ss_colour, 0x808080);

	// Note: in Vorg, the score sprites are stored with transparency mode 0: this changed to mode 1 when fading down

	return(sprite);
}


/******************************************************************************
*%%%% UpdateScoreSprites
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	UpdateScoreSprites(MR_VOID)
*
*	FUNCTION	Moves, fades and kills score sprites
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	UpdateScoreSprites(MR_VOID)
{
	SCORE_SPRITE*	sprite;
	SCORE_SPRITE*	sprite_prev;


	sprite	= Score_sprite_root_ptr;

	while(sprite = sprite->ss_next)
		{
		if (!(--sprite->ss_timer))
			{
			// Kill score sprite
			MRKill2DSprite(sprite->ss_2dsprite);

			// Remove structure from linked list
			sprite_prev = sprite->ss_prev;
			sprite->ss_prev->ss_next = sprite->ss_next;
			if	(sprite->ss_next)
				sprite->ss_next->ss_prev = sprite->ss_prev;

			// Free structure memory
			MRFreeMem(sprite);
			sprite = sprite_prev;
			}
		else
			{
			// Move and fade sprite
			sprite->ss_x 	+= sprite->ss_vx;
			sprite->ss_y 	+= sprite->ss_vy;
			sprite->ss_xy.x	= sprite->ss_x >> 16;
			sprite->ss_xy.y	= sprite->ss_y >> 16;

			if ((SCORE_SPRITE_LIFETIME - sprite->ss_timer) < 4)
				{
				// Fade poly up
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.r = (SCORE_SPRITE_LIFETIME - sprite->ss_timer) * 0x20;
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.g = (SCORE_SPRITE_LIFETIME - sprite->ss_timer) * 0x20;
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.b = (SCORE_SPRITE_LIFETIME - sprite->ss_timer) * 0x20;
				}
			else
				{
#ifdef PSX
				// Set poly to abr of 1
				sprite->ss_2dsprite->sp_polygon[MRFrame_index].tpage 	&= ~0x60;
				sprite->ss_2dsprite->sp_polygon[MRFrame_index].tpage 	|= 0x20;
#endif
				// Fade poly down
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.r 	= (sprite->ss_colour.r * sprite->ss_timer) / SCORE_SPRITE_LIFETIME;
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.g 	= (sprite->ss_colour.g * sprite->ss_timer) / SCORE_SPRITE_LIFETIME;
				((MR_SP_CORE*)sprite->ss_2dsprite)->sc_base_colour.b 	= (sprite->ss_colour.b * sprite->ss_timer) / SCORE_SPRITE_LIFETIME;
				}
			}
		}
}


/******************************************************************************
*%%%% AddFrogScore
*------------------------------------------------------------------------------
*
*	SYNOPSIS	SCORE_SPRITE*	sprite =	AddFrogScore(
*											FROG*		frog,
*											MR_ULONG	score_id,
*											MR_MAT*		lwtrans)
*
*	FUNCTION	High level function to increase a frog's score and create a
*				score sprite if necessary
*
*	INPUTS		frog		-	ptr to frog
*				score_id	-	score equate (eg. SCORE_50)
*				lwtrans		-	ptr to transform for origin of score sprite.  If
*								NULL, use frog's lwtrans
*
*	RESULT		sprite		-	ptr to SCORE_SPRITE created, or NULL
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	08.05.97	Tim Closs		Created
*	17.06.97	Gary Richards	Added Time bonus.
*
*%%%**************************************************************************/

SCORE_SPRITE*	AddFrogScore(	FROG*		frog,
								MR_ULONG	score_id,
								MR_MAT*		lwtrans)
{
	MR_VIEWPORT*		vp;
	SCORE_BOOK*			score_book;
	SCORE_SPRITE*		sprite;
	MR_XY				xy;
	MR_TEXTURE*			texture;
	MR_SVEC				svec;
	TONGUE*				tongue;
	CAV_FAT_FIRE_FLY*	fire_fly;

	MR_ASSERT(frog);

	score_book = &Score_library[score_id];

	// Was this a score bonus ?
	if ( score_book->sb_flags & SCORE_FLAG_SCORE )
		{
		// Yes ... just add score
		AddFrogPoints(frog, score_book->sb_value);
		}
	// Was this a light bonus ?
	else if ( score_book->sb_flags & SCORE_FLAG_LIGHT )
		{
		// Yes ... add light level
		ADD_FROG_LIGHT(frog,score_book);
		}
	// Was this a time bonus
	else if (score_book->sb_flags & SCORE_FLAG_TIME )
		{
		// Yes ... add the time.
		ADD_FROG_TIME(frog,score_book->sb_value);
		// Check we've not gone over the MAX.
		if (Game_map_timer > ( Game_map_time * 30 )	)
			Game_map_timer = Game_map_time * 30;
		}
	// Was this a reduce score bonus
	else if (score_book->sb_flags & SCORE_FLAG_REDUCE_SCORE )
		{
		// Yes ...	Add a neg score.
		AddFrogPoints(frog, score_book->sb_value);
		if (frog->fr_score < 0)
			frog->fr_score = 0;
		}
	// Was this an extra life
	else if (score_book->sb_flags & SCORE_FLAG_ADD_EXTRA_LIFE )
		{
		// Check to make sure we don't already have enough lives.
		if (frog->fr_lives < FROG_MAX_LIVES)
			{
			if (Game_total_players == 1)
				{
				// Add extra life and Play 'jingle'
				ADD_FROG_EXTRA_LIFE(frog, score_book->sb_value);
				frog->fr_lives = MIN(frog->fr_lives,FROG_MAX_LIVES);
				MRSNDPlaySound(SFX_GEN_EXTRA_LIFE, NULL, 0, 0 );
				}
			}
		}
	// Was this a POWERUP Flag
	else if (score_book->sb_flags & SCORE_FLAG_POWERUP )
		{
		switch (score_book->sb_value)
			{
			// -------------------------------------
			case FROG_POWERUP_AUTO_HOP:
			frog->fr_auto_hop_timer = POWERUP_AUTO_HOP_TIME ;
			MRSNDPlaySound(SFX_GEN_EXTRA_LIFE, NULL, 0, 1 << 7 );
				break;
			// -------------------------------------
			case FROG_POWERUP_SUPER_TONGUE:
			frog->fr_super_tongue_timer = POWERUP_SUPER_TONGUE_TIME ;
			MRSNDPlaySound(SFX_GEN_EXTRA_LIFE, NULL, 0, 2 << 7 );
				break;
			// -------------------------------------
			case FROG_POWERUP_QUICK_JUMP:
			frog->fr_quick_jump_timer = POWERUP_QUICK_JUMP_TIME ;
			MRSNDPlaySound(SFX_GEN_EXTRA_LIFE, NULL, 0, 3 << 7 );
				break;
			// This was taken out because it was causing lots of problems.
			case FROG_POWERUP_SUPER_LIGHT:
				// Yes ... add light level
				ADD_FROG_LIGHT(frog,score_book);
//				tongue = (TONGUE*)(frog->fr_tongue->ef_extra);
//				fire_fly = (CAV_FAT_FIRE_FLY*)(tongue->to_target + 1);
//				// Let's copy where we would like the Frog to go.
//				MR_COPY_SVEC((MR_SVEC*)&frog->fr_user_target, (MR_SVEC*)&fire_fly->ff_target);
//				// Grab the camera for this Viewport (Frog) and copy were we are.
//				MR_COPY_VEC((MR_VEC*)&frog->fr_user_source, (MR_VEC*)Cameras[frog->fr_frog_id].ca_offset_origin);
//				// Grab the current position of the frog.
//				MR_COPY_VEC((MR_VEC*)&frog->fr_user_current, (MR_VEC*)&frog->fr_lwtrans->t);
//				// Set the camera offset to point at the new Vector.
//				Cameras[frog->fr_frog_id].ca_offset_origin = &frog->fr_user_current;	
//				// Go into frog user mode for moving Frogger to Target.
//				SetFrogUserMode(frog, FROGUSER_MODE_MOVE_FROGGER_TO_TARGET);
//			
//				frog->fr_user_flags 	   = FROGUSER_MOVING_TOWARDS_TARGET;
//				frog->fr_user_speed 	   = 0;
//				frog->fr_user_acceleration = 0; 
				break;
			// -------------------------------------
			}
		ADD_FROG_POWERUP(frog, score_book->sb_value);			
		}

	// Are we in multiplayer mode ?
	if ( Sel_mode == SEL_MODE_RACE )
		{
		// Yes ... exit now! ( No score in multiplayer mode )
		return NULL;
		}

	// Make sure we have a texture for this Bonus.
	if ((Game_flags & GAME_FLAG_SCORE_SPRITES) && (score_book->sb_texture != NULL))
		{
		// Create score sprite
		if (Game_total_viewports > 1)
			{
			// 2 or more viewports, so frog id is viewport id
			vp = Game_viewports[frog->fr_frog_id];
			}
		else
			{
			// 1 viewport only
			vp = Game_viewports[0];
			}

		// Get screen coord of plane origin
		if (lwtrans)
			MRWorldtrans_ptr = lwtrans;
		else
			MRWorldtrans_ptr = frog->fr_lwtrans;

		svec.vx = (MR_SHORT)MRWorldtrans_ptr->t[0] - (MR_SHORT)vp->vp_render_matrix.t[0];
		svec.vy = (MR_SHORT)MRWorldtrans_ptr->t[1] - (MR_SHORT)vp->vp_render_matrix.t[1];
		svec.vz = (MR_SHORT)MRWorldtrans_ptr->t[2] - (MR_SHORT)vp->vp_render_matrix.t[2];
		gte_SetRotMatrix(&vp->vp_render_matrix);
		MRApplyRotMatrix(&svec, (MR_VEC*)MRViewtrans_ptr->t);
		gte_SetTransMatrix(MRViewtrans_ptr);
		gte_ldv0(&MRNull_svec);
		gte_rtps();
		texture = score_book->sb_texture;
		gte_stsxy((MR_LONG*)&xy);
		sprite	= CreateScoreSprite(xy.x, xy.y, texture, vp);
		}
	else
		sprite = NULL;
	
	return(sprite);
}


/******************************************************************************
*%%%% AddFrogPoints
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	AddFrogPoints(	FROG*		frog,
*										MR_LONG		score)
*
*	FUNCTION	Low level function to add points to the frogs score, and work
*				out whether extra lives should be awarded, and so on. This
*				code grew until a macro became unweldy, hence this function.
*
*	INPUTS		frog		-	ptr to frog
*				score		-	score in points
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	21.07.97	Martin Kift		Created
*
*%%%**************************************************************************/

MR_VOID	AddFrogPoints(	FROG*		frog,
						MR_LONG		score)
{
	// Add points first and rebuild HUD
	frog->fr_old_score	= frog->fr_score;
	frog->fr_score 		+= score;

	// Is score too great ?
	if ( frog->fr_score > 99999999 )
		{
		// Yes ... clock score
		frog->fr_score -= 99999999;
		}

	(frog->fr_hud_script + HUD_ITEM_SCORE - 1)->hi_flags |= HUD_ITEM_REBUILD;

	// Update lives script (which is only active in single player mode as far as I can see)
	if (Game_total_players == 1)
		{
		// have we reached score at which a bonus life is awarded? If so, 
		// award and up bonus score limit
		if (frog->fr_score >= frog->fr_life_bonus_score)
			{
			frog->fr_lives = MIN(frog->fr_lives+1, FROG_MAX_LIVES);
			frog->fr_life_bonus_score += FROG_LIFE_AWARD_SCORE;
			(frog->fr_hud_script + HUD_ITEM_LIVES - 1)->hi_flags |= HUD_ITEM_REBUILD;
			}
		}
}