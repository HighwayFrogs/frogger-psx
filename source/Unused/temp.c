typedef __animation_data
	{
	MR_BOOL		ad_repeated;
	MR_ULONG	ad_num_frames;

	};	// ANIMATION_DATA


ANIMATION_DATA		Animation_data =
	{
	{,},
	};

/******************************************************************************
*%%%% FrogStartAnimation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	FrogStartAnimation(
*									MR_ULONG	anim_num,
*									FROG*		frog_ptr)
*
*	FUNCTION	Start a new Frog animation.  Starts the new animation and sets
*				the animation system to either single shot or repeated, depending
*				on the type of animation.
*
*	NOTES		Perhaps this routine should wait for the current animation to reach
*				it's last frame before starting the new animation.
*
*	INPUTS		anim_num	-	number of animation to start
*				frog_ptr	-	ptr to FROG
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID FrogStartAnimation(MR_ULONG	anim_num,FROG* frog_ptr)
{

#ifdef	FROG_ANIMATION

	// Start animation
	MRAnimEnvSingleSetAction(frog_ptr->fr_api_item,anim_num);

	// Flag animation as repeating
	((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags &= ~MR_ANIM_ENV_ONE_SHOT;

	// Is animation single shot ?
	if ( Animation_data[anim_num].ad_repeated == FALSE )
		// Yes ... flag animation as single shot
		((MR_ANIM_ENV*)frog->fr_api_item)->ae_flags |= MR_ANIM_ENV_ONE_SHOT;

	// Flag frog as current doing this animation
	frog_ptr->fr_animation = anim_num;

	// Reset animation frame count
	frog_ptr->fr_animation_count = 0;

#endif	// FROG_ANIMATION

}

/******************************************************************************
*%%%% FrogUpdateAnimation
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID			FrogUpdateAnimation(
*													MR_VOID)
*
*	FUNCTION	Handle Frog animations.  Updates each Frogs current animation
*				frame number.  If it is a single shot animation and all frames
*				have been played it re-triggers the default waiting animation.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	28.05.97	William Bell	Created
*
*%%%**************************************************************************/

MR_VOID FrogUpdateAnimation(MR_VOID)
{

#ifdef	FROG_ANIMATION

	// Locals
	MR_ULONG			loop_counter;
	FROG*				frog_ptr;

	// Loop once for each frog
	for(loop_counter=0;loop_counter<?;loop_counter++)
		{

		// Get pointer to this Frog
		frog_ptr = &Frog[loop_counter];

		// Inc Frog animation frame count
		frog_ptr->fr_animation_count++;

		// End of animation ?
		if ( frog_ptr->fr_animation_count == Animation_data[frog_ptr->fr_animation )
			{

			// Yes ... reset animation frame count
			frog_ptr->fr_animation_count = 0;

			// Was it a single shot animation ?
			if ( ((MR_ANIM_ENV*)frog_ptr->fr_api_item)->ae_flags & MR_ANIM_ENV_ONE_SHOT )
				{
				// Yes ... return to default animation
				FrogStartAnimation(FROG_ANIMATION_WAIT,frog_ptr);
				}

			}

		}

#endif	// FROG_ANIMATION

}