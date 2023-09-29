/******************************************************************************
*%%%% mr_fx.c
*------------------------------------------------------------------------------
*
*	Viewport based effects processing
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

#include	"mr_all.h"


/******************************************************************************
*%%%% MRCreateEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRCreateEffect(
*						MR_ULONG		effect_id,
*						MR_VIEWPORT*	viewport,
*						MR_ULONG		user_var);
*
*	FUNCTION	Initialises a viewport contained effect
*
*	INPUTS		effect_id	-	Effect identifier
*				viewport	-	Pointer to the viewport to attach effect to
*				user_var	-	Effect-specific control value
*							 		MR_FX_TYPE_FADE_<xx>	-	Speed of fade
*							 		MR_FX_TYPE_VSHUT_<xx>	-	Frames for shut
*			
*	NOTES		You cannot create a new effect if an effect is currently in 
*				progress. You must shut down the current effect first, using
*				MRDeleteEffect().
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRCreateEffect(	MR_ULONG		effect_id,
						MR_VIEWPORT*	viewport,
						MR_ULONG		user_var)
{
	MR_EFFECT* 		effect_ptr;

	MR_ASSERT(viewport != NULL);				  	// Must be a valid viewport
	MR_ASSERT(viewport->vp_effect.fx_type == NULL);	// No effect allowed

	effect_ptr = &viewport->vp_effect;

	// Mark current polygon set as valid, other one invalid
	effect_ptr->fx_buff_stat[MRFrame_index]			= 0;
	effect_ptr->fx_buff_stat[MRFrame_index^0x01]	= 1;
											  	
	switch (effect_id)
		{

		// ---

		case	MR_FX_TYPE_FADE_UP:
		case	MR_FX_TYPE_FADE_DOWN:

				// Set speed and fade value (set initial fade value if fading up)
				if (effect_id == MR_FX_TYPE_FADE_UP)
					effect_ptr->fx_data.fx_fade_data.fx_fade_value = MR_FX_FADE_MAX;
				else
					effect_ptr->fx_data.fx_fade_data.fx_fade_value = 0;

				effect_ptr->fx_data.fx_fade_data.fx_fade_speed = user_var;		
				
				// Set fader polygons
				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly);
				setSemiTrans(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly, 1);


				// Set ABR changing polygons	(mode is SUBTRACTIVE)
				setPolyFT3(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr);

				setXY3(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr, -1,-1,-1,-1,-1,-1);
				effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr.tpage = defTPage(0,0,2);		

				break;

		// --- 

		case	MR_FX_TYPE_VSHUT_OPEN:
		case	MR_FX_TYPE_VSHUT_CLOSE:

				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0);
				setRGB0(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0, 0, 0, 0);
				
				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1);
				setRGB0(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1, 0, 0, 0);

				// ((half viewport height)<<16) / number of frames) = delta 

				effect_ptr->fx_data.fx_vshut_data.fx_vshut_count = user_var;

				if (effect_id == MR_FX_TYPE_VSHUT_OPEN)
					{
					effect_ptr->fx_data.fx_vshut_data.fx_vshut_delta	= ((viewport->vp_disp_inf.h << 15) / user_var);							
					effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs		= 0;
					}
				else
					{
					effect_ptr->fx_data.fx_vshut_data.fx_vshut_delta	= -((viewport->vp_disp_inf.h << 15) / user_var);							
					effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs		= (viewport->vp_disp_inf.h << 15);
					}
															 				
				break;

		// ---

		default:
				MR_ASSERT(FALSE);
				break;

		}

	effect_ptr->fx_type = effect_id;

}


/******************************************************************************
*%%%% MRDeleteEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRDeleteEffect(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Stops any current effect for the viewport. Also clears the
*				MR_VP_EFFECT_OVER flag.
*
*	INPUTS		viewport	-	Pointer to the viewport containing effect
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRDeleteEffect(MR_VIEWPORT* viewport)
{
	MR_ASSERT(viewport != NULL);

	viewport->vp_flags &= ~MR_VP_EFFECT_OVER;
	viewport->vp_effect.fx_type = MR_FX_TYPE_NONE;
}


/******************************************************************************
*%%%% MRProcessEffect
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRProcessEffect(
*						MR_VIEWPORT*	viewport);
*
*	FUNCTION	Performs processing for the effect linked to the viewport
*
*	INPUTS		viewport	-	Pointer to the viewport containing effect
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	15.05.96	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRProcessEffect(MR_VIEWPORT* viewport)
{
	MR_EFFECT*	effect_ptr;

	MR_ASSERT(viewport != NULL);

	effect_ptr 	 = &viewport->vp_effect;

	switch(effect_ptr->fx_type)
		{

		// ---- Processing for standard fade up/down ---

		case	MR_FX_TYPE_FADE_UP:
		case	MR_FX_TYPE_FADE_DOWN:

			// If the primitives used by this frame aren't valid, set 'em up...
			if (effect_ptr->fx_buff_stat[MRFrame_index])
				{
				// Mark this buffer as valid
				effect_ptr->fx_buff_stat[MRFrame_index] = 0;

				// Set fader polygons
				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly);
				setSemiTrans(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly, 1);

				// Set ABR changing polygons	(mode is SUBTRACTIVE)
				setPolyFT3(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr);

				setXY3(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr, -1,-1,-1,-1,-1,-1);
				effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr.tpage = defTPage(0,0,2);		
				}
			

			// Adjust fade value, and see if it's over, then set a bit in the viewport flags
			if (effect_ptr->fx_type == MR_FX_TYPE_FADE_UP)
				{
				if (effect_ptr->fx_data.fx_fade_data.fx_fade_value)
					{
					effect_ptr->fx_data.fx_fade_data.fx_fade_value =
						MAX(0, (effect_ptr->fx_data.fx_fade_data.fx_fade_value - effect_ptr->fx_data.fx_fade_data.fx_fade_speed));

					if (!(effect_ptr->fx_data.fx_fade_data.fx_fade_value))
						viewport->vp_flags |= MR_VP_EFFECT_OVER;
					}
				}
			else
				{
				if (effect_ptr->fx_data.fx_fade_data.fx_fade_value != MR_FX_FADE_MAX)
					{
					effect_ptr->fx_data.fx_fade_data.fx_fade_value =
						MIN(MR_FX_FADE_MAX, (effect_ptr->fx_data.fx_fade_data.fx_fade_value + effect_ptr->fx_data.fx_fade_data.fx_fade_speed));

					if (effect_ptr->fx_data.fx_fade_data.fx_fade_value == MR_FX_FADE_MAX)
						viewport->vp_flags |= MR_VP_EFFECT_OVER;				

					}
				}
				 

			// Set colour for polygon
			setRGB0(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly, 
						effect_ptr->fx_data.fx_fade_data.fx_fade_value << 1,
						effect_ptr->fx_data.fx_fade_data.fx_fade_value << 1,
						effect_ptr->fx_data.fx_fade_data.fx_fade_value << 1);

			// Set dimensions of fade polygon to be dimensions of viewport
			setXYWH(&effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly,
					  0,0,viewport->vp_disp_inf.w, viewport->vp_disp_inf.h);
				
			// Add the primitive
			addPrim(MRVp_work_ot, &effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_poly);
			addPrim(MRVp_work_ot, &effect_ptr->fx_poly[MRFrame_index].fx_fade_prims.fx_fade_abr);
		
			break;


		// ---- Vertical shutter wipe

		case	MR_FX_TYPE_VSHUT_OPEN:
		case	MR_FX_TYPE_VSHUT_CLOSE:

			// If the primitives used by this frame aren't valid, set 'em up...
			if (effect_ptr->fx_buff_stat[MRFrame_index])
				{
				
				// Mark this buffer as valid
				effect_ptr->fx_buff_stat[MRFrame_index] = 0;

				// Set fader polygons
				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0);
				setRGB0(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0, 0, 0, 0);

				setPolyF4(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1);
				setRGB0(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1, 0, 0, 0);

				}

			// Calculate new offset (if we're still moving things around)

			if (effect_ptr->fx_data.fx_vshut_data.fx_vshut_count)
				{
				effect_ptr->fx_data.fx_vshut_data.fx_vshut_count--;
				effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs += effect_ptr->fx_data.fx_vshut_data.fx_vshut_delta;

				if (!(effect_ptr->fx_data.fx_vshut_data.fx_vshut_count))
					viewport->vp_flags |= MR_VP_EFFECT_OVER;
				}

			setXYWH(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0,
						0,0,
						viewport->vp_disp_inf.w, (viewport->vp_disp_inf.h>>1) - (effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs>>16));

			setXYWH(&effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1,
					  0, (viewport->vp_disp_inf.h>>1) + (effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs>>16),
						viewport->vp_disp_inf.w, (viewport->vp_disp_inf.h>>1)-(effect_ptr->fx_data.fx_vshut_data.fx_vshut_ofs>>16));

			addPrim(MRVp_work_ot, &effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_0);
			addPrim(MRVp_work_ot, &effect_ptr->fx_poly[MRFrame_index].fx_vshut_prims.fx_vshut_poly_1);

			break;


		// ---- Default case ----

		default:
			MR_ASSERT(FALSE);
			break;
		
		}
}


