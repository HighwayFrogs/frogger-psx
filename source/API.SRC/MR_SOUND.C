/******************************************************************************
*%%%% mr_sound.c
*------------------------------------------------------------------------------
*
*	Sound routines.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	02.08.96	Dean Ashton		Created
*	06.11.96	Tim Closs		MRSNDUpdateMovingSounds() now allows moving sounds
*								of type MRSNDVF_SINGLE, which kill themselves when
*								the sample has finished
*	30.03.97	Tim Closs		MRCreateMovingSound() - altered way NULL parameters work
*	04.06.97	Dean Ashton		Added owner field in moving sound structures, to 
*								allow for automatic clearing of link between user 
*								entities and moving sounds.
*	27.06.97	Dean Ashton		Cleared voice moving sound pointer in MRSNDKillMovingSound,
*								to stop potential multiple MRFreeMem's later on.
*	01.07.97	Dean Ashton		Fixed another potential bug, this time in MRSNDKillSound()
*
*%%%**************************************************************************/

#include	"mr_all.h"

// Pointers to project information
MRSND_VAB_INFO*		MRSND_vab_info_ptr;							// Pointer to project VAB array
MRSND_GROUP_INFO*	MRSND_group_info_ptr;						// Pointer to project GROUP array
MRSND_SAMPLE_INFO*	MRSND_sample_info_ptr;						// Pointer to project SAMPLE array

// Miscellaneous counters
MR_LONG		 		MRSND_number_of_vabs;
MR_LONG		 		MRSND_number_of_groups;
MR_LONG		 		MRSND_number_of_samples;

// Voice information
MR_UBYTE	 		MRSND_voice_status[MRSND_MAX_VOICES];		// Room for SpuGetAllKeysStatus
MRSND_VOICE_INFO	MRSND_voice[MRSND_MAX_VOICES];				// Room for information relating to each voice
MR_LONG				MRSND_current_ident;						// Used for generating unique tag identification

// Volume information
MR_ULONG			MRSND_master_volume;						// Master volume
MR_ULONG			MRSND_fx_volume;							// Effects volume level (0->127)
MR_ULONG			MRSND_cd_volume;							// CD volume level (0->127)

// Moving sound information
MRSND_MOVING_SOUND	MRSND_moving_sound_root;
MRSND_MOVING_SOUND*	MRSND_moving_sound_root_ptr;
MR_ULONG			MRSND_moving_sound_count;

// Moving sound targets for each viewport (for viewport-specific moving sound code)
MR_VEC*				MRSND_moving_sound_target[MRSND_MAX_VIEWPORTS];
MR_VEC*				MRSND_moving_sound_target_old[MRSND_MAX_VIEWPORTS];
MR_MAT*				MRSND_moving_sound_target_matrix[MRSND_MAX_VIEWPORTS];
MR_ULONG			MRSND_moving_sound_viewport_flags[MRSND_MAX_VIEWPORTS];
MR_USHORT			MRSND_viewports;

MR_LONG				MRSND_system_options_panning;


/******************************************************************************
*%%%% MRSNDInit
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_BOOL	status = MRSNDInit(	MRSND_VAB_INFO*		vab_info_ptr,
*											MRSND_GROUP_INFO*	group_info_ptr,
*											MRSND_SAMPLE_INFO*	sample_info_ptr);
*
*	FUNCTION	Initialises the sound subsystem, establishing links to the 
*				sound data within a project.
*
*	INPUTS		vab_info_ptr	-	Pointer to a project MRSND_VAB_INFO array
*				group_info_ptr	-	Pointer to a project MRSND_GROUP_INFO array
*				sample_info_ptr	-	Pointer to a project MRSND_SAMPLE_INFO array
*
*	RESULT		status			-	Fixed to TRUE for PlayStation..
*
*	NOTES		This function MUST be called before any sound playback is
*				attempted. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.03.97	Dean Ashton		Created
*	22.04.97	Dean Ashton		Changed to return MR_BOOL, consistent with PC API
*
*%%%**************************************************************************/

MR_BOOL	MRSNDInit(MRSND_VAB_INFO* vab_info_ptr, MRSND_GROUP_INFO* group_info_ptr, MRSND_SAMPLE_INFO* sample_info_ptr)
{
#ifdef	MR_API_SOUND
	CdlATV			si_cd_mixer;
	MR_SHORT		si_loop;

	// Setup LIBSND sound system
	SsInit();
	SsSetTickMode(SS_TICK60);

	SsStart();
	SsSetSerialAttr(SS_SERIAL_A, SS_MIX, SS_SON);
	SsSetSerialVol(SS_SERIAL_A, 0x7fff, 0x7fff);


	// Setup internal voice tables
	for (si_loop = 0; si_loop < MRSND_MAX_VOICES; si_loop++)
		{
		MRSND_voice[si_loop].vo_sample			 	=	NULL;
		MRSND_voice[si_loop].vo_moving_owner	 	=	NULL;
		MRSND_voice[si_loop].vo_flags 			 	=	NULL;
		MRSND_voice[si_loop].vo_current_vab_id	 	=	0;
		MRSND_voice[si_loop].vo_current_ident	 	=	0;
		MRSND_voice[si_loop].vo_current_adsr1	 	=	0;
		MRSND_voice[si_loop].vo_current_adsr2	 	=	0;
		MRSND_voice[si_loop].vo_current_note	 	=	0;
		MRSND_voice[si_loop].vo_current_fine	 	=	0;
		MRSND_voice[si_loop].vo_current_pitch_bend	=	0;
		MRSND_voice[si_loop].vo_current_vol_l	 	=	0;
		MRSND_voice[si_loop].vo_current_vol_r	 	=	0;
		MRSND_voice[si_loop].vo_current_req_vol_l	=	0;
		MRSND_voice[si_loop].vo_current_req_vol_r	=	0;
		}

	// Set initial volume level variables
	MRSND_master_volume	=	MRSND_DEFAULT_MASTER_VOL;
	MRSND_fx_volume		=	MRSND_DEFAULT_FX_VOL;
	MRSND_cd_volume		=	MRSND_DEFAULT_CD_VOL;

	// Set the hardware to respect the above variables
	SsSetMVol(MRSND_master_volume, MRSND_master_volume);
	si_cd_mixer.val0 = MRSND_cd_volume;
	si_cd_mixer.val1 = 0;
	si_cd_mixer.val2 = MRSND_cd_volume;
	si_cd_mixer.val3 = 0;
	CdMix(&si_cd_mixer);

	// Set voice allocation ident (0x0001 -> 0x7fff)
	MRSND_current_ident = 1;

	// Moving sound stuff
	MRSND_moving_sound_root_ptr = &MRSND_moving_sound_root;
	MRSND_moving_sound_root_ptr->ms_next_node = NULL;

	for (si_loop = 0; si_loop < MRSND_MAX_VIEWPORTS; si_loop++)	
		{
		MRSND_moving_sound_target[si_loop] 		 	= NULL;
		MRSND_moving_sound_target_old[si_loop] 		= NULL;
		MRSND_moving_sound_target_matrix[si_loop] 	= NULL;
		MRSND_moving_sound_viewport_flags[si_loop] 	= NULL;
		}

	MRSND_viewports = 1;
	MRSND_system_options_panning = NULL;

	// Store pointerts to vabs, groups and samples
	MRSND_vab_info_ptr		=	vab_info_ptr;
	MRSND_group_info_ptr	=	group_info_ptr;
	MRSND_sample_info_ptr	=	sample_info_ptr;

	// How many vabs (and initialise va_vab_id field too..)
	MRSND_number_of_vabs = 0;
	while (vab_info_ptr->va_vh_resource_id != -1)
		{
		vab_info_ptr->va_vab_id = -1;
		MRSND_number_of_vabs++; 
		vab_info_ptr++;
		}

	// How many groups
	MRSND_number_of_groups = 0;
	while (group_info_ptr->gi_min_voice != -1)
		{
		MRSND_number_of_groups++; 
		group_info_ptr++;
		}

	// How many samples
	MRSND_number_of_samples = 0;
	while (sample_info_ptr->si_flags != NULL)
		{
		MRSND_number_of_samples++; 
		sample_info_ptr++;
		}

#endif
	return(TRUE);
}


/******************************************************************************
*%%%% MRSNDOpenVab
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDOpenVab(	MR_LONG	ov_vab_ident, 
*										MR_BOOL	ov_wait_for_download);
*
*	FUNCTION	Given an enumerated VAB identifier (defined within the project)
*				this function will initiate the allocation of SPU-RAM, and the
*				associated transfer of ADPCM sound data to SPU-RAM. 
*
*	INPUTS		ov_vab_ident			-	Enumerated VAB identifier used as an index
*											into the projects VAB information array.
*	
*				ov_wait_for_download	-	TRUE if we want to block until the 
*											transfer of data to SPU-RAM is complete,
*											else FALSE
*					
*	NOTES		This function will cause an assertion failure if the required
*				.VH and .VB resources aren't present in system RAM.
*
*				If 'ov_wait_for_download' is FALSE, then detection SPU-RAM
*				transfer completion is to be performed by the calling project 
*				using the LIBSND SsVabTransCompleted function as follows:
*
*					SsVabTransCompleted(SS_WAIT_COMPLETED)
*						Returns once SPU-RAM transfer is complete (return = 1)
*
*					SsVabTransCompleted(SS_IMMEDIATE)
*						Returns '1' if transfer is complete, else '0' if ongoing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	13.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSNDOpenVab(MR_LONG ov_vab_ident, MR_BOOL ov_wait_for_download)
{
#ifdef	MR_API_SOUND
	MRSND_VAB_INFO*	ov_vabinfo_ptr = &MRSND_vab_info_ptr[ov_vab_ident];

	MR_ASSERT(ov_vabinfo_ptr->va_vab_id == -1);									// Vab can't be loaded already
	MR_ASSERT(MR_GET_RESOURCE_ADDR(ov_vabinfo_ptr->va_vh_resource_id) != NULL);	// .VB must be around
	MR_ASSERT(MR_GET_RESOURCE_ADDR(ov_vabinfo_ptr->va_vb_resource_id) != NULL);	// .VH too..

	// Attempt to open the Vab Header
	ov_vabinfo_ptr->va_vab_id = SsVabOpenHead(MR_GET_RESOURCE_ADDR(ov_vabinfo_ptr->va_vh_resource_id), -1);

	// Check for failure
	MR_ASSERT(ov_vabinfo_ptr->va_vab_id != -1);

	SsVabTransBody(MR_GET_RESOURCE_ADDR(ov_vabinfo_ptr->va_vb_resource_id), ov_vabinfo_ptr->va_vab_id);

	if (ov_wait_for_download)
		{
		SsVabTransCompleted(SS_WAIT_COMPLETED);
		}
#endif
}


/******************************************************************************
*%%%% MRSNDCloseVab
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDCloseVab(MR_LONG cv_vab_ident);
*
*	FUNCTION	Given an enumerated VAB identifier (defined within the project)
*				this function frees the SPU-RAM allocated for ADPCM sound data.
*
*	INPUTS		cv_vab_ident		-	Enumerated VAB identifier used as an
*										index into the project VAB information array	
*
*	NOTES		This kills all sounds first... 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		Created
*
*%%%**************************************************************************/

MR_VOID	MRSNDCloseVab(MR_LONG cv_vab_ident)
{	  
#ifdef	MR_API_SOUND
	MRSND_VAB_INFO*	cv_vabinfo_ptr = &MRSND_vab_info_ptr[cv_vab_ident];

	MR_ASSERT(cv_vabinfo_ptr->va_vab_id != -1);												// Vab must be loaded

	// Kill all sounds, and perform an update to finish killing them off...
	MRSNDKillAllSounds();
	MRSNDUpdateSound();

	// Close down the VAB
	SsVabClose(cv_vabinfo_ptr->va_vab_id);
	
	// Reset VAB identifier 
	cv_vabinfo_ptr->va_vab_id = -1;
#endif
}

/******************************************************************************
*%%%% MRSNDPlaySound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG ps_voice_id = MRSNDPlaySound(	MR_USHORT	ps_sound_id,
*														SndVolume*	ps_sound_vol,
*														MR_USHORT	ps_flags,
*														MR_LONG		ps_pitch_offset)
*												
*
*	FUNCTION	Allocates a voice from the samples owning group, and starts 
*				sound processing using scaled volume levels.
*
*	INPUTS		ps_sound_id			-	Sound sample enumerated value
*				ps_sound_vol		-	Pointer to a SndVolume structure, or NULL
*										if we are to use samples default volume
*				ps_flags			-	eg. SND_PLAYER_1
*				ps_pitch_offset		-	tone and fine pitch offsets.. (1 << 7) is
*									+1 semitone
*
*	RESULT		voice_id			-	32-bit identifier value for the allocated
*									 	voice.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	06.08.96	Dean Ashton		Created
*	11.11.96	Tim Closs		Changed to allow flags input
*	04.12.96	Tim Closs		Brought in line with new SND_SAMPLE_INFO struct
*	22.04.97	Dean Ashton		Check whether VAB is loaded before playing.
*
*%%%**************************************************************************/

MR_LONG	MRSNDPlaySound(	MR_USHORT	ps_sound_id,
						SndVolume*	ps_sound_vol,
						MR_USHORT	ps_flags,
						MR_LONG		ps_pitch_offset)
{
#ifdef	MR_API_SOUND
	MR_LONG				ps_voice_loop;
	MR_SHORT			ps_volume_l;
	MR_SHORT			ps_volume_r;
	MR_SHORT			ps_work_add;
	MR_SHORT			ps_work_sub;
	MRSND_SAMPLE_INFO*	ps_sample_info;
	MRSND_GROUP_INFO*	ps_group_info;
	MRSND_VAB_INFO*		ps_vab_info;
	MRSND_VOICE_INFO*	ps_voice_info;


	// Sound within range of sample array?
	MR_ASSERT(ps_sound_id < MRSND_number_of_samples);

	// Get pointers to appropriate structures and arrays
	ps_sample_info	= &MRSND_sample_info_ptr[ps_sound_id];
	ps_group_info	= &MRSND_group_info_ptr[ps_sample_info->si_group_id];
	ps_vab_info		= &MRSND_vab_info_ptr[ps_sample_info->si_vabinfo_id];

	// Check that vab is loaded
	MR_ASSERT(ps_vab_info->va_vab_id != -1);

	// Find a free voice in the group
	ps_voice_loop 	= ps_group_info->gi_min_voice;
	ps_voice_info	= NULL;
	while ((ps_voice_info == NULL) && (ps_voice_loop <= ps_group_info->gi_max_voice))
		{
		if (MRSND_voice[ps_voice_loop].vo_sample == NULL)
			{
			ps_voice_info = &MRSND_voice[ps_voice_loop];
			break;
			}
		ps_voice_loop++;
		}
	
	// If we didn't find a voice, return an error to caller
	if (ps_voice_info == NULL)
		return(-1);

	//	Setup the voice information		
	ps_voice_info->vo_sample				=	ps_sample_info;
	ps_voice_info->vo_moving_owner			=	NULL;
	ps_voice_info->vo_flags					=	MRSNDVF_INITIALISING | ps_sample_info->si_flags;
	ps_voice_info->vo_current_vab_id		=	ps_vab_info->va_vab_id;
	ps_voice_info->vo_current_ident			=	MRSND_current_ident;
	ps_voice_info->vo_current_adsr1			=	NULL;
	ps_voice_info->vo_current_adsr2			=	NULL;
	ps_voice_info->vo_current_pitch_bend	=	64;

	if (ps_pitch_offset != 0)
		{
		ps_voice_info->vo_current_note		=	ps_sample_info->si_pitch + (ps_pitch_offset >> 7);
		ps_voice_info->vo_current_fine		=	ps_pitch_offset & 0x7f;
		}
	else
		{
		if (ps_sample_info->si_pitch_mod != 0)
			{
			ps_work_sub = ps_sample_info->si_pitch_mod >> 8;
			ps_work_add = rand() & (ps_sample_info->si_pitch_mod - 1);

			ps_voice_info->vo_current_note	=	ps_sample_info->si_pitch - ps_work_sub + (ps_work_add >> 7);
			ps_voice_info->vo_current_fine	=	ps_work_add & 0x7f;
			}
		else
			{			
			ps_voice_info->vo_current_note	=	ps_sample_info->si_pitch;
			ps_voice_info->vo_current_fine	=	0;
			}
		}

	// Increment current identifier, and wrap when necessary
	MRSND_current_ident++;
	if (MRSND_current_ident == 0x7fff)
		MRSND_current_ident = 1;

	// Get volume from input or sound array
	if (ps_sound_vol == NULL)
		{
		ps_volume_l = ps_sample_info->si_max_volume;
		ps_volume_r = ps_sample_info->si_max_volume;
		}
	else
		{
		ps_volume_l = ps_sound_vol->left;
		ps_volume_r = ps_sound_vol->right;
		}

	// If (MRSND_system_options_panning == MRSND_HARD_PANNING), use only l or r channel
	if (MRSND_system_options_panning == MRSND_HARD_PANNING)
		{
		if (ps_flags & MRSND_PLAY_FORCE_LEFT)
			ps_volume_r = 0;
		else
		if (ps_flags & MRSND_PLAY_FORCE_RIGHT)
			ps_volume_l = 0;
		}
	
	// Store requested volume levels
	ps_voice_info->vo_current_req_vol_l	=	ps_volume_l;
	ps_voice_info->vo_current_req_vol_r	=	ps_volume_r;

	// Adjust effect volume based on master effect volume
	ps_voice_info->vo_current_vol_l	=	(ps_volume_l * MRSND_fx_volume) >> 7;
	ps_voice_info->vo_current_vol_r	=	(ps_volume_r * MRSND_fx_volume) >> 7;
		
	// Start the sound effect
	SsUtKeyOnV(	ps_voice_loop,
					ps_vab_info->va_vab_id,
					ps_sample_info->si_prog,
					ps_sample_info->si_tone,
					ps_voice_info->vo_current_note,
					ps_voice_info->vo_current_fine,
					ps_voice_info->vo_current_vol_l,	
					ps_voice_info->vo_current_vol_r);
					
	// Return voice identification tag
	return((ps_voice_info->vo_current_ident << 16)|(ps_voice_loop));
#else
	return(-1);
#endif
}


/******************************************************************************
*%%%%	MRSNDUpdateSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDUpdateSound(MR_VOID);
*
*	FUNCTION	Updates all voice structures with current operating status. Also
*				re-triggers sounds that are classed as MRSNDVF_REPEAT using the 
*				current volume levels.
*
*	NOTES		Needs updating to handle moving sounds.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDUpdateSound(MR_VOID)
{
#ifdef	MR_API_SOUND
	MRSND_MOVING_SOUND*	us_moving;
	MR_LONG				us_loop;

	// Update moving sounds
	MRSNDUpdateMovingSounds();

	// Obtain voice information for each voice
	SpuGetAllKeysStatus(MRSND_voice_status);	

	// Loop through each voice, interpreting the results 
	for (us_loop = 0; us_loop < MRSND_MAX_VOICES; us_loop++)
		{
		// If the voice is empty, just go onto the next one
		if (MRSND_voice[us_loop].vo_sample == NULL)
			continue;

		// Don't do anything to the voice on first call.
		if (MRSND_voice[us_loop].vo_flags & MRSNDVF_INITIALISING)
			{
			MRSND_voice[us_loop].vo_flags &= ~MRSNDVF_INITIALISING;			
			continue;
			}

		// If the channel is off, then act accordingly
		if (MRSND_voice_status[us_loop] == SPU_OFF)
			{
			if (MRSND_voice[us_loop].vo_flags & MRSNDVF_REPEAT)
				{
				// Sound is classed as MRSNDVF_REPEAT, so re-trigger it
				MRSND_voice[us_loop].vo_flags |= MRSNDVF_INITIALISING;

				// Recalculate a scaled volume from the requested one
				MRSND_voice[us_loop].vo_current_vol_l = (MRSND_voice[us_loop].vo_current_req_vol_l * MRSND_fx_volume) >> 7;
				MRSND_voice[us_loop].vo_current_vol_r = (MRSND_voice[us_loop].vo_current_req_vol_r * MRSND_fx_volume) >> 7;
				
				// Retrigger sample at updated volume level
				SsUtKeyOnV(	us_loop,			  
							MRSND_voice[us_loop].vo_current_vab_id,
							MRSND_voice[us_loop].vo_sample->si_prog,
							MRSND_voice[us_loop].vo_sample->si_tone,
							MRSND_voice[us_loop].vo_current_note,
							MRSND_voice[us_loop].vo_current_fine,
							MRSND_voice[us_loop].vo_current_vol_l,
							MRSND_voice[us_loop].vo_current_vol_r);
				}
			else
				{
				MRSND_voice[us_loop].vo_sample = NULL;

				if ((us_moving = MRSND_voice[us_loop].vo_moving_owner) != NULL)
					{
					MRSNDKillMovingSound(us_moving);
					}
				}
			}
	
		}
#endif
}

/******************************************************************************
*%%%% MRSNDChangeADSR
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDChangeADSR(	MR_LONG 	ca_voice_id,
*											MR_USHORT	ca_adsr1,
*											MR_USHORT	ca_adsr2);
*
*	FUNCTION	Sets ADSR values for the voice identified by ca_voice_id.
*
*	INPUTS		ca_voice_id		-	Voice identifier	
*				ca_adsr1		-	New ADSR 1 value
*				ca_adsr2		-	New ADSR 2 value
*
*	NOTES		Don't know what ADSR changes will do? Don't ask me.. 
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Integration
*
*%%%**************************************************************************/

MR_VOID	MRSNDChangeADSR(MR_LONG ca_voice_id, MR_USHORT ca_adsr1, MR_USHORT ca_adsr2)
{
#ifdef	MR_API_SOUND
	MRSND_VOICE_INFO*	ca_voice_info = &MRSND_voice[MRSND_EXTRACT_VOICE(ca_voice_id)];

	// Validate that we're still owning the voice
	MR_ASSERT(MRSND_EXTRACT_IDENT(ca_voice_id) == ca_voice_info->vo_current_ident);
		
	ca_voice_info->vo_current_adsr1 = ca_adsr1;
	ca_voice_info->vo_current_adsr2 = ca_adsr2;

	SsUtChangeADSR(	MRSND_EXTRACT_VOICE(ca_voice_id),
				 	ca_voice_info->vo_current_vab_id,
				 	ca_voice_info->vo_sample->si_prog,
				 	ca_voice_info->vo_current_note,
				 	ca_adsr1,
				 	ca_adsr2);
#endif
}

/******************************************************************************
*%%%% MRSNDPitchBend
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDPitchBend(	MR_LONG 	pb_voice_id,
*										MR_SHORT	pb_pitch_bend);
*
*	FUNCTION	Sets pitch bend values for the voice identified by pb_voice_id.
*
*	INPUTS		pb_voice_id		-	Voice identifier	
*				pb_pitch_bend	-	New pitch bend value
*
*	NOTES		I can't seem to get this to make any audible difference, but 
*				that could be due to the VAB file's I've tested it on.. :/
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.08.96	Dean Ashton		Created
*	14.03.97	Dean Ashton		API Integration
*
*%%%**************************************************************************/

MR_VOID	MRSNDChangePitch(MR_LONG cp_voice_id, MR_SHORT cp_pitch, MR_SHORT cp_fine)
{
#ifdef	MR_API_SOUND
	MRSND_VOICE_INFO*	cp_voice_info = &MRSND_voice[MRSND_EXTRACT_VOICE(cp_voice_id)];
	MR_SHORT			cp_new_pitch;
	MR_SHORT			cp_new_fine;

	// Validate that we're still owning the voice
	MR_ASSERT(MRSND_EXTRACT_IDENT(cp_voice_id) == cp_voice_info->vo_current_ident);

	if (cp_pitch == -1)
		cp_new_pitch = cp_voice_info->vo_current_note;
	else
		cp_new_pitch = cp_pitch;

	if (cp_fine == -1)
		cp_new_fine	= cp_voice_info->vo_current_fine;
	else
		cp_new_fine = cp_fine;

	SsUtChangePitch(MRSND_EXTRACT_VOICE(cp_voice_id),
					cp_voice_info->vo_current_vab_id,	
					cp_voice_info->vo_sample->si_prog,	
					cp_voice_info->vo_current_note,
					cp_voice_info->vo_current_fine,
					cp_new_pitch,
					cp_new_fine);

	cp_voice_info->vo_current_note = cp_new_pitch;
	cp_voice_info->vo_current_fine = cp_new_fine;
#endif
}


/******************************************************************************
*%%%% MRSNDPitchBend
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDPitchBend(	MR_LONG 	pb_voice_id,
*										MR_SHORT	pb_pitch_bend);
*
*	FUNCTION	Sets pitch bend values for the voice identified by pb_voice_id.
*
*	INPUTS		pb_voice_id		-	Voice identifier	
*				pb_pitch_bend	-	New pitch bend value
*
*	NOTES		I can't seem to get this to make any audible difference, but 
*				that could be due to the VAB file's I've tested it on.. :/
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	09.08.96	Dean Ashton		Created
*	14.03.97	Dean Ashton		API Integration
*
*%%%**************************************************************************/

MR_VOID	MRSNDPitchBend(MR_LONG pb_voice_id, MR_SHORT pb_pitch_bend)
{
#ifdef	MR_API_SOUND
	MRSND_VOICE_INFO*	pb_voice_info = &MRSND_voice[MRSND_EXTRACT_VOICE(pb_voice_id)];

	// Validate that we're still owning the voice
	MR_ASSERT(MRSND_EXTRACT_IDENT(pb_voice_id) == pb_voice_info->vo_current_ident);

	SsUtPitchBend(	MRSND_EXTRACT_VOICE(pb_voice_id),
					pb_voice_info->vo_current_vab_id,
					pb_voice_info->vo_sample->si_prog,
					pb_voice_info->vo_current_note,
					pb_pitch_bend);

	pb_voice_info->vo_current_pitch_bend = pb_pitch_bend;
#endif
}


/******************************************************************************
*%%%% MRSNDChangeVolume
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDChangeVolume(	MR_LONG		cv_voice_id,
*											SndVolume*	cv_sound_vol);
*
*	FUNCTION	Sets the volume for the voice identified by cv_voice_id.
*
*	INPUTS		cv_voice_id		-	Voice identifier
*				cv_sound_vol	-	Pointer to SndVolume structure holding volumes
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDChangeVolume(MR_LONG cv_voice_id, SndVolume* cv_sound_vol)
{
#ifdef	MR_API_SOUND
	MRSND_VOICE_INFO*	cv_voice_info = &MRSND_voice[MRSND_EXTRACT_VOICE(cv_voice_id)];
	MR_SHORT			cv_volume_l;
	MR_SHORT			cv_volume_r;

	// Validate that we're still owning the voice
	MR_ASSERT(MRSND_EXTRACT_IDENT(cv_voice_id) == cv_voice_info->vo_current_ident);

	// Get volume levels from current levels, or from new SndVolume structure
	if (cv_sound_vol == NULL)
		{
		cv_volume_l = cv_voice_info->vo_current_req_vol_l;
		cv_volume_r = cv_voice_info->vo_current_req_vol_r;
		}
	else
		{
		cv_volume_l = cv_sound_vol->left;
		cv_volume_r = cv_sound_vol->right;
		}

	// Store requested volume levels
	cv_voice_info->vo_current_req_vol_l	=	cv_volume_l;
	cv_voice_info->vo_current_req_vol_r	=	cv_volume_r;

	// Adjust effect volume based on master effect volume
	cv_voice_info->vo_current_vol_l	=	(cv_volume_l * MRSND_fx_volume) >> 7;
	cv_voice_info->vo_current_vol_r	=	(cv_volume_r * MRSND_fx_volume) >> 7;

	// Change voice volume
	SsUtSetVVol(MRSND_EXTRACT_VOICE(cv_voice_id),
				cv_voice_info->vo_current_vol_l,
				cv_voice_info->vo_current_vol_r);
#endif
}


/******************************************************************************
*%%%% MRSNDCheckSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDCheckSound(MR_LONG cs_voice_id)
*
*	FUNCTION	Returns a pointer to the sample playing on the voice
*				identified by cs_voice_id.
*
*	INPUTS		cs_voice_id		-	Voice identifier
*
*	RESULT		cs_sample		-	Pointer to sample playing on requested voice
*									or NULL if nothing playing.
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MRSND_SAMPLE_INFO* MRSNDCheckSound(MR_LONG cs_voice_id)
{
#ifdef	MR_API_SOUND
	return(MRSND_voice[MRSND_EXTRACT_VOICE(cs_voice_id)].vo_sample);
#else
	return(NULL);
#endif
}


/******************************************************************************
*%%%% MRSNDKillSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDKillSound(MR_LONG ks_voice_id);
*
*	FUNCTION	Kills the sample playing on the voice identified by ks_voice_id.
*
*	INPUTS		ks_voice_id		-	Voice identifier
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Inclusion
*	01.07.97	Dean Ashton		Made routine kill moving sound too..
*	30.08.97	Gary Richards	Made routine remove PTR to moving sound owner,
*								instead of Killing the Moving Sound.
*
*%%%**************************************************************************/

MR_VOID	MRSNDKillSound(MR_LONG ks_voice_id)
{
#ifdef	MR_API_SOUND
	MRSND_VOICE_INFO*	ks_voice_info = &MRSND_voice[MRSND_EXTRACT_VOICE(ks_voice_id)];

	// Validate that we're still owning the voice
	MR_ASSERT(MRSND_EXTRACT_IDENT(ks_voice_id) == ks_voice_info->vo_current_ident);

	ks_voice_info->vo_flags &= MRSNDVF_INITIALISING;
	SsUtKeyOffV(MRSND_EXTRACT_VOICE(ks_voice_id));

	// This function should *ONLY* kill the VOICE not the moving sound it's self.	
	if (ks_voice_info->vo_moving_owner != NULL)
		// Remove PTR to moving_sound. (But DON'T kill the MOVING SOUND.)
		ks_voice_info->vo_moving_owner = NULL;

#endif
}


/******************************************************************************
*%%%% MRSNDKillAllSounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDKillAllSounds(MR_VOID)
*
*	FUNCTION	Kills all active sounds
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDKillAllSounds(MR_VOID)
{
#ifdef	MR_API_SOUND
	MR_SHORT ks_loop;

	for (ks_loop = 0; ks_loop < MRSND_MAX_VOICES; ks_loop++)
		{
			if (MRSND_voice[ks_loop].vo_sample != NULL)
				SsUtKeyOffV(ks_loop);
		}
#endif
}


/******************************************************************************
*%%%% MRSNDResetAllLoopedVoices
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDResetAllLoopedVoices(MR_LONG** voice_id)
*
*	FUNCTION	Runs through the looped voices pointed to in an array
*				and resets any active voices
*				
*	INPUTS		voice_id	-	ptr to array of MR_LONG* ptrs to voice ids
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	29.08.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDResetAllLoopedVoices(MR_LONG** voice_id)
{
#ifdef	MR_API_SOUND
	while(*voice_id)
		{
		if (**voice_id != -1)
			{
			MRSNDKillSound(**voice_id);
			**voice_id = -1;
			}
		voice_id++;
		}
#endif
}


/******************************************************************************
*%%%% MRSNDClearAllLoopedVoicesIds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDClearAllLoopedVoicesIds(MR_LONG** voice_id)
*
*	FUNCTION	Runs through the looped voices pointed to in a null terminated
*				array and clears the voice ids.
*
*	INPUTS		voice_id	-	ptr to array of MR_LONG* ptrs to voice ids
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	30.09.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDClearAllLoopedVoicesIds(MR_LONG** voice_id)
{
#ifdef	MR_API_SOUND
	while(*voice_id)
		{
		**voice_id = -1;
		voice_id++;
		}
#endif
}


/******************************************************************************
*%%%% MRSNDCreateMovingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MRSND_MOVING_SOUND*	moving_sound	= 	MRSNDCreateMovingSound(
*													 	MR_VEC*		source,
*													 	MR_VEC*		source_old,
*													 	MR_USHORT	sound,
*													 	MRSND_MOVING_SOUND** owner);
*
*	FUNCTION	Creates and initialises a MRSND_MOVING_SOUND
*
*	INPUTS		source			-	ptr to moving sound position in world
*				source_old		-	ptr to moving sound old position in world. If NULL,
*									source is copied to moving_sound->ms_source_copy,
*									and both pointers are set to point to this
*				sound			-	sound equate
*				owner			-	The address of the pointer pointing to this sound,
*									or NULL if we don't want to keep a record.
*
*	RESULT		moving_sound*	-	ptr to MRSND_MOVING_SOUND created
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	04.12.96	Tim Closs		Removed volume input. Brought in line with new
*						 		MRSND_SAMPLE_INFO struct
*	14.03.97	Dean Ashton		API Inclusion
*	30.03.97	Tim Closs		Altered way NULL parameters work
*	04.06.97	Dean Ashton		Added 'owner' parameter, to allow moving sounds to
*								clear a pointer to them when the moving sound is
*								killed.
*
*%%%**************************************************************************/

MRSND_MOVING_SOUND*	MRSNDCreateMovingSound(MR_VEC* source, MR_VEC*	source_old, MR_USHORT sound, MRSND_MOVING_SOUND** owner)
{
#ifdef	MR_API_SOUND
	MRSND_MOVING_SOUND*	moving_sound;
	MR_LONG				loop;

	MR_ASSERT(source != NULL);

	// Link new structure into list
	moving_sound = MRAllocMem(sizeof(MRSND_MOVING_SOUND), "MOV_SND");

	if (moving_sound->ms_next_node = MRSND_moving_sound_root_ptr->ms_next_node)
		MRSND_moving_sound_root_ptr->ms_next_node->ms_prev_node = moving_sound;

	MRSND_moving_sound_root_ptr->ms_next_node = moving_sound;
	moving_sound->ms_prev_node = MRSND_moving_sound_root_ptr;

	// Set owner pointer
	moving_sound->ms_owner = owner;

	// Set up structure
	if (!source)
		{
		// Static - user must set up moving_sound->ms_source_copy
		moving_sound->ms_source		= &moving_sound->ms_source_copy;
		moving_sound->ms_source_old	= &moving_sound->ms_source_copy;
		}
	else
	if (!source_old)
		{
		// Moving - but can't use doppler
		moving_sound->ms_source		= source;
		moving_sound->ms_source_old	= source;
		}
	else
		{
		// Moving - can use doppler
		moving_sound->ms_source		= source;
		moving_sound->ms_source_old	= source_old;
		}

//	if (source_old)
//		{
//		moving_sound->ms_source		= source;
//		moving_sound->ms_source_old	= source_old;
//		}
//	else
//		{
//		MR_COPY_VEC(&moving_sound->ms_source_copy, source);
//		moving_sound->ms_source		= &moving_sound->ms_source_copy;
//		moving_sound->ms_source_old	= &moving_sound->ms_source_copy;
//		}

	for (loop = 0; loop < MRSND_viewports; loop++)
		{
		moving_sound->ms_voice_id[loop]	= -1;
		}
	moving_sound->ms_sound		= sound;
	moving_sound->ms_flags		= (MRSND_MOVING_SOUND_ACCEPT_FADE | MRSND_MOVING_SOUND_ACCEPT_PAN | MRSND_MOVING_SOUND_ACCEPT_DOPPLER);
	moving_sound->ms_min_radius	= MRSND_MOVING_SOUND_DEFAULT_MIN_RADIUS;
	moving_sound->ms_max_radius	= MRSND_MOVING_SOUND_DEFAULT_MAX_RADIUS;

	MRSND_moving_sound_count++;

	return(moving_sound);
#else
	return(NULL);
#endif
}
	

/******************************************************************************
*%%%% MRSNDKillMovingSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDKillMovingSound(
*						MRSND_MOVING_SOUND* moving_sound);
*
*	FUNCTION	Kills a MRSND_MOVING_SOUND structure
*
*	INPUTS		moving_sound	-	ptr to MRSND_MOVING_SOUND to kill
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion, use MRSND_viewport loop instead
*								of wired 0/1
*	27.06.97	Dean Ashton		Cleared voice moving sound pointer, to stop
*								potential multiple MRFreeMem's later on.
*
*%%%**************************************************************************/

MR_VOID	MRSNDKillMovingSound(MRSND_MOVING_SOUND* moving_sound)
{
#ifdef	MR_API_SOUND
	MR_LONG	loop;

	MR_ASSERT(moving_sound != NULL);

	// If moving sound is playing for a viewport, stop it
	for (loop = 0; loop < MRSND_viewports; loop++)
		{	
		if (moving_sound->ms_voice_id[loop] >= 0)
			{
			MRSND_voice[MRSND_EXTRACT_VOICE(moving_sound->ms_voice_id[loop])].vo_moving_owner = NULL;
			MRSNDKillSound(moving_sound->ms_voice_id[loop]);
			}
		}

	// Remove structure from linked list
	moving_sound->ms_prev_node->ms_next_node = moving_sound->ms_next_node;
	if	(moving_sound->ms_next_node)
		moving_sound->ms_next_node->ms_prev_node = moving_sound->ms_prev_node;

	// Clear the link between the moving sound and the entity that's linked to it.
	if (moving_sound->ms_owner != NULL)
		*moving_sound->ms_owner = NULL;

	// Free structure memory
	MRFreeMem(moving_sound);

	// Decrease count
	MRSND_moving_sound_count--;
#endif
}


/******************************************************************************
*%%%% MRSNDUpdateMovingSounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDUpdateMovingSounds(MR_VOID)
*
*	FUNCTION	Handles playing, killing and real time manipulation of
*				moving sound sources
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	06.11.96	Tim Closs		Now allows moving sounds of type MRSNDVF_SINGLE,
*								which kill themselves when the sample has finished
*	11.11.96	Tim Closs		Handles two sound targets (two viewports)
*	04.12.96	Tim Closs		Brought in line with new MRSND_SAMPLE_INFO struct
*	14.03.97	Dean Ashton		API Inclusion (hard panning commented out)
*
*%%%**************************************************************************/

MR_VOID	MRSNDUpdateMovingSounds(MR_VOID)
{
#ifdef	MR_API_SOUND
	MRSND_MOVING_SOUND*	moving_sound;
	MRSND_MOVING_SOUND*	moving_sound_prev;
	MR_USHORT			radius, volume, radiusb, voice, i;
	MR_LONG	 			doppler;
	MR_VEC	 			vec, panvec;
	MR_USHORT			max_vol, min_vol;
	SndVolume			volstruct;


	moving_sound = MRSND_moving_sound_root_ptr;
	while(moving_sound = moving_sound->ms_next_node)
		{
		for (i = 0; i < MRSND_viewports; i++)
			{
			if (MRSND_moving_sound_target[i] == NULL)
				goto next_viewport;

			MR_SUB_VEC_ABC(moving_sound->ms_source, MRSND_moving_sound_target[i], &vec);
			radius = MR_SQRT(MR_SQR(vec.vx >> 4) + MR_SQR(vec.vy >> 4) + MR_SQR(vec.vz >> 4)) << 4;

			if (moving_sound->ms_voice_id[i] >= 0)
				{
				// Sound already playing
				//
				// If sound has finished (not looped), kill moving sound
				voice = moving_sound->ms_voice_id[i] & 0xffff;
				if (
					(MRSND_voice[voice].vo_flags & MRSNDVF_SINGLE) &&
					(MRSND_voice[voice].vo_sample == NULL)
					)
					{
					moving_sound_prev = moving_sound->ms_prev_node;
					MRSNDKillMovingSound(moving_sound);
					moving_sound = moving_sound_prev;
					goto next_sound;
					}
				else
				if (radius > moving_sound->ms_max_radius)
					{
					// Kill sound. (Only the playing sound. NOT the Moving One!)
					MRSNDKillSound(moving_sound->ms_voice_id[i]);
					moving_sound->ms_voice_id[i] = -1;
					}
				}
			else
				{
				// No sound playing
				if (radius <= moving_sound->ms_max_radius)
					{
					// Play sound
					moving_sound->ms_voice_id[i] = MRSNDPlaySound(moving_sound->ms_sound, NULL, (1 << i), NULL);

					// Make a connection between the voice and this moving sound if we obtained a sound
					if (moving_sound->ms_voice_id[i] >= 0)
						MRSND_voice[MRSND_EXTRACT_VOICE(moving_sound->ms_voice_id[i])].vo_moving_owner = moving_sound;
					}
				}

			if (moving_sound->ms_voice_id[i] >= 0)
				{
				// Determine volume
				max_vol = MRSND_sample_info_ptr[moving_sound->ms_sound].si_max_volume;
				min_vol = MRSND_sample_info_ptr[moving_sound->ms_sound].si_min_volume;

				if (moving_sound->ms_flags & MRSND_MOVING_SOUND_ACCEPT_FADE)
					{
					radiusb	= MIN(MAX(radius, moving_sound->ms_min_radius), moving_sound->ms_max_radius);
					volume	= ((4096 - rsin((1024 * (radiusb - moving_sound->ms_min_radius)) / (moving_sound->ms_max_radius - moving_sound->ms_min_radius))) * (max_vol - min_vol)) >> 7;
					volume	+= (min_vol << 5);
					}
				else
					volume	= (max_vol << 5);

				// volume is 0..4095
				if (MRSND_system_options_panning == MRSND_HARD_PANNING)
					{
					if (MRSND_moving_sound_viewport_flags[i] & MRSND_VIEWPORT_FORCE_RIGHT)
						{
						volstruct.left 	= 0;
						volstruct.right	= volume >> 5;
						}
					else
						{
						volstruct.left 	= volume >> 5;
						volstruct.right	= 0;
						}
					}
				else
					{
					if (moving_sound->ms_flags & MRSND_MOVING_SOUND_ACCEPT_PAN)
						{
						// Modify according to panning
#ifdef DEBUG
						// Code to check valid inputs to VectorNormal
						MR_ASSERT(abs(vec.vx) < 0x4000);
						MR_ASSERT(abs(vec.vy) < 0x4000);
						MR_ASSERT(abs(vec.vz) < 0x4000);
#endif
						MRNormaliseVEC(&vec, &panvec);
						MRApplyTransposeMatrixVEC(MRSND_moving_sound_target_matrix[i], &panvec, &panvec);
						panvec.vx 	   	= MAX(0, MIN(8191, panvec.vx + 4096));
						volstruct.right	= (volume * panvec.vx) >> 18;
						volstruct.left 	= (volume * (8191 - panvec.vx)) >> 18;
						}
					else
						{
						volstruct.right	= volume >> 5;
						volstruct.left 	= volume >> 5;
						}
					}

				// Copied from a previous version of the API.
				if (moving_sound->ms_flags & (MRSND_MOVING_SOUND_ACCEPT_FADE | MRSND_MOVING_SOUND_ACCEPT_PAN))
					MRSNDChangeVolume(moving_sound->ms_voice_id[i], &volstruct);
	
				if (moving_sound->ms_flags & MRSND_MOVING_SOUND_ACCEPT_DOPPLER)
					{
					// Determine doppler shift
					MR_SUB_VEC_ABC(moving_sound->ms_source_old, MRSND_moving_sound_target_old[i], &vec);
					radiusb = MR_SQRT(MR_SQR(vec.vx >> 4) + MR_SQR(vec.vy >> 4) + MR_SQR(vec.vz >> 4)) << 4;
	
					// radius is new distance from target to source, radiusb is old distance

					doppler = MIN(MAX((MR_SHORT)(radius - radiusb), -MRSND_MOVING_SOUND_MAX_DOPPLER_RATE), MRSND_MOVING_SOUND_MAX_DOPPLER_RATE - 1);
		  			doppler = (-doppler * 127) / MRSND_MOVING_SOUND_MAX_DOPPLER_RATE;

					MRSNDPitchBend(moving_sound->ms_voice_id[i], doppler);
					}
				}
			next_viewport:
			}
		next_sound:
		}
#endif
}


/******************************************************************************
*%%%% MRSNDSetMovingSoundTarget
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDSetMovingSoundTarget(
*						MR_USHORT	id,
*						MR_VEC*		target_pos,
*						MR_VEC*		target_pos_old.
*						MR_MAT*		target_matrix)
*
*	FUNCTION	Sets the moving sound target (ear) position and old position
*				pointers
*
*	INPUTS		id				-	Viewport number to set target for
*									(MRSND_viewports targets are possible)
*				target_pos		-	ptr to world coord of target (ear)
*				target_pos_old	-	ptr to old position (for doppler)
*				target_matrix	-	ptr to target orientation matrix (for panning)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion, more error checking
*
*%%%**************************************************************************/

MR_VOID	MRSNDSetMovingSoundTarget(MR_USHORT	id, MR_VEC* target_pos, MR_VEC* target_pos_old, MR_MAT* target_matrix)
{
#ifdef	MR_API_SOUND
	MR_ASSERT(id <= MRSND_viewports);
	MR_ASSERT(target_pos);
	MR_ASSERT(target_pos_old);
	MR_ASSERT(target_matrix);

	MRSND_moving_sound_target[id]			= target_pos;
	MRSND_moving_sound_target_old[id]		= target_pos_old;
	MRSND_moving_sound_target_matrix[id]	= target_matrix;
#endif
}


/******************************************************************************
*%%%% MRSNDKillAllMovingSounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDKillAllMovingSounds(MR_VOID)
*
*	FUNCTION	Kills all moving sounds
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDKillAllMovingSounds(MR_VOID)
{
#ifdef	MR_API_SOUND
	while(MRSND_moving_sound_root_ptr->ms_next_node)
		MRSNDKillMovingSound(MRSND_moving_sound_root_ptr->ms_next_node);
#endif
}			


/******************************************************************************
*%%%% MRSNDResetAllMovingSounds
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDResetAllMovingSounds(MR_VOID)
*
*	FUNCTION	Resets all moving sound loops (and clears ids)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	03.09.96	Tim Closs		Created
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDResetAllMovingSounds(MR_VOID)
{
#ifdef	MR_API_SOUND
	MRSND_MOVING_SOUND*	moving_sound;
	MR_USHORT			i;

	moving_sound = MRSND_moving_sound_root_ptr;
	while(moving_sound = moving_sound->ms_next_node)
		{
		for (i = 0; i < MRSND_viewports; i++)
			{
			if (moving_sound->ms_voice_id[i] >= 0)
				{
				MRSNDKillSound(moving_sound->ms_voice_id[i]);
				moving_sound->ms_voice_id[i] = -1;
				}
			}
		}
#endif
}


/******************************************************************************
*%%%% MRSNDPlaySoundWithPan
*------------------------------------------------------------------------------
*
*	SYNOPSIS 	MR_VOID	MRSNDPlaySoundWithPan(	MR_USHORT	sound_id,
*			 									SndVolume*	sound_vol,
*			 									MR_VEC*		pos)
*
*	FUNCTION	Same as MRSNDPlaySound, but pans volumes according to position of
*				sound relative to ear(s)
*
*	INPUTS		sound_id	-	effect equate
*				sound_vol	-	ptr to a SndVolume structure or NULL
*				pos			-	ptr to source position in world
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.09.96	Tim Closs		Created
*	11.11.96	Tim Closs		Returns VOID, but can play two sounds (one in each
*								of two target ears)
*	14.03.97	Dean Ashton		API Inclusion (hard panning code commented out)
*
*%%%**************************************************************************/

MR_VOID	MRSNDPlaySoundWithPan(MR_USHORT sound_id, SndVolume*	sound_vol, MR_VEC* pos)
{
#ifdef	MR_API_SOUND
	MRSND_SAMPLE_INFO*	sample_info;
	MR_SHORT			volume_l;
	MR_SHORT			volume_r;
	MR_VEC				panvec;
	SndVolume			panned_vol;
	MR_USHORT			i;


	// Get volumes from structure
	if (sound_vol == NULL)
		{
		sample_info = &MRSND_sample_info_ptr[sound_id];
		volume_l = sample_info->si_max_volume;
		volume_r = sample_info->si_max_volume;
		}
	else
		{
		volume_l = sound_vol->left;
		volume_r = sound_vol->right;
		}
	
	for (i = 0; i < MRSND_viewports; i++)
		{
		if (MRSND_system_options_panning == MRSND_HARD_PANNING)
			{
			if (MRSND_moving_sound_viewport_flags[i] & MRSND_VIEWPORT_FORCE_RIGHT)
				{
				panned_vol.left	= 0;
				panned_vol.right 	= volume_r;
				}
			else
			if (MRSND_moving_sound_viewport_flags[i] & MRSND_VIEWPORT_FORCE_LEFT)
				{
				panned_vol.left 	= volume_l;
				panned_vol.right	= 0;
				}
			}
		else
			{
			// Check for valid target matrix for moving sound
			MR_ASSERT(MRSND_moving_sound_target_matrix[i] != NULL);

			// Pan volumes
			MR_SUB_VEC_ABC(pos, MRSND_moving_sound_target[i], &panvec);
			MRNormaliseVEC(&panvec, &panvec);
			MRApplyTransposeMatrixVEC(MRSND_moving_sound_target_matrix[i], &panvec, &panvec);
			panvec.vx = MAX(0, MIN(8191, panvec.vx + 4096));

			panned_vol.right	= (volume_r * panvec.vx) >> 13;
			panned_vol.left	= (volume_l * (8191 - panvec.vx)) >> 13;
			}

		MRSNDPlaySound(sound_id, &panned_vol, NULL, NULL);
		}
#endif
}


/******************************************************************************
*%%%% MRSNDPanSound
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDPanSound(	MR_LONG		voice_id,
*										MR_VEC*		pos,
*										MR_USHORT	id)
*
*	FUNCTION	Pans a sound (which is already playing) according to position
*				in world
*
*	INPUTS		voice_id	-	of sound
*				pos			-	of sound in world
*				id	 		-	viewport target ID (less than MRSND_viewports)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	04.09.96	Tim Closs		Created
*	11.11.96	Tim Closs		Now takes target id input
*	14.03.97	Dean Ashton		API Inclusion
*
*%%%**************************************************************************/

MR_VOID	MRSNDPanSound(MR_LONG voice_id, MR_VEC* pos, MR_USHORT id)
{
#ifdef	MR_API_SOUND
	MR_SHORT			volume_l;
	MR_SHORT			volume_r;
	MRSND_VOICE_INFO*	voice_info;
	MRSND_SAMPLE_INFO*	sample_info;
	MR_VEC				panvec;
	SndVolume			panned_vol;

	MR_ASSERT(id <= MRSND_viewports);
	MR_ASSERT(MRSND_moving_sound_target_matrix[id] != NULL);

	// Set pointers to sample and voice
	voice_info 	= &MRSND_voice[voice_id & 0xffff];
	sample_info = voice_info->vo_sample;

	volume_l		= sample_info->si_max_volume;
	volume_r		= sample_info->si_max_volume;

	MR_SUB_VEC_ABC(pos, MRSND_moving_sound_target[id], &panvec);
	MRNormaliseVEC(&panvec, &panvec);
	MRApplyTransposeMatrixVEC(MRSND_moving_sound_target_matrix[id], &panvec, &panvec);
	panvec.vx = MAX(0, MIN(8191, panvec.vx + 4096));

	panned_vol.right	= (volume_r * panvec.vx) >> 13;
	panned_vol.left		= (volume_l * (8191 - panvec.vx)) >> 13;

	MRSNDChangeVolume(voice_id, &panned_vol);
#endif
}


/******************************************************************************
*%%%% MRSNDSetViewports
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDSetViewports( MR_USHORT	number)
*
*	FUNCTION	Sets the total number of viewports (sound targets) used by the
*				sound system
*
*	INPUTS		number		-	number of viewports
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.12.96	Tim Closs		Created
*	14.03.97	Dean Ashton		Incorporated into API.
*
*%%%**************************************************************************/

MR_VOID	MRSNDSetViewports(MR_USHORT	number)
{
#ifdef	MR_API_SOUND
	MR_ASSERT(number > 0);
	MR_ASSERT(number <= MRSND_MAX_VIEWPORTS);

	MRSND_viewports = number;
#endif
}


/******************************************************************************
*%%%% MRSNDSetSystemPanningOptions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDSetSystemPanningOptions( MR_USHORT panning_opt)
*
*	FUNCTION	Sets system panning options, primarily used for multi-viewport
*				projects.
*
*	INPUTS		panning_opt	-	Flags representing options
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.03.97	Dean Ashton		Incorporated into API.
*
*%%%**************************************************************************/

MR_VOID	MRSNDSetSystemPanningOptions(MR_LONG panning_opt)
{
#ifdef	MR_API_SOUND
	MRSND_system_options_panning = panning_opt;
#endif
}


/******************************************************************************
*%%%% MRSNDGetSystemPanningOptions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_LONG panning_opt = MRSNDSetSystemPanningOptions(MR_VOID);
*
*	FUNCTION	Gets system panning options, primarily used for multi-viewport
*				projects.
*
*	RESULT		panning_opt	-	Flags representing options
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.03.97	Dean Ashton		Incorporated into API.
*
*%%%**************************************************************************/

MR_LONG	MRSNDGetSystemPanningOptions(MR_VOID)
{
#ifdef	MR_API_SOUND
	return(MRSND_system_options_panning);
#else
	return(NULL);
#endif
}



/******************************************************************************
*%%%% MRSNDSetViewportMovingSoundFlags
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDSetViewportMovingSoundFlags(	MR_USHORT	id,
*															MR_ULONG	flags);
*
*	FUNCTION	Given a moving-sound viewport id, this routine sets flags used
*				by moving sound routines.
*
*	INPUTS		id				-		Identifier for the viewport
*				flags			-		Flags for this viewports moving sound updates
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.03.97	Dean Ashton		Incorporated into API.
*
*%%%**************************************************************************/

MR_VOID	MRSNDSetViewportMovingSoundFlags(MR_USHORT id, MR_ULONG flags)
{
#ifdef	MR_API_SOUND
	MR_ASSERT(id <= MRSND_viewports);

	MRSND_moving_sound_viewport_flags[id] = flags;
#endif
}

/******************************************************************************
*%%%% MRSNDSetVolumeLevel
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRSNDSetVolumeLevel( 	MR_ULONG 	vol_source,
*				 						 		MR_ULONG	vol_level);
*
*	FUNCTION	Sets a volume level for a sound source
*
*	INPUTS		vol_source	-	Define representing a volume source change ID
*									Either 	MRSND_MASTER_VOLUME,
*											MRSND_FX_VOLUME, or
*											MRSND_CD_VOLUME,
*
*				vol_level	-	Volume level (0->127)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	18.03.97	Dean Ashton		Incorporated into API.
*
*%%%**************************************************************************/

MR_VOID	MRSNDSetVolumeLevel(MR_ULONG vol_source, MR_ULONG vol_level)
{
#ifdef	MR_API_SOUND
	CdlATV			sv_cd_mixer;

	MR_ASSERT(vol_level < 128);

	if (vol_source == MRSND_MASTER_VOLUME)
		{
		MRSND_master_volume = vol_level;
		SsSetMVol(MRSND_master_volume, MRSND_master_volume);
		}
	else
	if (vol_source == MRSND_FX_VOLUME)
		{
		MRSND_fx_volume = vol_level;
		}
	else
	if (vol_source == MRSND_CD_VOLUME)
		{
		MRSND_cd_volume		= vol_level;
		sv_cd_mixer.val0 	= MRSND_cd_volume;
		sv_cd_mixer.val1 	= 0;
		sv_cd_mixer.val2 	= MRSND_cd_volume;
		sv_cd_mixer.val3 	= 0;
		CdMix(&sv_cd_mixer);
		}
	else
		MR_ASSERT(FALSE);
#endif
}


//------------------------------------------------------------------------------
// The code and variables below are COMMENTED OUT. They are here to provide a
//	basic sound test function, and should be pasted into the project source code
//	so it can have access to fonts, button presses, and other project specific
// things.
//
//
// Under no circumstances is this code to be uncommented within mr_sound.c.
//
//
//------------------------------------------------------------------------------

/*********************** Start of Prototype Test code ***************************

MR_UBYTE		vdisp_voice;
MR_STRPTR		vdisp_status;
MR_BYTE			vdisp_prog;
MR_UBYTE		vdisp_l_vol;
MR_UBYTE		vdisp_r_vol;
MR_STRPTR		vdisp_type;

MR_BYTE			vdisp_spu_on;
MR_BYTE			vdisp_spu_on_env_off;
MR_BYTE			vdisp_spu_off_env_on;
MR_BYTE			vdisp_spu_off;

MR_STRPTR		vds_empty	 	= "----";
MR_STRPTR		vds_init	 	= "INIT";
MR_STRPTR		vds_play		= "PLAY";

MR_STRPTR		vdt_empty		= "------";
MR_STRPTR		vdt_single		= "SINGLE";
MR_STRPTR		vdt_repeat		= "REPEAT";
MR_STRPTR		vdt_looped		= "LOOPED";

MR_STRPTR		voice_disp[] 	= {" %b %s %B %b %b %s %b %b %b %b\n",
									(MR_STRPTR)&vdisp_voice,			(MR_STRPTR)2,
									(MR_STRPTR)&vdisp_status,
									(MR_STRPTR)&vdisp_prog,				(MR_STRPTR)2,
									(MR_STRPTR)&vdisp_l_vol,			(MR_STRPTR)3,
									(MR_STRPTR)&vdisp_r_vol,			(MR_STRPTR)3,
									(MR_STRPTR)&vdisp_type,
									(MR_STRPTR)&vdisp_spu_on,			(MR_STRPTR)1,
									(MR_STRPTR)&vdisp_spu_on_env_off,(MR_STRPTR)1,
									(MR_STRPTR)&vdisp_spu_off_env_on,(MR_STRPTR)1,
									(MR_STRPTR)&vdisp_spu_off,			(MR_STRPTR)1,
									NULL};

MR_SHORT		prog_id;
MR_UBYTE		sample_unnamed[] = "Unnamed";
MR_STRPTR		sample_id_ptr;

MR_STRPTR		sample_disp[]	= {"Current sound: %h - %s",
									(MR_STRPTR)&prog_id, (MR_STRPTR)3, 
									(MR_STRPTR)&sample_id_ptr,
									NULL};

MR_TEXT_AREA*	voice_line[24];
MR_TEXT_AREA*	sample_line;

MR_VOID	MRSNDTestSound(MR_VOID)
{
	MRSND_SAMPLE_INFO*	sample_ptr;
	MRSND_VAB_INFO*		vab_ptr;
	MR_VIEWPORT*		viewport;
	MR_LONG				loop;
	MR_LONG				text_y;
	
 	MR_LONG				test;
	MR_LONG				pbend=64;

	MRCreateDisplay(MR_SCREEN_STANDARD_320);
	MRSetDisplayClearColour(0x30,0x30,0x30);
	
	viewport = MRCreateViewport(NULL, NULL, MR_VP_SIZE_4096, 0);

	// Create text areas
	text_y = 42;	
	for (loop = 0; loop < 24; loop++)
		{
		voice_line[loop] = MRAllocateTextArea( NULL, NULL, viewport, 128, 8, text_y, 320, 8);
		text_y += 8;
		}

	sample_line = MRAllocateTextArea(NULL, NULL, viewport, 128, 16, 22, 320, 8);	
 
	// Test loop
	while(1)
		{
		DrawSync(0);
		VSync(0);
		MRSwapDisplay();
		MRReadInput();

		sample_ptr	= &MRSND_sample_info_ptr[prog_id];
		vab_ptr		= &MRSND_vab_info_ptr[sample_ptr->si_vabinfo_id];
	
		if (MR_CHECK_PAD_HELD(0,HRR_LEFT_2))
			{
			pbend--;
			if (pbend < 0)			
				pbend = 0;
			MRSNDPitchBend(test, pbend);
			}
		else
		if (MR_CHECK_PAD_HELD(0,HRR_RIGHT_2))
			{
			pbend++;
			if (pbend >127)			
				pbend = 127;
			MRSNDPitchBend(test, pbend);
			}
		else
		if (MR_CHECK_PAD_PRESSED(0,HRR_BLUE))
			{
//			MRSNDKillSound(test);
//			MRPrintf("Requested program %ld\n",prog_id);
			if (vab_ptr->va_vab_id != -1)
				{
				test = MRSNDPlaySound(prog_id, NULL, NULL, NULL);
				}
			}
		else
		if (MR_CHECK_PAD_PRESSED(0,HRR_RIGHT))
			{
			if (prog_id < (MRSND_number_of_samples - 1))
				prog_id++;
			}
		else
		if (MR_CHECK_PAD_PRESSED(0,HRR_LEFT))
			{
			prog_id--;
			if (prog_id < 0)
				prog_id = 0;
			}
		else
		if (MR_CHECK_PAD_PRESSED(0,HRR_UP))
			{
			MRSNDKillAllSounds();
			}


		MRSNDUpdateSound();
		
		// Update text areas with new status information
		
		MRStartGatso();
		for (loop = 0;  loop < 24; loop ++)
			{
			vdisp_voice		=	loop;
			vdisp_l_vol		= 	(MR_BYTE)MRSND_voice[loop].vo_current_vol_l;
			vdisp_r_vol		= 	(MR_BYTE)MRSND_voice[loop].vo_current_vol_r;
	
			if (MRSND_voice[loop].vo_sample == NULL)
				{
				vdisp_prog	=	-1;
				vdisp_status=	vds_empty;
				}
			else
				{
				vdisp_prog	=	MRSND_voice[loop].vo_sample->si_prog;
		
				if (MRSND_voice[loop].vo_flags & MRSNDVF_INITIALISING)
					vdisp_status=	vds_init;
				else
					vdisp_status=	vds_play;
				}
	
			if (MRSND_voice[loop].vo_sample == NULL)
				vdisp_type	=	vdt_empty;
			else
			if (MRSND_voice[loop].vo_flags & MRSNDVF_SINGLE)
				vdisp_type	=	vdt_single;
			else
			if (MRSND_voice[loop].vo_flags & MRSNDVF_REPEAT)
				vdisp_type	=	vdt_repeat;
			else
			if (MRSND_voice[loop].vo_flags & MRSNDVF_LOOPED)
				vdisp_type	=	vdt_looped;

			vdisp_spu_on			= 0;
			vdisp_spu_on_env_off	= 0;
			vdisp_spu_off_env_on	= 0;
			vdisp_spu_off 			= 0;

			if (MRSND_voice_status[loop] == SPU_ON)
				vdisp_spu_on = 1;

			if (MRSND_voice_status[loop] == SPU_ON_ENV_OFF)
				vdisp_spu_on_env_off = 1;

			if (MRSND_voice_status[loop] == SPU_OFF_ENV_ON)
				vdisp_spu_off_env_on = 1;

			if (MRSND_voice_status[loop] == SPU_OFF)
				vdisp_spu_off = 1;

			if (MRSND_voice[loop].vo_sample == NULL)
	  			MRBuildText(voice_line[loop], voice_disp, MR_FONT_COLOUR_WHITE);
			else
	  			MRBuildText(voice_line[loop], voice_disp, MR_FONT_COLOUR_YELLOW);
			}

		if (sample_ptr->si_sample_name == NULL)
			sample_id_ptr = sample_unnamed;
		else
			sample_id_ptr = sample_ptr->si_sample_name;
		
		if (vab_ptr->va_vab_id != -1)
			MRBuildText(sample_line, sample_disp, MR_FONT_COLOUR_CADMIUM);
		else	
			MRBuildText(sample_line, sample_disp, MR_FONT_COLOUR_RED);

		MRSNDUpdateSound();

		MRUpdateFrames();
		MRUpdateObjects();
		MRUpdateViewportRenderMatrices();
		MRRenderViewport(viewport);
		MRStopGatso();

		Progress_monitor();
		}
}

*********************** End of Prototype Test code ***************************/

