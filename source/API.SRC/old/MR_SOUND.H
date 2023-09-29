/******************************************************************************
*%%%% mr_sound.h
*------------------------------------------------------------------------------
*
*	API Sound routines.
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	02.08.96	Dean Ashton		Created
*	22.04.97	Dean Ashton		MRSNDInit() returns a MR_BOOL now.
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//-----------------------------------------------------------------------------
//	Typedefs
//-----------------------------------------------------------------------------

typedef	struct	__mrsnd_vab_info		MRSND_VAB_INFO;
typedef	struct	__mrsnd_group_info		MRSND_GROUP_INFO;
typedef	struct	__mrsnd_sample_info		MRSND_SAMPLE_INFO;
typedef	struct	__mrsnd_moving_sound	MRSND_MOVING_SOUND;
typedef	struct	__mrsnd_voice_info		MRSND_VOICE_INFO;
typedef	SndVolume						MRSND_VOLUME;

#else
#ifndef	__MR_SOUND_H
#define	__MR_SOUND_H

//-----------------------------------------------------------------------------
//	Defines
//-----------------------------------------------------------------------------

#define	MRSND_MAX_VOICES							(24)
														
#define	MRSND_MAX_IDENT								(0x7fff)
#define	MRSND_MIN_IDENT								(0x0001)


#ifndef	MRSND_DEFAULT_MASTER_VOL
#define	MRSND_DEFAULT_MASTER_VOL					(127)
#endif

#ifndef	MRSND_DEFAULT_FX_VOL
#define	MRSND_DEFAULT_FX_VOL						(100)
#endif

#ifndef	MRSND_DEFAULT_CD_VOL
#define	MRSND_DEFAULT_CD_VOL						(100)
#endif

#define	MRSNDVF_INITIALISING						(1<<0)
#define	MRSNDVF_SINGLE								(1<<1)
#define	MRSNDVF_REPEAT								(1<<2)
#define	MRSNDVF_LOOPED								(1<<3)

// Set volume flags
#define	MRSND_MASTER_VOLUME							(1)
#define	MRSND_FX_VOLUME								(2)
#define	MRSND_CD_VOLUME								(3)

// Play sound flags
#define	MRSND_PLAY_FORCE_LEFT						(1<<0)
#define	MRSND_PLAY_FORCE_RIGHT						(1<<1)

// Viewport sound flags
#define	MRSND_VIEWPORT_FORCE_LEFT					(1<<0)
#define	MRSND_VIEWPORT_FORCE_RIGHT					(1<<1)

// System panning options
#define	MRSND_NORMAL_PANNING						(0)
#define	MRSND_HARD_PANNING							(1)

// Moving sound flags
#define	MRSND_MOVING_SOUND_ACCEPT_FADE				(1<<0)
#define	MRSND_MOVING_SOUND_ACCEPT_PAN				(1<<1)
#define	MRSND_MOVING_SOUND_ACCEPT_DOPPLER			(1<<2)

#ifndef	MRSND_MOVING_SOUND_DEFAULT_MIN_RADIUS
#define	MRSND_MOVING_SOUND_DEFAULT_MIN_RADIUS		(0x0700)
#endif

#ifndef	MRSND_MOVING_SOUND_DEFAULT_MAX_RADIUS
#define	MRSND_MOVING_SOUND_DEFAULT_MAX_RADIUS		(0x1c00)
#endif

#ifndef	MRSND_MOVING_SOUND_MAX_DOPPLER_RATE
#define	MRSND_MOVING_SOUND_MAX_DOPPLER_RATE			(0x200)
#endif

// Project defines
#ifndef	MRSND_MAX_VIEWPORTS
#define	MRSND_MAX_VIEWPORTS							(4)		// maximum number of viewports (and sound targets)
#endif


//-----------------------------------------------------------------------------
//	Macros
//-----------------------------------------------------------------------------

#define	MRSND_EXTRACT_IDENT(vi)						((vi)>>16)
#define	MRSND_EXTRACT_VOICE(vv)						((vv)&0x7fff)
#define	MRSND_MAKE_VOICE_IDENT(v,i)					(((i)<<16)|(v))



//-----------------------------------------------------------------------------
//	Structures
//-----------------------------------------------------------------------------

struct	__mrsnd_vab_info
			{
			MR_LONG					va_vh_resource_id;		// Resource for the VAB Header
			MR_LONG					va_vb_resource_id;		// Resource for the VAB Body 
			MR_SHORT				va_vab_id;				// VAB Identifier allocated by LIBSND (-1 == Not allocated)
			MR_SHORT				va_pad;					// Pad
			};	//MRSND_VAB_INFO;


struct	__mrsnd_group_info
			{
			MR_SHORT				gi_min_voice;			// Minimum voice number for the group
			MR_SHORT				gi_max_voice;			// Maximum voice number for the group

			};	//MRSND_GROUP_INFO;


struct	__mrsnd_sample_info
			{
			MR_ULONG	 			si_flags;				// Flags for this sound 
			MR_USHORT	 			si_vabinfo_id;			// Owning MRSND_VAB_INFO identifier (actually an index)
			MR_USHORT	 			si_group_id;			// Owning MRSND_GROUP_INFO identifier (actually an index)
			MR_USHORT				si_prog;				// VAB program number (0-127)
			MR_USHORT				si_tone;				// VAB tone number (0-15)
			MR_USHORT				si_pitch;				// Pitch specification in half-tone units (0-127)
			MR_USHORT				si_pitch_mod;			// Power of 2 limit for pitch modification
			MR_USHORT				si_min_volume;			// Min volume sound can be
			MR_USHORT				si_max_volume;			// Max volume sound can be
			MR_UBYTE*				si_sample_name;			// Pointer to sample name, or NULL

			};	//MRSND_SAMPLE_INFO;


struct	__mrsnd_moving_sound
			{
			MRSND_MOVING_SOUND*		ms_next_node;						// linked list next node
			MRSND_MOVING_SOUND*		ms_prev_node;						// linked list prev node
			MRSND_MOVING_SOUND**	ms_owner;							// Address of the pointer to this moving sound
			MR_VEC*					ms_source;							// moving sound position in world
			MR_VEC*					ms_source_old;						// moving sound position in world (last frame)
			MR_VEC					ms_source_copy;						//	...the above can point to this if they like
			MR_LONG					ms_voice_id[MRSND_MAX_VIEWPORTS];	// voice id (-1 if no sound played) (for all viewports)
			MR_USHORT				ms_flags;							// flags
			MR_USHORT				ms_sound;							// sound equate to play (looped or single)
			MR_USHORT				ms_max_radius;						// radius at which sound is min volume
			MR_USHORT				ms_min_radius;						// radius at which sound is max volume

			};	//MRSND_MOVING_SOUND;


struct	__mrsnd_voice_info
			{
			MRSND_SAMPLE_INFO*		vo_sample;
			MRSND_MOVING_SOUND*		vo_moving_owner;
			MR_ULONG				vo_flags;		   		// Flags for this voice
			MR_SHORT				vo_current_vab_id;		// Holds VAB ID for current sample (allocated by LIBSND, not index into VAB info array)
			MR_SHORT				vo_current_ident;  		// Incremental ID for note modification protection
			MR_USHORT				vo_current_adsr1;  		// Current ADSR1 value
			MR_USHORT				vo_current_adsr2;  		// Current ADSR2 value
			MR_SHORT				vo_current_note;   		// Current pitch specification in half-tone units (0-127)
			MR_SHORT				vo_current_fine;   		// Current fine pitch specification			
			MR_SHORT				vo_current_pitch_bend;	// Current pitch-bend value (0-127, 64=Center)
			MR_SHORT				vo_current_vol_l;  		// Current left volume after scaling using effect volume level(0-127) 
			MR_SHORT				vo_current_vol_r;  		// Current left volume after scaling using effect volume level (0-127)
			MR_SHORT				vo_current_req_vol_l;	// Current left volume before scaling (0-127)
			MR_SHORT				vo_current_req_vol_r;	// Current left volume before scaling (0-127)
			MR_SHORT				vo_pad;					// Pad for MR_LONG alignment
			};	//MRSND_VOICE_INFO;


//-----------------------------------------------------------------------------
// Externs
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
//	Prototypes
//-----------------------------------------------------------------------------

extern	MR_BOOL				MRSNDInit(MRSND_VAB_INFO*, MRSND_GROUP_INFO*, MRSND_SAMPLE_INFO*);
extern	MR_VOID				MRSNDOpenVab(MR_LONG, MR_BOOL);
extern	MR_VOID				MRSNDCloseVab(MR_LONG);

extern	MR_LONG				MRSNDPlaySound(MR_USHORT, SndVolume*, MR_USHORT, MR_LONG);
extern	MR_VOID				MRSNDUpdateSound(MR_VOID);
extern	MR_VOID				MRSNDChangeADSR(MR_LONG, MR_USHORT, MR_USHORT);
extern	MR_VOID				MRSNDChangePitch(MR_LONG, MR_SHORT, MR_SHORT);
extern	MR_VOID				MRSNDPitchBend(MR_LONG, MR_SHORT);
extern	MR_VOID				MRSNDChangeVolume(MR_LONG, SndVolume*);
extern	MRSND_SAMPLE_INFO*	MRSNDCheckSound(MR_LONG);

extern	MR_VOID				MRSNDKillSound(MR_LONG);
extern	MR_VOID				MRSNDKillAllSounds(MR_VOID);
extern	MR_VOID				MRSNDResetAllLoopedVoices(MR_LONG**);
extern	MR_VOID				MRSNDClearAllLoopedVoicesIds(MR_LONG**);

extern	MRSND_MOVING_SOUND*	MRSNDCreateMovingSound(MR_VEC*, MR_VEC*, MR_USHORT, MRSND_MOVING_SOUND**);
extern	MR_VOID				MRSNDKillMovingSound(MRSND_MOVING_SOUND*);
extern	MR_VOID				MRSNDUpdateMovingSounds(MR_VOID);
extern	MR_VOID				MRSNDSetMovingSoundTarget(MR_USHORT, MR_VEC*, MR_VEC*, MR_MAT*);
extern	MR_VOID				MRSNDKillAllMovingSounds(MR_VOID);
extern	MR_VOID				MRSNDResetAllMovingSounds(MR_VOID);
extern	MR_VOID				MRSNDPlaySoundWithPan(MR_USHORT, SndVolume*, MR_VEC*);
extern	MR_VOID				MRSNDPanSound(MR_LONG, MR_VEC*, MR_USHORT);
extern	MR_VOID				MRSNDSetViewports(MR_USHORT);

extern	MR_VOID				MRSNDSetSystemPanningOptions(MR_LONG);
extern	MR_LONG				MRSNDGetSystemPanningOptions(MR_VOID);
extern	MR_VOID				MRSNDSetViewportMovingSoundFlags(MR_USHORT, MR_ULONG);

extern	MR_VOID				MRSNDSetVolumeLevel(MR_ULONG, MR_ULONG);

#endif	//__MR_SOUND_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

