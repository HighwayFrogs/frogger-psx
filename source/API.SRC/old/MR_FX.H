/******************************************************************************
*%%%% mr_fx.h
*------------------------------------------------------------------------------
*
*	New header file for mr_fx.h
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	21.11.96	Dean Ashton		Created
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef	struct	__mr_fx_fade_prims	MR_FX_FADE_PRIMS;
typedef	struct	__mr_fx_fade_data	MR_FX_FADE_DATA;
typedef	struct	__mr_fx_vshut_prims	MR_FX_VSHUT_PRIMS;
typedef	struct	__mr_fx_vshut_data	MR_FX_VSHUT_DATA;
typedef	struct	__mr_effect	  		MR_EFFECT;

#else
#ifndef	__MR_FX_H
#define	__MR_FX_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

#define	MR_FX_FADE_MAX			 	(127)

enum		{
			MR_FX_TYPE_NONE,													
			MR_FX_TYPE_FADE_UP,		
			MR_FX_TYPE_FADE_DOWN,
			MR_FX_TYPE_VSHUT_OPEN,
			MR_FX_TYPE_VSHUT_CLOSE,
			};


//------------------------------------------------------------------------------------------------
// Structures
//------------------------------------------------------------------------------------------------

struct	__mr_fx_fade_prims								// Polygon setup used for this type of effect
		{
		POLY_FT3	fx_fade_abr;		  				// Used to change the ABR value
		POLY_F4		fx_fade_poly;		  				// Viewport sized polygon (take size each frame)
	
		};		// MR_FX_FADE_PRIMS

struct	__mr_fx_fade_data				  				// Standard screen fade (up or down) data
		{
		MR_LONG		fx_fade_value;		  				// Current fade value
		MR_LONG		fx_fade_speed;		  				// Fade speed
	
		};		// MR_FX_FADE_DATA

struct	__mr_fx_vshut_prims								// Polygon setup used for this type of effect
		{
		POLY_F4 	fx_vshut_poly_0;	  				// Top half of vertical shut poly
		POLY_F4		fx_vshut_poly_1;	

		};		// MR_FX_VSHUT_PRIMS

struct	__mr_fx_vshut_data								// Vertical shutter wipe
		{
		MR_LONG		fx_vshut_delta;
		MR_LONG		fx_vshut_count;						// Counter so we know when to stop
		MR_LONG		fx_vshut_ofs;		  				// Fractional offset from center line of screen

		};		// MR_FX_VSHUT_DATA
		
struct	__mr_effect						  				// Effect control structure
		{
		MR_ULONG	fx_type;
		MR_USHORT	fx_buff_stat[2];	  				// Used for polygon invalidation

		union							  				// Polygon data for effects
			{
			MR_FX_FADE_PRIMS	fx_fade_prims;
			MR_FX_VSHUT_PRIMS	fx_vshut_prims;
			} fx_poly[2];

		union							  				// Internal data for effects
			{
			MR_FX_FADE_DATA	fx_fade_data;
			MR_FX_VSHUT_DATA	fx_vshut_data;
			} fx_data;

		};		// MR_EFFECT


//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_VOID		MRCreateEffect(MR_ULONG, MR_VIEWPORT*, MR_ULONG);
extern	MR_VOID		MRDeleteEffect(MR_VIEWPORT*);
extern	MR_VOID		MRProcessEffect(MR_VIEWPORT*);

#endif	//__MR_FX_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS

