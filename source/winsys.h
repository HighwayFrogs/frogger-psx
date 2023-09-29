#ifndef __winsys_h
#define __winsys_h

#include	"resource.h"

// Number of frames per second
#define		FRAMES_PER_SECOND				60

// Important define following
#define		MR_APPLICATION_REGISTRY_KEY		"Hasbro\\Frogger"
#define		MR_MAX_TIMERS					1

// API Debugging options
#define		WIN95_API_DEBUG

#ifdef		WIN95_API_DEBUG
	#define		MR_DEBUG
	#define		MR_DEBUG_DISPLAY
	#define		DEBUG

//	#define		MR_MEM_DEBUG
//	#define		MR_MEM_FULL_DEBUG
//	#define		MR_MEM_TORTURE
	#define		MR_USE_ASSERTS
	//#define		MR_SHOW_MOF_INFO
#endif

#define		PSX_ENABLE_XA			// this define controls playback of cd audio (use psx define for simplicity)
#define		PSX_RELEASE				// release

#define		MR_API_SOUND			// this gives us API sound effects

//#define		PSX_MASTER			// master
//#define		WIN95_CD_LOAD

#endif	// __WINSYS_H