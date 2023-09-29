/******************************************************************************
*%%%% mr_part.h
*------------------------------------------------------------------------------
*
*	New header file for mr_part.h
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

typedef	struct	__mr_pgen	  			MR_PGEN;					
typedef	struct	__mr_pgen_init			MR_PGEN_INIT;			
typedef	struct	__mr_pgen_inst			MR_PGEN_INST;					
typedef	struct 	__mr_ptype_point_geom	MR_PTYPE_POINT_GEOM;	
typedef	struct 	__mr_ptype_3d_geom		MR_PTYPE_3D_GEOM;	
typedef	struct 	__mr_ptype_2d_geom		MR_PTYPE_2D_GEOM;	

#else
#ifndef	__MR_PART_H
#define	__MR_PART_H

//------------------------------------------------------------------------------------------------
//	Defines
//------------------------------------------------------------------------------------------------

// MR_PGEN_INIT types
#define	MR_PTYPE_POINT		  				(0)
#define	MR_PTYPE_3D			  				(1)
#define	MR_PTYPE_2D			  				(2)

// MR_PGEN_INIT flags
#define	MR_PF_INACTIVE		  				(1<<0)					// Don't display this generator (or process particles)
#define	MR_PF_CLOSING_DOWN					(1<<1)					// Set if we're closing down
#define	MR_PF_NO_ACTIVE_PARTS				(1<<2)					// Set if all particle lifetimes 0
#define	MR_PF_EXIST_IN_GENERATOR_FRAME		(1<<3)					// Particles exist in frame of generator
#define	MR_PF_NO_GEOMETRY					(1<<4)					// No geometry memory is allocated or used


//------------------------------------------------------------------------------------------------
//	Structures
//------------------------------------------------------------------------------------------------

struct	__mr_pgen_init
		{
		MR_USHORT	pgi_type;											//	See MR_PGEN for descriptions
		MR_USHORT	pgi_flags;		
		MR_ULONG	pgi_prim_size;										// Size in bytes of a single particle poly

		MR_VOID		(*pgi_geom_init_callback)(MR_OBJECT*); 				// This is for mr_part use only
		MR_VOID		(*pgi_prim_init_callback)(MR_PGEN_INST*); 			// This is for mr_part use only
		MR_VOID		(*pgi_move_callback)(MR_OBJECT*);					// This is from MRUpdateObject()
		MR_VOID		(*pgi_disp_callback)(MR_PGEN_INST*, MR_VIEWPORT*);
		MR_LONG		pgi_gravity;
		MR_USHORT	pgi_max_particles;
		MR_USHORT	pgi_generator_life;
		MR_USHORT	pgi_particle_min_life;
		MR_USHORT	pgi_particle_max_life;
		MR_ULONG	pgi_user_data_1;
		MR_ULONG	pgi_user_data_2;

		};		//	MR_PGEN_INIT


struct	__mr_pgen
		{
		MR_USHORT	pg_type;											// Generator base type (Point/2d/3d)
		MR_USHORT	pg_flags;								 			// Flag settings
																						
		MR_VOID		(*pg_geom_init_callback)(MR_OBJECT*);				// This is for mr_part use only
		MR_VOID		(*pg_prim_init_callback)(MR_PGEN_INST*);			// This is for mr_part use only
		MR_VOID		(*pg_move_callback)(MR_OBJECT*);					// This is from MRUpdateObject()
		MR_VOID		(*pg_disp_callback)(MR_PGEN_INST*, MR_VIEWPORT*);	
		MR_LONG		pg_gravity;											// 'Gravity' value (16:16)
		MR_USHORT	pg_max_particles;								  	// Maximum number of particles allowed for this generator
		MR_SHORT	pg_generator_life;									// How long the generator should live (-1 means infinite)
		MR_USHORT	pg_particle_min_life;			  					// Minimum lifetime of an individual particle
		MR_USHORT	pg_particle_max_life;								// Maximum lifetime of an individual particle
																						
		MR_VOID*	pg_particle_info;									// Particle Geometry (separate to enable instancing later)
																						
		MR_SVEC		pg_offset;											// Offset from the particle frame
																						
		MR_ULONG	pg_user_data_1;										// User data 1
		MR_ULONG	pg_user_data_2;										// User data 2
																						
		MR_USHORT	pg_next_particle;									// Next particle index to use
		MR_USHORT	pg_prim_size;										// Size in bytes of a single particle poly
		MR_VOID*	pg_owner;											// Owning structure (eg. plane which owns this exhaust)
		MR_VOID*	pg_user_data_ptr;									// Points to optional allocation of user data (auto free on closedown)
																						
		};		//	MR_PGEN


struct	__mr_pgen_inst
		{
		struct	__mr_pgen_inst*	pi_next_node;							// Standard list stuff
		struct	__mr_pgen_inst*	pi_prev_node;

		MR_OBJECT*				pi_object;								// Hook back to object base

		MR_VOID*				pi_particle_prims[2];					// Pointers to each buffers primitives

		MR_USHORT				pi_kill_timer;							// Standard kill mechanism
		MR_USHORT				pi_pad;		  							// Pad for longword alignment

		};		// MR_PGEN_INST


struct __mr_ptype_point_geom
		{
		MR_VEC		pt_position;	 									// Position 		
		MR_VEC		pt_velocity;	 									// Velocity 		(16:16)
		MR_ULONG	pt_lifetime;										// Lifetime for this particle (0 means not displayed)
		MR_ULONG	pt_user;											// User data

		};		//	MR_PTYPE_POINT_GEOM;


struct __mr_ptype_3d_geom
		{
		MR_MAT		pt_matrix;											// Rotation and Translation
		MR_VEC		pt_velocity;										// Velocity			(16:16)
		MR_ULONG	pt_lifetime;										// Lifetime for this particle
		MR_ULONG	pt_user;											// User data

		};		//	MR_PTYPE_3D_GEOM;


struct __mr_ptype_2d_geom
		{
		MR_VEC		pt_position;						 				// Position			
		MR_VEC		pt_velocity;										// Velocity			(16:16)
		MR_ULONG	pt_lifetime;										// Lifetime for this particle
		MR_ULONG	pt_user;											// User data

		};		//	MR_PTYPE_2D_GEOM;



//------------------------------------------------------------------------------------------------
//	Prototypes
//------------------------------------------------------------------------------------------------

extern	MR_OBJECT*		MRCreatePgen(MR_PGEN_INIT* , MR_FRAME*, MR_ULONG, MR_SVEC*);
extern	MR_VOID			MRKillPgen(MR_OBJECT* pgen);
extern	MR_VOID			MRShutdownPgen(MR_OBJECT*);
extern	MR_VOID			MRShutdownPgenNow(MR_OBJECT*);

extern	MR_OBJECT*		MRCreateMemfixedWithInstsPgen(MR_PGEN_INIT*, MR_FRAME*, MR_ULONG, MR_VIEWPORT**);

#endif	//__MR_PART_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS
