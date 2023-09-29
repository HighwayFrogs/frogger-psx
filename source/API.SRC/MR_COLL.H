/******************************************************************************
*%%%% mr_coll.h
*------------------------------------------------------------------------------
*
*	Header for mr_coll.c
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	15.05.96	Tim Closs		Created
*	17.06.96	Dean Ashton		Changed collision type enum to start from 0
*	15.07.96	Tim Closs		Added MR_COLL_UNSTABLE equate
*	25.09.96	Tim Closs		New 4th param for MRCreateCollPrim(MR_USHORT, MR_USHORT, MR_FRAME*, MR_MAT*);
*								Only externed variables are now MRColl_lw_ptr, MRColl_matrix_ptr
*	10.10.96	Tim Closs		MRCheckCollPrimWithWorldPoint() now accepts frame input
*								MRCheckCollPrimsWithWorldPointAndFrame() renamed to
*								MRCheckCollPrimsWithWorldPoint()
*								MRReflectVectorInIntersectionPlane() now accepts frame input,
*								renamed to MRReflectVectorInCollPrim()
*								MRReflectVectorInIntersectionPlaneAndFrame() removed
*								Added	MRCheckBoundingBoxWithWorldPoint()
*								Added	MRReflectVectorInBoundingBoxPlane()
*	04.12.96	Tim Closs		MRReflectVectorInCollPrim now accepts reflection
*								normal ptr
*	12.02.97	Tim Closs		MRCheckCollPrimWithWorldPoint() REWRITEEN
*								MRCheckBoundingBoxWithWorldPoint() REWRITEEN
*								Added MRCollisionCheck()
*	11.03.97	Tim Closs		Added support for MR_COLLCHECK_C_POINT
*								Removed:
*								MRCheckCollPrimsWithWorldPoint()
*								MRReflectVectorInCollPrim()
*								MRPointToFrustrumCollision()
*								MRPointToFrustrumCollisionNoXY()
*								MRReflectVectorInBoundingBox()
*	12.03.97	Tim Closs		Added collision face flags
*
*%%%**************************************************************************/

#ifdef	__MR_ONLY_INCLUDE_TYPEDEFS

//------------------------------------------------------------------------------------------------
//	Typedefs
//------------------------------------------------------------------------------------------------

typedef struct	__mr_collprim			MR_COLLPRIM;
typedef struct	__mr_collcheck			MR_COLLCHECK;

#else
#ifndef	__MR_COLL_H
#define	__MR_COLL_H

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

// Collision primitive types
enum	{
		MR_COLLPRIM_CUBOID,
		MR_COLLPRIM_CYLINDER_X,
		MR_COLLPRIM_CYLINDER_Y,
		MR_COLLPRIM_CYLINDER_Z,
		MR_COLLPRIM_SPHERE,
		};

// Collision flags
#define	MR_COLL_STATIC				(1<<0)	// MR_FRAME* is cast to MR_MAT* (static frame)
#define	MR_COLL_LAST_IN_LIST		(1<<1)	// last collprim in list (eg. for nme planes)

// (intersection flags for cuboid)
#define	MR_COLL_NO_FACE_X_POS		(1<<2)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_X_NEG		(1<<3)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_Y_POS		(1<<4)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_Y_NEG		(1<<5)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_Z_POS		(1<<6)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_Z_NEG		(1<<7)	// do no intersection checking with this face

#define	MR_COLL_DISABLED			(1<<8)	// do no collision checking with this primitive

// (intersection flags for cylinder)
#define	MR_COLL_NO_FACE_END_POS		(1<<2)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_END_NEG		(1<<3)	// do no intersection checking with this face
#define	MR_COLL_NO_FACE_SURFACE		(1<<4)	// do no intersection checking with this face

// Collision face values
enum	{
		MR_COLLPRIM_FACE_SPHERE,
		MR_COLLPRIM_FACE_CYLINDER_CIRCLE,
		MR_COLLPRIM_FACE_CYLINDER_X_POS,
		MR_COLLPRIM_FACE_CYLINDER_X_NEG,
		MR_COLLPRIM_FACE_CYLINDER_Y_POS,
		MR_COLLPRIM_FACE_CYLINDER_Y_NEG,
		MR_COLLPRIM_FACE_CYLINDER_Z_POS,
		MR_COLLPRIM_FACE_CYLINDER_Z_NEG,
		MR_COLLPRIM_FACE_CUBOID_X_POS,
		MR_COLLPRIM_FACE_CUBOID_X_NEG,
		MR_COLLPRIM_FACE_CUBOID_Y_POS,
		MR_COLLPRIM_FACE_CUBOID_Y_NEG,
		MR_COLLPRIM_FACE_CUBOID_Z_POS,
		MR_COLLPRIM_FACE_CUBOID_Z_NEG,
		};

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------

struct	__mr_collprim
	{
	MR_USHORT		cp_type;					// eg. MR_COLLPRIM_CUBOID
	MR_USHORT		cp_flags;
	MR_FRAME*		cp_frame;					// frame that collision shape is sitting in
	MR_OBJECT*		cp_object;					// object that owns this collision prim
	
	MR_SVEC			cp_offset;					// offset from frame origin
	MR_LONG			cp_radius2;					// for cylinder base or sphere... SQUARED!
	MR_USHORT		cp_xlen;					// for cylinder_x or cuboid half-length
	MR_USHORT		cp_ylen;					// for cylinder_y or cuboid half-length
	MR_USHORT		cp_zlen;					// for cylinder_z or cuboid half-length
	MR_USHORT		cp_user;
	MR_MAT*			cp_matrix;					// NULL if aligned to cp_frame, else an additional rotation

	};	// MR_COLLPRIM

// MR_COLLCHECK checks point(s) (a) against collprim(s) (b) and calculates outputs (c)
//
// Possible inputs (a):
//
//	MR_SVEC 	array in world/frame
//	MR_HILITE	array in MR_STATIC_MESH
//	MR_HILITE	array in animation environment
//	MR_USHORT	animation environment model
//	MR_USHORT	animation environment part
//
// Possible inputs (b):
//
//	MR_COLLPRIM	array (global data)
//	MR_COLLPRIM	array in MR_STATIC_MESH
//	MR_COLLPRIM	array in animation environment
//	MR_BBOX		in MR_STATIC_MESH
//	MR_BBOX		in animation environment (global, percel or MR_PART)
//	MR_USHORT	animation environment model
//	MR_USHORT	animation environment part
//
// General inputs:
//
//	MR_ULONG	input (a) flags
//	MR_ULONG	input (b) flags
//	MR_ULONG	output (c) flags
//	MR_SVEC*	relative motion (world coords per cycle) of items (a) and (b)
//
// Possible outputs (c):
//
//	MR_VOID*	ptr to item (a) (MR_SVEC or MR_HILITE) that collided
//	MR_USHORT	index of above item in array
//	MR_VOID*	ptr to item (b) (MR_COLLPRIM or MR_BBOX) that collided
//	MR_USHORT	index of above item in array
//	MR_SVEC		reflection vector
//	MR_USHORT	animation environment model
//	MR_USHORT	animation environment part

// Inputs (a) flags
#define	MR_COLLCHECK_A_SVEC						(1<<0)
#define	MR_COLLCHECK_A_HILITE					(1<<1)
#define	MR_COLLCHECK_A_OWNER_STATIC_MESH		(1<<2)
#define	MR_COLLCHECK_A_OWNER_ANIM_ENV	  		(1<<3)
#define	MR_COLLCHECK_A_OWNER_FRAME		  		(1<<4)
#define	MR_COLLCHECK_A_OWNER_MATRIX	  			(1<<5)
#define	MR_COLLCHECK_A_ALL_PARTS				(1<<7)

// Inputs (b) flags
#define	MR_COLLCHECK_B_COLLPRIM_SPECIFIC		(1<<8)
#define	MR_COLLCHECK_B_BBOX_SPECIFIC	  		(1<<9)
#define	MR_COLLCHECK_B_OWNER_STATIC_MESH		(1<<10)
#define	MR_COLLCHECK_B_OWNER_ANIM_ENV			(1<<11)
#define	MR_COLLCHECK_B_OWNER_FRAME		  		(1<<12)
#define	MR_COLLCHECK_B_OWNER_MATRIX	  			(1<<13)
#define	MR_COLLCHECK_B_COLLPRIM					(1<<14)
#define	MR_COLLCHECK_B_PART_BBOX				(1<<15)
#define	MR_COLLCHECK_B_PERCEL_BBOX				(1<<16)
#define	MR_COLLCHECK_B_GLOBAL_BBOX				(1<<17)
#define	MR_COLLCHECK_B_ALL_PARTS				(1<<18)

// Outputs (c) flags
#define	MR_COLLCHECK_C_FACE						(1<<24)
#define	MR_COLLCHECK_C_POINT					(1<<25)
#define	MR_COLLCHECK_C_REFLECTION				(1<<26)

// Output flags written by collision functions
#define	MR_COLLCHECK_C_NO_OUTPUT				(1<<31)



struct	__mr_collcheck
	{
	// Inputs (a)
	MR_VOID*	mc_a_item;					// MR_SVEC* or MR_HILITE*
	MR_USHORT	mc_a_size;					// number of items in array
	MR_USHORT	mc_a_pad;
	MR_VOID*	mc_a_owner;					// MR_OBJECT* (static mesh) or MR_ANIM_ENV* or MR_FRAME*	or MR_MAT*
	MR_USHORT	mc_a_owner_model;			// if MR_ANIM_ENV_MULTIPLE, model index
	MR_USHORT	mc_a_owner_part;			// if MR_ANIM_ENV or MR_STATIC_MESH, part index

	// Inputs (b)
	MR_VOID*	mc_b_item;					// MR_COLLPRIM* or MR_BBOX*
	MR_USHORT	mc_b_size;					// number of items in array (if appropriate)
	MR_USHORT	mc_b_pad;
	MR_VOID*	mc_b_owner;					// MR_OBJECT* (static mesh) or MR_ANIM_ENV*
	MR_USHORT	mc_b_owner_model;			// if MR_ANIM_ENV_MULTIPLE, model index
	MR_USHORT	mc_b_owner_part;			// if MR_ANIM_ENV or MR_STATIC_MESH, part index
	
	// Outputs (c)
	MR_VOID*	mc_c_item_a;				// MR_SVEC* or MR_HILITE*
	MR_USHORT	mc_c_item_a_index;			// index of item a in array
	MR_USHORT	mc_c_item_a_model;			// if MR_ANIM_ENV_MULTIPLE, model index
	MR_USHORT	mc_c_item_a_part;			// if MR_ANIM_ENV, part index
	MR_USHORT	mc_c_pad;
	MR_VOID*	mc_c_item_b;				// MR_COLLPRIM* or MR_BBOX*
	MR_USHORT	mc_c_item_b_index;			// index of item a in array
	MR_USHORT	mc_c_item_b_model;			// if MR_ANIM_ENV_MULTIPLE, model index
	MR_USHORT	mc_c_item_b_part;			// if MR_ANIM_ENV, part index

	MR_USHORT	mc_c_face;					// face of collision prim
	MR_SVEC		mc_c_point;					// collision point (world coords)
	MR_VEC		mc_c_reflection_vector;		// reflection vector (world coords)
	MR_VEC		mc_c_reflection_normal;		// normal to collision surface (world coords)

	// General
	MR_ULONG	mc_c_flags;					// output flags (c) passed in to function
	MR_SVEC		mc_relative_motion;			// ab relative motion (if storing reflection vector)

	};	// MR_COLLCHECK


//-----------------------------------------------------------------------------
// Externs
//-----------------------------------------------------------------------------

extern	MR_MAT*			MRColl_lw_ptr;
extern	MR_MAT*			MRColl_matrix_ptr;


//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------

extern	MR_COLLPRIM*	MRCreateCollPrim(MR_USHORT, MR_USHORT, MR_FRAME*, MR_MAT*);
extern	MR_VOID			MRKillCollPrim(MR_COLLPRIM*);
extern	MR_VOID			MRResetCollisionPointers(MR_VOID);

extern	MR_BOOL			MRCheckCollPrimWithWorldPoint(MR_COLLPRIM*, MR_SVEC*, MR_MAT*, MR_COLLCHECK*);
extern	MR_BOOL			MRCheckBoundingBoxWithWorldPoint(MR_BBOX*, MR_SVEC*, MR_MAT*, MR_COLLCHECK*);
extern	MR_BOOL			MRCollisionCheck(MR_COLLCHECK*, MR_ULONG, MR_ULONG, MR_ULONG);

#endif	//__MR_COLL_H
#endif	//__MR_ONLY_INCLUDE_TYPEDEFS









