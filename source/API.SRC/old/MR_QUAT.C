/******************************************************************************
*%%%% mr_quat.c
*------------------------------------------------------------------------------
*
*	API Quaternion manipulation
*
*	CHANGED		PROGRAMMER		REASON
*	-------  	----------  	------
*	17.05.96	Tim Closs		Created
*	21.06.96	Tim Closs		Added tolerance parameter to MRNormaliseQuaternion
*	17.03.97	Tim Closs		Removed MRMulQuaternionByEulers..() functions
*					 			Added MRQuaternionBToMatrix()
*					 			MRMatrixToQuaternionB()
*	12.06.97	Tim Closs		MRInterpolateQuaternions() no longer assumes
*								MR_QUAT is long-aligned
*								(due to existence of MR_QUAT_TRANS structure)
*
*%%%**************************************************************************/

#include "mr_all.h"


/******************************************************************************
*%%%% MRQuaternionToMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRQuaternionToMatrix(
*						MR_QUAT*	q,
*						MR_MAT*	m);
*
*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
*
*	INPUTS		q			-	Pointer to quaternion (3.12 format)
*				m			-	Pointer to matrix to fill in
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	MR_GTE_QUAT_SPEEDUPS
MR_VOID	MRQuaternionToMatrix(	MR_QUAT*	q,
								MR_MAT*		m)
{
	MR_LONG	xs, ys, zs, wx, wy, wz, xx, xy, xz, yy, yz, zz;

	MR_ASSERT(q != NULL);
	MR_ASSERT(m != NULL);

	xs = q->x << 1,	ys = q->y << 1,	zs = q->z << 1;

	wx = q->c * xs,	wy = q->c * ys,	wz = q->c * zs;
	xx = q->x * xs,	xy = q->x * ys,	xz = q->x * zs;
	yy = q->y * ys,	yz = q->y * zs,	zz = q->z * zs;

	m->m[0][0] = 0x1000 - ((yy + zz) >> 12);
	m->m[0][1] = (xy + wz) >> 12;
	m->m[0][2] = (xz - wy) >> 12;

	m->m[1][0] = (xy - wz) >> 12;
	m->m[1][1] = 0x1000 - ((xx + zz) >> 12);
	m->m[1][2] = (yz + wx) >> 12;

	m->m[2][0] = (xz + wy) >> 12;
	m->m[2][1] = (yz - wx) >> 12;
	m->m[2][2] = 0x1000 - ((xx + yy) >> 12);
}
#endif


/******************************************************************************
*%%%% MRMulQuaternionABC
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMulQuaternionABC(
*						MR_QUAT*		a,
*						MR_QUAT*		b,
*						MR_QUAT*		c);
*
*	FUNCTION	Multiplies quaternions 'a' and 'b', placing result in 'c'.
*
*	INPUTS		a			-	Pointer to quaternion 'a' (input)
*				b			-	Pointer to quaternion 'b' (input)
*				c			-	Pointer to quaternion 'c' (output)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMulQuaternionABC(	MR_QUAT* a,
							MR_QUAT* b,
							MR_QUAT* c)
{
	MR_ASSERT(a != NULL);
	MR_ASSERT(b != NULL);
	MR_ASSERT(c != NULL);

	c->c = ((a->c * b->c) - (a->x * b->x + a->y * b->y + a->z * b->z)) >> 12;

	c->x = ((a->y * b->z - a->z * b->y) + (a->c * b->x) + (b->c * a->x)) >> 12;
	c->y = ((a->z * b->x - a->x * b->z) + (a->c * b->y) + (b->c * a->y)) >> 12;
	c->z = ((a->x * b->y - a->y * b->x) + (a->c * b->z) + (b->c * a->z)) >> 12;
}


///******************************************************************************
//*%%%% MRMulQuaternionByEulersLocalZXY
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	MRMulQuaternionByEulersLocalZXY(
//*						MR_QUAT*		b,
//*						MR_SHORT		ztheta,
//*						MR_SHORT		xtheta,
//*						MR_SHORT		ytheta);
//*
//*	FUNCTION	Multiplies quaternions 'b' by local Z, X and Y rotations
//*
//*	INPUTS		b	 		-	Pointer to quaternion 'b' 
//*				ztheta		-	Angle about Z axis (local z)
//*				xtheta		-	Angle about X axis (local x)
//*				ytheta		-	Angle about Y axis (local y)
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	17.05.96	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRMulQuaternionByEulersLocalZXY(	MR_QUAT* b,
//												MR_SHORT ztheta,
//												MR_SHORT xtheta,
//												MR_SHORT ytheta)
//{
//	MR_QUAT	t, s;
//	MR_LONG	cos;
//	MR_LONG	sin;
//
//	MR_ASSERT(b != NULL);
//
//	ztheta >>= 1;
//	ytheta >>= 1;
//	xtheta >>= 1;
//
//	// Do Z (a->c = cos, a->x = 0, a->y = 0, a->z = sin)
//	cos = rcos(ztheta);
//	sin = rsin(ztheta);
//	t.c = (( cos * b->c) - (sin * b->z)) >> 10;
//	t.x = ((-sin * b->y) + (cos * b->x)) >> 10;
//	t.y = (( sin * b->x) + (cos * b->y)) >> 10;
//	t.z = (( cos * b->z) + (b->c * sin)) >> 10;
//
//	// Do X (a->c = cos, a->x = sin, a->y = 0, a->z = 0)
//	cos = rcos(xtheta);
//	sin = rsin(xtheta);
//	s.c = (( cos * t.c) - (sin * t.x)) >> 14;
//	s.x = (( cos * t.x) + (t.c * sin)) >> 14;
//	s.y = ((-sin * t.z) + (cos * t.y)) >> 14;
//	s.z = (( sin * t.y) + (cos * t.z)) >> 14;
//
//	// Do Y (a->c = cos, a->x = 0, a->y = sin, a->z = 0)
//	cos = rcos(ytheta);
//	sin = rsin(ytheta);
//	b->c = (( cos * s.c) - (sin * s.y)) >> 12;
//	b->x = (( sin * s.z) + (cos * s.x)) >> 12;
//	b->y = (( cos * s.y) + (s.c * sin)) >> 12;
//	b->z = ((-sin * s.x) + (cos * s.z)) >> 12;
//}
//
//
///******************************************************************************
//*%%%% MRMulQuaternionByEulersLocalZX
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	MRMulQuaternionByEulersLocalZX(
//*						MR_QUAT*		b,
//*						MR_SHORT		ztheta,
//*						MR_SHORT		xtheta);
//*
//*	FUNCTION	Multiplies quaternions 'b' by local Z and X rotations
//*
//*	INPUTS		b	  		-	Pointer to quaternion 'b' 
//*				ztheta		-	Angle about Z axis (local z)
//*				xtheta		-		Angle about X axis (local x)
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	30.05.96	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRMulQuaternionByEulersLocalZX(	MR_QUAT* b,
//														MR_SHORT ztheta,
//														MR_SHORT xtheta)
//{
//	MR_QUAT	t;
//	MR_LONG	cos;
//	MR_LONG	sin;
//
//	MR_ASSERT(b != NULL);
//
//	ztheta >>= 1;
//	xtheta >>= 1;
//
//	// Do Z (a->c = cos, a->x = 0, a->y = 0, a->z = sin)
//	cos = rcos(ztheta);
//	sin = rsin(ztheta);
//	t.c = (( cos * b->c) - (sin * b->z)) >> 10;
//	t.x = ((-sin * b->y) + (cos * b->x)) >> 10;
//	t.y = (( sin * b->x) + (cos * b->y)) >> 10;
//	t.z = (( cos * b->z) + (b->c * sin)) >> 10;
//
//	// Do X (a->c = cos, a->x = sin, a->y = 0, a->z = 0)
//	cos = rcos(xtheta);
//	sin = rsin(xtheta);
//	b->c = (( cos * t.c) - (sin * t.x)) >> 14;
//	b->x = (( cos * t.x) + (t.c * sin)) >> 14;
//	b->y = ((-sin * t.z) + (cos * t.y)) >> 14;
//	b->z = (( sin * t.y) + (cos * t.z)) >> 14;
//}
//
//
///******************************************************************************
//*%%%% MRMulQuaternionByEulersY
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	MRMulQuaternionByEulersY(
//*						MR_QUAT*		b,
//*						MR_SHORT		xtheta,
//*						MR_SHORT		ytheta,
//*						MR_SHORT		ztheta);
//*
//*	FUNCTION	Multiplies quaternions 'b' by X, Y and Z rotations. 
//*
//*	INPUTS		b	  		-	Pointer to quaternion 'b' 
//*				xtheta		-	Angle about X axis (local x)
//*				ytheta		-	Angle about Y axis (world y)
//*				ztheta		-	Angle about Z axis (local z)
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	17.05.96	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRMulQuaternionByEulersY(	MR_QUAT* b,
//										MR_SHORT xtheta,
//										MR_SHORT ytheta,	
//										MR_SHORT ztheta)
//{
//	MR_QUAT	t, s;
//	MR_LONG	cos;
//	MR_LONG	sin;
//
//	MR_ASSERT(b != NULL);
//
//	ztheta >>= 1;
//	ytheta >>= 1;
//	xtheta >>= 1;
//
//	// Do Z (a->c = cos, a->x = 0, a->y = 0, a->z = sin)
//	cos = rcos(ztheta);
//	sin = rsin(ztheta);
//	t.c = (( cos * b->c) - (sin * b->z)) >> 10;
//	t.x = ((-sin * b->y) + (cos * b->x)) >> 10;
//	t.y = (( sin * b->x) + (cos * b->y)) >> 10;
//	t.z = (( cos * b->z) + (b->c * sin)) >> 10;
//
//	// Do X (a->c = cos, a->x = sin, a->y = 0, a->z = 0)
//	cos = rcos(xtheta);
//	sin = rsin(xtheta);
//	s.c = (( cos * t.c) - (sin * t.x)) >> 12;
//	s.x = (( cos * t.x) + (t.c * sin)) >> 12;
//	s.y = ((-sin * t.z) + (cos * t.y)) >> 12;
//	s.z = (( sin * t.y) + (cos * t.z)) >> 12;
//
//	// Do Y (b->c = cos, b->x = 0, b->y = sin, b->z = 0)
//	cos = rcos(ytheta);
//	sin = rsin(ytheta);
//	b->c = (( s.c * cos) - (s.y * sin)) >> 14;
//	b->x = ((-s.z * sin) + (cos * s.x)) >> 14;
//	b->y = (( s.c * sin) + (cos * s.y)) >> 14;
//	b->z = (( s.x * sin) + (cos * s.z)) >> 14;
//}
//
///******************************************************************************
//*%%%% MRMulQuaternionByEulersToMatrixY
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	MRMulQuaternionByEulersToMatrixY(
//*						MR_QUAT*		b,
//*						MR_SHORT		xtheta,
//*						MR_SHORT		ytheta,
//*						MR_SHORT		ztheta,
//*						MR_MAT*		m);
//*
//*	FUNCTION	Multiplies quaternions 'b' by X, Y and Z rotations. 
//*
//*	INPUTS		b			-	Pointer to quaternion 'b' 
//*				xtheta		-	Angle about X axis (local x)
//*				ytheta		-	Angle about Y axis (world y)
//*				ztheta		-	Angle about Z axis (local z)
//*				m			-	Matrix generated from new quaternion 'b'
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	17.05.96	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRMulQuaternionByEulersToMatrixY(	MR_QUAT* b,
//							 					MR_SHORT xtheta,
//												MR_SHORT ytheta,
//												MR_SHORT ztheta,
//												MR_MAT*	m)
//{
//	MR_QUAT	t, s;
//	MR_LONG	cos;
//	MR_LONG	sin;
//	MR_LONG	xs, ys, zs, wx, wy, wz, xx, xy, xz, yy, yz, zz;
//
//	MR_ASSERT(b != NULL);
//	MR_ASSERT(m != NULL);
//
//	ztheta >>= 1;
//	ytheta >>= 1;
//	xtheta >>= 1;
//
//	// Do Z (a->c = cos, a->x = 0, a->y = 0, a->z = sin)
//	cos = rcos(ztheta);
//	sin = rsin(ztheta);
//	t.c = (( cos * b->c) - (sin * b->z)) >> 10;
//	t.x = ((-sin * b->y) + (cos * b->x)) >> 10;
//	t.y = (( sin * b->x) + (cos * b->y)) >> 10;
//	t.z = (( cos * b->z) + (b->c * sin)) >> 10;
//
//	// Do X (a->c = cos, a->x = sin, a->y = 0, a->z = 0)
//	cos = rcos(xtheta);
//	sin = rsin(xtheta);
//	s.c = (( cos * t.c) - (sin * t.x)) >> 12;
//	s.x = (( cos * t.x) + (t.c * sin)) >> 12;
//	s.y = ((-sin * t.z) + (cos * t.y)) >> 12;
//	s.z = (( sin * t.y) + (cos * t.z)) >> 12;
//
//	// Do Y (b->c = cos, b->x = 0, b->y = sin, b->z = 0)
//	cos = rcos(ytheta);
//	sin = rsin(ytheta);
//	b->c = (( s.c * cos) - (s.y * sin)) >> 14;
//	b->x = ((-s.z * sin) + (cos * s.x)) >> 13;
//	b->y = (( s.c * sin) + (cos * s.y)) >> 13;
//	b->z = (( s.x * sin) + (cos * s.z)) >> 13;
//
//	xs = b->x,			ys = b->y,			zs = b->z;
//	b->x >>= 1,			b->y >>= 1,			b->z >>= 1;
//
//	wx = b->c * xs,	wy = b->c * ys,	wz = b->c * zs;
//	xx = b->x * xs,	xy = b->x * ys,	xz = b->x * zs;
//	yy = b->y * ys,	yz = b->y * zs,	zz = b->z * zs;
//
//	m->m[0][0] = 0x1000 - ((yy + zz) >> 12);
//	m->m[0][1] = (xy + wz) >> 12;
//	m->m[0][2] = (xz - wy) >> 12;
//
//	m->m[1][0] = (xy - wz) >> 12;
//	m->m[1][1] = 0x1000 - ((xx + zz) >> 12);
//	m->m[1][2] = (yz + wx) >> 12;
//
//	m->m[2][0] = (xz + wy) >> 12;
//	m->m[2][1] = (yz - wx) >> 12;
//	m->m[2][2] = 0x1000 - ((xx + yy) >> 12);
//}
//
//
///******************************************************************************
//*%%%% MRMulQuaternionByEulersToMatrixF
//*------------------------------------------------------------------------------
//*
//*	SYNOPSIS	MR_VOID	MRMulQuaternionByEulersToMatrixF(
//*						MR_QUAT*		b,
//*						MR_SHORT		xtheta,
//*						MR_SHORT		ytheta,
//*						MR_SHORT		ztheta,
//*						MR_MAT*		m);
//*
//*	FUNCTION	Multiplies quaternions 'b' by X, Y and Z rotations. 
//*
//*	INPUTS		b			-	Pointer to quaternion 'b' 
//*				xtheta		-	Angle about X axis (local y)
//*				ytheta		-	Angle about Y axis (world y)
//*				ztheta		-	Angle about Z axis (local z)
//*				m			-	Matrix generated from new quaternion 'b'
//*
//*	CHANGED		PROGRAMMER		REASON
//*	-------		----------		------
//*	17.05.96	Tim Closs		Created
//*
//*%%%**************************************************************************/
//
//MR_VOID	MRMulQuaternionByEulersToMatrixF(	MR_QUAT*	b,
//							 					MR_SHORT	xtheta,
//												MR_SHORT	ytheta,
//												MR_SHORT	ztheta,
//												MR_MAT*		m)
//{
//	// X rotation is about LOCAL Y axis, Y rotation is about WORLD Y axis
//	MR_QUAT	t, s;
//	MR_LONG	cos;
//	MR_LONG	sin;
//	MR_LONG	xs, ys, zs, wx, wy, wz, xx, xy, xz, yy, yz, zz;
//
//	MR_ASSERT(b != NULL);
//	MR_ASSERT(m != NULL);
//
//	ztheta >>= 1;
//	ytheta >>= 1;
//	xtheta >>= 1;
//
//	// Do Z (a->c = cos, a->x = 0, a->y = 0, a->z = sin)
//	cos = rcos(ztheta);
//	sin = rsin(ztheta);
//	t.c = (( cos * b->c) - (sin * b->z)) >> 10;
//	t.x = ((-sin * b->y) + (cos * b->x)) >> 10;
//	t.y = (( sin * b->x) + (cos * b->y)) >> 10;
//	t.z = (( cos * b->z) + (b->c * sin)) >> 10;
//
//	// Do X (about local Y)
//	cos = rcos(xtheta);
//	sin = rsin(xtheta);
//	s.c = (( cos * t.c) - (sin * t.y)) >> 12;
//	s.x = (( sin * t.z) + (cos * t.x)) >> 12;
//	s.y = (( cos * t.y) + (t.c * sin)) >> 12;
//	s.z = ((-sin * t.x) + (cos * t.z)) >> 12;
//
//	// Do Y (b->c = cos, b->x = 0, b->y = sin, b->z = 0)
//	cos = rcos(ytheta);
//	sin = rsin(ytheta);
//	b->c = (( s.c * cos) - (s.y * sin)) >> 14;
//	b->x = ((-s.z * sin) + (cos * s.x)) >> 13;
//	b->y = (( s.c * sin) + (cos * s.y)) >> 13;
//	b->z = (( s.x * sin) + (cos * s.z)) >> 13;
//
//	xs = b->x,			ys = b->y,			zs = b->z;
//	b->x >>= 1,			b->y >>= 1,			b->z >>= 1;
//
//	wx = b->c * xs,	wy = b->c * ys,	wz = b->c * zs;
//	xx = b->x * xs,	xy = b->x * ys,	xz = b->x * zs;
//	yy = b->y * ys,	yz = b->y * zs,	zz = b->z * zs;
//
//	m->m[0][0] = 0x1000 - ((yy + zz) >> 12);
//	m->m[0][1] = (xy + wz) >> 12;
//	m->m[0][2] = (xz - wy) >> 12;
//
//	m->m[1][0] = (xy - wz) >> 12;
//	m->m[1][1] = 0x1000 - ((xx + zz) >> 12);
//	m->m[1][2] = (yz + wx) >> 12;
//
//	m->m[2][0] = (xz + wy) >> 12;
//	m->m[2][1] = (yz - wx) >> 12;
//	m->m[2][2] = 0x1000 - ((xx + yy) >> 12);
//}


/******************************************************************************
*%%%% MREulersToQuaternion
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MREulersToQuaternion(
*						MR_QUAT*		q,
*						MR_SHORT		x,
*						MR_SHORT		y,
*						MR_SHORT		z);
*
*	FUNCTION	Generates a quaternion 'q' from euler angles in order Z, Y and
*				X (yaw, pitch and roll).
*
*	INPUTS		q		-		Pointer to quaternion 'q'
*				x		-		Roll (angle about X)
*				y		-		Pitch (angle about Y)
*				z		-		Yaw (angle about z)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MREulersToQuaternion(MR_QUAT* q, MR_SHORT x, MR_SHORT y, MR_SHORT z)
{
	//	Pilfered from web !!!
	MR_LONG	cosx, sinx;
	MR_LONG	cosy, siny;
	MR_LONG	cosz, sinz;

	MR_ASSERT(q != NULL);

	z >>= 1;
	y >>= 1;
	x >>= 1;
	cosz = rcos(z);
	sinz = rsin(z);
	cosy = rcos(y);
	siny = rsin(y);
	cosx = rcos(x);
	sinx = rsin(x);

	q->x = (sinx * ((cosy * cosz) >> 6) - cosx * ((siny * sinz) >> 6)) >> 18;
	q->y = (cosx * ((siny * cosz) >> 6) + sinx * ((cosy * sinz) >> 6)) >> 18;
	q->z = (cosx * ((cosy * sinz) >> 6) - sinx * ((siny * cosz) >> 6)) >> 18;
	q->c = (cosx * ((cosy * cosz) >> 6) + sinx * ((siny * sinz) >> 6)) >> 18;
}


/******************************************************************************
*%%%% MRNormaliseQuaternion
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRNormaliseQuaternion(
*						MR_QUAT*		a,
*						MR_QUAT*		b,
*						MR_USHORT	tolerance);
*
*	FUNCTION	Normalise quaternion to unit
*
*	INPUTS		a	  		-	Pointer to input quaternion 'a'
*				b	  		-	Pointer to output quaternion 'b'
*				tolerance	-	maximum deviance from unit modulus we allow
*
*	MOTES		A low deviance means normalisation never changes the quat by much,
*				hence is unnoticable.  A higher deviance may have to be used if
*				for example the quat is being rotated very fast (eg. during whoosh!)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	21.06.96	Tim Closs		Added tolerance parameter
*
*%%%**************************************************************************/

MR_VOID	MRNormaliseQuaternion(MR_QUAT* a, MR_QUAT* b, MR_USHORT tolerance)
{
	MR_LONG	d;


	MR_ASSERT(a != NULL);
	MR_ASSERT(b != NULL);
	
	d = MR_SQRT(MR_SQR(a->c) + MR_SQR(a->x) + MR_SQR(a->y) + MR_SQR(a->z));
	d = MIN(0x1000 + tolerance, MAX(d, 0x1000 - tolerance));

	d 		= (1 << 24) / d;
	b->c 	= (a->c * d) >> 12;
	b->x 	= (a->x * d) >> 12;
	b->y 	= (a->y * d) >> 12;
	b->z 	= (a->z * d) >> 12;
}


/******************************************************************************
*%%%% MRMatrixToQuaternion
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMatrixToQuaternion(
*						MR_MAT*	m,
*						MR_QUAT*	q);
*
*	FUNCTION	Converts a 3x3 rotation matrix to a unit quaternion
*
*	INPUTS		m	 	-		Pointer to matrix to fill in
*				q	 	-		Pointer to quaternion (3.12 format)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMatrixToQuaternion(MR_MAT* m, MR_QUAT* q)
{
	MR_LONG				trace, s;
	MR_SHORT			i, j, k;
	static	MR_SHORT	next[3] = {1, 2, 0};

	MR_ASSERT(m != NULL);
	MR_ASSERT(q != NULL);

	trace = m->m[0][0] + m->m[1][1] + m->m[2][2];

	if (trace > 0) 
		{
		s = MR_SQRT((trace + 0x1000) << 12);
		q->c = s >> 1;
		q->x = ((m->m[1][2] - m->m[2][1]) << 11) / s;
		q->y = ((m->m[2][0] - m->m[0][2]) << 11) / s;
		q->z = ((m->m[0][1] - m->m[1][0]) << 11) / s;
		} 
	else 
		{
		i = 0;
		if (m->m[1][1] > m->m[0][0])
			i = 1;
		if (m->m[2][2] > m->m[i][i])
			i = 2;
    	j = next[i];  
		k = next[j];
    
		s = MR_SQRT(((m->m[i][i] - (m->m[j][j] + m->m[k][k])) + 0x1000) << 12);
		((MR_SHORT*)q)[i+1] 	= s >> 1;
		q->c					= ((m->m[j][k] - m->m[k][j]) << 11) / s;
		((MR_SHORT*)q)[j+1] 	= ((m->m[i][j] + m->m[j][i]) << 11) / s;
		((MR_SHORT*)q)[k+1] 	= ((m->m[i][k] + m->m[k][i]) << 11) / s;
		}
}


/******************************************************************************
*%%%% MRInterpolateQuaternions
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInterpolateQuaternions(
*						MR_QUAT*		startq,
*						MR_QUAT*		endq,
*						MR_QUAT*		destq,
*						MR_USHORT		t);
*
*	FUNCTION	Spherical linear interpolation of two unit quaternions.
*
*	INPUTS		startq		-		Start quaternion
*				endq 		-		End quaternion
*				destq		-		Destination quaternion (output)
*				t	 		-		Interpolation value (0..1, 1 is 0x1000)
*
*	NOTES		Usual case calc:	14 multiplies, 2 divides
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.05.96	Tim Closs		Created
*	12.06.97	Tim Closs		Code no longer assumes MR_QUAT is long-aligned
*								(due to existence of MR_QUAT_TRANS structure)
*
*%%%**************************************************************************/

#ifndef	MR_GTE_QUAT_SPEEDUPS
MR_VOID	MRInterpolateQuaternions(	MR_QUAT* 	startq,
							 		MR_QUAT* 	endq,
							 		MR_QUAT* 	destq,
							 		MR_USHORT	t)
{
	MR_SHORT	omega, cosomega, sinomega;
	MR_SHORT	startscale, endscale;
	MR_BOOL		bflip;
	MR_ULONG	to;


	MR_ASSERT(startq);
	MR_ASSERT(endq);
	MR_ASSERT(destq);

	if (t == 0)
		{
		destq->c = startq->c;
		destq->x = startq->x;
		destq->y = startq->y;
		destq->z = startq->z;
		return;
		}

	cosomega = ((startq->c * endq->c) +
				(startq->x * endq->x) +
				(startq->y * endq->y) +
				(startq->z * endq->z)) >> 12;	// -0x1000..0x1000

	// If the above dot product is negative, it would be better to go between the 
	// negative of the initial and the final, so that we take the shorter path.  
 	bflip = FALSE;
	if (cosomega < 0) 
		{
		bflip 		= TRUE;
		cosomega 	= -cosomega;
		}		  

	// Usual case
	if ((0x1000 - cosomega) > MR_QUAT_EPSILON) 
		{
		// Usual case
		cosomega 	= MAX(-0x1000, MIN(0x1000, cosomega));
		omega		= MR_ACOS_RAW(cosomega);					// omega = acos(cosomega)
		sinomega	= rsin(omega);

		to			= (t * omega) >> 12;
		endscale	= (rsin(to) << 12) / sinomega;
		startscale	= rcos(to) - ((cosomega * endscale) >> 12);
		} 
	else 
		{
		// Ends very close
		startscale	= 0x1000 - t;
		endscale	= t;
		}

	if (bflip == TRUE)
		endscale = -endscale;

	destq->c = (startscale * startq->c + endscale * endq->c) >> 12;
	destq->x = (startscale * startq->x + endscale * endq->x) >> 12;
	destq->y = (startscale * startq->y + endscale * endq->y) >> 12;
	destq->z = (startscale * startq->z + endscale * endq->z) >> 12;
	return;
}
#endif


/******************************************************************************
*%%%% MRInterpolateQuaternionsBToMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRInterpolateQuaternionsBToMatrix(
*						MR_QUATB*	startq,
*						MR_QUATB*	endq,
*						MR_MAT*		matrix,
*						MR_USHORT	t);
*
*	FUNCTION	Spherical linear interpolation of two unit quaternions.
*
*	INPUTS		startq		-	Start quaternion
*				endq  		-	End quaternion
*				matrix		-	Destination matrix (output)
*				t	  		-	Interpolation value (0..1, 1 is 0x1000)
*
*	NOTES		Usual case calc:	14 multiplies, 2 divides
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	19.03.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	MR_GTE_QUAT_SPEEDUPS
MR_VOID	MRInterpolateQuaternionsBToMatrix(	MR_QUATB* 	startq,
							 				MR_QUATB* 	endq,
							 				MR_MAT* 	matrix,
							 				MR_USHORT	t)
{
	MR_SHORT	omega, cosomega, sinomega;
	MR_SHORT	startscale, endscale;
	MR_BOOL		bflip;
	MR_ULONG	to;
	MR_QUAT		destq;


	MR_ASSERT(startq);
	MR_ASSERT(endq);
	MR_ASSERT(matrix);

	if (t == 0)
		{
		MR_QUATB_TO_MAT(startq, matrix);
		return;
		}

	cosomega = ((startq->c * endq->c) +
				(startq->x * endq->x) +
				(startq->y * endq->y) +
				(startq->z * endq->z)) >> 0;					// -0x1000..0x1000

	// If the above dot product is negative, it would be better to go between the 
	// negative of the initial and the final, so that we take the shorter path.  
 	bflip = FALSE;
	if (cosomega < 0) 
		{
		bflip 		= TRUE;
		cosomega 	= -cosomega;
		}

	// Usual case
	if ((0x1000 - cosomega) > MR_QUAT_EPSILON) 
	  	{
		// Usual case
		cosomega 	= MAX(-0x1000, MIN(0x1000, cosomega));
		omega		= MR_ACOS_RAW(cosomega);					// omega = acos(cosomega)
		sinomega	= rsin(omega);
		
		to			= (t * omega) >> 12;
		endscale	= (rsin(to) << 12) / sinomega;
		startscale	= rcos(to) - ((cosomega * endscale) >> 12);
		} 
	else 
		{
		// Ends very close
		startscale	= 0x1000 - t;
		endscale	= t;
		}

	if (bflip == TRUE)
		endscale = -endscale;

	destq.c = (startscale * startq->c + endscale * endq->c) >> 6;
	destq.x = (startscale * startq->x + endscale * endq->x) >> 6;
	destq.y = (startscale * startq->y + endscale * endq->y) >> 6;
	destq.z = (startscale * startq->z + endscale * endq->z) >> 6;

	if (endscale)
		MRNormaliseQuaternion(&destq, &destq, 0x20);

	MR_QUAT_TO_MAT(&destq, matrix);
	return;
}
#endif


/******************************************************************************
*%%%% MRQuaternionBToMatrix
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRQuaternionBToMatrix(
*						MR_QUATB*	q,
*						MR_MAT*	 	m);
*
*	FUNCTION	Find the 3x3 rotation matrix represented by a quaternion
*
*	INPUTS		q		-		Pointer to quaternion (1.1.6 format)
*				m		-		Pointer to matrix to fill in
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.03.97	Tim Closs		Created
*
*%%%**************************************************************************/

#ifndef	MR_GTE_QUAT_SPEEDUPS
MR_VOID	MRQuaternionBToMatrix(	MR_QUATB*	q,
								MR_MAT*		m)
{
	MR_LONG	xs, ys, zs, wx, wy, wz, xx, xy, xz, yy, yz, zz;

	MR_ASSERT(q != NULL);
	MR_ASSERT(m != NULL);

	xs = q->x << 1,	ys = q->y << 1,	zs = q->z << 1;
	wx = q->c * xs,	wy = q->c * ys,	wz = q->c * zs;
	xx = q->x * xs,	xy = q->x * ys,	xz = q->x * zs;
	yy = q->y * ys,	yz = q->y * zs,	zz = q->z * zs;

	m->m[0][0] = 0x1000 - ((yy + zz) >> 0);
	m->m[0][1] = (xy + wz) >> 0;
	m->m[0][2] = (xz - wy) >> 0;

	m->m[1][0] = (xy - wz) >> 0;
	m->m[1][1] = 0x1000 - ((xx + zz) >> 0);
	m->m[1][2] = (yz + wx) >> 0;

	m->m[2][0] = (xz + wy) >> 0;
	m->m[2][1] = (yz - wx) >> 0;
	m->m[2][2] = 0x1000 - ((xx + yy) >> 0);
}
#endif


/******************************************************************************
*%%%% MRMatrixToQuaternionB
*------------------------------------------------------------------------------
*
*	SYNOPSIS	MR_VOID	MRMatrixToQuaternionB(
*						MR_MAT*		m,
*						MR_QUATB*	q);
*
*	FUNCTION	Converts a 3x3 rotation matrix to a unit quaternion
*
*	INPUTS		m		-		Pointer to matrix to fill in
*				q		-		Pointer to quaternion (1.1.6 format)
*
*	CHANGED		PROGRAMMER		REASON
*	-------		----------		------
*	17.03.97	Tim Closs		Created
*
*%%%**************************************************************************/

MR_VOID	MRMatrixToQuaternionB(	MR_MAT* 	m,
								MR_QUATB* 	q)
{
	MR_LONG				trace, s;
	MR_SHORT			i, j, k;
	static	MR_SHORT	next[3] = {1, 2, 0};

	MR_ASSERT(m != NULL);
	MR_ASSERT(q != NULL);

	trace = m->m[0][0] + m->m[1][1] + m->m[2][2];

	if (trace > 0) 
		{
		s = MR_SQRT((trace + 0x1000) << 12);
		q->c = s >> 7;
		q->x = ((m->m[1][2] - m->m[2][1]) << 5) / s;
		q->y = ((m->m[2][0] - m->m[0][2]) << 5) / s;
		q->z = ((m->m[0][1] - m->m[1][0]) << 5) / s;
		} 
	else 
		{
		i = 0;
		if (m->m[1][1] > m->m[0][0])
			i = 1;
		if (m->m[2][2] > m->m[i][i])
			i = 2;
    	j = next[i];  
		k = next[j];
    
		s = MR_SQRT(((m->m[i][i] - (m->m[j][j] + m->m[k][k])) + 0x1000) << 12);
		((MR_BYTE*)q)[i+1]	= s >> 7;
		q->c				= ((m->m[j][k] - m->m[k][j]) << 5) / s;
		((MR_BYTE*)q)[j+1]	= ((m->m[i][j] + m->m[j][i]) << 5) / s;
		((MR_BYTE*)q)[k+1]	= ((m->m[i][k] + m->m[k][i]) << 5) / s;
		}
}

