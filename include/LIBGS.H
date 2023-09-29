#ifndef _LIBGS_H_
#define _LIBGS_H_

/*
 * $PSLibId: Run-time Library Release 4.0$
 */

/*
 * libgs.h: Graphic Library Header 
 *
 *
 * Version 1.**	Apr,  8, 1994 
 *
 * Copyright (C) 1993 by Sony Corporation All rights Reserved 
 */

#ifndef NULL
#define NULL 0
#endif

/*** packet peripheral pointer ***/
typedef unsigned char PACKET;

#define PSBANK 0x80000000
/*** --- Zsort resolution --- ***/
#define ZRESOLUTION     0x3fff

/*** --- coordinate keyword - ***/
#define WORLD NULL
#define SCREEN ((GsCOORDINATE2 *)0x0001)


typedef struct {
	VECTOR  scale;
	SVECTOR rotate;
	VECTOR  trans;
}       GsCOORD2PARAM;

typedef struct _GsCOORDINATE2 {
	unsigned long flg;
	MATRIX  coord;
	MATRIX  workm;
	GsCOORD2PARAM *param;
	struct _GsCOORDINATE2 *super;
	struct _GsCOORDINATE2 *sub;
}       GsCOORDINATE2;

typedef struct {
	MATRIX  view;
	GsCOORDINATE2 *super;
}       GsVIEW2;

typedef struct {
	long    vpx, vpy, vpz;
	long    vrx, vry, vrz;
	long    rz;
	GsCOORDINATE2 *super;
}       GsRVIEW2;

typedef struct {
	int     vx, vy, vz;
	unsigned char r, g, b;
}       GsF_LIGHT;


typedef struct {
	unsigned p:24;
	unsigned char num:8;
}       GsOT_TAG;


typedef struct {
	unsigned long length;
	GsOT_TAG *org;
	unsigned long offset;
	unsigned long point;
	GsOT_TAG *tag;
}       GsOT;

typedef struct {
	unsigned long attribute;/* pers,trans,rotate,disp */
	GsCOORDINATE2 *coord2;	/* local dmatrix */
	unsigned long *tmd;
	unsigned long id;
}       GsDOBJ2;

typedef struct {
	unsigned long attribute;/* pers,trans,rotate,disp */
	GsCOORDINATE2 *coord2;	/* local dmatrix */
	unsigned long *pmd;	/* pmd top address */
	unsigned long *base;	/* object base address */
	unsigned long *sv;	/* shared vertex base */
	unsigned long id;
}       GsDOBJ3;

typedef struct {
	unsigned long attribute;/* pers,trans,rotate,disp */
	GsCOORDINATE2 *coord2;	/* local dmatrix */
	unsigned long *tmd;
	unsigned long id;
}       GsDOBJ4;

typedef struct {
	unsigned long attribute;
	GsCOORDINATE2 *coord2;
	unsigned long *tmd;
	unsigned long *packet;
	unsigned long id;
}       GsDOBJ5;

typedef struct {
	unsigned long attribute;
	short   x, y;
	unsigned short w, h;
	unsigned short tpage;
	unsigned char u, v;
	short   cx, cy;
	unsigned char r, g, b;
	short   mx, my;
	short   scalex, scaley;
	long    rotate;
}       GsSPRITE;

typedef struct {
	unsigned long attribute;
	short   x, y;
	DR_MODE mode[2];	/* Draw mode primitive */
	SPRT    packet[2];	/* Sprite primitive */
}       GsSPARRAY;

typedef struct {
	unsigned char u, v;
	unsigned short cba;
	unsigned short flag;
	unsigned short tpage;
}       GsCELL;

typedef struct {
	unsigned char cellw, cellh;
	unsigned short ncellw, ncellh;
	GsCELL *base;
	unsigned short *index;
}       GsMAP;

typedef struct {
	unsigned long attribute;
	short   x, y;
	short   w, h;
	short   scrollx, scrolly;
	unsigned char r, g, b;
	GsMAP  *map;
	short   mx, my;
	short   scalex, scaley;
	long    rotate;
}       GsBG;

typedef struct {
	unsigned long attribute;
	short   x0, y0;
	short   x1, y1;
	unsigned char r, g, b;
}       GsLINE;

typedef struct {
	unsigned long attribute;
	short   x0, y0;
	short   x1, y1;
	unsigned char r0, g0, b0;
	unsigned char r1, g1, b1;
}       GsGLINE;

typedef struct {
	unsigned long attribute;
	short   x, y;
	unsigned short w, h;
	unsigned char r, g, b;
}       GsBOXF;

typedef struct {
	short   dqa;
	long    dqb;
	unsigned char rfc, gfc, bfc;
}       GsFOGPARAM;


typedef struct {
	unsigned long pmode;
	short   px, py;
	unsigned short pw, ph;
	unsigned long *pixel;
	short   cx, cy;
	unsigned short cw, ch;
	unsigned long *clut;
}       GsIMAGE;

typedef struct {
	short   offx, offy;
}       _GsPOSITION;

typedef struct {
	GsDOBJ2 *top;
	int     nobj;
	int     maxobj;
}       GsOBJTABLE2;

typedef struct {
	PACKET
	* (*f3[2][3]) ();
	PACKET
	* (*nf3[2]) ();
	PACKET
	* (*g3[2][3]) ();
	PACKET
	* (*ng3[2]) ();
	PACKET
	* (*tf3[2][3]) ();
	PACKET
	* (*ntf3[2]) ();
	PACKET
	* (*tg3[2][3]) ();
	PACKET
	* (*ntg3[2]) ();
	PACKET
	* (*f4[2][3]) ();
	PACKET
	* (*nf4[2]) ();
	PACKET
	* (*g4[2][3]) ();
	PACKET
	* (*ng4[2]) ();
	PACKET
	* (*tf4[2][3]) ();
	PACKET
	* (*ntf4[2]) ();
	PACKET
	* (*tg4[2][3]) ();
	PACKET
	* (*ntg4[2]) ();
	PACKET
	* (*f3g[3])();
	PACKET
	* (*g3g[3])();
	PACKET
	* (*f4g[3])();
	PACKET
	* (*g4g[3])();
}       _GsFCALL;


#define GsDivMODE_NDIV 0
#define GsDivMODE_DIV  1
#define GsLMODE_NORMAL 0
#define GsLMODE_FOG    1
#define GsLMODE_LOFF   2

/*
 * libgs macro 
 */
#define GsOFSGTE 0
#define GsOFSGPU 4
#define GsINTER  1
#define GsNONINTER 0
#define GsRESET0 0
#define GsRESET3 (3<<4)

/*
 * object attribute set macro 
 */
#define GsLDIM0 0
#define GsLDIM1 1
#define GsLDIM2 2
#define GsLDIM3 3
#define GsLDIM4 4
#define GsLDIM5 5
#define GsLDIM6 6
#define GsLDIM7 7
#define GsFOG   (1<<3)
#define GsMATE  (1<<4)
#define GsLLMOD (1<<5)
#define GsLOFF  (1<<6)
#define GsZIGNR (1<<7)
#define GsNBACKC (1<<8)
#define GsDIV1   (1<<9)
#define GsDIV2   (2<<9)
#define GsDIV3   (3<<9)
#define GsDIV4	 (4<<9)
#define GsDIV5	 (5<<9)
#define GsAZERO  (0<<28)
#define GsAONE   (1<<28)
#define GsATWO   (2<<28)
#define GsATHREE (3<<28)
#define GsALON   (1<<30)
#define GsDOFF   (1<<31)
/*
 * BG/sprite attribute set macro 
 */
#define GsPERS   (1<<26)
#define GsROTOFF (1<<27)

#define GsIncFrame()  (PSDCNT++, PSDCNT= PSDCNT?PSDCNT:1, \
                      (PSDIDX= (PSDIDX==0?1:0)))

#define GsUpdateCoord()  (PSDCNT++, PSDCNT= PSDCNT?PSDCNT:1)

#define GsSetAzwh(z,w,h)    GsADIVZ = (z),GsADIVW = (w),GsADIVH = (h);

#define GsTMDFlagGRD	0x04

/*
 * FLIP macro for GsSort[Fast]SpriteB
 */
#define GsHFLIP		0x01
#define GsVFLIP		0x02

/*
 * TMD structure 
 */
/*** GTE PACKET to-GPU command '<packet-name>.code' ***/
#define GPU_COM_F3    0x20
#define GPU_COM_TF3   0x24
#define GPU_COM_G3    0x30
#define GPU_COM_TG3   0x34

#define GPU_COM_F4    0x28
#define GPU_COM_TF4   0x2c
#define GPU_COM_G4    0x38
#define GPU_COM_TG4   0x3c

#define GPU_COM_NF3   0x21
#define GPU_COM_NTF3  0x25
#define GPU_COM_NG3   0x31
#define GPU_COM_NTG3  0x35

#define GPU_COM_NF4   0x29
#define GPU_COM_NTF4  0x2d
#define GPU_COM_NG4   0x39
#define GPU_COM_NTG4  0x3d


/*** TMD structure ****/
typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short n0, v0;
	u_short v1, v2;
}       TMD_P_F3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
}       TMD_P_G3;

typedef struct {
	u_char	out, in, dummy, cd;
	u_char	r0, g0, b0, code;
	u_char	r1, g1, b1, dummy1;
	u_char	r2, g2, b2, dummy2;
	u_short n0, v0;
	u_short v1, v2;
}       TMD_P_F3G;

typedef struct {
	u_char	out, in, dummy, cd;
	u_char	r0, g0, b0, code;
	u_char	r1, g1, b1, dummy1;
	u_char	r2, g2, b2, dummy2;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
}       TMD_P_G3G;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short v0, v1;
	u_short v2, p;
}       TMD_P_NF3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_char  r1, g1, b1, p1;
	u_char  r2, g2, b2, p2;
	u_short v0, v1;
	u_short v2, p;
}       TMD_P_NG3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short n0, v0;
	u_short v1, v2;
	u_short v3, p;
}       TMD_P_F4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
	u_short n3, v3;
}       TMD_P_G4;

typedef struct {
	u_char	out, in, dummy, cd;
	u_char	r0, g0, b0, code;
	u_char	r1, g1, b1, dummy1;
	u_char	r2, g2, b2, dummy2;
	u_char	r3, g3, b3, dummy3;
	u_short n0, v0;
	u_short v1, v2;
	u_short v3, dummy4;
}       TMD_P_F4G;

typedef struct {
	u_char	out, in, dummy, cd;
	u_char	r0, g0, b0, code;
	u_char	r1, g1, b1, dummy1;
	u_char	r2, g2, b2, dummy2;
	u_char	r3, g3, b3, dummy3;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
	u_short n3, v3;
}       TMD_P_G4G;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_short v0, v1;
	u_short v2, v3;
}       TMD_P_NF4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  r0, g0, b0, code;
	u_char  r1, g1, b1, p1;
	u_char  r2, g2, b2, p2;
	u_char  r3, g3, b3, p3;
	u_short v0, v1;
	u_short v2, v3;
}       TMD_P_NG4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p;
	u_short n0, v0;
	u_short v1, v2;
}       TMD_P_TF3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
}       TMD_P_TG3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  r0, g0, b0, p1;
	u_short v0, v1;
	u_short v2, p2;
}       TMD_P_TNF3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  r0, g0, b0, p1;
	u_char  r1, g1, b1, p2;
	u_char  r2, g2, b2, p3;
	u_short v0, v1;
	u_short v2, p4;
}       TMD_P_TNG3;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  tu3, tv3;
	u_short p1;
	u_short n0, v0;
	u_short v1, v2;
	u_short v3, p2;
}       TMD_P_TF4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  tu3, tv3;
	u_short p1;
	u_short n0, v0;
	u_short n1, v1;
	u_short n2, v2;
	u_short n3, v3;
}       TMD_P_TG4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  tu3, tv3;
	u_short p1;
	u_char  r0, g0, b0, p2;
	u_short v0, v1;
	u_short v2, v3;
}       TMD_P_TNF4;

typedef struct {
	u_char  out, in, dummy, cd;
	u_char  tu0, tv0;
	u_short clut;
	u_char  tu1, tv1;
	u_short tpage;
	u_char  tu2, tv2;
	u_short p0;
	u_char  tu3, tv3;
	u_short p1;
	u_char  r0, g0, b0, p2;
	u_char  r1, g1, b1, p3;
	u_char  r2, g2, b2, p4;
	u_char  r3, g3, b3, p5;
	u_short v0, v1;
	u_short v2, v3;
}       TMD_P_TNG4;

struct TMD_STRUCT {
	u_long *vertop;         /* vertex top address of TMD format */
	u_long  vern;           /* the number of vertex of TMD format */
	u_long *nortop;         /* normal top address of TMD format */
	u_long  norn;           /* the number of normal of TMD format */
	u_long *primtop;        /* primitive top address of TMD format */
	u_long  primn;          /* the number of primitives of TMD format */
	u_long  scale;          /* the scale factor of TMD format */
};

/*
 * active sub divide structure 
 *
 */

#define minmax4(x1,x2,x3,x4,x5,x6) x1>x2?(x6=x1,x5=x2):(x5=x1,x6=x2),\
                                   x3>x6?x6=x3:x3<x5?x5=x3:0,\
                                   x4>x6?x6=x4:x4<x5?x5=x4:0

#define minmax3(x1,x2,x3,x4,x5)    x1>x2?(x5=x1,x4=x2):(x4=x1,x5=x2),\
                                   x3>x5?x5=x3:x3<x4?x4=x3:0


typedef struct {
	short   vx, vy, vz;
	u_char  tu, tv;
}       VERT;

typedef struct {
	short   vx, vy, vz;
	u_char  tu, tv;
	CVECTOR col;
}       VERTC;


typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg0;		/* gte flag */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_FT4 si;		/* work packet */
}       GsADIV_FT4;

typedef struct {
	VERT    vt[4];
}       GsADIV_P_FT4;



typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg0;		/* gte flag */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_GT4 si;		/* work packet */
}       GsADIV_GT4;

typedef struct {
	VERTC   vt[4];
}       GsADIV_P_GT4;


typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg0;		/* gte flag */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_G4 si;		/* work packet */
}       GsADIV_G4;

typedef struct {
	VERTC   vt[4];
}       GsADIV_P_G4;

typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg0;		/* gte flag */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_F4 si;		/* work packet */
}       GsADIV_F4;

typedef struct {
	VERT    vt[4];
}       GsADIV_P_F4;


typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_FT3 si;		/* work packet */
}       GsADIV_FT3;

typedef struct {
	VERT    vt[3];
}       GsADIV_P_FT3;

typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_GT3 si;		/* work packet */
}       GsADIV_GT3;

typedef struct {
	VERTC   vt[3];
}       GsADIV_P_GT3;

typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_G3 si;		/* work packet */
}       GsADIV_G3;

typedef struct {
	VERTC   vt[3];
}       GsADIV_P_G3;

typedef struct {
	u_long  limit;		/* divide limit */
	long    hwd, vwd;	/* dummy */
	int     shift;		/* OT shift */
	u_long *org;		/* OT org */
	u_long *pk;		/* packet base */
	long    otz;		/* gte otz */
	long    adivz;		/* active divide codition z */
	short   adivw, adivh;	/* active divide condition w,h */
	long    flg;		/* gte flag */
	short   minx, miny, maxx, maxy;	/* polygon min-max */
	short   hwd0, vwd0;	/* resolution of screen */
	u_long *tag;		/* work temprly for addPrim */
	POLY_F3 si;		/* work packet */
}       GsADIV_F3;

typedef struct {
	VERT    vt[3];
}       GsADIV_P_F3;

/*
 * for GsUNIT
 */
#define GsUNIT_TERM	0xffffffff	/* Primitive terminater */

#define GsUNIT_DIV1	(1<<24)		/*  2 x  2 divide */
#define GsUNIT_DIV2	(2<<24)		/*  4 x  4 divide */
#define GsUNIT_DIV3	(3<<24)		/*  8 x  8 divide */
#define GsUNIT_DIV4	(4<<24)		/* 16 x 16 divide */
#define GsUNIT_DIV5	(5<<24)		/* 32 x 32 divide */

#define GsMapJntAxesMIMe(p,q)		GsMapJntMIMe(p,q)
#define GsMapRstJntAxesMIMe(p,q)	GsMapRstJntMIMe(p,q)
#define GsMapJntRPYMIMe(p,q)		GsMapJntMIMe(p,q)
#define GsMapRstJntRPYMIMe(p,q)		GsMapRstJntMIMe(p,q)


typedef struct _GsCOORDUNIT {
	unsigned long		flg;
	MATRIX			matrix;
	MATRIX			workm;
	SVECTOR			rot;
	struct _GsCOORDUNIT	*super;
}	GsCOORDUNIT;

typedef struct {
	MATRIX  	view;
	GsCOORDUNIT	*super;
}       GsVIEWUNIT;

typedef struct {
	long    	vpx, vpy, vpz;
	long    	vrx, vry, vrz;
	long    	rz;
	GsCOORDUNIT 	*super;
}       GsRVIEWUNIT;

typedef struct {
	GsCOORDUNIT	*coord;	/* local dmatrix */
	unsigned long	*primtop;
}       GsUNIT;

typedef struct {
	unsigned long	type;
	unsigned long	*ptr;
}	GsTYPEUNIT;

typedef struct {
	unsigned long	*primp;
	GsOT 		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
}	GsARGUNIT;

typedef struct {
	DVECTOR		vec;
	short		otz;
	short		p;
}       GsWORKUNIT;

typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	unsigned long	*primtop;
	SVECTOR		*vertop;
	SVECTOR		*nortop;
}	GsARGUNIT_NORMAL;

typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	unsigned long	*primtop;
	SVECTOR		*vertop;
	GsWORKUNIT	*vertop2;
	SVECTOR		*nortop;
	SVECTOR		*nortop2;
}	GsARGUNIT_SHARED;
	
typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	unsigned long	*imagetop;
	unsigned long	*cluttop;
}	GsARGUNIT_IMAGE;

typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	GsCOORDUNIT	*coordtop;
	long		*mimepr;
	u_long		mimenum;
}	GsARGUNIT_JntMIMe;


typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	GsCOORDUNIT	*coordtop;
}	GsARGUNIT_RstJntMIMe;

typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
	long		*mimepr;
	u_long		mimenum;
}	GsARGUNIT_VNMIMe;

typedef struct {
	unsigned long	*primp;
	GsOT		*tagp;
	int		shift;
	int		offset;
	PACKET		*out_packetp;
}	GsARGUNIT_RstVNMIMe;
  
typedef struct
{
  unsigned long	*primp;
  GsOT		*tagp;
  int		shift;
  int		offset;
  PACKET	*out_packetp;
  long          header_size;
  unsigned long *htop;
  unsigned long *ctop;
  unsigned long *ptop;
} GsARGUNIT_ANIM;

typedef struct {
  short    idx;
  u_char   sid;
  u_char   pad;
} GsSEH;

typedef struct {
  u_long  rewrite_idx;
  u_short size,num;
  u_short ii;
  u_short aframe;
  u_char  sid;
  char  speed;
  u_short srcii;
  short   rframe;
  u_short tframe;
  u_short ci,ti;
  u_short start;
  u_char  start_sid;
  u_char  traveling;
} GsSEQ;

typedef struct {
	u_long		*mimepr;
	u_long		mimenum;
	u_short 	mimeid;
	unsigned	internal:1, mapped:1, r:14;
}	GsMIMePrimHeader;

/*
 * GsTYPEUNIT code macro
 *
 *
 *	31             24              16               8               0
 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	|       |       |I|C|S|B|B|L|F|D| | | | | |M|T|P|M|L|     |I|C|T|
 *	|DEV ID |CATEGOR|N|L|T|O|C|G|O|I| | | | | |I|I|S|I|M|CODE |I|O|M|
 *	|       |       |I|P|P|T|L|T|G|V| | | | | |M|L|T|P|D|     |P|L|E|
 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	|       |       |               |                               |
 *	|DEV ID |CATEGOR|     DRIVER    |           PRIMITIVE TYPE      |
 *
 *
 *	DEV ID
 *		DEV ID(Developper ID)
 *				0000: SCE Reserved
 *
 *	CATEGORY
 *		CATEGOR(Category) 
 *				0000: Polygon Driver
 *				0001: Shared Primitive Data
 *				0010: Image Data
 *				0011: Animation
 *
 *	DRIVER
 *		INI(init)	0: none
 *				1: need to initialize COORDINATE
 *		CLP(clip)	0: no clip
 *				1: clip
 *		STP(Semi-trans) 0: none
 *				1: semi transparency
 *		BOT(both-side)	0: one-side polygon
 *				1: both-side polygon
 *		BCL(back-clip)	0: back clip normal
 *				1: back clip negative
 *		LGT(light)	0: lighting
 *				1: no lighting
 *		FOG(fog)	0: fog off
 *				1: fog on
 *		DIV(divide)	0: no divide
 *				1: divide
 *
 *	PRIMITIVE TYPE
 *		MIM(MIMe)	0: with no Built-in MIMe
 *				1: with Built-in MIMe
 *		TIL(tile)	0: with no tile texture
 *				1: with tile texture
 *		PST(pre-set)	0: no preset
 *				1: preset
 *		MIP(mip-map)	0: no mip-map
 *				1: mip-map
 *		LMD(light-mode)	0: with normal
 *				1: with no normal
 *		CODE		000: line
 *				001: triangle
 *				010: quad
 *				011: strip mesh
 *				100: sprite
 *		IIP		0: flat
 *				1: gouraud
 *		COL(colored)	0: one color
 *				1: gradation
 *		TME		0: texture mapping OFF
 *				1: texture mapping ON
 */

#define	GsUF3		0x00000008	/* flat triangle */
#define	GsUFT3		0x00000009	/* texture flat triangle */
#define	GsUG3		0x0000000c	/* gour triangle */
#define	GsUGT3		0x0000000d	/* texture gour triangle */
#define	GsUF4		0x00000010	/* flat quad */
#define	GsUFT4		0x00000011	/* texture flat quad */
#define	GsUG4		0x00000014	/* gour quad */
#define	GsUGT4		0x00000015	/* texture gour quad */

#define	GsUFF3		0x00020008	/* fog flat triangle */
#define	GsUFFT3		0x00020009	/* fog texture flat triangle */
#define	GsUFG3		0x0002000c	/* fog gour triangle */
#define	GsUFGT3		0x0002000d	/* fog texture gour triangle */
#define	GsUFF4		0x00020010	/* fog flat quad */
#define	GsUFFT4		0x00020011	/* fog texture flat quad */
#define	GsUFG4		0x00020014	/* fog gour quad */
#define	GsUFGT4		0x00020015	/* fog texture gour quad */

#define GsUCF3		0x0000000a	/* colored flat triangle */
#define GsUCFT3		0x0000000b	/* colored texture flat triangle */
#define GsUCG3		0x0000000e	/* colored gour triangle */
#define GsUCGT3		0x0000000f	/* colored texture gour triangle */
#define GsUCF4		0x00000012	/* colored flat quad */
#define GsUCFT4		0x00000013	/* colored texture flat quad */
#define GsUCG4		0x00000016	/* colored gour quad */
#define GsUCGT4		0x00000017	/* colored texture gour quad */

#define	GsUNF3		0x00040048	/* nonLight flat triangle */
#define	GsUNFT3		0x00040049	/* nonLight texture flat triangle */
#define	GsUNG3		0x0004004c	/* nonLight gouraud triangle */
#define	GsUNGT3		0x0004004d	/* nonLight texture gouraud triangle */
#define	GsUNF4		0x00040050	/* nonLight flat quad */
#define	GsUNFT4		0x00040051	/* nonLight texture flat quad */
#define	GsUNG4		0x00040054	/* nonLight gouraud quad */
#define	GsUNGT4		0x00040055	/* nonLight texture gouraud quad */

#define	GsUDF3		0x00010008	/* div flat triangle */
#define	GsUDFT3		0x00010009	/* div texture flat triangle */
#define	GsUDG3		0x0001000c	/* div gour triangle */
#define	GsUDGT3		0x0001000d	/* div texture gour triangle */
#define	GsUDF4		0x00010010	/* div flat quad */
#define	GsUDFT4		0x00010011	/* div texture flat quad */
#define	GsUDG4		0x00010014	/* div gour quad */
#define	GsUDGT4		0x00010015	/* div texture gour quad */

#define	GsUDFF3		0x00030008	/* div fog flat triangle */
#define	GsUDFFT3	0x00030009	/* div fog texture flat triangle */
#define	GsUDFG3		0x0003000c	/* div fog gour triangle */
#define	GsUDFGT3	0x0003000d	/* div fog texture gour triangle */
#define	GsUDFF4		0x00030010	/* div fog flat quad */
#define	GsUDFFT4	0x00030011	/* div fog texture flat quad */
#define	GsUDFG4		0x00030014	/* div fog gour quad */
#define	GsUDFGT4	0x00030015	/* div fog texture gour quad */

#define	GsUDNF3		0x00050048	/* div nonLight flat triangle */
#define	GsUDNFT3	0x00050049	/* div nonLight texture flat triangle */
#define	GsUDNG3		0x0005004c	/* div nonLight gouraud triangle */
#define	GsUDNGT3	0x0005004d	/* div nonLight tex gouraud triangle */
#define	GsUDNF4		0x00050050	/* div nonLight flat quad */
#define	GsUDNFT4	0x00050051	/* div nonLight texture flat quad */
#define	GsUDNG4		0x00050054	/* div nonLight gouraud quad */
#define	GsUDNGT4	0x00050055	/* div nonLight tex gouraud quad */

#define	GsUSCAL		0x01000000	/* shared calculate vertex and normal */
#define	GsUSG3		0x0100000c	/* shared gour triangle */
#define	GsUSGT3		0x0100000d	/* shared texture gour triangle */
#define	GsUSG4		0x01000014	/* shared gour quad */
#define	GsUSGT4		0x01000015	/* shared texture gour quad */

#define	GsUSFG3		0x0102000c	/* shared fog gour triangle */
#define	GsUSFGT3	0x0102000d	/* shared fog texture gour triangle */
#define	GsUSFG4		0x01020014	/* shared fog gour quad */
#define	GsUSFGT4	0x01020015	/* shared fog texture gour quad */

#define	GsUSNF3		0x01040048	/* shared nonLight flat tri */
#define	GsUSNFT3	0x01040049	/* shared nonLight texture flat tri */
#define	GsUSNG3		0x0104004c	/* shared nonLight gour tri */
#define	GsUSNGT3	0x0104004d	/* shared nonLight texture gour tri */
#define	GsUSNF4		0x01040050	/* shared nonLight flat quad */
#define	GsUSNFT4	0x01040051	/* shared nonLight texture flat quad */
#define	GsUSNG4		0x01040054	/* shared nonLight gour quad */
#define	GsUSNGT4	0x01040055	/* shared nonLight texture gour quad */

#define	GsUMF3		0x00000018	/* mesh flat tri */
#define	GsUMFT3		0x00000019	/* mesh texture flat tri */
#define	GsUMG3		0x0000001c	/* mesh gour triangle */
#define	GsUMGT3		0x0000001d	/* mesh texture gour triangle */
#define	GsUMNF3		0x00040058	/* mesh nonLight flat tri */
#define	GsUMNFT3	0x00040059	/* mesh nonLight tex flat tri */
#define	GsUMNG3		0x0004005c	/* mesh nonLight gour triangle */
#define	GsUMNGT3	0x0004005d	/* mesh nonLight tex gour tri */

#define	GsUTFT3		0x00000209	/* tile texture flat triangle */
#define	GsUTGT3		0x0000020d	/* tile texture gour triangle */
#define	GsUTFT4		0x00000211	/* tile texture flat quad */
#define	GsUTGT4		0x00000215	/* tile texture gour quad */

#define	GsUPNF3		0x00040148	/* preset nonLight flat triangle */
#define	GsUPNFT3	0x00040149	/* preset nonLight tex flat triangle */
#define	GsUPNG3		0x0004014c	/* preset nonLight gouraud triangle */
#define	GsUPNGT3	0x0004014d	/* preset nonLight tex gour triangle */
#define	GsUPNF4		0x00040150	/* preset nonLight flat quad */
#define	GsUPNFT4	0x00040151	/* preset nonLight tex flat quad */
#define	GsUPNG4		0x00040154	/* preset nonLight gouraud quad */
#define	GsUPNGT4	0x00040155	/* preset nonLight tex gour quad */

#define GsUIMG0		0x02000000	/* image data with no-clut */
#define GsUIMG1		0x02000001	/* image data with clut */

#define GsVtxMIMe	0x04010020	/* Vertex-MIMe */
#define GsNrmMIMe	0x04010021	/* Normal-MIMe */
#define GsRstVtxMIMe	0x04010028	/* Reset-Vertex-MIMe */
#define GsRstNrmMIMe	0x04010029	/* Reset-Normal-MIMe */
#define GsJntAxesMIMe	0x04010010	/* Joint-Axes-MIMe */
#define GsRstJntAxesMIMe \
			0x04010018	/* Reset-Joint-Axes-MIMe */
#define GsJntRPYMIMe	0x04010011	/* Joint-RPY-MIMe */
#define GsRstJntRPYMIMe	0x04010019	/* Reset-Joint-RPY-MIMe */

/*
 * PROTOTYPE DIFINITIONS 
 */
#if defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
extern  "C" {
#endif

	void    GsInitGraph(unsigned short x, unsigned short y, unsigned short intmode,
		              unsigned short dith, unsigned short varmmode);
	void    GsInit3D(void);
	void    GsMapModelingData(unsigned long *p);

	void    GsSetProjection(long h);
	int     GsSetFlatLight(int id, GsF_LIGHT * lt);
	void    GsSetLightMode(int mode);
	void    GsSetFogParam(GsFOGPARAM * fogparm);
	void    GsSetAmbient(long r, long g, long b);
	void    GsDrawOt(GsOT * ot);
	void    GsSetWorkBase(PACKET * outpacketp);

	void    GsSortObject3(GsDOBJ3 * objp, GsOT * ot, int shift);
	void    GsSortObject4(GsDOBJ2 * objp, GsOT * ot, int shift, u_long * scratch);
	void    GsSortObject5(GsDOBJ5 * objp, GsOT * ot, int shift, u_long * scratch);
	void    GsSortObject5J(GsDOBJ5 * objp, GsOT * ot, int shift, u_long * scratch);

	void    GsSortSprite(GsSPRITE * sp, GsOT * ot, unsigned short pri);
	void    GsSortSpriteB(GsSPRITE * sp, GsOT * ot, unsigned short pri,
				unsigned short flip);
	void    GsSortFastSprite(GsSPRITE * sp, GsOT * ot, unsigned short pri);
	void    GsSortFastSpriteB(GsSPRITE * sp, GsOT * ot, unsigned short pri,
				unsigned short flip);
	void    GsSortFlipSprite(GsSPRITE * sp, GsOT * ot, unsigned short pri);
	void    GsInitFastSpriteArray(GsSPARRAY * sp, short n);
	void    GsSetFastSpriteArray(GsSPARRAY * sp, unsigned short w, unsigned short h,
	             unsigned short tpage, unsigned char u, unsigned char v,
			               unsigned short cx, unsigned short cy,
		         unsigned char r, unsigned char g, unsigned char b);
	void    GsSortFastSpriteArray(GsSPARRAY * sp, unsigned short n,
				              GsOT * ot, unsigned short pri);
	void    GsSortBg(GsBG * bg, GsOT * ot, unsigned short pri);
	void    GsSortFastBg(GsBG * bg, GsOT * ot, unsigned short pri);
	void    GsInitFixBg16(GsBG * bg, u_long * work);
	void    GsSortFixBg16(GsBG * bg, u_long * work, GsOT * otp, unsigned short pri);
	void    GsInitFixBg32(GsBG * bg, u_long * work);
	void    GsSortFixBg32(GsBG * bg, u_long * work, GsOT * otp, unsigned short pri);
	void    GsSortLine(GsLINE * lp, GsOT * ot, unsigned short pri);
	void    GsSortGLine(GsGLINE * lp, GsOT * ot, unsigned short pri);
	void    GsSortBoxFill(GsBOXF * bp, GsOT * ot, unsigned short pri);
	void    GsSortPoly(void *pp, GsOT * ot, unsigned short pri);

	void    GsClearOt(unsigned short offset, unsigned short point, GsOT * otp);
	GsOT   *GsSortOt(GsOT * ot_src, GsOT * ot_dest);
	GsOT   *GsCutOt(GsOT * ot_src, GsOT * ot_dest);
	void    GsDefDispBuff(unsigned short x0, unsigned short y0, unsigned short x1, unsigned short y1);
	void    GsSortClear(unsigned char, unsigned char, unsigned char, GsOT *);
	void    GsGetTimInfo(unsigned long *im, GsIMAGE * tim);
	void    GsSwapDispBuff(void);
	int     GsGetActiveBuff(void);
	void    GsSetDrawBuffClip(void);
	void    GsSetDrawBuffOffset(void);
	void    GsSetClip(RECT * clip);
	DRAWENV *GsSetClip2(RECT * clip);
	void    GsSetOffset(long x, long y);
	void    GsSetOrign(long x, long y);

	void    GsInitCoordinate2(GsCOORDINATE2 * super, GsCOORDINATE2 * base);
	void    GsMulCoord0(MATRIX * m1, MATRIX * m2, MATRIX * m3);
	void    GsMulCoord2(MATRIX * m1, MATRIX * m2);
	void    GsMulCoord3(MATRIX * m1, MATRIX * m2);
	void    GsGetLw(GsCOORDINATE2 * m, MATRIX * out);
	void    GsGetLs(GsCOORDINATE2 * m, MATRIX * out);
	void    GsGetLws(GsCOORDINATE2 * m, MATRIX * outw, MATRIX * outs);

	u_long  GsLinkObject3(unsigned long pmd_base, GsDOBJ3 * objp);
	void    GsLinkObject4(unsigned long tmd_base, GsDOBJ2 * objp, int n);
	void    GsLinkObject5(unsigned long tmd_base, GsDOBJ5 * objp, int n);

	void    GsSetLightMatrix(MATRIX * mp);
	void    GsSetLightMatrix2(MATRIX * mp);
	int     GsSetRefView2(GsRVIEW2 * pv);
	int     GsSetRefView2L(GsRVIEW2 * pv);
	int     GsSetView2(GsVIEW2 * pv);
	void    GsSetLsMatrix(MATRIX * mp);
	void    GsSetClip2D(RECT * rectp);
	void    GsInitVcount();
	long    GsGetVcount();
	void    GsClearVcount();
	void	GsDefDispBuff2(u_short x0, u_short y0, u_short x1, u_short y1);
	void	GsDrawOtIO(GsOT *ot);
	PACKET *GsGetWorkBase();
	void	GsInitGraph2( u_short x, u_short y, u_short intmode, u_short dith, u_short vrammode);
	void	GsSortObject4J(GsDOBJ2 *objp, GsOT *otp, int shift, u_long *scratch);
	void	GsInitFastSprite2(GsSPARRAY *sp, u_short pri, short w, short h, u_short tpage, u_short cba, u_char u, u_char v, u_char r, u_char g, u_char b);
	void	GsSortFastSprite2(GsSPARRAY *sp, u_short n, GsOT *otp, u_short pri);
	void    GsClearDispArea(unsigned char r, unsigned char g, unsigned char b);

	u_long *GsPresetObject(GsDOBJ5 * objp, u_long * base_addr);
	void    GsScaleScreen(SVECTOR * scale);

	PACKET *GsA4divF3L(TMD_P_F3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divF3LFG(TMD_P_F3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divF3NL(TMD_P_F3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNF3(TMD_P_NF3 * op, VERT * vp, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divF4L(TMD_P_F4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divF4LFG(TMD_P_F4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divF4NL(TMD_P_F4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNF4(TMD_P_NF4 * op, VERT * vp, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG3L(TMD_P_G3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG3LFG(TMD_P_G3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG3NL(TMD_P_G3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNG3(TMD_P_NG3 * op, VERT * vp, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG4L(TMD_P_G4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG4LFG(TMD_P_G4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divG4NL(TMD_P_G4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNG4(TMD_P_NG4 * op, VERT * vp, PACKET * pk, int n,
			           int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT3L(TMD_P_TF3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT3LFG(TMD_P_TF3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT3NL(TMD_P_TF3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNTF3(TMD_P_TNF3 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4L(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4LFG(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4NL(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNTF4(TMD_P_TNF4 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4LM(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4LFGM(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divFT4NLM(TMD_P_TF4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNTF4M(TMD_P_TNF4 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG3L(TMD_P_TG3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG3LGG(TMD_P_TG3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG3NL(TMD_P_TG3 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divNTG3(TMD_P_TNG3 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4L(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4LFG(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4NL(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTNG4(TMD_P_TNG4 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4LM(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4LFGM(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTG4NLM(TMD_P_TG4 * op, VERT * vp, VERT * np, PACKET * pk, int n,
			             int shift, GsOT * ot, u_long * scratch);
	PACKET *GsA4divTNG4M(TMD_P_TNG4 * op, VERT * vp, PACKET * pk, int n,
			            int shift, GsOT * ot, u_long * scratch);
	PACKET *GsTMDfastF3GL(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF3GLFG(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF3GNL(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG3GL(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG3GLFG(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG3GNL(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstF3GL(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstF3GLFG(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstF3GNL(TMD_P_F3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstG3GL(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstG3GLFG(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsPrstG3GNL(TMD_P_G3G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG3M(TMD_P_G3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG3MFG(TMD_P_G3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTG3M(TMD_P_TG3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTG3MFG(TMD_P_TG3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF4GL(TMD_P_F4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF4GLFG(TMD_P_F4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF4GNL(TMD_P_F4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG4GL(TMD_P_G4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG4GLFG(TMD_P_G4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG4GNL(TMD_P_G4G *op, VERT *vp, VERT *np, PACKET *pk,
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG4M(TMD_P_G4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastG4MFG(TMD_P_G4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTG4M(TMD_P_TG4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTG4MFG(TMD_P_TG4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF3M(TMD_P_F3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF3MFG(TMD_P_F3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTF3M(TMD_P_TF3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTF3MFG(TMD_P_TF3 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF4M(TMD_P_F4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastF4MFG(TMD_P_F4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTF4M(TMD_P_TF4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);
	PACKET *GsTMDfastTF4MFG(TMD_P_TF4 *op, VERT *vp, VERT *np, PACKET *pk, 
						int n, int shift, GsOT *ot, u_long *scratch);

	/*
	 * prototype for GsUNIT
	 */
	extern u_long *GsU_00000008(GsARGUNIT *);
	extern u_long *GsU_00000009(GsARGUNIT *);
	extern u_long *GsU_0000000c(GsARGUNIT *);
	extern u_long *GsU_0000000d(GsARGUNIT *);
	extern u_long *GsU_00000010(GsARGUNIT *);
	extern u_long *GsU_00000011(GsARGUNIT *);
	extern u_long *GsU_00000014(GsARGUNIT *);
	extern u_long *GsU_00000015(GsARGUNIT *);
	extern u_long *GsU_00020008(GsARGUNIT *);
	extern u_long *GsU_00020009(GsARGUNIT *);
	extern u_long *GsU_0002000c(GsARGUNIT *);
	extern u_long *GsU_0002000d(GsARGUNIT *);
	extern u_long *GsU_00020010(GsARGUNIT *);
	extern u_long *GsU_00020011(GsARGUNIT *);
	extern u_long *GsU_00020014(GsARGUNIT *);
	extern u_long *GsU_00020015(GsARGUNIT *);
	extern u_long *GsU_0000000a(GsARGUNIT *);
	extern u_long *GsU_0000000b(GsARGUNIT *);
	extern u_long *GsU_0000000e(GsARGUNIT *);
	extern u_long *GsU_0000000f(GsARGUNIT *);
	extern u_long *GsU_00000012(GsARGUNIT *);
	extern u_long *GsU_00000013(GsARGUNIT *);
	extern u_long *GsU_00000016(GsARGUNIT *);
	extern u_long *GsU_00000017(GsARGUNIT *);
	extern u_long *GsU_00030008(GsARGUNIT *);
	extern u_long *GsU_00030009(GsARGUNIT *);
	extern u_long *GsU_0003000c(GsARGUNIT *);
	extern u_long *GsU_0003000d(GsARGUNIT *);
	extern u_long *GsU_00030010(GsARGUNIT *);
	extern u_long *GsU_00030011(GsARGUNIT *);
	extern u_long *GsU_00030014(GsARGUNIT *);
	extern u_long *GsU_00030015(GsARGUNIT *);
	extern u_long *GsU_00040048(GsARGUNIT *);
	extern u_long *GsU_00040049(GsARGUNIT *);
	extern u_long *GsU_0004004c(GsARGUNIT *);
	extern u_long *GsU_0004004d(GsARGUNIT *);
	extern u_long *GsU_00040050(GsARGUNIT *);
	extern u_long *GsU_00040051(GsARGUNIT *);
	extern u_long *GsU_00040054(GsARGUNIT *);
	extern u_long *GsU_00040055(GsARGUNIT *);
	extern u_long *GsU_00010008(GsARGUNIT *);
	extern u_long *GsU_00010009(GsARGUNIT *);
	extern u_long *GsU_0001000c(GsARGUNIT *);
	extern u_long *GsU_0001000d(GsARGUNIT *);
	extern u_long *GsU_00010010(GsARGUNIT *);
	extern u_long *GsU_00010011(GsARGUNIT *);
	extern u_long *GsU_00010014(GsARGUNIT *);
	extern u_long *GsU_00010015(GsARGUNIT *);
	extern u_long *GsU_00050048(GsARGUNIT *);
	extern u_long *GsU_00050049(GsARGUNIT *);
	extern u_long *GsU_0005004c(GsARGUNIT *);
	extern u_long *GsU_0005004d(GsARGUNIT *);
	extern u_long *GsU_00050050(GsARGUNIT *);
	extern u_long *GsU_00050051(GsARGUNIT *);
	extern u_long *GsU_00050054(GsARGUNIT *);
	extern u_long *GsU_00050055(GsARGUNIT *);
	extern u_long *GsU_00040058(GsARGUNIT *);
	extern u_long *GsU_00040059(GsARGUNIT *);
	extern u_long *GsU_0004005c(GsARGUNIT *);
	extern u_long *GsU_0004005d(GsARGUNIT *);
	extern u_long *GsU_01000000(GsARGUNIT *);
	extern u_long *GsU_0100000c(GsARGUNIT *);
	extern u_long *GsU_0100000d(GsARGUNIT *);
	extern u_long *GsU_01000014(GsARGUNIT *);
	extern u_long *GsU_01000015(GsARGUNIT *);
	extern u_long *GsU_0102000c(GsARGUNIT *);
	extern u_long *GsU_0102000d(GsARGUNIT *);
	extern u_long *GsU_01020014(GsARGUNIT *);
	extern u_long *GsU_01020015(GsARGUNIT *);
	extern u_long *GsU_01040048(GsARGUNIT *);
	extern u_long *GsU_01040049(GsARGUNIT *);
	extern u_long *GsU_0104004c(GsARGUNIT *);
	extern u_long *GsU_0104004d(GsARGUNIT *);
	extern u_long *GsU_01040050(GsARGUNIT *);
	extern u_long *GsU_01040051(GsARGUNIT *);
	extern u_long *GsU_01040054(GsARGUNIT *);
	extern u_long *GsU_01040055(GsARGUNIT *);
	extern u_long *GsU_00000018(GsARGUNIT *);
	extern u_long *GsU_00000019(GsARGUNIT *);
	extern u_long *GsU_0000001c(GsARGUNIT *);
	extern u_long *GsU_0000001d(GsARGUNIT *);
	extern u_long *GsU_00000209(GsARGUNIT *);
	extern u_long *GsU_0000020d(GsARGUNIT *);
	extern u_long *GsU_00000211(GsARGUNIT *);
	extern u_long *GsU_00000215(GsARGUNIT *);
	extern u_long *GsU_02000000(GsARGUNIT *);
	extern u_long *GsU_02000001(GsARGUNIT *);
	extern u_long *GsU_00040148(GsARGUNIT *);
	extern u_long *GsU_00040149(GsARGUNIT *);
	extern u_long *GsU_0004014c(GsARGUNIT *);
	extern u_long *GsU_0004014d(GsARGUNIT *);
	extern u_long *GsU_00040150(GsARGUNIT *);
	extern u_long *GsU_00040151(GsARGUNIT *);
	extern u_long *GsU_00040154(GsARGUNIT *);
	extern u_long *GsU_00040155(GsARGUNIT *);
	extern u_long *GsU_00000000(GsARGUNIT *);
	
	/* update driver */
	extern u_long *GsU_03000000(GsARGUNIT_ANIM *);
	
	/* hokan driver */
	extern void GsU_03000010(GsARGUNIT_ANIM *);	
	extern void GsU_03000001(GsARGUNIT_ANIM *);
	extern void GsU_03000009(GsARGUNIT_ANIM *);
	extern void GsU_03000909(GsARGUNIT_ANIM *);
	extern void GsU_03000100(GsARGUNIT_ANIM *);
	extern void GsU_03000910(GsARGUNIT_ANIM *);
	extern void GsU_03000011(GsARGUNIT_ANIM *);
	extern void GsU_03000911(GsARGUNIT_ANIM *);
	extern void GsU_03000111(GsARGUNIT_ANIM *);
	extern void GsU_03000019(GsARGUNIT_ANIM *);
	extern void GsU_03000119(GsARGUNIT_ANIM *);

	/* MIMe driver */
	extern u_long *GsU_04010020(GsARGUNIT *);
	extern u_long *GsU_04010028(GsARGUNIT *);
	extern u_long *GsU_04010010(GsARGUNIT *);
	extern u_long *GsU_04010018(GsARGUNIT *);
	extern u_long *GsU_04010011(GsARGUNIT *);
	extern u_long *GsU_04010019(GsARGUNIT *);
#define GsU_04010021 GsU_04010020
#define GsU_04010029 GsU_04010028

	extern GsCOORDUNIT *GsMapCoordUnit(u_long *, u_long *);
	extern u_long *GsGetHeadpUnit(void);
	extern int GsScanUnit(u_long *, GsTYPEUNIT *, GsOT *, u_long *);
	extern void GsMapUnit(u_long *);
	extern void GsSortUnit(GsUNIT *, GsOT *, u_long *);
	extern void GsGetLwUnit(GsCOORDUNIT *, MATRIX *);
	extern void GsGetLsUnit(GsCOORDUNIT *, MATRIX *);
	extern void GsGetLwsUnit(GsCOORDUNIT *, MATRIX *, MATRIX *);
	extern int GsSetViewUnit(GsVIEWUNIT *);
	extern int GsSetRefViewUnit(GsRVIEWUNIT *);
	extern int GsSetRefViewLUnit(GsRVIEWUNIT *);
	extern u_long *GsScanAnim(u_long *,GsTYPEUNIT *);
	extern long GsLinkAnim(GsSEQ **,u_long *);

	/* for MIMe */
	extern GsMIMePrimHeader *GsMapJntMIMe(u_long *primtop, u_long *hp);
	extern GsMIMePrimHeader *GsMapNrmMIMe(u_long *primtop, u_long *hmd, 
			u_long *hp);
	extern GsMIMePrimHeader *GsMapVtxMIMe(u_long *primtop, u_long *hmd, 
			u_long *hp);
	extern u_long GsMapRstVtxMIMe(u_long *primtop, u_long *hp);
	extern u_long GsMapRstNrmMIMe(u_long *primtop, u_long *hp);
	extern u_long GsMapRstJntMIMe(u_long *primtop, u_long *hp);
#define GsMapJntAxesMIMe(p,q) GsMapJntMIMe(p,q)
#define GsMapRstJntAxesMIMe(p,q) GsMapRstJntMIMe(p,q)
#define GsMapJntRPYMIMe(p,q) GsMapJntMIMe(p,q)
#define GsMapRstJntRPYMIMe(p,q) GsMapRstJntMIMe(p,q)

#if defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
}
#endif



/* EXTERN */
extern RECT CLIP2;		/* clipping area */
extern short PSDBASEX[2], PSDBASEY[2];	/* double buffer base */
extern short PSDIDX;		/* double buffer index */
extern u_long PSDCNT;		/* frame counter for using matrix cache */
extern _GsPOSITION POSITION;	/* 2d offset */
extern DRAWENV GsDRAWENV;	/* DRAWENV of Gs */
extern DISPENV GsDISPENV;	/* DISPENV of Gs */
extern MATRIX GsLSMATRIX;	/* Local-Screen Matrix of Gs */
extern MATRIX GsWSMATRIX;	/* Current World-Screen Matrix of Gs */
extern MATRIX GsWSMATRIX_ORG;	/* Original World-Screen Matrix of Gs */
extern long HWD0, VWD0;		/* rezolution of Holyzontal and Vertical */
extern MATRIX GsLIGHTWSMATRIX;	/* World-Screen Light Matrix of Gs */
extern MATRIX GsIDMATRIX;	/* Unit Matrix */
extern MATRIX GsIDMATRIX2;	/* Unit Matrix including Aspect retio */
extern PACKET *GsOUT_PACKET_P;	/* Work Base pointer */
extern long GsADIVZ;		/* Active sub divide condition (z) */
extern short GsADIVW, GsADIVH;	/* Active sub divide condition (w,h) */
extern int GsLIGHT_MODE;	/* lighting mode global */
extern u_long GsMATE_C, GsLMODE, GsLIGNR, GsLIOFF, GsZOVER, GsBACKC, GsNDIV;
extern u_long GsTRATE, GsTON, GsDISPON;


#if 0
extern _GsFCALL GsFCALL5;	/* GsSortObject5J Func Table */
/* hook only functions to use */
jt_init5()
{				/* GsSortObject5J Hook Func */
	PACKET *GsPrstF3NL(), *GsPrstF3LFG(), *GsPrstF3L(), *GsPrstNF3();
	PACKET *GsTMDdivF3NL(), *GsTMDdivF3LFG(), *GsTMDdivF3L(), *GsTMDdivNF3();
	PACKET *GsPrstG3NL(), *GsPrstG3LFG(), *GsPrstG3L(), *GsPrstNG3();
	PACKET *GsTMDdivG3NL(), *GsTMDdivG3LFG(), *GsTMDdivG3L(), *GsTMDdivNG3();
	PACKET *GsPrstTF3NL(), *GsPrstTF3LFG(), *GsPrstTF3L(), *GsPrstTNF3();
	PACKET *GsTMDdivTF3NL(), *GsTMDdivTF3LFG(), *GsTMDdivTF3L(),*GsTMDdivTNF3();
	PACKET *GsPrstTG3NL(), *GsPrstTG3LFG(), *GsPrstTG3L(), *GsPrstTNG3();
	PACKET *GsTMDdivTG3NL(), *GsTMDdivTG3LFG(), *GsTMDdivTG3L(),*GsTMDdivTNG3();
	PACKET *GsPrstF4NL(), *GsPrstF4LFG(), *GsPrstF4L(), *GsPrstNF4();
	PACKET *GsTMDdivF4NL(), *GsTMDdivF4LFG(), *GsTMDdivF4L(), *GsTMDdivNF4();
	PACKET *GsPrstG4NL(), *GsPrstG4LFG(), *GsPrstG4L(), *GsPrstNG4();
	PACKET *GsTMDdivG4NL(), *GsTMDdivG4LFG(), *GsTMDdivG4L(), *GsTMDdivNG4();
	PACKET *GsPrstTF4NL(), *GsPrstTF4LFG(), *GsPrstTF4L(), *GsPrstTNF4();
	PACKET *GsTMDdivTF4NL(), *GsTMDdivTF4LFG(), *GsTMDdivTF4L(),*GsTMDdivTNF4();
	PACKET *GsPrstTG4NL(), *GsPrstTG4LFG(), *GsPrstTG4L(), *GsPrstTNG4();
	PACKET *GsTMDdivTG4NL(), *GsTMDdivTG4LFG(), *GsTMDdivTG4L(),*GsTMDdivTNG4();
	PACKET *GsPrstF3GNL(), *GsPrstF3GLFG(), *GsPrstF3GL();
	PACKET *GsPrstG3GNL(), *GsPrstG3GLFG(), *GsPrstG3GL();

	/* flat triangle */
	GsFCALL5.f3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstF3L;
	GsFCALL5.f3[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstF3LFG;
	GsFCALL5.f3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstF3NL;
	GsFCALL5.f3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF3L;
	GsFCALL5.f3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF3LFG;
	GsFCALL5.f3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF3NL;
	GsFCALL5.nf3[GsDivMODE_NDIV] = GsPrstNF3;
	GsFCALL5.nf3[GsDivMODE_DIV] = GsTMDdivNF3;
	/* gour triangle */
	GsFCALL5.g3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstG3L;
	GsFCALL5.g3[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstG3LFG;
	GsFCALL5.g3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstG3NL;
	GsFCALL5.g3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG3L;
	GsFCALL5.g3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG3LFG;
	GsFCALL5.g3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG3NL;
	GsFCALL5.ng3[GsDivMODE_NDIV] = GsPrstNG3;
	GsFCALL5.ng3[GsDivMODE_DIV] = GsTMDdivNG3;
	/* texture flat triangle */
	GsFCALL5.tf3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstTF3L;
	GsFCALL5.tf3[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstTF3LFG;
	GsFCALL5.tf3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstTF3NL;
	GsFCALL5.tf3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF3L;
	GsFCALL5.tf3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF3LFG;
	GsFCALL5.tf3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF3NL;
	GsFCALL5.ntf3[GsDivMODE_NDIV] = GsPrstTNF3;
	GsFCALL5.ntf3[GsDivMODE_DIV] = GsTMDdivTNF3;
	/* texture gour triangle */
	GsFCALL5.tg3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstTG3L;
	GsFCALL5.tg3[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstTG3LFG;
	GsFCALL5.tg3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstTG3NL;
	GsFCALL5.tg3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG3L;
	GsFCALL5.tg3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG3LFG;
	GsFCALL5.tg3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG3NL;
	GsFCALL5.ntg3[GsDivMODE_NDIV] = GsPrstTNG3;
	GsFCALL5.ntg3[GsDivMODE_DIV] = GsTMDdivTNG3;
	/* flat quad */
	GsFCALL5.f4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstF4L;
	GsFCALL5.f4[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstF4LFG;
	GsFCALL5.f4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstF4NL;
	GsFCALL5.f4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF4L;
	GsFCALL5.f4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF4LFG;
	GsFCALL5.f4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF4NL;
	GsFCALL5.nf4[GsDivMODE_NDIV] = GsPrstNF4;
	GsFCALL5.nf4[GsDivMODE_DIV] = GsTMDdivNF4;
	/* gour quad */
	GsFCALL5.g4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstG4L;
	GsFCALL5.g4[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstG4LFG;
	GsFCALL5.g4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstG4NL;
	GsFCALL5.g4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG4L;
	GsFCALL5.g4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG4LFG;
	GsFCALL5.g4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG4NL;
	GsFCALL5.ng4[GsDivMODE_NDIV] = GsPrstNG4;
	GsFCALL5.ng4[GsDivMODE_DIV] = GsTMDdivNG4;
	/* texture flat quad */
	GsFCALL5.tf4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstTF4L;
	GsFCALL5.tf4[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstTF4LFG;
	GsFCALL5.tf4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstTF4NL;
	GsFCALL5.tf4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF4L;
	GsFCALL5.tf4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF4LFG;
	GsFCALL5.tf4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF4NL;
	GsFCALL5.ntf4[GsDivMODE_NDIV] = GsPrstTNF4;
	GsFCALL5.ntf4[GsDivMODE_DIV] = GsTMDdivTNF4;
	/* texture gour quad */
	GsFCALL5.tg4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsPrstTG4L;
	GsFCALL5.tg4[GsDivMODE_NDIV][GsLMODE_FOG] = GsPrstTG4LFG;
	GsFCALL5.tg4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsPrstTG4NL;
	GsFCALL5.tg4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG4L;
	GsFCALL5.tg4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG4LFG;
	GsFCALL5.tg4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG4NL;
	GsFCALL5.ntg4[GsDivMODE_NDIV] = GsPrstTNG4;
	GsFCALL5.ntg4[GsDivMODE_DIV] = GsTMDdivTNG4;
	/* gradation triangle */
	GsFCALL5.f3g[GsLMODE_NORMAL] = GsPrstF3GL;
	GsFCALL5.f3g[GsLMODE_FOG] = GsPrstF3GLFG;
	GsFCALL5.f3g[GsLMODE_LOFF] = GsPrstF3GNL;
	GsFCALL5.g3g[GsLMODE_NORMAL] = GsPrstG3GL;
	GsFCALL5.g3g[GsLMODE_FOG] = GsPrstG3GLFG;
	GsFCALL5.g3g[GsLMODE_LOFF] = GsPrstG3GNL;
}
#endif

#if 0
extern _GsFCALL GsFCALL4;	/* GsSortObject4J Func Table */
/* hook only functions to use*/
jt_init4()
{				/* GsSortObject4J Hook Func */
	PACKET *GsTMDfastF3NL(), *GsTMDfastF3LFG(), *GsTMDfastF3L(),*GsTMDfastNF3();
	PACKET *GsTMDdivF3NL(), *GsTMDdivF3LFG(), *GsTMDdivF3L(), *GsTMDdivNF3();
	PACKET *GsTMDfastG3NL(), *GsTMDfastG3LFG(), *GsTMDfastG3L(),*GsTMDfastNG3();
	PACKET *GsTMDdivG3NL(), *GsTMDdivG3LFG(), *GsTMDdivG3L(), *GsTMDdivNG3();
	PACKET *GsTMDfastTF3NL(), *GsTMDfastTF3LFG(), *GsTMDfastTF3L(), *GsTMDfastTNF3();
	PACKET *GsTMDdivTF3NL(), *GsTMDdivTF3LFG(), *GsTMDdivTF3L(), *GsTMDdivTNF3();
	PACKET *GsTMDfastTG3NL(), *GsTMDfastTG3LFG(), *GsTMDfastTG3L(), *GsTMDfastTNG3();
	PACKET *GsTMDdivTG3NL(), *GsTMDdivTG3LFG(), *GsTMDdivTG3L(), *GsTMDdivTNG3();
	PACKET *GsTMDfastF4NL(), *GsTMDfastF4LFG(), *GsTMDfastF4L(), *GsTMDfastNF4();
	PACKET *GsTMDdivF4NL(), *GsTMDdivF4LFG(), *GsTMDdivF4L(), *GsTMDdivNF4();
	PACKET *GsTMDfastG4NL(), *GsTMDfastG4LFG(), *GsTMDfastG4L(), *GsTMDfastNG4();
	PACKET *GsTMDdivG4NL(), *GsTMDdivG4LFG(), *GsTMDdivG4L(), *GsTMDdivNG4();
	PACKET *GsTMDfastTF4NL(), *GsTMDfastTF4LFG(), *GsTMDfastTF4L(), *GsTMDfastTNF4();
	PACKET *GsTMDdivTF4NL(), *GsTMDdivTF4LFG(), *GsTMDdivTF4L(), *GsTMDdivTNF4();
	PACKET *GsTMDfastTG4NL(), *GsTMDfastTG4LFG(), *GsTMDfastTG4L(), *GsTMDfastTNG4();
	PACKET *GsTMDdivTG4NL(), *GsTMDdivTG4LFG(), *GsTMDdivTG4L(), *GsTMDdivTNG4();

	/* flat triangle */
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF3L;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF3LFG;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF3NL;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF3L;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF3LFG;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF3NL;
	GsFCALL4.nf3[GsDivMODE_NDIV] = GsTMDfastNF3;
	GsFCALL4.nf3[GsDivMODE_DIV] = GsTMDdivNF3;
	/* gour triangle */
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG3L;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG3LFG;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG3NL;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG3L;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG3LFG;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG3NL;
	GsFCALL4.ng3[GsDivMODE_NDIV] = GsTMDfastNG3;
	GsFCALL4.ng3[GsDivMODE_DIV] = GsTMDdivNG3;
	/* texture flat triangle */
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF3L;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF3LFG;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF3NL;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF3L;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF3LFG;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF3NL;
	GsFCALL4.ntf3[GsDivMODE_NDIV] = GsTMDfastTNF3;
	GsFCALL4.ntf3[GsDivMODE_DIV] = GsTMDdivTNF3;
	/* texture gour triangle */
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG3L;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG3LFG;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG3NL;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG3L;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG3LFG;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG3NL;
	GsFCALL4.ntg3[GsDivMODE_NDIV] = GsTMDfastTNG3;
	GsFCALL4.ntg3[GsDivMODE_DIV] = GsTMDdivTNG3;
	/* flat quad */
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF4L;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF4LFG;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF4NL;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF4L;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF4LFG;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF4NL;
	GsFCALL4.nf4[GsDivMODE_NDIV] = GsTMDfastNF4;
	GsFCALL4.nf4[GsDivMODE_DIV] = GsTMDdivNF4;
	/* gour quad */
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG4L;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG4LFG;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG4NL;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG4L;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG4LFG;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG4NL;
	GsFCALL4.ng4[GsDivMODE_NDIV] = GsTMDfastNG4;
	GsFCALL4.ng4[GsDivMODE_DIV] = GsTMDdivNG4;
	/* texture flat quad */
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF4L;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF4LFG;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF4NL;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF4L;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF4LFG;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF4NL;
	GsFCALL4.ntf4[GsDivMODE_NDIV] = GsTMDfastTNF4;
	GsFCALL4.ntf4[GsDivMODE_DIV] = GsTMDdivTNF4;
	/* texture gour quad */
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG4L;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG4LFG;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG4NL;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG4L;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG4LFG;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG4NL;
	GsFCALL4.ntg4[GsDivMODE_NDIV] = GsTMDfastTNG4;
	GsFCALL4.ntg4[GsDivMODE_DIV] = GsTMDdivTNG4;
	/* gradation  triangle */
	GsFCALL4.f3g[GsLMODE_NORMAL] = GsTMDfastF3GL;
	GsFCALL4.f3g[GsLMODE_FOG] = GsTMDfastF3GLFG;
	GsFCALL4.f3g[GsLMODE_LOFF] = GsTMDfastF3GNL;
	GsFCALL4.g3g[GsLMODE_NORMAL] = GsTMDfastG3GL;
	GsFCALL4.g3g[GsLMODE_FOG] = GsTMDfastG3GLFG;
	GsFCALL4.g3g[GsLMODE_LOFF] = GsTMDfastG3GNL;
	/* gradation  quad */
	GsFCALL4.f4g[GsLMODE_NORMAL] = GsTMDfastF4GL;
	GsFCALL4.f4g[GsLMODE_FOG] = GsTMDfastF4GLFG;
	GsFCALL4.f4g[GsLMODE_LOFF] = GsTMDfastF4GNL;
	GsFCALL4.g4g[GsLMODE_NORMAL] = GsTMDfastG4GL;
	GsFCALL4.g4g[GsLMODE_FOG] = GsTMDfastG4GLFG;
	GsFCALL4.g4g[GsLMODE_LOFF] = GsTMDfastG4GNL;
}
#endif

#if 0
extern _GsFCALL GsFCALL4;	/* GsSortObject4J Func Table */
jt_init4()
{				/* Gs SortObject4J Active sub divide Func */
	PACKET *GsTMDfastF3NL(), *GsTMDfastF3LFG(), *GsTMDfastF3L(), *GsTMDfastNF3();
	PACKET *GsA4divF3NL(), *GsA4divF3LFG(), *GsA4divF3L(), *GsA4divNF3();
	PACKET *GsTMDfastG3NL(), *GsTMDfastG3LFG(), *GsTMDfastG3L(), *GsTMDfastNG3();
	PACKET *GsA4divG3NL(), *GsA4divG3LFG(), *GsA4divG3L(), *GsA4divNG3();
	PACKET *GsTMDfastTF3NL(), *GsTMDfastTF3LFG(), *GsTMDfastTF3L(), *GsTMDfastTNF3();
	PACKET *GsA4divTF3NL(), *GsA4divTF3LFG(), *GsA4divTF3L(), *GsA4divTNF3();
	PACKET *GsTMDfastTG3NL(), *GsTMDfastTG3LFG(), *GsTMDfastTG3L(), *GsTMDfastTNG3();
	PACKET *GsA4divTG3NL(), *GsA4divTG3LFG(), *GsA4divTG3L(), *GsA4divTNG3();
	PACKET *GsTMDfastF4NL(), *GsTMDfastF4LFG(), *GsTMDfastF4L(), *GsTMDfastNF4();
	PACKET *GsA4divF4NL(), *GsA4divF4LFG(), *GsA4divF4L(), *GsA4divNF4();
	PACKET *GsTMDfastG4NL(), *GsTMDfastG4LFG(), *GsTMDfastG4L(), *GsTMDfastNG4();
	PACKET *GsA4divG4NL(), *GsA4divG4LFG(), *GsA4divG4L(), *GsA4divNG4();
	PACKET *GsTMDfastTF4NL(), *GsTMDfastTF4LFG(), *GsTMDfastTF4L(), *GsTMDfastTNF4();
	PACKET *GsA4divTF4NL(), *GsA4divTF4LFG(), *GsA4divTF4L(), *GsA4divTNF4();
	PACKET *GsTMDfastTG4NL(), *GsTMDfastTG4LFG(), *GsTMDfastTG4L(), *GsTMDfastTNG4();
	PACKET *GsA4divTG4NL(), *GsA4divTG4LFG(), *GsA4divTG4L(), *GsA4divTNG4();
	PACKET *GsA4divTF4L();

	/* flat triangle */
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF3L;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF3LFG;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF3NL;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divF3L;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divF3LFG;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divF3NL;
	GsFCALL4.nf3[GsDivMODE_NDIV] = GsTMDfastNF3;
	GsFCALL4.nf3[GsDivMODE_DIV] = GsA4divNF3;
	/* gour triangle */
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG3L;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG3LFG;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG3NL;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divG3L;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divG3LFG;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divG3NL;
	GsFCALL4.ng3[GsDivMODE_NDIV] = GsTMDfastNG3;
	GsFCALL4.ng3[GsDivMODE_DIV] = GsA4divNG3;
	/* texture flat triangle */
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF3L;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF3LFG;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF3NL;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divTF3L;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divTF3LFG;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divTF3NL;
	GsFCALL4.ntf3[GsDivMODE_NDIV] = GsTMDfastTNF3;
	GsFCALL4.ntf3[GsDivMODE_DIV] = GsA4divTNF3;
	/* texture gour triangle */
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG3L;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG3LFG;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG3NL;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divTG3L;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divTG3LFG;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divTG3NL;
	GsFCALL4.ntg3[GsDivMODE_NDIV] = GsTMDfastTNG3;
	GsFCALL4.ntg3[GsDivMODE_DIV] = GsA4divTNG3;
	/* flat quad */
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF4L;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF4LFG;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF4NL;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divF4L;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divF4LFG;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divF4NL;
	GsFCALL4.nf4[GsDivMODE_NDIV] = GsTMDfastNF4;
	GsFCALL4.nf4[GsDivMODE_DIV] = GsA4divNF4;
	/* gour quad */
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG4L;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG4LFG;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG4NL;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divG4L;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divG4LFG;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divG4NL;
	GsFCALL4.ng4[GsDivMODE_NDIV] = GsTMDfastNG4;
	GsFCALL4.ng4[GsDivMODE_DIV] = GsA4divNG4;
	/* texture flat quad */
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF4L;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF4LFG;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF4NL;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divTF4L;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divTF4LFG;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divTF4NL;
	GsFCALL4.ntf4[GsDivMODE_NDIV] = GsTMDfastTNF4;
	GsFCALL4.ntf4[GsDivMODE_DIV] = GsA4divTNF4;
	/* texture gour quad */
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG4L;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG4LFG;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG4NL;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsA4divTG4L;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_FOG] = GsA4divTG4LFG;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_LOFF] = GsA4divTG4NL;
	GsFCALL4.ntg4[GsDivMODE_NDIV] = GsTMDfastTNG4;
	GsFCALL4.ntg4[GsDivMODE_DIV] = GsA4divTNG4;
	/* gradation triangle */
	GsFCALL4.f3g[GsLMODE_NORMAL] = GsTMDfastF3GL;
	GsFCALL4.f3g[GsLMODE_FOG] = GsTMDfastF3GLFG;
	GsFCALL4.f3g[GsLMODE_LOFF] = GsTMDfastF3GNL;
	GsFCALL4.g3g[GsLMODE_NORMAL] = GsTMDfastG3GL;
	GsFCALL4.g3g[GsLMODE_FOG] = GsTMDfastG3GLFG;
	GsFCALL4.g3g[GsLMODE_LOFF] = GsTMDfastG3GNL;
	/* gradation  quad */
	GsFCALL4.f4g[GsLMODE_NORMAL] = GsTMDfastF4GL;
	GsFCALL4.f4g[GsLMODE_FOG] = GsTMDfastF4GLFG;
	GsFCALL4.f4g[GsLMODE_LOFF] = GsTMDfastF4GNL;
	GsFCALL4.g4g[GsLMODE_NORMAL] = GsTMDfastG4GL;
	GsFCALL4.g4g[GsLMODE_FOG] = GsTMDfastG4GLFG;
	GsFCALL4.g4g[GsLMODE_LOFF] = GsTMDfastG4GNL;
}
#endif

#if 0
extern _GsFCALL GsFCALL4;	/* GsSortObject4J Func Table */
/* hook only functions to use */
jt_init4()
{				/* GsSortObject4J Hook Func (for material attenuation)*/
	PACKET *GsTMDfastF3NL(), *GsTMDfastF3MFG(), *GsTMDfastF3M(),*GsTMDfastNF3();
	PACKET *GsTMDdivF3NL(), *GsTMDdivF3LFG(), *GsTMDdivF3L(), *GsTMDdivNF3();
	PACKET *GsTMDfastG3NL(), *GsTMDfastG3MFG(), *GsTMDfastG3M(),*GsTMDfastNG3();
	PACKET *GsTMDdivG3NL(), *GsTMDdivG3LFG(), *GsTMDdivG3L(), *GsTMDdivNG3();
	PACKET *GsTMDfastTF3NL(), *GsTMDfastTF3MFG(), *GsTMDfastTF3M(), *GsTMDfastTNF3();
	PACKET *GsTMDdivTF3NL(), *GsTMDdivTF3LFG(), *GsTMDdivTF3L(), *GsTMDdivTNF3();
	PACKET *GsTMDfastTG3NL(), *GsTMDfastTG3MFG(), *GsTMDfastTG3M(), *GsTMDfastTNG3();
	PACKET *GsTMDdivTG3NL(), *GsTMDdivTG3LFG(), *GsTMDdivTG3L(), *GsTMDdivTNG3();
	PACKET *GsTMDfastF4NL(), *GsTMDfastF4MFG(), *GsTMDfastF4M(), *GsTMDfastNF4();
	PACKET *GsTMDdivF4NL(), *GsTMDdivF4LFG(), *GsTMDdivF4L(), *GsTMDdivNF4();
	PACKET *GsTMDfastG4NL(), *GsTMDfastG4MFG(), *GsTMDfastG4M(), *GsTMDfastNG4();
	PACKET *GsTMDdivG4NL(), *GsTMDdivG4LFG(), *GsTMDdivG4L(), *GsTMDdivNG4();
	PACKET *GsTMDfastTF4NL(), *GsTMDfastTF4MFG(), *GsTMDfastTF4M(), *GsTMDfastTNF4();
	PACKET *GsTMDdivTF4NL(), *GsTMDdivTF4LFG(), *GsTMDdivTF4L(), *GsTMDdivTNF4();
	PACKET *GsTMDfastTG4NL(), *GsTMDfastTG4MFG(), *GsTMDfastTG4M(), *GsTMDfastTNG4();
	PACKET *GsTMDdivTG4NL(), *GsTMDdivTG4LFG(), *GsTMDdivTG4L(), *GsTMDdivTNG4();

	/* flat triangle */
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF3M;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF3MFG;
	GsFCALL4.f3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF3NL;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF3L;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF3LFG;
	GsFCALL4.f3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF3NL;
	GsFCALL4.nf3[GsDivMODE_NDIV] = GsTMDfastNF3;
	GsFCALL4.nf3[GsDivMODE_DIV] = GsTMDdivNF3;
	/* gour triangle */
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG3M;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG3MFG;
	GsFCALL4.g3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG3NL;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG3L;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG3LFG;
	GsFCALL4.g3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG3NL;
	GsFCALL4.ng3[GsDivMODE_NDIV] = GsTMDfastNG3;
	GsFCALL4.ng3[GsDivMODE_DIV] = GsTMDdivNG3;
	/* texture flat triangle */
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF3M;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF3MFG;
	GsFCALL4.tf3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF3NL;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF3L;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF3LFG;
	GsFCALL4.tf3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF3NL;
	GsFCALL4.ntf3[GsDivMODE_NDIV] = GsTMDfastTNF3;
	GsFCALL4.ntf3[GsDivMODE_DIV] = GsTMDdivTNF3;
	/* texture gour triangle */
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG3M;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG3MFG;
	GsFCALL4.tg3[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG3NL;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG3L;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG3LFG;
	GsFCALL4.tg3[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG3NL;
	GsFCALL4.ntg3[GsDivMODE_NDIV] = GsTMDfastTNG3;
	GsFCALL4.ntg3[GsDivMODE_DIV] = GsTMDdivTNG3;
	/* flat quad */
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastF4M;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastF4MFG;
	GsFCALL4.f4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastF4NL;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivF4L;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivF4LFG;
	GsFCALL4.f4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivF4NL;
	GsFCALL4.nf4[GsDivMODE_NDIV] = GsTMDfastNF4;
	GsFCALL4.nf4[GsDivMODE_DIV] = GsTMDdivNF4;
	/* gour quad */
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastG4M;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastG4MFG;
	GsFCALL4.g4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastG4NL;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivG4L;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivG4LFG;
	GsFCALL4.g4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivG4NL;
	GsFCALL4.ng4[GsDivMODE_NDIV] = GsTMDfastNG4;
	GsFCALL4.ng4[GsDivMODE_DIV] = GsTMDdivNG4;
	/* texture flat quad */
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTF4M;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTF4MFG;
	GsFCALL4.tf4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTF4NL;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTF4L;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTF4LFG;
	GsFCALL4.tf4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTF4NL;
	GsFCALL4.ntf4[GsDivMODE_NDIV] = GsTMDfastTNF4;
	GsFCALL4.ntf4[GsDivMODE_DIV] = GsTMDdivTNF4;
	/* texture gour quad */
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_NORMAL] = GsTMDfastTG4M;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_FOG] = GsTMDfastTG4MFG;
	GsFCALL4.tg4[GsDivMODE_NDIV][GsLMODE_LOFF] = GsTMDfastTG4NL;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_NORMAL] = GsTMDdivTG4L;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_FOG] = GsTMDdivTG4LFG;
	GsFCALL4.tg4[GsDivMODE_DIV][GsLMODE_LOFF] = GsTMDdivTG4NL;
	GsFCALL4.ntg4[GsDivMODE_NDIV] = GsTMDfastTNG4;
	GsFCALL4.ntg4[GsDivMODE_DIV] = GsTMDdivTNG4;
	/* gradation  triangle */
	GsFCALL4.f3g[GsLMODE_NORMAL] = GsTMDfastF3GL;
	GsFCALL4.f3g[GsLMODE_FOG] = GsTMDfastF3GLFG;
	GsFCALL4.f3g[GsLMODE_LOFF] = GsTMDfastF3GNL;
	GsFCALL4.g3g[GsLMODE_NORMAL] = GsTMDfastG3GL;
	GsFCALL4.g3g[GsLMODE_FOG] = GsTMDfastG3GLFG;
	GsFCALL4.g3g[GsLMODE_LOFF] = GsTMDfastG3GNL;
	/* gradation  quad */
	GsFCALL4.f4g[GsLMODE_NORMAL] = GsTMDfastF4GL;
	GsFCALL4.f4g[GsLMODE_FOG] = GsTMDfastF4GLFG;
	GsFCALL4.f4g[GsLMODE_LOFF] = GsTMDfastF4GNL;
	GsFCALL4.g4g[GsLMODE_NORMAL] = GsTMDfastG4GL;
	GsFCALL4.g4g[GsLMODE_FOG] = GsTMDfastG4GLFG;
	GsFCALL4.g4g[GsLMODE_LOFF] = GsTMDfastG4GNL;
}
#endif

#endif				/* _LIBGS_H_ */
