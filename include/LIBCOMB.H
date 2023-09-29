/*
 * $PSLibId: Run-time Library Release 4.0$
 */
/*
 * File:libcomb.h
*/
#ifndef _LIBCOMB_H_
#define _LIBCOMB_H_

/* status bits */
#define COMB_CTS		0x100
#define COMB_DSR		0x80
#define COMB_FE			0x20
#define COMB_OE			0x10
#define COMB_PERROR		0x8
#define COMB_TXU		0x4
#define COMB_RXRDY		0x2
#define COMB_TXRDY		0x1


/* control bits */
#define COMB_BIT_DTR	0x1
#define COMB_BIT_RTS	0x2

/*
 * Prototypes
 */
#if defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
extern "C" {
#endif

extern void AddCOMB(void);
extern void DelCOMB(void);
extern void ChangeClearSIO(long);
extern long _comb_control(unsigned long,unsigned long,unsigned long);

#if defined(_LANGUAGE_C_PLUS_PLUS)||defined(__cplusplus)||defined(c_plusplus)
}
#endif
#endif /*_LIBCOMB_H_*/

