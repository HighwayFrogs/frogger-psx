/*
 * $PSLibId: Run-time Library Release 4.0$
 */
#ifndef _AUTOPAD_H_
#define _AUUTOPAD_H_

#define EXTENTION_APD   ".pad"
#define EXTENTION_LOG   ".log"

#define APDHDR_LABEL    "PAD"
#define APDHDR_TYPE     (u_short)0x1

#define LOGFILE_LEN     80

typedef struct {
        char            label[4];       /* 判別ラベル                   */
        u_short         type;           /* ファイルタイプ               */
        u_short         reserved1;      /* 未使用                       */
        u_long          size;           /* ヘッダを含まないデータサイズ */
        u_long          count;          /* パッドデータの数             */
} APDSAVE_HEADER;

#endif
