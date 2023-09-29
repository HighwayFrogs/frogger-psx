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
        char            label[4];       /* ���ʃ��x��                   */
        u_short         type;           /* �t�@�C���^�C�v               */
        u_short         reserved1;      /* ���g�p                       */
        u_long          size;           /* �w�b�_���܂܂Ȃ��f�[�^�T�C�Y */
        u_long          count;          /* �p�b�h�f�[�^�̐�             */
} APDSAVE_HEADER;

#endif
