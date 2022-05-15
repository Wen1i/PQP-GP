#pragma once


#define SM4_ENCRYPT 1//���ܱ�־
#define SM4_DECRYPT 0//���ܱ�־

struct sm4Context
{
	int mode;//ѡ�����/����mode
	unsigned long sk[32];//subkey:32������Կ
};



/* ���ܵ�context���ã�modeȷ���Ǽ���enc������Կ������Կ��չ�㷨����
*\param  ctx <sm4Context*>             һ��sm4��������
*        key <unsigned char[16]>       ��ε�����Կ
*/
void sm4Setkey_Enc(sm4Context* ctx, unsigned char key[16]);



/* ���ܵ�context���ã�modeȷ���ǽ���dec������Կ������Կ��չ�㷨����
*\param  ctx <sm4Context*>            һ��sm4��������
*        key <unsigned char[16]>      ��ε�����Կ
*/
void sm4Setkey_Dec(sm4Context* ctx, unsigned char key[16]);



/* һ��sm4
*\param  SK                           32������Կ
*        plain                        ����
*        cipher                       ����
*/
void sm4_1_Round(unsigned long SK[32], unsigned char plain[16], unsigned char cipher[16]);


/* ecbģʽ
 *\param  SK      32������Կ
 *        input   ����
 *        output  ���
 *        length  ����
 */
void sm4_ecb(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);


/* ѭ��չ�� �ڲ�2�� ��ecb */
void sm4_ecb_LoopUnRoll2(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);

/* ѭ��չ�� �ڲ�4�� ��ecb */
void sm4_ecb_LoopUnRoll4(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);

/* ѭ��չ�� �ڲ�8�� ��ecb */
void sm4_ecb_LoopUnRoll8(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);

/* ѭ��չ�� �ڲ�16�� ��ecb */
void sm4_ecb_LoopUnRoll16(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);


/* չʾ�ĺ��� */
void shower(unsigned char* show, unsigned long len);


/* ��ʼ������ */
void init(unsigned char* arr, int len);


/* ���ܵ�context���ã�modeȷ���Ǽ���enc������Կ������Կ��չ�㷨����  simd
*\param  ctx <sm4Context*>       һ��sm4��������
*        key <unsigned char[16]> ��ε�����Կ
*/
void sm4Setkey_Enc_SIMD(sm4Context* ctx, unsigned char key[16]);


/* ���ܵ�context���ã�modeȷ���ǽ���dec������Կ������Կ��չ�㷨����  simd
*\param  ctx <sm4Context*>       һ��sm4��������
*        key <unsigned char[16]> ��ε�����Կ
*/
void sm4Setkey_Dec_SIMD(sm4Context* ctx, unsigned char key[16]);

/* һ��sm4 simd
*\param  SK   32������Կ
*        plain ����
*        cipher ����
*/
void sm4_1_Round_SIMD(unsigned long SK[32], unsigned char plain[16], unsigned char cipher[16]);

/* ecbģʽ   simd
 *\param  SK      32������Կ
 *        input   ����
 *        output  ���
 *        length  ����
 */
void sm4_ecb_SIMD(unsigned long SK[32], unsigned char* input, unsigned char* output, unsigned long length);