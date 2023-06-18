#pragma once

#ifndef XTRAP_UNIPER
#define XTRAP_UNIPER

#pragma comment(lib,"XTrap_Unipher_mt.lib")

#define XTRAP_DECRYPT_KEY "891882f7d4235da"

int __cdecl UniperEncFunc_Buf(unsigned char *szBuf, int iBufSize, unsigned char * szKey, int iKeySize);
int __cdecl UniperDecFunc_Buf(unsigned char *szBuf, int iBufSize, unsigned char * szKey, int iKeySize);

#endif