#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#pragma once

#define     START_ADDRESS       "DCBA"
#define     END_ADDRESS         "HGFE"
#define     ALERT_FUNCTION      "LKJI"
#define     GETPC_FLAG          "PONM"
#define     SAVED_ESP           "TSRQ"
#define     STACK_BASE          "dcba"
#define     STACK_LIMIT         "hgfe"

#define     SHELLCODE_LIMIT_SIZE    0x0F
#define     ADDR_32_MASK            0x000000FF
#define     ADDR_32                 4
#define     RANDOM_OFFSET           0x200
#define     _1Megabyte_             1024*1024
#define     STACK_MIDDLE            _1Megabyte_/2

typedef struct _SHELLCODE_DATA{
    PBYTE ShellcodeBuffer;
    DWORD dwShellcodeSize;
    LPVOID lpGetPcFlag;
    BOOL bExecutableStack;
} SHELLCODE_DATA, *PSHELLCODE_DATA;

VOID LoadShellcode(PSHELLCODE_DATA ShellExecData);
VOID SetGetPcFlag();
VOID InitTestEnv(PSHELLCODE_DATA pShellData, BOOL ExecStack, PBYTE ShellcodeBuffer, DWORD dwShellcodeSize, LPVOID GetPcFunction);