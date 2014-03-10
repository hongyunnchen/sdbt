#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "utils.h"
#include "..\libs\diStorm\include\distorm.h"
#pragma once

#define     NO_UNREFRENCED_INST
#define     OCCIPUED            '!'
#define     OCCIPUED_STR        "!" 

#define     MAX_DECODE_BUFFER       512
#define     DEFINE_HEX              16
#define     MAX_INST_LEN            16
#define     INST_VISITED            0x01

#define     SHORT_BRANCH_SIZE       0x02
#define     SHORT_BRANCH_BYTE       0x01
#define     SHORT_CN_BRANCH_SIZE    0x02
#define     SHORT_CN_BRANCH_BYTE    0x01
#define     LONG_BRANCH_SIZE        0x05
#define     LONG_BRANCH_BYTE        0x01
#define     LONG_CN_BRANCH_SIZE     0x06
#define     LONG_CN_BRANCH_BYTE     0x02
#define     LONG_ADDRESS_SIZE       0x04

#define     NOP_INST                0x90


#define     DIS_BASE                0x1337
#define     DIS_ERROR               DIS_BASE
#define     DIS_VISITED             DIS_BASE+1
#define     DIS_OUT_OFBOUND         DIS_BASE+2
#define     DIS_VISITED             DIS_BASE+3
#define     DIS_UNREF_INST          DIS_BASE+4
#define     DIS_UNMAPED_INST        DIS_BASE+5
#define     DIS_NO_ERROR            DIS_BASE+6
#define     DIS_REG_BASE_OP         DIS_BASE+7
#define     DIS_REG_BASE_MEM_OP     DIS_BASE+8
#define     DIS_BRANCH_RET          DIS_BASE+9
#define     DIS_STACK_GEN_MEM_WRITE DIS_BASE+10
#define     DIS_STACK_GEN_REG_WRITE DIS_BASE+10
#define     DIS_STACK_POP_WRITE     DIS_BASE+11
#define     DIS_ILLEGAL_INST        DIS_BASE+12

#define JUMP_R8(a)                      ( a.size == SHORT_BRANCH_SIZE )
#define JUMP_R16(a)                     ( a.size == 3 )
#define JUMP_R32(a)                     ( a.size == LONG_BRANCH_SIZE )
#define JUMP_FAR(a)                     ( a.size >  LONG_CN_BRANCH_SIZE )
#define CALL_FAR(a)                     ( a.size >  LONG_CN_BRANCH_SIZE )
#define IS_BRANCH(a)                    ( ( a[0] == 'J' ) || ( strstr(a, "CALL")) || ( strstr(a, "RET")) )
#define IS_BRANCH_RET(a)                ( strstr(a, "RET") )
#define IS_MEM_SHORT_CN_BRANCH(a)       ( ((PBYTE)a)[0] != 0xEB && ((PBYTE)a)[0] != 0xE8 )
#define IS_MEM_LONG_CN_BRANCH(a)        ( ((PBYTE)a)[0] == 0x0F )
#define IS_LONG_CN_BRANCH(a)            ( a.size ==  LONG_CN_BRANCH_SIZE)
#define IS_LONG_BRANCH(a)               ( a.size ==  LONG_BRANCH_SIZE   )

DWORD diStormRecursive( DWORD gStartAddress, DWORD dwStartAddress, DWORD dwEndAddress, PBYTE DisassMap, PCHAR * InstList, BOOL bJumpLocation );
DWORD GetInstructionSize(DWORD dwAddress);
DWORD GetBranchData(DWORD dwStartAddress, DWORD dwInstAddress, DWORD dwBufferSize, PSC_BRANCH_LOC pBranchLoc);