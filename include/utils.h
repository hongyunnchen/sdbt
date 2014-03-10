#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#pragma once

#define BIN_DATA_SIZE   1024*8
#define SC_SIZE         512

typedef enum { SHORT_BRANCH, LONG_BRANCH } BRANCH_TYPE;

typedef struct _SC_BIN_DATA {
    PBYTE Data;
    DWORD dwCount;
} SC_BIN_DATA, *PSC_BIN_DATA;

typedef struct _SC_CHECK_LOC {
    DWORD dwCheckLocation;
    DWORD dwCheckSize;
} SC_CHECK_LOC, *PSC_CHECK_LOC;

typedef struct _SC_BRANCH_LOC {
    DWORD dwBranchAddress;
    INT BranchTarget;
    INT LongBranchOp;
    signed char ShortBranchOp;
    BRANCH_TYPE Type;
    CHAR szRegister[128];
} SC_BRANCH_LOC, *PSC_BRANCH_LOC;

char * str_replace ( const char *string, const char *substr, const char *replacement );
PBYTE StringToByteArray(PBYTE Result, PCHAR szString, DWORD dwSize );
VOID BinDataAppend(PSC_BIN_DATA BinData, PBYTE NewData, DWORD dwSize);
VOID BinDataDump(PCHAR szFileName, PSC_BIN_DATA BinData);
VOID DumpBranchInfo( BRANCH_TYPE Type, DWORD dwOp, DWORD dwOffset ); 
VOID DisassDataDump(PCHAR szFileName, PCHAR * DisassData, DWORD dwSize);