#include "..\include\sc_translate.h"
#include "..\include\sc_disassmble.h"
#include "..\include\sc_test.h"
#include "..\include\sc_rewrite.h"
#include "..\include\utils.h"

extern  HANDLE gProcessHeap;

PVOID TranslateAssembly(PCHAR szAsmString, PDWORD dwSize, PCHAR szFunctionName)
{
	CAssembler *CAsm;
	INT dwBinarySize;
    PBYTE Buffer;
    DWORD i = 0;

	CAsm = casm_create();
	casm_source(CAsm, szAsmString);
	dwBinarySize = casm_compile(CAsm, NULL, 0);

	if (dwBinarySize < 0) {
		//printf("[%s] compile error: %s\n", szFunctionName, CAsm->error);
        //printf("Asm :\n%s\n",szAsmString);
		casm_release(CAsm);
		return NULL;
	}

    Buffer = (PBYTE) HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, dwBinarySize);
	casm_compile(CAsm, (PUCHAR)Buffer, dwBinarySize);
	casm_release(CAsm);

    /* asmpure alignment bug - add extra INT3 (0xCC) at the end of assembled buffer */
    for ( i = dwBinarySize; i > 0; i-- )
    {
        if ( Buffer[i] == 0x90 && Buffer[i-1] == 0x90 && Buffer[i-2] == 0x90 && Buffer[i-3] == 0x90 && Buffer[i-4] == 0x90 )
            break;
    }

    *dwSize = i - 4;
    return Buffer;
}

PSC_BIN_DATA TranslateCode(PBYTE dwCode, DWORD dwCodeSize, BOOL bDumpBinary, PCHAR szBinFile, BOOL bDumpDisass, PCHAR szDisassFile)
{
    PSC_BIN_DATA FinalShellcode;
    SC_CHECK_LOC CheckLocation[SC_SIZE];
    SC_BRANCH_LOC BranchLocation[SC_SIZE];
    PBYTE DissassMap;
    CHAR szDestReg[MAX_DECODE_BUFFER];
    PCHAR * szInstList;
    DWORD dwInstSize               = 0;
    DWORD dwBranchCount            = 0;
    DWORD dwCheckCount             = 0;
    DWORD dwCheckSize              = 0;
    DWORD dwBranchType             = 0;
    DWORD dwInstType               = 0;
    DWORD i                        = 0;
    DWORD dwDisassembledBufferSize = 0;
    BOOL  bError                   = FALSE;
    BOOL  bConditionalBranch       = FALSE;
    BOOL  bMemWrite                = FALSE;
    BOOL  bMemRead                 = FALSE;
    BOOL  bFloatingPointGetPc      = FALSE;

    
    DissassMap = (PBYTE) HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, dwCodeSize);
    szInstList = (PCHAR *)HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, dwCodeSize * sizeof(PCHAR));
    for ( i = 0; i < dwCodeSize; i++ ) szInstList[i] = (PCHAR)HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, MAX_DECODE_BUFFER);

    /* Decode the buffer */
    diStormRecursive( (DWORD)dwCode, (DWORD)dwCode, (DWORD)dwCode + dwCodeSize, DissassMap, szInstList, FALSE);

    /* allocate shellcode data buffer */
    FinalShellcode          = (PSC_BIN_DATA)HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, sizeof(SC_BIN_DATA));
    FinalShellcode->Data    = (PBYTE)HeapAlloc(gProcessHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, BIN_DATA_SIZE);
    FinalShellcode->dwCount = 0;
    i = 0;

    while ( i < dwCodeSize )
    {
        if ( *szInstList[i] )
        {
            dwInstSize = GetInstructionSize( (DWORD)&dwCode[i] );
            BinDataAppend(FinalShellcode, &dwCode[i], dwInstSize );
            dwDisassembledBufferSize += dwInstSize;

            if ( !IS_BRANCH(szInstList[i]) )
            {
                if ( IsIllegalInstruction(szInstList[i]) )
                {
                    /* illegal inst before Conditional Branch is not valid */
                    if ( bConditionalBranch )
                    {
                        /* in this situation we overwrite the original instruction */
                        FinalShellcode->dwCount -= dwInstSize;
                        CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode); 
                        if ( ( dwCheckSize = FilterIllegalInstruction( dwInstSize, FinalShellcode) ) == 0 )
                        {
                            bError = TRUE;
                            goto __END;
                        }

                        CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize - dwInstSize;
                        dwCheckCount++;
                    }
                    else
                    {
                        bError = TRUE;
                        goto __END;
                    }
                }
                else if ( ( dwInstType = IsStackManipulation( szInstList[i], szDestReg ) ) != DIS_ERROR )
                {
                    if ( dwInstType == DIS_ILLEGAL_INST )
                    {
                        /* in this situation we overwrite the original instruction */
                        FinalShellcode->dwCount -= dwInstSize;
                        CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode);
                        if ( ( dwCheckSize = FilterIllegalInstruction( dwInstSize, FinalShellcode) ) == 0 )
                        {
                            bError = TRUE;
                            goto __END;
                        }

                        CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize - dwInstSize;
                        dwCheckCount++;
                    }
                    else
                    {
                        /* in stack manipulation we overwrite the original instruction */
                        FinalShellcode->dwCount -= dwInstSize;
                        CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode); 
                        if ( ( dwCheckSize = StackPutBoundCheck( szInstList[i], BranchLocation[dwBranchCount].szRegister, dwInstSize, FinalShellcode, dwInstType) ) == 0 )
                        {
                            bError = TRUE;
                            goto __END;
                        }
                        if ( dwCheckSize > CHECK_SIZE_LIMIT )
                            CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize;
                        else
                            CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize - dwInstSize;
                        dwCheckCount++;
                    }
                }
                else if ( IsMemoryRead( szInstList[i], szDestReg ) == TRUE )
                {
                    /* we put check after inst so we should plus the address by inst size */
                    CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode + dwInstSize);
                    if ( ( dwCheckSize = MemReadPutGetPcCheck( szDestReg, FinalShellcode) ) == 0 )
                    {
                        bError = TRUE;
                        goto __END;
                    }

                    bMemRead = TRUE;
                    CheckLocation[dwCheckCount].dwCheckSize = dwCheckSize ;
                    dwCheckCount++;
                }

                else if ( IsMemoryWrite( szInstList[i], szDestReg ) == TRUE )
                {
                    /* memory write inst before a memory read is not valid */
                    if ( bMemRead )
                    {
                        /* in memory write situation we overwrite the original instruction */
                        FinalShellcode->dwCount -= dwInstSize;
                        CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode ); 
                        if ( ( dwCheckSize = MemWritePutGetPcCheck( szInstList[i], szDestReg, dwInstSize, FinalShellcode) ) == 0 )
                        {
                            bError = TRUE;
                            goto __END;
                        }

                        /* we NOP the original inst by asm compiler, so we have to sub the original ist size from check size */
                        bMemWrite = TRUE;
                        CheckLocation[dwCheckCount].dwCheckSize = dwCheckSize - dwInstSize; 
                        dwCheckCount++;
                    }
                    else
                    {
                        bError = TRUE;
                        goto __END;
                    }
                }
            }
            else
            {
                dwBranchType = GetBranchData((DWORD)dwCode, (DWORD)&dwCode[i], dwCodeSize, &BranchLocation[dwBranchCount] );
                if ( IS_MEM_SHORT_CN_BRANCH(&dwCode[i]) )
                    bConditionalBranch = TRUE;

                if ( dwBranchType == DIS_NO_ERROR )
                {
                    dwBranchCount++;
                }
                if ( dwBranchType == DIS_OUT_OFBOUND )
                {
                    /* out of bound branch before a Conditional Branch indicates this sequence is not valid */
                    if ( bConditionalBranch )
                    {
                        FinalShellcode->dwCount -= dwInstSize;
                        CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode ); 
                        if ( ( dwCheckSize = BranchPutOutOfBoundErrorHandler( szInstList[i], dwInstSize, FinalShellcode) ) == 0 )
                        {
                            bError = TRUE;
                            goto __END;
                        }
                        CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize - dwInstSize; 
                        dwCheckCount++;
                    }
                    else
                    {
                        bError = TRUE;
                        goto __END;
                    }
                }
                if ( dwBranchType == DIS_REG_BASE_OP )
                {
                    /* in out of bound branch situation we overwrite the original instruction */
                    FinalShellcode->dwCount -= dwInstSize;
                    CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode); 
                    if ( ( dwCheckSize = BranchRegPutBoundCheck( szInstList[i], BranchLocation[dwBranchCount].szRegister, FinalShellcode) ) == 0 )
                    {
                        bError = TRUE;
                        goto __END;
                    }
                    CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize; 
                    dwCheckCount++;
                }
                if ( dwBranchType == DIS_REG_BASE_MEM_OP )
                {
                    /* in out of bound branch situation we overwrite the original instruction */
                    FinalShellcode->dwCount -= dwInstSize;
                    CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode); 
                    if ( ( dwCheckSize = BranchMemRegPutBoundCheck( szInstList[i], BranchLocation[dwBranchCount].szRegister, dwInstSize, FinalShellcode) ) == 0 )
                    {
                        bError = TRUE;
                        goto __END;
                    }
                    if ( dwCheckSize > CHECK_SIZE_LIMIT )
                        CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize;
                    else
                        CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize - dwInstSize;
                    dwCheckCount++;
                }
                if ( dwBranchType == DIS_BRANCH_RET )
                {
                    /* in out of bound branch situation we overwrite the original instruction */
                    FinalShellcode->dwCount -= dwInstSize;
                    CheckLocation[dwCheckCount].dwCheckLocation = (&dwCode[i] - dwCode); 
                    if ( ( dwCheckSize = BranchRetPutBoundCheck( szInstList[i] , FinalShellcode) ) == 0 )
                    {
                        bError = TRUE;
                        goto __END;
                    }
                    CheckLocation[dwCheckCount].dwCheckSize =  dwCheckSize; 
                    dwCheckCount++;
                }
            }

            i += dwInstSize;
        }
        else
        {
            BinDataAppend(FinalShellcode, &dwCode[i], 1 );
            i++;
        }
    }

    if ( dwBranchCount > 0 && dwCheckCount > 0 )
    {
        UpdateBranchLocations( FinalShellcode, BranchLocation, dwBranchCount, CheckLocation, dwCheckCount );
    }

    if ( bDumpBinary )
        BinDataDump(szBinFile, FinalShellcode);
__END:
    HeapFree( gProcessHeap, 0, DissassMap );
    for ( i = 0; i < dwCodeSize; i++ ) HeapFree( gProcessHeap, 0, szInstList[i]);
    HeapFree( gProcessHeap, 0, szInstList );

    /* if overall disassembled buffer size is less than this limit,
       this is not a valid sequence                                 */
    if ( dwDisassembledBufferSize < SHELLCODE_LIMIT_SIZE )
        return NULL;

    if ( bError )
        return NULL;

    return FinalShellcode;
}
