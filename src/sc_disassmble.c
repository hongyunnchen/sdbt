#include "..\include\sc_disassmble.h"
#include "..\include\sc_rewrite.h"

VOID PutBranchLable( DWORD dwAddress, PCHAR szDestString )
{
    CHAR szLocString[MAX_DECODE_BUFFER];

    _snprintf(szLocString, MAX_DECODE_BUFFER, "loc_%.8x:\n", dwAddress);
    strncat( szLocString, szDestString, MAX_DECODE_BUFFER );
    strncpy( szDestString, szLocString, MAX_DECODE_BUFFER );
}

VOID SetBranchLocation(DWORD dwAddress, PCHAR szAddaress, PCHAR szDestString)
{
    CHAR szLocString[MAX_DECODE_BUFFER];
    PCHAR szResult;

    _snprintf(szLocString, MAX_DECODE_BUFFER, "loc_%.8x", dwAddress);
    szResult = str_replace(szDestString, szAddaress, szLocString );
    strncpy( szDestString, szResult, MAX_DECODE_BUFFER );
    free( szResult );
}

DWORD GetInstructionType( DWORD dwAddress )
{
    UINT dwDecodeInstCount = 0;
   _DInst DecomposeInst;
   _CodeInfo DecomposeCodeInfo = {0};
   DecomposeCodeInfo.code = (const uint8_t *)dwAddress;
   DecomposeCodeInfo.codeLen = MAX_INST_LEN;
   DecomposeCodeInfo.dt = Decode32Bits;
   
   distorm_decompose(&DecomposeCodeInfo, &DecomposeInst, 1, &dwDecodeInstCount);
   return META_GET_FC(DecomposeInst.meta);
}

BOOL DecodeInstruction(DWORD dwAddress, DWORD dwOffset, PCHAR szDecodeBuffer, _DecodedInst* DisassmbledInst)
{
    UINT dwDecodeInstCount = 0;
    _DecodeResult DecodeResult;
    _OffsetType DecodeOffset = dwOffset;

    DecodeResult = distorm_decode(DecodeOffset, (const unsigned char*)dwAddress, MAX_INST_LEN, Decode32Bits, DisassmbledInst, 1, &dwDecodeInstCount);
    if ( DecodeResult != DECRES_INPUTERR )
    {
        if ( szDecodeBuffer != NULL )
        {
            /* if this is a unknown instruction, replace it with a illegal instruction,
               so it will filter in translation process */
            if ( strstr((PCHAR)DisassmbledInst->mnemonic.p, "DB ") )
                strncpy( szDecodeBuffer, "CLI", MAX_DECODE_BUFFER );
            else
                _snprintf(szDecodeBuffer, MAX_DECODE_BUFFER, "%s%s%s", (char*)DisassmbledInst->mnemonic.p, DisassmbledInst->operands.length != 0 ? " " : "", (char*)DisassmbledInst->operands.p);
        }
        return TRUE;
    }

    return FALSE;
}

DWORD GetInstructionSize(DWORD dwAddress)
{
    UINT dwDecodeInstCount = 0;
    _DecodedInst DisassmbledInst;
    _DecodeResult DecodeResult;

    DecodeResult = distorm_decode(0, (const unsigned char*)dwAddress, MAX_INST_LEN, Decode32Bits, &DisassmbledInst, 1, &dwDecodeInstCount);
    if ( DecodeResult != DECRES_INPUTERR )
    {
        return DisassmbledInst.size;
    }

    return 0;
}

DWORD diStormRecursive( DWORD gStartAddress, DWORD dwStartAddress, DWORD dwEndAddress, PBYTE DisassMap, PCHAR * InstList, BOOL bJumpLocation )
{
    DWORD dwDisMapOffset;
    DWORD dwOffset = 0;
    DWORD dwInstType;
    INT dwJumpOffset;
    _DecodedInst DisassmbledInst;

    dwDisMapOffset = (dwStartAddress - gStartAddress );

    do
    {
        if ( ( dwStartAddress + dwOffset ) >= dwEndAddress )
            return DIS_OUT_OFBOUND;

        if ( DisassMap[dwDisMapOffset] == INST_VISITED )
            return DIS_VISITED;

        /* decode instruction at address */
        if ( DecodeInstruction( dwStartAddress + dwOffset, dwDisMapOffset, InstList[dwDisMapOffset], &DisassmbledInst ) == FALSE )
            return DIS_ERROR;

        /* put branch label if it's a branch */
        if ( bJumpLocation )
        {
            PutBranchLable( dwDisMapOffset, InstList[dwDisMapOffset]);
            bJumpLocation = FALSE;
        }

#ifdef  DIS_DEBUG
        printf("%s", InstList[dwDisMapOffset]);
#endif

        /* mark address as visited */
        DisassMap[dwDisMapOffset] = INST_VISITED;

        /* get instruction type */
        dwInstType = GetInstructionType( dwStartAddress + dwOffset );

#ifdef  NO_UNREFRENCED_INST
        /* FIX : change this in diStorm meta */
        if ( strstr(InstList[dwDisMapOffset], "HLT" ) )
            /* we visit no more instruction after HLT */
            return DIS_UNREF_INST;
#endif

        /* Indicates the instruction is one of: JMP, JMP FAR. */
        if ( dwInstType == FC_UNC_BRANCH )
        {
            /* FIX : resolve relative register branches */
            if ( !IsReg32( (PCHAR)DisassmbledInst.operands.p ) && !IsMemOp((PCHAR)DisassmbledInst.operands.p) )
            {
                if ( !JUMP_FAR(DisassmbledInst) )
                {
                    /* get the branch offset */
                    dwJumpOffset = strtoul((const char*)DisassmbledInst.operands.p, NULL, DEFINE_HEX);

                    /* check if it is inside the buffer ? */
                    if ( dwJumpOffset < ( dwEndAddress - gStartAddress ) )
                    {
                        /* set branch location in decode string */
                        SetBranchLocation( dwJumpOffset, (PCHAR)DisassmbledInst.operands.p, InstList[dwDisMapOffset]);
                        /* visit jump location */
                        diStormRecursive( gStartAddress, (gStartAddress + dwJumpOffset ), dwEndAddress, DisassMap , InstList, TRUE);
                    }
                }
            }

#ifdef  NO_UNREFRENCED_INST
            /* we visit no more instruction after UNC_BRANCH */
            return DIS_UNREF_INST;
#endif

        }

        /*
        * Indicates the instruction is one of:
        * JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        */
        else if ( dwInstType == FC_CND_BRANCH )
        {
            if ( !JUMP_FAR(DisassmbledInst) )
            {
                if ( !IsReg32( (PCHAR)DisassmbledInst.operands.p ) && !IsMemOp((PCHAR)DisassmbledInst.operands.p) )
                {
                    /* get the branch offset */
                    dwJumpOffset = strtoul((const char*)DisassmbledInst.operands.p, NULL, DEFINE_HEX);

                    /* check if it is inside the buffer ? */
                    if ( !( dwJumpOffset > ( dwEndAddress - gStartAddress ) ) )
                    {
                        /* set branch location in decode string */
                        SetBranchLocation( dwJumpOffset, (PCHAR)DisassmbledInst.operands.p, InstList[dwDisMapOffset]);
                        /* visit jump location */
                        diStormRecursive( gStartAddress, (gStartAddress + dwJumpOffset ), dwEndAddress, DisassMap , InstList, TRUE);
                    }
                }

                /* visit location after jump */
                diStormRecursive( gStartAddress, (gStartAddress + dwDisMapOffset) + DisassmbledInst.size, dwEndAddress, DisassMap , InstList, FALSE);
            }
        }

        /* Indicates the instruction is one of: CALL, CALL FAR. */
        else if ( dwInstType == FC_CALL )
        {
            if ( !CALL_FAR(DisassmbledInst) )
            {
                /* get the branch offset */
                dwJumpOffset = strtoul((const char*)DisassmbledInst.operands.p, NULL, DEFINE_HEX);
                
                if ( !IsReg32( (PCHAR)DisassmbledInst.operands.p ) && !IsMemOp((PCHAR)DisassmbledInst.operands.p) )
                {
                    /* check if it is witting the buffer ? */
                    if ( !( dwJumpOffset > ( dwEndAddress - gStartAddress ) ) )
                    {
                        /* set branch location in decode string */
                        SetBranchLocation( dwDisMapOffset, (PCHAR)DisassmbledInst.operands.p, InstList[dwDisMapOffset]);
                        /* visit call location */
                        diStormRecursive( gStartAddress, (gStartAddress + dwJumpOffset ), dwEndAddress, DisassMap , InstList, TRUE);
                    }
                }
                /* visit location after call */
                diStormRecursive( gStartAddress, (gStartAddress + dwDisMapOffset) + DisassmbledInst.size, dwEndAddress, DisassMap , InstList, FALSE);
            }
        }

#ifdef  NO_UNREFRENCED_INST
        /* Indicates the instruction is one of: RET, IRET, RETF. */
        else if ( dwInstType == FC_RET )
        {
            return DIS_UNREF_INST;
        }
#endif

        dwDisMapOffset += DisassmbledInst.size; 
        dwOffset += DisassmbledInst.size;

    } while ( TRUE );
}

DWORD GetBranchData(DWORD dwStartAddress, DWORD dwInstAddress, DWORD dwBufferSize, PSC_BRANCH_LOC pBranchLoc)
{
    _DecodedInst DisassmbledInst;
    DWORD dwBranchOffset;
    DWORD dwBranchOperand;
    CHAR szDecodeBuffer[MAX_DECODE_BUFFER] = {0};

    DecodeInstruction(dwInstAddress, 0, NULL, &DisassmbledInst);

    if ( IS_BRANCH_RET(DisassmbledInst.mnemonic.p) )
        return DIS_BRANCH_RET;

    if ( !CALL_FAR(DisassmbledInst) && !JUMP_FAR(DisassmbledInst) )
    {
        if ( !IsReg32( (PCHAR)DisassmbledInst.operands.p ) && !IsMemOp((PCHAR)DisassmbledInst.operands.p) )
        {
            if ( IS_LONG_CN_BRANCH(DisassmbledInst) )
                dwBranchOperand = _byteswap_ulong(strtoul((const char*)&DisassmbledInst.instructionHex.p[4], NULL, DEFINE_HEX));
            else if ( IS_LONG_BRANCH(DisassmbledInst) )
                dwBranchOperand = _byteswap_ulong(strtoul((const char*)&DisassmbledInst.instructionHex.p[2], NULL, DEFINE_HEX));
            else 
                dwBranchOperand = strtoul((const char*)&DisassmbledInst.instructionHex.p[2], NULL, DEFINE_HEX);

            dwBranchOffset  = strtoul((const char*)DisassmbledInst.operands.p, NULL, DEFINE_HEX);

            /* check if it is witting the buffer ? */
            if ( !( ( ( dwInstAddress - dwStartAddress ) + dwBranchOffset ) > dwBufferSize ) )
            {
                pBranchLoc->dwBranchAddress = ( dwInstAddress - dwStartAddress );
                pBranchLoc->BranchTarget = ( pBranchLoc->dwBranchAddress + dwBranchOffset );
                if ( DisassmbledInst.size == 2 ) pBranchLoc->ShortBranchOp = dwBranchOperand;
                if ( DisassmbledInst.size >  2 ) pBranchLoc->LongBranchOp  = dwBranchOperand;
                pBranchLoc->Type = DisassmbledInst.size == 2 ? SHORT_BRANCH : LONG_BRANCH;
                return DIS_NO_ERROR;
            }
        }

        _snprintf(szDecodeBuffer, MAX_DECODE_BUFFER, "%s%s%s", (char*)DisassmbledInst.mnemonic.p, DisassmbledInst.operands.length != 0 ? " " : "", (char*)DisassmbledInst.operands.p);
        if ( IsMemoryBranch( szDecodeBuffer, pBranchLoc->szRegister ) )
            return DIS_REG_BASE_MEM_OP;
        else if ( IsNoneMemoryBranch( szDecodeBuffer, pBranchLoc->szRegister ) )
            return DIS_REG_BASE_OP;
    }

    return DIS_OUT_OFBOUND;
}