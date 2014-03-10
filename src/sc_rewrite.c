#include "..\include\sc_rewrite.h"
#include "..\include\sc_disassmble.h"
#include "..\include\sc_translate.h"
extern HANDLE gProcessHeap;

BOOL IsMemOp(PCHAR szReg)
{
    PCHAR StringPosStart = NULL;
    PCHAR StringPosEnd   = NULL;

    StringPosStart = (PCHAR)strstr( szReg, "[" );
    StringPosEnd   = (PCHAR)strstr( szReg, "]" );
    if ( StringPosStart && StringPosEnd )
        return TRUE;

    return FALSE;
}

BOOL IsReg32(PCHAR szReg)
{
    PCHAR RegisterTable[] = { "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP" , "ESP" };
    DWORD i;
    
    for ( i = 0; i < 8; i++ )
        if ( !strcmp(szReg, RegisterTable[i]) )
            return TRUE;

    return FALSE;
}

BOOL IsNoneMemoryBranch(PCHAR szInst, PCHAR szDestReg)
{
    PCHAR StringPosStart;

    if ( strstr( szInst, " "  ) )
    {
        StringPosStart = (PCHAR)strstr( szInst, " " );
        memcpy(szDestReg, ++StringPosStart, 3 );
        szDestReg[3] = '\0';
        if ( IsReg32( szDestReg ) )
            return TRUE;
    }
}

BOOL IsMemoryBranch(PCHAR szInst, PCHAR szDestReg)
{
    PCHAR StringPosStart;
    PCHAR StringPosEnd;

    if ( strstr( szInst, "]"  ) )
    {
        StringPosStart = (PCHAR)strstr( szInst, "[" );
        StringPosEnd   = (PCHAR)strstr( szInst, "]" );
        memcpy(szDestReg, ++StringPosStart, (StringPosEnd - StringPosStart) );
        szDestReg[StringPosEnd - StringPosStart] = '\0';
        return TRUE;
    }

    return FALSE;
}


/* currently support MOV and POP  with 32bit registers 
   TODO : Other implicit memory read instructions like LODS/STOS
   also support ADD/SUB/MUL/XOR/OR/AND
*/
BOOL IsMemoryRead(PCHAR szInst, PCHAR szDestReg )
{
    PCHAR StringPos;

    if ( strstr( szInst, "MOV"  ) )
    {
        if ( strstr( szInst, ", ["  ) )
        {
            StringPos = (PCHAR)strstr( szInst, " " );
            memcpy(szDestReg, ++StringPos, 3 );
            szDestReg[3] = '\0';
            if ( IsReg32( szDestReg ) )
                return TRUE;
            return FALSE;
        }
    } else if ( strstr( szInst, "POP" ) )
    {
        if ( !strstr( szInst, "ESP" ) )
        {
            /* TODO : Handle the POPF/POPA correctly */
            if ( strcmp(szInst, "POPF") && strcmp(szInst, "POPA") )
            {
                StringPos = (PCHAR)strstr( szInst, " " );
                memcpy(szDestReg, ++StringPos, 3 );
                szDestReg[3] = '\0';
                if ( IsReg32( szDestReg ) )
                    return TRUE;
                return FALSE;
            }
        }
    }

    return FALSE;
}

BOOL IsIllegalInstruction(PCHAR szInst)
{
    if ( strstr( szInst, "INT") || strstr( szInst, "SYSENTER") || strstr( szInst, "SYSEXIT") ||
         strstr( szInst, "STI") || strstr( szInst, "CLI") || strstr( szInst, "IN ") || strstr( szInst, "OUT ") )
        return TRUE;

    return FALSE;
}

DWORD FilterIllegalInstruction(DWORD dwInstSize, PSC_BIN_DATA pData)
{
    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    DWORD i;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szNopOrgInst[MAX_DECODE_BUFFER];
    CHAR szErrorWrite[] = "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
    for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
    strncat(szNopOrgInst, szErrorWrite, MAX_DECODE_BUFFER);
    if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "FilterIllegalInstruction" ) ) != NULL )
    {
        BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
        HeapFree( gProcessHeap, 0,  pCompiledAsm );
        return dwCompiledAsmSize;
    }

    return 0;
}

DWORD IsStackManipulation(PCHAR szInst, PCHAR szDestReg )
{
    PCHAR StringPosStart;
    PCHAR StringPosEnd;

    if ( strstr(szInst, "ESP,") )
    {
        if ( strstr( szInst, "], "  ) )
        {
            StringPosStart = (PCHAR)strstr( szInst, "[" );
            StringPosEnd   = (PCHAR)strstr( szInst, "]" );
            memcpy(szDestReg, ++StringPosStart, (StringPosEnd - StringPosStart) );
            szDestReg[StringPosEnd - StringPosStart] = '\0';
            return DIS_STACK_GEN_MEM_WRITE;
        }
        else if ( strstr( szInst, "MOV"  ) || strstr( szInst, "XCHG"  ) )
        {
            StringPosStart = (PCHAR)strstr( szInst, ", " );
            memcpy(szDestReg, ++StringPosStart, 3 );
            szDestReg[3] = '\0';
            if ( IsReg32( szDestReg ) )
                return DIS_STACK_GEN_REG_WRITE;
            return DIS_ILLEGAL_INST;
        }
        else if ( strstr( szInst, "POP" ) )
        {
            return DIS_STACK_POP_WRITE;
        }
    }

    return DIS_ERROR;
}

DWORD StackPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister,  DWORD dwInstSize, PSC_BIN_DATA pData, DWORD dwType)
{

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    DWORD i;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szNopOrgInst[MAX_DECODE_BUFFER];
    CHAR szGenRegBoundCheck[] = "    CMP %s, 0x61626364\n"
                                "    JB OUT_BOUND\n"
                                "    CMP %s, 0x65666768\n"
                                "    JBE IN_BOUND\n"
                                "OUT_BOUND:\n"
                                "    MOV EAX, 0x51525354\n"
                                "    MOV ESP, [EAX]\n"        /* SavedESP */
                                "    POPFD\n"
                                "    POPAD\n"
                                "    POP EAX\n"
                                "    JMP EAX\n"
                                "IN_BOUND:\n"
                                "    %s\n"                    /* orginal branch inst */
                                "    NOP\n"                   /* nops are for asmpure alignment bug */
                                "    NOP\n"
                                "    NOP\n"
                                "    NOP\n"
                                "    NOP\n";

    CHAR szGenMemBoundCheck[] =  "    PUSH EAX\n"
                                 "    LEA EAX, [%s]\n"
                                 "    CMP EAX, 0x61626364\n"
                                 "    JB OUT_BOUND\n"
                                 "    CMP EAX, 0x65666768\n"
                                 "    JBE IN_BOUND\n"
                                 "OUT_BOUND:\n"
                                 "    MOV EAX, 0x51525354\n"
                                 "    MOV ESP, [EAX]\n"        /* SavedESP */
                                 "    POPFD\n"
                                 "    POPAD\n"
                                 "    POP EAX\n"
                                 "    JMP EAX\n"
                                 "IN_BOUND:\n"
                                 "    POP EAX\n"
                                 "    %s\n"                    /* original branch inst */
                                 "    NOP\n"                   /* nops are for asmpure alignment bug */
                                 "    NOP\n"
                                 "    NOP\n"
                                 "    NOP\n"
                                 "    NOP\n";

    CHAR szPopBoundCheck[] = "    PUSH EAX\n"
                             "    MOV EAX, [ESP+4]\n"
                             "    CMP EAX, 0x61626364\n"
                             "    JB OUT_BOUND\n"
                             "    CMP EAX, 0x65666768\n"
                             "    JBE IN_BOUND\n"
                             "OUT_BOUND:\n"
                             "    MOV EAX, 0x51525354\n"
                             "    MOV ESP, [EAX]\n"        /* SavedESP */
                             "    POPFD\n"
                             "    POPAD\n"
                             "    POP EAX\n"
                             "    JMP EAX\n"
                             "IN_BOUND:\n"
                             "    POP EAX\n"
                             "    %s\n"                    /* original branch inst */
                             "    NOP\n"                   /* nops are for asmpure alignment bug */
                             "    NOP\n"
                             "    NOP\n"
                             "    NOP\n"
                             "    NOP\n";

    CHAR szErrorWrite[] = "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";  

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    if ( dwType == DIS_STACK_GEN_MEM_WRITE )
        sprintf(szTestBound, szGenMemBoundCheck , szTargetRegister, szInst);
    else if ( dwType == DIS_STACK_POP_WRITE ) 
        sprintf(szTestBound, szPopBoundCheck, szInst);
    else if ( dwType == DIS_STACK_GEN_REG_WRITE )
        sprintf(szTestBound, szGenRegBoundCheck, szTargetRegister, szTargetRegister, szInst );
    else 
        return 0;

    if ( ( pCompiledAsm = TranslateAssembly( szTestBound, &dwCompiledAsmSize, "StackPutBoundCheck" ) ) == NULL )
    {
        /* probably something is wrong in branch mem instruction,
           so we put a error handler here and overwrite the memory
           branch instruction.
        */
        ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
        for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
        strncat(szNopOrgInst, szErrorWrite, MAX_DECODE_BUFFER);
        if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "StackPutBoundCheck" ) ) != NULL )
        {
            BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
            HeapFree( gProcessHeap, 0,  pCompiledAsm );
            return dwCompiledAsmSize;
        }

        return 0;
    }

    BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
    HeapFree( gProcessHeap, 0, pCompiledAsm );
    return dwCompiledAsmSize;
}


/* currently support MOV/XOR/AND/OR with 32bit registers (TODO : PUSH/ADD/SUB/STOS ) Manipulation */
BOOL IsMemoryWrite(PCHAR szInst, PCHAR szDestReg )
{
    PCHAR StringPosStart;
    PCHAR StringPosEnd;
    /* FIX : match the whole word, so don't use strstr */
    if ( strstr( szInst, "MOV"  ) || strstr( szInst, "XOR"  ) || 
         strstr( szInst, "AND"  ) || strstr( szInst, "OR"   ) ||
         strstr( szInst, "ADD"  ) || strstr( szInst, "SUB"  ) )
    {
        if ( strstr( szInst, "MOVS"  )) 
        {
            strcpy(szDestReg, "EDI");
            return TRUE;
        }

        if ( strstr( szInst, "STOS"  )) 
        {
            strcpy(szDestReg, "EDI");
            return TRUE;
        }

        if ( strstr( szInst, "], "  ) )
        {
            StringPosStart = (PCHAR)strstr( szInst, "[" );
            StringPosEnd   = (PCHAR)strstr( szInst, "]" );
            memcpy(szDestReg, ++StringPosStart, (StringPosEnd - StringPosStart) );
            szDestReg[StringPosEnd - StringPosStart] = '\0';
            return TRUE;
        }
    }
    return FALSE;
}

DWORD BranchRetPutBoundCheck(PCHAR szInst, PSC_BIN_DATA pData)
{
    /*
    Bound check is performed by following assembly:
        PUSH TempReg
        MOV TempReg, [ESP+4]
        CMP TempReg, ShellocdeStartAddress
        JB NO_GETPC
        CMP TempReg, ShellcodeEndAddress
        JA NO_GETPC
        POP TempReg
        MOV ESP, SavedESP
        POPAD
        RET
    NO_GETPC_%d:
        <rest of shellcode>
    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szBoundCheck[] = "    PUSH EAX\n"
                          "    MOV EAX, [ESP+4]\n"
                          "    CMP EAX, 0x41424344\n"
                          "    JB OUT_BOUND\n"
                          "    CMP EAX, 0x45464748\n"
                          "    JBE IN_BOUND\n"
                          "OUT_BOUND:\n"
                          "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "IN_BOUND:\n"
                          "    POP EAX\n"
                          "    %s\n"                    /* original branch inst */
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    sprintf(szTestBound, szBoundCheck , szInst);
    
    if ( ( pCompiledAsm = TranslateAssembly( szTestBound, &dwCompiledAsmSize, "BranchRetPutBoundCheck" ) ) != NULL )
    {
        BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
        HeapFree( gProcessHeap, 0,  pCompiledAsm );
        return dwCompiledAsmSize;
    }

    return 0;
}

DWORD BranchMemRegPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister,  DWORD dwInstSize, PSC_BIN_DATA pData)
{
    /*
    Bound check is performed by following assembly:
        PUSH TempReg
        LEA TempReg, [DstReg]
        CMP TempReg, ShellocdeStartAddress
        JB NO_GETPC
        CMP TempReg, ShellcodeEndAddress
        JA NO_GETPC
        INC [GetPcFlag]
    NO_GETPC_%d:
        POP TempReg
        MOV ESP, SavedESP
        POPAD
        RET
        <rest of shellcode>

    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    DWORD i;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szNopOrgInst[MAX_DECODE_BUFFER];
    CHAR szBoundCheck[] = "    PUSH EAX\n"
                          "    LEA EAX, [%s]\n"
                          "    CMP EAX, 0x41424344\n"
                          "    JB OUT_BOUND\n"
                          "    CMP EAX, 0x45464748\n"
                          "    JBE IN_BOUND\n"
                          "OUT_BOUND:\n"
                          "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "IN_BOUND:\n"
                          "    POP EAX\n"
                          "    %s\n"                    /* original branch inst */
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";

    CHAR szErrorWrite[] = "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";  

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    sprintf(szTestBound, szBoundCheck , szTargetRegister, szInst);
    
    if ( ( pCompiledAsm = TranslateAssembly( szTestBound, &dwCompiledAsmSize, "BranchMemRegPutBoundCheck" ) ) == NULL )
    {
        /* probably something is wrong in branch mem instruction,
           so we put a error handler here and overwrite the memory
           branch instruction.
        */
        ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
        for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
        strncat(szNopOrgInst, szErrorWrite, MAX_DECODE_BUFFER);
        if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "BranchMemRegPutBoundCheck" ) ) != NULL )
        {
            BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
            HeapFree( gProcessHeap, 0,  pCompiledAsm );
            return dwCompiledAsmSize;
        }

        return 0;
    }

    BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
    HeapFree( gProcessHeap, 0,  pCompiledAsm );
    return dwCompiledAsmSize;
}


DWORD BranchRegPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister, PSC_BIN_DATA pData)
{
    /*
    Bound Check check is performed by following assembly:

        CMP DstReg, ShellocdeStartAddress
        JB NO_GETPC
        CMP DstReg, ShellcodeEndAddress
        JA NO_GETPC
        MOV ESP, SavedESP
        POPFD
        POPAD
        POP EAX
        JMP EAX
    NO_GETPC_%d:
        <rest of shellcode>

    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szBoundCheck[] = "    CMP %s, 0x41424344\n"
                          "    JB OUT_BOUND\n"
                          "    CMP %s, 0x45464748\n"
                          "    JBE IN_BOUND\n"
                          "OUT_BOUND:\n"
                          "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "IN_BOUND:\n"
                          "    %s\n"                    /* orginal branch inst */
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    sprintf(szTestBound, szBoundCheck , szTargetRegister , szTargetRegister, szInst);
    
    if ( ( pCompiledAsm = TranslateAssembly( szTestBound, &dwCompiledAsmSize, "BranchRegPutBoundCheck" ) ) != NULL )
    {
        BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
        HeapFree( gProcessHeap, 0,  pCompiledAsm );
        return dwCompiledAsmSize;
    }

    return 0;
}

DWORD BranchPutOutOfBoundErrorHandler(PCHAR szInst, DWORD dwInstSize, PSC_BIN_DATA pData)
{
    /*
    Bound handler is performed by following assembly:
        MOV ESP, SavedESP
        POPFD
        POPAD
        POP EAX
        JMP EAX
    NO_GETPC_%d:
        <rest of shellcode>

    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    DWORD i;
    CHAR szTestBound[MAX_DECODE_BUFFER];
    CHAR szNopOrgInst[MAX_DECODE_BUFFER];
    CHAR szBoundCheck[] = "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "OUT_BOUND:\n"
                          //"    %s\n"                    /* orginal branch inst */
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";   

    ZeroMemory( szTestBound, MAX_DECODE_BUFFER );
    ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
    for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
    sprintf(szTestBound, szBoundCheck , szInst);
    strncat(szNopOrgInst, szTestBound, MAX_DECODE_BUFFER);
    
    if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "BranchPutOutOfBoundErrorHandler" ) ) != NULL )
    {
        BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
        HeapFree( gProcessHeap, 0,  pCompiledAsm );
        return dwCompiledAsmSize;
    }

    return 0;
}

DWORD MemReadPutGetPcCheck(PCHAR szTargetRegister, PSC_BIN_DATA pData)
{
    /*
    GetPC check is performed by following assembly:

        CMP DstReg, ShellocdeStartAddress
        JB NO_GETPC
        CMP DstReg, ShellcodeEndAddress
        JA NO_GETPC
        INC [GetPcFlag]
        MOV ESP, SavedESP
        POPAD
        RET
    NO_GETPC_%d:
        <rest of shellcode>

    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    CHAR szTestGetPc[MAX_DECODE_BUFFER];
    CHAR szGetPcCheck[] = "    CMP %s, 0x41424344\n"
                          "    JB NO_GETPC\n"
                          "    CMP %s, 0x45464748\n"
                          "    JA NO_GETPC\n"
                          "    MOV EAX, 0x4D4E4F50\n"   /* asmpure wont compile INC [0x4D4E4F50] */
                          "    INC [EAX]\n"             /* SHELLCODE GETPC FLAG */
                          "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "NO_GETPC:\n"
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";   

    ZeroMemory( szTestGetPc, MAX_DECODE_BUFFER );
    sprintf(szTestGetPc, szGetPcCheck , szTargetRegister , szTargetRegister);
    
    if ( ( pCompiledAsm = TranslateAssembly( szTestGetPc, &dwCompiledAsmSize, "MemReadPutGetPcCheck" ) ) != NULL )
    {
        BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
        HeapFree( gProcessHeap, 0,  pCompiledAsm );
        return dwCompiledAsmSize;
    }

    return 0;
}

DWORD MemWritePutGetPcCheck(PCHAR szInst, PCHAR szTargetRegister, DWORD dwInstSize, PSC_BIN_DATA pData)
{
    /*

    FIX : Pushing TempReg in stack change ESP value,
          ESP may be part of a memory write operation
          and changing its value may cause false negative.
          ( but I think we have already detected the get pc
            before this happen! anyway... )
    INFO : memory write is ether a getpc indicator by writing 
           in shellcode memory range or a invalid memory write.
           in both ways we return to caller, but in in getpc case
           we set GetPcFlag before returning.

    GetPC check is performed by following assembly:
        PUSH TempReg
        LEA TempReg, [DstReg]
        CMP TempReg, ShellocdeStartAddress
        JB NO_GETPC
        CMP TempReg, ShellcodeEndAddress
        JA NO_GETPC
        INC [GetPcFlag]
    NO_GETPC_%d:
        POP TempReg
        MOV ESP, SavedESP
        POPAD
        RET
        <rest of shellcode>

    */

    PVOID pCompiledAsm;
    DWORD dwCompiledAsmSize;
    DWORD i;
    CHAR szTestGetPc[MAX_DECODE_BUFFER];
    CHAR szNopOrgInst[MAX_DECODE_BUFFER];
    CHAR szGetPcCheck[] = "    PUSH EAX\n"
                          "    LEA EAX, [%s]\n"
                          "    CMP EAX, 0x41424344\n"
                          "    JB NO_GETPC\n"
                          "    CMP EAX, 0x45464748\n"
                          "    JA NO_GETPC\n"
                          "    MOV EAX, 0x4D4E4F50\n"   /* asmpure wont compile INC [0x4D4E4F50] */
                          "    INC [EAX]\n"             /* SHELLCODE GETPC FLAG */
                          "NO_GETPC:\n"
                          //"    POP EAX\n"
                          "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          //"    %s\n"                    /* this is the actual write inst, for debugging only */
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";

    CHAR szErrorWrite[] = "    MOV EAX, 0x51525354\n"
                          "    MOV ESP, [EAX]\n"        /* SavedESP */
                          "    POPFD\n"
                          "    POPAD\n"
                          "    POP EAX\n"
                          "    JMP EAX\n"
                          "    NOP\n"                   /* nops are for asmpure alignment bug */
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n"
                          "    NOP\n";  

    ZeroMemory( szTestGetPc, MAX_DECODE_BUFFER );
    ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
    for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
    sprintf(szTestGetPc, szGetPcCheck , szTargetRegister, szInst);
    strncat(szNopOrgInst, szTestGetPc, MAX_DECODE_BUFFER);

    if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "MemWritePutGetPcCheck" ) ) == NULL )
    {
        /* probably something is wrong in write mem instruction,
           os we put a error handler here and overwrite the memory]
           write instruction.
        */
        ZeroMemory( szNopOrgInst, MAX_DECODE_BUFFER );
        for( i = 0; i < dwInstSize; i++ ) strncat(szNopOrgInst, "    NOP\n", MAX_DECODE_BUFFER);
        strncat(szNopOrgInst, szErrorWrite, MAX_DECODE_BUFFER);
        if ( ( pCompiledAsm = TranslateAssembly( szNopOrgInst, &dwCompiledAsmSize, "MemWritePutGetPcCheck" ) ) != NULL )
        {
            BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
            HeapFree( gProcessHeap, 0,  pCompiledAsm );
            return dwCompiledAsmSize;
        }

        return 0;
    }

    BinDataAppend(pData, (PBYTE)pCompiledAsm, dwCompiledAsmSize );
    HeapFree( gProcessHeap, 0,  pCompiledAsm );
    return dwCompiledAsmSize;
}

VOID BranchAddShortToLongOverhead( PSC_BIN_DATA ShellcodeData, SC_BRANCH_LOC BranchLoc[], DWORD dwBranchLocSize, SC_CHECK_LOC CheckLoc[], PDWORD dwCheckLocSize )
{
    DWORD i, j;
    DWORD dwFreeCheckLoc;
    DWORD dwBranchOffsetChange;
    DWORD dwGapDataSize;
    LPVOID BaseAddress , SourceAddress;
    DWORD dwLongBranchSize;
    int BranchChanges;
    signed short BranchOffset;

    dwFreeCheckLoc = *dwCheckLocSize + 1;

    for ( i = 0; i < dwBranchLocSize; i++ )
    {
        BranchChanges = 0;
        dwBranchOffsetChange = 0;

        if ( BranchLoc[i].Type == SHORT_BRANCH )
        {
            for ( j = 0; j < *dwCheckLocSize; j++ )
            {
                /* backward branch */
                if ( CheckLoc[j].dwCheckLocation < BranchLoc[i].dwBranchAddress && CheckLoc[j].dwCheckLocation > BranchLoc[i].BranchTarget )
                {
                    BranchChanges +=  CheckLoc[j].dwCheckSize;
                }

                /* forward branch */
                if ( CheckLoc[j].dwCheckLocation > BranchLoc[i].dwBranchAddress && CheckLoc[j].dwCheckLocation < BranchLoc[i].BranchTarget )
                {
                    BranchChanges +=  CheckLoc[j].dwCheckSize;
                }

                /* branch offset changes */
                if ( CheckLoc[j].dwCheckLocation <= BranchLoc[i].dwBranchAddress )
                {
                    dwBranchOffsetChange += CheckLoc[j].dwCheckSize;
                }
            }

            if ( BranchChanges != 0 )
            {
                 /* backward branch */
                if ( BranchLoc[i].dwBranchAddress > BranchLoc[i].BranchTarget )
                {
                    BranchOffset = ( BranchLoc[i].ShortBranchOp + ( 0xFFFF - BranchChanges + 0x01 ) ) & 0x0000FFFF;
                    if ( BranchOffset < -128 )
                    {
                        /* set short branch to long branch overhead and fill the gap */
                        dwLongBranchSize = IS_MEM_SHORT_CN_BRANCH((BYTE)(ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange)) ? LONG_CN_BRANCH_SIZE : LONG_BRANCH_SIZE;
                        CheckLoc[dwFreeCheckLoc].dwCheckLocation = ( BranchLoc[i].dwBranchAddress + SHORT_BRANCH_SIZE );
                        CheckLoc[dwFreeCheckLoc].dwCheckSize     = ( dwLongBranchSize - SHORT_BRANCH_SIZE );
                        BaseAddress   = (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + dwLongBranchSize  );
                        SourceAddress = (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_SIZE );
                        dwGapDataSize = ShellcodeData->dwCount  - (BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_SIZE);
                        memcpy( BaseAddress , SourceAddress, ShellcodeData->dwCount  );
                        memset( SourceAddress, NOP_INST, ( dwLongBranchSize - SHORT_BRANCH_SIZE ));
                        ShellcodeData->dwCount += ( dwLongBranchSize - SHORT_BRANCH_SIZE );
                        dwFreeCheckLoc++;
                        *dwCheckLocSize++;
                    }
                }
                /* forward branch */
                else
                {
                    BranchOffset = BranchLoc[i].ShortBranchOp & 0x0000FFFF;
                    if ( BranchOffset > 128 )
                    {
                        /* set short branch to long branch overhead and fill the gap */
                        dwLongBranchSize = IS_MEM_SHORT_CN_BRANCH((BYTE)(ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange)) ? LONG_CN_BRANCH_SIZE : LONG_BRANCH_SIZE;
                        CheckLoc[dwFreeCheckLoc].dwCheckLocation = ( BranchLoc[i].dwBranchAddress + SHORT_BRANCH_SIZE );
                        CheckLoc[dwFreeCheckLoc].dwCheckSize     = ( dwLongBranchSize - SHORT_BRANCH_SIZE );
                        BaseAddress   = (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + dwLongBranchSize  );
                        SourceAddress = (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_SIZE );
                        dwGapDataSize = ShellcodeData->dwCount  - (BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_SIZE);
                        memcpy( BaseAddress , SourceAddress, ShellcodeData->dwCount );
                        memset( SourceAddress, NOP_INST, ( dwLongBranchSize - SHORT_BRANCH_SIZE ));
                        ShellcodeData->dwCount += ( dwLongBranchSize - SHORT_BRANCH_SIZE );
                        dwFreeCheckLoc++;
                        *dwCheckLocSize++;
                    }
                }
            }
        }
    }
}

BOOL GetLongBranch(BYTE Branch, PBYTE Buffer, INT Target, PDWORD pdwSize)
{   
    switch ( Branch )
    {
        case 0x70: /* JO */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x800F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x71: /* JNO */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x810F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x72: /* JB, JANE, JC */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x820F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x73: /* JNB, JAE, JNC */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x830F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x74: /* JZ, JE */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x840F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x75: /* JNZ, JNE */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x850F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x76: /* JBE, JNA */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x860F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x77: /* JNBE, JA */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x870F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x78: /* JS */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x880F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x79: /* JNS */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x890F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7A: /* JP, JPE */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8A0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7B: /* JNP, JPO */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8B0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7C: /* JL, JNGE */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8C0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7D: /* JNL, JGE */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8D0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7E: /* JLE, JNG */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8E0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
        case 0x7F: /* JNLE, JG */
            *pdwSize = LONG_CN_BRANCH_SIZE;
            *(WORD *)Buffer = 0x8F0F;
            memcpy( (LPVOID)( Buffer + LONG_CN_BRANCH_BYTE), &Target, sizeof(Target));
            return TRUE;
    }

    return FALSE;
}

VOID UpdateBranchLocations( PSC_BIN_DATA ShellcodeData , SC_BRANCH_LOC BranchLoc[], DWORD dwBranchLocSize, SC_CHECK_LOC CheckLoc[], DWORD dwCheckLocSize)
{
    /* FIX : fix it for short jumps that changes to long jump
       The first byte of a SHORT Jump is always EB and the second is a relative offset 
       from 00h to 7Fh for Forward jumps, and from 80h to FFh for Reverse (or Backward) jumps.
       ref : http://thestarman.narod.ru/asm/2bytejumps.htm
    */
    DWORD i, j;
    DWORD dwBranchOffsetChange;
    INT BranchChanges;
    signed int LongBranchOffset;
    signed short ShortBranchOffset;
    BYTE LongBranch[16];
    DWORD LongBranchSize;

    //BranchAddShortToLongOverhead( ShellcodeData, BranchLoc, dwBranchLocSize, CheckLoc, &dwCheckLocSize);

    for ( i = 0; i < dwBranchLocSize; i++ )
    {
        BranchChanges = 0;
        dwBranchOffsetChange = 0;

        for ( j = 0; j < dwCheckLocSize; j++ )
        {
            /* backward branch */
            if ( CheckLoc[j].dwCheckLocation < BranchLoc[i].dwBranchAddress && CheckLoc[j].dwCheckLocation >= BranchLoc[i].BranchTarget )
            {
                BranchChanges +=  CheckLoc[j].dwCheckSize;
            }

            /* forward branch */
            if ( CheckLoc[j].dwCheckLocation > BranchLoc[i].dwBranchAddress && CheckLoc[j].dwCheckLocation <= BranchLoc[i].BranchTarget )
            {
                BranchChanges +=  CheckLoc[j].dwCheckSize;
            }

            /* branch offset changes */
            if ( CheckLoc[j].dwCheckLocation <= BranchLoc[i].dwBranchAddress )
            {
                dwBranchOffsetChange += CheckLoc[j].dwCheckSize;
            }
        }

        if ( BranchChanges != 0 )
        {
            if ( BranchLoc[i].Type == SHORT_BRANCH )
            {
                /* backward branch */
                if ( BranchLoc[i].dwBranchAddress > BranchLoc[i].BranchTarget )
                {
                    ShortBranchOffset = ( BranchLoc[i].ShortBranchOp + ( 0xFFFF - BranchChanges + 0x01 ) ) & 0x0000FFFF;
                    if ( ShortBranchOffset < -128 )
                    {
                        GetLongBranch( *(BYTE *)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange ), LongBranch, ShortBranchOffset - LONG_ADDRESS_SIZE, &LongBranchSize);
                        memcpy( (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange ) , LongBranch, LongBranchSize);
                    }
                    else
                    {
                        memcpy( (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_BYTE ) , &ShortBranchOffset, SHORT_BRANCH_BYTE);
                    }
                }
                /* forward branch */
                else
                {
                    ShortBranchOffset = ( BranchLoc[i].ShortBranchOp + BranchChanges ) & 0x0000FFFF;
                    if ( ShortBranchOffset > 128 )
                    {
                        GetLongBranch( *(BYTE *)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange ), LongBranch, ShortBranchOffset - LONG_ADDRESS_SIZE, &LongBranchSize);
                        memcpy( (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange ) , LongBranch, LongBranchSize);
                    }
                    else
                    {
                        memcpy( (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + SHORT_BRANCH_BYTE ) , &ShortBranchOffset, SHORT_BRANCH_BYTE );
                    }
                }
            }
            else if ( BranchLoc[i].Type == LONG_BRANCH )
            {
                /* convert endianness */
                LongBranchSize = IS_MEM_LONG_CN_BRANCH(ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange) ? LONG_CN_BRANCH_BYTE : LONG_BRANCH_BYTE;
                LongBranchOffset = ( BranchLoc[i].LongBranchOp  + BranchChanges );
                memcpy( (PVOID)( ShellcodeData->Data + BranchLoc[i].dwBranchAddress + dwBranchOffsetChange + LongBranchSize ), &LongBranchOffset, LONG_ADDRESS_SIZE);
            }
        }
    }
    
}