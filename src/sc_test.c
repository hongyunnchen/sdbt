#include "..\include\sc_test.h"

extern BOOL bGetPcDetected;
extern DWORD dwThreadCount;
LPVOID SavedEsp;
LPVOID SavedEax;

VOID GetStackBoundaries( PDWORD dwLow, PDWORD dwHigh )
{
    PNT_TIB ThreadInfo;

    /* get the thread stack range from TIB. */
    ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );

    *dwHigh  = (DWORD)ThreadInfo->StackBase;
    *dwLow = (DWORD)ThreadInfo->StackLimit;
}


VOID InitTestEnv(PSHELLCODE_DATA pShellData, BOOL ExecStack, PBYTE ShellcodeBuffer, DWORD dwShellcodeSize, LPVOID GetPcFlag, BOOL bAllocStack)
{
    pShellData->bExecutableStack       = ExecStack;
    pShellData->lpGetPcFlag            = GetPcFlag;
    pShellData->dwShellcodeSize        = dwShellcodeSize;
    pShellData->ShellcodeBuffer        = ShellcodeBuffer; 
}

LONG WINAPI ShellcodeUnhandledExceptionFilter(DWORD dwExceptionCode, struct _EXCEPTION_POINTERS *pExceptionPointer) 
{
    /*
    switch (dwExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION :
        printf("Exception Type : EXCEPTION_ACCESS_VIOLATION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;                         
    case EXCEPTION_DATATYPE_MISALIGNMENT :
        printf("Exception Type : EXCEPTION_DATATYPE_MISALIGNMENT\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED :    
        printf("Exception Type : EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_DENORMAL_OPERAND :
        printf("Exception Type : EXCEPTION_FLT_DENORMAL_OPERAND\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_DIVIDE_BY_ZERO :
        printf("Exception Type : EXCEPTION_FLT_DIVIDE_BY_ZERO\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_INEXACT_RESULT :
        printf("Exception Type : EXCEPTION_FLT_INEXACT_RESULT\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_INVALID_OPERATION :
        printf("Exception Type : EXCEPTION_FLT_INVALID_OPERATION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_OVERFLOW :    
        printf("Exception Type : EXCEPTION_FLT_OVERFLOW\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_STACK_CHECK :  
        printf("Exception Type : EXCEPTION_FLT_STACK_CHECK\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_FLT_UNDERFLOW :      
        printf("Exception Type : EXCEPTION_FLT_UNDERFLOW\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_INT_DIVIDE_BY_ZERO :  
        printf("Exception Type : EXCEPTION_INT_DIVIDE_BY_ZERO\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_INT_OVERFLOW :     
        printf("Exception Type : EXCEPTION_INT_OVERFLOW\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_PRIV_INSTRUCTION :    
        printf("Exception Type : EXCEPTION_PRIV_INSTRUCTION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_IN_PAGE_ERROR :          
        printf("Exception Type : EXCEPTION_IN_PAGE_ERROR\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_ILLEGAL_INSTRUCTION :      
        printf("Exception Type : EXCEPTION_ILLEGAL_INSTRUCTION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_NONCONTINUABLE_EXCEPTION : 
        printf("Exception Type : EXCEPTION_NONCONTINUABLE_EXCEPTION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_STACK_OVERFLOW :        
        printf("Exception Type : EXCEPTION_STACK_OVERFLOW\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_INVALID_DISPOSITION :      
        printf("Exception Type : EXCEPTION_INVALID_DISPOSITION\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_GUARD_PAGE :  
        printf("Exception Type : EXCEPTION_GUARD_PAGE\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    case EXCEPTION_INVALID_HANDLE :       
        printf("Exception Type : EXCEPTION_INVALID_HANDLE\n Address : 0x%p\n", pExceptionPointer->ExceptionRecord->ExceptionAddress);
        break;  
    }
    */
    /*
    __asm MOV ESP, SavedEsp
    __asm POPFD
    __asm POPAD
    __asm POP EAX
    __asm MOV EAX, SavedEax
    */
    dwThreadCount--;
    TerminateThread( GetCurrentThread(), -1);
    return EXCEPTION_EXECUTE_HANDLER;

} 

VOID LoadShellcode(PSHELLCODE_DATA ShellExecData)
{
    DWORD dwStartAddress, dwEndAddress;
    DWORD dwStackBase,dwStackLimit, dwStackSize;
    DWORD i,j;
    DWORD dwOldProtect;
    LPVOID lpShellcodeStack;
    LPVOID lpFakeStackBase;
    LPVOID lpFakeStackLimit;
    BYTE FixAddress[ADDR_32];
    PBYTE FixedBuffer;

    bGetPcDetected = FALSE;
    FixedBuffer    = ShellExecData->ShellcodeBuffer;
    dwStartAddress = (DWORD)ShellExecData->ShellcodeBuffer;
    dwEndAddress   = (DWORD)ShellExecData->ShellcodeBuffer + ShellExecData->dwShellcodeSize;
    
    /* allocate the fake stack */
    lpFakeStackBase  = VirtualAlloc( NULL, _1Megabyte_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    lpFakeStackLimit = (LPVOID)((DWORD)lpFakeStackBase + _1Megabyte_ - 10240);
    lpShellcodeStack = (LPVOID)((DWORD)lpFakeStackBase + STACK_MIDDLE);

    /* mark shellcode address as executable */
    VirtualProtect( (LPVOID)ShellExecData->ShellcodeBuffer, ShellExecData->dwShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    /* make stack executable */
    if ( ShellExecData->bExecutableStack )
        VirtualProtect( lpFakeStackBase, _1Megabyte_, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    
    for ( i = 0 ; i < ShellExecData->dwShellcodeSize ; i++)
    {
        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), START_ADDRESS, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( dwStartAddress >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }

        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), END_ADDRESS, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( dwEndAddress >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }

        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), GETPC_FLAG, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( (DWORD)ShellExecData->lpGetPcFlag >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }

        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), SAVED_ESP, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( (DWORD)&SavedEsp >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }

        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), STACK_BASE, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( (DWORD)lpFakeStackBase >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }

        if ( !memcmp( (const void *)(ShellExecData->ShellcodeBuffer+i), STACK_LIMIT, ADDR_32 ) )
        {
            for ( j = 0; j <= ADDR_32-1 ; j++ ) FixAddress[j] = (BYTE)( ( (DWORD)lpFakeStackLimit >> ( j * ADDR_32*2 ) ) & ADDR_32_MASK );
            RtlCopyMemory( (void *)(ShellExecData->ShellcodeBuffer+i), FixAddress, sizeof(FixAddress) );
        }
    }
    
    __try{
        /* execute shellcode */
        __asm PUSH END_LOC              /* save return address                  */
        __asm PUSHAD                    /* save general purpose registers       */
        __asm PUSHFD                    /* save eflags register                 */
        __asm MOV  SavedEsp, ESP        /* save original stack pointer          */
        __asm MOV  SavedEax, EAX        /* save EAX value                       */
        __asm MOV  ESP, lpShellcodeStack/* setup fake stack                     */
        __asm MOV  EAX, FixedBuffer     /* load ebp with shellcode buffer       */
        __asm MOV  [ESP + 0x0c], ESP    /* restore esp to fake stack            */
        __asm MOV  [ESP + 0x08], EAX    /* restore ebp to shellcode buffer      */
        __asm POPAD                     /* null out all register                */
        __asm POPFD                     /* null out eflags                      */
        __asm PUSH EBP                  /* load the shellcode buffer            */
        __asm XOR  EBP, EBP             /* null out ebp                         */
        __asm RET                       /* execute                              */
    }
    __except( ShellcodeUnhandledExceptionFilter(GetExceptionCode(), GetExceptionInformation())){}

END_LOC:
    __asm MOV  EAX, SavedEax
    VirtualFree( lpFakeStackBase, _1Megabyte_, MEM_RELEASE);
    //TerminateThread( GetCurrentThread(), -1);
    return;
}

