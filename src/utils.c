#include "..\include\utils.h"

char * str_replace ( const char *string, const char *substr, const char *replacement )
{
  char *tok = NULL;
  char *newstr = NULL;
  char *oldstr = NULL;
  /* if either substr or replacement is NULL, duplicate string a let caller handle it */
  if ( substr == NULL || replacement == NULL ) return _strdup (string);
  newstr = _strdup (string);
  while ( (tok = strstr ( newstr, substr ))){
    oldstr = newstr;
    newstr = (char *)malloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 );
    /*failed to alloc mem, free old string and return NULL */
    if ( newstr == NULL ){
      free (oldstr);
      return NULL;
    }
    memcpy ( newstr, oldstr, tok - oldstr );
    memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
    memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
    memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
    free (oldstr);
  }
  return newstr;
}

PBYTE StringToByteArray(PBYTE Result, PCHAR szString, DWORD dwSize )
{
    CHAR szByteChar[3];
    DWORD i,j;

    for ( i = 0, j = 0; i <= (dwSize-2); i +=2, j++)
    {
        memset(szByteChar, 0, 3 );
        memcpy(szByteChar, (szString+i), 2);
        Result[j] = strtoul((const char*)szByteChar, NULL, 16);
    }

    return Result;
}


VOID BinDataAppend(PSC_BIN_DATA BinData, PBYTE NewData, DWORD dwSize)
{
    memcpy( (BinData->Data + BinData->dwCount), NewData, dwSize);
    BinData->dwCount += dwSize;
}

VOID BinDataDump(PCHAR szFileName, PSC_BIN_DATA BinData)
{
    FILE *fp;
    fp = fopen(szFileName, "wb");
    if ( fp != NULL )
    {
        fwrite(BinData->Data, BinData->dwCount, 1, fp);
        fclose(fp);
        return;
    }
}

VOID DisassDataDump(PCHAR szFileName, PCHAR * DisassData, DWORD dwSize)
{
    DWORD i = 0;
    FILE *fp;
    CHAR szData[1024];

    fp = fopen(szFileName, "w");

    if ( fp != NULL )
    {
        while ( i <= dwSize )
        {
            if ( *DisassData[i] )
            {
                ZeroMemory( szData, 1024 );
                _snprintf(szData, 1024, "\t%s\n", DisassData[i]);
                fwrite(szData, strlen(szData), 1, fp);
            }

            i++;
        }

        fclose(fp);
        return;
    }
}

VOID DumpBranchInfo( BRANCH_TYPE Type, DWORD dwOp, DWORD dwOffset )
{
    printf("----------- BRANCH INFO -----------\n");
    printf("Branch Type : %s\n", Type == SHORT_BRANCH ? "SHORT_BRANCH" : "LONG_BRANCH");
    Type == SHORT_BRANCH ? printf("Branch New Op : %.2x\n", dwOp) : printf("Branch New Op : %.8x\n", dwOp);
    printf("Branch New Offset : %.8x\n\n", dwOffset);
}