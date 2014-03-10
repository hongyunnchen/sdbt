#include <Windows.h>
#include "..\libs\asmpure\asmpure.h"
#include "..\include\utils.h"
#pragma once

PVOID TranslateAssembly(PCHAR szAsmString, PDWORD dwSize, PCHAR szFunctionName);
PSC_BIN_DATA TranslateCode(PBYTE dwCode, DWORD dwCodeSize, BOOL bDumpBinary, PCHAR szBinFile, BOOL bDumpDisass, PCHAR szDisassFile);