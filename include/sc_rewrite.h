#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "utils.h"
#pragma once

#define CHECK_SIZE_LIMIT 30

BOOL IsReg32(PCHAR szReg);
BOOL IsMemOp(PCHAR szReg);
BOOL IsMemoryRead(PCHAR szInst, PCHAR szDestReg );
BOOL IsMemoryWrite(PCHAR szInst, PCHAR szDestReg );
BOOL IsNoneMemoryBranch(PCHAR szInst, PCHAR szDestReg);
BOOL IsMemoryBranch(PCHAR szInst, PCHAR szDestReg);
DWORD MemReadPutGetPcCheck(PCHAR szTargetRegister, PSC_BIN_DATA pData);
DWORD MemWritePutGetPcCheck(PCHAR szInst, PCHAR szTargetRegister, DWORD dwInstSize, PSC_BIN_DATA pData);
DWORD BranchRegPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister, PSC_BIN_DATA pData);
DWORD BranchMemRegPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister,  DWORD dwInstSize, PSC_BIN_DATA pData);
DWORD BranchPutOutOfBoundErrorHandler(PCHAR szInst,  DWORD dwInstSize, PSC_BIN_DATA pData);
DWORD BranchRetPutBoundCheck(PCHAR szInst, PSC_BIN_DATA pData);
DWORD FilterIllegalInstruction(DWORD dwInstSize, PSC_BIN_DATA pData);
BOOL IsIllegalInstruction(PCHAR szInst);
DWORD IsStackManipulation(PCHAR szInst, PCHAR szDestReg );
DWORD StackPutBoundCheck(PCHAR szInst, PCHAR szTargetRegister,  DWORD dwInstSize, PSC_BIN_DATA pData, DWORD dwType);
VOID UpdateBranchLocations( PSC_BIN_DATA ShellcodeData , SC_BRANCH_LOC BranchLoc[], DWORD dwBranchLocSize, SC_CHECK_LOC CheckLoc[], DWORD dwCheckLocSize);