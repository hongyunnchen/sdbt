//=====================================================================
//
// casmpure.h - assembly pure compiler
//
// NOTE:
// for more information, please see the readme file.
//
//=====================================================================
#ifndef __CASMPURE_H__
#define __CASMPURE_H__

#include "cloader.h"
#include "cparser.h"
#pragma once


//---------------------------------------------------------------------
// CAssembler Definition
//---------------------------------------------------------------------
struct CAssembler
{
	CParser *parser;
	CLoader *loader;
	int srcblock;
	int srcsize;
	char *line;
	char *source;
	char *error;
	int errcode;
	int lineno;
};

typedef struct CAssembler CAssembler; 



#ifdef __cplusplus
extern "C" {
#endif
//---------------------------------------------------------------------
// Interface
//---------------------------------------------------------------------

// create assembler
CAssembler *casm_create(void);

// delete assembler
void casm_release(CAssembler *self);

// reset compiler state and clean source buffer
void casm_reset(CAssembler *self);

// add source to assembler source buffer
int casm_source(CAssembler *self, const char *text);

// compile source buffer
// if (code == NULL) returns compiled code size
// if (code != NULL) and (maxsize >= codesize) compile and returns codesize
// if (code != NULL) and (maxsize < codesize) returns error
int casm_compile(CAssembler *self, unsigned char *code, long maxsize);

// get error
const char *casm_geterror(CAssembler *self, int *errcode);


// HIGH LEVEL interface:

// add a single line to assembly
int casm_pushline(CAssembler *self, const char *fmt, ...);

// compile and write execode into a memory block
// you can call free() when you need to dispose
void *casm_callable(CAssembler *self, long *codesize);


// load assembly source file (will reset source buffer)
int casm_loadfile(CAssembler *self, const char *filename);

// save compiled code into file
int casm_savefile(CAssembler *self, const char *filename);

// dump instructions and source line 
int casm_dumpinst(CAssembler *self, FILE *fp);


#ifdef __cplusplus
}
#endif

#endif


