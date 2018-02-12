//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// file_decomp_pdf.h author Ed Borgoyn eborgoyn@sourcefire.com

#ifndef FILE_DECOMP_PDF_H
#define FILE_DECOMP_PDF_H

#include <zlib.h>

#include "file_decomp.h"

#define ELEM_BUF_LEN        (12)
#define FILTER_SPEC_BUF_LEN (40)
#define PARSE_STACK_LEN     (12)

/* FIXIT-L Other than the API prototypes, the other parts of this header should
   be private to file_decomp_pdf. */

enum fd_PDF_States
{
    PDF_STATE_NEW,
    PDF_STATE_LOCATE_STREAM,     /* Found sig bytes, looking for dictionary & stream*/
    PDF_STATE_INIT_STREAM,       /* Init stream */
    PDF_STATE_PROCESS_STREAM     /* Processing stream */
};

struct fd_PDF_Parse_Stack_t
{
    uint8_t State;
    uint8_t Sub_State;
};

struct fd_PDF_Parse_t
{
    const uint8_t* xref_tok;
    uint32_t Obj_Number;
    uint32_t Gen_Number;
    uint8_t Parse_Stack_Index;
    uint8_t Sub_State;
    uint8_t State;
    uint8_t Dict_Nesting_Cnt;
    uint8_t Elem_Index;
    uint8_t Filter_Spec_Index;
    uint8_t Elem_Buf[ELEM_BUF_LEN];
    uint8_t Filter_Spec_Buf[FILTER_SPEC_BUF_LEN+1];
    fd_PDF_Parse_Stack_t Parse_Stack[PARSE_STACK_LEN];
};

struct fd_PDF_Deflate_t
{
    z_stream StreamDeflate;
};

struct fd_PDF_t
{
    union
    {
        fd_PDF_Deflate_t Deflate;
    } PDF_Decomp_State;
    fd_PDF_Parse_t Parse;
    uint8_t Decomp_Type;
    uint8_t State;
};

// FIXIT-L don't obfuscate pointers
typedef fd_PDF_Parse_Stack_t* fd_PDF_Parse_Stack_p_t;
typedef fd_PDF_Parse_t* fd_PDF_Parse_p_t;
typedef fd_PDF_t* fd_PDF_p_t;

/* API Functions */

/* Init the PDF decompressor */
fd_status_t File_Decomp_Init_PDF(fd_session_t*);

/* Run the incremental PDF file parser/decompressor */
fd_status_t File_Decomp_End_PDF(fd_session_t*);

/* End the decompressor */
fd_status_t File_Decomp_PDF(fd_session_t*);

#endif

