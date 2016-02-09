//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// file_decomp.h author Ed Borgoyn eborgoyn@sourcefire.com

#ifndef FILE_DECOMP_H
#define FILE_DECOMP_H

// File_Decomp global typedefs (used in child objects)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <string.h>

#include "main/snort_types.h"

/* Function return codes used internally and with caller */
typedef enum fd_status
{
    File_Decomp_DecompError = -2,  /* Error from decompression */
    File_Decomp_Error = -1,        /* Error from decompression */
    File_Decomp_OK = 0,
    File_Decomp_NoSig = 1,         /* No file signature located */
    File_Decomp_Complete = 2,      /* Completed */
    File_Decomp_BlockOut = 3,      /* Blocked due to lack of output space */
    File_Decomp_BlockIn = 4,       /* Blocked due to lack in input data */
    File_Decomp_Eof = 5            /* End of file located */
} fd_status_t;

typedef enum file_compression_type
{
    FILE_COMPRESSION_TYPE_NONE,
    FILE_COMPRESSION_TYPE_DEFLATE,
    FILE_COMPRESSION_TYPE_ZLIB,
    FILE_COMPRESSION_TYPE_LZMA,
    FILE_COMPRESSION_TYPE_MAX
} file_compression_type_t;

typedef struct fd_session_s* fd_session_p_t, fd_session_t;

#include "file_decomp_pdf.h"
#include "file_decomp_swf.h"
#include <zlib.h>

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

/* Potential decompression modes, passed in at initalization time. */
#define FILE_SWF_LZMA_BIT    (0x00000001)
#define FILE_SWF_ZLIB_BIT    (0x00000002)
#define FILE_PDF_DEFL_BIT    (0x00000004)

/* The FILE_REVERT and FILT_NORM functionality is currently not implemented */
#define FILE_FILT_NORM_BIT   (0x40000000)    /* Normalize the PDF /Filter value string */
#define FILE_REVERT_BIT      (0x80000000)    /* Revert to 'uncompressed' state */

#define FILE_PDF_ANY         (FILE_PDF_DEFL_BIT)
#define FILE_SWF_ANY         (FILE_SWF_LZMA_BIT | FILE_SWF_ZLIB_BIT)

/* Error codes either passed to caller via the session->Error_Alert of
   the File_Decomp_Alert() call-back function. */
enum FileDecompError
{
    FILE_DECOMP_ERR_SWF_ZLIB_FAILURE,
    FILE_DECOMP_ERR_SWF_LZMA_FAILURE,
    FILE_DECOMP_ERR_PDF_DEFL_FAILURE,
    FILE_DECOMP_ERR_PDF_UNSUP_COMP_TYPE,
    FILE_DECOMP_ERR_PDF_CASC_COMP,
    FILE_DECOMP_ERR_PDF_PARSE_FAILURE
};

/* Private Types */
typedef enum file_type
{
    FILE_TYPE_NONE,
    FILE_TYPE_SWF,
    FILE_TYPE_PDF,
    FILE_TYPE_MAX
} file_type_t;

typedef enum states
{
    STATE_NEW,        /* Session created */
    STATE_READY,      /* Session created and ready for content, no file/decomp selected */
    STATE_ACTIVE,     /* Decompressor inited and ready for content */
    STATE_COMPLETE    /* Decompression completed */
} fd_states_t;

/* Primary file decompression session state context */
struct fd_session_s
{
    uint8_t* Next_In;   /* next input byte */
    uint32_t Avail_In;  /* number of bytes available at next_in */
    uint32_t Total_In;  /* total number of input bytes read so far */

    uint8_t* Next_Out;  /* next output byte should be put there */
    uint32_t Avail_Out; /* remaining free space at next_out */
    uint32_t Total_Out; /* total number of bytes output so far */

    /* Internal buffer setup by _Init().  App can overide. */
    uint8_t* Buffer;    /* pointer to decompresiion buffer */
    uint32_t Buffer_Len; /* length of decompression buffer */

    /* Configuration settings */
    uint32_t Compr_Depth;
    uint32_t Decompr_Depth;
    uint32_t Modes;     /* Bit mapped set of potential file/algo modes */

    /* Alerting callback */
    void (* Alert_Callback)(void* Context, int Event);
    void* Alert_Context;

    /* Internal State */
    uint8_t File_Type;   /* Active file type */
    uint8_t Decomp_Type; /* Active decompression type */
    uint8_t Sig_State;   /* Sig search state machine */
    uint8_t State;       /* main state machine */

    union
    {
        fd_PDF_t PDF;
        fd_SWF_t SWF;
    } Decomp_State;

    /* Specific event indicated by DecomprError return */
    int Error_Event;
};

/* Macros */

/* Macros used to sync my decompression context with that
   of the underlying decompression engine context. */
#ifndef SYNC_IN
#define SYNC_IN(dest) \
    dest->next_in = SessionPtr->Next_In; \
    dest->avail_in = SessionPtr->Avail_In; \
    dest->total_in = SessionPtr->Total_In; \
    dest->next_out = SessionPtr->Next_Out; \
    dest->avail_out = SessionPtr->Avail_Out; \
    dest->total_out = SessionPtr->Total_Out;
#endif

#ifndef SYNC_OUT
#define SYNC_OUT(src) \
    SessionPtr->Next_In = (uint8_t*)src->next_in; \
    SessionPtr->Avail_In = src->avail_in; \
    SessionPtr->Total_In = src->total_in; \
    SessionPtr->Next_Out = (uint8_t*)src->next_out; \
    SessionPtr->Avail_Out = src->avail_out; \
    SessionPtr->Total_Out = src->total_out;
#endif

/* Inline Functions */

/* If available, look at the next available byte in the input queue */
inline bool Peek_1(fd_session_p_t SessionPtr, uint8_t* c)
{
    if ( (SessionPtr->Next_In != NULL) && (SessionPtr->Avail_In > 0) )
    {
        *c = *(SessionPtr->Next_In);
        return( true );
    }
    else
        return( false );
}

/* If available, get a byte from the input queue */
inline bool Get_1(fd_session_p_t SessionPtr, uint8_t* c)
{
    if ( (SessionPtr->Next_In != NULL) && (SessionPtr->Avail_In > 0) )
    {
        *c = *(SessionPtr->Next_In)++;
        SessionPtr->Avail_In -= 1;
        SessionPtr->Total_In += 1;
        return( true );
    }
    else
        return( false );
}

/* If available, get N bytes from the input queue.  All N must be
   availble for this call to succeed. */
inline bool Get_N(fd_session_p_t SessionPtr, uint8_t** c, uint16_t N)
{
    if ( (SessionPtr->Next_In != NULL) && (SessionPtr->Avail_In >= N) )
    {
        *c = SessionPtr->Next_In;
        SessionPtr->Next_In += N;
        SessionPtr->Avail_In -= N;
        SessionPtr->Total_In += N;
        return( true );
    }
    else
        return( false );
}

/* If there's room in the output queue, put one byte. */
inline bool Put_1(fd_session_p_t SessionPtr, uint8_t c)
{
    if ( (SessionPtr->Next_Out != NULL) && (SessionPtr->Avail_Out > 0) )
    {
        *(SessionPtr->Next_Out)++ = c;
        SessionPtr->Avail_Out -= 1;
        SessionPtr->Total_Out += 1;
        return( true );
    }
    else
        return( false );
}

/* If the output queue has room available, place N bytes onto the queue.
   The output queue must have space for N bytes for this call to succeed. */
inline bool Put_N(fd_session_p_t SessionPtr, uint8_t* c, uint16_t N)
{
    if ( (SessionPtr->Next_Out != NULL) && (SessionPtr->Avail_Out >= N) )
    {
        strncpy( (char*)SessionPtr->Next_Out, (const char*)c, N);
        SessionPtr->Next_Out += N;
        SessionPtr->Avail_Out -= N;
        SessionPtr->Total_Out += N;
        return( true );
    }
    else
        return( false );
}

/* If the input queue has at least one byte available AND there's at
   space for at least one byte in the output queue, then move one byte. */
inline bool Move_1(fd_session_p_t SessionPtr)
{
    if ( (SessionPtr->Next_Out != NULL) && (SessionPtr->Avail_Out > 0) &&
        (SessionPtr->Next_In != NULL) && (SessionPtr->Avail_In > 0) )
    {
        *(SessionPtr->Next_Out) = *(SessionPtr->Next_In);
        SessionPtr->Next_Out += 1;
        SessionPtr->Next_In += 1;
        SessionPtr->Avail_In -= 1;
        SessionPtr->Avail_Out -= 1;
        SessionPtr->Total_In += 1;
        SessionPtr->Total_Out += 1;
        return( true );
    }
    else
        return( false );
}

/* If the input queue has at least N bytes available AND there's at
   space for at least N bytes in the output queue, then move all N bytes. */
inline bool Move_N(fd_session_p_t SessionPtr, uint16_t N)
{
    if ( (SessionPtr->Next_Out != NULL) && (SessionPtr->Avail_Out >= N) &&
        (SessionPtr->Next_In != NULL) && (SessionPtr->Avail_In >= N) )
    {
        strncpy( (char*)SessionPtr->Next_Out, (const char*)SessionPtr->Next_In, N);
        SessionPtr->Next_Out += N;
        SessionPtr->Next_In += N;
        SessionPtr->Avail_In -= N;
        SessionPtr->Avail_Out -= N;
        SessionPtr->Avail_Out -= N;
        SessionPtr->Total_Out += N;
        return( true );
    }
    else
        return( false );
}

/* API Functions */

/* Create a new decompression session object */
fd_session_p_t SO_PUBLIC File_Decomp_New();

/* Initialize the session */
fd_status_t SO_PUBLIC File_Decomp_Init(fd_session_p_t SessionPtr);

/* Use an internal decompression buffer */
fd_status_t SO_PUBLIC File_Decomp_SetBuf(fd_session_p_t SessionPtr);

/* Run the incremental decompression engine */
fd_status_t SO_PUBLIC File_Decomp(fd_session_p_t SessionPtr);

/* Close the decomp session processing */
fd_status_t SO_PUBLIC File_Decomp_End(fd_session_p_t SessionPtr);

/* Close the current decomp session, but setup for another */
fd_status_t SO_PUBLIC File_Decomp_Reset(fd_session_p_t SessionPtr);

/* Abort and delete the session */
fd_status_t SO_PUBLIC File_Decomp_StopFree(fd_session_p_t SessionPtr);

/* Delete the session object */
void SO_PUBLIC File_Decomp_Free(fd_session_p_t SessionPtr);

/* Call the error alerting call-back function */
void SO_PUBLIC File_Decomp_Alert(fd_session_p_t SessionPtr, int Event);
#endif

