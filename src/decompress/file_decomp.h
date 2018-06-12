//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <cstring>

#include "main/snort_types.h"

/* Function return codes used internally and with caller */
// FIXIT-L these need to be split into internal-only codes and things that may be returned to the
// application. The codes used by PDF and SWF should be standardized. PDF is returning BlockIn and
// BlockOut while SWF is using OK. There also needs to be clarity about what Error means and what
// should be done about it. Is it just an indicator of programming error or are there operational
// cases where it occurs? No idea whether Complete and Eof are real things and what should be done
// about them.

enum fd_status_t
{
    File_Decomp_DecompError = -2,  /* Error from decompression */
    File_Decomp_Error = -1,        /* Error from decompression */
    File_Decomp_OK = 0,
    File_Decomp_NoSig = 1,         /* No file signature located */
    File_Decomp_Complete = 2,      /* Completed */
    File_Decomp_BlockOut = 3,      /* Blocked due to lack of output space */
    File_Decomp_BlockIn = 4,       /* Blocked due to lack in input data */
    File_Decomp_Eof = 5            /* End of file located */
};

enum file_compression_type_t
{
    FILE_COMPRESSION_TYPE_NONE,
    FILE_COMPRESSION_TYPE_DEFLATE,
    FILE_COMPRESSION_TYPE_ZLIB,
    FILE_COMPRESSION_TYPE_LZMA,
    FILE_COMPRESSION_TYPE_MAX
};

/* Potential decompression modes, passed in at initialization time. */
#define FILE_SWF_LZMA_BIT    (0x00000001)
#define FILE_SWF_ZLIB_BIT    (0x00000002)
#define FILE_PDF_DEFL_BIT    (0x00000004)

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
enum file_type_t
{
    FILE_TYPE_NONE,
    FILE_TYPE_SWF,
    FILE_TYPE_PDF,
    FILE_TYPE_MAX
};

enum fd_states_t
{
    STATE_NEW,        /* Session created */
    STATE_READY,      /* Session created and ready for content, no file/decomp selected */
    STATE_ACTIVE,     /* Decompressor inited and ready for content */
    STATE_COMPLETE    /* Decompression completed */
};

/* Primary file decompression session state context */
struct fd_session_t
{
    // FIXIT-L replace with abstract base class pointer used for
    // PDF or SWF subclass and eliminate switches on File_Type
    union
    {
        struct fd_PDF_t* PDF;
        struct fd_SWF_t* SWF;
    };

    const uint8_t* Next_In;     // next input byte
    uint8_t* Next_Out;          // next output byte should be put there

    // Alerting callback
    void (* Alert_Callback)(void* Context, int Event);
    void* Alert_Context;

    uint32_t Avail_In;   // number of bytes available at next_in
    uint32_t Total_In;   // total number of input bytes read so far

    uint32_t Avail_Out;  // remaining free space at next_out
    uint32_t Total_Out;  // total number of bytes output so far

    // Configuration settings
    // FIXIT-L Compr_Depth and Decompr_Depth only support OHI and eventually should be removed
    uint32_t Compr_Depth;
    uint32_t Decompr_Depth;
    uint32_t Modes;      // Bit mapped set of potential file/algo modes

    int Error_Event;     // Specific event indicated by DecomprError return

    // Internal State
    uint8_t File_Type;   // Active file type
    uint8_t Decomp_Type; // Active decompression type
    uint8_t Sig_State;   // Sig search state machine
    uint8_t State;       // main state machine
};

/* Macros */

/* Macros used to sync my decompression context with that
   of the underlying decompression engine context. */
#ifndef SYNC_IN
#define SYNC_IN(dest) \
    dest->next_in = const_cast<Bytef*>(SessionPtr->Next_In); \
    (dest)->avail_in = SessionPtr->Avail_In; \
    (dest)->total_in = SessionPtr->Total_In; \
    (dest)->next_out = SessionPtr->Next_Out; \
    (dest)->avail_out = SessionPtr->Avail_Out; \
    (dest)->total_out = SessionPtr->Total_Out;
#endif

#ifndef SYNC_OUT
#define SYNC_OUT(src) \
    SessionPtr->Next_In = (const uint8_t*)(src)->next_in; \
    SessionPtr->Avail_In = (src)->avail_in; \
    SessionPtr->Total_In = (src)->total_in; \
    SessionPtr->Next_Out = (uint8_t*)(src)->next_out; \
    SessionPtr->Avail_Out = (src)->avail_out; \
    SessionPtr->Total_Out = (src)->total_out;
#endif

/* Inline Functions */

/* If available, look at the next available byte in the input queue */
inline bool Peek_1(fd_session_t* SessionPtr, uint8_t* c)
{
    if ( (SessionPtr->Next_In != nullptr) && (SessionPtr->Avail_In > 0) )
    {
        *c = *(SessionPtr->Next_In);
        return( true );
    }
    else
        return( false );
}

/* If available, get a byte from the input queue */
inline bool Get_1(fd_session_t* SessionPtr, uint8_t* c)
{
    if ( (SessionPtr->Next_In != nullptr) && (SessionPtr->Avail_In > 0) )
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
   available for this call to succeed. */
inline bool Get_N(fd_session_t* SessionPtr, const uint8_t** c, uint16_t N)
{
    if ( (SessionPtr->Next_In != nullptr) && (SessionPtr->Avail_In >= N) )
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
inline bool Put_1(fd_session_t* SessionPtr, uint8_t c)
{
    if ( (SessionPtr->Next_Out != nullptr) && (SessionPtr->Avail_Out > 0) )
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
inline bool Put_N(fd_session_t* SessionPtr, const uint8_t* c, uint16_t N)
{
    if ( (SessionPtr->Next_Out != nullptr) && (SessionPtr->Avail_Out >= N) )
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
inline bool Move_1(fd_session_t* SessionPtr)
{
    if ( (SessionPtr->Next_Out != nullptr) && (SessionPtr->Avail_Out > 0) &&
        (SessionPtr->Next_In != nullptr) && (SessionPtr->Avail_In > 0) )
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
inline bool Move_N(fd_session_t* SessionPtr, uint16_t N)
{
    if ( (SessionPtr->Next_Out != nullptr) && (SessionPtr->Avail_Out >= N) &&
        (SessionPtr->Next_In != nullptr) && (SessionPtr->Avail_In >= N) )
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
namespace snort
{
/* Create a new decompression session object */
SO_PUBLIC fd_session_t* File_Decomp_New();

/* Initialize the session */
SO_PUBLIC fd_status_t File_Decomp_Init(fd_session_t*);

/* Run the incremental decompression engine */
SO_PUBLIC fd_status_t File_Decomp(fd_session_t*);

/* Close the decomp session processing */
SO_PUBLIC fd_status_t File_Decomp_End(fd_session_t*);

/* Close the current decomp session, but setup for another */
SO_PUBLIC fd_status_t File_Decomp_Reset(fd_session_t*);

/* Abort and delete the session */
SO_PUBLIC fd_status_t File_Decomp_StopFree(fd_session_t*);

/* Delete the session object */
SO_PUBLIC void File_Decomp_Free(fd_session_t*);

/* Call the error alerting call-back function */
SO_PUBLIC void File_Decomp_Alert(fd_session_t*, int Event);
}
#endif

