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

// file_decomp.cc author Ed Borgoyn <eborgoyn@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_decomp.h"

#include <cassert>

#include "detection/detection_util.h"
#include "utils/util.h"

#include "file_decomp_pdf.h"
#include "file_decomp_swf.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static const char PDF_Sig[5] = { '%', 'P', 'D', 'F', '-' };
static const char SWF_ZLIB_Sig[3] = { 'C', 'W', 'S' };
#ifdef HAVE_LZMA
static const char SWF_LZMA_Sig[3] = { 'Z', 'W', 'S' };
#endif
static const char SWF_Uncomp_Sig[3] = { 'F', 'W', 'S' };

/* Please assure that the following value correlates with the set of sig's */
#define MAX_SIG_LENGTH (5)

static struct sig_map_s
{
    const char* Sig;
    size_t Sig_Length;
    bool Enabled;
    file_type_t File_Type;
    file_compression_type_t File_Compression_Type;
} Signature_Map[] =
{
    // none: compression type is embedded in PDF dictionaries
    { PDF_Sig, sizeof(PDF_Sig), false, FILE_TYPE_PDF, FILE_COMPRESSION_TYPE_NONE },

    { SWF_ZLIB_Sig, sizeof(SWF_ZLIB_Sig), false, FILE_TYPE_SWF, FILE_COMPRESSION_TYPE_ZLIB },
#ifdef HAVE_LZMA
    { SWF_LZMA_Sig, sizeof(SWF_LZMA_Sig), false, FILE_TYPE_SWF, FILE_COMPRESSION_TYPE_LZMA },
#endif
    { nullptr, 0, false, FILE_TYPE_NONE, FILE_COMPRESSION_TYPE_NONE }
};

/* Define the elements of the Sig_State value (packed for storage efficiency */
#define SIG_MATCH_ACTIVE    (0x80)
#define SIG_SIG_INDEX_MASK  (0x70)
#define SIG_SIG_INDEX_SHIFT (4)
#define SIG_CHR_INDEX_MASK  (0x07)
#define SIG_CHR_INDEX_SHIFT (0)

/* Look for possible sig at the current payload location.
   Do NOT beyond the current location (initial Next_In). */
static fd_status_t Locate_Sig_Here(fd_session_t* SessionPtr)
{
    uint64_t Sig_Index, Char_Index;

    /* If there's no new input, we don't change state */
    if ( (SessionPtr->Avail_In == 0) ||
        (SessionPtr->Next_In == nullptr) || (SessionPtr->Next_Out == nullptr) )
        return( File_Decomp_Error );

    if ( SessionPtr->Avail_Out < MAX_SIG_LENGTH )
        return( File_Decomp_BlockOut );

    /* Given that we are here, there is at least one input byte to process.
       And at least enough room in the output stream for the signature. */

    /* Have we started down a sig string? */
    if ( (SessionPtr->Sig_State & SIG_MATCH_ACTIVE) != 0 )
    {
        /* Get the current index into the sig map table (indicating which sig) and
           the index into the sig itself.  */
        Sig_Index = (SessionPtr->Sig_State & SIG_SIG_INDEX_MASK) >> SIG_SIG_INDEX_SHIFT;
        /* Char_Index indicates the sig char that we are looking for now. */
        Char_Index = (SessionPtr->Sig_State & SIG_CHR_INDEX_MASK) >> SIG_CHR_INDEX_SHIFT;
    }
    else
    {
        Sig_Index = 0;
        Char_Index = 0;
    }

    /* There must be more in the input stream for us to look at, else
       we indicate that we didn't find the sig yet. */
    if ( SessionPtr->Avail_In <= Char_Index )
        return( File_Decomp_BlockIn );

    /* NOTE:  The following code block makes the assumption that there are
              at least MAX_SIG_LENGTH bytes in the output buffer.  This assumption
              is valid for the current implementation where the signature only
              occurs at the beginning of the file.  For the generic case of the sig
              begin embedded with the file, the search will need to modified.*/
    while ( true )
    {
        /* if we get to the end of the sig table (or the table is empty),
           indicate that we didn't match a sig */
        if ( Signature_Map[Sig_Index].Sig == nullptr )
            return( File_Decomp_NoSig );

        /* Get next char and see if it matches next char in sig */
        if ( (Signature_Map[Sig_Index].Enabled) &&
            (*(SessionPtr->Next_In+Char_Index) == *(Signature_Map[Sig_Index].Sig+Char_Index)) )
        {
            /* Check to see if we are at the end of the sig string. */
            if ( Char_Index == (Signature_Map[Sig_Index].Sig_Length-1) )
            {
                const uint8_t* Sig = (const uint8_t*)Signature_Map[Sig_Index].Sig;
                uint16_t Len = (uint16_t)Signature_Map[Sig_Index].Sig_Length;

                SessionPtr->File_Type = Signature_Map[Sig_Index].File_Type;
                SessionPtr->Decomp_Type = Signature_Map[Sig_Index].File_Compression_Type;

                if (SessionPtr->File_Type == FILE_TYPE_SWF)
                {
                    Sig = (const uint8_t*)SWF_Uncomp_Sig;
                    Len = (uint16_t)sizeof( SWF_Uncomp_Sig );
                }
                /* The following is safe as we can only be here is there are
                   are least MAX_SIG_LENGTH bytes in the output buffer */
                (void)Put_N(SessionPtr, Sig, Len);
                /* Skip the Sig bytes in the input stream */
                SessionPtr->Next_In += Len;
                SessionPtr->Avail_In -= Len;
                SessionPtr->Total_In += Len;
                return( File_Decomp_OK );
            }

            /* check for more available input bytes */
            if ( Char_Index < SessionPtr->Avail_In )
            {
                /* Set to the next char and keep checking this matching sig */
                Char_Index += 1;
                continue; /* goto top of while() loop */
            }
            else
            {
                /* Indicate that we are actively finding a sig, save the char index
                   and save the sig index.  We'll pickup where we left off when more
                   input is available. */
                SessionPtr->Sig_State = SIG_MATCH_ACTIVE |
                    ((Sig_Index & SIG_SIG_INDEX_MASK) << SIG_SIG_INDEX_SHIFT) |
                    ((Char_Index & SIG_CHR_INDEX_MASK) << SIG_CHR_INDEX_SHIFT);
                return( File_Decomp_BlockIn );
            }
        }
        else
        {
            /* Failed somewhere matching this sig, goto next sig and reset the
               Char_Index to the beginning */
            Sig_Index += 1;
            Char_Index = 0;
        }
    }
}

static fd_status_t Initialize_Decompression(fd_session_t* SessionPtr)
{
    fd_status_t Ret_Code = File_Decomp_OK;

    switch ( SessionPtr->File_Type )
    {
    case ( FILE_TYPE_SWF ):
    {
        Ret_Code = File_Decomp_Init_SWF(SessionPtr);
        break;
    }
    case ( FILE_TYPE_PDF ):
    {
        Ret_Code = File_Decomp_Init_PDF(SessionPtr);
        break;
    }
    default:
        return( File_Decomp_Error );
    }

    if ( Ret_Code == File_Decomp_OK )
        SessionPtr->State = STATE_ACTIVE;

    return( Ret_Code );
}

static fd_status_t Process_Decompression(fd_session_t* SessionPtr)
{
    fd_status_t Ret_Code = File_Decomp_OK;

    switch ( SessionPtr->File_Type )
    {
    case ( FILE_TYPE_SWF ):
    {
        Ret_Code = File_Decomp_SWF(SessionPtr);
        break;
    }
    case ( FILE_TYPE_PDF ):
    {
        Ret_Code = File_Decomp_PDF(SessionPtr);
        break;
    }
    default:
        return( File_Decomp_Error );
    }

    if ( Ret_Code == File_Decomp_Complete )
        SessionPtr->State = STATE_COMPLETE;

    return( Ret_Code );
}

namespace snort
{
/* The caller provides Compr_Depth, Decompr_Depth and Modes in the session object.
   Based on the requested Modes, gear=up to initialize the potential decompressors. */
fd_status_t File_Decomp_Init(fd_session_t* SessionPtr)
{
    int Sig;

    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    SessionPtr->State = STATE_READY;
    SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;

    for ( Sig=0; Signature_Map[Sig].Sig != nullptr; Sig++ )
    {
        if ( (Signature_Map[Sig].File_Type == FILE_TYPE_PDF ) &&
            ((SessionPtr->Modes & FILE_PDF_ANY) != 0) )
            Signature_Map[Sig].Enabled = true;

        if ( (Signature_Map[Sig].File_Type == FILE_TYPE_SWF ) &&
            (Signature_Map[Sig].File_Compression_Type == FILE_COMPRESSION_TYPE_ZLIB) &&
            ((SessionPtr->Modes & FILE_SWF_ZLIB_BIT) != 0) )
            Signature_Map[Sig].Enabled = true;

#ifdef HAVE_LZMA
        if ( (Signature_Map[Sig].File_Type == FILE_TYPE_SWF ) &&
            (Signature_Map[Sig].File_Compression_Type == FILE_COMPRESSION_TYPE_LZMA) &&
            ((SessionPtr->Modes & FILE_SWF_LZMA_BIT) != 0) )
            Signature_Map[Sig].Enabled = true;
#endif
    }

    return( File_Decomp_OK );
}

/* Returns a new session object from the MemPool */
fd_session_t* File_Decomp_New()
{
    fd_session_t* New_Session = new fd_session_t;

    New_Session->State = STATE_NEW;
    New_Session->Sig_State = 0;
    New_Session->Total_In = 0;
    New_Session->Total_Out = 0;
    New_Session->Avail_In = 0;
    New_Session->Next_In = nullptr;
    New_Session->Avail_Out = 0;
    New_Session->Next_Out = nullptr;
    New_Session->File_Type = FILE_TYPE_NONE;

    return New_Session;
}

/* Process Decompression.  The session Next_In, Avail_In, Next_Out, Avail_Out MUST have been
   set by caller.
*/
fd_status_t File_Decomp(fd_session_t* SessionPtr)
{
    fd_status_t Return_Code;

    if ( (SessionPtr == nullptr) || (SessionPtr->State == STATE_NEW) ||
        (SessionPtr->Next_In == nullptr) || (SessionPtr->Next_Out == nullptr) )
        return( File_Decomp_Error );

    /* STATE_NEW: Look for one of the configured file signatures. */
    if ( SessionPtr->State == STATE_READY )
    {
        /* Look for the signature at the beginning of the payload stream. */
        if ( (Return_Code = Locate_Sig_Here(SessionPtr)) == File_Decomp_OK )
        {
            /* We now know the file type and decompression type.  Setup appropriate state. */
            if ( (Return_Code = Initialize_Decompression(SessionPtr)) == File_Decomp_OK )
            {
                return( Process_Decompression(SessionPtr) );
            }
            else
                return( Return_Code );
        }
        else
            /* Locate_Sig_Here() might return BlockIn, BlockOut, Error, or NoSig */
            return( Return_Code );
    }
    else if ( SessionPtr->State == STATE_ACTIVE )
    {
        return( Process_Decompression(SessionPtr) );
    }
    else
        return( File_Decomp_Error );
}

fd_status_t File_Decomp_End(fd_session_t* SessionPtr)
{
    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    switch ( SessionPtr->File_Type )
    {
    case ( FILE_TYPE_SWF ):
    {
        return( File_Decomp_End_SWF(SessionPtr) );
    }
    case ( FILE_TYPE_PDF ):
    {
        return( File_Decomp_End_PDF(SessionPtr) );
    }
    }

    return( File_Decomp_Error );
}

fd_status_t File_Decomp_Reset(fd_session_t* SessionPtr)
{
    fd_status_t Ret_Code;

    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    Ret_Code = File_Decomp_End(SessionPtr);

    SessionPtr->State = STATE_READY;

    return( Ret_Code );
}

fd_status_t File_Decomp_StopFree(fd_session_t* SessionPtr)
{
    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    File_Decomp_End(SessionPtr);
    File_Decomp_Free(SessionPtr);

    return( File_Decomp_OK );
}

void File_Decomp_Free(fd_session_t* SessionPtr)
{
    assert(SessionPtr);

    switch ( SessionPtr->File_Type )
    {
    case FILE_TYPE_SWF:
        assert(SessionPtr->SWF);
        snort_free(SessionPtr->SWF);
        break;

    case FILE_TYPE_PDF:
        assert(SessionPtr->PDF);
        snort_free(SessionPtr->PDF);
        break;
    }

    delete SessionPtr;
}

void File_Decomp_Alert(fd_session_t* SessionPtr, int Event)
{
    if ( (SessionPtr != nullptr) && (SessionPtr->Alert_Callback != nullptr) &&
        (SessionPtr->Alert_Context) )
        (SessionPtr->Alert_Callback)(SessionPtr->Alert_Context, Event);
}

} // namespace snort

//--------------------------------------------------------------------------
// unit tests 
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("File_Decomp_StopFree-null", "[file_decomp]")
{
    REQUIRE((File_Decomp_StopFree((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_Reset-null", "[file_decomp]")
{
    REQUIRE((File_Decomp_Reset((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_End-null", "[file_decomp]")
{
    REQUIRE((File_Decomp_End((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_Init-null", "[file_decomp]")
{
    REQUIRE((File_Decomp_Init((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_New", "[file_decomp]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    REQUIRE(p_s->State == STATE_NEW);
    REQUIRE(p_s->Sig_State == 0);
    REQUIRE(p_s->Total_In == 0);
    REQUIRE(p_s->Total_Out == 0);
    REQUIRE(p_s->Avail_In == 0);
    REQUIRE(p_s->Avail_Out == 0);
    REQUIRE(p_s->Next_In == nullptr);
    REQUIRE(p_s->Next_Out == nullptr);
    REQUIRE(p_s->File_Type == FILE_TYPE_NONE);
    File_Decomp_Free(p_s);
}

TEST_CASE("File_Decomp-null", "[file_decomp]")
{
    REQUIRE((File_Decomp((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp-not_active", "[file_decomp]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    REQUIRE((File_Decomp(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}

TEST_CASE("File_Decomp-complete_state", "[file_decomp]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    p_s->State = STATE_COMPLETE;
    REQUIRE((File_Decomp(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}

TEST_CASE("Initialize_Decompression-not_active", "[file_decomp]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    REQUIRE((Initialize_Decompression(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}

TEST_CASE("Process_Decompression-not_active", "[file_decomp]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    REQUIRE((Process_Decompression(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}
#endif

