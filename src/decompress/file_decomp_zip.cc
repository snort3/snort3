//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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

// file_decomp_zip.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_decomp_zip.h"
#include "utils/util.h"

using namespace snort;

// initialize zlib decompression
static fd_status_t Inflate_Init(fd_session_t* SessionPtr)
{
    z_stream* z_s = &(SessionPtr->ZIP->Stream);

    memset((char*)z_s, 0, sizeof(z_stream));

    z_s->zalloc = (alloc_func)nullptr;
    z_s->zfree = (free_func)nullptr;

    SYNC_IN(z_s)

    int z_ret = inflateInit2(z_s, -MAX_WBITS);

    if ( z_ret != Z_OK )
        return File_Decomp_Error;

    return File_Decomp_OK;
}

// end zlib decompression
static fd_status_t Inflate_End(fd_session_t* SessionPtr)
{
    z_stream* z_s = &(SessionPtr->ZIP->Stream);

    inflateEnd(z_s);

    return File_Decomp_OK;
}

// perform zlib decompression
static fd_status_t Inflate(fd_session_t* SessionPtr)
{
    const uint8_t *zlib_start, *zlib_end;

    z_stream* z_s = &(SessionPtr->ZIP->Stream);

    zlib_start = SessionPtr->Next_In;

    SYNC_IN(z_s)

    int z_ret = inflate(z_s, Z_SYNC_FLUSH);

    SYNC_OUT(z_s)

    zlib_end = SessionPtr->Next_In;

    // keep track of decompression progress
    SessionPtr->ZIP->progress += zlib_end - zlib_start;

    if ( z_ret == Z_STREAM_END )
        return File_Decomp_Complete;

    if ( z_ret != Z_OK )
        return File_Decomp_Error;

    if ( SessionPtr->Avail_Out == 0 )
        return File_Decomp_BlockOut;

    return File_Decomp_OK;
}

// allocate and set initial ZIP state
fd_status_t File_Decomp_Init_ZIP(fd_session_t* SessionPtr)
{
    if ( SessionPtr == nullptr )
        return File_Decomp_Error;

    SessionPtr->ZIP = (fd_ZIP_t*)snort_calloc(sizeof(fd_ZIP_t));

    // file_decomp.cc already matched the local header
    // skip the version and bitflag (4 bytes)
    SessionPtr->ZIP->State = ZIP_STATE_SKIP;
    SessionPtr->ZIP->Length = 4;

    // land on compression method
    SessionPtr->ZIP->Next = ZIP_STATE_METHOD;
    SessionPtr->ZIP->Next_Length = 2;

    return File_Decomp_OK;
}

// end ZIP processing
fd_status_t File_Decomp_End_ZIP(fd_session_t* SessionPtr)
{
    if ( SessionPtr == nullptr )
        return File_Decomp_Error;

    // end zlib decompression if we are processing a stream
    if ( SessionPtr->ZIP->State == ZIP_STATE_INFLATE )
        Inflate_End(SessionPtr);

    // File_Decomp_Free() will free SessionPtr->ZIP
    return File_Decomp_OK;
}

// run the ZIP state machine
fd_status_t File_Decomp_ZIP(fd_session_t* SessionPtr)
{
    uint8_t byte;

    if ( SessionPtr == nullptr )
        return File_Decomp_Error;

    fd_ZIP_t* parser = SessionPtr->ZIP;

    // while we have data to read in the stream
    while ( SessionPtr->Avail_In > 0 )
    {
        if ( SessionPtr->Next_In == nullptr )
            return File_Decomp_Error;

        switch ( parser->State )
        {
        // local header
        case ZIP_STATE_LH:
            // check if we are done with the local_header
            if ( parser->Index == parser->Length )
            {
                // check if we read a local_header
                if ( parser->local_header != ZIP_LOCAL_HEADER )
                    return File_Decomp_Complete;

                // read a local_header, reset the index
                parser->Index = 0;

                // reset ZIP fields
                parser->local_header = 0;
                parser->method = 0;
                parser->compressed_size = 0;
                parser->filename_length = 0;
                parser->extra_length = 0;

                // reset decompression progress
                parser->progress = 0;

                // skip the version and bitflag (4 bytes)
                parser->State = ZIP_STATE_SKIP;
                parser->Length = 4;

                // land on compression method
                parser->Next = ZIP_STATE_METHOD;
                parser->Next_Length = 2;
                continue;
            }
            // read the local header
            byte = *SessionPtr->Next_In;
            parser->local_header |= byte << parser->Index*8;
            break;
        // compression method
        case ZIP_STATE_METHOD:
            // check if we are done with the method
            if ( parser->Index == parser->Length )
            {
                // read the method, reset the index
                parser->Index = 0;

                // skip:
                //  modtime(2), moddate(2), crc(4) = 8 bytes
                parser->State = ZIP_STATE_SKIP;
                parser->Length = 8;

                // land on compressed size
                parser->Next = ZIP_STATE_COMPSIZE;
                parser->Next_Length = 4;
                continue;
            }
            // read the method
            byte = *SessionPtr->Next_In;
            parser->method |= byte << parser->Index*8;
            break;
        // compressed size
        case ZIP_STATE_COMPSIZE:
            // check if we are done with the compressed size
            if ( parser->Index == parser->Length )
            {
                // read the compressed size, reset the index
                parser->Index = 0;

                // skip the uncompressed size (4 bytes)
                parser->State = ZIP_STATE_SKIP;
                parser->Length = 4;

                // land on filename length
                parser->Next = ZIP_STATE_FILENAMELEN;
                parser->Next_Length = 2;
                continue;
            }
            // read the compressed size
            byte = *SessionPtr->Next_In;
            parser->compressed_size |= byte << parser->Index*8;
            break;
        // filename length
        case ZIP_STATE_FILENAMELEN:
            // check if we are done with the filename length
            if ( parser->Index == parser->Length )
            {
                // read the filename length, reset the index
                parser->Index = 0;

                // read the extra field length next
                parser->State = ZIP_STATE_EXTRALEN;
                parser->Length = 2;
                continue;
            }
            // read the filename length
            byte = *SessionPtr->Next_In;
            parser->filename_length |= byte << parser->Index*8;
            break;
        // extra length
        case ZIP_STATE_EXTRALEN:
            // check if we are done with the extra length
            if ( parser->Index == parser->Length )
            {
                // read the extra length, reset the index
                parser->Index = 0;

                // skip the filename and extra fields
                parser->State = ZIP_STATE_SKIP;
                parser->Length = parser->filename_length + parser->extra_length;

                if ( (SessionPtr->Avail_Out > 0) && (parser->method == 8) )
                {
                    // we have available output space and
                    // the compression type is deflate (8),
                    // land on the compressed stream, init zlib
                    parser->Next = ZIP_STATE_INFLATE_INIT;
                    parser->Next_Length = parser->compressed_size;
                    continue;
                }

                // no output space or compression type isn't deflate, skip the stream
                parser->Length += parser->compressed_size;

                // land on another local header
                parser->Next = ZIP_STATE_LH;
                parser->Next_Length = 4;
                continue;
            }
            // read the extra length
            byte = *SessionPtr->Next_In;
            parser->extra_length |= byte << parser->Index*8;
            break;
        // initialize zlib inflate
        case ZIP_STATE_INFLATE_INIT:
            parser->State = ZIP_STATE_INFLATE;

            if ( Inflate_Init(SessionPtr) == File_Decomp_Error )
                return File_Decomp_Error;

            // fallthrough
        // perform zlib inflate
        case ZIP_STATE_INFLATE:
        {
            // run inflate
            fd_status_t status = Inflate(SessionPtr);

            if ( status == File_Decomp_Error )
            {
                // error inflating the stream
                // File_Decomp_End_ZIP() will
                // close the inflate stream
                return File_Decomp_Error;
            }

            if ( status == File_Decomp_BlockOut )
            {
                // ran out of output space
                // progress should be < compressed_size
                if ( parser->progress >= parser->compressed_size )
                    return File_Decomp_Error;

                // close the inflate stream
                Inflate_End(SessionPtr);

                // skip the rest of the stream
                parser->State = ZIP_STATE_SKIP;
                parser->Length = parser->compressed_size - parser->progress;

                // land on another local header
                parser->Next = ZIP_STATE_LH;
                parser->Next_Length = 4;
                continue;
            }

            if ( status == File_Decomp_Complete )
            {
                // done decompressing the stream
                // close the inflate stream
                Inflate_End(SessionPtr);

                // parse next local header
                parser->State = ZIP_STATE_LH;
                parser->Length = 4;
                continue;
            }

            // keep the inflate stream open
            // circle back for more input
            return File_Decomp_OK;
        }
        // skip state
        case ZIP_STATE_SKIP:
            // check if we need to skip
            if ( parser->Index < parser->Length )
            {
                unsigned skip = parser->Length - parser->Index;

                // check if we can skip within this flush
                if ( SessionPtr->Avail_In < skip )
                {
                    // the available input is < skip
                    parser->Index += SessionPtr->Avail_In;

                    unsigned min = SessionPtr->Avail_In < SessionPtr->Avail_Out ?
                                   SessionPtr->Avail_In : SessionPtr->Avail_Out;

                    // copy what we can
                    Move_N(SessionPtr, min);

                    // get more input
                    return File_Decomp_BlockIn;
                }

                if ( SessionPtr->Avail_Out < skip )
                {
                    // the available input is >= skip
                    // the available output is < skip <= available input
                    skip -= SessionPtr->Avail_Out;
                    // copy what we can
                    Move_N(SessionPtr, SessionPtr->Avail_Out);
                    // available output is now 0
                    // skip the rest
                    SessionPtr->Next_In += skip;
                    SessionPtr->Avail_In -= skip;
                    SessionPtr->Total_In += skip;
                    // done skipping, index should be 0
                }
                else
                {
                    // the available input is >= skip
                    // the available output is >= skip
                    // copy skip bytes from input to output
                    Move_N(SessionPtr, skip);
                    // done skipping, index should be 0
                }
            }
            // done skipping, reset the index
            parser->Index = 0;

            // switch to the next state
            parser->State = parser->Next;
            parser->Length = parser->Next_Length;
            continue;
        }

        // make sure we can write a byte
        if ( SessionPtr->Avail_Out > 0 )
        {
            // advance and copy the stream
            Move_1(SessionPtr);
        }
        else
        {
            // advance the stream
            SessionPtr->Next_In += 1;
            SessionPtr->Avail_In -= 1;
            SessionPtr->Total_In += 1;
        }

        parser->Index++;
    }

    return File_Decomp_BlockIn;
}
