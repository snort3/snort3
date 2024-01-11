//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// file_decomp_zip.h author Brandon Stultz <brastult@cisco.com>

#ifndef FILE_DECOMP_ZIP_H
#define FILE_DECOMP_ZIP_H

#include <zlib.h>

#include "file_decomp.h"

namespace snort
{
class BoyerMooreSearchCase;
}

#define MACRO_BINNAME_LEN 14

static const char* const macro_binname = "vbaProject.bin";

static const uint32_t ZIP_LOCAL_HEADER = 0x04034B50;
static const uint8_t header_pattern[4] = { 0x50, 0x4B, 0x03, 0x04 };
static const uint8_t DATA_DESC_BIT = 0x08;

enum fd_ZIP_states
{
    ZIP_STATE_LH,             // local header (4 bytes)

    // skipped:
    // ZIP_STATE_VER,         // version (2 bytes)

    ZIP_STATE_BITFLAG,        // bitflag (2 bytes)
    ZIP_STATE_METHOD,         // compression method (2 bytes)

    // skipped:
    // ZIP_STATE_MODTIME,     // modification time (2 bytes)
    // ZIP_STATE_MODDATE,     // modification date (2 bytes)
    // ZIP_STATE_CRC,         // CRC-32 (4 bytes)

    ZIP_STATE_COMPSIZE,       // compressed size (4 bytes)

    // skipped:
    // ZIP_STATE_UNCOMPSIZE,  // uncompressed size (4 bytes)

    ZIP_STATE_FILENAMELEN,    // filename length (2 bytes)
    ZIP_STATE_EXTRALEN,       // extra field length (2 bytes)

    ZIP_STATE_FILENAME,    // filename field (filenamelen bytes)

    //skipped:
    // ZIP_STATE_EXTRA,       // extra field (extralen bytes)
    // ZIP_STATE_STREAM,      // compressed stream (compsize bytes)

    ZIP_STATE_OLE_FILE,
    ZIP_STATE_INFLATE_INIT,   // initialize zlib inflate
    ZIP_STATE_INFLATE,        // perform zlib inflate
    ZIP_STATE_SEARCH,         // search for local header
    ZIP_STATE_SKIP            // skip state
};

struct fd_ZIP_t
{
    // zlib stream
    z_stream Stream;

    // decompression progress
    uint32_t progress;

    // ZIP fields
    uint32_t local_header;
    uint16_t bitflag;
    bool data_descriptor;
    uint16_t method;
    uint32_t compressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
    char* file_name;
    // field index
    uint32_t Index;

    // current parser state
    fd_ZIP_states State;
    uint32_t Length;

    // next parser state
    fd_ZIP_states Next;
    uint32_t Next_Length;

    // local file header searcher
    snort::BoyerMooreSearchCase* header_searcher;
};

// allocate and set initial ZIP state
fd_status_t File_Decomp_Init_ZIP(fd_session_t*);

// end ZIP processing
fd_status_t File_Decomp_End_ZIP(fd_session_t*);

// run the ZIP state machine
fd_status_t File_Decomp_ZIP(fd_session_t*);

#endif

