//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_process.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_PROCESS_H
#define FILE_MIME_PROCESS_H

// Provides list of MIME processing functions. Encoded file data will be decoded
// and file name will be extracted from MIME header
// FIXIT-L This will be refactored soon

#include <pcre.h>
#include "main/snort_types.h"
#include "file_api/file_api.h"
#include "utils/sf_email_attach_decode.h"

#define BOUNDARY     0

/* state flags */
#define MIME_FLAG_FOLDING                    0x00000001
#define MIME_FLAG_IN_CONTENT_TYPE            0x00000002
#define MIME_FLAG_GOT_BOUNDARY               0x00000004
#define MIME_FLAG_DATA_HEADER_CONT           0x00000008
#define MIME_FLAG_IN_CONT_TRANS_ENC          0x00000010
#define MIME_FLAG_EMAIL_ATTACH               0x00000020
#define MIME_FLAG_MULTIPLE_EMAIL_ATTACH      0x00000040
#define MIME_FLAG_MIME_END                   0x00000080
#define MIME_FLAG_IN_CONT_DISP               0x00000200
#define MIME_FLAG_IN_CONT_DISP_CONT          0x00000400

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    /* Data header section of data state */
#define STATE_DATA_BODY    2    /* Data body section of data state */
#define STATE_MIME_HEADER  3    /* MIME header section within data section */
#define STATE_DATA_UNKNOWN 4

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64

typedef struct _MimePcre
{
    pcre* re;
    pcre_extra* pe;
} MimePcre;

SO_PUBLIC int log_file_name(
    const uint8_t* start, int length, FILE_LogState* log_state, bool* disp_cont);

SO_PUBLIC int set_log_buffers(MAIL_LogState** log_state, MAIL_LogConfig* conf);

SO_PUBLIC void init_mime(void);
SO_PUBLIC void free_mime(void);

SO_PUBLIC const uint8_t* process_mime_data(
    Flow *flow, const uint8_t *start, const uint8_t *end,
    MimeState *mime_ssn, bool upload, FilePosition position);

SO_PUBLIC void free_mime_session(MimeState*);
SO_PUBLIC void free_mime_session(MimeState&);

SO_PUBLIC void finalize_mime_position(Flow* flow, void* decode_state, FilePosition* position);
SO_PUBLIC void reset_mime_paf_state(MimeDataPafInfo *data_info);

/*  Process data boundary and flush each file based on boundary*/
SO_PUBLIC bool process_mime_paf_data(MimeDataPafInfo *data_info,  uint8_t val);
SO_PUBLIC bool check_data_end(void *end_state,  uint8_t val);

#endif

