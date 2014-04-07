/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2012-2013 Sourcefire, Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  9.25.2012 - Initial Source Code. Hcao
 */

#ifndef FILE_MIME_PROCESS_H
#define FILE_MIME_PROCESS_H

#include <pcre.h>
#include "file_api.h"
#include "sf_email_attach_decode.h"
#include "mempool/mempool.h"

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

/* log flags */
#define MIME_FLAG_FILENAME_PRESENT           0x00000004

typedef struct _MimePcre
{
    pcre       *re;
    pcre_extra *pe;

} MimePcre;

int log_file_name(const uint8_t *start, int length, FILE_LogState *log_state, bool *disp_cont);
int set_log_buffers(MAIL_LogState **log_state, MAIL_LogConfig *conf, void *mempool);
void* init_mime_mempool(int max_mime_mem, int max_depth, void *mempool, const char *preproc_name);
void* init_log_mempool(uint32_t email_hdrs_log_depth, uint32_t memcap,  void *mempool, const char *preproc_name);
void init_mime(void);
void free_mime(void);
const uint8_t* process_mime_data(void *packet, const uint8_t *start, const uint8_t *end,
        const uint8_t *data_end_marker, uint8_t *data_end, MimeState *mime_ssn, bool upload);
void free_mime_session(MimeState *mime_ssn);
void finalize_mime_position(Flow *flow, void *decode_state, FilePosition *position);
#endif 
