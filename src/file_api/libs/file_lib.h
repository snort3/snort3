/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
*/
/*
**  Author(s):  Hui Cao <hcao@sourcefire.com>
**
**  NOTES
**  5.25.12 - Initial Source Code. Hcao
*/

#ifndef FILE_LIB_H
#define FILE_LIB_H

#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow.h"

#define SNORT_FILE_TYPE_UNKNOWN          UINT16_MAX  /**/
#define SNORT_FILE_TYPE_CONTINUE         0 /**/

typedef struct _MagicData
{
    uint8_t *content;       /* magic content to match*/
    int content_len;        /* length of magic content */
    uint32_t offset;             /* pattern search start offset */

    struct _MagicData *next; /* ptr to next match struct */

} MagicData;

typedef struct _RuleInfo
{
    uint32_t   rev;
    char       *message;
    char       *type;
    uint32_t   id;
    char       *category;
    char       *version;
    MagicData  *magics;
} RuleInfo;

typedef enum _File_Verdict
{
    FILE_VERDICT_UNKNOWN = 0,
    FILE_VERDICT_LOG,
    FILE_VERDICT_STOP,
    FILE_VERDICT_BLOCK,
    FILE_VERDICT_REJECT,
    FILE_VERDICT_PENDING,
    FILE_VERDICT_MAX
} File_Verdict;

struct FileContext
{
    bool file_type_enabled;
    bool file_signature_enabled;
    uint8_t    *file_name;
    uint32_t   file_name_size;
    uint64_t   file_size;
    bool       upload;
    uint64_t   processed_bytes;
    uint32_t   file_type_id;
    uint8_t    *sha256;
    void *     file_type_context;
    void *     file_signature_context;
    void *     file_config;
    time_t expires;
    File_Verdict verdict;
    bool suspend_block_verdict;
};

typedef enum _FilePosition
{
    SNORT_FILE_POSITION_UNKNOWN,
    SNORT_FILE_START,
    SNORT_FILE_MIDDLE,
    SNORT_FILE_END,
    SNORT_FILE_FULL
} FilePosition;

typedef enum _FileProcessType
{
    SNORT_FILE_TYPE_ID,
    SNORT_FILE_SHA256
} FileProcessType;


/*Main File Processing functions */
void file_type_id( FileContext* context, uint8_t* file_data, int data_size, FilePosition position);
void file_signature_sha256( FileContext* context, uint8_t* file_data, int data_size, FilePosition position);

/*File context management*/
FileContext *file_context_create(void);
void file_context_reset(FileContext *context);
void file_context_free(void *context);
/*File properties*/
void file_name_set (FileContext *context, uint8_t *file_name, uint32_t name_size);
int file_name_get (FileContext *context, uint8_t **file_name, uint32_t *name_size);
void file_size_set (FileContext *context, uint64_t file_size);
uint64_t file_size_get (FileContext *context);
void file_direction_set (FileContext *context, bool upload);
bool file_direction_get (FileContext *context);
void file_sig_sha256_set (FileContext *context, uint8_t *signature);
uint8_t* file_sig_sha256_get (FileContext *context);

const char* file_info_from_ID(void *conf, uint32_t);
extern int64_t file_type_depth;
extern int64_t file_signature_depth;

void free_file_identifiers(void*);
#if defined(DEBUG_MSGS) || defined (REG_TEST)
void file_sha256_print(unsigned char *hash);
#endif
#endif

