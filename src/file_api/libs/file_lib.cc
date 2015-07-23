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
/*
**  Author(s):  Hui Cao <huica@cisco.com>
**
**  NOTES
**  5.25.12 - Initial Source Code. Hcao
*/

#include "file_lib.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file_identifier.h"
#include "file_config.h"
#include "file_api/file_capture.h"

#include "main/snort_types.h"
#include "hash/hashes.h"
#include "utils/util.h"

// FIXIT-L these are no longer needed
#define SHA256CONTEXT SHA256_CTX
#define SHA256INIT    SHA256_Init
#define SHA256UPDATE  SHA256_Update
#define SHA256FINAL   SHA256_Final

static inline int get_data_size_from_depth_limit(FileContext* context, FileProcessType type, int
    data_size)
{
    FileConfig* file_config =  (FileConfig*) context->file_config;
    uint64_t max_depth;

    if (!file_config)
        return data_size;

    switch (type)
    {
    case SNORT_FILE_TYPE_ID:
        max_depth = file_config->file_type_depth;
        break;
    case SNORT_FILE_SHA256:
        max_depth = file_config->file_signature_depth;
        break;
    default:
        return data_size;
    }

    if (context->processed_bytes > max_depth)
        data_size = -1;
    else if (context->processed_bytes + data_size > max_depth)
        data_size = (int)(max_depth - context->processed_bytes);

    return data_size;
}

/* stop file type identification */
static inline void _finalize_file_type (FileContext* context)
{
    if (SNORT_FILE_TYPE_CONTINUE ==  context->file_type_id)
        context->file_type_id = SNORT_FILE_TYPE_UNKNOWN;
    context->file_type_context = NULL;
}
/*
 * Main File type processing function
 * We use file type context to decide file type across packets
 *
 * File type detection is completed either when
 * 1) file is completed or
 * 2) file type depth is reached or
 * 3) file magics are exhausted in depth
 *
 */
void file_type_id( FileContext* context, uint8_t* file_data,
        int size, FilePosition position)
{
    int data_size;
    FileConfig* file_config = context->file_config;

    if (!context || !file_config)
        return;

    /* file type already found and no magics to continue*/
    if (context->file_type_id && !context->file_type_context)
        return;

    /* Check whether file type depth is reached*/
    data_size = get_data_size_from_depth_limit(context, SNORT_FILE_TYPE_ID, size);

    if (data_size < 0)
    {
        _finalize_file_type(context);
        return;
    }

    file_config->find_file_type_id(file_data, data_size, context);

    /* Check whether file transfer is done or type depth is reached*/
    if ( (position == SNORT_FILE_END)  || (position == SNORT_FILE_FULL) ||
         (data_size != size) )
    {
        _finalize_file_type(context);
    }
}

void file_signature_sha256(
    FileContext* context, uint8_t* file_data, int size, FilePosition position)
{
    int data_size;

    if (!context)
        return;

    data_size = get_data_size_from_depth_limit(context, SNORT_FILE_SHA256, size);

    if (data_size != size)
    {
        context->file_state.sig_state = FILE_SIG_DEPTH_FAIL;
        return;
    }

    switch (position)
    {
    case SNORT_FILE_START:
        context->file_signature_context = SnortAlloc(sizeof(SHA256CONTEXT));
        SHA256INIT((SHA256CONTEXT*)context->file_signature_context);
        SHA256UPDATE((SHA256CONTEXT*)context->file_signature_context, file_data, data_size);
        break;
    case SNORT_FILE_MIDDLE:
        if (!context->file_signature_context)
            context->file_signature_context = SnortAlloc(sizeof(SHA256CONTEXT));
        SHA256UPDATE((SHA256CONTEXT*)context->file_signature_context, file_data, data_size);
        break;
    case SNORT_FILE_END:
        if (!context->file_signature_context)
            context->file_signature_context = SnortAlloc(sizeof(SHA256CONTEXT));
        if (context->processed_bytes == 0)
            SHA256INIT((SHA256CONTEXT*)context->file_signature_context);
        SHA256UPDATE((SHA256CONTEXT*)context->file_signature_context, file_data, data_size);
        context->sha256 = (uint8_t*)SnortAlloc(SHA256_HASH_SIZE);
        SHA256FINAL(context->sha256, (SHA256CONTEXT*)context->file_signature_context);
        context->file_state.sig_state = FILE_SIG_DONE;
        break;
    case SNORT_FILE_FULL:
        context->file_signature_context = SnortAlloc(sizeof (SHA256CONTEXT));
        SHA256INIT((SHA256CONTEXT*)context->file_signature_context);
        SHA256UPDATE((SHA256CONTEXT*)context->file_signature_context, file_data, data_size);
        context->sha256 = (uint8_t*)SnortAlloc(SHA256_HASH_SIZE);
        SHA256FINAL(context->sha256, (SHA256CONTEXT*)context->file_signature_context);
        context->file_state.sig_state = FILE_SIG_DONE;
        break;
    default:
        break;
    }
}

/*File context management*/

FileContext *file_context_create(void)
{
    FileContext *context = (FileContext *)SnortAlloc(sizeof(*context));
    return (context);
}

static inline void cleanDynamicContext (FileContext *context)
{
    if (context->file_signature_context)
        free(context->file_signature_context);
    if(context->sha256)
        free(context->sha256);
    if(context->file_capture)
        file_capture_stop(context);
}

void file_context_reset(FileContext *context)
{
    cleanDynamicContext(context);
    memset(context, 0, sizeof(*context));

}

void file_context_free(void *ctx)
{
    FileContext *context = (FileContext *)ctx;
    if (!context)
        return;
    cleanDynamicContext(context);
    free(context);
}

/*File properties*/
/*Only set the pointer for performance, no deep copy*/
void file_name_set (FileContext *context, uint8_t *file_name, uint32_t name_size)
{
    if (!context)
        return;
    context->file_name = file_name;
    context->file_name_size = name_size;
}

/* Return 1: file name available,
 *        0: file name is unavailable
 */

int file_name_get(FileContext* context, uint8_t** file_name, uint32_t* name_size)
{
    if (!context)
        return 0;
    if (file_name)
        *file_name = context->file_name;
    else
        return 0;
    if (name_size)
        *name_size = context->file_name_size;
    else
        return 0;
    return 1;
}

void file_size_set(FileContext* context, uint64_t file_size)
{
    if (!context)
        return;
    context->file_size = file_size;
}

uint64_t file_size_get(FileContext* context)
{
    if (!context)
        return 0;
    return (context->file_size);
}

void file_direction_set(FileContext* context, bool upload)
{
    if (!context)
        return;
    context->upload = upload;
}

bool file_direction_get(FileContext* context)
{
    if (!context)
        return false;
    return (context->upload);
}

void file_sig_sha256_set(FileContext* context, uint8_t* signature)
{
    if (!context)
        return;
    context->sha256= signature;
}

uint8_t* file_sig_sha256_get(FileContext* context)
{
    if (!context)
        return NULL;
    return (context->sha256);
}

const char* file_type_name(void* conf, uint32_t id)
{
    FileMagicRule* info = NULL;
    FileConfig* file_config =  (FileConfig*) conf;

    if (SNORT_FILE_TYPE_UNKNOWN == id)
        return "Unknown file type, done";

    else if (SNORT_FILE_TYPE_CONTINUE == id)
        return "Undecided file type, continue...";

    info = file_config->get_rule_from_id(id);

    if (info != NULL)
        return info->type.c_str();

    return NULL;
}
/**
bool file_IDs_from_type(const void *conf, const char *type,
     uint32_t **ids, uint32_t *count)
{
    if ( !type )
        return false;

    return get_ids_from_type(conf, type, ids, count);
}

bool file_IDs_from_type_version(const  void *conf, const char *type,
    const char *version, uint32_t **ids, uint32_t *count )
{
    if ( !type || !version )
        return false;

    return get_ids_from_type_version(conf, type, version, ids, count);
}

bool file_IDs_from_group(const void *conf, const char *group,
     uint32_t **ids, uint32_t *count)
{
    if ( !group )
        return false;

    return get_ids_from_group(conf, group, ids, count);
}
**/

/*
 * Print a 32-byte hash value.
 */
void file_sha256_print(unsigned char* hash)
{
    printf("SHA256: %02X%02X %02X%02X %02X%02X %02X%02X "
        "%02X%02X %02X%02X %02X%02X %02X%02X "
        "%02X%02X %02X%02X %02X%02X %02X%02X "
        "%02X%02X %02X%02X %02X%02X %02X%02X\n",
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
        hash[8], hash[9], hash[10], hash[11],
        hash[12], hash[13], hash[14], hash[15],
        hash[16], hash[17], hash[18], hash[19],
        hash[20], hash[21], hash[22], hash[23],
        hash[24], hash[25], hash[26], hash[27],
        hash[28], hash[29], hash[30], hash[31]);
}

