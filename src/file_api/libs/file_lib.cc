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
#include "hash/hashes.h"
#include "utils/util.h"
#include "file_api/file_capture.h"

FileContext::FileContext ()
{
    file_type_context = NULL;
    file_signature_context = NULL;
    file_config = NULL;
    file_capture = NULL;
}

FileContext::~FileContext ()
{
    if (file_signature_context)
        free(file_signature_context);
    if(sha256)
        free(sha256);
    if(file_capture)
        stop_file_capture();
}

inline int FileContext::get_data_size_from_depth_limit(FileProcessType type, int
    data_size)
{
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

    if (processed_bytes > max_depth)
        data_size = -1;
    else if (processed_bytes + data_size > max_depth)
        data_size = (int)(max_depth - processed_bytes);

    return data_size;
}

/* stop file type identification */
inline void FileContext::finalize_file_type ()
{
    if (SNORT_FILE_TYPE_CONTINUE ==  file_type_id)
        file_type_id = SNORT_FILE_TYPE_UNKNOWN;
    file_type_context = NULL;
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
void FileContext::process_file_type(const uint8_t* file_data, int size, FilePosition position)
{
    int data_size;

    if (!file_config)
        return;

    /* file type already found and no magics to continue*/
    if (file_type_id && !file_type_context)
        return;

    /* Check whether file type depth is reached*/
    data_size = get_data_size_from_depth_limit(SNORT_FILE_TYPE_ID, size);

    if (data_size < 0)
    {
        finalize_file_type();
        return;
    }

    file_type_id =
        file_config->find_file_type_id(file_data, data_size, processed_bytes, &file_type_context);

    /* Check whether file transfer is done or type depth is reached*/
    if ( (position == SNORT_FILE_END)  || (position == SNORT_FILE_FULL) ||
        (data_size != size) )
    {
        finalize_file_type();
    }
}

void FileContext::process_file_signature_sha256(const uint8_t* file_data, int size,
    FilePosition position)
{
    int data_size = get_data_size_from_depth_limit(SNORT_FILE_SHA256, size);

    if (data_size != size)
    {
        file_state.sig_state = FILE_SIG_DEPTH_FAIL;
        return;
    }

    switch (position)
    {
    case SNORT_FILE_START:
        file_signature_context = SnortAlloc(sizeof(SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        break;
    case SNORT_FILE_MIDDLE:
        if (!file_signature_context)
            file_signature_context = SnortAlloc(sizeof(SHA256_CTX));
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        break;
    case SNORT_FILE_END:
        if (!file_signature_context)
            file_signature_context = SnortAlloc(sizeof(SHA256_CTX));
        if (processed_bytes == 0)
            SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        sha256 = (uint8_t*)SnortAlloc(SHA256_HASH_SIZE);
        SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
        file_state.sig_state = FILE_SIG_DONE;
        break;
    case SNORT_FILE_FULL:
        file_signature_context = SnortAlloc(sizeof (SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        sha256 = (uint8_t*)SnortAlloc(SHA256_HASH_SIZE);
        SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
        file_state.sig_state = FILE_SIG_DONE;
        break;
    default:
        break;
    }
}

FileCaptureState FileContext::process_file_capture(const uint8_t* file_data,
    int data_size, FilePosition position)
{
    if (!file_capture)
    {
        file_capture = new FileCapture;
    }

    file_state.capture_state =
        file_capture->process_buffer(file_data, data_size, position);

    return file_state.capture_state;
}

void FileContext::stop_file_capture()
{
    if (file_capture)
    {
        delete file_capture;
        file_capture = NULL;
    }

    file_capture_enabled = false;
}


void FileContext::update_file_size(int data_size, FilePosition position)
{
    processed_bytes += data_size;
    if ((position == SNORT_FILE_END)or (position == SNORT_FILE_FULL))
    {
        file_size = processed_bytes;
        processed_bytes = 0;
    }
}

uint32_t FileContext::get_file_type()
{
    return file_type_id;
}

void FileContext::config_file_type(bool enabled)
{
    file_type_enabled = enabled;
}

bool FileContext::is_file_type_enabled()
{
    return file_type_enabled;
}

void FileContext::config_file_signature(bool enabled)
{
    file_signature_enabled = enabled;
}

bool FileContext::is_file_signature_enabled()
{
    return file_signature_enabled;
}

void FileContext::config_file_capture(bool enabled)
{
    file_capture_enabled = enabled;
}

bool FileContext::is_file_capture_enabled()
{
    return file_capture_enabled;
}

/*File properties*/
/*Only set the pointer for performance, no deep copy*/
void FileContext::set_file_name (const uint8_t *name, uint32_t name_size)
{
    file_name = (uint8_t*) name;
    file_name_size = name_size;
}

/* Return true: file name available,
 *        false: file name is unavailable
 */

bool FileContext::get_file_name(uint8_t** name, uint32_t* name_size)
{
    if (name)
        *name = file_name;
    else
        return false;

    if (name_size)
        *name_size = file_name_size;
    else
        return false;

    return true;
}

void FileContext::set_file_size(uint64_t size)
{
    file_size = size;
}

uint64_t FileContext::get_file_size()
{
    return file_size;
}

uint64_t FileContext::get_processed_bytes()
{
    return processed_bytes;
}
void FileContext::set_file_id(uint32_t id)
{
    file_id = id;
}

uint32_t FileContext::get_file_id()
{
    return file_id;
}


void FileContext::set_file_direction(FileDirection dir)
{
    direction = dir;
}

FileDirection FileContext::get_file_direction()
{
    return (direction);
}

void FileContext::set_file_sig_sha256(uint8_t* signature)
{
    sha256 = signature;
}

uint8_t* FileContext::get_file_sig_sha256()
{
    return (sha256);
}

void FileContext::set_file_config(FileConfig* config)
{
    file_config = config;
}

FileConfig*  FileContext::get_file_config()
{
    return file_config;
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

void FileContext::print_file_data(FILE* fp, const uint8_t* data, int len, int max_depth)
{
    char str[18];
    int i;
    int pos;
    char c;

    if (max_depth < len)
        len = max_depth;

    fprintf(fp,"Show length: %d \n", len);
    for (i=0, pos=0; i<len; i++, pos++)
    {
        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) and (c == ' ' or !isspace(c)))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos)
    {
        str[pos] = 0;
        for (; pos < 17; pos++)
        {
            if (pos == 8)
            {
                str[pos] = ' ';
                pos++;
                fprintf(fp, "%s", "    ");
            }
            else
            {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}

/*
 * Print a 32-byte hash value.
 */
void FileContext::print_file_sha256()
{

    unsigned char* hash = sha256;

    if (!sha256)
        return;

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

#define MAX_CONTEXT_INFO_LEN 1024
void FileContext::print()
{
    char buf[MAX_CONTEXT_INFO_LEN + 1];
    int unused;
    char* cur = buf;
    int used = 0;

    unused = sizeof(buf) - 1;
    used = snprintf(cur, unused, "File name: ");

    if (used < 0)
    {
        printf("Fail to output file context\n");
        return;
    }
    unused -= used;
    cur += used;

    if ((file_name_size > 0) && (unused > (int)file_name_size))
    {
        strncpy(cur, (char*)file_name, file_name_size);
        unused -= file_name_size;
        cur += file_name_size;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile type: %s(%d)",
            file_type_name(file_config, file_type_id), file_type_id);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile size: %u",
            (unsigned int)file_size);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        snprintf(cur, unused, "\nProcessed size: %u\n",
            (unsigned int)processed_bytes);
    }

    buf[sizeof(buf) - 1] = '\0';
    printf("%s", buf);
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
