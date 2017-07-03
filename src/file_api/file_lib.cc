//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_lib.h"

#include <openssl/sha.h>

#include <iostream>
#include <iomanip>

#include "hash/hashes.h"
#include "framework/data_bus.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "utils/util.h"

#include "file_capture.h"
#include "file_config.h"
#include "file_enforcer.h"
#include "file_flows.h"
#include "file_service.h"
#include "file_segment.h"
#include "file_stats.h"

FileInfo::~FileInfo ()
{
    if (sha256)
        delete[] sha256;
}

void FileInfo::copy(const FileInfo& other)
{
    if (other.sha256)
    {
        sha256 = new uint8_t[SHA256_HASH_SIZE];
        memcpy( (char*)sha256, (const char*)other.sha256, SHA256_HASH_SIZE);
    }

    file_size = other.file_size;
    direction = other.direction;
    file_type_id = other.file_type_id;
    file_id = other.file_id;
    file_name = other.file_name;
    verdict = other.verdict;
}

FileInfo::FileInfo(const FileInfo& other)
{
    copy(other);
}

FileInfo& FileInfo::operator=(const FileInfo& other)
{
    // check for self-assignment
    if (&other == this)
        return *this;

    copy(other);
    return *this;
}

/*File properties*/

void FileInfo::set_file_name(const char* name, uint32_t name_size)
{
    if (name and name_size)
    {
        file_name.assign(name, name_size);
    }

    file_name_set = true;
}

std::string& FileInfo::get_file_name()
{
    return file_name;
}

void FileInfo::set_file_size(uint64_t size)
{
    file_size = size;
}

uint64_t FileInfo::get_file_size() const
{
    return file_size;
}

uint32_t FileInfo::get_file_type() const
{
    return file_type_id;
}

void FileInfo::set_file_id(size_t id)
{
    file_id = id;
}

size_t FileInfo::get_file_id() const
{
    return file_id;
}

void FileInfo::set_file_direction(FileDirection dir)
{
    direction = dir;
}

FileDirection FileInfo::get_file_direction() const
{
    return direction;
}

uint8_t* FileInfo::get_file_sig_sha256() const
{
    return (sha256);
}

std::string FileInfo::sha_to_string(const uint8_t* sha256)
{
    uint8_t conv[] = "0123456789ABCDEF";
    const uint8_t* index;
    const uint8_t* end;
    std::string sha_out;

    index = sha256;
    end = index + SHA256_HASH_SIZE;

    while (index < end)
    {
        sha_out.push_back(conv[((*index & 0xFF)>>4)]);
        sha_out.push_back(conv[((*index & 0xFF)&0x0F)]);
        index++;
    }

    return sha_out;
}

FileContext::FileContext ()
{
    file_type_context = nullptr;
    file_signature_context = nullptr;
    file_capture = nullptr;
    file_segments = nullptr;
    inspector = (FileInspect*)InspectorManager::acquire(FILE_ID_NAME, snort_conf);
    file_config = inspector->config;
}

FileContext::~FileContext ()
{
    if (file_signature_context)
        snort_free(file_signature_context);
    if (file_capture)
        stop_file_capture();
    if (file_segments)
        delete file_segments;
    InspectorManager::release(inspector);
}

inline int FileContext::get_data_size_from_depth_limit(FileProcessType type, int
    data_size)
{
    uint64_t max_depth;

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
inline void FileContext::finalize_file_type()
{
    if (SNORT_FILE_TYPE_CONTINUE ==  file_type_id)
        file_type_id = SNORT_FILE_TYPE_UNKNOWN;
    file_type_context = nullptr;
}

void FileContext::log_file_event(Flow* flow)
{
    // wait for file name is set to log file event
    if ( is_file_name_set() )
    {
        switch (verdict)
        {
        case FILE_VERDICT_LOG:
            // Log file event through data bus
            get_data_bus().publish("file_event", (const uint8_t*)"LOG", 3, flow);
            break;

        case FILE_VERDICT_BLOCK:
            // can't block session inside a session
            get_data_bus().publish("file_event", (const uint8_t*)"BLOCK", 5, flow);
            break;

        case FILE_VERDICT_REJECT:
            get_data_bus().publish("file_event", (const uint8_t*)"RESET", 5, flow);
            break;
        default:
            break;
        }
        if ( file_config->trace_type )
            print(std::cout);
    }
}

FileVerdict FileContext::file_signature_lookup(Flow* flow)
{
    if (get_file_sig_sha256() && is_file_signature_enabled())
    {
        FilePolicy& inspect = file_config->get_file_policy();
        return inspect.signature_lookup(flow, this);
    }
    else
        return FILE_VERDICT_UNKNOWN;
}

void FileContext::finish_signature_lookup(Flow* flow, bool final_lookup)
{
    if (get_file_sig_sha256())
    {
        //Check file type based on file policy
        FilePolicy& inspect = file_config->get_file_policy();
        FileVerdict verdict = inspect.signature_lookup(flow, this);
        if ( verdict != FILE_VERDICT_UNKNOWN || final_lookup )
        {
            log_file_event(flow);
            config_file_signature(false);
            file_stats->signatures_processed[get_file_type()][get_file_direction()]++;
        }
        else
        {
            snort_free(sha256);
            sha256 = nullptr;
        }
    }
}

void FileContext::check_policy(Flow* flow, FileDirection dir)
{
    file_counts.files_total++;
    set_file_direction(dir);
    FilePolicy& inspect = file_config->get_file_policy();
    inspect.policy_check(flow, this);
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileContext::process(Flow* flow, const uint8_t* file_data, int data_size,
    FilePosition position)
{
    if ( file_config->trace_stream )
    {
        FileContext::print_file_data(stdout, file_data, data_size,
            file_config->show_data_depth);
    }

    file_counts.file_data_total += data_size;

    if ((!is_file_type_enabled()) and (!is_file_signature_enabled()))
    {
        update_file_size(data_size, position);
        return false;
    }

    if ((FileService::get_file_enforcer()->cached_verdict_lookup(flow, this,
        file_config->get_file_policy()) != FILE_VERDICT_UNKNOWN))
        return true;

    /*file type id*/
    if (is_file_type_enabled())
    {
        process_file_type(file_data, data_size, position);

        /*Don't care unknown file type*/
        if (get_file_type() == SNORT_FILE_TYPE_UNKNOWN)
        {
            config_file_type(false);
            config_file_signature(false);
            update_file_size(data_size, position);
            stop_file_capture();
            return false;
        }

        if (get_file_type() != SNORT_FILE_TYPE_CONTINUE)
        {
            config_file_type(false);
            file_stats->files_processed[get_file_type()][get_file_direction()]++;
            //Check file type based on file policy
            FilePolicy& inspect = file_config->get_file_policy();
            inspect.type_lookup(flow, this);
            log_file_event(flow);
        }
    }

    /* file signature calculation */
    if (is_file_signature_enabled())
    {
        if (!sha256)
            process_file_signature_sha256(file_data, data_size, position);

        file_stats->data_processed[get_file_type()][get_file_direction()]
            += data_size;

        update_file_size(data_size, position);

        if ( file_config->trace_signature )
            print_file_sha256(std::cout);

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (is_file_capture_enabled())
        {
            process_file_capture(file_data, data_size, position);
        }

        finish_signature_lookup(flow, ( file_state.sig_state != FILE_SIG_FLUSH ) );
    }
    else
    {
        update_file_size(data_size, position);
    }

    return true;
}

bool FileContext::process(Flow* flow, const uint8_t* file_data, int data_size,
    uint64_t offset)
{
    if (!file_segments)
        file_segments = new FileSegments(this);
    return file_segments->process(flow, file_data, data_size, offset);
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
        if (!file_signature_context)
            file_signature_context = snort_calloc(sizeof(SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        if(file_state.sig_state == FILE_SIG_FLUSH)
        {
            static uint8_t file_signature_context_backup[sizeof(SHA256_CTX)];
            sha256 = (uint8_t*)snort_alloc(SHA256_HASH_SIZE);
            memcpy(file_signature_context_backup, file_signature_context, sizeof(SHA256_CTX));

            SHA256_Final(sha256, (SHA256_CTX *)file_signature_context);
            memcpy(file_signature_context, file_signature_context_backup, sizeof(SHA256_CTX));
        }
        break;

    case SNORT_FILE_MIDDLE:
        if (!file_signature_context)
            return;
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        if(file_state.sig_state == FILE_SIG_FLUSH)
        {
            static uint8_t file_signature_context_backup[sizeof(SHA256_CTX)];
            if ( !sha256 )
                sha256 = (uint8_t*)snort_alloc(SHA256_HASH_SIZE);
            memcpy(file_signature_context_backup, file_signature_context, sizeof(SHA256_CTX));

            SHA256_Final(sha256, (SHA256_CTX *)file_signature_context);
            memcpy(file_signature_context, file_signature_context_backup, sizeof(SHA256_CTX));
        }

        break;

    case SNORT_FILE_END:
        if (!file_signature_context)
            return;
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        sha256 = new uint8_t[SHA256_HASH_SIZE];
        SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
        file_state.sig_state = FILE_SIG_DONE;
        break;

    case SNORT_FILE_FULL:
        if (!file_signature_context)
            file_signature_context = snort_calloc(sizeof (SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        sha256 = new uint8_t[SHA256_HASH_SIZE];
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
        file_capture = new FileCapture(file_config->capture_min_size,
            file_config->capture_max_size);
    }

    file_state.capture_state =
        file_capture->process_buffer(file_data, data_size, position);

    if (file_state.capture_state != FILE_CAPTURE_SUCCESS)
        stop_file_capture();

    return file_state.capture_state;
}

FileCaptureState FileContext::reserve_file(FileCapture*& dest)
{
    if (!file_capture || !is_file_capture_enabled())
        return FileCapture::error_capture(FILE_CAPTURE_FAIL);

    FileCaptureState state = file_capture->reserve_file(this);
    config_file_capture(false);
    dest = file_capture;
    file_capture = nullptr;
    return state;
}

void FileContext::stop_file_capture()
{
    if (file_capture)
    {
        delete file_capture;
        file_capture = nullptr;
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

uint64_t FileContext::get_processed_bytes()
{
    return processed_bytes;
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
void FileContext::print_file_sha256(std::ostream& log)
{
    unsigned char* hash = sha256;

    if (!sha256)
        return;

    std::ios::fmtflags f(log.flags());
    log <<"SHA256: ";
    for (int i = 0; i < SHA256_HASH_SIZE; i+=2)
    {
        log << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (int)hash[i];
        log << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (int)hash[i+1];
        if (i < SHA256_HASH_SIZE - 2)
            log << ' ';
    }

    log << std::endl;
    log.flags(f);
}

void FileContext::print(std::ostream& log)
{
    log << "File name: " << file_name << std::endl;
    log << "File type: " << file_config->file_type_name(file_type_id)
        << '('<< file_type_id  << ')' << std::endl;
    log << "File size: " << file_size << std::endl;
    log << "Processed size: " << processed_bytes << std::endl;
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

