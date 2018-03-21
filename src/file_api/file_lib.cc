//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "utils/util_utf.h"

#include "file_api.h"
#include "file_capture.h"
#include "file_config.h"
#include "file_cache.h"
#include "file_flows.h"
#include "file_service.h"
#include "file_segment.h"
#include "file_stats.h"

using namespace snort;

// Convert UTF16-LE file name to UTF-8.
// Returns allocated name. Caller responsible for freeing the buffer.
char* FileContext::get_UTF8_fname(size_t* converted_len)
{
    FileCharEncoding encoding = get_character_encoding(file_name.c_str(), file_name.length());
    char* outbuf = nullptr;
    if (encoding == SNORT_CHAR_ENCODING_UTF_16LE)
    {
#ifdef HAVE_ICONV
        // UTF-16LE takes 2 or 4 bytes per character, UTF-8 can take max 4
        const size_t outbytesleft = (file_name.length() - UTF_16_LE_BOM_LEN) * 2;
        char* inbuf = (char*)snort_alloc(file_name.length());
        memcpy(inbuf, file_name.c_str(), file_name.length());
        outbuf = (char*)snort_alloc(outbytesleft + 1);
        char* const buf_start = outbuf;
        outbuf = UtfDecodeSession::convert_character_encoding("UTF-8", "UTF-16LE", inbuf + UTF_16_LE_BOM_LEN,
            outbuf, file_name.length() - UTF_16_LE_BOM_LEN, outbytesleft, converted_len);
        snort_free(inbuf);
        if (outbuf == nullptr)
        {
            snort_free(buf_start);
            return nullptr;
        }
#else
        *converted_len = (file_name.length()- UTF_16_LE_BOM_LEN) >> 1;
        outbuf = (char*)snort_alloc(*converted_len + 1);
        uint32_t i, k= 0;
        for ( i = UTF_16_LE_BOM_LEN; i < file_name.length(); i+=2, k++)
            outbuf[k] = (char)file_name[i];
        outbuf[k] = 0;
#endif
    }
    return outbuf;
}

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
    file_name_set = other.file_name_set;
    verdict = other.verdict;
    file_type_enabled = other.file_type_enabled;
    file_signature_enabled = other.file_signature_enabled;
    file_capture_enabled = other.file_capture_enabled;
    file_state = other.file_state;
    // only one copy of file capture
    file_capture = nullptr;
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

void FileInfo::set_file_id(uint64_t id)
{
    file_id = id;
}

uint64_t FileInfo::get_file_id() const
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

void FileInfo::config_file_type(bool enabled)
{
    file_type_enabled = enabled;
}

bool FileInfo::is_file_type_enabled()
{
    return file_type_enabled;
}

void FileInfo::config_file_signature(bool enabled)
{
    file_signature_enabled = enabled;
}

bool FileInfo::is_file_signature_enabled()
{
    return file_signature_enabled;
}

void FileInfo::config_file_capture(bool enabled)
{
    file_capture_enabled = enabled;
}

bool FileInfo::is_file_capture_enabled()
{
    return file_capture_enabled;
}

FileCaptureState FileInfo::reserve_file(FileCapture*& dest)
{
    if (!file_capture)
        return FileCapture::error_capture(FILE_CAPTURE_FAIL);

    FileCaptureState state = file_capture->reserve_file(this);
    config_file_capture(false);
    dest = file_capture;
    file_capture = nullptr;
    return state;
}

FileContext::FileContext ()
{
    file_type_context = nullptr;
    file_signature_context = nullptr;
    file_capture = nullptr;
    file_segments = nullptr;
    inspector = (FileInspect*)InspectorManager::acquire(FILE_ID_NAME, true);
    config = inspector->config;
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
        max_depth = config->file_type_depth;
        break;
    case SNORT_FILE_SHA256:
        max_depth = config->file_signature_depth;
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

void FileContext::log_file_event(Flow* flow, FilePolicyBase* policy)
{
    // wait for file name is set to log file event
    if ( is_file_name_set() )
    {
        bool log_needed = true;

        switch (verdict)
        {
        case FILE_VERDICT_LOG:
            // Log file event through data bus
            DataBus::publish("file_event", (const uint8_t*)"LOG", 3, flow);
            break;

        case FILE_VERDICT_BLOCK:
            // can't block session inside a session
            DataBus::publish("file_event", (const uint8_t*)"BLOCK", 5, flow);
            break;

        case FILE_VERDICT_REJECT:
            DataBus::publish("file_event", (const uint8_t*)"RESET", 5, flow);
            break;
        default:
            log_needed = false;
            break;
        }

        if (policy and log_needed)
            policy->log_file_action(flow, this, FILE_ACTION_DEFAULT);

        if ( config->trace_type )
            print(std::cout);
    }
}

FileVerdict FileContext::file_signature_lookup(Flow* flow)
{
    if (get_file_sig_sha256())
    {
        FilePolicyBase* policy = FileFlows::get_file_policy(flow);

        if (policy)
            return policy->signature_lookup(flow, this);
    }

    return FILE_VERDICT_UNKNOWN;
}

void FileContext::finish_signature_lookup(Flow* flow, bool final_lookup, FilePolicyBase* policy)
{
    if (get_file_sig_sha256())
    {
        verdict = policy->signature_lookup(flow, this);
        if ( verdict != FILE_VERDICT_UNKNOWN || final_lookup )
        {
            FileCache* file_cache = FileService::get_file_cache();
            if (file_cache)
                file_cache->apply_verdict(flow, this, verdict, false, policy);
            log_file_event(flow, policy);
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

void FileContext::set_signature_state(bool gen_sig)
{
    if ( gen_sig )
    {
        if ( sha256 )
        {
            snort_free(sha256);
            sha256 = nullptr;
        }

        file_state.sig_state = FILE_SIG_FLUSH;
    }
    else
        file_state.sig_state = FILE_SIG_PROCESSING;
}

void FileContext::check_policy(Flow* flow, FileDirection dir, FilePolicyBase* policy)
{
    file_counts.files_total++;
    set_file_direction(dir);
    policy->policy_check(flow, this);
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileContext::process(Flow* flow, const uint8_t* file_data, int data_size,
    FilePosition position, FilePolicyBase* policy)
{

    if ( config->trace_stream )
    {
        FileContext::print_file_data(stdout, file_data, data_size,
            config->show_data_depth);
    }

    file_counts.file_data_total += data_size;

    if ((!is_file_type_enabled()) and (!is_file_signature_enabled()))
    {
        update_file_size(data_size, position);
        return false;
    }

    if ((FileService::get_file_cache()->cached_verdict_lookup(flow, this,
        policy) != FILE_VERDICT_UNKNOWN))
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
            FileVerdict v = policy->type_lookup(flow, this);
            if ( v != FILE_VERDICT_UNKNOWN )
            {
                FileCache* file_cache = FileService::get_file_cache();
                if (file_cache)
                    file_cache->apply_verdict(flow, this, v, false, policy);
            }

            log_file_event(flow, policy);
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

        if ( config->trace_signature )
            print_file_sha256(std::cout);

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (is_file_capture_enabled())
        {
            process_file_capture(file_data, data_size, position);
        }

        finish_signature_lookup(flow, ( file_state.sig_state != FILE_SIG_FLUSH ), policy);
    }
    else
    {
        update_file_size(data_size, position);
    }

    return true;
}

bool FileContext::process(Flow* flow, const uint8_t* file_data, int data_size,
    uint64_t offset, FilePolicyBase* policy)
{
    if (!file_segments)
        file_segments = new FileSegments(this);
    return file_segments->process(flow, file_data, data_size, offset, policy);
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
        config->find_file_type_id(file_data, data_size, processed_bytes, &file_type_context);

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
        if (file_state.sig_state == FILE_SIG_FLUSH)
        {
            static uint8_t file_signature_context_backup[sizeof(SHA256_CTX)];
            sha256 = (uint8_t*)snort_alloc(SHA256_HASH_SIZE);
            memcpy(file_signature_context_backup, file_signature_context, sizeof(SHA256_CTX));

            SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
            memcpy(file_signature_context, file_signature_context_backup, sizeof(SHA256_CTX));
        }
        break;

    case SNORT_FILE_MIDDLE:
        if (!file_signature_context)
            return;
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        if (file_state.sig_state == FILE_SIG_FLUSH)
        {
            static uint8_t file_signature_context_backup[sizeof(SHA256_CTX)];
            if ( !sha256 )
                sha256 = (uint8_t*)snort_alloc(SHA256_HASH_SIZE);
            memcpy(file_signature_context_backup, file_signature_context, sizeof(SHA256_CTX));

            SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
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
        file_capture = new FileCapture(config->capture_min_size,
            config->capture_max_size);
    }

    file_state.capture_state =
        file_capture->process_buffer(file_data, data_size, position);

    if (file_state.capture_state != FILE_CAPTURE_SUCCESS)
        stop_file_capture();

    return file_state.capture_state;
}

void FileContext::stop_file_capture()
{
    if (file_capture)
    {
        delete file_capture;
        file_capture = nullptr;
    }

    config_file_capture(false);
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

uint64_t FileContext::get_processed_bytes()
{
    return processed_bytes;
}

void FileContext::print_file_data(FILE* fp, const uint8_t* data, int len, int max_depth)
{
    char str[18];
    int i, pos;

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
        char c = (char)data[i];

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

void FileContext::print_file_name(std::ostream& log)
{
    if (file_name.length() <= 0)
        return;

    size_t fname_len = file_name.length();
    char* outbuf = get_UTF8_fname(&fname_len);
    const char* fname  = (outbuf != nullptr) ? outbuf : file_name.c_str();

    log << "File name: ";

    size_t pos = 0;
    while (pos < fname_len)
    {
        if (isprint((int)fname[pos]))
        {
            log << fname[pos];
            pos++;
        }
        else
        {
            log << "|";
            bool add_space = false;
            while ((pos < fname_len) && !isprint((int)fname[pos]))
            {
                int ch = 0xff & fname[pos];
                if (add_space)
                    log << " ";
                else
                    add_space = true;
                log << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << ch;
                pos++;
            }
            log << "|" << std::dec;
        }
    }
    log << std::endl;

    if (outbuf)
        snort_free(outbuf);
}

void FileContext::print(std::ostream& log)
{
    print_file_name(log);
    log << "File type: " << config->file_type_name(file_type_id)
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

