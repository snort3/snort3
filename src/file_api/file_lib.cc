//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "packet_tracer/packet_tracer.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
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
#include "file_module.h"
#include "detection/fp_detect.h"

using namespace snort;

THREAD_LOCAL ProfileStats file_perf_stats;

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
    if (user_file_data)
    {
        user_file_data_mutex.lock();
        delete user_file_data;
        set_file_data(nullptr);
        user_file_data_mutex.unlock();
    }

    if (sha256)
        delete[] sha256;
}

void FileInfo::copy(const FileInfo& other, bool clear_data)
{
    if (&other == this)
        return;

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
    url = other.url;
    url_set = other.url_set;
    verdict = other.verdict;
    file_type_enabled = other.file_type_enabled;
    file_signature_enabled = other.file_signature_enabled;
    file_capture_enabled = other.file_capture_enabled;
    file_state = other.file_state;
    pending_expire_time = other.pending_expire_time;
    if (clear_data)
    {
        // only one copy of file capture
        file_capture = nullptr;
        policy_id = 0;
        user_file_data = nullptr;
    }
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

void FileInfo::set_url(const char* url_name, uint32_t url_size)
{
    if (url_name and url_size)
    {
        url.assign(url_name, url_size);
    }

    url_set = true;
}

std::string& FileInfo::get_file_name()
{
    return file_name;
}

std::string& FileInfo::get_url()
{
    return url;
}

void FileInfo::set_file_size(uint64_t size)
{
    file_size = size;
}

uint64_t FileInfo::get_file_size() const
{
    return file_size;
}

void FileInfo::set_file_type(uint64_t id)
{
    file_type_id = id;
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

void FileInfo::set_policy_id(uint32_t id)
{
    policy_id = id;
}

uint32_t FileInfo::get_policy_id()
{
    return policy_id;
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

int64_t FileInfo::get_max_file_capture_size()
{
    return (file_capture ? file_capture->get_max_file_capture_size() : 0);
}

void FileInfo::set_file_data(UserFileDataBase* fd)
{
    user_file_data = fd;
}

UserFileDataBase* FileInfo::get_file_data() const
{
    return user_file_data;
}

FileContext::FileContext ()
{
    file_type_context = nullptr;
    file_signature_context = nullptr;
    file_capture = nullptr;
    file_segments = nullptr;
    inspector = (FileInspect*)InspectorManager::acquire_file_inspector();
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
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FILE_VERDICT, (const uint8_t*)"LOG", 3, flow);
            break;

        case FILE_VERDICT_BLOCK:
            // can't block session inside a session
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FILE_VERDICT, (const uint8_t*)"BLOCK", 5, flow);
            break;

        case FILE_VERDICT_REJECT:
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FILE_VERDICT, (const uint8_t*)"RESET", 5, flow);
            break;
        default:
            log_needed = false;
            break;
        }

        user_file_data_mutex.lock();

        if (policy and log_needed and user_file_data)
            policy->log_file_action(flow, this, FILE_ACTION_DEFAULT);

        user_file_data_mutex.unlock();

        if ( config->trace_type )
            print(std::cout);
    }
}

FileVerdict FileContext::file_signature_lookup(Packet* p)
{
    Flow* flow = p->flow;

    if (get_file_sig_sha256())
    {
        FilePolicyBase* policy = FileFlows::get_file_policy(flow);

        if (policy)
            return policy->signature_lookup(p, this);
    }

    return FILE_VERDICT_UNKNOWN;
}

void FileContext::finish_signature_lookup(Packet* p, bool final_lookup, FilePolicyBase* policy)
{
    Flow* flow = p->flow;

    if (get_file_sig_sha256())
    {
        verdict = policy->signature_lookup(p, this);
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
            p, "finish signature lookup verdict %d\n", verdict);
        if ( verdict != FILE_VERDICT_UNKNOWN || final_lookup )
        {
            FileCache* file_cache = FileService::get_file_cache();
            if (file_cache)
                file_cache->apply_verdict(p, this, verdict, false, policy);

            if ( PacketTracer::is_active() and ( verdict == FILE_VERDICT_BLOCK
                    or verdict == FILE_VERDICT_REJECT ))
            {
                PacketTracer::log("File: signature lookup verdict %s\n",
                    verdict == FILE_VERDICT_BLOCK ? "block" : "reject");
            }
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
bool FileContext::process(Packet* p, const uint8_t* file_data, int data_size,
    FilePosition position, FilePolicyBase* policy)
{
    // cppcheck-suppress unreadVariable
    Profile profile(file_perf_stats);
    Flow* flow = p->flow;

    if ( config->trace_stream )
    {
        FileContext::print_file_data(stdout, file_data, data_size,
            config->show_data_depth);
    }

    file_counts.file_data_total += data_size;

    if ((!is_file_type_enabled()) and (!is_file_signature_enabled()))
    {
        update_file_size(data_size, position);
        processing_complete = true;
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
            p, "File: Type and Sig not enabled\n");
        if (PacketTracer::is_active())
            PacketTracer::log("File: Type and Sig not enabled\n");
        return false;
    }

    if (cacheable and (FileService::get_file_cache()->cached_verdict_lookup(p, this, policy) !=
        FILE_VERDICT_UNKNOWN))
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
            p, "file process completed in file context process\n");
        processing_complete = true;
        return true;
    }

    /*file type id*/
    if (is_file_type_enabled())
    {
        process_file_type(p, file_data, data_size, position);

        /*Don't care unknown file type*/
        if (get_file_type() == SNORT_FILE_TYPE_UNKNOWN)
        {
            config_file_type(false);
            config_file_signature(false);
            update_file_size(data_size, position);
            processing_complete = true;
            stop_file_capture();
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                "File: Type unknown\n");
            if (PacketTracer::is_active())
                PacketTracer::log("File: Type unknown\n");
            return false;
        }

        if (get_file_type() != SNORT_FILE_TYPE_CONTINUE)
        {
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                "File: Type-%s found\n", file_type_name(get_file_type()).c_str());
            if (PacketTracer::is_active())
                PacketTracer::log("File: Type-%s found\n",
                    file_type_name(get_file_type()).c_str());
            config_file_type(false);

            if (PacketTracer::is_active() and (!(is_file_signature_enabled())))
            {
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                   "File: signature config is disabled\n");
                PacketTracer::log("File: signature config is disabled\n");
            }

            file_stats->files_processed[get_file_type()][get_file_direction()]++;
            //Check file type based on file policy
            FileVerdict v = policy->type_lookup(p, this);
            if ( v != FILE_VERDICT_UNKNOWN )
            {
                if (v == FILE_VERDICT_STOP)
                    config_file_signature(false);
                FileCache* file_cache = FileService::get_file_cache();
                if (file_cache)
                    file_cache->apply_verdict(p, this, v, false, policy);

                if ( PacketTracer::is_active() and ( v == FILE_VERDICT_BLOCK
                        or v == FILE_VERDICT_REJECT ))
                {
                    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                       "File: file type verdict %s\n", v == FILE_VERDICT_BLOCK ? "block" : "reject");
                    PacketTracer::log("File: file type verdict %s\n",
                        v == FILE_VERDICT_BLOCK ? "block" : "reject");
                }
            }

            log_file_event(flow, policy);
        }
    }

    /* file signature calculation */
    if (is_file_signature_enabled())
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "file signature is enabled\n");
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

        finish_signature_lookup(p, ( file_state.sig_state != FILE_SIG_FLUSH ), policy);

        if (file_state.sig_state == FILE_SIG_DEPTH_FAIL)
        {
            verdict = policy->signature_lookup(p, this);
            if ( verdict != FILE_VERDICT_UNKNOWN )
            {
                FileCache* file_cache = FileService::get_file_cache();
                if (file_cache)
                    file_cache->apply_verdict(p, this , verdict, false, policy);

                log_file_event(flow, policy);
            }
            else
            {
                FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, p,
                    "File: Sig depth exceeded\n");
                if (PacketTracer::is_active())
                    PacketTracer::log("File: Sig depth exceeded\n");
                return false;
            }
        }
    }
    else
    {
        update_file_size(data_size, position);
    }

    return true;
}

bool FileContext::process(Packet* p, const uint8_t* file_data, int data_size,
    uint64_t offset, FilePolicyBase* policy, FilePosition position)
{
    if (!file_segments)
        file_segments = new FileSegments(this);
    return file_segments->process(p, file_data, data_size, offset, policy, position);
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
void FileContext::find_file_type_from_ips(Packet* pkt, const uint8_t* file_data, int data_size,
    FilePosition position)
{
    bool depth_exhausted = false;

    if ((int64_t)processed_bytes + data_size >= config->file_type_depth)
    {
        data_size = config->file_type_depth - processed_bytes;
        assert(data_size > 0);
        depth_exhausted = true;
    }
    const FileConfig* const conf = get_file_config();
    Packet *p = DetectionEngine::set_next_packet(pkt);
    DetectionEngine de;
    p->flow = pkt->flow;

    p->context->file_data = { file_data, (unsigned int)data_size };
    p->context->file_pos = processed_bytes;
    p->context->file_type_process = true;
    p->context->set_snort_protocol_id(conf->snort_protocol_id);
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    p->proto_bits |= PROTO_BIT__PDU;

    bool set_file_context = false;
    FileFlows* files = FileFlows::get_file_flows(p->flow, false);
    if (files)
    {
        FileContext* context = files->get_current_file_context();
        if (!context or context != this)
        {
            files->set_current_file_context(this);
            set_file_context = true;
        }
    }
    fp_eval_service_group(p, conf->snort_protocol_id);
    if (set_file_context)
        files->set_current_file_context(nullptr);
    /* Check whether file transfer is done or type depth is reached */
    if ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL) || depth_exhausted)
        finalize_file_type();
}

void FileContext::process_file_type(Packet* pkt,const uint8_t* file_data, int data_size,
    FilePosition position)
{
    /* file type already found and no magics to continue */
    find_file_type_from_ips(pkt, file_data, data_size, position);
}

void FileContext::process_file_signature_sha256(const uint8_t* file_data, int data_size,
    FilePosition position)
{
    if ((int64_t)processed_bytes + data_size > config->file_signature_depth)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, GET_CURRENT_PACKET,
            "process_file_signature_sha256:FILE_SIG_DEPTH_FAIL\n");
        file_state.sig_state = FILE_SIG_DEPTH_FAIL;
        return;
    }

    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
        "processing file signature position: %d sig state %d \n", position, file_state.sig_state);
    switch (position)
    {
    case SNORT_FILE_START:
        if (!file_signature_context)
            file_signature_context = snort_calloc(sizeof(SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "position is start of file\n");
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
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "position is middle of the file\n");
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
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "position is end of the file\n");
        break;

    case SNORT_FILE_FULL:
        if (!file_signature_context)
            file_signature_context = snort_calloc(sizeof (SHA256_CTX));
        SHA256_Init((SHA256_CTX*)file_signature_context);
        SHA256_Update((SHA256_CTX*)file_signature_context, file_data, data_size);
        sha256 = new uint8_t[SHA256_HASH_SIZE];
        SHA256_Final(sha256, (SHA256_CTX*)file_signature_context);
        file_state.sig_state = FILE_SIG_DONE;
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "position is full file\n");
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

    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET,
        "Updating file size of file_id %lu at position %d with processed_bytes %lu\n",
        file_id, position, processed_bytes);
    if ((position == SNORT_FILE_END)or (position == SNORT_FILE_FULL))
    {
        file_size = processed_bytes;
        processed_bytes = 0;
        processing_complete = true;
    }
}

uint64_t FileContext::get_processed_bytes()
{
    return processed_bytes;
}

void FileContext::print_file_data(FILE* fp, const uint8_t* data, int len, int max_depth)
{
    if (max_depth < len)
        len = max_depth;

    fprintf(fp,"Show length: %d \n", len);

    int pos = 0;
    char str[18];
    for (int i=0; i<len; i++)
    {
        char c = (char)data[i];
        if (isprint(c) and (c == ' ' or !isspace(c)))
            str[pos] = c; // cppcheck-suppress unreadVariable
        else
            str[pos] = '.'; // cppcheck-suppress unreadVariable
        pos++;
        fprintf(fp, "%02X ", data[i]);

        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' '; // cppcheck-suppress unreadVariable
            pos++;
            fprintf(fp, "%s", " ");
        }
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
    size_t fname_len = file_name.length();
    if (!fname_len)
        return;

    char* outbuf = get_UTF8_fname(&fname_len);
    const char* fname  = (outbuf != nullptr) ? outbuf : file_name.c_str();

    if (!PacketTracer::is_daq_activated())
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

    if (!PacketTracer::is_daq_activated())
    	log << std::endl;

    if (outbuf)
        snort_free(outbuf);
}

void FileContext::print(std::ostream& log)
{
    print_file_name(log);
    if (url.length() > 0)
        log << "File URI: "<< url << std::endl;
    log << "File type: " << config->file_type_name(file_type_id)
        << '('<< file_type_id  << ')' << std::endl;
    log << "File size: " << file_size << std::endl;
    log << "Processed size: " << processed_bytes << std::endl;
}
