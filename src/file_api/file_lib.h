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

// file_lib.h author Hui Cao <huica@cisco.com>

#ifndef FILE_LIB_H
#define FILE_LIB_H

// This will be basis of file class

#include <mutex>
#include <ostream>
#include <string>

#include "file_api/file_api.h"
#include "utils/util.h"

#define SNORT_FILE_TYPE_UNKNOWN          UINT16_MAX
#define SNORT_FILE_TYPE_CONTINUE         0

const std::string VerdictName[] =
{"Unknown", "Log", "Stop", "Block", "Reset", "Pending", "Stop Capture", "INVALID"};

class FileConfig;
class FileSegments;

namespace snort
{
class FileCapture;
class FileInspect;
class Flow;

class SO_PUBLIC FileInfo
{
public:
    virtual ~FileInfo();
    FileInfo() = default;
    FileInfo(const FileInfo& other);
    FileInfo& operator=(const FileInfo& other);
    uint32_t get_file_type() const;
    void set_file_type(uint64_t index);
    void set_file_name(const char* file_name, uint32_t name_size);
    void set_url(const char* url, uint32_t url_size);
    std::string& get_file_name();
    std::string& get_url();
    // Whether file name has been set (could be empty file name)
    bool is_file_name_set() const { return file_name_set; }
    bool is_url_set() const { return url_set; }

    void set_file_size(uint64_t size);
    uint64_t get_file_size() const;
    void set_file_direction(FileDirection dir);
    FileDirection get_file_direction() const;
    uint8_t* get_file_sig_sha256() const;
    std::string sha_to_string(const uint8_t* sha256);
    void set_file_id(uint64_t index);
    uint64_t get_file_id() const;

    // Configuration functions
    void config_file_type(bool enabled);
    bool is_file_type_enabled();
    void config_file_signature(bool enabled);
    bool is_file_signature_enabled();
    void config_file_capture(bool enabled);
    bool is_file_capture_enabled();
    void set_policy_id(uint32_t id);
    uint32_t get_policy_id();
    void set_file_data(UserFileDataBase* fd);
    UserFileDataBase* get_file_data() const;
    void copy(const FileInfo& other, bool clear_data = true);
    // Preserve the file in memory until it is released
    // The file reserved will be returned and it will be detached from file context/session
    FileCaptureState reserve_file(FileCapture*& dest);
    int64_t get_max_file_capture_size();

    FileState get_file_state() { return file_state; }

    FileVerdict verdict = FILE_VERDICT_UNKNOWN;
    bool processing_complete = false;
    std::mutex user_file_data_mutex;
    struct timeval pending_expire_time = {0, 0};

protected:
    std::string file_name;
    bool file_name_set = false;
    std::string url;
    bool url_set = false;
    uint64_t file_size = 0;
    FileDirection direction = FILE_DOWNLOAD;
    uint32_t file_type_id = SNORT_FILE_TYPE_CONTINUE;
    uint8_t* sha256 = nullptr;
    uint64_t file_id = 0;
    FileCapture* file_capture = nullptr;
    bool file_type_enabled = false;
    bool file_signature_enabled = false;
    bool file_capture_enabled = false;
    FileState file_state = { FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING };
    uint32_t policy_id = 0;
    UserFileDataBase* user_file_data = nullptr;
};

class SO_PUBLIC FileContext : public FileInfo
{
public:
    FileContext();
    ~FileContext() override;

    void check_policy(Flow*, FileDirection, FilePolicyBase*);

    // main processing functions

    // Return:
    //    true: continue processing/log/block this file
    //    false: ignore this file
    bool process(Packet*, const uint8_t* file_data, int data_size, FilePosition, FilePolicyBase*);
    bool process(Packet*, const uint8_t* file_data, int data_size, uint64_t offset, FilePolicyBase*,
        FilePosition position=SNORT_FILE_POSITION_UNKNOWN);
    void process_file_signature_sha256(const uint8_t* file_data, int data_size, FilePosition);
    void update_file_size(int data_size, FilePosition position);
    void stop_file_capture();
    FileCaptureState process_file_capture(const uint8_t* file_data, int data_size, FilePosition);
    void log_file_event(Flow*, FilePolicyBase*);
    FileVerdict file_signature_lookup(Packet*);

    void set_signature_state(bool gen_sig);

    //File properties
    uint64_t get_processed_bytes();

    void print_file_sha256(std::ostream&);
    void print_file_name(std::ostream&);
    static void print_file_data(FILE* fp, const uint8_t* data, int len, int max_depth);
    void print(std::ostream&);
    char* get_UTF8_fname(size_t* converted_len);
    void set_not_cacheable() { cacheable = false; }
    bool is_cacheable() { return cacheable; }
    bool segments_queued() { return (file_segments != nullptr); }

private:
    uint64_t processed_bytes = 0;
    void* file_type_context;
    void* file_signature_context;
    FileSegments* file_segments;
    FileInspect* inspector;
    FileConfig*  config;
    bool cacheable = true;

    void finalize_file_type();
    void finish_signature_lookup(Packet*, bool, FilePolicyBase*);
    void find_file_type_from_ips(Packet*, const uint8_t *file_data, int data_size, FilePosition);
    void process_file_type(Packet*, const uint8_t* file_data, int data_size, FilePosition);
};
}
#endif

