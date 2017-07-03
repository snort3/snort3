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

// file_lib.h author Hui Cao <huica@cisco.com>

#ifndef FILE_LIB_H
#define FILE_LIB_H

// This will be basis of file class

#include <ostream>
#include <string>

#include "file_api/file_api.h"
#include "utils/util.h"

#define SNORT_FILE_TYPE_UNKNOWN          UINT16_MAX
#define SNORT_FILE_TYPE_CONTINUE         0

class FileCapture;
class FileConfig;
class FileSegments;
class Flow;
class FileInspect;

class SO_PUBLIC FileInfo
{
public:
    virtual ~FileInfo();
    FileInfo() { }
    FileInfo(const FileInfo& other);
    FileInfo& operator=(const FileInfo& other);
    uint32_t get_file_type() const;
    void set_file_name(const char* file_name, uint32_t name_size);
    std::string& get_file_name();
    // Whether file name has been set (could be empty file name)
    bool is_file_name_set() const { return file_name_set; }

    void set_file_size(uint64_t size);
    uint64_t get_file_size() const;
    void set_file_direction(FileDirection dir);
    FileDirection get_file_direction() const;
    uint8_t* get_file_sig_sha256() const;
    std::string sha_to_string(const uint8_t* sha256);
    void set_file_id(size_t index);
    size_t get_file_id() const;
    FileVerdict verdict = FILE_VERDICT_UNKNOWN;

protected:
    std::string file_name;
    bool file_name_set = false;
    uint64_t file_size = 0;
    FileDirection direction = FILE_DOWNLOAD;
    uint32_t file_type_id = SNORT_FILE_TYPE_CONTINUE;
    uint8_t* sha256 = nullptr;
    size_t file_id = 0;

private:
    void copy(const FileInfo& other);
};

class SO_PUBLIC FileContext : public FileInfo
{
public:
    FileContext();
    ~FileContext();

    void check_policy(Flow*, FileDirection);

    // main processing functions

    // Return:
    //    true: continue processing/log/block this file
    //    false: ignore this file
    bool process(Flow*, const uint8_t* file_data, int data_size, FilePosition);
    bool process(Flow*, const uint8_t* file_data, int data_size, uint64_t offset);
    void process_file_type(const uint8_t* file_data, int data_size, FilePosition position);
    void process_file_signature_sha256(const uint8_t* file_data, int data_size, FilePosition pos);
    void update_file_size(int data_size, FilePosition position);
    void stop_file_capture();
    FileCaptureState process_file_capture(const uint8_t* file_data, int data_size,
        FilePosition pos);
    void log_file_event(Flow*);
    FileVerdict file_signature_lookup(Flow*);

    // Preserve the file in memory until it is released
    // The file reserved will be returned and it will be detached from file context/session
    FileCaptureState reserve_file(FileCapture*& dest);

    // Configuration functions
    void config_file_type(bool enabled);
    bool is_file_type_enabled();
    void config_file_signature(bool enabled);
    bool is_file_signature_enabled();
    void config_file_capture(bool enabled);
    bool is_file_capture_enabled();

    void set_signature_state(bool gen_sig)
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

    //File properties
    uint64_t get_processed_bytes();

    void print_file_sha256(std::ostream&);
    static void print_file_data(FILE* fp, const uint8_t* data, int len, int max_depth);
    void print(std::ostream&);

private:
    bool file_type_enabled = false;
    bool file_signature_enabled = false;
    bool file_capture_enabled = false;
    uint64_t processed_bytes = 0;
    void* file_type_context;
    void* file_signature_context;
    FileConfig* file_config;
    FileInspect* inspector;
    FileCapture* file_capture;
    FileSegments* file_segments;
    FileState file_state = { FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING };

    inline int get_data_size_from_depth_limit(FileProcessType type, int data_size);
    inline void finalize_file_type();
    inline void finish_signature_lookup(Flow*, bool);
};

#endif

