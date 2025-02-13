//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// file_api.h author Hui Cao <hcao@huica.com>
// 5.25.12 - Initial Source Code. Hui Cao

#ifndef FILE_API_H
#define FILE_API_H

// File API provides all the convenient functions that are used by inspectors.
// Currently, it provides three sets of APIs: file processing, MIME processing,
// and configurations.

#include <atomic>
#include <bitset>
#include <cstring>
#include <string>

#include "main/snort_config.h"
#include "main/snort_types.h"

#define     ENABLE_FILE_TYPE_IDENTIFICATION      0x1
#define     ENABLE_FILE_SIGNATURE_SHA256         0x2
#define     ENABLE_FILE_CAPTURE                  0x4
#define     FILE_ALL_ON                          0xFFFFFFFF
#define     FILE_ALL_OFF                         0x00000000

enum FileAction
{
    FILE_ACTION_DEFAULT = 0,
    FILE_RESUME_BLOCK,
    FILE_RESUME_LOG
};

#define UTF_16_LE_BOM "\xFF\xFE"
#define UTF_16_LE_BOM_LEN 2

enum FileVerdict
{
    FILE_VERDICT_UNKNOWN = 0,
    FILE_VERDICT_LOG,
    FILE_VERDICT_STOP,
    FILE_VERDICT_BLOCK,
    FILE_VERDICT_REJECT,
    FILE_VERDICT_PENDING,
    FILE_VERDICT_STOP_CAPTURE,
    FILE_VERDICT_MAX
};

enum FilePosition
{
    SNORT_FILE_POSITION_UNKNOWN,
    SNORT_FILE_START,
    SNORT_FILE_MIDDLE,
    SNORT_FILE_END,
    SNORT_FILE_FULL
};

enum FileCaptureState
{
    FILE_CAPTURE_SUCCESS = 0,
    FILE_CAPTURE_MIN,                 /*smaller than file capture min*/
    FILE_CAPTURE_MAX,                 /*larger than file capture max*/
    FILE_CAPTURE_MEMCAP,              /*memcap reached, no more file buffer*/
    FILE_CAPTURE_FAIL                 /*Other file capture failures*/
};

enum FileSigState
{
    FILE_SIG_PROCESSING = 0,
    FILE_SIG_DEPTH_FAIL,              /*larger than file signature depth*/
    FILE_SIG_FLUSH,
    FILE_SIG_DONE
};

enum FileProcessType
{
    SNORT_FILE_TYPE_ID,
    SNORT_FILE_SHA256,
    SNORT_FILE_CAPTURE
};

enum FileDirection
{
    FILE_DOWNLOAD,
    FILE_UPLOAD
};

enum FileCharEncoding
{
    SNORT_CHAR_ENCODING_ASCII,
    SNORT_CHAR_ENCODING_UTF_16LE
};

struct FileState
{
    FileCaptureState capture_state;
    FileSigState sig_state;
};

namespace snort
{
#define FILE_ID_MAX          1024
typedef std::bitset<FILE_ID_MAX> FileTypeBitSet;

class FileContext;
class FileInfo;
class Flow;
struct Packet;

class UserFileDataBase
{
public:
    UserFileDataBase() = default;
    virtual ~UserFileDataBase() = default;
    UserFileDataBase(const UserFileDataBase& other);
    UserFileDataBase& operator=(const UserFileDataBase& other);

private:
    void copy(const UserFileDataBase& other);
};

class SO_PUBLIC FilePolicyBase
{
public:

    FilePolicyBase();
    virtual ~FilePolicyBase();

    // This is called when a new flow is queried for the first time
    // Check & update what file policy is enabled on this flow/file
    virtual void policy_check(Flow*, FileInfo*) { }

    // This is called after file type is known
    virtual FileVerdict type_lookup(Packet*, FileInfo*)
    { return FILE_VERDICT_UNKNOWN; }

    // This is called after file signature is complete
    virtual FileVerdict signature_lookup(Packet*, FileInfo*)
    { return FILE_VERDICT_UNKNOWN; }

    virtual void log_file_action(Flow*, FileInfo*, FileAction) { }

    void add_ref()
    { ++ref_count; }

    SO_PUBLIC static void delete_file_policy(FilePolicyBase*);

private:
    std::atomic_uint ref_count;
};

inline void initFilePosition(FilePosition* position, uint64_t processed_size)
{
    *position = SNORT_FILE_START;
    if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}

inline void updateFilePosition(FilePosition* position, uint64_t processed_size)
{
    if ((*position == SNORT_FILE_END) || (*position == SNORT_FILE_FULL))
        *position = SNORT_FILE_START;
    else if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}

inline void finalFilePosition(FilePosition* position)
{
    if (*position == SNORT_FILE_START)
        *position = SNORT_FILE_FULL;
    else if (*position != SNORT_FILE_FULL)
        *position = SNORT_FILE_END;
}

inline bool isFileStart(FilePosition position)
{
    return ((position == SNORT_FILE_START) || (position == SNORT_FILE_FULL));
}

inline bool isFileEnd(FilePosition position)
{
    return ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL));
}

inline FileCharEncoding get_character_encoding(const char* file_name, size_t length)
{
    FileCharEncoding encoding = SNORT_CHAR_ENCODING_ASCII;
    if (length >= UTF_16_LE_BOM_LEN)
    {
        if (memcmp(file_name, UTF_16_LE_BOM, UTF_16_LE_BOM_LEN) == 0)
            encoding = SNORT_CHAR_ENCODING_UTF_16LE;
    }

    return encoding;
}

SO_PUBLIC uint64_t get_file_processed_size(Flow* flow);
SO_PUBLIC FilePosition get_file_position(Packet* pkt);
SO_PUBLIC void set_rule_id_from_type(SnortConfig* sc, uint64_t id, std::string type,
    std::string file_category, std::string file_version, std::vector<std::string> file_groups);
SO_PUBLIC void get_magic_rule_ids_from_type(const std::string& type,
    const std::string& version, FileTypeBitSet& ids_set, SnortConfig*);
}
#endif

