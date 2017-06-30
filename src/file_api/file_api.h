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
// file_api.h author Hui Cao <hcao@huica.com>
// 5.25.12 - Initial Source Code. Hui Cao

#ifndef FILE_API_H
#define FILE_API_H

// File API provides all the convenient functions that are used by inspectors.
// Currently, it provides three sets of APIs: file processing, MIME processing,
// and configurations.

#include <string>

#include "main/snort_types.h"

#define     ENABLE_FILE_TYPE_IDENTIFICATION      0x1
#define     ENABLE_FILE_SIGNATURE_SHA256         0x2
#define     ENABLE_FILE_CAPTURE                  0x4
#define     FILE_ALL_ON                          0xFFFFFFFF
#define     FILE_ALL_OFF                         0x00000000


#define     FILE_RESUME_BLOCK                    0x01
#define     FILE_RESUME_LOG                      0x02

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

const std::string VerdictName[] =
{"Unknown", "Log", "Stop", "Block", "Reset", "Pending", "Stop Capture", "INVALID"};

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

struct FileState
{
    FileCaptureState capture_state;
    FileSigState sig_state;
};

class FileContext;
struct FileCaptureInfo;

#define DEFAULT_FILE_ID   0

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

SO_PUBLIC uint64_t get_file_processed_size(class Flow* flow);
FilePosition get_file_position(struct Packet* pkt);

#endif

