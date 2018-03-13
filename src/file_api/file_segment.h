//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
//  file_segment.h author Hui Cao <huica@cisco.com>

#ifndef FILE_SEGMENT_H
#define FILE_SEGMENT_H

// Segmented file data reassemble and processing

#include <string>

#include "file_api.h"

namespace snort
{
class Flow;
}
class FileConfig;

class FileSegment
{
public:
    FileSegment() = default;
    ~FileSegment();

    // Use single list for simplicity
    FileSegment* next = nullptr;
    uint32_t offset = 0;
    std::string* data = nullptr;
};

class FileSegments
{
public:
    FileSegments(snort::FileContext*);
    ~FileSegments();

    void clear();

    // Process file segments with current_offset specified. If file segment is out of order,
    // it will be put into the file segments queue.
    int process(snort::Flow*, const uint8_t* file_data, uint64_t data_size, uint64_t offset,
        snort::FilePolicyBase*);

private:
    FileSegment* head = nullptr;
    uint64_t current_offset;
    snort::FileContext* context = nullptr;

    void add(const uint8_t* file_data, uint64_t data_size, uint64_t offset);
    FilePosition get_file_position(uint64_t data_size, uint64_t file_size);
    int process_one(snort::Flow*, const uint8_t* file_data, int data_size, snort::FilePolicyBase*);
    int process_all(snort::Flow*, snort::FilePolicyBase*);
};

#endif

