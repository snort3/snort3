//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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
//  file_segment.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_segment.h"

#include "file_lib.h"
#include "file_module.h"

#include "detection/detection_engine.h"

using namespace snort;

FileSegment::~FileSegment ()
{
    if (data)
        delete data;
}

FileSegments::FileSegments (FileContext* ctx)
{
    head = nullptr;
    tail = nullptr;
    current_offset = 0;
    context =  ctx;
}

FileSegments::~FileSegments ()
{
    clear();
}

void FileSegments::clear()
{
    FileSegment* current_segment = head;

    while (current_segment)
    {
        FileSegment* previous_segment = current_segment;
        current_segment = current_segment->next;
        delete previous_segment;
    }

    head = nullptr;
    tail = nullptr;
    current_offset = 0;
}

// Update the segment list based on new data
void FileSegments::add(const uint8_t* file_data, int64_t data_size, uint64_t offset)
{
    if (!head)
    {
        FileSegment* new_segment = new FileSegment();
        new_segment->offset = offset;
        new_segment->data = new std::string((const char*)file_data, data_size);
        FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
            GET_CURRENT_PACKET , "Adding segment, offset : %u data_size : %lu\n",
            new_segment->offset, data_size);
        head = new_segment;
        tail = new_segment;
        return;
    }

    uint64_t start = offset;
    uint64_t end = offset + data_size;
    // left points to segment that "next" pointer needs to be updated
    FileSegment* left = nullptr;
    FileSegment* previous = nullptr;
    bool find_left = false;

    // Find left boundary, left points to segment that needs update.
    // The list is sorted by offset, so instead of always walking from the
    // head we use head/tail fast paths and, for a middle insertion, walk
    // from whichever end is closer to the target offset. This keeps
    // in-order (ascending or descending) inserts O(1). tail has the maximum
    // offset, so a node greater than start exists iff tail->offset > start.
    if (tail->offset > start)
    {
        find_left = true;

        if (head->offset > start)
        {
            // start is before every segment: insert before head
            left = nullptr;
        }
        else
        {
            // head->offset <= start < tail->offset: find the last segment
            // whose offset is <= start (same node the head walk would stop
            // just after) by walking from the closer end.
            uint64_t head_dist = start - head->offset;
            uint64_t tail_dist = tail->offset - start;
            FileSegment* le = head;

            if (tail_dist < head_dist)
            {
                for (FileSegment* n = tail->prev; n; n = n->prev)
                {
                    if (n->offset <= start)
                    {
                        le = n;
                        break;
                    }
                }
            }
            else
            {
                while (le->next and (le->next->offset <= start))
                    le = le->next;
            }

            left = le;
        }
    }
    else
    {
        // start >= tail->offset: new segment belongs at the end of the list
        find_left = false;
        previous = tail;
    }

    // New segment should be at the end of link list
    if (!find_left)
    {
        left = previous;
        if (left->offset +left->data->size() >start)
        {
            offset = left->offset + left->data->size();
            data_size = end -offset;
            file_data = file_data + offset - start;
        }
        insert_segment(file_data, data_size, offset, find_left, &left);
    }
    // New segment should be at the start of link list
    else if (!left)
    {
        if (end > head->offset)
        {
            /* Overlap, trim off extra data from end */
            data_size = head->offset - offset;
        }
        insert_segment(file_data, data_size, offset, find_left, &left);
    }
    else
    {
        //Left Overlap
        while(left and (left->offset + left->data->size() <= end))
        {

            const uint8_t *cur_file_data = file_data;
            if ( (left->offset + left->data->size() > start)  )
            {
                offset = left->offset + left->data->size();
                data_size = end - offset;
                cur_file_data = cur_file_data + offset - start;
            }
            //Right Overlap
            if ( left->next and (left->next->offset < end) )
            {
                data_size = left->next->offset - offset;
            }

            insert_segment(cur_file_data, data_size, offset, find_left, &left);
            left = left->next;
        }
    }
}

void FileSegments::insert_segment(const uint8_t* file_data, int64_t data_size, uint64_t offset, bool find_left,  FileSegment** left)
{
    // ignore overlap case
    if (data_size <= 0)
    {
        FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL,
            GET_CURRENT_PACKET, "Complete overlap while adding segments  offset : %lu data_size : %lu\n",
            offset, data_size);
        return;
    }

    FileSegment* new_segment = new FileSegment();
    new_segment->offset = offset;
    new_segment->data = new std::string((const char*)file_data, data_size);

    FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
        GET_CURRENT_PACKET, "Adding offset : %lu data_size : %lu\n", offset,
        data_size);
    if (!*left)
    {
        // Insert before head
        new_segment->next = head;
        if (head)
            head->prev = new_segment;
        else
            tail = new_segment;
        head = new_segment;
    }
    else if (!find_left)
    {
        // Append after left (left is the tail)
        new_segment->prev = *left;
        (*left)->next = new_segment;
        tail = new_segment;
    }
    else
    {
        // Insert after left, before left->next
        new_segment->next = (*left)->next;
        new_segment->prev = *left;
        if ((*left)->next)
            (*left)->next->prev = new_segment;
        else
            tail = new_segment;
        (*left)->next = new_segment;
        *left = (*left)->next;
    }
}

FilePosition FileSegments::get_file_position(uint64_t data_size, uint64_t file_size)
{
    if (current_offset == 0)
    {
        if (file_size == data_size)
            return SNORT_FILE_FULL;
        else
            return SNORT_FILE_START;
    }

    if (file_size and (file_size <= data_size + current_offset))
        return SNORT_FILE_END;

    return SNORT_FILE_MIDDLE;
}

int FileSegments::process_one(Packet* p, const uint8_t* file_data, int data_size,
    FilePolicyBase* policy, FilePosition position)
{
    if (position == SNORT_FILE_POSITION_UNKNOWN)
        position = get_file_position(data_size, context->get_file_size());

    return context->process(p, file_data, data_size, position, policy);
}

int FileSegments::process_all(Packet* p, FilePolicyBase* policy)
{
    int ret = 1;

    FileSegment* current_segment = head;
    while (current_segment && (current_offset == current_segment->offset))
    {
        FILE_DEBUG(file_trace,  DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
          p, "processing the current offset %lu\n", current_offset);

        ret = process_one(p, (const uint8_t*)current_segment->data->data(),
            current_segment->data->size(), policy);

        if (!ret)
        {
            clear();
            break;
        }

        current_offset += current_segment->data->size();
        head = current_segment->next;
        if (head)
            head->prev = nullptr;
        else
            tail = nullptr;
        delete(current_segment);
        current_segment = head;
    }

    return ret;
}

/*
 * Process file segment, do file segment reassemble if the file segment is
 * out of order.
 * Return:
 *    1: continue processing/log/block this file
 *    0: ignore this file
 */
int FileSegments::process(Packet* p, const uint8_t* file_data, uint64_t data_size,
    uint64_t offset, FilePolicyBase* policy, FilePosition position)
{
    int ret = 0;

    if (offset < current_offset)
    {
        if (offset + data_size > current_offset)
        {
            file_data += (current_offset - offset);
            data_size = (offset + data_size) - current_offset;
            offset = current_offset;
        }
        else
        {
            FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL,
                p, "not adding to file segment queue offset %lu , current_offset %lu\n",
                offset , current_offset);
            return 1;
        }
    }

    // Walk through the segments that can be flushed
    if (current_offset == offset)
    {
        if (head and offset+data_size > head->offset)
            data_size = head->offset - offset;

        ret =  process_one(p, file_data, data_size, policy, position);
        current_offset += data_size;
        if (!ret)
        {
            clear();
            return 0;
        }

        ret = process_all(p, policy);
    }
    else if ((current_offset < context->get_file_size()) && (current_offset < offset))
    {
        add(file_data, data_size, offset);
        return 1;
    }

    return ret;
}

