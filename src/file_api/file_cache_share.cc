//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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
//  file_cache_share.cc author Shilpa Nagpal <shinagpa@cisco.com>


#include "config.h"

#include "file_cache_share.h"
#include "file_service.h"
#include "log/messages.h"

using namespace snort;

void FileCacheShare::handle(DataEvent& de, Flow*)
{
    FileMPEvent& fe = static_cast<FileMPEvent&>(de);
    int64_t timeout = fe.get_timeout();
    FileHashKey key = fe.get_hashkey();
    FileInfo file = fe.get_file_ctx();

    LogMessage("File Cache Sharing: Received event with file_id %lu\n", key.file_id);

    FileCache* file_cache = FileService::get_file_cache();
    if (file_cache)
    {
        bool cache_full = false;
        int64_t cache_expire = 0;
        FileContext* file_got = file_cache->add(key, timeout, cache_full, cache_expire, ins);
        if (file_got)
        {    
            *((FileInfo*)(file_got)) = file;
        }
    }
}

bool serialize_file_event(snort::DataEvent* event, char*& buffer, uint16_t* len)
{
    if (!event)
        return false;

    snort::FileMPEvent* file_event = static_cast<snort::FileMPEvent*>(event);
    uint16_t event_buffer_len = file_event->get_data_len();
    if (event_buffer_len == 0)
        return false;
    
    buffer = new char[event_buffer_len];
    if (!buffer)
        return false;

    file_event->serialize(buffer, len);
    return true;
}

bool deserialize_file_event(const char* buffer, uint16_t len, snort::DataEvent*& event)
{
    if (!buffer || len == 0)
        return false;

    snort::FileMPEvent* file_event = new snort::FileMPEvent();
    if (!file_event)
        return false;

    file_event->deserialize(buffer, len);
    event = file_event;
    return true;
}
