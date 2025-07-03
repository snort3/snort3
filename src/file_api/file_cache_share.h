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

// file_cache.h author Shilpa Nagpal <shinagpa@cisco.com>

#ifndef FILE_CACHE_SHARE_H
#define FILE_CACHE_SHARE_H

#include "framework/mp_data_bus.h"
#include "pub_sub/file_events.h"

class FileCacheShare : public snort::DataHandler
{
public:
    FileCacheShare(FileInspect* fi) : DataHandler(FILE_ID_NAME) { ins = fi; }
    void handle(snort::DataEvent&, snort::Flow*) override;
private:
    FileInspect* ins;
};

bool serialize_file_event(snort::DataEvent* event, char*& buffer, uint16_t* len);
bool deserialize_file_event(const char* buffer, uint16_t len, snort::DataEvent*& event);

#endif

