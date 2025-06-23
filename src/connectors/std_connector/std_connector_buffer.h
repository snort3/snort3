//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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

// std_connector_buffer.h author Cisco

#ifndef STD_CONNECTOR_BUFFER_H
#define STD_CONNECTOR_BUFFER_H

#include <atomic>
#include <list>
#include <mutex>
#include <string>
#include <thread>

#include "helpers/ring2.h"

struct TextLog;

class StdConnectorBuffer
{
public:
    StdConnectorBuffer(const char* output);
    ~StdConnectorBuffer();

    void start();

    Ring2::Writer acquire(size_t buffer_size);
    bool release(const Ring2::Writer&);

private:
    std::string destination;
    std::mutex start_mutex;

    std::mutex rings_mutex;
    std::list<Ring2> rings;
    std::list<std::list<Ring2>::iterator> rings_removed;
    std::thread* sink{nullptr};
    std::atomic_flag sink_latest{false};
    std::atomic_flag sink_run{false};
};

#endif
