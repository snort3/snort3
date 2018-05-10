//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// This header includes request class which is used by the control connections
// to read control commands and send responses for those commands.

#ifndef REQUEST_H
#define REQUEST_H

#include "main/snort_types.h"

class Request
{
public:
    Request(int f = -1);

    bool read(int&);
    const char* get() { return read_buf; }
    bool write_response(const char* s) const;
    void respond(const char* s, bool queue_response = false);
#ifdef SHELL
    bool send_queued_response();
#endif

private:
    int fd;
    char read_buf[1024];
    size_t bytes_read;
    const char* queued_response = nullptr;
};
#endif
