//--------------------------------------------------------------------------
// Copyright (C) 2017-2021 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "request.h"

#include "log/messages.h"
#include "main.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// request foo
//-------------------------------------------------------------------------

bool Request::read()
{
    bool newline_found = false;
    char buf;
    ssize_t n = 0;

    while ( (bytes_read < sizeof(read_buf)) and ((n = ::read(fd, &buf, 1)) > 0) )
    {
        read_buf[bytes_read++] = buf;

        if (buf == '\n')
        {
            newline_found = true;
            break;
        }
    }

    if ( n <= 0 and errno != EAGAIN and errno != EINTR )
        return false;

    if ( bytes_read == sizeof(read_buf) )
        bytes_read = 0;

    if ( newline_found )
    {
        read_buf[bytes_read] = '\0';
        bytes_read = 0;
        return true;
    }
    else
        return false;
}

bool Request::write_response(const char* s) const
{
    ssize_t n = write(fd, s, strlen(s));
    if ( n < 0 and errno != EAGAIN and errno != EINTR )
        return false;
    else
        return true;
}

// FIXIT-L supporting only simple strings for now
// could support var args formats
void Request::respond(const char* s, bool queue_response, bool remote_only)
{
    if (remote_only && (fd == STDOUT_FILENO))
        return;

    if ( fd < 1 )
    {
        if (!remote_only)
            LogMessage("%s", s);
        return;
    }

    if ( queue_response )
    {
        lock_guard<mutex> lock(queued_response_mutex);
        queued_response.emplace(s);
        return;
    }
    write_response(s);
}

#ifdef SHELL
bool Request::send_queued_response()
{
    const char* qr;
    {
        lock_guard<mutex> lock(queued_response_mutex);
        if ( queued_response.empty() )
            return false;
        qr = queued_response.front();
        queued_response.pop();
    }
    return write_response(qr);
}
#endif

SharedRequest get_dispatched_request()
{
    return get_current_request();
}
