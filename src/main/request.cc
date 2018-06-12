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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "request.h"

#include "log/messages.h"
#include "main.h"
#include "utils/util.h"

//-------------------------------------------------------------------------
// request foo
//-------------------------------------------------------------------------

Request::Request(int f)
{
    fd = f;
    bytes_read = 0;
}

bool Request::read(int& f)
{
    bool newline_found = false;
    char buf;
    ssize_t n = 0;

    fd = f;
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
    {
        f = -1;
        return false;
    }

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
void Request::respond(const char* s, bool queue_response)
{
    if ( fd < 1 )
    {
        snort::LogMessage("%s", s);
        return;
    }

    if ( queue_response )
    {
        queued_response = s;
        return;
    }
    write_response(s);
}

#ifdef SHELL
bool Request::send_queued_response()
{
    bool ret = true;
    if ( queued_response )
    {
        ret = write_response(queued_response);
        queued_response = nullptr;
    }

    return ret;
}
#endif
