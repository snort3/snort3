//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "response_buf.h"

#include "control/control.h"
#include "log/messages.h"

using namespace snort;

StatsResponseBuf::StatsResponseBuf(ControlConn* conn) : ctrlcon(conn)
{ setp(buffer, buffer + sizeof(buffer) - 1); }

StatsResponseBuf::~StatsResponseBuf()
{ flush(); }

int StatsResponseBuf::sync()
{ return flush(); }

int StatsResponseBuf::flush()
{
    const auto pending = pptr() - pbase();
    if ( pending > 0 )
    {
        *pptr() = '\0';
        if ( !send_chunk(buffer) )
            return -1;
        setp(buffer, buffer + sizeof(buffer) - 1);
    }

    return 0;
}

StatsResponseBuf::int_type StatsResponseBuf::overflow(int_type ch)
{
    if ( traits_type::eq_int_type(ch, traits_type::eof()) )
        return sync() == 0 ? traits_type::not_eof(ch) : traits_type::eof();

    if ( pptr() == epptr() && sync() != 0 )
        return traits_type::eof();

    *pptr() = traits_type::to_char_type(ch);
    pbump(1);
    return ch;
}

bool StatsResponseBuf::send_chunk(const char* data) const
{
    if ( !data || !*data )
        return true;

    if ( ctrlcon )
        return ctrlcon->respond("%s", data);
    else
        LogMessage("%s", data);

    return true;
}
