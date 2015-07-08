//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// piglet_utils.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_utils.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace Piglet
{
using namespace std;

// -------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------

void Timer::start()
{
    if ( !running )
    {
        start_time = chrono::system_clock::now();
        running = true;
    }
}

void Timer::stop()
{
    if ( running )
    {
        stop_time = chrono::system_clock::now();
        running = false;
    }
}

chrono::duration<double> Timer::delta()
{ return stop_time - start_time; }

// -------------------------------------------------------------------------
// Test
// -------------------------------------------------------------------------

// FIXIT-M: Need a better way to do error logging.
Test& Test::operator<<(string s)
{
    _message.append(s);
    return *this;
}

void Test::endl()
{
    if ( !_message.empty() )
        messages.push_back(_message);
}
} // namespace Piglet

