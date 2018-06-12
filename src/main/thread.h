//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef THREAD_H
#define THREAD_H

// basic thread management utilities

#include <string>

#include "main/snort_types.h"

#define THREAD_LOCAL_TBD
//#define THREAD_LOCAL // for single-threaded debugging

// `__thread` is a gnu extension that at present is slightly faster than
// `thread_local` (possibly due to the lack of dynamic initialization)
#ifdef USE_THREAD_LOCAL
#    define THREAD_LOCAL thread_local
#else
#    define THREAD_LOCAL __thread
#endif

enum SThreadType
{
    STHREAD_TYPE_PACKET,
    STHREAD_TYPE_MAIN
};

void set_instance_id(unsigned);
void set_thread_type(SThreadType);

void set_run_num(uint16_t);
uint16_t get_run_num();

namespace snort
{
SO_PUBLIC unsigned get_instance_id();
SO_PUBLIC SThreadType get_thread_type();
SO_PUBLIC inline bool is_packet_thread()
{
    return get_thread_type() == STHREAD_TYPE_PACKET;
}

// all modules that use packet thread files should call this function to
// get a packet thread specific path.  name should be the module name or
// derived therefrom.
SO_PUBLIC const char* get_instance_file(std::string&, const char* name);
}

void take_break();
bool break_time();

#endif
