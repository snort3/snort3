//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// this is a gnu extension that at present is slightly faster than the
// c++11 form
#define THREAD_LOCAL __thread

// the c++11 form currently seems to be slightly slower than __thread
// possibly due to dynamic initialization requirements
//#define THREAD_LOCAL thread_local

void set_instance_id(unsigned);
void set_instance_max(unsigned);

struct SnortConfig;
bool set_cpu_affinity(SnortConfig*, const std::string&, int cpu);
bool set_cpu_affinity(SnortConfig*, int thread, int cpu);
void pin_thread_to_cpu(const char* source);

SO_PUBLIC unsigned get_instance_id();
SO_PUBLIC unsigned get_instance_max();

// all modules that use packet thread files should call this function to
// get a packet thread specific path.  name should be the module name or
// derived therefrom.
SO_PUBLIC const char* get_instance_file(std::string&, const char* name);

void take_break();
bool break_time();

#endif

