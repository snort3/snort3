//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
// Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

#ifndef SNORT_H
#define SNORT_H

// Snort is the top-level application class.
#include <daq_common.h>

#include "main/snort_types.h"

class ContextSwitcher;

namespace snort
{
class Flow;
class SFDAQInstance;
struct Packet;
struct SnortConfig;

class Snort
{
public:
    static SnortConfig* get_reload_config(const char* fname, const char* plugin_path,
        const SnortConfig* old);
    static SnortConfig* get_updated_policy(SnortConfig*, const char* fname, const char* iname);
    static void setup(int argc, char* argv[]);
    static bool drop_privileges();
    static void do_pidfile();
    static void cleanup();

    static bool has_dropped_privileges();
    SO_PUBLIC static bool is_reloading();

private:
    static void init(int, char**);
    static void term();
    static void clean_exit(int);
    static void reload_failure_cleanup(SnortConfig*);

private:
    static bool initializing;
    static bool reloading;
    static bool privileges_dropped;
};

// RAII-style mechanism for removal and reinstallation of Snort's crash handler
class SO_PUBLIC OopsHandlerSuspend
{
public:
    OopsHandlerSuspend();
    ~OopsHandlerSuspend();
};
}

#endif

