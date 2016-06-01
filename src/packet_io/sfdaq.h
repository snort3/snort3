//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// sfdaq.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_H
#define SFDAQ_H

extern "C" {
#include <daq.h>
}

#include <string>

#include "main/snort_types.h"

struct SnortConfig;

class SFDAQInstance
{
public:
    SFDAQInstance(const char* intf);
    ~SFDAQInstance();
    bool configure(const SnortConfig*);
    void abort();
    const char* get_interface_spec();
    int get_base_protocol();
    bool can_inject();
    bool can_inject_raw();
    bool can_replace();
    bool can_start_unprivileged();
    bool can_whitelist();
    bool start();
    bool was_started();
    bool stop();
    void set_metacallback(DAQ_Meta_Func_t);
    int acquire(int max, DAQ_Analysis_Func_t);
    int inject(const DAQ_PktHdr_t*, int rev, const uint8_t* buf, uint32_t len);
    bool break_loop(int error);
    const DAQ_Stats_t* get_stats();
    int modify_flow_opaque(const DAQ_PktHdr_t*, uint32_t opaque);
private:
    bool set_filter(const char*);
    std::string interface_spec;
    DAQ_Meta_Func_t daq_meta_callback;
    void* daq_hand;
    int daq_dlt;
    int s_error;
    DAQ_Stats_t daq_stats;
};

class SFDAQ
{
public:
    static void load(const SnortConfig*);
    static void unload();
    static void print_types(std::ostream&);
    static void init(const SnortConfig*);
    static void term();
    static bool forwarding_packet(const DAQ_PktHdr_t*);
    static const char* get_type();
    SO_PUBLIC static uint32_t get_snap_len();
    static bool unprivileged();
    static const char* get_input_spec(const SnortConfig*, unsigned instance_id);
    static const char* default_type();
    // FIXIT-M X Temporary thread-local instance helpers to be removed when no longer needed
    static void set_local_instance(SFDAQInstance*);
    static SFDAQInstance* get_local_instance();
    SO_PUBLIC static const char* get_interface_spec();
    SO_PUBLIC static int get_base_protocol();
    static bool can_inject();
    static bool can_inject_raw();
    static bool can_replace();
    static int inject(const DAQ_PktHdr_t*, int rev, const uint8_t* buf, uint32_t len);
    static bool break_loop(int error);
    static const DAQ_Stats_t* get_stats();
};

#endif

