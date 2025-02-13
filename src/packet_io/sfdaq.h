//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <daq_common.h>

#include <ostream>

#include "main/snort_types.h"

struct SFDAQConfig;

namespace snort
{
class SFDAQInstance;

class SFDAQ
{
public:
    static void load(const SFDAQConfig*);
    static void unload();

    static void print_types(std::ostream&);
    static const char* verdict_to_string(DAQ_Verdict verdict);
    static bool init(const SFDAQConfig*, unsigned total_instances);
    static void term();

    static bool init_instance(SFDAQInstance*, const std::string& bpf_string);

    static const char* get_input_spec(const SFDAQConfig*, unsigned instance_id);
    static const char* default_type();
    SO_PUBLIC static const DAQ_Stats_t* get_stats();

    static bool can_inject();
    static bool can_inject_raw();
    static bool can_replace();
    static bool can_run_unprivileged();
    SO_PUBLIC static bool get_tunnel_bypass(uint16_t proto);

    // FIXIT-M X Temporary thread-local instance helpers to be removed when no longer needed
    static void set_local_instance(SFDAQInstance*);

    SO_PUBLIC static SFDAQInstance* get_local_instance();
    SO_PUBLIC static const char* get_input_spec();
    SO_PUBLIC static int get_base_protocol();

    static int inject(DAQ_Msg_h, int rev, const uint8_t* buf, uint32_t len);
    SO_PUBLIC static bool forwarding_packet(const DAQ_PktHdr_t*);
};
}
#endif

