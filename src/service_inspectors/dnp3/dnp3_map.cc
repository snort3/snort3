//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// dnp3_map.cc author Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnp3_map.h"

#include <cstddef>
#include <cstring>

/* Name/value pair struct */
struct dnp3_map_t
{
    const char* name;
    uint16_t value;
};

/* Mapping of name -> function code for "dnp3_func" option. */
static dnp3_map_t func_map[] =
{
    { "confirm", 0 },
    { "read", 1 },
    { "write", 2 },
    { "select", 3 },
    { "operate", 4 },
    { "direct_operate", 5 },
    { "direct_operate_nr", 6 },
    { "immed_freeze", 7 },
    { "immed_freeze_nr", 8 },
    { "freeze_clear", 9 },
    { "freeze_clear_nr", 10 },
    { "freeze_at_time", 11 },
    { "freeze_at_time_nr", 12 },
    { "cold_restart", 13 },
    { "warm_restart", 14 },
    { "initialize_data", 15 },
    { "initialize_appl", 16 },
    { "start_appl", 17 },
    { "stop_appl", 18 },
    { "save_config", 19 },
    { "enable_unsolicited", 20 },
    { "disable_unsolicited", 21 },
    { "assign_class", 22 },
    { "delay_measure", 23 },
    { "record_current_time", 24 },
    { "open_file", 25 },
    { "close_file", 26 },
    { "delete_file", 27 },
    { "get_file_info", 28 },
    { "authenticate_file", 29 },
    { "abort_file", 30 },
    { "activate_config", 31 },
    { "authenticate_req", 32 },
    { "authenticate_err", 33 },
    { "response", 129 },
    { "unsolicited_response", 130 },
    { "authenticate_resp", 131 }
};

/* Mapping of name -> indication bit for "dnp3_ind" option. */
static dnp3_map_t indication_map[] =
{
    /* The order is strange, but this is the order in which the spec
       lists them. */
    { "all_stations", 0x0100 },
    { "class_1_events", 0x0200 },
    { "class_2_events", 0x0400 },
    { "class_3_events", 0x0800 },
    { "need_time", 0x1000 },
    { "local_control", 0x2000 },
    { "device_trouble", 0x4000 },
    { "device_restart", 0x8000 },
    { "no_func_code_support", 0x0001 },
    { "object_unknown", 0x0002 },
    { "parameter_error", 0x0004 },
    { "event_buffer_overflow", 0x0008 },
    { "already_executing", 0x0010 },
    { "config_corrupt", 0x0020 },
    { "reserved_2", 0x0040 },
    { "reserved_1", 0x0080 },
};

bool dnp3_func_is_defined(uint16_t code)
{
    size_t num_funcs = sizeof(func_map) / sizeof(func_map[0]);
    size_t i;
    int func_is_defined = false;

    /* Check to see if code is higher than all codes in func map */
    if (code > func_map[num_funcs-1].value)
        return func_is_defined;

    for (i = 0; i < num_funcs-1; i++)
    {
        /* This short-circuit check assumes that the function map remains
           in-order. */
        if (code <= func_map[i].value)
            break;
    }

    if (code == func_map[i].value)
        func_is_defined = true;

    return func_is_defined;
}

int dnp3_func_str_to_code(const char* name)
{
    size_t num_funcs = sizeof(func_map) / sizeof(func_map[0]);
    size_t i;

    for (i = 0; i < num_funcs; i++)
    {
        if (strcmp(name, func_map[i].name) == 0)
            return func_map[i].value;
    }

    return -1;
}

int dnp3_ind_str_to_code(const char* name)
{
    size_t num_indications = sizeof(indication_map) / sizeof(indication_map[0]);
    size_t i;

    for (i = 0; i < num_indications; i++)
    {
        if (strcmp(name, indication_map[i].name) == 0)
            return indication_map[i].value;
    }

    return -1;
}

