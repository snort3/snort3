/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef TCP_CONFIG_H
#define TCP_CONFIG_H

#include "decode.h"
#include "target_based/sftarget_protocol_reference.h"
#include "framework/bits.h"

struct FlushMgr
{
    uint32_t   flush_pt;
    uint16_t   last_count;
    uint16_t   last_size;
    uint8_t    flush_policy;
    uint8_t    flush_type;
    uint8_t    auto_disable;
    //uint8_t    spare;

};

struct FlushConfig
{
    FlushMgr client;
    FlushMgr server;
    uint8_t configured;

};

#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
struct FlushPointList
{
    uint8_t    current;

    uint32_t   flush_range;
    uint32_t   flush_base;  /* Set as value - range/2 */
    /* flush_pt is split evently on either side of flush_value, within
     * the flush_range.  flush_pt can be from:
     * (flush_value - flush_range/2) to (flush_value + flush_range/2)
     *
     * For example:
     * flush_value = 192
     * flush_range = 128
     * flush_pt will vary from 128 to 256
     */
    uint32_t *flush_points;
};
#endif

struct Stream5TcpConfig
{
    uint16_t policy;
    uint16_t reassembly_policy;
    uint16_t flags;
    uint16_t flush_factor;

    uint32_t session_timeout;
    uint32_t max_window;
    uint32_t overlap_limit;
    uint32_t hs_timeout;

    uint32_t max_queued_bytes;
    uint32_t max_queued_segs;

    uint32_t max_consec_small_segs;
    uint32_t max_consec_small_seg_size;

    FlushConfig flush_config[MAX_PORTS];
    FlushConfig flush_config_protocol[MAX_PROTOCOL_ORDINAL];
#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
    FlushPointList flush_point_list;
#endif

    PortList small_seg_ignore;

    void* paf_config;

    int footprint;
    uint16_t session_on_syn;
    uint16_t port_filter[MAX_PORTS + 1];

    Stream5TcpConfig();

    void set_port(Port port, bool c2s, bool s2c);
    void set_proto(unsigned proto_ordinal, bool c2s, bool s2c);
    void add_proto(const char* svc, bool c2s, bool s2c);
};

#endif

