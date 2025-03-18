//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_overlap_resolver.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 11, 2015

#ifndef TCP_OVERLAP_RESOLVER_H
#define TCP_OVERLAP_RESOLVER_H

#include <vector>

#include "normalize/norm_stats.h"
#include "stream/stream.h"

#include "tcp_defs.h"

class TcpReassemblySegments;
class TcpSegmentDescriptor;
class TcpSegmentNode;
class TcpSession;
class TcpStreamTracker;

class TcpOverlapState
{
public:
    TcpOverlapState(TcpReassemblySegments& seglist);
    ~TcpOverlapState() = default;

    void init(TcpSegmentDescriptor&);

    uint32_t slide_seq() const
    { return seq + slide; }

    TcpReassemblySegments& seglist;
    TcpSegmentDescriptor* tsd = nullptr;

    TcpSegmentNode* left = nullptr;
    TcpSegmentNode* right = nullptr;
    const uint8_t* rdata = nullptr;

    uint32_t seq = 0;
    uint32_t seq_end = 0;
    uint32_t rseq = 0;

    int32_t overlap = 0;
    int32_t slide = 0;
    int32_t trunc_len = 0;

    uint16_t len = 0;
    uint16_t rsize = 0;
    int8_t tcp_ips_data = 0;

    bool keep_segment = true;
};

class TcpOverlapResolver
{
public:
    TcpOverlapResolver() = default;
    virtual ~TcpOverlapResolver() = default;

    void eval_left(TcpOverlapState&);
    void eval_right(TcpOverlapState&);

    Overlap::Policy get_overlap_policy()
    { return overlap_policy; }

protected:
    virtual bool is_segment_retransmit(TcpOverlapState&, bool*);
    virtual void drop_old_segment(TcpOverlapState&);
    virtual bool zwp_data_mismatch(TcpOverlapState&, TcpSegmentDescriptor&, uint32_t);

    virtual void left_overlap_keep_first(TcpOverlapState&);
    virtual void left_overlap_trim_first(TcpOverlapState&);
    virtual void left_overlap_keep_last(TcpOverlapState&);
    virtual void right_overlap_truncate_existing(TcpOverlapState&);
    virtual void right_overlap_truncate_new(TcpOverlapState&);
    virtual void full_right_overlap_truncate_new(TcpOverlapState&);
    virtual void full_right_overlap_os1(TcpOverlapState&);
    virtual void full_right_overlap_os2(TcpOverlapState&);
    virtual void full_right_overlap_os3(TcpOverlapState&);
    virtual void full_right_overlap_os4(TcpOverlapState&);
    virtual void full_right_overlap_os5(TcpOverlapState&);

    virtual void insert_left_overlap(TcpOverlapState&) = 0;
    virtual void insert_right_overlap(TcpOverlapState&) = 0;
    virtual void insert_full_overlap(TcpOverlapState&) = 0;

    Overlap::Policy overlap_policy = Overlap::Policy::DEFAULT_POLICY;
};

class TcpOverlapResolverFactory
{
public:
    static void initialize();
    static void term();
    static TcpOverlapResolver* get_instance(Overlap::Policy);

private:
    TcpOverlapResolverFactory() = delete;

    static TcpOverlapResolver* overlap_resolvers[Overlap::Policy::MAX_OVERLAP_POLICY];
};

#endif
