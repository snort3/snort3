//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment_descriptor.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_segment_descriptor.h"

#include "detection/rules.h"
#include "packet_io/packet_tracer.h"
#include "protocols/tcp_options.h"

#include "tcp_defs.h"
#include "tcp_event_logger.h"
#include "tcp_stream_tracker.h"

using namespace snort;

static THREAD_LOCAL Packet* ma_pseudo_packet;
static THREAD_LOCAL tcp::TCPHdr ma_pseudo_tcph;

TcpSegmentDescriptor::TcpSegmentDescriptor(Flow* f, Packet* p, TcpEventLogger& tel)
    : flow(f), pkt(p), tcph(pkt->ptrs.tcph),
      packet_number(p->context->packet_number),
      seq(tcph->seq()),
      ack(tcph->ack()),
      wnd(tcph->win()),
      end_seq(seq + (uint32_t)pkt->dsize),
      timestamp_option(0),
      src_port(tcph->src_port()),
      dst_port(tcph->dst_port())
{
    packet_timestamp = p->pkth->ts.tv_sec;
    packet_from_client = p->is_from_client();

    // don't bump end_seq for fin here we will bump if/when fin is processed
    if ( tcph->is_syn() )
    {
        end_seq++;
        if ( !tcph->is_ack() )
            tel.log_internal_event(SESSION_EVENT_SYN_RX);
    }
}

TcpSegmentDescriptor::TcpSegmentDescriptor
    (snort::Flow* f, snort::Packet* p, uint32_t meta_ack, uint16_t window)
    : flow(f), pkt(ma_pseudo_packet), tcph(&ma_pseudo_tcph),
      packet_number(p->context->packet_number)
{
    // init tcp header fields for meta-ack packet
    ma_pseudo_tcph.th_dport = p->ptrs.tcph->raw_src_port();
    ma_pseudo_tcph.th_sport = p->ptrs.tcph->raw_dst_port();
    ma_pseudo_tcph.th_seq = p->ptrs.tcph->raw_ack();
    ma_pseudo_tcph.th_ack = meta_ack;
    ma_pseudo_tcph.th_offx2 = 0;
    ma_pseudo_tcph.th_flags = TH_ACK;
    ma_pseudo_tcph.th_win = window;
    ma_pseudo_tcph.th_sum = 0;
    ma_pseudo_tcph.th_urp = 0;

    // init meta-ack Packet fields stream cares about for TCP ack processing
    pkt->pkth = p->pkth;
    pkt->ptrs = p->ptrs;
    pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(), *p->ptrs.ip_api.get_src());
    pkt->ptrs.dp = p->ptrs.sp;
    pkt->ptrs.sp = p->ptrs.dp;
    pkt->active = p->active_inst;
    pkt->action = &p->action_inst;
    if( p->is_from_client() )
    {
        pkt->packet_flags = PKT_FROM_SERVER;
    }
    else
    {
        pkt->packet_flags = PKT_FROM_CLIENT;
    }
    pkt->flow = p->flow;
    pkt->context = p->context;
    pkt->dsize = 0;
    pkt->daq_msg = p->daq_msg;
    pkt->daq_instance = p->daq_instance;

    seq = tcph->seq();
    ack = tcph->ack();
    wnd = tcph->win();
    end_seq = seq;
    timestamp_option = 0;
    src_port = tcph->dst_port();
    dst_port = tcph->src_port();

    packet_timestamp = p->pkth->ts.tv_sec;
    packet_from_client = !p->is_from_client();
    meta_ack_packet = true;
}

void TcpSegmentDescriptor::setup()
{
    ma_pseudo_packet = new Packet(false);
}

void TcpSegmentDescriptor::clear()
{
    delete ma_pseudo_packet;
    ma_pseudo_packet = nullptr;
}

uint32_t TcpSegmentDescriptor::init_mss(uint16_t* value)
{
    if ( pkt->ptrs.decode_flags & DECODE_TCP_MSS )
    {
        tcp::TcpOptIterator iter(tcph, pkt);

        for ( const tcp::TcpOption& opt : iter )
        {
            if ( opt.code == tcp::TcpOptCode::MAXSEG )
            {
                *value = extract_16bits(opt.data);
                return TF_MSS;
            }
        }
    }
    *value = 0;
    return TF_NONE;
}

uint32_t TcpSegmentDescriptor::init_wscale(uint16_t* value)
{
    if ( pkt->ptrs.decode_flags & DECODE_TCP_WS )
    {
        tcp::TcpOptIterator iter(tcph, pkt);

        for (const tcp::TcpOption& opt : iter)
        {
            if (opt.code == tcp::TcpOptCode::WSCALE)
            {
                *value = (uint16_t)opt.data[0];

                // If scale specified in option is larger than 14, use 14 because of limitation
                // in the math of shifting a 32bit value (max scaled window is 2^30th).
                // See RFC 1323 for details.
                if (*value > 14)
                    *value = 14;

                return TF_WSCALE;
            }
        }
    }
    *value = 0;
    return TF_NONE;
}

void TcpSegmentDescriptor::set_retransmit_flag()
{
    if ( PacketTracer::is_active() )
    {
        PacketTracer::log("stream_tcp: Packet was retransmitted and %s from the retry queue.\n",
            pkt->is_retry() ? "is" : "is not");
    }

    // Mark the packet as being a re-transmit if it's not from the retry
    // queue. That way we can avoid adding re-transmitted packets to
    // the retry queue.
    if ( !pkt->is_retry() )
        pkt->packet_flags |= PKT_RETRANSMIT;
}


