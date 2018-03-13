//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// stream_libtcp_unit_test.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifndef STREAM_LIBTCP_UNIT_TEST_H
#define STREAM_LIBTCP_UNIT_TEST_H

namespace snort
{
class Flow;
struct Packet;
}

snort::Packet* get_syn_packet(snort::Flow*);
snort::Packet* get_syn_ack_packet(snort::Flow*);
snort::Packet* get_ack_packet(snort::Flow*);
snort::Packet* get_fin_packet(snort::Flow*);
snort::Packet* get_rst_packet(snort::Flow*);
snort::Packet* get_data_packet(snort::Flow*);

void release_packet(snort::Packet*);

#endif

