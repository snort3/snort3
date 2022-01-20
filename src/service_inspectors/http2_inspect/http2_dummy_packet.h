//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_dummy_packet.h author Katura Harvey <katharve@cisco.com>

/*
 * The purpose of this Packet subclass is to enable H2I to take direction from http_inspect on
 * whether or not to send a frame to detection. When http_inspect is processing normal HTTP/1.1
 * traffic it is dealing with a real packet that has a context, the field on which disable_all()
 * is called to disable detection on that packet. With HTTP/2 traffic, http_inspect is processing a
 * dummy packet that H2I created, which does not contain a context object. Rather than create an
 * entire new context object when we really only need a bool, http_inspect checks if the flow is
 * HTTP/2 and sets a bool instead of calling it's usual disable_all(). H2I checks the bool and can
 * then call disable_all() on the real packet.
 */

#ifndef HTTP2_DUMMY_PACKET_H
#define HTTP2_DUMMY_PACKET_H

#include "protocols/packet.h"

class Http2DummyPacket : public snort::Packet
{
public:
    Http2DummyPacket() : snort::Packet(false) { }
    bool is_detection_required() { return !disable_inspect; }
};

#endif
