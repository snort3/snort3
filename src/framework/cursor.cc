//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// cursor.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cursor.h"

#include "detection/detection_util.h"
#include "protocols/packet.h"

using namespace snort;

Cursor::Cursor(Packet* p)
{
    reset(p);
}

Cursor::Cursor(const Cursor& rhs)
{
    *this = rhs;
    delta = 0;
}

void Cursor::reset(Packet* p)
{
    InspectionBuffer buf;

    // FIXIT-M should this be converted to get_fp_buf()?
    if ( p->flow and p->flow->gadget and
        p->flow->gadget->get_buf(buf.IBT_ALT, p, buf) )
    {
        set("alt_data", buf.data, buf.len);
    }
    else
    {
        set("pkt_data", p->data, p->get_detect_limit());
    }
}

