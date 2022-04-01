//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>

#include "cursor.h"

#include "detection/detection_util.h"
#include "protocols/packet.h"

using namespace snort;

unsigned CursorData::cursor_data_id = 0;

Cursor::Cursor(Packet* p)
{
    reset(p);
}

Cursor::Cursor(const Cursor& rhs)
{
    name = rhs.name;
    buf = rhs.buf;
    sz = rhs.sz;
    pos = rhs.pos;

    if (rhs.data)
    {
        data = new CursorDataVec;

        for (CursorData*& cd : *rhs.data)
            data->push_back(cd->clone());
    }
}

CursorData* Cursor::get_data(unsigned id) const
{
    if (data)
    {
        for (CursorData*& cd : *data)
        {
            if (cd->get_id() == id)
                return cd;
        }
    }

    return nullptr;
}

void Cursor::set_data(CursorData* cd)
{
    assert(cd);

    if (data)
    {
        unsigned id = cd->get_id();
        for (CursorData*& old : *data)
        {
            if (old->get_id() == id)
            {
                delete old;
                old = cd;
                return;
            }
        }
    }
    else
    {
        data = new CursorDataVec;
    }

    data->push_back(cd);
}

void Cursor::reset(Packet* p)
{
    InspectionBuffer buf;

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

