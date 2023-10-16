//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// out_unixsock.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "conversion_state.h"
#include "data/dt_table_api.h"

namespace output
{
static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_table("alert_unixsock");
    c.get_table_api().close_table();
    return nullptr;
}

static const ConvertMap alert_unixsock_api =
{
    "alert_unixsock",
    ctor,
};

const ConvertMap* alert_unixsock_map = &alert_unixsock_api;
} // namespace output

