//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

// tpkt_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tpkt_decode.h"

#include "cotp_decode.h"

using namespace snort;

TpktAppliSearchStateType tpkt_internal_search_from_tpkt_layer(Cursor* tpkt_cur)
{
    // none of the values in the TPKT header affect parsing at this time so
    // doing any extra verification here would just lead to false negatives
    TpktAppliSearchStateType res = TPKT_APPLI_SEARCH_STATE__EXIT;

    if (tpkt_cur->add_pos(sizeof(TpktHdr)))
    {
        res = tpkt_search_from_cotp_layer(tpkt_cur);
    }
    return res;
}

