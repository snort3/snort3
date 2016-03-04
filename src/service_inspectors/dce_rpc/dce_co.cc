//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// dce_co.cc author Rashmi Pitre <rrp@cisco.com>
// based on work by Todd Wease

#include "dce_co.h"

/********************************************************************
 * Function: DCE2_CoInitTracker()
 *
 * Initializes fields in the connection-oriented tracker to
 * sentinels.  Many decisions are made based on whether or not
 * these fields have been set.
 *
 ********************************************************************/
void DCE2_CoInitTracker(DCE2_CoTracker *cot)
{
    if (cot == NULL)
        return;

    cot->max_xmit_frag = DCE2_SENTINEL;
    cot->data_byte_order = DCE2_SENTINEL;
    cot->ctx_id = DCE2_SENTINEL;
    cot->opnum = DCE2_SENTINEL;
    cot->call_id = DCE2_SENTINEL;
    cot->stub_data = NULL;
    cot->got_bind = 0;

    cot->frag_tracker.opnum = DCE2_SENTINEL;
    cot->frag_tracker.ctx_id = DCE2_SENTINEL;
    cot->frag_tracker.expected_call_id = DCE2_SENTINEL;
    cot->frag_tracker.expected_opnum = DCE2_SENTINEL;
    cot->frag_tracker.expected_ctx_id = DCE2_SENTINEL;
}

