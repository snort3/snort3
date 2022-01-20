//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <flow/flow.h>
#include "ssl_flow_data.h"

unsigned SslBaseFlowData::inspector_id = 0;

SSLData* SslBaseFlowData::get_ssl_session_data(snort::Flow* flow)
{
    SslBaseFlowData* fd = (SslBaseFlowData*)flow->get_flow_data(SslBaseFlowData::inspector_id);
    return fd ? &fd->get_session() : nullptr;
}
