//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "stream_inspectors.h"

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* nin_stream_base;
extern const BaseApi* nin_stream_ip;
extern const BaseApi* nin_stream_icmp;
extern const BaseApi* nin_stream_tcp;
extern const BaseApi* nin_stream_udp;
extern const BaseApi* nin_stream_user;
extern const BaseApi* nin_stream_file;

extern const BaseApi* ips_stream_reassemble;
extern const BaseApi* ips_stream_size;

static const BaseApi* stream_inspectors[] =
{
    nin_stream_base,
    nin_stream_ip,
    nin_stream_icmp,
    nin_stream_tcp,
    nin_stream_udp,
    nin_stream_user,
    nin_stream_file,

    ips_stream_reassemble,
    ips_stream_size,

    nullptr
};

void load_stream_inspectors()
{
    PluginManager::load_plugins(stream_inspectors);
}

