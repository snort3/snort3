//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#include "util_net.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_cidr.h"
#include "util_cstring.h"

namespace snort
{
char* ObfuscateIpToText(const SfIp* ip, SfCidr& homenet, SfCidr& obfunet, InetBuf& ab)
{
    ab[0] = 0;

    if ( !ip )
        return ab;

    if ( !obfunet.is_set() )
    {
        if (ip->is_ip6())
            SnortSnprintf(ab, sizeof(ab), "x:x:x:x::x:x:x:x");
        else
            SnortSnprintf(ab, sizeof(ab), "xxx.xxx.xxx.xxx");
    }
    else
    {
        SfIp tmp;
        tmp.set(*ip);

        if ( homenet.is_set() )
        {
            if ( homenet.contains(&tmp) == SFIP_CONTAINS )
                tmp.obfuscate(&obfunet);
        }
        else
        {
            tmp.obfuscate(&obfunet);
        }

        SfIpString ip_str;
        SnortSnprintf(ab, sizeof(ab), "%s", tmp.ntop(ip_str));
    }

    return ab;
}
}
