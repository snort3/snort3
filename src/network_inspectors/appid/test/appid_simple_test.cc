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

// appid_simple_test.cc author stechew

// Make some API calls to demonstrate that we can link with appid libs.

#if 0
#include <stdio.h>
#include "util/fw_avltree.h"
#include "protocols/protocol_ids.h"
#include "sfip/sfip_t.h"
#include "sfip/sf_ip.h"
#include "fw_appid.h"
#endif
int main()
{
#if 0
    IpProtocol proto=IpProtocol::TCP;
    sfip_t* ip = nullptr;
    SFIP_RET status;

    printf("Testing...\n");

    ip = sfip_alloc("10.1.1.1", &status);
    fwAvlInit();
    appSharedDataAlloc(proto, ip);
#endif
    return 0;
}

