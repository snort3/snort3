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

#include "intf.h"

#include <netinet/in.h>
#include <pcap.h>

#include "log/messages.h"
#include "sfip/sf_ip.h"

//------------------------------------------------------------------------------
// interface stuff
//------------------------------------------------------------------------------

void PrintAllInterfaces()
{
    char errorbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int j = 1;

    if (pcap_findalldevs(&alldevs, errorbuf) == -1)
        snort::FatalError("Could not get device list: %s.", errorbuf);

    printf("Index\tDevice\tPhysical Address\tIP Address\tDescription\n");
    printf("-----\t------\t----------------\t----------\t-----------\n");

    for (dev = alldevs; dev != nullptr; dev = dev->next, j++)
    {
        printf("%5d", j);
        printf("\t%s", dev->name);
        printf("\t00:00:00:00:00:00");

        if (dev->addresses)
        {
            struct sockaddr_in* saddr = (struct sockaddr_in*)dev->addresses->addr;
            if ((saddr->sin_family == AF_INET) || (saddr->sin_family == AF_INET6))
            {
                snort::SfIp dev_ip;
                dev_ip.set(&saddr->sin_addr, saddr->sin_family);

                snort::SfIpString ip;
                printf("\t%s", dev_ip.ntop(ip));
            }
            else
                printf("\tdisabled");
        }
        else
            printf("\tdisabled");

        printf("\t%s\n", dev->description);
    }
    pcap_freealldevs(alldevs);
}

