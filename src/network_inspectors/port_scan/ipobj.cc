//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

// ipobj.c

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ipobj.h"

#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;

/*
   IP COLLECTION INTERFACE

   Snort Accepts:

   IP-Address		192.168.1.1
   IP-Address/MaskBits	192.168.1.0/24
   IP-Address/Mask		192.168.1.0/255.255.255.0

   These can all be handled via the CIDR block notation : IP/MaskBits

   We use collections (lists) of cidr blocks to represent address blocks
   and individual addresses.

   For a single IPAddress the implied Mask is 32 bits,or 255.255.255.255, or 0xffffffff, or -1.
*/
IPSET* ipset_new()
{
    IPSET* p = (IPSET*)snort_calloc(sizeof(IPSET));
    sflist_init(&p->ip_list);
    return p;
}

void ipset_free(IPSET* ipc)
{
    if (ipc)
    {
        SF_LNODE* cursor;
        IP_PORT* p = (IP_PORT*)sflist_first(&ipc->ip_list, &cursor);

        while ( p )
        {
            sflist_static_free_all(&p->portset.port_list, snort_free);
            p = (IP_PORT*)sflist_next(&cursor);
        }
        sflist_static_free_all(&ipc->ip_list, snort_free);
        snort_free(ipc);
    }
}

int ipset_add(IPSET* ipset, SfCidr* ip, void* vport, int notflag)
{
    if ( !ipset )
        return -1;

    {
        PORTSET* portset = (PORTSET*)vport;
        IP_PORT* p = (IP_PORT*)snort_calloc(sizeof(IP_PORT));

        p->ip.set(*ip);
        p->portset = *portset;
        p->notflag = (char)notflag;

        if ( notflag )
            sflist_add_head(&ipset->ip_list, p);            // test NOT items 1st
        else
            sflist_add_tail(&ipset->ip_list, p);
    }

    return 0;
}

int ipset_contains(IPSET* ipc, const SfIp* ip, void* port)
{
    PORTRANGE* pr;
    unsigned short portu;
    IP_PORT* p;

    if ( !ipc )
        return 0;

    if ( port )
        portu = *((unsigned short*)port);
    else
        portu = 0;

    SF_LNODE* cur_ip;

    for (p =(IP_PORT*)sflist_first(&ipc->ip_list, &cur_ip);
        p!=nullptr;
        p =(IP_PORT*)sflist_next(&cur_ip) )
    {
        if (p->ip.contains(ip) == SFIP_CONTAINS)
        {
            SF_LNODE* cur_port;

            for ( pr=(PORTRANGE*)sflist_first(&p->portset.port_list, &cur_port);
                pr != nullptr;
                pr=(PORTRANGE*)sflist_next(&cur_port) )
            {
                /*
                 * If the matching IP has a wildcard port (pr->port_hi == 0 )
                 * or if the ports actually match.
                 */
                if ( (pr->port_hi == 0) ||
                    (portu >= pr->port_lo && portu <= pr->port_hi) )
                {
                    if ( p->notflag )
                        return 0;
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void portset_init(PORTSET* portset)
{
    sflist_init(&portset->port_list);
}

static int portset_add(PORTSET* portset, unsigned port_lo, unsigned port_hi)
{
    PORTRANGE* p;

    if ( !portset )
        return -1;

    p = (PORTRANGE*)snort_calloc(sizeof(PORTRANGE));

    p->port_lo = port_lo;
    p->port_hi = port_hi;

    sflist_add_tail(&portset->port_list, p);

    return 0;
}

static int port_parse(char* portstr, PORTSET* portset)
{
    char* port_begin = snort_strdup(portstr);
    char* port1 = port_begin;
    char* port2 = strstr(port_begin, "-");

    if (*port1 == '\0')
    {
        snort_free(port_begin);
        return -1;
    }

    if (port2)
    {
        *port2 = '\0';
        port2++;
    }

    char* port_end;
    unsigned port_lo = strtoul(port1, &port_end, 10);
    unsigned port_hi = 0;

    if (port_end == port1)
    {
        snort_free(port_begin);
        return -2;
    }

    if (port2)
    {
        port_hi = strtoul(port2, &port_end, 10);
        if (port_end == port2)
        {
            snort_free(port_begin);
            return -3;
        }
    }
    else
    {
        port_hi = port_lo;
    }

    /* check to see if port is out of range */
    if ( port_hi > MAX_PORTS-1 || port_lo > MAX_PORTS-1)
    {
        snort_free(port_begin);
        return -4;
    }

    /* swap ports if necessary */
    if (port_hi < port_lo)
    {
        unsigned tmp = port_hi;
        port_hi = port_lo;
        port_lo = tmp;
    }

    portset_add(portset, port_lo, port_hi);
    snort_free(port_begin);

    return 0;
}

static int ip_parse(char* ipstr, SfCidr* ip, char* not_flag, PORTSET* portset, char** endIP)
{
    char* port_str;
    char* comma;
    char* end_bracket;

    if (*ipstr == '!')
    {
        ipstr++;
        *not_flag = 1;
    }
    else
    {
        *not_flag = 0;
    }

    comma = strchr(ipstr, ',');
    end_bracket = strrchr(ipstr, ']');

    if (comma)
    {
        *comma = '\0';
    }
    else if (end_bracket)
    {
        *end_bracket = '\0';
    }

    if (ip->set(ipstr) != SFIP_SUCCESS)
        return -1;

    /* Just to get the IP string out of the way */
    char* lasts = nullptr;
    strtok_r(ipstr, " \t", &lasts);

    /* Is either the port after the 1st space, or null */
    port_str = strtok_r(nullptr, " \t", &lasts);

    while (port_str)
    {
        if (!comma)
        {
            comma = strchr(port_str, ',');
            if (comma)
                *comma = '\0';
        }

        if (!end_bracket)
        {
            end_bracket = strrchr(port_str, ']');
            if (end_bracket)
                *end_bracket = '\0';
        }

        port_parse(port_str, portset);
        port_str = strtok_r(nullptr, " \t", &lasts);
    }

    if (portset->port_list.count == 0)
    {
        /* Make sure we have at least one port range in list, but
         * an invalid port range to convey all is good.  */
        portset_add(portset, 0, 0);
    }

    if (comma)
    {
        *endIP = comma;
        *comma = ',';
    }
    else if (end_bracket)
    {
        *end_bracket = ']';
        *endIP = end_bracket;
    }
    else
    {
        /* Didn't see the comma or end bracket, so set endIP now */
        *endIP = port_str;
    }

    return 0;
}

int ipset_parse(IPSET* ipset, const char* ipstr)
{
    char* copy, * startIP, * endIP;
    int parse_count = 0;
    char set_not_flag = 0;
    char item_not_flag;
    char open_bracket = 0;
    SfCidr ip;
    PORTSET portset;

    copy = snort_strdup(ipstr);
    startIP = copy;

    if (*startIP == '!')
    {
        set_not_flag = 1;
        startIP++;
    }

    while (startIP)
    {
        if (*startIP == '[')
        {
            open_bracket++;
            startIP++;
            if (!*startIP)
                break;
        }

        if ((*startIP == ']') || (*startIP == '\0'))
        {
            open_bracket--;
            break;
        }

        portset_init(&portset);

        if (ip_parse(startIP, &ip, &item_not_flag, &portset, &endIP) != 0)
        {
            snort_free(copy);
            return -5;
        }

        if (ipset_add(ipset, &ip, &portset, (item_not_flag ^ set_not_flag)) != 0)
        {
            snort_free(copy);
            return -6;
        }

        parse_count++;

        if (endIP && (*endIP != ']'))
        {
            endIP++;
        }

        startIP = endIP;
    }

    snort_free(copy);

    if (!parse_count)
        return -7;

    if (open_bracket)
        return -8;

    return 0;
}

