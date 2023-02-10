//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "ipobj.h"

#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;
using namespace std;

/*
   IP COLLECTION INTERFACE

   Snort Accepts:

   IP-Address           192.168.1.1
   IP-Address/MaskBits  192.168.1.0/24
   IP-Address/Mask      192.168.1.0/255.255.255.0

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

static bool search_mask(char* token, bool is_ipv6)
{
    return (strchr(token, '/') or
        (!is_ipv6 and strchr(token, ':')));
}

static bool search_mask_delim(char* token, bool is_ipv6)
{
    return (token[strlen(token)-1] == '/' or
        (!is_ipv6 and token[strlen(token)-1] == ':'));
}

static bool check_ipv6(char* token)
{
    if (count(token, token + strlen(token), ':') > 1)
        return true;
    else
        return false;
}

// Formats:
// ip/:mask/bit or ip /: mask/bit or ip /:mask/bit
// or ip mask
// eg 1.1.1.1/32, 1.1.1.1 : 0.0.0.0, 1.1.1.1 0.0.0.0, 1.1.1.1 /32
// mask, port optional
static char* check_delimiter(char* ipstr)
{
    string prev;
    char* saveptr     = nullptr;
    char* saveptr_sub = nullptr;
    vector<char*> subtokens;
    bool is_ipv6 = false;

    char* token = strtok_r(ipstr, ",", &saveptr);
    while (token)
    {
        size_t i = 0, port_index = 1;
        char* tmp_subtoken = strtok_r(token, " \t", &saveptr_sub);
        if (tmp_subtoken)
            is_ipv6 = check_ipv6(tmp_subtoken);
        while (tmp_subtoken)
        {
            subtokens.emplace_back(tmp_subtoken);
            if (search_mask_delim(tmp_subtoken, is_ipv6))
                port_index = i + 2;
            else if (search_mask(tmp_subtoken, is_ipv6))
                port_index = i + 1;
            else if ((i == 1) and strchr(tmp_subtoken, '.'))
                port_index = i + 1;
            i++;
            tmp_subtoken = strtok_r(nullptr, " \t", &saveptr_sub);
        }
        for (i = 0; i < subtokens.size(); i++)
        {
            if (i < port_index)
                prev += string(subtokens[i]);
            else
                prev += string("#") + subtokens[i];
        }
        subtokens.clear();
        prev += string(",");
        token = strtok_r(nullptr, ",", &saveptr);
    }
    prev.pop_back();
    char *tmp_ipstr = new char[prev.length() + 1];
    strcpy(tmp_ipstr, prev.c_str());
    return tmp_ipstr;
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

    /* Just to get the IP string out of the way */
    char* lasts = nullptr;
    char* ip_str = strtok_r(ipstr, "#", &lasts);

    if (ip->set(ip_str) != SFIP_SUCCESS)
        return -1;

    /* The port is after the # */
    port_str = strtok_r(nullptr, "#", &lasts);

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
        port_str = strtok_r(nullptr, "#", &lasts);
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

    char* tmp_copy = snort_strdup(ipstr);
    copy = check_delimiter(tmp_copy);
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
            snort_free(tmp_copy);
            delete[] copy;
            return -5;
        }

        if (ipset_add(ipset, &ip, &portset, (item_not_flag ^ set_not_flag)) != 0)
        {
            snort_free(tmp_copy);
            delete[] copy;
            return -6;
        }

        parse_count++;

        if (endIP && (*endIP != ']'))
        {
            endIP++;
        }

        startIP = endIP;
    }

    snort_free(tmp_copy);
    delete[] copy;

    if (!parse_count)
        return -7;

    if (open_bracket)
        return -8;

    return 0;
}

