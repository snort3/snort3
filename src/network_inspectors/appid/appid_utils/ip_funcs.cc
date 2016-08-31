//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// ip_funcs.cc author Sourcefire Inc.

#include "ip_funcs.h"

#include "sfutil.h"
#include "log/messages.h"
#include "utils/util.h"

RNAIpAddrSet* ParseIpCidr(char* ipstring, uint32_t* netmasks)
{
    char* toks[2];
    int num_toks;
    RNAIpAddrSet* ias;
    char* cp;
    struct in_addr ia;

    if (ipstring == nullptr)
        return nullptr;

    ias = (RNAIpAddrSet*)snort_calloc(sizeof(RNAIpAddrSet));
    strip(ipstring);
    cp = ipstring;
    if (*cp == 'h')
    {
        ias->addr_flags |= IPFUNCS_HOSTS_IP;
        cp++;
    }

    if (*cp == 's')
    {
        ias->addr_flags |= IPFUNCS_APPLICATION;
        cp++;
    }

    if (*cp == '!')
    {
        ias->addr_flags |= IPFUNCS_EXCEPT_IP;
        cp++;
    }

    if (!strcasecmp(ipstring, "any"))
    {
        ias->range_max = ~0;
        return ias;
    }

    num_toks = Split(cp, toks, 2, "/");

    if (inet_pton(AF_INET, toks[0], &ia) <= 0)
    {
        ErrorMessage("IPFunctions: %s failed to translate", toks[0]);
        snort_free(ias);
        return nullptr;
    }

    ias->range_min = ntohl(ia.s_addr);

    if (num_toks > 1)
    {
        ias->netmask = (unsigned)strtoul(toks[1], nullptr, 0);

        if (ias->netmask < 32)
        {
            ias->netmask_mask = netmasks[ias->netmask];
            ias->range_min &= ias->netmask_mask;
            ias->range_max = ias->range_min + ~ias->netmask_mask;
        }
        else
        {
            ias->netmask = 32;
            ias->netmask_mask = netmasks[ias->netmask];
            ias->range_min &= ias->netmask_mask;
            ias->range_max = ias->range_min;
        }
    }
    else
    {
        ias->netmask = 32;
        ias->netmask_mask = netmasks[ias->netmask];
        ias->range_min &= ias->netmask_mask;
        ias->range_max = ias->range_min;
    }

    return ias;
}

RNAIpv6AddrSet* ParseIpv6Cidr(char* ipstring)
{
    char* toks[2];
    int num_toks;
    RNAIpv6AddrSet* ias;
    char* cp;
    struct in6_addr ia;

    if (ipstring == nullptr)
        return nullptr;

    ias = (RNAIpv6AddrSet*)snort_calloc(sizeof(*ias));
    strip(ipstring);
    cp = ipstring;
    if (*cp == 'h')
    {
        ias->addr_flags |= IPFUNCS_HOSTS_IP;
        cp++;
    }

    if (*cp == 's')
    {
        ias->addr_flags |= IPFUNCS_APPLICATION;
        cp++;
    }

    if (*cp == '!')
    {
        ias->addr_flags |= IPFUNCS_EXCEPT_IP;
        cp++;
    }

    if (!strcasecmp(ipstring, "any"))
    {
        ias->range_max.lo = ULLONG_MAX;
        ias->range_max.hi = ULLONG_MAX;
        return ias;
    }

    num_toks = Split(cp, toks, 2, "/");

    if (inet_pton(AF_INET6, toks[0], &ia) <= 0)
    {
        ErrorMessage("IPFunctions: %s failed to translate", toks[0]);
        snort_free(ias);
        return nullptr;
    }
    memcpy(&ias->range_min, (const void*)&ia, sizeof(ias->range_min));
    NSIPv6AddrNtoH(&ias->range_min);

    if (num_toks > 1)
    {
        ias->netmask = (unsigned)strtoul(toks[1], nullptr, 0);

        /* Convert cidr to netmask */
        if (!ias->netmask)
        {
            ias->range_max.hi = ULLONG_MAX;
            ias->range_max.lo = ULLONG_MAX;
        }
        else if (ias->netmask < 64)
        {
            ias->netmask_mask.hi = ULLONG_MAX << (64 - ias->netmask);
            ias->range_min.hi &= ias->netmask_mask.hi;
            ias->range_min.lo = 0;
            ias->range_max.hi = ias->range_min.hi + ~ias->netmask_mask.hi;
            ias->range_max.lo = ULLONG_MAX;
        }
        else if (ias->netmask == 64)
        {
            ias->netmask_mask.hi = ULLONG_MAX;
            ias->range_min.hi &= ias->netmask_mask.hi;
            ias->range_min.lo = 0;
            ias->range_max.hi = ias->range_min.hi + ~ias->netmask_mask.hi;
            ias->range_max.lo = ULLONG_MAX;
        }
        else if (ias->netmask < 128)
        {
            ias->netmask_mask.hi = ULLONG_MAX;
            ias->netmask_mask.lo = ULLONG_MAX << (128 - ias->netmask);
            ias->range_min.lo &= ias->netmask_mask.lo;
            ias->range_max.hi = ias->range_min.hi;
            ias->range_max.lo = ias->range_min.lo + ~ias->netmask_mask.lo;
        }
        else
        {
            ias->netmask_mask.hi = ULLONG_MAX;
            ias->netmask_mask.lo = ULLONG_MAX;
            ias->range_max = ias->range_min;
        }
    }
    else
    {
        ias->netmask = 128;
        ias->netmask_mask.lo = ULLONG_MAX;
        ias->netmask_mask.hi = ULLONG_MAX;
        ias->range_max = ias->range_min;
    }

    return ias;
}

