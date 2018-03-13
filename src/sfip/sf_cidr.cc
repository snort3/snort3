//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// sf_cidr.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_cidr.h"

using namespace snort;

SfIpRet SfCidr::set(const char* src)
{
    return addr.set(src, &bits);
}

/* Check if ip is contained within the network specified by this addr */
/* Returns SFIP_EQUAL if so.
 * XXX assumes that "ip" is not less specific than "addr" XXX
*/
SfIpRet SfCidr::contains(const SfIp* ip) const
{
    uint16_t i;
    const uint32_t* pn, * pi;

    /* SFIP_CONTAINS is returned here due to how sfvar_ip_in
     * handles zeroed IPs" */
    if (!ip)
        return SFIP_CONTAINS;

    pn = addr.get_ip6_ptr();
    pi = ip->get_ip6_ptr();

    /* Iterate over each 32 bit segment */
    for (i = 0; i < bits / 32; i++, pn++, pi++)
    {
        if (*pn != *pi)
            return SFIP_NOT_CONTAINS;
    }

    unsigned int mask = 32 - (bits - 32 * i);
    if (mask == 32)
        return SFIP_CONTAINS;

    /* At this point, there are some number of remaining bits to check.
     * Mask the bits we don't care about off of "ip" so we can compare
     * the ints directly */
    unsigned int temp = ntohl(*pi);
    temp = (temp >> mask) << mask;

    /* If pn was setup correctly through this library, there is no need to
     * mask off any bits of its own. */
    if (ntohl(*pn) == temp)
        return SFIP_CONTAINS;

    return SFIP_NOT_CONTAINS;
}

