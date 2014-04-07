/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * Author(s):  Andrew R. Baker <andrewb@snort.org>
 *             Martin Roesch   <roesch@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/* includes */

#include "ip_addr_set.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>

#include "util.h"
#include "mstring.h"
#include "parser.h"
#include "snort_debug.h"
#include "snort.h"
#include "ipv6_port.h"
#include "sfip/sf_vartable.h"

IpAddrSet *IpAddrSetParse(SnortConfig*, const char *addr)
{
    IpAddrSet *ret;
    int ret_code;
    vartable_t *ip_vartable;

    ip_vartable = get_ips_policy()->ip_vartable;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got address string: %s\n",
                addr););

    ret = (IpAddrSet*)SnortAlloc(sizeof(IpAddrSet));

    if((ret_code = sfvt_add_to_var(ip_vartable, ret, addr)) != SFIP_SUCCESS)
    {
        if(ret_code == SFIP_LOOKUP_FAILURE)
            ParseError("Undefined variable in the string: %s", addr);
        else if(ret_code == SFIP_CONFLICT)
            ParseError("Negated IP ranges that equal to or are"
                " more-specific than non-negated ranges are not allowed."
                " Consider inverting the logic: %s.", addr);
        else
            ParseError("Unable to process the IP address: %s", addr);
    }

    return ret;
}

void IpAddrSetDestroy(IpAddrSet *ipAddrSet)
{

    if(!ipAddrSet)
        return;

    sfvar_free(ipAddrSet);
}

