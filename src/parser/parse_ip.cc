//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "parse_ip.h"

#include "log/messages.h"
#include "main/policy.h"
#include "sfip/sf_ipvar.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"

sfip_var_t* sfip_var_from_string(const char* addr, const char* caller)
{
    sfip_var_t* ret;
    int ret_code;
    vartable_t* ip_vartable = nullptr;

    if (snort::get_ips_policy())
        ip_vartable = snort::get_ips_policy()->ip_vartable;

    ret = (sfip_var_t*)snort_calloc(sizeof(sfip_var_t));

    if ((ret_code = sfvt_add_to_var(ip_vartable, ret, addr)) != SFIP_SUCCESS)
    {
        if (ret_code == SFIP_LOOKUP_FAILURE)
        {
            snort::ParseError("%s: Undefined variable in the IP list: %s", caller, addr);
            return ret;
        }
        else if (ret_code == SFIP_CONFLICT)
        {
            snort::ParseError("%s: Negated IP ranges equal to or"
                " more-specific than non-negated ranges are not allowed."
                " Consider inverting the logic: %s.", caller, addr);
            return ret;
        }
        else if (ret_code == SFIP_LOOKUP_UNAVAILABLE)
        {
            snort::ParseError("%s: Error parsing IP list: %s. "
                "Snort variables are only permitted in rule headers, otherwise use Lua variables.",
                caller, addr);
            return ret;
        }
        else
        {
            snort::ParseError("%s: Unable to process IP list: %s", caller, addr);
            return ret;
        }
    }

    return ret;
}

