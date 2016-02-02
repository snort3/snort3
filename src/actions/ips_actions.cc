//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// ips_actions.cc author Russ Combs <rucombs@cisco.com>

#include "ips_actions.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STATIC_IPS_ACTIONS
extern const BaseApi* act_react;
extern const BaseApi* act_reject;
#endif
extern const BaseApi* act_replace;

const BaseApi* ips_actions[] =
{
#ifdef STATIC_IPS_ACTIONS
    act_react,
    act_reject,
#endif
    act_replace,
    nullptr,
};

