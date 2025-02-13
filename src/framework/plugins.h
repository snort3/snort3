//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// plugins.h author Russ Combs <rucombs@cisco.com>

#ifndef PLUGINS_H
#define PLUGINS_H

// top level headers required by plugins
// used to establish base header dependencies

// the base API is comprised of the set of headers installed
// in framework/snort_api.h less these plugin specific headers
// which have their own API versions:

#include "framework/codec.h"
#include "framework/connector.h"
#include "framework/inspector.h"
#include "framework/ips_action.h"
#include "framework/ips_option.h"
#include "framework/logger.h"
#include "framework/mpse.h"
#include "framework/policy_selector.h"
#include "framework/so_rule.h"

// forward decls we must explicitly include here to
// generate the complete set of API dependencies:

#include "flow/flow.h"
#include "framework/module.h"
#include "framework/pig_pen.h"
#include "protocols/packet.h"

#endif

