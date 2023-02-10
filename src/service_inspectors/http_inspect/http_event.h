//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_event.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_EVENT_H
#define HTTP_EVENT_H

#include "utils/event_gen.h"
#include "utils/infractions.h"
#include "utils/util_cstring.h"

#include "http_enum.h"

//-------------------------------------------------------------------------
// HTTP Event generator
//-------------------------------------------------------------------------

using HttpEventGen = EventGen<HttpEnums::EVENT__MAX_VALUE, HttpEnums::EVENT__NONE, HttpEnums::HTTP_GID>;

static const unsigned BASE_1XX_EVENTS = 100;
static const unsigned BASE_2XX_EVENTS = 200;

//-------------------------------------------------------------------------
// Http Infractions
//-------------------------------------------------------------------------

using HttpInfractions = Infractions<HttpEnums::INF__MAX_VALUE, HttpEnums::INF__NONE>;

#endif

