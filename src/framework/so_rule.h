/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// so_rule.h author Russ Combs <rucombs@cisco.com>

#ifndef SO_RULE_H
#define SO_RULE_H

#include "snort_types.h"
#include "framework/base_api.h"
#include "framework/ips_option.h"

struct Packet;

// this is the current version of the api
#define SOAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define SOAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// rule format is:  header ( <stub opts>; soid:<tag>; <detect opts>; )
// <stub opts> must include sid
// <detect opts> may include so opts like so:<key>;
// ctor(<key>) returns eval func and optional data
// data is freed with dtor(data)

typedef int (*so_eval_f)(void*, Packet*);
typedef so_eval_f (*so_new_f)(const char* key, void**);
typedef void (*so_del_f)(void*);
typedef void (*so_aux_f)();

struct SoApi
{
    BaseApi base;

    const uint8_t* rule;
    unsigned length;

    // these may be nullptr
    so_aux_f pinit;  // initialize global plugin data
    so_aux_f pterm;  // clean-up pinit()

    so_aux_f tinit;  // initialize thread-local plugin data
    so_aux_f tterm;  // clean-up tinit()

    // these must be set
    so_new_f ctor;   // get eval with optional instance data
    so_del_f dtor;   // clean up instance data
};

#endif

