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
// base_api.h author Russ Combs <rucombs@cisco.com>

#ifndef BASE_API_H
#define BASE_API_H

// use these for plugin modules
// this is the current version of the api
#define MODAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define MODAPI_PLUGIN_V0 0

enum PlugType
{
    PT_DATA,
    PT_CODEC,
    PT_LOGGER,
    PT_IPS_OPTION,
    PT_SO_RULE,
    PT_INSPECTOR,
    PT_SEARCH_ENGINE,
    PT_MAX
};

class Module;
typedef Module* (*mod_ctor_f)();
typedef void (*mod_dtor_f)(Module*);

// if we inherit this we can't use a static initializer list :(
// so BaseApi must be the prefix (ie 1st member) of all plugin api
struct BaseApi
{
    PlugType type;
    const char* name;
    unsigned api_version;
    unsigned version;
    mod_ctor_f mod_ctor;
    mod_dtor_f mod_dtor;
};

#endif

