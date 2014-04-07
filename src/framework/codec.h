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
// codec.h author Russ Combs <rucombs@cisco.com>

#ifndef CODEC_H
#define CODEC_H

#include "snort_types.h"
#include "framework/base_api.h"

struct Packet;

// this is the current version of the api
#define CDAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define CDAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// FIXIT just starting points for Codec and CodecApi

class Codec {
public:
    virtual ~Codec() { };

    virtual bool decode(Packet*);
    virtual bool encode(Packet*);

protected:
    Codec(const char* s) { name = s; };

private:
    const char* name;
};

typedef int (*cd_eval_f)(void*, Packet*);
typedef cd_eval_f (*cd_new_f)(const char* key, void**);
typedef void (*cd_del_f)(void*);
typedef void (*cd_aux_f)();

struct CodecApi
{
    BaseApi base;

    // these may be nullptr
    cd_aux_f pinit;  // initialize global plugin data
    cd_aux_f pterm;  // clean-up pinit()

    cd_aux_f tinit;  // initialize thread-local plugin data
    cd_aux_f tterm;  // clean-up tinit()

    // these must be set
    cd_new_f ctor;   // get eval with optional instance data
    cd_del_f dtor;   // clean up instance data
};

#endif

