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
// nhttp_api.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_API_H
#define NHTTP_API_H

#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/inspector.h"

#include "nhttp_module.h"
#include "nhttp_flow_data.h"

class NHttpApi
{
public:
    static const InspectApi nhttp_api;
    static const char* classic_buffer_names[];

private:
    NHttpApi() = delete;
    static Module* nhttp_mod_ctor() { return new NHttpModule; }
    static void nhttp_mod_dtor(Module* m) { delete m; }
    static const char* nhttp_my_name;
    static const char* nhttp_help;
    static void nhttp_init() { NHttpFlowData::init(); }
    static void nhttp_term() { }
    static Inspector* nhttp_ctor(Module* mod);
    static void nhttp_dtor(Inspector* p) { delete p; }
    static void nhttp_tinit() { }
    static void nhttp_tterm() { }
};

#endif

