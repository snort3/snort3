/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "framework/so_rule.h"
#include "managers/ips_manager.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"

// FIXIT add profiling - note: will be for so option
// overall, and include all the various so evals

class SoOption : public IpsOption
{
public:
    SoOption(const char*, const char*, SoEvalFunc f, void* v);
    ~SoOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet* p)
    { return func(data, p); };

private:
    const char* soid;
    const char* so;
    SoEvalFunc func;
    void* data;
};

SoOption::SoOption(
    const char* id, const char* s, SoEvalFunc f, void* v)
    : IpsOption("so")
{
    soid = id;
    so = s;
    func = f;
    data = v;
}

SoOption::~SoOption()
{
    if ( data )
        IpsManager::delete_so_data(soid, data);
}

uint32_t SoOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a,b,c,soid);
    mix_str(a,b,c,so);
    final(a,b,c);
    return c;
}

bool SoOption::operator==(const IpsOption& ips) const
{
    SoOption& rhs = (SoOption&)ips;

    if ( strcmp(soid, rhs.soid) )
        return false;

    if ( strcmp(so, rhs.so) )
        return false;

    return true;
}

static IpsOption* so_ctor(
    SnortConfig*, char* args, OptTreeNode* otn)
{
    void* data;
    SoEvalFunc func = IpsManager::get_so_eval(otn->soid, args, &data);

    if ( !func )
    {
        ParseError("Can't link so:%s", args);
        return nullptr;
    }
    return new SoOption(otn->soid, args, func, data);
}

static void so_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi so_api =
{
    {
        PT_IPS_OPTION,
        "so",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    1, 0x0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    so_ctor,
    so_dtor,
    nullptr
};

const BaseApi* ips_so = &so_api.base;

