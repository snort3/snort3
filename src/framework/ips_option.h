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
// ips_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_OPTION_H
#define IPS_OPTION_H

#include "snort_types.h"
#include "framework/base_api.h"
#include "detection/rule_option_types.h"

struct Packet;

// this is the current version of the api
#define IPSAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define IPSAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// api for class
// eval and action are packet thread specific
//-------------------------------------------------------------------------

struct SnortConfig;

class IpsOption {
public:
    virtual ~IpsOption() { };

    // main thread
    virtual uint32_t hash() const; 
    virtual bool operator==(const IpsOption& ips) const;

    bool operator!=(const IpsOption& ips) const
    { return !(*this == ips); };

    // packet threads
    virtual void config(SnortConfig*) { };
    virtual bool is_relative() { return false; };
    virtual int eval(Packet*) { return true; };
    virtual void action(Packet*) { };

    option_type_t get_type() const { return type; };
    const char* get_name() const { return name; };

protected:
    IpsOption(const char* s, option_type_t t = RULE_OPTION_TYPE_OTHER)
    { name = s; type = t; };

private:
    const char* name;
    option_type_t type;
};

typedef void (*ips_opt_f)(SnortConfig*);
typedef bool (*ips_chk_f)();

typedef IpsOption* (*ips_new_f)(SnortConfig*, char*, struct OptTreeNode*);
typedef void (*ips_del_f)(IpsOption*);

// FIXIT is this still useful?
typedef enum _RuleOptType
{
    OPT_TYPE_ACTION = 0,
    OPT_TYPE_LOGGING,
    OPT_TYPE_DETECTION,
    OPT_TYPE_MAX

} RuleOptType;

struct IpsApi
{
    BaseApi base;
    RuleOptType type;
    unsigned max_per_rule;
    unsigned protos;

    ips_opt_f ginit;
    ips_opt_f gterm;
    ips_opt_f tinit;
    ips_opt_f tterm;
    ips_new_f ctor;
    ips_del_f dtor;
    ips_chk_f verify;
};

static inline int ips_option_eval(void* v, Packet* p)
{
    IpsOption* opt = (IpsOption*)v;
    return opt->eval(p);
}

#endif

