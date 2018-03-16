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
// ips_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_OPTION_H
#define IPS_OPTION_H

// All IPS rule keywords are realized as IpsOptions instantiated when rules
// are parsed.

#include "detection/rule_option_types.h"
#include "framework/base_api.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"

//-------------------------------------------------------------------------
// api for class
// eval and action are packet thread specific
//-------------------------------------------------------------------------

class Cursor;
struct OptTreeNode;
struct PatternMatchData;

namespace snort
{
struct Packet;
struct SnortConfig;
class Module;

// this is the current version of the api
#define IPSAPI_VERSION ((BASE_API_VERSION << 16) | 0)

enum CursorActionType
{
    CAT_NONE,
    CAT_ADJUST,
    CAT_SET_OTHER,
    CAT_SET_RAW,
    CAT_SET_FILE,
    CAT_SET_BODY,
    CAT_SET_HEADER,
    CAT_SET_KEY,
};

enum RuleDirection
{
    RULE_FROM_CLIENT,
    RULE_FROM_SERVER,
    RULE_WO_DIR
};

class SO_PUBLIC IpsOption
{
public:
    virtual ~IpsOption() = default;

    // main thread
    virtual uint32_t hash() const;
    virtual bool operator==(const IpsOption& ips) const;

    bool operator!=(const IpsOption& ips) const
    { return !(*this == ips); }

    virtual bool is_agent() { return false; }

    // packet threads
    virtual bool is_relative() { return false; }
    virtual bool fp_research() { return false; }
    virtual bool retry(Cursor&) { return false; }
    virtual void action(Packet*) { }

    enum EvalStatus { NO_MATCH, MATCH, NO_ALERT, FAILED_BIT };
    virtual EvalStatus eval(Cursor&, Packet*) { return MATCH; }

    option_type_t get_type() const { return type; }
    const char* get_name() const { return name; }
    const char* get_buffer() const { return buffer; }

    virtual CursorActionType get_cursor_type() const
    { return CAT_NONE; }

    // for fast-pattern options like content
    virtual PatternMatchData* get_pattern(SnortProtocolId, RuleDirection = RULE_WO_DIR)
    { return nullptr; }

    virtual PatternMatchData* get_alternate_pattern()
    { return nullptr; }

    static int eval(void* v, Cursor& c, Packet* p)
    {
        IpsOption* opt = (IpsOption*)v;
        return opt->eval(c, p);
    }

    static void set_buffer(const char*);

protected:
    IpsOption(const char* s, option_type_t t = RULE_OPTION_TYPE_OTHER);

private:
    const char* name;
    const char* buffer;
    option_type_t type;
};

enum RuleOptType
{
    OPT_TYPE_LOGGING,
    OPT_TYPE_DETECTION,
    OPT_TYPE_META,
    OPT_TYPE_MAX
};

typedef void (* IpsOptFunc)(SnortConfig*);

typedef IpsOption* (* IpsNewFunc)(Module*, OptTreeNode*);
typedef void (* IpsDelFunc)(IpsOption*);

struct IpsApi
{
    BaseApi base;
    RuleOptType type;

    unsigned max_per_rule;
    unsigned protos;

    IpsOptFunc pinit;
    IpsOptFunc pterm;
    IpsOptFunc tinit;
    IpsOptFunc tterm;
    IpsNewFunc ctor;
    IpsDelFunc dtor;
    IpsOptFunc verify;
};
}
#endif

