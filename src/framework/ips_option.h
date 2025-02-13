//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// ips_option.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_OPTION_H
#define IPS_OPTION_H

// All IPS rule keywords are realized as IpsOptions instantiated when rules
// are parsed.

// the IPSAPI_VERSION will change if anything in this file changes.
// see also framework/base_api.h.

#include <cinttypes>

#include "detection/rule_option_types.h"
#include "framework/base_api.h"
#include "framework/cursor.h"
#include "framework/pdu_section.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"

//-------------------------------------------------------------------------
// api for class
// eval and action are packet thread specific
//-------------------------------------------------------------------------

class Cursor;
struct IpsInfo;
struct PatternMatchData;
struct TagData;
struct SoRules;

namespace snort
{
struct Packet;
struct SnortConfig;
class Module;

// this is the current version of the api
#define IPSAPI_VERSION ((BASE_API_VERSION << 16) | 3)

enum CursorActionType
{
    CAT_NONE,
    CAT_READ,
    CAT_ADJUST,
    CAT_SET_OTHER,
    CAT_SET_RAW,
    CAT_SET_FAST_PATTERN,
    CAT_SET_SUB_SECTION,
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

    virtual bool retry(Cursor&) { return false; }
    virtual void action(Packet*) { }

    enum EvalStatus { NO_MATCH, MATCH, NO_ALERT, FAILED_BIT };
    virtual EvalStatus eval(Cursor&, Packet*) { return MATCH; }

    virtual CursorActionType get_cursor_type() const
    { return CAT_NONE; }

    // for fast-pattern options like content
    virtual PatternMatchData* get_pattern(SnortProtocolId, RuleDirection = RULE_WO_DIR)
    { return nullptr; }

    virtual PatternMatchData* get_alternate_pattern()
    { return nullptr; }

    option_type_t get_type() const { return type; }
    const char* get_name() const { return name; }

    bool is_buffer_setter() const
    { return get_cursor_type() > CAT_ADJUST; }

    virtual section_flags get_pdu_section(bool to_server) const;

    // these methods are only available to the instantiator method (IpsNewFunc)
    static bool has_plugin(IpsInfo&, const char* name);

    static void set_priority(const IpsInfo&, uint32_t);
    static void set_classtype(IpsInfo&, const char*);

    enum Enable { NO, YES, INHERIT };
    static void set_enabled(IpsInfo&, Enable);

    static void set_flowbits_check(IpsInfo&);
    static void set_detection_filter(IpsInfo&, bool track_src, uint32_t count, uint32_t seconds); // don't install header

    static void set_stateless(IpsInfo&);
    static void set_to_client(IpsInfo&);
    static void set_to_server(IpsInfo&);

    static void set_gid(const IpsInfo&, uint32_t);
    static void set_sid(const IpsInfo&, uint32_t);
    static void set_rev(const IpsInfo&, uint32_t);

    static void set_message(const IpsInfo&, const char*);
    static void set_metadata_match(IpsInfo&);

    static void set_tag(IpsInfo&, TagData*);
    static void set_target(const IpsInfo&, bool src_ip);

    static void set_file_id(const IpsInfo&, uint64_t);
    static void add_reference(IpsInfo&, const char*, const char*);
    static void add_service(IpsInfo&, const char*);

    static void set_soid(IpsInfo&, const char*);
    static const char* get_soid(const IpsInfo&);

    typedef snort::IpsOption::EvalStatus (* SoEvalFunc)(void*, class Cursor&, snort::Packet*);
    static SoEvalFunc get_so_eval(IpsInfo&, const char* name, void*& data);

    static SnortProtocolId get_protocol_id(const IpsInfo&);

    static SoRules* get_so_rules(const IpsInfo&);

protected:
    IpsOption(const char* s, option_type_t t = RULE_OPTION_TYPE_OTHER);

private:
    const char* name;
    option_type_t type;
};

enum RuleOptType
{
    OPT_TYPE_LOGGING,
    OPT_TYPE_DETECTION,
    OPT_TYPE_META,
    OPT_TYPE_MAX
};

typedef void (* IpsOptFunc)(const SnortConfig*);

typedef IpsOption* (* IpsNewFunc)(Module*, IpsInfo&);
typedef void (* IpsDelFunc)(IpsOption*);

struct IpsApi
{
    BaseApi base;
    RuleOptType type;

    int max_per_rule;   // max instances of this keyword per IPS rule, 0 - no limits, negative - generate a warning
    unsigned protos;    // bitmask of PROTO_BIT_* from decode_data.h

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
