//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// ips_mms_func.cc author Jared Rittle <jared.rittle@cisco.com>
// modeled after ips_modbus_func.cc (author Russ Combs <rucombs@cisco.com>)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/util_ber.h"

#include "mms.h"

using namespace snort;

static const char* s_name = "mms_func";

//-------------------------------------------------------------------------
// function lookup
//-------------------------------------------------------------------------

#define MMS_FUNC__UNSET 255

struct MmsFuncMap
{
    const char* name;
    uint8_t func;
};

// Mapping of name -> function code for 'mms_func' option
static MmsFuncMap mms_func_map[] =
{
    { "status",                              0 },
    { "get_name_list",                       1 },
    { "identify",                            2 },
    { "rename",                              3 },
    { "read",                                4 },
    { "write",                               5 },
    { "get_variable_access_attributes",      6 },
    { "define_named_variable",               7 },
    { "define_scattered_access",             8 },
    { "get_scattered_access_attributes",     9 },
    { "delete_variable_access",             10 },
    { "define_named_variable_list",         11 },
    { "get_named_variable_list_attributes", 12 },
    { "delete_named_variable_list",         13 },
    { "define_named_type",                  14 },
    { "get_named_type_attributes",          15 },
    { "delete_named_type",                  16 },
    { "input",                              17 },
    { "output",                             18 },
    { "take_control",                       19 },
    { "relinquish_control",                 20 },
    { "define_semaphore",                   21 },
    { "delete_semaphore",                   22 },
    { "report_semaphore_status",            23 },
    { "report_pool_semaphore_status",       24 },
    { "report_semaphore_entry_status",      25 },
    { "initiate_download_sequence",         26 },
    { "download_segment",                   27 },
    { "terminate_download_sequence",        28 },
    { "initiate_upload_sequence",           29 },
    { "upload_segment",                     30 },
    { "terminate_upload_sequence",          31 },
    { "request_domain_download",            32 },
    { "request_domain_upload",              33 },
    { "load_domain_content",                34 },
    { "store_domain_content",               35 },
    { "delete_domain",                      36 },
    { "get_domain_attributes",              37 },
    { "create_program_invocation",          38 },
    { "delete_program_invocation",          39 },
    { "start",                              40 },
    { "stop",                               41 },
    { "resume",                             42 },
    { "reset",                              43 },
    { "kill",                               44 },
    { "get_program_invocation_attributes",  45 },
    { "obtain_file",                        46 },
    { "define_event_condition",             47 },
    { "delete_event_condition",             48 },
    { "get_event_condition_attributes",     49 },
    { "report_event_condition_status",      50 },
    { "alter_event_condition_monitoring",   51 },
    { "trigger_event",                      52 },
    { "define_event_action",                53 },
    { "delete_event_action",                54 },
    { "get_event_action_attributes",        55 },
    { "report_event_action_status",         56 },
    { "define_event_enrollment",            57 },
    { "delete_event_enrollment",            58 },
    { "alter_event_enrollment",             59 },
    { "report_event_enrollment_status",     60 },
    { "get_event_enrollment_attributes",    61 },
    { "acknowledge_event_notification",     62 },
    { "get_alarm_summary",                  63 },
    { "get_alarm_enrollment_summary",       64 },
    { "read_journal",                       65 },
    { "write_journal",                      66 },
    { "initialize_journal",                 67 },
    { "report_journal_status",              68 },
    { "create_journal",                     69 },
    { "delete_journal",                     70 },
    { "get_capability_list",                71 },
    { "file_open",                          72 },
    { "file_read",                          73 },
    { "file_close",                         74 },
    { "file_rename",                        75 },
    { "file_delete",                        76 },
    { "file_directory",                     77 },
    { "additional_service",                 78 },
    // 79 not defined
    { "get_data_exchange_attributes",       80 },
    { "exchange_data",                      81 },
    { "define_access_control_list",         82 },
    { "get_access_control_list_attributes", 83 },
    { "report_access_controlled_objects",   84 },
    { "delete_access_control_list",         85 },
    { "change_access_control",              86 },
    { "reconfigure_program_invocation",     87 },
};

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(mms_func_map) / sizeof(MmsFuncMap));

    for (size_t i = 0; i < max; ++i)
    {
        // return true when the passed string matches a known function
        if (strcmp(s, mms_func_map[i].name) == 0)
        {
            n = mms_func_map[i].func;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// func option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats mms_func_prof;

class MmsFuncOption : public IpsOption
{
public:
    MmsFuncOption(uint16_t v) :
        IpsOption(s_name)
    {
        func = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint16_t func = MMS_FUNC__UNSET;
};

uint32_t MmsFuncOption::hash() const
{
    uint32_t a = func, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool MmsFuncOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const MmsFuncOption& rhs = (const MmsFuncOption&)ips;
    return(func == rhs.func);
}

IpsOption::EvalStatus MmsFuncOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(mms_func_prof);

    if (!p->flow)
    {
        return NO_MATCH;
    }

    // check if the packet function matches the rule option function
    MmsFlowData* mmsfd = (MmsFlowData*)p->flow->get_flow_data(MmsFlowData::inspector_id);
    if (!mmsfd)
    {
        return NO_MATCH;
    }

    if (!mmsfd->is_mms_found())
    {
        return NO_MATCH;
    }

    Cursor eval_cur = Cursor(p);
    if (!eval_cur.set_pos(mmsfd->get_mms_offset()))
    {
        return NO_MATCH;
    }

    BerReader ber(eval_cur);
    BerElement e;

    if (!ber.read(eval_cur.start(), e))
    {
        return NO_MATCH;
    }

    // check for a message type that contains a service
    switch (e.type)
    {
    case MMS_MSG__CONFIRMED_REQUEST:       // fallthrough
    case MMS_MSG__CONFIRMED_RESPONSE:
        // shift cursor to next tag
        if (eval_cur.add_pos(e.header_length))
        {
            // skip past the `invoke_id`
            if (ber.read(eval_cur.start(), e))
            {
                if (eval_cur.add_pos(e.header_length + e.length))
                {
                    // get the next tag
                    if (ber.read(eval_cur.start(), e))
                    {
                        // check to see if the optional `list_of_modifiers` field is in use and
                        // skip when it is
                        const uint32_t OPTIONAL_LIST_OF_MODIFIERS_TAG = 0x10;
                        if (e.type == OPTIONAL_LIST_OF_MODIFIERS_TAG)
                        {
                            if (!eval_cur.add_pos(e.header_length + e.length))
                            {
                                return NO_MATCH;
                            }

                            // get the next tag
                            if (!ber.read(eval_cur.start(), e))
                            {
                                return NO_MATCH;
                            }
                        }

                        // check to see if the byte is less than the value of the
                        // `status` service request (0x80). When this is the case
                        // it indicates that a service tag value larger than what
                        // could fit within the available space in the preceding
                        // byte (5 bits).
                        if (e.type < 0x80)
                        {
                            // if the type is the same as what was requested by the user, return a
                            // match
                            // no mask used here as the long form is in use, which causes
                            // the next byte to contain the tag value.
                            // the entire byte can be used in this case
                            // When looking at this type of message in a traffic capture,
                            // the byte being compared here will be preceded by 0xBF
                            // which is handled by the BER reader utility
                            if ((e.type) == func)
                            {
                                return MATCH;
                            }
                        }
                        else
                        {
                            // if the type is the same as what was requested by the user, return a
                            // match
                            // a mask is used since only the low 5 bits can be used
                            uint8_t ber_tag_value_mask = 0b00011111;
                            if ((e.type & ber_tag_value_mask) == func)
                            {
                                return MATCH;
                            }
                        }
                    }
                }
            }
        }

        break;

        // no default
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~",     Parameter::PT_STRING, nullptr, nullptr,
      "func to match" },

    { nullptr, Parameter::PT_MAX,    nullptr, nullptr,nullptr }
};

#define s_help \
    "rule option to check MMS function"

class MmsFuncModule : public Module
{
public:
    MmsFuncModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &mms_func_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    uint8_t func = MMS_FUNC__UNSET;
};

bool MmsFuncModule::set(const char*, Value& v, SnortConfig*)
{
    if (!v.is("~"))
    {
        return false;
    }

    long n;

    if (v.strtol(n))
    {
        func = (uint16_t)n;
    }
    else if (get_func(v.get_string(), n))
    {
        func = static_cast<uint8_t>(n);
    }
    else
    {
        return false;
    }

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MmsFuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    MmsFuncModule* mod = (MmsFuncModule*)m;

    return new MmsFuncOption(mod->func);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_mms_func = &ips_api.base;

