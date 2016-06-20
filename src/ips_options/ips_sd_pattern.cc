//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// ips_sd_pattern.cc author Victor Roemer <viroemer@cisco.com>

// FIXIT-M use Hyperscan

#include <string.h>
#include <assert.h>
#include <string>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "detection/detection_defines.h"
#include "detection/pattern_match_data.h"
#include "hash/sfhashfcn.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "parser/parser.h"
#include "profiler/profiler.h"
#include "sd_pattern_match.h"
#include "log/obfuscator.h"

#define s_name "sd_pattern"
#define s_help "rule option for detecting sensitive data"

struct SdStats
{
    PegCount nomatch_notfound;
    PegCount nomatch_threshold;
};

const PegInfo sd_pegs[] =
{
    { "below threshold", "sd_pattern matched but missed threshold" },
    { "pattern not found", "sd_pattern did not not match" },
    { nullptr, nullptr }
};

static THREAD_LOCAL SdStats s_stats;

struct SdPatternConfig
{
    std::string pii;
    unsigned threshold = 1;
    bool obfuscate_pii;
};

static THREAD_LOCAL ProfileStats sd_pattern_perf_stats;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class SdPatternOption : public IpsOption
{
public:
    SdPatternOption(const SdPatternConfig&);
    ~SdPatternOption();

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet* p) override;

private:
    unsigned SdSearch(Cursor&, Packet*);

    const SdPatternConfig config;
    SdOptionData* opt;
};

SdPatternOption::SdPatternOption(const SdPatternConfig& c) :
    IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE), config(c)
{
    opt = new SdOptionData(config.pii, config.obfuscate_pii);
}

SdPatternOption::~SdPatternOption()
{
    delete opt;
}

uint32_t SdPatternOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a, b, c, config.pii.c_str());
    mix_str(a, b, c, get_name());
    finalize(a, b, c);
    return c;
}

bool SdPatternOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const SdPatternOption& rhs = static_cast<const SdPatternOption&>(ips);

    if ( config.pii == rhs.config.pii
        and config.threshold == rhs.config.threshold )
        return true;

    return false;
}

unsigned SdPatternOption::SdSearch(Cursor& c, Packet* p)
{
    const uint8_t* const start = c.buffer();
    const uint8_t* buf = c.start();
    uint16_t buflen = c.length();
    const uint8_t* const end = buf + buflen;

    unsigned count = 0;
    while (buf < end && count < config.threshold)
    {
        uint16_t match_len = 0;

        if ( opt->match(buf, &match_len, buflen) )
        {
            if ( opt->obfuscate_pii )
            {
                if ( !p->obfuscator )
                    p->obfuscator = new Obfuscator();

                uint32_t off = buf - start;
                p->obfuscator->push(off, match_len - 4);
            }

            buf += match_len;
            buflen -= match_len;
            count++;
        }
        else
        {
            buf++;
            buflen--;
        }
    }

    return count;
}

int SdPatternOption::eval(Cursor& c, Packet* p)
{
    Profile profile(sd_pattern_perf_stats);

    unsigned matches = SdSearch(c, p);

    if ( matches >= config.threshold )
        return DETECTION_OPTION_MATCH;
    else if ( matches == 0 )
        ++s_stats.nomatch_notfound;
    else if ( matches > 0 && matches < config.threshold )
        ++s_stats.nomatch_threshold;

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~pattern", Parameter::PT_STRING, nullptr, nullptr,
      "The pattern to search for" },

    { "threshold", Parameter::PT_INT, "1", nullptr,
      "number of matches before alerting" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SdPatternModule : public Module
{
public:
    SdPatternModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value& v, SnortConfig*) override;

    const PegInfo* get_pegs() const override
    { return sd_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&s_stats; }

    ProfileStats* get_profile() const override
    { return &sd_pattern_perf_stats; }

    void get_data(SdPatternConfig& c)
    { c = config; }

private:
    SdPatternConfig config;
};

bool SdPatternModule::begin(const char*, int, SnortConfig*)
{
    config = SdPatternConfig();
    return true;
}

bool SdPatternModule::set(const char*, Value& v, SnortConfig* sc)
{
    config.obfuscate_pii = sc->obfuscate_pii;
    if ( v.is("~pattern") )
    {
        config.pii = v.get_string();
        // remove quotes
        config.pii.erase(0, 1);
        config.pii.erase(config.pii.length()-1, 1);
    }
    else if ( v.is("threshold") )
        config.threshold = v.get_long();
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new SdPatternModule;
}

static void mod_dtor(Module* p)
{
    delete p;
}

static IpsOption* sd_pattern_ctor(Module* m, OptTreeNode*)
{
    SdPatternModule* mod = (SdPatternModule*)m;
    SdPatternConfig c;
    mod->get_data(c);
    return new SdPatternOption(c);
}

static void sd_pattern_dtor(IpsOption* p)
{ delete p; }

static const IpsApi sd_pattern_api =
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
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sd_pattern_ctor,
    sd_pattern_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sd_pattern_api.base,
    nullptr
};
#else
const BaseApi* ips_sd_pattern = &sd_pattern_api.base;
#endif

