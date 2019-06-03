//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// rna_module.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_module.h"

#include <cassert>

#include "log/messages.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//-------------------------------------------------------------------------
// rna params
//-------------------------------------------------------------------------

static const Parameter rna_params[] =
{
    { "rna_conf_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to RNA configuration" },

    { "rna_util_lib_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to library for utilities such as fingerprint decoder" },

    { "fingerprint_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to fingerprint patterns" },

    { "custom_fingerprint_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to custom fingerprint patterns" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// rna module
//-------------------------------------------------------------------------

RnaModule::RnaModule() : Module(RNA_NAME, RNA_HELP, rna_params)
{ }

RnaModule::~RnaModule()
{
    delete mod_conf;
}

bool RnaModule::begin(const char* fqn, int, SnortConfig*)
{
    if (strcmp(fqn, "rna"))
        return false;
    else if (!mod_conf)
        mod_conf = new RnaModuleConfig;
    return true;
}

bool RnaModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("rna_conf_path"))
        mod_conf->rna_conf_path = std::string(v.get_string());
    else if (v.is("rna_util_lib_path"))
        mod_conf->rna_util_lib_path = std::string(v.get_string());
    else if (v.is("fingerprint_dir"))
        mod_conf->fingerprint_dir = std::string(v.get_string());
    else if (v.is("custom_fingerprint_dir"))
        mod_conf->custom_fingerprint_dir = std::string(v.get_string());
    else
        return false;

    return true;
}

bool RnaModule::end(const char* fqn, int, SnortConfig*)
{
    if (mod_conf == nullptr and strcmp(fqn, "rna") == 0)
        return false;

    return true;
}

RnaModuleConfig* RnaModule::get_config()
{
    RnaModuleConfig* tmp = mod_conf;
    mod_conf = nullptr;
    return tmp;
}

PegCount* RnaModule::get_counts() const
{ return (PegCount*)&rna_stats; }

const PegInfo* RnaModule::get_pegs() const
{ return snort::simple_pegs; }

ProfileStats* RnaModule::get_profile() const
{ return &rna_perf_stats; }

#ifdef UNIT_TEST
TEST_CASE("RNA module", "[rna_module]")
{
    SECTION("module begin, set, end")
    {
        RnaModule mod;

        CHECK_FALSE(mod.begin("dummy", 0, nullptr));
        CHECK(mod.end("rna", 0, nullptr) == false);
        CHECK(mod.begin("rna", 0, nullptr) == true);

        Value v1("rna.conf");
        v1.set(Parameter::find(rna_params, "rna_conf_path"));
        CHECK(mod.set(nullptr, v1, nullptr) == true);

        Value v2("rna_util.so");
        v2.set(Parameter::find(rna_params, "rna_util_lib_path"));
        CHECK(mod.set(nullptr, v2, nullptr) == true);

        Value v3("/dir/fingerprints");
        v3.set(Parameter::find(rna_params, "fingerprint_dir"));
        CHECK(mod.set(nullptr, v3, nullptr) == true);

        Value v4("/dir/custom_fingerprints");
        v4.set(Parameter::find(rna_params, "custom_fingerprint_dir"));
        CHECK(mod.set(nullptr, v4, nullptr) == true);

        Value v5("dummy");
        CHECK(mod.set(nullptr, v5, nullptr) == false);
        CHECK(mod.end("rna", 0, nullptr) == true);

        RnaModuleConfig* rc = mod.get_config();
        CHECK(rc != nullptr);
        CHECK(rc->rna_conf_path == "rna.conf");
        CHECK(rc->rna_util_lib_path == "rna_util.so");
        CHECK(rc->fingerprint_dir == "/dir/fingerprints");
        CHECK(rc->custom_fingerprint_dir == "/dir/custom_fingerprints");

        delete rc;
    }
}
#endif
