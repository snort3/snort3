//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// rna_module_test.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../rna_module.cc"

#include "rna_module_mock.h"
#include "rna_module_stubs.h"

// To avoid warnings between catch.hpp and UtestMacros.h macro definitions,
// since rna_module.cc has both catch and cpputest tests
#undef CHECK
#undef CHECK_FALSE
#undef CHECK_THROWS

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void set_tcp_fp_processor(TcpFpProcessor*) { }
void set_ua_fp_processor(UaFpProcessor*) { }
void set_udp_fp_processor(UdpFpProcessor*) { }
void set_smb_fp_processor(SmbFpProcessor*) { }

namespace snort
{
    void SnortConfig::register_reload_handler(ReloadResourceTuner* rrt) { delete rrt; }
}

TEST_GROUP(rna_module_test)
{
};

TEST(rna_module_test, push_tcp_fingerprints)
{
    // In plain English, we test that the RNA module pushes tcp fingerprints
    // correctly to the processor:
    // 1. create a raw fingerprint
    // 2. create the corresponding expected tcp fingerprint
    // 3. call Module::set() for each field
    // 4. call Module::end(), to push the module internal fingerprint to the
    //    config processor
    // 5. do this for a client-type fingerprint and a server-type fingerprint
    // 6. the module config is private, so create an inspector and pass the
    //    config on to the inspector
    // 6. retrieve the client and server vectors from the processors and
    //    match expected in each case

    RnaModule mod;

    // input fingerprint
    RawFingerprint rawfp;
    rawfp.fpid = 948;
    rawfp.fp_type = FpFingerprint::FpType::FP_TYPE_SERVER;
    rawfp.fpuuid = "12345678-1234-1234-1234-012345678912";
    rawfp.ttl = 64;
    rawfp.tcp_window = "10 20 30-40 50 60-70";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 3 4 8";
    rawfp.ws = "6";
    rawfp.df = true;

    // expected
    TcpFingerprint tfpe;
    tfpe.fpid = rawfp.fpid;
    tfpe.fp_type = rawfp.fp_type;
    tfpe.fpuuid = rawfp.fpuuid;
    tfpe.ttl = rawfp.ttl;
    tfpe.tcp_window = vector<FpElement> {
        FpElement("10"), FpElement("20"), FpElement("30-40"),
        FpElement("50"), FpElement("60-70") };
    tfpe.mss = vector<FpElement> { FpElement("X") };
    tfpe.id = vector<FpElement> { FpElement("X") };
    tfpe.topts = vector<FpElement> {
        FpElement("2"), FpElement("3"), FpElement("4"), FpElement("8") };
    tfpe.ws.emplace_back(FpElement("6"));
    tfpe.df = rawfp.df;

    CHECK(mod.begin("rna", 0, nullptr) == true);
    CHECK(mod.begin("rna.tcp_fingerprints", 0, nullptr) == true); // instantiates processor

    auto server_fpid = rawfp.fpid;
    {
        Value v((double) server_fpid);
        v.set(Parameter::find(rna_fp_params, "fpid"));
        CHECK(mod.set("rna.tcp_fingerprints.fpid", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.fp_type);
        v.set(Parameter::find(rna_fp_params, "type"));
        CHECK(mod.set("rna.tcp_fingerprints.type", v, nullptr) == true);
    }

    {
        Value v(rawfp.fpuuid.c_str());
        v.set(Parameter::find(rna_fp_params, "uuid"));
        CHECK(mod.set("rna.tcp_fingerprints.uuid", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.ttl);
        v.set(Parameter::find(rna_fp_params, "ttl"));
        CHECK(mod.set("rna.tcp_fingerprints.ttl", v, nullptr) == true);
    }

    {
        Value v(rawfp.tcp_window.c_str());
        v.set(Parameter::find(rna_fp_params, "tcp_window"));
        CHECK(mod.set("rna.tcp_fingerprints.tcp_window", v, nullptr) == true);
    }

    {
        Value v(rawfp.mss.c_str());
        v.set(Parameter::find(rna_fp_params, "mss"));
        CHECK(mod.set("rna.tcp_fingerprints.mss", v, nullptr) == true);
    }

    {
        Value v(rawfp.id.c_str());
        v.set(Parameter::find(rna_fp_params, "id"));
        CHECK(mod.set("rna.tcp_fingerprints.id", v, nullptr) == true);
    }

    {
        Value v(rawfp.topts.c_str());
        v.set(Parameter::find(rna_fp_params, "topts"));
        CHECK(mod.set("rna.tcp_fingerprints.topts", v, nullptr) == true);
    }

    {
        Value v(rawfp.ws.c_str());
        v.set(Parameter::find(rna_fp_params, "ws"));
        CHECK(mod.set("rna.tcp_fingerprints.ws", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.df);
        v.set(Parameter::find(rna_fp_params, "df"));
        CHECK(mod.set("rna.tcp_fingerprints.df", v, nullptr) == true);
    }

    // push it to the processor
    CHECK(mod.end("rna.tcp_fingerprints", 0, nullptr) == true);

    // add one for the client too, by changing only the type and id
    auto client_fpid = rawfp.fpid+1;     // non duplicate id
    rawfp.fp_type = FpFingerprint::FpType::FP_TYPE_CLIENT;

    {
        Value v((double) client_fpid);
        v.set(Parameter::find(rna_fp_params, "fpid"));
        CHECK(mod.set("rna.tcp_fingerprints.fpid", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.fp_type);
        v.set(Parameter::find(rna_fp_params, "type"));
        CHECK(mod.set("rna.tcp_fingerprints.type", v, nullptr) == true);
    }

    {
        Value v(rawfp.fpuuid.c_str());
        v.set(Parameter::find(rna_fp_params, "uuid"));
        CHECK(mod.set("rna.tcp_fingerprints.uuid", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.ttl);
        v.set(Parameter::find(rna_fp_params, "ttl"));
        CHECK(mod.set("rna.tcp_fingerprints.ttl", v, nullptr) == true);
    }

    {
        Value v(rawfp.tcp_window.c_str());
        v.set(Parameter::find(rna_fp_params, "tcp_window"));
        CHECK(mod.set("rna.tcp_fingerprints.tcp_window", v, nullptr) == true);
    }

    {
        Value v(rawfp.mss.c_str());
        v.set(Parameter::find(rna_fp_params, "mss"));
        CHECK(mod.set("rna.tcp_fingerprints.mss", v, nullptr) == true);
    }

    {
        Value v(rawfp.id.c_str());
        v.set(Parameter::find(rna_fp_params, "id"));
        CHECK(mod.set("rna.tcp_fingerprints.id", v, nullptr) == true);
    }

    {
        Value v(rawfp.topts.c_str());
        v.set(Parameter::find(rna_fp_params, "topts"));
        CHECK(mod.set("rna.tcp_fingerprints.topts", v, nullptr) == true);
    }

    {
        Value v(rawfp.ws.c_str());
        v.set(Parameter::find(rna_fp_params, "ws"));
        CHECK(mod.set("rna.tcp_fingerprints.ws", v, nullptr) == true);
    }

    {
        Value v((double) rawfp.df);
        v.set(Parameter::find(rna_fp_params, "df"));
        CHECK(mod.set("rna.tcp_fingerprints.df", v, nullptr) == true);
    }

    // push it to the processor
    CHECK(mod.end("rna.tcp_fingerprints", 0, nullptr) == true);

    // only now create the inspector
    RnaInspector inspector(&mod);   // inspector owns the processor

    // final check
    const auto* processor = inspector.get_fp_processor();

    auto tfps = processor->get(server_fpid);
    auto tfpc = processor->get(client_fpid);

    // test fingerprint equality - does not use ids
    CHECK(*tfps == tfpe);
    CHECK(*tfpc == tfpe);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
