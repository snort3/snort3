//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// tp_lib_handler_test.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <string>

#define TP_SUPPORTED 1

#include "tp_lib_handler.h"
#include "appid_config.h"
#include "main/snort_debug.h"
#include "log_message_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace std;

TPLibHandler* tph = nullptr;
AppIdModuleConfig config;

AppIdModuleConfig::~AppIdModuleConfig() { }

TEST_GROUP(tp_lib_handler)
{
};

TEST(tp_lib_handler, load_unload)
{
    tph = TPLibHandler::get();
    tph->pinit(&config);
    CHECK_TRUE(tph->have_tp());

    CreateThirdPartyAppIDSession_t asf = tph->tpsession_factory();
    ThirdPartyAppIDSession* tpsession = asf();

    CHECK_TRUE(tpsession != nullptr);

    delete tpsession;

    tph->pfini();
}

TEST(tp_lib_handler, tp_lib_handler_get)
{
    tph=TPLibHandler::get();
    TPLibHandler* tph2=TPLibHandler::get();
    CHECK_EQUAL(tph,tph2);
    TPLibHandler::pfini();
}

TEST(tp_lib_handler, load_error)
{
    // Trigger load error:
    AppIdModuleConfig config;
    config.tp_appid_path="nonexistent.so";
    TPLibHandler::get();
    TPLibHandler::pinit(&config);
    CHECK_FALSE(TPLibHandler::have_tp());
    TPLibHandler::pfini();
}

TEST(tp_lib_handler, tp_appid_module_pinit_error)
{
    // Trigger MODULE pinit error:
    AppIdModuleConfig config;
    config.tp_appid_path="./libtp_mock.so";
    config.tp_appid_config="";  // forces MODULE::pinit() to return 1.
    tph=TPLibHandler::get();
    tph->pinit(&config);
    CHECK_FALSE(tph->have_tp());
    tph->pfini(1);                      // print stats too.
}

int main(int argc, char** argv)
{
    config.tp_appid_path="./libtp_mock.so";
    config.tp_appid_config="./tp.config";
    
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);

    return rc;
}

