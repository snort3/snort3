//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// client_app_smtp_test.cc author Steve Chew <stechew@cisco.com>
// unit test for client_app_smtp

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if 0
#include "network_inspectors/appid/detector_plugins/detector_smtp.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

#include <string>

struct AddAppData
{
    AppId client_id = 0;
    std::string* version_str = nullptr;
} app_data;

void fake_add_app(AppIdSession*, AppId, AppId client_id, const char* version)
{
    mock().actualCall("add_app");
    app_data.client_id = client_id;
    if (app_data.version_str)
        delete app_data.version_str;
    app_data.version_str = new std::string(version);
}

void check_client_version(const uint8_t* client_str, AppId client_id,
    const char* version_str, PegCount* client_count)
{
    ClientSMTPData clientData;
    const uint8_t* data_end = client_str + strlen((const char*)client_str)-2;
    smtp_client_mod.api = &fake_clientappapi;

    mock().expectOneCall("add_app");

    LONGS_EQUAL(0, IdentifyClientVersion(&clientData, client_str, data_end, nullptr, nullptr));
    LONGS_EQUAL(client_id, app_data.client_id);
    LONGS_EQUAL(1, *client_count);
    STRCMP_EQUAL(version_str, app_data.version_str->c_str())
    mock().checkExpectations();
}

TEST_GROUP(client_app_smtp)
{
    void setup()
    {
        memset(&appid_stats, 0, sizeof(appid_stats));
    }

    void teardown()
    {
        delete app_data.version_str;
        app_data.version_str = nullptr;
        mock().clear();
    }
};

TEST(client_app_smtp, identify_client_version_empty_data)
{
    ClientSMTPData clientData;
    LONGS_EQUAL(1, IdentifyClientVersion(&clientData, nullptr, nullptr, nullptr, nullptr));
}

TEST(client_app_smtp, extract_version_and_add_client_app_success)
{
    ClientSMTPData clientData;
    PegCount client_count = 0;
    const uint8_t* client_str=(const uint8_t*)"Thunderbird 17.2\r\n";
    const uint8_t* data_end = client_str + strlen((const char*)client_str)-2;
    smtp_client_mod.api = &fake_clientappapi;

    mock().expectOneCall("add_app");

    LONGS_EQUAL(0, extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD), client_str, data_end, &clientData, nullptr, 0,
        &client_count));
    LONGS_EQUAL(1, client_count);
    STRCMP_EQUAL("17.2", app_data.version_str->c_str())
}

TEST(client_app_smtp, extract_version_and_add_client_app_missing_version)
{
    ClientSMTPData clientData;
    PegCount client_count = 0;
    const uint8_t* client_str=(const uint8_t*)"Thunderbird \r\n";
    const uint8_t* data_end = client_str + strlen((const char*)client_str)-2;
    smtp_client_mod.api = &fake_clientappapi;

    LONGS_EQUAL(1, extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD), client_str, data_end, &clientData, nullptr, 0,
        &client_count));
    LONGS_EQUAL(0, client_count);
    mock().checkExpectations();
}

TEST(client_app_smtp, extract_version_and_add_client_invalid_extra_space)
{
    ClientSMTPData clientData;
    PegCount client_count = 0;
    const uint8_t* client_str=(const uint8_t*)"Thunderbird  1.0\r\n";
    const uint8_t* data_end = client_str + strlen((const char*)client_str)-2;
    smtp_client_mod.api = &fake_clientappapi;

    LONGS_EQUAL(1, extract_version_and_add_client_app(APP_ID_THUNDERBIRD,
        sizeof(APP_SMTP_THUNDERBIRD), client_str, data_end, &clientData, nullptr, 0,
        &client_count));
    LONGS_EQUAL(0, client_count);
    mock().checkExpectations();
}

TEST(client_app_smtp, identify_client_version_microsoft_outlook)
{
    const uint8_t* client_str=(const uint8_t*)"Microsoft Outlook, 15.0\r\n";
    check_client_version(client_str, APP_ID_OUTLOOK, "15.0",
        &appid_stats.smtp_microsoft_outlook_clients);
}

TEST(client_app_smtp, identify_client_version_microsoft_outlook_express)
{
    const uint8_t* client_str=(const uint8_t*)"Microsoft Outlook Express 13.0\r\n";
    check_client_version(client_str, APP_ID_OUTLOOK_EXPRESS, "13.0",
        &appid_stats.smtp_microsoft_outlook_express_clients);
}

TEST(client_app_smtp, identify_client_version_microsoft_outlook_imo)
{
    const uint8_t* client_str=(const uint8_t*)"Microsoft Outlook IMO, 11.0\r\n";
    check_client_version(client_str, APP_ID_OUTLOOK, "11.0",
        &appid_stats.smtp_microsoft_outlook_imo_clients);
}

TEST(client_app_smtp, identify_client_version_evolution)
{
    const uint8_t* client_str=(const uint8_t*)"Ximian Evolution 7.0\r\n";
    check_client_version(client_str, APP_ID_EVOLUTION, "7.0", &appid_stats.smtp_evolution_clients);
}

TEST(client_app_smtp, identify_client_version_lotus_notes)
{
    const uint8_t* client_str=(const uint8_t*)"Lotus Notes 2.0\r\n";
    check_client_version(client_str, APP_ID_LOTUS_NOTES, "2.0",
        &appid_stats.smtp_lotus_notes_clients);
}

TEST(client_app_smtp, identify_client_version_applemail)
{
    const uint8_t* client_str=(const uint8_t*)"Apple Mail (1984.1)\r\n";
    check_client_version(client_str, APP_ID_APPLE_EMAIL, "1984.1",
        &appid_stats.smtp_applemail_clients);
}

TEST(client_app_smtp, identify_client_version_applemail_missing_end_parenthesis)
{
    //  Missing trailing parenthesis after version.
    const uint8_t* client_str=(const uint8_t*)"Apple Mail (1984.1\r\n";

    ClientSMTPData clientData;
    const uint8_t* data_end = client_str + strlen((const char*)client_str)-2;
    smtp_client_mod.api = &fake_clientappapi;

    LONGS_EQUAL(1, IdentifyClientVersion(&clientData, client_str, data_end, nullptr, nullptr));
    mock().checkExpectations();
}

TEST(client_app_smtp, identify_client_version_eudora)
{
    const uint8_t* client_str=(const uint8_t*)"QUALCOMM Windows Eudora Version 0.3\r\n";
    check_client_version(client_str, APP_ID_EUDORA, "0.3", &appid_stats.smtp_eudora_clients);
}

TEST(client_app_smtp, identify_client_version_eudora_pro)
{
    const uint8_t* client_str=(const uint8_t*)"Windows Eudora Pro Version 2.2\r\n";
    check_client_version(client_str, APP_ID_EUDORA_PRO, "2.2",
        &appid_stats.smtp_eudora_pro_clients);
}

TEST(client_app_smtp, identify_client_version_aol)
{
    const uint8_t* client_str=(const uint8_t*)"AOL 6.4\r\n";
    check_client_version(client_str, APP_ID_AOL_EMAIL, "6.4", &appid_stats.smtp_aol_clients);
}

TEST(client_app_smtp, identify_client_version_mutt)
{
    const uint8_t* client_str=(const uint8_t*)"Mutt/1.5.21\r\n";
    check_client_version(client_str, APP_ID_MUTT, "1.5.21", &appid_stats.smtp_mutt_clients);
}

TEST(client_app_smtp, identify_client_version_kmail)
{
    const uint8_t* client_str=(const uint8_t*)"KMail/2112\r\n";
    check_client_version(client_str, APP_ID_KMAIL, "2112", &appid_stats.smtp_kmail_clients);
}

TEST(client_app_smtp, identify_client_version_mozilla)
{
    const uint8_t* client_str=(const
        uint8_t*)"Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20111105 Thunderbird/21.12\r\n";

    check_client_version(client_str, APP_ID_THUNDERBIRD, "21.12",
        &appid_stats.smtp_thunderbird_clients);
}

TEST(client_app_smtp, identify_client_version_thunderbird)
{
    const uint8_t* client_str=(const uint8_t*)"Thunderbird 17.2\r\n";

    check_client_version(client_str, APP_ID_THUNDERBIRD, "17.2",
        &appid_stats.smtp_thunderbird_clients);
}

TEST(client_app_smtp, identify_client_version_mozilla_thunderbird)
{
    const uint8_t* client_str=(const uint8_t*)"Mozilla Thunderbird 5.0\r\n";
    check_client_version(client_str, APP_ID_THUNDERBIRD, "5.0",
        &appid_stats.smtp_thunderbird_clients);
}

#endif
//  FIXIT-M Add additional tests for other client types (Outlook, etc).

int main(int, char**)
{
#if 0
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
#endif
}

