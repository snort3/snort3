//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_app_descriptor_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../appid_app_descriptor.h"

using namespace snort;

#include "appid_mock_definitions.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void ApplicationDescriptor::set_id(
    const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

TEST_GROUP(appid_subtype_list)
{

};

TEST(appid_subtype_list, add_subtype)
{
    AppIdServiceSubtypeList subtype_list;
    AppIdServiceSubtype subtype1;
    subtype1.service = "subtype1";

    // Add first subtype
    subtype_list.add(subtype1);
    CHECK_EQUAL(1, subtype_list.size());
    CHECK_EQUAL("subtype1", subtype_list.head()->data.service);

    // Add second subtype
    AppIdServiceSubtype subtype2;
    subtype2.service = "subtype2";
    subtype_list.add(subtype2);
    CHECK_EQUAL(2, subtype_list.size());
    CHECK_EQUAL("subtype2", subtype_list.head()->next->data.service);

    // Add third subtype, should remove the first one due to limit
    AppIdServiceSubtype subtype3;
    subtype3.service = "subtype3";
    subtype_list.add(subtype3, 2);
    CHECK_EQUAL(2, subtype_list.size());
    CHECK_EQUAL("subtype2", subtype_list.head()->data.service);
    CHECK_EQUAL("subtype3", subtype_list.head()->next->data.service);
}

TEST(appid_subtype_list, emplace_front)
{
    AppIdServiceSubtypeList subtype_list;
    auto item1 = subtype_list.emplace_front();
    item1->service = "subtype1";
    CHECK_EQUAL(1, subtype_list.size());
    CHECK_EQUAL("subtype1", subtype_list.head()->data.service);

    auto item2 = subtype_list.emplace_front();
    item2->service = "subtype2";
    CHECK_EQUAL(2, subtype_list.size());
    CHECK_EQUAL("subtype2", subtype_list.head()->data.service);
    CHECK_EQUAL("subtype1", subtype_list.head()->next->data.service);
}

TEST(appid_subtype_list, emplace)
{
    AppIdServiceSubtypeList subtype_list;
    auto item1 = subtype_list.emplace();
    item1->service = "subtype1";
    CHECK_EQUAL(1, subtype_list.size());
    CHECK_EQUAL("subtype1", subtype_list.head()->data.service);

    auto item2 = subtype_list.emplace();
    item2->service = "subtype2";
    CHECK_EQUAL(2, subtype_list.size());
    CHECK_EQUAL("subtype1", subtype_list.head()->data.service);
    CHECK_EQUAL("subtype2", subtype_list.head()->next->data.service);
}

TEST(appid_subtype_list, clear)
{
    AppIdServiceSubtypeList subtype_list;
    auto item1 = subtype_list.emplace_front();
    item1->service = "subtype1";
    auto item2 = subtype_list.emplace_front();
    item2->service = "subtype2";

    CHECK_EQUAL(2, subtype_list.size());
    subtype_list.clear();
    CHECK_EQUAL(0, subtype_list.size());
    CHECK(subtype_list.empty());
    CHECK(subtype_list.head() == nullptr);
    CHECK(subtype_list.tail() == nullptr);
}

TEST(appid_subtype_list, splice)
{
    AppIdServiceSubtypeList list1;
    auto item1 = list1.emplace();
    item1->service = "subtype1";
    auto item2 = list1.emplace();
    item2->service = "subtype2";

    AppIdServiceSubtypeList list2;
    auto item3 = list2.emplace();
    item3->service = "subtype3";
    auto item4 = list2.emplace();
    item4->service = "subtype4";

    CHECK_EQUAL(2, list1.size());
    CHECK_EQUAL(2, list2.size());

    // Splice list2 into list1 with no limit
    list1.splice(list2);
    CHECK_EQUAL(4, list1.size());
    CHECK_EQUAL("subtype1", list1.head()->data.service);
    CHECK_EQUAL("subtype2", list1.head()->next->data.service);
    CHECK_EQUAL("subtype3", list1.head()->next->next->data.service);
    CHECK_EQUAL("subtype4", list1.head()->next->next->next->data.service);

    // List2 should be empty after splicing
    CHECK(list2.empty());

    AppIdServiceSubtypeList list3;
    auto item5 = list3.emplace();
    item5->service = "subtype5";

    // Splice list3 into list1 with a limit of 3
    list1.splice(list3, 3);
    CHECK_EQUAL(3, list1.size());
    CHECK_EQUAL("subtype3", list1.head()->data.service);
    CHECK_EQUAL("subtype4", list1.head()->next->data.service);
    CHECK_EQUAL("subtype5", list1.head()->next->next->data.service);
    CHECK(list3.empty());
}

TEST(appid_subtype_list, overflow_cases)
{
    AppIdServiceSubtypeList subtype_list;
    for (uint i = 0; i < UINT16_MAX; ++i)
    {
        auto item = subtype_list.emplace();
        item->service = "subtype" + std::to_string(i);
    }
    CHECK_EQUAL(UINT16_MAX, subtype_list.size());

    const AppIdServiceSubtype* const res = subtype_list.emplace();
    CHECK(res == nullptr); // Should not allow more than UINT16_MAX entries

    const AppIdServiceSubtype* const res2 = subtype_list.emplace_front();
    CHECK(res2 == nullptr); // Should not allow more than UINT16_MAX entries

    AppIdServiceSubtype subtype;
    subtype.service = "new_subtype";
    subtype_list.add(subtype, UINT16_MAX);
    CHECK_EQUAL(UINT16_MAX, subtype_list.size()); // Size should remain UINT16_MAX 
    CHECK(subtype_list.tail()->data.service == "new_subtype"); // The last entry should be the new subtype

    AppIdServiceSubtypeList subtype_list2;
    for (uint i = 0; i < 20; ++i)
    {
        auto item = subtype_list2.emplace();
        item->service = "new_subtype" + std::to_string(i);
    }
    subtype_list.splice(subtype_list2, 10);
    CHECK(subtype_list.size() == 10); // Size should be capped at 10
}

int main(int argc, char** argv)
{
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    return rc;
}