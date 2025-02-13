//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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

// grouped_list_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <cstring>
#include <vector>

#include "helpers/grouped_list.h"

using namespace snort;
using namespace std;

struct Type
{
    int id = 0;
    const char* name = "";

    bool operator ==(const Type& r) const
    { return id == r.id and !strcmp(name, r.name); }
};

using Elem = GroupedList<Type>;

template <class... Args>
static void check_container(const Elem& cont, Args&& ... args)
{
    const vector<Type> data{std::forward<Args>(args)...};
    Elem* it = cont.get_next();

    for (const auto& d : data)
    {
        REQUIRE(it != nullptr);
        CHECK((**it) == d);
        it = it->get_next();
    }

    CHECK(it == &cont);
}

TEST_CASE("Basic", "[Double list]")
{
    Elem cont;
    Elem* group = nullptr;

    SECTION("no data")
    {
        check_container(cont);
    }

    SECTION("1 element")
    {
        const Type data = {1, "one"};
        Elem* el = new Elem(cont, group, data);

        CHECK(el != nullptr);

        check_container(cont, data);
    }

    SECTION("3 elements")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* el1 = new Elem(cont, group, data1);
        Elem* el2 = new Elem(cont, group, data2);
        Elem* el3 = new Elem(cont, group, data3);

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);
        CHECK(el3 != nullptr);

        check_container(cont, data1, data2, data3);
    }
}

TEST_CASE("Groups", "[Double list]")
{
    Elem cont;

    SECTION("3 element group")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_a, data2);
        CHECK(group_a == el2);
        Elem* el3 = new Elem(cont, group_a, data3);
        CHECK(group_a == el3);

        check_container(cont, data1, data2, data3);

        auto cnt = Elem::erase_group(group_a);
        CHECK(cnt == 3);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("3 groups")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;
        Elem* group_b = nullptr;
        Elem* group_c = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_b, data2);
        CHECK(group_b == el2);
        Elem* el3 = new Elem(cont, group_c, data3);
        CHECK(group_c == el3);

        check_container(cont, data1, data2, data3);

        auto cnt1 = Elem::erase_group(group_a);
        CHECK(cnt1 == 1);
        CHECK(group_a == nullptr);

        check_container(cont, data2, data3);

        auto cnt2 = Elem::erase_group(group_b);
        CHECK(cnt2 == 1);
        CHECK(group_b == nullptr);

        check_container(cont, data3);

        auto cnt3 = Elem::erase_group(group_c);
        CHECK(cnt3 == 1);
        CHECK(group_c == nullptr);

        check_container(cont);
    }

    SECTION("interleaving groups")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;
        Elem* group_b = nullptr;
        Elem* group_c = nullptr;

        new Elem(cont, group_a, data1);
        new Elem(cont, group_b, data2);
        new Elem(cont, group_c, data3);
        new Elem(cont, group_a, data1);
        new Elem(cont, group_b, data2);
        new Elem(cont, group_c, data3);
        new Elem(cont, group_a, data1);
        new Elem(cont, group_b, data2);
        new Elem(cont, group_c, data3);

        check_container(cont, data1, data2, data3, data1, data2, data3, data1, data2, data3);

        auto cnt1 = Elem::erase_group(group_a);
        CHECK(cnt1 == 3);
        CHECK(group_a == nullptr);

        check_container(cont, data2, data3, data2, data3, data2, data3);

        auto cnt2 = Elem::erase_group(group_b);
        CHECK(cnt2 == 3);
        CHECK(group_b == nullptr);

        check_container(cont, data3, data3, data3);

        auto cnt3 = Elem::erase_group(group_c);
        CHECK(cnt3 == 3);
        CHECK(group_c == nullptr);

        check_container(cont);
    }

    SECTION("leaving a group (middle)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_a, data2);
        CHECK(group_a == el2);
        Elem* el3 = new Elem(cont, group_a, data3);
        CHECK(group_a == el3);

        check_container(cont, data1, data2, data3);

        el2->leave_group();
        delete el2;
        CHECK(group_a == el3);

        check_container(cont, data1, data3);

        auto cnt = Elem::erase_group(group_a);
        CHECK(cnt == 2);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("leaving a group (begin)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_a, data2);
        CHECK(group_a == el2);
        Elem* el3 = new Elem(cont, group_a, data3);
        CHECK(group_a == el3);

        check_container(cont, data1, data2, data3);

        el1->leave_group();
        delete el1;
        CHECK(group_a == el3);

        check_container(cont, data2, data3);

        auto cnt = Elem::erase_group(group_a);
        CHECK(cnt == 2);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("leaving a group (end)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_a, data2);
        CHECK(group_a == el2);
        Elem* el3 = new Elem(cont, group_a, data3);
        CHECK(group_a == el3);

        check_container(cont, data1, data2, data3);

        el3->leave_group();
        delete el3;
        CHECK(group_a == el2);

        check_container(cont, data1, data2);

        auto cnt = Elem::erase_group(group_a);
        CHECK(cnt == 2);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("leaving a group (one by one)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        CHECK(group_a == el1);
        Elem* el2 = new Elem(cont, group_a, data2);
        CHECK(group_a == el2);
        Elem* el3 = new Elem(cont, group_a, data3);
        CHECK(group_a == el3);

        check_container(cont, data1, data2, data3);

        el3->leave_group();
        delete el3;
        CHECK(group_a == el2);

        el2->leave_group();
        delete el2;
        CHECK(group_a == el1);

        el1->leave_group();
        delete el1;
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("leaving a group (repeated call)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        const Type data4 = {4, "four"};
        const Type data5 = {5, "five"};
        Elem* group_a = nullptr;

        Elem* el1 = new Elem(cont, group_a, data1);
        Elem* el2 = new Elem(cont, group_a, data2);
        Elem* el3 = new Elem(cont, group_a, data3);
        Elem* el4 = new Elem(cont, group_a, data4);
        Elem* el5 = new Elem(cont, group_a, data5);

        check_container(cont, data1, data2, data3, data4, data5);

        el1->leave_group();
        el1->leave_group();
        el1->leave_group();

        el3->leave_group();
        el3->leave_group();
        el3->leave_group();

        el5->leave_group();
        el5->leave_group();
        el5->leave_group();

        CHECK(group_a == el4);
        check_container(cont, data1, data2, data3, data4, data5);

        delete el1;
        delete el2;
        delete el3;
        delete el4;
        delete el5;
    }
}

TEST_CASE("Memory management (value by copy)", "[Double list]")
{
    Elem cont;
    Elem* group_a = nullptr;
    Elem* group_b = nullptr;

    SECTION("delete element")
    {
        const Type data = {1, "one"};
        Elem* el = new Elem(cont, group_a, data);

        CHECK(el != nullptr);

        check_container(cont, data);

        delete el;

        check_container(cont);
    }

    SECTION("delete group")
    {
        const Type data = {1, "one"};
        Elem* el = new Elem(cont, group_a, data);

        CHECK(el != nullptr);

        check_container(cont, data);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("delete element, then delete group")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        Elem* el1 = new Elem(cont, group_a, data1);
        Elem* el2 = new Elem(cont, group_b, data2);

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);

        delete el2;

        check_container(cont, data1);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont);

    }

    SECTION("delete group, then delete element")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        Elem* el1 = new Elem(cont, group_a, data1);
        Elem* el2 = new Elem(cont, group_b, data2);

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, data2);

        delete el2;

        check_container(cont);
    }

    SECTION("delete elements (remain), then delete group")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* el1 = new Elem(cont, group_a, data1);
        Elem* el2 = new Elem(cont, group_b, data2);
        Elem* el3 = new Elem(cont, group_b, data3);

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);
        CHECK(el3 != nullptr);

        delete el2;

        check_container(cont, data1, data3);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, data3);

    }

    SECTION("delete group, then delete elements (remain)")
    {
        const Type data1 = {1, "one"};
        const Type data2 = {2, "two"};
        const Type data3 = {3, "three"};
        Elem* el1 = new Elem(cont, group_a, data1);
        Elem* el2 = new Elem(cont, group_b, data2);
        Elem* el3 = new Elem(cont, group_b, data3);

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);
        CHECK(el3 != nullptr);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, data2, data3);

        delete el2;

        check_container(cont, data3);
    }
}

TEST_CASE("Memory management (value in-place)", "[Double list]")
{
    Elem cont;
    Elem* group_a = nullptr;
    Elem* group_b = nullptr;

    SECTION("delete element")
    {
        Elem* el = new Elem(cont, group_a, 1, "one");

        CHECK(el != nullptr);

        check_container(cont, Type{1, "one"});

        delete el;

        check_container(cont);
    }

    SECTION("delete group")
    {
        Elem* el = new Elem(cont, group_a, 1, "one");

        CHECK(el != nullptr);

        check_container(cont, Type{1, "one"});

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont);
    }

    SECTION("delete element, then delete group")
    {
        Elem* el1 = new Elem(cont, group_a, 1, "one");
        Elem* el2 = new Elem(cont, group_b, 2, "two");

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);

        delete el2;

        check_container(cont, Type{1, "one"});

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont);

    }

    SECTION("delete group, then delete element")
    {
        Elem* el1 = new Elem(cont, group_a, 1, "one");
        Elem* el2 = new Elem(cont, group_b, 2, "two");

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, Type{2, "two"});

        delete el2;

        check_container(cont);
    }

    SECTION("delete elements (remain), then delete group")
    {
        Elem* el1 = new Elem(cont, group_a, 1, "one");
        Elem* el2 = new Elem(cont, group_b, 2, "two");
        Elem* el3 = new Elem(cont, group_b, 3, "three");

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);
        CHECK(el3 != nullptr);

        delete el2;

        check_container(cont, Type{1, "one"}, Type{3, "three"});

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, Type{3, "three"});

    }

    SECTION("delete group, then delete elements (remain)")
    {
        Elem* el1 = new Elem(cont, group_a, 1, "one");
        Elem* el2 = new Elem(cont, group_b, 2, "two");
        Elem* el3 = new Elem(cont, group_b, 3, "three");

        CHECK(el1 != nullptr);
        CHECK(el2 != nullptr);
        CHECK(el3 != nullptr);

        Elem::erase_group(group_a);
        CHECK(group_a == nullptr);

        check_container(cont, Type{2, "two"}, Type{3, "three"});

        delete el2;

        check_container(cont, Type{3, "three"});
    }
}
