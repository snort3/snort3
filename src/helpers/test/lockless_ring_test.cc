//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// ring2_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vector>
#include <thread>

#include "catch/catch.hpp"

#include "../lockless_ring.h"

TEST_CASE("Basic", "LocklessRing")
{
    LocklessRing<uint32_t> llr(1024);

    SECTION("Try read empty")
    {
        REQUIRE(0 == llr.size());

        uint32_t value = 0;
        REQUIRE(false == llr.try_pop(value));
    }

    SECTION("Try push and pop")
    {
        REQUIRE(0 == llr.size());

        for (uint32_t i = 0; i < 512; ++i)
        {
            REQUIRE(true == llr.try_push(i));
        }

        REQUIRE(512 == llr.size());

        for (uint32_t i = 0; i < 512; ++i)
        {
            uint32_t value = 0;
            REQUIRE(true == llr.try_pop(value));
            REQUIRE(i == value);
        }

        REQUIRE(0 == llr.size());
    }

    SECTION("Try push over capacity")
    {
        REQUIRE(0 == llr.size());

        for (uint32_t i = 0; i < 1024; ++i)
        {
            REQUIRE(true == llr.try_push(i));
        }

        REQUIRE(1024 == llr.size());

        REQUIRE(false == llr.try_push(1024));

        REQUIRE(1024 == llr.size());

        for (uint32_t i = 0; i < 1024; ++i)
        {
            uint32_t value = 0;
            REQUIRE(true == llr.try_pop(value));
            REQUIRE(i == value);
        }
        REQUIRE(0 == llr.size());
    }

    SECTION("Multiple producers")
    {
        const uint32_t num_producers = 4;
        const uint32_t items_per_producer = 256;

        std::vector<std::thread> producers;
        for (uint32_t p = 0; p < num_producers; ++p)
        {
            producers.emplace_back([&, p]() {
                for (uint32_t i = 0; i < items_per_producer; ++i)
                {
                    while (!llr.try_push(p * items_per_producer + i))
                    {
                        // busy wait
                    }
                }
            });
        }

        for (auto& prod : producers)
        {
            prod.join();
        }

        REQUIRE(num_producers * items_per_producer == llr.size());

        bool seen[num_producers * items_per_producer] = { false };
        for (uint32_t i = 0; i < num_producers * items_per_producer; ++i)
        {
            uint32_t value = 0;
            REQUIRE(true == llr.try_pop(value));
            seen[value] = true;
        }

        for (uint32_t i = 0; i < num_producers * items_per_producer; ++i)
        {
            REQUIRE(true == seen[i]);
        }

        REQUIRE(0 == llr.size());
    }

    SECTION("Multiple consumers")
    {
        const uint32_t total_items = 1024;
        const uint32_t num_consumers = 4;
        const uint32_t items_per_consumer = 256;

        for (uint32_t i = 0; i < total_items; ++i)
        {
            REQUIRE(true == llr.try_push(i));
        }

        REQUIRE(total_items == llr.size());

        std::vector<std::thread> consumers;
        bool seen[total_items] = { false };
        for (uint32_t c = 0; c < num_consumers; ++c)
        {
            consumers.emplace_back([&, c]() {
                for (uint32_t i = 0; i < items_per_consumer; ++i)
                {
                    uint32_t value = 0;
                    while (!llr.try_pop(value))
                    {
                        // busy wait
                    }
                    seen[value] = true;
                }
            });
        }

        for (auto& cons : consumers)
        {
            cons.join();
        }

        for (uint32_t i = 0; i < total_items; ++i)
        {
            REQUIRE(true == seen[i]);
        }

        REQUIRE(0 == llr.size());
    }
}