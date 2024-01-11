//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// address_space_selection.h author Ron Dempster <rdempste@cisco.com>

#ifndef ADDRESS_SPACE_SELECTION_H
#define ADDRESS_SPACE_SELECTION_H

// Evaluation elements for selecting policies based on address space

#include <vector>

#include "framework/policy_selector.h"

struct AddressSpaceSelection
{
    std::vector<uint32_t> addr_spaces;
    snort::PolicySelectUse use;

    AddressSpaceSelection();

    void clear();
};

#endif

