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
// mitigator_exception.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_EXCEPTION
#define MITIGATOR_EXCEPTION

#include <csignal>
#include <cstdint>

#include "main/snort_types.h"

#include "mitigator_types.h"

namespace snort
{

class SO_PUBLIC MitigationException
{
public:
    static void print_mitigation_info(int32_t signal, bool accepted);

    MitigationException() = delete;

    explicit MitigationException(int32_t signal)
    { print_mitigation_info(signal, true); }
};

} // namespace snort

#endif
