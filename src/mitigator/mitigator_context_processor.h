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
// mitigator_context_processor.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_CONTEXT_PROCESSOR_H
#define MITIGATOR_CONTEXT_PROCESSOR_H

#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

#include "main/snort_types.h"

#include "mitigator_types.h"

namespace snort
{

class  MitigationContextProcessor
{
public:
    static MitigationGlobalContext* global_context();

    static const MitigationModuleContext* get_module_context(const MitigationModule& module);
    static MitigationModuleContext* take_module_context(const MitigationModule& module);

    static void emplace_context(std::string module_name, bool enabled);

    static std::vector<std::string_view> get_supported_modules();
};

} // namespace snort

#endif

