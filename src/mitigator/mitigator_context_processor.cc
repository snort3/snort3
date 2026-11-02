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
// mitigator_context_processor.cc author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mitigator_context_processor.h"

namespace snort
{

static MitigationGlobalContext& s_global_ctx()
{
    static MitigationGlobalContext ctx {};
    return ctx;
}

static MitigationModuleContexts& s_module_ctxs()
{
    static MitigationModuleContexts ctxs;
    return ctxs;
}

static std::mutex& s_modules_mutex()
{
    static std::mutex mtx;
    return mtx;
}

MitigationGlobalContext* MitigationContextProcessor::global_context()
{
    return &s_global_ctx();
}

const MitigationModuleContext* MitigationContextProcessor::get_module_context(const MitigationModule& module)
{
    std::lock_guard<std::mutex> lock(s_modules_mutex());
    const auto it = s_module_ctxs().find(module);

    return it != s_module_ctxs().end() ? it->second.get() : nullptr;
}

MitigationModuleContext* MitigationContextProcessor::take_module_context(const MitigationModule& module)
{
    std::lock_guard<std::mutex> lock(s_modules_mutex());
    const auto it = s_module_ctxs().find(module);

    return it != s_module_ctxs().end() ? it->second.get() : nullptr;
}

void MitigationContextProcessor::emplace_context(std::string module_name, bool enabled)
{
    auto ctx = std::make_unique<MitigationModuleContext>();
    ctx->module = module_name;
    ctx->enabled = enabled;
    std::lock_guard<std::mutex> lock(s_modules_mutex());
    s_module_ctxs().emplace(std::move(module_name), std::move(ctx));
}

std::vector<std::string_view> MitigationContextProcessor::get_supported_modules()
{
    std::vector<std::string_view> modules;

    std::lock_guard<std::mutex> lock(s_modules_mutex());
    for(const auto& ctx : s_module_ctxs())
    {
        modules.push_back(ctx.first);
    }

    return modules;
}

} // namespace snort
