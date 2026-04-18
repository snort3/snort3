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

// file_olefile_fuzz.cc author Jason Crowder <jasocrow@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helpers/boyer_moore_search.h"
#include "../file_olefile.h"

using namespace snort;

THREAD_LOCAL const snort::Trace* vba_data_trace = nullptr;
Packet* DetectionEngine::get_current_packet() { return nullptr; }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(snort::Packet const&) { }
LiteralSearch::Handle* search_handle = nullptr;
const LiteralSearch* searcher = nullptr;
static snort::BoyerMooreSearchNoCase static_searcher((const uint8_t*)"ATTRIBUT", 8);
namespace snort
{
void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const Packet* p, const char* fmt, va_list ap) { }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t* vba_buf = nullptr;
    uint32_t vba_buf_len = 0;
    uint32_t clamped_size = (uint32_t)size;

    if (size > UINT32_MAX)
    {
        return 0;
    }

    searcher = &static_searcher;

    oleprocess(data, clamped_size, vba_buf, vba_buf_len);

    if (vba_buf && vba_buf_len)
    {
        delete[] vba_buf;
    }

    return 0;
}
