//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
// js_pdf_norm.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_pdf_norm.h"

#include "trace/trace_api.h"

#include "js_norm_module.h"

using namespace jsn;
using namespace snort;

bool PDFJSNorm::pre_proc()
{
    if (src_ptr >= src_end)
        return false;

    const Packet* packet = DetectionEngine::get_current_packet();

    if (!ext_script_type)
    {
        trace_logf(1, js_trace, TRACE_PROC, packet,
            "PDF starts\n");
        ext_script_type = true;
    }
    else
    {
        trace_logf(2, js_trace, TRACE_PROC, packet,
            "PDF continues\n");
    }

    buf_pdf_in.pubsetbuf(nullptr, 0)
        ->pubsetbuf(const_cast<char*>((const char*)src_ptr), src_end - src_ptr);
    pdf_out.clear();
    delete[] buf_pdf_out.take_data();

    auto r = extractor.process();

    if (r != PDFTokenizer::PDFRet::EOS)
    {
        trace_logf(2, js_trace, TRACE_PROC, DetectionEngine::get_current_packet(),
            "pdf processing failed: %d\n", (int)r);
        return false;
    }

    src_ptr = (const uint8_t*)buf_pdf_out.data();
    src_end = src_ptr + buf_pdf_out.data_len();

    // script object not found
    if (!src_ptr)
        return false;

    return true;
}

bool PDFJSNorm::post_proc(int ret)
{
    src_ptr = src_end; // one time per PDU, even if JS Normalizer has not finished

    return JSNorm::post_proc(ret);
}
