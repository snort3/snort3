//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_js_norm.h author Tom Peters <thopeter@cisco.com>
// http_js_norm.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef HTTP_JS_NORM_H
#define HTTP_JS_NORM_H

#include <cstring>

#include "js_norm/js_norm.h"
#include "js_norm/js_pdf_norm.h"
#include "search_engines/search_tool.h"

#include "http_field.h"
#include "http_flow_data.h"
#include "http_event.h"
#include "http_module.h"

snort::SearchTool* js_create_mpse_open_tag();
snort::SearchTool* js_create_mpse_tag_type();
snort::SearchTool* js_create_mpse_tag_attr();

void js_normalize(const Field& input, Field& output, const HttpParaList*, HttpInfractions*, HttpEventGen*);

class HttpJSNorm
{
public:
    virtual ~HttpJSNorm() {}

    virtual snort::JSNorm& ctx() = 0;

    void link(const void* page, HttpEventGen* http_events_, HttpInfractions* infs)
    { page_start = (const uint8_t*)page; http_events = http_events_; infractions = infs; }

    uint64_t get_trans_num() const
    { return trans_num; }

protected:
    const uint8_t* page_start = nullptr;
    HttpEventGen* http_events = nullptr;
    HttpInfractions* infractions = nullptr;
    uint64_t trans_num = 0;
    bool script_continue = false;
};

class HttpInlineJSNorm : public snort::JSNorm, public HttpJSNorm
{
public:
    HttpInlineJSNorm(JSNormConfig* jsn_config, uint64_t tid, snort::SearchTool* mpse_open_tag,
        snort::SearchTool* mpse_tag_attr) :
        JSNorm(jsn_config), mpse_otag(mpse_open_tag), mpse_attr(mpse_tag_attr), output_size(0), ext_ref_type(false)
    { trans_num = tid; }

    snort::JSNorm& ctx() override
    { return *this; }

protected:
    bool pre_proc() override;
    bool post_proc(int) override;

private:
    snort::SearchTool* mpse_otag;
    snort::SearchTool* mpse_attr;
    size_t output_size;
    bool ext_ref_type;
};

class HttpExternalJSNorm : public snort::JSNorm, public HttpJSNorm
{
public:
    HttpExternalJSNorm(JSNormConfig* jsn_config, uint64_t tid) : JSNorm(jsn_config)
    { trans_num = tid; }

    snort::JSNorm& ctx() override
    { return *this; }

protected:
    bool pre_proc() override;
    bool post_proc(int) override;
};

class HttpPDFJSNorm : public snort::PDFJSNorm, public HttpJSNorm
{
public:
    HttpPDFJSNorm(JSNormConfig* jsn_config, uint64_t tid) :
        PDFJSNorm(jsn_config)
    { trans_num = tid; }

    snort::JSNorm& ctx() override
    { return *this; }

protected:
    bool pre_proc() override;
    bool post_proc(int) override;
};

#endif

