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
// js_norm.h author Cisco

#ifndef JS_NORM_H
#define JS_NORM_H

#include "helpers/event_gen.h"

#include "js_config.h"
#include "js_enum.h"

namespace jsn
{
class JSIdentifier;
class JSNormalizer;

const char* ret2str(int);
}

namespace snort
{

class SO_PUBLIC JSNorm
{
public:
    JSNorm(JSNormConfig*, bool ext_script_type = false, uint32_t generation_id = 0);
    JSNorm(const JSNorm&) = delete;
    virtual ~JSNorm();

    void tick()
    { ++pdu_cnt; }

    void normalize(const void*, size_t, const void*&, size_t&);
    void get_data(const void*&, size_t&);
    void flush_data(const void*&, size_t&);
    void flush_data();

    uint32_t get_generation_id() const
    { return generation_id; }

protected:
    virtual bool pre_proc();
    virtual bool post_proc(int);

    bool alive;
    uint32_t pdu_cnt;

    const uint8_t* src_ptr;
    const uint8_t* src_end;

    jsn::JSIdentifier* idn_ctx;
    jsn::JSNormalizer* jsn_ctx;
    bool ext_script_type;

    JSEvents events;
    JSNormConfig* config;
    uint32_t generation_id;
};

}

#endif
