//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// pop_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pop_module.h"

#include <cassert>

#include "log/messages.h"

using namespace snort;
using namespace std;

static const Parameter s_params[] =
{
    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "base64 decoding depth (-1 no limit)" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Non-Encoded MIME attachment extraction depth (-1 no limit)" },

    { "decompress_pdf", Parameter::PT_BOOL, nullptr, "false",
      "decompress pdf files in MIME attachments" },

    { "decompress_swf", Parameter::PT_BOOL, nullptr, "false",
      "decompress swf files in MIME attachments" },

    { "decompress_zip", Parameter::PT_BOOL, nullptr, "false",
      "decompress zip files in MIME attachments" },

    { "decompress_vba", Parameter::PT_BOOL, nullptr, "false",
      "decompress MS Office Visual Basic for Applications macro files in MIME attachments" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Quoted Printable decoding depth (-1 no limit)" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Unix-to-Unix decoding depth (-1 no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap pop_rules[] =
{
    { POP_UNKNOWN_CMD, "unknown POP3 command" },
    { POP_UNKNOWN_RESP, "unknown POP3 response" },
    { POP_B64_DECODING_FAILED, "base64 decoding failed" },
    { POP_QP_DECODING_FAILED, "quoted-printable decoding failed" },
    { POP_UU_DECODING_FAILED, "Unix-to-Unix decoding failed" },
    { POP_FILE_DECOMP_FAILED, "file decompression failed" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// pop module
//-------------------------------------------------------------------------

PopModule::PopModule() : Module(POP_NAME, POP_HELP, s_params)
{
    config = nullptr;
}

PopModule::~PopModule()
{
    if ( config )
        delete config;
}

const RuleMap* PopModule::get_rules() const
{ return pop_rules; }

const PegInfo* PopModule::get_pegs() const
{ return pop_peg_names; }

PegCount* PopModule::get_counts() const
{ return (PegCount*)&popstats; }

ProfileStats* PopModule::get_profile() const
{ return &popPerfStats; }

bool PopModule::set(const char*, Value& v, SnortConfig*)
{
    const int32_t value = v.get_int32();
    const int32_t mime_value = (value > 0) ? value : -(value+1); // flip 0 and -1 for MIME use

    if ( v.is("b64_decode_depth") )
        config->decode_conf.set_b64_depth(mime_value);

    else if ( v.is("bitenc_decode_depth") )
        config->decode_conf.set_bitenc_depth(mime_value);

    else if ( v.is("decompress_pdf") )
        config->decode_conf.set_decompress_pdf(v.get_bool());

    else if ( v.is("decompress_swf") )
        config->decode_conf.set_decompress_swf(v.get_bool());

    else if ( v.is("decompress_zip") )
        config->decode_conf.set_decompress_zip(v.get_bool());

    else if ( v.is("decompress_vba") )
        config->decode_conf.set_decompress_vba(v.get_bool());

    else if ( v.is("qp_decode_depth") )
        config->decode_conf.set_qp_depth(mime_value);

    else if ( v.is("uu_decode_depth") )
        config->decode_conf.set_uu_depth(mime_value);

    return true;
}

POP_PROTO_CONF* PopModule::get_data()
{
    POP_PROTO_CONF* tmp = config;
    config = nullptr;
    return tmp;
}

bool PopModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new POP_PROTO_CONF;
    return true;
}

bool PopModule::end(const char*, int, SnortConfig*)
{
    return true;
}

