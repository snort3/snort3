//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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

// imap_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imap_module.h"

#include <cassert>

#include "log/messages.h"

using namespace snort;
using namespace std;

static const Parameter s_params[] =
{
    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "base64 decoding depth (-1 no limit)" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "non-Encoded MIME attachment extraction depth (-1 no limit)" },

    { "decompress_pdf", Parameter::PT_BOOL, nullptr, "false",
      "decompress pdf files in MIME attachments" },

    { "decompress_swf", Parameter::PT_BOOL, nullptr, "false",
      "decompress swf files in MIME attachments" },

    { "decompress_zip", Parameter::PT_BOOL, nullptr, "false",
      "decompress zip files in MIME attachments" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "quoted Printable decoding depth (-1 no limit)" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Unix-to-Unix decoding depth (-1 no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap imap_rules[] =
{
    { IMAP_UNKNOWN_CMD, "unknown IMAP3 command" },
    { IMAP_UNKNOWN_RESP, "unknown IMAP3 response" },
    { IMAP_B64_DECODING_FAILED, "base64 decoding failed" },
    { IMAP_QP_DECODING_FAILED, "quoted-printable decoding failed" },
    { IMAP_UU_DECODING_FAILED, "Unix-to-Unix decoding failed" },
    { IMAP_FILE_DECOMP_FAILED, "file decompression failed" },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// imap module
//-------------------------------------------------------------------------

ImapModule::ImapModule() : Module(IMAP_NAME, IMAP_HELP, s_params)
{
    config = nullptr;
}

ImapModule::~ImapModule()
{
    if ( config )
        delete config;
}

const RuleMap* ImapModule::get_rules() const
{ return imap_rules; }

const PegInfo* ImapModule::get_pegs() const
{ return imap_peg_names; }

PegCount* ImapModule::get_counts() const
{ return (PegCount*)&imapstats; }

ProfileStats* ImapModule::get_profile() const
{ return &imapPerfStats; }

bool ImapModule::set(const char*, Value& v, SnortConfig*)
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

    else if ( v.is("qp_decode_depth") )
        config->decode_conf.set_qp_depth(mime_value);

    else if ( v.is("uu_decode_depth") )
        config->decode_conf.set_uu_depth(mime_value);

    return true;
}

IMAP_PROTO_CONF* ImapModule::get_data()
{
    IMAP_PROTO_CONF* tmp = config;
    config = nullptr;
    return tmp;
}

bool ImapModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new IMAP_PROTO_CONF;
    return true;
}

bool ImapModule::end(const char*, int, SnortConfig*)
{
    return true;
}

