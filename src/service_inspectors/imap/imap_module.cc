//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "base64 decoding depth (-1 no limit)" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "non-Encoded MIME attachment extraction depth (-1 no limit)" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "quoted Printable decoding depth (-1 no limit)" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
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
    const long value = v.get_long();
    const long mime_value = (value > 0) ? value : -(value+1); // flip 0 and -1 for MIME processing
    if ( v.is("b64_decode_depth") )
        config->decode_conf.set_b64_depth(mime_value);
    else if ( v.is("bitenc_decode_depth") )
        config->decode_conf.set_bitenc_depth(mime_value);
    else if ( v.is("qp_decode_depth") )
        config->decode_conf.set_qp_depth(mime_value);
    else if ( v.is("uu_decode_depth") )
        config->decode_conf.set_uu_depth(mime_value);
    else
        return false;

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

