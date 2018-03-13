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

// ssh_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh_module.h"

#include <cassert>

using namespace snort;
using namespace std;

#define SSH_EVENT_RESPOVERFLOW_STR \
    "challenge-response overflow exploit"
#define SSH_EVENT_CRC32_STR \
    "SSH1 CRC32 exploit"
#define SSH_EVENT_SECURECRT_STR \
    "server version string overflow"
#define SSH_EVENT_WRONGDIR_STR \
    "bad message direction"
#define SSH_PAYLOAD_SIZE_STR \
    "payload size incorrect for the given payload"
#define SSH_VERSION_STR \
    "failed to detect SSH version string"

static const Parameter s_params[] =
{
    { "max_encrypted_packets", Parameter::PT_INT, "0:65535", "25",
      "ignore session after this many encrypted packets" },

    { "max_client_bytes", Parameter::PT_INT, "0:65535", "19600",
      "number of unanswered bytes before alerting on challenge-response overflow or CRC32" },

    { "max_server_version_len", Parameter::PT_INT, "0:255", "80",
      "limit before alerting on secure CRT server version string overflow" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap ssh_rules[] =
{
    { SSH_EVENT_RESPOVERFLOW, SSH_EVENT_RESPOVERFLOW_STR },
    { SSH_EVENT_CRC32, SSH_EVENT_CRC32_STR },
    { SSH_EVENT_SECURECRT, SSH_EVENT_SECURECRT_STR },
    { SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR },
    { SSH_EVENT_PAYLOAD_SIZE, SSH_PAYLOAD_SIZE_STR },
    { SSH_EVENT_VERSION, SSH_VERSION_STR },

    { 0, nullptr }
};

const PegInfo ssh_pegs[] =
{
    { CountType::SUM, "packets", "total packets" },
    { CountType::NOW, "concurrent_sessions", "total concurrent ssh sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent ssh sessions" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// ssh module
//-------------------------------------------------------------------------

SshModule::SshModule() : Module(SSH_NAME, SSH_HELP, s_params)
{
    conf = nullptr;
}

SshModule::~SshModule()
{
    if ( conf )
        delete conf;
}

const RuleMap* SshModule::get_rules() const
{ return ssh_rules; }

const PegInfo* SshModule::get_pegs() const
{ return ssh_pegs; }

PegCount* SshModule::get_counts() const
{ return (PegCount*)&sshstats; }

ProfileStats* SshModule::get_profile() const
{ return &sshPerfStats; }

bool SshModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("max_encrypted_packets") )
        conf->MaxEncryptedPackets = v.get_long();

    else if ( v.is("max_client_bytes") )
        conf->MaxClientBytes = v.get_long();

    else if ( v.is("max_server_version_len") )
        conf->MaxServerVersionLen = v.get_long();

    else
        return false;

    return true;
}

SSH_PROTO_CONF* SshModule::get_data()
{
    SSH_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool SshModule::begin(const char*, int, SnortConfig*)
{
    assert(!conf);
    conf = new SSH_PROTO_CONF;
    return true;
}

